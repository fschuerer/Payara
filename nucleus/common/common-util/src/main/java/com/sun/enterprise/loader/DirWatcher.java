/*
 *    DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 *    Copyright (c) [2019-2024] Payara Foundation and/or its affiliates. All rights reserved.
 *
 *    The contents of this file are subject to the terms of either the GNU
 *    General Public License Version 2 only ("GPL") or the Common Development
 *    and Distribution License("CDDL") (collectively, the "License").  You
 *    may not use this file except in compliance with the License.  You can
 *    obtain a copy of the License at
 *    https://github.com/payara/Payara/blob/main/LICENSE.txt
 *    See the License for the specific
 *    language governing permissions and limitations under the License.
 *
 *    When distributing the software, include this License Header Notice in each
 *    file and include the License file at glassfish/legal/LICENSE.txt.
 *
 *    GPL Classpath Exception:
 *    The Payara Foundation designates this particular file as subject to the "Classpath"
 *    exception as provided by the Payara Foundation in the GPL Version 2 section of the License
 *    file that accompanied this code.
 *
 *    Modifications:
 *    If applicable, add the following below the License Header, with the fields
 *    enclosed by brackets [] replaced by your own identifying information:
 *    "Portions Copyright [year] [name of copyright owner]"
 *
 *    Contributor(s):
 *    If you wish your version of this file to be governed by only the CDDL or
 *    only the GPL Version 2, indicate your decision by adding "[Contributor]
 *    elects to include this software in this distribution under the [CDDL or GPL
 *    Version 2] license."  If you don't indicate a single choice of license, a
 *    recipient has the option to distribute your version of this file under
 *    either the CDDL, the GPL Version 2 or to extend the choice of license to
 *    its licensees as provided above.  However, if you add GPL Version 2 code
 *    and therefore, elected the GPL Version 2 license, then the option applies
 *    only if the new code is made subject to such option by the copyright
 *    holder.
 */

package com.sun.enterprise.loader;

import com.sun.enterprise.util.CULoggerInfo;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.OVERFLOW;

/**
 * Watch directory for new classfiles.
 * Classes may get added to class folders during deployment when they are generated by rmic or jaxws.
 * To enable that we use WatchService to get notified of the changes. The changes are processed when
 * an item is looked up, on calling thread.
 */
class DirWatcher {
    /**
     * Verify if item might be present under given path.
     *
     * @param parent root path of classloader. Should be registered beforehand
     * @param item classpath item to look for
     * @return false if the item is definetely not present in the path
     */
    static boolean hasItem(Path parent, String item) {
        return forPath(parent).hasFilesystemItem(parent, item);
    }

    /**
     * Register root path for scanning.
     * This is pre
     * @param path
     * @throws IOException
     */
    static void register(Path path) throws IOException {
        forPath(path).registerInFilesystem(path);
    }

    static void unregister(Path path) {
        forPath(path).unregisterFromFilesystem(path);
    }

    private static DirWatcher forPath(Path path) {
        return PER_FS.computeIfAbsent(path.getFileSystem(), DirWatcher::new);
    }

    /**
     * Per filesystem instance.
     */
    private static final Map<FileSystem, DirWatcher> PER_FS = new ConcurrentHashMap<>();

    private static final Logger LOGGER = CULoggerInfo.getLogger();

    private final WatchService watchService;
    private Map<Path, WatchProcessor> processors = new ConcurrentHashMap<>();

    private DirWatcher(FileSystem fileSystem) {
        try {
            this.watchService = fileSystem.newWatchService();
        } catch (IOException | UnsupportedOperationException e) {
            throw new IllegalArgumentException("Filesystem WatchService is unavailable", e);
        }
    }

    private void registerInFilesystem(Path path) throws IOException {
        if (Files.notExists(path)) {
            // Quite often the root path doesn't even exist yet (and registering for watch would fail)
            // In such case we register watcher for parent directory so it would register the main watcher
            // when directory is created
            processors.compute(path, (p, watcher) -> watcher == null ? ItemChecker.registerNonExisting(p, watchService) : watcher.subscribe());

            for(;;) {
                path = path.getParent();
                WatchProcessor watcher = processors.computeIfAbsent(path, p -> new ParentWatcher(p, watchService));
                if (watcher.registered || Files.exists(path)) {
                    watcher.register();
                    break;
                }
            }
        } else {
            processors.compute(path, (p, watcher) -> watcher == null ? ItemChecker.registerExisting(p, watchService) : watcher.subscribe());
        }
    }

    private boolean hasFilesystemItem(Path parent, String item) {
        syncWatches();
        WatchProcessor checker = processors.get(parent);
        if (checker == null || !(checker instanceof ItemChecker)) {
            LOGGER.info(() -> "Watch service attempted to get checker for untracked item " + parent.toAbsolutePath());
            return true; // true is always safe answer
        }
        return ((ItemChecker)checker).hasItem(item);
    }

    private synchronized void syncWatches() {
        while(true) {
            WatchKey key = watchService.poll();
            if (key == null) {
                return;
            }
            Path root = (Path) key.watchable();

            WatchProcessor processor = processors.get(root);
            if (processor == null || processor.isCancelled()) {
                key.cancel();
                continue;
            }

            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                boolean keepRegistered = true;
                if (kind == OVERFLOW) {
                    LOGGER.warning(() -> "File system watcher overflowed for " + root);
                    keepRegistered = processor.overflowed();
                } else {
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();

                    if (kind == ENTRY_CREATE) {
                        keepRegistered = processor.created(filename);
                    }
                    if (kind == ENTRY_DELETE) {
                        keepRegistered = processor.deleted(filename);
                    }
                }
                if (!keepRegistered) {
                    key.cancel();
                }
            }
            boolean valid = key.reset();
            if (!valid) {
                processor.cancelled();
            }
        }
    }

    private void unregisterFromFilesystem(Path path) {
        WatchProcessor processor = processors.get(path);
        if (processor != null) {
            if (processor.unsubscribe()) {
                processor.cancelled();
                processors.remove(path);
            }
        }
    }

    class ParentWatcher extends WatchProcessor {


        ParentWatcher(Path p, WatchService watchService) {
            super(p, watchService);
        }

        @Override
        protected void register() {
            super.register();
            try (Stream<Path> stream = Files.list(root)){
                stream.forEach(this::registerSubProcessor);
            } catch (IOException e) {
                LOGGER.log(Level.FINE, "Error when listing directory",e);
            }
        }

        @Override
        protected boolean created(Path filename) {
            LOGGER.fine(() -> "In parent directory "+root+": created "+filename);
            Path path = root.resolve(filename);
            registerSubProcessor(path);
            return true;
        }

        private void registerSubProcessor(Path path) {
            if (Files.isDirectory(path)) {
                WatchProcessor processor = processors.get(path);
                if (processor != null) {
                    processor.register();
                }
            }
        }

    }


}
