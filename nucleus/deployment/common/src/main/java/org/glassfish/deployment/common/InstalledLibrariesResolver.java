/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 1997-2015 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * https://glassfish.dev.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
// Portions Copyright 2018-2024 Payara Foundation and/or affiliates

package org.glassfish.deployment.common;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.jar.Attributes;
import java.util.jar.JarInputStream;
import java.util.logging.*;
import java.util.*;
import java.util.stream.Collectors;

import org.glassfish.api.deployment.archive.ReadableArchive;

import org.glassfish.logging.annotation.LogMessageInfo;

/**
 * This class resolves the dependencies between optional packages (installed libraries) and also between
 * apps/stand-alone modules that depend on optional packages (installed libraries)
 * @author Sheetal Vartak
 */

public class InstalledLibrariesResolver {

    // installed libraries list (accounts only for "domainRoot/lib/applibs" and not any
    // of "java.ext.dirs" entries)
    private static Map<Extension, String> appLibsDirLibsStore = new HashMap<Extension, String>();
    private static List<Path> warLibraries = new ArrayList<>();

    public static final Logger deplLogger = org.glassfish.deployment.common.DeploymentContextImpl.deplLogger;

    @LogMessageInfo(message = "Optional package {0} does not exist or its Specification-Version does not match. Unable to satisfy dependency for {1}", level="WARNING")
    private static final String PACKAGE_NOT_FOUND = "NCLS-DEPLOYMENT-00011";

    @LogMessageInfo(message = "Optional package dependency satisfied for {0}", level="INFO")
    private static final String PACKAGE_SATISFIED = "NCLS-DEPLOYMENT-00012";

    @LogMessageInfo(message = "Error in opening optional package file {0} due to exception: {1}.", level="WARNING")
    private static final String INVALID_ZIP = "NCLS-DEPLOYMENT-00013";

    @LogMessageInfo(message = "Exception occurred : {0}.", level="WARNING")
    private static final String EXCEPTION_OCCURRED = "NCLS-DEPLOYMENT-00014";

    @LogMessageInfo(message = "Specification-Version for the optional package [ {0} ] in the jarfile [ {1} ] is not specified. Please provide a valid specification version for this optional package", level="WARNING")
    private static final String NULL_SPEC_VERS = "NCLS-DEPLOYMENT-00015";

    @LogMessageInfo(message = "Skipping extension processing for {0} due to error: {1}", level="INFO")
    private static final String SKIPPING_PROCESSING_INFO = "NCLS-DEPLOYMENT-00016";

    /**
     * Resolves installed library dependencies
     * @param manifest Manifest File
     * @param archiveUri archive
     * @return status indicating whether all dependencies (transitive) is resolved or not
     */
    public static boolean resolveDependencies(Manifest manifest, String archiveUri) {
        try {
            getInstalledLibraries(archiveUri, manifest, true, appLibsDirLibsStore);
        } catch (MissingResourceException e1) {
            deplLogger.log(Level.WARNING, PACKAGE_NOT_FOUND, new Object[]{e1.getClass(), archiveUri});
            return false;
        }

        deplLogger.log(Level.INFO, PACKAGE_SATISFIED, new Object[]{archiveUri});

        return true;
    }

    /**
     * check whether the optional packages have all their 
     * internal dependencies resolved
     * @param libDir libraryDirectory
     */
    public static void initializeInstalledLibRegistry(String libDir ) {
        try (var jarStream = Files.list(Path.of(String.format("%s/warlibs", libDir)))
                .filter(path -> (Files.isRegularFile(path) || Files.isSymbolicLink(path))
                        && path.toString().endsWith(".jar"))){
            warLibraries = jarStream.collect(Collectors.toList());
        } catch (IOException e) {
            deplLogger.fine("Error in opening package directory " + libDir + " due to exception: " + e.getMessage());
        }
        initializeInstalledLibRegistryForApplibs(libDir);
    }

    public static Set<String> getInstalledLibraries(ReadableArchive archive) throws IOException {
        Set<String> libraries = new HashSet<>();

        if (archive == null) {
            return libraries;
        }

        Manifest manifest = archive.getManifest();

        //we are looking for libraries only in "applibs" directory, hence strict=false
        Set<String> installedLibraries = getInstalledLibraries(archive.getURI().toString(), manifest,
                false, appLibsDirLibsStore);
        libraries.addAll(installedLibraries);

        // now check my libraries.
        List<String> libs = getArchiveLibraries(archive);
        if (libs != null) {
            for(String libUri : libs) {
                try (InputStream libInputStream = archive.getEntry(libUri)) {
                    if(libInputStream == null) {
                        continue;
                    }
                    manifest = new JarInputStream(libInputStream).getManifest();
                    if(manifest != null) {
                        libraries.addAll(getInstalledLibraries(archive.getURI().toString(), manifest, false, appLibsDirLibsStore));
                    }
                }
            }
        }

        return libraries;
    }

    /**
     * These libraries will be included in non-internal WAR applications,
     * to improve developer experience and not require all dependencies to be included in the WAR.
     * @return list of libraries in <domain_root>/lib/warlibs
     */
    public static List<Path> getWarLibraries() {
        return warLibraries;
    }

    private static Set<String> getInstalledLibraries(String archiveURI, Manifest manifest, boolean strict,
                                                     Map<Extension, String> libraryStore) {
        Set<String> libraries = new HashSet<String>();
        String extensionList = null;
        try {
            extensionList = manifest.getMainAttributes().
                    getValue(Attributes.Name.EXTENSION_LIST);
            if(deplLogger.isLoggable(Level.FINE)){
                deplLogger.fine("Extension-List for archive [" + archiveURI + "] : " + extensionList);
            }
        } catch (Exception e) {
            //ignore this exception
            if (deplLogger.isLoggable(Level.FINE)) {
                deplLogger.log(Level.FINE,
                        "InstalledLibrariesResolver : exception occurred : " + e.toString());
            }
        }

        if (extensionList != null) {
            StringTokenizer st =
                    new StringTokenizer(extensionList, " ");
            while (st.hasMoreTokens()) {

                String token = st.nextToken().trim();
                String extName = manifest.getMainAttributes().
                        getValue(token + "-" + Attributes.Name.EXTENSION_NAME);
                if (extName != null) {
                    extName = extName.trim();
                }

                String specVersion = manifest.getMainAttributes().
                        getValue(token + "-" + Attributes.Name.SPECIFICATION_VERSION);

                Extension extension = new Extension(extName);
                if (specVersion != null) {
                    extension.setSpecVersion(specVersion);
                }
                //TODO possible NPE when extension is unspecified
                boolean isLibraryInstalled = libraryStore.containsKey(extension);
                if (isLibraryInstalled) {
                    String libraryName = libraryStore.get(extension);
                    libraries.add(libraryName);
                } else {
                    if(strict){
                        throw new MissingResourceException(extName + " not found", extName, null);
                    }else{
                        // no action needed
                    }
                }
                if (deplLogger.isLoggable(Level.FINEST)) {
                    deplLogger.log(Level.FINEST, " is library installed [" + extName + "] " +
                            "for archive [" + archiveURI + "]: " + isLibraryInstalled);
                }
            }
        }
        return libraries;
    }


    /**
     * @return a list of libraries included in the archivist
     */
    private static List<String> getArchiveLibraries(ReadableArchive archive) {
        Enumeration<String> entries = archive.entries();
        if (entries == null) {
            return null;
        }

        List<String> libs = new ArrayList<>();
        while (entries.hasMoreElements()) {
            String entryName = entries.nextElement();
            if (entryName.indexOf('/') != -1) {
                continue; // not on the top level
            }

            if (entryName.endsWith(".jar")) {
                libs.add(entryName);
            }
        }
        return libs;
    }


    /**
     * initialize the "applibs" part of installed libraries ie.,
     * any library within "applibs" which represents an extension (EXTENSION_NAME in MANIFEST.MF)
     * that can be used by applications (as EXTENSION_LIST in their MANIFEST.MF)
     * @param domainLibDir library directory (of a domain)
     */
    private static void initializeInstalledLibRegistryForApplibs(String domainLibDir) {
        String applibsDirString = domainLibDir + File.separator + "applibs";

        deplLogger.fine("applib-Dir-String..." + applibsDirString);
        ArrayList<File> validApplibsDirLibFiles = new ArrayList<File>();
        Map<Extension, String> installedLibraries = getInstalledLibraries(applibsDirString, null, validApplibsDirLibFiles);
        appLibsDirLibsStore.putAll(installedLibraries);


        for (File file : validApplibsDirLibFiles) {
            JarFile jarFile = null;
            try {
                jarFile = new JarFile(file);
                Manifest m = jarFile.getManifest();
                if (m != null) {
                    boolean found = true;
                    try {
                        getInstalledLibraries(file.getAbsolutePath(), m, true, appLibsDirLibsStore);
                    } catch(MissingResourceException mre ) {
                            deplLogger.log(Level.WARNING, PACKAGE_NOT_FOUND, new Object[] {mre.getClass(),
                                    file.getAbsolutePath()});
                    }
                }
            } catch (IOException ioe) {
              deplLogger.log(Level.WARNING, INVALID_ZIP, new Object[] {file.getAbsolutePath(), ioe.getMessage()});
            }finally {
                if (jarFile!=null)
                    try {
                        jarFile.close();
                    } catch (IOException e) {
                      deplLogger.log(Level.WARNING, EXCEPTION_OCCURRED, new Object[] {e.getMessage()});
                    }
            }
        }

    }

    private static Map<Extension, String> getInstalledLibraries(String libraryDirectoryName, Set processedLibraryNames,
                                                                List processedLibraries) {
        Map<Extension, String> installedLibraries = new HashMap<Extension, String>();

        File dir = new File(libraryDirectoryName);

        if (deplLogger.isLoggable(Level.FINE)) {
            deplLogger.log(Level.FINE, "installed library directory : " + dir);
        }

        File[] libraries = dir.listFiles();
        if (libraries != null) {
            try {
                for (int i = 0; i < libraries.length; i++) {

                    if (deplLogger.isLoggable(Level.FINE)) {
                        deplLogger.log(Level.FINE, "installed library : " + libraries[i]);
                    }
                    /*
                     *Skip any candidate that does not end with .jar or is a
                     *directory.
                     */
                    if (libraries[i].isDirectory()) {
                        deplLogger.log(Level.FINE,
                                "Skipping installed library processing on " +
                                        libraries[i].getAbsolutePath() +
                                        "; it is a directory");
                        continue;
                    }

                    if (!libraries[i].getName().toLowerCase(Locale.getDefault()).endsWith(".jar")) {
                        deplLogger.log(Level.FINE,
                                "Skipping installed library processing on " +
                                        libraries[i].getAbsolutePath() +
                                        "; it does not appear to be a JAR file based on its file type");
                        continue;
                    }
                    JarFile jarFile = null;
                    try {
                        jarFile = new JarFile(libraries[i]);

                        Manifest manifest = jarFile.getManifest();
                        if(processedLibraryNames != null){
                            processedLibraryNames.add(libraries[i].toString());
                        }
                        if(processedLibraries != null){
                            processedLibraries.add(libraries[i]);
                        }

                        //Extension-Name of optional package
                        if (manifest != null) {
                            String extName = manifest.getMainAttributes().getValue(Attributes.Name.EXTENSION_NAME);
                            String specVersion = manifest.getMainAttributes().
                                    getValue(Attributes.Name.SPECIFICATION_VERSION);
                            deplLogger.fine("Extension " + libraries[i].getAbsolutePath() +
                                    ", extNameOfOPtionalPkg..." + extName +
                                    ", specVersion..." + specVersion);
                            if (extName != null) {
                                if (specVersion == null) {
                                    deplLogger.log(Level.WARNING,
                                                   NULL_SPEC_VERS,
                                                   new Object[]{extName, jarFile.getName()});
                                    specVersion = "";
                                }

                                Extension extension = new Extension(extName);
                                extension.setSpecVersion(specVersion);

                                installedLibraries.put(extension, libraries[i].getName());
                            }
                        }
                    } catch (Throwable thr) {
                        String msg = deplLogger.getResourceBundle().getString(
                                "enterprise.deployment.backend.optionalpkg.dependency.error");
                        if (deplLogger.isLoggable(Level.FINE)) {
                            deplLogger.log(Level.FINE, MessageFormat.format(
                                    msg, libraries[i].getAbsolutePath(), thr.getMessage()), thr);
                        } else {
                            LogRecord lr = new LogRecord(Level.INFO,
                                                         SKIPPING_PROCESSING_INFO);
                            lr.setParameters(new Object[] { libraries[i].getAbsolutePath(), thr.getMessage() } );
                            deplLogger.log(lr);
                        }
                    } finally {
                        if (jarFile != null) {
                            jarFile.close();
                        }
                    }
                }
            } catch (IOException e) {
                deplLogger.log(Level.WARNING,
                        "enterprise.deployment.backend.optionalpkg.dependency.exception", new Object[]{e.getMessage()});
            }
        }
        return installedLibraries;
    }

    static class Extension {
        private String extensionName;
        private String specVersion = "";
        private String specVendor = "";
        private String implVersion = "";
        private String implVendor = "";

        public Extension(String name){
            this.extensionName = name;
        }
        
        public String getExtensionName() {
            return extensionName;
        }

        public void setExtensionName(String extensionName) {
            this.extensionName = extensionName;
        }

        public String getSpecVersion() {
            return specVersion;
        }

        public void setSpecVersion(String specVersion) {
            this.specVersion = specVersion;
        }

        public String getSpecVendor() {
            return specVendor;
        }

        public void setSpecVendor(String specVendor) {
            this.specVendor = specVendor;
        }

        public String getImplVersion() {
            return implVersion;
        }

        public void setImplVersion(String implVersion) {
            this.implVersion = implVersion;
        }

        public String getImplVendor() {
            return implVendor;
        }

        public void setImplVendor(String implVendor) {
            this.implVendor = implVendor;
        }

        public boolean equals(Object o){
            if(o != null && o instanceof Extension){
                Extension e = (Extension)o;
                if((o == this) ||
                    (e.getExtensionName().equals(extensionName) &&
                        (e.getImplVendor().equals(implVendor)    || (e.getImplVendor().equals(""))  ) &&
                        (e.getImplVersion().equals(implVersion)  || (e.getImplVersion().equals("")) ) &&
                        (e.getSpecVendor().equals(specVendor)    || (e.getSpecVendor().equals(""))  ) &&
                        (e.getSpecVersion().equals(specVersion)  || (e.getSpecVersion().equals("")) )
                    )){
                    return true;
                }else{
                    return false;
                }
            }else {
                return false;
            }
        }

        public int hashCode() {
            int result = 17;
            result = 37*result + extensionName.hashCode();
            return result;
        }
    }
}
