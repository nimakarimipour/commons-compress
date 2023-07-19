/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.compress.archivers.dump;

import java.io.IOException;
import java.util.Date;
import java.util.Objects;

import org.apache.commons.compress.archivers.zip.ZipEncoding;
import edu.ucr.cs.riple.taint.ucrtainting.qual.RUntainted;

/**
 * This class represents identifying information about a Dump archive volume.
 * It consists the archive's dump date, label, hostname, device name and possibly
 * last mount point plus the volume's volume id andfirst record number.
 * <p>
 * For the corresponding C structure see the header of {@link DumpArchiveEntry}.
 * </p>
 */
public class DumpArchiveSummary {

    private long dumpDate;
    private long previousDumpDate;
    private int volume;
    private String label;
    private int level;
    private String filesys;
    private String devname;
    private String hostname;
    private int flags;
    private int firstrec;
    private int ntrec;

    DumpArchiveSummary(final byte[] buffer, final ZipEncoding encoding) throws IOException {
        dumpDate = 1000L * DumpArchiveUtil.convert32(buffer, 4);
        previousDumpDate = 1000L * DumpArchiveUtil.convert32(buffer, 8);
        volume = DumpArchiveUtil.convert32(buffer, 12);
        label = DumpArchiveUtil.decode(encoding, buffer, 676, DumpArchiveConstants.LBLSIZE).trim();
        level = DumpArchiveUtil.convert32(buffer, 692);
        filesys = DumpArchiveUtil.decode(encoding, buffer, 696, DumpArchiveConstants.NAMELEN).trim();
        devname = DumpArchiveUtil.decode(encoding, buffer, 760, DumpArchiveConstants.NAMELEN).trim();
        hostname = DumpArchiveUtil.decode(encoding, buffer, 824, DumpArchiveConstants.NAMELEN).trim();
        flags = DumpArchiveUtil.convert32(buffer, 888);
        firstrec = DumpArchiveUtil.convert32(buffer, 892);
        ntrec = DumpArchiveUtil.convert32(buffer, 896);

        //extAttributes = DumpArchiveUtil.convert32(buffer, 900);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DumpArchiveSummary other = (DumpArchiveSummary) obj;
        return Objects.equals(devname, other.devname) && dumpDate == other.dumpDate && Objects.equals(hostname, other.hostname);
    }

    /**
     * Get the device name, e.g., /dev/sda3 or /dev/mapper/vg0-home.
     * @return device name
     */
    public String getDevname() {
        return devname;
    }

    /**
     * Get the date of this dump.
     * @return the date of this dump.
     */
    public Date getDumpDate() {
        return new Date(dumpDate);
    }

    /**
     * Get the last mountpoint, e.g., /home.
     * @return last mountpoint
     */
    public String getFilesystem() {
        return filesys;
    }

    /**
     * Get the inode of the first record on this volume.
     * @return inode of the first record on this volume.
     */
    public int getFirstRecord() {
        return firstrec;
    }

    /**
     * Get the miscellaneous flags. See below.
     * @return flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * Get the hostname of the system where the dump was performed.
     * @return hostname the host name
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Get dump label. This may be autogenerated, or it may be specified
     * by the user.
     * @return dump label
     */
    public String getLabel() {
        return label;
    }

    /**
     * Get the level of this dump. This is a number between 0 and 9, inclusive,
     * and a level 0 dump is a complete dump of the partition. For any other dump
     * 'n' this dump contains all files that have changed since the last dump
     * at this level or lower. This is used to support different levels of
     * incremental backups.
     * @return dump level
     */
    public int getLevel() {
        return level;
    }

    /**
     * Get the number of records per tape block. This is typically
     * between 10 and 32.
     * @return the number of records per tape block
     */
    public int getNTRec() {
        return ntrec;
    }

    /**
     * Get the date of the previous dump at this level higher.
     * @return dumpdate may be null
     */
    public Date getPreviousDumpDate() {
        return new Date(previousDumpDate);
    }

    /**
     * Get volume (tape) number.
     * @return volume (tape) number.
     */
    public int getVolume() {
        return volume;
    }

    @Override
    public int hashCode() {
        return Objects.hash(devname, dumpDate, hostname);
    }

    /**
     * Is this volume compressed? N.B., individual blocks may or may not be compressed.
     * The first block is never compressed.
     * @return true if volume is compressed
     */
    public boolean isCompressed() {
        return (flags & 0x0080) == 0x0080;
    }

    /**
     * Does this volume contain extended attributes.
     * @return true if volume contains extended attributes.
     */
    public boolean isExtendedAttributes() {
        return (flags & 0x8000) == 0x8000;
    }

    /**
     * Does this volume only contain metadata?
     * @return true if volume only contains meta-data
     */
    public boolean isMetaDataOnly() {
        return (flags & 0x0100) == 0x0100;
    }

    /**
     * Is this the new header format? (We do not currently support the
     * old format.)
     *
     * @return true if using new header format
     */
    public boolean isNewHeader() {
        return (flags & 0x0001) == 0x0001;
    }

    /**
     * Is this the new inode format? (We do not currently support the
     * old format.)
     * @return true if using new inode format
     */
    public boolean isNewInode() {
        return (flags & 0x0002) == 0x0002;
    }

    /**
     * Set the device name.
     * @param devname the device name
     */
    public void setDevname(final String devname) {
        this.devname = devname;
    }

    /**
     * Set dump date.
     * @param dumpDate the dump date
     */
    public void setDumpDate(final Date dumpDate) {
        this.dumpDate = dumpDate.getTime();
    }

    /**
     * Set the last mountpoint.
     * @param fileSystem the last mountpoint
     */
    public void setFilesystem(final String fileSystem) {
        this.filesys = fileSystem;
    }

    /**
     * Set the inode of the first record.
     * @param firstrec the first record
     */
    public void setFirstRecord(final int firstrec) {
        this.firstrec = firstrec;
    }

    /**
     * Set the miscellaneous flags.
     * @param flags flags
     */
    public void setFlags(final int flags) {
        this.flags = flags;
    }

    /**
     * Set the hostname.
     * @param hostname the host name
     */
    public void setHostname(final String hostname) {
        this.hostname = hostname;
    }

    /**
     * Set dump label.
     * @param label the label
     */
    public void setLabel(final String label) {
        this.label = label;
    }

    /**
     * Set level.
     * @param level the level
     */
    public void setLevel(final int level) {
        this.level = level;
    }

    /**
     * Set the number of records per tape block.
     * @param ntrec the number of records per tape block
     */
    public void setNTRec(final int ntrec) {
        this.ntrec = ntrec;
    }

    /**
     * Set previous dump date.
     * @param previousDumpDate the previous dump dat
     */
    public void setPreviousDumpDate(final Date previousDumpDate) {
        this.previousDumpDate = previousDumpDate.getTime();
    }

    /**
     * Set volume (tape) number.
     * @param volume the volume number
     */
    public void setVolume(final int volume) {
        this.volume = volume;
    }
}
