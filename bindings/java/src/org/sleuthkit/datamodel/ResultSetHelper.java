package org.sleuthkit.datamodel;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Database helper class the wraps most of the mappings from ResultSet to
 * Content subclass constructors.
 *
 * @author pmartel
 */
class ResultSetHelper {

	SleuthkitCase db;
	
	private enum DBColumns {
		// Must be kept up to date with current database layout
		fs_obj_id(1), obj_id(2), attr_type(3), attr_id(4), name(5), meta_addr(6),
		type(7), has_layout(8), has_path(9), dir_type(10), meta_type(11),
		dir_flags(12), meta_flags(13), size(14), ctime(15), crtime(16), atime(17),
		mtime(18), mode(19), uid(20), gid(21), md5(22), known(23), parent_path(24);
		
		int index;
		private DBColumns(int index) {
			this.index = index;
		}
	}

	ResultSetHelper(SleuthkitCase db) {
		this.db = db;
	}

	Image image(ResultSet rs, String name, String[] imagePaths) throws TskException, SQLException {

		long obj_id, type, ssize;
		String tzone;

		obj_id = rs.getLong("obj_id");
		type = rs.getLong("type");
		ssize = rs.getLong("ssize");
		tzone = rs.getString("tzone");

		Image img = new Image(db, obj_id, type, ssize, name, imagePaths, tzone);
		return img;
	}

	String imagePath(ResultSet rs) throws SQLException {
		return rs.getString("name");
	}

	VolumeSystem volumeSystem(ResultSet rs, Image parent) throws SQLException {

		long id = rs.getLong("obj_id");
		long type = rs.getLong("vs_type");
		long imgOffset = rs.getLong("img_offset");
		long blockSize = rs.getLong("block_size");

		VolumeSystem vs = new VolumeSystem(db, id, type, imgOffset, blockSize);

		vs.setParent(parent);
		return vs;
	}

	Volume volume(ResultSet rs, VolumeSystem parent) throws SQLException {
		Volume vol = new Volume(db, rs.getLong("obj_id"), rs.getLong("addr"),
				rs.getLong("start"), rs.getLong("length"), rs.getLong("flags"),
				rs.getString("desc"));
		vol.setParent(parent);
		return vol;
	}

	FileSystem fileSystem(ResultSet rs, FileSystemParent parent) throws SQLException {

		FileSystem fs = new FileSystem(db, rs.getLong("obj_id"), rs.getLong("img_offset"),
				rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
				rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
		fs.setParent(parent);
		return fs;
	}
			
	File file(ResultSet rs, FileSystem fs) throws SQLException {
		File f = new File(db, rs.getLong(DBColumns.obj_id.index), rs.getLong(DBColumns.fs_obj_id.index), 
				rs.getLong(DBColumns.meta_addr.index), rs.getLong(DBColumns.attr_type.index),
				rs.getLong(DBColumns.attr_id.index), rs.getString(DBColumns.name.index),
				rs.getLong(DBColumns.dir_type.index), rs.getLong(DBColumns.meta_type.index),
				rs.getLong(DBColumns.dir_flags.index), rs.getLong(DBColumns.meta_flags.index),
				rs.getLong(DBColumns.size.index),rs.getLong(DBColumns.ctime.index),
				rs.getLong(DBColumns.crtime.index), rs.getLong(DBColumns.atime.index),
				rs.getLong(DBColumns.mtime.index), rs.getLong(DBColumns.mode.index),
				rs.getLong(DBColumns.uid.index), rs.getLong(DBColumns.gid.index),
				rs.getLong(DBColumns.known.index), rs.getString(DBColumns.parent_path.index));
		f.setFileSystem(fs);
		return f;
	}
	
	Directory directory(ResultSet rs, FileSystem fs, String name) throws SQLException {
		Directory dir = new Directory(db, rs.getLong(DBColumns.obj_id.index),
				rs.getLong(DBColumns.fs_obj_id.index), rs.getLong(DBColumns.meta_addr.index),
				rs.getLong(DBColumns.attr_type.index), rs.getLong(DBColumns.attr_id.index),
				name, rs.getLong(DBColumns.dir_type.index), rs.getLong(DBColumns.meta_type.index),
				rs.getLong(DBColumns.dir_flags.index), rs.getLong(DBColumns.meta_flags.index),
				rs.getLong(DBColumns.size.index), rs.getLong(DBColumns.ctime.index),
				rs.getLong(DBColumns.crtime.index), rs.getLong(DBColumns.atime.index),
				rs.getLong(DBColumns.mtime.index), rs.getLong(DBColumns.mode.index),
				rs.getLong(DBColumns.uid.index), rs.getLong(DBColumns.gid.index),
				rs.getLong(DBColumns.known.index), rs.getString(DBColumns.parent_path.index));
		dir.setFileSystem(fs);
		return dir;
	}

	Directory directory(ResultSet rs, FileSystem fs) throws SQLException {
		return directory(rs, fs, rs.getString(DBColumns.name.index));
	}
	
}