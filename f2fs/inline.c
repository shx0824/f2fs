/*
 * fs/f2fs/inline.c
 *
 * Authors:
 *      Shi Xing
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>

#include "f2fs.h"

void f2fs_clear_inode_inline_flag(struct f2fs_inode *raw_inode)
{
	raw_inode->i_reserved &= ~F2FS_INODE_INLINE_DATA;
}

void f2fs_set_inode_inline_flag(struct f2fs_inode *raw_inode)
{
	raw_inode->i_reserved |= F2FS_INODE_INLINE_DATA;
}

int f2fs_inline_data_attempt(struct inode *inode)
{
	return is_inode_dyn_flag_set(F2FS_I(inode), F2FS_INLINE_DATA_ATTEMPT);
}

int f2fs_has_inline_data(struct inode *inode)
{
	return is_inode_dyn_flag_set(F2FS_I(inode), F2FS_INLINE_DATA_FL);
}

static int f2fs_read_inline_data(struct inode *inode, struct page *page)
{
	void *src_addr, *dst_addr;
	loff_t size = i_size_read(inode);
	struct page *ipage = get_node_page(F2FS_SB(inode->i_sb), inode->i_ino);

	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	src_addr = page_address(ipage);
	dst_addr = page_address(page);

	memcpy(dst_addr, src_addr + INLINE_DATA_OFFSET, size);
	zero_user_segment(page, INLINE_DATA_OFFSET + size, PAGE_CACHE_SIZE);
	SetPageUptodate(page);

	f2fs_put_page(ipage, 1);

	return 0;
}

int f2fs_read_inline_data_page(struct inode *inode, struct page *page)
{
	int ret = 0;

	if (!page->index) {
		ret = f2fs_read_inline_data(inode, page);
	} else if (!PageUptodate(page)) {
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
		SetPageUptodate(page);
	}

	unlock_page(page);

	return ret;
}

int f2fs_convert_inline_data(struct page *p,
			     struct inode *inode, unsigned flags)
{
	int err;
	int ilock;
	loff_t size;
	struct page *page, *ipage;
	void *src_addr, *dst_addr;
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);

	if (!p->index)
		page = p;
	else
		page = grab_cache_page_write_begin(inode->i_mapping, 0, flags);

	if (IS_ERR(page))
		return PTR_ERR(page);

	ipage = get_node_page(sbi, inode->i_ino);
	if (IS_ERR(ipage)) {
		f2fs_put_page(page, 1);
		return PTR_ERR(ipage);
	}

	src_addr = page_address(ipage);
	dst_addr = page_address(page);

	size = i_size_read(inode);
	memcpy(dst_addr, src_addr + INLINE_DATA_OFFSET, size);
	zero_user_segment(ipage, INLINE_DATA_OFFSET,
			  INLINE_DATA_OFFSET + MAX_INLINE_DATA);
	clear_inode_dyn_flag(F2FS_I(inode), F2FS_INLINE_DATA_FL);
	set_page_dirty(ipage);
	f2fs_put_page(ipage, 1);

	if (!p->index) {
		SetPageUptodate(page);
	} else {
		ilock = mutex_lock_op(sbi);
		err = f2fs_reserve_block(inode, 0);
		if (err)
			goto err;
		mutex_unlock_op(sbi, ilock);

		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}

	return 0;

err:
	mutex_unlock_op(sbi, ilock);
	f2fs_put_page(page, 1);
	return err;
}

int f2fs_write_inline_data(struct inode *inode,
			   struct page *page, unsigned size)
{
	void *src_addr, *dst_addr;
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	struct page *ipage = get_node_page(sbi, inode->i_ino);

	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	src_addr = page_address(page);
	dst_addr = page_address(ipage);

	memcpy(dst_addr + INLINE_DATA_OFFSET, src_addr, size);
	clear_inode_dyn_flag(F2FS_I(inode), F2FS_INLINE_DATA_ATTEMPT);
	if (!f2fs_has_inline_data(inode))
		set_inode_dyn_flag(F2FS_I(inode), F2FS_INLINE_DATA_FL);
	set_page_dirty(ipage);
	f2fs_put_page(ipage, 1);

	return 0;
}
