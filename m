Return-Path: <kasan-dev+bncBC42V7FQ3YARBP7LRWLAMGQE7PZGJ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f190.google.com (mail-lj1-f190.google.com [209.85.208.190])
	by mail.lfdr.de (Postfix) with ESMTPS id 78901565FB3
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:20:32 +0200 (CEST)
Received: by mail-lj1-f190.google.com with SMTP id g25-20020a2e9e59000000b0025baf0470fesf3014967ljk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:20:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976832; cv=pass;
        d=google.com; s=arc-20160816;
        b=g9z9mpAeptmweiQ77cSmPZUyhMsHD79Y8IpmmVkU6pSBpgKaV9D0Up1YhsSgfdrHPk
         gDCDv9McBwFk5JqFLwIRS9wk960oHIP5vRjhYH+P5K5cFbLT4PLmJxMCfgeQvMVjhxf5
         ujl7YuiEZU1p0MrOfs3VXUV913jawkh0TuXRN/oPhM5sWmGDMylqoRVYGouVdj+vwRPD
         TNTlD7hIAIzsm/LH/1vof9uJSnJ7znv217DTx3LYnev+1+Qfxjox609jCyjv9EclShqj
         vCKDA+hKCumENxNz24RyY6qedBykxHc2+SKzmw8H0remt2SLPseDCMcCZKUJWxe6d6Q0
         lucA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=nhCBq4HsROi6j6vfpSk0YZcKCbmLVMSbggLSJ9RLju4=;
        b=ScG1NbZSOkoA46rCtvTI1BL94Ksfmumf/1GnPEuQBJAvYxL+L8cqfa2hjWGvU8ytyn
         Jga8NGo9tCIe0DmSLw7oEzbagWqSGVnIaaE6V00Fd5konypJQKD1QDGLW7FsYIEhtZ6u
         1D5NWiqMHWsCa8wqYE6GZH6/8yBZB/hqFzwb2JyAYzx2MVZukQgvSTWm400IeRQFF8P9
         llzPRDCOpvbRQzMNkZIaxI/HDl04V4+7jwZuww2/FoFusNRVu43thV9amIFZNGnf7o/4
         mkXi/61GobipR1/Se/dkABJCqpUM4HuYxRNuvkSMh3dWymhDou3mq9TbB+uMjCeK8+52
         m2MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=n5GfKHxk;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nhCBq4HsROi6j6vfpSk0YZcKCbmLVMSbggLSJ9RLju4=;
        b=JOCrvSlxVa38YXSJF7S/1qP1zpIeDz0wyZGzhmRXG+v/BPCxwGQLfrMA3ms7UIF+7p
         4uzh7aV+g/uLWU0jaUm5A7bxvFkIxMKePQtU50ymt1I3lZS0kuGd3uY+Z12R68njK1pd
         EEligXXI5+mU2Gu9NTx8DmYYobSGUPg6a2ixA/yiAtessWsYSosAgWQPJAsfhGTxsA0s
         XZJ7dOCuOse6w1k/2pnxaowd1SzNOhryaZwGMZEDomdmaMbQ5LbhW1mzsXTfDO6aYJXb
         LCjNjevpkh/oYcuV4H08vA21WTBvm2+ddFvhCF1h+lzp2vX5a4bXMpYuUAWZPSx58oSg
         ctWA==
X-Gm-Message-State: AJIora9Bc35pegaKLbNZfgoF0sCEXfuWUbFwrouJdxS0v7GrV7n2iDRT
	5JTSONoGDY2LqMwRrPhdzyc=
X-Google-Smtp-Source: AGRyM1vlPoDZl9xY0Eh48CCoRNRo1XJQiY83kVClgVGWlCeYYlIU8zoMT7NxfP3mk4tPMVX0KlYw9A==
X-Received: by 2002:a05:6512:3b09:b0:483:7ec3:cba1 with SMTP id f9-20020a0565123b0900b004837ec3cba1mr128427lfv.113.1656976832044;
        Mon, 04 Jul 2022 16:20:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238e:b0:481:2fa:2826 with SMTP id
 c14-20020a056512238e00b0048102fa2826ls203004lfv.0.gmail; Mon, 04 Jul 2022
 16:20:30 -0700 (PDT)
X-Received: by 2002:a05:6512:3f10:b0:47f:42ae:c0fc with SMTP id y16-20020a0565123f1000b0047f42aec0fcmr19483774lfa.688.1656976830706;
        Mon, 04 Jul 2022 16:20:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976830; cv=none;
        d=google.com; s=arc-20160816;
        b=nxki9ZQx+CSIr8HA8z1FBrhyKRkJGv2hBkk7r9TbHD0jHQJi/Z/bZMQOALcq/RWjOd
         YSXqFgxMHW43T7Bmz3ujORLTYzE6d6p5M+i8kA4sWJh4W+Riamq50DwpnMelkG3aumqX
         JHGOhoOkYsLLe35KjCxYlU1z/FATGm/+wXjDioCQLYZ3uVV8xaI7WRnCG0pKETijBUbN
         QH+AET0JyDoYXEkm9TeOZ3XRFcxVLwpdB7pzYFXN5iYcnrDeaqiSt+GRbZTpmJtXadeP
         C9OoTjAYdkdd0wMuxbdcTjTb6kizeDH3tg9RBIplb5uvzLl5bcglQ2ChUNQj/piA23v1
         wbgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZXbvLYuQek+nCVjr7grEEvJKDaLQpWJKjOeNxyQtcLo=;
        b=Lb9YwnxsI4NRUNtpo4wxCHqsZoRziP1N/zrXKyak1Rr/5rExx3QP3LDG84AGh/LbTt
         ZhxD2HHYnjO7nnxKRy7PA1bWVWSMgw/pImlm2ac61vGkmj2gKfxAckSYNOcGlu9YJoV0
         0f+F7xwBYwyOJQH2Z99spf8fjFlRBKpLB0VJpkzB83SnNzvvrI9jEg5LvKA8FGGYKG1M
         uSkUhpDywd7qRgOxAL05jukiB/9jvMJjBsdp4U+8vWRF6BGGsCprzuUtw0pRcOyxKZzW
         W8WRLY4CPSSuwpzTCe5QFZYr8lI8GhemFSan/toNF5q9i6b4H9+4SXi7jcN5e+LzLJMw
         Fs0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=n5GfKHxk;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si1146959ljo.8.2022.07.04.16.20.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:20:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VM1-008Aid-7w;
	Mon, 04 Jul 2022 23:19:45 +0000
Date: Tue, 5 Jul 2022 00:19:45 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Segher Boessenkool <segher@kernel.crashing.org>,
	Vitaly Buka <vitalybuka@google.com>,
	linux-toolchains <linux-toolchains@vger.kernel.org>
Subject: Re: [PATCH 1/7] __follow_mount_rcu(): verify that mount_lock remains
 unchanged
Message-ID: <YsN1kfBsfMdH+eiU@ZenIV>
References: <YsJWCREA5xMfmmqx@ZenIV>
 <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
 <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
 <YsNFoH0+N+KCt5kg@ZenIV>
 <CAHk-=whp8Npc+vMcgbpM9mrPEXkhV4YnhsPxbPXSu9gfEhKWmA@mail.gmail.com>
 <YsNRsgOl04r/RCNe@ZenIV>
 <CAHk-=wih_JHVPvp1qyW4KNK0ctTc6e+bDj4wdTgNkyND6tuFoQ@mail.gmail.com>
 <YsNVyLxrNRFpufn8@ZenIV>
 <YsN0GURKuaAqXB/e@ZenIV>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YsN0GURKuaAqXB/e@ZenIV>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=n5GfKHxk;
       spf=pass (google.com: best guess record for domain of
 viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted
 sender) smtp.mailfrom=viro@ftp.linux.org.uk;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zeniv.linux.org.uk
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

	Just in case - this series is RFC only; it's very lightly
tested.  Might be carved into too many steps, at that.  Cumulative
delta follows; might or might not be more convenient for review.

diff --git a/fs/namei.c b/fs/namei.c
index 1f28d3f463c3..f2c99e75b578 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -567,7 +567,7 @@ struct nameidata {
 	struct path	root;
 	struct inode	*inode; /* path.dentry.d_inode */
 	unsigned int	flags, state;
-	unsigned	seq, m_seq, r_seq;
+	unsigned	seq, next_seq, m_seq, r_seq;
 	int		last_type;
 	unsigned	depth;
 	int		total_link_count;
@@ -772,6 +772,7 @@ static bool try_to_unlazy(struct nameidata *nd)
 		goto out;
 	if (unlikely(!legitimize_root(nd)))
 		goto out;
+	nd->seq = nd->next_seq = 0;
 	rcu_read_unlock();
 	BUG_ON(nd->inode != parent->d_inode);
 	return true;
@@ -780,6 +781,7 @@ static bool try_to_unlazy(struct nameidata *nd)
 	nd->path.mnt = NULL;
 	nd->path.dentry = NULL;
 out:
+	nd->seq = nd->next_seq = 0;
 	rcu_read_unlock();
 	return false;
 }
@@ -788,7 +790,6 @@ static bool try_to_unlazy(struct nameidata *nd)
  * try_to_unlazy_next - try to switch to ref-walk mode.
  * @nd: nameidata pathwalk data
  * @dentry: next dentry to step into
- * @seq: seq number to check @dentry against
  * Returns: true on success, false on failure
  *
  * Similar to try_to_unlazy(), but here we have the next dentry already
@@ -797,7 +798,7 @@ static bool try_to_unlazy(struct nameidata *nd)
  * Nothing should touch nameidata between try_to_unlazy_next() failure and
  * terminate_walk().
  */
-static bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsigned seq)
+static bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry)
 {
 	BUG_ON(!(nd->flags & LOOKUP_RCU));
 
@@ -818,7 +819,7 @@ static bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsi
 	 */
 	if (unlikely(!lockref_get_not_dead(&dentry->d_lockref)))
 		goto out;
-	if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
+	if (unlikely(read_seqcount_retry(&dentry->d_seq, nd->next_seq)))
 		goto out_dput;
 	/*
 	 * Sequence counts matched. Now make sure that the root is
@@ -826,6 +827,7 @@ static bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsi
 	 */
 	if (unlikely(!legitimize_root(nd)))
 		goto out_dput;
+	nd->seq = nd->next_seq = 0;
 	rcu_read_unlock();
 	return true;
 
@@ -834,9 +836,11 @@ static bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsi
 out1:
 	nd->path.dentry = NULL;
 out:
+	nd->seq = nd->next_seq = 0;
 	rcu_read_unlock();
 	return false;
 out_dput:
+	nd->seq = nd->next_seq = 0;
 	rcu_read_unlock();
 	dput(dentry);
 	return false;
@@ -1466,8 +1470,7 @@ EXPORT_SYMBOL(follow_down);
  * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
  * we meet a managed dentry that would need blocking.
  */
-static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
-			       struct inode **inode, unsigned *seqp)
+static bool __follow_mount_rcu(struct nameidata *nd, struct path *path)
 {
 	struct dentry *dentry = path->dentry;
 	unsigned int flags = dentry->d_flags;
@@ -1496,15 +1499,12 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				path->mnt = &mounted->mnt;
 				dentry = path->dentry = mounted->mnt.mnt_root;
 				nd->state |= ND_JUMPED;
-				*seqp = read_seqcount_begin(&dentry->d_seq);
-				*inode = dentry->d_inode;
-				/*
-				 * We don't need to re-check ->d_seq after this
-				 * ->d_inode read - there will be an RCU delay
-				 * between mount hash removal and ->mnt_root
-				 * becoming unpinned.
-				 */
+				nd->next_seq = read_seqcount_begin(&dentry->d_seq);
 				flags = dentry->d_flags;
+				// makes sure that non-RCU pathwalk could reach
+				// this state.
+				if (read_seqretry(&mount_lock, nd->m_seq))
+					return false;
 				continue;
 			}
 			if (read_seqretry(&mount_lock, nd->m_seq))
@@ -1515,8 +1515,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 }
 
 static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
-			  struct path *path, struct inode **inode,
-			  unsigned int *seqp)
+			  struct path *path)
 {
 	bool jumped;
 	int ret;
@@ -1524,16 +1523,15 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 	path->mnt = nd->path.mnt;
 	path->dentry = dentry;
 	if (nd->flags & LOOKUP_RCU) {
-		unsigned int seq = *seqp;
-		if (unlikely(!*inode))
-			return -ENOENT;
-		if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
+		unsigned int seq = nd->next_seq;
+		if (likely(__follow_mount_rcu(nd, path)))
 			return 0;
-		if (!try_to_unlazy_next(nd, dentry, seq))
-			return -ECHILD;
-		// *path might've been clobbered by __follow_mount_rcu()
+		// *path and nd->next_seq might've been clobbered
 		path->mnt = nd->path.mnt;
 		path->dentry = dentry;
+		nd->next_seq = seq;
+		if (!try_to_unlazy_next(nd, dentry))
+			return -ECHILD;
 	}
 	ret = traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
 	if (jumped) {
@@ -1546,9 +1544,6 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 		dput(path->dentry);
 		if (path->mnt != nd->path.mnt)
 			mntput(path->mnt);
-	} else {
-		*inode = d_backing_inode(path->dentry);
-		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
 	}
 	return ret;
 }
@@ -1607,9 +1602,7 @@ static struct dentry *__lookup_hash(const struct qstr *name,
 	return dentry;
 }
 
-static struct dentry *lookup_fast(struct nameidata *nd,
-				  struct inode **inode,
-			          unsigned *seqp)
+static struct dentry *lookup_fast(struct nameidata *nd)
 {
 	struct dentry *dentry, *parent = nd->path.dentry;
 	int status = 1;
@@ -1620,37 +1613,24 @@ static struct dentry *lookup_fast(struct nameidata *nd,
 	 * going to fall back to non-racy lookup.
 	 */
 	if (nd->flags & LOOKUP_RCU) {
-		unsigned seq;
-		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
+		dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
 		if (unlikely(!dentry)) {
 			if (!try_to_unlazy(nd))
 				return ERR_PTR(-ECHILD);
 			return NULL;
 		}
 
-		/*
-		 * This sequence count validates that the inode matches
-		 * the dentry name information from lookup.
-		 */
-		*inode = d_backing_inode(dentry);
-		if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
-			return ERR_PTR(-ECHILD);
-
-		/*
+	        /*
 		 * This sequence count validates that the parent had no
 		 * changes while we did the lookup of the dentry above.
-		 *
-		 * The memory barrier in read_seqcount_begin of child is
-		 *  enough, we can use __read_seqcount_retry here.
 		 */
-		if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
+		if (unlikely(read_seqcount_retry(&parent->d_seq, nd->seq)))
 			return ERR_PTR(-ECHILD);
 
-		*seqp = seq;
 		status = d_revalidate(dentry, nd->flags);
 		if (likely(status > 0))
 			return dentry;
-		if (!try_to_unlazy_next(nd, dentry, seq))
+		if (!try_to_unlazy_next(nd, dentry))
 			return ERR_PTR(-ECHILD);
 		if (status == -ECHILD)
 			/* we'd been told to redo it in non-rcu mode */
@@ -1731,7 +1711,7 @@ static inline int may_lookup(struct user_namespace *mnt_userns,
 	return inode_permission(mnt_userns, nd->inode, MAY_EXEC);
 }
 
-static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
+static int reserve_stack(struct nameidata *nd, struct path *link)
 {
 	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS))
 		return -ELOOP;
@@ -1746,7 +1726,7 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
 	if (nd->flags & LOOKUP_RCU) {
 		// we need to grab link before we do unlazy.  And we can't skip
 		// unlazy even if we fail to grab the link - cleanup needs it
-		bool grabbed_link = legitimize_path(nd, link, seq);
+		bool grabbed_link = legitimize_path(nd, link, nd->next_seq);
 
 		if (!try_to_unlazy(nd) || !grabbed_link)
 			return -ECHILD;
@@ -1760,11 +1740,11 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
 enum {WALK_TRAILING = 1, WALK_MORE = 2, WALK_NOFOLLOW = 4};
 
 static const char *pick_link(struct nameidata *nd, struct path *link,
-		     struct inode *inode, unsigned seq, int flags)
+		     struct inode *inode, int flags)
 {
 	struct saved *last;
 	const char *res;
-	int error = reserve_stack(nd, link, seq);
+	int error = reserve_stack(nd, link);
 
 	if (unlikely(error)) {
 		if (!(nd->flags & LOOKUP_RCU))
@@ -1774,7 +1754,7 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
 	last = nd->stack + nd->depth++;
 	last->link = *link;
 	clear_delayed_call(&last->done);
-	last->seq = seq;
+	last->seq = nd->next_seq;
 
 	if (flags & WALK_TRAILING) {
 		error = may_follow_link(nd, inode);
@@ -1836,43 +1816,50 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
  * to do this check without having to look at inode->i_op,
  * so we keep a cache of "no, this doesn't need follow_link"
  * for the common case.
+ *
+ * NOTE: dentry must be what nd->next_seq had been sampled from.
  */
 static const char *step_into(struct nameidata *nd, int flags,
-		     struct dentry *dentry, struct inode *inode, unsigned seq)
+		     struct dentry *dentry)
 {
 	struct path path;
-	int err = handle_mounts(nd, dentry, &path, &inode, &seq);
+	struct inode *inode;
+	int err = handle_mounts(nd, dentry, &path);
 
 	if (err < 0)
 		return ERR_PTR(err);
+	inode = path.dentry->d_inode;
 	if (likely(!d_is_symlink(path.dentry)) ||
 	   ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
 	   (flags & WALK_NOFOLLOW)) {
 		/* not a symlink or should not follow */
-		if (!(nd->flags & LOOKUP_RCU)) {
+		if (nd->flags & LOOKUP_RCU) {
+			if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
+				return ERR_PTR(-ECHILD);
+			if (unlikely(!inode))
+				return ERR_PTR(-ENOENT);
+		} else {
 			dput(nd->path.dentry);
 			if (nd->path.mnt != path.mnt)
 				mntput(nd->path.mnt);
 		}
 		nd->path = path;
 		nd->inode = inode;
-		nd->seq = seq;
+		nd->seq = nd->next_seq;
 		return NULL;
 	}
 	if (nd->flags & LOOKUP_RCU) {
 		/* make sure that d_is_symlink above matches inode */
-		if (read_seqcount_retry(&path.dentry->d_seq, seq))
+		if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
 			return ERR_PTR(-ECHILD);
 	} else {
 		if (path.mnt == nd->path.mnt)
 			mntget(path.mnt);
 	}
-	return pick_link(nd, &path, inode, seq, flags);
+	return pick_link(nd, &path, inode, flags);
 }
 
-static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
-					struct inode **inodep,
-					unsigned *seqp)
+static struct dentry *follow_dotdot_rcu(struct nameidata *nd)
 {
 	struct dentry *parent, *old;
 
@@ -1889,14 +1876,15 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 		nd->path = path;
 		nd->inode = path.dentry->d_inode;
 		nd->seq = seq;
+		// makes sure that non-RCU pathwalk could reach this state
 		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
 			return ERR_PTR(-ECHILD);
 		/* we know that mountpoint was pinned */
 	}
 	old = nd->path.dentry;
 	parent = old->d_parent;
-	*inodep = parent->d_inode;
-	*seqp = read_seqcount_begin(&parent->d_seq);
+	nd->next_seq = read_seqcount_begin(&parent->d_seq);
+	// makes sure that non-RCU pathwalk could reach this state
 	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
 		return ERR_PTR(-ECHILD);
 	if (unlikely(!path_connected(nd->path.mnt, parent)))
@@ -1907,12 +1895,11 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 		return ERR_PTR(-ECHILD);
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-ECHILD);
-	return NULL;
+	nd->next_seq = nd->seq;
+	return nd->path.dentry;
 }
 
-static struct dentry *follow_dotdot(struct nameidata *nd,
-				 struct inode **inodep,
-				 unsigned *seqp)
+static struct dentry *follow_dotdot(struct nameidata *nd)
 {
 	struct dentry *parent;
 
@@ -1936,15 +1923,12 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
 		dput(parent);
 		return ERR_PTR(-ENOENT);
 	}
-	*seqp = 0;
-	*inodep = parent->d_inode;
 	return parent;
 
 in_root:
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-EXDEV);
-	dget(nd->path.dentry);
-	return NULL;
+	return dget(nd->path.dentry);
 }
 
 static const char *handle_dots(struct nameidata *nd, int type)
@@ -1952,8 +1936,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 	if (type == LAST_DOTDOT) {
 		const char *error = NULL;
 		struct dentry *parent;
-		struct inode *inode;
-		unsigned seq;
 
 		if (!nd->root.mnt) {
 			error = ERR_PTR(set_root(nd));
@@ -1961,17 +1943,12 @@ static const char *handle_dots(struct nameidata *nd, int type)
 				return error;
 		}
 		if (nd->flags & LOOKUP_RCU)
-			parent = follow_dotdot_rcu(nd, &inode, &seq);
+			parent = follow_dotdot_rcu(nd);
 		else
-			parent = follow_dotdot(nd, &inode, &seq);
+			parent = follow_dotdot(nd);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
-		if (unlikely(!parent))
-			error = step_into(nd, WALK_NOFOLLOW,
-					 nd->path.dentry, nd->inode, nd->seq);
-		else
-			error = step_into(nd, WALK_NOFOLLOW,
-					 parent, inode, seq);
+		error = step_into(nd, WALK_NOFOLLOW, parent);
 		if (unlikely(error))
 			return error;
 
@@ -1995,8 +1972,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
-	struct inode *inode;
-	unsigned seq;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
 	 * to be able to know about the current root directory and
@@ -2007,7 +1982,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 			put_link(nd);
 		return handle_dots(nd, nd->last_type);
 	}
-	dentry = lookup_fast(nd, &inode, &seq);
+	dentry = lookup_fast(nd);
 	if (IS_ERR(dentry))
 		return ERR_CAST(dentry);
 	if (unlikely(!dentry)) {
@@ -2017,7 +1992,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 	}
 	if (!(flags & WALK_MORE) && nd->depth)
 		put_link(nd);
-	return step_into(nd, flags, dentry, inode, seq);
+	return step_into(nd, flags, dentry);
 }
 
 /*
@@ -2372,6 +2347,8 @@ static const char *path_init(struct nameidata *nd, unsigned flags)
 		flags &= ~LOOKUP_RCU;
 	if (flags & LOOKUP_RCU)
 		rcu_read_lock();
+	else
+		nd->seq = nd->next_seq = 0;
 
 	nd->flags = flags;
 	nd->state |= ND_JUMPED;
@@ -2473,8 +2450,8 @@ static int handle_lookup_down(struct nameidata *nd)
 {
 	if (!(nd->flags & LOOKUP_RCU))
 		dget(nd->path.dentry);
-	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
-			nd->path.dentry, nd->inode, nd->seq));
+	nd->next_seq = nd->seq;
+	return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry));
 }
 
 /* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
@@ -3393,8 +3370,6 @@ static const char *open_last_lookups(struct nameidata *nd,
 	struct dentry *dir = nd->path.dentry;
 	int open_flag = op->open_flag;
 	bool got_write = false;
-	unsigned seq;
-	struct inode *inode;
 	struct dentry *dentry;
 	const char *res;
 
@@ -3410,7 +3385,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 		if (nd->last.name[nd->last.len])
 			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
 		/* we _can_ be in RCU mode here */
-		dentry = lookup_fast(nd, &inode, &seq);
+		dentry = lookup_fast(nd);
 		if (IS_ERR(dentry))
 			return ERR_CAST(dentry);
 		if (likely(dentry))
@@ -3464,7 +3439,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 finish_lookup:
 	if (nd->depth)
 		put_link(nd);
-	res = step_into(nd, WALK_TRAILING, dentry, inode, seq);
+	res = step_into(nd, WALK_TRAILING, dentry);
 	if (unlikely(res))
 		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
 	return res;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN1kfBsfMdH%2BeiU%40ZenIV.
