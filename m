Return-Path: <kasan-dev+bncBC42V7FQ3YARBRFMRGLAMGQEAIMGRJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f64.google.com (mail-lf1-f64.google.com [209.85.167.64])
	by mail.lfdr.de (Postfix) with ESMTPS id E1BB2564BE8
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 04:53:57 +0200 (CEST)
Received: by mail-lf1-f64.google.com with SMTP id bp15-20020a056512158f00b0047f603e5f92sf2512993lfb.20
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jul 2022 19:53:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656903237; cv=pass;
        d=google.com; s=arc-20160816;
        b=ks4giwl220Upv2cw0Qlmc9qhL+p0QHwnnkiN0kv16uSTLlHMJTGKGrCdExzcmr1PBv
         2Kh3gyfvYjAnahjq3UemeMjpG91MYXFES03LDliYxQ9uGxyT2VpuH3pmZ2X74xiI5yWf
         lwxMuYcH2kDndY9pJ1pOKQisP+MlaNCbhjlDFEknWwC+ipO/Alsw8kngETbN8Dj+XZyB
         IDwJZhw8vnWf0CooCYx6JxI/ykd3lsDF8lNbahTlHxMdq5DlWCxyPYnfxWcyJ1EL5WU4
         sF2RlaeiA4mScOSsEqLYs4c9P/7cmPiGf2wdbh2rKGS2dXVweIDOPO5DstNkkKCVzYDQ
         naQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=R/353jVDro2M2Xg5VASGD0b1CN0OehIZWtiatxcixd4=;
        b=o6/pSFqaAqcV7hvUkQVc8B8n9s8tlaVwxEV3UDMIByTZB5Z9VjtsO0YcKSs3Zk7T7D
         DV+r4ixNes1pgyym4b2dtXuQxj+DMskHsz7JYNUtX2JaI5r1SjCR3/N/+kjpEqNftFUC
         DFIfRsftSbEim5Px+9qZrRvPBWeBBzq3ici854nkcHso0BEu9ftcKhUZ5yN7oN0MwaKF
         ywTx5Lh8FgL1UdHyjY4pd9Pp1b2LIcZG+7NkZVbXoBiHEmpBRRORsNOjj0tLr9Bo2RrY
         nZm9bHk62R8AQkAed5uUBzfBaWr0+q5fyvVULezuvztl9IvTglkbmb0iUIXApjyUeo0s
         LqAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=a6Wr3eXa;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R/353jVDro2M2Xg5VASGD0b1CN0OehIZWtiatxcixd4=;
        b=A5T8IdIqYaXMQlzBH79FWR2+o3JnE20lT9QQyyDA8SoBZbOWQsJYumrg5KYnU8yPQk
         afSLlWi/qFRAKi5pzj6/xlRX9hZWLrpUzjfhntta1riur6S7nAOasCF+CU//t3OS9jwa
         SvE9UNY9+dDQcIZFHVgV6IwY58oi5f718QBfjis8N0oqyobvDbgQaGVaNs8LOGGmY5V/
         E+WE81v736uKpxCwMS/Hof3HL6mpbd3J1DKO5QHd6dm4dJLrmLFIH+dvQfkJN8NtsKcA
         9IENoQRSF+wUyTLiyPUZU3brL9NgOrV5xjQjERKLFVSYHfup1ZRtqZ6iL+j8kuBGzgIp
         JFhw==
X-Gm-Message-State: AJIora97oGJoNhWpit6nL8l9ShNyR3sr2dgWef2/RxEgvhkUWAVWnZrU
	R5XRFzo3fYGtp1Sv+ygk6EE=
X-Google-Smtp-Source: AGRyM1tOtYRh5CQao7lUZRwr+5AHXdmmmL4Kvpe30+AxbA5GOuqpXNQErtpJU7X0rjHUTSOxurDq9A==
X-Received: by 2002:a05:651c:987:b0:25b:ce6b:1a9 with SMTP id b7-20020a05651c098700b0025bce6b01a9mr16147252ljq.275.1656903236956;
        Sun, 03 Jul 2022 19:53:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls3168393lfb.1.gmail; Sun, 03 Jul 2022
 19:53:55 -0700 (PDT)
X-Received: by 2002:a05:6512:acc:b0:47f:769e:6aef with SMTP id n12-20020a0565120acc00b0047f769e6aefmr16324561lfu.26.1656903235446;
        Sun, 03 Jul 2022 19:53:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656903235; cv=none;
        d=google.com; s=arc-20160816;
        b=GshVLbY7BDJQlomOayjMHaMFr3TQlpWe/xKQQRaXvNuo57aZwzPNlMxPS7kYIXSm2j
         +awKxGeeo8nJEZjaN2H0/rskC9Bn0r3FbNDmG6w3+41gMrteYAGVEsQw4uX3F59yd5Du
         qLhNmx6Iih+h43/HPNQomJcCEoVD66jurcbXt/bAmOUeOYln4ASdGYisn0+7ps+UVzg3
         yFg/zaIVqqQ8TRwWiwYLDJky4UpucwyQKkJlXNya14GhYeMvPJMwDQAmIxG2dF2kSwYd
         a19bbpIGbFb3J2ol8TasAa8OWfTa6n955yJn9fGpkEGt2YuxK+RBBn3dbt7w3dmElC2A
         crYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=vO9e4FK09OExUNkGvxoa/0O9s2rDe2YLeW0ZmG6+6Kg=;
        b=JS6cGBob81me/o2QDKe6onqh8hqDZL1WIIidHi5N2vmLNAZ4d7xdCZuqzfGeU18vqk
         +qHghblfSBTQ/d1g/aE7E+zN6KVw4vOMsII1Z1qxwGF06aocnZSQFVUo0Tgkel3DSNRX
         ivMzAH2VnrJaK3a+RptArEous4awMHbzSJfU6/26HL2m++5iwMMjGbuaQLpNGacqXSw9
         A79AIkwT0KCA1IBgS8X3KUbi06JgS1yfDw+dIZVHCEZlHe7cYUyqTLfxcPHuSnkxwXHK
         bf+AaE+zHuh365gEEtyN8BUejQJT+EaNoN+KHE5d5qoGlAODtD8MajV7zBG30WND6/jQ
         MrUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=a6Wr3eXa;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si1054259ljo.8.2022.07.03.19.53.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jul 2022 19:53:54 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8CCn-007r8W-Fz;
	Mon, 04 Jul 2022 02:52:57 +0000
Date: Mon, 4 Jul 2022 03:52:57 +0100
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
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to
 step_into()
Message-ID: <YsJWCREA5xMfmmqx@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=a6Wr3eXa;
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

On Sat, Jul 02, 2022 at 10:23:16AM -0700, Linus Torvalds wrote:

> Al - can you please take a quick look?

FWIW, trying to write a coherent documentation had its usual effect...
The thing is, we don't really need to fetch the inode that early.
All we really care about is that in RCU mode ->d_seq gets sampled
before we fetch ->d_inode *and* we don't treat "it looks negative"
as hard -ENOENT in case of ->d_seq mismatch.

Which can be bloody well left to step_into().  So we don't need
to pass it inode argument at all - just dentry and seq.  Makes
a bunch of functions simpler as well...

It does *not* deal with the "uninitialized" seq argument in
!RCU case; I'll handle that in the followup, but that's a separate
story, IMO (and very clearly a false positive).

Cumulative diff follows; splitup is in #work.namei.  Comments?

diff --git a/fs/namei.c b/fs/namei.c
index 1f28d3f463c3..7f4f61ade9e3 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1467,7 +1467,7 @@ EXPORT_SYMBOL(follow_down);
  * we meet a managed dentry that would need blocking.
  */
 static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
-			       struct inode **inode, unsigned *seqp)
+			       unsigned *seqp)
 {
 	struct dentry *dentry = path->dentry;
 	unsigned int flags = dentry->d_flags;
@@ -1497,13 +1497,6 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				dentry = path->dentry = mounted->mnt.mnt_root;
 				nd->state |= ND_JUMPED;
 				*seqp = read_seqcount_begin(&dentry->d_seq);
-				*inode = dentry->d_inode;
-				/*
-				 * We don't need to re-check ->d_seq after this
-				 * ->d_inode read - there will be an RCU delay
-				 * between mount hash removal and ->mnt_root
-				 * becoming unpinned.
-				 */
 				flags = dentry->d_flags;
 				continue;
 			}
@@ -1515,8 +1508,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 }
 
 static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
-			  struct path *path, struct inode **inode,
-			  unsigned int *seqp)
+			  struct path *path, unsigned int *seqp)
 {
 	bool jumped;
 	int ret;
@@ -1525,9 +1517,7 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 	path->dentry = dentry;
 	if (nd->flags & LOOKUP_RCU) {
 		unsigned int seq = *seqp;
-		if (unlikely(!*inode))
-			return -ENOENT;
-		if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
+		if (likely(__follow_mount_rcu(nd, path, seqp)))
 			return 0;
 		if (!try_to_unlazy_next(nd, dentry, seq))
 			return -ECHILD;
@@ -1547,7 +1537,6 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 		if (path->mnt != nd->path.mnt)
 			mntput(path->mnt);
 	} else {
-		*inode = d_backing_inode(path->dentry);
 		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
 	}
 	return ret;
@@ -1607,9 +1596,7 @@ static struct dentry *__lookup_hash(const struct qstr *name,
 	return dentry;
 }
 
-static struct dentry *lookup_fast(struct nameidata *nd,
-				  struct inode **inode,
-			          unsigned *seqp)
+static struct dentry *lookup_fast(struct nameidata *nd, unsigned *seqp)
 {
 	struct dentry *dentry, *parent = nd->path.dentry;
 	int status = 1;
@@ -1628,22 +1615,11 @@ static struct dentry *lookup_fast(struct nameidata *nd,
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
 
 		*seqp = seq;
@@ -1838,13 +1814,21 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
  * for the common case.
  */
 static const char *step_into(struct nameidata *nd, int flags,
-		     struct dentry *dentry, struct inode *inode, unsigned seq)
+		     struct dentry *dentry, unsigned seq)
 {
 	struct path path;
-	int err = handle_mounts(nd, dentry, &path, &inode, &seq);
+	struct inode *inode;
+	int err = handle_mounts(nd, dentry, &path, &seq);
 
 	if (err < 0)
 		return ERR_PTR(err);
+	inode = path.dentry->d_inode;
+	if (unlikely(!inode)) {
+		if ((nd->flags & LOOKUP_RCU) &&
+		    read_seqcount_retry(&path.dentry->d_seq, seq))
+			return ERR_PTR(-ECHILD);
+		return ERR_PTR(-ENOENT);
+	}
 	if (likely(!d_is_symlink(path.dentry)) ||
 	   ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
 	   (flags & WALK_NOFOLLOW)) {
@@ -1870,9 +1854,7 @@ static const char *step_into(struct nameidata *nd, int flags,
 	return pick_link(nd, &path, inode, seq, flags);
 }
 
-static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
-					struct inode **inodep,
-					unsigned *seqp)
+static struct dentry *follow_dotdot_rcu(struct nameidata *nd, unsigned *seqp)
 {
 	struct dentry *parent, *old;
 
@@ -1895,7 +1877,6 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	}
 	old = nd->path.dentry;
 	parent = old->d_parent;
-	*inodep = parent->d_inode;
 	*seqp = read_seqcount_begin(&parent->d_seq);
 	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
 		return ERR_PTR(-ECHILD);
@@ -1910,9 +1891,7 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	return NULL;
 }
 
-static struct dentry *follow_dotdot(struct nameidata *nd,
-				 struct inode **inodep,
-				 unsigned *seqp)
+static struct dentry *follow_dotdot(struct nameidata *nd, unsigned *seqp)
 {
 	struct dentry *parent;
 
@@ -1937,7 +1916,6 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
 		return ERR_PTR(-ENOENT);
 	}
 	*seqp = 0;
-	*inodep = parent->d_inode;
 	return parent;
 
 in_root:
@@ -1952,7 +1930,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 	if (type == LAST_DOTDOT) {
 		const char *error = NULL;
 		struct dentry *parent;
-		struct inode *inode;
 		unsigned seq;
 
 		if (!nd->root.mnt) {
@@ -1961,17 +1938,17 @@ static const char *handle_dots(struct nameidata *nd, int type)
 				return error;
 		}
 		if (nd->flags & LOOKUP_RCU)
-			parent = follow_dotdot_rcu(nd, &inode, &seq);
+			parent = follow_dotdot_rcu(nd, &seq);
 		else
-			parent = follow_dotdot(nd, &inode, &seq);
+			parent = follow_dotdot(nd, &seq);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
 		if (unlikely(!parent))
 			error = step_into(nd, WALK_NOFOLLOW,
-					 nd->path.dentry, nd->inode, nd->seq);
+					 nd->path.dentry, nd->seq);
 		else
 			error = step_into(nd, WALK_NOFOLLOW,
-					 parent, inode, seq);
+					 parent, seq);
 		if (unlikely(error))
 			return error;
 
@@ -1995,7 +1972,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
-	struct inode *inode;
 	unsigned seq;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
@@ -2007,7 +1983,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 			put_link(nd);
 		return handle_dots(nd, nd->last_type);
 	}
-	dentry = lookup_fast(nd, &inode, &seq);
+	dentry = lookup_fast(nd, &seq);
 	if (IS_ERR(dentry))
 		return ERR_CAST(dentry);
 	if (unlikely(!dentry)) {
@@ -2017,7 +1993,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 	}
 	if (!(flags & WALK_MORE) && nd->depth)
 		put_link(nd);
-	return step_into(nd, flags, dentry, inode, seq);
+	return step_into(nd, flags, dentry, seq);
 }
 
 /*
@@ -2473,8 +2449,7 @@ static int handle_lookup_down(struct nameidata *nd)
 {
 	if (!(nd->flags & LOOKUP_RCU))
 		dget(nd->path.dentry);
-	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
-			nd->path.dentry, nd->inode, nd->seq));
+	return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry, nd->seq));
 }
 
 /* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
@@ -3394,7 +3369,6 @@ static const char *open_last_lookups(struct nameidata *nd,
 	int open_flag = op->open_flag;
 	bool got_write = false;
 	unsigned seq;
-	struct inode *inode;
 	struct dentry *dentry;
 	const char *res;
 
@@ -3410,7 +3384,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 		if (nd->last.name[nd->last.len])
 			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
 		/* we _can_ be in RCU mode here */
-		dentry = lookup_fast(nd, &inode, &seq);
+		dentry = lookup_fast(nd, &seq);
 		if (IS_ERR(dentry))
 			return ERR_CAST(dentry);
 		if (likely(dentry))
@@ -3464,7 +3438,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 finish_lookup:
 	if (nd->depth)
 		put_link(nd);
-	res = step_into(nd, WALK_TRAILING, dentry, inode, seq);
+	res = step_into(nd, WALK_TRAILING, dentry, seq);
 	if (unlikely(res))
 		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
 	return res;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsJWCREA5xMfmmqx%40ZenIV.
