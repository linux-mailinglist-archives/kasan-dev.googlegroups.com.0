Return-Path: <kasan-dev+bncBC42V7FQ3YARBRE5RSLAMGQEDFEZVOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f60.google.com (mail-lf1-f60.google.com [209.85.167.60])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DB03565A8F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 18:01:10 +0200 (CEST)
Received: by mail-lf1-f60.google.com with SMTP id br6-20020a056512400600b00482af9d63fasf882700lfb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 09:01:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656950470; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9sSnKpUCbiXXZaJ78o1z6cDLAl6SiW09GqWVQqcg8bZTO/mEfT1yObt8QgoNY2r/q
         zT8ViVm/OidM6+osxZ7wAMZu5dOCCqTGoHIeLCndxuFWkIe1Oe/5E9po5TDlTJ+xxrQ1
         8YZg/6jq/TGv4bWm+RvsGcKGRBYx2e5PYGRhDYOXkYi4xG09bBK3fDosTnHoZ612zulU
         ldzj1P9sLtMrJ5D4Xz5AI9i47ZWOU1q3KiFUQMJy2pNsWprdPMdBQqFVzUisf/retcFm
         Oo/R0Cz6UdP7EkopSPbGlc9qtk768h1e0LrfFiR32hBGzWz+nBYggiuyKwyABtqwg5S+
         91RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=DcxkOesSfRGunr2OR0qP2i1a5RR0BgQS33SF4RXnLWY=;
        b=pTr4jK/1s1iC4UCtALxHwqtxykO9W3lZQJTVgW0+K+CGc+BbQY3xvWh4e2sM4jbDPJ
         Wl0CIvrpnSfbUxKgz6Ww/jNfEZnQzJVHrodBXL6cVb9Y7xQzptLr132GgLRKe8WgJcnJ
         gn+WCs0XxOsuVWX0xA8TilixfHCKpFd5ayz7i+yMJg/kA8z3BuPSKg5oX1zwWmh+JRZQ
         gIIASvHzcKc9OhcjnkWu/bkiEqNFeErvp4jWqX44ifq/4a6rwvsiOt9YhM1C45dfz1ms
         LBEvIs8GsF2+4emvcf8okrU2Q+U4Xs0YbQvMnmunJmDFn70tY0p8ni51b9p+uAlqQM7a
         7IxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=vyIOd2yM;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DcxkOesSfRGunr2OR0qP2i1a5RR0BgQS33SF4RXnLWY=;
        b=JY5x7uvp+jygcxbV/s0p7HCp830WcTSfjXz4VfnBQNNdx18gWHcO65fs/oLqzC6Y2u
         UlMEQbHT7jZWkcl+KBGmwnHq08xZ5VXpItZVTBlqI/pKGShTcfK7iBxHWSk18VZb3QuX
         Lwy4Iz125gylPmV00A8nTqq8K5se9lSTiEIRVWzT05WxI6uu+lN0SEBUjfhuWxAzlL1T
         Z+5DyYsBpsADCl7TLRTLcJc3rVc7V50RVYXLzSVFBF3hcq1OfjTHnGWYYlxJmdKhT6s9
         SCpVpHM96vGTNKTNhPZpZ32959fgPoOVnNNLMvFpY06KRUe4nTSa1HklXTTkasUXFC+3
         2l3g==
X-Gm-Message-State: AJIora9NfD0X1jpJQqnttRK3GQj2KLOzugT+7mpHVHxCUZVoOMrQwJDd
	uRjo/J9c2hkkbstKUoFJQkY=
X-Google-Smtp-Source: AGRyM1v4Ggr8PB3Nmw43aw9A+v7JFu5ekj6NBhm+4sqV5xw5YilpRGcwZ7+9SgowunXu2bVELQQkXg==
X-Received: by 2002:a05:6512:1093:b0:47f:787b:ae4a with SMTP id j19-20020a056512109300b0047f787bae4amr18508383lfg.180.1656950468530;
        Mon, 04 Jul 2022 09:01:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls876349lfn.2.gmail;
 Mon, 04 Jul 2022 09:01:07 -0700 (PDT)
X-Received: by 2002:ac2:51cc:0:b0:482:e88a:950b with SMTP id u12-20020ac251cc000000b00482e88a950bmr660262lfm.270.1656950467125;
        Mon, 04 Jul 2022 09:01:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656950467; cv=none;
        d=google.com; s=arc-20160816;
        b=yAsE6xzLQr7xPHgwh1+8g0/KwEfZ7jmSvyStLknOR+wNfqOdwZu3XJPqFK/LytqAvg
         1MR6wxxPdSzgSQCy3bVa5dRHrOsMgMzJoewOcYlcsZK+dTBwvhBfKRjgcC09p8AX9LBP
         srloKMOqFgMTmJqSqVfzVADSH/Ec8ZEHZbT/SoJAeOeMAHJFryXp+iKOnCZ3JNlIMikx
         /gyYuPGpI0/J8R61SFbFXSTSK8d2D1AWl7gHPbEJ3E6a0K/3f4i2jyfbepmyHm+Cp/yK
         v+1Co031c29IAGna5p3cxW9SBXOn7qz/FU9Sc/8hB3hzaH6QE6RydpKP70WXhyV8gr3J
         mRJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fJSa99kaNUPkEQt1qWsYz3mdtudAL/LrNvC0glhW4Fc=;
        b=CA/n2k2YjJj24oHYIUSH3WFE9xr2KbKeShuPiZqv2ihiutDTma/msEcpkgQwppBjni
         iHxqWYFWOjlUeHMbCmFHP61KxyxcevDA6SHMzaweCRkHl21/d25rv6DyVMUSt7QwaKkY
         UmXac5FDOZxa8MOlsV//BJJs2BRpmQ5snMrkl422NTJLbI5MZxc+drPZcrnFRT9Cg363
         WwTxlWM/OCcNt+LtiCZhlwqBexwGx8ylxJdjpHObHzjlhs51X+g3JRdvVFHC/oNatIIE
         BS6oyzbJVNE997fnL5IHS0WoOs2MN2vFnDxlbvnHtoyg82st9ZF1yaK6pXDtZ48mLtdl
         Ms4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=vyIOd2yM;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id v12-20020a056512348c00b00482b3534361si125656lfr.6.2022.07.04.09.01.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 09:01:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8OUj-0083uJ-3n;
	Mon, 04 Jul 2022 16:00:17 +0000
Date: Mon, 4 Jul 2022 17:00:17 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Alexander Potapenko <glider@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
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
Message-ID: <YsMOkXpp2HaOnVJN@ZenIV>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV>
 <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com>
 <YsLuoFtki01gbmYB@ZenIV>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YsLuoFtki01gbmYB@ZenIV>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=vyIOd2yM;
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

On Mon, Jul 04, 2022 at 02:44:00PM +0100, Al Viro wrote:
> On Mon, Jul 04, 2022 at 10:20:53AM +0200, Alexander Potapenko wrote:
> 
> > What makes you think they are false positives? Is the scenario I
> > described above:
> > 
> > """
> > In particular, if the call to lookup_fast() in walk_component()
> > returns NULL, and lookup_slow() returns a valid dentry, then the
> > `seq` and `inode` will remain uninitialized until the call to
> > step_into()
> > """
> > 
> > impossible?
> 
> Suppose step_into() has been called in non-RCU mode.  The first
> thing it does is
> 	int err = handle_mounts(nd, dentry, &path, &seq);
> 	if (err < 0) 
> 		return ERR_PTR(err);
> 
> And handle_mounts() in non-RCU mode is
> 	path->mnt = nd->path.mnt;
> 	path->dentry = dentry;
> 	if (nd->flags & LOOKUP_RCU) {
> 		[unreachable code]
> 	}
> 	[code not touching seqp]
> 	if (unlikely(ret)) {
> 		[code not touching seqp]
> 	} else {
> 		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
> 	}
> 	return ret;
> 
> In other words, the value seq argument of step_into() used to have ends up
> being never fetched and, in case step_into() gets past that if (err < 0)
> that value is replaced with zero before any further accesses.
> 
> So it's a false positive; yes, strictly speaking compiler is allowd
> to do anything whatsoever if it manages to prove that the value is
> uninitialized.  Realistically, though, especially since unsigned int
> is not allowed any trapping representations...

FWIW, update (and yet untested) branch is in #work.namei.  Compared to the
previous, we store sampled ->d_seq of the next dentry in nd->next_seq,
rather than bothering with local variables.  AFAICS, it ends up with
better code that way.  And both ->seq and ->next_seq are zeroed at the
moments when we switch to non-RCU mode (as well as non-RCU path_init()).

IMO it looks saner that way.  NOTE: it still needs to be tested and probably
reordered and massaged; it's not for merge at the moment.  Current cumulative
diff follows:

diff --git a/fs/namei.c b/fs/namei.c
index 1f28d3f463c3..b12c6b53579d 100644
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
@@ -1496,14 +1499,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
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
 				continue;
 			}
@@ -1515,8 +1511,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 }
 
 static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
-			  struct path *path, struct inode **inode,
-			  unsigned int *seqp)
+			  struct path *path)
 {
 	bool jumped;
 	int ret;
@@ -1524,16 +1519,15 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
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
+		// *path and nd->next_seq might've been just clobbered
 		path->mnt = nd->path.mnt;
 		path->dentry = dentry;
+		nd->next_seq = seq;
+		if (!try_to_unlazy_next(nd, dentry))
+			return -ECHILD;
 	}
 	ret = traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
 	if (jumped) {
@@ -1546,9 +1540,6 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 		dput(path->dentry);
 		if (path->mnt != nd->path.mnt)
 			mntput(path->mnt);
-	} else {
-		*inode = d_backing_inode(path->dentry);
-		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
 	}
 	return ret;
 }
@@ -1607,9 +1598,7 @@ static struct dentry *__lookup_hash(const struct qstr *name,
 	return dentry;
 }
 
-static struct dentry *lookup_fast(struct nameidata *nd,
-				  struct inode **inode,
-			          unsigned *seqp)
+static struct dentry *lookup_fast(struct nameidata *nd)
 {
 	struct dentry *dentry, *parent = nd->path.dentry;
 	int status = 1;
@@ -1620,37 +1609,24 @@ static struct dentry *lookup_fast(struct nameidata *nd,
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
@@ -1731,7 +1707,7 @@ static inline int may_lookup(struct user_namespace *mnt_userns,
 	return inode_permission(mnt_userns, nd->inode, MAY_EXEC);
 }
 
-static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
+static int reserve_stack(struct nameidata *nd, struct path *link)
 {
 	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS))
 		return -ELOOP;
@@ -1746,7 +1722,7 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
 	if (nd->flags & LOOKUP_RCU) {
 		// we need to grab link before we do unlazy.  And we can't skip
 		// unlazy even if we fail to grab the link - cleanup needs it
-		bool grabbed_link = legitimize_path(nd, link, seq);
+		bool grabbed_link = legitimize_path(nd, link, nd->next_seq);
 
 		if (!try_to_unlazy(nd) || !grabbed_link)
 			return -ECHILD;
@@ -1760,11 +1736,11 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
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
@@ -1774,7 +1750,7 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
 	last = nd->stack + nd->depth++;
 	last->link = *link;
 	clear_delayed_call(&last->done);
-	last->seq = seq;
+	last->seq = nd->next_seq;
 
 	if (flags & WALK_TRAILING) {
 		error = may_follow_link(nd, inode);
@@ -1836,15 +1812,25 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
  * to do this check without having to look at inode->i_op,
  * so we keep a cache of "no, this doesn't need follow_link"
  * for the common case.
+ *
+ * NOTE: nd->next_seq must be the validated sampled dentry->d_seq
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
+	if (unlikely(!inode)) {
+		if ((nd->flags & LOOKUP_RCU) &&
+		    read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
+			return ERR_PTR(-ECHILD);
+		return ERR_PTR(-ENOENT);
+	}
 	if (likely(!d_is_symlink(path.dentry)) ||
 	   ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
 	   (flags & WALK_NOFOLLOW)) {
@@ -1856,23 +1842,21 @@ static const char *step_into(struct nameidata *nd, int flags,
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
 
@@ -1895,8 +1879,7 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	}
 	old = nd->path.dentry;
 	parent = old->d_parent;
-	*inodep = parent->d_inode;
-	*seqp = read_seqcount_begin(&parent->d_seq);
+	nd->next_seq = read_seqcount_begin(&parent->d_seq);
 	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
 		return ERR_PTR(-ECHILD);
 	if (unlikely(!path_connected(nd->path.mnt, parent)))
@@ -1907,12 +1890,11 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
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
 
@@ -1936,15 +1918,12 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
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
@@ -1952,8 +1931,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 	if (type == LAST_DOTDOT) {
 		const char *error = NULL;
 		struct dentry *parent;
-		struct inode *inode;
-		unsigned seq;
 
 		if (!nd->root.mnt) {
 			error = ERR_PTR(set_root(nd));
@@ -1961,17 +1938,12 @@ static const char *handle_dots(struct nameidata *nd, int type)
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
 
@@ -1995,8 +1967,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
-	struct inode *inode;
-	unsigned seq;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
 	 * to be able to know about the current root directory and
@@ -2007,7 +1977,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 			put_link(nd);
 		return handle_dots(nd, nd->last_type);
 	}
-	dentry = lookup_fast(nd, &inode, &seq);
+	dentry = lookup_fast(nd);
 	if (IS_ERR(dentry))
 		return ERR_CAST(dentry);
 	if (unlikely(!dentry)) {
@@ -2017,7 +1987,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 	}
 	if (!(flags & WALK_MORE) && nd->depth)
 		put_link(nd);
-	return step_into(nd, flags, dentry, inode, seq);
+	return step_into(nd, flags, dentry);
 }
 
 /*
@@ -2372,6 +2342,8 @@ static const char *path_init(struct nameidata *nd, unsigned flags)
 		flags &= ~LOOKUP_RCU;
 	if (flags & LOOKUP_RCU)
 		rcu_read_lock();
+	else
+		nd->seq = nd->next_seq = 0;
 
 	nd->flags = flags;
 	nd->state |= ND_JUMPED;
@@ -2473,8 +2445,8 @@ static int handle_lookup_down(struct nameidata *nd)
 {
 	if (!(nd->flags & LOOKUP_RCU))
 		dget(nd->path.dentry);
-	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
-			nd->path.dentry, nd->inode, nd->seq));
+	nd->next_seq = nd->seq;
+	return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry));
 }
 
 /* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
@@ -3393,8 +3365,6 @@ static const char *open_last_lookups(struct nameidata *nd,
 	struct dentry *dir = nd->path.dentry;
 	int open_flag = op->open_flag;
 	bool got_write = false;
-	unsigned seq;
-	struct inode *inode;
 	struct dentry *dentry;
 	const char *res;
 
@@ -3410,7 +3380,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 		if (nd->last.name[nd->last.len])
 			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
 		/* we _can_ be in RCU mode here */
-		dentry = lookup_fast(nd, &inode, &seq);
+		dentry = lookup_fast(nd);
 		if (IS_ERR(dentry))
 			return ERR_CAST(dentry);
 		if (likely(dentry))
@@ -3464,7 +3434,7 @@ static const char *open_last_lookups(struct nameidata *nd,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsMOkXpp2HaOnVJN%40ZenIV.
