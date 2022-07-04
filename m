Return-Path: <kasan-dev+bncBC42V7FQ3YARB7HIRWLAMGQE2T3D3WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-f185.google.com (mail-lj1-f185.google.com [209.85.208.185])
	by mail.lfdr.de (Postfix) with ESMTPS id D226F565F9F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:15:09 +0200 (CEST)
Received: by mail-lj1-f185.google.com with SMTP id h9-20020a2eb0e9000000b0025d3255018dsf5804ljl.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:15:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976509; cv=pass;
        d=google.com; s=arc-20160816;
        b=DnaR56jW9Zldhs4t5xzQRdyfe6EntLx+1b8ss30ODV558nKxkxGgYaekF+mL9eu7/Z
         KiAE22Z6nSX6IzMGJs4bOITNfTDs9nCzqxbLN+I2scP4wHWakkqJlM5vVMbuA8vSDbyK
         PVcsmCETjG3mbY5vwRLKuLsUxHgt3ALZ1kiYzbQlwmF8iGy5WYTd6MV2qGZ8GRAMCqke
         Au5gX8M6lq8F2LWvq/MOvF3EkN2FhGMAcUWLWp0PUKHG+xhk/DksLLVdF3QuE68jLl8Z
         CFjltq4Q3rg4Hlaw+bMYINvuLo2PaI8wE99WT6+fH2/tZkWYwEvfPLTcBBGHNL3KjNrb
         Z8Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=IipV7Gt0H244V4guUTf9dHTlvs8zhgeXBRFC0HF0na8=;
        b=IfsXvs9yV2bXSiQJ+7g2/PsLtDtVrZLl7kqP6TfFu3E8ahffEF06KZpFvokDmZcQ7e
         lSSJ45penADNYvNKnV0Lq7LZlXDdp24aw0rKsffazI4OnA+1DyvGz9tb1M+EgXKvBhUr
         EO/C/vlw/P9IA6Oa/80mycnciTF/XWgrAgCGOexG/ZGWBpcecNEHNYUOr7jXVMYBwOsq
         +z6p4G0U3kP15NmyJUyZrBYAehEj9da6QjSf8sKwnCGKh1kjvLbw4siF0aYk9itKzUlV
         c3nCJOkgsJquisj2R51HTRBZ/tbR6Lv19n8/RR64GfK4vNxhoa3dW0TT5axyf0UI39R8
         jd7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OJehKGWk;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IipV7Gt0H244V4guUTf9dHTlvs8zhgeXBRFC0HF0na8=;
        b=LBiHYhL10WtIQTQxxXzuOBgf9pDTT5nDFyaJ26NC8gMzAhbgG+1w/NmFDGHUw2bZlg
         i9qmfSnGAbl+Gy7GJy4d4se1pNd40HRBEDqQG4pdZ+2vfqBq0YSmePzjY0vk+WYRPM83
         4LA1VBQhAZHM9o6IZDxNwAFaP2augn/1Dvz5XNkF9CaAIN1WkXkZ9LQN0OVJ/z2kd1bz
         HkIaF2KSV/CnDi/MP+1txxkhq5UNqyibLXpZlH9lzU+vdRKMoN5Q7YxXJHnmPVqDBADi
         TTkZ1o+9HpEHeANmJ+EGdg8I5R/Wy24blkUshmoh/KEjOy3Wskg7w+oSl67acJWfRIJp
         2i2A==
X-Gm-Message-State: AJIora+8D5IXxHY+QfsyZjtldebs+vxjs/LvD6XjW4mhav6xUMIGqzZd
	RtQoBBNto0ZRkkj9txIrkMM=
X-Google-Smtp-Source: AGRyM1urVThyp72Nzk0jgESQqi175DcoUK1ninmTLe9iVMtrs+fLfTz+nYZOCFFlgFQjNcHN4WHD8Q==
X-Received: by 2002:a2e:6a03:0:b0:25b:f8cf:8e39 with SMTP id f3-20020a2e6a03000000b0025bf8cf8e39mr14457822ljc.166.1656976509178;
        Mon, 04 Jul 2022 16:15:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls198929lfv.3.gmail; Mon, 04 Jul 2022
 16:15:07 -0700 (PDT)
X-Received: by 2002:a05:6512:20cb:b0:481:7b9:ffb7 with SMTP id u11-20020a05651220cb00b0048107b9ffb7mr19791847lfr.573.1656976507727;
        Mon, 04 Jul 2022 16:15:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976507; cv=none;
        d=google.com; s=arc-20160816;
        b=Z6wKLWXPDnwP0Z4h7by25gEAVSSuaFryEU3f2R5HQmuSg/gI4hwxz5Cgm8RPSp4hms
         FQd71Wo9mg385Lf60yR/bcx3Pmk1LRKFh03kBvWWWlcOR4TOjnxZqklDXEWxmyGl9SFz
         vwktz2WsvFDLrQ7zlzOhOERQUnP/i3HrXuLyxolZdUaVeJffLCXtTPgH8fWFXqr7ZrUf
         rG29ff7pgCc28UCymSU8uFcvCxkn3hsIQGsxGnjlTSKHSs8/WXxD15+0mRESYl/ZkLIf
         LG39wx0cvUNpykss1Do5k9lu/PJIXQLhJVkzDl7bjB3uJHNzp8Mt4IEE8DZ7HGLfDTAA
         qMAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Br5WlNNviFIy/GyDPGw5BoV/8TxCR0XRwVG74vstYTg=;
        b=jMG7D8QcCqWTf6nImW6G/J+ehIIsAY/XG+Rzhu5Gt05CSJaCn+d7sFiDiEMlpxYfHo
         3eCaS/rRVYzRaAfPN9BtfFWcSXsdUVKo4114mZLatdk8IuHE3H7YCrCO9XUl5HFxWMRC
         L1D4rlSZucD595Jfy+8WEsY41ARasn6T0dB6AqnagkL6gc29mmvLBBvkDvnuoECaytA2
         Fd7fEW2kRIdxr12cLxs8108pm57vvxMj3VDvAW4Qx4mQUDXEgDTqkBx7Xhx4kE5N2UGY
         xDmrcVjAyPWstC3EtnXOO2kQt6F0HtL8NbD0i4RiWwoCspksuIqAw41fhOgnGNNCCuKh
         RSLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OJehKGWk;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si985858lfv.13.2022.07.04.16.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:15:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VH6-008AX3-3B;
	Mon, 04 Jul 2022 23:14:40 +0000
Date: Tue, 5 Jul 2022 00:14:40 +0100
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
Subject: [PATCH 3/7] namei: stash the sampled ->d_seq into nameidata
Message-ID: <YsN0YFIDaO+/Hr3+@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OJehKGWk;
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

New field: nd->next_seq.  Set to 0 outside of RCU mode, holds the sampled
value for the next dentry to be considered.  Used instead of an arseload
of local variables, arguments, etc.

step_into() has lost seq argument; nd->next_seq is used, so dentry passed
to it must be the one ->next_seq is about.

There are two requirements for RCU pathwalk:
	1) it should not give a hard failure (other than -ECHILD) unless
non-RCU pathwalk might fail that way given suitable timings.
	2) it should not succeed unless non-RCU pathwalk might succeed
with the same end location given suitable timings.

The use of seq numbers is the way we achieve that.  Invariant we want
to maintain is:
	if RCU pathwalk can reach the state with given nd->path, nd->inode
and nd->seq after having traversed some part of pathname, it must be possible
for non-RCU pathwalk to reach the same nd->path and nd->inode after having
traversed the same part of pathname, and observe the nd->path.dentry->d_seq
equal to what RCU pathwalk has in nd->seq

	For transition from parent to child, we sample child's ->d_seq
and verify that parent's ->d_seq remains unchanged.
	For transitions from child to parent we sample parent's ->d_seq
and verify that child's ->d_seq has not changed.
	For transition from mountpoint to root of mounted we sample
the ->d_seq of root and verify that nobody has touched mount_lock since
the beginning of pathwalk.  That guarantees that mount we'd found had
been there all along, with these mountpoint and root of mounted.
It would be possible for a non-RCU pathwalk to reach the previous state,
find the same mount and observe its root at the moment we'd sampled
->d_seq of that
	For transitions from root of mounted to mountpoint we sample
->d_seq of mountpoint and verify that mount_lock had not been touched
since the beginning of pathwalk.  The same reasoning as in the
previous case applies.

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 104 ++++++++++++++++++++++++++---------------------------
 1 file changed, 52 insertions(+), 52 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index ecdb9ac21ece..c7c9e88add85 100644
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
@@ -1467,7 +1471,7 @@ EXPORT_SYMBOL(follow_down);
  * we meet a managed dentry that would need blocking.
  */
 static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
-			       struct inode **inode, unsigned *seqp)
+			       struct inode **inode)
 {
 	struct dentry *dentry = path->dentry;
 	unsigned int flags = dentry->d_flags;
@@ -1496,7 +1500,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				path->mnt = &mounted->mnt;
 				dentry = path->dentry = mounted->mnt.mnt_root;
 				nd->state |= ND_JUMPED;
-				*seqp = read_seqcount_begin(&dentry->d_seq);
+				nd->next_seq = read_seqcount_begin(&dentry->d_seq);
 				*inode = dentry->d_inode;
 				/*
 				 * We don't need to re-check ->d_seq after this
@@ -1505,6 +1509,8 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				 * becoming unpinned.
 				 */
 				flags = dentry->d_flags;
+				// makes sure that non-RCU pathwalk could reach
+				// this state.
 				if (read_seqretry(&mount_lock, nd->m_seq))
 					return false;
 				continue;
@@ -1517,8 +1523,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 }
 
 static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
-			  struct path *path, struct inode **inode,
-			  unsigned int *seqp)
+			  struct path *path, struct inode **inode)
 {
 	bool jumped;
 	int ret;
@@ -1526,16 +1531,15 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 	path->mnt = nd->path.mnt;
 	path->dentry = dentry;
 	if (nd->flags & LOOKUP_RCU) {
-		unsigned int seq = *seqp;
-		if (unlikely(!*inode))
-			return -ENOENT;
-		if (likely(__follow_mount_rcu(nd, path, inode, seqp)))
+		unsigned int seq = nd->next_seq;
+		if (likely(__follow_mount_rcu(nd, path, inode)))
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
@@ -1550,7 +1554,6 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 			mntput(path->mnt);
 	} else {
 		*inode = d_backing_inode(path->dentry);
-		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
 	}
 	return ret;
 }
@@ -1610,8 +1613,7 @@ static struct dentry *__lookup_hash(const struct qstr *name,
 }
 
 static struct dentry *lookup_fast(struct nameidata *nd,
-				  struct inode **inode,
-			          unsigned *seqp)
+				  struct inode **inode)
 {
 	struct dentry *dentry, *parent = nd->path.dentry;
 	int status = 1;
@@ -1622,8 +1624,7 @@ static struct dentry *lookup_fast(struct nameidata *nd,
 	 * going to fall back to non-racy lookup.
 	 */
 	if (nd->flags & LOOKUP_RCU) {
-		unsigned seq;
-		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
+		dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
 		if (unlikely(!dentry)) {
 			if (!try_to_unlazy(nd))
 				return ERR_PTR(-ECHILD);
@@ -1635,7 +1636,7 @@ static struct dentry *lookup_fast(struct nameidata *nd,
 		 * the dentry name information from lookup.
 		 */
 		*inode = d_backing_inode(dentry);
-		if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
+		if (unlikely(read_seqcount_retry(&dentry->d_seq, nd->next_seq)))
 			return ERR_PTR(-ECHILD);
 
 		/*
@@ -1648,11 +1649,10 @@ static struct dentry *lookup_fast(struct nameidata *nd,
 		if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
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
@@ -1733,7 +1733,7 @@ static inline int may_lookup(struct user_namespace *mnt_userns,
 	return inode_permission(mnt_userns, nd->inode, MAY_EXEC);
 }
 
-static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
+static int reserve_stack(struct nameidata *nd, struct path *link)
 {
 	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS))
 		return -ELOOP;
@@ -1748,7 +1748,7 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
 	if (nd->flags & LOOKUP_RCU) {
 		// we need to grab link before we do unlazy.  And we can't skip
 		// unlazy even if we fail to grab the link - cleanup needs it
-		bool grabbed_link = legitimize_path(nd, link, seq);
+		bool grabbed_link = legitimize_path(nd, link, nd->next_seq);
 
 		if (!try_to_unlazy(nd) || !grabbed_link)
 			return -ECHILD;
@@ -1762,11 +1762,11 @@ static int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
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
@@ -1776,7 +1776,7 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
 	last = nd->stack + nd->depth++;
 	last->link = *link;
 	clear_delayed_call(&last->done);
-	last->seq = seq;
+	last->seq = nd->next_seq;
 
 	if (flags & WALK_TRAILING) {
 		error = may_follow_link(nd, inode);
@@ -1838,12 +1838,14 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
  * to do this check without having to look at inode->i_op,
  * so we keep a cache of "no, this doesn't need follow_link"
  * for the common case.
+ *
+ * NOTE: dentry must be what nd->next_seq had been sampled from.
  */
 static const char *step_into(struct nameidata *nd, int flags,
-		     struct dentry *dentry, struct inode *inode, unsigned seq)
+		     struct dentry *dentry, struct inode *inode)
 {
 	struct path path;
-	int err = handle_mounts(nd, dentry, &path, &inode, &seq);
+	int err = handle_mounts(nd, dentry, &path, &inode);
 
 	if (err < 0)
 		return ERR_PTR(err);
@@ -1858,23 +1860,22 @@ static const char *step_into(struct nameidata *nd, int flags,
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
 
 static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
-					struct inode **inodep,
-					unsigned *seqp)
+					struct inode **inodep)
 {
 	struct dentry *parent, *old;
 
@@ -1891,6 +1892,7 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 		nd->path = path;
 		nd->inode = path.dentry->d_inode;
 		nd->seq = seq;
+		// makes sure that non-RCU pathwalk could reach this state
 		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
 			return ERR_PTR(-ECHILD);
 		/* we know that mountpoint was pinned */
@@ -1898,7 +1900,8 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	old = nd->path.dentry;
 	parent = old->d_parent;
 	*inodep = parent->d_inode;
-	*seqp = read_seqcount_begin(&parent->d_seq);
+	nd->next_seq = read_seqcount_begin(&parent->d_seq);
+	// makes sure that non-RCU pathwalk could reach this state
 	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
 		return ERR_PTR(-ECHILD);
 	if (unlikely(!path_connected(nd->path.mnt, parent)))
@@ -1909,14 +1912,13 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 		return ERR_PTR(-ECHILD);
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-ECHILD);
-	*seqp = nd->seq;
+	nd->next_seq = nd->seq;
 	*inodep = nd->path.dentry->d_inode;
 	return nd->path.dentry;
 }
 
 static struct dentry *follow_dotdot(struct nameidata *nd,
-				 struct inode **inodep,
-				 unsigned *seqp)
+				 struct inode **inodep)
 {
 	struct dentry *parent;
 
@@ -1940,14 +1942,12 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
 		dput(parent);
 		return ERR_PTR(-ENOENT);
 	}
-	*seqp = 0;
 	*inodep = parent->d_inode;
 	return parent;
 
 in_root:
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-EXDEV);
-	*seqp = 0;
 	*inodep = nd->path.dentry->d_inode;
 	return dget(nd->path.dentry);
 }
@@ -1958,7 +1958,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 		const char *error = NULL;
 		struct dentry *parent;
 		struct inode *inode;
-		unsigned seq;
 
 		if (!nd->root.mnt) {
 			error = ERR_PTR(set_root(nd));
@@ -1966,12 +1965,12 @@ static const char *handle_dots(struct nameidata *nd, int type)
 				return error;
 		}
 		if (nd->flags & LOOKUP_RCU)
-			parent = follow_dotdot_rcu(nd, &inode, &seq);
+			parent = follow_dotdot_rcu(nd, &inode);
 		else
-			parent = follow_dotdot(nd, &inode, &seq);
+			parent = follow_dotdot(nd, &inode);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
-		error = step_into(nd, WALK_NOFOLLOW, parent, inode, seq);
+		error = step_into(nd, WALK_NOFOLLOW, parent, inode);
 		if (unlikely(error))
 			return error;
 
@@ -1996,7 +1995,6 @@ static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
 	struct inode *inode;
-	unsigned seq;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
 	 * to be able to know about the current root directory and
@@ -2007,7 +2005,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 			put_link(nd);
 		return handle_dots(nd, nd->last_type);
 	}
-	dentry = lookup_fast(nd, &inode, &seq);
+	dentry = lookup_fast(nd, &inode);
 	if (IS_ERR(dentry))
 		return ERR_CAST(dentry);
 	if (unlikely(!dentry)) {
@@ -2017,7 +2015,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 	}
 	if (!(flags & WALK_MORE) && nd->depth)
 		put_link(nd);
-	return step_into(nd, flags, dentry, inode, seq);
+	return step_into(nd, flags, dentry, inode);
 }
 
 /*
@@ -2372,6 +2370,8 @@ static const char *path_init(struct nameidata *nd, unsigned flags)
 		flags &= ~LOOKUP_RCU;
 	if (flags & LOOKUP_RCU)
 		rcu_read_lock();
+	else
+		nd->seq = nd->next_seq = 0;
 
 	nd->flags = flags;
 	nd->state |= ND_JUMPED;
@@ -2473,8 +2473,9 @@ static int handle_lookup_down(struct nameidata *nd)
 {
 	if (!(nd->flags & LOOKUP_RCU))
 		dget(nd->path.dentry);
+	nd->next_seq = nd->seq;
 	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
-			nd->path.dentry, nd->inode, nd->seq));
+			nd->path.dentry, nd->inode));
 }
 
 /* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
@@ -3393,7 +3394,6 @@ static const char *open_last_lookups(struct nameidata *nd,
 	struct dentry *dir = nd->path.dentry;
 	int open_flag = op->open_flag;
 	bool got_write = false;
-	unsigned seq;
 	struct inode *inode;
 	struct dentry *dentry;
 	const char *res;
@@ -3410,7 +3410,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 		if (nd->last.name[nd->last.len])
 			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
 		/* we _can_ be in RCU mode here */
-		dentry = lookup_fast(nd, &inode, &seq);
+		dentry = lookup_fast(nd, &inode);
 		if (IS_ERR(dentry))
 			return ERR_CAST(dentry);
 		if (likely(dentry))
@@ -3464,7 +3464,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 finish_lookup:
 	if (nd->depth)
 		put_link(nd);
-	res = step_into(nd, WALK_TRAILING, dentry, inode, seq);
+	res = step_into(nd, WALK_TRAILING, dentry, inode);
 	if (unlikely(res))
 		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
 	return res;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0YFIDaO%2B/Hr3%2B%40ZenIV.
