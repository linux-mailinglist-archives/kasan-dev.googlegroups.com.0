Return-Path: <kasan-dev+bncBC42V7FQ3YARBE7KRWLAMGQEBAWCESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f55.google.com (mail-lf1-f55.google.com [209.85.167.55])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E279565FAD
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:17:40 +0200 (CEST)
Received: by mail-lf1-f55.google.com with SMTP id y8-20020ac24208000000b0047f9fc8f632sf3383086lfh.11
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:17:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976660; cv=pass;
        d=google.com; s=arc-20160816;
        b=nipWDr5RuoqRDi+bqUI9rGre3XGeqio6OVKAve2WAl7oSWJAaiH0KXPxA8o40INUk7
         QPb+zxf+a5MgJ3wLyIRdMS4BQAwQQOXMcwRix4DossUp3brS+rc8b6wYtaQx0vwbAo2V
         cfTJkP4nOKxVb6ya+YSRcKsRkWdjgr6ABMq1hPgVkM8FfqzCpLE0UQ6A0N9boqPV3pge
         uCzTVTPH7Lkpq0Vpjm/0GoBFQm4XaZdovxfrZTI/BrMxQ854lyb5MORtcUnvz2fyaEAy
         u2FqTBbbNyl19sdyHrn0EmN+zmKonMXzgG8iM+3y9pbYdYwU3pY9lKmN29Xy1Hk8Ypm/
         yleg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=P1jxrIZYR1wHSUHZwKhhnsBFs+52yPANDa+Y54uA2ww=;
        b=TL+/SG7CHW2Mt5IEoqPJjVEW+RVb6U04JVxDeyfZc0WAoXFGSmNLSAMiKum9d+Wjjv
         J1SXtxg9CJy9eUEb4ypxVj2kUeuXI+M4pA432LOic1cOdV0LJ+6+RtAVeINx4ZJwr/h1
         FhsM3b56vX6wVYF4EGI0xGNAXzkbm3IappIAXv10oWZwt71r2fX+JbGXm+TId+EdtotJ
         na2yOf6JAwPbJo9W2d82mAbQCvyMxVmi00A2pAmShcVrBxiNwC7Q8sAeHJmio2WzNgHu
         q6NXKlhk1cPEt/XMReY1SbS98VDfwVQChspxWYZTSxPFW9agqp+4HGSXOVYU4ifx/aVl
         bptA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=XMq6en3D;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P1jxrIZYR1wHSUHZwKhhnsBFs+52yPANDa+Y54uA2ww=;
        b=5scPweVtRUKrg017S8MIJ3ANSxkQqW7czo405f+j/toHp7ej8GhChPgiNs0JZzFRlb
         aVNrEwunqxdWe1UC3LUZp4B/SyVuv6hGK9ZB6JbTQlXn9Q9ooGhgbTjaIkwpIuknfxoE
         +jhwktwPxcL/plnliRoNlDzifs6534QPeu6R4zuwCuD83+ng9jwKqnhY3xgNQfcbUtYG
         80dzb1p+svxt4vxGxV7iu/kgHOnMRa/2BHOnmxcwicaizaNoeo1LeFz9cB1Kar8f/Qh+
         rcfEhyL5W/hnbZAOswCr3wb+r0lu0VmGWaceMYmeEEwRgFNKQlkZZTWYfiNfWilKhfbq
         QNwg==
X-Gm-Message-State: AJIora+yAi7noqRL9BNqoCOG9GIFxjMyBkr2B3JNxL5TAJM7lRtjXXz9
	P2B/mR0/1pNd9bNP8tnShOI=
X-Google-Smtp-Source: AGRyM1sYc2Wuid4IT9FNOg9URrFZb5YwC6fdDNBZaKqkt3DSmksXqapX8y2bmE1zpirpsBQAEkop9g==
X-Received: by 2002:a2e:95ce:0:b0:25a:6c99:e863 with SMTP id y14-20020a2e95ce000000b0025a6c99e863mr17352283ljh.337.1656976659767;
        Mon, 04 Jul 2022 16:17:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls200302lfn.2.gmail;
 Mon, 04 Jul 2022 16:17:38 -0700 (PDT)
X-Received: by 2002:a05:6512:2610:b0:47f:74dc:3205 with SMTP id bt16-20020a056512261000b0047f74dc3205mr19281351lfb.429.1656976658427;
        Mon, 04 Jul 2022 16:17:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976658; cv=none;
        d=google.com; s=arc-20160816;
        b=F2K0Sf5CKQiDa4hYvRMy1NrMT276vh1BOyyccmX1FCD6yPa1kRgFxTRObX33u+ouhM
         MijIi8OpYrGOfE5At2A7f8zJJ0lkwDRsq83h4qUw/2XkXguObtM8fE2MpOstr9W/9ijZ
         nCvd90bkPTrSwzYnFEZDKvTNDZxrEZdLj0wPaayIx3lQaHYsu4cJnLgqz3dqqGcDgByC
         cmPy7gBhvxQvG69jNv3t9JnldZX10cT4pnf+ZXHw+fPjNxZk+bLXOUGGe+yGUUx7/2fL
         v/C+AFyJ9fvx7Ozkll/9m6xpQTTEvasjVRjEq7NqTN+Gm/pnFEZX2rZJCuhrXZV+O4yc
         R6Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NqVApc9I2DDH/ifQWSRH221HRDI5UWBJClZrnVtHcvg=;
        b=wS5160xW28XSWNgSr7rzHAioZoerhc5JxFr1/+9duJmxtBNBxINQGDv+VNwJO4tA/n
         bdDnWklo1hlo7O+KUxY3RNhyiTfiJTD4DdCjBPw8oD4qezy0ulMKUeDc8rEuIsOJ5Xzy
         oYiVvgjOfx6zx5DSLYjk2wU1pqFbr485hYLj9b5hJLsoKM2+NVIhHOfgm6umt7uSd43t
         Ynz5Ng58VOsqqZKZ+44hMP08YluE3ShAJeo4GAXkKZ/zZVY4F0DfK2kWFM1NkE0kLa8g
         chvOVgfHYZzZowGWBNrhSPdXAs/tx51wMNJDEoFuynaKBzf1xXFPv68RqvVNXleQwAw2
         tH3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=XMq6en3D;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si1146727ljo.8.2022.07.04.16.17.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:17:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VJP-008AcR-HB;
	Mon, 04 Jul 2022 23:17:03 +0000
Date: Tue, 5 Jul 2022 00:17:03 +0100
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
Subject: [PATCH 7/7] step_into(): move fetching ->d_inode past handle_mounts()
Message-ID: <YsN07/fVcHSbDDlm@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=XMq6en3D;
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

... and lose messing with it in __follow_mount_rcu()

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 31 +++++++++++--------------------
 1 file changed, 11 insertions(+), 20 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index cdb61d09df79..f2c99e75b578 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1470,8 +1470,7 @@ EXPORT_SYMBOL(follow_down);
  * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
  * we meet a managed dentry that would need blocking.
  */
-static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
-			       struct inode **inode)
+static bool __follow_mount_rcu(struct nameidata *nd, struct path *path)
 {
 	struct dentry *dentry = path->dentry;
 	unsigned int flags = dentry->d_flags;
@@ -1501,13 +1500,6 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 				dentry = path->dentry = mounted->mnt.mnt_root;
 				nd->state |= ND_JUMPED;
 				nd->next_seq = read_seqcount_begin(&dentry->d_seq);
-				*inode = dentry->d_inode;
-				/*
-				 * We don't need to re-check ->d_seq after this
-				 * ->d_inode read - there will be an RCU delay
-				 * between mount hash removal and ->mnt_root
-				 * becoming unpinned.
-				 */
 				flags = dentry->d_flags;
 				// makes sure that non-RCU pathwalk could reach
 				// this state.
@@ -1523,7 +1515,7 @@ static bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
 }
 
 static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
-			  struct path *path, struct inode **inode)
+			  struct path *path)
 {
 	bool jumped;
 	int ret;
@@ -1532,12 +1524,7 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 	path->dentry = dentry;
 	if (nd->flags & LOOKUP_RCU) {
 		unsigned int seq = nd->next_seq;
-		*inode = dentry->d_inode;
-		if (read_seqcount_retry(&dentry->d_seq, seq))
-			return -ECHILD;
-		if (unlikely(!*inode))
-			return -ENOENT;
-		if (likely(__follow_mount_rcu(nd, path, inode)))
+		if (likely(__follow_mount_rcu(nd, path)))
 			return 0;
 		// *path and nd->next_seq might've been clobbered
 		path->mnt = nd->path.mnt;
@@ -1557,8 +1544,6 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 		dput(path->dentry);
 		if (path->mnt != nd->path.mnt)
 			mntput(path->mnt);
-	} else {
-		*inode = d_backing_inode(path->dentry);
 	}
 	return ret;
 }
@@ -1839,15 +1824,21 @@ static const char *step_into(struct nameidata *nd, int flags,
 {
 	struct path path;
 	struct inode *inode;
-	int err = handle_mounts(nd, dentry, &path, &inode);
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
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN07/fVcHSbDDlm%40ZenIV.
