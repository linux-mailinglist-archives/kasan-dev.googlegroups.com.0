Return-Path: <kasan-dev+bncBC42V7FQ3YARBKXJRWLAMGQEDRYL7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-f64.google.com (mail-ej1-f64.google.com [209.85.218.64])
	by mail.lfdr.de (Postfix) with ESMTPS id 50D9B565FA2
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:15:55 +0200 (CEST)
Received: by mail-ej1-f64.google.com with SMTP id hd35-20020a17090796a300b0072a707cfac4sf2205615ejc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:15:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976555; cv=pass;
        d=google.com; s=arc-20160816;
        b=IIhvD3YWQob2Mkz/dCLYNH16Fuz6H5en180BA+TXNTjEOoIx8oocFXUeYEcCSXH1UC
         5QaZTpvbmhAlxVRdTgmtezL/gf1ishWM60thWuUFfgFOVPYIdv/aO3/bCkF+iH+QNGrD
         0DBQH/w0XQ13l18lFe1+mk6BskJMhAMsQ0+eX5LGL+pXMy7IETR64hz+roaCBbkvMQ+x
         k82WJ87GARHo0+A2UuOYOBmBaohEnfWJdfkzfDIEwOx5+Fz9uwO/LKrH+kDkFwN5tNJ5
         QYQjhOwRXSKOOqeKMj2uaOo73i8s2gXg50KrqdyJEv1aYLrr+yqr4iCQW2yPYt02T+kg
         lKGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=vJG/R+JUXhRmCCsQFzmMsDFuIo/1d2g7+xPCoTRhEmk=;
        b=v+PoHpytdoPBNBaq22JD2EKj37MxJynLt5VvXGdF6rLQwYNXET4ifZiNTdB/QWPxbz
         WUhF7a5KDIz+/HDAFrKHFqm5BLu7DaALwSFotBSGKNKTrdN8V4spMpkKjZYCa2X5W55o
         nB1iVUJTgXzwmXxukjC6oHRg+dULQstpsN4bxVTFmUs5jgmarzHtcmv7cqKsHgsbAz/a
         hKfow9RfsX1VG9YcKS5vVPGKjM4MxJovWrhAUjQF/txOckSQvmy92pAmv9zfVceT+Gx5
         Zm7+vmPRitlsJZXFI/NysADTyH3H2IssAHW4GAO7rKw40ARGehjE0nFBN94v4Spt5cdJ
         r4lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OwdNXG7l;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vJG/R+JUXhRmCCsQFzmMsDFuIo/1d2g7+xPCoTRhEmk=;
        b=a7/Ji1sx9xErXuKvzfNE6EssU8hNAziWBfnLHCPDnIZtFUv1uxitYhC51XxOiUQep0
         AkuJYy1fvRbhHNjNmheDprN8dqybqQaVZZo9m1yJlS9c6cPYh5rGfRqIiOfCdtdy4L82
         XniBAwwFmnIfdNxi/iI4Hr7uqfOtDtmXI3zKoGtIEV+xK1gDzKL6vCN8soeOexdawB5g
         1aKHP8pNz4PFDlVermPDSHxsiTkOmHdzSYi4E8IXBP84kHdt3rds3nf07cX+ZySX/U6F
         WsSVtTRdfQacb5XXt62JLmCRkmLmls7mFHZkI1vC55VsSGbaZR0w0C0WUl0169qZAq9S
         B9PA==
X-Gm-Message-State: AJIora+04OmrrQSL/iXizimIl/Dw46dYQnZGozMhdVPkrkCktTwsH4tz
	vZEVfFd9nUsZ2ZFaZ4UGJlg=
X-Google-Smtp-Source: AGRyM1vH/r5MMaAyMuGXb3QdNhNExFsxtmn7n/z+2+EKpyT/f+1uVZPmnXftY36RZ276Y9PnripD9A==
X-Received: by 2002:a05:6402:12d8:b0:43a:6a70:9039 with SMTP id k24-20020a05640212d800b0043a6a709039mr7671923edx.379.1656976555099;
        Mon, 04 Jul 2022 16:15:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35d5:b0:43a:7724:247e with SMTP id
 z21-20020a05640235d500b0043a7724247els134159edc.2.gmail; Mon, 04 Jul 2022
 16:15:54 -0700 (PDT)
X-Received: by 2002:a05:6402:1606:b0:43a:2204:8b5e with SMTP id f6-20020a056402160600b0043a22048b5emr14244241edv.316.1656976553993;
        Mon, 04 Jul 2022 16:15:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976553; cv=none;
        d=google.com; s=arc-20160816;
        b=vYNoVFfzo8NKwAObRdSIxzd27xToHBWmtIA7HLlT8GtrJZoExApoXT1qK0PM/Am5kG
         wzii3lxJ39jAc6b5GsUhGJslJ3J4DeIMFYMo40rIOEKh0rU/Cs0Uq1iMSKPs75P8B8jV
         xuNB5fnubbH524Ce51QjIQeG04NnPijyqJ2iYK10i6twkcfmp6O/Wg4nspI+Up7fv/cw
         3o6SzRaay2na8ZdlLR/rzEeiZrZLui/V87w2bJmES3Epvo5znvXPVpWkLDI+KcDUdJXg
         GeFl5RSp61QUoQwInyLhfuxeqcB0+1pe83yGc1ZNa15IiRZYXUFYAPQMztmmQ1rwN3Qj
         XHfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=phosGs0ReDXhvjah48sBo0KCwl+d1jcc+HCEqeu58tc=;
        b=ygHIcOlwFggIrdvpSu30/57W1Q0P8489n6+kR0BdFWKB5K+FOHOgzLJvbXZXZdsKcy
         T78U9fkwmU1+WHUMaJcelx4dEsQqA2EGIJqwbcxQLmK69x5BQ2NNa8nYr1d4bbr1a4/7
         Lrgq9sc5cjX3RcOvS0xBFc/lO93sfimuAJk9gaXowwijDIjZymJjMnDDZhq06HKl8JkA
         yHYcBgzWm0VEdtq/Rmykv95Q/Xh6O0eWB+PKofk4f3O91FmMC5CEIE74GuHdMuwHyJIq
         KASRbhoKxctkLUNfoxoqTRnPyzscxEQOZQJGZF1FHe8DpL4cJ5PGISfOmLZfQw/oCpiu
         X6fQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OwdNXG7l;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id t1-20020a056402524100b0042d687c85d2si962288edd.0.2022.07.04.16.15.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:15:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VHc-008AYW-Qq;
	Mon, 04 Jul 2022 23:15:12 +0000
Date: Tue, 5 Jul 2022 00:15:12 +0100
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
Subject: [PATCH 4/7] step_into(): lose inode argument
Message-ID: <YsN0gGIUtmYHYXYB@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=OwdNXG7l;
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

make handle_mounts() always fetch it.  This is just the first step -
the callers of step_into() will stop trying to calculate the sucker,
etc.

The passed value should be equal to dentry->d_inode in all cases;
in RCU mode - fetched after we'd sampled ->d_seq.  Might as well
fetch it here.  We do need to validate ->d_seq, which duplicates
the check currently done in lookup_fast(); that duplication will
go away shortly.

After that change handle_mounts() always ignores the initial value of
*inode and always sets it on success.

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 17 +++++++++++------
 1 file changed, 11 insertions(+), 6 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index c7c9e88add85..dddbebf92b48 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1532,6 +1532,11 @@ static inline int handle_mounts(struct nameidata *nd, struct dentry *dentry,
 	path->dentry = dentry;
 	if (nd->flags & LOOKUP_RCU) {
 		unsigned int seq = nd->next_seq;
+		*inode = dentry->d_inode;
+		if (read_seqcount_retry(&dentry->d_seq, seq))
+			return -ECHILD;
+		if (unlikely(!*inode))
+			return -ENOENT;
 		if (likely(__follow_mount_rcu(nd, path, inode)))
 			return 0;
 		// *path and nd->next_seq might've been clobbered
@@ -1842,9 +1847,10 @@ static const char *pick_link(struct nameidata *nd, struct path *link,
  * NOTE: dentry must be what nd->next_seq had been sampled from.
  */
 static const char *step_into(struct nameidata *nd, int flags,
-		     struct dentry *dentry, struct inode *inode)
+		     struct dentry *dentry)
 {
 	struct path path;
+	struct inode *inode;
 	int err = handle_mounts(nd, dentry, &path, &inode);
 
 	if (err < 0)
@@ -1970,7 +1976,7 @@ static const char *handle_dots(struct nameidata *nd, int type)
 			parent = follow_dotdot(nd, &inode);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
-		error = step_into(nd, WALK_NOFOLLOW, parent, inode);
+		error = step_into(nd, WALK_NOFOLLOW, parent);
 		if (unlikely(error))
 			return error;
 
@@ -2015,7 +2021,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 	}
 	if (!(flags & WALK_MORE) && nd->depth)
 		put_link(nd);
-	return step_into(nd, flags, dentry, inode);
+	return step_into(nd, flags, dentry);
 }
 
 /*
@@ -2474,8 +2480,7 @@ static int handle_lookup_down(struct nameidata *nd)
 	if (!(nd->flags & LOOKUP_RCU))
 		dget(nd->path.dentry);
 	nd->next_seq = nd->seq;
-	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
-			nd->path.dentry, nd->inode));
+	return PTR_ERR(step_into(nd, WALK_NOFOLLOW, nd->path.dentry));
 }
 
 /* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
@@ -3464,7 +3469,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 finish_lookup:
 	if (nd->depth)
 		put_link(nd);
-	res = step_into(nd, WALK_TRAILING, dentry, inode);
+	res = step_into(nd, WALK_TRAILING, dentry);
 	if (unlikely(res))
 		nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
 	return res;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0gGIUtmYHYXYB%40ZenIV.
