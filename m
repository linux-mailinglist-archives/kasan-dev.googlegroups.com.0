Return-Path: <kasan-dev+bncBC42V7FQ3YARBP7JRWLAMGQEQHKYUWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f63.google.com (mail-lf1-f63.google.com [209.85.167.63])
	by mail.lfdr.de (Postfix) with ESMTPS id EB606565FA5
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:16:15 +0200 (CEST)
Received: by mail-lf1-f63.google.com with SMTP id bp15-20020a056512158f00b0047f603e5f92sf3393155lfb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:16:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976575; cv=pass;
        d=google.com; s=arc-20160816;
        b=b7Gkzo/A1MeCvPJ3+NFfWiwsjHiHCYyNSyv36vZ6nlHwMqodo80LdoKEsTHT8lCAmi
         xRb1eW5pKhRTfN+dC/ZNdcMEvUwO+brfum3KC8gl5m6PLY99/PEeX6wvobsYPCsHbAs0
         ZkI5oKIiH5ALYkxnjVAALPFOooaW0BxPCFaFjQvBL/sdtG3JrY7SQ/pBfUjOtxACxMRq
         ARGA+ijDPlGVcfsB0atMpGWH6Ysoi8rw12OLSj4xODGL5BqRc/dyVESZcD2WoPhruypM
         1T4uaZ660ZULmAaVL+BY2hm0V60DQxjTcN2lHzy2y7JSNl0FcNBRj/DESt7TlzXHUyQg
         Puhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=vOLQjnvlOj0wMHWk/DLImsYtW86jAITYRa4mYDBc5y8=;
        b=WmCmHwPntRQFdFZlJxQ4Kv+H+VQWRD0rjvQ51NEq735mRyXSrW4tASUc/BXZ5LSs1x
         nx46oltt0RndpuoEOZJ9OQLAkoAqtrMd9JtufcoM2Qd5CqalL0965GARE5LXvlDgsnsY
         0/KPTrPP2XXQRTJHJdAcHdpp1lTqL5bki1Ry8n7n/T7zAGuXA67ddI+/UgriRz+TYN/s
         iE9PeBlSiuTzIjh1AWVml2ils8ED7F4NgIzg4uTTI0lPdVgHsDwRGZdVgPdCjlZ0vSiy
         MKNZB07V7joW/6k/sahGNYDqyPwGbvv1YZ+IKkXBliggXNXp7K3Ii27+lx1f2rHkdR33
         ClQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=cKBVkMzK;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vOLQjnvlOj0wMHWk/DLImsYtW86jAITYRa4mYDBc5y8=;
        b=SmWCt27o/zvHiTgdNf4bxO+b0bACm/4WC0OtBHGnbzwqi+xaDjoBn2N2/1MKgEVuUt
         8pxFr/T+e+PBYOsGwNPY6p7WcWJ3E4/oCT/mPI9Zg0AaxA4ZHr9M47/xvIqGktXkwTpF
         H0Bb/4BKbL8h+Ilc53IWWeLdWEXSYMKWbTIr9peJb1fOj9CuEDkskR+9kRWt9IAT1cV5
         g6ev4i0dIpv0xMOZb2G8DSUQGLz3fUVCCM6SZOTtsRsa4Badye3UU8dwOemhCS0DUATr
         JC2PQFwW/9AYjZLbm2kqqbn3bNhvJkLcsNUtTycX8jSXEnM1RxQeHXxQJL0bSXt0n6G6
         ydOg==
X-Gm-Message-State: AJIora/7QPWwgsqyIy6vOM2rw6GNep3up6G77lx5sTmboRTHGmDtSswz
	uPcqH37n9KQdMl6FcXw686c=
X-Google-Smtp-Source: AGRyM1sxAB2IvSHCmnzyOG5WZezU6XXBnnd8vb/8j3LTPsoXjZQAu6iY+QxjG34PAcoD2vCBxMHo5w==
X-Received: by 2002:a05:6512:3c81:b0:47f:ad61:7edc with SMTP id h1-20020a0565123c8100b0047fad617edcmr20807196lfv.133.1656976575375;
        Mon, 04 Jul 2022 16:16:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls199656lfv.3.gmail; Mon, 04 Jul 2022
 16:16:14 -0700 (PDT)
X-Received: by 2002:a05:6512:3d05:b0:47f:b068:2342 with SMTP id d5-20020a0565123d0500b0047fb0682342mr19723702lfv.462.1656976574181;
        Mon, 04 Jul 2022 16:16:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976574; cv=none;
        d=google.com; s=arc-20160816;
        b=xCJuiKc+qQuZt7UCHK0tZbSQ/XHY4Svpxi6dDHyjy3j8405hyGRZoNkULTqXrscW7W
         zUGiXKL4+BO4alUyMwWycKQRSPtX6yiWVrtSpnLL0D1UsJSHnO565SvHuWysbj1ANMXG
         PNSCKE9Zjq3WhaLQ574mW7dDzBwk7LkBJt9izWlFZBLKJ8lGQ+fGmG/4gf9B4TJlepxR
         cTSTxqGdfRWBN0rei5ihcVTh6I/04PmcP1dRhRYiSH2b+A9FIdMkEZ0Z9sWoAeIPproa
         j7qW1rm9q2D7hQVmrb96kxtJ7tnwWM14v7/1GONiibgXwdoYZYaSRNW9QcTS3iolP0Gj
         Umug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pcS1G1OlD4As8AY5pL4+nnYUmzJ1Ij+cKL5OnlOGDmU=;
        b=n1T9s7VY70OiCNUpDinML0RKiXL+VuzunbOUmTySmJHeJ6+2MGHJ8TBHUHu83nYI62
         Upszg7Ngs3RFJzerkmW893DKW3Zh9polnGGU/ncZsD7Ev6xZPuNkgGQ9CCtVLwi/cJXc
         Ul0wOLCvzNctl/n5rqD3sOl4U3k38Q7cmKzRJPvNTiavn0AQtgutbuGYz3j0403OABvR
         2OhyhdzGd885lsz5Wox5wxY1DSAqtHuWNgYgvCZtj5etm6MK7YLcqB1BvjMg+z82BbFp
         aKMxymZ2WdLJhaergjSXalA107u/1MudokeJ8TNh6YggjQkYt4X/2JBuLHG3uZtIw7cT
         S9wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=cKBVkMzK;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id o9-20020ac25e29000000b0047f8e0add59si1435359lfg.10.2022.07.04.16.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:16:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VI2-008AZ2-Rt;
	Mon, 04 Jul 2022 23:15:38 +0000
Date: Tue, 5 Jul 2022 00:15:38 +0100
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
Subject: [PATCH 5/7] follow_dotdot{,_rcu}(): don't bother with inode
Message-ID: <YsN0mtY5ecwW7MS3@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=cKBVkMzK;
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

step_into() will fetch it, TYVM.

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 15 ++++-----------
 1 file changed, 4 insertions(+), 11 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index dddbebf92b48..fe95fe39634c 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1880,8 +1880,7 @@ static const char *step_into(struct nameidata *nd, int flags,
 	return pick_link(nd, &path, inode, flags);
 }
 
-static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
-					struct inode **inodep)
+static struct dentry *follow_dotdot_rcu(struct nameidata *nd)
 {
 	struct dentry *parent, *old;
 
@@ -1905,7 +1904,6 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	}
 	old = nd->path.dentry;
 	parent = old->d_parent;
-	*inodep = parent->d_inode;
 	nd->next_seq = read_seqcount_begin(&parent->d_seq);
 	// makes sure that non-RCU pathwalk could reach this state
 	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
@@ -1919,12 +1917,10 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-ECHILD);
 	nd->next_seq = nd->seq;
-	*inodep = nd->path.dentry->d_inode;
 	return nd->path.dentry;
 }
 
-static struct dentry *follow_dotdot(struct nameidata *nd,
-				 struct inode **inodep)
+static struct dentry *follow_dotdot(struct nameidata *nd)
 {
 	struct dentry *parent;
 
@@ -1948,13 +1944,11 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
 		dput(parent);
 		return ERR_PTR(-ENOENT);
 	}
-	*inodep = parent->d_inode;
 	return parent;
 
 in_root:
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-EXDEV);
-	*inodep = nd->path.dentry->d_inode;
 	return dget(nd->path.dentry);
 }
 
@@ -1963,7 +1957,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 	if (type == LAST_DOTDOT) {
 		const char *error = NULL;
 		struct dentry *parent;
-		struct inode *inode;
 
 		if (!nd->root.mnt) {
 			error = ERR_PTR(set_root(nd));
@@ -1971,9 +1964,9 @@ static const char *handle_dots(struct nameidata *nd, int type)
 				return error;
 		}
 		if (nd->flags & LOOKUP_RCU)
-			parent = follow_dotdot_rcu(nd, &inode);
+			parent = follow_dotdot_rcu(nd);
 		else
-			parent = follow_dotdot(nd, &inode);
+			parent = follow_dotdot(nd);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
 		error = step_into(nd, WALK_NOFOLLOW, parent);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0mtY5ecwW7MS3%40ZenIV.
