Return-Path: <kasan-dev+bncBC42V7FQ3YARB5HJRWLAMGQENRIYPZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-f56.google.com (mail-wm1-f56.google.com [209.85.128.56])
	by mail.lfdr.de (Postfix) with ESMTPS id 895E0565FA9
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:17:08 +0200 (CEST)
Received: by mail-wm1-f56.google.com with SMTP id j35-20020a05600c1c2300b003a167dfa0ecsf5961644wms.5
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:17:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976628; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLRu5LzOjm/Zjj2tJH11Puy6vB2JC01t/3CNY0dfmCz6PapRjwuwwi4dZVsFjookUs
         1wykvc0IaMhobvKFfIDpMKBuBuXylMCFAm5JPxGbPE48XHUZp+GArHk9spDN2QHem2ox
         +SZGHzFtoan48aO+PkPOTJAzzDLfK9IoqPchKETEtZ88cwyzh1HydtBfPvlWXCdU87CS
         B8z/wKpemTa4AQS/KfQjAJdqV4t4Kptc3xRwRcU9CoZkzeq7HyIERMEJ45vjtBYBZ1+6
         bsTkBMtMqGIx0ZsXQirD6NEVvAUX3u9YbcWv+6X6e+ifSH/oUoV37JijfuzdIIFlykLS
         I40Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=sULxh/0y/YRwtWnLbHBHkAdquiZxhY3nZiw1NUIGdJ0=;
        b=rXStuHU9+bBkoiAFu5xx18aBp5+5D7PJLmgnuevkhTk3wOQdSDsYG3mRufF/I2qPlQ
         ycYudFoKHmsInQH0iJ0VNtOTdt3C3QXQ2dEvbkVB4CfznDD5smHd9+2UNsBhTA81Ovi5
         NVOVgujesM2ICWsZkMaVxBhCh+8OM+9AlJARbUe6uCXA5H6z7A8dg/5hUmjZ7jj2zl3Z
         HzorpDYDQMhNVA0hlAp8C3V5XYBdYPLCnxMI4XweB8KUWrk+2rU2J+2ztwvhyYaFX+M8
         DdChUKDoOVDtJrULHRN6Qwr+Ew4a6cFw/5visnA2DMcc82CsGVD5Ts90rbtAiSjHFU7O
         ifHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=uElzEPYg;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sULxh/0y/YRwtWnLbHBHkAdquiZxhY3nZiw1NUIGdJ0=;
        b=F3LoI4NEwst6EkolmMqfHk33q1YkprX4MyR6cwRPIdxJcSO/IXtRFEJFVebPG66AfQ
         s59eIsDu8i0perrrDBwhOR3/taujUimh8uXAG1plrrenbE9sEsPPwAjyBSb14ouQYG5B
         w7dgkq4UPoX12TxCrm3ZHW1pAOD0VikxfgPOLN1Kwzq1ASj+ZGJJj1L9SqCE05pKDwBt
         CEWC7s7vwhpH+CkU2ucmJyayQ8H1TjrWlEQnHVMrhKsfFXwMkr/+ZOzHCOS8vsWiObaG
         B3SNatuVLZt7HrTRVLIAiSxjOdeL2JMpGnczot0J+uK2Ci5g2uAFLn9Ug0wSvxi2s6Wu
         HnDQ==
X-Gm-Message-State: AJIora9qAsBGv94S/P5kEknyNm+SizAms2n8UGmd+BrmVs4M1ZMO33G4
	hr00iqOlsd7Cgn4DkfwBy38=
X-Google-Smtp-Source: AGRyM1v78JUauyQ9Rp4wmM//1HNb8EYSdS7LwaEAnUGUGrmbhmLwzLnNayhVhPZcF/2oNTVXx31wBg==
X-Received: by 2002:a7b:cd0d:0:b0:3a1:8f1e:cb2f with SMTP id f13-20020a7bcd0d000000b003a18f1ecb2fmr18864491wmj.10.1656976628335;
        Mon, 04 Jul 2022 16:17:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da7:b0:3a0:3b20:d119 with SMTP id
 p39-20020a05600c1da700b003a03b20d119ls7795492wms.1.canary-gmail; Mon, 04 Jul
 2022 16:17:07 -0700 (PDT)
X-Received: by 2002:a05:600c:4fd0:b0:3a2:b57b:2200 with SMTP id o16-20020a05600c4fd000b003a2b57b2200mr2827844wmq.197.1656976627323;
        Mon, 04 Jul 2022 16:17:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976627; cv=none;
        d=google.com; s=arc-20160816;
        b=RknJcX/8l+jLnstdaW57SA5/JW4EZFAQWH+DB7xZevFogimilO2nSmpG5p48cKSPYb
         KH8y2Za4d4hyX4xvDTHYItkF9PVpq214ONSdD5MrtYqXCbliIQ++bXBqakfloL/JSHk3
         3FNZWiaqNxGXt3F6Mx7JKj4+nlZVpuQImEihCqe0pZ4RK8SIMsFKNrJqlomMyq/fj05y
         Tf1Bhaza9SpwKNmFpTfV3BVKOtep79pZF8nBpRxnjWaj1wlNWAT5zKh1v/fiDMzWgE/M
         YWdYjz8RXholybg4nG9dAxmOOOyEayyoSySlKLwPdQPaS5UrHdMGIdS0E8cb3m3AETkm
         tB6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3Krii5I77Jw+hei/sBgWu8KHpDCvwQjbHpsrcFH98j0=;
        b=QY32CuqqeX17Ypj4bPbPmb0m/0T07qiPIzWE9G294qk1AolcVbiGB6kyDGwrebHV6a
         ZbtqaOD7IQdnjsYNvbycDfgNCaO8A7O8NyRQ/lps2FjvBNqum19qCxjnrmuK5P6PiLtA
         ulOwAngtl03oNoat/PcGhuIRiPXbJm00rkENMZt62KeNSxGzotPomDsQosafcGFrBE7Q
         7OqVRu66FL7i/W5wvKIS8V2pxABVy9G4y+Qm5RllC4PZfJ9TTyHP85Y+Mhzcp0tOrnPx
         l2jv4+YKxEcwcCqaR967d8/EfZ+GLyLX2z94S0OQb0br0OgmP0CNhMCLHuXMyUfr3ulN
         g/tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=uElzEPYg;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id j32-20020a05600c1c2000b003a03ade6826si357939wms.0.2022.07.04.16.17.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:17:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VIs-008AbM-Q3;
	Mon, 04 Jul 2022 23:16:31 +0000
Date: Tue, 5 Jul 2022 00:16:30 +0100
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
Subject: [PATCH 6/7] lookup_fast(): don't bother with inode
Message-ID: <YsN0zovcB+d26OcT@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=uElzEPYg;
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

Note that validation of ->d_seq after ->d_inode fetch is gone, along
with fetching of ->d_inode itself.

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 24 +++++-------------------
 1 file changed, 5 insertions(+), 19 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index fe95fe39634c..cdb61d09df79 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1617,8 +1617,7 @@ static struct dentry *__lookup_hash(const struct qstr *name,
 	return dentry;
 }
 
-static struct dentry *lookup_fast(struct nameidata *nd,
-				  struct inode **inode)
+static struct dentry *lookup_fast(struct nameidata *nd)
 {
 	struct dentry *dentry, *parent = nd->path.dentry;
 	int status = 1;
@@ -1636,22 +1635,11 @@ static struct dentry *lookup_fast(struct nameidata *nd,
 			return NULL;
 		}
 
-		/*
-		 * This sequence count validates that the inode matches
-		 * the dentry name information from lookup.
-		 */
-		*inode = d_backing_inode(dentry);
-		if (unlikely(read_seqcount_retry(&dentry->d_seq, nd->next_seq)))
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
 
 		status = d_revalidate(dentry, nd->flags);
@@ -1993,7 +1981,6 @@ static const char *handle_dots(struct nameidata *nd, int type)
 static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
-	struct inode *inode;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
 	 * to be able to know about the current root directory and
@@ -2004,7 +1991,7 @@ static const char *walk_component(struct nameidata *nd, int flags)
 			put_link(nd);
 		return handle_dots(nd, nd->last_type);
 	}
-	dentry = lookup_fast(nd, &inode);
+	dentry = lookup_fast(nd);
 	if (IS_ERR(dentry))
 		return ERR_CAST(dentry);
 	if (unlikely(!dentry)) {
@@ -3392,7 +3379,6 @@ static const char *open_last_lookups(struct nameidata *nd,
 	struct dentry *dir = nd->path.dentry;
 	int open_flag = op->open_flag;
 	bool got_write = false;
-	struct inode *inode;
 	struct dentry *dentry;
 	const char *res;
 
@@ -3408,7 +3394,7 @@ static const char *open_last_lookups(struct nameidata *nd,
 		if (nd->last.name[nd->last.len])
 			nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
 		/* we _can_ be in RCU mode here */
-		dentry = lookup_fast(nd, &inode);
+		dentry = lookup_fast(nd);
 		if (IS_ERR(dentry))
 			return ERR_CAST(dentry);
 		if (likely(dentry))
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0zovcB%2Bd26OcT%40ZenIV.
