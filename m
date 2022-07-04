Return-Path: <kasan-dev+bncBC42V7FQ3YARBZPIRWLAMGQEJT3U3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f60.google.com (mail-ed1-f60.google.com [209.85.208.60])
	by mail.lfdr.de (Postfix) with ESMTPS id A1BDA565F9C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 01:14:45 +0200 (CEST)
Received: by mail-ed1-f60.google.com with SMTP id n8-20020a05640205c800b00434fb0c150csf7892890edx.19
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 16:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656976485; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZ36E/bz1X/fLWPeEmXi+FE8qsDTNunUfzra8Hj8sAfZckvjEQ9VLqkxiqw98FiUh8
         Z52AmGds19zNF8qC2sOYFO84ZG/+V1r9neVC3VFtfvBO+v8xFKsdnksOATVLjMl2K0l1
         R6EFUPx2nx8DPHcPqQz540OmOdtzRL30iAfjriwJerG6uvCZOA+MkYYW2CglIOepISKA
         IcGW4XB5y5e22XwdAtN2JLnEYsL/JwcLCk/EsG4xR5FQ5oayHB1M0kWq2VgOHQrsRY5r
         t9zxMNS6nxruG5uGiWinl5yF7yocOM/LNs0SxsZJuj3RpemgofKRBMyALaDyVynR+Sti
         6jEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=HACsiB0z8sJ17oqnDT7y9dw3VZGh3Q9RRcjyRYn7pCE=;
        b=iA3loCtoxlWhniQyyBt64gZ22hRnCWRv8z2I+TWSQzl3X9GqmRuw/+UjjxlbCEzEpu
         JMrY6ZpGUCrGsfJRfULYLaQfNUNfCOaDoKRQCUyEQ0mSBHrX6EncFcLHsG56FflD1RuH
         LcmY9zbB/VHh9B91uZWex6lCadcrVCJ2gP+O3JoWrU0o0Z+N1Pjo+UtSEk6A4nM9jEi1
         ILjDpUJfEqiSPbqDwBJa8IRybLzFmoYHnkqB98rmndpf3tSGcbj4RYQgyvvUfiUf3YOs
         MIfObiCkOhZmATnSSTlTgFVa5msu4ImTEki6Q3BdRp3Er9Etr0unqJyejC7KPmxuZ4+k
         j+Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=sWOTLQXm;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HACsiB0z8sJ17oqnDT7y9dw3VZGh3Q9RRcjyRYn7pCE=;
        b=JRCvl0lfbo+BIlx+cPob7H2xF4iVsgWVEYEg4TJsnJ59PY5//cbC/cTZhP8td0F6DJ
         4/3Z98vqTa/MP4lBZVGyhlEEo6vUvo6y41XPuWuJjsK0jXJtwOEPbl+/ky6NbdJN94uN
         OAlbjL2JCMLxxzsIzkmhu3sz1r4SDjnGuAmWsmtjMf4Qz7/CV7W1g/tRJpexinf/dR1m
         4gRL3tmHwO1i1VCKUXSprOCA0K5oc7JMBkCwyhljKoK/qteHDge0bA61k5GQOtSUVJKY
         GkRKCfnSOOCqKjKMdbw9pOn74FhMyyQv8Y6oZilES6phnM9EzHDvKpcVsqY+GeF7WSHm
         +FCw==
X-Gm-Message-State: AJIora8Yq1Tj2ignt4fx3QbMO8CzSsFSwNC0N19Au1QYekbXBlxE5ZTb
	1UeaONW8DH0NjECZ6Lj+qxI=
X-Google-Smtp-Source: AGRyM1tCBBJyfM3Ct1fDRbdFTxG1/zyQeGQXJ3EwjTZ6RcDuXvZw1dljs0MEQ+UZbixprn98vwZZLw==
X-Received: by 2002:a17:906:b250:b0:726:efbf:702d with SMTP id ce16-20020a170906b25000b00726efbf702dmr30520506ejb.135.1656976485277;
        Mon, 04 Jul 2022 16:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35d5:b0:43a:7724:247e with SMTP id
 z21-20020a05640235d500b0043a7724247els132530edc.2.gmail; Mon, 04 Jul 2022
 16:14:44 -0700 (PDT)
X-Received: by 2002:a05:6402:15a:b0:431:71b9:86f3 with SMTP id s26-20020a056402015a00b0043171b986f3mr41161757edu.249.1656976484054;
        Mon, 04 Jul 2022 16:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656976484; cv=none;
        d=google.com; s=arc-20160816;
        b=wnEHfq2/PZBxViwh+G5CpHM8DF12XP7Ak57KdVBV6QNVzYZ5iaoeMitVxXnuWRIbbu
         oi82ScLCsipuxSWFXloAWidZSiJ36+cJsgwnHm/CkupiQSbxR94QL1ONOhKTQpQ82lZW
         gN+8EvT82T6ia4ImgzOzMHiz0ScEz+QyhjwHhawxEOHAUUKug9DriAMvd3iSW9XpendV
         TkkxHexJZhc4Ue73aDIat34ZQephL6EGLrTwyjdJcOySrvKvOO+MiET1HIGhgT42F9+2
         FporgYfcPWhxt7i7JXKXBwG72uSR6N2TLEUWC3HQeAKn0HMQ47Zq7sMVqHuyM0MkVgUJ
         ERGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yVde6OT5Ehv5tuk0crezw61+e6oS2AMOyyAHAkO3zT4=;
        b=a52JCLRPi4eGc/GMudbZWWfXpW4UhsTX8Oao+6SCpk4mKdZIjCwO1jFTmsAqp1fhwg
         ZtY3oNARzWhfbA4jDooeKUUs4H5JUmYA4hUGrPGxwzuL7RzH/j0rgyvlEMMmDNR+odUP
         9cyo2MTzMSXbRzv5x5FSCSpJAYaZblVMTRYm/bpe7L4bjU5nSFoRSxPgnFvVGM/qioP9
         jV44yqAj/5w/7gk3/9G6WNxCul0YAX/s+6dZGTlW8Wcr3uLeZw7VbEfHnYHuPGyI6M+m
         TqDuKWzbl3KxOnABx/CRDYLNtgqvT+dGLzf+4yitoSg0NeMlY7wzQsc8BlLuOa9ZchIn
         2k1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=sWOTLQXm;
       spf=pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id k24-20020a05640212d800b0043a6dd6b3e8si131437edx.5.2022.07.04.16.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Jul 2022 16:14:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of viro@ftp.linux.org.uk designates 2a03:a000:7:0:5054:ff:fe1c:15ff as permitted sender) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.95 #2 (Red Hat Linux))
	id 1o8VGd-008AW9-Ka;
	Mon, 04 Jul 2022 23:14:11 +0000
Date: Tue, 5 Jul 2022 00:14:11 +0100
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
Subject: [PATCH 2/7] follow_dotdot{,_rcu}(): change calling conventions
Message-ID: <YsN0Qy5d69q6YWhS@ZenIV>
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
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=sWOTLQXm;
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

Instead of returning NULL when we are in root, just make it return
the current position (and set *seqp and *inodep accordingly).
That collapses the calls of step_into() in handle_dots()

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
---
 fs/namei.c | 16 +++++++---------
 1 file changed, 7 insertions(+), 9 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index 4dbf55b37ec6..ecdb9ac21ece 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1909,7 +1909,9 @@ static struct dentry *follow_dotdot_rcu(struct nameidata *nd,
 		return ERR_PTR(-ECHILD);
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-ECHILD);
-	return NULL;
+	*seqp = nd->seq;
+	*inodep = nd->path.dentry->d_inode;
+	return nd->path.dentry;
 }
 
 static struct dentry *follow_dotdot(struct nameidata *nd,
@@ -1945,8 +1947,9 @@ static struct dentry *follow_dotdot(struct nameidata *nd,
 in_root:
 	if (unlikely(nd->flags & LOOKUP_BENEATH))
 		return ERR_PTR(-EXDEV);
-	dget(nd->path.dentry);
-	return NULL;
+	*seqp = 0;
+	*inodep = nd->path.dentry->d_inode;
+	return dget(nd->path.dentry);
 }
 
 static const char *handle_dots(struct nameidata *nd, int type)
@@ -1968,12 +1971,7 @@ static const char *handle_dots(struct nameidata *nd, int type)
 			parent = follow_dotdot(nd, &inode, &seq);
 		if (IS_ERR(parent))
 			return ERR_CAST(parent);
-		if (unlikely(!parent))
-			error = step_into(nd, WALK_NOFOLLOW,
-					 nd->path.dentry, nd->inode, nd->seq);
-		else
-			error = step_into(nd, WALK_NOFOLLOW,
-					 parent, inode, seq);
+		error = step_into(nd, WALK_NOFOLLOW, parent, inode, seq);
 		if (unlikely(error))
 			return error;
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YsN0Qy5d69q6YWhS%40ZenIV.
