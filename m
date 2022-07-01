Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTEH7SKQMGQEHQRIG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 61319563548
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:17 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id qf29-20020a1709077f1d00b00722e68806c4sf835273ejc.4
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685517; cv=pass;
        d=google.com; s=arc-20160816;
        b=jUlBJj8b7zETYqsrlUbWYPDPw2JCQA/sLrpVLHGmM45QONFJTV6um7RcDjvBdIMFXH
         9r0/7rHDMPY0Qb4fif9R5dEyTSrcrPQxwxTwKaW1YzvjlfLTdx3+eCXWAAcq6/PcGuK9
         qvMf/efx1+bQYW1VHBUpxecY+2ggFCik9Ql1CRIA493fPuFwxk5CxUcPLwQxQwSBD8Cl
         Zo7Jq6xIfz4F9LGQdT4cnlInt8oITmnW4/UWHWmdF1zcO+zQ0lbZXIPHJG2KJmBKvQv6
         uuW7+GQj55xbGu3rzmL6BAvsVxI0YKGkwdhDjezBjanoeLwYqmvTkN6qd1ch16uGnXRK
         YE5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=NgiRPsguSKySW6ZjDd/eigdJX1V0OEXUsmfK1uUPWfI=;
        b=xB+xLpBzkO6pc2+0qwqLmbJoOjZ3wRPIEchthyJ2bzZvDTDXJRUGFahEBKUqqbMFnM
         KUV8cv2To1aJdmqubHobaC9Hh+d1qcbVMSgMf+lninJtbP/mn/NBGVSw7gEtjSXAhuzX
         mJPTHwcgWfekLPCkJBaKy9jyKOWFjhnPKNQkrk1WftPKVljRYcakACghWCF5bIsjpO+h
         jdtbbrJBntEa4bQKFcstf7XLjvZV127Kh/QIAp18iOh//9j8vsk0+gwu5ayoplqQcGvW
         0DjsV2+i7b2wVBpGYoqxxOFtgizCWIbLdNLEIAdZqDZaZVY8sEJy3CSSApAm0x+1o2BB
         g+sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q64KAy7O;
       spf=pass (google.com: domain of 3ywo_ygykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ywO_YgYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NgiRPsguSKySW6ZjDd/eigdJX1V0OEXUsmfK1uUPWfI=;
        b=BuQhHXPcbX7ZALsIw0dGlEg7dNP8MNCLDucX682JOSHpjOFCRbIpOVUldDI/MaBmfQ
         lLWBICyhDSySGEGg1VZz4gRkynnLdeZMZ3VlgxAstHYab/c4+fr/uWx4OEoAsKJcr8Tc
         XLrf0pLaOwqouxZesTuatC4+fVfuKi5+zdaQzsOpTc55QGQQcgf0alZUVuag4IJU0W5t
         gomFdFW2aILt6IjDxIZN9veTU7x6A+uSR7lR6VAVlp7vTObIQ77PsPCxrbm14b+T4Xap
         2TX5THd/gUm6K4XpHmZwxf9j+rTON+5tORJRIW7/4k1ORfAYHkDwVTBi7rWuFQESy/4n
         pphw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NgiRPsguSKySW6ZjDd/eigdJX1V0OEXUsmfK1uUPWfI=;
        b=QtSyjagZFHtlcBpPX3XCCaZcz9ggs41q8C1q6sW0yvHyrSn3wS5TNwmC+zaFOEMunF
         CXq/7Fi1tDUItXQVwYNDkRfNvYgR+4r1sTWCWZR+7S6pFWz4XTP9H5F/gMhJ8qSXMYG5
         4Z/7+SlObaCcdBbv9NG+RiVwVfdjIFjKGD1lnodh1CtXab1hJ1nLneL5UfrYdjXcW8qe
         QxEMZSWBbO3SSBaRL6E21CU87QTzNONfkc+Om5fKDebCIgk7PCYG0Zq6bySlzBAdXuum
         S+YjUcMID+5QI4/Ym2m6V8hIHBfKHQi3O8cw8Q+Kar2IfDtjSKWMR3YDLwFwvDF80QZ7
         40yw==
X-Gm-Message-State: AJIora/sODkZ7vsKdLyqfKuOYJxp2myHwuLd5X2mQLjGbh7nlHY56lii
	xL865b7fxFkttpbQjDlPKOM=
X-Google-Smtp-Source: AGRyM1tElJ1rc5ytEJebA9eUTBB7BfzEavvR8vRDZdL/DYTArC/QBAc/1yGIyWt/ER60A7+sLIjW/A==
X-Received: by 2002:a17:907:3e94:b0:726:3b46:ba20 with SMTP id hs20-20020a1709073e9400b007263b46ba20mr14633059ejc.314.1656685517141;
        Fri, 01 Jul 2022 07:25:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4245:b0:435:dc4b:1bad with SMTP id
 g5-20020a056402424500b00435dc4b1badls372236edb.1.gmail; Fri, 01 Jul 2022
 07:25:16 -0700 (PDT)
X-Received: by 2002:a05:6402:5008:b0:437:7f01:82a with SMTP id p8-20020a056402500800b004377f01082amr19503649eda.220.1656685516065;
        Fri, 01 Jul 2022 07:25:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685516; cv=none;
        d=google.com; s=arc-20160816;
        b=VQSZwNTs98CIQyeMWp10tnC6mZERn+y2mapsfd9rFFmT0Lb2cG8Xb9yEqCf5H97y0K
         eBmnjUjpU5uNJIx5+7xKRRQmxBW28mvsGZm7K6xuWdUHpFpRS5rKZvlj+shIeFJ5emVZ
         TMxCvTBv5wzWFLWfbalFxXWhlUNTVUJEpNhrGoGX53FGY4CoSGjX4SxbsmJo+dzgWmAb
         3wU2c8yrino8MVqeBzo/fZhGEJUDZX3yt7Ssdm3WIN/mpIiEiYT6nWVQzmtiJXSo7GQC
         4sZkKS0uDxUJHAGa3FGkSZ7P6ce+V4YGZW2xkfQoA6hfraIaMz9JKKLMKK/mb2uj0Kdr
         Cf8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/n5egAWhgjqHJF7YploSYMAs3TFFsaM1JiTS0Bn58vA=;
        b=W0kZtzqHY4+bn7rRwBphCGXpDRpfPcEi/iU+enBWYASxAa1wizpnH49pOSi5y28CsQ
         xegVQx6BlgCmnQAT7B0aPbtVea4Xfdzql2IpAIOCBlhRMwdnLq+ijcwR+9RyC6hROi64
         WTrco/GVoFt0k7RJX7WHgTf4WVyjdMXT/YJJWYLn6s56fQsgkI38Zsz3FosGctfIwHIT
         onjVkIOdLXxfmM+UELJBidN3MbmkEcA8k4UC+RPGkxh6nNyHLiY30zJ4Laa4buXAks+O
         /H8cuo7CL3J/SmOeWDN9WXN5y+Ip+HixHxNi5+meDKUD9uw0c1u03f6W7ad9BHaO11G4
         h5UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q64KAy7O;
       spf=pass (google.com: domain of 3ywo_ygykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ywO_YgYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id t1-20020a056402524100b0042d687c85d2si698406edd.0.2022.07.01.07.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ywo_ygykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id h16-20020a05640250d000b00435bab1a7b4so1894888edb.10
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:51ca:b0:437:79a9:4dd with SMTP id
 r10-20020a05640251ca00b0043779a904ddmr19173589edd.319.1656685515729; Fri, 01
 Jul 2022 07:25:15 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:08 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-44-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Evgenii Stepanov <eugenis@google.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Q64KAy7O;       spf=pass
 (google.com: domain of 3ywo_ygykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ywO_YgYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Under certain circumstances initialization of `unsigned seq` and
`struct inode *inode` passed into step_into() may be skipped.
In particular, if the call to lookup_fast() in walk_component()
returns NULL, and lookup_slow() returns a valid dentry, then the
`seq` and `inode` will remain uninitialized until the call to
step_into() (see [1] for more info).

Right now step_into() does not use these uninitialized values,
yet passing uninitialized values to functions is considered undefined
behavior (see [2]). To fix that, we initialize `seq` and `inode` at
definition.

[1] https://github.com/ClangBuiltLinux/linux/issues/1648#issuecomment-1146608063
[2] https://lore.kernel.org/linux-toolchains/CAHk-=whjz3wO8zD+itoerphWem+JZz4uS3myf6u1Wd6epGRgmQ@mail.gmail.com/

Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Kees Cook <keescook@chromium.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Vitaly Buka <vitalybuka@google.com>
Cc: linux-kernel@vger.kernel.org
Cc: linux-toolchains@vger.kernel.org
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I94d4e8cc1f0ecc7174659e9506ce96aaf2201d0a
---
 fs/namei.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/fs/namei.c b/fs/namei.c
index 1f28d3f463c3b..6b39dfd3b41bc 100644
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -1995,8 +1995,8 @@ static const char *handle_dots(struct nameidata *nd, int type)
 static const char *walk_component(struct nameidata *nd, int flags)
 {
 	struct dentry *dentry;
-	struct inode *inode;
-	unsigned seq;
+	struct inode *inode = NULL;
+	unsigned seq = 0;
 	/*
 	 * "." and ".." are special - ".." especially so because it has
 	 * to be able to know about the current root directory and
@@ -3393,8 +3393,8 @@ static const char *open_last_lookups(struct nameidata *nd,
 	struct dentry *dir = nd->path.dentry;
 	int open_flag = op->open_flag;
 	bool got_write = false;
-	unsigned seq;
-	struct inode *inode;
+	unsigned seq = 0;
+	struct inode *inode = NULL;
 	struct dentry *dentry;
 	const char *res;
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-44-glider%40google.com.
