Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPGV26MAMGQELTTOKOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id F27545AD25B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:37 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id z11-20020a2eb52b000000b00261d940ce36sf2792504ljm.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380732; cv=pass;
        d=google.com; s=arc-20160816;
        b=f9aDEISLIJ7SlmByTCG8WgwgXU7VBC0dZeOOV1P2m8ZObq2Nbxap7x5+cWAOzgKMGL
         +Npl0LuP/pL5R2kqZ7uiAmI6daXoUjsY15hKQBiJuAcKsYeqZdupbMNQ0o3HGDhgwUqS
         q3yZaTI3XKxcchdoinqHYVlp1JhCYVjNE5JkOr4sFudshaHn8CqI8FlXh83dGaLmcKt+
         DHSpS0dmIPp9122EAxi7IF9D66lpzdMoI/eglYjYfde8a0emC06XicBDIBU0LfCgU0jl
         Q5flJXTOThP59PgGzuShnY/fKfN9VRvMhi1hLxF2t67StL2y2k1JB/YKBML2FioSfMjI
         S31Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+HwiXMhkuh2W6T+qefUq7XKDo1qQsQBTJcTRutXBx1k=;
        b=lvHLKLYyU9gQGkVR98LKTOF6aQhyVTSaSt7Kkg2uWANuT67XrHxMJooyeZSkhoVUgb
         aZ5qTr4j0ivbjWVLFyTQFddDWdEn53N6YuKgLwdOT7qFQ8V58an1cehz1SBtWhIdgG77
         qEBamcdAEi2pg/Kd/2cOKWj/QJDAaT5+GWQzFIi3+xDTUb5JX0xfuAruSnVgTLK2X7V9
         ukdb4c/qst3Bu//1yFUsSSKmMFLoSF72NcTF+uu4Ww5QeLXLyRj0ct1WfrkbLaseiPaJ
         Sb471nwHlhSbR+VMC477pDHsaVig+2Ye6MZlp95ydq7wY4Ck40l8jr5jVa8PRTnqY5lE
         jnfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bQ+/47cK";
       spf=pass (google.com: domain of 3uuovywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uuoVYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=+HwiXMhkuh2W6T+qefUq7XKDo1qQsQBTJcTRutXBx1k=;
        b=B+K+IvppkDR9oRXFMJ9apFvjkdt0lXiSJSBKDXyHcVo2N2crC/Cntt0LzcM4tWHRlv
         sfY0w9CvrNrCUnCshTM00tFy7VINtgym/af5vsEKj0+JUGUBXbDLcFUoYZWX0G7NotKi
         TrTSxOskwEKdRwkiKqvHyf3OKfzz22Qv3LFludKifzDjl641P9H9gLnfyU35pbLEfWll
         CgZIMF+gv1r08stEIO+xnTAalzc6gMZpIRtRRcvXKoXjK/8X0yBKEGfbVNm+tSde0/5z
         n9wwWCbFOAsfEjpLU5MgWK+QLwlvpOulvw35x1sA1o5xD1CvgQldQ7KJZy5JZBSIujWr
         CLEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=+HwiXMhkuh2W6T+qefUq7XKDo1qQsQBTJcTRutXBx1k=;
        b=JtcG7MCMi6+4xff2FpWopfajjaICK15M4qSuUIuAo0KAQ/C/I+cKG06vAP5zElHg0l
         k6bDcihpF2vhUtzwiOaNGCgbLegqLsZRMAQhfdZZoN1FcP6GGbrUAHrpsLwy6a+/18se
         Gahrku7u29y/3FhrDKr3fQDy5QuoC4nTkdBTAPDejerNL2j01kswJgVYqsFWHt+259wd
         qfMIU2p6udW24hLbMLnHUTiP75OuFz5fq09Et/QCWuvvm1gAc9lbVW7GG3SZ1G9oygpz
         lVFLz4AEjUA28phLjcU/05UHLNrAnnCnHJqqZTdqd5TpZ+CjZAwjMMpQwF+nZAeAg4cf
         P5wA==
X-Gm-Message-State: ACgBeo1IDb/TGIexNXHuFsWSw/Enh+AeCESHvWsvuXeZrmT9kJp/uQA4
	mkmfe2X47+6pByKKQ4yM7aA=
X-Google-Smtp-Source: AA6agR7wMiLER0trdn9PHopF0jxFIgZPltTAwxFEbqAR5EVpm8M+jldrdC/ZjP16UQ+t2aNyqnDajg==
X-Received: by 2002:a05:651c:2385:b0:268:92f0:5f45 with SMTP id bk5-20020a05651c238500b0026892f05f45mr6826669ljb.405.1662380732329;
        Mon, 05 Sep 2022 05:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:880c:0:b0:25e:7450:b825 with SMTP id x12-20020a2e880c000000b0025e7450b825ls1560880ljh.5.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:31 -0700 (PDT)
X-Received: by 2002:a2e:9c88:0:b0:263:d696:75ba with SMTP id x8-20020a2e9c88000000b00263d69675bamr11250203lji.491.1662380731048;
        Mon, 05 Sep 2022 05:25:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380731; cv=none;
        d=google.com; s=arc-20160816;
        b=I2X7/dzmyWAalx+CdsnkGKs+hM8UT7ooJ1R5K0e4thN3A/2Kp6zvllCnlj43lrFq5e
         ACwfdngHlj7i93VjRDKsDYUkT43tOzx1O9HXKOQ/VvDS+juqRhjX5rAcmjD97VN6kVNX
         GpshNsZ1zbiet/EY7L09usY9J8jSj8PMoNpLvDJGH/3DqPJGBzrskeqKeCyrXyEzR+IK
         Yv2yi4jT0SmdEjYWuqZyJ35dQBiLYUrTQK9aE5p7kGLGuTNFr6du1vkptwD4bPYtBUx5
         QpAfUVWIzgLFzO0C8tKVq5M6c1V41zofsOTqNQXdONxzIOCqBf/v1COhSDSSPWA2FUuD
         Lejg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=XCZJZVAa3O+3/P+XN9/lo0y8HYORhozGNxqdXHsrUsA=;
        b=N2xTP5cbG1fcZidFcVV/61tT2goE+LYXFY677HlD7Im2wK5kwZrcqZkwtNxcd3jaKP
         KheNTfdpUk4Lz4RZtj8jHdQH9F5LFghJgNtkIjoUvkTkyGbHW7oq8lKA6GDLmNVRZjMW
         IJ29I57LkFCSLx3fRMziRoRuaruvZgiwM8K4K5Fo815/orrcr8+jw307ylKuMDYH2Bbb
         jxpiTplJmhthAzD06FFp69p2daLRj1ZnqqZXnTogdUy2FwJXJ5YbASnCwOcyC3mpG5PL
         c7miTMI0PRU4MT2NPmsMBd62SIXmcOTjOQ3ONJVsGK8zxqGbpii+1nAAb+XOoEiPkEwg
         FQvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bQ+/47cK";
       spf=pass (google.com: domain of 3uuovywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uuoVYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d23-20020a056512369700b00492f1480d0fsi314015lfs.13.2022.09.05.05.25.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uuovywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id ay27-20020a05600c1e1b00b003a5bff0df8dso6220707wmb.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a5d:598f:0:b0:220:8005:7def with SMTP id
 n15-20020a5d598f000000b0022080057defmr25144707wri.435.1662380730400; Mon, 05
 Sep 2022 05:25:30 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:20 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-13-glider@google.com>
Subject: [PATCH v6 12/44] kmsan: disable instrumentation of unsupported common
 kernel code
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="bQ+/47cK";       spf=pass
 (google.com: domain of 3uuovywykcqcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3uuoVYwYKCQcnspklynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--glider.bounces.google.com;
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

EFI stub cannot be linked with KMSAN runtime, so we disable
instrumentation for it.

Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
caused by instrumentation hooks calling instrumented code again.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
v4:
 -- This patch was previously part of "kmsan: disable KMSAN
    instrumentation for certain kernel parts", but was split away per
    Mark Rutland's request.

v5:
 -- remove unnecessary comment belonging to another patch

Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
---
 drivers/firmware/efi/libstub/Makefile | 1 +
 kernel/Makefile                       | 1 +
 kernel/locking/Makefile               | 3 ++-
 lib/Makefile                          | 3 +++
 4 files changed, 7 insertions(+), 1 deletion(-)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index d0537573501e9..81432d0c904b1 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -46,6 +46,7 @@ GCOV_PROFILE			:= n
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 318789c728d32..d754e0be1176d 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -38,6 +38,7 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
+KMSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # Don't instrument error handlers
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index d51cabf28f382..ea925731fa40f 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,8 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/lib/Makefile b/lib/Makefile
index ffabc30a27d4e..fcebece0f5b6f 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -275,6 +275,9 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
+# recursion.
+KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
 obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-13-glider%40google.com.
