Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7E46GQMGQEBYDV7KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FE634759E1
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Dec 2021 14:47:52 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf14638605wme.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Dec 2021 05:47:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639576072; cv=pass;
        d=google.com; s=arc-20160816;
        b=DH7EgpfqVRVPEOuMRZy3yHrLPB+P7gQtn659SrB3M51S2ktvOszmqJ0bW/MQGuS+T+
         Pg9Xud15wpyJ3Rk0eyp8iV1gSX8X6kOLAsmyIDVsDPjgagbbKfeIHuWOPQh91maHTn8c
         w8PTFpKI3Ibst+LG1e9+LQ6TCs+C4zi3WR6WuhHYjahwjlg75Oh4OduPlXCb/ELCwAEj
         fuGY+f5nelEqxBRDUzhzxixql9PQBcXG0uUhXkzI1SG3cucPn9yLecqKERSE4g+XnlwB
         MN14I2qFHxXXfQBGYEZy2ytCdfACuvRjSwqObQlf4xuRaxqVNABa0Ijkbf5KJTkJuoeo
         cqEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=AZ/DCk7+w/OFvekO9PBVgS3sdo4VCo3dTk7LI7jPAUE=;
        b=1GdqUoYgfOQsRH84xY32sGgWFAptPDgRwvjUs9ycJsSMTFawIhyV7Rz6Iu2xmT97zC
         ixefJIORTkuN+LLRN/jO59ortZC9EUMwhAGdXqVd6HP9S9t3HLJUObLQfajKU2xX02yQ
         P2m7WmRAov1t8OAzrDxRsbjXxz+pOhJHgf7+w2uD9To4qLixDToAAi6CyyriLl/Z+MBi
         qW0awHJbJXlFg5wO/uEY6RGzuPFm8iw+bpW4zBeEpT6EAANQYQpuK1DVECKM7XL8mhO9
         p4/p3qkhNyQ3Oc5N+ar4CIUW4KOQ3gNY536J53Z1djWSBswvoOu6qXIpPFJktV0Nq3QE
         1+xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dz6MSih8;
       spf=pass (google.com: domain of 3bvk5yqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BvK5YQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=AZ/DCk7+w/OFvekO9PBVgS3sdo4VCo3dTk7LI7jPAUE=;
        b=bMx9cbNceouUEl0hxUWp24YUQHwH3VvY7MhZfCkw3Hpl7dSneBtQp2hnuHTZBftO1/
         VAxdysS4Zd/VVAwGCmJuaWNcJlJUvUiQ80U76fiCQt8F1MM6uVqZ/id0BrDvzP2jJGjW
         6YOAXVgxhTjkByIOeij53N56HQtvBJWc1L/Da0RTKJMPsb7HDDn8J01Pd+15OweKNBH3
         x4MYDTZw17qr6H/gdw8L2Xkkg/WUYo2cOVUQBrm9lKE+1Vfmv5h4Yv0Dic00LcbfVCk3
         x5urUmR8TtMrv71H9ZfRWAohrhpJVtEN87TtekYl3gfxSehBo70n9Bw7dmDCsUDSux9T
         r0fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AZ/DCk7+w/OFvekO9PBVgS3sdo4VCo3dTk7LI7jPAUE=;
        b=R4V+ArLqY4g7EqgPbh1fRiLMGktHEwNXi+PKZ9gBrVuA1uqsXR00lfEy3FpH3m6kbP
         1WBrPMCE6PISC5TCJzC43QY87lHaYwhPKrrtVeWlRm1/vJXVGkbfY4S1H2eW+rTP57fv
         v2YymRfx7V4d2Rmw+6HxdfoHYswscncjSfPius2saRsaSyqnKXgSdbkjJ2C88Uc9WgDu
         jugS7SO8dQGK2TJrYOKxfQ+v6VKPWpwMxQZUFRdpIKiMyS1fMJpAbr8Ky4KmwE7Bqjpf
         80l/pzvgYiKq+7DX5zbhT3f0/Ha01cM4CvBM/23JDAvqk1bVoJFouXjeo4Sqzi2Or75Z
         tpTw==
X-Gm-Message-State: AOAM533Fda271GEBoYN9QO7IJeKUDk+LexM91G2hAiu3fu6CY5dtIt1b
	WUva9KOIR3mPF+0WNavs+zY=
X-Google-Smtp-Source: ABdhPJwMZKs933awuCwNuLkwsHdDMVSM1SneEqwSttkpoOZtgMB/Az3bhJbGWZbMEr3IanLtpWwoAA==
X-Received: by 2002:a05:600c:1f05:: with SMTP id bd5mr1091446wmb.171.1639576072014;
        Wed, 15 Dec 2021 05:47:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls1948687wrp.1.gmail; Wed, 15 Dec
 2021 05:47:51 -0800 (PST)
X-Received: by 2002:adf:c7d2:: with SMTP id y18mr1297107wrg.717.1639576070952;
        Wed, 15 Dec 2021 05:47:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639576070; cv=none;
        d=google.com; s=arc-20160816;
        b=0izZRfCkfc8SMULe4rWtShiukgB3OIT9iyIYdH3eg19VqvuiaqK47lxk7SgNcG25lt
         s+J1F1R+4nAsYZuPh6Ocghwf5zFsFUUwcVCy32M3Hb21p8PkP/LEYLAQRJj0Gbjs2RFp
         IIbaLZh+V1ynxbtGcF1S2E3B1lGglQtwuvONCUQ89oeYfTg8jD27FVE9BlXCnKg98czz
         cBSDmOjQyYRV7WGJBU+SbspBh9kpZfVmLxx8q8iYwIsLV/O6dJsoKsZUWAmnmxhnAy4b
         3Ik7EAkWBHTkaWGp00a/le67Yoy068nU/0aT17UZjiwzBWSE+LRLBiuydmQD4TotuzEK
         +fvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=OiRhOn6hhEzgrwgWwdtGgn/CZg2YKiK3rEUHDdKnpy4=;
        b=BbBaHO8MeBvoPPi3yA6Zuid1cV2CUTS+/TV96w1OZgx4iHzU8hSHSmvNdJqmne6Jzw
         innQT9bGlOo1RL7aNtY/8Bh7T8A2z3KNp7w5kZRTNfGXjw+kpKHQc9lY5HdKZDe8a1fr
         y+s3nX6av02XDFyEmaE4XEh4riUUX7h09I4E16PhH0y3HP+gvpEAudlZ7r0geB2j4SuN
         BiLug6tV9wacEhFh2YeMHk5TacEw+4cXcw8KXUrC2VXr3UclbRmmjg630ySVCD+fZf/8
         5b4frtEfcHbnGcx1Tch067sqOu29vJonH0gJ+g/pZZZ8pq7wTowpIrbldjX42VhYe37W
         WEXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dz6MSih8;
       spf=pass (google.com: domain of 3bvk5yqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BvK5YQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a1si90202wrv.4.2021.12.15.05.47.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Dec 2021 05:47:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bvk5yqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 69-20020a1c0148000000b0033214e5b021so12608832wmb.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Dec 2021 05:47:50 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f9c2:fca2:6c2e:7e9f])
 (user=elver job=sendgmr) by 2002:a05:600c:4e56:: with SMTP id
 e22mr2873386wmq.39.1639576070516; Wed, 15 Dec 2021 05:47:50 -0800 (PST)
Date: Wed, 15 Dec 2021 14:46:18 +0100
Message-Id: <20211215134618.3241240-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.173.g76aa8bc2d0-goog
Subject: [PATCH -kbuild] Revert "ubsan, kcsan: Don't combine sanitizer with
 kcov on clang"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dz6MSih8;       spf=pass
 (google.com: domain of 3bvk5yqukceulsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3BvK5YQUKCeULScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This reverts commit ea91a1d45d19469001a4955583187b0d75915759.

The minimum Clang version is now 11.0, which fixed the UBSAN/KCSAN vs.
KCOV incompatibilities.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Nathan Chancellor <nathan@kernel.org>
---
 lib/Kconfig.kcsan | 11 -----------
 lib/Kconfig.ubsan | 12 ------------
 2 files changed, 23 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index e0a93ffdef30..b81454b2a0d0 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -10,21 +10,10 @@ config HAVE_KCSAN_COMPILER
 	  For the list of compilers that support KCSAN, please see
 	  <file:Documentation/dev-tools/kcsan.rst>.
 
-config KCSAN_KCOV_BROKEN
-	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
-	depends on CC_IS_CLANG
-	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=thread -fsanitize-coverage=trace-pc)
-	help
-	  Some versions of clang support either KCSAN and KCOV but not the
-	  combination of the two.
-	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
-	  in newer releases.
-
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
 	depends on DEBUG_KERNEL && !KASAN
-	depends on !KCSAN_KCOV_BROKEN
 	select STACKTRACE
 	help
 	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index e5372a13511d..31f38e7fe948 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -27,16 +27,6 @@ config UBSAN_TRAP
 	  the system. For some system builders this is an acceptable
 	  trade-off.
 
-config UBSAN_KCOV_BROKEN
-	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
-	depends on CC_IS_CLANG
-	depends on !$(cc-option,-Werror=unused-command-line-argument -fsanitize=bounds -fsanitize-coverage=trace-pc)
-	help
-	  Some versions of clang support either UBSAN or KCOV but not the
-	  combination of the two.
-	  See https://bugs.llvm.org/show_bug.cgi?id=45831 for the status
-	  in newer releases.
-
 config CC_HAS_UBSAN_BOUNDS
 	def_bool $(cc-option,-fsanitize=bounds)
 
@@ -46,7 +36,6 @@ config CC_HAS_UBSAN_ARRAY_BOUNDS
 config UBSAN_BOUNDS
 	bool "Perform array index bounds checking"
 	default UBSAN
-	depends on !UBSAN_KCOV_BROKEN
 	depends on CC_HAS_UBSAN_ARRAY_BOUNDS || CC_HAS_UBSAN_BOUNDS
 	help
 	  This option enables detection of directly indexed out of bounds
@@ -72,7 +61,6 @@ config UBSAN_ARRAY_BOUNDS
 config UBSAN_LOCAL_BOUNDS
 	bool "Perform array local bounds checking"
 	depends on UBSAN_TRAP
-	depends on !UBSAN_KCOV_BROKEN
 	depends on $(cc-option,-fsanitize=local-bounds)
 	help
 	  This option enables -fsanitize=local-bounds which traps when an
-- 
2.34.1.173.g76aa8bc2d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211215134618.3241240-1-elver%40google.com.
