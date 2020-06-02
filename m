Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7V33L3AKGQEY42N2ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 740DF1EC209
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:44:15 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id u123sf607447vsb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:44:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591123454; cv=pass;
        d=google.com; s=arc-20160816;
        b=o5f7PeyIW5PBxQpogWhoPWdSDOFClNjhotc5hKabG11PhUO/PKeaCYGS7oEeaB/XON
         HW/Gu6XUApacT+lQVvAjUlsB3iAXxy7CR6lrE6Nc1a0GBrI8JRiKDuqPvEIFJBNCGqAV
         J78dlU38hCqq41fxCZvGRZgDBZh+NPyfqkWnHcv+D7e70hwYAv+uutFJXqK46Q6I4Po9
         iFSAht6Rgk+ATVaXEH9KGNRLP0S8iIJCoNmUtW5EDUrX/RKTJSxl5Sf9AfwQL+XCh2gf
         iK2/jyHPzkCZtvQab4g9CP0H6Vxd7Q6Or+WTOf6/Yq+W2AOEill719Paru1CQzdFlncI
         bj4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=1MCme/qwqeZtLDjEcX0kP/bkYIMrtqbNNani+7DBnMw=;
        b=z0kt6BIeCVjiSV0jQ1RNa/eG+IDiW3+Vmu5U/JIy3dZF5kz/HHobcDYVa1px0MAz7j
         lA6ibzvuF89OsjHpAsnzqcELtJzxZ2wWycHWtO4cMYX4qpBXaFUnAfZgLEYIueckMd09
         rzpPk+zJr6JBeXP107mpyzNWaqzfFHpOH0xuLQ0vaQNoI1HO/IlEBpP3rBZViaQ8i/OS
         Z6ajFHM+2iSlj19IbNHPvYsd63cdupyshs/d+u9XdwhIRT2NeZIXjuwm7/fUrgiLOzOb
         JG+E8l7Vw56FtqBygPxQCNFFKcY1BBV22WvBbmTkiz5VqQA5aKCHrUD2uuo4/V8uTQm4
         rdWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bo8SJMR+;
       spf=pass (google.com: domain of 3_z3wxgukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_Z3WXgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1MCme/qwqeZtLDjEcX0kP/bkYIMrtqbNNani+7DBnMw=;
        b=KKjcH0EGFyYlfAtbZdkpWrMuyEZlaUe5DbzYsItqu6+Cn5QtGfjGo/+RW/tBOIK93q
         6hnHOoLzBPNYeDKgwVSI02muN/KGFISP34mqL/V9G2TOyySozcah9AdY5aHgrnaEW1dj
         hEna5gzIQt2r7nu98SZoEmqCez6AQB0IYGv539D5dyQnm3WJwhxkyzRIFBJOiLIO4oqb
         gg/wpwY5V2WVOiz/lTXTCigFRtiSPpgqwSHSQ2jOjCAhfm8FtoahViibtb7QeOF1cwjK
         bVwFWipcjhRdalmkeqwRo+fNKi06Ug6WPG8CIcAcUeq57teMYAAK7UyrpZucmezhDQKP
         GzQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1MCme/qwqeZtLDjEcX0kP/bkYIMrtqbNNani+7DBnMw=;
        b=noYSUnMNOIDhf0NCNL1aLSQWhxfC+ecVYIvCMiNyYxhz/6NoCxMmSgK2GmOwwUSr+U
         BWNgTXjvLyX/hqVCG70iedjvLpXaNEVsVxEQ7YIYNXuvC0b6r00zuoaLi9jltIJ/zGRA
         hs2Brt4Jv/p6/FiYjBIh4kPTVl5tHVocIYZFNo5NyNwpCaeHDl2UV22YHNSVptAHT0Bd
         v9z6KazBYH4/UcilsAZFQBdX8Z7KT+KtI7xlcdUHLAe0g8ZgLIwswfBr4W3jp8K6e3NL
         VC1d00v4cffAOTfy0V98+Mi/0YR/h9LQVGDeRJUtOMnrwVRgB8z6P21x9/9WNZXs9N2M
         Mdlw==
X-Gm-Message-State: AOAM5306XXVy/uvqDHz2ib9XdUXnTbK9dlVI2EgNkrd0a5lmbQRgfAr9
	p5G1Hjlq4HPwTDYqY8l2WUg=
X-Google-Smtp-Source: ABdhPJzgCzehWQLEowcbRvk/SOhgOuH2gYv/3qyWjmbZiCmUmXQSwgo1YnsmtcLE2AlUjbKq+uAG8Q==
X-Received: by 2002:a1f:3655:: with SMTP id d82mr18604332vka.1.1591123454386;
        Tue, 02 Jun 2020 11:44:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c305:: with SMTP id r5ls1091654vsj.9.gmail; Tue, 02 Jun
 2020 11:44:14 -0700 (PDT)
X-Received: by 2002:a67:1502:: with SMTP id 2mr19779940vsv.80.1591123453999;
        Tue, 02 Jun 2020 11:44:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591123453; cv=none;
        d=google.com; s=arc-20160816;
        b=sQpB0mVwoIXI6D9qJPyRyF+fdCGDREU9oJtUGeTiGvbSqwA1kUpWef0pQrYQt/DVCa
         iy9k7m6p3UvnrQzakypIeo6GSzVwXJw1k4BxIYFnw/pMLJY+xquEfws+9Ym8JR2SPqLQ
         cROtUwuZqE6d4y13qVcAsSJ14uHX1BmjbTmPU6jmU2PEceITtyqROKlm4BnBK7TWg8js
         cvlGE87KoFjxpr7Eloi0sPN3Jsg+MpGubXWkSaByR1UjKapwt5FTabkl2dWgvWX422o5
         6eNodKHnjIdDtn8pvbIbkeLb6RwE30sqPABJTitNK1qMVKp0cl0i/gnc1FOTMbyv0G8L
         jl1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=051VEaYf6qrL8JFuh/5zzz3L2mMvFIzQDHhJf0eGSZs=;
        b=vsxjno1LAv64K+4PhJoRGKcnLkFw6BPg2m7bUZo9I43NX2fq7g4CQfj46IarEELalO
         QkJXJvCEXj/1cv6usYO9nJDkgy7V3JzCYBxqORi/+dvPoKUx6nhkZcZdMcphnmq3MpdH
         bOoewym3gOZiPpcOUmCWfAm8N4q6F/ITrgndThP0fmcIFCieYbE+q/2uGFOWgXmmkRa5
         1j/RFphsHjOos88XN4oaJs3eu4UjD0awUhUwxqk8BEkyRzAUO/Fz4VDcU4BW9ka/bIbf
         9Kxt22WGGkdwS1zmvpHjRRIvBszMLGR2Msd/lppY5nSCH69t6AMMK+XXduUIOEgLRzdN
         gxIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bo8SJMR+;
       spf=pass (google.com: domain of 3_z3wxgukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_Z3WXgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q20si223502uas.1.2020.06.02.11.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:44:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_z3wxgukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id n7so18047363ybh.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:44:13 -0700 (PDT)
X-Received: by 2002:a25:c606:: with SMTP id k6mr31464032ybf.10.1591123453516;
 Tue, 02 Jun 2020 11:44:13 -0700 (PDT)
Date: Tue,  2 Jun 2020 20:44:08 +0200
Message-Id: <20200602184409.22142-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN and UBSAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, clang-built-linux@googlegroups.com, paulmck@kernel.org, 
	dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Bo8SJMR+;       spf=pass
 (google.com: domain of 3_z3wxgukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3_Z3WXgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
have a compiler that does not fail builds due to no_sanitize functions.
This does not yet mean they work as intended, but for automated
build-tests, this is the minimum requirement.

For example, we require that __always_inline functions used from
no_sanitize functions do not generate instrumentation. On GCC <= 7 this
fails to build entirely, therefore we make the minimum version GCC 8.

For KCSAN this is a non-functional change, however, we should add it in
case this variable changes in future.

Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
Apply after:
https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
---
 init/Kconfig      | 3 +++
 lib/Kconfig.kasan | 1 +
 lib/Kconfig.kcsan | 1 +
 lib/Kconfig.ubsan | 1 +
 4 files changed, 6 insertions(+)

diff --git a/init/Kconfig b/init/Kconfig
index 0f72eb4ffc87..3e8565bc8376 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -39,6 +39,9 @@ config TOOLS_SUPPORT_RELR
 config CC_HAS_ASM_INLINE
 	def_bool $(success,echo 'void foo(void) { asm inline (""); }' | $(CC) -x c - -c -o /dev/null)
 
+config CC_HAS_WORKING_NOSANITIZE
+	def_bool !CC_IS_GCC || GCC_VERSION >= 80000
+
 config CONSTRUCTORS
 	bool
 	depends on !UML
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 81f5464ea9e1..15e6c4b26a40 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -20,6 +20,7 @@ config KASAN
 	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
+	depends on CC_HAS_WORKING_NOSANITIZE
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 5ee88e5119c2..2ab4a7f511c9 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -5,6 +5,7 @@ config HAVE_ARCH_KCSAN
 
 config HAVE_KCSAN_COMPILER
 	def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
+	depends on CC_HAS_WORKING_NOSANITIZE
 	help
 	  For the list of compilers that support KCSAN, please see
 	  <file:Documentation/dev-tools/kcsan.rst>.
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index a5ba2fd51823..f725d126af7d 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
 
 menuconfig UBSAN
 	bool "Undefined behaviour sanity checker"
+	depends on CC_HAS_WORKING_NOSANITIZE
 	help
 	  This option enables the Undefined Behaviour sanity checker.
 	  Compile-time instrumentation is used to detect various undefined
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602184409.22142-1-elver%40google.com.
