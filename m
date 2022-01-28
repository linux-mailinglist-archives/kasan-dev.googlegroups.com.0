Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4EXZ6HQMGQENJJ5CWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 37BD049F7AC
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 11:56:49 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id j1-20020aa7c341000000b0040417b84efesf2863563edr.21
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 02:56:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643367409; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqDuAmYn0VeFngwe52v44xYQbuU6ammyjNOw+DX8+qtkmw1RGGUMkAdeftyKK8eQUu
         cQCaluVW3APjVeZTD9IJKFP5jAXBpbs0+TTMeC8lyEgv0MuUA16Ly0CzqjdXEBrc/M03
         FIXBFjXrXf67URZ93dn63V+a0MdNmhRG78IF44SHBprOXl8tReYDVj+tUz6dIsW04eVC
         MZbZsBe1E4k1JHrLSQck4sNNtRjpAPKeH4MeNIDPK3t4YrZzvM24wf8qhb7Q4A+0ny/j
         q7QQbzA17BRg9sDcXL5jqqnnJnioM/ahgA+h7tmlmqFd+568FXHFefV03xWYoDgvk3e+
         /Itg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=+kZdYz6mFpo7rSruY9mkBWU0KV4A+pZrcHH+5IEAFNg=;
        b=xLcrmoOw4awxtET38yhdHhMXhAreF6rSMPP1JHAt4Rdx7ft8rk6p/Iu0t5p0xSSkC8
         teS64JVLpQ/PyP2VTElYn3lKKhYzTUXh6FF0PxKcStgo4BINRosNvFylNIudTkMA94UV
         UscMarGjnm/FHZ88t7RUOkAn4kib0AVmuMN6hK3iMYcPHOLT2yzYthKOyJjk5bJaL9qs
         G077V9VyqxMnNQgxKwo0wZv667K/AqHn8LOqEC63h8XaON9bXwKumZm5jmEKNPrQnTdC
         M9RAa9PnbvjhkRr+RbAmq523A5ZgpxO9NdMYx6UWZp85qO4N9v4ZW0m6q4BZcZjWF9cW
         TNDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fhKHd24T;
       spf=pass (google.com: domain of 378vzyqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=378vzYQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+kZdYz6mFpo7rSruY9mkBWU0KV4A+pZrcHH+5IEAFNg=;
        b=LNVebXpTx6p83PZu2yXGu0Jg6zDbVTO+UeOPIxQbeGLt81bWbDSbiM4afPHo0S9uWp
         Jrsqx1H0Lie7NgLBOmmGm6663W3ZUTPBEdEosM5KWS2XqyUHesdfXLAmkQCJtAtCNecU
         9hL8v7dULLHk/drzm8toW6y2Hw0QN5Ro+nLTnSIEoVml8RXEdBrFFeFpr8SzdSV5z85R
         N065/zXrP8NQnGwZ1M3JRu+O9kOgKjQOmRm9pj3lVT4XnGPPHQUaeHpZZI2KqJ3NAl/1
         b9HjDDqnRec4lEBpgnhcw0SoUCCCjcZ/JxHXu3ec4CZPDTIBNmFDWFBN9GvtN1C6CKG0
         V5+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+kZdYz6mFpo7rSruY9mkBWU0KV4A+pZrcHH+5IEAFNg=;
        b=xC7Qx6I+AFCtZIHZjFkfdz3v9j2sLrDmHKhUgcjx8IqTKdRCeAvSqQZ66N1gtCQk8W
         qzANs35CyKrJLfuVW2f9qDti2xBUcjql+Cc+x6m5BxaBLCoWmIwx010aa/SmWjhBQpwI
         g0hdLepq7bn/NdyYs47AP/FOT+GMTIqDG/VacooIAtfEkddX/lGU2xGboZZ3EE/1KjON
         V2u0co0CfCr7vIXVqI2xBXU0daQLtnanbYLpZF2l1aT/+h26n5oafHVJPD0D3x8rvSy4
         uUKfeAqnmf56cb7xY0+b7P5ACLO0tsoY8pCFb6j7VApR1MjVKHsyZRS3zWNZv2ursAl/
         xvPQ==
X-Gm-Message-State: AOAM533D4s6l88BX+MedhESjVDzcEw4jA/61WMGZ89Lsg71Wk7lBN9UZ
	+qkloGzz/M9K/PQWFvW1qs8=
X-Google-Smtp-Source: ABdhPJwomQxUcT36slkkawqp5u4a1UewtyjFyJUJ/mNP0dzD1ctt66pWnhoYPNTMIvDfW0jjCbkRQQ==
X-Received: by 2002:a17:906:dc8d:: with SMTP id cs13mr6631400ejc.174.1643367408821;
        Fri, 28 Jan 2022 02:56:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:629d:: with SMTP id nd29ls3858057ejc.4.gmail; Fri,
 28 Jan 2022 02:56:47 -0800 (PST)
X-Received: by 2002:a17:907:94d6:: with SMTP id dn22mr6111298ejc.81.1643367407807;
        Fri, 28 Jan 2022 02:56:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643367407; cv=none;
        d=google.com; s=arc-20160816;
        b=q2tviMgCC2ht1XSuz0Aq4hX1T1it5ARbuX4lEUdche/7PSR+LFexFG+rxMvM9nW48y
         fiofpduFWx7ONXzJwGwcUSvAf02Tf7nszgXPT2NnC+2Sr0RsuuVag87IL1+zxJP15cmr
         0K2OAcuAyY/yeqcozk79G7XfZh4B+p5srigKz0oYigYAewIOJWnu48jTaExlGGtwfmKq
         eAZFWzEmiv5l0D9e/sJyGErypEryRWwfpZgrsnx/piI41aeV3+9AvQMAqv+vz8CALabM
         tfK1RSQFEsUueElwbLWSMKdAc/h5yN0Kqyy23S0Qsz/SDsvYe5MsskC1vB+TMs2sq6Dm
         AAig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hOuzpWzwLqePrG7KzMy6POmcapEVAbM5YRYunKpotWo=;
        b=WPf2KIAmQpjD4qP8cb9ALIZv8+MfMSHgGCtb4Mcl1DWNHQC1yT2pW32UFopqQTfOMQ
         /yU+i2AluTxZMz+st9sh1iQ/+F7I+gu8bmMF93l0iwMjgrCdCtBvn8M57Y60+7FRomUx
         HKHD4FRr0gUu0kffvn1DngCDDYtDj9YdHn+O+SfpibTmtO1eEXEMiLsbL9P5tAU4wZkd
         715i9tuuxJqX1URKP3frwoWI7pKPQ+UkTVykLZYkWL10ci1PfgrBVi0818mOb1+LO1s7
         rr5afzwPO0DbTStL4kQq2Nca8AHtTAWz/loBHcW36xpcBBAlM4KyNclOs1/x1LWNLTXM
         2bJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fhKHd24T;
       spf=pass (google.com: domain of 378vzyqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=378vzYQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v18si238051edy.0.2022.01.28.02.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 02:56:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 378vzyqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id z1-20020adfbbc1000000b001df54394cebso1281549wrg.20
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 02:56:47 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f088:5245:7f91:d730])
 (user=elver job=sendgmr) by 2002:a1c:a544:: with SMTP id o65mr15295285wme.160.1643367407413;
 Fri, 28 Jan 2022 02:56:47 -0800 (PST)
Date: Fri, 28 Jan 2022 11:56:31 +0100
Message-Id: <20220128105631.509772-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
Subject: [PATCH] Revert "ubsan, kcsan: Don't combine sanitizer with kcov on clang"
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, linux-mm@kvack.org, 
	Arnd Bergmann <arnd@arndb.de>, linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fhKHd24T;       spf=pass
 (google.com: domain of 378vzyqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=378vzYQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Since df05c0e9496c ("Documentation: Raise the minimum supported version
of LLVM to 11.0.0") the minimum Clang version is now 11.0, which fixed
the UBSAN/KCSAN vs. KCOV incompatibilities.

Link: https://bugs.llvm.org/show_bug.cgi?id=45831
Link: https://lkml.kernel.org/r/YaodyZzu0MTCJcvO@elver.google.com
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Nathan Chancellor <nathan@kernel.org>
---
 lib/Kconfig.kcsan | 11 -----------
 lib/Kconfig.ubsan | 12 ------------
 2 files changed, 23 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 63b70b8c5551..de022445fbba 100644
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
index 236c5cefc4cc..f3c57ed51838 100644
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
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220128105631.509772-1-elver%40google.com.
