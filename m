Return-Path: <kasan-dev+bncBCF5XGNWYQBRB7FT4DZAKGQE7Q6WTJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 62FD41728AB
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:25 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id c66sf342583qkb.13
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832124; cv=pass;
        d=google.com; s=arc-20160816;
        b=M9paE5PMRFXHOdk1JgwLeKWnr7vn5MzZsOX+gXjqM2PNmHSroUWdMuGoMaI21FbESK
         a6sY1cvXfvFiN51l1lndOVux8c+lHyNsljLm3ykEh2JJdB/ViE1v35um2MkcWptJFFSO
         dwoog6MNnyuEYUhd24zYq/v/lBZbXG0LysFIUeJEqDrk3aKnYEAKUH/Vm5lJDQZuZv+c
         gFbF6j1ktlScGzu/wQ2QvzAMF3Bh/1zHM78aXFua9DwHgIzFDY195wssSOKMumNn/L9m
         UY+XOTV/hdWtvyWmkIbzAXSALnlzxG5ePXqNfcVZFygAhAIhh9xClsIcI+HwlZQyakg1
         aQMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AzMg1bP+UoORjX2jkhKX6w/l0R4tUvz97CHMEPOX7Wo=;
        b=vA5lGiEnCw4efwB88kkEB8fVkkhGehRcEMSaIXQSoF5H21wa3jxCGfj4onjDk5et0L
         lqpk/C8IXqmlqvWIGLJ5sqbgYtGpJxZjOVEdym58c4IiRSWQBSqswcn9tUQq4baJWgXm
         +IMsLzDTPYbHWpRm99RT23lez+afih7xTblnv+/sEMWRM3vROm/jG6UoXl8xQypMciLC
         kM0jBHfHnPms/kbOperLzizggZqVb/BTXYCi66nK2HygB1fHOA2Nv8miW8rcspKkY067
         ICqhOUtaIsGo0xAQwHYaJUbmrjllzZvrSEgrNv+jFcjxMtrk5G/O8QV50QpRYGjI2rD8
         Npeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eKbq1uyx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AzMg1bP+UoORjX2jkhKX6w/l0R4tUvz97CHMEPOX7Wo=;
        b=B42TLCtHOo1ecilSWMCtvY0hWsyZwADU5Cp357fQxjh4OTDcOW8QXQ1tnndMbmjOhJ
         gIf8nhO1yRYj5PtWMem0sbtQq7ZDY1hTyIwg/jn7r16oZr3PfDpGCm+5QeD7qsP8FOKG
         ne2G7k+8uu59XwmUVDOsJPT+8+xniEguX8mKgjDSFnrtZI4QU6iAbgcHgwRZ5opJgqtE
         vJG7hESituSAttdbdtbs3mJzjrXLpEKEbIZjzDC/R592hi+9UuQkxQAdOsH2YeaMGDk9
         g0q4PQsJ3WIK/bOmDYQ5BPjLpIGSfzxtkeDOhcP+5ZSEJpWiDmZhZ493Oc/2dvfvJhU6
         X0KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AzMg1bP+UoORjX2jkhKX6w/l0R4tUvz97CHMEPOX7Wo=;
        b=GeP3X1ULEfPs1G4PZmatTmEpGodXL0I5yE3NE8FcDrVjBI/tXShNXN2r9qedk0uZh4
         kUs/pdzQHNk7dbWqCF3oIusfezl7RDHax4Nhz5Rf/dvwIm+Vf1m5WTMoZH9HKw17whI6
         aOXcqOKNEyn+hKhqW6iqiJ3hQRoNjtvQye26dDm89qNE0HFpZBCDPRNSQc//F6ijfPrg
         k84Glq9xQsuV/NBCqdt0VguPhLJqjSTO4iOfoqGqLp4XStaHBNmQ4naWKd2hxZFYBuZs
         VISH7QB3MGPbzqXTiyC+fg6I4b6lnDEcUqHzcnJCRX9oAPp5VuRZalkwfCEj2ZS6ffwx
         2VUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWui/TW6p8xft2R913Amw/CaCPT1a+TS2MgeyPe37yxkXXkePTG
	tfuInILvaAEe45dVW+FM7us=
X-Google-Smtp-Source: APXvYqwjFX8LvHgeMkOm25dKocMhmLGRewL+zltzTm6H3xALaEMKnrEVWBI9Nfoc+Ecl2WyT1uPidg==
X-Received: by 2002:ac8:1a30:: with SMTP id v45mr875862qtj.80.1582832124463;
        Thu, 27 Feb 2020 11:35:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6701:: with SMTP id e1ls250195qtp.8.gmail; Thu, 27 Feb
 2020 11:35:24 -0800 (PST)
X-Received: by 2002:ac8:2a55:: with SMTP id l21mr884307qtl.111.1582832123951;
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832123; cv=none;
        d=google.com; s=arc-20160816;
        b=UAvznIq++TGPdUa7GC48iEt1wq6Q7WeV7CU/loxjAdpQWvcKN3Bc8llrlYGly06naV
         0DunWwBotUuElQvyEGQMBtv/PSPFOxXBF3GSJcQespiXUoh+YQJtg4r5E1elQK/eZglc
         tVJw103r7cWoEWoGPfjV9owy7GURBdoYDj0TMbil6Ne/VTzJingccBKKqVa8DVxy3tr3
         rmLPrsZDm5PCRnA7DdPrGp026ppeqEg5xRkxU+zZFEgJDRUMCKe9BNMqESmDZSdUSDGd
         GNduSliCr8i5ZtZInZL7FyhHHPCzFOw18fqoZwQIyASMoUa2g/y5rExYz/Tgs3uITf/U
         9ElQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ouVhJC1LzbMtIjBpkBkXzJDLKbzWPj7ADPmF+3aq9S8=;
        b=uEs4uYJYUZe+23Ih4uxph4bjYoA1ZgdKucQ4QHRq2PSwqYhriKBW0KJB+2yQF/kqjj
         KOXnLNWBKvgExb0ktmsO0JGICfPCZ8Gbzb/SXOt06h138Fg6k4pvNeuZUFJmUJjlf+T4
         BFnbsV2orGd40Np6mFIFCnBVGshzWhjWJ2NMRzr7g6ynsKFE07etemBLmwvpvNpBlWjx
         qM71ykehUXOhMbGuiG8A51Aor6vGThjM65d2j2evB2XVeYR18JIR5DLHPJnHVpvIOOtB
         upfwimDj0KKNb+RsWdq0cGxhDU9+iDc+TLcJLdae70Ahaoj2/OuNb0TmzLqMcbmKPVDs
         6QsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eKbq1uyx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id f52si34954qtk.2.2020.02.27.11.35.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id p11so195337plq.10
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:23 -0800 (PST)
X-Received: by 2002:a17:902:ba8a:: with SMTP id k10mr312829pls.333.1582832123523;
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id v22sm4018043pfe.49.2020.02.27.11.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:20 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v5 1/6] ubsan: Add trap instrumentation option
Date: Thu, 27 Feb 2020 11:35:11 -0800
Message-Id: <20200227193516.32566-2-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eKbq1uyx;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Content-Type: text/plain; charset="UTF-8"
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

The Undefined Behavior Sanitizer can operate in two modes: warning
reporting mode via lib/ubsan.c handler calls, or trap mode, which uses
__builtin_trap() as the handler. Using lib/ubsan.c means the kernel
image is about 5% larger (due to all the debugging text and reporting
structures to capture details about the warning conditions). Using the
trap mode, the image size changes are much smaller, though at the loss
of the "warning only" mode.

In order to give greater flexibility to system builders that want
minimal changes to image size and are prepared to deal with kernel code
being aborted and potentially destabilizing the system, this introduces
CONFIG_UBSAN_TRAP. The resulting image sizes comparison:

   text    data     bss       dec       hex     filename
19533663   6183037  18554956  44271656  2a38828 vmlinux.stock
19991849   7618513  18874448  46484810  2c54d4a vmlinux.ubsan
19712181   6284181  18366540  44362902  2a4ec96 vmlinux.ubsan-trap

CONFIG_UBSAN=y:      image +4.8% (text +2.3%, data +18.9%)
CONFIG_UBSAN_TRAP=y: image +0.2% (text +0.9%, data +1.6%)

Additionally adjusts the CONFIG_UBSAN Kconfig help for clarity and
removes the mention of non-existing boot param "ubsan_handle".

Suggested-by: Elena Petrova <lenaptr@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 lib/Kconfig.ubsan      | 22 ++++++++++++++++++----
 lib/Makefile           |  2 ++
 scripts/Makefile.ubsan |  9 +++++++--
 3 files changed, 27 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 0e04fcb3ab3d..9deb655838b0 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -5,11 +5,25 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
 config UBSAN
 	bool "Undefined behaviour sanity checker"
 	help
-	  This option enables undefined behaviour sanity checker
+	  This option enables the Undefined Behaviour sanity checker.
 	  Compile-time instrumentation is used to detect various undefined
-	  behaviours in runtime. Various types of checks may be enabled
-	  via boot parameter ubsan_handle
-	  (see: Documentation/dev-tools/ubsan.rst).
+	  behaviours at runtime. For more details, see:
+	  Documentation/dev-tools/ubsan.rst
+
+config UBSAN_TRAP
+	bool "On Sanitizer warnings, abort the running kernel code"
+	depends on UBSAN
+	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
+	help
+	  Building kernels with Sanitizer features enabled tends to grow
+	  the kernel size by around 5%, due to adding all the debugging
+	  text on failure paths. To avoid this, Sanitizer instrumentation
+	  can just issue a trap. This reduces the kernel size overhead but
+	  turns all warnings (including potentially harmless conditions)
+	  into full exceptions that abort the running kernel code
+	  (regardless of context, locks held, etc), which may destabilize
+	  the system. For some system builders this is an acceptable
+	  trade-off.
 
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
diff --git a/lib/Makefile b/lib/Makefile
index 611872c06926..55cc8d73cd43 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -279,7 +279,9 @@ quiet_cmd_build_OID_registry = GEN     $@
 clean-files	+= oid_registry_data.c
 
 obj-$(CONFIG_UCS2_STRING) += ucs2_string.o
+ifneq ($(CONFIG_UBSAN_TRAP),y)
 obj-$(CONFIG_UBSAN) += ubsan.o
+endif
 
 UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 019771b845c5..668a91510bfe 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,5 +1,10 @@
 # SPDX-License-Identifier: GPL-2.0
 ifdef CONFIG_UBSAN
+
+ifdef CONFIG_UBSAN_ALIGNMENT
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
+endif
+
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=shift)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=integer-divide-by-zero)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=unreachable)
@@ -9,8 +14,8 @@ ifdef CONFIG_UBSAN
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=bool)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=enum)
 
-ifdef CONFIG_UBSAN_ALIGNMENT
-      CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
+ifdef CONFIG_UBSAN_TRAP
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize-undefined-trap-on-error)
 endif
 
       # -fsanitize=* options makes GCC less smart than usual and
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-2-keescook%40chromium.org.
