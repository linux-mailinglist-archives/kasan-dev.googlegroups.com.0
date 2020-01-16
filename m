Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRXW73YAKGQEKUF3XMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id B490013D170
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:23 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id o142sf6832982ybg.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137862; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ih2fR+Avp/hlytqFsNbTEG/sgmoCjJwVZhHm5JFKnHg8Y5PHuGa/G/Rhp9twQL6fvK
         k3s5t+tWJHMS68aE+TRA4M4AgZfLJDog8m4xp7uU+QhEf8gq60Xyj+1EVm8r7ZtfKtcP
         5v/1ZNCXjg5LNR+DuqJe1kblTuL1sxKg0ToZhtNkMLr9pkUgrqXgjQvggFS2VsgjfguK
         9Fwdp6oHjqyIQ2+cmBNaBt4qJ9ccRoHpkzDF6hoK7JMmZRkF+tt3NhUGdOZ3o8r3erGf
         Hm4ty1Mq19pC7fUe22/SJZ+RPQPg8JIi2wXJ8nX+O7UjjzpHXBEOtcvxZyunYd22qih1
         3oWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nTDNEO/V4tVEs0bvMndutlHk1UEhs6Izl/jJ3INnq4U=;
        b=KsBwegH1TuvTa/TXt1RI8tZcb7qrk0C7MeQ+Fha1mGWbwT/VHYzkuvRUYQtw82l7pp
         nHHwUh1Qe5oricbJ57CAUxr3bnjOzhDVDty8nS6flSsLttILLrRP5UzwWl1sifLWIOcR
         JDp0kgqVybUah5PDiGj5M3dOkXM7FstJeSqa/ZBpXfCErbQgzSE323/Tz8agt0qrnIaZ
         qSnVxI/uhrcBv5lwSDM2igBRJN2E3rwqkRNRbvk3NHSUmJuMsSFAWuzAgnhgx4pYr4TZ
         6zzir4RcnLX2a2dMQCUifu6O+Ea67MEfsgC6Sbpf3Fi7LDELb9sWGxeTTsiHcmBdf6sG
         rmfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Oy7tVeYN;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nTDNEO/V4tVEs0bvMndutlHk1UEhs6Izl/jJ3INnq4U=;
        b=ffdOCGiasaBJIUEPJUZfnzV1Ma9LNOIw78Blo0DuL2cBaVz1qkxfTTM/XMxgLQBx7j
         firXbULADGFCz1mTd/njY9T6ODQ60yEIinxevQrGM88NcXIvcdxqR0v0YHUz8CGCsgSW
         uqNTZjJ4i6X13aDvDj6A7aN4por7i0GMqd2ezPdGDrN304m5rfmseihnE3lKWMhIZEOM
         ngefuLkHSGKEPqs24tnyexhHbO6SGBxz91Eykc/gZqClhPvhylSpGimKMDi5yFQzchvN
         6kHZUsj/qmcyn+1wBx/KXOR3PUnX1klfstzkylVJvjU+++NxXWgkfmtu4TQ8GsdgZHhY
         703w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nTDNEO/V4tVEs0bvMndutlHk1UEhs6Izl/jJ3INnq4U=;
        b=tc27i6UXCUXupQDTIqX6ccPCZpJT19Vkni72pqZ08uaTzReQ4khuFa1TgVfCvOW9xO
         OUlMO/ByRDd0vtaPjP457BfzqtbGAYKl0lVf7Cit20DlIdVzUCkaKi02CxxfmKIlpiq3
         HuH+O2bvXbbEaK1yAiOg/hDgLbAN6G2oxX1/tC2TiSoL+ApDBOmpYKV8vMONCh/5e6Gb
         ySuHuv+YvKCR0i2dlCNqDHnfvlW7RvB3h3EULIB14jhDI2lRIPGrNVNX5elQyWrXy9fu
         REUmcL1YuC+zpsVYTJjsfZpEc7n5Z3qaOZVoe2alOYITHU9MAKzhu6wD52s1mgxTYntu
         XDGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWQt0CUyMKCuUG87GekE/7MB1ZbzxPKACD2OHSk4DAk2+C7ciH
	o6FZfn1iB2hIRvqey6+KdO8=
X-Google-Smtp-Source: APXvYqxool9ixSZdasrYHc+knGnTDi9e3DkyQ1I8maKuSUrG9l1RxMrnusOv4LjmUSdjRYzAG8auwg==
X-Received: by 2002:a81:8986:: with SMTP id z128mr20221250ywf.320.1579137862710;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:66c6:: with SMTP id a189ls3318876ywc.8.gmail; Wed, 15
 Jan 2020 17:24:22 -0800 (PST)
X-Received: by 2002:a81:83c8:: with SMTP id t191mr25221677ywf.19.1579137862391;
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137862; cv=none;
        d=google.com; s=arc-20160816;
        b=X57wiy4JUc0PEVAC6U/MkMLfp0SuOFWSmc8ELxzEQBvYF/dkK5YqMbsFiphct6Wrbm
         SDmnAoVN8GF9M/VllzJzvHC3fyFaD2jtDe0HGhwnYz41SWLeFxOAusB6QTjU4GW8Gytx
         JlWiapKtRUgm7vlHujvY5rwjl0ElCLwOwGLZSbIliuK2EZ4MgE6suWaKfEpFynrtlsl+
         yqlSbksHRopFVH9EsD+lEvxkrzhiUF7fbwkT7v4zjy764tETALYb9md1D0R+OSY7Yl6H
         VX06i+7WuQaRTDJmzYklP8njBIWurlQ7GgtPGK3kALF6QCJEKTnEMmlqEXT3Kz5F3G8c
         xRjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vuuIloFbVRb0p706sR0GRT1NGf5G9e2wBRiCGVrk15E=;
        b=g0XE9O0JK4NohZDWiQlFfsIanx+vQVTOAmkdgtp7KBKF+ext75p/SlPj8JPz0mMcVH
         fJXZed9MfaXUXGd2FwINS8JBaMkB4Vq8mNICrs64QG+BfM2w2kHfaBlcE8JCZUNfXyrV
         pk+sCbrO94iaqp7hp+Ytq+mMx3GMrR07DzDDl67U36QZavYO5hoOfF7veg87Mv8xLvAU
         e/fKfIop30+0b1V/blNz21VFL7StDxPVh4UUWTbCnXSSOXtZYU1BKgzWC6oqMy13tGbW
         TdqxP/q1Q/nVwUWLBCctjAFhetRMKF/yvhill9DQafuI5X2kz4qRa1EQSP5UZ1E8TAs6
         pmwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Oy7tVeYN;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id n67si1129933ywd.3.2020.01.15.17.24.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:22 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id u63so2497024pjb.0
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:22 -0800 (PST)
X-Received: by 2002:a17:90b:258:: with SMTP id fz24mr3458273pjb.6.1579137861582;
        Wed, 15 Jan 2020 17:24:21 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 189sm23827180pfw.73.2020.01.15.17.24.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:18 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
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
Subject: [PATCH v3 1/6] ubsan: Add trap instrumentation option
Date: Wed, 15 Jan 2020 17:23:16 -0800
Message-Id: <20200116012321.26254-2-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Oy7tVeYN;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042
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
index 93217d44237f..3114ef1727f8 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -275,7 +275,9 @@ quiet_cmd_build_OID_registry = GEN     $@
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-2-keescook%40chromium.org.
