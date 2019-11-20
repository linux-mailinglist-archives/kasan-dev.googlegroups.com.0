Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJND2LXAKGQEZ6GH4GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 86CA61030F2
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:06:46 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id h80sf14807918qke.15
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:06:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574212005; cv=pass;
        d=google.com; s=arc-20160816;
        b=egrrFKvoziFikYmglVpTe/Xkbl+twaElZyonvfDxcipPXoZ+KLU3gwpVxfPO2xqeEe
         gNggq22Aav90qBsuiNrRAy35qHogVQxCd8Swb167+j1FRTS02cNK2aGLN6kNrkQFoVNH
         D0RdNgKZ+wbzT2BgCpy/xoV+QSnlxuAz4M4HXIsdlwyMEOexTwtWSPEf+Tw+MFfTzoo6
         fX3AShue4xsLAMvlVJsYU+zGe/q6LzmuHbR7Nn7MX8OL8vv+ITZnBf9sXmh/NTVDdQEO
         rm7XpYmHC1Byxj3VcnqQ97o5GoK4X8xi0tUfEHpOe2xLzJTznhFzV4j9yFXxgFd0iyNl
         boXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=ytF1HG0pVX+E89GinE+yu/weyixJZCBVzPBqPIZEgmw=;
        b=Abq63/orcBmGGWoaVHBh2hLCd7hLCv9b6jhUVqHnbIZXytcc+w3j7REm/rzXoilLeT
         sSXJy6L2EUAnGYCUlfNleJxd4PUxYW6qeybPqby+00OWOSQ7Xzh9AzSMaNzjjDb28FtX
         uEyJgnuV9gGz496rxHuYh4L6jhGE0t4hiRFt5nt1+UgWz2bYOjFSojiRq39lYRA/oUNn
         UUtSknrAz7DiguanPxHFrezbGTBkNVHf0M9w9sRccIunkoLfoGUk1YwDf0ppK9MBgy2h
         07lSwF7/PuE7ee/Y7FUiFPxoGpKSs/IuCGBHItev2Ai/uG4i63NpisvVHJJfb9dylluh
         2yWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GjW65mTR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ytF1HG0pVX+E89GinE+yu/weyixJZCBVzPBqPIZEgmw=;
        b=nHHXM+DMwSqkuNfc7ZUY9JSDKUU2+hARQo6hh3+vy0wERwPKyhWFOdG4uf5lkFOvkS
         MqV4pmnyKWqc9Xa1xY1UK/cWc8lfymNWC4OUKn485AKbsk0Fq2P90WCKnSOhOXFa1OjF
         ug0SynlMtYNNMEe2i5rh6uCDROP71OLIgKTLsZJ8vq54Eos3bGs0VcG7Mh4MVHWDqdKQ
         UUWPgGi/7M4OloBjFg9EUyBnxWMnR9RDs3JBCI14KuyzPXe8xvuBSRU/QUoGv4hzwR2d
         qR2uD05cEqQzlguSIoEKYNOg0KQg/Rd9stKJk5zbSniDruiQIhSGSAA0F1SD31gQqTsU
         +U7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ytF1HG0pVX+E89GinE+yu/weyixJZCBVzPBqPIZEgmw=;
        b=PRK5nahlQQKcLameEqcH6LwymAIG5gyD4nan+3JavcOhkV1ffV/O7jVsGIp62HZqC+
         F5vXSugcsYD7OnZ1WIKpTo8NVO8FLMh2Rrb+VAbXuD0sL6s6XvR8JJAipImoSn+CeLtI
         mGkI+SoXeSh0JzVDPy+WH7gZTabK+hXr3NFtvHf7asAd9y5/70dgJVdiROOj9obEnNnx
         l/md18Qim+0TqDgdvMxYkti60E1XSxV0z90dX9lr6sfs9jYqukeXuAQ1QxmpNngkhXGm
         Yn48huRdTB4Mjc5cPI9VVx2SjHDbLRcl0t1/plJEYAmPOqUcOTaQpql7v5AWzpxRPZ6l
         G5pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWXZojHk2FHH+1ea2/z8agMa1qbjBBBEZarBSy8gtCr0Nl2BRJm
	msanJoXpV81w0hVUsIDjgD8=
X-Google-Smtp-Source: APXvYqzPUxjuhEeY9UF7azl2vefEQ3Ojb+UUrC0NK6mE3mDExgqrAFnFzNk462V3m1I7boHzfYtKnQ==
X-Received: by 2002:a37:6442:: with SMTP id y63mr156997qkb.264.1574212005568;
        Tue, 19 Nov 2019 17:06:45 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6289:: with SMTP id w131ls156375qkb.15.gmail; Tue, 19
 Nov 2019 17:06:45 -0800 (PST)
X-Received: by 2002:a37:ba44:: with SMTP id k65mr135255qkf.169.1574212005241;
        Tue, 19 Nov 2019 17:06:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574212005; cv=none;
        d=google.com; s=arc-20160816;
        b=BEo74axf+joI7+mNVYw6TXsKGsPDyC4LDo5ydEBaNLCyimINbiyWtSo55m+HYmtAOX
         rK23ljCO0MwJ7foh2Mldj1Z+7CszoAKd6GohYzh09OzVpAXzFKhean8jQreAbYlBHXaw
         7QLGK+ENXkJ+Uue3RmMHBLhYOKPdVsWBPHV3jCbZgxfqXoP+ezTMPsUQxLNGvssIIBLJ
         Wk8Dh2jtfSya4KMVDgdkJZpgTr74ScPxh3KF7Beas9Dbw2+On/HcfyiWwL5VhjyvGY/c
         PL4aaBrQTz6bRkxYSH6xGICYl0kp1XFwompFraknw+rArarcsISRlAU0TgpS8bWbQHE4
         X1Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=cO8TBOltsH4skyCZjRFi1jjLHEcJb6wGQF3Nty2AFlw=;
        b=q11eNczxNiYXaH+0Gjp3sCjyXUgCSkKVGGGaFQh60dYLewx0bzrYZBgTDr+o97s2Z6
         ip7V7h0UAUnNZoEy8+tNsMqfcWe4bu29rCasy1PEaVC6bxx1zXouE2A9DGIzQAP6MCxP
         rybbZaQCFaYr5Xi418kmqPDL8bcAEpD6dx/aNHzwo9IgXQBJFhuQtehuELgzyPxKrSU3
         gfczfi9rqX/qeSH8wUwxi/IJ1G0ZB23lCNiBw5hdMi76Br5+nh2z8k8J3atRkLav/UgZ
         QVIM0/Mr0DuqRweQxoNDwj00bs97u+JkvK+TEkoaD6z3tyYHVP6iMCCGxtl2HqGb39gU
         Ud0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GjW65mTR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id y41si1549408qtb.5.2019.11.19.17.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 17:06:45 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id p26so13304609pfq.8
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 17:06:45 -0800 (PST)
X-Received: by 2002:aa7:9f89:: with SMTP id z9mr651850pfr.123.1574212004404;
        Tue, 19 Nov 2019 17:06:44 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t15sm27916646pgb.0.2019.11.19.17.06.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 17:06:41 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH 1/3] ubsan: Add trap instrumentation option
Date: Tue, 19 Nov 2019 17:06:34 -0800
Message-Id: <20191120010636.27368-2-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191120010636.27368-1-keescook@chromium.org>
References: <20191120010636.27368-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=GjW65mTR;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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
minimal changes to image size and are prepared to deal with kernel
threads being killed, this introduces CONFIG_UBSAN_TRAP. The resulting
image sizes comparison:

   text    data     bss       dec       hex     filename
19533663   6183037  18554956  44271656  2a38828 vmlinux.stock
19991849   7618513  18874448  46484810  2c54d4a vmlinux.ubsan
19712181   6284181  18366540  44362902  2a4ec96 vmlinux.ubsan-trap

CONFIG_UBSAN=y:      image +4.8% (text +2.3%, data +18.9%)
CONFIG_UBSAN_TRAP=y: image +0.2% (text +0.9%, data +1.6%)

Suggested-by: Elena Petrova <lenaptr@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/Kconfig.ubsan      | 15 +++++++++++++--
 lib/Makefile           |  2 ++
 scripts/Makefile.ubsan |  9 +++++++--
 3 files changed, 22 insertions(+), 4 deletions(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 0e04fcb3ab3d..d69e8b21ebae 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -5,12 +5,23 @@ config ARCH_HAS_UBSAN_SANITIZE_ALL
 config UBSAN
 	bool "Undefined behaviour sanity checker"
 	help
-	  This option enables undefined behaviour sanity checker
+	  This option enables undefined behaviour sanity checker.
 	  Compile-time instrumentation is used to detect various undefined
-	  behaviours in runtime. Various types of checks may be enabled
+	  behaviours at runtime. Various types of checks may be enabled
 	  via boot parameter ubsan_handle
 	  (see: Documentation/dev-tools/ubsan.rst).
 
+config UBSAN_TRAP
+	bool "On Sanitizer warnings, stop the offending kernel thread"
+	depends on UBSAN
+	depends on $(cc-option, -fsanitize-undefined-trap-on-error)
+	help
+	  Building kernels with Sanitizer features enabled tends to grow
+	  the kernel size by over 5%, due to adding all the debugging
+	  text on failure paths. To avoid this, Sanitizer instrumentation
+	  can just issue a trap. This reduces the kernel size overhead but
+	  turns all warnings into full thread-killing exceptions.
+
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
 	depends on UBSAN
diff --git a/lib/Makefile b/lib/Makefile
index c5892807e06f..bc498bf0f52d 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -272,7 +272,9 @@ quiet_cmd_build_OID_registry = GEN     $@
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
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120010636.27368-2-keescook%40chromium.org.
