Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQ5I3PXAKGQEXE7RIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0CC105941
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 19:15:32 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id i7sf1066561uak.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 10:15:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574360132; cv=pass;
        d=google.com; s=arc-20160816;
        b=c7nt2uJeaf80I0DKSq42eswB26EyXoYg0MQflP00g/ILPbweqa19A4NWaVx8fr2eXA
         Ca85byvYsYcrCYJhRILcbOVXqJC+L5FBM2mgnf/gMGB1LqSXxGhqWyNsIpgiNVf2BcET
         O6DKAHxNbW/jLkN4uFV5mgosvug7eBnHGG79SdEGQe6ozFM5a85IgT1XKLXJb6zEG1KZ
         PpbgceF86QF3Fqz5XbnRket4Ipx5gAi6hh0LHrGH1YEpYyksVEEwcRkZWFAU9rP8cgRw
         nq0WIBTLqEoSb3OklqdaSFh0YJ2UuwsLE6EPnzndPIiTMLWZnk/Ygbk6cz89qwJudCKq
         zZ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=4aVwFVLWl1EUJaMoUZz+2SpoSFFub54ianHhUB9r46Y=;
        b=BhglSwLDihO6aDrsSJC1vLz2XqHwcP7zHEQCQmxFg/BxGlT2lzMB68qpOS0xkwfyy2
         0BEtHn/Xz7zGz9Q7zARyh/uoM/ARPqgxXfqCFaWTHa6GiudtP8pkuZChmT+v9HCd1ZML
         Mfb8BxrPppe55AaGVIaqWSH8IytwhuqYEFvQjumSqdRPNT1vRAiBXDjz8EbQT31eYV8G
         CPg7zNFwOt8uU83x95aJMHwCXch0EIOiTeRNqsdZ12tfLiuUfFQuQGCjTdv2vHtmaqDw
         2Q+IN9hjEyIcajdfbGZ+/k9iFupRcXn+IRmPgADQGtR4A+YAgWDwjCT87Zx6OUmjbu96
         4HZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nANVur5k;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4aVwFVLWl1EUJaMoUZz+2SpoSFFub54ianHhUB9r46Y=;
        b=Q2Kng9IXP9Ajk/AhLz4I09Egx4KbTWCZ3CQIwzEDZl1ny6oc+ItTvFwFf90G3dS38H
         DPdJEizVcB5xwnolysgDxFDwOM8sitDtNkqI+wKrnNUdbdlirHynsB+4jvX9DU1Q2nfR
         i7sDKmjzCrbhmjGu4qEL93ZsAocAItbUMVkR0M6T9FEi2vkXWXHQDDfwR2RaUT/yi5Zi
         83mr5rmr7ZpaHBlf/3Kv/Bt4LGTss+w2x6pjJho0+wIx9rW5F5NS9wPrhOoz70+dXPUL
         lQSqmaMT/5eGSxn6li7/y47s84m3V+/gKB0NP8+yw89KX+k6PZwRpb+0Z3txZCvoGH3H
         7nzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4aVwFVLWl1EUJaMoUZz+2SpoSFFub54ianHhUB9r46Y=;
        b=KBhAcLyoLwT1TasES3+/aXHnu7EnU7yiVqI/hzQLJUusGfELqtGaYFQhKy6NR3s3Kl
         5D0W/TdMwWsCxWmhD7J1PpTyr+HfY/azPozW7CM7ka1ChNDxbk2RW1uWAp6qt+w9WouT
         2E0Sxd801b6g2eavPjpDKVXcBJeHtxqwt94uAm0weEyibdOvfrL3Ka7D64/99i8RpLL6
         THV8yBFWV0ulKDyp66dUzNVlZRlF6NOlHtfQnZY2Gxca/Lf4LiD7asJ1z820p8rZnyen
         /jjyzD6voAVf4aYaZo/cEIuJCNTy3nuY348q+4I3VfHZzNcgSEVs9u8/ASAsx7LQlLW3
         mdcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFe/KgzOzeIu/0kV/sYr1l4vp01Q59P6RO2DxXTQN5CuVjhmq1
	AxLk1+ybpNgxfv3B6VRaZAo=
X-Google-Smtp-Source: APXvYqyX/Duu6CLNs+BKz0zjYwVGx6DEOGcL1ZeSpnXVPBNPPH7yNmZHM+ClYiGp3DOqAyxIHanAjQ==
X-Received: by 2002:a05:6102:119:: with SMTP id z25mr6901943vsq.135.1574360131783;
        Thu, 21 Nov 2019 10:15:31 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c116:: with SMTP id d22ls873186vsj.14.gmail; Thu, 21 Nov
 2019 10:15:31 -0800 (PST)
X-Received: by 2002:a67:d692:: with SMTP id o18mr7094831vsj.151.1574360130920;
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574360130; cv=none;
        d=google.com; s=arc-20160816;
        b=JvdAcUrBXhgXMPcqDUzZlPvT3qcL8XZGHekVXUS2PoGJUEMc/0OHQpfhlqf00GSp+l
         bn6vvzcnRF1aWMCxtUHZitbvAWgZtcq/A6/rVaq4uIWcf/h4IBSQXQfD6nnDRRZDo1e/
         f6Wq9OZmQLiEm2W6zZ4J8S3hyzcuOmiHo+QwB2f9k3Dx4xb4FJ+fXzh5peFsvpVL1daj
         ld9JgBWyplCwoKci0UxOXzHpaS8/8Fgx2/8lRmYGEz5BjzNNPXQWMKpSBootkhIv9tM7
         E42NDL7rKwH8vwid5CbAYa8VTw2NRBu0L0iA/VxZso165Dk0eIMRCe/MflsqA4t8AC0C
         PSxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=ccHak5xmnouFPda/AWVo/lGwU/xGWHbS5K0BgsHuUQE=;
        b=yTaI03tzC+dxwcnmiXvZO1BakJ0w7FLceQb1w4AHRMStVhRGOq0WQJ3SZSfH0gM11W
         tziCSd7F0CU2kpdVCQbNEEGIWHt+D+bxK0Ge0MSTquFBPu7Xqr0QUhvH+GLYT/Knb1oU
         VsOJeMWazB9hQFw8w1kqmZGri97k++2fgaClwqOXKOzrAUPuqEIBG79M5uYCCmWO95DS
         KckdItIh2qeW4Kr077uef8ZYjhxT3CoWWXEdUUly209X+dL7tPuKeb8kxYMl4fIyUvSL
         rXToQTeQxMsyOOu7FFBrnKoZ9SfU5t1dy+eHKxM9M3EJTpU2I6PTSyacsTLryuvM9XVU
         Uglg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nANVur5k;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id p195si223865vkp.1.2019.11.21.10.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id s5so2101314pfh.9
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 10:15:30 -0800 (PST)
X-Received: by 2002:a63:535c:: with SMTP id t28mr11108812pgl.173.1574360129873;
        Thu, 21 Nov 2019 10:15:29 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h66sm4373925pfg.23.2019.11.21.10.15.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 10:15:28 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH v2 1/3] ubsan: Add trap instrumentation option
Date: Thu, 21 Nov 2019 10:15:17 -0800
Message-Id: <20191121181519.28637-2-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191121181519.28637-1-keescook@chromium.org>
References: <20191121181519.28637-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=nANVur5k;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191121181519.28637-2-keescook%40chromium.org.
