Return-Path: <kasan-dev+bncBDCPL7WX3MKBBY4M43BQMGQENGGVKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC427B0974A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-313fab41f4bsf1946721a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794724; cv=pass;
        d=google.com; s=arc-20240605;
        b=bHptiyICrTl41/2FgtwG339NiGcWB2cNGgbcHLBb1c5Cjvl3gSzJk/rqt8rWrrWbmy
         U+FDoRWIk7w/ZIF+IQUGWXTTYExREnStgZZh7saEWhBZ/XK+7R4WW6Y8mMsr3wn3ZmXR
         xu3DNBdDfTdPJ0ICg2wlgZZeTFu7CynvLG+1bwleLkKtSwjOGXUfTxTtl01IeGNnhWP2
         o2pdZUyVO58nn9pRHXxg1oDlBN7Y8oCgm0Cn3yOA9Es0K8sf+9vNmKoBKyM+VhWcGWw+
         okRx9Rw/KFkR5IrgASUN8NmKE1+N0S3TlN5um5X1E+Ty95osaJc0SspQeAeqIUJdtK9w
         d8ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=msBH8IqOGj8YeY4ehXd3gPfa+QHbKahd4aqwp0qU6d8=;
        fh=W/82Q/A1PyolB52ZYE2vN0NP+DNuX8T2rnFWklSjO2o=;
        b=TmljYwjoHCaWRbWoyEwHV7fel9Chj+lDuij8zkPioR6UKMoyateXNF4a3DWweAL9qD
         47lsUIh9Ye65yO5rA8hv7XF3bKe5tJqRIwAMLMRMdYqUDsU8CWJIbMLdKHXZ2avPANoF
         nCEH9ZHyi/OUEhigNj4s17OhL9Z6HjfyLRxt7M4qtx9NZFLNT38LsG5cPVrfXniPNn0a
         x+43+USMZkt812iMgIrIXdwCTNmyNkr4bvrLgihIzAQsw9voQcrRxSBjUYL5VLTyUMQg
         7pXmKtUFJMHzkQZAa4grYHLjHVinGwNk9BJdhJx16obqxu5EfVGU+SYxgThTRbYhJeln
         ooHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AUGKErrg;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794724; x=1753399524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=msBH8IqOGj8YeY4ehXd3gPfa+QHbKahd4aqwp0qU6d8=;
        b=D76PwTVMSO2sJVSRHGNyT0utk5+FREtp+JRAuX2+r0mG4Bzzktvj1N5ftGDMFTyNb7
         HH1JQ03OPm+3V+44v/wjpMy9rhgtUjjqWmV3jzLotv/8lseNAyph6SQMfVeAps22K5g6
         n+Et5YPhfaaelHSRm7NQRD6p3Q1H+0NPNH6KlL06oDElSa/qSRt3fZuQwUrCa5neiyd8
         d/+wcCOTrEdlX2JYUMmJ+QVkTTBrI1Ni7Diit+tk8QP5d+zgS5nO2UAeQmrVXzuu2mOo
         OKiGh1xlloyPrTqZuDQIhyKXlpap3dS+METDf0DPsoE/yIx+fmx9VcA1FNqesMcKTleq
         AUgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794724; x=1753399524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=msBH8IqOGj8YeY4ehXd3gPfa+QHbKahd4aqwp0qU6d8=;
        b=uW8jTLLaVlQhr0e91u0IvSC3BQDg/iYbjVurA/qy0y6nlQa6e6IZfD0cXo4jB0m3jf
         zTFFaeefpZ+Sab6NIFSOjo8bAvxIySVoZd8euWwjffS1cP+0glUrpvcTSlq8GV/sBZai
         YepH8Njxv92mpHKr3E87jLBWLQ8jLX6wLJiKnkKl3QXRZQpXKo7HD3iBiu4jgb+vqSzY
         0AflhdVKCyI7CkhNtiX6ciGyY/ZKCg+AsrvAoANRN185i/5Qh5X5uFA4Kkrg1OCOqaP/
         fcLsUFZ5jCI5PFrDX+IdDfBxuvVfEsjlApIv7ZPRhBNvwVcG4zdpoACJkCyfMKL/BMKL
         AkKA==
X-Forwarded-Encrypted: i=2; AJvYcCUnt89JuGkWokApGbsrvQr8lERGVtTQvfWGWbUXTawut+Gjhn+VvajhqTdEpxuOkqoa9Avf7g==@lfdr.de
X-Gm-Message-State: AOJu0Yy0V1iCUGPfNpR2ZbI5lMMdWzTyRAT/adgG1Ig3zs4aEsk4+/gv
	/2AlY6oPJk2E1HhFHCt574L8hDR2BfBZz363G0WhVUTQJSKLQAV56UjW
X-Google-Smtp-Source: AGHT+IH0jxSV8/tAUGJCAohHoo0FDtG+zRZ/o/9LAjIyorC8sXI4or8quXDrsPAZZcf9HuDHpZC2yw==
X-Received: by 2002:a17:90b:1c0f:b0:315:7ddc:4c2a with SMTP id 98e67ed59e1d1-31caf844d9dmr6544043a91.12.1752794723717;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcplGh2FTVn5XZKAVYWRJBgBA3iYTGPkfo62DZce8lKw==
Received: by 2002:a17:90b:3902:b0:311:9c81:48ad with SMTP id
 98e67ed59e1d1-31cae5e7abcls1688993a91.0.-pod-prod-03-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVARWjhz5dJAWQnY3jnscR5K+3hYdxerwcTbXT9oy6E4HXvU0mamMmbNLGH3A1O0xtt/rldJeG72PU=@googlegroups.com
X-Received: by 2002:a17:90b:4d0a:b0:312:959:dc3f with SMTP id 98e67ed59e1d1-31caf8213f1mr5574609a91.3.1752794722423;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794722; cv=none;
        d=google.com; s=arc-20240605;
        b=b+MaEqlaTEVW7Qi1gPfLqAVe9TRKvIb++LqNrAJzMcoIveV+rq1CAbI536rzCxqMy1
         kIL3oGVLWMzictLB9wc6T93XkLg48fJiDj2menJC0OjLDKZC6EYPuw286JH1ePn6hqN/
         23OrPiyLccAzJkqbA54lVM21fivf53ekWRkgjvUF8jKNZCvLui2tcJclM/q5dnrzrtWr
         YOvjfKq0QbM3QY4BKuMoQEx6a/r+9ewdkt7CE9uvwkAdfiTyHVOhtzcKmBuQjuE2T1Y5
         tI4XTyNzrC4CitA6fUPqfxUXZr+S8EABNcB8B0c1CKbFslh0kj88a0pGZ2Wl3INerS74
         APUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4j17pn+//SHkaX8ONm+HlhNEvqzcDQ+QNAUfr7A3lEQ=;
        fh=8x6JZkwKUJEOcntYJTSm/UAPOUD388UwI2Fu7UJ9f0c=;
        b=PQuRe65lzLLAvPabjSNDKHwjhmJfQ5xvil69vk/K07h402mV2RmG98y49/I8IqHWEG
         lnNAk34MTvvLvyrGyzNteiXZHExCJ/MujWV91eK822LDQFLLolIzeTri9ddOxlRAZply
         3tgP40jmaPfJeSQgGj2YNjoPceGB+kkdnXZUaYY25RR9F0sgZW/0ZZ38D0OD8/5BiA7f
         xrLTzF4MqIGjpJ8Z5uL3tAuTtb/Afr085eOk2QzeMwtDCJDnd4MNoAmqRJabn/r8rMVO
         RJsCkucQJBzKPUiWIZqTmbul3tPBzYe+CDLa/ryvUEplcbAN6NNCWLEiVMwXbLrIS4EA
         Sq/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AUGKErrg;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c9f2575f1si196141a91.2.2025.07.17.16.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 63DCE45D74;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4C60C2BCB2;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Ingo Molnar <mingo@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 11/13] kstack_erase: Support Clang stack depth tracking
Date: Thu, 17 Jul 2025 16:25:16 -0700
Message-Id: <20250717232519.2984886-11-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2299; i=kees@kernel.org; h=from:subject; bh=p+7YUBTmffdnZ8pKAPuZ2rzC3Zvp9P0MFRgY7Xz1ydU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbbG7zxw1MKkM064+GM3V+Tde9mealUNMf2f76+qDy 8tCpi7qKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmMipUEaG5+yu528923yg/cGf LXo63TrVrF9WH93oLN82IVl472aLiYwMX8V2fuAxEd03U60q9AgTd2GJSKHMR3slK0ZZ/dXf71Y xAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AUGKErrg;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

Wire up CONFIG_KSTACK_ERASE to Clang 21's new stack depth tracking
callback[1] option.

Link: https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth [1]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
---
 security/Kconfig.hardening    | 5 ++++-
 scripts/Makefile.kstack_erase | 6 ++++++
 2 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index f7aa2024ab25..b9a5bc3430aa 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -82,10 +82,13 @@ choice
 
 endchoice
 
+config CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
+	def_bool $(cc-option,-fsanitize-coverage-stack-depth-callback-min=1)
+
 config KSTACK_ERASE
 	bool "Poison kernel stack before returning from syscalls"
 	depends on HAVE_ARCH_KSTACK_ERASE
-	depends on GCC_PLUGINS
+	depends on GCC_PLUGINS || CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
diff --git a/scripts/Makefile.kstack_erase b/scripts/Makefile.kstack_erase
index 5223d3a35817..c7bc2379e113 100644
--- a/scripts/Makefile.kstack_erase
+++ b/scripts/Makefile.kstack_erase
@@ -8,6 +8,12 @@ kstack-erase-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE) += -fplugin-arg-stack
 DISABLE_KSTACK_ERASE := -fplugin-arg-stackleak_plugin-disable
 endif
 
+ifdef CONFIG_CC_IS_CLANG
+kstack-erase-cflags-y += -fsanitize-coverage=stack-depth
+kstack-erase-cflags-y += -fsanitize-coverage-stack-depth-callback-min=$(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE)
+DISABLE_KSTACK_ERASE  := -fno-sanitize-coverage=stack-depth
+endif
+
 KSTACK_ERASE_CFLAGS   := $(kstack-erase-cflags-y)
 
 export STACKLEAK_CFLAGS DISABLE_KSTACK_ERASE
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-11-kees%40kernel.org.
