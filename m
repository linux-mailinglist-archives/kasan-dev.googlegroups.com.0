Return-Path: <kasan-dev+bncBDCPL7WX3MKBBGPYX7AQMGQEGZTGBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CAD0AAC1B17
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:54 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2d4e42a2b2bsf5772787fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975193; cv=pass;
        d=google.com; s=arc-20240605;
        b=OJrcGGxDGm4u6c7/y+pULdEfJJoUng0fzNbS4ZjV4NrXqxuNEBw81XKlyTqyeXt7i4
         1O/VEMNUTrS2iZedsS1KlPvI2mDECknhWp2R7bA4prvTjW/mVJIP3PWfBqLzM2PG6qiR
         JJbvgY4gkh9TvQwvLFhAbFI02oCIvPPtdcEY/EjqZlA2/CedfCY2bpDoqTK2WRg3Yfmd
         doLcjUfq8r3yJA0mlPNAxUapiYcc13XI2TKe/BuQNg3CipgWOAJkPRLwC2Si1dHFp4W7
         VyBXjDtGRUjXZ0YhpR7QcJ/oxEOsu1CiQP+DFYlLtwkO9TM71nqAuYpoDiM+QPGmXsfC
         CecQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+quuXrSXTqducEZaDQF2JNoWdVfOtQqn0eXOy5Rjrh8=;
        fh=iPF+nQI64R8aJHaZKgWw+GdnHbwSmGPhqI/3s4y8+4k=;
        b=UEDebs/0usSNE5cUYNuI25eKpviWmGre9nKQqdXFlhkno86AwWfFY1ZZSkTPkCtLPF
         cD8LpwXdboSax54a51VOAyurKISr4ZR4y1vydtflyTu/qWoDdcv15IHGJgmLCRbF+pyX
         QRaLVxrw62l8cIHLGET3+8/WYXonKPoog7kFZ9WxHioPgJxBfDxha0Fq19e/o9d0HDdg
         GF/mLTQCylkMcuKISleRgVHfYtXPuqIiHVckTgwAKKEPxyttArAR+Yt0ysvctMGcCAKO
         1bafAztCX/Qs5GXVQR0vpIXJPKprwlVF3sBSj5//uAqJhgQBX9wMuuMl6CtDuEx/y5LV
         jDgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cuoIUYt5;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975193; x=1748579993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+quuXrSXTqducEZaDQF2JNoWdVfOtQqn0eXOy5Rjrh8=;
        b=fv3RSA98mo84qY9yJdlLBKSB/8PIt3R6Te6j8+UoVf4y4X55j3Lw2sxnluLnmmbpss
         jFptU2KEoFccWMDLqs3+H0weH84II8v7whHPZQz67hWkxKNpbcN1H2+YCSGWOjbbX76o
         R9eIsINYLM7pciSmEBtah4HlQy2gyPdHCtpTQ+kKp8xYExY19Sq/UOIf8zyWoms68S5z
         NHtr8JUgzED/3PIKzHLNzqiWak46Ecgw3alDc5Wg/BNgRbTASf07B3oA5gbgPVFzyzEM
         c+j8IPc8Id/mh2lawbDox7z0d+cKHW5oSC1fBDgavi7pfsnO+tXyoT83/KtvvB+JCjXS
         CJgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975193; x=1748579993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+quuXrSXTqducEZaDQF2JNoWdVfOtQqn0eXOy5Rjrh8=;
        b=upShGklnbR6gGZIkq01JKxnfbVn4AbdqrabHa+yP+LiakaY/wbyEO78yK5J+uSZWCe
         o62dS0XMpFvL/RYU8Z/oX6aflxQ1SesmK0X3r+WdiV5om7w4i4uB0L/6LgZh67syQroj
         rU9i/bOtCCbx8PObYgQI9rNdqSqjuaMbbhBi5ofI8Rc/5hoQML8xO+IPw5lo7IWBSSsG
         ykjQFxnQqCO7InPCm99pqvVxVrZS+dm6Uf1A6KQbytpyfKYLMKjJ2XxIx+MSHhNn0Yxv
         nyFyhg2V8E00I7bcEwMg65ln3z1XUj9HD6nmRR4AMBTNhzrMCczsfeObeT6ryCWBSiz+
         6B/Q==
X-Forwarded-Encrypted: i=2; AJvYcCW+x0tnlMEaGJitLioyxLSIeTFbU0Ael9NzoMKXDR+d/2yPPj2jLHhdPall+hQWIXjUTgX3wg==@lfdr.de
X-Gm-Message-State: AOJu0YyEz+sMbkxc7W69a+oguotXra0uIQTyvwKfJJkvE1JnvQtfMrTz
	UzgmT0o9kDGL3ntuXOTi6ntK/QG6zzXwpCKQfWqGZuyVjEarkjygoEyt
X-Google-Smtp-Source: AGHT+IHWqvtBnbW2tsKIUmF6fXct+p0dE7V5lHtcJutyQ0Pte24Mep629Tg2jkhZrywoHNMCpFs7dg==
X-Received: by 2002:a05:6871:d107:b0:2d5:ba2d:80df with SMTP id 586e51a60fabf-2e3c81725a8mr16598802fac.8.1747975193218;
        Thu, 22 May 2025 21:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHLE5O5T1z7AGXUccZbVgPgbx4Y9Iwu1fcyBV+ia+lg/w==
Received: by 2002:a05:6871:53c4:b0:2c2:d749:9156 with SMTP id
 586e51a60fabf-2e39c951368ls964458fac.0.-pod-prod-05-us; Thu, 22 May 2025
 21:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXleAvdb7y6OdnhVy2LWzMSbKslid7U7SzDkV7oDjwB1bS9q7BupQhXwH+H1QskBzxRxunyLzv87w=@googlegroups.com
X-Received: by 2002:a05:6e02:3184:b0:3dc:7b3d:6a37 with SMTP id e9e14a558f8ab-3dc7b3d7069mr159579995ab.8.1747975182002;
        Thu, 22 May 2025 21:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975181; cv=none;
        d=google.com; s=arc-20240605;
        b=bcKiNiNp5/PNQrBr6IihYAZn7Q23GwyS85V2xedOjzjHcOxUkdq+hO2F1AXP1mXms7
         DqYeuwAgVIooD6BgxqOdO+pSck1pe+KJs0VcsDqYismpiCNHPM9Ng/iCx+vYOevgqJWT
         hwxNvzsnhWy7EOSIUZpYRmJe23lsx30iNjn4pxNHtH7+M/zSX17Mp0aEluELgoINEnAe
         aSBfLpiIMq8gGr4nAI8SnZFlMvkWOFhqsw4l6+mm5bpS7gVN2zWGpX5h4dyOMXM6xYvg
         hSY4RrboquKWWMo6+CJeM9r11r82X1z1PQnnhA8BlTn+a91boIlYcDXU/dagDZdr+Kkg
         w3cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4j17pn+//SHkaX8ONm+HlhNEvqzcDQ+QNAUfr7A3lEQ=;
        fh=cygJepZfPPJV/Ca4ACYTWMy/d1rKkp/i+dzWIHuBXG0=;
        b=dW/jFTPZgmKN11GX9IgaBvSwlR1u6KGiy8lmd+9KO+AHAXj56kX6fXPlqRvrOYefsE
         m2A4HotNa5OlEE6ZxiRUCORv37CCnmD0Rdbx+5IxUg7YIHAaFK9x3pvd72S4bWotpboX
         dZbyjTPS7yUwsgTtEM/MGSALlkng5G97IPZkNnegXgaJBKopCZ5nnpDO7lJlmRhncrvX
         WxDDTvPBMAOtW8FAKo6qqOfqmoK6OMboTXDoXyfvijMzNURgwV+/ftS4LzWJ0ulaeMS/
         9JjB2OLUDvIhx+/E/AsMwyYMvhoIRFwlZRauumbFL94DrKhgXYOnKmXSmgu6mTmU/Kdx
         B4lQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cuoIUYt5;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3dc8c775233si1361695ab.1.2025.05.22.21.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 704BD62A6A;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 37879C4AF09;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
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
Subject: [PATCH v2 12/14] kstack_erase: Support Clang stack depth tracking
Date: Thu, 22 May 2025 21:39:22 -0700
Message-Id: <20250523043935.2009972-12-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2299; i=kees@kernel.org; h=from:subject; bh=p+7YUBTmffdnZ8pKAPuZ2rzC3Zvp9P0MFRgY7Xz1ydU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/vPnPUwKQyTLv6YDRX59942Z9pVg4x/Z3tr6sPL i8Lmbqoo5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCIh3gy/2RSNKlmvL8m9MY2r Wbrn3fITnxd82hB9cYHtv/Cm+4suZTMyPNm8de0lHpnV+k8jWq5Yr/ylxKmUuEhjp6St9pbzk2V 2cwEA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cuoIUYt5;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-12-kees%40kernel.org.
