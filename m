Return-Path: <kasan-dev+bncBDCPL7WX3MKBBIWH53AAMGQEVTRGZSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id BD630AAE8AD
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:17:09 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-60601184d87sf171940eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:17:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641826; cv=pass;
        d=google.com; s=arc-20240605;
        b=GPrIE1s2ab1St4lXd19mnnd0Iq9+wOC3QSx86gZADivYqgf1sy9L5Y9mF+Ti+Rl5QE
         yIlGjHADWvB7h3OxBM2hcxUvt42kArGfhsoCZlOqvUUJZNAUn9CpCRJZrSfBCeRtQFeL
         fUoiE8UWT/NHRfegxfghO7cD+0X8DmiNmfVGflgV3RZ8TLDrirImzbcYuMsuyvkXWIw9
         qhOegJYmJ4V2KuD3z51L/mS/zx7WdamsfTBdxdIZFYTRbUWp9DaVnnxUWxLzT/6pOGHP
         KL0VFEHPKAQBGS9hJsH9R/D4Q78iP4PfKJ0a0J2OYN8KpB45W6zU0psF2GAK/7WfP8ke
         ZVdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ETwmpMVc1t1QxCxTQ5kA9V6ZMOOi05CnR9set2n4xfA=;
        fh=TMVP/tkcLln9FzOw/KZURLl7UihSl5bSAMdVzdMkRHM=;
        b=ECj47W6MWDxiHallCa6tC2otee+R+LJ+ayIpG2/n6wiYP7wyD9zZYFaa8mrr6AUXvY
         bepagnHlv8JdibrcIsN8HXVZn4bnwonpKXtYNEuahAtIgbJiKiF6X+xMwfXENo+1pMmr
         XWbzJKWJf6Ehx/90vbYnVvmTAZApDmuqww9oIMc0+z/31oD8B5PiII3iVu27IlpGkuf1
         K+rTW1B1hqYW9253A/+DgkSiS3xH7EbxG3dWoeMi7CwGXWb8eqLzoRKautttR9zmTM1s
         vAPrdF28jTGxpHhGxt9qRjy5ktdxmc8muU5UWt0t4kq0+bgHl6KCzDqtBZ2uqY2whFY+
         DDSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TxTsO8yk;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641826; x=1747246626; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ETwmpMVc1t1QxCxTQ5kA9V6ZMOOi05CnR9set2n4xfA=;
        b=oRqohmIb1phsNfATYc8gVS4LAq6UwkboF8hNrVRScIJKRxBswDE/JiHky1blMi26m8
         fwjhRwMYdwc4OQzJcBbId673Ix0D/4HReKMt93468KApj2GuhpoEgylcuqvLd1lYOA/C
         qesXw34sRoJj0vAY5SFQ3dzkITyNwXrYgfZQKn9JooY+CfjTVxkcKxUdzpfGf5FlNIok
         udG9TQQG/BK0gn7W69Z+IcZnjM7BdMX+Yy9PLwHoxVzEhz711AqGf2agoz7I4rw03GmV
         3MQhhaNrZ0uNbIFhxhv90LzH2/wjmyj0tTx7NRdCFjlbjnTGKYmW6GF0iMaEA2aHUvtk
         mTFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641826; x=1747246626;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ETwmpMVc1t1QxCxTQ5kA9V6ZMOOi05CnR9set2n4xfA=;
        b=sVFcdsEKNlSL1sCdSo80viVsDjsTpV0BLLgftbGm3A8uOK7YXe11SZP+Ur9Tg+FYlf
         T0OblnlXV8BHVTgeekWsi1OrAIa9XMiWqfqZaszmrsnKYbOk9T69RedVDG4vHIFtl95v
         y3/SWZFJqaevEWw4afcz3OQ/Q2z6U1b2euA9JyiqB/mEQxm6GPfnUC4onU++8s9EfcM7
         XtAI0sOwQZLamr5hwOcRkOQTkanHK2T+SmAoDccKvg4qbATkN3wcxqkK5fZpxdFISS0f
         TiH/b9u7VvXQGV3Unw4OS6//FENJbnZ5vmC0P+D+QsbYZQ+uvpsPRAvId1o3T8s2yO8R
         lQ/Q==
X-Forwarded-Encrypted: i=2; AJvYcCWbxr699H9X2bYNtI3gwPG9BFRaekeKXQwS5FGHmxAxQGT9CqkZSTcbTwwSoRaa/EY7jk82wA==@lfdr.de
X-Gm-Message-State: AOJu0Yyew/jaJmiWsD+5yGZF+ecGbRl3pQ+bYiutUNxpj2izPodPOhNy
	HVsg+wRVwJ23QFn5BqpTavJhhnVtj/bkrlDOKY3kRi3boOyyDezU
X-Google-Smtp-Source: AGHT+IF7XPFvVXSCmtDyRqqnmsXc5ZszJ26DSUm6VBmfxQdJLN1CHild55Q1GIjrhYkf0F30Bj2iHA==
X-Received: by 2002:a05:6820:270e:b0:606:d85b:570e with SMTP id 006d021491bc7-60833971681mr276601eaf.3.1746641826449;
        Wed, 07 May 2025 11:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGItfmx8ubQUonuuBAbhi1wK7BS2Tk0jS2HmLzbsMXFvQ==
Received: by 2002:a4a:a2ca:0:b0:604:4e1e:cf36 with SMTP id 006d021491bc7-60832e0e02els125534eaf.0.-pod-prod-08-us;
 Wed, 07 May 2025 11:17:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtxI1b0ctSHxtvi/GsTOqln5js6zxNhAOyRQA/B6jON5vTKBn+3o1x2tGhV7rTr4ACkmMsOuoQTyc=@googlegroups.com
X-Received: by 2002:a17:90b:1d03:b0:2ee:53b3:3f1c with SMTP id 98e67ed59e1d1-30b28ce2bd5mr222377a91.5.1746641781587;
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641781; cv=none;
        d=google.com; s=arc-20240605;
        b=LMIk9/7QyO5OQALuTaQSJz94a+OMlRKyuXzjkTmHcU/q3yjZkWOHwcBsaU/KvdR+YG
         zsA9AZJhbzXMy9dxWh4if2jD6k8TbjFJVXOT5tILS1krXoON3SRdgy2oIlx+wrFQkMPF
         SByOKJEnYSQl1WFApn/TU+580YfXNJrTv5KaWU6NMLCpn1r66UET7W5CjIDhhPM+RBBF
         FKFfuCMFjXKqsCSjwpIdVFwAGqjLwMhBmWgkNm9m74jkw3jrEMbWXCstMPgCUMItZAah
         mFqJjmxz+pZrJNRhKEHR8TRnEXPTfUYbSs3L46u99KDxpLropV+ITHVKeRlzdgIAFlUC
         PoWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YiONM8NAF1ek+5Qrsn/XPNAluqSaF4eM+UwbzQ4ovEM=;
        fh=cygJepZfPPJV/Ca4ACYTWMy/d1rKkp/i+dzWIHuBXG0=;
        b=HTXHCJ0BXjZUzaV70cPyw69wKw+CD7BH7VmO8oiMIlOYb0/99NFkxzY8hxXz8sESRD
         XZZ2B1/2phnrp9quEJTtoMYi/4z6D/MnvTw5MKq0Szqiv8V/4g4nY2b2J1EtHsen9fao
         E6g6tKmnxP64llTUFtIrlBnFGuVSKvm0IEb6gpK/j1sYKnohs1+VroQkEMTeTdyNKa5J
         mN01W8ZTtSv46wxDMJvdJUCcaimTeuk9t479ij5UFhfTTBIQaZVX36YYejA/VzYGc10o
         N+gFZcXgIpu8fesyav6kThIl/lPv8LI/f4ogSUcTI6WFbgIDWDr6OzkYIQF4AsJBMpQf
         wF2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TxTsO8yk;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30ad483f38esi32093a91.1.2025.05.07.11.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6ECBA4AB29;
	Wed,  7 May 2025 18:16:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 415D2C4AF0D;
	Wed,  7 May 2025 18:16:21 +0000 (UTC)
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
Subject: [PATCH 6/8] stackleak: Support Clang stack depth tracking
Date: Wed,  7 May 2025 11:16:12 -0700
Message-Id: <20250507181615.1947159-6-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250507180852.work.231-kees@kernel.org>
References: <20250507180852.work.231-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2395; i=kees@kernel.org; h=from:subject; bh=HWoalOBMMGh9CGDJhSNrUZqEPdcdOzZUgEuD85/CAd4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi3OV3f9aX9C6psL+Z4P189SPmrHrPq2vaGzQi7++J e3+b/9ZHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABOZW8zIcOOQ8o9DShIK8v8K 78ip3l31Xjeztf3PMTP1fVIJigJ7RBj+absd2iPNURU2fbXh3XVreGuX+2wvdGKVFoni+iFa91+ TGwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TxTsO8yk;       spf=pass
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

Wire up CONFIG_STACKLEAK to Clang 21's new stack depth tracking
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
 security/Kconfig.hardening | 5 ++++-
 scripts/Makefile.stackleak | 6 ++++++
 2 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 2be6aed71c92..94aa8612c4e4 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -158,10 +158,13 @@ config GCC_PLUGIN_STRUCTLEAK_VERBOSE
 	  initialized. Since not all existing initializers are detected
 	  by the plugin, this can produce false positive warnings.
 
+config CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
+	def_bool $(cc-option,-fsanitize-coverage-stack-depth-callback-min=1)
+
 config STACKLEAK
 	bool "Poison kernel stack before returning from syscalls"
 	depends on HAVE_ARCH_STACKLEAK
-	depends on GCC_PLUGINS
+	depends on GCC_PLUGINS || CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
diff --git a/scripts/Makefile.stackleak b/scripts/Makefile.stackleak
index 1db0835b29d4..639cc32bcd1d 100644
--- a/scripts/Makefile.stackleak
+++ b/scripts/Makefile.stackleak
@@ -8,6 +8,12 @@ stackleak-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE) += -fplugin-arg-stacklea
 DISABLE_STACKLEAK  := -fplugin-arg-stackleak_plugin-disable
 endif
 
+ifdef CONFIG_CC_IS_CLANG
+stackleak-cflags-y += -fsanitize-coverage=stack-depth
+stackleak-cflags-y += -fsanitize-coverage-stack-depth-callback-min=$(CONFIG_STACKLEAK_TRACK_MIN_SIZE)
+DISABLE_STACKLEAK  := -fno-sanitize-coverage=stack-depth
+endif
+
 STACKLEAK_CFLAGS   := $(stackleak-cflags-y)
 
 export STACKLEAK_CFLAGS DISABLE_STACKLEAK
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507181615.1947159-6-kees%40kernel.org.
