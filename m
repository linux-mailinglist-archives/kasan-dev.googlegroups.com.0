Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUAXOPQMGQEMNYZIUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BF15469A299
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:45:39 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id b19-20020a05600c4e1300b003e10d3e1c23sf3982866wmq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:45:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676591139; cv=pass;
        d=google.com; s=arc-20160816;
        b=JxSYOiAj1g35ke1gIJuf3s/ZgxqgOZKPMP0hd7swboWyhyysa15q/GSjRbByoK3nYY
         KVhel9b91ucQgI0mRkkYnoLA7ouBjA6CPlASm+gbM2797s6DC1MCysRrz8I2aF15qAvk
         znUC4Nbmfui3jeEAvsYEYG0VLhCYsGP6a3b+51RP7sxVQ1EQum2F9eCtB/thhHcgFM7a
         ZWeloMX5Ogm4clz9MJ79QWBCDqHniz1ULFZtzWX4hFvQ6UawecpGO9ycIbbdfJxamOiK
         t1XYWb3yk4lll9nAzvyjQKgXSD0586i6tRCfNLmKykgypbIQDX/BkM19nHdCb1iH/vLc
         +r+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WCbncjhw6k9Pn/5/5NUoyU5msDftBnHwJSiDDf93XLU=;
        b=o0l94XIVJzcs5bbaRQxeauxYg/io86RgSmL6+VO2pIxXM/Vrl+ufvzJCAy2BsD0R0q
         i7i2LD7uc+HmaA7fpBSoZM7e2CVvGoFBASumIRQyzB1UhcV+4PhL0Ux9VckzQMWyaxQN
         hgykjdtZFsqjEhypNtAuATGqps2pnuVPEgMVDfG7SFNyANTq47bUq1Nvkl/yu7dBIDFh
         iKmfsyFc+SVnSjD6tsm2ouZ/E325IHGHMSx7G27/QnlsNmafhyBxvxnNQXk1BfC1TDZU
         rtIYUcIEdAGU7hjpl6ao0glkOa2fsivNesVKvBiQ/jo/zBBvyHlbbyMVj5ksknubqnlh
         dSSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HPdFHv+a;
       spf=pass (google.com: domain of 3imduywukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3IMDuYwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WCbncjhw6k9Pn/5/5NUoyU5msDftBnHwJSiDDf93XLU=;
        b=n5bVwyQEFUFdSwGf1nY+ZiAyL83A20bfArhBHFyh1ESQ7PjxUfy4ha3vKE8nii2NcT
         p81FB5v3AZRZYf5Tb+QyO2hyPtu0t/64nvxjTaLVcuwthTuos9ozvlkndIHph3i0Ntc1
         wgWxt4TPZObJeak1Dx8vCHUvQ2NK0FFpg3GYW5ONb+grtgiZ1mrOWpSIPLf/VgC9grlR
         5hGQFsv61QJX9lJ4yay+phedUE906snD0px23JExDCdHdg3SsUgj8aZj7BNfEA9WlvP+
         VNejht6RjW1u+JeiXhHljTmCa9Fls5z7IAfmbc0FARFr1UtoKP4P9lgqGPLfD3N9Ma1F
         M8Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WCbncjhw6k9Pn/5/5NUoyU5msDftBnHwJSiDDf93XLU=;
        b=AhUFQUyO/VMIhG/Zs03P6ZapqU84eDh57VyTTlENEqPsT70UOhX9PW92NYVcSZMYru
         jLqZLNfnwP0BxYYG7r+7OusMd6jhRtqI2e337wWXer36Evlpi+UUeDPXjdRa4BehIdRo
         EgDB1rG6hAMh2rYmr3BmzRHHGgKsUstjDrw0SnrnQUnTWI6FPRsv7P3Sd/oRJrbGZ2RH
         5HYVvdbzOev8K/2fIx5Aond64a4QgekXa6CJAK9jzRUA+68da+wK9UqAgM8uPILCnPJ+
         tnNmUis06eLLvauIETVBeLnYb+eiRlVhXE6uVwuGRBvu0mZ91ZiwY0EWkjgWH6tlH26u
         jpAg==
X-Gm-Message-State: AO0yUKUPo9qaf+Aoi0fFr8dhb67AzrtvY/NEWZ7My4pVFaxb7Bq61TEq
	FV+ow9JDSgn7ELHIApxwYOVavQ==
X-Google-Smtp-Source: AK7set/4khSJPYIXIobkZdE2vuZS+H7CY3XObrTKksqZ0/HCJiEKh3QOCpBhxNCDBRnr40WCTLpmMA==
X-Received: by 2002:a05:600c:5493:b0:3df:fffb:5afd with SMTP id iv19-20020a05600c549300b003dffffb5afdmr337039wmb.70.1676591139006;
        Thu, 16 Feb 2023 15:45:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c0a:b0:3dc:5674:6707 with SMTP id
 j10-20020a05600c1c0a00b003dc56746707ls3313340wms.2.-pod-canary-gmail; Thu, 16
 Feb 2023 15:45:37 -0800 (PST)
X-Received: by 2002:a05:600c:4d90:b0:3e0:1a9:b1e0 with SMTP id v16-20020a05600c4d9000b003e001a9b1e0mr6956364wmp.25.1676591137427;
        Thu, 16 Feb 2023 15:45:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676591137; cv=none;
        d=google.com; s=arc-20160816;
        b=usSNfvWC5H+Tv9Gnu7by1mWokCARdQOsVdczAvLi6/0k8WGyJA4POU2eTWsjsSSjk+
         +dAcNz/EHwpSuE9EBn9HkS/g70+mox9OiUajRh5kkwrqz8kWO3w5816XNDkjMYE2Utf3
         0p4b96YLWFd2xrogSQy0P1NecnNAF3dKl2fc71AR2wUvjcXWE5kuREi2iz246nKt1wY8
         ClGenAxOf02YumOQwVq+VmW9oc+GOX7R+NEo4EOyaH8iryzJ3rGlcuEaB9lUENe2GVwl
         mVpGI3fb5bkKCcWoNpE+NWUX+6k9QgMICloJgxPX0YkKCQbgPzLj0+R0/6yOHWsRqIFZ
         JwdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WEP0gdOIpvbUmMDY5eO53Tqx5XD06xr9LMwpgFaq1D0=;
        b=pcmKY/+Fu8H9Jx/OKb5+nXxL8wlbCE4Q0yPPrvM97Ir6t54jGkIpmAAujGqU1l1YCA
         /cUlIO8LO7oLz/CpqvVqMvNc0K6QEyFDT20JeYzItGS6EI+IWrUplQDYRsDIWbAm2c+k
         GnFOhxf/wSyntvEtnfYZwUmd8O/R29UH0vCttpasqn2Hg+3zR5ctZ+jYStMYmshCqDzK
         eTdeOs9EkzrhWWSQBywC1UQnmu0t79qCm60epVKYcAGPWT/2V+O6fEAS0CH1126dEPoH
         TCZbRkRw6VmKv8rBAoIfqEL/RNEqy2Qbq/PdQMLM7xAfbM08JI2UMfNZt0SNf74Rgf+x
         IxGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HPdFHv+a;
       spf=pass (google.com: domain of 3imduywukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3IMDuYwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id iw15-20020a05600c54cf00b003dd1c15e7ffsi96529wmb.2.2023.02.16.15.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 15:45:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3imduywukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id bq13-20020a056402214d00b004a25d8d7593so3552905edb.0
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 15:45:37 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:34a3:b9c:4ef:ef85])
 (user=elver job=sendgmr) by 2002:a05:6402:2485:b0:4ad:739c:b38e with SMTP id
 q5-20020a056402248500b004ad739cb38emr1528006eda.1.1676591136985; Thu, 16 Feb
 2023 15:45:36 -0800 (PST)
Date: Fri, 17 Feb 2023 00:45:21 +0100
In-Reply-To: <20230216234522.3757369-1-elver@google.com>
Mime-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com>
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230216234522.3757369-2-elver@google.com>
Subject: [PATCH -tip v4 2/3] kasan: Treat meminstrinsic as builtins in
 uninstrumented files
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HPdFHv+a;       spf=pass
 (google.com: domain of 3imduywukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3IMDuYwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Where the compiler instruments meminstrinsics by generating calls to
__asan/__hwasan_ prefixed functions, let the compiler consider
memintrinsics as builtin again.

To do so, never override memset/memmove/memcpy if the compiler does the
correct instrumentation - even on !GENERIC_ENTRY architectures.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* New patch.
---
 lib/Kconfig.kasan      | 9 +++++++++
 mm/kasan/shadow.c      | 5 ++++-
 scripts/Makefile.kasan | 9 +++++++++
 3 files changed, 22 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index be6ee6020290..fdca89c05745 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -49,6 +49,15 @@ menuconfig KASAN
 
 if KASAN
 
+config CC_HAS_KASAN_MEMINTRINSIC_PREFIX
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=kernel-address -mllvm -asan-kernel-mem-intrinsic-prefix=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=kernel-address --param asan-kernel-mem-intrinsic-prefix=1))
+	# Don't define it if we don't need it: compilation of the test uses
+	# this variable to decide how the compiler should treat builtins.
+	depends on !KASAN_HW_TAGS
+	help
+	  The compiler is able to prefix memintrinsics with __asan or __hwasan.
+
 choice
 	prompt "KASAN mode"
 	default KASAN_GENERIC
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index f8a47cb299cb..43b6a59c8b54 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -38,11 +38,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
-#ifndef CONFIG_GENERIC_ENTRY
+#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG_GENERIC_ENTRY)
 /*
  * CONFIG_GENERIC_ENTRY relies on compiler emitted mem*() calls to not be
  * instrumented. KASAN enabled toolchains should emit __asan_mem*() functions
  * for the sites they want to instrument.
+ *
+ * If we have a compiler that can instrument meminstrinsics, never override
+ * these, so that non-instrumented files can safely consider them as builtins.
  */
 #undef memset
 void *memset(void *addr, int c, size_t len)
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index fa9f836f8039..c186110ffa20 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -1,5 +1,14 @@
 # SPDX-License-Identifier: GPL-2.0
+
+ifdef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
+# Safe for compiler to generate meminstrinsic calls in uninstrumented files.
+CFLAGS_KASAN_NOSANITIZE :=
+else
+# Don't let compiler generate memintrinsic calls in uninstrumented files
+# because they are instrumented.
 CFLAGS_KASAN_NOSANITIZE := -fno-builtin
+endif
+
 KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
 
 cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230216234522.3757369-2-elver%40google.com.
