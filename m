Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7Z4GPQMGQELAWBJAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id AA6276A1860
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 10:00:04 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id e8-20020a05651c038800b002904f23836bsf4235205ljp.17
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 01:00:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677229204; cv=pass;
        d=google.com; s=arc-20160816;
        b=J4Ge0KRovTQ/cybKNXua+Icvwoiq2pgvFuSW7Rq/mloxGWJja9WzW9lkvFtcd5cbRg
         gLhgQaCjI6+jYfYvZo0a+IuDzxn2wnM0rRKfIJlhQpHZJei4KtWcFD3ohfwG8hVLgTq+
         4nv6LiiHhYb9JONYcY2XWlUhVd6l2C0F6GL5eqE/YsV5N0SOVOLvWWVmKEJ6eaCEAMak
         fHsMGBa6PSzDaOMkQjzJZVFqPvURwI+ap84pJtENTkdYIIuBOjIO0afFuQj9cQcPAw6L
         mqPTFv2UkHqJITAfxKLscFTnpLnOiJPDa+p8Uq5YBOGAIa9dYBvryZfPMziTqOOwcl77
         B38Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dVzSRqswyLc815oF+QbOTcht9UoQmj65pQtFIn9blr8=;
        b=kQAFGqGqq7gSQ9bbRr87akbh/7aIaiXGKxMwUWNPDE9HWff6kRnPLh8FuR3ogCZb0h
         WHUup8+ZH0Zir/LHsyfPN00ksfGeEe0X4Tre7s10CxgCXVgIhi99pU/oBOn8TVRmG3sS
         C60a/I8/KTfEoEDwtpGo5sMGoQ66V6EKoeGTDEfajcdCgIGRwBgBelOriC2M/gPx458B
         sJbMWCQNi03I5Rcl6emf4B3IdXYI/wo29sv3P9mmDWDH4X7pFSHlCggvATLuin4cyid1
         /6+v07WDNltI0Imsy32WFMKREZ3QO0MGR4E8QNdi3G3FCD0taHjH2MQgT+Ylq/UZ4Wn/
         5FVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KNP4d6RV;
       spf=pass (google.com: domain of 3kxz4ywukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXz4YwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dVzSRqswyLc815oF+QbOTcht9UoQmj65pQtFIn9blr8=;
        b=bd/ghnexVHoYGH4F4UINnxMiDKOV9xF5QECcaGWolxlqlsNNdV8E8nCpugDwhI8C2R
         /put+XQb/InbKBnJrzonKQU98nviAa+/+U68Xs31nkO9WpmoSrv3sN1aDXOF6Q4/hudZ
         u19BsEghGd7LnGEY1SimPmAj43BPMXLIhc2DXssyqVmaCeYz36R5nJNvxsZeTKkQIdJc
         nHepTgsouhi6T6aBcDtfGe2OCTAlUa3hocQPyfann/5zzQPipCage0XKM56hhZV89QVU
         qHj2qD94DPiVCV3KAn52JToKqspObv6RmWjyKyNErXMwOzcceW0Ap/CjZqCJzlDuKH+h
         Hc8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dVzSRqswyLc815oF+QbOTcht9UoQmj65pQtFIn9blr8=;
        b=3hoauUpz5CqVHxvtPkq/Hx40RObqsHLiHaKl8Vui6/qsj1r5My4WGil7fEYMWMadSs
         sCMlWqTzNSySAhD7t3jjPD8t3mShVIqn5fnJY882jh6TpV1N7V3ihtjc5SkhG4Dr5mRV
         ieMl/DwKnvh05FBlerOwY6dyS2BTGFqDhzHeI4hknEBNOhBpLmIPtskZSGg+AvJSmkZG
         YbV14rRMXCCdELbXEjPOCtdlOmlrEwncdJY7mCz+qK9rKZNoLwpzGKkduNUKeYAC/Cah
         irMMYP5AxJSoYtKsCxQdhSi/WUmns1G0p+YcGK3qcm+DaomkUDwk1ZTqRPZl9Kxm/BSs
         8Ung==
X-Gm-Message-State: AO0yUKXWJgqgWYYqHITkWRzgGktUN7kBzZ4UcCoz3uywuRc/ipQTbrJR
	HPAHu8rUzPJx46+6BrRLW8k=
X-Google-Smtp-Source: AK7set+5UDu7fLFsh39ZbZrmZEh2eqsdo4cqQaI+IjvEynSpX+6KUHdj6r7XPVUjrfM21Qz5/NyPsg==
X-Received: by 2002:a2e:b5d6:0:b0:293:531b:90ce with SMTP id g22-20020a2eb5d6000000b00293531b90cemr4581015ljn.4.1677229203936;
        Fri, 24 Feb 2023 01:00:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7805:0:b0:295:e6f:9742 with SMTP id t5-20020a2e7805000000b002950e6f9742ls365269ljc.0.-pod-prod-gmail;
 Fri, 24 Feb 2023 01:00:02 -0800 (PST)
X-Received: by 2002:a2e:320f:0:b0:295:a778:62e3 with SMTP id y15-20020a2e320f000000b00295a77862e3mr215039ljy.53.1677229202191;
        Fri, 24 Feb 2023 01:00:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677229202; cv=none;
        d=google.com; s=arc-20160816;
        b=Auf2ZZ8CYs7xiKRS4YBJtGC7HJ6CpMjkeWb48AlIIaSEU5u7iNOxHBt1rsN3u0u75j
         T684+3kQ6HgF4iLQ3NMmirCHOF/XMiGaExv9Ee8K9+zDsSUGCYeRHqk2p/3LpxJXJvVR
         k6GWN9Z28APj74hZXbuF2ub7OYjAGJHFSwL25KzmlLWngMe66uN2zpd1HGWBOseB4GZ0
         IBURyDphrz/xdjVr+x3eTcpqp3i/TLOeAoQ2GazeuWX7t9RzhTWEqA5ceywhbh8qb/5B
         Wz5ZfkQBVj4bTbkWKEcNDGqfZ8e6geTPU+JwY7VBK8cWQf/vPEsLHUltgmcKw51aNGqy
         RRbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ni0X0/loZejzrEM3ahtyHsQ4czmgqm9WNAw1TT3btvM=;
        b=Ax8HeUFC6NC/gPiwAkwvEauukZduYcLw3wUbAdZv8cjuMzHB/lYR1h1B8whhciFswK
         kTxhDogzboQyLkOkn58SDboIvSIB/2YtOfkY1Dq0lHfAvu9X0SxcGiUrB2DX+MIZnywj
         nIZz4n+cU5KKDjnta5g5OAJ3UH1McKDG4/OIyqLDP3z+CNHHvzCVNyoK7FtdxwPMdUOL
         3ZgiYoQI+70LJyCz4GaQ5SITm2ER9Tcn9Pr3JqnaMj7sVOLHiqygp27tguVDFcZrJw6c
         rSqq9K49ffLg5M2j3KLOhe54P9VZmC9ZZ+YoMvRmFvHoNToRQebxIUzkUcEQTgUWOwlC
         CKxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KNP4d6RV;
       spf=pass (google.com: domain of 3kxz4ywukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXz4YwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id y6-20020a196406000000b004dc4c4ff7dcsi550374lfb.2.2023.02.24.01.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Feb 2023 01:00:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kxz4ywukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cf11-20020a0564020b8b00b0049ec3a108beso18363983edb.7
        for <kasan-dev@googlegroups.com>; Fri, 24 Feb 2023 01:00:02 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:53eb:6453:f5f5:3bb9])
 (user=elver job=sendgmr) by 2002:a50:d544:0:b0:4ad:6e3e:7da6 with SMTP id
 f4-20020a50d544000000b004ad6e3e7da6mr7001699edj.6.1677229201684; Fri, 24 Feb
 2023 01:00:01 -0800 (PST)
Date: Fri, 24 Feb 2023 09:59:40 +0100
In-Reply-To: <20230224085942.1791837-1-elver@google.com>
Mime-Version: 1.0
References: <20230224085942.1791837-1-elver@google.com>
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Message-ID: <20230224085942.1791837-2-elver@google.com>
Subject: [PATCH v5 2/4] kasan: Treat meminstrinsic as builtins in
 uninstrumented files
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Jakub Jelinek <jakub@redhat.com>, 
	linux-toolchains@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kbuild@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KNP4d6RV;       spf=pass
 (google.com: domain of 3kxz4ywukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kXz4YwUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Linux Kernel Functional Testing <lkft@linaro.org>
Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224085942.1791837-2-elver%40google.com.
