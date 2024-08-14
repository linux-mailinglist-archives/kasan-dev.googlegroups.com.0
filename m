Return-Path: <kasan-dev+bncBAABBFFO6O2QMGQEUHYP5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E534F951F84
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:11:02 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-52eff5a4faasf8369567e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651862; cv=pass;
        d=google.com; s=arc-20160816;
        b=xuQvq9S0LqnawHQLj38v4ok980ZbM0W3AdLFCBE86Fde7uI10hKpagFCCsafr8uOIu
         l6FcdB8zk9aIZcYTpwEtaMpvcWju24ELsakBE8a2ixBjvbPT12OPP8sAUzGPto4oB6aQ
         gSNHr2FsBavECbIS7ZWYDf+1ZXQqTgj4I+Mp1ySQAZ7zRib9u2w21AzzBHd0/jQmnaYw
         EIxtiQv2k2xsUNgC7vyVm1sunqm6cXVdlyw1cH+1vj2xeks5zfAha7rMGXLUjWZLhon1
         np/QS1TzhCvbHe1T0tulEdU93nMCF0OTuTE92lltQ1j5yaJPlDULCT6YJcn9ioAFWbLt
         VHWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=r/D0yT+NM8zDwVcW6f+bYbxxKHlEL1n5ac4FGo6WU1Q=;
        fh=mHklRiiDDRhRqLnOHx8322UOFNAZ3Sruz/y09OOTW6s=;
        b=kR/pdNwBKSHA5hTpcYIuy+49kIQz3rn6WrDGfGXq8PTjiB4gOvT5+tD1JDQVkF3Zd/
         5GY/Y9lgesKXVbrk+cKV0qzApX+MjloZ3Y+SFC5EHt8d5yB9gulPl0rhxGRB2ttX5ni6
         p0q12Jcv1o4USwNiWBf5h3FKTgeApdDjXyATrgAerfHWjHAJUOkgYH/8JM2P28/YsEsv
         jMBGSqC97S7a7v6wzsmeJLVd54Y/HuAnIlauIl9e501SdgFLwZvPVf7jZkNkJtTaSRJp
         vL/I8YbWbC8cs7DqGIbeukE57UvJ7ZIx6vnH/LQjZOSVqzitaWEqcxg8TJkwo/gJ/tgp
         ysUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vLOP3kXA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651862; x=1724256662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r/D0yT+NM8zDwVcW6f+bYbxxKHlEL1n5ac4FGo6WU1Q=;
        b=WwSWrs3uUq35L1lUIytE2viwDnyTvMdvMd3mFHsIvWOSFVctrFrXz6MoP4sZFe7PoB
         Zc1YLU/YUoEk5b7/EkiRp5N7oAjWerXKITzGyXB6nMpvFwakiPt8HkEEQ6imXvR6bLCp
         84YJKNJRcrs1VsTFkSSJYT/ocNpo5Mj+FPJgOCWsp1+clkkK9UIsAsAE5oe3fEp5R4iS
         tnnpxlFZBbvbgGiyejXOtk8mNCkaNuWH7XlIWloqeuE24INwaowZ9OYjQlUujWpgYe22
         yjSOJoyCXdYQmjFl1C0pyRq/cOt9hwJ//H7SzXF9MgpO4qCJRMztrH/0CaL7sJtMLl3e
         uvog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651862; x=1724256662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=r/D0yT+NM8zDwVcW6f+bYbxxKHlEL1n5ac4FGo6WU1Q=;
        b=YpBA0Qhr8l+/LKtOHSbXFWjOOuN3rTMuMIIRfWkGzdyPtfwxP41dp2sO3WnWGbGF6q
         nM6OM9ZHIGf7+j2miPmc755MmU7zBweYaBjWRKHPnkXHePdfFodz8dZAZEMPUg0AozkW
         Embl3wQoTHffIEWPvyKMtgPNBi2vSfW0QZ3wLO3yLd1b53evhAilCevq9CUzUXqytH1l
         xcEYE9Qdhh5LJle5qGaONhJt1YrXXTcK5BBufH12vZeYWl6+EneKstusN8oVaTOOZZqY
         ZDSnEy2FjGFHWCA6HSse1+NPQPFCHfuX9tpS9yun0b/pQbP68T5GS7bAn5bKwmFHBqez
         CkTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7X2axVOoHrP1CsGzHmXI1rku53MCXczOGjPwykyw2DRvC75Gw3SLIiGGUh9mnAkDGVOCmya3impPZEdE4CbpABzU3pU0n2w==
X-Gm-Message-State: AOJu0YxKGphlfquPT1OBlniQTledBWYQsvD3CCWD/bwsayrPUs2da5+m
	4NmErCw7piOyMgm6QKkZyHuc7OLIDWoM1ywQSQOitPwp0qZs39pd
X-Google-Smtp-Source: AGHT+IEBzliTkbLNW+uBnDdQcH64j0IrVFJOYAnnI5cAY6UeKg7TRprsqGQsgW5Zj71LHBqHr6/ivA==
X-Received: by 2002:a05:6512:b24:b0:52c:859c:91dd with SMTP id 2adb3069b0e04-532eda670d1mr2085232e87.5.1723651860944;
        Wed, 14 Aug 2024 09:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e07:0:b0:52f:cbbe:1afc with SMTP id 2adb3069b0e04-53307f478f6ls33966e87.2.-pod-prod-09-eu;
 Wed, 14 Aug 2024 09:10:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUI3xYok698Pf3KkJAAgk3JcEfnjwsMVdo8CsENvoBHcx9rAeLAV3R7/j+UiJHv6tRgsVrI10UbqC6b4Xlua4/xqly37zVKQJxDpw==
X-Received: by 2002:a05:6512:3d87:b0:52c:881b:73c0 with SMTP id 2adb3069b0e04-532eda799ddmr2030379e87.17.1723651858641;
        Wed, 14 Aug 2024 09:10:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651858; cv=none;
        d=google.com; s=arc-20160816;
        b=R/hasfG27mKALptlmV9Ex8iZSgCH//dviv6Jzc3tApMqN7f2zGMjxhws8xo2kNKAgO
         AFGiTokZdsyeDIw++SR4yKMKu5zqDk1z07ZwFKlxpT5vVY9ew+5yEkdpHxBPRUijP/Ga
         AeJ4rpdlYiW7Pn7eB4fnrcRLIImoU47r3kWU5ZdkK1qNOBbMT+s0hsrm2LGyitPign4W
         IZcydyOh71BQNkYYLzaR87rpFi3RYfaK6EZe2iEV8mD5is4bdU3Zv3GpQoQHaGH2nFNx
         Qy8Vx+z2VODCoC0LNAiRQCoL1SR23sn7oijf2K8Rk4GwQaZoRrVLv6jYbP/P9Nymr78W
         PAUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CK1cjU9tK76LBIellpq38/TTF/N+OU0syvysYZxFmi4=;
        fh=d1tWONeWGyFfFKCK4xiIS0wfneH96UGsHS1ZoHfzk5s=;
        b=L3hl4FuO1tqZbeRRZ/L64Y2/VdwwY/FGVTElne+VzHOMfu2vpPNCQHsrt8M3O1Yx9Z
         tOSTjwkGcM7oyC0uwXLbaLIHltIIId3g9xC4/+6mI4AE0rZJKpDat2UK+eZ9jV34IBlo
         +iNsKLwmzb9eo1cl0iUfVUs+RFlahmJlxXZQ8d0L5EJzMRUf5bMcyc/RRK/hxTMriCA8
         z/1dV74HJSeUKdMwVqOwyHISeDmM0Y4X/Oh56lts4Ra2XYBI+2xlVjnYdlJ3u+QP8Sy1
         YMZPpMlaDRG0t153Z6RTrhe0m6RvWNzilu0pkV98x26DwB13W6aK+6mwJYTsL9wkzBvj
         bvhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=vLOP3kXA;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-183.mta0.migadu.com (out-183.mta0.migadu.com. [2001:41d0:1004:224b::b7])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53200e91898si195899e87.1.2024.08.14.09.10.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 09:10:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b7 as permitted sender) client-ip=2001:41d0:1004:224b::b7;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Matthew Maurer <mmaurer@google.com>,
	Miguel Ojeda <ojeda@kernel.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] kasan: simplify and clarify Makefile
Date: Wed, 14 Aug 2024 18:10:52 +0200
Message-Id: <20240814161052.10374-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=vLOP3kXA;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b7 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

When KASAN support was being added to the Linux kernel, GCC did not yet
support all of the KASAN-related compiler options. Thus, the KASAN
Makefile had to probe the compiler for supported options.

Nowadays, the Linux kernel GCC version requirement is 5.1+, and thus we
don't need the probing of the -fasan-shadow-offset parameter: it exists in
all 5.1+ GCCs.

Simplify the KASAN Makefile to drop CFLAGS_KASAN_MINIMAL.

Also add a few more comments and unify the indentation.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

---

Changes v1->v2:
- Comments fixes based on Miguel Ojeda's feedback.
---
 scripts/Makefile.kasan | 45 +++++++++++++++++++++---------------------
 1 file changed, 23 insertions(+), 22 deletions(-)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 390658a2d5b74..aab4154af00a7 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -22,30 +22,31 @@ endif
 ifdef CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_INLINE
+	# When the number of memory accesses in a function is less than this
+	# call threshold number, the compiler will use inline instrumentation.
+	# 10000 is chosen offhand as a sufficiently large number to make all
+	# kernel functions to be instrumented inline.
 	call_threshold := 10000
 else
 	call_threshold := 0
 endif
 
-CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
-
-# -fasan-shadow-offset fails without -fsanitize
-CFLAGS_KASAN_SHADOW := $(call cc-option, -fsanitize=kernel-address \
-			-fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
-			$(call cc-option, -fsanitize=kernel-address \
-			-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
-
-ifeq ($(strip $(CFLAGS_KASAN_SHADOW)),)
-	CFLAGS_KASAN := $(CFLAGS_KASAN_MINIMAL)
-else
-	# Now add all the compiler specific options that are valid standalone
-	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
-	 $(call cc-param,asan-globals=1) \
-	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
-	 $(call cc-param,asan-instrument-allocas=1)
-endif
-
-CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
+# First, enable -fsanitize=kernel-address together with providing the shadow
+# mapping offset, as for GCC, -fasan-shadow-offset fails without -fsanitize
+# (GCC accepts the shadow mapping offset via -fasan-shadow-offset instead of
+# a --param like the other KASAN parameters).
+# Instead of ifdef-checking the compiler, rely on cc-option.
+CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
+		-fasan-shadow-offset=$(KASAN_SHADOW_OFFSET), \
+		$(call cc-option, -fsanitize=kernel-address \
+		-mllvm -asan-mapping-offset=$(KASAN_SHADOW_OFFSET)))
+
+# Now, add other parameters enabled similarly in both GCC and Clang.
+# As some of them are not supported by older compilers, use cc-param.
+CFLAGS_KASAN += $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
+		$(call cc-param,asan-stack=$(stack_enable)) \
+		$(call cc-param,asan-instrument-allocas=1) \
+		$(call cc-param,asan-globals=1)
 
 # Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
 # instead. With compilers that don't support this option, compiler-inserted
@@ -57,9 +58,9 @@ endif # CONFIG_KASAN_GENERIC
 ifdef CONFIG_KASAN_SW_TAGS
 
 ifdef CONFIG_KASAN_INLINE
-    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
+	instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
 else
-    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
+	instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
 endif
 
 CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
@@ -70,7 +71,7 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
 ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
-CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+	CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
 endif
 
 endif # CONFIG_KASAN_SW_TAGS
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814161052.10374-1-andrey.konovalov%40linux.dev.
