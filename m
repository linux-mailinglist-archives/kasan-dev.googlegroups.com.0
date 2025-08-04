Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBB4PYTCAMGQEBJIPTAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4524B1A96F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 21:18:32 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-459d8020b7bsf8532675e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 12:18:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754335112; cv=pass;
        d=google.com; s=arc-20240605;
        b=S+LqAnI+zf4MBkGDRO/r8TDGmvYnsFt8OVDfUX8tQScQiXxa0KFEXIAM9jjzPvWT5o
         VQeg4DHvOZekIpnfvsEFFrvySZYjm95ESLZLfZ25HFp+Osfwi8cKEuGWekokiXAitC8u
         K6jTRYIy/oz0wUmHxXr5hiGaK8/V8/swHdCv7yZq3f3eT+6MTSyiU4nS/glAI6XUHvMq
         8qsbkmCC5AOP4uZ0nQGfsYrsYAYnruD9498VZv4EFQkn54RygObDgQqXb1wdUasZWCAb
         3paUV3wOjp8ZBRAJaoIKdb62o8uakXQrfXJ0TCkAeGRWD87YRJ7ch4iFD3XTTX09ZYfH
         74vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=5MzZum/WGGqVqa/9XtPLGCUq3obRVCd5vyO2Wt336zo=;
        fh=oQyyX5sRMrMRYv65Pl/7+YCDgRX4YzUwnO4TTIgbt68=;
        b=OzQp9rkY1wW2Axt/b3n3DzpJEMgAm1kVUaC569mmbn+24KcvG49ThJMhm+WJuS7xwJ
         GuUW7AWU1rDNuinPDQxvBK3oDrFyDKKQC8RlLp1JNWYD159vJz3O9pr9DF1w8IcCiq9v
         4QB79r2mSws3EX7aI4QWhmIPaUVUE6xn0XM/JGc8ouGTuZGpEqIQC9V6oYhchrhnzj0M
         vMsdCjs1OtKStTjD4hWn5Q7U450ukCSrHejGxe98qx1OeWCDs75HO8hiI8ffsBRyRFLL
         RfNxs3CS+mc2fmEgkninSTZMyofMHAxk7Xgf6CeLZlA03/L1qISGtymf80tlOzLDxwo+
         k83Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fWcp3B8o;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754335112; x=1754939912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5MzZum/WGGqVqa/9XtPLGCUq3obRVCd5vyO2Wt336zo=;
        b=Nck8j9qY5DpliHHNGw5iGUCr2MEmUrx5Sgj6ejM3ppn9VROhPZVAXcWSuCq4HTpzzH
         /t5u5lGCbiJfx6yUxnthhjlTX+WgJkhsIos1NCeb9W+11RTpDzXUVMF7pLA6kCFccSc9
         jZQOAx0Ggbh+IORRVYijER77gEdtEG7QJBCNubvPC5ngJabKH9HM6/wttarex7pWl2+y
         wfPk3A/R3wTrJ/Elg0N0rOLAcXlSzQD4NNumyHQeDmmQgGp9NPBg9tir65EFb6aTpcTj
         vLCTvUy/pHj8wFSU2MaBjeZQqOtTFNElynqddHOpHNOkUJp2WuTcNcJiwE6xEwlmBtrT
         Tz0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754335112; x=1754939912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5MzZum/WGGqVqa/9XtPLGCUq3obRVCd5vyO2Wt336zo=;
        b=wsPqFHuDTkn1Igx2beWVetQGuF3buAR8Z9JicO85tewD8iXWOm0SKDChGH3XGMCz01
         E6Fu9RQRAk3EnFEqBR0alHxbjxyutv6I4v9W3+EbMvRLU7377Rq71OcojMZrtjPHXwi+
         a21rAyeHPVTdJFpStnCcxdfuODvpMtDPqJCXlf3YOonmYYkIebi1TOjlUeMJs2AQ7NT/
         mAGclgvuB+elta3wEVdiLTJTqEf6uAyH+byJuN53OQZuho6IhFDt4zoZjHfW5aOG8cP/
         d6z7oWjTW7Paz4uMdM6tMjOccMHR9v8KC35Ls+/1b35FjrcRVe0p+dkE+hMoMAjyhfsq
         mtmA==
X-Forwarded-Encrypted: i=2; AJvYcCWiWaIbm++GeqIzW2bSvkmSsza0zuutPMyZiyeSaaWi3/WuOkeFG1PcZKBTkrGSxSQ/uqjfng==@lfdr.de
X-Gm-Message-State: AOJu0YyLsf3MYSP7+cVbF2mhI4ESRP3grYD59pG86YS7ZzKrwlicch3A
	HWDLMSdJzCFCPOgv9lNRUAHXdGEKDOqmvMKGgkp8gPCG6M8UIsOXaB6i
X-Google-Smtp-Source: AGHT+IE31hP2DQCrV9zg9O5MNtq9qDP5EHbdlBtJAnS3Vs9vQRJVTZXo9hbBQ5SvKcZFNPo1LebJ+A==
X-Received: by 2002:a05:6000:26c8:b0:3b7:94c3:277d with SMTP id ffacd0b85a97d-3b8d9474a6fmr8268244f8f.20.1754335112094;
        Mon, 04 Aug 2025 12:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdTIo9bIyMKOXRmsxCzK4UzpTW6ANj9AfEZdjuH6Qc2iA==
Received: by 2002:a05:6000:2c0b:b0:3b7:89fd:a279 with SMTP id
 ffacd0b85a97d-3b79c3561eels2044003f8f.0.-pod-prod-05-eu; Mon, 04 Aug 2025
 12:18:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQACF5ji87bDMja8GVb7yM89AWQoUxKh8h2+5h+a23cUTW5IoZ1s/QVaqNDqmQGg3ZX+uhLi3DrFw=@googlegroups.com
X-Received: by 2002:a05:6000:26cb:b0:3b7:886b:fb8d with SMTP id ffacd0b85a97d-3b8d94bb42bmr7448173f8f.31.1754335109181;
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754335109; cv=none;
        d=google.com; s=arc-20240605;
        b=dScdYGJUdROVLiKYkOkg+YBGf4XNw6Y7CSmbNmlM3yUNIT4MEDSjUJ0LD6v2g4Bl/F
         ycH9ry6jsCMzjf1IIkTkPAx7wC5AUPm9gDZ/BIe8ndNJoyET7dPV5DFo2HGZzaMLh9cB
         psyMkLttYQvOttXEe1OIoC6dshTMHIUUoru2rWresyEv/6RA7MbrfpVe7vRGBrk9vYM0
         lspoCDKKwQFkzFGcWefunPhOLnt9IwqzkVog/7bAM5TRdkI3KSgQBib85+xatFvIRQSy
         wcKcrg1Yl0I6DN8E2FP8q+nCmEdXUHow8TGnzOEu4zPg5gnDqxY844b2Oy2P6VEsxCVe
         +FDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=toe9nuO+2sDqStO+Lp3ssNFV6aT9Bxci34jiczavffM=;
        fh=/nylxGRH7NF0t+YRuYHOjkceNHIZ9xhaPTr1eRzeM6c=;
        b=ka5pjpyjgJz2b1M9n5rNRnMPfTmS/cMk2WFkMVzygeQI2SLiRllFQpocwY3ZQbANbU
         ytXzfaK01al38x1dLQVzfjtSnx2q4cy847wuwxPG6CONLlQiBsEWCoTh8zyQOb84EDUo
         XUbjeoFXS/82s4GQgo+Dhz/sLpZvk89VxzFeFh8uzZdjxzTP3w+kBE2iByqyj0bcXDwO
         oWyEvHVzzpa2as2GEDqrYu9CxIb5jjgyEf023hWIoe+OfuKxt95cvP/8563wXScOknsU
         Xin0pNYataADZPQ2T5N6syXgT6YpscZY9zTSjt+MqdHztsN1+to2bCDgPXU0VteasyGa
         0i/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fWcp3B8o;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c46a1f6si270308f8f.5.2025.08.04.12.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-459d5ab32d1so20105e9.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4wvir+o0/g/psyWVGD7M2Hy1nffBcyybUWszG7M4a08i6nXFBr5ecYTVGbAoeY6lxjd7P5vCL0u4=@googlegroups.com
X-Gm-Gg: ASbGncs6ieAnx3dZW1ZoCKPbhbyUXxG3tsep2t9yOT81xWPG+VEW4IT6sPZIg8jGgE9
	p40LgYh0gCTmFcL+IfCf3gr6ydUB5MJsTweeduktuvsDb+898lfNUV+bZR7XOW9BEoM43dWDrja
	/3OXe7553scfBwyTaHc2HuE3lMFjUySYZcU9oj+h5NuLyp9Y8Fym6RvDoRgcrBT4lNWdXYTlbT0
	gbhsdN5ALz1tkKq524slNMbsNyodHJbXRq7ORDAnvBZQK1uQW5p0qrTL0HzH+ymypB17fKTwNyR
	+cH8Cn7BWoi2IBCLWFDEWaBAjJlsFaHKGLRVRcgv6YPIH0/AF8fkgBoiX3Nj7/f40ziGAH0HUhN
	kEi/mySvO7Q==
X-Received: by 2002:a05:600c:a212:b0:453:79c3:91d6 with SMTP id 5b1f17b1804b1-459e15e6259mr86595e9.1.1754335108155;
        Mon, 04 Aug 2025 12:18:28 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:2069:2f99:1a0c:3fdd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-459dd85f423sm33348665e9.18.2025.08.04.12.18.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 04 Aug 2025 21:17:07 +0200
Subject: [PATCH early RFC 3/4] kasan: add support for running via KCSAN
 hooks
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250804-kasan-via-kcsan-v1-3-823a6d5b5f84@google.com>
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
In-Reply-To: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
To: Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, 
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1754335100; l=10086;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=y9lF2CD6zfkfZgvGaHoJ5qNs6uZl48FfUZ5qO9DoJ2o=;
 b=YpEZ1lrDao+pTUdAML2s5r2iEEJOkeJ6f219/fzn6kEo/SpJLJ2GwRh4rGUp3e+41ekTkTWfp
 AJPeUtPm+r7BC3tfmqlv05iHKsUBIUTu9ax8GDhAWYWUtkm2aRP0kfA
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fWcp3B8o;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Inserting ASAN and TSAN instrumentation at the same time is not
supported by gcc/clang, and so the kernel currently does not support
enabling KASAN (which uses ASAN) and KCSAN (which uses TSAN) at the same
time.
But luckily, the TSAN hooks provide a large part of what we get from ASAN
hooks; so it is possible to hook up KASAN indirectly through KCSAN.

There are some trade-offs with this - in particular:

 - Since OOB detection for stack and globals relies on ASAN-specific
   redzone creation in the compiler, it won't be available when using
   TSAN instrumentation (because the compiler thinks we only want
   instrumentation for catching UAF).
 - Unlike KASAN, KCSAN does not have instrumentation for functions like
   memcpy(), and this KASAN mode inherits this issue from KCSAN.
 - It makes it impossible to selectively disable KCSAN without also
   disabling KASAN, or the other way around. To be safe, this mode only
   enables KCSAN instrumentation in files in which both KASAN and KCSAN
   are allowed.
   (There are currently some places in the kernel that disable KASAN
   without disabling KCSAN - I think that's probably unintentional, and
   we might want to refactor that at some point such that either KASAN
   and KCSAN are enabled in the same files, or files covered by KCSAN
   are a subset of files covered by KASAN if that's somehow problematic.
   Opting out of every compiler instrumentation individually in makefiles
   seems suboptimal to me.)
 - I expect its performance to be significantly worse than normal KASAN,
   but have not tested that; performance is not really something I care
   about for my usecase.

NOTE: instrument_read() and such call both KASAN and KCSAN, so KASAN
will see duplicate accesses from instrument_read().

Signed-off-by: Jann Horn <jannh@google.com>
---
 include/linux/kasan.h   | 14 ++++++++++++++
 kernel/kcsan/core.c     | 13 +++++++++++++
 lib/Kconfig.kasan       | 17 +++++++++++++++++
 lib/Kconfig.kcsan       |  2 +-
 mm/kasan/kasan.h        | 11 -----------
 mm/kasan/kasan_test_c.c |  4 ++++
 mm/kasan/shadow.c       |  3 ++-
 scripts/Makefile.lib    |  6 +++++-
 8 files changed, 56 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..818c53707e72 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -75,6 +75,20 @@ extern void kasan_enable_current(void);
 /* Disable reporting bugs for current task */
 extern void kasan_disable_current(void);
 
+/**
+ * kasan_check_range - Check memory region, and report if invalid access.
+ * @addr: the accessed address
+ * @size: the accessed size
+ * @write: true if access is a write access
+ * @ret_ip: return address
+ * @return: true if access was valid, false if invalid
+ *
+ * This function is intended for KASAN-internal use and for integration with
+ * KCSAN.
+ */
+bool kasan_check_range(const void *addr, size_t size, bool write,
+				unsigned long ret_ip);
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8a7baf4e332e..aaa9bf0141a8 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -728,6 +728,19 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 	if (unlikely(size == 0))
 		return;
 
+#ifdef CONFIG_KASAN_KCSAN
+	/*
+	 * Use the KCSAN infrastructure to inform KASAN about memory accesses.
+	 * Do this only for real memory access, not for KCSAN assertions - in
+	 * particular, SLUB makes KCSAN assertions that can cross into ASAN
+	 * redzones, which would KASAN think that an OOB access occurred.
+	 */
+	if ((type & KCSAN_ACCESS_ASSERT) == 0) {
+		kasan_check_range((const void *)ptr, size,
+				  (type & (KCSAN_ACCESS_WRITE|KCSAN_ACCESS_COMPOUND)) != 0, ip);
+	}
+#endif
+
 again:
 	/*
 	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..0ee9f2196448 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -133,6 +133,7 @@ choice
 
 config KASAN_OUTLINE
 	bool "Outline instrumentation"
+	depends on !KCSAN
 	help
 	  Makes the compiler insert function calls that check whether the memory
 	  is accessible before each memory access. Slower than KASAN_INLINE, but
@@ -141,17 +142,33 @@ config KASAN_OUTLINE
 config KASAN_INLINE
 	bool "Inline instrumentation"
 	depends on !ARCH_DISABLE_KASAN_INLINE
+	depends on !KCSAN
 	help
 	  Makes the compiler directly insert memory accessibility checks before
 	  each memory access. Faster than KASAN_OUTLINE (gives ~x2 boost for
 	  some workloads), but makes the kernel's .text size much bigger.
 
+config KASAN_KCSAN
+	bool "Piggyback on KCSAN (EXPERIMENTAL)"
+	depends on KASAN_GENERIC
+	depends on KCSAN
+	help
+	  Let KASAN piggyback on KCSAN instrumentation callbacks instead of
+	  using KASAN-specific compiler instrumentation.
+
+	  This limits coverage of KASAN and KCSAN to files that are supported by
+	  *both* KASAN and KCSAN.
+
+	  This is only useful if you want to run both the KASAN and KCSAN
+	  subsystems at the same time.
+
 endchoice
 
 config KASAN_STACK
 	bool "Stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
 	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	depends on !ARCH_DISABLE_KASAN_INLINE
+	depends on !KASAN_KCSAN
 	default y if CC_IS_GCC
 	help
 	  Disables stack instrumentation and thus KASAN's ability to detect
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 609ddfc73de5..86bf8f2da0a8 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -13,7 +13,7 @@ config HAVE_KCSAN_COMPILER
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
 	depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
-	depends on DEBUG_KERNEL && !KASAN
+	depends on DEBUG_KERNEL
 	select CONSTRUCTORS
 	select STACKTRACE
 	help
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e64..ec191ff1fc83 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -335,17 +335,6 @@ static __always_inline bool addr_has_metadata(const void *addr)
 }
 #endif
 
-/**
- * kasan_check_range - Check memory region, and report if invalid access.
- * @addr: the accessed address
- * @size: the accessed size
- * @write: true if access is a write access
- * @ret_ip: return address
- * @return: true if access was valid, false if invalid
- */
-bool kasan_check_range(const void *addr, size_t size, bool write,
-				unsigned long ret_ip);
-
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static __always_inline bool addr_has_metadata(const void *addr)
diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..c4826c67aa33 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -154,6 +154,8 @@ static void kasan_test_exit(struct kunit *test)
 #define KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test) do {		\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))				\
 		break;  /* No compiler instrumentation. */		\
+	if (IS_ENABLED(CONFIG_KASAN_KCSAN))				\
+		kunit_skip((test), "No checked mem*() with KCSAN");	\
 	if (IS_ENABLED(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX))	\
 		break;  /* Should always be instrumented! */		\
 	if (IS_ENABLED(CONFIG_GENERIC_ENTRY))				\
@@ -1453,6 +1455,7 @@ static void kasan_global_oob_right(struct kunit *test)
 
 	/* Only generic mode instruments globals. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_KCSAN);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
@@ -1468,6 +1471,7 @@ static void kasan_global_oob_left(struct kunit *test)
 	 */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_CC_IS_CLANG);
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_KCSAN);
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..136be8e6c98d 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -38,7 +38,8 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
-#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG_GENERIC_ENTRY)
+#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && \
+		!defined(CONFIG_GENERIC_ENTRY) && !defined(CONFIG_KASAN_KCSAN)
 /*
  * CONFIG_GENERIC_ENTRY relies on compiler emitted mem*() calls to not be
  * instrumented. KASAN enabled toolchains should emit __asan_mem*() functions
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 017c9801b6bb..2572fcc0bf50 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -56,10 +56,13 @@ is-kasan-compatible = $(patsubst n%,, \
 	$(KASAN_SANITIZE_$(target-stem).o)$(KASAN_SANITIZE)$(is-kernel-object))
 ifeq ($(CONFIG_KASAN),y)
 ifneq ($(CONFIG_KASAN_HW_TAGS),y)
+# Disable ASAN instrumentation if KASAN is running off the KCSAN hooks.
+ifneq ($(CONFIG_KASAN_KCSAN),y)
 _c_flags += $(if $(is-kasan-compatible), $(CFLAGS_KASAN), $(CFLAGS_KASAN_NOSANITIZE))
 _rust_flags += $(if $(is-kasan-compatible), $(RUSTFLAGS_KASAN))
 endif
 endif
+endif
 
 ifeq ($(CONFIG_KMSAN),y)
 _c_flags += $(if $(patsubst n%,, \
@@ -95,7 +98,8 @@ endif
 is-kcsan-compatible = $(patsubst n%,, \
 	$(KCSAN_SANITIZE_$(target-stem).o)$(KCSAN_SANITIZE)$(is-kernel-object))
 ifeq ($(CONFIG_KCSAN),y)
-_c_flags += $(if $(is-kcsan-compatible), $(CFLAGS_KCSAN))
+enable-kcsan-instr = $(and $(is-kcsan-compatible), $(if $(CONFIG_KASAN_KCSAN),$(is-kasan-compatible),y))
+_c_flags += $(if $(enable-kcsan-instr), $(CFLAGS_KCSAN))
 # Some uninstrumented files provide implied barriers required to avoid false
 # positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
 _c_flags += $(if $(patsubst n%,, \

-- 
2.50.1.565.gc32cd1483b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250804-kasan-via-kcsan-v1-3-823a6d5b5f84%40google.com.
