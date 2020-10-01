Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMOE3H5QKGQERJST6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EE7C280B13
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:46 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id w92sf75752qte.19
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593905; cv=pass;
        d=google.com; s=arc-20160816;
        b=oVAz0VqW68ui6Thzs9ThvSZxUYpCuIyX4DgkGB5vHK+AaLMzrOHgGjc2Pvq94r05hy
         6YNi7NfZ1k0sbOV12g3jeVafR9ubPDHIEGnRGvJ+wwPiEkjiJagRh+39WQxOIHxqLSIe
         AujJllGqfk20YHOFpkCY5rmk2GpfNseofmPMkMK/GTBZRcXL74gnMGbCGMFPqvA9HZ/Z
         0dV3yjWELnSnCG9EyH4VUZ3iiSKkfvIJSHpMgQRr62RGnagu8ZFABpdQna8ZcRA6mjmY
         4kfEuaLAD83mJE7/dh+lauNAGVfGlCb0ULdpyUBpDtFRK68kDisM2ES8yhnNYwED4v9Y
         0fZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jS5n+CD0hKF8akt7+C5pFQM2YsIlDo5ZaFVYEI+VnSQ=;
        b=St2UiVovIMwCwQNSRQPeJLUmYTdUFaSkqYE0rF++1wsy1o/9s4F7YnMWqtSHEmiu+8
         w3M0E63o8nyLN6Vg+MCpjQcwE/sqLctHd2ULM4RwbGAeAmtqJKKY2vAUgV6evyI0KZSQ
         my4kibqOtAneLidwI6XgRu/kKWc8DCDSaL1KZy/IyOWTOINs/eHVr26oeFWk4MCI+DkD
         kBz+6RA4AJsbOnZLDckqtmvkSjLZHYvQxvm7x5D13YWcscZlfkEMnzM300qiKWY8gUh9
         68VZDpp30CZ6kj/DFzbEnpoYC6K5rnynws2JA53dKmWos0pzd93+s7AmaAGM0R64vQAD
         ycbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TW/FPr4b";
       spf=pass (google.com: domain of 3mgj2xwokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MGJ2XwoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jS5n+CD0hKF8akt7+C5pFQM2YsIlDo5ZaFVYEI+VnSQ=;
        b=rL5FMEQ+g+r0ODZjVJ8JyX8zEMmX6+fa4Rcls+yOb3kejaMwf7YblLKpWPfmxLs+Nd
         HQd3Ia9h+c992YPKcb3pJ4BRcFO0AVKbaEfq3uPwRK6sfZyYB8zr93PiYHdBIOaI+8K5
         5iVQvvRMbw426pSW63rl+UrqyHwWCevQZRtaKwy5G/kBx8SU/WK82n0aX7b80KE1QFJ0
         PDp/Ya2SVABybYJmQGqMtYj7ggIW629St1av5oCFFHdI1dYDaqVqnpWYZ6LnBkmeODfa
         ompXWHcr38O3xx/lxm1JCpGeNR7JK1A7QsfGBP45UbxQ3r3ztDyZ5xhrCYpMt/E+cxU7
         hlvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jS5n+CD0hKF8akt7+C5pFQM2YsIlDo5ZaFVYEI+VnSQ=;
        b=t5zWBYeeTaXwfkaxAs7H06qKj5YYWw1fAcCCUzmxtv7aZC+ADEbC6I+5Jy8ZjnV4oj
         u7AzLdgVTltR+3AFZLAfxcSIRveO6bV9Fz2sWu/1O4Y0BpXFPYp2+f7jWJP9lwhuAiA0
         E56S+8Wmw9Ddpkeo/yG0dS2FQKYiDEpZ2wyY05eJB2bUnGkyqfOZiSsM2GPHptGez9CU
         x86AQbaHVrTsW1SJJhKnBMCRnK3orkyi8/G/RscAvHIuVAPR5S2KWiPJ4185hirOZFBr
         fhS/1M2TBElf92l09WHklhJXUHiUjbaEbn7bxcl/Zc+S1o7PQ8jO5IDFJwjXXeuYD9ON
         V/jg==
X-Gm-Message-State: AOAM533LC/SgCY4wFihB8Vb4MnAQYTFVBYpcxJAUWfaylEKc3FpSPRoR
	OOc+tuU+TI//C6NGf27GKow=
X-Google-Smtp-Source: ABdhPJzUGEzD2aeEu2k7t/Z6b4YPdcltYt4XFAuk1Pjob3dtjShKfCJ8iZq1IKO3BQ5Y+RND5ETGog==
X-Received: by 2002:a37:a654:: with SMTP id p81mr9890678qke.255.1601593905640;
        Thu, 01 Oct 2020 16:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:8f7:: with SMTP id y52ls2660293qth.10.gmail; Thu, 01 Oct
 2020 16:11:45 -0700 (PDT)
X-Received: by 2002:aed:2703:: with SMTP id n3mr10439102qtd.235.1601593905162;
        Thu, 01 Oct 2020 16:11:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593905; cv=none;
        d=google.com; s=arc-20160816;
        b=ZGNHiHVZnUio9J6acjq1yeDn2ZIF12jft0vl//3p3UHcpNIOtqyRE9+sP2hEDw5TJB
         iNHxb9CULBwTp28KiIKGIxwQ5D/h+ZCWlWGFlwpFJQBdOydFYC7n6tp8/xKrFlNmb1AR
         7NUgrEtz9o7Y3pHyr7G8n80uAdhNayu2h/KuhyJtPr/IgKZG9rABDwbXL88h8epwdYaB
         h5YkL8I+/Q0g2qgh6OzT2Dq8WTAcg+D0/z/evP5yKVC8OZ7C1/OjCzwyQ1pvCyJFCjLP
         VO//kkhv9GOagD0vENR1IQnVPfdbDZkQRXvry/IQLg/T6iZCf0fIHJWthn25Be77lomX
         lOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=y9SVZYHYHpZATyjbHTG3PyiS7DYM984ggxAJRWK49Xc=;
        b=03KsbbNKyqvWcr63FZZTsFT1peFWOy7jwGZb0lX7qe5VE7l/G20xinNFvLQPGgecUN
         XIVNZETfhREqROIGkkmNRMJiB/yz01qE3uBjO730vcrKr8nvT5PBPZUoDsHA6iIB+Ulv
         ESSCAaI98hmNZwudwKZBauemLVF64xhPpWzOGxKt7OiM+IoRRS8CiIp1ZpBwazWVD9ar
         YtRKYucd4olRxKWBQ5byIwbR5bLAeA6RgyRsB5/2kQoWTjQNxL0GaYyfVBCeRReJbGmx
         pXHSm34QFpJwZzwn6AE2ai9ALW7UsaMZFa97zPY7D5BLL7BKju82yfC5+gGm8WT8aJM1
         VzuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="TW/FPr4b";
       spf=pass (google.com: domain of 3mgj2xwokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MGJ2XwoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id x13si501895qtp.0.2020.10.01.16.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mgj2xwokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id y17so59931qky.0
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:57cc:: with SMTP id
 y12mr10157533qvx.48.1601593904745; Thu, 01 Oct 2020 16:11:44 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:26 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <b0873fbe914dc46cae079acc9687d914792d850a.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 25/39] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="TW/FPr4b";       spf=pass
 (google.com: domain of 3mgj2xwokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3MGJ2XwoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 18 ++++++++++++++++++
 2 files changed, 26 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index e424fc3a68cb..268a3b6cebd2 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,6 +231,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 50b59c8f8be2..9c73f324e3ce 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -241,6 +241,24 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define init_tags(max_tag)			arch_init_tags(max_tag)
+#define get_random_tag()			arch_get_random_tag()
+#define get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0873fbe914dc46cae079acc9687d914792d850a.1601593784.git.andreyknvl%40google.com.
