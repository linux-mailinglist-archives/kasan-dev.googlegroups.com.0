Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHFP5T6AKGQEUWXD3QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3261E29F50E
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:25 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id f4sf1677043ljn.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999644; cv=pass;
        d=google.com; s=arc-20160816;
        b=JD0IUnQ2xAIFLBzYIGQ55p6Q0o9W/YE5bo95rsmYIM+9r9Yg1F5kLCl8Ur1+HiobEe
         DEhS0Numep8HHD+4ZLuBtDctgXJdlVtYN8+h470wiIHj7j/fxczEL3JMEIB9WB1BGTaH
         PXkpgiN3plVbEPbwQ9Ks2w5xQm0Aq2wKwFh867E9pI7UdAFhVgkoWbITVz6Ee/LnRSc3
         Ob2gJe10oquKtBBHqiUVOPRMDYBkzi7GzF4/vCHw8b7/n5s/i7crM7WRzllbO2L2tNCo
         2QiISbYxaY+aZxms+AomsgfSqKD6iJH8ZOjcLX/uLTc6wiO19maDPAlNSraVGuPZz+c7
         Kv7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=amBv8k79aQZxVm75eHF0+8rqm27zX9VQPwri3OMQzZk=;
        b=S5U6iS7y/u3deEdrVfkjUutMWcbGRNPQ87TYwpFmfqTt34WVTNtHmXjw2LPLNcFvm6
         /CwrrHVzIUnS4O86kREdZ6LgG+dyKmexza9Kbc3s4cVilv2q2ygwTEbhZ/hjDVsFn4Y4
         z1BEAxJ5jGLOQF0+HjQRYYEQfPhVOHg0pkD5foPCIWN3kE3Wl7Mnm7CyAMp1EmWqR57n
         Y8FRk7XdHD7n0EzgJKbJzziopuyKRKNQ848qX+KTlYQIvB0Y7ednFThD+o7TjYp9c4RV
         D+kAQ/kZ9nK8KyZ3beBSY2OqrMeNcijvGuyHVjHA9V9+IssqosXhzaxbwMSZajYTCAng
         tNOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bAn7xcpe;
       spf=pass (google.com: domain of 3mxebxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mxebXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=amBv8k79aQZxVm75eHF0+8rqm27zX9VQPwri3OMQzZk=;
        b=NUhbuf+eGskaZ4LHi1fjsgspmgWGtVg/vlrN5kz6bvw9qzmfc1J/7bx4eWHTkciGL0
         S8YfDbH2SAyR7r6kJfUZRjG9Y6ldKTm3Fh9aI7G3qqrNUlQEjVYD+/WAUAwX+EVOT1FV
         5gTG1+vdKu8VRqLHVIgx5EHX+ppmLC4xC1764w79QoI3Zjzz+y3iivNPf4RVSV8M7pLU
         y39JcCFb3JM633hJkd5DFZofEg9u+duAiqjOqvf7s2VM9MR6TyryBZXSOAGG5mjMfL+U
         hf5dqMrnO1BccUPMw0dPtqvQ7s9SZP6ee1cHMSfQ58kScjmCd+Gj1AOqtsztHmTu5nsf
         9NKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=amBv8k79aQZxVm75eHF0+8rqm27zX9VQPwri3OMQzZk=;
        b=uYhQS+4++D9neDd3pk6BGSIY640W3Cs1+plpgqSB0HJ++XBogG7HI/KWbHAaOjL/DO
         hYXmwEOZGN6psq7F17Ir3mQbj0pgtPXvpryaLmQ+/mb4wSQm8hZei50O9MfGgDIArFnh
         GnMuYUuLwaXb7Wm/skHbmBQmNgmXvb0WjxRSGdXjrjZcJ+LiPdVm4zL8jn7QDRJeseJf
         87TxH1sDeGLC6OuCgYKn2cJAV7t04XdrQ/EFI2Q6HqENWEOrQo5QyS17Qci3e2DBDtyO
         b8jqvWbi3pO/581rttGN0VqQqe8PgkFLk/aXpUJTMjc7gz2wF+7fdAMu2hqaYJTpVLR8
         PfFw==
X-Gm-Message-State: AOAM532Q1tMGN2hqaslGqOUlyk5urHYkRT2enzRcI/+H+M+X8qEYl2i8
	gEqqrscH5xGLtqseKD4x5WI=
X-Google-Smtp-Source: ABdhPJyL5rzxpWcGanAvj4dkF37UO49B2C1tmbzA0ODk5/6sU13kGhC9JKDJqhF6iZz0qIhI//UETQ==
X-Received: by 2002:a05:6512:519:: with SMTP id o25mr2349532lfb.379.1603999644711;
        Thu, 29 Oct 2020 12:27:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2397184lff.1.gmail; Thu, 29 Oct
 2020 12:27:23 -0700 (PDT)
X-Received: by 2002:a19:81ca:: with SMTP id c193mr147029lfd.449.1603999643776;
        Thu, 29 Oct 2020 12:27:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999643; cv=none;
        d=google.com; s=arc-20160816;
        b=L7SifdM5QQro5i63KjxyRpmy+1+vyTJeFx09CXK99RCF6HXhD74c8+JSvw+Y0wl4+l
         WG40+IwRDiMTI6D+K/anu9dd79RSkOEKCYRyrLDieG/B0q04lYTp8dNIJVLdPe1EEfWB
         5pzfSPEkGyI1bC/h6k69K3X+rQFodAtfOveRRbpCCNIbKPxN7L5JJeNXKbFHiRiEDVgj
         CQFStKQkNoo7OG4L69sDd438eg5XorcdIsOdFATLpPIoEZXBMwtBzyhggaM+rtmPCHOQ
         ogYk1aub/MH3W0piUQaG+3KkV9WgGZ2RahFiIYlpmpnLxt7cJPp2QL/ko4Bzze48x+xs
         uE2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VDtcX23y6dPJZ06sfD07OvqXxdMGED0dxQgWlB1yXT4=;
        b=OF8AGJEbv6v2iBZ/PRj5uzN2lfT+vZi/ASCcokUGTh15WhqqZT9AdoJmL8CXrAzWXl
         RaFcREMDh/0FNXDtc9zi5GxM/IuLXrzuNVdugIblyso3vExNrvkhnbfpUVwzqrRKhh7p
         VjfptUhztZkDCDCWnXvb3FHV3IiD9fIMar3PSwX2ksOoKmgyvMibAPLK9V2LcyHF+H27
         HXu/LgFLPM3WHumA4VuqpOtKzVpwxDfsaeVlEvuNvjWoOipc4uySxeZv2Y481EqrKvNG
         UzsPuIeETwxrtWdyVQm+8LzTwf854hFv60WP/1HlCIOvh5OCiUIW2rr13Y6ST/Fm3lt/
         ADIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bAn7xcpe;
       spf=pass (google.com: domain of 3mxebxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mxebXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x20si124862lfq.12.2020.10.29.12.27.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mxebxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f11so1673361wro.15
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:23 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:26c3:: with SMTP id
 m186mr711801wmm.115.1603999643083; Thu, 29 Oct 2020 12:27:23 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:52 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <9dbafd4d95545ea4fce7310975cb440f77042d25.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 31/40] kasan: introduce CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bAn7xcpe;       spf=pass
 (google.com: domain of 3mxebxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mxebXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

This patch adds a configuration option for a new KASAN mode called
hardware tag-based KASAN. This mode uses the memory tagging approach
like the software tag-based mode, but relies on arm64 Memory Tagging
Extension feature for tag management and access checking.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
---
 lib/Kconfig.kasan | 58 +++++++++++++++++++++++++++++++++--------------
 1 file changed, 41 insertions(+), 17 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index ec59a0e26d09..e5f27ec8b254 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
 config HAVE_ARCH_KASAN_SW_TAGS
 	bool
 
-config	HAVE_ARCH_KASAN_VMALLOC
+config HAVE_ARCH_KASAN_HW_TAGS
+	bool
+
+config HAVE_ARCH_KASAN_VMALLOC
 	bool
 
 config CC_HAS_KASAN_GENERIC
@@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
 
 menuconfig KASAN
 	bool "KASAN: runtime memory debugger"
-	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
-		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
+	depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
+		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
+		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
+		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
-	select CONSTRUCTORS
 	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
@@ -37,18 +40,24 @@ choice
 	prompt "KASAN mode"
 	default KASAN_GENERIC
 	help
-	  KASAN has two modes: generic KASAN (similar to userspace ASan,
-	  x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
-	  software tag-based KASAN (a version based on software memory
-	  tagging, arm64 only, similar to userspace HWASan, enabled with
-	  CONFIG_KASAN_SW_TAGS).
+	  KASAN has three modes:
+	  1. generic KASAN (similar to userspace ASan,
+	     x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
+	  2. software tag-based KASAN (arm64 only, based on software
+	     memory tagging (similar to userspace HWASan), enabled with
+	     CONFIG_KASAN_SW_TAGS), and
+	  3. hardware tag-based KASAN (arm64 only, based on hardware
+	     memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
+
+	  All KASAN modes are strictly debugging features.
 
-	  Both generic and tag-based KASAN are strictly debugging features.
+	  For better error reports enable CONFIG_STACKTRACE.
 
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables generic KASAN mode.
 
@@ -61,8 +70,6 @@ config KASAN_GENERIC
 	  and introduces an overhead of ~x1.5 for the rest of the allocations.
 	  The performance slowdown is ~x3.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
@@ -70,11 +77,15 @@ config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
 	help
 	  Enables software tag-based KASAN mode.
 
-	  This mode requires Top Byte Ignore support by the CPU and therefore
-	  is only supported for arm64. This mode requires Clang.
+	  This mode require software memory tagging support in the form of
+	  HWASan-like compiler instrumentation.
+
+	  Currently this mode is only implemented for arm64 CPUs and relies on
+	  Top Byte Ignore. This mode requires Clang.
 
 	  This mode consumes about 1/16th of available memory at kernel start
 	  and introduces an overhead of ~20% for the rest of the allocations.
@@ -82,15 +93,27 @@ config KASAN_SW_TAGS
 	  casting and comparison, as it embeds tags into the top byte of each
 	  pointer.
 
-	  For better error detection enable CONFIG_STACKTRACE.
-
 	  Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
 	  (the resulting kernel does not boot).
 
+config KASAN_HW_TAGS
+	bool "Hardware tag-based mode"
+	depends on HAVE_ARCH_KASAN_HW_TAGS
+	depends on SLUB
+	help
+	  Enables hardware tag-based KASAN mode.
+
+	  This mode requires hardware memory tagging support, and can be used
+	  by any architecture that provides it.
+
+	  Currently this mode is only implemented for arm64 CPUs starting from
+	  ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
+
 endchoice
 
 choice
 	prompt "Instrumentation type"
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	default KASAN_OUTLINE
 
 config KASAN_OUTLINE
@@ -114,6 +137,7 @@ endchoice
 
 config KASAN_STACK_ENABLE
 	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
+	depends on KASAN_GENERIC || KASAN_SW_TAGS
 	help
 	  The LLVM stack address sanitizer has a know problem that
 	  causes excessive stack usage in a lot of functions, see
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9dbafd4d95545ea4fce7310975cb440f77042d25.1603999489.git.andreyknvl%40google.com.
