Return-Path: <kasan-dev+bncBCMMDDFSWYCBBPE7RG6QMGQEVNGYBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 461F0A27880
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:34:55 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-21dcc9f3c8asf90928885ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:34:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690492; cv=pass;
        d=google.com; s=arc-20240605;
        b=YoBF7WnNteNJMKudRSO6Cw6aiOEo69paQv/CLWbmn/tY3hqi00wokwgXXp7ESrO5YP
         cR8Tj8cf4N068xVGGi63Y+a0FnBNJZS4MWsMC9ImSJQfB+TimFSS7HYVzUB9faPojhP5
         Ja0MmUgbFHiy1lBlngxxETkgaQUxot3vXfDE82O9eg6hhnt54InKVeNSjCIANr8ouF3o
         R+btVLlBlFP1rYakws/WQU938Q2GYuafwP2ZJYhNYqdt9ZhU3VQO5SS9d2/rP+UhL0bC
         PtPrInsTL2/ctbe7eDTTbMhvrdZROIAfH+EQN8ElfTYfbUs+MR6n9VxTAM1NyYPd/94W
         RUDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7GQa9d/JwgBJoZbSyfZQQreWdnrSwxviBHqi+RhLqCA=;
        fh=Nk2RSXEKWqkvbpUUfOacG/7psQA0xJCasEeYUcMHqSk=;
        b=cKa3Hin9cFIjva6tPPQrTH4Xz0c2vn0oqCwu4RO6vjBLEz64e2ny6McNgd4oQLvpv0
         STbA3zfEeYCitB8ElMl+USM1U8dErN6GgNmMtbs1Kb83CWb/1K5HsPZ4RlP9fvMrLePD
         dmMvDUHVDN4lE40SGXRSDphmP9I61z5ADxXxRtgnwxHfjPv/BVcY/3+YQR3hyyvsQHnp
         CSEHO3savgHZqJjSiCcZ66HoWDSUHD8tyRxA5peIPYaSUr8t4utkNKP8WMLVEQxWHG7Y
         idoeVKBpdHg3f/aqMWJnamFk75yAn6wpqhWlVaZ3Q96VrCVa+NbiMf1utfNKIvUFvwPw
         VRNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eR9zw6tE;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690492; x=1739295292; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7GQa9d/JwgBJoZbSyfZQQreWdnrSwxviBHqi+RhLqCA=;
        b=dxvJ84qn2Hi+j+jlPR8eJ3R65735xFDiWiR+YepfCVAWGb+GmNmTYcYMS18o8K1PND
         ZxKs317hqrc7AEYMcoL+hICEElT657os1hTp9+r0GnB8jal2QhM71SbsabVFzoNcxy65
         55Jb+2bGc8Dfnud4DswgjxpbZad4Gp75JVRQ0R8wWOvXvBCro94MgfBqapjAllkF/fou
         pdqctUJW8RUVxrn6Ue2XsCxrPaOX26jWeLbnzXs6gmkjPFilD5lxWMEEcwUqLjnUS3Kd
         ILWEwS+mnnfyqhgr2uwIFc+FjCts526Cn4/d/Z9aZfdOTX2hH62vFmevIFY1JHLdsX40
         YJ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690492; x=1739295292;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7GQa9d/JwgBJoZbSyfZQQreWdnrSwxviBHqi+RhLqCA=;
        b=Gvp/O7FJSB2IMShkT8ncivpmMazaIg2B2+4v7tgfy0Ej47Nbf/KkeOKt6oWVdAaZ72
         VjXO3HzgKHfhogm5vd8UBFQfE05/XL3HlhA4D5P+HpZ42TcAmRzX4NDSVsbNA0ohAZ26
         ZbUlk4yG2+GQoF5bRU8yKFmG9lUtH0QSV3Z+9Bqu2X21zIMPomhknTNfcAPCsg+zu530
         HznTrp0bSZMdJ50K9Q27g7TqH6ksHXJozU3opkMRZgH+j5wJm+4bLlVfK8t8dKVJ4wdH
         VIDxh8mzrFzcFrpa0OiLiC+EQzfXt2E0t1+SYhFm25WRMzS5VxEL0NzrfQdqZyYcM4wf
         0k1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnWIMoFeWOCklROoK8VJlEWzSxawxemUwkAFm5IxYhiy+CQd0j6t2BrKFZmSx1ysSBwvSwTA==@lfdr.de
X-Gm-Message-State: AOJu0YzD+WxqLnea0yn6nPHWnSkU9z3K/CIV0FvbxIe9siHTrMiQ+SxB
	aYhEHKgsWdFHaaGdgsBPTf8YGw+FejxsmCVtdfDhy3YwPHcnQcyk
X-Google-Smtp-Source: AGHT+IFErOUQbK0+Eirptm/Nhay2GnSZLLlkXvoPg7mh36N+OigKZP/oytNRlT5sdu4HBRrn4jlTnQ==
X-Received: by 2002:a05:6a21:b97:b0:1e8:bff6:8356 with SMTP id adf61e73a8af0-1ed7a63ceb5mr42690850637.20.1738690492408;
        Tue, 04 Feb 2025 09:34:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:acb:b0:725:4630:50f1 with SMTP id
 d2e1a72fcca58-73033b21724ls82168b3a.0.-pod-prod-02-us; Tue, 04 Feb 2025
 09:34:51 -0800 (PST)
X-Received: by 2002:a05:6a00:8581:b0:730:29ac:b687 with SMTP id d2e1a72fcca58-73029acb719mr4041692b3a.23.1738690491118;
        Tue, 04 Feb 2025 09:34:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690491; cv=none;
        d=google.com; s=arc-20240605;
        b=Ft3WIF5PMX1uV8pDu8M/eWwRBwxPM/af8Mg3J2Q7V/WFXv7ous4dFPdoDzgijEHZch
         uYfWj0GhSZL90djDm3pTnUMhp9kx35OOMJkp+5g4bJdENvNbcb2fOJUdzIycRidtwzhu
         gk5eiYhfpTIrHhmuV83aToc2jJgnXxhRfrCBqi1V7uEWvaJHoPMVFkjyaIpgacxQbh+w
         6VblQQG1GUl8KL3ZbT/QPwGd8knZ1jBdZgy1X0u6isRkFCzH5LTBFzu5x3U9DFtn+43k
         g/HQiiv34EagOdP9PfkQTs+x6bqTNVtdf39hqxsRR8wXOyyJ6LQg7lI5BE6B4mE9fqKh
         /ysw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ygTPRb3ywRhSzYmq1+08ZzVsKFhrG8jkildWvsOZQlE=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=VhOVAqMGu58mU5Alvn0mkFt6cYEDpc6uhlgiU1aHWyGlsPLH1gvu0rfj2f1+R0cD8V
         X+nCxwOy90u0JSLY13NEyvKmBR3GnGOk1tHyvLPRqVLjOsSUcGILUqovhnYsTdixF6sk
         gcMKosl+G0rLY1No7EmX2F/bkqGJQw+3aJPeWzRQlH5EiEAK542E9fHJQfSDD+vkgqmW
         cHVDyVLHKuBKHRzYpqI3GtLRh4X54Xr0Be3jz4wZCr4qqc+YvbAEhyybTlwpSuGZMn00
         /k5RnOdW5SLpxhlw//bhcWrhwIhxJn3/+N4Z7hIWsdQ98sNtKCxU9bdkAMl/If8tQdXv
         jykg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eR9zw6tE;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-72fe6967ba5si550726b3a.5.2025.02.04.09.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:34:51 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: fXaCVSrnTECcpA1bDTXF7Q==
X-CSE-MsgGUID: k/WObjbySGOT4NYhdU3/aw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930319"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930319"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:34:49 -0800
X-CSE-ConnectionGUID: hsBgrPAEQzS1k8EGLwQyaA==
X-CSE-MsgGUID: MO+fRiNSTeubDAn41XyOaA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866143"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:34:37 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: luto@kernel.org,
	xin@zytor.com,
	kirill.shutemov@linux.intel.com,
	palmer@dabbelt.com,
	tj@kernel.org,
	andreyknvl@gmail.com,
	brgerst@gmail.com,
	ardb@kernel.org,
	dave.hansen@linux.intel.com,
	jgross@suse.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	arnd@arndb.de,
	corbet@lwn.net,
	maciej.wieczor-retman@intel.com,
	dvyukov@google.com,
	richard.weiyang@gmail.com,
	ytcoode@gmail.com,
	tglx@linutronix.de,
	hpa@zytor.com,
	seanjc@google.com,
	paul.walmsley@sifive.com,
	aou@eecs.berkeley.edu,
	justinstitt@google.com,
	jason.andryuk@amd.com,
	glider@google.com,
	ubizjak@gmail.com,
	jannh@google.com,
	bhe@redhat.com,
	vincenzo.frascino@arm.com,
	rafael.j.wysocki@intel.com,
	ndesaulniers@google.com,
	mingo@redhat.com,
	catalin.marinas@arm.com,
	junichi.nomura@nec.com,
	nathan@kernel.org,
	ryabinin.a.a@gmail.com,
	dennis@kernel.org,
	bp@alien8.de,
	kevinloughlin@google.com,
	morbo@google.com,
	dan.j.williams@intel.com,
	julian.stecklina@cyberus-technology.de,
	peterz@infradead.org,
	cl@linux.com,
	kees@kernel.org
Cc: kasan-dev@googlegroups.com,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org
Subject: [PATCH 01/15] kasan: Allocation enhancement for dense tag-based mode
Date: Tue,  4 Feb 2025 18:33:42 +0100
Message-ID: <808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=eR9zw6tE;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Tag-based KASAN (on arm64) works by generating a random 8-bit tag and
putting it in both the top byte of the pointer (that points to the
allocated memory) and into all bytes of shadow memory that correspond to
the chunk of allocated regular memory. Each byte of shadow memory covers
a 16 byte chunk of allocated memory - a value called KASAN granularity.
This means that out-of-bounds memory accesses that happen inside the 16
bytes can't be caught.

The dense mode offers reducing the tag width from 8 to 4 bits and
storing two tags in one byte of shadow memory - one in the upper 4 bits
of the byte and one in the lower 4. This way one byte of shadow memory
can cover 32 bytes of allocated memory while still keeping the "16 bytes
per one tag" granularity. The lower 4 bits of each shadow byte map bytes
of memory with offsets 0-15 and the upper 4 bits map offsets 16-31.

Example:
The example below shows how the shadow memory looks like after
allocating 48 bytes of memory in both normal tag-based mode and the
dense mode. The contents of shadow memory are overlaid onto address
offsets that they relate to in the allocated kernel memory. Each cell
|    | symbolizes one byte of shadow memory.

= The regular tag based mode:
- Randomly generated 8-bit tag equals 0xAB.
- 0xFE is the tag that symbolizes unallocated memory.

Shadow memory contents:           |  0xAB  |  0xAB  |  0xAB  |  0xFE  |
Shadow memory address offsets:    0        1        2        3        4
Allocated memory address offsets: 0        16       32       48       64

= The dense tag based mode:
- Randomly generated 4-bit tag equals 0xC.
- 0xE is the tag that symbolizes unallocated memory.

Shadow memory contents:           |0xC 0xC |0xC 0xE |0xE 0xE |0xE 0xE |
Shadow memory address offsets:    0        1        2        3        4
Allocated memory address offsets: 0        32       64       96       128

Add a new config option and defines that can override the standard
system of one tag per one shadow byte.

Add alternative version of the kasan_poison() that deals with tags not
being aligned to byte size in shadow memory.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 include/linux/kasan.h | 18 ++++++++++++++++++
 lib/Kconfig.kasan     | 21 +++++++++++++++++++++
 mm/kasan/kasan.h      |  4 +---
 mm/kasan/shadow.c     | 33 ++++++++++++++++++++++++++++++---
 4 files changed, 70 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 03b440658817..ea0f5acd875b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -35,6 +35,24 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
 /* Software KASAN implementations use shadow memory. */
 
+#ifdef CONFIG_KASAN_SW_TAGS_DENSE
+#define KASAN_GRANULE_SHIFT	(KASAN_SHADOW_SCALE_SHIFT - 1)
+#define KASAN_SHADOW_SCALE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+static inline u8 kasan_dense_tag(u8 tag)
+{
+	return (tag << KASAN_TAG_WIDTH | tag);
+}
+#else
+#define KASAN_GRANULE_SHIFT	KASAN_SHADOW_SCALE_SHIFT
+#define KASAN_SHADOW_SCALE_SIZE	(1UL << KASAN_GRANULE_SHIFT)
+static inline u8 kasan_dense_tag(u8 tag)
+{
+	return tag;
+}
+#endif
+
+#define KASAN_GRANULE_SIZE	(1UL << KASAN_GRANULE_SHIFT)
+
 #ifdef CONFIG_KASAN_SW_TAGS
 /* This matches KASAN_TAG_INVALID. */
 #define KASAN_SHADOW_INIT 0xFE
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 98016e137b7f..d08b4e9bf477 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -19,6 +19,13 @@ config ARCH_DISABLE_KASAN_INLINE
 	  Disables both inline and stack instrumentation. Selected by
 	  architectures that do not support these instrumentation types.
 
+config ARCH_HAS_KASAN_SW_TAGS_DENSE
+	bool
+	help
+	  Enables option to compile tag-based KASAN with densely packed tags -
+	  two 4-bit tags per one byte of shadow memory. Set on architectures
+	  that have 4-bit tag macros.
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
@@ -223,4 +230,18 @@ config KASAN_EXTRA_INFO
 	  boot parameter, it will add 8 * stack_ring_size bytes of additional
 	  memory consumption.
 
+config KASAN_SW_TAGS_DENSE
+	bool "Two 4-bit tags in one shadow memory byte"
+	depends on KASAN_SW_TAGS
+	depends on ARCH_HAS_KASAN_SW_TAGS_DENSE
+	help
+	  Enables packing two tags into one shadow byte to half the memory usage
+	  compared to normal tag-based mode.
+
+	  After setting this option, tag width macro is set to 4 and size macros
+	  are adjusted based on used KASAN_SHADOW_SCALE_SHIFT.
+
+	  ARCH_HAS_KASAN_SW_TAGS_DENSE is needed for this option since the
+	  special tag macros need to be properly set for 4-bit wide tags.
+
 endif # KASAN
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 72da5ddcceaa..0e04c5e2c405 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -128,9 +128,7 @@ static inline bool kasan_requires_meta(void)
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
-#else
+#ifdef CONFIG_KASAN_HW_TAGS
 #include <asm/mte-kasan.h>
 #define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
 #endif
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d6210ca48dda..368503f54b87 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -123,7 +123,8 @@ EXPORT_SYMBOL(__hwasan_memcpy);
 
 void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
-	void *shadow_start, *shadow_end;
+	u8 *shadow_start, *shadow_end, *shadow_start_aligned, *shadow_end_aligned, tag;
+	u64 addr64, addr_start_aligned, addr_end_aligned;
 
 	if (!kasan_arch_is_ready())
 		return;
@@ -134,16 +135,42 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 	 * addresses to this function.
 	 */
 	addr = kasan_reset_tag(addr);
+	addr64 = (u64)addr;
 
-	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
+	if (WARN_ON(addr64 & KASAN_GRANULE_MASK))
 		return;
 	if (WARN_ON(size & KASAN_GRANULE_MASK))
 		return;
 
 	shadow_start = kasan_mem_to_shadow(addr);
 	shadow_end = kasan_mem_to_shadow(addr + size);
+	addr_start_aligned = round_up(addr64, KASAN_SHADOW_SCALE_SIZE);
+	addr_end_aligned = round_down(addr64 + size, KASAN_SHADOW_SCALE_SIZE);
+	shadow_start_aligned = kasan_mem_to_shadow((void *)addr_start_aligned);
+	shadow_end_aligned = kasan_mem_to_shadow((void *)addr_end_aligned);
+
+	/* If size is empty just return. */
+	if (!size)
+		return;
 
-	__memset(shadow_start, value, shadow_end - shadow_start);
+	/* Memset the first unaligned tag in shadow memory. */
+	if (addr64 % KASAN_SHADOW_SCALE_SIZE) {
+		tag = *shadow_start & KASAN_TAG_MASK;
+		tag |= value << KASAN_TAG_WIDTH;
+		*shadow_start = tag;
+	}
+
+	/* Memset the middle aligned part in shadow memory. */
+	tag = kasan_dense_tag(value);
+	__memset(shadow_start_aligned, tag, shadow_end_aligned - shadow_start_aligned);
+
+	/* Memset the last unaligned tag in shadow memory. */
+	if ((addr64 + size) % KASAN_SHADOW_SCALE_SIZE) {
+		tag = KASAN_TAG_MASK << KASAN_TAG_WIDTH;
+		tag &= *shadow_end;
+		tag |= value;
+		*shadow_end = tag;
+	}
 }
 EXPORT_SYMBOL_GPL(kasan_poison);
 
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman%40intel.com.
