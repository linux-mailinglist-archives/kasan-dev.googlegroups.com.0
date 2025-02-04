Return-Path: <kasan-dev+bncBCMMDDFSWYCBB6U7RG6QMGQEQ5PHLEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C0AFA27890
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:35:58 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2163dc0f689sf103721305ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:35:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690557; cv=pass;
        d=google.com; s=arc-20240605;
        b=VD9I9X+rS/kkLnJH2gxbtFwDUq/ONXcD3ZeVMQ+XNo7yur+pu8NGapOJm4BGl8oifv
         T45gkp9ONVQ60kBvEzZN/8cWAu0xuc1L6pISanMI14d7b9+YP0sXXLAOO0LR20KooqmX
         BksO0tIqwJYmkp7awAYLyReEWz3RYgpuIVnUZpiJFYIYMZl0c/BTvIgPSxHtp27XWXtM
         SQrb6sqBzVm0zyTUuv6JixqcNBDWf9U4c4AE1xbnDLhUWAg/crCp5FBkVp1DPiKhRMxH
         BI8flKGxwaqWA8gcsWCD7bze9lubAJNbsb4Zmh4+E9ZHpBecA7vU8RT6VReIGroLR37P
         /fYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bsR4bD/cuKUSC15fQmornQgXiDLv1vto+etrzpgvw+I=;
        fh=Rr0MrcQ127nbT+40L9S4CZix+dE4+1q5jfuFR9btk+I=;
        b=jUmEHspPoxQ4Wf4MYbFlwWMy6EKlExDBlE3jnwBUM++OFzJF1PJe+Ie96L5gv11E86
         In1yd+HIpRdX6ucHzOdZ/LmfFlsWr0JuXUffLtFE/sywf4BjoCPadmoHntQDMkYyF5UP
         Ap57nhIituZ6WQ1P9nkv/GWy7hL+K2aNr2pI1oDRGi6k+6IHAczet1W7Mr6NWE4iSnxN
         gooGYRPitRVZ1yP4jpWPQXJIVRIoadOt+q17s1iyyD6IvHDgGqtU5ITFGEtMkg+xFC/X
         pxp4FwGZAS6GiZ6qwrIi7XrMW9mx3BiTu9tVFFNra+g23jXpgHn3yowzsYy7M6hAtg5z
         SZBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KbwpkOKU;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690557; x=1739295357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bsR4bD/cuKUSC15fQmornQgXiDLv1vto+etrzpgvw+I=;
        b=ISRjVlvS8HEmkkm0ljT3Hc+XoplvEeCxe1QyfpJ/Mbkl/rRBEeFptQH8Rn6xKdxTTB
         1SCZgIHjANt35C3dgTLQLnuJTZa/SlmArneft2X3br0x9KGCGAsG7DVLfWL9tmQfgxEt
         YYAa95rp6/g2SzkPq+ZxCnvU0Oje1se60ZZaKB1Dca6ZgeXG2huKXGA84s3D/reogFxH
         /ps6yORwnMpF9sQ/2vaPCR6rgyVbedbO4NnTOJBQB0FF3rb/mUkz+DVHy+AAThUen1wh
         /CCfzGQ1ChckyKly8c+Rw8kdjDiMjWI338oV6bJCDt3gS628+o0YeSL86EnMmO+6fbRG
         b2ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690557; x=1739295357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bsR4bD/cuKUSC15fQmornQgXiDLv1vto+etrzpgvw+I=;
        b=sxmdzCstahz0691yI9Ch2BOw39YiK0cTcFjfG+rCXvnJ6hrsmHNQ/7Am/N466lChrW
         x8ZtU+vUvGr7u9xrkhE4BBfzP2XzfkjObkyOQ29fc0GzNa8h19NbV1sXVS8ZpMxtLfaI
         Brng3bRP3HzkNkZzmdX2GAutSk4QRvyQfc+4rAHsZEtW+RFJMl9rrHHTsc2jMk6FnMIi
         JhXLWbzr1QtxRbbguQZTMZA7EjJCRP1PMXPEZaQRsbNLCr6gVe/tHj+UjdlJt/99VYsb
         /oR9CLYe7w6uOGq5DytFyTqC8am3fJuYO6JgeOGQLi3kIxFpJSFi6gDXat3lvtwkbkzG
         fbBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6eWDelKuvWZWNuEIoTQus/aID2fLC7kt6yDRr5QpiX9RVqCnQ6sGaWX4KfwXFy9n3f/6NkA==@lfdr.de
X-Gm-Message-State: AOJu0YwiBnb4iHOUwzVEJTVXhlNplmTAnVzaqXbrQujmv5AFfX49G/5f
	udOnCmjjF4C7n9gbE1KR9X3f7LG/fzPaJes1Ge4pmRDcPWc2sK9E
X-Google-Smtp-Source: AGHT+IEY8ATupW4/2SlwfeyOP8LtA38v1p5jhEIk0LANPLp9azVG7z3temo7Rrwgqx3Ho8VuIMp4Mg==
X-Received: by 2002:a05:6a21:33a4:b0:1e1:a9dd:5a58 with SMTP id adf61e73a8af0-1ed7a6c87f9mr46877982637.30.1738690555220;
        Tue, 04 Feb 2025 09:35:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:44ca:b0:725:ed76:c92 with SMTP id
 d2e1a72fcca58-72fe2c14f0fls6466848b3a.0.-pod-prod-06-us; Tue, 04 Feb 2025
 09:35:52 -0800 (PST)
X-Received: by 2002:a17:902:d583:b0:21f:c67:a68a with SMTP id d9443c01a7336-21f0c67a771mr27824295ad.31.1738690552197;
        Tue, 04 Feb 2025 09:35:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690552; cv=none;
        d=google.com; s=arc-20240605;
        b=VtpcjjFVDeYL+wgzv01cH8PpIOAdqN2ZvvFaHGpdMMm5VfTE4NIxsem+getjIqqlQJ
         8Y+IwS0Fq0Yf44iw0xT+YBn0gUEfqIdQ2fB/Ii6Y7vZlVaMcpCvIRBNQxCQOygb9BE6T
         Iy5BqPaRQomYB6ZswvQFiSfIdxufko5y2jUylPiOeREjklNV+nWZsNWRh0A9URFFv11z
         D7hqFY6nivjCVjjle37rmos1DUWSvNip/t32a4vV5Cy9AySRoOJ2KigFtGG9gKQeZCrC
         UR8WijP7iTdcEh+4PV9TEKFvSqieyDq9fuMI08L0EOe8sRP6auc5E8PnjynRNtM8U+7J
         BWOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4BMCwGV6PWVYHkQSqSGJPvpDzUETn/4+hKDV9iJhNHI=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=Ds5GdvZ8UB1TzIJBJt4NiM6nKMn9eYrkoLxuwGYcBBmdowZFh369T+LtjfHH9hnQ9I
         ZKCJqaTU8RvbqCd1eY7dGRiDlpHj3yshEQujaVGWChU1ppxGEKDPCce0FM41Y9hl4u4T
         gIJdmUXA5WUefNf5pUtimehjpabbgoZlfF3m5WL7MDjfDW8XfOeMTgSN6AZhnNLMHQJG
         SsVdpNnauBYOntZl1m6nB/Ezk3dYw31lz8swKsGRUByyBUCWqSLC3U8MlPeCs5WZWbAF
         uyzuePFpVJ8ILuU9jK+qIzNXru1tsjDS22hfzAtXkSiLsdBXgUYm2xle2VAPF+VnJSGO
         kYRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=KbwpkOKU;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f9c3149a13si86431a91.1.2025.02.04.09.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:35:52 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: rAXFFRHnQjaTLPO+QsHEAg==
X-CSE-MsgGUID: KruNQtFBTheMX4+bAZ2wOA==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930632"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930632"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:50 -0800
X-CSE-ConnectionGUID: EjCbNRnNQ/eG0RktDBjJIQ==
X-CSE-MsgGUID: zLXQup0VQWiJeXH9lbUyzw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866602"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:38 -0800
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
Subject: [PATCH 06/15] x86: Reset tag for virtual to physical address conversions
Date: Tue,  4 Feb 2025 18:33:47 +0100
Message-ID: <80aa9a4c633502b5330c40f8b2d4da705dca92e7.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=KbwpkOKU;       spf=pass
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

Any place where pointer arithmetic is used to convert a virtual address
into a physical one can raise errors if the virtual address is tagged.

Reset the pointer's tag by sign extending the tag bits in macros that do
pointer arithmetic in address conversions. There will be no change in
compiled code with KASAN disabled since the compiler will optimize the
__tag_reset() out.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/include/asm/page.h    | 17 +++++++++++++----
 arch/x86/include/asm/page_64.h |  2 +-
 arch/x86/mm/physaddr.c         |  1 +
 3 files changed, 15 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index 1b93ff80b43b..09c3914d8ce4 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -7,6 +7,7 @@
 #ifdef __KERNEL__
 
 #include <asm/page_types.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/page_64.h>
@@ -41,7 +42,7 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
 #define __pa(x)		__phys_addr((unsigned long)(x))
 #endif
 
-#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
+#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(__tag_reset(x)))
 /* __pa_symbol should be used for C visible symbols.
    This seems to be the official gcc blessed way to do such arithmetic. */
 /*
@@ -65,9 +66,17 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
  * virt_to_page(kaddr) returns a valid pointer if and only if
  * virt_addr_valid(kaddr) returns true.
  */
-#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define page_to_virt(x)	({									\
+	__typeof__(x) __page = x;								\
+	void *__addr = __va(page_to_pfn((__typeof__(x))__tag_reset(__page)) << PAGE_SHIFT);	\
+	(void *)__tag_set((const void *)__addr, page_kasan_tag(__page));			\
+})
+#endif
+#define virt_to_page(kaddr)	pfn_to_page(__pa((void *)__tag_reset(kaddr)) >> PAGE_SHIFT)
 extern bool __virt_addr_valid(unsigned long kaddr);
-#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
+#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long)(__tag_reset(kaddr)))
 
 static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 {
@@ -81,7 +90,7 @@ static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
 
 static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
 {
-	return __canonical_address(vaddr, vaddr_bits) == vaddr;
+	return __canonical_address(vaddr, vaddr_bits) == __tag_reset(vaddr);
 }
 
 #endif	/* __ASSEMBLY__ */
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index f3d257c45225..6e24aeff36eb 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -33,7 +33,7 @@ static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
 extern unsigned long __phys_addr(unsigned long);
 extern unsigned long __phys_addr_symbol(unsigned long);
 #else
-#define __phys_addr(x)		__phys_addr_nodebug(x)
+#define __phys_addr(x)		__phys_addr_nodebug(__tag_reset(x))
 #define __phys_addr_symbol(x) \
 	((unsigned long)(x) - __START_KERNEL_map + phys_base)
 #endif
diff --git a/arch/x86/mm/physaddr.c b/arch/x86/mm/physaddr.c
index fc3f3d3e2ef2..7f2b11308245 100644
--- a/arch/x86/mm/physaddr.c
+++ b/arch/x86/mm/physaddr.c
@@ -14,6 +14,7 @@
 #ifdef CONFIG_DEBUG_VIRTUAL
 unsigned long __phys_addr(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/80aa9a4c633502b5330c40f8b2d4da705dca92e7.1738686764.git.maciej.wieczor-retman%40intel.com.
