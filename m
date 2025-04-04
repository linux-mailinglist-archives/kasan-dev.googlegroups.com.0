Return-Path: <kasan-dev+bncBCMMDDFSWYCBBFVXX67QMGQEPDMQ4YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BCE6A7BD65
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:16:08 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6e8f9450b19sf44179896d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772567; cv=pass;
        d=google.com; s=arc-20240605;
        b=lDXMBUp+5gaDn0nH8Q6kEcweHatMUhc7xGeWXhnlBlH6VusUESY3rUADuS0xrO0egj
         iZO/v0XE0wOlwusM6lVoGt3ZshFMxcV1Pn7v3d4zmUuQWnm+Gmymhazu1R+4+uqjNCdo
         Bxc9VQ3zevvXvIqyy916j+kEnCsZK2yh1LAzdEQe6uxnoxCaBgvd8tlGOAudx8IRyQw+
         y5SHdI9m24Cpq+ynJm/v6QnWSntmlsykjB+Ka56BmUT+6H4oNLK+N09Z7EahwmX7VmWO
         vYUNl23mQyr/s1dHMl84t3aALJALuWRTp9zW4lOWkMJEGikCQrrAdzmRgaNR9EOxVT84
         UJpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ByRDZ3Js/DbweWxOHv2Whsj9cQ4m6LRqJM6MeiqWm80=;
        fh=RQB6rNGsZnArwL0dojyfXW05aamAUqc4VK8Ix66nfS0=;
        b=LRYq+ZNxYPcnx4qkevABm9xhBcq+aqTgl77aYP03wVsCZZ33CllcPB/ogqpRSIHAfL
         2OWfnEyG63+nT2agCxL1CQvDZFamVz8aUaFjuEtcqh50+u2PBBY4ytz+VwRBJnqhNKmS
         KP/sr/P8u9Zmd0Ujsnx4G7OkYc+XmH5ymZnM1808/2sUDsafAGxBIRAuh+gYB/IXU7Wl
         EGv6oV6NrdTLx32LhaIaPC+9ASfYD3jZZBzoadgrP4qHSmG0pjcYCo4SozDmKRQDP0Sz
         MP9ZvftuIJ76TCiTpB6nFyq5LpXQIQWqtoRlC74TekSJ0RclgptIjOHvjG1YDLRLVpmr
         pUgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DKVGvWxT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772567; x=1744377367; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ByRDZ3Js/DbweWxOHv2Whsj9cQ4m6LRqJM6MeiqWm80=;
        b=sz4Y/MKetEpf5VyyjIU8S1fSh8dG+pclLH2SSzFc/qDCfXiWTumcgRwoen0C6UpxCP
         0n+l1dcGKCl/QILZS/7vlJKq42jGw38LqT7fS9Jg4ivdEP2viIrEj6ITYaW8Qg0CkOtB
         FgOOER2qzUlNZUPK2APNwmwQLGb9GIxqOZVsALFpkvzXlFll+R3AkBnjkzxLxSjzZERO
         5KrS80S/yt0ComDp0jGlwQh+6iflsQIwNut4/t1tcmHAKbbQKrwZ/4I4D48Gy6W9YjbM
         UK7BDC15kEi7pXN8w75I8nxIw0QJWzblBywq51WG2Q6/84GHoJHE2/ebDhh99YFgUc7Q
         KKpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772567; x=1744377367;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ByRDZ3Js/DbweWxOHv2Whsj9cQ4m6LRqJM6MeiqWm80=;
        b=AUI3ZtP0VOc0Bw2gfVGxSA+B1UpU+2u1ehmMKXrPqpSC0rzyA8nA6tShKmwDmffWDw
         krRhyIO5Qg4S444hl1wr4q3OlG2buQ0b4jNrLzw/LNQlSirdv1aMvYgDDOD5dxNMK8mM
         T2caq9FLJLFfiVGYlK/Glv0JG1oLdTBs/zF66lCmdiVdhX/jp+PDasx7Ax6i+Pz6AzTp
         C23UNWTPi2f3jZafmIB6pdXIvON52J5JxBmgKD/1SDRfqVdsqzkFrt9LDoeoZLjJRRSU
         IbYsNmUQLSqndpx2eM107wVEB62O05QWyqUXRR8IPxdLkxKZZ4p1b8P5XnY05rkiOz7o
         bcYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXH7uXuQEA1EfUrYuIdqedD/BOILOaJN93F8dHzF5ohnNS0xKI59y/dXnwZKHPxalzTgFgPUg==@lfdr.de
X-Gm-Message-State: AOJu0YzitQe/cc77/aI+80Ng7CWnbFXf721kzyD/56z5IUXaFL4P4vnO
	nh4vItG68U5c3cpAhG0EofgwNUa+K6DFh3f5eTYxgZcDrXUNKLhR
X-Google-Smtp-Source: AGHT+IF9eLcqtk4acHQ+7nBj8YXR/I9Dcj9TwOzUx/IcwuglgNZGPp82XeGx2F3mg5X0XyvEbtOLKg==
X-Received: by 2002:a05:6214:21ae:b0:6ed:1637:442f with SMTP id 6a1803df08f44-6ef0bf9c501mr92814126d6.17.1743772567101;
        Fri, 04 Apr 2025 06:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIXd1N1wca2YYD38kQThMupU3sF4QnPKes3ZjJfAbAYmw==
Received: by 2002:ad4:42b1:0:b0:6e8:ebb0:eed with SMTP id 6a1803df08f44-6ef0bf7e012ls38801756d6.1.-pod-prod-00-us;
 Fri, 04 Apr 2025 06:16:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK+x63a4XEIxEKI60wHGHkFxEEsqQDvtwI7WqMfQzQEC1Y+8F/Fa479PJHzbTaSXdM1xgwti5Dzb8=@googlegroups.com
X-Received: by 2002:a05:6214:2aa6:b0:6e4:2479:d59b with SMTP id 6a1803df08f44-6eff55c6812mr50300046d6.16.1743772563770;
        Fri, 04 Apr 2025 06:16:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772563; cv=none;
        d=google.com; s=arc-20240605;
        b=GqyTEzKFdkd1CyCL72iHZtINgfIh6QRGJ+6A9BTa5hbz2Ye2w773TP94+NKAp2KHMj
         7QNtnASa7U8rqb1T70CXXct2MCQxzqGwq+J0PZEZIwFN+wISui5givPJmvd6P3U99J4O
         DDmhXl6nZ1+UYZlTjNvPMW32kwFznUxBDrvTssLZFxXq68JS0LRkKWQ09jVX8pMcm+TZ
         rguTTxFz5eLYjiSqc+W7cTHepNYE6SbzVPfC8mJwMyWVJAfvDmadXAkTrYDnsd7lMu2B
         klm9xYZziJlU8NsimbwlN5kmhJ/FnAE52TQvQRGmM0AGYlEcapJ0RJPy9Hj2nW9IrrA3
         RHQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BzPu5bL1P82hpoNCxPuVzaAFLr4FB1kFlHIDeW2Ujs8=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=jlpIlPkkQsRwtLb0sCbNNWLtN13g4io0krunNf1JMCKvunZHnpGTyLVjf0EgF/0stb
         3AfXrG4iz36QQKnQ+c+1r41DlPhtc5VA2FH4j63hWpuVVgv9EjJ5DqVcfqL12GnwUoWw
         kwPWoDTzAmMo9IWYxWXc1HAGOAbjAKJSB+yMds0cFARSc5IleC+mViHAeDZ6HXMhne70
         V8qwWz1MzX7O3LmHSb7L6kIyi5di9BFuzwOXtoren8oL/RVoTlyn1Gk+pbvhvm8UD+6r
         oP8De842g9sI+9+hclHMV/OR2SLMLFHLpFlG2r9G07AN+HyLtKMKVhy/9NB4k4BLlqBd
         YOXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DKVGvWxT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ef0f0e1032si1503586d6.4.2025.04.04.06.16.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:16:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: 2ZlCMChSTYSFIaGSaV34lg==
X-CSE-MsgGUID: v22AxpgjSeGfniZ1FyQTIA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401742"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401742"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:03 -0700
X-CSE-ConnectionGUID: /v4yemxXRNCf9yxykbmk+A==
X-CSE-MsgGUID: DvwOzQD2QMSbRSno4tJp0A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157141"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:47 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 05/14] x86: Reset tag for virtual to physical address conversions
Date: Fri,  4 Apr 2025 15:14:09 +0200
Message-ID: <a8332a2dc5b21bd8533ea38da258c093fb9f2fe2.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DKVGvWxT;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
index 9265f2fca99a..e37f63b50728 100644
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
 
 #endif	/* __ASSEMBLER__ */
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index d3aab6f4e59a..44975a8ae665 100644
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a8332a2dc5b21bd8533ea38da258c093fb9f2fe2.1743772053.git.maciej.wieczor-retman%40intel.com.
