Return-Path: <kasan-dev+bncBCMMDDFSWYCBBVME2G6QMGQEBG23AOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C233A394E9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:18:31 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-220d6c10a17sf95398855ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:18:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866709; cv=pass;
        d=google.com; s=arc-20240605;
        b=IT0ZcyxYbDbu1aEOMwIxF8r/VUMWWOhu5aiRrWPRKEibxYqP4HV5W+Z3b0y04E42XR
         1Tre1OngOC16hTxS920TXegxOHQ85qo8uq6dfv/doqLLX0FDLKnlCy8eT79v5tOJ9WbY
         swwhH3IBsNfjPAmogQ3IjLxbM6J/tTKGO6sB9pCNBZ1JrFhLqzaqekdllSpzS6IKe0uH
         pj/WoSMYOzji0/K1tSZgmvBelhbQgrUEhiicS1/HQ0AeI8oQyIcZS5VIAlYg53QY3HHk
         9FsDzG1bIRQ976JXwSTgGi8ZHVaZIPQK2DtIMo8cCVVfgPGuBTl2D86gLz60qsiGbU5T
         mr4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XK/M2zvKJ6HI+4mdS7jzDAA0WeIRs/8oCo1CPQm17h4=;
        fh=vgTY46lEFdxwBd2Mlbbo6wT0UwKWz9790eeF/TO9ejM=;
        b=jKZ1M2N89CBjW2ArRPp/x3EToP1Jx7E5IFAJ2qBfJsUtLbyN8wxO8C2uTpg8/qVnqj
         rfnHtOAlixIChCE6Dfwu5sH4MDKNbceu/k5fm6SKhgXr8VAHDM7N9GeEHQV4O3+hXXu6
         WHwiP0GwfvL6yyC+4lxWGX2NqVZ00muU1PHKlDbmY/TSPAZr0/5lYLix0ipQdbxAlRlv
         y/13nbZWnyu74KK+0S+NaC1wmnbxILpMFyJEIyWNYS+Xp6/nb8mxKg3MwWVk6FFxCK0a
         DxHvpAIlDcych9Giikd0cP66+SbwapJFCFGYfRC97NrIr0y4CpCYZzTJcTvzIhxCQjoC
         0+qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PVWpQFBN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866709; x=1740471509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XK/M2zvKJ6HI+4mdS7jzDAA0WeIRs/8oCo1CPQm17h4=;
        b=QWe8zRPQSkS/WzNrdJRqROhvtY0shob3niOocbJ5aoT2kJbsCVeOkpCGgq8GWrt8hx
         xdl8/+A/TzhNi6WndE+pzl6RUk4FxL1enlze8uZ9da6PWlW5TWRITULkplkorJkeHVOZ
         Dek4Fh2ZJna7z2lQXRWybwPgiqf+lHWU9224yCln4A5XULnK7jGE5SxOVno/HAgzyqPg
         IfwOyc0ZdLt93vbywdzhFSkXz3aIffPvhH2p/D93X09VxmzbVqudeKA/HYKRbouoTwzQ
         H7v/qMG/Xlj3Qf6O5KXRrx2LhIT4TqdpF3HWuGIDKW7nf2oYTuPHdLAvQbVUTyuMCEpI
         aXIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866709; x=1740471509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XK/M2zvKJ6HI+4mdS7jzDAA0WeIRs/8oCo1CPQm17h4=;
        b=Aa0VuZDss7Ra9NtQMm0oraocCLNo+GUj+vBpeQzEgXFq0fTbYcOzqPN0m5biYn+GLn
         IiJ1JPdAscrAgPNXXA4EJTP3fkGA7grhU4kUs4MbAIMcWxk6S4KMO/J0pVfSiEjAH+U0
         tJapI4nIyXGaFdVqrjW8a7jTrrMKi22vKZ73aKlWxPc9G+gh2LVcNtxx54jVU9ut7+xr
         NroZBEmdIGWIaQY6UWiJEmGbMb2PlpppITE8SBuwqztOPXomui6+BW8KhlbRZ4sfZlP+
         IigmieCHPgKM17ebAmhQ+BLaKzr944JyFPV9A56n+ymyjfJeCtzfAjk8TB07e5qrggJB
         nz1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOkYZMZtSkMA/jySaR/9S0IqSLdLnmQozXs8H/BkIF84dc9ZddcBluTeQ8jLR3lv+ESMg+QQ==@lfdr.de
X-Gm-Message-State: AOJu0YxoIR6AoMgq+PJ8yj79IQSvW7ARTl4VJEzxQKFT0VGb/RJOwkWN
	wBH92ZHMAt2yCiBlPGR1ERX7e7hUAgLogUfqnHgKGeRqLO660PKC
X-Google-Smtp-Source: AGHT+IHe3XNlGXSGxoJs0E9IHDG9ZveED7CUzQZumCWQs69JyMqmfe2jv+luyCcT0K2Jur6AVzd0vg==
X-Received: by 2002:a17:90b:17d1:b0:2f1:2e10:8160 with SMTP id 98e67ed59e1d1-2fc4076f03dmr19970511a91.11.1739866709522;
        Tue, 18 Feb 2025 00:18:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHcW0yydMVLZJo9z38neRo0f41f3soS5GeQtCo2uTVATw==
Received: by 2002:a17:90a:cb06:b0:2fa:1e2f:ae09 with SMTP id
 98e67ed59e1d1-2fc0d821b2dls3611876a91.2.-pod-prod-00-us; Tue, 18 Feb 2025
 00:18:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWTYILdsWwfefpQRq5we8VrVHVO6N92HJFqWPDxGgjt6oiKKfkjgu5Bx9CVxNyW5m9wXF+QkcG5IvA=@googlegroups.com
X-Received: by 2002:a17:90b:2d8d:b0:2f6:e47c:1750 with SMTP id 98e67ed59e1d1-2fc4076f328mr20590777a91.13.1739866708378;
        Tue, 18 Feb 2025 00:18:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866708; cv=none;
        d=google.com; s=arc-20240605;
        b=dDeKnPuMY44bzl9NCUNezckSsxQWEMIQeeKNESbw4GbGHMYSdEoduSr9E4IRkg5Mr4
         WUy8HEqBM4Ur5+KIb1d/B8WJREyXWH5OBoK+I5S4Zn9+9qvAt/PmIu5HhryE2DI2wUdY
         WVh9hfl4sWoQ7wc5DGIj+2Y70dkiKXaqMRzOUj14m9GAJINltWHL9MqEAS+sn7Udmuzh
         HS7N+IMaAsGgCMgEISIyWA1TQ/wzZ57svaWOHw89Rq024yDRs46AFIEqjk/j750T4VO9
         D7JK3qAycf6evkZMwuIswHwVPVCzucDUpIo8KXEpYTDYLB6Pn+sTI+Deq/s94Tp3BoEq
         l2Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IkiSs8Mx0ftzr0bNH0MOKgRQ603f42VR6P8kP2Y60Y8=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=hbZ/hddM+jIduBiFAyNXmYXsEtXQ7pp40exJ4FKr7wqa2DSDK1pGNlNmn5MtBvnqxX
         477P+1lAwdry/bbdM0djD963TLWIOLkbkb/qg5HbN/kXQTMD/WCIV0DtOzAlaD6CEsEw
         KiKz10Dj7LdK74T4H7EZpiJdCVAAjUgTZf8dNZbL5GwEH8ZOzhArn43L78FTnVUlEKiy
         6CB016mtXJATNAl22Gwrc1ECnvVCAo9KtLgij+/lXbRF42VYjnR6BapUnL7WSzzhi0q/
         hdCMJI0uyxtkTHTegC6QCjhU28Pa27tcfVJYkeGKGV5tLDCgeYtQN1DtQw0fstsd5Hgo
         Xbjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PVWpQFBN;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fc138a78a8si479573a91.0.2025.02.18.00.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:18:28 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: jj0Z+v57QMSbZs0BTCgzpQ==
X-CSE-MsgGUID: e7bqTpdzQC2BP896RgAmQg==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150262"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150262"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:27 -0800
X-CSE-ConnectionGUID: 5z9vRN7wSMWUvwtxJjGh6g==
X-CSE-MsgGUID: Z/kyhOw/QdSF0c+xdlivEw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247683"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:10 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 07/14] x86: Reset tag for virtual to physical address conversions
Date: Tue, 18 Feb 2025 09:15:23 +0100
Message-ID: <dc2aa15404098561c1eb5bad9b31b8d404f93b1c.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=PVWpQFBN;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
index c9fe207916f4..fdafeb06c195 100644
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
index d63576608ce7..54990ea82f74 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dc2aa15404098561c1eb5bad9b31b8d404f93b1c.1739866028.git.maciej.wieczor-retman%40intel.com.
