Return-Path: <kasan-dev+bncBCMMDDFSWYCBBPEOWPCQMGQEALON4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id E9B68B34BCA
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:27:41 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7eac60d6c18sf551606685a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:27:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153661; cv=pass;
        d=google.com; s=arc-20240605;
        b=YsBlHU36cf24ZvvrXFADxIcHQ4cFFs066Yy9X6Xd/x84Mmxjx/DA1V138VZhn6ih84
         i/UP5vtfri8xFbVsHLInijjMTdTYAFBqJrrVaSePP7AuCtWZ6YNzFopzOSZeQpfp3F1n
         aEapJtjkKbQQuc3f744NbZcAas33JytYJvrVtUJmHNAC70Ppkh2jtJagbkqQOtOxzdeH
         H2z5scqgt/uo+cQkwOhygVDiV70lAt3RMCefTdHwJ35WwvT9b3p2i24VE+m7Qsp0ts63
         EicJN5+JHYXI8B4wM3dl2/atn0+g5R/4EM5b1Cy+b/ftjS7EpdMlh3hlqKDB4GkyUM3g
         1j8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tyAjpWnfbXjAuRdEz07gHFDrzZE8TGXONgfgTRJEVyE=;
        fh=2ttYTObB6lWlHkI3/o3k4VkEGGlgKRoRuJA6mXzNWgA=;
        b=jH1gmHl0bOg5XSluEg5upDyyTLJlUn7WQLxjnJF6InYzp6ME7zkD4UhAv3XKBdJdsR
         /NMVoU65wsVk/FCkBYc/2UKBgKTG/ff9BlZDJUYICtfxzO3sYihY6QRdoNHxiATAkmfy
         ZRZSbs11ZmsZha35RTGmT2PJgIglyKM3TSArFzkkEXaLbbbfqlgKJ4rlCR17S2amLvl+
         8i7KKA2xGazIAu07jd+a6R9cwQogBVLyd0MC7ZOCdonpvWc6BCuT88MtRs/uwfzvKEE5
         9zbNCy3EySwZbmncXySMIWTerCzyXH0xRDU9IoxgNhQJO+F7E45rSBQQox1bToF468Kb
         pVQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BWBiGv3G;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153661; x=1756758461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tyAjpWnfbXjAuRdEz07gHFDrzZE8TGXONgfgTRJEVyE=;
        b=uHQQwJ790G8ENQu/azmP4VJFMyWUd38MZwcZchhG2N7FcI50MpTd8eFt6+0f9VFfii
         7C7yyq90x+WfUiXcMdmHmBG84e5BdPsS0j+dKQXswyCuAead7Tu6Rwem8bgaS1AGOvxt
         tNwRIlnpNsFQL+W8KqtfeNaSLenpKoUQtMlZyNhLzItB8bOMvmKdeE5ge33nvmq1tx4u
         7BmQx6l/lrhZiYi1MtsdnzbegaxtBBGaWRyBvXxaiGONIEWZC7urKDmT+mY+zoOFi10U
         NeDvyMG9NsoiILKn8Xk0OiYG9YTIJ37gpLCf3vZqP2tzb6aaM70ZyzhSnGUaVYkQy8MX
         gxiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153661; x=1756758461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tyAjpWnfbXjAuRdEz07gHFDrzZE8TGXONgfgTRJEVyE=;
        b=DDkb3wjzHoApKqlC2D5AVERN+q0rzKEs81+fJpciYCN18n99rVF5yEBfv16mGro24L
         AtkyKvIgUFyNgCICIL3L5+JlrcfS51kJMNXw+GwfB+wPjAKWOc8V92IBt4jEmBgs6A8S
         PO7yuCSxTf3fnvnvOXm+fJBmYlDekozHBm9tcLhhVO40IPHxogjowPVI562/zqQDXZ0X
         Pz2du38JN7Ld9mO8GRneTd8Wk4jdTAKzLDjo37IycqZ/IGTDynfEiiRvfRmz6s7J+9zp
         OyvDzaxezRwWc+Y6G24qITgfMicKUzOP6RifKSqOc0fHEwZuOXLN1+qFD/91629gpbPW
         u2iA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX4ilEKSm0v77DDYvQpWzfOwiQcI4wZV0U6jcIAUvWwsmvPM/8pwaQzCvAF4EHhPjsFd72guA==@lfdr.de
X-Gm-Message-State: AOJu0YwwFSeiAKlxlAJFteGtuncQsuHGR8N5tIqV1smEr0j2F19H1Bwr
	k1dEI2peq3x59MttYdgVW8v92xWtkcABMX72Xauz/YuOB4KuAIBvQZMJ
X-Google-Smtp-Source: AGHT+IGu0zoMKpGdfy2ePDHqt4HSfM/rgBxUhw0v1Jmsy521xgxC2DZWUlmkTtqa1jYE8xLgQARD4A==
X-Received: by 2002:a05:620a:2552:b0:7e2:3a27:a120 with SMTP id af79cd13be357-7ea1107d640mr1496807285a.54.1756153660453;
        Mon, 25 Aug 2025 13:27:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfdebjjv8ufQsQYHX7ZJNbOkAG5CVAd+IQXGs9yY2g6YQ==
Received: by 2002:a05:622a:48:b0:4b0:7b0a:5903 with SMTP id
 d75a77b69052e-4b29d960a9els70065731cf.2.-pod-prod-07-us; Mon, 25 Aug 2025
 13:27:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdoRfIQjRS5OpJ7o63eyOLXOY5kc9I8zQM1CLh8UDJfUqrTaeHyxUi5HBSwXB4nKB2P3MUMyZcvBs=@googlegroups.com
X-Received: by 2002:a05:620a:7106:b0:7e8:666:8bdf with SMTP id af79cd13be357-7ea110954f0mr1674342885a.63.1756153659587;
        Mon, 25 Aug 2025 13:27:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153659; cv=none;
        d=google.com; s=arc-20240605;
        b=b49SJSVTVKQaJ7bpVSXiAG8TroOt/n2a7u38ginaxjSmUNuNZo+wFKFu/Zov1XfWbD
         gIz5+xfkxxg6cMWGz5PPu8uK5N4E/w3jKmwbi4Zc59sjdiyZ7QLgS7MImfKffjOUdxtR
         GuGvftuDHU+BJ5C92N5sqX/D9jJwnPPS7nY72tVDfyi63l00SyD2DDZ/zgZTtLXmcC55
         qUkhyJQ+oGM4QwpVZ6BOXEpiXqsWfUCq/E2BjH4O3zr4N8Kix8tuF3Dt51GBwnIwcz92
         SzHBs14xpcsgjb0xg4C6tNW8KvbR5e4uEaS7I56rdhTA3XlHPgTmuj/XGCOoldbGTWuz
         ADag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MvLwRIAhBi7gRgPiOgwd9SrdmrLVz29BtT7bdQhwA2w=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=T887v+8b4NHLQLW16GoXusZHcyoAVn9Cn1PYuIN1rTZkGbbTwdBWOPvGi8pCi0TDi7
         TLWGdQC5EDkOYaYbnN8DX+lDk/fYwn7hwc2f7JLmJrf9EV+Dy8fvxAW07WRWNM1rnNEu
         6xGFve4MI12xsZDLzzQHyY324iFdcgPMh7t2Emc7d8AlaNCza+mQykDHzUrpNvfOK1Hk
         JRq6TsTHer6dLzKA3gEiC4+VPCGRNZerHcUYd+sIuPX741d2D7R9UbhL4yL9vj32YdDA
         ik9gEvS8XQvCHKtYPzgXT7f/9Q+mJrAFjZ7Lih+rzPCurKPRN1OA4cd8xW2Z/8J36W2F
         rmBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BWBiGv3G;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7eeb4416f99si19660485a.3.2025.08.25.13.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:27:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: m2/6xt96Qfm/mnHXe3c9Iw==
X-CSE-MsgGUID: fCIHn+k5TUiEuoLTYxIjSw==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970500"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970500"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:38 -0700
X-CSE-ConnectionGUID: 88rMVBboREqinEplSn4Mdw==
X-CSE-MsgGUID: 3rIVdVdjQ/akH62ekpclSQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780355"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:19 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 06/19] x86: Reset tag for virtual to physical address conversions
Date: Mon, 25 Aug 2025 22:24:31 +0200
Message-ID: <462dc78d4d986007e82c12ad57bb6b11f85b19a1.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BWBiGv3G;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
Changelog v5:
- Move __tag_reset() calls into __phys_addr_nodebug() and
  __virt_addr_valid() instead of calling it on the arguments of higher
  level functions.

Changelog v4:
- Simplify page_to_virt() by removing pointless casts.
- Remove change in __is_canonical_address() because it's taken care of
  in a later patch due to a LAM compatible definition of canonical.

 arch/x86/include/asm/page.h    | 8 ++++++++
 arch/x86/include/asm/page_64.h | 1 +
 arch/x86/mm/physaddr.c         | 2 ++
 3 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index 9265f2fca99a..bcf5cad3da36 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -7,6 +7,7 @@
 #ifdef __KERNEL__
 
 #include <asm/page_types.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/page_64.h>
@@ -65,6 +66,13 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
  * virt_to_page(kaddr) returns a valid pointer if and only if
  * virt_addr_valid(kaddr) returns true.
  */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define page_to_virt(x) ({							\
+	void *__addr = __va(page_to_pfn((struct page *)x) << PAGE_SHIFT);	\
+	__tag_set(__addr, page_kasan_tag(x));					\
+})
+#endif
 #define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
 extern bool __virt_addr_valid(unsigned long kaddr);
 #define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index 015d23f3e01f..b18fef43dd34 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -21,6 +21,7 @@ extern unsigned long direct_map_physmem_end;
 
 static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
diff --git a/arch/x86/mm/physaddr.c b/arch/x86/mm/physaddr.c
index fc3f3d3e2ef2..d6aa3589c798 100644
--- a/arch/x86/mm/physaddr.c
+++ b/arch/x86/mm/physaddr.c
@@ -14,6 +14,7 @@
 #ifdef CONFIG_DEBUG_VIRTUAL
 unsigned long __phys_addr(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
@@ -46,6 +47,7 @@ EXPORT_SYMBOL(__phys_addr_symbol);
 
 bool __virt_addr_valid(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/462dc78d4d986007e82c12ad57bb6b11f85b19a1.1756151769.git.maciej.wieczor-retman%40intel.com.
