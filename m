Return-Path: <kasan-dev+bncBCMMDDFSWYCBBKVARG6QMGQECAZJCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D5F45A2789D
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:36:46 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d00eac3de2sf36104845ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:36:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690602; cv=pass;
        d=google.com; s=arc-20240605;
        b=lozu1rjxqOdWIPFnacD9qF0XaoeoP2+dLLAv/AZhoIdDpKMaDaNLsgRlC2lL7/Tuhm
         nkpPyyqo661kgQ8som3PxVTIxP0sS03CrqYTJ2ICyzIvNOxA/WmqQiDOwx5MF5T/3jXC
         F+HFRsJ5woh8JpJh+tmWPa76WNsxI1f/X2fTZ7w2sjrFDzdoDZrB1OEg/nqJDxJRtmOS
         NGtIKzAnU2iOxrvI1JUydL0PwZUDdawEqOEmzlmXFIcPCRRH5Ycta5zWXtQzaw39rSjv
         /v3kyP0PdHVjGYl/mHO7aKe8yui78rwEw87MxeHgNtpL5YQ36s+J3skEnqzF7Z1zWrUz
         AZbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YpkvFBqoKgNVJPKEYBhpVZEJNpm+CE2UtuUrOxwoxHI=;
        fh=vFSgKeu2X8TeI2Y7OiwPjM2uZIDLLtIhEZEa/hWtu9Q=;
        b=h3sdGtz58993P6c26SH5W29zdbmqnZkGfhCSYmIGXmn/6QWUSqsyYru5eEo3jYyJBf
         jhUI67LAS40sTS4cHhtGLiBw3xYPHqo07JepW5cnkxocWI1sdvpmmqYzwmbaBAMgnr1q
         bkU/D3I8+FqoOELsuiBIDjjo2DN0qsQ4X1J2QiXKPoTnVLDMVHrrhvl9AlAsj4TA+ZzU
         3JLrG0R3i6qwQqnEDdZXzsoyMSqyQLNQQsMMP8DiadcTo+V7FRj26K9TrJPJcqRLxvna
         FVqrWWtsmjup+kclIoZWd5orMJzNx1M2YgeYZ0If4QwNaaQGT1bVcs32HXQfCaRoMreT
         vBrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VkzqC/rm";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690602; x=1739295402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YpkvFBqoKgNVJPKEYBhpVZEJNpm+CE2UtuUrOxwoxHI=;
        b=lXef5MJoaAK8yEMUcZKxGPi1CeZkqkUxlylEf7EF4dCr2QamTt9FH7PSMV4C5NZZ+d
         DWJ2FzDIMTFxW/Y9fwWKuYsSd543+jG6yGH+bEz0adbPr1ZSRNLkNFMxpwRpiYQybaTQ
         0kyEAkdha6Rvpchb3+teGTONNqiB5yephljLjr3Zk7lQdu10jB8KsKTMR4woz+yZMgRi
         0pTCZz+ABlgrPBgpmQz5fxCGnLWFeajAAMY9BTVLx9Oc3kE+fXofQwByhKjQgSwaQjtX
         mXMRAhR3mFaAeUcTG8kUPNhHHugKGdGoIWTUDoGiIk7Oj8rOhtEsfMpQf+m5Dq8YB+pR
         K9Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690602; x=1739295402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YpkvFBqoKgNVJPKEYBhpVZEJNpm+CE2UtuUrOxwoxHI=;
        b=joEO8XfACAfVWeyCUsXv4kQL6KtNOGVLrdCp1c/I1RHMeL4SO2P0pcXmoOm7Xjfhj9
         Uo+Rn96Z+1LYpFIFDx1f+kU0Oa0y+3C0esEhZKVY0I2nvCyT8kBcD8SZ3TZjo54uXHlX
         0OOmRpx+nFBcwaQMW/nkwbjw2rgr8bKaR0DNdgy2PF2pQlD7gtVCkklDvgIw4L/hcob3
         31cYKahkjINj4eUq3zaJHQAxZeygXqEAUwNzw6SP4XHrB91bxx8NDmIl+mmmeQ3RAgJx
         rDSVoMwYrQiKT//1QvVSqZKJVAUeWKvHdxRUA5WFApwoqRBKhWm2gJAj/406IKsC4rFH
         ESYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnbLZqjKRxkg4+jTGWxEG5V2j4W2AhmcE4wXmDng2BYfLrKeYEzzpaXQ92wQrO2H/tD2zFJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzo9f9Ur3Cnk4MMcovqu6GW4dQrM3SfH5vDYYlx45iUp2sqdMwv
	zZ8z/WKWr3RJwsMRYdv2BNPTLjYRFDplq/a8VslETkuokrwsDfj9
X-Google-Smtp-Source: AGHT+IEvhKRP6fvKIe4zC9V2e8MyhRiK4JPreuCJ+xq+TTpoMCOo32ISIxb2YQEAU1MPyL8znb63Uw==
X-Received: by 2002:a05:6e02:1f12:b0:3d0:134b:6762 with SMTP id e9e14a558f8ab-3d0134b68cfmr153380595ab.6.1738690602631;
        Tue, 04 Feb 2025 09:36:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca0e:0:b0:3cf:c8b9:882f with SMTP id e9e14a558f8ab-3d008d91f97ls17586005ab.1.-pod-prod-09-us;
 Tue, 04 Feb 2025 09:36:42 -0800 (PST)
X-Received: by 2002:a05:6e02:13a1:b0:3cf:b012:9f9d with SMTP id e9e14a558f8ab-3cffe406acdmr198383455ab.14.1738690601824;
        Tue, 04 Feb 2025 09:36:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690601; cv=none;
        d=google.com; s=arc-20240605;
        b=bU3Y5RE4PVCgrIbvFKd7y5dw3dfo4aKuCbRcPIQf5KG3qUs8DRbFO8NyjJFN/HK6jD
         g5BEPkoETc59excKOtJ3ZbG+2zu4J1HV0XsBFZ0IOH6pMkXCoiS7HLhm6jdN+tH7Oygt
         qbK1cHcH86KnKWbj8FhrHo5vIkDR4TnlYQsLJlf0WouATaP6WzjDLoqNaJ7UQMjTl4MN
         7FudtcOLdXqagwUmMh2RQxLba+bQRoJY6Ueuk2bPQwQUZFKreh0Nb+Iq5GBIhXHlJtsi
         fGrm8gvFy3IboO2Mn2VJ5zTI6M0qkhOF1b3AXfcz+r1zObmZyVg4NGlRVtLuPtPLKJgn
         pXcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pLFVRgBwiXf+T1hr1v6y3oXYvLLcOkmu5U12KRQmKlw=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=F2PqeTPe3VpwjP1wGSo3ZqZHy54U9ZzVfWoNmtZmS6Wweo3F/YT0cOelfJZGgUB0vB
         /WKFIbSzUZF9jPMw7uiRy6Y3xmexwUdSE+baE7SyF4wUXXdEN9NJdTPue1stBvXWQ7sp
         WXu5I/Jt+v8nj26h/YcTy0iywDUq8Ol7rulFFM2syysfFZMUSWyvoJZ0gBcxlc9JJUqa
         XP3nYKhD5Pg+eFIUFM7h2BjkEShBdTMeLRmmI+kGhPyomsa8WUnO8PN+FUIuNM4Jr9Nm
         nwwMR0R8SdTMK7ad/3V7cprQ7Kp7XDxlGwW1v8W1JehXI+sTl1XjgeahlThqIeEQkbWk
         C/LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VkzqC/rm";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d00a5111c3si4865535ab.2.2025.02.04.09.36.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:36:41 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: VLenKphLTe+yYuXQ8m+gog==
X-CSE-MsgGUID: Lxn4wLZ/Q42iTl7Ur76lgw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930920"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930920"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:39 -0800
X-CSE-ConnectionGUID: euT5Fx0UQBaZT6g1J2Ba6Q==
X-CSE-MsgGUID: VDPCZKL7T1GLAmeyS4orWQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866863"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:27 -0800
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
Subject: [PATCH 10/15] x86: KASAN raw shadow memory PTE init
Date: Tue,  4 Feb 2025 18:33:51 +0100
Message-ID: <28ddfb1694b19278405b4934f37d398794409749.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="VkzqC/rm";       spf=pass
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

In KASAN's generic mode the default value in shadow memory is zero.
During initialization of shadow memory pages they are allocated and
zeroed.

In KASAN's tag-based mode the default tag for the arm64 architecture is
0xFE which corresponds to any memory that should not be accessed. On x86
(where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
during the initializations all the bytes in shadow memory pages should
be filled with 0xE or 0xEE if two tags should be packed in one shadow
byte.

Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
avoid zeroing out the memory so it can be set with the KASAN invalid
tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
 include/linux/kasan.h       | 25 +++++++++++++++++++++++++
 mm/kasan/kasan.h            | 19 -------------------
 3 files changed, 41 insertions(+), 22 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 9dddf19a5571..55d468d83682 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -35,6 +35,18 @@ static __init void *early_alloc(size_t size, int nid, bool should_panic)
 	return ptr;
 }
 
+static __init void *early_raw_alloc(size_t size, int nid, bool should_panic)
+{
+	void *ptr = memblock_alloc_try_nid_raw(size, size,
+			__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, nid);
+
+	if (!ptr && should_panic)
+		panic("%pS: Failed to allocate page, nid=%d from=%lx\n",
+		      (void *)_RET_IP_, nid, __pa(MAX_DMA_ADDRESS));
+
+	return ptr;
+}
+
 static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 				      unsigned long end, int nid)
 {
@@ -64,8 +76,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 		if (!pte_none(*pte))
 			continue;
 
-		p = early_alloc(PAGE_SIZE, nid, true);
-		entry = pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
+		p = early_raw_alloc(PAGE_SIZE, nid, true);
+		memset(p, PAGE_SIZE, kasan_dense_tag(KASAN_SHADOW_INIT));
+		entry = pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL);
 		set_pte_at(&init_mm, addr, pte, entry);
 	} while (pte++, addr += PAGE_SIZE, addr != end);
 }
@@ -437,7 +450,7 @@ void __init kasan_init(void)
 	 * it may contain some garbage. Now we can clear and write protect it,
 	 * since after the TLB flush no one should write to it.
 	 */
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	kasan_poison(kasan_early_shadow_page, PAGE_SIZE, KASAN_SHADOW_INIT, false);
 	for (i = 0; i < PTRS_PER_PTE; i++) {
 		pte_t pte;
 		pgprot_t prot;
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 83146367170a..af8272c74409 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -151,6 +151,31 @@ static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 		__kasan_unpoison_range(addr, size);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
+{
+	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
+		return;
+	if (WARN_ON(size & KASAN_GRANULE_MASK))
+		return;
+
+	hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+/**
+ * kasan_poison - mark the memory range as inaccessible
+ * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
+ * @size - range size, must be aligned to KASAN_GRANULE_SIZE
+ * @value - value that's written to metadata for the range
+ * @init - whether to initialize the memory range (only for hardware tag-based)
+ */
+void kasan_poison(const void *addr, size_t size, u8 value, bool init);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init);
 static __always_inline void kasan_poison_pages(struct page *page,
 						unsigned int order, bool init)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a56aadd51485..2405477c5899 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -466,16 +466,6 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
-{
-	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
-		return;
-	if (WARN_ON(size & KASAN_GRANULE_MASK))
-		return;
-
-	hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
-}
-
 static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 {
 	u8 tag = get_tag(addr);
@@ -497,15 +487,6 @@ static inline bool kasan_byte_accessible(const void *addr)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-/**
- * kasan_poison - mark the memory range as inaccessible
- * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
- * @size - range size, must be aligned to KASAN_GRANULE_SIZE
- * @value - value that's written to metadata for the range
- * @init - whether to initialize the memory range (only for hardware tag-based)
- */
-void kasan_poison(const void *addr, size_t size, u8 value, bool init);
-
 /**
  * kasan_unpoison - mark the memory range as accessible
  * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/28ddfb1694b19278405b4934f37d398794409749.1738686764.git.maciej.wieczor-retman%40intel.com.
