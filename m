Return-Path: <kasan-dev+bncBCMMDDFSWYCBBVM7RG6QMGQE73UTUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D74B3A27885
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:35:21 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-71e1dd4c277sf1746859a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:35:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690517; cv=pass;
        d=google.com; s=arc-20240605;
        b=HpM1iqGpOtJMVKRMrZoepMJc6pnJqsgzwd+MMnR9B8i3Ru+mrDtWuZktNzs31+rfCd
         IaSRHifJ5zGhJGkQ07kYgNCB3HzBXMnF+mvdoUxmAeSF4h0wUN/67SUk2w4Rju7nbwNM
         8jIJL+CIrpWyq1Vg+CJxc1dHARFPYlVxiA/dPpSJ8DCz7WdeGfAhrztUJTF+4hN6cxak
         Qx2otKs/PYS2AMOMiAs4JmYIxouvZ9xf6hF7X9zExXjUywWn19pWwi8FwaJCyncJ8EIl
         7NtQYhzHUJbnto3PqF9ijXid2K0R3EOpx9p0JQteV7gLyOVL9w2RG3CmTQMiggBcV1xH
         E5yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=K+KdkHghJRbBLuKNxPdqk6UN8dXwcZUBjHS+hI8Ek6w=;
        fh=DooHjTMMi57P2B9SyD/gIIh1JTOsZPjWroMoHwuXsBY=;
        b=CEkHmtcYPlbzaM5AHhG/XHwQ4XAIc3SmBS4AuzXJr81BHfhMCtS87CCDbJnM3zELUY
         C8RzWYdiQFpXxIt7GHZjUNWlfnXwwi7rqR5RmRFXKdvZ4yBAVNbFcYY97u6Tf1GqBvwB
         2tPTfk9G+pU+rdrigd9RZdylTRbir/UB+mPbfmwKlUCB4ktj61+eT9iT+m+tsf0OYiEc
         j1Tqr6LzH/SBgPTTb3MoKZVYfQIFEb9JsLn4IviDb0KJSPOHLs9Zl5zMb4VMQUEclcyC
         4VOJ+FZcK7vBJRYayjR4hYWjVMsFx3nobYbADIscx7wlIh2s1C7av2uWJXpsRUnDr1z/
         exiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lNICcpBG;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690517; x=1739295317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K+KdkHghJRbBLuKNxPdqk6UN8dXwcZUBjHS+hI8Ek6w=;
        b=ER0QPSWV70OrfZtagX6YypvCtVONDTUuObK018wPAdO9Go/mdVRjKxnwDQbZRaOCtS
         Zb3qBL7kDDQ0Hctrapgx1N6AhKxVyfHbBnzcOy6YRBz0+Kn+EMlRvlgqrHBUguf+pM1V
         DQRQHlALTWBxFyCOV6L6XP0qclP5PD9/6N8oqJFO9PYQTh6bUmMRVDhJHr2YbPZZ9Ie+
         7+f5e+w30qH20g8tDzsPJ1YTDp2XRIFYGGXytJqY38PLOcTie66p6NvamZ81Cwx+9sqC
         NzDtR6f/2ME9HvxEY2TIYg9/6EBI4lZONgsPwqsfXx4cfb50TtyWoZddEz+DUzv/3aEl
         BW+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690517; x=1739295317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K+KdkHghJRbBLuKNxPdqk6UN8dXwcZUBjHS+hI8Ek6w=;
        b=gR2zMJATe7wWR+y8yStuyVdKkvTgrq8r8V/vnyo7xawsYk/DY0mOZfjh5N9eIBUgBO
         yZWdYfEyI9Is/jxdK7/YWyTSzlBQx0x6Sn2AmTNS2V+2WPSob/GUt+ixTRQIb3RmWv8W
         0/g5pGzo8Pqelb1Q0qd7QmkZKtsAYo4XO8BrTf2p3IAHniReJZ+yashULdYvHaBCX4VH
         nmyC0Xa/wLOZWbKtcD143OdWVP7rIz51TsiUNMM2qXZLt/v9EsBcXvhagANnCHiaiDof
         qA4IryLXoPaSF6LxC+d0cYjEG3+nMO0kr40soKfpAQAJCf45UU/EBT7tpGxVTklSPQ9q
         zp7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXykD3lHzfqisMOvFVdmp/FmXvwt+2euQQcgLjLEbljpqTa88pOnVilPlTIMM1QDBUrWpsAIw==@lfdr.de
X-Gm-Message-State: AOJu0YzcZKepd2l3004IYpBdj14wCIjk1c9Y+CLQTUu8iECAJoeTwLwH
	NyP6U2WqccQpMjpASUAvE/VUJhpfpmXOg/V55wqXpU5Ur5De9fxc
X-Google-Smtp-Source: AGHT+IH/1QLuMbT/sMXj5283MnC86wV74XqLGXipSYGqiKNpH+jFEssRiiOATW/IcHO0XmwjCO3MnQ==
X-Received: by 2002:a05:6830:d89:b0:718:9b8b:429d with SMTP id 46e09a7af769-72656732108mr17196069a34.4.1738690517455;
        Tue, 04 Feb 2025 09:35:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a16:b0:2a0:218e:bd25 with SMTP id
 586e51a60fabf-2b350d3f174ls647268fac.2.-pod-prod-04-us; Tue, 04 Feb 2025
 09:35:16 -0800 (PST)
X-Received: by 2002:a05:6871:3a83:b0:29e:67cd:1a8f with SMTP id 586e51a60fabf-2b32f2ed3d8mr14352782fac.37.1738690516434;
        Tue, 04 Feb 2025 09:35:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690516; cv=none;
        d=google.com; s=arc-20240605;
        b=Ikpke6FKX2GlOa8zJdk0VdtF6uoQINQ8BLMnzPCWGaCA64QolPZBZJqRn1jOu6hI36
         xTUCqz+cj5MSmoU4DfZUz8eX1B0+g7ecnRZPnU4a7r2xmwIOEAWwtsJDnkWFpnbUIH0f
         LaRjyaR9/vh5tAMqv/Uhr8cEWMLWyA6kHYypeJsjo5e6EIijtyvLXVnJyeIhFLjCKEb5
         Fw9N3MtOiIswP/GiB6MlSkMeGy6G5NAMuqYvPADBYHxHhFZVfP2nCrn20AyNRr/UU9l9
         0oot8F2yHQZadmmNKyqxb1v6rN6V0bFHvumZIAojiFjaiTJc27ySkLbsyUBMBbOmNoai
         Gwyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WFW8QfccSsjvCfxPySJ9vuy2PIzxbcJNxEP0RlFEUe8=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=az7lHk6hD98vXwPMW6sT8BbY0bBPSTw3ppKYkJfvg6EmW6SbLskqssimW8d9/XCJAx
         zwoNQtTcPvFV19tg9RMuubQ45jGohSPsXFSdGg8EALwQlThFVaw7N9mRZ7fPmYqM4/9z
         JCESsiexIZ2r33geFxn2PALQQv+PUPTUzTEZ72KggfZPJ7OpmU6xmNU92iZNSLxDZgJ/
         xhxA3DDDLSHoryqz5vtSTPI3LBvBQTEg4ZYFgt6BHd3GEW668kKDEK6Jd6npLEKADGNQ
         492TjoVztEOow/T+TyM9sswaUoxVNM/Aroo81IYIDUVgV7VOvvu544Sc38o5Cvc8q6M/
         4sNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lNICcpBG;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b35653c699si501066fac.3.2025.02.04.09.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:35:15 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: 5P2My6yCTruhcQDvS9qb8A==
X-CSE-MsgGUID: rpGzV+pSSWidqCH1CU+Aug==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930442"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930442"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:14 -0800
X-CSE-ConnectionGUID: GXavZLsESKizsbio/E/Srw==
X-CSE-MsgGUID: e0b52Ax9SOSm68zuxVJ9gQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866342"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:02 -0800
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
Subject: [PATCH 03/15] kasan: Vmalloc dense tag-based mode support
Date: Tue,  4 Feb 2025 18:33:44 +0100
Message-ID: <a8cfb5d8d93ba48fd5f2defcccac5d758ecd7f39.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lNICcpBG;       spf=pass
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

To use KASAN with the vmalloc allocator multiple functions are
implemented that deal with full pages of memory. Many of these functions
are hardcoded to deal with byte aligned shadow memory regions by using
__memset().

With the introduction of the dense mode, tags won't necessarily occupy
whole bytes of shadow memory if the previously allocated memory wasn't
aligned to 32 bytes - which is the coverage of one shadow byte.

Change __memset() calls to kasan_poison(). With dense tag-based mode
enabled that will take care of any unaligned tags in shadow memory.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 mm/kasan/kasan.h  |  2 +-
 mm/kasan/shadow.c | 14 ++++++--------
 2 files changed, 7 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d29bd0e65020..a56aadd51485 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -135,7 +135,7 @@ static inline bool kasan_requires_meta(void)
 
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
-#define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
+#define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_SHADOW_SCALE_SIZE << PAGE_SHIFT)
 
 #ifdef CONFIG_KASAN_GENERIC
 #define KASAN_PAGE_FREE		0xFF  /* freed page */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 368503f54b87..94f51046e6ae 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -332,7 +332,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (!page)
 		return -ENOMEM;
 
-	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
+	kasan_poison((void *)page, PAGE_SIZE, KASAN_VMALLOC_INVALID, false);
 	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
 
 	spin_lock(&init_mm.page_table_lock);
@@ -357,9 +357,6 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
-	shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
-	shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
-
 	/*
 	 * User Mode Linux maps enough shadow memory for all of virtual memory
 	 * at boot, so doesn't need to allocate more on vmalloc, just clear it.
@@ -368,12 +365,12 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	 * reason.
 	 */
 	if (IS_ENABLED(CONFIG_UML)) {
-		__memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
+		kasan_poison((void *)addr, size, KASAN_VMALLOC_INVALID, false);
 		return 0;
 	}
 
-	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
-	shadow_end = PAGE_ALIGN(shadow_end);
+	shadow_start = PAGE_ALIGN_DOWN((unsigned long)kasan_mem_to_shadow((void *)addr));
+	shadow_end = PAGE_ALIGN((unsigned long)kasan_mem_to_shadow((void *)addr + size));
 
 	ret = apply_to_page_range(&init_mm, shadow_start,
 				  shadow_end - shadow_start,
@@ -546,7 +543,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	if (shadow_end > shadow_start) {
 		size = shadow_end - shadow_start;
 		if (IS_ENABLED(CONFIG_UML)) {
-			__memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
+			kasan_poison((void *)region_start, region_start - region_end,
+				     KASAN_VMALLOC_INVALID, false);
 			return;
 		}
 		apply_to_existing_page_range(&init_mm,
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a8cfb5d8d93ba48fd5f2defcccac5d758ecd7f39.1738686764.git.maciej.wieczor-retman%40intel.com.
