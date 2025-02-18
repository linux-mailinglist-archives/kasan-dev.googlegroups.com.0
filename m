Return-Path: <kasan-dev+bncBCMMDDFSWYCBB2ME2G6QMGQEKZSGALY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 14AAFA394EF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:18:51 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6e64dac8126sf75235636d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:18:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866730; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZxReE1/450TpzRam87WrtCTP+3C40tk3QMnD1/NBhe4cdcypkWOkxuarRY/qqmbB71
         /RHguPoolPsCP01LB60Kv1mBJHyp2oQKKVA/Vw48BU9OPh0Vcd8m1kRN2zEbAY06ZeTU
         epP3zn0S6lBvpguRi6teHRFhnM7Xyk441ivSwYxhgkUkUyFCtSlfEY01vbe1tMeS6kZG
         Xtf/WDZFOxnlGDEyzvLtqXIbpX06TEHy6PHWcm916oGCFvKDCyozJTjsMvUZyXAI6sQI
         WTbSXfLWtI4CJ8PO9MsFHTUmfGZ0KplEl4hX5Ogy3ftyFVsiNWHS+LTnmIMy8FKRVUv2
         tg+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CzbVQ33/X4cf4iDvSBj2L5IJ1OeIHA/VVLCnZnFLP7Y=;
        fh=IT7Lw2ulrtNGzZJRU/KD3RLcxvciv0ugo5l62MOMmRc=;
        b=UjHGAxKxsfX83CNgKhdf2QIAzoI6EAdI5mMNVzIN2Tr7Ae0swOmURf1fphHbG5D31M
         OU3B9fxJrTQLwwv2Y8LBTx8QuGrmTBLmeXLWWT48xXsGBYPRSACDE7eGlT7smwaFLL1Q
         V6VCoC7coxhAjOEZoncLTTRTlAq7tlO7PEolkqby7jegTGLznJQgINec7PXW1TEp6AJ+
         7SHjxQf1b0ruTRaof7t4Iu+n8ceb26Wf5SIGwwer8yuafIXRbVkapRSlveY7TWpalTz2
         w4r2QaD1m3EpVismOXsY3hRHlu1FJ53PeN7VwX5lRl1Ec/KTDgWJZNWZ3D+Uv+WYpT+3
         Uz1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MvF8gBZs;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866730; x=1740471530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CzbVQ33/X4cf4iDvSBj2L5IJ1OeIHA/VVLCnZnFLP7Y=;
        b=wHuXK8WPhehbrmbHz4wA3fJlN7xp385plOsX6YbLLwkjamcWdRkDmB3Pt3V3ViIkhE
         5RD3Eklr9SLJHeRyZRh5t9JJxs9PoGAkqXAyWxLGKsxqmIdATOvMbDd+NoH6Br8gWRGw
         H77VMbxsu/AEFUH9ogzmwGpL2vHcS6Od3JHPViOxEJ9bGHsiog4Z0lqULPVy4avmm3jW
         4PZFKkAuAYJQz1ncm3ZwuL+8TJDMo602t07m6H8TMXh2pLiV9rl82F6R9ifqBtxT9uc7
         cbkGx/C7P2pnLkEmvJY17S846BHJahwKti6UTmUlBCEIabmhwhgEupj9FwvD2Iyu1yVG
         ZFyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866730; x=1740471530;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CzbVQ33/X4cf4iDvSBj2L5IJ1OeIHA/VVLCnZnFLP7Y=;
        b=qSlAHB/Oe+QfZHNRhpGb99/kdSc6Z3SgdPgPxeXiQisw/d3i4Zz7BYc90qMH/+1I1a
         JELR3Fn/0ZdZIhcZxD8BbjIkrY+0gLKpORxfKfgRUYOWPZOhvGhLktChsUZhjfSSTqlI
         ri2Jg6DIoG/BzyOI9I5Tm48LZ/TPD6j6M9nasv5Cxzd1z7BuMLWg3WvA1KpBiltfKs/r
         em98TaTMVCMaaMdX0LJzPhb+x5MQTrwpVTAG7S5ecdxzyu/PqRA07pyeWSt3936UUnJ9
         yLK+PtfNiAE2MBffjU5CBpKGLCmqFLNJTnoUW/sttUlIPHM86k2G17xXsUe7H+vKKbzu
         kdHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYt7Ov9xA9Y4SVYypCiE0EaNaChs+h9uUJ7ckjmtQtA9AZFI51CfQStsVWaR9An76v+/GvaQ==@lfdr.de
X-Gm-Message-State: AOJu0YxFb685ScNN09biQODv5LFhZNKX/Ix4j2iHO9wi7n3Xolz27oeU
	LzxZ9YJ4IiiZwTarBG+b9ky/ZP3YZW7twM5Yp6IQT73tLPHZEIkJ
X-Google-Smtp-Source: AGHT+IF1fK6EY1dXHL0xdQo9lFE47ORr8xdNglTVpSehVJZt9n4jzS0V3qxopTpUpo/i1NjMGHd7mA==
X-Received: by 2002:a05:6214:27e2:b0:6d8:916b:1caa with SMTP id 6a1803df08f44-6e66cce6e34mr189955806d6.27.1739866730017;
        Tue, 18 Feb 2025 00:18:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGYAp2Kr80AxPD3KqtrYueig8U4fxZrivfpwLCAZfi9/Q==
Received: by 2002:ad4:5504:0:b0:6e4:4503:bac4 with SMTP id 6a1803df08f44-6e65c215cb4ls24721826d6.0.-pod-prod-01-us;
 Tue, 18 Feb 2025 00:18:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWWlXmNydN1xWoK/PuqkyGJzH35cXCkYKGoSmvk/PoX+BF+m3J/BTGGZF5J6pW2oIhnloyAj0IxJcA=@googlegroups.com
X-Received: by 2002:a05:6122:2525:b0:520:51a4:b84f with SMTP id 71dfb90a1353d-5209dad10b5mr6195006e0c.4.1739866729067;
        Tue, 18 Feb 2025 00:18:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866729; cv=none;
        d=google.com; s=arc-20240605;
        b=TQawh77NajzTI9m9VAYouP9w7+mPqn6ewKuHhcVvZqbXJW43qMA5Vd1FkbPdYybFcy
         CdRJ2nt8d/Mboa/Iyhbf6RKMbx69Y6IyPZjVBqX1LipWRJExEgdPTLmPrBd0GXzAA3pL
         6XgKhxWoEjWs0ySEaCGGKbIMGPQ6lwoCkT0qN+Wo2U5QbCPivB3UOOZAlvtk0UV26qUR
         leNoulneeFcNHXYA4Q9xy2PmJnA2D1WAsSdQizxJVskh/KPafnVlmNNuyXdCab8TVWOY
         2bjr7RRXn27PU4UD/SfVO8gIw5Z7CFcfMf3lmpCvT9vEdOP8M3tNHN8KgWgiXMjSFTVU
         DkwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Dq6MnYM3YBaeNWtWD0oUNO4zWYWOlBEkNt7N4mL1ols=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=W6fKqIYMDXxrgXwb2Ql3XzhrJFRjMZKDnyQXwrsM047sov0FQEjp5vhihn2rT9IgtU
         tbE5xfZ2RZIATSyk92vGn/mjGofMBKiDqV/phYVKy1qvsL7iMrLjIkTudCuBE8jOJL92
         H6jI3P5E9xgeMpI6noqJBfVeQfy73417s9T5oRpaH1+aozUm/b3cs2aoYGGx9lOGd5sf
         fNuEwxsLDkDnS+8sfgxh+od9RuOzUWaRVMKc9vMprvqOY+RUObXZ9ZDBqJBobpWrPxqh
         7PDpHG5eXjk6LseGNlKoiLbnUEmFXHPLnYP+b3RyRGRVOo5KqqJsN3/0H26Gq2LDZL2M
         ApxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MvF8gBZs;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-520b350831dsi208247e0c.0.2025.02.18.00.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:18:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 46e5nBbdTP+dpYCZL0InfQ==
X-CSE-MsgGUID: yaes2ZSnQBuaiv0+lLCSYg==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150303"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150303"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:48 -0800
X-CSE-ConnectionGUID: wF3cj88LRZaiNzHrGFykHQ==
X-CSE-MsgGUID: O+VYLHV1SG6BS6/LzC21Dw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247761"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:28 -0800
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
Subject: [PATCH v2 08/14] x86: Physical address comparisons in fill_p*d/pte
Date: Tue, 18 Feb 2025 09:15:24 +0100
Message-ID: <c5191b5bee5e0418752bf1c6159a2f0ce3490c1d.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MvF8gBZs;       spf=pass
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

Calculating page offset returns a pointer without a tag. When comparing
the calculated offset to a tagged page pointer an error is raised
because they are not equal.

Change pointer comparisons to physical address comparisons as to avoid
issues with tagged pointers that pointer arithmetic would create. Open
code pte_offset_kernel(), pmd_offset(), pud_offset() and p4d_offset().
Because one parameter is always zero and the rest of the function
insides are enclosed inside __va(), removing that layer lowers the
complexity of final assembly.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Open code *_offset() to avoid it's internal __va().

 arch/x86/mm/init_64.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index 01ea7c6df303..e555895dbb68 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -251,7 +251,10 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vaddr)
 	if (pgd_none(*pgd)) {
 		p4d_t *p4d = (p4d_t *)spp_getpage();
 		pgd_populate(&init_mm, pgd, p4d);
-		if (p4d != p4d_offset(pgd, 0))
+
+		if (__pa(p4d) != (pgtable_l5_enabled() ?
+				  __pa(pgd) :
+				  (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK))
 			printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
 			       p4d, p4d_offset(pgd, 0));
 	}
@@ -263,7 +266,7 @@ static pud_t *fill_pud(p4d_t *p4d, unsigned long vaddr)
 	if (p4d_none(*p4d)) {
 		pud_t *pud = (pud_t *)spp_getpage();
 		p4d_populate(&init_mm, p4d, pud);
-		if (pud != pud_offset(p4d, 0))
+		if (__pa(pud) != (p4d_val(*p4d) & p4d_pfn_mask(*p4d)))
 			printk(KERN_ERR "PAGETABLE BUG #01! %p <-> %p\n",
 			       pud, pud_offset(p4d, 0));
 	}
@@ -275,7 +278,7 @@ static pmd_t *fill_pmd(pud_t *pud, unsigned long vaddr)
 	if (pud_none(*pud)) {
 		pmd_t *pmd = (pmd_t *) spp_getpage();
 		pud_populate(&init_mm, pud, pmd);
-		if (pmd != pmd_offset(pud, 0))
+		if (__pa(pmd) != (pud_val(*pud) & pud_pfn_mask(*pud)))
 			printk(KERN_ERR "PAGETABLE BUG #02! %p <-> %p\n",
 			       pmd, pmd_offset(pud, 0));
 	}
@@ -287,7 +290,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
 	if (pmd_none(*pmd)) {
 		pte_t *pte = (pte_t *) spp_getpage();
 		pmd_populate_kernel(&init_mm, pmd, pte);
-		if (pte != pte_offset_kernel(pmd, 0))
+		if (__pa(pte) != (pmd_val(*pmd) & pmd_pfn_mask(*pmd)))
 			printk(KERN_ERR "PAGETABLE BUG #03!\n");
 	}
 	return pte_offset_kernel(pmd, vaddr);
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c5191b5bee5e0418752bf1c6159a2f0ce3490c1d.1739866028.git.maciej.wieczor-retman%40intel.com.
