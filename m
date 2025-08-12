Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZEC5XCAMGQE7XW2R6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B36BB22864
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:28:06 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-41ea6bb72dfsf1580455b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:28:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005285; cv=pass;
        d=google.com; s=arc-20240605;
        b=ItiboUvOQHpaJxAX5jz/jSb3X3Eo38MCeE+UFBN+f/j7w3YlLxz03LQeGDhs/oY3yc
         m2TR+4m5RTuqI5Y7rydtewhVIDi5IgSyAO3yILWb+rPqkkQhJEy4iq5sKyXBW2ZGFhAr
         8HS3BCw3pEjT3Lwq7O6xMqrxk3iY/4H9B37H2qoIAunF1uCjs1LlOVRGeq9RaEf7K7gw
         dS5h80q82+a+FHdtgQkvU4HGZrzYF7U2IKQZiTBKfsis0tBepjdIjEAwK+SDTcngNIbj
         W4JpDhqiaxO48Le85J7BwkcrCr9sJagjH/BWKrV//TGLjw1wQ/1O0GLfC7UWnmdGxJEw
         L7gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=B4bPB3vAQouHU7OJMYaDxiXMVQBti3fUuFKjU68KSHc=;
        fh=Sayx5wN5t+hq2EMv5LqA38egYhPYjdBNBipU9yqbkDs=;
        b=L8WnWUaHQmweeIn26f4qQDXeQvSkzmwJH8F+y/QIduuM5029OfgkIdQc6seYQeJvSB
         cfOjLvyrOl4MVRascLDpWbFaO1iyuYve3zajTe7GGl4+dkxEajjy+aLWuuDKJjgBOxQ8
         Gq5wO/JGNXB8sxyQWiMaAbRujqqAemjOVdBHz89y7Kb7Lp59v59fY3wihhIJwvGHvt6G
         NqssPd0o3ln94Fl4qLlFDT7PrkHm9fYP4NXGwiYGkIZ8PKBzQASfynMXlzHXjtU+Cy7E
         mpvdgXDRir2QxhX4RzyqaxPLJKLK4k+2cBZC/enA88XV3CUe/quO8IE3QmLpopHLzawn
         nkJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RWRSvSNu;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005285; x=1755610085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B4bPB3vAQouHU7OJMYaDxiXMVQBti3fUuFKjU68KSHc=;
        b=G+MYWl5NkGTxyvidK9lCUnRyWiV7J4cwuF55R0pi8/4sjxbuz7XlxDkxAU4vyv7v64
         FjrE+D8sG8aiIP6TWuAqU/xUmJfBkSnqyeGfb8gwGXiYBAag1yyAbw91HK6WIFevkXk3
         zncVeyG5U3gqY/cCPOtPSJfC8sO+X5YP0L1yhOJ/ezGaLfcVEajUgTOdyjEG2YJyOlKR
         tmIGim+XAf/VfmvFiSTIUkXzRBoS6T+t5oBqkWQq51bKOISW0lpDZpJRbOmA0PUrTHng
         mKu8MYCKUNladSEXjWL6rx097z9PJ/MY5xENjK5Zh17puebSVN/z2VL/e4WAcuMRhlV8
         KxkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005285; x=1755610085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B4bPB3vAQouHU7OJMYaDxiXMVQBti3fUuFKjU68KSHc=;
        b=fYFxDwdT7z6wqcbLf6nfUamEHaIx+L6KfpWsYj0cbGOaBqU2SuhwlaAeywPI5rS613
         sZivwM4sO+8f2w6XkYMNY5WH4RQfSLQ0572WIelJ39zXRXKpD/1779aGVVlEfn0my0Ii
         U5hkGe2oDjZEak/cha46VsZ2JdTpjnZ4LtGVLy9QN+9466w79cvCnS0SVFGg/HQOMpK/
         ilbdbNRV7gXGIP+CR+uMexfu3GQkKbVx0oPycezACWTgt9sw3DT1ZjrXVc53vCnmgEO3
         RaLaeALuV44faS3gBn52SGLaL62ZN/4eWmqiycSDCTE2ke5Fscf08ttlf9+3ogoipp4b
         ohTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2GWVvRIKt/kmJQFGTXBTwUmrwngbif5PPX7Y10HNWHrSvSXgP4NsSvuikTP9dsexRmo996A==@lfdr.de
X-Gm-Message-State: AOJu0YxB2aENQDy0OipDeFkLI0FLZdW3A47g08wUvSX8/Edy2ovgh/E6
	owCKhtvT/G39l6uYY7OwjHP2l+VfXCKoYnBJEG53J0SJEQ0bEPtI6gWs
X-Google-Smtp-Source: AGHT+IFZL0JnsASWPTNiGif8UkG3tsX+rl2KbuN37TanAYLItQhyfsTHS5S+ZlsC6wsNsABtfVN8DA==
X-Received: by 2002:a05:6808:2216:b0:41e:8566:1486 with SMTP id 5614622812f47-435c923242cmr1588208b6e.36.1755005285001;
        Tue, 12 Aug 2025 06:28:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZda6FU3bAsKDaWgn2PTQbN2HAalcd8mnWja+jNF5izK5g==
Received: by 2002:a05:6871:7c15:b0:30b:d237:4ffd with SMTP id
 586e51a60fabf-30bfe706325ls1858646fac.1.-pod-prod-04-us; Tue, 12 Aug 2025
 06:28:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXReph6VJ1E6ewseg9Lix69dDab6+/7+2RB3XsYQPCUWtJizKpS6IhdsWUC78BY5LelK8RwEhTLq9w=@googlegroups.com
X-Received: by 2002:a05:6870:1b08:b0:2ff:a4c2:b52c with SMTP id 586e51a60fabf-30c95127822mr2098459fac.34.1755005284122;
        Tue, 12 Aug 2025 06:28:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005284; cv=none;
        d=google.com; s=arc-20240605;
        b=Avmk92Y3WIRTIPkU3zmb3ndTaWA5ayJoHcCmNUo8b8dK+E4PJ1GxxqrM1iIuG4ptrD
         +i/RwLstvlNgXO8tDdwJDT8dSZMguCl6YJtLCbJac3caYAIkVwXK+lUwRFdvujvl2/7h
         p3DuBxsSQ91T/IVzfIeNbGs+FKimP2hXP7mgR2VgsflD0YEAM7iyVWjqvEmRe3OHOGHJ
         SFxTtR4T6/CEGPSp7IjjStUGene+m+XgvMFmluXacN/FWAX3CnLidaoa/HGHCS5aNPVP
         Sp7l0yVqVZCT+WfqDdmhKd4pKViY6XDksJ2ThmwDC7h86moFrlwnVpv2Y9HsY4diBkSO
         2qTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8Yt/OTgZ/9yEnA4n8YiO4smWuTjOCRRH+QOana0DyvQ=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=czYMBfQifx8urUG3QblztkPffQUKF2TPwlPZiyX27S6u08uxRXjn4cRjqzMT6ngEm4
         9QKscSzVw1aq2CBqlPYeZFpsYl4r4IHpGfcu7fvHnYwulYJEkWU2ZltpZ47TVrdSQfZh
         j0CPjt/LZScKGT+BqRF27hnMNuzHhjwWDUpAM782ZOtgixuf1FyJykYqrA1aMT2g6xF1
         WTR85zzeROSzaKJtERspVi0iwNALtBwGJjilf2v1VE0sT7zJ5Ht9E4d2jKVNZJPlJon0
         7wrUPHfd7JbKLR0/YOee/meVWElEQIyxYxXLA+SInqAXJUQg8EtsFCxDtczVcb0FtT2x
         oN4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=RWRSvSNu;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30c0d115ac5si428575fac.2.2025.08.12.06.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:28:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: 838kKliEQfaaVkRH28EB2g==
X-CSE-MsgGUID: r5ssacTXQsyznd4GJo6DlQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903558"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903558"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:02 -0700
X-CSE-ConnectionGUID: 63q+EOftQWWQMSotLrPagg==
X-CSE-MsgGUID: fl7/gRLpTkieCVLNXAAdgQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831460"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:27:38 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 08/18] x86: Physical address comparisons in fill_p*d/pte
Date: Tue, 12 Aug 2025 15:23:44 +0200
Message-ID: <ef6496efec1b978c0f479a5cc62ff92edce82912.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=RWRSvSNu;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
index 76e33bd7c556..51a247e258b1 100644
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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ef6496efec1b978c0f479a5cc62ff92edce82912.1755004923.git.maciej.wieczor-retman%40intel.com.
