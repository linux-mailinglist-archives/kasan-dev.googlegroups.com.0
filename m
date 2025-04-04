Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJNXX67QMGQEPBMTCKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 5670BA7BD6A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:16:23 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4769a1db721sf52407051cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:16:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772582; cv=pass;
        d=google.com; s=arc-20240605;
        b=DDsCmuQVkrk3HFDjoyzdRDsVE2/pMrjrGPFa0G91mzMO28a5Sq4rPA9xcmmi48guwk
         YzgdoErC8FsZelssDszHJY9ePZWqrxy4FreXxlSlf/gFDb89yraCRl7EU2SB/aviqZTv
         uTvG2Zs4gOK0Ozyz2irz7eF6FRXezp4AAq4l0l0h8WMkXuExp+smfBCzElLCf2aCIrri
         +LaoCxZj1FoAvvBfD3mjFL0cFHLq5uREQRRNOc+0I7eEshN8TazHAKC04ky9h9jfmvwF
         dNT8tI/9oXBpOugJFJ78W3wAnqZC3lwC7oY/A0c/qa9DYgEgkFAQn9dKoKDpWJ/cqE3m
         whug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nlZwMDjtLuNwdyseDCaZH9G/lkyGq7b93+2qVmDfrpg=;
        fh=TDMMdsg456RE3/Ef+i5QSYMkAHA5COKvU5ASOs3jRBk=;
        b=aZizHS1eBY+mO7+NFkB/cyCEkFSBqUGnWReNF03k4gwHNWP0wXROT7jt9rNDi+/y3b
         hnZZTNzaPNY9fqNQMl9c7qjTFaQUyCEe1fGqll59VyZ55e93rQM0mZMFE7J/+igyvyln
         DKKzLMHWzb9ui1lC92sENFgThOtaw/6H9M30Wy5M97oPJbnF9qVVevPY0MQSd5sRYCf7
         hxiFuCzsq36+dCVF6rLaJXWtctGnqj2G1DgbKvYo59v0OW0endLGOHgcUq6TqT/pMWYR
         f2bPjLntYBL0qRJVhWG/sOpvDOA0qfwOFS382Po4lQAbmk63es+1/GvvXIZn5vOeR38l
         AgrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ny2OzY9C;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772582; x=1744377382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nlZwMDjtLuNwdyseDCaZH9G/lkyGq7b93+2qVmDfrpg=;
        b=DDSL6B053nHifWoeTABToCozC/G2L98wpj94pzR8xpHiDSyWBLwm6ccqCzz4cXBPEE
         2cHV3A/Dkp7vmB5KouirrrGK1FlPAI204jXzbm0QSFBtWRKDtlMOdeHlOY7dWDKjlro0
         VX94MC360g/6n0OTYI0z98Rl5XVXoommvcCBcNd6HI7A2ZQmt+fDWSz49JpSMNSN1He0
         +a46Nutvah030H2/WCO98wKNEDchxJcb1gFgLtgBKdYdw2lA1t0cVhXnv5mo4hNgu7gd
         4734YDqQK3kbLgrVh7uCcwylhoLqMSZp9qoAwcfeXxHDugk3K7OQ1ScPxWdH/en+Ugm9
         KWkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772582; x=1744377382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nlZwMDjtLuNwdyseDCaZH9G/lkyGq7b93+2qVmDfrpg=;
        b=ZhmISkvEiUatUvIJCuqBmASF5M/fMz06m7GdLmb/AL2AXPzw5nOhRs1SNzIQjM7EF8
         zfFi0/OvkpXKHXWu5qCataB0L7bO5qYO5975W9ej9Z8HvpHx8281HnbkPD0dcYmrgQ/c
         QK1NsedYXH46yPxaI1dfi+wczeHKW/jaGxA2w8PTh1ESJOAWfw/aQHzq7yI1RPzNosrh
         TUeQvPbTCns13egHIdBdduG2De8ceG0BLISIxum+TrmVN/+r/vxl36Kync6APk03Z5or
         XcnVdAk79Kx3QnDLQaN2dBSpIJcsF9pF4KBwaqgOYGUyqdg+KdQB158UFV6d0tsyawCR
         TaTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGiZ+Tb38CeECBzOxGSFvww1FW5C4o7Uu39Wb9h84KFHlwUMXw1LDy3iP9RW/DWRrnvIDqTw==@lfdr.de
X-Gm-Message-State: AOJu0YxxUFaufAlPio+fGiZ78npjjqBDw/xTIuv58f5M4qfqnBFP7Ngi
	ZzZcxLgX9P38y/2zBuhElmMnc6UUBjrx50dNPMJ0vvVvkhF6rNye
X-Google-Smtp-Source: AGHT+IHp9RtdnCUYINkxCFkM/mYRl6PmyBaf+I7gH+rIAbRq2YR3EjlRDLRC1xX2ON22yUDR9BFA6w==
X-Received: by 2002:ac8:7d8f:0:b0:476:8a83:9617 with SMTP id d75a77b69052e-47924936c1cmr48908951cf.21.1743772582153;
        Fri, 04 Apr 2025 06:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKUrymEqsmDUxGxNB9z5wiJWPGULwaEV38b5fJdKC+NNg==
Received: by 2002:ac8:45d2:0:b0:477:7740:602b with SMTP id d75a77b69052e-4791639b121ls35281921cf.2.-pod-prod-06-us;
 Fri, 04 Apr 2025 06:16:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKTpmjV6xWpfDxlLs5vapjT/uhGm7qCjwUoLfDSZlyupCnJQ8jQ+n8c03cIh/y1EpRsRkVzTJyBlc=@googlegroups.com
X-Received: by 2002:a05:620a:198a:b0:7c5:407e:1ff8 with SMTP id af79cd13be357-7c774d275eemr418824785a.2.1743772578848;
        Fri, 04 Apr 2025 06:16:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772578; cv=none;
        d=google.com; s=arc-20240605;
        b=lLZFM/wNderFNPr+NbC+Rb87nGWsA/wXDqGyTSuzK1Kz3iAUJJ7rQCWvWrn1wzC9I7
         CwcDl7t2CkFUcnDDgkZKrCojgz6EV8qcTpxaWzI7jq06zy9O9LXmklx0I1b/WeSMM1eN
         PXGboUc3c1/JcC36RW9JZSiKQXrS50RmLH+uVZWjAtT3PONo4vqmGpdIIu1myY/1cztw
         zVDow6b1sukYI4+OIFwbGkfstfh6P3HluSjSaebA0mP3F3EtkDarnv0vtDjWQWYvWTsU
         9auASnslbs/FfVSGqDlT8R+lakIOofAzkh24+v8NuGuBaPAkv3wuClMi8LdDrPqDYwl+
         KIFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KdeR7X0VD5TGF1E859GfE1E2NKkX8Ya0qtNSI/kkmbg=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=l0yKrsktU69iCmO+Jy16YWR6rvjnaiv0oq/GHWMGTyw0oCmxbJ2S0UQ1d1FRi939ZT
         pmXMoVeA2KNaKJ33b9F6aekkxF7CT5o88oN6S4KqVeseVKaL5uj9Pq8OMzBo8wxqs0fd
         3gmc6+Qda9QbzVZm2g3bxTR7hUUisUpE4Igizz3beLU0F4I54SYBWWGok4++p0Q4HGhV
         HXJ+7pvQVwIJCxoMEeI9M9e71UT970jqp0IThLrFz2i0MOU9ZEEN6OK+komre0jDkuDu
         AVrhinUDZC04ceJjax4FmtZaekME559nyGC//xmkrruWnjqxgOsqR8GkP9bQstXq4ItY
         8caQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ny2OzY9C;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8738aefc2d7si144120241.0.2025.04.04.06.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:16:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: otNKPnvDR+euNsg7mu+dFw==
X-CSE-MsgGUID: EHsItd5qT++xRjW593N0RA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401763"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401763"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:18 -0700
X-CSE-ConnectionGUID: 8CO0HA7DQ/SZXENmyMAkLw==
X-CSE-MsgGUID: PBphbyn9T9ueR/8k6hXkMQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157194"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:02 -0700
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
Subject: [PATCH v3 06/14] x86: Physical address comparisons in fill_p*d/pte
Date: Fri,  4 Apr 2025 15:14:10 +0200
Message-ID: <926742095b7e55099cc48d70848ca3c1eff4b5eb.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ny2OzY9C;       spf=pass
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
index 519aa53114fa..d40699c16f14 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -251,7 +251,10 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vaddr)
 	if (pgd_none(*pgd)) {
 		p4d_t *p4d = (p4d_t *)spp_getpage();
 		pgd_populate(&init_mm, pgd, p4d);
-		if (p4d != p4d_offset(pgd, 0))
+
+		if (__pa(p4d) != (pgtable_l5_enabled() ?
+				  (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK :
+				  __pa(pgd)))
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/926742095b7e55099cc48d70848ca3c1eff4b5eb.1743772053.git.maciej.wieczor-retman%40intel.com.
