Return-Path: <kasan-dev+bncBCMMDDFSWYCBBENARG6QMGQEBKPJMAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 96503A27897
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:36:19 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-29e8124e922sf7957211fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:36:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690578; cv=pass;
        d=google.com; s=arc-20240605;
        b=kiM+n8d5dkwSsfKvZVNvR7Y/RRaejVcguEfwTrgC4RKfSLmcQjwbmtaGsEMPHuVFNS
         +c80FedYEjuDtMuMlP964V8gvV9ABAWBHFeP7A+oEv+cMPSL8yCrzWyimJi5b+ZFvZ1X
         Yvlt6GJeVA9kC35TBCcO0B3gKg5rQhuO+FDTzukBpU52jvBig61R+sSF1yj4UKLsrGFm
         veYu6Iy/hlrWGfRAcDBICGQlZphpypmslaqRNlNOWMy5cnBYvLkE3cMSMj0mupOZ32Wp
         kdtqeuZATzsjbVJ8wvhvOObtAhh6eqlSsX7Hx9SxLh9butZkiE0NEyCRcJIiyw1Oanfw
         T8rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TkiG4+SkBObvJUCFtTlTcaU22Fpxaew1DJ7j75vzoZc=;
        fh=6gPXVdquuC/PQR3lHBgGGFmqiXig86hP6LI5WQmQQDQ=;
        b=CkSSoenjEd601fyPqNKmPWwpObzHuQIm+KqQXLRjZIk53RXmk1nVZbJGC7fab348XX
         px7cx4mBfROejXNtLIQkPmV0KJ92l7iR3c35Y8vlanJln7nTYJuRlDFsW1mldsQZmgr6
         9Wq7XE5WoDkIybKTQqmCyaKMzpCJdUDkiRl7adprRjR9zT5O/pw1If2Q2/wLNcLD47E8
         5MrZd1Pvgt80B1i9SMDPwRfvlFO3Vwhh9guoVMhWjAtvbe7y324K2F8k0eQNjdPVSQjO
         jCmgIexkjveRRFsScrS4yj6dbxczeo7hfCP7A2L3JtV3HL1EbszUwemr6wKSaYcPmxeW
         5XhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VW8l/rCH";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690578; x=1739295378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TkiG4+SkBObvJUCFtTlTcaU22Fpxaew1DJ7j75vzoZc=;
        b=kXieRXCJ35KSA43P0AtAqFDU3A9Ebl+x9P13AJDW6KyrZPCZy9jXrTyzAvJfZWrMVk
         VnZLKsR2QodYchLkdQPz9+xM4jvTnx51aLEPti1vPlbgs6PlZ/HEwODSKPNM8t2mNfmf
         7D00o7feklAlQg+F9eWDFXQQxansklOSNJkhvyE5ppAAsqqDbLlnYqkVojnCqKP1DEWB
         PpCbGVSWuro0CH5aFvsWM+kj/dknAys8MiHBDmoj5sRdgZUFP01onTDlQ2CJPScyZBQ/
         Luo8fMOtQ4kNhlbicIUFKqhFd3HBpzTVmbltZD5p3KkZNr0MF/g7MixWFQ9o1GQe0+dc
         k4Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690578; x=1739295378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TkiG4+SkBObvJUCFtTlTcaU22Fpxaew1DJ7j75vzoZc=;
        b=UHfFi4C1o+3RfcEPOu0TZ5Vw/xAdxgKjJKIWxlg4iMNkszVd3glZ5qMgug8Ts26p8O
         zdBS++QyjsG45rc3OVVsmNWx2f7cd5vlPta9ZoPE8HQtL33Agc0NutITOpJ7cdTTeD0E
         wt+qncRPEZhLCkHh+SPd9r2HhU5Eaoe3SmYOGhIR2DqiqLEjmUoRE9S0Fe3on3449QTc
         LpfXJt06ebH+/rom6QkpNTUU+pI9CvcuKyLPfUC2sNVRS4m+PIaWVtKvuFTelG09CVKI
         MVZthrx5uXMdDtKuu5bNmPZ0Kqqofh9VffNzxdUn4/nY6Ytl55qIQp1rWaa/qeBedOnC
         B0Lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWR5X/SV0aGZVObHn8wyAyC8WrmPYJ7Mv+RvciUaiZmF4TEfckFZKN7TXiWwtv7hsriQ0iUIQ==@lfdr.de
X-Gm-Message-State: AOJu0YzqCi6Z54DMK+ygo17/PsPNWE+sKuV3T/AHFraa2o5yTkfwGfGE
	LZrr8J+ai1YBVHJzZ1vKJXNW0qpVvgRRFl2gK8uLQ/f5JpyAa2vF
X-Google-Smtp-Source: AGHT+IGC6lobsZgQE4Kfg5SZcdYdPdDoHlySbMNlL2sCoDREGMsuhRG9TI6L4Sbc+34XkPgTRXKazA==
X-Received: by 2002:a05:6870:a691:b0:29e:5a89:8ed8 with SMTP id 586e51a60fabf-2b32f01109dmr15410527fac.11.1738690578152;
        Tue, 04 Feb 2025 09:36:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2f10:b0:2a0:1e92:8674 with SMTP id
 586e51a60fabf-2b350c8ee6dls1004823fac.1.-pod-prod-08-us; Tue, 04 Feb 2025
 09:36:17 -0800 (PST)
X-Received: by 2002:a05:6871:a011:b0:29e:6814:19d with SMTP id 586e51a60fabf-2b32f00e66dmr16573884fac.9.1738690576780;
        Tue, 04 Feb 2025 09:36:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690576; cv=none;
        d=google.com; s=arc-20240605;
        b=QpqMm/vSiZ1SZ5Op7klmDc8oVXt2ev6t3EEdANLgw8HhbLLB4MUvCT8f3fx2ADD3Ho
         ve5FDNFGSnfwXKbt60mLiI2rvm6hAOlIyIwJX4l5FUcdp3nJ2+fcqj/jx+cgT5e+Iicc
         4zDZ1vS8S5M4vmuHDPnbRJ1ooDIJHhlLuFUeVjG0stuOIO0bJXRPI7oypFOMiaJaOP/O
         /pqpoyI6nhy1MWUEbizlvZsU0tCAvXbUtNZkx04gK5nyzM+f9rs7g8WFoIaUCVP/owem
         UJwcc8mNq2TC8BixeC09AgZmzutB0AcKJsTSaWNPDv0CUkqPAL954se2HqE9GT39ysTl
         kfOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lQ5v1NnA6R05ztWWI7B+8ia+Rd5WZ3/fmwVsOhBY4uI=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=VfjI1cmf/xBOYb43gkUi1wjoWF8BwRIRgt985xalVbdxz19mJTA4DoXNK2jRBsWCN7
         atIXXih4SuTu3HxOdwNN49Bhw4aoeFs972YE2tfEufj5mwDZRtsFmdOa34732xdMF6Aw
         gZDx3Xp4zLYWWUdgT8RifDUW7JkWrMhCwx6pzeWkDYAcLq5qOmlz1TW0cqHV8K9scL9p
         q0hnskLg9pYoSSfUqWb5CfX9fdMofErBe6dVTh0JF8P0kM3/sF1u9OUD389f/IOXK/Kn
         fCde6C7zmQA9MVVGPb4Yg3lRvg4O0oLtXvTCYRiFi7a3HqtX1+WnNvcqZEL1iYfgzs7c
         nSIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="VW8l/rCH";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b3565b748bsi585850fac.4.2025.02.04.09.36.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:36:16 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: f3QBbjSKQFCnl2lD0Dy3ww==
X-CSE-MsgGUID: qXK/qWCISLuXeZW8Ca6RFg==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930739"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930739"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:14 -0800
X-CSE-ConnectionGUID: +qvwGRPBT+u0hTrJ0ps4gQ==
X-CSE-MsgGUID: gKQBPywxQQq2MfdmEZxhgA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866742"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:36:02 -0800
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
Subject: [PATCH 08/15] x86: Physical address comparisons in fill_p*d/pte
Date: Tue,  4 Feb 2025 18:33:49 +0100
Message-ID: <2c2a71ec844db597f30754dd79faf87c9de0b21f.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="VW8l/rCH";       spf=pass
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

Calculating page offset returns a pointer without a tag. When comparing
the calculated offset to a tagged page pointer an error is raised
because they are not equal.

Change pointer comparisons to physical address comparisons as to avoid
issues in KASAN that pointer arithmetic would create.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/mm/init_64.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
index ff253648706f..bb101412424a 100644
--- a/arch/x86/mm/init_64.c
+++ b/arch/x86/mm/init_64.c
@@ -251,7 +251,7 @@ static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vaddr)
 	if (pgd_none(*pgd)) {
 		p4d_t *p4d = (p4d_t *)spp_getpage();
 		pgd_populate(&init_mm, pgd, p4d);
-		if (p4d != p4d_offset(pgd, 0))
+		if (__pa(p4d) != __pa(p4d_offset(pgd, 0)))
 			printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
 			       p4d, p4d_offset(pgd, 0));
 	}
@@ -263,7 +263,7 @@ static pud_t *fill_pud(p4d_t *p4d, unsigned long vaddr)
 	if (p4d_none(*p4d)) {
 		pud_t *pud = (pud_t *)spp_getpage();
 		p4d_populate(&init_mm, p4d, pud);
-		if (pud != pud_offset(p4d, 0))
+		if (__pa(pud) != __pa(pud_offset(p4d, 0)))
 			printk(KERN_ERR "PAGETABLE BUG #01! %p <-> %p\n",
 			       pud, pud_offset(p4d, 0));
 	}
@@ -275,7 +275,7 @@ static pmd_t *fill_pmd(pud_t *pud, unsigned long vaddr)
 	if (pud_none(*pud)) {
 		pmd_t *pmd = (pmd_t *) spp_getpage();
 		pud_populate(&init_mm, pud, pmd);
-		if (pmd != pmd_offset(pud, 0))
+		if (__pa(pmd) != __pa(pmd_offset(pud, 0)))
 			printk(KERN_ERR "PAGETABLE BUG #02! %p <-> %p\n",
 			       pmd, pmd_offset(pud, 0));
 	}
@@ -287,7 +287,7 @@ static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
 	if (pmd_none(*pmd)) {
 		pte_t *pte = (pte_t *) spp_getpage();
 		pmd_populate_kernel(&init_mm, pmd, pte);
-		if (pte != pte_offset_kernel(pmd, 0))
+		if (__pa(pte) != __pa(pte_offset_kernel(pmd, 0)))
 			printk(KERN_ERR "PAGETABLE BUG #03!\n");
 	}
 	return pte_offset_kernel(pmd, vaddr);
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2c2a71ec844db597f30754dd79faf87c9de0b21f.1738686764.git.maciej.wieczor-retman%40intel.com.
