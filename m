Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZUOWPCQMGQEG7TDPFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC0AB34BD3
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:28:24 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-3254ae38a17sf998359a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:28:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153703; cv=pass;
        d=google.com; s=arc-20240605;
        b=PMf3VWJNqCR0UjnJn6ktHfg8QyKRDO8NakhXyG6kO20x60vtHlAfTEBxDSfOS533oc
         bYWgkRG2WWYHtLAVcaxiPyTp/xznUtamVawDT+Un5kxAD2dhmK17bZ8Hd72XH/7kpKqb
         Uky/HIBzaLzh8b/4uhWM3fkPnG8BBpIjBmcRnBC5ryWxWbXGCQjWzWB1WOeh5F0kCc8O
         2EsS1vIP38Rwz2S9YFAtVQLD1fE1umhy9HjKLFQOem+jqxxmPljeW6RDalyko9fBeoj8
         qwiFsbfjKi6zlTG1UqjjrH7xSVmBaQrOJCdk8w3am5UacOzUgbatmM3kBChZpFV6wAAJ
         f9pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cYW6LZPpxD6ogJ0UYjRzrA0dvu0J9TfXoh63gMEe1dA=;
        fh=WaTXlH3GRqueA5cuedNN517Mc7Ybow1B3uJOLK6oEGY=;
        b=LESSqh92WrPYgs9jxphYrWG39r8Zd5JF+I/ccgJ359mKk85LkACmX822gQcfD2vKEl
         eZG2w8u8+I4eBxx5Ag+CMtb7ZfuOxtX4LVARALmJnelyVCR8RhkWPRJwWp52RKGmEeef
         bgFnNr17VykcLF2JqVCEWB2gD9PpxMXDCsGiYE/+QVXdUPtcdmW28q1cfcilLo7g3HND
         F6xjjN5wVly0k+mYZicPiwNePRNYLUztVbo8/onnf4fnSVeMhMNpXeVYzxnjYa9YHktW
         QDkIUpqYRzyIHRum6q8vPHbSXcDk3S7vuvSE5s1H+VvBBRuqMoB4mMMhiINuo1Bct4yM
         2oIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BVCpFbD7;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153703; x=1756758503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cYW6LZPpxD6ogJ0UYjRzrA0dvu0J9TfXoh63gMEe1dA=;
        b=XIkUK7yxyoc53p68J0tR5CBGxso2oya+ekbVbaALykV7kQXf21ZNu5tXaBNFfd/U8Y
         vIV1oZXzHmjE98d8zjU1cYAlX//2aBPVuPJ7xh3wZ/b+SKpOlrkkqUjD/vWwwkR+wtvq
         pwFCIzSlCuTDBBQmpPnIrtPaMLRmp/VBJhSttrG/2Bons89QoDMfEj0o1x1bYs4Z96+2
         CdWXdBcRwdzclM/Tf50x7RYRhO2DSWIgHkeircCoLFrJDJ+lVhj2Lnb6vEggy+M10V4O
         qxj50DIB8y6a+GCn66CsdWRHSqupWy+zhWOHO0aJzn+qaUZj82wOUwlEqDjd5+rkWxaL
         KmAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153703; x=1756758503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cYW6LZPpxD6ogJ0UYjRzrA0dvu0J9TfXoh63gMEe1dA=;
        b=hGbnet9fwroWOwWnMfOnR69gpzFXtNLrywGDrCwHW3ndh3aTn/O8fzEN740x/6n7yK
         hpYX4SV+XfG8XZkv1AXMa4jRD6Ahbg+M9Ju+EV01aSw4i3iQmQzB32/fMbPZEFqsT1bE
         /9Jh4B3YWJiRDP5fQj2yvupVZv9Fm6FH/Fr7OJgrpkirEps5mjxVfcceo9BVu4W/hPEG
         HKIVI/aujP/Uqo+tA8Kgz2plYz6xvNmOG1FRjtkZeOobXeGOan81t8FGzzYzpiQLH9pQ
         RHrg5lE2UgEC6IhN3JXcf8kIfrNpSmNSvogVFZjF0jKGxY12h0OVFoawMIbRyLtJvYK+
         8Rhg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlTuvfIXVZFFc5VBD0NSVmClcXNPUHFqXuh4tCx0FawD7EoV+/Wg7pogyKx3ZGCs93Eza86Q==@lfdr.de
X-Gm-Message-State: AOJu0Yymzfsd4fRrDyMRz6SUv17u74mgOzQVALn+RvbcMyScf/FKtn28
	FADQ9lRnZbInd/g28BNjhZA26l2jkfgeWQ/2hEACgvIvuS8B9rwW8e1K
X-Google-Smtp-Source: AGHT+IGY6U/7E41rYAvruYU9+Q/pCuzJfF/3OmG5UgTdLzqEHvzc1qZX3HiO7JtjOe8NlHIM7E4bpw==
X-Received: by 2002:a17:90b:4f45:b0:31e:ffd4:ecdc with SMTP id 98e67ed59e1d1-32515ef2adcmr8088679a91.7.1756153703057;
        Mon, 25 Aug 2025 13:28:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeORYoJ3sImdrgVVwN0hbbGXScusF0B43BNX6hstRK4vQ==
Received: by 2002:a05:6a00:1597:b0:770:3c50:ac6c with SMTP id
 d2e1a72fcca58-7703c50af92ls2807742b3a.1.-pod-prod-05-us; Mon, 25 Aug 2025
 13:28:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjaYhuWhI/ioI680tOziawR7bmIPxP6Wgn3yr9ojitG012/uUhpYMgieEJjE8T+Sg9oI0PDXfDfT8=@googlegroups.com
X-Received: by 2002:a05:6a00:3912:b0:748:e5a0:aa77 with SMTP id d2e1a72fcca58-7702f9f153fmr19359783b3a.13.1756153701815;
        Mon, 25 Aug 2025 13:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153701; cv=none;
        d=google.com; s=arc-20240605;
        b=fGfakG5GpLB3+4v2wC8l+IpltcFiNH8mRHyKudx/JphFU5Kx2tPbohk13uDmgW93Kj
         JwMsDBC+k444pw+gkLttNuuJcGQpb4r5ddcd3ZeNDQbOTAi0Zfy+GFJIc+ERK+tjikS1
         PgF/wlKzz3ULp5ExVTK7cl9VxK+6uFUxJZqS7/mEGYOMpoQ694WlMbFrWv0elmax+g2N
         5ZUVL1/td6lCzAoPAYH6uBXhjdUdEbUI8m5+xWS3AdsfDDWWhyHM6arpeUeOUE2itll1
         brbnIBEY4+PVEioFezzyt4hq/FKJ+cWEsNUufVJy0Ep40xd4h8qsQMJZox84elscblce
         Fk7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8Yt/OTgZ/9yEnA4n8YiO4smWuTjOCRRH+QOana0DyvQ=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=F4ZWJfEqDDosn4A07kst1bVlY9m85m8Q/tDNOk1PFoXPHquFYePjVpchG0bwtmByNk
         0Ukng+qLR642JS6Wxtm2iRoop1r1U351veBZHiHR70m6F5jxQ8Vgzb4HaytiWz6keGeC
         RYyVH87mrut8z5C+Buf79x6/ugFq+AmjL7CR+iiYRbHgOlUD7Ub8W+buZG4E6sTrpSYY
         CKqLE8fKjwVStcLLIFZj/46huywEeJcp2yzOF4DBI8vMqod83wxN3qxweEOMPIE3uMlD
         WBtWi45upHBSZfvRrFM61Hg4pD5VfAO1iDUUk+2G5U9da0T439Hscr5LfMOppaZ9Lork
         zunQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BVCpFbD7;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77046a189f4si80767b3a.4.2025.08.25.13.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: rP5RFZLwTvqTgL5yV5nFtw==
X-CSE-MsgGUID: B7Tcp+eoSta+SHmEL+xqqA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970583"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970583"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:28:20 -0700
X-CSE-ConnectionGUID: BTOD3xT1SsCYAVcn5cBJcQ==
X-CSE-MsgGUID: Ag3FqLySS2u86QrmhSMmLQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780435"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:59 -0700
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
Subject: [PATCH v5 08/19] x86: Physical address comparisons in fill_p*d/pte
Date: Mon, 25 Aug 2025 22:24:33 +0200
Message-ID: <308f29aa95ebf7b293b6c2970384a2c2b34a64ef.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BVCpFbD7;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/308f29aa95ebf7b293b6c2970384a2c2b34a64ef.1756151769.git.maciej.wieczor-retman%40intel.com.
