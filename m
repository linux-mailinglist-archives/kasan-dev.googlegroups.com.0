Return-Path: <kasan-dev+bncBCMMDDFSWYCBB6MOWPCQMGQEQW5NJ5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B916B34BD7
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:28:42 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e9538359d12sf1865938276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153721; cv=pass;
        d=google.com; s=arc-20240605;
        b=P0/g7GtouC+A+qfEtEwYQ1323AQ0MNbAyapiD5AGzHf5QNVcI9/TtCcTAfGRp2xTpN
         bwZrLq7dliOTV3PHF8AOIqdmRMCKT7bXwxQD2Ofv3wgUJ4mvzQ/hC0DDxZ2ME7hisW/8
         eFMZ1a2umtimm6o/DUgdNB1Uy3gNmccdJ4ISFgCctURId3gwacf1dTnMCIL0buzB5Am2
         h4gqF3kTA4x8drhwKgHUU8JbnIjWE0XuispV+GOLu5FSGNN4n5uBA96ekEXsPkpyn4kZ
         eCIA53vfo93QiHyJe4OIs36VtZ1hUTUEDC44TXvaB/POfvlWvDeol1ST7ecvAsMRfs67
         Dm/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ta7RGTORgKWFplIEeFEyMSEdHBPn0O0W6KaRuiVSF9o=;
        fh=/a1Ge0OHuG3Gkc0H8d5ZYYeOm0+z39IkotYGRdU+m1g=;
        b=YPITqawrLuvJmpF5Y/M6F1mmCFGKmZbp55J0FrT2+tFaoGv5TVBbiiE/FpRJ+oss5J
         DRHeO8AlpKz+GUUHIdeOFS77tgKgAu5oQWRL+nplnlbnITwtmq2olWIfKfLkLhiC6VW3
         3EJ0b1hv9/UCmx6AnksfbPvbAxs2S0NP3xs/7L0XhYfyHyTzrsSuXwh+7dFV3LBpAyt0
         R4cQGZuROZjJTLgCfqcU4n883Ifht+suw7LsS64JzVeFM3vRZyl9xCc9KvA4ujmkZBTB
         DsqX1EsiHU3+LXZicim2DXPRWrp+sA85CFMc0vu7PIv4anzsPDdx2sqembG/k9Xqyexs
         ad3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jWfVcTob;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153721; x=1756758521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ta7RGTORgKWFplIEeFEyMSEdHBPn0O0W6KaRuiVSF9o=;
        b=QBOTzExv/2QSLRlE/i8rc4JCA7iNmzOfj7fDzafjCdntSX5vjjSi76uL+GlS73mO13
         XTEqJ5qnW5P0HH98TNyXOHAO0tSFiICyCtg0r5qze6X8s9W4Lh6V/iKYDJr5n9gUQw0F
         S+VKUYBD6pB9zx3r51RpaIhFVog/9pSb7+479y0goGCxlVVRaNP1IF88GKx6EW+oYvhq
         smt5MO3KzB9/YOKdP2Mpe0HN0JVDGxcZtf4ecioaENehw8GUVdaV2Gfng8Flu8MJqag6
         ns5Ww/iMjQK9P+qPjNKrcWk6i3aD+kEQyHoxTJyHeT5izFTaT/XxSEhVk/nf3Qqcj34s
         GkFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153721; x=1756758521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ta7RGTORgKWFplIEeFEyMSEdHBPn0O0W6KaRuiVSF9o=;
        b=NF4UTdiNt74ghN50f2de7lE6oteynW+nUaQlA4fSMMi+pD1TpZKpzXQzl0ZyUjRZR3
         bJd+nuTihqVCZdJvQz3/jx5GujN/yc202zzY2gVWa8dqwcEC3djJIEDXiwt6NVTH3jkM
         08WLXOu0seZ7ozb+iifVHxizN0bAbbAuo/gVr0uZsZBpdMOUxptMEzZyPIMVeunFrmmP
         CTdMMdm4IvZZ36PKAh8sYkedy23zc3fKCsac3GjDNwOqvNwYdbsrv6gj31fIgtyC+dmW
         7rb7YMtKFZtvzQh1YXjaJhyy8pgQCQsB7IC1uK7Zxr0kfYWVdQ5f8hq4h/R75VTm041v
         0e7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdAAgBS8E7YiZPHm8ZYiOhWgxGuA9KPlLoOapEXXI8UP6k9FXyyTYq4ENMPuF5YGmoCkB2ng==@lfdr.de
X-Gm-Message-State: AOJu0YwDRz2FBIeOr7vvs9pBnTPy9l6ahr2QzK+y0A7KU87MQ5EBbFDE
	32YD7p84+SDWeDL6xFNnND2HEPPk92aNogJJHlUaqRI2BEErA4feG7Pe
X-Google-Smtp-Source: AGHT+IFRHL5jvv58ivRIPqbQLZWJZjW+kO1tCbnUxKx5z4lw5m5lhcEhgPYDW7tPP2AR55P17lt+Zw==
X-Received: by 2002:a05:6902:102d:b0:e96:dcb9:d4d5 with SMTP id 3f1490d57ef6-e96dcb9d7f1mr713027276.25.1756153721339;
        Mon, 25 Aug 2025 13:28:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCNsLTyeNLF7OPCDtK7XW+NTlImYt1zyIBjiTuL5IFow==
Received: by 2002:a25:53c2:0:b0:e95:602c:8395 with SMTP id 3f1490d57ef6-e95602c8d53ls700291276.0.-pod-prod-00-us;
 Mon, 25 Aug 2025 13:28:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvM/yuOL2RSD2k8ZiJlEx5M0grwkhspvZ/K3l2zTC2VDTifpJynk3uWEi9M9YkVVAPNkoitQw4fWw=@googlegroups.com
X-Received: by 2002:a05:690c:5c1c:b0:719:d8dc:343f with SMTP id 00721157ae682-72126c5c5f2mr11478537b3.15.1756153720519;
        Mon, 25 Aug 2025 13:28:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153720; cv=none;
        d=google.com; s=arc-20240605;
        b=exFkLTCqGY13hGeBINItZXNjAdw9LDQiBwQ36GtoREj6YRjKe/v+uZCLluZvCYTcdk
         NqJdNrKO2qyrxNEeIksRIF0f9AZ7jqtn78FbBI0SfYMpUvZxeZyb20vvGkuS9KZFtpmn
         vGulFt4mYU2q3ni8N0CDa6GWRaHUoOotS2WEHaRP2vrJdtTkwTwR2qB/o08IOVIgyEtX
         sUH+m3k3pMugJexSR1ffPaa7R1z0qa0dC7li5/4KkzD5NF1hIkVjW+E/SB8QYjsJLnKl
         amJRXFzakt4ipM1k6KxOQNJR5Cg5vGGy2WdLGCJO0lqGigIjv3YHFXHrMyTsw0YWw4t8
         gJpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uNbMRp4NAvF971szzz7CR/2vyv0vBk3AYCxV9Q+eZ04=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=DKEL+bcSuAYCqlnMwJsJavSLlMEQB8HKSqLphHWElcR4qwOrusCVvbkZOtRvrjZPh1
         u2CUeMOVeaGO/mWWvOI7+EN4ySC8EIp5c4W0zH+BGM/GQyMq/nVZTCwQkj9TJ6LB0CHp
         t2G3Okmj0d+wd2lAjXvYRoTVjTWdrL+iCUCX2m2XvA4CXe1gyflGn9xHQa/dLIQtR7bC
         idpEEtngyjbuKu+0ZSqEpNvCMJBcx3WKOllzyt5pxpycBpm12GDJvrC+aE3LoUvdghBy
         uw8Cm5SZ0GJEo114B1gZa9qL4KeaStW7lhaYkBkF13bAoncfX9evULY6BSh96umefuFf
         pK6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jWfVcTob;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5f8ae7ef907si185057d50.0.2025.08.25.13.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: xlni60g2SoO5XVBDAU8J1Q==
X-CSE-MsgGUID: eP9EXOSgQkSGTiPQugTsqg==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970640"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970640"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:28:39 -0700
X-CSE-ConnectionGUID: ZdrF+c9oTnqXBOaj3/bbCw==
X-CSE-MsgGUID: b88EEwdzTV2GCqGXKxP8lQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780469"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:28:20 -0700
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
Subject: [PATCH v5 09/19] x86: KASAN raw shadow memory PTE init
Date: Mon, 25 Aug 2025 22:24:34 +0200
Message-ID: <9a7958543abababa30d534c44ba2f26d6bd692d6.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jWfVcTob;       spf=pass
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

In KASAN's generic mode the default value in shadow memory is zero.
During initialization of shadow memory pages they are allocated and
zeroed.

In KASAN's tag-based mode the default tag for the arm64 architecture is
0xFE which corresponds to any memory that should not be accessed. On x86
(where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
during the initializations all the bytes in shadow memory pages should
be filled with it.

Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
avoid zeroing out the memory so it can be set with the KASAN invalid
tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Remove dense mode references, use memset() instead of kasan_poison().

 arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
 1 file changed, 16 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d216..e8a451cafc8c 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -34,6 +34,18 @@ static __init void *early_alloc(size_t size, int nid, bool should_panic)
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
@@ -63,8 +75,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 		if (!pte_none(*pte))
 			continue;
 
-		p = early_alloc(PAGE_SIZE, nid, true);
-		entry = pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
+		p = early_raw_alloc(PAGE_SIZE, nid, true);
+		memset(p, PAGE_SIZE, KASAN_SHADOW_INIT);
+		entry = pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL);
 		set_pte_at(&init_mm, addr, pte, entry);
 	} while (pte++, addr += PAGE_SIZE, addr != end);
 }
@@ -436,7 +449,7 @@ void __init kasan_init(void)
 	 * it may contain some garbage. Now we can clear and write protect it,
 	 * since after the TLB flush no one should write to it.
 	 */
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	for (i = 0; i < PTRS_PER_PTE; i++) {
 		pte_t pte;
 		pgprot_t prot;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9a7958543abababa30d534c44ba2f26d6bd692d6.1756151769.git.maciej.wieczor-retman%40intel.com.
