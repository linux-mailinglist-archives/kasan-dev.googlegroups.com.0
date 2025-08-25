Return-Path: <kasan-dev+bncBCMMDDFSWYCBBUMOWPCQMGQED7UFAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CE4AAB34BCF
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:28:02 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-886e2e808d0sf91508639f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:28:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153681; cv=pass;
        d=google.com; s=arc-20240605;
        b=UU1UuxNxRJFdBBH6vVC7xNdsFTB7GIZpEfFPNeXDJ0T5li/U91/580ArZJl+VXeQat
         QHBWtSjswdIh2+lKctBIEhULB3wurNZSDWk8rBiMsspihmaDGWHb7fiFFSadTEl5o92a
         eWUh8XkJ+w/5p8/7Hc0bWaLcSbBbIGqnQGMFrAM3l5znP6h8ZYZTRlVwfwwO4Va0LgE9
         0mdrMc6ndpwp058VPKxVcJreYFD1OxX1XZ8jVhcRd75DNWeEnOZ2hX/EegSP3hxNniFF
         iNq/cNLVD1+LXDvoeE8EGhxN3EFhWh6hqXjunQyK8/DwL97LfeDE9Ps28r4TJjg9SpbK
         FIDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3QaLtoAI5ukH3+R+qBtBnIHOaznCjT+FSwGaPGD5CRc=;
        fh=W9etHWD0iSS9RgcAkEW5hHUxBzS1OVxj1DQIoUaTRTQ=;
        b=NmJzhSy0eV+blmSGwx0AoS5qHs4dSBGFx0QTE3kkSiAMj4deVUD4YhmFOxzyOb6P9F
         mQCZRMFBKOZY+ArMvDCRW+ItT5bN1LiDt6tXlDajShPTMiDXJlzX8LZ+eqlkkS+zcBKC
         ehghJXNB1IIVC1KZq/ETnMXfksaaAx48AcRtrPuBCVgZl+4qnG+W6STK1wuwYVAGFzij
         6OYL7ZmMSsA8ogIP/xljQFz7uXjnn3PODwhRaK9+OXxSpdgHgP1x2XnqTR614OglqaUq
         ZJqAIXiik2pw8q1PDLoc5f4m9gEfHi0rVZfP9VXSnn3XPtMqUsmtwxmgr5Q8jW1IARtD
         4WpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MLqsJd2t;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153681; x=1756758481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3QaLtoAI5ukH3+R+qBtBnIHOaznCjT+FSwGaPGD5CRc=;
        b=VavJ9/4uLK+WRd7V0pZ9TGpTIAIKgcAFDt91bZcsePhULn6Cv7LOHR9WfE05JtOZwR
         G6Y2vYzJ2zaANpQgsHZRo3HcPORTLqy5iWSyJi+67NZoKYQtiey1MeuYrZnXw+2Ke+3/
         5qv8ieaIutIGgnAPuEUlecRJTrolAQ2e3uQcvRsDIehPzRs0xuIJgxAbJGPmDwrSnGaL
         lL43OC42Gk2yjstWbZqDMvVf01htOfnrt5YpfBV+ZtTs0unYi29OirWhuewBSEBVW5JR
         lhQwytlcjnwSEKYnAq3+ikYAsm16UpM/WIaUSVfLRUpfXkpTVNb3/EY50ZMa/oMCDAVm
         LIsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153681; x=1756758481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3QaLtoAI5ukH3+R+qBtBnIHOaznCjT+FSwGaPGD5CRc=;
        b=GYv35Vj+i+/4TU3OR0L0yAR2nOr25AO57e2i/98QIaRMmfreN5sVTnAqipKEOP8GyM
         /o9D+/qRpy0+0xlaaLNuX267Gs8cBItPIDVEPBFfG+6ZrXR2gealxQxQjD0RDNqGOBdt
         FBr4I+LnwEsCM18F92NLvKeYNXwW1Tdzo3XrQ4Qpm2iUAFoYQMojKIyNPfw1DEPn/M3d
         DSMWSWTjZELQ3nDXcFiwZ56SdrMODCEfeOwD/bTARFY/uc9kTdRvfMGvjnIhad9YjBGZ
         FH/LVXFNsndxlGlW9ZiRwcxo5cY6iPjAG2eENDhaRQkkaegmyY4coL52r2mDcfmVnsDo
         OvzA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOWnvo7hLfHnJGe0tVx1uAS20eD/zYISNUi2KkgIIb9tm455zjrzAUVzMuWDKEPuKZ2HccMw==@lfdr.de
X-Gm-Message-State: AOJu0YyEKZSZ40vAnvs/9FnjS7xHxNT+mopNyDtCit6oce2cPsibKxlL
	8r8tUDc44ylaDr+D8KZcLIFOHwRdpVZvmywe9SyVrn0gg1b26s5VdO/A
X-Google-Smtp-Source: AGHT+IH4rLCbY8frBpGm3tg4GmjIH1Ky4z2u0DKwFHj+9ZMRS4bKixwkEALJ3NyyA0kyA1q5yb487Q==
X-Received: by 2002:a05:6e02:1c06:b0:3e5:3ce4:6953 with SMTP id e9e14a558f8ab-3e922508756mr203457815ab.22.1756153681385;
        Mon, 25 Aug 2025 13:28:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAO5mbZxRyQX4zmSb/TTXkcO6ioACkgZ5mAti2Tdi4Pg==
Received: by 2002:a05:6e02:470e:b0:3e9:4ca5:9f5e with SMTP id
 e9e14a558f8ab-3e94ca5a510ls22444015ab.1.-pod-prod-06-us; Mon, 25 Aug 2025
 13:28:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUu4ryfxiRvHDOcLpuysQ2FjqWnEWTh58mZu/BNR4epRO/K3LB7+gCbTzup1GB7JCOAdHuxUnZVIi8=@googlegroups.com
X-Received: by 2002:a05:6e02:214f:b0:3e5:52a3:dade with SMTP id e9e14a558f8ab-3e921f3872bmr193999125ab.16.1756153680396;
        Mon, 25 Aug 2025 13:28:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153680; cv=none;
        d=google.com; s=arc-20240605;
        b=JADmKuwm67vKjC1CxpMn++wtN5fcnEiykDk422c04gcmKCFetxcVtR911BcSjvGhMM
         fw1Y4UniGMtKGKy907FPY5W1FhKWtTwbTFz3g6W6Khh/6y9vvGFMzva2b0r4Ewxc6CBw
         5R9VqWmPRNvGQlXSbVZoxL0ui2M0LrlzrU6CquJ0jd+M3akSe0f0r9WBoQ1sv1Emus0+
         D7BKP1zTkXHUNbqLlvcLtTZN1Pia6FllKGybxr0vzfBir32aBMhjqEnN5FIO4wLotasT
         XaXQBvoSYYDgIEjIdTAEDjKw7sp4JqwtuL0NZnr18mtBrPWBNYuaizb2ihPjRq+p94a9
         58IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kYZ+dqLP5QNCFRdzHbpUCXXAFIxaQWi0G4WcLC3mnNM=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=GLAj2ELeVXzpeRnyNv/T7c9A7I86GGa3tAOROBpJq0dBnn/TMP5xOfZzo5btHU8Vtc
         03w1LJSOTipC/Fna4rf+CZZGmZqv6SI+ilUSmTnDw6nfMuQqT4mbUiddXT3RKPxEYLpl
         3i6bX8MQeyR+elGlCBmZykV47wb5lf56ixATe7LWpw8KCoE/f7OsTwUmG8wu6q5uonkq
         Hl9KKlzlGaOfi4sEoOsotoMMv1XU4NyOVFsAvHWCfhiKFyMsgBkNyQ4AVoWdsDVwmz+B
         drbWnZQwJib9DaZI47wqiPf5HP0IsxiE/iqsQzxN09jik8H7S9fAZ6pg6VvphVzfrMNy
         JzrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MLqsJd2t;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886d85baa27si23181639f.1.2025.08.25.13.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:28:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: zK8KqUJXRdWKJueF9jgOdQ==
X-CSE-MsgGUID: Aft4b/KkQVKe+Risz72uug==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970534"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970534"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:58 -0700
X-CSE-ConnectionGUID: TjWS6R7AR16c56RIZHi+hw==
X-CSE-MsgGUID: 97rsnWJETkOP5iPCSk+S2Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780379"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:27:38 -0700
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
Subject: [PATCH v5 07/19] mm: x86: Untag addresses in EXECMEM_ROX related pointer arithmetic
Date: Mon, 25 Aug 2025 22:24:32 +0200
Message-ID: <c773559ea60801f3a5ca01171ea2ac0f9b0da56a.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MLqsJd2t;       spf=pass
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

ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
Related code has multiple spots where page virtual addresses end up used
as arguments in arithmetic operations. Combined with enabled tag-based
KASAN it can result in pointers that don't point where they should or
logical operations not giving expected results.

vm_reset_perms() calculates range's start and end addresses using min()
and max() functions. To do that it compares pointers but some are not
tagged - addr variable is, start and end variables aren't.

within() and within_range() can receive tagged addresses which get
compared to untagged start and end variables.

Reset tags in addresses used as function arguments in min(), max(),
within().

execmem_cache_add() adds tagged pointers to a maple tree structure,
which then are incorrectly compared when walking the tree. That results
in different pointers being returned later and page permission violation
errors panicking the kernel.

Reset tag of the address range inserted into the maple tree inside
execmem_cache_add().

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v5:
- Remove the within_range() change.
- arch_kasan_reset_tag -> kasan_reset_tag.

Changelog v4:
- Add patch to the series.

 mm/execmem.c | 2 +-
 mm/vmalloc.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/execmem.c b/mm/execmem.c
index 0822305413ec..f7b7bdacaec5 100644
--- a/mm/execmem.c
+++ b/mm/execmem.c
@@ -186,7 +186,7 @@ static DECLARE_WORK(execmem_cache_clean_work, execmem_cache_clean);
 static int execmem_cache_add_locked(void *ptr, size_t size, gfp_t gfp_mask)
 {
 	struct maple_tree *free_areas = &execmem_cache.free_areas;
-	unsigned long addr = (unsigned long)ptr;
+	unsigned long addr = (unsigned long)kasan_reset_tag(ptr);
 	MA_STATE(mas, free_areas, addr - 1, addr + 1);
 	unsigned long lower, upper;
 	void *area = NULL;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6dbcdceecae1..c93893fb8dd4 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3322,7 +3322,7 @@ static void vm_reset_perms(struct vm_struct *area)
 	 * the vm_unmap_aliases() flush includes the direct map.
 	 */
 	for (i = 0; i < area->nr_pages; i += 1U << page_order) {
-		unsigned long addr = (unsigned long)page_address(area->pages[i]);
+		unsigned long addr = (unsigned long)kasan_reset_tag(page_address(area->pages[i]));
 
 		if (addr) {
 			unsigned long page_size;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c773559ea60801f3a5ca01171ea2ac0f9b0da56a.1756151769.git.maciej.wieczor-retman%40intel.com.
