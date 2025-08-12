Return-Path: <kasan-dev+bncBCMMDDFSWYCBB64C5XCAMGQEPGCAJXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B50B22867
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:28:29 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b085852fb8sf217808441cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005308; cv=pass;
        d=google.com; s=arc-20240605;
        b=WIbiq2fNeX0t8zC+0l6DhMDSJNGlFdVdTdTXu88+w1zjN//RkCL3IyD3RUkMu8W8W7
         huHn2ihsg/miEJQVM7nHCkic6lDkBmf2q3vgBJnUJtP3NVGa28iM2FG4kDUoo5UEkP8+
         QlBZc69r5890yJWqWumIGuw6ZrHs8JDRVaeDDfE1fntXa4Qn/X3jlkZprGhfWa55EuLd
         ZYLnNEULkzKFtWmxkv4olJQ+IACSW5t/zw18IlGVkVh+DBxdZG3Aegq5Rlx7ZRa5JtOe
         QChW1f6Xcop906x6Y/xrRMISEca8Q6P92wnuZ/49vVJ7wogLZ+4zr4R400Oh7O1/BRu5
         cZ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R5ZKdQJVP5o4XCFTi7VtTbIJSHUqpPqQuWvBbiTr8gc=;
        fh=iwgy/x/HqttzXYMD8wYMaURrJjcKClcJkWU+XO5MuMY=;
        b=hi1b4JhKrZp5pfUIt04Sz1+jDDQXLNeqNZaewM8DquwqlQjqbXKnzYEH2TMoJ2KdCs
         B37e7H8TYvjGXNUU7i+J4XvdKuDtxM4ef25+RR1czwZIddoxGuL1exfFnSohZyRHJ2od
         xNEWi0owvyAZ6jhJzbuLY9KSGsBAEbRzRv/kb35c9x86Y2EBs5CvwkycfIs9O1UzXGBl
         IoDuX+4QRvVsRCEIPbwd+VmDufrybieostQsZ9/wVjsX/0TOgkuBlvMoNY47rdpYWHdo
         EFw/j2ZSn00pjpvz0eC02MyILwGM4v+4vuwjP3M7DR3/BsHtQ7+AlaazUX9KtglG5ZNN
         nRZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JavcaNMc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005308; x=1755610108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R5ZKdQJVP5o4XCFTi7VtTbIJSHUqpPqQuWvBbiTr8gc=;
        b=qtpJeelIrK7hABRyXYgoOI1r7Caz4+w9+ZJy8yhQ8SxJFYAiNid0qhY4dJ5sUc90ZX
         s6LNHk4aN/t+wQiYBLotyUOfprgU+KWDhCtcj9/VVa5Vccd4hmyu9uATSC4pG7v1w7uz
         D9/q0aFpxUeWQe2E9tXBcMQj+s23NkBeRu2GMSWgwoBaFekaSc/CVd8lWbVSl5HzJd4p
         1K2UhVnAuCb4pnAUqq/5Ussn0uMRG04b0NdEhh0inVj5pmf9bn7OXgcMdnHaHZQSg3V/
         4fQoKI2OJ+IZPLExD/cT1h3tchaBUQisUsTF3Mzg8HX7gowsACA3TSJ3fH83SFMj4VY7
         TSoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005308; x=1755610108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R5ZKdQJVP5o4XCFTi7VtTbIJSHUqpPqQuWvBbiTr8gc=;
        b=NIuVbWKzwrnzTwKFblEvvcJGsNgy+mu23p/Ac7yIjCiZsun608Ue1jJKYsNGwFiHEq
         vAsLGWFz3yP1ee1nstlklCwVcp9hT7CLAlEoHBgH47AR/hxvwMIqN8+3Krxe737vw/p5
         2b1YYeeq6p4IpjP+tKf1ohUC4DdGa21RBRme8rxM/Mi2AbJTXKsbrQqZXHQ8KdTQPP9C
         B/5WIyiijD/5okFeNA48udQzWHQlqk0tXzZY7MRi7Tu40XlTdZyaCwzYMqOBE8U10mVf
         5NuyRGWZZX4Cxefes7aH2h/tWIpToKItGmXtZs+MKLFfym3OVDhT1FET+SpIGDCpJdWQ
         nYBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjJNYzpQ7G8udcwDzfFelytPPsjttnGhr/8WRX6rrz5p0EL+S2jGjZbUDMsz+bXNkj6tN88g==@lfdr.de
X-Gm-Message-State: AOJu0YwbYHV4ad/IQV5XkSNAlyTKRsajMC6XBEY1x3LxCudtLkPbIb/o
	2eglR0Z8c1q8UWoEvDRPNny7AjDGskW34BOWPNYwYT3be/3w9vA5KU5Z
X-Google-Smtp-Source: AGHT+IHMBKf256pXiU2lsrfgVZcWpsgbmTDE8jBo8vtjl14uGqhAxEcdRhRPfy4ajdvGhBM+mjV8Hg==
X-Received: by 2002:a05:622a:1a09:b0:4ab:705b:2e70 with SMTP id d75a77b69052e-4b0ecbc6938mr43389141cf.20.1755005307955;
        Tue, 12 Aug 2025 06:28:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcIWjfxW5ew2Et5LglxhtBg8PokxX1J5UFF8JMTFELZBg==
Received: by 2002:ac8:5891:0:b0:4ab:9462:5bc0 with SMTP id d75a77b69052e-4b0a061729als88790051cf.2.-pod-prod-06-us;
 Tue, 12 Aug 2025 06:28:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+ImPjlRX8jGvebcZIdu8+IUBA0VY54R8g/XBB1U2qdGbsqOzAWNBQn7npmUz3I3QXj8KuGMN//cE=@googlegroups.com
X-Received: by 2002:a05:622a:5cd:b0:4a4:41c0:b256 with SMTP id d75a77b69052e-4b0ecba2ddemr50645721cf.11.1755005306900;
        Tue, 12 Aug 2025 06:28:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005306; cv=none;
        d=google.com; s=arc-20240605;
        b=k1t2E1W1CfLCz0oYA59p4bPMI5nBR6kWpEjBX5hkBxMKLWxro5NW56liz6q72Fa0gC
         OB0qQN4ZfJRqlGUkuLBAdt39Org6luDdjH+t9DllMIgEyCCdXWXSrx0CE0jUT2XoCjNL
         Vz4yu65quviCF1yr2dZMbKvz4bgOIPrmZfGv4+sZAdaidmEPB5AoF8j+lp94GwTQgKOZ
         /SsytbteX6yVcwPksmUvGGdrLv2oqgf0x9Ul5oaqi8bb/2gELkcI6rBoFhB8xs76u2jn
         ByJeTmPBWRXo4Yp8roc9BdufVCZhmRdJ8HRjGw8JE/V+MoG/k8i7NL34styfphp1pJG9
         6Qcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uNbMRp4NAvF971szzz7CR/2vyv0vBk3AYCxV9Q+eZ04=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=c/GURyeNnZGOw1DCEYdPvjxfCNv3ysujkxyM/wBHCCFSw0zBeZiSsg1xat6LyE7q4A
         nt+xynZcQZMoqQVvtuIKksqkPWFj8I0t/E4qZwcJSOIk9u3+6ssNX+deZM1pI42IdlZY
         qF4GrKZkyYv63a2L+lWFUlg4nlCVpgy8kR6ohtz8vtxqh9dJfoq911yCIB2PXErlrbNL
         qJwdvH5VJ8RpJUSkYz9QOmAgHRnIBeLZ2/z82NrD6IozlUiwNz+N50GUKkZtovQia8dj
         4W5vhHnUr4EylIc2UxDB5z02eQiQ1rKTtpdcjp/3Vih7Ib+p+FC26JQCA3Fh0ZLeSrig
         THpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=JavcaNMc;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b09b2d8f4fsi6459671cf.3.2025.08.12.06.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:28:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: JLpd4mkxQrugIMtjYJhXyg==
X-CSE-MsgGUID: vjhpIQLJQiKtwWgSYf8J/g==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903614"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903614"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:26 -0700
X-CSE-ConnectionGUID: RvG1WbQvQdy6dQLlny3rTg==
X-CSE-MsgGUID: gCS5TnjYQ6isOtqp7VNDUw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831505"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:28:02 -0700
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
Subject: [PATCH v4 09/18] x86: KASAN raw shadow memory PTE init
Date: Tue, 12 Aug 2025 15:23:45 +0200
Message-ID: <38129f9031dfefc3e9465a0bf06fd32256cdc157.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JavcaNMc;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/38129f9031dfefc3e9465a0bf06fd32256cdc157.1755004923.git.maciej.wieczor-retman%40intel.com.
