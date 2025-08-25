Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJMPWPCQMGQETE27NNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id BCFA6B34BE2
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:29:26 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-74381fe3a8fsf6106499a34.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:29:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153765; cv=pass;
        d=google.com; s=arc-20240605;
        b=PTO/wcOOVFGqDvC/dFfwei/4AK55nJ66R8O0oU78fK6HHtBenf1qgkVwzHhZ01hThh
         eIpr3eU+ZL1gDXfMt2QtH7kxJ3ZRjM74poeBsAiX2YYZJL7YObizkHXm6aPo70dEs1UD
         2bGr2mDW2CQ/gm8GLcpaGu+TXr6wQ0U98KQpEJM7ZIPTcXTZksdjFnq9TFCGdhjGFOfs
         Qmb7IJyww2GwgFgdtP9oJdawUI35tW6KV+0sYs8QE5BhqAiev1onsB4yd+Sd2AejNn8p
         KGnrNImExN8YsTZSm/SOClKnPErrIMrkjD3SFGJLaNDznrbK2Ywu17u0neGclMkNZJa0
         f0Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AeoEBoCkgdT7ETXYQjWuIp4ux5EcePytlr220whXOLA=;
        fh=tBaQX8IS4+MnhH+y/gp5O+L+FcQ/8jS99fyBLQKkBZs=;
        b=YzyT19eoBnFTXkPTDdb1jnynTRORnOK5v450RZ/tlNEYL1eFh//kECFJGUppO4JZEM
         YrGRVfLDok5wPthZxrylgQKxHOd6hF8zCD2a2KNUMkTB+nN8O0tDocowwDv229vaV17A
         sKhewNB/45ALs+5+QhemulfI718HS6OxYax62+OpUf9ti1hzb6FdCg4RHkwFdiuy8TeC
         olBRTq3v1cW7/jHBsul7WT6EExbTDRmOHDv7ShS6bYaTcXSSGAx8HNWW9BOiBeBqk/jr
         qTXVee+Y99nvElheSIks3PAJ6cV/OiUiCIfigP1fT3ApwDOOT5ktMxX9PRWf2b4sOOnZ
         p7Rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dMNcrVXW;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153765; x=1756758565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AeoEBoCkgdT7ETXYQjWuIp4ux5EcePytlr220whXOLA=;
        b=OzOMuMaWnsfrPvF9QFHcnMRe4AkOj8Ge0CMsGKanA51NcQALf3zzrh9b0N2CxOM7E6
         WrK7Mk3qCRkOf5TcC2NN0QgxUeVFUBZzZZpc2IuMOWYWwzUGDJFaDG6kDEbQWAyx9VND
         5vmlmIqHqxJHghFnpZarWLu0Z3mNYM0kPNkgtW4IKbSbGcdo5SpXcJs/xrHMJMDZrK3o
         WM0gTOZeSs3XDbiFmvcRlzwQ6aoNjS5SU6ByDccxySwoC2mR/sVRHhz6NCX5lxSd/ztE
         EclW8zIA+T7FCv6SGZtq7zePZNP0SKQxRQtojoR3YEyMq9a1ygCm3rx3fz9uIu+2BqFI
         riNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153765; x=1756758565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AeoEBoCkgdT7ETXYQjWuIp4ux5EcePytlr220whXOLA=;
        b=Nou9gvIp7cmT6SsGc1WvwhvY76W7QfMmk/+zpQsjzGEaFxXOLB0HmEGQ9cj4jpAcW/
         6qvA7R44FH0icvC5XNj79BlfUfKP/Sr9zqFv8D8FmaYsGXxlYhpEIIcQ9G0KVuQuKNzM
         8LbH28YHQ+W7OW97rdEuvunk7zzMXTdH/hdDcs/bshIBybnH+Nu5Q49wBF4EsJ7ZVXAE
         WbMJzbu/eRjgCidZBFgqVeS0jFIv4JtzRooVjsapVtUWACUyNWmbl0R4hCFakOuQ3rXp
         OLq/pN5GeVIYQeKPUtoHGv3rdI5WQu3QGAZje2YveFzHH63HVhfZW9bcC9ozYML11jRA
         9jCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsotN/e/IAUDnq8UenT5veEVIA7FnuVRI0/IiLrXETIvXP9OB5Wc9ZUeN7GDGRbH1cAMNg5Q==@lfdr.de
X-Gm-Message-State: AOJu0YzKJZ7VNfOIfLlUFMl4es2sRwdxA6Mq5WoeLpSesLDE8P6WVx/W
	4g+U7QnxdslO0/we1c9cvt9s23e5EIXdKXz+ozzEe6A/aPioKVggNUVr
X-Google-Smtp-Source: AGHT+IEk2xm/N/UZRlZRGdYP9dIq1ZnLyC+8SafVxcqub+FcfTsGrUSJawFOP4y6xwbYPLfNSKTu5Q==
X-Received: by 2002:a05:6830:d18:b0:744:f0db:a19d with SMTP id 46e09a7af769-74500a8cefdmr7773357a34.33.1756153765266;
        Mon, 25 Aug 2025 13:29:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7IIEhGBRf3YpLkKODR9IpwFoJAOLecdF4pYBhzCbDIg==
Received: by 2002:a05:6820:2505:b0:61b:4b36:2def with SMTP id
 006d021491bc7-61da8c0d23fls1047725eaf.1.-pod-prod-03-us; Mon, 25 Aug 2025
 13:29:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3PZyOyaFVza0455L9JTXJevsw6NKIVZ6jYv96km8jQPc566uS3MVletABRMoov3yusfq3pVR9d5A=@googlegroups.com
X-Received: by 2002:a05:6808:4f14:b0:435:6b6e:9192 with SMTP id 5614622812f47-43785249c69mr7297939b6e.26.1756153764367;
        Mon, 25 Aug 2025 13:29:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153764; cv=none;
        d=google.com; s=arc-20240605;
        b=I1Vo0rdmAWbZCvpdogEzsJDcE6V6SLM+9RbONuPEhny8P8/hyOmGCeekFlpxAWrLDL
         kpHP01fsZ7nJbe9MotDVY2ZD9k7liDP2NcOUCtbEG8ENhozkgkxJ1gkPZqnCRFZsrX3o
         Eu3VBwYxu5IdJTF7twFZY7y+Ic4aD7Vh6dQym9p4Iskdf4ZN/thbLVQKlUsvkHpMDrrr
         XV2pMfsa1sgIkk04Y4I+fel/bEYsF99aX2WfERcG6EZ2Gg2V+3L0QGTHlqGpnc0ea37M
         fsuMSm3JMu9/2N7z58ZpghtbMnN2vKmtguqAJsGhhV616bFMdQb9ozg2o7DGLzyJ0oZk
         oDuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Vtq72QdDzuyXtvGk9IlmoBuW1v+doc629hK/mnAoeUQ=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=SY5ePneX0kaULub2qyoS6ja3iuV40EW9YmZrkBITNJlOU0TV5H5W4k2U0LAoP2YC8U
         b8EWUYCr2sGky+T7qc+rEYZGRZcySPzN439DIbWFUavFjRRRjZbXTvbpXzPbYMmU2R4D
         TTv1Rg3xoRiGi5sWU0j21IgVogKxHof4YKXbScraC9ofukgZDn96neXjcles2ApTTDeT
         5WZcgILVhaqwrCklLFoUd7fW9KHEma6IaHqTC5reyagrDeHKRc4FHfd6yVWlNt71PGGJ
         NisJ+2vnuD6BtjRCLN56tz3G9stThkvXLL7WLYqmtRXY+S6g0yzYtYT02dA9XU/tkDjw
         D9Ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dMNcrVXW;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7ca1704si342211fac.5.2025.08.25.13.29.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:29:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: n6OrRrc9QYagydqh1WMoPw==
X-CSE-MsgGUID: iHYHiUCQSYe4Pz1xx09BAA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970751"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970751"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:23 -0700
X-CSE-ConnectionGUID: 2iU/MAdEQzuCmnajWPCpwA==
X-CSE-MsgGUID: Li6ndXn4Q1+50YJZ69xiow==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169780561"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:29:02 -0700
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
Subject: [PATCH v5 11/19] x86: LAM initialization
Date: Mon, 25 Aug 2025 22:24:36 +0200
Message-ID: <ffd8c5ee9bfc5acbf068a01ef45d3bf506c191a3.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dMNcrVXW;       spf=pass
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

To make use of KASAN's tag based mode on x86, Linear Address Masking
(LAM) needs to be enabled. To do that the 28th bit in CR4 has to be set.

Set the bit in early memory initialization.

When launching secondary CPUs the LAM bit gets lost. To avoid this add
it in a mask in head_64.S. The bitmask permits some bits of CR4 to pass
from the primary CPU to the secondary CPUs without being cleared.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/kernel/head_64.S | 3 +++
 arch/x86/mm/init.c        | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/x86/kernel/head_64.S b/arch/x86/kernel/head_64.S
index 3e9b3a3bd039..18ca77daa481 100644
--- a/arch/x86/kernel/head_64.S
+++ b/arch/x86/kernel/head_64.S
@@ -209,6 +209,9 @@ SYM_INNER_LABEL(common_startup_64, SYM_L_LOCAL)
 	 *  there will be no global TLB entries after the execution."
 	 */
 	movl	$(X86_CR4_PAE | X86_CR4_LA57), %edx
+#ifdef CONFIG_ADDRESS_MASKING
+	orl	$X86_CR4_LAM_SUP, %edx
+#endif
 #ifdef CONFIG_X86_MCE
 	/*
 	 * Preserve CR4.MCE if the kernel will enable #MC support.
diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
index bb57e93b4caf..756bd96c3b8b 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -763,6 +763,9 @@ void __init init_mem_mapping(void)
 	probe_page_size_mask();
 	setup_pcid();
 
+	if (boot_cpu_has(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
+
 #ifdef CONFIG_X86_64
 	end = max_pfn << PAGE_SHIFT;
 #else
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ffd8c5ee9bfc5acbf068a01ef45d3bf506c191a3.1756151769.git.maciej.wieczor-retman%40intel.com.
