Return-Path: <kasan-dev+bncBCMMDDFSWYCBBX4F2G6QMGQE3I4O5NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B59DEA39501
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:20:49 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5fa359ec475sf4004036eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:20:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866848; cv=pass;
        d=google.com; s=arc-20240605;
        b=CZUc/5lBujX8voIXkutP5RM3FOO0ULLNIAERtvGF57VnoorU9UV94C3prEnqoXFa4m
         PjjQ0Dnqbs3i//BFNwzJt9IvAmksoVXj68KOtXIakC0BSUCCNHxmzAP9+6Hvp0ryKJ6S
         79g1pweZc/8A9EHtmwR/ZSoJEbNKK24wQlikgPg/kmx3kDRGmrPPFEHoeGgFOS8sF2MQ
         9L7ZUUC+OD++sM0j2XMXMne+yvFA0Uk4iKbtjl7Z1bt4EQCXTPPqgV/Bf6pwJa7ighcC
         m1BBfEGhNjdbCIqRlqe/oWdMoZYUcaaY2mXnb0QsmLQj172tOs+BMAT19Ux9269P8KkI
         iN0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hb/O6x1SKzAr8xb+YDPatkUYnvM8jr2C0ti74K5lOZQ=;
        fh=Y+x/kBA0s7zX5++JT1tT+nddxtX13sZVs0ylTFodmGs=;
        b=QQTcGZJseIrjTIveM3qK9SYLyGZj+DKw/H5LSF3CDxEPuIKKH/RsyF+QSkdYQD45PB
         PDFivvO8B9E6wAZFbUu5Py8A6PTY4KS5Y1IGNLM8v6BWFDDt/cwo/sdOi/Cg08VhH5Et
         j2ev+TUjcNkHlP+8prGSJp0FIEu/fO3B6pSi8tXpU7APel4s3s6dBgzJCt6gIEmra9gz
         UKbQxea4FC/OytovnJ1iH488fElWC9TsGX/7uBqShvsFQ5tXUZvwr6YIY/vxdQZYQpkr
         vqToTVTBmFlHjB8zCXXi2a4xGYV6D/dsm/7hwjuuuMEARyI4hyEmqfS5o4BchZ2WgXoW
         v09Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eRkaE6I5;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866848; x=1740471648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hb/O6x1SKzAr8xb+YDPatkUYnvM8jr2C0ti74K5lOZQ=;
        b=QZIJiSANFD9EZin8+JtyWHd35gt8rvv+KsdSTZIMMVAAz/2/aDfHr0AJRIKcM4tFEz
         RG0YHbskF3Ew8WzAt+vJXUR+dd3JSi6X1niIoIoR9Tefy4bD1ES2EP49SVGveMT2v4/m
         zbU0g0/9mPMLv8x6n1V6jcQuMHVaINaV/z6SN9q54Da6dIEkmvuUYh4nQMDbsDsC3rMk
         NQ3jBEQO1tLmZa9NPsT7iQzOfiB70DywIolBsMsyGzzv0QVH6e66jPFzzpbKZbOWC4yB
         RYZIbR5y3dcE93wmGN9hUfr61fMmm7Wp1W56BdWl32IwHxhGGTN+sE3KMvT+osHg1H79
         KgmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866848; x=1740471648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hb/O6x1SKzAr8xb+YDPatkUYnvM8jr2C0ti74K5lOZQ=;
        b=l0ByrPsq9WowgYMWnuSjW2qYt2VVniDMAaGws4G2QiU9bhhvKtkRwzJiXE0BRJyms6
         x9ZDTIrp3hNUWi+Znv6TMboyWbjasBbVGydzfFZheY3HCMXqdKu39kDTQxCVX2TTz57g
         c42z8b4TnLTpmslX+nSdAVraCEdE0gc4d+Bd51+MavbhCfWB7mYsY9See3pqQavZYUsY
         bD4/v80J7G/2Cqk/9JcHd7rWnt8B5GCVL/N+8q2/2O9x2PAvf82hMG3p+eECaCihRa3h
         i93O2gQXLqXBXUFCOKU6DVvBsX5c7wYijIUfeDdJ9iwzdxscs3sXUu2wqlZuycmjs9W9
         SmZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZE5eOZFZ5a/mdg0pn6CxsEQYRrFSxRhXpN6xFYKLgg50atIwAzN0NkTxNrCYiT5f+LksaqA==@lfdr.de
X-Gm-Message-State: AOJu0YxzUOsGZ4NMb7/XXiRoH8kVaTj8Yu7fr/25orxUx2O85AQXCnRb
	nGnQp08b2sH/EllVn7Y9U43fY8HQfVOM9QVb42mcInrob5RAbqc0
X-Google-Smtp-Source: AGHT+IGLbCQTvx2C63n+RRqwmo21ceFsn9QspNvMgxHN6FX3fM51yYmZEfJHZJ9rjAhkvJQpc9UVTQ==
X-Received: by 2002:a05:6820:61f:b0:5fc:82d4:b779 with SMTP id 006d021491bc7-5fcc56ec76emr9182845eaf.6.1739866848030;
        Tue, 18 Feb 2025 00:20:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFMsc+U3T8kPNfm1JkPearSJlU1VMZU9xb/vTNKvIiXIQ==
Received: by 2002:a4a:dd19:0:b0:5f7:f41b:6c67 with SMTP id 006d021491bc7-5fcaf8637d7ls442301eaf.2.-pod-prod-07-us;
 Tue, 18 Feb 2025 00:20:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1L8kDKE8SBa46LYw7U4AV1tgpbre12QBRIWuxBTP0q2ESW2fUVjjwUE6rceYcjdNnJLmzScUXM5M=@googlegroups.com
X-Received: by 2002:a05:6820:811:b0:5fc:9be1:f410 with SMTP id 006d021491bc7-5fcc5735aeamr6964527eaf.8.1739866847279;
        Tue, 18 Feb 2025 00:20:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866847; cv=none;
        d=google.com; s=arc-20240605;
        b=IU38uqN9XJwA5e+UyN5+G7IABLvtZAqQ6XYWp8lxeDWxXP3rU3Jv+jI/1oZieQqA4F
         +qolzq8CLnD5Tkl6Ss/3O4aAU7GSxbXaRcUnASvjoXn7XbglyZO+zSG67EWlYrXsE3F8
         Vypo6zrCPEzV8HDfpNxacpHInnyIhfnQ38hoKGF3Ysl8TMIk7upnzd/VosVtJwKyZMkC
         jwhd0QKAPa4IgotOtTQbKZ3KXstTdMbcoP0y7uCcFLuSP22NzcfJzqAZ2CcbztGwe9Kt
         YQLr/g3gJvVDU62+z7+jGn1lnwPt8Lbo4hjeNpM6gA2zeon7Qz19aTmVHYOReWfl8nvV
         hwOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=y+2vJ5V8fj0QHnrVr72+4J/GflVUeiKjoW1Qh/HQtpE=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=CRIL9l9+/kUE7bGV4RajIExHyoJVi0vIvxhk/trzivEqcaqE2g3f1n5UWY7oVKgIqR
         2hLEa2i8XO94PVS4umQVuyZnv0cRIA3cnG82T9MOzBW81rEaRY4e7fafvL9Nu5jdtxIp
         WUKSNu/FQ167Tzw3DCiyFi1W9epipuzTr6p8AOu9JskEDdDhGb6OnE2rahi0UfoifDlI
         zH4Cggu//AwGLRL7EK21uBLxJR4/mSzoY7Q3QmgXoDRLLaKNtIr6mu/kYxauB+WDL6g6
         95rNKY8iBwws8sS0U5KIm9bQHZuYj3/woQ0IFks5D15IjK2pdcI/Uw+J67/q62LRGiA7
         jbug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=eRkaE6I5;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5fceaad3f38si95792eaf.1.2025.02.18.00.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:20:46 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: gwe8OCnFTGiBgqlGU+evmw==
X-CSE-MsgGUID: YSRvT/+yRcagkUGvcb8Sfw==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150615"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150615"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:20:46 -0800
X-CSE-ConnectionGUID: WmLxTe3CRhiKO8fnH2NB1g==
X-CSE-MsgGUID: lzXfGprHTkiUTI4Yyjdk7g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119248085"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:20:25 -0800
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
Subject: [PATCH v2 14/14] x86: Make software tag-based kasan available
Date: Tue, 18 Feb 2025 09:15:30 +0100
Message-ID: <d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=eRkaE6I5;       spf=pass
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

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 32 bytes
of memory map to one shadow byte and 16 in generic mode.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Remove KASAN dense code.

 arch/x86/Kconfig                | 6 ++++++
 arch/x86/boot/compressed/misc.h | 1 +
 arch/x86/include/asm/kasan.h    | 2 +-
 arch/x86/kernel/setup.c         | 2 ++
 4 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index f4ef64bf824a..dc48eb5b664f 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -195,6 +195,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -402,6 +403,11 @@ config KASAN_SHADOW_OFFSET
 	hex
 	default 0xdffffc0000000000 if KASAN_GENERIC
 
+config KASAN_SHADOW_SCALE_SHIFT
+	int
+	default 4 if KASAN_SW_TAGS
+	default 3
+
 config HAVE_INTEL_TXT
 	def_bool y
 	depends on INTEL_IOMMU && ACPI
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index dd8d1a85f671..f6a87e9ad200 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 4bfd3641af84..cfc31e4a2f70 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,7 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 
-#define KASAN_SHADOW_SCALE_SHIFT 3
+#define KASAN_SHADOW_SCALE_SHIFT CONFIG_KASAN_SHADOW_SCALE_SHIFT
 
 /*
  * Compiler uses shadow offset assuming that addresses start
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index cebee310e200..768990c573ea 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1124,6 +1124,8 @@ void __init setup_arch(char **cmdline_p)
 
 	kasan_init();
 
+	kasan_init_sw_tags();
+
 	/*
 	 * Sync back kernel address range.
 	 *
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman%40intel.com.
