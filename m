Return-Path: <kasan-dev+bncBCMMDDFSWYCBBHNYX67QMGQEVLPWIKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id ACB6FA7BD8A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:18:22 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-af96cdd7f5bsf1397157a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:18:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772701; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dxl53dWbcQAihj+qzEaBRE1xqMUmeGRBLKEM94MFu0fmigNwGVaFycz39sR+Sllgv1
         tSOOx44cWd+48imMnyeiwdx+UryAL+Wi3+9ZPftiif2CkN+0cMDXsRR1PhEFaPi+S2S6
         9VUIeIJB6RCfW4ntUomq/bp6W6cjp11ZZR8E9ipl5EJc/1yzy57876fUAArsrIyaAlVW
         AYRuNRI7kyjLJA9GX33w1GcW9XNElT5mxRXEnQW2JMBcxODczSx8qdEE2UW3it4D/zZx
         VohLclUrctS4iDzSBhldUQZ7yMYvIT30hDoU4TnR4yT4Ce7hZOSl4Ba2r/ChtqhHMPRW
         1OcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ijmIZ2RA3gb3zUaDqMYMfP9ioKWPeR5htj4HZTA22kI=;
        fh=RrpyXgztjeNPmCVYE198kLZWQA5/Otzd4j43j2t8sa8=;
        b=BCrOz56kZdRCCOeCYM+wOdlu1tkkivIc7GjnL41PUKuieW0DT8R08m4m9ChaQtY44R
         yxfJ86N6PnsasVfhYhxrVsSt5NK4NA6dEgR2xPESYfZRbDWaPPr6r7yRwZ/1BqWSsQUe
         Pl7F6kLxe86HJvi2elA2kqf1kKukQd1J/+vUR+hNz+ztIXfXLi7VB6tsnx7CyG2RSAkN
         TIzMerp2w/9xoR108+Ltu2WYJkzPtpMD4iAFgZpn3nwugLtVwv//CzVctGXv3mSb/Bwg
         m9F+7q/6KWim6e8/llvM//dXxQb3bS5SE5TphL1qfF2J1Ef9pEu8y+/0H83u+DVIiRfh
         ESkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=U4e235vT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772701; x=1744377501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ijmIZ2RA3gb3zUaDqMYMfP9ioKWPeR5htj4HZTA22kI=;
        b=jak+HFWgivzC7FT1fEzrr5UuMEavzDUXRxCaugOQewUZoZp9wUfLyIgPbrHduRqFf8
         TWCL3Tdr6XtdY1yGDJj594RArSy/x11SC3sipon7RFDTLY9A6TjT1IH7JT5wvfNofyPf
         Nb7uIp0LLSTSCDf3SzkGq5LfDqn5tFJQuUs4IhwFKyBr+PK2Om9fTll8KcahVX0nnDYj
         CX3jjpkCEHMIjrpgMTZ8aw+6TcpMJnT2JC0S+SJRfb7bq+TxHGJ46nAjFl7upkRSdN1z
         IQlL8XLPg4u1ldx5zZi9wD+w4I3QuAJ9VCJWITnjlyhpL5TtixFb8letoUnsnjnUjMJP
         z2WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772701; x=1744377501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ijmIZ2RA3gb3zUaDqMYMfP9ioKWPeR5htj4HZTA22kI=;
        b=g7OjKVZv1ww65FQ1cVESJ9u+h57MOZyM/vMgTy4goPm+kSK1LIOqZ2q5v1kdEgxHtZ
         n1wb8axNGztZ9qP3A7AlggpT5YDHltaIzbWQ7e4dDKszDzUxBEV7p4DZQGmue59bCZVr
         pjMPFmuE+Q74lia9/vPRQR4kU2jpDWB5TA2W9jZzjW3j/CQm8qL2Iki6eVbf0abQCpza
         Lst0gfFr8d7MgEItI6YMAj4Te/oGusT52PFyQPqX3R1TDamS8FecO2f64dbPnW/yqD4R
         hiJal7IsI93HBVii6krBDXeRuezDXqBOJOsiekwsRc+aBP3DEfg9cfXlOGkK9srwbe2E
         MjEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcyRcPoVPkh1i0wt85armkPApkfp39e6a35d/YaLEjm88Ky9tD9VzM2BQQxODJAUyID/1cbQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw/WNMqzP2L1ChjY1EFHq7Lyel76BHTGN/W/BGiWRMYz5pvKgNJ
	j3wuJw1DfnLtO0zQgG2xEe42SsAS2aXsOUKsPCsReOXXY+3vS+wY
X-Google-Smtp-Source: AGHT+IHGEThLTM53+r5AIkVqtL+vC15JwGn20uGxEBeAB2Kk0ftCk9a6MNwlr5rONNv/0i6xN8GQuw==
X-Received: by 2002:a17:902:f646:b0:229:1717:8826 with SMTP id d9443c01a7336-22a8a06d686mr48144875ad.28.1743772701236;
        Fri, 04 Apr 2025 06:18:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIHONAl0rlPf+BW1UqAaiZ+ei1aX6RrsNMOBUqYygKWuA==
Received: by 2002:a17:902:d588:b0:21f:7c14:e7f5 with SMTP id
 d9443c01a7336-229762092b6ls23712575ad.0.-pod-prod-01-us; Fri, 04 Apr 2025
 06:18:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8lYL1fCubB91HRfDv/72GUhBGyZ3IasNomAXd5h14nDvgdcZMeifRaDVTe+qYKGo1FrT12aSOAFY=@googlegroups.com
X-Received: by 2002:a17:902:ecc4:b0:223:4537:65b1 with SMTP id d9443c01a7336-22a8a0a3a91mr46679685ad.36.1743772700102;
        Fri, 04 Apr 2025 06:18:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772700; cv=none;
        d=google.com; s=arc-20240605;
        b=kgiEFquPU6TNeDshdCqz79LbHje5DF56pw44QpwwTTlDKk5AVSPfMX5VaZvMFszApL
         oPs/Ysg8lNuFAWvmQr66vwlrUGpNbyZITo1rAqfmLnLeR+PHsgcD1NljiSbKrOoVw/xU
         j5ieAvbXNU+ava+5Gk5o5OOWeTNn0ib5SYUw+c0xDBE6yf/X8PJ4CwHlrKkP32Pa7yZa
         oogjPpa43qrFJlhS5vyIoMLe3Snk2oKw0m6aEkiATGocArfTLEdAznsLO4/9z7frCvQA
         DtaKVnl0v+ZPrv/mO+eklDlChiFi+U60c6v6PABrpv5ShEnbJs+ZH6bCQ6SakJJiM0KA
         YiLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8gqGofCgAw35fL6rFp8nm8qS6bGOYi033PWynYkryUI=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=TbFnz5+BkR5StffxY7o2zn8r8j7n+FRtdtR44hJsKYa76vBATkcVsXCikdpHC7K0zQ
         sEdRu5TWMPUVWDsZ93Rr5oi1PnYedefZEZYt2AKQ1sQ40xS3wrEUz8pHe3QuT6SmmuU1
         o2u2h11ovP59Alg7RcDSUGRE8rVpNkcMGtAGY9xY7C2VcXdyCJ3mUTQJpGp1A5lZn4Du
         Fe62Mt/rhb2FguvqU8BEU6QuVMZt9Rx6bvHRqX/VpPYJ+T1bO2jQFVnKywUPAa5LbZr5
         tUuUwdVmTczZ5apxHH85ipu9rebadB4Jdp+Caspinw1XFZIOeSICH+WREMMjJbhRZCPN
         9gig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=U4e235vT;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-229786625ffsi1550175ad.11.2025.04.04.06.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:18:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: TV4qt0vBQXCme3mf1L7gmw==
X-CSE-MsgGUID: eBwDAKygSzSU7lz6D6BX/w==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55402089"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55402089"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:18:18 -0700
X-CSE-ConnectionGUID: JIG12BvgSLmwXeiVgXuG4w==
X-CSE-MsgGUID: 6Y3E6zPDSmCFZvSwlS/caA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157431"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:18:03 -0700
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
Subject: [PATCH v3 14/14] x86: Make software tag-based kasan available
Date: Fri,  4 Apr 2025 15:14:18 +0200
Message-ID: <3ed2c4baaf9b182c9d9716db95387ee14d98c99c.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=U4e235vT;       spf=pass
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

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
 arch/x86/Kconfig                     | 5 +++--
 arch/x86/boot/compressed/misc.h      | 1 +
 arch/x86/include/asm/kasan.h         | 9 +++++++++
 arch/x86/kernel/setup.c              | 2 ++
 arch/x86/mm/kasan_init_64.c          | 2 +-
 lib/Kconfig.kasan                    | 3 ++-
 7 files changed, 22 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index f2db178b353f..1e2d6b3ae231 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffc0000000000 |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffdffc0000000000 |   -6    PB | ffeffc0000000000 |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 15f346f02af0..cfe1cb15950e 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -197,6 +197,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -402,8 +403,8 @@ config AUDIT_ARCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
-	default 0xdffffc0000000000
+	default 0xdffffc0000000000 if KASAN_GENERIC
+	default 0xffeffc0000000000 if KASAN_SW_TAGS
 
 config HAVE_INTEL_TXT
 	def_bool y
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
index 212218622963..d2eedaa092d5 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,8 +6,16 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_SCALE_SHIFT 4
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_END	KASAN_SHADOW_OFFSET
+#define KASAN_SHADOW_START	(KASAN_SHADOW_END - ((UL(1)) << (__VIRTUAL_MASK_SHIFT - KASAN_SHADOW_SCALE_SHIFT)))
+#else
 /*
  * Compiler uses shadow offset assuming that addresses start
  * from 0. Kernel addresses don't start from 0, so shadow
@@ -24,6 +32,7 @@
 #define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
 					(1ULL << (__VIRTUAL_MASK_SHIFT - \
 						  KASAN_SHADOW_SCALE_SHIFT)))
+#endif
 
 #ifndef __ASSEMBLER__
 #include <linux/bitops.h>
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index c7164a8de983..a40d66da69f4 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1182,6 +1182,8 @@ void __init setup_arch(char **cmdline_p)
 
 	kasan_init();
 
+	kasan_init_sw_tags();
+
 	/*
 	 * Sync back kernel address range.
 	 *
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index e8a451cafc8c..b5cf3dca6954 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -371,7 +371,7 @@ void __init kasan_init(void)
 	 * bunch of things like kernel code, modules, EFI mapping, etc.
 	 * We need to take extra steps to not overwrite them.
 	 */
-	if (pgtable_l5_enabled()) {
+	if (pgtable_l5_enabled() && !IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
 		void *ptr;
 
 		ptr = (void *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..9ddbc6aeb5d5 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -100,7 +100,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3ed2c4baaf9b182c9d9716db95387ee14d98c99c.1743772053.git.maciej.wieczor-retman%40intel.com.
