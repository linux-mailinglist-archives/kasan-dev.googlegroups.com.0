Return-Path: <kasan-dev+bncBCMMDDFSWYCBB4NWX67QMGQE7Z7A3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id A5D92A7BD5D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:15:44 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2ff6943febesf1598795a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:15:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772530; cv=pass;
        d=google.com; s=arc-20240605;
        b=SsnNXA5lcsJkqcpcH+wRHLx2w5lg9XtINMwkLQ0K6b8DRHwbZTUxwQz1Mk7dCyYOTU
         0mTAvtQ07Kqfq/602TqtjXLs9BghPrXWWSxSzNHL4zx2F3FuDHZPJwWGTgDM8P9+M4XW
         FtVMfk1NKJegGR92ACM73hTq5V0CXh0/Hk3/3CeF2TSr40lv5NZHdZfmLCCvEg330zaE
         7OqWv+yg7hO2nINohLe+DlYeCZqvNNvl5SMVZu/qmvQrpFchaQW0e3s4Zh/wYnKC/GAF
         UDShFTwMnI77ZREFXWvhHy3SQAl7+/v6FKp+hFQEFGMLk+NORwfNmIoQGO2EkqUNXxJF
         UWQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Lmck9Xt6g18G9eYpHnfrRLV8wgsvSpfOwp8aXRWmg0k=;
        fh=WMX57CiygHCsYBrRkW6PEZeJAPu0zQxQpCGyjvqlEZc=;
        b=etfD18l6SI49Y+/KndFKhl0J/8yzOF+3gUDV1Uj25yBT1DzEbI8ABnh+NpgXmTKUbb
         BdFAHS+l1xlOwFpjcfID8P87S8kYpxSB+dH0bcuBxU7tasL6P0g1w8A31sUb05AXR2id
         oMxPa0i//W/qRWfYVmLRllm0lRoCVnWtfQHO36n7x7zOFmQyKs8TBJmEkhdQToCPkHlX
         DeppLgZ85sgjde7wsqOesLHizjpRPHh3rU/4ytIFelXUQ0CPwIwRoJvJryx1EDJGjiNG
         41jZc5VxtwlxZhtBJFBOibmrgi46P2eawt7Zq7yJ9A/dGtA2bTD/LXAnOnD3yYfIE0fU
         Wahw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aaXtFhL1;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772530; x=1744377330; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Lmck9Xt6g18G9eYpHnfrRLV8wgsvSpfOwp8aXRWmg0k=;
        b=UAv7Gu/JGZ2GduV9iSvs2aCw7oCupQ+JBOremqM4uOmjp+4tnnmrWZQ4xNRsWEn+Qj
         IUIAt6jXUl2YAqd+bBrzF7z+0L3iRiiAyEoAgV14pUjSF7F6+D5jIIDBlODL7wuidVS0
         8BQDV8sHp3CoTMIsw6pVq3OX5fexy7expWOtVOfMNbNO3B4noIOZGndXrU7Iy7MabLnj
         qBera+612aTAQsnfmEj6aqa+ucw2Bb0P59qlNqn2fwzKGudPpMxGxtSaq0GLf2aADZie
         VqTlGk8QG86ZIWvV7W8604ahUKz9T6WtmjEjmSZMDv+hIRYuY4lOapGcCngrpBG2HoL8
         4TSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772530; x=1744377330;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Lmck9Xt6g18G9eYpHnfrRLV8wgsvSpfOwp8aXRWmg0k=;
        b=r06/tP7pA7Bp6syTHjVd6JqG2+2iT/alJK+sp2kleJrtekSChvMqlRvGPrTIZHaIKj
         YIYZpBvvHIizHMkW+OL3cYRLE4EATnLH0aglTVxQlN2SNytdotBBWiSPLY93e7gy4ukZ
         Z9S1xeCUbU2KiTlyzE6ZPCZTHDYUNt71qlX+OrxphDTxUvvB+0HWXlyTDZHF2LlIGmqy
         S3UK+SdzMTqDQQ60lkFGWIOyRqoicI2EB/+EoKxq4OMR6l+Wl1bDVHlu0DDidG+r/4zs
         VgumtpX82mW2QH3DxGnbXHXrVkcdm/Ka7o/5aCniZeR19jgL57CdlSf4kAjR6etOxPSN
         A6gA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVygMxQk251rmP8Sb6xf9tTo9GyRgSEpiXEi578UlWv37ANCUOpbl1XkL0LxPWb227UrnvM2A==@lfdr.de
X-Gm-Message-State: AOJu0YyyuJvwTHnKcuL6XpFe4ALsPFnmnttrDrFNCXaJjZG+GKkvTAlQ
	k+oXUXsx/KlU54dm6KM60G4SWiyFeNB53dyQdOL2Eogk56u+XaM7
X-Google-Smtp-Source: AGHT+IEX4z42MNe2N6C+j6aTGgY1Cy6WpcFvIV9oaGcYhJ8jvCOcV/T4Bj6IrP4lxf5SMT+lxTbuLA==
X-Received: by 2002:a17:90b:3bce:b0:2ee:c30f:33c9 with SMTP id 98e67ed59e1d1-306a4eb769emr4808186a91.14.1743772529923;
        Fri, 04 Apr 2025 06:15:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ+ZbJwdi2hsyseSc3s43ZFXjRYSul6OGSMv6hk0Uzagg==
Received: by 2002:a17:90a:9c18:b0:2fa:5364:c521 with SMTP id
 98e67ed59e1d1-30579f98bf5ls690385a91.1.-pod-prod-00-us; Fri, 04 Apr 2025
 06:15:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMniKjbYpNYtTDZga1s3BxrMvFIFGOZCI3yWUfRL2hS1zen8tdP1m5ByXD634yUdWMU8S6UB979no=@googlegroups.com
X-Received: by 2002:a17:90a:d64e:b0:2fa:2268:1af4 with SMTP id 98e67ed59e1d1-3057a5c7bb9mr10220550a91.7.1743772528712;
        Fri, 04 Apr 2025 06:15:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772528; cv=none;
        d=google.com; s=arc-20240605;
        b=icXA6kMTLFGyOxxvcF5qY04U+WXI8TFgfiealrLHAaTstsRiZtb81N3JpiJMAW225e
         kXnaTKYpZpmfHiefZpS+XKyeSALog+GHgOoh9Vlx3FJNKKT+em96lH2QwLKqytrxw99e
         yMGJTtzB20281YVlyV8kxwhFTTh691jIJtlC7JjRJNZIcxAgt7BoIQnFg+ka57N82r65
         pd/4NLpOnDeQMcmXkgr3K22Ka6pzMBg/pNiptZ6eaXxJANzf0n+qIuczjT7zLGq3zW3H
         OoBn+WsKpISYYEvpzgVLXWJeoP7QaYPkaWPC3nwkchyuxpsNiOL5ochE+SeqtoZKL3uG
         DKRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eJOHrb/uxZmkYwfE/IAvy2u0mkBJZjoP2KYSbzFPajw=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=O6bJJzCP6nDQW1x+hGNv/+0BFlYrLOEVhoMP1pv2YprODaC9VgQe3NthQmxjoFxMB5
         SMizB1dQOrqUN4jhBkrjLnjKqGZjw2j0tDy7HGnTXFOmuxGPDsbNXMkGI05uWfFWCEOv
         cT7oQtBgD5xEt+N63VC9QHE1BSdBPrS/Wob6zffHJGsnUgrFDxrH9bb4XC62+EgnYB9D
         2lwlIWMC6uRKKHLKMlSq0YEFt+ad6W5QhF4j4t1dF09/2PMs272VFHv7UtALo5TxRpM2
         oRIobVY4mpUx526k83uSjF0BuRI0MoIDdRijyHyTfkbWNeu7QmO2qNYUPJ9ULNbQsQnR
         xfXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aaXtFhL1;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3057c85d085si183775a91.0.2025.04.04.06.15.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:15:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: beu1JugqRBGsmVM7v/kCOQ==
X-CSE-MsgGUID: uNKMh7xASZ6VlGpZ3bC2zg==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401600"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401600"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:17 -0700
X-CSE-ConnectionGUID: 6W/+ARP9QJe63qKWe4pGFQ==
X-CSE-MsgGUID: mcoWCZX1T/6lCeGBRJQLmA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128156968"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:02 -0700
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
Subject: [PATCH v3 02/14] kasan: sw_tags: Support tag widths less than 8 bits
Date: Fri,  4 Apr 2025 15:14:06 +0200
Message-ID: <6db4abef7daff8cdb07ad1cfd4fdd30a4893d5c3.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aaXtFhL1;       spf=pass
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

From: Samuel Holland <samuel.holland@sifive.com>

Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This is
needed on x86 and RISC-V, which support different tag widths. For
consistency, move the arm64 MTE definition of KASAN_TAG_MIN to
asm/kasan.h, since it is also architecture-dependent.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/arm64/include/asm/kasan.h   |  6 ++++--
 arch/arm64/include/asm/uaccess.h |  1 +
 include/linux/kasan-tags.h       | 13 ++++++++-----
 3 files changed, 13 insertions(+), 7 deletions(-)

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index e1b57c13f8a4..4ab419df8b93 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,8 +6,10 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
-#include <asm/mte-kasan.h>
-#include <asm/pgtable-types.h>
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
+#endif
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 5b91803201ef..f890dadc7b4e 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -22,6 +22,7 @@
 #include <asm/cpufeature.h>
 #include <asm/mmu.h>
 #include <asm/mte.h>
+#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/memory.h>
 #include <asm/extable.h>
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index 4f85f562512c..e07c896f95d3 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,13 +2,16 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
+#include <asm/kasan.h>
+
+#ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-#define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
-#define KASAN_TAG_MAX		0xFD /* maximum value for random tags */
+#endif
+
+#define KASAN_TAG_INVALID	(KASAN_TAG_KERNEL - 1) /* inaccessible memory tag */
+#define KASAN_TAG_MAX		(KASAN_TAG_KERNEL - 2) /* maximum value for random tags */
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
-#else
+#ifndef KASAN_TAG_MIN
 #define KASAN_TAG_MIN		0x00 /* minimum value for random tags */
 #endif
 
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6db4abef7daff8cdb07ad1cfd4fdd30a4893d5c3.1743772053.git.maciej.wieczor-retman%40intel.com.
