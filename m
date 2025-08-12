Return-Path: <kasan-dev+bncBCMMDDFSWYCBBH4C5XCAMGQECXTLYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E9782B22857
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:26:56 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3e55eb7bfa3sf13654865ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:26:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005216; cv=pass;
        d=google.com; s=arc-20240605;
        b=jmFUN6hvwC95zk944x2IyN2QP4XOk7boOD9KggNgb4nFtKmEn+5pH0XU60iQU9AjoR
         K3womG12/CSYTXO+HgPHND5nZzAllGOfGpjjLvKLT62+l+MsBMTr3aQMmm3TWaYVUJAA
         gJwI0KXVgekCKq4/bIUGLZ54apgDiwD0flaxZKbLyN2taLyPwqRJgk4QKB9NnSzBgPYN
         hFQ1CTiipQl4Umt+JijuHNOkSV7LgfAyPnSU57S6Izq7Jb4F/B7AvDtQ8nahAQI7AO9z
         eGOSmjOgUvFdJG1LysCE/UMFd8Ldiml/dUBgSpExVTVmfiL/EVkpZ7LOA43wQojCx2tC
         ebDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Xqn+d3HtfnnKaJOpyIXD/NcHg58xJmqNxP1Vn4DIkA0=;
        fh=gsKh0W/Wk+c3FvlDnCYiedmyGOjnjtCo/8y9j79CZ6s=;
        b=ls0neUYm2fk31D+X8RYsf2oNpaFkYpL2s/1T1LNuhY86Mgaz/asR2A0RpPnh57yvDG
         uhg5xxzW1O/gOHBuHlVYLpVrTnuzWqFCMkuxX0I9dNEIO12lW+ZZInyyG19a48hazek3
         NCgCvfWKYw5C1Uul6GNMXZSPYOi2MOS0ZgBXEwfqYORXtSIffyAplxnvv6WUzfdNqfCE
         mGnoYRvS15TpZbu+SY349TqRdrKjrnG0aBYhFRmDFGZsyZCP4NI4h7YIi3bAgPYPwuRZ
         RfF6MvfYiaVQB8hdDgp2bCwTyNFUfmp9bq57alhhnB8zieH65oFXHnKePdlX5tZZ8g5d
         3SjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ELXrUPWj;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005216; x=1755610016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xqn+d3HtfnnKaJOpyIXD/NcHg58xJmqNxP1Vn4DIkA0=;
        b=WEhODm/WkMnuYpLgExZeBnEXo66w5RSNdgwcABtXJrhUi5XO1mh3vWs6AsjXhtRgLv
         bHsFSrN1zEhGHu6pDxN8PraBbyFQkzdC532YAupAeQT01eab4Esb6uU0rFcRWkYuffWb
         5DFe2gCAgz2eMChUn6Z+Dtz45A1l0dCsHJl6+AzYPuAz6vC2ap7Fx+vXrNHON9x6s1h4
         qEyccwvLuHZILGkqxbNv2byPZ/9FPQEm4Eb3P5iyBcSublgyYzTGpfxBcQKkLpAZeykN
         ZVKmSOmtMH4b10TtnRG06ucernUZ4V9+OkoL4bQjv23QEnqKKKQJF/VbmEbgIXSZRJvK
         CGZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005216; x=1755610016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xqn+d3HtfnnKaJOpyIXD/NcHg58xJmqNxP1Vn4DIkA0=;
        b=KL/rn34StumjFnBtjfRCAoh9HjWVXIa2cGcFJa1dVCRdmnqEOrXztVVP2cgXEFCH2/
         g+iC54RqX/joZef6uWq7u6nea8+R9nJiyP7NUWRYKu47/SysH7iCJ8aYPFO2eNy3eE5i
         yioSxdH+wjbA1dv642bPz7RjFL+Bw5DpclOmVnz5qca9K+hI4PrvoExubeLqdph6Hpvk
         FnwmCH52s5eD+vMLsGOMijnCVUtbKWv7RAtbDpsVVZFDfbWs5XmNDwBKoshYEpR5MgHZ
         qHEvz6QRwI2xSl3XiF08XRCCwPbFbKL8x0z7NHliMNAHWwzZ0XVvUkBuxYJteihtUDuw
         81YQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOillalmvh4T+I7845+6tFUrj6sh0YlBNyTu1x636offcs6qVjv6Loue5qD6Ivbf0HCiuUlg==@lfdr.de
X-Gm-Message-State: AOJu0YxIg1ibKXOXxAiwb53ETq5YZR0xHIU9esFd23XYkHMQWykOGj0J
	Z77nRbo+Satlg1aF3XBMwS5kv1S40y213rkqfwigcxvMvAWljqd4IrOn
X-Google-Smtp-Source: AGHT+IEHD3GgrRxTCXxLUs5k8QwmjLnbFhem+f5oXJCt8f/vkFKiykW81VRHoDwjNjJfK8RkYZt/PQ==
X-Received: by 2002:a05:6e02:2785:b0:3e5:5937:e543 with SMTP id e9e14a558f8ab-3e55937e7f1mr65199875ab.0.1755005215541;
        Tue, 12 Aug 2025 06:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfnA5Sn/vLLQVCww7pchTiVUZF/Q5gfhyQ4ubje4kH5sg==
Received: by 2002:a05:6e02:4802:b0:3dd:b5f6:ef15 with SMTP id
 e9e14a558f8ab-3e524941b06ls51058705ab.0.-pod-prod-08-us; Tue, 12 Aug 2025
 06:26:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9TC3WGGW/Js1R6lKm1gW25Cx/O3xFRcOwi4B0WrUr8s78atcXoBU6JL3Vi7mOmeXBGT7Hvmk33co=@googlegroups.com
X-Received: by 2002:a05:6602:15ca:b0:884:389:adc7 with SMTP id ca18e2360f4ac-8840389ae34mr1877705539f.4.1755005214579;
        Tue, 12 Aug 2025 06:26:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005214; cv=none;
        d=google.com; s=arc-20240605;
        b=Hj7yXeNeAnxO0/de3pN9cEddizeqpjB9erPlpXWu56Z+i86Bvav68RiE3biQ/uIg8S
         TjAYEc+WhIpOalB1eobLfmzuejEaLuD37ePEFmswPRKfv6m8DCpHoTWQn5gIYHdZfqN8
         S1COCNYAUMkHGOdJ6laCsVCfPt/2NhdrzH2J4wZw/W2tyN/TnsnBXhLdnLJP71OSrvab
         H+WWGv4CsFpKdI0vuFzQiFwopPwa5iYVYc7atvRrOmvrTA/Xahp3pe4auhM3fM4/Cr8U
         edKQ1QRL5YMVbQvwI/c2ictb3X76PHGN5uc5nMP7SIUYqD9I6PkrpeRDjWAXcPw/z0rP
         q8vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HbFrm91SUbV4l5hJiwCmmvNUYm5bhZMJ5aJamdpeZ6g=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=JC+NV6RRvNXRq5m4T2Kjblu8QeqZXd4/hkMOtBA9hF4CpgTb4swx8fg9GV9xbgYtBZ
         GGEbrIpzv+DYkSEenlvd+ltgx8S8ewp7N8ZFavDWBcqAPgHAqjdU+2B1S5NoeHlnTn7U
         7fqDvejNAZJosxHO1bJSBx21hbCppZxBzQFlbaEvvAucT8lMk/cJ8oQ/1AKLefkFk0kK
         ohuVjthLrNPGOtQ3z3hQ6nLvzDFl7Dcy9FHkJVLv6v2vRtYy7BSIBI0XXcDdGgbSIAWt
         tNmitghMzTazEyJBNu+zAHMDysjgLkwY6KNnipDTn+D5+6T8gMoKGrJDtKXRrY/gy0tS
         Cu1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ELXrUPWj;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si49156639f.1.2025.08.12.06.26.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:26:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: SLL+9awRRNyqiUaA4eKmUw==
X-CSE-MsgGUID: GNekfH+FT62FYBFQ3jtvAw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903220"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903220"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:25:44 -0700
X-CSE-ConnectionGUID: G0cKUUX3QdeIuuUQDf731Q==
X-CSE-MsgGUID: HyifQRzJTUaZ4oYqgT0L6w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831317"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:25:22 -0700
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
Subject: [PATCH v4 02/18] kasan: sw_tags: Support tag widths less than 8 bits
Date: Tue, 12 Aug 2025 15:23:38 +0200
Message-ID: <780347f3897ea97e90968de028c9dd02f466204e.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ELXrUPWj;       spf=pass
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

From: Samuel Holland <samuel.holland@sifive.com>

Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
pointer tags. For consistency, move the arm64 MTE definition of
KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
RISC-V's equivalent extension is expected to support 7-bit hardware
memory tags.

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
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/780347f3897ea97e90968de028c9dd02f466204e.1755004923.git.maciej.wieczor-retman%40intel.com.
