Return-Path: <kasan-dev+bncBCMMDDFSWYCBBS4F2G6QMGQEIYUF5UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BA2A394FF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:20:28 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d2a63dc62asf5688235ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:20:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866827; cv=pass;
        d=google.com; s=arc-20240605;
        b=BfOJBFOVSXqRN6iL5rRTmH8naAu1OdfSw27W0dccKLpREFF7+SgfgZ6WcJON3Cjb9d
         N1Z3nS60sDWN65QsSrVRkezvfwh8k+PJPBjdtMvVISTTjYBGsEmDxt7bwpdS/nINnYHK
         tcG/F7nyrMv+wd+W+N0pON0cSx0G854caHiiXdbPnVw4NzIdpMcoBz16lsQfBWWsslsM
         xyXHuX66pRCmVERqXGSLSlC9T77C7rljTKZISCy8OO68sf/AHJqd1SB5lKZkFlDcNO3F
         gp+T1ynKssxhpzFEtxcQWZOdIWDhnDIb4kqMiG4qDfuSFSm+6aBfF5chi9E4audItCZ9
         DuwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XycO6pueW/7pfcID39RNsextUsZMsGyCBAJtuG9N/OQ=;
        fh=toyiV/7Fzsv0/eKM3QLkqQu1Ku4yhtwINSXfUlZ1zr4=;
        b=QvCh8aL90gurHtKT7/0GR8lKSo6xyGq5yZ7Sb/qYTAPfBYpU/xXJIf6PF8m6BHckk6
         XOLWjYrtqotxH/FvPcoUPEgpxcE3yfCwxtwtW441A60Cwhj4eC0WRNpdo8PM9mhnXwCE
         wmWRpnHmz/dYx/vFcT5H4mkeiEaAzb3CebWkQ4yfhN2VtnYn9Aj4BtV3tg9/kHiQLTx/
         6C+lM9TGXzkdFvj4W4dJJkXntF0lRXslu5ONaW+2gtszCmBRDYyDYbuxzUgG8W1cKZG1
         IUqRvCz0PWa+mg9zYTIZVM6V7NFrj2e0UnR/vKg5IRpTpW1fvcGW7duUzwjXGl4WQIZN
         kvAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="DNrLW0/0";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866827; x=1740471627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XycO6pueW/7pfcID39RNsextUsZMsGyCBAJtuG9N/OQ=;
        b=K3lvRbygo2qQe6K4vvVjYfzl/3ajzERRMUFex9zj/hQkscvnOpFDT36Rje8JPITZrJ
         V6ONY3M7Ouv0QMeYawdvDGa8URW0FsWen9wHYnYcAYzPsittrEFx1LEiYbUdPZIqkr5I
         XjYCWd1IReDQHyG6P/gt5Bhe4WXnNqQxJBh+gaKQqjs95yiGCfIPwVIpy/YNFTNKc//w
         aCF7T9oR9YK0IImTaFjOrn5nl+Xq/zfGDCruoPpREMTg2zwIOvfkFzANMVh0bnuEDGVy
         Tfg+cIDAWkvIBdruzTqV0NHrUJeD4HuPYxQdScShuzo113Igtq2evMzycaQ1LpG3iI+X
         W00Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866827; x=1740471627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XycO6pueW/7pfcID39RNsextUsZMsGyCBAJtuG9N/OQ=;
        b=pS/5qgjPLr3Mdj0bgHvKRga7B2tfyO2d9CPeZwNKDz9ePgj8PIEnvrJLFbp14aL0WS
         gkH/Dvoeege01XORvaIxjcKF80fxkGdx1lX3TOSgIxmqmB5EHc8vM8xXfAdI1WG9ula8
         F89oq0fRzfBestP3434uaMVHVrW8riPAf+jTBjWbBS0fK2bXUzVXmA4iFtXK0lm4lb4L
         ZQ4wVs3fV6Q98kjsT/gjMNTcv2OcQgJfN3SVovVtda7KDhLVufoJ+8Fax5FWJTmomX3t
         17dB2VFyMlr1cpi65n8Y4OBU9exITQI8Fh9TtdIUbz6tSXpKuzOsTsVisdyMheFqk200
         J22g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+2AdIjfr0ObSdU/AKTJSAMHmKIePZ7KbF5xR7KpQdWND5gvoXm74Uwjw0rlpd43y5s5DZuw==@lfdr.de
X-Gm-Message-State: AOJu0YwCHGb8kCgWCaiL0baP5/gpXf/9NIMQds6muSGK9OlEM5H6g4SL
	YCpdvVWBxa/1HvxBUxBCoKdlo3ZChx8L38A/6w/K8FRWwGJGYEQL
X-Google-Smtp-Source: AGHT+IFXp7otfGXnKbMSQk6qaW+wYltRvdB/eng+Yyn7CnGgnhkGNP2zVchjMK2pp7uh7t8zSQbFZw==
X-Received: by 2002:a05:6e02:b2f:b0:3cf:c82f:586c with SMTP id e9e14a558f8ab-3d280763f46mr96452545ab.4.1739866827371;
        Tue, 18 Feb 2025 00:20:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEb+E+8g5ju15hmkZqKsfjS5yszu9BDK8al1xebDmWleQ==
Received: by 2002:a05:6e02:12e1:b0:3d2:abf9:2b19 with SMTP id
 e9e14a558f8ab-3d2abf92c04ls1949875ab.1.-pod-prod-06-us; Tue, 18 Feb 2025
 00:20:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXMrOzbKjNcudxtPUtslA7C7hd/9Nka0HqIJWIhVqbdcoVfKeU+7K6jZCvMvHlCsj+s5eNHj5MasZY=@googlegroups.com
X-Received: by 2002:a05:6602:341d:b0:855:2bc8:69dc with SMTP id ca18e2360f4ac-8557a163688mr1131802939f.14.1739866826655;
        Tue, 18 Feb 2025 00:20:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866826; cv=none;
        d=google.com; s=arc-20240605;
        b=cgJBQ4DcJAlikydA+zR12EO4F3VVvB9vWRiBa+9h1gzamNZogFxwCXFcTlkd8m1Uvh
         6MJtnIdwCQi1NuyE/QE6mInMGv/I9jaTOp+kikP8HVGYu+Wqkx6Olg2Olv7GFr93by+s
         24G0tlZBOujm3zvePnuoR2NrVHwyqsiHVAqg9ylm6RLjnxXJGBlJtiMmCXzUBEuUHWFR
         OMJRR+UL1ooqAjYomVz+S3qiKH90M7UobiF7NiBcRpK9cJA4Jy5V66XN4UXPNPTmwcni
         oyqfEfIVypHI2uHIDqix3PfpmRmWWUFqPNoX1JIcFRbHGkANK/eMBw3VrwSCu2uonnoZ
         It3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LvxOhHcvAG8oEwurNxE+t8tG/ggtZ5vdhW46eAhAGP0=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=F/vMMRCvoRL1afKX5Tf/lcT8Yqs/F507P4nM8kAL8pMBZK6pQ43r69IfY2OanHz8CI
         KFfmcl1C9LIV4WYCp/nukNVP3YKU5xkzxbw+O+3lUSGagjC09l7rF30DXoOG9S06kDti
         wtV0zJ+icUTP4pBaMhDjL56B1v8rWqIytO5X+hB+dvn+C2TeIiy00w3dOtgUxYVR2veJ
         5HOEbT97V9UyS2s9KGiYhd5xSP3uGuCTeUIXvUR3S3uEo0peO7EhC6qXyRETKRv1iESC
         dUQNfBdlGGw8aMzhVwvrQUIZg+zP/wobxqda+5KZwsY8g/8FVMQkkknxGLPSzZwqHpjL
         UD6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="DNrLW0/0";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-855a7b63574si3686539f.3.2025.02.18.00.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:20:26 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: QEvEpbfZQ/yOISgZVX14jQ==
X-CSE-MsgGUID: m/n2pZpLTBq8BsDCuepHNQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150576"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150576"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:20:26 -0800
X-CSE-ConnectionGUID: ZBHrRLDGSHmtBzW5XHTLlA==
X-CSE-MsgGUID: DOPqudHOR6e9SmDmLLK9pQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119248027"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:20:07 -0800
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
Subject: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
Date: Tue, 18 Feb 2025 09:15:29 +0100
Message-ID: <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="DNrLW0/0";       spf=pass
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

On x86, generic KASAN is setup in a way that needs a single
KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
to facilitate boot time switching and it's a compiler ABI so it can't be
changed during runtime.

Software tag-based mode doesn't tie shadow start and end to any linear
addresses as part of the compiler ABI so it can be changed during
runtime. This notion, for KASAN purposes, allows to optimize out macros
such us pgtable_l5_enabled() which would otherwise be used in every
single KASAN related function.

Use runtime_const infrastructure with pgtable_l5_enabled() to initialize
the end address of KASAN's shadow address space. It's a good choice
since in software tag based mode KASAN_SHADOW_OFFSET and
KASAN_SHADOW_END refer to the same value and the offset in
kasan_mem_to_shadow() is a signed negative value.

Setup KASAN_SHADOW_END values so that they're aligned to 4TB in 4-level
paging mode and to 2PB in 5-level paging mode. Also update x86 memory
map documentation.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Change documentation kasan start address to non-dense values.

 Documentation/arch/x86/x86_64/mm.rst |  6 ++++--
 arch/x86/Kconfig                     |  3 +--
 arch/x86/include/asm/kasan.h         | 14 +++++++++++++-
 arch/x86/kernel/vmlinux.lds.S        |  1 +
 arch/x86/mm/kasan_init_64.c          |  5 ++++-
 5 files changed, 23 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index f2db178b353f..5014ec322e19 100644
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
+   ffe0000000000000 |   -6    PB | fff0000000000000 |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 6df7779ed6da..f4ef64bf824a 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -400,8 +400,7 @@ config AUDIT_ARCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
-	default 0xdffffc0000000000
+	default 0xdffffc0000000000 if KASAN_GENERIC
 
 config HAVE_INTEL_TXT
 	def_bool y
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index a75f0748a4b6..4bfd3641af84 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -5,7 +5,7 @@
 #include <linux/const.h>
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
-#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
 /*
@@ -14,6 +14,8 @@
  * for kernel really starts from compiler's shadow offset +
  * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
  */
+#ifdef CONFIG_KASAN_GENERIC
+#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
 					((-1UL << __VIRTUAL_MASK_SHIFT) >> \
 						KASAN_SHADOW_SCALE_SHIFT))
@@ -24,12 +26,22 @@
 #define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
 					(1ULL << (__VIRTUAL_MASK_SHIFT - \
 						  KASAN_SHADOW_SCALE_SHIFT)))
+#endif
+
 
 #ifndef __ASSEMBLY__
+#include <asm/runtime-const.h>
 #include <linux/bitops.h>
 #include <linux/bitfield.h>
 #include <linux/bits.h>
 
+#ifdef CONFIG_KASAN_SW_TAGS
+extern unsigned long KASAN_SHADOW_END_RC;
+#define KASAN_SHADOW_END	runtime_const_ptr(KASAN_SHADOW_END_RC)
+#define KASAN_SHADOW_OFFSET	KASAN_SHADOW_END
+#define KASAN_SHADOW_START	(KASAN_SHADOW_END - ((UL(1)) << (__VIRTUAL_MASK_SHIFT - KASAN_SHADOW_SCALE_SHIFT)))
+#endif
+
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index 0deb4887d6e9..df6c85f8f48f 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -353,6 +353,7 @@ SECTIONS
 
 	RUNTIME_CONST_VARIABLES
 	RUNTIME_CONST(ptr, USER_PTR_MAX)
+	RUNTIME_CONST(ptr, KASAN_SHADOW_END_RC)
 
 	. = ALIGN(PAGE_SIZE);
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 299a2144dac4..5ca5862a5cd6 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -358,6 +358,9 @@ void __init kasan_init(void)
 	int i;
 
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
+	unsigned long KASAN_SHADOW_END_RC = pgtable_l5_enabled() ? 0xfff0000000000000 : 0xfffffc0000000000;
+
+	runtime_const_init(ptr, KASAN_SHADOW_END_RC);
 
 	/*
 	 * We use the same shadow offset for 4- and 5-level paging to
@@ -372,7 +375,7 @@ void __init kasan_init(void)
 	 * bunch of things like kernel code, modules, EFI mapping, etc.
 	 * We need to take extra steps to not overwrite them.
 	 */
-	if (pgtable_l5_enabled()) {
+	if (pgtable_l5_enabled() && !IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
 		void *ptr;
 
 		ptr = (void *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman%40intel.com.
