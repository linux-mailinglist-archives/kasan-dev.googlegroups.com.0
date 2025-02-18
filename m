Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGUE2G6QMGQEXJFOOFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D6B4A394E2
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:17:32 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3ce8cdf1898sf40373465ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866650; cv=pass;
        d=google.com; s=arc-20240605;
        b=D0RugZR3/CbN9xi6fRFd/RToEQlLGLpimzSxtKW2YCERIPgRjiu2F92lwUCcQsSMyj
         X8h3Iq7zDuZVyBiS3YdgRNrI5sjhreRaRcY1SyiNhuFmWbz8WUqtflJ8Qr/x4jvcSef1
         UInsHdohH/td9DM3lPExsoadtzMUD8/KLm3nWRP/Ze0Aj9YO/imiEvaZynttC3RxapWf
         tDPirp0vVKG3C/MXAH7odMkj2IRUUPi/aQXeWK4P4WOqe4mFK1iOWoFZrCjDPOxs4VrB
         fuoyPOTgU5qFNUtoP/oJemEywKgxxCbzoO5q2Yia5iVP4gVIOxfh078Glu7xvD5mIkcJ
         lUdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=frJZDI474eXZG1ou0yCgwQ3vYF16g4A1HPw6XGrRpbA=;
        fh=lS8MYOQqh/h7Njlo9EF5C/UEsIrZY7ODb9criu9W6rw=;
        b=IeRqrIwQiqgKqb4eIk5GR+ycmrNIUu01koaNJ+w7Q5D17l61H1RPlrnutQQMRs9RFl
         O2xSPFDHEivbXUu/kM4sOTuEPRwXY+05jtEKJOPsqFV+1+hPfVKt9yfVaUDuB6bXpse5
         2xTwZrGO1bUsOcwb4FptYCVaR+TiiMiC2XZybu4mAWSkGbDxg6xj7XSjEEmjRaeP4nYe
         wvewBtG6KdmFXHsBRC9YtbImMICag3WoIw0itd6uR+0pZdE7sOrDCIIFa+QOfw+6IkPQ
         83bA2lSVJypn2E6u9ZZR4lGuHBn0rMcXUTkNjGq6+xbcP7b8R+2MvJaY0uaqvEOSFjpQ
         7v3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BFI7yhzP;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866650; x=1740471450; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=frJZDI474eXZG1ou0yCgwQ3vYF16g4A1HPw6XGrRpbA=;
        b=a9MTMYTZt7oUS+3RP1vJfDJsn+UEWgi9pbz3DZj/OR5kHWpTomTFBEPBoidvqWTRT0
         ZVOUr2ukwUmPFwnL9uZOV0TbBEfNU0eNKYWBjGFbHZmm+Q8NH4v09OrFvhMInMa/c29K
         DpcoPbyHAlUnOtse8GjTHGUFy2d070GgRryQ5uk3htkPI5lIHEmw1vcKkj6OStvn1/u6
         8kzcPkh9B7F/yJuj6NoTXlsiGTzo4AplmCvxAfuhT9vf+Ke2DdRjVIONlvVeFAJzo/sP
         Xmf/MskdBsn9D0POYBWcC3pZJWHve4Tn3mdY5L4GBYwq1bxKVAkDzoHYcc9wCVhSIv9s
         f0Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866650; x=1740471450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=frJZDI474eXZG1ou0yCgwQ3vYF16g4A1HPw6XGrRpbA=;
        b=HzlTYU3vM7TC/bLUe4jmlT0RZXxrQuU9EfNDARn4MDpFVwJwOys6V39DFcNHYr7ulX
         JtTgIK7mOvRHTphs4wEIlKtjRfPtAxTGowxth0BM0oX19Y5DLl6pk/PYQVTUFKmLXL5W
         dsQvXmVcYoUDfhciHvmFPWZMX5z6uWHrFcgFNjY9fWpSJQT6ui0mfUC4uJczc+IX16w0
         wFv/F2osoHQznTN3F/YlSvcgZCyzUbOoCDcF64Y0dqvAZohpkZdmY+uhYOCBlYC25MRg
         Ekt84Jw6sF0sthM0t+YagGLP/JAD1c/BZpMkXtU5SGUeyORZpqx5YBc4kh9jTiCbECdX
         h0Hw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdSY1ohShiUfeROkXlI9fWbvov9/9h2oKsSJ5bUlYuc6LNMQmRdofvA6QbquUlpidlUb72NQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywm+c0cU0XXnOznTR7HBHRXGyaypDH/er3K7wLVNjWua4eTkI15
	ed/hMI+SlY3bioVeGW/3L3XB1P/L2TdA1HhWJJJqtzXcdNuV3ObW
X-Google-Smtp-Source: AGHT+IH4oHHDYzlyG6AV8OBpe68Y1JOE6Ai+OXY3pDXiM00cyVNWc7Yt+JePoB9g2cCA6wjlwstsvA==
X-Received: by 2002:a05:6e02:2411:b0:3d2:1206:cabe with SMTP id e9e14a558f8ab-3d28095152emr131206455ab.22.1739866650497;
        Tue, 18 Feb 2025 00:17:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE0h2S47wm8P719V8qZh9cwRFffCLHq6Pt/3j/HeqOcVQ==
Received: by 2002:a92:605:0:b0:3d2:3dc2:c429 with SMTP id e9e14a558f8ab-3d23dc2c78fls9912415ab.0.-pod-prod-03-us;
 Tue, 18 Feb 2025 00:17:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVFvO7ph0iIZQspQZda3seOYqa+Ojfsv0RThRV1amJ7de3fJC573KcLkHmlkitBpstfvVD6v1RJJS0=@googlegroups.com
X-Received: by 2002:a05:6e02:19c6:b0:3ce:4b12:fa17 with SMTP id e9e14a558f8ab-3d280918309mr102098275ab.19.1739866649050;
        Tue, 18 Feb 2025 00:17:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866649; cv=none;
        d=google.com; s=arc-20240605;
        b=H4dWepQjbCkYyn8nJYNabfohFyCCRoTFhOTw548stS9UWQ4uwu6y4QbsAwEubqUaIE
         PWr0GWNHDHaHNCCJZV9pVSiCE0SFcubYg8XCrPA0zGuB2vNW0nygdh+J+iXWeEhlaGKW
         pld+XwmYhkxThDvjZ67k3aFN9SSM1oVA3dM/f70AwkmM8w5BocqSMZV+/M6cUewEGCBD
         PFqlRGECovrQqQWuCoKc/nW0Swq8O9+6n1xhUHQbbnhGbQwfGRc7ieKTBg/Rntv6wAe9
         Jrbhoj7mItDesliWri3jQ5Oarzc9bfB9Zo8OyKyvWeIBTXIMzuq9GQzI8fMFbwLnWr5V
         Y7MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/cX1p2lxroC4wffAIvexwPR0Fxx/XW76IQ4D/P2WkdY=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=ZGZaf2p91GfjcRKMHjt7PEdxqjX1iONBsv10MZdhq8uG0qELMunKFfxngGkOxmSf17
         Sxbhre0/OVElINc9q3Y3FfDJCRuRjUugZ0iTixAoorK1RrDIk5P/bZ1NLrVRI06Gzq5Y
         WCkJKEyNJu7uxnVrQH3EObiDvKTmS2MkPsOhdQVAZA8DuLC1PnmMN3OoJIj9gGTEwb/Y
         UgwABEtLPWDtttiZurcczQ6EiY7y+iwCZjx3Vd2ITNLSAb7qMFs7qK+GkPFZfgvhi2Pk
         huCqHZFocfk26V00RoxRbWn/5ABiSKqhrGvHll1DB1QGlv4VcN6GWORdsO7ujass7I5y
         ockg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BFI7yhzP;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d2ac802fb5si474225ab.1.2025.02.18.00.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:17:28 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: y+mwikemTYaDsmCmL/w3mQ==
X-CSE-MsgGUID: pXdd+Xf9QsmNfrDKlpa4XA==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150136"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150136"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:28 -0800
X-CSE-ConnectionGUID: xKQi23p7SyujmVCTf7U/Zg==
X-CSE-MsgGUID: 9P48bDiJSRi9kqQCnYaSFA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247544"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:10 -0800
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
Subject: [PATCH v2 04/14] kasan: sw_tags: Support tag widths less than 8 bits
Date: Tue, 18 Feb 2025 09:15:20 +0100
Message-ID: <09962dd580a56e308d98b7bd5829dc57928bcc40.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BFI7yhzP;       spf=pass
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
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/09962dd580a56e308d98b7bd5829dc57928bcc40.1739866028.git.maciej.wieczor-retman%40intel.com.
