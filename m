Return-Path: <kasan-dev+bncBCMMDDFSWYCBBNUC5XCAMGQEZE45YZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 59796B2285F
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:20 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e55eb7bfa3sf13660885ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005239; cv=pass;
        d=google.com; s=arc-20240605;
        b=O82pRBZKQkdq0HojreI3NwLBBahKG4LkiAokMphtM6rnIhRiZLdDiZC8bXf2DoSaiq
         iEJJRJVTbPZA94TR1RLIr0rPRDfrKG+mz1pN5bA91Fd6kcFJbEG9Al+EEU3w89kzOKRJ
         v5Gt3tXgrzvSFlOcsBjy7KsuALzR0Eqg+Gqb2YbOs8Ff9ZtXjgwaEi2aVppHyGaXr6CH
         Uv4NF1Y0DXMUaEEY3DrOnYijhbGyW+XQ+lVeLzalxFBWv5BRbYoi1a38kRrJ6dxpHhbK
         xPd2jSJmEzDJjpngtIAJ92BWfRizAR4jfYzWmsQiKzKs8vjF2bDXvlw88z3wYwajnmol
         u4SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Hh+2MvwBjE/FgsRNLg4FCoiJKgApOiRYiUHz8fMwczY=;
        fh=ZFycWkdtkEV/xKbAXLZrojnmJfG2zXST2kt2/vgYwnA=;
        b=b76WpR4DcvGJ6/tbMKTIOVX5flchAkrzf0kesLPEsx9MSCeFlr7FPGL5daWJajLOC0
         7XZ6N2ubcG8qqw2zL8DdXOnYxaFk5f5iDquoF3eGcIiUIrIh55zSg3cmEEtD4bqw70rU
         40rrMS+48bMjlPgCm+S7EYbloGLRWoc90G8t9xLZaNTlqdxwvfMJc7fECmEk8ULfQJes
         Q2T7rz8bNMM8VX31Fwin5Lk7+yGhdgRo/WtErIqQYyLERFYMXOJamlmg0Zkwl0DkTCqu
         2pMJbuWFjJsPMcF5CUeLGVQWgtWNB/W65o0eUtlDpczvtVTPVXX/uE4udfMFQ8sxrdzK
         DzXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Fo0Vm+Cg;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005239; x=1755610039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hh+2MvwBjE/FgsRNLg4FCoiJKgApOiRYiUHz8fMwczY=;
        b=ssvCLyL5fjIV1KCuX3UUw5+ZjMCescxCOm9oUAebNdmhUEa55Jbs3idY+6Ohdx0s47
         sUgGI/9W79D3O4Q+B0S/N2EfvlZWTR7WEGZWWziqADF9UK4fZA0i6AkF1KROyjgUbqZd
         niOOkobfYJtTRbJaYgDtwsfuhupXBcpIhHzDFF8MRIgrLDtC+14TSuh3VuUhLoowjOKd
         lW4n7qWONvcjDLNRMLR5tF/PKlDhL8gjSqYXMLXMIOCanFAdizbHb+gidVW6+xZ0zqsq
         wKQc7ouolO34/nY+05Ks9+DYspKXlvBdedth2qCYtmiVgLe9NV7/uWGaiW/MbGHsc2Ca
         jtVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005239; x=1755610039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hh+2MvwBjE/FgsRNLg4FCoiJKgApOiRYiUHz8fMwczY=;
        b=imXy/6znMV5Vxa/372TbIujFg51s1NCWO8MgAPLLzhEEuxzXVaAgPl4AqoTGmsOQdt
         R00Axu/NRX+rUOSy4fEjD/WVQkTczPYT0Bo/k4KjQK7dFkxs/mqjmfcpO15axJVlaKf6
         SiF1QomOu2NNRtTJEHZ/HNA05Gwz5juCdQ7gVYH7WbNxQpYYdjcR+T5G3BiqqdabF1bW
         ri8IPC2aapwvcC1GY3Sp7le3a5jCARUNovFQuqKhTsf14MakP6WnShAS7FQYAg3U6F3F
         jVtHviVm4HVfHFc3w92CxxDbfL1jR9iHj7cQxWNUmwbmEmRSoxVttQoQjNYSIz3g4OoL
         N4/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8MqBO5FxNE6TNWRAd/PJCsZOWe8vESaW7std1L9pQgfEc6xG+Ri0ZqV5bg11N1cxOMLCPMA==@lfdr.de
X-Gm-Message-State: AOJu0YyE2MukdJyMP9B0tjkEPstOrG60cfdBEBjJaiBASkIH5xxs7h9v
	h05Gl1EPrO2SP7CfNYXOnKmOGeLqkSXHf89erWtqMVGNiiJZrge4gacF
X-Google-Smtp-Source: AGHT+IGhZgRelhEJyP2EmTijpew0DM59FOqdfNC8vEsDeVvxWKUEqE3GJTAJXF/Br+yFmSraQ6NE3A==
X-Received: by 2002:a05:6e02:1feb:b0:3e5:53da:3b8 with SMTP id e9e14a558f8ab-3e553da172emr106722155ab.1.1755005238967;
        Tue, 12 Aug 2025 06:27:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdArhOy/yq7hQhCwM1E4P+tS7V13uSvIS+kwHMOY8iqtQ==
Received: by 2002:a05:6e02:3f07:b0:3dd:bfcd:edd6 with SMTP id
 e9e14a558f8ab-3e55a8154a2ls11364415ab.1.-pod-prod-08-us; Tue, 12 Aug 2025
 06:27:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcuUJc1opgkkeK75AwUvcap/BCF//3FgOJANWYWr6JN8BoufU9k9N+HsQ8VYPA14BzWJXqFoCoyuI=@googlegroups.com
X-Received: by 2002:a05:6602:1492:b0:881:7837:6058 with SMTP id ca18e2360f4ac-883f10dcd58mr2968329439f.0.1755005237961;
        Tue, 12 Aug 2025 06:27:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005237; cv=none;
        d=google.com; s=arc-20240605;
        b=cLodu6T0g/XLf61qE6he6I9NPONpzuS8e3nXO2X1RemJrXgkjNs69VoN1TASAfYSt1
         VS125MJuZykRAn3ZeKQQPb8KI1kDqB5hau1hzDmpgyPcFczRD9jCi+dR7oUpe4Uyx/JA
         aPy7v1Z2ncuZxMkScsPGyoXP+nCzFX8n9mz+i80cY74wv8mnl+veyanLJgd6fuBnxwj+
         yPLZuTFmCVuUz50Z72d0y9eRsf/hgPxvexcBqWcd1MNH9pUJB62OEEGagDE28WrW1Za5
         1IXEnrHZ7wHrGbh5WtyqOfGtPCgpAcWJYaG77gPeHUYEBgUJfpWnxZITdtqGAwTmgYkY
         Oxmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6K2KDerpzPX7U8bmSLlP0LUJqVmYwFaKvvwSlmusGeg=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=I6K9v9WUEtggyAGLdI8Qh3wSFxqfSfEI1COVrf2mgNtxFwCg5k6QbEl5K68K93XR9X
         QMeonDQn/wphNS2P7VTFrJvJdAartiCwd1Dikg025yBpm7MpkoebLroAHbOIc2cTbe9m
         xopLgfjh0QwNSVQWSew6bhKqwvdhpKAL7AfpePfq4yyETgiWLn5Ac/ClShWi3L9VuAKx
         nf2b+dzmTIGTqheLL6oIXCPKZbVUaMlX0dDNIOb8xjd7tu6M4GM6Hg2IoY5bky6ixGgk
         08SPfosEYssPhyyFd2iJKd02Cw+XB2TG9ScPPcaG742mAr4fqDZziaGgf49qz99Qmz/N
         bzBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Fo0Vm+Cg;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f1999f30si40539839f.2.2025.08.12.06.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:27:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: e8SJpI6OQ6CpYnJFSlGNTQ==
X-CSE-MsgGUID: cgsCESZ9RGOogy4Yex1xRw==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903482"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903482"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:27:17 -0700
X-CSE-ConnectionGUID: wC4pRigPTk65sPn+FhCwlg==
X-CSE-MsgGUID: 65CUt4VoQ8Opy1+rKR26tg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831425"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:55 -0700
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
Subject: [PATCH v4 06/18] x86: Reset tag for virtual to physical address conversions
Date: Tue, 12 Aug 2025 15:23:42 +0200
Message-ID: <01e62233dcc39aeb8d640eb3ee794f5da533f2a3.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Fo0Vm+Cg;       spf=pass
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

Any place where pointer arithmetic is used to convert a virtual address
into a physical one can raise errors if the virtual address is tagged.

Reset the pointer's tag by sign extending the tag bits in macros that do
pointer arithmetic in address conversions. There will be no change in
compiled code with KASAN disabled since the compiler will optimize the
__tag_reset() out.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Simplify page_to_virt() by removing pointless casts.
- Remove change in __is_canonical_address() because it's taken care of
  in a later patch due to a LAM compatible definition of canonical.

 arch/x86/include/asm/page.h    | 14 +++++++++++---
 arch/x86/include/asm/page_64.h |  2 +-
 arch/x86/mm/physaddr.c         |  1 +
 3 files changed, 13 insertions(+), 4 deletions(-)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index 9265f2fca99a..15c95e96fd15 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -7,6 +7,7 @@
 #ifdef __KERNEL__
 
 #include <asm/page_types.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/page_64.h>
@@ -41,7 +42,7 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
 #define __pa(x)		__phys_addr((unsigned long)(x))
 #endif
 
-#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(x))
+#define __pa_nodebug(x)	__phys_addr_nodebug((unsigned long)(__tag_reset(x)))
 /* __pa_symbol should be used for C visible symbols.
    This seems to be the official gcc blessed way to do such arithmetic. */
 /*
@@ -65,9 +66,16 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
  * virt_to_page(kaddr) returns a valid pointer if and only if
  * virt_addr_valid(kaddr) returns true.
  */
-#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define page_to_virt(x) ({							\
+	void *__addr = __va(page_to_pfn((struct page *)x) << PAGE_SHIFT);	\
+	__tag_set(__addr, page_kasan_tag(x));					\
+})
+#endif
+#define virt_to_page(kaddr)	pfn_to_page(__pa((void *)__tag_reset(kaddr)) >> PAGE_SHIFT)
 extern bool __virt_addr_valid(unsigned long kaddr);
-#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
+#define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long)(__tag_reset(kaddr)))
 
 static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 {
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index 015d23f3e01f..de68ac40dba2 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -33,7 +33,7 @@ static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
 extern unsigned long __phys_addr(unsigned long);
 extern unsigned long __phys_addr_symbol(unsigned long);
 #else
-#define __phys_addr(x)		__phys_addr_nodebug(x)
+#define __phys_addr(x)		__phys_addr_nodebug(__tag_reset(x))
 #define __phys_addr_symbol(x) \
 	((unsigned long)(x) - __START_KERNEL_map + phys_base)
 #endif
diff --git a/arch/x86/mm/physaddr.c b/arch/x86/mm/physaddr.c
index fc3f3d3e2ef2..7f2b11308245 100644
--- a/arch/x86/mm/physaddr.c
+++ b/arch/x86/mm/physaddr.c
@@ -14,6 +14,7 @@
 #ifdef CONFIG_DEBUG_VIRTUAL
 unsigned long __phys_addr(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/01e62233dcc39aeb8d640eb3ee794f5da533f2a3.1755004923.git.maciej.wieczor-retman%40intel.com.
