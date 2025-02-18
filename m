Return-Path: <kasan-dev+bncBCMMDDFSWYCBBQ4E2G6QMGQEO4RQPII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C6FD6A394E6
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:18:12 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d05b1ae6e3sf41572345ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:18:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866691; cv=pass;
        d=google.com; s=arc-20240605;
        b=QVzOsnzCw0X38Ha5vgentK1Ov2Izkq8I8dUmQuNqJA/Pql30G/Wiz82SVOOWWKolxc
         X2jwhBx+kmVN4ajsaady7sg+Cee23bXtXJAW9AiG7E9x7B87AqiOdBJwPoHrYZ1kmPU4
         pXH+GpU9n9ouzya2t4sF4FRi82e0ofcVV0bH3r0ts3Ynt77vWWqfho13Ce3RQVm2PQZO
         iiwPJG8RH3+V7uZ7NTE/UudXWFDY/XtfVZ4tso/gZye38UItF4yH3oYG0CQUEaYlFBZM
         SgxeuwEMOORC6vX1a06Q4AJRBZgQ4j0DsLBROlWbuyLDEBE3WxfgAMJ2MjGjU+OH6v6b
         6FLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=numUTD1b55c2Db98or154sRhUEeJW5MZLGBuCCBlago=;
        fh=DNbqmYn6PIlP6rlrYAIeTBqL3ZHMeyQbxweUzvXjgoE=;
        b=Mcq5L3Pmx2B8IsLIgvRmMZab7GVxW6EJejWixZkqBG7bNWweSzYUWUlucgvw1GJtFC
         k4RTM1OsbHDH/oqGmOeNnl0il1Nfbet8/XmnKK8n371tkwXAK5MqGS8k1iOFApGm3L3O
         fR4csvLXO9fPz5TmxvaFTEcAroS6kOzt21DVExHujaeO00z40qHFLpwa5W/L2/HWdp3/
         fioeymLHq1pYNvt2N2lLsKDiPtl/N5S4EcluAD2PUqE0Dk7XA3nRBGUInsdBJb1sOAEw
         8kpLgDkhbi6w9LmFPUOg3cNvqsDTgRPDAo33CNaeRLqrUGCSMMIchyG75Wr+yQoSRoAj
         UfQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=h7RIXWs9;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866691; x=1740471491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=numUTD1b55c2Db98or154sRhUEeJW5MZLGBuCCBlago=;
        b=twZDI13dbwUWM7LKMv3nv4DqaX7aXBw+xi/qZV3cupq+DFy37EfKIIf6dheLZcOboy
         vaH9buUAOySa5ySO8q/1glPKdel4/nHeCP9ENLheByCtzm1CdVCsM3dtQyWVIKaHlHg/
         KcWw8JJs6mX48QsaVUwpDXe2mf8T2JYuYq9xB+0WGOw1mX2cXQnMyFLbUw7nmbt2mDWV
         OEEaIlVLp1BslGM+nxDeIYP9UuzbDRQe6F4LSny/i05aNhGakxT4yoNK3qviu/OjMNwQ
         NJdf9RJEezJxINVK+JkO0Rk+5osC1z742woPr+3BSsi/4VtRxMgNDcV7lkEQyfXQdeqU
         oO5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866691; x=1740471491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=numUTD1b55c2Db98or154sRhUEeJW5MZLGBuCCBlago=;
        b=ST74atWAL14eAEuj5FNx5rZRm7OWgh2rFnOTZP9Jsu4AqQXKRfmJ6fTyfI2kl3S4X6
         tjfq0Po2A4aR7zkLvU20SqP/mak71+NWfOeoCvLRRgDUy+RtqPJfi2hH+RMvYUp/CQuL
         GbIjPcx/93yDMcKnss1cwJ7UPAvwE65RPVD2BQga1xhw3KvWmNlEPnUL+JKR48lBb+iV
         dxd9MfUxpgh+oc50J0HsGP6qE8gHAWP2ir8zA6AMivadS7DOH8GevzeEeg5wwpfMEg38
         kfyIJr87V1HobqNoaesIUn1Y9Em/qxxcmHcs4etH55ITvWTTvGiewXK+I42tOdX01FPv
         TmKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdILHj3FHDYuPVrnGKqyyn2xrQHPxSMZKaQaCrZPJhYYpN/m8Jx7hGa9+IzwPKoSLObGMdRw==@lfdr.de
X-Gm-Message-State: AOJu0YxPGOuoE2KI7CbUefrcdVbOzjv+cubLFCK87tobCX5HgLspP/NH
	xbHWeAtb39XMdWa8cM2Eeqv5OFIkUdpsqmmySJF0s/eNVlIq0V3J
X-Google-Smtp-Source: AGHT+IEEndnurnGD95GQcUwivqbqkFMXQ0bShmgY3U6er7DeH00HMy1d2T2QsCh4fu+tTPSuwFoccQ==
X-Received: by 2002:a05:6e02:1aac:b0:3cf:fc11:90ca with SMTP id e9e14a558f8ab-3d28079efeemr106209935ab.6.1739866691363;
        Tue, 18 Feb 2025 00:18:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEqVKsp4DLSxS2/wl/JSVZH3QEXDLSOQ1sGNae99m5iSA==
Received: by 2002:a05:6e02:2167:b0:3d2:af50:1124 with SMTP id
 e9e14a558f8ab-3d2af501350ls862545ab.2.-pod-prod-04-us; Tue, 18 Feb 2025
 00:18:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVy22kRL31+Hmkx1N/ZV6/cxogGXVRH2QXM8eR023i01wHPRAfZeUGaVjXiYx/PrccNIKHQXG/LZA=@googlegroups.com
X-Received: by 2002:a05:6602:6408:b0:855:31ea:da2e with SMTP id ca18e2360f4ac-8557a0ef458mr1256640539f.6.1739866690671;
        Tue, 18 Feb 2025 00:18:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866690; cv=none;
        d=google.com; s=arc-20240605;
        b=RaeSBQOU+H4fZFp7gt9TKlfJvZs8nQMbw2IPrJKiDgKnIOIN7i/IsnvAZcTvgM2og4
         rnK2RHyCcigoR+lXPz+1Nz+5jjhDq73jlTJwBi9tJ5hcGq4Ge87h3gHIceMrK2xusMel
         G6O/C1F3cHdYums1wXBYTjdlY4xaHvCezm9w22L0i/Th9x/NCYH9vFtix4kTf+HFqyU0
         P/XKWfoTrDglcKosLY9ToTXEC9fg3oH5TGZ6gKKb4S4z/BTlSjbQvzeU+CI2xResG/Fw
         iGJ9oMUlpodybM3q6NwlN8TaUn5xTOQVPmI/bSP1/J0j+gnEnC41TPAjd1GKj/EnF6Yb
         DUMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hd/rmwwNUxEWJaueMUiOYmy433JWOqfiDFpi9akupUI=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=AdWNoS+cL6Vggswm0c6StqPXn7rT6jkzfhGHWELvIUZQAMHo9u+ZRJPaduxTjY7boW
         uNhxi3MntsdEV7e+6GeDlNPap0SvjJBwnCbDbq63UXUZj8bHhci2Rgz8FoqsUn/103EQ
         eA8EYnUoIqk/pJ7IavEHIIi1uoXyUlQGLqSd6t1tuWG4u1AUahvTDR4LtyxFAUj+iwWf
         WWrLG/XLEMDIJ2i4vCIlyYX31ME7ThOB8yBXg7qkdLN5pFLM14PE/cfW0wxRTx8c1stm
         edw1GbVnRnDW2sPvly7ARvzY+7wffUKHBFUi8U0JgrJjPk+jP8V2sE7a8kQECzbCKApa
         mqMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=h7RIXWs9;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-85566eda33bsi48908139f.2.2025.02.18.00.18.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:18:10 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: ANzVtH06RFOkWUYLdsP8ww==
X-CSE-MsgGUID: K/O3XTx5QMGoSUCtGEBwlw==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28150216"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28150216"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:18:09 -0800
X-CSE-ConnectionGUID: CUmazHzUQ3u+x4JDYFIJPA==
X-CSE-MsgGUID: v51nsDBYQWmIf8M/s1m01w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247639"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:17:49 -0800
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
Subject: [PATCH v2 06/14] x86: Add arch specific kasan functions
Date: Tue, 18 Feb 2025 09:15:22 +0100
Message-ID: <7099fb189737db12ab5ace5794080458d7a14638.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=h7RIXWs9;       spf=pass
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - mainly to set and retrieve tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++--
 1 file changed, 30 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index de75306b932e..8829337a75fa 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -3,6 +3,8 @@
 #define _ASM_X86_KASAN_H
 
 #include <linux/const.h>
+#include <linux/kasan-tags.h>
+#include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
@@ -24,8 +26,33 @@
 						  KASAN_SHADOW_SCALE_SHIFT)))
 
 #ifndef __ASSEMBLY__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+
+#define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
+#define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
+#define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+#else
+#define __tag_shifted(tag)		0UL
+#define __tag_reset(addr)		(addr)
+#define __tag_get(addr)			0
+#endif /* CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN
+
+static inline const void *__tag_set(const void *addr, u8 tag)
+{
+	u64 __addr = (u64)addr & ~__tag_shifted(KASAN_TAG_KERNEL);
+	return (const void *)(__addr | __tag_shifted(tag));
+}
+
 void __init kasan_early_init(void);
 void __init kasan_init(void);
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
@@ -34,8 +61,9 @@ static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
 static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
 						   int nid) { }
-#endif
 
-#endif
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASSEMBLY__ */
 
 #endif
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7099fb189737db12ab5ace5794080458d7a14638.1739866028.git.maciej.wieczor-retman%40intel.com.
