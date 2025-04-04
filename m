Return-Path: <kasan-dev+bncBCMMDDFSWYCBB5NWX67QMGQEUVNMQCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id C9A6AA7BD5E
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:15:44 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2ff78bd3026sf1961510a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:15:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772534; cv=pass;
        d=google.com; s=arc-20240605;
        b=UMOZTTiACdepioItZM54utcdTQl20qYNTWUe4Rz+Ksvs8bpKHpwfW7INYrouefs0cB
         SwjU9Ly7xiG2unIqna1zqhGxKid07P1Ct67N7cKdnJKoCmfJr5YU7pXMzV4Kb/ai2cm5
         Z7oNePv/XUwGvGgjkDeO4ydvROE8D3YCqXXB/TJiwTbETazLu6aZH7JqRE6KnCmZWS+W
         j+q3KSIMUIkIhJASCYih7izTGxA7OdZfMxn2cDLNGvPWsURLc7vgfkgJDjvi8hTJfbQX
         xz3L90hH+sqACcfPQb6pYqH22CRf6yY+gEtXYBH46UXeKK93P2UXmjMtRaO2xQ1DWL2P
         DEcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jDIUM19RJvyc2dT1t/+pdMCUJvT7E2PtYSNxKCZKP2Q=;
        fh=G6/h++hR+f9RGgfwcqZ2zYZD55BloXUl2zx5ZplOjOw=;
        b=kVbeE4zIPqONPH6WQgO5uUm21vvVKmblBvR21GS65yVQv4wrh9POFPlvtkhOWYeAMq
         DMaKPSsf4dJwZNDhrzDlrORBRNhnuuSWrLAf5+IHDk0phCXljAWtTaxTC6bfswP6M57j
         +i4jTC63jPcBn6BjMt4ZM0tYJaaDHbG0j+M2zkJPAZYsZiHn9EP+FSXphb/bse0otEBX
         VnteVDR1S6XWtmm/4F+F2lLzbxiNb611v4N9/epjPz40nOeaJ0TcPRaTm7pvZQ6JUQkd
         kYjgirmW5oTUnZ6b+4sGT1DYJKGpZwe9MTcDN8Dwptb7ikzmOdoAZQXPvi2Ggn8IoYG9
         o7ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=b+Wmrqc3;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772534; x=1744377334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jDIUM19RJvyc2dT1t/+pdMCUJvT7E2PtYSNxKCZKP2Q=;
        b=xt8OqTheD93Ql3HxczH3vl/mEdqqH/8S/cNdv3q/ol3OzJqEACVU9yXlCYIijChZeN
         QUAhyrtIlnbOzLLnUWPYCUbWLOGCB/eNRw5Eb/QudIcv49iQ0w5DEiDnlqkmECbmU6q5
         th+0syk1jPLXlKMA8RrcGsOZZW/pjSwrvPDQs+yRm/uNniOCYb5LNEexc1oywQvRt+Da
         myPKOju4hNGB58eXzEsCnZ11/2LFLdy6F/U0uKVCKVCNIcr5EA7XAtKpkyIwk1PNqzD4
         rYSAGElUvySlxmnZ5F4+sZnZpA/vX2XEr7yhbNXlLRGJj7b203XhVAru58zO0kkHuDsL
         TWbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772534; x=1744377334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jDIUM19RJvyc2dT1t/+pdMCUJvT7E2PtYSNxKCZKP2Q=;
        b=no/DmcSEdV5uAubyHdP216XmALtPdKaRruNcQ3BJRpTEmJzBcjogGFphkb/BL9pzf3
         +aR/r0xfa0cazJMOaym53HhEQRmmi+Xuzvb7i2WXapgF30tjp2PL3zUp7MlC7YTfigek
         e4OQmx/Hd8oCmKSmB1TmbFu0loVVc0Jfv3NEtlPLOjb5pvyVR/uhfaj1fXyjHb8E5TVx
         GQCLny0Heu/frVcBiN1dkpG+5LKKPDMW5Vyvvt9h00Rj93GixDGHZ4j2OsYxwg2WrX4D
         FZ5dm2JId+iXEIeYoYvaPaD+06cZnsZ6ij3MAG558JfQwq/uo3F0j65ZIvBzPa4UVy2E
         pmaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFCPsxuUhviDGI8OxHm1v1VcerxkEhlexkbRl0eL/98AlmDPST+f2U82XCVduqKx1rUWtvZQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywhl5vdblIE7QkRiV9Jbq2nNKhqtm6H3NXj0l/UhQHwBEmo/pdq
	qqggIDQy3GLDzKWMNbEbQqiEzwCuIBgWyz/9xxQxYlBj5MTgAHR0
X-Google-Smtp-Source: AGHT+IG3h6f96tHYpx16Mp7wBz6pljaFN5BL8C9efvNezxCwZ3kJ/0HjBdd10XNipcJaX6KuYkvJKw==
X-Received: by 2002:a17:90b:3d47:b0:2ff:58e1:2bc9 with SMTP id 98e67ed59e1d1-306a48d1a4fmr4628023a91.25.1743772534218;
        Fri, 04 Apr 2025 06:15:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL/ymOZd+zlYhpDydWVlRPcrY20Mjze48M4fuvlOL++ug==
Received: by 2002:a17:90b:5146:b0:301:1dae:af6 with SMTP id
 98e67ed59e1d1-30579fbb5f3ls1655045a91.2.-pod-prod-02-us; Fri, 04 Apr 2025
 06:15:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEviB0xel8/lLmwdBGM3zW9Ay4RT92b2QMYb6O1BZsft2ydzzn9iyRvQG2SgCzfLUgWF5Bsn5wNYg=@googlegroups.com
X-Received: by 2002:a17:90b:2f4b:b0:303:75a7:26a4 with SMTP id 98e67ed59e1d1-306a47feff9mr4874986a91.7.1743772533022;
        Fri, 04 Apr 2025 06:15:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772533; cv=none;
        d=google.com; s=arc-20240605;
        b=Veu4Pu/ntLt2iMwafNJDO1LjpcfrNnjhHu6Jo4w34Wimx+rJ2RpkrOMV1grPe2N9HG
         AthfP5xvXwUAdHzKin8bGVzqIxwD8VV06q+N37ZanyJvAbVPi7HbBcqaSXfZ4Yva5J76
         6qcaaMvAo4GtJ4+jIhz83TFLq4FsBvDn7FyPyIUl5hTRA4ZqzXHSS9tQmlojrcHYMiCs
         SCBKC3UA5yKBTu55X8yDi80XICAl6xb560h/kQNSjJ9MugwcnrCi/rbad1oaNs4RCsDE
         o0SSa6Ky5kjZA12ZDh4h28twC/kTh19wqbFA1lNsOnRwgDRdUc+b52OopXjZoQnqg6mA
         U9Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RNRm/NWTNCpFCplFUFXOJkHxOM9uo6rxFDglg0b3zbs=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=DmSFdw9DFkJ2GbbGT41evU4wnNSfVXZi5btzOjgCEo5/EqlKbxemI865BjmFwLR15A
         iYVmCGB9hqtEu5CmEj6S/TbRm1gzMkzvfRZRIwrOZaFvuZCfMexPhCHl9wPK1kZAVKtR
         qDdJqTm+ugyWIC4urdCabEiMCW641fgAQB9vlhDYtO68/dMqDI1IslO3Uvn9R9FH49I7
         Ws9q0UHtunMWp7xvLMJ52ho+3nSOYB6T+YJOAhTTxG7FAMtdG1Ht2S58oqiJnmPxDDe0
         9a/CC65T+1olH0Yw+C6AUUeo/zHO3zIfg7VQlv1617Q3C+6+bJQzbe226LrJpHidkscq
         2x1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=b+Wmrqc3;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3057c85d085si183775a91.0.2025.04.04.06.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:15:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: IfKx53K+Tta67JJJ2RrA0A==
X-CSE-MsgGUID: QhZzrXLWSQK56EZ10s8KSg==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401629"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401629"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:32 -0700
X-CSE-ConnectionGUID: tH8/P6IgSuuHLhHzruVqJg==
X-CSE-MsgGUID: 0efeALDRQGCxEo3GUCuhZQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157007"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:17 -0700
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
Subject: [PATCH v3 03/14] x86: Add arch specific kasan functions
Date: Fri,  4 Apr 2025 15:14:07 +0200
Message-ID: <e06c7c0fdbad7044f150891d827393665c5742fd.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=b+Wmrqc3;       spf=pass
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - mainly to set and retrieve tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Reorder functions so that __tag_*() etc are above the
  arch_kasan_*() ones.
- Remove CONFIG_KASAN condition from __tag_set()

 arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++--
 1 file changed, 30 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index d7e33c7f096b..212218622963 100644
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
 
 #ifndef __ASSEMBLER__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
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
+
+static inline const void *__tag_set(const void *addr, u8 tag)
+{
+	u64 __addr = (u64)addr & ~__tag_shifted(KASAN_TAG_KERNEL);
+	return (const void *)(__addr | __tag_shifted(tag));
+}
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
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
+#endif /* __ASSEMBLER__ */
 
 #endif
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e06c7c0fdbad7044f150891d827393665c5742fd.1743772053.git.maciej.wieczor-retman%40intel.com.
