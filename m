Return-Path: <kasan-dev+bncBCMMDDFSWYCBBQVXX67QMGQE6L2BP3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E86A7BD75
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:16:52 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3052d29759bsf2993871a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:16:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772611; cv=pass;
        d=google.com; s=arc-20240605;
        b=ObrgZ+7jF0rKueoJvNzD180cA3UCH4QpWkclg4HoXyc7FqF0mBgYnGlMHmTzeUHLKH
         x7+NGeUHz5cqJEeBwov9yPpKrGXjQOlrwMxBWJv/daCfKzNTwU72gNHQ0C5z87f8yT7h
         7IpwTiBorZu3yjuyL/BkKm9fmTms4AKp1V4nMbXkKd6taz98SjeXL55chrCyuZy++PUP
         x69uiwjQIAzL8vY4AyDpbEkTbBUXIKe3ygGf4tdrJEv/oZZ0Kue/B32Qlfgw5j09xFCh
         PDPgN5KLYLekE5JXy3jRKEV4FVTDGbvrQzSVOokKvvhNZZI1c+PlsWk88cQfAnPEzYKt
         08/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YSVnHzLfqUNKuvV8+tX70fkI7XKLrPIfwiYAAMM2Huo=;
        fh=E/QFizfKZw+IfjToBxHaWfnlxVQ1+J4KrD7UeioItSc=;
        b=Jl4fAiBE9zZwulNlvZgONUXa6Z5wrz/6Z87sJ4T/2M1/jiTUyiA1tiB3Im1ykGBKM4
         RsMiHQMefo8xgCEkxNXBizo9UeqHW/tQ1/0K307zkzJ6ynrpQxrrdrt6VW+Y0PXVuqqk
         2BeibMaErGtm4rGbuyvf01Zf8lWcFd4lwv6eCvgq/4oPNGAv/RRHFKAp+RJOk1UPTsVn
         LbYhdzHV33fuSDJ0FLirI4wuLf5xjI2FC2+T7RrmBecQjnshRMQ/HOs1Vl+JS7YjSLAU
         qvpZncym7bE/EShZQJNZ4qRoKQ3QBOQVQ8ywqgfXEsVsUkyUL1XTJNYkuOzzQbOzQ7bn
         8kEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="F/fvFkUy";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772611; x=1744377411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YSVnHzLfqUNKuvV8+tX70fkI7XKLrPIfwiYAAMM2Huo=;
        b=c7o6fsBOhpzhymxsNyuYKeDupvDplRjGQGK+WZC90HJDyPipWV3wotYP0dsbPmAYmp
         E5g5Kd6IB2COeYg+hygI1CbzpcMesw1xA1OK87drSx9qJ/rdSydgrILRo40ua7TY56I6
         8kU+tbCjk9xv0bRVreTFsKayITF8klT1CqRfedbBrw9fUkO8aefatYLOMjDCq6+XNaTS
         DLbpAE9naQVjsq6atk0wYiGZ9s3meUTiy1d3icF1bQm085ky35aXqy35DtAcU5mezy/s
         AhRFDz1r+XxJ6R23cKSwEWI3lsdWyi8v/pyu6iIGlRQglLC6JwBEiLJvqsQg1zsx6mEf
         RmTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772611; x=1744377411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YSVnHzLfqUNKuvV8+tX70fkI7XKLrPIfwiYAAMM2Huo=;
        b=uWtC+Vi+k/l7Uc4j2f/LtOahvJ1KFGZLog3gb1eCR3N6cMaCqcMZZa1U0+PIYpz875
         f4q3TEw3Y1PLxvcQ6V0hgpgLHM13dlrwMDW3mKF7l08XPyr9Kp18TQttatXjqtR/EfkA
         Pn67UAetvJxdZARoUBbYTC8GSWJO/ZTmmvzH0VZ/3ExDDsg9IRli8OHP3O9yZt4LJcF7
         CvZpHj8yYXccQ7KsmZK0xVA3eDXgcXiTw4AAdUhKQx7fl8nj7U6+tRRplnr7kvC+imvr
         Jo5WkVO2dgdMEb1X46biQjdQHM8Pjw43hemUdjB+zbrh1fzUPmZqQg3Fg9uTEVFJq6Uf
         7HYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4xR80qCf6GiT+L2pSywxc2/wo0POcxX/44UD80u6HZlrJjzEZ3g4b+U0l4qYx4RFSbMXoZw==@lfdr.de
X-Gm-Message-State: AOJu0YwG7OehFRkTsM9FyCmNgUXBF0MIBnYxVI39gFKxNvjactf4w5E1
	fIa8rHDyl0dtIa02Pp3hRqVVBhkcvoGcpyYy58SLSZuCHKcZ0aMN
X-Google-Smtp-Source: AGHT+IHD1xEhIXCfrpcCodCCLZtPTDgXnRQoeGq0V8AHURnUCdI3WNFsoR6WST8SnaGRpfjzINesJg==
X-Received: by 2002:a17:90a:d448:b0:2ff:6ac2:c5a5 with SMTP id 98e67ed59e1d1-306a496f939mr4128894a91.26.1743772610766;
        Fri, 04 Apr 2025 06:16:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL2FD6O+RcGZd6gN84OBiCWRMJJWrcpy9jIm1JZwQpHHg==
Received: by 2002:a17:90a:d718:b0:303:6c6f:2ba2 with SMTP id
 98e67ed59e1d1-30579f920abls145753a91.2.-pod-prod-03-us; Fri, 04 Apr 2025
 06:16:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWanDgd9Gje8qyMTUkHFQMJ7S8XVG8txqc9m6Fw7VFbBYyRBVY/FdtMFGnagYf+e9d80ZmyD+GKIXI=@googlegroups.com
X-Received: by 2002:a17:90a:f946:b0:2fe:a614:5cf7 with SMTP id 98e67ed59e1d1-306a48534cfmr4623660a91.3.1743772609562;
        Fri, 04 Apr 2025 06:16:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772609; cv=none;
        d=google.com; s=arc-20240605;
        b=bZIgJsAzTC7nYg+wmCKZ1KQIMZvgFCB6lV9tfEC3TjXyMkqdU18Fen6Zu75nUvpMgl
         RcwEeIUuC4+/vYrAJEX+qNxzIsei48FcjNPl6sxSSNMBYaI1G32iYT1mmfBWf4pHYoC5
         dRHL+0Lmoeib88AkzEoGCgOuW4XLqkdvwPTo6gOwIvTSkoUFYTjCEH+FMhdkVC5d+OOU
         I8X29yO6OaLFUurZGCHhgbUIRHQ03osM/dJo+F9kVS59U66E1P0B2chT0j1uScRewfM3
         8VBmUkH6vC/AiDPprSMVtyYrAStzdT6oSCfeu9V5f+ZZ10wV1o2qIySOwxaMvAkebv4D
         86mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wVLQ4BnG0OXK3p1MFinu0qIASsM8XSU4urWEXhy+z2k=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=MfU7AuVx8Aegbe5FegTvJLU0BruLBDSX1XSwpuHBFZJnYv/N4rE/OLNLJOnRfMPTrt
         4dc7u6PotL+Yan07CU3aKZxPuzHdTxp+g1sDJd7vOshLC5YZt8ZZDWEG0Hkmb1bAMoop
         BOn5CLHjZvjHLwBnSoKYWje9bRVXqD3znz4RA26VZFPDi5i6gOU/hm/m5chQF67U2CJj
         gCpXrkKc+vzQ83tdODz3N7Imr5LkQVLw4j7xFM4mo7LHACSrZLwGr2cAVkaOlsme11Xd
         H5hEEaW+YnVKmK7JfVnbTsFtTu8mz5tJFfHKXYZOn7NUMTvld9D4is3ljss/8iPrWFSV
         zIIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="F/fvFkUy";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30561ca1e70si477729a91.0.2025.04.04.06.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:16:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: Wk3BZg6rRKSMhAL09/H0CA==
X-CSE-MsgGUID: wple8KmnR86zz3pyYVBH+A==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401860"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401860"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:48 -0700
X-CSE-ConnectionGUID: KRVPdSrrQwCsFMKOJCYkCg==
X-CSE-MsgGUID: BkRczVO7Rcyr+7Hf/uQO/g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157245"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:16:32 -0700
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
Subject: [PATCH v3 08/14] x86: LAM initialization
Date: Fri,  4 Apr 2025 15:14:12 +0200
Message-ID: <43b4db5c872bfaa4881cf45103b8fd3a826c1a9e.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="F/fvFkUy";       spf=pass
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

To make use of KASAN's tag based mode on x86 Linear Address Masking
(LAM) needs to be enabled. To do that the 28th bit in CR4 needs to be
set.

Set the bit in early memory initialization.

When launching secondary CPUs the LAM bit gets lost. To avoid this it
needs to get added in a mask in head_64.S. The bit mask permits some
bits of CR4 to pass from the primary CPU to the secondary CPUs without
being cleared.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/kernel/head_64.S | 3 +++
 arch/x86/mm/init.c        | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/x86/kernel/head_64.S b/arch/x86/kernel/head_64.S
index fefe2a25cf02..95b897b8bbd2 100644
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
index bfa444a7dbb0..84cefc5dd69b 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -766,6 +766,9 @@ void __init init_mem_mapping(void)
 	probe_page_size_mask();
 	setup_pcid();
 
+	if (boot_cpu_has(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
+
 #ifdef CONFIG_X86_64
 	end = max_pfn << PAGE_SHIFT;
 #else
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/43b4db5c872bfaa4881cf45103b8fd3a826c1a9e.1743772053.git.maciej.wieczor-retman%40intel.com.
