Return-Path: <kasan-dev+bncBCMMDDFSWYCBBYFXX67QMGQEH36KX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D1EC3A7BD7D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:17:22 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-73720b253fcsf1772545b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772641; cv=pass;
        d=google.com; s=arc-20240605;
        b=XtgSaMTbadUnZKnabdRrJGdZguhZf00vYr1TQA1RUbGMyqzVE0In8UOrUd9NV2IEoL
         X4/cxYzkgddSm9DqKo9cgV3v0Z9AfNPDH4D4iP/OPhpfUOGI0SpdFDxpCKGrcWLZFsK4
         r0UxWSGSVmyHZ0fSoc2E/M+i/vOrh7M9hc2Kwv1THhc9lb8CFrDc+M2doC3+KpUYN19K
         zRbWuIK6RinuIQFCaxeBmIB1G+F0jj+EdoG71FUhSlNlQNXA/raNqRgy5bqF4HlCD26K
         rehSAVMO6dl9N1O/PUZHMv+H/240rnT0bdvYtK1qiV1bxQPOuZXnj0uheRfc3HHQbsB7
         RR8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zry8dS8nc2bNL0JrmvL0awIfl8M3pzU3esd0cADhUzg=;
        fh=REYZGoXGv39GvtLLbfWBGkH5qfGFx611CIkzOfJxd9o=;
        b=iGxNd9N5YlMKRhBtEAb1AiuYwgBlAIiFfYUjRcXuoH9N3o93L49fNZr15fi4m+AU4w
         pb5o2wbHY6nJLywI+Dvq9zsVD/OXaKpJT8Qrb4sE13/DZGKOR5DAR+73C6hJ4FAi6txz
         xaBx9w9p+OXb+ifh1Uib1D/tETGHshKRTJPOOnvr+Jc2dfWVD6FSEz5CpkimgoIQCV6S
         4qYjnCg0U1dtrd/bSVjiHdo9Kuf2AZUBksNbsJLDoLRPPC82S+LO46eSLyFGwGyA07G3
         14PAM/avL+HosGXeQTNDXHYHTIQI7dqntUtCmqwdWOgV24TgVbBUCT8yaMb6Vv7K6EKb
         b7Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K6xPdlWR;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772641; x=1744377441; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zry8dS8nc2bNL0JrmvL0awIfl8M3pzU3esd0cADhUzg=;
        b=FXFMI06IHnh16UqYxYErPp/BA8grSRqWoVXZWr6EOcc6PqEZ+xV7Kau2XnzHvdMpRU
         VSSTuY3gxdufIruMajT9fwZO+AEe49mTQf1jG1TFUZQHWr/daR82Fkxe5Tvha7nRzC5Z
         Do5EP5vx2nGcgZspNRTLHVcEOdOSrKImtnh7T2gFspHQXAAwrUebEYqv5P9fXyDYlARK
         YCTG3zMlBkqqryku91q302bpO71azzFk0YFi9u5TEwyeQ2whwbRVCF9XYv7X5FS8Elx1
         7jmc4JDiEqfTbSY4oJReDgb4zddhN6l4AB68Zg47GMnc0qc27yCO/lUyV8v96P15ZZ7w
         QWaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772641; x=1744377441;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zry8dS8nc2bNL0JrmvL0awIfl8M3pzU3esd0cADhUzg=;
        b=FAEB0624JxTPvlt5eswcWgTsABBMv1erOsWle4pum87ATT90p6Ow5l+JdCkT7sqzHD
         agSwsls89Lfzyn+NHCbug3rBGu4WFftC5ONSmOHXryTf4SZbYSuzG8U4XEjKqvLZofQu
         kkIujP+CQMwdwW4RE95nWpg5e2cR+UbLbJ391WL1xEWlHa7qefSC3oaKoP27Ipb72CLz
         oTKC2K8G4NuHAQ84Ag5w1YndgG05Yz0iQ3PEfguXrVpjKcFBNWTp1cZ+Gzx87/o5auCv
         XC5gC0xUxbij5GX0BRJyy62BwB48F/3WCmbI0pNWVeStrroA16uHFGmZUNwuP37cbvf1
         pvOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjRVYBQNlAwKFGRvCtaFJrwn7iV+C0udbIlgzzM0ks7Hw1iX27dsm6neFxThabiqTWB2EspQ==@lfdr.de
X-Gm-Message-State: AOJu0YzMuW5flvX3hcILMfuK+zvKiEaHWpkYjJ3IIBc2oqjyKc4Mcm2+
	cYSi4k1ltlrY552QUPDpT2dpwP748a7uh8Afzo1QDRPlOKEZtCtK
X-Google-Smtp-Source: AGHT+IFGxoQtB2Ph/aygrF5UxOvUZt/4EfAl5hOnqsH+KQmyFkqB9nZafZ2fchxVH4cjiWVW4QVdyw==
X-Received: by 2002:a05:6a00:398d:b0:730:95a6:375f with SMTP id d2e1a72fcca58-739e6fbd92fmr3186369b3a.3.1743772641045;
        Fri, 04 Apr 2025 06:17:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKjjMgDZawTlEnNMm0BgJ3DwYe96UxN3lE+Y6mv4nc4EQ==
Received: by 2002:a05:6a00:1d9b:b0:736:cdfd:9229 with SMTP id
 d2e1a72fcca58-739d5c8ed1als2002467b3a.1.-pod-prod-09-us; Fri, 04 Apr 2025
 06:17:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaPCaSZLGr4kguDDL+/NOwsVz1pyCfQxryChTcBfphpGfH1K+jQH+hMRc+BfqEu/H5ronCoTxIMww=@googlegroups.com
X-Received: by 2002:a05:6a00:1942:b0:732:2923:b70f with SMTP id d2e1a72fcca58-739e7050374mr2926786b3a.11.1743772639683;
        Fri, 04 Apr 2025 06:17:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772639; cv=none;
        d=google.com; s=arc-20240605;
        b=Sr+vrd6VcZBg0aLO3MP0xmzgDHTeKocJH0GsG82t27u1aWhgr/pIBfY8KSm/w4oqy2
         QBna3iq3uiubPSJlyhe1fPQPh10vdskClGFrOryj+wKrbJlg9DDNYQhFPldO5IaAfuDh
         h3U8sYbVow9h2DtxAG9JBStrL5y3gkcmBVJHaHFd9f4BEB4kgm/uOjIYMqCnjqg3HqN7
         430e6tB816VChaFxY2Q3zKUxvavJPmvgJ5V1WYbgH+MjeoobmRomphq0+hp7VwWj1sbS
         QZYNNVevmCTRxnM0rUyyoeFKd4YG+LL0cdIvDe1CAb0c2jfkFtUTr5NMCxFdAJo4SIW0
         Aeeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hdkFszdtBdvZ7spFw9JqGKHX1CI6+ij0yexdS7qNDVs=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=lUkcIlPx//hSIQKAfoHyZk0M7w+i2uUYhQc3x9ZIKjwC5tkH7nWRyT7A8PlOqYOPGL
         7cFFMNryOY9GpjhJmPaaaTCPuPwE4rKA5pDyVA6HP6GWIzY/ESh9FVnOmX2sNWTg9Ngy
         ej40DgYCXMiaQk0WBd10uyqqvdbA2e+H+Gjyhsdf70C5k1mkJKvAt5Ju6wQ4IyEXPNM3
         su6VhwUezd8kTnKt5WLIN40nQNYH3ljKr/uqSBp3m7qmo0XDEWDJ/78/baASeUwVU3A/
         UuyH0rLO9D9ug+PyITBhxIXAgg5Z2b4sOQRBI7/Jm1SZ3valbI9YsY5DbbBh+at4tWha
         wG7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K6xPdlWR;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-739d9ea902fsi158058b3a.4.2025.04.04.06.17.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:17:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: C6TiVUQjRJySRahS+OrqAQ==
X-CSE-MsgGUID: yXWQGVWaTWeSokJzEpEFgQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401940"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401940"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:18 -0700
X-CSE-ConnectionGUID: fsVEwllhSRmFPFm7kCxT5g==
X-CSE-MsgGUID: rCQHxZP4R6qYhcSTuBxnqw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157312"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:02 -0700
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
Subject: [PATCH v3 10/14] x86: Update the KASAN non-canonical hook
Date: Fri,  4 Apr 2025 15:14:14 +0200
Message-ID: <c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=K6xPdlWR;       spf=pass
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

The kasan_non_canonical_hook() is useful in pointing out that an address
which caused some kind of error could be the result of
kasan_mem_to_shadow() mapping. Currently it's called only in the general
protection handler code path but can give helpful information also in
page fault oops reports.

For example consider a page fault for address 0xffdefc0000000000 on a
5-level paging system. It could have been accessed from KASAN's
kasan_mem_to_shadow() called on 0xfef0000000000000 address. Without the
kasan_non_canonical_hook() in the page fault case it might be hard to
figure out why an error occurred.

Add kasan_non_canonical_hook() to the beginning of show_fault_oops().

Update kasan_non_canonical_hook() to take into account the possible
memory to shadow mappings in the software tag-based mode of x86.

Patch was tested with positive results by accessing the following
addresses, causing #GPs and #PFs.

Valid mappings (showing kasan_non_canonical_hook() message):
	0xFFFFFFFF8FFFFFFF
	0xFEF0000000000000
	0x7FFFFF4FFFFFFFFF
	0x7EF0000000000000
Invalid mappings (not showing kasan_non_canonical_hook() message):
	0xFFFFFFFFF8FFFFFF
	0xFFBFFC0000000000
	0x07EFFC0000000000
	0x000E000000000000

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Move the report.c part from first patch in the series to this new
  patch to have x86 changes in one place.
- Add the call in fault oops.
- Extend the comment in report.c with a graphical representation of what
  addresses are valid and invalid in memory to shadow mapping.

 arch/x86/mm/fault.c |  2 ++
 mm/kasan/report.c   | 36 +++++++++++++++++++++++++++++++++++-
 2 files changed, 37 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 697432f63c59..16366af60ae5 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -511,6 +511,8 @@ show_fault_oops(struct pt_regs *regs, unsigned long error_code, unsigned long ad
 	if (!oops_may_print())
 		return;
 
+	kasan_non_canonical_hook(address);
+
 	if (error_code & X86_PF_INSTR) {
 		unsigned int level;
 		bool nx, rw;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index f24f11cc644a..135307c93c2c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -700,7 +700,7 @@ void kasan_non_canonical_hook(unsigned long addr)
 	 * operation would overflow only for some memory addresses. However, due
 	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
 	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
-	 * the overflow always happens.
+	 * the overflow always happens (for both x86 and arm64).
 	 *
 	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
 	 * possible shadow addresses belong to a region that is the result of
@@ -715,6 +715,40 @@ void kasan_non_canonical_hook(unsigned long addr)
 			return;
 	}
 
+	 /*
+	  * For x86-64, only the pointer bits [62:57] get reset, and bits #63
+	  * and #56 can be 0 or 1. Thus, kasan_mem_to_shadow() can be possibly
+	  * applied to two regions of memory:
+	  * [0x7E00000000000000, 0x7FFFFFFFFFFFFFFF] and
+	  * [0xFE00000000000000, 0xFFFFFFFFFFFFFFFF]. As the overflow happens
+	  * for both ends of both memory ranges, both possible shadow regions
+	  * are contiguous.
+	  *
+	  * Given the KASAN_SHADOW_OFFSET equal to 0xffeffc0000000000, the
+	  * following ranges are valid mem-to-shadow mappings:
+	  *
+	  * 0xFFFFFFFFFFFFFFFF
+	  *         INVALID
+	  * 0xFFEFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL)
+	  *         VALID   - kasan shadow mem
+	  *         VALID   - non-canonical kernel virtual address
+	  * 0xFFCFFC0000000000 - kasan_mem_to_shadow(0xFEUL << 56)
+	  *         INVALID
+	  * 0x07EFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL >> 1)
+	  *         VALID   - non-canonical user virtual addresses
+	  *         VALID   - user addresses
+	  * 0x07CFFC0000000000 - kasan_mem_to_shadow(0x7EUL << 56)
+	  *         INVALID
+	  * 0x0000000000000000
+	  */
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_X86_64)) {
+		if ((addr < (u64)kasan_mem_to_shadow((void *)(0x7EUL << 56)) ||
+		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL >> 1))) &&
+		    (addr < (u64)kasan_mem_to_shadow((void *)(0xFEUL << 56)) ||
+		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL))))
+			return;
+	}
+
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
 
 	/*
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman%40intel.com.
