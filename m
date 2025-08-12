Return-Path: <kasan-dev+bncBCMMDDFSWYCBBWED5XCAMGQEP3LVISY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 77259B22873
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:30:01 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-478f78ff9besf198447671cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:30:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005400; cv=pass;
        d=google.com; s=arc-20240605;
        b=QXvQRb6wsvd1V3HLaubE12kJcQxfmeIIYdRa3dI0shX34nBmZN6Do+RonML0MoOsx5
         FYoNU8dLEnl7tc9m0+balRb7NNVEDb00dt+DNO+86HmEWo0+vcCC+UHi8aX15BPuP5DR
         RIC5rEYkVWLdcmm/HQW7ohFX4CGCrzmbyPC4PL9h7BS7OcXMdk7uVV3NQdjQB1+2NILC
         MANsPRuBl+Zj7EPN4dw7bQHnYA+dwcoV2oJz1drsMa+I/DabPjvu5vHjcTl047lWLss9
         Ym4zvWKqOhL4/I9T94FlRNh0iEX2hyipuLVl9l+YPdltxUfSFCK0ud7myqYCVIWXKaoG
         OEKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hmvjmAJsMce9b8ia/HxOVVYCy1OLucdVxYkkjXq8WcM=;
        fh=oPZgn0h5YkSPJ9fG4SW3vC1fez78OGswR2UKZ+cVBm0=;
        b=T09ovLG2nMg2TP+AA+m2YcaMdWnXkm83MlUAQ/6RNlTPy/Z03PqrFj4HjOG+mPBAXN
         myM6fOl3Y11zZNcThH8WiHTYuQaajrw5/FWxGoul+v+4ThVdLk3YQm+HDDLJ7Wkd/vET
         XaPE6QBHxJEeG3r+ARTZoonqf3IAdKgvIqTuAoJAheg2/J/iVYAWOXjQFtBZ3vvk20d7
         SjyckUztA6jQ0zjSY4nMKJMLXTGILliWsTrBYRdz5cqELsrmtwSiM/3j/Pt8kZ1950v9
         OYFzjS3dFjjqvWxV4OeI+CQaJgBRYRVXYBUyjvzwunCKJT9+tXUegkF41fmOiUgyFxHh
         evWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=O5ms1iwj;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005400; x=1755610200; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hmvjmAJsMce9b8ia/HxOVVYCy1OLucdVxYkkjXq8WcM=;
        b=RVumXKv+S3WeplD2n+0mzDYuJZ8DKUdDAWiWB0bf8U8y65oOWcMnwZwR734bWyypxm
         o9AlYP0PJ0Q+DI1Ie1zt3Uk8dDSvfQFP233B1vOALHoRve6Lvhdpon/opWEUP2b/rQeD
         N3k3bsy/7yr9Rtf+Z+V4lEjGBoKNMHnQzwHsTY0lPQL/LsjnpT+FHxdhYSbQ0MKIekx/
         aADG5MN8ij3EwQYtcuHz1z6RbFx7HGxBxIzKFObC92q4Rew8nM6j+J3n1p74wZETgD+9
         oHpH9zGPiP3b0v8YTx5sBxsFPoAE+ncAn35Nkro5YEwPjLfaQesvzsDLZObB1yH9gURB
         SkRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005400; x=1755610200;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hmvjmAJsMce9b8ia/HxOVVYCy1OLucdVxYkkjXq8WcM=;
        b=pD1qRwuVDaYxyP/JRzMlM33EXKsRtRSJOGC+dlScNlJLJYT5zrZqXtXLxFLoKP5qCb
         BdiabFBQJeA98E/gCFfDyNjaxJOLLc0frXqw2F4C8gS+dCnPI/I+KMR80O04XTrj1nrx
         lTmJcN2zxrTHp3wd93N8OAxderNoUOAfivkkizsVi8sWmIc84sXbTXGa9dpYkOuwDRWD
         xM3iwIG//pPHMPiizMKnhgPzmZ38mpq/X/WFoBAX9otmnvAztC3xJLy7qGK5SfyNKKPg
         KZjK/o3sX5P441613U/F9G/RRvuXVkWQ04icnmUvosup5qHuea5N9J41teP1E62WOws7
         B2Tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUq0NGDvwut1alOrAz/UztoOjhnPX1e3s+BMFZ5EkAAddz1+KmlohikZ+6XItd34Hnq4rfsMA==@lfdr.de
X-Gm-Message-State: AOJu0YzkjiQusiQ/E9I2JaZLpXihZIVNgdLGYlLm+478ioKUJSXgvcz/
	g9OPHgB7TLYpy1ZV4uVg+Ttv/0YYjIgZDUWiQOcjphJdnLnseGx2Ua7t
X-Google-Smtp-Source: AGHT+IErvaBZdKo0Ue9sFfXOrYcU4RSLnc5NPHWraiQ71PzIdphmY1hN9uQfngxWT1ZOgJndgT+NOw==
X-Received: by 2002:a05:622a:18a6:b0:4ab:840a:f0a with SMTP id d75a77b69052e-4b0ecc5136cmr40227201cf.34.1755005400197;
        Tue, 12 Aug 2025 06:30:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZer9b+CF7rP63bOoBWQkVRAJEI/exgIV/j68qD5/lC1uA==
Received: by 2002:a05:622a:1345:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b0a04e38e7ls96614681cf.2.-pod-prod-04-us; Tue, 12 Aug 2025
 06:29:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzTqRzzP/2BsvqjTqpuaMsMoQOEw7R9ERznIs9/2zmi/3eK5NJ6EF0u+MhKnXNteYEcUjQ7OBmW9Y=@googlegroups.com
X-Received: by 2002:a05:6122:4589:b0:539:44bc:78f1 with SMTP id 71dfb90a1353d-53afaa22364mr1404231e0c.5.1755005399180;
        Tue, 12 Aug 2025 06:29:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005399; cv=none;
        d=google.com; s=arc-20240605;
        b=eddl8Z2C/B1phwTSm1h1PrdpJtp1UnRm71mcVns8M2CKjwgyj5EVS0Szv8AfqdIQxg
         zAUPMVyQG2mptxQaurRTde8kpv89jKvEIoyB7O+5hx2HSeLe1hys7IuSFDX3ryl6zOFK
         x3+3P+AtNw6LtIY5gEhY4b204REzwoNdb/ejrmPygJ34+EvuA+daneIrWiVx6jiG8+uP
         AHEEP70GVT/bRaXOnIiqd0SUcfDRN9ehD0QTy7eHVJUpv3F7jfZngoqoXar04uHtW5ZJ
         L5XLFtX43eruD9K8OHHFNL4Ifxuxvz6BGd38NtF+ZJyNLZWLAJ/ZRIMPydRBGaEpY7Gh
         G8dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XJiZK/ZPyG3ykxKNSXW3kYtWo0Nz0Qcpx4tZ2otWEt8=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=e83dNDVqgQgSNfi18KBBjTnYoQ+DaDnIjIKmqJsCnJ988zCH0FrvekNBTmNY7lDYQZ
         MDy8qQ+7j9H4fonQRUpx8m8H5Ybgk4esrxCmuOTADUSm6oP8NlEWjF3SDNrGFTZOIXlS
         Vs47Lha9J0kpyqSwXleH4fpIOWWX6ud5HtqPU5N/wNfs4vHmBZuTbjSKmJSEoYZ5HEId
         /qJR/pLBkdDxXmCmUzCXGxLOagcly1L3cyEAuaa494JfVH1GrIEg9LaBYc9hUDjcCESS
         ETNSR3qEWjvnbOztaPM8SgFJhTngYKKnW/HM9rrgfXjUfPp6E32DtoC6NylPQS3KaTR3
         gkqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=O5ms1iwj;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b0258660si679279e0c.3.2025.08.12.06.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:29:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: sPnzVH0pS369/bZ6poxBwA==
X-CSE-MsgGUID: sQGZ/om+TzqsyuJxrNjqZQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903852"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903852"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:58 -0700
X-CSE-ConnectionGUID: vu28n5RXQyCx06dXuuNJDg==
X-CSE-MsgGUID: KI/7/IerRmiIwK8D24KJGg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831619"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:29:34 -0700
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
Subject: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN reports
Date: Tue, 12 Aug 2025 15:23:49 +0200
Message-ID: <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=O5ms1iwj;       spf=pass
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

Inline KASAN on x86 does tag mismatch reports by passing the faulty
address and metadata through the INT3 instruction - scheme that's setup
in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).

Add a kasan hook to the INT3 handling function.

Disable KASAN in an INT3 core kernel selftest function since it can raise
a false tag mismatch report and potentially panic the kernel.

Make part of that hook - which decides whether to die or recover from a
tag mismatch - arch independent to avoid duplicating a long comment on
both x86 and arm64 architectures.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Make kasan_handler() a stub in a header file. Remove #ifdef from
  traps.c.
- Consolidate the "recover" comment into one place.
- Make small changes to the patch message.

 MAINTAINERS                   |  2 +-
 arch/arm64/kernel/traps.c     | 17 +----------------
 arch/x86/include/asm/kasan.h  | 26 ++++++++++++++++++++++++++
 arch/x86/kernel/alternative.c |  4 +++-
 arch/x86/kernel/traps.c       |  4 ++++
 arch/x86/mm/Makefile          |  2 ++
 arch/x86/mm/kasan_inline.c    | 23 +++++++++++++++++++++++
 include/linux/kasan.h         | 24 ++++++++++++++++++++++++
 8 files changed, 84 insertions(+), 18 deletions(-)
 create mode 100644 arch/x86/mm/kasan_inline.c

diff --git a/MAINTAINERS b/MAINTAINERS
index 7ce8c6b86e3d..3daeeaf67546 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13167,7 +13167,7 @@ S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
 F:	arch/*/include/asm/*kasan*.h
-F:	arch/*/mm/kasan_init*
+F:	arch/*/mm/kasan_*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
 F:	mm/kasan/
diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index f528b6041f6a..b9bdabc14ad1 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1068,22 +1068,7 @@ int kasan_brk_handler(struct pt_regs *regs, unsigned long esr)
 
 	kasan_report(addr, size, write, pc);
 
-	/*
-	 * The instrumentation allows to control whether we can proceed after
-	 * a crash was detected. This is done by passing the -recover flag to
-	 * the compiler. Disabling recovery allows to generate more compact
-	 * code.
-	 *
-	 * Unfortunately disabling recovery doesn't work for the kernel right
-	 * now. KASAN reporting is disabled in some contexts (for example when
-	 * the allocator accesses slab object metadata; this is controlled by
-	 * current->kasan_depth). All these accesses are detected by the tool,
-	 * even though the reports for them are not printed.
-	 *
-	 * This is something that might be fixed at some point in the future.
-	 */
-	if (!recover)
-		die("Oops - KASAN", regs, esr);
+	kasan_inline_recover(recover, "Oops - KASAN", regs, esr);
 
 	/* If thread survives, skip over the brk instruction and continue: */
 	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 1963eb2fcff3..5bf38bb836e1 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,28 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_KASAN_SW_TAGS
+
+/*
+ * LLVM ABI for reporting tag mismatches in inline KASAN mode.
+ * On x86 the INT3 instruction is used to carry metadata in RAX
+ * to the KASAN report.
+ *
+ * SIZE refers to how many bytes the faulty memory access
+ * requested.
+ * WRITE bit, when set, indicates the access was a write, otherwise
+ * it was a read.
+ * RECOVER bit, when set, should allow the kernel to carry on after
+ * a tag mismatch. Otherwise die() is called.
+ */
+#define KASAN_RAX_RECOVER	0x20
+#define KASAN_RAX_WRITE		0x10
+#define KASAN_RAX_SIZE_MASK	0x0f
+#define KASAN_RAX_SIZE(rax)	(1 << ((rax) & KASAN_RAX_SIZE_MASK))
+
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
 /*
  * Compiler uses shadow offset assuming that addresses start
@@ -35,10 +56,15 @@
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+bool kasan_inline_handler(struct pt_regs *regs);
 #else
 #define __tag_shifted(tag)		0UL
 #define __tag_reset(addr)		(addr)
 #define __tag_get(addr)			0
+static inline bool kasan_inline_handler(struct pt_regs *regs)
+{
+	return false;
+}
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 static inline void *__tag_set(const void *__addr, u8 tag)
diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index 2a330566e62b..4cb085daad31 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -2228,7 +2228,7 @@ int3_exception_notify(struct notifier_block *self, unsigned long val, void *data
 }
 
 /* Must be noinline to ensure uniqueness of int3_selftest_ip. */
-static noinline void __init int3_selftest(void)
+static noinline __no_sanitize_address void __init int3_selftest(void)
 {
 	static __initdata struct notifier_block int3_exception_nb = {
 		.notifier_call	= int3_exception_notify,
@@ -2236,6 +2236,7 @@ static noinline void __init int3_selftest(void)
 	};
 	unsigned int val = 0;
 
+	kasan_disable_current();
 	BUG_ON(register_die_notifier(&int3_exception_nb));
 
 	/*
@@ -2253,6 +2254,7 @@ static noinline void __init int3_selftest(void)
 
 	BUG_ON(val != 1);
 
+	kasan_enable_current();
 	unregister_die_notifier(&int3_exception_nb);
 }
 
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 0f6f187b1a9e..2a119279980f 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -912,6 +912,10 @@ static bool do_int3(struct pt_regs *regs)
 	if (kprobe_int3_handler(regs))
 		return true;
 #endif
+
+	if (kasan_inline_handler(regs))
+		return true;
+
 	res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);
 
 	return res == NOTIFY_STOP;
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index 5b9908f13dcf..1dc18090cbe7 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -36,7 +36,9 @@ obj-$(CONFIG_PTDUMP)		+= dump_pagetables.o
 obj-$(CONFIG_PTDUMP_DEBUGFS)	+= debug_pagetables.o
 
 KASAN_SANITIZE_kasan_init_$(BITS).o := n
+KASAN_SANITIZE_kasan_inline.o := n
 obj-$(CONFIG_KASAN)		+= kasan_init_$(BITS).o
+obj-$(CONFIG_KASAN_SW_TAGS)	+= kasan_inline.o
 
 KMSAN_SANITIZE_kmsan_shadow.o	:= n
 obj-$(CONFIG_KMSAN)		+= kmsan_shadow.o
diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
new file mode 100644
index 000000000000..9f85dfd1c38b
--- /dev/null
+++ b/arch/x86/mm/kasan_inline.c
@@ -0,0 +1,23 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kasan.h>
+#include <linux/kdebug.h>
+
+bool kasan_inline_handler(struct pt_regs *regs)
+{
+	int metadata = regs->ax;
+	u64 addr = regs->di;
+	u64 pc = regs->ip;
+	bool recover = metadata & KASAN_RAX_RECOVER;
+	bool write = metadata & KASAN_RAX_WRITE;
+	size_t size = KASAN_RAX_SIZE(metadata);
+
+	if (user_mode(regs))
+		return false;
+
+	if (!kasan_report((void *)addr, size, write, pc))
+		return false;
+
+	kasan_inline_recover(recover, "Oops - KASAN", regs, metadata, die);
+
+	return true;
+}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 54481f8c30c5..8691ad870f3b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -663,4 +663,28 @@ void kasan_non_canonical_hook(unsigned long addr);
 static inline void kasan_non_canonical_hook(unsigned long addr) { }
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+/*
+ * The instrumentation allows to control whether we can proceed after
+ * a crash was detected. This is done by passing the -recover flag to
+ * the compiler. Disabling recovery allows to generate more compact
+ * code.
+ *
+ * Unfortunately disabling recovery doesn't work for the kernel right
+ * now. KASAN reporting is disabled in some contexts (for example when
+ * the allocator accesses slab object metadata; this is controlled by
+ * current->kasan_depth). All these accesses are detected by the tool,
+ * even though the reports for them are not printed.
+ *
+ * This is something that might be fixed at some point in the future.
+ */
+static inline void kasan_inline_recover(
+	bool recover, char *msg, struct pt_regs *regs, unsigned long err,
+	void die_fn(const char *str, struct pt_regs *regs, long err))
+{
+	if (!recover)
+		die_fn(msg, regs, err);
+}
+#endif
+
 #endif /* LINUX_KASAN_H */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman%40intel.com.
