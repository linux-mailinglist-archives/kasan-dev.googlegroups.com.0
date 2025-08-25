Return-Path: <kasan-dev+bncBCMMDDFSWYCBB2UNWPCQMGQEXI6DXQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 978E7B34BB6
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:26:20 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-3250e3b161bsf4205441a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:26:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153579; cv=pass;
        d=google.com; s=arc-20240605;
        b=i/HiwaHFXqcVmh/I2YDZKG7pEZk0TJcmDO4jpkEQ8g8F9GqiGiqspY5SKo+DXU6zCe
         C0pI3VzgRyLr7AFxD7DPD3RdqPecyKEQAB+F2NVXt1wcbTz6VmdAbNK8inQwc8VgWpkU
         hiYJRoFt2dp9MYBOIA5rU0yy9/PbP/y7KRz7WSNCFhfVEj9IFo521pg+L69H2QAKNix0
         1Z8p4pZY49j3oJFXl3gPzicxMJ/dL//4561aJCi5kFEACRJp1Wu2F0ZFjMa9dWCtWdqh
         +SYhnpDLZiEPXw3jCJN0XOy22vEaljMd1ijgf3WbeMhTq4hjf7bGEQBWcLRsIlSKnwE/
         SH/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZVdw8AAXTd/hIvR772GYB9DT8LNYRUBJPQerKBx5tPU=;
        fh=fcsZwd996QrMdTXolPGfcirG19jZknm6i8rzgHQxrAc=;
        b=JprgYrSRp7s19J8otOvhcXpnZ2efkWtoewXtF/EGr274sB8D2EN6xMYt2hWUMjxlCr
         1X0lUvWMTNwbJhI9JQoSXQ/aqJDLkaRmgjjW5JFVelgKFri2Pmzt2uD+C4FGK4tqlrsH
         qH1PXoUJFm66vuJfB9d928Jqm0deFvgLtl/XCn0+JbUZrcSYyt4shG1a2S3T4MglGzYE
         dlCIEXR0R0tZATaQQiO3kvIbxMXbrxOO7g7t7SdKR3b1Km7sRlFKC69VHnDRHZUzNYoD
         nIQ3n2NIg/Ygj3JQ5oZkitHBAUcFzVIbydhvXMb/ezr953zFVOaYZkuQTHWdTJDd/n5V
         C6lA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NF6aItKy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153579; x=1756758379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZVdw8AAXTd/hIvR772GYB9DT8LNYRUBJPQerKBx5tPU=;
        b=ptwKoe5yshKSFKPDb/h6wXbzq83mE+r8iEEdp8tP9w1e8c5Slrs580DfYW8y7o8Lz3
         aUkE0tkAlWubTPxkcw82I5amm7Aq6fBdFW4FcTVm9Z24XI83wRkTWjuqLqsWn1IU3SsB
         YyTtZsCoFGU0Q3rGauCXBKhdp46U/b+yzQXTi8XEqAvKWirGrKwuRF0jjBTsXJyx6t/6
         gc+0E15BSCsQ7MO62ilkyTF4PFN/kW85n7Kq5/Kcfb0r+bK3P73KX6KZUkjmuNuTU9RS
         IAQ9GTFxe8p+x5x3YAjxlf5K8/Ik1GTq8oA+1ingk1Axr8hXOe25qV/tP2GUhHWduQkm
         EZSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153579; x=1756758379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZVdw8AAXTd/hIvR772GYB9DT8LNYRUBJPQerKBx5tPU=;
        b=tFZ+5/Wldw8lroS3/gcDtN5oZhcbONczjj4oOS6h6r/xwdjXfDNJD9iGzFhhxsyrhE
         /gLlEgQj/Y+YM6DLC7X5rVmx/3he9yF0e37nrP0TFNQ6rCgDUNh60zD+4TKHtgyyQC+0
         9UHUXW3Ha0+G9sttMCWaHc/G8OC3L49ZZKP0RkNeE1E4AZAFx3deatOCzztj0x0sEQnX
         033KwE4qHVZjmFKD2dX2h61vBRo7Ng3ze2h8CZ/b/WFbMiPtWG7PKRjE2acSjvR01sC0
         XkwXDLPau4pQ+7G0KG4oINp+soFSDrlkqdZBlhV6hztwJggLAOdmf/yOU0soryX+FZD6
         Sdyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZolnJbT5znUgrpeGvC7sY4z/8b1mML0bWaDmi8RXk8oLXKiKvM2i5YZa9hiw3oXd1/d9rWw==@lfdr.de
X-Gm-Message-State: AOJu0Yy74WqGuvw+nN4bhz4Zz8vK5pGI5HEAHvjIbyXd8iB1gaLrwuhZ
	upg/yZT6ZNQqke8VoefOEE77DJzsmctWtIMBcCe1ZDScb+cGJ83kMqLw
X-Google-Smtp-Source: AGHT+IEmDu0f4fPHN2xHJqwMsm9p7oXFwmpS/FltvKMYejR0AM4sdJJX6F3xEHPDo/HrTNdYB7H24w==
X-Received: by 2002:a17:90b:51cd:b0:31e:f193:1822 with SMTP id 98e67ed59e1d1-32517745f63mr16786351a91.28.1756153578878;
        Mon, 25 Aug 2025 13:26:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe58Pt8LXPlhcwvAM+9kaWtRFFb+TZ26qLww7cEBO8Ijg==
Received: by 2002:a17:90a:1589:b0:31f:7cc:aa74 with SMTP id
 98e67ed59e1d1-324eb8538fdls3756612a91.2.-pod-prod-02-us; Mon, 25 Aug 2025
 13:26:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/Rlr9Fb0aIF3u9pDais7qkMQn3kwfrfJYbRIIhF2/It5MAYgMwWC7u9JYzlR9pwHNpj+BZZxYasw=@googlegroups.com
X-Received: by 2002:a17:90b:3fc4:b0:325:c492:1570 with SMTP id 98e67ed59e1d1-325c49217ffmr4405507a91.19.1756153577491;
        Mon, 25 Aug 2025 13:26:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153577; cv=none;
        d=google.com; s=arc-20240605;
        b=bdPyjaV6EqSNsDXlRZjtKtOvk1HMXuQgygYAeQp8QBZYSjasHn9Sh9JOyICcYlgxbT
         YVjyoqoeZKTfX46Lbl57dfIsIvAL5Ay/6SPO38QMqXVR8+2JsE08d6Q1LDgfBBQ43hso
         vxXy1IR8kk4tPr5hZ+j6mQonAxsFauSFYaQ6ygOdy8H52t+1QqVKloIbYSFXYPWuNNg7
         0W6BL9w6MWcTLQqpoEFZNs7JuGtctA4iGpRkb0RvK0FGZ33ZEEgE8B1XkfU0dvS9CESy
         DsepcjfI/B1kEc6ad9/4G4P/wT/qHPYCF173tSkQC804XaKhcBiBmTq5tLZdhBC9mL9f
         wctw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HbFrm91SUbV4l5hJiwCmmvNUYm5bhZMJ5aJamdpeZ6g=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=OytYhCRLAbwsgSlvojs+iYzSXOZA1V8kIAVVhz/rgjlY2uPLVTTlzAISUiEmVVQWaX
         recBuco7o3eGKJNfaDYHZ0l+LQGqPmutHUkqYgalUL0EF5Nub/CiBCXVM/SYamea2+a2
         hGRudbFm2D1cbGTDVGJD7v4GZ5YD1BhG5EGV/VCwWvym02xw21DSqGD4I6mb373dn82A
         bAA9A53L01m0U5NimY35KVXo+BU/H/lPNLIXZ9bLT2S+J/IEve/tBf4slMt7pyxy9sy8
         EA6EuRHhlfzEou8kkIQeo0s11w7U2LoSWMkLA9w1PnPrxHy+CBdvPEPunyBMMXgIzoRP
         HiHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NF6aItKy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3254aa5f981si390086a91.3.2025.08.25.13.26.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:26:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: zYqvB6W7SmuROBltR1Z82Q==
X-CSE-MsgGUID: NJTV2PBtSX6m40fk25NLUA==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970299"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970299"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:26:15 -0700
X-CSE-ConnectionGUID: +L18yj8dSzOfEZlF7N6ftA==
X-CSE-MsgGUID: jAlCsbyqSiWfjyrRW8QvcQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169779897"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:25:53 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 02/19] kasan: sw_tags: Support tag widths less than 8 bits
Date: Mon, 25 Aug 2025 22:24:27 +0200
Message-ID: <83955e7079c0fb9c11169d25adc6303f0c66c1ec.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NF6aItKy;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/83955e7079c0fb9c11169d25adc6303f0c66c1ec.1756151769.git.maciej.wieczor-retman%40intel.com.
