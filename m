Return-Path: <kasan-dev+bncBCMMDDFSWYCBBDVYX67QMGQEUVZGJDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E205A7BD88
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:18:08 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-224192ff68bsf20054025ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772687; cv=pass;
        d=google.com; s=arc-20240605;
        b=g7UspsjTAaqF7zzNSwjy4NyAzw0DXdb8JBDBiRi3cRQbNyHqQdQSfHep+R9FI3jTjM
         W572JPIoaPgsbK6T0CWH1Ev8e/0J3Qra8HDF5PDTwgSAF42P7HHFk0hOcdX50RW5AD/F
         Y2Uru3AkKBZv+BTXZ55+soajWgWx8JeCKUxFKWAS6W2/TOq+PSNsml6anuun3o+peicC
         rZsC2Oytrk7ELftysFyOwW2S/PohKwZEsRE1w4r4qmShY6h7vXhtcGCZRMDZYcqa4ow9
         nxuqTjOIc1W9t04Pnx0yKGoIEUpLpoueMVx+j6OdMgFVvUG2pF5QjtZ+46nw5rsQ5q7o
         dMaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D5dwWsAWCiLd07onaHQdUvfdcFVzpouTYKGRD2oyRls=;
        fh=hjM2HmJeBxv89c/DXONvoaCqsiQnxGLFOMEmAg+QfX4=;
        b=EfLf4gtBEM08/1FJQQuteUk5TACZgil84xwzfPilshSBGX1Xwwm5c9RgmsKJUFaf1A
         ZluEjijlwA+rmwEK1zjTBiXGMdxbvvejSSBlJ9AQ+2lJplrtUYS8BEyKzMToBMbd0Nub
         x8dnyz19jB4hW3AkRj2WoxX/lPQmaixtylFoVDwi3ZHioxQRe/Yb7dX9OLkSX3Fvoj6F
         h1E8xwvBEVCFU/IFeLi9Fj7DoVzHqPbvRO50CDQgtrneogyyA/sk3fnlB2oXTbbMEcJx
         4JBXHCFeubx+7BRRPaN6ZRVbrKQ/H2kt17SUPU53tubI2yK1omJoBWiQ6BEEhDxEcV55
         UVNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="SF/dxn65";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772687; x=1744377487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D5dwWsAWCiLd07onaHQdUvfdcFVzpouTYKGRD2oyRls=;
        b=l2sbho59xccxX0YL8RGx5pp8ds2VmSKyn42kob4+gEmZqDIxWBx1kFYSKeKL1PG/rS
         YTIfDsAiKMMBZnEL7axvw3SyXX38eaYfxUti+2aJyHVuSBsUodlUY5LR7ge48edpi09d
         jb1a9AgsYwYwa83REndAj+XxfTMO07FwSG6OT+FunnAH2gLOcdbmfxyyw5PYnElun2bR
         aIzVGCVFnUByoa8/d9NqmIjEkefAvhfmRNGdh9ILYsqW7SRiB6gWOzB5PAlRKLzvu9Wq
         ucCRfbFN3+EZ2UW8dCnySsQ8EhU9/XPZs4IcHjWUGHo/B1ocxrfkIoa3EP9twRcBSwOF
         XVgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772687; x=1744377487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D5dwWsAWCiLd07onaHQdUvfdcFVzpouTYKGRD2oyRls=;
        b=YQO1ISykGwiMc4X1FsfmUSKcQh6wc4r05e0uKveTRE7Xxg36HeXb0iC/9qactecmvT
         DMn4T31PtHYDWDSluMsVeH/3by+oNHLk0vFLWwSvAT52DnMkqnL4JMgsq1+vlIpoC56H
         VefGWWbAaD5pzFGQpdR3y3Xd7jf9OoxeVcnKJS6yVgtdrgwWG3lEN+2bPE89ncMObgDd
         m88bHawAK8VCp3ITwvHrSUkj81Aa2yvh4uZSdIsDgTD6hSEAsKCiXIhF1nUfcJKn/eh1
         8l6G2ib8yZRheanvqV2HhsPQbIxzSRXek7XtlAQiWnHG5RsrEy+JsdXp1wAMlxyqRCDJ
         +qUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZqtgNNbtWCC0XWeoB2ebGTtKrvi4BwsxfzvJnGs672vUIY77g3GSa6XFDdAnRmqmX3byeVQ==@lfdr.de
X-Gm-Message-State: AOJu0YyaSD2B1QbZ2dzA2ECKCm6TTDM87Ui5yHy8E0NtWLjw9YMslP6y
	4kf+2B6SrRObbU3HFVbVsbKvWFlNSp91Y90I17CAb94Po+aYqxSI
X-Google-Smtp-Source: AGHT+IFHHO6zyGtwOyFYaHxUNz13/5zEtTy60ObA1A3bwXiii3/ZdnIzT9C2YYYYtza5Nx0q64phDg==
X-Received: by 2002:a17:902:d48a:b0:224:376:7a07 with SMTP id d9443c01a7336-22a8a04c023mr35128445ad.13.1743772686475;
        Fri, 04 Apr 2025 06:18:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL6zHNAXqm+ghUTbvwrELqIx/8lAerIbwHB3mu7jN1z8g==
Received: by 2002:a17:903:1665:b0:215:7e7:5e20 with SMTP id
 d9443c01a7336-229762210eals20481425ad.0.-pod-prod-02-us; Fri, 04 Apr 2025
 06:18:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWt5uqWxbsxAJ0XSaWLNV4BsHVszW46z09148xhjqpyUf6YCvo/dag/yEpgK1Pr4dQ1tC7vimDxaMg=@googlegroups.com
X-Received: by 2002:a17:903:190d:b0:226:38ff:1d6a with SMTP id d9443c01a7336-22a8a032418mr33580115ad.7.1743772685027;
        Fri, 04 Apr 2025 06:18:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772685; cv=none;
        d=google.com; s=arc-20240605;
        b=THEj7fG4S5b2AU4YuPp3Gn2q3FmYtWCSdae6xHm3RJO62ExdbQKjhy5KzjvY3UkuuV
         7fNCLs7aKQuqrzjMpTpxJRKc9JfALZhqHoo/xuRCat7pxh5r/RJ5Pa6k6GSv1cSM8Mtr
         zQWcElkHK5MDIjvb0f2u2SVbhftc8EAoZJEBMWrVnXnyk+IYAX8fZ9txmUxxd/uPXFGj
         TQO1TJy4T6P/c6lhaSDkIrsdGHQK7N/bjQvJPSqA2F0bg0k0BQmGanjkakniM1FYZX07
         9rfaJ20Sx52dbDPhGi7wvVvb4wViuii/dOkU8VjBH5wNB/Sl3g/7ZPYrl4TwJqFUq3ET
         k8qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hZzhASaz3Qj/h/GRsL/4I1VLPg+/CfxJsMQCXOGKIVU=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=dvU+snnh060oYuhTnpOYMzid75C46iQZFkIyJN60CtXXY6ZDlMMedxS2sJjJ3jRXU5
         roBCC3YpWgaKyfNgwLfiTS20xQP/vNrXub2Z/qBcoi/031BbmIBPd73w8Awfl96qEaX+
         uvqp19wxfubs/DH5otstHNNYAJoPhIuQILc0ti1u5h+4IKx5N6IvCyzlrvPNRgHUH5e0
         8ec3E1ychPechxAmyhxE5wl+8w7K8kSwgOsJRT0Eqx4chEmdzgxK4uTWMe1w8tPx3L7z
         E+Ant5L3BZJ2g3wHg5ZK/Ad1HcelAobv6XAV732Y2N4QUIzg3CRX+yESaw496ZmKbZhN
         OAJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="SF/dxn65";
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-229785c3a72si1570285ad.4.2025.04.04.06.18.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:18:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: 5upb7S93SDG6lFIluCVOUA==
X-CSE-MsgGUID: n6ps4e++RhKt3sMCPW5gEA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55402058"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55402058"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:18:03 -0700
X-CSE-ConnectionGUID: vtMsu7eRSsCTmkinYXKa3w==
X-CSE-MsgGUID: mneJnZk0QlShqxm/wu1ARw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157400"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:48 -0700
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
Subject: [PATCH v3 13/14] mm: Unpoison pcpu chunks with base address tag
Date: Fri,  4 Apr 2025 15:14:17 +0200
Message-ID: <61033ef5b70277039ceeb8f6173e8b3fbc271c08.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="SF/dxn65";       spf=pass
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

The problem presented here is related to NUMA systems and tag-based
KASAN mode. Getting to it can be explained in the following points:

	1. A new chunk is created with pcpu_create_chunk() and
	   vm_structs are allocated. On systems with one NUMA node only
	   one is allocated, but with more NUMA nodes at least a second
	   one will be allocated too.

	2. chunk->base_addr is assigned the modified value of
	   vms[0]->addr and thus inherits the tag of this allocated
	   structure.

	3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
	   executed which calculates per cpu pointers that correspond to
	   the vms structure addresses. The calculations are based on
	   adding an offset from a table to chunk->base_addr.

Here the problem presents itself since for addresses based on vms[1] and
up, the tag will be different than the ones based on vms[0] (base_addr).
The tag mismatch happens and an error is reported.

Unpoison all the vms[]->addr with the same tag to resolve the mismatch.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Remove last version of this patch that just resets the tag on
  base_addr and add this patch that unpoisons all areas with the same
  tag instead.

 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/shadow.c     | 11 +++++++++++
 mm/vmalloc.c          |  3 +--
 3 files changed, 22 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 54481f8c30c5..bd033b2ba383 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -613,6 +613,13 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
+static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmap_areas(vms, nr_vms);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -637,6 +644,9 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..9496f256bc0f 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -582,6 +582,17 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
+{
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		kasan_poison(vms[area]->addr, vms[area]->size,
+			     arch_kasan_get_tag(vms[0]->addr), false);
+		arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vms[0]->addr));
+	}
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 61981ee1c9d2..fbd56bf8aeb2 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4783,8 +4783,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
 	for (area = 0; area < nr_vms; area++)
-		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
+		kasan_unpoison_vmap_areas(vms, nr_vms);
 
 	kfree(vas);
 	return vms;
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/61033ef5b70277039ceeb8f6173e8b3fbc271c08.1743772053.git.maciej.wieczor-retman%40intel.com.
