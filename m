Return-Path: <kasan-dev+bncBCRKFI7J2AJRBI4VTCEQMGQEO55TMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF543F7192
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:17:34 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id h36-20020a6353240000b0290233de51954bsf13825212pgb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883043; cv=pass;
        d=google.com; s=arc-20160816;
        b=HvSihcYD1tALX9lrzx2GOqtySb1in4M2tgASifPdW/Z6OHwtMol/T7L+KIvDnBQDlW
         sjkA0m4Zq5xi6CZ3VlDcUTrHE4PgurAvwBQThpaQkD1Zb63pSB7W5/yEF6849ggHK0Wy
         tImn2G/xR4YuF+AydbOq9eDRSluPBnD+2OeOELC9xTEx488TUJhPE2OUM58KKZFLzKRp
         CdbodukMUxi/i6FtSXkSehNvAYBt7NF6hMuTlw599Khhsy4I1CMyYHEkjpZ70kjSm3lU
         ORHzcZjeIOqfBIKMiRKpisshOtvV6fgiXbyKHI6qzU3N4yPtva4nuQOO5lrVhvkZaN8U
         VovQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2vX6zdX5124EwMFvdjTal/UA7Dyp2LD9Av1vFlm1ps8=;
        b=F83sroZMxYQw2QJLU1vZi3NfKzUcJ4MgAJQRQBNRX8IhymWjFA26Z91LFfrKPkI9U4
         zTknGLJe3iNV3Q+l9IEPytrfs82gREbSWjkW8AeKSMmaJfzkFYVl75m88l5bAuz1FTwy
         XzAOH7PuqeWltUibeCUaZMUOWbcfyYqitg9tijPS6TKbcU4X26zi12RHqjtycm0C6O89
         /mORMmAcOYCiD+XYUnomvyjamfF/sFgaiuzy+uf2dgvJAKmn/GnwV5+MvEq5xH+etxmG
         21hvmssbEd/GkAMl6ASfitO9qXx4EExRZNRNu7s7osVEfccmPNCjk7OSNDFeMun/ZcjD
         Pj3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vX6zdX5124EwMFvdjTal/UA7Dyp2LD9Av1vFlm1ps8=;
        b=VCxbtgv7lVN6dGRUGlKd3Oo935g+S0zZEqK4gXEWlnozyYCNx1okeVnbi7oeU6Zrtr
         lK2r2cpsQ4I787cMnHDkFvOhaljj8F4eTTuqbMrvde4K+Z/8OhuTboQVsnaxlHnd5Gsy
         LXnkTg0c3ykbrCP4rObLxxsczTiQBHoRhylrzc205vsHzp5EwtdXfIeZM4kNV+oclovp
         ZFqfnBfi2A4oFrOFa1A3ebOiXT8/UiWO11beqZlbhW3huguRNHl/997662vwKSYi+gEH
         XFjiudSTBkZpzV0Gze1jfKkswlZhcuVEoY9eK9NHRwy9x4eweUe5WLwUIb9LAZBCn9Bq
         osoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vX6zdX5124EwMFvdjTal/UA7Dyp2LD9Av1vFlm1ps8=;
        b=HDEBJAl2r1gOqT5OKwWYNYKEx3RmKBaRZ8bm9h9siwVS+CAja3CbxOoMl/OheRil3i
         1BMgT5FzBjkLMSmFzHP5wfoNA5VoauC86qbIM3pSgtmkX3ClbGiGREXH6Gbq99nmrqQG
         YXQ6YBW732BYkiBWhBzB+f4O+LOuEJV4HcrUoaKI81Yc4j47IDkrmAFB8mqnUWiZ1kjX
         4EAdUgBp7lj62J7F2lxyiaI6jjigONOfTjgSsov1IDUBpTT6ZwwgsvZkes97SnImUmIB
         7DeJVy8QAoenzuz4pQlH/VC9EUoEedc7cFos8xXRVZTXA4eevwXOak8sjuOH7Rl7QEbx
         6UTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xLkgnAQrVDxX3CRDfebpPRerek9lfisL+1sZTadKw0mnwOFvH
	5wkqLV8dSKFBGWDa7ZLD250=
X-Google-Smtp-Source: ABdhPJxT8M69ywpVHiEliOZl89y2CrTpw8uMn9GVxmZ5P3cJYyRFNcVGHf9ETRb2qdxdU/51MbY/Hg==
X-Received: by 2002:a62:dbc3:0:b029:3e0:ec4a:6e60 with SMTP id f186-20020a62dbc30000b02903e0ec4a6e60mr42387399pfg.25.1629883043588;
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d54:: with SMTP id y81ls678344pfc.10.gmail; Wed, 25 Aug
 2021 02:17:23 -0700 (PDT)
X-Received: by 2002:a65:508a:: with SMTP id r10mr41178980pgp.96.1629883043036;
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883043; cv=none;
        d=google.com; s=arc-20160816;
        b=vlSqMmpWDHbpAQmw4Di3XgxAHovV+Gxx1RxkGf6adAOW3jywh9yO9VEmoUdY0bAKgi
         ussfhPqCER37paJ/6dDENOwKjdRqdPQG4OSjxN28xT+ZMf7H/WGGJmsBajSoC6GQibic
         4gHlCgvapuhJjdnzJWJjO7X5R+S2Wq5Dz0KOlcqFsGMcuXf6E0iwFt36/taCEluTj9pe
         WT8oAbp/K+uzle0r5GQFCHYh+ibQKCtByj3AqGMLCswX9H+soxE9EZXmOxwuobRhs5sF
         rvFzsOtLot0vjz2Qv3QO/MfxgEdbsKoVzAdp8d6VRQOZ97PxZTtSyBtYdEkPh1JPBOnB
         +xDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Vz4mOQwhKwUORsZht+JDd2/y3XjAhoY0V7be4xxwIV8=;
        b=XOujpRsmmwo8sX+jXanwNj+TzA8s0rn/+ZsbEmY3MR1Y5DSPRVT8NK6RlxmnPScVVj
         PtaTxlEgrsHXRHbZsMmXlDIajA7XOuP1v7XOLzSEaWhqFNhO3eRVOkkT3bDjAwcl7UnC
         LCKIOtmVZ91PidJd5AaFoevQiOYOMdw1UHWNy7d8S6n6lTd53UicbqBUcqSf1M4xHRnN
         fywMCi31Ga6ZDm1FRj++Qq5LWFXk6k8oQvD7xrrVyglngFsHTCQhA00s0n6m07NFQXZ5
         Ni7HpOTJgNTTF7hITo4h8DHz0pI7SNUjHEaTkwN0+HIRkpBFauc4cxI1thR7Y5Jzgd5s
         LBiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id g3si320378pjs.2.2021.08.25.02.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:17:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GvgJC0gzCzbdRJ;
	Wed, 25 Aug 2021 17:13:31 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:21 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 25 Aug 2021 17:17:20 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Russell King <linux@armlinux.org.uk>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH 1/4] ARM: mm: Provide set_memory_valid()
Date: Wed, 25 Aug 2021 17:21:13 +0800
Message-ID: <20210825092116.149975-2-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

This function validates and invalidates PTE entries.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm/include/asm/set_memory.h |  5 ++++
 arch/arm/mm/pageattr.c            | 41 +++++++++++++++++++++++--------
 2 files changed, 36 insertions(+), 10 deletions(-)

diff --git a/arch/arm/include/asm/set_memory.h b/arch/arm/include/asm/set_memory.h
index ec17fc0fda7a..bf1728e1af1d 100644
--- a/arch/arm/include/asm/set_memory.h
+++ b/arch/arm/include/asm/set_memory.h
@@ -11,11 +11,16 @@ int set_memory_ro(unsigned long addr, int numpages);
 int set_memory_rw(unsigned long addr, int numpages);
 int set_memory_x(unsigned long addr, int numpages);
 int set_memory_nx(unsigned long addr, int numpages);
+int set_memory_valid(unsigned long addr, int numpages, int enable);
 #else
 static inline int set_memory_ro(unsigned long addr, int numpages) { return 0; }
 static inline int set_memory_rw(unsigned long addr, int numpages) { return 0; }
 static inline int set_memory_x(unsigned long addr, int numpages) { return 0; }
 static inline int set_memory_nx(unsigned long addr, int numpages) { return 0; }
+static inline int set_memory_valid(unsigned long addr, int numpages, int enable)
+{
+	return 0;
+}
 #endif
 
 #endif
diff --git a/arch/arm/mm/pageattr.c b/arch/arm/mm/pageattr.c
index 9790ae3a8c68..7612a1c6b614 100644
--- a/arch/arm/mm/pageattr.c
+++ b/arch/arm/mm/pageattr.c
@@ -31,6 +31,24 @@ static bool in_range(unsigned long start, unsigned long size,
 	return start >= range_start && start < range_end &&
 		size <= range_end - start;
 }
+/*
+ * This function assumes that the range is mapped with PAGE_SIZE pages.
+ */
+static int __change_memory_common(unsigned long start, unsigned long size,
+				pgprot_t set_mask, pgprot_t clear_mask)
+{
+	struct page_change_data data;
+	int ret;
+
+	data.set_mask = set_mask;
+	data.clear_mask = clear_mask;
+
+	ret = apply_to_page_range(&init_mm, start, size, change_page_range,
+					&data);
+
+	flush_tlb_kernel_range(start, start + size);
+	return ret;
+}
 
 static int change_memory_common(unsigned long addr, int numpages,
 				pgprot_t set_mask, pgprot_t clear_mask)
@@ -38,8 +56,6 @@ static int change_memory_common(unsigned long addr, int numpages,
 	unsigned long start = addr & PAGE_MASK;
 	unsigned long end = PAGE_ALIGN(addr) + numpages * PAGE_SIZE;
 	unsigned long size = end - start;
-	int ret;
-	struct page_change_data data;
 
 	WARN_ON_ONCE(start != addr);
 
@@ -50,14 +66,7 @@ static int change_memory_common(unsigned long addr, int numpages,
 	    !in_range(start, size, VMALLOC_START, VMALLOC_END))
 		return -EINVAL;
 
-	data.set_mask = set_mask;
-	data.clear_mask = clear_mask;
-
-	ret = apply_to_page_range(&init_mm, start, size, change_page_range,
-					&data);
-
-	flush_tlb_kernel_range(start, end);
-	return ret;
+	return __change_memory_common(start, size, set_mask, clear_mask);
 }
 
 int set_memory_ro(unsigned long addr, int numpages)
@@ -87,3 +96,15 @@ int set_memory_x(unsigned long addr, int numpages)
 					__pgprot(0),
 					__pgprot(L_PTE_XN));
 }
+
+int set_memory_valid(unsigned long addr, int numpages, int enable)
+{
+	if (enable)
+		return __change_memory_common(addr, PAGE_SIZE * numpages,
+					__pgprot(L_PTE_VALID),
+					__pgprot(0));
+	else
+		return __change_memory_common(addr, PAGE_SIZE * numpages,
+					__pgprot(0),
+					__pgprot(L_PTE_VALID));
+}
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825092116.149975-2-wangkefeng.wang%40huawei.com.
