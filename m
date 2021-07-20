Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMPR3CDQMGQEPFFVLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0873F3CF22A
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jul 2021 04:45:07 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id c7-20020a92b7470000b0290205c6edd752sf12086916ilm.14
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 19:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626749106; cv=pass;
        d=google.com; s=arc-20160816;
        b=xWQDQJbQwzNSIwtNdoRy8dl/MjYwPXyWDsuqMHaFe/DAwoY3J+4tYShwGGrx0ph4EZ
         PlWJ2Ny63YxE+fGbA6eFWJ9bGq1CNmCvK7j5ej3PnvMfbGr1eIys3sEd4MD6tQRr0zqB
         23CWAxY9b4DqDvP8mYNG7Z6Nruj4p6y9WPY8ZT/DZBqe33XaMshp/Vf3Wbd/mfWCLMWk
         QKX+RCsPaaPmxuKc/iq/oiltWiad/iCTOjfh4AHLoZADqRbvnAfdQLDYjBJU5FTq5mWD
         kDOk0ieaMkf8x3FKCaLYPcWnZZtDDM7n4faGLJM5E/+RFXwdv0GY/rGlHIAsUYVa73tF
         8QeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zsPPr+9VH06xjvKxYJZ9n7vsiZWG0RdvFAwM+JVwZ7I=;
        b=q7oXhvmW2WJlUx2/MCSXA59UEjT/oo2BRYXx7FyoqDn2yuX9mjIJ0yF3tAEN+2hnVJ
         4BB6lp4LdVPbhNcy//dUMgmLOwXufbyIq2vaPfslGD1EEZg2VcImPyww/mLMv1O1knSF
         +S78GxYlonYdDpj8kUzSiyTwd3mkGXa/FQY5zXpOZjqY1ISpNCdV6Kz/VwkDQcOzAvEg
         3cnDMKjq0jWqOhSXNVu8qBZNhfWhCIMfNcpmng2AwIiWtL683NL1jssD/RXiazKcmDzV
         LKFK7j6YRnKkVHwoDV8DM6+3GLeBjqeYSKWznwLioH9bM2viURvqc6djqAtbewcatZyy
         xHTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zsPPr+9VH06xjvKxYJZ9n7vsiZWG0RdvFAwM+JVwZ7I=;
        b=A2bykvdT5DmekGJGKDk9hpcAVKPUuF7Xlo5VfJK/O+Zk4javGdnSkqewlsJYUnr52f
         pumA/18ajS9wJJFKuv9BWl+uuYYx5D4SH9UERh7+hlOUgEuOoWRL286biECQYCC6OGFm
         tSo886hRtburnUgvSQyrBmqwIN3GtItYfvmItYUgx/DvT56OKdZ3seig8jTFBW1QKbXB
         a/Mr7M7z0yQcP6l96tKSvTpMRtRnzxGBLdV/c4IwftbINriZ1Xjf4vKrDXJNkycScTWg
         iS9F5AQRc8QO2JKSFm+km8av2yBn0r0yHT1vLl+i9E7ZFycZVGwgLb76UTI0g1PZaDUI
         hr2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zsPPr+9VH06xjvKxYJZ9n7vsiZWG0RdvFAwM+JVwZ7I=;
        b=snPvdeUGTa5tUlvmQEutzQjORbQHPjbPym/tmO+/ITn3rdkILTKn4hr1XNtmf7Y7uO
         WL4c4ZvDclH5F5VFpEdxPaqg4WkQuGdMDQQl730dr3J3bnMmHZYiQ/2S0z2+jSEZN5sk
         1EunP2Tjdg5bfTDymmrqDffC1AfVk1DtojjKQTctb0zdjn4MsFvQjDR4COJsalQzqZXi
         GYXr174bXTEqXswKlbmTN7Q0sfPaJjxi6x+XBPxZAAuHc68HCtU+R+jNI+wtVbJ9zI9F
         R0yf1UcP7CgaX7tExHXD0hmI+nxO5zhoe51PK1goQw2BsRvFn+iZUPs7zIHNVrZWVG/g
         wUXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53075ghH6Vq8Co4sjg8vNqgiHwWqf8AXUIBA/jxfxU7h1U4lxdw+
	MaY/J116MOgWoh+t+qALBko=
X-Google-Smtp-Source: ABdhPJxv8DHoH/cTPzUaYhYj2sZkSg8RZAsSSALC7lkazJwESacEfJhsuJPK8POM8cq5SVTFLn4nwg==
X-Received: by 2002:a05:6e02:114f:: with SMTP id o15mr18124708ill.255.1626749105985;
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:144b:: with SMTP id p11ls3897235ilo.8.gmail; Mon,
 19 Jul 2021 19:45:05 -0700 (PDT)
X-Received: by 2002:a92:a004:: with SMTP id e4mr18044469ili.299.1626749105668;
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626749105; cv=none;
        d=google.com; s=arc-20160816;
        b=QFANZGSKsgnuAznYMLRcypUBWAeiGZvr598OBK0RVpFCf3qkBs7pIdldXmrdJ8YxEn
         bSdlRbDaMlEt9elaqEoObgB3p00cZR1hZ/4S0EcJK/XaGkoxaHFBnntyX49BkJSmqNVQ
         66TqB/Wb+ESpowM1IVzZCztIdHf8UUSkp6Xm0wpO7TwiZcRqNu7YjcX9vB13jz5EM3dZ
         nofn+7JPoZ94kCS52x4Y3FzCxqUC0/FGp9whGvcQaemvF9J7OjoiFFNixFuQtLGjPoFc
         ncT2BrPMWdu/eBsutAzh0uzYwVOOSthR2dGBsunhhnqRmsaygmxpxmsKio71HXPz0YpB
         FUYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=KrKuI/XJWT4MFNxgJp4Lrk6Bph2Sj0NOSUZ+QE+Almk=;
        b=vhyoSRprAYsNRghES7BZIj5OIPTh+Tzx9oY+daVhwegD3PiXp9DiLglNq4zIkFjr/e
         eHu1kK+YBTzvPniTkBfBsYRmShOxBkDhJZ17DkhzzIRBodYA6+PtfMUB50kNDnfwU8eN
         coPsEzLhz8PYgiCygkrnCuZMapfrvbSawE++3fLY0m2WGA4W0M8mAw/wJdDFQe2J7cK+
         qVeekH05WjfhS3AuTH8mcd8Yp/7qUJ5T9AsaQRqafOEc2M7WShvSUVw5IYnVdJyLwmL6
         KzjWvfOXDP3+3Oz4RqiBukapPFnkBo7bWbvdipFJVj+XhKWmoMTT2bCYGo6G5Jf6HDAv
         ozqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id e16si1584283ilm.3.2021.07.19.19.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GTNHp0Vy0z7wx0;
	Tue, 20 Jul 2021 10:40:54 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:32 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:31 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH v2 2/3] arm64: Support page mapping percpu first chunk allocator
Date: Tue, 20 Jul 2021 10:51:04 +0800
Message-ID: <20210720025105.103680-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
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

Percpu embedded first chunk allocator is the firstly option, but it
could fails on ARM64, eg,
  "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
  "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
  "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"

then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
even the system could not boot successfully.

Let's implement page mapping percpu first chunk allocator as a fallback
to the embedding allocator to increase the robustness of the system.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm64/Kconfig       |  4 ++
 drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
 2 files changed, 76 insertions(+), 10 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index b5b13a932561..eacb5873ded1 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1045,6 +1045,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
 	def_bool y
 	depends on NUMA
 
+config NEED_PER_CPU_PAGE_FIRST_CHUNK
+	def_bool y
+	depends on NUMA
+
 source "kernel/Kconfig.hz"
 
 config ARCH_SPARSEMEM_ENABLE
diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
index 4cc4e117727d..563b2013b75a 100644
--- a/drivers/base/arch_numa.c
+++ b/drivers/base/arch_numa.c
@@ -14,6 +14,7 @@
 #include <linux/of.h>
 
 #include <asm/sections.h>
+#include <asm/pgalloc.h>
 
 struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
 EXPORT_SYMBOL(node_data);
@@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_t size)
 	memblock_free_early(__pa(ptr), size);
 }
 
+#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
+static void __init pcpu_populate_pte(unsigned long addr)
+{
+	pgd_t *pgd = pgd_offset_k(addr);
+	p4d_t *p4d;
+	pud_t *pud;
+	pmd_t *pmd;
+
+	p4d = p4d_offset(pgd, addr);
+	if (p4d_none(*p4d)) {
+		pud_t *new;
+
+		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+		if (!new)
+			goto err_alloc;
+		p4d_populate(&init_mm, p4d, new);
+	}
+
+	pud = pud_offset(p4d, addr);
+	if (pud_none(*pud)) {
+		pmd_t *new;
+
+		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+		if (!new)
+			goto err_alloc;
+		pud_populate(&init_mm, pud, new);
+	}
+
+	pmd = pmd_offset(pud, addr);
+	if (!pmd_present(*pmd)) {
+		pte_t *new;
+
+		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+		if (!new)
+			goto err_alloc;
+		pmd_populate_kernel(&init_mm, pmd, new);
+	}
+
+	return;
+
+err_alloc:
+	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
+	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);
+}
+#endif
+
 void __init setup_per_cpu_areas(void)
 {
 	unsigned long delta;
 	unsigned int cpu;
-	int rc;
+	int rc = -EINVAL;
+
+	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
+		/*
+		 * Always reserve area for module percpu variables.  That's
+		 * what the legacy allocator did.
+		 */
+		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
+					    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
+					    pcpu_cpu_distance,
+					    pcpu_fc_alloc, pcpu_fc_free);
+#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
+		if (rc < 0)
+			pr_warn("PERCPU: %s allocator failed (%d), falling back to page size\n",
+				   pcpu_fc_names[pcpu_chosen_fc], rc);
+#endif
+	}
 
-	/*
-	 * Always reserve area for module percpu variables.  That's
-	 * what the legacy allocator did.
-	 */
-	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
-				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
-				    pcpu_cpu_distance,
-				    pcpu_fc_alloc, pcpu_fc_free);
+#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
+	if (rc < 0)
+		rc = pcpu_page_first_chunk(PERCPU_MODULE_RESERVE,
+					   pcpu_fc_alloc,
+					   pcpu_fc_free,
+					   pcpu_populate_pte);
+#endif
 	if (rc < 0)
-		panic("Failed to initialize percpu areas.");
+		panic("Failed to initialize percpu areas (err=%d).", rc);
 
 	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
 	for_each_possible_cpu(cpu)
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210720025105.103680-3-wangkefeng.wang%40huawei.com.
