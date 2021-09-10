Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBG35OEQMGQER4G3OJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 619D64066C5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 07:30:46 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id o130-20020a62cd88000000b004053c6c1765sf724233pfg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 22:30:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631251845; cv=pass;
        d=google.com; s=arc-20160816;
        b=GQfEScA9xvEijiVhklJy1uf2XoBUdFY3eORl6b6hpmVz79c043DCaxVwVsHl9/BdJA
         mikfCPz3F6yzBJnRwtPF7D0ksKIuESsOwg91tO1mOVRFUIzvp7kt4M7Sx5ztDr6bAKBq
         UWEAtX8rIcBEPTgRxkwKSSSOCMQAJtYAANNxr92fg3m2fv39KWo/j72phsWLzed77EaU
         LQOmX+cNHreb0+DZwPqpSAVqwnrkpqEGzOF+iaTIA8PUiN0RvRQpZgeD6MFrBeX1fL0d
         j9iQrQB7r3Mn/Bk2MKMSMD+63CD4rO6P0IbxKcWoxSaEUFYNMSVPnm0vjPI9+ojWvuLv
         EhUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zkIzMDqu2S/OfphufyT8TJAQ8Pa9huc1xSlYv6gFslQ=;
        b=tCZvW8ZwXXv0b5rXKbwjyCqNVZc7L+cnf9Hakfm/sJrGpK6irj+VPwnn4cmzu0AI9o
         V3Zun83A9a9gw69ojaTFCN9f7kBzw4QjsnWEwNhcZTMkwPAQEMOWyzNsjEfDsWBPZSyW
         Xbn1yXgJBB4eGorvgYf/Tkjyj+4E0hS3QKmEJc8K2Vqzj1LF6gGsgDamQC0Ef/TdJ4pH
         Mi5UCbagJ/m2jDz6OGgpGMTkSkYc9Ua3xaT1MRjqc4tgnS6Plena7d9oPYlzl9Z+D7pm
         UwYOCsqd6fLbGtfWbmGFJQ5lDlNeR0CRAXXnbzg1TC7qkzk2l1pJqBF4gL1+zYaJQ+9r
         tSwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkIzMDqu2S/OfphufyT8TJAQ8Pa9huc1xSlYv6gFslQ=;
        b=h4cikuEoTakR8opoannesW8Axj15GaH5a+udO734i6QtT8TrMJEW1bcpRDVHrx1hdj
         s4ZfbFrvofR9bX6Z0TzEcku9vzafrcshZ/OFtdBG9VHOYEYUI9bJ5qT3oCJRN7dL87ip
         2H2F19OaryBOuw7WjW2l1hR/0Wi9CRlSpHsaaFkIAUXOVkemhyRh3/ktjDSnybo6uv2e
         vcKN8sqP0XmXbcFeChxDmNMDd9+h3CsCI3s5wmyvLvfyOhZZH7HDvs3PP78NVMw+55ME
         rRbEQbAyTpfFp0Z1CoXdhRRH3r+jEW7cULzjEvsmegwBtj0xNYC9HIyqa5R4cyIq0J29
         Hvcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkIzMDqu2S/OfphufyT8TJAQ8Pa9huc1xSlYv6gFslQ=;
        b=GyHU4OgvTxjZUUTUj6N2pkcUGo8+Vqw9CJSvUp4cMX2uwM5MNygUB+InNXV+CJ3f6A
         +NzsTEbOecrICTFY2IVuP6mos14uNMyCpoGnrLCXxY70dA9ree+hu/oSzBZIwGRfDo51
         bI7F+NFmpUFIg2eZskD0xbM8kGlOa950GZFj32DjZGj/qZqPfcIMbf6X6pZ75+dFOekl
         MFxYKfwu9HZkSLv4yAtXUXr9ijoBrl7O1+R3yA99jQ/+oe7l0keb3HyZ1OKJte1rNd2N
         xBzWnLCnenk48OA9w7CbDmdfUl+44LKqaEscNSOZ7UzS1DINF141zzaR6G0jad0gpEMf
         bbCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Q0fHtiOXI4uu/bQ+dV7VEFWci6a8QlrdQ5ujbOPK7TFJ7CYQn
	MikdipIMeD+NZDWJjljdlzA=
X-Google-Smtp-Source: ABdhPJzeWdFJuuuKfcJ4Qx4F/WxUgVZq/7g0QbRbJovViRWluYpvTBIK3V1q6OLF/kCJVnhtK9KYHw==
X-Received: by 2002:a17:90a:de16:: with SMTP id m22mr7591468pjv.54.1631251844901;
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:830f:: with SMTP id h15ls1864945pfe.6.gmail; Thu, 09 Sep
 2021 22:30:44 -0700 (PDT)
X-Received: by 2002:a62:80d8:0:b0:3f2:72f5:bb31 with SMTP id j207-20020a6280d8000000b003f272f5bb31mr6560711pfd.0.1631251844352;
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631251844; cv=none;
        d=google.com; s=arc-20160816;
        b=AfAMgpQGxOmGmiznAIuvghQh0tfxytyfJzbPQ3JZCYNlcYcGh2bEnxyi2jFe06rfoX
         4evpi2nOnrwdmYgsxSB3tq2tLBmkGWa9StEUsSh0SavOZ4ojYdDLVUsG4SYhbx1gRO5i
         MQMVKwCWNzmJSJOqCLpu8JnPazJ6wEfRBciGVjzPA/vWMewYJsOgt2Zs2fC2xLS/XU7V
         l8R4VsJHk1BIeNSJdS5rjfkPMtDIdN8Js6WPpiTY/+s+bIY7QFuEW8Btx4QZo3xkTnAO
         bWtHtgy5MbKUqts/Vxg9a2lwQq6O6ns0cGxmxs6HAWGJFUmxD8mG5qUB+ccyLK4W/vQ2
         mFDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=XI9HzmKOoyri65Uuo794oHyspeFdsG4eI2q519F2l74=;
        b=murI7aFlQC0qHkLVN0GEgpCmmlyMJ9+3HUwYbf+PBR5EdFFM8zt+J5H3/cbMrsNpeL
         thJsAyQrI/n+NvTQED4UBuj80IKEUI/+9boeR3zAJRkdUyDX7HzLT9VX8CLMLH8XzAfJ
         vphI0z/+NSAPb/5f38bqV4pScISU8CgxmZjSxKUoDW+q03dyo8PhK3/aPli16ZdTnda3
         pJBuF4PzqBLUA4IohkUbi16tDj5muen/eEIqBLt4JKV54JTbTQysozVr97md/eoWmUJi
         vD3ftf+68ZzjvfgwG2+e2nPVjTplMWUY9dwImhHEb25nnUQ8RB4tAzawHgJMlqISuQWj
         mu0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id u127si131709pfc.5.2021.09.09.22.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4H5PZ557rKzVr2T;
	Fri, 10 Sep 2021 13:29:17 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:11 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:11 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v4 2/3] arm64: Support page mapping percpu first chunk allocator
Date: Fri, 10 Sep 2021 13:33:53 +0800
Message-ID: <20210910053354.26721-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
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

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm64/Kconfig       |  4 ++
 drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
 2 files changed, 76 insertions(+), 10 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 077f2ec4eeb2..04cfe1b4e98b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1042,6 +1042,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
 	def_bool y
 	depends on NUMA
 
+config NEED_PER_CPU_PAGE_FIRST_CHUNK
+	def_bool y
+	depends on NUMA
+
 source "kernel/Kconfig.hz"
 
 config ARCH_SPARSEMEM_ENABLE
diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
index 46c503486e96..995dca9f3254 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910053354.26721-3-wangkefeng.wang%40huawei.com.
