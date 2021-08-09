Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTPMYOEAMGQEZDX2IEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D67DC3E42C5
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 11:33:02 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id c19-20020a25c0130000b029059337c4e310sf9800366ybf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 02:33:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628501582; cv=pass;
        d=google.com; s=arc-20160816;
        b=tW6rp24cnnCfyvJIs94UEXzXWWGiMW6OvjdXvdx97LrERGKBStbszW/aMJ1v/5IJxc
         DBJ92DcFyE78rhN1gytyyTWLSF+IzmHaOYCPXNVZ/C5dpa1zs5NNWddSY3he62n2Kd3S
         R1+vZN6KtfH49u2YRsoNAH6RojQ9gCZQeWAqSGzwqTU3r/3Lf7TbZ9ZOSamMvbLFybSW
         eTinHT8XrceJLS7iyHQAENh6hDD4t/uMclQV6Pg8JsOpgQ5rbkL5uZ/WzXa6jcWEArRP
         WUypBEnwIa2bjpUCekBHKA8tJbAQoLmSG13+yPnFvmQV7Na/Kdla+sGG0eJAslDsfKRM
         E8yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/tuBXpgbNTbd+JTsKJpA0tdp0qFjMNKOUPgxGxgGR0M=;
        b=X12OZ6DVZe1Qharw56rK+h+51iPJpgl3gxoGVaPk95+uJPGzdQJuqMu6pMbBebWzbI
         hR7IwxxI8HrSp0EcdjXEo9czX+CK51LI8LkAvxTuRc/ud9U3a8aT8ek1/2h17y3gPUj+
         m8dmeSBie7aNb7B/ZEPKIoGSLyGn2XEQDBSQp0e2Qb/JcpI3VkWdRWfqEWw5/25dO29C
         HLFNP4cR6Or8jPW6SW24FA0ZWoC6YfgTliwWSFd+ermW9CqRgkz2fps++3ETPZm6LPNU
         DwexYK4b/Wca3lw/DfVOU3Y6E3xi4E/1KRjyyGeMIEWn0Z73COfjDFu/MSIlspDKD4d6
         dqFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/tuBXpgbNTbd+JTsKJpA0tdp0qFjMNKOUPgxGxgGR0M=;
        b=oZy3lu9lfJtEHTlm6/Pbk6B+6jNOZkIrePlwgBtSJpcfSKhzrFAbskHb/H8c9njI/S
         FMuRfi8DkGqlEVuqZeShCzw0xGhjsZJBw464NfXFjLMW0pPOx69tusntyPhU4TISEeuT
         +s+yOu3q/nG+skjZAWcA4i+xKuGxjlcujOSMGor1kluQuG1iEN71o5Q2xNsSytT1UBtf
         xf5nuAwQKBXXj6VVRnRlfTMV72Dw151jHXKSdOOq85/8vBaErq5QFfs7csmNh48cUOPc
         NE9j/kO+kxezyeH2BIKMj4o+WkYPbCGutur53pvklWt3DGJLAm+Zo1YETlAv/bw/hsnc
         CrFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/tuBXpgbNTbd+JTsKJpA0tdp0qFjMNKOUPgxGxgGR0M=;
        b=UaeFwJ7yeBkJwfakbv1oAipbfCAzt7pa/Qxil08wa270V9uU9QOTZ434nTX0Sj21AK
         GljsjDoM7ajT+9TbehEiJt0uXVIZyT1Uz2lud095VkVNmqA6VTuE9V00vu4wS3lnKoOm
         FmSG4Q8h9cHW7DaHkOS6QFDO13ffHvyNhfcGvXgMoPW9ipFma4KHIJzRQz9BBOGbn3/b
         ga9FuhoylfzRn8ilst9pL051f49nmfaGtjr66fdwx+DMrzzwlH+GxFJj78KaegiE7WIX
         tzfZ7OuZA4pCxvIFFTX+wmkpARyMoy483IE7Gbk0+op5G/1cI3AYwZLt4I53KNwc5aOX
         Ja0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VEubqXD807BubfUpaJl1a+m68h3+t3nmwzV2YrqEXklR5cENn
	KVcUiLo+8cReX9Y3trIyAYY=
X-Google-Smtp-Source: ABdhPJyYuxJWcaPyS+oNl07JVTpmp+VKEgOr2NRDIa/wQ0enDEzXEr03gDzkJNlGlq/eB5bBbA2sPw==
X-Received: by 2002:a25:e60a:: with SMTP id d10mr28651565ybh.56.1628501581963;
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d705:: with SMTP id o5ls103575ybg.1.gmail; Mon, 09 Aug
 2021 02:33:01 -0700 (PDT)
X-Received: by 2002:a5b:9c9:: with SMTP id y9mr30162673ybq.460.1628501581569;
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628501581; cv=none;
        d=google.com; s=arc-20160816;
        b=bJLg6k4e8uZTZdBemuW8ty/V8i3MlU1FCBTvTp2sT+w9SErgzw1dWCg8hPmBiBeswB
         aPiVQjiQWKZp9HqDal+pgejc6Huw2d/HQDm+tPCcE5/4ZjfwOSW4ngE4isgSt66NI6Hs
         zG44Lx4ZrfPmsG/1H20gPjKNMrko0faZ0ladY/ztZ/rOnabG7M9jbxfEDfa3Q1tWcxov
         W4LgS4qF39xtNiXtwVQHcgFJHzi4VWynh2fAoQdL30FTasKBPDk5ySGMbzeIMXUWARBO
         cexaneT52PWnVVq5uNVI8gviCYVcF2ZvDyArXaaEs5t8QTEuCk2Dp2VJtjp5Bvv4w6KP
         bvqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GUL1ItjO6xfsVHV63cEJXAActC2mw9s/t7DlG5Wi+zg=;
        b=W+c697HMqBHCdJPXI7ZRobhJ7DDJfgczh1rvby+LxK9+IAxILdFdCym+E2uov39LxJ
         BXdvvUWXa7YNj1HL+Hd57iYmAKEB6hR81n0TttbrOKs0tdtgEhg68ISCGSLYupbePmGg
         dMv1WOFUbbNL0PN2VYsu5h4gmFTdu2B+nV1UvN9hkXlVQ94MHasMv49WINp7RAW5FKDN
         J3mJwPmUmuEwaATDuOfhbUZVyaM+DXAxGOS50KLpYcsz21TilAVTkaLRVtYxn78kTPcJ
         s8NzjTccMU+VHELLUbC7P8Y/xoqeWHrCSsi6+dhImjeO9fUtpz+eFkJg0ODSIBzrXue1
         TOkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id d10si1037105ybq.1.2021.08.09.02.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GjrTC3VYlz1CV0x;
	Mon,  9 Aug 2021 17:32:15 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:27 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:27 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v3 2/3] arm64: Support page mapping percpu first chunk allocator
Date: Mon, 9 Aug 2021 17:37:49 +0800
Message-ID: <20210809093750.131091-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
References: <20210809093750.131091-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
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
index fdcd54d39c1e..39f27e268c38 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809093750.131091-3-wangkefeng.wang%40huawei.com.
