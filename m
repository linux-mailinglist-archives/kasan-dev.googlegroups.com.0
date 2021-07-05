Return-Path: <kasan-dev+bncBCRKFI7J2AJRB5GPRODQMGQEO5MEWOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AD023BBBF5
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:07:33 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id o14-20020a05620a0d4eb02903a5eee61155sf13873467qkl.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:07:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483252; cv=pass;
        d=google.com; s=arc-20160816;
        b=F6mv4AaTIjAuGFJ2XpTahdPVD8bFG5dO0Qf6rXW3TlLh682Ix8fuC8nhr7Min4lNo+
         mFbS9P5rMiGi+QvoeJFAmVVoJZrhIrRNLjr9B1KwaiPx7pIkYzidkzTumTdwWkoKuWn6
         UFMXgN/VTNWOZ1r1U0CkA/dd4gER5wbVwwAi+u1LKdqkaofLdCv6hO8baCK6SjWgUxjd
         HUeQGDNxDk2QZFOgq3TV8+H6UYUgaDltki/75lxzpMVKa1xGRnMXXHfDX5Yr7vSXSkzq
         YTwzXPwTJGar9960O1BhCyNO+d7DCv8P8WeTvPbPN5FIhXwLV6wsh4xQ5Xgvsg1r2z14
         9+gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cE8NyiCuCCnlJWEEq5ZO2zoswtGWfCZwCIXMDrkN2yQ=;
        b=p3kHckAqPjNKCQWURPoY+PlDrA6xiKsTRZSlMja6DTzTuz7V0LpM2yC+QNO/ga3LMk
         KIfDm2yF/Diqc8mSOJUmOd0Hp3XuOvFzpIpn+QHguU69aG0uUWbkYqHLfSkHr7gdBlvI
         xpZFZOONPcmlz2p9yfW2Jy2vJp2k4y96Mg2QR8V11U+17rUGP5ozckpRexk1AREdkmTZ
         JjC3ZT7/CMqO9k05ilMQkOlQKcl1IuAyTfl7h5ysAoLgAMVJZf4sWc9YqvsCS2Tz/b0R
         q0z6iiaChTkXWg/OeoVe/vRcC7iGL4GIfYjbZDFXmyPcBngppGlMzng50zTufHZuRyja
         U7Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cE8NyiCuCCnlJWEEq5ZO2zoswtGWfCZwCIXMDrkN2yQ=;
        b=j+/K3mhR8LrwO6Ni3QM5eabRpQfz+RBTtxmU3zevGMtbZxhGx+3UPz4HMtzb/XB+7t
         0kv2lhjX7wI/6akloTkAQLQxRgMI2ItwpKPx3sfoRKox8hx+IzQBAfgib8tG8SO308+G
         y/qLIqxhsL/6KppUgacrZtRNyLWFN4aLQ8ZEG/ju/mLoLjHtZhZtM5vz8WQ6DVU2m4Sf
         TJST/tYoahbkeqeQ4sESrh/H/UbdF0JOC+RxbMCUsHu3B7R1nrDpgB+WJsYwFg02+xfr
         tSRbfcbQ4uQVf0EKXPn5hZfuSeN4gU8SAO0w+pOb3Yjx/0kja9HmNnNqV5H41YMn5lW8
         A4Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cE8NyiCuCCnlJWEEq5ZO2zoswtGWfCZwCIXMDrkN2yQ=;
        b=F8Vag58Gu5HZWQ9QGhYyQl4/3+BDlpbs3n+RI670+WqY9GdrmuaTatnW5ihChIGXn4
         DlCEKovEB24ea6FmVBvm4fonFHMt7SkegX/J6fUZL/eR8XeU0pUGQ6Xm28zqtyrNcqtZ
         VkKz7/oj7x/E+ZpCxU/AMNRwk7lagq4sf+HKxsqvUtB+9ybPj5jdT9T4MIFvVW7j1ZGv
         IPJz5GxVG61Bpy8XCJknG5aF16DaT0E+RsM8x9eMj6OJOK1DbNWg78TIwS/prvqiQCew
         nPnT1tC9Hbh8ROL5nzVinIsvLrpt1SvaOIvKmqD1xZy2R7spfSgSq4llkZdtbQfBG4kN
         aYew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rYHawHhfJlbA9V65tUi2TK159VhEHI9BMRPWt29uprkveC8Yf
	qJMsxkof/zltaYJL/o4SQ/k=
X-Google-Smtp-Source: ABdhPJx7EnlSXAh9zU/hWhGcNvjKmiVBRUDPxgtpl6Ewj3DAikgOFrNMggskMG3it6z2/IHKJtAU0Q==
X-Received: by 2002:a05:622a:10a:: with SMTP id u10mr12127718qtw.173.1625483252400;
        Mon, 05 Jul 2021 04:07:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7772:: with SMTP id h18ls7920317qtu.5.gmail; Mon, 05 Jul
 2021 04:07:32 -0700 (PDT)
X-Received: by 2002:ac8:468b:: with SMTP id g11mr12074534qto.344.1625483251895;
        Mon, 05 Jul 2021 04:07:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483251; cv=none;
        d=google.com; s=arc-20160816;
        b=SkVRiJ0SOi+MNh1Ctite0U9MWsJwduwAQtjnsUIFS/lP2bY96Kl0Yjcv66OS3af1kE
         P8e5CWzz0CLNnJdy+fTaqcLEi8tPguRsw9Uec95inu5wnW3bunY00UqmJzYEVb2WUNck
         H6e17GsB8Y2JJ0NMgVD7D2NNHbtJ5UfDZQITAKuDAx8ZKwsloh0Mza6fgo/UvvMd0JnO
         Xrn/oppXCdP9w8MPu6suKl3zL3AODrgatx0LDr4PfdFOPQH2XCJ5MAWgTymN4jWp3rrT
         7iUlAwFOQSpdt+U5ObXDHeQl8j/wvIiM8cbXO2KagyIWMdq6L4Iq83QglCUG+55KPj76
         FC2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=qjvmdob0WPIKhhQa3NGg/CnUjyTqgCAhIXZ6vwfV8Fg=;
        b=N2yffbA/YrGG8NXEhQspECfGLyHe3SaZCqqXNcTvX295D3U6Xp5YzMsktJfvn+XA3J
         P+PkO0IL7bFTxsQejT6+EAdjkbJ/yKR9oZbYmDXq46cDG7+X7tW6G3EtbkfTcFypepV7
         5p+Pb9/P04snA30741Uk/l6HbjM+Ca6tT9Ymh3O+E7qzhlrrLoleL1PVf/NAWrjidQFf
         oyg4O1SZInQR8c88F7sDFD8qj2nh9z/AgwPM80IlID7YY1LbkeGyCSlmGZcOSoJvi8ZO
         LBayd84ucIPhRrllm1bmIDDNiv116wcdxKhuNGEitrVLoERYnQwGNzavFNPWFB5R/I5S
         ev3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id l1si1178554qkp.4.2021.07.05.04.07.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:07:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GJN9b13G6zZmhx;
	Mon,  5 Jul 2021 19:04:19 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:29 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:28 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH -next 2/3] arm64: Support page mapping percpu first chunk allocator
Date: Mon, 5 Jul 2021 19:14:52 +0800
Message-ID: <20210705111453.164230-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
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

then we could meet many "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
the system can't boot successfully.

Let's implement page mapping percpu first chunk allocator as a fallback
to the embedding allocator to increase the robustness of the system.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm64/Kconfig       |  4 ++
 drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
 2 files changed, 76 insertions(+), 10 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e07e7de9ac49..a4e410bcdacf 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705111453.164230-3-wangkefeng.wang%40huawei.com.
