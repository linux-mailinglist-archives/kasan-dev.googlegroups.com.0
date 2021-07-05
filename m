Return-Path: <kasan-dev+bncBCRKFI7J2AJRB5OPRODQMGQENYNR2SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A893BBBF6
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:07:34 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 67-20020a2514460000b029053a9edba2a6sf23125586ybu.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:07:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483253; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1cj0mkptEBlc2MUrwY4U1T+pmOzZtNw1B6uN1LckUqSEkxmdpF9h8XE+rktY8raeZ
         VvQyWK2DlUPNnFdDc3DDrvUUMzmnmOTy+oi5biLsLQkMjaim8FWc/HOrMeCTCktrDcPO
         iCRhJUHO9OCCWF2XmsqHSUVf22/x0HJw8p0/jypGNjP2BPHPqKIFKVfgTCphpk9OFEnX
         YIBhmMO0hG8+nAP0XJeQ9ouQzDbGvfFc2Su5z7zfCLFAG91SLnt1q5A3X9alFUUg/Jql
         rHiNcU45ggs6t0OtSC17UBwzd0hxvMmdYG5vf9E+ES3ioNslrRt0lp06C6ObBHv5bV2R
         S9cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OdXjonqONU56N44ZwjOsWJaG/L65z+AKwRbj1k3KZY4=;
        b=juGd7Gsf/KXuhOlJLrTAuI1uyvLjOg0V8bgmEZPItlJ412AxzZ8/hvDVWKyb2aGHEd
         youJQBA6BgcyySY4cswQiSS7M5cX7mnnmru3KZ/xJ1WaKULxKm/pk7hmf3saIVj3jnTL
         aTwT6BmyTRRm6TL48Qt1poX3sdqV42ifAGAyL7HPbpbcnB6pKJxcawTbfLxglBPqlyxS
         NQ0AEeHsUIXRNcfvnQJB7cziF0FSb7d5ZceTWUUAsZ6tExfguh/47BV0KgGPDXCZRI9B
         mHZY32VSqo0720rhyOdA0Z7dOtgBmtfB0OS4jQv84sXISibtuj8rH1+QblwshQRW3oqc
         UcOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdXjonqONU56N44ZwjOsWJaG/L65z+AKwRbj1k3KZY4=;
        b=dYsogU6buSU9MPnz3dQzBj+7sRTTcxJr09cToFSYNED8uJjC/8SxtCyxZA/AXMr3g2
         cYWdSD4FlQCReH0EtvwH3qvg0GWmNCk+NBDqVmo0i2M/AWqpX9DxIFk6eepLNOrvEprR
         gI09e4TlapqhGmGNCX9PXnACjhByRnc7oadx+Bnws2uFPm5PvErw9eNCrwvCaWuy7zJc
         pzrpTxhI9pGeerCexQnKG1EVhi96TZAsxqwKh6Rg3EMXJ0kRgPgN/RaDFXJqKmhemrEp
         Ss45Y1K9kWhCIr6OOhMpm0KOruOPNWXtvoABw2h6rntB9V/jcGN0SaTwlwjV+IEbMfXK
         xXJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdXjonqONU56N44ZwjOsWJaG/L65z+AKwRbj1k3KZY4=;
        b=sGgu9oWOLditsVf2G72+V4pFY/9WRZz1BESXP67g3ZUPlVI/BKw7WFlXYT/w0380tU
         mFRWz7pQOIM1WgJrssn0CfGIhgJzROca1/R/Zus5FINIhJqQ1lVWvsiNLm2rfddHNDqB
         zAFRghbcBmeLUB1GCvUS5xp/42x2EDhXMVosaA3Cg/CIa1p/vq5NfBd0IbilEnlV8SKa
         kU/4WnHpQjiW3jU2bItHZVBMZhlmrrjL7sVf+3/qo63YqxySbMgvGQP1tgZ6ZgniGNe5
         oBJRb+duydrK2Cb1EyeTRRDUbgLXS5YuCsupjKkzktd2ILR+3hQJ22AWRvIc0jBJ4woG
         I+Kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gkfLQ0+palXDwOYXj1xZu+PhePrdIEFOqziXvJc1UcMqJh1yu
	vlnMDxPzeVWtpf2ZmaDu2x8=
X-Google-Smtp-Source: ABdhPJybhG1DGsv8sbLPuUKbSQJEAIvw6pIEsBs9DC1k36xhcqau5qDv1+20oqDRUH+uUMCdW2ZuGA==
X-Received: by 2002:a25:f446:: with SMTP id p6mr17510794ybe.288.1625483253137;
        Mon, 05 Jul 2021 04:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3f06:: with SMTP id m6ls3110764yba.6.gmail; Mon, 05 Jul
 2021 04:07:32 -0700 (PDT)
X-Received: by 2002:a25:5092:: with SMTP id e140mr16909770ybb.292.1625483252722;
        Mon, 05 Jul 2021 04:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483252; cv=none;
        d=google.com; s=arc-20160816;
        b=jbE+SWZbhbTc9DcrGA81U0Hx1h+vv5zMHAPmz7ifbx8fntPgokjYFohiuulDQQMxm7
         s121GGs/ZmI8Kn62Kol1yuGv5zcWWDm0yUEEHP8VGWfKtlXXhYO67Zf8bzrKWhnIOnmP
         pQ5NdKkrIETMxtSEc5uZpSOxMLwWqC0uSNvT72fJ93JKYOdVlDNtOrBMoqr6Ron/DEcM
         IWTlX+cpFI40ft/g4FZHYUjiVArzbGBbvI2s+CnscrjWOBGhfMD1PNUINc37pR9mgm4W
         SKbKgFKTh8A5NzmWUngcmOEOAB0MQw0/6u79/NMOOLVHbn2uYZhRQuiePUJxX1Hs+tRG
         IUvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GIWo48pOc4a2aKJUl/6oMAOOjO5MIDqjNBsCd6psIZs=;
        b=vqP33qgKVyyqMx4ExE/YaeT2TS2uAzB85VIfkUZv6yMsd+ESz6G2+7ZX5t5UV6maSO
         QTq2CiJxvNWwUT0dxLaun2XFYlnsCC2pPx+EKbYdsmdhZzGAQhWRaN6n74jOnhOm/3PH
         P7Ce6gTQBaYidkpN0hOG3lRdi74TVHbDvIE8FtHjKlKf4l9KyAFkx5JsoG3pFlJzEALU
         XYJugbLCWFEclqkJCu3s9tIz3d0nAFRTvxoGtkVf0Gi5WkpErJgVtr3nPrwP1JRkxiMK
         1HpiXfmtfuIB+hoo0QcXY2svJD2JhQNbjMOa65rraDSXY1hVklyORnW3SL6Av6v6pEYa
         Eh6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id c13si1630755ybr.5.2021.07.05.04.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GJN6z6RkCz1CFPK;
	Mon,  5 Jul 2021 19:02:03 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:30 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:29 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
Date: Mon, 5 Jul 2021 19:14:53 +0800
Message-ID: <20210705111453.164230-4-wangkefeng.wang@huawei.com>
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

With KASAN_VMALLOC and NEED_PER_CPU_PAGE_FIRST_CHUNK, it crashs,

Unable to handle kernel paging request at virtual address ffff7000028f2000
...
swapper pgtable: 64k pages, 48-bit VAs, pgdp=0000000042440000
[ffff7000028f2000] pgd=000000063e7c0003, p4d=000000063e7c0003, pud=000000063e7c0003, pmd=000000063e7b0003, pte=0000000000000000
Internal error: Oops: 96000007 [#1] PREEMPT SMP
Modules linked in:
CPU: 0 PID: 0 Comm: swapper Not tainted 5.13.0-rc4-00003-gc6e6e28f3f30-dirty #62
Hardware name: linux,dummy-virt (DT)
pstate: 200000c5 (nzCv daIF -PAN -UAO -TCO BTYPE=--)
pc : kasan_check_range+0x90/0x1a0
lr : memcpy+0x88/0xf4
sp : ffff80001378fe20
...
Call trace:
 kasan_check_range+0x90/0x1a0
 pcpu_page_first_chunk+0x3f0/0x568
 setup_per_cpu_areas+0xb8/0x184
 start_kernel+0x8c/0x328

The vm area used in vm_area_register_early() has no kasan shadow memory,
Let's add a new kasan_populate_early_vm_area_shadow() function to populate
the vm area shadow memory to fix the issue.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm64/mm/kasan_init.c | 18 ++++++++++++++++++
 include/linux/kasan.h      |  2 ++
 mm/kasan/init.c            |  5 +++++
 mm/vmalloc.c               |  1 +
 4 files changed, 26 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 61b52a92b8b6..c295a256c573 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -287,6 +287,24 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{
+	unsigned long shadow_start, shadow_end;
+
+	if (!is_vmalloc_or_module_addr(start))
+		return;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(start);
+	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
+	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
+	kasan_map_populate(shadow_start, shadow_end,
+			   early_pfn_to_nid(virt_to_pfn(start)));
+}
+#endif
+
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5310e217bd74..79d3895b0240 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
 	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index cc64ed6858c6..d39577d088a1 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 	return 0;
 }
 
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{
+}
+
 static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 {
 	pte_t *pte;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a98cf97f032f..f19e07314ee5 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2249,6 +2249,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 	vm->addr = (void *)addr;
 
 	vm_area_add_early(vm);
+	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
 }
 
 static void vmap_init_free_space(void)
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705111453.164230-4-wangkefeng.wang%40huawei.com.
