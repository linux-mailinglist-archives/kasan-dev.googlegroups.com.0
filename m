Return-Path: <kasan-dev+bncBCRKFI7J2AJRBRXR3CDQMGQE3NX7I5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DED83CF22C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jul 2021 04:45:27 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id z30-20020a630a5e0000b029022c78a7fc98sf16603064pgk.11
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 19:45:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626749126; cv=pass;
        d=google.com; s=arc-20160816;
        b=IR/iuXZmLe7RG/LNo3w8SQZ5LiSfwX50t6Tnbej1fD6ZNPZFxbFaaXlYInutvt7/Pv
         sdrwqafRgBx2JxsQBSZ4Z27Yhz69Ug/pQtaQ7Pwgsis56h87N1GFHef2zViihj/NxPV8
         sK/Hit99SdbgHs3Nv7X15BihpodJYBHjCrn6nch2PbHeTu027pr2E6swPNP2wpUfK11o
         E4RssCrekKj79b3kssOl05EG7X5l/chuXGKxmonP+xxCQZj/yNcqsGJUaaQ3uaAmS2Zw
         HQooEcWSsFpAJeiSu3W+o84vSg+RACctvTlLX4vfmL5ByDM01Mkr8dPKF3gye5iJBL94
         p0RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RGQMppB79oE8wyx+otedfocjj2tlZyjGUAaM7fVDcfA=;
        b=GOVelNSMxIt2JGEkllFPGgfiR2+SAzxp0odlVcwzHe3sP9Oc/h+EJ+ytcub44WX9ZH
         mnc3DKZjwR4K7WgGNTlvnAIAK3R3yg6Ezm7u7CSrm7SsUBgWRacrhvaBLA879vKuH4j9
         qRXlybTFZK1JNgJ6AhXSx7BJmX8jokccdfk+A4A5mKw3/EVv0WAigXT58e/t6hZhBAcN
         DCAcEqMRnkNqnSDLM/+Ewo/sa11/c3qT8P/+4EK2c6wtl1qZERy4ifzcQvz1Z8fBVxhF
         ltIv572uuOe2bR+go8TAzO98X+kGzRSNjP24G7B2EHvmeswe7CR/7fDaYl+qjojQsh3i
         Vvjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGQMppB79oE8wyx+otedfocjj2tlZyjGUAaM7fVDcfA=;
        b=anXIpLvQdx9nXJvsSeMHlHl74H1CeTBisWyuHIIaEvotmzuQggBB/WFB+HbMRnSftB
         izy7f9Rz3cqA7re+G3BbNtYTLpgV7sEnw+v34rwHQ7ozP6KL90GZf2V48p+0iry7mne1
         nQ0vLdVYQ9erPwGt1aAgN3kKF7F8fZiPpQCxzcHkcEpDvwFvdBWtHUiRECtvW7aT51h1
         BUYljiBGkXK32YgP1Yy2q+aHDopeXfspm2B9jfk8w43Q2T9XoCx5TgprqFDiNyyW023Z
         N0IJXPa6iA2FBCMmwcjSGvJ4HTLUUPEX0WSpJan6m3xlgsN70a0Crc9mGlJVrYvLk6yA
         H+rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RGQMppB79oE8wyx+otedfocjj2tlZyjGUAaM7fVDcfA=;
        b=KOCBaqC9d9DWSsAoRsa6xcRQjlJTc2ydC5aEEYBd74adpmbOoFhdTCCsVJ89qWTe7f
         sQxRLAY+drcRe9nc4YNRC4hylVE8P29UKDcIvjtoTvtkP8a3xffNWOLehyY3fnCD26Qs
         /1PpNLf5YPVDTNdbbgMr4CMFxBwvAba+BhVpOXeHnKZwkdhNiNrIJXOlzX8l1gK7ISyz
         R9ojTRgqmGuyaSUE5I/LRcKg5CkSlubijAAnOzoZQDHeA9YY1G5e0QhC81xb6z63/LN3
         fWJ1QTjoUjMnq+nhrQ+oPGJltHqF0noJipTdWpMzU4n/K9otr9Nyw0kjLSZ8pS3P5b9L
         sn/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FXEiL4bxnGVEqb/oJNsNhaOKLfEuOAuhQAtT5Si52Ac45nCQP
	aFVVTN0ba0d8VuhJq4YMU9M=
X-Google-Smtp-Source: ABdhPJzowX6RJUuDCMmCniZJRRlLLuekqL0cqmgM1NZacXIDjkHbomZQTF14s6KG4VXwVJl+SFgl0Q==
X-Received: by 2002:a17:90a:1909:: with SMTP id 9mr28205377pjg.105.1626749126345;
        Mon, 19 Jul 2021 19:45:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e643:: with SMTP id p3ls10509474pgj.6.gmail; Mon, 19 Jul
 2021 19:45:25 -0700 (PDT)
X-Received: by 2002:a62:e90b:0:b029:30e:4530:8dca with SMTP id j11-20020a62e90b0000b029030e45308dcamr29053717pfh.17.1626749125830;
        Mon, 19 Jul 2021 19:45:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626749125; cv=none;
        d=google.com; s=arc-20160816;
        b=CcKK1y4PIK1XnKaV5LUEwUZW59CHR2OU3qNMYQIz9gz9IrzMVT7kZznU+vn098Q9SC
         knelTpgch+zyBKx4OqPMXydI9Tf0VCjpE84/FoaOY41LhNxba1LCQC7Af3AhFrxLj/LZ
         3Z6AqXfMvPHH9VaJeykbsuoHdyJCkVt7CvkjzB8hi4BBdgBPxZjxQDV7coTM8Ak2DRS4
         cWfE76jQ/xmHBgFr8kCVH7MdLwwqdKIcVS9cJs4q3YB7TuWf8Ckig7jAjDpuloKsQibk
         PoqXvoSvY5t0fvJbbY/EwBW+ND9idXU+2Tz0IkdKvRUY6kASIRr/lM6vNv/BgUQt2w20
         lgwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=6/p5tOl+C6rwWEil80VlySFadESUyDTACQYaxyep7Cc=;
        b=bZcsWWP6Hj0RgbBlTrBQ8qdDXcVXMUV+F6qPt0gCkkrkBVRnn/Az1/fB384u46jusD
         rWLm4kpEGmKbuHHs5ClzzbjfOPFT2ola+dp+2kC2UhySFk6Uuq6lxwyy+pwFXZtUaUXW
         wr9dPUlqddnTj0ydqFEIy6NURtElzBHcJr51FAHb45GYEtMeL/Y/gWYI4rOm/UMI0o5C
         tRpwMXleXzlmxf2NYP3KBgOje15lj2x0lG24uHbeBXLnjhv109PjcJHy9jxDVeelAP8l
         Jmrx4TJ3VAWUCb8leQuKDLLXN038ntYxe9r3duKGAVGEuNMNmOUC51f8+ULm8xJLt48c
         0DMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id o2si185815pjj.1.2021.07.19.19.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 19:45:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GTNJB45GZz7wx6;
	Tue, 20 Jul 2021 10:41:14 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:32 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:32 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH v2 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
Date: Tue, 20 Jul 2021 10:51:05 +0800
Message-ID: <20210720025105.103680-4-wangkefeng.wang@huawei.com>
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
 arch/arm64/mm/kasan_init.c | 17 +++++++++++++++++
 include/linux/kasan.h      |  6 ++++++
 mm/kasan/init.c            |  5 +++++
 mm/vmalloc.c               |  1 +
 4 files changed, 29 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 61b52a92b8b6..46c1b3722901 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -287,6 +287,23 @@ static void __init kasan_init_depth(void)
 	init_task.kasan_depth = 0;
 }
 
+#ifdef CONFIG_KASAN_VMALLOC
+void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
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
index dd874a1ee862..3f8c26d9ef82 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -133,6 +133,8 @@ struct kasan_cache {
 	bool is_kmalloc;
 };
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+
 slab_flags_t __kasan_never_merge(void);
 static __always_inline slab_flags_t kasan_never_merge(void)
 {
@@ -303,6 +305,10 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{ }
+
 static inline slab_flags_t kasan_never_merge(void)
 {
 	return 0;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210720025105.103680-4-wangkefeng.wang%40huawei.com.
