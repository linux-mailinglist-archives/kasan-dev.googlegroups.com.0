Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTPMYOEAMGQEZDX2IEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B2E83E42C6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 11:33:03 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id na18-20020a17090b4c12b0290178153d1c65sf17459059pjb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 02:33:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628501582; cv=pass;
        d=google.com; s=arc-20160816;
        b=bSlysfxxd4dVk5c/cDu2cEd3TK86oGu4faXnap2IAoyhIVv/9Z5XO6Z4f/US+rtivq
         DqD0vE2OzGwCCCUvu5owx9tBkzTARuhf/XDuq3gnt3V6xbeXFRJEAmWIxSJn9LQMdvz8
         BHamgzwoND+W2PDdgGWHFkHj0+oMQQl6m63uC04XlfhXTv0WrY1iYiCQaV7w/rZI1fM0
         IsGsY1ry9TjL2JYGIQOK2Sz3H48IW8CUh5gJvhGOUeRsz+jGDha6e+krlC0BxzvSreU+
         Vmr4NGzLDXWjR3j5v4BPpAUqrcgtRckjfCUq3dUxgcV7o+MKtsgO2zEBieO/zpaE2mQu
         7bkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NPc/lB3OpPuLxxBXJAz5RtGibTwCMnHjQnAI6415xrA=;
        b=hIgzQmKmRV79hNnWJl5Qqnxxq1Tgp09kqhGmrIaPuO4hq4oJtFScotyfrRKkQuz4Uq
         EwMKEHHwa1cg12qHEmAM+VAWa28dFFzFw5GOz8Sjc6/HLz/00dfG73zMnvUbHCJqwztu
         AC/DAE2lhfIgx5U0yj/HkQKg82gHghjX50nN1ePbjwwDGLdQRBzEVrepA3m0oNQowBy4
         rqUL8lxYzo4UvkQLpoD6Qk2T0QKCSoVTgbvrGcJhshqh9lvhhvfL9R5a2rYztQBCvVUF
         nNQWir9X47vZgiS9aWz/FtuxhUi9osaYzPQNVC2Ep2KalgMweUNWcCq0x8nS5Y+ybEQV
         P/+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NPc/lB3OpPuLxxBXJAz5RtGibTwCMnHjQnAI6415xrA=;
        b=R69LkQ/pJ49f5O9QVpvlG2I/jaCHAE/41kn4Wy7k8IU2m9kC54Sy7t1EZB4xJYFQI6
         dNlFkb+0P8XzCdEfMVj5U1M6b6T0zrIF1dx/mJKcWVfpM/tLeUQHhpCg/GJTt9bpfS/f
         2mDdsSUeQsz82+YrHblpbShLdyW7+nUGiZTv+U5NczAvarIWj8A84i1hnrlddxkE5XxG
         aUqVoquUhDDwph9gjln3eqiIDlZ5fljNixsB15XmZEzgQzQHucjM1dpDoLBuN8/Jd0MN
         EsKuTnu1ge/xgFOmquR9KzSMvvS1emgodQy60l27+C0qDBVz/bDcstL1q37M7AFimzNE
         kWxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NPc/lB3OpPuLxxBXJAz5RtGibTwCMnHjQnAI6415xrA=;
        b=f9XQvmNU1Cp4YkIrJcmwSzsCtKYjhUmhuQfIMPSuNsR0BuskCpELtzonNUVIrEL/hm
         GpFoB1V0wPCmDICSGznQROHwK4YXVSb50bJHLfYbtDD60AdfORbPlVoTyKJZ1/o8HQOm
         bDG2WSF27oJGsyYR6Dm0wR8ktkkJguDux6thypyk8MXjxmHUa9HgaQqZcqrZ7kKPUZCt
         wGGTBQ1uqoXWb5hJg+3Bnl3fj/NquRp9xkkw0baqDwbXdw6HnJVSDPiwMruUAMOUjbQ5
         Oh77xp/oC8q3FztUojdqn7iLwpixRAgmPq//VmmYCImX6zLEFA6q5VysCwAspIdoBnab
         ml3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305DkAG3mdh8oNOp6iUggIs5yKN9Xa8Uhlrmq7qp3uUCYRVrBER
	2Y+YP8Xt6E4d7QwlLeuxCU0=
X-Google-Smtp-Source: ABdhPJyrXYAZRRzamQyIDiuVtKWb76Svkml7vApnX5l7OeXQj9Plbo2zkWnlf2VMGMWancIgNIg35A==
X-Received: by 2002:a17:90a:4bcf:: with SMTP id u15mr24165687pjl.62.1628501581905;
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5c1:: with SMTP id u1ls7307642plf.11.gmail; Mon, 09
 Aug 2021 02:33:01 -0700 (PDT)
X-Received: by 2002:a17:902:e786:b029:12d:2a7:365f with SMTP id cp6-20020a170902e786b029012d02a7365fmr9308356plb.21.1628501581351;
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628501581; cv=none;
        d=google.com; s=arc-20160816;
        b=Zq5FLtezTXAaC/qQPN5wCZZVwNSA0Zx7IAWEVTAN94MKYerNpYP/UID7ej8Ser6S/W
         UEbpUvD2LquzOBLD2L5gbdlf/dVA2xVY484V/tkgiUhU7qv+n+85WaXjbv2Uqj8gXhjQ
         PJLS8CpCXYS5Oo9HjW0TOdw+oCKIQYNTl8PN6IG42p+gOqYg+bbdxqcL6ayMgKlFRNVz
         +jvA9RNqvmC66LpMXpEXr5gWx4Eo8RvizCZJe3NbeM+hjD/duGvAg66WiJkend5hiGo5
         PLccIXS/TieFzRda2TMK7ZGdpmaoar1N5vbjH5vmJ8ZcK3DiGG/orI8CxNQiie2RdhfD
         8/sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=e0lSNQZPk0uzXwfCsZaHqJ4toDeDmOz7+pHqToLiDW4=;
        b=WzFOhTaucOXEGKR6G+nJPk+1KVhcXLRjti7uknCJJbRx4L4VFCWspQgcf9SmyBWx61
         Xdw1KHLEKjT0KV+brqB00CWwUZ4n5ZItqsEdi/5wuA2yuHFs0mCBj03sqVBpKFyLWg2e
         oG6EBaHu2X0H2BkUFzjBMnXVJqzOkHrsaeiXus2S8GA74IeatOA7rsA4sYl6qBc6NSMJ
         bBaHaltJbQdRfY+SxFgW5bOh2kM98ZiCpJjkQhpxRjs7/QyJuYmnld5WIKk70PugmAAG
         zMgFa9q29ExFAYBePwinXmqsoOKVqVJVlf/SYhOJ71w7KZ7TFzB/zYLbCiU0MC+KlP6e
         1ZKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id bb19si56736pjb.2.2021.08.09.02.33.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4GjrTD16kVz1CV1f;
	Mon,  9 Aug 2021 17:32:16 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:28 +0800
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
Subject: [PATCH v3 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
Date: Mon, 9 Aug 2021 17:37:50 +0800
Message-ID: <20210809093750.131091-4-wangkefeng.wang@huawei.com>
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
 arch/arm64/mm/kasan_init.c | 16 ++++++++++++++++
 include/linux/kasan.h      |  6 ++++++
 mm/kasan/init.c            |  5 +++++
 mm/vmalloc.c               |  1 +
 4 files changed, 28 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 61b52a92b8b6..5b996ca4d996 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -287,6 +287,22 @@ static void __init kasan_init_depth(void)
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
+	kasan_map_populate(shadow_start, shadow_end, NUMA_NO_NODE);
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
index 1e8fe08725b8..66a7e1ea2561 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2253,6 +2253,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809093750.131091-4-wangkefeng.wang%40huawei.com.
