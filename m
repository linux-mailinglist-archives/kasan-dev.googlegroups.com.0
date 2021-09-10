Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBO35OEQMGQE2JQHUQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 547F84066C4
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 07:30:46 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id k3-20020ab07143000000b002b3108e6dc5sf528156uao.4
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 22:30:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631251845; cv=pass;
        d=google.com; s=arc-20160816;
        b=gaB3Rr1BqBssOUt7GcjX0heXhHX+UZwV0/xHwcIokoeIyDVvg7h9psiDzsH9m1ga0r
         Ki1oBvKv6/WF+QvWzqD73A40VHE9YjhDNbmaBqPciYlJbrfAMB0tXQre13HreE1M8Dev
         gsc25fE7N40W6q/cn4z+vYRXowCSM/GAfu1ADNb5/JXyMLtoMnjao7F4P0n+TQzthMU/
         Cy71i1ai/GfnANy+we71i66Sv9J5evpqYJcykUc2ERLWBB5DVqkf4GfLUNl0NeVW721J
         tYGDpuaBctu97rt566a4S461z8TsZqrMSUGBCC2TLziVQzUy4At4HOddBZi1dMS3RZkv
         dspQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zYNVeOm1wKJEEjwaUhWHTqNKFFV6WZHjQ4RSD+LLpkg=;
        b=HsoZy2cffn8bx3Op1SbG8Lb1QBtqdfopWRo2K5N9aUK51/7wD0TMdmiF4/1EVZbWWq
         rTJOwWhB5BsboypH0iDEpjgJMqMTt3gqFhtikuwoawNYX0uGOHmTTMyKbmZncP0kI+vp
         wRq+9xENZ486pMgqg0Lmqr53ND74IfUV98u7YRynw0a86P3UkbKbwh7+YDFBEeGWb1GW
         MxOtWt7bUb1dA9MYe0TKiioGOlFppDQ0M6wYTNjiTWzodhty3kucm/Tjzl2onQCQF/Z5
         h/t/g1DSxZX0N0PnUs9NfhHc0+W/T2UOplAeEC9eLBoJl7FnTDETXw9V7sNNMvEWEqn0
         lnIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYNVeOm1wKJEEjwaUhWHTqNKFFV6WZHjQ4RSD+LLpkg=;
        b=gnk8IzH8F4pJ1ZiLYbl/IcY8GYCZ7EKP7HJBjLaWHK5USp+dkcY/jgOSnnDf4uRqq/
         n76vnZwsiF0hs4ZtDNwxkYZPMNytbLjjkFg11qU2ir6uF8iPJSBpJJ4BKIIujvrG809e
         QsPsGOA4No3NrpFVMKViY9YAuhh6N+HW+1gjSBfkxrSpvaRU6rcHsMi724VyNp9V2glr
         upU29ocIoexE8/rex+padiGIXEeUbWP2BXFWOys4xYBFOVfNEq0WX61ocSPojsfiLQdz
         UG5L4StAXFHuuPX16N5RnlS2NYluvpPzyWUK0bKZ0jw4kCY2OWBsDvWesRSVTVxUj45A
         KfQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYNVeOm1wKJEEjwaUhWHTqNKFFV6WZHjQ4RSD+LLpkg=;
        b=xkKYf5aE5qeS2FO4moyYDLnzLdGVJq7BxZ2EcROh675VaUO3nZTYC+Mcd9OZA3z5s5
         PmCScM7mKA3DCmUAjoF1YwYs2+roEWg1BC40Uc959eN6Wsyr6VGgAMvlWdtfDW3sNMxg
         51rHKCBaykyvp08eOa9lLeMkHcHILdCff65eoUtcRbvhzy1fdjFk3WIOZkvrG2J/rV2u
         Uu/PWdxXVmOrwdQabGI728Upnt0T1tBqeyTzwIJqN5Dk214FR+U9Jo55Tp7nG0v1jDtM
         30JLqyuvn1Cxl38Px5TUE+fgKYCn8AoRlCnOuQ7EmZsKFBKkdQ9Wm1id91BUmUDLBDf2
         z4Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AYdi2Q0BuKaFgbRxZd7fKLtcM7DjM0LZf6AeHUa1jHJSKqwk8
	Tg0Ijhr+hn3w/bXYkSau27k=
X-Google-Smtp-Source: ABdhPJzquLZg5Iq9AAjx2tj+xWdTZDrmtunuAUy+pEq79T1r0CPa4L3m47NmPoeK7DUvLAvN+ag3bQ==
X-Received: by 2002:a1f:3095:: with SMTP id w143mr4457193vkw.0.1631251845396;
        Thu, 09 Sep 2021 22:30:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edd7:: with SMTP id e23ls801866vsp.5.gmail; Thu, 09 Sep
 2021 22:30:44 -0700 (PDT)
X-Received: by 2002:a67:cd91:: with SMTP id r17mr4728651vsl.20.1631251844863;
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631251844; cv=none;
        d=google.com; s=arc-20160816;
        b=UVZm/Z5lVKZbnvC0bAg8+LTeEr9GV5NRVPEP+35/UinF55yJCzSU8s4CcFkji/Vkw+
         XVUmBnmF9yNDSLNJ6MknubZqHsviIXp01PJPZDpoxGuGn2ubdcOjhoJHK6Akrg82MKoM
         e5uU4xrc0Vt5Uvu5ro78FfQDubHhtq71NMFnkBKdMLykKn4BtVCV5OhiTcZuU0/rCtSb
         KAdSX8jf/CIuFTJmY1+5VNIPDUR4X+weLonWgnUfOSsMfmFFNCD07Hf58zTsbEs4Ty6H
         hoVm/qeKJWtBNa4hMrNEfCd12sAGrzl1pgcu4XYCBeJpfPGrc77W4uFS+R4a62WcVVPs
         nWkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=XXd5DTK2QvKz71FhyrC61VMgaoSD/+g/iqKjrSCfKIk=;
        b=PZ3QW+UG/gVpepLuJ5BqIQZZJu7OYsgUrW29JIMIi+ZW4DhXgBCgAp3KG5o7x1VF2a
         By/Aj+zIDT5wt5q2gAkYo2qAof3wro+Q1I24TOYkbIoc91YGVbPci1ATfMzrCmnpsZjM
         GN+IixMtwYuV5WKUbYZsCnYbhXqLOwkE9D5anI+xzw6LCOAELOcaK8NvwywjDp+CMaos
         DEQva6Jz5hZ2U+fqUwtDDUcQH3fjwj0X0ITxXokOiYI39B8pAwgxToGTuk5DuwNeup3b
         zu1PhpaKFDECZNGywYPCcHYLRs3MmpddZB6PE1bdyEH41ABgx8UPilQ/VbXXsaDMyu5Y
         2Org==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id y23si349830vkn.1.2021.09.09.22.30.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv711-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4H5PVV0SBnzR2TJ;
	Fri, 10 Sep 2021 13:26:10 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv711-chm.china.huawei.com (10.1.198.66) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:12 +0800
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
Subject: [PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with KASAN_VMALLOC
Date: Fri, 10 Sep 2021 13:33:54 +0800
Message-ID: <20210910053354.26721-4-wangkefeng.wang@huawei.com>
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

Acked-by: Marco Elver <elver@google.com> (for KASAN parts)
Acked-by: Andrey Konovalov <andreyknvl@gmail.com> (for KASAN parts)
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
index dd874a1ee862..859f1e724ee1 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -434,6 +434,8 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
+void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline int kasan_populate_vmalloc(unsigned long start,
@@ -451,6 +453,10 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) {}
 
+static inline void kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
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
index 5ee3cbeffa26..4cb494447910 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2287,6 +2287,7 @@ void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 	vm->addr = (void *)addr;
 	vm->next = *p;
 	*p = vm;
+	kasan_populate_early_vm_area_shadow(vm->addr, vm->size);
 }
 
 static void vmap_init_free_space(void)
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910053354.26721-4-wangkefeng.wang%40huawei.com.
