Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTPC4GTQMGQEGVTSBMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C9D0793CAC
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Sep 2023 14:32:14 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-64f5aeb8388sf37057196d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Sep 2023 05:32:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694003533; cv=pass;
        d=google.com; s=arc-20160816;
        b=hITDoM2ElgD9kb0lzfD8YpSTRVfTeaXYg55G99TY3a4NnTmSRcUjKhCcgHEie4sCmO
         fD0vxyGyu5DOWclWlt4Q4QdsCOUh/WtMfHNDM5WPygxFNvz5PN89PsmcX7sNLA1Pi1rJ
         tJlemhe2G5dRybDfChbIaNtn5MSyBXyshYZfbvMKEL8uLd6UryPTtBwIxSwlxDoan+G9
         6wuKrmtCr0QYgs3fXp7EMPdX8eLmCnps9vwOrjJYZ9Hs1+D4Q2kPOQRZZ4gMz7rDhMqF
         9msgBsB6IFSP9xhZx14q9fZzQUz0FifG70s2/EUg7SGtO+urXJF1V2vGaPIXok3qBmnm
         95aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=l2M3l8WFhrjGY38ELPR7EEA5LMslyYrTFnGzpZHXm94=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=QYRXpJeunUjMS6ffrgit+b7Ajw4rSeOCwoC61gaRnDc3CPS+2o8Ftu/EpQ++7enGdx
         SrdCLQapWIIqj47pghPSDKjrdC2B1VkzX9pHsfgk7Y9kPombwZFDCs0jPZCJVciQ9R0O
         PJHI/5YPslpdYYOqKiybJcc/cv0ZYslmDmsO0ob+9fJAyodTgbWC4ECF8/ZppF6BbB1X
         wOx8oqAU/CrBI4BXGLuqU62/093/56nZVxkPN8CWFa7WpD6BhQBhOLzipa73Joa7JOSa
         3PbHjUgLJ6wkguWmGrDeLV0qQu87XLd8fck4Jfy//NXJ7/aiQXsi17FMlbgtFuJc7sP/
         npRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694003533; x=1694608333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=l2M3l8WFhrjGY38ELPR7EEA5LMslyYrTFnGzpZHXm94=;
        b=M2RH1zVin4OcL3vVdOtPc/EUK3DHJnZlr7mnlj15vZXuFfFHKvwxWt87haBsdY1sPj
         3snZ59x12jzKKd5oY8ZTcALYMVBBrKq1DcSd9FaP8lbeUvn/fqifOfYMxKJVlFL/Xe7y
         iOy4aanBdoJqYineqayg7EFES9KvpbN7qKXw/LWfajUvNg8uNnMCkscvcJqCE7kLlWxC
         K6V8lwrkDX3Lmg/1kb9KtVrUEhoibm8Aoupj0MseWMJdybmueZ6YL0G7/8orJi4mzqW4
         7RvhMi7iNJ1NMK5xpcrKx2IEgBwXPBW3Z4Igase0ZxgmdNPgK95RzQxreb0C0NXQEKzN
         jekg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694003533; x=1694608333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l2M3l8WFhrjGY38ELPR7EEA5LMslyYrTFnGzpZHXm94=;
        b=ElbCPzSKgUXaLw/HjatvyOP9RBIrQMddmuX8D6FNf4TZMRM6Uzjvb7ww/FEAtJtpwV
         u4QEfau/HHOqt21jnY34cvKpjdkfAOKu7KDjbOngCnfzAyWDwxqCssgiXIBuhVvapkat
         X04a7xowh7nIQUFU0kh61ySc1FsgbqhWq6egueZHEhBw4xKo6AJuoS8cW0MJBL58H8jR
         xaC28yL7AgHFvk4Ts0wzvG8sPD5J8iMyJKfxYoVqEMKJlsOapdvgUCTSmDyJdDSCLgSm
         q5JP6du/pQNBK5sw7aO48k8+RaZYEBQNqCzNVSoSWTRjCdqyjtiysJ/FzBdYyE3vjXIU
         Vpxw==
X-Gm-Message-State: AOJu0Yzt4tfgJqmS1KrcFmslAD+Q25Nu8dGldKf/6EjSChWs4GWW5azc
	Vpi5i6xmX4FwPp5zAfXizjs=
X-Google-Smtp-Source: AGHT+IG+QEngY56pRAY1SJ67dEzq43e0OWjPhy8RU/hFjWMkhuA1+q3+150PyEYa4XZw5FW5s1Gz3w==
X-Received: by 2002:a0c:c3cc:0:b0:636:e4f:6b9a with SMTP id p12-20020a0cc3cc000000b006360e4f6b9amr15450878qvi.17.1694003533192;
        Wed, 06 Sep 2023 05:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ca12:0:b0:647:3660:dc31 with SMTP id c18-20020a0cca12000000b006473660dc31ls441251qvk.2.-pod-prod-01-us;
 Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
X-Received: by 2002:a67:fd9a:0:b0:44d:547d:7e84 with SMTP id k26-20020a67fd9a000000b0044d547d7e84mr2948137vsq.28.1694003532488;
        Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694003532; cv=none;
        d=google.com; s=arc-20160816;
        b=naMPnQhy+4B0EhqLtT/GGTVIeIs8oS/uJFylh782QdBD8N7M+F0iTg2/FdqusDRtik
         Wi4S17gDvfO7OqbDwhbqCrp0c5QlBIMf2SlmyT4SWNvbDS6OyV993WDRg4WXy9HvN1kG
         y2Cs83qTSMhdBW7/CifrITxzHIa14dZyAXJJRvkobNrXOo5nNAvpuWqnI4Th7JGoX1Lb
         WKtZwTQMHvpxqAEZ6wH2X5NZ/GwZb4y6VWAvVPFC2s1BAoMn419hWUMJNNKM97D+ANlJ
         PuRx+2hLfgJQXQocOpPoRQe6zUCpVzT5bw8vF1dDkR9X0j4tGkodRwdMLzBXEQKjRe1y
         3y6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=YsHmY5hkpTTrJQqvQfSH4rSGK0inQUOy9GMYacmc4e0=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=v8gFN1ZaEMK8diECoGJmq3u9goQgQGvsy7PIYCAjkDY1TUWykuvRzrvuaD68WHvGkL
         wl4QmWTMMZyJSIvv/QhlxIYD8HAvUkNrUGBLKlEoi77tMXOrh+1FQiLbwMmZ8/n0fYVf
         LT9kggM+5BL8WrEd5xvQL0MeDyfTBA3+WpF7k1OfBC3QEqUmnEg9GjEdaB+OCsMKzh/D
         57fOq97K1pug7HREtrsYzP+BUntxlUo4vKLEUwjGTRy5vOC4jzqT5mnOKIEuTmsTKof/
         az/x6xacG0z2BzEPLFJLIDvAcSbCH2LjIAMWM3LXkP05Zc4B71myIuR0OtNHZAZYanrv
         EUbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id j19-20020a056102335300b0044d41076eedsi2103221vse.1.2023.09.06.05.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4RghXr4FGFzrSb1;
	Wed,  6 Sep 2023 20:30:20 +0800 (CST)
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Wed, 6 Sep 2023 20:32:08 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock() in kasan_depopulate_vmalloc_pte()
Date: Wed, 6 Sep 2023 20:42:34 +0800
Message-ID: <20230906124234.134200-4-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm100001.china.huawei.com (7.185.36.93)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

There is a similar softlockup issue with large size in kasan_release_vmalloc(),

  watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker/6:1:59]
  _raw_spin_unlock_irqrestore+0x50/0xb8
  free_pcppages_bulk+0x2bc/0x3e0
  free_unref_page_commit+0x1fc/0x290
  free_unref_page+0x184/0x250
  __free_pages+0x154/0x1a0
  free_pages+0x88/0xb0
  kasan_depopulate_vmalloc_pte+0x58/0x80
  __apply_to_page_range+0x3ec/0x650
  apply_to_existing_page_range+0x1c/0x30
  kasan_release_vmalloc+0xa4/0x118
  __purge_vmap_area_lazy+0x4f4/0xe30
  drain_vmap_area_work+0x60/0xc0
  process_one_work+0x4cc/0xa38
  worker_thread+0x240/0x638
  kthread+0x1c8/0x1e0
  ret_from_fork+0x10/0x20

But it is could be fixed by adding a cond_resched_lock(), but see comment
about kasan_release_vmalloc(), free_vmap_area_lock is to protect the
concurrency, so it looks risky, any advise to fix this issue?

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 include/linux/kasan.h | 9 ++++++---
 mm/kasan/shadow.c     | 9 ++++++---
 mm/vmalloc.c          | 7 ++++---
 3 files changed, 16 insertions(+), 9 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 3df5499f7936..6d85715c47ad 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -385,7 +385,8 @@ void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
 int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
-			   unsigned long free_region_end);
+			   unsigned long free_region_end,
+			   void *lock);
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -400,7 +401,8 @@ static inline int kasan_populate_vmalloc(unsigned long start,
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) { }
+					 unsigned long free_region_end,
+					 void *lock) { }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -435,7 +437,8 @@ static inline int kasan_populate_vmalloc(unsigned long start,
 static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long end,
 					 unsigned long free_region_start,
-					 unsigned long free_region_end) { }
+					 unsigned long free_region_end,
+					 void *lock) { }
 
 static inline void *kasan_unpoison_vmalloc(const void *start,
 					   unsigned long size,
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d7d6724da2e0..4bce98e2b30d 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -416,12 +416,14 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 }
 
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
-					void *unused)
+					void *lock)
 {
 	unsigned long page;
 
 	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
 
+	cond_resched_lock(lock);
+
 	spin_lock(&init_mm.page_table_lock);
 	if (likely(!pte_none(ptep_get(ptep))))
 		pte_clear(&init_mm, addr, ptep);
@@ -511,7 +513,8 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
  */
 void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
-			   unsigned long free_region_end)
+			   unsigned long free_region_end,
+			   void *lock)
 {
 	void *shadow_start, *shadow_end;
 	unsigned long region_start, region_end;
@@ -547,7 +550,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 		apply_to_existing_page_range(&init_mm,
 					     (unsigned long)shadow_start,
 					     size, kasan_depopulate_vmalloc_pte,
-					     NULL);
+					     lock);
 		flush_tlb_kernel_range((unsigned long)shadow_start,
 				       (unsigned long)shadow_end);
 	}
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 228a4a5312f2..c40ea7d1b65e 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -1768,7 +1768,8 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
 
 		if (is_vmalloc_or_module_addr((void *)orig_start))
 			kasan_release_vmalloc(orig_start, orig_end,
-					      va->va_start, va->va_end);
+					      va->va_start, va->va_end,
+					      &free_vmap_area_lock);
 
 		atomic_long_sub(nr, &vmap_lazy_nr);
 		num_purged_areas++;
@@ -4198,7 +4199,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 				&free_vmap_area_list);
 		if (va)
 			kasan_release_vmalloc(orig_start, orig_end,
-				va->va_start, va->va_end);
+				va->va_start, va->va_end, NULL);
 		vas[area] = NULL;
 	}
 
@@ -4248,7 +4249,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 				&free_vmap_area_list);
 		if (va)
 			kasan_release_vmalloc(orig_start, orig_end,
-				va->va_start, va->va_end);
+				va->va_start, va->va_end, &free_vmap_area_lock);
 		vas[area] = NULL;
 		kfree(vms[area]);
 	}
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230906124234.134200-4-wangkefeng.wang%40huawei.com.
