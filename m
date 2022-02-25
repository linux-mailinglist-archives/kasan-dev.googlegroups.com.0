Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBUM64OIAMGQEZSX2L2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2114C44D3
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 13:45:05 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id f189-20020a1c38c6000000b0037d1bee4847sf1503067wma.9
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:45:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645793105; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z9frP1c+WOlWm9fL5wDe9eBDX2Tpa1kiw/oOOLWFMA11QJ9jiIUY0kB4j+YXHyxipo
         1CxW+CE08fOmi9R/jwQG2eda0e658gGlmmutUxKa29NF0PyI1f+AA6yhilv359Ew3cRJ
         wEveE24/B4C1EBMqoCp3TjSxIxangVlSzq5X4J4ZzuCKL1NqekoMS8RRjwY/jpr9Oxjg
         CNT38ZNaotwcyFaNkwwppHCrlOhZihIPJdvT+RszlfyNT/u02QyIC5rVbneUMAC8QfYC
         j31dIOJzYbZahw4a8v6vbmeQrVC72zg0sTeXRpI9TS86QTI91RcnvbJD1ytRvKwI6Xcg
         EJXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=crnMeEvBwRxp/0HkLagKBhTkfonxlhFBzGA72/YcJLw=;
        b=NMs7ZPWjsC8ArjLFIjPZpHmMGC5Yq6Fq/TgMhKO6AtDanBcesNCkDAAvOS9f4xvd22
         +qSu8qZP5M2j1JDYM9CY0CwfBI8lB0Vq9P7vYUW1hdxroOhl3MhmuOhGhrOr5sbVNzQo
         kVOyHNBLx+/HEoDo8McWBxpTYv+9G7ZLTJ8cYSccynLkNmoPSbghZN289B2VA6Nvh11L
         cWjhbdq+JghrYrn4n4iJcjfKezHkz6t96UnMlHbshEPQEWTZvEOmIqIh+ENyJcL/UaEx
         yh0fYGTYIpdQrFfY5HD2CJtjN/R4A9yfxY6RsDDsG/lyEYBV4gL6kqdJML4RN2mOmQkz
         4pyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=bcEi+LRi;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crnMeEvBwRxp/0HkLagKBhTkfonxlhFBzGA72/YcJLw=;
        b=IUjWIdo0sTp5zIUHzgCcyrJcgK5WYMIv302GPNNkol47AMdru+3pVjTCwPDGtpuvCZ
         1jWyQUvM2akFXLgpjdM562TAsDeB9mnACnAP4GHv1/HdNE8ViwqZpU1c6/132ii4HvwP
         hzh/WOyzZ51qQa3o31nOpXFSbha9qIJ565MoiaKpD7IGRrxRDyF+yyiSlPOf6ygBPQHU
         04/ZFucQi6+eaxxZ9VJjdcpAY26k2NpdWf0KFi3jyazkvAQvwJAzgQGe4d8t3JL8EdBo
         uJZmaWEj5Nq+OH0EUf10EkWzr8IO7fDcVNyY+MARQVADic68QI/rgOMSjiyFATC5fm6z
         SQ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=crnMeEvBwRxp/0HkLagKBhTkfonxlhFBzGA72/YcJLw=;
        b=xpxUueos3Xm1Mn9cqwbXnoun8wg9R17Dahc5JqPiHS8z9PnxgT/HyRuoCYVCc/UOYH
         6LPq3cAsqbB5CHn1aANSbsR4qdfOQjkSJnDqRaehig+7AwBSreE0N35+s6bj/MmYFaHK
         ba0kiH6ZRa135gq4bHeWACVrz0ystaISbz7G0FK+qNSWc5+tWlReAPJq3VSx8F4a8/03
         Rdn+7P3u6Kvu6Rv1Xo0W89GR36GjypCR08IaIEinBF94MUFe2Jwi2H79gnUKSXYP6i/X
         TZ5wU0HyAoV8yJZYkYGvPORjlfW6XhFDaiCzMCsIzFtwvf6U9bsQsUBLtAJKhpKeawaV
         DNeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FBEayfnxp5xoMBJ0lQKcPzZZZQmiQxQ1/ADBfaiDG9r/TRuel
	hW3OSU5XRqkE6kel1icaNvU=
X-Google-Smtp-Source: ABdhPJyJF8cbQNDCq0JYfvwRz6+GgRJexenQliysEy7sjme+qfnzHBYUTJEr0i0cOoWmCJZZsUA3/g==
X-Received: by 2002:a05:600c:3b25:b0:37b:c6f3:74b4 with SMTP id m37-20020a05600c3b2500b0037bc6f374b4mr2682192wms.56.1645793105287;
        Fri, 25 Feb 2022 04:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls17490wrc.1.gmail;
 Fri, 25 Feb 2022 04:45:04 -0800 (PST)
X-Received: by 2002:a5d:628b:0:b0:1ed:a09b:aea9 with SMTP id k11-20020a5d628b000000b001eda09baea9mr6158753wru.565.1645793104406;
        Fri, 25 Feb 2022 04:45:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645793104; cv=none;
        d=google.com; s=arc-20160816;
        b=E7lmgyh6Ic8KO4Oyy6zuBc5FspaceQ7HTB/mkpCcW2rjBlGPnYXHA1cAIQv6VxAyvn
         aMSLULm+gITcnHH8mBG0LzGaEWDFccJjr3cuNhjYB0N3lst/+pWW6lysQTU9/Ff584Fi
         cv2YyJAYvnaly4iweAD3HHfyxcH6cA20BtauBlQlF/cSnWufGCc/QM29uwOHeI8zhFVI
         1SWZivogxVPHRZ8vxTApv+yeW/sj1PdFV8O2W0wvgPP0eY9wFNwNnkkd5AuFhnCSTAtj
         p3Idt/UmX0Q6ZxqlLzR4hzEF5h+2xLOVHde5/uBVPZq8VIDl/sj693qWjcuXxu232rEW
         Bvuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=SnSbt9srZ7OcpfO0TO3d0HjnXYX+4WJ6SgK04DiqgE8=;
        b=gAig7V69y7g01fg9nPksm5mxFH4JjDBgcoy9SYOwc9XT9IjeFM8xyJh8+llkvGi6TY
         V1SokuDgULIsLxVQi5OReSAoL1IIo07SK0WoDI7YIMeW/VqP54dThhSJjLxD1roNiSRB
         FNrQEDs4PMV+zQpe/+QDcbdHlFfKq3MNj7N+wIEWwWvUgF/qTthiVg1h17fRiivXIb8k
         WIHHJa8sUHvlz+GfLpFfOVY/toihxesdF6v8qFAcQCxCgY7vbEW3hAqLcYN04d0rxubS
         evNoZEbPTqTXMa3sGxFoFCcj/vVjeiAvzWaiMEjY/2IHqBnKOJbR2sBAQcTcqFKtGjSx
         mFMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=bcEi+LRi;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id i12-20020a5d558c000000b001ea830df1aasi51207wrv.7.2022.02.25.04.45.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:45:04 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id CE86E3F1B7
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 12:45:02 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id ay7-20020a05600c1e0700b003813d7a7d03so461576wmb.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 04:45:02 -0800 (PST)
X-Received: by 2002:a5d:6a41:0:b0:1ed:c1da:6c22 with SMTP id t1-20020a5d6a41000000b001edc1da6c22mr5742733wrw.473.1645793102135;
        Fri, 25 Feb 2022 04:45:02 -0800 (PST)
X-Received: by 2002:a5d:6a41:0:b0:1ed:c1da:6c22 with SMTP id t1-20020a5d6a41000000b001edc1da6c22mr5742718wrw.473.1645793101972;
        Fri, 25 Feb 2022 04:45:01 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id l13-20020a05600002ad00b001ea78a5df11sm2712125wry.1.2022.02.25.04.45.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 04:45:01 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v3 5/6] riscv: Move high_memory initialization to setup_bootmem
Date: Fri, 25 Feb 2022 13:39:52 +0100
Message-Id: <20220225123953.3251327-6-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=bcEi+LRi;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Content-Type: text/plain; charset="UTF-8"
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

high_memory used to be initialized in mem_init, way after setup_bootmem.
But a call to dma_contiguous_reserve in this function gives rise to the
below warning because high_memory is equal to 0 and is used at the very
beginning at cma_declare_contiguous_nid.

It went unnoticed since the move of the kasan region redefined
KERN_VIRT_SIZE so that it does not encompass -1 anymore.

Fix this by initializing high_memory in setup_bootmem.

------------[ cut here ]------------
virt_to_phys used for non-linear address: ffffffffffffffff (0xffffffffffffffff)
WARNING: CPU: 0 PID: 0 at arch/riscv/mm/physaddr.c:14 __virt_to_phys+0xac/0x1b8
Modules linked in:
CPU: 0 PID: 0 Comm: swapper Not tainted 5.17.0-rc1-00007-ga68b89289e26 #27
Hardware name: riscv-virtio,qemu (DT)
epc : __virt_to_phys+0xac/0x1b8
 ra : __virt_to_phys+0xac/0x1b8
epc : ffffffff80014922 ra : ffffffff80014922 sp : ffffffff84a03c30
 gp : ffffffff85866c80 tp : ffffffff84a3f180 t0 : ffffffff86bce657
 t1 : fffffffef09406e8 t2 : 0000000000000000 s0 : ffffffff84a03c70
 s1 : ffffffffffffffff a0 : 000000000000004f a1 : 00000000000f0000
 a2 : 0000000000000002 a3 : ffffffff8011f408 a4 : 0000000000000000
 a5 : 0000000000000000 a6 : 0000000000f00000 a7 : ffffffff84a03747
 s2 : ffffffd800000000 s3 : ffffffff86ef4000 s4 : ffffffff8467f828
 s5 : fffffff800000000 s6 : 8000000000006800 s7 : 0000000000000000
 s8 : 0000000480000000 s9 : 0000000080038ea0 s10: 0000000000000000
 s11: ffffffffffffffff t3 : ffffffff84a035c0 t4 : fffffffef09406e8
 t5 : fffffffef09406e9 t6 : ffffffff84a03758
status: 0000000000000100 badaddr: 0000000000000000 cause: 0000000000000003
[<ffffffff8322ef4c>] cma_declare_contiguous_nid+0xf2/0x64a
[<ffffffff83212a58>] dma_contiguous_reserve_area+0x46/0xb4
[<ffffffff83212c3a>] dma_contiguous_reserve+0x174/0x18e
[<ffffffff83208fc2>] paging_init+0x12c/0x35e
[<ffffffff83206bd2>] setup_arch+0x120/0x74e
[<ffffffff83201416>] start_kernel+0xce/0x68c
irq event stamp: 0
hardirqs last  enabled at (0): [<0000000000000000>] 0x0
hardirqs last disabled at (0): [<0000000000000000>] 0x0
softirqs last  enabled at (0): [<0000000000000000>] 0x0
softirqs last disabled at (0): [<0000000000000000>] 0x0
---[ end trace 0000000000000000 ]---

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index c27294128e18..0d588032d6e6 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -125,7 +125,6 @@ void __init mem_init(void)
 	else
 		swiotlb_force = SWIOTLB_NO_FORCE;
 #endif
-	high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));
 	memblock_free_all();
 
 	print_vm_layout();
@@ -195,6 +194,7 @@ static void __init setup_bootmem(void)
 
 	min_low_pfn = PFN_UP(phys_ram_base);
 	max_low_pfn = max_pfn = PFN_DOWN(phys_ram_end);
+	high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));
 
 	dma32_phys_limit = min(4UL * SZ_1G, (unsigned long)PFN_PHYS(max_low_pfn));
 	set_max_mapnr(max_low_pfn - ARCH_PFN_OFFSET);
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220225123953.3251327-6-alexandre.ghiti%40canonical.com.
