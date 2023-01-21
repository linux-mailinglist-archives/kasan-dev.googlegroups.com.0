Return-Path: <kasan-dev+bncBDUNBGN3R4KRBGNAV2PAMGQEW6FGDXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A2E6764E0
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:22 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id cp12-20020a056830660c00b00682cd587d0csf3467221otb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285081; cv=pass;
        d=google.com; s=arc-20160816;
        b=P4DTx7Y2lWAne7p6ME8dEcz27HF9b1wBx1Ufq4t+kCZwxN2+Xntxl1Zw8iFr0B5exD
         H4RAXkTzFblRyuU3snvmbQS4/02tE1OipaPQLSgQBfTQHllPU5oTbZPwVXX6FS9GyS/n
         bKRBpBhHrH1sr5JQndg2UVBUj4QkG+srYeALlq5LHnsxsn93w/FjJikII2DUXuD/8qua
         T07eFzPPIJ8Lmz/WwW4T6teqATt+awOuS2CSsX6iUPEsLBaIB32/lGX8+LzULEsl8aFa
         sF31uCDky0nbQaNvmq6PpbTATUFdCGG9tiWfD+0QXQdGYklLPAF0BHOWhXW+EoggtD+0
         vo+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fXh/YBQjOE6/j21ZQsnHydt/qlR6rXsndOCgEDmrVPs=;
        b=ZOAtplG8WankvqMyRU6BNSZ546pezlSlmxoxcXmw5bVkArFzhL7FkJk9mmyQCTQliV
         S3vWAohbwMYWQWAj8LgisTtGhs9zq2GkzYjaD2HGiEtulF+bCbQ+SDGs5o/MC2PPmHra
         xWBYVCYLQxSm3JObiN+qsIKVslh0G23xR/2YQtIBaDrta2SSe/AlN3bTaOi3mlmRUMfC
         KaPXpujkHSjxOO8BqWbJaeZ9shJ1d7C88WMEJWQoOYyRNXAgIa7stWmDbwVB7mUa+6gp
         qaQNY9Dw7OHscYA6dae1MjObZexrcFzfrZwejtkPD+gLpETvh9rBhVbcP0tdpki95U7u
         PkQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=1nYfA6Iq;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fXh/YBQjOE6/j21ZQsnHydt/qlR6rXsndOCgEDmrVPs=;
        b=nSQLyxzOMd6L8NXR8Smy3iGW0+/yPWZCYFmWJHjiMYmzGp1p++OS2ulQm0FDOZzyij
         q/u1Gy4SXx7tn8smc0V+ejA4AoYSFtOVn4G0yHJf+sUeH3YzgHVXaj9f9qEQZg1S9d0q
         axyAzTCHHt+Lvc80AKeSKcVP1zjePRiFLfqZf3sqnVS4DqrsU0+Y6YAxR8wj5n5tiWqg
         1dYBKG1A3P3tg5kJLR2Z+9yFdJoFcYwv2Onb8OQM9UokqoZirTWVwIV6kUmAVKI/BkJo
         9WTrVAu9sBimEn7Es38QKKpQUh0Tl0Jtn2E+E2xZGV5ZrM4rzBH44qIzFa3SRU8U4HD0
         WTuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fXh/YBQjOE6/j21ZQsnHydt/qlR6rXsndOCgEDmrVPs=;
        b=CTtoTsmen4FbjexHDJ3Kf4dLABI6u+0R5EI2hdpRX9LC07sBhBg2PHVhBcUIelx5RI
         m33IP60LGsotL+wG39ncjqp1ix4NuuEKWZVH3S9svyJxW/SX1bF0xdBEwK/2hDMBHj8t
         tDydmEfXcNColURAZSRYhwrX7QNO534Sn8oRP9nWMWdX47Bo+FZnlSpWaG3NulVkuSVW
         HxMa/tDJruwFy9gy+c6dW/KRE6nXxNjfsdlCTCZjNFIPPvU/h0aDTqaK72fYkzVLi7B1
         +YhoU23JYHo75MaUQrU/t1a6NvN+ELdJKqJlnUI1ggwmjwIbESJMQ4BZdUz7pxlIsHAv
         9KYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpFrKOY6HkkjpI1Ld+lS6dIKaWTUIUWVn+LzUYbUq377915HIfN
	RINBzelksiBQoYw1w4OVW+s=
X-Google-Smtp-Source: AMrXdXsYhldWls2iw3iRsOorl9zfTqTJ/RkoZvx5wB4gQoqZeEbdOOHqR3CV/dQRG+6EqAfUkDXoLA==
X-Received: by 2002:a05:6830:3289:b0:684:9679:acb3 with SMTP id m9-20020a056830328900b006849679acb3mr1086706ott.79.1674285081537;
        Fri, 20 Jan 2023 23:11:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b143:b0:15f:b75c:fa2a with SMTP id
 a3-20020a056870b14300b0015fb75cfa2als2268891oal.1.-pod-prod-gmail; Fri, 20
 Jan 2023 23:11:21 -0800 (PST)
X-Received: by 2002:a05:6870:1609:b0:15e:ce8d:f65c with SMTP id b9-20020a056870160900b0015ece8df65cmr11276065oae.23.1674285081009;
        Fri, 20 Jan 2023 23:11:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285080; cv=none;
        d=google.com; s=arc-20160816;
        b=g9ef9s4A72TUxUlbjVrjstMDDR/HdUBQaD+7jSRTOehYIPsvlKW6eM+YJ0igAocXDb
         LvsFRMcXyFA77HiSiLZv0/K8dhIKoErnQY81yGa3Dm66T2aU/FBbQEk+PyNG2vnGfSGO
         OxkaQ3ORgPwqyIUDKErBHGXFxlofbUI7og7wfTsKNNpqOjlcKGDLZ27nOHxjIC+yzxxW
         Hx8BFI9YvfA9gOndlAaY6G8b8PDwBGxNpPX9KhCci4zS7Rg/xRrWDH8d/v/Ka8K+Davg
         0yZhu7QUNvYDq/nHyxRwgA4961SGHRUTwuZE/klQbQI/NGjc8MhKB9HX09GjdaIpy9Wt
         uuEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2AhZtCg8WcctCTduxx8cDUSUIZL38/xwLWyYwxGa4ko=;
        b=faolIbLDi2xSCaqwxierlhAJwdfi2wF7bJi2AkufaRRGw6N3vGT+aZQIkCtSn4HrdN
         ckx3FOdy/DiiTD5R88J9wPrpd8lCu3FrsCouBNKFic/aa97VuBFNcXg+86n+egW8qaWr
         7nuqfk4Jc7OcCmabIZ3LLxjimRM0pNdcN5a4rFp9BLxP6B5D0OaiRKvVlm+moUa28TWL
         PwU7XPH+W7+kB+FpVR2tBjKcM4Xq0LGMR3hmHG2j5A4+y5s2yFK3XciH+M2k95KpwSuC
         VEekFl5AwuY+w2mE34+ZclU53b2gLTfASOy/VzkvHFVPYV/81SrDrRmXdmGBMZyr3Gb3
         4RoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=1nYfA6Iq;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id u13-20020a056871008d00b001480308ea6csi5204298oaa.0.2023.01.20.23.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:18 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81y-00DTre-Kp; Sat, 21 Jan 2023 07:11:15 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 08/10] mm: move debug checks from __vunmap to remove_vm_area
Date: Sat, 21 Jan 2023 08:10:49 +0100
Message-Id: <20230121071051.1143058-9-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=1nYfA6Iq;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
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

All these checks apply to the free_vm_area interface as well, so move
them to the common routine.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 97156eab6fe581..5b432508319a4f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2588,11 +2588,20 @@ struct vm_struct *remove_vm_area(const void *addr)
 
 	might_sleep();
 
+	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
+			addr))
+		return NULL;
+
 	va = find_unlink_vmap_area((unsigned long)addr);
 	if (!va || !va->vm)
 		return NULL;
 	vm = va->vm;
+
+	debug_check_no_locks_freed(vm->addr, get_vm_area_size(vm));
+	debug_check_no_obj_freed(vm->addr, get_vm_area_size(vm));
 	kasan_free_module_shadow(vm);
+	kasan_poison_vmalloc(vm->addr, get_vm_area_size(vm));
+
 	free_unmap_vmap_area(va);
 	return vm;
 }
@@ -2664,10 +2673,6 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	if (!addr)
 		return;
 
-	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
-			addr))
-		return;
-
 	area = remove_vm_area(addr);
 	if (unlikely(!area)) {
 		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
@@ -2675,11 +2680,6 @@ static void __vunmap(const void *addr, int deallocate_pages)
 		return;
 	}
 
-	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
-	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
-
-	kasan_poison_vmalloc(area->addr, get_vm_area_size(area));
-
 	vm_remove_mappings(area, deallocate_pages);
 
 	if (deallocate_pages) {
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-9-hch%40lst.de.
