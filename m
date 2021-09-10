Return-Path: <kasan-dev+bncBCRKFI7J2AJRBA635OEQMGQEHNYDQMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id A58A74066C2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 07:30:44 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id bh31-20020a056808181f00b0026d71fa022csf646881oib.9
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 22:30:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631251843; cv=pass;
        d=google.com; s=arc-20160816;
        b=kQKysAIiOp9BlSowX5mxk+CbM2bq9pMPyWQj/D21OODz/s8L/KUqs9WzLbpn2eEzcX
         D7Dry1/U+XzOf2tegtB3ZPyk6jLZ8SGM6TUKOud353bGokccbFOwHzjBXrfdlpXw1ZRe
         d3ltzT5Zph1UOUvdok+ZMjVudwGd8sjw572IdRBQ9z7Woz1+h5vLMUTjp/XSTK+mZ5Ix
         BIsXwROgDoh+fwFxJogjyfAc4/sJIZAx6e0Mwc+1pC4m0nEyBxaBksDlqbKnnrnjtEjE
         cXw2eN2X1mF3Kaom1WvxVwYnq0FLxRb9kZSUPKS1HnSJOFagjSVJY+W3CksBX7O/fYtm
         Vpgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cbM2VPaD6N6lafVaVIsUv5Q4+TE0ofBjqgtpWZV4t/o=;
        b=jRnNaFLed8Em5s8QD+Q2uobZnKPbY36uAkvhZA6vtbmN46b9TVDfezoYwmLYOQMTP1
         oSHRRYqss/Qhw8nJ3AU7wN7JYAO0rIHR0XgWIKwEuW2JpntlWTJ9C0O+TdUgVTRMe8bW
         8Q0F6ioSe8q8gDkgxFxVjHaNLb5R19SDaEW4XMg1vXYHoazzCWJXmtFBBXhrUWINNgwS
         8OKUKc717ok/HL90W5ks2Skdrn+Z0JaHue0KYklkZWUsMZJMC0mgJ82LEH0mPOo+nL/W
         CUg6IKkjS6ImwW9mvkjfn6kH//wxkFbxf3Qt7v647Fz22HmuzXWh6hlKyDw3QTGltr9M
         35AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbM2VPaD6N6lafVaVIsUv5Q4+TE0ofBjqgtpWZV4t/o=;
        b=Al6bFrxTs5ngZdomXOKF2JEX9fzd9wOZBtxaWAad63C/0yJ2PGEqpoGcvAT6mjQ9LB
         p/a14z+0+uH2LshzhbknnWBbi3QJhqTEWKA5kestpjzg+XMSDrsHU0tRxklidMFXoa+b
         AYClJ61YmMPpfisRk/pb4BlzaMtb7p9twgpPm9EQXx3z/N9/fC67l5PUTHSonCWOy736
         a3afwndmzSyb6OQJV/ee2U1Cq4JBrmCAr+ljM45LK9zjcnOR0cHvFpfTc67F6YWcfrNL
         i+fP1OgxkaF/CewmqFRo2763votxpP5qo8wEjOVmQFkrFk5uMFYppEYJNwpCXvp+UhqS
         7bAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbM2VPaD6N6lafVaVIsUv5Q4+TE0ofBjqgtpWZV4t/o=;
        b=etkMrndsnalWqAY0+WOLW4n6qpyRsuTV4ntP/vRX8bQeoSWai/PIDJ3tJD/bgZmv6b
         1a8KEV06QOfojndEXDAG18VJm3D6iWG6afhYJZ56s/Smw4gPnTBn1UVV01zeDsHaSmi8
         kWr3RLKwFgocUyVyjAKFW+OEr/PkBhEqHh2CF+euEurLoy99TBBl5mxovH857kG5XRuk
         uHmr9ZBYk7B37AXRP0UxEmDTQtsw9szWtZgvHJUBhestUYKyC5pROqLaaR4ofmUsprIo
         0WjuUug+uS+Krrhs/4XSTHrOZQlP9Mb4FOxQ69dPph1JZ/k4VNAIrO6/wNubl/DKjoel
         6W5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nSn92+Htrl9jXWDS2LfP7py7zctiRvBFm0Kz4qMhgM7wRrFKB
	3lWaWXii20paWkcRF5fbWhY=
X-Google-Smtp-Source: ABdhPJysFIZ7lRwuKTP5o9FAVenLTzYX8Xufhaw5k2eQRYGZxZ+IxCsh5n4IRZW5ug7ymnvjeAZFig==
X-Received: by 2002:a05:6830:1ca:: with SMTP id r10mr3146633ota.322.1631251843515;
        Thu, 09 Sep 2021 22:30:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1415:: with SMTP id w21ls1136001oiv.6.gmail; Thu,
 09 Sep 2021 22:30:43 -0700 (PDT)
X-Received: by 2002:a05:6808:95:: with SMTP id s21mr2933836oic.80.1631251843176;
        Thu, 09 Sep 2021 22:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631251843; cv=none;
        d=google.com; s=arc-20160816;
        b=hNZptM8pw8eAu5beFnMrV/egS4zcu1g8yugp5/8cS31Q2CFQLhHFrdkmAuc7iWXQsw
         oBC3sAaZNM502ZSH2iNkEvIgdw6jnPSYB7TruFOfIBa0tEKZ0CFAzwBhxGM+zQU0Coko
         lj/YAuYLZJ70pWkL0tm1tKRvIfaxW3awh+64Bu39HvU2D9saNIqOTZUz7TIeEf+ouhEs
         TaDWQoLW0RPqlixC2G/5oRtjqXbpJUEyhrgewALYYaw0WnhufQXFIBS/uCMG5w2E62Cu
         IzHAxCpkbCKVDCP5/lSkPUSKp/vCRf8nXQmPbd47ZhIJzHduzf1df/YBIBWjPiQLkTBM
         okew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=SHdkNqj8jzUnYs8Egy6y5yDC2JBFs1r+tUIzwMLzr8Y=;
        b=ilHlYW9SgOAuRTO6KVEQXikU5rYnIlbeihpxayRyev7Sebqe4eY9BIxHdG1IUIlu3q
         qah8RRIwbNPUFi38ZdQA2srtdSfAnizp9vt14vKPEel7k/4x0gAsvKYC6bntdXEky3Cq
         g4lru7TmEf7tUCX/ZCBamwHfBc+w+OcIldH4LPux2PG2yBt9MgDOh75T0GovnondiiOF
         JBAg6yvdffUEjC5QMEOQJUiWKrcpb5f0ohwT82zAjO77+y2zZyuZZrz3gKvhc2WJv8qU
         o/lOcveDqfT/SmRsVV8uCl7VkaUl6JZmaGV5Tr5bubGYugQtmp9nw94w555skNjiOZoC
         1gkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id a9si597188oiw.5.2021.09.09.22.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 22:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4H5PZW36g6z8t09;
	Fri, 10 Sep 2021 13:29:39 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:11 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Fri, 10 Sep 2021 13:30:10 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <elver@google.com>, <akpm@linux-foundation.org>,
	<gregkh@linuxfoundation.org>
CC: <kasan-dev@googlegroups.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v4 1/3] vmalloc: Choose a better start address in vm_area_register_early()
Date: Fri, 10 Sep 2021 13:33:52 +0800
Message-ID: <20210910053354.26721-2-wangkefeng.wang@huawei.com>
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
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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

There are some fixed locations in the vmalloc area be reserved
in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
pcpu_page_first_chunk(), it calls vm_area_register_early() and
choose VMALLOC_START as the start address of vmap area which
could be conflicted with above address, then could trigger a
BUG_ON in vm_area_add_early().

Let's choose a suit start address by traversing the vmlist.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/vmalloc.c | 18 ++++++++++++------
 1 file changed, 12 insertions(+), 6 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d77830ff604c..5ee3cbeffa26 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2272,15 +2272,21 @@ void __init vm_area_add_early(struct vm_struct *vm)
  */
 void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 {
-	static size_t vm_init_off __initdata;
-	unsigned long addr;
+	unsigned long addr = ALIGN(VMALLOC_START, align);
+	struct vm_struct *cur, **p;
 
-	addr = ALIGN(VMALLOC_START + vm_init_off, align);
-	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
+	BUG_ON(vmap_initialized);
 
-	vm->addr = (void *)addr;
+	for (p = &vmlist; (cur = *p) != NULL; p = &cur->next) {
+		if ((unsigned long)cur->addr - addr >= vm->size)
+			break;
+		addr = ALIGN((unsigned long)cur->addr + cur->size, align);
+	}
 
-	vm_area_add_early(vm);
+	BUG_ON(addr > VMALLOC_END - vm->size);
+	vm->addr = (void *)addr;
+	vm->next = *p;
+	*p = vm;
 }
 
 static void vmap_init_free_space(void)
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910053354.26721-2-wangkefeng.wang%40huawei.com.
