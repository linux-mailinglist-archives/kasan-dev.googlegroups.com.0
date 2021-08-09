Return-Path: <kasan-dev+bncBCRKFI7J2AJRBTPMYOEAMGQEZDX2IEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 493693E42C4
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 11:33:02 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id i32-20020a25b2200000b02904ed415d9d84sf16534862ybj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 02:33:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628501581; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZcqRt8zvXm6yqNE7Hnu/IKHQEhwZX2IN13pDNPEgO6ihC78CX677U9gdY6BtYdaNN8
         Jr8B/62IOfW6xaOvyOXr5/orIcV9Q8ejm25ATixqudnMpp2JMtkntNJI+8K3t2MAKpIY
         Nw166HmPYdy/H6c1KOnlvDio3GJuyJ+Jex4PifZuYwhGWZPrjaOrhOyumDXWHHOH1QfW
         tb9ey6Xs0IfpehJ4hQgYG9H1Q6aL6lTZOUxZ6iPXySjEDRPtwa6aX8AGRgTMv7ggkemc
         95XEZO+OYRGQfau0CojQtmRcJBEitIaWDPWnNH8jbN+FwcVr7rtKkhf9I87QMqK+npet
         eC9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XYRlpTDYVEjEBFXAw6YPDTV5l3NJVisg2COmM7UufkY=;
        b=Z528pAh+krlonSqAJ00hlyd/fLYC9qJ0eqOCEW6fxBCsDI4iL3EWmY1U4hnubu69gf
         1JLrmZj9v59jCEYN1bqaYeDkSI3tC1PTXDliAaWvnEFpSlOxNX9VlkXvC9xCcMF6FhMF
         TOOByyHy5wVi4CQdJSj2/jPnSndpa9+kvoo7FFDZG5BHbdEaKmH2C53+fqf8jSNG7FSQ
         wD+yBPtMoxQvDigYCjyy7Hfcp2n1Bf3JlGR9sG8DDzG0tnqtXhGpclGsMwQPMVfLadIT
         4T/E9eXGZnVQ2nrFn7ogjRxSRsVXeYp3b4ha785UqWWQ1CM3s2e78Sw2XDEYxpmGMrVy
         rCVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XYRlpTDYVEjEBFXAw6YPDTV5l3NJVisg2COmM7UufkY=;
        b=Nz68WhCMMzJOOaDLiDbfDnOhu/OzFrLFgUFDHwAX5VtrTE5Y5NEyfL8Nfabt2LrAQh
         z0IQ+A1l4ZcjQI8RZ/RIGEdxtJgdDFjvOsJkBZ4P8qJA1J/G6KSJORzGvqcAchVS30q2
         tS4I1t1sjxqQw/3bY75egRUo4p6683c6w0mqAD3WmL02zu28sbc16ywpsJGBln8c88cF
         igwc0BWZA2ke/gCeVLL5t6R0eswVtWP5kdY2poR11cZWzxCm8T5SLOMJVwfpSUBFaZOe
         gTpPtG/XVNbLS4uF55fqbUCCE0i9lE7ZEfWd7SuDSBfyuDKPSX4dnaD6AHeBzMEo+uXa
         vurw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XYRlpTDYVEjEBFXAw6YPDTV5l3NJVisg2COmM7UufkY=;
        b=Vp5RulSDcknMsp/pqwKNW7kqCrJ/rv0oGYi2quaRRpuhurVjoQkUj23ctx8vheznlJ
         pkZigC157Y+r3SAgzHi1bTdmq98IMPKniC82ZA/QbFXXiN9JY5DJ20N6lzXMaGK836+J
         sv2958H8PvXJC+yDNyVNc+5CKq1eiKDUhsli7+W+q6mkdaNnqyozmknyHrbc/s/rw4d7
         Dgar5cRLf6q9LlIy1zk6MKhMDiBoVH2VpwGByWJxaWvPnn9IGxXr8ew8Zh0QLod3vYfR
         Z5eFEIIwDdFFXbgPxXEpu4/wWiRbDQ5BHO0rcYzeevTDsQESj0MoBtGvYbn/PbjEfT1E
         c/WA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NvN/hkrCFRkWV+uknV/9exx5sFoOsQh0tQIeuEUvQBnfdcKBa
	oZl62Fo2GGpaVVAkL3vxUOQ=
X-Google-Smtp-Source: ABdhPJwnQEdVXht4Adr3Alk5BplgtVhtJ1R6c7PuejDwPHeO4KbSHdzWFkdzgZ2uu2F8PxAeYy4nzQ==
X-Received: by 2002:a25:d312:: with SMTP id e18mr31004179ybf.14.1628501581175;
        Mon, 09 Aug 2021 02:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:d4a:: with SMTP id f10ls103578ybr.6.gmail; Mon, 09 Aug
 2021 02:33:00 -0700 (PDT)
X-Received: by 2002:a25:ae24:: with SMTP id a36mr28185212ybj.205.1628501580716;
        Mon, 09 Aug 2021 02:33:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628501580; cv=none;
        d=google.com; s=arc-20160816;
        b=0h9nprWjJzfGKLUNsKMFzy0hzB6GdlOn3hqUu4cDNXHU8FIee1xEGM5hT7GO9X5kJr
         okuD11my9ahRf5RAJD9u7+wbCV0LCB9YFM+vCe8pw4F29M+lXuyyxKqn1eXZvmHSdAI7
         8NacJh+IrUftqtEzxvQl7Q2aZ7CeurSTdR7C2Jqh8Sp/IvTKnX5pVyufRCrdiNEag9Em
         6Q6netHHSHzdpFyUm4yWZQy11BqO/ERoH0f3elgvj7Yszcc7sqBaX6VvtFd95qCqT2pG
         seP6N7/RrXOqfvQDihOJIYDSubs6novtnePQeSUZJod0OZPUyMCrN8kt62lOawaWtZ07
         PGVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=EAGRf1Et+tzYsN6U73rPfAHcBkVggeZ8F78bJocYRo4=;
        b=Q1uzQR8rzP6PWlMEO65PE8Hg13gaCQ/ferKlSh0zTKEXyu8gMIkOSy2W2ySv27sB5b
         S434gPofOZOObK3ViPkM8fukhQBkVt4Kw08+G/Cl6RvOLDHO0vWqgoTtou0X7Q0RWM43
         Kl1g9ZpN1KWADlZObu1NnFHp9T4n4WzMX0fioiSvKaWLtwb+gatIujPHhNVQWxMLMQ/+
         4Qumi0q1I4X6Xojb0JBIVPujxMmw7SVJ/Usc38NZF7IJd4GdpOlSbg0KVw90elfhaDOA
         0TBJrCI4ioBO/8VlY2lxSvc2Bj4E6Iu3R3T3W9FSRpfnmj988J/UF713n833O2UonqsL
         VQCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id z205si1302328ybb.0.2021.08.09.02.33.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 02:33:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GjrNv5rTZz85Yj;
	Mon,  9 Aug 2021 17:28:31 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:27 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 9 Aug 2021 17:32:26 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
	<andreyknvl@gmail.com>, <dvyukov@google.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, <elver@google.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v3 1/3] vmalloc: Choose a better start address in vm_area_register_early()
Date: Mon, 9 Aug 2021 17:37:48 +0800
Message-ID: <20210809093750.131091-2-wangkefeng.wang@huawei.com>
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

There are some fixed locations in the vmalloc area be reserved
in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
pcpu_page_first_chunk(), it calls vm_area_register_early() and
choose VMALLOC_START as the start address of vmap area which
could be conflicted with above address, then could trigger a
BUG_ON in vm_area_add_early().

Let's choose the end of existing address range in vmlist as the
start address instead of VMALLOC_START to avoid the BUG_ON.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/vmalloc.c | 16 +++++++++++-----
 1 file changed, 11 insertions(+), 5 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d5cd52805149..1e8fe08725b8 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2238,11 +2238,17 @@ void __init vm_area_add_early(struct vm_struct *vm)
  */
 void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 {
-	static size_t vm_init_off __initdata;
-	unsigned long addr;
-
-	addr = ALIGN(VMALLOC_START + vm_init_off, align);
-	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
+	struct vm_struct *head = vmlist, *curr, *next;
+	unsigned long addr = ALIGN(VMALLOC_START, align);
+
+	while (head != NULL) {
+		next = head->next;
+		curr = head;
+		head = next;
+		addr = ALIGN((unsigned long)curr->addr + curr->size, align);
+		if (next && (unsigned long)next->addr - addr > vm->size)
+			break;
+	}
 
 	vm->addr = (void *)addr;
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809093750.131091-2-wangkefeng.wang%40huawei.com.
