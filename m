Return-Path: <kasan-dev+bncBCRKFI7J2AJRBMPR3CDQMGQEPFFVLXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 969DC3CF229
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jul 2021 04:45:06 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id 53-20020a9f21b80000b02902a1de813977sf9891124uac.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 19:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626749105; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8LQq7+MnWbrw0713KEn7dAr2z/wAjnd8zpAGzNISQ00Y5Xab3kBnBz22BlgyQiHRz
         EmMXFxfRSMvftSSh+PXWG9VSxQ3PoK3tjXBEIayQRtHKAHaKjhL1CjBabUW1+DaSoRb9
         +Oi5Mm7UJrVuYSKfTdI1cDuBjz/V/Kty4xVrT82J9iv0Qzru7hPAcdic2lsP4x/TjkVV
         JupOWmSXK6g1H1J48RVp6vd8jy4rJntSO6yhOrOXthO9coURYmyH0sunk+ItcDE9DWCl
         y8XCZazbMeL6O2xA6uJ7Zw7sL/Jsqf8neAZ68LqGKuFaJuxTRa5Sx7Llc2IyHLhzU9jN
         3sCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=L2v68ZGpCUDWzco+dWiLp1ky4bspR3ylreP65zyoBRs=;
        b=KiWQdz5oM8f8GmEuniwA92JzQH2u3GJAApABgljwGXfeV12DCrg0j5Qtvnn5iGX/4G
         3i3GBVUclYAhpfuKDKAOwCbaxn/JyGMYpHiVHauBLNtC39fuLpQkryUg+utylG/+8mUk
         XIoUIYzpNLO+hInsF97fFUaK/PPXuAImdVF7HCoHj6rRTpyuHhjeFY/TCW/gFkpG5hpB
         VFNBReK0xIbiyFb+OuXtl01USuZCpMAlTqvlh6SX9cPWJoidsUc9DmyxzEMggSyhjazv
         ZnQT2pLfcXcv3Dj372ir0v3FK44UO35fhMtE6zWaXXG4xQ0ExuQD8JqYT+XsNytmvZk8
         hbsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2v68ZGpCUDWzco+dWiLp1ky4bspR3ylreP65zyoBRs=;
        b=XdtilUYSotKdJsUNiFKKtfXumclXJ5/QLLyfUwqOa+/9Li5uzTAi7jx+udOowlNkoi
         XIymZQlktnlGP2ILMDeOsSp/8FXpcjrrsaXMgE8BOJ7Zd4A/aSDh5l4ABT1E0u7e8MXf
         ELxJ5DkJP+8Ja/Ca7Cv2DakJaHLYBHUPibN1TE44ZZnmRaLQKnelSOni2LYL+sn76alz
         gtY9SI/E+T19oj7cskeBhdns1rINU50jLRLMYN0yilKUCobI8HUixGwzfpiYb/eKKAEW
         HIyxP4Dt6HoYR1qFsZcVeiCRsUR5n/fQhIeUR19x5AIlPK2R2PmtIqTOQyq09kKqbMbq
         udRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L2v68ZGpCUDWzco+dWiLp1ky4bspR3ylreP65zyoBRs=;
        b=oljlCy3CaSI4FmBnTR0fxOm8fmPlVmGf50oqH/GerPAyTBalhCVlD0jqcoe/8H4kPE
         +IRrQzaabxksTxIgl8/yW6p+/iSmh6n1g03ZOo1rgipGeXiowEabxHWP3JFaw+Fu166g
         K3zg+DQCuf1jOZADWd3DCU1MxBy7+kxYGwGoCv5PVQwZ2uMeUYxokuG4w63zayN/De5E
         76M1611q7LqkkgbTrF6mJi60bJNCd/bnE3BheiPm7oxU4JHIrr1Xf3bQVjIH/hKdbkDP
         +lhCd5XW7hlcao0+HUaE/54qWx/IQzy8g9i/UhuBTCBqCZ7sLRFCZe9oa44DPKrrY+W8
         bMiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ft6py1X9VZiQPfZb4rMTc31lR6PI1xrnUhjiRzB23z1fK09xQ
	YqdRyh+v0tQj7P4gyt82DLw=
X-Google-Smtp-Source: ABdhPJwn79PZUW6tOnH2umrj49K3HLhytA9Dms6qkquXbHFhy81UGrEVARx8qChMZy3iljUUIf4QHw==
X-Received: by 2002:ab0:728a:: with SMTP id w10mr29114717uao.12.1626749105645;
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1c86:: with SMTP id c128ls5894267vsc.2.gmail; Mon, 19
 Jul 2021 19:45:05 -0700 (PDT)
X-Received: by 2002:a05:6102:2369:: with SMTP id o9mr27325703vsa.18.1626749105056;
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626749105; cv=none;
        d=google.com; s=arc-20160816;
        b=SQxMM5AhWAoL1xxH90aC1dZ4HrWBK4/xbS4zGP0vZEEcyDg4gejHSHhwO9Yf8B0/vk
         L0pgCi0dCvMdTfTXEFWctJZll5OJAeKQLyahndvZpJpfrducHEs6fis/sJBE6cnj5prr
         RWlJiJ3lWk7vyohwRIrab0HYJpCn0ur/Io6LBxsPDcC4MGB0rOFPIo1DYxUjj2czrTli
         TUTAl85JlOydRkh0hwJQpfCYrZmsmj9HwL6xbGiOOVIq1xecTqrq4xdu+bC5iIMpZpl7
         N3syM+hK1p1husFPO2GADjmichTDkaKC6UQQYiU/DSZbqSaX4djDE7jTZTlVAD00dpwK
         mgeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=crhEsxlvP6MHymS30oH4t45tFzrcS7jAYSivt7vxdIc=;
        b=QhYrY5GOHn0wzYWyWxoH5VU4PDoyoTL7ILINAPTpO+9VFIL4oF4Dp+STRiUQORKfPT
         2JSthZgvc7mXVX89DRd995qGHD6GplFqQnRi9OXNRKJeqXsmRAMnrkA/gb697AjxZ4UN
         JLcG8wx7SUBL009DJaw8xxPcJBfV1mvvh3H2KLnXvN6IzyEs7BM4pKJxf5sMxvIhbroY
         2GWvMr9gP/ZoWC3HS9fiW+e5Xji8uYcJ3++GA2i29D5gQyQ643yY+qLVrdCiGJWBmQWN
         KTxJ7f2LSCP+C5w2yDDH0Nl5oXlp+2FgcwP/g0Vz/4QVBDNfFoRa9Nd1fg54tS2VkGtn
         ihIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id n18si1026768vsk.2.2021.07.19.19.45.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 19:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4GTNHn3dPpz7wx2;
	Tue, 20 Jul 2021 10:40:53 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:31 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Tue, 20 Jul 2021 10:44:31 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH v2 1/3] vmalloc: Choose a better start address in vm_area_register_early()
Date: Tue, 20 Jul 2021 10:51:03 +0800
Message-ID: <20210720025105.103680-2-wangkefeng.wang@huawei.com>
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
 mm/vmalloc.c | 8 +++++---
 1 file changed, 5 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d5cd52805149..a98cf97f032f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struct *vm)
  */
 void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 {
-	static size_t vm_init_off __initdata;
+	unsigned long vm_start = VMALLOC_START;
+	struct vm_struct *tmp;
 	unsigned long addr;
 
-	addr = ALIGN(VMALLOC_START + vm_init_off, align);
-	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
+	for (tmp = vmlist; tmp; tmp = tmp->next)
+		vm_start = (unsigned long)tmp->addr + tmp->size;
 
+	addr = ALIGN(vm_start, align);
 	vm->addr = (void *)addr;
 
 	vm_area_add_early(vm);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210720025105.103680-2-wangkefeng.wang%40huawei.com.
