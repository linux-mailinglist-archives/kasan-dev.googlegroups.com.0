Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEFIUSJQMGQECZA3HEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3378251149B
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 11:59:46 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id s1-20020a4aa541000000b0033909641803sf803827oom.21
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 02:59:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651053584; cv=pass;
        d=google.com; s=arc-20160816;
        b=kgirHOnA6UFZgZVAVR6hziGQ5WWFg3smkShQE/5miOtwxKNCKhSp6o1f4O5JoH5P1a
         4TpjhanPmv2dfRhmSrYyjSfH7E+MCVYAO8FKgTzS8m5lBLxw0OpQNMA8O1+5zA0LS9NO
         yH2OjRAmNWigCWTb84eOIPUNwYvBOWIzZ5eOrTNpUGmP1RFTggd7iZVOWlaWedRZ05uq
         Qta9Z14mFkcIViiV6+LDtPvRx3lKilXtjRUUSLmDTzQ/y2zQOQyBBE0WrkudbS5MpmAX
         +i0uHXSyQECBSGwQpN5ZE1JpNR7OAwDjBdTOnUeyQuaLTa9L6Vy+XAGnmnlcDQTKYIqt
         ZU2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=sJczi+HaZVIjCuFLnjxLAAIWnY4NqxhIxE6bPHyfnac=;
        b=lrhKvi/WOu8fpM7B912L2ViWxxaJzNFuky97gizhPvj8sd5c4gX5cX/3xsXgkAq+j1
         90REK5e4QWyYBIkVuutq8hUXWs22WRmYne7zfE1cjXqz/lu2hQOUZ54GcbC77nMNxtIu
         UycPMASaj+6QSAQgzzP+zzVndOKZQvwgbGwQ9hXiYviG7nIPQmdTeM4OrbEWJVNwtVxH
         dagIxZwIUqxqTOYr7Y4M8n6SYWatbIkgvtaxaTiAM8AX3ZJxdBixN1Xr2uQ0o/RAa1/B
         RyrgSs5LUappddOuMCGLYZE2IFUffIwSetQkF3Vz4BCnr74ayb2nRUJn27RcrMQacsNp
         x2sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sJczi+HaZVIjCuFLnjxLAAIWnY4NqxhIxE6bPHyfnac=;
        b=e/A5u2nXyyZ73sVI/3yPLDnB3wMV0IOfBryEmEsNGXxrsN1Mq3xrM6mGRc9DEFyfmM
         5I/Pu7l1lqNcYzRAt9uKuoNbZl8DufAoMMEWvfbSMUaO9IMe9nw+lYhF3nRFcsvvnqfR
         j9XE5D0oD71tnqeDRHcPi6gjuI5m82Vn92zy0lUoc1hAmBHJuWdA5C9D0dg7fS+S0pIq
         A5sc8nkaBoFHIw/h3mX4vV7dQV6pPrCCve6cqP+VkJ9ZfMBjeQrJVsU1kICQvGZIg3L1
         xt54v5Qh1Uk/mjKGd/tKzLzFZ4Xe6WmUnrX2DTzL4s8K7/Twjcwie86enEoTt4qtFZbh
         q/ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJczi+HaZVIjCuFLnjxLAAIWnY4NqxhIxE6bPHyfnac=;
        b=GmAF+RR038b9rIdoint5zVNgzBQvDmKPM/uN6ChwkAVRKZ6eL8AE8bsCNg7pun+ctF
         Zm/WW8DpD1EF78ueWWX7Q/JSXcrcbZf5+22O2AVAaVEHnZRUQ5gfKnk+EXS5Mdz5b7JE
         zrYHgZ5LnYpN2cIt8A/N7hplSVlxloNOPUFfu7MDdKbX3I3vINfEiUMQym0qGUp0Y1a7
         y9hGhcRN9AeP0ZeHMvT+mg2YHZJ2wXt+293jFEhM1yTWHqBe0I+/E8pHwRu8NOvqMR34
         jm1ji4/kRiOJONwFWqOXrg9/CJN+BniYEIE4D7/U2WY/fdIYAwXzuNjWC06MBzvooX6U
         xUmg==
X-Gm-Message-State: AOAM533tM359Z/oR6Y85jrrMUd0OWYChNqzPvlQlgvYjg/p9uK00+dRW
	P/2nP1EDgMqOZpWhEjIkjJ8=
X-Google-Smtp-Source: ABdhPJyR8Ub/056Tr9hfE48hvRtgEWjFGS0lD9781pFWITrosU779K+EMPG5on7aU4nDde3hn9rqpw==
X-Received: by 2002:a9d:750f:0:b0:605:d70d:6112 with SMTP id r15-20020a9d750f000000b00605d70d6112mr1780624otk.19.1651053584732;
        Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:154:b0:e9:6abf:f9bb with SMTP id
 z20-20020a056871015400b000e96abff9bbls1916563oab.7.gmail; Wed, 27 Apr 2022
 02:59:44 -0700 (PDT)
X-Received: by 2002:a05:6870:538c:b0:da:f5e5:5b56 with SMTP id h12-20020a056870538c00b000daf5e55b56mr15464201oan.241.1651053584295;
        Wed, 27 Apr 2022 02:59:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651053584; cv=none;
        d=google.com; s=arc-20160816;
        b=B6g0mRZOmeZIrJFH3MM9kH5oZCBGPRgi4kKWP7jTJwpJWmAuJR5bUh9nHwjjT7oaOz
         qG7LRl6c+9QBKRDgYXT8pvOvVekOH755QyLoPwtajrJvOVBb1nhqWz6Z7NvrbQx+OrzX
         D5Lml0aYnGprSmb+vXUXwN/14xvW6QQoqSN6baTxRJMxDMDQx1fg6ikmehGMrkZEkE/U
         FkF+z5c+BxaYdUP0Y2fR9kXYroSvAViihHKwkIPxSJWWNgsq7LlvZFoUrSWN19G+vUuO
         4LbvryQmI/6DCMx/ZYgvGIPc/STsiCpXOUv0kZYOcwHAxGbfRTF/UnVSLtYXOfMVy9de
         Lhig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=+Attp3Ies5FlYFASvUkIGClN+Rk3jLk6vUh7TWZfjg8=;
        b=JB1tYvvtxngZd00BHXC6cOGWR2IJrVntIuDDz6It3guhJWhrkcRi1jrv1Gswrxrl0u
         1wjn5nu6rc1etCMaUpCRHielSTTeQRPaplPPXnyjmrhxxmhrZm+eSckhuU/tgTMlFJg+
         vFHpLp1vZSVy5N+R4piZE+dgF2yYPEMVpB3XwgxMKZkGRJzTTMl2HAwYYB4KcfDKvwyv
         vbIIGOycsjIHzQqRi7j5DWPpXtiSY+qQppvS7/XotEdq1xeAJU5kpal0bbvWnkkEnxug
         yWZZg4y+usAzsjoD1I/C7vkzSc1PmvHqbjCNWIv/tO16qXemwgeXM+RPppSLFnC+E0s7
         mDrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id s18-20020a05680810d200b003227a4ecc4asi46938ois.3.2022.04.27.02.59.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 02:59:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 3e1c3739de0b45bd9e456dfe0070ed7c-20220427
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.4,REQID:e6ff2951-49ff-4921-a4da-7f6959bb91d0,OB:20,L
	OB:0,IP:0,URL:0,TC:0,Content:-20,EDM:0,RT:0,SF:95,FILE:0,RULE:Release_Ham,
	ACTION:release,TS:75
X-CID-INFO: VERSION:1.1.4,REQID:e6ff2951-49ff-4921-a4da-7f6959bb91d0,OB:20,LOB
	:0,IP:0,URL:0,TC:0,Content:-20,EDM:0,RT:0,SF:95,FILE:0,RULE:Spam_GS981B3D,
	ACTION:quarantine,TS:75
X-CID-META: VersionHash:faefae9,CLOUDID:975bacc6-85ee-4ac1-ac05-bd3f1e72e732,C
	OID:055001bf033d,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,File:nil
	,QS:0,BEC:nil
X-UUID: 3e1c3739de0b45bd9e456dfe0070ed7c-20220427
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1732903374; Wed, 27 Apr 2022 17:59:36 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Wed, 27 Apr 2022 17:59:34 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 27 Apr
 2022 17:59:32 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 27 Apr 2022 17:59:32 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux@armlinux.org.uk>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <lukas.bulwahn@gmail.com>,
	<mark.rutland@arm.com>, <masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v5 1/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Wed, 27 Apr 2022 17:59:15 +0800
Message-ID: <20220427095916.17515-2-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
References: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

Simply make shadow of vmalloc area mapped on demand.

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and support CONFIG_VMAP_STACK with KASan.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
---
 arch/arm/Kconfig         | 1 +
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 2e8091e2d8a8..f440cf59cea1 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -75,6 +75,7 @@ config ARM
 	select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_PFN_VALID
 	select HAVE_ARCH_SECCOMP
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..29caee9c79ce 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -236,7 +236,11 @@ void __init kasan_init(void)
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
-	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
+					    kasan_mem_to_shadow((void *)VMALLOC_END));
+
+	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
 				    kasan_mem_to_shadow((void *)-1UL) + 1);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427095916.17515-2-lecopzer.chen%40mediatek.com.
