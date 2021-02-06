Return-Path: <kasan-dev+bncBCN7B3VUS4CRBE5K7GAAMGQE2DQIB7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B364311C33
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Feb 2021 09:36:36 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id y186sf1769036vsc.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Feb 2021 00:36:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612600595; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUG3RHu5WpZJgTekkXDlWy6aGLfzGSxuPgOSBdeRYV8d7GoxtbrvnUPidgN0TaWErI
         p2uhYO+W1U2FEW/U1hdI8C8V5K3A7fdqwKBDz6cWv/dr1VO4vHGfn1R92uBIiFUCv/z2
         B4uZZze4kcGAxnyXaeqoJtmCQUJ7+xw8GbC052l9QEOv5wSBneQbRqO/58wpXglavthV
         nvk4I6jJnYhrnwwczeDzJ9A3F781GeiKROOy46knwuXeBufJAr6+JGwak3ckdHwTHNs0
         +NDTtPmhgheAZ0oKE+rkdhB15vATvktOHIoo7HyHsgJaZ6wIr7Ll+v7HGDCDR03gxL0l
         QBMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2w38oFDgoAf6Z3dH38kdGKFk7nlj1pGkK7mHRdbtrxI=;
        b=Kt6hvp/VTGPrsesrTbnuu4haVGU5GzyPW1WvvdPCT90uUK/o+LQA8+YYLDJgf44RDx
         jecuAXbhEH42h0iZX/e680CPMUlrDKtqeLfZIZvTzr0QIOjrwnmk3NExMJdu395cm1JP
         uTKYO4m7vUCbWCuvWNaqaWF4B4N90xGft1Te9iU3ySZhMpenqSEHkj25yk3suy/FWiAU
         WNyer8e31ky+9JtjBGSrUfebZV0oz7TMIUfAkHtlmRLesRv3hp7iB1vY4a5jIT8/WUkS
         9+YQINTglhGpSiqI6Qu5XyUpB2y7oNHq6xa4ckKZl7X82qkQna/JWHjDuNm/MlfSzHxx
         qgNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w38oFDgoAf6Z3dH38kdGKFk7nlj1pGkK7mHRdbtrxI=;
        b=kcYDce/f9wJsT0bY2DnllJRsFY2ySrE+Q/IiO77QJtYLU1X9bhHlt0LU/TT5RfAZFn
         HeS6Yx1afWCyUvH9U5NI4w2rB75D2qx5ns+Ou4N4r3gCehYKzwfKffmzf8w/qskqMJFy
         LrYxW5+yvio//FaoPpifmzuW3sBLiQ8RBTpIZjUudJ7wzN2cXSp597Bc9263/lokGh9d
         vj+xbRQvhHxg9GmC9vT8HRbO2BRFUdYiGmf4cI3YIqz1rkuVF/thZZyfCaM2IzMpY7wW
         eVWkbJofAIajMu85/L/XSeaeG9ZOLlulvFtjmTEzspx1jcnti8ECt2StIDLOF0OK1s7S
         sDAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2w38oFDgoAf6Z3dH38kdGKFk7nlj1pGkK7mHRdbtrxI=;
        b=KwRWcvB572YmG86GJiPytvL0yIKfFb8EH54FKjnVH8hny3Y6FIY8hManpzusdrzV5n
         nvQ8f67N3cRvDrUCFuG0W34xKFK356H4jqltYET74jzYyt3YWFVb3RcJ8TqT28hke/t1
         bQVoYaVkY2SmonoXUh0NbPCpEburkTX4DcP+SbabGLhIx+4NyDQkghFNM+HRe1vRlLr2
         Dzb1MfSsT2y+UjrgIw32X2Rb70T3MIFDaA8ITDSeKod6KYbJ8ld42r2zOMqPzLWZZI1J
         JIeJVefWEjyXxqoUv9aHyTQKRteodcY/xjYUajQgDPxwULcjwhJmgqWYf+bvKPVDazbF
         9G5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nl09+qAR21BDRMBFXCX+pL8qAvHQGNam2zTS3OjHX7v6l9BON
	sSgrmilFxIU5dc70ClUYBgQ=
X-Google-Smtp-Source: ABdhPJx8ENdDl9+zs2K9myzNCX1qCBKoFuzDfQUDM7iNPMO3g2rbsxz6GYPkz3lVRrPaATji60PkRg==
X-Received: by 2002:a67:7d41:: with SMTP id y62mr5713185vsc.44.1612600595156;
        Sat, 06 Feb 2021 00:36:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:32d:: with SMTP id d13ls657268vko.11.gmail; Sat, 06
 Feb 2021 00:36:34 -0800 (PST)
X-Received: by 2002:a1f:6ac3:: with SMTP id f186mr6006117vkc.18.1612600594767;
        Sat, 06 Feb 2021 00:36:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612600594; cv=none;
        d=google.com; s=arc-20160816;
        b=wd+jEr5PFNpcP+FBMUIlPRu5ZXDwb3sERGfNzkIxnboDy+qyd5ePDLsedwn5CIq73C
         Y/41Dax3HGC8mQMnfVnqt82MJ4aDrx1DjIOaAw+S+zdDcFg/N5f5+fqI4xW78iHzC6Hn
         7yxQiHEjinlJxc1y+tnDDFLBNGCS5/Hayn0d5XDc0WcIx4q+KjJi09L39jusISNE41fq
         nQWyn9X+sEulr34qtuMdE1BTpFJgURb9ubkfIDW9E1LZY4rTLkbvPLTDb/k2JYRbgk1W
         4F2yAZVutw0ZsDkmtdtv8vBKdhfLdyN7XuXDg69ln/Zzd/4aBQttwDTzvSL49nwJi/mZ
         rMCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=V6EOw2xU6isc1fD9l8CsjWL30yK1fdoxWILVstSGR2g=;
        b=q3O58tZwJOZvhE/6iukpImQVdSsI+wrSuORhCVb+BWTEljv6kGUrJcHnUhZkXn/ewW
         HTXQ1IigZBUUZOmlPBI5a8UMmkLriThICrLa6NdqOl7lL3DhumwlCrsQHYTKsapuP/0H
         oF8SvH4VHkCM5wf6ZwCX/iyOeC1QM8H93RptuajBY+O6M4hJ60U8WyziO3bKpI2JLPvS
         MzLJJFZib4aBz2iJiJ2yBuQBGSu4oTEbKBPCsCzuN8zugau1ynWRJqoieviEbbPqogH4
         +MNZWD7J1nOB/LYEesNtorLVAJjfoSdai7OEDJfsXg/44JdUdqlT1tXAYniv5zO9VV/w
         bQIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id j25si731181vsq.2.2021.02.06.00.36.33
        for <kasan-dev@googlegroups.com>;
        Sat, 06 Feb 2021 00:36:34 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 116b2c8ac0214046a6ae1e0de80caeb6-20210206
X-UUID: 116b2c8ac0214046a6ae1e0de80caeb6-20210206
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1111705410; Sat, 06 Feb 2021 16:36:29 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 6 Feb 2021 16:36:08 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 6 Feb 2021 16:36:08 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<will@kernel.org>
CC: <dan.j.williams@intel.com>, <aryabinin@virtuozzo.com>,
	<glider@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-mediatek@lists.infradead.org>, <yj.chiang@mediatek.com>,
	<catalin.marinas@arm.com>, <ardb@kernel.org>, <andreyknvl@google.com>,
	<broonie@kernel.org>, <linux@roeck-us.net>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <robin.murphy@arm.com>,
	<vincenzo.frascino@arm.com>, <gustavoars@kernel.org>, <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v3 5/5] arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled
Date: Sat, 6 Feb 2021 16:35:52 +0800
Message-ID: <20210206083552.24394-6-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Before this patch, someone who wants to use VMAP_STACK when
KASAN_GENERIC enabled must explicitly select KASAN_VMALLOC.

From Will's suggestion [1]:
  > I would _really_ like to move to VMAP stack unconditionally, and
  > that would effectively force KASAN_VMALLOC to be set if KASAN is in use.

Because VMAP_STACK now depends on either HW_TAGS or KASAN_VMALLOC if
KASAN enabled, in order to make VMAP_STACK selected unconditionally,
we bind KANSAN_GENERIC and KASAN_VMALLOC together.

Note that SW_TAGS supports neither VMAP_STACK nor KASAN_VMALLOC now,
so this is the first step to make VMAP_STACK selected unconditionally.

Bind KANSAN_GENERIC and KASAN_VMALLOC together is supposed to cost more
memory at runtime, thus the alternative is using SW_TAGS KASAN instead.

[1]: https://lore.kernel.org/lkml/20210204150100.GE20815@willie-the-truck/

Suggested-by: Will Deacon <will@kernel.org>
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index a8f5a9171a85..9be6a57f6447 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -190,6 +190,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
+	select KASAN_VMALLOC if KASAN_GENERIC
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210206083552.24394-6-lecopzer.chen%40mediatek.com.
