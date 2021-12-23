Return-Path: <kasan-dev+bncBCN7B3VUS4CRB3XHSGHAMGQEX7FLE6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id A3AAB47E3EB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 14:04:47 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id m9-20020a05620a24c900b00467f2fdd657sf4261836qkn.5
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 05:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640264686; cv=pass;
        d=google.com; s=arc-20160816;
        b=aAZQN2DnYihMHy4ouAC+7KlQefhfbjpwcBteaERtCF+kAFoIwzg5WlqpIgLKXGACVY
         m7it0rodylHz0WTtfEqUgVvbXIBbsUM3l+qf49OtDMBC5PjQTKxk958q0RoWWeFJ4D+u
         H6ZK6i2Fo3/MyzhghXjyIanAb7ZtlAZcwai+coSCvwlxmLss89Q/mmt5hXY6G/xdfFtX
         iTZMPJWvlN1yKqau/Kn9HH+95xpxJPciKfHbaww0hX1Z27o+9VTzfzTNpmpjJsZZNVh1
         GQuGEQhPSfUXgJVkVbmiIz+7NzdWK1H8B/X9unrD2dDBwpJsVXIIoYVqw+ej+PnMX62Z
         SEsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j9lkbk0RN9flzEjSgrfdtrxHpyJuguGAU5SjTzTATRI=;
        b=PRiBiDHBFLCYMQHTw9ZjRmbBsIxMWeF89G7llPPbj9Es4NwQY2qnmQSQ1Y2kcNneyi
         fEKlzJIy1mcYTPwxGz23/gJF/GCpnQ8y1hcW3aklFYOCzYF1ydMaE4qNfIef5BMaqk1s
         HU3ZDxBSznkMoU6Rj3f/lVDVU2II2isxQVWRgxca6lsqwWdslVluxorPCutAE1U8kDpj
         CVIMVYcRI8OeC6we1deU+an6U1TKOi7FO5zo30ox3eXLEZ3llUF7/0qrSG/Wtwt8b6Na
         80jOauYMhBjbk5zdsxbhuOuTO//A+wkAJsHyvEBrjyDZgYe8c6nJGyF0PoLZprCaO4nV
         gH8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j9lkbk0RN9flzEjSgrfdtrxHpyJuguGAU5SjTzTATRI=;
        b=qdzEu+Z3WOpH34/muswWnMfKProUbLW0iyCNzvcXKrecRMtwkugDZuIzK72Jb8OzH3
         HURjmFNUe7WUfFiAimvMyVF8+Jf0+Y6gAxzo0yC/ZeAbFnu7tIuLyhUzdUyZnIi9B8tj
         v6OOXB5NoTByU7xHFr+rjJ5ztK+kdXJAlmlQF75ERg3QK/2LRtI9yPs7KBqw9zNe53CO
         NTiuhbRNfJnRw6A3u74N2SnlYi6GYkZkqrKa3K+Jjw/KrWID9T5ucBVUBvhi1AVaCKTp
         Yus8a0vBkhvn2suWjmyV7WaP8limq7CXhkLDCmacVxKHpqsNUbZDSQuifOB4/Hs/ge5a
         WCbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j9lkbk0RN9flzEjSgrfdtrxHpyJuguGAU5SjTzTATRI=;
        b=HJzj3r0c32m9tX2CIFNC/CtBc/c1ZRXmRhTHy0r/+eG2mC1CX49MvFJtPPSgZmnYWr
         YDz+ens/QLmSyXICvZXFuV+i6CF4uH7c0kKn0RCXk41WBhuKll4c+Rb41t/2RZpts0YH
         96KRCMe0IykDLUj7JnKFTgItMPl9RIyi93QuAkzi6/EdLdN7V6s6FA3llH6VPLiS2DJR
         Jhs8Yb2wj6eSQgKxE31Ir7dt5NMnAtP+WKd1daT5fJ3+ez1Cb3K0LwiTx522rubVhSMe
         k/4Rzfre0ekXz44ap1Sl4L3I8LjVCQCguqeWlzZZKgWTT/0gZlYdbWHARByNDNj5uX9m
         9ZOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qdZF7vlidKG3/7jiRAR+BYoEq5o8VxE7xQ3v/xy87ga7iiA0Z
	vSMzL1hU+iDA3in4Xy2lv4M=
X-Google-Smtp-Source: ABdhPJxHeblb6PqShuoGHPDlB0lyUfS3DPubKGuIgPAlcA9CxnQIIVJkaMI7Q8OVwO/+YA00sD1Ybg==
X-Received: by 2002:a05:620a:45aa:: with SMTP id bp42mr1211722qkb.556.1640264686449;
        Thu, 23 Dec 2021 05:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1986:: with SMTP id u6ls2659053qtc.0.gmail; Thu, 23
 Dec 2021 05:04:46 -0800 (PST)
X-Received: by 2002:a05:622a:1055:: with SMTP id f21mr1456446qte.421.1640264685975;
        Thu, 23 Dec 2021 05:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640264685; cv=none;
        d=google.com; s=arc-20160816;
        b=t82OGtu4V5qjanj/fg/QaCOrKtqtIOW8ALsuUZk+RS1KDkJ5jzOgQ729GsrjjgNku6
         /4x/XMTxTOt9oZ3EMIZROhstGFj35aSKLjtzgbW/421rzouQj0NQBbCetbVV7dtmOc50
         /YwKmzPvB9qTNt6oG1A4ga2A4Ksk+Tj+9YuMDss/J8dTK4XLbTpq8PyKHBfV6kKuOw6h
         SkFC/rBB+0vqmquIYs93/C1OSJOL2zS8ARt6juRoB/hM7+WSR882DEwJyhKFvXS/I6w4
         c2w6yWyCuukwlTQ2xB9fd0QlBqQ/pq3a9lKVTViKAC1rkXhxv9TwyhtbTHJgjUBTMqAf
         cySg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=Au5G8ZUALKdpzUarOe3JJq5F06BIgki4ODZFNhYPcjs=;
        b=b+u5M1q1J4u9bXBaVJ3+q3hUL1V2b8DhFGoFDEnk4fKg49Y5riudfnGrY01oD3NKT/
         lLCxNWrDRWAUuk9ZXCTGCgiq3dKnS/luWFGS44+v3+aPiralXleSZFPkEQcq/CO6nI74
         36owHj2Vxz95S8anMGuToFO4gDTCisRATdKcVkU+DQFuJEFL/6+dROV4+z05pNerllsn
         LhggXXJC+YA0CwrAjI+GMiQ8G5UPeP/EtEbObFTs4piS7ukCCAEDOIa4240nitIBYb0w
         3ZK5rskH8yfSPLRKKium0PEyXkYEAZxzljKyTjAsLiW05pLhbgP/tMNnNo6fsUFJ5gS5
         Vwsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id f3si1054617qtb.3.2021.12.23.05.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Dec 2021 05:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 69369d50f71d4276ad6f4de1521c3921-20211223
X-UUID: 69369d50f71d4276ad6f4de1521c3921-20211223
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1651115744; Thu, 23 Dec 2021 21:04:38 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 23 Dec 2021 21:04:37 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Thu, 23 Dec
 2021 21:04:37 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 23 Dec 2021 21:04:37 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <ardb@kernel.org>
CC: <dvyukov@google.com>, <f.fainelli@gmail.com>,
	<kasan-dev@googlegroups.com>, <lecopzer.chen@mediatek.com>,
	<linus.walleij@linaro.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux@armlinux.org.uk>,
	<liuwenliang@huawei.com>, <stable@vger.kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH] ARM: module: fix MODULE_PLTS not work for KASAN
Date: Thu, 23 Dec 2021 21:04:37 +0800
Message-ID: <20211223130437.23313-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
References: <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
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

> > Fixes: 421015713b306e47af9 ("ARM: 9017/2: Enable KASan for ARM")
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm/kernel/module.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/arch/arm/kernel/module.c b/arch/arm/kernel/module.c
> > index beac45e89ba6..c818aba72f68 100644
> > --- a/arch/arm/kernel/module.c
> > +++ b/arch/arm/kernel/module.c
> > @@ -46,7 +46,7 @@ void *module_alloc(unsigned long size)
> >         p = __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
> >                                 gfp_mask, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
> >                                 __builtin_return_address(0));
> > -       if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || p)
> > +       if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || IS_ENABLED(CONFIG_KASAN) || p)
> 
> 
> Hello Lecopzer,
> 
> This is not the right place to fix this. If module PLTs are
> incompatible with KAsan, they should not be selectable in Kconfig at
> the same time.
> 
> But ideally, we should implement KASAN_VMALLOC for ARM as well - we
> also need this for the vmap'ed stacks.

Hi Ard,

Thanks a lots for your advice.

Of course, I just simulate how arm64 did, It's surrounded by a bunch of
IS_ENABLED(CONFIG_...). I think I could also send a patch for arm64 to
move out the IS_ENABLED() to Kconfig.

Actually I have a patch set support KASAN_VMALLOC for arm which is
similar with I did for arm64, this patch is regarded as the first patch
from the serise.

But It has problems that it's very easy to run out of vmalloc area
due to 32bit address space(balance between low and highmem),
so the serise is pending and I send this patch alone.

Anyway, I'll send v2 to move the conditioni-if to Kconfig.

thanks,

Lecopzer










-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211223130437.23313-1-lecopzer.chen%40mediatek.com.
