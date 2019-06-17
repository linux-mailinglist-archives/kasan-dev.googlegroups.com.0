Return-Path: <kasan-dev+bncBAABBWNATTUAKGQEZPT2WKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 59A94478DF
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 06:00:27 +0200 (CEST)
Received: by mail-yw1-xc38.google.com with SMTP id b188sf10928766ywb.10
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Jun 2019 21:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560744026; cv=pass;
        d=google.com; s=arc-20160816;
        b=VmjVJQvbJDUXoPEema1AAnd9TREzbWpHy3r+EU29BXlDhDGXLtZ9zoWwELKzzXQpk1
         JB7c9ohkMo00Q7lMiaHY66aby49nsL9K/ypV7P06idNJnHEiBAZp+LVs8XgtR8kyHJKJ
         Ez9NCZ4+oBSlH6nnfcrN92JKiy2wjw1eIFoJ7/r8P3F4jgi3YlsKzy/S76tG4Glnk+Mf
         UCMAH3YHDMfdoYOWXJ870Pz3nxnWYZcskR7MQzUdPSGw156XXjcfUjCWIRc8Od8Eoy8a
         k9kMaLISo7Jd1ediggqikUQy7A+/6nvdFw0+wJVKShZ9sXlYWe9P1AxcuKqIYzOwc34F
         sweA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=6z6p1MENFLGyEpsv/kxgASlxNVw2YAUK/oka6IASTDw=;
        b=kWu0D1V5Yd9Htz/JyppFgD8X7rfjjcwjAs4XiLiOOAOSA9LYi1k8sp/uhWcBImoYUu
         BxDD0ms5cCMxAEPMdMgOifwq+XJ1+VXNaaSD1fOzEH9073XIQCWTDyo6FTClCadT3E9e
         nKWrVVh2FrwQFcHYsKTx+iOPGTXasm4lWs22n+qqej+m7VELx2qsrEl3ot4IzDkzAppH
         WORihtLVJWqi/agn/TfNVkKcgt9ohdYLmPEa2yXYMh/1yAw+XY6JGPz+/H3wlarYBcE/
         HCNYC1Uc08e2r2DStar6qkxIf04ofnETshjWuQlcQ/kj/3+Fk7law+naNYVgxcYgWDMG
         5fJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6z6p1MENFLGyEpsv/kxgASlxNVw2YAUK/oka6IASTDw=;
        b=IyOol8XzBWHpNz27a8/RKlt4FvielvZ03KDrdMBL4AdtmpIwKbMddgZQ5P+JKg7vrd
         sbxmXKmOlydAy5mpKejGl8hJ6PwBDw5BDe3c7WQkcK2FYCnYaRDxTLqkTuE42XIe1DnF
         8E0iLy4zP+1ymwjbUyu158XTQBdtOkPK/+159ueSU/KicaHwEkeM4e4O0z0zX9WofEit
         APBBixzzteX9huox9/aOvcu2xcjptLsPdO9X08Cca+f1SvphcGZusCcHep9bzTO2uYSC
         H731ePlsHjCP77kD5uqWUKSFz4a26RxvsJP7JwKy5t/XZDV68J9k0bDnpy2GmXQhvaVB
         MrTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6z6p1MENFLGyEpsv/kxgASlxNVw2YAUK/oka6IASTDw=;
        b=hVowqWWlPe63XvBprce5CROXS64/BOOFVVktkYBZZaoOjViWDAYNtYomGdn6tGS0LM
         fC5OU0fWbXJjL3bpU2C5DO+Yn/4JzZ6hFJuY2uQwasAiKG0Hv6zzJFNSwx1VEyOuyH4a
         v35NvsP5WgROQwfOliH/RsW3IRpFRf+05OPTzCBpMkdcztuoTbRvF6wQzC2psp4ry+NT
         2OGX9VqG5pyamdPDehxDoMuT4yo7Qg6HMfh8xRvb3QNqnQxSclac+V0JGzmYQKgr65S8
         32EI3w/pFex0eIsgoEM5Wms1BWUk26piuJsJ9VAbZY7VxpYXgKZaIT9OOppwZMmZMEBM
         mXrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV6EI+BH2YzdDh2R5z9RenKAPspWHu+xErFhI40OaCokw5tzTCs
	dOMnxiGlbMlUIwhTC4/OGME=
X-Google-Smtp-Source: APXvYqyPUfuaU+KYb0kPlzyzQtou2enBCiOEzQzJX7UCBLzBka8LOhO03G9W1wA2w8hzEpo4NiVGnQ==
X-Received: by 2002:a81:2845:: with SMTP id o66mr46331418ywo.477.1560744025821;
        Sun, 16 Jun 2019 21:00:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6ac3:: with SMTP id f186ls1775886ybc.11.gmail; Sun, 16
 Jun 2019 21:00:25 -0700 (PDT)
X-Received: by 2002:a25:3214:: with SMTP id y20mr12512711yby.181.1560744025225;
        Sun, 16 Jun 2019 21:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560744025; cv=none;
        d=google.com; s=arc-20160816;
        b=n9zThdZgy+vy+/5C15r4oIONeOyVXSUYCzDPf64OjKqqlESuYUtGWAvKKFj2O0Dpka
         IbftTjLTAab0GFk7XaJ5FYOJg2MGTcmOhlD06nLnTTCeFxTq+tIG82bxsG2d7A3eHocY
         UtA2JGolPasczo1OxSkmW/urzlYQYxoTXn0bTvImtc552iWpt46dLG6aboL54AQw2pSX
         S0X7Ovl5Q+Ny7p6aIU0EamhLGx9c/l1YwGz/QDoOGFMmPENtsfd0iOENYSx9CVRO4MHi
         YuJzOv10uCzfMPl+QxaldEDYr8DZF9C9uX330c61RxM9APh4myetrak80+jsa7AZXJ2A
         ecrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=XnEdrBkKM7udA2kzVesWGzGVoOtWxKegmT2E9+/IH6Q=;
        b=s/akx6mUlMkGLvi1/WRaxei5OmzxW7a4C5miJv6shrO08JaDzOzxtCLNXeq6oTXhVt
         KTDyt4nBvY4i/RPNzoI5GU0kx4x44FPyrZ36pEkYe3LrBxy1fp0m0FcO+SYisiqXKpGC
         HHA/TRRyP8nV+6YV4yvQ1pXH+q3/H5t1g7PL6eItuzrUWKAV+LgLfYrwKmGunkT4OKaE
         Ov05lqMWXyYDQPikkgv4NcDt1iQzaQUovoIsHwsqerDGvt0U2SAP7jCdgpT/zV2B6+2v
         RxtrZjNekAbn3Iqj82uCfgiemNq9obkP3x6dFQsqECi4lQiFwgk+4r3ZnMHCB8WWSlZ1
         2ung==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id n193si473677yba.3.2019.06.16.21.00.24
        for <kasan-dev@googlegroups.com>;
        Sun, 16 Jun 2019 21:00:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4f8413c5163f45fab280b7f808ef34f4-20190617
X-UUID: 4f8413c5163f45fab280b7f808ef34f4-20190617
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1298173636; Mon, 17 Jun 2019 12:00:19 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 17 Jun 2019 12:00:18 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 17 Jun 2019 12:00:17 +0800
Message-ID: <1560744017.15814.49.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Mon, 17 Jun 2019 12:00:17 +0800
In-Reply-To: <1560479520.15814.34.camel@mtksdccf07>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Fri, 2019-06-14 at 10:32 +0800, Walter Wu wrote:
> On Fri, 2019-06-14 at 01:46 +0800, Walter Wu wrote:
> > On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> > > 
> > > On 6/13/19 11:13 AM, Walter Wu wrote:
> > > > This patch adds memory corruption identification at bug report for
> > > > software tag-based mode, the report show whether it is "use-after-free"
> > > > or "out-of-bound" error instead of "invalid-access" error.This will make
> > > > it easier for programmers to see the memory corruption problem.
> > > > 
> > > > Now we extend the quarantine to support both generic and tag-based kasan.
> > > > For tag-based kasan, the quarantine stores only freed object information
> > > > to check if an object is freed recently. When tag-based kasan reports an
> > > > error, we can check if the tagged addr is in the quarantine and make a
> > > > good guess if the object is more like "use-after-free" or "out-of-bound".
> > > > 
> > > 
> > > 
> > > We already have all the information and don't need the quarantine to make such guess.
> > > Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> > > otherwise it's use-after-free.
> > > 
> > > In pseudo-code it's something like this:
> > > 
> > > u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> > > 
> > > if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> > > 	// out-of-bounds
> > > else
> > > 	// use-after-free
> > 
> > Thanks your explanation.
> > I see, we can use it to decide corruption type.
> > But some use-after-free issues, it may not have accurate free-backtrace.
> > Unfortunately in that situation, free-backtrace is the most important.
> > please see below example
> > 
> > In generic KASAN, it gets accurate free-backrace(ptr1).
> > In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> > programmer misjudge, so they may not believe tag-based KASAN.
> > So We provide this patch, we hope tag-based KASAN bug report is the same
> > accurate with generic KASAN.
> > 
> > ---
> >     ptr1 = kmalloc(size, GFP_KERNEL);
> >     ptr1_free(ptr1);
> > 
> >     ptr2 = kmalloc(size, GFP_KERNEL);
> >     ptr2_free(ptr2);
> > 
> >     ptr1[size] = 'x';  //corruption here
> > 
> > 
> > static noinline void ptr1_free(char* ptr)
> > {
> >     kfree(ptr);
> > }
> > static noinline void ptr2_free(char* ptr)
> > {
> >     kfree(ptr);
> > }
> > ---
> > 
> We think of another question about deciding by that shadow of the first
> byte.
> In tag-based KASAN, it is immediately released after calling kfree(), so
> the slub is easy to be used by another pointer, then it will change
> shadow memory to the tag of new pointer, it will not be the
> KASAN_TAG_INVALID, so there are many false negative cases, especially in
> small size allocation.
> 
> Our patch is to solve those problems. so please consider it, thanks.
> 
Hi, Andrey and Dmitry,

I am sorry to bother you.
Would you tell me what you think about this patch?
We want to use tag-based KASAN, so we hope its bug report is clear and
correct as generic KASAN.

Thanks your review.
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560744017.15814.49.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
