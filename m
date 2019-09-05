Return-Path: <kasan-dev+bncBAABBY6VYHVQKGQEURWUFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C1D2A982A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Sep 2019 03:54:45 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id d10sf310850vkl.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 18:54:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567648484; cv=pass;
        d=google.com; s=arc-20160816;
        b=NqKZY2om6ItV14Ws2F+Toch+Kp3J1fmFliQPu0oe0mBpK5hQ259Dsz6Dprld+LCh+X
         aQxLmPhEeWAs6SHISOYxqM67cXYcWidKBHhGDp6jlWOF7vnlLOWZS9746Espc2mPPM1H
         LiDyMdIi4zqoZIagyH6rpGfU3bHNRA3/cDkEX8WoLxDpiFKWfX0nFSGTbGs5KXgq9E27
         IR8yBZy27ASe+ngKhmKZrvIAIBq7RJBIy/WMwTwgbH+HNBPeBK6VAyrdm43rb8qOCzgV
         a6yxbJUdZlEHsLj61JG4aYQ0Hadko7SbJ0+i7ieKkBY2CbUc5ur/41DcBSICunjLXS5O
         sN8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Qd014qYjhCLjm3te2CTlIhY/uAUwLaZNMJrw5lL+SNE=;
        b=AZOyk+4174c22HI3SktLH7cjB0Ljk4LhnejD222q0VQodlH6ptVayQ4bWzgqjs1pJO
         m+Zek3qHdrMwuUxrs2dfgPvpdjw+jczBDGCb3RfX2z6y7iTVi/jZzlWEdTdSb6mwcks0
         I8MGq+SzO3HOKkkiofaK7ZRjyLai0oWKWsLyH5OavgEhzcmjACcjFlG2TimV2y4RYLqK
         ioU0g4heqJAt7Yzk+SvcGrVGdYpXiJaxkmS+46sQGB5BIST1szQZVerFkuN0ZDl/SQ2i
         3rAPqqNHeMZpKuiG9tUDIW7ob3Ix/innPqdlO4qJo37cVykJOIZM+O1HuVHOzHIJoXk0
         ESPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qd014qYjhCLjm3te2CTlIhY/uAUwLaZNMJrw5lL+SNE=;
        b=WMVYYg3q126Qj81+SnTc4dg73yLflEesGLVGO5CDm712/OXUtmz5+1NE41VuGNYKYE
         MnG6VXgblmAPXhrPk8/KmAF3A8GC2bkxYGKIy/GwD90/Xh6GaBFlLT53idORC5hKYY3d
         c3R61ATbdNsb+yBHscJKgrlevDUHAAAbk6WL5iwseO8dN+omZVD9mbtpUIEy+OVfDKh2
         OtrzvmFzCu8NuzO+5eDPF7t6XVkCnCkgUyQDcFpeVXHCRTw52fC9VbcRA6YUlQTzQNLs
         Zvasw8Yy9FWo3fm0k5Em1isU0TaNuBPUr8QjlTtk9xW11/hmh3gZDUk6CPXF9VZ3Ix0c
         Fhyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qd014qYjhCLjm3te2CTlIhY/uAUwLaZNMJrw5lL+SNE=;
        b=HVf2Lq3NyV4L84JpDtczUPoLMArghTFNbbMsgFbQmdUFN+INyFxm3/FrG5BcMeLkMz
         2ZXburjUEK19ZstYptrFiNubUuMl5NVnI6klJPWkkSIkhhCnKmRY6yoV7YY/t8wJmsXv
         HymThLGTRTKBNk+4MEPtDkUW5yuyx7rfElGvPA9P4XnkzrV8N4uru1wyO1Cjt7sVB0iT
         1vEUyM+Wr7Ou2/DPPImPrY28tMD3O961VI3KaZofjGysRz+KHY5mtjTlbrIem/ArL9aw
         BuEFPaEtLt390Ytb3e05wUvdhdC/FhjD610gp1aXVd34h4UTrYocfsdwlv0Lpnr5vKTp
         n/og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7b+wXRuaYRWRKfBBRDvPdC14howH9mAcbAgGMiH9k6JtIpFOa
	DkXDBoEE9VF3tt5CdRcfB9M=
X-Google-Smtp-Source: APXvYqxAbEHeEKRNvs0mZ/L+oza2T3JPgvusqqc/V9dbWHQxlcbJ/C3SWilhjGjVTk7JmH6E2olLJw==
X-Received: by 2002:a67:f08d:: with SMTP id i13mr481144vsl.193.1567648483750;
        Wed, 04 Sep 2019 18:54:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a8c4:: with SMTP id r187ls25992vke.1.gmail; Wed, 04 Sep
 2019 18:54:43 -0700 (PDT)
X-Received: by 2002:a1f:a5d8:: with SMTP id o207mr388427vke.12.1567648483488;
        Wed, 04 Sep 2019 18:54:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567648483; cv=none;
        d=google.com; s=arc-20160816;
        b=gYs0ETBJrBHD9NS+lAUEL2gT15yGSMx1XQ942iC3MBhRTkGc8hSjxoYi2KvrT5gXK8
         D5Zgv9YgAE+MXt6mJeuasqhiprmWE5kIIMkXnvxQN/zjmT0LRJSIt2HrUzJc+p+Arw4B
         mElk9inZAlt1lmYRQfQAo/jIuwDfWPFDImpb5ENA028DcbXDuZO+Q62Wd+64/Qtx0D7t
         f0lmigPZRV5Y4OCfo7+Fb32UXOBEPEz/P+o1XD4OTzfqrGG9d3tVJlo27fKCAhcPsgRe
         2pYMw4rwKLZYyf/sG4gbCoGEQxDwk3dGcF3XPLZFL64ucudwtTEEdnz8ILNtFUxoT+Bc
         hEYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=44K2RMvDlyMUuJv+Ew7sgcZ2GN+ORnaEZF+Qp/0BFq0=;
        b=ykXJ16mS7GzSgRUFDGyfgeH19Yau+QLM3RTKRvOQl9Vg9vIhXFLc7S8f2XyifYrJ8d
         LWPZDLW4Lj7x67B4dh/BvPQ5EVOFX1SLhALz/t2azeynXoaFRDqg8NzadCk2KwjfrqlC
         efNdVZJJpHn0oIIWHuKwoG53uoV+ADyJ1fEa3JRdBAfPMSxiS06cg84G1OwCpg5zxyNy
         UGleDeR3OoLZYX7hQemFmMAlQVA921U4Fj/xrlm8EeePxp2qTZXqBJu0/Q2MsY/hAP6B
         MNPnvMW4vp9eCIzSa5qNfHgncnV8BQjD6IXXVx0YFSd5yYO2mV6FoL3OIkwaDq2BGdDF
         hSzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a128si41866vkh.1.2019.09.04.18.54.41
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Sep 2019 18:54:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e1c814d6fac6479dbb5a3b406a2fee58-20190905
X-UUID: e1c814d6fac6479dbb5a3b406a2fee58-20190905
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1846864118; Thu, 05 Sep 2019 09:54:37 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 5 Sep 2019 09:54:34 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 5 Sep 2019 09:54:34 +0800
Message-ID: <1567648476.32522.36.camel@mtksdccf07>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Qian Cai <cai@lca.pw>
CC: Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Ryabinin" <aryabinin@virtuozzo.com>
Date: Thu, 5 Sep 2019 09:54:36 +0800
In-Reply-To: <1567607824.5576.77.camel@lca.pw>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <CAAeHK+wyvLF8=DdEczHLzNXuP+oC0CEhoPmp_LHSKVNyAiRGLQ@mail.gmail.com>
	 <1567606591.32522.21.camel@mtksdccf07> <1567607824.5576.77.camel@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

On Wed, 2019-09-04 at 10:37 -0400, Qian Cai wrote:
> On Wed, 2019-09-04 at 22:16 +0800, Walter Wu wrote:
> > On Wed, 2019-09-04 at 15:44 +0200, Andrey Konovalov wrote:
> > > On Wed, Sep 4, 2019 at 8:51 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > +config KASAN_DUMP_PAGE
> > > > +       bool "Dump the page last stack information"
> > > > +       depends on KASAN && PAGE_OWNER
> > > > +       help
> > > > +         By default, KASAN doesn't record alloc/free stack for page
> > > > allocator.
> > > > +         It is difficult to fix up page use-after-free issue.
> > > > +         This feature depends on page owner to record the last stack of
> > > > page.
> > > > +         It is very helpful for solving the page use-after-free or out-
> > > > of-bound.
> > > 
> > > I'm not sure if we need a separate config for this. Is there any
> > > reason to not have this enabled by default?
> > 
> > PAGE_OWNER need some memory usage, it is not allowed to enable by
> > default in low RAM device. so I create new feature option and the person
> > who wants to use it to enable it.
> 
> Or you can try to look into reducing the memory footprint of PAGE_OWNER to fit
> your needs. It does not always need to be that way.

Thanks your suggestion. We can try to think what can be slimmed.

Thanks.
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567648476.32522.36.camel%40mtksdccf07.
