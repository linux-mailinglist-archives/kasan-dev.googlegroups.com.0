Return-Path: <kasan-dev+bncBDE6RCFOWIARBOM2W36AKGQEPM2DVUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 503D32927BE
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 14:57:30 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id f14sf5201969ljg.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 05:57:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603112250; cv=pass;
        d=google.com; s=arc-20160816;
        b=HjOk4Jf1pij2jizHoOAmDHQCt0vV0TM67Vn9fLJ769b+7c+dwOMfLs8lyUB7+LBN9M
         +tKsjD+Q/0KDjdqwbJq+ToyFnKqr0UGn/2hdBMsZXe153DdO2+c97s9uIaKBYPJlNUld
         ForKRdNuAQjQMIB3keSOd0PRWhujrM3JZ2TFjs0tjzmhkwlxARtQRxrw5m+k3rrwaNv+
         VRhddd7gYyqT7AOSUdaa4Z2ofeFoM3W2FYaoDIQhrL5ecs0V52ABMzjoBrg51EBarkIh
         Y8iTgUIi0cG55nBqoKy3HYF1TLuLDLg5Yiea0kV92M1wRiHf17TGNninigIaPCZcX6j9
         Eyhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HM45UoBcgzrMsok/5YEY4Qy8G/Mt81gPNHQYN42kzPY=;
        b=dPs2i48Hp0DSaCPJ2Cx3VTDEryS+zWHrDq43LPfCUJPwaiwkLq5tjdvUcAADt/781a
         J3+vmauB/aJSzp2DAFcUdIQDNS9D/F2aLZz0ckMo/JxJpXaF85NYfk4Ems9ar9NNuxwk
         5ZncrjkrwCBjpqy1CKO+wgkQx62mZzMkhsUzZeKdj7rlromjgjL53m928Sk1fJC25hr1
         GH26drNHy1g+ChXrrb74jxkFm+gTGjM3M7+hSe6B/PVyzZSOH48C9XWXAL2qVPWw6Wgc
         A++7/5nUKlg2xLDxqs9ClQPIpXt0hVKLzgrd9aix2NlyoXHRfK4w1yppLAtL+ZTcXpUQ
         X94Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OzjU9n5u;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HM45UoBcgzrMsok/5YEY4Qy8G/Mt81gPNHQYN42kzPY=;
        b=P0a/zq8mu1lTxOtxBo60FSON9x85FBLDp3llmxppg4twvS6hfeOXmtCJipNAAI9SOn
         eZSfJvARHy3W8an0/Gy8HV2WTirM1ZSnH2FIt07sGmRyKayw5bDYlcMVYNp4OgGY6v4i
         G/CSoheaBq2RbD1MX074wLmnjr5WlteKxV3eVp61Qyv6P46QVjm0YNa6ByQfJ+umyDNR
         xyJ7whqpKOjICN4FLLBySwKG6XLbp4BUAtm5luNEYc6TQ6RcdOwRvYpJ5jSFAk4gZ9gR
         RDFq1R8E53HGWsKztVeuGyYZ4YBJv1WByJBQHBrWNHlYqds/ZHUzadtM8nML0sa5PXQL
         kcmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HM45UoBcgzrMsok/5YEY4Qy8G/Mt81gPNHQYN42kzPY=;
        b=nfuSKMMRvP+lWGPq1wIiKWU9VM275Knigbq0/hZlwdzV8jNQjWjLEovHgGjuxgGTrI
         MvQD1BhCFp/wa5D0BIFXRELc3uP7Q0dXoX6BxY4M2Bi3pPp7xgDOYw+DUX4zS14269Xs
         qRPeunKfUK4HHtsJMea/3TrjG9wxWqD51wOJ6SHWdgC4W9pl8byTfhlUvWHQ6jOlCLtU
         p9kPVUQ6NI9sGMU+uKHtHEIMdVnLw5MxNedPU4hUBdLXFXgIofvCtpyt85ggB8kSDEvr
         7D94q0bAi6x1T7YqRCDgTaGhs4ImFSL44zuLCU66CD2atfH5iQO2Sz53lJGxUwQu3QZ7
         aELA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vFEwNwMkIfCHm4YGaDzUXV7LZogg3lvm2d3KSVZJ451c9MB4H
	G0kssiy3tf3OQobH26q571U=
X-Google-Smtp-Source: ABdhPJyBa7h+ddy0A6MP4Us54Mno5ZmZyukEwMU9UVx19L7/LWadGk3WyaYSRNuUXXQV7IoHmjsdGg==
X-Received: by 2002:a2e:8e88:: with SMTP id z8mr6851497ljk.13.1603112249918;
        Mon, 19 Oct 2020 05:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls4001428lff.1.gmail; Mon, 19 Oct
 2020 05:57:28 -0700 (PDT)
X-Received: by 2002:a19:857:: with SMTP id 84mr5462191lfi.235.1603112248891;
        Mon, 19 Oct 2020 05:57:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603112248; cv=none;
        d=google.com; s=arc-20160816;
        b=p0Icq9IPH69ieyYxpOZNAuZ+gz8mTyqyXW2f0cQir05DyDh636+yX+B0OJjruCjqvb
         N+VUNMTslAbn7YkkLKGy25xE9B2uWF1szPbjib2nxE3Zul628XCw5flRdccYPSIsSV9B
         aEUfxlpZF4LjLqpeJSSqjmfUy+jI7HNKAc/TDg7Vme5w/YMPslKsctwA6GvNugKPTl+8
         QfASoDtdTfNYvKGbacIc7Of0/tOUJgaORQZVeyp6wlYKK0eFx+EUYvIcHx76TbeRP2s/
         UGmr1uqVUDdr8LIQEFB2zo48xRIB4XsBWJ/Yil5JUiVa1I/hdsWFbMVDAPo9JYKQqci2
         Vdkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5tVla9jFf5QPewwv9fw3dMCQOBk+IDXwQ8zt7SAS7qc=;
        b=ugcom20R+CkZgScoRk8B21R1BwBcRGbR6Nq3UulzF8Pp6ZB/Ve6YX42gLb+byZ2B90
         TGVbvDeJgmy19uI3w4tw65ZWmINaVeerp5YMDeRoarmNYY5CO3aptbtCbsoc4susIB9d
         gGnrDlRmH/Inks0Zt5buTdcAWjU0cnmP0aZG4xI4OrPOFULnJ8DNj29NLPcnhw8G/mbz
         zbcx6QLyPWmXENHC+WBotyNUvz0p22gGbTRw+uM5LlC/cTY1NlTUZZChBQOly1dZo6aQ
         fnRMPwWU5PElP83S1EsGQvt54ecauIoGX3BcQ9wBMKYADmf44Y5NvDSXdS6A4gSrbdyi
         Awaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OzjU9n5u;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id o22si50625ljp.8.2020.10.19.05.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 05:57:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id d24so11759484ljg.10
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 05:57:28 -0700 (PDT)
X-Received: by 2002:a2e:a162:: with SMTP id u2mr6756108ljl.283.1603112248557;
 Mon, 19 Oct 2020 05:57:28 -0700 (PDT)
MIME-Version: 1.0
References: <20201019084140.4532-1-linus.walleij@linaro.org>
 <20201019084140.4532-5-linus.walleij@linaro.org> <20201019093421.GA455883@linux.ibm.com>
 <CAMj1kXGgrtj79UQ7Ei5NEEQ1_ALTJRVALFnjOmhZLb_4tSHauQ@mail.gmail.com> <20201019100458.GB455883@linux.ibm.com>
In-Reply-To: <20201019100458.GB455883@linux.ibm.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Mon, 19 Oct 2020 14:57:17 +0200
Message-ID: <CACRpkdZ8aV2J-i59soJDpi=85BnuzwRPerWRMR8Odh38i56d6A@mail.gmail.com>
Subject: Re: [PATCH 4/5 v16] ARM: Initialize the mapping of KASan shadow memory
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Abbott Liu <liuwenliang@huawei.com>, Russell King <linux@armlinux.org.uk>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Ahmad Fatoum <a.fatoum@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=OzjU9n5u;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, Oct 19, 2020 at 12:05 PM Mike Rapoport <rppt@linux.ibm.com> wrote:
> On Mon, Oct 19, 2020 at 11:42:44AM +0200, Ard Biesheuvel wrote:

> > > > +     for_each_memblock(memory, reg) {
> > > > +             void *start = __va(reg->base);
> > > > +             void *end = __va(reg->base + reg->size);
> > > > +
> > >
> > > I've killed for_each_memblock() recently and we have now
> > >
> > >         for_each_mem_range(idx, &pa_start, &pa_end)
> > >
> > > instead.
> > >
> >
> > Will the enumeration include NOMAP regions as well? We could actually
> > omit them here, since they don't need KASAN shadow.
>
> The NOMAP regions are omitted.

Hm I suppose I need to update the patch series once the merge
window closes on top of v5.10-rc1, then use this nifty facility
in Russell's patch tracker that can update pending patches.

I thought it would be safe to put them in the patch tracker after
16 iterations, haha :D

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZ8aV2J-i59soJDpi%3D85BnuzwRPerWRMR8Odh38i56d6A%40mail.gmail.com.
