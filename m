Return-Path: <kasan-dev+bncBDGPTM5BQUDRBMFEWL5QKGQECZE6UWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 26C57277116
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 14:33:54 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id 18sf2443721ilt.9
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 05:33:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600950833; cv=pass;
        d=google.com; s=arc-20160816;
        b=CK8Pps+NHE16gSi9GZZXphJnUCaDWkxjUrki+X4R1X9O1JgQKetCuPDH+ZsWG6H60E
         njrp6otys9/eKeuOZ6BYgZdaHP6W2T8bkoGyiha51O4ab54SUNe855Hca67HXDvrLs60
         mCCuN0eBiBx94BPir/eItHscwfrjqzE8oXl14GcgENxr4/wxyFA6D+K/nYJfihioLXL1
         lP5DhHTAJYg/FLZgKyy/dAVeCcAwhuu6ayKhUfkddhaH7IDwV4CFsw9RCAfFd0+RlMyD
         h4Z2YFLmQrqmJ11GzxXuDJt/0C4ihK9z6I5RXuOuU6ZHvIT4fpACMYUym7Ry5aJhPMLx
         U10g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=2xC3Dzg2kR/3rRDJdNwySm5cY7xU9YCzPjh+yeRXOVw=;
        b=yvUjtHim81coE4pn1fCPaW+39wcpD3dSSWAaEdbkr6cm2xhCF6GyYsWA71+AomUTgT
         oBA0LNC7adNR6D36k+L1cOru/oSpgCNFwTEgmH+jySWLFzJdzP62Pu900+bedl1R4MzY
         0rD/xpX+imOwjkYLuUlDb1ii7ESR1KqNZbdkCXtRXEIoaneyTuoGveFbImTNgmrpEZBT
         wzj8pf/aaImwY7hSe+E5i0XHQMomfZ/otUx4NIgwOdcatt8Hkm3O++2+fNx4SprFFxxD
         tHNhcKYJrVq2kypOyaygXS4gpc0vr71yGJQd38vHsNMJk4e3F3Ex51R8SPczfDhVW8Ry
         +PWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=YgF878XP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2xC3Dzg2kR/3rRDJdNwySm5cY7xU9YCzPjh+yeRXOVw=;
        b=XnMbwfijjzkjT2KieqkHZL8xL0OQOC9sgEDzX29RzgIS25VX+dgcVkDrG9G0/43B8/
         /Qi3UKf5DZ+zeYVRvvpbJ3FxijriKWtaIXatKfQE6duZ/I8A9QvEoqVO1NnP90zzoyCN
         XOUA3vQTHVJMnFjdaA007kny0xuKT7jZDOztSjVKstE1elZUO89qLpVLMOefdDCE6mjB
         ciE9tRqj9akmXYYmog/fbg4+2CgYtasYCULfNwozIbge0vIhxxK7zRjmiUE84HMeCcAy
         sQi0olREMOwcEqm/+oF4CX046U0ah+hNobGTSY4HvJminngX3F5hTp/xqt8oer1+QEui
         fM1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2xC3Dzg2kR/3rRDJdNwySm5cY7xU9YCzPjh+yeRXOVw=;
        b=hGRqtZ862I3t/D8tP72yoz/ic9wn6lFEKNJRRaVEpNO47F3KCKehuKFeDLUKfO+UdO
         UmZr2YhlF3LhHsp6w2mv553v0uCzlgvKvpOagz/0SF5njjlAjeIIrGULMDucySdknvLu
         f2G8PPktEre1Gewys5pvBub/xDDCpmpMWa1BLgHl/nDiTz4IFdZbCb0nSMoi/JYPeDJN
         uE1LqkQi9AKMDRzWYDYE4UkGQ1FYsV534wvTjWZjOwt7ZrPDKZNowSOCH7mVfHqbyvlB
         pLbd37DS105eZsQT8SxgloJNx1Crof4VXX6ENSt2HOfWNpuEjlkeOaDkP1woXGxW6BKP
         eeCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533szpaUSYyRyMWzQKs1btIZJz2LvSwt5+Q6fXJ2Bo8m8a3AT3pP
	3hBI/aoXe0pSLJ6NuUsgUuU=
X-Google-Smtp-Source: ABdhPJyf70iMfgy+aCbrqdVMv7QV03QpImn3ujsFFM8ev5FsWTPYdKuFGHWu27mkzmRMRjHbe4rLKw==
X-Received: by 2002:a05:6638:ec5:: with SMTP id q5mr3437538jas.13.1600950832861;
        Thu, 24 Sep 2020 05:33:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c64b:: with SMTP id k11ls376721jan.1.gmail; Thu, 24 Sep
 2020 05:33:52 -0700 (PDT)
X-Received: by 2002:a05:6638:cdc:: with SMTP id e28mr3434351jak.100.1600950832378;
        Thu, 24 Sep 2020 05:33:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600950832; cv=none;
        d=google.com; s=arc-20160816;
        b=Piz6/UTjFXl6YSl7QZe+jE3HwxIoxUdNzOPMblBR5akXHCZO0q1dgGLV/6aSBVUb4Y
         yUizDhIqgsTQf+lV6V7M2GHxp4W9gJ/GA3H9JG6mE3xC1UjY6zWOqoPIuuFmwxYkdI6d
         XOinIpB6X6wp7nGcTUkVys19Zd4pxctYHPuqjp3dAq7o+C3RvOpK2Jh88ZOjRdcc2dVH
         2cHKRxoHeO5NxAW/Z9wnssGa6pyHtrmSPbKR7hrXkUJCjjAkclm6WG6Y9Du7QZAgDqZh
         PewEVfS1sYraHIWQOUiGRNMXt2zsGthZBtDKSOYrBdU9MREs//V81pMvcYCMhKPhkRvE
         005g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=3xhvL/jxHoFM4lCpaJFVgA5szl9rK3NZUTpqOY0oS0A=;
        b=GYcaRQnNTHXK5qLhTnMPRZF5EUBCjjIeRnF6hZZ90WK1N1lpDZh82rwiX4QnMZJ20P
         4kMF92Qjw1JjWXaueuNw5ChML5YhvxCKK5uDBCok+/JsCmCOh9npA+LpkMoiuxALMO9Z
         O1Oyv0KTFNyc9JoScUuqAnsu3sifgoNTT14B7p8zN8AUufSxfcR4G+E0c7jNlq4uv9mP
         CPZE/zVCjmmpcnr89l/DRatAlS/8Nklz23DFKvg89dOt2tZzM0oX4UCMwsQiaX7sxQpU
         WMdUyz/3t8dz0ffUj+Pt7s7jnJm84Ovj/SXQyfUAGrP8HLE07hzWh+iSIKO5qglg3oSY
         qOeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=YgF878XP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a13si182834ios.2.2020.09.24.05.33.51
        for <kasan-dev@googlegroups.com>;
        Thu, 24 Sep 2020 05:33:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c6d82b8a50b644eab02e850af9bf1686-20200924
X-UUID: c6d82b8a50b644eab02e850af9bf1686-20200924
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1621613781; Thu, 24 Sep 2020 20:33:47 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 20:33:42 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 20:33:43 +0800
Message-ID: <1600950825.19591.2.camel@mtksdccf07>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic
 KASAN
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Alexander Potapenko <glider@google.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner
	<tglx@linutronix.de>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, "Linux
 Memory Management List" <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Thu, 24 Sep 2020 20:33:45 +0800
In-Reply-To: <CAG_fn=U_dshqBB8HBhGyYnn_vScTOcLJX=mfU+8Wi5wjZL2oYA@mail.gmail.com>
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
	 <CAG_fn=U_dshqBB8HBhGyYnn_vScTOcLJX=mfU+8Wi5wjZL2oYA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 06AAE36FCA1A35D7BBA6DD440E2BA708F1295AAE573EAC13CD5AE6AAD26BA90B2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=YgF878XP;       spf=pass
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

On Thu, 2020-09-24 at 13:51 +0200, 'Alexander Potapenko' via kasan-dev
wrote:
> > ---
> > Documentation/dev-tools/kasan.rst |  5 +++--
> > kernel/time/timer.c               |  3 +++
> > kernel/workqueue.c                |  3 +++
> > lib/test_kasan_module.c           | 55 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
> > mm/kasan/report.c                 |  4 ++--
> > 5 files changed, 66 insertions(+), 4 deletions(-)
> 
> While at it, can you remove a mention of call_rcu() from the
> kasan_record_aux_stack() implementation, as it is no more
> RCU-specific?
> 

Thank you for your reminder. v5 will do it. 

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1600950825.19591.2.camel%40mtksdccf07.
