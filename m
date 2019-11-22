Return-Path: <kasan-dev+bncBAABBU4X33XAKGQEXJONWEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D0591066E9
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 08:18:44 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id r4sf4241002ioo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 23:18:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574407123; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQDznS+tvYGDz/XanMf5iruoVNHS242P4IcO67g83ErVky38l8nRk+seeYR2VVEO/E
         Ot1uuVI5ddSBv2Ntgwv/3dL1ANvNS4gohRYZLMfZuNkflUM0yWfxdkCS8IylBBYjoOeA
         bEUmSe6Q7MOqmP+Tg2A7d6F/IoUpUyn4A2gbtN3ZPr+Kxg9HK98dGf2EqaKJgHmlew0c
         PZUWahE+5xvVp9+0rfbDEUyQ4e0icnKFbc3lwJJR3ySnqETU/4WH0rSqjLyjdhH9BbZj
         FTqMzXJ26V87KTXxJNQm1D3sWYWD3ywvHv/UBfqet594PHmm+0hx1Y6cUF5JldDrlFrW
         K8Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Nc0bVfudsOOaTJqdHN66U4G3S8V/LLKDwh+vrQecLN0=;
        b=yGXZxgGBjJ+uzldsBbI1RaExZG0VJV6bGmb6SD9BUgqz7l3/SgNG2Z+3Pn+wS0w0yd
         dtZ4vDIQ3Ytzt3D/hQXED2PITlGs8jPUu1GJiNfpMVXp2rwRiSaEprqoFDMQlUVAvyEl
         GOstyQZb0xCrN8UvhgKzBbVoPoJmIs6ro4yMT9gOmHtxi3HFutvgW+Py/i4o96qpCcCx
         MY6o+zYWDxHoBO2CHZjbEwZUWFzSVrtllIks/IxfoYmUPCSki+Jj+34OMexyMtrARc73
         5BzNA+IJB+WOaGYdvVTM0cgjUlAL9juIHYHttUus4Fraimcve3fXPkcass/SX1Qw0oO0
         I8Mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gHxeAf5s;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nc0bVfudsOOaTJqdHN66U4G3S8V/LLKDwh+vrQecLN0=;
        b=izIlCReZ2hsOTfu6BstgJmKytASv4W8LDOVKh/kbHXcrwJgvr2qIwsnwVY79Kxi353
         wzVcWTs8Go9G3qhTUWtJbz1oSTaFeGGQ9cvThCMWzWSKkWeLWkjVNKwPh33R3LhllVis
         yzY4rmflkBZJcHdb7NZDRUhJg2ttnbZlTKKAR1ylKWJ9lzi4C24byajXD7/CRZGwauP2
         Szjl9tcRchUkrw3iMtiHGKZ7B/U76fpVB/cQLGa24S/Ir61zXV5brv3YEUzZ+of0doKo
         n+J01gK/8wUeqwxSa999aVAX8gRYuKQAlWXH3EF2iMPT6Lh05hyFnFqR6j93nXyf3edf
         P8YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nc0bVfudsOOaTJqdHN66U4G3S8V/LLKDwh+vrQecLN0=;
        b=Z3LfdSaJ1aX7RAikpHeesX1MUrLPXxFmCE29iO1ws4x89Bcrpsce+9oDbJ/X0Md+jG
         dHArUoBcAyTeUfUVoQym0wBntjCdnIUwaCTXBkJ3rNj7yK5pCGvS90MC2bLuFWG4VYS7
         QRmv0Yy4/Yw1leQ9b7YZ/TpvBtb2LIzN7LgF8hmkQ5TxpgsSCvbuSdSzko2K07u4jbSF
         fZWd/pcZe0gZtuBCb7S2ZHoGQ5KuWvdr3TRekXpg6+nY6jTDNVi+7al2+SWgpz0rDvYZ
         3WiA2CTTMwqZEz3YNVGiwy78+Kd4fskd1OKd1fCQ8t0vTcESOLCIpypG5K0mzd3AnCla
         Wlcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFWpS60V2O6BQGteddE6mqqa9Xb6WgDJgIS5W7DOwrEwxL/Mup
	JoHks09Cj/5qaJQ6EVNyEOg=
X-Google-Smtp-Source: APXvYqxNTNhYgWKcAjCTISZHZSGswU+SSti7Ly6Qq91aHqth6gUe2iJ2d35IzD/Bkeuqt15cEITbiQ==
X-Received: by 2002:a6b:5913:: with SMTP id n19mr2587850iob.306.1574407123220;
        Thu, 21 Nov 2019 23:18:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d143:: with SMTP id t3ls1624544ilg.6.gmail; Thu, 21 Nov
 2019 23:18:42 -0800 (PST)
X-Received: by 2002:a92:9117:: with SMTP id t23mr14271884ild.307.1574407122938;
        Thu, 21 Nov 2019 23:18:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574407122; cv=none;
        d=google.com; s=arc-20160816;
        b=H/uNGU/zx/R15xDlQXryrnT8VUlS6gKjp19n5Y1VB4l1OMQKxofiA9Mia5KVaKM86n
         LUw0P199K/eCAbyM2aU4RoI0BBuA9VTfXbytlG/f+UeFvjzmqgUw3LXTRLt3OjjkDC2y
         95lmvcHjPZ3XKhxHcmJ0sNEF7nbOT3qUVS51rfZWuOQs6CH9wl/yslSr07HQfYALW6EN
         Q9uHxwD3HG0CRDNxf8V6Y5adbi7/P6W/DSyPUko+DD+cZn5WRHslIg17Q9e+jt4+WO6k
         5MkaZ614JmajXJ7wX968/nppx4TqJ2jD2RUPD1SMoFIx6VIlE8pa4Y0KuGsgvOiZLnXg
         IwCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=Rn/XoDq5loIZaVO1pS6BYoAXB6sUp5RYn3/dfFUf7zc=;
        b=LViNYlXqXp94CG6lhe2NITPe0JmMNvZvIJBMJEPNgRTXZAOtWolMTq+/oCe6ifCWnS
         nmb4Dm+v9mYYSRJSsmBA3IfquX4INEFQ9slGLipHAHMm6tHV2H4qo2w6pFMtaCEhyTyy
         ax+QgJsmuC7dDwHwJp0c1xGPRXWtC/aLjlS5qg9cDrMuxUvGMxjQy6ISK3iXy0/onqav
         66Wew5b9jqyaaHc1/VJ1KZ2L28GSAFgSBH8ZstRmICBd2CHfFiQdGo6s/JdZZohri1+f
         G3waSe7qppdlmnbGSCOVoDA0ZUxqmbrmKbZJ3E/mTKY3tOsnCdVuP8ld5TnVwNP8J9q2
         UkUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=gHxeAf5s;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k25si165648iog.5.2019.11.21.23.18.42
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Nov 2019 23:18:42 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: a81b81e6f8804a6bb5c3d97cbf665b8d-20191122
X-UUID: a81b81e6f8804a6bb5c3d97cbf665b8d-20191122
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 295321122; Fri, 22 Nov 2019 15:18:37 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 22 Nov 2019 15:18:30 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 22 Nov 2019 15:18:28 +0800
Message-ID: <1574407116.8338.10.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Andrew Morton
	<akpm@linux-foundation.org>
Date: Fri, 22 Nov 2019 15:18:36 +0800
In-Reply-To: <b2ba5228-dec0-9acf-49e9-d57f156814ef@virtuozzo.com>
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
	 <b2ba5228-dec0-9acf-49e9-d57f156814ef@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=gHxeAf5s;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Fri, 2019-11-22 at 01:20 +0300, Andrey Ryabinin wrote:
> 
> On 11/12/19 9:53 AM, Walter Wu wrote:
> > KASAN missed detecting size is a negative number in memset(), memcpy(),
> > and memmove(), it will cause out-of-bounds bug. So needs to be detected
> > by KASAN.
> > 
> > If size is a negative number, then it has a reason to be defined as
> > out-of-bounds bug type.
> > Casting negative numbers to size_t would indeed turn up as
> > a large size_t and its value will be larger than ULONG_MAX/2,
> > so that this can qualify as out-of-bounds.
> > 
> > KASAN report is shown below:
> > 
> >  BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> >  Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72
> > 
> >  CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> >  Hardware name: linux,dummy-virt (DT)
> >  Call trace:
> >   dump_backtrace+0x0/0x288
> >   show_stack+0x14/0x20
> >   dump_stack+0x10c/0x164
> >   print_address_description.isra.9+0x68/0x378
> >   __kasan_report+0x164/0x1a0
> >   kasan_report+0xc/0x18
> >   check_memory_region+0x174/0x1d0
> >   memmove+0x34/0x88
> >   kmalloc_memmove_invalid_size+0x70/0xa0
> > 
> > [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Reported-by: kernel test robot <lkp@intel.com>
> > ---
> 
> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

Hi Andrey, Dmitry,

Thanks for your review and suggestion.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574407116.8338.10.camel%40mtksdccf07.
