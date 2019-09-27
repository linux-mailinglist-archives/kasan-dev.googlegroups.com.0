Return-Path: <kasan-dev+bncBAABBI5WXDWAKGQEQ3RUIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id D0121C072E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 16:22:28 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id f9sf12647475ioh.6
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 07:22:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569594147; cv=pass;
        d=google.com; s=arc-20160816;
        b=JGAxEiHAqzaj5F1xuI9Cn8uTXRaTp80Ijly+QbFHzELAMHAT90/YeHE+JsVJ7vQqr2
         wFWgQUSkG6dezHVmBaN6SnthnrtOhPAu8T0CsXw9cLoN/l1NoFyrvzE19oWQKpmZoeID
         +xK2af7QS9xd2fkfY2sgPuAb8u6IllVMgLaxI9e2gypVefB7XtqB9Qi2x0mk/7rKEw5J
         md/mqjrLa5vnUgesuz+260lk82BbZjSb3x1btlL22xSMya3Gnn9D8kvEoSoQ23UWVTem
         OI356ys4SHxbidym9LfVsgWnblXv8jS9JUpfJkk9gLoaoCuE5XLsx/MxNy2vGb3Khwmf
         Suaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=CIYlpZvkjSmj5HeMPfru4+cLa8S2UC1TWmrj5ODkmis=;
        b=OEY9djebmhzDhWIiBBpE5XEOYBz5aJ1b8+BlswmIAtsWRg9VGdTdbeSZGvrAeZso13
         D53y8c4p64Nnk9qp12p1uSB3DWPnr8yDszyZa/SEPvoz+g0NQss44EY59OUsoXogJGbM
         wfummGG9jvkN4tfcHbp3JTAtCUQ833vnwMHiS93h+A7xRsA5dtijmKIb2ujJz49agasm
         OZ3QvecICpWhxKhOoHXZjSmT55Pm6rrANJ0q2QI3U5kmu4x3FTYLtlRfa6Ydlmbpr1Dq
         bn0TGwE24CdBUGZmYX1+6ZcqljcQm+KsbfICzmKEOMCNNqEQXpFsgeBj1Oe/34YrR5gd
         AP9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CIYlpZvkjSmj5HeMPfru4+cLa8S2UC1TWmrj5ODkmis=;
        b=TSxY2cT90XYJQ+6oS7FHAkbyXVlXSVxgcPMsiDOoFv4/6zD6DLDyDS/unnVIUm1N0g
         nXKzEaQ8FMUBrJ2GfGan2+z/Oa/kHRix0SslWkGlTeDpqEbIxPZ8X2Q3IeRYpSfhAywx
         K/636rT12xJyw9eVIgMlyGEMNQec6V+/wgx0IQOQE8I/JE5plfx3Jfozp2BFcoVGxIHv
         dc2Sttd8+ubiz7ofH4LeJvhpcJOCjeo7ULOve+mQKsqeyjWuJX2F0W5GEIFE5zed8Ten
         UhLRSSV6kkrIpdfAsvVTTERoClcA1eb0LLwRaZONEglvZl7MpWtL1b1J0OsWoSdmF5BV
         UkTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CIYlpZvkjSmj5HeMPfru4+cLa8S2UC1TWmrj5ODkmis=;
        b=JKwzwrwc4YgiETsy7YZkQxlmTvt8ktN5w70sq6tkrg0p/CJSXHfsrYxbvQ5x7ltUFt
         hV2ZQzZfYdL4HHhekAV96mB9ebru4m2mdcLkshFm/WmxOu0mN7Yido7RX9zkzwUame04
         OF5LXMkbV3NhbSb88JPTerPIQDKOGzHaGM18e5ZpNP8GuKcxPukf6UaMePj4f6LgoQSW
         dDiYFGMTExMnNL1x2ADaGV05STzQuPaTkXyq/dSEEZhxdH1IUXZe96e2sAzV3teE4b2g
         i9uVzQmTLQVhyAz6sV3KyEffA1cKx4yCHi2yW+83ubFmbt4uUr4MacvEZbVeplgN7yZ1
         PNzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUKU9cDSEJhvFuCRGGShqVKOVdv/945Cz1XRVbovqnQtPEmOAZ0
	QtFw2GCgu+tGt9SjO+827yQ=
X-Google-Smtp-Source: APXvYqy0ZEVgyvEEGqyIWwUoqlJ3Ty2n75Vltljxo3g6/l8Fu6oHAKfesbCbVL9zRRw7i3uIeZuDOw==
X-Received: by 2002:a5e:da0a:: with SMTP id x10mr9170945ioj.286.1569594147607;
        Fri, 27 Sep 2019 07:22:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1589:: with SMTP id 9ls562591ilv.4.gmail; Fri, 27 Sep
 2019 07:22:27 -0700 (PDT)
X-Received: by 2002:a92:3f0a:: with SMTP id m10mr4889644ila.158.1569594147318;
        Fri, 27 Sep 2019 07:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569594147; cv=none;
        d=google.com; s=arc-20160816;
        b=0Isv+Y5Px3sGlob5ukptC2E5a70MtlEpQL9VbtsVtRXyYSLAGyu+QdPpBSV4xgh14G
         etTREp6t5kbfIov0yKCfqA3MH4pRRhdD60m1Ff/B3f6BpOCTAzt5AUC2U8onKHZeWEP4
         sn2yBnSgmIhKPSF1w0YCkN8PB00fCUhCo1sp4OLm+MO+LV3f4hOl3r/DJRZAEG57IcBp
         y0R8Jv/nsHhT8hVoWuop3QAZcsLNUpTPrf05bJ5zp1lC/9M9HYJKyJDtF7SAnNeMmx3D
         laayoMS1ocsWWsw+Pbqq4rHBZLHDaEwLsvcvLfa+S22ty1kClXgcaiXSFb8FOyHOjzNB
         swdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=UiQ9feDIESVenJae2CXR2GA1/8aJ+VYIufyXcZo9cDU=;
        b=QHyGmThN7d0EtEiqVh8v8LxuZ4bcvcsQZlkaMoZG60Ef9xsK1emhmWmUMsrryXTn8z
         PnkkfFtz+vt9aRPsDrCHTkK0FTyYG2IPWHdgYXymJqH+MMDeqnu6waRF1TgRphCJFeIw
         7jmHA0rNcII22IkH0wMKRS5xyOVRNNrJ5RMvboWQ29C1ItGk/rGknx9mJWXDlbwapl28
         CKDhdCn6+OtH83uVTymnDzUz76nTB0lns14obMD9OsJmkCZ8Aa2eFzlPKZ57GFSN1uPK
         +RfdVHjkhUD5GQ5KdLTOcnPkaI50SthGJY2NaKyLqXyCkgemfSzKxsWmy+rC0KRtRMhs
         kEkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id f11si344480iok.4.2019.09.27.07.22.26
        for <kasan-dev@googlegroups.com>;
        Fri, 27 Sep 2019 07:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 5969bb150a984d08adde2d2ffdd3d229-20190927
X-UUID: 5969bb150a984d08adde2d2ffdd3d229-20190927
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 399212952; Fri, 27 Sep 2019 22:22:23 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 27 Sep 2019 22:22:19 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 27 Sep 2019 22:22:19 +0800
Message-ID: <1569594142.9045.24.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Fri, 27 Sep 2019 22:22:22 +0800
In-Reply-To: <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
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

On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.com> wro=
te:
> >
> > memmove() and memcpy() have missing underflow issues.
> > When -7 <=3D size < 0, then KASAN will miss to catch the underflow issu=
e.
> > It looks like shadow start address and shadow end address is the same,
> > so it does not actually check anything.
> >
> > The following test is indeed not caught by KASAN:
> >
> >         char *p =3D kmalloc(64, GFP_KERNEL);
> >         memset((char *)p, 0, 64);
> >         memmove((char *)p, (char *)p + 4, -2);
> >         kfree((char*)p);
> >
> > It should be checked here:
> >
> > void *memmove(void *dest, const void *src, size_t len)
> > {
> >         check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >         return __memmove(dest, src, len);
> > }
> >
> > We fix the shadow end address which is calculated, then generic KASAN
> > get the right shadow end address and detect this underflow issue.
> >
> > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > ---
> >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> >  mm/kasan/generic.c |  8 ++++++--
> >  2 files changed, 42 insertions(+), 2 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b63b367a94e8..8bd014852556 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_memset(=
void)
> >         kfree(ptr);
> >  }
> >
> > +static noinline void __init kmalloc_oob_in_memmove_underflow(void)
> > +{
> > +       char *ptr;
> > +       size_t size =3D 64;
> > +
> > +       pr_info("underflow out-of-bounds in memmove\n");
> > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > +       if (!ptr) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       memset((char *)ptr, 0, 64);
> > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > +       kfree(ptr);
> > +}
> > +
> > +static noinline void __init kmalloc_oob_in_memmove_overflow(void)
> > +{
> > +       char *ptr;
> > +       size_t size =3D 64;
> > +
> > +       pr_info("overflow out-of-bounds in memmove\n");
> > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > +       if (!ptr) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       memset((char *)ptr, 0, 64);
> > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > +       kfree(ptr);
> > +}
> > +
> >  static noinline void __init kmalloc_uaf(void)
> >  {
> >         char *ptr;
> > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
> >         kmalloc_oob_memset_4();
> >         kmalloc_oob_memset_8();
> >         kmalloc_oob_memset_16();
> > +       kmalloc_oob_in_memmove_underflow();
> > +       kmalloc_oob_in_memmove_overflow();
> >         kmalloc_uaf();
> >         kmalloc_uaf_memset();
> >         kmalloc_uaf2();
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 616f9dd82d12..34ca23d59e67 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_poisoned_n(u=
nsigned long addr,
> >                                                 size_t size)
> >  {
> >         unsigned long ret;
> > +       void *shadow_start =3D kasan_mem_to_shadow((void *)addr);
> > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr + size - =
1) + 1;
> >
> > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
> > -                       kasan_mem_to_shadow((void *)addr + size - 1) + =
1);
> > +       if ((long)size < 0)
> > +               shadow_end =3D kasan_mem_to_shadow((void *)addr + size)=
;
>=20
> Hi Walter,
>=20
> Thanks for working on this.
>=20
> If size<0, does it make sense to continue at all? We will still check
> 1PB of shadow memory? What happens when we pass such huge range to
> memory_is_nonzero?
> Perhaps it's better to produce an error and bail out immediately if size<=
0?

I agree with what you said. when size<0, it is indeed an unreasonable
behavior, it should be blocked from continuing to do.


> Also, what's the failure mode of the tests? Didn't they badly corrupt
> memory? We tried to keep tests such that they produce the KASAN
> reports, but don't badly corrupt memory b/c/ we need to run all of
> them.

Maybe we should first produce KASAN reports and then go to execute
memmove() or do nothing? It looks like it=E2=80=99s doing the following.or?

void *memmove(void *dest, const void *src, size_t len)
 {
+       if (long(len) <=3D 0)
+               kasan_report_invalid_size(src, dest, len, _RET_IP_);
+
        check_memory_region((unsigned long)src, len, false, _RET_IP_);
        check_memory_region((unsigned long)dest, len, true, _RET_IP_);



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1569594142.9045.24.camel%40mtksdccf07.
