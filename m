Return-Path: <kasan-dev+bncBAABBKUD27WAKGQEOGH4KMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 03448C9AEA
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 11:38:52 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id s39sf1623466ywa.19
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 02:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570095530; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUQ9M1ewiFBvsjjeOPVt7C8P0h3pD/6B4qR02CMv6dc13joPJXx9vto7wht7LRkHJK
         T2+E6DaK42WhOHuZkfpQ1P9C6p5z5q76cFrQcxMPoaY1enFhG2x4hV14Ljwiac5JDGT+
         YpHsWGw1IlnGP5uz5Yb4zTWx4BfkKNh6qcigLDHtE9WtG1ti5W1E4gJpJ67aU1ZnjJJG
         y9j5dyscB/y/vjDANkXqRaXwUknjE/aqz1FGPmCIXqdeJZoXu6LaQBCjBbsiK9iR6MkX
         k8UH3CyQLcAUqD/JjV9v5mFWquqD1TsILiMha9KcXEtZfpTWohnKdIHf/o8GDbk5QWGT
         OPkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=YhQwx4V07ydNUUdADPMteWvEy2lLxDzB7qxge+cyen0=;
        b=l311lJDdCiTRGVoz1JYUVPc36zXLwDwSTqD6d78XLKSceHKNOVrKhSZ8/Gub23AXcM
         Mj0XsdqZKwGP/KyNupwuTYtpMmImaEj73mWa2W/HfN6VHiwQ/fMYgOW+rpDhSVUsU6N5
         XQnq0fsuocrhxr11wj8CCLu70Ee6yCeZg6g8gON8/S91TAE5SdwctLNwAgkvu72Sr4/Y
         fRBDKLE4aZrXR6CYheIrXorodep3kDsept9XAiOG8T5MxVnlFdCAm3sEX48jSWcpM4e1
         7g5iR6sgyLKt8bSThiFWNCXLV0OLiGOw7AORPUxJF67/o7EgPC7Y5FgKDvBNxMeTQLRD
         8iag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YhQwx4V07ydNUUdADPMteWvEy2lLxDzB7qxge+cyen0=;
        b=dlP7g/AMKf5k3Xm1istCBNq4QGQ5W9oK97VuNCz1IYIqRrAIfhyR9Y0J7TK/OpwVOU
         8Nb8khFwWL4udwKHRxdkK62+tGPiNqRVF93mFfZG4XqKadPZBn0SPPOXAP7GbzwfX6QW
         hxDH5hxdyoVjf2SWkCveBsskgqM1QP8FYGqRkZJdTHNNBtyIQFfcZYNXNkWj28MhS+e9
         6V69F8G8AWI1219i61L2zTQR43XBbEtqDPvWia9JeI4exBZ/ZGOqe9fOAlW20DjPyhj7
         qoZnuKqd69Mr30sDjbFGNYOohng17UwzuaiWK9A3lB7ZLL2q1qrKk2ILe50ZdnfkoaIy
         NrKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YhQwx4V07ydNUUdADPMteWvEy2lLxDzB7qxge+cyen0=;
        b=Iv49cSoj6Wmi7zoDa4K07kJwpBibiId0bFPhR+RZ/oiR7T1obPY+vxsZOw9h4bN6bH
         1V+4P4Vq5oTswtc8XJaFBJvNaABfJqSE2Uij9EBTNPVD4RILyOpbSgk4PHGP30zY2uw3
         +6TU/AJ82JvCxhrz/QQrrksT53eIlhu/WL/BwVnUvR7W8FCh092fOPpxVIUg4Vlk4tuE
         evxnOi1kY5qJUBnoYrjWzAefJl4pr0eWzwgBdw4DqDC465Q91mis4ybD6aFklheYsIFo
         SQsMIvo9eAvvqr/GSJ6WTOtnBzzSxd/+M6O2/Jkn4Urfh76+9/MlCV9bxIw3JcEGx7PQ
         dkvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUy09FgaFQ8H60IOgMPJtyfSop1Djh4/BcmOG3+vPwSLKwR0t/g
	hX6RYMJfNQQGXH3Elk9x22c=
X-Google-Smtp-Source: APXvYqwPE3med5j9E7B0BSILfvrG5mhjQPIWm0M0vEkJBP1JuzUjV9Ejj6o0oR/lzsobbPfAVffFXQ==
X-Received: by 2002:a25:55c4:: with SMTP id j187mr5383645ybb.6.1570095530509;
        Thu, 03 Oct 2019 02:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:48ca:: with SMTP id v193ls341247ywa.12.gmail; Thu, 03
 Oct 2019 02:38:50 -0700 (PDT)
X-Received: by 2002:a0d:d945:: with SMTP id b66mr5845930ywe.446.1570095530195;
        Thu, 03 Oct 2019 02:38:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570095530; cv=none;
        d=google.com; s=arc-20160816;
        b=DdpNupSkSLnjh8dVPnq8N3RbTyBFe+GNbCgUwvEhBUFBsPrOr9ong2E1WV4EUWwglj
         jH6Gxauaq/TF0byJWMJw6wNNKXq8VKAsUcpZp7xtWXLit9zV0LEIzQKkQSlL7Wz/EdHN
         M29RCMNZWSG1YL8bI4AZochTRr2/FDql11W+F6LP0st8ghfeDeU63Fem99qgJkRlbHeN
         RnrVXa5a6Wg5vQOfdnasP4a6W+Ht5KYuwwfaXCuUa9kGVRtQ7RI1s14qYxR2ihNnbCjj
         NZWKct+tAymBksHvJkbeolblIDQ4LhuQnStvc4ukwp6pUCgcbUyrbmYd5ip9M0+sgsf3
         /rtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=esQ2nUrP0s+Gu6NevFsRIawxjviV4XHkWxO7TFApsBs=;
        b=h9yuX5bQGg6EjLvacAyEKrbI++poPmGxf1IHUaNAUXRAai/gZElLVB/MP8RHQ3PbPo
         62hkzgZCj1qGY/wNpiWpYe698RJl23eqe3lFX5zF0lMX/o4b6rNGTZ6Y9p3hiUfeTZuH
         3tGcfPnPv/8hE43dfYPBC9kkNiNHsVFGuvLiqSw/k6Py9MdrMJP5TYFnFLtNl9Tp6dpi
         JeozL7HHeM3lRdo3RbDlW376gvDMoOP0a+NgugWPFoyS6t+7N8SUnsv0oIJMBXkUbaAx
         sRchssbdzdg+BipqjxqtXG4TwvEIcvlJlVwsPgJgo9xbupcbcu4K6MzshPZT/2C+M9KP
         T/ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id t73si133558ybi.4.2019.10.03.02.38.49
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Oct 2019 02:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 83d216c888f543e887d8043adfa60921-20191003
X-UUID: 83d216c888f543e887d8043adfa60921-20191003
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1843083875; Thu, 03 Oct 2019 17:38:46 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 3 Oct 2019 17:38:43 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 3 Oct 2019 17:38:44 +0800
Message-ID: <1570095525.19702.59.camel@mtksdccf07>
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
Date: Thu, 3 Oct 2019 17:38:45 +0800
In-Reply-To: <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <1570018513.19702.36.camel@mtksdccf07>
	 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
	 <1570069078.19702.57.camel@mtksdccf07>
	 <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
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

On Thu, 2019-10-03 at 08:26 +0200, Dmitry Vyukov wrote:
> On Thu, Oct 3, 2019 at 4:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
> >
> > On Wed, 2019-10-02 at 15:57 +0200, Dmitry Vyukov wrote:
> > > On Wed, Oct 2, 2019 at 2:15 PM Walter Wu <walter-zh.wu@mediatek.com> =
wrote:
> > > >
> > > > On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> > > > > On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > > > > > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediate=
k.com> wrote:
> > > > > > >
> > > > > > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > > > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@med=
iatek.com> wrote:
> > > > > > > > >
> > > > > > > > > memmove() and memcpy() have missing underflow issues.
> > > > > > > > > When -7 <=3D size < 0, then KASAN will miss to catch the =
underflow issue.
> > > > > > > > > It looks like shadow start address and shadow end address=
 is the same,
> > > > > > > > > so it does not actually check anything.
> > > > > > > > >
> > > > > > > > > The following test is indeed not caught by KASAN:
> > > > > > > > >
> > > > > > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > > > > > >         memset((char *)p, 0, 64);
> > > > > > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > > > > > >         kfree((char*)p);
> > > > > > > > >
> > > > > > > > > It should be checked here:
> > > > > > > > >
> > > > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > > {
> > > > > > > > >         check_memory_region((unsigned long)src, len, fals=
e, _RET_IP_);
> > > > > > > > >         check_memory_region((unsigned long)dest, len, tru=
e, _RET_IP_);
> > > > > > > > >
> > > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > > }
> > > > > > > > >
> > > > > > > > > We fix the shadow end address which is calculated, then g=
eneric KASAN
> > > > > > > > > get the right shadow end address and detect this underflo=
w issue.
> > > > > > > > >
> > > > > > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > > > > > > >
> > > > > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > ---
> > > > > > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++=
++++
> > > > > > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > > > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > > > > > >
> > > > > > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > > > > > index b63b367a94e8..8bd014852556 100644
> > > > > > > > > --- a/lib/test_kasan.c
> > > > > > > > > +++ b/lib/test_kasan.c
> > > > > > > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_=
oob_in_memset(void)
> > > > > > > > >         kfree(ptr);
> > > > > > > > >  }
> > > > > > > > >
> > > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_under=
flow(void)
> > > > > > > > > +{
> > > > > > > > > +       char *ptr;
> > > > > > > > > +       size_t size =3D 64;
> > > > > > > > > +
> > > > > > > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > > +       if (!ptr) {
> > > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > > +               return;
> > > > > > > > > +       }
> > > > > > > > > +
> > > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > > > > > +       kfree(ptr);
> > > > > > > > > +}
> > > > > > > > > +
> > > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_overf=
low(void)
> > > > > > > > > +{
> > > > > > > > > +       char *ptr;
> > > > > > > > > +       size_t size =3D 64;
> > > > > > > > > +
> > > > > > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > > +       if (!ptr) {
> > > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > > +               return;
> > > > > > > > > +       }
> > > > > > > > > +
> > > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > > > > > +       kfree(ptr);
> > > > > > > > > +}
> > > > > > > > > +
> > > > > > > > >  static noinline void __init kmalloc_uaf(void)
> > > > > > > > >  {
> > > > > > > > >         char *ptr;
> > > > > > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(=
void)
> > > > > > > > >         kmalloc_oob_memset_4();
> > > > > > > > >         kmalloc_oob_memset_8();
> > > > > > > > >         kmalloc_oob_memset_16();
> > > > > > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > > > > > >         kmalloc_uaf();
> > > > > > > > >         kmalloc_uaf_memset();
> > > > > > > > >         kmalloc_uaf2();
> > > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_i=
s_poisoned_n(unsigned long addr,
> > > > > > > > >                                                 size_t si=
ze)
> > > > > > > > >  {
> > > > > > > > >         unsigned long ret;
> > > > > > > > > +       void *shadow_start =3D kasan_mem_to_shadow((void =
*)addr);
> > > > > > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)=
addr + size - 1) + 1;
> > > > > > > > >
> > > > > > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((vo=
id *)addr),
> > > > > > > > > -                       kasan_mem_to_shadow((void *)addr =
+ size - 1) + 1);
> > > > > > > > > +       if ((long)size < 0)
> > > > > > > > > +               shadow_end =3D kasan_mem_to_shadow((void =
*)addr + size);
> > > > > > > >
> > > > > > > > Hi Walter,
> > > > > > > >
> > > > > > > > Thanks for working on this.
> > > > > > > >
> > > > > > > > If size<0, does it make sense to continue at all? We will s=
till check
> > > > > > > > 1PB of shadow memory? What happens when we pass such huge r=
ange to
> > > > > > > > memory_is_nonzero?
> > > > > > > > Perhaps it's better to produce an error and bail out immedi=
ately if size<0?
> > > > > > >
> > > > > > > I agree with what you said. when size<0, it is indeed an unre=
asonable
> > > > > > > behavior, it should be blocked from continuing to do.
> > > > > > >
> > > > > > >
> > > > > > > > Also, what's the failure mode of the tests? Didn't they bad=
ly corrupt
> > > > > > > > memory? We tried to keep tests such that they produce the K=
ASAN
> > > > > > > > reports, but don't badly corrupt memory b/c/ we need to run=
 all of
> > > > > > > > them.
> > > > > > >
> > > > > > > Maybe we should first produce KASAN reports and then go to ex=
ecute
> > > > > > > memmove() or do nothing? It looks like it=E2=80=99s doing the=
 following.or?
> > > > > > >
> > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > >  {
> > > > > > > +       if (long(len) <=3D 0)
> > > > > >
> > > > > > /\/\/\/\/\/\
> > > > > >
> > > > > > This check needs to be inside of check_memory_region, otherwise=
 we
> > > > > > will have similar problems in all other places that use
> > > > > > check_memory_region.
> > > > > Thanks for your reminder.
> > > > >
> > > > >  bool check_memory_region(unsigned long addr, size_t size, bool w=
rite,
> > > > >                                 unsigned long ret_ip)
> > > > >  {
> > > > > +       if (long(size) < 0) {
> > > > > +               kasan_report_invalid_size(src, dest, len, _RET_IP=
_);
> > > > > +               return false;
> > > > > +       }
> > > > > +
> > > > >         return check_memory_region_inline(addr, size, write, ret_=
ip);
> > > > >  }
> > > > >
> > > > > > But check_memory_region already returns a bool, so we could che=
ck that
> > > > > > bool and return early.
> > > > >
> > > > > When size<0, we should only show one KASAN report, and should we =
only
> > > > > limit to return when size<0 is true? If yse, then __memmove() wil=
l do
> > > > > nothing.
> > > > >
> > > > >
> > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > >  {
> > > > > -       check_memory_region((unsigned long)src, len, false, _RET_=
IP_);
> > > > > +       if(!check_memory_region((unsigned long)src, len, false,
> > > > > _RET_IP_)
> > > > > +               && long(size) < 0)
> > > > > +               return;
> > > > > +
> > > > >         check_memory_region((unsigned long)dest, len, true, _RET_=
IP_);
> > > > >
> > > > >         return __memmove(dest, src, len);
> > > > >
> > > > > >
> > > > Hi Dmitry,
> > > >
> > > > What do you think the following code is better than the above one.
> > > > In memmmove/memset/memcpy, they need to determine whether size < 0 =
is
> > > > true. we directly determine whether size is negative in memmove and
> > > > return early. it avoid to generate repeated KASAN report. Is it bet=
ter?
> > > >
> > > > void *memmove(void *dest, const void *src, size_t len)
> > > > {
> > > > +       if (long(size) < 0) {
> > > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_)=
;
> > > > +               return;
> > > > +       }
> > > > +
> > > >         check_memory_region((unsigned long)src, len, false, _RET_IP=
_);
> > > >         check_memory_region((unsigned long)dest, len, true, _RET_IP=
_);
> > > >
> > > >
> > > > check_memory_region() still has to check whether the size is negati=
ve.
> > > > but memmove/memset/memcpy generate invalid size KASAN report will n=
ot be
> > > > there.
> > >
> > >
> > > If check_memory_region() will do the check, why do we need to
> > > duplicate it inside of memmove and all other range functions?
> > >
> > Yes, I know it has duplication, but if we don't have to determine size<=
0
> > in memmove, then all check_memory_region return false will do nothing,
>=20
> But they will produce a KASAN report, right? They are asked to check
> if 18446744073709551614 bytes are good. 18446744073709551614 bytes
> can't be good.
>=20
>=20
> > it includes other memory corruption behaviors, this is my original
> > concern.
> >
> > > I would do:
> > >
> > > void *memmove(void *dest, const void *src, size_t len)
> > > {
> > >         if (check_memory_region((unsigned long)src, len, false, _RET_=
IP_))
> > >                 return;
> > if check_memory_region return TRUE is to do nothing, but it is no memor=
y
> > corruption? Should it return early when check_memory_region return a
> > FALSE?
>=20
> Maybe. I just meant the overall idea: check_memory_region should
> detect that 18446744073709551614 bytes are bad, print an error, return
> an indication that bytes were bad, memmove should return early if the
> range is bad.
>=20
ok, i will send new patch.
Thanks for your review.

>=20
> > > This avoids duplicating the check, adds minimal amount of code to
> > > range functions and avoids adding kasan_report_invalid_size.
> > Thanks for your suggestion.
> > We originally want to show complete information(destination address,
> > source address, and its length), but add minimal amount of code into
> > kasan_report(), it should be good.
> >
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/1570069078.19702.57.camel%40mtksdccf07.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1570095525.19702.59.camel%40mtksdccf07.
