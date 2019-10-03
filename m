Return-Path: <kasan-dev+bncBAABBYPZ27WAKGQE64VBV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F948C9FDB
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 15:51:31 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d3sf2958885qtr.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 06:51:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570110690; cv=pass;
        d=google.com; s=arc-20160816;
        b=ied/02L1ioxay3Dnl0OF2DHsWFGGjEgZJgemNPs8Hk4NSwDmeQCrU+Fc8W7lS2bYv7
         lq65Pc1sSxy7cQHAYCVj2yFgzkaZs2h2/ccOpa8w3SLqdPzD/i4EM+eY/1oSTdFbHKkS
         4gjnIEbZG1qsackZcfHDsN/oEsXkT57DoPr7h42nmVEjxh7CM5kEr3opNp80hwTPSWHM
         Jtc/stnOHN4MPhzcBmTGIPGUm/W6itDbwJWTBuQ8VzOt2BourV6+iQJzM3CaqA5cquSX
         F4VWQElh3w1SzQqWRVlOXNIKD9qr4vV6FduOz/fvb58ykLCXT91WUTwjESssaohnSdlL
         /b5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=jlvfZCR7KiyUofx3iVVxA+Eh3T32tSgZy+fuipiq3Wo=;
        b=n5ZA6+Iu0JyZbmBhHLzKCk7jmAy77odVxXl4uvCDIvWJWwu3ElrhvBq1FYWfoXLMpU
         AjEGX3cH9Gwimwzu+WokFdEKN9qMCGBr1TqyVQ/S+aoNLYwAiqaIRvuzlUJnR4bJpyAb
         evnl8efNC9apyWs2iQNGIkfCBDy2VW3JBco5va37kaw4MJPBbJLRehFmBI/YZu1NTT4w
         0+2Lw+G2vHTLaBXChrwzTUKbTlWmve29tWPhXJi4gx2HJs8sYW8pd79A/2YU9qT3+ZM9
         Wqy4hvG2lvde6Rg26u5ZU/URvdykFzh7Tm6fGS0qKATSwGOLB1KFUDe+AppSbtWvFkf8
         oo6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jlvfZCR7KiyUofx3iVVxA+Eh3T32tSgZy+fuipiq3Wo=;
        b=WSaxpbjFg48Ns9L90BXjCIC0oiK32GTUbQV0leiZlo4ACR2B8bvSk83XBrdQmP7e1k
         D9ISboRgbtcMtHoBjNjb4wpydgAacd+vSPd2oYQxn3RqJ1PnlT1sFrNq5eDvwk8K3Zxu
         yCOhmZSki5SIjy3Ao8Q2qSxuPxPJr9sM+P0jeYOz0u9A/swDdDfQgysdNoP3Wo69NkLN
         P/lGe02Q8Mp6JN/GSHwR2C4i0yRabBd6TAAhdNL4JbvbQ3kwAQ1Bh1MqiQpJsl4HMG7D
         Q3koURCOcvTu4C4ui4qVFB6SyMhLOX5DmzotHJTNv4+3ApF99vOmAnqGvNovUMprV8Sd
         5XPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jlvfZCR7KiyUofx3iVVxA+Eh3T32tSgZy+fuipiq3Wo=;
        b=ozSvYN0lYeboovTrTrrRHEGMvsmTXZb8jirNOskJFXo6z2kngTgfUFD4Wa3v5B9XyP
         pEHeUlptz3NYSIKuMqtGv4aegycgCUhZsq0x7brV+IPkmoIVCq7GYl8twBzqLSCWojF+
         HFx9nP5IOosE2Qj/7gKCymlKNpyEaz9EvOcVzPh0MruYZ8f1jlfW1kHEQmEZPJyypaq0
         TjYzp+c4xWFFw3yykNuElSPDVaPK2+K3/hOoQcFIAyYRuk6Vn9cJ12hnrkFHVJx41jjR
         3/Wy1eIbcpMnsdaY38Qv+Aed5Qq1moxfZpZ8OckHM/DWT6tP0ApkygI1QSmL0LfueOcF
         4AIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYYA6Pesv31NTikCCJFGPg9a0sDU5c0EQypQatHu/6S/olcweE
	9au7H66SaGMV5eroztWzeqI=
X-Google-Smtp-Source: APXvYqyPmp2tV1O7kbZu6RXPUjmE7Lrt7cQCTCPj1VHMP2ekjMovkEWS9hCPhWl5RsyXB7aLF4DQ8w==
X-Received: by 2002:a0c:9051:: with SMTP id o75mr8539529qvo.147.1570110689840;
        Thu, 03 Oct 2019 06:51:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aed6:: with SMTP id n22ls464062qvd.6.gmail; Thu, 03 Oct
 2019 06:51:29 -0700 (PDT)
X-Received: by 2002:a0c:bc15:: with SMTP id j21mr8603188qvg.234.1570110689496;
        Thu, 03 Oct 2019 06:51:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570110689; cv=none;
        d=google.com; s=arc-20160816;
        b=Upvmi+IzZcH6MTEdCWcYwryNc6eLqh56BLdef4UDdhSVJqcrDb3e3p7ZwKt78J2TRU
         8CiB+5e/2c8YzCOUPtgUN6SgcDZYySYcMK8rDX1XsOta83sVCRhthGOGvczcoB7R1zT+
         OXxpz30spgli/78svLuC/e2AS7cG/pl0AV98m/qKyLAIgTLxTTwuvelG7znTty8/T10u
         uNK/8gNTSYKe+UtDwtepGdlzBUhC3aTSq5a73TjV6Jo1+2qeZdXwk5NSVzRCoNPwW2rY
         PSFA22ZdOqLcuXToD5E3K3NgRtiP+EqNVH7ysUJA01k7U4eXTkrQd2rXxU1Cf4IBTxji
         Be9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=QuACN+wl5fI7jq+TfDi5x51mloucXkOR3JtImCsyzc0=;
        b=TrvrXakxeFIuzVLOoFl0P5TTIk8I4uBMFxo22z1c8Sm/r9YnYMJgR5N6acXXKA5FHp
         KyosO4hGh1Yd/qHCxQ8EikUidd7n8uwLwtRUvR2yHY/YpbIZqlGZ4495OkpNY67Tcp1H
         O+B3TgidltF8Zng52JjKXgIurH+B+NIQkrfKlpo8fOLKvdu9UKaB/06ttkPh9U40THob
         Zz8TZ7qS5PKOjXPeR3VcZoXsHpocpnoULMKnGYF5Ki2yX/NXGuxFA4701BSFrfvOw4L8
         7pH5nTkB0+p5/kQmqrQNAXgz5ga1R/Mb4RGwuGktPVZl7iNo6CwdIGwZtaE7ulPLh0Db
         vLZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id c78si113206qkb.7.2019.10.03.06.51.28
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Oct 2019 06:51:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 3d904f6d175441b6a8b24f17d6deb2bc-20191003
X-UUID: 3d904f6d175441b6a8b24f17d6deb2bc-20191003
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1733192920; Thu, 03 Oct 2019 21:51:23 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 3 Oct 2019 21:51:21 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 3 Oct 2019 21:51:20 +0800
Message-ID: <1570110681.19702.64.camel@mtksdccf07>
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
Date: Thu, 3 Oct 2019 21:51:21 +0800
In-Reply-To: <1570095525.19702.59.camel@mtksdccf07>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <1570018513.19702.36.camel@mtksdccf07>
	 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
	 <1570069078.19702.57.camel@mtksdccf07>
	 <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
	 <1570095525.19702.59.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

On Thu, 2019-10-03 at 17:38 +0800, Walter Wu wrote:
> On Thu, 2019-10-03 at 08:26 +0200, Dmitry Vyukov wrote:
> > On Thu, Oct 3, 2019 at 4:18 AM Walter Wu <walter-zh.wu@mediatek.com> wr=
ote:
> > >
> > > On Wed, 2019-10-02 at 15:57 +0200, Dmitry Vyukov wrote:
> > > > On Wed, Oct 2, 2019 at 2:15 PM Walter Wu <walter-zh.wu@mediatek.com=
> wrote:
> > > > >
> > > > > On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> > > > > > On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > > > > > > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@media=
tek.com> wrote:
> > > > > > > >
> > > > > > > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > > > > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@m=
ediatek.com> wrote:
> > > > > > > > > >
> > > > > > > > > > memmove() and memcpy() have missing underflow issues.
> > > > > > > > > > When -7 <=3D size < 0, then KASAN will miss to catch th=
e underflow issue.
> > > > > > > > > > It looks like shadow start address and shadow end addre=
ss is the same,
> > > > > > > > > > so it does not actually check anything.
> > > > > > > > > >
> > > > > > > > > > The following test is indeed not caught by KASAN:
> > > > > > > > > >
> > > > > > > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > > > > > > >         memset((char *)p, 0, 64);
> > > > > > > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > > > > > > >         kfree((char*)p);
> > > > > > > > > >
> > > > > > > > > > It should be checked here:
> > > > > > > > > >
> > > > > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > > > {
> > > > > > > > > >         check_memory_region((unsigned long)src, len, fa=
lse, _RET_IP_);
> > > > > > > > > >         check_memory_region((unsigned long)dest, len, t=
rue, _RET_IP_);
> > > > > > > > > >
> > > > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > > > }
> > > > > > > > > >
> > > > > > > > > > We fix the shadow end address which is calculated, then=
 generic KASAN
> > > > > > > > > > get the right shadow end address and detect this underf=
low issue.
> > > > > > > > > >
> > > > > > > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D19934=
1
> > > > > > > > > >
> > > > > > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > > > ---
> > > > > > > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++=
++++++
> > > > > > > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > > > > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > > > > > > >
> > > > > > > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > > > > > > index b63b367a94e8..8bd014852556 100644
> > > > > > > > > > --- a/lib/test_kasan.c
> > > > > > > > > > +++ b/lib/test_kasan.c
> > > > > > > > > > @@ -280,6 +280,40 @@ static noinline void __init kmallo=
c_oob_in_memset(void)
> > > > > > > > > >         kfree(ptr);
> > > > > > > > > >  }
> > > > > > > > > >
> > > > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_und=
erflow(void)
> > > > > > > > > > +{
> > > > > > > > > > +       char *ptr;
> > > > > > > > > > +       size_t size =3D 64;
> > > > > > > > > > +
> > > > > > > > > > +       pr_info("underflow out-of-bounds in memmove\n")=
;
> > > > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > > > +       if (!ptr) {
> > > > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > > > +               return;
> > > > > > > > > > +       }
> > > > > > > > > > +
> > > > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > > > > > > +       kfree(ptr);
> > > > > > > > > > +}
> > > > > > > > > > +
> > > > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_ove=
rflow(void)
> > > > > > > > > > +{
> > > > > > > > > > +       char *ptr;
> > > > > > > > > > +       size_t size =3D 64;
> > > > > > > > > > +
> > > > > > > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > > > +       if (!ptr) {
> > > > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > > > +               return;
> > > > > > > > > > +       }
> > > > > > > > > > +
> > > > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > > > > > > +       kfree(ptr);
> > > > > > > > > > +}
> > > > > > > > > > +
> > > > > > > > > >  static noinline void __init kmalloc_uaf(void)
> > > > > > > > > >  {
> > > > > > > > > >         char *ptr;
> > > > > > > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_ini=
t(void)
> > > > > > > > > >         kmalloc_oob_memset_4();
> > > > > > > > > >         kmalloc_oob_memset_8();
> > > > > > > > > >         kmalloc_oob_memset_16();
> > > > > > > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > > > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > > > > > > >         kmalloc_uaf();
> > > > > > > > > >         kmalloc_uaf_memset();
> > > > > > > > > >         kmalloc_uaf2();
> > > > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory=
_is_poisoned_n(unsigned long addr,
> > > > > > > > > >                                                 size_t =
size)
> > > > > > > > > >  {
> > > > > > > > > >         unsigned long ret;
> > > > > > > > > > +       void *shadow_start =3D kasan_mem_to_shadow((voi=
d *)addr);
> > > > > > > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void =
*)addr + size - 1) + 1;
> > > > > > > > > >
> > > > > > > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((=
void *)addr),
> > > > > > > > > > -                       kasan_mem_to_shadow((void *)add=
r + size - 1) + 1);
> > > > > > > > > > +       if ((long)size < 0)
> > > > > > > > > > +               shadow_end =3D kasan_mem_to_shadow((voi=
d *)addr + size);
> > > > > > > > >
> > > > > > > > > Hi Walter,
> > > > > > > > >
> > > > > > > > > Thanks for working on this.
> > > > > > > > >
> > > > > > > > > If size<0, does it make sense to continue at all? We will=
 still check
> > > > > > > > > 1PB of shadow memory? What happens when we pass such huge=
 range to
> > > > > > > > > memory_is_nonzero?
> > > > > > > > > Perhaps it's better to produce an error and bail out imme=
diately if size<0?
> > > > > > > >
> > > > > > > > I agree with what you said. when size<0, it is indeed an un=
reasonable
> > > > > > > > behavior, it should be blocked from continuing to do.
> > > > > > > >
> > > > > > > >
> > > > > > > > > Also, what's the failure mode of the tests? Didn't they b=
adly corrupt
> > > > > > > > > memory? We tried to keep tests such that they produce the=
 KASAN
> > > > > > > > > reports, but don't badly corrupt memory b/c/ we need to r=
un all of
> > > > > > > > > them.
> > > > > > > >
> > > > > > > > Maybe we should first produce KASAN reports and then go to =
execute
> > > > > > > > memmove() or do nothing? It looks like it=E2=80=99s doing t=
he following.or?
> > > > > > > >
> > > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > > >  {
> > > > > > > > +       if (long(len) <=3D 0)
> > > > > > >
> > > > > > > /\/\/\/\/\/\
> > > > > > >
> > > > > > > This check needs to be inside of check_memory_region, otherwi=
se we
> > > > > > > will have similar problems in all other places that use
> > > > > > > check_memory_region.
> > > > > > Thanks for your reminder.
> > > > > >
> > > > > >  bool check_memory_region(unsigned long addr, size_t size, bool=
 write,
> > > > > >                                 unsigned long ret_ip)
> > > > > >  {
> > > > > > +       if (long(size) < 0) {
> > > > > > +               kasan_report_invalid_size(src, dest, len, _RET_=
IP_);
> > > > > > +               return false;
> > > > > > +       }
> > > > > > +
> > > > > >         return check_memory_region_inline(addr, size, write, re=
t_ip);
> > > > > >  }
> > > > > >
> > > > > > > But check_memory_region already returns a bool, so we could c=
heck that
> > > > > > > bool and return early.
> > > > > >
> > > > > > When size<0, we should only show one KASAN report, and should w=
e only
> > > > > > limit to return when size<0 is true? If yse, then __memmove() w=
ill do
> > > > > > nothing.
> > > > > >
> > > > > >
> > > > > >  void *memmove(void *dest, const void *src, size_t len)
> > > > > >  {
> > > > > > -       check_memory_region((unsigned long)src, len, false, _RE=
T_IP_);
> > > > > > +       if(!check_memory_region((unsigned long)src, len, false,
> > > > > > _RET_IP_)
> > > > > > +               && long(size) < 0)
> > > > > > +               return;
> > > > > > +
> > > > > >         check_memory_region((unsigned long)dest, len, true, _RE=
T_IP_);
> > > > > >
> > > > > >         return __memmove(dest, src, len);
> > > > > >
> > > > > > >
> > > > > Hi Dmitry,
> > > > >
> > > > > What do you think the following code is better than the above one=
.
> > > > > In memmmove/memset/memcpy, they need to determine whether size < =
0 is
> > > > > true. we directly determine whether size is negative in memmove a=
nd
> > > > > return early. it avoid to generate repeated KASAN report. Is it b=
etter?
> > > > >
> > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > {
> > > > > +       if (long(size) < 0) {
> > > > > +               kasan_report_invalid_size(src, dest, len, _RET_IP=
_);
> > > > > +               return;
> > > > > +       }
> > > > > +
> > > > >         check_memory_region((unsigned long)src, len, false, _RET_=
IP_);
> > > > >         check_memory_region((unsigned long)dest, len, true, _RET_=
IP_);
> > > > >
> > > > >
> > > > > check_memory_region() still has to check whether the size is nega=
tive.
> > > > > but memmove/memset/memcpy generate invalid size KASAN report will=
 not be
> > > > > there.
> > > >
> > > >
> > > > If check_memory_region() will do the check, why do we need to
> > > > duplicate it inside of memmove and all other range functions?
> > > >
> > > Yes, I know it has duplication, but if we don't have to determine siz=
e<0
> > > in memmove, then all check_memory_region return false will do nothing=
,
> >=20
> > But they will produce a KASAN report, right? They are asked to check
> > if 18446744073709551614 bytes are good. 18446744073709551614 bytes
> > can't be good.
> >=20
> >=20
> > > it includes other memory corruption behaviors, this is my original
> > > concern.
> > >
> > > > I would do:
> > > >
> > > > void *memmove(void *dest, const void *src, size_t len)
> > > > {
> > > >         if (check_memory_region((unsigned long)src, len, false, _RE=
T_IP_))
> > > >                 return;
> > > if check_memory_region return TRUE is to do nothing, but it is no mem=
ory
> > > corruption? Should it return early when check_memory_region return a
> > > FALSE?
> >=20
> > Maybe. I just meant the overall idea: check_memory_region should
> > detect that 18446744073709551614 bytes are bad, print an error, return
> > an indication that bytes were bad, memmove should return early if the
> > range is bad.
> >=20
> ok, i will send new patch.
> Thanks for your review.
>=20
how about this?

commit fd64691026e7ccb8d2946d0804b0621ac177df38
Author: Walter Wu <walter-zh.wu@mediatek.com>
Date:   Fri Sep 27 09:54:18 2019 +0800

    kasan: detect invalid size in memory operation function
   =20
    It is an undefined behavior to pass a negative value to
memset()/memcpy()/memmove()
    , so need to be detected by KASAN.
   =20
    KASAN report:
   =20
     BUG: KASAN: invalid size 18446744073709551614 in
kmalloc_memmove_invalid_size+0x70/0xa0
   =20
     CPU: 1 PID: 91 Comm: cat Not tainted
5.3.0-rc1ajb-00001-g31943bbc21ce-dirty #7
     Hardware name: linux,dummy-virt (DT)
     Call trace:
      dump_backtrace+0x0/0x278
      show_stack+0x14/0x20
      dump_stack+0x108/0x15c
      print_address_description+0x64/0x368
      __kasan_report+0x108/0x1a4
      kasan_report+0xc/0x18
      check_memory_region+0x15c/0x1b8
      memmove+0x34/0x88
      kmalloc_memmove_invalid_size+0x70/0xa0
   =20
    [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
   =20
    Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
    Reported-by: Dmitry Vyukov <dvyukov@google.com>

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b63b367a94e8..e4e517a51860 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -280,6 +280,23 @@ static noinline void __init
kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
=20
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size =3D 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr =3D kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -734,6 +751,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size;
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2277b82902d8..5fd377af7457 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
-	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
+	if(!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
=20
 	return __memset(addr, c, len);
 }
@@ -110,7 +111,8 @@ void *memset(void *addr, int c, size_t len)
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
+	if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
+		return NULL;
 	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
=20
 	return __memmove(dest, src, len);
@@ -119,7 +121,8 @@ void *memmove(void *dest, const void *src, size_t
len)
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
+	if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
+		return NULL;
 	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
=20
 	return __memcpy(dest, src, len);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..02148a317d27 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,6 +173,11 @@ static __always_inline bool
check_memory_region_inline(unsigned long addr,
 	if (unlikely(size =3D=3D 0))
 		return true;
=20
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	if (unlikely((void *)addr <
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		kasan_report(addr, size, write, ret_ip);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0e5f965f1882..0cd317ef30f5 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -68,11 +68,16 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
=20
 static void print_error_description(struct kasan_access_info *info)
 {
-	pr_err("BUG: KASAN: %s in %pS\n",
-		get_bug_type(info), (void *)info->ip);
-	pr_err("%s of size %zu at addr %px by task %s/%d\n",
-		info->is_write ? "Write" : "Read", info->access_size,
-		info->access_addr, current->comm, task_pid_nr(current));
+	if ((long)info->access_size < 0) {
+		pr_err("BUG: KASAN: invalid size %zu in %pS\n",
+			info->access_size, (void *)info->ip);
+	} else {
+		pr_err("BUG: KASAN: %s in %pS\n",
+			get_bug_type(info), (void *)info->ip);
+		pr_err("%s of size %zu at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read", info->access_size,
+			info->access_addr, current->comm, task_pid_nr(current));
+	}
 }
=20
 static DEFINE_SPINLOCK(report_lock);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0e987c9ca052..b829535a3ad7 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
size, bool write,
 	if (unlikely(size =3D=3D 0))
 		return true;
=20
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	tag =3D get_tag((const void *)addr);
=20
 	/*


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1570110681.19702.64.camel%40mtksdccf07.
