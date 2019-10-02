Return-Path: <kasan-dev+bncBAABBV5J2LWAKGQEKBOVZEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 74E74C8811
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 14:15:21 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id n71sf504632ybg.5
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 05:15:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570018520; cv=pass;
        d=google.com; s=arc-20160816;
        b=ObjLz9m/T5m+gY7Zp4KBMC3zulvs66XQEBdRFs5HtkX5OdEhDYfCZCnaU73dli4Gj9
         IOpfnxCIfb/rlXNiFjEnCypTN8EGEp36gqkEm+5M4H1cLmiC0wvPKZFWawFpOEZ8zuLO
         xKs1yorbQ6pew+j4kzrHShbggmFtDA6Zhc74Fa2hwdHAyWpaiLlCgBwQfHBho3BcCPQr
         KuOvoPOAVDT/7n2RfqAxwPyPxMq7NFtnolSTee2CwiYKrXRBibLlmIcebLy9R+3LE+7j
         caJpMP+r+6YbSIzJX9ojDhAJnqXRUysiIMutbSZiKAXfKR8v30jMb/vOT3RN+M1NOAWz
         8h/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=Kh6da9uvqF2LMGSGTvR4NhiFUgPm/7VwfHgtj4prxhs=;
        b=meuNflW8csEOhAxovwhAZzVrs2Nobf7KZdy6M8ZUr+8cptxISZY6IAe9Ec1t50TZj4
         ag8/PxoPVy5ssYequ8+TAs5bnaJ7BHvpeT4LVvK4vl7q6MGVQLQA1vBjo6n1ZMMoOnqV
         kZjQ9Mphkijltw5Njc0nuE+/6ik8Nv74+iD0Ik8/ICUY/VZfZRE/J4dzh6zCSfg5E+Ns
         FHO+2cOkyuGHcmswWCj5m1PhS1s1YtHh3cDmliIBfwwqBdE4WAMH75Qsrcp5o/7PCOVI
         TFBnjD9GZZpLbAfE9HQ+EyLDqU65Mu2xQ3bB4gdmNMWjSponr4Qhp97a2nCuh0mW4obi
         KvGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kh6da9uvqF2LMGSGTvR4NhiFUgPm/7VwfHgtj4prxhs=;
        b=euZdF+pqJ39QSZh0n3YQ4hHvFUMYVXGfhg+/Dv5eKrjzJq520C28JqrJ3mSGFHsmo4
         IYMzNtNPPIQbkbjdZV2OdiISIbV7zcnzndUu24y8HkR7Wh6nxUg5mlc4SDmVMZfqzJBy
         bjCpvP2vZnTtc76vU4cKSDOYeTeu8AAl/PtzFQ2J/nc25lQRggMlyFOGRcTri3e58JQk
         FQa0nECyyBLJDY66+5pDaWC9zwZc8wMBqNGjvw25u0UIXsBZFpoQF+tkJy/vo3plAwbz
         /BtFsD9KHLegtwd8y63AfKaaR9yxW/GYlUW+ALV7np2J2ADJObuspagDkPgBGa/EQvvM
         K6/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Kh6da9uvqF2LMGSGTvR4NhiFUgPm/7VwfHgtj4prxhs=;
        b=BxTUW5tXMq47z5iefCYvoYVNVwGGRETu92TkiV5DsAyX9nkAe4VpYuCwuCuX0/4rju
         B6XHPALfp/MLr4nIYvRUFdbtMNnDyYokqtAmt9e7q6tF7eMlEUxzHYPA3QvBrqRHNwmh
         ChEenjp9AncjvcwGHCvx1buCYOqaNRK3AUVgcJJocXsOHozqLEQgGRdAsUvsQj1Wx1Qa
         L7SpQHiuWrUYWr6IhlnxbgHQuOniUyz9BpBEmbCTsKPuYgO2D6jRBBS1UbzslHmyAYps
         luHazWQU4wzSD2Rmi9dblJdf81ohZgrMNI6E6gByuXhrH+CzAlgCkmvfjg09FeBKVHTg
         sBVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVN3uFq85Vkx4oPMqTzlEv4y1wIC+Kk+rMNNsLnjcp4ek2BDgek
	olstgq0S85G7pROItBJBmoU=
X-Google-Smtp-Source: APXvYqzCqc/JJmZFSgvQf5L3Wm1c/f8eiTC8rc2DFew/jcj7he2hQiFVHJHMWRnCgqtfvkQyDLQCwg==
X-Received: by 2002:a81:2849:: with SMTP id o70mr2248122ywo.389.1570018520153;
        Wed, 02 Oct 2019 05:15:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:148a:: with SMTP id 132ls383943ywu.16.gmail; Wed, 02 Oct
 2019 05:15:19 -0700 (PDT)
X-Received: by 2002:a81:c60e:: with SMTP id l14mr2403870ywi.454.1570018519782;
        Wed, 02 Oct 2019 05:15:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570018519; cv=none;
        d=google.com; s=arc-20160816;
        b=SzG7QHfCwqc4Go8RNlmXx7s4DL1lb0Bpqzh6rdZJxrJbxm0Wk004XngV9rCRojiPad
         AJ8DqlMeG3Nq2B6fyURmDo8t76sjZExkVdWDM+ZsAJF7ZOvy0qdVMCsQ6EEXASrf+MZL
         GlifhE+TVVS78QFk18T/flrIfMAS3kikjhXDjwwBaphnrr4JXtPXgCUab9pr7itErugX
         GHNLTu6QmexI1XzyaRRSAMpRow7UY1ZjIBvhtTtuukA792jHujGW3LGNZ66T3Uza1eNV
         lM5pzWGsVgxzkQt7jB8drC1VnLkYVseEJGtzJ8xNAoJug16VDsGdr1BJUnhf99/mwdjU
         H4Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=f+x99srqfg0psAPQ7ONce1vOkJXny3zuywhi+8zr0Uk=;
        b=BKf/G3aFhsbYaot4UcrWnsDfX8fdZzYdaV/2eO5y/MbTd441T9fbh7B8kO12nmDPRT
         NGPCGdmBBwhmLIEgbfy7ZKC50Gdn4yN2Nh6vWZgVKsdgMPN05e7iPm9q10KqqPvMTfJe
         K+7Wuguo814jqMLCNWFMHftCZBjBkCwp/zDJ+co820mQzR0fDF81ZHT6lpTDTXec6y/0
         p4k/IzX4V/2KB3L3a6IXDUOOXKgg2VfXqoi8QdeFY0Wzeck1DxPj5pkwy4OZkWpJhDDt
         QglZyfCpkHqmRllDqgar54M9owmXxepxoupu2PRwMSSL9yI83IrnF20ydFMgpp3VG6S7
         LULQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id u129si973619ywc.1.2019.10.02.05.15.18
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Oct 2019 05:15:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 187b45e8e86d4579955d053e51dadfd8-20191002
X-UUID: 187b45e8e86d4579955d053e51dadfd8-20191002
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 721684038; Wed, 02 Oct 2019 20:15:15 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 2 Oct 2019 20:15:12 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 2 Oct 2019 20:15:11 +0800
Message-ID: <1570018513.19702.36.camel@mtksdccf07>
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
Date: Wed, 2 Oct 2019 20:15:13 +0800
In-Reply-To: <1569818173.17361.19.camel@mtksdccf07>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
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

On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.com> w=
rote:
> > >
> > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.co=
m> wrote:
> > > > >
> > > > > memmove() and memcpy() have missing underflow issues.
> > > > > When -7 <=3D size < 0, then KASAN will miss to catch the underflo=
w issue.
> > > > > It looks like shadow start address and shadow end address is the =
same,
> > > > > so it does not actually check anything.
> > > > >
> > > > > The following test is indeed not caught by KASAN:
> > > > >
> > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > >         memset((char *)p, 0, 64);
> > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > >         kfree((char*)p);
> > > > >
> > > > > It should be checked here:
> > > > >
> > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > {
> > > > >         check_memory_region((unsigned long)src, len, false, _RET_=
IP_);
> > > > >         check_memory_region((unsigned long)dest, len, true, _RET_=
IP_);
> > > > >
> > > > >         return __memmove(dest, src, len);
> > > > > }
> > > > >
> > > > > We fix the shadow end address which is calculated, then generic K=
ASAN
> > > > > get the right shadow end address and detect this underflow issue.
> > > > >
> > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > > >
> > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > ---
> > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > >
> > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > index b63b367a94e8..8bd014852556 100644
> > > > > --- a/lib/test_kasan.c
> > > > > +++ b/lib/test_kasan.c
> > > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_m=
emset(void)
> > > > >         kfree(ptr);
> > > > >  }
> > > > >
> > > > > +static noinline void __init kmalloc_oob_in_memmove_underflow(voi=
d)
> > > > > +{
> > > > > +       char *ptr;
> > > > > +       size_t size =3D 64;
> > > > > +
> > > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > +       if (!ptr) {
> > > > > +               pr_err("Allocation failed\n");
> > > > > +               return;
> > > > > +       }
> > > > > +
> > > > > +       memset((char *)ptr, 0, 64);
> > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > +       kfree(ptr);
> > > > > +}
> > > > > +
> > > > > +static noinline void __init kmalloc_oob_in_memmove_overflow(void=
)
> > > > > +{
> > > > > +       char *ptr;
> > > > > +       size_t size =3D 64;
> > > > > +
> > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > +       if (!ptr) {
> > > > > +               pr_err("Allocation failed\n");
> > > > > +               return;
> > > > > +       }
> > > > > +
> > > > > +       memset((char *)ptr, 0, 64);
> > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > +       kfree(ptr);
> > > > > +}
> > > > > +
> > > > >  static noinline void __init kmalloc_uaf(void)
> > > > >  {
> > > > >         char *ptr;
> > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
> > > > >         kmalloc_oob_memset_4();
> > > > >         kmalloc_oob_memset_8();
> > > > >         kmalloc_oob_memset_16();
> > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > >         kmalloc_uaf();
> > > > >         kmalloc_uaf_memset();
> > > > >         kmalloc_uaf2();
> > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > --- a/mm/kasan/generic.c
> > > > > +++ b/mm/kasan/generic.c
> > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_poison=
ed_n(unsigned long addr,
> > > > >                                                 size_t size)
> > > > >  {
> > > > >         unsigned long ret;
> > > > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)addr);
> > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr + s=
ize - 1) + 1;
> > > > >
> > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *)add=
r),
> > > > > -                       kasan_mem_to_shadow((void *)addr + size -=
 1) + 1);
> > > > > +       if ((long)size < 0)
> > > > > +               shadow_end =3D kasan_mem_to_shadow((void *)addr +=
 size);
> > > >
> > > > Hi Walter,
> > > >
> > > > Thanks for working on this.
> > > >
> > > > If size<0, does it make sense to continue at all? We will still che=
ck
> > > > 1PB of shadow memory? What happens when we pass such huge range to
> > > > memory_is_nonzero?
> > > > Perhaps it's better to produce an error and bail out immediately if=
 size<0?
> > >
> > > I agree with what you said. when size<0, it is indeed an unreasonable
> > > behavior, it should be blocked from continuing to do.
> > >
> > >
> > > > Also, what's the failure mode of the tests? Didn't they badly corru=
pt
> > > > memory? We tried to keep tests such that they produce the KASAN
> > > > reports, but don't badly corrupt memory b/c/ we need to run all of
> > > > them.
> > >
> > > Maybe we should first produce KASAN reports and then go to execute
> > > memmove() or do nothing? It looks like it=E2=80=99s doing the followi=
ng.or?
> > >
> > > void *memmove(void *dest, const void *src, size_t len)
> > >  {
> > > +       if (long(len) <=3D 0)
> >=20
> > /\/\/\/\/\/\
> >=20
> > This check needs to be inside of check_memory_region, otherwise we
> > will have similar problems in all other places that use
> > check_memory_region.
> Thanks for your reminder.
>=20
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip)
>  {
> +       if (long(size) < 0) {
> +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> +               return false;
> +       }
> +
>         return check_memory_region_inline(addr, size, write, ret_ip);
>  }
>=20
> > But check_memory_region already returns a bool, so we could check that
> > bool and return early.
>=20
> When size<0, we should only show one KASAN report, and should we only
> limit to return when size<0 is true? If yse, then __memmove() will do
> nothing.
>=20
>=20
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> +       if(!check_memory_region((unsigned long)src, len, false,
> _RET_IP_)
> +               && long(size) < 0)
> +               return;
> +
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>=20
>         return __memmove(dest, src, len);
>=20
> >=20
Hi Dmitry,

What do you think the following code is better than the above one.
In memmmove/memset/memcpy, they need to determine whether size < 0 is
true. we directly determine whether size is negative in memmove and
return early. it avoid to generate repeated KASAN report. Is it better?

void *memmove(void *dest, const void *src, size_t len)
{
+       if (long(size) < 0) {
+               kasan_report_invalid_size(src, dest, len, _RET_IP_);
+               return;
+       }
+
        check_memory_region((unsigned long)src, len, false, _RET_IP_);
        check_memory_region((unsigned long)dest, len, true, _RET_IP_);


check_memory_region() still has to check whether the size is negative.
but memmove/memset/memcpy generate invalid size KASAN report will not be
there.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1570018513.19702.36.camel%40mtksdccf07.
