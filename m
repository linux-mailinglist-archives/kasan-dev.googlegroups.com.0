Return-Path: <kasan-dev+bncBAABBW5U2XWAKGQEYLPTZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B4715C96A6
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 04:18:04 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id p66sf790346yba.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 19:18:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570069083; cv=pass;
        d=google.com; s=arc-20160816;
        b=n8bYaTAMgtmzikKqk/9WZC/e+d3oO/qOnm4tD5wif0CBVYxGdYpkmYRD4qRgbskODV
         Wh2l5A50bbuL7GOR3/ksFdUOUsDmvuA/tVsIDJFqI8OGPLaocZ2guE35wv9WLBmaquHV
         Pvb7s2AWOfNRxj9NwAw+eqNeI/9UU3xAL9Iz/LB9hlyN6MTRC4YUG36VJCrjBqmqgFMl
         FIq94cZ2Z6gL1m0VhILcGF7bTmTx1Fr8h6ujO78fhsela/TpNYTKMccYkheCUZo5VF5B
         kuAAYjO99YU/LWAHrhtnR5yrNMZ3VYbqMWnhkysvHvY5BRKZVMNRdDEwlVDnpol4jBnY
         qMYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=35J6ZAE+1TYdd1jd0NMPkJIB7UucgOubyPald1XTtlQ=;
        b=sONd8nTD7kUr+FyX54/Sinh1eb4XWNuv14vePIyO+NcQeHGI/kKOJeUTsWaFwyAD+M
         Zhcdjm8c0rydUBf/KULt6v24WrSJQMQQ9DQfV8m4j0SGJTqpp6Ed9gbG0OTQ5jelXUru
         CaTC0EfC0goUiK71zi885lZCpSViIHv+AHEX7CWDHNrpEHJWd7Fb636dr4MrNwci3Kz3
         EdpqcU7nAf9JM3HK3U2Wko2vI0QRDuBvqnnZD4iugEYrV4/6r/rUViL8SbBPW1EmNJwn
         fPyNj8K1VEQLk5g5OjBZDn9Lge2UGiSreNe7RDiZ4nxO35cPrEhvihqlzhhIgHNoHBDG
         QG8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=35J6ZAE+1TYdd1jd0NMPkJIB7UucgOubyPald1XTtlQ=;
        b=RyGwaF4SDI1VIRCYL0vzq6t0V00FEY5Q6hr9JTabczRv/MaKdVOO+mucA5HBb44A2F
         OG375k/ZctdeAW7BZg0zO2GP2LLjtCh6ki7qeij11rRNQXYDe2bqKvP6McvWCXzy3ZdD
         0zK3wTH3uIUqsffkYOTwsFxLYne5mhpbbMvmcHoCBn+YxrcGITS6y8PP6NmPbycNxSVZ
         7qiSiyKRWltG2EdFwJhQFW31Gfy+9BTACcI/PqgIaN/H7GRH7uhPXlt0LI5uUQn3BTQz
         8yX+kvC9PN/PW1+uHQmnFKFp9MlV/yul/GwFT4z0esuUT6aadfdpYlG5B0IvLhtTLF+r
         a0Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=35J6ZAE+1TYdd1jd0NMPkJIB7UucgOubyPald1XTtlQ=;
        b=oQGYIuHswkLZYFY1Z/aCO5qQsV3U7h4AK94o8W1EEuE3r0BY5RmuX7LBsNIW9kh+YW
         MOvb5NPpeJAPq0sZtDSvnMfY99lmV45B+L4pvCU3KxpjxLUU5xOksOqT5u9p63LT1MDw
         uBA9mxwQbFTlR9JC/gGXPRzZRcP1MEAd8o2KuzKy+BTEqi+Tq+Jo1asd3ccEl6/pkb7J
         W4yGRmkBO3/qDjxsCjhdI9Y1F46hUg/6lTMQrHmXwkW0zlpKwnDOIdDOqP3DTnr3tpdm
         4nSmslzOY03QocCUnF0xenNVrDIMcF/WevFt9h+cSqkkN++o3KsNyssDAGyF7E3JtmXN
         HvqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUup6ZG14537dYXLiV8Gf8CgeI9EyEWRB4tEDHJOygt/xWwTvMC
	r1VOGEKRjdyzNtgkzrr3/0U=
X-Google-Smtp-Source: APXvYqw/rAD7e7U1lCjpNpWdtCZWwsl94ZcOlyMU94l4ARy/Q6cZ3RgU2vK5NsCAV7QrHpfub2b5bg==
X-Received: by 2002:a0d:cc0c:: with SMTP id o12mr4634893ywd.390.1570069083562;
        Wed, 02 Oct 2019 19:18:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d611:: with SMTP id y17ls187731ywd.13.gmail; Wed, 02 Oct
 2019 19:18:03 -0700 (PDT)
X-Received: by 2002:a0d:c3c6:: with SMTP id f189mr5008766ywd.397.1570069083024;
        Wed, 02 Oct 2019 19:18:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570069083; cv=none;
        d=google.com; s=arc-20160816;
        b=AwOMexYBLl4RPhra/T1BzvfCROL7aaxwVpTWuVCNtYyei3hOy32Qa4ZdzHWRaUHMpp
         yBCgcyhsC/F6f7jsQfexXzciDbnVJobM7/+fYs3DHn+/KkygKv1jcemTO/Pw1yooYLnW
         2QNxSF3sWXCOd4uq5ZpWnCsBxGxDrnXr6M74k1VHe3cbU6V6iXyoNbnYl9RImR9KFOcs
         3o/IjliveZjIr9vg/oAa/DlNRqOJZJ4GrABlhbsHJcU6lfvwjYNkojZrIFJQYQLG3kHC
         kxKBr77vtON/3W/KOW+LUsR5WPVlgVblRmyrEB9FByjIA2HjC9nPOdNPsRf+z3Fz4Cxm
         ulfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=0VwpYvHVy59r2j4yReWVIOlIoRqTsF+54N/p2JZqFzM=;
        b=YcP6VA4mo9wOnvalnw3Iym5o+g+rtrKZXmIpcE2uTOkh9gfTGpZuydS329Ln4CXcKe
         YpREPwNu0YEfMWKFGr2aOjFZgXDdh4MaWxuxj1+va3Gyw2Td/fKnnWfJm1PS7VsVZpDo
         B+PnmhW1uSC1zxZlkOOccxzocW+N9ij/FxC3igFo95IyCbhDl5hMHsq8wOnMj5gMKDZE
         c0Ji+/xMivtNOQYw6P9YRVgmoYErPfK0PwlapLa6GUSGhVDy07cO/ariIvM18MZLtZQs
         GNHc4EsTH5l2DhSY+Zqz2jux1gZtzz2SStlYirx2o+wp79/V3LTq28oqJ4PjghJ4MZ9O
         Ub/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id a1si54480ywh.3.2019.10.02.19.18.02
        for <kasan-dev@googlegroups.com>;
        Wed, 02 Oct 2019 19:18:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6a934931ebee47a7b59356e638e1e5f6-20191003
X-UUID: 6a934931ebee47a7b59356e638e1e5f6-20191003
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 356317875; Thu, 03 Oct 2019 10:18:00 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 3 Oct 2019 10:17:59 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 3 Oct 2019 10:17:58 +0800
Message-ID: <1570069078.19702.57.camel@mtksdccf07>
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
Date: Thu, 3 Oct 2019 10:17:58 +0800
In-Reply-To: <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <1570018513.19702.36.camel@mtksdccf07>
	 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
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

On Wed, 2019-10-02 at 15:57 +0200, Dmitry Vyukov wrote:
> On Wed, Oct 2, 2019 at 2:15 PM Walter Wu <walter-zh.wu@mediatek.com> wrot=
e:
> >
> > On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> > > On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > > > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.co=
m> wrote:
> > > > >
> > > > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediate=
k.com> wrote:
> > > > > > >
> > > > > > > memmove() and memcpy() have missing underflow issues.
> > > > > > > When -7 <=3D size < 0, then KASAN will miss to catch the unde=
rflow issue.
> > > > > > > It looks like shadow start address and shadow end address is =
the same,
> > > > > > > so it does not actually check anything.
> > > > > > >
> > > > > > > The following test is indeed not caught by KASAN:
> > > > > > >
> > > > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > > > >         memset((char *)p, 0, 64);
> > > > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > > > >         kfree((char*)p);
> > > > > > >
> > > > > > > It should be checked here:
> > > > > > >
> > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > > {
> > > > > > >         check_memory_region((unsigned long)src, len, false, _=
RET_IP_);
> > > > > > >         check_memory_region((unsigned long)dest, len, true, _=
RET_IP_);
> > > > > > >
> > > > > > >         return __memmove(dest, src, len);
> > > > > > > }
> > > > > > >
> > > > > > > We fix the shadow end address which is calculated, then gener=
ic KASAN
> > > > > > > get the right shadow end address and detect this underflow is=
sue.
> > > > > > >
> > > > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > > > > >
> > > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > ---
> > > > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> > > > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > > > >
> > > > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > > > index b63b367a94e8..8bd014852556 100644
> > > > > > > --- a/lib/test_kasan.c
> > > > > > > +++ b/lib/test_kasan.c
> > > > > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_=
in_memset(void)
> > > > > > >         kfree(ptr);
> > > > > > >  }
> > > > > > >
> > > > > > > +static noinline void __init kmalloc_oob_in_memmove_underflow=
(void)
> > > > > > > +{
> > > > > > > +       char *ptr;
> > > > > > > +       size_t size =3D 64;
> > > > > > > +
> > > > > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > +       if (!ptr) {
> > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > +               return;
> > > > > > > +       }
> > > > > > > +
> > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > > > +       kfree(ptr);
> > > > > > > +}
> > > > > > > +
> > > > > > > +static noinline void __init kmalloc_oob_in_memmove_overflow(=
void)
> > > > > > > +{
> > > > > > > +       char *ptr;
> > > > > > > +       size_t size =3D 64;
> > > > > > > +
> > > > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > +       if (!ptr) {
> > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > +               return;
> > > > > > > +       }
> > > > > > > +
> > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > > > +       kfree(ptr);
> > > > > > > +}
> > > > > > > +
> > > > > > >  static noinline void __init kmalloc_uaf(void)
> > > > > > >  {
> > > > > > >         char *ptr;
> > > > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void=
)
> > > > > > >         kmalloc_oob_memset_4();
> > > > > > >         kmalloc_oob_memset_8();
> > > > > > >         kmalloc_oob_memset_16();
> > > > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > > > >         kmalloc_uaf();
> > > > > > >         kmalloc_uaf_memset();
> > > > > > >         kmalloc_uaf2();
> > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > > > --- a/mm/kasan/generic.c
> > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_po=
isoned_n(unsigned long addr,
> > > > > > >                                                 size_t size)
> > > > > > >  {
> > > > > > >         unsigned long ret;
> > > > > > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)ad=
dr);
> > > > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr=
 + size - 1) + 1;
> > > > > > >
> > > > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *=
)addr),
> > > > > > > -                       kasan_mem_to_shadow((void *)addr + si=
ze - 1) + 1);
> > > > > > > +       if ((long)size < 0)
> > > > > > > +               shadow_end =3D kasan_mem_to_shadow((void *)ad=
dr + size);
> > > > > >
> > > > > > Hi Walter,
> > > > > >
> > > > > > Thanks for working on this.
> > > > > >
> > > > > > If size<0, does it make sense to continue at all? We will still=
 check
> > > > > > 1PB of shadow memory? What happens when we pass such huge range=
 to
> > > > > > memory_is_nonzero?
> > > > > > Perhaps it's better to produce an error and bail out immediatel=
y if size<0?
> > > > >
> > > > > I agree with what you said. when size<0, it is indeed an unreason=
able
> > > > > behavior, it should be blocked from continuing to do.
> > > > >
> > > > >
> > > > > > Also, what's the failure mode of the tests? Didn't they badly c=
orrupt
> > > > > > memory? We tried to keep tests such that they produce the KASAN
> > > > > > reports, but don't badly corrupt memory b/c/ we need to run all=
 of
> > > > > > them.
> > > > >
> > > > > Maybe we should first produce KASAN reports and then go to execut=
e
> > > > > memmove() or do nothing? It looks like it=E2=80=99s doing the fol=
lowing.or?
> > > > >
> > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > >  {
> > > > > +       if (long(len) <=3D 0)
> > > >
> > > > /\/\/\/\/\/\
> > > >
> > > > This check needs to be inside of check_memory_region, otherwise we
> > > > will have similar problems in all other places that use
> > > > check_memory_region.
> > > Thanks for your reminder.
> > >
> > >  bool check_memory_region(unsigned long addr, size_t size, bool write=
,
> > >                                 unsigned long ret_ip)
> > >  {
> > > +       if (long(size) < 0) {
> > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > > +               return false;
> > > +       }
> > > +
> > >         return check_memory_region_inline(addr, size, write, ret_ip);
> > >  }
> > >
> > > > But check_memory_region already returns a bool, so we could check t=
hat
> > > > bool and return early.
> > >
> > > When size<0, we should only show one KASAN report, and should we only
> > > limit to return when size<0 is true? If yse, then __memmove() will do
> > > nothing.
> > >
> > >
> > >  void *memmove(void *dest, const void *src, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_)=
;
> > > +       if(!check_memory_region((unsigned long)src, len, false,
> > > _RET_IP_)
> > > +               && long(size) < 0)
> > > +               return;
> > > +
> > >         check_memory_region((unsigned long)dest, len, true, _RET_IP_)=
;
> > >
> > >         return __memmove(dest, src, len);
> > >
> > > >
> > Hi Dmitry,
> >
> > What do you think the following code is better than the above one.
> > In memmmove/memset/memcpy, they need to determine whether size < 0 is
> > true. we directly determine whether size is negative in memmove and
> > return early. it avoid to generate repeated KASAN report. Is it better?
> >
> > void *memmove(void *dest, const void *src, size_t len)
> > {
> > +       if (long(size) < 0) {
> > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > +               return;
> > +       }
> > +
> >         check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >
> > check_memory_region() still has to check whether the size is negative.
> > but memmove/memset/memcpy generate invalid size KASAN report will not b=
e
> > there.
>=20
>=20
> If check_memory_region() will do the check, why do we need to
> duplicate it inside of memmove and all other range functions?
>=20
Yes, I know it has duplication, but if we don't have to determine size<0
in memmove, then all check_memory_region return false will do nothing,
it includes other memory corruption behaviors, this is my original
concern.=20

> I would do:
>=20
> void *memmove(void *dest, const void *src, size_t len)
> {
>         if (check_memory_region((unsigned long)src, len, false, _RET_IP_)=
)
>                 return;
if check_memory_region return TRUE is to do nothing, but it is no memory
corruption? Should it return early when check_memory_region return a
FALSE?

>=20
> This avoids duplicating the check, adds minimal amount of code to
> range functions and avoids adding kasan_report_invalid_size.
Thanks for your suggestion.
We originally want to show complete information(destination address,
source address, and its length), but add minimal amount of code into
kasan_report(), it should be good.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1570069078.19702.57.camel%40mtksdccf07.
