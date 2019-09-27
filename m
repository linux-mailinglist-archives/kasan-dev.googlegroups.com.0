Return-Path: <kasan-dev+bncBCMIZB7QWENRBC6MXHWAKGQEHBKHQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 453C3C0C29
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 21:42:05 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id o204sf2760023ywc.12
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 12:42:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569613324; cv=pass;
        d=google.com; s=arc-20160816;
        b=nAxZSOADrafDZ37tUf+LPCGD0r8Uo+u6vOUvFQg7tS4jQ/z0zyU7kWa9niRFQwH0sE
         MTjF73eheDCMFBJqdmQEFWPHuXxoskVCqAxCcbhjoVQa+05szu8uPtyn2b49tUGJ5jNO
         JwnLX+udtrpP2ng3zApXhBNLdqFzIS57VKGZYpdkenA7qy7mdaJoS+zHtu638LmaVLEb
         ndYaQdkbxkdaRFv6PPslNjv8Y1ZituVXHRwBto+uf7AP89LLTWNiGUOHPZGL/6qgsMCo
         l8ucbV+yeLoP2F+kHRaUaOgqddL1wkOmsFuVPleDJVyEuFET6zscoCQQhknLcVbtSK68
         PTNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wYhFp83C3/avWx2LOMmHi25An/Y1AaSV7Kxp/OF4ud4=;
        b=hCyRnJcTj1nnmCLvKJ+mLfK+uF2j/r5Sl5EIUoXnrbfHLTTlU9nTTfAAGXxxdqEgUT
         iHFdaiOgeVXJATJLZTRi4Yul6er+8wtopj5K5wvePfIIpWhj2JLuI6jpMBkg8WUPLVFf
         qJ+7iksjmN1eKY0T+ZkKWbFqVl9hnmZds7hHmBjbW1fd4K9+OPr7/exxDl/YGXa8kS3b
         ckbMJptQCrMjq3hmXUXl6/4uHt9yxIW+Co5pRTDlrebz6gVDA0IIWY6RJ905AbyCq4/O
         FqT4gJBxYmBC6K5Fx6vm2flOisbygN4uM2NcU6r5i7fHXUF7UPjmiF4zyV24nrDalExF
         8YcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vd7UFaaC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wYhFp83C3/avWx2LOMmHi25An/Y1AaSV7Kxp/OF4ud4=;
        b=AHfGEdWk/pLl0UPnDzo4kPqtR0Aypq6rBByS79OgMjbdh++MGlxJbajtv9epaXUAsV
         UEIIkZr7Z/wbvEMm3Nmw9fw+s0ZIAxY/17sSOOHM25OaxztePL1qrhrcHfYrssxKi0+W
         eArfYaveQ3XFF9Cesmzt8Dv0//o/2H0lJSxp1yCT+k8utp/PPwKgEehVf0NJMijr3qxa
         U2Rf0YwvIqxEtDcv93COAa13ERMJRYdVCFDROS5Oph99/hB/Yyt5hZ6WZwyllwlKk6Ld
         u6hPACai9ljFES++uhIGflZ8mglCw/ZKs5IdmNF4LyBqHZDBvOcbrIaG9JGPlvDznBci
         H9/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wYhFp83C3/avWx2LOMmHi25An/Y1AaSV7Kxp/OF4ud4=;
        b=ZgI3YAwuFjK3BS347HZFRC4vcdgDwj/Qq4IpJqqtaKMZnOlhWrdWYA/y5ZTmjZE/52
         qCw+FYpdg4nXFITv/6YnFQI/EWETvE1fFACXwl4nXzPi5HxuvF3oeJgK14Up8+EmPpL6
         1M1SZTr5hv/WoDqb3j7FmWN2yWXuXsliKTMuFhthDDUhjcWxZLhmuxEjV96mcSAayISf
         Vn9Ntf3r66UgPffd2hRry/iIKDIIoiuy9XTgHDyrTv8j+FKKjiMuvVkWf+pz66Yaib98
         s5XAXQzAlkPX7EyOoM3ZuP5nihzslldChLtQBOdd1UtIcRP6lO5gfSjy3F2hhNl6wQAQ
         sLbw==
X-Gm-Message-State: APjAAAV1Io3vMN3JYpdwwped3S+31/KScz1kMy+QS4hAZrpeS4YdFQlk
	jpAVsdqmo382e57xyJMP6G8=
X-Google-Smtp-Source: APXvYqwSVbPZBcykDBDjD6bY/JYVAEhQj4zKX1tlgI7wKFIfjHhVO1yYyJnanvYLHO0gqdwTwYEKLg==
X-Received: by 2002:a81:310f:: with SMTP id x15mr4116439ywx.257.1569613323932;
        Fri, 27 Sep 2019 12:42:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e68e:: with SMTP id d136ls1107053ybh.9.gmail; Fri, 27
 Sep 2019 12:42:03 -0700 (PDT)
X-Received: by 2002:a25:b7c8:: with SMTP id u8mr6889131ybj.212.1569613323656;
        Fri, 27 Sep 2019 12:42:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569613323; cv=none;
        d=google.com; s=arc-20160816;
        b=Wmypc5pUn4ULuJ+YA9KOqmnfbIwRAKUjmjouI9+9iI41i1mQGhi3lYsGKCfYaqQ6Cl
         p7j+dKQxfhSAp7pHrS1doaEsVhrLY2h4XcSrRDlXbXBgbW79VfALmMKCQYH02bQxzSve
         mmdZz6tyqQdjul+/aLF6ZW1wxmLXhZESMI3ySZhYFe3kiWHzrURUbcNzNuuSWenypAyn
         6kyss9gxOvTFfUMUQAsIHHRV01ckOXxeAaJCOxIlHPcXE0cgJYxPfSJhyyrlrrVzxlgK
         4rmaN5ND6D89caYDCCylYENqZQV2HhkTJWW1umtiPpKfvzXc5bB9Zx3ohy0c793VhKQO
         3TEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GdzRgDBYfpDpx6nQGoKtzOVBfnyfeeybzCuIbLx6fB0=;
        b=B7gauS8Qkd2zy7A59fvCFB8Shdn8jbSC8/3fDR/pmR5XuHr3ANVwFX0FJo5Nbxr9Wz
         3BhS1DtuYdQZtk7+ITeXMJbnUgeXdhxwxmHkAhK58UTMdanmPjy6s3DkMyTlwZSnxR/g
         dYz35z4Aid/E1E7ldrtGdrskYz6VMFig2pP4p/p5chDjumUd3qu65ohuDVXpCDPSHQTI
         XJ8z6WEZXJ4AAbstSYfLrqdKRz07dlGoCxlYVn5tg7yhVzd0CS2hWSPhjVCnM/J+fjon
         1XZ1I1mMPzJV1h4j2cznxuI1o7NI9Y1+9p5IpqosJ7FHSqMjuYfy1fxDKwl4jNTWv6Sk
         Bkzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vd7UFaaC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id h83si473283ybg.3.2019.09.27.12.42.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Sep 2019 12:42:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id r5so8777387qtd.0
        for <kasan-dev@googlegroups.com>; Fri, 27 Sep 2019 12:42:03 -0700 (PDT)
X-Received: by 2002:ac8:7646:: with SMTP id i6mr12175862qtr.50.1569613322867;
 Fri, 27 Sep 2019 12:42:02 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com> <1569594142.9045.24.camel@mtksdccf07>
In-Reply-To: <1569594142.9045.24.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Sep 2019 21:41:51 +0200
Message-ID: <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vd7UFaaC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.com> wrote=
:
>
> On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.com> w=
rote:
> > >
> > > memmove() and memcpy() have missing underflow issues.
> > > When -7 <=3D size < 0, then KASAN will miss to catch the underflow is=
sue.
> > > It looks like shadow start address and shadow end address is the same=
,
> > > so it does not actually check anything.
> > >
> > > The following test is indeed not caught by KASAN:
> > >
> > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > >         memset((char *)p, 0, 64);
> > >         memmove((char *)p, (char *)p + 4, -2);
> > >         kfree((char*)p);
> > >
> > > It should be checked here:
> > >
> > > void *memmove(void *dest, const void *src, size_t len)
> > > {
> > >         check_memory_region((unsigned long)src, len, false, _RET_IP_)=
;
> > >         check_memory_region((unsigned long)dest, len, true, _RET_IP_)=
;
> > >
> > >         return __memmove(dest, src, len);
> > > }
> > >
> > > We fix the shadow end address which is calculated, then generic KASAN
> > > get the right shadow end address and detect this underflow issue.
> > >
> > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > >
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > ---
> > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> > >  mm/kasan/generic.c |  8 ++++++--
> > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index b63b367a94e8..8bd014852556 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_memse=
t(void)
> > >         kfree(ptr);
> > >  }
> > >
> > > +static noinline void __init kmalloc_oob_in_memmove_underflow(void)
> > > +{
> > > +       char *ptr;
> > > +       size_t size =3D 64;
> > > +
> > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > +       if (!ptr) {
> > > +               pr_err("Allocation failed\n");
> > > +               return;
> > > +       }
> > > +
> > > +       memset((char *)ptr, 0, 64);
> > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > +       kfree(ptr);
> > > +}
> > > +
> > > +static noinline void __init kmalloc_oob_in_memmove_overflow(void)
> > > +{
> > > +       char *ptr;
> > > +       size_t size =3D 64;
> > > +
> > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > +       if (!ptr) {
> > > +               pr_err("Allocation failed\n");
> > > +               return;
> > > +       }
> > > +
> > > +       memset((char *)ptr, 0, 64);
> > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > +       kfree(ptr);
> > > +}
> > > +
> > >  static noinline void __init kmalloc_uaf(void)
> > >  {
> > >         char *ptr;
> > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
> > >         kmalloc_oob_memset_4();
> > >         kmalloc_oob_memset_8();
> > >         kmalloc_oob_memset_16();
> > > +       kmalloc_oob_in_memmove_underflow();
> > > +       kmalloc_oob_in_memmove_overflow();
> > >         kmalloc_uaf();
> > >         kmalloc_uaf_memset();
> > >         kmalloc_uaf2();
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 616f9dd82d12..34ca23d59e67 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_poisoned_n=
(unsigned long addr,
> > >                                                 size_t size)
> > >  {
> > >         unsigned long ret;
> > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)addr);
> > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr + size =
- 1) + 1;
> > >
> > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
> > > -                       kasan_mem_to_shadow((void *)addr + size - 1) =
+ 1);
> > > +       if ((long)size < 0)
> > > +               shadow_end =3D kasan_mem_to_shadow((void *)addr + siz=
e);
> >
> > Hi Walter,
> >
> > Thanks for working on this.
> >
> > If size<0, does it make sense to continue at all? We will still check
> > 1PB of shadow memory? What happens when we pass such huge range to
> > memory_is_nonzero?
> > Perhaps it's better to produce an error and bail out immediately if siz=
e<0?
>
> I agree with what you said. when size<0, it is indeed an unreasonable
> behavior, it should be blocked from continuing to do.
>
>
> > Also, what's the failure mode of the tests? Didn't they badly corrupt
> > memory? We tried to keep tests such that they produce the KASAN
> > reports, but don't badly corrupt memory b/c/ we need to run all of
> > them.
>
> Maybe we should first produce KASAN reports and then go to execute
> memmove() or do nothing? It looks like it=E2=80=99s doing the following.o=
r?
>
> void *memmove(void *dest, const void *src, size_t len)
>  {
> +       if (long(len) <=3D 0)

/\/\/\/\/\/\

This check needs to be inside of check_memory_region, otherwise we
will have similar problems in all other places that use
check_memory_region.
But check_memory_region already returns a bool, so we could check that
bool and return early.


> +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> +
>         check_memory_region((unsigned long)src, len, false, _RET_IP_);
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w%40mail.gmai=
l.com.
