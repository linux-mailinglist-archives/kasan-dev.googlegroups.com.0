Return-Path: <kasan-dev+bncBCMIZB7QWENRBSOZ2LWAKGQETZG23OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 33773C8A51
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 15:57:31 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id q84sf9566697vkb.12
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 06:57:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570024650; cv=pass;
        d=google.com; s=arc-20160816;
        b=v07pPq9afXXWmbbymGmGRTB08+miTiLoPhY6N3ZxgmgEkPFE/4b2BdhO/2KmJafz8F
         NZkQc/tZmjAgUZQGNOiqOKuD+7QbB7FS+Swf13tACAbDZwDI39h90BSGdu//vatyhjxs
         ic5sWhc7Hj0DE084CPwq3lEF9QNw6vkPMOLc0lFIe5sJcfxbhnuPbPB6N51y+gTNE1Ik
         JsDEbFwCxSpRdLROVq8uiyTKk/EcJDnbDJJt1qYfTx916o3fDNQGrC3Gm7EM4HKt0Sv8
         hp29IBisOorJB5xBQL8VNcNgHl8y9Vk84nWPzkPaz3kRatGDoB6crso7V++z5ijv0EKB
         +lWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Upr7D8B/dKRj4wE9QfLeKR6QesvAD6XGQs6UpEfq2FU=;
        b=UCwCvaXvVWkHwCMwCkw1ZpjA+jIkdlCGQmFdOs9/9FR15uga74NiELBg9VJeCIcgzI
         r9Ca4GJBYTtKfroVYREWvLSXL8dTYt1ngxVJ3dQCVVQb8Xfomj6c9IWIV+7OpTSK2o6J
         53A+UfDFxMnx5h0HVRnIMAGVT8ussfbVE6Sa9VG1stAuaT2No+JxsUnRiDvMRH+2dFoa
         a4jWjPdJr32KdSy0LSvUGAPhiZtyQhf3YE3L9cqqUYlT/GJ9RntksbkkE2YChhnoeRym
         rBJ4up3Jj/B1PfxqEtMzXE6n1mx4HC6YZMLi0sKctRA2veOhNgJcoV9pHU5OAM2zFISE
         OS/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LOOnU4O6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Upr7D8B/dKRj4wE9QfLeKR6QesvAD6XGQs6UpEfq2FU=;
        b=bprL/pCAf0+AZ/GRDKqqSZWbyOunmsjoKs/x+ZA32tKmZKLdZ9QGhZ3vl7dQ85uDNe
         U+M0AJaXNZug0FRHEtFSSkX5fcRp4aD5UCpMD/0QUnaM0I5G8ikBHC2Lg+VQMpoAPIxW
         kn26vZU1+AUesFwvbw93FybGYu/lwWgny8552gHMIqcswCjjow5cOl9ty7cgh6/yBY64
         z3F5fqyVf4j833mLSnRTmDF6sic10aIIn2GsmxpqprpNWlpBgrwnbG6QnWDoTDK/Oc8z
         3Mm71hbsdrKISPuxCC/AYZZgR3DcIAI3W+Ymo1JZmJFA2R3ynd8lXDjMxGthRNwW41q7
         0Upg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Upr7D8B/dKRj4wE9QfLeKR6QesvAD6XGQs6UpEfq2FU=;
        b=IPH+t5rdpn6hJriMki7RQOcFigucnoaON8xgbZ3F2SKglt0iJxpEPWhIT7qxAHKGFw
         AfnFoNhpCxe36FSqBJ02K/w71gHrgOr72js57fuRgIYrp8lX/UaPROYmnhjQZyaYPvz9
         e8DaIVehCsv4KoYzZ8TEL72PDdYCThWmr3+SpQK0jXWzeXosOfwiTig1qHREmoaSh9ef
         hDX2zEeuTHIfIn5Fh21Iz07Dpzqno0Ubb53A2LYpMkuAZuhM+2JKe4XG6hDtO0n7wOcF
         wVWs9zxYiZXqXoASdFkEBQk8b8dI+Mz9Qel4Xz7N3x3SpJc/YyzsQX0hRb1B0akvznbm
         7HXw==
X-Gm-Message-State: APjAAAUGZfjP5XVtV4IjM5uJ/hljtobpkRwOUIJ+smZaDYjCVC5BzMl/
	xZK1JM4XyC6aMS6/rzrzBa4=
X-Google-Smtp-Source: APXvYqxcZK808uGlDPB+DhfCJD8w+kh+vitNm6o/j7C6Sx6Q2P8HZhDaP2//yx8b+sIO1DYLk02m7A==
X-Received: by 2002:a67:da10:: with SMTP id v16mr1999505vsj.80.1570024649847;
        Wed, 02 Oct 2019 06:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7c54:: with SMTP id x81ls256900vsc.1.gmail; Wed, 02 Oct
 2019 06:57:29 -0700 (PDT)
X-Received: by 2002:a67:bc15:: with SMTP id t21mr1868084vsn.90.1570024649542;
        Wed, 02 Oct 2019 06:57:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570024649; cv=none;
        d=google.com; s=arc-20160816;
        b=cJdawZV2gn/NBZlRwmBD6ALdv2E/MFzOHtFOLfLKGGBkIXW1n1x/nNogln/1vLEUK/
         qaw9kOeYuR8xTVMHf/xlTw6KT8395IkypxDFzvZ59FGHaQOzaMQi7TgM7UP/jUTrhzfq
         M3cDjSHcSQ2l0VKrrPb7896Ir99u3LbWlrYbshtGH1NRrus4vAssAhrLX6nxmTzgZngP
         4RISIaW0y7LJvquu4zTvA+WrKkgYQ5Q7WYv2ZYafRZkdlby/wU613A3IfiF1U0SpJ5St
         w9dxH3xFAi4x16o7TfEs2ABwwb8kEfrY0ma9hnZAXGyuKmvk13LvF0CJ+5Mq/ozs+XgF
         be8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V8brLeomy2wdADVlgEAXrAF/graRCxkPl6qeQ6D8/UY=;
        b=hzxtorAEutxTVqvnGWRfZlocYBvBuThnQk7wHi46Y9BnGn/jQZ6vkMlVMK2SChsqbi
         BTJ0Y0VyGXy8qt29TRFNrMXRMhEnZoboB5BOFDlD/plOMTTmcMWyic5ymneDelES/kpX
         fmMJfSldAoAzKsJlemO5ytTvLbvXh3ANPjvv/HLCUWn1G7e/gmKlJr1b45MOpxJF0pfn
         vdFbbFLxrxSWec4RvpZtvXwNeBRvmKl9jeEXg2dxuQYN/AiDSYYnQyGOUTO2Gvpq8tTu
         LKoaS4YS6fD3rWMfbmfXfLWsnQBc31IQiimXOaabTNXSijMaOZN40YbalGVw9Y13HEbx
         r2UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LOOnU4O6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id u65si767357vsb.0.2019.10.02.06.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 06:57:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id q203so15084851qke.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 06:57:29 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr3463814qkn.407.1570024648625;
 Wed, 02 Oct 2019 06:57:28 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
In-Reply-To: <1570018513.19702.36.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Oct 2019 15:57:16 +0200
Message-ID: <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=LOOnU4O6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Wed, Oct 2, 2019 at 2:15 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> > On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.com>=
 wrote:
> > > >
> > > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.=
com> wrote:
> > > > > >
> > > > > > memmove() and memcpy() have missing underflow issues.
> > > > > > When -7 <=3D size < 0, then KASAN will miss to catch the underf=
low issue.
> > > > > > It looks like shadow start address and shadow end address is th=
e same,
> > > > > > so it does not actually check anything.
> > > > > >
> > > > > > The following test is indeed not caught by KASAN:
> > > > > >
> > > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > > >         memset((char *)p, 0, 64);
> > > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > > >         kfree((char*)p);
> > > > > >
> > > > > > It should be checked here:
> > > > > >
> > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > {
> > > > > >         check_memory_region((unsigned long)src, len, false, _RE=
T_IP_);
> > > > > >         check_memory_region((unsigned long)dest, len, true, _RE=
T_IP_);
> > > > > >
> > > > > >         return __memmove(dest, src, len);
> > > > > > }
> > > > > >
> > > > > > We fix the shadow end address which is calculated, then generic=
 KASAN
> > > > > > get the right shadow end address and detect this underflow issu=
e.
> > > > > >
> > > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > > > >
> > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > ---
> > > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> > > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > > >
> > > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > > index b63b367a94e8..8bd014852556 100644
> > > > > > --- a/lib/test_kasan.c
> > > > > > +++ b/lib/test_kasan.c
> > > > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in=
_memset(void)
> > > > > >         kfree(ptr);
> > > > > >  }
> > > > > >
> > > > > > +static noinline void __init kmalloc_oob_in_memmove_underflow(v=
oid)
> > > > > > +{
> > > > > > +       char *ptr;
> > > > > > +       size_t size =3D 64;
> > > > > > +
> > > > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > +       if (!ptr) {
> > > > > > +               pr_err("Allocation failed\n");
> > > > > > +               return;
> > > > > > +       }
> > > > > > +
> > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > > +       kfree(ptr);
> > > > > > +}
> > > > > > +
> > > > > > +static noinline void __init kmalloc_oob_in_memmove_overflow(vo=
id)
> > > > > > +{
> > > > > > +       char *ptr;
> > > > > > +       size_t size =3D 64;
> > > > > > +
> > > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > +       if (!ptr) {
> > > > > > +               pr_err("Allocation failed\n");
> > > > > > +               return;
> > > > > > +       }
> > > > > > +
> > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > > +       kfree(ptr);
> > > > > > +}
> > > > > > +
> > > > > >  static noinline void __init kmalloc_uaf(void)
> > > > > >  {
> > > > > >         char *ptr;
> > > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
> > > > > >         kmalloc_oob_memset_4();
> > > > > >         kmalloc_oob_memset_8();
> > > > > >         kmalloc_oob_memset_16();
> > > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > > >         kmalloc_uaf();
> > > > > >         kmalloc_uaf_memset();
> > > > > >         kmalloc_uaf2();
> > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > > --- a/mm/kasan/generic.c
> > > > > > +++ b/mm/kasan/generic.c
> > > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_pois=
oned_n(unsigned long addr,
> > > > > >                                                 size_t size)
> > > > > >  {
> > > > > >         unsigned long ret;
> > > > > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)addr=
);
> > > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr +=
 size - 1) + 1;
> > > > > >
> > > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *)a=
ddr),
> > > > > > -                       kasan_mem_to_shadow((void *)addr + size=
 - 1) + 1);
> > > > > > +       if ((long)size < 0)
> > > > > > +               shadow_end =3D kasan_mem_to_shadow((void *)addr=
 + size);
> > > > >
> > > > > Hi Walter,
> > > > >
> > > > > Thanks for working on this.
> > > > >
> > > > > If size<0, does it make sense to continue at all? We will still c=
heck
> > > > > 1PB of shadow memory? What happens when we pass such huge range t=
o
> > > > > memory_is_nonzero?
> > > > > Perhaps it's better to produce an error and bail out immediately =
if size<0?
> > > >
> > > > I agree with what you said. when size<0, it is indeed an unreasonab=
le
> > > > behavior, it should be blocked from continuing to do.
> > > >
> > > >
> > > > > Also, what's the failure mode of the tests? Didn't they badly cor=
rupt
> > > > > memory? We tried to keep tests such that they produce the KASAN
> > > > > reports, but don't badly corrupt memory b/c/ we need to run all o=
f
> > > > > them.
> > > >
> > > > Maybe we should first produce KASAN reports and then go to execute
> > > > memmove() or do nothing? It looks like it=E2=80=99s doing the follo=
wing.or?
> > > >
> > > > void *memmove(void *dest, const void *src, size_t len)
> > > >  {
> > > > +       if (long(len) <=3D 0)
> > >
> > > /\/\/\/\/\/\
> > >
> > > This check needs to be inside of check_memory_region, otherwise we
> > > will have similar problems in all other places that use
> > > check_memory_region.
> > Thanks for your reminder.
> >
> >  bool check_memory_region(unsigned long addr, size_t size, bool write,
> >                                 unsigned long ret_ip)
> >  {
> > +       if (long(size) < 0) {
> > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > +               return false;
> > +       }
> > +
> >         return check_memory_region_inline(addr, size, write, ret_ip);
> >  }
> >
> > > But check_memory_region already returns a bool, so we could check tha=
t
> > > bool and return early.
> >
> > When size<0, we should only show one KASAN report, and should we only
> > limit to return when size<0 is true? If yse, then __memmove() will do
> > nothing.
> >
> >
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > +       if(!check_memory_region((unsigned long)src, len, false,
> > _RET_IP_)
> > +               && long(size) < 0)
> > +               return;
> > +
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >         return __memmove(dest, src, len);
> >
> > >
> Hi Dmitry,
>
> What do you think the following code is better than the above one.
> In memmmove/memset/memcpy, they need to determine whether size < 0 is
> true. we directly determine whether size is negative in memmove and
> return early. it avoid to generate repeated KASAN report. Is it better?
>
> void *memmove(void *dest, const void *src, size_t len)
> {
> +       if (long(size) < 0) {
> +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> +               return;
> +       }
> +
>         check_memory_region((unsigned long)src, len, false, _RET_IP_);
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>
>
> check_memory_region() still has to check whether the size is negative.
> but memmove/memset/memcpy generate invalid size KASAN report will not be
> there.


If check_memory_region() will do the check, why do we need to
duplicate it inside of memmove and all other range functions?

I would do:

void *memmove(void *dest, const void *src, size_t len)
{
        if (check_memory_region((unsigned long)src, len, false, _RET_IP_))
                return;

This avoids duplicating the check, adds minimal amount of code to
range functions and avoids adding kasan_report_invalid_size.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbbZhvz9ZpHtgL8rCCsV%3DybU5jA6zFnJBL7gY2cNXDLyQ%40mail.gm=
ail.com.
