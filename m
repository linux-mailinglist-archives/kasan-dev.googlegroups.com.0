Return-Path: <kasan-dev+bncBCMIZB7QWENRBCVJ23WAKGQEN42YUKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id B1ECFC9835
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 08:26:19 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id k132sf632149vka.5
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 23:26:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570083978; cv=pass;
        d=google.com; s=arc-20160816;
        b=IjqQ/TmBX8ePWOTdI1UxQjQaWH7szo1RsAIn5ChrbNEcGTsu/rvQz9uGghh/VRKxdR
         hNI9rHk+R/qApp8Re6FfNcH3x0Ko4MOyTugr2xTxnh+22kbDYjzMILRLlAFTsXcTWh62
         0Mkyhbdp7iYJLppyS092I0v3jFuYlnfe4Ik7+F7ei7//6muEVWDud6y0P5K93G84BNtQ
         RawFBv/MOlW1pZVsddPaJSsuBq+VbZKb9GIy1oPA80eyyGVQzwiHR5CwtCDBg0TjCDa3
         kCR2bpq6DYz1m6nct0uMQb34q3S2CAQFIryT1GviYoHbslVEjdHy+MPPKa4898PLlfWh
         y5ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=betyiOSHqWsGwkuY1NqLRsbQzF5bZE3H7lobXU+1MnY=;
        b=GxjVfNVhg3DKH/OUFmL4dg+QlFHk5cVp+1i6VlqPPPwL4hpnLGDhx3vX71wijraAq8
         MZXK6gwx+R66duLziRiXXp6z9r7QJ8TaDYbFdhgAirkYlgVxbSis3YfRYsZ8w4OLc3fj
         DxWuxU6agL2wMgwAEVCA08RCgvoc3Y26EaddrkIC1ZII3pT3uNhp4VaN7SZljCGrNKQo
         JoLYzSSapu4GL54ZQmgBxFCa/q0GLqI1r0VyVitEIkhroBZViD/TIXZ2dgt3Q2uBt8rA
         p4fL78TcU3MK+FeszYXDXLL7g4uvmwYUSY5QFcj+tgUx1rNm/j3EkyDKWSnu4z8WX1h4
         7wdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QqpipN7E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=betyiOSHqWsGwkuY1NqLRsbQzF5bZE3H7lobXU+1MnY=;
        b=QcgAyJHg0ej6Kz1GNI4/o6FwwmWQCuTSTmQeF5WCtqnuko1wBJDADRioV1VrIF+s3k
         3cbX05dzBnyo3+VzQTGK2IW+Mi1U+g2AuR3KtkS5WTF4r1EEs1BqEOQvGEjOhOJAcAr5
         asTggjITHUEmXwNMvn/aPJbfoVyI7Gugs2SgK1qV++ncU5Dy34D1RtRxqhb0UOUyctHV
         rKoiTlATMxl5sXuArap6HcYAisxrRklodXAa233J+Omb5zfYdAV2KZlLNwqGcxTQ9E0T
         7+swDM4hHQL/JxvAOOfDdQ/QViBMNI+3SzxVRiVMw+Uku5lupLRNC365pvq/Wy0gcTkL
         VK+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=betyiOSHqWsGwkuY1NqLRsbQzF5bZE3H7lobXU+1MnY=;
        b=SUW+P+MGNCB1Sf+DvMdVebTVPXClMWgsT3ro8/8aTIwPKBzvEYVlOOZskOakPl64q1
         b06uP48mCgfeXb68yyq6IbltOd1M4FQ9xyxdR4kewkjyl/vlB5n0l6JgERhuQfBPU0ha
         Aycu61Xe2PYXJ4VnY6y1qr1fdKRkw8CQE6gX6HX6hISfrdJsZ2RfreCZf5oKvURTsvFS
         L+8ZoAb5vDKCTxcssWb1+Ot4D/TQUtLZKCRazmt+NM2pTrgvznhVNdgr+6/RK/aGf9+H
         EM2ONkZzekxgo59w8d7REkzGiz6SG8SJPF8Bt3zfOTiMbJ07P/W07uhDU0OHiNhK/muv
         VkMQ==
X-Gm-Message-State: APjAAAU025tj6O++S/vGf0omULj/EoT5t2kQp8iHerJ4zIR5HA+uSyMx
	M4nN2VkVDn9c1oAOvaIQPZM=
X-Google-Smtp-Source: APXvYqzQqwWxzXC6FpC3Bv4rXEmIgO/G3gVN52ZalQeBuDV9uVXTfjBGoj+aQVUS2JXRDoT7MwpkBg==
X-Received: by 2002:ab0:7451:: with SMTP id p17mr3918471uaq.76.1570083978444;
        Wed, 02 Oct 2019 23:26:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2d8f:: with SMTP id t137ls521469vst.10.gmail; Wed, 02
 Oct 2019 23:26:18 -0700 (PDT)
X-Received: by 2002:a67:f306:: with SMTP id p6mr4108112vsf.131.1570083978130;
        Wed, 02 Oct 2019 23:26:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570083978; cv=none;
        d=google.com; s=arc-20160816;
        b=VhXX4w5rPAfcbH/okQHU6InYfih8azYednS3s+t480N9fwlUNmcU6Oo9phOB0bGc2t
         7wcdic9F93MYRfdUbZNuw0fbqjKYYh2I+Edq+OiApgp9ACvjXiQdn1fMnQ8DQgAGGps8
         ATj0Qj895nsIE9SJt9l9+20kl11xq+hDL8ivunYulidkK6qFa9I6rZ6DA9ilcebSJKmj
         K/Y5b47T4MSceONVfejoML7okvIsIL8QaSpADTP6HbiRDei/Ymr00WaF6/uhE/CLaNcC
         HQld/pgE7D7FD3YYVRcfSIqsJFqjOdAJlB9QeGBoV0grpe1H8RZdvFaygp7E7awGM9vd
         E9rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4nvCkkxF3tpM+x3xn7dqGTYCKi4uqYijHIaCGSNEFak=;
        b=qwJlevxjI7M7rfJihJRE+Uu8Aic41YmE41Bv7fg7vaP8Tfkg5fG0UOc4qpZa9zvTaW
         wqkMiRKcsUkj/gGMoevA3GhtEaF5VkvsLJjllO4fI/h2rVbizYQXLXLVultKWM48psw/
         0etGR13lDlDfiOeo3m9DlreZAHJnllziOmjR7n3g71kdrwjd9VWbXn0gI3Y5UX3pmvI/
         oYMPSmlxmufZ1AxSATKbEI+bYGifo6BGs8hpaBke6A1yGMkkN4G4KTC9lZ4BwXCjmrEt
         DQ1u0m5INdLdXX27lreN11YEJFk5hzoP7DwFC4WTgBMA3Lx40iVU7+EKuDIss9CSrdHv
         U+zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QqpipN7E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id y14si81621vsj.2.2019.10.02.23.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 23:26:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id z67so1204046qkb.12
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 23:26:18 -0700 (PDT)
X-Received: by 2002:a37:9202:: with SMTP id u2mr2854753qkd.8.1570083977128;
 Wed, 02 Oct 2019 23:26:17 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com> <1570069078.19702.57.camel@mtksdccf07>
In-Reply-To: <1570069078.19702.57.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Oct 2019 08:26:05 +0200
Message-ID: <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=QqpipN7E;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Oct 3, 2019 at 4:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Wed, 2019-10-02 at 15:57 +0200, Dmitry Vyukov wrote:
> > On Wed, Oct 2, 2019 at 2:15 PM Walter Wu <walter-zh.wu@mediatek.com> wr=
ote:
> > >
> > > On Mon, 2019-09-30 at 12:36 +0800, Walter Wu wrote:
> > > > On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> > > > > On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.=
com> wrote:
> > > > > >
> > > > > > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > > > > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@media=
tek.com> wrote:
> > > > > > > >
> > > > > > > > memmove() and memcpy() have missing underflow issues.
> > > > > > > > When -7 <=3D size < 0, then KASAN will miss to catch the un=
derflow issue.
> > > > > > > > It looks like shadow start address and shadow end address i=
s the same,
> > > > > > > > so it does not actually check anything.
> > > > > > > >
> > > > > > > > The following test is indeed not caught by KASAN:
> > > > > > > >
> > > > > > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > > > > > >         memset((char *)p, 0, 64);
> > > > > > > >         memmove((char *)p, (char *)p + 4, -2);
> > > > > > > >         kfree((char*)p);
> > > > > > > >
> > > > > > > > It should be checked here:
> > > > > > > >
> > > > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > > > > {
> > > > > > > >         check_memory_region((unsigned long)src, len, false,=
 _RET_IP_);
> > > > > > > >         check_memory_region((unsigned long)dest, len, true,=
 _RET_IP_);
> > > > > > > >
> > > > > > > >         return __memmove(dest, src, len);
> > > > > > > > }
> > > > > > > >
> > > > > > > > We fix the shadow end address which is calculated, then gen=
eric KASAN
> > > > > > > > get the right shadow end address and detect this underflow =
issue.
> > > > > > > >
> > > > > > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > > > > > >
> > > > > > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > > > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > > ---
> > > > > > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++=
++
> > > > > > > >  mm/kasan/generic.c |  8 ++++++--
> > > > > > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > > > > > >
> > > > > > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > > > > > index b63b367a94e8..8bd014852556 100644
> > > > > > > > --- a/lib/test_kasan.c
> > > > > > > > +++ b/lib/test_kasan.c
> > > > > > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oo=
b_in_memset(void)
> > > > > > > >         kfree(ptr);
> > > > > > > >  }
> > > > > > > >
> > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_underfl=
ow(void)
> > > > > > > > +{
> > > > > > > > +       char *ptr;
> > > > > > > > +       size_t size =3D 64;
> > > > > > > > +
> > > > > > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > +       if (!ptr) {
> > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > +               return;
> > > > > > > > +       }
> > > > > > > > +
> > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > > > > > +       kfree(ptr);
> > > > > > > > +}
> > > > > > > > +
> > > > > > > > +static noinline void __init kmalloc_oob_in_memmove_overflo=
w(void)
> > > > > > > > +{
> > > > > > > > +       char *ptr;
> > > > > > > > +       size_t size =3D 64;
> > > > > > > > +
> > > > > > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > > > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > > > > > +       if (!ptr) {
> > > > > > > > +               pr_err("Allocation failed\n");
> > > > > > > > +               return;
> > > > > > > > +       }
> > > > > > > > +
> > > > > > > > +       memset((char *)ptr, 0, 64);
> > > > > > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > > > > > +       kfree(ptr);
> > > > > > > > +}
> > > > > > > > +
> > > > > > > >  static noinline void __init kmalloc_uaf(void)
> > > > > > > >  {
> > > > > > > >         char *ptr;
> > > > > > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(vo=
id)
> > > > > > > >         kmalloc_oob_memset_4();
> > > > > > > >         kmalloc_oob_memset_8();
> > > > > > > >         kmalloc_oob_memset_16();
> > > > > > > > +       kmalloc_oob_in_memmove_underflow();
> > > > > > > > +       kmalloc_oob_in_memmove_overflow();
> > > > > > > >         kmalloc_uaf();
> > > > > > > >         kmalloc_uaf_memset();
> > > > > > > >         kmalloc_uaf2();
> > > > > > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > > > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > > > > > --- a/mm/kasan/generic.c
> > > > > > > > +++ b/mm/kasan/generic.c
> > > > > > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_=
poisoned_n(unsigned long addr,
> > > > > > > >                                                 size_t size=
)
> > > > > > > >  {
> > > > > > > >         unsigned long ret;
> > > > > > > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)=
addr);
> > > > > > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)ad=
dr + size - 1) + 1;
> > > > > > > >
> > > > > > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void=
 *)addr),
> > > > > > > > -                       kasan_mem_to_shadow((void *)addr + =
size - 1) + 1);
> > > > > > > > +       if ((long)size < 0)
> > > > > > > > +               shadow_end =3D kasan_mem_to_shadow((void *)=
addr + size);
> > > > > > >
> > > > > > > Hi Walter,
> > > > > > >
> > > > > > > Thanks for working on this.
> > > > > > >
> > > > > > > If size<0, does it make sense to continue at all? We will sti=
ll check
> > > > > > > 1PB of shadow memory? What happens when we pass such huge ran=
ge to
> > > > > > > memory_is_nonzero?
> > > > > > > Perhaps it's better to produce an error and bail out immediat=
ely if size<0?
> > > > > >
> > > > > > I agree with what you said. when size<0, it is indeed an unreas=
onable
> > > > > > behavior, it should be blocked from continuing to do.
> > > > > >
> > > > > >
> > > > > > > Also, what's the failure mode of the tests? Didn't they badly=
 corrupt
> > > > > > > memory? We tried to keep tests such that they produce the KAS=
AN
> > > > > > > reports, but don't badly corrupt memory b/c/ we need to run a=
ll of
> > > > > > > them.
> > > > > >
> > > > > > Maybe we should first produce KASAN reports and then go to exec=
ute
> > > > > > memmove() or do nothing? It looks like it=E2=80=99s doing the f=
ollowing.or?
> > > > > >
> > > > > > void *memmove(void *dest, const void *src, size_t len)
> > > > > >  {
> > > > > > +       if (long(len) <=3D 0)
> > > > >
> > > > > /\/\/\/\/\/\
> > > > >
> > > > > This check needs to be inside of check_memory_region, otherwise w=
e
> > > > > will have similar problems in all other places that use
> > > > > check_memory_region.
> > > > Thanks for your reminder.
> > > >
> > > >  bool check_memory_region(unsigned long addr, size_t size, bool wri=
te,
> > > >                                 unsigned long ret_ip)
> > > >  {
> > > > +       if (long(size) < 0) {
> > > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_)=
;
> > > > +               return false;
> > > > +       }
> > > > +
> > > >         return check_memory_region_inline(addr, size, write, ret_ip=
);
> > > >  }
> > > >
> > > > > But check_memory_region already returns a bool, so we could check=
 that
> > > > > bool and return early.
> > > >
> > > > When size<0, we should only show one KASAN report, and should we on=
ly
> > > > limit to return when size<0 is true? If yse, then __memmove() will =
do
> > > > nothing.
> > > >
> > > >
> > > >  void *memmove(void *dest, const void *src, size_t len)
> > > >  {
> > > > -       check_memory_region((unsigned long)src, len, false, _RET_IP=
_);
> > > > +       if(!check_memory_region((unsigned long)src, len, false,
> > > > _RET_IP_)
> > > > +               && long(size) < 0)
> > > > +               return;
> > > > +
> > > >         check_memory_region((unsigned long)dest, len, true, _RET_IP=
_);
> > > >
> > > >         return __memmove(dest, src, len);
> > > >
> > > > >
> > > Hi Dmitry,
> > >
> > > What do you think the following code is better than the above one.
> > > In memmmove/memset/memcpy, they need to determine whether size < 0 is
> > > true. we directly determine whether size is negative in memmove and
> > > return early. it avoid to generate repeated KASAN report. Is it bette=
r?
> > >
> > > void *memmove(void *dest, const void *src, size_t len)
> > > {
> > > +       if (long(size) < 0) {
> > > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > > +               return;
> > > +       }
> > > +
> > >         check_memory_region((unsigned long)src, len, false, _RET_IP_)=
;
> > >         check_memory_region((unsigned long)dest, len, true, _RET_IP_)=
;
> > >
> > >
> > > check_memory_region() still has to check whether the size is negative=
.
> > > but memmove/memset/memcpy generate invalid size KASAN report will not=
 be
> > > there.
> >
> >
> > If check_memory_region() will do the check, why do we need to
> > duplicate it inside of memmove and all other range functions?
> >
> Yes, I know it has duplication, but if we don't have to determine size<0
> in memmove, then all check_memory_region return false will do nothing,

But they will produce a KASAN report, right? They are asked to check
if 18446744073709551614 bytes are good. 18446744073709551614 bytes
can't be good.


> it includes other memory corruption behaviors, this is my original
> concern.
>
> > I would do:
> >
> > void *memmove(void *dest, const void *src, size_t len)
> > {
> >         if (check_memory_region((unsigned long)src, len, false, _RET_IP=
_))
> >                 return;
> if check_memory_region return TRUE is to do nothing, but it is no memory
> corruption? Should it return early when check_memory_region return a
> FALSE?

Maybe. I just meant the overall idea: check_memory_region should
detect that 18446744073709551614 bytes are bad, print an error, return
an indication that bytes were bad, memmove should return early if the
range is bad.


> > This avoids duplicating the check, adds minimal amount of code to
> > range functions and avoids adding kasan_report_invalid_size.
> Thanks for your suggestion.
> We originally want to show complete information(destination address,
> source address, and its length), but add minimal amount of code into
> kasan_report(), it should be good.
>
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/1570069078.19702.57.camel%40mtksdccf07.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZwNv2-QBrvuR2JvemovmKPQ9Ggrr%3DZkdTg6xy_Ki6UAg%40mail.gm=
ail.com.
