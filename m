Return-Path: <kasan-dev+bncBAABBQ4MY3WAKGQE4XQP3QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 71F15C1ABC
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 06:36:21 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id w16sf27866308ioc.15
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Sep 2019 21:36:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569818179; cv=pass;
        d=google.com; s=arc-20160816;
        b=WImECtj4Xw4VocDcaguVCzVg7ViAVQ0pfh4NZYKWQJe7pC4IISW9+WurdElt/roex8
         VhRSWIGZs5lSdv5C46faCiQX/MvB92D6sdN+kDhEWK3cKTg6Sw3uRAbLJyq5KRxjzNbU
         Y5pbe1AtiAwr7ih+ZLq4gVdN5GtM6rw3PJy8pHL0v43ovtFHIZHIPAWhsjz2Yuk1FNaD
         qT/Eshl+0MSyoISc3zdGWArNK11OFoO3nkG3KI5i4TAabIjQpharXRbzbCdPLIwUHe30
         M9ITuRMeX9V14KIIOUJMj6R82UJdqo9oZoYLeelpbM5wQwXKMdQv6wS/ATxcuZVo9VIL
         bf9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=yUhK80i1FfjnUpyFaw9kqyR2jc/BZp1+yEeon/Z0dGA=;
        b=SbreAnCdtwqDryMZeZMG0KmPSdH1YVLgJXjKL1Fa1aXJB2tOTnPoBNMS7MjtWCgdJR
         ed5TtuXx2aPx7krdwHvCxBfRbjSeSIpZcDAjaChzy6HpNjFh80MrN101nXkz2S06v3dt
         xS1fDY2B7yvdZj4F7En32ywMdg+uXNr7z3fgr01ttrx5DBqP4tpOce9dTnY9Ms09QnDA
         MlI2j9uH9++4RP4TSp7pGfgoaQdWmcsR10ge6cKfIRXR2cTJ/4g+jeCg3nk5UldnnCyb
         fFVdQbqIAz0KKLGvc204Yv11K+4DyeoRsCzSbETdLwKSRKpqFgr6DBOxDafz9qfNfMxg
         j8JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yUhK80i1FfjnUpyFaw9kqyR2jc/BZp1+yEeon/Z0dGA=;
        b=VupKo+3vRFwp9wKgWMslA7fqSwzIc6IkGjzG3lUg8OfeLL3nCdPOFI+EuOQutMq8Sy
         1KTjGP3+U7fbBYlUSBJf2Un2MY/P+ZoO1aldfsddFSLnNkTvn+OCJxOlMurrz+ZvfrvT
         YI2Kdj5vmXmei+fbDjz8e/zDU4PBQchEV5X7ZcT+zEO4TH0a5H2IHtqmyBH92711/KYo
         ElF3824HVI5bQKQKqJbA/sbEta8v3NfL81ipaNYnOX9bjTv8azzDCDFEW5Ree1iDr7/Z
         BJNuWMj9DAySdYBJIzdrVY60dzbXWkn0nDhae+u/6zRBtF7accHsHnh8tHtMCkah+40N
         X2ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yUhK80i1FfjnUpyFaw9kqyR2jc/BZp1+yEeon/Z0dGA=;
        b=gE1zPjMme/MHDczsGERDvigeBhQGCkxehhUsEY3KFGOU+9QHF6daHtpmRaBcYDungG
         +zeBnIr1ohzaXUArlQxH9CnJ0nKr2z+ogrICYVfU1drGsZwxMhVOyPJHvTeX2p98ouHz
         sIFzfoNA0RdV60U0zEzLvRkC7x3GRPQczOw0njntMhL9BYG2yfCPkbTlrh7MwDqn0rBu
         PcPuXFqHnqGrZactwbmcO8xmwoIz9LExjR1a4xOXlZZhLFYjj1tWVVzJOfjokyECFTGk
         oODspSM11HXIyxN3oOyOTRn+pRurxinSK1OeXoPGrY2LXZh/JYHacEKh0saGIyQxQ5jg
         lzew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWGH/AhhRszmY5eeDi5pXhM/9tRxYpUTZ7PZUt5oLhE+mPUaY9c
	77pswGp8DRl65VcYbO5QgH0=
X-Google-Smtp-Source: APXvYqw9MlIICY/jcUaCk/FwPOJd7F6usjUaXuvK4KQ1hI9Y2RJd/hBRst2nZadSZRt8yH5eFBDB7w==
X-Received: by 2002:a92:af15:: with SMTP id n21mr18882161ili.224.1569818179779;
        Sun, 29 Sep 2019 21:36:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8112:: with SMTP id e18ls1668281ild.16.gmail; Sun, 29
 Sep 2019 21:36:19 -0700 (PDT)
X-Received: by 2002:a92:1559:: with SMTP id v86mr18733381ilk.130.1569818179357;
        Sun, 29 Sep 2019 21:36:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569818179; cv=none;
        d=google.com; s=arc-20160816;
        b=aXxpAKn/d6oK2iVxqhypwCX51b+bBUY5bBtPirToQTdxaUnVNDMfUKYAQySwdvvPWN
         wjikQ3ItI3z765hyS5MOlLmIIwxCQXaaiXdukr0Jwf21o/KPUw44hZily4nC2LiPNhKJ
         wTiVQGrSwewRV3k1L8a5dHY3FjcpHnf4aGuJqUTs9lHdKAzPEQlmkqmW8no3vTr/uQjW
         WDhM1P+zzKMWfcRwVMHecFkZC/jOQxygG7PxgSa51LxfvYVuzapPqmWaNP4UPk+YtpwR
         024Zk5yO1wjoutJqNCkqUEiNCZuZl1QrpccEoLG3dHJV3GfwIRO+PHldO+FMR55tg3yu
         crzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=xCfaFLTLBO66HP36F/ja2IQ4avavXrTK7fTX6jP4F9I=;
        b=bxr720Lef9NehDw+0pRk0colD/TDZTxD4P/+YTgEHeNL6Qs1Hjtfc2OQ+7fGgSsxmY
         zYVDgWniH9xzsrdWSIVIf1sNJHCVuhxmq2S+wdX/U6Ok8CoMeoHPX72Zu1BwI6/D60vz
         LO8YFHzV3orM6t/PI26qW4XUshyRLJ4gadbq7u00BtQLUHTeLkD+6Pg8cWcyDJ38mBtA
         NE0YydjOAgUzFYdWQpPolSDzKnYWEXQt+TTl7N2+OwKYsVOX3PvDbJ2PrvI/dzL3kHXO
         lZi6+Ty5qDba6sFpMX5blxOcseEX6w9k+czmti7s/Oj21e38VQFL2NteZZwbYxh61sf+
         GPyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id n201si925065iod.3.2019.09.29.21.36.18
        for <kasan-dev@googlegroups.com>;
        Sun, 29 Sep 2019 21:36:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e1d300432a7e4615a02e2666ab96cad6-20190930
X-UUID: e1d300432a7e4615a02e2666ab96cad6-20190930
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1444693639; Mon, 30 Sep 2019 12:36:14 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 30 Sep 2019 12:36:12 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 30 Sep 2019 12:36:12 +0800
Message-ID: <1569818173.17361.19.camel@mtksdccf07>
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
Date: Mon, 30 Sep 2019 12:36:13 +0800
In-Reply-To: <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
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

On Fri, 2019-09-27 at 21:41 +0200, Dmitry Vyukov wrote:
> On Fri, Sep 27, 2019 at 4:22 PM Walter Wu <walter-zh.wu@mediatek.com> wro=
te:
> >
> > On Fri, 2019-09-27 at 15:07 +0200, Dmitry Vyukov wrote:
> > > On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.com>=
 wrote:
> > > >
> > > > memmove() and memcpy() have missing underflow issues.
> > > > When -7 <=3D size < 0, then KASAN will miss to catch the underflow =
issue.
> > > > It looks like shadow start address and shadow end address is the sa=
me,
> > > > so it does not actually check anything.
> > > >
> > > > The following test is indeed not caught by KASAN:
> > > >
> > > >         char *p =3D kmalloc(64, GFP_KERNEL);
> > > >         memset((char *)p, 0, 64);
> > > >         memmove((char *)p, (char *)p + 4, -2);
> > > >         kfree((char*)p);
> > > >
> > > > It should be checked here:
> > > >
> > > > void *memmove(void *dest, const void *src, size_t len)
> > > > {
> > > >         check_memory_region((unsigned long)src, len, false, _RET_IP=
_);
> > > >         check_memory_region((unsigned long)dest, len, true, _RET_IP=
_);
> > > >
> > > >         return __memmove(dest, src, len);
> > > > }
> > > >
> > > > We fix the shadow end address which is calculated, then generic KAS=
AN
> > > > get the right shadow end address and detect this underflow issue.
> > > >
> > > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D199341
> > > >
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > > > ---
> > > >  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
> > > >  mm/kasan/generic.c |  8 ++++++--
> > > >  2 files changed, 42 insertions(+), 2 deletions(-)
> > > >
> > > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > > index b63b367a94e8..8bd014852556 100644
> > > > --- a/lib/test_kasan.c
> > > > +++ b/lib/test_kasan.c
> > > > @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_mem=
set(void)
> > > >         kfree(ptr);
> > > >  }
> > > >
> > > > +static noinline void __init kmalloc_oob_in_memmove_underflow(void)
> > > > +{
> > > > +       char *ptr;
> > > > +       size_t size =3D 64;
> > > > +
> > > > +       pr_info("underflow out-of-bounds in memmove\n");
> > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > +       if (!ptr) {
> > > > +               pr_err("Allocation failed\n");
> > > > +               return;
> > > > +       }
> > > > +
> > > > +       memset((char *)ptr, 0, 64);
> > > > +       memmove((char *)ptr, (char *)ptr + 4, -2);
> > > > +       kfree(ptr);
> > > > +}
> > > > +
> > > > +static noinline void __init kmalloc_oob_in_memmove_overflow(void)
> > > > +{
> > > > +       char *ptr;
> > > > +       size_t size =3D 64;
> > > > +
> > > > +       pr_info("overflow out-of-bounds in memmove\n");
> > > > +       ptr =3D kmalloc(size, GFP_KERNEL);
> > > > +       if (!ptr) {
> > > > +               pr_err("Allocation failed\n");
> > > > +               return;
> > > > +       }
> > > > +
> > > > +       memset((char *)ptr, 0, 64);
> > > > +       memmove((char *)ptr + size, (char *)ptr, 2);
> > > > +       kfree(ptr);
> > > > +}
> > > > +
> > > >  static noinline void __init kmalloc_uaf(void)
> > > >  {
> > > >         char *ptr;
> > > > @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
> > > >         kmalloc_oob_memset_4();
> > > >         kmalloc_oob_memset_8();
> > > >         kmalloc_oob_memset_16();
> > > > +       kmalloc_oob_in_memmove_underflow();
> > > > +       kmalloc_oob_in_memmove_overflow();
> > > >         kmalloc_uaf();
> > > >         kmalloc_uaf_memset();
> > > >         kmalloc_uaf2();
> > > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > > index 616f9dd82d12..34ca23d59e67 100644
> > > > --- a/mm/kasan/generic.c
> > > > +++ b/mm/kasan/generic.c
> > > > @@ -131,9 +131,13 @@ static __always_inline bool memory_is_poisoned=
_n(unsigned long addr,
> > > >                                                 size_t size)
> > > >  {
> > > >         unsigned long ret;
> > > > +       void *shadow_start =3D kasan_mem_to_shadow((void *)addr);
> > > > +       void *shadow_end =3D kasan_mem_to_shadow((void *)addr + siz=
e - 1) + 1;
> > > >
> > > > -       ret =3D memory_is_nonzero(kasan_mem_to_shadow((void *)addr)=
,
> > > > -                       kasan_mem_to_shadow((void *)addr + size - 1=
) + 1);
> > > > +       if ((long)size < 0)
> > > > +               shadow_end =3D kasan_mem_to_shadow((void *)addr + s=
ize);
> > >
> > > Hi Walter,
> > >
> > > Thanks for working on this.
> > >
> > > If size<0, does it make sense to continue at all? We will still check
> > > 1PB of shadow memory? What happens when we pass such huge range to
> > > memory_is_nonzero?
> > > Perhaps it's better to produce an error and bail out immediately if s=
ize<0?
> >
> > I agree with what you said. when size<0, it is indeed an unreasonable
> > behavior, it should be blocked from continuing to do.
> >
> >
> > > Also, what's the failure mode of the tests? Didn't they badly corrupt
> > > memory? We tried to keep tests such that they produce the KASAN
> > > reports, but don't badly corrupt memory b/c/ we need to run all of
> > > them.
> >
> > Maybe we should first produce KASAN reports and then go to execute
> > memmove() or do nothing? It looks like it=E2=80=99s doing the following=
.or?
> >
> > void *memmove(void *dest, const void *src, size_t len)
> >  {
> > +       if (long(len) <=3D 0)
>=20
> /\/\/\/\/\/\
>=20
> This check needs to be inside of check_memory_region, otherwise we
> will have similar problems in all other places that use
> check_memory_region.
Thanks for your reminder.

 bool check_memory_region(unsigned long addr, size_t size, bool write,
                                unsigned long ret_ip)
 {
+       if (long(size) < 0) {
+               kasan_report_invalid_size(src, dest, len, _RET_IP_);
+               return false;
+       }
+
        return check_memory_region_inline(addr, size, write, ret_ip);
 }

> But check_memory_region already returns a bool, so we could check that
> bool and return early.

When size<0, we should only show one KASAN report, and should we only
limit to return when size<0 is true? If yse, then __memmove() will do
nothing.


 void *memmove(void *dest, const void *src, size_t len)
 {
-       check_memory_region((unsigned long)src, len, false, _RET_IP_);
+       if(!check_memory_region((unsigned long)src, len, false,
_RET_IP_)
+               && long(size) < 0)
+               return;
+
        check_memory_region((unsigned long)dest, len, true, _RET_IP_);

        return __memmove(dest, src, len);

>=20
>=20
> > +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> > +
> >         check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >
> >


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1569818173.17361.19.camel%40mtksdccf07.
