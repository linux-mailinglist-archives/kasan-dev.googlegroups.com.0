Return-Path: <kasan-dev+bncBCMIZB7QWENRB5OS5PWAKGQEEN3BGQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FDE7CDC5A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 09:29:59 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id a2sf10376938pfo.12
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 00:29:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570433398; cv=pass;
        d=google.com; s=arc-20160816;
        b=etosmHB3e6TRygM4M2YfYRDHjEZxU0+SSFnBuCjYzKc+1nvHr4iEmAuZKtTtqHsXsb
         bgJK3XCqhxgs6hQE3iHMKHxjvDMSgm8T2RHFljWYZaxbTHWq3x1oyOlBpmb9obdQLtYU
         GwmiebPWWrl6tZY7zVqAV5yFFmqwiqfVd4PB400mbMbKGA3203JfD7FqgQ6iOsNKE2Ce
         Gz8J5Q14ZUYvO6FMVcThVJhrQ/hwBGGfdoM2Yw7Nlt5Od4yYUemXHJPdt8cSWs4mgPCy
         csu5MYeRfjOlOF94hG+iXV9gVXYcZRbHceYwXtFTEE5YektxQ3Swao7tP9jSq62POPyW
         UB6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fKybbZy1Xvr6jdea4cG2S9mcFqka0J+Hu5woizeEG7s=;
        b=G6JBtlDyJ1MFwYSUfjcHzyO2d76Adtzb9g/MxVAFN87D4irKdNoxU13k9qgmqhIR0i
         BIeu+oRsxxwoQD48FvlGRN9esdUUGMj1NbGIqMqB1rUz8qKmordMC5HsKHyO+Va1n+Xk
         UfSECR4X4XjmSFxpJ36jb/Rdf9T0qJKpxDBoz6QH2vis/1ocMx3RtqTFZahlKkYULN0t
         cYGu1bN0g1eiBsnqi7C55FkBppH5Mvt/X5Us/uRSWbDwwdjVCsmKAy98fY3Gi42/x4RH
         JlXBq2e9P8/YyHnTRynNHsJuHcAYp8tl8yOouYWIkm1xcAvOSX94W+BVUR7a2bWdqnHX
         EH8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VlTtBxnD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fKybbZy1Xvr6jdea4cG2S9mcFqka0J+Hu5woizeEG7s=;
        b=h2bCsylK65yfQdSwtU/grtmnD+PUUDc15XjFE8rIOlc6QwtUiWN2jetj5q+WFao93N
         IovwOs+bPRFVo9pw198IiKelwzCl0W7jFKPI/aRrBaHadOEOaq7lFjuQiudg0PTyT5Vl
         B2aR/tkIoCkDHqZH43JvDbh9kSFSQevXRGKyulV9u7rSSo558zMvZvyWAokoNKuKdzKB
         TNc1Mlyv2gQa+pNdCx2uHUiCUbTvqOsYtxuHbSc2J/njr066HcA42I34ds1lzME7mW2r
         c9YPo3OPht6BRub0nfoaKf9n1aMCKgLdns5H2uRJWSfU1vLPcERNxukMVIoiyBKIX0Lz
         uDXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fKybbZy1Xvr6jdea4cG2S9mcFqka0J+Hu5woizeEG7s=;
        b=V1uqK5/vEX/AEMU3ixPUDP4vOzelBW4tBL6HOTAp1z2jq/QK67l+zH1bDjO+oG46f0
         F+iGJc+5+KCDH1F+rxto+5fcNDU/pO1S84l5aWfXE1/h/HixNZ9kXRPUqcT8Pdl8St54
         /y5+e3n1aZg8bGE0C49MA5onaBbL/z1Y2iSrNoGeUL1pOdU6ytCbNXy6Ws6Kl1caDbef
         F1CjkTCci0E9K0FO+9/6GqgoNqS0O/FrSdHPUMKoOmlVpohd7Doipoys/QKNlc/vlmkV
         Ng6PBj2/95GYBosA9AN9wMHa4e06gF0PUdmS81ZrrPmAQOu1DSI3R+WsS57GcRjIYNjB
         G0zQ==
X-Gm-Message-State: APjAAAVyof5WFLrPQZOAKKpmpHARR0oMQ2fiPpx5IPBqGwvV7SmFm1QQ
	VeBs/m+i48A2U0EfPBNmz/c=
X-Google-Smtp-Source: APXvYqychcXBJ/sQAA2CP/1iAQA7Hcv4gwy/3fNN5puCau4VhIhBhFhbueC75d/JtgMLoU9ObuhxaA==
X-Received: by 2002:a65:5544:: with SMTP id t4mr29869332pgr.119.1570433398070;
        Mon, 07 Oct 2019 00:29:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:35e6:: with SMTP id r93ls2906800pjb.2.gmail; Mon, 07
 Oct 2019 00:29:57 -0700 (PDT)
X-Received: by 2002:a17:90a:380a:: with SMTP id w10mr32358864pjb.104.1570433397640;
        Mon, 07 Oct 2019 00:29:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570433397; cv=none;
        d=google.com; s=arc-20160816;
        b=SEEti3Bl8+NNN187No1//US4osGz4kCipGZo1tzC6h5m8hvKlraeU90REVLKZ6xWVD
         pE7s4Wv5fv581vaFH0GGtGqia/BcwYHeIX5DpWRPbTcm6SpOYtLTC/b8jtAmxIa0Nl17
         nSyPPaopp4vEMGSX1nrlREdFawyHV9ioebRFfbbgiRv6oL6G9KqNlcis1nsSeY618E+v
         cwYVrVEJ/YYjIgKOTKqIJyH1QWN8Ka602e3Z5sX/5VGD4G5i0oEs/k1rdvdTxG012cKF
         y2+sqOHwr0VCOMDVkkVi+RHPtuL1NkMS4VrBqbwI50+xg9hBAP9tK0kYqXMDFwuOW3Xl
         KscA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5/whrwnXmuipWLBmQ5DFzrwToiDCS8kW6Zb6tPW0PAM=;
        b=sXZTwXp5UJIyCil3tD66QlAkW5ADvCGldYDvyi4cRfsR/sx6oxGDKiFa1kSJ3rJs+n
         PFILbzfyAQ83k+WD5ZTv17WiH1LKQlXDFqAimVSBdREbRTLl5cwoTZkRMXkZHrcrZ2OT
         Kg53taZtwiQ7jvYqtbboyrNmUij2l4vpCt571KbehFpqQqxbsJ21/GCggY2w8oPJBS93
         MaddObhwuc/seTQ7PWPPHVhAxpE/VthCRbKJfbyrmV35+PCFkzBDpunHFirXxPOfLDl/
         D77JQbQ6MNHq5l+0dVTnle19fiqWmCNPuJ/v2bJboXTRMCb1wRopIrP8lo+petXpqtrh
         Mjkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VlTtBxnD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id b1si830781pjw.1.2019.10.07.00.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 00:29:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id u186so11683836qkc.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 00:29:57 -0700 (PDT)
X-Received: by 2002:a37:985:: with SMTP id 127mr21743116qkj.43.1570433396036;
 Mon, 07 Oct 2019 00:29:56 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07> <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07> <1570018513.19702.36.camel@mtksdccf07>
 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
 <1570069078.19702.57.camel@mtksdccf07> <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
 <1570095525.19702.59.camel@mtksdccf07> <1570110681.19702.64.camel@mtksdccf07>
 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
 <1570164140.19702.97.camel@mtksdccf07> <1570176131.19702.105.camel@mtksdccf07>
 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
 <1570182257.19702.109.camel@mtksdccf07> <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
 <1570190718.19702.125.camel@mtksdccf07> <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
 <1570418576.4686.30.camel@mtksdccf07>
In-Reply-To: <1570418576.4686.30.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 09:29:44 +0200
Message-ID: <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VlTtBxnD;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Oct 7, 2019 at 5:23 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> > > > > > "out-of-bounds" has downsides of both approaches and won't prevent
> > > > > > duplicate reports by syzbot...
> > > > > >
> > > > > maybe i should add your comment into the comment in get_bug_type?
> > > >
> > > > Yes, that's exactly what I meant above:
> > > >
> > > > "I would change get_bug_type() to return "slab-out-of-bounds" (as the
> > > > most common OOB) in such case (with a comment)."
> > > >
> > > >  ;)
> > >
> > >
> > > The patchset help to produce KASAN report when size is negative size in
> > > memory operation function. It is helpful for programmer to solve the
> > > undefined behavior issue. Patch 1 based on Dmitry's suggestion and
> > > review, patch 2 is a test in order to verify the patch 1.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > >
> > > Walter Wu (2):
> > > kasan: detect invalid size in memory operation function
> > > kasan: add test for invalid size in memmove
> > >
> > > lib/test_kasan.c          | 18 ++++++++++++++++++
> > > mm/kasan/common.c         | 13 ++++++++-----
> > > mm/kasan/generic.c        |  5 +++++
> > > mm/kasan/generic_report.c | 10 ++++++++++
> > > mm/kasan/tags.c           |  5 +++++
> > > mm/kasan/tags_report.c    | 10 ++++++++++
> > > 6 files changed, 56 insertions(+), 5 deletions(-)
> > >
> > >
> > >
> > >
> > > commit 0bc50c759a425fa0aafb7ef623aa1598b3542c67
> > > Author: Walter Wu <walter-zh.wu@mediatek.com>
> > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > >
> > >     kasan: detect invalid size in memory operation function
> > >
> > >     It is an undefined behavior to pass a negative value to
> > > memset()/memcpy()/memmove()
> > >     , so need to be detected by KASAN.
> > >
> > >     If size is negative value, then it will be larger than ULONG_MAX/2,
> > >     so that we will qualify as out-of-bounds issue.
> > >
> > >     KASAN report:
> > >
> > >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> > >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > > cat/72
> > >
> > >      CPU: 2 PID: 72 Comm: cat Not tainted
> > > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> > >      Hardware name: linux,dummy-virt (DT)
> > >      Call trace:
> > >       dump_backtrace+0x0/0x288
> > >       show_stack+0x14/0x20
> > >       dump_stack+0x10c/0x164
> > >       print_address_description.isra.9+0x68/0x378
> > >       __kasan_report+0x164/0x1a0
> > >       kasan_report+0xc/0x18
> > >       check_memory_region+0x174/0x1d0
> > >       memmove+0x34/0x88
> > >       kmalloc_memmove_invalid_size+0x70/0xa0
> > >
> > >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > >
> > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> > >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > >
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 6814d6d6a023..6ef0abd27f06 100644
> > > --- a/mm/kasan/common.c
> > > +++ b/mm/kasan/common.c
> > > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> > >  #undef memset
> > >  void *memset(void *addr, int c, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > > +               return NULL;
> > >
> > >         return __memset(addr, c, len);
> > >  }
> > > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> > >  #undef memmove
> > >  void *memmove(void *dest, const void *src, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > +               return NULL;
> > >
> > >         return __memmove(dest, src, len);
> > >  }
> > > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > > len)
> > >  #undef memcpy
> > >  void *memcpy(void *dest, const void *src, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > > +               return NULL;
> > >
> > >         return __memcpy(dest, src, len);
> > >  }
> > > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > > index 616f9dd82d12..02148a317d27 100644
> > > --- a/mm/kasan/generic.c
> > > +++ b/mm/kasan/generic.c
> > > @@ -173,6 +173,11 @@ static __always_inline bool
> > > check_memory_region_inline(unsigned long addr,
> > >         if (unlikely(size == 0))
> > >                 return true;
> > >
> > > +       if (unlikely((long)size < 0)) {
> > > +               kasan_report(addr, size, write, ret_ip);
> > > +               return false;
> > > +       }
> > > +
> > >         if (unlikely((void *)addr <
> > >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> > >                 kasan_report(addr, size, write, ret_ip);
> > > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > > index 36c645939bc9..23951a453681 100644
> > > --- a/mm/kasan/generic_report.c
> > > +++ b/mm/kasan/generic_report.c
> > > @@ -107,6 +107,16 @@ static const char *get_wild_bug_type(struct
> > > kasan_access_info *info)
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> > > +        * out-of-bounds has downsides of both approaches and won't prevent
> > > +        * duplicate reports by syzbot.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> > > +
> > >         if (addr_has_shadow(info->access_addr))
> > >                 return get_shadow_bug_type(info);
> > >         return get_wild_bug_type(info);
> > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > index 0e987c9ca052..b829535a3ad7 100644
> > > --- a/mm/kasan/tags.c
> > > +++ b/mm/kasan/tags.c
> > > @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
> > > size, bool write,
> > >         if (unlikely(size == 0))
> > >                 return true;
> > >
> > > +       if (unlikely((long)size < 0)) {
> > > +               kasan_report(addr, size, write, ret_ip);
> > > +               return false;
> > > +       }
> > > +
> > >         tag = get_tag((const void *)addr);
> > >
> > >         /*
> > > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > > index 969ae08f59d7..19b9e364b397 100644
> > > --- a/mm/kasan/tags_report.c
> > > +++ b/mm/kasan/tags_report.c
> > > @@ -36,6 +36,16 @@
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> > > +        * out-of-bounds has downsides of both approaches and won't prevent
> > > +        * duplicate reports by syzbot.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> >
> >
> > wait, no :)
> > I meant we change it to heap-out-of-bounds and explain why we are
> > saying this is a heap-out-of-bounds.
> > The current comment effectively says we are doing non useful thing for
> > no reason, it does not eliminate any of my questions as a reader of
> > this code :)
> >
> Ok, the current comment may not enough to be understood why we use OOB
> to represent size<0 bug. We can modify it as below :)
>
> If access_size < 0, then it has two reasons to be defined as
> out-of-bounds.
> 1) Casting negative numbers to size_t would indeed turn up as a "large"
> size_t and its value will be larger than ULONG_MAX/2, so that this can
> qualify as out-of-bounds.
> 2) Don't generate new bug type in order to prevent duplicate reports by
> some systems, e.g. syzbot."

Looks good to me. I think it should provide enough hooks for future
readers to understand why we do this.

> > > +
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >         struct kasan_alloc_meta *alloc_meta;
> > >         struct kmem_cache *cache;
> > >
> > >
> > >
> > > commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> > > Author: Walter Wu <walter-zh.wu@mediatek.com>
> > > Date:   Fri Oct 4 18:32:03 2019 +0800
> > >
> > >     kasan: add test for invalid size in memmove
> > >
> > >     Test size is negative vaule in memmove in order to verify
> > >     if it correctly produce KASAN report.
> > >
> > >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index 49cc4d570a40..06942cf585cc 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -283,6 +283,23 @@ static noinline void __init
> > > kmalloc_oob_in_memset(void)
> > >         kfree(ptr);
> > >  }
> > >
> > > +static noinline void __init kmalloc_memmove_invalid_size(void)
> > > +{
> > > +       char *ptr;
> > > +       size_t size = 64;
> > > +
> > > +       pr_info("invalid size in memmove\n");
> > > +       ptr = kmalloc(size, GFP_KERNEL);
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
> > >  static noinline void __init kmalloc_uaf(void)
> > >  {
> > >         char *ptr;
> > > @@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
> > >         kmalloc_oob_memset_4();
> > >         kmalloc_oob_memset_8();
> > >         kmalloc_oob_memset_16();
> > > +       kmalloc_memmove_invalid_size();
> > >         kmalloc_uaf();
> > >         kmalloc_uaf_memset();
> > >         kmalloc_uaf2();
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baho7BEvQstd2%2Ba2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ%40mail.gmail.com.
