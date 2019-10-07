Return-Path: <kasan-dev+bncBAABBFO75LWAKGQEC7TEJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EAD1CDA9D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 05:23:03 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id q127sf9965675pfc.17
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Oct 2019 20:23:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570418582; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHBdpSVm6VOAl+3y/+4DON4FCV7l1k8CPHWvKz+cx6TAKjCIUq9/aHOhW6ar32ya9V
         oT4IkvZauhzlHYuE4n54yCP+0IgNaQig5AChnppCDCvdknwLYqM4o9Es4kgzRG2KS0/U
         +Avub7V80A3yj2yHyFApN3fqXzts90KkDM/1CLVfq5cswYDBu+x0RbjHtU6XutWZuziS
         8PfFLynQSiH3AEWMzClLDk4ey5WuUodcvJqXDSDsLl9u6dKrIz1vclixEbmSL7/rL3IW
         uiEdyflObJ+SFX7PE5dVZzz0UfZ63JQFB4n5ePw2rFmH0FWvxphCQ2DKMO2a0SYHSdAJ
         CTcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=o8bP1RWQ1UmVkLPPcrOiGSR94L+RqRU8HXzoux7j4MU=;
        b=k6EqBdqYAn3DlK3DtEfuKaPaPwYmC8dOSMZZMEvXn4IgVO7hDltAZiCH7it4Jb7RNj
         JV5fK/tA0iUjmGnlPmGRHkSa/HC+4e4epeiJf2DYDMQBchY9hD2xG5AN2Y/Qz3m9K5Fe
         I4SyjLZsME3qDsa0mPZMvqYx2500DEQJ43RqXwB0l2ck3mipiSntBZUYVHL2rE2t/zTB
         dset1+aBle9WpAjEomwWF+DpasnSMA3ZaUojaU151WDna65sviRHoMEK1mV2xV+0tYKR
         qlbfqrUD778cAnh7/G7bH5bG5DlhVYe40BrOpoeDZtZgMWWDzaNQsJ0uvEDOh0dwBfhs
         kYag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8bP1RWQ1UmVkLPPcrOiGSR94L+RqRU8HXzoux7j4MU=;
        b=E1Mmqj/e28jTD5I6g10oUbMwgDCP+q2t8Rx+mReOtT64IMitQlvRsUv/sWNAZlGTst
         sjqgSY0FtWorhkosUbqRZqLFU0yStbeaIGBFUNSw6PfwBYbu3TjYIsiUWQ8ANWn8I15W
         z57vIL4YWLvTSahMOawyRRJxrOSB2UzL9SN5pXq9jMX+x7Fg0Mpk4w6qur5cZp9bg//A
         rj1IboYJmQtVCkskR6xSkPWu/4VGXbQfUjZVt6xVgP+3vEJdUz1pYfGE4Thdh9LjDvWO
         7OxaXc8y/cEa7SI4yUh7wherHwDPEW+i0PkZqTr1ClIbgeW5VaPPci96dXX+alKNH6dg
         eLPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o8bP1RWQ1UmVkLPPcrOiGSR94L+RqRU8HXzoux7j4MU=;
        b=JGpZj84Cc9vGTD7up1TtK0cSwmK1lj5b1yuwLb31rLcQ+d3NmBWK+6lEJi0rdJgPLI
         6OBGUdltpX7sOcamz8sTU8NidUZ6XyZaR1UMXwnWwUVpPlFdbzYxbRd/9ybz2qdJLy1/
         uqDXDvIwFMH8xAjlyJpqK57BiYwEuTI+dzJxWvoCkIyGVFXMc3zcf3lmB8tXIZPfaIKh
         Sgbsejw8LtOlhzz1LIiRjzp7ajVgWBw+aHzczy4g4QtU4vCxBHLXfV+GVUF45/qJ6EkE
         eMoVdI3I6B0hny0d5xKlYgMvX4K0+lIErqowurzvNEdmuEOXrSpjrpPBeXPtmRXVKumv
         pFyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVt8FRFuDsUvz3JKXZfotfzrqFh0zCEsEatqjZK0usoNeKwSRRr
	9dEcNbebezW8X9PR11GRpKg=
X-Google-Smtp-Source: APXvYqzl/KZ2bGJd8+qSzxoC9pDyncacmLrJPVvXeGdHeSKkYZ/W/UqmVm3r1k4SzCVrZBs1UFd9Rg==
X-Received: by 2002:aa7:9494:: with SMTP id z20mr31068841pfk.112.1570418581787;
        Sun, 06 Oct 2019 20:23:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:24f:: with SMTP id t15ls2713000pje.1.canary-gmail;
 Sun, 06 Oct 2019 20:23:01 -0700 (PDT)
X-Received: by 2002:a17:902:2e:: with SMTP id 43mr27833469pla.268.1570418581542;
        Sun, 06 Oct 2019 20:23:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570418581; cv=none;
        d=google.com; s=arc-20160816;
        b=K4aoLioGIpQs7NH365Mnj8i7F390EC0T8SmLWCN60fcYDYoh1CgQoID4jfSSSmBEXM
         crWUZllzrKpgi5w6NYxaLBioYvzIyCXAnMyABtZyf6l1LCGvKxmURYRGzBwu6E3fBsmo
         rMDLqkMcM1tN59HqSiD0+xJXXcnEhOmhgq6HOlK642CJMWt17zc5hEexeeQY+958WNL1
         77Zp8Vbr3uHgsPjROeH1o5q90bSymydE81nDBlLwBt02adO3INy41Jdv198+8CCzH541
         TRj7FqXS0UlrMdcnHM72jfWt90jJNiC8jy72Hzc6xEvkwzAHFLU7QJc+MIIhDclf6GX1
         2OOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=vIf2IovS/4c8jXSBUnGMMP0P1hdH6afoW0yR14HC4kk=;
        b=lbQbebMOOXYJXh9xsfsUOYmBrYSAr8xQiS2K1fJThhcfVzy3TBHVGq9SfeX3EloSRi
         WrCL/sRtSlRlrdA3HSmyTo/c9EvcmhrJ1jxyFybFDV1QuRMiNjph3JjxVqTlz2+9NJJ5
         GW5GmcObOkunWJP2Hj+biY01WvKEbA7P87pueei6dzhquEFz+UJD7LgNlKCtrhTLYghd
         jv2Bnu1tH1XbqKOi+rUv/Xz3XGQWeJ2XiPC2bP3Zri+siaq+gdFRbc8sFqUhck9xG2kH
         lewVngDYgU+yoiQpxA+mPC83isA7oV1VG+gdXXmUpOVDnaSx1H7LVj+GpVf6zgbIPNhV
         g0KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id p9si501821pjo.0.2019.10.06.20.23.01
        for <kasan-dev@googlegroups.com>;
        Sun, 06 Oct 2019 20:23:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: db22c50fed0049b8908838c70e04a5d9-20191007
X-UUID: db22c50fed0049b8908838c70e04a5d9-20191007
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 488879034; Mon, 07 Oct 2019 11:22:57 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 7 Oct 2019 11:22:49 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 7 Oct 2019 11:22:55 +0800
Message-ID: <1570418576.4686.30.camel@mtksdccf07>
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
Date: Mon, 7 Oct 2019 11:22:56 +0800
In-Reply-To: <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
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
	 <1570110681.19702.64.camel@mtksdccf07>
	 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
	 <1570164140.19702.97.camel@mtksdccf07>
	 <1570176131.19702.105.camel@mtksdccf07>
	 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
	 <1570182257.19702.109.camel@mtksdccf07>
	 <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
	 <1570190718.19702.125.camel@mtksdccf07>
	 <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
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

On Fri, 2019-10-04 at 15:52 +0200, Dmitry Vyukov wrote:
> On Fri, Oct 4, 2019 at 2:05 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Fri, 2019-10-04 at 11:54 +0200, Dmitry Vyukov wrote:
> > > > > "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> > > > > "out-of-bounds" has downsides of both approaches and won't prevent
> > > > > duplicate reports by syzbot...
> > > > >
> > > > maybe i should add your comment into the comment in get_bug_type?
> > >
> > > Yes, that's exactly what I meant above:
> > >
> > > "I would change get_bug_type() to return "slab-out-of-bounds" (as the
> > > most common OOB) in such case (with a comment)."
> > >
> > >  ;)
> >
> >
> > The patchset help to produce KASAN report when size is negative size in
> > memory operation function. It is helpful for programmer to solve the
> > undefined behavior issue. Patch 1 based on Dmitry's suggestion and
> > review, patch 2 is a test in order to verify the patch 1.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> >
> > Walter Wu (2):
> > kasan: detect invalid size in memory operation function
> > kasan: add test for invalid size in memmove
> >
> > lib/test_kasan.c          | 18 ++++++++++++++++++
> > mm/kasan/common.c         | 13 ++++++++-----
> > mm/kasan/generic.c        |  5 +++++
> > mm/kasan/generic_report.c | 10 ++++++++++
> > mm/kasan/tags.c           |  5 +++++
> > mm/kasan/tags_report.c    | 10 ++++++++++
> > 6 files changed, 56 insertions(+), 5 deletions(-)
> >
> >
> >
> >
> > commit 0bc50c759a425fa0aafb7ef623aa1598b3542c67
> > Author: Walter Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Oct 4 18:38:31 2019 +0800
> >
> >     kasan: detect invalid size in memory operation function
> >
> >     It is an undefined behavior to pass a negative value to
> > memset()/memcpy()/memmove()
> >     , so need to be detected by KASAN.
> >
> >     If size is negative value, then it will be larger than ULONG_MAX/2,
> >     so that we will qualify as out-of-bounds issue.
> >
> >     KASAN report:
> >
> >      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
> >      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> > cat/72
> >
> >      CPU: 2 PID: 72 Comm: cat Not tainted
> > 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
> >      Hardware name: linux,dummy-virt (DT)
> >      Call trace:
> >       dump_backtrace+0x0/0x288
> >       show_stack+0x14/0x20
> >       dump_stack+0x10c/0x164
> >       print_address_description.isra.9+0x68/0x378
> >       __kasan_report+0x164/0x1a0
> >       kasan_report+0xc/0x18
> >       check_memory_region+0x174/0x1d0
> >       memmove+0x34/0x88
> >       kmalloc_memmove_invalid_size+0x70/0xa0
> >
> >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> >
> >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> >     Reported -by: Dmitry Vyukov <dvyukov@google.com>
> >     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..6ef0abd27f06 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +               return NULL;
> >
> >         return __memset(addr, c, len);
> >  }
> > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +               return NULL;
> >
> >         return __memmove(dest, src, len);
> >  }
> > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> > len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +               return NULL;
> >
> >         return __memcpy(dest, src, len);
> >  }
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 616f9dd82d12..02148a317d27 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -173,6 +173,11 @@ static __always_inline bool
> > check_memory_region_inline(unsigned long addr,
> >         if (unlikely(size == 0))
> >                 return true;
> >
> > +       if (unlikely((long)size < 0)) {
> > +               kasan_report(addr, size, write, ret_ip);
> > +               return false;
> > +       }
> > +
> >         if (unlikely((void *)addr <
> >                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
> >                 kasan_report(addr, size, write, ret_ip);
> > diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> > index 36c645939bc9..23951a453681 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -107,6 +107,16 @@ static const char *get_wild_bug_type(struct
> > kasan_access_info *info)
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> > +        * out-of-bounds has downsides of both approaches and won't prevent
> > +        * duplicate reports by syzbot.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> > +
> >         if (addr_has_shadow(info->access_addr))
> >                 return get_shadow_bug_type(info);
> >         return get_wild_bug_type(info);
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 0e987c9ca052..b829535a3ad7 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
> > size, bool write,
> >         if (unlikely(size == 0))
> >                 return true;
> >
> > +       if (unlikely((long)size < 0)) {
> > +               kasan_report(addr, size, write, ret_ip);
> > +               return false;
> > +       }
> > +
> >         tag = get_tag((const void *)addr);
> >
> >         /*
> > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > index 969ae08f59d7..19b9e364b397 100644
> > --- a/mm/kasan/tags_report.c
> > +++ b/mm/kasan/tags_report.c
> > @@ -36,6 +36,16 @@
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> > +        * out-of-bounds has downsides of both approaches and won't prevent
> > +        * duplicate reports by syzbot.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> 
> 
> wait, no :)
> I meant we change it to heap-out-of-bounds and explain why we are
> saying this is a heap-out-of-bounds.
> The current comment effectively says we are doing non useful thing for
> no reason, it does not eliminate any of my questions as a reader of
> this code :)
> 
Ok, the current comment may not enough to be understood why we use OOB
to represent size<0 bug. We can modify it as below :)

If access_size < 0, then it has two reasons to be defined as
out-of-bounds.
1) Casting negative numbers to size_t would indeed turn up as a "large"
size_t and its value will be larger than ULONG_MAX/2, so that this can
qualify as out-of-bounds.
2) Don't generate new bug type in order to prevent duplicate reports by
some systems, e.g. syzbot."

> 
> 
> 
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         struct kasan_alloc_meta *alloc_meta;
> >         struct kmem_cache *cache;
> >
> >
> >
> > commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> > Author: Walter Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Oct 4 18:32:03 2019 +0800
> >
> >     kasan: add test for invalid size in memmove
> >
> >     Test size is negative vaule in memmove in order to verify
> >     if it correctly produce KASAN report.
> >
> >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 49cc4d570a40..06942cf585cc 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -283,6 +283,23 @@ static noinline void __init
> > kmalloc_oob_in_memset(void)
> >         kfree(ptr);
> >  }
> >
> > +static noinline void __init kmalloc_memmove_invalid_size(void)
> > +{
> > +       char *ptr;
> > +       size_t size = 64;
> > +
> > +       pr_info("invalid size in memmove\n");
> > +       ptr = kmalloc(size, GFP_KERNEL);
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
> >  static noinline void __init kmalloc_uaf(void)
> >  {
> >         char *ptr;
> > @@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
> >         kmalloc_oob_memset_4();
> >         kmalloc_oob_memset_8();
> >         kmalloc_oob_memset_16();
> > +       kmalloc_memmove_invalid_size();
> >         kmalloc_uaf();
> >         kmalloc_uaf_memset();
> >         kmalloc_uaf2();


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570418576.4686.30.camel%40mtksdccf07.
