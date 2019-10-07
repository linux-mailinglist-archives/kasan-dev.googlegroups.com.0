Return-Path: <kasan-dev+bncBAABBNHZ5PWAKGQELGB7VJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A6DBCDDB8
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 10:52:05 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id o32sf9596313pgm.18
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 01:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570438324; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ii2Fo+ndxDz1csismIJ1OQo10GIeynB7yZyK4kIS6wIYaYlh2yQ+DK7jJ8ol86jLYe
         z0f1xhDTHJyzhpSQQPA1EcEOelLgq5SjecZwkE/BA98ue9vR2SXC/cJon7ZEXmsEpKBw
         PZZMHiKvyX5UP/3DkvDQOe5SX6SW0EAK1jpl0YQXEyg6FJ5jxBmaM/IjQwknzaskVLAK
         XB6HjkhbsaSh2Mmy+Ocf7u3Qe/r8YQsjy4bUDdK14FZfejmT1hLpDI29tQ9SYDcdYnSN
         4342zevaaeTsDradpqGsLGTbRNtzya8vzA2UyKRm9YSTwsfXgu7INDH3+Con9XCkTNQu
         YjSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=uGaqxSC613a2xJyZIU9nP+9QkkmHJcbJWzL8UQ23T+Y=;
        b=MdDjUtp5oIyy0oIxFza5HZ6vVI5zJ0ITWrpGq1ylp6ukc2MJdK+dfkxRF6OqrOelIS
         gZ+UvzHN9Wfb6TuJdOOlBW6TIXPfFOKRpsxxb1O+JTV7iCr1nDM2cO1lsoZqmWGnMVul
         u3mjjUFhP+971UBi7Y0RCHk5Fkcw765r1q2dOVM54P0yGKhPSaLxtDGHQBoxXuFNoKFx
         0p+PzTCB6qbHaRApkw+3HS3GMu9IXrEoBgF9tjqFLguV3r9+qOqICwEKENtuVfQthmnH
         0cPGiZbIFsp0qgyCQ99IS2ZkcGg9yyC+W9fCAkb3AiQVuHsBZ2sBCUmcvEM157A87yQ7
         XiJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uGaqxSC613a2xJyZIU9nP+9QkkmHJcbJWzL8UQ23T+Y=;
        b=NzGTkM87BhkLb5H1ZcLaLvqoiamXCw28//6UxeMwzrsPppHkZBDrUMkrty2xMWD3m3
         2k2HkDgcJ1iI7K0ZlZk7ngjlgBCbJn4GsfgzVJRWD+XILI/an3fCwmQcIAHRM3fyaAzx
         U47Q137lBRhCSDtubu4rKW1FnmAfSCz4iUWgqDDYuMb1ay7/ejdU1453uNan6IZpBPfJ
         eMFVrZBjBulUaWyfz1TVLZMn1axKQWT1mxxi1M5Vv042IxCpM3aCTvMZENK+c8tq0OuP
         JbZwfX4hXHMZzjVSIzvs7Y21jBU2i6PXdRPQ8/C2wg6ykTsVNgRuj+60kDodNctYVK+v
         VNCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uGaqxSC613a2xJyZIU9nP+9QkkmHJcbJWzL8UQ23T+Y=;
        b=qICSHMKkb8nVJL4GJ4n5k+rvDgQHfaWSCs++Uoqp1rb1TnsCvgxtbRYi2W3oL3nBxe
         Yb8/sMDTnKkwo6C+ed5JKrzuypI+b3xFpfEFBkKGrg700j7DAH4BAFApMNlzu+zMMP3M
         x7nC0bP4RxrjuJl2zmU4cTynttHsB+Ub/X8b90P+HnGWknUFzUARpXEfNw9JWnZ/93+X
         NarUl1go8uCmrIEL+LgA2DLrljgVP0ZChVSIm2SxlzWIWQuT3dlm+kwKKBBBPwuGipw3
         M7HsNxWnh62yFWHl/12M+2AuEcsXvHph4J0xSTa4/zMjmRZUgQ4tUnW1ghBZldAsKiLA
         n9tQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWRV65OaxhpKY9FjqbDAxcTu67sJhqOgzhjLu7p+0lMCkpQW7LY
	qomS41yDsbxiwI7Lvaz7hlQ=
X-Google-Smtp-Source: APXvYqzTGAFZATb9TmT321d7DVmQl8CqK0TXqAKPghG1LeoeDyA17/Ywv1jlYGdwTtrcyeWBlsvRBQ==
X-Received: by 2002:a63:5820:: with SMTP id m32mr11161110pgb.49.1570438324160;
        Mon, 07 Oct 2019 01:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6947:: with SMTP id e68ls2300109pgc.6.gmail; Mon, 07 Oct
 2019 01:52:03 -0700 (PDT)
X-Received: by 2002:a62:7d54:: with SMTP id y81mr31722298pfc.86.1570438323710;
        Mon, 07 Oct 2019 01:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570438323; cv=none;
        d=google.com; s=arc-20160816;
        b=0Lh4pNxDYjiNUGfA9nq7dGrHEgHwToMbojedIe0zswQFXuHqRualljfymGxs/LOh1J
         IfzoAsP4+QGM8XxVcTlH03FRhzLE2tLJxbjAkxOp3JKPRQ17nwctVH2qy232Eoq797tW
         jsuWsBB+jit4wnVbmEkuj91S2EtEKKl0Fc9lKkVFr298HO8IWgVigIuEZr5vhDrodJtp
         J0fhsH/PB9Hn6v8MHaZVwUO4li5IXZvF0Y1qoPI7xTSXhwegNnc2tTmh7ir2QwOuRHSw
         Syx9DPked5MP6nFWwvut20aSbWtuZ7fwL4P/brMuz4F6ZAmPFCSHlQKshRRFZbLWmsga
         7fYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=7xFyB1td6aszrvIDi3SygSnK4z8NYGOeqgk8Mu+POBk=;
        b=kgGjcxVoseP/CLjFWy5L7DeQLPELy/b1/qymiJe4yaeZd3GhdIXRfwFBbD1HOiSGxv
         21hCEOr8A7LmBRHTNcraONw5+Ih3bmdhgRv5UOfN0J9yHQDdKRZVDrBTCUCzWiK79f++
         TyK048qV9yoWJmTrySQEWogqbWIEoHVjmOhgt2l3edswT7X1kWe+SNgjlP06Ut7OpqEQ
         Arj7v2Pw6O+pNoTc3kh+cbOgTZbFhJYHZ3Wig6FECy5pxwAM6Ldx0NTw/cEaN08XODr7
         MluBmYBTtCU/dR6RmY3vCtikJ5v365Kw9aZzicQ2UdZGqTg87ZdprEGESlSJdvvg5hjp
         6z3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id o23si18284pjt.2.2019.10.07.01.52.03
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2019 01:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 6eaafef2995a4a6aa98d7ddc6c762b60-20191007
X-UUID: 6eaafef2995a4a6aa98d7ddc6c762b60-20191007
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 684474058; Mon, 07 Oct 2019 16:51:59 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 7 Oct 2019 16:51:56 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 7 Oct 2019 16:51:56 +0800
Message-ID: <1570438317.4686.44.camel@mtksdccf07>
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
Date: Mon, 7 Oct 2019 16:51:57 +0800
In-Reply-To: <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
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
	 <1570418576.4686.30.camel@mtksdccf07>
	 <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
	 <1570436289.4686.40.camel@mtksdccf07>
	 <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
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

On Mon, 2019-10-07 at 10:24 +0200, Dmitry Vyukov wrote:
> On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > The patchsets help to produce KASAN report when size is negative numbers
> > in memory operation function. It is helpful for programmer to solve the
> > undefined behavior issue. Patch 1 based on Dmitry's review and
> > suggestion, patch 2 is a test in order to verify the patch 1.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> >
> > Walter Wu (2):
> > kasan: detect invalid size in memory operation function
> > kasan: add test for invalid size in memmove
> >
> >  lib/test_kasan.c          | 18 ++++++++++++++++++
> >  mm/kasan/common.c         | 13 ++++++++-----
> >  mm/kasan/generic.c        |  5 +++++
> >  mm/kasan/generic_report.c | 12 ++++++++++++
> >  mm/kasan/tags.c           |  5 +++++
> >  mm/kasan/tags_report.c    | 12 ++++++++++++
> >  6 files changed, 60 insertions(+), 5 deletions(-)
> >
> >
> >
> >
> > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Oct 4 18:38:31 2019 +0800
> >
> >     kasan: detect invalid size in memory operation function
> >
> >     It is an undefined behavior to pass a negative numbers to
> > memset()/memcpy()/memmove()
> >     , so need to be detected by KASAN.
> >
> >     If size is negative numbers, then it has two reasons to be defined
> > as out-of-bounds bug type.
> >     1) Casting negative numbers to size_t would indeed turn up as a
> > large
> >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > can
> >     qualify as out-of-bounds.
> >     2) Don't generate new bug type in order to prevent duplicate reports
> > by
> >     some systems, e.g. syzbot.
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
> > index 36c645939bc9..ed0eb94cb811 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > kasan_access_info *info)
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * If access_size is negative numbers, then it has two reasons
> > +        * to be defined as out-of-bounds bug type.
> > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        * 2) Don't generate new bug type in order to prevent duplicate
> > reports
> > +        * by some systems, e.g. syzbot.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> 
> "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> prevent duplicates. "heap-out-of-bounds" is the frequent one.


    /*
     * If access_size is negative numbers, then it has two reasons
     * to be defined as out-of-bounds bug type.
     * 1) Casting negative numbers to size_t would indeed turn up as
     * a  "large" size_t and its value will be larger than ULONG_MAX/2,
     *    so that this can qualify as out-of-bounds.
     * 2) Don't generate new bug type in order to prevent duplicate
reports
     *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
frequent KASAN bug type.
     *    It won't prevent duplicates. "heap-out-of-bounds" is the
frequent one.
     */

We directly add it into the comment.

> 
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
> > index 969ae08f59d7..012fbe3a793f 100644
> > --- a/mm/kasan/tags_report.c
> > +++ b/mm/kasan/tags_report.c
> > @@ -36,6 +36,18 @@
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * If access_size is negative numbers, then it has two reasons
> > +        * to be defined as out-of-bounds bug type.
> > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        * 2) Don't generate new bug type in order to prevent duplicate
> > reports
> > +        * by some systems, e.g. syzbot.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         struct kasan_alloc_meta *alloc_meta;
> >         struct kmem_cache *cache;
> >
> >
> >
> >
> >
> >
> >
> >
> > commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Oct 4 18:32:03 2019 +0800
> >
> >     kasan: add test for invalid size in memmove
> >
> >     Test size is negative vaule in memmove in order to verify
> >     if it correctly get KASAN report.
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
> >
> >
> >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570436289.4686.40.camel%40mtksdccf07.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570438317.4686.44.camel%40mtksdccf07.
