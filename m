Return-Path: <kasan-dev+bncBAABB6NI3TWAKGQE6YBTC6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id C59C4CB78A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 11:44:26 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id 59sf5919630qtc.5
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 02:44:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570182265; cv=pass;
        d=google.com; s=arc-20160816;
        b=puOHnIm05++NOMjIHvH8WK5jFl90Ueqr+uwJ8Dro0kQKfcemC5xwm0ZxjzOtOaiWom
         vlGRn2qLTtvicOL/jS0ocod5LcHrUxb33h7v62ZsqEhustyqNWTgXE/JUSQ5BKNzKZyb
         QEAI0gY6hnAKzscxrbCII1J+ULF7DUj72eolwRhi2nyczj9sbw6bzndvQBRqYFoW8qIv
         3CTeD9B2xPOH30+ECtroenUvGIbl+qhqjpkxIDv+XDTfNFNsBVFtHm1SOftCQFyyc5tG
         vKgD/GqRW3cI3W6GGIcs5u/etpRHqduju/l8XU3h8qUjznDb8FRVe5481+F5lJi5IDF/
         5CPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=UDhHLlGjoVl8k58KOP+6XXDhbiq+zZoP4yUkAttHN9Y=;
        b=qjIO0KGcP8Da+3YclRnnFf0rt3JJOHMq+1txHvflcPbG6HYNMSVJp+tWIvgT5OJZ53
         8BgLfoZEDLHpsNvAw9KLNyf33g7yyQwF9TxOZcI0rE/JOvoV/qJAyEbqFoqqK0F02Ggg
         p9GCJ+zUcJOs0G6TmnDskgRlTZ4n0Be5+ddvkDBFro21K64X+pxCCcLXE6FQ0IGhzSGV
         0q+JZxaBSmFXK00SpuaN+m1uGDykE8HmpWF9JWsi/120jiV9wcEyCa9+w2reraDfg7VB
         TrjxMVcdOamIleB+NOLNNuWc51CeQrHnulXIBZsUFsLtqFffkttHqDht6cheRF7mdI6N
         ybYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UDhHLlGjoVl8k58KOP+6XXDhbiq+zZoP4yUkAttHN9Y=;
        b=o/balf5SzBX+FFEe9ssx+oQXOTUcJKSTc64FKkrytwqUMFL22D2vTxu5Yk/IRFUHrA
         Zs/Ssn6Na/XFgykq8RStXTKk5766YpQWh48KwShK4ud072oGQeWP8p6qpMRcP9YR95QV
         xnjrUHZXRxnGctHDBVxF6DqlyeHlubR3knLQro5L9Vf3v1gfTmo6YJUw1epbLn+5xEKG
         ME9gpCKovdylznGfvFJE5YCCuG4CD2QfobQsahpi5sL2M+PrORpIikaoG8cO47BARano
         5f8/rbfZgBWRfPxgcwsC0G6+P0NWvJL+jwZ+lLHK5kdF5E9z8Kzk2CPKYa/j5an7MS9g
         +FMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UDhHLlGjoVl8k58KOP+6XXDhbiq+zZoP4yUkAttHN9Y=;
        b=ZS1YvC/QwZ5Y16pJC6UCet16hEEnqcX08wuW4Guh/aIxRoqmCq4u3VnE66LZsOp85f
         S3Y17NUzH2Vl/W6Ldbztqlzu5vkz8xjKEdTzCMAP3q4Z/rPYelVQDkvWQefPPtt3wlpc
         ovhjpoo6mH/EE3NCx2y5rv81XkuEJoILQpdwd+oFdrS3oglGIGRuf0hztARPzZ/tWtPx
         q7L7GfBOVYfqoze8kXPYKFplWHaN4RmGgPoMeu5tr+/idqTgUl7qX6OBSbmvq9MmZF/r
         6uZHHE14+pplj17IqqU/1M5RSYFFxqiJrc/aPJq97wwwCIwjelq8MZD+nsFdh1fIQ/yk
         TuWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWpt6SDjDrKT9ls7xGWs1ZbVLCvWNTiwxUPBGLZ+BvijdXWB27F
	S2n7lJ2qxdwAlMXZOgWCEXA=
X-Google-Smtp-Source: APXvYqxIizv1DpVx4vvhSTWJx3IczM8jU+WRKwHxhCyDyVI1CPVABGnokUSOAZqqsGa3hVaicJUZuw==
X-Received: by 2002:ae9:c219:: with SMTP id j25mr9029603qkg.277.1570182265371;
        Fri, 04 Oct 2019 02:44:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f992:: with SMTP id t18ls1513056qvn.14.gmail; Fri, 04
 Oct 2019 02:44:25 -0700 (PDT)
X-Received: by 2002:a0c:f689:: with SMTP id p9mr12918873qvn.215.1570182265080;
        Fri, 04 Oct 2019 02:44:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570182265; cv=none;
        d=google.com; s=arc-20160816;
        b=qjOCmNqSW8VlrZDCQTOZyOl8syXQHDEdLpeNaLhezrmZxsnT325QofTPEPxKhjTbTR
         NNWAmXuaj3/1Xdr6jXI2cfAMywxSCMJoglrBa8TZV92SbVQRIFx7cvG/5C0lYaMXUiTa
         nlyQo8hiS2RPisRSjyHk3rCEYN5LNHNzgH5BfENxmhaIvSWyJwVrM+Van/b3N6bQPhro
         QIwgSExY546qsX4BEw75CWJNGdkMhTKSnlTHV+ry1h9AaGH8Y3C3xQ14hY12h6g78uUx
         WniN23qznrU5jpUexRmL0YsqduW65XRU4b59rbYZBVpX5/V4xBHlG8j4MtOG1NDHWpui
         XSug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=UFIqxiglkJwHC1P49tC1xK/LdWqJpvO6OrjhY17wu6E=;
        b=RB7BB/BiB+J7SFub3NQ73PJ7Y//4+zhxeMA3cHEVUVdg0FpJcJG9D5A7/pweplEauN
         EfDD5NvUgyNNWlQyUNoGH86T4IjNhotfXPZXdspp9KkU9VVmzmMXYOwsuLEJdHFNCDVw
         gR+UX7F5th18Ve62dcorFUfNkoouSHC4hE6Zq+tKuR3q/JpE338BXzOcyo6NZdsbWzJA
         SJpn8dG57KcuB34Yx2lm6DpP+4gtdLbMswc6J22mFTiHfC2Bs+oUEL91izTEewWxUUFE
         v3oHlLOCF0RIHY4od7JB7uZyT5fi9Z2EaN2YXo/diyP34/oGSUx+wEWNzMbyAwAy499N
         pTIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l189si266627qke.6.2019.10.04.02.44.23
        for <kasan-dev@googlegroups.com>;
        Fri, 04 Oct 2019 02:44:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: f67b3a2d9d194aad9b6e4888dd33f68f-20191004
X-UUID: f67b3a2d9d194aad9b6e4888dd33f68f-20191004
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 753597374; Fri, 04 Oct 2019 17:44:18 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 4 Oct 2019 17:44:16 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 4 Oct 2019 17:44:15 +0800
Message-ID: <1570182257.19702.109.camel@mtksdccf07>
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
Date: Fri, 4 Oct 2019 17:44:17 +0800
In-Reply-To: <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
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

On Fri, 2019-10-04 at 11:18 +0200, Dmitry Vyukov wrote:
> On Fri, Oct 4, 2019 at 10:02 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Fri, 2019-10-04 at 12:42 +0800, Walter Wu wrote:
> > > On Thu, 2019-10-03 at 16:53 +0200, Dmitry Vyukov wrote:
> > > > On Thu, Oct 3, 2019 at 3:51 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:>
> > > > >
> > > > >  static void print_error_description(struct kasan_access_info *info)
> > > > >  {
> > > > > -       pr_err("BUG: KASAN: %s in %pS\n",
> > > > > -               get_bug_type(info), (void *)info->ip);
> > > > > -       pr_err("%s of size %zu at addr %px by task %s/%d\n",
> > > > > -               info->is_write ? "Write" : "Read", info->access_size,
> > > > > -               info->access_addr, current->comm, task_pid_nr(current));
> > > > > +       if ((long)info->access_size < 0) {
> > > > > +               pr_err("BUG: KASAN: invalid size %zu in %pS\n",
> > > > > +                       info->access_size, (void *)info->ip);
> > > >
> > > > I would not introduce a new bug type.
> > > > These are parsed and used by some systems, e.g. syzbot. If size is
> > > > user-controllable, then a new bug type for this will mean 2 bug
> > > > reports.
> > > > It also won't harm to print Read/Write, definitely the address, so no
> > > > reason to special case this out of a dozen of report formats.
> > > > This can qualify as out-of-bounds (definitely will cross some
> > > > bounds!), so I would change get_bug_type() to return
> > > > "slab-out-of-bounds" (as the most common OOB) in such case (with a
> > > > comment).
> > > >
> > > Print Read/Write and address information, it is ok.
> > > But if we can directly point to the root cause of this problem, why we
> > > not do it?  see 1) and 2) to get a point, if we print OOB, then user
> > > needs one minute to think what is root case of this problem, but if we
> > > print invalid size, then user can directly get root case. this is my
> > > original thinking.
> > > 1)Invalid size is true then OOB is true.
> > > 2)OOB is true then invalid size may be true or false.
> > >
> > > But I see you say some systems have used bug report so that avoid this
> > > trouble, i will print the wrong type is "out-of-bound" in a unified way
> > > when size<0.
> > >
> >
> > Updated my patch, please help to review it.
> > thanks.
> >
> > commit 13e10a7e4264eb25c5a14193068027afc9c261f6
> > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Oct 4 15:27:17 2019 +0800
> >
> >     kasan: detect negative size in memory operation function
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
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..97dd6eecc3e7 100644
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
> > @@ -110,7 +111,8 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> > +               return NULL;
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> 
> I would check both calls.
> The current code seems to be over-specialized for handling of invalid
> size (you assume that if it's invalid size, then the first
> check_memory_region will detect it and checking the second one is
> pointless, right?).
> But check_memory_region can return false in other cases too.
> Also seeing first call checked, but the second not checked just hurts
> my eyes when reading code (whenever I will read such code my first
> reaction will be "why?").
> 
I can't agree with you any more about second point.

#undef memmove
void *memmove(void *dest, const void *src, size_t len)
{
    if (!check_memory_region((unsigned long)src, len, false, _RET_IP_)
||)
        !check_memory_region((unsigned long)dest, len, true, _RET_IP_);
        return NULL;

    return __memmove(dest, src, len);
}

> 
> >
> >         return __memmove(dest, src, len);
> > @@ -119,7 +121,8 @@ void *memmove(void *dest, const void *src, size_t
> > len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> > +               return NULL;
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >         return __memcpy(dest, src, len);
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
> > index 36c645939bc9..ae9596210394 100644
> > --- a/mm/kasan/generic_report.c
> > +++ b/mm/kasan/generic_report.c
> > @@ -107,6 +107,13 @@ static const char *get_wild_bug_type(struct
> > kasan_access_info *info)
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> 
> "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> "out-of-bounds" has downsides of both approaches and won't prevent
> duplicate reports by syzbot...
> 
maybe i should add your comment into the comment in get_bug_type?

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
> > index 969ae08f59d7..1e1ca81214b5 100644
> > --- a/mm/kasan/tags_report.c
> > +++ b/mm/kasan/tags_report.c
> > @@ -36,6 +36,13 @@
> >
> >  const char *get_bug_type(struct kasan_access_info *info)
> >  {
> > +       /*
> > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > +        * so that this can qualify as out-of-bounds.
> > +        */
> > +       if ((long)info->access_size < 0)
> > +               return "out-of-bounds";
> > +
> >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> >         struct kasan_alloc_meta *alloc_meta;
> >         struct kmem_cache *cache;
> >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570176131.19702.105.camel%40mtksdccf07.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570182257.19702.109.camel%40mtksdccf07.
