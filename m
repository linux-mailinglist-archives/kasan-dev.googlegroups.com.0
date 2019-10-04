Return-Path: <kasan-dev+bncBAABBNE33PWAKGQEGI44JBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C3E4CB3F5
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 06:42:29 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id r39sf898735uad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 21:42:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570164148; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQ0qhHjqXihDbNd3rQflyLQFJ2QzLGhTe1aJpE6w5KuLhA8a8TwZVpae42d1CUYHrt
         HqqQyIOkzZBLGQsvoY57Bl3BI9bQM2Vd3HgVSV8YaQsXznGQ78i8np34ndDs7mdo0P8/
         AGE3yizUhX+UfueCC9Pq4IKbyPOdaSnU1gs46lKmP3xDMJC479VAY89B5XVmH+ZAO/kg
         zgAABR2+DodJivqqYXICBlEW44Suu9pBR21FkA2ew402ibEzlP8aYyWdIJsvW/XhyYh5
         3Cz+ReM94BRP8V0e9tgzexBYwGnFRFmsp+5Brj66Qrh8jzlyfizhxhhvPQxhN1t0VWPk
         Ajfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=C7OYTxeoshLUlnfmCx89QjuT37exd1u6TM4UckvEEA4=;
        b=Yqg24giilPzCCFViHy6n8KOQ+Yv4QJPn9nNHMBuhYHxA9TJtLhfxMDFBVdZx1kHZzI
         ObTn3hCIdSy6/IxvIEEBVjwPTpUDtE2QQwZdgY4yIPhmzYZC6ZnKQNQBjzNnJzctlmxu
         9iycrsdQXEtMt3+x0sI7LhFueKCEfISRtRjTWkX1op3q1zg7goCd5efYvIpkfBbw0tpF
         gTBylcKktfNxl0yy9Ma+UvbEEUyxl3RHAsVRfnBTwt6SiCS3rXyseIFzD5twLmkEdYdC
         GPK5LvQ5SccdljS7gWceUoW/kfNjoDWmJStMrLkD5hulgKRj6dywO2pmI0u2BuTbtjK9
         6b3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C7OYTxeoshLUlnfmCx89QjuT37exd1u6TM4UckvEEA4=;
        b=GG5uK08RcQNHi1Rn2B6/hvSNQ5m3GowUCizrcdwhc8VmNPYjoEn+fFl5uo7Aqwu2lM
         mCL6cUQR3908KbML9BW+YPfehc/PB5MXTohijy2CPQ3P0y2dO8gGlaTmll1fVVE/iZSJ
         E74n4NYDeRworSUq2aJt96DP859Oxb9aKt/WTsqd4rTxQCgwmuNMz512tO5W5afnhevL
         kI4SfF4+3YJ6lj9ZcXwarRnYNsgAVGh/HC1qaKVXx2/aSO8ieYy2liePRuba0MESnNn2
         BiUPmK71kRqc2pKnQS6o5f1iaWwS4uJoAGusBCyGZah//SPM7/REJEGiPt10htecqH2x
         75hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C7OYTxeoshLUlnfmCx89QjuT37exd1u6TM4UckvEEA4=;
        b=dU8hB4AMLRwZ9YgLA6V3KNJ8gqrckLft7D/dHDiabCqKadmvOv3V/JlSdYUP+Q0mHc
         7JU2L1KS3ZSBOYjEXzVFLAoEdhHHFvJK11+m+KBOvkIGsJlpRMZYRDhqfu1XEMBpTEZS
         6QDaTgatPjfVdFbMyxdgzVg8u3b4z1gdfVg8nT0fKfuIMHbEQH7nnmn898fbewwwrIgJ
         7joLIqY4q+KMsLXyHjd4Mp7VsPm2MIkSKQteLebsnzNu5h5zS2pIWIiIKSeldOjxNRFE
         vm2TwN06UIanNHXyyu4i+Z5EYlwBtgUhYLTdvX3AQdAyF6sDHhZwO3I5riz75cOGu4P3
         REaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWQwBuB8MEJuGCHGux/GT8NNPKTLPSXk/FQG7+pzJAR+VsMnY1v
	bCHJF2iCpC69XW7oor8qmS4=
X-Google-Smtp-Source: APXvYqyKw/vnFM9mpaa31DlZwY1NH/nAg7NkQlfGXaD2vyORHO8GjoNbGF/e8xfT+/pXyKWXnpclsA==
X-Received: by 2002:a67:ba10:: with SMTP id l16mr6833553vsn.106.1570164148364;
        Thu, 03 Oct 2019 21:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f916:: with SMTP id t22ls875609vsq.12.gmail; Thu, 03 Oct
 2019 21:42:28 -0700 (PDT)
X-Received: by 2002:a67:8d81:: with SMTP id p123mr7045117vsd.152.1570164148076;
        Thu, 03 Oct 2019 21:42:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570164148; cv=none;
        d=google.com; s=arc-20160816;
        b=p5G5ON/i7Dwl5qQzze8B71ogiAcYHUCLPCDvTyDq8QmgOC2E8Q+PFef6eLFmykLC60
         9N2DVVot+dWgROZwJJqpsxqNIufg8nwpZmlwEfgjiKBJhx3w5qxuUi3YlOKGPjuBFdmb
         L+qQ2U7tg4+oREENMkdc+xkyH0DxshN0pu9xEDFUOfOQrBFS/WHAJZcaff+zO/hXJ72M
         4rSdHQytpG7mwk/Mv3yUWgiO7an16HXXc3peFb62OV7OnBcFT/SCsxuyroI78y9B+BIn
         vjS27hJMtXYAXVWg5guMsCSNTg4Pft0wB0iAJYCnjHdxnYIZryBrSK2jm/FR3mlsDUhO
         3T3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=BjqiVIPha8vyJRABs7+PyPQbWGkuj66YlDVlYtkjCl4=;
        b=gmJhcUqp1vB1w4uT/YEeptjmSIdUIymretxhEgSm83eOn+neK+r+H0myOh0SwZ0q/u
         eNGONSdh+re7awr+1tNrgiYQb6xV8c2GOwLKXlO/mQMmy3EkyD4djW1sKtPJr8HAMLEg
         EWOWs+EVOMvujkOv48i85ofWiWLES6Cbe/mdSIKEscPIJ2+OxdXeKkRbdcHmN3vLlrGv
         bbVy0dQE9rg+iW2SecvGi/jlEsRY6ystgbRwMk8IAnBriQedn7tQj50Am6UsQCkRwffx
         9bD/pwDWvmSqlknXZ0queG/IAuCB5186TFJJCpXN0ALyd6EOvPlIUE/VsxaIF9v46ROY
         AqZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id p18si328377vsn.1.2019.10.03.21.42.26
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Oct 2019 21:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: a5b84de73c1b4932be65f10a106b7541-20191004
X-UUID: a5b84de73c1b4932be65f10a106b7541-20191004
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 935648087; Fri, 04 Oct 2019 12:42:22 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 4 Oct 2019 12:42:20 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 4 Oct 2019 12:42:20 +0800
Message-ID: <1570164140.19702.97.camel@mtksdccf07>
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
Date: Fri, 4 Oct 2019 12:42:20 +0800
In-Reply-To: <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
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

On Thu, 2019-10-03 at 16:53 +0200, Dmitry Vyukov wrote:
> On Thu, Oct 3, 2019 at 3:51 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:>
> > how about this?
> >
> > commit fd64691026e7ccb8d2946d0804b0621ac177df38
> > Author: Walter Wu <walter-zh.wu@mediatek.com>
> > Date:   Fri Sep 27 09:54:18 2019 +0800
> >
> >     kasan: detect invalid size in memory operation function
> >
> >     It is an undefined behavior to pass a negative value to
> > memset()/memcpy()/memmove()
> >     , so need to be detected by KASAN.
> >
> >     KASAN report:
> >
> >      BUG: KASAN: invalid size 18446744073709551614 in
> > kmalloc_memmove_invalid_size+0x70/0xa0
> >
> >      CPU: 1 PID: 91 Comm: cat Not tainted
> > 5.3.0-rc1ajb-00001-g31943bbc21ce-dirty #7
> >      Hardware name: linux,dummy-virt (DT)
> >      Call trace:
> >       dump_backtrace+0x0/0x278
> >       show_stack+0x14/0x20
> >       dump_stack+0x108/0x15c
> >       print_address_description+0x64/0x368
> >       __kasan_report+0x108/0x1a4
> >       kasan_report+0xc/0x18
> >       check_memory_region+0x15c/0x1b8
> >       memmove+0x34/0x88
> >       kmalloc_memmove_invalid_size+0x70/0xa0
> >
> >     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
> >
> >     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> >     Reported-by: Dmitry Vyukov <dvyukov@google.com>
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b63b367a94e8..e4e517a51860 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -280,6 +280,23 @@ static noinline void __init
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
> > @@ -734,6 +751,7 @@ static int __init kmalloc_tests_init(void)
> >         kmalloc_oob_memset_4();
> >         kmalloc_oob_memset_8();
> >         kmalloc_oob_memset_16();
> > +       kmalloc_memmove_invalid_size;
> >         kmalloc_uaf();
> >         kmalloc_uaf_memset();
> >         kmalloc_uaf2();
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 2277b82902d8..5fd377af7457 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +       if(!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +               return NULL;
> 
> Overall approach looks good to me.
> A good question is what we should return here. All bets are off after
> a report, but we still try to "minimize damage". One may argue for
> returning addr here and in other functions. But the more I think about
> this, the more I think it does not matter.
> 
agreed

> 
> >         return __memset(addr, c, len);
> >  }
> > @@ -110,7 +111,8 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > +       if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> > +               return NULL;
> >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> >         return __memmove(dest, src, len);
> > @@ -119,7 +121,8 @@ void *memmove(void *dest, const void *src, size_t
> > len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > +       if(!check_memory_region((unsigned long)src, len, false, _RET_IP_))
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
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 0e5f965f1882..0cd317ef30f5 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -68,11 +68,16 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
> >
> >  static void print_error_description(struct kasan_access_info *info)
> >  {
> > -       pr_err("BUG: KASAN: %s in %pS\n",
> > -               get_bug_type(info), (void *)info->ip);
> > -       pr_err("%s of size %zu at addr %px by task %s/%d\n",
> > -               info->is_write ? "Write" : "Read", info->access_size,
> > -               info->access_addr, current->comm, task_pid_nr(current));
> > +       if ((long)info->access_size < 0) {
> > +               pr_err("BUG: KASAN: invalid size %zu in %pS\n",
> > +                       info->access_size, (void *)info->ip);
> 
> I would not introduce a new bug type.
> These are parsed and used by some systems, e.g. syzbot. If size is
> user-controllable, then a new bug type for this will mean 2 bug
> reports.
> It also won't harm to print Read/Write, definitely the address, so no
> reason to special case this out of a dozen of report formats.
> This can qualify as out-of-bounds (definitely will cross some
> bounds!), so I would change get_bug_type() to return
> "slab-out-of-bounds" (as the most common OOB) in such case (with a
> comment).
> 
Print Read/Write and address information, it is ok.
But if we can directly point to the root cause of this problem, why we
not do it?  see 1) and 2) to get a point, if we print OOB, then user
needs one minute to think what is root case of this problem, but if we
print invalid size, then user can directly get root case. this is my
original thinking.
1)Invalid size is true then OOB is true.
2)OOB is true then invalid size may be true or false.

But I see you say some systems have used bug report so that avoid this
trouble, i will print the wrong type is "out-of-bound" in a unified way
when size<0.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570164140.19702.97.camel%40mtksdccf07.
