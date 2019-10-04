Return-Path: <kasan-dev+bncBCMIZB7QWENRBSNN3TWAKGQEK4OP36I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93AF8CB7B3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 11:54:18 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id c12sf4261553ybp.16
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 02:54:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570182857; cv=pass;
        d=google.com; s=arc-20160816;
        b=nhnljHcVvEJ0H+Cp+9mPzR4uFHeKxJul5Aqx0/Pnh77rKN7iH8ZRFZV/pTvA3dyhOn
         BF6Zu31QTLnd2Aw7PMyt7lrkRspqxyHoVPuggfc3kVlc/ZWrcK2dlU2Ix0H26IBP0+jl
         aSSQYoxLfX6vBygn96/XlUU34cLA8sh4/ewghFiOkKfyUmjVFFHSuuXUT6DPw4iW7ub5
         TKmeyd5Husq6VoAKHwrhcWxGRqvVqmZpa3vPSu5fHcaKHhA+3BiTB9a7V2a2m9woiCWp
         QuOnq3Q41iGf/dTmrOV6v46upbd7u8wiKX2JnyJAyBPkvBlByCoEQfUIsXD/ebgys/PA
         CB3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dySss8OoKEmgQ3Vc2ClRjOciUxFjiy5qJ6pSw4Ts6Bs=;
        b=QHb94Jlw6J61bMWzp8bM/qSybU6SBrJc/4pY3AolbKJKeCoNTefkcsH5s9cpAIZf56
         BLFcOX06vazo52QUMhUPuyagSfc6pmJsMHbqlFfoCkaSwawvh2V3zwstaXRr4IVzrg9M
         2dnKmnrGVI0Hp1EU8nHVbgXLI9DjQqRNN6KJ+UaJrQxfMbUmfzV2tDEmJAVqrPWmqRHY
         C7zgnd6gowdTExPMbvN40q5DBlgHzPPciq+6UkNrTlVyNclDgggFbhyxTfP4/KkChMwh
         cvhA6DsRk3oYNs4qfNoZPets1LW4QT2++lmchm4cTn2XQskQLN8wz4/OZ1f+zb8aFTVP
         JNhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1g0d+tr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dySss8OoKEmgQ3Vc2ClRjOciUxFjiy5qJ6pSw4Ts6Bs=;
        b=d75D8C1OVT0qVjhs0dlin9PNb6ZFnUc3EfW2jrFWowc9onlNW9la1CkwfuHtxQibHb
         3Mmb0U+hJZclZ4GmbpGpuJIbZLK5jZh4NzFGfdXNinFKnNqW62qXIgG1vGrDwYoOvNgS
         /Iz0wBQt/v1KMBWMrH+yb7INDEt+pzGgF2NdsNeJPn5w9D8yE3X7G8K6U5RhHmm6TiFx
         BLM/rtLyB9otMuWzMA5HrBzeuinZLvdzr9VaNDmerkIIEIQsEkJZy7Md0X5WQNEeTUjy
         miDMcFmdhyFLp4Imc8o4BDN6XJZ+VTLhMphi0xjQQZJqyIzr60P/gIPc5qXA12wlIZvn
         uNfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dySss8OoKEmgQ3Vc2ClRjOciUxFjiy5qJ6pSw4Ts6Bs=;
        b=Za0NH2Mzbe1VPt1bfZzmlEiwwP7zUwc6vUwrEW37pOpEzvS6lOPxiyJCMhdXrpTKJy
         YUmNZpeb+T0mzXfFCuk8lRQ0fncNe+ISNeEMBv9kDihFQNTsMialp09lbDRC3AvxplUy
         wW3uR3SMvRlrBwxjMe4eNgZCNVZsQ3r1yEhqvg3wMCzfY/eDOf2suiu02yy1iPgJZfUm
         gdtzMytD42HetIuIlTaLJwi2C643CC6erjHo/gRWwNTx1Aq5V6Xy6uO22jMJI7VVpjvh
         E/TXnP9lezpEiMttlWLVFe0eVTaZEkm3Ocae+7p1CN3O6nWG3xs5CFa9aPzlM7nAsB/4
         wFjw==
X-Gm-Message-State: APjAAAWBWJmwjIRjpT3B9AqJ+V28lgW8/acggl6xc2E3FiBxv5nN5aQo
	NrYKgpqKvtjEpLRAuI1auYE=
X-Google-Smtp-Source: APXvYqxTxNDHIiRvGxfVDXovxEtrHBZL2Jvduxava+f6sblysfY/S7AkeU+Bq3/WxnKQNO/lVPACww==
X-Received: by 2002:a81:a401:: with SMTP id b1mr9437884ywh.280.1570182857595;
        Fri, 04 Oct 2019 02:54:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e64a:: with SMTP id p71ls975607ywe.11.gmail; Fri, 04 Oct
 2019 02:54:17 -0700 (PDT)
X-Received: by 2002:a0d:ea93:: with SMTP id t141mr10267362ywe.19.1570182857231;
        Fri, 04 Oct 2019 02:54:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570182857; cv=none;
        d=google.com; s=arc-20160816;
        b=yPDAFAs6xGAu/hhLpweXrXJpjXXB7bZzfBN70KOWHnh28rWPwd/clKrnUd1ihcF0MQ
         lTGN5WRleqwSK66mGjOQKolRF3EIZA8DynJ53ujr5y3kiBT2p07X2Hp/LE7OUUUu6SXj
         ZLk00MVNm4SpJ0ctnMyHtXBR6j7HBYcvpceb0iCrJAEUqvz2UMYfkcFBWpJhFzfddgIf
         RnS3DE2UGvhYqBYneIx6Z+w3LJ3DfZ7xQpRjCk2/eSosFzdt+O8ZYOBxWJYW+04wut9b
         WzgCXnw0JsemWQWeDjoVPRTfwnI9NjXHcSXzY7asVvG+EhgF4UrP4ZFl0qPnna5dYKhM
         AD4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lYr8ibckse0BmUaAjEkti+4k6yIQOCn91r/LNpsvMM0=;
        b=BvcNvywXHl2k2/ziNl6bID6QtrJ/PuxGrxqYxiH1FmOS5YvgwyGlFMz5Bb5ffY5Ywl
         fX6m6ywT00grGtmenX1fqPc+9r8+/Ck5XhGffmGr6fjSht7fiEbd+NSQy/DVvS4qX6g4
         3HdY2n3eFnWI57b3QNSm/soyrYn9eX50HJlpEcz7hgABG7IuCqLrNukO/p98ETosuKNR
         72v+cPsE36OfhMzECU801I3kl4l34Oe6o1FZUl0nzb+vl/IjHGaY4Vp59PBsgzuykbAR
         eXn+9dF/n0vbi0yrROrltWnfdwLzpxf0d5C+fg3QgAuHhv4uNzVH0UyHUYlogrRqa0Eq
         f2wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1g0d+tr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id j136si32242ybj.3.2019.10.04.02.54.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 02:54:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id c3so7679151qtv.10
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 02:54:17 -0700 (PDT)
X-Received: by 2002:ac8:108b:: with SMTP id a11mr14866143qtj.380.1570182856217;
 Fri, 04 Oct 2019 02:54:16 -0700 (PDT)
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
 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com> <1570182257.19702.109.camel@mtksdccf07>
In-Reply-To: <1570182257.19702.109.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2019 11:54:04 +0200
Message-ID: <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=m1g0d+tr;       spf=pass
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

On Fri, Oct 4, 2019 at 11:44 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Fri, 2019-10-04 at 11:18 +0200, Dmitry Vyukov wrote:
> > On Fri, Oct 4, 2019 at 10:02 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > On Fri, 2019-10-04 at 12:42 +0800, Walter Wu wrote:
> > > > On Thu, 2019-10-03 at 16:53 +0200, Dmitry Vyukov wrote:
> > > > > On Thu, Oct 3, 2019 at 3:51 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:>
> > > > > >
> > > > > >  static void print_error_description(struct kasan_access_info *info)
> > > > > >  {
> > > > > > -       pr_err("BUG: KASAN: %s in %pS\n",
> > > > > > -               get_bug_type(info), (void *)info->ip);
> > > > > > -       pr_err("%s of size %zu at addr %px by task %s/%d\n",
> > > > > > -               info->is_write ? "Write" : "Read", info->access_size,
> > > > > > -               info->access_addr, current->comm, task_pid_nr(current));
> > > > > > +       if ((long)info->access_size < 0) {
> > > > > > +               pr_err("BUG: KASAN: invalid size %zu in %pS\n",
> > > > > > +                       info->access_size, (void *)info->ip);
> > > > >
> > > > > I would not introduce a new bug type.
> > > > > These are parsed and used by some systems, e.g. syzbot. If size is
> > > > > user-controllable, then a new bug type for this will mean 2 bug
> > > > > reports.
> > > > > It also won't harm to print Read/Write, definitely the address, so no
> > > > > reason to special case this out of a dozen of report formats.
> > > > > This can qualify as out-of-bounds (definitely will cross some
> > > > > bounds!), so I would change get_bug_type() to return
> > > > > "slab-out-of-bounds" (as the most common OOB) in such case (with a
> > > > > comment).
> > > > >
> > > > Print Read/Write and address information, it is ok.
> > > > But if we can directly point to the root cause of this problem, why we
> > > > not do it?  see 1) and 2) to get a point, if we print OOB, then user
> > > > needs one minute to think what is root case of this problem, but if we
> > > > print invalid size, then user can directly get root case. this is my
> > > > original thinking.
> > > > 1)Invalid size is true then OOB is true.
> > > > 2)OOB is true then invalid size may be true or false.
> > > >
> > > > But I see you say some systems have used bug report so that avoid this
> > > > trouble, i will print the wrong type is "out-of-bound" in a unified way
> > > > when size<0.
> > > >
> > >
> > > Updated my patch, please help to review it.
> > > thanks.
> > >
> > > commit 13e10a7e4264eb25c5a14193068027afc9c261f6
> > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > Date:   Fri Oct 4 15:27:17 2019 +0800
> > >
> > >     kasan: detect negative size in memory operation function
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
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > index 6814d6d6a023..97dd6eecc3e7 100644
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
> > > @@ -110,7 +111,8 @@ void *memset(void *addr, int c, size_t len)
> > >  #undef memmove
> > >  void *memmove(void *dest, const void *src, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> > > +               return NULL;
> > >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >
> > I would check both calls.
> > The current code seems to be over-specialized for handling of invalid
> > size (you assume that if it's invalid size, then the first
> > check_memory_region will detect it and checking the second one is
> > pointless, right?).
> > But check_memory_region can return false in other cases too.
> > Also seeing first call checked, but the second not checked just hurts
> > my eyes when reading code (whenever I will read such code my first
> > reaction will be "why?").
> >
> I can't agree with you any more about second point.
>
> #undef memmove
> void *memmove(void *dest, const void *src, size_t len)
> {
>     if (!check_memory_region((unsigned long)src, len, false, _RET_IP_)
> ||)
>         !check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>         return NULL;
>
>     return __memmove(dest, src, len);
> }
>
> >
> > >
> > >         return __memmove(dest, src, len);
> > > @@ -119,7 +121,8 @@ void *memmove(void *dest, const void *src, size_t
> > > len)
> > >  #undef memcpy
> > >  void *memcpy(void *dest, const void *src, size_t len)
> > >  {
> > > -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > > +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_))
> > > +               return NULL;
> > >         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > >
> > >         return __memcpy(dest, src, len);
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
> > > index 36c645939bc9..ae9596210394 100644
> > > --- a/mm/kasan/generic_report.c
> > > +++ b/mm/kasan/generic_report.c
> > > @@ -107,6 +107,13 @@ static const char *get_wild_bug_type(struct
> > > kasan_access_info *info)
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> >
> > "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> > "out-of-bounds" has downsides of both approaches and won't prevent
> > duplicate reports by syzbot...
> >
> maybe i should add your comment into the comment in get_bug_type?

Yes, that's exactly what I meant above:

"I would change get_bug_type() to return "slab-out-of-bounds" (as the
most common OOB) in such case (with a comment)."

 ;)

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
> > > index 969ae08f59d7..1e1ca81214b5 100644
> > > --- a/mm/kasan/tags_report.c
> > > +++ b/mm/kasan/tags_report.c
> > > @@ -36,6 +36,13 @@
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> > > +
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >         struct kasan_alloc_meta *alloc_meta;
> > >         struct kmem_cache *cache;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZnWPEO-9DkE6C3MX-Wo%2B8pdS6Gr6-2a8LzqBS%3D2fe84w%40mail.gmail.com.
