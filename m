Return-Path: <kasan-dev+bncBCMIZB7QWENRBVP25PWAKGQE73IBWGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6ABCDDCA
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 10:54:47 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 101sf5388667oth.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 01:54:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570438486; cv=pass;
        d=google.com; s=arc-20160816;
        b=JWnABZBZqbGaljlp4skVOGDqrvD1XvmXercataYUV2PrZ2BQIjunEIfzOxOdJQZu4H
         HlFRlXn0lOr7HhWF1rZxSLJ2WvTGthdcYrbQTgD/G/YjnXj0rn8IX407seUZgtf+Q1CQ
         SPQU+zLpig3Gvnyn7H9pHR2Lq3GqcFJZyM/YYiH1WwfySOUUOgSMxvgQimdi94v+F350
         QgZdbkFYMxUNe0WXyl9c7Phgh2t4Sws+Xd9MFwcm7t+gF/ZpvOnJeae33gMVawU7ROdS
         SvFgInpSPEsGKHX1c5CDL6yTD9/pdu5vLVAl0zuG7D0Roeg15TPBKmDcQjNv9NEkyW48
         WpPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lE1VNbFhx1cK0NDz0TQTCrz03xYmWDHdPuapltsDr+0=;
        b=iL2BcEvGu25gRAlvhf0SImriukgDUT46zMKj7RU6Sexm0Zg5iF5AZRH/Pm53H50iLL
         G173uE2aMEdsdgJ9NFMj8T/BZPnuFWyrfNgEf7mKN3A9FyIMSjI9OiF08CeLfjDacRn4
         Y6z2/n/C65jhhNBeYZziIreWB/GeZ0u5LmL5SL5PtQu3p9y482gfzJn7zXaRwTbv4zT9
         0ZQ3l8ZeEooOhJx32b3P5HpZ4nj224kp0HIiIu8FkUZmKuyijobtVz5NjeCUns2aWePO
         z+ILnz7oI9q0wwLwT4i0zW328NYBAh74JqVfkmwojxN7TyeirIx/wo1ntl25eHKUyA3+
         CPvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IPcU/D/V";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lE1VNbFhx1cK0NDz0TQTCrz03xYmWDHdPuapltsDr+0=;
        b=d+6z62O4k3TyA3+bm9GOjiTTzZVCMj4gzgIuJA/YfHnyr3OJHxczEsXRXr4epB4/Ir
         CJeTWFrin15IQfI7hrvEWOka9+UJuQeSLG8t3uu1M9Z6PVsMFzA43nFm9w5DgpByMowh
         KqOcoDuyo6i1I24GwJaIFx/gUs1q25kyv7sv6s9g3NkOwEyH5bolStIKqxFOO48xCnkl
         +dHfe7wz+YrMraw8z6BhEqyGPfCT8uK4d07PDcJOWgPOcapx3yXOIoveVsTbBrWo25J0
         FtSnHkUrfn6Cj7t5HvhT7cZqRYNnx3Al4tW2Wn6jcZHp7pcJl4wupmKGSi8f/e61nkxf
         xvwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lE1VNbFhx1cK0NDz0TQTCrz03xYmWDHdPuapltsDr+0=;
        b=dLBIrPetU0ePFwwvL03g4a8NCu24LQFsMcqwpWZzGJNHcuwgS9+pcIDFVoLsNeF7os
         wjnTBLuMbAEGYoIMr+8FeEHn3IbmlJ7weCyXp0IbiHcarjwSWxcyLGOP4G4enXPteYPN
         jFk2GAxiu/J9TUbTXWrgogAk7Rth8h5G3rftHV9COiyWXnxZmHUds0cWCZosVJrIVIAF
         VsZ527L1y9QqLZM78Xnn16hftvnMMBgBN0eu8XaDbTNGTKMsrm8dRsqUnFkKmCLe6cIG
         XQ9FptSzxgMv/awHysMMa318B0Gm3BsqpbknIHFYMVXt2gjapv6r2acvQuuHk4EJbBPC
         8sPg==
X-Gm-Message-State: APjAAAXKtoMKDz6Qau3QhLLIuSF++NcBQ2tuI4aB+glwH6KYeU0peuMm
	JqWnrzdNlG49jIkxez9Hex0=
X-Google-Smtp-Source: APXvYqwoHlROPXyDFM3ydvZQntm7uiBmeJwDUQuXZUAmszdnlr+LcjIe0NnqD+zY4Sl3/z/5Sw4SEw==
X-Received: by 2002:aca:c7c3:: with SMTP id x186mr345402oif.11.1570438485999;
        Mon, 07 Oct 2019 01:54:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1d1:: with SMTP id e75ls2791089ote.15.gmail; Mon, 07 Oct
 2019 01:54:45 -0700 (PDT)
X-Received: by 2002:a05:6830:158d:: with SMTP id i13mr20319172otr.67.1570438485701;
        Mon, 07 Oct 2019 01:54:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570438485; cv=none;
        d=google.com; s=arc-20160816;
        b=0z779TStv7IGTa4yZkv2llS8CDJJILIb4Hz389FofdPeuQiTM9e6YFaZg5imm6Vn5v
         35I/9IjBH+zcu4wUy8VWLTbuUGhAU3HVbnTfq/QL86zLt0L+jlGpq+c3HX1VQn3cpHzu
         JKeGYvfXKkqsFdPH1KPcHvY+ZxYmxj+S5hsu/xXweB/NAMD7oJBimn0IvqPadgAx3ZbA
         2LVJmZ6nMFT40UWaZYqASogXrD1lRVe/hCKsW+2HbkFHcRYTBXWE3WVsK7/U27mpbP6t
         /VjNnxCrGJXhgpZxfMyg8nPgb1HMkUhtFUsvyWSlp/HR57ZTq7ty+5/xjXrutMQRA8jw
         7ZFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3xmQjgOqY3AnnnxJQcdkIBmEXEk3wAq3gvPuP8Bb9/o=;
        b=FXyGxg23uZ6vZbEtIcUTwBaNBMPXTAcq1DbBmpgR863UgLKE0I3DIdu8hASV58PAi1
         RePEkO7xblETktNUDFSxm+4DWvU4Jgj5fx66qE+BXf62Is1T8FMTd3Bn1UBWr0r8KIqP
         EBuWrN12NDiDOD0O9kLfkZ1vslvjricGZCk0vgfmIbR8SzX81LKLrVLliIWLDZl1QMPP
         eTgpHMnp62TLVsZJxJAa2jwHMcQEBAIyd5FU+AF3i4SkMjb5tyytg2Klfo8n5ydzLK0t
         1YKwznX5FTikMHsSDqrXJlUHGpeK8fz/+bxBrwhsWl6xt3S1glCQRGT0aoCRoa8u+kcn
         IZnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IPcU/D/V";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id k198si1389743oib.4.2019.10.07.01.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 01:54:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w2so11852248qkf.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 01:54:45 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr20557320qkn.407.1570438484426;
 Mon, 07 Oct 2019 01:54:44 -0700 (PDT)
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
 <1570418576.4686.30.camel@mtksdccf07> <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
 <1570436289.4686.40.camel@mtksdccf07> <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
 <1570438317.4686.44.camel@mtksdccf07>
In-Reply-To: <1570438317.4686.44.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 10:54:32 +0200
Message-ID: <CACT4Y+Yc86bKxDp4ST8+49rzLOWkTXLkjs0eyFtohCi_uSjmLQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="IPcU/D/V";       spf=pass
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

On Mon, Oct 7, 2019 at 10:52 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2019-10-07 at 10:24 +0200, Dmitry Vyukov wrote:
> > On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > The patchsets help to produce KASAN report when size is negative numbers
> > > in memory operation function. It is helpful for programmer to solve the
> > > undefined behavior issue. Patch 1 based on Dmitry's review and
> > > suggestion, patch 2 is a test in order to verify the patch 1.
> > >
> > > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> > >
> > > Walter Wu (2):
> > > kasan: detect invalid size in memory operation function
> > > kasan: add test for invalid size in memmove
> > >
> > >  lib/test_kasan.c          | 18 ++++++++++++++++++
> > >  mm/kasan/common.c         | 13 ++++++++-----
> > >  mm/kasan/generic.c        |  5 +++++
> > >  mm/kasan/generic_report.c | 12 ++++++++++++
> > >  mm/kasan/tags.c           |  5 +++++
> > >  mm/kasan/tags_report.c    | 12 ++++++++++++
> > >  6 files changed, 60 insertions(+), 5 deletions(-)
> > >
> > >
> > >
> > >
> > > commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > Date:   Fri Oct 4 18:38:31 2019 +0800
> > >
> > >     kasan: detect invalid size in memory operation function
> > >
> > >     It is an undefined behavior to pass a negative numbers to
> > > memset()/memcpy()/memmove()
> > >     , so need to be detected by KASAN.
> > >
> > >     If size is negative numbers, then it has two reasons to be defined
> > > as out-of-bounds bug type.
> > >     1) Casting negative numbers to size_t would indeed turn up as a
> > > large
> > >     size_t and its value will be larger than ULONG_MAX/2, so that this
> > > can
> > >     qualify as out-of-bounds.
> > >     2) Don't generate new bug type in order to prevent duplicate reports
> > > by
> > >     some systems, e.g. syzbot.
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
> > > index 36c645939bc9..ed0eb94cb811 100644
> > > --- a/mm/kasan/generic_report.c
> > > +++ b/mm/kasan/generic_report.c
> > > @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> > > kasan_access_info *info)
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * If access_size is negative numbers, then it has two reasons
> > > +        * to be defined as out-of-bounds bug type.
> > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > reports
> > > +        * by some systems, e.g. syzbot.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> >
> > "out-of-bounds" is the _least_ frequent KASAN bug type. It won't
> > prevent duplicates. "heap-out-of-bounds" is the frequent one.
>
>
>     /*
>      * If access_size is negative numbers, then it has two reasons
>      * to be defined as out-of-bounds bug type.
>      * 1) Casting negative numbers to size_t would indeed turn up as
>      * a  "large" size_t and its value will be larger than ULONG_MAX/2,
>      *    so that this can qualify as out-of-bounds.
>      * 2) Don't generate new bug type in order to prevent duplicate
> reports
>      *    by some systems, e.g. syzbot. "out-of-bounds" is the _least_
> frequent KASAN bug type.
>      *    It won't prevent duplicates. "heap-out-of-bounds" is the
> frequent one.
>      */
>
> We directly add it into the comment.


OK, let's start from the beginning: why do you return "out-of-bounds" here?



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
> > > index 969ae08f59d7..012fbe3a793f 100644
> > > --- a/mm/kasan/tags_report.c
> > > +++ b/mm/kasan/tags_report.c
> > > @@ -36,6 +36,18 @@
> > >
> > >  const char *get_bug_type(struct kasan_access_info *info)
> > >  {
> > > +       /*
> > > +        * If access_size is negative numbers, then it has two reasons
> > > +        * to be defined as out-of-bounds bug type.
> > > +        * 1) Casting negative numbers to size_t would indeed turn up as
> > > +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> > > +        * so that this can qualify as out-of-bounds.
> > > +        * 2) Don't generate new bug type in order to prevent duplicate
> > > reports
> > > +        * by some systems, e.g. syzbot.
> > > +        */
> > > +       if ((long)info->access_size < 0)
> > > +               return "out-of-bounds";
> > > +
> > >  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > >         struct kasan_alloc_meta *alloc_meta;
> > >         struct kmem_cache *cache;
> > >
> > >
> > >
> > >
> > >
> > >
> > >
> > >
> > > commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> > > Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> > > Date:   Fri Oct 4 18:32:03 2019 +0800
> > >
> > >     kasan: add test for invalid size in memmove
> > >
> > >     Test size is negative vaule in memmove in order to verify
> > >     if it correctly get KASAN report.
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
> > >
> > >
> > >
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570436289.4686.40.camel%40mtksdccf07.
>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570438317.4686.44.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYc86bKxDp4ST8%2B49rzLOWkTXLkjs0eyFtohCi_uSjmLQ%40mail.gmail.com.
