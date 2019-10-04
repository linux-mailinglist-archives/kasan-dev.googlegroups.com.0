Return-Path: <kasan-dev+bncBCMIZB7QWENRBGM53XWAKGQEF22KKEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A444CBC42
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 15:52:27 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id b67sf6395935qkc.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 06:52:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570197145; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRpPSDGLrc9WKzjWT1j5Ujq8itJ9w1scC511McA7BZnXwP26dCKQhFY7onqFsyvaS3
         NvGIsEgF48Cmt+1z8ufWiKuT0trFvL2lWBs9Ckc0+3JGV16+QUsi+ZPj0wmVZ4ZD10nH
         arBV/90ytNxAO7ARZUYww6E5uQeZQFgsv/7NcaDZZmx5536A+sJGHGtFzws4X0reCFQs
         mC0TeLD7rvxGHU3VHDWFRV6JyKI6QwYHVEYVxPyg9k5RHdGqbkHW5bSj5fPs+GKA/Hpa
         ix04rGHxvAnZr0vgrVZuu76UqOefJLJ/aEHVJAS4ps+lzPSFlAmTWIh9bmBtZXrJH0z1
         YcOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/TgvQTKkC2ZHdQmHC882yEEVT2sOQd3iDpvrexKj4Rg=;
        b=pIgwToguI3p7nOZ0hfHfVPeIb8rUY8MGniM46Wqoe4lNrYWGo02nMdrHi9XB2TnXvr
         ETRNDdoxXmOW6zKuiWfJf6PJUWSR86o2cei4b4hCqd+lMIkVbhocnQLgBjdEkNGfk4pC
         WNgWjb4Xhtekmep5k3Kxu1FjIw0G5uxqUu3Ckibg6a45OKoxEP+szg3Tv+bHKRbvFLrn
         nthJsxUKS5ofx2tROu7ibYxja7MWLRIDWdp0Qtnu5J5ssBiBUqepZ+0wc8MAuLPEftnR
         xTJauft3OQDUn1BrfaUr1vNGob862vFY1QKtG2mqb9vsUXiBMU04zAdJ+lEx2/Ekl+Uh
         SOsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3wWmtC0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/TgvQTKkC2ZHdQmHC882yEEVT2sOQd3iDpvrexKj4Rg=;
        b=tocEO/hbU7dpR3kzfRlagBuIuhNo8g+I0PUvg4EfH+OvJIuD5nKmEdoGrPY/vLIYa/
         2cENCedeBcSdtEajfVoG7rrRr38C7BuiSa9o2OXwubsCNdQwIrjjgAnSuJGZT+IgLaH+
         zcIOo+sBqb7wtOmDLA6srRpGhqGtMsyfmOwGMekPjl+4rg+tZ/3z+B137Ir1BazA3RGx
         1FfBkYblB9F2vCtQk2pI8ksWYAfYiBs1xdfgfuyIdDTjEVo0xnHl5QLwUrE9Ew96p2Jr
         2/mYo73xNRWKpU0oJjY9/h/0eyV3h28WGBUevgmQp4GtLQrNBRhKg0KQFn/esJ6ZtnD0
         TCng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/TgvQTKkC2ZHdQmHC882yEEVT2sOQd3iDpvrexKj4Rg=;
        b=eK4PNdA6F4SIVQcI16K1K0D1X8gLO9LwVM/dbDlJL577Tx7/2Oy3EKtb69LXbzAhbo
         hnEutQ5YJ2yE8iIQBGgym4C62DU5OZkmjYo8KU7sD2/ZCVSrOw/DKxgea8zIfVlBNnBe
         qT5DLsvYhjzFtJsZgUNZYVfayXG4iYE08Umj7ie1Px+gOZ+RfUt4r8gpRYdjLcJHKlbK
         wIf80Rxj8PCuUmG6T6K5SSj8Pucy0gJ1x6LGu68WbCntAb5+UYUPcfmvt1a8wnF2ekXF
         O+8vfu0teg1OatStBzCJFzLl5Psfn4X2wWeeQcRnN4F9AiEeNOETsRrlubzXd55qRHVq
         zpXw==
X-Gm-Message-State: APjAAAVNEbfc5Kj2vZWbZr4EVDQIi3Rcn4iHR7ht0I8JpD6UjyTsk/Eh
	n6fbWS3oLRsZwPlG6/QowpU=
X-Google-Smtp-Source: APXvYqwVBOVmB6PEXdV6Mi2wU2rw339Egqthpjox1prF1Sl3VYso+yzrthmJU8/ROubTGRS+Git6EA==
X-Received: by 2002:ac8:301b:: with SMTP id f27mr15061159qte.83.1570197145632;
        Fri, 04 Oct 2019 06:52:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eb01:: with SMTP id j1ls1625414qvp.11.gmail; Fri, 04 Oct
 2019 06:52:25 -0700 (PDT)
X-Received: by 2002:a0c:ea27:: with SMTP id t7mr14066901qvp.103.1570197145316;
        Fri, 04 Oct 2019 06:52:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570197145; cv=none;
        d=google.com; s=arc-20160816;
        b=nn8MI3dZ2+WKoaDrAVRii8IFLrsp3GDxU2ZD7nr+2IP/T/7yY4NbPFqeYvkb57OE6Y
         FTe3IRMhO/U1HLbNfpe5pZm7lzJR3fz36tWOoNXnG2ZQzHGkyqf9+ZcEb0FgGKReHJJN
         abGtjI6799pYshkDsa/I6xv9SfQJxPwZOwHB5QkQRmdzj25NkmmCWEEugjskQB8ILFao
         CyTenyyYs21fC/uzSsDxNjJxxtgN103+2ljfLCMAwrKWZ/LESJLJ3n8yNxHrSO9D0Mew
         F0RPBalt5EY0ZGdSsVg8l0p4G4TV3I9t5LNz67zmO3cN0SuU3m0hqrrdZLwzV7hNo0q4
         11Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Soan35jSNw0pBZHNZx4RYBGEDn5tQAp2CqUTHCkSaUU=;
        b=l8FgJeguOJ1QRQ2Rl4uR4inVzmzInd7cPsihaBQ54YPc6PYHmOCJS/9VTrjw/pZOK1
         WJARyD4TqzpEoss8rE8q/6N1Qj8ZbpPpi+gaZtyaoiogGnaMYAIGPRQSBbms8MeW+kj+
         MuxqRmYf4Ly5SifdT/b0ehwZfryXcBz2I0X4OGLnAmqEjPgYjJJ6q1scrrphJfJgb/2s
         3i1uDa/DFbdqumrqB90I5CpGaN6rXzlxHyKLTIiT2wjo7iddyvLAZzPeS7pMgTNTDJlv
         6eWSQcXEJNyoCyKbZegzsg+OQ08NeOI9dw9LAGByFK+WEs8LQXBK9/sS1ZZm/LDyp6FJ
         E1CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F3wWmtC0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id v7si382148qkf.5.2019.10.04.06.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 06:52:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x134so5871416qkb.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 06:52:25 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr9297358qkn.407.1570197144318;
 Fri, 04 Oct 2019 06:52:24 -0700 (PDT)
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
 <1570190718.19702.125.camel@mtksdccf07>
In-Reply-To: <1570190718.19702.125.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Oct 2019 15:52:12 +0200
Message-ID: <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=F3wWmtC0;       spf=pass
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

On Fri, Oct 4, 2019 at 2:05 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Fri, 2019-10-04 at 11:54 +0200, Dmitry Vyukov wrote:
> > > > "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> > > > "out-of-bounds" has downsides of both approaches and won't prevent
> > > > duplicate reports by syzbot...
> > > >
> > > maybe i should add your comment into the comment in get_bug_type?
> >
> > Yes, that's exactly what I meant above:
> >
> > "I would change get_bug_type() to return "slab-out-of-bounds" (as the
> > most common OOB) in such case (with a comment)."
> >
> >  ;)
>
>
> The patchset help to produce KASAN report when size is negative size in
> memory operation function. It is helpful for programmer to solve the
> undefined behavior issue. Patch 1 based on Dmitry's suggestion and
> review, patch 2 is a test in order to verify the patch 1.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
>
> Walter Wu (2):
> kasan: detect invalid size in memory operation function
> kasan: add test for invalid size in memmove
>
> lib/test_kasan.c          | 18 ++++++++++++++++++
> mm/kasan/common.c         | 13 ++++++++-----
> mm/kasan/generic.c        |  5 +++++
> mm/kasan/generic_report.c | 10 ++++++++++
> mm/kasan/tags.c           |  5 +++++
> mm/kasan/tags_report.c    | 10 ++++++++++
> 6 files changed, 56 insertions(+), 5 deletions(-)
>
>
>
>
> commit 0bc50c759a425fa0aafb7ef623aa1598b3542c67
> Author: Walter Wu <walter-zh.wu@mediatek.com>
> Date:   Fri Oct 4 18:38:31 2019 +0800
>
>     kasan: detect invalid size in memory operation function
>
>     It is an undefined behavior to pass a negative value to
> memset()/memcpy()/memmove()
>     , so need to be detected by KASAN.
>
>     If size is negative value, then it will be larger than ULONG_MAX/2,
>     so that we will qualify as out-of-bounds issue.
>
>     KASAN report:
>
>      BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
>      Read of size 18446744073709551608 at addr ffffff8069660904 by task
> cat/72
>
>      CPU: 2 PID: 72 Comm: cat Not tainted
> 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
>      Hardware name: linux,dummy-virt (DT)
>      Call trace:
>       dump_backtrace+0x0/0x288
>       show_stack+0x14/0x20
>       dump_stack+0x10c/0x164
>       print_address_description.isra.9+0x68/0x378
>       __kasan_report+0x164/0x1a0
>       kasan_report+0xc/0x18
>       check_memory_region+0x174/0x1d0
>       memmove+0x34/0x88
>       kmalloc_memmove_invalid_size+0x70/0xa0
>
>     [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
>
>     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
>     Reported -by: Dmitry Vyukov <dvyukov@google.com>
>     Suggested-by: Dmitry Vyukov <dvyukov@google.com>
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..6ef0abd27f06 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -       check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memset(addr, c, len);
>  }
> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memmove(dest, src, len);
>  }
> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
> len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -       check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -       check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +       !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> +               return NULL;
>
>         return __memcpy(dest, src, len);
>  }
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..02148a317d27 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -173,6 +173,11 @@ static __always_inline bool
> check_memory_region_inline(unsigned long addr,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         if (unlikely((void *)addr <
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>                 kasan_report(addr, size, write, ret_ip);
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..23951a453681 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -107,6 +107,16 @@ static const char *get_wild_bug_type(struct
> kasan_access_info *info)
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> +        * out-of-bounds has downsides of both approaches and won't prevent
> +        * duplicate reports by syzbot.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "out-of-bounds";
> +
>         if (addr_has_shadow(info->access_addr))
>                 return get_shadow_bug_type(info);
>         return get_wild_bug_type(info);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 0e987c9ca052..b829535a3ad7 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
> size, bool write,
>         if (unlikely(size == 0))
>                 return true;
>
> +       if (unlikely((long)size < 0)) {
> +               kasan_report(addr, size, write, ret_ip);
> +               return false;
> +       }
> +
>         tag = get_tag((const void *)addr);
>
>         /*
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 969ae08f59d7..19b9e364b397 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,16 @@
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> +        * out-of-bounds has downsides of both approaches and won't prevent
> +        * duplicate reports by syzbot.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "out-of-bounds";


wait, no :)
I meant we change it to heap-out-of-bounds and explain why we are
saying this is a heap-out-of-bounds.
The current comment effectively says we are doing non useful thing for
no reason, it does not eliminate any of my questions as a reader of
this code :)




> +
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
>
>
>
> commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> Author: Walter Wu <walter-zh.wu@mediatek.com>
> Date:   Fri Oct 4 18:32:03 2019 +0800
>
>     kasan: add test for invalid size in memmove
>
>     Test size is negative vaule in memmove in order to verify
>     if it correctly produce KASAN report.
>
>     Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 49cc4d570a40..06942cf585cc 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -283,6 +283,23 @@ static noinline void __init
> kmalloc_oob_in_memset(void)
>         kfree(ptr);
>  }
>
> +static noinline void __init kmalloc_memmove_invalid_size(void)
> +{
> +       char *ptr;
> +       size_t size = 64;
> +
> +       pr_info("invalid size in memmove\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       memset((char *)ptr, 0, 64);
> +       memmove((char *)ptr, (char *)ptr + 4, -2);
> +       kfree(ptr);
> +}
> +
>  static noinline void __init kmalloc_uaf(void)
>  {
>         char *ptr;
> @@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
>         kmalloc_oob_memset_4();
>         kmalloc_oob_memset_8();
>         kmalloc_oob_memset_16();
> +       kmalloc_memmove_invalid_size();
>         kmalloc_uaf();
>         kmalloc_uaf_memset();
>         kmalloc_uaf2();

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g%40mail.gmail.com.
