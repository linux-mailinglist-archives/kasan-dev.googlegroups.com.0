Return-Path: <kasan-dev+bncBCMIZB7QWENRBTXM5PWAKGQEB737RQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C22ACDD32
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 10:24:48 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id p2sf10490621pff.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 01:24:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570436686; cv=pass;
        d=google.com; s=arc-20160816;
        b=Otp1a6Ik1/br+bfTqx5WnNLuxHA9AxvSBClFelMocchrCQJ3dLCG1a0G6bezKN22yT
         3Mm30rB13Zj/4x8baoABJfRsZD+5JBcfYp7Bypi8ghWj3nzx+QfR+kWB+8tm+qTJyfZu
         b2gCJBM7cXSKJRb4NORoq0W6sxGtArh3GPP8HucNMbSgZ4cC/g/gqzMYVMAogQgvZu8c
         kqiaiNocxUXfeQ29yBDasU2O+QGIPhN54WE5s5VKYFIUFj8HC5sNxuwRU5KyJRr2ykxL
         rCfKdDqxUjTYvxaJuvNR0Dg+OlM4hnfU9SvlMLRIW3PsV+/73PNMXjULgFXOedbHakK6
         ZWCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OlPOE1QPJmFJUtzJmlDUgwlQbsXZsoBFOdryCQBCm08=;
        b=r45rN+tEjN0rDf/fQQrS/5HvrjAKBjtwQNxeg60i+OTMzEmrZ38tgGyF49WUr+qJFd
         uYlz2bNtyyyZuKgfVW3aJd0TOVvA6gQUbya1LJyVxnOKHuD2VKaQcYEghk0qjANQ5D78
         DDI/VB8hz8d0p7o0q8T/nMo9yBOMCQEXea1n1VYegxbhapNpOa7OqKuFhkD9Eaju3uj7
         Pra4FFcj5OjG1WwztpDfyirIw/BFunYr9tNc4ERh2rkZjdE2mK8BCwFhWTevpzUyfwMj
         ZCVtUI9HXmpBawK50BByQHHaFOLwzUR/9VnshCEc50z6JS/76GGGX7WD8YHcHoVCPIDi
         WGHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hen5dp5h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OlPOE1QPJmFJUtzJmlDUgwlQbsXZsoBFOdryCQBCm08=;
        b=T/9ITyX7B7qq6IHJYsShc59/hp0x0iuwg2mU/+nRpgPEOgQhTr9Oqgn5HG16Cdyq21
         GwYPmofYKDvlh0i5MvADZ3gc69wCahrbZBE/ZIVTnOqNepNy4V53TNQ+kLOHVIDyPvfp
         X9diSBY9TGFmTLo1GOVH7rNs27VZjVx1uo/Ydf37bGOl5C99/oW9TCtoy+v8OPK2sNuq
         GQzTvUwD0R912123xQz2IhZWO06ChMSZaO7utUfaFLCfKU5AXRyxLg321Oj3lt1xY1W/
         d17tVOXIk9xlxQbe5mdE3z/iVJ4rxv9cgMF+SzK+ydnRuf5VPmNEHFpv8Fbq1/Z22rQC
         /6cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OlPOE1QPJmFJUtzJmlDUgwlQbsXZsoBFOdryCQBCm08=;
        b=s6pNNo2gPevAh0SLn2r6V7J3Dr4XnruLhCXwp6fzC5GDs09vWmDnWTQdi786dQk4wV
         gmqVWY/uIcChvb1XO43jWVSq1FuiNI6eELQSxa1QarT4dS5Up8I7vDQP9g2gwvXRUX7Y
         Ez40B8Lj/0Mc7FCLbXcs8Yp5+ts2ifWeVj1WisKrdQMvyWkL6V11uwJSW/HWK97ydSjl
         AEB9E21yW1O+qFPZRnfeLOmv2HR2q5UhVRyjzXpmqBB4/yWeZaSpORl6ZGbpHsolb0zU
         JCUuIxOMxqHwWiD2kyWk63ASicyQliGyelKN5hM3OGTTmpLcohV4reMVnAXK5zejs/sQ
         ZzDQ==
X-Gm-Message-State: APjAAAW+oK0zmBDal/zTecJttpeXRz8XRDGCtjdFdG79zaYxrHosvRX/
	TS3fvUobgmkbWKGqXm/bYQc=
X-Google-Smtp-Source: APXvYqxs90aVpqK8N1gV/bJDp7/h/uGqtdpEaXRx6uiXOFH4rkHc+bXS8EEC09T6fHTsDCZw8j1j5A==
X-Received: by 2002:aa7:94af:: with SMTP id a15mr15942610pfl.157.1570436686838;
        Mon, 07 Oct 2019 01:24:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:644a:: with SMTP id y71ls4284646pfb.9.gmail; Mon, 07 Oct
 2019 01:24:46 -0700 (PDT)
X-Received: by 2002:a62:a518:: with SMTP id v24mr32104972pfm.126.1570436686521;
        Mon, 07 Oct 2019 01:24:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570436686; cv=none;
        d=google.com; s=arc-20160816;
        b=fOZ7+byHImH8J99D96s3QmZwVNBSr/rf64I4xDSrem+mDDh4XdjcRMSz4ty+wk7PZz
         bYCQCBsApAWoiR5tV1sMRjJ+NezL4OgEB8cGu0JC80TsxZoy3mMrPsJR98NNRbjHf/I3
         7U8fHuuJRq+iOAaCdn7+rJZVQqFffyDQb7VqjzN2E/10A2Eyo0b7xHNppPEJUx/ykh9f
         wko3i4yGZzw6DDVIV9p8TDCdn062+ardHcUDPCC8fv9n1oUUwHH8i7SVRSsZJbS2DIeh
         FjSkuGMPlZtG8YJEYMQTcfeGTjZlH+JjgRdXT48LdyXrisdkHkiCplh6Hkg62Oc1hRjk
         STsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8DB4/MTLlkvkxLbC1PzaZFDFcZ5ssBbsLI3qX2hSeG0=;
        b=NnWC7Nr8ZH4NPpVgVxym08q7fPt+6brNpJnrIIAClJNF0VNmdC7ltkkT5jB9ZQYW40
         3/CzotH4eb+YTbI7txrh5OQq7j0NvK5SWHBDe0e/9cBKW5UDy0vA0R/101T5kqpakGFV
         optXvudUHocWTa99KFpiEHc7ATVrxoyILzb9A+42lZ0OU2eiBPCCloll72lkxXCh2udh
         ENTZbe9tIA6Gj4uNaPMn9tH032dyP9NLudSKy2QKmKVfXLN4LKjvf0uQtq50/OBSzV10
         cAmplOnKLWKmYIZrMKBz1BOK4KFaF/rr/VI/CUYfBg0MZnxcgL5h/uKu2TZAP5q458pE
         +kew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hen5dp5h;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id q141si1002540pfc.4.2019.10.07.01.24.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Oct 2019 01:24:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id u186so11787986qkc.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Oct 2019 01:24:46 -0700 (PDT)
X-Received: by 2002:a37:9202:: with SMTP id u2mr22501265qkd.8.1570436685395;
 Mon, 07 Oct 2019 01:24:45 -0700 (PDT)
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
 <1570436289.4686.40.camel@mtksdccf07>
In-Reply-To: <1570436289.4686.40.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Oct 2019 10:24:33 +0200
Message-ID: <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Hen5dp5h;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Mon, Oct 7, 2019 at 10:18 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> The patchsets help to produce KASAN report when size is negative numbers
> in memory operation function. It is helpful for programmer to solve the
> undefined behavior issue. Patch 1 based on Dmitry's review and
> suggestion, patch 2 is a test in order to verify the patch 1.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
>
> Walter Wu (2):
> kasan: detect invalid size in memory operation function
> kasan: add test for invalid size in memmove
>
>  lib/test_kasan.c          | 18 ++++++++++++++++++
>  mm/kasan/common.c         | 13 ++++++++-----
>  mm/kasan/generic.c        |  5 +++++
>  mm/kasan/generic_report.c | 12 ++++++++++++
>  mm/kasan/tags.c           |  5 +++++
>  mm/kasan/tags_report.c    | 12 ++++++++++++
>  6 files changed, 60 insertions(+), 5 deletions(-)
>
>
>
>
> commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
> Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> Date:   Fri Oct 4 18:38:31 2019 +0800
>
>     kasan: detect invalid size in memory operation function
>
>     It is an undefined behavior to pass a negative numbers to
> memset()/memcpy()/memmove()
>     , so need to be detected by KASAN.
>
>     If size is negative numbers, then it has two reasons to be defined
> as out-of-bounds bug type.
>     1) Casting negative numbers to size_t would indeed turn up as a
> large
>     size_t and its value will be larger than ULONG_MAX/2, so that this
> can
>     qualify as out-of-bounds.
>     2) Don't generate new bug type in order to prevent duplicate reports
> by
>     some systems, e.g. syzbot.
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
> index 36c645939bc9..ed0eb94cb811 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
> kasan_access_info *info)
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * If access_size is negative numbers, then it has two reasons
> +        * to be defined as out-of-bounds bug type.
> +        * 1) Casting negative numbers to size_t would indeed turn up as
> +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        * 2) Don't generate new bug type in order to prevent duplicate
> reports
> +        * by some systems, e.g. syzbot.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "out-of-bounds";

"out-of-bounds" is the _least_ frequent KASAN bug type. It won't
prevent duplicates. "heap-out-of-bounds" is the frequent one.

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
> index 969ae08f59d7..012fbe3a793f 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,18 @@
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +       /*
> +        * If access_size is negative numbers, then it has two reasons
> +        * to be defined as out-of-bounds bug type.
> +        * 1) Casting negative numbers to size_t would indeed turn up as
> +        * a 'large' size_t and its value will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        * 2) Don't generate new bug type in order to prevent duplicate
> reports
> +        * by some systems, e.g. syzbot.
> +        */
> +       if ((long)info->access_size < 0)
> +               return "out-of-bounds";
> +
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
>
>
>
>
>
>
>
>
> commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
> Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
> Date:   Fri Oct 4 18:32:03 2019 +0800
>
>     kasan: add test for invalid size in memmove
>
>     Test size is negative vaule in memmove in order to verify
>     if it correctly get KASAN report.
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
>
>
>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570436289.4686.40.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g%40mail.gmail.com.
