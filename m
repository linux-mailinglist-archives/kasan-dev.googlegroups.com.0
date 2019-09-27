Return-Path: <kasan-dev+bncBCMIZB7QWENRBGUTXDWAKGQEBKL3COA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 01BBBC05FB
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 15:07:40 +0200 (CEST)
Received: by mail-yw1-xc3a.google.com with SMTP id r64sf1816662ywb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Sep 2019 06:07:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569589658; cv=pass;
        d=google.com; s=arc-20160816;
        b=y347gvsMtSfZaIkelbSpmPB2TCIKcCUmJ5sN8fUABBY3fOvHdIAH83GIxVODi+zPP7
         LWTXaAyzfX1exokt4JCg/lR0b3la9/GSyICCWPjQJnlxkx0VdYlOIXNYuS8MUrs5WYvu
         9GPR84ozs4YCdj6AT6vH/3BySh/2DB5FG21EioYKx3YMxxjYLp3Q01WLBHXGBoMUfA3I
         gHCRD0M/6rRt4EN5B3HJy5GBhBctLQ1oj0hWvlTSS6dsO7TJ6HQbRq5CDhrolE3HKTKK
         v5ht2Goo1gARjqyubnv9kUBzi785Ovov303yD9jf9daUeHsbGHXTRDn2nIOvLmc8ZpHY
         4Atw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gJBKkAfhIjDUKCY9p36nQ+VMB0V9ivoKwSLTs2vl0RI=;
        b=I6nE6xoK6vC5ZqOsS+Wf+VkrZ996QSSxNEvxkvoJa/yjWssnzWhncNdbXOrLB2ypXj
         EwjCNBm28LKJzgfdcycPkEdCxTCI0Jh2v16V9Xv8kcIOlUh+65LIq78AG8NngCaMa/IU
         qg8ozCT7DCKdQEuNL5U5AJKCcfUzTrr8A61UCZ+i+PDfxyoFECnqmPvQe8IVaQdhVX7A
         ts+Z5tSj49GI5VHLHqcMk+BLIJE0mlSFVSKAzd3SZNBgRfPAJAcFoa4hz+nr5MYWS7DM
         wrVglKASwinYf/z5QAkMRmG+GlwbZd6RcE+vfALBkmlAmuiomP5ggMBN37ryuPdxHfNl
         DB8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eCGU90/x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJBKkAfhIjDUKCY9p36nQ+VMB0V9ivoKwSLTs2vl0RI=;
        b=FLP8w8eeDnkM36ZEZPPCVz+IthU9kdcEDQ/W/y2ChdwEGJ8sf+gCwxHuINsOP6RDNt
         MM9jwHdk5fOeZQ6NgykPnqpkAOiJa5+oxKf66vlaAwux3PiviXQ9nMKlEH3Bu5eeQC++
         1YoK6GaRzzhZ9Q0q8jgMZC9bIfM8WRY9lzOpv+dvf33Z3rwLx4aLM5abX4FkPEjfRJsL
         +QUfwG2AUMQm1AQvyN3bLoj61cd1VEvcF8ZtNPcvOUWWXXdubxZnPL7aIa4wLjcYC/ni
         Wuzm8xkaZsMnXjPhXv1aIHTDnhhZn9vRsMXAwHYkYuIkgJZBs5vCZ3aKaGQYhO5NPHGU
         HOrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJBKkAfhIjDUKCY9p36nQ+VMB0V9ivoKwSLTs2vl0RI=;
        b=iEy8v3feKzN7F4yERKALtV3GOMRrKPWU1wt6Z8FxMcSCALs6nVVkNge+bYu3K4zBNb
         4ZkiQoif3EAQNLwhZPfKW8fDaivmX6NVT6vgkf3eMMlC1hSB8KJFqUixPLas61yX7a15
         M1Rzo94xq/h4H4RIe/Jvh0ESoPmhDLwkVWAqEioIGBkeOPqA+ELglXnBoZyTXaNmWRok
         uljyY3sLGUu3P9d2rtUM3Kuc0NmZ7upf7WnagLrjhrg5T+2YBb/lb6PsZr3tJcA7lxXi
         0JHWRZKSaHP2jfch4OGrn+1iznIUxdWt0a++KB62Dq0Z4D3MDID+iSFTBOmWklsWgEoi
         gArg==
X-Gm-Message-State: APjAAAWkCvOn63VHJbHcmbchV2VbQ8+sJ2VnNt/PA6Nc0Hc+c9a3OkXq
	vQnmo5MqZBrB26UKioL3kOk=
X-Google-Smtp-Source: APXvYqzod+Plz6JOwfzEBRPioEKXkal3mlAfr1u7WO3LRK3Pv/IuPFLN/otB3+x1+rlaT3VnqhYozg==
X-Received: by 2002:a25:4e8a:: with SMTP id c132mr5538620ybb.116.1569589658737;
        Fri, 27 Sep 2019 06:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:48ca:: with SMTP id v193ls399596ywa.12.gmail; Fri, 27
 Sep 2019 06:07:38 -0700 (PDT)
X-Received: by 2002:a81:2e4d:: with SMTP id u74mr2682697ywu.12.1569589658379;
        Fri, 27 Sep 2019 06:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569589658; cv=none;
        d=google.com; s=arc-20160816;
        b=kMfrxYh+mzmJn5SQdCcIUI8mbtkKwque0phGt0CCmFeP06L2zLSEmEsZf9pCl7SIbD
         68OUdynY2xg4B+RNrdeREDmLhK3T4+gpyu45K7aP8ooRZdOp15VW3B4U48Xg/LUHKJ3O
         jFywOSQNLEaOc69A37MSzS+DNBB9eGqRsYfGX4UGhTI0HjcnOp6hCWmVgNH9r3AFcLd4
         jAtD+1qQXs2nQVToWI427nR0ZwUyGgr3WaMpJ6eV2D/hL+Ke4twK1xk+Csxd9bMlwPF6
         xieBDmMzl1rarQ3+GWWUbIBLgtmzqLkISdbdNqjeUNXUa1G7LAAipcAstW+mE3KPujm2
         0iQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KFGrykQPVrfrF/RCxAyujZ2hxx3LnFuQxZYE85jjQVw=;
        b=eR/iZoJ8WmLogSPdTip1VfIHDhDBCqJ/cssuJKO0UF2rwcg60VEeAYCUTJ8oTaGUCw
         hwdpNLXh+uHyZezV6XSGkdYcIpPguaXcDwuuKmdjCANp2KSAaM29jful+gjZYcnu0mG5
         ZmwoCCVv6ckxK9KMLXGzB79jkd+TkdIavHWAaEGVVVm38DLSVC16+cjwepwS6N2bEN9N
         KV8Q6aRZNVja/A94AFnv154uuwakgOe3YbUMHw0dZfpkTFQDmluoXDeopSFmlcWk4afv
         IuxBGXGDvdX5hrHPisZQe2QauyLpxJkF+fTn3XFywPpbhmNycUCsjOV4opjV9BT5LlEl
         3nqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eCGU90/x";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id w13si267341ybe.4.2019.09.27.06.07.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Sep 2019 06:07:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id w2so1886647qkf.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Sep 2019 06:07:38 -0700 (PDT)
X-Received: by 2002:a37:9202:: with SMTP id u2mr4399020qkd.8.1569589657502;
 Fri, 27 Sep 2019 06:07:37 -0700 (PDT)
MIME-Version: 1.0
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Sep 2019 15:07:25 +0200
Message-ID: <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b="eCGU90/x";       spf=pass
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

On Fri, Sep 27, 2019 at 5:43 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> memmove() and memcpy() have missing underflow issues.
> When -7 <= size < 0, then KASAN will miss to catch the underflow issue.
> It looks like shadow start address and shadow end address is the same,
> so it does not actually check anything.
>
> The following test is indeed not caught by KASAN:
>
>         char *p = kmalloc(64, GFP_KERNEL);
>         memset((char *)p, 0, 64);
>         memmove((char *)p, (char *)p + 4, -2);
>         kfree((char*)p);
>
> It should be checked here:
>
> void *memmove(void *dest, const void *src, size_t len)
> {
>         check_memory_region((unsigned long)src, len, false, _RET_IP_);
>         check_memory_region((unsigned long)dest, len, true, _RET_IP_);
>
>         return __memmove(dest, src, len);
> }
>
> We fix the shadow end address which is calculated, then generic KASAN
> get the right shadow end address and detect this underflow issue.
>
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  lib/test_kasan.c   | 36 ++++++++++++++++++++++++++++++++++++
>  mm/kasan/generic.c |  8 ++++++--
>  2 files changed, 42 insertions(+), 2 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b63b367a94e8..8bd014852556 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -280,6 +280,40 @@ static noinline void __init kmalloc_oob_in_memset(void)
>         kfree(ptr);
>  }
>
> +static noinline void __init kmalloc_oob_in_memmove_underflow(void)
> +{
> +       char *ptr;
> +       size_t size = 64;
> +
> +       pr_info("underflow out-of-bounds in memmove\n");
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
> +static noinline void __init kmalloc_oob_in_memmove_overflow(void)
> +{
> +       char *ptr;
> +       size_t size = 64;
> +
> +       pr_info("overflow out-of-bounds in memmove\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       memset((char *)ptr, 0, 64);
> +       memmove((char *)ptr + size, (char *)ptr, 2);
> +       kfree(ptr);
> +}
> +
>  static noinline void __init kmalloc_uaf(void)
>  {
>         char *ptr;
> @@ -734,6 +768,8 @@ static int __init kmalloc_tests_init(void)
>         kmalloc_oob_memset_4();
>         kmalloc_oob_memset_8();
>         kmalloc_oob_memset_16();
> +       kmalloc_oob_in_memmove_underflow();
> +       kmalloc_oob_in_memmove_overflow();
>         kmalloc_uaf();
>         kmalloc_uaf_memset();
>         kmalloc_uaf2();
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 616f9dd82d12..34ca23d59e67 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -131,9 +131,13 @@ static __always_inline bool memory_is_poisoned_n(unsigned long addr,
>                                                 size_t size)
>  {
>         unsigned long ret;
> +       void *shadow_start = kasan_mem_to_shadow((void *)addr);
> +       void *shadow_end = kasan_mem_to_shadow((void *)addr + size - 1) + 1;
>
> -       ret = memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
> -                       kasan_mem_to_shadow((void *)addr + size - 1) + 1);
> +       if ((long)size < 0)
> +               shadow_end = kasan_mem_to_shadow((void *)addr + size);

Hi Walter,

Thanks for working on this.

If size<0, does it make sense to continue at all? We will still check
1PB of shadow memory? What happens when we pass such huge range to
memory_is_nonzero?
Perhaps it's better to produce an error and bail out immediately if size<0?
Also, what's the failure mode of the tests? Didn't they badly corrupt
memory? We tried to keep tests such that they produce the KASAN
reports, but don't badly corrupt memory b/c/ we need to run all of
them.




> +       ret = memory_is_nonzero(shadow_start, shadow_end);
>
>         if (unlikely(ret)) {
>                 unsigned long last_byte = addr + size - 1;
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190927034338.15813-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZxz%2BR%3DqQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw%40mail.gmail.com.
