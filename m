Return-Path: <kasan-dev+bncBCMIZB7QWENRBCOG436AKGQE4RBTFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C9E229D12B
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 17:57:47 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id l188sf2829333pfl.23
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 09:57:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904265; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYjE0DWTWZy0aOnuer81Bw4asAyzy/Y3U3brgklNUF2YS63MNu/Y0zwvzPvCC0jtK3
         KlL1xGOe80OX5bj+ncpZwj1Lj+4uCk3Y7uoKpZJa9XmP3665Rt5hS5kp95NB6lUFpoKT
         AUpYRJLewRMxpBzn2kIdkamhSBt4osM3WMBBXJzBvvmsztWf98zA05Tu7UOLjVjITyEU
         QQFutCfWWqgCanAytI4WpAf4frDa42C548Nlcpthkb6wIzgwW3Wq9rQwuFi+zvEOxyiA
         /XSf9PG5iHFdcgT+VIA2jcJciDDn/UX3WkwkqnhnlTGLxc7kEhmD9Qs8MzZXHDps9zpR
         c7wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MwytI9l3rbVsaG1VkjYbnDtDRkZuOw9qfbb6vtgLC2U=;
        b=fkEkDIpcqaIUjaPP4TfCgogiouO8/LAnRIfz1OCqNW5aJxIHEU0pLYKeCnJviTkOVs
         Whebzvm+QGIDLNEwihWaDqkG7q1G4yR0d8y/DZZKC6XWNAaCnMKPrs+kQgsBC7zyxpC1
         v4maDv2R6LL4tkoUk4FhGpTvqQfBtqJR9eYO4A+PG4qHkJY/74wDYIIXo4S5ZA7vk1vR
         //Jd9gkLHXR/XpGAmHYX2Cgl6+t1OOBVuM3Bk1zgNs30+tZ+Kh40RkuNdq84qszT4nEq
         IUhUyFdhE3dqNlIgyG5mGtq/wTVGDxar+d1d3yO2O0PWG17H5ziw0hUVIz/vB6W4YYl4
         Qqrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eWofOYiP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MwytI9l3rbVsaG1VkjYbnDtDRkZuOw9qfbb6vtgLC2U=;
        b=d7NxIPq2sPs4a6Vkl8R0lrbvE8HfQBQlQsRQn6iSs5uNZ3wdDGLnRqAYhf/kQn+4Rs
         QCaE2dIfMcmak+qAq3qMh7slBgl0avzyT/u9ienvEO7g0yIoQL9FmtQOfkxLYfDUafLS
         HG4b3khJMVemSQfZHli4NdAVltYyVdzqMgeJxMGeVvttl/dfw9f5zy5FYNTA+RS45dx5
         AElps8V6XIzY6bJHSUS6/DMwC+AwwzEClo8yqXCZg6KMb762MK2d+UKYb3n1mY1pOrMm
         d66Ka24ujSxgo6oNgtv4aL96leZg3BY1lVX1nJ7t/bRx9zlDaw267Vx92nI30PKTZ9lv
         ElUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MwytI9l3rbVsaG1VkjYbnDtDRkZuOw9qfbb6vtgLC2U=;
        b=Mga06+jcGt9W9ByAjIs4YvJRwVcqGk0HpJxRAwqgmz6jdsVUkUJ3TdWf2Pq/McyRvF
         LdGObFGrK4g9ph2WAogTVZVUtjnCjqiud2lXCu5mKUYqzuD8JYye7VOKW1aSJdRGk0+3
         SNBCRolLWiLxjQvBOKGfpJfq26sdSA3jq50Q7lRQhtMi+/nq/5txKE3n572UTtLVEbb6
         2tvwUa1JOjPBarJtvY2RH7JouHe5mvPD45Hvl1T+JwkIoHILIQRqAaNqS35t6Geycv0+
         x1Sh7L0Rs3JonHBQ0tSr3JOnABSj5xp2CYl4NduVRGM35VQjUiz766cgjLf7F4/KTtZ3
         RaEQ==
X-Gm-Message-State: AOAM5302kVWAelm1YYwRoqnpwqETMLdx2kQRLf2X/YslhHQa5iAAV9rx
	StJqMefKRoyao3fPYgiJxLU=
X-Google-Smtp-Source: ABdhPJxPFVOUYvEfVbXzMYBH2luH6zhq2bQuqqvZFZPxCNTqCyfyucvhihsHT/BWLbwcTTM/yYqAaA==
X-Received: by 2002:a63:4661:: with SMTP id v33mr278351pgk.163.1603904265226;
        Wed, 28 Oct 2020 09:57:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d88:: with SMTP id t8ls78343pji.2.canary-gmail;
 Wed, 28 Oct 2020 09:57:44 -0700 (PDT)
X-Received: by 2002:a17:902:d686:b029:d6:5192:345b with SMTP id v6-20020a170902d686b02900d65192345bmr17889ply.66.1603904264664;
        Wed, 28 Oct 2020 09:57:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904264; cv=none;
        d=google.com; s=arc-20160816;
        b=PKvKSEmCX3TefStCaYzcugWjEiAH1+7s9L1moscW3pjB5RJpSpsZEG4lGSKMXtW6JR
         8qrSD2iMztk7nwsSJXZjlcaCBk83fwk+Jj2NIQquCFrNHfL2dA/NBtqssmYUm5Fk6BFx
         n/B+sf7qULmlTE1TYJpDh5O5P94tiVAIpJpqhmjujFBQeufUuURmt0FdeaA/VVq+qxc6
         3Pph5xqsXMOvuv7iWlYdaEKbrJqx6v8werp4RPhgPanA1MvPskdaxJeglwSrGScDfBfi
         jLjuVKBuaQI4fpT7VIB+xtuBDABEhBhQWtFlkh5XuNAG4R1Zsbml8O03z/c4TB8glhGM
         gtAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Zxgi7xd3nW4FDFVux6haRrdrCJvaqFEyqWtMMDIWgYY=;
        b=remtl6KuapSBVtUssbhhuUSAyYO4ZpfFcz/jLhMyDBpT9PrOQG2/hbOanYqv3tVaRy
         nxcA8S9NBMBv5SToXwNIqyCHhnCnQcYTOPRQPNSdlh9UmzN+E+VRdQgwzZjW2y2BEFMv
         UdnYQrvViGgBUIaCzrWd2Hs4+Cjr6AY5hVaNTh3RcZ5O37paM8nRTfBYWR3cJxeevWXS
         Ff9ultmV3Yj09LdcIoKpULON4kF89qCwczdEYxStQugcmVZpW+UE9g4mAY9al2PvyS4Z
         62MIoHGEkbG7yWxSzCPJjP0tl/fD7/DL3XN9bVREr5MatXwbp3dZMG7fYQYfpczw3RZv
         0TMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eWofOYiP;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id x6si3490pjn.2.2020.10.28.09.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 09:57:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id p3so2083269qkk.7
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 09:57:44 -0700 (PDT)
X-Received: by 2002:a37:7b44:: with SMTP id w65mr8409031qkc.350.1603904264037;
 Wed, 28 Oct 2020 09:57:44 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <f7b6b3b784e80d3ff82012295503def6164be657.1603372719.git.andreyknvl@google.com>
In-Reply-To: <f7b6b3b784e80d3ff82012295503def6164be657.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 17:57:33 +0100
Message-ID: <CACT4Y+bk9n6+v5dkcm8ngxQ=HbK9jS2N1nCm3F1vQLSxBiiTSA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 17/21] kasan: simplify kasan_poison_kfree
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eWofOYiP;       spf=pass
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> kasan_poison_kfree() is currently only called for mempool allocations
> that are backed by either kmem_cache_alloc() or kmalloc(). Therefore, the
> page passed to kasan_poison_kfree() is always PageSlab() and there's no
> need to do the check.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If31f88726745da8744c6bea96fb32584e6c2778c

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 11 +----------
>  1 file changed, 1 insertion(+), 10 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a581937c2a44..b82dbae0c5d6 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -441,16 +441,7 @@ void __kasan_poison_kfree(void *ptr, unsigned long ip)
>         struct page *page;
>
>         page = virt_to_head_page(ptr);
> -
> -       if (unlikely(!PageSlab(page))) {
> -               if (ptr != page_address(page)) {
> -                       kasan_report_invalid_free(ptr, ip);
> -                       return;
> -               }
> -               kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
> -       } else {
> -               ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> -       }
> +       ____kasan_slab_free(page->slab_cache, ptr, ip, false);
>  }
>
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbk9n6%2Bv5dkcm8ngxQ%3DHbK9jS2N1nCm3F1vQLSxBiiTSA%40mail.gmail.com.
