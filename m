Return-Path: <kasan-dev+bncBCMIZB7QWENRB5NK4D6AKGQE5EN7MBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id A725629AC50
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:41:26 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id n62sf612415oig.9
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802485; cv=pass;
        d=google.com; s=arc-20160816;
        b=hPehFq6VXj47it74hS2Ii/XrqlzC4il8dyf7McmQKXJEY1n/zK5+1fpypZnBatuEmc
         s/KknHKwfNeGG25faglnpVnApLPBj8Ec8ZjwQPoqGG+hLdehPvdg6ngDfZi9vlgt16Su
         vf8RMgy2H3ZcJC3sGFZLZvwqLzZ+VDmU4+vMRPosttvZ0IS0v9OwMV3cjSJx5th1nZ9v
         uNodB/OKb1VYRMSDWjne9L4Q89hZKBKyyyD17p2fWkNV4L1hy64E7XxplTLxnLmJsaZ2
         LCm/SuHae5euVsb+9rJ5I94TTl86yYtRVmzr8Fs/EOiedk8/2qzA24gcKKM0ghZs/UsH
         nrjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TDPcG+nSehrwptzAAw2drT6ZUuwAfEwRl0w5DAOJMlg=;
        b=Xeqovd21mpmz5o0VfvleEZtWntgDL8k5l7aGyYVCZEShU3Z5FpAPypusr7QqRJJf5q
         UqiyIXsn6hN/XlVeSXeLiMkaE2wNF1CPQwsgXDlaO8440Oxx6W8lzok4rlKatxvNVfK9
         S2NrFd+u7wDknde+sK+DqUCRCv+fGR2qRQJFjoG0TOekM0uD669S/NFjTxwQ8mOCjPxg
         Cq3mDDLchpZOHIZ7id4RQTjeWYDZI4+BhZvmX71aT/my3HWK05vVzEjPiSbi33uksbOB
         Gmk19D10YuVBuQM3V+a4ywX3bl+jSY6cXGc3BADzL95ZHSGr0VPKjjYZWmg9KWsrIyeC
         oQhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UMOH9tN9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TDPcG+nSehrwptzAAw2drT6ZUuwAfEwRl0w5DAOJMlg=;
        b=B+gfF+gjVg0g+9KMQF78bU8JqxanrpZPOBasOrpSQqsmEua7inObzaWjYUf3p4W2Zm
         TamkRcbuXpIZL0kgvMePiJAmOdxSktfSLYmrduaTerFYkN0E4JDFx1/NrApsSgPfWqVD
         bxC9/ICuaOem3mQ93A2Ypw/nSKPLS4n2hzfGPUk1kDGPemK7neSzPFXalpskSaMJPgnf
         TTr64I8hGiZBt0ACljLQ/IJXkO6cXL/xlyWyX/2cjBvOmF9M2Hbf/Iv+CiT6Tft3JY9X
         9b1hbSeJS4Mb8VsbhO2RHEXhs/rvziUCJnHuYVVKZD64XlCXbuhb198cbaVmVKLFTPiz
         gUZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TDPcG+nSehrwptzAAw2drT6ZUuwAfEwRl0w5DAOJMlg=;
        b=sl+GCTrgwgjzisRGsk8C0nhwPVvd0Dz2vtnuVn/D7dMr08eh555X7TBYUNq1ngfadv
         jria9gFukgHToxYIITdJfvJ/ApQU3U+ZTcsTKWdjt29T/G4QLUSwG6jJ8VLioZWTxnDB
         9yoy/qOr/vVjR48oXm4PL6VYsbSONaswQ6FHFkPYEvqLPIBSRD8Cv/Uu/6wy3pZ6rOM1
         IladCQT9kSGi27lRnDHGH/N5lCHJzvrEoRdhtQd9zeKSpIN5JGwtKOaZzpkOBcNlXj9m
         eGoVfpAU+7X86pEvemyTmwsQomKTJkpv65f6RD4aMSOy0p57OuLeV3s4iNAZjSpH1N8i
         J/Jg==
X-Gm-Message-State: AOAM533jvzFEbIV4do4SdmuOy9MVy5wJxnivG2D5A0XJsoSlD/lbM29C
	i7ULMIqQCTczRHSijzFAaiI=
X-Google-Smtp-Source: ABdhPJy+w6vr3cCO9eawiUKZ37Rl7Inf2T30Q4GvzymsO35WuuwW+T9hxTRSAxuJqnrAfp+ehiENiw==
X-Received: by 2002:a05:6830:451:: with SMTP id d17mr1261680otc.294.1603802485419;
        Tue, 27 Oct 2020 05:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:c193:: with SMTP id w19ls104605oop.9.gmail; Tue, 27 Oct
 2020 05:41:25 -0700 (PDT)
X-Received: by 2002:a4a:bc92:: with SMTP id m18mr1642009oop.39.1603802485037;
        Tue, 27 Oct 2020 05:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802485; cv=none;
        d=google.com; s=arc-20160816;
        b=UBEXff5HIwCXZARdkUgkU0FP1Q6zGPKPg8Qt0r5TiOqXtA8jAExjtMQ+x5H1Tveqi9
         haSL0kzgEyjfOv7KJnuWqYSQC3lhgKN+Dsw1lltVrTc5p0fe2kvsFNTpo04zzmZNuJLN
         g2I+WlvDhUI83z++9Aa19PF8/NBQDERpKNbzniZeZuu/xLzUZGRCO3jpSi5faYjEMQzk
         Oum2FvR7t+n8bzv/zmEfzJ5/Eut8SQfwsSu9IIB2QN8gTpw6Z+Fb9ukOZc0qxIVryC19
         jQv3e+NiL+RqpXXH1yOGzORO0EUNBv2BhtZelw87liRvOf/3IdOJBHH+sHun5SMc0KUX
         3m+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0WSVQEGSlOmtaeUZ3M4C4CAr2aYtzYDFb3Hz1iLTMF8=;
        b=CRsoUJ3TXZAk97FYnR+N4immgKy4LLsYKT7AWRhsZDgNnsLrNn1m/aaIiWWWdlzNhy
         ZdIepK1X9oeJZMJCtJIEVgcf+rsu8S0pVAz3rFAtnWu0zYMJK32g6XDa2Xh0UP8XVWUc
         whr/TiOlM+RcytGroityNhAOfH0CUl1vue0KYBtSDDl84q5aH4WfbFMN7pN4PFl7Vj5o
         0WFH45k9dUcz+79sunPvJZnwhJ5jUGNuwlZJmQyYHdYGgtVLcba+2nsa8pQ4WVg+kJFk
         +3cMCXJfcyhwkalqrd5dk9JQXn9tpKquqfvuL+ty5eTw5ghWR94mUgJ4VEzi8YdJjiaK
         4SCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UMOH9tN9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d20si138308oti.1.2020.10.27.05.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id r7so940402qkf.3
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:41:25 -0700 (PDT)
X-Received: by 2002:a05:620a:1657:: with SMTP id c23mr1940261qko.231.1603802484307;
 Tue, 27 Oct 2020 05:41:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <595f9936a80b62ab89b884d71e904eaa884a96c2.1603372719.git.andreyknvl@google.com>
In-Reply-To: <595f9936a80b62ab89b884d71e904eaa884a96c2.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:41:13 +0100
Message-ID: <CACT4Y+aLbptEajrccpMrMPAPivmm0DHXgpV-Jt=h-axjqx6BcA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 03/21] kasan: introduce set_alloc_info
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
 header.i=@google.com header.s=20161025 header.b=UMOH9tN9;       spf=pass
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add set_alloc_info() helper and move kasan_set_track() into it. This will
> simplify the code for one of the upcoming changes.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8fd04415d8f4..a880e5a547ed 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>         return __kasan_slab_free(cache, object, ip, true);
>  }
>
> +static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> +{
> +       kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> +}
> +
>  static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                                 size_t size, gfp_t flags, bool keep_tag)
>  {
> @@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>                 KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
> -               kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> +               set_alloc_info(cache, (void *)object, flags);
>
>         return set_tag(object, tag);
>  }
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaLbptEajrccpMrMPAPivmm0DHXgpV-Jt%3Dh-axjqx6BcA%40mail.gmail.com.
