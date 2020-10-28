Return-Path: <kasan-dev+bncBCMIZB7QWENRB7VA4X6AKGQE7D5NQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 78F3F29CF9E
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:05:35 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id f9sf2520184qkg.13
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:05:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603883134; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZQaavX+oGiKLH3gL+Ce5ilbcBGO6tQ2JPj11GOftd19+csCxYvY5NLBRvUftVFtQnv
         m5bSpKR7pS05lL0Ohd1sQvpwBuijjeYeg3xf1kTT1rF91OIuHYaKV4AiiJnHYXlhw/0V
         qrxbbQZbzdcsCoXBkuMySBYPlctKIquM9DgPP7wZtSLEMGUOWcLlg3Scn0kCWX+y/Zle
         u+tf/WytrRsA/Hcr2LbJqJwu8VnVrVjAj8aaSHkq5Bkcp2jGgiO9uXz6hQ31TfU8OLUg
         iOpSgYSDhnVEnqx6g/APzlXDh2Aafaa6HN5CSLdtizoHXrPCxQTWgl59TaN9Yw0nn0TO
         zNcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+fgyJhCc8bN+BOc/cc16M3+PT6K5VyAqOz/1hZ7a2xc=;
        b=DWezxOI/ixRyYA+py/sB+27Z3xe51u9yTI2v29qVE1aO173qv77sm/2UKZ5amug2Gm
         Ap8ABV9h6kVM9YcrispE3edGfCG3l9QilOxp80R/M77T4KCstH87R+ABe6Wo8qBUAogy
         NRrKYq6LOlVcWwL3Nig6/Ns9pXvi0uKK1CsLGJg80xS8QAM8cC4dwbriGoWo/OwqW9Lq
         J+zNpv8LYiL9I8359FD8umLCvvBRvlbB7AOPzHCHUHIQulWj73ZiYmsbvw3FZg1QmU8L
         bha1mgUV988eiy8IMUIdp/8jXj4RnpOq3pMcLFf2CSxS24cwU+xpW7PZZ/JYKT6myQNZ
         hm9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h3qRf1hh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+fgyJhCc8bN+BOc/cc16M3+PT6K5VyAqOz/1hZ7a2xc=;
        b=pPHs8Ue34AUSNcUwVUcf5Yt/Ev+x07IOCvGen8UVeKwfuonniMj2yvjgrsw0Z9QjrX
         roeYyG5dJUTqMruSgIF132Tov6XUmvNI+4w/Htb9zhumkxyjqsjTJYCSMCnqgq7M08Kr
         CaajdO4Fw5I3llEueShReqSqVQDq1X82IFcfOuAuQfCFxGaDlWgST4nmC/OlBiiKznfK
         m+FGifmZuTiteFd4qCRRyQRuhj18BWZyoNtyRLgkaNLH8XVYqcwpfAqfjhC376MDM0Gs
         qofUOEGlovhwFL/+D4IjqnlaVJzMZ2r5CaE6Wo53ePeQL6DiGjkyOA1bTzua8FCBjXTr
         9R5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+fgyJhCc8bN+BOc/cc16M3+PT6K5VyAqOz/1hZ7a2xc=;
        b=kHQ91/wA6qy3PXh3AgGBHdnJcRU1NKzaQbPppGTPa0Mxv9L2KjYA7D8ik8FOY66MUV
         tbrH1uapXZHXkctcZFfTo7auHEZMI2GNGxR5QxyYFKiviUkCMKKaVJslSmb15zNTB4Rh
         yYIxLzRFOyoE9/edIejov4j4n/44BBH7f2ojC6JnmmgMvcW66EUJEQZkowzzwtqJ/0s3
         7bNV0Krzv8DLt4QHdu62CMqYGDoV5K/gWI/lb+v2KUu7FDex6wiBnOhUCWPh9vkjy0Iq
         u0Z7myjti6VAcsVax/WMfIHK+T8c8nUnJMdr4vjRnIC+uA7lNZhJmuhXtqpcUpYh+jpv
         f4JQ==
X-Gm-Message-State: AOAM532uyiKO3qdk61buKcW6o5d4BtsGJWFXAy6+Jk24coUA0oYkUEah
	BjGINCbjjlcYjqGUMyjstXg=
X-Google-Smtp-Source: ABdhPJz/qPugGIT3M5Xr87ikaNUX3cTr8N7S44Zv4Wewq8Kykjc7kswuiG54/HqP6iohqM2rt0JhoA==
X-Received: by 2002:aed:2984:: with SMTP id o4mr29317qtd.194.1603883134296;
        Wed, 28 Oct 2020 04:05:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aad6:: with SMTP id g22ls223859qvb.10.gmail; Wed, 28 Oct
 2020 04:05:33 -0700 (PDT)
X-Received: by 2002:ad4:4b2a:: with SMTP id s10mr7230420qvw.54.1603883133808;
        Wed, 28 Oct 2020 04:05:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603883133; cv=none;
        d=google.com; s=arc-20160816;
        b=KdcaPtni0gr1nMprbPLA65bYXuXaDlVq8axPkswKTah2RxsTadc2NgfsQkM7rru7Vq
         gVYDW7ngagtfA0Sqw5S2ozFxGWVhfrFbSIfo/IxdaeHlsSBN2pQXy9XeJpj7eqpUS+Iu
         j97vTcq1cEN7i87gQdsOrTSTt6oyKpZyBWeUAY/kleNP4WO5dbTcAk/rWqYPaBPUciQj
         Rl7N37CNN33cAPv+kPigr81pd9NP88QS6wttzA5A4OQRs5gkWcq1QJcLK1l4lmyoOL9k
         ZCs8qAgmpDKtlMZddnLi+01S+7KPUUXwcz3Gk9XxeoxKZLdxr+dDDFVP3lyPB3Ys2nDP
         Am5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BnTFjO5iPodWJwaiH+f8UvOorIZZfBBlIOwtDZT/AaY=;
        b=TaJUTaSGRBsrk3SOMU0nRa5EqFhSIlb0gJX9bH5TBp4i3xkFNJ4+39MqjVCeKnSmfb
         wLyuBeBSgpACG/v6/4blbawrHwonxwV5uxQEIebYhiMNACFz45BbxDuI8HIRVcDzPXLr
         rBdtdOdfYWghv+tzFaDvmu8xoSBJcUIDB0/ksOnWu3U3L0hvYVWa/K+nKAcs1H+AxGg1
         KUHqzoMhhX7TP6mQ6UDQZfraNmTQeTUZU4k3LiH1Nde1SEco+n8QFCqssBKNCEZZe21X
         VBIHDU7c+B84gyO+Kt5nFowEwkd7vxY9sMe8J0ZJBbw7dB0mgNNcgmAQh2Ip+N+jVX/V
         OYDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h3qRf1hh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id o11si245819qtq.5.2020.10.28.04.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:05:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 140so4067460qko.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:05:33 -0700 (PDT)
X-Received: by 2002:a37:a00c:: with SMTP id j12mr834383qke.231.1603883132900;
 Wed, 28 Oct 2020 04:05:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <b75b7fe2842e916f5e39ac5355c29ae38a2c5e0a.1603372719.git.andreyknvl@google.com>
In-Reply-To: <b75b7fe2842e916f5e39ac5355c29ae38a2c5e0a.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:05:21 +0100
Message-ID: <CACT4Y+YcQH2mKv3y15XkWa-tKvyhRQHAw5dLVoAkFRWgFMLq1w@mail.gmail.com>
Subject: Re: [PATCH RFC v2 09/21] kasan: inline kasan_reset_tag for tag-based modes
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
 header.i=@google.com header.s=20161025 header.b=h3qRf1hh;       spf=pass
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
> Using kasan_reset_tag() currently results in a function call. As it's
> called quite often from the allocator code this leads to a noticeable
> slowdown. Move it to include/linux/kasan.h and turn it into a static
> inline function.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
> ---
>  include/linux/kasan.h | 5 ++++-
>  mm/kasan/hw_tags.c    | 5 -----
>  mm/kasan/kasan.h      | 6 ++----
>  mm/kasan/sw_tags.c    | 5 -----
>  4 files changed, 6 insertions(+), 15 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 93d9834b7122..6377d7d3a951 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -187,7 +187,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>
>  void __init kasan_init_tags(void);
>
> -void *kasan_reset_tag(const void *addr);
> +static inline void *kasan_reset_tag(const void *addr)
> +{
> +       return (void *)arch_kasan_reset_tag(addr);

It seems that all implementations already return (void *), so the cast
is not needed.

> +}
>
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index b372421258c8..c3a0e83b5e7a 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -24,11 +24,6 @@ void __init kasan_init_tags(void)
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> -void *kasan_reset_tag(const void *addr)
> -{
> -       return reset_tag(addr);
> -}
> -
>  void kasan_poison_memory(const void *address, size_t size, u8 value)
>  {
>         set_mem_tag_range(reset_tag(address),
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 456b264e5124..0ccbb3c4c519 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -246,15 +246,13 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>         return addr;
>  }
>  #endif
> -#ifndef arch_kasan_reset_tag
> -#define arch_kasan_reset_tag(addr)     ((void *)(addr))
> -#endif
>  #ifndef arch_kasan_get_tag
>  #define arch_kasan_get_tag(addr)       0
>  #endif
>
> +/* kasan_reset_tag() defined in include/linux/kasan.h. */
> +#define reset_tag(addr)                ((void *)kasan_reset_tag(addr))

The cast is not needed.

I would also now remove reset_tag entirely by replacing it with
kasan_reset_tag. Having 2 names for the same thing does not add
clarity.


>  #define set_tag(addr, tag)     ((void *)arch_kasan_set_tag((addr), (tag)))
> -#define reset_tag(addr)                ((void *)arch_kasan_reset_tag(addr))
>  #define get_tag(addr)          arch_kasan_get_tag(addr)
>
>  #ifndef arch_init_tags
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 099af6dc8f7e..4db41f274702 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -67,11 +67,6 @@ u8 random_tag(void)
>         return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>
> -void *kasan_reset_tag(const void *addr)
> -{
> -       return reset_tag(addr);
> -}
> -
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip)
>  {
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYcQH2mKv3y15XkWa-tKvyhRQHAw5dLVoAkFRWgFMLq1w%40mail.gmail.com.
