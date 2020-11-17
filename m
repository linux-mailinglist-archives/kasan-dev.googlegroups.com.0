Return-Path: <kasan-dev+bncBCMIZB7QWENRBU46Z76QKGQE34LCQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 328D02B6216
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 14:25:40 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id x28sf8190508oog.8
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 05:25:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605619539; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVuTsdVlXLiHASh72R1k9V32I0mwFiUPcclwxBPaoV2+33M6Z3yV1juTKbgLP0PBR3
         H47viMjIbFnZBIDbuNgjXINZRZP6bOy7g4+sf4RWPuPq7RdD7OWD+jJyIOe1PYLLGoR7
         1FGVC0PeQw5Az/pQj3p2zB5ko73eBL3sumbJkormwonsYKBR7pHBMTxWNk8GWHpiqayQ
         ib8z9FngpTCFfXJWzJ1jIXX5m0lHNenSaHdSKg2qsZuTLJ6wMZn/jwD3thvLmFxwCSSS
         BECBS9/wC2tbqpf8hkQH7Vg5FMp7Tpjyn/qreijERvnmwniXM7tqRw65bn+lbUo4evrH
         v8Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Su+jEOwF90KBefherA9q1oLvQ0tk48nn09/8XM0Hw5k=;
        b=KAcPfSIrBJchGSDvv90NbJnqNLSm4sLftFsL97+aXzmk5R5pN+jUmDAHl6ryizagX2
         L+NdaCnBPV1/ZGHUu8rmDKT9CT2Fi/aPh3lLF7s4NGoPvcgPJAFaWDHeSBjsjiMxL6pG
         aOS7kreUVKiWC0VvRWwnRYnp9J8vSXJXvVewE098KwhxYQvtRzGjCqKP2MYKoAFFUutK
         98eHSqaAGHfrMdu7/xNrTdLrhjrflTvWc6ysQrx2zVw62WgQzHVNCGNEL3bQXgsUFmrb
         z6vbixBu0TuPuVPB4E7b1sEqlaq+BVbuN6j1kr5OAOkhBuk5NTOoXY9AQk/y6jxGakZK
         OsWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ws9G6B7b;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Su+jEOwF90KBefherA9q1oLvQ0tk48nn09/8XM0Hw5k=;
        b=QYGUR+qqNsI8PGbzo83mTkLifJUFUvvuikOPzK6dmA0lEDpAc1nutwgGWhfYVpMoWV
         7GAkuhY3fUUmeKnnHGpWn7fQ7mXF5DHXx2h/kSdQkQegwyYb1fIJ51K7XWAneXYjniSe
         imIxHDpjXKwYas9GWBxWWk6GRRcgC5M7nP857G5NLTxycpuiOxOqGmhqwTGWbgMycrOl
         5Kh0BFSMvNMIYxAGlAqNOAPUstpXBgsMkRSjQzqz/O0K4fXC2Q4UMC9B4T3DcmQX0A1Y
         pYFxU2T04+8hbGkVwgJscLUsz7Gw/cbtGGOlWBx1dYacKw9bWv8ynQy84iRPbQSbmBd9
         GUag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Su+jEOwF90KBefherA9q1oLvQ0tk48nn09/8XM0Hw5k=;
        b=k6nmG/wQ/Eye7jDoxB6UnizLsZSKtuF9UzIWDVmgNALjUIZRebWUc7+BNkkqoJtVRd
         0Ms2Knhge0UPM8leMwW2uEuTztYYwlREd0qqIVQs7HlL3Zw6E33g/BH85bl2REfN9EIT
         wdEOhxN2lPTHrkfF5sCPNbGPP2BpTlgPuU06j9H7Xhvhe0xI48jFSXk4lEPPLkQ0LGfN
         Cx6VWARL33FPPnkmHVsJin87u3XpDfQEFt88BxtoFW5vyZxlK2s0JburQyxUSylNEBw2
         HO9C4k3O5piABa4wUgUEr1+yC4FkwBatasu5iMKTpHx6QINawrKsRnh/NY3AXsIFt9Wo
         3exA==
X-Gm-Message-State: AOAM530h9RoUQ2MXc2qKUAJFq2atiUmmlozEbG9XQTC9PRlPfWmADDNw
	tmKRSUV+dE/tgupuotm6wT4=
X-Google-Smtp-Source: ABdhPJzyX8YQUwG2HkQ2q1zNt3yKmh39FY9xbVF9mj4Wq+0P+HEG6g5sPDo1gs/DPQJNYcQXDFyI5A==
X-Received: by 2002:a4a:3b83:: with SMTP id s125mr3050672oos.82.1605619539205;
        Tue, 17 Nov 2020 05:25:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5f11:: with SMTP id f17ls4128215oti.6.gmail; Tue, 17 Nov
 2020 05:25:38 -0800 (PST)
X-Received: by 2002:a9d:8d7:: with SMTP id 81mr3029570otf.345.1605619538790;
        Tue, 17 Nov 2020 05:25:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605619538; cv=none;
        d=google.com; s=arc-20160816;
        b=qbGorGX6Kcv89ra4HQaRTjRnQduXmlBjg1HflgDN8JvC3QQYIoW8X8dyZxqOWrxifh
         +9lTvB6KlhhmlPuHRnviushRTitPdcxWhcufyiQbzPtNDRRYTmOay6mv0uF9BIBaz3QT
         56+NYUfs0d3qG5/s7Hr0E72rxA12i2iJjt3+DDAzzlEOB7uVrlJQ3mrZNPI1x7omWcqG
         ofNEPxPeGFOVup4/QmD7Dwx0q6SvbUVtvq6WozGAqaAT/2gf5GXY1qlf54AT2KodavA2
         ZA1CeORLBy5efW7WwwG0t8BG20KlfgXKiY4NegShXufX1Hg5fpbUerF4QbFZu9wttw4U
         70Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WIETnv3xre8DddqB3eoABg/F+YsdxEpmfCm9JSQKUFk=;
        b=eyNNA3QihK7Qn0IvifeRyydnXJibPW6U8dm7jCMYR9tdXx9ljMkvTDHQsbCBPc8ZRG
         /kvKL0sB6aWQJrPtjboWlhrxR3z879XdoFvy1Ob7/aKNbzVMYho2OYqDBUPP/o5Brb58
         hXv9/pdsw0GlgnShmv8s0e7PJw8lo+7biuBMtTsuQQG8JJoWFAadtMtoZVe6p1KE3asP
         5oT6lkIovSdL8pWdmw9P2fdwZ1Pkzv0BuATPYR24JWrtH1BOfrMbq75Qp+Rw9V8Ne79D
         bfchm9rL4Kz4IY9JB3hKaQlDWHEyCvyk3zYVLghLyogqQ4mIa5N1HuDxmgPxKNiuGNQJ
         IVjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ws9G6B7b;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id l23si116278oil.2.2020.11.17.05.25.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 05:25:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id d9so20251142qke.8
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 05:25:38 -0800 (PST)
X-Received: by 2002:a37:9747:: with SMTP id z68mr18952443qkd.424.1605619538042;
 Tue, 17 Nov 2020 05:25:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
In-Reply-To: <6f0a1e72783ddac000ac08e7315b1d7c0ca4ec51.1605305978.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 14:25:26 +0100
Message-ID: <CACT4Y+azmp-xczEt5rQmejtrnQ=e9PFC15tOHTjA3nHfgQ5gpg@mail.gmail.com>
Subject: Re: [PATCH mm v3 18/19] kasan, mm: allow cache merging with no metadata
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ws9G6B7b;       spf=pass
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

On Fri, Nov 13, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> The reason cache merging is disabled with KASAN is because KASAN puts its
> metadata right after the allocated object. When the merged caches have
> slightly different sizes, the metadata ends up in different places, which
> KASAN doesn't support.
>
> It might be possible to adjust the metadata allocation algorithm and make
> it friendly to the cache merging code. Instead this change takes a simpler
> approach and allows merging caches when no metadata is present. Which is
> the case for hardware tag-based KASAN with kasan.mode=prod.
>
> Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba

Somehow gerrit contains an old version... so I was going to
independently propose what Marco already proposed as simplification...
until I looked at the patch in the email :)

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  include/linux/kasan.h | 21 +++++++++++++++++++--
>  mm/kasan/common.c     | 11 +++++++++++
>  mm/slab_common.c      |  3 ++-
>  3 files changed, 32 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 16cf53eac29b..173a8e81d001 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -81,17 +81,30 @@ struct kasan_cache {
>  };
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> +
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +
>  static __always_inline bool kasan_enabled(void)
>  {
>         return static_branch_likely(&kasan_flag_enabled);
>  }
> -#else
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
>  static inline bool kasan_enabled(void)
>  {
>         return true;
>  }
> -#endif
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */
> +
> +slab_flags_t __kasan_never_merge(void);
> +static __always_inline slab_flags_t kasan_never_merge(void)
> +{
> +       if (kasan_enabled())
> +               return __kasan_never_merge();
> +       return 0;
> +}
>
>  void __kasan_unpoison_range(const void *addr, size_t size);
>  static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
> @@ -238,6 +251,10 @@ static inline bool kasan_enabled(void)
>  {
>         return false;
>  }
> +static inline slab_flags_t kasan_never_merge(void)
> +{
> +       return 0;
> +}
>  static inline void kasan_unpoison_range(const void *address, size_t size) {}
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index cf874243efab..a5a4dcb1254d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -87,6 +87,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
>  }
>  #endif /* CONFIG_KASAN_STACK */
>
> +/*
> + * Only allow cache merging when stack collection is disabled and no metadata
> + * is present.
> + */
> +slab_flags_t __kasan_never_merge(void)
> +{
> +       if (kasan_stack_collection_enabled())
> +               return SLAB_KASAN;
> +       return 0;
> +}
> +
>  void __kasan_alloc_pages(struct page *page, unsigned int order)
>  {
>         u8 tag;
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 0b5ae1819a8b..075b23ce94ec 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -19,6 +19,7 @@
>  #include <linux/seq_file.h>
>  #include <linux/proc_fs.h>
>  #include <linux/debugfs.h>
> +#include <linux/kasan.h>
>  #include <asm/cacheflush.h>
>  #include <asm/tlbflush.h>
>  #include <asm/page.h>
> @@ -54,7 +55,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -               SLAB_FAILSLAB | SLAB_KASAN)
> +               SLAB_FAILSLAB | kasan_never_merge())
>
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>                          SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
> --
> 2.29.2.299.gdc1121823c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bazmp-xczEt5rQmejtrnQ%3De9PFC15tOHTjA3nHfgQ5gpg%40mail.gmail.com.
