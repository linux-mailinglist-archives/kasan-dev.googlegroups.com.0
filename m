Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZND3D5QKGQENBA4H2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C445928052C
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:29:09 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id j75sf2086386lfj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:29:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573349; cv=pass;
        d=google.com; s=arc-20160816;
        b=IWYVlhEWDMZzLh8O7s11y4YNxnOKLihp8opOjoCpMa9jIq6XhP/chFCQ9KSsfGJnUZ
         D7LCywzLkxLUmUidqZRXig9IUDWCUlJzkGjJTRbec1F4SHx7akHUgpRwFI1Zp8Yg3Ewn
         s7eAgdvUMiiyi7vcLNtocFPt35NB/AhH9yYvLFfCOXzfd5DPszSpyCvzKixp+2JFm133
         LfbhpdRAB7gjLNTLovsAi20BVK/qJYKtP5JEPIS8ioyiCcIRrfeOjn9nGzOeZ/tfbHDo
         WMyuSDSK8TyP/o7IIaAAjdgaLsc4bfKG9jC4ctINA0bc311S6N4On/18kM9SW+TLsUXP
         y5Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Z2xtPoIAu2jNgE3nNBHuLsQsatzCytCezrRA6jvyjSA=;
        b=DcFe1bTM2YpUqjw7poBTxxS8gxKQSRB2wIUQZIw21oSWa60PVGY4Um1KR8GByX6w5B
         X9/6oxMrFq+9ENN1sI4nIRR4NLTxvIOiwhfzfARPtXj4t2jHvEcNAvIhyatySftc2+SW
         cTkpObg3zilxClLKdK23XeZywUnvO2DfK/S00Be/CufJdTmYvxQ7jzNeg1gJyBb2zFbZ
         rAO9VO9PWtrHBQsAjaMq3vlKkFOkL7R+tVgIVAbzPxDty7d36880Q03ovuoKGpRKI4Ss
         TisLkG/9idG2ocbNgzDhxNAWoelz6XqR51wvD6JAc2lWpDPr+BO8mecy05K1OGveBzpJ
         BlQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I+gsOCjj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Z2xtPoIAu2jNgE3nNBHuLsQsatzCytCezrRA6jvyjSA=;
        b=c+ELn8OMDrrj8TFgiZoG+VcQOVsXlnAyR9ds0WaYBC3PE4tkS4kRPGtyQi3aqFdeoq
         G6HY426ReV7Zm0iM+qe7WpfIMPSIE+Nr2hR1zzvzB/hqcpCxcNC/0LuPFWUoBjnMjI7j
         T/y1F6Mtcpj+AorQdjsoMNx4Yw7Ha/cXTAwWCHKQGxZlCOspVLewbuyqPPAuoQIqwtVL
         X2hPKkAY5oEiLBa4ZkUXXvZRgbSd+eeD57ydcdzF7oa9A3gNmKfw7BTXwKi3BaC/rjcV
         IkpDAa1nxLwbRyDdN99o8XtHrXa4/EJEIptni4plRY9juE2qGVySbE0YIc8g3uoama8k
         1+2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z2xtPoIAu2jNgE3nNBHuLsQsatzCytCezrRA6jvyjSA=;
        b=jxMeXGmA8UjQLaBPc+iAiDv8kSaEYjPiaeBhkmUI1oYXCG0Ia+viXGYm22oI/O4QKo
         VXGQmA9r+DYz9wNawrzlVzu8m+UBICO0J+XxfgzqQiiIx1uSbx/BRFDOqpfkA9BXbUmg
         0WtBjlBwkrMTg/gg+bQM5g6IfbYRYG7e/yulbMb6gHr753HqHt6ix0M2PumyRDN+mj3U
         I3SYhSGZhQaYZ6rURRghIdz/oQFp9LkZJuN8z+NFKY1goRvhxPlpS+GGbuqAaZ9uSe89
         4cOdEQAXarGSwPVggDWfxN0OIGz6Yjc5uVqFOQsSYTCIrj5QVbTgCZSxiBWU+va2809I
         ihHw==
X-Gm-Message-State: AOAM530UT66nbq4e9EhXe4krqa2oernQ3N1WeX8q10H5EdAlKxENi1EQ
	Cu7ffRokhVcMfNSveL9k/ts=
X-Google-Smtp-Source: ABdhPJyXAE8K6lBljjj0rBkQPqia8YxP23R8DXyYQjhxPKzsS8beFQ1E66OKXTjjl5p9Il5b5MR0wQ==
X-Received: by 2002:a05:6512:110a:: with SMTP id l10mr3364526lfg.552.1601573349289;
        Thu, 01 Oct 2020 10:29:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1677117lfn.2.gmail; Thu, 01 Oct
 2020 10:29:08 -0700 (PDT)
X-Received: by 2002:a19:8446:: with SMTP id g67mr2738169lfd.87.1601573348250;
        Thu, 01 Oct 2020 10:29:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573348; cv=none;
        d=google.com; s=arc-20160816;
        b=Wyf0wnfU0In4Ca22Y20KRRhNljdfSypw6LhciVVrgyqKruHI+8TRXSsfgRXBzyxE4k
         413it1LoeHfYQ779vS0jz4vLCdlZaZjbFgi8pqxm0f4vcq9P7iDdMAm+YiC/RYpjZo7g
         cF21wTr+91IlOU+xSjz8b54oN1N3H4tN+FwUsT44tW2Wh9JRhnhXQgKlpuDuoUi1EwnX
         0Y+AZV8lVqbMgKuq/mtYUKU74H7TZaCS8VEFdYcsaEWfKiCmVTMmp5jIVPgw8x7lqXYA
         d7ZZhMmWkAysgCzZkR+rDXNNqzjpZQfJN5A+NYruVDByTxeIQ4y+/JCJ4GR3Md5L2vwW
         uECw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iPaQCzihnyHNLy47NnUWbDr7GfchzwJLlA5r6ihLSYU=;
        b=Ouysw9g5vWdFQZxaXu4siu/CGTtx32Qo8SVyFAmsK7v2m2vqgJXCM42zCOn6iAM4Ss
         0E7pc/67lzXbFlg83AwhGzfzIyu07DBFjvlXF3eJKW4K4fOeG7eD+compt0hLA3qn4BN
         3GvlfPDAJfK0sNAYP5R2U4IH/p7V4f2SXGl6BWyoljifMai+mftyZQYiYAaEe9i4Cvb/
         ++Xb8nZWCIY51cE4AZxxnohJYGdl8ZGsHYlitayBsAjH2bO8tKgnmkzeO7m30qpCWXK7
         l5mf1LD9mQKkJjMGUEFhFXmQg/KE+H5IhPNX4BNxiwK//5bdFhP6nYOmgxL83lGc0PW7
         TdnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I+gsOCjj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id f23si197415ljg.8.2020.10.01.10.29.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:29:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id d4so3713686wmd.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:29:08 -0700 (PDT)
X-Received: by 2002:a1c:4c0d:: with SMTP id z13mr1011876wmf.113.1601573347642;
        Thu, 01 Oct 2020 10:29:07 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id m3sm9926381wrs.83.2020.10.01.10.29.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:29:06 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:29:01 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 04/39] kasan: shadow declarations only for software
 modes
Message-ID: <20201001172901.GB4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <9de4c3b360444c66fcf454e0880fc655c5d80395.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9de4c3b360444c66fcf454e0880fc655c5d80395.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I+gsOCjj;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Group shadow-related KASAN function declarations and only define them
> for the two existing software modes.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
> ---
>  include/linux/kasan.h | 44 ++++++++++++++++++++++++++-----------------
>  1 file changed, 27 insertions(+), 17 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bd5b4965a269..44a9aae44138 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -3,16 +3,24 @@
>  #define _LINUX_KASAN_H
>  
>  #include <linux/types.h>
> +#include <asm/kasan.h>
>  
>  struct kmem_cache;
>  struct page;
>  struct vm_struct;
>  struct task_struct;
>  
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  
>  #include <linux/pgtable.h>
> -#include <asm/kasan.h>
> +
> +/* Software KASAN implementations use shadow memory. */
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define KASAN_SHADOW_INIT 0xFF
> +#else
> +#define KASAN_SHADOW_INIT 0
> +#endif
>  
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> @@ -29,6 +37,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
>  		+ KASAN_SHADOW_OFFSET;
>  }
>  
> +int kasan_add_zero_shadow(void *start, unsigned long size);
> +void kasan_remove_zero_shadow(void *start, unsigned long size);
> +
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> +{
> +	return 0;
> +}
> +static inline void kasan_remove_zero_shadow(void *start,
> +					unsigned long size)
> +{}
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +#ifdef CONFIG_KASAN
> +
>  /* Enable reporting bugs after kasan_disable_current() */
>  extern void kasan_enable_current(void);
>  
> @@ -69,9 +94,6 @@ struct kasan_cache {
>  	int free_meta_offset;
>  };
>  
> -int kasan_add_zero_shadow(void *start, unsigned long size);
> -void kasan_remove_zero_shadow(void *start, unsigned long size);
> -
>  size_t __ksize(const void *);
>  static inline void kasan_unpoison_slab(const void *ptr)
>  {
> @@ -137,14 +159,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  	return false;
>  }
>  
> -static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> -{
> -	return 0;
> -}
> -static inline void kasan_remove_zero_shadow(void *start,
> -					unsigned long size)
> -{}
> -
>  static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  
> @@ -152,8 +166,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  
>  #ifdef CONFIG_KASAN_GENERIC
>  
> -#define KASAN_SHADOW_INIT 0
> -
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> @@ -168,8 +180,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
>  
> -#define KASAN_SHADOW_INIT 0xFF
> -
>  void kasan_init_tags(void);
>  
>  void *kasan_reset_tag(const void *addr);
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001172901.GB4162920%40elver.google.com.
