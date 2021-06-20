Return-Path: <kasan-dev+bncBDW2JDUY5AORB6WHXSDAMGQEQYCZZEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0241C3ADE1F
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:18:19 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id k25-20020a5d52590000b0290114dee5b660sf7064990wrc.16
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:18:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624187898; cv=pass;
        d=google.com; s=arc-20160816;
        b=QC7HHKZ6s+PYHJudBblcGWSGk+2cr7qg2w6PS6OjUK3yUYhq/JXX2W1/5hxH9uSuSZ
         Hef1/NDinsH58m26BjPNU0lPm4HVf7pv4i5F4Hmc4943REjMt9NA+v5vR0Za7HaT0MQI
         8IjO3/rPb12PSeERBCodBBGxLwT+l2QUNmRuhJVaZ5WWUgnT/MJcti18tS4x01wpQPzv
         XGPnC4T1CZV0IfjW5C8pBGIvrz2aIFGzlkHZM36uu/9GK9+roC5hRn8abZI69r2ZL+sF
         HVriJk172f5xNDjiQ/rmXyq8ixCA5YuwYxgsMZPoUHR4NqfIL5wpQKDIz9P4lrKM9DVZ
         GGwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=b/+55G6HQXWIH/F6f8MpgPs1LeTIoJMxmrwo35bWfpI=;
        b=POf+TufwAtlKaftL8tJB0e3tIZ0gW/ekzA2FbgsZHKNFrOnTuf9226JzlXToRAYQ4z
         HrujEFncBaDA9vrzKW1dLYrbPPE+ZvsKEGwqXxvwkZMXPVVJXS+zvHA5SttiOAR5+e/Z
         bnBf7BV6y8WvSKXU/xWWzk+G6eCvXuKSjF+ziG+DLTjmim1IdIF6AAQ3d8gUrMEWmeVc
         srLLcL/rpxSHi0TZQdHuNzse2edgHRzttwE09RzAvZxAACakw/fkGySLhReymqGAtROr
         5HZMPC9mzDhuwT1VGUscz0re+/lyrHt2z+mNYD+8H5caxFr5qusShrBDF9AQFPLd66+B
         ZWUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PUPR7UCL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b/+55G6HQXWIH/F6f8MpgPs1LeTIoJMxmrwo35bWfpI=;
        b=XaF2FoGKCdbu/ueMX7LZ+LYJ4XoHcb4fsofkYjhoHfHwibYW8H8hXAgFMMqH3rqyAE
         VyUseiHToF7/FcOlIRIgEWVS3I6c79eNpVzeOxHMMH8l2ddJb4nUIjRkJr01lEpjUBh6
         G4gB9Hcw9VX0DZKk6hXApH4mhNV0kKlbSaB71yD/jnr5SuhlFFAnZpTpBeVo8mYgeBk1
         6n1ofTiGRzPKcbjoikwtYyguwx9Xb0m7BtfnRJLyMD4KmeZASBYXbFY8xOB8Wc0TW+P7
         H2oSB1KDI0bdTNca6405PlOxkMIUT/KwT7PHgKuAbQdLxURN9YY3LvVmCjCw5F5l3cxf
         dtcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b/+55G6HQXWIH/F6f8MpgPs1LeTIoJMxmrwo35bWfpI=;
        b=G2qf8XML4oy2Y4aXE8otC9/w3u5IXhDVUPWywpZW9qMH+YS+TGsOb0S+dkhVvXvi99
         J/s3gdaFn5mGJxXJStXulnHwXEgxUJ2tmvt+LX3sM+BaoGJtpRqQyNo/OxPxi6BHrPmv
         XONC8e3WVomnux9gzJnTT24hD/BgnSseIY4Dh4ZK6tQbFJ56fignPmYArxVSxKLvtsSU
         AgrHqclHVcijVbtwKT3nOb7GZkoq+2YvI9N1gN5fY5FD1KJbA1kfH7FYQ7fTHhipATHw
         eafPEvvio8Ut22VZiV3SeJlqu/7aPLhTT5BzTKuUdxFjW96ud05YcYGBXCcoG6GCzIvu
         dmnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b/+55G6HQXWIH/F6f8MpgPs1LeTIoJMxmrwo35bWfpI=;
        b=VKvmqedp98DzUOlcfJN52wXgF9wVdysUPXiuqaDy5e6HYCG3CYobN/htub3ePxCMsI
         AYEvbFMfrAtCErlUxtm6Wcs9sTWTkB+Y9rjtffNrjigSTdXd7IOYW4ReR0PLoMR0yFAt
         8QnOx1aPRtRt4ausoPlm09MHxeflqTLu4F0tJgDmhuPKZ+gFL6XJiQFpDjipjOWyBzXl
         +D0Z9BTo0MwFwQdBB5kw+mBP4VlgEMoRcSb7UthJHAtpvcYHaTJCWqbXdORP9XnmVBLo
         mAqKkoJqLTdbvYJmpdVYLk9aXHBiBmlQWCoSOuzi6up/HmLS54KhZTOMtswKR/WwpW9A
         2JaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5337yxP8RF0EnBPR/BGxjpVBXJSjIm1I9frTrZOB+F8UnSGDZ3UH
	MOQguv+z1ijT2Q6FGGWoXdw=
X-Google-Smtp-Source: ABdhPJyXhBXGmUJ79JTtBa5OHUy2pVtzNV2cYUx162AmPhg51sGdgUmk/WpHc2AgSKlDnnbSxvA61A==
X-Received: by 2002:a1c:f312:: with SMTP id q18mr21993778wmq.12.1624187898781;
        Sun, 20 Jun 2021 04:18:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe4c:: with SMTP id m12ls3323643wrs.0.gmail; Sun, 20 Jun
 2021 04:18:18 -0700 (PDT)
X-Received: by 2002:a5d:56c4:: with SMTP id m4mr22154819wrw.92.1624187898013;
        Sun, 20 Jun 2021 04:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624187898; cv=none;
        d=google.com; s=arc-20160816;
        b=Ue+sppAfe6PIKeOhDNPdaSwo7qjPgukYDMyu7nSbU8GneHRllTtztUfQOS+w647sKs
         pUkHuln4kF96I9fP24OxaldBuvn9gTfCNLtfQl/asRWPLiXj6JGGxroJW8sDDo8AjFev
         wVhYJKjBiq3/YPVmvA62zzyD5Rgoj5rqMrObnLu3db9VCX25gaxKRY98vFhscsHkrJ6w
         6zYaf7mU19ET619RQEZ84xkrIgCB+75U1y+Ht8eT3Y3iedCtzR8H1fgX2RZVl3SI4gPc
         9JyE7q/fNqTmvE2If2EnQksAIbEj8HLgIghX8LYa+bODWvVA1WOjwzMHaTvzGm4hOzzY
         8oug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QziFBff9GiMT4Os8umf/EiLjglEeNn/Ybki8x4poeu0=;
        b=so5UXzu7m+YV/6sAE7QGghA0dWI92MF3HIJae/OK4gJcvq9h6gcb/RLMjhD1gdoGVM
         AlVqrGCjkj0QkOWngDYNK7wr6xzlSe8HDUA6DmeNRHsDyNo6O5O/ixyQK5WsjgXhhDVz
         Rbkq+Gc4FrHwqe9tqgfN8frJK1mmYb9wOBeuZTwD3fQLt3O3VyJs3QAlkHxBIwdqHoC6
         S30c63alCgkoGCKWs4iaXXahYkATddDGdo0pn2kWXfLRTsDLrCI87Viww2JEexzMT+LX
         ZX/kHJXefEqwpVjTMC248UrLPuMz15OMhee/4w0DZENcPrYS1wZkujp5fREoHXkUyCdl
         Yhsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PUPR7UCL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id c26si842884wmr.1.2021.06.20.04.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:18:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id hv20so17618134ejc.12
        for <kasan-dev@googlegroups.com>; Sun, 20 Jun 2021 04:18:18 -0700 (PDT)
X-Received: by 2002:a17:906:6b90:: with SMTP id l16mr11511853ejr.439.1624187897865;
 Sun, 20 Jun 2021 04:18:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210617093032.103097-1-dja@axtens.net> <20210617093032.103097-5-dja@axtens.net>
In-Reply-To: <20210617093032.103097-5-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Jun 2021 14:17:57 +0300
Message-ID: <CA+fCnZejE20i=R4=J1TCkoqhukT1G-vnADP_byxpoRULfOvC-A@mail.gmail.com>
Subject: Re: [PATCH v15 4/4] kasan: use MAX_PTRS_PER_* for early shadow tables
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=PUPR7UCL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 17, 2021 at 12:30 PM Daniel Axtens <dja@axtens.net> wrote:
>
> powerpc has a variable number of PTRS_PER_*, set at runtime based
> on the MMU that the kernel is booted under.
>
> This means the PTRS_PER_* are no longer constants, and therefore
> breaks the build. Switch to using MAX_PTRS_PER_*, which are constant.
>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Suggested-by: Balbir Singh <bsingharora@gmail.com>
> Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Reviewed-by: Balbir Singh <bsingharora@gmail.com>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  include/linux/kasan.h | 6 +++---
>  mm/kasan/init.c       | 6 +++---
>  2 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 768d7d342757..5310e217bd74 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -41,9 +41,9 @@ struct kunit_kasan_expectation {
>  #endif
>
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS];
> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>  extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>
>  int kasan_populate_early_shadow(const void *shadow_start,
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 348f31d15a97..cc64ed6858c6 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -41,7 +41,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 3
> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>  static inline bool kasan_pud_table(p4d_t p4d)
>  {
>         return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
> @@ -53,7 +53,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 2
> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>  static inline bool kasan_pmd_table(pud_t pud)
>  {
>         return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
> @@ -64,7 +64,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>         return false;
>  }
>  #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS]
>         __page_aligned_bss;
>
>  static inline bool kasan_pte_table(pmd_t pmd)
> --
> 2.30.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZejE20i%3DR4%3DJ1TCkoqhukT1G-vnADP_byxpoRULfOvC-A%40mail.gmail.com.
