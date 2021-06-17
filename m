Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXKVODAMGQEKITM7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id A66773AAD08
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:08:55 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id z33-20020a9f37240000b02902789095144dsf549344uad.22
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:08:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913734; cv=pass;
        d=google.com; s=arc-20160816;
        b=mE+h+bA+RPXAQEks3ci9UOn1UTI2jT9ZD0CubgKXql7hlItVJpgTz6WZMM4/lUJ1uT
         c3BRAPp81SmEyKzoQoSTf5jxMlT7GnDrQ3qRuBDW3oqNLeARb+Nkz3E+qK7XFJonJMdU
         xoWksceOwyY+fFbGd9OJxR0RTg7wzvOUKIi/nV0w31gT/szVY3x4imx4mvqAlqD+1oGR
         fISE4ZiHBrxC/hYSgwio1H/NF4nLzcmgupFAIabHlW8/kpUZX2Nc5h0ARuLB6/jn8MPF
         y2aHZJD4JGJo/KvjMiUaYSjqiyz2YxeKaBweu68kkoRi3vBejI57ZEgpM85JE28ttwRi
         Rbyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7lMaXGnKaAJu1vEPQdENZjdWmLubWJvrGd+aprJyDfA=;
        b=YRKLaxWqA/oQcWoQ+iBZFceBN3DiQtY1eNMyy2PyTAoCzfqHNRfmc8xdn8hX8Ajqnm
         Qq8uYRTccPYwy/Lce3mwciZDr4Kmh6xo+cRUn0jWPMwEgb/YToqDuhUSHndpToKNCyFP
         40dllqSi/SwBBoT/3Sa4Cw3wO4NFQJbE5uO9pH0Cj+wSb9yGBddsD+6jEOipv7gk6TNh
         qlnWf5YQ0AcLoOpKN6Wpk8R2vEJF2HmbijAn/S1jA0KiUU0s6JwjdIu1DuOa8N/Ln1w4
         tYB9tCTXg/jUYXjSytW9k1ASx5Oqww7d8rfG6LHl2u0SBHApLcVdbUe9E3NAeyx/qnmg
         0ZbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzliMFti;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7lMaXGnKaAJu1vEPQdENZjdWmLubWJvrGd+aprJyDfA=;
        b=XFqJB1COmX59ZVy7pTuh8KmX7kRDmyjif3cF+yvd0ZZ5QcfUHRuSTbbAOr/JHslmh7
         OcJmqElFwnOiYs3JpeQjvxFSTFe7rcWbmooTKUCizIs6BdGj2YAoNPv/vJKi/ph6Mn6z
         qj2sICrJ4QEcohCpxgW7k4cwamujeZfCnUoqhE7UALPhKhDtcjzDz0/T3Zq70Gvv6mG6
         +BhL1Baf3u5X+g0PdGuSpj6F/9RYqhbvmHW7vQz340KhYEIlLKbhTQ8Nh+nHcyR8rALc
         +0tgT/3+h9cumrE6LeCsEF0B79WgdBS1FyMxjJkBj41Fvbn7fTr5TxvhXN7sIjArh4lo
         whJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7lMaXGnKaAJu1vEPQdENZjdWmLubWJvrGd+aprJyDfA=;
        b=Ictd33m9jsUXghEUlDTRuTdM0MHmO/plqJiReTVLuSFx7FEYN9ZcwbmajRFrM0lwpI
         gyg8LrVe4xECXQEZBsyTdBaighFhReJVOvwwxt3GA0vxIIvAQFxwPxUt+dDLS/JttSSB
         FNxaAh7XptxthaXnSQQx23372/fDPel1a+lB45tfQV3DdtflGPe2/HTF4yUh0dBuoZfZ
         jCCCx97nEujjb62ChH9pxcjaTJscjmDVwai0a1T+PgjtF5uSAAeMNhh820ihH4BWo6T+
         XgEvApXMBu1AMD0EN/M/lOM2/+rdLTUL2BQ91gyPY3wJie/1hcorfgGJ97y1rtubK2Ob
         3zbQ==
X-Gm-Message-State: AOAM530WUaOiXpSFyYt6eSoTWo6JWcaPet+HN416QSXDHcfuGfRmkhOB
	Hz8rWA0bn8y35lkvhH/RaFs=
X-Google-Smtp-Source: ABdhPJxkbF6YHwlMDu3TwqUmFg8IY+93wQg34GEpTbk9LpUZBKA/2G2jf3Hy1DYVYd4Fr5/IvdYe4g==
X-Received: by 2002:ab0:7642:: with SMTP id s2mr469489uaq.133.1623913734457;
        Thu, 17 Jun 2021 00:08:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fc4f:: with SMTP id p15ls1228981vsq.2.gmail; Thu, 17 Jun
 2021 00:08:53 -0700 (PDT)
X-Received: by 2002:a67:bb14:: with SMTP id m20mr3199453vsn.0.1623913733890;
        Thu, 17 Jun 2021 00:08:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913733; cv=none;
        d=google.com; s=arc-20160816;
        b=YiLJefxZ3P6EYUTmJ0e67qgytFq/CIzsa6uEC8So38WRGdGxYch5w6o9y/o9vE2gmO
         +WZ9/AJJgD/ELDTaqWY7yPJRnHJ4lWqv5A0/26vfDc6OIAByTb9HknXnKO+s+Xehreuo
         cY3ma+5GAqYqwRb6y7bR54AJtGvpBydbuUSUyQvnWRVFC+5ChH6BV+B/b7Qh0SuQv0nQ
         8I6QRCtPfZuC647X7tu/AFhvzWOl3ptLnyVVioQ9A9VjGIfbUKFHwlTLwqsGS14kZdxl
         gGyPJPFwGdT6hEjiUf6rnbIjvdzvLfR/y4EnpDEke30SlXzkHapUFA5OGYoQAbjYUjzI
         krdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MsqYILgAKurijhL/t9Pxm6TteQj8nlU+VZKZOuCyAgE=;
        b=HbpNbz2LFk17TiZd96nHmaL6FGQGGY5TT/HFPAKBQRX8ntpSFaZQK219SSh5wHCoXo
         Fr3mUfv5wsM76HBVQOZFfqniIiq/2knxq6v5CDiange2TEs4Vtdgjbq69F/wGQoTzWrA
         hPfTpf3qnopUMvnUIvamPU6SDLgweZDcTAFXwb1WfGD2oK9e4gg4fxylNuQx0MTTZk4z
         PaS3fHUg0IY7jY/fZu1nlksDmftaKFdtbh/+Jbcqaof/rJeIxKF/wpNjgIhhMTiA605L
         H1RIOI46VjoBxV4A9keGdF+3D0QmlMd4h+9MUSs4FRo4vlmaR0pi8CF/pRr2lDDmfE5G
         vLyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzliMFti;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id n15si343805uaw.1.2021.06.17.00.08.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 00:08:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id j11-20020a9d738b0000b02903ea3c02ded8so5168554otk.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 00:08:53 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr3236836oto.17.1623913733228;
 Thu, 17 Jun 2021 00:08:53 -0700 (PDT)
MIME-Version: 1.0
References: <20210617063956.94061-1-dja@axtens.net> <20210617063956.94061-4-dja@axtens.net>
In-Reply-To: <20210617063956.94061-4-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 09:08:41 +0200
Message-ID: <CANpmjNPo1Cn5PNQB0kRWU_481WKUO1WkY-kDYhBTQkT0VXsF0A@mail.gmail.com>
Subject: Re: [PATCH v14 3/4] mm: define default MAX_PTRS_PER_* in include/pgtable.h
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PzliMFti;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 17 Jun 2021 at 08:40, Daniel Axtens <dja@axtens.net> wrote:
>
> Commit c65e774fb3f6 ("x86/mm: Make PGDIR_SHIFT and PTRS_PER_P4D variable")
> made PTRS_PER_P4D variable on x86 and introduced MAX_PTRS_PER_P4D as a
> constant for cases which need a compile-time constant (e.g. fixed-size
> arrays).
>
> powerpc likewise has boot-time selectable MMU features which can cause
> other mm "constants" to vary. For KASAN, we have some static
> PTE/PMD/PUD/P4D arrays so we need compile-time maximums for all these
> constants. Extend the MAX_PTRS_PER_ idiom, and place default definitions
> in include/pgtable.h. These define MAX_PTRS_PER_x to be PTRS_PER_x unless
> an architecture has defined MAX_PTRS_PER_x in its arch headers.
>
> Clean up pgtable-nop4d.h and s390's MAX_PTRS_PER_P4D definitions while
> we're at it: both can just pick up the default now.
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>
> s390 was compile tested only.
> ---
>  arch/s390/include/asm/pgtable.h     |  2 --
>  include/asm-generic/pgtable-nop4d.h |  1 -
>  include/linux/pgtable.h             | 22 ++++++++++++++++++++++
>  3 files changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
> index 7c66ae5d7e32..cf05954ce013 100644
> --- a/arch/s390/include/asm/pgtable.h
> +++ b/arch/s390/include/asm/pgtable.h
> @@ -342,8 +342,6 @@ static inline int is_module_addr(void *addr)
>  #define PTRS_PER_P4D   _CRST_ENTRIES
>  #define PTRS_PER_PGD   _CRST_ENTRIES
>
> -#define MAX_PTRS_PER_P4D       PTRS_PER_P4D
> -
>  /*
>   * Segment table and region3 table entry encoding
>   * (R = read-only, I = invalid, y = young bit):
> diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pgtable-nop4d.h
> index ce2cbb3c380f..2f6b1befb129 100644
> --- a/include/asm-generic/pgtable-nop4d.h
> +++ b/include/asm-generic/pgtable-nop4d.h
> @@ -9,7 +9,6 @@
>  typedef struct { pgd_t pgd; } p4d_t;
>
>  #define P4D_SHIFT              PGDIR_SHIFT
> -#define MAX_PTRS_PER_P4D       1
>  #define PTRS_PER_P4D           1
>  #define P4D_SIZE               (1UL << P4D_SHIFT)
>  #define P4D_MASK               (~(P4D_SIZE-1))
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 9e6f71265f72..69700e3e615f 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1625,4 +1625,26 @@ typedef unsigned int pgtbl_mod_mask;
>  #define pte_leaf_size(x) PAGE_SIZE
>  #endif
>
> +/*
> + * Some architectures have MMUs that are configurable or selectable at boot
> + * time. These lead to variable PTRS_PER_x. For statically allocated arrays it
> + * helps to have a static maximum value.
> + */
> +
> +#ifndef MAX_PTRS_PER_PTE
> +#define MAX_PTRS_PER_PTE PTRS_PER_PTE
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PMD
> +#define MAX_PTRS_PER_PMD PTRS_PER_PMD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PUD
> +#define MAX_PTRS_PER_PUD PTRS_PER_PUD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_P4D
> +#define MAX_PTRS_PER_P4D PTRS_PER_P4D
> +#endif
> +
>  #endif /* _LINUX_PGTABLE_H */
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-4-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPo1Cn5PNQB0kRWU_481WKUO1WkY-kDYhBTQkT0VXsF0A%40mail.gmail.com.
