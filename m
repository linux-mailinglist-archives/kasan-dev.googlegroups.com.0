Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAMFROQQMGQEQ633WAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6475B6CBC8F
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 12:33:39 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1777dadbde5sf6508284fac.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 03:33:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679999618; cv=pass;
        d=google.com; s=arc-20160816;
        b=gMX+zzdNsjLHr0Qj92XomxqzM4Lang376dHwD4EEsBD6jbs6ToTZt84s81kbyKfDHH
         WaggTl2tPUGmQ+5jfmIwbWVgUiTyQeHSWfs7BpYFlgrdIHOkFEzyu1yI53FIvjWVm4z7
         Y0Gr8Nq7rnUCGpE8Ukl7E6Trhqx8grI0SGhSsba98AM2japeTdbm5kN8htAcliBgLjyp
         X3Nb9S2tKWKoWkzWF06fXRrX0IhkY8F3rzYWw7LSz5E+AZsZMI1HG+tR6TxsxHerWNkZ
         OeUiKXVtP7toHQGIlcMDYIGQcuUJMwaQOyopnZCzEpLKhtMTqLClg+qjTvFIJic3Ut41
         BCFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/uyJZ251bvi4YINrb6Az+Zz8bNeq13dftYKAiP5dXQI=;
        b=yLXe+pskoIlL8E/mOWdfL5EFuFwdAdpj71dwymeAOt3J2JWK/f+P/MzUDCRTH3UtoE
         PjbA6c/jj4yS4bICN+bDFr2nxtoVwMP5/g7Qahb3GHMm3yPKjZemDEd37lXnL9twtqIZ
         pjQYLVU5UmRmW99+wLQ8x2LwYKRDWn99qOeXBAe1TDFAudpJR4eodWMzbM9oj2NSSLGd
         iEYL4lw6+kUb7/KLoar0EAP1HqAHYg7WXqxAZa4s4tYYXHOjs2vEt5BOp8Fa7EZzgHcn
         qgV60MBlmYFLGpUBW7i8aOp/g15RcDFFA9w6zY7BpTkdPzL87sD6LaZBZ8OUSq0BPp+4
         vdnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q6BWSq3V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679999618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/uyJZ251bvi4YINrb6Az+Zz8bNeq13dftYKAiP5dXQI=;
        b=CHsD4hWu7EHDRn1Q2M8LnrARl2STPfl/UEOuG6mIzXA5gpwDU9R1U9jO61iQTej164
         eq6z6z/gM4Wf40xo9fD6mxtYXx0I2zC2dLozphGun2y2u2/VlomOULOhG3mciwp4PkBB
         sqDMANxnwppP0Pt3v/ms7K3kr3UhDxhOLrbj+kkyIZSPFiCdbGy1AkOKq4fSie+LZTeK
         2MNJIAC/o8Kenp0o0hLSmx5SSEKtc+RR9B161z1/+Admjy9C725yQ2nRSBa/F2koSee4
         O2elouQtu5t/kO8rBaKMrupTSMtwxTes93Hu6umar3NBgK3AoFRA/Jeub2mGXpQjnXoB
         e1Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679999618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/uyJZ251bvi4YINrb6Az+Zz8bNeq13dftYKAiP5dXQI=;
        b=IWnkN6uht93C5gEBy58jnSL/97sawW7UHWVQi0/pFCI4F4sB+a1FF+d+dep/8NzTTP
         H4JBWARnB28PgS9vuqgbT1ACzQGh0djQuw5FDFA5K1XyC6XpJGhgfPbHWflodHcvFdgB
         7YG7YhZk5dEnhV6Gh45lesa8WUvzaiuxYAjO0VkmcixzlRFGcSS1K1d7HSkicAgGr9k0
         4QrR/S37u/8asOQ1O9GpM1tqnMywQ5aeE2I0axDCJN5OzWEerrppuJfIduvuuTJGrBGY
         806lkPA/sIk6IL1UH4tQ0a/58y+hjatMMxNSE1glPv3eb0ejYc0XYztlrZ6Thg/Bl6CR
         G0Ew==
X-Gm-Message-State: AAQBX9eey+2yQD8lwlvkfQkcNUlpkDyrs98cG2vXDj0bt6cnuAVyi1jo
	s+lkLRwwktfUNgdYtHeqZuQ=
X-Google-Smtp-Source: AKy350YTLu/dCScLLRdCwz+G/HlHj/NK6H/h9oPxT6VuzTYVrZXO3/qSJm5IL47oKJb5HIL+3YSW9Q==
X-Received: by 2002:a9d:6485:0:b0:6a1:561e:3381 with SMTP id g5-20020a9d6485000000b006a1561e3381mr625093otl.0.1679999617739;
        Tue, 28 Mar 2023 03:33:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:68c5:b0:698:cfb:c76 with SMTP id
 cw5-20020a05683068c500b006980cfb0c76ls1739678otb.2.-pod-prod-gmail; Tue, 28
 Mar 2023 03:33:37 -0700 (PDT)
X-Received: by 2002:a05:6830:1da6:b0:6a1:2289:52a5 with SMTP id z6-20020a0568301da600b006a1228952a5mr5302529oti.28.1679999617210;
        Tue, 28 Mar 2023 03:33:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679999617; cv=none;
        d=google.com; s=arc-20160816;
        b=L0B0gyZGcCn/jJ2eRiLaith/tiruYv/mfBRaMgwLjcU1ysBr3qXYFGDbMQo4t04o0N
         gv5lApytvRkKgGDFtqfTS1TORuWJFzoSq4NwKK60+Y9efS4SCTjAjqITqZBI9cOtaOOq
         D58bssQA++/DAitWb4vFrxqpfINb8Dl5n/6Usmoi+2Kp5ZFC2OXyTcZjIA7iUnEHZDuc
         OhlfH7vqIR67adnowBghmp60OV+7ATgmQaYEhNM6a7qvWeKYVc6d/8jEswfFfG2ipilF
         1Y4fEhWGEa9QmEe8j8aF7yI8jo4Q3gNOKvXsCGnYhw0D0N0fJap3+5C87EIXI3BdNis7
         y4HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZDR+svhMJqmi1JNTt9QQspjwqS4wpTbac+Zzy4tDFxI=;
        b=lFt4CP76gCO6hp+Kzy9II3aC1KrTBbyLxw4ecQuRmvnVfnetfwiNqhaE7xYzVXHZOQ
         63Ekk4nUZ1RX6JvGzpR+MHfrUXt+GPJ8KRMDiyjrkUqqFXyTbkd5hvKg9C3EZ/AqUfaW
         FqhveV8M1ZTLXOyJrFrEbUFtHe2iaBxUimrQu5CTPcxpXi3XWeolCm/f/P1ZovoG67VK
         NPS742+4iBFx5rT0XsswfyhZFGj6dLQq4oMT0aw/IuSnAbEBHZoiqFIGZhzPD+ZrIIV3
         2ImkEJnKrRjvXgo+3K98Nec7NrbEWJ69pdZJgoIZl8RjlcqLZtwIgqLJGj4wjaSOrmDm
         IMbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q6BWSq3V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id y1-20020a0568302a0100b0069f974342fcsi2097362otu.0.2023.03.28.03.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 03:33:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id cf7so14385148ybb.5
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 03:33:37 -0700 (PDT)
X-Received: by 2002:a25:2d20:0:b0:b75:afb9:a257 with SMTP id
 t32-20020a252d20000000b00b75afb9a257mr14063323ybt.65.1679999616628; Tue, 28
 Mar 2023 03:33:36 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-4-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-4-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 12:32:59 +0200
Message-ID: <CANpmjNNry_OxZJFAKSFf9Cpb2SCWM-__AF25BpGwOXpa+DJBUQ@mail.gmail.com>
Subject: Re: [PATCH 3/6] mm: kfence: make kfence_protect_page() void
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q6BWSq3V;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Tue, 28 Mar 2023 at 11:58, Muchun Song <songmuchun@bytedance.com> wrote:
>
> The arch_kfence_init_pool() make sure kfence pool is mapped with base page
> size (e.g. 4KB), so the following PTE lookup in kfence_protect_page() will
> always succeed. Then there is no way to stop kfence_protect_page() always
> returning true, so make it void to simplify the code.
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
>  arch/arm/include/asm/kfence.h     |   4 +-
>  arch/arm64/include/asm/kfence.h   |   4 +-
>  arch/parisc/include/asm/kfence.h  |   7 +-
>  arch/powerpc/include/asm/kfence.h |   8 +--
>  arch/riscv/include/asm/kfence.h   |   4 +-
>  arch/s390/include/asm/kfence.h    |   3 +-
>  arch/x86/include/asm/kfence.h     |   9 +--
>  mm/kfence/core.c                  | 142 +++++++++++++++++---------------------
>  8 files changed, 73 insertions(+), 108 deletions(-)
>
> diff --git a/arch/arm/include/asm/kfence.h b/arch/arm/include/asm/kfence.h
> index 7980d0f2271f..c30a5f8125e8 100644
> --- a/arch/arm/include/asm/kfence.h
> +++ b/arch/arm/include/asm/kfence.h
> @@ -43,11 +43,9 @@ static inline bool arch_kfence_init_pool(void)
>         return true;
>  }
>
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         set_memory_valid(addr, 1, !protect);
> -
> -       return true;
>  }
>
>  #endif /* __ASM_ARM_KFENCE_H */
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> index a81937fae9f6..7717c6d98b6f 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -12,11 +12,9 @@
>
>  static inline bool arch_kfence_init_pool(void) { return true; }
>
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         set_memory_valid(addr, 1, !protect);
> -
> -       return true;
>  }
>
>  #ifdef CONFIG_KFENCE
> diff --git a/arch/parisc/include/asm/kfence.h b/arch/parisc/include/asm/kfence.h
> index 6259e5ac1fea..290792009315 100644
> --- a/arch/parisc/include/asm/kfence.h
> +++ b/arch/parisc/include/asm/kfence.h
> @@ -19,13 +19,10 @@ static inline bool arch_kfence_init_pool(void)
>  }
>
>  /* Protect the given page and flush TLB. */
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         pte_t *pte = virt_to_kpte(addr);
>
> -       if (WARN_ON(!pte))
> -               return false;
> -
>         /*
>          * We need to avoid IPIs, as we may get KFENCE allocations or faults
>          * with interrupts disabled.
> @@ -37,8 +34,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
>                 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>
>         flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
> -
> -       return true;
>  }
>
>  #endif /* _ASM_PARISC_KFENCE_H */
> diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
> index 6fd2b4d486c5..9d8502a7d0a4 100644
> --- a/arch/powerpc/include/asm/kfence.h
> +++ b/arch/powerpc/include/asm/kfence.h
> @@ -21,16 +21,14 @@ static inline bool arch_kfence_init_pool(void)
>  }
>
>  #ifdef CONFIG_PPC64
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         struct page *page = virt_to_page(addr);
>
>         __kernel_map_pages(page, 1, !protect);
> -
> -       return true;
>  }
>  #else
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         pte_t *kpte = virt_to_kpte(addr);
>
> @@ -40,8 +38,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
>         } else {
>                 pte_update(&init_mm, addr, kpte, 0, _PAGE_PRESENT, 0);
>         }
> -
> -       return true;
>  }
>  #endif
>
> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
> index d887a54042aa..1299f47170b5 100644
> --- a/arch/riscv/include/asm/kfence.h
> +++ b/arch/riscv/include/asm/kfence.h
> @@ -46,7 +46,7 @@ static inline bool arch_kfence_init_pool(void)
>         return true;
>  }
>
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         pte_t *pte = virt_to_kpte(addr);
>
> @@ -56,8 +56,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
>                 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
>
>         flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
> -
> -       return true;
>  }
>
>  #endif /* _ASM_RISCV_KFENCE_H */
> diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfence.h
> index d55ba878378b..6d7b3632d79c 100644
> --- a/arch/s390/include/asm/kfence.h
> +++ b/arch/s390/include/asm/kfence.h
> @@ -33,10 +33,9 @@ static __always_inline void kfence_split_mapping(void)
>  #endif
>  }
>
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
>         __kernel_map_pages(virt_to_page(addr), 1, !protect);
> -       return true;
>  }
>
>  #endif /* _ASM_S390_KFENCE_H */
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
> index ff5c7134a37a..6ffd4a078a71 100644
> --- a/arch/x86/include/asm/kfence.h
> +++ b/arch/x86/include/asm/kfence.h
> @@ -38,13 +38,9 @@ static inline bool arch_kfence_init_pool(void)
>  }
>
>  /* Protect the given page and flush TLB. */
> -static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +static inline void kfence_protect_page(unsigned long addr, bool protect)
>  {
> -       unsigned int level;
> -       pte_t *pte = lookup_address(addr, &level);
> -
> -       if (WARN_ON(!pte || level != PG_LEVEL_4K))
> -               return false;
> +       pte_t *pte = virt_to_kpte(addr);

This WARN and bailing here has helped us catch an issue early before
[1] - and because KFENCE ought to be enabled as a debugging tool, the
philosophy is to be failure tolerant and not crash the system here,
hence the "return false".

[1] https://lore.kernel.org/lkml/Y3bCV6VckVUEF7Pq@elver.google.com/

We're relying on the architecture doing the "right thing", but it's
not entirely unlikely that the arch ends up doing the wrong thing due
to some bug like above (i.e. arch_kfence_init_pool() is faulty).

Nack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNry_OxZJFAKSFf9Cpb2SCWM-__AF25BpGwOXpa%2BDJBUQ%40mail.gmail.com.
