Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7OKV76QKGQE37MBUQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id ABA8D2AF1F5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 14:22:06 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id m8sf974036otp.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 05:22:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605100925; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZpbAIg6kJThfb0YLrUHwf6a4xeh8K+7F71/y8eDX2aCOIt3nsK/0NWYVCsOk3zg6o
         nNy/wsmDb97dMApOmio8kgxXZx38Q9Cmq3JOpL0tuTSAaNpYQHsrOi74wRLONPLLkd0f
         p3ixWsZrWd4faNWywAPxe8QZXLElGmLdfjGV7ibtnM0jih24St9omsY3wICYRNiEUVZN
         LBATE/DbLh7YY7h7/BY5tRcJmjYUd7zlRYs9xQ4+OvDHUhxVuT+8q/76h3QqKtm3jh23
         jhG/wYZkybwsTH1KAVAq9T94ADaiM1KRcK6/+pcYCOfR/cqcz1fRYkhwQ3v+4T3VxE+5
         yEwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=luMK4oBdNCJrNaH66Yn1WVTexEejxfvaqr279JsGUVk=;
        b=YumNpSQCqVm3K2j2P+OAOhp2q+quracGsSn/YoIBbvuIqCtnBQ7Tp+XYOvB//zcUbY
         bIKp9UKCgSEkrUl4IzM8FZgXZmQ7uL26jFCKhJUu98fT1rwoIj2zKjEgx/LA0mhfH6VW
         2Vb0nnBaKenGQib1h4hg4VTqB23klIhLWbqKA2E3Dv/GDhWORsY+39d2uzPFrCJs0qUF
         qf9NY3E6y+e1kca+wRy5RMuzTWy2/uqU0xGTAwVcjUbK0xYep/eYl8JTul71q6OXpArT
         RgVZTznuX2tj8QcV/0+6IDC+/HVP3UMXFrQ69ou8nFuEDQNGTG+eKxJKgy36ny5jNRXG
         8otw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="I8TMNct/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=luMK4oBdNCJrNaH66Yn1WVTexEejxfvaqr279JsGUVk=;
        b=DhsfQ+d9CIegHeSIwJ/FAEFDOpWlQbwe6+/0oYUKrW2/sN8xTlNblXm8UaWklefkf8
         If03jedhXEPBB9qqO8atMwBy6UycR82C7YTHNqwQgUPvEk5zlkmA8VWvKlwPbZisnpCv
         x5Ixye7GRBSh+BwSGoFKzw8gx4J3LGZaGrB6/SEZpjYJu5FJue7vijpJzlJFDYmJjak/
         twf1uVb+5zavftNgtgNC6x4QlsAR8gnDtjNr53MdvSEisxASEWXBTxnZD2JOVG5Os7Az
         RjxxkdhrxYHIPzkEMuTJdsd4p5VRMnr2m7vZnTnPQx/81TO63U1NjYnahj4oxOUu7DcF
         rZ+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=luMK4oBdNCJrNaH66Yn1WVTexEejxfvaqr279JsGUVk=;
        b=DCk/CHUAE5s2AKlrNnoetUO7DpGgY4WakPPnA4z7dCK79T6UvJBfDixrc6KY0un4E/
         4Cy0yFcYr5XK/35mkBJJopejgWCkkcJhcmogVl4ZKavcXAfSLy3f/aH2vcZ5pDCeTE2w
         pNm3mCrKToUOCQNO18y/s+IWqeOiSULvpT8VnLtnTbrxuggatNFViM+nWp4EibElLQu9
         vfgYvewhYBbMQB8Vh4X1ZzdkD0PYGuhV8hRMzlxn8wVeazfy/LO9LluGV7MdN3HRImPG
         3is1G1eUFVc1Vns9ijuy5wf5cf6QjrMYsL88XJJ/lUvSpeA3Amvjb3h47xd3kAjMfUzo
         Wjxw==
X-Gm-Message-State: AOAM531N5KkIUZZOQOAVx6YEvg+TOB5IpOze1bz3/fik4+B3P/bJ01ZJ
	FeeH7PMSoQLARavsTNcZKT0=
X-Google-Smtp-Source: ABdhPJzsxdlgcTi5nQDMKZM3yYaNX9stVbs9s8LXmGNmdDwBDq3JYPpoA52NWdt+52EYDeOaTn8CHQ==
X-Received: by 2002:a9d:171a:: with SMTP id i26mr18459041ota.260.1605100925663;
        Wed, 11 Nov 2020 05:22:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls3906550oie.2.gmail; Wed, 11 Nov
 2020 05:22:05 -0800 (PST)
X-Received: by 2002:aca:c70b:: with SMTP id x11mr2145692oif.58.1605100925282;
        Wed, 11 Nov 2020 05:22:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605100925; cv=none;
        d=google.com; s=arc-20160816;
        b=HD7p3JwB4b9ZSpTrSq4dVTqxk9XgbpIDlwvCelZTQx2efUFveIwHBQIBMALjcFUAlY
         9ibV8mdIYQ/mrGpWP6Z3P5M09pM2vVWzy/9ZjRXh7d5p3KLY1Ea8RCEUphiSmkGLhUFu
         ngEMuaxQQjxHZchlOuOxcbDzj52xTT0lQBpXOqKrD8OCFDp3PifbbmvDYs8tFRdeXvtJ
         p+Zt0roAPjz4bjmRETWqWa/Z29LgKi4gcLmG/nzvMIoSNYTJSzqC2o/wPvey8blKwYWZ
         WpcloYEXNAQbk3qiWlfO4JzaCS9K7Qru9lBzhqQB0CmK4T2aKgXQ3df6Xrxl9GEs9c3m
         abOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+bz5ZIdNzpU0ai7uZOTCO8K/nvk/MwhwV4tVntYFBxU=;
        b=MeSrt265iwDA+UCLdDzZZvG7Nh/aRg/cN0EGAUcTKYFXJvdvTKssIAMPOz0FuO+6T2
         l1pK0wJ44juuIdBHx+vXnfSlOy8Y8hrEeEvbVeqLgGWuqrfMQ8qM7URpIgUPFQCly/iO
         9Gg/PfTOjAoV9Yruh8dNztBrPMN6jB+jt/ZGkmrC89bqOyladojD2sCKOU2mLUuyoo+v
         hK0Ep2c6jIr9dV2vYsCe6BimGh1n92ZJV/bf6Xs7un9oohkD7n8sMHNEpNS9TcCfehBr
         4k2o+RFseebbqy4wu/snWg159hLADVMvJPNKCo8DlbK+rV2bOVD2UMsEn46sK/+j0LxE
         /rlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="I8TMNct/";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id e22si185366oti.2.2020.11.11.05.22.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 05:22:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id 13so836269qvr.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 05:22:05 -0800 (PST)
X-Received: by 2002:a05:6214:d43:: with SMTP id 3mr3584715qvr.38.1605100924596;
 Wed, 11 Nov 2020 05:22:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <4d261d4cbd9842c51cb6f9b36cadc9054cabe86b.1605046192.git.andreyknvl@google.com>
In-Reply-To: <4d261d4cbd9842c51cb6f9b36cadc9054cabe86b.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 14:21:52 +0100
Message-ID: <CAG_fn=VseeYfkzogUaqj6hqSjZzaEGe=0jkQYRu=2S0m7Vrd=g@mail.gmail.com>
Subject: Re: [PATCH v9 03/44] kasan: group vmalloc code
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="I8TMNct/";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f44 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Group all vmalloc-related function declarations in include/linux/kasan.h,
> and their implementations in mm/kasan/common.c.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: Ie20b6c689203cd6de4fd7f2c465ec081c00c5f15
> ---
>  include/linux/kasan.h | 41 +++++++++++++----------
>  mm/kasan/common.c     | 78 ++++++++++++++++++++++---------------------
>  2 files changed, 63 insertions(+), 56 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 30d343b4a40a..59538e795df4 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -75,19 +75,6 @@ struct kasan_cache {
>         int free_meta_offset;
>  };
>
> -/*
> - * These functions provide a special case to support backing module
> - * allocations with real shadow memory. With KASAN vmalloc, the special
> - * case is unnecessary, as the work is handled in the generic case.
> - */
> -#ifndef CONFIG_KASAN_VMALLOC
> -int kasan_module_alloc(void *addr, size_t size);
> -void kasan_free_shadow(const struct vm_struct *vm);
> -#else
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
> -static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> -#endif
> -
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>
> @@ -156,9 +143,6 @@ static inline bool kasan_slab_free(struct kmem_cache =
*s, void *object,
>         return false;
>  }
>
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
> -static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> -
>  static inline int kasan_add_zero_shadow(void *start, unsigned long size)
>  {
>         return 0;
> @@ -211,13 +195,16 @@ static inline void *kasan_reset_tag(const void *add=
r)
>  #endif /* CONFIG_KASAN_SW_TAGS */
>
>  #ifdef CONFIG_KASAN_VMALLOC
> +
>  int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
>  void kasan_poison_vmalloc(const void *start, unsigned long size);
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size);
>  void kasan_release_vmalloc(unsigned long start, unsigned long end,
>                            unsigned long free_region_start,
>                            unsigned long free_region_end);
> -#else
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
>  static inline int kasan_populate_vmalloc(unsigned long start,
>                                         unsigned long size)
>  {
> @@ -232,7 +219,25 @@ static inline void kasan_release_vmalloc(unsigned lo=
ng start,
>                                          unsigned long end,
>                                          unsigned long free_region_start,
>                                          unsigned long free_region_end) {=
}
> -#endif
> +
> +#endif /* CONFIG_KASAN_VMALLOC */
> +
> +#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
> +
> +/*
> + * These functions provide a special case to support backing module
> + * allocations with real shadow memory. With KASAN vmalloc, the special
> + * case is unnecessary, as the work is handled in the generic case.
> + */
> +int kasan_module_alloc(void *addr, size_t size);
> +void kasan_free_shadow(const struct vm_struct *vm);
> +
> +#else /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
> +
> +static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
> +static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> +
> +#endif /* CONFIG_KASAN && !CONFIG_KASAN_VMALLOC */
>
>  #ifdef CONFIG_KASAN_INLINE
>  void kasan_non_canonical_hook(unsigned long addr);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 33d863f55db1..89e5ef9417a7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -536,44 +536,6 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>         /* The object will be poisoned by page_alloc. */
>  }
>
> -#ifndef CONFIG_KASAN_VMALLOC
> -int kasan_module_alloc(void *addr, size_t size)
> -{
> -       void *ret;
> -       size_t scaled_size;
> -       size_t shadow_size;
> -       unsigned long shadow_start;
> -
> -       shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> -       scaled_size =3D (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_=
SHIFT;
> -       shadow_size =3D round_up(scaled_size, PAGE_SIZE);
> -
> -       if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> -               return -EINVAL;
> -
> -       ret =3D __vmalloc_node_range(shadow_size, 1, shadow_start,
> -                       shadow_start + shadow_size,
> -                       GFP_KERNEL,
> -                       PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> -                       __builtin_return_address(0));
> -
> -       if (ret) {
> -               __memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -               find_vm_area(addr)->flags |=3D VM_KASAN;
> -               kmemleak_ignore(ret);
> -               return 0;
> -       }
> -
> -       return -ENOMEM;
> -}
> -
> -void kasan_free_shadow(const struct vm_struct *vm)
> -{
> -       if (vm->flags & VM_KASAN)
> -               vfree(kasan_mem_to_shadow(vm->addr));
> -}
> -#endif
> -
>  #ifdef CONFIG_MEMORY_HOTPLUG
>  static bool shadow_mapped(unsigned long addr)
>  {
> @@ -685,6 +647,7 @@ core_initcall(kasan_memhotplug_init);
>  #endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
> +
>  static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>                                       void *unused)
>  {
> @@ -923,4 +886,43 @@ void kasan_release_vmalloc(unsigned long start, unsi=
gned long end,
>                                        (unsigned long)shadow_end);
>         }
>  }
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
> +int kasan_module_alloc(void *addr, size_t size)
> +{
> +       void *ret;
> +       size_t scaled_size;
> +       size_t shadow_size;
> +       unsigned long shadow_start;
> +
> +       shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> +       scaled_size =3D (size + KASAN_SHADOW_MASK) >> KASAN_SHADOW_SCALE_=
SHIFT;
> +       shadow_size =3D round_up(scaled_size, PAGE_SIZE);
> +
> +       if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> +               return -EINVAL;
> +
> +       ret =3D __vmalloc_node_range(shadow_size, 1, shadow_start,
> +                       shadow_start + shadow_size,
> +                       GFP_KERNEL,
> +                       PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> +                       __builtin_return_address(0));
> +
> +       if (ret) {
> +               __memset(ret, KASAN_SHADOW_INIT, shadow_size);
> +               find_vm_area(addr)->flags |=3D VM_KASAN;
> +               kmemleak_ignore(ret);
> +               return 0;
> +       }
> +
> +       return -ENOMEM;
> +}
> +
> +void kasan_free_shadow(const struct vm_struct *vm)
> +{
> +       if (vm->flags & VM_KASAN)
> +               vfree(kasan_mem_to_shadow(vm->addr));
> +}
> +
>  #endif
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVseeYfkzogUaqj6hqSjZzaEGe%3D0jkQYRu%3D2S0m7Vrd%3Dg%40mai=
l.gmail.com.
