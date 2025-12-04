Return-Path: <kasan-dev+bncBDW2JDUY5AORBK7SY3EQMGQEAXARFCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A9A56CA48D0
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:39:09 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-37a4fb06b1fsf4942411fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 08:39:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764866349; cv=pass;
        d=google.com; s=arc-20240605;
        b=QgTKqG8pzKY5CnV1oFCsq/M5xl12Y9NqkTLV4EyuCrc/fvl92mI572CWVWgrIu8hGy
         juMzW31vCWikQzQkzb9iaDxIgexyWP/3DSSmyG1n4O1yqXmgLCmvya8zxygqAkbWS26Z
         57qm4j9rPpJfuNvs20NghIWFhGXxscqTYWJwPBCG56/JGUFHCqB42gEIU3n1UVCFhexn
         xRKZbd4/pJsj9W0lvBzAA2USzhM0mBNiP89DXbWds+C+kUeBswHD8bKuY1w06JbpgxnR
         7X0ewge8uSBIajfjx10wkbm6+KN2NClmlYdGJb40pGpES6A1TOSt5zjXCGtHrsA24A1P
         tKnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fTURhUPhy+rCBUp5ZxpAsHbhyKrGOUtdF7PMoq0uw1A=;
        fh=kDW593FFPlR4BhgDuvmft/7RM2qO1Hn9kT1wyWwktF0=;
        b=C+YGMDWC6CYgXg9fT498eborpliM6C/IJiy6iieWzxinjWOuvnQFcJ/xX9ql8R1Wnh
         7mLxMi6ZDurB47hS97/v29KdIj75VM+nJ6BB3ObE8diN5qYCaRXTxBEo99c+B/ldGvGc
         or0/WsFshArYM8zHNeeR1q/sjMYCOfMjJTo5fVX5kHZHgjWX4IqtGa2iMblZFL6gKVmR
         iA/mjQIMimzk24oRGha7oEckOvGyXtPNRjmdcHmuxLSYFyXNuXqv3r1wGgEYG9r2a7Kp
         gOyU5d633POBcy1WBKlKzdTUa9vqz6x48f7A+T2VPi/RZNhSFz+Vy2ABSu07sGMmwJ79
         vjlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ESjv8QCO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764866349; x=1765471149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fTURhUPhy+rCBUp5ZxpAsHbhyKrGOUtdF7PMoq0uw1A=;
        b=lEv+ymVfRpS+HcHKQrVeSftOeOyCdvc4pcais0dH09rhRHN8jL3t1krKortDbz9fZL
         I7GibybYNTmv7pTUHDOvktunn6pgwJz1sVZQxVStLHAx391sd0hbvJM6vOYu/64CuTYB
         T8+P+ob7ubkwJtDpDIGIaRz8pcvEbq6OSWNb+ERD8YmhQq45cIVDhT3J+NMUL7dtpYxi
         IyyOQ1ohfgyBP1JXDUSTQPSaB6dLeUblk/IWjeUb2NLkfiYsA9KXT+og1U02cqrsjOTC
         r6iwrj/1VHgvJpdcD6f+nQp9YWWFYSozDTkI2QI54mbjaBYuAXcaANxkoMwISZ4u/+67
         6/eA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764866349; x=1765471149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fTURhUPhy+rCBUp5ZxpAsHbhyKrGOUtdF7PMoq0uw1A=;
        b=WQdOG+35iwM3VtJLuZw45W9KgJCqn1ObyM47LUS9rUUy/c64BCq/sfFevLm7IhZULu
         Dr3EaQylUsnLd9j+Opq9ZQYU3PKWI0Hb88i8C3oHpi6z0w5tZ9NTg7fG5HGMIZQ6DL+B
         lSBy2k1ktAtJLDGcAjrHNhCkInFhvqaEqxw8KmEzV+jnbvfT4WE+dUNHqLLWBhMmHYpC
         ElVzcJW7X/QgRTSYBMCJ4F5XCdanejhns8yCPC2AHyRGxdkjNF2O0n2QFM19AY0UJo0C
         DkfudDCb5w/PFxWi5hXWvFL/trocnTsITt2GxzUVlO8y65UgR0bxpJ6mV2M++COjVT1Q
         8D7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764866349; x=1765471149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fTURhUPhy+rCBUp5ZxpAsHbhyKrGOUtdF7PMoq0uw1A=;
        b=dOKlnrvwSOua+duaO8KTX1Ra7YNVCZBediGHpTrefswiRhZ/kucqVA647hUof9Ee9s
         ZI5S7S17nmNUqcEDvZctKkUs48K7U93uk4UpQsqf9SbgnHZlS+0lXj7Ox91TS9lWZBqg
         ZGjtfuInmVnf3QciPaEINJFClp2A+tT6KLZ7XGlJAPqkqFrCCI8KGQrEaJ/iURDxXt7w
         /zXu7RP82iPxd7ecuvuOz70SzSBnkGvJaXDmasJ1fiXa8/eUc8LW+KUEF/i5aTs1fRss
         A7ngS6tasLEs2qtTgBzC5tIi5G7dsT3y58CYXMlx7gbQKVC9mYC/SneXhGGY7ejmG7ik
         Flrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzsNjuq4KT9oIy/SU53+DSd4DplSeYPzyyXbivhhv+FviXYt7D43SZJy5gl+W6DaT9dnRyFw==@lfdr.de
X-Gm-Message-State: AOJu0YwmoEWLnw5NsBdSFC21VKUNMYwzDz+OYQ67BTqpImikKur5qHk0
	15NXosIdh8DrwUshtqEXpCb+8JCz7hb1I4DaFMQa4gpC6wpZHb1vxY02
X-Google-Smtp-Source: AGHT+IEtLXr55U/F6vnxI4j/xyxAeA5BMzIGOBmTGf8NiMXEFPxS7MmHoCXFFiJqCHr3FQVfjzHrwQ==
X-Received: by 2002:a05:6512:3d93:b0:595:91c5:3dd8 with SMTP id 2adb3069b0e04-597d66bcd19mr1185949e87.26.1764866348597;
        Thu, 04 Dec 2025 08:39:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bceqVONYaOP1nk2+VU55pbG645GkITbw6IZ/S8Sx1NxA=="
Received: by 2002:ac2:5693:0:b0:597:d607:45f3 with SMTP id 2adb3069b0e04-597d6d56f5als315583e87.1.-pod-prod-07-eu;
 Thu, 04 Dec 2025 08:39:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3eT8H2ddw/7SHgfiopCLvnoHyrV7ryfxKz6D7Ek30tFeroEsZIdGiaGj6GtGgszD4sXnoj9GKlZ4=@googlegroups.com
X-Received: by 2002:a05:6512:3e1e:b0:592:f2fc:51f0 with SMTP id 2adb3069b0e04-597d66bd8bdmr1152578e87.30.1764866345580;
        Thu, 04 Dec 2025 08:39:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764866345; cv=none;
        d=google.com; s=arc-20240605;
        b=klB2laI9xqIs/sDnm4jnTXbqt2KdP4lGM51SiaCqYGnal6gIJ0cGuXzl69hk8YIUXA
         uTzoC0DlhEFzONX25QjPnDGLVKYZ14R/cer8OzpI8sqUbQu00+CNWEhzKua5uq2LFpGq
         RD3VtiT0bXDnR1NNk7dJFnLJqkHHbqeHD/J6MdmMXz5K+ZAOrLr3UPs9Vj2cbFujfVCj
         vrSMPZS2ZQEbv8bVrQITD0LZ267C2NNw+WDDdE7gXLwf5wgCRKXuvGIS3m/5zBM78eWQ
         itVxKK19Z7/+6XaCVJnhg1AInr0mYKTPXSxh/kA9kzdT1Saw5Ybgero1gIwKrKkGQDpo
         qLpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=neM2aFFGXkdhFk1Bgngnbt+CCpd3u3ncCxbfP639ydc=;
        fh=7VRk2kycxLl89uJ/PqVoR6RHCRtmkkY7oPrSDRVcjxg=;
        b=bd/8NhSJSI0LFYzS00lbm9u23mjlclJUN085kP6XKhCW95L/u02CQRzjAjMhBAkf4m
         6IHqedrR1GkggaHUcGFsL0pVLFVxNGpW01xA5f2g6eHrb4HNrhgJWFdJOiVxDYeoWfD3
         v1tr4mP8c16QW7YMBEwbRTtwODCGZPJKC3oKFbCQdTIhMZE/A4dF7FqCKFmjJerzMVeQ
         ooMGUr6mQ3vU4R7QPwl6v+vgPCzo2qP0z4zYqBsotR5YvYgXGEVJxo0hp+wXLXPZlONh
         BJx14fSEP3JDPiAcB8o9JQThOHQrmA81lFX4+qFgkz3rBvJkvKaLdqBUIN751FcvvhoY
         8rZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ESjv8QCO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-597d7abca95si39698e87.0.2025.12.04.08.39.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 08:39:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-42e2e47be25so668042f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 08:39:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXKfuZ1nO+JcZguhi2AvimbYFnLNQUJf8E5q8mGh2b3Cs0171NutnzkLwo/n50WbZqXNGDC9l0zUzM=@googlegroups.com
X-Gm-Gg: ASbGnctb8R1AQjqXOOuIZbIYcQJh0yBTu9Ms3IosYRZyCQOEamJn8FbdTYf2LfnAwm1
	idBvmtDsu3T9PpZbjZLLbey0TQ1v6MmRzplS+ASJXC5DSZ07ZSz0gt6YvsRsT+WI3WTxZeHxgoa
	Up7SONBPdg0aiGpNTNF50aGD3qytMomw9MUTdM3Cn2/4X+Tkd4lO4xbeO92m1VHSyRNS22hrAKO
	vzFz6dOzwlzi6Vs1i0KOO6YF2C7XjaMwzjB9KZLH+LV2B6WqncBcueMW96ZHSc89D3Kl/274eyi
	/IjfwX6VfVKZl+fHrGC1Ikdt0LlnE3Zk0KNx11k=
X-Received: by 2002:a5d:5f84:0:b0:42c:a449:d6ab with SMTP id
 ffacd0b85a97d-42f7984151bmr3587206f8f.30.1764866344934; Thu, 04 Dec 2025
 08:39:04 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-2-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-2-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 17:38:54 +0100
X-Gm-Features: AWmQ_bkK3QIZDgXBUmjiM3wqIjjTq9eL1_nc5mEHts5eDeieA_K5fYtO6D27Mp0
Message-ID: <CA+fCnZfDYHUVKX-hdX3SgmuvJEU-U+MuUJGjs-wJJnfRDHz2sw@mail.gmail.com>
Subject: Re: [PATCH v4 01/12] mm/kasan: add conditional checks in functions to
 return directly if kasan is disabled
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ESjv8QCO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> The current codes only check if kasan is disabled for hw_tags
> mode. Here add the conditional checks for functional functions of
> generic mode and sw_tags mode.
>
> This is prepared for later adding kernel parameter kasan=3Don|off for
> all three kasan modes.
>
> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  mm/kasan/generic.c    | 17 +++++++++++++++--
>  mm/kasan/init.c       |  6 ++++++
>  mm/kasan/quarantine.c |  3 +++
>  mm/kasan/report.c     |  4 +++-
>  mm/kasan/shadow.c     | 11 ++++++++++-
>  mm/kasan/sw_tags.c    |  3 +++
>  6 files changed, 40 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 2b8e73f5f6a7..aff822aa2bd6 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -214,12 +214,13 @@ bool kasan_byte_accessible(const void *addr)
>
>  void kasan_cache_shrink(struct kmem_cache *cache)
>  {
> -       kasan_quarantine_remove_cache(cache);
> +       if (kasan_enabled())

Please move these checks to include/linux/kasan.h and add __helpers to
consistent with how it's done for other KASAN annotation calls.
Otherwise eventually these checks start creeping into lower level
functions and the logic of checking when and whether KASAN is enabled
becomes a mess.



> +               kasan_quarantine_remove_cache(cache);
>  }
>
>  void kasan_cache_shutdown(struct kmem_cache *cache)
>  {
> -       if (!__kmem_cache_empty(cache))
> +       if (kasan_enabled() && !__kmem_cache_empty(cache))
>                 kasan_quarantine_remove_cache(cache);
>  }
>
> @@ -239,6 +240,9 @@ void __asan_register_globals(void *ptr, ssize_t size)
>         int i;
>         struct kasan_global *globals =3D ptr;
>
> +       if (!kasan_enabled())
> +               return;
> +
>         for (i =3D 0; i < size; i++)
>                 register_global(&globals[i]);
>  }
> @@ -369,6 +373,9 @@ void kasan_cache_create(struct kmem_cache *cache, uns=
igned int *size,
>         unsigned int rem_free_meta_size;
>         unsigned int orig_alloc_meta_offset;
>
> +       if (!kasan_enabled())
> +               return;
> +
>         if (!kasan_requires_meta())
>                 return;
>
> @@ -518,6 +525,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache, =
bool in_object)
>  {
>         struct kasan_cache *info =3D &cache->kasan_info;
>
> +       if (!kasan_enabled())
> +               return 0;
> +
>         if (!kasan_requires_meta())
>                 return 0;
>
> @@ -543,6 +553,9 @@ void kasan_record_aux_stack(void *addr)
>         struct kasan_alloc_meta *alloc_meta;
>         void *object;
>
> +       if (!kasan_enabled())
> +               return;
> +
>         if (is_kfence_address(addr) || !slab)
>                 return;
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index f084e7a5df1e..c78d77ed47bc 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -447,6 +447,9 @@ void kasan_remove_zero_shadow(void *start, unsigned l=
ong size)
>         unsigned long addr, end, next;
>         pgd_t *pgd;
>
> +       if (!kasan_enabled())
> +               return;
> +
>         addr =3D (unsigned long)kasan_mem_to_shadow(start);
>         end =3D addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
> @@ -482,6 +485,9 @@ int kasan_add_zero_shadow(void *start, unsigned long =
size)
>         int ret;
>         void *shadow_start, *shadow_end;
>
> +       if (!kasan_enabled())
> +               return 0;
> +
>         shadow_start =3D kasan_mem_to_shadow(start);
>         shadow_end =3D shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 6958aa713c67..a6dc2c3d8a15 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -405,6 +405,9 @@ static int __init kasan_cpu_quarantine_init(void)
>  {
>         int ret =3D 0;
>
> +       if (!kasan_enabled())
> +               return 0;
> +
>         ret =3D cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online",
>                                 kasan_cpu_online, kasan_cpu_offline);
>         if (ret < 0)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 62c01b4527eb..884357fa74ed 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -576,7 +576,9 @@ bool kasan_report(const void *addr, size_t size, bool=
 is_write,
>         unsigned long irq_flags;
>         struct kasan_report_info info;
>
> -       if (unlikely(report_suppressed_sw()) || unlikely(!report_enabled(=
))) {
> +       if (unlikely(report_suppressed_sw()) ||
> +           unlikely(!report_enabled()) ||
> +           !kasan_enabled()) {
>                 ret =3D false;
>                 goto out;
>         }
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 29a751a8a08d..f73a691421de 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -164,6 +164,8 @@ void kasan_unpoison(const void *addr, size_t size, bo=
ol init)
>  {
>         u8 tag =3D get_tag(addr);
>
> +       if (!kasan_enabled())
> +               return;
>         /*
>          * Perform shadow offset calculation based on untagged address, a=
s
>          * some of the callers (e.g. kasan_unpoison_new_object) pass tagg=
ed
> @@ -277,7 +279,8 @@ static int __meminit kasan_mem_notifier(struct notifi=
er_block *nb,
>
>  static int __init kasan_memhotplug_init(void)
>  {
> -       hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PRI)=
;
> +       if (kasan_enabled())
> +               hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLB=
ACK_PRI);
>
>         return 0;
>  }
> @@ -658,6 +661,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size=
, gfp_t gfp_mask)
>         size_t shadow_size;
>         unsigned long shadow_start;
>
> +       if (!kasan_enabled())
> +               return 0;
> +
>         shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
>         scaled_size =3D (size + KASAN_GRANULE_SIZE - 1) >>
>                                 KASAN_SHADOW_SCALE_SHIFT;
> @@ -694,6 +700,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size=
, gfp_t gfp_mask)
>
>  void kasan_free_module_shadow(const struct vm_struct *vm)
>  {
> +       if (!kasan_enabled())
> +               return;
> +
>         if (IS_ENABLED(CONFIG_UML))
>                 return;
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index c75741a74602..6c1caec4261a 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -79,6 +79,9 @@ bool kasan_check_range(const void *addr, size_t size, b=
ool write,
>         u8 *shadow_first, *shadow_last, *shadow;
>         void *untagged_addr;
>
> +       if (!kasan_enabled())
> +               return true;
> +
>         if (unlikely(size =3D=3D 0))
>                 return true;
>
> --
> 2.41.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfDYHUVKX-hdX3SgmuvJEU-U%2BMuUJGjs-wJJnfRDHz2sw%40mail.gmail.com.
