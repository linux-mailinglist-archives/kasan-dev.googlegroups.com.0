Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZVU26FAMGQEGOWESPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8947C41DDC3
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 17:40:23 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id n15-20020ad44a2f000000b0038288117acdsf10962963qvz.23
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 08:40:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633016422; cv=pass;
        d=google.com; s=arc-20160816;
        b=CHU67Qqocjs9Su0ZU4fXbOfExkw/Rd/hnkqgIIfsn9tK6jNv/Ikp0FUIqE6xAr/W70
         7H4iOsG3ZGCEbRRod4GhxDeR5UjPeRVDzfc50+cbBFfxu3U4AUyHkO/SITk9L/QDUkvy
         vek4pYYrhWuTu5sLeqafnzkMY+9vpCBY7b+Laxtu0DPbE24avlWM0sB8GnwKX9UJbx8m
         7ehHmIcgmVQb3hnrpgEYQN/w5BXbDzKM33GTjvuMiV+VSpFaKyT1s8CMMnPsz9o8VTQ4
         S8H0bG3OPwDrso99GxraCK7zYYdPblAuv/tFLF4A1Ebzz8NAigHxDUZpr4Q+iC1i4WSE
         GUqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NBZ1WYburZUqwkjOdy6yNfIG1EtrNLMmJnsJ9Rym4oY=;
        b=xkWNlEPY84KOx42fIFGzUsQjiK5awO12jhVL4OuYdtG8OYFj2ZvI+bF6ojDBdGoaJe
         q9cY9jnFnBtU360qFN4JsjjUqzyM4HIRNdRh7f3OdxQtGK7IRS96lQKAcv4mT7fnHCIG
         XtHweW0t/ibICadYQ7TcB1N68muoLwIPf9n/DiFy57idp2w8YNZo7VAagmHLaHLY2oTc
         +9ObHS7/4pNA2n71mxIdLLc4UHcmKZocr+USDB1GYY7ETtywM+wa8pwcx88OzxhigQ3U
         KEQydhnfxpjG6rJ4y9H3LIS7dmXokZSXYev/KhCG43Tb8Cq+S77nCopobORIZuqWX2zT
         MdWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dESEuhyj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=NBZ1WYburZUqwkjOdy6yNfIG1EtrNLMmJnsJ9Rym4oY=;
        b=SUvhcP5EovWycHk7f5UXTeA6hVgwVb8PPjBva750NQrUQL/35vcKg3rj8H7QU4NLhu
         XcYhSJ6329OhNpvUsBkD9LT0cuu7chsI9hBTVtc3WY96PYWFET6LsePMHz3CmcBFCNcc
         zxSv9a20lvwzk/5MqyCm2J0ZZljw08SbkYtU6DVJQ4bfaemZtpLWEwg1vbEuZ8dYpXKY
         okjUvvDivPm81EvZTppQ7pplz8PR0eYP7Uxm1cudL+5nz29XshcDUgIHmjWxF2sON0Uk
         ou4dkD/CckeXhQC7c2pA4UBX4W8z3j9KAvj0MTYwv64m93LX6x3jGs22ow0MfYbO/+xX
         H+fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NBZ1WYburZUqwkjOdy6yNfIG1EtrNLMmJnsJ9Rym4oY=;
        b=uU6XdJZahL1x0KbYVo54JPxJ3o8HW0EuWKhek3ueTPoXwmyv5N0z/gixjlMlnypeRx
         0Fc08lghp9CQYY1qG9aXPUXGaje+YOnzD6USUwNqvZWCZDQkiwidEtpqaMtx5zZaxn1P
         I8FJnpwVGblfpIiZ+g+wHWRPHLi061IXGDCMhZzCXgHy4P0ApmKikpUnZm+y25QnLIOq
         0kQeDWKRW1OGkUX7AUf+ECVze/8Q0MNr2anmL21TZpyvCgKO6h3Adsp4wbqkXZfURlE7
         RN9IYOyypH+7EuZwQcSy1c1tpWGTemhZeZOzmASu8J/ZiTgPleY6xlLmmx0NM2w+Mjv7
         3Cxw==
X-Gm-Message-State: AOAM532PM8gKAA1/H6wU/kR3KZDRLF+bMqLFqDHQOkmBQZ/vLB5UF504
	HoIETEy3/Wc+NZOefv/lMgQ=
X-Google-Smtp-Source: ABdhPJxYOWURwaHFpblyVXoopEYIIltWA5JdL1SDLlridjma8XlRBe15MUwawpRSNYo/mE8Jl+jFeg==
X-Received: by 2002:ac8:4084:: with SMTP id p4mr7461110qtl.255.1633016422271;
        Thu, 30 Sep 2021 08:40:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:14a8:: with SMTP id x8ls4460325qkj.8.gmail; Thu, 30
 Sep 2021 08:40:21 -0700 (PDT)
X-Received: by 2002:a37:687:: with SMTP id 129mr5345401qkg.10.1633016421790;
        Thu, 30 Sep 2021 08:40:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633016421; cv=none;
        d=google.com; s=arc-20160816;
        b=jx2c5xsFBVAenyTb+5XLgW6HMYVl7yOhaOP9AiA3P6gg/FWLRG9DyX7eXMTHI5j/D+
         zYC3Gb2QgTb99IY+zMqanOIOrtXjUTIlo/TKXof40fAkoNs8OelnUiYuANE2dqswBh00
         NV5+QSGRxbHx/RRv2K6vgfwdVJM+a1a73nkUy2UxH5pwfQAbXdSaHN1Eo3jm2FdlWz++
         DmKmh7M2d23IJGnU6gRCr/R6QMpqtza12u+2XJf3dru9u79uwBiYYGURyDmMnYDwr4fI
         k+IXzZdjhd5L2jM83Qz2nx1+5XjCReDQopoAayv9muoj4n9LRSxsVmbcG+NpxmtL/x9A
         GNww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rk528hO09V+xXN91B1hSKF0BEg5FNswtyGgnAwkONyI=;
        b=MSxU1bdwbITX3sZOJ3G135qgAVEk/HeP/6fjXqvpvG2oqNwdOMejSzIywqK8wCWONk
         ot0Ztrw7z51Frfp/QXNCbXbZR5WX0pG3xRmQ1s6w1zyijjyqN3ex79vsTdHxnXBEuzEP
         aOBB7trCB6kqpzeN7fne05Q0o4LKMdsfaXjeItshTUE7QQ8cU+QZvKvtcyA3uXUplQxZ
         ZArpZAyea8vl8FvlZ56SUKIvUgmBqIMmrRXry1DQ8hgQvAbaDMrYYHOGGZIqkk/OwIZR
         Cs4MTYenEYo+I14elY9VIZPmG8rLB7Q0KAu+/4b+T6oeyH6cHwt+Q53eBlOD/SeDuFGq
         RtXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dESEuhyj;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id 11si444508qtu.5.2021.09.30.08.40.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Sep 2021 08:40:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id 72so6215735qkk.7
        for <kasan-dev@googlegroups.com>; Thu, 30 Sep 2021 08:40:21 -0700 (PDT)
X-Received: by 2002:a37:5446:: with SMTP id i67mr5480440qkb.502.1633016421262;
 Thu, 30 Sep 2021 08:40:21 -0700 (PDT)
MIME-Version: 1.0
References: <20210930153706.2105471-1-elver@google.com>
In-Reply-To: <20210930153706.2105471-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Sep 2021 17:39:44 +0200
Message-ID: <CAG_fn=XmtwrqdDwMmKeiJCwKWBEFphfgBHYq0FPOjCZm-mV2+w@mail.gmail.com>
Subject: Re: [PATCH] kfence: shorten critical sections of alloc/free
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dESEuhyj;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as
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

On Thu, Sep 30, 2021 at 5:37 PM Marco Elver <elver@google.com> wrote:
>
> Initializing memory and setting/checking the canary bytes is relatively
> expensive, and doing so in the meta->lock critical sections extends the
> duration with preemption and interrupts disabled unnecessarily.
>
> Any reads to meta->addr and meta->size in kfence_guarded_alloc() and
> kfence_guarded_free() don't require locking meta->lock as long as the
> object is removed from the freelist: only kfence_guarded_alloc() sets
> meta->addr and meta->size after removing it from the freelist,  which
> requires a preceding kfence_guarded_free() returning it to the list or
> the initial state.
>
> Therefore move reads to meta->addr and meta->size, including expensive
> memory initialization using them, out of meta->lock critical sections.
>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kfence/core.c | 38 +++++++++++++++++++++-----------------
>  1 file changed, 21 insertions(+), 17 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index b61ef93d9f98..802905b1c89b 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -309,12 +309,19 @@ static inline bool set_canary_byte(u8 *addr)
>  /* Check canary byte at @addr. */
>  static inline bool check_canary_byte(u8 *addr)
>  {
> +       struct kfence_metadata *meta;
> +       unsigned long flags;
> +
>         if (likely(*addr =3D=3D KFENCE_CANARY_PATTERN(addr)))
>                 return true;
>
>         atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
> -       kfence_report_error((unsigned long)addr, false, NULL, addr_to_met=
adata((unsigned long)addr),
> -                           KFENCE_ERROR_CORRUPTION);
> +
> +       meta =3D addr_to_metadata((unsigned long)addr);
> +       raw_spin_lock_irqsave(&meta->lock, flags);
> +       kfence_report_error((unsigned long)addr, false, NULL, meta, KFENC=
E_ERROR_CORRUPTION);
> +       raw_spin_unlock_irqrestore(&meta->lock, flags);
> +
>         return false;
>  }
>
> @@ -324,8 +331,6 @@ static __always_inline void for_each_canary(const str=
uct kfence_metadata *meta,
>         const unsigned long pageaddr =3D ALIGN_DOWN(meta->addr, PAGE_SIZE=
);
>         unsigned long addr;
>
> -       lockdep_assert_held(&meta->lock);
> -
>         /*
>          * We'll iterate over each canary byte per-side until fn() return=
s
>          * false. However, we'll still iterate over the canary bytes to t=
he
> @@ -414,8 +419,9 @@ static void *kfence_guarded_alloc(struct kmem_cache *=
cache, size_t size, gfp_t g
>         WRITE_ONCE(meta->cache, cache);
>         meta->size =3D size;
>         meta->alloc_stack_hash =3D alloc_stack_hash;
> +       raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> -       for_each_canary(meta, set_canary_byte);
> +       alloc_covered_add(alloc_stack_hash, 1);
>
>         /* Set required struct page fields. */
>         page =3D virt_to_page(meta->addr);
> @@ -425,11 +431,8 @@ static void *kfence_guarded_alloc(struct kmem_cache =
*cache, size_t size, gfp_t g
>         if (IS_ENABLED(CONFIG_SLAB))
>                 page->s_mem =3D addr;
>
> -       raw_spin_unlock_irqrestore(&meta->lock, flags);
> -
> -       alloc_covered_add(alloc_stack_hash, 1);
> -
>         /* Memory initialization. */
> +       for_each_canary(meta, set_canary_byte);
>
>         /*
>          * We check slab_want_init_on_alloc() ourselves, rather than lett=
ing
> @@ -454,6 +457,7 @@ static void kfence_guarded_free(void *addr, struct kf=
ence_metadata *meta, bool z
>  {
>         struct kcsan_scoped_access assert_page_exclusive;
>         unsigned long flags;
> +       bool init;
>
>         raw_spin_lock_irqsave(&meta->lock, flags);
>
> @@ -481,6 +485,13 @@ static void kfence_guarded_free(void *addr, struct k=
fence_metadata *meta, bool z
>                 meta->unprotected_page =3D 0;
>         }
>
> +       /* Mark the object as freed. */
> +       metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
> +       init =3D slab_want_init_on_free(meta->cache);
> +       raw_spin_unlock_irqrestore(&meta->lock, flags);
> +
> +       alloc_covered_add(meta->alloc_stack_hash, -1);
> +
>         /* Check canary bytes for memory corruption. */
>         for_each_canary(meta, check_canary_byte);
>
> @@ -489,16 +500,9 @@ static void kfence_guarded_free(void *addr, struct k=
fence_metadata *meta, bool z
>          * data is still there, and after a use-after-free is detected, w=
e
>          * unprotect the page, so the data is still accessible.
>          */
> -       if (!zombie && unlikely(slab_want_init_on_free(meta->cache)))
> +       if (!zombie && unlikely(init))
>                 memzero_explicit(addr, meta->size);
>
> -       /* Mark the object as freed. */
> -       metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
> -
> -       raw_spin_unlock_irqrestore(&meta->lock, flags);
> -
> -       alloc_covered_add(meta->alloc_stack_hash, -1);
> -
>         /* Protect to detect use-after-frees. */
>         kfence_protect((unsigned long)addr);
>
> --
> 2.33.0.685.g46640cef36-goog
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
kasan-dev/CAG_fn%3DXmtwrqdDwMmKeiJCwKWBEFphfgBHYq0FPOjCZm-mV2%2Bw%40mail.gm=
ail.com.
