Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN5O4OPAMGQEZU6JWDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id C64C568279F
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 09:54:16 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id x29-20020ab05add000000b0050f5111c4f0sf5410355uae.5
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 00:54:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675155255; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMU1/ZA+10wDKRx4t5V+NYfYh93yqnINB2ZhBqGZ0FM7mPGhCbB137DHtxwdNn6yAE
         8obJml7IVlqnzAPDWuACqu8hXqY53Hbge8QPkMSs+utAJU6pab2BXe8MdrOo/guuaYoP
         6Nky1F2I6D4q1l1klZCb9vl/606B1d/SK1vGn2tu+ZXlQYAImYqXRvQ+SFxhn98Wkktn
         ldi9dGqU05u59m1Z5E1JDkYM8obAwPCUrSFKG9darbdEAwynbTwUUv0DBfKDtZOieiFr
         1Pdlxeq1PoO/cOsQhdbNXFfzH5QIJaOp+prfS1r5VDrlBNE043HgQCtKIGLeUPBUmGDU
         Sx5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xBgF4y5Xf4jEAKTeZhhDCcFT23H231N41d9v2bm0hHs=;
        b=tJ8U4HuZnWOZ2p9AadxT23wsQlyxcSrGNKqP6huzjeXB3som3xrJkLmxFP1tAQrIzb
         AvkyRfC6Lsze3FK69ZXDnKPWLbqc4PTAeMvE/buMDsad6P/mmd08qNwAI0uyNqxJOHAF
         +tXlamFcmy+acoGuCWQjQbBdb4fdDi8eMEslYQX2RiqMFuP6uOjDj5q3skXXcXqpjHkR
         NPq2hs0LUSJ5GDg81NDCaVNrbXBWrERHpo4EJHcLaqDO6t7jBZPcHsgBAjT0cxkgWcUc
         AL8PU4GXv2ICwyVbR/4E99rPzvPYCup5wRw75RU1rmwooGiR0Y8tWnj2b4jbUTzeugYe
         rKNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rAIko5S6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xBgF4y5Xf4jEAKTeZhhDCcFT23H231N41d9v2bm0hHs=;
        b=BoQ9K0OIDh/kmcp4iqFDj11AVzRdTOWpmT6vy+Rr7/p8kZJPkzpVRzJNlb0Ig/DlME
         VlWLWy0YgpidkX42/GCLpYPYyyLns34BefiDqE7zLAG8nMGYNwG3lRd/rXde78wBp0oe
         8wHzKdAlPRzARClQDw9UQI9y7rHJwde6XSokJ5U7u/1gRncntJlRKAfsBUsvKQSnCDbP
         PNjjwAf4ircGbN0EFLfkcnoxQKGgx7wbGa3iuq0N/6WOeefKVQieeTUSXu7G0HO50FGy
         /SQ9UheugL3iF0+mbnBve4bcgZpNpzeDbkYGi081ttb/qe9//7m42G8NiBBkkCLTOH1L
         laZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=xBgF4y5Xf4jEAKTeZhhDCcFT23H231N41d9v2bm0hHs=;
        b=Hw+xM346erA8kZ3an8eqHStfk7b5j7m0RNUynhP55Rxp5bhsoF238TpNNModgLHtn8
         aZAgbYw3cMPucMvYyH6Qf2Nvt12BYL1VTQ8ZztNIKxI69SPMof4kxzz1p0+4tKL3t+l7
         udw8Kk9hZkku39mmC0sjAlxzRZG3zu2/eb/o1ScgQbNaeHe4n3lBhtqFK7YtQwlGjDwk
         fzQAERJvQyxD/CBkILl8Zg/TBXZx56f3eTd1MjmIZ2TGGdv1GdAmOEfEGY04zzqHsUVO
         pZev+b6vLmzJ062sNLkjIm6vSCWEnHFn1EC3AsdU45PUESvWEoIGH5IAPE88jHLDnZ87
         rw0Q==
X-Gm-Message-State: AO0yUKU4o81dAkhiPPpMo3DCuSedaCFkfw8S/7XFYSmANgxS6W3L7HDl
	MPAG9JnLjm4RucP2E8m3QaM=
X-Google-Smtp-Source: AK7set/5AaTo5opDHH5lYU37bgQMvuw0DJpjEpgh/Uchgb+lKUc85D2BWZ+pfDnT2HMyw/GVpD7jsg==
X-Received: by 2002:a1f:5f87:0:b0:3e9:2762:f53f with SMTP id t129-20020a1f5f87000000b003e92762f53fmr2186120vkb.10.1675155255471;
        Tue, 31 Jan 2023 00:54:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3d9a:b0:3f6:c79c:3ce9 with SMTP id
 h26-20020a0561023d9a00b003f6c79c3ce9ls1768184vsv.5.-pod-prod-gmail; Tue, 31
 Jan 2023 00:54:14 -0800 (PST)
X-Received: by 2002:a67:6b85:0:b0:3fa:b3be:8e1 with SMTP id g127-20020a676b85000000b003fab3be08e1mr2743432vsc.11.1675155254664;
        Tue, 31 Jan 2023 00:54:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675155254; cv=none;
        d=google.com; s=arc-20160816;
        b=sdIubaFougErA/PKrfeg/qJNw46hPcqAFy3Rvb+7hnl9J5OzK5xBCz07kSSxvO7P3n
         rLNTqOwhx/uMHXsu9sf4KUm2Wb70eCA5B0B4rWnlZy/epQ7Gljzi9uKVdU6SvydxmM0D
         pRyKIUVJjVOLy8EjYzMuM9ONj7yv2tZCOlqpmdwjXR0dhigdVvjca2r5iJXDY7BH026x
         paHjadCpiVA/Y5s1aJEouu+9yk4sQjm80q0tcrwJs4w44O9ouX5bb7unXLNjxKhoKxCu
         0U0sm0BVhuxi0gbF2zWWkIEpFylhOC/S/TAomqRzNGLwIGRQ2eSheQE1sZGJBcYjGWeS
         2Rug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q1SrdDNUlC8jwW9ILBpZQKsxZB0Kk6bmk1dzxOugPqw=;
        b=XzC7pfmhrXPGS2SST7OKqkp2jzMvcFquO69M/NvkvBqFF1rCL2pZGyZpAwEJzY10k/
         oFzraKtB568SvnoWH2lcw3EqGAG714IoHZSGl/+eb/Vzf/AAW852FDkrB+DEmvGoaXhE
         FGRJ4srvdiSmajRJFUYIO+uGDuz7U11ORPYvXbdDMKUsMXj3Hs4O1/4mnONk5GKpl/0+
         UPMk5E/kJXi9ohCKLFvF2NtC8X/eUrAlIYWXo+dY4jL+5PdiO+8AD6XmRGpD3u8BKSwP
         5LVgqJJn1mvnz3uDp7YKytqulhABCYzMd4MXBLyCCDcm9EGlaqbFXSkIrx2sgpKQB4Zz
         pw4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rAIko5S6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id bl9-20020a05613006c900b005e51a1a1ef1si1540092uab.2.2023.01.31.00.54.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 00:54:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-51ba4b1b9feso20580967b3.11
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 00:54:14 -0800 (PST)
X-Received: by 2002:a81:6d4:0:b0:468:5fe3:7771 with SMTP id
 203-20020a8106d4000000b004685fe37771mr6562874ywg.267.1675155254079; Tue, 31
 Jan 2023 00:54:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
In-Reply-To: <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 09:53:37 +0100
Message-ID: <CANpmjNPakvS5OAp3DEvH=5mdtped8K5WC4j4yRfPEJtJOv4OhA@mail.gmail.com>
Subject: Re: [PATCH 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rAIko5S6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
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

On Mon, 30 Jan 2023 at 21:51, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> The current implementation of the extra_bits interface is confusing:
> passing extra_bits to __stack_depot_save makes it seem that the extra
> bits are somehow stored in stack depot. In reality, they are only
> embedded into a stack depot handle and are not used within stack depot.
>
> Drop the extra_bits argument from __stack_depot_save and instead provide
> a new stack_depot_set_extra_bits function (similar to the exsiting
> stack_depot_get_extra_bits) that saves extra bits into a stack depot
> handle.
>
> Update the callers of __stack_depot_save to use the new interace.
>
> This change also fixes a minor issue in the old code: __stack_depot_save
> does not return NULL if saving stack trace fails and extra_bits is used.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/stackdepot.h |  4 +++-
>  lib/stackdepot.c           | 38 +++++++++++++++++++++++++++++---------
>  mm/kasan/common.c          |  2 +-
>  mm/kmsan/core.c            | 10 +++++++---
>  4 files changed, 40 insertions(+), 14 deletions(-)
>
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index c4e3abc16b16..f999811c66d7 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -57,7 +57,6 @@ static inline int stack_depot_early_init(void)        { return 0; }
>
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                                         unsigned int nr_entries,
> -                                       unsigned int extra_bits,
>                                         gfp_t gfp_flags, bool can_alloc);
>
>  depot_stack_handle_t stack_depot_save(unsigned long *entries,
> @@ -71,6 +70,9 @@ void stack_depot_print(depot_stack_handle_t stack);
>  int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>                        int spaces);
>
> +depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
> +                                               unsigned int extra_bits);

Can you add __must_check to this function? Either that or making
handle an in/out param, as otherwise it might be easy to think that it
doesn't return anything ("set_foo()" seems like it sets the
information in the handle-associated data but not handle itself ... in
case someone missed the documentation).

>  unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);
>
>  #endif
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 7282565722f2..f291ad6a4e72 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -346,7 +346,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
>   *
>   * @entries:           Pointer to storage array
>   * @nr_entries:                Size of the storage array
> - * @extra_bits:                Flags to store in unused bits of depot_stack_handle_t
>   * @alloc_flags:       Allocation gfp flags
>   * @can_alloc:         Allocate stack slabs (increased chance of failure if false)
>   *
> @@ -358,10 +357,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
>   * If the stack trace in @entries is from an interrupt, only the portion up to
>   * interrupt entry is saved.
>   *
> - * Additional opaque flags can be passed in @extra_bits, stored in the unused
> - * bits of the stack handle, and retrieved using stack_depot_get_extra_bits()
> - * without calling stack_depot_fetch().
> - *
>   * Context: Any context, but setting @can_alloc to %false is required if
>   *          alloc_pages() cannot be used from the current context. Currently
>   *          this is the case from contexts where neither %GFP_ATOMIC nor
> @@ -371,7 +366,6 @@ static inline struct stack_record *find_stack(struct stack_record *bucket,
>   */
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                                         unsigned int nr_entries,
> -                                       unsigned int extra_bits,
>                                         gfp_t alloc_flags, bool can_alloc)
>  {
>         struct stack_record *found = NULL, **bucket;
> @@ -461,8 +455,6 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>         if (found)
>                 retval.handle = found->handle.handle;
>  fast_exit:
> -       retval.extra = extra_bits;
> -
>         return retval.handle;
>  }
>  EXPORT_SYMBOL_GPL(__stack_depot_save);
> @@ -483,7 +475,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                                       unsigned int nr_entries,
>                                       gfp_t alloc_flags)
>  {
> -       return __stack_depot_save(entries, nr_entries, 0, alloc_flags, true);
> +       return __stack_depot_save(entries, nr_entries, alloc_flags, true);
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_save);
>
> @@ -566,6 +558,34 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>  }
>  EXPORT_SYMBOL_GPL(stack_depot_snprint);
>
> +/**
> + * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
> + *
> + * @handle:    Stack depot handle
> + * @extra_bits:        Value to set the extra bits
> + *
> + * Return: Stack depot handle with extra bits set
> + *
> + * Stack depot handles have a few unused bits, which can be used for storing
> + * user-specific information. These bits are transparent to the stack depot.
> + */
> +depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
> +                                               unsigned int extra_bits)
> +{
> +       union handle_parts parts = { .handle = handle };
> +
> +       parts.extra = extra_bits;
> +       return parts.handle;
> +}
> +EXPORT_SYMBOL(stack_depot_set_extra_bits);
> +
> +/**
> + * stack_depot_get_extra_bits - Retrieve extra bits from a stack depot handle
> + *
> + * @handle:    Stack depot handle with extra bits saved
> + *
> + * Return: Extra bits retrieved from the stack depot handle
> + */
>  unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
>  {
>         union handle_parts parts = { .handle = handle };
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 833bf2cfd2a3..50f4338b477f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -43,7 +43,7 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
>         unsigned int nr_entries;
>
>         nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> -       return __stack_depot_save(entries, nr_entries, 0, flags, can_alloc);
> +       return __stack_depot_save(entries, nr_entries, flags, can_alloc);
>  }
>
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 112dce135c7f..f710257d6867 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -69,13 +69,15 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
>  {
>         unsigned long entries[KMSAN_STACK_DEPTH];
>         unsigned int nr_entries;
> +       depot_stack_handle_t handle;
>
>         nr_entries = stack_trace_save(entries, KMSAN_STACK_DEPTH, 0);
>
>         /* Don't sleep (see might_sleep_if() in __alloc_pages_nodemask()). */
>         flags &= ~__GFP_DIRECT_RECLAIM;
>
> -       return __stack_depot_save(entries, nr_entries, extra, flags, true);
> +       handle = __stack_depot_save(entries, nr_entries, flags, true);
> +       return stack_depot_set_extra_bits(handle, extra);
>  }
>
>  /* Copy the metadata following the memmove() behavior. */
> @@ -215,6 +217,7 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
>         u32 extra_bits;
>         int depth;
>         bool uaf;
> +       depot_stack_handle_t handle;
>
>         if (!id)
>                 return id;
> @@ -250,8 +253,9 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
>          * positives when __stack_depot_save() passes it to instrumented code.
>          */
>         kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
> -       return __stack_depot_save(entries, ARRAY_SIZE(entries), extra_bits,
> -                                 GFP_ATOMIC, true);
> +       handle = __stack_depot_save(entries, ARRAY_SIZE(entries), GFP_ATOMIC,
> +                                   true);
> +       return stack_depot_set_extra_bits(handle, extra_bits);
>  }
>
>  void kmsan_internal_set_shadow_origin(void *addr, size_t size, int b,
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPakvS5OAp3DEvH%3D5mdtped8K5WC4j4yRfPEJtJOv4OhA%40mail.gmail.com.
