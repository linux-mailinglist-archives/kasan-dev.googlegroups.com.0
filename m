Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDWMWGFAMGQEFNWX73Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id C0CAF415CDC
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 13:33:35 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id m6-20020ab073c6000000b002b330799c9csf2086443uaq.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 04:33:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632396815; cv=pass;
        d=google.com; s=arc-20160816;
        b=O7P+fPxOOfUA/JrxE22LBKMURa3aZfCFibjwACOa5LMKSWkHHU6dpP0YfgnP8AFu81
         JZNUyc1MSftFefXhfLmc8/kkBUU51LCVLKDcxCAQeYJmZMEtaQjewNMQhVcNog3J3CWG
         xlJ/DCkkbxfT1uFkiqMPbZFbPON5x6OnLf9Bo1wk4D/SdFhcyXOIPYxtl2zRfe5bAPrI
         fQPblP6QWnWmg5ivV0HGDfYFd9i+6aAsu5q+Zf71/JOJv4TxG5o0k18Tdqt6V1ybYGyd
         76z7A6ci/FQoXHTaiGmYZ776u2Hmr7SUl2kXgkh/JNFtXs3XTPXqA+0nOpoXxwYjMGLp
         JOzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qkx4B69qVeVLXSAx3Lj0kZqz0okksx0VJeKx3T8FRRo=;
        b=VVfspC9Brg8lqneuRiQzFTDy4E2M3Nl/vTOseTeNYhSE1vwg+wzJbLorghkb9UQXP/
         2/Di7lqs8/zNphmaxz/fGskPaJcxRywoch5yVAs1lCFuvNXHedd4iT1tJIczV99AkX9o
         0ID3fGwaKrWNFZoOAROWjNgKpQEX7dLnCtP0yz7Qg/RYceZyOFda2kcYfkmD3afZQlCt
         IvvPFnQo7KQKOiTEkBTjn9t3m2EGMauZ/ZDhHyQFy487Afas1pzkSMlcF0D2eXSf9cQN
         vIvYpRzL+xb7rD6c1cZdY4iaBq4jvN3m/ZeVy2bsSiJGiCepTa5hfAdxiOe/bDum1aQP
         BRIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Zr+iAvq3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Qkx4B69qVeVLXSAx3Lj0kZqz0okksx0VJeKx3T8FRRo=;
        b=NmcgjNlUUmYTpQ8Kz09KU5enmZXZkQmhEjmI7s9vDJN40789O178ez1Ap3Ao3eqZ7S
         JO6t2qYYc9C1jlLz5VV+xWVkpMRfTfnd8La+DG5fSwghCB+gJ/kX2xsTHhJGrK43pejp
         QKM/7Rnpm8eFuz0OfTn/Kc+Rc5MtGHcI7NSKvlnrxAQffb1ZFJNa6mHP+FBs/baTCNVr
         cEjDHoS+3PO2//9VfVVWKgIVgH1L6HMaNCDe/lVtTAJ7QoaP+F6JoFLzu90HsYvhoagd
         suGkbuFO6RRrV2YeRlYSg+vlM5e9oPDG8xF4IUk0EFWW9++fqVW2ZU2FBotyW1NE9pHF
         c1hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qkx4B69qVeVLXSAx3Lj0kZqz0okksx0VJeKx3T8FRRo=;
        b=3YoT/Fv0uqKDMjVOXjdB1U//FDAvZ37vvrxK9FkJ5i+EIS8HJOe6X6ugC+zpyJzQyr
         ok6KisQcd2tBcQeSDPKN/H3oJ0gF1HkLnD+rhoZ+esxBekI9DK8tkLHVpSkSmHLz/ZG8
         e1mCuIongte08R/r0aZtz6+5JTGEz/o4irceCaDln0FdyUvZF1zdIl4lj+vW+yDhfZq4
         4cHNcagUt/OiCa/UmhcpmBws/4xPDz7Evu6eP+tyqGnNVHNketAxVzPm4mNq7cHnCY88
         N6xvk7HP7rXa+x4L3UmGog7Yx8ZvhMShs98P7jJIHhwOT3wHkb9825l+D7LFb+Jmsjuu
         +NjQ==
X-Gm-Message-State: AOAM530bCSJ4aOu1+TsYDuK1cM3WQdkyZzsYtzIP73Jg+ieixd7kVakH
	Y3+BTr/1GcCYfMBDbwilf78=
X-Google-Smtp-Source: ABdhPJylLcJ/JlAq5NdQUPIwtRV1HFPu0922bbrC0sHbDd7dgVnjUif0sIHODrhVLhDEGc8jJl0YiQ==
X-Received: by 2002:a67:eb51:: with SMTP id x17mr3414498vso.8.1632396814869;
        Thu, 23 Sep 2021 04:33:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d294:: with SMTP id z20ls1232274vsi.8.gmail; Thu, 23 Sep
 2021 04:33:34 -0700 (PDT)
X-Received: by 2002:a67:ad17:: with SMTP id t23mr3305501vsl.35.1632396814387;
        Thu, 23 Sep 2021 04:33:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632396814; cv=none;
        d=google.com; s=arc-20160816;
        b=owsi233w81LEkj8ALtW4WubsQU+5gavnJ4m6uBsp7q96lysoyw0c9aMwhm5pEoA33B
         nPw/XwA8i1+7dyJkoAiBhdi5czI70l2hrxmuNkJvgramRKEAn1Ev2OHxvSHrTmx1j/Lu
         nnrhkkZdYOZmjlVhcRNXfLayZyAmnBy24MAKCRcwMftvrSWXLmhhm2R7cZ4SKKlNelNH
         FgO7QTow9AmviYkXOKZ52q2IlkV86CQJmRh+vioBv29oGNPDbJTWSMUC7z48fSqaTXU2
         4SNAy/E5slUBDG/ZCTJ6ddJ6NlO/ZH4HBvNCDrbaxncNMupsuXXkW/5iIeJvPxLGR5nJ
         +YsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ggXcEXb/CHUjvrcz3BZioGS0po09zhrTU/EfIgarfj8=;
        b=FKN/gcCbUlF2slABSUMjoUH8ZgN826lt9Oq5RWFwEi/j+8CJjRIjENBbQtIxvrA2oH
         7xz72Vf9plwVbqYNbPhTwr/I2zDm8+FIG6m80o9WEcSbj5e7TzlYnAxLuSv81yW1e0J1
         slmjqYa0AHThTgsZBTT8qUP2tCcKDQhgWmhx/Yp+InshU1WZiWX0ioEypOniZoJx1wnf
         os6vPQU0z+50HGM+bCNSDNCxnth6SyUtqtI6gSwp3SJ9t1sikp/uWbJ9OnLS3XedZBFy
         h6rs1vN5pmRPtaU2h/sDZRxPk2Ow8/3HDNHnbtNEmpcvYf+AV/DgcseoabGnuKKDDb/e
         2guA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Zr+iAvq3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id u64si279862vku.4.2021.09.23.04.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 04:33:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id q81so17193034qke.5
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 04:33:34 -0700 (PDT)
X-Received: by 2002:a37:8044:: with SMTP id b65mr4254304qkd.150.1632396813877;
 Thu, 23 Sep 2021 04:33:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-3-elver@google.com>
In-Reply-To: <20210923104803.2620285-3-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 13:32:57 +0200
Message-ID: <CAG_fn=W+_Dx8TKofckVCUWCiPy_pS01r2AUWBYAS2yEMShmFcQ@mail.gmail.com>
Subject: Re: [PATCH v3 3/5] kfence: move saving stack trace of allocations
 into __kfence_alloc()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Zr+iAvq3;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as
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

On Thu, Sep 23, 2021 at 12:48 PM Marco Elver <elver@google.com> wrote:
>
> Move the saving of the stack trace of allocations into __kfence_alloc(),
> so that the stack entries array can be used outside of
> kfence_guarded_alloc() and we avoid potentially unwinding the stack
> multiple times.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
> v2:
> * New patch.
> ---
>  mm/kfence/core.c | 35 ++++++++++++++++++++++++-----------
>  1 file changed, 24 insertions(+), 11 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 249d75b7e5ee..db01814f8ff0 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -187,19 +187,26 @@ static inline unsigned long metadata_to_pageaddr(co=
nst struct kfence_metadata *m
>   * Update the object's metadata state, including updating the alloc/free=
 stacks
>   * depending on the state transition.
>   */
> -static noinline void metadata_update_state(struct kfence_metadata *meta,
> -                                          enum kfence_object_state next)
> +static noinline void
> +metadata_update_state(struct kfence_metadata *meta, enum kfence_object_s=
tate next,
> +                     unsigned long *stack_entries, size_t num_stack_entr=
ies)
>  {
>         struct kfence_track *track =3D
>                 next =3D=3D KFENCE_OBJECT_FREED ? &meta->free_track : &me=
ta->alloc_track;
>
>         lockdep_assert_held(&meta->lock);
>
> -       /*
> -        * Skip over 1 (this) functions; noinline ensures we do not accid=
entally
> -        * skip over the caller by never inlining.
> -        */
> -       track->num_stack_entries =3D stack_trace_save(track->stack_entrie=
s, KFENCE_STACK_DEPTH, 1);
> +       if (stack_entries) {
> +               memcpy(track->stack_entries, stack_entries,
> +                      num_stack_entries * sizeof(stack_entries[0]));
> +       } else {
> +               /*
> +                * Skip over 1 (this) functions; noinline ensures we do n=
ot
> +                * accidentally skip over the caller by never inlining.
> +                */
> +               num_stack_entries =3D stack_trace_save(track->stack_entri=
es, KFENCE_STACK_DEPTH, 1);
> +       }
> +       track->num_stack_entries =3D num_stack_entries;
>         track->pid =3D task_pid_nr(current);
>         track->cpu =3D raw_smp_processor_id();
>         track->ts_nsec =3D local_clock(); /* Same source as printk timest=
amps. */
> @@ -261,7 +268,8 @@ static __always_inline void for_each_canary(const str=
uct kfence_metadata *meta,
>         }
>  }
>
> -static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size,=
 gfp_t gfp)
> +static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size,=
 gfp_t gfp,
> +                                 unsigned long *stack_entries, size_t nu=
m_stack_entries)
>  {
>         struct kfence_metadata *meta =3D NULL;
>         unsigned long flags;
> @@ -320,7 +328,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *=
cache, size_t size, gfp_t g
>         addr =3D (void *)meta->addr;
>
>         /* Update remaining metadata. */
> -       metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
> +       metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED, stack_entrie=
s, num_stack_entries);
>         /* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
>         WRITE_ONCE(meta->cache, cache);
>         meta->size =3D size;
> @@ -400,7 +408,7 @@ static void kfence_guarded_free(void *addr, struct kf=
ence_metadata *meta, bool z
>                 memzero_explicit(addr, meta->size);
>
>         /* Mark the object as freed. */
> -       metadata_update_state(meta, KFENCE_OBJECT_FREED);
> +       metadata_update_state(meta, KFENCE_OBJECT_FREED, NULL, 0);
>
>         raw_spin_unlock_irqrestore(&meta->lock, flags);
>
> @@ -742,6 +750,9 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>
>  void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
>  {
> +       unsigned long stack_entries[KFENCE_STACK_DEPTH];
> +       size_t num_stack_entries;
> +
>         /*
>          * Perform size check before switching kfence_allocation_gate, so=
 that
>          * we don't disable KFENCE without making an allocation.
> @@ -786,7 +797,9 @@ void *__kfence_alloc(struct kmem_cache *s, size_t siz=
e, gfp_t flags)
>         if (!READ_ONCE(kfence_enabled))
>                 return NULL;
>
> -       return kfence_guarded_alloc(s, size, flags);
> +       num_stack_entries =3D stack_trace_save(stack_entries, KFENCE_STAC=
K_DEPTH, 0);
> +
> +       return kfence_guarded_alloc(s, size, flags, stack_entries, num_st=
ack_entries);
>  }
>
>  size_t kfence_ksize(const void *addr)
> --
> 2.33.0.464.g1972c5931b-goog
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
kasan-dev/CAG_fn%3DW%2B_Dx8TKofckVCUWCiPy_pS01r2AUWBYAS2yEMShmFcQ%40mail.gm=
ail.com.
