Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFX2TTWQKGQEXWZH46I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F02ED9606
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 17:54:00 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id x77sf24138814qka.11
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 08:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571241239; cv=pass;
        d=google.com; s=arc-20160816;
        b=MqGRo/9d2QkvR0fJBNyhe9syRFr3+JSd9IKvgrz9NHNvqyaGyWSf2EpFp5eNbEWIjt
         IsExLSUt2RmKwmbORO/KJ82vIN27XSufCHwpTIa5GMidrzaLdk/dwcWOC3aP6FJ4YAvG
         KO9jaJNMehvlxuuzHIFDpluPYyhjlnd49gsxsvI83Dp5JTfca7VF4v9paMxd93kdOrCx
         00qBJFs/j1FwQGOJSk2pL8rCfxK8hk922ndNKcugnBcdRdfhb9mbOXDOAk2nwtAEQ+KB
         Kry7/Ea9Pne2E8w4mbkttGyu7NFYnV6mzu34fafJU6q9Jb5jDMVel26JPvurnJEqbFTf
         99Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wesOgvFSEyuP0lBdcp51C0O5xTgcB9Hl8ZzyToc/e3k=;
        b=kkk4oR/S5JO/DUYZjcyiRh21sHf0KaJMFwWe0kOBSx1rk7qboVmHG9U1LDVtKUi5wQ
         d/wKWwCTOyuiXpWKDrWa4eVElxjGdmZ68aD6kXLyZg/xmFiO3jRbaaXblVati3p0NoH3
         Xd6vqVBoGTNrSHFTE2wyLVHOTO42qG5udP77RHZrg5qmBTC7O4iepCTDHbYc71YHKzHC
         rlMXv7P134kV5wx8E9/RJR3bgaDhNWQzzVJ0b5rq6CXUIYNZtcAIJuJnzzqSilm+2Ry2
         QezTRxwUCmzSM26SUYORWbhOZXeo2DsAThRTP3BZUTdParmhJ/4Q6kg8NR06Jqs4j6bi
         v28Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oO69GKlE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wesOgvFSEyuP0lBdcp51C0O5xTgcB9Hl8ZzyToc/e3k=;
        b=jt98FPnYChvHMW3ODOGknxoKzuUo83busmrkE3EH4ntThW3RmDHrqcmDarIKwD32Ow
         kmiL8bKvnThTtwwsgCIZXQSE/Gi+DbheIyqdUr/D7Ltkp3snaqoHm10UQHkJLbxAD3C+
         WKOUWb2xWSBrFOWke011ENEnn3PLCFV5jKgO8l8T1I8Bo0R+NW/cjVohPRRBn/KzT3B3
         QwHlhiOxARqE9rAYFwQGxA3by4LCOivCkZwDbK2RtxpIHrRQbC4sSsVSy+8eXCUhkI+4
         lQDVKBanlLRr4G2n64wpR4nwxV/0JXJZeokRLuUs0lQFHMcm7NUOWpfz0bx4Erq7eUNr
         iQYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wesOgvFSEyuP0lBdcp51C0O5xTgcB9Hl8ZzyToc/e3k=;
        b=rK2ct/HGuuY0yUWCjREXmE28+cDZvB4uOlV/uPprnFrpluLxkSHxDkqua7ouNz9L/f
         dq38mel0Br6fPh6e9kXV4T5hNmj/QHAg3YPFtPnjFaFyKP8CirMdhOV7+YLVQi8H+m6g
         Mg6xbBx42ON6OxzGmp/wFDqQ8pjvU+Jya7W0i/DCY0MyzzSRDeK2OL/WlLxQA828r1og
         vFwrN8bdSExyPGnIKU+pan9E3dQZmheokhEqFg1bp7fWbTmadHg9GksgZtBYJcKAgSis
         /hHhft0+fhu5XQDsfwCHkUL0l60DXeRfD0meAKZE7/kazUm9nx6npfZYUEORu2SSdhkG
         nKcQ==
X-Gm-Message-State: APjAAAUL2NU14yDh8oi4ChUlfKlUrfigSgFEXO3HfArD5Z7nHUsA1RXo
	K+VoHH0YwdD3XJDUdKXjyCg=
X-Google-Smtp-Source: APXvYqwUPz5woSqkpofsKB7nJpislm1pN187KZ+jHhSmo9BSfxexHhJrV5iAX7af+ooHIHpjevKUKw==
X-Received: by 2002:aed:29e7:: with SMTP id o94mr44562293qtd.161.1571241239071;
        Wed, 16 Oct 2019 08:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eb01:: with SMTP id j1ls3902461qvp.11.gmail; Wed, 16 Oct
 2019 08:53:58 -0700 (PDT)
X-Received: by 2002:a0c:91bd:: with SMTP id n58mr43853389qvn.62.1571241238499;
        Wed, 16 Oct 2019 08:53:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571241238; cv=none;
        d=google.com; s=arc-20160816;
        b=T1ZH8AO2MNKY7VUvWwELOwjB+eDigmG4G3AbIYUW0IzbYiHhhWNjiVjXGkFoiY8VGw
         GZ1CO2E18mrzJCa303pmy1xJ6EX8kyokgfyzPiXzRTSfzV2roTjoyfCKKe+MLuitYYZK
         J8JX8WKW0hoF2FIbaum+L+G5SP3he8BQhyj0Rbk7+vjX5nh8BQ6zEpnHf5fh/lUIXL8N
         NLhZirShfnTSZOj44rSdan+zn8H//kucQUdQteGPqbaKUn82zrnuwFImI5blFMwII/Mx
         N+wyC9LCJ/StOp0Lie+vBClIbek0uEg60a4nSFF+SoGla+rJkHcJI73W5gCZgcncsfdg
         vKVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ES8PPxqISv6le2aU+Na1jJhECeSWLsXBsBUpCljFmNc=;
        b=WOrv7MDp47SUlA1SL4Fo8vKaPbfGAIdwC/usD7iFWB7Ag7KXh2EQ3kHgA97pSIPk8E
         XFpyjl2+d4QOWo0oMiQiRoi3ihEd8vnTcfxKC1IOeZpZ+PeYdsHsEt3oRFUlG5GYv0oo
         a6koTQmXGL99NcOrIcVSWbjbQNGw+lg2ysbuz9cKat11fJ/2Z2ShrBwl8hCzC1eZr0Uy
         YS0L4KGLLAwEocip+5GGvXrG8gObwgy9e2i0fC7g/p2qIcSuRKbCEOv/J34MIc+0mAyW
         +ch47/2txpjBySKS8FVYyjaaybijjDAMAf4qRaHOQTTxLoX5VJ4zImnYQFr4YzaNujJe
         +69Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oO69GKlE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id o13si1500397qkj.4.2019.10.16.08.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 08:53:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id s22so20577787otr.6
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 08:53:58 -0700 (PDT)
X-Received: by 2002:a9d:7590:: with SMTP id s16mr8514934otk.2.1571241237486;
 Wed, 16 Oct 2019 08:53:57 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-2-elver@google.com>
 <20191016151643.GC46264@lakrids.cambridge.arm.com>
In-Reply-To: <20191016151643.GC46264@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 17:53:45 +0200
Message-ID: <CANpmjNNctoVsUc+VbJ_RAMgLxcbvjq55gK1NdE0G0muMdv1+Ng@mail.gmail.com>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, ard.biesheuvel@linaro.org, 
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Daniel Axtens <dja@axtens.net>, Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, Dmitry Vyukov <dvyukov@google.com>, "H. Peter Anvin" <hpa@zytor.com>, 
	Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oO69GKlE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Wed, 16 Oct 2019 at 17:16, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index 2c2e56bd8913..34a1d9310304 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -1171,6 +1171,13 @@ struct task_struct {
> >  #ifdef CONFIG_KASAN
> >       unsigned int                    kasan_depth;
> >  #endif
> > +#ifdef CONFIG_KCSAN
> > +     /* See comments at kernel/kcsan/core.c: struct cpu_state. */
> > +     int                             kcsan_disable;
> > +     int                             kcsan_atomic_next;
> > +     int                             kcsan_atomic_region;
> > +     bool                            kcsan_atomic_region_flat;
> > +#endif
>
> Should these be unsigned?

I prefer to keep them int, as they can become negative (rather than
underflow with unsigned), if we e.g. have unbalanced
kcsan_enable_current etc. Since we do not need the full unsigned range
(these values should stay relatively small), int is more than enough.

> > +/*
> > + * Per-CPU state that should be used instead of 'current' if we are not in a
> > + * task.
> > + */
> > +struct cpu_state {
> > +     int disable; /* disable counter */
> > +     int atomic_next; /* number of following atomic ops */
> > +
> > +     /*
> > +      * We use separate variables to store if we are in a nestable or flat
> > +      * atomic region. This helps make sure that an atomic region with
> > +      * nesting support is not suddenly aborted when a flat region is
> > +      * contained within. Effectively this allows supporting nesting flat
> > +      * atomic regions within an outer nestable atomic region. Support for
> > +      * this is required as there are cases where a seqlock reader critical
> > +      * section (flat atomic region) is contained within a seqlock writer
> > +      * critical section (nestable atomic region), and the "mismatching
> > +      * kcsan_end_atomic()" warning would trigger otherwise.
> > +      */
> > +     int atomic_region;
> > +     bool atomic_region_flat;
> > +};
> > +static DEFINE_PER_CPU(struct cpu_state, this_state) = {
> > +     .disable = 0,
> > +     .atomic_next = 0,
> > +     .atomic_region = 0,
> > +     .atomic_region_flat = 0,
> > +};
>
> These are the same as in task_struct, so I think it probably makes sense
> to have a common structure for these, e.g.
>
> | struct kcsan_ctx {
> |       int     disable;
> |       int     atomic_next;
> |       int     atomic_region;
> |       bool    atomic_region_flat;
> | };
>
> ... which you then place within task_struct, e.g.
>
> | #ifdef CONFIG_KCSAN
> |       struct kcsan_ctx        kcsan_ctx;
> | #endif
>
> ... and here, e.g.
>
> | static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx);
>
> That would simplify a number of cases below where you have to choose one
> or the other, as you can choose the pointer, then handle the rest in a
> common way.
>
> e.g. for:
>
> > +static inline bool is_atomic(const volatile void *ptr)
> > +{
> > +     if (in_task()) {
> > +             if (unlikely(current->kcsan_atomic_next > 0)) {
> > +                     --current->kcsan_atomic_next;
> > +                     return true;
> > +             }
> > +             if (unlikely(current->kcsan_atomic_region > 0 ||
> > +                          current->kcsan_atomic_region_flat))
> > +                     return true;
> > +     } else { /* interrupt */
> > +             if (unlikely(this_cpu_read(this_state.atomic_next) > 0)) {
> > +                     this_cpu_dec(this_state.atomic_next);
> > +                     return true;
> > +             }
> > +             if (unlikely(this_cpu_read(this_state.atomic_region) > 0 ||
> > +                          this_cpu_read(this_state.atomic_region_flat)))
> > +                     return true;
> > +     }
> > +
> > +     return kcsan_is_atomic(ptr);
> > +}
>
> ... you could have something like:
>
> | struct kcsan_ctx *kcsan_get_ctx(void)
> | {
> |       return in_task() ? &current->kcsan_ctx : this_cpu_ptr(kcsan_cpu_ctx);
> | }
> |
> | static inline bool is_atomic(const volatile void *ptr)
> | {
> |       struct kcsan_ctx *ctx = kcsan_get_ctx();
> |       if (unlikely(ctx->atomic_next > 0) {
> |               --ctx->atomic_next;
> |               return true;
> |       }
> |       if (unlikely(ctx->atomic_region > 0 || ctx->atomic_region_flat))
> |               return true;
> |
> |       return kcsan_is_atomic(ptr);
> | }
>
> ... avoiding duplicating the checks for task/irq contexts.
>
> It's not clear to me how either that or the original code works if a
> softirq is interrupted by a hardirq. IIUC most of the fields should
> remain stable over that window, since the hardirq should balance most
> changes it makes before returning, but I don't think that's true for
> atomic_next. Can't that be corrupted from the PoV of the softirq
> handler?

As you say, these fields should balance. So far I have not observed
any issues. For atomic_next I'm not concerned as it is an
approximation either way (see seqlock patch), and it's fine if there
is a small error.

> [...]
>
> > +void kcsan_begin_atomic(bool nest)
> > +{
> > +     if (nest) {
> > +             if (in_task())
> > +                     ++current->kcsan_atomic_region;
> > +             else
> > +                     this_cpu_inc(this_state.atomic_region);
> > +     } else {
> > +             if (in_task())
> > +                     current->kcsan_atomic_region_flat = true;
> > +             else
> > +                     this_cpu_write(this_state.atomic_region_flat, true);
> > +     }
> > +}
>
> Assuming my suggestion above wasn't bogus, this can be:
>
> | void kcsan_begin_atomic(boot nest)
> | {
> |       struct kcsan_ctx *ctx = kcsan_get_ctx();
> |       if (nest)
> |               ctx->atomic_region++;
> |       else
> |               ctx->atomic_region_flat = true;
> | }
>
> > +void kcsan_end_atomic(bool nest)
> > +{
> > +     if (nest) {
> > +             int prev =
> > +                     in_task() ?
> > +                             current->kcsan_atomic_region-- :
> > +                             (this_cpu_dec_return(this_state.atomic_region) +
> > +                              1);
> > +             if (prev == 0) {
> > +                     kcsan_begin_atomic(true); /* restore to 0 */
> > +                     kcsan_disable_current();
> > +                     WARN(1, "mismatching %s", __func__);
> > +                     kcsan_enable_current();
> > +             }
> > +     } else {
> > +             if (in_task())
> > +                     current->kcsan_atomic_region_flat = false;
> > +             else
> > +                     this_cpu_write(this_state.atomic_region_flat, false);
> > +     }
> > +}
>
> ... similarly:
>
> | void kcsan_end_atomic(bool nest)
> | {
> |       struct kcsan_ctx *ctx = kcsan_get_ctx();
> |
> |       if (nest)
> |               if (ctx->kcsan_atomic_region--) {
> |                       kcsan_begin_atomic(true); /* restore to 0 */
> |                       kcsan_disable_current();
> |                       WARN(1, "mismatching %s"\ __func__);
> |                       kcsan_enable_current();
> |               }
> |       } else {
> |               ctx->atomic_region_flat = true;
> |       }
> | }
>
> > +void kcsan_atomic_next(int n)
> > +{
> > +     if (in_task())
> > +             current->kcsan_atomic_next = n;
> > +     else
> > +             this_cpu_write(this_state.atomic_next, n);
> > +}
>
> ... and:
>
> | void kcsan_atomic_nextint n)
> | {
> |       kcsan_get_ctx()->atomic_next = n;
> | }

Otherwise, yes, this makes much more sense and I will just introduce
the struct and integrate the above suggestions for v2.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNctoVsUc%2BVbJ_RAMgLxcbvjq55gK1NdE0G0muMdv1%2BNg%40mail.gmail.com.
