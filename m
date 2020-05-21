Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ4DTL3AKGQEUYGV3FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E9A531DCDE6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:27:04 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id b131sf5168723pga.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590067623; cv=pass;
        d=google.com; s=arc-20160816;
        b=JW/TCWn0ORx3To/d0ikfzHYU6cHW8Pygo3QIV5dV9lOEIQVBRzxyuQQKosZSviWqQC
         KSCTAnqpoBLIjGPsZRrvfOy7phn9MkMGUZTI2xJMvvl0ga8Oru84hQjymBtLHSKjjzBl
         BPcJJxxSwV4hsOAECK25S5bMbHQBxnycEVgBLYljvifVECBURJhCnFVeA4FpO+ygKQ97
         cdFHQZzWMDYZjzg7LVMeU3fi24s+fEKtK3Gd23BcpKi58S8phdZnLvqpbxbwgaaKHDE8
         A28F/ck955SHahiJK0ybR/BpZ3hIjmNxwDCf+wc5QH9FaeZqLu+uK3W9JhNAl/1z7iTo
         TKgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ewnP7AUOq86CD7o0GsiirDq27gcfgDNr7Ec3IgzyDeU=;
        b=Fb+DTT9QYbP6XfcX4hF2ilnnu+HV0wGkMWbqXdsbR8sCjQLDgD2pAcI8pSm6X/VP8X
         Icr5VFUKo6dT1gerpRtnIUw9LeWgfa2WPggvbAJcHC7Hx+/UZCXWsPJRYrGXdvV66FxX
         5yoSBJ7z4IoNXiE4woJ4fMUxHJaw7b2d54vCEToLqOUO3KT2iRftsNFGHhwKMzMcd7G0
         mwAiluLTvHbak1QUM1JBKb22987sXcIatd/CQM0iez3QHl2XK1E04J10vWDmAeYd4ZXn
         g/3exkqqtaecUvPv51QFKo7wAYPtze/Kyc+ShGy/xCfSfDoSRQwrzmFFxSkH+qcOvn95
         jCbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GXlGtQiQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ewnP7AUOq86CD7o0GsiirDq27gcfgDNr7Ec3IgzyDeU=;
        b=ifzvueT6lq9J0vm1QA/SFbUPYKrj2bpaL/dEmLoZsYM39SF/Ns7yOsK8zKWZOlFLFD
         9aa/AzvRa+rn5UCJmaah2OdLVD7dIiILoU25g2PV/m6o17emDXworClWJY3mpfLtqxbT
         WPznqjI6Gi1XR9qGfhlgXyqvl9urfwGotkb97wQ3U1W3tKlU7LuDWvq10GPBP+NDysmf
         40nwG24yn2Aqmx/0AXAIDu4AWRGy0IR401XPqBWnInEkAYzWC/0quc3Aho/WghIk+17Q
         jC679rtPyRFAmFLZuzkbQRehpYxcbEQCrgY0PM07Tpls3m3BTiYqQnUrndPcLWbfQzs5
         ZEPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ewnP7AUOq86CD7o0GsiirDq27gcfgDNr7Ec3IgzyDeU=;
        b=VRAdgpaTwBNkbLDNZOKmUE70WMRfa55fO8ob9oueR27OttQ61xWAVIq+z/AS8W/c5x
         b10YX3NQ88UHqYohf7PnHEZM7DZbIi9JGtRPZWIF+ddiaWUKuBs+uNYmSbB1Kz+LFFFz
         hfAMPdUNmbsRsnnZSYygQz82HjY7/mywxJDOafcyafGCWKkw/gDBWfHTHuN9MeApsu+W
         nXHsdmTrLRv8IocJaTZUS9J2ps5gGTMJ2IPL3jebu4BEH2G8F6S19ZblLJpX4Br9KoU0
         Occ2o0Z8o2yH/NXHd0DSBpat8yti5GKq564UpzW+cjTpxij3yolhpEpLxHLxV0c8A+Qy
         Rrfw==
X-Gm-Message-State: AOAM5330DNVxBG4tXCPq8g0miV9xgkmMl2HIB+IO/kcXDuoKtCvBS7qT
	h+1Bl8etKRit9sf5TeUoXrI=
X-Google-Smtp-Source: ABdhPJyHshWhoBvAd64SpRscmP79+3BsiuSxeuIIbYY4Y+j+J58FloV9uRqJbn5FYOEDxOILywY8ug==
X-Received: by 2002:a62:ab04:: with SMTP id p4mr9640051pff.254.1590067623606;
        Thu, 21 May 2020 06:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:55c3:: with SMTP id j186ls666113pfb.6.gmail; Thu, 21 May
 2020 06:27:03 -0700 (PDT)
X-Received: by 2002:a05:6a00:46:: with SMTP id i6mr9718100pfk.146.1590067623087;
        Thu, 21 May 2020 06:27:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590067623; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQaru05A7NSJ8iBPeIbdL7fcRoLYTPWIgyLapLnJNPTLQAcHhfZhBlVSmOjZeLt9L9
         UtbHR06w533PJT1D92GZa9RyqNv+QykGdyiiqF1aQByjVxsxugSS0wzy7Zg7fN9Ni5eK
         bwDH4Hqw7c19QZSOW7JnJwdwKf5qOHL51bBY1LT1Lrhqd37giHXdvzKnNFAhp8vG3cBD
         gKxZCeJEfzbkJTVt6N1gj4X5a1Nu9VKEMAhSLx6J4Q5d1kU9QmB0UfD0TcOja3MuJweU
         FUqScj1hW/padq3qyzsRa7RggydVElFz2STdu/x7U8DD6U3yx2gu5VZ/M/ouBM/MVggR
         GPiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Moc8xalnKllIyEU4EMIrwAPrYnUw5Fl91QeBkTIQAoU=;
        b=get8s/7KvYlHhemHxD/OPm3S6zwYnl04j6/29YU6/e7ktkTIfWA805ZPwgvhIZ6WyF
         z+g/ES/HKjk8dYg1DnwGPeaBHH9Udc9nSuUB9ueQriFgoiy8njFRkJS4YGPA6mRVf1mf
         Q0hJTbGGPZXn5YvgWIJuU5P5uC34Fkbd7R5TCBECSaNAHgCPXuGt9cMwiw2iLsndjshG
         vVPDqoWfBnFEDWkQ1TEtJ0+VoFV5UqMwy/C4PPByqNrMDtRG4rykUe2T9+E9/6LE64NO
         a4CGMiSSsKaf7DUNe769Zdv5EvfBOy/Nsd9Z+QKpIEjOl63S6Zof/PIPF2ijKhIjXf7t
         XelQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GXlGtQiQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a1si365710plp.2.2020.05.21.06.27.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 06:27:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id c3so5447856otr.12
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 06:27:03 -0700 (PDT)
X-Received: by 2002:a05:6830:18ce:: with SMTP id v14mr6550417ote.251.1590067622152;
 Thu, 21 May 2020 06:27:02 -0700 (PDT)
MIME-Version: 1.0
References: <20200521110854.114437-1-elver@google.com> <20200521110854.114437-4-elver@google.com>
 <20200521131803.GA6608@willie-the-truck>
In-Reply-To: <20200521131803.GA6608@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 May 2020 15:26:48 +0200
Message-ID: <CANpmjNNDRb+wokzagQtLRVvZrj-8eH87gOX1JwG9hWf+eicRNg@mail.gmail.com>
Subject: Re: [PATCH -tip v2 03/11] kcsan: Support distinguishing volatile accesses
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GXlGtQiQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 21 May 2020 at 15:18, Will Deacon <will@kernel.org> wrote:
>
> On Thu, May 21, 2020 at 01:08:46PM +0200, Marco Elver wrote:
> > In the kernel, volatile is used in various concurrent context, whether
> > in low-level synchronization primitives or for legacy reasons. If
> > supported by the compiler, we will assume that aligned volatile accesses
> > up to sizeof(long long) (matching compiletime_assert_rwonce_type()) are
> > atomic.
> >
> > Recent versions Clang [1] (GCC tentative [2]) can instrument volatile
> > accesses differently. Add the option (required) to enable the
> > instrumentation, and provide the necessary runtime functions. None of
> > the updated compilers are widely available yet (Clang 11 will be the
> > first release to support the feature).
> >
> > [1] https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> > [2] https://gcc.gnu.org/pipermail/gcc-patches/2020-April/544452.html
> >
> > This patch allows removing any explicit checks in primitives such as
> > READ_ONCE() and WRITE_ONCE().
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Reword Makefile comment.
> > ---
> >  kernel/kcsan/core.c    | 43 ++++++++++++++++++++++++++++++++++++++++++
> >  scripts/Makefile.kcsan |  5 ++++-
> >  2 files changed, 47 insertions(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index a73a66cf79df..15f67949d11e 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -789,6 +789,49 @@ void __tsan_write_range(void *ptr, size_t size)
> >  }
> >  EXPORT_SYMBOL(__tsan_write_range);
> >
> > +/*
> > + * Use of explicit volatile is generally disallowed [1], however, volatile is
> > + * still used in various concurrent context, whether in low-level
> > + * synchronization primitives or for legacy reasons.
> > + * [1] https://lwn.net/Articles/233479/
> > + *
> > + * We only consider volatile accesses atomic if they are aligned and would pass
> > + * the size-check of compiletime_assert_rwonce_type().
> > + */
> > +#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
> > +     void __tsan_volatile_read##size(void *ptr)                             \
> > +     {                                                                      \
> > +             const bool is_atomic = size <= sizeof(long long) &&            \
> > +                                    IS_ALIGNED((unsigned long)ptr, size);   \
> > +             if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
> > +                     return;                                                \
> > +             check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
> > +     void __tsan_unaligned_volatile_read##size(void *ptr)                   \
> > +             __alias(__tsan_volatile_read##size);                           \
> > +     EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
> > +     void __tsan_volatile_write##size(void *ptr)                            \
> > +     {                                                                      \
> > +             const bool is_atomic = size <= sizeof(long long) &&            \
> > +                                    IS_ALIGNED((unsigned long)ptr, size);   \
> > +             if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
> > +                     return;                                                \
> > +             check_access(ptr, size,                                        \
> > +                          KCSAN_ACCESS_WRITE |                              \
> > +                                  (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
> > +     }                                                                      \
> > +     EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
> > +     void __tsan_unaligned_volatile_write##size(void *ptr)                  \
> > +             __alias(__tsan_volatile_write##size);                          \
> > +     EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
> > +
> > +DEFINE_TSAN_VOLATILE_READ_WRITE(1);
> > +DEFINE_TSAN_VOLATILE_READ_WRITE(2);
> > +DEFINE_TSAN_VOLATILE_READ_WRITE(4);
> > +DEFINE_TSAN_VOLATILE_READ_WRITE(8);
> > +DEFINE_TSAN_VOLATILE_READ_WRITE(16);
>
> Having a 16-byte case seems a bit weird to me, but I guess clang needs this
> for some reason?

Yes, the emitted fixed-size instrumentation is up to 16 bytes, so
we'll need it (for both volatile and non-volatile -- otherwise we'll
get linker errors). It doesn't mean we'll consider 16 byte volatile
accesses as atomic, because of the size check to compute is_atomic
above.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNDRb%2BwokzagQtLRVvZrj-8eH87gOX1JwG9hWf%2BeicRNg%40mail.gmail.com.
