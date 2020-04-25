Return-Path: <kasan-dev+bncBAABBB4DR32QKGQEB5K6S5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id EC5CD1B82AC
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Apr 2020 02:17:12 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id t130sf12834545iod.10
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 17:17:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587773831; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJGDay74RRWQiYKs6L5MVEE2qrdLKI5pQVFK/50LsubN+5fNha57DjTEb45QibVrMl
         zB9xDbBSLZqyi8ez5DzSMXqt4Jn2xk9I/HU4NbvfVIi2pbImjMJhzQCzXD5q+gh2zuE+
         C4pootEGxd+sJHUAsnasNMrkP/6UOCm6kRVj2jF6jxJpv5z1s/1dGT3xQ5gGuUsZtnoL
         tMJYFXY9zJzMqLIvAm+JHVw1GE7HfymKU6w/QcIf7c2tL0Ztl8lESiKGCv6r8EMCzSgB
         UokAPX44O5M+DBLVudve/3zUtwJfdAFXobIj+xy6CNrjAhp9Codv5jsmUiPCUU1S0Reb
         iovg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=SdyQe6ZZDs1lWdZXHbpPBZZVikBSGqO3IlR6TjxL7B4=;
        b=hswcCLzZScAnPIDkHiz0BSCgIpLRWaUCbwhe2nNdDBbpkZedYTk177CTnyW4+IFoLv
         0ieVo5F0XzpAZGcy1GHycHsJ1btwkEvjvobNMxjdo+q5csDg+aXEkgyAqG+PH5XVudzV
         dUWRGBISCZUw9KQZj+zi/2mArQBQDRmgCBfwi8g60MI4AlXt4s0OfIJrZitwrOZR/dpq
         KZf5/nfgxIy2SKYXggnU7Qw/0Vmx8MVnpkjkywtesJuE/o5g+qrcBSNT4hPqqkm9uBfY
         xIlBJmlgJDwfgANK6/cnZAhgdvWJhXeoK1YtFqCCh8m5lZAGivNGmw0XL/C/0IE8udgB
         nTDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=OmTWmL9q;
       spf=pass (google.com: domain of srs0=uv6n=6j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UV6n=6J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SdyQe6ZZDs1lWdZXHbpPBZZVikBSGqO3IlR6TjxL7B4=;
        b=EPa1UvGBRO/OvFWJjcvC/NzNMhOn0AP49Fxl/OCCJbD0SSBdxVpsmL9TrGOaWGecf+
         qckibyf7i1dlnJZHKcDDB8+I4+lS3w94XnqbqRCyJUCGu+lhdtQK2YWrVeD9OtJZJ5qM
         HyenFVT54Zhh58gtWrJMfWe/c4yvhXYs56eu6P0h9m2BeGslMBhxEs9j0xVfQFvsmcyg
         0kKxXh7/k9V+JGrouiSKDQsskIyBi/0xNDh4rwqGq5NA0narMy9/wQFB8iVMrB3dcfSx
         yIYLIyu40cIgQYjftKXF7R+PziJ8iBHLamPUZ1H7goncjck8eGjeWGwWnUQWNkkrrKxj
         4ZJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SdyQe6ZZDs1lWdZXHbpPBZZVikBSGqO3IlR6TjxL7B4=;
        b=Mmy8D9IKV/kIjC/BIyD5dPf2SyRAoegdjMttJ5QE4GFRzRhOMvHcvnrHWMUcw/JLr7
         wk7PtQlB0zknjxCvUeC+AAB06YtS7Nu86mnVs9vwBwzBLKsEJTktfXJQb0kpNBLpPWe8
         E3hXCoIsZSISEPxepuQIS7P2oAvuMWvq4huK1gs9AU454ParJcPHtvFyeGeh6N+sirHg
         Iq54FZQkoILe+MocsyDlonFKgWBWr+Rs5UaIQnUgnRKYAIMMkDRHQm1eF2HL1ZiXZsQD
         OdAsuFD5952gI7M6CobuOyY0d8vip2GoRPfyNrNBOyDg4oZ1L3PkecKeNKMdzOpqVHNV
         l9yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub57RHb8MuYTLhSrA3s3+AtEu+gSPXTTqIpVeY/gZhISBDTlB9b
	3D1tzYuRfuBTS0NSHFE+BR8=
X-Google-Smtp-Source: APiQypLHZ5IVGdCEV9JBW9Fw8LaQSLqLvatbTaL7V47axbRrORwYv29Bx/4crUc9j3Ysrj26qvOR3A==
X-Received: by 2002:a92:5f55:: with SMTP id t82mr11559104ilb.261.1587773831652;
        Fri, 24 Apr 2020 17:17:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:17c4:: with SMTP id z4ls3055812iox.4.gmail; Fri, 24
 Apr 2020 17:17:11 -0700 (PDT)
X-Received: by 2002:a6b:dd16:: with SMTP id f22mr11084608ioc.178.1587773831367;
        Fri, 24 Apr 2020 17:17:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587773831; cv=none;
        d=google.com; s=arc-20160816;
        b=nDndhqWUdSIbkjvPCm0O4yMg894uJ7oUb4Jg43jGzFomfPlfLkygxgXEvAOz9UuuHq
         RAtEGbECyGkHgNckG3AfJuIWbw8E1oi6i5w9kBjkO1VDlIJFhEuy8yUKldz/EYXj1dY9
         u2xBMD5GiyMhf6EcdItZUfwR2KJ59Ddq3HlvV2Jq6RwHsy2bQoCQEcxRsmBzI1FN7sfp
         WAm7TFoQfXkaV1Emvtf+1qk+sJFeX5++SCcc/dIKAvatUu3rrn94/e4AToU1chG8RN/5
         akKVu8XpN5uSm+MAYu/M4KJrGHoiavbUTwnUoFyJTKZuSnAnJpaYTNrol8oX7uZvLEuQ
         pl3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=qRqdGtGDwwLLxIwkhKkU5E5J4Dh9LHMlJAiQQkEFCoI=;
        b=Xhom4+YHjZEKSByOWzw0BSAi+amW3MUJJ0gK9b5twizErFKqu84Y04WouPrN81Nf6o
         jzAJuiQovpSkjp1loGPTukZxg+zMEqNfuundCOh91Dsj1pn0cjWOlRCJo0WfuRhDEcvQ
         dK8wyRNJ6GKt/NPGz0k+SHrqMwfX5LbVQH/vNZzj0GYc9i9s335ZP+HFw+iDsHBI1/xl
         aeqppYMohshp8tDbCYjZJ8DtyqhclQRIxGznH7xtTX5ucKtwBrKqilPNPjhKxsIrcx1w
         sCpgA9anusQeRdlDJeSH2ZqGgeSUGePj1C3wP9jp0iAp7MPlZGpLHGYI2yErR0Nv6uoJ
         a+3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=OmTWmL9q;
       spf=pass (google.com: domain of srs0=uv6n=6j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UV6n=6J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y87si241782ilk.0.2020.04.24.17.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Apr 2020 17:17:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=uv6n=6j=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9E7A82074F;
	Sat, 25 Apr 2020 00:17:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 724CF352339B; Fri, 24 Apr 2020 17:17:10 -0700 (PDT)
Date: Fri, 24 Apr 2020 17:17:10 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 1/2] kcsan: Add __kcsan_{enable,disable}_current()
 variants
Message-ID: <20200425001710.GF17661@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200424154730.190041-1-elver@google.com>
 <CANpmjNOaUc8-Y4MMre5mWLjywTZ+B0B9L-cQijeYEMcw9Vapsw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOaUc8-Y4MMre5mWLjywTZ+B0B9L-cQijeYEMcw9Vapsw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=OmTWmL9q;       spf=pass
 (google.com: domain of srs0=uv6n=6j=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UV6n=6J=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Apr 24, 2020 at 05:57:04PM +0200, Marco Elver wrote:
> On Fri, 24 Apr 2020 at 17:47, Marco Elver <elver@google.com> wrote:
> >
> > The __kcsan_{enable,disable}_current() variants only call into KCSAN if
> > KCSAN is enabled for the current compilation unit. Note: This is
> > typically not what we want, as we usually want to ensure that even calls
> > into other functions still have KCSAN disabled.
> >
> > These variants may safely be used in header files that are shared
> > between regular kernel code and code that does not link the KCSAN
> > runtime.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > This is to help with the new READ_ONCE()/WRITE_ONCE():
> > https://lkml.kernel.org/r/20200424134238.GE21141@willie-the-truck
> >
> > These should be using __kcsan_disable_current() and
> > __kcsan_enable_current(), instead of the non-'__' variants.
> > ---
> 
> Paul: These 2 patches may want to be in the set for 5.8, depending on
> what Will wants to do.
> 
> An alternative would be that Will takes my 2 patches and carries them,
> avoiding some complex patch-dependency. That is assuming his set of
> patches will go in -tip on top of KCSAN.

For the moment I have pulled them into -rcu and am testing them,
thank you!  I will leave them in the v5.9 bucket for the moment,
but please let me know how things proceed with Will.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >  include/linux/kcsan-checks.h | 17 ++++++++++++++---
> >  kernel/kcsan/core.c          |  7 +++++++
> >  2 files changed, 21 insertions(+), 3 deletions(-)
> >
> > diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
> > index ef95ddc49182..7b0b9c44f5f3 100644
> > --- a/include/linux/kcsan-checks.h
> > +++ b/include/linux/kcsan-checks.h
> > @@ -49,6 +49,7 @@ void kcsan_disable_current(void);
> >   * Supports nesting.
> >   */
> >  void kcsan_enable_current(void);
> > +void kcsan_enable_current_nowarn(void); /* Safe in uaccess regions. */
> >
> >  /**
> >   * kcsan_nestable_atomic_begin - begin nestable atomic region
> > @@ -149,6 +150,7 @@ static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
> >
> >  static inline void kcsan_disable_current(void)         { }
> >  static inline void kcsan_enable_current(void)          { }
> > +static inline void kcsan_enable_current_nowarn(void)   { }
> >  static inline void kcsan_nestable_atomic_begin(void)   { }
> >  static inline void kcsan_nestable_atomic_end(void)     { }
> >  static inline void kcsan_flat_atomic_begin(void)       { }
> > @@ -165,15 +167,24 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
> >
> >  #endif /* CONFIG_KCSAN */
> >
> > +#ifdef __SANITIZE_THREAD__
> >  /*
> > - * kcsan_*: Only calls into the runtime when the particular compilation unit has
> > - * KCSAN instrumentation enabled. May be used in header files.
> > + * Only calls into the runtime when the particular compilation unit has KCSAN
> > + * instrumentation enabled. May be used in header files.
> >   */
> > -#ifdef __SANITIZE_THREAD__
> >  #define kcsan_check_access __kcsan_check_access
> > +
> > +/*
> > + * Only use these to disable KCSAN for accesses in the current compilation unit;
> > + * calls into libraries may still perform KCSAN checks.
> > + */
> > +#define __kcsan_disable_current kcsan_disable_current
> > +#define __kcsan_enable_current kcsan_enable_current_nowarn
> >  #else
> >  static inline void kcsan_check_access(const volatile void *ptr, size_t size,
> >                                       int type) { }
> > +static inline void __kcsan_enable_current(void)  { }
> > +static inline void __kcsan_disable_current(void) { }
> >  #endif
> >
> >  /**
> > diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> > index 40919943617b..0a0f018cb154 100644
> > --- a/kernel/kcsan/core.c
> > +++ b/kernel/kcsan/core.c
> > @@ -625,6 +625,13 @@ void kcsan_enable_current(void)
> >  }
> >  EXPORT_SYMBOL(kcsan_enable_current);
> >
> > +void kcsan_enable_current_nowarn(void)
> > +{
> > +       if (get_ctx()->disable_count-- == 0)
> > +               kcsan_disable_current();
> > +}
> > +EXPORT_SYMBOL(kcsan_enable_current_nowarn);
> > +
> >  void kcsan_nestable_atomic_begin(void)
> >  {
> >         /*
> > --
> > 2.26.2.303.gf8c07b1a785-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200425001710.GF17661%40paulmck-ThinkPad-P72.
