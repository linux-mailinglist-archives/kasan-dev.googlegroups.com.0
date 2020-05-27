Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVVUXD3AKGQEWIX34HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F3AF1E3AD6
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 09:44:25 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id v6sf23094063qkd.9
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 00:44:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590565463; cv=pass;
        d=google.com; s=arc-20160816;
        b=NNVWsWlrH/GGi5C7J+5zlWCEnOXpkiHeihtuCE3V+jnxBUfcDEb39RMGq/0TbCGCFO
         ILDwwjKCrRCP1dfQqhXo45JJZoVPd5yM3EW7Vj9IjtSX2TE6y0c5A+35FTpu33t/hK7e
         8+UyradxxacVCbNnzQBbiYekY19EUSQf55srL/66Pi/B8XKwpt/vHDWkaHHvcFekDng+
         BlTxNFVSxc7uM9vBAwsRBf0ukvFKEbI0Fuw19W4MjNkDpRADcGSSZpxvM9JOuufSTHWy
         0rLTbrJLAhs870890oisKDGfkZyM1zRrRe9yXuUCtyeYpn5k5PHGUwmthE3ENvN2ojTc
         4XzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tshbWPXB1v6hkxBQ0opy1ewXndYT4PUFgX0hans4QYw=;
        b=YHOetualOCm16Y+8ur6AyGdxCR5daoGsBuSKm7mHsaD8i1V2wmCc8bBke/krtKjy7D
         fbZvYYwYudJgWwjt70ocDmOfSvlvbZt8SzymVyhK3CLbSZ0bkS4yK0lxVQUl/ke0Na+v
         vfa5hcQ3ir1f50WujGAJEonAN70nrQvFUdA+UYVvC5b6lWTbIlaNGSgM4Vdiqu/Q/f0z
         vzbBdGuXFrSE3BvyFG/1tFSVIL3xAShdqwhWrFczT9y6aTq51QYWc7o9CIYBmuaUlxhP
         50VL+A8V8iFAVz21VA1I+bgobFX46lG8gJtXGRmOEfnbSwDb3OhL67x0TqX9zXqrpz+w
         Z24g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bea7jtiq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tshbWPXB1v6hkxBQ0opy1ewXndYT4PUFgX0hans4QYw=;
        b=XwyzDSGDkWgrRG9I8cf6cohMarVaISIZMFmLwLQwISO8Q0pBDXumNao5VUFwKGVU31
         zA+QSlocW6BjN9OrAaJTHxgXBL9GjcUeVu2jOkiIYhXym2QVcbiJ41Xh9uH9YHupvUI9
         CxFWIvNwHYImQAx0wY7hKkzh8X+TFgWrWxT+LMHOWDWcAeZwiGWGPUbYdIfOxbiOE/Df
         bKiE9igRP9WNCY3ys9YN4nKT0hAuwXGGAudGRDeRPUlT7x8hkVUWV3/xmUvrGGTYEtz5
         68Wpi4MwtOn0aQ1JxJuNpFrYqSvbbssHSoYDCEsK727pNNwRfB0NjszzqmTqkDFg1rd/
         h6kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tshbWPXB1v6hkxBQ0opy1ewXndYT4PUFgX0hans4QYw=;
        b=mkODMt67qlICsZudAvkSbW0tVjob0POl8n5m4I5xtK6yYa0JmCFBwLBZlbYznhn+va
         ZMwPXeMnN8oQx1S4zlT2wiE+O5gbZ4gCBTdAUNI2eXVrFebd1YAWWulG5UiFtM9E+y2H
         6vsLct8jMFyP7NhpCRN9qFcbrgI7k2pJNUoz1UH5c5K61+1nrqlSZPpV35W51xSdv88U
         oosTXA6s/1y9mU44tBukO9Olm9mon1QeqM8DeNePpMa5d1XGEwnE6d6HD0+bXxelkH3h
         iyw/uAf5cEQAef00QUhoprLxgAIXlIb/UidNX4ZpW1Vjd1dQyxZx5Q8xoXE3lLf04GTm
         ljKg==
X-Gm-Message-State: AOAM533ibVPqKy1Wm0B7JX0JO1842KZgWGVsKgAzivNdn3sMxC4EE0yr
	lOKrS9J3LwX/882uvmdTNi0=
X-Google-Smtp-Source: ABdhPJxdj74nRs2TosVKNLhHc51kzA2UZYM/1t9wwLOwxjiKK2mB+TGsw+Zw1Ep0N5dzLXe/Y1ISyQ==
X-Received: by 2002:ac8:71cc:: with SMTP id i12mr2882214qtp.178.1590565462331;
        Wed, 27 May 2020 00:44:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c8b:: with SMTP id y11ls1944495qtv.4.gmail; Wed, 27 May
 2020 00:44:22 -0700 (PDT)
X-Received: by 2002:ac8:4d0f:: with SMTP id w15mr2996382qtv.120.1590565461999;
        Wed, 27 May 2020 00:44:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590565461; cv=none;
        d=google.com; s=arc-20160816;
        b=K3py3WAL5ULhm46p4Foiyev1StZFqikft1Fjbvi1ih3g9+fa/fw74oWpZgFZNe6F24
         /8t/Eqh938LMOTB1sVpIEXDZGgYubu57nvqULh8azoRZOloBLV6lAmo458Xqqgz5R0Br
         UPDKatPtLOSkyJJ4NrFmdJ/EtCFX8Aephe1zAk3xmEqfINp8IPa0KQhr/m55xASFXImf
         Q+YVER3nsQQho9d0M790BdGY4L1VOp2g7RUOU4ggbrPcjxpjiPyfrsoSIwFgbwLMFsi5
         C4yO4xbbPZM2YPoQPTnOwq8XDgTRT0n9pr0BYNMEXfkskCVf3p4jwpM2YD0VzUV8XzYT
         vubw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zbcumbiOybyvrNPq+S8EAFFWXxgWspgqCp4xRwbHRuI=;
        b=fFLYxDepq34oVTBiT8ZjiQoe80WKlRoi0fWUnMreLzLQG0paSF7OeUPhUQmEKjIc7q
         nCMREy+kia2Hx1n/ih8AAPa//NvLxN2MF0rLW6a09dj3VWWn/l90R3lDiibeVK3hF6jM
         4k807wY24ywEDfbr1teqlgaJ6tYJEkF1NiMYBE48hHBxihxnTYSjKUHEr03xd456dj1T
         6a6R5BNHKPYWd2aXTpoi51yYQDqfIErncskcCQXgYePwM0tCXk/f3VQwRNRnRAnIOiV8
         oWU3kth+b2IWasqgcPjVdlKEsEo9lNF5MFXdHmjmELfN618fvrz30bwh4afdo6Vel1np
         X5qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bea7jtiq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id z206si222955qka.4.2020.05.27.00.44.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 00:44:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id x22so18494447otq.4
        for <kasan-dev@googlegroups.com>; Wed, 27 May 2020 00:44:21 -0700 (PDT)
X-Received: by 2002:a9d:27a3:: with SMTP id c32mr3972097otb.233.1590565461246;
 Wed, 27 May 2020 00:44:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck> <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
 <20200526173312.GA30240@google.com> <CAK8P3a3ZawPnzmzx4q58--M1h=v4X-1GtQLiwL1=G6rDK8=Wpg@mail.gmail.com>
 <CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com> <20200527072248.GA9887@willie-the-truck>
In-Reply-To: <20200527072248.GA9887@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 May 2020 09:44:09 +0200
Message-ID: <CANpmjNO2A39XRQ9OstwKGKpZ6wQ4ebVcBNfH_ZhCTi8RG6WqYw@mail.gmail.com>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
To: Will Deacon <will@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Nick Desaulniers <ndesaulniers@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Bea7jtiq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 27 May 2020 at 09:22, Will Deacon <will@kernel.org> wrote:
>
> On Wed, May 27, 2020 at 01:10:00AM +0200, Arnd Bergmann wrote:
> > On Tue, May 26, 2020 at 9:00 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > >
> > > On Tue, May 26, 2020 at 7:33 PM 'Marco Elver' via Clang Built Linux
> > > <clang-built-linux@googlegroups.com> wrote:
> > > > On Tue, 26 May 2020, Marco Elver wrote:
> > > > > On Tue, 26 May 2020 at 14:19, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > Note that an 'allyesconfig' selects KASAN and not KCSAN by default.
> > > > > But I think that's not relevant, since KCSAN-specific code was removed
> > > > > from ONCEs. In general though, it is entirely expected that we have a
> > > > > bit longer compile times when we have the instrumentation passes
> > > > > enabled.
> > > > >
> > > > > But as you pointed out, that's irrelevant, and the significant
> > > > > overhead is from parsing and pre-processing. FWIW, we can probably
> > > > > optimize Clang itself a bit:
> > > > > https://github.com/ClangBuiltLinux/linux/issues/1032#issuecomment-633712667
> > > >
> > > > Found that optimizing __unqual_scalar_typeof makes a noticeable
> > > > difference. We could use C11's _Generic if the compiler supports it (and
> > > > all supported versions of Clang certainly do).
> > > >
> > > > Could you verify if the below patch improves compile-times for you? E.g.
> > > > on fs/ocfs2/journal.c I was able to get ~40% compile-time speedup.
> > >
> > > Yes, that brings both the preprocessed size and the time to preprocess it
> > > with clang-11 back to where it is in mainline, and close to the speed with
> > > gcc-10 for this particular file.
> > >
> > > I also cross-checked with gcc-4.9 and gcc-10 and found that they do see
> > > the same increase in the preprocessor output, but it makes little difference
> > > for preprocessing performance on gcc.
> >
> > Just for reference, I've tested this against a patch I made that completely
> > shortcuts READ_ONCE() on anything but alpha (which needs the
> > read_barrier_depends()):
> >
> > --- a/include/linux/compiler.h
> > +++ b/include/linux/compiler.h
> > @@ -224,18 +224,21 @@ void ftrace_likely_update(struct
> > ftrace_likely_data *f, int val,
> >   * atomicity or dependency ordering guarantees. Note that this may result
> >   * in tears!
> >   */
> > -#define __READ_ONCE(x) (*(const volatile __unqual_scalar_typeof(x) *)&(x))
> > +#define __READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
> >
> > +#ifdef CONFIG_ALPHA /* smp_read_barrier_depends is a NOP otherwise */
> >  #define __READ_ONCE_SCALAR(x)                                          \
> >  ({                                                                     \
> >         __unqual_scalar_typeof(x) __x = __READ_ONCE(x);                 \
> >         smp_read_barrier_depends();                                     \
> > -       (typeof(x))__x;                                                 \
> > +       __x;                                                            \
> >  })
> > +#else
> > +#define __READ_ONCE_SCALAR(x) __READ_ONCE(x)
> > +#endif
>
> Nice! FWIW, I'm planning to have Alpha override __READ_ONCE_SCALAR()
> eventually, so that smp_read_barrier_depends() can disappear forever. I
> just bit off more than I can chew for 5.8 :(
>
> However, '__unqual_scalar_typeof()' is still useful for
> load-acquire/store-release on arm64, so we still need a better solution to
> the build-time regression imo. I'm not fond of picking random C11 features
> to accomplish that, but I also don't have any better ideas...

We already use _Static_assert in the kernel, so it's not the first use
of a C11 feature.

> Is there any mileage in the clever trick from Rasmus?
>
> https://lore.kernel.org/r/6cbc8ae1-8eb1-a5a0-a584-2081fca1c4aa@rasmusvillemoes.dk

Apparently that one only works with GCC 7 or newer, and is only
properly defined behaviour since C11. It also relies on multiple
_Pragma. I'd probably take the arguably much cleaner _Generic solution
over that. ;-)

I think given that Peter and Arnd already did some testing, and it
works as intended, if you don't mind, I'll send a patch for the
_Generic version. At least that'll give us a more optimized
__unqual_scalar_typeof(). Any further optimizations to READ_ONCE()
like you mentioned then become a little less urgent.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO2A39XRQ9OstwKGKpZ6wQ4ebVcBNfH_ZhCTi8RG6WqYw%40mail.gmail.com.
