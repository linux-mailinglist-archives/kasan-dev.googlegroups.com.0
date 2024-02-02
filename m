Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUUA6OWQMGQEI5QNBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A1210846D7A
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:13:39 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3638219eb79sf138655ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:13:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706868818; cv=pass;
        d=google.com; s=arc-20160816;
        b=BmlznHonADl29CSJ9mBsqEMmxos/0uciwDEyirQtXZLZXBiPqRdNybyk7alN5rZtdy
         /eKox+jxXufRbg3d4ow98CW2wR81t6hZ/StwmYM9wnKe1vpR++avFWVnI6uzElehXAr4
         chlwojw77IYjibHZDLwQesrsg0OdP4Ecpx+igZbH9vX3ie2f+W3fDC4Yya9/XDJb8fvd
         fzhzuFxWPQu7KHOU1gZeFRe1zRdVcpVxSfMewXHcI2DPwG3QUF+Jb8RdHWYdISNsdEYX
         tcCfbS0dCxHVuLkCn/g8jpPRbmT4zmCYtnZiUv31k0clLEMInM5zGndUVoYFVe7UbpWQ
         Jlpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5v4DZrWckuIOeHpFLeO9JpVIoHnu8m55SZNeIUTMo+I=;
        fh=1bctnidDWyH/QbqR5PTBCAr9R5IXvnO+h1wPbeZ6UaE=;
        b=iV+8vDPScvPQ7NAl18KxJcyBYvy3Bbhvy0qQ4ap+1py0eNLLxIAoSkFO4o4hiwBgSu
         QA1nmt8g8gfSgeeDoj+7KIAt/VW3qwh970PNHine3tllu/vnImidruzX+oHV45aFbNlM
         shBDVz6iROM51Xib/2FNutyqaTils06/YVRH5WfriXwIt1smP3rKM08mBGJ0YIUYoUme
         6fqBGcG9NqbC7Ovq6FVii+J5X9zyUFqRA6mEjWpZZD1Baqs1LkhsD182JzTTRO7h8nw7
         cCVckOFw4G77RywPCcB/p8ZGB3KNBkZv6KnJY1OO64nxkDUN2EyyUK0WCk7CAo3UEkDr
         SPDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HXzbXqnq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706868818; x=1707473618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5v4DZrWckuIOeHpFLeO9JpVIoHnu8m55SZNeIUTMo+I=;
        b=bUBErlXgovkCu7b70nMgy5w+TdN+Qs8yAQVnc4Ko1LIgczCzALanJZU3WJ2AwaDtaj
         e9wwnVANtZdTALiqSTv/ievreEBTY/ydkfrS0wpBQaOBOHVggL0bELyxXjl0D2vbchw7
         gE2lupF+ilqOZIpOR3szXD3f9HVqBTNQPo4DrO6YHqUM+rPsreVo4FGajNgrw26SoAnK
         QSH+bJJrUt8gvo27h/7Zx0yls3iBOLqMhviVy/HfiuRJM20j1NTEdo+7WAmZhENHaN6r
         LvHqDAFFKhMuS1RdhDo6HCLw9+9wtOhydlk5dD2XgHtdaiTtGejJPCWZegCoxYJbQHnB
         NDuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706868818; x=1707473618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5v4DZrWckuIOeHpFLeO9JpVIoHnu8m55SZNeIUTMo+I=;
        b=duU+aVmHu/eXrMRdgYjcFxeq/O5zB666sETMxgbOi74EEsoWJh3g0goXtsju45bjOI
         ZzPxPRNSwxBw+08n/7qorEUNr9ffN6BbF847CRMm8714bBY/XqsPrctNRREYCHQqVfQU
         aM8d9fouHAspE9JUksOYh/nZ3qt4oNQXsfpjNUBu08/42t7kGx0teHKJQYemvB0SOXSm
         xwvTQJMEGQGAAeCHsBWFVavhFUAw/b9unNAxQbTdLJDw9P2YOzj+BOirAIoIlzuBdv6s
         J6dbdPcpnmL2xoaevohHKQ+KpdP10gAW7w+c/F30RwRpVce0gBuPasyiHLevSNyXOgSg
         m+HQ==
X-Gm-Message-State: AOJu0Yxh8a7MED3hCMtEwA5R/peUtkppptL96m+pSwMHYAHwPk8rowlO
	b1KOUlM9SjlC8BXG6x3+coNGMgA1mSeQQJ2FFa5s/USHDYND0+1E
X-Google-Smtp-Source: AGHT+IFWyMlRXnEEimg3w9aCRoHKdqEe+dowGb5KHqI2RGFcLHymyxV5aLHBl+wJhiH7Yx/Nk7Xvfg==
X-Received: by 2002:a05:6e02:85:b0:363:82e4:cbb9 with SMTP id bc5-20020a056e02008500b0036382e4cbb9mr146793ilb.16.1706868818150;
        Fri, 02 Feb 2024 02:13:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5514:0:b0:59a:78b5:20dd with SMTP id e20-20020a4a5514000000b0059a78b520ddls266825oob.2.-pod-prod-08-us;
 Fri, 02 Feb 2024 02:13:36 -0800 (PST)
X-Received: by 2002:a05:6808:150f:b0:3be:3dd5:98f4 with SMTP id u15-20020a056808150f00b003be3dd598f4mr7550478oiw.35.1706868816145;
        Fri, 02 Feb 2024 02:13:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706868816; cv=none;
        d=google.com; s=arc-20160816;
        b=WkTzmjfG8jD9yOJ3RNzV+xO1Pajf/duLNMZqCcAndtWYP5KVmQcrtetNDsJBtGSlEU
         zJfTm5zOcE11LsMrN+pLK77HsfNpgdsPUsjfOn+OdJVJy3iL0KammWOljSV61KnUaqZF
         wN/Gh190N83GPfzzyEwxM1jm11JdZDB02SOFmNlWLAvBmBaGLfnX+ctMBmx4SFnUjoDp
         Fbfy/VPQpmUy0AJRIzB3nwIO6MQ5gFLmvmGL1ikXinBjKaLoVzCkpbMNBdL3UiGZOInf
         V1/09ia9pdCyoYvTVskqCkyamSKq5Z3LzqsjnavuF2s91SOf706of0/UftSg9YnK0NEC
         0Ehw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=itc1lWSzDl2ak1k3l4KGvZCc9ZWdvBnL0W7Kq6iSLm8=;
        fh=1bctnidDWyH/QbqR5PTBCAr9R5IXvnO+h1wPbeZ6UaE=;
        b=ar9AmBnB12SpbWhrWghOpgh1iGL8niyABTb7qM1f98KwOT5ARe9QBVRJbqHdd0/J2C
         0ap/6TfrH/CjS6Himu9WbqeSIKVmp1g7SxZMH7hm06HlLdX6sYkNhaoxm7AVeVzw50BE
         wVS4kwxkEZpXWi3xUeZ2JW+OC3N48w/m9eVuZ5ppZ28+j0paBZRev9ORaamT+ZaymZNa
         78THt0PkmtxaLy2XoUJY+1JlHGyesW7fBUAdtWXKRLFLamTXSLb3ySv11wXfJqFXMW0U
         JcZc0vucfQ7ol3lqSKywBSNAUAh9k9YZDuxMv7Xg8M7UKQILTCoPh0IVrzB+yziyqUoG
         PtZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HXzbXqnq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCUmH+ZSxnlq5coKd0e9tQchB4mKKidkBKTVzSASSjHMuMsYjuaidhWTyQaVRXOxljCo5oGLyDzdqFyF1II50VTH/jcwq19jM6UfRA==
Received: from mail-ua1-x92a.google.com (mail-ua1-x92a.google.com. [2607:f8b0:4864:20::92a])
        by gmr-mx.google.com with ESMTPS id x33-20020a056a0018a100b006dfe9a9195csi115155pfh.2.2024.02.02.02.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:13:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as permitted sender) client-ip=2607:f8b0:4864:20::92a;
Received: by mail-ua1-x92a.google.com with SMTP id a1e0cc1a2514c-7d5bbbe57b9so921650241.3
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:13:36 -0800 (PST)
X-Received: by 2002:a05:6122:13a:b0:4bd:789a:64dd with SMTP id
 a26-20020a056122013a00b004bd789a64ddmr6184191vko.2.1706868814944; Fri, 02 Feb
 2024 02:13:34 -0800 (PST)
MIME-Version: 1.0
References: <20240131210041.686657-1-paul.heidekrueger@tum.de>
 <CANpmjNPvQ16mrQOTzecN6ZpYe+N8dBw8V+Mci53CBgC2sx84Ew@mail.gmail.com> <nrknx5hi3nw7t4kitfweifcwyb436udyxldcclwwyf4cyyhvh5@upebu24mfibo>
In-Reply-To: <nrknx5hi3nw7t4kitfweifcwyb436udyxldcclwwyf4cyyhvh5@upebu24mfibo>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Feb 2024 11:12:56 +0100
Message-ID: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
Subject: Re: Re: [PATCH RFC v2] kasan: add atomic tests
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HXzbXqnq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92a as
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

On Fri, 2 Feb 2024 at 11:03, Paul Heidekr=C3=BCger <paul.heidekrueger@tum.d=
e> wrote:
>
> On 01.02.2024 10:38, Marco Elver wrote:
> > On Wed, 31 Jan 2024 at 22:01, Paul Heidekr=C3=BCger <paul.heidekrueger@=
tum.de> wrote:
> > >
> > > Hi!
> > >
> > > This RFC patch adds tests that detect whether KASan is able to catch
> > > unsafe atomic accesses.
> > >
> > > Since v1, which can be found on Bugzilla (see "Closes:" tag), I've ma=
de
> > > the following suggested changes:
> > >
> > > * Adjust size of allocations to make kasan_atomics() work with all KA=
San modes
> > > * Remove comments and move tests closer to the bitops tests
> > > * For functions taking two addresses as an input, test each address i=
n a separate function call.
> > > * Rename variables for clarity
> > > * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp=
_store_release()
> > >
> > > I'm still uncelar on which kinds of atomic accesses we should be test=
ing
> > > though. The patch below only covers a subset, and I don't know if it
> > > would be feasible to just manually add all atomics of interest. Which
> > > ones would those be exactly?
> >
> > The atomics wrappers are generated by a script. An exhaustive test
> > case would, if generated by hand, be difficult to keep in sync if some
> > variants are removed or renamed (although that's probably a relatively
> > rare occurrence).
> >
> > I would probably just cover some of the most common ones that all
> > architectures (that support KASAN) provide. I think you are already
> > covering some of the most important ones, and I'd just say it's good
> > enough for the test.
> >
> > > As Andrey pointed out on Bugzilla, if we
> > > were to include all of the atomic64_* ones, that would make a lot of
> > > function calls.
> >
> > Just include a few atomic64_ cases, similar to the ones you already
> > include for atomic_. Although beware that the atomic64_t helpers are
> > likely not available on 32-bit architectures, so you need an #ifdef
> > CONFIG_64BIT.
> >
> > Alternatively, there is also atomic_long_t, which (on 64-bit
> > architectures) just wraps atomic64_t helpers, and on 32-bit the
> > atomic_t ones. I'd probably opt for the atomic_long_t variants, just
> > to keep it simpler and get some additional coverage on 32-bit
> > architectures.
>
> If I were to add some atomic_long_* cases, e.g. atomic_long_read() or
> atomic_long_write(), in addition to the test cases I already have, wouldn=
't that
> mean that on 32-bit architectures we would have the same test case twice =
because
> atomic_read() and long_atomic_read() both boil down to raw_atomic_read() =
and
> raw_atomic_write() respectively? Or did I misunderstand and I should only=
 be
> covering long_atomic_* functions whose atomic_* counterpart doesn't exist=
 in the
> test cases already?

Sure, on 32-bit this would be a little redundant, but we don't care so
much about what underlying atomic is actually executed, but more about
the instrumentation being correct.

From a KASAN point of view, I can't really tell that if atomic_read()
works that atomic_long_read() also works.

On top of that, we don't care all that much about 32-bit architectures
anymore (I think KASAN should work on some 32-bit architectures, but I
haven't tested that in a long time). ;-)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A%40mail.gmail.=
com.
