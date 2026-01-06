Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD6F6XFAMGQEX4VC5UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8CFCFAA88
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 20:29:21 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-65f30d38617sf2420155eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 11:29:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767727760; cv=pass;
        d=google.com; s=arc-20240605;
        b=FZ5t6W7qHKxbs/74CNadw6FZawOmuAEBV1qFS6XwtTb/lLFT9DQYmMNy3OfyCX0L5F
         hKTDwSAuotb4itAafxrie2gWglxJ3IR0YnpH2z3nU13sYm6Zt9JuWdAwY2GaY911t5Cr
         nuQI+U2O1aPqn36K08rbpNnMcirezXDTfngfcMr9IsciuopIa/YcnPLRfQPHK/J1VR02
         4R5vlL1P3Nczrzg1LRu6oEK+oNu42VT4M+9yrilP/GpSmpSBA/Lt/bmdTp0zVwTgLPCH
         z/CzSbHnSVUOL24n+eMFpXUOv3IZRI1Nzy4BQY1aMqY6DUDOLXwoR8iAiXldR21I9N1H
         Ag9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=v102CtK3v9OxZ3FlYLAHuUhpf3GGQyRdl8BozU+FptA=;
        fh=SngmasWzsKC6LEzBXjx1JR9IFpfyQTNxRiZm6ZJXCgM=;
        b=Wj6OEZjghWfUbhQL8Jrvjf4euS/Q3kf8ywdjdy/0yezjnZYZn9eTSNi3aldXYi8TuN
         +5i7kvdx1qSyCI26+A/blqEg1wpu0BBYmmwGMBa/cBnPwlRgC3OR50X+yxyCtohHxuz+
         HcE9ajiE4xV4l86jQqvipizawrA0ZEKZ5pExAQgFMHwWWw1xsb23m7xaGF1A1Hv6NFSK
         e/G8fWnJ/tmBBFCqMHN53A5vUwMlBtTSmy4rJPABp3KoEfjztFX1z7nqWP5zmCNf9NU9
         NUFR/2YSW1L1z9CVjvPU5F12xHuc5Q1y9I5ne9GwOgiCURdrMYpOHJW558d61y8vauT4
         ByMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VT5aD8DD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767727760; x=1768332560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=v102CtK3v9OxZ3FlYLAHuUhpf3GGQyRdl8BozU+FptA=;
        b=SHaMQ0uFzgZX3vB6qO801i4E/aFDeIu4mNa4lDadxW1ev52VgDUpwkT6Xxkplb3L5U
         /QmQdE4UkuelG+wl/IAEi8+8zx/rY9NO2O6Ed0/B0vJgF81XHQlayt51Es1zl1T9c984
         U5tE8XZaY/eIVanSjOV4CGv3KwmuKVIn1g3sSehlY7W/p8kGC6Y1WG4YkLabwpkUYRS0
         JprRJdu9UwXc29lEMlejIyTV35iGMF6nI/GxqfwxQvOqCfnjuco9zw6PnIX1k8sImlxD
         s89J4+0eGfsKYQOk66hZSNtn+K+ISNPCdbBlX0jHbAnhwHXpfwvYeys4QPtBS42osErr
         J/fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767727760; x=1768332560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=v102CtK3v9OxZ3FlYLAHuUhpf3GGQyRdl8BozU+FptA=;
        b=ShIJsKziYMUXVM/0nal5InN10YRUY2czr1siJBaRkRd27XP6sxiEBPwVnyOkqkbSp9
         SfTSZMbEdK75UW0go3cZR90RgoKfgCi1+zQUG4l/7lU3VGrkab8OiLh96haDtOjLNLVE
         8snvarBoD2LR9zSjrUPlpxoQZJAOC9vR9evJ6SrpeemvyFhtR++yMSFvmmXmekaIf1yT
         RGLBM0Phz2kvmd34Mbpw/ZSyBssnv6KkNjkD9MjfaJhevUID2V46rib3mkiFwETNimCL
         ZnK+hLiXZA6PWdP8QjcpCFquJ6SB+bk3buaBeT3AQE9RrRgYCkFTyreYv+WLfW7U6LZh
         WiHw==
X-Forwarded-Encrypted: i=2; AJvYcCVZsNS3YLNXkn8z4hgfQkJV+GJSR4sgNKXHxLG9BHfondhEOl/8hO4r7QyAGbNr1uRa8sXgqw==@lfdr.de
X-Gm-Message-State: AOJu0YxTP8cze+6fICfpbyrvdMUZCbVLxN+Aj90i6ah4hPbs8sz0ZdM2
	1XKdHVRfUMzba5jPIMCDp8X049a/GfKVtquKZOumMY4RKmpmscQ6GlT5
X-Google-Smtp-Source: AGHT+IH4aiMVfqsT/A/Irz8iMFMzCi/nCVDf+l9QbVmb3lUsnbVXfGqZfgoJGOMG11vmrRIOQJCfaw==
X-Received: by 2002:a05:6820:448d:b0:65b:38e2:33b5 with SMTP id 006d021491bc7-65f47a1a6b7mr2113267eaf.49.1767727760069;
        Tue, 06 Jan 2026 11:29:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaFioLeE4osCY0UjgiABqAywel8HITFeLLHo4rhmHe7VA=="
Received: by 2002:a05:6820:26f:b0:65e:8c88:30dc with SMTP id
 006d021491bc7-65f47430c5fls498997eaf.2.-pod-prod-02-us; Tue, 06 Jan 2026
 11:29:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhD1wy6rMAqoEbQJP4pmEvKPlmi9R/IKbMPIpHvOCYkBNdVLE0/DQGhZzLjIN8WvgfVnuoXkUW0oQ=@googlegroups.com
X-Received: by 2002:a05:6808:6b8a:b0:453:746a:c618 with SMTP id 5614622812f47-45a6bf28457mr57262b6e.61.1767727759131;
        Tue, 06 Jan 2026 11:29:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767727759; cv=none;
        d=google.com; s=arc-20240605;
        b=eyC2e1cogu9zpYvZhNeeim8wb4yHVo+bvhKsJ1doSaOQgBjaHed+vaLwOSV7U7YsoT
         rO7HLqvJfTfe8g11Uk+NPkb+Y05edLg0g+ayDHrPTemMdGEYQfysB/ic0qlrpwCE2KnC
         2AXXqlmIHGck8LiaUGs/tLkGcdQCg6pxu+uiJjO989O00UVuKfbZ8TCRbSruvVwzBHTN
         +j1p8LkDU/KdcgQItqLbYYUZz+rlqFR7HBFtO2KIVzIQ5Lz2VcRRWk9WiwgtUXMDmOr2
         qA91Naur3K53DRCv0gb1crhUolHSw1WEqwFEGsUO8FzLgcF4BuJaF8S/fSlASOtTTvq8
         1aPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h+fw2uOH7rfXDKHv296LmegV1D5QyXRSiBc8OZxA9qs=;
        fh=Uu2TcjfJvzy/HVud0iZpdJFvjmHxW/ftsx4EYqAgSu8=;
        b=HBQnKqgdQxkx+CT+eLTBNOfiYRdEIkal0UWg70xaK+n3xz4rM0eUOrzl5t6LHcANkN
         r4AQPIl8Zmk7ahhEXokGLzRLO2G+E+R2jBAFuC1Qr0dB/P+qvyc2c3SrT6jg50/MHAkx
         EpgfBwq6Z+FjViA93iD8OwMy8w32RTjbF/hSH6eWCPXRCIdTz0bQ/q5YYCmbADLw1HK3
         Hkhhlot50k7kRsW9p4ie/rmV6+Rs/RUiPSQ/vZ0jt6EjpfQTdk/sVVudHEZPntmMHxwp
         Fum+OIj4O5pC5emMJ6WhKfwV9hMM7jr5SXvYPqTqm/W4UIug3+1GEAVJ2iWXNZah3SbJ
         tC9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VT5aD8DD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1229.google.com (mail-dl1-x1229.google.com. [2607:f8b0:4864:20::1229])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45a5ef8b70fsi208756b6e.8.2026.01.06.11.29.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Jan 2026 11:29:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) client-ip=2607:f8b0:4864:20::1229;
Received: by mail-dl1-x1229.google.com with SMTP id a92af1059eb24-121b14efeb8so797607c88.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Jan 2026 11:29:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUmaoHn0yBuZObo0+R/FB6/lTpTOTK13UbCTab/AgJ9V2+/zb+pg3UXT747824Crk4QI9ymWJtAQcY=@googlegroups.com
X-Gm-Gg: AY/fxX40Wn7U6Kkoqol1RQe7FOtkF61hcIExOxwM8swUJ+/fZIp/Q0CrTn9cttEyWAw
	b9L7D6iCp8Ghs7vEX47lw3J7iGkwnFVlv1aivmYLoiq6ymR94ALNt0CPOQy0uATet63z6DAeHN+
	ELi4y+w00+LnN0xfeWhUezCC53ILnr4urG9zQae1StK2mGZi+QbsexHKhDCWyw8T08GL3OUOFi+
	af5G9fKeZ+v9+QBAdlTtQr9EiOPgzzNxLK35du0ddNMzmQubuEfvext5El/0tMxlD/MWHwMAa0L
	AzIgtA6tflfn+CGRXxqdZqRnu4g=
X-Received: by 2002:a05:7022:4199:b0:11b:ca88:c4f7 with SMTP id
 a92af1059eb24-121f8b67cc0mr18897c88.40.1767727757907; Tue, 06 Jan 2026
 11:29:17 -0800 (PST)
MIME-Version: 1.0
References: <20251231-rwonce-v1-0-702a10b85278@google.com> <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com> <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local> <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local> <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
 <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
In-Reply-To: <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Jan 2026 20:28:41 +0100
X-Gm-Features: AQt7F2pduEl0iy3ZX0HLxlaIYaHR9bRxCAH-5viQta6DXK6OToIwGPr_JhTocFA
Message-ID: <CANpmjNPdnuCNTfo=q5VPxAfdvpeAt8DhesQu0jy+9ZpH3DcUnQ@mail.gmail.com>
Subject: Re: [PATCH 0/5] Add READ_ONCE and WRITE_ONCE to Rust
To: paulmck@kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Alice Ryhl <aliceryhl@google.com>, 
	Gary Guo <gary@garyguo.net>, Will Deacon <will@kernel.org>, 
	Richard Henderson <richard.henderson@linaro.org>, Matt Turner <mattst88@gmail.com>, 
	Magnus Lindholm <linmag7@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <lossin@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	FUJITA Tomonori <fujita.tomonori@gmail.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Lyude Paul <lyude@redhat.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Anna-Maria Behnsen <anna-maria@linutronix.de>, John Stultz <jstultz@google.com>, 
	Stephen Boyd <sboyd@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VT5aD8DD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 6 Jan 2026 at 19:18, 'Paul E. McKenney' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> > On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> >
> > > Some C code believes a plain write to a properly aligned location is
> > > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > > it's recommended to assume such), and I guess that's the case for
> > > hrtimer, if it's not much a trouble you can replace the plain write with
> > > WRITE_ONCE() on C side ;-)
> >
> > GCC used to provide this guarantee, some of the older code was written
> > on that. GCC no longer provides that guarantee (there are known cases
> > where it breaks and all that) and newer code should not rely on this.
> >
> > All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.
>
> Agreed!
>
> In that vein, any objections to the patch shown below?

I'd be in favor, as that's what we did in the very initial version of
KCSAN (we started strict and then loosened things up).

However, the fallout will be even more perceived "noise", despite
being legitimate data races. These config knobs were added after much
discussion in 2019/2020, somewhere around this discussion (I think
that's the one that spawned KCSAN_REPORT_VALUE_CHANGE_ONLY, can't find
the source for KCSAN_ASSUME_PLAIN_WRITES_ATOMIC):
https://lore.kernel.org/all/CAHk-=wgu-QXU83ai4XBnh7JJUo2NBW41XhLWf=7wrydR4=ZP0g@mail.gmail.com/

While the situation has gotten better since 2020, we still have latent
data races that need some thought (given papering over things blindly
with *ONCE is not right either). My recommendation these days is to
just set CONFIG_KCSAN_STRICT=y for those who care (although I'd wish
everyone cared the same amount :-)).

Should you feel the below change is appropriate for 2026, feel free to
carry it (consider this my Ack).

However, I wasn't thinking of tightening the screws until the current
set of known data races has gotten to a manageable amount (say below
50)
https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
Then again, on syzbot the config can remain unchanged.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> ------------------------------------------------------------------------
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> index 4ce4b0c0109cb..e827e24ab5d42 100644
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -199,7 +199,7 @@ config KCSAN_WEAK_MEMORY
>
>  config KCSAN_REPORT_VALUE_CHANGE_ONLY
>         bool "Only report races where watcher observed a data value change"
> -       default y
> +       default n
>         depends on !KCSAN_STRICT
>         help
>           If enabled and a conflicting write is observed via a watchpoint, but
> @@ -208,7 +208,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
>
>  config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
>         bool "Assume that plain aligned writes up to word size are atomic"
> -       default y
> +       default n
>         depends on !KCSAN_STRICT
>         help
>           Assume that plain aligned writes up to word size are atomic by
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPdnuCNTfo%3Dq5VPxAfdvpeAt8DhesQu0jy%2B9ZpH3DcUnQ%40mail.gmail.com.
