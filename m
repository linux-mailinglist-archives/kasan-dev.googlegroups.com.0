Return-Path: <kasan-dev+bncBCG5FM426MMRBPMIYPFQMGQETVI3VWQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yFgzLj/EcGkNZwAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRBPMIYPFQMGQETVI3VWQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:19:11 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C0656A45
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:19:11 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59b6d228006sf5133488e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 04:19:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768997950; cv=pass;
        d=google.com; s=arc-20240605;
        b=WMWNgOnlQQoUzUKFDnKh5F/Yo99nr/jsbR8T7DaAfsbzS/z65e8Oyx9JtKHn9DpKWe
         smn7LV6rBKY/KKr8p0JW19JPGdaXwFtTOeaRKgYi0uLvim/76G8tGus77BhviDO5HBY0
         uCi36eyjSVSwKdTvjX8ij0cD+V8fVGJTg4HAnRw6bh3tUf+YybCGQbiourGgTFwragGu
         /AmnlOYTPanQCfQNJb6HWGysqtGmTTNbTMvob06lRZCz8wCnhoz4eGSl6c+GATLkBQE1
         xQYxWX2kCi6s3pfIPbX3cdYMuLGId+J4BO2aflRNrGJA9cmRRJYygxERck3o9nzKCXgB
         qsEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=EmlHaXpC3Zsws0ys7gVhdQpimyaABEOiuDCEOL8PraM=;
        fh=0RHIpGFWalKPAV4onPwsaXFr7dv6ZD9ITNevdxjCfW4=;
        b=OKX3w8ERhOf5cFbUH6cFVyu3FgFVtXDywcdropoRxvhzhgi4TpovVF0vY+T0snAsMx
         T8Jl1zv8W21k9OvwFtUHuv0R9yHceBYt03TWyK/vIPwchSkciA43I7+cdEq0h6BIisJ8
         /4AOEAtKZpcTe7McP9w52hddVFdpJv9XuwWUghfwefC3fwPUtj/ICBLcaygzw9J10ZjJ
         RZLXPXpBtn9pFLGFAHH2Z6aMz84DTyYdG5oxnPVBsUdCGvKiCVHhP9T3IH3f84EbZRm0
         ecsBQF76IR9ClqotYksF4XICut6oBjq4NJQXlFwxEd7gN6+jjPbpeKQwivGZIz+YsY/c
         SQSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Hz/KeHnu";
       spf=pass (google.com: domain of 3osrwaqkkcdc3eb57krae9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OsRwaQkKCdc3EB57KRAE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768997950; x=1769602750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EmlHaXpC3Zsws0ys7gVhdQpimyaABEOiuDCEOL8PraM=;
        b=Gb4KC69YXG5t//qxrkCfBH+h0btHjrvn7sXqXfVxNDCLJyJv5wXlcjlvMWj0LOobvr
         iCt2TPUd+dZc4qDSMwXdoPArPvx2Q0H13s2gXVTqdtzZeFRwrygoXABZSwW95mbw1G88
         v0/2WrwkTqz9c2f2dOoKezNjzCxkBkfO26/wLi2/GJ/+pjDllE/AXdC9BivPQkDuiqwc
         +9DlFGMr2ELG8+2qGV5mxbOzoesIdrra1vWHX1sDQT0zrtnpqViaaG0XP3Ya/PKHgvqy
         b2R+iIgMpNXriJ8EvvKMxCbgvLcD1tVE/wXQuBukY2cKM0Pm0OqUVdi/7swnVe5qlNct
         hboA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768997950; x=1769602750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EmlHaXpC3Zsws0ys7gVhdQpimyaABEOiuDCEOL8PraM=;
        b=Wb9OaENB8PytbvN8bIQ2shLG+1al5g2vhm2It00ipVfMDEt9uZOnAmCe48/DFrhgDB
         sjotqo5i1KpOYQTp0VgaFFyPjzepoGgiBg055G09L6F9cFTDSZ7WP9cOHKjcqO3foTQc
         TJGU05h+eHK1kHaXDf1SzgSPY2TMW6bLiK3vWKo/uiivh1KxPxdOPn6RVnCGcIh/ptGa
         eQp9XjJWjVc5q4NowUcQNBkBa9yD9gd06QNhHKAMAG4YCNa0zKz9/n3aKP8OTRlhSuZO
         p8pJD/RC/a6Y+51jnAmes+WxHIj4E3ctQcaHj0+TDFf2uvVB0iSsM9b6gF85iD0aMEBw
         KQ4A==
X-Forwarded-Encrypted: i=2; AJvYcCXfZ7lIxy9U7KdpF3PAXTGcgT7o8ykUlw1Y7fj1jsy3swrOz23xZPCLXceyKGjDVKjN8AKSHQ==@lfdr.de
X-Gm-Message-State: AOJu0YxbOb/w9V7lymyXr2y6c861wQ7hK14YZqtBAUohOfkceYt+twHe
	7njWP5Y14/A24FUbdPNdw8OCPDkdY18q/4BezUO0zumiiGdXYX2toOTv
X-Received: by 2002:a05:6512:3ca8:b0:59b:79d9:6cc with SMTP id 2adb3069b0e04-59baeef1358mr6755027e87.33.1768997950244;
        Wed, 21 Jan 2026 04:19:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GbxdJ5cvxMe6HgpavYqej8+zrnJ4nx5LS+8F06j6iYng=="
Received: by 2002:a2e:8856:0:b0:37a:2d92:62ea with SMTP id 38308e7fff4ca-385bbcc6a89ls597201fa.0.-pod-prod-02-eu;
 Wed, 21 Jan 2026 04:19:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnaBD1KOuk8/aIcoBz/lMc1IuokJM6uGdcvuYHdOXVNmokIFgVTV4ChqfLGwcOpGcJXa1ttnoZyvo=@googlegroups.com
X-Received: by 2002:a05:651c:1b8d:b0:383:27d9:79f1 with SMTP id 38308e7fff4ca-3838431e77bmr39590881fa.37.1768997947288;
        Wed, 21 Jan 2026 04:19:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768997947; cv=none;
        d=google.com; s=arc-20240605;
        b=ZiIiIvJF/q0GfQGqyyR1+twvo0GclgEP6xhZCNe8P2OAWHS/0LAY/++bpwPbW87Lk7
         sJFO/124C27wyZArVuHwFF+9Mal2aJoF9BLOoOR2tyOcoiVOp7tiGffTiUXvKcLCp98n
         Ghc4wD5TNvTTGzMKY/ko4fX/2LvW7hH07HZKuQOxknO1zBMZLLHBl26ZH2OAJ2wHNa0e
         NJ3LAz1vqFququary0STKlU4tOGqRWyH3nKZszntL7+wlI9uvmZkK4wNlvTxyfyizw2d
         xzIUkh2mf6ysGoZczmm/UlqT67Cr5voS1PfJOItNWmiwxMnsK/Cbhu+jn1+zsd55weGT
         y98g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tW692zqK7I63nrKQN1683F1Ixt/sQ4szIigR0l7y37E=;
        fh=4wXVDoP2C6gXepDOY4xIJiI0yKfRxE+q2PRsXTzwXn4=;
        b=k3SbHx6VtuSyya6AJRpx/EIuHassW6tqyUyuIYayshF2QN6AiRqh0f+RsYEMNQrUUR
         30aAivzgyOD2K9rNE6c+ZFfNaG/yVm7sJYAgoidrvmiND25rDyRC2LWIrwaFC1rTPbcX
         2/GdW2DWlJ3aqZKZwF5e2l903Oq5ATHj2nIcca0G0CBJcLsMYluMihrJ8Hz5tox/UzYd
         29f2Mx9VmBL/JvBXKvyuR6YjTfS/MPO88t3VVTGQuDSiKEWsOj8DpWL5hoP3L0irS0Eo
         M3wdTSjADG7/KvBy2LQCJ44dj28uws/sa2XxPsotRQQhV9/h+Uqt+UonTdO7ANwL7tU5
         QtTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Hz/KeHnu";
       spf=pass (google.com: domain of 3osrwaqkkcdc3eb57krae9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OsRwaQkKCdc3EB57KRAE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d35eabsi2900151fa.3.2026.01.21.04.19.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 04:19:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3osrwaqkkcdc3eb57krae9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477cf25ceccso66129115e9.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 04:19:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVDv8g/56aFQU/cNFdGApjtpqoDZ52dIM+ePP5TLEIde3QM/N/CBcwtfQZvo9UincpQg2mXSTa+0IU=@googlegroups.com
X-Received: from wmcu4.prod.google.com ([2002:a7b:c044:0:b0:47e:db03:6850])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:45d1:b0:471:14b1:da13 with SMTP id 5b1f17b1804b1-4803e7a2c17mr77774955e9.14.1768997946591;
 Wed, 21 Jan 2026 04:19:06 -0800 (PST)
Date: Wed, 21 Jan 2026 12:19:05 +0000
In-Reply-To: <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
Message-ID: <aXDEOeqGkDNc-rlT@google.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Gary Guo <gary@garyguo.net>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, 
	"=?utf-8?B?QmrDtnJu?= Roy Baron" <bjorn3_gh@protonmail.com>, Benno Lossin <lossin@kernel.org>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Elle Rhumsaa <elle@weathered-steel.dev>, 
	"Paul E. McKenney" <paulmck@kernel.org>, FUJITA Tomonori <fujita.tomonori@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Hz/KeHnu";       spf=pass
 (google.com: domain of 3osrwaqkkcdc3eb57krae9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OsRwaQkKCdc3EB57KRAE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCG5FM426MMRBPMIYPFQMGQETVI3VWQ];
	RCPT_COUNT_TWELVE(0.00)[19];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[google.com,gmail.com,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 57C0656A45
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 04:47:00PM +0000, Gary Guo wrote:
> On Tue Jan 20, 2026 at 4:23 PM GMT, Marco Elver wrote:
> > On Tue, Jan 20, 2026 at 07:52PM +0800, Boqun Feng wrote:
> >> In order to synchronize with C or external, atomic operations over raw
> >> pointers, althought previously there is always an `Atomic::from_ptr()`
> >> to provide a `&Atomic<T>`. However it's more convenient to have helpers
> >> that directly perform atomic operations on raw pointers. Hence a few are
> >> added, which are basically a `Atomic::from_ptr().op()` wrapper.
> >> 
> >> Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
> >> conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
> >> named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
> >> `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
> >> `atomic_set()`, so keep the `atomic_` prefix.
> >> 
> >> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
> >> ---
> >>  rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
> >>  rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
> >>  2 files changed, 150 insertions(+)
> >> 
> >> diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
> >> index d49ee45c6eb7..6c46335bdb8c 100644
> >> --- a/rust/kernel/sync/atomic.rs
> >> +++ b/rust/kernel/sync/atomic.rs
> >> @@ -611,3 +611,107 @@ pub fn cmpxchg<Ordering: ordering::Ordering>(
> >>          }
> >>      }
> >>  }
> >> +
> >> +/// Atomic load over raw pointers.
> >> +///
> >> +/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
> >> +/// with C side on synchronizations:
> >> +///
> >> +/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
> >> +/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.
> >
> > I'm late to the party and may have missed some discussion, but it might
> > want restating in the documentation and/or commit log:
> >
> > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> > like memory_order_consume than it is memory_order_relaxed. This has, to
> > the best of my knowledge, not changed; otherwise lots of kernel code
> > would be broken.
> 
> On the Rust-side documentation we mentioned that `Relaxed` always preserve
> dependency ordering, so yes, it is closer to `consume` in the C11 model.

Like in the other thread, I still think this is a mistake. Let's be
explicit about intent and call things that they are.
https://lore.kernel.org/all/aXDCTvyneWOeok2L@google.com/

> If the idea is to add an explicit `Consume` ordering on the Rust side to
> document the intent clearly, then I am actually somewhat in favour.
> 
> This way, we can for example, map it to a `READ_ONCE` in most cases, but we can
> also provide an option to upgrade such calls to `smp_load_acquire` in certain
> cases when needed, e.g. LTO arm64.

It always maps to READ_ONCE(), no? It's just that on LTO arm64 the
READ_ONCE() macro is implemented like smp_load_acquire().

> However this will mean that Rust code will have one more ordering than the C
> API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.

On that point, my suggestion would be to use the standard LKMM naming
such as rcu_dereference() or READ_ONCE().

I'm told that READ_ONCE() apparently has stronger guarantees than an
atomic consume load, but I'm not clear on what they are.

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDEOeqGkDNc-rlT%40google.com.
