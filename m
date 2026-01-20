Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI6YX3FQMGQERJG677Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IMP5MSWsb2mhEwAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBI6YX3FQMGQERJG677Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:24:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 62250476C8
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:24:05 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-432a9ef3d86sf2622612f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:24:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768926244; cv=pass;
        d=google.com; s=arc-20240605;
        b=biE+4onwKWDSZp6thrrcNKQX7O61so26za6RqX246hFJl3qqy69+zQRnnC5IBo3xTa
         3ovsdO5W1/C1zswAU1gM70b6HQEu1jXw1f30PGZdHpbn5429ZRf/no0Lq0SI7/H4n6zh
         qYhp/xHL6w0q5ghaf8zkrW16LtJcAzod6t+bsmjYY6eKwK03tMOQVNrLMH2fMyXc65uW
         gy+1z3YL0T3SAopb08EI9L1uCQBnfSx3i/4O6KegVXXuSDgigRHaOu/QYzUA8njZBykE
         UrlHAvYutiHFQvv7zFYkxFevCnJZ1tf9f6+QLaG5y31ANZY0bthkfaTRB/CeRfcfj4Zr
         2/Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HE/ocmu03pqnx/1k+ZWVK4nohMOYiN4x56s/Ka2bmTA=;
        fh=2j2F3WPnhpN6dbnFFudlViyPhxZbfF03InIGhjIWD04=;
        b=e18jzNDj3ew/MdMLK175q/1Rvc90tJmQCV5WByz7OhLFNJw3ERQ+7IrBAarfR+HZEh
         ccrOHyBRyDOli5mGS1F50/ZAd8m9yt8msNojtlvkg3XBtTml8Xv0gspvdCl6rsDQuZfS
         4Ph/nf4gsenugH68kyc3lV4my9MBnEZPGc/wrSxBv8uwBCq847kbzDU+BZwNHOQ9YJJo
         eG+MHlww88elkc/Tv0/WA1qGR71k2TvB8ys/zCgQ5pYwN9xi7B+bHedEB54ifcHXpEMU
         Oc/fRlWkwuWt925SRj4aK9b3jl57QOk0VHqhA0rezSf/lELZW0ICF7NlVyK/6gqMlHV/
         kEgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p5bwPL2y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768926244; x=1769531044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HE/ocmu03pqnx/1k+ZWVK4nohMOYiN4x56s/Ka2bmTA=;
        b=QhHUOstpO1aTUAkPac1uHJ2c2ybzZmQBvTE9BhKO8YJOBWZeJF6mzY57vR8RT5Kr6q
         FNV8PWO5PPa+C/vjRYbL2IERMfdSdIU9zZMO8TRT411nFjfigReUNMFl9LHUsZfouw2H
         AtoqkgZyjpDna8tg1zjOkDyV2oBXh6yair8rbFLFF4hNzr6h+atYI4dMCbq2QDpKVk4w
         boDJxVEPdAmlLWbX4Dq6Vis+imA+VNhc3ARIAK/TIIraF4UlSiBesiSKqEQ20fbURsNK
         SDpNC5avUJ9Wy3TNY+rWeqBCjgaH75wxULIuZndOQulQSy9wBsUO4yEpnUY6C0cneOZQ
         GiNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768926244; x=1769531044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=HE/ocmu03pqnx/1k+ZWVK4nohMOYiN4x56s/Ka2bmTA=;
        b=va6xRzo4zdF/4ZSQ84wGs7iWOpx0r2Wj4QEuHqondrFBpTSu4MfYlJkO56WaWgJBiF
         XsuLpDXs35gkqTbn9P/i8BqIjV0N4GKSTmbERnZPudjZbeAXSmBRH23kbYPy12LM4UtF
         +mW1JhjG/Est+FvbuLRjVLErK2hYESKM+hRD7XGK/L4Lrif3OlClZ6HM6EysXx4Fyrq5
         K/vHuzt1VRiObOce2smAyzaoRZEsvzK3c13J7qbWBhf2KatvTR0rVYFVbbz9s9zUK/um
         LXAvo1IJQRDvhKaWkdHDPqdWV/X1BBsbmyJyq4Uii7gp21+G/qBAfuRdckjEAheZqiv1
         XtJg==
X-Forwarded-Encrypted: i=2; AJvYcCXB39l8PDaIvhMYRJMYcsAwbSD7fBBCwhhLtd0duznU2G3HNl9iJZFuPcPKfRmO2hVU3XaDsQ==@lfdr.de
X-Gm-Message-State: AOJu0YzM1VqKIU11Hp/TaljX7Y/SnN44RWtcETe3A6W/YQjsNElnVYXa
	SYFbHIXJb3KMmKeQXjEJkSaa3co7ThU8RRi4cCs0mgv1eVcdqFLqx2jB
X-Received: by 2002:a05:6000:4304:b0:432:8504:b8a9 with SMTP id ffacd0b85a97d-4356a06769cmr22416905f8f.62.1768926244434;
        Tue, 20 Jan 2026 08:24:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HhDC+chBux5Jztsf3GVx+TF4gOYkX6hAp293n1f6S60Q=="
Received: by 2002:a05:6000:2f84:b0:426:cb20:6c35 with SMTP id
 ffacd0b85a97d-43563e18a25ls3352483f8f.0.-pod-prod-06-eu; Tue, 20 Jan 2026
 08:24:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUSamYN4NZX0QZ7SRY8czBvP2EVVQzzn3PB6OjKGrU2EgetPO5EvCdhiLSemGfWknHpeqftyXG9Oe0=@googlegroups.com
X-Received: by 2002:a5d:588d:0:b0:42f:8816:a506 with SMTP id ffacd0b85a97d-4356a067764mr20289027f8f.63.1768926241765;
        Tue, 20 Jan 2026 08:24:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768926241; cv=none;
        d=google.com; s=arc-20240605;
        b=QEhsgz5oh3wuDQt20k1MoaF2LExnmyUI+iW+EIUcs2Q3UksewjUWbX3d7uRFAowTdT
         IzdDSFfBVITmNNn4EfLKGm3WamgZpdbvVtag1jCniiud7yAvv5YNyiRJ6kiFP393GMlb
         MkIVUfJodV+EyfCYfCYBd54QhtwAuhO8tEZEgJfGWsNLgRf2umKwHT6ICxHq0OYBl1kE
         dJ7d4KIenmOyzJsuH3fbXbfSSd1cQ6dTCnn2mvQSslqtFgoqaAirxRm7Sk5Qb5I9J8WA
         GM+LJBJFT+r7hYPb/ozbkQOJikGmkhUe7o515MX44db3ujv+XbcRd0ozfr3y24aw1YQM
         /iBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=kNTcrrXAP9aiDb63ILRilIlxrZ3yFdWvD8IViTWFwuw=;
        fh=m8zERS8uy/9ZY8XHaNxcTUdgPGj//kF+uyQw+O0oDV0=;
        b=a/s4xat542Jno19/pZHsrQM2GJA3VdRGkn8dJ1yAj6mEKyND0dSvDwWaULIR2IqNX6
         jJiSOkhEDKkUF5uNRnDAs+OaAYQShB2d7804OdrJjiZh4aVqDMIMmwfy4aUrPj5P7+Jz
         OXVUOchfdWt/Lxq+l6nLmv5IprMOG191lCssJC9ucxTWC+Eqd71/VfXOlUNOWD7rLYYO
         hXcVVF2PFo9NDGsQd3IKlhPx1z18KTFUJPQXVFkgUbwbaMWGKoCjKZyg1gsXl282QJaz
         naDFyq4ZJzbmLJDJIJxknpyHVQ+4xdbmtW58dc0W4TurPNxqq/K6ui+dlFf5yS10LHwP
         BvGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p5bwPL2y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356996ed8asi283754f8f.7.2026.01.20.08.24.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 08:24:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-47ee07570deso38829425e9.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 08:24:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVDYcSSwUguu6BmQY4bVJY9fHQm1+S0Oy2oz/BCmxmGe0XA085qUic3M9MLonJYj9UQKZGqc9lw6fM=@googlegroups.com
X-Gm-Gg: AY/fxX5HrxNxLUPZp+dbhADfl+opGmv27y2nRB+3utYihieTFUD3OXV2iacOGxOF1+d
	vnHGFbGskWWh2j1W6VOb+tlYCYukF3X8ZavjrstfUNH5+ZbFt1afQCmRctq4j5PIo/jdndxMRAC
	ZlgSQLvavt3C4WTJ3jzMMQtoVfcryf9mo3lfISXzCqYrjmYhS17MuoQVV8mBbQ3By8i+MZqskeh
	HvQS8CZE10rLWOLd1nIerqL5HJ8uXrEL7KjVPLNAHpXgsvP4aaFPyjM8wmu3jeNJIeSX7KHT7Zm
	dwBWzTYkzmroI7PJhXlQ4P8MwqDvmZrLlh68cUFH8YbXfaYZ+BAPSPI1hR+9fg/4YW1DhZVv06T
	RnBvnZFyONDLBitJ+2Er+ygMpH4Lb9Vw4s0urPLy6/BXsdudYmhtEkhy9oj0EefKInmRQpxTG4X
	Wrm0TxDYc9DkDxzfrSiv7Q5lAnhq87KdlMJu6Jr15ktxhTWkk=
X-Received: by 2002:a05:600c:548a:b0:477:1bb6:17e5 with SMTP id 5b1f17b1804b1-4801eb10f27mr172875965e9.30.1768926240817;
        Tue, 20 Jan 2026 08:24:00 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:7c8:a22a:d5aa:54db])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-43569926ffcsm29599978f8f.18.2026.01.20.08.23.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 08:24:00 -0800 (PST)
Date: Tue, 20 Jan 2026 17:23:54 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>, Gary Guo <gary@garyguo.net>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Elle Rhumsaa <elle@weathered-steel.dev>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
Message-ID: <aW-sGiEQg1mP6hHF@elver.google.com>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260120115207.55318-3-boqun.feng@gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p5bwPL2y;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBI6YX3FQMGQERJG677Y];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[elver@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[lpc.events:url,mail-wr1-x439.google.com:rdns,mail-wr1-x439.google.com:helo]
X-Rspamd-Queue-Id: 62250476C8
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 07:52PM +0800, Boqun Feng wrote:
> In order to synchronize with C or external, atomic operations over raw
> pointers, althought previously there is always an `Atomic::from_ptr()`
> to provide a `&Atomic<T>`. However it's more convenient to have helpers
> that directly perform atomic operations on raw pointers. Hence a few are
> added, which are basically a `Atomic::from_ptr().op()` wrapper.
> 
> Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
> conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
> named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
> `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
> `atomic_set()`, so keep the `atomic_` prefix.
> 
> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
> ---
>  rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
>  rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
>  2 files changed, 150 insertions(+)
> 
> diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
> index d49ee45c6eb7..6c46335bdb8c 100644
> --- a/rust/kernel/sync/atomic.rs
> +++ b/rust/kernel/sync/atomic.rs
> @@ -611,3 +611,107 @@ pub fn cmpxchg<Ordering: ordering::Ordering>(
>          }
>      }
>  }
> +
> +/// Atomic load over raw pointers.
> +///
> +/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
> +/// with C side on synchronizations:
> +///
> +/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
> +/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.

I'm late to the party and may have missed some discussion, but it might
want restating in the documentation and/or commit log:

READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
like memory_order_consume than it is memory_order_relaxed. This has, to
the best of my knowledge, not changed; otherwise lots of kernel code
would be broken. It is known to be brittle [1]. So the recommendation
above is unsound; well, it's as unsound as implementing READ_ONCE with a
volatile load.

While Alice's series tried to expose READ_ONCE as-is to the Rust side
(via volatile), so that Rust inherits the exact same semantics (including
its implementation flaw), the recommendation above is doubling down on
the unsoundness by proposing Relaxed to map to READ_ONCE.

[1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf

Furthermore, LTO arm64 promotes READ_ONCE to an acquire (see
arch/arm64/include/asm/rwonce.h):

        /*
         * When building with LTO, there is an increased risk of the compiler
         * converting an address dependency headed by a READ_ONCE() invocation
         * into a control dependency and consequently allowing for harmful
         * reordering by the CPU.
         *
         * Ensure that such transformations are harmless by overriding the generic
         * READ_ONCE() definition with one that provides RCpc acquire semantics
         * when building with LTO.
         */

So for all intents and purposes, the only sound mapping when pairing
READ_ONCE() with an atomic load on the Rust side is to use Acquire
ordering.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW-sGiEQg1mP6hHF%40elver.google.com.
