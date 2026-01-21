Return-Path: <kasan-dev+bncBCG5FM426MMRBD5AYPFQMGQEEP22MHY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8MxrGBHQcGkOaAAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRBD5AYPFQMGQEEP22MHY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:09:37 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id F351357597
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:09:36 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-6580e793380sf1615553a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 05:09:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769000976; cv=pass;
        d=google.com; s=arc-20240605;
        b=W5bm+oIVyT0R8fvGNu9a2X/d6nGhatKN3MHtsT/S3hzwSeR1GV5STl7rm5auUn6fAP
         hIwQp3aOaSOeB8Tb+Cb2I3AhLWYCcbAaT3pAIB+E6UJZ0WrEGaF1dNpzGLHHazPIFnMO
         xJ7Z2lDCNr2NTTYnEvA/pBVAQZL6+qtaSDZecNxX6x0PjFUd8UKFoekIwieYWT8E981L
         30Zfb22/O2k+jmB6ndXomMa6E2GOs3j/x9HlpsDG+ef5nurB2wIv1IXzXQzkpOPRVq1H
         /W7JJMVbZJg7luQvKkwcOnh8hMAcYRwD0xFUzzZCwRNl1HhKGZAuEV2lWtHEe2m2vtIy
         jdsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1L3X01sFkrhkh13xU6zxCHkzlK0m5PR+yQYYEniGcVg=;
        fh=cpcZ2AeKkUEmO4dHpYqHdHAwOquRUM/Dkn6e1B+2fFk=;
        b=JGetp0dqw4/Z0xI2N+v9JGGdEJW1SvR9nCN+fYo4jjETXMiuZlkAj0ZhjXgOnUfEsd
         MHS6uurlyi3LEumvALu14KrZaCzqfFy250wlT6MLQYR+cpOdmCGUJmdRVNuPNae/XIBn
         L1TGbZdfu5l2gDw42Qd/3Dy/fQCAJmlayAll6cZB8kWOD/C9SkWp6laarESXz0kijapE
         esYQ/HuZo96f/P85Gh3bOHzQbHLRFdhe/tKUfzb1cdzXT2FtgX98xDmQYgoXjpowcD+i
         sfbg1kh9WwaA5vT8KKkc4KqxQjhYTn0U6BdSHCACzIj8AF3NOMVZEu1PjiyerJ8bJj7U
         MnsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VZnhJLT1;
       spf=pass (google.com: domain of 3ddbwaqkkcciitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DdBwaQkKCcIitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769000976; x=1769605776; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1L3X01sFkrhkh13xU6zxCHkzlK0m5PR+yQYYEniGcVg=;
        b=K3StNZ5bToTwCjrCDBuhLkqnmBtVsh11VnffSaRVbv3nrWvany0c5B9bWw2ilFN+MK
         jnkpRC1ACLwW+L//SAlejxLGXQ8b6OhM5m730Nnp2ncbIed9dMzwpQoZDr3AJwE9fGb+
         /nFzOz+Euj8cMBXskcVV0p3ZC6ral2W+dxsMZR3nrZQVa6td7aL+00gpW/tP3DEZ69cd
         iSzrr3ObVNCd2Z9YHrwUphqanWxQMX+eLhsKodt3UrJ6LyAtcV/04ls+p0yxaZoqWLkw
         UvUT6hEI9xhzjxqxRCzTzvKHnvLFzHcwYVJklAuzEzkgPxfHTaQM8TJuiLiYwslBhzNO
         5qCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769000976; x=1769605776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1L3X01sFkrhkh13xU6zxCHkzlK0m5PR+yQYYEniGcVg=;
        b=lUSGnkDWN+mrXNhOAVy/Mh5g5DH3Q5iGwu4y1daVz5S3btsshIho4UyoC7BwBCDJnU
         MJtXbGRhplrWQ6tTNBUc3qbCkveb8LJc9Sj4lSkuJYR6uKnb18oDguHYP5Um/b9h64BC
         z3jGmu9DPceP8LBpN4L67j6Jd+PpdMK9lsG3TGikCHWauqXKPlr1xLNweqw50ilvgPdv
         98XXj0jtL8OKqhGn9Sm0u5owTtER0j2aJVB5jt80vzxVrRCF7NSuuuyR4n8ZT2nqHWxU
         CdwzSPf0BIvmrht5hBI7FMrNnczxvI/NibgGg/u+dxNZV3Xoq8WRTpgcDoxzGGC7GZV+
         mmpw==
X-Forwarded-Encrypted: i=2; AJvYcCWexuTqH1+6QI6OpAdZrN8teNpDX24sac94CfV9Z9gHYFMNkTlB/qU3T8egfG7GFP/5WwP1eQ==@lfdr.de
X-Gm-Message-State: AOJu0YxHan48sYi3apiMy3A/ArbRy6aZ5KzpljlRn61ntZYI+8fS+D3A
	Lp+SYKIMbxz+kV+xz6dPRYsKe0Dy9syAwmN534PatLHcJlJ+gq8CVuIF
X-Received: by 2002:a05:6402:3491:b0:64b:5562:c8f4 with SMTP id 4fb4d7f45d1cf-654524cf27fmr14000214a12.7.1769000976092;
        Wed, 21 Jan 2026 05:09:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EMat8J8zJsggzTJFndWIOBVBPb2pAP9IGaaWWDHw7erg=="
Received: by 2002:a05:6402:3256:20b0:653:9932:b504 with SMTP id
 4fb4d7f45d1cf-6541c6e875fls5944790a12.2.-pod-prod-01-eu; Wed, 21 Jan 2026
 05:09:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWxQutDV1bn7SMukJy02xVGIaRpKj0R0st8o1jfnNK9D+azggd0UPzCWlXbXYHkCNDSBH5ufPnqqIM=@googlegroups.com
X-Received: by 2002:a05:6402:40d4:b0:653:9849:df10 with SMTP id 4fb4d7f45d1cf-65452bcc095mr13423194a12.26.1769000973947;
        Wed, 21 Jan 2026 05:09:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769000973; cv=none;
        d=google.com; s=arc-20240605;
        b=jbX+kEg1Oi3C4rE21TsilE/9ZJTtRE1yITVxGTwbAPPsQX35X4iMJYhJerpQFeHeK4
         cJmalMAHfnoc4TdRTrYT9Uan9riwOnGM07U9Ovx1LoNA8XVsFA1oTcDykoVRQDIG8eXN
         VGj3M7UkgS3sLQh9QOjUAwy7q2gvP+gQWCf7UZR2RlwdEMstrDXiqKHeTO8XPBxmE3YN
         sunIXPIkV3bnMFHqEZm/SVDxZY7WTFEmXARx4eQbxE6b4ab6GLiM5cMQxu2gKYGFjkDU
         O6E6Lr2X/S2BgtN47ZZx/Z5dfB2ejFNFTQC+Wsuc6X+QTxogGby5+JAQHZPD8u0+EXom
         Extg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=e6EfVFXbq2W0nAFcvfXqkhYP0i8qGUxUjSq0sP59zac=;
        fh=Tb9S4bW3DYMuTCgMIdtt1wNN5jfW9cxmlI0xW/E9bJM=;
        b=adBn8wygrJd94J5xWAZH8PZC5P/9HLjnGZtxwK+RSg4nPIuNq9LNC9CIGZ0NQG8AGW
         hBVE/guFylC0Y23CxKh+U1rXEBqow2x52d/qPXdQ+Bo6FvJwyCs1w2MC4NKE+1nk1uAy
         bli2Ke56Z/BHB4ZN65S9jxhLWzhdApyjbvkgiQGQHJ8PkyYSKLylHOpvX7SzbjEJW6ET
         XjdVXl0GT7uYPzuGNCi8HRqpZfEBdC9V87PCw3wNdldWLbQitOwKR6MIZlNW9psCzTNG
         kGUM+mvwjS1eKkCcZwmsOyXEk37O08SKc6eyw3ZgLQxIKO1AeSHZAIYqeLO9VbF3bYRE
         pHdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VZnhJLT1;
       spf=pass (google.com: domain of 3ddbwaqkkcciitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DdBwaQkKCcIitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65452cca91fsi251104a12.2.2026.01.21.05.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 05:09:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ddbwaqkkcciitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64b735f514dso7210323a12.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 05:09:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUgqPCz6RrOknmizslh3+zQHW06Xa4BjXVPzM3DzRrz6I1ZvbnlAUQ63qakv+rTLPpqGk6asmGyQ7k=@googlegroups.com
X-Received: from edrn25.prod.google.com ([2002:aa7:c459:0:b0:658:3f8:4209])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6402:51d4:b0:658:2e5d:cc1 with SMTP id 4fb4d7f45d1cf-6582e5d1110mr308806a12.21.1769000973476;
 Wed, 21 Jan 2026 05:09:33 -0800 (PST)
Date: Wed, 21 Jan 2026 13:09:32 +0000
In-Reply-To: <CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg=Ww@mail.gmail.com>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
 <aW_rHVoiMm4ev0e8@tardis-2.local> <CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg=Ww@mail.gmail.com>
Message-ID: <aXDQDFjKnjOi7Pri@google.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, linux-kernel@vger.kernel.org, 
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
 header.i=@google.com header.s=20230601 header.b=VZnhJLT1;       spf=pass
 (google.com: domain of 3ddbwaqkkcciitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DdBwaQkKCcIitqkmz6ptowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--aliceryhl.bounces.google.com;
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
X-Spamd-Result: default: False [0.79 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_RHS_MATCH_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MV_CASE(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	TAGGED_FROM(0.00)[bncBCG5FM426MMRBD5AYPFQMGQEEP22MHY];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-ed1-x537.google.com:rdns,mail-ed1-x537.google.com:helo]
X-Rspamd-Queue-Id: F351357597
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 01:13:57PM +0100, Marco Elver wrote:
> On Tue, 20 Jan 2026 at 23:29, Boqun Feng <boqun.feng@gmail.com> wrote:
> [..]
> > > > > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> > > > > like memory_order_consume than it is memory_order_relaxed. This has, to
> > > > > the best of my knowledge, not changed; otherwise lots of kernel code
> > > > > would be broken.
> >
> > Our C's atomic_long_read() is the same, that is it's like
> > memory_order_consume instead memory_order_relaxed.
> 
> I see; so it's Rust's Atomic::load(Relaxed) -> atomic_read() ->
> READ_ONCE (for most architectures).
> 
> > > > On the Rust-side documentation we mentioned that `Relaxed` always preserve
> > > > dependency ordering, so yes, it is closer to `consume` in the C11 model.
> > >
> > > Alright, I missed this.
> > > Is this actually enforced, or like the C side's use of "volatile",
> > > relies on luck?
> > >
> >
> > I wouldn't call it luck ;-) but we rely on the same thing that C has:
> > implementing by using READ_ONCE().
> 
> It's the age-old problem of wanting dependently-ordered atomics, but
> no compiler actually providing that. Implementing that via "volatile"
> is unsound, and always has been. But that's nothing new.
> 
> [...]
> > > > I think this is a longstanding debate on whether we should actually depend on
> > > > dependency ordering or just upgrade everything needs it to acquire. But this
> > > > isn't really specific to Rust, and whatever is decided is global to the full
> > > > LKMM.
> > >
> > > Indeed, but the implementation on the C vs. Rust side differ
> > > substantially, so assuming it'll work on the Rust side just because
> > > "volatile" works more or less on the C side is a leap I wouldn't want
> > > to take in my codebase.
> > >
> >
> > Which part of the implementation is different between C and Rust? We
> > implement all Relaxed atomics in Rust the same way as C: using C's
> > READ_ONCE() and WRITE_ONCE().
> 
> I should clarify: Even if the source of the load is "volatile"
> (through atomic_read() FFI) and carries through to Rust code, the
> compilers, despite sharing LLVM as the code generator, are different
> enough that making the assumption just because it works on the C side,
> it'll also work on the Rust side, appears to be a stretch for me. Gary
> claimed that Rust is more conservative -- in the absence of any
> guarantees, being able to quantify the problem would be nice though.
> 
> [..]
> > > However, given "Relaxed" for the Rust side is already defined to
> > > "carry dependencies" then in isolation my original comment is moot and
> > > does not apply to this particular patch. At face value the promised
> > > semantics are ok, but the implementation (just like "volatile" for C)
> > > probably are not. But that appears to be beyond this patch, so feel
> >
> > Implementation-wise, READ_ONCE() is used the same as C for
> > atomic_read(), so Rust and C are on the same boat.
> 
> That's fair enough.
> 
> Longer term, I understand the need for claiming "it's all fine", but
> IMHO none of this is fine until compilers (both for C and Rust)
> promise the semantics that the LKMM wants. Nothing new per-se, the
> only new thing here that makes me anxious is that we do not understand
> the real impact of this lack of guarantee on Linux Rust code (the C
> side remains unclear, too, but has a lot more flight miles). Perhaps
> the work originally investigating broken dependency ordering in Clang,
> could be used to do a study on Rust in the kernel, too.

We did already have discussions with the Rust compiler folks about this
topic, and they said that they are comfortable with Rust doing the exact
same hacks as C since that should "work" in Rust for the same reasons it
"works" in C.

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDQDFjKnjOi7Pri%40google.com.
