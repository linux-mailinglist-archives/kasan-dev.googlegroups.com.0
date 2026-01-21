Return-Path: <kasan-dev+bncBCG5FM426MMRBGU7YPFQMGQEL57EREQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GASFNpzPcGkOaAAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRBGU7YPFQMGQEL57EREQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:07:40 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 806B957530
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:07:40 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b6cf50eb2sf3013283e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 05:07:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769000860; cv=pass;
        d=google.com; s=arc-20240605;
        b=LdGQLI2R46o7d57MvH08Ojb6/CdRq962SYpwXkVyDY1klCIHyLHl4bJH3VnsXEwBkB
         cN6KjfpPsJPZUkZQFP6ms3cd7k2dIyiTRVAWfyjyUfJAYcKhpAnLaXwjRW6WDU3UDOrP
         QzrUfbtN7ihUrj8Slt77Fsn/vCfPCawFEnX65i2Wz2w2N3WNBXfRPY3NublwZFeY5YaO
         6Z2ycwfsQcM6Ag36TtWjh091qqlk9WG2kQ+h9tGOh6ReKrJj95yqTOmgerXE4G6EYgGd
         +1XQv0/Bj7higVg7S0DxQXO8sHk1MeWtrcFAYBWljiKkVuAiswX4TBy6sbQXczBfgdvj
         DoJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3Yct09DPxb9RFlFN9OP/v08slpBd4CYopIhkBFEv5QM=;
        fh=3XzQbZ8A+6RtycNSyYlm68uDUgG7mO1+rz3jZs/eb1U=;
        b=EGAwApmMAfncM7Ecz4bojN6wQ9CLTWfUqAceTrd3hMKpSQ4UINPg3Ou76YpY66mrwe
         P2wu5ZGT/6M74zdR8ZGWJdk+Vm9j743IOd0+GPX47wb7I1r3sBpJEf9MqlUIZAaXLoRB
         n57Gn/rpZlZCTnv2f6ztZlERUbVzgREtUJMNk/5Vw3Z6h3YHCUFjZI6M7WYSizeIcuC8
         f1bwEr2BOn1ajPL9bMv8+1fOwqxPQe8V6s0JvBmsD5sauWX3hNAEOvJa+kXd45G5bcWX
         wsOlIH45zUT0C6HcyLdDi0FMBQHmxtYCwvZDQfFtGbY9SJGSD6yQTWst3rUzjHGef6Oq
         CuKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g+8g0J6r;
       spf=pass (google.com: domain of 3l89waqkkcuwozwqs5cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3l89waQkKCUwozwqs5Cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769000860; x=1769605660; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3Yct09DPxb9RFlFN9OP/v08slpBd4CYopIhkBFEv5QM=;
        b=KQz3OvYPxlBfaAmF/cCOuEpxzaQKYHR56pO/0lALHMGKmuL3pbyIun2HkmoeW//S9U
         pJsGX6lcysqnh/W01zdLw5hYE9gwWGLBxqX43u+foo660vwyAIAV4sjUeffCoCe5QhV2
         BYCYzZN4XbONgy2sZL1FWMqtCGGU7XUSRFqD0sDehP5yvRTgVWlPdlgT00uDX6Je7Fnd
         6q/U4nf8jeOtPx6k48Ri11e+emAgJ72/0NcToDzkq6Qrw0BgekDMkC/01Iktc4GfpVaS
         YoznhcCS2BGDWAqnYOjlBn7V7xUB9AZsIaagYmWLmRAlTwvM4XMkzUZljYQH7PQUn8+G
         9VbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769000860; x=1769605660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3Yct09DPxb9RFlFN9OP/v08slpBd4CYopIhkBFEv5QM=;
        b=GUnFB+TL3bIMIMsUkHXkgFKxYDbbt9y71ZBoERRAzdJFhHi6h2ZpfCKMMrudnpLJgS
         5sKeU3gpS+JrjZWMmQL8UmHpP10F6mshHUlC4B5yq92SG8Ok/NRzNnW/kkvcKjJQak/3
         CsrZAPh0Z9KAF066EfLZXJj+9L2SCZOp0P1e7e2ZvxjcR5yUGAY6KB0s7FN0m7a2SoKf
         upLd6xP1FSa8W9re70Tsj1Ik8Va5bCaucorvnS9RYmeCwq8dR7Rac/QH1Sym5U1Jvbns
         nwjDxzi6z9apISS3hvvNfi6m9BOeXe9cDz9AjlW3IVpfRvgmybqotq7Wny7Tu/wx4/MA
         fuQg==
X-Forwarded-Encrypted: i=2; AJvYcCUhw7IRhdj7jilsMoQm9iqtd5L+Y+MzB4fRclA5lvVRJk5M0UaS9B1A8hTI8+/rwGOYkxh2TQ==@lfdr.de
X-Gm-Message-State: AOJu0YzdRuuFoOnSw9WEM8E3cHI2cpwLPGRiu59Fl1/hAP/lQ4qy2BDZ
	Dj8KE/+/oQl82HgK5EuPsMXDi7cH+HIh54xksc3+ihvtGRtSmgEaBlU/
X-Received: by 2002:a05:6512:3f0f:b0:59b:b0e4:7755 with SMTP id 2adb3069b0e04-59dc8f0d819mr1915733e87.11.1769000859409;
        Wed, 21 Jan 2026 05:07:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HHLCS0yQZFhzBGSM+a1P/19K7r3xlsON1JHnWEwcWnTA=="
Received: by 2002:a05:6512:108e:b0:598:f876:261c with SMTP id
 2adb3069b0e04-59ba6b05616ls1769199e87.0.-pod-prod-07-eu; Wed, 21 Jan 2026
 05:07:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuKqniwhdM4Cs9WaNNy5reHpKVuwkOncwCD8lLSmw+o2wdq12lDsXeu2ZHGnWDld74FhFx/TTfrYc=@googlegroups.com
X-Received: by 2002:a05:6512:108d:b0:59d:d1ea:ea45 with SMTP id 2adb3069b0e04-59dd1eaecf3mr677273e87.18.1769000856547;
        Wed, 21 Jan 2026 05:07:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769000856; cv=none;
        d=google.com; s=arc-20240605;
        b=CneYq48e8/zGYUthD0houZHHB8CMFYujE6hEaT7kU6ABj3SsNhi+NV5/ngHvYNytIY
         uwpusU/24Zt+GaOEBmfhqtM5RSV7Da7MM48DAcclVsEy4GJ79sBM1B0UlL5aN2n+rgQy
         PqHiReQHEll37xdUG0XgO4ayCnX6s2w8NcZ4e8GEEHrZhHmK9t5pVKfGd6uXLGPKdh4I
         puDzPIVEkGDyIjFMP/+1s6MYJtWl2zfjQ81AUgpwmmY+sgJMU3TujaEVLFUZiFG1TA8i
         n6qGHapgxh23d9HADSkT1VpNurmq6FQE1N8FtNfzQcRW/dZLyNAq6uAhySIByA2DDcWi
         0o7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iQtXgItu1Zy/WBkyH0gCN+HFn5zyM6SkcEvV7kJAMKk=;
        fh=qIDoaOV6FdGVQG7nfB7N+ts5urUWNmsFJcrxUgAtqzM=;
        b=USAYop0Q43df6Os++9RFGfYks2p3JzvyHIpWXQkDwKcVtzlPrx6NzQt0ZfERIRJ0Xi
         dy4aYzVnIu5q6odeNBpY9tXra7+pPoRn1kgNAFihRx4A8BbwmsnOnChToNpM5G/ZIu0g
         vcnVyhRW67uo6RJ4aH6HCrM75MtaAII+/T/ivpH3DCtCXka0XEUclMX0MbCu6zpRrj8X
         WZbOzfylg3Is0B+S8EpDF6yHyuyzjJbpQPvdXtm62N92oaug1hSJ2BDV6ndBwpn1fuMA
         oL3LxruOXO+D4pcHn04imWdoUxnc/IjWMOLAa8yl1q+Eqz2ovHshNAJjK4lgrXPCkYAz
         mrRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g+8g0J6r;
       spf=pass (google.com: domain of 3l89waqkkcuwozwqs5cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3l89waQkKCUwozwqs5Cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf397de9si307684e87.6.2026.01.21.05.07.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 05:07:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3l89waqkkcuwozwqs5cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47d3ba3a49cso65457085e9.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 05:07:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV54MxncvsPwwTZt+JWs7SUgQWQnH9x+cYu/pVkDKcsihEEqZCy5Gv2vRQ7fsbfhD9BPSeXkPGX/38=@googlegroups.com
X-Received: from wmbd16.prod.google.com ([2002:a05:600c:58d0:b0:477:54e1:e29e])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:8b82:b0:480:1b65:b744 with SMTP id 5b1f17b1804b1-4801eb0e10emr234136695e9.28.1769000855966;
 Wed, 21 Jan 2026 05:07:35 -0800 (PST)
Date: Wed, 21 Jan 2026 13:07:34 +0000
In-Reply-To: <aXDL5NUOH_qr390Q@tardis-2.local>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <aXDEOeqGkDNc-rlT@google.com> <CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g@mail.gmail.com>
 <aXDL5NUOH_qr390Q@tardis-2.local>
Message-ID: <aXDPliPQs8jU_wfz@google.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Marco Elver <elver@google.com>, Gary Guo <gary@garyguo.net>, linux-kernel@vger.kernel.org, 
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
 header.i=@google.com header.s=20230601 header.b=g+8g0J6r;       spf=pass
 (google.com: domain of 3l89waqkkcuwozwqs5cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3l89waQkKCUwozwqs5Cvzu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--aliceryhl.bounces.google.com;
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
	MV_CASE(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCG5FM426MMRBGU7YPFQMGQEL57EREQ];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[19];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	FREEMAIL_CC(0.00)[google.com,garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev,gmail.com];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 806B957530
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 08:51:48PM +0800, Boqun Feng wrote:
> On Wed, Jan 21, 2026 at 01:36:04PM +0100, Marco Elver wrote:
> [..]
> > >
> > > > However this will mean that Rust code will have one more ordering than the C
> > > > API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.
> > >
> > > On that point, my suggestion would be to use the standard LKMM naming
> > > such as rcu_dereference() or READ_ONCE().
> 
> I don't think we should confuse Rust users that `READ_ONCE()` has
> dependency orderings but `atomc_load()` doesn't. They are the same on
> the aspect. One of the reasons that I don't want to introduce
> rcu_dereference() and READ_ONCE() on Rust side is exactly this, they are
> the same at LKMM level, so should not be treated differently.

That's okay with me - I just don't think "relaxed" is a good name for
atomic_load() if that's the case.

> > > I'm told that READ_ONCE() apparently has stronger guarantees than an
> > > atomic consume load, but I'm not clear on what they are.
> > 
> > It's also meant to enforce ordering through control-dependencies, such as:
> > 
> >    if (READ_ONCE(x)) WRITE_ONCE(y, 1);
> 
> Note that it also applies to atomic_read() and atomic_set() as well.

Just to be completely clear ... am I to understand this that READ_ONCE()
and the LKMM's atomic_load() *are* the exact same thing? Because if so,
then this was really confusing:

> my argument was not about naming, it's
> about READ_ONCE() being more powerful than atomic load (no, not because
> of address dependency, they are the same on that, it's because of the
> behaviors of them regarding a current access on the same memory
> location)
> https://lore.kernel.org/all/aWuV858wU3MeYeaX@tardis-2.local/

Are they the *exact* same thing or not? Do you mean that they are the
same under LKMM, but different under some other context?

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDPliPQs8jU_wfz%40google.com.
