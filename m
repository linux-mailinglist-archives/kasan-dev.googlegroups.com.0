Return-Path: <kasan-dev+bncBCG5FM426MMRBWXOXXFQMGQEX4U6CII@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SM0sBACub2nxEwAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRBWXOXXFQMGQEX4U6CII@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:32:00 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id A95F247985
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:31:55 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id a640c23a62f3a-b8704795d25sf582153666b.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:31:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768926715; cv=pass;
        d=google.com; s=arc-20240605;
        b=F0ZhMbVZsiAQah51K3kqj2mQ7vQs3LUY+Dm+d3MkC74P6lHY/UTMz/CL1aLBGMxgYD
         GgDsQwsg3936ruH8Bon/xmO/t1+mfcjCjFZ2ngEYsjELFoQbb0sOWXJBTtDe8WWBsgwL
         asKEs8knIb9aq0lYo7MEh3RI7R746ZnSVkEINpsde9oqJS30D249bVZKNeO1i9vPfSVv
         f+/n/xRSI3o8wqHUbEnVqdTU9eAewQ4H1zCk0FgLJn6n5sxLZJMOF6ZaNodMZ5f+g4R3
         HqE50qSmTS9nzvH+DuZR+Rhmtg4eHDL5GgS2aDeh9yAanb6qK4/JQYckEiI0xNHapElG
         VJTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Oi2JC+AnFKPWXi+J/O4DBh7B81kCVUVE6LzYFmsdjTg=;
        fh=AW+nFF8W/yMFntPSzZyj03mxHq/J8I8s8dfQjxqyhP8=;
        b=K/9QT/Ruq7xcOhIhNbqG01wSuQ7xOng7PiGk88ikcrPU6t1HeDjzV+150shC4tscHo
         RVZZ3aU5A8rgxUjtFqXw6NQ6/E9xYq6kOdJoEV1AMPTsHWaoxJ2sxVShK7e5TzZ37j/B
         Klx7oGat/+WlNtwo0/5mD/vClAiugPU5EB/noazaY2X7GF9Vd6HLx8qhzgluqzzsHkDM
         CouX8rQI/aZBtn3Vp3YWJR0R/Toa0suC8qSr3cKf2y+opk6Ei52xI/X1lS/bAKWWk7gx
         4z09nhdgF5VbKO4NjvpjVevyCHE9ZPyfSaeuHz8TDpLTFUo8vJ2dAtqiCnt2LbD/fJoH
         Gafw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3fVx9iZw;
       spf=pass (google.com: domain of 3whdvaqkkcvcza713gn6a5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WHdvaQkKCVczA713GN6A5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768926715; x=1769531515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Oi2JC+AnFKPWXi+J/O4DBh7B81kCVUVE6LzYFmsdjTg=;
        b=xnEAuOms5U13WzBCQrBYUCa3KynQcVbI7YEzbV8/hN69plcKP8b6u5krKY8zq26hQO
         m8N+Irgn5G3Qn/yCdzbwjKsizJS0Z+2kokGn+R1CC9fcg5Vvt1WCV+INSyU+Ym4BlVdV
         ZhjRzEJLaEL9l8yZDQPSdzaFOzCNVZcjHEas6s7PeQSbgANQFlnyV1pmXQ8RKrokK/qC
         D6OAi41OrUc+nMWTmfzCWmJ/u2jhb7Vh0y4d7/8MuathT8n5cBfack3yVfZZg8KxwyqY
         USJdYadqSnb13J8MDYvc9Vi2hh/BiHiCJOgYCwghCkbVKEzjcVAgrc2wtqeAG3fhFOTJ
         d6DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768926715; x=1769531515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Oi2JC+AnFKPWXi+J/O4DBh7B81kCVUVE6LzYFmsdjTg=;
        b=jUBp6YcOl/vN+6r5xG/yYf+Hk2jh4lll0I6hkvlTAQKJf598pjcPm/PrUBRoVH41B4
         DR7twJLiiHjy0zqogZGPRuSBy6WnHyyVFoWrqsCJKtcZ8pl5vFa6gcraxY2XO/feIHMi
         Qm2OsO1rjQyuN1wO9U1lrR4BhLDJLC8AUvYGE6gDMen2XdPO2yGSaVpxyCsHflpEJjgY
         5U38EbaSYsBEuLqGy3k/XZZ2JZuiYpcmuNGTHcbvDXM+4VZmxJ0fjy13rV5RVlNc939W
         jAdqhZU6uCP3v8moONBcOaZR7zGQnlQPFSoYltmU4bYlFFrkpemcnbcKJdb9qKz8B4KR
         UEfQ==
X-Forwarded-Encrypted: i=2; AJvYcCVBBcezxxTt9s4zH5mt5grWYsM4lciKVIx4Bg7esvHr3xzj2U4b86F5Jb2is0XAoY+A3V+wDQ==@lfdr.de
X-Gm-Message-State: AOJu0YxOzW1euD2GMSV7fFH+s0pW3EAcYpDEMW7UXUfSglr/WS1i/urY
	4inZNcT4ZGgkUvwfv8o4qIHHgOle3RXylbXLDWOTNTqc+nxgAMlYH5Gk
X-Received: by 2002:a05:6000:604:b0:430:f41f:bd5a with SMTP id ffacd0b85a97d-4356a089a52mr19953310f8f.57.1768912730734;
        Tue, 20 Jan 2026 04:38:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HTlqa2pk3TW6Cm5BxZqMnpYUAc7RWggKIxVtYaiUBlrA=="
Received: by 2002:a05:6000:2484:b0:426:fc42:689f with SMTP id
 ffacd0b85a97d-435641701e9ls3899080f8f.2.-pod-prod-05-eu; Tue, 20 Jan 2026
 04:38:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVlGJmovRdQFpjM03aM5zmSE/md/QG29ulnOKi5yeTbJYake7a/No7zhW127H7UZr6wv46YC+pMx8U=@googlegroups.com
X-Received: by 2002:a5d:5d81:0:b0:430:8583:d19b with SMTP id ffacd0b85a97d-4356a07722bmr19441455f8f.33.1768912728505;
        Tue, 20 Jan 2026 04:38:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768912728; cv=none;
        d=google.com; s=arc-20240605;
        b=gcWcSAAvzxb/H6GwThPQ0SHbDYXkAHXHQbMuFxd1qQNX3zAVeW4ZB8D7Wgj4BndR8J
         kY2+OeVp1+vHn+5uSlYv93U4dn0i6mQZ2+mVMgUALwe3HE1sToU+OaO7R0LmFlMxHrM6
         +XCEmuvj0h/fjdSTpAWqidywXmGUes9onm292XL/YutFiDMuDDtGgDg+oQ7S5gpLAKau
         UqFSGB8Iee5GqqwBd4qkOfWiPMNHrYBrTdGGsPAcbYz/IfoQK4kZZf+0Wur1IA/XoORD
         5npvWeYk7/lpZl5zxMoWhqKRJkFwvjjNG+OBnLxiimha8R8wJnL8H5KLg3bB+IjyuOYR
         XMnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=v5uBS89EprhTXTMtWy33Byzr1DNzGriqxZMXGCf0cIw=;
        fh=g2mbsMI6j+dizjGSbjsiJYbOVPquzvqNiWc2fRzBOCg=;
        b=RJSn0VvopeZV0bS2xHepnVEu3NAWJ8d+wsoFsh4dgm/Fn5ny8PRBZTQhzZlWTSh2mM
         Yj/ackB69tWTNR8a/Z9V4DCB/MgKKYu9+KK0n5oZ4G/nzJUOxbEI6hKEJtXr7YBfnFZX
         5+WARHiosnECWdSSE77IMn1Ac0Rtlv4RnyRwYxI7QUNqexDeX2zbzFZfJERe9OTWmiR9
         /s9EkTf3emvg78qVrlnueIVn79J3ZyUHy1ICqp6LWGjLpbuSf9Aibms6Vh9rGf/TkQAg
         iBEarn/IATAjKKunro6QhQ+pIQp3aBon+4TcPDD6M2+E4LpUjzIgSwCKIpYwJGVA4Izh
         Wseg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3fVx9iZw;
       spf=pass (google.com: domain of 3whdvaqkkcvcza713gn6a5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WHdvaQkKCVczA713GN6A5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356992141csi256266f8f.2.2026.01.20.04.38.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 04:38:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3whdvaqkkcvcza713gn6a5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-4325aa61c6bso3187203f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 04:38:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV1XpHueGFzBp6LSGw3CnH2IJtTiRMdt65h6u8mHFdCK+Nl10kIO2jhE1EfGz7rIUCi0Mtr0XOkAx0=@googlegroups.com
X-Received: from wrp4.prod.google.com ([2002:a05:6000:41e4:b0:435:948f:2ec0])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:2885:b0:430:fd84:317a with SMTP id ffacd0b85a97d-4356a051d68mr21671610f8f.38.1768912728086;
 Tue, 20 Jan 2026 04:38:48 -0800 (PST)
Date: Tue, 20 Jan 2026 12:38:47 +0000
In-Reply-To: <20260120115207.55318-2-boqun.feng@gmail.com>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-2-boqun.feng@gmail.com>
Message-ID: <aW93VwfgkHpJfjVs@google.com>
Subject: Re: [PATCH 1/2] rust: sync: atomic: Remove bound `T: Sync` for `Atomci::from_ptr()`
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Gary Guo <gary@garyguo.net>, Miguel Ojeda <ojeda@kernel.org>, 
	"=?utf-8?B?QmrDtnJu?= Roy Baron" <bjorn3_gh@protonmail.com>, Benno Lossin <lossin@kernel.org>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Elle Rhumsaa <elle@weathered-steel.dev>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>, 
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3fVx9iZw;       spf=pass
 (google.com: domain of 3whdvaqkkcvcza713gn6a5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WHdvaQkKCVczA713GN6A5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--aliceryhl.bounces.google.com;
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
	TAGGED_FROM(0.00)[bncBCG5FM426MMRBWXOXXFQMGQEX4U6CII];
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
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,umich.edu,weathered-steel.dev,google.com,gmail.com];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: A95F247985
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 07:52:06PM +0800, Boqun Feng wrote:
> Originally, `Atomic::from_ptr()` requires `T` being a `Sync` because I
> thought having the ability to do `from_ptr()` meant multiplle
> `&Atomic<T>`s shared by different threads, which was identical (or
> similar) to multiple `&T`s shared by different threads. Hence `T` was
> required to be `Sync`. However this is not true, since `&Atomic<T>` is
> not the same at `&T`. Moreover, having this bound makes `Atomic::<*mut
> T>::from_ptr()` impossible, which is definitely not intended. Therefore
> remove the `T: Sync` bound.
> 
> Fixes: 29c32c405e53 ("rust: sync: atomic: Add generic atomics")
> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>

Reviewed-by: Alice Ryhl <aliceryhl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW93VwfgkHpJfjVs%40google.com.
