Return-Path: <kasan-dev+bncBCG5FM426MMRBXHPXXFQMGQE4EGQNXY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id orxuGjygb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRBXHPXXFQMGQE4EGQNXY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:33:16 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 94BC84627B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:33:15 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59b7b7a46a5sf3951282e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:33:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923193; cv=pass;
        d=google.com; s=arc-20240605;
        b=JSvofLsi+0YiQpnZTd15oLzdCaiQpjkaoLCrDS3wE1DRurONkDvBgI9FthoaIg53Sn
         hPxb0bbwuSZhFE/Z4YV6D//hMcEEQBL5KobLRXEEjbjZiPblyGe6DRcPhO+JQ4OdM1BO
         cdlUCek187fZpzDcHGXgweVA+ifM+LiNepE1HJajw3ugKimvgdRbZGxqEnFNGMLGdJpy
         a7yMOMkwkXfCsfhe2vGLz42cZQQszhavGHuqOekgs1o0w8inK4d/AIPU61V55cXPGvWV
         lKXz8HRsT5dpOhEalN268QOasUKwIw2JV7uQynbWdHoYC5dVuMixdc0XeZp/Ur6tCd5A
         au1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hmWpQvE/HrhI0GW8Arr0kzISQJUL9Z+bqw6QnaKPyUA=;
        fh=G1KtTaUe3ZJEOVRLmtZQmZ2QAm3Rt2YYLPNFvvV/fjE=;
        b=QCs5YRjV9BQ8glIrsfirnXRDTismpCh/H3TULDZ+dJL/DD/KeEA2vjUSuP4GPNY47V
         PETMMGivAcHArgBjhQtQp+H5sVHcbMc8SOYaZ2MGy9Dsdcn5xxrMg4gpSLPOXS9/Waq4
         DNmprsKUHrMtbsTO95KEeZj5W31gNx/ww3qYf5tp8WzKOJvETt2XeZncx4XsluRg32PR
         wpuHlpjIC6tvwS0CNFV3klerfULFTNZMrK+ZezbZU2vr1kdXkoX16MOJLiZWwaA9XlB0
         TZuJevrFTvzVrC1wIe+aMVOXjM1cq5zDhUBwrropjbl3maaLj+jMoSUOl8SXFRi6MiPQ
         mJZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QcFNXxQI;
       spf=pass (google.com: domain of 32xdvaqkkcdg4fc68lsbfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32XdvaQkKCdg4FC68LSBFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923193; x=1769527993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hmWpQvE/HrhI0GW8Arr0kzISQJUL9Z+bqw6QnaKPyUA=;
        b=B1VGy4wLHRcLg2LP5fRjrhDr1Lvpx+qn1nnQYTAsn+FhlFxdwxbsi9pK8FTET/9nGJ
         RPX1ABNKaIX73yEDpeE/P5PfAC66Ieh8T7rTmQAcx4KlDLxHdkRYCrnFBzZsmCuDRNYj
         puDiCGZJNoSBL7JQMDdWyV88JZk5n/4w7bVSAVpKEGuV4RlQPiFIl4broKVJgdizJOLf
         4F/2P8vE0+wHMUR06xR6jf8paGUOOwAh1CFZgvJgAiEzQAaqPIpNnUp33Hbs8rtMNq0K
         kAGJZ5atrIaAJK85xF2p40lbMDljHyLTKPyQBHQVOhIYUmzaX6I52rYl6UL8IQOOJB6C
         /5CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923193; x=1769527993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hmWpQvE/HrhI0GW8Arr0kzISQJUL9Z+bqw6QnaKPyUA=;
        b=nJC5mknvhj9RDxuHSXyzAGgKVZd6RHH7wEj7EX3IT6dKTvksk4LK6n8xsBeIGJ3DDV
         LtAVNEjEvwNAM2aMVG5kAmVxlfShWfmwF1VCC2+tvu9jEqu17ziOEuMzAxhMGn9Uo2W/
         BxyUO2bY1ShY5GnpZdb3JuFGUXXK4Ok/iqJ8FsN54u/d6R1LldFsOPwu5C+3QQp90mOc
         JU0PyyC3m5L59KAiuccdjBcArIXoMPmX9BCxqpiUtlFGyJJbU61YaMiq1A4P1h+7IrZX
         ILFwbD8OhFiC8+gFZ1+sJMNhIno+ToZThpw/cjg7tdly4tceohj2W2Ey16U1q3B+q+0g
         NF+Q==
X-Forwarded-Encrypted: i=2; AJvYcCVSx9VSiun3njiGZwhGqcfnuR3lTTDvVON8caaZSiv8eq9Sz5orjXfES6EnraCGZeqTGZGOSw==@lfdr.de
X-Gm-Message-State: AOJu0YzAzN2BEELEYVQm4z5LGbhLvyYd1gl9dXOSXKhJDpd/ecdENZwy
	4zisNAlIOz3dDf1g9p9odJeeVPWzhdpUiFel//mJR5EOJJzEMUapKrJx
X-Received: by 2002:a05:6512:4016:b0:59b:7b59:a4ac with SMTP id 2adb3069b0e04-59baeecf7ffmr4967240e87.14.1768912861050;
        Tue, 20 Jan 2026 04:41:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FH/cn0g7M1+NnEd7NLp8Jfa48wsAK3qkLmM7RLSCejDA=="
Received: by 2002:a05:6512:baa:b0:59b:6cb8:9cf3 with SMTP id
 2adb3069b0e04-59ba6c57486ls2126404e87.1.-pod-prod-03-eu; Tue, 20 Jan 2026
 04:40:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZXm3rbKcvzR6HPq9IqogEUbrQsNOFz0Y73/LVizxkz8aBU5UvJ4ZMhItm9OlP8hv+LUjbEzdePM0=@googlegroups.com
X-Received: by 2002:a05:6512:3b0a:b0:596:51d0:9373 with SMTP id 2adb3069b0e04-59baeef7cadmr5363107e87.24.1768912858365;
        Tue, 20 Jan 2026 04:40:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768912858; cv=none;
        d=google.com; s=arc-20240605;
        b=F9Q1JHr+KyYBYBXsO5Y6S3ba59II1ZrHWEVarVXwFRZ1jBoCwYgfdv4dgnCJej6psf
         mAdMd9oycSY0hjfP0pPBSRIiixrnaq33hlLxULOfdNpQjzsyNJvmA2VyYIZjPiunwawn
         zD0OulcQgsrkmKifRKBBNTEacYFtLuSsVHR1Te68GR01GxrnXFyedIKEcAOjDm8Rb8GY
         V9obfrBRBW+Rset3iS5jG3tPSAaRtRcFG2n41lcnUwZnxBVkYisiQyz25LseaKwbD4df
         iw+28xS1Dss7mYcqSkquTeBp9iYT9DZItNAZkF4oqaygBoZhGlQCSgHl2ilK79gcWBU3
         qr9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=WZRsF4NvxTK9k0YGvZ/neWvOZ1bis6ac+sRh2zfafCw=;
        fh=7gC7m+i7YowW8NQ3eHybMsjFT5HPlklRB/c0XQYkxTU=;
        b=VJeQwMNiAKFpaqegwdFs+JP5WDBALYn9QRlKGCBeHkigCvYKduthrikIImc7bgtek+
         anRNiAkoFXrE8JGlSL7/5dQFnDjAEgSJaX3hqK3h0cFHAghsGx/ufsrvwcAVHQzJ2M35
         AXizVF3jw5YMz8X0+RYByVAUckO1w/YuMoZn6dMD8g5hH2m4jGzF9okSvwZDc5enAASr
         zJID2wde6hLuSD2FVkmA91GCyFteQ+T8vKOWfyYZ9aLhmwjQ9/9Uw+7eWeei7CthUXWk
         VUV9rKax2WgLpQ+2s4DUqHUNlkrtZsOb7xqrCoPvpvY8B1uty512ai00OMk0woHMiE0e
         ZaYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QcFNXxQI;
       spf=pass (google.com: domain of 32xdvaqkkcdg4fc68lsbfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32XdvaQkKCdg4FC68LSBFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59cb80f4cc9si196186e87.0.2026.01.20.04.40.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 04:40:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 32xdvaqkkcdg4fc68lsbfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64d01707c32so8557029a12.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 04:40:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW3s5qOpwTS69MtC0WNYUwZJCQm7cV9WEtm6k+X0P8w+iEZ/sPTFjOXglJtSLa8vC0buyRwMDnL91w=@googlegroups.com
X-Received: from edqp3.prod.google.com ([2002:aa7:d303:0:b0:64b:511b:32fc])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6402:3643:b0:64c:e9b6:14d7 with SMTP id 4fb4d7f45d1cf-654bb427f7amr8037497a12.24.1768912857702;
 Tue, 20 Jan 2026 04:40:57 -0800 (PST)
Date: Tue, 20 Jan 2026 12:40:56 +0000
In-Reply-To: <20260120115207.55318-3-boqun.feng@gmail.com>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
Message-ID: <aW932LmY0IBwrIt7@google.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
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
 header.i=@google.com header.s=20230601 header.b=QcFNXxQI;       spf=pass
 (google.com: domain of 32xdvaqkkcdg4fc68lsbfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32XdvaQkKCdg4FC68LSBFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--aliceryhl.bounces.google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCG5FM426MMRBXHPXXFQMGQE4EGQNXY];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,umich.edu,weathered-steel.dev,google.com,gmail.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DWL_DNSWL_BLOCKED(0.00)[googlegroups.com:dkim];
	DNSWL_BLOCKED(0.00)[2a00:1450:4864:20::54a:received,2a00:1450:4864:20::13b:from];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x13b.google.com:rdns,mail-lf1-x13b.google.com:helo]
X-Rspamd-Queue-Id: 94BC84627B
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 07:52:07PM +0800, Boqun Feng wrote:
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

Reviewed-by: Alice Ryhl <aliceryhl@google.com>

> +/// - `atomic_store(.., Relaxed)` maps to `WRITE_ONCE()` when using for inter-thread communication.

typo: "when used for"

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW932LmY0IBwrIt7%40google.com.
