Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOHOX3FQMGQEEJ646NQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IMxcAju3b2kBMQAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBOHOX3FQMGQEEJ646NQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:11:23 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AE9A48532
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:11:22 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-81f39ad0d82sf10565202b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:11:22 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768929081; cv=pass;
        d=google.com; s=arc-20240605;
        b=S+J7jlWMNbAjp4ArIRAJyZPO0IanYF8yRmTibaHfanxfcWmroAbk9NpPGWkpnj3OUp
         rRW29lKAYT0deeSWMPzPkBL4aIb24akOuH2mlh41FdKdt5e9G0bkV0mgbberHcKUbXPk
         qPYHC1IlGwyMD6oM0xUI1Gv3PqG4kF3AD3xdW66lYc7NNmgRRWDDXYF44sT/t6o8Y0SA
         grG0PJRhRor+Jdg03/I7vHEE9hZSZkvP4TIwmUhOSB80m2q/695oIcPhYfGX42eyNSKi
         1lZkEpct/dK4yutsFPgMvyiONfxvrOp69FNJrGTp71vWDLhRmbDlTvLaeiwRaOu/HIpd
         vnWA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fwIDaKT8qoGVJfZbXQ+XKgsBN6dY00BJnr7ljhuEq5A=;
        fh=MBOe3N2GmRguCMcMdD3gXEJzIJ06s5gDB/3isVGHPdA=;
        b=lB8vdvPlNIjKfYtd3ZPsRPEXzyZks/Uag/Wl/CAW6abKJFT78X61k5erhcwlNzwxse
         XnqzU+ib1URpl4fdZwgmOR4nfSb+wSTwzKcAKIzrUXsWBc4MMhYg8zSpnlMntZYz6D+1
         uRxPaCVIoxC4gx8tN8kFnsnPq5Asl4zEBGsXDlfnuc09RvGOH0EYAEvd3+g+Cq1ZEva8
         cQ61b2agLf+LsWpai5U/TnDdpLsOxwrGWqfCmPAU/qqE3S1/Y0ZjQTq7knlbGX7iL6p3
         6/hfxqqjK61mq4lHXdWpEqejG1DjD6jZ8d6ZyAUR9QMmRJIDdbPrJ7QVI8b56WUDR0QO
         hVgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dal3FOaU;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768929081; x=1769533881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fwIDaKT8qoGVJfZbXQ+XKgsBN6dY00BJnr7ljhuEq5A=;
        b=Dt+sOvHZBu91Q0pwEFwVKWWOFyaQLidz5v6q1vp/lEwRFl8oVlgip6s15jBTJNcJNE
         vk2k32HHkROO0S5WeMASbzTzYmccHwVC6867YnVBRrYimer0vlXlraunpXc7nKtKvJhO
         Ke7P4cvkwstzkpWRJ4LVdy9nSe6UjXmIAjGjxm0YZD3hCDx+pIMoR5IKtE2SoFRiEzE9
         ySQ5zsKGs1w4Vp4E/PyGbOWGbXfD2EBokhTXD3936HmMCxutN96mNsoHW1rz5jvMnw81
         YoXG1lTn6ytBUvkIjvXb38finHaKYJul1wVvG329VF2Br0qRtU9yMeyqFDI2aQMHVZKY
         SPDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768929081; x=1769533881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fwIDaKT8qoGVJfZbXQ+XKgsBN6dY00BJnr7ljhuEq5A=;
        b=FWpEq6s6EG0b7elxNGOwuhdW6p2Q/kKMY6y6TXbGfvJJnV6O62kX1W421dNyY00JHh
         0gJQFuJxGRU8Q4Hri9cFaW9L9WxLixdrtToLrsMPmRmin75AmApl4sXTQuAly/kWVyOG
         ouLXKNhlGDwaeUmaUpf9JUumViU9hU7Aqejfk5YB+lsY8VBgUfGn3TGsSyJlX8YdJYE1
         dFtiGqmgWsl5bgvZtNjtAZ/6aWL+M+ToF0GZo/os3+rWVIxHlwzsppadCt4dUtgGS3qc
         Z7XroorQsoNo9VPei2IQ4MW80wmhFstI7rydEEg9nT9j8/0MMWVAchc79SeovLbXxjPy
         ENRg==
X-Forwarded-Encrypted: i=3; AJvYcCW94jxLJqSwJXAtedqBmrhiVB8+AfHXSW/LqF/rqS+M6k3sZhY/YXxoS/qJ0WeI6xflx2hKfg==@lfdr.de
X-Gm-Message-State: AOJu0Yw4sFFR/1MeEcTlp4zVH922OtPC4UwAgAhSYm3QYhPNZf14tEus
	qIx+BOqGd9/EvLt6/NV+onxmXjb46cuzegl9Sw38SUSU036w9qO6YbRn
X-Received: by 2002:a05:6a00:e84:b0:81f:3cb7:cf99 with SMTP id d2e1a72fcca58-81fa01b8cc6mr11712357b3a.17.1768929080690;
        Tue, 20 Jan 2026 09:11:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Egwd7mj6zWD4UcfvSA/v1U479AzljgfTFRt9MV2KmLlQ=="
Received: by 2002:a05:6a00:7111:b0:81e:82e9:8ca1 with SMTP id
 d2e1a72fcca58-81f8eb820adls4071552b3a.2.-pod-prod-03-us; Tue, 20 Jan 2026
 09:11:18 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWKlNjYMVtyHZb+4qa+ZOsTB6AZdtl28y90ia8jhNgregOZtMURWIOg9o7sW4TqN3wvyP9h4Q7H5PQ=@googlegroups.com
X-Received: by 2002:a05:6a00:1151:b0:81e:c5a:8c25 with SMTP id d2e1a72fcca58-81fa036a7d3mr13423653b3a.44.1768929078539;
        Tue, 20 Jan 2026 09:11:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768929078; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tjx25/VU1XJWbt5Mz3LG3XvXhZf2HogXsfT5o5LBWWvp7rhtER+VPvB/NzbS32VXlG
         xw7HG9sri+W0usa3Ic9hGEJ+hPsnFCGQuSpIkAPPU5MP0DqejAYEPhwXjbcykHLQC4XV
         Lmnu2T8M0YfoH8IY8eB0JjGQ7iYxfttwALenX7KWlCMSvKqogS6FLKdSCpmTQZav5Q3r
         HzodxuFdT1cJeObGVALIpVXB8HA8kHe41301pK5RtvoAikovjik9o5NszjHpFFCQLLt5
         S39zWfs/h/8X4wNpzzxHqomiGmbGpMaA3GPOx9c3h4ZGR1yyKwK0OK8n0YaMzkLhtRzs
         gaqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g4kM6F8fKl+Qeywz6sdK1X/LSmekcFRs5fj3WsFdO/s=;
        fh=mAV/kKuQSpqEI8A1vF6g1oKTJdTV2yO5/PCW/GRPCB4=;
        b=WE09pkasVFaxbKU2XZbSVEnY44fbgTgGdT9HYFOat5x/o3Q+1wnlqV4LMGL1iPUcbX
         h+6O/pAqJWa9mya6D+bL/FDQctYTh2alRYAteL0dCQ/qAmTR8xEInt3jE7FY1nyr8Ugp
         UIjrKou9cDDzf3Tzghe8zV97K6RQWGVyhzUjYGICm24+/F0hxy/H7WssDdatGzNR1uul
         lv5A8gHjVJGC6jCgsQXzuVVsIQMPBCTP/g7b15GgShQO51nZqjU1n9jCt96R2x0uAO5f
         6tVPjlLNYuE8FRjwAwkWNLY2ucBb1km9ilALop0KEmCOsTIKMhXYJqU6w5zR//gn6/DY
         LFoQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Dal3FOaU;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1229.google.com (mail-dl1-x1229.google.com. [2607:f8b0:4864:20::1229])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81fa108c5dcsi403426b3a.2.2026.01.20.09.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 09:11:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) client-ip=2607:f8b0:4864:20::1229;
Received: by mail-dl1-x1229.google.com with SMTP id a92af1059eb24-121a0bcd364so7123882c88.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 09:11:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768929078; cv=none;
        d=google.com; s=arc-20240605;
        b=TENGPYKNt9QjAaWNh5XJtrfRXsHzgC0bXSq/1k4qPtJqeHiR5q2jaD2zyOWsB6hOtC
         Xm0XDvBKWCy8MsHsI5hBASM6JhR1cPNWfMcu3gLnUSviapoBmwyIZ1suAmf8BqD59r+c
         E1MA046FQ0Eiy0ExOBDVGstbju/tJNBAdjeT4YGnCjrwGvlYeQaZnbQ1kBObJBbIEsIx
         hr/Dx04SrHjhpobl8kAOU/nd6zlCNsHFTFmYo/AF3fKuwQFfIodqH7TEhdob4e13S1wr
         CwAB+ta9kWe/gcsdn5o5rbPsiae7ssDE5ECr5yDCaO0OthUo9Q3l55iZFw8TUeX/j8ce
         ZyOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g4kM6F8fKl+Qeywz6sdK1X/LSmekcFRs5fj3WsFdO/s=;
        fh=mAV/kKuQSpqEI8A1vF6g1oKTJdTV2yO5/PCW/GRPCB4=;
        b=GapoLp+Q3r9B8efQ29B5U5ZI0YEgLxI06+tKHX7k48zEDZ0zb7qljwPu0ivik9U4gz
         ybTxHapwBfIIU0q3B/N8yf4L0tXUV0l5tqf//arHIM8NjYw8yeM0xIi21u23cflxyHK+
         BnRPPB22BLzKKOAxnJsYPbfwcyyAbFjf+WaL1ETJFaPrOhA5o72RvatxBh8f0W16nFnV
         BhBeFBEpHAfqg8BC9Q5vUCNfvkkldEgDEBF4CXkE+Kk5GurBJh4D3xp5LscZNjMkQivr
         2D7BOZIwxC88Gj1Ljg3Nv76k9PwNYKagmi2BBfycl5ezDVnJfTh8DqgvFRNKm1Hfp2BU
         yMnw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCU8d3bvBf+B6lKDLj4rBwBH+uZ1eroZ8m/jVAbSdZOgFmB52LLvd/6VRwiLqm84n1hRnBumoiOTQkM=@googlegroups.com
X-Gm-Gg: AY/fxX58h38Pg1JJB6GfTZ7qepXot8xWwBCo3Kv3IJIcRZi1BE8q/NfNqylWbxGe73a
	mUZf7dVB04AYM1h6jZ4PpriXu4hRazQ7ZWGvbUfXPzh4moqyLUTjV6WNTF2T7EfJMWGGEJWRYuO
	o97SK5448VV2lTTP9Qf/fTnV/ElRy7BZ5JctRQy5M/eZ3MjRcHA+QC2PhY0l/ymTMOmL7sgpiW3
	IL96U/1SzzgFxgbJ6i63yp4PeABSI/kWGauSFjw3a6s56irLG0+1twxqMW0uZp6KwF6B7Ip1LF6
	eX7rlbgcTMZ9mkd7aFk2BTaiSgo=
X-Received: by 2002:a05:7022:628d:b0:11b:a8e3:8468 with SMTP id
 a92af1059eb24-1244a779a72mr13184278c88.33.1768929077367; Tue, 20 Jan 2026
 09:11:17 -0800 (PST)
MIME-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
In-Reply-To: <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jan 2026 18:10:40 +0100
X-Gm-Features: AZwV_Qj8_3cuVM1FyOzfrOkRiYXrFtw2NSR95u4VFEpxArqad_WPWywp-t-FlH0
Message-ID: <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
To: Gary Guo <gary@garyguo.net>
Cc: Boqun Feng <boqun.feng@gmail.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <lossin@kernel.org>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Elle Rhumsaa <elle@weathered-steel.dev>, 
	"Paul E. McKenney" <paulmck@kernel.org>, FUJITA Tomonori <fujita.tomonori@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Dal3FOaU;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev];
	RCPT_COUNT_TWELVE(0.00)[19];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBOHOX3FQMGQEEJ646NQ];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[elver@google.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[lpc.events:url,mail.gmail.com:mid,garyguo.net:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 7AE9A48532
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, 20 Jan 2026 at 17:47, Gary Guo <gary@garyguo.net> wrote:
>
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

Alright, I missed this.
Is this actually enforced, or like the C side's use of "volatile",
relies on luck?

> > It is known to be brittle [1]. So the recommendation
> > above is unsound; well, it's as unsound as implementing READ_ONCE with a
> > volatile load.
>
> Sorry, which part of this is unsound? You mean that the dependency ordering is
> actually lost when it's not supposed to be? Even so, it'll be only a problem on
> specific users that uses `Relaxed` to carry ordering?

Correct.

> Users that use `Relaxed` for things that don't require any ordering would still
> be fine?

Yes.

> > While Alice's series tried to expose READ_ONCE as-is to the Rust side
> > (via volatile), so that Rust inherits the exact same semantics (including
> > its implementation flaw), the recommendation above is doubling down on
> > the unsoundness by proposing Relaxed to map to READ_ONCE.
> >
> > [1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf
> >
>
> I think this is a longstanding debate on whether we should actually depend on
> dependency ordering or just upgrade everything needs it to acquire. But this
> isn't really specific to Rust, and whatever is decided is global to the full
> LKMM.

Indeed, but the implementation on the C vs. Rust side differ
substantially, so assuming it'll work on the Rust side just because
"volatile" works more or less on the C side is a leap I wouldn't want
to take in my codebase.

> > Furthermore, LTO arm64 promotes READ_ONCE to an acquire (see
> > arch/arm64/include/asm/rwonce.h):
> >
> >         /*
> >          * When building with LTO, there is an increased risk of the compiler
> >          * converting an address dependency headed by a READ_ONCE() invocation
> >          * into a control dependency and consequently allowing for harmful
> >          * reordering by the CPU.
> >          *
> >          * Ensure that such transformations are harmless by overriding the generic
> >          * READ_ONCE() definition with one that provides RCpc acquire semantics
> >          * when building with LTO.
> >          */
> >
> > So for all intents and purposes, the only sound mapping when pairing
> > READ_ONCE() with an atomic load on the Rust side is to use Acquire
> > ordering.
>
> LLVM handles address dependency much saner than GCC does. It for example won't
> turn address comparing equal into meaning that the pointer can be interchanged
> (as provenance won't match). Currently only address comparision to NULL or
> static can have effect on pointer provenance.
>
> Although, last time I asked if we can rely on this for address dependency, I
> didn't get an affirmitive answer -- but I think in practice it won't be lost (as
> currently implemented).

There is no guarantee here, and this can change with every new
release. In most cases where it matters it works today, but the
compiler (specifically LLVM) does break dependencies even if rarely
[1].

> Furthermore, Rust code currently does not participate in LTO.

LTO is not the problem, aggressive compiler optimizations (as
discussed in [1]) are. And Rust, by virtue of its strong type system,
appears to give the compiler a lot more leeway how it optimizes code.
So I think the Rust side is in greater danger here than the C with LTO
side. But I'm speculating (pun intended) ...

However, given "Relaxed" for the Rust side is already defined to
"carry dependencies" then in isolation my original comment is moot and
does not apply to this particular patch. At face value the promised
semantics are ok, but the implementation (just like "volatile" for C)
probably are not. But that appears to be beyond this patch, so feel
free to ignore.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN%3Dug%2BTqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A%40mail.gmail.com.
