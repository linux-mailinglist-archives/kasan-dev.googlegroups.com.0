Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXEQYPFQMGQEQHXTAUQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4JM+IF/IcGkNZwAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBXEQYPFQMGQEQHXTAUQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:36:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id F417456E29
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:36:46 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-c1d27c65670sf508128a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 04:36:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768999005; cv=pass;
        d=google.com; s=arc-20240605;
        b=fDEW9X7P0Vl6yphDMCL586bUhu9TNIsfKSpJdRIq0xl80cj3E8WUN5TITRWSF7QMXo
         jDR6TzUu/Y+VUfwrUvEvXEKPtqFHUrHuQqpyvb06IE04vlQagbrKe6YP5d0ub/yPqE9h
         HmaIICpdOeQ1Dg2T8+hakMgjeOzdIWdUlhwBs5UCjf2MaG3GSJjRAJ9L+qk3CI1SOLiW
         49dbI6n88CK3OeLDh0T9oDkbbF2DiEaVt1OQmEIpXqnRLn19esiT0SuPtgeYD7Ny6ByX
         7ij6PkjquQGjwPCTxxuMdt5wuBfak3eZRAmTzdb3c0WKezM9XFnLFGwEwlqLwGPAmwtV
         4C7g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DV9TzIm5wXTQ57AOzw4ncrJzDzSLR5DQtkk/9Xxld4o=;
        fh=Y5yv/4Ax8i1o2WQEOMwPDAWX9vbkjamLsFqH/axNpkw=;
        b=lhldQNJSKIVN0A5wlAe32MqklrEHXHq0fkO0le/V1hJuyOI22P+I0PRoXRzX0k96H/
         pnoDs869FbkDgj0CC9qQtkjpUkaq7IJpcCEvsuQY9IYxP6aAx+JpJF2x9gf00j70BIX9
         psZOKaAUgGmOxkYBR2hPxe3yPz/qc6BKBh2Q1E/cek83nahyl9CqCxRKL19sLq9XPrNx
         ghVaeqpLw2hh4PBcu3NOAnhZM3Me7w358z7ftP1HXJU3QAxRB/Fh8CbCIJ0eUuG5LBRK
         XbEb0e1bXawqJhoNy6XxmIKeGhp1WkCDYMGSsRWxVpxsTra6sUq+g7DO7HGXT314mtln
         j1gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MhuF0Onp;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768999005; x=1769603805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DV9TzIm5wXTQ57AOzw4ncrJzDzSLR5DQtkk/9Xxld4o=;
        b=Rr12h2HBhV30vuCUEXasN8Gp/iVfyyA2q7WvA9cHPpmnpemR+m/le/7Nbe7opjlHhP
         OotRLRVd+sl4vh/5EloMK04Rnp57FhYNnF5jM51WdDr6hbPYCRVCJ6b/Z3YCNyScv/52
         XodvfDFgnaGKJhjAlcI+VEpwN8baZrOTyl0bhv6I5cYGWzj5Y/ouIhJc33RsPLUM/FjI
         vfdryCYsyXAP2akwvFGXNp7MKOyHtNlO9f81Uymdf34wXjnrjENi/LI2cbF4ZdBpdmIG
         RMcs4u9ECmOxSzzTW8Hbh07CtJGyNPWZY+Hm8E+ksxTDtReufd1PFQZvMLi0PZLWh27h
         2aQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768999005; x=1769603805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DV9TzIm5wXTQ57AOzw4ncrJzDzSLR5DQtkk/9Xxld4o=;
        b=KVrVTxKtd2bGHWuiWKyXKoIulEAF7Uo3HvNmEerf1qvwMZUdbK+qAIj8eiagtWTE/+
         ktb9maDmozKspVcrFEVt6CnddVo0XKGztDdgQYrvlAsCyrSN2QVamYT4FAGqfKCyv7zt
         WQbSGlsnqjdYfJ8Rsyhe1n/A60YWR3uq/6m4uUjPhzpMejUCx+rJOV5Du5xOO3DllPkg
         65RbP5QWzlsti+P3CD315EKNloaNksDW5M7JfAFwK5rXPUWKS0UMiMnlC65PVbgf6/nb
         +1f91s70+pgFjimBpS/C0N7NxFIOtnZjeSFo7u+eEnrk+VwDN8KOWJtU8TGKiCiWqkqz
         0N0g==
X-Forwarded-Encrypted: i=3; AJvYcCUgV24OjHYHIpqK90MDkDrgeX005eGELuVWJZ0mC/e1Z8f/HP6Zt6OJ3oAI2U3lYTNOUMzRdg==@lfdr.de
X-Gm-Message-State: AOJu0YzeMDgLPZNVr3cW7nGg8074nxnvs1nZhqN2Eq4zXPhNFe1QLyVb
	4JmcWhjZLRP+61dj9Sjiuk4JueXfRrXwsmNgLY7uSM07IwhNhESw6Kun
X-Received: by 2002:a17:90a:be07:b0:343:3898:e7c9 with SMTP id 98e67ed59e1d1-352677ed610mr12624647a91.2.1768999004796;
        Wed, 21 Jan 2026 04:36:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HmeN/vAZ/M9IvB7kCcN6f1X0q8oBW9V3hxBU7JGVZZnQ=="
Received: by 2002:a17:90a:c292:b0:34e:be5f:7cfe with SMTP id
 98e67ed59e1d1-352fad4f56cls355269a91.2.-pod-prod-00-us-canary; Wed, 21 Jan
 2026 04:36:43 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV4WIlu4S1H3wQdG86b6v90XZLMPj+gaBu2NsoUiSI4Y3hDswG4dWtaoDw7O4jMaz6aFAJdXE3+5gg=@googlegroups.com
X-Received: by 2002:a05:6a21:1493:b0:364:783:8c0e with SMTP id adf61e73a8af0-38dff28bfe4mr14754460637.11.1768999003307;
        Wed, 21 Jan 2026 04:36:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768999003; cv=pass;
        d=google.com; s=arc-20240605;
        b=GrHBRRxMBqXqipxbN+bIvP06f5S0cMRDaTjGGK54S48BBcpoX4XkqJbHPDedEVAMTJ
         imcxoUc67/fTvHFH4PvUfk0SPQLZ232axUbw//HnoGeCt57zqFpYEprxVloEb23vPqq+
         X6Fh1z9qHosJZ+wAzkZ5pjd4zDzKhfC5SoqwBl5op8MEZREuRHdeHbckD8p00psfmpb0
         kib+9IiQyIyB7qH+a006Lbp56j8E3+5FdS8l8932ihDpK9tWcMdxupvFTBjHbkwl4KCq
         O9lZXTTY9KhGWa5jo6vI+mm0haq0EvKyy0sJMgxsR7vV3iEpZBbxPKFpU5zQ1KSOzljP
         c2cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PEaTN9s2p8Sn9ZSd/CWHeV/MqX0nPOxMFs3ofH5u/yQ=;
        fh=3Z3m55omX9ekAE97hIckJkOCEpCdZnTZtU2LvB5N1cA=;
        b=eXo9cf8kxym8aPYVpCx4S2D5WDDImyOgqf+IU8Ge5t1Gr0agw/bVcYF7Ouqcc3ZLuF
         L5QiUzYJu6o7K0mKJdIPoBt6SYnHtOj8X7UQ/e/s+u7jyxmNzSGtBILLNj3NH5qX8W9f
         eoMNyKE8tHHgc4JMLaZxAmKoBAA+OkLuxarbbunHAqcut5tTBsctfS17FNXQzzOObhqz
         dfbiT3Lb7C6tX3jfbyAEuLjOn5eN4xo3a4yTE1WC1AZjqO6v1WRnNKi5oeSDvc6M8QUa
         h3rOjP4rY7000Flb1eVUGebYVKcz1EV1hVrSUitRBtF0xgrlVe6L1o7vsECcHEWdl/3V
         qOXA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MhuF0Onp;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1230.google.com (mail-dl1-x1230.google.com. [2607:f8b0:4864:20::1230])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c5edf21a779si576674a12.1.2026.01.21.04.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 04:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) client-ip=2607:f8b0:4864:20::1230;
Received: by mail-dl1-x1230.google.com with SMTP id a92af1059eb24-1220154725fso831485c88.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 04:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768999003; cv=none;
        d=google.com; s=arc-20240605;
        b=JOGmX3DA8eBuHIMcXI9z84Z8WjDkZPd20ddW3Qwpl0eb0l2cHCOksGjuZ/xK/dHb7L
         RYIXha7a+F7tKrS7mp/zG6S3P03BNE/7XQgK5LLoRlOLMLRH8YC9hz+D6FRgLdLUNuwB
         hsWnOwPGjI5o3u05UEz/E59pWezJznpKNSbqe93/W6Tpn90cHLoSoiJO0hURhBB+gDay
         yDYYzMvf6vpMXHyRZdKzK7mKRTX1BUV18cf7EV2lgxsAbw3LcigwYrFK5rtnq0XOCYmL
         uVMchjzLOvK2N5O8F5jaHlFNbPI1TxO/e+nfqSnrRaZWNIEBuSL82QgRU06HleIEQBSt
         me3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PEaTN9s2p8Sn9ZSd/CWHeV/MqX0nPOxMFs3ofH5u/yQ=;
        fh=3Z3m55omX9ekAE97hIckJkOCEpCdZnTZtU2LvB5N1cA=;
        b=htz1DjX9jBcU0jFtGrY2j91+xqmWVYk6qhf+CjJPqv2Z0zj+Dc9hG+nGeoG1IHGzEW
         0WgrGJTWMApcfkx96/S1oST3R9avOe8eoe73Z574J0ni+rkhUDmSWhbQJ5XWfOZK3i88
         mfPxuLU8cRhQHEDoQnhOePPs8Ybm2d3ms+LinG9olmdXMBXpRzLDEqCSEQH+aD5uODWG
         8WAvpMpkODxN5wHFdDMC+gI+7lJvsZc9OUozDFtQs9oyW9mSylDWAUH8NfT+t9wcdpIN
         zxxmsO2o4Bz02JwwbAkUAj8A5fevwPHDHv3EfiKZyNlb3VlD9FCEiRC3wkKGHIlR7jFH
         6ySQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWWznm9u6Cd1MxiNpznbXtsMaWSuLUO8fXBTZ1oo7+3UFTXsdWR7UO0zvz1ODEWthmlW09qxJwQ/Zo=@googlegroups.com
X-Gm-Gg: AZuq6aJ8IELR7nz5ea/eFAGP4iZVf1K9LoR19gJgYka4CTHDymqcnIjjlkRaHIWuxqB
	OiCclh38E15Jk/DG+RF4q3hj+oaB4zpGQKfJtIte9qCfLnwS/deodJJJMlflfOUGGlVcS3mhIhA
	APAcub4hv26+gUiSnSk7GgFRaB9q/6TpLsvk1evhJHJ2AqZBsopcMRVGcP+bogevBE/WcELhtvp
	skOYBY3FTvIk1OcQR2zzv/Y4gqgaD1ukSg0JKh1SQqmMxaVETIKDHBlFKa17ugO5XS6ky07wQys
	oqv+X0EJEPI41Y7dB9qEzviTEgr6F42lR36J
X-Received: by 2002:a05:7022:6b99:b0:11b:ca88:c4f1 with SMTP id
 a92af1059eb24-1244ae9ee20mr14221247c88.20.1768999002171; Wed, 21 Jan 2026
 04:36:42 -0800 (PST)
MIME-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com> <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net> <aXDEOeqGkDNc-rlT@google.com>
In-Reply-To: <aXDEOeqGkDNc-rlT@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jan 2026 13:36:04 +0100
X-Gm-Features: AZwV_QgBBL7kVX6shPY_rD_ZSqxEg43eFMwlNHC3kU2drrTme4vk8R8dbzHINHg
Message-ID: <CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g@mail.gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over
 raw pointers
To: Alice Ryhl <aliceryhl@google.com>
Cc: Gary Guo <gary@garyguo.net>, Boqun Feng <boqun.feng@gmail.com>, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <lossin@kernel.org>, Andreas Hindborg <a.hindborg@kernel.org>, 
	Trevor Gross <tmgross@umich.edu>, Danilo Krummrich <dakr@kernel.org>, 
	Elle Rhumsaa <elle@weathered-steel.dev>, "Paul E. McKenney" <paulmck@kernel.org>, 
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MhuF0Onp;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
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
	TO_DN_SOME(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBXEQYPFQMGQEQHXTAUQ];
	RCPT_COUNT_TWELVE(0.00)[19];
	RCVD_COUNT_THREE(0.00)[4];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[garyguo.net,gmail.com,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: F417456E29
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, 21 Jan 2026 at 13:19, Alice Ryhl <aliceryhl@google.com> wrote:
[...]
> > On the Rust-side documentation we mentioned that `Relaxed` always preserve
> > dependency ordering, so yes, it is closer to `consume` in the C11 model.
>
> Like in the other thread, I still think this is a mistake. Let's be
> explicit about intent and call things that they are.
> https://lore.kernel.org/all/aXDCTvyneWOeok2L@google.com/
>
> > If the idea is to add an explicit `Consume` ordering on the Rust side to
> > document the intent clearly, then I am actually somewhat in favour.

That'd be a mistake, too, as the semantics is not equivalent to "C++
consume" either, but arguably closer to it than "C++ relaxed" (I
clearly got confused by the Linux Rust Relaxed != Normal Rust
Relaxed).
It's also known that consume or any variant of it, has been deemed
unimplementable, since the compiler would have to be able to reason
about whole-program dependency chains.

> > This way, we can for example, map it to a `READ_ONCE` in most cases, but we can
> > also provide an option to upgrade such calls to `smp_load_acquire` in certain
> > cases when needed, e.g. LTO arm64.
>
> It always maps to READ_ONCE(), no? It's just that on LTO arm64 the
> READ_ONCE() macro is implemented like smp_load_acquire().
>
> > However this will mean that Rust code will have one more ordering than the C
> > API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.
>
> On that point, my suggestion would be to use the standard LKMM naming
> such as rcu_dereference() or READ_ONCE().
>
> I'm told that READ_ONCE() apparently has stronger guarantees than an
> atomic consume load, but I'm not clear on what they are.

It's also meant to enforce ordering through control-dependencies, such as:

   if (READ_ONCE(x)) WRITE_ONCE(y, 1);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g%40mail.gmail.com.
