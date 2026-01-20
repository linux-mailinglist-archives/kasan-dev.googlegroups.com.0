Return-Path: <kasan-dev+bncBCG5FM426MMRB5HOXXFQMGQEATS7DAQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GB8IFqCgb2kLCAAAu9opvQ
	(envelope-from <kasan-dev+bncBCG5FM426MMRB5HOXXFQMGQEATS7DAQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:34:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8407462BB
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:34:55 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6580eb3fe28sf330453a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:34:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923295; cv=pass;
        d=google.com; s=arc-20240605;
        b=MsARgL/m4RTLo7RU3tbb3xi6PYYaxFNe7FcXkZt/2Dfbbo66UUd8qgXZ8tvrMic+1r
         E7B7IF5olGNn6ZMyhYrMh71BI2fpr7P/0/6St/Bob+YMIZUY/53FREaXGVNAcTS4Zl+Z
         x9fgWq/JEzkWwwTeYzThGcaQli1Rt6NIYSgK0giILklP5VQH/CZdDvOE8AQJyJXekPQQ
         spCmW4Yo8MaaqxEcq5VsfupyuMFStZdhNAxLrydb/ew6N2TqPfnPFTN9fAYfr1xs/+pI
         bbWy1gJoQFewBe7MyLL3JVaSOWwNssNTrx3d5RcJf5bF7p3RLapMOzhdQ5/feh2sWmz2
         rzVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ABqpTdrwJXXfDuPyth1BELrs8pJcKX8IFpFMnRAUHeo=;
        fh=4QLj3uRIs9a3rL95q80Ko8o/FpE0RKh35NGHcI2C/FU=;
        b=CRunykeL+HWt1CWRQVuQWRDiIlqUMMkoZNY3dEPB+4/B9frwD0RlLDmbMK6LMOGKJc
         NFpWB2/bp7jiuS5GI8OQ+r+XSpURo3LQKKqy1EzfIx4o+8KJ/5VZ7r0aeXTdS6969UCV
         1a38n1/Jv6/81QMUpZBOZ/JPJVzmil1rbi95mZEH0QWNDEWfNc1WVXMBVJdKkzuJSoVg
         40ZUeUNY5BVxKAQ/FeV4ZBG3eOvq7S3wmXmdpx5j8w3Qry9ykn/Ac1ccJN7RwY2qzHOc
         XbYujodMGV5b0pnDLRsKxbWjtElM0oaYIKcHDVe2BCp3yW/CiADPH2xu63LAIOiREVok
         pkoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="A8/t9JlI";
       spf=pass (google.com: domain of 3cndvaqkkcxepaxrtgnwavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cndvaQkKCXEPaXRTgnWaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923295; x=1769528095; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ABqpTdrwJXXfDuPyth1BELrs8pJcKX8IFpFMnRAUHeo=;
        b=I9ftMJYFZCvpY6+Mcy4T7H9DBMz4u6dsoYdHPFM54JoA9OHLZzpbjnlrYzt0Uom/qJ
         5lcbhIeT4TsVhWnep/NBP3ixNHEKg+Y3ZxmrwaSMA0DC0bYInfnPfj+73Pm4ZJJVcaWi
         /iXTjJOyBlKukqocaunlFAelEKkHqQKK3dPAPMrl7Yxe0mgqcby5Dq/yCGQu8h668p1m
         AX/uL2ZKMngCTRY6Bcs9vERXU8JtUVRb3azyi6MKzgcH7AuXPk/bMmH+fNldIADAhQ+E
         BmJb2l6x+Of1V+FiBYL8AKWuNABkoas59zLG8EjmOLZIBBfV4DlS9tKwHwWggAwNFQns
         /xAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923295; x=1769528095;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ABqpTdrwJXXfDuPyth1BELrs8pJcKX8IFpFMnRAUHeo=;
        b=qdb49bC4olKgRGKnU6fY5+VsbF+0lI15hFPESFzLMI1UrwlJzUxpmxaIrqinIz7s9D
         FDFvKHW30mvOAuS6QR1JiP/Ge7wiriVnbkAgzsh6GDRFXU8CoMMxFhSfdL9ijuwm42ZT
         WMgHEO7VKyHBg3WcWt7eo6bEJsO/1b5PwRvO1pfVhOumXLOpP5BmnmtIzPgRI3aTIL2l
         EtPG25+4drxBvu5FlzTTzHVbGkmi/EXCM+YqRVlBKk4s3+ij/mmgRzVQZpFVjfsL6CuQ
         vfLOuuL0lK2yg8LbYVo0DQcgK/zPG3Y6lv3WRJzRFTRxYcrzIHQlMnVnHLcUJs9AueDb
         XC4w==
X-Forwarded-Encrypted: i=2; AJvYcCWqLS9xPylKvea/3J7EZESWMjvtylN2vFaUVe//AbX7oxIFggSrJVNzgFSSweT7QTY1geDQCg==@lfdr.de
X-Gm-Message-State: AOJu0YxeDODDwtqQyfUulRgqPUPlhAUjHdY6h/YOQB/nJgqXY2u8lvJJ
	PaQzlvlt3W8nYMbPTP3ysAX3EPlBAxsji1IDAs6UoJvmFEYKGCUEA+cV
X-Received: by 2002:a05:600c:3b1b:b0:480:3230:6c9b with SMTP id 5b1f17b1804b1-48041472847mr6338305e9.7.1768912757130;
        Tue, 20 Jan 2026 04:39:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EmVQo8bC7R+v+ueWxZ/YGB6xTRcw7InSUWxFLUT49HVg=="
Received: by 2002:a05:600c:46c8:b0:47e:e937:e9bc with SMTP id
 5b1f17b1804b1-47f3b7d6f46ls31826535e9.1.-pod-prod-09-eu; Tue, 20 Jan 2026
 04:39:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXn2u+uBXUPv0j7yMQlnBHX/W4aOvRMZcQR+6AkKGdymRIJM+27IZ9dZz7nUAVnqTeTo+ApD6/HPGM=@googlegroups.com
X-Received: by 2002:a05:600c:608b:b0:479:1b0f:dfff with SMTP id 5b1f17b1804b1-4803e7a2cc0mr24828565e9.10.1768912754932;
        Tue, 20 Jan 2026 04:39:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768912754; cv=none;
        d=google.com; s=arc-20240605;
        b=VlF9trc60acm/w5KyQmRPJoUkF6zr7U1DmNe7v+Ts/SMi4QMuPq2XCWINdolahNwkT
         WbGZJ3WhfYS7i37rky1HVaVs2hkeNYA04VnbRD1kEitXiiREPlbH5Xmq8Zxnau+uF0j1
         NFW8wPtBmYeRGVIE0HcNU3h7J9gBwpchEeIrWjfPQjtQ5MvSoUbNlGACBsFymJEx6aBA
         x1+Ewlac+RTDty2f63O2j1XOtKyE8I2+M5OhCIL1/l3dCcrJ+IyCTlKUdRcXlqJh473L
         dlAZUbD3nsPSrLoFdRBUSarqZ6oAzA9cTNJ4SKYVA5SZE587do96xpCoWIGl+4G08N2k
         RD/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aC20Vi3ua6RNxinQI5h1askXn9iFU0ocrDNDebQDeNI=;
        fh=aJBNF80yspplHfiE6BFfRTe+STfPi2K2g9kNP0Idw8I=;
        b=T5GsyZlqvSc4RvaMklp4hIuOE9LTe19Ag/Jbj1dPuYKlGF1SwaqDSIKO2X2KpwV93a
         5klMD/ce72wr/qKE/W35xY6mAZ5HM2ycyh6gRS8x0TxIteHEvS9gn9naYG1hykGuQku7
         TuRIbzfdVni3N15usl57ruHYMfYKa1fEVHbPiIy2NlmbrSlowvPwMgQ0PC/lX36xBR0x
         dRPUjzNCHh/H2p+PfWFFZQLyVRk9cb1w4/kZ1Zp92Rm4GHLR+rW5zYLkig4qmhNvohaj
         F5KHHiVnZsbCi+I6eIzzCh6lFhP82IDrp5IwA65mAuBcDOGlngi+rD0PCncDNMwv9eZS
         txYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="A8/t9JlI";
       spf=pass (google.com: domain of 3cndvaqkkcxepaxrtgnwavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cndvaQkKCXEPaXRTgnWaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4801fdc74a0si728025e9.2.2026.01.20.04.39.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 04:39:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cndvaqkkcxepaxrtgnwavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47edee0b11cso27723475e9.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 04:39:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVSnDHXf+I6knJ1hsTDBaorHGjuj47FRrr5BWoC5bMj4P4X7gXyhxJnjiYf7ahgTDeuFjdYcbXbvsc=@googlegroups.com
X-Received: from wmig10.prod.google.com ([2002:a05:600c:140a:b0:47a:9f70:c329])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:811a:b0:480:1dc6:2686 with SMTP id 5b1f17b1804b1-4801eac0cfcmr156081605e9.13.1768912754423;
 Tue, 20 Jan 2026 04:39:14 -0800 (PST)
Date: Tue, 20 Jan 2026 12:39:13 +0000
In-Reply-To: <20260120115207.55318-2-boqun.feng@gmail.com>
Mime-Version: 1.0
References: <20260120115207.55318-1-boqun.feng@gmail.com> <20260120115207.55318-2-boqun.feng@gmail.com>
Message-ID: <aW93cQq0Cyd9ivpE@google.com>
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
 header.i=@google.com header.s=20230601 header.b="A8/t9JlI";       spf=pass
 (google.com: domain of 3cndvaqkkcxepaxrtgnwavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3cndvaQkKCXEPaXRTgnWaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--aliceryhl.bounces.google.com;
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	TAGGED_FROM(0.00)[bncBCG5FM426MMRB5HOXXFQMGQEATS7DAQ];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[gmail.com];
	MIME_TRACE(0.00)[0:+];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a00:1450:4864:20::53f:from];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,umich.edu,weathered-steel.dev,google.com,gmail.com];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DWL_DNSWL_BLOCKED(0.00)[googlegroups.com:dkim];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a00:1450:4864:20::34a:received];
	DNSWL_BLOCKED(0.00)[2a00:1450:4864:20::34a:received,2a00:1450:4864:20::53f:from];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	HAS_REPLYTO(0.00)[aliceryhl@google.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: D8407462BB
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

there is a typo in patch title

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW93cQq0Cyd9ivpE%40google.com.
