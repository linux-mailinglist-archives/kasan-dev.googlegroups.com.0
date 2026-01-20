Return-Path: <kasan-dev+bncBC6LHPWNU4DBB5GYXXFQMGQEX6PYCOI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IOU8GA+pb2kZEwAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBB5GYXXFQMGQEX6PYCOI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:10:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D9F2A4722E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:10:54 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-45a135956eesf10399832b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:10:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768925453; cv=pass;
        d=google.com; s=arc-20240605;
        b=gtcfehiEX1lkGGwRSzij3VbZXAANJz84MtMGHK59dqnmhq36WmEAptSQfEa8HjX/fY
         5B8h1tBwWGq0I5ra0habTn7c85T0eR/q1fk7e6TP+VL4IyGQe+8ix5IK6hXJ0iDTyenJ
         h9cFsnW3X6OaUbkVXqv83X265RiqYxpXXdU6PXGLQxmahyWS41KVWXdGzoky0v2gPVPz
         8E8OtJRmHAWlUuRA7iO1rlYFiGWO/GEo3z2uH1u07nw72oqaWARGv9sk9jAUPdFE0pRU
         oaBzWTSKXA4RFTc9BGVfrehDhcDpSoOAdQKGIMQ9XohHRA3CB0K8GVZVPwyvY5tW1RkO
         y39A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:sender
         :dkim-signature:dkim-signature;
        bh=d2xYFEbRq/+mfJIp2UECu0MUylCvMWh7yvZD2n2bhS8=;
        fh=94DhgUcgWgDP7bvkJO9yE40Bl4gwzOFUIOPvczNz+qY=;
        b=k1gFoEh9qCjh/MNP9ND98RjffbHmj2zq6nLJN1t5L6L5ymWrIQp3q+4k9DVpb3PGlF
         RSA6xng5ugdAgkXZOsh7eLFDMtM6ayxPMTTl2iasRHFR02aeyRZt9p/5R+Bomd1MDOe4
         0AFAsMCZAj06owwecu1Q6wPDOYmOEhVtubIIOA8HdDjSYol+3lLYR+Cx0QdrbEx/dTx+
         Cxa+AckR+Z4rxDujV8DJOIM2tfjMIKG4g9s4soTzmM/2BDWi6lNoKfk9SfGsub+d4+pY
         eZtWinP8q2Z0ye9ncLue7lAgvSBTAz/gSYyJJgzjRS9KZ3r5LLBH4H1nZJGgL/HVadwd
         k9CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3UxII0n;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768925453; x=1769530253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d2xYFEbRq/+mfJIp2UECu0MUylCvMWh7yvZD2n2bhS8=;
        b=WCEYxACxARN8Rz+0xpu9LPnc+KWdKOgxrhXWVxSfl5sHJpsO3s+Q3jSgjDr7dhdIfh
         XwkJbeBFm9pUh3DETmkz7k6FkzRJ97uch4EVyyRa7DhWQ4nV1FLrec++deMFb9WY6MQr
         NI2FUx9BdZIEtVPPUCQl+M5hSF7vFVs+9cxt5ySuKPvb72CjyUaxD1Q6Z6kgaNUxkn6e
         EXLXDDzWRal2FKqGs657JeypEKe2xqg5ZLHc4ic+YX02+6Ei++/XbfRaf7Q5LLYFexMu
         sk+3Eh+/QZJ4gXEaYT+B3HOQhrlFoOiOWfsdZkxi1xHDtRjHYc2P2TbLWqBg6B7tQ4am
         u5bQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768925453; x=1769530253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d2xYFEbRq/+mfJIp2UECu0MUylCvMWh7yvZD2n2bhS8=;
        b=dObm30hwbIrT22phyrS0/bj+h/GGUPdFkFJTXf+m+4gqgPYTqAHlBr54gvxSMo+r7+
         Yj0qp5NDBT6Bm9HUXs2AaVqxlWh7EtvyWloAYieIgWdzEeMZMnQ25IbnHPeAeFPzXP03
         x0De4YToPfSAyx8TonbCVO49q5z6zndrm1oydWe1L73n2CnM+5MyXUdMFHhJ+ztHvcA+
         0emZCVxAf6xdfY9Wgv0Vt9FTN4Sqc01a1UDjfZFkjh/zzpE9aGqXXgt3dLwoxFhqbsiC
         DcQs4cXSmBHp5f7Jg28u+Qnw2eLwhwikcu5x8VHZUod8LgeUwUZgF2cxLpttWicAuwb+
         PQSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768925453; x=1769530253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :feedback-id:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d2xYFEbRq/+mfJIp2UECu0MUylCvMWh7yvZD2n2bhS8=;
        b=gWbPUsW7RsIo+r+4I4sCG+M+AxYM+ScihCBH//Ab18i3aSL0mufMXfjL+Rx6VsFb2w
         UzoOU/KzVjp9puPhBlqqeGgJFpbIcWfRiGDiqh0Bcy6oetDnH3INqhbm0kAkC4vGcKQz
         LWmYU8ggmNy7IgBYepg1UQoJ+i4MVqN+02F+eGtVrlpBO3m7tbRFlAdTHSqJz0ZIwpiR
         NnvTyTDbODnnxEUdX/k9EgTJ/d8FPcVtIf6dWmORHY54HIWRKMfD40iHq+BZnoKIS+3Q
         4jcsvA2ZpnvsWKMYF669ZUyvAm+QXAQZHl45BhGshTyybklTOiaqxRQR8UBkP/iA9g3j
         mVng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnb+47nd+2Vuo7uyr9DvCDZGBdiMG0DOUe1zdA2+tg9bANIbTQkVMI1uOSv/Ub6AgrogS6dw==@lfdr.de
X-Gm-Message-State: AOJu0YyZmbJBkS5JagaZQMGUWK6ddQuByvjNnYebWYLgjDuHEU6Xp/V/
	T8vBzWi9b9k+FWszu8U5raGJQvSDya/0JkqbBaCPmKrTmdijq7eoOQPr
X-Received: by 2002:a05:622a:312:b0:502:9da8:818d with SMTP id d75a77b69052e-502d85be11fmr11168001cf.82.1768909940479;
        Tue, 20 Jan 2026 03:52:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GjCqa6hPfNrbayCxFFaQa8Lin03lLuMu+eO2eEF1OIkg=="
Received: by 2002:a05:622a:513:b0:501:4a3e:41ff with SMTP id
 d75a77b69052e-502149f60fels86665811cf.1.-pod-prod-09-us; Tue, 20 Jan 2026
 03:52:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGS+lD4zc7D/u7PDykqf48OBz948Yoq82wmIEWJ2zHqXSkul8Sv1udqcLpSZEHyTh4pi66V9Ul1V8=@googlegroups.com
X-Received: by 2002:ac8:7f01:0:b0:4ee:483:3123 with SMTP id d75a77b69052e-502d858b29dmr14500511cf.67.1768909939405;
        Tue, 20 Jan 2026 03:52:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768909939; cv=none;
        d=google.com; s=arc-20240605;
        b=klcLI0vU363XYAzErZcd1hYf5Ab0NZolB77nxnEh3tvAjHy/xbzbtP9MFEhJkKu2Au
         FesSe7czbiP++XTNmdrDIcuorbO3qf2VpKdIMiXsYc6JdHe1C8t8KyJe29vPOfdhA/YF
         gRGCYX6mZIvXij3z+Z9BkhKehodv498nQq8yGcO3cTj34oEfJVpHCKk5H6voo9KnwZvR
         AMnbKtCMwqQq9QSvkLSKNMrRLeEjfcLGHsvQ69GfVimQYPoeqkqeEIlbpPVgkI02CI6R
         G1lwGigdSYrZ/3zhznyzCgLTOz96vI5vr1bMG5Uvct1d8KBO6kQuI2PCZM7mMzsQkiMs
         e3FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:dkim-signature;
        bh=noKL7zQXHKYfYinQlJHUIYY5IKQR6tHuuXlN5E414EI=;
        fh=TB+inXU4V+/++DCWTw6gTrUoBPbY9P4Qjxnom8Bn1V0=;
        b=UWDJVDbMCWwry7afKcojPamiBPERyCF4GyjPT7vMtvxNY9cAmsDsN47oBmaT6AlkNj
         s6SQHQQ3nXPV7WgMtZNNORTuD7PJCJzSI1XR5sARUxzjEPhjmFWwOZ3qf6wv7YqAKjWh
         VQEHdCjqB5n7WT1MaN9jMh4ctjFUMt8KNDGKw4oEDs1+/hPk5yjT0NyvIQ2T1utfmrIm
         wXAS7bMoz/tYw96yB76jYMrGyrmNAO79xahdrFf+FIXn/VPv1KqoHFWuEJC6nH/j3rh+
         7qqkfedDdpITF0pjyxlcJvkDZ5JQutCCsJwqrnT1Revr3DAFCWVtixX6a41vVRCnIJzn
         Sqaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S3UxII0n;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6a72419b1si40181685a.7.2026.01.20.03.52.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 03:52:19 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-88a288811a4so54561416d6.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 03:52:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUdJLmNmFKQksgLfYuDQrb5lO6QVKjIHjhPYiTnmqp+2NUo5qDkVLNLjSx5d1X1gGwAiRmZZ7yBGaU=@googlegroups.com
X-Gm-Gg: AZuq6aJqaUAgMwuG9ZfIx8+kyjonx6biDLsc2SaX+gt7UAqGxJuOqDj3zOaWbOq4+mB
	tM/M3PTWcDOOtA66sCAzhNOSQrkueLpLnBlqOWsp56XwkTgeB4nt65oYt8SxsU+2o5gYeysjnPe
	y3mW9h3n1rEh4RZNnnfq/A50Wt6HyUJdBZQ+7F8QwnhWEiuMpQnkENbfRaY/bn62Fv78K8vRFSh
	M74QPq8Emd0oZIfRzB6XcX5fpNxFKBCcyeqA7uTwDLKWtMxx/bKGFpNokYfICd4UU0Ea8htbip+
	f2N0RCifRiATX6pjuZCKk2LRE8MEY9ExY3RG1BczQhTzX668oI3klDNO1Ed+u8GbOPqDBWoDy3Y
	2B0GjYlcICh30akFF+kKFHwZAvPl+I0pzWNvIeK4dFEAXV/oRnZnDh/SGiH4NS5w73M0tEUCp0n
	9vr4wV3fPH/4+0QfjdmSy8bV52qpDdQjgg4/N0fJ9l3eXGRPYGYzgKa9YgrNHqH3OJ5XQdyDILo
	5v1LCrP0B9yhCj2zQpZbYLd0A==
X-Received: by 2002:a0c:f6d0:0:b0:894:4793:efb5 with SMTP id 6a1803df08f44-89463837a6cmr13834676d6.4.1768909938912;
        Tue, 20 Jan 2026 03:52:18 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-8942e6c9a9dsm107071836d6.43.2026.01.20.03.52.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 03:52:18 -0800 (PST)
Received: from phl-compute-05.internal (phl-compute-05.internal [10.202.2.45])
	by mailfauth.phl.internal (Postfix) with ESMTP id 8EB16F40068;
	Tue, 20 Jan 2026 06:52:17 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-05.internal (MEProxy); Tue, 20 Jan 2026 06:52:17 -0500
X-ME-Sender: <xms:cWxvae6kc1TFcI9TJPWN-r0Pi54xEVHRlnTp-vtGY1_5kR1y9bNnsw>
    <xme:cWxvaczkpMf4NjmQMHZz9DaKkERaCs-ewKaWwY6SKRG7FlYpzDD6ttDVLp4-B8Ptq
    9TGgF5MDOIAZaMxRxBpNVj8MMU1t4okSniNUn08IIj-wX5gr_DJig>
X-ME-Received: <xmr:cWxvaWD7IC7dfygFMVaTHzAYsQAUPgjYrvLCDOAmhrvV765T-eUhM4XQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugedtfeegucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhephffvvefufffkofgjfhgggfestdekredtredttdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpeegleejiedthedvheeggfejveefjeejkefgveffieeujefhueeigfegueehgeeg
    gfenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvgdpnhgspghrtghpthhtohepvddtpdhmohguvgepshhmthhpohhuthdprhgt
    phhtthhopehlihhnuhigqdhkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprh
    gtphhtthhopehruhhsthdqfhhorhdqlhhinhhugiesvhhgvghrrdhkvghrnhgvlhdrohhr
    ghdprhgtphhtthhopehlihhnuhigqdhfshguvghvvghlsehvghgvrhdrkhgvrhhnvghlrd
    horhhgpdhrtghpthhtohepkhgrshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgt
    ohhmpdhrtghpthhtohepfihilhhlsehkvghrnhgvlhdrohhrghdprhgtphhtthhopehpvg
    htvghriiesihhnfhhrrgguvggrugdrohhrghdprhgtphhtthhopegsohhquhhnrdhfvghn
    ghesghhmrghilhdrtghomhdprhgtphhtthhopehmrghrkhdrrhhuthhlrghnugesrghrmh
    drtghomhdprhgtphhtthhopehgrghrhiesghgrrhihghhuohdrnhgvth
X-ME-Proxy: <xmx:cWxvacaWZh4sjTdNnxvo-RY08pCAGMHU6oz3GtYY83TahsLzo3zhPA>
    <xmx:cWxvaVH9v9jIsSv3xBvewOIYhqwrvpqIM-4f5SBsPuYuerGbhySryA>
    <xmx:cWxvaYuLdN-3g2qZTwjnkdP5nvAjWgUAp8FbfGHHKKMntdAi0DlrmQ>
    <xmx:cWxvaTIFjoNqnVJsZBRniY4Unvx_7-2ldrTR_nrHxhWNyETxhfMZ7Q>
    <xmx:cWxvaeO4loKUB_fs2fsM5G6nADvOiAYKujq3cBHqFJYbyNu4pFPDyWDl>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Jan 2026 06:52:16 -0500 (EST)
From: Boqun Feng <boqun.feng@gmail.com>
To: linux-kernel@vger.kernel.org,
	rust-for-linux@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Gary Guo <gary@garyguo.net>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?= <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Elle Rhumsaa <elle@weathered-steel.dev>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Subject: [PATCH 1/2] rust: sync: atomic: Remove bound `T: Sync` for `Atomci::from_ptr()`
Date: Tue, 20 Jan 2026 19:52:06 +0800
Message-ID: <20260120115207.55318-2-boqun.feng@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260120115207.55318-1-boqun.feng@gmail.com>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
MIME-Version: 1.0
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S3UxII0n;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f29
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBB5GYXXFQMGQEX6PYCOI];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[kernel.org,infradead.org,gmail.com,arm.com,garyguo.net,protonmail.com,google.com,umich.edu,weathered-steel.dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[boqunfeng@gmail.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_COUNT_SEVEN(0.00)[8]
X-Rspamd-Queue-Id: D9F2A4722E
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

Originally, `Atomic::from_ptr()` requires `T` being a `Sync` because I
thought having the ability to do `from_ptr()` meant multiplle
`&Atomic<T>`s shared by different threads, which was identical (or
similar) to multiple `&T`s shared by different threads. Hence `T` was
required to be `Sync`. However this is not true, since `&Atomic<T>` is
not the same at `&T`. Moreover, having this bound makes `Atomic::<*mut
T>::from_ptr()` impossible, which is definitely not intended. Therefore
remove the `T: Sync` bound.

Fixes: 29c32c405e53 ("rust: sync: atomic: Add generic atomics")
Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
---
 rust/kernel/sync/atomic.rs | 5 +----
 1 file changed, 1 insertion(+), 4 deletions(-)

diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
index 224bd57da1ab..d49ee45c6eb7 100644
--- a/rust/kernel/sync/atomic.rs
+++ b/rust/kernel/sync/atomic.rs
@@ -215,10 +215,7 @@ pub const fn new(v: T) -> Self {
     /// // no data race.
     /// unsafe { Atomic::from_ptr(foo_a_ptr) }.store(2, Release);
     /// ```
-    pub unsafe fn from_ptr<'a>(ptr: *mut T) -> &'a Self
-    where
-        T: Sync,
-    {
+    pub unsafe fn from_ptr<'a>(ptr: *mut T) -> &'a Self {
         // CAST: `T` and `Atomic<T>` have the same size, alignment and bit validity.
         // SAFETY: Per function safety requirement, `ptr` is a valid pointer and the object will
         // live long enough. It's safe to return a `&Atomic<T>` because function safety requirement
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120115207.55318-2-boqun.feng%40gmail.com.
