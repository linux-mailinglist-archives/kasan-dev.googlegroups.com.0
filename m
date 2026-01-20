Return-Path: <kasan-dev+bncBC6LHPWNU4DBB5WYXXFQMGQE7VP2HRQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0DmYCNuub2lBGgAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBB5WYXXFQMGQE7VP2HRQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:35:39 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94ADF47B03
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:35:38 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id ada2fe7eead31-5ec96023d46sf14378370137.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:35:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768926937; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ri4EUWASxjA6rl0jdXpQH02hPTMZmm5u4jwIg4KsHhnsFeazligwCEAafXW8lMk56R
         W2o/YUAZJfvs/KS3fnSoTBooqhq9tG6EMr36ZvDEa+yplxmoo1a5ym/kELvagxhz3ugN
         OxPIbNppxFs3dSiXrbbVZ/BFbuZ/PVoUzb2ZWb91CyS6UonIpqbTzXYR0b6OLBaNMuST
         r5ZyHvJ/vs2RTuVQs2fmlkgp4Kh5Dp7lNYO0p1w0nWhL+4m22RhoAdks5JbdBqYC/JNS
         Hwy+7E3ZE3fef+fmGmA2NA7ToYoo83tmyJ2Zk8if0kiTn//jKrcB2JejZl5JTzuZNZ1m
         H/FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:sender
         :dkim-signature:dkim-signature;
        bh=z3vph7IAQ/YXdwOzc69vnC53Nw8cfBBEURy78rm7eb8=;
        fh=luKkh9VQN3bAAOQZsKR/blveYRjjdHiuYnwC7nIKWFg=;
        b=FAsMeRXWoartfvt4rbA1vXpbukxKrB3Ga76p2hk8b1AZf7cil0UhVIRhmA0R6TEuH+
         HOVG/a0cjY8uXIz7T6lOGSj5lZfKGlwwNU7joHAMtc+tWvC2cxIhopLyaeQvklq+TZKk
         Cp8+nB6TKxGgh9v/vAh/zz1+nkXTw6pt7SMe9lBF+PH0R8dYFhSqu1YYhd7FqmyN5Zft
         5sFFK6bCL7+HhV266JVDvrTe2KHbp3PA+l6Uo+DvBaZ4RV4QNpzyY0DBG9YKwJMd0Y+H
         smThxDt4n0l72AKWwOPrx+vflZ4FyhrdblhPgMDVzw+yN7CgIsqcZ7BgzSfnF0exJyNI
         lXaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m+X30Bjk;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768926937; x=1769531737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z3vph7IAQ/YXdwOzc69vnC53Nw8cfBBEURy78rm7eb8=;
        b=VRCLG8749IOWdMu9fsfS2gcQYbxcoRhihMHMIXwCtfYc2NYrPXP0r4fd6rOaCa2f4T
         Xb0hliDQ2gYWGoMglEfvA4Ky0rk+kgSO6RPHxYew1DdfHWqETPv+xzrBgqFRi17EVYL9
         kaBds+17AIHZYqglD5JCimmAKiGxPuoqsccZO+rkrDc9LiU+iZySWVMkgvHKkwCBgieq
         18Gy918VQxZkUH5aTVjlyZM44xNq6lIOR8pCbc1qm+RBo0BKI8Kkst8asIAaMcbEacuW
         yvB8NeCzRYTjZ49lgnduFHI8uw0mD48/INFOgKBu5tyqwSjqA+i2Bfnd8KrGEB4zFgs7
         Laxw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768926937; x=1769531737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:feedback-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z3vph7IAQ/YXdwOzc69vnC53Nw8cfBBEURy78rm7eb8=;
        b=YUchtU4ndUtt8AjkOx88suVTceTM/ndIKJLtINv77LtDS/+Y6/lmhyIUZqJQHt09Gh
         n6GGmtLYsXkmZxNDjCRvFiAC2KsBkpmhRp4IomCYCSaM2HIGEZfW5MezOv2ZNeQPgm8/
         GzkYD+FPwGwgxaavemjP2drrwSWhvZLw+aWgMdznhUAPBYTakA06d8GiMQ+a42nx0YxJ
         Vg64qwFld9Xmi0T1PzcAWBcwsiJcqm2DgF9Y5HW8yS9ohw/8gIRwDae5wAcQuya0ThAq
         1DOcWrVuAoXj5rd74BOhNZ5gZ9cwsJGy9KcHtyCnRcnwQxhvS+FMpdxASQWfoJA+7l6j
         DFmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768926937; x=1769531737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :feedback-id:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z3vph7IAQ/YXdwOzc69vnC53Nw8cfBBEURy78rm7eb8=;
        b=CX3WjXYhtaDT2F0EiYVLm7uvgVX0qvtHD6AY6WR8eNtuafSiamaG9Vj1RWSPyT+L0x
         wkpQFM/aYw4+6XM/z+d9jxMdTqaxxMA/9IqmG5nwsdkmU+IBxcjrPUha4hz4FtK03DTB
         1tkvYbtveNJQU6mqthkwYlDfM8xEW5Ii/Fw1hiY6HU+6gs9CS4MxM3RLduaJw4HY2+3Q
         2okAX6FYXohOaMvmoYc7tAp1uL6Q6/QelV5EsdONjhkFJJ8mq8pxjF4WPn/15lYpFezd
         K7ncju2QoMFwJuisx81bTeZzy5jzXV7r0e04FExOTsxJd4AmPk9xU1Y+/jUfO9Lxsp9s
         sB1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFnesH46bJ2BgEg6cXa0qYfqHl5SLnSPix/zp31TzVn6hpt67e57pEtYLq3rmH3sCjHNvovg==@lfdr.de
X-Gm-Message-State: AOJu0YwoW8kyAEbx69rZMOJMlTBlBPYB4vYg2K/ohX1k53CnEEGThHhO
	NBW99qcA1ET8w2LRXqVCmtS0ktauzgx05KHIOggbvvZepZeh9S/OPwFf
X-Received: by 2002:a05:622a:546:b0:4ff:a6b7:6c9d with SMTP id d75a77b69052e-502a1660944mr193156891cf.38.1768909943193;
        Tue, 20 Jan 2026 03:52:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fheutp84512VqdxNJyYkAWmx/casOIMqG/8VxMfEMYQA=="
Received: by 2002:ac8:73cf:0:b0:4f1:83e4:6f59 with SMTP id d75a77b69052e-50147dd1cedls36064371cf.2.-pod-prod-00-us-canary;
 Tue, 20 Jan 2026 03:52:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUv7Aa1T8R5HUb5OvoXSM7KN47cFZQWgEDzlec63HIvO9980GwN3lHB7p8BR+PcXrh5cJcSgaBucGg=@googlegroups.com
X-Received: by 2002:a05:620a:10b4:b0:8c5:ee3b:db47 with SMTP id af79cd13be357-8c5ee3bdb6cmr1733701285a.15.1768909942184;
        Tue, 20 Jan 2026 03:52:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768909942; cv=none;
        d=google.com; s=arc-20240605;
        b=AsI2KlVb6gqHWV/hD1pRg3NBCBxEsThIrwYHitQy6uFYUgqpcZePBx2sv7/R+3Ol0F
         y2pLMp29To6uGB6SxkFWjMdPYtgL3ww/zZhJPLPna+Xp8EPcbm72pYZOsKYqedT2IdDs
         QFq/5jcez7tKRt82NVZUNl16Ad8GejLDUWR+GIVLPkd2TfvUbkZL8nelWemEeufi03nO
         oZFAKb8WneEtNpEvNd8yySJlIGsfbZ9vkLP1tKxzE6Cr1z6IeNzT6JGOlofudZLgzbVk
         BJL9pfOUNf6aZRTzepC7S8uYuKb3HInaRyxLKdfHrJyJ7Hv+xueLAX/G3oi2HUyLk/Qy
         iqhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:feedback-id:dkim-signature;
        bh=1M3E4UxKfMJ+dI/l+/VVbPQmnjuaMV2kWf95M7jFT9o=;
        fh=si4VKKSZd9OPrbNLmGmTrJI3sph7qraILxr9/fzaYDc=;
        b=aADAc2KPXo648Af+dsTg/D/zhMXVTEKOeF+OLMGBZv/KViUVXC4YJ/Hfd9XXi+dbaE
         puGLIH7n+UW9qMGxU2yqvqsPh5xankLnnQWDOn+CZfDZ/2hTlfVjEUD879jNObEI51/u
         ObNBRsnfXiESW7yom9+uDFfMuKGJHBH2ScVtN+PknaNmPYjF0AAGL2oevEJUn4uvaBwU
         sLM1ZhbrSScMqFswKrMknMKg8NWRJ4GvwnevOpbOnoPvfgkV4k0eq2R16kksXwMiwF9Q
         8xHmYQ67eDm/G8sJ0+j4lXrJd1baQJp9XtI2hD1gc7lDeIP9FkZCYKjpV1DBQ8emMiGE
         IFgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m+X30Bjk;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6a71ac4dfsi41999985a.1.2026.01.20.03.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 03:52:22 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-88a37cb5afdso87188596d6.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 03:52:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVEiTkfemj4iJbWXviOlYJEWhfrbIiKHtbcT49bNErrllgT+6mGq01WEGOXcKJnn0j8zXGnWvAHjU8=@googlegroups.com
X-Gm-Gg: AZuq6aIKnOUykfsvJY2ZygHspp0q1/a4kazzdknGlmuNavBHoUNlp4STD1DYb7Fw2fd
	qZewH1FgqyFvOZCmP2IyWiLnevHmO0bVjxGkwKgaWBzGcq/1OBIsfIOmKXvqvCFXQcXRgOh7Yb/
	T7iqGw/ddeEtetQUB2O7xawJU0CP75UNztX9bAgnavFAt7XcFwNtzDRuHmhW07PzZpMXfHEVLOB
	JsWP3MVAKeMjGSYq9jBFaG+fmu1joDCW3QCvLF4bLpL3spTuTUvKZw+JYLdyhun8dDbDkuH4rcf
	l6LCWsfpoPdcd/uqDsGKVRQnYz9VlvPXebnukK25YExiV35waVbuGHOSTgSGSvvTR/Z7FywBhwb
	sew6CARzj/5vKfkMAeocPcqRLCZeTvIsFag/v69GlrPYWOHxcyuD/pPSGDy+VyxHyrgpfMoHpG/
	0gWI8dkJMqGZqjvQUNBqsvzZc8yQzZ9O2IbxBvYvzM31QXhNdDsTJFwbiqR6MkoCtPfs7OBMcvY
	DcelyKlSNNyWVQ=
X-Received: by 2002:a05:6214:da6:b0:88a:375b:ed7c with SMTP id 6a1803df08f44-89398273c7cmr206650326d6.35.1768909941648;
        Tue, 20 Jan 2026 03:52:21 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-8942e6214c5sm100416876d6.25.2026.01.20.03.52.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 03:52:21 -0800 (PST)
Received: from phl-compute-04.internal (phl-compute-04.internal [10.202.2.44])
	by mailfauth.phl.internal (Postfix) with ESMTP id 45E7EF40068;
	Tue, 20 Jan 2026 06:52:20 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-04.internal (MEProxy); Tue, 20 Jan 2026 06:52:20 -0500
X-ME-Sender: <xms:dGxvaeqkIaxe-HgSJlZ-XdYMXejqbWoVC6UThHAb-Rvic93GdQubJA>
    <xme:dGxvaSa8gav2xX32Oy285vSFg7ByFOIkpt2RK0DzHdiMZ8fTzzLqNBx5e_FUfMpdi
    q34jZJ9pgSsoNGFH4kULx4XuYenM8xrxCzOzpnI7_mYQrejR5fx8w>
X-ME-Received: <xmr:dGxvaRSPUthtjWaovyWv9pjjrE3aB0mWKVLe1ItVXOUhdQ5PqESJVUhy>
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
X-ME-Proxy: <xmx:dGxvaYfKNo8QDwLYM9CXeiISh2_oldLP9KNgBPMv_C14CM-1i-LTMw>
    <xmx:dGxvaYlvME6F5NCUZJYEaj9oEaPojavelmjuY8g2-7LJ489XKk0xQA>
    <xmx:dGxvaVhMjOriFRdNi62qvTsp8VlSSPfzz_4B3_23vklb-14ShEa8zg>
    <xmx:dGxvaREoz1sQ_A-5H57v0CBmy4qsl47VgFTj2JbsxHXyWG7Ei8Jxwg>
    <xmx:dGxvacx2qewmct1PBt13iNre5_XJTp0BvOBLUs-Wl3WS5g1zXfe541fl>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Jan 2026 06:52:19 -0500 (EST)
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
Subject: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers over raw pointers
Date: Tue, 20 Jan 2026 19:52:07 +0800
Message-ID: <20260120115207.55318-3-boqun.feng@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260120115207.55318-1-boqun.feng@gmail.com>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
MIME-Version: 1.0
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m+X30Bjk;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2b
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
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBB5WYXXFQMGQE7VP2HRQ];
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
X-Rspamd-Queue-Id: 94ADF47B03
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

In order to synchronize with C or external, atomic operations over raw
pointers, althought previously there is always an `Atomic::from_ptr()`
to provide a `&Atomic<T>`. However it's more convenient to have helpers
that directly perform atomic operations on raw pointers. Hence a few are
added, which are basically a `Atomic::from_ptr().op()` wrapper.

Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
`atomic_store()`, their 32bit C counterparts are `atomic_read()` and
`atomic_set()`, so keep the `atomic_` prefix.

Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
---
 rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
 rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
 2 files changed, 150 insertions(+)

diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
index d49ee45c6eb7..6c46335bdb8c 100644
--- a/rust/kernel/sync/atomic.rs
+++ b/rust/kernel/sync/atomic.rs
@@ -611,3 +611,107 @@ pub fn cmpxchg<Ordering: ordering::Ordering>(
         }
     }
 }
+
+/// Atomic load over raw pointers.
+///
+/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
+/// with C side on synchronizations:
+///
+/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
+/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.
+///
+/// # Safety
+///
+/// - `ptr` is a valid pointer to `T` and aligned to `align_of::<T>()`.
+/// - If there is a concurrent store from kernel (C or Rust), it has to be atomic.
+#[doc(alias("READ_ONCE", "smp_load_acquire"))]
+#[inline(always)]
+pub unsafe fn atomic_load<T: AtomicType, Ordering: ordering::AcquireOrRelaxed>(
+    ptr: *mut T,
+    o: Ordering,
+) -> T
+where
+    T::Repr: AtomicBasicOps,
+{
+    // SAFETY: Per the function safety requirement, `ptr` is valid and aligned to
+    // `align_of::<T>()`, and all concurrent stores from kernel are atomic, hence no data race per
+    // LKMM.
+    unsafe { Atomic::from_ptr(ptr) }.load(o)
+}
+
+/// Atomic store over raw pointers.
+///
+/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
+/// with C side on synchronizations:
+///
+/// - `atomic_store(.., Relaxed)` maps to `WRITE_ONCE()` when using for inter-thread communication.
+/// - `atomic_load(.., Release)` maps to `smp_store_release()`.
+///
+/// # Safety
+///
+/// - `ptr` is a valid pointer to `T` and aligned to `align_of::<T>()`.
+/// - If there is a concurrent access from kernel (C or Rust), it has to be atomic.
+#[doc(alias("WRITE_ONCE", "smp_store_release"))]
+#[inline(always)]
+pub unsafe fn atomic_store<T: AtomicType, Ordering: ordering::ReleaseOrRelaxed>(
+    ptr: *mut T,
+    v: T,
+    o: Ordering,
+) where
+    T::Repr: AtomicBasicOps,
+{
+    // SAFETY: Per the function safety requirement, `ptr` is valid and aligned to
+    // `align_of::<T>()`, and all concurrent accesses from kernel are atomic, hence no data race
+    // per LKMM.
+    unsafe { Atomic::from_ptr(ptr) }.store(v, o);
+}
+
+/// Atomic exchange over raw pointers.
+///
+/// This function provides a short-cut of `Atomic::from_ptr().xchg(..)`, and can be used to work
+/// with C side on synchronizations.
+///
+/// # Safety
+///
+/// - `ptr` is a valid pointer to `T` and aligned to `align_of::<T>()`.
+/// - If there is a concurrent access from kernel (C or Rust), it has to be atomic.
+#[inline(always)]
+pub unsafe fn xchg<T: AtomicType, Ordering: ordering::Ordering>(
+    ptr: *mut T,
+    new: T,
+    o: Ordering,
+) -> T
+where
+    T::Repr: AtomicExchangeOps,
+{
+    // SAFETY: Per the function safety requirement, `ptr` is valid and aligned to
+    // `align_of::<T>()`, and all concurrent accesses from kernel are atomic, hence no data race
+    // per LKMM.
+    unsafe { Atomic::from_ptr(ptr) }.xchg(new, o)
+}
+
+/// Atomic compare and exchange over raw pointers.
+///
+/// This function provides a short-cut of `Atomic::from_ptr().cmpxchg(..)`, and can be used to work
+/// with C side on synchronizations.
+///
+/// # Safety
+///
+/// - `ptr` is a valid pointer to `T` and aligned to `align_of::<T>()`.
+/// - If there is a concurrent access from kernel (C or Rust), it has to be atomic.
+#[doc(alias("try_cmpxchg"))]
+#[inline(always)]
+pub unsafe fn cmpxchg<T: AtomicType, Ordering: ordering::Ordering>(
+    ptr: *mut T,
+    old: T,
+    new: T,
+    o: Ordering,
+) -> Result<T, T>
+where
+    T::Repr: AtomicExchangeOps,
+{
+    // SAFETY: Per the function safety requirement, `ptr` is valid and aligned to
+    // `align_of::<T>()`, and all concurrent accesses from kernel are atomic, hence no data race
+    // per LKMM.
+    unsafe { Atomic::from_ptr(ptr) }.cmpxchg(old, new, o)
+}
diff --git a/rust/kernel/sync/atomic/predefine.rs b/rust/kernel/sync/atomic/predefine.rs
index 5faa2fe2f4b6..11bc67ab70a3 100644
--- a/rust/kernel/sync/atomic/predefine.rs
+++ b/rust/kernel/sync/atomic/predefine.rs
@@ -235,6 +235,14 @@ fn atomic_basic_tests() {
 
             assert_eq!(v, x.load(Relaxed));
         });
+
+        for_each_type!(42 in [i8, i16, i32, i64, u32, u64, isize, usize] |v| {
+            let x = Atomic::new(v);
+            let ptr = x.as_ptr();
+
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            assert_eq!(v, unsafe { atomic_load(ptr, Relaxed) });
+        });
     }
 
     #[test]
@@ -245,6 +253,17 @@ fn atomic_acquire_release_tests() {
             x.store(v, Release);
             assert_eq!(v, x.load(Acquire));
         });
+
+        for_each_type!(42 in [i8, i16, i32, i64, u32, u64, isize, usize] |v| {
+            let x = Atomic::new(0);
+            let ptr = x.as_ptr();
+
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            unsafe { atomic_store(ptr, v, Release) };
+
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            assert_eq!(v, unsafe { atomic_load(ptr, Acquire) });
+        });
     }
 
     #[test]
@@ -258,6 +277,18 @@ fn atomic_xchg_tests() {
             assert_eq!(old, x.xchg(new, Full));
             assert_eq!(new, x.load(Relaxed));
         });
+
+        for_each_type!(42 in [i8, i16, i32, i64, u32, u64, isize, usize] |v| {
+            let x = Atomic::new(v);
+            let ptr = x.as_ptr();
+
+            let old = v;
+            let new = v + 1;
+
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            assert_eq!(old, unsafe { xchg(ptr, new, Full) });
+            assert_eq!(new, x.load(Relaxed));
+        });
     }
 
     #[test]
@@ -273,6 +304,21 @@ fn atomic_cmpxchg_tests() {
             assert_eq!(Ok(old), x.cmpxchg(old, new, Relaxed));
             assert_eq!(new, x.load(Relaxed));
         });
+
+        for_each_type!(42 in [i8, i16, i32, i64, u32, u64, isize, usize] |v| {
+            let x = Atomic::new(v);
+            let ptr = x.as_ptr();
+
+            let old = v;
+            let new = v + 1;
+
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            assert_eq!(Err(old), unsafe { cmpxchg(ptr, new, new, Full) });
+            assert_eq!(old, x.load(Relaxed));
+            // SAFETY: `ptr` is a valid pointer and no concurrent access.
+            assert_eq!(Ok(old), unsafe { cmpxchg(ptr, old, new, Relaxed) });
+            assert_eq!(new, x.load(Relaxed));
+        });
     }
 
     #[test]
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120115207.55318-3-boqun.feng%40gmail.com.
