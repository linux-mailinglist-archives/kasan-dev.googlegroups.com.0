Return-Path: <kasan-dev+bncBC6LHPWNU4DBBMUOX3FQMGQEV42AGNY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EFJfKumvb2nMKgAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBBMUOX3FQMGQEV42AGNY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:40:09 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E72047C4E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:40:09 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-88a2cc5b548sf404596d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:40:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768927208; cv=pass;
        d=google.com; s=arc-20240605;
        b=bngTb86H3cYqYecOKcKQtZzw5PjLDX6dVl0X2YmBIzBwGMT4Hy+GI4Zey9XKEJf8wT
         ZH0Bu8bfxoKngPfmujMyUW1OqiDIU2ZdugY3UKFvc5OY7xCAu+KOXgMDWGYdM19A+s0J
         wZNsWOv5Sq+ff7ZQjZzbh4Gs/Ih6pFvutGejqJYy9/YLOVDAVwv4pG6lHJjNV3eqsZ84
         7/iRnpzDcbbPC8EW0ACu7HvlEasvrvJZUaEiJVIXylWmt5gkmDNYpojSYHZ+hNnYbg0+
         RYQkuyLF+J3ZsN3aeIaKkamEumEgi8XRCJg6mxBRCcMXaRKxyQ1xZxLosGkSJGeHU333
         8Mrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=Esj90gUNnMd/Z/QvdKUY6layY2A0L8HVaNWlwx9Q0Hc=;
        fh=/d5lahXpZFPC0hjJZzEx1Gg2sbvn1AGTdGSmpGs9ZXo=;
        b=CiS+OZfFUW9++vLI2SZMzsk+RPgm43VMtFT5DMI3rFF7FzXgz9M5wbj7CLdNKlV50p
         v7C/rKzVLs22JZhbOdjwm5YVrjlciPELQfdpjlmskK/xviT4c4q6Y9cuPEznwH3chlHl
         w5GP9hKWD5p7KKTSxQGN0OCLbcI2VaVqhxpV63bfh0Kt50pPFcWHKRxBPTBYk1EnxBSD
         xuXpA3+FOMU9/IKog0HPtY26nd0t2jqq0n5TtvULCs14UK6lGa/r9qooA5Xy3WBjMPZQ
         Lss8c96sp0Mh6HBRx6Rxn9uxWr2qWWkiPI4cz2HJnVLALlMj+sOTPmdtoZ4RuyvzMhjr
         34uA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LzacXXhf;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768927208; x=1769532008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Esj90gUNnMd/Z/QvdKUY6layY2A0L8HVaNWlwx9Q0Hc=;
        b=ECWa9VptUJG/L8eSfdDFoHWBwnYBrv9ZILsx7dCq090eaoYXIPJNL78Q66OHR0Xp7v
         ITmVsjv3PgYGm10GND5UqPMswiLsFDJAAdKsq7go2al027YLptgEUBilBS+5FNc/80OZ
         +xcZr3DH3Sp+uVztN/EpisbBfsYAc1UddKw77NicT20yJzwybWEiIZgyH/PDbGWryVCD
         K1+tq5AqQ6MwPpC+grx98HZBJdX8SSDymY9DkrqiKSA+NG1uiYIkACadgG1/Mb9z9rdR
         BybKgvPhI7Q1uneQoXmX6iC87I2SqhU2ktzcxeEDp+8ruZOz9pjN4eEijEo9a5TedI5I
         dZLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768927208; x=1769532008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Esj90gUNnMd/Z/QvdKUY6layY2A0L8HVaNWlwx9Q0Hc=;
        b=PWbbUFcmmr3e9tAOzZ2SofxFWD87jkH8NQ/1oykedeGG8RthiJydcsdgsxqSb8nWXn
         DiNC1Sl+wXLhGyPlzSBnG2CXfO3cegSuDUkk2Rj84iqPUWPdamYe1aR3/GaA2vplFwj8
         KYZERBi7/52R8qRza8uW02P6snM67SAQ/zOw31S2B/7x2aN4O7XAE0LLX7vHwe9QwSXi
         PY6+j1nPFC+VgP8xOUzVXUm329kCoNoF5dc4DtD5N446bwGfxYIkAMn28uqPwOwPHoRw
         MJqc+XGZxTs+o/qNbOBlghLqyxmp5dhU7CUOu3bU84tLB6wEOENeqWQhSehhCNMNF3aq
         N6iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768927208; x=1769532008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Esj90gUNnMd/Z/QvdKUY6layY2A0L8HVaNWlwx9Q0Hc=;
        b=U+9E2WR5jQya2rI3h/pDPX9AJkDkMOuGyFCV1ZtzD4GCCRk9d5sNcgeRMNsCU4LM9c
         ncrkGIw+HeSplrX6/1LFZSI1dntzn2NARGJQAHJPDZEm8OIRVEOG8UGwIHOi3BH+2fPj
         Xwuhi2dpNAa87ky9MQ2bDByQg0W408kP9SHIxhqRXTjEtwXiSYRrzmswRxhHbuuEC8Ho
         r43r1bfBWWicpTb11lB0FZUVD/u4pv7xZPqqWcTMiaDNCuUQyf9dsMeH9z4THC4MbMlT
         4VIqrlEZrXXtpWSmjU3g9uwzDm7ryhNgng9vl5D6FSG1bMjXCw9OZtsZMz9eT6hctrLG
         joWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWk7ib4D7ptk35uDOKH73oBMRD18yaFnIecUT7sdR8yTCxzuMrmgrpnrGcTD1XyBBaHZpHGjA==@lfdr.de
X-Gm-Message-State: AOJu0Yzi6hLveGqkT3dfteIB/cZBcaTcQHYJQNrpd+P3jSaYVifP2BK/
	emCRUOS54eqQJlPFrtZazinRX1dh7DQG1FvBndfbZIAtHgGE0seMKqvD
X-Received: by 2002:ac8:5e49:0:b0:501:43fa:92b0 with SMTP id d75a77b69052e-502a165245fmr221270861cf.36.1768916787149;
        Tue, 20 Jan 2026 05:46:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GJKA3NqkDPeZtPLbkd+tPjqtjOv68IL6OjPQR4U3VOgA=="
Received: by 2002:ac8:7d11:0:b0:4cb:6555:7da8 with SMTP id d75a77b69052e-502149f207bls65035661cf.1.-pod-prod-00-us;
 Tue, 20 Jan 2026 05:46:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWn8nbWLob46GogTg2OnA+6638MRHZmg+DJe//Q1kqRqByKPpTurI8sv2KCo/+A9NC6IOyeeaDfniI=@googlegroups.com
X-Received: by 2002:ac8:5a55:0:b0:4f7:a06d:c4df with SMTP id d75a77b69052e-5019f9021bdmr280280741cf.33.1768916786174;
        Tue, 20 Jan 2026 05:46:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768916786; cv=none;
        d=google.com; s=arc-20240605;
        b=PLZhiKSGrx4tzJ+4LQ7RyKAm3t/6QYyFPXU1WdX/8PviVraoy7xqMz5mkYG/vSHdb5
         aqU7TrcmhMh4ZSpEd+F12YnoC16bSPtaiAlG+ewedS6M8HzQgwJiD41F/RyQ9QQK9FHy
         CdKRkzMF7Fij1TbHFKFCvDDFdpnoTD5dfyqkcBx4BYJ5M2NUG7KgIoY8XJgw9bI6JT5A
         blCcyV2BF7BfKvU/d/uDRE1vNWgD5bsVBZFBSaKo8LBYy8Oj5gQuKPieXUMPpyYid/lG
         ekgkD6BMzkclDKlzmojBAE7NnsS+YGRcOnOv9RM5W+sUeMebbyySXjoHhoXPOVyWhaTo
         t3bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=spiJEUz7YrJ9p2nUXIqRGXS2HMPY7smmsApThddibpI=;
        fh=tNkEhBHiVKw/Qp+fSmlXcV4d9QP9p2W3N7yHyGSy5IU=;
        b=KvSBgbfnec3bBVxD50skL701RPnFg8IvLl2AGTPgu06fgPx5vRHiDBTUY/7nscFPOF
         fxvuJOHNF2qLRRitW8rKmu29z5KSg+tjus9nSvM32RPDNqQCzKabWhsW6a1ukbU/Of8Y
         2Q2Dp3BniGCi6YjJWzvvuIKBwRDfma3SGuPHvM56iCDj+weDzzpozHwySGN5jrQuHBvX
         nkdR1YfuPSiBArbiehx46NzT0H1moHmbTpmk43Pip0ISZg2vKDOLwCiGwguKu6G4Jhh3
         Z9HdHZ/0xkMHbvX4sJoeUxN5aVQ5zb+oXGQ2HpMLCwsh2rCbFijE7hoWCMJSkMQj6/GM
         DrAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LzacXXhf;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1e340acsi3905801cf.3.2026.01.20.05.46.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 05:46:26 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-88a37cb5afdso88444916d6.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 05:46:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV1KBKAeLO67hHhhhsFhDQ1LUR74VW6FxF6tV9wBnEIiPjfw8uyEHN/EVn4SQi34tUGoYBAMXFXLIc=@googlegroups.com
X-Gm-Gg: AZuq6aKNy5AoqckhoXylmjutcrVlrwLjvBD/1t7v9ljdwS+GIYeLIL3nzW6MNynfGif
	vrvUo9uacdPZbJlMeAkEBLaawqH/RhmF+8vc68ieDcfYyY8fHyOYwablOMtalyfejA161ED+4Bl
	QClh+4oaRew+ekjHGDodDHj+rmruYHkYbI+MAzBYfeSgUZkjBnoC3ztqrVVLkgVek0TmiaUFns1
	DRfUBtcsZA4UmeHCNvBe74IazVFa3tODLpMjP7jHmHmiyNwUVTGFklB1kYETmZrxTLnWEiNeqOw
	TW1l4UWaMPoHWtwnWV2LjT40DrgcK5iqKFIfZ7ZmYHlhU3wr6LTPeAKStyYl0AymY0rH+HtRY4H
	xwSXGJWbNqT0zo0rCyQAfzt8YMcd2gzw82fZg0uPtp0VAwN7U+UtOjzDvM6FWQiKp7RTSLoMvGk
	KDJKOsLQxvX7VMFLi4xh4iLUj0ICxR7F5n05It69e+Ee6pzWaDAM6SoXe/9QETuzSZc/9Rl6S8V
	/fiiTj5MSCzNMI=
X-Received: by 2002:a05:6214:212b:b0:888:6fde:7b72 with SMTP id 6a1803df08f44-8942d7e0460mr207178096d6.32.1768916785693;
        Tue, 20 Jan 2026 05:46:25 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-502a1dc88afsm92873801cf.15.2026.01.20.05.46.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 05:46:25 -0800 (PST)
Received: from phl-compute-07.internal (phl-compute-07.internal [10.202.2.47])
	by mailfauth.phl.internal (Postfix) with ESMTP id 21AB8F40068;
	Tue, 20 Jan 2026 08:46:24 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-07.internal (MEProxy); Tue, 20 Jan 2026 08:46:24 -0500
X-ME-Sender: <xms:MIdvaQkDpiNERS6ZDD4RFZudbe96RkXEG5Wn29PLm557bOa1XWPz7Q>
    <xme:MIdvaUs4h2u9Z_7MEcSZmC9VEDBsHBBSVfuke7zpWKDLeq2-kmXOu_jvLDXnYNngJ
    ZVx5Xi0f2bxZMXo13vO7uoQOQSRGweEao2rUSvdf8-MekJKAqvVUQ>
X-ME-Received: <xmr:MIdvaXOilmeqLVnK2rp1aK1365CAufvcBz90iScfNGoXpVwIf8AbSLKw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugedtheejucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpeehudfgudffffetuedtvdehueevledvhfelleeivedtgeeuhfegueevieduffei
    vdenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvgdpnhgspghrtghpthhtohepvddtpdhmohguvgepshhmthhpohhuthdprhgt
    phhtthhopehgrghrhiesghgrrhihghhuohdrnhgvthdprhgtphhtthhopehlihhnuhigqd
    hkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehruhhsthdq
    fhhorhdqlhhinhhugiesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehlih
    hnuhigqdhfshguvghvvghlsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtohep
    khgrshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgtohhmpdhrtghpthhtohepfi
    hilhhlsehkvghrnhgvlhdrohhrghdprhgtphhtthhopehpvghtvghriiesihhnfhhrrggu
    vggrugdrohhrghdprhgtphhtthhopehmrghrkhdrrhhuthhlrghnugesrghrmhdrtghomh
    dprhgtphhtthhopehojhgvuggrsehkvghrnhgvlhdrohhrgh
X-ME-Proxy: <xmx:MIdvad3LHcnIdXmOV485ryfI6aeyEO2Pzol-W2-6wgJ_YlykIMl9qQ>
    <xmx:MIdvaRxCqAWXdtgPRWYk4pYYoJos9kf-wSqMqFhp-sScDFFni8Dcgg>
    <xmx:MIdvafo3TCGCaN943c9JFJ-cMLXIAQBZwRgtqq8vV5VKtE0TJOTmNg>
    <xmx:MIdvaXUqoonHROVQUjoZfnTP7G7HI-oq0KcLQwRzB9By4gcaXHI1Gg>
    <xmx:MIdvaWrIaKYHWyMx29-tty7pCsEXlwWAsFfCNpiW_4uCGvfWyHKHnzgJ>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Jan 2026 08:46:23 -0500 (EST)
Date: Tue, 20 Jan 2026 21:46:21 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Gary Guo <gary@garyguo.net>
Cc: linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Elle Rhumsaa <elle@weathered-steel.dev>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
Message-ID: <aW-HLUWC3C9HZIGX@tardis-2.local>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <DFTG8D7VQNUR.2VK3OZ0R92MEV@garyguo.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <DFTG8D7VQNUR.2VK3OZ0R92MEV@garyguo.net>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LzacXXhf;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2a
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBBMUOX3FQMGQEV42AGNY];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,garyguo.net:email,tardis-2.local:mid,mail-qv1-xf39.google.com:rdns,mail-qv1-xf39.google.com:helo];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[boqunfeng@gmail.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MISSING_XM_UA(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[8]
X-Rspamd-Queue-Id: 2E72047C4E
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 01:25:58PM +0000, Gary Guo wrote:
> On Tue Jan 20, 2026 at 11:52 AM GMT, Boqun Feng wrote:
> > In order to synchronize with C or external, atomic operations over raw
> 
> The sentence feels incomplete. Maybe "external memory"? Also "atomic operations
> over raw pointers" isn't a full setence.
> 

Ah, my bad, should be "atomic operations over raw pointers are needed",

> > pointers, althought previously there is always an `Atomic::from_ptr()`
> 
> You mean "already an"?
> 

To me, it's kinda similar, but let's use "already"

> > to provide a `&Atomic<T>`. However it's more convenient to have helpers
> > that directly perform atomic operations on raw pointers. Hence a few are
> > added, which are basically a `Atomic::from_ptr().op()` wrapper.
> >
> > Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
> > conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
> > named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
> > `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
> > `atomic_set()`, so keep the `atomic_` prefix.
> 
> I still have reservation on if this is actually needed. Directly reading from C
> should be rare enough that `Atomic::from_ptr().op()` isn't a big issue. To me,
> `Atomic::from_ptr` has the meaning of "we know this is a field that needs atomic
> access, but bindgen can't directly generate a `Atomic<T>`", and it will
> encourage one to check if this is actually true, while `atomic_op` doesn't feel
> the same.
> 

These are valid points, but personally I feel it's hard to prevent
people to add these themselves ;)

> That said, if it's decided that this is indeed needed, then
> 
> Reviewed-by: Gary Guo <gary@garyguo.net>
> 

Thank you.

> with the grammar in the commit message fixed.
> 

The new commit log now:

In order to synchronize with C or external memory, atomic operations
over raw pointers are need. Although there is already an
`Atomic::from_ptr()` to provide a `&Atomic<T>`, it's more convenient to
have helpers that directly perform atomic operations on raw pointers.
Hence a few are added, which are basically an `Atomic::from_ptr().op()`
wrapper.

Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` have a
conflict naming to 32bit C atomic xchg/cmpxchg, hence the helpers are
just named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
`atomic_store()`, their 32bit C counterparts are `atomic_read()` and
`atomic_set()`, so keep the `atomic_` prefix.


Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW-HLUWC3C9HZIGX%40tardis-2.local.
