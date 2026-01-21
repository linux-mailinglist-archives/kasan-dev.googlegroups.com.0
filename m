Return-Path: <kasan-dev+bncBC6LHPWNU4DBB2UXYPFQMGQEH24MXWA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CFp5OOzLcGkOaAAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBB2UXYPFQMGQEH24MXWA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:51:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 759395717F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 13:51:56 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-502a341e108sf129035601cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 04:51:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768999915; cv=pass;
        d=google.com; s=arc-20240605;
        b=jHIEuYMzxv/Vc9v/x+8yUsa30pwuS+zXRnGmcc3VFAucx+pO3aVm2Dk09CtNJ832jc
         6dRXNq7gNHj/iYXne2zsDSdphiONfsQixruz/tpXNeRciPb4BlJXXw3YeKzckjBjFxCs
         5K/KvEhmpZSfGpIbHQrhXymrOXPvMwOzJ0yOV6ibh8unfuXiZTz0L3b9BoDX6KqDQFCr
         5WaVyfVPwi8k+gQn+YDNyyzFOjTSaiClc8fe/Lcwsc6ZdCwc8LY0X2F+rvUSh6dHJPNx
         1oNhaDMRogn5URopLLgdyW9dJ7pXKrNCd4OELX0yEtgSS4kAHywUMj1NQOa7PtDv6o34
         MwDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=6VGCh02CBtoDUzRxPt7s1SZJ/CB2OrSX9DlSxeDvIek=;
        fh=Gcb63C85cS5tO+eCUdxTPN8kBkHbHwbjVBNHDlLKtbE=;
        b=drtQfsIandgUAKJhx8hXbSO1L8CX5GZiocSEKiYe3NmuE5szC+RfJP8xGuxBHqGlhx
         yOCb2BDXrVAIqQNbC9e9NKbwVCI7GoSdZClp8RqVNx4CsrRdN+CvSmjDkMo3LUoDxTpy
         2qbsfr7HYbyBXauDlSD+Ob6c7kN4u59Ai3JgVQXVVS177YFt8l/b+UtBsuodRYndu57J
         IKrmRBq88iLnUyLrSg4ptiX2mqrLJvuy/B7U+kQWKrSDWKsIethK+sROBEPChjMHFPdW
         Wd2PT85BpesVUKWKwIYTEw9k3PnEYmmGpJY2msWEcBhhW7L9Xwz7bvKqrEVMG7cGQPk6
         HPpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YqqSXZvY;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768999915; x=1769604715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6VGCh02CBtoDUzRxPt7s1SZJ/CB2OrSX9DlSxeDvIek=;
        b=VVP4LUaKKHXvktm4pwvFIszSkw9ajbOZO4KfLXwuqwOWEKySXkVjrktfNSfs4OahNm
         tsxYnlhTG9pKnZ4KHRw9Jo3PyZ0SA6WS6jOaXNNrKwn9v7NL+Lm4xgTtcdEkz7WXdUZ9
         zT5fYScbMcUrbZoX4fACzbKckqJ6N6yEMUSNv8tC6TZbQq3zyu/JvYNkIDUCA+a7jCNl
         mGomCWsC7VAIJsBI4NZoi+LGBlYVeUGwPTLW4gXx9CXrwZRoc/a/Lf92LIu0CrD55Tr1
         xFYeRRhO5ZmscYyYhmziAExEsUWrWbelJNXij8Jkf/rdbTTd7F281GqhPr2o7fd/NM3F
         zY/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768999915; x=1769604715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6VGCh02CBtoDUzRxPt7s1SZJ/CB2OrSX9DlSxeDvIek=;
        b=MLuPh83D+GK6MktDULhPqjraBvmGHHaeLkYyBfQEKrBH9BD4ZaVFZ0CE34FfkBYcST
         /AYzhEnd4DiDazwsAhKFZQrYNvdzVxhvm08p0f0gO5G3vOm31FbGLECHovoVOcaHlBls
         omCPtvmV4duu3Yip9bXcK38SB9Fl6i7tygOC7U5TgLgUEemi4r/KofHuv21PxBit4mg7
         xRcDtwDyGejoj0xkFJVdZYn4kC+yKi4FIDTQL/0dF7srDpFHbWOesihQPa789sxB7iLH
         lqWF/pbrea4vfr17YbrKlHkRMk6r9Qw5lB/4VIWCG48bmvEYReVE8cVzs7OxINCq8NtG
         Rh0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768999915; x=1769604715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6VGCh02CBtoDUzRxPt7s1SZJ/CB2OrSX9DlSxeDvIek=;
        b=pgCV1H3Vrhu3yMLSx0ZaAq+0srpMKXriR8Tw61nODk+wib5UcGOMj7wZMzgUYwpCvt
         63bgDO0QXLq2R9IrDxEb+b9rHcpOs5/CCyYf6vwqR36m+gDZzhiLWGcOvFkHErFqYVn5
         l7/qnhxZExLcuOF0/FEkfPVk4RGZPhB61+hRYK7cszyqxlDNI1fvww3Q700xvoyiBsrR
         VgThEk5r2j2plNutJPZ1bmoBUEgX6an2EH24Olbgy+47k54M8RJJXjsli38IVIXQVWtS
         STYDYOB0hqAftwrXw7ERrhyXqS9UzcM2Dq1U2CBeQ9hqltlx7zes+QitoH12tY8oMDTP
         8TlQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX4tHs+DDjOQzLcQhjHCI2EJth+u1DVAyYYH20oFFDMI5QB28TvyNFrPTX/hMFHoiWJJTVY9g==@lfdr.de
X-Gm-Message-State: AOJu0YyA4LkUwPnDztoqLDleJqvn2V9egDI7Ntq5iDfSNgJmburUJx33
	3lxm3G+tvjiX4U74tMPw5WtVd+aKwfm+emXIcKThNIFlA8KkHVMMFMSI
X-Received: by 2002:a05:622a:14cf:b0:4e6:ebcc:23fb with SMTP id d75a77b69052e-502d84f2c62mr70142741cf.36.1768999915138;
        Wed, 21 Jan 2026 04:51:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Haw/Ri549FAsKVC1O8wStN7dcZ4l3nBGZEEw3pD8vt7g=="
Received: by 2002:a05:622a:513:b0:501:4a3e:41ff with SMTP id
 d75a77b69052e-502149f60fels111514251cf.1.-pod-prod-09-us; Wed, 21 Jan 2026
 04:51:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXuC6nqWskhrhJYqSn1aKjIq2JIBZlPEBJla6pZq0u9ZoFrED7S1hKSys2MTP/9xa2UzKto79iIrBA=@googlegroups.com
X-Received: by 2002:a05:620a:690e:b0:85c:bb2:ad8c with SMTP id af79cd13be357-8c6cce514e8mr627079485a.74.1768999914232;
        Wed, 21 Jan 2026 04:51:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768999914; cv=none;
        d=google.com; s=arc-20240605;
        b=lM/80SlC1O28bl65PYRvoaRm5i4h+2u1BPfRX6zKKofK5lw6mnPrzUPqzK1sUj5Ji9
         v+ZN8WPli7L68s5EvLmks7pzwEdpiU396wg3lM4LjhqZ04BfwOYknEff8ZyttnjAXA7w
         yKyDOfTg06wmYcmaIRhpvR+CKupWDZnUhyT+8VnmmPnCQqFaIxs2+oJuYV4+hxuTBDpK
         fY/xZ5Ro3F4zvlnqoKwEd7FBYuLy+YHGb1YaapZgbRae3dC/c3wMZjvvg84JbEJZKltH
         dc7cYHNYGnIf7uzU92W8JZMhZhhPS32SVZVDF56R6USHSTbpkNU4U2LEfw/mo5P+6jrr
         jBOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=Ff1eounqvwFWz5fvkxu9F0ExQjANboKm57xpRsw3Ti0=;
        fh=lmPZh8GBmXx8VG4j3NxNG67J0Pv2d9qvzuJ0NEy8lsI=;
        b=JV0A7usBkrFDUvGHX+K5Tr3/sD4We3eVV5bqDj5NpxJf9YGGLLJagv3553BwG26Sdu
         XRTJhfruLqS/RK+Yx4MjwwDJBKE/4Xeqp3h6fFeVQwZPlRNdwvlHPZrvmxLyFsjvxxM2
         NM9HYF5UyZSsXrlDYKMtlY2zWQxJ8y5CfBRnJJQHGwgF/jI1SlzvCWHkRfQg4rBBigq6
         cqyNuT/4KxHPG3ifbPG4QKVDhd+1xpAm6LQNPnFtoiFr6Lbn73iF9K8azdG5SIYN7PX1
         pn+AwwZD7D69zqAeWuXPvfH623byioK1KbE9+ed5JAgd4EkxW2pE++CX7JRqLUtOJpwF
         srJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YqqSXZvY;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1d45467si5044281cf.1.2026.01.21.04.51.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 04:51:54 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::732 as permitted sender) client-ip=2607:f8b0:4864:20::732;
Received: by mail-qk1-x732.google.com with SMTP id af79cd13be357-8c6d76b9145so41356485a.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 04:51:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW69PF/oWaHIXWYnirYiyFg92ccoost7fPJdPMxNfOmz976d34xMlA4h9brMFrY4YEA2WyM/c5NVoU=@googlegroups.com
X-Gm-Gg: AZuq6aJu6dtHr4jXMsN4jrU8uypmkjM/aKOzeESdJACXFBsMUDxUG9YL/XFJi1maXc8
	lAdamIb/mY+asJObpsZeDq5Kbe2fwhxTlFTooz+AJShFsq6FrGahsGx6WqzG2VwFWc29ZUkyEIX
	mhZzKEDuMQKJ4LfHAL2JCDJhExS1er6dx4ji+ukiUODZwtH523a6sHYucvr3wrFJx4C3dEwygMo
	ov2GaMG7cNkuQV6T2qLlQlCeQhK5lDm5cPSN3xbP4ze54ExTkwqwJVGDJoUirx/8GRywqGZaQ9I
	EdLfqa8ZdvNB+wCPgA8hJviLgYontwFC3+JY8UCfEeZIvZlmlQtpHjumjhgDQBj84Wu7m/exq2f
	A8Blx2XuIHfDgKu4Md2STLmSPJCgBIY46qfkaMC0LVUoO3ficqHLLcMJ3NmfKDNbxbqVia9ZHx6
	nhc9nQkgIGptE2JLqYTwI8BYuZ3abR1UudaCGTKE/e0rEVTubsZVlihut3KAkWQtBfjsMcYHRcC
	rUSxU0HwfTmMik=
X-Received: by 2002:a05:620a:4720:b0:8c5:310d:3b2a with SMTP id af79cd13be357-8c6ccdbeeb5mr646477385a.19.1768999913732;
        Wed, 21 Jan 2026 04:51:53 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-8942e6c9b83sm124581826d6.46.2026.01.21.04.51.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 04:51:53 -0800 (PST)
Received: from phl-compute-06.internal (phl-compute-06.internal [10.202.2.46])
	by mailfauth.phl.internal (Postfix) with ESMTP id E712CF4006A;
	Wed, 21 Jan 2026 07:51:51 -0500 (EST)
Received: from phl-frontend-04 ([10.202.2.163])
  by phl-compute-06.internal (MEProxy); Wed, 21 Jan 2026 07:51:51 -0500
X-ME-Sender: <xms:58twaUGSkaSpbx7JXEZcxEnx57vxUAoduMTdegZwu8a5u5M9Mg5GDQ>
    <xme:58twaSODH4rN0LeVuGC31txCvV3AQMyf8ig2IJvk2hLk-vjtj30YHp05UAGQa1dQS
    OkaXFlxYQ8baIGqrvq8taVpGT6EHGEFNrqf1a-WVwRcwP_f0pryVQ>
X-ME-Received: <xmr:58twaWuQzJC_XwZiqktfROP6_V5V9E36i7JgsETfbmSkp98jrJIAlfDR>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugeeffedvucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpeehudfgudffffetuedtvdehueevledvhfelleeivedtgeeuhfegueevieduffei
    vdenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsoh
    hquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedq
    udejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmh
    gvrdhnrghmvgdpnhgspghrtghpthhtohepvddtpdhmohguvgepshhmthhpohhuthdprhgt
    phhtthhopegvlhhvvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhopegrlhhitggvrh
    ihhhhlsehgohhoghhlvgdrtghomhdprhgtphhtthhopehgrghrhiesghgrrhihghhuohdr
    nhgvthdprhgtphhtthhopehlihhnuhigqdhkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlh
    drohhrghdprhgtphhtthhopehruhhsthdqfhhorhdqlhhinhhugiesvhhgvghrrdhkvghr
    nhgvlhdrohhrghdprhgtphhtthhopehlihhnuhigqdhfshguvghvvghlsehvghgvrhdrkh
    gvrhhnvghlrdhorhhgpdhrtghpthhtohepkhgrshgrnhdquggvvhesghhoohhglhgvghhr
    ohhuphhsrdgtohhmpdhrtghpthhtohepfihilhhlsehkvghrnhgvlhdrohhrghdprhgtph
    htthhopehpvghtvghriiesihhnfhhrrgguvggrugdrohhrgh
X-ME-Proxy: <xmx:58twaXXugDnVSIzPc3Z6tmRgJ0gzc-8kpLQlF6EU4_1T359kNr0AvQ>
    <xmx:58twadSMEqXBgc6u8BpISVpCgFbZnNBK-m9n-slSUZr_BmMMRXyQQQ>
    <xmx:58twaVJYT_K8atwdL48TaGRLXMspI_cX4L6NB3oMz9TS27ghfquNNg>
    <xmx:58twae3_JXhGRQsrMvzx9L3rTqWlzKH6-fDOyUi1yXzfXsRfn6I7KQ>
    <xmx:58twaYJ89IAFyCeo86kIWY9aLZFkQt1cwWFbCBN6iPl_iRTb-RzRxx1k>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 21 Jan 2026 07:51:51 -0500 (EST)
Date: Wed, 21 Jan 2026 20:51:48 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Alice Ryhl <aliceryhl@google.com>, Gary Guo <gary@garyguo.net>,
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, kasan-dev@googlegroups.com,
	Will Deacon <will@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Elle Rhumsaa <elle@weathered-steel.dev>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
Message-ID: <aXDL5NUOH_qr390Q@tardis-2.local>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <aXDEOeqGkDNc-rlT@google.com>
 <CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YqqSXZvY;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::732
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBB2UXYPFQMGQEH24MXWA];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail-qt1-x839.google.com:rdns,mail-qt1-x839.google.com:helo];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[google.com,garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev,gmail.com];
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
X-Rspamd-Queue-Id: 759395717F
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 01:36:04PM +0100, Marco Elver wrote:
[..]
> >
> > > However this will mean that Rust code will have one more ordering than the C
> > > API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.
> >
> > On that point, my suggestion would be to use the standard LKMM naming
> > such as rcu_dereference() or READ_ONCE().

I don't think we should confuse Rust users that `READ_ONCE()` has
dependency orderings but `atomc_load()` doesn't. They are the same on
the aspect. One of the reasons that I don't want to introduce
rcu_dereference() and READ_ONCE() on Rust side is exactly this, they are
the same at LKMM level, so should not be treated differently.

> >
> > I'm told that READ_ONCE() apparently has stronger guarantees than an
> > atomic consume load, but I'm not clear on what they are.
> 
> It's also meant to enforce ordering through control-dependencies, such as:
> 
>    if (READ_ONCE(x)) WRITE_ONCE(y, 1);

Note that it also applies to atomic_read() and atomic_set() as well.

Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDL5NUOH_qr390Q%40tardis-2.local.
