Return-Path: <kasan-dev+bncBC6LHPWNU4DBBOWKYPFQMGQEYGQ5KDY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WHNDIzzlcGk+awAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBBOWKYPFQMGQEYGQ5KDY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:39:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb140.google.com (mail-yx1-xb140.google.com [IPv6:2607:f8b0:4864:20::b140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C60F588C4
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:39:56 +0100 (CET)
Received: by mail-yx1-xb140.google.com with SMTP id 956f58d0204a3-644548b1d9asf8803891d50.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 06:39:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769006395; cv=pass;
        d=google.com; s=arc-20240605;
        b=S1/CQ0ToFeujDGn+a9KSQyG0w2RJg4jX2TcRyBaq561s5uv5tEqrOsbh1ZosBWj0It
         4a6Ki1INk2G3nm+xP4fKozFIPtIPYlFev6BclVplviybt3IcHiaD6AwnZEPaypxXFpt9
         NtrIgbJJdxOPeMY0C3uxhjApKZxzqrV4+X+qkoZPw27kVub5uz+hlR/MnAgGx2V/VowR
         fWDCk02p7u5hwluexxFT9mQUxsVHZM3SZ1/kH+TpX6EpWXUW3FLPd6D9nsTEU0m6avcl
         1yLQl5PmDQ31gg3hldtEgwC4OibvNVPk7MEwK3StXo31iEclJtULG45Z3Uziwf1slqBV
         hwpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=qsRsJS4YNjwEel0KgIslcxM6gDGsb47ns/lfmK5F21w=;
        fh=6+gcohSue+ckUus/nuNmO2fDfW9EdJiTL04PzfZ3ZOU=;
        b=FQxA3Dt5Hsc3iuykVL6Gdi5p+YK9veSCjJeMZjjHV+E/pBgTn4QEuMCijpm8uWI2tS
         5X9xTnEQkhoLCNG0xjQfi79YhyOEZV8VtKSrYVn6sXSnYyOfwsoc5g74rbVbnUgDO29B
         thMR04W+WIgsSx9zntSulnJNvvM+ilY81ccaYzgQzEOv4C/da22vBKoxDOSzlZh1b5ry
         fLaYXbmplcwKSjPd+jFTE+LWtw8QeNlE4UBsf0poU/mckvkodHN2wCeRAOt2zPeEQakH
         vafAkn+NN5tWJMSE4/71N+vKhJoNDDx/i6bO2kYUgdUbapipBZqVXPhmGWWVkbbmkQe2
         Zs/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ALalIbB2;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::1235 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769006395; x=1769611195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qsRsJS4YNjwEel0KgIslcxM6gDGsb47ns/lfmK5F21w=;
        b=ecQ9Kl3O4KXpLy4bCyxhCzVfLEyyheZxoOtOfE6wsu0gxaUu4jReavPXK5bH98ZPn2
         HjLsVY5I/WLXANcVw3N9ef0oAF1zsKtvh0wEbfGRf3oGLzpQ0exoyRQ0pE9feFyCuxvq
         6YbJFVBuQhIcSxyRWd32jvSMfo2R+j2bfLtiGq3tBBf4ahNVNnlComBAA/Y5Ywp/COTj
         0a20mNjiTUGwDKVON54WzKiGOQnAq+GQV2Ccx9gznTcqNVfuZTEypJEcWquHpeo8BrfZ
         L60/bFLjP8JoIlspchHJHSHwjcWj0gv6cVjgGcriGSnsJ/QRUT7tw2E3DQLeza+JFJdU
         d3tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769006395; x=1769611195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qsRsJS4YNjwEel0KgIslcxM6gDGsb47ns/lfmK5F21w=;
        b=hpBwJzzKGTXAoLMrYcV8Iy2MCGOy4G6lAh36pCltR3HoHU3lzhv4EqE0lOeamxgMiO
         e4DQx+/0LbgoNSpp95PsrDDG4aDth2Vv6o/qfIv0s09qIYEjoip9GoVj/CvAnS8S9pYG
         Rw9Owb551EtNZO6z6GPvIqcXUdO56HeOlBNPnGnUJ92DWEx9ouRrRJpH+8jvw3RZZxkH
         YN4TYU5Erd0zK3vdzIJj+biDNjEQTcGnxFHabekR7eDvD2WRN+WwYZ0TrpW4ddAZCPRr
         d3wYO5o2hyXPVZcCq6jLv3verD794ziPWrCu1uD4Bhrqto+TakLi0OUpxOHIN6jKnytG
         ct+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769006395; x=1769611195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qsRsJS4YNjwEel0KgIslcxM6gDGsb47ns/lfmK5F21w=;
        b=MlRFB2e177axr3BV/OBely2Bf4jU6oUyuy3qwrqq2uaDwtzo+iH7Tg/f/8+i5qo4Sb
         H4xPA97HtxhSkTglMmpDykx4zGI/qR8cV7LwnEQgCGOpPZd+NYlHwzXC+IzsZ/7kFYnq
         4l4RJW4RIRM4Zh1Kq2nj2RzjRwiAEctW2nPCD3K6UKLKDDZZFcjVbIN4tvTISWKGxpku
         Rk/5s5bsWMThQnBoxoQz9aHmCQxDmsG92hqtW9J0wmoFV3O0GZWyGXWMEyXeprrN9CBc
         qOjl4+fXIt7XdtzXDvRWTZmqIuVEVKr2F7ziidfZEDIjB/3LsmQiQMfw/EVT+fYBWw/M
         BH0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqxyvMWz0ruXAU0U/hJdtyz8cU7RHYqxeA8tMZ8//xGQhtX9E01fBI52EnPhohEG+580flBg==@lfdr.de
X-Gm-Message-State: AOJu0YxDeIu6KjGmZ9mzdCZsjUIv1vx/QSC8QGidIwzELTOXVPBj8X38
	PeXVaWlAMGOppLmZzfpTi57pUjpV7CUtn9yCurYLYAKKQ0JuVjJQroIl
X-Received: by 2002:a05:690c:60c4:b0:787:badd:4c with SMTP id 00721157ae682-7940a1574acmr99675697b3.27.1769006394394;
        Wed, 21 Jan 2026 06:39:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ej0NecYEX5wkyU5+cDqPqeVkPMPBmRG2kbnZgD9Grxdg=="
Received: by 2002:a53:ce82:0:b0:649:40d6:8cb7 with SMTP id 956f58d0204a3-64940d693fdls1106413d50.1.-pod-prod-08-us;
 Wed, 21 Jan 2026 06:39:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6RVG7+thLd1JtWgBaySlC2amoN3eS4GsBHMBLPp/HYI3yqDxshb+UEhsmmKQh7kJ6Zd5RWKs3hho=@googlegroups.com
X-Received: by 2002:a05:690c:6609:b0:793:db5f:f8fc with SMTP id 00721157ae682-7940a0e3832mr97893787b3.10.1769006392694;
        Wed, 21 Jan 2026 06:39:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769006392; cv=none;
        d=google.com; s=arc-20240605;
        b=AwmBbC4KiGhavaWiHgS6VjQqFobVXxGnh5v8rwi68EtAua4jdKpf7Byyp5/8vrkA5o
         qV1XQiNN0lkka4ZryAs1XYcQT5xGDEvE517jK8aSroHERu3MV3K0xIk5uvXhCztmBl/M
         oFlC4gXnhtgxkYyUUohD2Oh4XDzIh7DKT3XkGSdt62gyiK+oxjt0/6OqwsWqPnJgCW0e
         3xxYtllRKREhGhRxFUbGRSv7ameAhUsEAHEgDq45gtNmvpFGuZ3nfOTZHby1Wve/lkTU
         0WdBuQbI3n0q35JjZlSb3KsNexCeYS7j1Ktff902XAWfQrdL9Opz6h9fkR+D6uHJL1mx
         6r+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=BLcZMH22PMLngVZW1Pr6WIQb6BYdcrFZicgkGSpRFnU=;
        fh=PVZPF5IfgCCTRtSOe0ExlzSrW8EXkMKuIfMKkODkDtU=;
        b=JjKzCNFMzk2gZDuBdT2IFnO7pM+y3Gw5nVsoLUrBuNUV0h/QdqjLOA/7bWXsgaDmHb
         rKeCJp9FKckVjm6aPwP1w5c9AZsHQE7h1mIJtPCxNorXzgmTOIdsRWWgB2SoEIJ9qz9u
         WOHX9idgHylrCGcVIarFoi6mLVqLyNIPQ7er5E+x6uWqOKYFtaiaMnSpd82U+jYnMWJ9
         6ptm4+NVSQpmV7ITXDpiVI5+7wuV2x7hDyV2IAdvTUYGJTidbx6iM5+Qgj0uRWe1dH2Z
         cojNTArxB9lSMTTRFnEMpl0+7ZlTk6stu4J654oOVjrzNzadx0n2YxRmH0NNkgdv0DIN
         mgpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ALalIbB2;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::1235 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1235.google.com (mail-dl1-x1235.google.com. [2607:f8b0:4864:20::1235])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c654122csi6004227b3.0.2026.01.21.06.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 06:39:52 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::1235 as permitted sender) client-ip=2607:f8b0:4864:20::1235;
Received: by mail-dl1-x1235.google.com with SMTP id a92af1059eb24-121a0bcd376so4344389c88.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 06:39:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXvZeRUvmzy+s2P2lBCZLb/NLFGTixCLZrKufMy50yjSujFExd5zyOET+3IlUR2RE1g1yV/RTk18zA=@googlegroups.com
X-Gm-Gg: AZuq6aLEjmxXmhFfwAbhnKlP2cf7RpuaKWGgK4ii/tHzpEb4Ua02W28j48jx1uNJZIH
	8hKUgvEVSVIBACTpXAPN5YvF9YQC+UjPyEVBqU9o2clDGbrPeQYTnSKolxJ2Owxaulo394hvpYK
	k1zwW4llKGmHN3DiQJDrI8wsy6RcDkJEFbMln0ajkf79Io9Sq5rJNbVYXD1NDLxBIOzBdNxHz54
	O5ouidYJTKzA8ZHQDUaQM0CCFLhccoDcFrHnFA0mS6r6UIKK296UVbFSvjvXbTa0m2eeW+eAWPl
	Y0GDb+d9/80TUoD3q/qN1ra7vqz6ZJboinKDYp5xlCP4UlbKZ2Uf9ORCaAxxtMNp4YzO2TaNgzP
	i5ZeXFWfuAH5qk/3Gx0ycNLapTs0DUqvTSR+7VnbNmnl65HrYxN1h088wlMlmsXlujOjVUkboKj
	pfzKaUXTnp6vXSa7jUoo/oUklbCTDJCR6Q2ewIJ0LsgrmsS1+eT6EnqvDGuJS/o2co3lm/hje1R
	d0FQau9SKW9WIw=
X-Received: by 2002:ac8:5a8a:0:b0:502:9abf:a89f with SMTP id d75a77b69052e-502d85074d8mr56654461cf.41.1769000304933;
        Wed, 21 Jan 2026 04:58:24 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-502a1d9f480sm112557811cf.13.2026.01.21.04.58.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 04:58:24 -0800 (PST)
Received: from phl-compute-05.internal (phl-compute-05.internal [10.202.2.45])
	by mailfauth.phl.internal (Postfix) with ESMTP id 9287AF40068;
	Wed, 21 Jan 2026 07:58:23 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-05.internal (MEProxy); Wed, 21 Jan 2026 07:58:23 -0500
X-ME-Sender: <xms:b81waZUXCA5b7_qat5LZqZYJW1NkZrWahIWNw1B9RjoV5gfNEa8DkQ>
    <xme:b81waee_z64k_jmXfpq3dYEMz9KfulJ02ofTqys7ZsWInOcrR750BpxJY9PXWbdtn
    Iqvcu2ueC7hF4T3qzNAxfqGiO67hCJ8vNiyX0udzTXCOj56CF4h>
X-ME-Received: <xmr:b81wad-HHoOir8j-lQk0CLGKoNG0X6zglpvrbgIFjn1BGePx3lYVbVcr>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugeeffeegucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpeeftdevhfevteettdfgffeigfekieetudejgfdukeeihfffheehueevleffkeef
    vdenucffohhmrghinheplhhptgdrvghvvghnthhsnecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgv
    rhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfh
    gvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthho
    pedvtddpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtohepvghlvhgvrhesghhoohhglh
    gvrdgtohhmpdhrtghpthhtohepghgrrhihsehgrghrhihguhhordhnvghtpdhrtghpthht
    oheplhhinhhugidqkhgvrhhnvghlsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpth
    htoheprhhushhtqdhfohhrqdhlihhnuhigsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhr
    tghpthhtoheplhhinhhugidqfhhsuggvvhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrgh
    dprhgtphhtthhopehkrghsrghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdp
    rhgtphhtthhopeifihhllheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepphgvthgvrh
    iisehinhhfrhgruggvrggurdhorhhgpdhrtghpthhtohepmhgrrhhkrdhruhhtlhgrnhgu
    segrrhhmrdgtohhm
X-ME-Proxy: <xmx:b81wadmCqcGj5xTe7itFHc83W1okWdihA5c0cJUg1ni6v3c0mqousA>
    <xmx:b81waWiT25eU8l5WhPNKNLqdLi895cSvJC2kDbHkx_nuWvamYB2oMA>
    <xmx:b81waVYdQFaGJc-eDx6CHOioS55nmBM78Vas1w_LPZO4D_XccSuzbA>
    <xmx:b81waaF6W27Y3C0x1lF0XdDOPxCG-UqTdRcwBdpB7OyWQkBURyQsbg>
    <xmx:b81waSZz55cpaJE_C3npEbNnvh-wgPvRnpertyHamIBoYHwZCFVCI2pV>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 21 Jan 2026 07:58:22 -0500 (EST)
Date: Wed, 21 Jan 2026 20:58:21 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Gary Guo <gary@garyguo.net>, linux-kernel@vger.kernel.org,
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
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
	FUJITA Tomonori <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
Message-ID: <aXDNbbvBfTYJD1kJ@tardis-2.local>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
 <aW_rHVoiMm4ev0e8@tardis-2.local>
 <CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg=Ww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNpb7FE8usAhyZXxrVSTL8J00M4QyPUhKLmPNKfzqg=Ww@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ALalIbB2;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::1235
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBBOWKYPFQMGQEYGQ5KDY];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[19];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	TO_DN_SOME(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[boqunfeng@gmail.com,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[8]
X-Rspamd-Queue-Id: 1C60F588C4
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 01:13:57PM +0100, Marco Elver wrote:
> On Tue, 20 Jan 2026 at 23:29, Boqun Feng <boqun.feng@gmail.com> wrote:
> [..]
> > > > > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> > > > > like memory_order_consume than it is memory_order_relaxed. This has, to
> > > > > the best of my knowledge, not changed; otherwise lots of kernel code
> > > > > would be broken.
> >
> > Our C's atomic_long_read() is the same, that is it's like
> > memory_order_consume instead memory_order_relaxed.
> 
> I see; so it's Rust's Atomic::load(Relaxed) -> atomic_read() ->
> READ_ONCE (for most architectures).
> 
> > > > On the Rust-side documentation we mentioned that `Relaxed` always preserve
> > > > dependency ordering, so yes, it is closer to `consume` in the C11 model.
> > >
> > > Alright, I missed this.
> > > Is this actually enforced, or like the C side's use of "volatile",
> > > relies on luck?
> > >
> >
> > I wouldn't call it luck ;-) but we rely on the same thing that C has:
> > implementing by using READ_ONCE().
> 
> It's the age-old problem of wanting dependently-ordered atomics, but
> no compiler actually providing that. Implementing that via "volatile"
> is unsound, and always has been. But that's nothing new.
> 
> [...]
> > > > I think this is a longstanding debate on whether we should actually depend on
> > > > dependency ordering or just upgrade everything needs it to acquire. But this
> > > > isn't really specific to Rust, and whatever is decided is global to the full
> > > > LKMM.
> > >
> > > Indeed, but the implementation on the C vs. Rust side differ
> > > substantially, so assuming it'll work on the Rust side just because
> > > "volatile" works more or less on the C side is a leap I wouldn't want
> > > to take in my codebase.
> > >
> >
> > Which part of the implementation is different between C and Rust? We
> > implement all Relaxed atomics in Rust the same way as C: using C's
> > READ_ONCE() and WRITE_ONCE().
> 
> I should clarify: Even if the source of the load is "volatile"
> (through atomic_read() FFI) and carries through to Rust code, the
> compilers, despite sharing LLVM as the code generator, are different
> enough that making the assumption just because it works on the C side,
> it'll also work on the Rust side, appears to be a stretch for me. Gary
> claimed that Rust is more conservative -- in the absence of any
> guarantees, being able to quantify the problem would be nice though.
> 

I don't disagree and share the similar concern as you do.

> [..]
> > > However, given "Relaxed" for the Rust side is already defined to
> > > "carry dependencies" then in isolation my original comment is moot and
> > > does not apply to this particular patch. At face value the promised
> > > semantics are ok, but the implementation (just like "volatile" for C)
> > > probably are not. But that appears to be beyond this patch, so feel
> >
> > Implementation-wise, READ_ONCE() is used the same as C for
> > atomic_read(), so Rust and C are on the same boat.
> 
> That's fair enough.
> 
> Longer term, I understand the need for claiming "it's all fine", but
> IMHO none of this is fine until compilers (both for C and Rust)
> promise the semantics that the LKMM wants. Nothing new per-se, the
> only new thing here that makes me anxious is that we do not understand
> the real impact of this lack of guarantee on Linux Rust code (the C
> side remains unclear, too, but has a lot more flight miles). Perhaps
> the work originally investigating broken dependency ordering in Clang,
> could be used to do a study on Rust in the kernel, too.

You mean this:

	https://lpc.events/event/16/contributions/1174/

? If so, that'll be great! I believe if we could learn about how Rust
compiler can mess up with dependency ordering, it'll be a very helpful
resource to understand how we can work with Rust compiler to resolve it
in a pratical way.

I believe that work was LLVM-based, so it should apply to Rust code as
well, except that we may need to figure out what optmization the Rust
front end would do at MIR -> LLVM IR time that could affect dependency
orderings.

Regards,
Boqun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDNbbvBfTYJD1kJ%40tardis-2.local.
