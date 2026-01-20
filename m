Return-Path: <kasan-dev+bncBC6LHPWNU4DBBYUDYDFQMGQE7NVI42A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MK04A+UBcGmUUgAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBBYUDYDFQMGQE7NVI42A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 23:29:57 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 805334CFB4
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 23:29:56 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-8946f51b8c8sf10540486d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 14:29:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768948195; cv=pass;
        d=google.com; s=arc-20240605;
        b=G5m2UMoIBRQWn0iC4a3H/dQ+KVLWaYXnImHmPG3dDKgdMe38BGw/xs1DPg5o8Jwu2M
         NgIvmVqXMWaIuYaqwmx9gaVO/FMybdA4vDqWaA+l0UzCdkeubd6FSx9B4+X2bQpTLL6K
         55jPyE9A35lRWoF6kFR1S8h6Z7CD7oEYcOPhDd3TbMu8MxyaUWBrn2hvem/Im+BhvMPx
         4Loti5rwPW8I63/QKJUUlM1yi073QPfoWoV29+13JRAkKNNtUMQn9wpJnFbY5rkXnNIC
         zNMZgpHkYxPtTI2np4b0S7HYBiBQFUX781XW3aekVo71hzx/y/59hy7Brt7ChjwGMxJt
         5fuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=CdHQu6QIxtXw/KTMIibj2POrEybfA2ajfZ6gVlW7ZyA=;
        fh=29NVw7q4t9DQiwdCEEZer1G9Q6uwgnmZpWiQAlEeg2c=;
        b=ZzynPhxkaCplsZyA+ML8xshxLw4erfHYua5RChkaoOFDd3T88Z9dQUz9FPLVAUieju
         aLxBqH0RBhqCrnTgmKt1svPs0riHpSABjR3AY8Tjiio9TnmkpcF72fDLNwPtOVGnVMaO
         4HNdcgN46j1I35Dhn6JarCwV45TkEMkQNFJPQ0e7zVMkhmPt3Lu35Kk+FrO7+PMXx44x
         J3d5+jDVFUUU0pUu5mQBewPeqx1xfT1F9/ezWY/m+08y3+sUk9QZx8VYFREFiwVzcDEI
         6nlpKjYn9svtQJ0jOJ1ghMTsMfqrFcMLfOX8aAHdNxjxgSodJ0GMRFMH9Nd7Zt02VFap
         I4tA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CcnAKTG4;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768948195; x=1769552995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CdHQu6QIxtXw/KTMIibj2POrEybfA2ajfZ6gVlW7ZyA=;
        b=q4Z/2aSZZWR4GGoAlpckwtUIMEMYfNi/ANNBKS9XJu5ZBcwn3H8IWJaARcgytxWTuk
         zATHEBUFOivsdQ406ua9AA7hvKZA3nkmzJu/vAnBPWiV7ONz/5v8OhYNsdslpXQexQvu
         sVjhEjsO6sAK7UZDXOohw1EjpU3meZq9C7DTCC2mNdVepD66yOJRdnUQPz7OfSXAjmOn
         HdlPQQcQdigxiomi1F7m/5ebZIhfQP5qEFyzRQctfyPOWKn39a8/dKujw5vklCqjAJuf
         nhpZY1q0TGU5c+f4z2sXJkeX+oG1+HxSf9wEHR/6TJ4TBiKAEhBsNyY2BRoxZc2TXGp9
         zrjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768948195; x=1769552995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CdHQu6QIxtXw/KTMIibj2POrEybfA2ajfZ6gVlW7ZyA=;
        b=E2DGpMSwUT3LjVW3FjuDdXf842XiKSE7kd9Uc0C+I2vsUvnSIhMLgzw7uC46iyI+s4
         KK9pbKDYXTUrEkRE0aR0SnyD/UvUJzSZtAse/d8mrQQgb7l+bi32Bc9N+WY3QJvbqp4p
         nUODexm0FYjgJITa79iNKYfXEiBqQJmcmceYDqXZ368sfsbXFp0GTfWwYxzC+gwAQqBw
         vj+26uWIJ3PbwHV4d1wB4WXaJUMWq8RAYz9j4c8UQZScFhXOeABDXJzgJFoN0ughokAF
         1/m4BhqVwhBYQfrsZcNm66dlyQzNHYiNUjDUGdY14wiXc4OLLelBUhC2Gq4cO/nDtfhr
         NfYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768948195; x=1769552995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CdHQu6QIxtXw/KTMIibj2POrEybfA2ajfZ6gVlW7ZyA=;
        b=HbrTmRf6xCJp24GYyfIM6fGEiPh3mjaQmZjBfA1cXsjDDfQpjv2ChpdqLAsvn08SFZ
         qnGBcmo5vkr571KoKTkKN0NOo/v9/Q6ESMebcR8jB2hn5kpUBpmFvteM/yaV6xP3WaaM
         BDlJGrQxdqNcVpDfz5MyJ45yFg4Qjx2zUsCNoX6Tg6vfxqcev5jw/WoWgJW2VVpQSKWB
         l3AXGii0/2gsZclJCEIzCShnok8TZ3Dfpjk6oHmp42v9Nfu7fRXpvJsedKEtdbUo3edN
         Au8/sxB/R67pnHw88vSHXZ9jok6o8iZnMXDy3SHWH7bOw0Wx8iQQ7nrRXsbunfF9tt+q
         qidw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVe/h7zIQf6iiSUlsBCGZH4cZXVVlX9GM8nIbT7EPljqcDm3ESsic6guHJCyz9koEyxQyxIMA==@lfdr.de
X-Gm-Message-State: AOJu0YzpKV1ylHH57KIVUkjsHjvQNSIZhx7L2CFMR/Z/gNE/4rS03US1
	Xe8TRPcT7iiZsFJwSy1ziBoir9NSAxRP+rpz0eSV0hsZejeh/TZq8qDr
X-Received: by 2002:a05:6214:c8b:b0:87c:2900:1f97 with SMTP id 6a1803df08f44-8942e531c13mr233173836d6.44.1768948195081;
        Tue, 20 Jan 2026 14:29:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H8YQpfYqOanCVkKwrdEMBEjfUpBx7rDMtGSHP2i7WqxQ=="
Received: by 2002:a05:6214:e43:b0:882:4764:faad with SMTP id
 6a1803df08f44-894221ce34cls116623756d6.0.-pod-prod-06-us; Tue, 20 Jan 2026
 14:29:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX52HOZGopDC4d5WdKPy4jO5/YFWP8NNQkks+0T0jkVTYX1fTq66MQ3aLGK/u8B2ugXpCniHghiF/k=@googlegroups.com
X-Received: by 2002:a05:6122:c85:b0:54a:721a:e4db with SMTP id 71dfb90a1353d-563b72bf270mr5014994e0c.3.1768948194210;
        Tue, 20 Jan 2026 14:29:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768948194; cv=none;
        d=google.com; s=arc-20240605;
        b=hnBZDvHS0850Z33T9oFkoOlN3/J9CjiiJVftG7opjaygs7vK//o3JRJgItuQLDg6TZ
         GgcI4oieI0osQLU17A8b4xHU1VdBGL16qJ1tilOb1KMNPq11/+JFZ+oPvGH6WVSYQl8B
         hAy5qU23vyh5zbYWh/AQSXRAyWRKkVGEX9KnzHAJ4r0A9tk/kHZQbQlPbBn4cpUfXowP
         mdw1/e4MJSu+0kRqQqph7MOMmOXqB704tFmsWHxK6AOHLx4sA8ogFs5rTqt4rXtwhO4A
         EOUR9p3iNlo14yBPFCNk2V0aJ5x9OSfJkbivTknvqXNeHtEvsTVS2wo0G5MbRrc51Vuf
         wWKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=qi2aIzmcDbNCw7y614MiDKvrAh6Yp1kcr0zXJQZmRWc=;
        fh=0eo1uNgLVoVklbcNxRgduIaC++ynYZ3Y1IO9xpnyCV0=;
        b=Jio4rLtCzT9OosmVhGqC9KMhtVbYWK/n0UQU3FBOp5tuhblBJh2Kxnseobobpt02n1
         VRxkfSmQ4QuTplkJuHsNtx38rS57AoKI/nSPzGU7mBFiPtkhk1G+lBGH0AlVDNhuPYCd
         yMMtf0X5gucB2q+XoMXFm7OcMcCgDAJzDDIDzeO5Dsw9THnbsyxn+4Vti0bORFEd+4Ab
         BGzfH18VZ1QS8BsCLVAY2yrxMCca5Bnywq9Sk3X1l7hfOPGJCqB4/OWJ9u/HQL4HW8Y4
         YVfUtXCnF7swlZ/OqeOhpg8SgfYjGRueM4AvWtMHKi6uryQp4JNJ4xdbzpoX+KXtD7wD
         ga7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CcnAKTG4;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-564bbfbe416si266279e0c.0.2026.01.20.14.29.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 14:29:54 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-81e9d0cd082so4581810b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 14:29:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVgxePEB0sDnFX3Qu7IOt2xqGtpC1ZW3K4QwulZ57fDmN7uJYkKCuB2xwOPtXWI2+G0Je00Mrne2Ho=@googlegroups.com
X-Gm-Gg: AY/fxX7gdDYb2g4Mey+vg3vpUqrsxRaeGGaH4MDptkCnm5OXrYIc6qUTq4/0NpZpRNq
	dD6MPCDduJYAWwCgg/3zIgO+M7uF8IoNZZlZmbHzbEii4a/m+SMqrmCMLS/gycAgCOzZOKgnPvz
	YnKvi5CUv3KGWeimeoCydil+fNO+gBMlBCjGJbBlCqObsGuV8KK6FefuGBQo1c1ES1YxtpGUQCa
	enDVz6LsHBAOLY5KHV6FFI3s4LfhXLAHS41a1xKJQ9tH9ui/gV2+wgngx/yqneJHslz9S56LFnN
	IJNixAMU7nye4QbJn2IQz6wSWjOBB9KRobo7Hs2uiR823Sgxw12Xeba1vZ3i93D1CiHQP+/4Yuj
	roU1vm1hxsiUQw1gH/qgOKkYwAxnGertLfj6Hvi+0brAq/9f38RwUv7+YuuFXeMrSJdiM8Bu8yJ
	TF2LCxNzbzBlp1rG/MThuofaoAPbt0g2JJWCGVVTQXfUPaMDNFCkTp4VVIS6el4zmo6RFgwTXlP
	mHrM+4XzUX3lbM=
X-Received: by 2002:a05:6214:ccc:b0:888:8913:89af with SMTP id 6a1803df08f44-8942e45d08emr223107256d6.15.1768942369869;
        Tue, 20 Jan 2026 12:52:49 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-8942e6c6610sm112900286d6.40.2026.01.20.12.52.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 12:52:49 -0800 (PST)
Received: from phl-compute-05.internal (phl-compute-05.internal [10.202.2.45])
	by mailfauth.phl.internal (Postfix) with ESMTP id E41E5F40068;
	Tue, 20 Jan 2026 15:52:47 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-05.internal (MEProxy); Tue, 20 Jan 2026 15:52:47 -0500
X-ME-Sender: <xms:H-tvaX1kojIonb-EVRFpy3nglRT3m4AeyFq7gIGsjhlxAtE3Glai1g>
    <xme:H-tvaa_uevsm1j_nA4NTrtwklcrJfcdM4U0q6A4GEV260X5EjBnwaltr4cbZMvGn6
    KjzbhVqDrWzmPLPK60YegDkEA-bX_UG4FRaExVHfUbCwIJ6YbElIQ>
X-ME-Received: <xmr:H-tvaQcjaYTt02Yr6xj4KoQlgTn24zVa3RbwW5LW2HZzf9Kn0JJzuuiT>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugedugedvucetufdoteggodetrf
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
X-ME-Proxy: <xmx:H-tvaeGCsw5xjDM64D8SjYhhnldkREtAoHHk6fltcQp4MrUla1gBfw>
    <xmx:H-tvadDGhFi5HIGAu0qJl6c5giOIok1DS4KJaLxc8GXWSUoaLq7W9Q>
    <xmx:H-tvaZ5wWvabU4cN2ouWL4rRJ2lISLHhEX-o5ZFM64zCTWHORNKLwg>
    <xmx:H-tvaUmgw3ZWtOfh6dkJaodk5OiAevILKQNizkbEcsqYM6MmybKYTw>
    <xmx:H-tvaa5r9CTMjCLfZ_XDQgRhgYTbFp-IzPCnUePD-4VcLlCTbe87NB3X>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Jan 2026 15:52:47 -0500 (EST)
Date: Wed, 21 Jan 2026 04:52:45 +0800
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
Message-ID: <aW_rHVoiMm4ev0e8@tardis-2.local>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CcnAKTG4;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::42b
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
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBBYUDYDFQMGQE7NVI42A];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[lpc.events:url,garyguo.net:email,googlegroups.com:email,googlegroups.com:dkim,tardis-2.local:mid];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[19];
	FREEMAIL_CC(0.00)[garyguo.net,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
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
X-Rspamd-Queue-Id: 805334CFB4
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue, Jan 20, 2026 at 06:10:40PM +0100, Marco Elver wrote:
> On Tue, 20 Jan 2026 at 17:47, Gary Guo <gary@garyguo.net> wrote:
> >
[...]
> > >> +
> > >> +/// Atomic load over raw pointers.
> > >> +///
> > >> +/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
> > >> +/// with C side on synchronizations:
> > >> +///
> > >> +/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
> > >> +/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.
> > >
> > > I'm late to the party and may have missed some discussion, but it might

Thanks for bringing this up ;-)

> > > want restating in the documentation and/or commit log:
> > >
> > > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> > > like memory_order_consume than it is memory_order_relaxed. This has, to
> > > the best of my knowledge, not changed; otherwise lots of kernel code
> > > would be broken.

Our C's atomic_long_read() is the same, that is it's like
memory_order_consume instead memory_order_relaxed.

> >
> > On the Rust-side documentation we mentioned that `Relaxed` always preserve
> > dependency ordering, so yes, it is closer to `consume` in the C11 model.
> 
> Alright, I missed this.
> Is this actually enforced, or like the C side's use of "volatile",
> relies on luck?
> 

I wouldn't call it luck ;-) but we rely on the same thing that C has:
implementing by using READ_ONCE().

> > > It is known to be brittle [1]. So the recommendation
> > > above is unsound; well, it's as unsound as implementing READ_ONCE with a
> > > volatile load.
> >
> > Sorry, which part of this is unsound? You mean that the dependency ordering is
> > actually lost when it's not supposed to be? Even so, it'll be only a problem on
> > specific users that uses `Relaxed` to carry ordering?
> 
> Correct.
> 
> > Users that use `Relaxed` for things that don't require any ordering would still
> > be fine?
> 
> Yes.
> 
> > > While Alice's series tried to expose READ_ONCE as-is to the Rust side
> > > (via volatile), so that Rust inherits the exact same semantics (including
> > > its implementation flaw), the recommendation above is doubling down on
> > > the unsoundness by proposing Relaxed to map to READ_ONCE.
> > >
> > > [1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf
> > >
> >
> > I think this is a longstanding debate on whether we should actually depend on
> > dependency ordering or just upgrade everything needs it to acquire. But this
> > isn't really specific to Rust, and whatever is decided is global to the full
> > LKMM.
> 
> Indeed, but the implementation on the C vs. Rust side differ
> substantially, so assuming it'll work on the Rust side just because
> "volatile" works more or less on the C side is a leap I wouldn't want
> to take in my codebase.
> 

Which part of the implementation is different between C and Rust? We
implement all Relaxed atomics in Rust the same way as C: using C's
READ_ONCE() and WRITE_ONCE().

> > > Furthermore, LTO arm64 promotes READ_ONCE to an acquire (see
> > > arch/arm64/include/asm/rwonce.h):

So are our C's atomic_read() and Rust's Atomic::load().

> > >
> > >         /*
> > >          * When building with LTO, there is an increased risk of the compiler
> > >          * converting an address dependency headed by a READ_ONCE() invocation
> > >          * into a control dependency and consequently allowing for harmful
> > >          * reordering by the CPU.
> > >          *
> > >          * Ensure that such transformations are harmless by overriding the generic
> > >          * READ_ONCE() definition with one that provides RCpc acquire semantics
> > >          * when building with LTO.
> > >          */
> > >
> > > So for all intents and purposes, the only sound mapping when pairing
> > > READ_ONCE() with an atomic load on the Rust side is to use Acquire
> > > ordering.
> >
> > LLVM handles address dependency much saner than GCC does. It for example won't
> > turn address comparing equal into meaning that the pointer can be interchanged
> > (as provenance won't match). Currently only address comparision to NULL or
> > static can have effect on pointer provenance.
> >
> > Although, last time I asked if we can rely on this for address dependency, I
> > didn't get an affirmitive answer -- but I think in practice it won't be lost (as
> > currently implemented).
> 
> There is no guarantee here, and this can change with every new
> release. In most cases where it matters it works today, but the
> compiler (specifically LLVM) does break dependencies even if rarely
> [1].
> 
> > Furthermore, Rust code currently does not participate in LTO.
> 
> LTO is not the problem, aggressive compiler optimizations (as
> discussed in [1]) are. And Rust, by virtue of its strong type system,
> appears to give the compiler a lot more leeway how it optimizes code.
> So I think the Rust side is in greater danger here than the C with LTO
> side. But I'm speculating (pun intended) ...
> 
> However, given "Relaxed" for the Rust side is already defined to
> "carry dependencies" then in isolation my original comment is moot and
> does not apply to this particular patch. At face value the promised
> semantics are ok, but the implementation (just like "volatile" for C)
> probably are not. But that appears to be beyond this patch, so feel

Implementation-wise, READ_ONCE() is used the same as C for
atomic_read(), so Rust and C are on the same boat.

Regards,
Boqun

> free to ignore.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW_rHVoiMm4ev0e8%40tardis-2.local.
