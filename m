Return-Path: <kasan-dev+bncBC6LHPWNU4DBBN7NYPFQMGQE6MHI4AI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4Hs7Nrn2cGmgbAAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBBN7NYPFQMGQE6MHI4AI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 16:54:33 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FC1D59816
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 16:54:33 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-88a2cc5b548sf32615856d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 07:54:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769010872; cv=pass;
        d=google.com; s=arc-20240605;
        b=MJ4gMNUfRbkvw/Tb+udkR4KqSIPrx+A8ed9oliTTMmT5BC4fSUTtxOuFf7opGr2PYd
         gJfvUw/QnGMZYkUw9REKEaABrRdl80+04zk0koFe210fBdOclo/zRUAAXUXDshUpT5D/
         CRiZmodM7n4xEsL16UYJjIBCM9704594E80/8umhxSwAX3rQtvQuZCCfTEpic5g7dkWn
         Fn5cjT4FJKt9i8T1zv8qoBfEPK7cs3O1VNmgP5aUz+C1Q3JGr8e3WBB4+94pooghBN5V
         lu9eG9kyIbQDxW+Osx/IskLIiZS+7ucUZid/Pgq41ymVaF8fkAP3BcAJUuHB3xW7z8eC
         Tg+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=VQytvRLI+QUP8S6jfvDIZ5SlzEcBtiVjyVuxU63h4dc=;
        fh=u9SkHfas//1kcZRcRnqY1p2e5MhggJVpLVRMwN3zpVE=;
        b=OF4z50ldeYiW7j7J511yog6hHBaAaOLSWMckYnoiwY/kDz/BoMlyNc3VLWPTC4R8Kt
         rWXs/8qhLyoNMZKK6e/FXmvCZlWenb+hQu5xxAnC8MprZC5+zgTQSrfbVhoeE8GwRkHB
         G+H9iJ7JNruKIXEL7CcrUnN1/wxkT3OUn3MiZzSWOr3jqZkKiMLFmvZtrRfcgEUv/0IN
         qRHiPVSMQm2Q/kRkjaRjO9Sf0fv8ipiRxWQI70JLqKBaoKuRm14fSxTuro3ubz7BIheo
         /rkWFt1QZPpaHyivX+SxHxloLbx8BY6MxNDG+xl55c8v7Q2/Ig/JhYDX92Opj2EM0DXc
         VAFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NRDITbJb;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769010872; x=1769615672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VQytvRLI+QUP8S6jfvDIZ5SlzEcBtiVjyVuxU63h4dc=;
        b=B6XmmMl/SlBHLJdI4j4gjrMrFAFguNf+3RVX2gEMutorE0bln1n82bDB1vh8QyBPnx
         LVQrzHZZT/HNlmAIvV2p54xO1ersSeO0e2PbCmLUResViNjEbavoCCj2QdlW5O328Gz0
         78CqUqA6M7+7T4wt5dKyAEnTGZHUy03DpbmE/DnSALXW4l696m2tnr2nukTwSNx8i3Eh
         OMdxYskPGwF1tu3fAMADBZ2lz7SPeg1KhfGm+kd7fSV3RGy+gRsPgYfZdMxA/iRPbvAy
         gnPtf4uYHwdvQKE1X7rLD49+SgmVus32lDb9UjkyRRlFm+ibhyuuYvCgj2h+3it9p0mX
         SLmw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769010872; x=1769615672; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VQytvRLI+QUP8S6jfvDIZ5SlzEcBtiVjyVuxU63h4dc=;
        b=Es7thYXEqmUrjb0k1lppoi6h6m2+IBYYSkZ0bJ6s3+VerrRRGbJOGU4UQ3Y4AndgMl
         hx+SuyCUFFFOPMqlN8a9Ujz642S8XY+SEUVor0durer+jIeRG8v4xr61t4iK0KXK0Vee
         kZhRPRgMU80LlEdb68KXe4B7VgaaAQF6Q8QGmpIE78zRrUifMkEiLS+dZ30ty5cAWgnK
         jEUToo7agELLwIXc+41fMvfWD/UnRRGfhRCo8OFdKwpGZyIaG4aPlRqeKswvnR8hnGK3
         19mmhDYJ3egCLrxVnoeEWO9jW7CietdqxVq1B2QdzUsc14UjyKlUeLmb/DFFMfmfJjD3
         2dRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769010872; x=1769615672;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VQytvRLI+QUP8S6jfvDIZ5SlzEcBtiVjyVuxU63h4dc=;
        b=j1D58i8fse1V7FCQcJgmtDLnZEAhScxiNaHLBdZDnhLFw0WvMcvNxcsrpOPY/0tG8f
         MRXICEEziCfwbH418YWB6BrnOsFi70IBP0G++psTskPD1xh/RRTiK+OwuDVx2MezpLsJ
         34X/0sWcWSfDRr0aaGevRDh9ykvd1u3Ua9nV/ztZXjL+lOOCtLuo7bZpYFybR9EpsMw1
         1av1Gxs2e7Nb+GyB7ohLGhJkdvZ+Q67YdwnV1ekLK8Im3gXCXUGlNO1ukN4Iy8uKPIJP
         +QmMjIC73nc8F/91rUrO2nm6WSEa4ayl5B9SpSRxnk07TWF9ufOVhGV/m3Y67i1eNVSG
         fMrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDBDAVzLZ692BW05hFzQCx/ljWeuRR5jHjy8C1wwVR+Qx6jjCmD60XKUF01xMTJ9luIWA/TQ==@lfdr.de
X-Gm-Message-State: AOJu0YykyplAzzPe81+AkkWnPkeRuoqVREO9spagP3D1oIiRObueOW50
	La9Uq4EZaaPiVlLOie0Nnv91bYC9IRfpEvh2aBQExOY5qOFrQW4c3Eu9
X-Received: by 2002:ac8:5f90:0:b0:501:4a33:f3d9 with SMTP id d75a77b69052e-5018ed2d544mr292267991cf.0.1769010871608;
        Wed, 21 Jan 2026 07:54:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GFwXqRRB1pwLiXKXdXlFwuGG7gUeWYf9lINhzODaMDog=="
Received: by 2002:a05:6214:8105:b0:892:66c6:bc2e with SMTP id
 6a1803df08f44-8947034f518ls12939256d6.2.-pod-prod-00-us-canary; Wed, 21 Jan
 2026 07:54:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWkfYjRb7GMMlT/DAgdGQaVnidxo4L+ehK/uu+TdR2jIgkf5I/At290NoCESxxKwLEoFOswDzbYQ4g=@googlegroups.com
X-Received: by 2002:a05:6122:500a:b0:563:466c:2 with SMTP id 71dfb90a1353d-563aa9aae66mr6380151e0c.5.1769010870064;
        Wed, 21 Jan 2026 07:54:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769010870; cv=none;
        d=google.com; s=arc-20240605;
        b=Tz6IAb3/Fk1pctjH0GQfH/OBM0I6+3VZ+taFXEOEyoW+pVKwAZKxxoG1o6v/6HcPnG
         Le038jXZuygkB9YpBtnDih0m8BGZAlv0CCZX7xRzxiqyZOi3PQ8ddX1Dfp4A756F88wK
         t5GX6LaV1McRc9F6vqGZcSX/T11X0gM231+7i0Z3NL8CIe92gRLb1dA3qKLBKjdCItwN
         R77VaV7L3NM+Pe0gfzTyTmFjDWO9VRHjlgk2cBldmDF8BDurKr5/J/hNkJpUtrUjlL6o
         Sq2ifAQQGIg/5cd0FCCNbpO+nqJCCv887Y1nj8S0Jubr+fj31SkP4IUFPyV02J+/wss3
         n2pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=vBuHUIxWMnLe6s7TwsvCGhfWapOm3oLq0HDTyptAlGo=;
        fh=NW9FevoFJi3RG4ynrneytKJL6bCS0hF2Kz+WO2yy61E=;
        b=dla6bxPh/n+n/hxi1r/thgeaeqZMPIVPtQ4rqgvrUqjlLvmmSqATNvKEmjGcS92nTw
         Mi2XIURG+sif0VQb/3VOGuIKUCBBHjUArWHiXiNLD4CEoPEEeqVvGZgj9/Qgpi1go5iO
         uTWbvxB+x/nabnkCgJDXCGA8xbGEksaVoLxdqB8WNjiBE5ICvkedyRPB3/vrUdNCIsrV
         PlVUSAyxhtJvKEWffRaTSMo7z75xDqGcnQ27SlJ5zHgk0q1WWtlIlchOSi4vh4lnEfJ2
         7NI+tPJOZH8cc01R4uQdOU2mn71WoQpp1MdCMVh2VykxBIs+apWHBNBgm1u4SpBMd+Is
         MA9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NRDITbJb;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-563b716bcaasi508919e0c.8.2026.01.21.07.54.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jan 2026 07:54:30 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id 5614622812f47-45c7f3a9676so708184b6e.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jan 2026 07:54:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUVyl0Vcuew+q0G4QOZVNIPzlLd5suX4tOZLI3P7hNDpARH9+ypG3701Xm2mayP5/LDZdmrUUsvkDo=@googlegroups.com
X-Gm-Gg: AZuq6aIhc5wiSDR1gEc1s54/TXgZ+Yv0ivzS1xUtw8OFaJyORYZKdE1Jbc4kTS3MIZL
	+/f0vtOW7RAHLnXHZhW5p4DOpwVHfqBwDpXeAnN1uhRywzh2UhbWvw7BHvvCVdgIRr6e12GNqP0
	hqYc3uaVCT2JeOyoVSqZTX/b/t9plKfLxObIIYC+Yd6N60gZ5QfRXGX9Mte42tSi+DOmhmVIqe1
	JVcaqDkinDgVjsTZ2u0yddsk8bLNJTuXoIxLexN4veW5pyWEKQVZi8oxTOn6AOgRDYDlLJbPo+l
	tgT1KYDNvQfIfqQN6Chi/8SWHsJV/hUT1711IQL8/8aMI9+A9BeuQyvCSfPZqSIZM1wSAfLo8DQ
	PGhqNiPRdJZRO3DFt297YSg9SSDDuGj87YzqZcfis3rPGmPMqmpPqLxkDUCT50QNYPA4Rt9mv86
	FZ9bvxA6VXiNYSLt8TIJRqC5ztZh5/NUwJdxnmR8N1WLVzNZbqteszR249fges6EeC7fSdFaJSH
	jnop2hho0lqyHs=
X-Received: by 2002:a05:6214:21ef:b0:87c:19af:4b76 with SMTP id 6a1803df08f44-89398144853mr314752936d6.17.1769004274227;
        Wed, 21 Jan 2026 06:04:34 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id 6a1803df08f44-8942e6d8a94sm124931226d6.56.2026.01.21.06.04.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 06:04:33 -0800 (PST)
Received: from phl-compute-06.internal (phl-compute-06.internal [10.202.2.46])
	by mailfauth.phl.internal (Postfix) with ESMTP id 82E98F4006D;
	Wed, 21 Jan 2026 09:04:31 -0500 (EST)
Received: from phl-frontend-04 ([10.202.2.163])
  by phl-compute-06.internal (MEProxy); Wed, 21 Jan 2026 09:04:31 -0500
X-ME-Sender: <xms:79xwaRPgS8h0JnF8HDazDYFECjiK0XRf_br3BZs2plL4fMjDAe722Q>
    <xme:79xwaY1R9fsjITBQ4yKxSWOJU3sP5x_pIHLOyR7_TbiehKPP2R_EqaVSuweruAo4k
    eaLFD_gv1cDSAb28i6hpJyT-SMrIX3LLsRJuMe-AYXeWe0Oy8PO3Q>
X-ME-Received: <xmr:79xwaY2vAFacNlU5ffdaLISbe6CBRMyv8522yQ8kaXcNVrqe9RXlb3h6>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugeefgeekucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhepfffhvfevuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpefhtedvgfdtueekvdekieetieetjeeihedvteehuddujedvkedtkeefgedvvdeh
    tdenucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgv
    rhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfh
    gvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthho
    pedvtddpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtoheprghlihgtvghrhihhlhesgh
    hoohhglhgvrdgtohhmpdhrtghpthhtohepvghlvhgvrhesghhoohhglhgvrdgtohhmpdhr
    tghpthhtohepghgrrhihsehgrghrhihguhhordhnvghtpdhrtghpthhtoheplhhinhhugi
    dqkhgvrhhnvghlsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheprhhushht
    qdhfohhrqdhlihhnuhigsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheplh
    hinhhugidqfhhsuggvvhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthho
    pehkrghsrghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhope
    ifihhllheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepphgvthgvrhiisehinhhfrhgr
    uggvrggurdhorhhg
X-ME-Proxy: <xmx:79xwae-7AjQM7cRhrID17z6Ip7K1eCj6XX0BcbwSoxR7SPnuwnSQmg>
    <xmx:79xwacalaiU0QPeoC1XhJN7CzYPqHVgjh_4cloRVJjbl_SZf2a1WGg>
    <xmx:79xwaVxjU5nPqxd_mcPpASdcQ9Jeq9x06toUhHgGaDVEK_wxZroVPQ>
    <xmx:79xwaS-vARAtWkjKWHBijayn1MXGlO2wWdH4VjAucuXb14OOmzvCBQ>
    <xmx:79xwaZxny1W8998ySnA5TLfT8cQGMeb3X_G-z8hLwsB6H5O6XZsesuNN>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 21 Jan 2026 09:04:30 -0500 (EST)
Date: Wed, 21 Jan 2026 22:04:28 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Alice Ryhl <aliceryhl@google.com>
Cc: Marco Elver <elver@google.com>, Gary Guo <gary@garyguo.net>,
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
Message-ID: <aXDc7KYgkD7g4HVd@tardis-2.local>
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <aXDEOeqGkDNc-rlT@google.com>
 <CANpmjNMq_oqvOmO9F2f-v3FTr6p0EwENo70ppvKLXDjgPbR22g@mail.gmail.com>
 <aXDL5NUOH_qr390Q@tardis-2.local>
 <aXDPliPQs8jU_wfz@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aXDPliPQs8jU_wfz@google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NRDITbJb;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::229
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
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBBN7NYPFQMGQE6MHI4AI];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[tardis-2.local:mid,mail-qv1-xf3a.google.com:rdns,mail-qv1-xf3a.google.com:helo];
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
X-Rspamd-Queue-Id: 5FC1D59816
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed, Jan 21, 2026 at 01:07:34PM +0000, Alice Ryhl wrote:
> On Wed, Jan 21, 2026 at 08:51:48PM +0800, Boqun Feng wrote:
> > On Wed, Jan 21, 2026 at 01:36:04PM +0100, Marco Elver wrote:
> > [..]
[...]
> > 
> > Note that it also applies to atomic_read() and atomic_set() as well.
> 
> Just to be completely clear ... am I to understand this that READ_ONCE()
> and the LKMM's atomic_load() *are* the exact same thing? Because if so,
> then this was really confusing:
> 
> > my argument was not about naming, it's
> > about READ_ONCE() being more powerful than atomic load (no, not because
> > of address dependency, they are the same on that, it's because of the
> > behaviors of them regarding a current access on the same memory
> > location)
> > https://lore.kernel.org/all/aWuV858wU3MeYeaX@tardis-2.local/
> 
> Are they the *exact* same thing or not? Do you mean that they are the
> same under LKMM, but different under some other context?

Right, they are the same thing under LKMM when used for inter-thread
synchronization when they are atomic. But when READ_ONCE() (and
__READ_ONCE()) used on types that are larger than machine word size,
they are not guaranteed to be atomic, hence semantics-wise READ_ONCE()
firstly guarantees "once" (volatile and no data race with WRITE_ONCE())
and then on certain types, it's atomic as well.

* In the case that we need atomicity, we should just use atomic_load().
* In the case that we don't need atomicity and no data race, we can just
  use read_volatile().
* In the case that there is a non-atomic concurrent write, that suggests
  we have a bug in C code or we simply should have some other
  synchronization. Or if we believe the conncurrent write has at last
  per-byte atomicity, then we can have `READ_ONCE()`-like function that
  returns a `MaybeUninit` to bear the possible tearing.

Regards,
Boqun

> 
> Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXDc7KYgkD7g4HVd%40tardis-2.local.
