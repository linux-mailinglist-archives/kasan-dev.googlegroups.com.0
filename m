Return-Path: <kasan-dev+bncBC6LHPWNU4DBB4OYXXFQMGQETKNDAHA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YBuaNRWmb2kfEgAAu9opvQ
	(envelope-from <kasan-dev+bncBC6LHPWNU4DBB4OYXXFQMGQETKNDAHA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:58:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 480CA46E64
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:58:13 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-81f3f3af760sf9595918b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:58:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768924691; cv=pass;
        d=google.com; s=arc-20240605;
        b=c9trILlsuuA6b9Fx++r9G5arn+IMS5GmyzW6VexkZySp1eFnABQT2VWNxLL3Nm/Xly
         5ylfjGo5cTJrJXZTyYb1qi36tGFdsJqGRbR4GNBWnEXBAkKvwysHpPc1dB41WbjHuneZ
         /qlwuQmoViDurEbCLajHLZmowYg1+EH/2Tz/IOgsSC+zuBwkcRRZVLMxYgyKHCCoDUri
         emJ9qwxlyBbzEhr8wUXBEoQY3XiW4rqzvv5WIzsrl8AkorMA4lSzgquEDtsdiUx0IExx
         vK/U/5ymBD4QWRUD9u6ILiAZvq7Ajy8XGAaYdpQTJF8VDMblGL8pnIr8yfQnQxrf1gO6
         spPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:feedback-id:sender:dkim-signature:dkim-signature;
        bh=KTDf/xl6+M0f14P38brrtExnPt0AHYFAVPEtzDx2pq4=;
        fh=Ts1peoOY90K5CZ+HqR40MdofTaElPSI51skqyHLfovY=;
        b=lQfAojP785pvS7fbgeil6ZlKRK672rI8060XkcLVFpAcq0OxhRk1OWBWnBd5Nb+ep8
         A5WohNj/c9sz+N4T5grwgsbsKNwGp0ZjIAq52UA0w4YuYDQmnBiCVSuE1xtMundWzCVI
         rvW+lqD33BG+Y85e2mmSJQ1hfw5TSPpYj8/gHDx9JJf8qnQEwe/th2ttYZFLdLE9t/pB
         FnWcWZ2jBA+qRKdr4gGxRxI9T16qkhm+MeuDl2ucoMSgsq3l1R9LPQn5JRQpYPTRF5wb
         7Rv30E5VtOH4WRS29GJ+9TnFFCKA1bW7wlCGltvuOluYpiLtonj9dPlsTHAhT3FJpkbH
         tdqg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RaDoXbJQ;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924691; x=1769529491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :feedback-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KTDf/xl6+M0f14P38brrtExnPt0AHYFAVPEtzDx2pq4=;
        b=x0Y/pz/2+oU63zzP6f6sQB7i2WqVBBlaJP/IDjTwurTwQaY4pMdekCRdwu/7HjAx6p
         LQDThblOoxwaoPE8Yh2Pas6tLEm6Hhfr/wMPv9qn4iQf5jCd8fvBCyBNFWNiER0M56DA
         OVYoO3TPm8ss8X4hVVfsbyNe3jKYT8WwfGKa0VAGqcDC3aEeqrgpjWZ9Ytl8MUNWr12/
         zbCj4X9nGsHSYTlSckiPCvpf6MlHNKABQysa4qqbvzehsEenRq5aqSLY7WtU91Z5ohGL
         +HR9Vxl0wp5NQgdNtr1/qlBalFovmBfAYOBajMaleoYruHoMncujdlOHTQW70CPqq4B8
         TARw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768924691; x=1769529491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :feedback-id:from:to:cc:subject:date:message-id:reply-to;
        bh=KTDf/xl6+M0f14P38brrtExnPt0AHYFAVPEtzDx2pq4=;
        b=jRcSgp21DIXWDnItBweB1TGct9n9Z/vgsu6iW5Y3T7unpHWa2KlDuwZ57Ume5M0mus
         zZDASD7hUhdyKKv/VihOZTjPYceQb0JA7h0itVZkEG3/4zOFnyYcgtOb/7wZFppgeXzb
         iVryWkWwme4MiKDWAC/kaWwQUm7G8U0iLCC3tvM+VA0S35zechMuli6n0pStXq/vZoE9
         KYoX/x0w4+DWpTlV/3X52H4g3s8g54ASOeAFNnAoPvLZ14Bg9ahTxx7PCuhqPetLkNcH
         3xw7MdLfYQdZzSjAr/DZCZmjMOCSzdGUmjMXqOENimOpD76UcQTg/ZdM7ODFR2RvdP3s
         zspQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924691; x=1769529491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:feedback-id:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KTDf/xl6+M0f14P38brrtExnPt0AHYFAVPEtzDx2pq4=;
        b=G+cCOsfq1/F/hJyEvhEY0F3YhHA8cDpdx19hLFrRveaVtl9aGgtB+D4psS82Y8DjU8
         wRPA5U/s/x6djItAVs0KOO5Po7c3QgMqK3iPEshIVOXer2t0aMZVTsi2FWB/DEv4ANKr
         j2TJ9nOYRat1EjJhQcTI0JIu3it/+iaS/ksEodEGypGlzNaoJlfw9gWxKqe16T562trk
         7bg2VmRudWMTgsB6vlyz6K4J85Xij/PcAYbbTjUpalN2xeVnUwx8z7JRe/vFyAI3Yocj
         HmILtRNM8PSljLoL84igV4OrdGraYJIBSzIc7acpcw1/QuVc91GwTIrFCrd+yDG45SGf
         AxmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9ZNtZdbtcOF5QiblVQKOXnRw5TMOUZoG9/fFB+PzcBGsw6Di5bTuEy4ulZ6BhypOazXvDow==@lfdr.de
X-Gm-Message-State: AOJu0YwgjCb5TvtXrILqrg8LL4q+0c1/pTD2VYvOPCQwRviP90hu5gGy
	Cqxqe+y8kIEFrZBMPu0uJ6CCMAe5faR661RS3b2dTHDOtn35yUTtPURI
X-Received: by 2002:a05:622a:1649:b0:4ed:b94c:774a with SMTP id d75a77b69052e-502a1648dbemr217596701cf.5.1768909938123;
        Tue, 20 Jan 2026 03:52:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GhOMOY9oulIrco0h1tRNxfoKXuH4EX5tvvLKmwl4NMEw=="
Received: by 2002:a05:622a:91:b0:4eb:a15e:a083 with SMTP id
 d75a77b69052e-502149f1679ls89048271cf.1.-pod-prod-03-us; Tue, 20 Jan 2026
 03:52:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXod1bHwzZQWvjS1SfiiC9w8c0a9pBnqLsxuvjdUn8oW9FVOdL1nhDGiNCP0D11UM4czX4QiHsCVXM=@googlegroups.com
X-Received: by 2002:a05:622a:1884:b0:4f4:c104:8e9f with SMTP id d75a77b69052e-502a17c35e6mr186059111cf.75.1768909937003;
        Tue, 20 Jan 2026 03:52:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768909936; cv=none;
        d=google.com; s=arc-20240605;
        b=I5w9grfIlPzmspRAxiZSImWHf/aIbupJXDyn6/n0dNmJ3kX861vg3IQISqpTD3K4iI
         jsciGEHWT57MLVRmR08py5qDrpV+4I/9s/AVlKP6x4N1GkI2vkI+/6AaAgCJVNMhwiON
         bXAjzzYYvH5gKmyqFeH69k2RdpRyAmge/W8qN74y1XEO/erMGygE85hkwFpHhFcYZHvl
         NCLDjKOJDixkTKcRnr7UFdCQgWA+7Q8ux+Cpsprdj8kDLVdbSbqPMIEvkrsEVRjcWHLK
         tQEFxRL/Xl0038fDwEoenZQX67yy5B2GliohXa/VjeI9+i6lGPBzPuNmQJ2vudifQD2I
         tqkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:feedback-id:dkim-signature;
        bh=3jCOHRzv4aKjnldOO0XQggF0Di9XNaJfQUF6T7RtB4A=;
        fh=QDFtfWkWZ6HaUqFNpN4NpLlu8ztiD1hQLBCg2Oo08lM=;
        b=E0EfMtdaaoczzmzS8ouhOv+zlonAt5pAi2Ywdkp1n2fF94qV97VyhU8BgIramaWuYQ
         M3c2kOAhAYn3CVGdrXreclly6gqK6c+4z/PkBk3dKNOdji86pYX/3SvItW379toyKOJr
         GYWV2EVLF2GaBoYxlKs3frFJQwxRwtDSeQBhPPRy9rQHC6yc6uL0jv8L9hxKHNb15xIJ
         /NOJttKpLrOjysFajBmFaEyR/waPQq4I7AoOGhlnDvBMlP5ze6Y3KANNtmkt/KsGNm8M
         1CHyNK2FqQcZ92npi0naC0y4bwBuqI+1kJgVy5hfIP5eb3es/AdsZ8IfuXUSfa131CcX
         vZmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RaDoXbJQ;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1ea3beasi3704291cf.8.2026.01.20.03.52.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 03:52:16 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id af79cd13be357-8c6c922850cso109800285a.2
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 03:52:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWBR7puSzDKMdoh2mdaYgON7JHFcZG/Sya+0BZky0vNsCF0oi02XGC7A6G1j9YZBSwm+OFc0B+FeDQ=@googlegroups.com
X-Gm-Gg: AY/fxX7KjjLBGXblvuJUFHiRlavukI3azcuwX3aSxoQC2e5Jbd/j47/XMnvsQ02sEJH
	d4GSV7kXt97n0FuE+3AomVQZepK24GnIrpYIZ2Whp97bHXu8fxX189J1wpKFU/jepo3jN/ZrDGJ
	UF++7LNn+RIMMemCNOTEuZUK3Ak5JsvRRQ4UxloU4sf0KZIagzcnrydVheVThIDa5J0je+VVvXb
	pZFMeAWAxgTjtwKm2pSFJMKD5fiDdYbZPJi2y0IhegI0JqZKkOZ9TxjObpVO6mUQTUFurwhPdzp
	6K+NwARAPSQbwsinQiNKoDDC1VH/+7zFB7jdtIub7HVRXjE43XcASuN9hLECWCPOp5KpXgF+kpq
	qx1FDxTP+j3WHIsaB9ezXCbS0eUXNdgkB/QPVt+jHhf2NClZCf8wccr4zQhYI7PXsV4GBdInk6v
	MxCZQ8PYMbrO/yWjkyCcak3pqfM1p7vfZ4vm3hqOrmok2fzSdHMhN3YUYporAp4zX4f1sEiZGJa
	e6fc5tNovU/eT4=
X-Received: by 2002:ac8:5ac2:0:b0:501:4857:62e3 with SMTP id d75a77b69052e-502a17567camr193852581cf.50.1768909936488;
        Tue, 20 Jan 2026 03:52:16 -0800 (PST)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-502a1d9eca6sm99050811cf.11.2026.01.20.03.52.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 03:52:16 -0800 (PST)
Received: from phl-compute-04.internal (phl-compute-04.internal [10.202.2.44])
	by mailfauth.phl.internal (Postfix) with ESMTP id 8333BF40068;
	Tue, 20 Jan 2026 06:52:14 -0500 (EST)
Received: from phl-frontend-03 ([10.202.2.162])
  by phl-compute-04.internal (MEProxy); Tue, 20 Jan 2026 06:52:14 -0500
X-ME-Sender: <xms:bmxvaWGr-4XpSM2vYETxRfUydfurWqwHFWJHiYR4KhaLawbuGlmK7w>
    <xme:bmxvacP1XsD6L4zGUHJS-GKS6exgJDYz4GNc69LdovkPTiAg9XappwTcXrJoE7tBb
    1QJaNmCVCPmIcANzBF-Jw6zwj6JeIpfyQuxg0jBC7_VevoPjMxvjA>
X-ME-Received: <xmr:bmxvaYseTBbK91tjAnIgIZ4nsUU5pt3fox2UdyKq9mHmollKkMp5ZbMG>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefgedrtddtgddugedtfeegucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfurfetoffkrfgpnffqhgenuceu
    rghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmnecujf
    gurhephffvvefufffkofgggfestdekredtredttdenucfhrhhomhepuehoqhhunhcuhfgv
    nhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtthgvrh
    hnpeeggeeukeeghfevudektdevjeehhfekffevueefudeivdelteeltdekheejgfeiveen
    ucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuvehluhhsthgvrhfuihiivgeptdenuc
    frrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhs
    ohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnh
    hgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthhopedv
    tddpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtoheplhhinhhugidqkhgvrhhnvghlse
    hvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheprhhushhtqdhfohhrqdhlihhn
    uhigsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheplhhinhhugidqfhhsug
    gvvhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehkrghsrghnqdgu
    vghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopeifihhllheskhgvrh
    hnvghlrdhorhhgpdhrtghpthhtohepphgvthgvrhiisehinhhfrhgruggvrggurdhorhhg
    pdhrtghpthhtohepsghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmpdhrtghpthhtoh
    epmhgrrhhkrdhruhhtlhgrnhgusegrrhhmrdgtohhmpdhrtghpthhtohepghgrrhihsehg
    rghrhihguhhordhnvght
X-ME-Proxy: <xmx:bmxvaRUyAXBwVhh_V6IggSwh965r_5ycO2CiXOl1oFwnxZdIrzUaPg>
    <xmx:bmxvafQX8S1hdf_qS3P8eOrUvH3N6-86RENZCU3v91371q2d_58Q1g>
    <xmx:bmxvafJUjytmr_Y_iDeVc80QQA6XSAGnWssoZysgpL-n3M7wdpK54Q>
    <xmx:bmxvaQ1Q3Ph2XeOXJbSoSzmOgXP6qMYFVJSm48JOJrLVZLudCjGwZw>
    <xmx:bmxvaSJaEbhz4J4k9DL3G6r9PGLr8WJKLvCTeSQJf2kmGQStvOl5P2je>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Jan 2026 06:52:13 -0500 (EST)
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
Subject: [PATCH 0/2] Provide Rust atomic helpers over raw pointers
Date: Tue, 20 Jan 2026 19:52:05 +0800
Message-ID: <20260120115207.55318-1-boqun.feng@gmail.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RaDoXbJQ;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::72c
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
	TAGGED_FROM(0.00)[bncBC6LHPWNU4DBB4OYXXFQMGQETKNDAHA];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-pf1-x43c.google.com:rdns,mail-pf1-x43c.google.com:helo];
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
X-Rspamd-Queue-Id: 480CA46E64
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

[1] indicates that there might be need for Rust to synchronize with C
over atomic, currently the recommendation is using
`Atomic::from_ptr().op()`, however, it's more convenient to have helper
wrapper that directly perform operation over pointers. Hence add them
for load()/store()/xchg()/cmpxgh().

While working on this, I also found an issue in `from_ptr()`, therefore
fix it.

[1]: https://lore.kernel.org/rust-for-linux/20251231-rwonce-v1-0-702a10b85278@google.com/

Regards,
Boqun

Boqun Feng (2):
  rust: sync: atomic: Remove bound `T: Sync` for `Atomci::from_ptr()`
  rust: sync: atomic: Add atomic operation helpers over raw pointers

 rust/kernel/sync/atomic.rs           | 109 ++++++++++++++++++++++++++-
 rust/kernel/sync/atomic/predefine.rs |  46 +++++++++++
 2 files changed, 151 insertions(+), 4 deletions(-)

-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120115207.55318-1-boqun.feng%40gmail.com.
