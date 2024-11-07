Return-Path: <kasan-dev+bncBCKLNNXAXYFBB6FDWO4QMGQEQBJTSLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E56B69C091D
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 15:43:05 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-43163a40ee0sf6894315e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 06:43:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730990585; cv=pass;
        d=google.com; s=arc-20240605;
        b=D4HsaZk6mMmhURxxsS+DI763bwrKIj1YilfJMAKNML++u5NSMnh2f8rCFz38AO53Kl
         KZgAcBtnjs/EOFDCrkDLHo91MettzeiSgi2k/FssyqrZSSspDGMkdflRSwj09NsTDS0g
         5HKc19FiUtXeEbd5waL3GskAYPMVv+3PYk5yPhDcl5+n4VMTPd3byNt4fEG0vVcyiXdj
         dshkrqT3/tbjYACsQa8D7/x40+KQf7tzDp9VleqVXHVJjyd+jXB6S3tCTVWMGv09f5a1
         v0y6UwqDFL8KFTCFQHI3z/GbR3QX3d3BTlE6sdi2QoOICNFM/yleBYEaCyfRPQBwfegK
         dMBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fuOb2x+kFGt3Oo+Z0PBLxeWXbm0cY/PhZM13Ph9OkCA=;
        fh=+O1S9tjHyUddh9h3CpglewEKNQqG9Vz6mksprlHfYDc=;
        b=IXIc4PIlhbOF/HxwTeNyT5xDuooFeCt0y1vPddkAAPYz/yiZ6mnoEWlsqNFH4R76tu
         fQivqT59Y0YUcLj5XWq9IXef7YEgnZkeUyEsmK757Hi4jgfsNbyJSawP/3KUJ1IZy42x
         gOGMwEff5+jyqo+Cvv8oIphSV6IBB5/BCOtz4zVKoNkXIDJPL2NXoyYKHRreDGOHiSXM
         hiFfmFCkhJw5l/sB8QyEjL6uOIUtLgKo6TnIj/HoXpQgmP7ZzT2nRkydONId0KHn6/vj
         4c2v4Cbxx+f2MCipUdBTt6jqDxTTiOQrAyve64Avv5p1p3gxV/qmhrVWyothNxZuv6lB
         BAJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=G83b4EPS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=ZKJS7su5;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730990585; x=1731595385; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fuOb2x+kFGt3Oo+Z0PBLxeWXbm0cY/PhZM13Ph9OkCA=;
        b=duuCOs7miD9VEY98zNooOX76oIf/N442jtCxQinPruhHQ+aXvr+wL1oj427NIIkkul
         czNnlIEKoIP80oldFT3tJm+ZezKK8Sr+UxV8IOxHDOM8xdFkhylBbYvE9/OChi1jxLWB
         kNouFchc5Tp27cWkQJv/2skkUm81l/2PrktRSKW26zyCbUuxG8xgaU1LuIYpVbKbiTdo
         CmDl+ivbHWDHIxMd2kwzotDnFomKiwjBQOLFzfXjs/C9N7zlJENMeZUqrchjubIhAZKy
         vYI91nsPda0wPSuWXdSJxFZX1oj6J35Q06KfCPb8w42iR0/+t4ePxLT5eRYE0j6/zedO
         bj0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730990585; x=1731595385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fuOb2x+kFGt3Oo+Z0PBLxeWXbm0cY/PhZM13Ph9OkCA=;
        b=SBmOcWpDtVJWPPm02iVEIcydZ9nVx67Rb15k3P2IqWBKE5oscoXSEUuvsrHigdwMT3
         PRCpmEqi8rjIFj51jmvl6MwhUDs/uXJ/bm1h7cNN+Jt9V37AXeAivmiysrTQcVXfU4xt
         WhtEhQXbF21VozY583BOgdQ+dHhr2JwtLR+Q7aHft1CrWn4C700WHUfO00/5yEdSQu2e
         8y1fHbcZH2cMVnsTMA6Q4RewxhYbmJTbqX8z73k72kX4LrwrqsftukCH0NELVIp1dLIw
         Yv93m6mW2nXvtwp/+a/ylX73THeTbiD8gJeZ+kr7xUCxZQkGdaGK4AuLIu7MWzfOA2OW
         EO7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkhpO6hMFwmo4cIMjmK7RtQWR3raGKYxhzoS6pICA3p72dSI5yYQZdNkWzV32BOl2tJS+l6w==@lfdr.de
X-Gm-Message-State: AOJu0Yy8gJGwB0xehx4dxBYOYNnFoiL5Vl2f//Xneatu7fmgZZA1j4s7
	zYN5PkR6ctbSpERugxVee8XlRatSVDBrah6ywqgX1z/2wHvs7ZH6
X-Google-Smtp-Source: AGHT+IEEZwrOH0Y+UHrxn12VeT+z4FmSclCVUks9RxL0rQKuFWmU1ugmJ9ixz6pDUwdSgFgbq7FEsA==
X-Received: by 2002:a05:600c:3b9c:b0:42c:bb10:7292 with SMTP id 5b1f17b1804b1-4319ac70754mr402186975e9.1.1730990584845;
        Thu, 07 Nov 2024 06:43:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:49a8:b0:431:11e7:f13b with SMTP id
 5b1f17b1804b1-432af02ee6als4214485e9.2.-pod-prod-07-eu; Thu, 07 Nov 2024
 06:43:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUltWb2Wg2V5ZjotSP31UgT31oSvi5jgQBu2WIlcoXCcgdInONUsYxfdC1H+rxNdPryudEzGn8Ga48=@googlegroups.com
X-Received: by 2002:a05:600c:548a:b0:42c:c003:edd1 with SMTP id 5b1f17b1804b1-4319ac9c555mr383781265e9.10.1730990582287;
        Thu, 07 Nov 2024 06:43:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730990582; cv=none;
        d=google.com; s=arc-20240605;
        b=ZXXobx0LA7wJm5JUuf/Co3ZLo2C4ldCuvMQ/A+Fdmo4OcGq/sZOIkZrntLDGzFiKW/
         lgyGxX75fjA4o2ep7sriq20di6tvznMBsi+BNcnZyaAbeG99u2eaFhs6JYMIJKSizAF0
         839YreYQRJKlpBxoes/EXrXGx5FtuD4jJTUziIo+mF0fFE/lGThe4feb5lZNnB7qcaPv
         Y/GO103S8kAJRZZfaEDGcts5i4rEhSi909TREn1k9LIcrxaY0DYAH+Cm0HptvVsWd4A4
         Ddo7DWIVanCLu2ACW44mkLONxm6O37nLNgIILV8VTKId4o24Jys791EER6+39TEwugYS
         X4uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=+3nFScjAqsAlvVm2mxTWkS7nXe59tRsb+n/sCrz1BIo=;
        fh=TOEpJ47tM1/mlMKFgxd4xKhxdFATaNPuKBwJy+FBOCI=;
        b=VGPkIhpYVRzNbUbMo+mLCLuqmv+h/aqdMgAnxffxAFOnYwKpJrxQb7CaF21Ks6kRE8
         VpS2frUgY8Iep90WTSv0ADXpMLRlvplECqDt1O2siY33k9R2FuP5usdrKzwG+6ZwE93X
         fd4FPHVZDL95oxEkxcwRO2+Gv5s+QmvmUXlEHBARi0ecV2hzIR18KvGiLIBkpCbjbgzY
         d4AmYrARKQnZOGzsMdxm+zmfruSA6fyCOvrlGOWp/MZfe4tbhhVq1uJSc2ylEuW8aoYw
         Nb76HWMXEjpJGlzDDqZTpKkWksZJy50XONs0twgRNjHSnazZUVkizi40HvPIYQpPmRMS
         vhzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=G83b4EPS;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=ZKJS7su5;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432a368745esi3318345e9.1.2024.11.07.06.43.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 06:43:02 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 7 Nov 2024 15:43:00 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Message-ID: <20241107144300.gbzCzBRf@linutronix.de>
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
 <20241104105053.2182833-2-bigeasy@linutronix.de>
 <ZyluI0A-LSvvbBb9@boqun-archlinux>
 <20241107112107.3rO2RTzX@linutronix.de>
 <45725c86-d07f-4422-a6fd-c9f02744ac75@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <45725c86-d07f-4422-a6fd-c9f02744ac75@paulmck-laptop>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=G83b4EPS;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=ZKJS7su5;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2024-11-07 06:08:35 [-0800], Paul E. McKenney wrote:
=E2=80=A6
> This statement in scf_torture_cleanup() is supposed to wait for all
> outstanding IPIs:
>=20
> 	smp_call_function(scf_cleanup_handler, NULL, 0);

This should be
	smp_call_function(scf_cleanup_handler, NULL, 1);

so it queues the function call and waits for its completion. Otherwise
it is queued and might be invoked _later_.

> And the scf_cleanup_handler() function is as follows:
>=20
> 	static void scf_cleanup_handler(void *unused)
> 	{
> 	}
>=20
> Does that work, or am I yet again being overly naive?

See above. I can send a patch later on if you have no other complains ;)

> 							Thanx, Paul

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241107144300.gbzCzBRf%40linutronix.de.
