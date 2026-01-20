Return-Path: <kasan-dev+bncBDRYTJUOSUERBCHPX3FQMGQEF735GDQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id AHRKKIu3b2kBMQAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERBCHPX3FQMGQEF735GDQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:12:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BACCF4857B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:12:42 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-88a2cff375bsf128939856d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:12:42 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768929161; cv=pass;
        d=google.com; s=arc-20240605;
        b=HHIVwwRZBxnSS+dl/Z1+zPr00V5zcy46E79oFy3xlbavY4c1gCUdrxMVMgaXevzDp9
         P2c1fxfaoBfcvMnXCIqmWwkn+MkpmP8jvvTNETgejNKYhw8JrmXHZ5EwltatBWF9BoO6
         Uy6Dgfyc4E2TNvQczYh+PjSpv96NZ+/qwkSN7cKxrVPsSM7cDFSpaerniqdHzTt3ip5C
         sS6kjcuRZZgThyd5GgwBGADEWglxCXi3RMRJPPYlkLeRTNbMXatfo2nEdA/n2ToK1wv/
         mb7NU9qvJ18zAtJ7csJnx3HgSHfGpXQCPWguiDsB7ShF0QRbIqouKy5BzbpLYbuuW/Jv
         uAzg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :to:from:subject:cc:message-id:date:sender:dkim-signature;
        bh=yfxacDBC3ATeE7RSO4ZjjiYh1FlUfS5HpMogeaPcgyk=;
        fh=Ukvgw7Vag6lBPRBJppXr74vLGdztd/5V3NQc7uw9rAc=;
        b=HcIuEgA8eMl2xw3s5o/g48kDStobuVIpzd7H/GdB2PEGaIFP+X/9FWfDKLCwoxib+/
         Ra/Wimn5eR0CO4NPQsLTb5TGKIZNhEiaL/ubsMvWChTofI4ZE88OWAxo1GmmfqxawxGH
         sbEGU/HJl98eBaF1mcPpYbXiuUsaoSH4UEXlu8hQ2sjaDf812CgFCQb/8NiFTqq0hZme
         0Rbo46SOj26kisqsl9aup/0sUftew4mgE0GaFCorkYJB/hqaTZRkWxJ6pstzMtCitkxX
         5FiJI7B27lGqjo3rhiCm8KROR+YUhJLbsdKrnhBsn3TYUpdf/74lXTSN4Cr0lFPtDCll
         MrSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=uJW9RQNu;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::1 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768929161; x=1769533961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:to:from
         :subject:cc:message-id:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yfxacDBC3ATeE7RSO4ZjjiYh1FlUfS5HpMogeaPcgyk=;
        b=s3f2HEHR3u2GRwdRAFj8RotMInUMG9XNxckdYa83i+9G2y6fx+v82ex6BQr+jHxWBa
         HEO4X1wt/Wndb1enZoBgmb0QDg3rXYsdpln+nyBxinYT7jNm2xGIu9jn/+wqrg9LxABX
         YLLCLPRW6G599XRrPCxXka4WXRScU0f457See4lQ8xAMkBpUzStrtSqcJiNT5MiLxcd4
         J+ukvI3XPA7KIB4JDtOJttlO/Z7JoZfZySDqfjwGcPjhctbc8MJ2LOUc65JUJGrvHfRV
         GmhVosfwoZQBd92jHxHVowJSA1hCvREwbE1j7i4R5/A8cUuJ8VZHDxel3jWxutOyR0On
         srMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768929161; x=1769533961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:to:from:subject:cc:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yfxacDBC3ATeE7RSO4ZjjiYh1FlUfS5HpMogeaPcgyk=;
        b=r84JklBnhtwHWLIq2uW7nKHHDmg5t+SekJA3So+lPUIi6UfuQNwQxSl51QeA819yqo
         xfu7IHMaxQclFrqIwhp0QZHci2InWb1mc5MRPj5540TgdBpLbPzSULDFB72qbC365+zZ
         Fv3VHU/JblNua572Hi0cZa+RyHhteu7M/WAiCpQ607sVPKqJFF46ACCy62CnvsBu4P52
         Pn7ZYHy1aY7InbKR2ERY6PdcDRbc5+3k1Md8EDgVZRzvCn0yTRoFaCBLCx9RnO7xv05D
         dnR8YgCLokzbPuEyNkmR5AoXUGPbSDVE1uZUzB/AQaIc1JzB984UvlWBcxTGaB7MHXYh
         b2xg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCV9SjJmpNpe/HGFpjn6WbDsczzzPMY2/VDWp+1LkwkiqDTUAcQXtajwxhl3gaHVXLgM/lI3Dw==@lfdr.de
X-Gm-Message-State: AOJu0Yy90v/4ded/P2TvRDuhyrkWithipluM2UAsK7jxwBL+Mo+42L0h
	xSz0NVOkDocTWMWxT67BQjKm1raiZ8VNRubTbTEK0Zpug9zFvcdYLws6
X-Received: by 2002:a05:6214:1c8b:b0:882:7571:c023 with SMTP id 6a1803df08f44-8942e4a7458mr217856036d6.47.1768929161193;
        Tue, 20 Jan 2026 09:12:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GypVcpteeAdT0yqhDgE8wjqMscUbiHO2/r9pESrjDa5w=="
Received: by 2002:ad4:5e86:0:b0:78c:3f6:27af with SMTP id 6a1803df08f44-894221da472ls63168006d6.0.-pod-prod-05-us;
 Tue, 20 Jan 2026 09:12:40 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXpSKf8q+LvoM+0600tRcnqE100BN+tPldr5mevltf5YK4L1dHl2pw11uk7yHKClPWdSgbv0M4stsE=@googlegroups.com
X-Received: by 2002:a05:6102:1607:b0:5e1:866c:4f8b with SMTP id ada2fe7eead31-5f1a7222abfmr3710846137.44.1768929160136;
        Tue, 20 Jan 2026 09:12:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768929160; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ubf1NVR5p746pEFS9R5+Jh82eUFF3aS2Ft0YdZpDwndggm4HlhZX8c7M6haZwyz2FE
         YcFSkLNR+36RqPCsONie1+bSsf4KqYnDjDjDy2fTDnYzcmb8xZkoLJdVpDiqEOY+VRc/
         SAl7QtirwzmyU7fRjXC0l+vvunyiGi71K2BEDhz3qc9TaoVn+wT6GNNAXYl3PdRMqW1S
         mxLunK9trg2EY+hEgydxZAqrqDb2BPrrVqA7KDCz3mkUTugX4u7H22V9NZHusHGDzLnL
         0dfF3RZAkDJD9+1kbxdHsDaApo0ZXOWCm2l4KEQK9X8vFGxMZA+qObo3FVLHcfwnxP4u
         pLTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:to:from:subject:cc:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=2NNRqb23Utmc/V0dkcVb0HjsJhxSUJb5OXrhCNNH1AE=;
        fh=iftlcEqTzKeYdg2kfuH9jsgClLuZuer1va0lmmvtTr4=;
        b=WqdPsAW4yKkjcZKn+Hz6Gd5vv6/IhW9ffhB9zayJj+sWqjtH9Z5vVdmtzjpfzGS1Za
         viEo9qutfHsF9LLJg1eJTII1OYusoUog066rTZg76d4Zigw3e6GCIoKy0j9i3lz/rjiI
         IGqeLkTRwMfGwr3R92OU4+rjxTKtLH2s824IGPaNASA0PcPd/QjM+psITgFGFBjC26a5
         9HkuaNDtCEtBAcVyoS6ifj+tFJHoLeWY1+k/aE50nKWD168Migq+keTquUuehRKeVLqc
         J7/6ekZl528VuxTAzTBF0u8FAPNDbE7b4xCPEGhRmhQcYokO9ZMWqGyDzbdCE9M/UNT9
         P5+Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=uJW9RQNu;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::1 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from LO3P265CU004.outbound.protection.outlook.com (mail-uksouthazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c205::1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-9480bcaf976si42290241.2.2026.01.20.09.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 09:12:39 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::1 as permitted sender) client-ip=2a01:111:f403:c205::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kvNe/XqfxKhgEoOe5BOr6sBcP1Xy5PMdl4LFOBWLVCFirfoILCNwTPDC/ZUV5dWBzOurSpssiZxGSn+GnFPYvOZ7xRlS3W9JSdw9NC1cjPQR5zoENFwbh+kJBdP2yQ4GDcxV1f1HKGF211ghLG5g2TdHnAaApQBa3Y4io3ePa+4ufGNopnzH3PmM8sT24t1DGLvPjO7tMUmBD6dtEpExIwKdnEf4aHprJTrlTFTZ3PiEIiLx8kHZ38uFVbMK1jVM3P7sX7nOQZQcPWgN7nl/nWbpKFhPt4mCIJYsB2V+L2srriwIlthkJS/RtJAOIw15lCOrFGk36nh1MBDnEdNqUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2NNRqb23Utmc/V0dkcVb0HjsJhxSUJb5OXrhCNNH1AE=;
 b=jWZNnQvZk2+Ez4N4pxVmOjBOj1IuepcJd2LcOtBjCTLj5TydBJQkfsGbwr07hKA3VEk7nw48cUe9ef/mgbD5RqJIV3B4AmSsEfIfxEH4xXhxqDYRNnT4wPh/UwmGIUTWR4PoetHGCcaeAaWWvxNMyu+2JFurzAQAA5QNhyPEQhqqnjRP2CN4M5dQcdXXsLN1E6tnniGk+dl8TX0juWCBLfPQI4Qc1TJLnCpaHVDrzP6GrHCD+v+PWfAgnjBfVIiGnAf8fhhqSHvStbjz+JDoLSXd282f+RrRyVsS4BXHjmyiQhO+iGeBH+YC+K1gUt3C3303goQ2ixOwSTWjc8fKOQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by LO0P265MB3274.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:168::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 17:12:36 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9520.012; Tue, 20 Jan 2026
 17:12:35 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Tue, 20 Jan 2026 17:12:35 +0000
Message-Id: <DFTL1VEGDRZH.3SRFEE9L1XGEE@garyguo.net>
Cc: <linux-kernel@vger.kernel.org>, <rust-for-linux@vger.kernel.org>,
 <linux-fsdevel@vger.kernel.org>, <kasan-dev@googlegroups.com>, "Will
 Deacon" <will@kernel.org>, "Peter Zijlstra" <peterz@infradead.org>, "Mark
 Rutland" <mark.rutland@arm.com>, "Gary Guo" <gary@garyguo.net>, "Miguel
 Ojeda" <ojeda@kernel.org>, =?utf-8?q?Bj=C3=B6rn_Roy_Baron?=
 <bjorn3_gh@protonmail.com>, "Benno Lossin" <lossin@kernel.org>, "Andreas
 Hindborg" <a.hindborg@kernel.org>, "Alice Ryhl" <aliceryhl@google.com>,
 "Trevor Gross" <tmgross@umich.edu>, "Danilo Krummrich" <dakr@kernel.org>,
 "Elle Rhumsaa" <elle@weathered-steel.dev>, "Paul E. McKenney"
 <paulmck@kernel.org>, "FUJITA Tomonori" <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
From: "Gary Guo" <gary@garyguo.net>
To: "Marco Elver" <elver@google.com>, "Boqun Feng" <boqun.feng@gmail.com>
X-Mailer: aerc 0.21.0
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
In-Reply-To: <aW-sGiEQg1mP6hHF@elver.google.com>
X-ClientProxiedBy: LO4P265CA0089.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2bc::6) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|LO0P265MB3274:EE_
X-MS-Office365-Filtering-Correlation-Id: e515a239-a584-42dc-c9eb-08de58471b5f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|10070799003|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?NDBSWHNqVlRvTnpmb0lxNlZRdXRZUi94UDZpUGhwRzNKZXU2ckdCSUgwdE45?=
 =?utf-8?B?a0lYYXJJQnFVVWVhT3IwODg0cGtLNTJnWE1RSk1JUVl3aVY4NHkyYm9ySmJL?=
 =?utf-8?B?Q3UvZEdaeUV2L0VXak5KV3pobyt0SEZoZStYUDIvdjBWWnVkaVgyMnFDYmxF?=
 =?utf-8?B?dWlKZ1lIOUp6MXZGT2hHTVFJWEZvdndheHRIS2lZRmdaTGtHb3VEdjF4UXA3?=
 =?utf-8?B?MUJ6bFlBMjM0d0hlSlBCRVhQZFhyaXdoY2JIa2R2TlFOODlGeTBra0hoa1E3?=
 =?utf-8?B?aStDNDM2cGJLenBad1c5WE00dWVrZDc2bmFFS3FTNENkUTlqeHB4UjR0cVBy?=
 =?utf-8?B?RjNiWDJWa0Rzemx0ZlZpV0JxbU9SOUdBYi9HRVpFVm1CZ29JQ3diYm5wVnJn?=
 =?utf-8?B?TG1YNytpYUM5Tkk2OHlMeDVKejMwZEkvRFhTK3UzeU4wZk9xTUp2b005MDFM?=
 =?utf-8?B?YnRRU1pmTi94MDZhUWpodlpkaWNJN0UwQkVxWWdrOUhWYWExbmJTd0VGV1kz?=
 =?utf-8?B?WFlYT3RsZU44OHk2aHNxbWZtcjNrYWF0eGN4ZU00ZDhOTXdxbHh2TWVzRVZR?=
 =?utf-8?B?elVZakwzS0p6dmJaWmhTbzZEYUR0azZnSXpkaXJJci9MUEVGQ2pSb3NhNWgw?=
 =?utf-8?B?UVdOTEYvUVo3TzNXeXN5L3hmS3h6U0tXZUl0aE8wSXVsdUU3ZWZsUDNPQ3U2?=
 =?utf-8?B?U2g1bkhLaHVqODFndmtDdzdBajRoREdhNFJsc2lqK0xlZEdLME85UjhlV1V1?=
 =?utf-8?B?MHNBVGY3TkpxbmQ1SHdoOXBQUlRZL0RGc3B2LzRJNzRCTnF5N0NIWG5CekQy?=
 =?utf-8?B?T2xER3k0RFErS3dqYkV6ZkFXbDg3bkZ6SkZPZEQxN1dGcU5GWkNmSTk4bGxl?=
 =?utf-8?B?MUFQSnZMNVJUNXlQL3JmbWI3ZkhvcTFjNmwxTWl6S1c1MldJLy9Ba2JQbU0y?=
 =?utf-8?B?UFliblpoT3pOeitpUmxXdWl3RDZKSDlmdTZZdlVOSUJCRXhOWEVrZjgrOXZu?=
 =?utf-8?B?Rks1THErd2I4QzNOYXVISWwxNHFOVk0vdnZjOHlyK2c3NDZJUXR6YXdTN3VC?=
 =?utf-8?B?RWFHbm41ODBBUExCNVY5aWV6TDZ2eEtDVzJ1YnBtYXROSW1ZcjJ1WEFpczUr?=
 =?utf-8?B?aG84eVR1SGZCN21xV3k3R1pTQmlSRktURGNhd2dsZUlHUndVek5ERERJaCs3?=
 =?utf-8?B?bG9UVEw1d2pLMVErWWN3Zk9lZEY5dzlRKzIxMXp3UDFtYkhVTmo5dGZJN0J0?=
 =?utf-8?B?bDZQTk9ZclVzaDNZSUloTXZUSFUwbnJabEc5MTEvNGo3UEVmcktyNjk3Smc3?=
 =?utf-8?B?QXorYzRCM3hsYy93VTYwNFU0UlJXNnpYMHRLbzdMTXFHd3NIYzZPdUZ1MFhG?=
 =?utf-8?B?b1RLR05xZ3ZhTU9XSGZQTkhDNjJsR1Fwa1NnUCtBK3pBVHRWRklRMmk3UDdK?=
 =?utf-8?B?SjdKelloTkhxMnIwWTJ0ZVJmcm9PclZKN09Qd0hrRllIU3gvT0ZXYi9jN1Iw?=
 =?utf-8?B?b0hNcU9NTkI3SEpGTm1QWFNRaUtrbVRybkV6b2lTTy9pK0p0bW1UQk5yZExz?=
 =?utf-8?B?Q1cwTVBJZUhuTzFsMnc3M3lENFpsK2ZHRzFHVVp2dVlhQjFraFZvV1hJRll3?=
 =?utf-8?B?YXEwSnY4TmZsMkpkOVVzTDZIWWpLNVZWN0gyM2s4SlJ0ZTRhSGdKSEF3dkxK?=
 =?utf-8?B?SU1sR09IWE0rdURsT1ZSQUx0S05BcmIwTDk3bzlCZjZiVmJsc2dtU3ozc3pM?=
 =?utf-8?B?SWJValNNaDVCNGlkSTJTeFVxUzR4UzQveFZmVUUwMDExakRjaVBNb1FxK1U3?=
 =?utf-8?B?QUNFVmpjcU9SUlcrbGNwMmJvNG5qYXJjd3NwS0JzMnM3MDNZL1VxcFFCTW9K?=
 =?utf-8?B?anJnUHlDVXVkMkpsVEM4NUJIOXVpcytFQ1J5MitKdUhwSWZqQnp0aXcrOWV6?=
 =?utf-8?B?NUFXYkJzcDFJdVJPVHY5eURSNThzdE5rS1kvZGdwYXlEQkF3amZ4RFhveFlr?=
 =?utf-8?B?MmZ4VUxOQUU1S0ZrRTF2VmYwakp1RUxUV0o5aFdDZWRLUVRrVGJTWlFWdG9P?=
 =?utf-8?Q?X3HzH8?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(10070799003)(1800799024);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?anhIbXp1ZDVudGdGWEQraUd5eXo1QUluSTA2dEFTNnlLNUw5eHo0cVBrcUEx?=
 =?utf-8?B?dnd3c3cyMExwMDNjdHRVckpKM2pRYkRBU2QrTlJkdVFPU2grVHprd251eTBI?=
 =?utf-8?B?SSs1Yy9JSEZuU3FHRk83dUVtbUs5Mkl6VTRqZm5qNERrY205RmNVeVVrc21h?=
 =?utf-8?B?T0lRK2crTW5Nem9icktROE9pMGppVFdoS2U3K1QvcGQweGZaNUtrRUNyeDFY?=
 =?utf-8?B?blBVTmdqOFpTeVhMV0pLNFNJTDE1N01iUk84WkplOHN4WnNIbzh3ejJmamxa?=
 =?utf-8?B?YWpmNzFKYS9ybHNBSHRkcWc2b0p1ZGZnNDhoRkYvNGJKdWlYQ0s2Q29BUGhB?=
 =?utf-8?B?Q0VlY1lUdWNLRlBJRG9Fd0hZREpkaWllSUFKVFZGUkYzK0I5QnNpT28rNGpv?=
 =?utf-8?B?MzF2ZGRCNEc1NWhLazF4L0pOWVh3VEJRanMzbnV1RmpaS1lsU2M4TjZiOHNQ?=
 =?utf-8?B?M1YzQnVEbkx4VVRZT013SkJDaWRxMVk4N0ZVT0ZIb2gzNnU0S3o3SXNsUVho?=
 =?utf-8?B?Y1JwUmM3NUxRZjVBRFVjMXFoeGUybENDVk1ucFVNQVVTWjJQVXpZMDVEV0hV?=
 =?utf-8?B?blZ2cFpEWk5pUDF4Z2NLK1VsOHc5ZFQ0R3dHS21OQzAvRzdWVm5HaGZRWjJj?=
 =?utf-8?B?bEZidGdrYzdkTWRZZ0d4VjlwcXJYb01RTE9uUmhKUVd6cGNDTDZvKy9zRHZU?=
 =?utf-8?B?NUJZNkhQQnUrQ2RBanBXalFkOGpudXhIejBieEowUU1RZzh6eWsrR2VmbkRV?=
 =?utf-8?B?M005bEtYQU1KN0xDb21QMjBWS1d0YlpleHFEejN2VmJvdFZaTEEwaytheGV2?=
 =?utf-8?B?Z0M3MnZ1dmwzTWpwK0ZMNHE3ZkNtOXp2Y0FqaCtDMHB4QisxTkJnQTAxQkg2?=
 =?utf-8?B?TDVGU3VVdU1QOHVkVkxRMWgyQ0N5WkZqU1M0QndLS1Bvd3YrLzhUMloyaXdP?=
 =?utf-8?B?a3JnWmZZcjZORFlCU0VDNm9vdEtDb3RSMWkyY0FCUnVyNHRDZkhBTHBBbklO?=
 =?utf-8?B?dUFqWXBWSDNVMkpGdm52UkszTURnc3pDbGFsQktyK3dtYTBUVkVaUHZ6c3c3?=
 =?utf-8?B?WEJId2F0dzJ0ZHhYTzY1eHZSbFJxWUVRNW9lT0NpU01xc1ZQTVRsYUlBTmdM?=
 =?utf-8?B?VXZneFlNeVZWWmI1L3pDQ2VEbDlQdjg0djRDa09UWXVhdjdZbDEyMm0yNVky?=
 =?utf-8?B?eWFWaG82NlJRY01zSThjc2ZoNCtBdnJZMUJzYndvVnBpWEZqQW5kV1JtZFVM?=
 =?utf-8?B?NUpCNWp4WkZLYjZyUjhwdHRidWdYd3ViT05nMk1DWUdzSjBGd00yYTIwV1ov?=
 =?utf-8?B?c2ZkRHFyMGR6aXF5K1Z0eC9pSjgrQWdpdlcwMVZMcGRxdDhzeGlFRFhhRTg1?=
 =?utf-8?B?RGZFbmJPL2xaUkpZNVdrQTRYcTlRcmVtZXJUTFR1YzFEYVJJdnhJdGtjUC9h?=
 =?utf-8?B?NWtyMnZVK0c4d0FDTlhKRE8xU1RSQ1M0T3BCRGVtQ0JTMEVBWUtib0wzWDVo?=
 =?utf-8?B?Nll6SzExemlxTk9DN0djUkw0alVLaGMvTSt2b0VNQmVDMmpQTkZIaVZlbWtP?=
 =?utf-8?B?Z0dIc1pDS2xTMHVoMGJzcWl1Q3BjTzVaM0o4TzRNbTJpUVdTM2Y1bmsvcHg2?=
 =?utf-8?B?bnVvSDdSWFhqYVVTWVcyd0ZWaVpzeDFHQUNuaHJuV2xWclhyOXNFWDZxa0p1?=
 =?utf-8?B?UVg0V2sxemRuYkJleEt0QjIya2lnZ292QVJjU01hTnlCZDF5d1NpR29oUnNF?=
 =?utf-8?B?QU41QmRZK3VFQVU2K0sxU2tRM0ZLWVJ1MEhnTUZUeXFlelZJMFpLSmMySnhJ?=
 =?utf-8?B?WGlQWEdHdDVRbk9USjUrNVBGN2p3QjEwaEtGQ1BGTkFoUTR1UkJDeVpQcCs1?=
 =?utf-8?B?OWRhZFQ2UVdUaUU0bEx4TXhYUmFxM0lLRlRibzBra291cE9oZ3pyNGlJb0VE?=
 =?utf-8?B?aGg2aDh0NExpYWlaZUI5bzdMUUlSdlYrQktTWURYU1RCMHA0TzN1dEpZMnRv?=
 =?utf-8?B?VHNrT3c3QnB3Y1pxWHdlOHJLOGVGNTF3bEpsdG5RU3JqOHRzYnUrQk5wclY4?=
 =?utf-8?B?V3VSV25Edm8xczFLUkRNS09zKzM5dVJXWDdrTndMR2ZMZXRFSWNESVQ3WVQ3?=
 =?utf-8?B?SWxJQXora2o0MCtkLzFTeEVHYWtxTE9saXdOUGdmbkxZUEZXL0lza29PWUdM?=
 =?utf-8?B?UmxrcXdUb0NXUVkxUVk3VnlPV3RHanpnTStKcVRxQVlUZzR5eVZvR2pFTHoy?=
 =?utf-8?B?Sm03djg2aXpIb2NRVFR6QmtHTG1uWjFwRGdkTkpMeEU4SGxlS3JiSkxieEVZ?=
 =?utf-8?B?TURDaDB0dkdJS2h3eFJmb2xKUGpFOHlSbG5ZaWdLNDFOWS9HNzhZZz09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: e515a239-a584-42dc-c9eb-08de58471b5f
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 17:12:35.9217
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: HyPtZNe/Nj3QSUgQPSu3YMyJEPreH8IG0MuqXRh9LevQ0aTeYH+bwSZjsIsAKFOehwaqVXBllVwHXwuh+KXBkw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO0P265MB3274
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=uJW9RQNu;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 2a01:111:f403:c205::1 as permitted sender)
 smtp.mailfrom=gary@garyguo.net;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	DMARC_POLICY_SOFTFAIL(0.10)[garyguo.net : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[google.com,gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERBCHPX3FQMGQEF735GDQ];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[gary@garyguo.net,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[lpc.events:url,garyguo.net:mid,googlegroups.com:email,googlegroups.com:dkim,mail-qv1-xf3f.google.com:rdns,mail-qv1-xf3f.google.com:helo]
X-Rspamd-Queue-Id: BACCF4857B
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue Jan 20, 2026 at 4:23 PM GMT, Marco Elver wrote:
> On Tue, Jan 20, 2026 at 07:52PM +0800, Boqun Feng wrote:
>> In order to synchronize with C or external, atomic operations over raw
>> pointers, althought previously there is always an `Atomic::from_ptr()`
>> to provide a `&Atomic<T>`. However it's more convenient to have helpers
>> that directly perform atomic operations on raw pointers. Hence a few are
>> added, which are basically a `Atomic::from_ptr().op()` wrapper.
>> 
>> Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
>> conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
>> named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
>> `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
>> `atomic_set()`, so keep the `atomic_` prefix.
>> 
>> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
>> ---
>>  rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
>>  rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
>>  2 files changed, 150 insertions(+)
>> 
>> diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
>> index d49ee45c6eb7..6c46335bdb8c 100644
>> --- a/rust/kernel/sync/atomic.rs
>> +++ b/rust/kernel/sync/atomic.rs
>> @@ -611,3 +611,107 @@ pub fn cmpxchg<Ordering: ordering::Ordering>(
>>          }
>>      }
>>  }
>> +
>> +/// Atomic load over raw pointers.
>> +///
>> +/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
>> +/// with C side on synchronizations:
>> +///
>> +/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
>> +/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.
>
> I'm late to the party and may have missed some discussion, but it might
> want restating in the documentation and/or commit log:
>
> READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
> like memory_order_consume than it is memory_order_relaxed. This has, to
> the best of my knowledge, not changed; otherwise lots of kernel code
> would be broken. It is known to be brittle [1]. So the recommendation
> above is unsound; well, it's as unsound as implementing READ_ONCE with a
> volatile load.
>
> While Alice's series tried to expose READ_ONCE as-is to the Rust side
> (via volatile), so that Rust inherits the exact same semantics (including
> its implementation flaw), the recommendation above is doubling down on
> the unsoundness by proposing Relaxed to map to READ_ONCE.
>
> [1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf
>
> Furthermore, LTO arm64 promotes READ_ONCE to an acquire (see
> arch/arm64/include/asm/rwonce.h):
>
>         /*
>          * When building with LTO, there is an increased risk of the compiler
>          * converting an address dependency headed by a READ_ONCE() invocation
>          * into a control dependency and consequently allowing for harmful
>          * reordering by the CPU.
>          *
>          * Ensure that such transformations are harmless by overriding the generic
>          * READ_ONCE() definition with one that provides RCpc acquire semantics
>          * when building with LTO.
>          */

Just to add on this part:

If the idea is to add an explicit `Consume` ordering on the Rust side to
document the intent clearly, then I am actually somewhat in favour.

This way, we can for example, map it to a `READ_ONCE` in most cases, but we can
also provide an option to upgrade such calls to `smp_load_acquire` in certain
cases when needed, e.g. LTO arm64.

However this will mean that Rust code will have one more ordering than the C
API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.

> So for all intents and purposes, the only sound mapping when pairing
> READ_ONCE() with an atomic load on the Rust side is to use Acquire
> ordering.

Forget to reply to this part in my other email, but this is definitely not true.
There're use cases for a fully relaxed load on pointer too (in hazard pointer
impl, a few READ_ONCE need depedendency ordering, a few doesn't), not to mention
that this API that Boqun is introducing works for just integers, too.

Best,
Gary



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFTL1VEGDRZH.3SRFEE9L1XGEE%40garyguo.net.
