Return-Path: <kasan-dev+bncBDRYTJUOSUERB3MEX3FQMGQE5Y6BZJA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EPKTD8qub2lBGgAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERB3MEX3FQMGQE5Y6BZJA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:35:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id B4DE047AEE
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:35:21 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-8c538971a16sf125087285a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:35:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768926920; cv=pass;
        d=google.com; s=arc-20240605;
        b=AQTHNcBks/LSK8Y4nxx0hjckGosJU4Gk7ugbN9c+Gd7M101LMO50aaPbls62g/kfe8
         qKRUwL/ZT4inE52k4gwtuBnfULM9edL28A35WK+CdpbVBiaalvp7UYKS5qg/OJe+6YEI
         iumgFcm5PuJfksR71KYehQWHLY3XsDj3Ti3rjTWyLv+uiwHBYrPkanOA6jGq5IfflGlb
         rc5V5/ReuV/0t7R412KFjjX6PAaXDPw159M5fzdjzlVShj3UKF+VdlDjbiS9OQVZrAyT
         C85SEf/oYDaFOlw8Zcy9PGmC6hNAgF29lEGDdxtWy5pKQJ6yPKoR1E/oCLnGvx7fNfu1
         KlRA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :to:from:subject:cc:message-id:date:sender:dkim-signature;
        bh=/kRER4A29lwpJZfWgKxISjmWaJOfp6V0d66oGJOr0CA=;
        fh=cF7f2XtW1U/eo9J7IppI98toWoxbR4Xx3W5SlzX4/eM=;
        b=T2ylSYCRtJJvHU/ztbhn45QmBwbsLtLl6k/rM3xLqpgXwqGr8dXTGYJ2ne6Fexe/e5
         QjbTFiJGpADPqq4icKRfG4u1M3ge4IRIDbTkvWM6ynqVvc6AWk7NQaxgXD7JXIJ5S//w
         KvBWMQh/dvw1vyfoddQy3PeLtkFgA9Xoe7Dvj25Bn46OwfR4CdkGPAHV60p51tC5AhYZ
         hwkN4oSBJh1BhlyW+IKsN9nzQ1pJb8filzsykH7EveIfblArdwr6unpJXLdkXAwxBtwt
         5MPGyMbfcUHIIdwpHqPqJRzYkwNaBO8jgw/zS14wv/T43Tkk0xcirq7aeLPnaP9tWMYI
         QAeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=IpME9Jnp;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768926920; x=1769531720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:to:from
         :subject:cc:message-id:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/kRER4A29lwpJZfWgKxISjmWaJOfp6V0d66oGJOr0CA=;
        b=MW7YgVHWn+6kIm9CKW8/OrMB6/jp6QznaYjW+Rdh7g8t4CYGaZGhOhJPMV0wxofo48
         NbP7t6BZjo9YXJZVO+bkbIeD7LeS4vjErIkTSYrNfxD5j7M/RgzD3qCb3qQZrYiME/Sz
         QxJT7IqPUZbC4iTZJMh7b3Ldb+5vBq/Z03k//PfPmHZDqVj7QEhUy50/HCBg4SPDeN1f
         UWpiH+1kbtVqWmfKL/O4hqfMZg0kSkmgLV7F6f5WahrR5/D8cNAucqPeNqSPQSDKvNzi
         Jpyr8dmIpIp++y2Oivji5QHBj5jF+OY75O5hXA831k3k8o0S7fGGYWRnpdsm955x5TOw
         Tl4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768926920; x=1769531720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:to:from:subject:cc:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/kRER4A29lwpJZfWgKxISjmWaJOfp6V0d66oGJOr0CA=;
        b=dhQFVnStk2pOE4Quh5dx1ElYJTF0L6R1QcmSzfG+VszE/o/fdaJefiRRUZHGp2FJpb
         lBcIdoZmKhvM0e0C+dTNHM7CpF3NB07n1pms1ZCRGBxbUV+oVBvbXqPdFy5Xnzyy+fKC
         DvIUA2ZB5f5SH2onWO9f9ARSQEAEGZxup16GWcfacArrf1sfkqJxnCZNUOT8768G4Dsz
         GzfjBf1XcA3CdcfYpGVg7Z/Ayr3RbmJzRpLG3ldR+3gAUihrcjwd5eiyg2SpVj+T/FX3
         v5vcZswdki9I9ZHdqV5MkP/+B6N9AzYka9uITy6WuTG6H1reeh9zr9B5swqWIGfBkFcz
         elbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVJet6nv/1RmIUAlHKO7PbsBBbNpEsD9FPcJsmff6fxcerVOPYlKt3ZIQ14f2OZXVmqiCTKvA==@lfdr.de
X-Gm-Message-State: AOJu0YwjntEs3bYbr+vWDrAK6/x4YFQNQUYHIEU6vvQARDlL8i65cBXK
	YVIC6qnwTxJWYvc8MDy5WAxgIxeb8N/NGjF2Ea1fuAqPGCJW8Dcpqd5y
X-Received: by 2002:a05:6820:1391:b0:660:ffff:da11 with SMTP id 006d021491bc7-662affaebfdmr705942eaf.26.1768915565445;
        Tue, 20 Jan 2026 05:26:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GUxr9nxJ1nGQTyW6uw+I1RD/M+3fFulJ14bkpgqK5XsQ=="
Received: by 2002:a05:6820:38e:b0:661:1c64:96f9 with SMTP id
 006d021491bc7-6611c649b34ls1627210eaf.0.-pod-prod-07-us; Tue, 20 Jan 2026
 05:26:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWvGXMexJeqSbIEwcWUFekH1v5cIOW5P2gZ/YGMErPWim5t56oFcKAb24wYuY1t680rpMCxcpk2kLA=@googlegroups.com
X-Received: by 2002:a05:6830:3902:b0:7cf:d784:5ca with SMTP id 46e09a7af769-7d140ab6afcmr970022a34.19.1768915564240;
        Tue, 20 Jan 2026 05:26:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768915564; cv=pass;
        d=google.com; s=arc-20240605;
        b=i0BLSVTeQ6H+SkqnPReBhdJiP1B1N/DRU6aeJqqR7IA1BqOodC4H7pjm4N71JQI1As
         z3QzGbwStSMiPJaoy+YutYcszF4nX8vr+i6TvbIo5Drl0KkNCl73xi7yV/rCTk+8xfNT
         P1lsB+ru5RILB0Vzxzt6rJpWEwe4M5y+b8Ha4/YXwnrXku1kd5a4s+LVAm3wrzc0Tslo
         X12YfYsAWr53aeYW39f7YDnMVSw0Z2sZLBuvS4z9K2opSTyulvl5/WElk2QxkbzHaCqm
         s6M7WlUPcx5XWHQKEpjWesBwY8iVSEnVLz7EZbYxpLwkAJHyORczftza6uE8R2hj4kdp
         roYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:to:from:subject:cc:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=lyBYOzLiJcFMD727b8aIxupmHcGtENy5h6NX8gvB05A=;
        fh=QD2tcYjdZSxvAc7OsizuWCoB+dOSN2AGfIkysM9/RIQ=;
        b=VbeUPYIeO7Ol8c+2pLrTHwUYW1Hv3s6fx10nm4U70IOM/H4eQjDpi2+AR3hrV5CSII
         DuCS5p+vWJpsCuywohKSW0zw2fgUNGlWTGiBGNO2ruVb+ApraR03DOrnzjkqV4gyk7vK
         MDYDIJTTlsc2oDqj32mdGiP4tIc2+6j6wXAIQk0AfPj2KC2gfdEa5vkSDP4S5t35/AvT
         oAZHWNxlgJG8XvqjZJt+Y4OC/Nd2eXUouSw89Nzzd1Xvgeelkh+bEDH4jErrmlhb6/4i
         qh4qFyjP1GVig1kLzYDLsr9CpIXGu3xYkWHPmISMytOyHX9+3CxE/E7fzjjnhoMEuHBj
         0LTg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=IpME9Jnp;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from CWXP265CU009.outbound.protection.outlook.com (mail-ukwestazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c206::3])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cfdf264e95si466230a34.6.2026.01.20.05.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 05:26:04 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) client-ip=2a01:111:f403:c206::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=O1+UtA0oGZbqutPwellowHkUHNxJFE46IzMCOiwPHwXWKyWA4+M/yqEawB+p1T+8eAuS7URi43XgchytwPQR+y2slhTLDE2YkH3rNK91yMKs+e0xfqUuOP23XZyfEHkF1zV1mkRxtjfWvE8EtJErh2LeN9Ezcqyd3/lw4MyqXBoeKBHGi5cIE8lfsws340dr6ErAZZaNIYAkmA6c/CLVsrqf4z08VU3xL9+aNLCtskhh/jg79HHl1RZ+P5s0Yp9E8ae2vEulhFSye3EU4QwwLMupnR/iG11qjCJQUNWmJ+o7KF5FNBkEWV8Z3n86XZrswZifynKxKXyZSm/jLGJ74g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lyBYOzLiJcFMD727b8aIxupmHcGtENy5h6NX8gvB05A=;
 b=guvxHq2dvoOgeMkQPNnaJo4UE+Yht5ohZ37cE0G34fvbdTioieK56Fr7B4ZIXRjEX3QOX5w1G20wGUO+N/I28SvDmi+OzSwj6OAkq93tpNym2+8MrCGIQzwmBT1utx3KsUEpkB0s8O9CI5qBKddG/9+hVECjK36KLui2vheBhoaWNI2rvPeFdkxVFU03RYJ/IQjl7BqBqTVjmCQuA3K42UnRsUj7xI8WWBk34DKV4trjx/fNVW6BR66TnLVul5ytqD2Fc080mDkyrDYyhCW23w+cL80sJgczy27MEj2NSY8zk6vjEbcAd5F0BzwgMOP4XEtrP0Kd0iJwab57ETnkOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by LO2P265MB5086.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:251::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 13:25:59 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9520.012; Tue, 20 Jan 2026
 13:25:59 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Tue, 20 Jan 2026 13:25:58 +0000
Message-Id: <DFTG8D7VQNUR.2VK3OZ0R92MEV@garyguo.net>
Cc: "Will Deacon" <will@kernel.org>, "Peter Zijlstra"
 <peterz@infradead.org>, "Mark Rutland" <mark.rutland@arm.com>, "Gary Guo"
 <gary@garyguo.net>, "Miguel Ojeda" <ojeda@kernel.org>,
 =?utf-8?q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, "Benno Lossin"
 <lossin@kernel.org>, "Andreas Hindborg" <a.hindborg@kernel.org>, "Alice
 Ryhl" <aliceryhl@google.com>, "Trevor Gross" <tmgross@umich.edu>, "Danilo
 Krummrich" <dakr@kernel.org>, "Elle Rhumsaa" <elle@weathered-steel.dev>,
 "Paul E. McKenney" <paulmck@kernel.org>, "Marco Elver" <elver@google.com>,
 "FUJITA Tomonori" <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
From: "Gary Guo" <gary@garyguo.net>
To: "Boqun Feng" <boqun.feng@gmail.com>, <linux-kernel@vger.kernel.org>,
 <rust-for-linux@vger.kernel.org>, <linux-fsdevel@vger.kernel.org>,
 <kasan-dev@googlegroups.com>
X-Mailer: aerc 0.21.0
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
In-Reply-To: <20260120115207.55318-3-boqun.feng@gmail.com>
X-ClientProxiedBy: LO4P123CA0643.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:296::10) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|LO2P265MB5086:EE_
X-MS-Office365-Filtering-Correlation-Id: b3a92e28-a919-459f-a699-08de58277335
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|10070799003|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?ZncrK1pMNnZsdWMrWFFTUlplK0FFMnNBMWtKOUIya1F5SVpUQ1RLT2pRRHN4?=
 =?utf-8?B?THlvYlNyNHU2TzZKNzMxaW1UdTlmZHRleS8yTStjN1Rad0poTFlSa0hGcDJw?=
 =?utf-8?B?QWpGd2xhK3laVDZ0Qm9zNnBBaHdIMk5jemVTSnJTK25zamhTWDZjSFpVQ1Vz?=
 =?utf-8?B?UG5JQ3lLTGd6VTJLb0ZUWkNtV2h4THVGWnBtenhlM0pwbVkrUVZDL1drWVdr?=
 =?utf-8?B?ZTA3V3B1a2dUd1V2M1paRXRMWEtpZFVjRGZla2hHNUJ6MlNRRlNoazBhc1lU?=
 =?utf-8?B?clM4K2w0RmJsRVQwZFc2YU82NklHNFZmS3dwWWZET1N4ZkZOclRCMHlLYUl6?=
 =?utf-8?B?cHVFYksza0NodlNGU3Q5Uy9hcC9reDJqNUEzNXNZd2xwSTdSUlB2a0V6bzA5?=
 =?utf-8?B?bzJOWEpjTnlJWTEyWVhUb3YrZEM2eHJSUHRjRDdmdVU1RHdLbGdnTHYzWHJ5?=
 =?utf-8?B?cVJrR2k2UnUrdHpsV2p5cTQxNERxSnJSYnIxSUVRclNrN3Z4QzdjL25yMjEx?=
 =?utf-8?B?QzhIcldQWUVZVjZHUDJkQzEwOHlnQ3hWNi9XN3RraUhaNUJJd01mTzkrYWNV?=
 =?utf-8?B?L3lKR3lqVU5vVTJnK2NGRTlhaVViVEg3OGxJdGRUSzlHYXpTUGw1KzJzL2p3?=
 =?utf-8?B?NUY2MEFjbnFzZ3FXZTJheVB3aTVDTmhXWlJxUUtSeUFLcXRLTDRyZ3ozLy96?=
 =?utf-8?B?OUpVSWM3ZGFRMkVtc1N4cFg3dWYvbVQ0bmo0dFovSDJWVWVxVkZPcmJwL1dD?=
 =?utf-8?B?eUo1MXpuaUZhdGlod1A4R2huU0daRHNhNmxKUzJjdWR2MFVpRit3K1hoZFBE?=
 =?utf-8?B?UVF6bE9lTnVaVFc4TW9KTUJwRXVhWkhHT3ZRQ3htQlROdmlaUEZZMmI2SmQx?=
 =?utf-8?B?MDdQWXBIMDMwditLTzBiWDh6dGt5ZUQ3eVpJSzVDb1JQZ005UUxSYjBUUmc2?=
 =?utf-8?B?K09LaE9EY01zdGw5dDc0ajJlWFl2dmFaazFoRWNoeDZVNU5ZM0tFOGZxd3k0?=
 =?utf-8?B?M0ZqZ0FaaWZRTFlaRnNGUHdiNjVSd1p6aVdwTVUrOHhXSGtEbVJYMkNzeWpo?=
 =?utf-8?B?M1RmRkxBb21McVR6U0tCUGlHRjk2OFloNGZiWjgyZ1B3b2hkcTRDSytvd2ps?=
 =?utf-8?B?L01NQjNJMlNNMURCUGhvR0hpQTNwUE45VHdKNXBSalVOSkdxSms0em52d2hR?=
 =?utf-8?B?eEtPQkJWWnlKZnB1ZnB6K2o5WmxKUEV0b1k5dXd6MTE2NFBnV2p6TmFqMXJX?=
 =?utf-8?B?UTl2bEpuUTZ6Y1pZT3JkZ3BIekxXYnJzMGg4d0xsQVg5d054RWRLSjZwcWc2?=
 =?utf-8?B?REhSdWwrZmVaSGJ5MHVFbnhDelRoOHQvTmdPTEpVT3A3alpmNnpnSngzTVdU?=
 =?utf-8?B?NXd5SnlRVTBtaVZFM1AyQmpzLzVYakJObk9tL213M3Bsd1I3dG8zK25Gdkhq?=
 =?utf-8?B?QVg2Vmg1QnRsM04wT0JZNkJHMjNHUWFnSmhhbFlqZUpjSlF2MkNjTUk3cWl2?=
 =?utf-8?B?N0l0SCtvS0hlMnFQUldEckxrK2hyb1EwbjdRRXM5K3VDVXMza0RERUtwaDZl?=
 =?utf-8?B?c1hYaGJoR1RQbzhKdVpGbi9oY0laM3NjajEzeThQWlRvT044akltbGZhSWtN?=
 =?utf-8?B?eVJwb3JGMEpkVWlqTTUxY2I3Wm1BTGc2eE9lMzFsMDE4c3Q4R3lKV1R5WDRY?=
 =?utf-8?B?QlQ3QmlaUXYyZkdsTk9Jb294TTNiNVdOYWcwc0JWMWo4QXE4M0dUTC9DS3da?=
 =?utf-8?B?MGJIdFBub25oaTZaNzRkV0RuOW96OURQS3BVaUNqc0Y5YjBaTWdQaEU4STBO?=
 =?utf-8?B?ZjNDeWdSTnA5WW5hMjZyOHVBVGxBVEJDY0JqNkwzTFRRSitkWS9QZndET3J2?=
 =?utf-8?B?UlJwbldEQ2g4dUllVVZIMjgzNWNadWtyelNqQ2tKdGwyVDFBT1I0RDlPYUlL?=
 =?utf-8?B?MFE5SGZ4TWFlVHdFaGpwVU5RNm5BeVd6V09ldlVOTGlvaFozY3I2S3dLZHNT?=
 =?utf-8?B?RXpGSnVhMlpkQU8zYnJQYW5XWEZlNkx0SkR4MTJWWW1zbEVoYTBpSUx0WWw3?=
 =?utf-8?B?WU5MU0ovcXp5VmhsanM3cEJXenowSEp6R0NSb3U2Qi9telZ4dHN3bW9JUWxt?=
 =?utf-8?Q?SzDg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(10070799003)(1800799024)(7053199007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?SWkvMHo0dFNteXE1ZHJFZXZDdXZRZ3RaaVJaM1Q4WFRJVXFUbnZISkNQdGti?=
 =?utf-8?B?aVRnb3VoVlpoRGx6SFc3SEx4WG1NY3RDWFlwVVNFY0R3R20xSmhpdEc1eGRK?=
 =?utf-8?B?WVZkL1ltYWJrQ3FtQkFGeG1HV1lhZVc1cDY1ZnArZHVaQ1V1cGttdkVFWm84?=
 =?utf-8?B?cm82L1VncUxCbkFOSVlqSXBlUVVFbC9aRFo1YlY1WUtaaElQdHBOdzY1ek1v?=
 =?utf-8?B?UjVsNjNVZ3RQQkNMREwvTEZmNzRQZU05Sy85Rk5FcStlY2MvUGU3cDRoQTdv?=
 =?utf-8?B?cUc1VEgyTTZJWVQ1dzRBR1JnM2ZKb1JSY3JWazZZaHpMcEFCWWtKM2Mwa2hD?=
 =?utf-8?B?Nko3MWIzU2UrYjh2TmpVaC9hN0RYU21VKzduNlU2OXFxcHkyU0pDa0FGTk1k?=
 =?utf-8?B?cUt1WTNTSGZDMmFaM3Bzd1RpZzRackdmSUh2NlF5d2E4T1VXSThUSW1QTEpB?=
 =?utf-8?B?N1ptWS9CRTRhK1JaRVRBNzM4b2plOGlhOW4vVmM2SmRGWFFFS2JOcy9RcDVw?=
 =?utf-8?B?U0xrNjNPZWtrdnJCY1ZXYjdTNWJ0NUZ6dTlJQmQyeXdJdjJpczg1cnk1bVhs?=
 =?utf-8?B?YlppaytFQkN3ckZScWQrT0xjc0VzV0w2cXMxSVpYTlBzU0thcWQ2ZG1NMS9F?=
 =?utf-8?B?Tm9ReHppa1lFV0lLYm42VFdoOXBua1UzQitsSmVUbFdGWHhQVjhka3BxVjhw?=
 =?utf-8?B?U3RUbStLNGZMakJpK25Jb1hZNytYT2lzNmd3eGxzTU4rOWwzckNzU1BZSkdl?=
 =?utf-8?B?WDdBZTRoemM4UE5jNnZuZi9PeWxMOC9CMGJ2QUFWa2d0bDRHank3bk5aem54?=
 =?utf-8?B?WGpmdjRCbnFSQUZJK1FWOHF2QmJVN2lmTzU3WG5vNWhIWjM1Y3h3N3MwRHpU?=
 =?utf-8?B?R0dpSi8yUzZIYlhxSmlCenFvMmM4b0xBWlRFQWVsWjE3LzJTWWZEdk1SenpH?=
 =?utf-8?B?WXhaVktqeTBVT0o5MVlHU2YxTlRoYWN2bW1HNUlTN0hwUzZCTjNYSXkwY0Ro?=
 =?utf-8?B?d3Z3aFFKSFI0Q0lOTGExWjArVWo2QjN1UWNqbFY0d0VvOXhkR3NqY0tUSXNv?=
 =?utf-8?B?b3Nrc0xSZkVxTzFGY3pBVW1McWU4eVFaYWlQcDhibk5pbXdCTFRheG5FMmdo?=
 =?utf-8?B?TlVRL1dlRkltQnZDR2s1emJxWTZVSGlDMSt2MFBVZUVBb1JvTFROZldCU25K?=
 =?utf-8?B?c0h2T0NnZlpLVktPWWpOUFlUWWdlaG1GTDYydnpFSUlQV25XV0x2MWJRYUtv?=
 =?utf-8?B?YjBBMUZIc3A5WGJsekgxYzM4MkJOOGFIdXhabEJuQmg4eUZTMUJJUksza1B0?=
 =?utf-8?B?dndyeTl1RCt5V1dvc1FRZWZweGdLWTNVVTh1VHFpMjJFZkljRFBXRVlSOGhk?=
 =?utf-8?B?V0Uvc0xWaEJORUQxSUpYK2Rzd2ZybFo1Wkpmd2trOUxCK1J5MEdtT2dUdjdk?=
 =?utf-8?B?QkdqL2QwUkFpMUpXWE1vRUc2bkwvaThpTm5wV01Na3BhTFgyOHQwV1VyOEVv?=
 =?utf-8?B?bUxrZXh6U2lsZndpMmJ6b3M1Y0VNcnlJbmtrNy82MkNDcFdsSWlGKzlxSDEw?=
 =?utf-8?B?SXdmaWlua0JXVVdHUFNOalExZWJSL2JONnpWeHF3RFVqRTZZT2lkaFNKUlF0?=
 =?utf-8?B?Tkd5d2dZSmRZTmVOZmxiU2lRWURwazJJUDBGdWlLNWp5aFR2eDBuamplZEFZ?=
 =?utf-8?B?dlBrMnNSOFFGcjVDck1DRjV3VWVyQzFJdXBvcFZ4dDBPR2xBT3pvcmhDakxt?=
 =?utf-8?B?dHhjUUZKTmx1WWtEb1QwSGMxMFJ2K3hFWXRObkVEa0N2VDl1N0x0NG9hUURU?=
 =?utf-8?B?MzMwK1dNTWhpdW1oMHZjTHNuUFdxeFdEYjU1KzU1RWQyWUU5dzYxLzBLcjY0?=
 =?utf-8?B?TmNwSFhkREFjZUtPM0dudW5mMWx3UjQxK2RselhUbzF4eENuc0ZTdVp4RUtW?=
 =?utf-8?B?WFk3RHdCV3R5d0pabE5BcS9EZEtBQ21NYTNIWkdLSzhIYm5UQmlhOS84cFpZ?=
 =?utf-8?B?M3J6aE9zZ2tQcWlYVEtuYWY2UDJwMG5XRzZGM2w2RFAxd0xwS3duczNvRlRr?=
 =?utf-8?B?a2ViVTFzeURCM0hpeWVKL1J3eEVMZXNiTVdaYnZmeXQxdWJ2eGJJclkxRGZ5?=
 =?utf-8?B?R3BvYzlwbGxBdkhEN1N6aEdRTWhyaWdwSUhlaDFjYzRsTUpOQUFTZXIwUS9D?=
 =?utf-8?B?Z3M3clBLeVZEdG8rcUZXNWxXN1BKT29SZDdKa1RiSGhLN1piSVI4L3FOQnYx?=
 =?utf-8?B?Sk11VjF3YTB6N1BnSUpUZjUvNGZNWnJwVENScWJvWFZ3cXc2clpWbWM5U0xh?=
 =?utf-8?B?cVV6UnFKWkk0NHdWTmVHQlZPNFRCR2RQMGFGRkpyYmtFaW80NS9JZz09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: b3a92e28-a919-459f-a699-08de58277335
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 13:25:59.3791
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: oUn9MRdJ6hjSjQU3Xx5FPEq/4qkz2IEq3sGrqlhq/LnMZ/Q/dCCT4CAfIyhpC7Y/Z7bDN26nbCFh1cmDxmpfYw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO2P265MB5086
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=IpME9Jnp;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender)
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
	FREEMAIL_TO(0.00)[gmail.com,vger.kernel.org,googlegroups.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERB3MEX3FQMGQE5Y6BZJA];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[gary@garyguo.net,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[kernel.org,infradead.org,arm.com,garyguo.net,protonmail.com,google.com,umich.edu,weathered-steel.dev,gmail.com];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[garyguo.net:email,garyguo.net:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: B4DE047AEE
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue Jan 20, 2026 at 11:52 AM GMT, Boqun Feng wrote:
> In order to synchronize with C or external, atomic operations over raw

The sentence feels incomplete. Maybe "external memory"? Also "atomic operations
over raw pointers" isn't a full setence.

> pointers, althought previously there is always an `Atomic::from_ptr()`

You mean "already an"?

> to provide a `&Atomic<T>`. However it's more convenient to have helpers
> that directly perform atomic operations on raw pointers. Hence a few are
> added, which are basically a `Atomic::from_ptr().op()` wrapper.
>
> Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
> conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
> named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
> `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
> `atomic_set()`, so keep the `atomic_` prefix.

I still have reservation on if this is actually needed. Directly reading from C
should be rare enough that `Atomic::from_ptr().op()` isn't a big issue. To me,
`Atomic::from_ptr` has the meaning of "we know this is a field that needs atomic
access, but bindgen can't directly generate a `Atomic<T>`", and it will
encourage one to check if this is actually true, while `atomic_op` doesn't feel
the same.

That said, if it's decided that this is indeed needed, then

Reviewed-by: Gary Guo <gary@garyguo.net>

with the grammar in the commit message fixed.

Best,
Gary

>
> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
> ---
>  rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
>  rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
>  2 files changed, 150 insertions(+)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFTG8D7VQNUR.2VK3OZ0R92MEV%40garyguo.net.
