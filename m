Return-Path: <kasan-dev+bncBDRYTJUOSUERBRPYX3FQMGQEHXWEV6Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YFLuIke8b2kOMQAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERBRPYX3FQMGQEHXWEV6Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:32:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 096FA489DA
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 18:32:55 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-888825e6423sf119827646d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 09:32:54 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768930374; cv=pass;
        d=google.com; s=arc-20240605;
        b=DqbpoHV8vY7C/fEA3Nu5DBpwBLlBPairwkAAqsvQgR+0V4PTf6D3kyNlDV7boNPtyU
         KkIhF2l3D9lOlZwW0//5mDqCxmbH/QH92F+U6lAFDnDG2BVOqPN9SUq5xCzuaZ4+gqEn
         kluHJYKGPFGHVSV4WV3PNP4+/oyBbqvWMcRNcox/ItPg5Bwx2iQpWpFo/Cv1gxoRqXSy
         /QFmxBVDDHVTbwapvt4y6Pi1EdLDPOBcrZeWTYQndXzEEbcFhMuB63rNuXKhfMUyKtE+
         JPJoRIOjDpf8gsJcuf/nub2R75GkLSjxS6uv3PCKfDkibBxPdK+GReicPHUhet6G2ADe
         vXHQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :subject:cc:to:from:message-id:date:sender:dkim-signature;
        bh=1gouCjon8H0BVkzbpZPfoAbA/Nmcdqc4LDfHJjK3FCg=;
        fh=fwM3iEz39d5GhU2NJWdaTFHEYTNnsqQgxCJ69Klky5g=;
        b=RkF1slGRXZh9WAvCVnrBjwpB6GFnKYQGeUh8wOb8ZbMWGniSFJ+Uw1A8oQAY5dVw6m
         Y1Rhcq1X5IkzowbO83GEexk24FooBFz/zEQ+Ji6vINXAAWLQB1bNT3mQsNGbfFAEYNUt
         hdhXyDX0oL1xKkDSnjYLqBMNtTwCDk5iv30KKtVMu+UsZXIL2zoU6Aktm7WNLSxNRIR5
         Vyx0SBdwFywT/7+7GcX6nNPiuOD7Kb1mVerT9U3gx8nlPf/nrLMV7OE47ewSt3ddpdZN
         BU4Eh6iHKDXRjmYpTAMdBHpFZocRVScc6kIWPBMb/79nFj2eXfj59t81iYUAWYMwJ+0g
         Toyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=qNDpBUIt;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768930374; x=1769535174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:subject:cc:to
         :from:message-id:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1gouCjon8H0BVkzbpZPfoAbA/Nmcdqc4LDfHJjK3FCg=;
        b=NLe7dsLikcKY/xwiwiNN3lxmB3w0ZJkmPQs/SiV2mxhz9sy7i4FAm20VB4xkFCdYTW
         fn3Rf3tz+Y7wFqJc4wjCSAKnGbwCmNGo0KoaAVyvof2cbN0hG8gEOGKhOu1v2JHDKK7v
         CibQM1ge9EAsFaZB7f0aDxazExVuMhRydMD00xtg/WsBpWD/t94I6G7DSCYQKf6MWQZI
         XoIIZwuTmDSoFao6uFZoA5v8f2KIDexmFf879IRetNaoHUiHrDTiUTDmHBpssMvGdkOF
         C+r8VPeqvbTVDp89Uuvt6qvOpfqSYnc4NOK70Hb8u/fxEUpdzpiFmcAP2k5h/gexHDc1
         9Ilg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768930374; x=1769535174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:subject:cc:to:from:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1gouCjon8H0BVkzbpZPfoAbA/Nmcdqc4LDfHJjK3FCg=;
        b=X6Xs92dPosEDAJkC+n3F8ringL3nP4UpEjapWoPi0Fm4fmTbpL+iyBjkUUn2TK/iMP
         68TXjo8nuOzPr/W9FCTYUDDElZHICdQxnPaViJZMW8OJ92D4Tg7lbFJRktWbgK9vdnIC
         pnFm8dOmR7E6QlmNyRKq9tjm8YlO6uPqK0H1OYAeBRg5VNLpQX3D9B26euPw8Rx23GFt
         fdD34h+82u/UEfdHodeSANZpouXj7OeHsuLPL+pNBqDwfzDzdqwiXsbBlwnPSoVQRKa8
         eP4P+8WT9BaWBD+r2SHEfNjWx2CvxI6wSqS5H3530Q98MNqyoAHGji3DxYEDANSaMsYK
         2ZLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXa/PN2VUwSybkUSG2pNAazGtrWGVCDUCjiaRaMpMAAZxqBdntkq0YxCTyMKBnWmu3Ji+tFmA==@lfdr.de
X-Gm-Message-State: AOJu0YyKPUBns5BJw84pM2ZJ/vHkrCDXIQ0/Rv3alSKoAe7cB0052YWg
	yj5PnBoTo0087JjZSmU0xqCOqepA9e7NzuyPvqUx3ZkOV5TCzVnK6jPM
X-Received: by 2002:a05:6214:2687:b0:894:647c:d044 with SMTP id 6a1803df08f44-894647cd2e3mr34186276d6.19.1768930373581;
        Tue, 20 Jan 2026 09:32:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GCGiGZviGLVNFBUaodRVyPWRR1tUO39xp2ei4UceV2+A=="
Received: by 2002:a05:6214:1c09:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-894222e7986ls101096246d6.1.-pod-prod-03-us; Tue, 20 Jan 2026
 09:32:52 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVss0TeGeZLVEx07Vkn6s98ceaO9/yy7Zs9SwG29z91Tx4SHffzOXJf4ECbI0gdp7i1OLRvmjd9aT8=@googlegroups.com
X-Received: by 2002:a05:6102:54a6:b0:5ed:8e3:b674 with SMTP id ada2fe7eead31-5f1a5525af2mr5066804137.20.1768930372596;
        Tue, 20 Jan 2026 09:32:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768930372; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wg4s0OLOslETmcGZyNcX8FJHVQ4Pv9nvTBga804grM2iVtZgiBhzFxZnmuquFBp7hC
         +bRuBfT3YnP+aY2gIrRItH7xeg7Ppks+DzfAovbmvOukikKJzLqmxIsOpmJz7blooedP
         YiO5QiU/OaW4VL0FlRf+fFfBE+TaJOlt+QHrbmVewXKh00sOdpXaIVrKpw/TLRILI8ZF
         FM4MtVO22uPZa5GVWRHX7f04XtntjuHXbDS3yc83+rPIOovSoZv2SpoJaIfY21Nl1b70
         6hS59o7JmYUXZ5Ppol/OYOdvYJkImm8/vPcslgLKz7DOuDZgcHlJMFYbRp+mXZGfsla+
         Ul8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:subject:cc:to:from:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=U0yLaB0JaizwBpWq4+GDYEd45+XXiQPzUgSVMgeIzno=;
        fh=GxOVJFYZhLUUWUnqYvVCH3g+eb/b8CRMGklKYQxEwSE=;
        b=CZhmpnGSN3x4Xe7PDLd830HLUaHEIKet5NS3AnSaMie8kMfZM/YiVaAiAPvGZZV825
         2w0VBa4qlzHODCaijE7qbcPNOPs1djp0EZzqoWxm8b+Hs3+J5c/IIlFG1KYFmmUofgFc
         uLqRP4AlTVeFsJUcxtHucBNXWezVuYEU8IFLADS2oe1cjOuZSfO5aLkw1YAwBSUaZOQb
         12ActV9yQiGaK0k81K/j/UD3N/cA1MZPCP6tdKBXS3P2HTnCNDHNkNwUqnZ1yqC49dww
         ILrpty5DF96gabFaCxHc4cNmN6YaVZI+RB8W+Am+KH/i8CX3EIvW70OWiyvedOu7kJuI
         W9hg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=qNDpBUIt;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from LO2P265CU024.outbound.protection.outlook.com (mail-uksouthazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c205::3])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5f1a689ba91si409829137.0.2026.01.20.09.32.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 09:32:52 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) client-ip=2a01:111:f403:c205::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OFfh5SDmrNeXmuwpoctfTir27HV3fyFgrQvzpFtlK1NzCcjoykRCxp6CcmYweSZZ7zCJklN8DgEObuY52hOhTkibWmBsvvVpHBfarPZA6y8LXBG0ac91F5iUxgQVicMLW2jFtz0proNQGQLlTFkSLa3wKr0XGG4LSFfkNQfUktD3wXchBn9SV4PqjYq0iZEFcOlD91+tByZSlFnaEyD+GIwUdPU1T/PEqRWO4kJRuGuM0iB3YyF5Hv1J3FctZ7z5y3B8Uhj/L4YItErQznyE1jxiJT9VVgIxc23i3EEdr0Qjg2QEQ7dBWEhSKsKT0kARSQjUPJOuEMClVntHX9Fhcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=U0yLaB0JaizwBpWq4+GDYEd45+XXiQPzUgSVMgeIzno=;
 b=kWApWPIKldD2fFO42EJZML6g10zV+HyDc1WbeEZLIaBZ6GfEcODWu0+HAtPdlmfo0dIxvTF7CiuFJwbGfR7OvQGj59OGzFr1f19ZqfcxrTecJFQNlIILH/9YF1ZLDluMQljCnQRdYp1DOSvXx0te14v6pY2U3LlLfbW97DLioiwLwzmZWg2suIhlnOWnhgMgex9mqXCemBMrhJ85xDpM9jmjXUB1aet2/2JUoBXlXkofV2Ys/tPATk5Wv5f6wLfFD6DOeZGF3hIoqU74wjzLTYpI8biRQsVOaU4c+OjRvS4pWx04ybFvyId6lPAC7GaXIAFVIUhUbhUUTurX0/Zq0Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by LO0P265MB5455.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:245::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.13; Tue, 20 Jan
 2026 17:32:48 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9520.012; Tue, 20 Jan 2026
 17:32:48 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Tue, 20 Jan 2026 17:32:48 +0000
Message-Id: <DFTLHCJKPBRM.2G76Y35NCHNZM@garyguo.net>
From: "Gary Guo" <gary@garyguo.net>
To: "Marco Elver" <elver@google.com>, "Gary Guo" <gary@garyguo.net>
Cc: "Boqun Feng" <boqun.feng@gmail.com>, <linux-kernel@vger.kernel.org>,
 <rust-for-linux@vger.kernel.org>, <linux-fsdevel@vger.kernel.org>,
 <kasan-dev@googlegroups.com>, "Will Deacon" <will@kernel.org>, "Peter
 Zijlstra" <peterz@infradead.org>, "Mark Rutland" <mark.rutland@arm.com>,
 "Miguel Ojeda" <ojeda@kernel.org>, =?utf-8?q?Bj=C3=B6rn_Roy_Baron?=
 <bjorn3_gh@protonmail.com>, "Benno Lossin" <lossin@kernel.org>, "Andreas
 Hindborg" <a.hindborg@kernel.org>, "Alice Ryhl" <aliceryhl@google.com>,
 "Trevor Gross" <tmgross@umich.edu>, "Danilo Krummrich" <dakr@kernel.org>,
 "Elle Rhumsaa" <elle@weathered-steel.dev>, "Paul E. McKenney"
 <paulmck@kernel.org>, "FUJITA Tomonori" <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
X-Mailer: aerc 0.21.0
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
 <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
In-Reply-To: <CANpmjNN=ug+TqKdeJu1qY-_-PUEeEGKW28VEMNSpChVLi8o--A@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0133.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:193::12) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|LO0P265MB5455:EE_
X-MS-Office365-Filtering-Correlation-Id: 8d8212fc-b26d-4465-10bb-08de5849ee48
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Z2VJcENGSmNnSWNkS2M1NkthSFVmaUlVbzkraE9oMUdqT1M4R1ZBb3ZEVUJa?=
 =?utf-8?B?d2c4VGpQMXlYbm9ja3VrSHhiN0tGQjBwaDVFbkNoVGlIMklOYStWcGJZKzRt?=
 =?utf-8?B?bjZ6bkFoclFMczlJRm5LMWc4OGZSbFZOa0pJemFBa1pmTkVOMC84NTNNWDY5?=
 =?utf-8?B?NHpuTG4vbHYzY2VJM0Q1NUJ4NjZNT0gxaXBBOFRjTVVHaGpwalNwTjdLbDg0?=
 =?utf-8?B?TlVVMVlzSW16QUJ0c3NuaWZvV2dtZDRmcFVqVTErMnJDeUdlY2pJS2w0K2FI?=
 =?utf-8?B?RzNKODFqWWt2VWtaelVlV3FNc1R4U2FmeStzZjIrWkNJQTZLcVptVlhKREtF?=
 =?utf-8?B?YUM1R3QvNjBzdzk3V3JDU3VyY2V3aXk1a2ZMZ1daUytMUngvN0N4R1RWWGp4?=
 =?utf-8?B?UDQyQ0c3T09SbXJsWW5NWmgvMHpMV0RaQnFOR2pMZTRiY1dOdHNaVzN6dm9j?=
 =?utf-8?B?ZTdqMmdabVNNd2ErdG9nVHZBSTV5bURRdGFOeW12Y1JZVVVVMnh5QkFRTTZ0?=
 =?utf-8?B?b1M1WXNsTEFvRE1oQ1VIRmhCdkFVV1R2ZWkxcWV2ODI4TXhNYzR5NFZaNDRG?=
 =?utf-8?B?SERvRUxvWjNzMEZYYitOUnl0T21CVjdEYU5oNkZnSFAyR3liSXR4T29pSGZw?=
 =?utf-8?B?QS94NDMwZlRtcjAvL0tjbjNpYnVXOXVxY1JRaFNMaSsyQ2VVVm5ZbzlUTWRW?=
 =?utf-8?B?NDR4NVZWSklPc0ZVMkJuN3hTbjR0ZitEakxwYW16Uy84Qzlna0lyN0hBTTNW?=
 =?utf-8?B?dWpjUzJDMWZBdFhWOHFVL1ppMHdQaWFQeTNxWjVVR0FualhYc3RObzF1YUJY?=
 =?utf-8?B?c3k2RmsyV2gyckQvVkJUSjNGWldNNjRiVkZyK2RMcmdYZnB5d2JRRVRXSnlu?=
 =?utf-8?B?M0o0Tml2NVB4TUdOVFlCaDhpVUFuU0JFdGNQUEZHN1NnL0FWVXdrTTVqWWZH?=
 =?utf-8?B?L0drd3J1ckZUVWJlWENVd3hOZVlBVDVQUituc0EyUExvV2NWV2x3V25oZTdw?=
 =?utf-8?B?T09ab3lDQTNldUIrYkxSOGdMd2hDTk13cmRtb0xyZVh0UUZJRXppVWhJS1Ix?=
 =?utf-8?B?Qkh1aVBiWGtNVTRtUlBkNytQTWxHRkZBSmE1eHJwOXk4YVJldTAydytNTkxZ?=
 =?utf-8?B?cUFGMitRQ2lpQlBHd1hzTmRKUnN4NHQrZmFiclMzcnJKNjVRV0UxOGdEOFlP?=
 =?utf-8?B?UW5zSWFkWFVaek1qMENScmNYaFE2dkxwZWxMMUg4K0tNRnpUQzRhN28xZ3lm?=
 =?utf-8?B?cGxSS1gzeU9uOW9PeDg2NXo2elBuYW9VQ1IrMlgyTDlzb0R5QUphSFQ2NEJv?=
 =?utf-8?B?YkJsdkJmZWJZRG8yR1BtNnVQTFpVZUhZQzdGcnlKK1Jtd2lGQ0tMMHRLTmpp?=
 =?utf-8?B?YU1TTldCSTJqNXJwTHRmbzU5eWRaUUhPN2VNOVpzTlJYV0diYnQ2dEh3QlpJ?=
 =?utf-8?B?K1NaSFdSNi9IcWFwK3BFQnIrc2hKcG53SDNoZXhvQkdvOE41U2hFaTlUWEtw?=
 =?utf-8?B?U2hndSs1M0wvTEtCTnpPM0ZJdEFLN3hvMUNYaUFDWTNmSDMyZjN1TFJvK3dW?=
 =?utf-8?B?YWlHSWZQckp4N043bzhRUk5Fdm1DcEdWQmY0RnI3S0xTQVdyc3M5MDdmVlp6?=
 =?utf-8?B?TDcyeHNYZXptd2Z4OEhmQzhQdXZLUmkydmRUcjJFbUJVbldPZTRKbmRaR3hD?=
 =?utf-8?B?NjNncGVDZytGSDUwbXJvdVNmMmNGNGREK21aSnc0K2dpT213M3NUcWJnNk5C?=
 =?utf-8?B?RW5PeDROVC9CZFV4OTdTNnU0Z3FRMnl2bXlaZlZpR2RTZk9Qa21UM3lpRkI5?=
 =?utf-8?B?RzVtRHpJRStmVjFiVTVSMFE0TTZNRFFzd01HVk5iMHFCZU5Td2ZQY1JaRXY3?=
 =?utf-8?B?U004MjdLRGFGNjg1NjYxbitCdjZtSWhCakFWeGV0MmxScGVFby8wOUtkUFJR?=
 =?utf-8?B?eWVIbmRUb3dSNElZb1ZqZW1yMVdCR2k0bnBsVVJ5b3VSV2t3OGFtWng4VENO?=
 =?utf-8?B?ay91THhob1Q4Wi8reFNxbWdCNm90TVZvVmdURkoxOTFkSjcyeVVvSDJWbFNo?=
 =?utf-8?Q?c2j6km?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?eEEwQzRQU3NHMXUyNU1QRDhhV1l1RnlTYUZtMXlaK0g5OEVxV1FNbklSU3Bw?=
 =?utf-8?B?L2xJeitPSlJxQ2trV2p2bGRPUGpGQmVQbmYyWXVQaXdnWHVLaXFRWjJjbHpN?=
 =?utf-8?B?empmSmhWV0lKMU03ZjNBbDNiZ1NpVmgwcGdHbnJFL2FjbEJXREQ3OEdkdGRJ?=
 =?utf-8?B?UXBybnMzTUR4bVFVVHVpOUd3Rk4zYUY5ejRZZXIwUFZRSjd5aGFMVHVrMGVs?=
 =?utf-8?B?b1lzeDZqYXBiaFdCVTFocnNSWkhlY2NjTmJYcHFvS2RWYzJFS1BCVW0yRHdD?=
 =?utf-8?B?Mm1qQ0pCMlVmK201OWZuWWNXakVDTUZyN05aZXJLWkpMUUJaYi9KVWdwbmQ1?=
 =?utf-8?B?UnJ3dnlCcEZORWp3dXowb1dYSkxybmo0aGIwNU1GZk5VRzE4cXk2N3FrUFhm?=
 =?utf-8?B?bEREb0ZsWm1Yd01GNVhZdlhERzYwZXRqM2Z6bmpmRWJramRSQTBBY08rOVJQ?=
 =?utf-8?B?MFpMYzl0d1FYWUttdkxVZVhFQnZzQzY3U2dTT2N3SllZVjBiL3BBRDhqT2h4?=
 =?utf-8?B?L0VMcXBkMWREdkN3MzNUc3M2UmxBcVlFWmRVZ1RtcktqYkdXSE45Nnp5WkFt?=
 =?utf-8?B?NkhYODdLSVV1S0I3MVphQWlCYkttK3NuL3gwTTFtN3BRL25vNmNndVFtUnpX?=
 =?utf-8?B?eCt2b1lod2hrZURwQ3BSQWRQV1gzQkFEUVRsbFNOUE9ZNVFTUmFLVnFBUmJy?=
 =?utf-8?B?WDFhVldrRURxbDA5Q1B6aVlLOU1UYlhOZWx5L3lKSlFCNkV0d0ttVmVYMkVM?=
 =?utf-8?B?a2l3U2Y4NEttV3M5aExZaDlUWDIxaGxOL2VCRXBkenRlY3IrTG5zWjhYSHdM?=
 =?utf-8?B?ZDJIWTBydWtnbVlDaVloYk5mclk2TlhOV1BxYlRNVnhFRjZkQ01FZDNLcXZp?=
 =?utf-8?B?c3NMOXRJaGxVTWN2RzFSQWcvODUxaHlYWDdaMWVielM4aTZkM2owMXlhc2to?=
 =?utf-8?B?bzZOL1hXR2x4NlpLRm9DdmdzMThaUVY2LzVHVXlKd2xtMTFjaXB5aFYvYzd3?=
 =?utf-8?B?aG1UM01SRStKZklnTXFUbWptOWJleUlZWTZjdXp2NDB6TVhBZzkyVlYrSGR1?=
 =?utf-8?B?S0NBV3BpUm5ZM1ozY3pwS2xVdW5wMDNWdzQvdUxiWW1tZ1VhWUh3OWduQXoz?=
 =?utf-8?B?VFpMZ0RPRnJtYWVVZnF0WHhOdlVwQnloam1aSkw2YUdLRUNJUjRFU1l4cXJU?=
 =?utf-8?B?eVlqM0hVUVcxZ3FTNmRvcFJSYTM1MzkreGU3anYzb0lWVkgwYS9CT1I4NjhN?=
 =?utf-8?B?NEdUTHBmVEpzNEQyOG9pZUFVaXdFang5ZnRJbzhuTUdiUXowOXg4alZUazlj?=
 =?utf-8?B?Vmtrb0JFNEpVVi9kQ0FtR01IMmxNR0ZwR0xMOFQyUUZvOFEvSEk0aVhsQTlX?=
 =?utf-8?B?VjI5c2E4NGdQdVBDSzRLcjdUaCtQTGVwcklUS2tzaWhPaWdOUG9TemdmL1hT?=
 =?utf-8?B?Q0crVzA0K2dIYkovUStqbUpORldWYzVtN2taeDN3eDJwVlJWMkRzUE5mR0R2?=
 =?utf-8?B?YWw4bWtsREhmbUJuZjZzK2FYdm5TQVAxdTdYWmE1ME44ZFk4cUM3c05JL2w3?=
 =?utf-8?B?K0lzMnJCRExCREV3NmZibDRHV0xLN1BBWGZ6RlRiRkxJdSs0VlhvYVZ6L1Nu?=
 =?utf-8?B?T2xmSndlaXdybnFOazdjc2pWZjJaMnN4L2VNSmhjZHdEYlNoUTJYd3doalBx?=
 =?utf-8?B?TWUrbWxPckxnNk9SV3BpcU9aNGkxY0NoYVpQUGxvKy9LbXVnK0JjWVF2MTla?=
 =?utf-8?B?eU91N2RSZ3FxR1JmUXpTaVVqbkVaVENVbWd4c3Q4dnJSY0tFTWlWZkdqbjVa?=
 =?utf-8?B?QTlZNVkyVmxXL3dLaGwwaEtjR3BLZzFpbzdKY2VlOU02TFUvV3V5TlY2V2xu?=
 =?utf-8?B?cEI3endETWMwN1lSTjRDdjNRcEV0NUY0NFZBL0dzTG1LcFZtUHlkcy93MUcw?=
 =?utf-8?B?bkZEa2ZNbTBlRzhhdm01LzBHY3IyWndmYklWYW8xcXl6MXpUUm9tOXV1aGI4?=
 =?utf-8?B?ZTFmMU9OOEFnY0grMXo4UmdNYTI1ZXhMZFFUNndYYVFQbTRJQ25kOTJpNVRa?=
 =?utf-8?B?SmlxRTNnQlBVZFRWUDlVekJCTnRPWTBqakh4S2tzUDZGSUJZeXlqWTZjM1dm?=
 =?utf-8?B?M1drNnRibk81ZE83QlJWckpQL0g3VmZ3Q2hIWjJsWWw3Q2s5U2dNQk1pbjhU?=
 =?utf-8?B?bDBtZjhhbm9Cd3hERGdMSzJHTU1sc1A3VStVYWJ0Q2xaOEZGR0N6dmdwcGg5?=
 =?utf-8?B?R3gxTkxHc05CSnR6cnh5R0JpamFKejJnMlRxSU5MbXRVRVA5WHJ6aWl2N3Jp?=
 =?utf-8?B?b05XZHVXZkYvRW01NUZUM0JiZXlXK0JKam5TOHN4aWdUMmpRUURTUT09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: 8d8212fc-b26d-4465-10bb-08de5849ee48
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 17:32:48.7448
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4b3nXy8P4x+v5T0PfFwx6oVUg9vZ2xpgBLh76ARh9sX4Hg8+qXZYYOIPG6DiQka85GgnhfuNyfijUEpG20zatg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO0P265MB5455
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=qNDpBUIt;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender)
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	DMARC_POLICY_SOFTFAIL(0.10)[garyguo.net : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERBRPYX3FQMGQEHXWEV6Q];
	RCPT_COUNT_TWELVE(0.00)[20];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[gary@garyguo.net,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[gmail.com,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,google.com,umich.edu,weathered-steel.dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[garyguo.net:email,garyguo.net:mid,lpc.events:url,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 096FA489DA
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue Jan 20, 2026 at 5:10 PM GMT, Marco Elver wrote:
> On Tue, 20 Jan 2026 at 17:47, Gary Guo <gary@garyguo.net> wrote:
>>
>> > I'm late to the party and may have missed some discussion, but it might
>> > want restating in the documentation and/or commit log:
>> >
>> > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
>> > like memory_order_consume than it is memory_order_relaxed. This has, to
>> > the best of my knowledge, not changed; otherwise lots of kernel code
>> > would be broken.
>>
>> On the Rust-side documentation we mentioned that `Relaxed` always preserve
>> dependency ordering, so yes, it is closer to `consume` in the C11 model.
>
> Alright, I missed this.
> Is this actually enforced, or like the C side's use of "volatile",
> relies on luck?
>
>> > It is known to be brittle [1]. So the recommendation
>> > above is unsound; well, it's as unsound as implementing READ_ONCE with a
>> > volatile load.
>>
>> Sorry, which part of this is unsound? You mean that the dependency ordering is
>> actually lost when it's not supposed to be? Even so, it'll be only a problem on
>> specific users that uses `Relaxed` to carry ordering?
>
> Correct.
>
>> Users that use `Relaxed` for things that don't require any ordering would still
>> be fine?
>
> Yes.
>
>> > While Alice's series tried to expose READ_ONCE as-is to the Rust side
>> > (via volatile), so that Rust inherits the exact same semantics (including
>> > its implementation flaw), the recommendation above is doubling down on
>> > the unsoundness by proposing Relaxed to map to READ_ONCE.
>> >
>> > [1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf
>> >
>>
>> I think this is a longstanding debate on whether we should actually depend on
>> dependency ordering or just upgrade everything needs it to acquire. But this
>> isn't really specific to Rust, and whatever is decided is global to the full
>> LKMM.
>
> Indeed, but the implementation on the C vs. Rust side differ
> substantially, so assuming it'll work on the Rust side just because
> "volatile" works more or less on the C side is a leap I wouldn't want
> to take in my codebase.

Ultimately it's down to same LLVM IR as ClangBuiltLinux, so if it works for C,
it'll work for Rust.

>
>> > Furthermore, LTO arm64 promotes READ_ONCE to an acquire (see
>> > arch/arm64/include/asm/rwonce.h):
>> >
>> >         /*
>> >          * When building with LTO, there is an increased risk of the compiler
>> >          * converting an address dependency headed by a READ_ONCE() invocation
>> >          * into a control dependency and consequently allowing for harmful
>> >          * reordering by the CPU.
>> >          *
>> >          * Ensure that such transformations are harmless by overriding the generic
>> >          * READ_ONCE() definition with one that provides RCpc acquire semantics
>> >          * when building with LTO.
>> >          */
>> >
>> > So for all intents and purposes, the only sound mapping when pairing
>> > READ_ONCE() with an atomic load on the Rust side is to use Acquire
>> > ordering.
>>
>> LLVM handles address dependency much saner than GCC does. It for example won't
>> turn address comparing equal into meaning that the pointer can be interchanged
>> (as provenance won't match). Currently only address comparision to NULL or
>> static can have effect on pointer provenance.
>>
>> Although, last time I asked if we can rely on this for address dependency, I
>> didn't get an affirmitive answer -- but I think in practice it won't be lost (as
>> currently implemented).
>
> There is no guarantee here, and this can change with every new
> release. In most cases where it matters it works today, but the
> compiler (specifically LLVM) does break dependencies even if rarely
> [1].

This is a 2022 slide, how much of it is still true today? Nikita has improved
how LLVM handles pointers quite significant in the past few years, so this might
not even apply anymore?

I'd like to see examples of LLVM still breaking address dependencies today, so
at least I'm aware when writing code that depends on them.

>
>> Furthermore, Rust code currently does not participate in LTO.
>
> LTO is not the problem, aggressive compiler optimizations (as
> discussed in [1]) are. And Rust, by virtue of its strong type system,
> appears to give the compiler a lot more leeway how it optimizes code.
> So I think the Rust side is in greater danger here than the C with LTO
> side. But I'm speculating (pun intended) ...

That's actually not the case. Rust people have long recognize that provenance is
a thing and it actually matters. The pointers have a full set of
provenance-aware APIs, and pointer-integer casts are discouraged.

Pointer comparison, for example, is explicitly defined as comparing address and
ignore the provenance, so it's invalid for compiler to do GVN on pointers.

Implementation side, Rust is extremely conservative in optimizing anything that
relates to the memory model currently and when pointers are involved, currently
it's up to LLVM to do most of work. This is mostly due to the lack of full
specification on the memory model, so may change in the future, but I am
optimisitc overall.

Best,
Gary

> However, given "Relaxed" for the Rust side is already defined to
> "carry dependencies" then in isolation my original comment is moot and
> does not apply to this particular patch. At face value the promised
> semantics are ok, but the implementation (just like "volatile" for C)
> probably are not. But that appears to be beyond this patch, so feel
> free to ignore.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFTLHCJKPBRM.2G76Y35NCHNZM%40garyguo.net.
