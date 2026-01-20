Return-Path: <kasan-dev+bncBDRYTJUOSUERBI75XXFQMGQENZC4V5Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id ALIzOK+kb2lJDwAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERBI75XXFQMGQENZC4V5Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:52:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x133e.google.com (mail-dy1-x133e.google.com [IPv6:2607:f8b0:4864:20::133e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6074446C70
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:52:15 +0100 (CET)
Received: by mail-dy1-x133e.google.com with SMTP id 5a478bee46e88-2b708fa4093sf1082694eec.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:52:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768924334; cv=pass;
        d=google.com; s=arc-20240605;
        b=IYvRZcS332cnTpPgrcIwmrChippTPD9mYvd6UIGSEQkzXCDwBOWNzLmnadC9NJFq0q
         ZQ3LgDRCzVNG6pvFSsL5vdWGlQgh7EYP6dZqTXRBwudbE0uycvNqwv+pM4p5j1e9ys3N
         XuNm4tFJlwnZHtWPb4Y/1378r6UtioknuJlQPciQpna7PHCKXOLFLY8O79Aya/aYYZhN
         pMSN9/Y8sBj1gZSTJ38EeSvHT7FCsXiS5hVWrpuaOo9OGfHYtTXAtMgNdusMW2otAFUT
         X3iZfNC+/ImHESqeivTnhidcIw2VXtmmN1eFQDAXVWwcusYjM1XzA39DsdqjSqD2dBex
         xG0Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :from:subject:cc:to:message-id:date:sender:dkim-signature;
        bh=hr+2HHll6t1HmCGzRhq+WhV40vOLV+eaV6A1qkJgKr0=;
        fh=lxMPxdbX+u8lao4pXWmoQs/TkpGUh99IOVWkBy+an2g=;
        b=bRfQ4cLJiYGuUUnQwUSFaBasECa5vOadVOld1Ql6tbY7uch3tmS4g/KNbqt1XYWeTw
         Qhg1zPIVFMODJkQet/XQdkmld+Br4PSKnIp5mORQHZ1X6xyRjoWtOhyfvHxy2966xiAi
         H5dgDasWtJwvBGFoJwiSzXYXqYLYsP5piL2XsbrDOeD2/DywDS/JjNV1ZHZRZIFPf24E
         +URVsETF1wWWBGBPS+JXIjeMqU+mtDq8t1IS+t82PLtowze9Y5AYmu3BcRX4OzpgHge8
         aNyi2tSQeY4wD5geQZhBLlKQWBDd1/phzddIAkO7kfFbVCccKQpgzj9FlO8ll0Y+BE1c
         M0vg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=DUiedkA1;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924334; x=1769529134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:from:subject
         :cc:to:message-id:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hr+2HHll6t1HmCGzRhq+WhV40vOLV+eaV6A1qkJgKr0=;
        b=lQRTC2A8apf1iVT5wfmbosaRIt0Fv19e+gQqRQxx6nzOSJbxN8bXhipksr/4PCmV9z
         xbsnxBv6nNPORq5NVU/Zp+OEBgirIo0M+jmTPeXjNTe/YaF+kdlhwbisbf3oInT0MSU3
         OYcwbHyt0M3sg9uebEnj4oICX/540pL2z6TvBYO0GZ1Gez0otEt6ugaLMteTQDVXeAhF
         O0elIAnJfkhCESpMoHyQVHj/ILmqz9OF6nNelnpbaqmYs3e3ZRUTcZPaZ04uMzsWeSwy
         0CJPCJkJSR4uwuPBwmf1A/XlPLbkPy+9yVadTytU2VDVU3TXE25N2eunPK4suaYCcfJT
         9ZFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924334; x=1769529134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:from:subject:cc:to:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hr+2HHll6t1HmCGzRhq+WhV40vOLV+eaV6A1qkJgKr0=;
        b=uoibM6EiE6Aszkq3BzyRVJKon28dSRUFiEN8icNa0GE724vj0wSP6DgrXGGJYzOyKU
         AHIjuMg0giu3sGXAT3gv6Y02BZaERSm/RX8JrhBqm3sLRbn3/O+1ogjwW8HNnqxx8ms4
         TsFXpIXkYGxd81KOEFldmSL6bI2/Ui8P+KX8scOWAtem36i0mDAI0MXcKi8L4WbZR251
         610OhK+SVKXN+PNG3bTH55bMIXof15M/rhH1tvizQjcs/HqIIvDKskT1d3WgctVQgHHP
         ZqwR1/6TemKZpvo+k5VqZ3vBgoQn30Br23s9rraA3a0gINTvAwqUzyxQ1jpu8L8RrgNy
         5tMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUWITb4F2UUIC186byUhz1Dj19xDnTEU0U2Otibvyixf2YOJX07iGpuxb8pCSnx1ljjxkF46w==@lfdr.de
X-Gm-Message-State: AOJu0Yxfv4kwQ9ZpjBwCmtuOfEwCQSbsUIWajaB65fybYVxDYIkoYTkK
	Ws7piNXtN+EMnT5MF9B/qD0jRSwUoburSJarWG6siMCjIWXGk3g/Bpct
X-Received: by 2002:a05:6820:2225:b0:65d:6ed:e065 with SMTP id 006d021491bc7-661189ad24fmr6048998eaf.58.1768914595869;
        Tue, 20 Jan 2026 05:09:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GZ9xqVup9npqvvNmjRmGFFKfKf4wGLK7Ur86c4fRVjJA=="
Received: by 2002:a05:6820:2d98:b0:65c:fb64:b018 with SMTP id
 006d021491bc7-6610e4ddf60ls2713861eaf.0.-pod-prod-05-us; Tue, 20 Jan 2026
 05:09:54 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXYGAmoWoVcdkH8/4irIDiDIPfiUM4odbu2kCVH79489UREGU2wPe5YzUPTMLoKCkU36Ol0gTFubg4=@googlegroups.com
X-Received: by 2002:a05:6820:82a:b0:659:9a49:8fd5 with SMTP id 006d021491bc7-661189e0d15mr6064668eaf.78.1768914594689;
        Tue, 20 Jan 2026 05:09:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768914594; cv=pass;
        d=google.com; s=arc-20240605;
        b=OSOR78GyDLdVSLyegPPtjkBkAqVpyygxgA0318KOafo080DQb48S4pZV7QDSf0jGGz
         kkm42ceCfwue3mGpdjIB1m+X8ZnmjYDeQnBtFb0fiz55zd9yweIlANqJbqVgZVv02TxP
         zPeEUiSns2M0m3+vx6/g3zpVphVzlQS8Lbnae3qxVNPM43A/Qc2RoaXpCCaYyYb2brvb
         qmR/P/e+QNaCgDWAd3C2uJKYrR68VctOXjIROMlNaEpE9wWDKnr2LQpPuaBOFBp0vjcj
         cg9KhTqKor+dp3Pm5+dmzK9Fv0TvSWzDZy7hSrNkWPR1WbJ5bzRICx7b2s5086ksbsk+
         Aqmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:from:subject:cc:to:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=SfmBYyNFe9dvqaJp74H80gcftgbIqUnw/98hdDW69ao=;
        fh=0IcVPq9gQal7yeljYNI3O+0UUDouVSAyYrLu0/V/rFc=;
        b=IWpve5pYjTOw7Q4pxO3ToiRk2uk9IOeNX2QWX9oEsWlem/SJT2m7BTZVwlI+6jXFQi
         RbzAcGY+JUJachJN2TRInnFE7kF0uRTq660Dra5KWChBoZGZs7Q09AuZHTejRIa0OLRM
         j0SDBGWFTfgXD9+vts8iWpAEBlh8xQe7989nKdWK+RdiBw/bhUf/bnOMsdOYq2mQys26
         oZ+09sNuN+2qeSZoWPhlk7MjvCQaMbShxRPd6KHNtU5GYZ2fiZS95bH70WyNOM1Oj8M6
         NDbAQDRNdF07TdKX/8HmJecrR15GPRFMhNjEAkZEQWn+kX9ZHiVgWTD5Odn9v+akx89N
         8EKA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=DUiedkA1;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from CWXP265CU009.outbound.protection.outlook.com (mail-ukwestazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c206::3])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6628c58bc7dsi349561eaf.4.2026.01.20.05.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 05:09:54 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::3 as permitted sender) client-ip=2a01:111:f403:c206::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PCNFuMI8WnGH6dispw8ODtFBCFwIAI8JbvxsTsjkywaaynMPQm2urA0xBlf+4nNFb0tLT6STNC0qS94yQ3p0OKAYlKOujXFr0hMJywedA1qmvtn3jnAuon4jDHV2OmdrC68Z3519KRW71vhiAov2SSVFrVSvcmkHJZHY/eGvg2zHnuAQO82/9YML2SAboRfXj7YhoxT2dlepCtPtDjXxenuvGTGZklot1hK+7ljVvDSWDEejUXOSIJ4GQv/0sTxao9tGvMnupH6TJlRdSXPAzgBL3w0auYv2WAeKu1bzzyN0A8cRBuaYZZsz3XmyibNEzb4yCBWa6S7N7GGQMDOKHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SfmBYyNFe9dvqaJp74H80gcftgbIqUnw/98hdDW69ao=;
 b=uWAjIxUQgYoqO4SGG5XH+yo4tvpl4vt1tb4iT+s6d0aMfRuyRISnuCX5mpOoGkh9oqRyWjByLPABkH6I74dbpI/q4mbejtRZOxGm2fBn85VuCY5aW0dbdAXPDV7L44olWTpvZdsQ+ZBycXfgEyjqBI5fR+jcnsYITa0Q08kCe0r4MUOtkLO1wbtno4oHfMK8rkekwawOuYI7pw8CBTevfiMs6z0LQEOdgvzttXDsvK1ml7Lq5NZ6D1C5WyLd4LHBz+ZUncKQZx8ukTj/V6Lwoyf1oD1k8l6ChYfm2huT0n3e/kW8+ucOGLF8KoZPkI+6wZa157yP3hGWViXSA11kQg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by CWXP265MB2118.GBRP265.PROD.OUTLOOK.COM (2603:10a6:400:7c::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 13:09:50 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9520.012; Tue, 20 Jan 2026
 13:09:50 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Tue, 20 Jan 2026 13:09:49 +0000
Message-Id: <DFTFW00MFONT.1WKK4LWVHUJL@garyguo.net>
To: "Boqun Feng" <boqun.feng@gmail.com>, <linux-kernel@vger.kernel.org>,
 <rust-for-linux@vger.kernel.org>, <linux-fsdevel@vger.kernel.org>,
 <kasan-dev@googlegroups.com>
Cc: "Will Deacon" <will@kernel.org>, "Peter Zijlstra"
 <peterz@infradead.org>, "Mark Rutland" <mark.rutland@arm.com>, "Gary Guo"
 <gary@garyguo.net>, "Miguel Ojeda" <ojeda@kernel.org>,
 =?utf-8?q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, "Benno Lossin"
 <lossin@kernel.org>, "Andreas Hindborg" <a.hindborg@kernel.org>, "Alice
 Ryhl" <aliceryhl@google.com>, "Trevor Gross" <tmgross@umich.edu>, "Danilo
 Krummrich" <dakr@kernel.org>, "Elle Rhumsaa" <elle@weathered-steel.dev>,
 "Paul E. McKenney" <paulmck@kernel.org>, "Marco Elver" <elver@google.com>,
 "FUJITA Tomonori" <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 1/2] rust: sync: atomic: Remove bound `T: Sync` for
 `Atomci::from_ptr()`
From: "Gary Guo" <gary@garyguo.net>
X-Mailer: aerc 0.21.0
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-2-boqun.feng@gmail.com>
In-Reply-To: <20260120115207.55318-2-boqun.feng@gmail.com>
X-ClientProxiedBy: LO4P123CA0426.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18b::17) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|CWXP265MB2118:EE_
X-MS-Office365-Filtering-Correlation-Id: 17a1cfea-9ca3-4147-8098-08de58253197
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|10070799003|1800799024|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eHpxL1FGWTBzbjk3cnFudElWNXluVVFvRjBvTENDVjFxNzFnbDREL3F2Z1cz?=
 =?utf-8?B?dWRsRndGRjJlbnFoQVR1anZVdUtPVEh1TktwbHEwdGREQU1BUkwxTXdSd1RL?=
 =?utf-8?B?andlWW1iUHh5SHJJSVA3QnFodUEyOHJGdCtqUWFLeENDY2FVMlpQaHVaUEVj?=
 =?utf-8?B?OXpDbFNFbS9vWGFZQlJjYWFaVENUK3RFT0tJa01kV3RvUjU4ZkRnNHVuajhR?=
 =?utf-8?B?SE5rY1A1QWk4WnpFVHRXS05XV1NJbHluK09NdlB1S25pUGd2YVNjenhlaVZH?=
 =?utf-8?B?SytjRjlmODZMVVhadCt5aFlCNTdpT3NjRmlEVnFZTFRPM0RXbWNtdElpMDZJ?=
 =?utf-8?B?bnQ2Z1RiWEkyN0R1dFRxYVloZFRLWXZqTmtCSVpVY0pTem1lWnZqYWZoSEgw?=
 =?utf-8?B?UDVBSVd0a1NmQ2tkZVlEek1lVG01eGJMR0sxNUM1Ulc5SkZYN1pwNVJjMUtB?=
 =?utf-8?B?KzFjN1pzY0N5aWJIdTR2WUltWU1uU1JwZ1RadXMxcFN0eHJNdXB6T3lxN3Uz?=
 =?utf-8?B?UUJhdlNYb1VGbTNZL2VIUnpiazZzTWk5Rk9MRlhuOURja3NaSzZkMjh0SCtl?=
 =?utf-8?B?aVg0T3dzeUpHTlloVzh6QTNlZXpkMWNRdHdZZG8vaWo5bGpwb0ZQc3JVY0tl?=
 =?utf-8?B?Vlp5TVhKcFZCN0twWkdFQ1JVY2tPTSsrUDl1L3ExTnplTUFtNEJTdmx0MFNH?=
 =?utf-8?B?M05WYVRzUlEweFNvQWNpNlpRV0g5OFJaRDlPbmVHbjZLUnZpOFE4YW9tVjRl?=
 =?utf-8?B?N2RsNU84RHYzTlptVGNSMlNzdnZweWN0VkZRTDN5eUhBb3FmYUoyU0k4c2tI?=
 =?utf-8?B?Tk5ONTVseXZYbE9ienRZeFdhU1I3ZW44RElSeGxvQWFMa0JRcjg2TUFFSG5z?=
 =?utf-8?B?V2RwbG5pVFQvN1l6SGlhOEw3MzJWQk16NmQ4MzJieUJoTW43SmlBM0puZlBi?=
 =?utf-8?B?SWZPd0E4aG1Fb0Q5dFNsNGZwTlJ4c0R5Q2JxOXg4RmtIdGVLMTdTME91UjZq?=
 =?utf-8?B?cy9FL09YZmxmRFkzY3dRSWdBclhrR2dMUW96WXQ5V3RvamJtRFk4NmNjRDhT?=
 =?utf-8?B?TFZWK05KYW5pRU1YVmJyMDBkWDFnZVorQUJFUzJzNXkxb01VZHdlWFA5WGlI?=
 =?utf-8?B?OU95NVRCTDZhWmloNkdvTlFwUnRldHNkSCs4elVwcUJhRTV6RVdmUmU3cmU2?=
 =?utf-8?B?c3BTNlNJUERXSkVSSG1lMXJrcDVJbTRwbUhtdnBVUG9XQnhoL1RDRm92eEJS?=
 =?utf-8?B?NzhWR2N5L2E2b1ZJZEcwek44a3JCZnBvK2RJTGhpU2hISHhwTkQ2NUg4REpG?=
 =?utf-8?B?T1gybGtTRmU4VUVlZDRlZ28rMW1IcU9BRExVUkowMm16M210VU4yN29BajU5?=
 =?utf-8?B?U3RlbVh3Tng4OSs4OFBoT1RMeDRNakNMVHdQUmNzZnZlV0pkbGF3RC9wVEZn?=
 =?utf-8?B?OC9valprcTMwQW9TenZzeEdkOVp6R1FqdGpxVDM2clJocVo0cUEyVkNSUU14?=
 =?utf-8?B?SXRUOHNzSGZCS2I5VEppQ0htS0Y4WUxWL2RoRnZ3Q1lrNUl5Qnh3VllBYUV4?=
 =?utf-8?B?cmJOZDRCVDBOTUpRcEs2RVZyVUxjRmpXK3BKR2pqWUY2dGpTT3dmSi9sSDZT?=
 =?utf-8?B?VmVOaVFGUDluaDNlRFNyVmRqY1Mzd0RoTHhtMW8yRXJEMFgwWGdBWUxUb0o1?=
 =?utf-8?B?cGhUMHBLQnBDeHdmbzg3K3pjVlBleFRZenoxN0FkMmliTVkyMmkyb0xBMnhQ?=
 =?utf-8?B?cnBnZ3VFRzNkY3JHWWFaUld4N0g0VE5FaDZYM1hsdHU0ZmM3UkludnlLc3VN?=
 =?utf-8?B?cW1IeC9VRzUwZng2blNJU2dvTlBSeVE0ZVdRUzhSU1BEb3BSUFhNL2kzMFB5?=
 =?utf-8?B?ck5jSHB2dDZCcE9VQ2ZpZ3E0cyswQzJndko2OFdMVXZ6Uk9CeEVuTjVSUkVj?=
 =?utf-8?B?OE1GUXZGZHlrckpJS3Z2dWNVTEZodjYwWDNjb1pJWHAvbkhLNmVIbTFRcHNp?=
 =?utf-8?B?dDZSbmlwbC9kYTYwMGZ3b05ZWmpzZDRURThpcHdOQ0twTDlrKy9qcUM0MzhR?=
 =?utf-8?B?V054N3RJN0hMWC9UQ3RMZDJaeEJLVTZOSk1TNkdia1hCclU4RGdQbTVtTTZx?=
 =?utf-8?Q?C/CM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(10070799003)(1800799024)(7416014)(7053199007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?WWxZWDdBaGd3L254bUVTL01XT1QxaFk2NU1ubi9XWGVseXJaVlpleXZqQWRq?=
 =?utf-8?B?a0gyRFpjUWs4dHcxZE1lV3NQejI3amNjY2JjNEpuTzFmdWpiNHhIY2M1Lyti?=
 =?utf-8?B?QTVtN1lDc3NqSUVya1liM2pDK01zOS9KaVZrejFuVFkxcTRJbDVYckIzb1Ba?=
 =?utf-8?B?UGFUaUl0cFNjUGhyTmJQRUZLa2tZN2dLOFV6SnpJdUN5cjdEbTR0QWVPejVq?=
 =?utf-8?B?dUVLbGkremN4cXhTYXNKTTd0NjRyL3hFUzdEbWhNZ1F5VXBXQ1pvTTNGRDVR?=
 =?utf-8?B?UFlMK3RjNGFmYjAxT3cxRXRGeDdIU05uOE95SVVDREVId2hieHlxWGwzdzNY?=
 =?utf-8?B?YVYyTVBxeXNLc0VZQ2I2dFhONWpEckRER2NrYWZTQXZRS2MyVS82ZHEydWx4?=
 =?utf-8?B?TkFyN2RQSlo2YitTUXZxSTh2WUVlaEUxL2t5L0pCMlFBbXlROURTYkJ0Lysx?=
 =?utf-8?B?TEVoOXRYZ2RydnJnV1F1cTZicXRNd2d3bzJNTUZtNFMwZ0hHREZsdXVzVmx1?=
 =?utf-8?B?TnVtdU0yczFPWmxyU2oxOGR3RkFqWU1Uc29DdFVVbjIyMldDRUlZZnBuOHdD?=
 =?utf-8?B?SDZZUmlsVlJRL2M5ZWMrRjN5LzBYN2I3ZGk3cTluajB1QWt3eHhKVjlvNkcx?=
 =?utf-8?B?bzQvSEFJQkNVYTgwblBQV081aUIyM0UzS0E2NmRXMGFGb1d0MjZGU0RLbTV0?=
 =?utf-8?B?c29ZL2VtblE2M3lEQ1Q1d3NlYmQ2VU1pNDBzaS9Xb3VXa1I4cEI1djJLa2R2?=
 =?utf-8?B?d2d3S0oyZGo2bkZ6bjZaQmlKNjJrTzNDSWV5WU5RaUNMUi92N1N6cnBXSlFI?=
 =?utf-8?B?QjRvSm93Zkl3dG1oUWRjWm9XYmsrTlRrbXZ0QTZYbjJwK3QzdjZ1dTMzOTg1?=
 =?utf-8?B?Z2RDVlAxakVKZm10MFpoUTFaUXkxTzF6MHduODhHdnk1MlA4ZzlKeGtIbHZt?=
 =?utf-8?B?UXh5amIwSkpQOUQvT3lUWXlOUTNocDVjQXF3RlB0SlpRaWUzcEh1YlpLMHJ0?=
 =?utf-8?B?MjA5VVBjWkZud0E5QUh1UzdhM2ZqTFhYWTYweDZMemZqa0tqWXNvS1lnaE5W?=
 =?utf-8?B?bEtENHIxMjlxUlQ2WTRuUXV3cnNJTkR3SVlGRVRrUVFNRDRON2o3R2tVcktI?=
 =?utf-8?B?cVl0dXpJZnR6NE0zTnZNS1ZMdGVML3hUdGZUcTYyeEVLSnVDNXZFOHpTaVFh?=
 =?utf-8?B?amNjaHRvdElFcVlUNlQrbU8ySTBEMENOU0pja1lSdk1rbWNlOGdpeWh3Nkt3?=
 =?utf-8?B?S3lRcHVuRHpEZ1RNc1NYU3pzOERWdkJ2aGs3NnNDcklabGZBVHI1V3ZmcHJC?=
 =?utf-8?B?enNWRW8yQ2dteWFqWmo4RWdWcC9xVGRPOTByRE9lMk1oUXRGM1Y3TFF5SUJ2?=
 =?utf-8?B?b3gyazVPVUpjYzAyekhVSEZYU3VseGtSNFBOUVZpdnl6WXlqbWdQN2srNHVj?=
 =?utf-8?B?ZHNlY2FGNjVQWC9YRTNJa3JoUVRsZ09udldnUTMwYXRwU1JzNHoyTmJoZG56?=
 =?utf-8?B?OXhqQzlBR2djMVg1N2U4OWVkcHJSMWg4bTFBL21LZFFVNlhyeFQzbGoxVWpY?=
 =?utf-8?B?U1dUVTYrWWlFRXAxYnlicWNKb3IzMmUvSnRIbGVyTWtOc0RINkJtNmUxcC9x?=
 =?utf-8?B?OXBESHl1bnRDOExxY1hCaE9peEVQdkZ4dU5Kdm1yMTZicjJmL05DMnV1Q0x2?=
 =?utf-8?B?am91N2E3amxCUXZqUE5oUUdvMkRHeVFHTHlkTzJFbnZ4aGJJTFNXZUhLMVli?=
 =?utf-8?B?TUZaRURVMjlja0tLNVkraXo3Zlo5enRKUWtJaStRem9NTGEzOTRRSTVpV3RU?=
 =?utf-8?B?a09NOTh1WnA3NURJQWFTWE5xc1VVOEFnZjRrYS8vaDNSa3lMT1dVOFVWL3RV?=
 =?utf-8?B?bTRXSGlyOXZ5MzNPY3g5dWMwTFgyRlBrT3JpSllBYitXQkE0QmZTaERDTk5I?=
 =?utf-8?B?eW1TLzJDQ3d4d3JwZU9yV1R1QUVlNGFhNDFJTURBckhRR3crT1R0VEtXVk8y?=
 =?utf-8?B?by9Vcmx4RlR4bGx3SXFSWnBERVMzUE5nclNMcTk3RjdOa1c4NHRacmdwcFhO?=
 =?utf-8?B?ODJocS83MHNyMWsyRGdHY1U3QzZjL2ZpMmptQWY4ZUVLbHlzdlZRL3BYd1JH?=
 =?utf-8?B?Qy9MUzJXUkg3SFhaN0JuUGlPVjdNenppUGkwWWVaaDhpWTd1aDM0d3RiTlcz?=
 =?utf-8?B?QU9lOFBnRmFNTnpRMVRvRWtTUEpXRzNWeEIzSVFQcG1mdEx3QjBldHpNRS9l?=
 =?utf-8?B?Q01RNFkyUlV1SE80cm1kY01ZNUJjU2QxRWo4alhPK2ZacXUyODJOQzFTZndG?=
 =?utf-8?B?dFc0UmJTaExEQm5RdzNwTGVNcjhkSUYySlhneUZNWERoSHBoL1M0dz09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: 17a1cfea-9ca3-4147-8098-08de58253197
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 13:09:50.3053
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ccW16GdYxGVarXTi5sgxsvH2Ty/OqPZq1psj0Ppw9ArzyyGfou1bk5XOATU/PJiYshMAelkomSlvvpq2oVOxLg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CWXP265MB2118
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=DUiedkA1;       arc=pass
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
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERBI75XXFQMGQENZC4V5Y];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,garyguo.net:email,garyguo.net:mid]
X-Rspamd-Queue-Id: 6074446C70
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Tue Jan 20, 2026 at 11:52 AM GMT, Boqun Feng wrote:
> Originally, `Atomic::from_ptr()` requires `T` being a `Sync` because I
> thought having the ability to do `from_ptr()` meant multiplle
> `&Atomic<T>`s shared by different threads, which was identical (or
> similar) to multiple `&T`s shared by different threads. Hence `T` was
> required to be `Sync`. However this is not true, since `&Atomic<T>` is
> not the same at `&T`. Moreover, having this bound makes `Atomic::<*mut
> T>::from_ptr()` impossible, which is definitely not intended. Therefore
> remove the `T: Sync` bound.
> 
> Fixes: 29c32c405e53 ("rust: sync: atomic: Add generic atomics")
> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>

Title has "Atomci" instead of "Atomic"

Reviewed-by: Gary Guo <gary@garyguo.net>

> ---
>  rust/kernel/sync/atomic.rs | 5 +----
>  1 file changed, 1 insertion(+), 4 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFTFW00MFONT.1WKK4LWVHUJL%40garyguo.net.
