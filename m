Return-Path: <kasan-dev+bncBDRYTJUOSUERBCPDX3FQMGQEJQ5KDTI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sPKYGYyxb2nMKgAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERBCPDX3FQMGQEJQ5KDTI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:47:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id E0B8847E8A
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:47:07 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-8946b186018sf16928216d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:47:07 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768927626; cv=pass;
        d=google.com; s=arc-20240605;
        b=jFZqkqFUUNzrpxb75akkqPqH66flpJp6sJMcc/Ha+pWk1hZqpNSpgS+RvoXDaNuWzl
         AT+TePHk1TCYk9aChCXt+zCdQfSshzn0S3B1hVO9ZgTwobgoyGZVoyhr18xIwqMaLDmc
         PEP6r/Um6Q6YK3PGjAfSHpN59a9N/RH3xjL8yC0fBQwTYQuRIkCEENd3FJP1qAmsq+FO
         HdyvmVy/AqOUXgxzKPWUDQfHtXztHqF1faWTxs+7fLEUvJH9JTTWcYQvZqhSiplJEa0F
         9pz8Elm9wW4F9NnByTzK1DcrK6ZgVvg9NwauKIh0o7u67M6x/WsPEbZu96D55JiZ+y1v
         2ftQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :to:from:subject:cc:message-id:date:sender:dkim-signature;
        bh=qC0cln8JQnXtnDG/osSeH8rwV+Y4j4X/0Y4Sl/3joIQ=;
        fh=VQeJhm4V2MBLXLIdRzEqQkXsBWKPnRCQgvzVRdx2mR8=;
        b=cg4SNCHnu5K/M7ODUK4Et/+cvCFrmYtbf+ujwQvjzhSjuK85PoCYodE4KaYt5TYUuz
         sFeT4snuZw53BSdM4newXcb4ollT9S2+QMMFNj59CrqOPZ00RWtjNJ7LOoTuyZwfLr/T
         pKOlPw/Pu/56bG+OGj1jJEk4dQICqFCGwMpvRuGlh6HlsdAX0jokoZXiQYmcPR0+RaiT
         lHZmxptt6zhXe3+ZfW36c6A+G9I8b4xxLU/ZtHN6X98Xo2xrbqrEJ4Y62XZnGWbhC6Sw
         RKvHm/92ioFQxBMxF+JjrzRgPFm/zvBMxLqINW7d/cpT4+HV9yikpCmZv7Ls931B5Zm+
         AO7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=oUqFY6YC;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::1 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768927626; x=1769532426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:to:from
         :subject:cc:message-id:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qC0cln8JQnXtnDG/osSeH8rwV+Y4j4X/0Y4Sl/3joIQ=;
        b=GP1anPZgY4M5BEB2FrXwV4lvooo+VMg1dgvMwUTM0RV1spkKzjWt48XUEoOnU6vLB7
         GTiLA5E1PYGjKUvFoZ8lv1kUo1xCBHNam8ZMTS08nrz1D/Oj+yXffnG/nF4srOz4rpRU
         v1pEzNdI6VvSHxs8f3Qt4R21OM/VA8kcVw0emr3O81SDYNDxfgBar2yeZthqfeIGgv2x
         e3yAQABuo+Zd5PCRdGAtd2pyuJxZh74wfijCGrpNur7LK1oVV+8mmgyzetO0U1OVp4y7
         0MrN/9/lRza3JPInU7vQE4Bu+aZVcuQI2uNxJYU108X5QUxj06aBNAS7We3QNMOKN+hG
         ifsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768927626; x=1769532426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:to:from:subject:cc:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qC0cln8JQnXtnDG/osSeH8rwV+Y4j4X/0Y4Sl/3joIQ=;
        b=mazt4gQqMyRcX3dybrCdtNgBs17oINttvlS2kXkL/DyLy/NaHdwNkS+fmCOQyjVSJw
         OjJ9w2lpA0ktB/Q2esR+eA9DGi0P8qInGUtJDbq3xRbrBmC9tIyetD9IQ0KeNjrcv28P
         152/QsxT7zpXBhRHBBkMqXHR1dHzjNY9DgWVE2N/TO+8g0pRSvBZ0+OuFM/v6Jlitybn
         W63L5+qY4zm5reecYcmCJdGkNrOKUYoGY29V5im3UUl+ragaOU2t5suYsFioWw9bKpXG
         xzM+SKvafcVJx8gEOEFMI6p53Sok1jJ2W2VW4ZzPsS6jdn/DhMeF5hvw5DXz4KNSI67I
         YpbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWhDEkPnMjkv7v7rVwtjfy1obXm/5vSKUiu3H+iyGZXBYalfDA1oc6jChngdSpivU2d4XCfUw==@lfdr.de
X-Gm-Message-State: AOJu0Yxj/HlOhvs51yz4kVIlfwQGnmswdG4eqJPNhwujufXiwUpfaPnO
	YDGX4NYyAnr+masEkQRjtmzhhPlHiwBntq2IbZoiFJB5nqb9WgI23JdK
X-Received: by 2002:a05:6214:e65:b0:890:3eb8:1ee3 with SMTP id 6a1803df08f44-894638d223dmr31151456d6.15.1768927626354;
        Tue, 20 Jan 2026 08:47:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FJRuKghzKqYg8plnfUTAj2kxaIQ/+LWIfKn4tscALwQQ=="
Received: by 2002:a05:6214:2aa4:b0:880:31e4:d7e4 with SMTP id
 6a1803df08f44-894222f19f7ls124449366d6.1.-pod-prod-07-us; Tue, 20 Jan 2026
 08:47:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXYSh1KxD8bs4ucGN8nhZyhDU4LJeEqKrdTgGAEvVLH1++TvNfG6M5f1O3NN6dxFTpqbUysTrT4IIA=@googlegroups.com
X-Received: by 2002:a05:6122:3222:b0:55e:7266:bab8 with SMTP id 71dfb90a1353d-565d6fae887mr804011e0c.1.1768927625088;
        Tue, 20 Jan 2026 08:47:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768927625; cv=pass;
        d=google.com; s=arc-20240605;
        b=MGd9iy6nbz8mh+CXBASPRunQ7fC76eCgKVNX5MEj1fflo+qZxwO9x7ojzXhE895F3q
         rY+SrdkhMUjLBMcaIqFLbYQlAJ84eglNHB5fSSxk/q6HqBPcyBv29XqNEA7Ndf4TrNC2
         R79OzjHeW5XESSgKEGL/r8BiEjYQJwu4or4YFq1Z1SW2HtTDnhRo03aMzbN9cb0CcqVT
         Xz9bK345C9/Df0vjMX/bx07NT/qky5mXA8z92C9Xx+LS6BBCieVh02BpQWxts0fB/0Ll
         VEwJbi07EOEk+gvFNMGZxAnBGEfSkyjKGFvIdZuC8n9bL+ghfbVSCDZFTC6PAR4GuA45
         zJNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:to:from:subject:cc:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=dW+u8TlYgkM4UdidoWGcQJdulKogz+28gjTDfcHIvh4=;
        fh=iftlcEqTzKeYdg2kfuH9jsgClLuZuer1va0lmmvtTr4=;
        b=crwJb0gO5uaT35MvaOuMSXY2LGq3HQNpWbXg++QM1Bz4FM7bVmzLPRtU3nH2EePviI
         5hHDb0gZWcWJK4jImTekbOGYg1zNHVMY6QoziPJYse52Hr8izwxeybwoohF7qNfggrwG
         Wn3HzvFBLvvHdkXJ1ZN6iXclcEzNzCfCf/gEW/9FyLVSqmOPP0RfmQLI6lPAvRyEfY9M
         4E+Cn9da/TOHkPq9uizKbtsqSx4BYroGhtkEEa1/HGXwP9g44/iW66xD7X5mkZvQsbrY
         wDybIsOS8DW8OFJ08qd2CC7Vz68pDOW+1bATxRFq/fkC2qDt6v/iUqyqj/kJ+r2TwMVL
         X55w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=oUqFY6YC;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::1 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from CWXP265CU008.outbound.protection.outlook.com (mail-ukwestazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c206::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-564552a1c5asi269598e0c.2.2026.01.20.08.47.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 08:47:04 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c206::1 as permitted sender) client-ip=2a01:111:f403:c206::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ceEyMETBY5qVlsQcOdWzKmupWyyrfbBxT4Z0RWlLfVREtM5sazSJkRQuHxydda8shoQ519/ndfnNjc3lGuDQAM5SLn6M7/QqiGWOWNMDD9wgrruYUGC4ogpiwZ1146k77H2i9H3xvkt9LflzRVMYAzvEURb0/3uef44YObb6BFUOsjkhdgCIHYyQus3u0fA+0ToOWRHopVFgnHSq8L6/Er4+WoELP/L+EDya7Z8X6t4gtFVzdhHZYEwvOOVfuxXZ4QLRklsPwEjIWSnKS6DYzZntCmBx3qXg0XSPDUCc9E+IhauFtzNIxCc8Gl7hTbVGi5oTdXrXcPrLZ3BQUa5Kjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dW+u8TlYgkM4UdidoWGcQJdulKogz+28gjTDfcHIvh4=;
 b=v9YyL4JXqP0CnCEo0fLHZzBoG9Xf+hydy8yPibxmaRD4mjKk6WqYda040KwxF41q14DfeHmHMibTI7/7RFC9CmDyEmJXdbH+awMPqDlUgGtqman24sZNOPW7rq5WmgnhxFSwEC4711T3x2boPF+NV15MNrsHf5vxqxFgDhVINAFWtRdlp/CRkxhRxSY/8d8fUA52EyStbN4zORCn7gx/pumvQ8PJeOzhZaeXnVF1xb/vlvDGloJlT3n4IicrUHPKZqpWJAiQJoLZGg1XUBV62jMtYduOhB7q76bTZ+06wlLV9BMVCdrVDZPjKtHhkDOl0a8xNKAl7zFudu6//0krkw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by LOAP265MB9205.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:493::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.6; Tue, 20 Jan
 2026 16:47:00 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9520.012; Tue, 20 Jan 2026
 16:47:00 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Tue, 20 Jan 2026 16:47:00 +0000
Message-Id: <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net>
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
X-ClientProxiedBy: LO4P265CA0103.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c3::6) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|LOAP265MB9205:EE_
X-MS-Office365-Filtering-Correlation-Id: ba67b6c7-45b4-476b-eeba-08de58438842
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?aHN3dHU0dVo5SGdOK0xhd2pVQktGMjBkdE1wRzZwKzZYQVVLR2pyMm9uelNF?=
 =?utf-8?B?YU52dG9wMGhEMmZsNHFyaHNRSndlYTdNNFdURFZUaURhL3hsRUtYWWtDMTNh?=
 =?utf-8?B?ZDh1RzNkQnI1cDJUSjJGQStYbFZUUUFydDdueUF2eG95cXhxdFF5aHZhenRF?=
 =?utf-8?B?T0M1WWVyOGp2dWFaMzZZK1dOUWNuYXkzUXpFVksvRlQvNzhYTkpHVWRpMjN6?=
 =?utf-8?B?RENQb3QyQ1o4TlozNnJEUTBwWFpXV1hBVkszSE8raDhVR2lNVjZXUzFubWt6?=
 =?utf-8?B?QmswYTkxOTZkeE95MlNUV012WTZ0ckhkem9zY1dZV2hIOVRRS1lsWVhIUHhs?=
 =?utf-8?B?ZHdNLzNMVzFkWnd5V1pMdUhXQ0RHREF5RHV5bXI0ZkFkTytVSG8wcS9nczQ1?=
 =?utf-8?B?cmVVUjIxM0lNck0wWGEwL0NNcGtnVi9GK2RlaFlMWTFOQW5IWEVLNDVJN0VO?=
 =?utf-8?B?eTE3VS9JMTNwSTZGSTl2bGJKbVhJa2R0SEVpWlIvdFVZeHdJbkRqZVZTSkxh?=
 =?utf-8?B?dEI1M1QyakwxR1JSaGxFUU5nTUh5aktPTy9NVUlsdzBzSHJrV1o5LzkxaU9N?=
 =?utf-8?B?dk5PaEpJV1BIdjBwUXlCWC9Qek15TkJNeHFDQnZOR2pFL3JrazMraUxvL1JV?=
 =?utf-8?B?UU1kYUhlU2F3S0xmVy94WGFKclNqeTNwbWtYZWVtZk5vU0s2b0xGU1htcXVs?=
 =?utf-8?B?Nm9lVEJwTElsVDVqckVmWHBidTJ6STZnNnlSa05WUURncGxCbDR5QVl6d2Mr?=
 =?utf-8?B?RWw2blR4eGpIc3BpQ2VvaS9FTGM2KzNpSFJndEUvam1mRTVaRWk5dW5BcTgw?=
 =?utf-8?B?Y0U4ckQ0WEx1M0IrUFMxVTlhYU5sdzR0R3hqZnYzdERaYzFlODRnbGFUWWx4?=
 =?utf-8?B?Qm1wZjBhQ3lEeXprWGQrdmM4TFF2RE5QNTQ2UjZNbWl6ZDFGME1RR3ZqZllQ?=
 =?utf-8?B?dVVpMXZ1dDBmb1Q1a0pLVDhXWGtzV0ZlRWZpeDFmYW1nVmpSbDRrRGhsQmJB?=
 =?utf-8?B?Z2k1eFh1Z3ZQRys2VUg0Nm5CZnFOUTI1MFR2WkZjRWVFUElEZWhNaFkxZWl4?=
 =?utf-8?B?TUtLbWhFdWZXdnFHQmMxSEV3NkVZbXZsOFpvUmc2YWQ5ZzV2RDZsRW1oVytF?=
 =?utf-8?B?VkQ3MEp3MjdEdll3MXVqNFNpcFVDbjF4RkltQTl5WWEwc2RvRDBxVXpjVjdL?=
 =?utf-8?B?MTF4ZXBuSVR5czhqa0JZYlBGdENCajNxekF4bnF0Q2FXTTIrd1h2TEpsVkRH?=
 =?utf-8?B?L0ljT1JrNnpLYUwveHU0ZjFtTitQQnBHSU5vMW82aWlNRUdVdERGUElIc2tB?=
 =?utf-8?B?WlRWRkdZYkVKYkRrMTZ1K0FYM1ZiSzM3S055SEdnSnFRaFJLY2dORXUxb2l4?=
 =?utf-8?B?WEFwV0MyVEFzWWwzOVVoRHo0UVY3T3E5UXRNc1B6VS9YMWxObmlLbkxrYTc2?=
 =?utf-8?B?cXhRQkxzQkRyMW5HdXBMT293ZTEzRWtOQkhJMGl3RDkvRENVVllGNFZDTVJM?=
 =?utf-8?B?cGRyZ0lmelkxL1h1akZGQlJkUFpOTlpVRGFuSEZJNHVReHRVK01zaHdmNmlL?=
 =?utf-8?B?eFlvS05kclVNVUlydHJsTDQvYzNPS0paQlZrKzIvWU1DOFlCc2Y3V0ExbXkz?=
 =?utf-8?B?U096TUQ1N2FZemxjNmdML01KcFpnOE92allDU2pqODRpNk8rd0xRSS9YdU1P?=
 =?utf-8?B?a0hiSFhsVGVKSkEzbzlmcjBDZjhGL0xEL1VUNGoramxOdUlPKzFQQklNbE5T?=
 =?utf-8?B?VE0yWUJha0tjcGg3MEtxWU0wMUFEQ1U5aUEySDM4allZbDQwVW1wN0gxMExk?=
 =?utf-8?B?NjFTL0hZR0NvSmxyR1BaRlRaSzlWVk83WWY0Vy9uRzF2RWo5Slg1WWM5TXIr?=
 =?utf-8?B?QjBJYXZjeTFNdlQ3WmtRQ0Zra3V6b0pqSEVXeU5TbmVPRVJwL3N2V2EzRG0z?=
 =?utf-8?B?d1NUNFh2enZQWlY2V2hhbTZzcDE4SVAvRUl3d3BEWWs5TktIUGZlUjZkSEpu?=
 =?utf-8?B?WFU4UDJwdDZmbDFnR2FxQWplc1JoTDNITDdMektXUGFPb3JOeGJtdG1FMXRG?=
 =?utf-8?Q?1Ng/iQ?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cGpzVERWcXpZaDBUNzU1Mk9QU1lDRWJ4bHc1WXd2TG5VMUoxS3V1MjUyb21t?=
 =?utf-8?B?M1BiMzhOa0Z4bTJHU1E1QWpoc2JtZzlIbW9ydnVhSUh0TEdnMVNleWxnbDRt?=
 =?utf-8?B?OGZ0Z2FhSUVqVnZ6TndyQlI0V3BJdG9MUnJoTjFDRWQxbUcwZjhIY3FGR2V3?=
 =?utf-8?B?d2JEYmRqL2YzcVIyRFJQQndoQjVDRHllM0xiSEZpTUp0NEhONVNNc2lQNm0v?=
 =?utf-8?B?TngzQ3pvQnVTZk1VSU5Ed2k1UzM0c1k4aERFajJBSUw2UUFpUHcwUXV3azVP?=
 =?utf-8?B?ZFppbXhEK01KRHJvQ05XQ1JKZWJrelViMUo2amthT1U1czVQUHJRc3d5VlEy?=
 =?utf-8?B?SXRBZFBxU3M5Qm1uMkVYZk5DUHkwV1ZiVGZSMWlPWVhKQUd0M1dPUVJaU2Yr?=
 =?utf-8?B?WDV1SEtEemoxNURoSS9WQThZWGdwbStmTkk5cVRCb2c2SDNBRTBIQzgrRTNy?=
 =?utf-8?B?SFVKK3M5eG05em8xQ2VSZnhRQW9lMFk0NjhtS1lrUEhvbDFXUjFrWFdSTzBO?=
 =?utf-8?B?dVJMSmZuTEhacWh0MHZMQ0Jpb3I4Z25obkZicitUakVHcmFUWkJrNEQ2T1Q5?=
 =?utf-8?B?WjJ3VWVWOGMzV0NzZzVzUW9BV2JZQlBlV2MvVXZrK3ozNzVWckpyck4vQW1L?=
 =?utf-8?B?NnBmQUpUeXBWTW9rdTBBdWN0SkJZTG54alF3ZGZGRENRRWM3MnFRUWhvZy96?=
 =?utf-8?B?YzlwbWpmRkgrUC84MEF4eFY1UnBVMldrQ09JM1hnWUF4aW96SjhtL0NPb0pK?=
 =?utf-8?B?NDFXaFRPTXczSG5ISENNNjUwNDJBRXI4Q2liajVDTjY0dDVWS2VOTFBwNHpK?=
 =?utf-8?B?TU84YnJ6UHpiK1d0cCtMTFk5V202eVYwNXQ0dmlvdmI0TEZvRTVodU1VQTVs?=
 =?utf-8?B?Tk1xZW1DMUxaSkUwNHRXOXpyT2tqZHZYYS9IQ3ZMWisrOGsvZXljYk4zb2cy?=
 =?utf-8?B?QmJSTkVSL2RvWnJKRHdnbnZJZyt4dktnV3g3TEtuLzV3MTliU0w5c3I2V1Zv?=
 =?utf-8?B?SXdwL3JCTXB0cm51bUt0WlNJU3gzcVBOTHdDVmZ0UGJYeW1WNGlxTklJWFJa?=
 =?utf-8?B?SnpLd2hQOVpRdTRpK3ZnMllFTEZQSzM3akpoV0M0RnhidlpsMW8zQWNtRnVY?=
 =?utf-8?B?bnVPOHNmV0JtazExRkc4N1AwU2V4cXJyYitWVnlxVnVQT1ZWT2ZrN2hhcXUx?=
 =?utf-8?B?UUFNNThBMmRNVjRFR09BaHRhNGMvcnFvWlFlbEN5aXM4ZnZuZTMrRXBTM0Jo?=
 =?utf-8?B?bUVSdjkrV1hlZERQcU12eitiYXMrQ2dyVzVsUmlQQXFVdUgweTJKWmkydmsw?=
 =?utf-8?B?cWlCMkNvdW9adDZ6YmZYRmR1dURRS3pXVDlWNVl0T09rU0lkN1VqWFR0ZVZQ?=
 =?utf-8?B?dVgwNkYwN29DV3JWOGZONndyL3FCV3lNSmhlUTRUZEE1Q0U2d3RlTVZSY09q?=
 =?utf-8?B?Mzgvdmo1TnBUbFk4UnA5aXUwWkovRW0wVWNuTXhnV2k5WEUyWFVpSjVVWnRG?=
 =?utf-8?B?THUwUUh3WHA1a2VTcnFvKzRrOE1CYmN1Z2dxckZaWkxjVWZ2SjhtSis4RXQw?=
 =?utf-8?B?LzBPZ0FkR21JYWtuVXVoNE1xd29ZTldSNkQ5a2QyLzM1elMwcnJKRE1yM3Ri?=
 =?utf-8?B?bUZFVGpwUS8vN0RySnM5blJLdUtWZE0zd3ZnMlVkMFM1Y29EV1ZmMU8xQ3Na?=
 =?utf-8?B?ZTFqdXlTNFhOa001Vngzejl6ZVBYZVRHdXZIWWxCRXJNWitjU0Q2V2M0SXB6?=
 =?utf-8?B?L0daajJEV2hCNUFHNks2T1BzRkZVZi9QbXdvcHZpa1ZCdnRzQVc2dWFVRHA5?=
 =?utf-8?B?TUpUQ09nZVQzalpjejhsRTRqcVZvL3c0TncwdndNb1JoT0lQV1Y2U0d4cE1Y?=
 =?utf-8?B?TVdzU2ZPZW9QbnFZOXpWUWxXMkxyQ2FNMXhrVm03em9BOEJmSmJzTUppNmN4?=
 =?utf-8?B?TXRDZ0lOWUFCYS9ORGF6UTlnZmcreko3UjRUMTdncDZzSmU4alpxTVZKRGl2?=
 =?utf-8?B?dnhhbEpYYllBZHlkZ2psakN6dXlKMERoZGdyUUJZaUpiWGtCRGFlM3lFTnp2?=
 =?utf-8?B?eHBZbGEzMG5nL0hGTnRlVVo3SzRSZ25TbTVVUTRtbTR6MVloTGc2RVUxdHRl?=
 =?utf-8?B?QXp3TE9vSUZZVzJwbnlhQVMrODByeCtGSDZ3OGE1OUxTa21QWmpFajcxUjQ0?=
 =?utf-8?B?SzhLWmxJSm04VlV6Umx0SlNFRDhlNG5VNlA5dmRYVmVsM2k3aEdFNFdPaXRv?=
 =?utf-8?B?UmZBSEJST1dENGRaZHdibndpbFcxY09tbmFQOEZIS3RvYWJhTWoyQWs3ZUVT?=
 =?utf-8?B?VEgrcXFVU0JVN3A1MzNQSnZaN3BOb210dWhBNHFiL0MvdzJCaWVVdz09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: ba67b6c7-45b4-476b-eeba-08de58438842
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 16:47:00.6031
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Vsrk2aopH79eS6qiFHAtzuM3wwS7k3EhfIJYmKuqRuNWIa7jZZsnxvBmDPbQ34yWZW5iwQF1kBK5l3oC21ECPg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LOAP265MB9205
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=oUqFY6YC;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 2a01:111:f403:c206::1 as permitted sender)
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
	FREEMAIL_TO(0.00)[google.com,gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERBCPDX3FQMGQEJQ5KDTI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[lpc.events:url,googlegroups.com:email,googlegroups.com:dkim,mail-qv1-xf38.google.com:rdns,mail-qv1-xf38.google.com:helo]
X-Rspamd-Queue-Id: E0B8847E8A
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
> would be broken.

On the Rust-side documentation we mentioned that `Relaxed` always preserve
dependency ordering, so yes, it is closer to `consume` in the C11 model.

> It is known to be brittle [1]. So the recommendation
> above is unsound; well, it's as unsound as implementing READ_ONCE with a
> volatile load.

Sorry, which part of this is unsound? You mean that the dependency ordering is
actually lost when it's not supposed to be? Even so, it'll be only a problem on
specific users that uses `Relaxed` to carry ordering?

Users that use `Relaxed` for things that don't require any ordering would still
be fine?

>
> While Alice's series tried to expose READ_ONCE as-is to the Rust side
> (via volatile), so that Rust inherits the exact same semantics (including
> its implementation flaw), the recommendation above is doubling down on
> the unsoundness by proposing Relaxed to map to READ_ONCE.
>
> [1] https://lpc.events/event/16/contributions/1174/attachments/1108/2121/Status%20Report%20-%20Broken%20Dependency%20Orderings%20in%20the%20Linux%20Kernel.pdf
>

I think this is a longstanding debate on whether we should actually depend on
dependency ordering or just upgrade everything needs it to acquire. But this
isn't really specific to Rust, and whatever is decided is global to the full
LKMM.

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
>
> So for all intents and purposes, the only sound mapping when pairing
> READ_ONCE() with an atomic load on the Rust side is to use Acquire
> ordering.

LLVM handles address dependency much saner than GCC does. It for example won't
turn address comparing equal into meaning that the pointer can be interchanged
(as provenance won't match). Currently only address comparision to NULL or
static can have effect on pointer provenance.

Although, last time I asked if we can rely on this for address dependency, I
didn't get an affirmitive answer -- but I think in practice it won't be lost (as
currently implemented).

Furthermore, Rust code currently does not participate in LTO.

Best,
Gary

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFTKIA3DYRAV.18HDP8UCNC8NM%40garyguo.net.
