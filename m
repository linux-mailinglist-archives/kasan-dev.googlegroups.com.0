Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB7UMU7DAMGQEOHAWEVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93504B5A244
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 22:20:16 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b49715fdfbsf191519801cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 13:20:16 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1758054015; cv=pass;
        d=google.com; s=arc-20240605;
        b=H4kZmMjjrHf2+Audql6FJr0FrPQ/DEQs7WI1FWitI3t7bb15bIyXZWxdZRJHUojo3z
         elLRQI8C7uIbwwCRjfPUnf2VlqRYkSQtL0XfJZFjy0VyoL4dmWfBhwmHWKGunA4XKcS4
         V6mdU7/jDulGvlfiwGF0BjjU9YXAMNrKP2niGvRpSkQaSxEM0gWuXNIkLenyQMekwRxA
         F5+eLaNGHREL44kEe0lY9r9i4MhWzoZLQmBbd5x5/GDa+TG+++O6f2ptbbGRoRUEXu60
         eDrRVXvNuqC+wcUAscHWIOyPqm4e5EbY51VrUmoymnQelS9yRpSxXOKPetA8g/P5haHt
         mfLw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=bYZgULawO86qmASqglswv2dcN4U6ESND2v4cKqezy+8=;
        fh=x8T0Xd1/lBSXKtTVN053IZ7L9FVWNUwgo3dUAF61AF4=;
        b=GhVUzrsV19LO9nBObm1mvFCbpxnx8+amMbc4riy6dXvJhRBrnmSpNR4LAgCa/8+z+5
         +0RzqkLObXsg5CUJybHpVfs3b+pE+VzDaxMnVRgib9+n3yoj7Ztl3oSWmiDmTvo5knXa
         eN6KmfPrlvqJnO9Lycq05m0CTKJZgNMw9gP4SdOy4qyqdYdtDVEHVTth4GWIEsyh73HO
         1hmgL7N3epLqGS+MHOcKbwiIj2A8CYT46OGg+JsuxzNVFlJ877e9ODMqEMZpgQTHK5Sw
         NRN8fcETg2L75DQBFpyPub6WFOIcO/3lELA92n/PzImjIVbYfe/pzPtdJer1311Fq0tK
         o18A==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758054015; x=1758658815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bYZgULawO86qmASqglswv2dcN4U6ESND2v4cKqezy+8=;
        b=jJNF+GHBc3bb0lBujlTmWJ/obIn9EQ3+g6RhlcIYUVyOkqGC6bD1OpqGoX/v0LSn6B
         0zeH+RUpgh4CE7cSoa/20sMasiNqI7qhtahLolAFhOp0QArWncOLNVqPMjOjvZuvy0h9
         /1UTYl9ky0XcY/BqAJxeM0JVPBCLp2yxaTNQoj6DwK1EkvguqkzUMWi7yRE6Mq3n5tgh
         Yo0yIfJLR8ssF6t2tlYaYiRVa0vpFEWTuQfB0KFSSe6Hx6lUtih/n8OMKdt/OZsWrr0M
         LuU/uI53zzXvvppExDmSvdcJU7eF3sg2GLn5DmBgmGdq7GsqtqoeU3FdmST+CGjA6Z1C
         WMAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758054015; x=1758658815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bYZgULawO86qmASqglswv2dcN4U6ESND2v4cKqezy+8=;
        b=NyOI/siJCdu4FMUZxHPp1Hbx5gxHH2d7MpX1X5TyYXop2U5GQ5DGi9zOPEIpYRBRKj
         mXuELmzaOpwsmnzYNEDJQuSmpdtffAwwjUAvK/6oBXK0Ud5zzm3P0O66bBC9/as2doIn
         v4sRMnP8VfRScuZt+llxbRiIZG6+iyKgrUN9wgEQh3CVEFSGilPf7BKarnrnglnYviBI
         dxcEFaeeK4ZZCYAMDWveNEEEIhWlwVGJ0dSPtO0KXxGSWJTvWluAGVPVmQd/hVz72aWm
         zP8W+dR4W3Pgd0vc5s1lRq94t2l+jbMu8hr0F20zrqm3Q/Xej+vTZkSnoswzNDImB+Yw
         rvpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCWgo/lcEpjp+A4eUBuDmqmzm7go/foxALoEnH3sc0oMpwJgK6WBKCihOqnQo6oeUouJGvJyyw==@lfdr.de
X-Gm-Message-State: AOJu0YzWgIJiOIh6MZH4VHEAYspG/TAOeMMt+fkNPJ9aVBswLGL5xOph
	hTWICobxMp25f7NmQir3Vy/c/uUVtxAhDDgd13NNBMwDex1ZP9kL+Lbx
X-Google-Smtp-Source: AGHT+IE2ZbHxsUDfmNrDe2gAM4Jrm2fFkcdyvQsGKx1nTdLxb4PCkQiJvvUPRjVUoELTRq/6vV4TOQ==
X-Received: by 2002:ac8:59cf:0:b0:4b7:a9ef:1987 with SMTP id d75a77b69052e-4b7aef57598mr88387721cf.39.1758054015180;
        Tue, 16 Sep 2025 13:20:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7NHUaDHQtBZeXsId8Y95NYXRnjcaA8A1I88BWxbai3Ww==
Received: by 2002:a05:622a:4cd:b0:4ab:9462:5bc0 with SMTP id
 d75a77b69052e-4b636cc04b2ls117488061cf.2.-pod-prod-06-us; Tue, 16 Sep 2025
 13:20:14 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCXCvHb85EMA5fqKEvrHQzMnWJWZlKaygy7lIwz/OG9rXVSfP5rPvT4SsBh5KJXYF0cZ4T7qwjNUScM=@googlegroups.com
X-Received: by 2002:a05:620a:45a4:b0:827:2774:65e8 with SMTP id af79cd13be357-827277466e1mr1642897185a.53.1758054014209;
        Tue, 16 Sep 2025 13:20:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758054014; cv=pass;
        d=google.com; s=arc-20240605;
        b=j/aR2JY5IcUqqKRbdaLF2bK6N/YUG5q75EZ6vIr0y908B1l51otA/D9hkZq8yVQAWw
         Y7mORHB4jd0ZGdUxXPTCdOlFyBwsYN0zz1rl/hNpTL5TkAjVHZkcDHs0YEbi7Cjfom/D
         CALMVlR2JRjkcNyjkY+2zDv4dCJ3ZcW+NZ0UOXy3GFwyg259A7SIefjLqIim4o+OIr+4
         LiTdxbCN7qVwPezghUSgmqdUVOGVyaqvfNJYEUa1jq1aV59T3gd8AedB/DHPkuYwgNyU
         3HHsAJuSKmuwpuRWiqXY5yoKGm/d57pC96LyPL5qZoJt8c/RYb4F2Uz4yWUgNxH6T32l
         /4pg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=C3YrmNehmqe1Ht9TRKWTelwYxC1g+CY9haqK59EB0B0=;
        fh=lJVQRhEe4KjqEpDa/+3QFv8qByHyuZ9TrzQWLwzaFGM=;
        b=iPz4nwGQGEPy0McxR7rA3Ix/gUsmSbpOZUFTTGzAiAcqqL4nrxmN/GY73L2RUHW+Qt
         C2zZ3RhmTFtj8WlNjNvS675UlGWtYmPl8zQLJ2lPgRFNcUnNkubX5cT/U+8UN+VpTAmq
         TctcnMW5S/7Ht7xyUSApqESyxNweFmkXZyIONs9ILsuA1I8MqC/tZnIxLy7lgqSoMvLN
         jvtIfWTFMegCrdZp+bp89cPEBpTVDIOICukFN9dfqU/1Nh6RLK9tDQhif0lFHQO2XfJ3
         HDIkc3CU2e9hiqpcxjhGSI27VZsj3ORd2Ggiw3bpaIuHaqu4X/bKpGiqYn5WnfbZP3Il
         KxEA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AM0PR02CU008.outbound.protection.outlook.com (mail-westeuropeazlp170130006.outbound.protection.outlook.com. [2a01:111:f403:c201::6])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820c87de2dasi62704685a.1.2025.09.16.13.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 13:20:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) client-ip=2a01:111:f403:c201::6;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=Mt7MdtgdyXq+GYPSRX0N8Qkm7vnigu1qXRCVq1SjHrQUEavZMh8f10L29FJHzG6YijbwRSL7HWh58dbnftruORZijjs0wtFmajbvMLyLrxSN+iZMw9IZDe4O9Q9PStAjXBnSm9+rakEjEzbBWHFvK0az08T8qbH0mZYNWezehGQFog91Qdz/0mQOmnoGPTeFmyN5y0fmi9iIt9iC6CS+NPPTxYbR9oh1usCur3UYmA2jUlICmLjVA+h3EnKB1IYNzmV8y1UBZyE757FA2BUcZikz/gvdEH89plCuWTOYOZweqG1lpN3WyzhOrrg8u1YLxdv3E75WIcGHLP2J6Ugm/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=C3YrmNehmqe1Ht9TRKWTelwYxC1g+CY9haqK59EB0B0=;
 b=NCPe0M5lsfkyWtCJXZi31mhed3fIR9QIFRisM38expgVOMGi+w034gIolgA52KMUuu1B231eMl1WOF/5tp8AqnV9lfLKkXDbFPXW5bZhHkFDOYedioq0f73f24B/3lix6b2iEqA20cC/xZ+aMv6mj1wvy6+YNRAS08WNXgz8gjhS8iTV0RgAeuk4xjrjLI8YAtY0twqNdB/uC7ytvuJNjSTLKwCKxWBbZqAqY07EKb4Yufh60Y96gKa6QBzEV+GiaWFiQbTcNuONhhjCA58T3OdYprdrmscT1Is42edUxERUkgM1BbgrIx6BGqU/PSvpjWrEgsRuxdYt+n6vssBa5w==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=kernel.org smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DU6P191CA0031.EURP191.PROD.OUTLOOK.COM (2603:10a6:10:53f::10)
 by AM8PR08MB6578.eurprd08.prod.outlook.com (2603:10a6:20b:36a::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 20:20:08 +0000
Received: from DB3PEPF0000885A.eurprd02.prod.outlook.com
 (2603:10a6:10:53f:cafe::95) by DU6P191CA0031.outlook.office365.com
 (2603:10a6:10:53f::10) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9137.13 via Frontend Transport; Tue,
 16 Sep 2025 20:20:08 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB3PEPF0000885A.mail.protection.outlook.com (10.167.242.5) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9137.12
 via Frontend Transport; Tue, 16 Sep 2025 20:20:08 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=O+dVUi6QJ8+erMATAE8/+NnNm1v8PIl61OyrfuR8i1XH8Ni48h9GYmKQR3O+Yc7V4jyzZE0ykw0EnlA5IIigBBJJz3NX34+hBB2d2D1BYUXPK2Icz1KzhjamhWFAR8NTtMPvqc0T1Tykm+d2lqTolrmIq59zqjrJszRDL932Riq1zjk16ZO+KN46tUdi5H8NZamGv3BNJ4lVUtV+UVAvukwGgFqThg/ME7GEAyyFjRlVPkvMAzMQ21JvOl+WCk9fSa+Oj/p9MSOevF0Y7wDHTP5GDT6MyqiAbDw5PLvq+SQrgK4611znNKfitFpDvCnRiVwX8iJlh2VNr7KiJuDS2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=C3YrmNehmqe1Ht9TRKWTelwYxC1g+CY9haqK59EB0B0=;
 b=RM4fidqMIB5autWCGUeWxq99bUyUfEeeCNzh4hTGO0uaNJ0Cq6k5yO3AJ30Ji9lLUTDkJF8nMMQfbDmBQ4EVfibC/6+ZNCRV7mDB+Fei5EhnfUWKQZSTIKolo5+vlWON+l4CicVeiFfeUQEVPlXESLA+SpQokKb3fmN12jTM6FbSnx40Wj4BSbvXHduxvTZs/bLYMIfd79FFUKhhiev0oMmm1PRdh6xNaUIFZ23mI9YSeaN6ax8D4Jc4YgRBCtkwWao5so2Ds16T9ZsiJOAa9pNSEDGG0Lcj/cDC+xD0E1uJI05sia1SD2gQB0InYPSgWBznXV37z6eGZTdiAbOpJg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by FRZPR08MB11097.eurprd08.prod.outlook.com
 (2603:10a6:d10:13d::15) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.23; Tue, 16 Sep
 2025 20:19:34 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%3]) with mapi id 15.20.9115.020; Tue, 16 Sep 2025
 20:19:33 +0000
Date: Tue, 16 Sep 2025 21:19:30 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Will Deacon <will@kernel.org>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	catalin.marinas@arm.com, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v7 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aMnGUr9zeutyPpAg@e129823.arm.com>
References: <20250903150020.1131840-1-yeoreum.yun@arm.com>
 <20250903150020.1131840-2-yeoreum.yun@arm.com>
 <aMm69C3IGuDHF248@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aMm69C3IGuDHF248@willie-the-truck>
X-ClientProxiedBy: LO6P265CA0015.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:339::8) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|FRZPR08MB11097:EE_|DB3PEPF0000885A:EE_|AM8PR08MB6578:EE_
X-MS-Office365-Filtering-Correlation-Id: 822ef14f-0e62-47d5-234c-08ddf55e6e6b
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?JNDyuGhrBv4SpZSvkhKQHrO+l7SJDZ5ZZpLETbU1RlXP8bD+56GrdrHtERch?=
 =?us-ascii?Q?ok98uh4JdtCbXVAeEgQqU6qdNXlc+iAk5olymZQEypBGlVVnhQJlkYZPvOie?=
 =?us-ascii?Q?IUNqs2H8x0JLoMDWmzEp80OhgRNkoBMH04wSe3Ctn7eUL7YKL2yNEI5UGo9T?=
 =?us-ascii?Q?GvdvRBA3vtw9vtK07zTTq5zD858aX0iu2K1eGQI8Af1YMI9PssE0qDlpQOFp?=
 =?us-ascii?Q?p4BbKFaZSXk8xNHR4ekP+Agz15aXBCWwVtoZsTvZXAqhZJKfaLyQPPgzO6Kt?=
 =?us-ascii?Q?dcSe1K0SkFyVehW2uo9JisrYSjbIJjuB8YcoVinox7CYWyZXTm3TYTafoOEe?=
 =?us-ascii?Q?jWn4ZoGSD3aClSStEQsH4gBZD808BpMpn+7j9kBIoWRBjxKquBj13wvDKzCM?=
 =?us-ascii?Q?OrvdqDb2dgkutxG+SdgQoxDBBPYAAHg7cn9kwxXwxqqpjjYf16IVjg/9AvAu?=
 =?us-ascii?Q?GYaWhYZw8+QU2NEBLYXRrKG6A4irJRKH5spRi4/R+HxgXJs5afUfv/xo0UEz?=
 =?us-ascii?Q?UZs8TaH1BXzIiUHWNritXKcO9SLN+DqkAWCk6z3jbwKdovPFU2+QmNOQjgBf?=
 =?us-ascii?Q?+Dk2tYTIBPegN3SaIVmlqYLZjItYB2+sxXHUEr/gPEgGMA24s4oBKcn3dUvh?=
 =?us-ascii?Q?wnZZH/Z9u06JeZ8NSfQl2Cnn5Ez5Ry98qvhccz9wCj78f9aLxbwlM5mXIOUK?=
 =?us-ascii?Q?hbnWn3/yKX493FQZEduyzIeFklKwxXgqmPCXASmpTrIfm7j+FU4MDpiBopzh?=
 =?us-ascii?Q?qcD+Jd5pk41jVYTorqOv2Io0Lvn6gXiUJlGSkO8jpIQdFoqkJQLjRXnw/Vyi?=
 =?us-ascii?Q?1SqXkGBKO6mkhn81glgv1IOu7VRyUqdeOSiZUWEJOg/w/MVONSeEVyBtdSd7?=
 =?us-ascii?Q?TU16V2NFBn/GtodA8klCJJVLeE+Yxd4Zv2u+j0F5iLB5jkWgn8MIwP1jZ6+A?=
 =?us-ascii?Q?AuaH/t3IYQnl5ZoaZpChjLSU7i15uWbvt812XWKkXZr3qO4dxj/AyMrZERfL?=
 =?us-ascii?Q?N3lq5lUNSpqeabdGcrSopasCYmyQA5NV8PTYFWchWFu8pffJm2baK8lEj0yx?=
 =?us-ascii?Q?pUx+QTA+Nrz1QGtkkQwBymNQHht2nUmvMRvqHt/JLi7ZODBMjPHaaZXmSS0B?=
 =?us-ascii?Q?JTnm2HmDQ/27m/1bILJS/FLe36YaJowJVFAa30dFM8GjDlavvOes0uni4QLX?=
 =?us-ascii?Q?an/7Yv1yWA20oj0l6RqVztVYbr3mSMZj9dCqG6QglwO8Hl7LKHH1Lom4FsRI?=
 =?us-ascii?Q?gcl65e9RgApJWTKuNuLEs/GbH8wo4DlnnqMJuJJVqn5d6KshqHtjvXHreosG?=
 =?us-ascii?Q?I43N196UjaZsGftuhQV79y/gh43mQf6EGmb9yigsHe2TwMySZN8MFm5uBRTx?=
 =?us-ascii?Q?l+UG76ylwzOVpxzzJdG3rS2QdHPoW++H2D7tV+OkPj8ALiViuCR36OeE+Y34?=
 =?us-ascii?Q?+Aal+mB1m0w=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: FRZPR08MB11097
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB3PEPF0000885A.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: c3807f4c-f252-444b-bb30-08ddf55e598e
X-Microsoft-Antispam: BCL:0;ARA:13230040|36860700013|1800799024|14060799003|7416014|376014|82310400026|35042699022;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?iGXzVzR0KlbvwFvy+AiLW/ip6uiWEGFIyaspagtumpEmJGnxf49laKFPeaXJ?=
 =?us-ascii?Q?v+ZOd9xLhOAA90jI+f08EhQWPr3FoFW8y3xCg3dH3v8hJ1rypk074C+q3sQ9?=
 =?us-ascii?Q?53mduiPCcatMdh6Z5NG/rIYboy8XIc13ogT7DDBXDXoyL0L8yTAQ8kalkkPl?=
 =?us-ascii?Q?jo0cx8/PLWxZV35g9+V2BrvI7lXxTVoWprws6NiGQK8pVZgzNDiNdJrK1tEv?=
 =?us-ascii?Q?q0uzfq1O45nNfTyLE557QPY0fyBjSsYQQPvR749KucAUcjTpy4PBONcYC+g9?=
 =?us-ascii?Q?rdS8WWSTbjAilhzQv7ilhQP98nKT0W1c0BkztCd4cjZ1DdUsW+j6+1x98+zq?=
 =?us-ascii?Q?xUxHs18c676qJn+Fdkc6rWQ9M8pLYMYZWxTPvxCynUs3pnyTJZ0yB8sm8ABa?=
 =?us-ascii?Q?mAVZEduJzcrcROpcJakLYAylOBc4U4d3IRkFiqq3JnDzsXlE2WnFgOahBeNL?=
 =?us-ascii?Q?Ktq1ebKj4Hs7jvFeK7FwdY9Na9XvdSk0KXlmajnTnH+xDgcYWNooE40lrdNo?=
 =?us-ascii?Q?kEhKvobUkb03F97jyMRjU5kL/IX9w/FMt0YQXHFWCMv49NgYcyT3WB/4Mq3R?=
 =?us-ascii?Q?hZCQGs4XjzQ9JbwfD3AN4pjwULfsN0bFdaBIFckcwsZhOww4HmXIosuYRyeW?=
 =?us-ascii?Q?vHPuJGgvNrr0satBwSp3Ry6/nQoPVfrKvDRGd1xGiOD2EOWUAYh0Tw9vMClX?=
 =?us-ascii?Q?ReMXpi3mszCEdDyDfT9h2HymEh9JZN3X0qqLm6Zfb1TVIoU3+UIJHbSvK+kv?=
 =?us-ascii?Q?melp6mjxo90BV7G6WkkyrG2nib6BmF00kl0JPPe6m8sNMQB3+pcdRI80xBMT?=
 =?us-ascii?Q?1jI9j10mUpmprkBprVXKmK+GlNxV3ExkCdlUx2luGhEvPW98Dep7v0nAUpKQ?=
 =?us-ascii?Q?e8q+1N7loWFe/La0IveOkhiOTQOovbdo6kpVLjVNqZYxu6hiM9oLd4xzmGNY?=
 =?us-ascii?Q?8Ipoe3Tpnd3BMNc97CSlbLb83gRv7HujQIxIF2R6ZqaC0V8wmYtMBgmVqNCC?=
 =?us-ascii?Q?i/eYL1VpQiaITAK6wt7AcYv3Xdp6VrL72P66jx9P69yTGNH4rGe1yRgk5X7r?=
 =?us-ascii?Q?qSUXyTx/VO3kwdS5Vfbv1TF17/0pRmp0TP7Hfx3BgcmPlvOsxsdcb58dQXjC?=
 =?us-ascii?Q?gvZLIAbp090i2QWIs1G7CGVDT8FhO1fAZT+BRFGQP2Doj/uIThRCGQ6ih/hV?=
 =?us-ascii?Q?dxoLSgX7OHYFGPTBoQBUZTL19/XvWu0Omfhm5mfFOFOSCwQsng60k737qz/d?=
 =?us-ascii?Q?qdIODzObsv/0uo/EgbzvLh3UwAor+Ks4FEF+BTUCrjs8PJzqj7MEKzMh7I1/?=
 =?us-ascii?Q?Vszh8q93k14zfxjniziao4jQhOk9vPxTZPME0iSyXRQQyy2TIb1IZSK2/rie?=
 =?us-ascii?Q?Rmfxzw2iIGGI/XKlfMZ8xH42scCetsL4qAfgFM1+v+PeVkRFK26r5r9CyEx3?=
 =?us-ascii?Q?IuGdbHvPnfOAi7Seu6kIPDDZXOVk2Tly31/iPf6RhxlR/QJvxi12+BwvXAqC?=
 =?us-ascii?Q?TnR/pUFlHB7LJkGQNgRforgRfnqLaSAVGiSU?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(36860700013)(1800799024)(14060799003)(7416014)(376014)(82310400026)(35042699022);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 20:20:08.3394
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 822ef14f-0e62-47d5-234c-08ddf55e6e6b
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB3PEPF0000885A.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR08MB6578
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=NJ+tRNwY;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Will,

> On Wed, Sep 03, 2025 at 04:00:19PM +0100, Yeoreum Yun wrote:
> > Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> > raise of tag check fault on store operation only.
> > Introcude KASAN write only mode based on this feature.
>
> Typo ^^

Thanks.

>
> >
> > KASAN write only mode restricts KASAN checks operation for write only and
> > omits the checks for fetch/read operations when accessing memory.
> > So it might be used not only debugging enviroment but also normal
> > enviroment to check memory safty.
> >
> > This features can be controlled with "kasan.write_only" arguments.
> > When "kasan.write_only=on", KASAN checks write operation only otherwise
> > KASAN checks all operations.
> >
> > This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> > ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> > with other function together.
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> > ---
> >  Documentation/dev-tools/kasan.rst  |  3 ++
> >  arch/arm64/include/asm/memory.h    |  1 +
> >  arch/arm64/include/asm/mte-kasan.h |  6 +++
> >  arch/arm64/kernel/cpufeature.c     |  2 +-
> >  arch/arm64/kernel/mte.c            | 18 ++++++++
> >  mm/kasan/hw_tags.c                 | 70 +++++++++++++++++++++++++++++-
> >  mm/kasan/kasan.h                   |  7 +++
> >  7 files changed, 104 insertions(+), 3 deletions(-)
>
> [...]
>
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9a6927394b54..d5b5fb47d52b 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
> >  	KASAN_ARG_VMALLOC_ON,
> >  };
> >
> > +enum kasan_arg_write_only {
> > +	KASAN_ARG_WRITE_ONLY_DEFAULT,
> > +	KASAN_ARG_WRITE_ONLY_OFF,
> > +	KASAN_ARG_WRITE_ONLY_ON,
> > +};
> > +
> >  static enum kasan_arg kasan_arg __ro_after_init;
> >  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> >  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> > +static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
> >
> >  /*
> >   * Whether KASAN is enabled at all.
> > @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
> >  #endif
> >  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
> >
> > +/* Whether to check write accesses only. */
> > +static bool kasan_flag_write_only = false;
> > +
> >  #define PAGE_ALLOC_SAMPLE_DEFAULT	1
> >  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
> >
> > @@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg)
> >  }
> >  early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
> >
> > +/* kasan.write_only=off/on */
> > +static int __init early_kasan_flag_write_only(char *arg)
> > +{
> > +	if (!arg)
> > +		return -EINVAL;
> > +
> > +	if (!strcmp(arg, "off"))
> > +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_OFF;
> > +	else if (!strcmp(arg, "on"))
> > +		kasan_arg_write_only = KASAN_ARG_WRITE_ONLY_ON;
> > +	else
> > +		return -EINVAL;
> > +
> > +	return 0;
> > +}
> > +early_param("kasan.write_only", early_kasan_flag_write_only);
> > +
> >  static inline const char *kasan_mode_info(void)
> >  {
> >  	if (kasan_mode == KASAN_MODE_ASYNC)
> > @@ -257,15 +284,28 @@ void __init kasan_init_hw_tags(void)
> >  		break;
> >  	}
> >
> > +	switch (kasan_arg_write_only) {
> > +	case KASAN_ARG_WRITE_ONLY_DEFAULT:
> > +		/* Default is specified by kasan_flag_write_only definition. */
> > +		break;
> > +	case KASAN_ARG_WRITE_ONLY_OFF:
> > +		kasan_flag_write_only = false;
> > +		break;
> > +	case KASAN_ARG_WRITE_ONLY_ON:
> > +		kasan_flag_write_only = true;
> > +		break;
> > +	}
> > +
> >  	kasan_init_tags();
>
> I'm probably missing something here, but why have 'enum
> kasan_arg_write_only' at all? What stops you from setting
> 'kasan_flag_write_only' directly from early_kasan_flag_write_only()?
>
> This all looks weirdly over-engineered, as though 'kasan_flag_write_only'
> is expected to be statically initialised to something other than 'false'.

For the conherent pattern for other options.
Since other options manage arg value and internal state separately,
I just followed former ancestor.

>
> >  	/* KASAN is now initialized, enable it. */
> >  	static_branch_enable(&kasan_flag_enabled);
> >
> > -	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
> > +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s)\n",
> >  		kasan_mode_info(),
> >  		str_on_off(kasan_vmalloc_enabled()),
> > -		str_on_off(kasan_stack_collection_enabled()));
> > +		str_on_off(kasan_stack_collection_enabled()),
> > +		str_on_off(kasan_arg_write_only));
>
> It's also confusing, because now you appear to be passing the funny new
> 'enum' type to str_on_off(), which expects a bool.

Oops. This is my mistake from v3 :(
Thanks to point out ///

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMnGUr9zeutyPpAg%40e129823.arm.com.
