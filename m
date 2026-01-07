Return-Path: <kasan-dev+bncBC6ZNIURTQNRBP4W7HFAMGQE5IKPQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 52BE9CFD867
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 13:02:10 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-34ac814f308sf3413978a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 04:02:10 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1767787328; cv=pass;
        d=google.com; s=arc-20240605;
        b=H5K/EvQ4lz0rNdBNuSPIGoE0nqoSYLtZUJFTiR/EohM+VIjy3psd/EaTTTTtVHZD/7
         CLYeXq4yBjNQ1kpwaK1HRJOE0iM/jm2BJYsWuqM8VD8XYn6FqOav0XyOIYigFCa/T0fL
         L0b59J5rGjZCRfdd8NM2czkzC0t48ryJCyZsEc0+OYS/pLO08QG0GwqdSHgkQb1Rkvgq
         xP2rmvL/KqEcVjLxx9EdM/ngNBAkhYx4Sjt0Etn697nplkKjntuQqLaLqnzaRXS76mmU
         CE0oKKxYxVoK5QhAUmEgvJNZ0ZpbKF5wtY3w+jMRn675jvBwmWj7JhGmC3whyidPIEqC
         X1HQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:dkim-signature;
        bh=XLdFisQWbqFWfQtZA7sY7Cp6thjN7/LOJd48QvWGqJI=;
        fh=WUG5+6urpX3ZlDazlP8z7EzHkRf24pgF8Sf21vyHxdY=;
        b=XLfgzbE3JTPJ8rOeQmaTzuG7WIv/j9Fab/q9wqKLWlVdVSKqxrWrtsG1hvMJLlhl+6
         bUspCasDKL9UEvAHN0BahlaDpnSItWoe2piCFEhC32NA5I7YLjrwQqFgF2Yf/0maLuEh
         IpV2Y/Qh2R5g4D24MOG6Hmn0NKy3f/lRZnA8QbJs5paYHLcK/UOA3tXXSKoF4nqKXL9p
         mgIptiIKIOGOqMGep2Nh3iXaVJqkHA8pyGUWbXG2EB/7SzgpilaHsAWDxAzQCao4Gyro
         FHNO1uccPmzihBXAAqtoT2BPI0ms0NWLBpCm6z0g0NubrK+5mwl9jHd2U+os1cYmapv5
         PEng==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=bkFWbSwx;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767787328; x=1768392128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XLdFisQWbqFWfQtZA7sY7Cp6thjN7/LOJd48QvWGqJI=;
        b=e8x71p2nZrONLf6SvAWwZIUjn56d2Wq7ImLvBIwrv39T+snZvkpDKf5oS+tkciMOcd
         Hu6kgp/o6+YtS5+MHzV3kNYBxqXVX5z0iwoHZzgzL2QRsr0vCjiqc4Dragz5OjtDbbeT
         1nLsYvDMN4bcHVI+ltEqbajBaD999e0HmkbQClAT8hwQujvEW4QRbNUj89QCIZcaMeRo
         SQzfHqDAK9Y14JDh9Ioo4PyBKMU2Maramz7uQh8iC6gOtO5lzbCnef/G7jQqzo14Ox65
         5ZznRA14QR3KxVrqeEJiv427LbQXxYveTKUGF4Py7X2ksVAyVF7n7U3i6X+waHYrxzyP
         f0uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767787328; x=1768392128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XLdFisQWbqFWfQtZA7sY7Cp6thjN7/LOJd48QvWGqJI=;
        b=oVDIWeezKGU4kSz2FIVMTsM6YXUSRkt/R3IG9r1ck7UfGMEJtjvPNOlU57oR44kj9v
         nIuqdzcTege8k2nQXO7F7lKpZMXW5T5NuaHBwcZAm0uXuFy/b0q9K/4i2wRpqbBm3lvm
         vumnboXI/zPs7QRVSSV/BB+p7H90DLCtvIMavQ7OgVnkq+LPB9hp3ks9jp7UIykugX+o
         lRwf/FmRxPJi3fZIZw9PsPTqxi8MPdizclmsepDuq+bdsQeK1BiPJwj8ADO++KXB5yLJ
         vcXgjx5H/Z9wIL48VVHOe4PWAOi84RHt9xVh2kcOwiBZExILuA3yB1lV0lSAf0tK7g6i
         TLWw==
X-Forwarded-Encrypted: i=3; AJvYcCVO7/I+VNyDTcpWLvsvcRB1gPIZ9NS5XBl8qXZbxCv9x9Vj06ChHFB+b+QloUfTWAwewIzK5w==@lfdr.de
X-Gm-Message-State: AOJu0YxabnhxsfFCbhmtIrbbMANZoV0cp3jtVXQnI89T51zhaH7kAe+Y
	o3PfSs7u6eKreiQHz5t7d9zJABjtEtKM50iCcLEP2XJG/XVg6hIUjI3F
X-Google-Smtp-Source: AGHT+IGOrNghxeyGdpI6SENviI0jGVLlqseAaxQEVHVHNSy7fAuwFzoaEBOAbEjVgtWoQ74Lu+ThEw==
X-Received: by 2002:a17:90b:1e02:b0:34e:808c:95eb with SMTP id 98e67ed59e1d1-34f68cd6b61mr1771388a91.32.1767787327889;
        Wed, 07 Jan 2026 04:02:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa0rsfY7+agwBjevyAbLXXwttB+ivq92mGDN8hwd5mKDg=="
Received: by 2002:a17:90b:20b:b0:340:7380:d09b with SMTP id
 98e67ed59e1d1-34f5ea78cc4ls1675191a91.2.-pod-prod-08-us; Wed, 07 Jan 2026
 04:02:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCU8skfalh8LI1BotI7AdU5i7dZNGn/BzSYX81Uak8szJ1anK/OEe2UEAfkEYZOfczNTa5ROlTxZXqY=@googlegroups.com
X-Received: by 2002:a17:90b:4984:b0:34c:9cf7:60a0 with SMTP id 98e67ed59e1d1-34f68c32aefmr2181305a91.5.1767787325328;
        Wed, 07 Jan 2026 04:02:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767787325; cv=pass;
        d=google.com; s=arc-20240605;
        b=XrHxIlYZntfVhMZJd/zXyH4Yn7vm8vbhojTQkIJxeV/+cv62h5UuahyqOPc8LAyxcB
         PkSj+VNyIfP6K7VUqyzebES50M2/CYsQyxFp9RvKyjUCyoawmIvsSwlsKp6iHbYlLLoV
         jbB/0xa1II4OztJG3eYi9vNB/nZwVbVLqJ25Ihwdp6SFV4YIaaF77Pki1RVeCUoHf0Pt
         MAY+yN++ZltmjLxx5fS6FwDqi+uBZAajPLI/4FTDkOdQMytSlSmwRZ3msSAA5Hcmt7Id
         yVCkSrFVC1/+ZeiU6hQkfm07si1ehftFvHfBXnqQFqVnlzK2cCHlINSqEg+KxzjQcKt2
         AOOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=eJ3lydofdy01tmtybht9zIJBp3RpI775AYciY7B8ucU=;
        fh=eHTCBJE8UjEYmE0r/x2qysASWnyQnwclK+1iuCfWeQY=;
        b=L+BvgVFVTXCW/Oo+TbAwnYmFZ/1rzAYaj042BoTWK5NH/+UbcHHRNvHF7nKoiqp5vH
         wajLz29MIugk4ocmq2n45EIqRHZDU9b32QuwrxdnfdFi3iuzMvYmVCbUHbpaTrSRgadb
         TPH6SSdJV2msfwriRUxuUwJBo+SH7hX2QguW6Q8mwQoeQieM3T1xDOX4WWFHOb/LZwsu
         HZweEa7leY9irEFzW4p6/7FaDhnPFxP+KfgWaTsFbqj79H6QonpdIB8dyCFuMiTuN3aG
         JotqTKrQAfVv2fBt8f0ad9kC95w4MBxT+tloIbFfdaPEWgXLfAYJikTTKx67fHVshU8D
         g6uQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=bkFWbSwx;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from SJ2PR03CU001.outbound.protection.outlook.com (mail-westusazlp170120002.outbound.protection.outlook.com. [2a01:111:f403:c001::2])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a3e4776e6bsi1094085ad.10.2026.01.07.04.02.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 04:02:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c001::2 as permitted sender) client-ip=2a01:111:f403:c001::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=AvHOAp8PX68C4HWQ74z2nOueWVuNPXFjUNlzKEaKmIUiy5Vg82OeXszgg+EU76BFQecUBYragZxWAlyKZ273eh3On4k+gxwMLfkMgbe2OtB0/Jfhhydbyd9rCOJWjYz80ADiEuQ4Ol9nMKUuAUMQPQI5f9QfvtBkw5GtK0ibS2s0jJOsoJU3LL8p7+n94weSiY2p9cAM7U+1H+xCXC5MTkNwkTpTAPZvsRrq3rWc7JdjY3b+ASAN70K2f9VzTreeQKd9BNjLuak/Bbspj4/y3zQ9vlhvhwThHDiKSEQSPLHchxE97p0X/P2Ynqncows5HnHxRBOnMZkruWfj9nCNww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=eJ3lydofdy01tmtybht9zIJBp3RpI775AYciY7B8ucU=;
 b=x0uhoF7JSIgxaGSXiBqYe6QdrtYtnElF2iiL/bm/DUsyCdp5rNY4rRIGTWJEsPBD5YM/dV1QGfiEphoaIFWmXSvbrvnXgl1AhcLnZevw7q4aJPZ0xQNvaE6qoLstwpoMPvXZrAXRWc1v+/PJfS2wtGKdy+BPD+xdDItYoNk8EW5mmOAHCGJ4LHjcDpW4KSrGdskuJwGpditKxrb4W5HpCwdsWmaEquk12RIUFPIWa3YQz64nr9KtRHKlxSGY9esYuSUoLQbRwy9a+DgMnyc+Y5jnKY2bjm9XvzjG+FXfJucP+bpGSI/DCDKpeLVNaew8aAdJb+zmTrvCPOaPjKyTBw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by BN8PR03MB5090.namprd03.prod.outlook.com (2603:10b6:408:db::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.2; Wed, 7 Jan
 2026 12:02:02 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9499.002; Wed, 7 Jan 2026
 12:02:02 +0000
Message-ID: <f24422b7-0985-4583-9d0c-7e8f303197b5@citrix.com>
Date: Wed, 7 Jan 2026 12:01:58 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>,
 Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86/kfence: Avoid writing L1TF-vulnerable PTEs
To: Alexander Potapenko <glider@google.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <CAG_fn=UnyVPSEt1bsWMw6QLRFkeMF8UcObVXv01j8FPYDV+__g@mail.gmail.com>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAG_fn=UnyVPSEt1bsWMw6QLRFkeMF8UcObVXv01j8FPYDV+__g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: LO0P265CA0006.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:355::17) To IA1PR03MB8288.namprd03.prod.outlook.com
 (2603:10b6:208:59e::6)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|BN8PR03MB5090:EE_
X-MS-Office365-Filtering-Correlation-Id: 54b709b4-0683-424b-5cb8-08de4de49185
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?L3MvNzliSlcvU3cyZk9qOGJLbGRyMWVRRDJjaGhvZG9lYXEyR0hKVWhSQ2tR?=
 =?utf-8?B?T1ZLUzJydzNXdDVhVUpEYVhSVlRwd3BCNWdNT2E2a2JZM0piQUJsdnZId1dY?=
 =?utf-8?B?UjEzV1FDTFVWL2F4dG5kT3RPNThZaW9oRC9xeCtUWFZlZkFzMGVYNmxiTzJW?=
 =?utf-8?B?cSt4OGtrZDBVejFucys4M3NvY3ZqRk9uelFCbmljRHF3WDNjMUlRVUhXMDgx?=
 =?utf-8?B?RXZYMVhvaVdFRGtUck05TEJadWorNDdUQlBsMzV0NGdDZkRNeUZLZXdRK3hN?=
 =?utf-8?B?KzhRa3NNL2FkWHhYWlNqNmkwODVtMWtzS3pwdjBZd21Tb3paN2VLWC83S1p1?=
 =?utf-8?B?N3liV1hHYVF2MGhXQ096MDVsNldoMnJ0MnBoUkpzSkc3T3BxKy9ZRStZellO?=
 =?utf-8?B?RGMzNnNGcTlFQkhnY0lDTlJOekNPWGkrQmtMVXRSK0pBM0l5QXNnUjMrWDZl?=
 =?utf-8?B?Q3dNT3RqTVVNU09aLzNkZm9vTkR2cEF5S1Ayak9yWXl5M3ZZOStEb01yV0VD?=
 =?utf-8?B?b1JoMFl3TzNqL3piaitKM3VtLy9IV0pHTTNRaWZqOHpEWnU3UlRQS3pPb0xX?=
 =?utf-8?B?T3ZPVjVMMXoyT2lpZTB1WkVwUEM4QlFuamhybVh4WDlXWVRVam8raURvRjNh?=
 =?utf-8?B?c1pHWXZ5ME1QK1A0TzhRbUhmQ1RVaXJHblRobDMzaFBOdmxPT09WMDBTbEZk?=
 =?utf-8?B?aDNwMU9pOXA4MmpSRjBxdHFsK2pQb1pGTXAxa1AvUzRGTzY4bmEzNENCaE5X?=
 =?utf-8?B?Tzgxc3NIY3E5Tm9UMEhPWHpvMzN0VXk0SDVEUWVMbnFMeUpFODZ0bE1McU9X?=
 =?utf-8?B?VWkraG5uS1pPM05jZTVjcVpjTFpRcDFqb0xvcEh4SFppaG5Oakk0Z1djZGti?=
 =?utf-8?B?MGRsbldoWlJMK0o4c2Jydk5BR1RqeXZIcmJJUmVuenFTdmdHSU1BaGxpK0VL?=
 =?utf-8?B?bVZ3eWlsSXNTZEJBN25tUmZseVIwbEwyUEZoc2dkRUpUdWJrMU9RUG44dUhX?=
 =?utf-8?B?OGtLT041V2Qxby9oRkFsc09MSWdFWFpDQ1o4dmZtL2xNYjdwT0dlT0RMQjMy?=
 =?utf-8?B?eFQwcFRYV010UmJXUWdMMGN0NzRxZ2NrbC8yalZLYmFqY3JQUGVIOGNjOU5w?=
 =?utf-8?B?OStYckdGNktWZ2VPNk9hUzAzZXdOS1F2L29HRW1rZks4N2lKbi9BSVM3QzVI?=
 =?utf-8?B?UjdiZ0pnUmJjMmFiVkxmRjJpMXk0Z3VZNktlSlRCejA3TFpzaklud3Z6bUlJ?=
 =?utf-8?B?MVNMTFdTalh3OEtHNVNVa0JqRUZpQjRERFNDbDAwQkFYd1ZSVVR6NWpQczBM?=
 =?utf-8?B?aGR3L1pJckN2Rmh0MnZ0aWRQWWVxZ3lNR1V1b1cySTVMQ1pCM1ZsNkhHU2NO?=
 =?utf-8?B?WGs3YXJvZEJmZTVEc2lFZFZqWW84VFhCQUV6bG5OdFFlSTlsTWUzZ0U0YVk1?=
 =?utf-8?B?RVhUeCtWREZ1V3liRHJCUkI5RFVtN092SzdJQXV4eTM0QXpvcnB4WXd6UTBP?=
 =?utf-8?B?VGVQY0lWM0plUzFCVjV4SG1vRkZlWEdDSzVIZll1Z3c4WGREVmNxUjhiTUE0?=
 =?utf-8?B?a24zV09wRGRjak8vU3lLYytKeTUrNG8rdVhsb2s5eFpuSTJUSlhRZ04xTU1t?=
 =?utf-8?B?cS9NNG1GMm5mWUg1SWk0R1ZmV0pOY2MydVR2ck1QUktnZDR1L1o2czdTZW1m?=
 =?utf-8?B?TW91c1dnRDM2akRHM2N2VUJqWENxS3MwWDVSdUw1NkhCaUFQajQrd0I4WWpk?=
 =?utf-8?B?VEdSSlk4V1NEdS9NcHZTUUdzQi96SUJJSXpTRy9jb3dhN3IvazNmV1F0RTc3?=
 =?utf-8?B?QlRoakNGc0ZnOFdncWZSVXZYSHU0WlN2bVdLZWhNVDRvTU03bzNGWEhGTGJY?=
 =?utf-8?B?WEsybVM5MDcvYzM0OUJOeldGd1pQT0tKYUtSRTFLSlNHdDd0N1gxN2hkdWR4?=
 =?utf-8?Q?Y5f68BxzcwB6O+puWAbRLcJgbIYHh7qT?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Q2R6c1IvcG5WVnN2T0ozVCtwQ2RkUVJ3eCsxVG5OMWxiRGZtVHJnM1pIdzdh?=
 =?utf-8?B?ZzQxdXRWeDh2c1dBYm02Z21EQjZHSkRqVzZNVTEyT2NJblFCMGZiTHNqUzV4?=
 =?utf-8?B?NVkrN1lwdnZqM3JXRThoVTZPdHk1OGpOTzZEdEhZWU5mOFF1WHZDSm5PWUZh?=
 =?utf-8?B?TWg3dnZZZldZZzdDN2RhYXdwVmhHQllvUHU2Z2xRdU5meG5abE90Wk44TXNX?=
 =?utf-8?B?cjFlRkYwbGNaSjQ2Z01zeWszTldtLy8wWmg3T01Ldmtadys3QjlxVmpNNmp5?=
 =?utf-8?B?ZzhJQjFnYXQwR3k1SWkrc1FQQTduUG1PU3p5Z1NYbk9pblphYXFFTERGck13?=
 =?utf-8?B?QkFOQ3ZRbHd4eXVpeGxjS2c5d055aVpLWENKT0VpTzk4WGFQdTRXNUJ5MGVH?=
 =?utf-8?B?cWRSOWR0dHRBUVRONXg5SUNCcDdpa0pFWkh2QTFMOWdFMmNUWjZvNWJBSjlv?=
 =?utf-8?B?VjlvOEJSbTdsQXE4VHBLN1hGWW5Eb0Jvc3F0R0JOYXA3ZC9hVWNuQS9JWG1F?=
 =?utf-8?B?RGNtMFZOQVhMWHlGNXdMVWVNd2JKckZhbG5iTzNzK0IzUmh6ZFNCNEF0UWZ4?=
 =?utf-8?B?d3RYdE5TQmNCV2tuK05GdUxXWndNbjJybUxRbEVCY0xBd3NPSnVmL21VR0Rs?=
 =?utf-8?B?ZXpwZmZFUTlwRyt3dFBVQUs3QnBITUxXZVVxakpMZWdzZXFPZnV6VE1lRkZI?=
 =?utf-8?B?ZDQ2bkRMTlp4S2YvUEc1NmFLS05oQnVnUzFDQW5jSy80dGp3LzlXaTBoMWNw?=
 =?utf-8?B?TmdBcEg1Wm9xYjFIRUxtNy83MnF3a05jaXMvRGlUT1AxRFBYY1ZFSzRramxI?=
 =?utf-8?B?RXZaNE03YnlKdEw0SVlwbGZMREYzUVFXZEVCc01telVtbjlWRFZrdW5tOEVY?=
 =?utf-8?B?Z3JEWENSckEvd2FzNmNjb3VLUVZFSVhEYTZ2eUdqS3pQWnF6QkIxTUNva2ZK?=
 =?utf-8?B?Wm9WZ0JUTWlKNEVtSGRHSTAvNERMcGphUnFISXp3eXNqM2Y3dk80Tm4rZGVr?=
 =?utf-8?B?MkNkMVpYdThxaXd3OVl3UGlLUEdNMU5DNzczSnpQdHRnN0pwREd2UkdNenl3?=
 =?utf-8?B?V0JTNEZmbHo4US83RzB4clRDaW9QM0JybGh1VURmcW01WXpZZkJLR0YzRksx?=
 =?utf-8?B?V2J6aTN3N0c5dVEraU5NeVBXSUV6T3Q1VFpZVFp2SXBxSFVLNlZaVmhoNi9R?=
 =?utf-8?B?emtFdk95K3VUeUlKNlZXSGZvNW5GMm16RVROSDMyK2h0em9hbG0xcDFPTDRU?=
 =?utf-8?B?L0dDMElpTVU4THRhRThKUlgwSFF2MlBhZThEOXlBODdLVnVMSXB6VlZNVDdK?=
 =?utf-8?B?SzJNODRnTXUvQTFhdG1uMnc5Qys5SHVocXA2dVZrTUFvM0MrVG56OGRsSXR5?=
 =?utf-8?B?TkFzNldYR3dwVFF5L2x3Rm5rdmgyM283U2M1M3Q5Qi9DTG9pbkROajkvN21H?=
 =?utf-8?B?Y3daclNvMGpkNEM0SHlvMk1sTG9ueVF2eXF6TWJRVks1S0xDK0Z3aUI5QVZn?=
 =?utf-8?B?MkRZbzFCdCtsMkl5aVNvaEZheHBCd3pZdUpLODNkNU1EbXJTNkcxcVFUdW9J?=
 =?utf-8?B?Nlovb00ra3lPeGFBS0JIcEsvdXdXNzVBNzJRb2VUVWNxWm5NelN4V3gvQkd3?=
 =?utf-8?B?dGZ6NVdZOVhpaUN4cU12V05VOWZrdlAxcmk1Nms5WWxTK3c0S24zQzRoTDNG?=
 =?utf-8?B?MkhGbENFL2JTYmhxYXY2Ylk0eGNialdaem1tb0hZbjBrRGtUYThyYTVjUmRL?=
 =?utf-8?B?b1pEeW5oNGV2WkpzUmFNdHVjUE0rN2Z5N1huNm9yRzUyMlZOQ1NNMTlTV3lv?=
 =?utf-8?B?QlMrMnpVQXVGVkJnb0owWGhCdGptOGl5QWRIZTFkMTIxSWU4UlYwcGtaNzFy?=
 =?utf-8?B?WjRSQ1N2TndzUGpWTTNZRXhkazNjcmdHNHc4TVRVT3BsdGFPUDlKc1oyNVox?=
 =?utf-8?B?YmNHUjRtcklUT1MzR2QrZ0o0TXNlcjc5M0ZCTzdaNUhHWUF5T3hvMFlpQ0pF?=
 =?utf-8?B?SU96MDQvVU9BN3FxMDFHUEhDWFNYK3ZXTi9HQk5QOWR4RWo2YTF5SHc4NmNP?=
 =?utf-8?B?R21vUm1IbTBJbVpwdmc0ajhrRjA4TXZxdUhOcU9hczBSWmMrOG1vYVRjVytI?=
 =?utf-8?B?S2o5TU9BdDZWTUpSMVlrL1Z1OWlWQml6MlBscW5ncVM1Y2pqRE1vcTVwT040?=
 =?utf-8?B?akNDUHpwa3BjdGpodDVKTHltRWcxSk1BcGtBT3RSOHdaSnhvSldTU0JpK0Ju?=
 =?utf-8?B?c2YwRzM4QnZFTGJBY0RtSVd0UXVMVkRjQUFsZmRjVTVsNDNDMWQxU2JyeGNr?=
 =?utf-8?B?SFY3cXRyVFNOVWpvYjVrVmZ1QXozeWZadUpwV3lBYjNpeVczbGVwZHh6RGtY?=
 =?utf-8?Q?8y1JVPcbiZAAWrrg=3D?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 54b709b4-0683-424b-5cb8-08de4de49185
X-MS-Exchange-CrossTenant-AuthSource: IA1PR03MB8288.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Jan 2026 12:02:02.6077
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kCPfdmgbvqL1oifoDpC7lvuT9w7OiFWn40MJyG5PlsJ/5treNXJ4GhwFKQAlaXTFtjXtU/zljEqh0ukG8TFwu/rjotEtU+4NWn3UEggTEvE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN8PR03MB5090
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=bkFWbSwx;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c001::2 as permitted
 sender) smtp.mailfrom=andrew.cooper@citrix.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=citrix.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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

On 07/01/2026 11:31 am, Alexander Potapenko wrote:
> On Tue, Jan 6, 2026 at 7:04=E2=80=AFPM Andrew Cooper <andrew.cooper3@citr=
ix.com> wrote:
>> For native, the choice of PTE is fine.  There's real memory backing the
>> non-present PTE.  However, for XenPV, Xen complains:
>>
>>   (XEN) d1 L1TF-vulnerable L1e 8010000018200066 - Shadowing
>>
>> To explain, some background on XenPV pagetables:
>>
>>   Xen PV guests are control their own pagetables; they choose the new PT=
E
>>   value, and use hypercalls to make changes so Xen can audit for safety.
>>
>>   In addition to a regular reference count, Xen also maintains a type
>>   reference count.  e.g. SegDesc (referenced by vGDT/vLDT),
>>   Writable (referenced with _PAGE_RW) or L{1..4} (referenced by vCR3 or =
a
>>   lower pagetable level).  This is in order to prevent e.g. a page being
>>   inserted into the pagetables for which the guest has a writable mappin=
g.
>>
>>   For non-present mappings, all other bits become software accessible, a=
nd
>>   typically contain metadata rather a real frame address.  There is noth=
ing
>>   that a reference count could sensibly be tied to.  As such, even if Xe=
n
>>   could recognise the address as currently safe, nothing would prevent t=
hat
>>   frame from changing owner to another VM in the future.
>>
>>   When Xen detects a PV guest writing a L1TF-PTE, it responds by activat=
ing
>>   shadow paging. This is normally only used for the live phase of
>>   migration, and comes with a reasonable overhead.
>>
>> KFENCE only cares about getting #PF to catch wild accesses; it doesn't c=
are
>> about the value for non-present mappings.  Use a fully inverted PTE, to
>> avoid hitting the slow path when running under Xen.
>>
>> While adjusting the logic, take the opportunity to skip all actions if t=
he
>> PTE is already in the right state, half the number PVOps callouts, and s=
kip
>> TLB maintenance on a !P -> P transition which benefits non-Xen cases too=
.
>>
>> Fixes: 1dc0da6e9ec0 ("x86, kfence: enable KFENCE for x86")
>> Tested-by: Marco Elver <elver@google.com>
>> Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks.

>
>>         /*
>>          * We need to avoid IPIs, as we may get KFENCE allocations or fa=
ults
>>          * with interrupts disabled. Therefore, the below is best-effort=
, and
>> @@ -53,11 +77,6 @@ static inline bool kfence_protect_page(unsigned long =
addr, bool protect)
>>          * lazy fault handling takes care of faults after the page is PR=
ESENT.
>>          */
> Nit: should this comment be moved above before set_pte() or merged wit
> the following comment block?

Hmm, probably merged as they're both about the TLB maintenance.=C2=A0 But t=
he
end result is a far more messy diff:

@@ -42,23 +42,40 @@ static inline bool kfence_protect_page(unsigned long ad=
dr, bool protect)
=C2=A0{
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned int level;
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pte_t *pte =3D lookup_address(ad=
dr, &level);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pteval_t val;
=C2=A0
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (WARN_ON(!pte || level !=3D P=
G_LEVEL_4K))
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return false;
=C2=A0
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 val =3D pte_val(*pte);
+
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * We need to avoid IPIs, as we =
may get KFENCE allocations or faults
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * with interrupts disabled. The=
refore, the below is best-effort, and
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * does not flush TLBs on all CP=
Us. We can tolerate some inaccuracy;
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * lazy fault handling takes car=
e of faults after the page is PRESENT.
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * protect requires making the p=
age not-present.=C2=A0 If the PTE is
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * already in the right state, t=
here's nothing to do.
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (protect !=3D !!(val & _PAGE_PRESE=
NT))
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return true;
+
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Otherwise, invert the entire =
PTE.=C2=A0 This avoids writing out an
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * L1TF-vulnerable PTE (not pres=
ent, without the high address bits
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * set).
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(pte, __pte(~val));
=C2=A0
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (protect)
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * If the page was protected (no=
n-present) and we're making it
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * present, there is no need to =
flush the TLB at all.
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!protect)
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return true;
=C2=A0
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * We need to avoid IPIs, as we =
may get KFENCE allocations or faults
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * with interrupts disabled. The=
refore, the below is best-effort, and
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * does not flush TLBs on all CP=
Us. We can tolerate some inaccuracy;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * lazy fault handling takes car=
e of faults after the page is PRESENT.
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Flush this CPU's TLB, as=
suming whoever did the allocation/free is
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * likely to continue runni=
ng on this CPU.
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */



I need to resubmit anyway, because I've spotted one silly error in the
commit message.

I could submit two patches, with the second one stated as "to make the
previous patch legible".

Thoughts?

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
24422b7-0985-4583-9d0c-7e8f303197b5%40citrix.com.
