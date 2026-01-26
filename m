Return-Path: <kasan-dev+bncBC6ZNIURTQNRBXWI37FQMGQEUIHV7KQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id SIYFCWHkd2k9mQEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBXWI37FQMGQEUIHV7KQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 23:02:09 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id B318E8DC93
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 23:02:08 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-8c52af6855fsf611938685a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 14:02:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769464927; cv=pass;
        d=google.com; s=arc-20240605;
        b=BpnPrJEuY6oIJco1nf1skvIRh5MwgK7SUDHNcfCTzgYTSVnB14X/Y+SobqY990BrmW
         /l6JS2ZsoGdsqm7CRkGvbS1bN7WEV17ZtZ45d+zGnfjQ9Kpuk33EbDbI2/t25S4xtfVF
         R15W2sJBBb+FZcVj1TGBoKIuoypyflM5s+FESpNgeb0NwyWww4sAXNhVrNtljPLHkF9T
         Y43sQHhdjQNfVJFeLxilsgWSd7kxQYQ5Mdv2l9tifusTD0N1zQ0nJlac787K8k6xIgNP
         r1uGrqhHKgBrMuDd4ppKEgRn4wO4p01RnKqhrtsCQ+0vsGVUXTNMQ+NJ0O6UT6oDLJDw
         xa9A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=epd95zmP+KeTpNTo6feyMZOLDS1U32XOUXN9x1+iXTE=;
        fh=ClleFix0ar4pKbxmaOjn7jnZrSgOyKA7xMaygUz3hGg=;
        b=NDc8/Qp7WJvJsXpvnOixwK/gAAJ8yFTNApMXdEJmtCS/boWFTiPf6/2q+5vmQaD0Dy
         JFwBa22v8hzwFXjaQY3tyyzgoNZgj3SdxLsLR7tdMCoojh2XNggntX9esV/SaLy5wk8W
         TlzcJMQKrOjytT/ZediEEH/IPDzgr72P6pYLQc5BshT6Zb4YD5DbEKZa07TvHJDzxW5G
         WeDK+PtvC8lcBMc0s0x0oR1wW+6iByew1JKS90t2Z1KSeMpHlq3f6krvJQAZh3oA+rBJ
         6dg3kqKRZ4nOEq3qviD+Nr8LbLXGbtdwYAp80+onc9dCaWuiN5JPynKZTh4tgPZ85ycl
         1tlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=DVOYpFwL;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c107::3 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769464927; x=1770069727; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:to:subject:cc
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=epd95zmP+KeTpNTo6feyMZOLDS1U32XOUXN9x1+iXTE=;
        b=pkRdm+4u8MzEgRbkppgSWb8V4SeK2RjCEuu9Lsf98c1Kx5MTROFFELm3bKQLbvDi4U
         xkyKZ7PlM/6Yo664HadIAn7UCPHF1Cz5jiVwPKtmS04HRvU+w+R/aiqyIs+MMVPdWIft
         QcrWveunn1L2koA1jql8RjmglXmm/aPEz2rM7jgg60lMVHzjxsjJPeNfReRvypUa817w
         5cW2+H3qG2Vcqtxl8TINTlDuZW87iTyp/n4yC1uInoLtOYA27gbE7UY7TZS31LcXxVVD
         3AErJqlFVQ/kqbFTaNAr+7/APp8Uknf0VzO1fNvEfdZMPYtTFPTx9FcYenme0I13e450
         g7hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769464927; x=1770069727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:content-language:references:to:subject:cc
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=epd95zmP+KeTpNTo6feyMZOLDS1U32XOUXN9x1+iXTE=;
        b=Gbs3NTl3cS15UeuvvsY5iZOV8wVqDTo0Si3T8T9DePy6SkTaUUlgK719He58KTY+uY
         +e+En/lFb1MuX2ERirCRxOxa6edXbbN/53m1n7LfbqSAXoKK5tD4a1GPFVHMKkNOAI7X
         Yw5uWfZmpv+kh+gotrC7QH/O71iEKWcb28DKWjWTZ809lFEwOaT1vxfPZ3KUJK7QvVTd
         Wum7Va6EM/tmYyphsIHaqx6NTc6eopLBzeSrdZ++XaK5bPAeQdQRftP1/msSqU8c7Oxx
         IKL7ik5GT0lADwOYO76za+suvXFA86P+dPXD9jhJicrrHp7SqnEoLVzp+M8TTD6UmNHt
         CuEg==
X-Forwarded-Encrypted: i=3; AJvYcCVqtdaQh/eN3wdyzL2LnmqQDoEij5s6sGFw2Qu/vj5XgplAyhh2RMS9uiiDMaxOpeQfcGmvzA==@lfdr.de
X-Gm-Message-State: AOJu0YwPeNnj6kD8zuiQ1FLJtF4c+4AptTRSoqGrQqmoYCsLihH2lFWL
	h24ci3EVsJV4UKZbnr5DdBq7qmRo39puFVgR3NY75/lVjXZ6+f4n7vY/
X-Received: by 2002:a05:620a:448b:b0:8c6:b1ba:3009 with SMTP id af79cd13be357-8c6f963c634mr689722285a.61.1769464927191;
        Mon, 26 Jan 2026 14:02:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fmf0u3ucnIBqieZuJI4UFBxjbVXRu6/lMUxWZVwBtLrw=="
Received: by 2002:a05:6214:2505:b0:888:3f27:d2e2 with SMTP id
 6a1803df08f44-8947df0e784ls93760036d6.2.-pod-prod-08-us; Mon, 26 Jan 2026
 14:02:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUpfKKhQE/FZP6Pao3B4kiZT9abjbwoboDlDBY/Rd5/D49sUIiIi0Kg43XN1i4zQ+deJQg9elTB5t4=@googlegroups.com
X-Received: by 2002:a05:620a:178b:b0:89b:9b75:f5f1 with SMTP id af79cd13be357-8c6f9614c42mr673360485a.53.1769464924184;
        Mon, 26 Jan 2026 14:02:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769464924; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZGSDgNzu1BWAH03Siv7341A2y/ZS510rndmLI0mVnY+hKhy9BZyKND0TJuyWqvu1R
         kEhrtBGzaD4g/PVxv4ku8GX8QfNqOPSBh4R6Www9l7ziSlBKsGMJos5RUi5ppS2KnyLB
         zNTq5wPEdy1rrgBuFaNCIJtdflQxEk7BG8kIwakJUdBneP18HyN+xw9QOhzFp/j3ToGL
         TZmg00xXUlTv/vMYcfkrinnw7CGZwby+0IYmkQtex+IquHZfrshBmRZTHqbF0dpdvQDt
         I9BbJKW+9LkbWIPjlCSLhWrrcF+tg3Gym8rBrSJtxCNRoqFx9PL5EJtDjFQN/59ZfYle
         KjMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=rxEP7fYNvV5qrOyPUDP++UkA1sMoV7O3JfjaICJUqeE=;
        fh=y8e/FXJVx60geSj/915Gb0xnsIKVO4bAAMIbXr86wBA=;
        b=lH+eicqFtjnFKmfVfTeBrSRIwP0CC75YR6buomjcyJ4gWqOsonXYPSwMKubCKQROSZ
         0HnFQyxHzhYHziRqtODcoOOPULO1sNN7xR13Z4sptBde+iohFyhh0rBB6iRQ2AdcHnE+
         WM3yJkUSP88lPBGWQQapQ7HJTsAjZEzFs2Z9Nr3hU0Kok0Ej5usI5p2TWcErFx/sjCoY
         jXdCFSfSfa08f7OKrz1cwngaDLYYqKIBeMZTkxhTEj8K9So/skQHili9FjNmbY8+U2Pc
         eD32UptMx6/BchWoseKe5gN1Yxpp0XPWcIKIuov+SXuI5wO1CE74skXvEEWvY3VrBJi0
         965g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=DVOYpFwL;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c107::3 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from PH0PR06CU001.outbound.protection.outlook.com (mail-westus3azlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c107::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8949157ce37si3659676d6.0.2026.01.26.14.02.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 14:02:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c107::3 as permitted sender) client-ip=2a01:111:f403:c107::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gupNQfDZPHUcHVC7DbXDn/jFvaS0qvwCbfaFqtKVC1zyXM9Ty6gkxaON6GDHujUZxlvLd+gdjTSz4iRqa35oyAps3hdTyclSL2kPoohHMJr49LI7iUbvJamnsI4KT3LkNsbxdbtmuuThV22MuHLvkooilkhxpjcAxC3Hi19spWwd4ihzC9hxrUieMH21KSGFFi1IT0zXCwbqK3qctRn29DpNgO9rvOTnWbFHr4BUilK3nrnPxzLJ2pUJCzEfvHhgmnONRtChk6u7t9ciblhc9YykeVH86nGxH6hIO1X2dap0GlJlez2w0IpOtZv8JHKCgL5gP0SqMq6elZqrgzQ5NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=rxEP7fYNvV5qrOyPUDP++UkA1sMoV7O3JfjaICJUqeE=;
 b=OsRAbOZ4BpFmnRutf0jfoaQ90Nio2rV57FzJmU6TV8p1M9RdKF2c7A2nSgdnWAJo9bDzq80yKh6xnY7FKDbkuqd9FjCvaxPpz1c1Ebp8Mqx+sFsKNfkmEnuBEmbySiKfk2fhx17UAepkpOAPgnoQ0fQKJdtGlNIsyKJB2T2wb24KTGYebcoddxbYdDyKpT52IYeLMCDNY4zhv8uKcXZMXBnYDpH2QJ+6F0dW37f16FVPaWxG2gWHIe6HHhlzyJlxrsJ/X7a25RmcYO+Vw5XeN9ILoN1wpNZpRCt1DarVZhzz/BXhzkCCacNG4/u2zsBagh2GhgkQkhdfLleuZf/UIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by BN9PR03MB6075.namprd03.prod.outlook.com (2603:10b6:408:118::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.11; Mon, 26 Jan
 2026 22:02:01 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9542.015; Mon, 26 Jan 2026
 22:02:01 +0000
Message-ID: <fe0e90d2-6237-4a23-baec-dbf8eeb45fc5@citrix.com>
Date: Mon, 26 Jan 2026 22:01:56 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Ryusuke Konishi <konishi.ryusuke@gmail.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2] x86/kfence: Fix booting on 32bit non-PAE systems
To: Borislav Petkov <bp@alien8.de>, Andrew Morton <akpm@linux-foundation.org>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126211046.2096622-1-andrew.cooper3@citrix.com>
 <20260126132450.fe903384a227a558fab50536@linux-foundation.org>
 <20260126215610.GEaXfi-r-5g-9SAVMI@fat_crate.local>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20260126215610.GEaXfi-r-5g-9SAVMI@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO2P265CA0230.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:b::26) To CH8PR03MB8275.namprd03.prod.outlook.com
 (2603:10b6:610:2b9::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|BN9PR03MB6075:EE_
X-MS-Office365-Filtering-Correlation-Id: 20c09b67-5a63-44bd-3f3c-08de5d268847
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?c3lhcnkvTVdqVEh2d0tMakUwQ3o1d09DMWNKUHJHLzFyYldBSnNQSEhacnhj?=
 =?utf-8?B?aEdhUFNpcTRCMXlwdjY1dTBkMlQrQVlCbGQ3aGY2U1RqRExoOEFZa1JaMExz?=
 =?utf-8?B?MHRFZDJDYWFBbmYyVVA3ZW02cXhxclduMmRVUVBrNWhteUJwc0ZGMThuSzBI?=
 =?utf-8?B?cGlPYU5zMGtpM2dYYW1IU053R3VwaksrZU1LNUdnUEtLb1AyZ1hHL1dENUZ4?=
 =?utf-8?B?NjFuOHMyN241TUlCcTNoM1dLOXNpT01NT3VvQ21DM0VId1ZaNTBLSFVwTVpH?=
 =?utf-8?B?bmZLQlhrelgydzU2UFRYYm90QkxqeGR3QTcycTZUR2QvV21waHdNRnBUeCtM?=
 =?utf-8?B?bktYQ24zSHRQRnVpdzc5L2g4N09mcTZtVkV4d3g2NFErYkhYLzhUckQ4dTJx?=
 =?utf-8?B?YnJkVEM3Uk1rRU5Kb2Z5bFQzOUx5ZFJIRzUrRFpESjRzZ0x6OGpFeExhNWdG?=
 =?utf-8?B?SkRNVWZoRjFBR2dCMUNlMjM4SlJBMkJjQWY2b0tGbmlXZ3BpakNYeVlkeE0z?=
 =?utf-8?B?TDZNY3N5UzBubzRUc21EeDg3SXd2S3ZFUy9iTXZDY3Q3ZlI3bjZwKzZZR0xP?=
 =?utf-8?B?VUhqQ05IYmpEM1BpUWFaRFZvTlRoWDNEU1Q1bGpNTEZuVWFDd2VRd2FlaU5p?=
 =?utf-8?B?RENmbnVNWVRDUmlpOGplSzBTWUxKb1BXTHIvOHozdW1yZTR5MEpFOWxWdXQ3?=
 =?utf-8?B?SHh1R3BqZ2xNN2kvY1VwcEhzM0RBTmtzZmEvOE9kaE51dVNrVXhHM0FwOVhY?=
 =?utf-8?B?cmovZEZuaFVxMU4wcEdEOUJHbEQxVmU4MlJIQ2FYUlNnZ05vTXRCd2lPN0Jh?=
 =?utf-8?B?L3FHamFuK3JEVjFmRXkweUIvY2tUS0Qybzl0U0RySFlENGwzTW0vaDBmT21C?=
 =?utf-8?B?YkZFc0xWdjMyTk5neExwUjFHMjR0azN0eVJHaDl0NVlmRDlidmRrQVFsNzFr?=
 =?utf-8?B?QlRiTFc0TThUdk1BMVJxSnY5U2gvYjQ2VmthOUJoRUx3SmRvaGo1ZGdGZHRE?=
 =?utf-8?B?K2RnQkZnWkFDMDhzSmFwdlVBS0tOSXl6ajBvOWtrbXFTeUJ4Q08ybEdFQnAw?=
 =?utf-8?B?U1NpZUVxalNJMVozaW45VmpwMWZnOHk1RlR5cGNoa25lZkRDamlzVUpCWWh0?=
 =?utf-8?B?NE44czVodkZ6R2svaDZwTVphRXNnSEZZZzZHdHNEUStUL21DU0oreUNLYU5q?=
 =?utf-8?B?WHdCN3FJc3p6ajBIYnlXZFFnRW42MGFWT2RCYmpoaHBnbGo3eGR5TWh6eEM0?=
 =?utf-8?B?Mi9jV2NqN0JyTEx3MUtHNHFESlRpTnZUaFlzZG13NE02NXhSMkFRbC80aUt2?=
 =?utf-8?B?emZRWDg4TnMwbkZ2OTlORUVpM3FvREphNE5UVmU2K1pkRHVoRjVkZXBUU01j?=
 =?utf-8?B?QzFUWmhVWGpieEN4UmVjSjZwZDV0UzJJa1dmUmp1bHozSWpMRUFuejZkRzlF?=
 =?utf-8?B?cE5EZ3FtYm1nZEtYRzdkeEQ0bkp2NCt0amdqYlR0a2ZBZWpaZGFWMC9ESmFY?=
 =?utf-8?B?VHY3M0JkT0VlSjdiZmR0Y3hNbWROL084bmN3VklzUE9lbHR3UVBkZGZWSURh?=
 =?utf-8?B?RnBTR3oySGt6OWJPZlM1TWpubzFtcXlwL3BveVl4b3JSTHhnQkdHeERwQWRL?=
 =?utf-8?B?bVFxdm1CWitiZnBJdW1KNEM0ZnZmbjlyYWRDL2ZZWFNiRUErSDNpcWwwVzRO?=
 =?utf-8?B?V3FGb2Q2V2p4Wm1oQUNVQXB6ZWxJUW54SklwdDUxbmZXR3RuWFBWc21mYktq?=
 =?utf-8?B?RFFnWmpXTTVkOVFMd2V2SkFqNWtDMEc5cS9ZWGlCWlRxRVdWM2V0eSt2WVBv?=
 =?utf-8?B?SnZyY09wdTRQZndSTnVHNFpQNUlDNWlDbEhxN25EVi82RUVHMXJDT2JPVENZ?=
 =?utf-8?B?UUswd01FMGRxOFhWeG1LMVBUT29iMkN5L2tPMTFwOHpCOW9UcENRSTh6NnRo?=
 =?utf-8?B?YUREWnV0U2VRelNQOWhWNng1Z3ArTVJLQWJ4emFMQzhUdElCOTdpdkRPQTYv?=
 =?utf-8?B?NFVDWDJmVUJja3F5RTV1bXV4MlBiOEkvSlJkYlRnQ0JjMWlHNDZOWGxnaUFs?=
 =?utf-8?B?WFNpcnZqQTNoOXpvdTlGMytmTkZtZ2xENTgrUnVpcWsrVWlVaEcvZm54aXNi?=
 =?utf-8?Q?59UE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?MGpYUlZka1R5R0Y5b3AybFV6VzJ5L2RtOXR4dThFT1lmeDUwbFFpazdMa2sw?=
 =?utf-8?B?VTZXRVVmcGx6WmpoRHdqYkc3U0xOeVhzV24xbmY3LzRucEVwS1piYXhMV2ts?=
 =?utf-8?B?amEvcmtHYW1Pek9CT05EKzlZMXE0Ky9PMlVMQ2JHc0hXUHBqQVFnY3hKUkFW?=
 =?utf-8?B?OHZsa2Y0M0dpbHRyK21MdUdFV1kzT1h2N2s2azJRZHY1b2FReUEzbXFwSlJo?=
 =?utf-8?B?REVKQVdtbXJ2YUhFWVJoMDV0Y2EyU3Y3SHB2RUZRc0NTS2JjUzllTlE3ZERX?=
 =?utf-8?B?KzZ2Rm51ckNNbVB3YVp1b1NlVVhpMUhlUFF4RDJ3WERYajg5SWFhODN5SzZD?=
 =?utf-8?B?QlZhZHRzWC9SUDQwVXowaHQwc0lWTElZNzkxQkZYQkpUOFRCS3pDSFczbnRU?=
 =?utf-8?B?eExWVy9BdzNiSXZSWEJmWlluVXQ3Y2F5ZHFvUkk4SS9pT1E4bms3aXQ0KzEz?=
 =?utf-8?B?ZGJ5OHhYYUNyR3J0SmJ3cG1CZHlSV3FZM2NOT291ejNMU2tnbHBUYkl0ZUpl?=
 =?utf-8?B?eWF1Q0ZWQ25wbDlJYys1ZXFmeUt1WjU2Zlg4bW1FTmJqa3R5LzJSa0VVY21s?=
 =?utf-8?B?dTFZaFRnTm01ZllCbnozc1FDTzBqNzFpeHc4MHgzL3BCWGs0R253S29ySkIy?=
 =?utf-8?B?bmlGcGhTNk1yQWhjYzZDWHZnc3VFbkExeGVIWFFsUWJvYmkwdlpJejFTcThm?=
 =?utf-8?B?dzE4SG1mSWhrMmZtTlVBSWJEWGY3RzRFY3ZQWXNrWHl2cEJ1S0dvOU5hbXJR?=
 =?utf-8?B?aVF3OG9WKzZyMEZZaFk3d2VlZW82aGhZS3BnYXNTODUrTXNJUVJ0eTg5UHZ6?=
 =?utf-8?B?U0ZOcUFMZlIwaFQ0WXNEUXVGS2hJQk5FM3lIUDgrKzhmUFNveitROWpnRDBs?=
 =?utf-8?B?SThlckg0UlJzcnVjVnVheE00YUkxbmxMVUhHa3pOR2gzcEFvRlVXbTlXWEdH?=
 =?utf-8?B?Y04zWElQRzk2a3R6d1RIMHArTDNVak5xSGFzSk13MkxRQ3Y5L3Z4UGtISXc0?=
 =?utf-8?B?dEh2QnVhSUd2dDQvRmpTWnovVEYyYlYwQkh6Rm1rMGRqaWJkbG1zNGtEcnVh?=
 =?utf-8?B?RU9ld0JVMjRCYTJPSWM1UElyQ0FCV0o5YnJJaXFmMU9HMUYzdFhVWUNOSkhD?=
 =?utf-8?B?aXkvbHJhdHd5bFlkQmlkNklTdWJ1Mm5zNVRXZEUzN2pieGNnK3NiMmp2SXlW?=
 =?utf-8?B?Z25jYko1OGxRQWhvK2kyYkFtcTVHYXBEb0NHaGRKWVpGSkV2WkJzSDdGODNv?=
 =?utf-8?B?YlBqNnQxQ2YwcmVkdjZKU2FTeVF6K2Jud3lORWVsTkp1MnVzUmpuNjRtbUR2?=
 =?utf-8?B?YUY1SmtwckNTWE9WbERuWVRpRy9zL1VWTnVPUnVxREpEcGdiN3JRU2prL3lo?=
 =?utf-8?B?bFVncmFIUE0vTS9lZEVLR1J4eDJlVkk2c0dqWVFjUjNlbk9Pb0trRFhBOUJQ?=
 =?utf-8?B?Y3ZmS1UwdFIwQTd0VEJ4Q2JiY3lydThHMVgvVHErZWdyaWJHUi9CeGs0MFhy?=
 =?utf-8?B?TlFSbXpHT2JnbG9FZG9pNjFHcWJBSWlKNXJ1UFh5aVZ3QVZ1cy81cStsZnZv?=
 =?utf-8?B?SGlZUFo4QlNqN0FUaGE0em5DQjlPVFlWbTNtbjFBN0YyK2p1OFJmakIxaE9s?=
 =?utf-8?B?bWw5aTY0eFhFcXVhQ3ZIK2JOU0pEWVBSZmd1M2owcFNpL2p1N0pOQjdEWEZN?=
 =?utf-8?B?TXFwdCswUEpGaWpNVjA5NjlQUXFPMU5PNDVzbkJaZk05V1daMDdmMnJMdDVN?=
 =?utf-8?B?THlxTE53eXNuamo2WWhaNG8rSi9EME1vTzE5RU9kTmQ1R1NEdDRIQWVSMjAz?=
 =?utf-8?B?dndvTWdnRVgzVG9obFRnM3dVMkJwZmFKR2trWmlWelM5T3JKa1NFS3FoNTNu?=
 =?utf-8?B?V1J3T1NLU0JkTk5SRWRSSkoxdGpXb0xDVTdlMVR0OGFtbWhPY0xnMzNkeFhE?=
 =?utf-8?B?MExRc2srM2RZOGhXUHZlK1BadlA3Nnp0a0MwREhtVFpHYTU0SHkyTldkZjE0?=
 =?utf-8?B?VE1YVXZkaFhJUU5IV0xDemlwclRweGozdnU1T0NJZGVRMUtiRGhObWFvdXFs?=
 =?utf-8?B?RXIrVm56TTRrUjFKWnpkUjB0RDRHcFpZTDFBaGNtRGxhbkQ3UnFJREVTVnJ0?=
 =?utf-8?B?d1N5dms5eCtwRmFwT2gwQTl0dENCaHFqUGE5emJFUkNGdWk4S003a2hHZURL?=
 =?utf-8?B?dDRMQmh0VFlFb3pUQnNtR2RIM1BzWmNuU2NUS044Wlh2NnNUZ0hReVpNUWt0?=
 =?utf-8?B?dk5BeUpTTitjY3Q2M3ZJTU1RdXV2TmVVZVpLY2ZhM3k2aExpR3ROai8zeS9z?=
 =?utf-8?B?UUcwMUZuOEpvSGhmT2g3RC9pZTlCQWpER05vbHRUc3RsclBjb1NHMExxMmZx?=
 =?utf-8?Q?OJ6lJCsqLYzwWPgY=3D?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 20c09b67-5a63-44bd-3f3c-08de5d268847
X-MS-Exchange-CrossTenant-AuthSource: CH8PR03MB8275.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Jan 2026 22:02:01.1268
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: k5i9NnBp+0wGEe1OvNK4JdGyBOFvKZyXY89LyHwKmxypJQRrMFgXFVagWyRSTiLWwT1xaZTziJPPr2FoHyvvD5cGyZBZsRob4uueTXqZRAM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN9PR03MB6075
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=DVOYpFwL;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c107::3 as permitted
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_RHS_MATCH_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBXWI37FQMGQEUIHV7KQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[citrix.com,vger.kernel.org,gmail.com,google.com,linutronix.de,redhat.com,linux.intel.com,kernel.org,zytor.com,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[alien8.de:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: B318E8DC93
X-Rspamd-Action: no action

On 26/01/2026 9:56 pm, Borislav Petkov wrote:
> On Mon, Jan 26, 2026 at 01:24:50PM -0800, Andrew Morton wrote:
>> Great thanks.  I'll add
>>
>> 	Tested-by: Ryusuke Konishi <konishi.ryusuke@gmail.com>
>>
>> and, importantly,
>>
>> 	Cc: <stable@vger.kernel.org>
>>
>> to help everything get threaded together correctly.
>>
>>
>> I'll queue this as a 6.19-rcX hotfix.
> You can add also
>
> Tested-by: Borislav Petkov (AMD) <bp@alien8.de>
>
> Works on a real hw too.

Thanks, and sorry for the breakage.

~Andrew

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fe0e90d2-6237-4a23-baec-dbf8eeb45fc5%40citrix.com.
