Return-Path: <kasan-dev+bncBC37BC7E2QERBJV5Y3FQMGQEGMB7EII@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +EfTHqiecWmgKQAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBJV5Y3FQMGQEGMB7EII@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:51:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD1F617CC
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:51:03 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-8947e6ffdd2sf14744046d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 19:51:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769053862; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZXl7o7/3x7eHTUxpHFofhF1bk3He+YHSXG7cAH8dWfTPxcPINX2/VQkJyu95gdaEFh
         NehUlQJHNpbLa1PgH3NGrYmAhE/ayOlIxCAEX/3KaNx5XL6ZZWvSsY0pW5Qi2JBGBHF6
         IlHpCzmwviMKza0TaxQNHhs7NCxy2gP2kPGEe0PCOstpw0JaK1MtG9w6Lkiy4GekFt3v
         9LGDL7lzb6y5gKf88wtaMRqbFw5N4DFXfNJkh9Zy1rcrYuVnfzTiTGAFHTR3X4fFhUO+
         MUUu2j06Np3uLAFQ7VPYpnWja+rPWoj32Rso6/aYDIiJQWHbOhWde/vKnx95OsrWn3MR
         7Hsw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=6ttqR75SprcqDEvDtUpmtgGsSDKSRtb9G1orbIxTWr8=;
        fh=9RZYjw+ISWDhzt8wEcSADM3YBkTdfqF8i80Gw0pXWG4=;
        b=dBprH7edHfVT8+Bx3VCTeNrAx/YDE+Yf60eW0HvdTsoWXhQ3vMr0PVkTmeAkfKsi18
         TPpuKgSOAngklZ5XpoM7G1sugZDp3qELWTgERuknM3WprwIw+jAORWE6jN4+YuF1G8bz
         NnCevzteH4P36kaLrj5ItUbXFOYN94jreseBjFeO4UEFgJjz7ta4qx0jEpq+Bkzc0y9i
         RyeivD5VM5FGssiR+YBc7gG6wqCBbS4buVuXe9F5P1vLbhXxic4ayhJ4xHfsnFrEd4GA
         PSCxP0gp3XBa3CaJ7Gg0c1ha4pqqSFqqPCkpd/bpp7dEY5uLvuEqWTWKmRHsx6KIGKtr
         dIug==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YgqbA0JT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VU7P8Bdb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769053862; x=1769658662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=6ttqR75SprcqDEvDtUpmtgGsSDKSRtb9G1orbIxTWr8=;
        b=YSVCxbnZWY1kwW4wA18/rvHkRnDuYm6ArMlWhnwiXe03dWI/fp0VeJQpEClaIllx+i
         2gs13yFLkRvQp6bVXragegwAaX02UPqAZ3WrybiP8wOdLdStk97I2I0NjE2m/RR153pp
         lSbehIA/1TYYRgq6oIW1Rt0yQMiQAwREGnEM5FA+o/JAh4m4EE+2BuMqWsDL5IyK9FzZ
         FPNCPDaF7mcM22JhpNLGp0tI76ubuwGcIDAHIy2IKeSkjdHfPfjKOmJiACLGwKmoeB22
         4+yyeoMkB5jda1tSFZrfbE2ffgp/NXc8b9hrYw6yX7gLTVSTK26X17l1yPV6pvYDQefR
         hD0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769053862; x=1769658662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6ttqR75SprcqDEvDtUpmtgGsSDKSRtb9G1orbIxTWr8=;
        b=l030KXBMlg766GbDchk2c9ZDZy3S/6L2AKxeAzoEAQBpTYWLOXpWPv/aJS1Mu9fw/9
         LTjMbtbDu4IlkKIbyQ8mY0u9snHy/d91gBQX3GTV5QnYiZbzicis+n32jI0urF6XxDzV
         LxCCycihPvFjoZGYIvENxcbM/GX0EAR+rLz3OxZZLWDlBNmWCtokvDFlA8iA2QkU24zj
         +QQfysSGKHgLV8fShysaS8k8fK8dtb1y/fFvS6rCpsepyxBydyKIlRs1ZfuLmx5denbo
         hq8naXqG+Knu/9xApP06T+oRdNCBT1xFb/x6tzllo5r3h27qBqOoEOzlB46g+J3PFovn
         6Mng==
X-Forwarded-Encrypted: i=3; AJvYcCWxnmOmM9TBg/WtiDhAAp5QaxvJyda4Ax9kHVcPG1w0epZA+EIXlJHt45nQBtGErl9NNZ68eA==@lfdr.de
X-Gm-Message-State: AOJu0YwzbpugqrMQ/HwAF8QQwg1YoCbARYY9Oq9SAdLJvbvWR+rdIh6Z
	FiIJN4yKhdrBUq+VkesV7MV+n1ImUsfFC72nvqoqbqZGyDm/bRsiQSlW
X-Received: by 2002:ad4:40c3:0:b0:894:7c62:11d9 with SMTP id 6a1803df08f44-8947c6216b6mr26133586d6.68.1769053862629;
        Wed, 21 Jan 2026 19:51:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EfBWrBVCQp6VPqJAHKcXwsWwZBBgb/SHCeenyze8tTZQ=="
Received: by 2002:a05:6214:2481:b0:882:3acc:d7a with SMTP id
 6a1803df08f44-8947ddff5e8ls11784896d6.0.-pod-prod-07-us; Wed, 21 Jan 2026
 19:51:01 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVVvPXiXWuGBSq6r2RNDDWw1j1VE+Hhu6tOaBuggsOUAXD5fKRj0J+MT111gZkIKsVWpn6ejYipZ+I=@googlegroups.com
X-Received: by 2002:a05:6214:ccc:b0:894:5f6e:fde3 with SMTP id 6a1803df08f44-894638d2e00mr110331036d6.19.1769053861448;
        Wed, 21 Jan 2026 19:51:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769053861; cv=pass;
        d=google.com; s=arc-20240605;
        b=JeAWPXbleZ0GamAW8apyyPWBTlkKZaepiuJo5MFQmeBRJur5v702ERC8hoiAHViago
         SEZIWPmRwl83LqYBd+UeTt6rhAK5GNzNY+Qz2SAEO4qSVrjqMIa9vVAlhMFY6Fl0WcPj
         K8sIC0dvouz/qwyVxYEj1rQP3sUsee3yhDHislkcMYnpjDvZe4y1eZNJ23/X9fJGNBUB
         jFUAN+a8JQV/ZgLw29Nx0swT/MduxwzFwftIY7yvDU4nTCujnBBtoc3EidJQ1sGCTDFQ
         mrB0qboD6g3Jt0f0EG6yni5u/7TX3Y5YH40k43E7ipfg7DJ0N0Q2PcO3tDwqMMkSDmcd
         dM6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=1bIzV2Irx3QMPzUOzWAgGO/HxC9PDNnBNK4/C6+zW4E=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=N9NufXDdTHbCpl1ZT6xDAZRJsnUTDapzia9wlSiFmn0/65CqQ6Li6DNGJtqIZQ7uZy
         /4198plsjGycHYjoIQQCXySExR50kRL1K0lgR44wY8nVoo6RzYsSTxKlNx37t+28pmho
         ksy8u5j+rHTp57ZU0slDxX7IiC1pzeO+gMARsEA82DKuvPYoacWGcvq7rGgLgtqrt/j9
         v4LvZRm6bNmW0D4oEBuxulfIYuDYSmCg/c7OOt3ELIjASpdTJqRpXzptnYEbz4Ua0N6m
         inoS8wern06+HmRKjxeZbCjbLfB8JghTrP/WTFQxunEps3O4ge4ADsFgactFjCLnvZV8
         bBqw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YgqbA0JT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VU7P8Bdb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8947108c5c1si1306286d6.0.2026.01.21.19.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 19:51:01 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60LMachw3028859;
	Thu, 22 Jan 2026 03:50:57 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br10vy46g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 03:50:56 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M3IcbC039561;
	Thu, 22 Jan 2026 03:50:56 GMT
Received: from bl2pr02cu003.outbound.protection.outlook.com (mail-eastusazon11011033.outbound.protection.outlook.com [52.101.52.33])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vc7pnv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 03:50:56 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Uks6MVwuV5n9eWUbsRMW443lPm0BYjDwzsAQmEDZsPG0T0UHSNZLCsjF40IK3NrBmkf7kgyX/xVT4aGMQb8I94gXPJvfcnBdA7LyhKSO0Exs2KMvBkSK8UzBpp77hKUgKntFOcD2NH7KkU9GSfX75bZWuoGZCNuX0AzhnugFfKf4fozHzzNCPnHPXvnJ9PCuP5UR7eDtnOySE2sq92/eGl5eo5ibk6FLFz4JQrZM2a0BPkYdHm6PX7LYuDMgMGxKOJ2pj5PkSRCnje+1VxZB7T0lQHORP0HUJH0+dl+JG9NtNAZ5l6ZBFbvIMn1nAusptbi9sE6d7dH4scCljPBr1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1bIzV2Irx3QMPzUOzWAgGO/HxC9PDNnBNK4/C6+zW4E=;
 b=rF2cQ200hyyoMgD18HNNLAulonmNDxI25v/VJ0/JgkrKtyYX8b4+4t30CbS7gOsjoSAEWn9x8BBY/W6hAB46J1U+d9mqUQBvs/Q4EDqH8DnwHn3bBLmDe4fXlFsOY46XoHqDmcIG1Olx0HQL9NX9elJfS3Qumvz6lWnHn4ZnQ6htQEaB5UYM6piiC+r6SF0ttrjP+03sP49R60980ioYEGfpfqRdZisCD1s/8nPB0JjmSkRoKzrfnmg6pmde2S1FeJ0THXZknpP0IWlF2ObWf21O34WV6salONHtAkITcybiAqBV27rrly/Em/mb28c5wi6muPhXTVJJqHPf81YkBQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DS0PR10MB7341.namprd10.prod.outlook.com (2603:10b6:8:f8::22) by
 LV3PR10MB8153.namprd10.prod.outlook.com (2603:10b6:408:287::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Thu, 22 Jan
 2026 03:50:51 +0000
Received: from DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d]) by DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d%5]) with mapi id 15.20.9542.008; Thu, 22 Jan 2026
 03:50:51 +0000
Date: Thu, 22 Jan 2026 12:50:38 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 16/21] slab: remove unused PREEMPT_RT specific macros
Message-ID: <aXGejjS93L5fALig@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz>
X-ClientProxiedBy: SE2P216CA0038.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:116::13) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS0PR10MB7341:EE_|LV3PR10MB8153:EE_
X-MS-Office365-Filtering-Correlation-Id: 6c36bd4c-5142-4190-c7ad-08de59696f60
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4CIXDDKJvq9Ad7XoYK/bZZ/8J8LzVtFxqq0I/fvswxHfnsLafL8uuVtOdtcb?=
 =?us-ascii?Q?oL5xGdzQyzCJX/U32B5maNbf/N6DslyRcRSlSE0OgJAxx0lU4WLmo+HKJo56?=
 =?us-ascii?Q?VWIK/gaAJKDcXYegazNugsyA0DuBQtR34Q4bov72R/WwW5YoeAW7iiJV0klx?=
 =?us-ascii?Q?59u3JVTDgISV9zIAJETWUJSnUBqy1oRuGn8MelNooWtcoBHduy/9rHGjjiiy?=
 =?us-ascii?Q?x+DcQ4NkAFcm8J/tvXUb4UVcksXqiSLGjgC7mvUhwsNocCoxMSawBP7EA7tn?=
 =?us-ascii?Q?RXMajVDdZ5wlSVl2KZjVH/ylMv9NyTEAZuJxBo1R9bfKDNcvRxrDd7qs9pT8?=
 =?us-ascii?Q?SNx7NR85lvqM/LsFUDUd6ifaQuwSgHaLWGklxUVVVvp5lOQ3BGqIeW1kNv2N?=
 =?us-ascii?Q?snPBiOxRH6sRhAJnsNR4YXv4y+NcCiNaPfrNzTkW81HUGx0lfQj1RPlM+amj?=
 =?us-ascii?Q?81pLOCr7ZBDBefDdjd8TCwBWZYo6zmiUvpIXDXRUcUId6KtJ0TtkemN4wUJ2?=
 =?us-ascii?Q?b/ZiNWZIjVz1om11z8vndzvKlfMwm2alTyLGoDOlU3PZ84GbC3/+8Q0a8EqY?=
 =?us-ascii?Q?lsuRXB5j1unDhWSTdXBS+KxBqkryTR7nifKRqGnE8n60a4JUBx7xgOmMzC/y?=
 =?us-ascii?Q?lVlu8+h7YUKd66NVhNc84U7MKvZ8Mnb1a/qtq/OiIuymNYwz4oE67eaBaBmG?=
 =?us-ascii?Q?TRyflkqmKpsV3CVlu9iVKGQ4pWl4FUOBGBtWM7IO3ELxw8j77AJL3CfQ0p9y?=
 =?us-ascii?Q?Fkrf4ewxGYFZGZJEf78Z0b522Fln05rsoUaOrL9lpnHJ14hAQPbddNWNBSis?=
 =?us-ascii?Q?30SZhiyeLqTX+ffZtRexG5znDh2b9jqavxAfAvg6oL5lfBr2jYX7vJjxL145?=
 =?us-ascii?Q?t8wwxYV1on01BXCojXQGPw1JhO9HEjrRSMqKUaj1CCGV5Ml8O5ZpeSoWhMZ3?=
 =?us-ascii?Q?71R0oChUfaZRur8dgwCaREFHwbBAGvdyFHwKF+yrAZqsXGbDnoicLwO/gXsO?=
 =?us-ascii?Q?pwCUWbADrbCDF86AuMkSQ5K8J68tfW7Xp1UKyeCtUFuTO7RN5gzhyrtU7lhn?=
 =?us-ascii?Q?o6vuD3A0PvvDEN/nxdeQ5pG8xC48o8vBfCc350jnJU1whUGsu7ixH/IkkEqW?=
 =?us-ascii?Q?XkX4Ms2M7035d6+M37w+hr0aJijmfMRAJTrkniVskusT+rKi3M9VN/W7ENWF?=
 =?us-ascii?Q?v8PVd/9fMY5n33GPjtQKwaBvv0TCUFpNYCBHz8+aVgLGswL73xNQ6mvJakgn?=
 =?us-ascii?Q?aUwniRRh0y+WUxGDbhvwmTlhTAYcJMIY7HkN1wriFg1zlSZoOraA98lP14ms?=
 =?us-ascii?Q?2WPpDOiErR1DHuSw6Ew0mtdMy71lTA6wp3ko3mnuJracPYY8jWIzJEX4poTD?=
 =?us-ascii?Q?l6OnRCWDz/TY64bEiztTa5Db3k2k+kDWUm34hNqZqF12gUDNTbSQCKqjz7/8?=
 =?us-ascii?Q?gZaK4Cd37vMEwQ7xyTVe63TDqXgxSqBy1JLvQLedfPbyvA9lZMG5wkog0ybC?=
 =?us-ascii?Q?jq15hvc2dn44O8UBfNK+bQTZyV+4IrV+XslcbUvQDCAfw29CnRTXp4HXdpx6?=
 =?us-ascii?Q?qmlNW4BmV0qiD6Vd0CQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS0PR10MB7341.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?LnBkLqQPDQpCYPivzOS5j2C7YlbgtEL73W9lTf6xh8dsGFiNFBUVK2beubr7?=
 =?us-ascii?Q?dD+nFBi+C0q/TpodimOLCVfa2Tl+yh9cJp5i2v15yLLy2I9URduJVjkHbzzQ?=
 =?us-ascii?Q?s7LJcc6NX8rwskUHso40s+FAkmYDBsMSng+udH0RaDSXxQId0GeunDhQHW0u?=
 =?us-ascii?Q?aKw079pqJvia6GaQ5Z5TWPGOFfkPplmwCAoHFBB2gulLxkiF7x41UNTFaNR9?=
 =?us-ascii?Q?eun8gfzVUyi7LK2ZuQomnUmwEmKoXc4mQxeC1KJnvJpW+8n17kMjJREpfxTu?=
 =?us-ascii?Q?NsDl7k4IqamyXlPOJ9kFqpi7Cv0kOVWTVUJ9mJFLwbPf0S3deTD9QuQv0WWS?=
 =?us-ascii?Q?zDDJ1dzZwXhiRAhS9L575COiUIy2eD6prfN+1I/iCJJs5614RBuuyxdaECsv?=
 =?us-ascii?Q?tA3N51jjWp9uUP4OiZ5Im7iyZbUu6E4nlh0oi4+VkZCjpGENnRiuKJH38nFR?=
 =?us-ascii?Q?ZvBunPAqC5LqoXRt8HnKPniti8Gx56EM8Sg2h2M4gxU39oRsXb0SdUdCmtsu?=
 =?us-ascii?Q?7ztIUwhYcy0Y0iOWN4kwk2XM9SHixec6k5Hr1Q9YXTTtU5kN/QRIVz5B55Tx?=
 =?us-ascii?Q?qukts86x4atJG/IELrqU1USstzO8HbxE45IZwCbJFHjgn40AkbrkXoeVKIp/?=
 =?us-ascii?Q?9VqkXITpCISLNycbquXpB+YTIuyL3XUE2YceT15wDGb2Dob4T5peJv32kDp0?=
 =?us-ascii?Q?at3ZvmwjE2VnEXdy9Z5G3iK0FRVwvEf5YVjvq8sArc1UF7DQ+f+SCIgoiOJw?=
 =?us-ascii?Q?tD3sa6nZGrDAQECorSK4siC9JgY9Aztd9RO4iVgPP9wk+DQEhnOiepPc619s?=
 =?us-ascii?Q?HEykc3TeT7Ykj/9gOS9SSPF9bvF723VH4I3dhj5e/Ct3RiRqPlsmRfLtKdyM?=
 =?us-ascii?Q?el4nP0dQ8/YXjAz3zJteeH5IT6W1mNZkB5gOGLUm0eeUNwGKJaxwZgjLuX7r?=
 =?us-ascii?Q?n89rDt/xxIYX62+ougi9QW0+KvT2vhagj0mD5kmdz6O80Dk3pc9YXOpPAbiy?=
 =?us-ascii?Q?ghTqQaH6IybrZZmw1Vmx1u9NP4FxoAOoMhFCfkqnNwd9T/+dUxLmP1gjnSAj?=
 =?us-ascii?Q?ARbqD3Gxh5D4GPGvfR3jTdvwstL+50AeM2HhOYatSj8tg7CMMg4YJFosM4Z4?=
 =?us-ascii?Q?3HpI5BJX+TTjVMJxblHFh2CPOQgXr/pmsSIfV1aDimg4XUjv/k1V+JWLC1au?=
 =?us-ascii?Q?0g7yIgmHr0PxXpCHb7NlGCnbj8JjHPOwIprcP6AMfB1Q3Mw57FRFlNsIm753?=
 =?us-ascii?Q?//r5aAH/0QubIF6PXp4RI8fC50g+3QAEnNvPVEsGBNrlS0brdRxqwByDDpco?=
 =?us-ascii?Q?6tyIzVSuNKHysSR9NhHk/erJsorT96UZcJv17dAzy40f9rYMjaSHiYN7oXMp?=
 =?us-ascii?Q?A8ubXwpxQI+cRSuXNTSIflGclbs1w7wI19pvJiYtcn0tXt89rb/EnNYf4X6a?=
 =?us-ascii?Q?5ywyo9Co8iBxSP1rRpyYWkhSVqjBRaPU4IMwaCcck9CA/jz+I3RWT4asqT74?=
 =?us-ascii?Q?mLYCyvSIyWo5deBIYJnvglzV0POviHudx+yoD1UxbZBUq3Yv1lHWwBX05Dw8?=
 =?us-ascii?Q?r4VduJ/9AlqjGMnsLMb8tta+mARCfJC33jZ1pWMfFLQOxgX6x0BBNE+jo7W2?=
 =?us-ascii?Q?7mi3JjtqzdcLcZjbbYZxndGjilBIYaWrvMmFmpvCzaG7UNXL8E1kvcEPXNLy?=
 =?us-ascii?Q?eJwVtG8N2S/eM2ozw+/nJ2Tr9wwYBil3zXNPjv4c8BGd6/+zvEIgcmCL3L7/?=
 =?us-ascii?Q?j1N4Q11PRQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 4y4+Mj+UrAx+K5i8Ej4okXtpLTWGrAJUCRXOjLK3djZvY7wDeJ7D6Rkp8aqdP2CeeXbKFyZIADex41BKBxt1B60/wThRTxuszQ+JhpIIofpdtF/Z+DaAw2EjRC0ZhLAa2Y9byEUrnPqVHPcplNVMhxtRwOe0HZ3Zt/vtDyI6z6v9YxKLZRzb6jBfCVh2SU8JfZxvq2aIEL0ztDOn87rcwaSQq6kAHV4UMkHlcP7qyIVQrpWvHmUPwhmZXoao7N+hEigFjwkhxk50Hek0PcvrYviVFFcPbHF7n7EteWz6FJOMWriz/99Khh2QXEBSe1rLGVjmOdUFbpr9hZZK02KEOTb++LsAW6s0oMf6BXW0Xda7TsVdqD/fOjL1P/eTakZ9jf0iGay/hb1bIO9iS73EK3Y82AqXsvHwjAsVMbFn5YH7yk7aBgZE/ZWLj6FtTgqb97rovIx4noa2stOocrex3dnHTyWUZvX7mL4q6ROFWJBFonc3BlZUuhYxgPLdMUosf2EFHEWeVVWKT48J/f21d+wYbaOpaB9qSor7u28nu2R8vx2z+9+hVH06xXxBjfZZ5Go/fKf7MiXLni6vu0FlnlDq4infWMVF8zhUeN6W0x8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6c36bd4c-5142-4190-c7ad-08de59696f60
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 03:50:51.6773
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: WIIjnKJiPUB/lwTmzuIgN2PstgCg9LNKsO7cwAeKQfnSFR185sRrCOLSsdy3cihiYqoWD3S0CFfkCysCo8DWUw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB8153
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 phishscore=0
 malwarescore=0 adultscore=0 mlxlogscore=860 suspectscore=0 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220026
X-Authority-Analysis: v=2.4 cv=H4nWAuYi c=1 sm=1 tr=0 ts=69719ea0 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=jXcXkP6qC-kw7IvTVz0A:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: C3-h2FYP3YCHfZ7hnx1OZHVlinXFRkNE
X-Proofpoint-ORIG-GUID: C3-h2FYP3YCHfZ7hnx1OZHVlinXFRkNE
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDAyNiBTYWx0ZWRfX7er7nbKDzhPp
 YnlUG/JzNfDe8G+GHeaKGLe16F7q/lUmU8JXd+rMxFbZC1d3EnxQv2dv8PKtlN97uT4E3O/nt5J
 fQkac0octpADTsjW64fw21ljDNc0tEIoTnwueYaaSIhNNTpyi4O98LSmqStfO7Ks3knsMsH9PIj
 z3Xhpy3Ox84/MNIbZb2QKk8vLiCkba/qYLyOcmLKjQ8DzRPl1hSnjFl7blB4iis4BZ7MQF26raA
 mdwYmSR9IeQndnN8Ve9tEzIfP4AguVSK1PINCc4CAOjN32hCifv7iOKfm6duN+mLrUmc2Wahl+u
 n2OX3YKyRH6JkcFwDS/Sc7q7suMRAsBbEEGLBlr2pBFQmwOyy/aAULedsy9fOsNGMC7uI0/aEtU
 jQCxQeDOtKD2MaORqOVJEr3zrkuVK5Asffdw6jM3iv9pTfTQdZyxUqjIJKXWvWL0eOge1U+3zni
 ThAB6XcwXX/s1X9rH+g==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=YgqbA0JT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=VU7P8Bdb;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBJV5Y3FQMGQEGMB7EII];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: DFD1F617CC
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:36PM +0100, Vlastimil Babka wrote:
> The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
> them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
> being removed. The only remaining usage is in fact testing whether we
> can assert irqs disabled, because spin_lock_irqsave() only does that on
> !RT. Test for CONFIG_PREEMPT_RT instead.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXGejjS93L5fALig%40hyeyoo.
