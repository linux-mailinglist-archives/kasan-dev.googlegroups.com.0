Return-Path: <kasan-dev+bncBAABBHFH67AAMGQENNPFTWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 681ADAB0FD7
	for <lists+kasan-dev@lfdr.de>; Fri,  9 May 2025 12:06:22 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-22fba2426f5sf12388635ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 May 2025 03:06:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1746785180; cv=pass;
        d=google.com; s=arc-20240605;
        b=iMvDyxmBomEVZPk3PHW/vr4ZxJy8QJIf+Dakys8AuQTMnikb8twBpJy9rU8IxJVDdu
         Vwd3b38Km3HOmJ+EOt9cD2UmYfRhKYOnmttSWVkd7kDqq5LAjsnFUO14fQasPt15fFnL
         LCLsC9RxAhk6yKbN6vHuH+ZmEFmrSGdye2lacsUtuQeObVG66OY+mojBAGUhcI7qL5Kn
         SB+oPMTTbP6l72LIWdSXIcMpqMSTLmebh9pgiIp34nXjd3/Z5DscpVpYCuXX5WwjPUsG
         /9601emb5zWEei+YcYB71wW4J9ZbRsLff5ZqnauPk+iKpeqDN+VEvREwS7To8que3sVy
         Zr9Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KoVGNBvGa+RrvYucMXvqBZgRybuZ7qEl+F2dPykZLLI=;
        fh=kG9xwPlU/Du1NLeDd0Cy8QHpFAwi3s+LJX1Bxk7ULf8=;
        b=igxHZ9iaBBe5dqIRMKpzse5v+D0/ToRfhf/M1TRBxyMxqZCGAiaHbkq0HNdWt5S7M3
         jM/9duqLllF3NfPNllecsFrAf+cp03d/PfeC6ywMK6+cEC6dvOJF4nRzDNGMYDySJB0q
         e8Yzp07zfIlEW7YU9/KfjASYnvfwZyZ+v7AM5VoZrsoew0ecAvO0bx0bX85T/0rGbe6+
         MD4DN5Tc92W0k7bstrsJMnKCu9S0Vd0SY8h4+DTTn0nkXvR7V+yRrgWFkzVTaGyAikWf
         JQ9AZKNnVT6ZMz5ZMA6Nawv1q9DRoWKJhSIfQCBtFXnqMgB9enw8ugTKCmv7EluIsYqt
         fPGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=bDRMCrpP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TFYWyx8K;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746785180; x=1747389980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KoVGNBvGa+RrvYucMXvqBZgRybuZ7qEl+F2dPykZLLI=;
        b=LqLtWbpjwv/516kozblJwsEhGdx/R+O1hCc/ugW8NoXlihwiCRDEYvv16GbFgM2zwF
         0OlR7ZB3anH6O1W/KKJhodp6qEaIX+MvKighghl2owsWujXo3NCZBXGPBfwAsG0TarIy
         g82G8bdZhEtrv6sadPR1z00czDuQ/Z70UkHZl/W9UamVUuGWqrVSz/6/OMxqlc/yats2
         pAUidagBWQuP+3s8XtweMOFNxx68WV55kZLE4F99wH0MpRqhH+8PAqHmBe/XZvtXVGto
         R1iUVh4ShAFe7aPub+Jj8M6XVR2Q1drci/CLJ/05rTtLuGQXes2B0j2G+rKska1xkzYh
         eH7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746785180; x=1747389980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KoVGNBvGa+RrvYucMXvqBZgRybuZ7qEl+F2dPykZLLI=;
        b=eaABwUW4q7oUKCHAVI799HSUs4xw0Edhi1mOjb/pfF4wcbeampkFDnPmajVshiWllT
         8NIm91DfSsz5qR2Hzj+GshZNX91V2kwFNP43Yjbrck+nNLi+zlN8sRMBRpsImAWKL3+V
         rMxOIhNMFM9EkxSGgczcmVnjo7VGfyrM57Aw+69QWEqX2lDVyZrdRCeBl296Lwnv7bjR
         212jxX+nnqF6EW3L00uL/CJk+in9ttjBLN7wSSdrShumaSY340Ab4C1RJmI51xxaI1bD
         GiaLfMXMpKUPRtztE7Bxhh1UjTRlhaDIAWuOr6PNJ6FiqcrfIXw3yBVDcjuWKb8NhKUN
         WqQA==
X-Forwarded-Encrypted: i=3; AJvYcCUolQX7EU8cPUVZxzIVxoO0c/oYnb2VbBhRUYXSpA7bjqW4mj8QTKcgZJHPCyixRrdCDPYTWg==@lfdr.de
X-Gm-Message-State: AOJu0Ywtc3kC+HZUkeFQmQRXTU9GjxMjyo0ErukJTQrki9oP8Pb7VjLu
	MpMEQs7wwU3DzSxHmZiLT5ODlNfNE/woIaae47iJAWsU8oIT9N3m
X-Google-Smtp-Source: AGHT+IEgd/ZS1+Ik+w7fCtLMKXIEKQGGR302pOByvF/riGd19a4eG6FD7qNThNH1kwT5ZFEwXGcE9A==
X-Received: by 2002:a17:903:228f:b0:223:4d5e:789d with SMTP id d9443c01a7336-22fc8b415e8mr41314795ad.19.1746785180468;
        Fri, 09 May 2025 03:06:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFkipr449dzHRHX2Y2M2oTlm/dq9jd9Z2ldlSQS348oYA==
Received: by 2002:a17:903:210c:b0:22e:5a11:1967 with SMTP id
 d9443c01a7336-22e84644e9dls11305885ad.2.-pod-prod-05-us; Fri, 09 May 2025
 03:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXGlVVjEZpKcOnpYocPkcNIAnVLysjsc1CpbE2J5TlOhMmegq7NoiHIpJtlZNTPTEErvQkLTr3TEmk=@googlegroups.com
X-Received: by 2002:a17:902:d582:b0:22e:17b2:3d42 with SMTP id d9443c01a7336-22fc8b6c3f1mr39555095ad.27.1746785179247;
        Fri, 09 May 2025 03:06:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746785179; cv=pass;
        d=google.com; s=arc-20240605;
        b=gzje+9iN8MMEGekI4rOt/om1C39CTjAGGhjD5px/1yqWkH9EreXJGN1Fr/iFT7EV9j
         fn5Au70skxyzme1IjkLVIIEmzlRfL2BG9UyIFZke1tUV9cnVwl+0EiZGlalHCn0mnni/
         WbH9d0B5ncnXY/gYRNiCSggEVq7zabLn7sp1W6EvR2p5Hl0NHWLNl65ncvDY/qL//Bvf
         cPWI8yyJQ4G125dTJ82LAVsh1DbGoLciamMwzjklxW2x8ErNNL6ppsKsGBVq6RRVGZeg
         JDH/zCJTnUfB96BqZaUiE4WTZto2dnXDqDbr/xQwV65gxSBr0o3s7TAlV1w8K3bGi786
         Y75g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=lITgDRHWkbUg+6zewGu8AkpDkoqK/cVbcWmCi9YtZhQ=;
        fh=vZDVMGuAHVstcoxpR37bje4wUcDtpbOa5BfyS9r5Fok=;
        b=dMn2WcJKJD1vMjC0WV38nonZHLWfCw0BGoOa77B6x0aJTWjRvI7geavbjNRCTZIiw6
         nyzpX6H5NRArG4BDnp9LWjEJThj2mCmg3GDLkAelfHvgsUAC00cH6i2OyEpS9ggFaMmi
         e75xtyTJsRbniP757GnDBxOKMTmF9Xlmykd39MsSfIjD+DpyasUMi2SqOsYDctnhzMnp
         yYj3RAbPb4dRZLK2deqdM8XHdslBB6ghtghQh+XSQIhAVbtFlVQoCymRz3UXgka/5brH
         ca1WPbUglOOnCJ9lHS1/OWSCvh4n2O9aJJYVH3eaWGuxYzQaXVfq9SkGlIoU1d3m2vcx
         tMbw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=bDRMCrpP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=TFYWyx8K;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc8215378si742025ad.8.2025.05.09.03.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 May 2025 03:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5499qkiM015633;
	Fri, 9 May 2025 10:06:13 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 46hfeyg0ke-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 09 May 2025 10:06:12 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 54994LRw002667;
	Fri, 9 May 2025 10:06:11 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazlp17010000.outbound.protection.outlook.com [40.93.20.0])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 46gmccuvnd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 09 May 2025 10:06:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wnhj2HdC54mqcOSdl4TLeg3/XXlmekRjY45NBzCBG4Vb3bu6t+XwT5hToPXrNfjwfQjZWpeqUm8kid8Y8dZTOEwDRatm4bRDIG+jbn1vmd1hng5gqBhc6UZK73826uPrSnWtn7/x88swf528hgHJ+C309F2b4SWn1bB7/2lvjizt/Ny4SBDrScbeJWwj48lSXLrT8WnKQtJSC8TpNMzPDIiLwdTzd5LpFAtFxf5mb+nErO1ueXGV8u+cPg7gbsbp5PWSeaimSztdGn1h44A5uSfFZKh8GpjQyUIacExjm5JFo61bvmolgXEIfm2JVgBymvi6xtR/iLD4SlDW2BjH+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lITgDRHWkbUg+6zewGu8AkpDkoqK/cVbcWmCi9YtZhQ=;
 b=S84uG0eAt5/k/KIeghFzcCjl52Wc6TI6K1VvU7LQVbHqe8sjWuf8wzoa0CsLR2q/tRwMWlijiiLAUWo8vRp3lh7lx5uZGNojVn5l5dO5L9KwyngWP7jhGjZznodxIDCM+SV1B8IZOI3dc4ChAx5mnAGfo6Vi+LqjCckgqWI+rsuu14evgG7Tbdit8Di9DRO8VW0rYlabqlAOdHJSG0hA63KVq/04abkkJpGtyGaq7VzbywGgSsLtwIc7P/7hONUfev3WL/nlyK0vsALyUB2OhGxAXN7yPszr8Qm3LXXSxS2MR/SC6h5Kd8UKDrhP0ieMOiJ8xs4PuHz00fg+Nl8+lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CH3PR10MB6785.namprd10.prod.outlook.com (2603:10b6:610:141::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8699.35; Fri, 9 May
 2025 10:06:08 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%4]) with mapi id 15.20.8699.022; Fri, 9 May 2025
 10:06:08 +0000
Date: Fri, 9 May 2025 19:05:56 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v6 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aB3ThByuJtxMpAXi@harry>
References: <cover.1746713482.git.agordeev@linux.ibm.com>
 <aabaf2968c3ca442f9b696860e026da05081e0f6.1746713482.git.agordeev@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aabaf2968c3ca442f9b696860e026da05081e0f6.1746713482.git.agordeev@linux.ibm.com>
X-ClientProxiedBy: SEWP216CA0115.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b9::7) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CH3PR10MB6785:EE_
X-MS-Office365-Filtering-Correlation-Id: 12c02c59-2dcd-4453-3225-08dd8ee11ddf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?AMlJyjK70fgpWGIDM0U8dkTVAUUnC5vzCL0/xWM36TnsWA4npiUd12lG/WM1?=
 =?us-ascii?Q?cZC33qJZ77yS81zflqCpXtftM3CYMm/SudAHvwylJldg1g3kXCt/l8tofUlK?=
 =?us-ascii?Q?5EJ8k+MO0rolBzUuUJ0xDT9Baz+Ug9kpzvQaQoJx6VKJD44GhWlxuA1AeIBS?=
 =?us-ascii?Q?nY/35Bm0hWEhndaJ85h2O5bqdWVpvVB86iskKePRCeVDlq9/wZya5dbRwwXR?=
 =?us-ascii?Q?kacJ2BglG/T6M3e1ziP9tbe8QoJCrKn94g44E7GxyiJv9KyNoluwzsToV//C?=
 =?us-ascii?Q?xkWX1n8109jl8ZScAFQ0G+0/OUWQ0Wu5nreP8fnWDhxhYXeo98ERfPGbbqtq?=
 =?us-ascii?Q?/YBC24EAFpYMOSa14YHlMxjuV/N2lBDMhVOmxCyYhTBhz1JmJzxLF1WzP4XL?=
 =?us-ascii?Q?N4PntZmIgToaMnlVGLgcXo1jg03TEVLTlxAzv3fubm38YRV5itswyEZZwgjW?=
 =?us-ascii?Q?oofGZNFUfrODH4LYVVCWA+xowVgsQGeXQltMVx0wcC89UDk2s1542xGLy+m2?=
 =?us-ascii?Q?lZLqPLUJIuMlW4NribexDovGLNKrMMOAMJ5007sHUBFYCsA89KApFioftB/T?=
 =?us-ascii?Q?erm1CFY/+SDgzfGVb04frR0/a4GrL+rnizWKDbB4OOuZRAuahI5CQ04HtOzG?=
 =?us-ascii?Q?3cBk4g5j64ETUJB8ZNwM4UfF3n4z9VXW8B1t+NpnJkRH+s4bvCs4ARiZQNBv?=
 =?us-ascii?Q?UpjtUWNWTHOKbFL+DXdvL1ybAxaUpVGZym3k30vDN9BMmOaH6EmD4I6qPpeC?=
 =?us-ascii?Q?/vXar0E+u7hFZ9nZ8l+jxdbF+kWl+BZoEYGS0R6LubYOHiEsEiDzNCRUVbzp?=
 =?us-ascii?Q?f1X1gko4oWDbuBTKk4MMhXWgOVxcHmaVDR715vlc8RU0GzEYMq0gwamDddv6?=
 =?us-ascii?Q?iP57Qjwr8Ri55aSAnVwBTPYbpu8Cj5bWi/h1PEhCrSL+DlaQGeIk2veuKl73?=
 =?us-ascii?Q?L8cfuQ8y9nSsPrjmy+e45EmgDlKh4vnOQs0B1m8wi2pu2j5q82SsUt7wX8gV?=
 =?us-ascii?Q?4V2dWstzL9W9iJ39+1gID6Jo9L0VO7lZR7CEI9AxyO/LqigcwGg3NJztrZt8?=
 =?us-ascii?Q?dFatonNBCf1iFKOgbcoW1XRfyqHr9Fh8XSIEqFafcHYmo7yH+Z1IgAutQnFD?=
 =?us-ascii?Q?J0NGYaITOVrb8m39gvMKyP2J5iD+eKGsszWJIstZpMmBnTy/1CIt2xgou26N?=
 =?us-ascii?Q?Y9CGnTo4bNfyhDy+uc3aKp0O3i09PNiqiu6+sdIU7uumBZ3gZ9KN3Hxo4eFZ?=
 =?us-ascii?Q?SlNdFP4arkMLthNhlyuv1PZPidAH6zGuNH+5InQWOu66ggL7tEt3Z/ag4Ly6?=
 =?us-ascii?Q?bRKaUyOTpo6X0xezmn/PXBNwl1u+GPlc8fmXuRzRNCMHIed2G1A5mKYGTnpi?=
 =?us-ascii?Q?FKKh24p+zLpXIN+O5UaTQVhbbSowL5MNu/+XMaqW2EpCY1G2TQW8LWACPX3p?=
 =?us-ascii?Q?wicfArKnj6A=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?6BCSGDUiDtN1RvUvIfIJ4tkSWHYIfT4lwf9fBndmpw5dG/CYUoDfJYAbR2RZ?=
 =?us-ascii?Q?5yHSXDDIyzi+woHJKI4iDk87ONnj1OyhGStfZa0zAYkB4kr1yf11xBPNT3rR?=
 =?us-ascii?Q?W2+4e5zoTR0SG6sQwKNPsXLijT/ubFiul8/nuiR8/ovN1+8Mj8/g+iZF3y/0?=
 =?us-ascii?Q?NAJ/2n15Xbu4cIxXJ2et/krskY319xE1SQxauJov8XwHVj/3jZyxOX6ZB9F4?=
 =?us-ascii?Q?n+lBElPyODfpeR0zTS7IDchBiY061FYU9yioZllVykh1k6R3qgpbnIVbrAcF?=
 =?us-ascii?Q?l6lZR/0DsHKR8JwXDlwHbl8A0kVlxio+ujoTr/QyGpBZ/gAK8OBAD5w2H+pX?=
 =?us-ascii?Q?2ChUg5RDPJy/dgcmggSP/prQGkVw0XuVtDJzlsPWUC/o/pvxlA+H4qAEZy9U?=
 =?us-ascii?Q?ptApkvhgQAtXwPTeLflHVoTq+hsRdU43mj99rUc/DQZaPiaws3aTlYVg015e?=
 =?us-ascii?Q?i0yuUD4MtGrw07JgKQajJ5czPsRMA5HAMaUd1uoTQjJ68g9//X0AzdV5TjJz?=
 =?us-ascii?Q?Bk/edqO61WPBSkg+7Q3aRVqGn5KV/CzThqlLe0Z0IaKee2wcgpw0IykGNrbm?=
 =?us-ascii?Q?/qlUxxnW7RFrfIz9qPb6L9YqPW6ZEUOllhKWCyOpQ84yAIipdcTy8E1pA2f+?=
 =?us-ascii?Q?5ITshJKcpJHMyftFM3t4lDdxw/+BkF0u+DrQKMtNmnpL8PkogSq7IVsrOdG2?=
 =?us-ascii?Q?9denROVXB0MGApiNmeo6YS8fISkNnGetHk6HP9GYloeg3C+8qJxMrsTUpn50?=
 =?us-ascii?Q?Sex5tUCJvQ76PcM1q3b93qnHc/ZdW83xGmvEfcRqcdFHE0CLFX1nH4A/cGsJ?=
 =?us-ascii?Q?WsRLiiAU7Cp0Z+IfpHaBHCAsWATVB7N906kE5xNZBsT7JBiRHmGQgb5k3R8i?=
 =?us-ascii?Q?k7bpMbpGPXv2Xnm3MiUZIgMIviagdcbNoGXBFw2yR33TN/1F6pCEn4we81zd?=
 =?us-ascii?Q?xyw9BLSC08bjrjmvWgps41Lz4pROdlvo18kWZ4I11lyTv2Dq4BE7xTCRPtlC?=
 =?us-ascii?Q?mr/XD189kbv1Q7py2Oh/oAJWQALebMY+UUIM5LbuJJUzRczykSrtUuHBr9jc?=
 =?us-ascii?Q?UAm8un94Qo179oCQnofHva2GxCscDwBuikfW4OBa1F5Pvujl7cpEzIXruvKK?=
 =?us-ascii?Q?KU0MAFZb1DN//MMZLf73IGv6qZrunfAtRd3ZA7JPO6n1ox7G8xLcn8yH5Ev5?=
 =?us-ascii?Q?lfLEszYHTjvpuJ/+XXwkiU0YU9VyyqNvmhYMS7l2Y4h+eJ78FR7Y1OdGcIoO?=
 =?us-ascii?Q?LpGFop3WPeJ+r2EI5vXA9AeXGcirBXpTnyjamg35BLQs0PRduS+5/0vsxn1X?=
 =?us-ascii?Q?hUqOx0/BJWEHECTL27e4yMLaWpNIAXgHKrXFvNQoVK55iHInOSdhp/FLhdlk?=
 =?us-ascii?Q?YSHmfUL5ZZKmNYi3lLLVcg45DVYBzYwuGwGgDgwhaPrSPM+qcZRj5H651aES?=
 =?us-ascii?Q?hsMk9flpW51cx6UvTGWnq3Sbre0vnj2/jgfjKFt1s5dZFCJO1Vl7PBscBspu?=
 =?us-ascii?Q?50dw5S8lqzrcYi8nw2/P1biL2yR4hley1lw2XAbml0QUgQlWgPCLSn+86Dz/?=
 =?us-ascii?Q?sHVHNOWWlhwcrpKoi5IhcH8W9zQpNHlrdRG41PSQ?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: PewUX7UB488v0LLdylLj4ntWHD6DnwZDFRNl0YkrN3TZfU1a70CV+INQrKxoGDrO4j2aHtyWmqDtrdzQYUdLz1rB3/kMMItdtr1naJqOg1/8xDmD3v/t7Bhnmm8CgIP5frMMcyRWtqhzvG5wquti4n1WiQUzOY5Hk3ZqOGELPK5QUsbo8vTkzl7wEk/OP8Ri2+bCo745ENDhS3ZHPyhnpbVMgB2WH5aEw45JPvjT7PuMtZDS1oDCRQdJUdtncfOckyjOpgPy68/1gS0BL+gtQO9Lud2VUrnWOWp+JWcPNL9H2MhvgQ+nmhZLK6GacFWwgTP3yL/QEBAtstw6+AUELq7oowzjFWA3hcazDwaYexuv75ni7d0IiahaPj3/Z///EuSS5f5+bb12IiDYBdj36A9DMM8+H07PFNcewyWHp84PSM5sdBtSX2eazTCsyQuawQJ5rQDcm2yqAEsjkmhxbj4P33o6q74iB+A9WJP9Sz5BOo4gKdC4Zx1wr9bVDemeHLExNezrHm6onw8seKQnWeiMxZVp0oSPpxFgKstJh9e2M+JjcjSOpPjTyIekDBcKTMs413248Sm615w9gQsDdO9QKzYm+eAycYUCemGKBXk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 12c02c59-2dcd-4453-3225-08dd8ee11ddf
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 May 2025 10:06:08.0668
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: p2cgSbJ2xUv56sGTpTGAd5jTXzXOENpyjUMoGuvRxZusHrq9VELid8QKqUX4Dk8FM+PPtOMTPITh6mstxb4r8A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB6785
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-09_04,2025-05-08_04,2025-02-21_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxlogscore=999
 malwarescore=0 bulkscore=0 suspectscore=0 adultscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2504070000 definitions=main-2505090097
X-Proofpoint-ORIG-GUID: lSN4NJWDp1pHMllRNHZV2eXTX7Lj3VN2
X-Proofpoint-GUID: lSN4NJWDp1pHMllRNHZV2eXTX7Lj3VN2
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA5MDA5NiBTYWx0ZWRfX250IRak8ei/R F8+7TWjPQFlLYL66X6UFe1jZcMZMdjohYxUFRsMHyD5ScxBLNgsOQa4wFuch2LcG+6crdS2kXkw fsVlgrNkGvVL2gf1LAzl8gfhmfQ/T8KDMs0Or6DWfYmC/t4h0hAvOaS/+L7U6b2l+KmuRyZWndG
 d/3czbqQtBnUKBD+QQn8+EiSecRwFxQTIrvCXQbg/q6V10s/PnJIOiPQToFD7SDsjWVZtaTTObM cK5wswJMBCppIlBHndzpSLSDeu7hDiEWmWxTHSDbh8Ds6E6BbWp6xNxvdBIsmCA6SGttTlmEaf1 HvCtLEJsfpK0Lv/imBerVpqZiPdbwJy7W1ljetlbSVsuQDkSjltrUFS09ZI/2yOpIEg9gPO1jmT
 uW2M17SJ64yIc/mPBWFLbm3wpsNzuTwZveB/fAgiND94wPEiivIpzCdL5WrqbWnmYOWGxdZW
X-Authority-Analysis: v=2.4 cv=ROWzH5i+ c=1 sm=1 tr=0 ts=681dd394 b=1 cx=c_pps a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19
 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=GoEa3M9JfhUA:10 a=pGLkceISAAAA:8 a=VwQbUJbxAAAA:8 a=VnNF1IyMAAAA:8 a=yPCof4ZbAAAA:8 a=p0nnNw9Qi5FJ1uIT6eAA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13186
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=bDRMCrpP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=TFYWyx8K;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, May 08, 2025 at 04:15:46PM +0200, Alexander Gordeev wrote:
> apply_to_pte_range() enters the lazy MMU mode and then invokes
> kasan_populate_vmalloc_pte() callback on each page table walk
> iteration. However, the callback can go into sleep when trying
> to allocate a single page, e.g. if an architecutre disables
> preemption on lazy MMU mode enter.
> 
> On s390 if make arch_enter_lazy_mmu_mode() -> preempt_enable()
> and arch_leave_lazy_mmu_mode() -> preempt_disable(), such crash
> occurs:
> 
> [    0.663336] BUG: sleeping function called from invalid context at ./include/linux/sched/mm.h:321
> [    0.663348] in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2, name: kthreadd
> [    0.663358] preempt_count: 1, expected: 0
> [    0.663366] RCU nest depth: 0, expected: 0
> [    0.663375] no locks held by kthreadd/2.
> [    0.663383] Preemption disabled at:
> [    0.663386] [<0002f3284cbb4eda>] apply_to_pte_range+0xfa/0x4a0
> [    0.663405] CPU: 0 UID: 0 PID: 2 Comm: kthreadd Not tainted 6.15.0-rc5-gcc-kasan-00043-gd76bb1ebb558-dirty #162 PREEMPT
> [    0.663408] Hardware name: IBM 3931 A01 701 (KVM/Linux)
> [    0.663409] Call Trace:
> [    0.663410]  [<0002f3284c385f58>] dump_stack_lvl+0xe8/0x140
> [    0.663413]  [<0002f3284c507b9e>] __might_resched+0x66e/0x700
> [    0.663415]  [<0002f3284cc4f6c0>] __alloc_frozen_pages_noprof+0x370/0x4b0
> [    0.663419]  [<0002f3284ccc73c0>] alloc_pages_mpol+0x1a0/0x4a0
> [    0.663421]  [<0002f3284ccc8518>] alloc_frozen_pages_noprof+0x88/0xc0
> [    0.663424]  [<0002f3284ccc8572>] alloc_pages_noprof+0x22/0x120
> [    0.663427]  [<0002f3284cc341ac>] get_free_pages_noprof+0x2c/0xc0
> [    0.663429]  [<0002f3284cceba70>] kasan_populate_vmalloc_pte+0x50/0x120
> [    0.663433]  [<0002f3284cbb4ef8>] apply_to_pte_range+0x118/0x4a0
> [    0.663435]  [<0002f3284cbc7c14>] apply_to_pmd_range+0x194/0x3e0
> [    0.663437]  [<0002f3284cbc99be>] __apply_to_page_range+0x2fe/0x7a0
> [    0.663440]  [<0002f3284cbc9e88>] apply_to_page_range+0x28/0x40
> [    0.663442]  [<0002f3284ccebf12>] kasan_populate_vmalloc+0x82/0xa0
> [    0.663445]  [<0002f3284cc1578c>] alloc_vmap_area+0x34c/0xc10
> [    0.663448]  [<0002f3284cc1c2a6>] __get_vm_area_node+0x186/0x2a0
> [    0.663451]  [<0002f3284cc1e696>] __vmalloc_node_range_noprof+0x116/0x310
> [    0.663454]  [<0002f3284cc1d950>] __vmalloc_node_noprof+0xd0/0x110
> [    0.663457]  [<0002f3284c454b88>] alloc_thread_stack_node+0xf8/0x330
> [    0.663460]  [<0002f3284c458d56>] dup_task_struct+0x66/0x4d0
> [    0.663463]  [<0002f3284c45be90>] copy_process+0x280/0x4b90
> [    0.663465]  [<0002f3284c460940>] kernel_clone+0xd0/0x4b0
> [    0.663467]  [<0002f3284c46115e>] kernel_thread+0xbe/0xe0
> [    0.663469]  [<0002f3284c4e440e>] kthreadd+0x50e/0x7f0
> [    0.663472]  [<0002f3284c38c04a>] __ret_from_fork+0x8a/0xf0
> [    0.663475]  [<0002f3284ed57ff2>] ret_from_fork+0xa/0x38
> 
> Instead of allocating single pages per-PTE, bulk-allocate the
> shadow memory prior to applying kasan_populate_vmalloc_pte()
> callback on a page range.
> 
> Suggested-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: stable@vger.kernel.org
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> 
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---

FWIW, this patch looks good to me.
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

With a minor suggestion below.

>  mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 63 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 88d1c9dcb507..660cc2148575 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -292,30 +292,81 @@ void __init __weak kasan_populate_early_vm_area_shadow(void *start,

... snip ...

> +static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
> +{
> +	unsigned long nr_populated, nr_pages, nr_total = PFN_UP(end - start);
> +	struct vmalloc_populate_data data;
> +	int ret;
> +
> +	data.pages = (struct page **)__get_free_page(GFP_KERNEL | __GFP_ZERO);
> +	if (!data.pages)
> +		return -ENOMEM;
> +
> +	while (nr_total) {
> +		nr_pages = min(nr_total, PAGE_SIZE / sizeof(data.pages[0]));
> +		nr_populated = alloc_pages_bulk(GFP_KERNEL, nr_pages, data.pages);
> +		if (nr_populated != nr_pages) {
> +			free_pages_bulk(data.pages, nr_populated);
> +			free_page((unsigned long)data.pages);
> +			return -ENOMEM;
> +		}
> +
> +		data.start = start;
> +		ret = apply_to_page_range(&init_mm, start, nr_pages * PAGE_SIZE,
> +					  kasan_populate_vmalloc_pte, &data);
> +		free_pages_bulk(data.pages, nr_pages);

A minor suggestion:

I think this free_pages_bulk() can be moved outside the loop
(but with PAGE_SIZE / sizeof(data.pages[0]) instead of nr_pages),
because alloc_pages_bulk() simply skips allocating pages for any
non-NULL entries.

If some pages in the array were not used, it doesn't have to be freed;
on the next iteration of the loop alloc_pages_bulk() can skip
allocating pages for the non-NULL entries.

> +		if (ret)
> +			return ret;
> +
> +		start += nr_pages * PAGE_SIZE;
> +		nr_total -= nr_pages;
> +	}
> +
> +	free_page((unsigned long)data.pages);
> +
>  	return 0;
>  }

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aB3ThByuJtxMpAXi%40harry.
