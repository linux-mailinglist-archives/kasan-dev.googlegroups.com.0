Return-Path: <kasan-dev+bncBD6LBUWO5UMBBF7V27CAMGQEUKT3VGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DFF0B1E916
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 15:24:40 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-741a54ec563sf696363a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 06:24:40 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754659479; cv=pass;
        d=google.com; s=arc-20240605;
        b=DnxgN4ZP6f5JMbekLP7GFRmXoKcp+H9AnlXAzm/2LLYoscYdnSsccxwRmbTktkfliB
         ZQWWy5O+iv1GeFa9hjL8F1tCT/Qtnq10JpI2wBbVq/f5ccJ9qBjVPli7L/4ucgEF0v8d
         S+dcZwXPunMIr+NJMv0ShWAm2srCNWfbkit50CM2nJIkA72u/9dqDFmnNy47Ro6CNHDp
         hLISRMrI3/KBAE24oAtjprBrg/rlbqFzAdep3Wyd4orO1g0qP07J9HrDNAmHfX1F7OOy
         t96zU4u42/xvjAoVjIO4y3KYsFCq4rHkHkAM8i94wjLneqFvp458rVv0tGRokEBWRNZz
         sppQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=1zXYbF8hBhZc64eBKEhMCOlKxMm4KhFD5Ikrqh1uO9o=;
        fh=bZUzDjPGUqx173taT588ygmFieewaRgeAEYzL1CJ5LI=;
        b=YkQZ9nzinv5+kc+wLmT5EKwH9aLPZfg9EJLSFU8ZcZhqYiTYzV8NYszpXwZbEzj3QS
         SUDz4bUDNY83Gl5afFJURuNElfm1d4IKjfHW2jppsWnrHsvkB0a1EzpxOfycfd0ymZNa
         P27bZ8Pk8kzUYVVf5l6x0oAi67gJNHbAfS+6ysaB+2SKu4JHXWGEGrI7v0XQoujVT38K
         26zk7JkXzxCdoLYEQlJxFFOD1EVLZbXkqnUkK0M8YbelulTsTecqSxzDUkEf8XpFUwDf
         ILGFJ46hW1ltKxKaIDmzj7M3N9JmM6d6M42yQPmbf825AgA8FCrvpmrLuxoo+5m1/5eM
         UkZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=LxvH2wCD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dJgB60Y7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754659479; x=1755264279; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1zXYbF8hBhZc64eBKEhMCOlKxMm4KhFD5Ikrqh1uO9o=;
        b=GBDZfuNIzh7S6nkbqYC8kaBLVhPmkFqHShbrrGUeq2pgCZMXfSXIOL7cAxTwBF8/Bo
         vEoyvkJavQaXRWUGR5942NhsDnRj0JBLHS8UB03G4cFE9DqTM7WDlPzDs7hOrEOIaTUR
         RoyfBijPF5RG0EtaC2o5Uglk9M6gm1Sn88PvCk11di33BMcWoBNYJau7lrx8NzV34NqB
         zXid/vBIIpDLeJieTteSDujhdf3izPtZZlHQHmlsHvsKwA06cOCMKhIm6Rg1NbgNdZDh
         Vbo/8pWtnVCRmbMV5c41/0yWguuKRvHjyXc7PNygk4YMnANbLWmhbt9m7RHhpcvGMiXV
         fDNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754659479; x=1755264279;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1zXYbF8hBhZc64eBKEhMCOlKxMm4KhFD5Ikrqh1uO9o=;
        b=UamlhQXMpy5xRQYuyuWZPA184Qz1NdH6Y0gNGlqlq3ETIVyoEQMJnLaQ5/UjqhnXSg
         XAjeXUgTgUT13ncpdHcGJZxGwNNEGROHGIcWPPm8qx4XUoVn28Ib2Utfk4JkR6a08BJA
         ALcSc/1by71/Vr2htg0R3NPwKTFO1GAj8SXJuXzrqD0rCmZLrRUyJQy03YmZ8tkKr5Mm
         A+0/ebBPYY8eyxS/UdmWlO4Y8XwpkPmucfNLKEfD9LsC/edU3NIeEx/Gk/dwrcZcH7Hb
         4AjHRk4wL8BnnBFcpg5lHH9pInCLkDVZF4GgkuLptC9tgIVgHJEuuefBPron/PpWs8fw
         02gg==
X-Forwarded-Encrypted: i=3; AJvYcCVrrC0SEK5Gpt8pjC4YePIArHYNxLn2nvf5vJmnfZ9A9mCSPk8ZRuc6e6nbTGDurm0oZRAt5Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy+SZ+05439p0gnI+5fGNg20J/k33q08n+d8tFej/U4DfNosH0x
	6z+W4V5FVRiduOItspvL97VDmM/u9gC5knHGN+jM2gaVbuZDKqa5Pufu
X-Google-Smtp-Source: AGHT+IGecOAPiGRsjfdhOHMRHCymy5LdLUnl/KFxabOBxQm4F46yrbTVclKqlVajCh6swRJgGarUvw==
X-Received: by 2002:a05:6830:90a:b0:73e:93dd:1f56 with SMTP id 46e09a7af769-7432c822de3mr1971226a34.13.1754659479172;
        Fri, 08 Aug 2025 06:24:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvhHjHRl1k3eIgJ2fnrv1MOi1rWP4U8ytzz6R1JoETTw==
Received: by 2002:a05:6820:4782:b0:611:ca38:7732 with SMTP id
 006d021491bc7-61b6e75960els330498eaf.1.-pod-prod-02-us; Fri, 08 Aug 2025
 06:24:38 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXSXzlPdFutzy+8XD3KZYZ7Uiert6VfCJJSPb8zLjl4QxYk5Zclmi0mSjuQVbZMiLzEM7Gt0SNHLDQ=@googlegroups.com
X-Received: by 2002:a05:6808:1454:b0:41e:11e1:a855 with SMTP id 5614622812f47-43597f8176fmr1884622b6e.19.1754659478177;
        Fri, 08 Aug 2025 06:24:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754659478; cv=pass;
        d=google.com; s=arc-20240605;
        b=hGda9NUUUZdHavl4W4KnA0hOpNaZjFFWaRMpCOCyu2z0BOCTTTrfw2uHCxEV49a9O+
         SGt1WzvuJZemVCYQku8doZD1s8rFl8JhR1Y/tELy3gYMyB/HFJUQa+Naki8fct0dCaK2
         n94LrsvmS0XaYTo3OE9A8vG+iSdOySCDKOcF8dp4NOJPkVRxjRDMeH24YL11KQBkkb6L
         GUBuOctRHSWyBexXwCXhSw7eD1eZtp04wuXtWcSy8U8JYxBR/eR6qBvgs0IjSKnV1Eja
         pqHGMxBjz1sRBdv4j2dyCHMojRmLiMbj9Vnat8z89yAr7OHTvNScul/6uCx4n9a+bJUR
         xcWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=hKFj4d9qNF9HKwdQdtFw5LmUx9zXT5iDHN6/7ATYRqw=;
        fh=4Ecr1l/hmhigpMtapn23TN0EzSydaoz0q4WGwZaekvU=;
        b=TJIKF08clesap50pDNjShClZEu4fgqvbNME0AIr0NHY0Z3t6CstcAwXiMXhCS9VPZG
         zDRjvB5WZkFn1yeFSd8U05FODO9UxIh/ETphwkqt+EIDluYu6xHEMd/u9xX+LL5VX35z
         IBKb3xMySgqEqEZ5VhKsCQZLMnbLTXny3tqpDkJ9vmDQm7suD7JBmXRqtZrmDLWQeK2L
         7ibLoto5W+yjhw0yQq9j1nSayEBUJsvpB3RNLAz6bg9ABm0SbjkgFDmK95T2pNJOl4ZL
         NOuFZVZeTQ3UAYBDs6KenSeN37YfeOpkr2J0pLuptXu6N/4AN//uaGER8bMVfmfpW0kW
         gZXQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=LxvH2wCD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dJgB60Y7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9c18881si70525173.6.2025.08.08.06.24.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Aug 2025 06:24:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 578DNUOw000780;
	Fri, 8 Aug 2025 13:24:33 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48bpxy6e0n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 08 Aug 2025 13:24:33 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 578D8ovB027150;
	Fri, 8 Aug 2025 13:24:32 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2041.outbound.protection.outlook.com [40.107.223.41])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48bpwqr1wu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 08 Aug 2025 13:24:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HvIyhy5WrcVxG3bX4KcUUqcs5lINzYf0nilWvi6KxL/4d2pnRcZfKTmdmrqKqBmRtv6lVawvYCRSMwMoGMqquz+js0u5SX2Z9Dze9g8DPQxdiZnH1eKKmvTjrhVn1HS6FjRsaSUrtZ0cc+as9K6aZWmC9QWUXa7hphavQ6K3kM9FjPxeBY2wFybtek9lhsvwINSpVTPqB9iNn9UW5+fnqUlbwYHKlQxcxFQT4WF4X8W36q33B9QTnioU3dUVfskptvvKObE+tiippaf9ThCcDKyrXS8sFwp/tVdiwbR9+fojP4UHzC47vV9OA/3S5/JkSxdY/YPx7FVDvHzCxG8G9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hKFj4d9qNF9HKwdQdtFw5LmUx9zXT5iDHN6/7ATYRqw=;
 b=IR9AU9ncJggjX/jiJjdwYG9jToyvdc4ju3KRKSua7OPXbEMFh8PZdev0bI7qWyOSwaBXFTrRtyzEwcxg8FiETd78D+6Vb4N1FeoD7VeXl526GqVNs2dartTC+OWwlxQ3I/emUfIP18RRcuFLXZC7iKREfN/1mvRQFskoHv5Aqdtwf23nnCGbJt+vbTSGVMh93YXEJiiO/s5Yhmgdbh0bT1A9YfClRXthcSfI3ru/YVKDVQNGHnzlabT9QSkFI4pvJk/xn0oCHOwiNI9B5p0M8U4U2/GJpaXv5sPAKB5vAAQhcUYW6ogpj+oH36WdHg5Y4ScJ3H/fiRA6uoas+DdgsA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA1PR10MB5993.namprd10.prod.outlook.com (2603:10b6:208:3ef::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.16; Fri, 8 Aug
 2025 13:24:23 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9009.013; Fri, 8 Aug 2025
 13:24:23 +0000
Date: Fri, 8 Aug 2025 14:24:19 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Baoquan He <bhe@redhat.com>
Cc: SeongJae Park <sj@kernel.org>, linux-mm@kvack.org, ryabinin.a.a@gmail.com,
        glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, akpm@linux-foundation.org,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <b5d313ef-de35-44d3-bcbc-853d94368c87@lucifer.local>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
 <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
 <aJX20/iccc/LL42B@MiWiFi-R3L-srv>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJX20/iccc/LL42B@MiWiFi-R3L-srv>
X-ClientProxiedBy: MM0P280CA0014.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:190:a::23) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA1PR10MB5993:EE_
X-MS-Office365-Filtering-Correlation-Id: 9145364d-52d1-4b17-e933-08ddd67ee414
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?W3gsCjInfKhLfQ4sMQqe2bbpFSL674L3JOH+qDfUz/iUu0cP9DjxOce79jLE?=
 =?us-ascii?Q?y4ifbwYaERlMgvn++wo3EhfxaMsKtMuRD+El+A1ooD+NhivpD/y5KuJnKkTI?=
 =?us-ascii?Q?bfK9M2ozVKj4y4h2dLfzHIC8lOYmYiQa2/FSDSx4UZuTr7M5RtGgRSWjO1VY?=
 =?us-ascii?Q?v9kkHcK3juNnXRlFBizTHSnzgVhil2GX+T+1EkIPu48H5yX5XwB1c9r9uVom?=
 =?us-ascii?Q?JvTfpwMHCJfkIvOFLHWtQa5aOL512TyhO5bnhMrFNXl/hVgbSeeaUU8KisTn?=
 =?us-ascii?Q?cNmYgpe0D9sKj6GfBMtyMTRQLJllhhvAa6iwxF1zgISgYljjupilj7B4hfG+?=
 =?us-ascii?Q?hLVEaACWVCn/m9b7pGNSyjr1G3RoFCwj5uWU2uv9FxAsnmFk4rQyRvWgwFcv?=
 =?us-ascii?Q?MTFBNrGuD8ytg3KSMrX3csNTqQVn1HZuCaEr8Uwl+/FSFrU17Z5gUpKi0V5L?=
 =?us-ascii?Q?DmmO6bAd8DGmjxE8spt5mU9S4o0h+FZq51HQVfT4Pu4Q7tJ1nC8hWhHbzW2y?=
 =?us-ascii?Q?jjuBoD+agEiy3OyvZRDQfsg/K0WJx6qvvFxxAYoVPqeyTO1Iz6qksnCkHRrW?=
 =?us-ascii?Q?Nd10zXth+rVoGc3oWXb/l15k5zZA0t8TPnTc/+UAOK8LdrfvRFSFrs9mq4hZ?=
 =?us-ascii?Q?LN75GsbIvB9KIfPQPoekmV3SKzYfA6GHGaPDu1MimsY37+kwU8P0Xo/JywjV?=
 =?us-ascii?Q?aOO1ZvSxtBXVyHUDHhr5bgC9ka41d7w/GEIH4T0UAvnnxHqXvMuKd8Jm213W?=
 =?us-ascii?Q?RYJUCusi/qe+j321rWpl4AqI+oa9MhLv1rnFIOsAKMDf/7+IoiWPaSnBTeG+?=
 =?us-ascii?Q?pvsXiX77XweaqrefFkVaHkP20ai/aImlQnpb2PKT3bCezkrrfkLESjN1JypJ?=
 =?us-ascii?Q?CyMAn38/uIcmvasoKf/8/gs1cXyqDl1rC3I/9IPaV8eLoBB/3vOdamC2wrLd?=
 =?us-ascii?Q?CCsgtW69GrjK64nZWZnrVtO5VT11BUsPN32eR8nR2CN/mcRSRRRFaV1DlstA?=
 =?us-ascii?Q?zRnC2p0MTVTSzsEo7C62lHshSlSdA959nDAdAI4Se8N3E7s9d38PYMXjIaLl?=
 =?us-ascii?Q?5Uhce2FY3JJ4aISXvXllVqE+WQVyGBKP4aE0Tb/2kBbDXR/3eO5EV+l0Gttz?=
 =?us-ascii?Q?XyOcDtl9gZEqieeuIlA33qTKmVG1QnYSuPde+o3aP03rVUwNPelSEKu3R5iT?=
 =?us-ascii?Q?x7d/5ZNY355wWhGZOVr1dz6PqNCzEJr0tiJX9FIWzk2k5z9YAxp0DxS6xAFZ?=
 =?us-ascii?Q?bATEavw/caJmtSlneejaIUVzGYDS2TDqrzHIN6nVTKDE9WBVhUWb6vJ+1C70?=
 =?us-ascii?Q?KBUGLhkbD1JlmxZbkMtPIIrRGMCz/SkW+CCp+t1u9jVGQIPUFclMe+UjErYn?=
 =?us-ascii?Q?6TLOlDC/y8XqSq6eHP4DFf9COUgWaMhiJPi15hDnCdYcuVOacR8kBDwHDKq+?=
 =?us-ascii?Q?BLGjZLzzNsk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?2H/jcLEayW3zNyGgSchTU4gXPLb178ieJMejTSNpuo/MNN014GEV3c5oxgeU?=
 =?us-ascii?Q?YlUxsrWgsq0jg721yTNSEM9VCEleDVR2gkhnyrUu5ULtzDjmrCGapi14A9fy?=
 =?us-ascii?Q?8dSpEUVp/qCLtL9MGGfZrw9E31OMLeHO20pT31NK2XtuTV6uqCYLPxTCowgq?=
 =?us-ascii?Q?OxuEXOqRtC7EQzVHyxL5A+rJUIzvKoz+XxnumUMO5pjFjwcpvehuRBkZSXSm?=
 =?us-ascii?Q?Wf4cgiw+/hgME9LznbiQWKqMPIXbLv3RYGt9QonA+5df4oJIBgmIgFk6a8dI?=
 =?us-ascii?Q?W/w782zInGskm7EC2tCX3opA+e5SiowxViplenXqT6r03WrJ8EIpwoqwa0N+?=
 =?us-ascii?Q?n/qzaWmaDOGdJU0bNYdCPmF78VgE2qwMd6deYry8LfokShC6EyeVuE95qwSO?=
 =?us-ascii?Q?6wUlNrEjm8YajYXAD4QRP5yPZwep8oWLBbyxtm8Yij0NIn6V1/v8/A2APFLy?=
 =?us-ascii?Q?dwlKvY7iu891PladEH7ghp8x8lD567BFQquHdyVz6m27RIqR80P7k1J4Vy5D?=
 =?us-ascii?Q?paOU0V8O7usL4MvbWFAyOG3QTQZ6htApgLM77Ik2qIFNuZCTRQ9EqooNuBp3?=
 =?us-ascii?Q?IHmZmSi1EH5RLYzLy+qcVsUP/Fh8lhhDoj3RfZXgHzxeqw8VJyEe6rW++vNC?=
 =?us-ascii?Q?DUl1JXJgcebHU32Id7TxKLSNY2HScMUFPH5b1eloR4Eh97ktfhmjaJp7GO0t?=
 =?us-ascii?Q?W0cWFXGSm+CIP3qhYsWgsstRTC9Igv/+zrEErFQXZvO8j+ZPTYhcG8Vrnvj/?=
 =?us-ascii?Q?5CpYsWmbmavfJZDrOcl/nO4sdYyETzeesJP0V8SXJO15NwmvpOcLRVLcXLXg?=
 =?us-ascii?Q?zJWoVx6Z2KadAHncR2phVKKDpYauZwCuNlZJIJ7CHl1TSZOFOtIK8p76z0GL?=
 =?us-ascii?Q?Xv5Abnh9y0VW4fKXfXKUcxd2pV7aEIy/ztSPo9WS04yo0Pn4014AyG+w7jSw?=
 =?us-ascii?Q?Xm7AHbfarq8fp/RpI0h6DZB7Geh2JqnYAfIeAcsnNzTj/UldxLIyTFPGSejo?=
 =?us-ascii?Q?tGM4ufpx3CbatoGzGrHE3ubdDTszMpuitwN6F3MITAR3+AZwJkKdq6IMN7n8?=
 =?us-ascii?Q?OTE5FRtd4y0XDYBqzoMuBS0wvkA1dsa2u4qI4Ssc6XQXNyKOtMWaoziztvFh?=
 =?us-ascii?Q?D0TXrJUN4MV7RKN8CFdW11WP3AHFE8iqDa2kfJMw2ZqRmzeazJueoPOKb3uC?=
 =?us-ascii?Q?lxRZX+Vf1YpLQRp4C6L/+Jliak5Sj+wMbv+40VTKLT6XpGDYEWsTlwKPzpbj?=
 =?us-ascii?Q?5ER2GmBuewONW7mn2z9ffqva04jvIpUIcBD7huA3hzNLCA4bCpB3a8ePoosu?=
 =?us-ascii?Q?W0jbK+9CrsjFBkJ1iLFHUzyYlSnaB/pZ+JlaaUanhh0wZmHzaGrEs4a8auGd?=
 =?us-ascii?Q?abx0Wos7aE0oG7XKLpLlH99x4mE8oQInYKlKiN8DeesZ98uDm70Q0jQa4e+A?=
 =?us-ascii?Q?lKe+znRPUwuaaArG4yCb/2d5mxbf0UwzgsmrKSXJfKMan0XpOC4xKJL91IEq?=
 =?us-ascii?Q?uxVb4ksaoCWVixvByePf7j2CO6errflzMIiy1oiOrxn+gxpZbsFOMD+8QPbN?=
 =?us-ascii?Q?9Y1JFBqsOyofcNQENfb1vrVMytKvV2uTyPC8yzKyO1COjmx1O/B1Dy0gdLV8?=
 =?us-ascii?Q?dQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 53qC+hor1ZNPh9dS4SqpMfcMKQa00C4w2soZAzsp/Dy1ecTxv3YFx3mqp0FrvKfVzVi98aH/pMKXXlb+tBmyGfGA6o5q20iO2trLKcJHX4XQ064Jjy+rv4LH1PL+zxkqbHa5qKMe5RQ59qJo+UmddeTl+N7ASFPqnwO3XW+RKqGrrvlc8s3rF9YUaucky86a8yTyBVqfXYykStqiLFMP/38Z2HFaNenU+Yo/c8aoE1r7iVeK8JXUT9yUQSC8mtJKV5WQhVSXFou22sLaX4i4JCnlxsT97/g18xlndGETvaf6lFmojFtETYOZwLX9vNcLGmWczniVq6yONZt12kdhU8PvhtJC1Mnl7iYt0MZcpu8Y2tEFdDKKbzJXyeF1toirlX+e3uf9kP/Mc3Av9598ohcsJMnnEDuAUDytViuzHh/VUWnC32mEL5g8BciIsvUll+P9+pd6XJJRs4YbYvTzE8ZlOy+AtvF5q0iuCML3CdVBhbYXHjJaX3QO1zgmIegYqfHhzOMpFM0sfunsV6dE/LWrFS6kDPZdQ4k1Lc40rSRZe9CoU+kdysCjHGoRm3R+6wIybt16pMh5hQu4s97Z8jadyxc3SqFWSfiCH5cbeuU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9145364d-52d1-4b17-e933-08ddd67ee414
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Aug 2025 13:24:23.7991
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: JTkr8UcChvIYyMrgJsrenW7++I9UomR5yPgAp2eeFc6JG7kLokhuuDWsG46w+UfkeHHMTVdFFymmQocZx1az4yiauL/qJCuw8U9+4v7w2Qc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB5993
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-08_04,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 adultscore=0
 malwarescore=0 mlxlogscore=999 phishscore=0 bulkscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508080109
X-Proofpoint-GUID: 5UY0Qza5ZX3vKrQ0-U-loajcgMBoEjNd
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODA4MDEwOSBTYWx0ZWRfXzOWXshkYvAVl
 iBK/HvSQV7SECC5PiNUoFPdnLIjY78gmwvAHXE1H1l8duJ2/vwIpz2uXSdHu5DSUpVtGbFnpJg3
 ydfvgchBsqRu0lBrBymrpfyG0oKzuMve9a6szpDkjNxkdJKdW0e8lI5wm0chaU9pcdO0i5Ba+YE
 NpV1foqs+H+2zymFk9oQBPHFLcOl5869/P9S0Bdx5fsXY5d3CPQVc8DjJpOs2Y2VaR6Bcw4B/Q4
 yQGo2h63bw/yWujZJCHHF62vcWDg4+GpHyPfjStADY7U6wAz2JPcCvyRziwaPyK9oaKb5QfRxb8
 dz75GptLJgndJuIAW9bU0jYAF+2DyrCHmjIYQ38i4GG6FoufH55XxQolCzBc1SJysfPyxnrsclE
 2xYWqq5F5GVdb9jW2rXUAKTVG1wlEI5fhU36265uQsDLeXpYzARUlNLhvi8C4AEkbu8eUXzz
X-Authority-Analysis: v=2.4 cv=Y9/4sgeN c=1 sm=1 tr=0 ts=6895fa91 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=3NcBxTQYnx3wGZEPvakA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: 5UY0Qza5ZX3vKrQ0-U-loajcgMBoEjNd
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=LxvH2wCD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=dJgB60Y7;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Fri, Aug 08, 2025 at 09:08:35PM +0800, Baoquan He wrote:
> On 08/06/25 at 05:26pm, Lorenzo Stoakes wrote:
> > > I found mm-new build fails when CONFIG_KASAN is unset as below, and 'git
> > > bisect' points this patch.
> >
> > Yup just hit this + bisected here.
>
> Sorry for the trouble and thanks for reporting.

No worries!

>
> >
> > >
> > >       LD      .tmp_vmlinux1
> > >     ld: lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'
> > >
> > > Since kasna_flag_enabled is defined in mm/kasan/common.c, I confirmed diff like
> > > below fixes this.  I think it may not be a correct fix though, since I didn't
> > > read this patchset thoroughly.
> > >
> > > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > > index b5857e15ef14..a53d112b1020 100644
> > > --- a/include/linux/kasan-enabled.h
> > > +++ b/include/linux/kasan-enabled.h
> > > @@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
> > >
> > >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > >
> > > +#ifdef CONFIG_KASAN
> > > +
> >
> > Shouldn't we put this above the static key declaration?
> >
> > Feels like the whole header should be included really.
>
> You are right, kasan_flag_enabled should be included in CONFIG_KASAN
> ifdeffery scope.

Firstly I _LOVE_ the term 'ifdeffery scope'. Fantastic :)

>
> Since CONFIG_KASAN_HW_TAGS depends on CONFIG_KASAN, we may not need
> include below CONFIG_KASAN_HW_TAGS ifdeffery into CONFIG_KASAN ifdeffery
> scope. Not sure if this is incorrect.

Well I don't think CONFIG_KASAN_HW_TAGS is necessarily implied right? So these
should remain I think, just nested in CONFIG_KASAN, should be fine.

>
> Thanks a lot for checking this.

No problem! Just ran in to it while doing other stuff in mm-new :)

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b5d313ef-de35-44d3-bcbc-853d94368c87%40lucifer.local.
