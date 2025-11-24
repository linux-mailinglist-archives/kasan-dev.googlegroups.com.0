Return-Path: <kasan-dev+bncBC37BC7E2QERBFX2R3EQMGQEXRRYWRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 33160C7ECBA
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Nov 2025 03:04:08 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-3d41cd7329fsf5375132fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 23 Nov 2025 18:04:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1763949846; cv=pass;
        d=google.com; s=arc-20240605;
        b=C7NK5z/8DdbpvlnUaSDnPi7vNc0RhuCRTZd+7CQBkM9RWlrz/OsXqvqqisstnzuV7+
         Lu3ara6l9SRShEulpWoi+0cENwT1f/FO2T4vCDaj1s3zyFPpkhfmWZltEAQedoGiLEIg
         536FF55JgPFAgOlALqyY+Drkh7JZhubjup2Ng73qXZcZcd9u8iWfmJ+r7/vhFiEIxwlW
         2QvKhiVspZcVujntgbfi0J21He7xBnp6gbZcxYxM7zDSXsltrRoiecpCFfMLe02AVrd6
         nt5e09KfMKbhM8CPzEUXgqalcDIfob+9ep8uAAp8VG9t7t/jiv7q8HLd+6bEkoK8/Z66
         Gf5Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=OUl7D37eiJ9I6Hi/jjfHTecQ4WTJXa0OxkMKSHhB+yk=;
        fh=u7Na1stod499PowPG96hjWFs+9ooANr7YK7qmNoBWnA=;
        b=E6sfzPX428B60W70JPXQ/JOQRPfDA4oVI0kuHR7MzXAflvt0hdj7fz8iNvOXGQl3I4
         zWZRqCUCOIVDErccra7Li5cA8mODC2686nW8CQiUaGlzW8ddnxwF0BulmDoGJUGQAHL1
         34TsFRhqBN6D7TfEYqNQYbhFvSyl/gHu+t11bFWE6L5HjmynevcJQff/bEfSjtFDEovU
         gyyPLIGrILm0g6/p1evINRXN/QZUtJROFasR4gAvrZ5JNQtfPABHcj55zWptIoaw12Bx
         6x+NCvRkXW1nQwHHwnr/hDTkiFKjClQDntjB0pwvvrRVtPXXDPZEqxMfjyD/ACLS/8/P
         d1uA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ffF0d5VE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Zhqc/zyv";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763949846; x=1764554646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OUl7D37eiJ9I6Hi/jjfHTecQ4WTJXa0OxkMKSHhB+yk=;
        b=UEsmSr9LLS/vnsf6grGRq5oyaWs0dEUBuu58akoeVERZmHCtIUNHlgwRbBP/5WaV0m
         ljsb6AMPq6R5AO1uuFxsQAEf1761Dv8+v6B8V9hthXZybdk0z7in8NaTnvAT5bJlZWqO
         Il6ZQscnsLXXrVFQEM8A2U7p548ATCftXhf+Mari1xdjY3Z6tRDRkGZLDCvjSaRvK8bx
         4N1IBbevMztkwEdHEZStjMo2JeaNg5NK8D5vv0g1sD2zDTEhq21x5ALtjz8px+B1MTUY
         oieLshSdeIpyApCf5PCG8QnUkY0gDHccuz8kbVTZSkzAyzljdE6FYkQ43R/xhtbvT8jI
         jfug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763949846; x=1764554646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OUl7D37eiJ9I6Hi/jjfHTecQ4WTJXa0OxkMKSHhB+yk=;
        b=gdIU1yPQPizxtY7+KZB9jp65C+feVxMtzmcAXBnVpY1j/7Tex7n9jHFeEIoJe6tag5
         TQQvY7Gb2PftzhAuVxwdgTaZ6WruCKynyY+fcINClVV+q5NmiOfXcP10SHugZHXwuLbY
         5aTqyL3GMEo21ibX/kjfWEhekW8QCKWGu3sxJ3+hpGkq4Ls95Ucie5l76hXLE/pODiwd
         lUx4xqosaRLy3l/dkfdfBtqlfa4oFzNgfKCZ/87XsDXMaZvpArcoc5rMaPpl65VxatKr
         q2j6OMW2H2xFxwI09eeoyOXAZhypUFnS/e/0rSnVi7eMAE4LiebP9tm7T1bk6hljUJyz
         RXYw==
X-Forwarded-Encrypted: i=3; AJvYcCUMh2YA1xKAz5jNWi1JVvBXg0vPQnOdb1/ON2sPjnvrspqTLOH2F91wrHVu4qShqwiHr+48+g==@lfdr.de
X-Gm-Message-State: AOJu0YyhOBBf4oU7OnLI8xBuk22h/NFcITRt7XlaqEZlEucu/UC59r8j
	rNIEIi18w5zbEjCmzIBKGkFc+UtPM8SDGW2E8IB6yeD9UYvUZrEX4AuX
X-Google-Smtp-Source: AGHT+IEeBHjTo2PnJgvKl/eoGoBV5mkdt0T31iVDjivsZkDqdGQ1E5oNf6wmDIw9zKcbHdOxqHV30g==
X-Received: by 2002:a05:6870:3b11:b0:3ec:51e3:4fd4 with SMTP id 586e51a60fabf-3ecbe5e5f2amr3727081fac.49.1763949846518;
        Sun, 23 Nov 2025 18:04:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bGDOgKb905B5+PWC3GkNMI29jbA8/dXb/RRInm67hoiA=="
Received: by 2002:a05:6870:c1d2:b0:3ec:401f:488b with SMTP id
 586e51a60fabf-3ec9b3e6f51ls2577145fac.1.-pod-prod-03-us; Sun, 23 Nov 2025
 18:04:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX4FFCuqiArKu9c9JXv5Qaic5uU8RPdEdeg607ZHvnyIw6XCzdI+lEvaH7r40JcuLvHmLU7ws2Jk5s=@googlegroups.com
X-Received: by 2002:a05:6830:34a9:b0:7c7:6a56:cfb3 with SMTP id 46e09a7af769-7c798c4af20mr6382406a34.8.1763949845675;
        Sun, 23 Nov 2025 18:04:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763949845; cv=pass;
        d=google.com; s=arc-20240605;
        b=QBD4+c2ov/aXy3PVMDp9gcCo5s2FjMGQhZvf4G6AY1Kx9gaZT3fJL4wLfAuBS9nk+R
         PnfIOHdPH7GqZ0FNR3vJjPoJQLWS0NOmAO3R5isadfd2MzBi406UXZos9ArVdQ5T/qJN
         +YtjZLlgGJRWsf9Kv6F1iB4zyzAj90KLfDVDdGmjuDDDKhvK+ojq9cUu7xQHjBFvQ8Pw
         nZbN0sjJDPT/wrz/cIdRurluKhs96SmmST14poG+9kPhKNILGrhaliyZQWWIhSxtVgh+
         dUaSIafm/1qOq8pfciD7CWaP7Cs3tD4/8h2LGPMxADz7ldWuLZWNgNBfTfCJ5w4UD50y
         7aRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=tn18t9XUDcnauTymyFkW4ET2sLb7CtfbjZdBx3ZiS1U=;
        fh=GHxOsgsgNia8HVsr4HWJkum6qpJiryzYn4ARnofWJUA=;
        b=SiFB7GCEsZ6sJGkiVcOZb01sVQePa/4lWVw9Aa6Tue6e8I3Id8s1FJ3wruKhs+OEO1
         Tetgyo+giGG9lQyY5otMw+19zM+i+DgS20uiuVB8pp55IIGpG4Z+1uwisgKfgrdM+nOG
         yyzsai9QXq5jz5qBVpep/XlzzIOqCqs6xa092c1X6iXTOWCYsEgOnql2JTJ0ZLNIf4Zc
         +nZxyNFM+nf6av0tjRK1NMPLKhurCkbxZ5+T0BPgLORybdXncsIPhLQydxxc8mr4rO1f
         KlXP5d5gusSfWz7flnAAefz6dNP20HGNHNRDIBFsCL9Srg2E6s/LFxs4VbXF5pPxuQTQ
         WtAw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ffF0d5VE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Zhqc/zyv";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c78d396a72si431341a34.4.2025.11.23.18.04.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 23 Nov 2025 18:04:05 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 5ANMdmFo3868235;
	Mon, 24 Nov 2025 02:04:03 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4ak8fk17gj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 24 Nov 2025 02:04:02 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5ANJxuRb022479;
	Mon, 24 Nov 2025 02:04:02 GMT
Received: from ch5pr02cu005.outbound.protection.outlook.com (mail-northcentralusazon11012057.outbound.protection.outlook.com [40.107.200.57])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4ak3mhj49m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 24 Nov 2025 02:04:02 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IHjLiEBRxJ4/Dy9dEjSYw27HQf8XBEBd6Znd/mQa21QLDk9/2u4Aw8g0Z/UIyE3SfvyXXLXm9O9tRDrNGZktdFkK2Ocqpc+1vEBddHTDgp/Lf8ws7ET/AWP6puHY15l7P+fj9y+HfdAdm8Rb/rSGztZw1tQ1PtkxDNEVX5zg2jEdlXlwOiztU1t1eqhZWInY4zsNLxKNVh+2ZlogrLfolR9vD5PlE0DH9j+JEIAhATDmYIGjhsT0lOQC24vB/4aabznDB7cQV3N4fA5hsL+sLavkG2gnnpOLHMbklLBvPm1F3CAGGjBzVYkgUXCaorT7FAuLEFqkByvBbeTaquiDvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tn18t9XUDcnauTymyFkW4ET2sLb7CtfbjZdBx3ZiS1U=;
 b=Hc/LG/ibBAjrYP/Y06bdf9PmqsSkqvLiJ7VpM+pvhlPY/SS1vHAj1TzajGuNnnz8DJRHUT0quN0jNKZvPeMSFqP+v5n7xdWh8uxL5bWR/5ObZYo5ouYyZ7CaLzoiXrehCQ/0QZpZtRVj3My3JMJfV6GVt0O3le0+BmT6GmkLUA1uUWteiXosXtYt6ohlrGFx9Mgu/KfU1Jflt+9fLXD64IdoSjtUdvjnt63sBrXmK4FZ9MdvcsnC3esJObgLi+58YngnNRdzYze6VnHab0I8o7Q+o8Q+oUlPUgSxL8DCyeEnwvR2JyWpEZkYIRBeI7ijuX5Jj45t6u4Arueds9PmHA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ5PPF8337777B9.namprd10.prod.outlook.com (2603:10b6:a0f:fc02::7b0) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9343.17; Mon, 24 Nov
 2025 02:04:00 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%6]) with mapi id 15.20.9343.011; Mon, 24 Nov 2025
 02:03:59 +0000
Date: Mon, 24 Nov 2025 11:03:50 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 01/16] slab: Reimplement page_slab()
Message-ID: <aSO9BroaxaNaC_hN@hyeyoo>
References: <20251113000932.1589073-1-willy@infradead.org>
 <20251113000932.1589073-2-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251113000932.1589073-2-willy@infradead.org>
X-ClientProxiedBy: SL2PR01CA0001.apcprd01.prod.exchangelabs.com
 (2603:1096:100:41::13) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ5PPF8337777B9:EE_
X-MS-Office365-Filtering-Correlation-Id: 133dace8-4c46-4a8f-ba7e-08de2afdbb6b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Mo37QouJl/Fcaddfv/jQhcnxCc7GtdrHImYI14C4kWVDQMLjRzrRG73C0FbH?=
 =?us-ascii?Q?bVbn1oVcR2CUtkRBpuxsFSWJ6jSrlhu4/3Jr3IJ9wYqKvjcpWS+bqSs95geK?=
 =?us-ascii?Q?gnznHEdmd60mzN33xgcb11ge+vAnprY7+/Z+FW2IbD5MGcKyegD/J6Zo07Bt?=
 =?us-ascii?Q?U2L1pYDwKjdHOV2fBvBC9KQpKHIUv2hkW4AOjAFYCoLsmSZa8zoSC4MS8Pdy?=
 =?us-ascii?Q?re6RNIkWMSceZIc7zF0TnHXj6SzAUXrn9t30kY+mipTFFpusa0bP3wEJ8Zfc?=
 =?us-ascii?Q?DXnu5ygT/Iopaz5W/BuAZQLx70uoVzIaJUc8na1Wod41hX49XpPadrH6drLQ?=
 =?us-ascii?Q?AVJKL4C+d8iUARQ7QCnh6/riPHkKZ+4b6ay5ZQXOzzRltyR4O0iSo2MKiHop?=
 =?us-ascii?Q?ZrEsELqeIhOH0MWs7FpjFSaSaODQiDknC8mzsQnv32Ed07DmXrZGyqRQyPbC?=
 =?us-ascii?Q?0RGEXwMK251jY0rMbYI92fV7scHELilL2oWkMAoB7dFO8ZvY+d+jAssUvM8C?=
 =?us-ascii?Q?kNuYzkAZ2cIz/Xw/FiHMmQ5XYm0RWdvbF/QN0sRSmumnE3hD/RW/ax4zNRL2?=
 =?us-ascii?Q?3T+r1nFhmOeh46Axtk19pjnHdNot5uiwQuZOYFt89IDbkpVPXKxqxOriDLXS?=
 =?us-ascii?Q?yL1xiWYN8gQdprztjKdVgRzZBuoKMd3kKCjmtCe9m7d8f8VTmfzc+caMK6Lm?=
 =?us-ascii?Q?e1rriSWhmeYHOhqa0ZmVlkM5R3HcBJ/ayZSuQ/7lIGeqYyixANtjxSQqISMR?=
 =?us-ascii?Q?OSJsQIgeZM7gVfWi42oKtU2etds41XGcz1pK/ol/vhEJlQy0QuOQC5rr6FAv?=
 =?us-ascii?Q?uIsOCnNkSLwO7BMnUnQ8K1EJS3FTTLRwv8MuY2h/vy4ybuE8Ht3Rb3VMRzFM?=
 =?us-ascii?Q?VvLF7BmIBL5XN5Zp8IXgKzAylJWrfpUuYeLvFHqavjUg3CPvCoeyQSlFPK/G?=
 =?us-ascii?Q?Gluf3X9I+/y3rtizFReiLlHViABLEhmVsYXDoVxsQu5DlFuxnl6FrngxdYMD?=
 =?us-ascii?Q?I2D+dVwclSbxeN0zgmW7/pgAnrabtK+/ZxstKORz3pOTgieRuPDgPNvPWAAz?=
 =?us-ascii?Q?hQvBMeYWDt8WoDKToF/ddDF+dFz4FdZ4yHosT+JdQ32M7wAceVEDHrcLwyYi?=
 =?us-ascii?Q?kapgCUS5MEgY299Ab7GSf79N6h6K7cnG3x/87NnZjEwZl18/D4it9BI5zyL+?=
 =?us-ascii?Q?J6OLHE4kTnMhHsEPxzTYfoZKmkmLrLWgCMRQiQYnMrtGAKqbFyPsmwrPzaNT?=
 =?us-ascii?Q?d8xA/tmfUf7h+ueKGoG5E9fOqdTf6B0yzW9sU/mWYxfQWorswIAoMhVfr6yP?=
 =?us-ascii?Q?N2K1BUL5hpCyjRmbs3GFWkrmy20oqD1Or70+Tgi5vIHIlvmF0oz9k5OIPFO0?=
 =?us-ascii?Q?Scykn8Df+YTYFuH6EQclY5thSevL+kgL69OHP9ZRXzWJWx0ARkGMPi/bnfXu?=
 =?us-ascii?Q?9AtyT/8yiqCML8CKpR6sAehONce4sBAU?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?qk3HO9+yTKqlra7u42IMdjVE9jI9d/hqay98JGgV9ut99/bUgClxCJxWJKvk?=
 =?us-ascii?Q?NIPDh8h9+L2a0mXTpcYiObP8LKquLrN8v5thD6Q7upvLNz/6DFYDVXSJfiTG?=
 =?us-ascii?Q?J5vOD3GOn9ZsesI88CDuOKEhdx0Wvoau0NklH5Kur7olVLCDTdamBqcHtgiT?=
 =?us-ascii?Q?ZgBSdFjGfSeyDqZC44lsN9rfbGrfRvck2P7gktDUT+qWOwzBMW7DDI9dQAxF?=
 =?us-ascii?Q?WcwrVeiCekWm133WVm3L/Oj1E5TUta9JReJ1Gthh22V7ytHe/+Wo6/bqXQaF?=
 =?us-ascii?Q?VZkLsbWLMBfUIKNIaEP62xyne8xkTD8nb3ZxtL/pBYQL9IOrxGrl0UaLSqlE?=
 =?us-ascii?Q?B7B99QSXzvtZrUQeWCsVLNJCLeILyEG3PFekvWoZF8/IV7aSIWNNU7Ib1D8X?=
 =?us-ascii?Q?+pLKWcI/3P6QyLmKBqkRRN9hGuw7ew2x4Pyh0/CqjzPOgffwntjcISpZWC0z?=
 =?us-ascii?Q?IwADzgYHJFYqaZRvsMkXftgYKqtk+2CT958RimiSez92+dLx1po0smNmXhZp?=
 =?us-ascii?Q?PYVUcBW8Ox4y5fF5lHEKvmJbZyC/4Sjvykw7wzQwzMgLlmepAW+OlY1jAh7i?=
 =?us-ascii?Q?oD0/LT2v2Zg0Jn88AkHBLsCSUx3Tz2m+E7YlyVKO7RDqgGfS7rFcapgZGgR4?=
 =?us-ascii?Q?J7kesbolWkse5sIvjLmk1c+6rWXBPaF7hlj0v6EiZEFBFEbidKaXqAQyjQbg?=
 =?us-ascii?Q?/4Z/0puTN0FgQIVLnuRVjZ6PbRP70PZOBO3WdD6d4k0KNlInc/nrMJhpy52L?=
 =?us-ascii?Q?rhqaV2myeWZZiEIZaeavMts2I1B8yLYZvJvNsfS+Bqptz7rjI5EE+RCMZ04y?=
 =?us-ascii?Q?zrFJqhPk9Ai8tGwfl3pwnu6FZD5mMT/EwZKm3PAMiNwVKaWR89tNS8zUAOxR?=
 =?us-ascii?Q?5C9nH1Xf3W0F/gV/SlKAxnrJziOm4EBLyiVXvRNj7U1MgIvX78J4uV0Oihst?=
 =?us-ascii?Q?mqnV6i/EsaD8m/qpiRmjq1vmwbcqmddPpFSnztldHu1kipLsBX13o68KaxP0?=
 =?us-ascii?Q?Ie9e22Tzxw1+CYm6qzqU0R3axphsSxZekaybOz/vIGkT+ndyiPNBKJLoN6ks?=
 =?us-ascii?Q?ZfvQW3RTmrsVcMZ1MW8OUtDDshTrHScF9rrGEow9d73QA7/BmBKQMLcza1qG?=
 =?us-ascii?Q?teHNoRRKG0RfFb43+inVqBwesJd9VrVvUVXH1LA9Fk0KeD4UeA8ZECHX8qJv?=
 =?us-ascii?Q?QWh5zV1ZyPQl5XwO/XEHQUSOZBkXkaj0drzfA729p7yvOe8GeFNGzkx0FLz+?=
 =?us-ascii?Q?h9wzC7IuC36jI5bx9870Gzz8QpBEPWVMKlPmIJo0Jk8hax0NjVzMT2+EfZFu?=
 =?us-ascii?Q?L89Qb+/RgvrDBNNhhZujZfZ1GSWKQyeVluJEwuQk7tNARo7+EAQlZA1JYYaI?=
 =?us-ascii?Q?la6mzFIdclsrYfCbxt1gmlNorJESPZ1BysPBOozVxjfNijnAZPl302kmhJPt?=
 =?us-ascii?Q?RoFtQ4BJqiO9xqEz30EU9GR+lIWFUyC5O6MqAPL8RtCWQ2NEgHBUBtkmh8+y?=
 =?us-ascii?Q?RV+35T8oao7pSqkrr9J6GK4mNb7JXtq+qtiq+Nm52XkOCD1LQbI45imYVckb?=
 =?us-ascii?Q?VdZWybtPW8VY82YsXNa3lyTX2OLI9A4AhvMdVvBB?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: XmQbImuKvkoWxhBz2tAJEVr85RHVGeBTSOVYewzQWl0Iv4eZq+1azSnJNjeweTqdnAnraQKL/J0WxmLxoFdzRn4NQko5yC8H12W2bsr60aFAdbh0qbEw0A5VN1IYPSnrOPGqFq4Zqn6bgt5+ozQ+xkvAYeBx+iaN3zxsu/u1UOzx1jf3sSQaXEyHvk1rEYyE+UrEib6TFqZVxzaQquF5Wc7DtQ1ow/hyPlBiaUzSqt5fGYtC04Vmw1GEweS+qfD7xMF8Gsm62u1zqXnTTkvnFxCPPkUfvzKql274D/KfUwz9QxzhYyMNSvdrXDkIifO8Gv8p40vsZ+LSglWLYqWmpEgMOHcgchcJPtRKg5BGuW98f+T5bYHtEHdxC81PE6bvD7rSlDsR44tJypVMe4fBsCV3J7/G7m4KqB4oTz4weAAYaepF3sIQL60g4iMBzRYt6aQDR+kVd09DBF+Hb/IOkuLH9ogtOJaWCPVGfVB0HK1aPfzMVbfxsKRqzyniYsfRCUSrK/VomXLUOKQiFsbN1/0QBT36XysUO9hKSc3BvyE3cw0vwwJhya+zEtNROaM5DeQxIjzpl2b9B4bXpOHRULn1KklOt73Au2Yv2gP0Y/E=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 133dace8-4c46-4a8f-ba7e-08de2afdbb6b
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Nov 2025 02:03:59.6037
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0fL1ZfJz4G0oECJfcbPmMbwpV5TOh6c2KzGU4t/cr99xE3z5cOYsOICoi4y4l2NMesIzLVba7hgF2DEuwmRxqg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ5PPF8337777B9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-24_01,2025-11-21_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0
 mlxlogscore=959 suspectscore=0 malwarescore=0 phishscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510240000 definitions=main-2511240016
X-Proofpoint-GUID: PBy8hssQgvAQDYR4kKn9XKu0cbE5vY7I
X-Proofpoint-ORIG-GUID: PBy8hssQgvAQDYR4kKn9XKu0cbE5vY7I
X-Authority-Analysis: v=2.4 cv=L+8QguT8 c=1 sm=1 tr=0 ts=6923bd13 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=6UeiqGixMTsA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=JfrnYn6hAAAA:8 a=1XWaLZrsAAAA:8 a=4RBUngkUAAAA:8 a=yPCof4ZbAAAA:8
 a=lOb0CVoLlyu5vuCBIF8A:9 a=CjuIK1q_8ugA:10 a=1CNFftbPRP8L7MoqJWF3:22
 a=_sbA2Q-Kp09kWB8D3iXc:22 cc=ntf awl=host:13642
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTI0MDAxNiBTYWx0ZWRfX6RGozqTbi3LG
 AZXC7495pQpAySL6Zj6alBn2cqShhPBhWoNw9lKLstA4O42J4Vv/CENIYgNzCfbpc7cNd8yzYVL
 DJ/nmwiYMtRIGEm1O2FFmSRNUgzchGqmrFxkgh3PgrS+IEiq+DJOUW9tRqZ39kj0A1kQws1YJKQ
 A72fQMrXALhOaCEGkvYitmnhtaljes3RTStLkT5WMqHrIdUrh4N276xuUtV6lIPxpmBp/WGnCq0
 /GljdOlyKZ1R9hDyngiLYw4Bw13z7y802QOxtHjzqsDslzadf70oOUd4D4ixbUfyVzO2dwuxlui
 6vLIDQtARqKS2G9+tL/OhYkiDCQ4Qy3JBMiDH06fFLVNs4eyO6FPY+damXRR8kZyUKMqxClHH4I
 tDkx4Cij/e4d+cIJS4nSu19yIKLNxDJHwlg/mZRHjpPdR1pdVaU=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ffF0d5VE;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="Zhqc/zyv";       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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

On Thu, Nov 13, 2025 at 12:09:15AM +0000, Matthew Wilcox (Oracle) wrote:
> In order to separate slabs from folios, we need to convert from any page
> in a slab to the slab directly without going through a page to folio
> conversion first.
> 
> Up to this point, page_slab() has followed the example of other memdesc
> converters (page_folio(), page_ptdesc() etc) and just cast the pointer
> to the requested type, regardless of whether the pointer is actually a
> pointer to the correct type or not.
> 
> That changes with this commit; we check that the page actually belongs
> to a slab and return NULL if it does not.  Other memdesc converters will
> adopt this convention in future.
> 
> kfence was the only user of page_slab(), so adjust it to the new way
> of working.  It will need to be touched again when we separate slab
> from page.
> 
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: kasan-dev@googlegroups.com
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aSO9BroaxaNaC_hN%40hyeyoo.
