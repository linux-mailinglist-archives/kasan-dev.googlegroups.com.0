Return-Path: <kasan-dev+bncBC37BC7E2QERBZFH5TFQMGQEAP2W6JY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qEYfBucTe2nLBAIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBZFH5TFQMGQEAP2W6JY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 09:01:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B14AD0FB
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 09:01:42 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-79472373f48sf13450057b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 00:01:42 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769673701; cv=pass;
        d=google.com; s=arc-20240605;
        b=a8kW9NRizcqB1RwwSY4Tz6XtgAZe9BrvSivRUIyKnQWea/AvK2FHhBrYXQZnYQiBym
         jWMpF5E2HyJvXY8oN3L/Hdnm2ir05iqvKe4N+GYO7gK/nl3y3znBE32xR60FM33Ak+Uf
         EkwOIMC3GF2hnBUd76fFVX/I8GV6ZW2KSQRB8gUKt/+DRJIabgiH5pZ86//TTd1bEmww
         Daerm08lsEc3SPVrInlN/UUxO5nsqx2EvogMiCIvlSg3P46fP9ffmdJFjZpst7i0/RuC
         ziQfdyVGXsAZw9siJQwtR0p8B5mDn7LAfeF+6faRcHyl0EEn08d8ZGoNPeEXTiTX55tP
         v8Zg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=p4Dc/dJ+jlXYjSYUKGN0YsA3SHvsxqr/Ve+4+X9PQok=;
        fh=K2VXSrKFoIZrlkHuLVKvFduRjBa4z1sLOVnQoZBdUCw=;
        b=eZy5fzCfnFwp2m3vKw+H+bYhO/dCx5bb7LGNBnmb4QnTCPy4EtiDPN5Uvmab0z/Ads
         0wGtGccFQTHN1fNCAI8EN7xoWGBy5g0re2oj9Mje+PaAuKPWZ8HCk6+r1ZLbOgJ+DEgK
         vrIKJXR+FGCLFR+5uzT3XijpLu4PDtBwZFGvL77yPzORGQPep8Vujy+ljxRdaUCTLUSf
         3bUj4iZwWEnq1Ph0bBjTiniL1r3C3rkxqJZbP2HEJ9+hPvVhEccAzlwPdkOWPwgQPAfT
         jeWJYBPMnZ6iaiTCa6a0m5xxDykvYeaW1PW8WokYwH33situj5Cr47Xw/FbHbTyFFoKQ
         gFnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=W4QysOv9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="d/E3U8lY";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769673701; x=1770278501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=p4Dc/dJ+jlXYjSYUKGN0YsA3SHvsxqr/Ve+4+X9PQok=;
        b=rCW56mO9iDRfPKVeQgBSinSIPt27gcR9Vk8kQ8P23YTPWumbg0OOVkbsYNZ/AIJ/Vy
         oMAFGkdxFOfZHkUGy7xMTv7wSatrEiN9k/V2INogEwHAfLSLvz8Ny4maOyskEMmRHEjT
         FG3Wd13qHijAQz0d8rIwzjTH4Glib7o+aob0rzc1YN9eBqMvralDE6Jt4Y/I39SP1EaV
         Dp6SkQYM3VCRtBnJ3sYJ2vX06re8LItuGy8Fz48AzNlk9soCwTHalRVW30RYcVx3F28/
         dHWz6H/YmWjO11Ri2h7f7TDrqLTeZgKamI+Uwai4l5GJBdrp3IZTyt34xwqrHQWKKPcY
         ISDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769673701; x=1770278501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=p4Dc/dJ+jlXYjSYUKGN0YsA3SHvsxqr/Ve+4+X9PQok=;
        b=kmcTKeVzVeaHJWaAiFwsSlUkZZF1VEczl/k9r5+GG4BcFxSnJR2f2gRk7uF8zM+h1O
         TLvxcAljR7tFqJtfZ42Sdy2DcZpXalEY28BBnB2sMz0L5oMIZ/g2nt4smrY4ET5k2FdV
         l3l5oLagA3vrEmXrp3HOzkN1qvcIuVsbSwIvEToJ1phAFg+vWpXW2IGbhbJT9B6rv+Kl
         Y8r5XEdHPbpdEhZ0JavnN4Ui5KPNzz7GvgYQrTdls3HFru7eoci5exTYQ4xNPl2vNWm8
         VtSxtJ6IevX28BmTZBYf0088zxTdXODAIZy+mp5tmwjycb/LAwjcavTKi1uFgAZJFSVC
         T/Sw==
X-Forwarded-Encrypted: i=3; AJvYcCVKuj5k9/e+emUXRrBbNEIaNKh5TBdrHyvtCIqWY0rh5YIwV0CHPT0etk6VfLDSkEu+Frr55w==@lfdr.de
X-Gm-Message-State: AOJu0Yw54RmGrp9vzfdDdeFnU9TdkRMyu1ydSHYp5Ciikg/Aw1+Xnvx1
	lb9pySsQ+jjMWDnvvhK+2T4WhbQ4NOBAkpmW8kYp/dD8qSqW98mVrM87
X-Received: by 2002:a05:690e:1203:b0:63f:c4f4:e199 with SMTP id 956f58d0204a3-6498fbe8a17mr6854052d50.15.1769673701017;
        Thu, 29 Jan 2026 00:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FwMokMyJqY3Q3meNNGB69H7nZ17z9J++V9p0tm0Gc6xw=="
Received: by 2002:a53:b1a8:0:b0:644:711f:4a0a with SMTP id 956f58d0204a3-649a00b5092ls387010d50.1.-pod-prod-09-us;
 Thu, 29 Jan 2026 00:01:40 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUDFafn3A1NTIAMFhKY6Ug8Zgf8M3iQiPbfvCgRl5L9eCNXApPerwhV8hlMTjLm0HJrX304zcfJvMA=@googlegroups.com
X-Received: by 2002:a05:690c:3608:b0:794:7348:e626 with SMTP id 00721157ae682-7947ac944f7mr72337327b3.64.1769673699911;
        Thu, 29 Jan 2026 00:01:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769673699; cv=pass;
        d=google.com; s=arc-20240605;
        b=dm3QdG4X4zrI71+rnyHYaDbR1cL/N467H2AZ/oPVUBcQuGW+1V8ITdt3ssfz8T38V1
         TbYDZoqBRgMlngz2rPkcqYDncdC/M1HiWfjqevvZqovc0bMpfC1No1GSNQZIDdjeaG1a
         DQb6TMJnJ4W+xH8UrGyiKHrqV7ZRIVS3pKBvSgfWPiJhWT0RnOr0EdVPy2ovqWut5vM/
         GTXjAoDM0zPyGsRNZe7sNERzF7o4BHLvagtj92jwvgUk9HUUUha5/APE8HSp1la9DGoe
         58n8dsBaIixKF7ejbk0t+SPph2gAwm7iffyoGagIPzsRrAPuPG2H+bmvEHBTKc1bUt4l
         /Hbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=8hEBAHr2aLNsYIkEDkDmlLGQh71a6seBEyP1K5EtNGA=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=IXIYQDwcHz7cwzv4qe6gJsagxiGd+/VQO90gRz8Lw+bykCEkAL++9plnfbFnON9aOt
         orxg6COgwMZgowKbs1K+3NezhAE67HiOtJCua+3l2Aut90TPXWAFJvaau6+ju5FTmc38
         0SU5BusiDidIpUSJrq3/GTh/c/Yien9t7fsKjB8bXOsPa0L3LsAR28VUiP9eCLazide5
         FFQLChfZzEhN7mClmlsBhGtRiNhTzQPcwME1VncJYQKi7300lXg1cwdfGBx2R2/Udei0
         GwroydWWmnJIGz4EAoiX1C5vesCnv8czvURHW+TOzAMie85a8RbV5c39CDQWwZ+V9C8V
         H3XA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=W4QysOv9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="d/E3U8lY";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-79490ccb030si590297b3.0.2026.01.29.00.01.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 00:01:39 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T6nimc1054988;
	Thu, 29 Jan 2026 08:01:35 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4by5b6aguv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 08:01:34 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T5vtKV019835;
	Thu, 29 Jan 2026 08:01:33 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011006.outbound.protection.outlook.com [40.107.208.6])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhhax47-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 08:01:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QwrR5HIBzmFoxfCRGJBP3M07zxB3S5RfTpMcBzLw2FjI6m2vSUY/aRMpTxDZ8ninT/Ia0r2XbtjGLhzDFI5h/52GLbiUE95OuIqouF8qfGy/k7I4cBcWHAv4xkpb79UcR9tEd1XZKKoMmaOB7ytUYDwYkS88x2Re5DFvfF4/VRPOsaqSmmxbkcASeMqJ9zq+KZM4xbu1yFSqFhxBbKvpZnK2kHkpIPwcM7FDVVTFrFjSV4MiccBjHJXP9GnEawp2ySNJwOh4uDquDjOrraikqm4e1jOgYc7EsljkpAzWl3mu8WfBsSxc8kJiekAJYS7g4CC6TD70L5sLqCvuI42auQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8hEBAHr2aLNsYIkEDkDmlLGQh71a6seBEyP1K5EtNGA=;
 b=elP4qZmhwgwh86Kw/F0bTIoOLKZ75P+m9RGPfPo6NA2Cgn1pIVRhCmZhBQ1PrK72xun+BJDfj16fkS4wJEKpWKp1Z87jqHX00brokbX23ZNI9PPU4rt7St3+r2+dRPVui/bN53zpKkqnKoTuSg2heaDfstmrLBVqqudO9LdM+BAEkAM+ek/g8H269MIyIi/SnWt1s9TImTDb9dR/LcGScJupJNvPA1MS3SKKVkFSbDEWO2lrOI5mw9TPDrANBBZDgjG28VYK2IsAQjL046ipK/vpYnUCMubiiiBqIHZ3r6J61yy4Dv0OK7uvbIIjLO2jd2RJqaWYwf3ifHhSLSWkxQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH3PPFFC83155F5.namprd10.prod.outlook.com (2603:10b6:518:1::7db) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9564.7; Thu, 29 Jan
 2026 08:01:29 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 08:01:29 +0000
Date: Thu, 29 Jan 2026 17:01:20 +0900
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
Subject: Re: [PATCH v4 10/22] slab: add optimized sheaf refill from partial
 list
Message-ID: <aXsT0FSP5IGCXxOt@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
X-ClientProxiedBy: SE2P216CA0025.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:114::19) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH3PPFFC83155F5:EE_
X-MS-Office365-Filtering-Correlation-Id: 639274e0-de04-4064-5728-08de5f0c9bcf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9rLWY7AHMkGfspDIC8aivEQknDmwqiJXpT2IznT+9U1QzXZpG3WtzVml6JV6?=
 =?us-ascii?Q?v3yz8vuz773OLit9wytBE8nLxGR7V8z51tkri5wXkS6ukTnXcs6Nq/9FEks4?=
 =?us-ascii?Q?caTmFYr7Wd3qLHC9SB7H3GByzUsK/7/CG8u/8OVf0PWIHMQShF8vuo0IeQDO?=
 =?us-ascii?Q?5sBJdrS5u7XylrTgREQQOnsc/K6sRHVjCapvVRQo1OFZGeQFX0YXL8e579dE?=
 =?us-ascii?Q?ouz6Z88z+QI9PEcz3BdcFelyIBrmIRXblEFCQb7XUa82WLr4RA4S10beHAWt?=
 =?us-ascii?Q?X4lpYNc0NGtSch4gfy1/7FKFSq5IBLzVpIzgyYLh3Jq+lLefNfT0lfU/W4Q1?=
 =?us-ascii?Q?+0WUbxn1mZ+sgU4stkc0FUjwx/qWK27NxYamh37rh+1ddDmJXAGJfEFWiNQ9?=
 =?us-ascii?Q?fiaVnM4dvpxr9aLePffnyRJpCvWkfVughxGvaVqsld/gmsndrhdEhcF+EIMz?=
 =?us-ascii?Q?AOLieXeh9KG6bI2d/VIX5XkHhgDonIEnMcNjpycqPtrQLKDSu1gFY6v3E/EA?=
 =?us-ascii?Q?6LwrL3Y+0iQQ8brrwTjn1R0xopYvetO5pFTf/VUo+CPlDfPTDbLeXX7908Q9?=
 =?us-ascii?Q?fGUXkeeHn8EJfAH/RjKnBeRn3LzkB1dnYCeSov8/33HYy17/XYXb318S2Zk9?=
 =?us-ascii?Q?z/Wc3QxAyIiG8lzdKJ9uFSl8CxxG7Ihk3PzK4kaLXpKldJBjDfjkgG0VsWMe?=
 =?us-ascii?Q?TDFvV0RpRIwl23oBQfo9nHx2V1cwn8jXbBmhxe0/7bdcKB1aw9L5phOxnM2X?=
 =?us-ascii?Q?gFzt2/PPojOYARtvVVmehq/ufSkjNwkBaA/fB+3WS5zT7eAr//Z6gkK/gvh/?=
 =?us-ascii?Q?Nu0i6hVTQ+DFrIHDh3esOig4WUAk2pCR2tCV+ajogCivHu+KtEf69exOmK7s?=
 =?us-ascii?Q?i73i89akLbM50PeuhaUne7y1NPWlfs3tk1/i8v8lDWw6aoLuGKt8k7+5jT+o?=
 =?us-ascii?Q?8DnF+rqcx4hdrb4qn/by9JbI2pYKOg9z0dT0yAFffdCbcTR2VAk720kEIsTX?=
 =?us-ascii?Q?7WCF8DUfnS/gz7foikBTz/R4L541DsI8n2NvJSw9vzHsMGp3u+o1knJq3z/r?=
 =?us-ascii?Q?7A+fYp4YqiQeXPrpYZmT6ock+nKfLpbJAJxgl6MS8Ywc1G0VF+ZvSoXxqtv4?=
 =?us-ascii?Q?P3xWJ/DXvMjBa4PSiI1XAYvQR4sJebpvWadCisO4sovwoCXtSBBGsXWEmVgQ?=
 =?us-ascii?Q?ZVwzweTi6w9n5NaK7MEfTmOiH9jN5xb0tDcu0xYr7QvORW+cbkVyy4ohMewk?=
 =?us-ascii?Q?SiNZ+u6xk89isej1qswzbwo/vSsfuS2Vr59AmCWpLxlYTaHK3OUcQowinKeL?=
 =?us-ascii?Q?wgImXT80ACTt0SnjUnZ6oJW9FEbzn5KQ7XQbSCZXWVlu6+MXGIMEdNMK1+A/?=
 =?us-ascii?Q?D7iHKxtUQddrp5k98K/HgCoZr/fdd88I8zLapsSBoOI10eCXUIThivmfnDx1?=
 =?us-ascii?Q?U45EgLnW4RGVVTEpv7WHLZylqPv/WV8+83pnooDULFik5Z301BFvsunAYr3b?=
 =?us-ascii?Q?EW0iSMEDzxqWfNGIgOM2//ohkujm3BPV6QH3o3L+0SksNEgAzSiBtDi6ipSr?=
 =?us-ascii?Q?kAZKhaX75mQ4IWqwiVU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?vLw4ZdPbjyYUkrniaDs5V8BhJ8ypiqXNsmNK+cTcfCC4+MhUziqDaQ1aSCep?=
 =?us-ascii?Q?r3+mIBYLnBtvZrKWhGl+LxBH/INCBuqSyXPK0dqB/d6haFZOZSkkHI1YnHoX?=
 =?us-ascii?Q?snBVCw+38InNObyATAiM61gqkR+Nv9w4Tw2/tJZjRpqptAIw4HSMKkPKvtww?=
 =?us-ascii?Q?7RC5jsgv1tOY5VRPgzNje6epuNc7/fpM+u/4Dff07hvhnPEPLzdEUg6EOmU4?=
 =?us-ascii?Q?SY/o7q8NnaVDsGwzj+AuhoSkFSXLzJAgAhgiQny1nAZ8Z5tSblxYL4grrCgn?=
 =?us-ascii?Q?v6v5DxAktQFegk7cMAPhR0ruVmhIs9tdWZihPS9rwIIH+82LzdfPLWpLo45H?=
 =?us-ascii?Q?2uzAxwh7wBHnISVoSfWIMOEGCGqAthpmEjvC/HCdNhbdrBFiqH6ODe9s7o2y?=
 =?us-ascii?Q?pxp5oH+e1ZszDd2z5eoyH1dfxbPyTAWS2G92iWk7x1EGLwPs2soGkPD6idPo?=
 =?us-ascii?Q?0BwOUfIAc/4RGTYDuu8/lXUbJ0qMabsRzpJj7IJb1Ss7ZiUVBoM1wwNqLj+a?=
 =?us-ascii?Q?4rbQZ8y/J35jxkRYqVNdfA60HaX/7r/tzqM8iHgKG2jRXE81aKVi4z3qEDer?=
 =?us-ascii?Q?CF7RZT5q+LavhJHUQC1pu3/fqRhKXk5UT/f3YpZgGg+hpSZhd79ObDA/scSR?=
 =?us-ascii?Q?4+mhn5FuPYWSkdLpa944VmaZoSNfQ9rpeWC/X8+ZB0vNzVhOEVuRSdu59nFf?=
 =?us-ascii?Q?nz1k1NZrOJM4rrgofv4gcw70D0mohHxDnKC/8Wwdlwed3WatifD0rzhOJYOw?=
 =?us-ascii?Q?V6SK8kmvH5giwODyACYjiguLAlfLD0tAi7N0Zu67KeVLWan4+iMFTa0Ec48F?=
 =?us-ascii?Q?Z2nQpr9kMSmT6AIDjMUd5qxxZLQI0pIlIkpewMx6JG9riqlywlIcdMrjTTFx?=
 =?us-ascii?Q?v6lU7t3WK97ptbnCt2aMGvKfWi2A6DoemBQufVHmtLZ/Y5AjH/bgL7swyvIU?=
 =?us-ascii?Q?ct8UT0RebXtfLTDKryq9jIDB89xEMwsXgihnAqY1RjHm04oGzstCCrA3CY12?=
 =?us-ascii?Q?Dwayi0ECFQS3GK5nCxLxJD7iqaa/7YR+f/7LOgpLdLkHXz4vooa71hYGoeae?=
 =?us-ascii?Q?AWXMG+n10fITOn3tlvneAr6hfcHCYnBcQLcGtBqUP8okk8eppokN0SR0PVpm?=
 =?us-ascii?Q?zEK93oidRw/G+NXcwWxrq0lTxw3pMRkx0paW1OUfzx5xxBpV689zl3uVEOx/?=
 =?us-ascii?Q?fKRPaW55fhm9sqWDShY60DGSmPohra4oIisPeAgcf5PYrfV9F2I0IduxXe/y?=
 =?us-ascii?Q?hiFPiy1o8HFQhkZKbHLu8lvORc5aBjbpsphZpGPWOWPSkW/+YxSIvBwy+QEm?=
 =?us-ascii?Q?scxyv3a2TZYqhedMEBjvYxiWuCKlPxQJhjO8LDsRcjizXr85fnxDo3mpK2tX?=
 =?us-ascii?Q?Mi95kdMxSGFei8oUXC8qhSBiIINSz39kLof0RRbgBdK0pXLLyj8a0wCoDCAe?=
 =?us-ascii?Q?Yo8YpvrjL7wQMu+V8Urm/v4h3MpgepW+WUrReL1PlWhO/tE4VWNK98sFqBk9?=
 =?us-ascii?Q?p8L78RXITlBSb6WnlzOp/isoPNR+cjeLmjr1dPcjd+1OQUn4T1evp2m9gSTc?=
 =?us-ascii?Q?dtW+IzNbPQv9yaGaQUiG/YLzkVf+JBTt6v9G20Cyt7rhMHLrNdPoINOuBoi8?=
 =?us-ascii?Q?SmJD438aS8wfD1+3MibxlBKRZdrPDnjqeLAcRvhU5kPdF5JvwsYvUAfslC7F?=
 =?us-ascii?Q?pZINUvPP0Gos0sRaIuAVO50vrvZH15AKpTu16C78mcHRJ6wK6wZlFkDezzOY?=
 =?us-ascii?Q?BxGg0YJjig=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 3kMl8vO1p+OkCMwYUWJ3hIp2X/Lz055LcdRYWcMZn3GeyjDFzdJxzH+POkUr3ribOYuymg2Qi7hdmPujMSQHY59mI7Rek8UFzBq2Smvvkw6LyxHC4BwMpoFGBsdZ7Rl2F4dvAuXjRwl6UW32UA78wKEJs3aIE2312NB26icXoFeE3S7PFebXC+bsdVYVhgYqeqmURTz7dGKvhHXh7FMtU7J94+RxBIQ/wNyK+4dpUHqsQjcrZtpcDwknIjq/PqZJnIpnYMcgfNCWy2KNIZsZp9fyH/J3D3VWhrSla6sM8oFVb9cAE4wEYXmJLDa3F3ubWB1TN79EsRctdUkQpRNKbGwXkJoXaQJvOBhUximfAhy8IY0GEAcoTj2LRS394j62tJlMJmg1hsAGKzsVo4OWgPdFE/pUicSHTOB9D2gKBGuOEhmuSbdbItRplPIsQZDTOIcT3L23u3/eKtNHIRIjRSsqNdiCTe3n1gfD2WBI/6zaQIcRiRZUf5X6YjhHd7atr1Akk//fiBm3m2YTsOx4s8pgBUPLJ8cNSIQOV/bHyiqO/PdmdkvafWpuPSr8saS6XeiYfScHD+DQs71g5BHMz9P0eDT0+2UpFEJqlYiGLoY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 639274e0-de04-4064-5728-08de5f0c9bcf
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 08:01:29.4279
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xKwoENHYhUoLKM2gk/HAIR22ZyHkBbZatx0z7RFTH2Vt9FUWTC0Yt3BjRYjpN3YbgAS9ySPrVX7J0s3iN2P1Rg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH3PPFFC83155F5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601290047
X-Proofpoint-GUID: KK2DieHiqsguCy25DD_QWaAXuCqOb9gl
X-Authority-Analysis: v=2.4 cv=OLQqHCaB c=1 sm=1 tr=0 ts=697b13de b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=u1qovP0KQFmDFdSvR1oA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12103
X-Proofpoint-ORIG-GUID: KK2DieHiqsguCy25DD_QWaAXuCqOb9gl
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA0NyBTYWx0ZWRfXzrasCwSNH7kp
 ftUwSsIKZQfNsXUfuhioyZN/km2afZayJwWecq89ZaLDoYKdtfAhv70IwNy5JV0D3uWtPtdPVME
 gmApqLERrP7gIjQ5+ln8DUaqfEgAIJLqPnlOXdspZfG+nEUPrQzE1CvgxQW/cO9zynFnh22EEdk
 NUnOF6X2ARVqJl0jPZpSUJl7lO08Tvh+R4c68Q6/tHudlVuKtokRWePalAmroULie2ZatDm5XXI
 Li1PB3D+Vc146uNm8kf1Gvhw2bu0EKE2doEubz9tdxGM72akokq997xX4da7jzE0o+uTgHFQlWD
 aPLDndcV6/LrWKI1S1ML5i1/svAP8cOkqsm/RkPKxA05Yi2kaJREOVZWvx6+mti6kMf7jIV2HIM
 VDp/fklJ6NwIUpCPftfTX/rCuYhpatkdQmOwmDAEwK8Besa6/M1ZoNvLG3mFT0dl6At8zr0dvrm
 8eivGbKEInlVZ/TUQJpyHhDrZj2KSpk/WPnS2RMQ=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=W4QysOv9;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="d/E3U8lY";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBZFH5TFQMGQEAP2W6JY];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:replyto,oracle.com:email,mail-yw1-x113e.google.com:helo,mail-yw1-x113e.google.com:rdns,googlegroups.com:email,googlegroups.com:dkim];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: A0B14AD0FB
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:48AM +0100, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Introduce struct partial_bulk_context, a variant of struct
> partial_context that can return a list of slabs from the partial list
> with the sum of free objects in them within the requested min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list. There is a racy read of slab->counters
> so make sure the non-atomic write in __update_freelist_slow() is not
> tearing.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions. It supports
> the allow_spin parameter, which we always set true here, but the
> followup change will reuse the function in a context where it may be
> false.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 293 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 272 insertions(+), 21 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 22acc249f9c0..142a1099bbc1 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -778,7 +786,8 @@ __update_freelist_slow(struct slab *slab, struct freelist_counters *old,
>  	slab_lock(slab);
>  	if (slab->freelist == old->freelist &&
>  	    slab->counters == old->counters) {
> -		slab->freelist = new->freelist;
> +		/* prevent tearing for the read in get_partial_node_bulk() */
> +		WRITE_ONCE(slab->freelist, new->freelist);
>  		slab->counters = new->counters;
>  		ret = true;
>  	}

Other than the above being WRITE_ONCE(slab->counters, new->counters),
Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsT0FSP5IGCXxOt%40hyeyoo.
