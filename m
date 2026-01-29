Return-Path: <kasan-dev+bncBC37BC7E2QERBL475TFQMGQEPY76QZA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2I15G7IPe2nqAwIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBL475TFQMGQEPY76QZA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:43:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E55FBACE14
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:43:45 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-45f0bfd68a3sf1162993b6e.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 23:43:45 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769672624; cv=pass;
        d=google.com; s=arc-20240605;
        b=K4NwGBSfo1qnEZSsxww+b6Vz/Uu5MogA2RMHPLyxfV+OvSaTFdId/n9TMSFePT85GA
         /19TnI2MLeD8A4Tm3oIAxTn4dq+VpPDxCaKnT6pqMa8XPKAuCwCHA6iIV5JbL66uRAS9
         8ffTRzApX4QxKvyawkBhg882VHuaGvhOgVEmriYrAWxGXxjm2CxsieZOPhoq94TZI64t
         IXZ63sVkrUqnT0Pk0FaOcGNwdDK7VrQ652xSY61u6k0r2wU0FAHcaoOd9pj/0yLIkxi1
         OKuhu4qq9PJk8sH5vwlW63fTR3xIJj3D4mKXD1Xg4cnbH7kB0yFYL8bIluUPC6O3Het4
         Lpeg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=vetvAmWcSnF21ZEOrAB6Ypn+5K1PwJTgaoevggXRGqo=;
        fh=1I0XZMtVObWlREZaWXQ/lQ34GnoE1/y0X5HzZuVHcnk=;
        b=Jr75u1OAZYQczIt0taNdihN6XaQZy0eFrjF/JDC7/DkgykHp4zTguJWXwWJSPubpr3
         RYMT8+67DDfQXOVpWhjSX0zQQWfV+2d1M2QLUy06zZAOhpVrIjRsumUG26PkvzZ7lUuW
         L5DW7CPiGp/r2gDJ6E/Ir1KnIaN5oyEImRR2FosHBEj9kemyf9WqQ1cWMTVdl0GPJmHC
         hQxWl4qJ+Nl2cUy6NDmTnAWCPtPHJYPlr1sGR7saoDxWUBQas3CaDbg6src1E2V/Neon
         uksTRNvjQy8RmXLu2dAQZ2BsD8xmGuNRnju09Ovx/Ak1bZLjsrr89Jc625jaMDw/1CsA
         ZXMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CZB+KPsQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=NQynkKbv;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769672624; x=1770277424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vetvAmWcSnF21ZEOrAB6Ypn+5K1PwJTgaoevggXRGqo=;
        b=TcRpgFe2yvdKL1sK1iY8SZqq5Q1fvfrVVmX3yzgTYeZTsvJb770mLzJk01TANv/azc
         Xme7nbsLxq5Jn2H/+xwZpFqvAnVc4jPc85WE5mV5y7mpRpOpvJhSyLbI16Ec7hLgd/Xr
         mKGbLSz5W4aEoNvoh3Ws0z5KJqjfUP7wQbyW0F0hp4pQmPuzXy6l7nzKcEAFMBw9aXBa
         aS6AGI+A/ZMGnbFhmo/54IvCVfoQJzD2pl69Z/l1Th1m7B3u3pfD++MsEgShXMpnlfDg
         HsTtNxZjyGDbzP/psSYgjVcGzm5pzifFB3+k4yHAJxL4HTVm+BW1TFSZzNoE6EYb756G
         xogg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769672624; x=1770277424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vetvAmWcSnF21ZEOrAB6Ypn+5K1PwJTgaoevggXRGqo=;
        b=BJr05xvJb9qxPsJNSZ5NbxgO7U4mYyL5n+dzzvHaIPE0CwHUgVECW1BoEv1mSCo9oZ
         sLU0jzjAMVMlYY0iGW1qbuA6scIT/U0eiSgAz/msk5Z6KnWhXubQ7vuGSG6quVeL+S/k
         Nj8RuSN4SBEp3ToYjECm4XMWStm7a+oB4ShOJ7EMu4MaejoclgGVjCDfZGte0z05LkYD
         Oz9xm64puRASsKgCfoXnNQRscZ+1BCVE9yYdnMQRKo2MYiVQUVOrYWN/fFvJtyqsDx+R
         6Et6bHT8uMKnMFVumrjlIJDu7EOkmu2qxDT2lCfDt6KjMXliyM/wL6LY+5dXF0DHfbrC
         ncGA==
X-Forwarded-Encrypted: i=3; AJvYcCWGCFqKL7Bo4IUn/vnkJsL5xl1UlDIf2tbJgF18jaoWCgsbNj+AWEct1cCWt4siGjsvpuVMkw==@lfdr.de
X-Gm-Message-State: AOJu0YxxNQAvVQASAh7O0hjJKmG3oVuEMq1uNjYLcboHx+TJiV930dNp
	o/sqlogwUrX2uUl2Ct+Wkjuay3rrmrCiL0MiHsVVOnaidZUY9mHQVWcr
X-Received: by 2002:a05:6808:1315:b0:450:471:b9ba with SMTP id 5614622812f47-45efc5ba406mr4462980b6e.14.1769672624096;
        Wed, 28 Jan 2026 23:43:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GEZHFQDURY/oPIfGaYYmz5GnFLic6cC/oq8uZESKPriA=="
Received: by 2002:a05:6870:ab1b:b0:409:6d31:a4cc with SMTP id
 586e51a60fabf-40985b746e5ls224946fac.2.-pod-prod-06-us; Wed, 28 Jan 2026
 23:43:43 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUX3IrhvzhSK6yFxikmgjGWWWyrwJYmDMPC4tqVF8ezUymmAQgwuvhhektR3vyjLxM4rgL5qoSeYM0=@googlegroups.com
X-Received: by 2002:a05:6808:1507:b0:45e:ecd9:ed9f with SMTP id 5614622812f47-45efc5f3aefmr4707579b6e.21.1769672623141;
        Wed, 28 Jan 2026 23:43:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769672623; cv=pass;
        d=google.com; s=arc-20240605;
        b=dVCZbWWOBWyHbdEyWlGtFgrRYqYECMKsQ2K6E7wQ1mU41erlL/PMC2eVue904kWIoW
         TdV35EPYn+k6TR06W3NyQWFQvjUxX1x2U9mEr+wKz+afUSd0LXHl0eh+Ry6sGnFN3LNX
         NtTNkctYR79uNlsBq7UhMOpc0uDvCJ1WwthdZd8LrD7mFVA3f+hGl2L0IoJratAs0Vlt
         G0KLMsKvkL37xXTY5e1XJoiBqTHjmFj12lrZqlvavpOfAdUM8a4X8aqpWEK3n/ZufkpK
         awTM67utLQuOGwNMk+8xXAT/VCPdC9Fvarmcc2UtNE/SUd7DFQGgxOlJlcmoWLb77/NL
         q9Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=HljGyR1yOI9nu+nZJlUT62iXw4lQqp3/PHg4UpbUiF4=;
        fh=jjFhQZomXq5YJvua040Aho4GXsn3+0pYnTfY73nR5cM=;
        b=dCqQOxlOLim02HflijcyjtJ7TpG7xL0lQW5TETLGPNXkD66HMdWXTWX/wyfWbPF2AM
         a+a30f0gxwZTEcDQZm4KGVBWq5GIa2oFQ6AjDn33X9Fsq6T1/z6kRtmRsa06rwil3dtb
         BjTFYm7VztjaE2v24qvE54bNtCWvmotnLDWmsOUBIuMTvO6srwxGlB9+cuM0ytGDf0NA
         eqaDh2I6iG/V7qBXU3xybJsgFKdwLk1TR+xJh305wpeAiPdvvglXMGaRke/C5IUpJZ7W
         Pswv9k5rNwFfl46JYkGZK1evMzx9dmM6RIpZ8UP0WEG+MnYKH326kUy2KhUEycvr0oMX
         z1Zg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=CZB+KPsQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=NQynkKbv;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45f0901bb6esi122361b6e.6.2026.01.28.23.43.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Jan 2026 23:43:43 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T1t1E73722958;
	Thu, 29 Jan 2026 07:43:40 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4by2vgjt6w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:43:39 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T6vr8d012130;
	Thu, 29 Jan 2026 07:43:38 GMT
Received: from bl2pr02cu003.outbound.protection.outlook.com (mail-eastusazon11011028.outbound.protection.outlook.com [52.101.52.28])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhc14y0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:43:38 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=jeJVrq5xpyTHJSmfgnP2Vl6WagWeKtC2u0ykD493Ct1gFBjX8hgc84Tdc7eMuPO1JNgyWHJSEf4kKOzx8Lhz9S3O6SO+w67DSajMUwArMSJ9v1CAnGB9myvd4smhDjq0LMzhbi0lTN+eTFtXAzg6MTgNgBb1psegKF7OH4J+lU/nvIt0wrmMQauSoqwk03ZmocoiDjxfFUHfRO+xvA0wiiVOWet/t2e/pPTrW7tGhF1afvqK90BekIRStoYd2fAjZAlMLrQnMSBocKxUFq2qz2WIH1xaG9NamHn2VvILghYXDu/TQPqWEHJ/hMIcr2BNDQtWC/SDOgFlHpUagMkWMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HljGyR1yOI9nu+nZJlUT62iXw4lQqp3/PHg4UpbUiF4=;
 b=OPMTGxNOxVupqYmRsLjDTb6xbqIeZKWu7Y+hmMbpcHnSLQjrxrLjSOrbXX+U+4tTv3tCDvMhbmzaxmrpkM035F9Z8MDY40kHJDoI9HqLJ2f90TJshV19wL1rTMV/ts3ylVYn5ndHyMWGXt45eovINb3X01TUAHOgzwvizHV0zdSA1oNJvEV/RW914VxS8lGE/Vw6AGz0I2sUSsF8l9lP3tcu1ruBBp1iNjirW7VWmvv1hUL0dcUIJwQewcKjc7QroqqQVT2XGEUAEqge1UJSVvT2bLZLEW52IP/MNAv58AedUDeY1GLCh2roF0iyIVA0yOA2KPqUwfsuBy82WJcjtg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB4623.namprd10.prod.outlook.com (2603:10b6:a03:2dc::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9564.10; Thu, 29 Jan
 2026 07:43:35 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 07:43:35 +0000
Date: Thu, 29 Jan 2026 16:43:28 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Hao Li <hao.li@linux.dev>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
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
Message-ID: <aXsPoPXvAWoSizCq@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-10-041323d506f7@suse.cz>
 <jgmmllqopl4rpihfe4jdnuifzexlffef5gehsocdcdu2xdj62j@xuz56etxseza>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <jgmmllqopl4rpihfe4jdnuifzexlffef5gehsocdcdu2xdj62j@xuz56etxseza>
X-ClientProxiedBy: SL2P216CA0195.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:1a::11) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB4623:EE_
X-MS-Office365-Filtering-Correlation-Id: a6c91df7-d3db-4edd-c41c-08de5f0a1be0
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?X5AhYiOAh8tRTbadKcXwL0NSFMZuHNkOe63oEd3SL1dNEXSGdfKTknUpav2i?=
 =?us-ascii?Q?UZ96Gse152x/N51oEkYhgHos9yQtvVFmGw4nxm4mRrTJ5v9G0OI9Srr3AgS3?=
 =?us-ascii?Q?3H7QcYgGacrOGOvR1JTiCJzsaXdpUGrp82KOZY91qPB6zz6U3xlCmcS5RKaa?=
 =?us-ascii?Q?HzG/oBuYQnlqvfF+4tzqbSCPlvYG1nAYvNyR6peZiqfRja34NExOBUyrjrdV?=
 =?us-ascii?Q?NvhVbqWJncYBjc4VKXAoKy4wiLzXv/gma1ZjroV5hyvuHI1rxseHvW/eLcwA?=
 =?us-ascii?Q?rs9ZSiigF44UPoO4C8r1wOpUxsK65wpUw/rz9B5naNLCE81eUpWCzUPGX23+?=
 =?us-ascii?Q?Iiz8kqr0rp+mK/GBm44GSO6MTh/4OTHzfXnVd3wrX8OXNQ6cjok0K4V2Mtxf?=
 =?us-ascii?Q?GEjskB8fOTN3Qylkx8+eBiFmZ7c0R/vOmdy4uS/lt7pCJjQ9roX5LtqnjzYZ?=
 =?us-ascii?Q?NKhjiMB4ZYBkjsY73apo9yb+4slG/FbFBRjUw7tG9Mr1QsA7zQzZ9KODQLvz?=
 =?us-ascii?Q?g89kmX1qgJjEFM9YH+bzByzTSJwtJMub7+LXoC4rl3xdQAbR9zeVxYqrTHAq?=
 =?us-ascii?Q?XNksmNzpakBrcIaP/k9Q7MEPCaktFEVyn/0swvgrdqF/RSbygRGZuZOXMpGv?=
 =?us-ascii?Q?ry3PAkzHgTSZ/F+qLRodlvv9VCLAhvZfZoDu0VN/qY27MUmwSoPEHmoNRMAp?=
 =?us-ascii?Q?3f5lpV6UvC+zAAnUnUsIFJJLveaWWwaTq0F6mBjKGul+JgW2uNrAeDLegilV?=
 =?us-ascii?Q?b1sgKFf2xibYLCeK8lHop/8HJwu6Ec8yb0rMZT6hPLKf2MddZ/HssnJA3wze?=
 =?us-ascii?Q?nFNQuGCojOPatE4aEiBCxEovD0iu2R/ibjJ35soAwZPb2lqsRn4rqAC8sPbU?=
 =?us-ascii?Q?qrqitzjS2zGEG1A9ZLbYy6VkXDtg5Xy0T+yUafh/TVEizBvoS7Pv+lwFizFl?=
 =?us-ascii?Q?Qc2wB791YYLPHcfiM7JW4R8PZ5PwLisAprHHiTOoLvWXKQlpk4b+0srbJtvd?=
 =?us-ascii?Q?+3qbDqWDyd71E03iGaNIoaGSOjnsZNU22viPBjZsj/g7uXfM0pY13bCUwbKR?=
 =?us-ascii?Q?br7ZPFKYyDlzXdzyZDYR5g20dVQw9Hadok56/4WvMOmklATFAJqGaE7CS+/S?=
 =?us-ascii?Q?J/akfo9vTSvL6Z4SIZfyOdsQEp597GJZIu9AKBL7paol+llLq4IEHgcE1E1i?=
 =?us-ascii?Q?5/mvlDWs9e4H2B8l3vG1G8cvTEqUBOaehCDiVyzDjOGml51ER8rrmRX4y8mT?=
 =?us-ascii?Q?qnli/le8E2O7vZZmzq79Ep0TOo8A9ANPX6+kB2bfImxgEnAz5Rq4jzMZHxdS?=
 =?us-ascii?Q?nwy1fmCi+eGBgdFXQNauqF9ZjE2rpv+jg9Rq/tuNBF0YdTOITyUdZglhuRBV?=
 =?us-ascii?Q?aYDwXic/nWoa1bfYTg+7pRUmROoXNj8ILA7ZCZZwE4AsBlWJQMccsptXDRvQ?=
 =?us-ascii?Q?NGnI8LZv4CMbHuC/qWmxJvN4rFPn8yuyoOWRLqq+1SVtAVyrlkHEZ17K2Jk+?=
 =?us-ascii?Q?xqDNd85D506UVO+q/j7FDL2hzdysfEoRbLA4b9c7tM3EUAZqcEzMqsRhwOaA?=
 =?us-ascii?Q?1Jb/OdN03RGNhQpYvDA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KCOip8WUEXOBAFLjAzGz26JKd+g3AlApVuvDRQthTodR+B+EjCzSX0gz3SJI?=
 =?us-ascii?Q?AlumIgwFK6Rvug2HIJMyW7aOQMMqlekoqsfdDyNad8a85GZ9gDjyLPzQcKZC?=
 =?us-ascii?Q?z4djq1N779H3WzNpk+sAcdmOqwXh6yyUFuOIWS2VseuOq8HCwt4vTbMCLERC?=
 =?us-ascii?Q?veQRlFiXb5NwfxEuE3Fivm766uRMk2HSmt7yrlGjsF3gqWS7agX45L5cXhRQ?=
 =?us-ascii?Q?21PPmTGKXZHKc5WaGJN+69x3rdr3blKgvCttHFPFrpULORUlpq0ZM2tuORZf?=
 =?us-ascii?Q?u0k5CBqSJDjsZpiQH8CQJO3kQGZ4/ioNelagiDO/YZcyiVoXOzbKNVT7WLbT?=
 =?us-ascii?Q?8f89bEeUsIhHiZ9201IBofN2EGM8uKtKwGBFoSguL49osyd1orrMpXWSQzOt?=
 =?us-ascii?Q?J6bjllbJ+WqK2HaPUlAXZGMy/OGOTHtQA1lSlnEFimrneOG4tAxjcL1jjmSP?=
 =?us-ascii?Q?JQrVV1FOnG0O2xkv62G6+OFKXFpzStNKLYtorl/5BwlRvnmVEudokY89JW12?=
 =?us-ascii?Q?FRu1sScaPhmQu9sopjACvGiyQ3/ljJmQ0Ox5XR2nY57BRWflYT3A47QR+qDz?=
 =?us-ascii?Q?uJDYkf0LPRKyQ6oRHqxTnixyAEUGLtTIzW5VB5n+FLPi29KtP8kZA4lria4x?=
 =?us-ascii?Q?ILAsGuMpDubNIY+Afd/1Is2ow0AZNFABxiNncNNaSG8UTvm8NOqLHvOUcDfk?=
 =?us-ascii?Q?SV2LVy2brCfKeyJBTXjIMev55bkkleuzN+R7iaVZQ+kdGoD2lfKMH1wRUmL8?=
 =?us-ascii?Q?hqpqWwkKSj+Hay/2LCZxL1oa3bm8l1TciYKzGDCRws9wYGS/XMGR9SzGSCHc?=
 =?us-ascii?Q?YDEwNoQLo833bhZXbMl6kSEg+LfpMbBSgITmPY+QSDhMKlxUgQRQNDBMISMP?=
 =?us-ascii?Q?z4wEvA611r/bfTQy29YZQgWP7VBuLriqAdJIfDiHiwyXaorflzZPKfidq1Qq?=
 =?us-ascii?Q?7/J7G99D4sGBeOTadTABGzfdXU+s/9BNCzznvsUs0HKDIppXgBdz2v/3P5aY?=
 =?us-ascii?Q?VPhPsOW4dATsrYGtTdsZbEZEUegPADCXqA7rvcbGQIEOdzyLErg0k1kbMEkg?=
 =?us-ascii?Q?Yh2OHpidvJN1Iyp70xSz/Vcymxmq6pLdvw3iYvq4ZL+TEtS12i2ifJBoUpnV?=
 =?us-ascii?Q?TmzjpTfURgaK79PmnC4UzUn72fABFxyKkjFqnvtmuGvhwzE/Vutv1KBkscMc?=
 =?us-ascii?Q?4aO13oFeKO9fJ+AqP5kMIdTf8sdk8mxqzFqGMsEn9sOg9bgSmSXN5rvp3HoW?=
 =?us-ascii?Q?0pjdixvuuCgVbAWd11ztKd0Q5q+7XYeO0MJdzH0chekYzH3rT9EtycEn8hvw?=
 =?us-ascii?Q?x7TDR13w1u1KTBbDnlgYbT2Q8vjLCZrmqrXOCqiVxfjtls/ATGQkMHgHk/WE?=
 =?us-ascii?Q?sRv3tGKKJutFiC8zmU9l0gQEmG6HxFz5/iISSeDKtaPo3W99D8Upxm8KTnjN?=
 =?us-ascii?Q?qCNYHzQ737E+VGCesaN7ysCrIuqOyEjuf8VGhQ19URNPOYqjCxU+ucEOgijT?=
 =?us-ascii?Q?ZDs4REnEnq5I3FInrZA0m4HyWHq6M4YSGMQESXZMsrPkY8lARH+Z4TXdRA0S?=
 =?us-ascii?Q?heSAXfn6UtpzaDsSZvIuJMCK0njmj7VHW3eMmK5Hh0rs/A51HpVaWsNKLz33?=
 =?us-ascii?Q?pLcwKLQTB4Ack2OM5ifyEPY4iDpxlJBS7RP6KS9an3F4FYqMR+JmKmBRY+Hw?=
 =?us-ascii?Q?lVtjiyodapdCGRnpifv4nX90R3fOrN5DRUglnZG+Ma6e7QWMpAMT2ICYVgXz?=
 =?us-ascii?Q?+wwdc38QUQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 88p3Ut9l0xYFv6psCjP+pUHNaqSW8/I23rh9dwTWdcReOxgdXne79pPOJPzt7ha1aMrEnJyGdPLn/HeQxd6uLG+7+W74IyQNTMYWtm4gZTZoEm8VFbQsoa72rYPWSQPCLo9DbG8d+sNVQ1jBRu5PI9i+zPIWoLXXtwiR+/aI+DIXvDobNG1zNaNE/FnEnPYp31sB4Qdk9d+7ALBxuP3RhfZJ1yq1N4atrbmQ3gJZfF8iX0t4gsIDsLmGOfE2W6G4luTMVltMGemWe7A0krOEKk8Dn/lnGDrSMx4MnlB4AOPLqkNpNzBWI8/yLabjfW4w7+SouMRFLZ78cEvpP10irrOl4F0IYjZ/v03jz2oFo8uWTYrlxSoGTj2fzratTI+lKm/scIZmer0KZYYsWlgaV2DJ1yjeLUKeRng8gBhGgnWJIytqTMgWsjgRQwOcHOpAP/butQanvEVe21NyE6kf8v/RvweZNeKXeLhC99X0Hk5G2g2LSbO2CY+ldYUUH3omhpG8mvGkmLehoxhhHGHLulK1d8+Kia73nqrexy8IkIcNyQ/GkOHuV7xOR5GYfbKDhaFstEjsq6Zidweo9pL9+w1ZohnqASawN8ORfFGvBKQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a6c91df7-d3db-4edd-c41c-08de5f0a1be0
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 07:43:35.6115
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: cVJyltraP94K4GKfVe+3YiLy05gdkl38wrKb7ITiTwZQj4MhcgJE9abHqNewCFWw2wiZ9FHwEno40evGIPpmLQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4623
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=950 malwarescore=0
 suspectscore=0 spamscore=0 adultscore=0 mlxscore=0 bulkscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2601150000 definitions=main-2601290045
X-Proofpoint-GUID: Tzsn0SsPRWjQ9EaE15ePwBCNK662YL7S
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA0NSBTYWx0ZWRfXwW/Nbze5KLOZ
 iP2S3b5uis/AdaTXywXZNlfPmyE6ELfjl40VX/AcyuY1BoiHtZaqz3xZEzM+cGvwrI+NXnFH/Gm
 gWLuAezdutbZ3bJj+N/29uZUpa8sMv4g1TMhTu/y3Drms5scjnrGrHsiDKKvLRqrlfR211IgVQz
 vzD86M4v5Lj9wQqzAOs9USsw0J51/J3jwAqTjtNXTOB29dMyUunJZg3YqBDqR1pR6w7yYl09n6A
 kN+G7O5zKRE5W7BR0SMrm0BytGc7Z6qm+xGD0sJnq4osVkZl70vUtSMXBmi51LtH+GzkRRUsWuS
 aUIKh7DBCbURlbuUY+AKyhTC67sUD+RKT/fGpxw92IIp4RUJQgWdGCTB9LBaP/PNj34P0EwieiI
 4JrduJsGdEJgJ0ThsHDLVEM/lxNWcmQsQ0ZrqPvpoCekeRueefHfUEXmbFiLpzJthiivlLxcACn
 4Q5FFFzvsUe78YN9sgQ==
X-Proofpoint-ORIG-GUID: Tzsn0SsPRWjQ9EaE15ePwBCNK662YL7S
X-Authority-Analysis: v=2.4 cv=a7s9NESF c=1 sm=1 tr=0 ts=697b0fab cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=xTB-ZrKxoltFZRK_9CIA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=CZB+KPsQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=NQynkKbv;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBL475TFQMGQEPY76QZA];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.cz,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,mail-oi1-x239.google.com:helo,mail-oi1-x239.google.com:rdns];
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
X-Rspamd-Queue-Id: E55FBACE14
X-Rspamd-Action: no action

On Mon, Jan 26, 2026 at 03:12:03PM +0800, Hao Li wrote:
> On Fri, Jan 23, 2026 at 07:52:48AM +0100, Vlastimil Babka wrote:
> > At this point we have sheaves enabled for all caches, but their refill
> > is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> > slabs - now a redundant caching layer that we are about to remove.
> > 
> > The refill will thus be done from slabs on the node partial list.
> > Introduce new functions that can do that in an optimized way as it's
> > easier than modifying the __kmem_cache_alloc_bulk() call chain.
> > 
> > Introduce struct partial_bulk_context, a variant of struct
> > partial_context that can return a list of slabs from the partial list
> > with the sum of free objects in them within the requested min and max.
> > 
> > Introduce get_partial_node_bulk() that removes the slabs from freelist
> > and returns them in the list. There is a racy read of slab->counters
> > so make sure the non-atomic write in __update_freelist_slow() is not
> > tearing.
> > 
> > Introduce get_freelist_nofreeze() which grabs the freelist without
> > freezing the slab.
> > 
> > Introduce alloc_from_new_slab() which can allocate multiple objects from
> > a newly allocated slab where we don't need to synchronize with freeing.
> > In some aspects it's similar to alloc_single_from_new_slab() but assumes
> > the cache is a non-debug one so it can avoid some actions. It supports
> > the allow_spin parameter, which we always set true here, but the
> > followup change will reuse the function in a context where it may be
> > false.
> > 
> > Introduce __refill_objects() that uses the functions above to fill an
> > array of objects. It has to handle the possibility that the slabs will
> > contain more objects that were requested, due to concurrent freeing of
> > objects to those slabs. When no more slabs on partial lists are
> > available, it will allocate new slabs. It is intended to be only used
> > in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> > 
> > Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> > only refilled from contexts that allow spinning, or even blocking.
> > 
> > Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/slub.c | 293 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
> >  1 file changed, 272 insertions(+), 21 deletions(-)
> > 
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 22acc249f9c0..142a1099bbc1 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -778,7 +786,8 @@ __update_freelist_slow(struct slab *slab, struct freelist_counters *old,
> >  	slab_lock(slab);
> >  	if (slab->freelist == old->freelist &&
> >  	    slab->counters == old->counters) {
> > -		slab->freelist = new->freelist;
> > +		/* prevent tearing for the read in get_partial_node_bulk() */
> > +		WRITE_ONCE(slab->freelist, new->freelist);
> 
> Should this perhaps be WRITE_ONCE(slab->counters, new->counters) here?

Agreed, this should be WRITE_ONCE(slab->counters, new->counters);

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsPoPXvAWoSizCq%40hyeyoo.
