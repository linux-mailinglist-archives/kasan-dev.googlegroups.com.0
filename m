Return-Path: <kasan-dev+bncBC37BC7E2QERBWNOXXFQMGQEWV6FT7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D2FDD3C506
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 11:22:19 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-8c52c67f65csf64030585a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 02:22:19 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768904538; cv=pass;
        d=google.com; s=arc-20240605;
        b=jl+/3ASy+vnoFMHjQ75mxg8+cy92H/5Ixzz3LRGiEXnkRlNqhpWQ4hGLAEhLsTWFZL
         yFPM3AZbreiuALWBE4LISCp9pD1FvYw4CnwfaodQLRLB28MNW8YB/vnNwxB70iCtP6pb
         7wN25zZM27uiyzu1WZQT+eFBDCG7UuE8CbGn2Uz9r36+kpkonheTuIiD4MxnA1OOrVKW
         xUn/QBVy6Ct5XSblLKM27EjJ7FE0vLdqJXP5qqk3CAYHYJtvhBLGawW79O/UOlGkj83q
         3eTyYScu9NcxvDAKhU6oECue1hN6uaS0DDlLRvLxCiLp48vw1xOUiV8kiDElegHxBA5v
         Y19Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=LhpEM+SP1ZUnSzyD6dlTx9yotFEZCbLoeBdcX5/FXfE=;
        fh=EmSBEnyEZK1+n3mVkTo//Z25PkGhi1N09v6q0Y5He2Y=;
        b=ENUA1Qfau+B22igV1vgOskLxM8baLSh5EJh4TBtbt9gAt9q/oE9XjesrfEDkJA6BEo
         qx9hFKtDHOjtokk42VAJRuAVAUfxUPflEtVEUnvzLcNpgJQVf9Fy5KuV3facB8zDwHen
         21rH3KHy2qKrMrXzEgJK75Jyc4MAgP15JJ/Bkw6FhVOpw7gMQDK8UwB1jIkS7XiQassS
         0YxZqvo7i2dUQKv5X4qAxjE7RMXevTkWdrtWH1nHL3b75599z36/t0iBOT54antJZT0c
         f+8JJUn1ynleWzYTQ7tqAIW0fpdt68zkuXesaOLLtZgczernBurLzSex6EItptSu4Uhx
         4SqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=lhfF5caj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HHdhBT68;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768904538; x=1769509338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=LhpEM+SP1ZUnSzyD6dlTx9yotFEZCbLoeBdcX5/FXfE=;
        b=rO3iN7XQzl0Ojlt7jqvH3qt1qKOcXI2kYZ3mu5ZDg88opW9iqlN91eMilCs5deaWmB
         nEZeV4Rgn4NALPoLE8VaB769r+sj+wpsdFievnvFGavB3s0aWPjYVqvP48luDK446YKI
         MV5/hXZ7YlRrWOvc/lWkBXC5xE3z+uj7+ymQi1J7sEd99XE23/9eFothc4gnmOm4ju1r
         BwxybGE2Xud6n+yvXbu2bVFPY3nmAHZimGMiaDL6Bx25bBVPE4JQrW4eoiBY43FlAs9E
         bN1LmGHxiI6GirguvXpzKibf4NC6jJIK2PgixR+q0zQWBnMShY+5xcsERpmvhuqEbqlK
         Z0cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768904538; x=1769509338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LhpEM+SP1ZUnSzyD6dlTx9yotFEZCbLoeBdcX5/FXfE=;
        b=VCOLsTf4Mavn7ybkKgivIVuPaEym92oJqUU7gxXTdC1Fpt6eUOXI4oD2AAG7hKniqF
         FqvwLCSJ6l8tkJxxiH1QpB3bEyAnIjtW7yoXpiYSoMdbRLjTBmt55VSV+2TsWxxLRoAV
         5WT+DG3I2tlBWI1Y24uc+ztrHxpx2TO1pu9R+/0CSApwGXdQDHqPTX4ur6ER2mfFqLbq
         H/WtYtSL+VhgqkSZPY/xTpwhb56xBhld42ujV0HRJyqA8HFUz3ZM2gEgncgOrkNMT1IG
         2WXVkC/3S/A3GzN0SDdx0SSwnvIqOuYbrYQZzmAGyEUFX9GxQ2dXulWgWVetoGSnJd9b
         W8OA==
X-Forwarded-Encrypted: i=3; AJvYcCVkv6MMQ3/YdHf5XZtcJo8bIQFWw6lO5WtAoNdfgp73z3ErmLHQ1hD9KdgI8G1eaOW9wULX5w==@lfdr.de
X-Gm-Message-State: AOJu0YwUYeKgrN9yAZuR8yQo6qSrCdfXAsjtC//oXKipCZoeCLmOuE04
	G9HoryA9XnOQQD2MK8qwyQarYcm17DMSmNL/0idWy1SSEMQBRY5HbYgU
X-Received: by 2002:a05:620a:17a3:b0:8b2:f182:694e with SMTP id af79cd13be357-8c6a6945228mr1801470085a.54.1768904537801;
        Tue, 20 Jan 2026 02:22:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ENquce5q4iRg92Q9Vu4cQ+1X66s8ypNcPGr3igY+ohvg=="
Received: by 2002:a05:6214:e43:b0:882:4764:faad with SMTP id
 6a1803df08f44-894221ce34cls101561326d6.0.-pod-prod-06-us; Tue, 20 Jan 2026
 02:22:16 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUujsUzVF/EzAjsFFqiTlNPvHvPSRJhhBJoQLZVWNJ/JtfojxsbUSqSUmieNlbImLlQILYUmUdWp3E=@googlegroups.com
X-Received: by 2002:a05:6214:1c0d:b0:88a:314c:28bb with SMTP id 6a1803df08f44-8942e45e694mr201161666d6.17.1768904536679;
        Tue, 20 Jan 2026 02:22:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768904536; cv=pass;
        d=google.com; s=arc-20240605;
        b=G5E3dSmdU7sgtA+kq50yhLp5asmV8wOzjEGhYWBM4rXq8gEnAWIfcwb7+EKIQoFwHS
         vWS8rO/xSd6lxX+ubQ/2y+fQwXXzUwWGijMZF0faqPqKqZM3nOk1dWbRzxYZMazQ3z3X
         EvhdYRRDKXy4CNmMfgMpHl4+QIx/43p1WA/bjfDqFNGfdpo46k2B1cUDNMTCGagKqv3c
         moeyXXaIfbLdLaZBcPOIA5k7j2hz+fGkK+GI7INs78j3ox7s3e5H0JXnA7DaABLxdEmn
         +FWzAbi943ymueyWBQY5DeeJrOyUZPird42wImNeB3VY2+A67KlE8zgjPkhPYLAafW0Z
         E0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=lJSOJC4YGhRsBaqmtUxhBTiqOUwITQ0rJQXeAW7i6rA=;
        fh=jjFhQZomXq5YJvua040Aho4GXsn3+0pYnTfY73nR5cM=;
        b=XL0v9OSjD9q1VkRDLn5oAtvleQxFZ9VwhlP2cie5vJmAXjibYkS16MA/OHhobomU+Y
         mKXBakWzWyayZmsxCjVKpuPvF23CC276klUoif+jz84d7SzhAdRUZKlTkOdB3r1PirFI
         vpoKcJLt3JYA2XnbO2J26SKqPa8lpgM/CEEGnwCrdNyhAbds0/NjwQc+3K8Xgp45R4bD
         u6F8FL5IygPwtrTiGobDGsQo86ni1lpYwwpS263l/SPwZLwJv0ojWlkygg2iQsXIT17K
         HT6YCqLyVpZRzLprcPYT0RoTyk7KBWRqYUyyOtrMghCrOgoxIee3M40znbZiquf9NcI1
         n8XQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=lhfF5caj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HHdhBT68;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8942e6a673esi3486826d6.9.2026.01.20.02.22.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 02:22:16 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60K7uv0D3338936;
	Tue, 20 Jan 2026 10:22:14 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br170bffy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 10:22:14 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60K8hqnV018024;
	Tue, 20 Jan 2026 10:22:13 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011056.outbound.protection.outlook.com [40.107.208.56])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0v9e5tc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 10:22:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=AbySoN4iyD2SX8eDeH/m/V08dypVXPpfoS/Dd6NgOBhpZhk/O40hC2FOD5f34qAvLPCIPQGevCfrM6bt5kqMrbH/euQccfylAti6dBo0EFI6WQq7mCohnFbTPMIo0/K5CWzpmxvSlMk0U1L/vioAaCRtEEjwH02jQXWsNe/XiZ3bEjRavzBRzlX5JmoJKWKLkY2JmS24mNZoLjVNBWuYKPz6f/KB/tq/F2djmfvrdysF6SkLk5kp58dJsqqte52hLGqaZQ/hsfrnejXzLYHmzyI2voiTY+bDfQfH7BK0H8qDBJA829YG+wBTGZ8RrsXeKudRhyJVSXAFxLFrjLot1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lJSOJC4YGhRsBaqmtUxhBTiqOUwITQ0rJQXeAW7i6rA=;
 b=ed1v59l++0PDrrf5aRsT+5A/SaFVkMiaT3ML4VBB9XymT3OoQGPKdqhH49hSusXJg6Vmv+XS3IaPgiyTo36BJc4JgxPfEh3jO0KLtcMjkOp020UFS45BJ6/KeFLpaTO/AVoXONMZqKslsJMRFpIDNFitEzMq2zv4g5voVK5tbg7qzfEEN30fnoiekEwivNuRfulNJHmTh70Uf/tXFqnDou7rXDxzQ0Vf5NwwZuHWNuMKy+xkUvZ5D5g62dxFKerGG7YycKbW3nG6M0VypHq27JA1ZMJg9XsP69+t+AtlRV9A2RupQj4DtQtPpwgV/sCGMXroIvs+I5ogo4psvo1F2Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SA1PR10MB997653.namprd10.prod.outlook.com (2603:10b6:806:4b3::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.12; Tue, 20 Jan
 2026 10:22:11 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.011; Tue, 20 Jan 2026
 10:22:10 +0000
Date: Tue, 20 Jan 2026 19:22:02 +0900
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
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <aW9XShBOG2yckTkz@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <aW3SJBR1BcDor-ya@hyeyoo>
 <e106a4d5-32f7-4314-b8c1-19ebc6da6d7a@suse.cz>
 <aW7dUeoDALhJI0Ic@hyeyoo>
 <zo75mmcyxdzrefl7fo4vy2zqfpzcox4vrmjsk63qtzzmwigbzk@2hb52by2j7yy>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <zo75mmcyxdzrefl7fo4vy2zqfpzcox4vrmjsk63qtzzmwigbzk@2hb52by2j7yy>
X-ClientProxiedBy: SE2P216CA0124.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c7::8) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SA1PR10MB997653:EE_
X-MS-Office365-Filtering-Correlation-Id: 54d721a5-2d24-4d96-b447-08de580dc5a1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?muKGUJsVUCpowgwNeaRT52bWcGPH0NeFsWhZjQKq1sLgLYgczgNHv2wl1BbY?=
 =?us-ascii?Q?DyvenBeRnzOlCSleDEjQXQVGUGBSiILbCDR8/OUdRMEdHV6yZ2B681OrlE2o?=
 =?us-ascii?Q?BnTP3nB/TyuLWpk9MOQTQksvn6Ow8mZ/plKwlOR8rbcmFSek1Ss/yzwTI3VA?=
 =?us-ascii?Q?zP5w/dZ9Ck2Lj9/DRMKPXQj038rxsFqCeBr/7vaIDwZUcuuYx3r29Vts2k//?=
 =?us-ascii?Q?2hKFMWTNIoinF/rDcZkEWeJebSeTzrbSQ0fvekkOSqZeq8IeFWycYA2VzjJi?=
 =?us-ascii?Q?2STLF3N4Fy4T/ZaPyWkWba9/Ac4aNqyh0jfQkbQoBBLPlvdZgKCPQZGSV3qM?=
 =?us-ascii?Q?IuHrf5rxCd1xo0MmFlxiWnTGyK35n220tWoxRgRIa/8PJkUob2I+3qn1/Ujf?=
 =?us-ascii?Q?O4Mn+6P+s/gGOZbkByZRJcwMy+nTy9rnAUJv7GUCbW8NMp8wPu8szSEB+K3j?=
 =?us-ascii?Q?Hn0kLcixQ3UcQVz3QXsdlt4Eo8+Dn80CYJRFEQzW4pTKjZoRnz0XBvDQHYhp?=
 =?us-ascii?Q?/rh2j0adVuMsFEICwYf1bHuuOh1yFoDFb0wC8foBmysxVIo4NbcN1Fxx6kzj?=
 =?us-ascii?Q?3Qt5mgWehkvypAV1nh2l8k2iDTO2AVEw5y53NeroJDmNV3KHYVzxg7szHpB7?=
 =?us-ascii?Q?XHDXR9v/4lf8HTl6O/DXSs6bcGVLL6m97pMI0gMI5fKROZP33sUAC6Ge3VFA?=
 =?us-ascii?Q?PC2tLd52iTDZkwOKPJ9X+/eSNT+/ntEAkQxswP1OHqEgYPxq4Bp5Nlr3hz5i?=
 =?us-ascii?Q?T/61EhrshWjl84hii0KBW9p2AJmZztbXfCvQLY7OFUpRaC1+YURV7pA+Owb3?=
 =?us-ascii?Q?7fOnvgwA0OZ1WemsERU1AUKkBHkCm29C/P3AFuVdu4feEDFTsBvQvP1uxEfl?=
 =?us-ascii?Q?XcPxpUfLzgiySbhYud3Eqb0u/hdKcHHXRqxr6biEv2qJ8MIfLhEvk/YiWLvx?=
 =?us-ascii?Q?Bczc7ixo8OoBMWFq+34h0Uu+hJslBBFZ1wPPn5o2zCmfcv4abeqmLEGmnhXb?=
 =?us-ascii?Q?mBqkTjAcoY/MOsh3nAQzH8dh/uCj0uLyuaTvaeq8pO2ROXWdu6evrfqvh5w6?=
 =?us-ascii?Q?V0HnK5ynLIgl4zEK9lJJTeKAS1zLYodKDsFWCgeftDZ1mXUp/ReqnAMCO4lV?=
 =?us-ascii?Q?+QSg3mhhVTgHyJACXtqpSvbq/Y22H+M8vGtzKkH+FUyfnBg383LQQAwopOr+?=
 =?us-ascii?Q?AT0B2KC+b2XFfcbUsoyyIxhYYPR/Rxfwb0OOGhs1OwoKAfr0YfIByZbZZM8W?=
 =?us-ascii?Q?YoHxStAeTpfieqXWptiUet/jqcy28y3y2o23v/Y9otaHITvWVY0SRXEnGVes?=
 =?us-ascii?Q?+kTp6o9JSCSsFTnSjJ2EU/s8MC5u1QKo5wBC8ECCn67yALoCWPuGgYCn6QyA?=
 =?us-ascii?Q?HlAtOBd5xFYWXVw97sIvZXrmFm4dbpvnCR2nhyrudO2mU7P4sxPsMqw/zNdF?=
 =?us-ascii?Q?xRzMLCQ8j4wULZqwgmWVavkCnQm9Kal+L8mEN6bY49v9wDtbxqgkW5g1de8Y?=
 =?us-ascii?Q?dPViWv3qEohAu27KW2MAYAYjkuN7Hhomc5xCwBWdetacF0YiFC79EphIgMQD?=
 =?us-ascii?Q?vjZkPiPBPMSmy8wLcBE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?V9OZII0+4tGwbLjrh/ZTBThz5Z6q2oGT0qXTl9a9XOOm2FZS3kHB+5GntEQt?=
 =?us-ascii?Q?rN/f8ZrZ6JfNvs+aazrGiV0fQXY5/KCUBB5R6VETe6x5TE+ONJSo9CN9fX6i?=
 =?us-ascii?Q?rGNRuAt9oUXPmkePx4hUWmAToFv6T6qTc2RaeQMjVIabkEUktzRMEN8akuPw?=
 =?us-ascii?Q?PP0yULixCnh0ewolhuNywDKmlkdNdQcK36KTGlTLFy/sy2kTg/MHApEoK8cm?=
 =?us-ascii?Q?cOwdvGbJ1ZFL2GrqTJ2L2xyApkPrzIC4/u5aIv/N40QIMZyMcANEH8Wdjq8o?=
 =?us-ascii?Q?/KplCHaQPeiW2N8eluHWz/94B962Wkp6aQ9hwNgzgalhYa5w/+PEYjdJdjzJ?=
 =?us-ascii?Q?RX8uGruph20AUmKMg8AExuzYMKGmmm+dtsNXs0vFpg9bzQMOF8cTxjIHOk5P?=
 =?us-ascii?Q?20HHSKspevvrfdwj1Me5wkgitTr0tVVS+FQ2mN5nIvE2cjObzNq0SDrFULXU?=
 =?us-ascii?Q?JnjH9RewzQt8WGQNjcVt8yRAPtQcGM2T4em4TbtLw0ZymWx+xjhqiDxXkrhn?=
 =?us-ascii?Q?zMfewihkPPV1EIQBNOcv9/vE9zq+IotazHkXEz5Hpwp0g73I6r+tPd4iaIyo?=
 =?us-ascii?Q?fyO1D1YmTIlaEIJjTTgdSG/b/E2815AviaIJfdl0thoKOC0C5krwOVCPc18o?=
 =?us-ascii?Q?nstRU1ZLdamQuG9vhAtNY1phMsyrYGsArs3n+jevaA2lU4spkYQpK2FQZXQE?=
 =?us-ascii?Q?6yjsocNXXDMZ2SX5/smspiE0OYIl9t+wlTz9po33TKnH/mIiHWFiDXvW/Gcp?=
 =?us-ascii?Q?fGxCeeEOQ/2IVfGQFuKDRxLmQLyYaao9+d0RclocrmlKdRVwu0VzjPlf6/mS?=
 =?us-ascii?Q?T4X/R5yNbOkWp5Fq2bIruj7z8arRXETqefVQ+lqM8CiM/aUhjNg9ARf0krlZ?=
 =?us-ascii?Q?FGhn8cD5WTmbwZTlTLw1mn17JvGGfv+Ef6FqIO0ls41y8Pyo1aJcPCdgsSYq?=
 =?us-ascii?Q?LmZDGJwyMyfZWiAJVJSsNm4n1p97WZWs1O9doQKqTg/buGonzKawZnyszsoS?=
 =?us-ascii?Q?9R/Ls+RXp3c1QNpVBgZB6EkjFxaI/9/SyHntbJi82OIe/VQR5vCObf1rChOa?=
 =?us-ascii?Q?Nbo1Y5uAgbFuZBfQ5uDFBxKJIa0jBci6iT4WgOmpRaz2DIMHKCGrTLo8DD0H?=
 =?us-ascii?Q?J/fKQU0UftcMVLMn9GrP+FrBE/wzGP81ga8BWu08sgJlxZf6VYWRWUt5jsqJ?=
 =?us-ascii?Q?vzuFFlw7oKxB3e+Sst8uSdH8lu1Lt/Yj921UGpeeYHtqQvWE6iFjbaGuOH2f?=
 =?us-ascii?Q?WiZvjFT9KGdJSaRLKe/ByXhJZi+qavilZpJOUlhOdwRLs1wqdAJHWAZduEz8?=
 =?us-ascii?Q?PgR/FRmsa/DgxeGFZ2GdKt9LM+WWuLjFYvHrjdnEXSn6oWOna+o2w9O/ZIso?=
 =?us-ascii?Q?podJ8mdqNSq6819h1ALAVECURiQVfng4oFxE4/d5mvG3oWHDgXCWlZAmdAmo?=
 =?us-ascii?Q?ynGC21LYrMtbjoXK9j1LMrPHgzwklJPpTFtqZ2JSdKlni6z0fKfeCTUfhaq4?=
 =?us-ascii?Q?Y2qRkHhFSwbdTqE/dDdqmZIV0PYqhj7+T7KTfPJUNSMZtfXWq4eL/bXmVgIt?=
 =?us-ascii?Q?Nwqe9mKsH4hUpn93p8OfZcjh8z142txe36oIxlJmf0XfHxygOvHwU5+pz9e3?=
 =?us-ascii?Q?QA24RnaYxDzdmrdKyJP+S5XDPT7qK450xtqPwON4+jjp/YTxiHCEYOUIdNoE?=
 =?us-ascii?Q?NSEm++CdzZj9AJQoNLloHvs4r6hfvFFUeVNne8W4EU9cohCw5EpAeHIRhmmJ?=
 =?us-ascii?Q?Q14DAp6SgQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: D0Ihxa+UJEOo5hCD+kR4VELLXfQADOqDMok8Mb3azxNJe6Zqp8sn/JGAo4OvfBjONhz+v5U6V9FIrMmme8t7AkxApsZefAm1pohuQxgn9rbgD2JaGYAv83FqhNRmDsJZEn1CgD16duJL3iDgGEP3ybPtHnDHZuztedWronVeJza9NdEb+EfrPAvWDJTlrJTDkJgR31bJabPmmJ3C4UgDsYFFcJRAYv8MQ0qp0a8TmISI137uoR1Bai5kbZCftPhVvmsOP2GP7pmA34CCtrHa91xfStWpffM9QSwKpwk95pNB6KlQ3aXdu5TO5InkfA7vZXef0O+QAJv6HN1UGPHxwhpVzjSv5jOo/DrKHMijthxbIhB4DdW085nPWBlzF3fx8oOdzF4F8/6Q0CAsmv6rqN6q3eX607ktYtJECL7fmKoK/wdvkO631B2eDRHoLVLS0PxaBvKK0ta8GBSjbSR7hTjXfDL8FAn/e1d3uS09DgCgsVRYKRF3cbPRcGpAIpztxA6rCRNIanc5rS2FNPkxfdUndQ3LkNurXfGOASqW7VB1ouR1iAd45N87MkX3cbouXMkPLG779NKESArXzamir4H9kparFgG77yWulsqsIvc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 54d721a5-2d24-4d96-b447-08de580dc5a1
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 10:22:10.8534
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: JF5gevasVxdHObGR8FMzwbB5ysPGsaBfmH2uXhCD36LYS4H+4/uiPU3DNGaqXf/tiOP+qWXmLlsT+jmKZq7Jrw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR10MB997653
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-20_02,2026-01-19_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 mlxscore=0 adultscore=0
 phishscore=0 suspectscore=0 spamscore=0 mlxlogscore=999 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601200085
X-Proofpoint-ORIG-GUID: Nbv9f2E63kD6UYtysROL82q7vT3K8b7Q
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIwMDA4NiBTYWx0ZWRfXw6J+5W2kHA/X
 /KqW05l0DswPa+LmYeko8rLeGts3FNTxGAf2hkvFL2I8qLFd/ou7pc0wsZR/XoHu5Y5CMY2I5y+
 RnJiJ17XZ9CuVQ+LT9SWKuwEu59kCANXSxjqPBD8FIywQ1OIJvesng7Pvrz0Mv8TmbREEClSJzX
 2Zhco2tJlBmfmLbnKUECsZYbHqYq8atWo4mjtK3H6uZ0LN0JnMUIy/fkB9AXznIOiaWltYK7WT9
 8KibYCI4eIT4Y9Nhu5tAK0gN+w9yTgIv7CcfFF/tn9f9/WmuChHUxqsX7TGwAKXB0NxKd9p2cRY
 8n4pWJTn16HPILshtOcgCemupGFXbSnEeD0BA/3Sx9lPADeiQ60ApS+6JG9L3L6T6ShwL+7VMwA
 00adCFfbPrgLjh1Brs0xB+nnw62So2JlwrwrZaf5OnR/trGfHa1BNnvcREHBdVdq+593dcZUzsb
 yBDljlNJ1O2WesmT5Kw==
X-Proofpoint-GUID: Nbv9f2E63kD6UYtysROL82q7vT3K8b7Q
X-Authority-Analysis: v=2.4 cv=FvoIPmrq c=1 sm=1 tr=0 ts=696f5756 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=XRh9JdlxYUBn2K024XgA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=lhfF5caj;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=HHdhBT68;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Jan 20, 2026 at 05:32:37PM +0800, Hao Li wrote:
> On Tue, Jan 20, 2026 at 10:41:37AM +0900, Harry Yoo wrote:
> > On Mon, Jan 19, 2026 at 11:54:18AM +0100, Vlastimil Babka wrote:
> > > On 1/19/26 07:41, Harry Yoo wrote:
> > > > On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> > > >>  /*
> > > >>   * Try to allocate a partial slab from a specific node.
> > > >>   */
> > > >> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> > > >> +		void **p, unsigned int count, bool allow_spin)
> > > >> +{
> > > >> +	unsigned int allocated = 0;
> > > >> +	struct kmem_cache_node *n;
> > > >> +	unsigned long flags;
> > > >> +	void *object;
> > > >> +
> > > >> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> > > >> +
> > > >> +		n = get_node(s, slab_nid(slab));
> > > >> +
> > > >> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> > > >> +			/* Unlucky, discard newly allocated slab */
> > > >> +			defer_deactivate_slab(slab, NULL);
> > > >> +			return 0;
> > > >> +		}
> > > >> +	}
> > > >> +
> > > >> +	object = slab->freelist;
> > > >> +	while (object && allocated < count) {
> > > >> +		p[allocated] = object;
> > > >> +		object = get_freepointer(s, object);
> > > >> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> > > >> +
> > > >> +		slab->inuse++;
> > > >> +		allocated++;
> > > >> +	}
> > > >> +	slab->freelist = object;
> > > >> +
> > > >> +	if (slab->freelist) {
> > > >> +
> > > >> +		if (allow_spin) {
> > > >> +			n = get_node(s, slab_nid(slab));
> > > >> +			spin_lock_irqsave(&n->list_lock, flags);
> > > >> +		}
> > > >> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> > > >> +		spin_unlock_irqrestore(&n->list_lock, flags);
> > > >> +	}
> > > >> +
> > > >> +	inc_slabs_node(s, slab_nid(slab), slab->objects);
> > > > 
> > > > Maybe add a comment explaining why inc_slabs_node() doesn't need to be
> > > > called under n->list_lock?
> 
> I think this is a great observation.
> 
> > > 
> > > Hm, we might not even be holding it. The old code also did the inc with no
> > > comment. If anything could use one, it would be in
> > > alloc_single_from_new_slab()? But that's outside the scope here.
> > 
> > Ok. Perhaps worth adding something like this later, but yeah it's outside
> > the scope here.
> > 
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 698c0d940f06..c5a1e47dfe16 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -1633,6 +1633,9 @@ static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
> >  {
> >  	struct kmem_cache_node *n = get_node(s, node);
> >  
> > +	if (kmem_cache_debug(s))
> > +		/* slab validation may generate false errors without the lock */
> > +		lockdep_assert_held(&n->list_lock);
> >  	atomic_long_inc(&n->nr_slabs);
> >  	atomic_long_add(objects, &n->total_objects);
> >  }
> 
> Yes. This makes sense to me.
> 
> Just to double-check - I noticed that inc_slabs_node() is also called by
> early_kmem_cache_node_alloc(). Could this potentially lead to false positive
> warnings for boot-time caches when debug flags are enabled?

Good point. Perhaps the condition should be

if ((slab_state != DOWN) && kmem_cache_debug(s))

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW9XShBOG2yckTkz%40hyeyoo.
