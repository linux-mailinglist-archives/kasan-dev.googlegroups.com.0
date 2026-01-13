Return-Path: <kasan-dev+bncBC37BC7E2QERBFG6S7FQMGQEKZY5VWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 25226D16F22
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 08:07:02 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-3fef084337fsf7818528fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 23:07:02 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768288020; cv=pass;
        d=google.com; s=arc-20240605;
        b=A3xTIETM1gR5oiEO6KplsuEoSRCqUo97LykIHVNS2hEZJ3KOWR8J1hx8Mf/iCxDKXh
         chN0h475bX49daS3mLh7e6LRZ9hl9jv+MVNWrnzzKLN70PWTL1K4ii3tErAYvpVdMyAo
         JmRiLNQjaFdy2LbrX6H5pGQBcTGGYzPpVjTgx52/XcotSyyrgXfYHvLZ5qmJPu/TQPSN
         sY4hzfEEqO527VarRlKoAzROtZDw3yls885xQx6xg//kXi7STjsfyjWxKabEdolMnQB4
         El86dpKKy+u7huzlmtV9G3nD/vbthsOyBIXx1/w0itOWDcE1EgF96vepcpOOCXkd4Aor
         5uCQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=67hBqrFyE9GbfXM6YSLeOIUoGTETJpov1B+axcjQh38=;
        fh=mknVCgrLjAV3bwCDSHmftOfaCGm/eq94ptDHBSgJMVM=;
        b=FrjBxDy4d/vLWyR1wMshDUcfbdoTrbIqGmkl5Y4JR33xzkbGfxsjUF6CGNjgPXvHTb
         wreGY74yK5yXahI/Zj550cm8c2fJQE5ib3pLSpTLYvUWpeFuO6QzPB0eX1oBVO1mYT7j
         my5q3vp8dG4sZWvrjwRX7ZJTQU3ma4A+SafAPA3KPZ3kBkoW1o2lfzlS+WB8Pz7KVbqZ
         JlyWSeOKyUVHEM3kfsv9iIFSbbdzXxBFu3BngbBcm0rpW0zP39JP+BubW3MM/nM6Bhep
         cBkGE1bStPV2dQqU1okoxXcTHpZ33d1+xeRp8WeeFixA081BOB+2yl2iTgkLprEdyPDN
         dKZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="hyhvPR/p";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dzy94Q0k;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768288020; x=1768892820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=67hBqrFyE9GbfXM6YSLeOIUoGTETJpov1B+axcjQh38=;
        b=ArGl156G7+AszAfRMKZZhf7ekEEGUky7rvQWjwvDocftPaV2NFe3VPHTwLibv6ShM3
         8VzFKfyN0PXHhyB3S6h2gl4hMWBT9dtol4EKroJ1PFMGM6UurQYY0pkfa0B6xtGixzMk
         7bH9Dm8glqTdg5lQ9tJiHifUoMjxHM9dioS/Aes+2cZVoQnKtbeBYrwzcGcswwOJmQUK
         TFvWkRQwKLXwicsKG0IuPHbJfhZHY5dEDB602Ue7WWhJ0w84ay1i9vgSry00DAKFv5Vz
         dqfZi5tGXVOif2lqpdCoiADAnvpKqn4gYBLDgUzEKTevG6O1YMUyevuHzM+k+uOiCGAP
         r3Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768288020; x=1768892820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=67hBqrFyE9GbfXM6YSLeOIUoGTETJpov1B+axcjQh38=;
        b=aG8s83cqlb73DE0y+KkysTuZjbXF98eFtJND0QfLvpwe9alrY6dzHfZdyJDkRWWfn+
         Qo/qMR+YmiviR0LPwIyofHWYb6qXvobF5x5QaLURVVGHu0Zw9FuYGzmHYRR3NQ+MucH5
         HNxWltdlDP4/BK6xgp+OhtQrdj0D4JeFtbQlrB/74FSPr/DRLaN4/LsFzyOEnO2JGAza
         RuKTxQajEdGSbnyO8oPtiK87dVMiAXiECYpQON84hQuHIrJDe/yv9sSOUom3/xzbkIR/
         Qa08o5BtkjYgEHRGCqhLOlZ+425xx9o89U3vjktkYtJbwq24zJOlmIovqTFuNBjXYMwh
         Np3A==
X-Forwarded-Encrypted: i=3; AJvYcCW+vdJU6wyQj9SuT7g7CaSdq4G3FwF3xEaEa2FNDWhCG0aNb3TJDOwlHx3MWOQb7lcg6yvSeA==@lfdr.de
X-Gm-Message-State: AOJu0Yxmnp82RbO/NASK1E+kv0cAxslqNK3AnsAzbpAuRqqsF0QyZZBQ
	lNAkbA4ri/SVxc3+LV2WHtsuIaTMXquY2FnRay78TNWRPPbDWLK9xOYB
X-Google-Smtp-Source: AGHT+IFqjghCMlKsRhNqdbmaHbnrMXT142anRanDQCHFiCd9vmSLO9gh78b8H+xdvOAMudWNcSlJ3A==
X-Received: by 2002:a05:6870:9627:b0:3f6:1f08:edeb with SMTP id 586e51a60fabf-3ffc0c0637bmr11269811fac.48.1768288020466;
        Mon, 12 Jan 2026 23:07:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EG8024OiXwsMlYPe453FDippXo10UrEXUXNIhj+n17SA=="
Received: by 2002:a05:6870:c22a:b0:3f5:d306:979f with SMTP id
 586e51a60fabf-3ff9d769f81ls2851161fac.0.-pod-prod-06-us; Mon, 12 Jan 2026
 23:06:59 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWvarNj/e4wPrSfK7OmbiZrcFFhuehrIihCsCybhOdQBMZpGoyxQJh2f3A9tJB94MwO9m7dQ/SrVvU=@googlegroups.com
X-Received: by 2002:a05:6870:8305:b0:3f5:4172:15 with SMTP id 586e51a60fabf-3ffc0c71639mr8736136fac.58.1768288019362;
        Mon, 12 Jan 2026 23:06:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768288019; cv=pass;
        d=google.com; s=arc-20240605;
        b=PaornabP/h9uNPgByGHEd1/v2zXPmOMn7PUSY9WHKWfVPpOOf6/AO5Dvhjzqr3ZyiU
         SPVMtJuUYAL1hIR5X1wtUbK2JtTaw71vB9vneiYnOSo/iDudtpd8nLQM/AuZDgRl9HQ3
         ofOP072HMYkzkaI5m/N2mWdNswyHRTB/bRa6fdFv3h+Ac9/NfCbyyEDTog9E7XA7Y4ZL
         GzHEsUlpns7LTo8b3ugrIyMplXeO1fkqzI2UUajJ+FNxYORpTwWIdwcPin2b7WCd06QM
         UugOvDJ3QHcJURpvLw/zPD8PyeLMwvv2vouUEMyB7MJx/pe0L2weptcxICc5U6mAfF+6
         1Wzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=Vem8sAy1HUGf23xkRnJma35B0ldz4fhz06+qpkqir4Y=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=Tcidsi1Vjg1POqUiksVXaPe+oEBzxvdZ4JTxUoZANT3oyZgu1uJAO4B8NQefDfcSnl
         t0w9lwYvDyviG51QIaJQzFE2dDs+ljnTTpYfC3NMPHEH5c9kzvYABs1J330UT4/hqx04
         gNjzbKDrA6t9Y1AgouXtxR5zzqTPTWRdS1CIv/wWT7d0GsCVlobx0SPYjczyK972wP28
         p7/VIOpviMqFqn+ag2d1virdTd2gBShj0YlZ2l2nXYAQpyt2t27rrQ5knfv0mfhtFVPn
         FNX+758MlY1sSnaP4vKhtwq+5eurOMPDoW4pLwdsxX0l/0xJ0noxxlKmbamB/i58h/ur
         eK1g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="hyhvPR/p";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dzy94Q0k;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3ffa6dddb3csi650713fac.3.2026.01.12.23.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 23:06:59 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60D1gfYd2419467;
	Tue, 13 Jan 2026 07:06:55 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkre3txss-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 Jan 2026 07:06:54 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60D5qXwD029363;
	Tue, 13 Jan 2026 07:06:53 GMT
Received: from sn4pr0501cu005.outbound.protection.outlook.com (mail-southcentralusazon11011006.outbound.protection.outlook.com [40.93.194.6])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd7j56ah-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 Jan 2026 07:06:53 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=eRS3lNlJKI48Tjht57OaFn/zDSCPHGHSLux5QtmNiXz12926r2ghX4LCrc2FhqmH8J2EBNihTmuyhq8W6KJAteILXWW7BtkCUfd+zVwHWEZMMCfFLLtHOZvjPqWJFn2LE4apNG7UyPNdH09SBpLlYo5b37PCE6mUEoJtcvQ/2FSA5PXbteTBwZ4SsxHMDvLJTYKj+OZ1vQAZ4KOMiEHM/vGqOgrf9ojgn+X0yypZFMvHcToS3Mq1llxUuzSVPgD9mQiYOU0V6BID29HQPftE5WPIDEC0djogh6dFSaJhAvJgCo6Wrt1NIOfTKtiCe2Yv2UIE17IdFlMjNhEcWMtoJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Vem8sAy1HUGf23xkRnJma35B0ldz4fhz06+qpkqir4Y=;
 b=TW1Kbga/5OdiNgDP/tZPcBpHY10Nv0EiAuBMfptCZhG84EetAjmqFl48qUVVWxjEEJCkIBUMYpxEdzrQp/NLTRiaVM/CaYdZiD1pyEGhKD0XMug6AiI4UJ7cDX/yiaAl8XJkCovcry124gLfbhlnJC6A2eUMoDVrvirx1Zp1S+srkZRnrOqoUwfSDI3a3TghLs3F7DtjU5Jc58GZwZffXnAAEPHFUF8KjKDTMfCTaYEcyTqqb+ECzjkpfLDzclwdyWQi4f8X89CFcWmbfDrDo4GIVQfGNQ7JQmYWjyamSarKOOvIN5iu5PMl8ACYKKfw/Q8oxpRn7toFdKM1fAPkvQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by MN6PR10MB8190.namprd10.prod.outlook.com (2603:10b6:208:501::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.7; Tue, 13 Jan
 2026 07:06:50 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9499.005; Tue, 13 Jan 2026
 07:06:50 +0000
Date: Tue, 13 Jan 2026 16:06:40 +0900
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
Subject: Re: [PATCH RFC v2 02/20] mm/slab: move and refactor
 __kmem_cache_alias()
Message-ID: <aWXvAGA_GqQEJpB4@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-2-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-2-98225cfb50cf@suse.cz>
X-ClientProxiedBy: SEWP216CA0081.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2bc::7) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|MN6PR10MB8190:EE_
X-MS-Office365-Filtering-Correlation-Id: afa86f52-3b4e-4d13-1a7a-08de527252da
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dKJmIlv6eZpEnZ6712YVeWJNu34M37hQDiIX2CDwx/Sho+4bdKRvNFtqMqi8?=
 =?us-ascii?Q?jbtcH8z88/oL67ceBDTnB8G7Ofbag9TW5aO0RjpmjnFzTvkC5xiH4oVDRCgg?=
 =?us-ascii?Q?MF+P2ZbRSlYScWMtNr76gGkyCf93HoeFVaiTR0avNs4JY7i51a1UCpA4vQG/?=
 =?us-ascii?Q?UpPI35R/OXjgh6GKUvmiOo/sTuP4Ys57vj3gGOfYza5ky1cbIT99kSV8mcoT?=
 =?us-ascii?Q?SLK/qtLOwbYWKBm6Al/oBfPHfJApToUtkoLSn+c1YmK2BQbyo/Id4TjmYIzO?=
 =?us-ascii?Q?Z8v/HN2/6Rs9mo+KUMwDqAgClU9Q73ojNQ/PUfFgfWZe88hv21pxPWL4v249?=
 =?us-ascii?Q?PGYzoRPGftJp4AoNCLVGy8rbDQ2T8xLaxkJ17ssFZ9Kro7hxcG8m1sE2QAyF?=
 =?us-ascii?Q?Hol/s2EQdJfhoNmpsa+vd6fH5uJJZ3Pxwq6U2OKyOX4E0Invr/+8nEqv7zQf?=
 =?us-ascii?Q?8r8hJ1Agu3y+rwwhlfRDEAjsvgHwHctDyrUHKt418CQ4mt6UTZddirP3OsTN?=
 =?us-ascii?Q?9kUto1Y+bHb26roJWh/CnN4WW1chKAUlENRR5l8TU8f+stYY81UKH75pCcNK?=
 =?us-ascii?Q?x3Lf3nYXws6x3XM1L9rR/8MPU65rCFo96/n6Ip6FlsoWBy2Xbr/iAN8sOhXK?=
 =?us-ascii?Q?4UMhY6ucZeIG85JZRJ1bq7M8TQzl/spSCnqfO5ROAqSHe8tmlPcRqyyd9Z21?=
 =?us-ascii?Q?GrcjoJwqj6y/CYS5AZaIybD07ewMPx4RNUX0E9UtrHXNhHzD9H/jkstQ9j60?=
 =?us-ascii?Q?qpR3Jj26gPkN05BHG1j7IQZLOqFwjUPek2YZHU32Pzc75GUp4uTGMwDYDSmt?=
 =?us-ascii?Q?JvdzY/WRzv7FZ19dg2P0tu+gFRTrSwBQN7VjKKB2I38Lr3oY3k17/vWO+pbr?=
 =?us-ascii?Q?VKZb1TDk/JbfphBGKb0BnXON8JnnSW6rf2nbp+xRJZ4KakUTM+WetGQelUMM?=
 =?us-ascii?Q?Iu5I08t/hrcxpMtYVXIC9TeB1HbBExlHpKPBUIkaGeN9JSvAJyj/fOYIcsAl?=
 =?us-ascii?Q?uvOzrqNAYd4h2N+HIvpXEfiwel9+FqCdygdhIWvVIalxHxBBuNU055ghVYKV?=
 =?us-ascii?Q?tZgfGQcNAsB1mxDEP1Dfge26hkkhtenkrUySK5Ql0DLE8X+PrMostlOzkm/m?=
 =?us-ascii?Q?51W2kdVUIYDkjKNmndy/GMdbyQpF+zA9oTNKrnkYBFWFi0XhK+YGwGkYZGyn?=
 =?us-ascii?Q?iKgm0nA0sQtfu1RdS0l/9XwKWm31Kt3B8xQdic2ef9MX5Ma466k0y6ZXWYzz?=
 =?us-ascii?Q?DdNBHjXeNxccE9jcu2RZ34JsFXS6SYoLLTNDMRA50q+1UIesus4kBff+7iZi?=
 =?us-ascii?Q?k62YVjmuPt+RlQ+UI2X4Fpxfp6Q0wotJly6hoWapa5k7Rjqwvfv9W4Q8LCpL?=
 =?us-ascii?Q?odTs4L1pSFKcgB68QQOoHTIWRUgNriU/Eq8S2JlcpXGceUo6Z8Z8wRkFVZBJ?=
 =?us-ascii?Q?NxNofU/8BtWmp/8vujnMdfTGgj8vNQmh?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BkkkVndHTYuOLP80Sb/V0vaIMku1hMlQPfrWqE/t4I/wAnU8cNMlUyDIATCM?=
 =?us-ascii?Q?1iFpZ56kW5gadUNiOg67Sm//MxZl53pr0tw3a30QGme8X++7dqLsKorufdTc?=
 =?us-ascii?Q?X0eWB5+eXCpkaT8nv8t6bmq3NWeGh8ULMaAO51KNVYXjwRDp/HVgXgZ9qe3e?=
 =?us-ascii?Q?2XSHJ+LTX1ZqYiRWDV6BtwiAhL3UDTGNfNZK0IwJQEY10RPi5zPzt10UJHwQ?=
 =?us-ascii?Q?15LOhLKfIj5/ZnDhOnsiIt0ejyivZk70GlJWmQVNuS+q6cBwpNOSBO6h5JKa?=
 =?us-ascii?Q?uLnxCGb0oDVnrJhs8y9tOMcfHghgPGmLXCyvSU3+O/6N2jyQtG7RMLAtIW/J?=
 =?us-ascii?Q?Q6cbnJqKfbIoY7RakG1H8OincVsqcNHuW2ZcFN4grrWi4wwVazRmlmJxY5It?=
 =?us-ascii?Q?KVkASFrRimvkFUQMrxOkCEylwSz+R3zAOykUU9z/mfLXXK1a4j9w2HRVmAfv?=
 =?us-ascii?Q?M+OPHPMbNX1GbQLtxRIjsN855qHcezleG5+i4l6pQqPSURnVq6oFgxSEXF0X?=
 =?us-ascii?Q?V5+WgBHTd8Up0kFr5jFrVhl1nXBv80VZcQf986kCflzs2zB/Y/TN50tmeXjA?=
 =?us-ascii?Q?WdRCIdhPduxGD+j/yisBfBYzVV6jjnFq34GFTgKdHLnkirAtKOYpfzDUPJ+J?=
 =?us-ascii?Q?ecIx8CEyTVDbXSW5Wlx/ln7Kxg3Yeq63uww2jgnEH+Wf/usUPqSBa04G6rJq?=
 =?us-ascii?Q?ZbjUvFmveEHeCHAzmoDY3wAC2lclP7i2x9Fl0otGCYCC1bYkaDVeZxt0QF54?=
 =?us-ascii?Q?ZwTcAxnt8i17uOmdGo+wTpG8T5xYeNR9m6WGv8e4yWx/OnTzybQub37BD2L/?=
 =?us-ascii?Q?I9fJoIQFP1wRkV/2+3id5QcNgzeXchEru/TOskv0Z0wdktBYuzDSUjnO+gIj?=
 =?us-ascii?Q?fHCM1Lwhp40N9lzBPDvqJ/oDEbMRN44P5WbFFQacbtjEefVTvzKvHgY4Vuhs?=
 =?us-ascii?Q?GEnEFaX+tZfXTkHkiDMECfKroZcLOhDr+Kn4u/JLSrsTNiBVarUvWjgx6v1+?=
 =?us-ascii?Q?skKJSe929Oxy3SETv8niDXG7daNoSstCbH6LAq0QT8Y56r+7LCZnim/iNTZQ?=
 =?us-ascii?Q?ZVAmtN8DmCisu4fL7XTIw+msxyrOFkU4uvTHgE1/bz7AbH/L8/ku5L+0d2O/?=
 =?us-ascii?Q?ZbWZhXszalnkPXKHXZ/YPICUXwl207hlYb7rcc5YpIRdQHs7mx/f9x6xFEa4?=
 =?us-ascii?Q?qPRbMwMqvl3FFoDsoD0TX3hqqXoQoPWcb43pxRmTMedSm/EGyf38LmqEpwY9?=
 =?us-ascii?Q?GAOlJEkFG6DK3JI0BOCdB+ltPvRcnxZnTZg/koWRdyIUYNB/hxUlmE2VTWJR?=
 =?us-ascii?Q?xHTGOjrirwuIt0pQkGrRi6/U6+XC8ZmYKnry1Z+c+oLwF6JNDXFI1Lb1khCl?=
 =?us-ascii?Q?M22N2hPULCQECJtbCDEE4lFLj+CkKPoY8cJ60dnKaZgO/F7Ab36+ylXk0YP5?=
 =?us-ascii?Q?TR47XXDGITaEmG6eLmX3Qsww/lHbqcXgY+Rz1rBBCz+xEGjTv2xnrlADY8S5?=
 =?us-ascii?Q?qz0t8aDPeyK4lbvfDvs0BJiS59ad2ytC67lrJBr9WUlSdluTwhT8VTrPVaki?=
 =?us-ascii?Q?2f13BNFsHtpOdO4PguZ2vVIFGYckIpVxSMwvPryEEp3A0SdYNSAtcNDx9B1B?=
 =?us-ascii?Q?vnt+3uZFazfLi6XvMSPUncUJW1D+KICgO56wgI9e8slO5SjLaVygSMqpFRBE?=
 =?us-ascii?Q?/Cg9NRpbjXaPJYmYEZSnUtLaSj2ctLy8frmwVyvxEuRHacIR+HGE/xp/OqOx?=
 =?us-ascii?Q?fs/pto3RZg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ixshtUTNuhODL+CLywgXps/qaXxz84fNue0RcvQkeMoWjzhOwCrXINAD7/PecNzG18COSGbx9PQavYyVewSkut/2eEvDPBBC27cd5vWVtQrBIEo7KOaHq6TY5y1Wt+Ksqo0W8DSZnCOL/grvIB0zdqmD1Vzch5T8mH9HOpiAvnDIA1XMkxCiiVb/S68noVVCbg5GFGLBuYUXn48B0lM8koyNm24oO4S43FHlIVsJMNcgBmhaC68iKSQxSavoeBlXFhWxRHaV8JxaODYUo2Cr7zzpQIZscJlP4n0KkRhyiPcXgMiICwnz17GJgoQmMNUNbCwSQogdKBE1edvWLRArVNq3iPqmaNdk2Tew6Jxi/UAut+bKif5e25s6T2tCujR/BOlfH+8TILbS0k9pQ3bjB7WMMEwLqZPbNbeB0ZxzIRuC3q1GzcI24aTNn/FBnKCcxxwCeirUxxm+9wlPLr7rKP2IMqNhsHyCxBbQcCh2E6yshT6v5NDgLEtGpa06cycf/PJpo8kd9iF7js2daTdbQ/Uq59yqpoH+mMsZvY4WRWXyVo9KjqovWaR4g+W/XaheFr0D7RnalttR5QW4ILYtjI1QOGtz6ScrMOXcv3/1ZF4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: afa86f52-3b4e-4d13-1a7a-08de527252da
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Jan 2026 07:06:50.4413
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kHGdqfpEaaTRvetNZwev4e+V7DFKqpqn6ldT7QV577ocsX9mTiUuqJoIJwork4HjIjwwDmnmglVXjcuc6dxFGw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN6PR10MB8190
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-13_01,2026-01-09_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 mlxscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2512120000 definitions=main-2601130057
X-Proofpoint-ORIG-GUID: iaGCeIHJVVwuwo0taLNVNzhhCOQYONnW
X-Authority-Analysis: v=2.4 cv=YKOSCBGx c=1 sm=1 tr=0 ts=6965ef0f b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=Pqqr0_FuijpkObcXNtcA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12109
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTEzMDA1NyBTYWx0ZWRfX0Vgy/e3UyAiQ
 mCvjTW2VzNLq3V3VHtEw1TWxVZYYU80Ux+RYR0w1Wy88zgrxKuQhbyimfTsLykrgMcO4TfweiJY
 aCKsq8qDagS+rorU+EOik3Rb++BsL8oXj5/bVNg3ZbcKURqNyspwFL/yG/iODsfh174ASRKDzbj
 8qw6pUc935mA27zGcnFpeB0lFMN8Kp1OtCuDLK8+RLCuoVUbJyhMV4+8nx+fPDtd245Kg+Aogn/
 J2fzIqu9hQgFH6ls/m2WZjRYXtY8AsN2JwdCAhyrfdacBtVi+Xk+v9zRj/F8bjgg75fnfW7ukg1
 7vgDIRiUQyz9+iJdze2Aw7fwv3pKupBCwpsXBhnwXeuiQq6k2R0nOU4gG3ChcSN6vzj+s19mWQ2
 sgkjVPKiKwXe1VsROlS8hQohAQPwcVYdojbXTCEs7sQxQDRhQb/BaSbnXiGG1wxaZgUN07RfGrH
 YvGfmfnkTOV1k6qMlHxNYEgG/A5bI8rWNJEcihIU=
X-Proofpoint-GUID: iaGCeIHJVVwuwo0taLNVNzhhCOQYONnW
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="hyhvPR/p";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=dzy94Q0k;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Jan 12, 2026 at 04:16:56PM +0100, Vlastimil Babka wrote:
> Move __kmem_cache_alias() to slab_common.c since it's called by
> __kmem_cache_create_args() and calls find_mergeable() that both
> are in this file. We can remove two slab.h declarations and make
> them static. Instead declare sysfs_slab_alias() from slub.c so
> that __kmem_cache_alias() can keep caling it.
> 
> Add args parameter to __kmem_cache_alias() and find_mergeable() instead
> of align and ctor. With that we can also move the checks for usersize
> and sheaf_capacity there from __kmem_cache_create_args() and make the
> result more symmetric with slab_unmergeable().
> 
> No functional changes intended.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Looks good to me, so:
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWXvAGA_GqQEJpB4%40hyeyoo.
