Return-Path: <kasan-dev+bncBC37BC7E2QERBQGCY7FQMGQEHP7MCHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MEyvH0LhcWk+MgAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBQGCY7FQMGQEHP7MCHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:35:14 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0152863252
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:35:13 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-40450320b4fsf1415780fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:35:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769070912; cv=pass;
        d=google.com; s=arc-20240605;
        b=GcDxorbwdNjponbL/sH9j+La7htaTqXn9JicW8GBOIo4n0xHM/N0JmusRtDCQ5eLam
         6JvsIHXCm39YI3rj4oyRV2bmj0xJGrYkpMjBAebwi1+Bbjq0dDOYh9z/knQ/x0aVpW7F
         3klsB2PpN9NOlgRdXH7O1QqFYCgM9UmCifNE41VDrlReWm1LmV85Kf8ExVuDNC+/5Z10
         NCtfG0xUf0YZNtk+txFgfHhWqQud3TaJtWUk4FCeacI9P2w+k51ZfaAdQENL0WEuc9yd
         PBs4qJX/WcKu3m+CeSC3gp44k/qy3e2/ZGfuZLWsD1CKqgq6Q4/HViaeQn7h981NvwvF
         e0nA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JOcMmlQQxplJs8yI2FSofOrB+AXVh8KsoO+ApYN7i4Q=;
        fh=jr6inM5YnJcIurRqC3ryeZqHgNcb68pcvizVwg1SkXs=;
        b=Wc+OicAhr8cwYXKwMjIO3qmZA068dK1dInBnSdSTGkZKSbe6eHSZtlZvaHnQbJv5B/
         vYIPIGFF+SUYumtAEDZNadEUXnbqZnv+2qwdtPgwRzXCMpY/yFERkaCsQkzFyhslKKe9
         zMPWGzc3lLuax3grCrlnsZt3CTDHjFNglMW5LFUEW8yLN4Jk/6NdzyCsnC3hTRdt0Zh9
         i0KIKUuDmkIQZRCj08mSO/cuWRGB5bNXpxecTs9nSKulJckHd1ch7R3/lBkWh95a+PnB
         YAcRyOKpQBW4004lM3KNNty7NKZ4YQgQ2N2uX5BgQB1YeZlbv1K7sVqna00tMyL+6wXi
         QXzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=U794ZqcJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=g0sfYPrb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769070912; x=1769675712; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JOcMmlQQxplJs8yI2FSofOrB+AXVh8KsoO+ApYN7i4Q=;
        b=eneXRhedE3vF/8DLPiX8n5zLdthAsx82acsa9i5llg2OB1v8eN2zdKjNl1TN4uUB0/
         wojQyeVKf5yqswrQGIELbT31zfCSYpHY/hBH5icGLrRAOj1g2sSai5AcpxXlx90dFDGt
         Z8BkZ/o9lKDUGF7licg1noFakgW4jSBifkAAfHEn5Yx2XXBGDxT0/z4DG3cqg8yL0alj
         j08XD4SXD+XEXVBZgCkhmFBLJ8j0dO3quGdrwlAB56b4hn48W7oUkqnWJ1U12xHJdCRy
         bgQnlQEnlrOF8IHfqsJ+v787uZl8tzQX3RjB+Jcy+icaY2gkm9WgUQUsIZw5GMBaEnvD
         I8Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769070912; x=1769675712;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JOcMmlQQxplJs8yI2FSofOrB+AXVh8KsoO+ApYN7i4Q=;
        b=OcQOLAuLJ6B4vVZeyFmrScT77hNa6mF61cDsIRp+2LVWQalrY3ljAkqc0JmvK3KjGD
         Qhz2QUb6qvM4ReN6WD2onWDYVzK7IkpjwcI+0ft8T1qEbCFqMsYM5FXOULpHbkilMUjB
         XATemYo67mKPF7gFmpxpUJuLA9Kmwmbn8xHET0AMGx+0ucX+0NgH6/i0gQDaElVm6frn
         UyigTIxoeTjWTYP5rwzZQQbaHCY1r2WeVTHlpsyVsvva/OvMyBmFr0rTixvLL+ES0S7I
         8NKCC4eg/OPhzri07BVfUxsHycUw1YV1yeY0zPr9CVgiMqvJWebqjnux06Shw4emAl7N
         6K7Q==
X-Forwarded-Encrypted: i=3; AJvYcCXsk9dM2EUNdUUNS090RpxceIpqC2HVzy3h+oMtldWUej3ifGhAXDq679UwwIgQuoyo+Row8Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6YwX+lvR0S7vaf/Jh+FEyIF4Yij1nND3Id0hsi6E6zNWeAHNC
	Yfkc0WUIBBkP1TNcsZnztnHMZd0Mwdy/yfhkRmETpKHCiL7QIhw8/vuN
X-Received: by 2002:a05:6871:7801:b0:3f5:d9b0:567e with SMTP id 586e51a60fabf-4044c1c64c6mr10666540fac.14.1769070912305;
        Thu, 22 Jan 2026 00:35:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GsrDQmDMMHynrc5UGE+BIVWmwybexJjL3LNM+ksXUdnw=="
Received: by 2002:a05:6870:a787:b0:408:894f:e0c1 with SMTP id
 586e51a60fabf-408894fe21fls210926fac.2.-pod-prod-02-us; Thu, 22 Jan 2026
 00:35:11 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXwFcoC05eqdLe6dWckQGWsfzQpAdvHsev6ovdD33vofmkJg7hLvnRIysF979z8yHBwNL3I9gxG97o=@googlegroups.com
X-Received: by 2002:a05:6870:a915:b0:3ec:4b7a:7ceb with SMTP id 586e51a60fabf-4044c631c09mr10688305fac.48.1769070911234;
        Thu, 22 Jan 2026 00:35:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769070911; cv=pass;
        d=google.com; s=arc-20240605;
        b=A8dM5DhsJcrwsiUHC5zlYCRDum5yCskTidXp1a8h5R7/1WTpjVfhsNT3V86mTEkkB9
         3kyhw9FcpJtlb93T6Lv+8LhtgUJ/eN2gN85hWcsk+JOyvnXiVm8M4OMck5V/N5dhWzKH
         nWgpwAbVA1asQR0AGR6UXLXMGFT0BKRFuCgLRPIwMN5ejUl9g4cGkcWVCczvPXJY3pB6
         ph7QFedYX8sZerLzujdaUTnmdKBLYXHaP0dcEo3TVYScLcUERg49OEDUuh/4TuvPwmcO
         em4AGBeS3EbYgIbbSnhPT0UYkPnsIQLH2XTtpgvgHHXeG6KlGPavXq6SGR5p51HfS+no
         2NYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=+l12CrUT6YUbUBDe3daCr+Tva7a9ZuJVVB35fxVpVEw=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=Zibe7OOBbDWANjhv/XS+ymiF43MY3aUW9+PkAkZEU0DF1X4xMw3VsgYRRCDEayhsJW
         rlnk2RhR7eU7fElpyNNiGeVMF9pCLWAudkqfA337+sE0QRjAwC6+pAUDKY4NDpCxXg0E
         L3am/kfck43FINo0ZIl4AIH1jX0oBAEmxjUP6JWbl4Dsgcs0J7HDTzqIet0Kf9+Co4wy
         EuxVi/KrSkFczXUIkiB8o9ZLxRNYOWlKQ2DuUE2mbd7fnByCqq2DDC1ZzSSms9C6ni3F
         376Pqe8SX+N09+P4WDVzWkTgS84zrEMSKbHKluAtN2w06oJYbzMKHfiyK08vtvos3dl8
         nVPg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=U794ZqcJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=g0sfYPrb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4044baddb49si580071fac.1.2026.01.22.00.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:35:11 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60LMVwk83031860;
	Thu, 22 Jan 2026 08:35:07 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br2ypy87j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 08:35:06 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M7VlXl032145;
	Thu, 22 Jan 2026 08:35:05 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010003.outbound.protection.outlook.com [52.101.46.3])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vgasqc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 08:35:05 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=LGUx+bHLtRwqELuF3hYdlBMlmrCPiJb0RTZQ4flDBuE3EnTk6P4qySgr8YOVHFnkzTrDalfTaK2t//u+e3MZ0bFoV9ZrJcsJIaAOldX5nuvEp/TS8he/EA/rDMbgl4R6XhuQ2w6E8NFoUk0Af1m4Q5fV2Lw/IDL38z2c53Hs+wXKDPFv04s2VWAcQ7CS+ihKniWZeGRoY5pE3+//29TCrowcgsaTjYs/L4+EVG5w70P0UrwtbB4qLBTcPluYOGKG7Qk3+5D7dfy+NF6bDkYljdvuZ6NQaFVwHooAvjeEHbAY/l12r/obXSAApZ5wReCNuWpzVQJeJ6bcIkleUgCsOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+l12CrUT6YUbUBDe3daCr+Tva7a9ZuJVVB35fxVpVEw=;
 b=CtbMddEG39t+ZjB8Nw0T9GTe2Wv/xWWjHn/fFAFIgETPQjN1uS9K7ut57ZUF/cHQ/tJLSSn0b3enCaAeHDPgXOyPYs1vSd+CMye9wHeSLXQIRsBRfE/bigTwaqONMNq0ZpUaysA46TGTB4OqTGkDyWiyuZJu1DPBG8eWjvOWREx0+u45U89IsOrpDWAVbyIuRmYzpogYHl/E6mP060pLA4UGXd/JLq87W+eQ+t1Gh72b5t8TqDdAGxV78PwnZq3rIyolrVpGwQshev/xUdqi6WdBNZBgG3XDhBtKaDcIeuLjfAYI8KhfRFsQvohpMgJr6PpMILF7V+VA/jIzRWVmXg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ0PR10MB4767.namprd10.prod.outlook.com (2603:10b6:a03:2d1::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.10; Thu, 22 Jan
 2026 08:35:02 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9542.010; Thu, 22 Jan 2026
 08:35:01 +0000
Date: Thu, 22 Jan 2026 17:34:54 +0900
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
Subject: Re: [PATCH v3 14/21] slab: simplify kmalloc_nolock()
Message-ID: <aXHhLtuQMZbquJ2p@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-14-5595cb000772@suse.cz>
 <aXGC_JRmz3ICjMHW@hyeyoo>
 <3aa8d400-fa6a-48bd-b9f2-3bd6f37e523d@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3aa8d400-fa6a-48bd-b9f2-3bd6f37e523d@suse.cz>
X-ClientProxiedBy: SEWP216CA0047.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2bd::11) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ0PR10MB4767:EE_
X-MS-Office365-Filtering-Correlation-Id: c7483e44-4698-4ffa-7f5b-08de59912271
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?5zn/EyCv+U48qtt6Xy/2YNzpLYdoDJ2rRVUN6HIP2h8wbku7N/X5jZCD31Se?=
 =?us-ascii?Q?AGDTI9YUInOwPUs2gzZsdXILaBaDlpMK9wakQJ64rgCDZMHu32VdNhYX/O4f?=
 =?us-ascii?Q?krMEbemxhiJSps2L/dIzMiFS+cVKoqwDgLP08soispfbahETA3/Ec4CJ7C/I?=
 =?us-ascii?Q?pocPYQ8Btcg2tdM4X6WePHemXmfFhK7U3CKP/mxgcHYejsJefePyV7gfGbQC?=
 =?us-ascii?Q?u16ogcrvMkMXVDN5v4AxO8DVvjRwavNnOcJiEftIn2yutLRx9vZEYe0RkNeF?=
 =?us-ascii?Q?ZNvdFrzW1A3eSSaTRicl7I1y9RFeemXaYrpJwNpckTdszlB9Q4ZGiEWaiv88?=
 =?us-ascii?Q?I4P+8fXcrzD21YnA2Silve98Hr4HiErlawtDUvJc6WSXiiVRw6r59Mr2ds+r?=
 =?us-ascii?Q?VrytlBY7uoAE5jSz7DzrrABnDCri3XjhrlTPTZfYzzdy5OSojbrDwWLt9APp?=
 =?us-ascii?Q?jc6hIRWw1QvYmq6wZc0nxJqe3ZRccXKBp5uLlC124OmdYVW7TEd9V+U83eB5?=
 =?us-ascii?Q?e6TwODrW/hmlOpjy4EQY7OFW8PqPaGc6BxVnujLLljesrrL7IJ2ko7DUfNe8?=
 =?us-ascii?Q?cCJi3BE8v6sPSnXSBRGVsXVFFAyZdSSSMahwIsauuO81UORPDSw0RC9SlfQy?=
 =?us-ascii?Q?+P8DlLzyWKKAVdWF3kHuo+5udrlc9tb6tSRLTnZT0YIT1kfAxSZwLqPy4Ois?=
 =?us-ascii?Q?xNQgAJAVOssMwssH9Ur9NBnGyxTiVpABof4/L3GC1H2Qos3gvt9PyU+mS9HS?=
 =?us-ascii?Q?IUVp6e9WaCVgHRPfg2tts+vENMmhC/+lafGvvjnl/zNahtW5Gv6TCxowyI5b?=
 =?us-ascii?Q?mL0+1vmhsgR+eY9fCCcsG2s4MjtP5ZZuPskeBduDwRobOqfW1lL5vvk/6XQs?=
 =?us-ascii?Q?mYmomHtfNAT4UYEnEGXLdWQjLmH3AiM3si9sdQG0t5qEwwSNCpqYuGO8FrSM?=
 =?us-ascii?Q?PpiTaYjmOsycJ66mtA9jQ1yR8J2KTYdoZLjtlsPYShLI/XWOJj+P69QzTzTN?=
 =?us-ascii?Q?MAypVrebgh2r+SoYo3gp5OWGIxmSp6gXvMeqHng0oLsGyX6YH4Bkfag33Tr1?=
 =?us-ascii?Q?/jtzt/EkXaZ+VwKrHkcy9yVTnct92r943HKcdD4KHCCOKRc4MKFx8BtNaRFl?=
 =?us-ascii?Q?dhSXIq4T6qiSA+UbOGuTqSbZtZdhzAhXTIRpXDu5Ay+PM7yfqBrZ3KoK0245?=
 =?us-ascii?Q?BQBb8zKktgdDz2D9E4y3JkBgFD9Zd3dlPYdhtdxA6xqiZ+rrpBmZ9kwBOQ+b?=
 =?us-ascii?Q?VXn7JtjIsxYTRtRT/EdeWZpuGGv6UFYneDbMKAr+mz0qWB5+sRYTnDyIyERA?=
 =?us-ascii?Q?K813fFjdY6z0IXz4p4D5F4ukJ/a7u7vnip7YuJbti/e+yyVsMbGDcnjTLO+Y?=
 =?us-ascii?Q?5pgIFqRteKZsoTqn4qRvW9QvfLmz6TV6Fz+G3NgcrmHl1VxKSW66/kOGBcib?=
 =?us-ascii?Q?scYStzL0thTW6Y7d26QpnfLAzA+VOUmY2bPBDixAwxYjB61pwBM8wfGrktlw?=
 =?us-ascii?Q?X2cg3O4JpuIwAcw3ySdFOYQLFuOjXBGIHITgq+2fKu+IrvIpNMJx2Igwx5ct?=
 =?us-ascii?Q?MYc3YtAxcOYyxe9WBhQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9zemOPkpNhXIP57X6FouoTymaOz23FXg9H9lkCtS4/NcpIHu7wpLehVIJEI6?=
 =?us-ascii?Q?XnovCS64Zjw5bAWHPQ/9S42dqca3fGU7MTgeEaTJuovI60oyeZjxNYEeGy60?=
 =?us-ascii?Q?KaNT1byiTOIhHloOg8KEZe3aFadLpKbGn6rJ7l0/6BQXPmI7cQJXqpdaHK7s?=
 =?us-ascii?Q?jKm7UpF+ZO5mO6a81BMugeKJsqC3WwrX3wNTzhQ4PhTciSDfJVpQPJKV8AbB?=
 =?us-ascii?Q?wjcsBwCzagyA6fpvQ6lt/ldKck2JnCndyAiWm+0c7m7kUi82y7c99iVJd0Lh?=
 =?us-ascii?Q?17PnqQV8cafFT7nAaXVRTtvCvAbnM4J6S1Aqh01MC6oaDeLMBUDYoG/KxNNj?=
 =?us-ascii?Q?Al/dRw/meZ67a44W/dh6hM0pCGGesmljngKcYWQE9R8IWrAg13YXpf8pD5ZN?=
 =?us-ascii?Q?lR2OXK4ZwUIgqViw6F8Y8/Mn+5ZB7aY1cEjF4ZeXx752cz5l0wWtzCwwJcyG?=
 =?us-ascii?Q?Kv2X0D4Dl/4lQm3Aw4G5MCM/UNQ2aJp2fIhEZYo7tUqv42Nhu0Kqv5eMvsth?=
 =?us-ascii?Q?BoHkWNOlJjooQj4r4gxOFoTd329LL690giJN/SMzNkScb0yRD1ueTVoEuUTQ?=
 =?us-ascii?Q?OxuL0i+NiW+dAlSjbuIZUP12fyeM68Mavxtq4JIoZuEE7XMEOjJUTahHNmcz?=
 =?us-ascii?Q?x5swxt/59CDBPPiyjBHCylBoUk0C3rnetK7D7N2UzE6ZQ21ZDg3ax7plUY2k?=
 =?us-ascii?Q?NSg0e9kxpgmVwI2lfwaf207ztFPz4aM6cJxf4cKV5XXHgXYSQqLxOrARlmyt?=
 =?us-ascii?Q?+C2ZVE0Gi87fTmtWdhdjM1tO0+IZrwjjADL1JD8m4/vICXh2aKQqwOGnr91G?=
 =?us-ascii?Q?HYzBPQBw98ixS02xswFTgFieXoo3cmPueT4ZTTuHHnnv3BSBlMWcanchEc1Y?=
 =?us-ascii?Q?TUew6cAyDbkiR3AneIdpir+USf58YnpkWt8hkevZ75VKS0KH4s8QxUkrERpf?=
 =?us-ascii?Q?h8lZcW+xY33Js7mF38RryDM9S8o/IvCnR1aZJKIAjz3bfgpC0RGFq6qDDbN8?=
 =?us-ascii?Q?S4Z5z/oigpjV57mzYMTxtR+FEbaXjaQ+/2BjnzKXxYpKiIv1GP4qO9U8x90s?=
 =?us-ascii?Q?Bz7H9UJhCh2nPpa6DOG+U7RasAikwKRcrIjmU6VIIHt/6M0G4CpvH51BiusA?=
 =?us-ascii?Q?b+1RQM6vMGipqsUFton6W83y446/0dsHzx/tI+VdI8csUOUV7ZivBtVV6VIc?=
 =?us-ascii?Q?9zdCndVku2clCpH0673Tk5HfbY90eKsd0jWSSq7AnEA8UXlL75LXI6kseIWG?=
 =?us-ascii?Q?thtiOoQ4Ant5gQmojQ48YOariqUoaiVrLFTBlEuhSAmLlkyszkMCbRRjRSjC?=
 =?us-ascii?Q?A6vCnUWSli5OZ89PWUOTCivJ3Q+yaOgiNx24ttp/DiZTAnCGgL4I91CRN0UD?=
 =?us-ascii?Q?sAjQ4w9hbtirrj9VQfzY9yddMsCJJlXT+xEP521SubbwouerM+hw/5YhmYOl?=
 =?us-ascii?Q?5lhSKnSg1soYRKzpqhk4HjjZF5VeEAvnnPYijSQfsd6Q2XJZyUafnjw0MI6J?=
 =?us-ascii?Q?w3WMrAOLC/nJW/H5k10I/Zjr6RbFhx/tWIr0Wvourqht9alltTVMIZJlJwNR?=
 =?us-ascii?Q?v76BC9W6sVLqEd7IkSUh+YMC8OceuH/Q/0PPsENRjZCpIYSXN4Z/U8KPvIAB?=
 =?us-ascii?Q?H0pkK50WTaD+Mpn2MdsZCFlGF6UkokPpi542KtAkBjnI73ot5FDnSIQqSpUx?=
 =?us-ascii?Q?F0H+v+tYTqKi8+742gvi2t/Nw8qyFAQSNMG4kfZfZUJ7QqZgk84fHk6WaZzL?=
 =?us-ascii?Q?GsyKj49M9w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Ksr1wpBXViAxsREOVyb0A72tutnsP85NY2ZjjeixpV04qgVvj+7NFyDu19ykcv6xE6Oden6pldC5dNg6W4AIisIZ4WxjvaruH4s05OI9Du7NJqAYRbE2iuZuHsQgEuEJ6FJ4QB4oc0zQn4e0bztseEmUNhQk7X1IAf794l3WIU19dYqZ1sO+0WskATHC7h7DSuwuDVfcvhU3GBy2CaPCJngAO00hK/X3jg17iWUJyOrpsqbNAoll4LmGwNHBL/+0MmW2/Dapq1IqOG2lIfpx0usGvmB8QgK9rLYaH/uG/dtRnUghek0gjqd/l02ZlJ/Mp/w1lvlN9OKi7kGEMWtYgCYJerg+21dfCHVOHUATNEOf17WDqqKt6FFAYmoJkM1ntqG/4YPA0N9VTKOKC2rzdsn7xEknhxfNCdNq+cgaaRDBbqPJnBEKIKzBSvdao5QcahUgodVS78/P+9AUjUwUDUqfRbR37EXm8LTTNyzlTYc4ybMLQKSK1PADEd6fABuzvCY6Es2EJw3DyzNHXhirQAqVODx4lLH7EWcEdGNR+qPjVNqWaQEQAyJwGVu5CakkBiKG87Az36o+L20Jx75EvuPc8LMC4nmOrIxw4WVkOW8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c7483e44-4698-4ffa-7f5b-08de59912271
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 08:35:01.7469
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: HUG4hQcW6dGUKFnGkKNFXo17Nj6nLbcvk3bHY8YGFJCb5KFYreiIILmGhpZwBQ+TUaIT9qYsAeEWpN/5izOiUw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB4767
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 bulkscore=0 adultscore=0
 spamscore=0 phishscore=0 mlxscore=0 mlxlogscore=771 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220057
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDA1NiBTYWx0ZWRfX3XgJ9+tKZyEc
 yAB24itrVRgL0t6XSr9924gvWOcevftPd46tknrvTiB90H3TbHceWjcE6I0ZEufS9Bahpi5uQHZ
 pCp89I71/Y/SDwOFTLPIrcF1PDfNSqwnAevcs8p8xRBRiXGT22vCXbF5jcbSSTZJrzyvVVjx+fG
 zhNHpRrDhFz+w1Y2ntHFt5O85mQso9Bh4VF1Ez8Xh6RmFFgQVlzaLckcBlfXssfECKhbLCpUPKq
 VTc6yDxR+XoMRqEeaFbY9L03c2/7TSEN2liiD/+cSm7pPiYsN0KfntCgbb18qmhWjg5NSBdaRcQ
 DWKxvm328UyN7EL/eV49Si/QSinxeuSe+77R7Cn6pxOWqE8quSeiBgZNRUcg3+SdPCZUiVqlGHs
 6kmcRkI2Ii6STBa7oKhM0A9fGhBFONiramu9F08J08PrZ1QAljw3xlFbw0IEsL/kMFrWZAvYzXj
 lFmYUDlk8/x3e2AS9HmTy7yW+jHb6iW5Uv0WsDoA=
X-Authority-Analysis: v=2.4 cv=de6NHHXe c=1 sm=1 tr=0 ts=6971e13a b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=e7c8kmyVcqSGSyQomPQA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13644
X-Proofpoint-ORIG-GUID: D_nnCAO7i4wRKCtf4v7d0l0mGWljaWtH
X-Proofpoint-GUID: D_nnCAO7i4wRKCtf4v7d0l0mGWljaWtH
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=U794ZqcJ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=g0sfYPrb;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBQGCY7FQMGQEHP7MCHI];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,googlegroups.com:email,googlegroups.com:dkim];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 0152863252
X-Rspamd-Action: no action

On Thu, Jan 22, 2026 at 09:16:04AM +0100, Vlastimil Babka wrote:
> On 1/22/26 02:53, Harry Yoo wrote:
> > On Fri, Jan 16, 2026 at 03:40:34PM +0100, Vlastimil Babka wrote:
> >>  	if (!(s->flags & __CMPXCHG_DOUBLE) && !kmem_cache_debug(s))
> >>  		/*
> >>  		 * kmalloc_nolock() is not supported on architectures that
> >> -		 * don't implement cmpxchg16b, but debug caches don't use
> >> -		 * per-cpu slab and per-cpu partial slabs. They rely on
> >> -		 * kmem_cache_node->list_lock, so kmalloc_nolock() can
> >> -		 * attempt to allocate from debug caches by
> >> +		 * don't implement cmpxchg16b and thus need slab_lock()
> >> +		 * which could be preempted by a nmi.
> > 
> > nit: I think now this limitation can be removed because the only slab
> > lock used in the allocation path is get_partial_node() ->
> > __slab_update_freelist(), but it is always used under n->list_lock.
> > 
> > Being preempted by a NMI while holding the slab lock is fine because
> > NMI context should fail to acquire n->list_lock and bail out.
> 
> Hmm but somebody might be freeing with __slab_free() without taking the
> n->list_lock (slab is on partial list and expected to remain there after the
> free), then there's a NMI and the allocation can take n->list_lock fine?

Oops, you're right. Never mind.
Concurrency is tricky :)

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXHhLtuQMZbquJ2p%40hyeyoo.
