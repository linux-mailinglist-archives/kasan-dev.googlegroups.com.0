Return-Path: <kasan-dev+bncBC37BC7E2QERBGUXY7FQMGQERE2BZEI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id BvNlGZzLcWl1MQAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBGUXY7FQMGQERE2BZEI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 08:02:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D9AFB625FE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 08:02:51 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-89470bda22asf24115986d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 23:02:51 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769065370; cv=pass;
        d=google.com; s=arc-20240605;
        b=VD0kkNVJuM5BYbT2ktGXQf9ttIPXT98DqkI2P/bcSKzycqE0uaBU5G3Qzsbe8+QJFA
         Gh3CEc+UginS0h30f/4opmfusteXJ5T2VEZot/O7q1vI0/EC3LG4TK/CDa5d+5BrFPOB
         i/vrmoGGBuT/ulMBfr1oDARN5hWDo6aHj3tA4qCxaOEd04q8omBuOZR9jWVe7IA1CSqZ
         uTc3M9qJo4HDto2p+AUGMfvFNvWXAE7rON7UAiMgbCoZcX/s7w+WMjwVcmTDzlJgFfG5
         BKol8GQnyUzmMEKpr/87rJv9sFYyzZwuh5bN9yGboBPZSmdVgmKRvOwy6HHXmOL01kU/
         3TNg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=VlVBKnaD+V1UNf8PnR0Y9TZxbsrGAyLNRevdDnl/oMs=;
        fh=gflbCONCwz6wbde4aXCpelWqD9+Re27ZPvdWGGiuN6Q=;
        b=aYnQjwB/SnhvwgzPYtycCoiWjXij4yYrLUhGcVAMBGl9aSTDt1eF8B/7Kk711UaJOu
         DHi7bZZCO3/wYFcI1qvfCEa3l1+dHCRpx9jtzL+zsji7qsroPBFAtFWJbXMXXrWjMA9I
         T5g6zvTiXaDaM/GR4spWfMkkAYN1lSYfJy+77XJKkkY1gqIbUjpIZy+SgzJc0hJ4rMQx
         SQDjYpQrs1JvG4pLP4YNgS1ROaohqMaqWPKLCE1HmwzZmCxr7WlmhOkCt7olvk6gAFxi
         AupIiBSddf2ArQGkWYbmFz+BWVGzVA64S2onHZMjS25yj6sF4GJq6LSq2d5OX91FRbcE
         43cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YAWSWHrQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hbmaqfi8;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769065370; x=1769670170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VlVBKnaD+V1UNf8PnR0Y9TZxbsrGAyLNRevdDnl/oMs=;
        b=bXHSf1K3+WUM2yBPKWHw0nAOTbk5S/z/WUZ6RcB6CQrlqp95dRvBVKhniKtl3C3lxQ
         NSH1m7sTqanx6oXxFASJ+UvxJ9lauV0l3EE3stA8NVAXmsJBUbTgj+hTggUVdMn+2cnz
         9zXyacs8u6e9PJJ9mI5MJlavUz/rUTwC+bS2Z4yp+xrq5TQv3xPKtZG/IsajQHld7KBw
         glvZBlLrO/zrXGcfry8NzpqH0iJFP1FvSkZtmV6ROVj328S3ng6F1kTO/oI2EoxSSndj
         g1WtU5BFh6tcs7ebEUMgV+YzIPUHs3A3pmSdRv2/Q/gNxmQ7HbCaQ7StGWrLUuoYACV1
         3GWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769065370; x=1769670170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VlVBKnaD+V1UNf8PnR0Y9TZxbsrGAyLNRevdDnl/oMs=;
        b=k0FUzSe9a4kwYneQM+R1cfRWWwiCFeR50LJ+SQsW3bDrAqrEkxbKJcr0ksvC1hFJaE
         uE4orY9ZbS9UENrtRhqJYlHOPK79491C0JpspngjNWc3TcJDK4039FJ/LaPevcsceUL5
         Twjzviu09HN7KGwKWEVii+pdxXct4Q27R52JH5nHn0/vaMDKywnUfyx/KXkOxK1tfrC6
         uu200ypNoOIaOyXfd8zEeCbkuKnhonqQIgc7yQeFlMLLxhJ2k/R8yQLD8zF7SuYsazAP
         CidRN6+fyWUTSIBgYgCsptovqecVaLHLc+zHDeho6fhrhWdNJ/6TyQ79s5GbHD3m0hfH
         QS/g==
X-Forwarded-Encrypted: i=3; AJvYcCVwCO4vi1fMx/7kgwf49vctKPvDPLLsx1bA9cr4RQUzF/C/Q9FYXOP+7//Ord3xt8mQHzAvGA==@lfdr.de
X-Gm-Message-State: AOJu0YxDFtTay0Q9g/azDHlGahZ0ahOASK4zCfWI0P80wmyd3fFP8ELI
	Fm16N9jrZy9HfCvYo2CO9SAQgIyrbZZf3ERvcrOLumgq71c5DtZt1u79
X-Received: by 2002:ad4:5bcc:0:b0:87a:903:17bd with SMTP id 6a1803df08f44-8942dcf6fb2mr320331186d6.20.1769065370431;
        Wed, 21 Jan 2026 23:02:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HIBN8iNHX8B8Sw7wmvuZs9jL9S9kyXfJY5lbwKfCx6yA=="
Received: by 2002:a05:6214:e8a:b0:779:d180:7e3f with SMTP id
 6a1803df08f44-8947decbdbals13362306d6.1.-pod-prod-01-us; Wed, 21 Jan 2026
 23:02:49 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVbnltG2oHHVxe23HjbLjd0y2lCsiCVmoZtyhRrydzeiWEiRD/N45OPL7kEOVcBbLMXmlUGQiqn3tU=@googlegroups.com
X-Received: by 2002:a05:6102:a46:b0:5f5:402b:7ee3 with SMTP id ada2fe7eead31-5f5402b83cdmr66826137.14.1769065369560;
        Wed, 21 Jan 2026 23:02:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769065369; cv=pass;
        d=google.com; s=arc-20240605;
        b=XaoFR3Tx2C4lomctCmf05mFkROre8pKJjGYdxXEXWdznI/qqxg695R1y8NgAZi9mqi
         YeOuCucIft7C12xTN7KkFYtpLCUPjunr8llO9L11BYWf53xTbvtSQE70VnIcyhme80Xp
         xpQA7GJGFP6wY9QCtjukkX6rKvIAqQm6n+BGZtuCnC0ok+XeJJnOgsrIuQab1dzIzfoA
         AJEVVsEkoUnGhn8RoMYopZMUV+DVBt7xcduG0+2THZ3A8ZbLnEY1hCzOWi0G/SnMB9dP
         RyDZEVqnj3cbur/uFJ6MIGVHmJJeANptBqlcXNRzEssm1A1/fkYaUQ9syCnbnqAlY0pp
         Er+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=SDOmLKkYQjftB9rH0rxxv3towFGZCxeglCreTScu87E=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=Yf18betJjneSItIGYE8+7ZZr46qjVgnE7xMWjgnNyty/6kA1QRgQaegE81scsuzdYU
         2AKRtghP2acbLN61rZRRucFvd/MusRtm+U6bqx4wFbO48czpP7SWzPdReB/7hjBRZqsh
         6byMx09m7aKXovoSyuaLWBHu5KOplnvc8OrU10s/HgD3uzDDQJX9olSRtzlOJiPJvDX3
         dWjLPe+1nWpTTkJ2bv06mpIOmQCDkoAU6A2+cqRYgQ3KZbtFvgDLmMrcGcAH4Ba6PpFm
         aSWQKcNTmci/tMwLpblxhicOQMlyfiCbcKqJ6/JJ4PsMA6ZWolR8ueX5fveFZGR6mYAw
         xa0A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=YAWSWHrQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hbmaqfi8;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5f1a6f4c6c3si562262137.3.2026.01.21.23.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 23:02:49 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60M3inmL3626777;
	Thu, 22 Jan 2026 07:02:45 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br0u9qdf5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 07:02:45 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M6F1Gq038803;
	Thu, 22 Jan 2026 07:02:44 GMT
Received: from bl0pr03cu003.outbound.protection.outlook.com (mail-eastusazon11012049.outbound.protection.outlook.com [52.101.53.49])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vcdawy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 07:02:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EBTErbAQikE+4Nd+dP88RvaIzkioi0aSp8787Xd1+bznmN5wOASyI4XjQx7za+P+lE9q7fGXMBE+xymrWGU7lwPOKL/8BoXJxg5qgucODUUc8uOW9A0EGoLVkyAGnOKzvTrrLmMpcrt1qOApg23xOC3f/n7kSzLLZMhErcfk4Jtq4QCyNp28cxq5CQY/JtW56BzEBu/A1yYvyZnAVR55td61zCfErdApZTLfmfZRy8B2LKXsV87ueqnDN8WH3PxyNTIDbWOuT7MbaRmmL2GUA9ackm40Ut5fhN5alSZDHH7wPJloheVppKRYboV5zMBn//9jPUugQ39XBwtUQHbNvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SDOmLKkYQjftB9rH0rxxv3towFGZCxeglCreTScu87E=;
 b=fsWYQPobvKbHQ6+cDlV6Ace8Q1RU5o0GltN/38sdjT5KOERh+8h5a5cZJbZE7U5y2wz7vfiOfCAhgv2MMJWr2nGGls3Ip7L15HM6angE5/WqKg3AoHfQW1hdsihZE+Y+aC1/A0+/itB/AlT+Qqsrbr9FeC5ARCwUzB3pPxrZC9wv+2pMHxDn/NP/KPdC14Mh5BIyoiKmcJbYlBGgGVLfOrF9mAN+YIIpeiHoHZDiCzdaPzflomvibzT48qf6OmKi5ISziNU8KfleM7i4modU/KhbVYd5zK8BUBktx93aB0cA2gffNZOdC7ptkeUFhMbBEqZzjeKl7vMCcM1J8DIaxA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from IA1PR10MB7333.namprd10.prod.outlook.com (2603:10b6:208:3fa::10)
 by IA3PR10MB8563.namprd10.prod.outlook.com (2603:10b6:208:571::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Thu, 22 Jan
 2026 07:02:39 +0000
Received: from IA1PR10MB7333.namprd10.prod.outlook.com
 ([fe80::e8e9:f35e:8361:ec06]) by IA1PR10MB7333.namprd10.prod.outlook.com
 ([fe80::e8e9:f35e:8361:ec06%7]) with mapi id 15.20.9542.009; Thu, 22 Jan 2026
 07:02:38 +0000
Date: Thu, 22 Jan 2026 16:02:28 +0900
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
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
Message-ID: <aXHLhF2kJxgy4M00@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2P216CA0097.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:3::12) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: IA1PR10MB7333:EE_|IA3PR10MB8563:EE_
X-MS-Office365-Filtering-Correlation-Id: 682029f9-7595-40ca-fdc9-08de598439ad
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?WcA+3zc47ooQapc+9vGrZsDoMPEn1ovFjcgUf8GyCLBi7j+dobpHGs6aAY3/?=
 =?us-ascii?Q?BqQ47R8gq1NWv+M6vYLpheNTbdBS5fCokND8uXleGrp1QtfkPEX8RAElMaCs?=
 =?us-ascii?Q?pUbnzNFqIk296TihizMEL8AiqYjb7wix/3bpq5JPc8AYAm3syUkmN4DfKGT8?=
 =?us-ascii?Q?ho9tKJvUS0U1Vu653fg96Y6h8LUxeIHuxEPxvJT4fZda//0x+wNnMWwuD5u/?=
 =?us-ascii?Q?xizJWvXFbAnOwS0og3m4oBYKUQpfhvqCh4lIRyyZu+KIKT66vqcRDb0P4QNc?=
 =?us-ascii?Q?JcmbW2xmRk41HkzHn45OyA1iYHjrS/0KzR0AQbpFa/veWqcr3ZnyVjwH9R2m?=
 =?us-ascii?Q?Ikwr3at+iTeUYlbrcUZuOhWJFbdp3PW3wZWU7nr59bqRhgr7OnKFQGWEubW5?=
 =?us-ascii?Q?Sf2p45x9kZClMLBstWbaDWQY5slSexJYT/QYHWuqDQfkqfTKeESqM0g203fh?=
 =?us-ascii?Q?/n5yMBqvzMejgDYRW7QO9H5CR+kyuDOZmC2/JBgoemqjNPeZv7FTvXOGIsaE?=
 =?us-ascii?Q?aSZH8MHVy7sORatsx9DvKdDjUBJuj+5KLdGx22n6h9tAxDkZWNJQ97KHpEcH?=
 =?us-ascii?Q?E+1lYJWO/sXMj7usa9TZ6nF+Gj2bciIZIQ4hgNKcleqouzPNlbEPjuYJFN8a?=
 =?us-ascii?Q?k/azrrfMCLhqlf+Aw7aeyqkHWUPuDxgvkAcPRboXNbua23weNSUsI0CGIPhV?=
 =?us-ascii?Q?2Lx6rZ2YX6dy0xukZ1VBzjYbjJ0i955KAsY+H1ZyXHEDDYzLEPpg8MIRDIcc?=
 =?us-ascii?Q?Vbk1AMy2YSWmCaDQcOD2YBBD4fasBc6Mu74c26qTDbP5pH4ovhi5A+Ar9UZI?=
 =?us-ascii?Q?MvJmmjPMmkoNa+viG4VzIq1WhS3z7JiuJSRFerrYNbW58yFJToNBdcp2nM1C?=
 =?us-ascii?Q?noodPiYYMT2V3yEPKWTXsPD0/ljctBVxzziP3GZm6Y2xyrcSTGaamXjNc07x?=
 =?us-ascii?Q?SUZBrg89kGHWkWjW3v8JfBzD1DYDs8s1uBDDHn9csKglTe6NHhK99NNqJzeG?=
 =?us-ascii?Q?yzSCGpe5Gn9Z+BksJ5t3c3nU6bjalym3+A1aMjyrTbYLnU8RhgGDdT59Tce4?=
 =?us-ascii?Q?heSQIZo38Y8VSeViTlYrNGsHRJ0kQ81+tyK3DtkKSXX8IeOpqX+oCOq/68GK?=
 =?us-ascii?Q?FGSAjh4s9FjbTA+Q6jk8lTLACz5Y1XGoHuuSwHQXPXCe+L5pFNGlbXjTjepT?=
 =?us-ascii?Q?MN7voUliSvVvNan2DmAaBPW/zaZCyqTdjbVnaUecLqXuvn4FNxHttx3grDCf?=
 =?us-ascii?Q?80kDAjM2Hy8EOK6xQDE9pq8vcZSDYShZADqr2pAQp0gim9o/aNoY73rv2BVy?=
 =?us-ascii?Q?GpycUDGvO715KRtK0jL57QNbYTDNvNMwzhi8OO7k/mdKM2fowpBvMn6x1je+?=
 =?us-ascii?Q?0znOl7GQNCixytr1AMdnYssxkNrXZFIIVoYurvPdulNMFOF6tuLb5GrFOGjg?=
 =?us-ascii?Q?Kcv66/XtTO2oPpwEjfY8+gUjTh71rFBkHLTSt4rzWUNZltHsQHQhfFTqamRJ?=
 =?us-ascii?Q?26kDfF9g9W653uiBQA6f0jfymf0ZPTtAWSOJJ4RZJFfyNpY+St69VKZ4BIvR?=
 =?us-ascii?Q?BcOXFakEkDApuuu7kfc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:IA1PR10MB7333.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?2NJvVn/SUro499mcyGMnSCtJwhr5C2CIqV6DVchFB40fmDTI7ckOTQcISjku?=
 =?us-ascii?Q?eDUb5q5GMemnIgEJZyNUGt3Sordn28FkyXXeOmLLQW54mkh3PKzRXMN8MGww?=
 =?us-ascii?Q?uu2f8I6q41MgS7QBTRGYn4Y7NKCbQFL3aq1ciZ3o1aMQYxLJqie9gqZPmMgs?=
 =?us-ascii?Q?x0xnStzrdItE+zoAO9+7RE58iQ3tqrnzIx4AXOuPaY187bU42VoSNWTNkCqM?=
 =?us-ascii?Q?LWN2sIEQTjqc8mQx8XhM7d2Hv5SYPSqu/UJYb9FgCcTla6Qrmo62dbvFBQkb?=
 =?us-ascii?Q?NW3Bbrl7/LEFWL7p7BOWeJjhYJlp2RJ/hSsUizWdrHiLTQ0Prn9hIpNqyLhI?=
 =?us-ascii?Q?6WJa9HI6JGRKDnQlR3LWob9iygd5Pn2PcE6nLzSOVdEy5aQQq3Fa7rGpIXqN?=
 =?us-ascii?Q?WYY+YHgiddWWWbcvX5/Sv9pUu0oNvA5MmC1VvFqx8ALA6mfMuXSbUiH0o+Fg?=
 =?us-ascii?Q?As7+ZnG6kHItxX+VHMWAcZvinFv5ev7GidaUpdq0APmerX3KahFKZqecGy0C?=
 =?us-ascii?Q?UvA82tYQob/K+BwauDE/yF0c6HD860reW4D8TkWaRHQpplkL+YIcQKM3fex3?=
 =?us-ascii?Q?BmUzNpgbOdi/SDXwEEZpjV6dg3XoC6rrq8a6mP7NsXKGtZv4qV3jTnsjYt9N?=
 =?us-ascii?Q?ML4ispkkTaDHyLYpyRPCvvF3+NxjnhGtg904TVgBrpPulh6SENUIVGRtlkCO?=
 =?us-ascii?Q?fkYOjG4iT8+/3W33Kvh6fqilxK2HsKymd3BVgps/NFb+6iMUta6XoQE+sQDm?=
 =?us-ascii?Q?L7l8anVIlj9mAfWyCwEXXa0ibm/gWUrEd/oVcv1gITlsThCN4To+4fxqs8uq?=
 =?us-ascii?Q?07i4/ckkZzphmGgZA5mKaJFRcrfe+8oxRKjABXa100i2zFJNTX6VdQzlXNcG?=
 =?us-ascii?Q?V6xAnKsXNDQqXvqdZnzG8X3XpNe2pGm3+2BC6AwIITYz44BFPwDpF3s9gPHb?=
 =?us-ascii?Q?dr/hjp9bKCazpcYN6ue1fh2lna6Cua8ihwkZtYwAr8GBUMciY/Gx64K2s4In?=
 =?us-ascii?Q?3qTlhm35oViVbp5T3TRcY4B9KNvQY1SNljeKXy6uypwgOyFupC2Z+MxFML2L?=
 =?us-ascii?Q?olPeVbVn1kwPYbDmGr62SdFX8arPA7cQi867nZYgi3C12rXhWjID1QS9TTVj?=
 =?us-ascii?Q?Bsm7Z5NEf7VajYMhBzPnkqhQa7PRyHCkoo5JGyAmVYH2sVhfwIdrfSRS/Li7?=
 =?us-ascii?Q?ZCc/JoQ52s+2Cf8xVF7RkWWYL9I2Rr43HPhSt7eiawKgQO9tvlck+jXwFDU/?=
 =?us-ascii?Q?xzskYwSXh0T1sJsdBXU2SepCXSOu+P+U3JdRJASWex45BbiWq25n25t5upl7?=
 =?us-ascii?Q?4itDPQBtoLM9Jx/PxFkWsNRJnCJvmMyeuy8VlF0Mn+pMt8O02Q83LjKlyg+k?=
 =?us-ascii?Q?zKp2Baek+5KdXeCF4rXYpbXcPl/vdTQq0fut14pR/9zSCA2B7RMo85oUHVGj?=
 =?us-ascii?Q?I7T4eMPR6r1xzoWkAJ/SnQ5h8x11T/LYVHIl9G/13lyBFvJOI0VEz7poJq8b?=
 =?us-ascii?Q?RIt3Bx1rX785vWmTWl1VG+rEFU4evJZQ6bqRRrFS1rM4x97nlanhJHwjf8kG?=
 =?us-ascii?Q?2XuNjal+0ivq6CZ+Tmls/N54wWTriSHYFT3EBUqfL5dzxwVGrjUmisRaIw+7?=
 =?us-ascii?Q?WueLstLTc+Lsj+iFItEAYBYzjIXU3lKGIru+WKWWOGTHpqgcJxL+ZuX3hMyL?=
 =?us-ascii?Q?NMR0KovB31aVY1BWhRg50syiq6Q5/EPYm0buYKn7X3cVjtWNh5NCKHavbkHd?=
 =?us-ascii?Q?GYVwEKZC1w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: vdHvUA3+8RZP3BCEPwKMPPyBx/uxLDUqYha83z/5ja/WBkLHugCy9ZT+x3poTnGpi5SJM84fR4nM0Aje6jPsaNC83FCmCiyG9F5awTrb6ND+BNT4RSFCULbnNknsI3x6YZ36Y3EUeYt7FAloSCXPgjP2bKQzoeqQ6OOcddUOb5o8XSY7ZjR9By1+/mW8QaOn1Dq19eTKH7dz+bTsPgprx51yNFlhR0oESY+6q5+Tv8cxZ9Pjt0FBGeYs2dcDRgeqvNZWlVO9+tU9D9Vd+dWS0ctQ7Z87mDs8ObXXoFkOOHlf6wIRwTWfnQOIA4+GqXd11FwLgrvBCzFwZruxLqqr8qKTh537jG9Q2JdHGht8AhqrwuxyAgqoBr6iU07ycNVEkeOXOS7+uIWHIvhqa+2MmS5ijWfAQ4E+MNWF2WYkUk7LyNkujgBHd+G36qFa1dj0qZ2btDG59l+BefQbNuFrQ5kHALEIU5FTnI2+xIkW3TPh8kvS32AL+6fEAdNTqjnm0wGqojwck+AfqucQNCvggjcrgW52QrkZ83IkgDI3KZTM7fILUjE6BZseN3J6Br89iopm1U3J7AIJgzyDfya6g6LLZcVyiF4Ljh2sSuK8Y0g=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 682029f9-7595-40ca-fdc9-08de598439ad
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 07:02:38.6758
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ccsKTQ+FzbJCe7u6V2k1ByYw5iY9hEH29fTizSbsRbh/WoGSDkKxJ8gIN/dbr1CzRt8ta1iIYA2E2JQfv7kyig==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8563
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 phishscore=0
 malwarescore=0 adultscore=0 mlxlogscore=585 suspectscore=0 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220043
X-Authority-Analysis: v=2.4 cv=OJUqHCaB c=1 sm=1 tr=0 ts=6971cb95 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=JuDMzERyrGprox_VUIoA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: 49HHSvJJbOBqt1X9DvHU3KROGWuhD43j
X-Proofpoint-ORIG-GUID: 49HHSvJJbOBqt1X9DvHU3KROGWuhD43j
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDA0NCBTYWx0ZWRfX2LprcWlHfJXg
 IP3iHF1NZqTA48GXzKh1sO1FXvHg8xaymkBOnb0p0hq4YAi5GpUEb8bJbBtGf2XyRJZrMinyJdo
 N1r78trD3teLc/OioOYldU4b/E/seDjkkazqSUued9eLfPe02z/D7+Ls0PuUoiE91KLoRLYcbjm
 ebbLHTFIoW2FUCyQ/SsA0Dv1pvIyZX/4NXPIjHQwxqQ4lFqMNXhvWhvSOyWYefBRQLOs2Oqfy4f
 8BqzObRVy0DEiAZktjKy8NYsQYPxhz/F8Tw1/hcrR2hgG5ESG3jN4KwUf9O2Cz6PzquMvVM1Y4N
 aeIxu2HOsBWBTUUWb/G0Cb67pyzcADMbwDH82q4tXojUkPAX24oztuGxJUqkGYpTdUUqCDfsIbj
 huT9iNhxc+N5z2wgGofuVxKZ8yk3M1J7RoJcxnseFUlLDbgURK3FBskMPOJv81hEQqmoERHI8Ti
 fgwlIpQk95/FIPD31CQ==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=YAWSWHrQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=hbmaqfi8;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBGUXY7FQMGQERE2BZEI];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,mail-qv1-xf3d.google.com:helo,mail-qv1-xf3d.google.com:rdns];
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
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: D9AFB625FE
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:37PM +0100, Vlastimil Babka wrote:
> __refill_objects() currently only attempts to get partial slabs from the
> local node and then allocates new slab(s). Expand it to trying also
> other nodes while observing the remote node defrag ratio, similarly to
> get_any_partial().
> 
> This will prevent allocating new slabs on a node while other nodes have
> many free slabs. It does mean sheaves will contain non-local objects in
> that case. Allocations that care about specific node will still be
> served appropriately, but might get a slowpath allocation.

Hmm one more question.

Given frees to remote nodes bypass sheaves layer anyway, isn't it
more reasonable to let refill_objects() fail sometimes instead of
allocating new local slabs and fall back to slowpath (based on defrag_ratio)?

> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
> might be refilling a sheaf that will be then used from a different
> allocation context.
> 
> We can also use the resulting refill_objects() in
> __kmem_cache_alloc_bulk() for non-debug caches. This means
> kmem_cache_alloc_bulk() will get better performance when sheaves are
> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
> it's compatible with sheaves refill in preferring the local node.
> Its users also have gfp flags that allow spinning, so document that
> as a requirement.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---


-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXHLhF2kJxgy4M00%40hyeyoo.
