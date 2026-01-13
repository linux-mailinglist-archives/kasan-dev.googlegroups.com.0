Return-Path: <kasan-dev+bncBC37BC7E2QERBJWSS3FQMGQEHQABQ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 41E68D1641B
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 03:08:40 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-88a43d4cd2bsf93197346d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:08:40 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768270118; cv=pass;
        d=google.com; s=arc-20240605;
        b=YC4TNnqGKzGMxQp0zcB+JJghWC21nP0tT2qfrFmi6g0dC7oproh7Pls1QTq50OYn93
         Uk8EQUc9O1UECa2gu2gHFcKHMZvOh3opwomwYRK6Q2T7XD3cALMYSgbIvdT3+8KkuAdJ
         pduuNmUtjXiq2X7A/5lYAXu9U9aY9d61cQz4cBAlONbXelqTUymc2F39j+YuCY5YVYAp
         twWDOZwW9A1x1IKjRxn9TZYe/Kz9pVsWGT8Ep4luH+UWzASAO+V5LQgIUoluQU/qsQQn
         /hfDjPBWVwqgi6Gd0W/YO1FVIeQNZug26AqdzLw9uzn2wMqfNDi7lKZsSICQKHSeXcqh
         IJOw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ncHYZN3f5Y+aP37TIZEFKcdxn98OFuipef933c/I7CQ=;
        fh=5CrrI1t1RiWpWtDaHgCNvW6WLRmEErlgfinvPrb5Si8=;
        b=b5ipo3bKzGwIUGfJLyY51BzEyDCAulp4mmzMNLs2LP/0SwPtg3zI8Gum11AYVidRJK
         M/MS0G0FUnSh32VBJufGZ2TnWhmAY8ZQF4eA8NgiVnxoVvIsn4Gy2wpdj2KfYsCguvZR
         P53r8ODp/D0OhPQlnkKTs6cEcAkaf3oiByy/OoIXwaYEGbS6u0Gnt6ELI5VWw8adF5tX
         VDD+zJ5TzSLLwREIJ2yThLzwkv/g8JP/PKc1WpUM7UeYaw8F98TybDM1eZlVA8k9MFCR
         754XiVdetoS5mkszwHZfidzAx9/veKY4bVHJBctWCiJxgb4DL7rLjjVkcJh+KsL5/cnw
         z5xA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KU9yB8N2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=thUqbrG1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768270118; x=1768874918; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ncHYZN3f5Y+aP37TIZEFKcdxn98OFuipef933c/I7CQ=;
        b=lw1DKwMb39L9wNPJ6G0jaA7i/P4820EfYe8zR1kUWLHfIvPdgJiAaycR08tk5cfNvc
         xbmKDAXiKHgYF/rCzM44X3MfT4PfHYadUtr0FVNmsBLVmOieRJOu86A4bmTSs6CEvbLn
         T5waoxQeau3UWxu8YRomss30v7noYp94ZPNjdD+VEPGdzWIlgvLQ/Bk9kxabEMB6UOq5
         cOUrhc2t1XvuxuhnVd5s9W2SToFTNr/FRi2roFQ9l3Id7/QN3dKBfKXrrEWaRLeeOaoQ
         JoLcZFjQNMnU55sX3/EYaF3Yw7ILzFw9MB/zQaSPIXNCUSEl/o2VmqsHNwtedCejzzry
         GpMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768270118; x=1768874918;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ncHYZN3f5Y+aP37TIZEFKcdxn98OFuipef933c/I7CQ=;
        b=v0160UPnBtjORnIFmhNVfp8XQ1VrkYkGU+y4bUil3S9IDHAFfAdOZMPtvVkAaRR6/U
         bb1J7OkYBw4AMjGy8ar5TAoGIehOnH1IkDo9GhtgoN6lCy/InGrjYiW7JQogZUdp0PNT
         4+76KiLxoxyhsmxNwyc1DtpH2A0QHQUm/6qzpnLGS1/AIp2lG92d1o6xwYXRU71/g4YY
         Qa1K92ihv/mSdC4DtSaZ9PzywA8Kr9mm0M8G6MCVj9VJ8mhm6k3cxvH5YsnxhUohP/sC
         A1RQv688fN0ZQsmhCkCkIddIVatQm1tj8JuFcMbWX/XcMl++I8VEJ9o8z13ni8W3LnZa
         aRzQ==
X-Forwarded-Encrypted: i=3; AJvYcCVmT89++8z7LyLOCaOHjxQvAGSWHSK0dQ5HfDA8/AQEUdAqfDCl2kZHxkFYaUXwJ5zGaA6fSw==@lfdr.de
X-Gm-Message-State: AOJu0YyBAeOxYQemJCL9UwxbigSIjGtRa+RNb+zzOOVdSrT2Ws4fbBpM
	XzKBu0PRrnhuxBF1gis22ETxk0dbVV6LJCC3jHV0Jn2FZYUu8NsBAsNz
X-Google-Smtp-Source: AGHT+IFK01XBshG/7jC/dWdQ109/ba/i7JC4gnzBmb2OQbwZPYfOEOAoccOdIPr7ui5gp9+IZuGodg==
X-Received: by 2002:a05:6214:19c6:b0:88a:442c:2988 with SMTP id 6a1803df08f44-89084183823mr265259736d6.6.1768270118284;
        Mon, 12 Jan 2026 18:08:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gi52o2XECm9btrHKIJZhsIRa/J3y4/Qz+Q7QUeGWjltg=="
Received: by 2002:a0c:f201:0:b0:888:3f27:d2e2 with SMTP id 6a1803df08f44-890756e1723ls112439136d6.2.-pod-prod-08-us;
 Mon, 12 Jan 2026 18:08:37 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUtFOAKRUcQO1+kmAofmUqd5btGIYX/sjLoj3g1yciRIx4ttGki7qDgIaX1WgKmqBF76VmoEyS9/0Y=@googlegroups.com
X-Received: by 2002:a05:6102:3349:b0:5db:ebb4:fdcf with SMTP id ada2fe7eead31-5ecb687b063mr7643708137.17.1768270117305;
        Mon, 12 Jan 2026 18:08:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768270117; cv=pass;
        d=google.com; s=arc-20240605;
        b=PFfGGrAdGRxnuB1FX5beYAAYezAcWsc6gG6XHWsaNEhWSvfk3kAahTAtSDSWu1KapX
         eAcSDLmJoZjeioRMT1e3rTaDghJIzqXCQF4AcRztv0hkaIZS6zyQjKh7y0ofPa9Hv4w5
         JrBYpr4uCl8YPf/mjgsI2rg/7FPY5SlZNu1922fm5HSC7LWBQRyERsV84wX99W7tJ7QR
         DADTNdDvzQwhRfa1eKKG3weeM56qmqSe7CvYdDlcbRSXFLjljApnh1N66qiDQhLvgb2K
         1jNN3VdIKYizv4H9Gq8XIRnoMP4Vi5hOzv15ehdwDvrA05fKFITYhQwSt7AQ9KPlv5l2
         AMqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=1/hftVT+vVnWQvhYgllBtzQan5o7gn1Yv+tsNyif6sM=;
        fh=kceCFzMIgve5i5+gz0p/EEtyI1JcVUwOSRB4LdjPUvg=;
        b=hDtgBQjdjXZY1Y32tANUdHUfKn2o4VDEnM2S8tpZZ9Qu/xYy614CLJwMGdwGvR2VWl
         3hB1sG7YwE8FRrNhKdT32jCZdGKrVCCRD7pe85Ub3v7e9n9A/H/w/vBzcmYcxbzPXfpD
         wxpIDvmxp57eIaUd+rWHx7gZ+Gi/JkwV1hKmp2bT59gaDHQdDBRaBvL6VZdPlT4HfwcU
         HdB1ZzIWagS09E0iu3Uaiep/jCDZhdXUc1Bktr7ULSpvjc5mBNb46oqBQmGFFp5JcJ+5
         VRySdpQJulLgNnl+k45v5FHO5QNIePAw+KluYEupq2jzNk2ttkqf7twQxL5k2g+XyMHE
         3nNg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KU9yB8N2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=thUqbrG1;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-944135fc6b5si801208241.2.2026.01.12.18.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 18:08:37 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60D1iFE42685997;
	Tue, 13 Jan 2026 02:08:34 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkntb2rqe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 Jan 2026 02:08:34 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60D1XM9C003921;
	Tue, 13 Jan 2026 02:08:33 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013021.outbound.protection.outlook.com [40.93.196.21])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd784269-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 Jan 2026 02:08:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HMK1bcCMsYU0itkdoHoWnr01DXgDrGxU3em7QSV75OXmJB1Nolsy9n1slM1C8xNbUod4PlP2s2I3efpYuHl+5i73GsdzxvmSdHJlKo+zS8lQ8elMPdDMAItvLsrF3UGykiiXcnbq2aSBL2tujCMa/zrjr9wxlw9WjtCjVtaU4I5Se9GRXYBcVKg4vAFBi6U2B8HlpOShRHfbUiEH3z+7DRI1x9b1pHRrBF1F8okp1HS1wu2dus/lgxLUK5e5bfhYf4Eu36gnzQ51orFtlW5vLp/uxssG6L0EFAvvsqNgvaJyMgomrz9bPkczCdk53Etd/Qt8ePPQvZtqJYYpL5g9DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1/hftVT+vVnWQvhYgllBtzQan5o7gn1Yv+tsNyif6sM=;
 b=eB6CkQ6/WZi22JHCNSpbrnWH7kKbsiPDnEIikPID8RLwUrs7SPGqmvKqZ/xFtlw+atafowwKIzEYksS+5Fle9RmviCcmAM6b5MIrX3PpkwIKUwkujb66kTQZvg7NP3whuKFlZl7EQHGknyvJ0JJjFM3shTX/0N7tQRg0RTIzuIO69/aFfzCePxSTF2Kp2JbD0RpkddU0uhLPSVYg+Ma+/O5/K2YFHjJTrMCJ6L6fAIctPnNglnsHiOYxk5htWJlxKd/9sRamTdEwuMFLe/42SAq4h6gUVDJp/f5ri8edb0OXxoDCYcbMOTYGCNo4RKt+g2rAqbDYhZfcuUE0CE71WA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA1PR10MB7200.namprd10.prod.outlook.com (2603:10b6:208:3f7::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9499.7; Tue, 13 Jan
 2026 02:08:29 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9499.005; Tue, 13 Jan 2026
 02:08:29 +0000
Date: Tue, 13 Jan 2026 11:08:19 +0900
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
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH RFC v2 01/20] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
Message-ID: <aWWpE-7R1eBF458i@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-1-98225cfb50cf@suse.cz>
X-ClientProxiedBy: SE2P216CA0134.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c7::6) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA1PR10MB7200:EE_
X-MS-Office365-Filtering-Correlation-Id: 11fcefe8-93ea-4b12-114f-08de5248a4a1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ahwxvERckPWqi3Sz+3FW+tPMVarfCs1axq7omVP6yycmoWmsosqJypM+Df4c?=
 =?us-ascii?Q?yw6FSwyOR/0hBh4HygjfZWBT8sRHylVwlNJhL0J5ItO5K5ito9sEKUNegdc3?=
 =?us-ascii?Q?G+Wz6OxNYMWWJcQ8tYtISZextePH4F72o03RxtNCrxvfoMMqshJd85nE5yiS?=
 =?us-ascii?Q?a4Qy6KAsINmQVKVQo6b5NndnHbMqPiWEQ7tAjNq6yNfK0B/3YttfML2TW2VO?=
 =?us-ascii?Q?0FXNrLcnHEHaGOUuE6OnXzDNLElYPfUzKSx8r7sAF828qIJpcnUfgeemaPKB?=
 =?us-ascii?Q?GuexM2rVi1vNEXe5RXDj27ba6yvGdK+QDUaARXvM3PtCdtB8P+H9hyJ+iVDV?=
 =?us-ascii?Q?C/naOTG/Y60hYvijAy1FxyBYGX+p7qadBAa/MK9i9bQ3GE6vKtVTPhSwXcP/?=
 =?us-ascii?Q?PolkD2Rf6k62i0+L95LZDUtgjSnoh0rC/cNs7JC1SiVfA2fLXG1ep2278yPO?=
 =?us-ascii?Q?75ySb2v0fYdyqHZnc2J3tbhPvZkaeJMo3G+kHxgnB73JjHY2XzkTgX7+qXVW?=
 =?us-ascii?Q?7YSTKEo/8kCiGDuIJSJPugrBcuXcrrZwWIEfmg3eqc141Ox+Dwd8N1L8pgVG?=
 =?us-ascii?Q?wMJbRVa+n1Z6gHiTKY/tXWWt6WgeQU6RPFkGQ1aMrvQRYPDqhn5BPW4ERQxB?=
 =?us-ascii?Q?OLSSvlnYy/L3YXWClobN290A3Cct+WTitKr9wadyb14UdENWYOsmtrwwlPJe?=
 =?us-ascii?Q?5QcKNK9W6zD+h3RCQrvSaQYGZYTdwTf6DTRZ40Bq8j/ROZig10ULDRooxmiQ?=
 =?us-ascii?Q?KZqjYAbT8ulHM4z5sZ8b1nnnAfzFpWj33pN2J0T8Z/PiwdG9/+MXiZdrJIiC?=
 =?us-ascii?Q?ky/XRTBaDoRPMRADlvKHFg+H9ErFnTfdZsFPv8ICD2cHgXGE3UCQwMjNoUTz?=
 =?us-ascii?Q?nienOgThvsT0YCWShIVojgf9sMQK/6LZozLI8Ndxj6lZMSO13viiRu+tz2Uf?=
 =?us-ascii?Q?dVflIx1VnhQwKYU4iwGlznOl26cs4EBqooQY7iKzP6KFA/HZkeWGe1zUAPzj?=
 =?us-ascii?Q?Tl/wSyYh5FJpqG9vMkhnycyBAOVe8xIopRohVZN2t1oCPLZqMnspGeswiLuO?=
 =?us-ascii?Q?Zh3Q+23oMk3qj+xIfo5JBXZWMfrGamN/cSpFVB5LVsrGQ4RC90QjXnaUcSiY?=
 =?us-ascii?Q?K2m9JfDHtDWVIsHxV0UESIWQNaRia970Ofzn8x7Tt5kb/OsphdZkHfLHr/T+?=
 =?us-ascii?Q?zlJnl4o0YJclEC7HVlNVr+UucuJ69bbOPFP87WMNlf1MhLaTwVrqjGnuQdOe?=
 =?us-ascii?Q?DepPFqXloR+7Y2J7192oTGvUkpDqCshSMByZ45ril3szdpK3Y27n84kuucG6?=
 =?us-ascii?Q?o6935H4TqrhAnbVtQZxchGIgliMnrH9XhtfUHlkRB7VkVq67IC42hgdYy/7j?=
 =?us-ascii?Q?XOxLEa0MHC9zScxDXOudnYnQE3QTrNuX0c5O1YaMEZ2P8lM88s2TfV3dx8Nb?=
 =?us-ascii?Q?3DNver7Qr4W1D5n6S8cGw3UeHpFJamaDyvdqujZIpYsNujVtb5lHQA=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?XwprTqC9qYw1rBQji5FEMqBPwNbIEM6xYfkBwwybmQbU94sUPyhb8lOIAIRk?=
 =?us-ascii?Q?6K9oWWJQ7u+ct0DGcCNgqpQhGR+ks7uSi4d/b8sxX0aVoklUs6YIve8VZAzy?=
 =?us-ascii?Q?ynCVQd8GWRRkVUCGo3jDS9E5bRFqO9mIuWNynYet2MG7xdoAYc3h6aaArXEc?=
 =?us-ascii?Q?ucaEmQ7vcv9oxSEbT1a/xTxHL4ZDyCEKsmr+Fh+Ra+C/ay58hcZMFLZSy3PP?=
 =?us-ascii?Q?glZvKz2WcWjbTRGuKmEyFOMVn7nY92W/cnCJgk8Re4VP/C4UCXzRzkQ4Z2g0?=
 =?us-ascii?Q?1fVTZXmzXqDW4QLKAaECwtHY7TlMX0LIMiiWSeIaWbyDNC78bHQc0406s/VU?=
 =?us-ascii?Q?G+qPdEaBvGbptrTvuJYHvxhP2MYUEsm+0Xr/7ijE6IZudelP0ENxvwrrHQYE?=
 =?us-ascii?Q?+hdDpxiBnKYK91QeRbbJk11qCYZQArC7iF5rEgWYMxIxUZVi2YEIk9xY9BNp?=
 =?us-ascii?Q?TTgczs42cBpmHA4GzS8y3PQHfkSlrNnFDDKV5CAv17scXQ6bz1FTU6xYISoY?=
 =?us-ascii?Q?y0uQZ/kj1oBA44LcOk2N1AP5+PZPh8lDROGDr/u07Umy0vt58OjoF77Mco37?=
 =?us-ascii?Q?n+g69FmRKiiu7NEbYcSjxTUAMbdCGEuPdVsy59ujeAtkvnMgkkNMHDs7xLu+?=
 =?us-ascii?Q?uHM6GTCDZCuGMLlzxbQ4IrwEb3jHBj6pyeZnpL5ymWR7EGp/h0aWnR+G8XSu?=
 =?us-ascii?Q?T4flumJp6UolwGIq9L/jdiE/dpQJOftSTgv0E84uExsmi3ebNulE6MwGjwnM?=
 =?us-ascii?Q?y+i97WqWZBldjGw+2muZOtzhG0w5JanqYrdfKQY+zvgZVmmxlwgHts7T3rDS?=
 =?us-ascii?Q?5Ixxj7dNJCb7312YcNrIlKTrvMF9E/63nggQMswloVdYMNJyDOft6g362WYg?=
 =?us-ascii?Q?vtbjY9U/9n4nJb8mbDOrj6I6k9M7+UoC/Fkd1xGtSH7N/uzKAFFeXRkUA0HR?=
 =?us-ascii?Q?ZPDDRfjLV7r3gxBcuJURIcZEbKoiSnmDQNLtl2aFkd3FqPvMbcDCWInQNVMO?=
 =?us-ascii?Q?z3h4vvVgmfW5Qfv/69yYzqX7N/I1O0EuAaP781nRJyahyD873nZRXdp0FxT4?=
 =?us-ascii?Q?1QTxa//32Q5iSbQHr2+thLXML7dDOvnG/IOo8RKnRsLdZbdKZXbijdop6YmM?=
 =?us-ascii?Q?Mf0e+OtBn5uzc6lD6mBJvucF7+yKoE61ic0Qg6jF5s7ifPpMu0wv3UuLHND8?=
 =?us-ascii?Q?ib4xAxDnp9jQ1cjSeH6olIQC8E+5/QnwIexsVwgLWWHYDmy6w2IpP1AlAH4y?=
 =?us-ascii?Q?zDM1zbB6W3YIo9ZNa7GeyTTJGtJqwG5dQkasUciV5T0GzkhTqJy7st4BdQj7?=
 =?us-ascii?Q?PXE8STfpkWnTLUq672SoWs03QraBHW0nRTVUnLp719h6dvKIeQe/BB5NR0Lu?=
 =?us-ascii?Q?CHbQjdWLr9oS8BkKxcipi+IruGjdtnOb3B2ySJQBe3cJhlWNtH+pf35UYi2b?=
 =?us-ascii?Q?KTAsD+SMN7vHxaSejWaqjnWuH3e7YjlFsVCU53GCbeUmE4G9B569vczaHvu8?=
 =?us-ascii?Q?DXwrVkfUGV41CH2G/3YDhu0YnsqExymHjCedi29cDJz8zJLIDR6E0XkK8QyT?=
 =?us-ascii?Q?G3RFbjJ84+QGQDPF9HeDSpHan45GjqBrtdalQFwYx+79Yloh6Nl5mQgspA9W?=
 =?us-ascii?Q?2fN0y9V2cpwnjgC2++UXBGSBYPixRR0HsegO3oAJrgibO2/vDODW3gonSW9Y?=
 =?us-ascii?Q?cqA030klzo1tSQ1kcFeOP0soeZPXWmZj3x6dqght4fGblQ8pcbhtsj9rbAww?=
 =?us-ascii?Q?v16Rr148kA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: qJlrKI2HEzt1Y/Hbkvao1QUoBnBI8BfRQs6NOggeiM96pHHLOkvWzWWI64LgQJIQPuvatQjce+EynG2tlZJtL+3P1Ss3/5m6UDx6BhP2baU4987hi3aHfwHpEXlbWQYIYZYpnYqrWIotCZshuiSZC9JNkNn/N366HBeWYrLu3V7z306RBMyLtY10dOpGbEQbx5+YQ2/cDA9JjH29PchP11/ZxOJ278FX51Fn8tBI2XjnTqffomxDpC6kKjcVVTdSlqWggMVxZhoHJuaE5luLPEJh3ON9aUuR3lZpxsJPzEj3cWMEVBbFVKi1HJxB5+ecBmf0V7EeaAg0f3L7QlYWdf5QYxjGroFoGpakXGFYbMzAb2d+NnaYUkD+dbYjDSTuzw9+LTkr76197r+pTnWk80uU+rNgkG+3T/cspICK+WXs1YEp1jPohJSDvPF3xRh3L7mZPHMJ/gCftQ/sHrt9THmgYVg5QcSaa6wwIJXmuEMrK6uSNxcV/mipdPAm+T07UjHaNUPUr7IrrD7H5nqweepOWZboy6Cb/L6XzQqxEvYqntI+20DhgEOWg3+TnTuJQopVfZ/+MBLySrLhy8aXgHcaXh43dnGfYcytPogiYNM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 11fcefe8-93ea-4b12-114f-08de5248a4a1
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Jan 2026 02:08:28.9630
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4RXT7NmSZsO4hQXq1Dz6LvcUTDubYZY6RBXO0lig8z9aqzHg/wrngksqbZn49rb9S8BMp92XqyZXilFLqmHSpw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB7200
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-12_07,2026-01-09_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 phishscore=0
 mlxlogscore=999 adultscore=0 suspectscore=0 spamscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2512120000
 definitions=main-2601130016
X-Proofpoint-GUID: Xr67118Ooycheau8cM1L-nHMbj94UglO
X-Proofpoint-ORIG-GUID: Xr67118Ooycheau8cM1L-nHMbj94UglO
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTEzMDAxNSBTYWx0ZWRfX31xaBlolCzXb
 54lL4WASL1Dru/og1WTw5nOiz1BIS6Ms8YLuQ/zF8fwco4sRi9zUelXHt978fMnOH5aCDE1OtzW
 cKD0cqsDYhG3dIPRp+sakaW9TlZkeZJAV2VKVst3tiVVQmrpM1fgSmah5uj30WtXSZATr1FMTTr
 wKvspXnt2xAq7+tkDOmU2PQLSo801rrbVm5ZDpOKiuSAvhVHAd0mkEQcEhmBwVoU0yhOc5sizkO
 fnWkj0mLwYgSMC/v7Nxm4vaKAcuUMeY+qNsB0LSDLJkJSAolrXEzDa2jT/md+6QZOVQdnfJR3fI
 dJOE1FWEpPwMLxZysU5NEF4Ts7fO4WZ71cWBCLtauDGLc/c6R7deesk/FNTjJjaJyrrSUtN6JT4
 aHZRo/bBkXaHL96r01NE/iCN09TBELRemPlxk/nG3u33YXiXUWeUunycQ7m0LzltMBM4J00G9I4
 O9kS/iYJNC1bxF6jDxw==
X-Authority-Analysis: v=2.4 cv=fIc0HJae c=1 sm=1 tr=0 ts=6965a922 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=5GxzKOEUuOeV4qbXql0A:9 a=CjuIK1q_8ugA:10
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=KU9yB8N2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=thUqbrG1;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Jan 12, 2026 at 04:16:55PM +0100, Vlastimil Babka wrote:
> After we submit the rcu_free sheaves to call_rcu() we need to make sure
> the rcu callbacks complete. kvfree_rcu_barrier() does that via
> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
> that.

Oops, my bad.

> Reported-by: kernel test robot <oliver.sang@intel.com>
> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
> Cc: stable@vger.kernel.org
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

The fix looks good to me, but I wonder why
`if (s->sheaf_capacity) rcu_barrier();` in __kmem_cache_shutdown()
didn't prevent the bug from happening?

>  mm/slab_common.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index eed7ea556cb1..ee994ec7f251 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
>   */
>  void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
>  {
> -	if (s->cpu_sheaves)
> +	if (s->cpu_sheaves) {
>  		flush_rcu_sheaves_on_cache(s);
> +		rcu_barrier();
> +	}
> +
>  	/*
>  	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
>  	 * on a specific slab cache.
> 
> -- 
> 2.52.0
> 

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWWpE-7R1eBF458i%40hyeyoo.
