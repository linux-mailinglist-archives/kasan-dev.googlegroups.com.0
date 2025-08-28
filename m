Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJ5PYLCQMGQEKKME5NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ED5DB3A8CE
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:53:45 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70d903d04dbsf27951936d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:53:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756403624; cv=pass;
        d=google.com; s=arc-20240605;
        b=bPEVYworKYdZO+zeLUm8ENF6lLSf4pzx1LHA00R+mruzXtIBDnC0ZGliCk5rkz8z6b
         JnwS2+npwpG7RpB2/B+yMSV3aeqVrsa5+K6nmpylSilxEtP9cnMS6H3u9PyCGyzg24d9
         x/Xb7r8XOPAcNUebLSlXhOm7CHWw1HzXfWtZyVAo3sbQyaEUrhfkYUhH+KSN6DwhKLil
         2GSeh3t6ZuCHNDPTbMWVFy2tRcKJquj8/eiQapWSFWI29mycoxuCvdeJg/E7MxxHxrDw
         ejPW4uChH7Y3Aa08SoxHJ7U1aR3C3vFTMoVK56GmWam4eTE/HML2JeXO3XbWRXTKpuFD
         Iy9g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bXPi/pkoT07j7rFb4QH3vnTJs2ziDUyB0oQodtV+xYQ=;
        fh=r77ap1KYojrFA5GlKeUkGpYfa7DJs3euxIbmBBpJXYM=;
        b=RtWDokMZ2jloUxi8MWcvVfu+s7/ko14ct71TWJEPl/7Xhn2xPIVPHDVBcsiisHG9YT
         8jlHUHqC/WcfGNg5M1kwJysq4E+mT2Oie6ocCmrGdYWDe6rc7Hw3l92Yp3y5jL7XjAmi
         buLuloHJHSGzbBNNPJF7FB/j/8K1WsLL1IdDro35ztBfJFFMB+aF+ANSZjumkulEMGFN
         G+tPSRjnc8vqksh+GbtS6r/xGgMTuwwZykKMg+3+ILM5va+gE3EwTKZgPc2ZYCIavCgu
         NlAL/STa0dDONLBpeswQXZAeIBs//GRhAnUeLb3WkZbqc6lRmyOA6gdXxwecPCDO8Wwu
         gK8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="h/fZokPa";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xDs0i0IW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756403624; x=1757008424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bXPi/pkoT07j7rFb4QH3vnTJs2ziDUyB0oQodtV+xYQ=;
        b=Zc0CCCwCPXcOgxiLauY9ddD86xgU3TXD8px/MPx0ytWb8SWdGln/HRSIuwu7yj60wk
         Dw/Fo1uUeBjzgNl5yuZgDPNLWIJl1Qc7oRTJ53T+cKovzI7IINDDJ3gdDuLi8eG7Oi9M
         W+AhOfwAmgKCLunKovIzl32C4vfUPv4+ubK/8impXAeHEkqGHgbN0ylpOzkWVaguj1GM
         S5iSUmkCLaAPkklLXrdJuTtQeMmx1oVeB6v3zeAy+1JryToBB6Vjh4Tx2Czr9RfOTLSh
         mg/8jI3CcYBjomLyfQoNz1uAPvjaKq77xcNtICQxShSk0AFwutCZjDRTqXYUyB5bToCk
         WPuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756403624; x=1757008424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bXPi/pkoT07j7rFb4QH3vnTJs2ziDUyB0oQodtV+xYQ=;
        b=qbt4RmpFOm+WP3oZv4docXY3s+zp046O7rQ0xvYvRglCf6nwqaTLt/gg4VhlmTP5pV
         tsTOLH6IAAdeIT4xxqUfYeFEiFo2vbUNE1LDlKBn37kQiuaHpQ69eZbqhj9u0jpsgpql
         o/o+q5ABIn3675fSkjhsvru0l6d89RWGBo6+j63bEOWqxZU3XI5FdjcWthzeM8MawZTD
         lDMxPre0HEvl/wgXtMCPTlykeln3IOIabpBRYlxU4cvO3D9RhxA4B9x2t5+ymEzrCWO3
         xs1nP+ZWB4Zj68rvj5Xm6RLC6ATjJLtNB4cgQTjQlQY33RA4dGPWm0zE9QIRjlwJDy2D
         87Mw==
X-Forwarded-Encrypted: i=3; AJvYcCXdMoBKyu/NAoPcDzi9w/OctZeQY+XqGYLJZQQvFJSGyi6adcboBIQHaQsgoeH2HwuVHleC+w==@lfdr.de
X-Gm-Message-State: AOJu0YwUbhNl8+blvTRCS1Ony6FB+wGwTlhlYCeaNu57IV/NFA0rSuhS
	aHrHt8+LR1ds6H3cooeaq6k+jq6O2nmLxlH3oOxxEl/LepAdM01/TD8d
X-Google-Smtp-Source: AGHT+IFecEAjB03463dWbrX8qDYtoUtuzKzZgKk5Wvo4v9dtL+pmCx1w8zwgDtLdFB82VGxb0EAWsQ==
X-Received: by 2002:ad4:5741:0:b0:70d:c870:e7e3 with SMTP id 6a1803df08f44-70dc870ea51mr162259276d6.12.1756403623987;
        Thu, 28 Aug 2025 10:53:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcK9IU9hxHU6y5MzPgZ+ysUC4dapO/xcPLAd+9rCM7LtA==
Received: by 2002:a05:6214:19e6:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-70df041b4b3ls19166946d6.2.-pod-prod-02-us; Thu, 28 Aug 2025
 10:53:43 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWWcGeuzK2or6/lZFCPLTdAs/D96Jt7C1vN1cYk2pVbynhTJJnWLHHQum/AUS51ZftOnLdCIJ5GM9Y=@googlegroups.com
X-Received: by 2002:a05:6122:1783:b0:539:3524:2138 with SMTP id 71dfb90a1353d-53c8a2d71a5mr9691054e0c.4.1756403622877;
        Thu, 28 Aug 2025 10:53:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756403622; cv=pass;
        d=google.com; s=arc-20240605;
        b=lj6rM1Q0gbII754T3F4WvWZzpYFt3glSOZ7TE23DluTDihiJtIANBZBBhf1Jf7bOTO
         Mx7CJ4kvBdK5pCqmcAVvbXI7axKIfWWc5WJRW6Rt8jj69pAkh7ufDraKE+yz5Gh5qMNQ
         GvXxtKGdUCSomI1kr794+3NcPt2irXWSDZJvOHTTzivzhitCrEfJAxleyolMy/G3Obj7
         NNCZOLXgonNj7dAmVTdGEgn5G/x6UpRSVOKg8WtThkthIk7pm0QlPh64DJ4oXFiMWyBa
         bxfqqTcov/afpPr0Ri75Ek36vWkhkldS8KOFXMHekOfR+5vt3bc7IdRyw/nTSSKtUsNe
         iZVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=GOYJsD/YhtXAS1h+B7Rccx3sCX2ZwTksQ3izTJdLVWY=;
        fh=z4XtlDX4ltCyrLXyLLLOUTjcD5Ergt6YW4bz/y7YDvc=;
        b=NM4IEn3vcSN4UivlsACOo+zBY3BNqQw7fQYT8k3+0unarRw1OBEcgCgI/f3AkiTHmW
         4M4O4jLqLv22SodgbSgw9ELZsyiCVVUkN+eQZO2Bo/+iSuqbyWMZF4DOsbSeVLGlSTIb
         AYS0iPTe5g2dF9kp0js777XcVj2Vm57KECssXtzJWfX9BmnUeDJgaE20v/62qI71LpcW
         qUnay2G2msYiUYShKjrqwtuJV9Hf0ZXlmwoYA9bgXTahuGSKWkr9tHOJ3yhsckysgwKg
         2vbykEflQAHxGmCVfiw6qIu8Z3ycCWkc4ITJBqnuW+VD92lil88GCvWhnIH+0liUpKFr
         TtSg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="h/fZokPa";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xDs0i0IW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5448cec265fsi14431e0c.2.2025.08.28.10.53.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:53:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMqsc023314;
	Thu, 28 Aug 2025 17:53:35 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt9895-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:53:35 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHcdas014760;
	Thu, 28 Aug 2025 17:53:34 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012066.outbound.protection.outlook.com [52.101.48.66])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c6v9j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:53:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=N3Ge+JLEutTd2MpRRhrS0tPCL6bdts+xffCnvLWKEIt4PZI/Wm5Jv/m//6iD4wIMpX+WeECpkGw0SvuDSBPwibT8b1Bs4bOsS8Fx0ZqBKwwC5TVgcdZ/JyLyFhrctW+EAOoYgs2ZUUZ0PT0pjHBSJWbH392BT6pRLRp5R4xHuNs0E9JW7DvNt4a1SvG7M3ALT0DeKsWNWpZfScnlh1CMexJewUXXkpzW8K93dILTfRK/tPfNUW3CH6HnR4HKgrcYlpl7ykvPyWpk3CpK6RZArk4BCmtfmz4rC6B/E9uctOhWUWvll5oygxVhgwj/6Y0l/a48mGOeNJ6GvTe0pCK9lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GOYJsD/YhtXAS1h+B7Rccx3sCX2ZwTksQ3izTJdLVWY=;
 b=NI8uL13ItAcnCSBwYPuETdBFAzmlNdOCudFfYL4DN4rVLi5QmYgIez6G62RUPaM7G0ixStwbCVnciSyrLp5nZ/zklzUQa3UIInoanZUIcooCdUy5T7BihHTn4+PBWeIVOj0UOByy6i0OQ6wveGMiPbK5BJC1gYFHqyKdeTdaZdw1kVPSNI4fC9gYo4qxNme//dGkT7FxlbgUcrUX5aLYpS47SSCC2FN+1yrvTMH8U2lbUBpo0jDtz0pDGZoBFQNKDB9Joa+ccQdQMhc4q2k/TpT0HAZvC5jUoNt2vY/FVKaiaap3wc5Cn/xDj93KCEDlioPIS/1syRPIl4+4qzRyFw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6827.namprd10.prod.outlook.com (2603:10b6:930:9e::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.15; Thu, 28 Aug
 2025 17:53:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:53:14 +0000
Date: Thu, 28 Aug 2025 18:53:06 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Marek Szyprowski <m.szyprowski@samsung.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 23/36] scatterlist: disallow non-contigous page ranges
 in a single SG entry
Message-ID: <c8d63b04-b8d4-4fb3-b2d1-f48d1004ba9e@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-24-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-24-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0576.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:276::23) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6827:EE_
X-MS-Office365-Filtering-Correlation-Id: 33cb7f35-ed9b-4dbc-535a-08dde65bc31a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1H7/qWXzWMGq2GRRAFvmGi9lYxn0MOHA7c5qJLxA3Ro9vnY4cy+OQOAlbzR+?=
 =?us-ascii?Q?pkRtYgzm0uWOuNnpnfUU2N13zY0REp0nXQxA8JHH+kGqwO3VVPM/tGCQjQM4?=
 =?us-ascii?Q?H2IhGnaVNZ6ATkyfmPuUxYLUaogXI4vHwAHdJ6EE6SplP1uHNq6Ama8pUHH3?=
 =?us-ascii?Q?mtRXk2GP5myA3KHx0VygQGiqQ+rkrgc7Yx9qwtM+RN58lgRTxtRKqHVTMtYV?=
 =?us-ascii?Q?tAwBJaCZ5tqu2gxAlQ6Byf94zFn0+wHCaMuT8LaaQ0hRxDaIygn2d15W/qTx?=
 =?us-ascii?Q?ig9nJiuP3j/W6ch5pCFsuyKdc0UXeMzVSDNV0EL52v4asguA7qwzZFvWvHi7?=
 =?us-ascii?Q?Gns8v2AVNt5TskEjPm8LkCZy5lXCPSiEyN2CSX10dnSGmebhhW7L8CPLM0s/?=
 =?us-ascii?Q?IWn3MmpbHvfkbNtLd+jM4khGeeOETlqRmq2ZBZabg5dW02LiWr6xHeJNGPWj?=
 =?us-ascii?Q?1ExDoCTR40uB+LnkffYWtq5LWPSqmsjXlYMj1U1bgYHO2BTskdAB2EGgutm4?=
 =?us-ascii?Q?efT1dFdDwqDsiAPdrhaF0o5cq+wQuQXOc2LJnJ+FTrWahdGbmiUBCMtypmHv?=
 =?us-ascii?Q?JVnRTS4s/NTQM5mZrSqNkhldKWasQyEuUSubnl+PpV7HHK/LcD6/enbdiSzW?=
 =?us-ascii?Q?t0CpVWKruPq4oGBnKsHQoIWLFh0mwUwKgyPaXH4++UgjPVwESnIus3XKkvj3?=
 =?us-ascii?Q?CUKsjjfvCBOUoxfAjaVEICCW2eQO5nFoSZWxUvCnbvV4uQ4qmxMdp6mLPSQ8?=
 =?us-ascii?Q?9w2k2cu2XzOsL9C73ZFUPTaOQqSDyGP2FTjkpVOlvdtZi6iYkTYOtu7rQ25r?=
 =?us-ascii?Q?+KNj6szsiJkomKFzqrIHVrP7gTbjODYOk2A9eo9gC8qytp6K6HXrvizn90TX?=
 =?us-ascii?Q?1ofjhPk5xBWj57EGyLlqDktnX5H1tkOaZiS1+8Oyr1r/7SVHtyMEZsp3S6KK?=
 =?us-ascii?Q?XIM+Nb5vE2I+8o5YBzyPFbT8WSz5IT0nnAoxtdSWfaDpzUyhpp0QMgOpUdj2?=
 =?us-ascii?Q?SBR8tnIFnBnjGb7kGdguHBmYN67IdHmAhm2zgB44EJL2xaIngtADh+Fmbmqs?=
 =?us-ascii?Q?flUtRAk4aC3lrKQDOkk9ZJmIpRK1RlYx+IMqr2zpQ9SzfN6TdDb0bxozy0Cn?=
 =?us-ascii?Q?XqPPvY6edFKtNumJAo6DBxp2wUH2plL+oSxlJVUR2z4a2e27VttT6Pipss5r?=
 =?us-ascii?Q?JJGRzOxnIafkhrhQcV/wDR06qrkSdZkWqtnm/ZQK1JB9BbsEnQomnjBtW7Qu?=
 =?us-ascii?Q?HjZdJcX1Fi8A89hzOUeYv3ZK1XwTrb120JUaM/pmrQT7QAzF43d0n5sHjnPV?=
 =?us-ascii?Q?K1lijFir9i5E+rB8gxmF5IyLU9gD0wnTAUTyBWLc8KJiB3gsV6A7nPcKourV?=
 =?us-ascii?Q?eL8cWOcDWMe2ARLkepfwTT12Hh9mZ1HzjtLg9t8v4cfGIGnUdETJWtUA7RQi?=
 =?us-ascii?Q?c8XVIL91vLs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ew0AJBaahxXfASFKbT+UKpAML+TRgstpi5erDBh8G2Rl3kS16NjpBxA8tH4q?=
 =?us-ascii?Q?4DjaFbaFPV1aDtNhw2lYw4kvdB7lediaBMgCYsXaVAvZbGItAZoh+Llqv8zm?=
 =?us-ascii?Q?zkF39YUH2qG427v1MUW4lY52AI0NLwHBwU5EtV7TmfwRPH8TpJAysmPGj/uQ?=
 =?us-ascii?Q?qx5i7rPrT5sJ24HP6bStVAIS12ErIMgWWKlT8sliQ4xb+oz+MVATNSmEIn0j?=
 =?us-ascii?Q?dCEIxdQfLOzFCbDy7R+Xhf+mPf4wo68m2bHivLOOeerIAeoh92SGU6Yy3vfd?=
 =?us-ascii?Q?KqU+DWy/iT7ZRej1VZOnQvT1LF+nGww8oIzYLtTbHoOo2Lm9Vcfhwdt496yH?=
 =?us-ascii?Q?hFEL4feCnV2H3HYvv5jo8Lks4CK80sW4SFcm1nvpvLnxgKsCdYzz/P+Bicfe?=
 =?us-ascii?Q?QZwo5G7rXQ0xsrMbAyjoI7Mdh4+Qwr3ZNaE7IhivISAo0vuY5bO4LNt9Ftua?=
 =?us-ascii?Q?BbWGR2vq9KZu4bmBLXtxmnn0ZEiE2RU5cb4MdaXQ7NVBUMAuH4+DH1vhsZRp?=
 =?us-ascii?Q?XAx4K0Ea/jqhgKkpfBWU8V+lhlnSR6aWkrB0Qfz3tjfJtOT49lI2Kb3LqF8m?=
 =?us-ascii?Q?GRMVUKYZSNEqIP7L1wR6VwGE7t1lN0CKwNrWpp0SNnvWkdZoRfaBKm3NzvF5?=
 =?us-ascii?Q?s6YqnePFZz84zz2TRYpg3p2CYgV5M1Y+Tyduj4p5pofvlz3wobCwVfaiBTnZ?=
 =?us-ascii?Q?OVuqZP6wIC550V05/SdHfIVIaJjP+GtWfB1VzHDwPDlKSs8WUSnKaFQ10tQw?=
 =?us-ascii?Q?1bLSL6KxziGfVnifYkcLAkyCMcfyDokXFPjPKgNDHVltdaJlyhydUFbD1XiG?=
 =?us-ascii?Q?aQE99NajEfD0xjszCt+GzWz44awzkmlLlI1QyizQtVRwln7ejgOMo6D7hNZN?=
 =?us-ascii?Q?RaFAX0Zsk5vQEG0ot1WAlTUiFAxsuIDiGdmC1OFNDt9BIsmzzytEaOwCI4Zt?=
 =?us-ascii?Q?l54bfUtVYjiFMAXYzscDJ50sM+TJzNAg8gLAGDxwjTDGTakKRcdtceubMxP/?=
 =?us-ascii?Q?K+9KYEARWpayOSqqwAowkrnfkOuA3y3OKDEp8u0EhtIpOizUCfr5lFlIkQ+t?=
 =?us-ascii?Q?pZkbntZd38/7A1P1KZUwnTQbI9m0fIBFKdNmXo5MeX/fvnfgDTmx0DFIlcPY?=
 =?us-ascii?Q?g6P5qS/2sftmv/ui66UkKZM20qxFsgP4CH4Hm3Q+YlShFln5dvr6sdRQaG4h?=
 =?us-ascii?Q?OI8jnjqNMOXwypPcLDuJsABfj/HqQcSF71AcQX4VWmCXGV2ZTO/CEIOyEERY?=
 =?us-ascii?Q?CeQzFamy8X5i6mpPXXL7vth6i8pN1xFJIL8l36SW09Ec0xL3Gu2v0kJbgnIM?=
 =?us-ascii?Q?D69Brc/u0jYqk/kpBOd+DER2XLQekqUCHId6HH/ggYr5gq6G3YNi3NE67Nbn?=
 =?us-ascii?Q?dlhaFu6M7RHWgdG8sIG5LcS2UPxk9LK8pzDYVdTgoGr9WFPwV83aO5cBUfp+?=
 =?us-ascii?Q?88Tp1809GQFxIlAHcH02+BySdHTkXxy1VDJSzq87eVr1rJ2czN8ABELzhzj6?=
 =?us-ascii?Q?oHLL6KgPKyF0oQ/ZvKhap5Rd2J9zRw6YN9bWgvEcTP/LpY8Y6NOzl5BPsgcd?=
 =?us-ascii?Q?j6RfM5fEyOwIpLSDgJw8c7N719naqU1VpXC3CSbxJVuk6f0dYO6P+TCSjg9D?=
 =?us-ascii?Q?0Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: B8A8/6OorYGOfqc/3ykWhPpNdRT6JTnlHZwCmyhNnErobwcO7uSHGOeWURDSxZstnlVVn+j3eGNhB53X+5zG+Xs4VOC1aU54WndaiYF+Vu77OV+M/hE4jcUeRbph6qwGOF9AnVYntr7lhQGu9BzA34AFNdtwRjrAud80DVaYbtuS1t2Eoyw0BbeCbk9cN3rk9FWeMfMIdFpuocfdcpkXlt5XXiXHlEHLOTbreE+bF74pQFD/OZBbtEiPgwEuDxrVWbCtEfRoc924Y80pmqZCTyoCxyBF8XhyJtzBPHXbpOr84Cp+jdGlJwXCTRjI4ZffDGfFAhtcUpO+zmqmcS/icNoHuuQ5+muqkCtZjgt+XZB4UXFV1W2riuNjCLNYU1ydnPlDwXH/oZKaHfAiXumoSfByyhnnhuTWKPR9P8bR6046cpf7O/Tap/An4okyPeBSzXLrbdg5jWSmNE3jLuzGvPoFlzuqhD9kTC61pnn7oB0O+BJxyPkYx5nQTJCZ6OJrZlZ8kO6hSa5712gjOBEh63Zwl36KinaRZNRd3L28vjr7/AP6Ew86WOXR/Lus3po5eIn3nd+kG3GyRWpBmJsD3gBmZtpuUi6XTeCYTmZYwlU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 33cb7f35-ed9b-4dbc-535a-08dde65bc31a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:53:14.6878
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 2UCuyntFxVRNOLXWk2FZn7BUuONtsxMgizgmgVyxjPamNI1keHdi2otdQ/DdRIYMVgU4cKfLsPEioNyb7adU1Sd25sOUKWD7+sDTg/u2bAc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6827
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 phishscore=0 adultscore=0 spamscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280150
X-Proofpoint-ORIG-GUID: 94ODpMm5JxgD2w1vOwGeZ-75oDVAIRmf
X-Proofpoint-GUID: 94ODpMm5JxgD2w1vOwGeZ-75oDVAIRmf
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b0979f b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=hD80L64hAAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=mkOwHSSQoByemH1NnRoA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:13602
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfX6qRXz9WMLuce
 aVbTbfBghCGnBuWgeKpDkzFE1ZdI0zypjs3nWONu2NHhNmCOxc7LMw3AhLxYylUG2H3m6O6uQ2m
 qeM69DThYLFRSYGZfb2KoKrfpojTW/6/tdoF8is8J+OxuDjZtmKRIZqgHwLwvH7JV3y9Ym8r6dO
 2qiphhNDMh+F+vlS/RMEVibzgA+ku/kBlYLNZkzu6KC36yh2aS78p0zzRf/guJpYIveuruo2aOj
 1Rtr5i0sur6y5JWH2hXq9aV1rfwwe2qMzNj16if5rCMXq7oRxZTmOmh4wKE9B4jiWjOMvozX/nB
 1wzykXZett26lMcoHpjklfFwywUkV7Lyv5+uQRp/QIDoJma/w9P1XL+DzMqnu2oBx2sxyu8ARZ/
 xfSx7GsjMwaL9KjAw36tI2j/G1IIJQ==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="h/fZokPa";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=xDs0i0IW;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:27AM +0200, David Hildenbrand wrote:
> The expectation is that there is currently no user that would pass in
> non-contigous page ranges: no allocator, not even VMA, will hand these
> out.
>
> The only problematic part would be if someone would provide a range
> obtained directly from memblock, or manually merge problematic ranges.
> If we find such cases, we should fix them to create separate
> SG entries.
>
> Let's check in sg_set_page() that this is really the case. No need to
> check in sg_set_folio(), as pages in a folio are guaranteed to be
> contiguous. As sg_set_page() gets inlined into modules, we have to
> export the page_range_contiguous() helper -- use EXPORT_SYMBOL, there is
> nothing special about this helper such that we would want to enforce
> GPL-only modules.

Ah you mention this here (I wrote end of this first :)

>
> We can now drop the nth_page() usage in sg_page_iter_page().
>
> Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

All LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  include/linux/scatterlist.h | 3 ++-
>  mm/util.c                   | 1 +
>  2 files changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/scatterlist.h b/include/linux/scatterlist.h
> index 6f8a4965f9b98..29f6ceb98d74b 100644
> --- a/include/linux/scatterlist.h
> +++ b/include/linux/scatterlist.h
> @@ -158,6 +158,7 @@ static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
>  static inline void sg_set_page(struct scatterlist *sg, struct page *page,
>  			       unsigned int len, unsigned int offset)
>  {
> +	VM_WARN_ON_ONCE(!page_range_contiguous(page, ALIGN(len + offset, PAGE_SIZE) / PAGE_SIZE));

This is pretty horrible as one statement, but I guess we can't really do better,
I had a quick look around for some helper that could work but nothing is clearly
suitable.

So this should be fine.


>  	sg_assign_page(sg, page);
>  	sg->offset = offset;
>  	sg->length = len;
> @@ -600,7 +601,7 @@ void __sg_page_iter_start(struct sg_page_iter *piter,
>   */
>  static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
>  {
> -	return nth_page(sg_page(piter->sg), piter->sg_pgoffset);
> +	return sg_page(piter->sg) + piter->sg_pgoffset;
>  }
>
>  /**
> diff --git a/mm/util.c b/mm/util.c
> index 0bf349b19b652..e8b9da6b13230 100644
> --- a/mm/util.c
> +++ b/mm/util.c
> @@ -1312,5 +1312,6 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
>  			return false;
>  	return true;
>  }
> +EXPORT_SYMBOL(page_range_contiguous);

Kinda sad that we're doing this as EXPORT_SYMBOL() rather than
EXPORT_SYMBOL_GPL() :( but I guess necessary to stay consistent...

>  #endif
>  #endif /* CONFIG_MMU */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c8d63b04-b8d4-4fb3-b2d1-f48d1004ba9e%40lucifer.local.
