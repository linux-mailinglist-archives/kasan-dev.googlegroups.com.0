Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4WEY3CQMGQEDXCCYLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 09AB9B3BBAD
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:52:04 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3f02c49973dsf45321015ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:52:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756471923; cv=pass;
        d=google.com; s=arc-20240605;
        b=TZYaf62ZWe0lVSfx9McSy4Gh/SLBJaUDyGYtl8B80aaGqqMnbqZ+mVr71zrOSVo2wv
         Jx4iBmmiQDgiZruIujZ+LUafGhu/fu8Zg7kEwz40JfkS85uw87I5GxnW1HnDBNMeH8Ve
         49HlYv9n2inyUS6WeF3JWhYvxsqeDXa/YEIh8peuBuo/LBpCfD40mz1AEcgTiOzzW6eK
         CZGb5A5Bl4xoTvRVOj8aKOx1xOZl7N0FRfOqfAw38CFw9jGCH4pYcQ4Ekcal3UobSW74
         E8psVHZGB7Smr1If9oGO2uf+hnhTpxOWqA+TdZmFGfehjwRu3E/oFyRYtLI6g+ACeR6m
         44Ag==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=spo+sg0Zcp8ADLMV3cAbzkj4zurv8arBwTVTbORKRNA=;
        fh=hPMj5VBzcmPT6clUPC3rSjeBrkG5b+ImQ88IDnF40c0=;
        b=keX3O/c+SNiL4Lycdr1FOyRkDRxkGvQ2AgIpdebKfpZx+H5UEncukDDTauGFOOYkEe
         3CA7zpMmL2bTWLaOEYMxGFG+TeY/gdpilu62lR+ItSNc5cLt6owV+K1FHIEemSayW3EP
         wC7TT3rIRqw2mpBxyUvl3AUERVZ2u2VVwtz/BERKjN2l1biGwjdTI8qOZxQ0BvwmXhYP
         mi+K7Eq71DmtWJjKfiLt/09NmJH5rwQurq0UESzl1StTd+PSendVkkj2GG1NMYpVm7Vk
         DhIbPBVNuRhel4tw5kgJh0/quOp8qiXKt/3FS90pIIOu/BPpeaR/Kzb+p5MvF80bcwbS
         gXFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=sf1ejbJ7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZJs0XvGC;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756471922; x=1757076722; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=spo+sg0Zcp8ADLMV3cAbzkj4zurv8arBwTVTbORKRNA=;
        b=fsZAWNuEeTV4CSQT5LOlgBaQB3QN4lKuArzc4YqG2spED+RYF9YA0mDgrNNVLB/11j
         +Bc2+yimtidPvq1K0m9P64GHKfLm6dJyJadaP81cYiiGV2E8jOJD+fKZp4gP8ESa9FEf
         00NZuMgytlZ9EoKk9kd+7ELV/vzfN/BH4K0J05VUzv99n7gqe+bF1v5caycRuVD0h0ob
         dTMpN6LZs2GKiDcBtgP/qMhnhIvC5ZpvcOz3Pwd27emBmyMJ/SQt9lvbCXfBIWuukqu/
         ieCPS6c2AIl3OscgScE2RYJtITId1pnboSORhUmE+fU7imaZMSqNesMYRUeqFU2F3uCd
         MXYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756471922; x=1757076722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=spo+sg0Zcp8ADLMV3cAbzkj4zurv8arBwTVTbORKRNA=;
        b=FQP5rkgQr7nYF1FSGMpOszTvvd9lw090udwTJncKrr1zI+b/snWBYLVpS8pChcp+D0
         w9FOWR8avGz1ZG70pNhUYgzNRLwCyOvUjybzc7CJn4bxsx4V9HIzxmoNfgexakgot9Q/
         PYEtuemjGllbg9Zt2iKMIBYEgfLTVPEmxCtOGYKqf5kuOk2IA0bkcnKn09iS43kAZnzd
         qcAZfEdCG4dhb3vpup03ux8GNryITwO3igoNdV0lE6ZGnFfuqpqdHyoaJo3HAy/jd42+
         /MOFrqdP7719SU3IV9j4mgodEaoB2XW014X0WRDCeGrvuaziR35wUu4wtgyWuPN7flYJ
         yzIw==
X-Forwarded-Encrypted: i=3; AJvYcCVDY7vrCJZOcEWDsgmArE5ccD6rIrZ/uQODw72KKg4Q4tb54DK657sncbreAknqaI6B3GudMw==@lfdr.de
X-Gm-Message-State: AOJu0YyujMUEY0rqpWZHpE2Uy9nMQSzyPiZpW9Q5X9wIJkTz6pQCiq9S
	tnmLpza8gtcJK41u+oLRCzvvju0ZagZaQ2wktQwCww/URgiYb/nzzaFL
X-Google-Smtp-Source: AGHT+IF1dEnbB8YwBb8LRMJ8flnh01E8JiAmTEdpNZTsGkrNCx9fU78i8ac3rUBPwKk5wnhqhPVDRw==
X-Received: by 2002:a05:6e02:b2b:b0:3ec:fab8:66d5 with SMTP id e9e14a558f8ab-3ecfab8682bmr243289055ab.26.1756471922612;
        Fri, 29 Aug 2025 05:52:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcLjmspn9BUT29qP2AENGzHzSXuZa+b3+GuVC5qOkR4Q==
Received: by 2002:a05:6e02:def:b0:3e5:1b1e:ec7c with SMTP id
 e9e14a558f8ab-3f13b180f26ls14365595ab.1.-pod-prod-01-us; Fri, 29 Aug 2025
 05:52:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXk1OSie8/hVFHJRjKBTbFPLerFNMC9jgU2cM7U4wFRRZrxYrm+vS5OPkWRZ6HAb4MfABYzyiVySr8=@googlegroups.com
X-Received: by 2002:a05:6e02:148a:b0:3eb:87a2:aead with SMTP id e9e14a558f8ab-3eb87a2b175mr355284985ab.18.1756471921472;
        Fri, 29 Aug 2025 05:52:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756471921; cv=pass;
        d=google.com; s=arc-20240605;
        b=eaMznsc7Bwy8pEJHzludL5lIFySJ4CfPSq7kI1lnl2/794qSSesPVmJC6CRKh+YGFv
         MxofGX/sCYrIGp6t4144XzQWzFsCqjF6fDIdTauwfijxEu6kBKqnRlc5vFUcF7W3rODW
         VvtmDM7DK9f8fAphm/+ASLy187F9I62GUdugvHu9Bn0aiiTCRU4VkYt9nagcH1IElbBw
         a8lj0ETSYsyl+B4WaTnjNEaA6+iF1E2YWSAhTS2tTOq3WCN7Zm9dhIknwFzHgKccYBUn
         5M3/iHDVoUU4yvYDBCaZnCZVakVTEyOGosmQj2ozu9ezE/NqXOCtSVJ/hWBij0bo1rLD
         Ef4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=pwh5I607Wmtm5xnJkouUwSqIJNZb1Z0CvioeJScwY1M=;
        fh=YFvOtbMpyWrVBfPdbuff9rmcMFT7cCVEYPf4hQHnYjU=;
        b=G39LZUhlxRQDc9QXPDL8Q3M7T3BDKG68535H58V8TH3vM85C7oSaBAwkJCFbRS8m+q
         /lQ9cL9KXQI1LRnfWO2omUotYSrUDK5DbM/J79ifu4c5F1h1jJRuZ5isyPgwjjtamlCt
         abtG7oPshmt6i0xBCUbCKJasT5wA0+Jpk2/QHq7rrbKTv4KDNli49ewWA5pY5G/vrwrY
         +965Ks720PbhITBLQEcpK6Lnymtnzczu2EzS8OxlKfgNF3Yt04utCh0bnjtI5II9/k/E
         jrSmxELEide0b5g90pl5ivkD+rvYLYhuG5ZMuYOY1vSt74owFgxosQqFgeAAGLY6TqGr
         lOUg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=sf1ejbJ7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZJs0XvGC;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f2a1f53ba6si874605ab.5.2025.08.29.05.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 05:52:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TAYiuD026792;
	Fri, 29 Aug 2025 12:51:50 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q48eth0f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:51:49 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TB0KOn005562;
	Fri, 29 Aug 2025 12:51:49 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12on2078.outbound.protection.outlook.com [40.107.237.78])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43d7ahq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 12:51:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wD05ZmvqguZ+h2mBa6ko8S/1Dd5QDOVYpE+Qdj3dSgyHFObg4HL6VxRYBP3/zuhgW0ctF8cck7YpADmqNEcgMT6VfgKI3EGWYuu8Ih+3T8g9YLKn2oCP5EgKwl5/dLjmxiHXlDayWvK2jrHhjJar1fN+y4TNTSzN/OIQT+Xpld30r7CfYzqkrvrNrjgGFrPfsED56KxhVCSFtI00xFpmZaQN6wxSh4rx2N6QM0qANXLkriyptaKq022J4uoxmbj/gaUMik+rpu9+JzUVFCxM8khQMrHFy6vOTkKXubGf1m+bgsMlGQw74SbQdUXSogUwKpxyuqJp7/wk+7L0jN//Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pwh5I607Wmtm5xnJkouUwSqIJNZb1Z0CvioeJScwY1M=;
 b=rEGxYXd2RnNgtswErVqufHBR7IMtzFpOLeUkTEFUIXPyIonrhqsZ/CoJTROyldVwYifS3UQ7QSn04xRzbv8CkbXjvCWqm2pXdog5h/9gZg18frWN4r9TiZXoGq4djgZHlK3itRdP7bRaGe985azXzlZ2SlV6hjCECZJxPrN1Fo2KyRNk9bFnGFv/Qs/LYen53kiK8x8lmJarsVj2PrZrBF5ta9Dwpt6/irBpxUFLnsZVgWifmT7d5siokJ38j+MCi7u1qq9UAZfr3pNIApajJ6JxbRpA0/7tRn48drLVQmNfXdjcVJXCRgfLqQx2e8hrKEVDA8FOXAo8hcjGH+K9GQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH3PR10MB7905.namprd10.prod.outlook.com (2603:10b6:610:1be::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.15; Fri, 29 Aug
 2025 12:51:44 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 12:51:43 +0000
Date: Fri, 29 Aug 2025 13:51:41 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
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
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 20/36] mips: mm: convert __flush_dcache_pages() to
 __flush_dcache_folio_pages()
Message-ID: <549a60a6-25e2-48d5-b442-49404a857014@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-21-david@redhat.com>
 <ea74f0e3-bacf-449a-b7ad-213c74599df1@lucifer.local>
 <2be7db96-2fa2-4348-837e-648124bd604f@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2be7db96-2fa2-4348-837e-648124bd604f@redhat.com>
X-ClientProxiedBy: LO2P265CA0435.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:e::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH3PR10MB7905:EE_
X-MS-Office365-Filtering-Correlation-Id: 58307290-420d-4b4e-1467-08dde6face80
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?xeaI7LyZbZcoxcRAdnCynOv1Mit3iq0g8yJQqBpLAenCQ06JHAcEy0aXIGnH?=
 =?us-ascii?Q?mxX4af0KFgrqFqzXCrc0FlHk+Jjbn0aIsQiougPgnRpxYdPdnDQCusFr2rOk?=
 =?us-ascii?Q?9Nbns1Ldj3UZWblNT5OSvSXwIIdlnS0mEn/rhbhJR235Sixgx543NMTLA6qW?=
 =?us-ascii?Q?2ODjly394EnXRpuqxaSQaklDsght/n0BrOVlYpkHjHGQ6pl7+xCiDZYbpG3V?=
 =?us-ascii?Q?5yGmEWNX8yiZ7wDPKm/Jf9CR0afRl2awZgFaNLJeg0dlk2ec1dKILaTLNMom?=
 =?us-ascii?Q?rBFh6edZshX0TjJjmEZ4vEPMbexJa2NjCc8qYrwCdfFTz9h6FWE4IJX2INLg?=
 =?us-ascii?Q?U3qAyzzt+7U4OYebmk7onamGscqytXdgvtwaosffqIr+Ql0X1gPqmSlb6PN4?=
 =?us-ascii?Q?RCA9fwi044PGrExlodEiWnHQFJ3EjPQGzMG80p2JdtA+Z2UZ4GTAYsQ35B3K?=
 =?us-ascii?Q?haSbMGHFTYLOQF+VPYM3kXhexbgMYWZBwL6ZYh8IsS6hJWFJ0OleIE0IRNnC?=
 =?us-ascii?Q?YWULf9EuCV765lePd1RnjHBVgf8zGGQpNSx/NidyLEKXS/WYoAknFlFPE22b?=
 =?us-ascii?Q?vzyxJz2DPCoiEi23ScR7T21zUsKs6x850aT2b9p9GywdnVsUTuK+kvnlwnG7?=
 =?us-ascii?Q?jskfVcUQNBOFy7PDCeq/FdcGuDo/WFvxJ4QzrlAtCS4EBwECW6ffKSvvrjvy?=
 =?us-ascii?Q?Nq4/TI7N21oeJqegoPlajj/8S4zyoCIK+9eNXNEpYy3m3SIxJ1o88fWCV6cl?=
 =?us-ascii?Q?L3yRdT53yGW5t7q8xPCFYV7RK+bpevrY9ZD3EtoRRJ7H599E/TKCJ4Y/VkXy?=
 =?us-ascii?Q?vMoGoXdxYEgIDJCyqPmzzz6wZff8Y6ow2t/m8DVdM8oUQ5fHxeAPs0UD0YPS?=
 =?us-ascii?Q?Oivb7KZEnukNM+2eseWT7gngis9a/X7xldPnxeGR10AQUQ1y3iRErE3Vbkme?=
 =?us-ascii?Q?lTSvX1ggXgvoCgQU2VSY9HAaTg9Xkzh5ZY9QCL3zz4q1WZ0h4e/jQHakbypT?=
 =?us-ascii?Q?2gazOlGQjbdDkgLjsxi4mwlrmfDk0lwq8szEG2PitY0x9Kwervzj5u6GfxxQ?=
 =?us-ascii?Q?0f8/tN914OOb7ZDJmJIjhViUMDBtCYq9lwKaM3oZ274ya0Sa67Q5TRtzfyUc?=
 =?us-ascii?Q?JD5WlYe0o420WBZhv782JKi0cIQr60N6Cw7BwSy6IOk7akiBHb9RPkres/Dz?=
 =?us-ascii?Q?/N9TJfyXGFPRJh49IAT2Sg3p/dijUUG/x0++S0rAFnEppAGeIv9uLJ1fSyB9?=
 =?us-ascii?Q?0RPlixa43aNQXgJkT04VLEQsbkbmNBvwQJuAS6b5RhqF2CSboV3jKvNRn5El?=
 =?us-ascii?Q?qKpLh3aI/qnjy6KkMTX5waiDZNpEf6DE+7Fihq+neWnIOouynlnLFy3qmrVT?=
 =?us-ascii?Q?vwKh4Y+ESr2pIRfAhorjDfxEguO418xm81DZrOgjJVYDJL8Pqq29q5stTCke?=
 =?us-ascii?Q?lT49yQjgjaU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?634ckdqopkQE+clIzzPwn1GUuN03xNX6tSMotBhEXMKR9OwT98f/Ru1jXE0Y?=
 =?us-ascii?Q?sbNIWVkQuR0SpMN4s0u+ihh5tJBIaNC+mgIaLSeagt4G4j0Xe3hd1sP3tvgS?=
 =?us-ascii?Q?fEziZW6xsYtq0Pu4rutCYexSlz/fg2jMDjgPtrCFGyqlAepxllJT6y4xC9SD?=
 =?us-ascii?Q?ayOkwiGpqp1fTgesxIDLtTqvkSk9jEd7ie2hn8fUJoCMHg4ZastEecD9rWEF?=
 =?us-ascii?Q?uF6Z+OAl6tI6MB3RceqXcCPFy1oSlZiXnSt2ahqFM6ftzyPiGyTR5A2i6Eg2?=
 =?us-ascii?Q?8fo5mKIlYB79/UI1k6KFy8wxJucUpnV2t5WcB5+1gD79jLLgufcJdKjqdc0R?=
 =?us-ascii?Q?SnAt95f7BOKdPBPl92PU0BEI2T/cpltF/xq02f49MlHHcmh3ThAOYCZUit/0?=
 =?us-ascii?Q?BG2OeCCJUoBC026+KQ54NGybU36IlqdHfjoWlCtRbcf4VC9F/h7nrLDpuG1b?=
 =?us-ascii?Q?t+DkiNhZ09cXw0FYU/DkWufMkT0/HYJNoe2JrzYA+ukUTAsWWsFVql3z9mc7?=
 =?us-ascii?Q?TaPkk0mkEzN8CFgDmJCW/tGuAItX7/k6xuOO66SaE3tenSALRp2Q+etSEuUD?=
 =?us-ascii?Q?Syh//5VYv0GmbiIXOnwJJ8dSMLU0euXXSL8ixHIHpLh/H6wPPFlf+4AH5IuS?=
 =?us-ascii?Q?hPl3mHhIE7hUxfqfw9Iu+Wju+ZjYUXGMfa6fgvQwNIPM851FHoidW9707Mcu?=
 =?us-ascii?Q?J89xGKWkVG5LCYixdudsTZbuTfvdJMgh5fxDzcKVFUbMA+SwjCWK1e7C9S50?=
 =?us-ascii?Q?Ts718B6ivNu6SnP26VR2hmbx+dZYphiZsnQrtVP1NhtbO72488MHBmdk43X/?=
 =?us-ascii?Q?bp67ffE/knEop9sGEtHntt5uPKxL8dTfvfw2UELK/NCMsuEnyXJuvrrBdKQU?=
 =?us-ascii?Q?YfzDFv3zFJEnhjdUkKkuTEGTOoZh1225M3POJ2WbfTnTnAzwiygbUC5NtMAO?=
 =?us-ascii?Q?2ie4kpaHOrdJMOD6klgG5A4aGOSfyDwW4nH7RwEyg4f5phJY/gMcWodHHdbe?=
 =?us-ascii?Q?3JjMrlq3TtXe3zYm3Bl0adfBxWtsYLusl4Bm/pyACkRM0jYGYtr6VUawVG+y?=
 =?us-ascii?Q?KmSgUg5ZZr6xhWEK+D6YasUZMLHvaPX9u8Nd7r7PBQUnwL1+Az3XCFbPTSBL?=
 =?us-ascii?Q?vQPAfS6lOC/x+BmHH6Jk7ZO8s5Hb9Y2AgJ0CvrLj1hWyHS09AsWJb0HE4nmI?=
 =?us-ascii?Q?mGVhL6i92GhNRQQ4oIFM1hUFoHkfv4zaknyeMoVd68zovK/aLJvVxhdae/A5?=
 =?us-ascii?Q?5faxzHPvUjlCZVx68Ssmuu5VKhChUBHu9pHtTzHjCoXjKqlFfSVmX+B+7I3q?=
 =?us-ascii?Q?mNGyFuDmXQb5Oy65KVyxFn4Msg+Ks/DhlnPt0kjmu1UIFNzQ4kAPpRW5RKeh?=
 =?us-ascii?Q?pbDVeK0AhgZ8Ekq7mgS/GShiToJGXzDrPtr8y9fbxOv4TfTsiMK5zc5+0vg8?=
 =?us-ascii?Q?yBy+eqIv0UGg2wgtsHn9iV8OoOoDMZ9pZ5t8F1mXNvoLdN2WdevB3cnQxGbi?=
 =?us-ascii?Q?3Ej8dEA2wmG/SAGLYkT2LDWNifb4XoC5/21/7puW7TYoLDcPfWJUOhYNjuP+?=
 =?us-ascii?Q?lCcdpRiljfLZb81LHoWxXhZE3GqCa02aO/YnW9AozWbp4bJ+scamrR9ykM2o?=
 =?us-ascii?Q?Aw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: c/ks1Qi4CX07e4+4yKPt2QvT/Gl0yVzmwaxlYsRimt1rz3DASGvafPvLQCcIjL4z5ifSaY78aDsolAYTYFV18MrXrI6nbwqrWS1uyAoLKDqr0lqLYlSYAbkxspA6aP2I17mNPj8ER38eYhpRoC17uyazWvEBAtKqkngDeh4w1VyiRnvgs7pcD4jeXveSj9oKe1PaU5XFrRGHS1ZBN+3K9lZkTwBWuDWfUmJuKZq+hhWc1TqoafbGs5E1oSJ+KYXVQHEofp8S+TyPAN/8rdhhs97veWro8E5HrV0JqZuCGVdQ2KC8WRj7TNt4POHKgi+7hryKprHNKQVR7ZCtQ4sm7gwW3sxDNrp7oRQxO01QqDyoCXtE/mSopPzS9iV3esRythN1t0icJXZjcIqhXq/zKXv2qXO5SZxV4F6D/6MQHLBg8kbtTrWNfJxMAsEs2bNsx9/ApoV+Nf4BhB/vweuHeClnruJH8zcreRU/YlQCjV9Ucg1yKNm6m3A74WH5UYlE4cweUI46OJ3AoduXUv8TjMf08p02PuVYikc/OjHKXR0JFVVHbW0WuxR1WHzlzITCtQsYYivI3JiidMmGG9quK5DkKyBfpcmSq40ITWnvYak=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 58307290-420d-4b4e-1467-08dde6face80
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 12:51:43.7968
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kzy7lqwubj8TkOkVvgrah2jeZSs6ow3pPNNg+vaCCM/zlbeuHqtZgkGcH0FY1xSIwhwxPj7Ikh1HzhVw0VH8oX+fFSqtwihUr8ge0iAhY+k=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7905
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=834 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290107
X-Proofpoint-GUID: j4pmZCMJvq-QMnwmX-e6gHT0_v0c6hkb
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNCBTYWx0ZWRfXxE+ah7S+2KnY
 X4Spn2G/FN4irPLpEPwcVLP6tRTujdYusfbvfvrkAqzitcBEZKwWrGpB6dKwDWy+pS3bDzb1ABa
 r5n+3h4DlinzlvP1uaJQXk9w07vZQZe+H/aOGrUIbqUVMANUCuJ85aLOHztl7AoRQclaHpA+AGy
 QfApngsD5RX+1ptspNHwm1gnUMEtsDHLZ0nI4V30aiDqwh25KYI/LPzrVQ3A9RdTbVAyTjJKGEh
 plxJxt8ymmTQAScQL+ZVU2Y3Xzng54Ly8Od7Iw7u3RuxvmuK3Cvb1x22bxhUXtOSy93EELMuzAH
 rotyfZ8AE68sBmt8jtnZl3HzxfoHbD2Yw3k3E4DFr/ncdIoxpkztZ7rhmYvVj8p/itoHvSkkV7s
 BIwDn3br
X-Authority-Analysis: v=2.4 cv=FtgF/3rq c=1 sm=1 tr=0 ts=68b1a265 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=08gvc_oQcYO4o9qCUcwA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: j4pmZCMJvq-QMnwmX-e6gHT0_v0c6hkb
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=sf1ejbJ7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ZJs0XvGC;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

On Thu, Aug 28, 2025 at 10:51:46PM +0200, David Hildenbrand wrote:
> On 28.08.25 18:57, Lorenzo Stoakes wrote:
> > On Thu, Aug 28, 2025 at 12:01:24AM +0200, David Hildenbrand wrote:
> > > Let's make it clearer that we are operating within a single folio by
> > > providing both the folio and the page.
> > >
> > > This implies that for flush_dcache_folio() we'll now avoid one more
> > > page->folio lookup, and that we can safely drop the "nth_page" usage.
> > >
> > > Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
> > > Signed-off-by: David Hildenbrand <david@redhat.com>
> > > ---
> > >   arch/mips/include/asm/cacheflush.h | 11 +++++++----
> > >   arch/mips/mm/cache.c               |  8 ++++----
> > >   2 files changed, 11 insertions(+), 8 deletions(-)
> > >
> > > diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
> > > index 5d283ef89d90d..8d79bfc687d21 100644
> > > --- a/arch/mips/include/asm/cacheflush.h
> > > +++ b/arch/mips/include/asm/cacheflush.h
> > > @@ -50,13 +50,14 @@ extern void (*flush_cache_mm)(struct mm_struct *mm);
> > >   extern void (*flush_cache_range)(struct vm_area_struct *vma,
> > >   	unsigned long start, unsigned long end);
> > >   extern void (*flush_cache_page)(struct vm_area_struct *vma, unsigned long page, unsigned long pfn);
> > > -extern void __flush_dcache_pages(struct page *page, unsigned int nr);
> > > +extern void __flush_dcache_folio_pages(struct folio *folio, struct page *page, unsigned int nr);
> >
> > NIT: Be good to drop the extern.
>
> I think I'll leave the one in, though, someone should clean up all of them
> in one go.

This is how we always clean these up though, buuut to be fair that's in mm.

>
> Just imagine how the other functions would think about the new guy showing
> off here. :)

;)

>
> >
> > >
> > >   #define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 1
> > >   static inline void flush_dcache_folio(struct folio *folio)
> > >   {
> > >   	if (cpu_has_dc_aliases)
> > > -		__flush_dcache_pages(&folio->page, folio_nr_pages(folio));
> > > +		__flush_dcache_folio_pages(folio, folio_page(folio, 0),
> > > +					   folio_nr_pages(folio));
> > >   	else if (!cpu_has_ic_fills_f_dc)
> > >   		folio_set_dcache_dirty(folio);
> > >   }
> > > @@ -64,10 +65,12 @@ static inline void flush_dcache_folio(struct folio *folio)
> > >
> > >   static inline void flush_dcache_page(struct page *page)
> > >   {
> > > +	struct folio *folio = page_folio(page);
> > > +
> > >   	if (cpu_has_dc_aliases)
> > > -		__flush_dcache_pages(page, 1);
> > > +		__flush_dcache_folio_pages(folio, page, folio_nr_pages(folio));
> >
> > Hmmm, shouldn't this be 1 not folio_nr_pages()? Seems that the original
> > implementation only flushed a single page even if contained within a larger
> > folio?
>
> Yes, reworked it 3 times and messed it up during the last rework. Thanks!

Woot I found an actual bug :P

Yeah it's fiddly so understandable. :)

>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/549a60a6-25e2-48d5-b442-49404a857014%40lucifer.local.
