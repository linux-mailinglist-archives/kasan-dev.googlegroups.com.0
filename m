Return-Path: <kasan-dev+bncBD6LBUWO5UMBBSWTYHCQMGQE7OUDATI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 56A12B3A21E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:38:04 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-61e1369316esf47100eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:38:04 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756391883; cv=pass;
        d=google.com; s=arc-20240605;
        b=UVl+QYL6O+QZ8TmfZDpzfHNgKrj1WST9Lh8rx8SOiYPHlnsOwr/7ZFBM6PeE7FW+oD
         ox8CuBJlG8LLILZbe7HFGoaiiA+JxYh0ZugThn4TCioLMhdXJbHcgdj5i9Sr51BiboVQ
         oJAYbJa07ficcU0qDYmSC0DF7b5qOFV/BDYPnxyr4JPmjOsj1sSWmS2wH9Q43xF+lHHE
         V40bYUiiZ1kkHZsc3BkF5qBGRcVzNEWoxPUHBZ1M2ty7l4tvRCOvokiV2isvYHrs1oKL
         9vpgOV/n3TE1kOxgx6CkqCO7qH7wSYIcv7leaRAzVmboNDkiqNTewmiZe0q4Zesgahx8
         OZcw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wRte2Z+4fDJssK86eg8qoDeoiRoRN1QQrWACxnxCLr8=;
        fh=i3cL4wn1Xi4FZV5cfl2VhMlx3VbCT4AtRELnaAcnLOQ=;
        b=LBRhFOzOas9veLtuF+NgvrGoDY0Y7QJri8XVAVGG4RshBGDQdb7w5WMNLw8vIEFDXn
         FfeAzOHGVvdPXRGGjy8ftQyJq3RLlS2+zmxXuaSZp6ZI51+zpwNVD5vg9OnR3cFCRAPA
         T4bqKA3JJeWxO8NxKxneW3G6yDMaoC0lFbaC7+snRd01CYEbsPSnn/hMXFVLNfO69A9A
         6rlQKPnzo9Kh+nL0hu6E65M2tBUpxHTyt5w8Cqt1joAXt6ewHU6FMIIHoGVDbBMic7hW
         NPf1hMG5CsIIAA+AClLFqBr0jSpGsrymmIesiAKIOOapIK0EIz8Ncx2zWeydyYQnG1ge
         Ihmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=b2j5o+23;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=i6xeNvLr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756391883; x=1756996683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wRte2Z+4fDJssK86eg8qoDeoiRoRN1QQrWACxnxCLr8=;
        b=o5tvfpH+TBa4dd+y4vELEjJQn+JQAIl0hoLvUdCyptX0OqC5V/Ozw2wA3zwoZ1KEG5
         kjxMy+RhZiF950P+yu4BC2YJWtLoNWShgRhfuJRz3uKouMIKAHHEXjY/kp1K1vLdG2Cm
         yV/wiO633xTa/w4FdkODkO4hpek/EKDK2OXCKR/zlciL8Rkj5SAVe08bWn/EYncP3+j3
         kYUGnKvVitm0sc3K3Lw3uk69/M35EDTr7Q2vTANHCN7QmJEy8/SU7JmgyJkZSEf/fGll
         Sq+yc90YzCbrfyX3OgUKvJIbm5eqjvDhElySRoVgc5r0jghUfZJ/GZb49JlyhF5GeUXd
         b/EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756391883; x=1756996683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wRte2Z+4fDJssK86eg8qoDeoiRoRN1QQrWACxnxCLr8=;
        b=hy5TZadMUG4j9HGP7BMNXvaEYIRTZgAMjMcBMcvSWwffee6+fSwIu+U6hoD3Sg34+Q
         1J07gqcHdt9uETgtWnjIQogBnPrY36U+Ci/WGKcq7kyjJK8AR+9ofIiB84+5Mm8FyJYZ
         uJbdl1wr2knsbjO54Ub1YUtxGjpgnmi42caorJbruUrZJZQjM8AbFsld70NuQLIlKBTH
         4XhrhiOt57YCOmVMOqG0RzZ9299G7ssI5GN5vEieCNBi//szKjTNzp8G//1zIHmCWpl2
         9p5PlI2CmdaX68y08vAQA+KWXhwGEe9UeaXJBflSQiT/QbeB8T74xlgK7VP12NX3Kpn7
         RCyA==
X-Forwarded-Encrypted: i=3; AJvYcCVbklh7l21g47H1OyMLpTU7aharDHKtJSXlAbgK4Ax8UW9C4I1dMjM4dEtRrADVFTmD4uOHSA==@lfdr.de
X-Gm-Message-State: AOJu0YxjpTugREq1HhwMcgPwY5+vTVmcJHNNoRaZTKUoewb+Ok21Ivn4
	MLENPBKsLvkkNd+bFkZ/czk/sqy9rnhHHUVyrJ11t+4xP+AY8QyOcpfS
X-Google-Smtp-Source: AGHT+IFyL7xr02VQ4EdaUoYCuU80q/wh0BjqAKRySkwJ4qfxGBM8bfFJCXkI7XU8iLLOl6zbC2b+hw==
X-Received: by 2002:a05:6808:6a87:b0:437:c839:ef3e with SMTP id 5614622812f47-437c83a069dmr3827197b6e.11.1756391882616;
        Thu, 28 Aug 2025 07:38:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc7y9kghLxL7REVAkr8Q1odqeFJz6OgqL3HLf4DuOYuOQ==
Received: by 2002:a05:6870:331f:b0:310:fb62:9051 with SMTP id
 586e51a60fabf-31595d635b4ls350669fac.0.-pod-prod-02-us; Thu, 28 Aug 2025
 07:38:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWwDrIm7FlZQrwKiM3pnWIbLwUehyIQzpd3I2YfOofIfjRWj60UJ/9yTDRcB8eBTTZWCVr9bt2e7is=@googlegroups.com
X-Received: by 2002:a05:6870:5693:b0:315:7222:d4e4 with SMTP id 586e51a60fabf-3157222e5e9mr3009506fac.23.1756391881747;
        Thu, 28 Aug 2025 07:38:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756391881; cv=pass;
        d=google.com; s=arc-20240605;
        b=jiwEtBpLcAV1Ln57AsoGg8sV2pjUtYqvRAFojwt6X1OX4lcte8qPCmiwxUEhdVsIzY
         UgfqHZSIwQTBcWY0+JtKy/s02Axabw8ou1ObzvJtqGZreZ9excAadySJxHe/s9t3SQAs
         Fn2YKu432081vpCxzHXZ9OJGKMOvvejnJeywn9grse0Bhcfd945lCiQUEw8k6TLm9xpT
         YP7pdH+sxyfUq0fBFzQ5J/JKJApXTbQZtE/F5H0Q84V9HUn2yC41HBYlV9aAeNdY9+K/
         yFpsx0z39+WcthhxJF9M3ReMPENcGSp7UCA6Ri1CYTAb6IMGixk22FThwvtI23AlMu2Q
         YJCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=b5tH1KF68LQjaOoMhaMize2UsFV2gZYrGIOvVBiOevM=;
        fh=NeSL1cR2ZBMAybBPS+m8gT6YhBemv0yBw2O7VZpkqgM=;
        b=CzOi8ZMpg+VtW8FnPimZdKgTqa4ls3Plos/Ar5fnGntAn3VZa1QoEsr7pTVwrzz5an
         F2BYIFIgiKTpg1I7zOQX7oTDcpLCI3gNlGIkTtWMngqxb7tp+pMKGQHH7CFjZTfQ8Vqb
         CSLYICsEezDR3GCk6Jj5vSgYHAEIhhZKCAMR66tK2AGdIXIXjuSRqjtvo2R/thptKf7p
         PnZK7k4ty0c9sY/darzEF/Giwq4uQ7kXWh8aGnz9lrdsRt/zUy5NrL5eRyxz1v2mMb9h
         yPvBHDkwmQcfk67nWB1vN+dU6VLxu3Yk7owpc1bvh5zg93K/j5XTiD2+K6r/UMjWhj5p
         fRZQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=b2j5o+23;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=i6xeNvLr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7628375si759835fac.0.2025.08.28.07.38.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 07:38:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEN3ec000406;
	Thu, 28 Aug 2025 14:37:52 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48r8twfcqa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:37:52 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEVXaE026713;
	Thu, 28 Aug 2025 14:37:51 GMT
Received: from nam04-dm6-obe.outbound.protection.outlook.com (mail-dm6nam04on2045.outbound.protection.outlook.com [40.107.102.45])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43bufwx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:37:51 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=a0qJ+Lg23t5waMA8DYkzTfSPnR4BRWBL0XR2Y51p7swZUDzbEUR9rkSNY2zmW0Zu3ooeWEcVHL2MLxgHh4VguXX47ulW9mgdlF9z2dYHeVqMmXWKE+FaVgR0KTVnvrr2M+TLMU77OprC6QBNiCFoWkhJEZsCqqtm/LBIoJe4Sm5NTozeCQI8BH5roJ0YU07+XvAGvxVd+1HQg7RhOqSTvFZUZOYtEPHNfxKpl/qLi1lHMZpiZI7I3nlmRz8Nnn3GLpmsOTOI+VoTAAX093KvniY9GK5y5yd//85/5HALuiLPCHnX4LhET8IWyadL7HXNdx9h6Gsy94BzVZgfLScP4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=b5tH1KF68LQjaOoMhaMize2UsFV2gZYrGIOvVBiOevM=;
 b=gt46zDZzcG/zh4R05gbtofOLHONA1SFRAxeiDEeFhw1FyjZsscTgD5PIr7DnZ1XvmmOjvDkKCqffAGvwYY6BYHKjJ1I6gcCROQEWWMowVmfGuuJ0zxj9Y8aqjkvdybi6MFeBOQLVqgij4a2m7VI6EVHy3oIQol2YlJiXeQIEFW+PQ21ajZhruYCVQCqE07GJ71mUTEHMjYNjvo7wvRD/YMx3ffPfEWoZxEX+//L+zndkbbuBfIL2gG1BzYKWYGxxxdiTcdZr4lzkAbd7DzDQPSqPhzCexuVe/9y/kwJ76j9wrS9CSYeb7wxTsWhp1tPHmdmR5tGEo8FlqNsIMKvaUQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH0PR10MB4805.namprd10.prod.outlook.com (2603:10b6:510:3b::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 14:37:44 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 14:37:44 +0000
Date: Thu, 28 Aug 2025 15:37:35 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
        SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>,
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
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 06/36] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
Message-ID: <f195300e-42e2-4eaa-84c8-c37501c3339c@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-7-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-7-david@redhat.com>
X-ClientProxiedBy: LO0P265CA0002.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:355::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH0PR10MB4805:EE_
X-MS-Office365-Filtering-Correlation-Id: eb9e2939-59f4-4e8c-45fa-08dde6407338
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?M7zGZc1w00WwNtxojrVZoPiF/vBUdFHsVZs1gX7G4vEVz7s9MRncG3Eo3vO/?=
 =?us-ascii?Q?sDtzyQxIbOT4Op9wCcsbRO7im1RBRWlp2BB4nTxIHluQfYokKcWjTRbZ4pHp?=
 =?us-ascii?Q?vuX/tvgUbU9zM8OXcfAJllBzSlPpLVjJle3IRkNY9aiMTAX7q3LIx8GuG3X5?=
 =?us-ascii?Q?mbeGVxfINcSKTRUvJDSVhIkSqlm1ij6LaqjcvTkMqFRXgl3GP5skgxge2D53?=
 =?us-ascii?Q?PVUT/Me7Tkz7VMN1ev3NPk8tV8OMdP8jyt0CTrxhcXLSwpMe65fkBE3B/lpJ?=
 =?us-ascii?Q?uLyO5oVnNRpNT76IXTL3wHAeQUDzynz60HVVpLOxpLKkqLzUEwDTZIAXqWTu?=
 =?us-ascii?Q?qH2+GW+Pae1YzJlh27EGJkn0HbnvfNKnjCVafbx1pUUbtgSyryV1ZowD8rf/?=
 =?us-ascii?Q?8oc05fhNq71ogpBXVYevt5daFRpI7ZarX650U5eBGSqhyRgw5mNTf3hV8yBI?=
 =?us-ascii?Q?zAhTJ7tvlbd5rBSolmpIxmh/i2MD62wxj/j6Rxz8AMkuV1BzpGODIRERV0IE?=
 =?us-ascii?Q?tGzAd9MxDxJuLPzpRoLWtVcbRWYYdFwK09LDc+7kF2OKPLzMfcdaUd3wjQh/?=
 =?us-ascii?Q?LdzeSBsccH3OSwe3m80AxgjqU9bJySoXdMWI+JtnfgWPVE20s6MuPC++URnV?=
 =?us-ascii?Q?uxNzK4v+BYUCShkiaNqGML/5lWWfM7/IqheY11HEzo62XwjF1ml1H58lEpO9?=
 =?us-ascii?Q?1SaWi/auO8y3sMIWxon6jsJZ+4hmh3LFF6BOefaEMPdQlql/x3MLmhHgSVds?=
 =?us-ascii?Q?YRO0Ch3IxwsK9tR0hNOGhsD3WZu8QMAhGlq0jjeGmlLCgxLlQPvV2qeFNxM2?=
 =?us-ascii?Q?BXMa6+l4V81T06PPO4z3tDR0Flj3zdWZVkiREpK1vgco88PUCpES/gjsXR6c?=
 =?us-ascii?Q?hSY+OMh+mCqKUttj7/BxNnNEOomw8Gx9ZM+VxkD3sSRbexSv048wrFZNgDO/?=
 =?us-ascii?Q?EcAZfT8VENlrQ9ohJGtD3M6eo66Ll5K+bjoSR+aJx0vOs8BohzrJN1DiSB16?=
 =?us-ascii?Q?MA9hI6m1DIdqxHlhsKESdkMAfTTa0u9T6Jok3mCocY2i+bfGUWdFuCXfVs/F?=
 =?us-ascii?Q?/7RdcIaAzJUlkxkqUuFei0rSkIX6M9lEZNirIfy75LZZNSJByNDfBDi74BJL?=
 =?us-ascii?Q?KRUJQKsDGiANgyR8MPu7WcgrPXo4ciKov3sdQcZq2LPT6QgVf2e1qqYaIiFC?=
 =?us-ascii?Q?2C1BIsM/B+5E1msIUej1UglhoDiZFSS5fSGOLL7kbbLb/Rf+uyICFivcY009?=
 =?us-ascii?Q?twha1eug5uI6oe2PQ+vytoKjs4ubSiiPqQmKmYUuw4ayNC55OUka/klP+pkJ?=
 =?us-ascii?Q?2R45ChtHxcIIxyexDZ+qxRPNWWqd4+mHv9vv8yNGnTjV2E50Stib3iNAKHAe?=
 =?us-ascii?Q?Ww/gWSrr+b1M2JqDcq/WLyEj2EqAJZtXoP2XxO0Ij4qpGHQbKc9b5y7wnUBW?=
 =?us-ascii?Q?WBdo62zLPDQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Akqa78VhwHUQ17KQPjFrOz7y+qII2Mkmog9vivy2SkU7BBF9nuKHaSG9M/5B?=
 =?us-ascii?Q?X1ho3QAErdGOtk0M34DnVgkly2pKJvicReXRzr3PdxCdFx8FugRoKllPkckE?=
 =?us-ascii?Q?9Bclirh6j75DsI48zu4b67Z//qsUgGy2igbxKICae70mDPTFtDUJ90G7x6tt?=
 =?us-ascii?Q?Ica/lfCD2X/VRB4B1QqXeMlrl2dTdutar30ik1kZR7DAkCN2Id1AbVUtLqdj?=
 =?us-ascii?Q?NMHdG3c29ZiwyCvXUp8bfLDAWf4B1rTyp8DosXWRZaaHaXdQ9NY6HNPYp74I?=
 =?us-ascii?Q?LZftuHaZsL69VxWFYKS1X/Ft2lv2qmV6kN1XpG+zhgAtHzHTvcMvIot/RfzP?=
 =?us-ascii?Q?yTusWszVqqMRK8W95XAPWL3Qd+i8bQT+AsB2sOKKHpxrfxfv1nCq3kMKTDkp?=
 =?us-ascii?Q?4OwJBdHJu7NIKo1I+IYZdhTrMMTFCFCIYX1czZGmESlX3MmIGnQeQS1tNBCw?=
 =?us-ascii?Q?mVuhGu7d/sDmmQKNCHcoP10NBf87nawmibR9X31M+CXJ7itFaUojTLCCYSzA?=
 =?us-ascii?Q?d6E4k7mjO0XGb8en9vgk5/omiDWlCUlC9IxE1tLaASZ46PUMKipjzr3PKC1J?=
 =?us-ascii?Q?XQijHDgqymfJq3D1KoXa7O+FGLYpRXRnnWKjvieuTti/MaiElrUwptC6Wtd5?=
 =?us-ascii?Q?9l8wIcmMXvZiaz6GL6CazNIYkrSf9zYNv8WyobU7ut/fz571M8naMtO0Pmi9?=
 =?us-ascii?Q?mSoOsmo9gNWsSbAGv5q6k8Keoug+MCUfCr+T/DuFSTLcT3YskyJ0NCvUYHAO?=
 =?us-ascii?Q?RHKP3xbXjYVDJnfj5vPFi+GcWaLjpAQ2YUzBj0bxy9h9+WPrC4tjtFJ7dIxP?=
 =?us-ascii?Q?lUxo9bLCxKTAa/GrU33XrlwSZd8sbRiQ6dNwpduiyZg8Bm0fKunjRAlS3A4T?=
 =?us-ascii?Q?zctx6vBbWDsne29FJyAyxkOqRHv8sieVahB/wcNsA+cLJeue2sl8U8XnN82j?=
 =?us-ascii?Q?DlDOdG9zehooJUnEpmTyK4w3jlSuB6Tb49rhs4H+5be9Jn77ouqK+S3NW5mE?=
 =?us-ascii?Q?OwCLp3g08UfJMAw71TwDuz9lPKG0GLJdLrrLgoz1kN+dLsjFUoigVR5LbPc6?=
 =?us-ascii?Q?hfa9kvSvrLBAh9KZ8YiHnhfkhSA/JbzOFposPp3JkGmFBLwpj0r7hkayeE66?=
 =?us-ascii?Q?z15j5WZVYVim4Fk8YBxTbGV36S6M2vDdXzu8f6PBLb9XtUrKwR0p8WBAyHAo?=
 =?us-ascii?Q?gXEq9wTG24wl/uGU/YUMLLmhTKQ9jLm7thZeNzhJtjpqagp2njuDSBx2IOBJ?=
 =?us-ascii?Q?c5eD0urm+xI90cDOuK+v72JEy+kL83BmNghi4+oqaq3rLDeBpZMOqNM2KV16?=
 =?us-ascii?Q?AYJV+fdTyJKw6tHY/Q/3FHHNUMFSJuu5CTIQmEJeHGnUaXJ+kygO7qRQB8Xl?=
 =?us-ascii?Q?y2+UKkQxV4bq7WyHeKmU9skA7ejg3zrS9HuKPWsFb033/ouCWmYBPrQFxu1a?=
 =?us-ascii?Q?5dypH/PUZUqDlgSN9lg+L3LPWK4Sq9cb/6GjNY49oQ5DpGGNRLNctovFRwuj?=
 =?us-ascii?Q?HxvTEqI2Cbw3hg7y+u2AUsRvtzwE+YMB6/84ZwI317DQZHgL6++RbnQaRLgv?=
 =?us-ascii?Q?fe+gMaeqBmFQE8mOB4bM0pjST6ggVDXGAsetc6ayRCfC9q+sgUPJZvC6anJp?=
 =?us-ascii?Q?JQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: GB41Br72xk6xcT2SgiVZYaAHSIhTipPwhDktyaUU0My8xzjpyXNcpkLsasn+kf0bc7uUcjMvzTRxO6OQGs69XY/5CzWLUX4TXs1aYgiOTCqudrLbm+2PUYQ2i3NiCFs4/qvRBAI+g0zPeNTbaB5og1sbZuJYE9VWKUCLpD88U4G+/x6bahLee1G1mI0wmPD8W20TnMoN+tiNr59vroI5DdjObYKt94ZKhbq9s8ek1V187vlRo793ZynBznt21WICKHUXu6WquNq+u12rjFNPdggLwWCWxblhNApKPpRwxA2k0onZR6s+Te/XrI6Tb/QiGpBTh5Fz1IjsxNJXccCw3hxI0LBj0aujkt/QIxqTP+8+xwm6bQc1Hta40Uq/h2D+FXH1GmLGkeeBGP7/EUl9NqHdcKA3aCDt0cHdaxeimDPaKR7VoaGfT4e13ilxWqIh1igWIPbVQvALIBoQqUEISNVJ8VM0NhppgE6dzQfnUJ6WE1lsNFZBFIFQarP4XSNUv9V4i7XMbrzq4ZDRUvPuQI7AEZliWHYLyEwWYJMVeEEHjRpbu/I6cdMLCMyFMO9X7MnqdH6qIq8pafGmAdi+eWM5UK+VKXaZGGqJiN097mo=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: eb9e2939-59f4-4e8c-45fa-08dde6407338
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:37:44.2450
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DAxhMYM1RU26kcgJXOQLgyNf4FE65bGw1Gu3pURATNPhoOOyE5C+DMXTVHdaFQdVbxVrtDO+MqtD9akAIIzFT1kA6XqwIIE9QSxm8o0UY08=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4805
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 bulkscore=0 malwarescore=0
 adultscore=0 phishscore=0 suspectscore=0 mlxlogscore=999 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280122
X-Proofpoint-ORIG-GUID: wAZJjhuMqLkWt6-vx2lJZJ83hLBAGVAd
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODI0MDE4NCBTYWx0ZWRfX4qtkk7sbDvE9
 gHA4uoQUCcz5YALuvEEnQlruQnzlvQDB+/rmpf4MxyWaQ5AVH30mpdBGId2AwGeNi6vpV9hYJJQ
 nyp4CDzJ5KOP8RzPb5QaiXFn1rhuugl1Zo/sR3XpPMQxOLXzLtZPFB0yMxvaMTCSEccGvjSD7Di
 gtOjXbjJghnSVvEoN+oD2Am5sdCRP4in3AU805OZIf/GpMLQfVaJbqS3ifquRIbhFsIrwlLP1ue
 sTkBuyYvL0WaYNxqBCLziXSdlp6xAGye4Zod+MuBvr70qihm+bDECB32BviQsC6qOomihPHg457
 Ol0RLAdzzELQmRCyQPtZyHCGgoH52GTHqncgItaxOW1NYU9eQL8k60x5Pi4VmraDJbLmntqZpEc
 MO/6aaKM
X-Proofpoint-GUID: wAZJjhuMqLkWt6-vx2lJZJ83hLBAGVAd
X-Authority-Analysis: v=2.4 cv=IciHWXqa c=1 sm=1 tr=0 ts=68b069c0 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=VwQbUJbxAAAA:8
 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=W-idY8GWlPOdh4pKdRgA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=b2j5o+23;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=i6xeNvLr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:10AM +0200, David Hildenbrand wrote:
> Let's reject them early, which in turn makes folio_alloc_gigantic() reject
> them properly.
>
> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
> and calculate MAX_FOLIO_NR_PAGES based on that.
>
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Acked-by: SeongJae Park <sj@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Some nits, but overall LGTM so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  include/linux/mm.h | 6 ++++--
>  mm/page_alloc.c    | 5 ++++-
>  2 files changed, 8 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 00c8a54127d37..77737cbf2216a 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct folio *folio)
>
>  /* Only hugetlbfs can allocate folios larger than MAX_ORDER */
>  #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
> -#define MAX_FOLIO_NR_PAGES	(1UL << PUD_ORDER)
> +#define MAX_FOLIO_ORDER		PUD_ORDER
>  #else
> -#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
> +#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
>  #endif
>
> +#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)

BIT()?

> +
>  /*
>   * compound_nr() returns the number of pages in this potentially compound
>   * page.  compound_nr() can be called on a tail page, and is defined to
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index baead29b3e67b..426bc404b80cc 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
>  int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>  			      acr_flags_t alloc_flags, gfp_t gfp_mask)
>  {
> +	const unsigned int order = ilog2(end - start);
>  	unsigned long outer_start, outer_end;
>  	int ret = 0;
>
> @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>  					    PB_ISOLATE_MODE_CMA_ALLOC :
>  					    PB_ISOLATE_MODE_OTHER;
>
> +	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
> +		return -EINVAL;

Possibly not worth it for a one off, but be nice to have this as a helper function, like:

static bool is_valid_order(gfp_t gfp_mask, unsigned int order)
{
	return !(gfp_mask & __GFP_COMP) || order <= MAX_FOLIO_ORDER;
}

Then makes this:

	if (WARN_ON_ONCE(!is_valid_order(gfp_mask, order)))
		return -EINVAL;

Kinda self-documenting!

> +
>  	gfp_mask = current_gfp_context(gfp_mask);
>  	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
>  		return -EINVAL;
> @@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>  			free_contig_range(end, outer_end - end);
>  	} else if (start == outer_start && end == outer_end && is_power_of_2(end - start)) {
>  		struct page *head = pfn_to_page(start);
> -		int order = ilog2(end - start);
>
>  		check_new_pages(head, order);
>  		prep_new_page(head, order, gfp_mask, 0);
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f195300e-42e2-4eaa-84c8-c37501c3339c%40lucifer.local.
