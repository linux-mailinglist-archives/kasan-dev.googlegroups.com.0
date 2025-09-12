Return-Path: <kasan-dev+bncBD6LBUWO5UMBBHHHR7DAMGQE72S67BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EDD7B54948
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:19:10 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-811917bdcfesf401799185a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:19:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672348; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kinw7x6LgbfHrg8JoJMTSWaF452a+Wf7+K4T9ahdKFer8h3NdunmPsNzWHHT7fBuWG
         87NHpjxZyS9NcqrbF63Rg2jd0Sh1T6slRTAmCHLWvbHsHbXQl2wUDh6e5b96XVjZahcm
         ftfk9NHt3Rio1QzoMUk5fdpD75aC65zZ1hyUwkcY9lKhRer3a2FBC/A6KM8455JUtg+l
         aSiydeRgLaL1N5aclX2xfiUngmNLgzami8MeDXs/MuoU/tmbhMRqfF5vu+qCx6HBX9+t
         iwmb1WE6xn7XGGDJZxPXEXv2rodLPF9CnEMuz0s1Hsl+j8hvBjqrAepFtznvIsnXQVNx
         loXg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bjmoxK2rgmBJVLxK37LdwUgciEKWKhRKRoNREa7fxJA=;
        fh=Zd1ZBR7jPI8t/LT/oUVtuRkpNT0lkgZ77sx2Zo4Vntg=;
        b=fN7U3OGfPQuI5GcPAPxn93ejR50OYeDRE7HxT7QZKF+ZnG/gDl0cPPzXWDzEbfNZqi
         Hvo0vIz0Nqb7J56mqP2V4FsjEP7AUOgldjpb0YU1xzn/afYHsGSCwhlp5gMEbt5ZgjfX
         hmgUhOwjArEbEs+91JK5nFjyRSJGhbbrGwSsRTGOTV4FvDgbTPvXWHW/tgj7fzij5SO9
         XzCEIJ4r4mAnlBE77AOf+VLUJatFe369y/huvBK86H+Xv5HDkkwF8MUxilRLfhQaej4n
         M/ZVKpOB4/j/EaHLcanmsnxMXawFjgNKIUvEk10n0Zvf/U/poQegxAw/d6J1Bkq8U7r9
         u3YQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qmDf+BUN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uKAuzopr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672348; x=1758277148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bjmoxK2rgmBJVLxK37LdwUgciEKWKhRKRoNREa7fxJA=;
        b=RAvfPgJEL339ZOg6lznZ/7KrUh+W0/pjqb1rEKuBUV/wvQF0OGLRXsQ/YZG+cDW06k
         yYRnmMExH7x6aBOd01R2bdHLwGnDdAkmVSBn8Gmy0xPEHXlCC2j8z6Jl+fKu4k6QuJxF
         4rDwOUQoXzV972yYU1+emc4Lf3nY5q36IiUZTaYaiQtDvWOlX+vmusjAtXZxKZcnqCNg
         78kA8juhFjDv6sfBobRikkH0AnI7P/2LyRBfI9MHs6e7sji+hl3gIrstMhhYqpGhxD8P
         3FAaXAtoh932oS3qDVuonAw1Qzk/Uljv6FqjZEVOmxIMZ8gdtkyAYuB+5qDY2BZhMaEh
         kZ0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672348; x=1758277148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bjmoxK2rgmBJVLxK37LdwUgciEKWKhRKRoNREa7fxJA=;
        b=izXbDDduk31RCko3kZ1B0puiAmnzdl0fN8Ann/dpEbp1h10keKVWrY7R8HG1j6AfAP
         6gXDLDj3o7RCHIj8eEkDFOMo+lmpid93Zlww3QNEwmDUzV2fraGF1As9sm5+PaAvtgXj
         AB02TsSgiO2aD9OlkAksMKiNopk7Q5zSqC8cKmiT/MIKl+faYkNmSIeDoxqcnpNFi/xr
         UCNqRhXevQFPUWQSLbT0nM2Hc32cvuLLwYa9BqWb7LYdk+nKaBcm7inobVUuvRmhRO7r
         UACuAzQiPk3lUbNnHjdjiamKpHJ5tXz2rBiiU4vKENAFmcBg29Lgpp1cGSK3VO3SdyIu
         4nQA==
X-Forwarded-Encrypted: i=3; AJvYcCWcMSo5rKvWLGEd7L2sDu5vIf6vQKBkSAGYVa31c7UIwHWbDxDHRVVMtMNb+8i74SM7+Y+s4A==@lfdr.de
X-Gm-Message-State: AOJu0YzGpWmAJLmP42v9+4Jq/hpHUXR6CaAO1nIOaDJvEX2yjjWIpZkU
	+UhivYKZSivXxIu6AlxUj7J/WRtJVT2ElpaJG72suDC4J/6P7Xy26Hwr
X-Google-Smtp-Source: AGHT+IExdth7jWNofhjGbBb+0F9aS2oxQlsuQsz7awIlb+w35C8ZTaYh115+ibF8NA6+SsVthlqEvw==
X-Received: by 2002:a05:620a:f15:b0:807:39c9:e3f7 with SMTP id af79cd13be357-823fc1d4927mr309754385a.21.1757672348511;
        Fri, 12 Sep 2025 03:19:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd4xcCvP0SUiDdqtYurWqSbof3+zuer2XcXNiXWr/gP/A==
Received: by 2002:a05:622a:3c8:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b636ccb94als32302361cf.2.-pod-prod-04-us; Fri, 12 Sep 2025
 03:19:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXmBSxtiqZlbC2SO9t8k9re3KgcOntpby7aCHFpyj0yLlqkhxGs/lYoVFLkskZ8sU7sKT4pFdKY1Lk=@googlegroups.com
X-Received: by 2002:a05:622a:303:b0:4b5:f7ea:9481 with SMTP id d75a77b69052e-4b77cfd4696mr26263821cf.32.1757672347682;
        Fri, 12 Sep 2025 03:19:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672347; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vy1LGEARphgf9LELPg65LJ12Wdil1nG7dG/n2lJJhN2xOw5phxgMIMSPxzCZDJ0sEe
         2UxQTDRogSCNFTqwd9dSiekP/lDTxWQjla3ivwbDPNGYR6TzqfTsVCHAu72kJwebWZ9K
         73vpNkpxKGEKXAxIPMhwT0mOGB/pYtM6iyM/SMGFbxVSlyvSUKgK6mO69vv+gRJ7bAWP
         ck1y8ZUD/IckQGRAwlwwlLoj5pWXf1EpvwbjgTs0wbT3BGDVw98nhOpXMsp8zIa07VfF
         PYIH9rcpfmp0bP7YJqH6MLULk0rRnVrR4ac1VWa1F26RaH3jMNeLAcPHVSEeM7e6JX9j
         LIDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=jX6r33sMvr0LNF82P65KSYJbjNMhMhSygE7yQ2LKK6w=;
        fh=fxoU1dqsh2V77cxUchWkOU7qzZ3JmF6mdakC7cDNnyI=;
        b=T5D9eV2mODF9ACrHxI+qYkoYc2Krqn2Oy7QYaPrSE6sveJD2twnkQbeqJNTX7SD4yP
         Wo+oocqUaDGzvQYk5wK0z0huZTuOcGhmCp7uAUODeiJzYy4N42sozSyZidlqackoVoVY
         DSSK0USdt/pBuBdQEpsFJZGmbhG98LmjhndknkGDzzpful1W8pQD5ZVtxJAFSiw4pHqA
         RI2ZsBNxqRtlK05L+HTcQkp50IV4/OFia9swYf3qV199D6zQHWol8UlxZ02Jvp1i2hL9
         491qvudzhWg5ezR1JqfglmWOb4DGkmvQpbJZjVeShNt4TQ5IJ/lkoc5fJtUwVc5bBY0P
         bdSw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=qmDf+BUN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uKAuzopr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b639d98e82si1657971cf.3.2025.09.12.03.19.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:19:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1tsMn017338;
	Fri, 12 Sep 2025 10:18:55 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49226syyeq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:18:54 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58CA25vg030667;
	Fri, 12 Sep 2025 10:18:49 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011069.outbound.protection.outlook.com [40.107.208.69])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bddmt6e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:18:49 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HQbxx0jiU9H6DNmeHTsDZCGH8KU4JDcAUmIn5vr2YqL9bjyR2xGfYl+dm13HJu1qdNIR+JTpXqnYKu4ISjHVjVcGz6GPR1NyLkBNbXGTfWw66BR/umO/X8E4jcF9rRV7U3qda0aLO8aG9966CiGPXa6CJIfPVfrCdkXO+BqX9UTEwfAgwp0bziZoa+eHcOW87ypfyhMU+1S0MEQ1rebQ3tA3f/DiTjqdTagzg2kNDJp2ESfYfn1h67B2ajDWX4pdJ/H5e2QyJjeF0pFHRopaaQ8gE1029lJEg8cSVboxKl8zTzyjSw2QD6cP60sKmQaYHvRfpUlNNrU2rLLBc0BgKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jX6r33sMvr0LNF82P65KSYJbjNMhMhSygE7yQ2LKK6w=;
 b=JLYTWC8gyk9ekwwokx+SmRfP6BQHHeUJB1eFLgfsUAzj73hNoO9B55xdiTcvFTXvoNPlxsA42s8eEa3AgnpuLM7sGVbbYQXzKvNC8x5d+bVZZAV7h4D0cIeZI+1FGXs2ioIt6wKf+p2ufN/jFSvPSyzRAuEPD7aJubfipPBYe0MBrJLYSwXIMcre9zV6n+EhDO17h/YaIe6JpR0ANPwXtz9ZFUJv4PtBDyV5deCN9DQt3op4AGzv9CySofnPj/HWxn+JqOR951xB5qngy4UiDJ7sn0YC1jfjXqtI4Z7uzOJ3xUYHkrrAwuVDUloO/D4T92DKt4tevLQvUbHDXtbqrA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB5566.namprd10.prod.outlook.com (2603:10b6:a03:3d0::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:18:46 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:18:45 +0000
Date: Fri, 12 Sep 2025 11:18:44 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Reinette Chatre <reinette.chatre@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Dan Williams <dan.j.williams@intel.com>,
        Vishal Verma <vishal.l.verma@intel.com>,
        Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
        Muchun Song <muchun.song@linux.dev>,
        Oscar Salvador <osalvador@suse.de>,
        David Hildenbrand <david@redhat.com>,
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <c7ae6643-f9bf-446f-a046-72ae2c8ff87c@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <dce30be7-90d3-4a6a-9b26-44d76c3190a0@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dce30be7-90d3-4a6a-9b26-44d76c3190a0@intel.com>
X-ClientProxiedBy: LO4P265CA0254.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:37c::18) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB5566:EE_
X-MS-Office365-Filtering-Correlation-Id: 710d88a8-aff1-4ce9-54b0-08ddf1e5c1c2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Dv6OCLaursfV2aDnQekuj0OjnNgUmjXiAIDW3fZv3mbszm8W46FrXVPrzVn+?=
 =?us-ascii?Q?pY4OZa6oU1AgGOucRCVklFfwx4CIsDP47sP4bVMA3UItAVnlPaLVZHY1azKM?=
 =?us-ascii?Q?CO992dYOTPPH1deCT66ILcfVUDRPgO0iG0XTHr6ZU69rC2WDq9YCyZfNiycT?=
 =?us-ascii?Q?eGgLkqI/RMdCfI5CuQ6VCxvnOkbuTI9/FNqluIlJHPKEnogKyvOQb3tTKDj9?=
 =?us-ascii?Q?aAb+uBS8eCNXLY6Xu8cM2mQfZyM0MTqFuhJrC2gHLhxpM4uJ5zM4FM5nvqWJ?=
 =?us-ascii?Q?XEc6Udj4dCgUhDS6KIV1SXojvmQI4vTiisyKuFz94oYjsv/Ly/4neZ6hBeZZ?=
 =?us-ascii?Q?HVs8aoXgJlr8m2U4lz2j753Y2Fig47fW8mpZOF6iNUoHjlshtjiPZRGe51DU?=
 =?us-ascii?Q?uGc7am1QwTksWotZwxYHDKpON2OKr/fY8qwxMGl6IOSZt2cxXjNnPMmJwhmw?=
 =?us-ascii?Q?DIYgY7f19etYJ4j4JR6t3t4sOhLNl0WC7uazu8o7YzExFgLvxWgsQr9k4mmy?=
 =?us-ascii?Q?1zWZDPxU6PoGLlQeIuPmUdV8LhtE/GYGyGGjjI7klXEXADXZE2xsGQiKlPW7?=
 =?us-ascii?Q?YsF9j/fSfKyxrJN1QlrZJQQ/XC8M9Z6vYrUs2Rh9qaHwx0BkLPUxEHTprhT/?=
 =?us-ascii?Q?661ogTS3VOKRpQ7tniemc2cuZLsx2G+CmNbvSf52Zzw0Wr2w664bXWB2+eFD?=
 =?us-ascii?Q?Q652SIreWB4Sl1hv3S5O+TG7G62PS88dZZVrHFsWhIAajWh10F7/qyf5SKrs?=
 =?us-ascii?Q?gR9apjZMDDisTlTvQ3HYJi9U2We41zGhVf5zKN8sjSnWHOKQkHK+D85rA6jI?=
 =?us-ascii?Q?k7q/1fX1hz8AFEmJHbdGioXDQDbD+eTV/tIjfwXdrwBitSE1xsl1Xjt/rxOG?=
 =?us-ascii?Q?38xBj8LU9wYAw9PBVIim5ggnhTcweWj8l1bPZyS4cmogk0cGhHK3uUs82rrX?=
 =?us-ascii?Q?yyes1aSYmr9X7YsGjcYKlY0aiNRi3ZR5Yv8hGw8sm54jl28DuV0ZOnPfBA9n?=
 =?us-ascii?Q?CvHHWg9PRpOprKm1Koauy9D/Y8muuxleU7XCDD4VYXfpeeyVT0eycljTLuyK?=
 =?us-ascii?Q?VlrJesAacnxLowyJc7gfvsza+jB926mLp/qNgR57y8NMEbCLXp7NEwvkEktL?=
 =?us-ascii?Q?2UMfhYrAdR5rz6tQgLV+qtTSK64ObzoacBYug+CN8tLWJjDOufjZBdeGQmmm?=
 =?us-ascii?Q?ZYwlTlmmAAxBMJhKJB9I45kG1S6gh5u60QQx7axNGX3Kln8QCArCHHRyLBUI?=
 =?us-ascii?Q?mIJUdG+yYz9BtI8CQoXFPBb+txndvl1GHrts9ZsdOPOoMztVW+Y7rzKTIOIn?=
 =?us-ascii?Q?XbaEkd8F0AO+Lzu24b+xVnn7kYMbVENV4aPlLT6xmKvQXizW4OS1eJ4amPNR?=
 =?us-ascii?Q?eWQbi2jDLdezrjugzR06AqutJbR5rsA5c5ZDUahWTBaaWqbA8gVZbMnc7cyk?=
 =?us-ascii?Q?DaogV3b6z8k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?4sjjFU1rUKliLZSITRpnmAyunO4K2DmiuXpGC1sdvyD/UcYKm8XK2D0a5oGf?=
 =?us-ascii?Q?LXu4G0DAjFiE++6upwWDvGcqxA7eO5vTTa5KFzMwI3Ze7miNubxVcFIWllLI?=
 =?us-ascii?Q?i65oCmBaYbQhiesuyvsWFHsNg1gZ6MKIW1R2jSDe76w+6ViAHJF9aoyjqtQC?=
 =?us-ascii?Q?37rsiV5ftChaNpGnXZ0oVUrPlDOMOenD8ber4NrnuxJPwt+BClh5REBmpK6t?=
 =?us-ascii?Q?aqARQeJTN/+gQkDhV3OsFCXPE45WbC8Nkx7xzReE51S3Wjm2O876kSURuu+Q?=
 =?us-ascii?Q?xVCikgxYfRTjm3Rb18siTsU7w7vkJ/N1wkdm+Pt8DMCJqrdox2QdQ7rzQhRC?=
 =?us-ascii?Q?wusELEn6F4ccCN849hXzkxUdQTz1BXH135a9J5zAarsMD0yLk+qDKF/rn98E?=
 =?us-ascii?Q?vFMi3aFSAMiUyiwukWjHFFpFbEKxQM44n6754yadL9WOfTalkOmj1J1V+ZiF?=
 =?us-ascii?Q?m5eTThNa2wPYnjCU6CisEqTG3cRaxBuO6OE88CI6qeAd6JHavR8ydEHU7Sqx?=
 =?us-ascii?Q?sHYnODf8TyYwm40luelOxvfHzSobWzwaReIYvuSOX4WYKroiDS8J3JU/Gq+p?=
 =?us-ascii?Q?Gvb9EkOt0OyyPIwOzIYMPrYxYcsM+LH3XfFqF4GFdVEzPgMlshjmdwmR1gV6?=
 =?us-ascii?Q?TV3RGtLyfjCNZKry2GOc1k6QruZ/skO4GdVFAQlBiRqLEu0OK00BfS/tcCLI?=
 =?us-ascii?Q?e9KqHQRdZSKqSLRcG5d622VziI2gxmMAPOGFPJthy7Mp4rZXDzzZwyRethWy?=
 =?us-ascii?Q?Wzix/DnKwXyV5596fn5E5qixrYnq9eYbbpV3btrbcYLKQRiOdjCB413jMSwV?=
 =?us-ascii?Q?ijH55HRI+ynfbBbQjBgqtSaMXsqHr6youZI6zLrnIkU6gQTaYhymRfozkrAV?=
 =?us-ascii?Q?Uo5dFGLTr5lkEhAtlgseuMldGo30x4UmVSwS6LP7hYUg/dDF+lq7b+K4ZfzY?=
 =?us-ascii?Q?y038iFN1DvQHYdS/XQ0PQRB3WTbPaxiXSnfb14Qgt8RVVDCLRZi54gvSgaRd?=
 =?us-ascii?Q?r9I4h8L8E64ZeoOHqZUWdd1CFNCC2Ne+FzsINSaQ3QlAFrUaHsdCGHy28iOW?=
 =?us-ascii?Q?5hIRu2mQulEW2d8fAxAC/3hEGAKOmyARj2+s918SGnuYKK/UMTDR8eqIW8YD?=
 =?us-ascii?Q?7bPPGW90R2MjM2gEi7K3j4v28Hw2GOVen6R7k2UCDFTzpb2NCbA5iZsysVK9?=
 =?us-ascii?Q?9AClrr4Yc72ArMnkzYsYo9rQeZHXoYwYtPJFNXnYjKcqKWMfThPJSBaHagDt?=
 =?us-ascii?Q?RTtnFY3rGp+HMHzB8ZZm3k11Jg/e41oQ3fb58zvLp9qqLhJmuHO6VEAvIMZp?=
 =?us-ascii?Q?9PklpWh0izVjKnIMKvhNiKIq4EYHebfCDWbLHRzA5+2KDcFJBbz79Yp2vtt6?=
 =?us-ascii?Q?m0Fbujs9kNzmRBkefnkSOXwLGyQoKc16NUjrAX6bQthwc0j1lf7XtvfAoNjz?=
 =?us-ascii?Q?hhQQLE9lr9Hoz5O9kOVVwgpH2EOoH+7IagTnmS6YJ/yYXgkpdG3TASdUiisI?=
 =?us-ascii?Q?inmJlaOj/biqCDs8L1ikq07i9jKlpXxKEgrT5riDUj1YOq6VO1vE7mhOdQDs?=
 =?us-ascii?Q?7wrQ+emt7JaCyK62H+nEoF+hlrHoBJsBGZc6LTYUrOAlvTs4ZTXtyUoKxkIz?=
 =?us-ascii?Q?2A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: gTKnYhHwrhBODx9kJJOINYNklqpQZqRZ3UcjmLa+mfdIA2sYb5p3abBIil9oPy9Op8Hel620yNXQ7ztHWMcIgo7zws56EZ6n89kpJHDpWwXYRqToyaM0Pfd1VIyoB8U1LL21g1Hu7RzSzR9o9EAJ3PhAgEf23GYf3HxkmjpG2Gs35/fu8rUM3gOqOiru7vMbE9/pVMrj+MsiuL9UY2MWypFxdKTsxdv5FCsqlM2CK6LexszEpkjimd6jbhMn2noNFILU1xYJiyRBhGUWMQmUSdBxOdWczbTPIAnZB0IOINpLm0Z33WO/3NTiZFlDW2Wpo6t+rVXCvPRvmvUIPtqjXz5+FOfxwtTzOFJKNHHmxMw3sUnqANMS4NycFscqZ3IAxqx+Ye+iPrqtlYgH4AJ7TDN2nNYkzFAKbj/C3DubX2ufet2Sc5WyP67i9yYF4cWFpJTgik8w+UjUSDS4lCrQlhY/zk5VS0043AlBwmrZH8cv3auNLHv80EPSUbTkUiRLEQKd3N50iqGfajl7bcR5kHBzHBawkHnNHCYUDa2wijMhTs9KeNiTkbNAX4kZVRQ7tkFHNJ1HRkCWkNzGngbDUsFmngDWOxOfyCfN/Fkp5kM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 710d88a8-aff1-4ce9-54b0-08ddf1e5c1c2
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:18:45.8923
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: qDqWsPDrgXDZES69G8RAzM41r+AkOxKuhkpbVP+jehq7Rk2YxNhFh9LyNXYKjQkO5pJEuWwrV74B1hKcJ7rjo5N1+cgdxzEcYX5fot8qk+c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB5566
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509120097
X-Authority-Analysis: v=2.4 cv=QeRmvtbv c=1 sm=1 tr=0 ts=68c3f38e cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=r6C59EgA_q0__gwBQGgA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: Fr4T8mX-YdnNip1VBCbEcHuwtDR0nR6E
X-Proofpoint-GUID: Fr4T8mX-YdnNip1VBCbEcHuwtDR0nR6E
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1OCBTYWx0ZWRfX5evfhbt/WB48
 Zqb1s4sepCZflMFo4VO6p87IFkbXkILKRUJdS3i0tA1H5YzByiVSCqH63+D49Bo4Q4hXI+jrHbK
 wNhV6dg/m1Gx9gY4BTM8QLzYSC1sh2ChQrnpb6RJAQI+Z0ldygyiT0gSeC32HBjNM8E/tWIMXIp
 BSJ1WWWwVb95fhuY4gh1mdw64BYjKeSh7GWyvVXY+9GEZfYR6FjEfMAwQt5eE5kEUTtP4cYwqcH
 /c0LhvhjouzDLosGhZDfvXPuiaWiyVa8mr/hJ0QXWQXKQ+9vzBjjxDPeOP7G1oZo8DatfSLa+iY
 s7Q3mqKVDsYD/mToW4NOQDd28jNhaENCsh1z8Yv83u7fF8uyWOT+cKh8M9z8yR5fD79TVmzSwWD
 zrG6BmGj
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=qmDf+BUN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=uKAuzopr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Sep 11, 2025 at 03:07:21PM -0700, Reinette Chatre wrote:
> Hi Lorenzo,
>
> On 9/10/25 1:22 PM, Lorenzo Stoakes wrote:
>
> ...
>
> > diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> > index 4a441f78340d..ae6c7a0a18a7 100644
> > --- a/include/linux/mm_types.h
> > +++ b/include/linux/mm_types.h
> > @@ -770,6 +770,64 @@ struct pfnmap_track_ctx {
> >  };
> >  #endif
> >
> > +/* What action should be taken after an .mmap_prepare call is complete? */
> > +enum mmap_action_type {
> > +	MMAP_NOTHING,		 /* Mapping is complete, no further action. */
> > +	MMAP_REMAP_PFN,		 /* Remap PFN range based on desc->remap. */
> > +	MMAP_INSERT_MIXED,	 /* Mixed map based on desc->mixedmap. */
> > +	MMAP_INSERT_MIXED_PAGES, /* Mixed map based on desc->mixedmap_pages. */
> > +	MMAP_CUSTOM_ACTION,	 /* User-provided hook. */
> > +};
> > +
> > +struct mmap_action {
> > +	union {
> > +		/* Remap range. */
> > +		struct {
> > +			unsigned long addr;
> > +			unsigned long pfn;
> > +			unsigned long size;
> > +			pgprot_t pgprot;
> > +		} remap;
> > +		/* Insert mixed map. */
> > +		struct {
> > +			unsigned long addr;
> > +			unsigned long pfn;
> > +			unsigned long num_pages;
> > +		} mixedmap;
> > +		/* Insert specific mixed map pages. */
> > +		struct {
> > +			unsigned long addr;
> > +			struct page **pages;
> > +			unsigned long num_pages;
> > +			/* kfree pages on completion? */
> > +			bool kfree_pages :1;
> > +		} mixedmap_pages;
> > +		struct {
> > +			int (*action_hook)(struct vm_area_struct *vma);
> > +		} custom;
> > +	};
> > +	enum mmap_action_type type;
> > +
> > +	/*
> > +	 * If specified, this hook is invoked after the selected action has been
> > +	 * successfully completed. Not that the VMA write lock still held.
>
> A typo that may trip tired eyes: Not -> Note ? (perhaps also "is still held"?)
> (also in the duplicate changes to tools/testing/vma/vma_internal.h)

Yeah good catch! Will fix if respin :)

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c7ae6643-f9bf-446f-a046-72ae2c8ff87c%40lucifer.local.
