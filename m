Return-Path: <kasan-dev+bncBD6LBUWO5UMBBP7JR7DAMGQECJ7GJRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BCB2B5499D
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:24:02 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2445806b18asf18614515ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:24:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672640; cv=pass;
        d=google.com; s=arc-20240605;
        b=iyR/8WWpwXjVlg4z4+8Xw/I+YEKPZU5K1tT+5UlQa7VcgQG4WLMEE7CwkaGJ/avJak
         B12o2jk3a6vpMPkCRSotLfovjHTBbJFATeHaG1ll1L5JymhGr63SXqJ7b6sJ8+YuF/wa
         pyYbHNY01pNHG3UnrgxIuU3mPGwrHVB2ro+5nxlRv9RQHjOWqFi8nr61Hfohdd+27ZZ/
         xrmtLz/fNXD1sR1xohlFTOs39xfx3E0Q345vO3FaTkuYJ41WIvyiwFxZtNC1t0e5qE3o
         K9TFFlooXf3/Ul8AGqUoQim/LcYYiDCx29RunhGD8edK6cB7npFRkvrrFDT3IBLsdyEP
         a7DA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=51aKA5cD2kldvxjcpq1i9SmrS3UGGxkU4UEYtCrp1BE=;
        fh=VR+WaAd3GNBhDOd1NPzCb+ae42eOTa0079H109CraBk=;
        b=c4QRancIZTlWFgDDJBFHwbIS5tIHebNPYym+eU0uwxeoX2tlQbpltmuudJ4paO+Zna
         Sl+urKBmgCuCamsZw41CQPmds31iX7rc0G8CtJ7eyCgTV2/rwRjBEb+LbAkOT2hXWahR
         cVYUGwD+m5+WCXisCcFDet4rz7DopOD+qgJSpg8k5OZeAvoOxMvMNHhF/F6VrUwlvHTY
         wKxsil6kUEeAO5RsDF8ZLNRojhY2E/cOkwwXqEPVpiKZf8/148oozHXuuo40+fcw0BDj
         J4kGi/SnHkA7XBdp5/6M2nLYU2XANIoNH9s8w+OUNkcqS7vog4kK+QlW5PhqDVuanoFn
         FDjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tg0AmU4P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Jr0UHzmI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672640; x=1758277440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=51aKA5cD2kldvxjcpq1i9SmrS3UGGxkU4UEYtCrp1BE=;
        b=riqlzU6rnPeCLArEoIUBIFRyNsSO8ObZyPbr/xpwtIh/iUUkbRGUqHOYbqmHP+bSPH
         wWxqDzROgl8UPAD+I38//I0cQGJbcp8pk9XHsq97eiUCcXAHi9pyy7LDM6iwltsi8fE+
         xDgKEe8LBJ8jXw0o6jt6TSfnXPJr8LzAJVAPfYAk41ky3s5mphhaZdg2zA5upUQPkX2L
         tez1s7t1t/oIKFJKmXlSFOZoTbq6N1xxifXrfCZWMNX6lGu4SjosLTbxqL6aO0Bq40Xu
         d0nGWG+KHTNtZPlspGBERltqYtfy4gWwp97pnsyvcoPcY1dwpdOC7v0TAZf/Eddmv/kD
         6LXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672640; x=1758277440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=51aKA5cD2kldvxjcpq1i9SmrS3UGGxkU4UEYtCrp1BE=;
        b=qlF0UlUjKX1Ufm1u+CSYJNEyHYbJSafyJBQ2COV/mUV0I1ZEmIguZeWRR4L086kTnC
         R/gktmUfKUyQle/s6zAI1LDkGJSPAAxueEQssZLFxtIBA1GYqoKrATEW5XE5eV3Ap+xI
         9ukTH0f+Nqz2SJvlOBMgrPmUbQz6oHqas1Pw/jQIi2f++hkjfJcEs/e8akHLXsIwlFUp
         m+LxGui9XZyqhq8P+uQ4E/EQY2mAIVr6RZ+TD3JOHomCZn0JHmzZY1a3MxTRuqxQMy8L
         YEFkXyzylg6pTvsYXgAyATO2cphTMBYMjdZ699Vmam7D4b+pB22bFXTqFkmHmkxtKORX
         MuwQ==
X-Forwarded-Encrypted: i=3; AJvYcCVGiMscdrLZTObZmaclwPwBlX4WeRZ7HaRSa1gosYaLa0w7T/I/jb/dlue6kuRTgfa2l/cRLA==@lfdr.de
X-Gm-Message-State: AOJu0YzR43GoqXNJhSOhmoZ6PNc5F9LZ3+P8wG6OXl21BgOmY4h5Nymq
	SvzKwrYhfowPKUj9pCHwcHCCaTiWFsIPcecaczR+sdQ9BD7PWxB1X7gV
X-Google-Smtp-Source: AGHT+IFwwgGjk9bgZS1o/hHWWN9Zp6hsZFY/XVOfEDdxipCF7tbIfbrGtzjqBafiZWqr3gN1n5RYAg==
X-Received: by 2002:a17:902:cecf:b0:24d:a3a0:5230 with SMTP id d9443c01a7336-25d27131d84mr30994575ad.58.1757672640576;
        Fri, 12 Sep 2025 03:24:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd45jnCBhorYonw+4VIAtWmiUacbafPew/CKle0873VmbA==
Received: by 2002:a17:902:e48b:b0:246:3293:4e0a with SMTP id
 d9443c01a7336-25bee1c51bels11070975ad.2.-pod-prod-09-us; Fri, 12 Sep 2025
 03:23:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVmeAhtPw09RhR+lLnF1nu3I2BbDSjZ9JXDJRMTV1SSKlW8mh66ad+FyFjRIDzxypB+ZFd3q0BWEcE=@googlegroups.com
X-Received: by 2002:a17:902:f542:b0:25f:2aeb:2f75 with SMTP id d9443c01a7336-25f2aeb32dfmr789585ad.12.1757672638911;
        Fri, 12 Sep 2025 03:23:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672638; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xl5SvX4LCoSwGHi3x00w3pOdcYgPSr9yrM4zK8dws9gCsf6qFrQYZqNORzyjh+668J
         mneHA7Vaz18k1/4nlylCvvdFKPkCdyBlGrcTrWUxfcB0MzWo5Oqi07RLbJquphZMBbeG
         RzjleTtggjBp8ROgFKv9G37v6NJreayWPwdL3olIy1NEC31elUbix1U/p2MBmFu9iW0k
         B9pIy+AGg+GoY/8daYbEdCjQDtCDfdHyoVH8mtUcGc6A+XpdZ3mmpBgQxdXjwUtyN82E
         vIvDhu8Zc9xIRygSBg00v13YcIh8eNjxTw7su0dSBoaTEbMrx4rCU2cQRR26Qby6nEA3
         lqRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=5pdEF4Rrg2N0FbqzEdPJGkWtEq7yvpGIcEb4LRMzHFM=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=Co9ND7WVmXahHBPQbfZq9mSn4a0Dg7HzNt+s6gcXqx2pgO/lx5vz03gOiCoi1rAePs
         1z4NWkgJBxnPLs8JxMw3IAYtJ+NuqYgtfRI2/eTYERso6cUJ2CDj2xFWR70ply0BoBOQ
         aqbrCRGup/LtvXCg6Do6isXU4KDe2YPBVFNRMQpH5KXFAIiezPj+5NI0owKlrA8OCHoB
         T1FecC3VafZO5HzmZlnA4C3SZuLjLFuI5dQDyYCKFaKA0uBLraUHrcYfBjNklzQHg5AY
         isE0mqTQKlOgNzWTHhQtfrUjEb//pvw3uW/XG8TAZN7r764ZO/Mk/33cZhDUdyy6fCf+
         dSmQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tg0AmU4P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Jr0UHzmI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd9809499si177818a91.1.2025.09.12.03.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:23:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1uAAV031031;
	Fri, 12 Sep 2025 10:23:45 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922x97wyv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:23:45 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58C8SQPk038722;
	Fri, 12 Sep 2025 10:23:43 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010060.outbound.protection.outlook.com [52.101.56.60])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bddpv0s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:23:43 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MnUorX936gAeKEumKq8drXcUQxFqJNv9/w07NO2Lx1slrTFC5u5kneyFiiB6r82Ti5t91N0iXJEXJq6NOyqzSSbTucKxNud+lybqLM4j/+7/dCrq2eXz2mUuPDXm++owJEN1M83XwULwp5hhM+xXKNzc1Cnn9/TzzIkuvwi2rLrfIMnIdfqnlAjHdLi0NCQCibq1psQ1E5IhsbtrE/Tp6KH2oRjZ/UmQjuiJu+Nyx7YSk1eypcQ/EaMdJAkYNZGSIMzcjUfwBqILznBOQIQb8jh6Il+HipiM62/TzX2tQmgCXgpHSNkweziU6CcxEh4hgw//c3nCCj70qQGNZLEsYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5pdEF4Rrg2N0FbqzEdPJGkWtEq7yvpGIcEb4LRMzHFM=;
 b=cnKQje0PNnGZle79j8+aR70CdM95Ppb6TkYPHR62GQw2LMGBRsOBsFFpftWY67+bGI4hPwhhV2evUQ5rOHBe83lZ7kFEFIE6VCHi+f3VAvGG9eSSWLkx/LWPP303HuqjyMP7e/MUnhfq+ddSbh0mtnzwpJmxkneMxxAzxf6k8Tpd/fXnS2XIyaIb4bnU0qUmlnkWUTgDFQYKiu5s68jIKtKWQtzOVWoOD0etAs1Zk7XJFDHf4BprXZyhBVn5+2hD4sQkcoKgtJWO3i+BOajZtx4yo8aG6WuV+6NRCCgVKFc5IyipKGCpI6xYCk3G/6mN08mPKJAqk2qn7Jh9noeyOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB5566.namprd10.prod.outlook.com (2603:10b6:a03:3d0::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:23:40 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:23:40 +0000
Date: Fri, 12 Sep 2025 11:23:38 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
        Reinette Chatre <reinette.chatre@intel.com>,
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
Subject: Re: [PATCH v2 07/16] mm: introduce io_remap_pfn_range_[prepare,
 complete]()
Message-ID: <ce124bd3-ee49-498a-ae23-47a4797f03bd@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <96a2837f25ad299e99e9aa1a76a85edb9a402bfa.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <96a2837f25ad299e99e9aa1a76a85edb9a402bfa.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO4P265CA0087.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2bd::18) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB5566:EE_
X-MS-Office365-Filtering-Correlation-Id: 594477ea-8ea0-4138-0d54-08ddf1e6714e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?8Px+wo4ynimZjOEgqY03rvMdoan/EnGCMUdQw6+SjvlBM0hAhbbGwMdEl0JX?=
 =?us-ascii?Q?mqDl2sAGHNL/1YnHakLeu0EtjMGYuh7tXVCbuHRVu1ETM1Gy4LL/8L2pJ6zO?=
 =?us-ascii?Q?qtgTXj+mc9gXeYUZCyQvIwiOqZ60pWpp9mVu/LHuJ2oeV24iIo8py3jmLFCq?=
 =?us-ascii?Q?0HYZcW9IF6eYSs3djYj5MWuQGq81AZ5LeTeg8dq00dWZKf23wjJdVul//g/9?=
 =?us-ascii?Q?CG2vvBhJegJfT7fmVESz+ZX6tgbn5oS6q0Q01FxhmxbGY03e4l5Yk+XRr2f4?=
 =?us-ascii?Q?G48alvKDRfi4Rfl3ifHwZctV7EchOFZSwLo7zv4hyYTbUNcTe4M2BjWjCv/2?=
 =?us-ascii?Q?zwqZvw2h1bYjdzVNblVlH9inCQhOlTxtB8kkBVtHkknTeA6e0t3Z/pAaC4NO?=
 =?us-ascii?Q?O89l6lfbC5pfGQYGa/SIYigL7e24J6ASB/DgwKaDls5EzAYvIExeSBlHVX9r?=
 =?us-ascii?Q?weCV+vgbTAKDEp+Yig0GgnzMGjaLaSt1weRGDd4Bq/yaMC2nS9U/a3nyrn1u?=
 =?us-ascii?Q?t5v4tmoKLEeIUuQM5slQgZ6qLEy2kuZykTNThLlxuZiJ9dp3LVBtSfkD4B69?=
 =?us-ascii?Q?7jJicDQSOpyhKtnB+1egO+IASEh4v4ir97Yuccnl27jFpGbzKqHKgiIrASee?=
 =?us-ascii?Q?ZzOtnOan7OHNFSp0SMk5FS5C75b8puzrKpzZX2QrrGCQY7++2Kx6k5khheZt?=
 =?us-ascii?Q?xKzdbeGvRbeP+dX3ya3NKe5pz125UKBM3Vp+z20nxfMi00EqixxOQlx5zey6?=
 =?us-ascii?Q?PF91I0ZyNAGVHu9heBHJCR/Ig97TipBRaRrmiieNiePElzCLjkc5Ul+59hos?=
 =?us-ascii?Q?aFZFiqmO4OK7PAv3guBtPbAgIcozuX8FHQGvNBAIiUU7kpxdUr5mmtUc11W1?=
 =?us-ascii?Q?rKgoiSpec6YWhShvd0SqxXnhMe1B5hHJQuLeqgAH3PCjOJVDjiA5BjmfsOQa?=
 =?us-ascii?Q?u3va5GpA1gWFvBhc/YUzMEZj26wxAuLmU55m/4On1WJFSSqNpNzwfHufPbtI?=
 =?us-ascii?Q?iR5gM38YBy9JgE+asNLBN8VBJhtUzyeVlkSWEAmn0djNp0QmiKBERAKnKYmc?=
 =?us-ascii?Q?rOcDKNRfrNm52dmvj08v0Fnbt+8fAnPZWwVQnPGL+rr6zul/5JhkIUSEY7uF?=
 =?us-ascii?Q?qWDahSXeHhOS1MpEypQQC+qvD6UK3dEnurX14uGD99Jrfip1F58wH8rjFKjt?=
 =?us-ascii?Q?dQ/y6DoqvT91Tf7gft02dHQc6g/RYRfXqsKDTVQi7gkCFijOLOcXPnRtoqSS?=
 =?us-ascii?Q?X0xnTsSIIADTTYHvr1eX0Dp3430rItzMWqsDrHt0h5dWq/bvqbPpuiLvGUKq?=
 =?us-ascii?Q?Atmh3WNvUxus0HlylVs8w79yaGOL0W14pyt/YBaLi7Igj7L/kmWm+Fe5p4Xw?=
 =?us-ascii?Q?uqF3QWmKVP8cL4p9u5Spj6QA+1ZYKnzlMIpNX7/FQR6obMuzoHALRnnIf8JO?=
 =?us-ascii?Q?5JfT2XPXcNw=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?35ffnHESixuTQWusbmKJx1hIqJHtBUw1rIXRgNMWxB0n9ORox4LpSw/eNK0S?=
 =?us-ascii?Q?kS3jA839KWv99+i5Pp9b5mnuF9XrWSaD+6NN9GQBE8qf5GPD0kfXBxxFW+7S?=
 =?us-ascii?Q?ZFjBJReomZvl2fAbJ9fM0jKETPWdmWLzT2c1xIBcB3ow9Kz4+KQhUjzdk49D?=
 =?us-ascii?Q?l63P9uArklxYQjU3dgy+4xFnZ/EVS2dT9pjivjh2ppUdcEM9Nlh3dlF4qWhM?=
 =?us-ascii?Q?FdUlbIGDdWhQV3P7RAXDjrX94lmMsczoRvQ5nVA9ZJfklqwUkp7Wh/k+0tn3?=
 =?us-ascii?Q?obcCuwmSiFXpHPsmXrBwFl7Qy94b9BjZ6+R48HIW8yqPCw0kVotrY+wXu0xE?=
 =?us-ascii?Q?7Vha45vrn6QY/DnDIuXe2cZeSQIv3ym+BKwrJurRslLKv0enHsBSIAZjX1nt?=
 =?us-ascii?Q?8o/WtOlardmHlysTjxJL0zwgTB2n782aa4Xw8+PIbNTICWTcomICqUBX7kja?=
 =?us-ascii?Q?Ma1K+D9pOrgW5y6pIF4HdkcXduckLsSMHIrXFxLgvfdkHb/uvy49ocD1hXpR?=
 =?us-ascii?Q?uPor3bDydNUt0V9oIS1nPEYmhB6VfjPyOKeDzJQfFBjcGaZ8LmrnTtzLBRWC?=
 =?us-ascii?Q?LYrdq30AYlBnI1s3esITYIBysG1kQ29eqSgDnIHCorO7u+RORLG9nqcwCWA9?=
 =?us-ascii?Q?7YdS6kUlZ1/D70+0ReTMA0lRtFjBPe+5wzy4ErMi5yqqd+F96NfyNFegSDdx?=
 =?us-ascii?Q?Y6spX8vcaLs3UQWaViqdwvTAbI1NL4bDE3EffCbwrPQtr5pdvFVf7jVLd8v3?=
 =?us-ascii?Q?92FULeAeH7HV4Xk6U6GawRsZfnEhj5XMsnjOmqpg5INFUlLFmQQIMxWT8A+4?=
 =?us-ascii?Q?lj1InwbO0aOOeYyOHr/8k+lpB5iqSH8mRh3xLADMtFDoauJpXeQGptXZNEoF?=
 =?us-ascii?Q?uEop61sETyixvan42yRQa19VM0pnJ6IAxBmXXXrssztjag2NbvCg8itD40+2?=
 =?us-ascii?Q?9x7g175ltSi67S1cdLs/5YOTofGqEzs1/7KBioONk8fLuwXc2XAagH7nItDQ?=
 =?us-ascii?Q?MXoydioWf5yR4RHqXAwLGvmtCwMglB9XGk1wZ2RB6XjwwwDy4//5+XcPAIXw?=
 =?us-ascii?Q?6dE+QuSU/VMpDe8bGJbdnKV4Cr2Je+wFJCMUuoUwWEuDM6RryJ7XIKv3IwSz?=
 =?us-ascii?Q?9XNqx4HGvNKvTyH6aAlIlV4ZpFqVekWr7BRnx465weXNGlGUf5GeVopT0A3A?=
 =?us-ascii?Q?WW5D84RAHGExT4U3ofrLilXQlCiwhpUDCmxniZWihXkSq+BTd4y51w1Em43f?=
 =?us-ascii?Q?4idxW1n5icxt2DhK7zj/Uo6KVNdZp6nIhTsttdcrt/GSQWuh3vAj/lwlviyi?=
 =?us-ascii?Q?lSb0LaGWZOU4/XLNzByCekfQ6nidN/gLpfxLjTUHBNPvDlaWIdoStMSCeznz?=
 =?us-ascii?Q?asij2A8UXioJkIi8lAXTgXQNo41IIEShY31LWUThqduSas41/Bxnn0EgJgl3?=
 =?us-ascii?Q?scFxm8Kz9R0Zv+C96OWpDG/l3/8UpcBIru0BntkB6BQ0r4T+kpVlVk/RuHMj?=
 =?us-ascii?Q?PUEGIXBwv3NH1YNA/sMU9CrMkRRMDLymmloMgINcd5a4XcCX8EgpXDkfQ+zX?=
 =?us-ascii?Q?mHVYIoiseDFwR8YphosnVhGep9KahL6gwS4QzZJHRdWaoizvgwouuLVlSg4S?=
 =?us-ascii?Q?jg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: jWekm3PupVf5cVqrmqnttxTmmRH3dNHAuZgB7c1XfELn4cA2kQh8l8m9ivHXfJcHpSpSfHL4OPCn87+oclxh+3l6aPQS6QT2bzp9ePcShvqqExXdGou5E53usLuTzGRr21B3u5oROd+9D1TK9bsyDYGBZhM/qyFrqk/D4mq+eAwRwtsmxRSH4VLRafzYbJRy8T46WR6E1PqZ493v1XkHCCX1BH6VQYkSgCOz6eg1nIRk0kNX6iwE8GOEeuhCVh2Td7rbl5Hlf2KFQ87fBux4jCKx3Al/jAD0iKXWRjbL1mXpCmJUS2+gRiQ/HJlOqwRW/m6VJKyrLyRt5nQMydUEnZAJnvsVh4eSD1XwdWnhsoUqGVFhtpkL+wa0sBoFTjdElMOlQNDMapAXrRgLu1IAnSQSnWU8yZw4T/O6ayGSqBB/CKbz9RC3WSV/fQtIyBADvoKaYH8MoNR7tKw/jCI1jxjEoUfr30Q9HqfHqY3elfE41wy/oWeFj4A/hJvQOS3EFqzBGYTzg0ipOdOKk7yY1sjdhxYCp06MaupCUE13XbhU7BpoQDnh8iyJnnnNdn6XTqTJ+9RqvIk4unjMicpzuP8RyjNn9Eql7PqtwRQ0NKM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 594477ea-8ea0-4138-0d54-08ddf1e6714e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:23:40.2930
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CNhkoC03fEY5nkn7DR1tkH0T7GlFCmy0WGBM4DcOO8tLfCai0Xsh1jVTybo49SlD8Mg1c/EPV7P6TUPOqHJP4NROQs4efEON3/z94dSA/UA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB5566
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 suspectscore=0
 mlxlogscore=999 adultscore=0 spamscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509120098
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2NiBTYWx0ZWRfXyhP/CVaBRTwi
 fwqi4D8Yv/6pELjMYH3VE+YWXMb+T88UZbo7wDh5r9JQw9f3hFotMmyr82uKUUs/OBx4uAoIqJY
 tkZ0FOFWLWgb1VWnEYR45Cj72lE+TToF3Nr1EOcm0fFfOyTseKqyyW+33BFidF/99UExLuJeiTH
 qKYs3ZjdQrPzf4uvsVTkujLmRbMqiyoe4GPEzlxOCdh2lZenWW8ctApfbfdmlkB+UOtnIrrL1iH
 GbNCJAZe0ddFv+kGl7vPHqIsXwysXfYfIRSjqXWa5jTsbhChV2CASqThfaVaitYw5Cg5XHZUHPK
 O6A5H2nJxPES41cf4VWwcFmGLD/oDuHuLcslyk64tIA3gwfe3SBccbmRq4P7bAc/YHXionC1zfJ
 +yjxx20zdCrsvEb/E8AXIFmJDUWb4w==
X-Proofpoint-GUID: tCtBY4U9LVT-Y1ykAU_TaNUj0fyoN4CG
X-Proofpoint-ORIG-GUID: tCtBY4U9LVT-Y1ykAU_TaNUj0fyoN4CG
X-Authority-Analysis: v=2.4 cv=LYY86ifi c=1 sm=1 tr=0 ts=68c3f4b1 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=fYYJ4SnnAo5NHOqtqxoA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12083
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tg0AmU4P;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Jr0UHzmI;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Could you apply the below fix-patch to address the delights and wonders of
arch-specific header stuff? :)

Cheers, Lorenzo

----8<----
From 1a8ddbbb3aab15104e7b7b5b7a5a286dd23d8325 Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Fri, 12 Sep 2025 10:58:23 +0100
Subject: [PATCH] sparc fix

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 arch/sparc/include/asm/pgtable_32.h | 3 +++
 arch/sparc/include/asm/pgtable_64.h | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/sparc/include/asm/pgtable_32.h b/arch/sparc/include/asm/pgtable_32.h
index cfd764afc107..30749c5ffe95 100644
--- a/arch/sparc/include/asm/pgtable_32.h
+++ b/arch/sparc/include/asm/pgtable_32.h
@@ -397,6 +397,9 @@ __get_iospace (unsigned long addr)

 int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
 		    unsigned long, pgprot_t);
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t pgprot);

 static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
 {
diff --git a/arch/sparc/include/asm/pgtable_64.h b/arch/sparc/include/asm/pgtable_64.h
index b8000ce4b59f..b06f55915653 100644
--- a/arch/sparc/include/asm/pgtable_64.h
+++ b/arch/sparc/include/asm/pgtable_64.h
@@ -1050,6 +1050,9 @@ int page_in_phys_avail(unsigned long paddr);

 int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
 		    unsigned long, pgprot_t);
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t pgprot);

 void adi_restore_tags(struct mm_struct *mm, struct vm_area_struct *vma,
 		      unsigned long addr, pte_t pte);
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ce124bd3-ee49-498a-ae23-47a4797f03bd%40lucifer.local.
