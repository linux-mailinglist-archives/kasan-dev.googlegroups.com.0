Return-Path: <kasan-dev+bncBD6LBUWO5UMBBHOMV3DAMGQEEA5HG3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 21290B83200
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 08:26:39 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-78e0ddd918asf9978556d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:26:39 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758176798; cv=pass;
        d=google.com; s=arc-20240605;
        b=En2SvFuriLpVSMB75j2NlzFZ637L8K13cA1BenPafwQqYJxZraZW7PQ8WcOAtAGEuQ
         8e+fgQZzGeLkiWB0WejCKkPpCSTAdmEAbnGxkxdUMD47RnnDoN/sLuwqANiv7LDneX0o
         CXBSEPc9W3QAOlJt8aNM1ZJhEPgww/zyaELjP2ekWhBgd5jRMDrppeKkbqbPWWeM7+Va
         TjOW53ylqeS45hwM6MaX6BMeEI7HpuEoBkXy4Zh4nQorWk+k9QdOl1LPCcBqtx9ipT8Z
         B1YVLxusO6KIfNtEHiEFRmxEjHX8QVVYWLlcNiFQ1AOSK5DzdID+I6i8FiLTA6U/I0lF
         Hwhw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RS5AK/1JzKF3Jdlf9XzJiZ9lD6XnpYGrRVEkhN2K8rQ=;
        fh=18bF4+f7eEgRX0aZU/5qvFRxCz6wlNodwy+pnZrhxX4=;
        b=BwTOe2DtvGwtehVuEb/8A7esu1hD4PftY53QYm0UyqU2tSxXYuQXQhfGzb5pvoqrPu
         ME1OKCv20hgH4ulZ/N2tIkC2g2YuYun+dHXMRIlXD/+Gp4Z5bRf4kUZ9jQyNGBqRFwzQ
         iUSM/NfLrnmRFBu5eLQNbx0Q/j4F41ArzPCM8fVJvxbNtFhF0r9g96WG70xW+GHJ8bR4
         TJn0cHBnEHPN4I6GoXKMgACxLgf3jUNhQeCshfWm7b9NCj2szR6x2zE5XcuSUfoWbJ5m
         JNhCYtMZh/PQ6HA9K8/XXK73lBIUQLxZUTXxrGK1Ciyta2Q20JQbrafMenqmZLkl+9HT
         hY1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RcL+V29n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=iPCAkxEJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758176798; x=1758781598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RS5AK/1JzKF3Jdlf9XzJiZ9lD6XnpYGrRVEkhN2K8rQ=;
        b=wx1MEqpt/dDCocqO8Wiy0zrRSufuXbgqTAfdoutJalOrklkc3fnmfrRls3OIUhLSQN
         AhPKLKIuERYcHmdUko9Kc5ZnczptF0auvIDKCttDkrEEr3cE3BjYkjnU04fQmUdJYRnM
         W7kT4E2FkMtWhDCqMIP1iUKGXqbhcZX/szT0kLRjep+gOPpVd0xF4PtAo+Q02tiQl6QO
         7uy9/p8JKKwz+DSKGbkLwa78S5Y9BtZKIAM/fwpg8jGHnS9psYqTNhq1RLDhApqup+vB
         RO6rVE7UGGC2MXOC2c0x348TjxrIwPpDRALJEcuchFMXyEyGYXhyhNwW2/16HQoDh2EV
         p6Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758176798; x=1758781598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RS5AK/1JzKF3Jdlf9XzJiZ9lD6XnpYGrRVEkhN2K8rQ=;
        b=nKUAQo3Z2dVY65LTGHgbXW6qe7LO2mXr0agLsv/AJUHtTbm9qevUdf7NhQgnJuzA34
         5bVST1thqnE6hDnmJAZuzK65wVfLjfeyMc59hf5QR0vz5ZEONtHiNuX1HuKja5frdtsU
         3nHHRpW4kTPmYF0Y97oRl7wEkxJYqdF5faOPdfXB0bs6BdVJK1RC3u+joCjdHoBwQ6sg
         wmtAYFtfkVr6enXvxlK5CNWY5FSc9DCEdA95MDeGkWvrG+SUsEq6J1CXE8jwqU665PC5
         Tnlne+1My8bmni8eP238ZB5GhF0AOJKqJWU03naUxY9E9fZpLUDjAS/7A+vuenTgCS/z
         Jdvw==
X-Forwarded-Encrypted: i=3; AJvYcCX/ZN8mYyyR3Giok//P4Pu3W1LwKsiU1iBj2+etZfneHkIY2opIirB27rVU0xvt7sjYm+lClQ==@lfdr.de
X-Gm-Message-State: AOJu0YxrZolY1sCquqEECpZBDIpu5Fc7VIxijsyVadxYPLGVCOWull/A
	jyPZhvb0pl492DWrap11Ua09x6siS/nF1DFf5BbU1j1wtLieOfKwopDY
X-Google-Smtp-Source: AGHT+IE10yYeHIJN1zgyv8BQcQFW3P30o9OQL3MXwCVEte0VmDiNgKOdGSybFhgUf2Zzft5JXQGHbg==
X-Received: by 2002:a05:622a:2445:b0:4b7:ad88:45f9 with SMTP id d75a77b69052e-4ba6799d54amr55645751cf.7.1758176797576;
        Wed, 17 Sep 2025 23:26:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4yMBbtvI8BeKqbUlhZmdbgkG1Wje17qD3vF5HBlGlQsA==
Received: by 2002:a05:622a:c5:b0:4b0:9935:4640 with SMTP id
 d75a77b69052e-4bdfb988e0als6752041cf.0.-pod-prod-09-us; Wed, 17 Sep 2025
 23:26:36 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXWNcP1AlVSJwU0KoNo+6Bz+Lmrzvsz0gkOZynrj9FzW7tZKiaCLky9KQ2IxvjeQLPPHisoeYWXmGA=@googlegroups.com
X-Received: by 2002:a05:620a:4691:b0:829:25f1:3208 with SMTP id af79cd13be357-8311371e40fmr437396385a.61.1758176796570;
        Wed, 17 Sep 2025 23:26:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758176796; cv=pass;
        d=google.com; s=arc-20240605;
        b=dmSjL/dX6itOF2OZX03+bOIWN8AbnBqxbOUFb9EM+pcGtcPA9T6a56o4+PGVrQ1ujk
         Ok1kwy3uRs4hJdnnaLDMb74PgRbFciHmyYtu44X7M0rZ1dFSGOhhXn3fK6YKVo02TG+r
         bO3DNJjqOd1H6N3kRDxdorwyhCEf5S2L8fr3nxjlmwWEtaKkdrtaByFlAtfCyz2gX1UW
         bJHsq3fOE8DlTbz+peBMSyvsQjJUe6GEOl1aDSjOFuTHe8k3/0Xgw4E7vwQHISf43meu
         Ny5ZbOiLJBIqdHkSI/2+KjOatvTRu1Siw9lrMjQu+P19uJSCLPg+2b6il6AVnBG+0fNb
         pgsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=9YN5nS5GfRLxC/jHbTM/RLaHf+vmfvOt9hoHfhGkeSM=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=GB1yUkJx9jU1plYu2Pbis1kdcqvYUrWSeKXvDQxVnNkUKOHhduhNOjHohIjnZDW9jE
         79AkJEaSRud94x49AThFyiHf2uqkMZ6MrVQMf7KXzDum7z1A8g8z5QXs5S8iETGdKMOj
         LXHOkEgp8qAaTkLYeycdKAjEHeE3jByKSRm2HzrkXvUoJowMYD8Zxht0oy2tXm2kd7g4
         yj2DPSlExEMFYd2R2ite2RFR9fKAx+EtoOQwKVk7+Yps/TzYhXsPtzaM8fwL3F7OW7Jo
         FRSqq+XtFuXtMuMb9LUyEVCJyZzhhxYd0LaHcg6pfE28zDinN6TqlTXgdKhcsrM4LnuD
         InKg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RcL+V29n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=iPCAkxEJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8361b1a5559si8388385a.0.2025.09.17.23.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 23:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HMFZ1Y014473;
	Thu, 18 Sep 2025 06:26:22 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fxbtsst-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 06:26:21 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58I3MBA7035116;
	Thu, 18 Sep 2025 06:26:20 GMT
Received: from sj2pr03cu001.outbound.protection.outlook.com (mail-westusazon11012011.outbound.protection.outlook.com [52.101.43.11])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2n0cju-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 06:26:19 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=GO4tI401hRN8+0UOq07MBZJKO4BPdUrjd5DCc9PcyrL3az9syydzAulensnsRGd2ZKXbVMCRQR4z+YDfxPh+W1oP7IO/ZqHzHWq/kSsuixgR9+SFDzohunwGWjMDEJq1ZirxX3Zv88bBaZ2vn/he73QXKbAaioPD5G2OISjB4QBF8Hb+/xsg/kCO6usMiQzgXVxHuXOyUk6ICZiV97UybIezDAviWA4/twPsWM7JXxmJ+5HyWmuUcl1cpOB7Ib14fLEH50UDcoAiiDpehitgB5WaidRz7tCyN3+15PZiQ9QmfdWHfLqLpkOPSy+THfEQ5Be+9MHDioSIMDluzTyHzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9YN5nS5GfRLxC/jHbTM/RLaHf+vmfvOt9hoHfhGkeSM=;
 b=myBcyCfkdMxkNJcroGQaejwU86l6lfjbF5JND8iJnaDqHKX9hgoQRPOAWG7+zaGdtPur30pw9kizfZVQ9qmHXdPN+dRX14hyAIq7T5cr4fd1vIeIcT0DU9fTTODB3uAn2fXbXRtz3POt69Obj//LYCEXaZn0fhUnfryWoGfI1YqfZyJVaz+Kwb8PHbMxi2QnTGIdv5wLdG/tOKsH5u98knNSPFHTYvDN0WayqqOssfZP3S4K7Nk5HEdu/knQhcDc7eldqQEAbAO/SIxiOSqiqs3bWZu3bkuCoKsMERvBAQtmP+eZR6wT8FeJ10M6ZvU5tNroLTHbBJ7kf6YxEcQ+aw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH0PR10MB5659.namprd10.prod.outlook.com (2603:10b6:510:fe::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Thu, 18 Sep
 2025 06:26:16 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Thu, 18 Sep 2025
 06:26:15 +0000
Date: Thu, 18 Sep 2025 07:26:14 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
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
        kasan-dev@googlegroups.com, iommu@lists.linux.dev,
        Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
        Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 07/14] mm: abstract io_remap_pfn_range() based on PFN
Message-ID: <9d28f23b-5455-46b4-b88e-682b707093be@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
 <20250917211944.GF1391379@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250917211944.GF1391379@nvidia.com>
X-ClientProxiedBy: LO4P123CA0207.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a5::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH0PR10MB5659:EE_
X-MS-Office365-Filtering-Correlation-Id: 2d4a7a35-5204-4951-67d4-08ddf67c4578
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9y4omMA4RmrNPRXFuUPyMgajAfvMHIcqGYxOoS6PiUqpKSXqaePdE8YJ6pYc?=
 =?us-ascii?Q?06LdIHG8mEdTLzTysxaFJ8HzqT4o2ITcf4Wef1vBl5lkzhQO2QlCtxdoblcu?=
 =?us-ascii?Q?Z1b9AC+gnMQJ0Typm2JcdfyKfBfKbD6MPsFh/aCbtzWAbBHeudkboSsLqKp5?=
 =?us-ascii?Q?UK0fiYlBmC1OOucCoAYUGDhEXvqbHZLMrcSnLnEfu3UYMH3fwX6d6eWJgyMg?=
 =?us-ascii?Q?+Yxjne73sqX5z6BcfPjNBtVS5qO3fUurY28JS6cSHbFu7fX9EfgmAm85NVtg?=
 =?us-ascii?Q?yqlCTMBu/AoXlBhpU9GWBDhbhjxWEexT+vPL86CYttQeAvnXLIg3YJyP9E0K?=
 =?us-ascii?Q?KPck7ddTZqzMGNwnqQ1ZGeeaO23/PH6xL2MmiPNDxGZujTjdw1zENxjbKN/J?=
 =?us-ascii?Q?5CzO4RDtBb3h96/l1ctRMomvnPXUiVbimaDGRNWP6zsWFpP1O3NXMk0OE0h6?=
 =?us-ascii?Q?B9YHxUnMPrCyftNHcN2iLagGT0j5FCGqhpqOioaxfpa3vOD3DEImbA5sSdi5?=
 =?us-ascii?Q?a/D4rzxOTY2XLcoeqg47Atg6F7Ryge84M3YQk0cvP9LaiASyKPxDNCTF5F4L?=
 =?us-ascii?Q?fczh30LaEpOL5TIk7/PQfLIq2Ebqohd7yoDqtH97ZUOtQfSgFq7GO9A7GoQ+?=
 =?us-ascii?Q?wJMjPNK7ieIebztm3xvKqpuDbjymX1/KUoabrLBqcYmW0j0pfL/IDIBwnQpH?=
 =?us-ascii?Q?HKMlG74BE0MY3J/Z19yHj7+tTIOXmkeRnbZPCFjRxbKLs4nu8iPTTEO0nN5E?=
 =?us-ascii?Q?PwJG6mM4CeLRWUrMRkkBgPn4wmZH1S5zlcooVhfRfBpfABrtrhkHt3cQoMpA?=
 =?us-ascii?Q?6Bhl4VlshmUjCjqShXBkEiI23x8j3Sr+WRtXUAoZ4wdav5bO4heOwy+PNc+f?=
 =?us-ascii?Q?4S7rjjButbPZ37t3qjSJbl+bhYzNs02BSflS2wpw3N2i4SlwM0m8wbEGmPvd?=
 =?us-ascii?Q?4Fr2qLyml129+N8G+lFbSrJk7hufncyrGMzC2WSGapN/8Gi7a0eeSqNG4Slj?=
 =?us-ascii?Q?6hKUVVvkaSKtp+Rup4PhuMknpsRQ1Cu9+U1LyMC3fdJer1SsawwVf64mZyEF?=
 =?us-ascii?Q?sFDZietm3lrvxuWI/wHM5oxhbfQ9FDHoB5rn7i/jTDyVevxqvqciq4hB+WK8?=
 =?us-ascii?Q?Agm05brOK89eOIhJNL4QG+pn8A0iMJ1gQ8MVrPn7LR/PO7bURdx0j4O6zp22?=
 =?us-ascii?Q?Mf7rWhXofhofNDnHQoJLULWft4EOg3VrRLHmbHm59D93OTRSJ1Q1N1sFmZdR?=
 =?us-ascii?Q?JcwLFEQGItyj6ePF2UIEAKsMmbQna9USHjmvH85lDn5UvJ8bnUBS1/QvPQWC?=
 =?us-ascii?Q?doOgBOJ5Uo+eGqPDaQgEiksCTdxtFfK7CFCRQmk1ilVI/H3vFK4lWpr+9cPT?=
 =?us-ascii?Q?TOZIHDbro4D602qhkbH6u09G1cpREVmETleHfkcdTvhQRsK03Mx48UVzEKXM?=
 =?us-ascii?Q?GU4PmBB142o=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?gf4JE4fc/N0mcXDZDjkpLyIfN8wkzpP8ICjJrX5sfKoZO5ydRpZJedZRXdSK?=
 =?us-ascii?Q?l7JvE7aWUY0iH/bqF01zS2YLsl/VGUPtF9b4CfbLPuaP4B3pJJWXkEld0SFb?=
 =?us-ascii?Q?m7k2YVoEjmlHt1VgjMykBUjzZndqIklZxmbxjX66oWddvZcCZehek1UHeKOa?=
 =?us-ascii?Q?Sk8AY+QhgrD0wcKJr7MmCp2mh1uX967l3zKpTig0NXa1IucgyMkpJBIaYdpx?=
 =?us-ascii?Q?SXAAdq3wo41FuXYaDFQhi/7wQ+5I/4P2NjHjsXUV6cgkOB+G2zWSm6PX1iF9?=
 =?us-ascii?Q?Ais/6mrVHqq+pTZZ5cPkUgwu+y9l+ScLwvPwkilrhHM6JN0lh17mOfDdj6dC?=
 =?us-ascii?Q?zFakUG3VISIUwpLowanb8Xx3t3tMbCU/Mr02YkNccqe8/eDsSilpGc3Cxx0J?=
 =?us-ascii?Q?HU9GC9wMJuzNQGWYsv7/ofL/Olc3JalkUBgpaxoamWc6/2DAWsiNCs4L1BfQ?=
 =?us-ascii?Q?w/BH/6tAo9taVW/iwO9M94gD9lA8ZYnIqng+3XwRXRo/xuw44eka83L0U6iD?=
 =?us-ascii?Q?5S85sJEyjj2c0SNqWmWm3ElJJGJYLv9Quu2hO/EQQPbDgoGB91H//ezSJGN4?=
 =?us-ascii?Q?RA/jQXbKw3KjzAqX3eTfH0Ww3thl01qSsis00gDzBo1YcUFp8YR5/AI92ifm?=
 =?us-ascii?Q?xcljAoGlIcYtJxJuujWreH3VzFPi6zPlu55smjrulxtY8edDCtXBy2yaJEJ6?=
 =?us-ascii?Q?qWUdS0ISul07fajoWr3KW1irtpYEY62uVi/3en8l2ssRUuOAJoEfrn8RmGpo?=
 =?us-ascii?Q?DDx+uX8ogeFkInWmTx7ScdidWbH6uJpuxeArluuz4OuNIlnKfKDkaFQvzeBk?=
 =?us-ascii?Q?6MjaGm2cGAUOZNPLXCGjEtzrvy/QoB0JGB/vjdwiSMQom9KGN25Fdy5S6/9N?=
 =?us-ascii?Q?p3eyDAnN3KgbjQOUWYc/OsiUlnd0bCQz/o3ivO5S0PjGbIMpguwi50MWmirB?=
 =?us-ascii?Q?ha2cTiHMxTDwtz/UojbCP3qqB5vfHVAKgF9cQBwQMnvviDpECF7CvBWuDVtz?=
 =?us-ascii?Q?n28IxomctdGGvfWYNnCrwVGD8YDSLS92PCvoT7rzGO+JOe7H+6VzNBkEqd+1?=
 =?us-ascii?Q?nodf3pYUDqMeXY1hvm/wFPveKp9ZLvQASV2vw1yNkYqreL1ziCcJSpcJj/u5?=
 =?us-ascii?Q?oA33uKn7ZDu25nqP9yDEEbPzDVXGzZ04+Id4UDzHg8YFZDS453FTTFKh1wRk?=
 =?us-ascii?Q?SHWzVLJdJiRBonO33foLaxnNJq4F9HpgFmsT2AOkTpL8I06Cw7LH1OQIr08+?=
 =?us-ascii?Q?XooHxmUHNf5tZBCIvhfYNgE+fvolyhXT0mEUW4/KOiTS8QFTMPhbkPAQ5RLT?=
 =?us-ascii?Q?IJci+wSQ6NHnrwTq8EvrUAKhis6wWTwkkiwo5CFBAQ/BfdRrAHc17iElUWc3?=
 =?us-ascii?Q?NsD7WfmE/nRTJhvIukht/zy8C5AxnoDKZTrmBpajfFl8QF13V/Ef89uErAQB?=
 =?us-ascii?Q?vaivJFkYbJnk2IrJpz5uSNAGN6uFwb2LMcOtqUmbrhLcJrNiEmNfmRoGP95R?=
 =?us-ascii?Q?zaF3vPpbQPjsN4usuWq083YSo6v/OE05i5FC9kSuM7PP+xKVzBZ27SVymajQ?=
 =?us-ascii?Q?KMsBMR41QmeKwoCE6YhzhhBmQECRUTY1dOYTzOkwGL5vQYbBHfHHLz4LgDZQ?=
 =?us-ascii?Q?KA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Gv0VpA0yieGTrTUnsQ68TCydDDGcwk5yKPKbcnnXsL7nmQUFSIyuYCCtNdtnQ7X/QOHuuJIF+UW1I/wXWLhgbWnv5Uv0cm5nEdwDVpJGZeTvz40coVoJ0YtFxlo491oLn2JNseQeYFnIm4CjmQAEE+lKVl61S8N5WZ0oUytuOck5OxWNJVg9yWWjBguNA74wIs5ysY/9lhpZgZxTbiWDDKEZSoLV2n+THhgNvJx8g2y2xPW+XDzce383m8ogibWCm9yvPxd+uBGVHNszqNW+H70YzkXmFzbl03kX6xOBt3K+vMwbWSFo1B2Hi9OrWi9i1g78IR8YssblVyADLDN+uCMNZ8as06IdE4dgEjN8ssFo2DIz8stdNKqj+taa+yyz2SFayh195tBAKCRxlMW6/vEFPVQtoeWR1nJo8X6KZlCRhm32HTvjV/No6PlfwPuxXchn2POfiSOJgOF4HXCBmUnINRE6C5cYrEpWO02yKc3QMlmkaqF/UfCVq7/yb173WX2BZs9hUzbqUthYKkqcfwFb/fZpIJbEaXhjPTczoELm2egJcuHn8/+UirbgRE8ptB+gaWK83PT7i19zSxZI0AdceUW4SOM6+LDM0dzAQgs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2d4a7a35-5204-4951-67d4-08ddf67c4578
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Sep 2025 06:26:15.9403
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1efGtBF7aoU4rPaCMu2SksdRj+DabWaQf8jPrpSZsOJDKrBhwdvkjmj6JbnPrbIvDp8zXOXrv8PFy0rztw6evERTxamm33nfOEgSSAFfhy8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB5659
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-18_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509180056
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX4Bpp2vdcAf0i
 KCHoLZHG/mJ1Z9Up/zquwUo5V/7xIaj8XlXU57zI2/JIREqYyzoupcUoJ1b80VMryOOuyUORA3y
 Ne2zxaoEV8Q0ansWN9qGv2vU7LSblPako1fJRSKWKm2nSM+rhrOd3XAAULji4v46Z0U//DI5izz
 hs1NIMtdE/TLy/Yq5WbKbOrMaX8t8qQ6PXIEuxwuLeQ47XPaPbDafmGHc5bbFzCUnQ9k8GYlvwp
 6MGjVK6XlcuLyBS8eD/F9QfZFgAqEVKth9dmAuMsOF5JAtOBsCNeolsWqEdxyyoZz8VRUTfC3Zi
 KxvPMqUOovmDQcpU2PJs8tdERQQSaEOPJWfuo/DQW1i3zW3dlY/+mITtQCUyRlrTx7qiqUlw+38
 CpOkYQZxU90bZbtCmH4vWMlp/T61Ow==
X-Authority-Analysis: v=2.4 cv=X5RSKHTe c=1 sm=1 tr=0 ts=68cba60d b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=AAxFpcqIBcFea-8j-GcA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-GUID: tC6EwaE0WPKqgZuZxlNUhubYhvsVmFML
X-Proofpoint-ORIG-GUID: tC6EwaE0WPKqgZuZxlNUhubYhvsVmFML
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=RcL+V29n;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=iPCAkxEJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Sep 17, 2025 at 06:19:44PM -0300, Jason Gunthorpe wrote:
> On Wed, Sep 17, 2025 at 08:11:09PM +0100, Lorenzo Stoakes wrote:
>
> > -#define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
> > -	remap_pfn_range(vma, vaddr, pfn, size, prot)
> > +#define io_remap_pfn_range_pfn(pfn, size) (pfn)
>
> ??
>
> Just delete it? Looks like cargo cult cruft, see below about
> pgprot_decrypted().

?? yourself! I'm not responsible for the code I touch ;)

I very obviously did this to prevent pgprot_decrypted() being invoked,
keeping the code idempotent to the original.

I obviously didn't account for the fact it's a nop on these arches, which
is your main point here. Which is a great point and really neatly cleans
things up, thanks!

>
> > +#ifdef io_remap_pfn_range_pfn
> > +static inline unsigned long io_remap_pfn_range_prot(pgprot_t prot)
> > +{
> > +	/* We do not decrypt if arch customises PFN. */
> > +	return prot;
>
> pgprot_decrypted() is a NOP on all the arches that use this override,
> please drop this.

Yes that's a great insight that I missed, and radically simplifies this.

I think my discovering that the PFN is all that varies apart from this +
your pedan^W careful review has led us somewhere nice once I drop this
stuff.

>
> Soon future work will require something more complicated to compute if
> pgprot_decrypted() should be called so this unused stuff isn't going
> to hold up.

Right, not sure what you're getting at here, for these arches will be nop,
so we're all good?

>
> Otherwise looks good to me
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Thanks!

>
> Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9d28f23b-5455-46b4-b88e-682b707093be%40lucifer.local.
