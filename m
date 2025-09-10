Return-Path: <kasan-dev+bncBD6LBUWO5UMBBIF4Q7DAMGQEJIF4BSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B479B521B0
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:22:58 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b522e289a39sf83871a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:22:58 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535776; cv=pass;
        d=google.com; s=arc-20240605;
        b=U97uchdFrj5V4c58X+2/baX72oFp/puwoUVu4W1CqcEqmNJQkrHv+8D6E6hCD4pGvg
         08Yry4r57c1f2itjye/4S0xf3RiDsx2V+zKdSMEMGncSj+ru+Q6U7dkCPmSVYq+BB1FX
         6xteRuK8dShWjt3pRF35aHGLyp/Lu5qTzymB0x36D6JL9rBlGYuxcZHD/fkJ6WiD5mrM
         RixDt4PMYtWdAlqDsUbKas2r1cVmqVX4hruIgi2nm5hn63ZjIOd0/tuoXW8W0QUaq0VK
         4gCxKzfGI+FDQ5E/myez7KU1zGf+l+ScuCP6oTk3C+rm89CCGI3qHPd1U3dO/K/PJJ8S
         En9Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=6eDmcPq0s4tkhHzfWKrCBJJZLWDJ7XCCE5CQALVVXSk=;
        fh=dQU8ZZAU+UuSzyOLCddpBFCQlATC88Lv9oiDgs38u6Q=;
        b=SYQKdOf2QkFwVCMOYRTL/56VJ+SPUCgWw33eD+B06aFvefOzRlzn2BRhQTF7tfKfYP
         tqI3v3qaJZIhrDS+aBbXJTeXPlXibauqZR1v/1MXj494Qy1x5NARUU9xjC42ISkd9Vkz
         4y5oylV4vC6sA+0rkmmDrX3hV9dzXq0kmkrbwSS3D9qjI6ilOQP+4caUj2/uxzWjjyeV
         WLMgl08FG/f+EKbxgHT3BPm6Aneb3UPOxh4Y8zEqxZ9WSFyIy1JpHak573/9qMcUvONS
         qgNBWpdTekXU2c1hToTjmWkyf7ZRLFBg5U/uGxmZQAvvrtBXq5xZyegMyUNjtivnEYj/
         OFiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DJg4eRCM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ASaT0Qlz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535776; x=1758140576; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6eDmcPq0s4tkhHzfWKrCBJJZLWDJ7XCCE5CQALVVXSk=;
        b=gp/OWQSB0U+OvgOaj348nOhyqs+a6mXBe0lGfAiIdAaUYxQcq1GBUlwvJ7qgx57jSj
         Z+FaGXVsf7T9GtxSPxZP2pA6wKrdR512ZiI1hPmUNPrpJbx6BP8QhsXmEx5zEB1UGQ5p
         yyCjdoZ+eLdc5NPEy1/YKWnfIqVIgU/AlJ+CXlORnTh+wcjFaTxXEo/xs6YHP1zbf4sa
         JLJt3hiOnd5NlGvW+NAJzPa4GYr7jGBKypCx+Ca40b500doaqIKByrMc/RJ/GmJinRS2
         iX6rzFV9YVb173Q1v+H0ddh4tcjTXttnIDbU3kXwx7Wvy1net4o4kIsXQOgKeaCUUdh6
         qSLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535776; x=1758140576;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6eDmcPq0s4tkhHzfWKrCBJJZLWDJ7XCCE5CQALVVXSk=;
        b=caonUmYGkuvZHN6GGL8GGcAfHyjpMoOZRc0AbT5kx5umD1Va8n6k1BA/2157JuimYg
         gnIYKF7INgJhu26Rjn5poJBEPl+iAUaEgwyTYYUd0NKMHkXvyoldCmfRhp4g0vafJta7
         d5TpdS75hylFemhBVB2aAa/k8/nhP5tQgocBsguCKi80ro6DLb/EsHqxadqAWox8xWij
         kk9OzzadUQIimpcSbe4r1hO9rFitAvJSy50/ldaAKyc5ywmRG91dORhYwrLmflc+nQD3
         qrhyES/SAn4QnHEhxxfPf1gqfFrkeIJxiziBiaxUmtbI+6hZ/3fMIKvKu6Zj5gW4qVaZ
         GN2w==
X-Forwarded-Encrypted: i=3; AJvYcCXXr0ZchT7TmEtk1VOCkSHvZRInvpWUFrtgvIIP5aGHB38loZXQjRTV4ZvfGVyb2owUd3oEmg==@lfdr.de
X-Gm-Message-State: AOJu0YzBqnCKXknJFOEetFheGkdBc54m+lXCszO0wB9s7Aenox/WN/g4
	5rREeNjlzDN1AewDMf71X9HaPybsWK4IxiztXzDWDmBjeyMmnRWTDk9q
X-Google-Smtp-Source: AGHT+IFs1t4iFQnpstzrRdLGDn2l8GEbVbmhizNXYcnyE1PC0+DXnUmPa89FdxIcMVs/+3t0SU5Y4g==
X-Received: by 2002:a17:903:1b64:b0:24b:4a9a:703a with SMTP id d9443c01a7336-2516e4aeb33mr243510185ad.17.1757535776541;
        Wed, 10 Sep 2025 13:22:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7m5Wru8yM2hYSTCtFkbuo4DpJXh6b5OA0IzA0nAcch9Q==
Received: by 2002:a17:902:e1c3:b0:246:64d2:f765 with SMTP id
 d9443c01a7336-25beb7f4dcfls343535ad.1.-pod-prod-06-us; Wed, 10 Sep 2025
 13:22:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXnCONdhs8LFdT1VCfCll6DPllgrEnqTid9HnK/8G198tP6ZNPVlzcP0o8LdAqd+4QquGgHNVixjII=@googlegroups.com
X-Received: by 2002:a17:903:b90:b0:24c:d6f7:2788 with SMTP id d9443c01a7336-251741866e3mr207433995ad.57.1757535774849;
        Wed, 10 Sep 2025 13:22:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535774; cv=pass;
        d=google.com; s=arc-20240605;
        b=iL4F7TkK/qYaKgCnWDircQFhtJPps0QTM51BPm3OP0KcZPaH0nnKCW55SaiAvESNMG
         bWPR9NiVO2qeQbHcKeYZi0BRQG5V3rj9pZ7diZvS7AdZEEdvZdYzl/qgdiEa57JmFjVm
         PL26PpZ/WQ7qrOuHbufVRnfjpbrLpv0PtWIs4QpewEujodVGGDsFBXkctfsMw8kQ83Md
         CKLdYJQ38nYVjPV3Uc2ChGzjdZtPczBcO+ybitPau6ehmdYGd7ePqxdFMWrUiUbOFfK1
         NGwo2SxV4DALUkjPHvLMdEJ81IjV5dtFecaaU3aRlot37CgIv/mhoJz3eqYSBFx/W0B2
         NazQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=W30YNRG8/lpU89Law2KHsxlhvmZdHGHDHObMYfthywc=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=PJtcQEN+F7K/EoIMgkU4C88J7Chn6FEi9GwRcFBGlwS4aFRDXeoFOEeWyNHLbydJRL
         wG+s5/DpCGMzAwj74xbrUUESdjgfyaek17OCTF1HTiIvBGEZuFBakcev53m/kpDfFZsy
         xT2OVD/2UGTYov4dHueQ3uDoNDTC/YphjJ9uGH7zVqQ8SIBVtO+6ldigALxDl8eapHVG
         XNsFxOgR2KBV8/xYSEUqruqwTgWE0aJHX4WPDJpq/Vo9eNc18PxgmucO/KtC+XrzDQED
         f4PiNWnOl4CVQdn1t9Cx46nA1ZLTPXRQMwSkKimlGvzZkzptQyowVuQH8dNhAWzrEGQ0
         wksQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DJg4eRCM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ASaT0Qlz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dbb4a9988si158288a91.2.2025.09.10.13.22.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:22:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfjnb031746;
	Wed, 10 Sep 2025 20:22:44 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921m2vyxh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:44 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJImr6032819;
	Wed, 10 Sep 2025 20:22:43 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010002.outbound.protection.outlook.com [40.93.198.2])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdcg0rc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:43 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XqGyrFr/pyZ4H9GyQBoYEEQTTWhz5iFxge9FYAKeKCsG24vhhAenUnpV15Ks26aqV+fUDpkpSNS8e2cBMH6HN8Z8iFUcCeESbFZkBjIEwAv2YzO5SAOdKN4XXjoOhVOPvPj16FVJwiyKDPhgIMMTFhMitT2K6fzVlQDNZEohYRGo1krC6UHMFVz8mC7gIrQZZRuaIVFeZUu71D4yVnd4UQOG5JNC8jfueq2Wo2FLzqaAgbQu0JBYgpRHEl/4xi6wpyIDai91vWVhcjOeXe98H6RSMmSadPrQLrL10vP0R4+Ge/T2LzjnQQqPDLYmlM3ejTAf59JxMhMMcFVXtpnDVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=W30YNRG8/lpU89Law2KHsxlhvmZdHGHDHObMYfthywc=;
 b=oGEjy3DVRMUn1GJs3ICLdBKbvMcQPypm5Fr1/TXiXwdYMB8Ncqc7fSQcg1KYZGs1WWFG9RF7/BU3aVusX3aM8tAWlMmQH7IeAT9cS+zAmVz/GJ7+S16wyl76mkHKGVtPIbTf6DFqEG2tivXrI9g4fttFdwq8DArJOIp0yweakzRqA9j4lEbqhP2/krSczxfwhbLxs47ch9ThPG3idPA6dEFy4KgZ4tCeKCoByEbMqGog+5Nh5jmBlIQ85fGOPNwnbtSpgBeGBPlnZr6WnzzQC/mQrmNeGpH4jclyrCbDGKlWxbwjzPlGpUbgdbstJGcR7TiuKdem5w2RhttnshpY4g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CO6PR10MB5789.namprd10.prod.outlook.com (2603:10b6:303:140::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 10 Sep
 2025 20:22:38 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:38 +0000
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
Subject: [PATCH v2 04/16] relay: update relay to use mmap_prepare
Date: Wed, 10 Sep 2025 21:21:59 +0100
Message-ID: <3e34bb15a386d64e308c897ea1125e5e24fc6fa4.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3PEPF00007A8A.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::61a) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CO6PR10MB5789:EE_
X-MS-Office365-Filtering-Correlation-Id: f64202fd-bfc3-404d-1ee3-08ddf0a7c96e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?98UnBXIMqNmQoYxI3TuWXMe6V3nZPkXP0hRmJRz+aXEYypEnMLgvyAPPhAqx?=
 =?us-ascii?Q?vV9kf8WMYM608xQiXk/NJDzpFI+BRHQu3ocyyRkyAGGxQ9rxwDaStTpHImnL?=
 =?us-ascii?Q?bME8Dl9qtYJFkWy1HOu0Ilj+AFx1VwRW7X1nr87g6TZvl3fvT+yU0+KpWA1Q?=
 =?us-ascii?Q?GTgvn6BAjzWYJvU9tvFaB/HqQXdmUC8f5NQ64CataiBT+leInJ7+KRJ0q8Yt?=
 =?us-ascii?Q?rgEMorVwA0wdUygM0PxUx7KQ8Con1YzsoJZ9FAqTEEKDTlYkNHPT36qTdLo0?=
 =?us-ascii?Q?U5hR454HUc3wECFzvDQiHjjivisJ45lZVfxO1tVN5EWv1au+zSUllPJhC8pl?=
 =?us-ascii?Q?8iPcK2vO4kECXpPoxry89Uwq+oMSJeIb1WVcLCAylPwk1UHgyEPLY/HapuLN?=
 =?us-ascii?Q?QzgBCKScykpjyYhoj6Yj0HwgKqyJcECARxs6hKc4C0Z7z/Nlt6G9Ag9c9WDy?=
 =?us-ascii?Q?rLjLQOpbr9MfssUH6oSPfWBJ7K8z1rJnjYSD5uD5C6WeWmu1mg5UQbgi0vo9?=
 =?us-ascii?Q?Xc8+d7pm5/xzl6saYqg4ddYzirjvtScu2NyyfQnuNzv4Fv/Vj17pxWLAkzvR?=
 =?us-ascii?Q?Tsp7qap8sTIk4VomyTCvVJd8IWiuN5mK+C7bceycdogFAOYjdoA3c29T2hRT?=
 =?us-ascii?Q?E7s/Yf3vwo6ZzDm0dApVoBM1D7vSjMtrb4QVQYTjlOr0a91NN1XUfJ0sdEgS?=
 =?us-ascii?Q?B09g855UIIuhp8dbqa9ub9QjrQay0lv/iImLr0mzkFILnPx4XcFoaxB3XUCt?=
 =?us-ascii?Q?kJk3seOIacpRTDXjvENuxdqbA3/GZ0CxoAWwX2dp9DVuNxfn62Tms10hoB6V?=
 =?us-ascii?Q?a7LljsshoK9jV2T3GnWw5BRUF3C4FjnvpAaa3sNkmYLiPWVwCzfpaCtejPep?=
 =?us-ascii?Q?bM0pE7NOQTTk5NE1ib+3uTzWG2f3DzOLUuoLrC2BccThsBRboSV7YKnri3ZL?=
 =?us-ascii?Q?DGw2SmObDZNnUm//oaJqV9D5W2Lsipwn8rMD4SPIwKaqKU0lPPFKRerj12rx?=
 =?us-ascii?Q?cko/yY1FFMISbLkgNexLi3zw7bhAj/LSk8H8owaQFiUROuZp1WwPdyOqH+U8?=
 =?us-ascii?Q?YnmDukUAD+e1KmjTppkZtOUCClrQYS7rt7H9a/HS3T1wg1BLNbAPIxNGTzO9?=
 =?us-ascii?Q?MdD4hala6yy4YXuBhreK7KlPmEHMH2dlQjsHUrxAp3qEqblonGaLYXFY0QPd?=
 =?us-ascii?Q?J3HmxHL/nNh8VcWTxTdkCyoocvB0EIWH2g3rD9HomExP3KPmRDQsLcW1rS9B?=
 =?us-ascii?Q?WWBLCTPFdSGW3zBrpZfWrHhhfR1fZJUzjyNFT/iCb/hfPRaeGzDV1ez30d8c?=
 =?us-ascii?Q?DoSlIVCVqJPddXyWgAMplJSa4vcNYBdvGvqWinmHxF0RhTkxa+6Uwziza1xr?=
 =?us-ascii?Q?JOnO5GpHHauhV3QpMaaj4npzGLc2Km/p6f5MCygSiZEuhPz3XWFNA0PBVgr0?=
 =?us-ascii?Q?Si3qC5hCwJE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?i9twudHJF1wu6JZNbBELsSlsFsutrph4JeiqCToSIKmDf6yYXpcKSYAxrNdC?=
 =?us-ascii?Q?XW0mX7odiZTUTUG53uXgMgJdhk585ZfkRUSpD5MSwEvaZE5cIfVq54OMN8Po?=
 =?us-ascii?Q?nbzYMEIsaf7Axv1YQjD8x5WeBkOAldLCjwWuTpxVmTf7D+OKF+nHoFbBgz88?=
 =?us-ascii?Q?wJPHyBVHpIfVYOwY3eLQAGyYPq+xjINtsM341tPxc5Huc4Rtk63LtHUls86N?=
 =?us-ascii?Q?Ug4KxLosbUrZvx8d+0e411AG4u1gYEgQUU80kFfKfrtsilTSoJwEsROzVI8a?=
 =?us-ascii?Q?GEHGu/qNfUaWlasAeuMWiMdxlM83CVgW6UBux83oLV95p/0Gh79oUutov416?=
 =?us-ascii?Q?TtZ1FyujOEkHGpOddIc8zOLbQe2DW8RZp3dRr3JSHkCeICH32t/04ITsFTRb?=
 =?us-ascii?Q?cCuALorm+fNM5UtHwhBNvRZnH56sZzqFe3Azn+VlH9YJpwLLLa/u7LfQVCGK?=
 =?us-ascii?Q?1RaAdOXZPZP/cIlvRz4ftYRBGcjOSBl6DvEECPSqo2MDBQpuntPt0wanoHjE?=
 =?us-ascii?Q?fz6ZBTrrR9x5LlT0LPnWeVgltpACOH1FNQjyB/o37nPNYoOq4adEVU+gTAPv?=
 =?us-ascii?Q?ySs/PLp3AABwinYkdC7uPVywfhpgkVIZ/AnySXtRoNb2V1bKRuRVFahxdO8y?=
 =?us-ascii?Q?9clEqUrsMw+4zZoJlRmmH8XwsAKVA/RcSY0PAlmpPPYokAF33yhUX+eyiPGf?=
 =?us-ascii?Q?nWmoztH3SM3mzlXzhAhzSQ7nVjP3xDGmbkBLG7z+PYX2jV4s0RRuEbhlvpL6?=
 =?us-ascii?Q?cUQjyzutFSEb1wt5V9gdzfN0ZKiYQC4GyEb0Gqf33Fk+NkaUZgIRmCcTNIUK?=
 =?us-ascii?Q?DNvZ1oHV83z93c+vVqAuD0V1oDovFY88vP7yLZhdPKzW1BtSQRGpcC93yXNO?=
 =?us-ascii?Q?GgPZZP3casKYbLOZBLuCch5XxXuhx7llTP5JsiC5yj8fe3JwYZwl5D+Exi4U?=
 =?us-ascii?Q?nihTFlUFeDJ3DZZEeTQcr3QlPhwwdjfLfcprcGhTVQ4ZHLQ3EYS4UUPNgDoY?=
 =?us-ascii?Q?5dKTMILEvV+uCkKgf/O6du22KUzDpYAWThh/SnDbyZ/OPvKaR7VpkRAvp8HH?=
 =?us-ascii?Q?MOvq4dNSyqq75T2XoO0h6pcMxbH7lfL+Z/bGOJI1IopSF71EIRuD2P5H6UCO?=
 =?us-ascii?Q?K1O6IMCMsFIKdHUz+X6I1SjQYPdNIqmX8gwRr48Yz6GJ8LoSX1BRcpKjKA0C?=
 =?us-ascii?Q?fBExyrjH8f/Q0HclrhYcPVZ2Y2uJyjSM8Sihg375BTG4RIDEnISWaeyooeVd?=
 =?us-ascii?Q?8hZ+305VihoZxZXGLFp8YPxgtpVpyYHp47BaNdGaa7Nsx94wuet7qZK2d3ln?=
 =?us-ascii?Q?Xp56OlW7vIbVWg/IKuqDHGblmszHBcJkApRmBbJoAikVI+T6bsqeLriuRHXH?=
 =?us-ascii?Q?AuBNWnVAxIN2EG6IQvR4+dgVPJRr0vIpOruZ032hmH7q1gvAuKBdgRiFaYzu?=
 =?us-ascii?Q?pUj6SWD/f0bdQFxTL4kLTHf+Q4oPKQoZPBGckCrSypLaA0ugi0+LSEV8rFdw?=
 =?us-ascii?Q?+9FBny+z1z7uzNs1lGo6Rb+7nxsRGlr/YlL4bzpuUMJV9q5U9ay8ZFKsjaww?=
 =?us-ascii?Q?hT95/XYHh/bMQBm2K+/9LgbBhjMBxr7gL/S1cnC8jA6LvfIEOEYJI6slx0Sa?=
 =?us-ascii?Q?zg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: jVcb4CMjz6PpIDipLEHqrW3Dbopufj65mM7tXrY6M/TFIqbEqheynQd5wk2uDY9T+GOzCRe0DIv5C1HuJWicCcnfHBwPO3VSIhFl2ILiId4jQTdXhr6rUIgL93T6WEjg1vZq62f8QQ1w97552Ykpig6voC/CNLxsne+YiMSwHRavmAdG5KpuEr3MOg5oVjGpAs1RNP9XE44ivhIMKvWusJFQStWXuEDgF13DFwoZyuWKW7lJyL1UqLvjhfQMUDiiiCOzhZ2TVRj35e0dU0XYzbJ+moS45hKjVRIjFAVrPmor7QX/DZNXpoe8wRy03iBM17eIRSOdRzkxbL1AVOwGTFd4plOofMcC+L4B1uObul8ckafbOmp3hdWLotJL0TnIE1Wod0621VV1VJUYHEjtOOt0Iw7E1eX7WptRT4CLl5SRcWertxmkcRndYNQYNBo7lP1iwga4Vc5RZXMmtaNFrjIu/bvvVrTpI2Z3iQp60x4xobyzdaG9G8NDPUEgpNyXvETwEr7IRguDIgwCY2q5dtKvQK2py2dsMNj2vrY2thOdOQmKWSHEQ2g3oKyHr/djNW7oO39LvKhy/SAaA71jI4PRUE7VP3CD5jAzwsUP+FU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f64202fd-bfc3-404d-1ee3-08ddf0a7c96e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:38.7905
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4ons/cXvo/Xys+KEJKwiWjZA5KeS/YdF1RdDmBpmU3ExUAJu1czFlln9XKyMkvqhqqgaVz95nv/nKIXme3zNX+CFqP/Lsp2NqXkitAWuucA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CO6PR10MB5789
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100189
X-Proofpoint-GUID: tAJTQQMvmeyWHxCzvi3ufsmK6me-MXpf
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MSBTYWx0ZWRfX3wFGBULK5EL7
 kf+Dylq7JJtiqmb/UG2p/ikaB+LvjuuL3QeW9SSVA//P0/l76YgHXcZvdUIP852TrBljb0rktl0
 Iuf5viOB9wRf/Ip6cg0gpc4UfTRsys3nGXIXj3E3pxvprcdaMu6xtwBxefNERGnd8HMlosTdt14
 oAGk2afd1PD31CHbvN52xG8zTwvsEuW6JI+sa4lFbbs+5vYHGg0B5s1mMsbRoNi9hOqvdCgoDwY
 LFPjOphcC0zOWZerqNMCTauFPHOeFm6Vl0qC/E7MYJznN1J9GRcORUUatXcgVyfsbFZ2KTdHzv1
 wacers/AMKjoGYqs8zSZfa6DjYAhdxxnNuMM4J/lOBzxKXn6eQulkMSSSH1/jqDtCMtAKg4abTR
 Y/L5Qzq9
X-Authority-Analysis: v=2.4 cv=Dp5W+H/+ c=1 sm=1 tr=0 ts=68c1de14 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=kVp6y68UWkg0hX7IE8kA:9
X-Proofpoint-ORIG-GUID: tAJTQQMvmeyWHxCzvi3ufsmK6me-MXpf
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=DJg4eRCM;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ASaT0Qlz;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

It is relatively trivial to update this code to use the f_op->mmap_prepare
hook in favour of the deprecated f_op->mmap hook, so do so.

Reviewed-by: David Hildenbrand <david@redhat.com>
Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 kernel/relay.c | 33 +++++++++++++++++----------------
 1 file changed, 17 insertions(+), 16 deletions(-)

diff --git a/kernel/relay.c b/kernel/relay.c
index 8d915fe98198..e36f6b926f7f 100644
--- a/kernel/relay.c
+++ b/kernel/relay.c
@@ -72,17 +72,18 @@ static void relay_free_page_array(struct page **array)
 }
 
 /**
- *	relay_mmap_buf: - mmap channel buffer to process address space
- *	@buf: relay channel buffer
- *	@vma: vm_area_struct describing memory to be mapped
+ *	relay_mmap_prepare_buf: - mmap channel buffer to process address space
+ *	@buf: the relay channel buffer
+ *	@desc: describing what to map
  *
  *	Returns 0 if ok, negative on error
  *
  *	Caller should already have grabbed mmap_lock.
  */
-static int relay_mmap_buf(struct rchan_buf *buf, struct vm_area_struct *vma)
+static int relay_mmap_prepare_buf(struct rchan_buf *buf,
+				  struct vm_area_desc *desc)
 {
-	unsigned long length = vma->vm_end - vma->vm_start;
+	unsigned long length = vma_desc_size(desc);
 
 	if (!buf)
 		return -EBADF;
@@ -90,9 +91,9 @@ static int relay_mmap_buf(struct rchan_buf *buf, struct vm_area_struct *vma)
 	if (length != (unsigned long)buf->chan->alloc_size)
 		return -EINVAL;
 
-	vma->vm_ops = &relay_file_mmap_ops;
-	vm_flags_set(vma, VM_DONTEXPAND);
-	vma->vm_private_data = buf;
+	desc->vm_ops = &relay_file_mmap_ops;
+	desc->vm_flags |= VM_DONTEXPAND;
+	desc->private_data = buf;
 
 	return 0;
 }
@@ -749,16 +750,16 @@ static int relay_file_open(struct inode *inode, struct file *filp)
 }
 
 /**
- *	relay_file_mmap - mmap file op for relay files
- *	@filp: the file
- *	@vma: the vma describing what to map
+ *	relay_file_mmap_prepare - mmap file op for relay files
+ *	@desc: describing what to map
  *
- *	Calls upon relay_mmap_buf() to map the file into user space.
+ *	Calls upon relay_mmap_prepare_buf() to map the file into user space.
  */
-static int relay_file_mmap(struct file *filp, struct vm_area_struct *vma)
+static int relay_file_mmap_prepare(struct vm_area_desc *desc)
 {
-	struct rchan_buf *buf = filp->private_data;
-	return relay_mmap_buf(buf, vma);
+	struct rchan_buf *buf = desc->file->private_data;
+
+	return relay_mmap_prepare_buf(buf, desc);
 }
 
 /**
@@ -1006,7 +1007,7 @@ static ssize_t relay_file_read(struct file *filp,
 const struct file_operations relay_file_operations = {
 	.open		= relay_file_open,
 	.poll		= relay_file_poll,
-	.mmap		= relay_file_mmap,
+	.mmap_prepare	= relay_file_mmap_prepare,
 	.read		= relay_file_read,
 	.release	= relay_file_release,
 };
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3e34bb15a386d64e308c897ea1125e5e24fc6fa4.1757534913.git.lorenzo.stoakes%40oracle.com.
