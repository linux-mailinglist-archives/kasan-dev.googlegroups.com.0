Return-Path: <kasan-dev+bncBD6LBUWO5UMBBF6O3DDQMGQEEWGVOVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF361BF1004
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:08 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-430d4ed5cfcsf63786995ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:08 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962327; cv=pass;
        d=google.com; s=arc-20240605;
        b=DIFeckapg6qqXHSx2HrCjtLMpuNoYDAyZHG3wVnz5NtXSkOqIZ0B3zR/qEofAlW/DH
         kpMszODgVn/2QBZ8ntb0461dPMlkiKNIH75eQhlKhkMacUiZGxaGtH4mMmNr1QSQA/7I
         hAh6kFpfZzktMWLArEZ1eLeWpUvWMs791ZsqoFZVE2juiQeG3rgERV/yL0AD3d5UDKPe
         oi1WWZba0KhU0Pp2He5emxEwfSL6sdU9kWPtRRye7r1mddvjY3iu2fuX24RmFnABCurT
         T6WM2Rmcmh97XP/p2UZ1Qc2PoZMpx+gLZH3cS7kI3KEMW7EyYYy0jFfVynwV9U8RN90c
         fpwQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1ZDDLNu4pRKfxONdbQxb5IKW9zuk9xQ81B0/KMHjJlQ=;
        fh=ueYy9dCYtynGs/pFBF/a/4YWbRZmpuZUAYJJGGFy2n0=;
        b=eZguVRPcdbSeObnEVcsejI8up+PjAKrKgoIkDmXKSTOati5KF5hAFlLMOLBHEY4fs9
         5xWbzKZsiqrnSCcMfVXZL81zUWU2SZd+HbkUkI9DIf9bIszQT5Hs3Ojzi1+m7jHmZ5j9
         nT8iagBC0aNyukMNPuMZFJ31lFNOtJmOUxGJr/da4s1GfxeFS/ErRsEkNBQnr6YAnC0h
         G+MWuiEfdeaspCfy/q862TgSXtlkxzKtBu2wHthngllT4t3VbvlUcYA22TUvelqBEYkD
         gHCA0sRxFGFlRIc8dWoeHtaWbCn5YtMtYU2zxZskfbbDmZN0JgHpT1zChy4y8UgQfOiS
         /+tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JnvxmEKd;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=m3KS06Tc;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962327; x=1761567127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1ZDDLNu4pRKfxONdbQxb5IKW9zuk9xQ81B0/KMHjJlQ=;
        b=vft4C64B5AVn4IhnPsXm8GU7giSi+zaAtYN903cZff1dri9Uoz4HYC6fsO6lnDtNLm
         A3HSji9ytcj57FGBz/tAVp2jw9Ab2kDFrZT/2UYFbeTml+6oZBBsO8tTVC2/xhOFRVv2
         1LRjsC2spwushKnt+R5w3MCcwEyX9gk2Se5+DJ0tmY+EcJ+oYRF02YVRSNV9BJ1D/U+y
         ZOXFL8+CRGVEhyTvf6OBvlp5XDbGOPYxAsX49uLL+6rzyaO0n+O/aCls8AJns8IOV4+c
         B7COlS2KP+xb182AD+1D3xtkRJ3KyXw6WK3JRqazo5vPDGXeq5bmC11V9hXTj4QKGGkY
         lTSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962327; x=1761567127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1ZDDLNu4pRKfxONdbQxb5IKW9zuk9xQ81B0/KMHjJlQ=;
        b=AqoT3WcKuL4MTZiF3MtjosdQclT6bzJ1os/D++qr97vfkkd+pdF+TZ1nW3if8LUk39
         Du90vpyt+ftDD4gtaqeLldiwOMJ3fI4p3lC3kt/e8TaX5EOzPKM0rk7cEq8R1A6UxeYa
         SQB50bNHZB4NEEmCkMiic7AGXtnOvhLaVkwCg9mmWcMwMO2HO3dxmnabzZS2VMLbcmcr
         y38iNND6yDDK1UTqWfbWRSMRqf0X/Ia8AoFPMjSGSO0qCgSLHKB3SBERZY2mjBoEjRMW
         y/dLHiZc9y+Fx+bhdQa9KVsrZ6JSL6i2V1BcL8vuGLRc0Y+8ini5CkV3GQiGcQdFVPpI
         SSCA==
X-Forwarded-Encrypted: i=3; AJvYcCWfIKHQBl/vjrf55wgIBkNZkVQ/1W9Ct6bxBpZpdVANldCIunMNmd4P6TpvO/g++K/htxRWrw==@lfdr.de
X-Gm-Message-State: AOJu0YyTbrZ3Epx22acY/Q8BPgGcd0NIt4pACkBnMtQqoIYMi51vVY2e
	9LjDogAPPyKbmCbj/G8eDyMWfbl0OWMqr3mfrRd5J150fCi+2smdi/QG
X-Google-Smtp-Source: AGHT+IGeNGL1pTHwaDJTsM2Crr5foucb8xFk67hKibqbUFrEHYBLyvO2D5Ffmu57BYN30Ubiuk1cgA==
X-Received: by 2002:a05:6e02:4506:20b0:430:ca90:d0b with SMTP id e9e14a558f8ab-430ca900e48mr128789135ab.26.1760962327359;
        Mon, 20 Oct 2025 05:12:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6tp7EQ2c23p6vqWj36/Ftr6hXJPJjwm+8PdPzpeX99UA=="
Received: by 2002:a05:6e02:50a:b0:42f:9b7b:bb73 with SMTP id
 e9e14a558f8ab-430b76f3970ls50473085ab.2.-pod-prod-02-us; Mon, 20 Oct 2025
 05:12:06 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXdXuErmrvimLutedM/coyKYGOpdiVyjMGQ8XV+Pvxh8gu+zq5Kza+lJalKno7pSJIuMFHkYISAr+Q=@googlegroups.com
X-Received: by 2002:a05:6e02:160e:b0:42f:8d40:6c4b with SMTP id e9e14a558f8ab-430c5246f89mr204398805ab.11.1760962326501;
        Mon, 20 Oct 2025 05:12:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962326; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sn6yxjdtVatFCuB1BPgWOlFov+iSKPZyiwvFH2jeRZKsQ74DnYTpmYqDxzfuovbngV
         joHfG600icwSL3hgCBrOaXFJnVYFSM1L914AUQlsnhWXiLWDJyS0n1CHbGJ6NDlN3ygm
         sAHAxI2mxauYiKm/PTQYGhLph7AMsSf/gi+LBDgDgoxx8n6XL0HObs0olmQGVyG93Tcm
         QmEGrvF0JvNIo+AOhzN1rppUlggcGwXG4w4mUZz18VTJttY3DvvMPwp0eORA003MB2Zm
         dPa/Kc0d5Wfgqzdhcm5cjSX1+f3jjOiQiaeDjeopM62JdUx0fbgLRF/PfCjDqEU7P9iI
         i6Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=t74fB1rLq63mz3sL6A47wt/uIDjXLjx7Gbd52PfTYGk=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=c+VrMwfSmUVf/pHdOiUZ7jQsM65FaqDw7558Y2wJSlHtFepqjpk3FndZFm7ul3sEzi
         O5iZszb+wtExUclwmPfbEfUjf8gSXgIHivlGVA7IDQpUjQ2rPS83UngN7f0MEaZRlPt7
         WFWrFqzWL9Wy/vAwh6DiJFgEclKV2AEDzZy8N+ibqkCJUYMuBi7BR9f2Wk7RgaW7e05g
         IQolBC9O9Q5nC8NDFn8G+OVaQ/7QFFaSxTEBuvxSzZyJ3qItcVrKZkkmIW7J7FPVzAm7
         /PhFgRpj0kF06Za9uwq/FHq9OnU/THzUmwDR4vKH1svL2ExwXYGaf61G80IGqs6JI562
         htfA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JnvxmEKd;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=m3KS06Tc;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-430d07bb12bsi5730975ab.3.2025.10.20.05.12.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8RniX008282;
	Mon, 20 Oct 2025 12:11:54 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v31d24em-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:54 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59K95vYr032333;
	Mon, 20 Oct 2025 12:11:52 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010009.outbound.protection.outlook.com [52.101.193.9])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bbmf8c-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:52 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=iuW8RNpGcUmQPhz4pbYJtqeSTxkLhq6VM+jgf///afP837EgZpRITW6gljTJJ46di/aJwtYyf4KvNlEtzohGdpx3uVaRgtLW7Qz/5TlkVTG7Vz7fG2Y8iG2zfv9EZZRUOw59zgQ+0qOhYNQAMFwhpBYan68Xk1yoVMai3Fa0ULjAzG9I37i22S8Wx0g2bijitRj/CZkmbQ/Ef89sy05dd5BEO7gIUEPBnGeLK/v40kIR8UAh6GmsaXU7kvb3Coqf7WJZxF8UjkDLorhuoshxyXd0Fpc5OQ57v0PrL8d8+0bva1kiIeLb0Dri89W+6QECfVw9NJM6py90ZThPsBPl3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=t74fB1rLq63mz3sL6A47wt/uIDjXLjx7Gbd52PfTYGk=;
 b=veJLU0FxYcxwca9qotThtYpaT5kzS83NiiKaiR6wDlqpU3+vxAuQLmHr2YGbteI7N5qDwSn9obdz15OeBZ3trYZnFpNIFPyZ8whGSqQhLCyR3Aw5e25RnXDGv/WU/oCWPRJAVrmQXMeAcpqWaI0wrWHMJfu26gQtOC0ZGZmC+O3ymm6/gDbqzEBHnrvp6MyK/k8Ae17mWcjiFFgzZh3gtRT9fTqAHdP66J75oaLoLC4jvORSrqXNzliDryVi2efdVLWixQhBL8bQOXvgbVdkkx1I8Q9pnBu0ZnywdNIj7p5MHercrqHgSBcHSY+EnLFZts7KbvzFto0qqBeoOG6JdA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:11:49 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:11:49 +0000
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
        Sumanth Korikkar <sumanthk@linux.ibm.com>
Subject: [PATCH v5 05/15] relay: update relay to use mmap_prepare
Date: Mon, 20 Oct 2025 13:11:22 +0100
Message-ID: <7c9e82cdddf8b573ea3edb8cdb697363e3ccb5d7.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO2P265CA0144.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:9f::36) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: 37d96410-d7d4-4133-e190-08de0fd1d887
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?kafMuMk73mJJw/zC3+RiNSe2+A1wxsu1b3NmS43eBVD2jnWjs7b6aOUvrpfJ?=
 =?us-ascii?Q?m5DMbDi72HnNzBmGJpLAw7nHnJ+wk/GtW30gi0sSCP19+WRGBrAd25by9EQb?=
 =?us-ascii?Q?hJtGDmiLMMR/dssgYOCoPNxxbwz4SQMb2jIP8TUoGGqYDXy+MIY/zN5gonZh?=
 =?us-ascii?Q?uegNWRWPC07k/3M8Nyj2hHn3pUb9HsJ4P4Yj4en6xlXE2p4KwRtNyc4LQXUC?=
 =?us-ascii?Q?KLcgBT4RIHvDgwNKyL+UuwUzOA4eudQ7iRx+/rfprhuT35hLhqg9joy7+6By?=
 =?us-ascii?Q?bsBt7DEMat/qGZp+HADDZ6mdzFCrgP04xYVTVutowkmyWkkxhSC6egaEKiwC?=
 =?us-ascii?Q?1a7rLywmP0+GTM0mXap2h3SPsUPa8xxSdo91q/jOf+/8EoNcqG++IX/XXKGH?=
 =?us-ascii?Q?TfOtpZmvvYlNffbebxHddWTFBXxvZjAzdEj419txsQrtk5q6Nll6G7AFQPuG?=
 =?us-ascii?Q?bYLJhZX4M3Nrx6XTHfRAuQptv4VB6NjoC0gZQ+hJnvwojpvm4oHlBRbDxggg?=
 =?us-ascii?Q?IqX/DVLLA95bZXidAaF4R7sPqmPs/NNyX8888jisO+HKFbuzWRzg57qFwP4L?=
 =?us-ascii?Q?rmELF/K2uPuDW1FY36jBiRHfIScTuUXypdy0ybK33/a1SNf2Km7CP9yWmDSb?=
 =?us-ascii?Q?VVrEd0g/DytGrKTmGG4INGZ1EUiQvSfL5akB3sb+bisRbFEk6dv+GO842+U1?=
 =?us-ascii?Q?Qx5boP8xzeYC5FNLYR6mQMzfuHIXpMp1Iy1c46rh15MThIBIas857IRGCBo/?=
 =?us-ascii?Q?3h7fOl+th4kQKtOMz1kXqhVPkgd296Xp9Ro1wpEAf12OSnkttAOo+E6KiJ+7?=
 =?us-ascii?Q?2efB2P79co7G3CwwXMJvTvaODL1wVl2eagxGEiPrK3OSv9zAK2y9IgURsF34?=
 =?us-ascii?Q?Cq3V/owpbjmULstheA/swz8hcqct+5MYoILP93uDwP/EpoyBXgCd606WL6MT?=
 =?us-ascii?Q?TR8b7uQe7Hq3qbM5Sy8J6HFI0UcY/61IoE+SBqVuPwSQ8HLl+ARJ+3ogXG15?=
 =?us-ascii?Q?mR3IIx9mBK46rQ3iMsI6bMVYvAOCA/TB32ae9ESGIBeO2KsPmaIciMd/rAQW?=
 =?us-ascii?Q?44e8JHxHC6lDnbfNs/wEHNg60n1lnQhCZzHW+bIu0OapoZW89+x/wSQ8cNty?=
 =?us-ascii?Q?/IHc6/8saDVeqWanZHYrRk2ZgJrWl+oy9zmPtToxhqafudEo1cDYdvJgRPuA?=
 =?us-ascii?Q?cpfBXJeEIC4QnGhORuOIxWZqcQiNpGVgjuaH7jVYU6kXZD/dmPdC7PSIoKry?=
 =?us-ascii?Q?jbglOskITvc3HqxG8Ii1e5hxJJwq+s/WQg/axnf4Iycnxk6avRNvGyDW8ng+?=
 =?us-ascii?Q?UDQSWiYVZrnnyEDrREML9iD05sl7WBLB8XuCpwuGCq3r6XWwpkNKsMzDRQrM?=
 =?us-ascii?Q?c69sd0128cYsqp/eA2RKaklW/mZ4DwEo3O0tahlfv/dRiX8PAv+2q8ph2Lbx?=
 =?us-ascii?Q?d1wg2/FO2NtU/HX4upPPXZUNM3q81+1J?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?G3cDzu3/FM7Lo9NfSWCEY5/4d9f7t57a29A3HouOUihs8FYR1SWNPvEoId1K?=
 =?us-ascii?Q?w4Lytyx84nkYYDFUf0C+TEoxJ+PvQvWMqP4AECpFeIQSG9/4L29jys/vPSHy?=
 =?us-ascii?Q?OpSTs8/J7d2coP5k8CKqlcnY1EJ9LzJapfHiahNOpOl8m5TsGS+kKn3fsxNu?=
 =?us-ascii?Q?Z5qhILeaOtBZmTmizlrBL/mVOo0J6+VOZVDFTqgTvAmT+18BUb+uK36/MPnv?=
 =?us-ascii?Q?OecGxEuFOMGYSZJEnqjD2rxD6nccoysQN2IcHINld6Iy3reCMRsouglsEhoC?=
 =?us-ascii?Q?h7DKSuuc1qyLH3oz9Ap2GbaV/Ye0adXK/2jB9Q6hJ04bwygzIi9//IRs5sKO?=
 =?us-ascii?Q?pSbic6AvQg1OXI3j1YVX/Y2V30MM0So8ooEoa3Jf3kGaIU6jeQws5M2m6PFx?=
 =?us-ascii?Q?vX8IUQ8uIvekrk/skLJnb2XcMEP8YKKMKnMnhYx7JA3e/snB9kPV/zHI+U8r?=
 =?us-ascii?Q?w/xil1gLpcAVDPewEoftnLjdiKo5HfoG8IbARvvLsaVmNUMJYE5T6C978HS7?=
 =?us-ascii?Q?DM2DrUWGz20qJEl/61N8Ypld6lL5UWNavYmLASlJH8Br4AmhLYxSN72HlXOT?=
 =?us-ascii?Q?6fa5daYRoTY5Gu5ZajdMR096tovdWWBczM2I1ohQ/Pqy8qJdmT/ue8TYGfbU?=
 =?us-ascii?Q?s2juVvNG7SyKjce9MxGdeqDclEnhwkwyIs+xvG4TiJK1CVOLabrvHM5sf0Z3?=
 =?us-ascii?Q?1F72IMjH6QIZESlnalfGSwS02LNjVQffW3t46I7coYUo+JSas5V0Lb4MN+nl?=
 =?us-ascii?Q?KWZYoHzktChiIb+y0NGWJa+VTnbsZQ6BfCyPdZ4Ob47lm5hTMkif1CRKF0SB?=
 =?us-ascii?Q?0uJpgksWjqg4kBZ9iTlYGsPrq5mHSSA8Z+jVys3Fzhi6YicX6+rKf5wxb+H4?=
 =?us-ascii?Q?7r3pzgbvIT5ytl8w4//LgTyhBMX7KJlKm5kVgaABk1fZl2l+qzR3/Rr+NeAn?=
 =?us-ascii?Q?ZxOT+PEiuXoi8TWRm2UTcip5PVZOhllyFP3pgmSJeAg8pYqS4D+YLYxSRXcU?=
 =?us-ascii?Q?tyFi0XRB4u5O/Muw+dbTz4VnDH3XfCM2ptZwqLcWRC3UNNJC8bC1yh8k7wiY?=
 =?us-ascii?Q?Nyc5X2JdViEQBVSKRG+rDflGkWRvEfi6p0rsxiBBrZSgiafIkscEsNxFBbLP?=
 =?us-ascii?Q?INWtzo2JaFtaUgctWVYqI6iYk+SxwgbOX5AaHxPnPPhPoVHu/B5RDjiT5YOL?=
 =?us-ascii?Q?zUxgGobteb3UaKgcALSykiiNmbBkYvH5J3tvKnFdqpMdA97FzTP+Y5EUM2Ls?=
 =?us-ascii?Q?2Tb/X3UDyp2QiNyuGxzOEGePgfQfPAPxJr3zbPg4/i4TU4RL637jsKYZ6UsN?=
 =?us-ascii?Q?urDzcq0R7aUsEk+qtNghBKggQxCJqtq10mqTROKyDcDJF2/ryxYsQ98GINNH?=
 =?us-ascii?Q?Xua5Gm8QSfyq8KBGOxhvMSKUfRgj/AaEQAuO8zuIFlPJMGz8AUdgsOh55BHa?=
 =?us-ascii?Q?1I8JkjNpdwBoh24SmV+KbpnXMq9ZElz0vRMFxyy/1Fyg8EN3ukpSOlRE2eoC?=
 =?us-ascii?Q?kIE3v72eZji9incj9PMCIxxRpB4BA9TZjHdquoJYH/IgB78hiHH3U8MATVru?=
 =?us-ascii?Q?+cRzfP3TGCtbXwkXsNtgCOZL7Z02KjertN4sPCNGRecLhe72tDU8U2TP9ZzN?=
 =?us-ascii?Q?kA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6/WQb1HsLAcQ5u9LvJK5kNV2WEqmyw6hgNk9ifPM9Xpm0k3vltLMfrlk2hc2/nw/MhzYyTWTSgAy6rmVuwRxQzLy1u9rR0XbDcVQ5KfX8aZ6l3ShxOi6d+7E/tI+nqtkOrXBs9/KUQMCDFpmroIRAQyAiseJg4FkrMuiOB+DgyV5SUvCoLA+VEsME93sr3pkKSmJrbufnKZmzGFMj0Ve5qu8eJ7hCap4TmLicn9hT8nClAK7R5nOaDuytXu/RCk8nORDRFSrAleMkhFpaqVty/eXCqJVedtX7cwJhvzMlEgzch265AS2d+uaw+irqq2W9bduTLbaTdncgE1qq9ULXaqu/yS8N+LH2BdL2H5X8+5krJFadFNAQ32DiiygHk2sa46NvYDFU4kWr8zBXvOmhf9FqS8tQhVTEyJ+zn7fyZXppwZ5NWHqCOFh/KawEj7TKat+T0VGZCJimJzgJ3r4vJ1XnjrW5yq1I+sW7ieWux8jkyWE7/pPTQu4lWtTYXn2F1fZktoiYrlz495MFozJvwikuRXr0nnjiprSXdbgai+be4S60mt5JFV7GIpDX88plx7gPAQ12Z92VaCVgA/S71nX7DYHvSijydl+uf56HfM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 37d96410-d7d4-4133-e190-08de0fd1d887
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:11:48.9201
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: BTRI5Xln7wnyfuqlUQkuiBdBarY0/68mvks3HB5z1yzF9aISlpDG7WxC49OjhZrS9DTJA+c5D+kbUYuNaEY3GRT5ZX4ng2HNllKDbkYGTDM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxlogscore=999
 phishscore=0 bulkscore=0 mlxscore=0 adultscore=0 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMyBTYWx0ZWRfX6yi8QIpH/Fha
 ZM7FlxkVEYTxltAEweQt2JzJd0GRF96iqS/j3qIzhOKcvt5Q41rvi17pFUE5jlJmbjeXvlceYwL
 mLaofHzdod9JQPJH+1+SQeN5JKpLh07gyUEFpCWPQxbg8Zq2/gYuT7Dj180ifVYlXS09XGFW1v0
 wZsvC5YZ1ajYsXqaFAEQbZ4rTtSK8uXoOBdbRQCpllivcr1xFgyvQSe0U109bSxTCkTRXeBQ34w
 FtPjfToWmX7wbb2OQxtWcV748ByKOIy0u7xYp3nhQ21aroq5knVMNZ3lipVR+RSVg4/I2AgGvZt
 23pvCNeZmmao4scr4yHqpJx+95JZlMoupBgqWCG3ewizyPDasCE9lBMPlb5Aqt6bhSttmxmd1TW
 1EqMPl8kTLq3HoO1zkbRQJbF3VKPvRIQ2M8UPvOLhEa30+TY85c=
X-Proofpoint-GUID: za3lK1AYrWhC2lIkKwQhch-rg92pwCG3
X-Authority-Analysis: v=2.4 cv=KoZAGGWN c=1 sm=1 tr=0 ts=68f6270a b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=Ikd4Dj_1AAAA:8 a=kVp6y68UWkg0hX7IE8kA:9 cc=ntf awl=host:13624
X-Proofpoint-ORIG-GUID: za3lK1AYrWhC2lIkKwQhch-rg92pwCG3
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=JnvxmEKd;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=m3KS06Tc;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

It is relatively trivial to update this code to use the f_op->mmap_prepare
hook in favour of the deprecated f_op->mmap hook, so do so.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: David Hildenbrand <david@redhat.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Reviewed-by: Pedro Falcato <pfalcato@suse.de>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7c9e82cdddf8b573ea3edb8cdb697363e3ccb5d7.1760959442.git.lorenzo.stoakes%40oracle.com.
