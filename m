Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJ6O3DDQMGQEWKJXCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id E55F2BF101F
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:25 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-78485b26ffdsf22445917b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962345; cv=pass;
        d=google.com; s=arc-20240605;
        b=SKRKm3VI+Jbi6VZ0MdOwB6w+gjejHDDQVVzXVTKDk2GfElXwIPDbrMN1xLc4Q8hwC6
         6jsY/YApyIaulSKYDWt4SlvmJhjT9vHIQ5NG8TvFJRiEx5VAjd/+KrvjoJNp2hSLNi7A
         CWCbt82o3Kqb5FtdrYirifqEdPXAq7o8OZ84mdnTWZNaW5sWgPY4hUHiPmGMyoJqKGFu
         kdIHbMyyIHN0QetrrjoR5y/RqEdnQn5eUkBv9XA8iSueLw7OnaUyN3Tm1icC+TcJAvQm
         suHtt/QXMIxn3jHwo+MUWX2w7Sk7Q3WL405hNUnUkG58Spsb4HhbhVd4eBvzu4imDV0B
         O/JA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fmkY96niEAxfbtd5XwBNilp0Qr+742hgj3q3myQ9nX0=;
        fh=ynAmWXjcC6JOmoiwrvrA/6m9XME5eXshYKWhW7XT6SM=;
        b=RN7NkWmA2zgco2HtviXCV9/we5PLH8YMAJAaXHAq1Z1aSsmAE2B3vH1cti3BLDfGNM
         5hJrkJGl+PsYC4iw1Im7KoSaasRC8b0D9kh9Bkgrnl1vvh7t9qvxE7lySmjFsFsq2kpY
         OtXO063C2PTWVB6S2hMUOL0iOtswDlO9nKwpMopjxyQ+FYfWwGVf0FbvR/xPuUd8vIGz
         FZIkgjX4B+KvsgY5ug5hheqAXVdZOkUkuhUBflzTg1gpITTk40OQ6vRglQiYMx8CcBhj
         keq1OYZ/0eFiZAQn1jOgK0qF/rYxfOfktrW/14T6QpN7zPCvQUSBsxncYzAIIXT4Mdph
         QcqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tl6upWuQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ytDKCpsK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962344; x=1761567144; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fmkY96niEAxfbtd5XwBNilp0Qr+742hgj3q3myQ9nX0=;
        b=a99btW/mE6wJDX4XVUdy1FFrTqulQggcSCwlYQX9hx2nmpZXorQhQsPGzmQGNspL/j
         JpbJA7/hJtJtni9a4xnIIPnOZpeXSExxCY0dcYm5M/DxyugQk30BMh1KRJmRX0OGjt31
         2qwzRD4HzFMMAurfT/Kz3BZ0gC5/xdzBcdbLyqSvVSTI7w4XRoVJJKp9/psbk3sdgX7C
         mETbzUVW8lAgGfmy0K1nLhkEpeHzu/t7OpPD7AGLnsZzHJ3qTfmqoBeVSyZ45UYkbeLv
         tElAAT3a8+sFcrW5g9rHO4o6W9nruBRzOUFaaFb8eTV9yCFVP5uqT625OqrOXb7M+wLS
         uMFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962344; x=1761567144;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fmkY96niEAxfbtd5XwBNilp0Qr+742hgj3q3myQ9nX0=;
        b=wKQccpLM1yca6ll1jJR7C8+SnYmiylyZlkilxm/pRJjUZilnZ2gHbxz4QEPKqwCMVI
         GCsQyGn1eMHAoetAn3XddUWjEpry4aY1mcXfzZDLZ6j8UkhlMTyR0spViik4t/10rPG8
         uKl1FEXcZTHaPKWz8JzgoT2BcddbR9woAVd/Z1xEQkL760eQR+CoS/8qC4jM1QpQN2tF
         a2uEdOjeaDhNIMk3so4Dek4gjhgbgP83x9QpHz0RpkKpSWjJzipR6NtdobYkLkh2nUI1
         +ysgp3QGtGpR0zO0zZA/OR5flv3VpQJ4zBq6tEpvnYglwl5yk+dsK1jPWTjYSUgVmp+d
         hQgw==
X-Forwarded-Encrypted: i=3; AJvYcCX3IpLjRPP7FNAlOtZCZWF/wYjLoh5Ai2aFPeIX3js6IWZK8j5I/uRmWPSmQrw+kd4UNX02cg==@lfdr.de
X-Gm-Message-State: AOJu0Yxwy3g0JtzLeS/nMANOG5XE07MTfVUSn8lmbt+Pyh9qMT93qOUJ
	Dlb3LBzwBKSk/J1Lt56DoGUJEfZ1QADtzBXhKYGzdL8WWHTJUG2mTDks
X-Google-Smtp-Source: AGHT+IG3xy/57yuq67kW88eHzSgS05O9PAuCGgIFxcMbE73ehjkPVgG4PhRVeL23Lk0qLEiY+OcRuA==
X-Received: by 2002:a05:690e:12cb:b0:63e:2f48:2bcb with SMTP id 956f58d0204a3-63e2f482c43mr5263075d50.62.1760962344125;
        Mon, 20 Oct 2025 05:12:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5969kneBdQ8WVMyJlZgMIVbAfYa5c6Kg7p72MPqHN02Q=="
Received: by 2002:a05:690e:23d5:b0:63d:e4d:b682 with SMTP id
 956f58d0204a3-63e0d76336dls3446391d50.2.-pod-prod-05-us; Mon, 20 Oct 2025
 05:12:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXLmtcfOgVoXiO8fdOj21cHypGTk0fOt9Q2p6iIg492W7C7OLuT0DwlUp7XmcutQ8/nSqXCusWiKCc=@googlegroups.com
X-Received: by 2002:a05:690c:700c:b0:784:8bcd:407d with SMTP id 00721157ae682-7848bcd41dcmr45093707b3.35.1760962343253;
        Mon, 20 Oct 2025 05:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962343; cv=pass;
        d=google.com; s=arc-20240605;
        b=EFBp1EjFKzQ6q5zsX1nKUbCF2Kj7v/QUNUwM8bdeSml+7t2CJ8sfufe2MvhNg81Gut
         5K4cO2IMuOHOoPWZ/cD8ZJT32DLIKFamA/yprzob/5asHg39FKkXRhHD63p+WFFSKXc2
         jtJEk0HV0j00mLm+mxCvjDltvQu2nFxTzhY/73MXgg90Z7d0/4DNtJXR9JI7hRRvfYQz
         H1Ykh8C3Qk+Q0CJAyaFLIraDorqSOabLKAwq8SVYhRVPIb8jdbvKseQTh61P4O9qunut
         NFqd+O1WWcJEUKPsM5w3GQwBNlWBTLVmT+rUEWZMeqfz9p9imx+nzmE22YNSdim3ogyp
         RhOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=hkRcJW/M+dm4jZPhiYSCwFh0exw6KGwB9L8LT71tBDc=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=B6tvtSQqXBx8wlTgzD2BNKNs2QxtGMh0eWF7LJJEdQMUlqyuok59LDSCdk1ouPI53k
         Ed+QCo/2KC8WZCaOTNlIDdSrtDdBS1lHHAw7GxcBLZfZIiJ0QPEpNv+5t28Ix3s2O7ni
         TB6sSUwQ+rxP0DS6sqYoEsosZNfBLUQAd0h5pn3rgkrLXJL8w1kYBGEdD3//eRGRMySR
         /EL5jRcCbV3/N3kdjUgPvBHznniTdgW1szdeiTvmtMEZDjGWvONP4dca+zHWL8Fi8Hx+
         NKrsR1Sj5YNe/a85Pd+CSoUAUxVSZlLNUewRPH+j28oQ23RQYkP+/TABwqhIED61nbp+
         qcpA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tl6upWuQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ytDKCpsK;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7846376da08si3418757b3.1.2025.10.20.05.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8RmX2005909;
	Mon, 20 Oct 2025 12:12:14 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2vvt4bc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:14 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KBVZKn013696;
	Mon, 20 Oct 2025 12:12:13 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013000.outbound.protection.outlook.com [40.93.196.0])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bam2vw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:13 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OUw3aLiCEHKDHfBlrcPhkoueV14z1AfmfTKq23giWxbucFJWws+gHqjRQERw7kVKMgtxZFjau8Ejd1vcx1jnb1HCMC2i9Jfj+6bqKOtBYeArOko1GavW9DrkSld4dKpJKTdYHLeM9rZVs3rbjWAJHAjs8jcEUo9GtXETnJ7jMMafKuwbyRB/SIr8K8T8KcRs+tC+25bxGPXlTkDx5Wc3Wdjr9rThfz/dj52V5PaEFImgBOiFvD75w7x0ZDExKIuFcQqUWGPnVe7hEeR0ZqsDezKO1OTrgOZDeRry1R14GVpxaxxV8X2B2sbEMtzYqp4XLG3RJ6jC0rapDN7q/LYmlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hkRcJW/M+dm4jZPhiYSCwFh0exw6KGwB9L8LT71tBDc=;
 b=EvX5mYvrnXsmerihstlI+WtNJvgkaf5E0LfHvr8XnzJTxyuknoF78gmfEFxIb/eWwNSzYxjdrewIAg1Gv+PqAxOGrihQol3DAb2C3TwOW7q5P5RrK/AgGCwV18yeaioZdA0pMD1nD8HHqknbC9378kUdGvYrMe/PvZ6DjKFDRETo9kcQGm6WuAS7sfZxafgPNjOIChq0Ds/BLwwBaBwRINJHR2nFUPj+zKiIhAL60ISFD6puzlHnuYhg9S+hHAylDyO6YvYeIeenAQhrGrw35kttJJPszCmo2CKuPkPCxljiwjjxsIuhyzSEYmfDhr2ScjRHqNSwqZ6BNpmI3JVriA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB6364.namprd10.prod.outlook.com (2603:10b6:806:26c::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.16; Mon, 20 Oct
 2025 12:12:09 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:12:09 +0000
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
Subject: [PATCH v5 14/15] mm: update mem char driver to use mmap_prepare
Date: Mon, 20 Oct 2025 13:11:31 +0100
Message-ID: <48f60764d7a6901819d1af778fa33b775d2e8c77.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0075.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2bd::16) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB6364:EE_
X-MS-Office365-Filtering-Correlation-Id: 0ae2b0e1-9976-4ec6-d340-08de0fd1e47b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BaT8ZtWt5cScVHR2EKv57M3wA/dMw1URiB7tQJEZ/iMgTrd6yD0MtJ2T0oNA?=
 =?us-ascii?Q?SBxfdykhsmy7P5UqbfLhgBAd4LoVSmv0anRda7PhbyAHAttZhF2AqEWXTuhi?=
 =?us-ascii?Q?a0qOyycQJGIAux61l9xgORqpWPgEB0tVDTSXQ2hIyOyR6Gs6xSKsOba0+Bkl?=
 =?us-ascii?Q?b4NhSXprn/Qip2PEeyOghTJzf6JUi+n/YDeGuPCi6k73j76Kbe6BCDAyd4bY?=
 =?us-ascii?Q?MyI28YdLHgiFhQT0QjOQ5kgIJE6Wb1WIkwiltIRkLVfBg3vo10D+LqK1QwI5?=
 =?us-ascii?Q?QTNBkFWmXXacUsLTOps4OlKwLlZBgi/K9IbGRTaHUrSsBkvb8cGZYZLyvrkH?=
 =?us-ascii?Q?lNx5CSb5Q9cV8DUsgmrxRMbRto/qR5/CImauFQrPsE1+x9hMO+RrRqZoAQEk?=
 =?us-ascii?Q?YeygsLPyj3N4Q6E9Bw8q1tG5qYqZpwi4iBHy+euYTHp0DWb4RMcUnesA29DY?=
 =?us-ascii?Q?pVdh6KfWNg1O6Mhe+e7ej1lFexrQk7xLn2GwnDCrJQDbZ3VqtfS8F1lpmS2l?=
 =?us-ascii?Q?1Gb1dcGhSVyBCIwXeLsPrjong8WdP8TD/JB77+2n92g9GfCcgFFcX4ptdR7X?=
 =?us-ascii?Q?w8oVPffWrjmSiKtW+lPcDzHrjIqARSFR4/WekU7vRGnasi1/n2dBwIXLA1zO?=
 =?us-ascii?Q?x28uCtzcjUHDYJwiOyQQdfmkR+UnFBwP60aIz0UoC+rshbx03Roy7H+lD4v1?=
 =?us-ascii?Q?oexSTeByww09p3m4Ao/REvzCgG8WBfBfoLSIdPtNZXTAB6o3MMJQitDXV6oK?=
 =?us-ascii?Q?TdjklYSoFz9BRjIYR7c7GWI7NeUMPQSK8e1itAaa27bN9lQYhXRP5t1VKqGE?=
 =?us-ascii?Q?QszXQlaeUpf3L670ScedVx81xO+vuP9Rv7vFtF8ktAP1vZ+AgG/mrpnRevdC?=
 =?us-ascii?Q?6yb4DIUjdGQQm7KxCRip0XOFWl0LvOIda3IUPNV0kfGcblU1SPZLbPOoy/wm?=
 =?us-ascii?Q?0bxPgv5ptF+I1EGrYjFY1tXhfjNFCdkp72Osj6Z6FvdFt9dh00IFeYNYO+ZC?=
 =?us-ascii?Q?Ikk0T5WZ5zKpcz0imE3J5Chw/9Vp46tV5NqyZ9o2Y94Y3a+I0mQTFsxwsPMX?=
 =?us-ascii?Q?vg5cL7BFRFgjVzvJTDCmd7NLKGc2OSTE8ahyoIbbpLFlkvVznIw9Fgl9aBLA?=
 =?us-ascii?Q?iwJ+YYQi/NfIz1hlyzafRT0wt2wd4ebbY6+GFple9+qAVOc6dbiCvirPnifK?=
 =?us-ascii?Q?4ibrS2FFiEadWNdYq/2CpF1ez92nu/3+IWa7HnKMrurRpsu3cYSp6TLGY+hi?=
 =?us-ascii?Q?WEg1d2Nz/GLSq/jC2urndDcLdHlD4UWg1q0kBGMDQ+wWBei4my6DfmA5iH0o?=
 =?us-ascii?Q?+ZxYiae8XUp4Hi2Cboyo2/gIv9qRvg/8JUyfhXBH7fhjOUuxSv5kvajvUKXI?=
 =?us-ascii?Q?UUPPS0Rg+GFz82tdrhRn2+2DX391yQEL1l+MxEJWNtcxUfKy2EloH3qglHON?=
 =?us-ascii?Q?Ll+UHMOt62cHC3dgGaRagZ5PvkVEt0OE?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?kltK42oOcyCr9kHpt/wufyp5JDGncXM2zQMkyC+GBybMya8UJep+oB94Pw/s?=
 =?us-ascii?Q?qjvtknMPmP97SltFwGKGzePh0tIlmH5/cFEbAd34iTN8DyxPiBRLooBNgKzW?=
 =?us-ascii?Q?2Q/xp1yuTDBys8SE/eakGqnpkbw3JmRy02bwUShOoQJoazqwM384pKMLZ6Hr?=
 =?us-ascii?Q?VtJ9NSAvbkVMjXXnukzNnV5GFaC5Dj/LlKeiKn0BRiJLzurX37ZFQebGbwZR?=
 =?us-ascii?Q?tH+vlKWwAFLzYe0RKjNWhy9bqHfETbtsE0Galm1QrC0clp8pt618NJnG1rwR?=
 =?us-ascii?Q?I6NITNhl7BE4nPawl8vSW76ls+vnVv7YvJicU2kGCpwYAZt1SnoGOEO3/WOz?=
 =?us-ascii?Q?qP40G1FgnA5Em2KB/xGDMrhaGdxhIICZE3bz5cZnAaiuq0jF6WF5HsrqAzeO?=
 =?us-ascii?Q?XeQKyKQhz/1mBhdK7S188jEB2N4VKs6hv10NLw/hwTgF+wBVoEOj80zAuAQv?=
 =?us-ascii?Q?9y/sGOJJip8POwgkUIiM1NNWqcKZUnrm9Cs0Uj+h2bW5DosQmmlCb9N0WHrX?=
 =?us-ascii?Q?T00FxcuAUaHk7/2TJXr46rLBd11ZTMxGGPWHb7o6bqkFEbC/fLw6ijySX3eL?=
 =?us-ascii?Q?63mfOgA2pJJ7upQtD1a9a4FiDZGgMol4AKltKlk7fHDr9x4myNjHFiYymicQ?=
 =?us-ascii?Q?xl3+aMTAV3WbUb2sPiXT+yX8mZxa7T+L3WdMW8HPCED7zHR9P8cIcpI20yHY?=
 =?us-ascii?Q?ppQo8JPMQ5k6Q78W2kUmDa2cteSDVeiQAm6Y3N/ApuPCJBWpEJY9mJLw40W8?=
 =?us-ascii?Q?I1ji5Yk3bymCko9/utFs+oeSXp61RLLCbH/dIb2HlRY0VtJxTCsnSGHvO7rI?=
 =?us-ascii?Q?aYO5AimgsglPoB6vOSzgSOTmoBUyDg4reo5Ug5sTQYVo4ZIJW+nFfZZ/bffv?=
 =?us-ascii?Q?fm5mcygmXMIR4QEmNR9MxrFjNseoXoPtQ0MvH+JiYA41xFOZWeay8j5nrE1K?=
 =?us-ascii?Q?Dy+5bMlYM7n7mnePWzaFieqVVECc1PvwPwyrR4eogeb7fe4Q8IKh2xGYzYE1?=
 =?us-ascii?Q?UTBJICjdJCRTAzN7SyYyeQt/Eo4X4CEoHTLtjPLYlczDmi6r4MB9EKmSyPbv?=
 =?us-ascii?Q?T6LXheCb7p7PE+RX46vhXdDuZBtY+5xWAwSZMv2uwTA6tOfHpsKF6r2xGuQH?=
 =?us-ascii?Q?iMAhjB/FrVD7THe5ZRXfADDKfzpYndVpSmAbGqC+5CtdfNcoPssgWL/H3sM4?=
 =?us-ascii?Q?Te/016rnXASAjrdvJhqoiKX0LMcyj2HrB6XQLIzr2y1QAT6KKi6nuiyEVTOz?=
 =?us-ascii?Q?D06ULtjy4+tRmryOc5aD3HNtzw0FzcK6bVMKBuRFomprzWe/K+azYIjaCIAo?=
 =?us-ascii?Q?xT20u/GetfjiNxlt4xHcnIHd/iT0oXALdBt5AOWqbw/935u4/bvCvXwmi0TX?=
 =?us-ascii?Q?6N8QBPFRQ/KTYLCHtG2dyicIb2U3Orod3aN4D74YQwkgRYO8QOL7FdS8FcnH?=
 =?us-ascii?Q?bs39xB/i1dTlLrXVKxMNlQzOpt9Kk9unUCT9AOg3ajINlZyDf4mEDgUqW4d4?=
 =?us-ascii?Q?rEzePK3PGv2ufFNgMap1o2RAWbMkBMmyW7ckNLnbo2lM08e8CDr/0YhhEP0O?=
 =?us-ascii?Q?r0wyIVnT39aEc/2fG3xCgdWy3SiXeCcrzAXqzb23cjLiZ/nxZIxV/9iC6IR9?=
 =?us-ascii?Q?Ag=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 0yC9KRzVoSQJ43apYJaXCuvWIacPkrRmG6nJafThA+lvRmH1OWMrJR/l/+shPbNxE37If6wSouFK19nT6v4oRAVMHxELaotm63ca7i+C1OPyBw86c/Tmo9QBWH85d28LQHakzI8eUpEvAcY4AOULVEEgtfBbsV/7eWGPBCWa7mUm7hrOM4tJgOixl0xoxaYf9aBSy5Km+hxFC7wE4bJ9oA2IntuW0z3FtaAoNyGVQoohuVkTMNJ8DXpOXBCHBitztLPfOfORkXuO4NSpYa+RYT0DtbeB/xo5/IwWxRIH8pRPeEdpgva1STh/LUjnKQiTEZpJd4aewQIpmsYHvdZPTBEtTThf/62ohzzuY1jRY7ydqildzabu8TzrqDfdo6EjcDaOOvfvYPcb/FC8rfTMoqq1BoyW7qiMZhcSWE58qAjDo7dJp6mRMeSw2SuC5e+E6Ti4hIQ8yn0IgtVPZw0ltyq0bGi3/Tnxocni1d5jNEz1Ljb6tQtJ4noER8tu3Gu4yKifP5TdN8YW4FOO9eVsVROL2G7eGKinvIy7zdkcdXIVQ4s0g4VwV1VylfXcxw741VdyEfMagBgLAf//ZMsnZ92BkPjjriLQIM8PX8rXdEY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0ae2b0e1-9976-4ec6-d340-08de0fd1e47b
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:12:08.9814
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: toXgtYSUIy5eEDHCSteL18qvRi5ZWCCHWp0piU2y5y3zKyBzO/oyest+VX6of35QhRubNBE2szdmkPw5BySDpmLSnvZO9FquDqOvvQoCa3o=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6364
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 malwarescore=0
 suspectscore=0 spamscore=0 adultscore=0 bulkscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfX/fxK+cFQZqB3
 N8MvmRIWxG9lcWH9RsSVNoMWFeifTfyDY7RtNDl1pf0AyB7EvLO19rcaiO888hJiASPDetfc1NM
 1zMtCA8VGy8COnz4sx5YWvc1zOqMnAMzhmAZxb8BXFhu1eyz7maElRxzB1wYDTFqDox5o2I17vk
 I+hx1vhmbgybFRjWfm4GLSWpbe8xoGZNB54Z7bTQP9c+l7QnkecsFP8a3fmQNyBV6+Fv6KlD8G0
 lFsMQML8Syj8SkT3deMzvpjyfdH4KQ9FftKVTeTdjH8feDl4LAFSejhqq/pO1jm0RpO1Bmgz0KW
 6kSWWL54XVizgKMzZ5Ptg27sRGtB6u9XDJzCe0Ag2IYmxdGCvTqh4BSNfMhrmrrYlcyR6ANjZd2
 HVYBZSEjj4+DIFBYCTAydA+GXRVU0Q==
X-Proofpoint-ORIG-GUID: FMPXVgvLnBq8x6JlQz5_u5TYslZA8D5A
X-Proofpoint-GUID: FMPXVgvLnBq8x6JlQz5_u5TYslZA8D5A
X-Authority-Analysis: v=2.4 cv=FuwIPmrq c=1 sm=1 tr=0 ts=68f6271e b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=Ikd4Dj_1AAAA:8
 a=x0R6ikhiTiIxgpotQrQA:9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Tl6upWuQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ytDKCpsK;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Update the mem char driver (backing /dev/mem and /dev/zero) to use
f_op->mmap_prepare hook rather than the deprecated f_op->mmap.

The /dev/zero implementation has a very unique and rather concerning
characteristic in that it converts MAP_PRIVATE mmap() mappings anonymous
when they are, in fact, not.

The new f_op->mmap_prepare() can support this, but rather than introducing
a helper function to perform this hack (and risk introducing other users),
utilise the success hook to do so.

We utilise the newly introduced shmem_zero_setup_desc() to allow for the
shared mapping case via an f_op->mmap_prepare() hook.

We also use the desc->action_error_hook to filter the remap error to
-EAGAIN to keep behaviour consistent.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
---
 drivers/char/mem.c | 84 +++++++++++++++++++++++++++-------------------
 1 file changed, 50 insertions(+), 34 deletions(-)

diff --git a/drivers/char/mem.c b/drivers/char/mem.c
index db1ca53a6d01..52039fae1594 100644
--- a/drivers/char/mem.c
+++ b/drivers/char/mem.c
@@ -304,13 +304,13 @@ static unsigned zero_mmap_capabilities(struct file *file)
 }
 
 /* can't do an in-place private mapping if there's no MMU */
-static inline int private_mapping_ok(struct vm_area_struct *vma)
+static inline int private_mapping_ok(struct vm_area_desc *desc)
 {
-	return is_nommu_shared_mapping(vma->vm_flags);
+	return is_nommu_shared_mapping(desc->vm_flags);
 }
 #else
 
-static inline int private_mapping_ok(struct vm_area_struct *vma)
+static inline int private_mapping_ok(struct vm_area_desc *desc)
 {
 	return 1;
 }
@@ -322,46 +322,49 @@ static const struct vm_operations_struct mmap_mem_ops = {
 #endif
 };
 
-static int mmap_mem(struct file *file, struct vm_area_struct *vma)
+static int mmap_filter_error(int err)
 {
-	size_t size = vma->vm_end - vma->vm_start;
-	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
+	return -EAGAIN;
+}
+
+static int mmap_mem_prepare(struct vm_area_desc *desc)
+{
+	struct file *file = desc->file;
+	const size_t size = vma_desc_size(desc);
+	const phys_addr_t offset = (phys_addr_t)desc->pgoff << PAGE_SHIFT;
 
 	/* Does it even fit in phys_addr_t? */
-	if (offset >> PAGE_SHIFT != vma->vm_pgoff)
+	if (offset >> PAGE_SHIFT != desc->pgoff)
 		return -EINVAL;
 
 	/* It's illegal to wrap around the end of the physical address space. */
 	if (offset + (phys_addr_t)size - 1 < offset)
 		return -EINVAL;
 
-	if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
+	if (!valid_mmap_phys_addr_range(desc->pgoff, size))
 		return -EINVAL;
 
-	if (!private_mapping_ok(vma))
+	if (!private_mapping_ok(desc))
 		return -ENOSYS;
 
-	if (!range_is_allowed(vma->vm_pgoff, size))
+	if (!range_is_allowed(desc->pgoff, size))
 		return -EPERM;
 
-	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
-						&vma->vm_page_prot))
+	if (!phys_mem_access_prot_allowed(file, desc->pgoff, size,
+					  &desc->page_prot))
 		return -EINVAL;
 
-	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
-						 size,
-						 vma->vm_page_prot);
+	desc->page_prot = phys_mem_access_prot(file, desc->pgoff,
+					       size,
+					       desc->page_prot);
 
-	vma->vm_ops = &mmap_mem_ops;
+	desc->vm_ops = &mmap_mem_ops;
+
+	/* Remap-pfn-range will mark the range VM_IO. */
+	mmap_action_remap_full(desc, desc->pgoff);
+	/* We filter remap errors to -EAGAIN. */
+	desc->action.error_hook = mmap_filter_error;
 
-	/* Remap-pfn-range will mark the range VM_IO */
-	if (remap_pfn_range(vma,
-			    vma->vm_start,
-			    vma->vm_pgoff,
-			    size,
-			    vma->vm_page_prot)) {
-		return -EAGAIN;
-	}
 	return 0;
 }
 
@@ -501,14 +504,26 @@ static ssize_t read_zero(struct file *file, char __user *buf,
 	return cleared;
 }
 
-static int mmap_zero(struct file *file, struct vm_area_struct *vma)
+static int mmap_zero_private_success(const struct vm_area_struct *vma)
+{
+	/*
+	 * This is a highly unique situation where we mark a MAP_PRIVATE mapping
+	 * of /dev/zero anonymous, despite it not being.
+	 */
+	vma_set_anonymous((struct vm_area_struct *)vma);
+
+	return 0;
+}
+
+static int mmap_zero_prepare(struct vm_area_desc *desc)
 {
 #ifndef CONFIG_MMU
 	return -ENOSYS;
 #endif
-	if (vma->vm_flags & VM_SHARED)
-		return shmem_zero_setup(vma);
-	vma_set_anonymous(vma);
+	if (desc->vm_flags & VM_SHARED)
+		return shmem_zero_setup_desc(desc);
+
+	desc->action.success_hook = mmap_zero_private_success;
 	return 0;
 }
 
@@ -526,10 +541,11 @@ static unsigned long get_unmapped_area_zero(struct file *file,
 {
 	if (flags & MAP_SHARED) {
 		/*
-		 * mmap_zero() will call shmem_zero_setup() to create a file,
-		 * so use shmem's get_unmapped_area in case it can be huge;
-		 * and pass NULL for file as in mmap.c's get_unmapped_area(),
-		 * so as not to confuse shmem with our handle on "/dev/zero".
+		 * mmap_zero_prepare() will call shmem_zero_setup() to create a
+		 * file, so use shmem's get_unmapped_area in case it can be
+		 * huge; and pass NULL for file as in mmap.c's
+		 * get_unmapped_area(), so as not to confuse shmem with our
+		 * handle on "/dev/zero".
 		 */
 		return shmem_get_unmapped_area(NULL, addr, len, pgoff, flags);
 	}
@@ -632,7 +648,7 @@ static const struct file_operations __maybe_unused mem_fops = {
 	.llseek		= memory_lseek,
 	.read		= read_mem,
 	.write		= write_mem,
-	.mmap		= mmap_mem,
+	.mmap_prepare	= mmap_mem_prepare,
 	.open		= open_mem,
 #ifndef CONFIG_MMU
 	.get_unmapped_area = get_unmapped_area_mem,
@@ -668,7 +684,7 @@ static const struct file_operations zero_fops = {
 	.write_iter	= write_iter_zero,
 	.splice_read	= copy_splice_read,
 	.splice_write	= splice_write_zero,
-	.mmap		= mmap_zero,
+	.mmap_prepare	= mmap_zero_prepare,
 	.get_unmapped_area = get_unmapped_area_zero,
 #ifndef CONFIG_MMU
 	.mmap_capabilities = zero_mmap_capabilities,
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/48f60764d7a6901819d1af778fa33b775d2e8c77.1760959442.git.lorenzo.stoakes%40oracle.com.
