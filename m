Return-Path: <kasan-dev+bncBD6LBUWO5UMBBUPT7LCQMGQEWDTRDCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 6428FB48B28
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:11:15 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b60dd9634dsf24919901cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:11:15 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329874; cv=pass;
        d=google.com; s=arc-20240605;
        b=L6TWR6/W5Xjx94BZjAkothyPUopMffjCHCp8aBN7f3BqvHVyKNlzQ+0vao0r06DVL9
         bW5c/YEosL41RfroIOVW79m3HDDEey+8LLP9p7jyftHC9sIBOqa3A1zfyisTKLjM53dG
         6gwKXF8BgQa/a83FOlemFGk2J9w7U4I6dgGwMyOZIgMmNv+0HQsHA2uh8Oud8oCpZQoF
         Mf36gLdd5dit5ecGH4Tgj5hVaB/fJMc0cBcSNEFbpt7Img9lBAIniQblLWLJj60e0NJV
         1gKRjJ7wfXv3OoeDWDKfhVN3d0B04iz6L39azAwLjEns32/JTXBVvUxVkU1gZfweKTd6
         BPPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=M1UOyOetwFaH/AXsAB89gvqwG0dULmIeuXL0tUTDYxU=;
        fh=IojAqyCERMy4kSB1lnkg6tMQRQoFlY6JLlGrllOnhjc=;
        b=Z5AfmAfMPpmc/KnH0mgmU92o2+ST+ccx3GsyBZk1R76jaXND1xbs7qyU6I2Py1wrWS
         dl5uWnTfq4cXUyTFqPY3Q2TcUlswCOrYNtVPEae48J1jFuQY3eHu145C2lozO7kEYdZQ
         3sMJyTG3zjt6eJVBW37gTnoJoRScJyQka7b5p//g4HPpKfvD2da9qzRDA/UIKPnZ00wf
         twys2pNQM78FlRkvKnxrrsfUW3TRixrzpL7FV7KO8nAr1H53i4VEsQxawcHpVBBYQYj1
         4SqXl/Nz4IPa7JHcltEgnKac0RDIe+yqOFX4qNEqaQ+t4I9y8V76ATHk1Mu1lsj7pSi6
         2FvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=eSyQIy2Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="DQQi/FUJ";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329874; x=1757934674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M1UOyOetwFaH/AXsAB89gvqwG0dULmIeuXL0tUTDYxU=;
        b=q425rzf4C/tNbjzsYXJpKxeddkR+CoYuFL69VAFbjgvnrkwCeFRjB3kyJpmOJn4xrj
         j25pcxxIIxxU/gbvaIX9UeABpvv1i7Q2soVaGWtLO4p9H9ZEpN7wu6Wpk9bNMJF4uwxS
         ob+swvVx5vrd2HFxgqE57t0SQyaHklu4zhqKrseHi46ffVSBw4HKy1NrjSuTOuE5yPgx
         +2KZ3es7mBag68DptGRiZIxdOJPqH0bAeJ9FSAKiyYy6QuP4eS5AdYezSr5IlUD+qXCh
         mmOzBAVcnQd9ip53otIxh2vk/FPYatYVBkL9YUD0qjHlbvl6KcKevTrKwQDwV0OxIS8K
         zV4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329874; x=1757934674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M1UOyOetwFaH/AXsAB89gvqwG0dULmIeuXL0tUTDYxU=;
        b=BUSzinkjXFxwL0+lYOxuPVAfwKaZ70kC20A3Bq+jLfk6XQS+u7HI1gzCXaNH2qME0W
         OjLxUHx9juJYpQqt+wWtpwThGMZdqEOgW0gAzU7Hy4n6ewZOtzcyxrriVlFC3JbkmAek
         dVw97ApW9QU3cjH1HHoAOtWG58lf+BL3r1ejuDs9ovokky2M2jYgLUxsUOljNOO1YwZ2
         ZZHV6Vn4Y9dCRo74chbMvNYJlHzc72X3Sj7ccNXElzwqesFjNXyELLSXG5y+GIDREGGD
         n304883OSkQAIly+jNUwsa+z90lWsextkNBngCUJT8kvjHJbwvEGsI4IUiuZm1SQkjBu
         70Ag==
X-Forwarded-Encrypted: i=3; AJvYcCXwFcgSL0lsdSPHD6+Yh9QRyiIlqaNcemTWbfMmvh8wKjGnAxLCZblbvkVLQzPtaVvt2sWEyg==@lfdr.de
X-Gm-Message-State: AOJu0YwZ9RXSTrNoHBI1zwpwYTjNzhbEB4VhRIijPSKFw3H8bKF0WiRT
	zQUBUD/7bcxV0PHCT+x46U1fOTGXSspnEQSbNlw07qZe/C3733B8UWqS
X-Google-Smtp-Source: AGHT+IHuiwvFtxnrFz2nAx8v1g1aYk0nAG6spfpPrdxERlbdW/bam+rYUv61g3lNFD0AXPtIKsoJQQ==
X-Received: by 2002:ac8:58cb:0:b0:4b5:de27:ccec with SMTP id d75a77b69052e-4b5f83b7b31mr86684521cf.19.1757329873522;
        Mon, 08 Sep 2025 04:11:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcncn7nnDHcK4Lvx/nd5VlfMDqtX/2o8loco9jkKlp1dQ==
Received: by 2002:a05:622a:242:b0:4b0:9c1e:fca1 with SMTP id
 d75a77b69052e-4b5ea7f763cls48202081cf.0.-pod-prod-01-us; Mon, 08 Sep 2025
 04:11:12 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU7MjKF2fTBMTi/bDCvdVXdtTOrI/rFtE8zvkkvo3XqCqmfXF3B7uIFJIfQiPetIBEP88luCJDtAp8=@googlegroups.com
X-Received: by 2002:a05:620a:3191:b0:7e2:43d1:1cfb with SMTP id af79cd13be357-813c39a0e3fmr733873685a.47.1757329872635;
        Mon, 08 Sep 2025 04:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329872; cv=pass;
        d=google.com; s=arc-20240605;
        b=FMWnrwsqk0q2Pkih9mXLQhw3xmBNsxkLEcVaVjt6aBmXxibo8LCDL60w553tcU1JLc
         3e1jNuglhaxTbIfbEjWtz/UTf2ARuWbni59iK42FjIqfWT5lxReONtP472lkGa4Mii21
         Nq8626pZUCVskqB0z9YGlowks3N2maJrhW5skm/KteV/KWR4LjjIKnzCigcBgCKGY3iA
         WSgMumnNwOMjNQWGsvz9O8n6xF1Htmm5x/dMtV14eTz5P0IXJZ0CclYyBtpCTMb7qFbE
         urO2YZyo9R91ChHIvxsIiOzP8jfWlfRp2WHPiwFQdUmbi93a12f8eOZyWVlwwJn0p4Ak
         MNCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=EWb6AFsZtXP/CoF5V/0efsXWpLqky8tkue6pBkjyArU=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=ZwdD89RqNn+3W8+L+FlSlwMfsYL1eT9/Bru5n6U8eBfUVJUUtUi5Vf3tiKT6Rnde+b
         OxeISaT2vb5QWzLpW88vEb2iBEMnvPOVtsjNtgXNrAOE5pTwcl4mmnaNDaEfFmAVSMDO
         oVcSa/YSDFURg35QdDieAn7YqUAL9ivublNH0HGfCVR1jh9vk9J6bok1oGcj63dm5Ru5
         N0nfmqFB7Yyw28MpQtxKNBfbRNFjymITlQhSj0CnhnBmoIR8cj5iOT+C9zXb3q5UkB7w
         aoedJQpHOux7jHHLnmpjqM+lQj3RYPEVjqOPalPo9OoCM7zuFTqrY/w97eNx0MnAPgGA
         j1Ow==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=eSyQIy2Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="DQQi/FUJ";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720ab9bff06si151406d6.2.2025.09.08.04.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:11:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588B9FGN007849;
	Mon, 8 Sep 2025 11:11:01 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491x16g028-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:00 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58896Ias025964;
	Mon, 8 Sep 2025 11:11:00 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12on2073.outbound.protection.outlook.com [40.107.237.73])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bd81muw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:00 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=VQNKZaiLuwXKRWUb7wMSG3bTzcyVxbg/pm9f+eBlM6vPciSmhxHm4p2WyMJ/og0q6Ew0hzJImA6YMxZ7KxUhD7GHIHS/30upM/R+ZfTVlUeaX59N/rjwGeZp/e2XglVsCEG+JxGszuljO6EjPjPhE0aLgabFkoInzBkE3aSXhmghYppIcNg+eG4hZE6a4l4EzmTnnXtQYcceDN+W6FrKU3qatEenYLHr5FY5prb6EnX2VkMS0nRPIXulpI3m4Q6IDv24BKEOI0Y0D9a6QVFDgAK5AmD3lEo8ROo88VoCObRP31nYrPECbWFz46KpWL9ycVG2NLqIAA4Psfkp1wYrtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=EWb6AFsZtXP/CoF5V/0efsXWpLqky8tkue6pBkjyArU=;
 b=KLOPYuLP3XVIUW8qsU4SdOkRYZ1mBd7YkrErGCCBCUy2B7w7aqNu7MSU0u3L5tsav8nqKvvgX+3JTa8OfmnUik72GJjg1cPHUFOVrGpkKsbxkbn01jRXqnWcUiokot8bVe6qFysdTFNNSqjIUsyqUn4M8md/C8TJv1paYfrwiESC5wBfb/ZNUNxsl27inWy9CKua6lRIL3JKzcFchd1d2HhIIAVDzRiLocHHmbg3WcDuqHOH2Ct9jQWgPJm9j5y3wCRe6nnobsJ2F5RGeCDX513bTapkOADgW/0xwqCPy6sZr9IZeuZOR0x28xBYI50oaKaVLTBfOleG4AYug9X4MA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS7PR10MB7155.namprd10.prod.outlook.com (2603:10b6:8:e0::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:10:56 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:10:56 +0000
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
Subject: [PATCH 00/16] expand mmap_prepare functionality, port more users
Date: Mon,  8 Sep 2025 12:10:31 +0100
Message-ID: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV2PEPF0000383E.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:144:1:0:5:0:13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS7PR10MB7155:EE_
X-MS-Office365-Filtering-Correlation-Id: d07ee87a-3f8d-472b-a40b-08ddeec861d1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?R8Iam1nXMBXXR2jWc8mol32ZeV9TKuQqJfAv46HuhQFzJBK2bPfh9oX6j+9d?=
 =?us-ascii?Q?kYQsmep3PmW9f+cNhjodcqPE+3SLM39/t5mWHDimnsLKEFfW+MNfZHTbI9vp?=
 =?us-ascii?Q?o7frHrotifIzrKXUzAM6fSV8dWcYL7ER8gy25/LfCaKu17QZTSH57Al20CdP?=
 =?us-ascii?Q?eanMJFn/y8HUpECHE4TRNSSv3KbTfBdVt09ZMwJR0biLBgPN6ZY6hnmhB+RV?=
 =?us-ascii?Q?2Sy1Y74aselbqMJ5VPecBlo104TVKub9JX4lZP6s7Kj20qbdSw7E/vdXbukR?=
 =?us-ascii?Q?5Dd3O8U34R8pH4VBzlOhWsBfigdA3nL6D5wBLrJfBjn7NQfOD3qqELGTZJqY?=
 =?us-ascii?Q?rgz5hwoh7jWLfvI4ZVH8I9bHF6H4aLADNE3ytidDKIaOESYJUcBSLq2RXLvB?=
 =?us-ascii?Q?LzIVf2IQ/qGDTEqGyD0vyrHffdCveOuXSFf1w7R5bjc1u98jK8xB38EuntTf?=
 =?us-ascii?Q?5AxmpJ9/G/RKy/v5BlDmKH+TbI2ZqLxtknrRuwvQPt9ZkfGTdY5KqGRyHWiE?=
 =?us-ascii?Q?EfFhUSE4yYbMvXD9qJ4/14dbk51PC8Sst2zTIwB57WjsLk5rs8ALEImlYHkE?=
 =?us-ascii?Q?op7fkad8U4hLvjHQGF3Hfnr2YR2w9CvVPQelnGT3cqWkfXsVR2b3Iq3VejOa?=
 =?us-ascii?Q?2EXMGTnWEzmv3xhcNwIe2wnH20HPqTgH1ZoUaniRZv+YiqKGAN4lUGrA4ZDE?=
 =?us-ascii?Q?/ISms0VlKPdTEuco+lKVkBxFdhRVLWLfAhc8Xm80z7uWpcDMyqkXjrAFkZNS?=
 =?us-ascii?Q?pvJ2HIE/T6nN76mjtuMFtObxsQjhSjg75xEtp/ODOs1Bj8YqrkQPeRp4uQXv?=
 =?us-ascii?Q?i6/kCV2xoSqSIYSyamilbxb74MAKBlaiIuka1YvqTSC//wJn6LokTBDSxDjj?=
 =?us-ascii?Q?H3R3CUt+L++bGhjbE3FWl5c25Jq6mmbFDmm+N0MNxnfGgOSg2kP5FE0+X20R?=
 =?us-ascii?Q?2p0yMZ50ggblDovhkczqeSDJCK7FOFOicrNA6/f4kz/WLjx//tqVhMHNnbNp?=
 =?us-ascii?Q?C23uTGCHSDhKxBJSK4vQiN7oPMCrIazsF8ONXnkqtUlzeYxbaqNdP6njqEh5?=
 =?us-ascii?Q?FDO1zxVKZJcIzQjcE9jX1LHl0gXmgz3UeDgDzuWvuL49RN40+IChDgz6tMPF?=
 =?us-ascii?Q?8/gfoEcTgM5omRmrA5PwdLlGfxvFAWcAEBLQPLSo8a/y8PPJXQYsmNPHiFlU?=
 =?us-ascii?Q?akSq4T6dWJkEs77XBKMqt9gAPI59JThaFN8fd/fZbrqZcc/KEP7yHRYN3b1i?=
 =?us-ascii?Q?8Bl/z+wZa7wki7dLzwY2SEXxMA48qE1n6eL7Klysn3EgMu3xh27M9u38Lp7k?=
 =?us-ascii?Q?ZcIg92VeFgWKa8vwAVN6mk+o9Jqd0+utSSDpnIthmon3QJAhBXWm7XSUjHQP?=
 =?us-ascii?Q?Zxeyo/h/IIrflBu9LNaox3c4/MJwFCb/O9WLCXzTwJB/ouf0NSF7Vsf6X+HB?=
 =?us-ascii?Q?WyGNbSVxEkg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uYPp4RuKjHQ86KZK49xvu0rMBfGKumeSN6UnLIGfBiDtAkggZiljmDiho0z2?=
 =?us-ascii?Q?iYlqMmohZoJ22qmZmii5mmfO/R3w4S6T5VnZQYLzu6uHfHCaFCLC15MPnSMo?=
 =?us-ascii?Q?V/Fm9PSVeKmzCz39LJTYi+lprLN763MqQ12sUm6TLcT305vAzsgiasRamjbD?=
 =?us-ascii?Q?pYp0l5bxJ55IM3uIt96Var8oG1J9gUjrktEd/jmSm0PWW0FO6LjaLoIorOW3?=
 =?us-ascii?Q?jNYh5V2kYr7ZWg/r3Q6XP/CWkR0teevRCKiZdpnvTCN0Nrne+185kLN6WUIW?=
 =?us-ascii?Q?KtBE479iLCZdDfC8zoyFITYybv6PevJHFQW1VV7zrcYsGfCeN3R/HRFNbJyF?=
 =?us-ascii?Q?gDTpesZIa8NkVNDQBDOpsRlE5IV6aggnOGny/I2BmEiWIfn+TpcUnsG4ji4T?=
 =?us-ascii?Q?AdYWSMeWdnELyp+1xA4VorIjr/ysYAa4aWCVFbbOZVfxZD4TPMMW2pslzEP0?=
 =?us-ascii?Q?r0XIPc6hbTsheJQACqx1UiJg1axNMWvuJTZLK4UzVe1wCbT9by4LWJxxy4MC?=
 =?us-ascii?Q?VbNZeh43X4c0x/xg+synHbbyOs8JHK8Pw0sXILYri0MRTDFLWe28Y3CCnvV3?=
 =?us-ascii?Q?NH/cvtA+FK/pMtDU+zdXyv8nF/4FWSbnBHCqThiZ10DTuCJyUyC/kr92nezD?=
 =?us-ascii?Q?zmLdkGnwNSSeS382psVgMHZzMXONGcGSy0Zkd+9/5IjGTkVWeOqQo+HO8q/r?=
 =?us-ascii?Q?bxBn7NKZSvoWtq8eSyiioGP7yfotvqQDq59rZ0xd0RmrcA19IgDBuV3ILyQ7?=
 =?us-ascii?Q?Lk8XrEN+F5RQRUNMI4JLnZ/abs0sI5v3xUIw9+ey23SOouiqWvxWcwcwozWU?=
 =?us-ascii?Q?b+0Zgpf6Yi8a5jNqBKZjeHMFBeCqgITq588xSPs4ZPWEywSg1TL78VHmmdTu?=
 =?us-ascii?Q?9GBc60gXieiQedmFR6lSXWMMd3oKr8nbffMLRnEhx888Tdk+xv0p+cDwGWxf?=
 =?us-ascii?Q?A+N1N0+V3g7QfqfhdIXxz0qWbLJkr24RPVdzDwGD7VCNVgavDbcgmb6LnFYn?=
 =?us-ascii?Q?8p4TG8dW1Z2YS+8XC1uAaptW8gjH4UrTRXch8ILR5NdAnQz0r5TVUCvaoEkE?=
 =?us-ascii?Q?/pp3eySQ4mgLHe3ksxWKTdKG1jLPDa/2RFlrgSpJF/jjr3JOR9Tk+FK7GHHA?=
 =?us-ascii?Q?LGSy1hHbcPJAN2KnwxWdjr3fqBS7yca+d88Fw2jEa/wzNWVQhLIXNJjgwmIz?=
 =?us-ascii?Q?3l8CmuBBe2evJ9VyTy7sFpDYLLhJXftTHIMJCWLBoV5GFvvFpUgI7pM8XPeR?=
 =?us-ascii?Q?SGYgRU0xwnnjTmEc4FYHgm5p8PUPO9jj3UaPygMAl6dITKNAhCytgng1iHPr?=
 =?us-ascii?Q?4w+9Nbcz1lKZx3mJl0GMZZhMfML6AIID5WBQueUFrbl8qO6cTLDN/3c2Pp7N?=
 =?us-ascii?Q?Zp9oj/RaWOVFj6XjNXSOjSqgGshf5bIW2lfTtH9sadizXOgbLbaamSIalbEx?=
 =?us-ascii?Q?xISHkCi/MozEnQWLn1BIDHm866KDzKk3HF4I+RvUwVS0aIIjLvtypjvviVxe?=
 =?us-ascii?Q?PyQZXp5KgBTuimej48eMCbZoPmYm0nFUipFwtfO4NetiIVJQVtLv2KQqOHBT?=
 =?us-ascii?Q?tM/afGJEM5le/v9/dRQEIxyDih06RFOeaNftecAWsaNJoMvAddfXCr7nqVKs?=
 =?us-ascii?Q?Pg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: okc4lnHfCE/Zc452CCwwI3RvZrq4nN7qesVAtF2iNghw0ozWlh84KiS3uKHltGwWEyO8gZQBaCeQlarwS+Q7q3jZaTzqFWkheo1QZrFnZuW+EvTEoq5NoxQLDDK8EYwVCj3cOMLBIajSZKekAh4jMumuOiRWnZA0X1cvo7/+zBwGG/Ik/G/stYwC3n83AniSrvCOMTRi78MGe3NF6o0pPuzrsT72OjQVN4erDTuxazfbcSFq70juAYnYD5cSv5b7jeLj/OTNUBp+fwyyge+Ts9J5QNaYunFiXTYlaBBBdIg6jf8OPvp9zYD/CGgkYtOI/14xejzMjnK9kvxem01GuBiTgCw+K8m3PMQKso9/IY97EDrbLvFi9EXpiv2d+L/wNgk0G1wk63Lo5GnwTSjrcRUgwfV+XJX2UuMRYLZHg+WlbyRPXOmQCqdNl8Otivj9CzbYAevJQlPYZ0MNORrACF60vCRgh2JwYsiytjlad9Qj5O206iXFpigFskPcDLu8uuGGlGsQF0WLauYgWvaUrWtoGgpeAe+IV1CnEPywb9g+8eS4NxeCH/FlI0jWyoBMIPWp7QSG696dB7fS+Y2FFQImtdZ1wcF0EKFc+Y5xgQs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d07ee87a-3f8d-472b-a40b-08ddeec861d1
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:10:56.0390
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: IQ8iwPI5tBc53cM23xSpvx6NaYHzh4VFNQ8ouM/bRyp/ihQ0p/qALULEnAyTuAssZxheMCq0DTvruF/9xATQQotfYFJuRZjqQulLZKmGKJo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB7155
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Authority-Analysis: v=2.4 cv=ULPdHDfy c=1 sm=1 tr=0 ts=68beb9c4 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=K8RJmEQGKBSf3h_esIAA:9 cc=ntf awl=host:13602
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMiBTYWx0ZWRfX0dDoqpPNY8qz
 EBzKWdo1krMvIfpWSM57kEQsaHmSe91wLPob+4VwMm7Gs+cKj4ioJ1JiAlTKrzS2uK3HR5xpBDr
 uQpkDUjeqFJPKguubnwO8hkQzxFuOJdguGBFKyZoExwuj2Wl4ZraLVGcBLNffRRR6hWT90JiRm1
 CBuQciMzWRD4Vze8Ysb04KHuhrx0mDJnyWpVOSNWUqpMkhhCfUQ7aqjdC/57wgS+RXORDHKi87h
 /6qbLzfhH3rS8e73lEVDI43VOSB9+SYxiGCISYJRY6PcKvT0EGdx5knOkixvp9icOEMLwrf46ay
 I7wFpGMOU4b/8mKZeASwUrCdLMQtee0BTKRHWY0/thJClBnyv/RoNPKozk7ZgyMQr1llHB2kjgy
 rriQJv1o/rW2W7BJ6FBqGsdQf3yZDw==
X-Proofpoint-GUID: -lLm35riCO2pDnBurG9BncbC9G2SEz-d
X-Proofpoint-ORIG-GUID: -lLm35riCO2pDnBurG9BncbC9G2SEz-d
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=eSyQIy2Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="DQQi/FUJ";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
callback"), The f_op->mmap hook has been deprecated in favour of
f_op->mmap_prepare.

This was introduced in order to make it possible for us to eventually
eliminate the f_op->mmap hook which is highly problematic as it allows
drivers and filesystems raw access to a VMA which is not yet correctly
initialised.

This hook also introduces complexity for the memory mapping operation, as
we must correctly unwind what we do should an error arises.

Overall this interface being so open has caused significant problems for
us, including security issues, it is important for us to simply eliminate
this as a source of problems.

Therefore this series continues what was established by extending the
functionality further to permit more drivers and filesystems to use
mmap_prepare.

After updating some areas that can simply use mmap_prepare as-is, and
performing some housekeeping, we then introduce two new hooks:

f_op->mmap_complete - this is invoked at the point of the VMA having been
correctly inserted, though with the VMA write lock still held. mmap_prepare
must also be specified.

This expands the use of mmap_prepare to those callers which need to
prepopulate mappings, as well as any which does genuinely require access to
the VMA.

It's simple - we will let the caller access the VMA, but only once it's
established. At this point unwinding issues is simple - we just unmap the
VMA.

The VMA is also then correctly initialised at this stage so there can be no
issues arising from a not-fully initialised VMA at this point.

The other newly added hook is:

f_op->mmap_abort - this is only valid in conjunction with mmap_prepare and
mmap_complete. This is called should an error arise between mmap_prepare
and mmap_complete (not as a result of mmap_prepare but rather some other
part of the mapping logic).

This is required in case mmap_prepare wishes to establish state or locks
which need to be cleaned up on completion. If we did not provide this, then
this could not be permitted as this cleanup would otherwise not occur
should the mapping fail between the two calls.

We then add split remap_pfn_range*() functions which allow for PFN remap (a
typical mapping prepopulation operation) split between a prepare/complete
step, as well as io_mremap_pfn_range_prepare, complete for a similar
purpose.

From there we update various mm-adjacent logic to use this functionality as
a first set of changes, as well as resctl and cramfs filesystems to round
off the non-stacked filesystem instances.


REVIEWER NOTE:
~~~~~~~~~~~~~~

I considered putting the complete, abort callbacks in vm_ops, however this
won't work because then we would be unable to adjust helpers like
generic_file_mmap_prepare() (which provides vm_ops) to provide the correct
complete, abort callbacks.

Conceptually it also makes more sense to have these in f_op as they are
one-off operations performed at mmap time to establish the VMA, rather than
a property of the VMA itself.

Lorenzo Stoakes (16):
  mm/shmem: update shmem to use mmap_prepare
  device/dax: update devdax to use mmap_prepare
  mm: add vma_desc_size(), vma_desc_pages() helpers
  relay: update relay to use mmap_prepare
  mm/vma: rename mmap internal functions to avoid confusion
  mm: introduce the f_op->mmap_complete, mmap_abort hooks
  doc: update porting, vfs documentation for mmap_[complete, abort]
  mm: add remap_pfn_range_prepare(), remap_pfn_range_complete()
  mm: introduce io_remap_pfn_range_prepare, complete
  mm/hugetlb: update hugetlbfs to use mmap_prepare, mmap_complete
  mm: update mem char driver to use mmap_prepare, mmap_complete
  mm: update resctl to use mmap_prepare, mmap_complete, mmap_abort
  mm: update cramfs to use mmap_prepare, mmap_complete
  fs/proc: add proc_mmap_[prepare, complete] hooks for procfs
  fs/proc: update vmcore to use .proc_mmap_[prepare, complete]
  kcov: update kcov to use mmap_prepare, mmap_complete

 Documentation/filesystems/porting.rst |   9 ++
 Documentation/filesystems/vfs.rst     |  35 +++++++
 arch/csky/include/asm/pgtable.h       |   5 +
 arch/mips/alchemy/common/setup.c      |  28 +++++-
 arch/mips/include/asm/pgtable.h       |  10 ++
 arch/s390/kernel/crash_dump.c         |   6 +-
 arch/sparc/include/asm/pgtable_32.h   |  29 +++++-
 arch/sparc/include/asm/pgtable_64.h   |  29 +++++-
 drivers/char/mem.c                    |  80 ++++++++-------
 drivers/dax/device.c                  |  32 +++---
 fs/cramfs/inode.c                     | 134 ++++++++++++++++++--------
 fs/hugetlbfs/inode.c                  |  86 +++++++++--------
 fs/ntfs3/file.c                       |   2 +-
 fs/proc/inode.c                       |  13 ++-
 fs/proc/vmcore.c                      |  53 +++++++---
 fs/resctrl/pseudo_lock.c              |  56 ++++++++---
 include/linux/fs.h                    |   4 +
 include/linux/mm.h                    |  53 +++++++++-
 include/linux/mm_types.h              |   5 +
 include/linux/proc_fs.h               |   5 +
 include/linux/shmem_fs.h              |   3 +-
 include/linux/vmalloc.h               |  10 +-
 kernel/kcov.c                         |  40 +++++---
 kernel/relay.c                        |  32 +++---
 mm/memory.c                           | 128 +++++++++++++++---------
 mm/secretmem.c                        |   2 +-
 mm/shmem.c                            |  49 +++++++---
 mm/util.c                             |  18 +++-
 mm/vma.c                              |  96 +++++++++++++++---
 mm/vmalloc.c                          |  16 ++-
 tools/testing/vma/vma_internal.h      |  31 +++++-
 31 files changed, 810 insertions(+), 289 deletions(-)

--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1757329751.git.lorenzo.stoakes%40oracle.com.
