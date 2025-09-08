Return-Path: <kasan-dev+bncBCN77QHK3UIBBYHO7PCQMGQEUZLZ5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id BF3C5B49385
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:33:53 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-807802c9c85sf1169991885a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:33:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757345632; cv=pass;
        d=google.com; s=arc-20240605;
        b=hFY7g2MUgDmGlJEP4PVPo+1YSiJRjiKLqbf0iraLY8xwAyOFyViIDcoQvyXLVanuJC
         zJ9K/CeY08D5oguyl2r4Ag5YQkbVsrdtv04EiidiJP7KgsyiYuR6CrH+dgK4nvOSz+EI
         YmO0WQCaNhZb6TceIBlvgf9tlTIPxvuct4FlFL9NwKYouFqZXNimksu8V7pFjuWGzzSG
         P4r3PxOpkOw4rIWhRcoBRSrHy4EnBiLf6DNGmdEbESw6jBN5zC0YVM8VVLZJsA0Vg2K6
         DsE6i0ZTMlozsUlImwlTV92NDfnNqngQyEPEbqL/DuTRSHQhs+lQQK75VDvXOgFbHa+6
         vb2g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ZHJRWwYAl15xCeF1fdMHz/s4SUMqqQ76yKEsZqoCHdA=;
        fh=p2MpYgwhPx5NFywb/gPyVAz3rJjh5aAcWDWpPDOgld8=;
        b=jtB2zvY0czyGJX44CC9Awwfc7U/kcEMVB1htTgSw+fIg+81QQC22hADQEklWKLWsOt
         8sl1VLG7HugbthVc0LD83SQe6jzkxR+2b9fqhmv9KJkTKHMFf0H6XNf8vV6E+r6zcWxt
         wnRt7vw+Q55z1+EbdhIBnuMc0QiJYta9kw7ZppgV7ki8gDQbmsrMM6qmRYDkTMrD+k2a
         tj5ESlbMXtSs91hzpEp5PgjjS/ucrbC+hddjH5FberLRoQ2TEZ+vMkkN7VLmbHnvj0/Z
         KrElGvRmCS8wRS3aCkmZX70GYYK0g0SsksnHwdI69NaVLLs5jQwzeNLi0rc6lxdS2frX
         1uIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Et3lA6Eh;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::62b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757345632; x=1757950432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZHJRWwYAl15xCeF1fdMHz/s4SUMqqQ76yKEsZqoCHdA=;
        b=XjWFMSAWFoURSA2c1PslIue6FXCj2TkWoEwXir7RGkCvJbBch47tFMi9Mq1xbxMz4j
         93NFAv7XtEVAXAXzZutx2mp7BHlJfVJObjVQ4aROftE9i/bKWtV1aE3v0QX3NbUz41H2
         xIQmd+/rP/faSxnpdIRiQi9q7SKaZ87fO/qH0zzx5RdQHGzJACBrkqmvMfthgV6ix06n
         DxCOTru2JGdfspLitc6QlMdYAuZTO8PrwHrsw33mvT0Jdl/BOL/xX1++GkM31oi5yDSU
         quCCSpm+Oht8i/Nvbvd0ByfBsvij7TdJhwpJPu9ypVDSQU3TiARHGFtJjdAIUjx+0E5L
         Cblw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757345632; x=1757950432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZHJRWwYAl15xCeF1fdMHz/s4SUMqqQ76yKEsZqoCHdA=;
        b=CXIrn14liAWxgQnYZ1VKMYLLQhRCgpGzz1Wzbts64R8df+QhXi7dsD3JcdDr8jHAQm
         eIe+HjScly4VVGxtjM03Wt5Ds7mV7eCPu2txIo/A+M/cyTlutdwpgEPi6P2F1ZeJTDi0
         7YL86yz5xsETz0z8SYx+PKQd9kIsZfUV+y5e4Z1sPevGpTIFvnJhB2gY3fl1I3dGANRn
         UAxco77qUiu1yOCG3bpw5Xe5DYX0dWFldx8XH8icbyNdhm2h24wLn0/GB/r1c3tvYO1+
         ifd31cpFkrcL0UY88KfPcycQBofutXg+/z1Hy8YA7R2sBoYKNz6HW2bHM7G75k0Bxgts
         Gu8g==
X-Forwarded-Encrypted: i=3; AJvYcCX3Bp1yYt9fvkAanjFfqa2UmqhsjroN4DSkjqwx3kpZJpkCkkM7fRviI8q++zWe746dMKsMhQ==@lfdr.de
X-Gm-Message-State: AOJu0YwB8d4ieDB6g6NxXExuhkdxu6ZZwqRDUVzfbQ8w3gibOdX4iu/R
	eUnqO9O2PpoYjpYlEzxtu3IOX6QyplCR9PGKb871FTIfODl8jCMP/R7Y
X-Google-Smtp-Source: AGHT+IEv0G39aiKQ6E/h8aMRvNdTXrAlkk+eVL45jjuxJpyJW000lCAUnS1q9p4rHuww/Q/k9yUPYg==
X-Received: by 2002:a05:620a:4006:b0:806:522a:25b6 with SMTP id af79cd13be357-813c0d0e1e9mr812376885a.27.1757345632502;
        Mon, 08 Sep 2025 08:33:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcZLsLyuE8+MpZjC748IS5+V2ZY1UkdLFqOakpakrhJLw==
Received: by 2002:a05:622a:242:b0:4b0:9c1e:fca1 with SMTP id
 d75a77b69052e-4b5ea7f763cls54357601cf.0.-pod-prod-01-us; Mon, 08 Sep 2025
 08:33:51 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUFtDhO0B6QI2Z7idXvABaQodpvchMcptetmUfr88cJxVpw7NvKPgLRa1Jy0RTD1Q6oJNlfzwD4LlU=@googlegroups.com
X-Received: by 2002:a05:622a:41:b0:4b2:8ac4:ef53 with SMTP id d75a77b69052e-4b5f84905bemr89029961cf.74.1757345631446;
        Mon, 08 Sep 2025 08:33:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757345631; cv=pass;
        d=google.com; s=arc-20240605;
        b=fnXfijocHf4FnF7cQEy1bDIP8WuV8NAnUaw9Y1INlsEe0HTLo7b1+l/vzvb3OKVLQP
         G0GDMYCwiUcfThOWI8bNMh0w8+WLdSZrZtkys5R2/pz2hTuHBMDzvEzA+J1kjlXbCErU
         Txg07OYPrGTOOOJjy/OmJspPFxLg7IbaIJg0qU7K24Y17a1DZGBNwqwLMiGpDMKO2a+0
         vwReUK8Kt0QFSSV8v14Q3Dam2bfh66CMoYrCxMctAFN9xbDmb/v95/oJm/qq6l1SvdNb
         PLaZXlPlETqpRb1H6hCJl0osX3IEi/oZl65YA3W66wgWldHLvmFoFL3PpkiMblvyLyc5
         zh+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Cl8F1qd2eBFExcsp+ZyEpNuRqUubzW5u4nbEAXt8sPM=;
        fh=+Wf9C59iNuYdLsCy0PbL6tF9O0tQ90PuA3pAFIiYL+Q=;
        b=GEidl9ZWKiVY2YCFlmcP+oqv4+LHTG7QnYfoec1Qta4o/kG50GykSmeT5JLlN/7E/Z
         S1lHzpb4h3sr3bWVyVKXXCOZZGTMie20r9zg5sT3mkocokH/xN0NWI2LQ0YINES0clCV
         bxm1vZX1o3Yi4ghiaFKnY2oFzotVIoHQXM/Uyh+Vg9R5hQiyf8c9FHUVLieyRmXoXCHD
         jw7mUhnc5UXrYGDjyakuMgMee5BLus370IkEYBZet1KhWFt/L+XJIUZuK6tVMIJMbMUW
         I9Ori6iO0d5NEwWumsAs2w9dZYfCQUI7Ygm7m+0hJ4DYdR5LL6UH0x8QAiELBDNVH0Lt
         xWHg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Et3lA6Eh;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::62b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on2062b.outbound.protection.outlook.com. [2a01:111:f403:2412::62b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa9e926e9si56524085a.5.2025.09.08.08.33.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:33:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::62b as permitted sender) client-ip=2a01:111:f403:2412::62b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wvGqU+BlIi6TgiOfXrZA5qvBdkOrGjc+tEuk04zdBm6nBG18ws7Vk6ktUzD4pEk41s+wTcOE3LnF4jtXaagCFqARU1/hsexW+mXxqfCcCvPqaW7Y+9MARQzKnYJzQ8RTAyZwmy/7g6xvOB0opgnYhqStScEif4lfbj2zKZvO7g8fbH7/L07C3YePVfenhj08VPS7tDvBbKumKXt4z1zQ74xJ5oXsJfhIR1V9lUKqr1wV+IN5CPNfcBFU7t7gnr/A6eB2aAJcvx9YKx5P1EvIaMM7aUOgxLyfo8UcpgWA/Hw/TOpVU61RvAqtCil5ikPS6lGlgme5Kb8whm6jKTansA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Cl8F1qd2eBFExcsp+ZyEpNuRqUubzW5u4nbEAXt8sPM=;
 b=IALElEGBCngR87plE1ERFwvhGhqhx6x51tLSYuKqbzVBCl+5g2XZn/6pZgf0963zZW82KMgRLBRzLjsKGgZMEi8d9OexP0HZpNg++c2jhZN7jeAaFdfF4my9ahS31Mt6OFcwk/F3Md9qEgQFSNflH2EkpllR83tXp0q+wGY7IRNE2+13J6eGf9BChW6XR9dBT286vuNf5KIo1RIc7z/aQgqIgQhxpr4RThBIpo0n7KtRiB+1SFoT9VyJ+xbQhHEFyso/Y8tMb2uVb+kMUXRbFQ/pkwY9x4OdJokx69NsJY2ZEv0ClUCWKC8vLherNZ0DwAbeAemX/6XsJti2z5yzjA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from BL1PR12MB5753.namprd12.prod.outlook.com (2603:10b6:208:390::15)
 by DS0PR12MB9037.namprd12.prod.outlook.com (2603:10b6:8:f1::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 15:33:45 +0000
Received: from BL1PR12MB5753.namprd12.prod.outlook.com
 ([fe80::81e6:908a:a59b:87e2]) by BL1PR12MB5753.namprd12.prod.outlook.com
 ([fe80::81e6:908a:a59b:87e2%6]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 15:33:45 +0000
Date: Mon, 8 Sep 2025 12:33:42 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dan Williams <dan.j.williams@intel.com>,
	Vishal Verma <vishal.l.verma@intel.com>,
	Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>,
	Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
	Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
	Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
	Reinette Chatre <reinette.chatre@intel.com>,
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <20250908153342.GA789684@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <20250908151637.GM616306@nvidia.com>
 <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8edb13fc-e58d-4480-8c94-c321da0f4d8e@redhat.com>
X-ClientProxiedBy: YT3PR01CA0142.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:83::24) To BL1PR12MB5753.namprd12.prod.outlook.com
 (2603:10b6:208:390::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL1PR12MB5753:EE_|DS0PR12MB9037:EE_
X-MS-Office365-Filtering-Correlation-Id: 62293ab1-18b2-4527-71e4-08ddeeed1846
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?OfexwaZ1qAXecR/I9MLGdg+4q3gY2zPAE7wUIBRgqoVULJIOAJdVY8yZjeM+?=
 =?us-ascii?Q?jyrER12D3LiUfbmGsRezeWFo06VZG+uCEdBegdcrFDsUxkS7N0C2gUBXadIw?=
 =?us-ascii?Q?FOnRnNaTph6Ygk5sFDh9Kqmc/hzSTTea8+918uwfYznUZZ5sHjGOnjkJLYV3?=
 =?us-ascii?Q?D7XDYE2hV+FXdal/j84uVw1ApcWHVIz4x2pP1p8Q4AEEw860HmGK/H4u4RHM?=
 =?us-ascii?Q?AvOQkl61kadumqVLe8nClFL3Mnj+UE3e5T+taODMixBLuwpUhB1c1QK2+YsD?=
 =?us-ascii?Q?JB/abcEQnAjJVY+gCZFgMHjYj37X+NG18UzY+4XX0XdX71KcB/NIt32eQNMw?=
 =?us-ascii?Q?3fCjo0xHzriCSYq0lYd9h8BamGLM/tSN3onTW0PxkiCpiBH8eo3Wm7DlxTMZ?=
 =?us-ascii?Q?CbVbDOfOrO5U8HH4zJeIzlPClmQMJLhvlFCbGtaTiSkav3gMSeS1k9AQ0PHZ?=
 =?us-ascii?Q?mSNUSWrR0UAmhVPJOg0onuMHlscG9X5sl7//sG7t6DEdSS4UKQU+Lzf15F7X?=
 =?us-ascii?Q?8o6OoZFc5exe+tv/dlOdb4dNaVRVEb+uOEeQw1gazyHwbk4A8OELrIeYxqYb?=
 =?us-ascii?Q?C3y7le/+QeTWCEzCD2msSVBrcXK8Jajv4bBAHeTykQmJmjVtuXmoDlOWcraK?=
 =?us-ascii?Q?DPE8fTnH8S4jQ5kZ/WqiyNfGuIuRonaAJA+N7dRVDfTA/MiZGaY5PQa61ySZ?=
 =?us-ascii?Q?P13eTuPjGhdiiUpR5vwet73M5zBD79KPNlbqTNuU1FP1/zIGQFc8a5c+qHcO?=
 =?us-ascii?Q?K1NbgHbi1B4SEwhKxTPZNMrV9czp1+BS6gJg9mpWsXoATuOH0ppRwAGAwcs+?=
 =?us-ascii?Q?/g0XgzDZdk8cHszF+jFLFv8u7MSYsWvmf8X0gIehj5/UxjFJMeoHEfsMyqR7?=
 =?us-ascii?Q?fjoKl1XqHrW3cQCIh1JJ/SjO33s5XxrMGfVNFXbJvefYdgAOvoMgizIQTwbv?=
 =?us-ascii?Q?yIFaW+/y0luabjAU5dzdgT4rndx8/DA+MEJTCFX2A70Z5vSqRMIQXzqWwsGl?=
 =?us-ascii?Q?/3nbp8eQQ9MbsCrpmUlt3Moq0j8Lp10o0OPnIEcmNkmNzMWT4DbAgoBpGIJJ?=
 =?us-ascii?Q?OO8OFY1zfLe+voh5cBUYnC2EITxj9DN+W32i9GL04CDh9aCFbrAlGL4Em2da?=
 =?us-ascii?Q?ByBcHKVsgvoeMIn+BwqiWArZwomllVXQZ60PA7rbc71oL33GAKUXJVElLQxx?=
 =?us-ascii?Q?KTExEgybB94AhbXfkExbTKvrTj5/0Y3fZIv/oMzR6VMS9vyNlUSNLRcCqvA6?=
 =?us-ascii?Q?pADpHHN+04pwULc7dGjGI8yLZVSxDNTsikprHE2MKjpw/eNqqRvYx8Kn3re+?=
 =?us-ascii?Q?8Qp260pkoOSAqzFhqzapbAnEYE2l8gZCiGDpOlwLkNh6GDvgcq+DUVKhVrcN?=
 =?us-ascii?Q?43iwktF0Di8pKMuxhrpjDds9ruST7YJKYo36dxo3KTYw5M4+16bMDQFQgP6X?=
 =?us-ascii?Q?s9QFP+fm9XU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL1PR12MB5753.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?NWYPb0XDGZP9lV/DXB4iYGnO5mF72swH0ERSUad4Do8YqCu/hcDyn7OY6JNf?=
 =?us-ascii?Q?6gEAQmDowMY/HDpKuvEFLxhRIFWbDDSsFlmn/HAHjSqMd3E0IfiWfAWQN9yC?=
 =?us-ascii?Q?CMN57SnFTFoM1mCtvMJk09S0MV4fho1EgML4X88DvvysExcb/YTUBrBHR5wr?=
 =?us-ascii?Q?3Uk9+mBEtqpodHZzUxXjIhKFOiaC0xZsQoOxq6XfB6dIJBqQ5Jem8BZslr98?=
 =?us-ascii?Q?YkwnNWeBtlEUc6tOYjyKIZEgKixneimM/7WjGd3BF1AE4aGzx1NhQabBsKSH?=
 =?us-ascii?Q?9zmLSM33X5mj0wspSEjqoW7ZSCtm+KcGR7f8mvFj6ACArXctZCFHlHhBQeoh?=
 =?us-ascii?Q?3krknZ15OKhxYQLotsZIIDVENbmauzrrF3R6Wj0oyD32CwiwhBxZdxTcDeYW?=
 =?us-ascii?Q?y97glatPlqS7ndsHKC8Sa1L0XlLekVahLX9YboPesWQ303KDHqtWSOWaWO00?=
 =?us-ascii?Q?xBOkcPVdXiGrd3E7eHRcLvGjzSLZukuEvwLE6zkQEcQ3GyFdr+0Vmjq8HwYO?=
 =?us-ascii?Q?KqZisxViIjiBLrASS+sTGTBJQGS54KdjkppGQEBWgEf+77kRSkA296hmOZUR?=
 =?us-ascii?Q?uZuNhpErA+8wxE5bwv1eTVVIrGQUkXgDVsz5f5NDwIDEYhqqPkU4UgWxaNiq?=
 =?us-ascii?Q?xvpyyTGo+VUXJKmaBkjxi/pYh8butaPuC0YvLD1pX1QgBr3GDWsapgyRV+1n?=
 =?us-ascii?Q?Ls0/rI/GxPJT/xidBA2ZfaQnSHGNSEoH7+vO3v8ve89PeXRzhg+Lsywk7iN1?=
 =?us-ascii?Q?wqRmcH2FNctSvXhOS19HEYMK47uNooG0UmC5r1XdZ9KsoT8fU8ONkOmQtGfA?=
 =?us-ascii?Q?wHSo0mHRh8y11oCnbTqTJ+VD5roayv40Rh6AMMd0pXMFJwZIW8moMaidbqTO?=
 =?us-ascii?Q?I8Ft/Cj1Hq2zG4k0yW2P3bFXctXcB1swqwyyH2wTqN6ZxJyaywk/BlBZGLYT?=
 =?us-ascii?Q?Q1NVme2eovr91f3zaJOH9SWX2bBJKcuwft982p7JCtmzVDGA9wsOO4adx0Hh?=
 =?us-ascii?Q?Liz4hDFUnjZuwWEwzwZD0MukqeJI6WZEYnrSpz6UdT5gXy0U15XmVWW4TB8x?=
 =?us-ascii?Q?f8yhnMoJ27Ed9Px64RK9pyehnXXjtxUGPq5qArUj/czhAl8MBzvFXojwSdlg?=
 =?us-ascii?Q?xVViCk1Yco3OeTST/ude6F7jXaOiLXjFn7UpKSo42UoGvKD49EhFCs4BXuDk?=
 =?us-ascii?Q?jhX0o0Jwu4NqybM6HKJENAZGiEXOBhfaYcDFvbjJ/kdIJSgx+kT+MZgWKk94?=
 =?us-ascii?Q?TbfjMDIhIlJE3DRFWs4Ae+p94ZCjjv3BFMCGUFHYQjl4a+h7p9mUyUly++/4?=
 =?us-ascii?Q?ZfKqZ7duFQHPitp4OHDsRW2YupmSYGqgLcE2tJ/iT/wZlbNc2LNM0Iq8hJPQ?=
 =?us-ascii?Q?DVtro54lMO0mRNnuC9dU97AU1yxkKTdXr/ASYx4MmHHrEnXxn+5p0AGfeO+n?=
 =?us-ascii?Q?sm4JJD2PNPXxu081S1KLgKUSRb/qAUS3hpTQ5zJp1HYojUdoD8TmyCPW7/6D?=
 =?us-ascii?Q?VetFcj7CVUkoySXFF4dSeQIyT0ybif5TMOVms9EGZ+g9E8sLpzWNqM4af0jf?=
 =?us-ascii?Q?HHeBEckKoI7EOAvRG1w=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 62293ab1-18b2-4527-71e4-08ddeeed1846
X-MS-Exchange-CrossTenant-AuthSource: BL1PR12MB5753.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:33:44.7583
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: A/yAki0ZFGGvcHRFOXm2BAGkF8f5EtB04iNvaJOcWQD16qm11k1FiOzD1sppt2QH
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR12MB9037
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Et3lA6Eh;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2412::62b as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Mon, Sep 08, 2025 at 05:24:23PM +0200, David Hildenbrand wrote:
> > 
> > > I think we need to be cautious of scope here :) I don't want to
> > > accidentally break things this way.
> > 
> > IMHO it is worth doing when you get into more driver places it is far
> > more obvious why the VM_SHARED is being checked.
> > 
> > > OK I think a sensible way forward - How about I add desc_is_cowable() or
> > > vma_desc_cowable() and only set this if I'm confident it's correct?
> > 
> > I'm thinking to call it vma_desc_never_cowable() as that is much much
> > clear what the purpose is.
> 
> Secretmem wants no private mappings. So we should check exactly that, not
> whether we might have a cow mapping.

secretmem is checking shared for a different reason than many other places..

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908153342.GA789684%40nvidia.com.
