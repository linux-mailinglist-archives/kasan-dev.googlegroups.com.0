Return-Path: <kasan-dev+bncBD6LBUWO5UMBBEOZ7PCQMGQEPMAVE3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E2DBB491FB
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 16:47:48 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-774209f46dcsf2796993b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 07:47:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757342866; cv=pass;
        d=google.com; s=arc-20240605;
        b=ccdLG8ZZtlGVCRfA9B0w3F4UKPaiv/Ft7kHUkzSUVo+5CKNg6eFTv/DNnbhRUCHx/p
         /zu7qSkeqbN/tV1sBuDv3NzkQwLmsJd2dNF0btlCzahlq/9HyzFY3vNA9sLUZIj30+5W
         1Y+Vtn7Y04buLq4jj+4UgHjJI4C2FWkSIceBOOOJrdDd76FD27WJ8IENF2oBUQzFjTKq
         fpyfh9RSDaTQxtzU8MxqychL1/7WK3FdOVLfy7FPdf12FfA/Yh1bhrz0W3dS0FvYuYXW
         ea6dYEPhoyiTikm0tSjH/gmc6d0GCYG07V8ciBnE6yo9iGNO0A7VIcnoCAweQbZpvgpN
         A0hQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=IdMmUorPM53nlv3ZOFeyNvfoWuftoz9UYJp+RGNXnS0=;
        fh=fIxPiAkOjsRVBpmkgTAAeODMTKAzBjGrUuu76a17TGE=;
        b=NeKrh8eOiDq2htZ29EOIhKFYzBtvEBLMdtq3XeyzghA7j5HIWHI45YRa+DupSzCNX0
         abLJVQYOftGw78Qm8LkkUi86ayjIX9UYiE6oQzBa/hveyCC1pRmuJCIoPtUXzyWzXRod
         c+u8feiZGRZgKT2YD1FPmIgowJYWhlPtP60Z+ycZ88fOb9+NthW72/5gsXeSIVPmsd3b
         RdhIZSdFZF3Ozj7jwiT93FwlSxP+3m4WB4ct0v9b8d20mV3d1xrc9rPXjUie/e5GJHJ1
         UQbQLawmQdCgbxQInnUBUZc0Fy4v+b1ikt+YB7YLet7CE2wdCFBejIPgCCJikjEnWIeO
         WI2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="qTGF/yNt";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=E+z8GtYj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757342866; x=1757947666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=IdMmUorPM53nlv3ZOFeyNvfoWuftoz9UYJp+RGNXnS0=;
        b=WVvrMR7lI8BZtLTsDAXng3Ggbo2JnM0terESPwlqPq+ZoL9MgTR/YyOwu3dqTd+RF/
         OA4Cm0EonPo/jSGoygc8tupaOg5MwhblSCB4Z36IU9JghO/I9VzAYi13CyZCy0oF2Pnq
         6J31RYBGMliK2nP5/8y1Vm4ZnoUu6g5OyYMjRk5DvLtjcPxTVMo3lqWieDHQpIT5CRnV
         91/5qr0Hxb5Or2XSd7mwsLTGxxHKYBunoefvgWhtdBx0W714heEu7LapSCz+vMa3JqBF
         Q+k0KE4A5jXVZm0grqd21z6Aj3iEBVoYkwuuMZDbHOkoMnclXE7V5gJpHub0GgnpObKB
         FKqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757342866; x=1757947666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IdMmUorPM53nlv3ZOFeyNvfoWuftoz9UYJp+RGNXnS0=;
        b=CgWwwVqknjCSkTshvtgvLxDUpHAo4LoD/aCZ3OlDW2MTkVxSX5In2pSxDw6hi9FjNA
         JqDyCePW1YIYwRr9lqPBkdVF2baTEAma1fppIeZAkNrwdBeZ07MeDVzqZwgWglwDDYml
         SuMzEti1r6S6rUF1L62qcvqUwNsN+QgAqHll9Pzn6hu3V3KiaUGrBeOc2kj091sakqx1
         ZiQxCFv4QqMtDNGicHnYdtbDF1SYnqNwVPmAwTSua4SzxFdbE74hefK0/PpUC9nD+t2P
         R9Z96wPSe+EqGvL3tMUdGTdzu1j8qDVq4PClJ5Fv5U/drEyFXYc6I4OeKsFLJxnB01Ca
         Y7Vw==
X-Forwarded-Encrypted: i=3; AJvYcCUM33NEX5UiKKRzH4cc1B6fIHktvq/SFpHCtv401zAIIgjTr0bv916FyjHXJZSOkO213GOyxg==@lfdr.de
X-Gm-Message-State: AOJu0YzW6ydV1+mM8HYvePb9kWJ628bhshfCbmuIN7+woYebFb5uI0SE
	pGL0dhO17rRjq8EDVAVBaTAMHQxFZpGs0BDXO8DI3SJek/kJD7060VPt
X-Google-Smtp-Source: AGHT+IGTkikxBqSJ+nvg90GtihSIt+eOhCpJVaA34OHIQGKyeRoK2IIwBrVbbWNdEJZljvhyDNgDFA==
X-Received: by 2002:a05:6a00:2d9d:b0:772:6c1a:7f18 with SMTP id d2e1a72fcca58-7742de26479mr8870785b3a.27.1757342866441;
        Mon, 08 Sep 2025 07:47:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeMS+cUgJynzg4OLoCmiEh1Zt0x6h9YGDwrZ//+EBIXiw==
Received: by 2002:a05:6a00:882:b0:772:62f1:6058 with SMTP id
 d2e1a72fcca58-7741f01e289ls3765530b3a.1.-pod-prod-01-us; Mon, 08 Sep 2025
 07:47:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVXHfJEek8DDQhxpt5b98/rY6FbAus5aY9mv0cksZKqv8S+OQmPb2QjqTMQoT2c12N6xlnY/m7peco=@googlegroups.com
X-Received: by 2002:a05:6a21:3290:b0:251:fbff:abb with SMTP id adf61e73a8af0-25345e2425dmr12108197637.49.1757342864415;
        Mon, 08 Sep 2025 07:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757342864; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQFVNRuWI8xGx9TUwuvD7oou4A00DmfdMArNwddZliCSfMHCYpW53FOBgJUeRiGBmk
         TWCmyIUaZGgHrIYfMM2Zi3Pd3I/eDwTI1n0Fiz6I+qriuAnMXKBi9znmhRGDUE1pLPJw
         7iA3jtkF3CrLC2hr+wfstrwApTs2vdW2PKe1NEk8Ln10EGd7/UKVtuIc+6fJ0PbSZ+3S
         ci4CAaeb2cCUAr/PuIH2sKN4oe95lA+wryoHKU9LQec9sHaE3hKB29FPRWgI7eOuIO3S
         Bx005G6ILKWPNm982gxPl9hc4BJsRu7S4yYiDAQGKG6a/zwgXtUU3INu2Xkb+0EUz9GH
         osqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=sl9A9tm5ODd+z5CWzzyagQFGQE1WJK61sW9fDPpxLQs=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=XBVMIE1F2RKBo+gV2SI1yZuY5gqv2X2/+BdkWT/FPZwOS6n1+xFLZ2SRggF2O1aI8o
         MQNbhk8K158StWDUujTdbhmu0rQe7kjwcX+hU7UvnRoqK4zLavNryr5H6glx0ElGCtNg
         2s3yPjQrgX+TCsbAkDkmIJRUW7wrPCgxwxP9WQ7F+MY5yJPO+GVYzaufgP8AKz3pkWTz
         mHD6Q9/O2M9H0SSW6yoQzUk4DxiOobR6745/1ILTM/j3VhbqNfqWeEBCa+VWX/m+vzRW
         crr5SaXUSo+A9C77TRooJo8HRnsqW+hUD5ZMfm8GhA9AS6p4sHpKtyKUPZPz2C1m4XHI
         hOqA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="qTGF/yNt";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=E+z8GtYj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-772436d7ef9si53916b3a.3.2025.09.08.07.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 07:47:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588Edko5003637;
	Mon, 8 Sep 2025 14:47:43 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49213p00hv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 14:47:43 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588EadH7002867;
	Mon, 8 Sep 2025 14:47:42 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2049.outbound.protection.outlook.com [40.107.223.49])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdetby8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 14:47:42 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=B3dDe4uSffKPrb0r/47ZUnNyD4Zgg3bhun0gxqzhQo1puoEXWcbo58rYLNJVaINqDlPPUIxlcFcpnzzSuuxW3pxb7YVaKyVB5llMgIVLktgTGIJug2/K9/BbDMhaSaabeNBB+y/oOhC/d8u7fjq4Zgl72LGYuJf7LoC0BXWIaGzQfH/GR0WgDHURQjNQj1HKJVMNk8TBQtNC99bomvSBblxOY5z2b1j4uqMeLxIR0ajicowxiRmszqJ6pRfPFpNBb4OdpQ6WBDriy/YZMZlsmPOWH5JRdQ+1bZg1tvqiUHcFyVoFJOsvBTXUyQSvuyItNEGgsTpdH1oQc1Yp5pwpJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sl9A9tm5ODd+z5CWzzyagQFGQE1WJK61sW9fDPpxLQs=;
 b=mhTXVf3OYhunWjm8CyDeUAmf8gFlRJQG6jvidvWVZtwYC/s8fT8EK/+Xo8j9/9zeR4Nkaz+y+Uj1pzAQv+9ApZL8lE2AC1krng09HH7UUiFydljx06EuHxEy5adJqJVKPG5RgpxK6tL0hIZgwxR6y/ibmbjO3yBPPjlZMtiLmqcoDDF69KA/xhW3Zyu4/2DFnYZz7bspSZJuc0O1no6prb36sYn6diRaTIcQLJrtfkoNp0d2ihPpPsF4jnLXh81OLZqJX+GLvIYef3oy+zbx4+aKl4poLz4x83YaZVOICG00p8CpOcJ6St8YyP010YmLlnfQXQhQnvgMx6MBpDN4HA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by BN0PR10MB5110.namprd10.prod.outlook.com (2603:10b6:408:114::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 14:47:36 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Mon, 8 Sep 2025
 14:47:36 +0000
Date: Mon, 8 Sep 2025 15:47:34 +0100
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908142011.GK616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0524.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:2c5::9) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|BN0PR10MB5110:EE_
X-MS-Office365-Filtering-Correlation-Id: e8d39c06-98fb-43d2-14df-08ddeee6a6b7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?EySgw0jRAQCcKEBRLKB3Jqz018O6120cPWWRk+WYFP4KHnN04AFua3KnKxJe?=
 =?us-ascii?Q?YSz24Ttsor71bZL6zsC5DBYMCKL6vV5fAnoGNiGGRU2Y+82nvuGq6j61T34j?=
 =?us-ascii?Q?UA5aYbi8fnGv62MWA+pV7OCIi2947ZjWRF5SFqAYlSwaafxKFdDkHr9inGKk?=
 =?us-ascii?Q?hTr78hPWXRRQzNWq49PlZfPBpZzf/oB/9VSog7Wnwg9zMi5a73xvg9Jlf3wC?=
 =?us-ascii?Q?KeryIxlK3XIB8uSjlkdOzKQDO6M0yK+LeJE2MSBTr4VyKs+pNlXurknxinlS?=
 =?us-ascii?Q?gwKYW93ZmyTcywdzz1otmP+ET8lUOAHgznDTRuf/lvnhejztUSau4DsToma0?=
 =?us-ascii?Q?cEI2l5Ac9XqZ7QvvgFFH6dYS1fMYxHw5Ca6L1DovYMXPSl6wwv2YsN7+kEkx?=
 =?us-ascii?Q?kdhZHlptxCWMUBKHbeUdPybp5bmmv/eNWBzdyHUxdiNAAzmgXfcU3Wk+HECs?=
 =?us-ascii?Q?yqaHbo6fO0tfQrfTsxSKJM/HLbsX0uCwC2oDbHvNybVSUbh8a4cvYzt2/c68?=
 =?us-ascii?Q?D7Y1oD32ivcUjZRiBAr7jHRgOfR2WGrTwYbvPPII7bbK/BDy6uxTolk5NLQA?=
 =?us-ascii?Q?rzquBI0YFcX/Enx1m/pFSmHwB8eDN8fq/xXwgXzPikwIWD9+vT/fUhkWzIeS?=
 =?us-ascii?Q?5PvkGPExYISxeqBkW1xpUS+H0F6rfzcwhGOdsi9ug0ngQuJTRQz3sRgoVtHv?=
 =?us-ascii?Q?pfl42Yi1aDU3/eAAQEf7ZuXiCBxLQHEv/FHfeGNhc5czZCrBXyTc4mWLxFqI?=
 =?us-ascii?Q?EeKeNbUY/0bY5e4ZHqdKDKhgbcCONdaLxWT1guCYyJSnlHEwDDQVodzbYe5M?=
 =?us-ascii?Q?5FdHjQnRsex4GAgSHSgA+7lMcBtIUhvzVzBhAumpoZL2cC3bnje2C0GEl7o7?=
 =?us-ascii?Q?CwqgnsdpPsYnuTHyAht8fYUz4enjPhTQUUcCBtsDmfcS6SGVlQz2+uAZr4do?=
 =?us-ascii?Q?rfCrLrGzrFAB5GAnQtkDmWUlJd3RPIiAlDrACpsMC/pDm6wj8YLCrmtOKyVb?=
 =?us-ascii?Q?1aR4NM1/L2Nps/+xwjkoLpogbYJTY1+vkxyMxkna9ckChJ0j/bWJCDlqt9U6?=
 =?us-ascii?Q?hAwyO7OlmvnkuJNblo8GgKqY5lDndKfFbH3V2GX2/YyWE3JEHSJEV0l8IgnE?=
 =?us-ascii?Q?6/Iyq7eOQWvvGGQlwNly3F3EStru+RZJICHKy1kK+WQUDbSLh/BlagAW9zbw?=
 =?us-ascii?Q?ymXNsiodNiF9QKdasapWlXTWqq+jYmIxiVwPMj0aCyiBrGueGRccxw9IFaar?=
 =?us-ascii?Q?7rUbTfRKhHH3YMaWD3sqJOOH1Bj2etsp1u8qFKEi/XwA7aJ9c8APBrbKw0a3?=
 =?us-ascii?Q?M+22cUrA/uKnUTQ2+xjtGyAhhJgTAU3jL12Byv+/EJxy+1/X/LYManN0RJHg?=
 =?us-ascii?Q?MuAX3MUAU6ikPHVeo3aLqw3mOa8OCd7O4tLXwPvstoeZBXZAvg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?JNxi5SvGu5HcsisG7Q+nqaiFCsK8egXvk2fvNJWX0ySp+pR0785o6NnFK5KS?=
 =?us-ascii?Q?EePptfF4Hq2Xjp7JKR/w1uuPVnD9MKFAxyrwYvn3y9wOTjQ72j5NlTZ/SjPM?=
 =?us-ascii?Q?AuG2X0ksbDveEzx0evJeE13nhGmpusEo+f0RZhxAihBd0IfOOgaeq7ARyeYA?=
 =?us-ascii?Q?pM4p8LVI5myWyeswlU0Tp06dKR1gfMQbPC1yd0Dfq6/A6qR6BT057aT/1P1A?=
 =?us-ascii?Q?iFsaOkoWW1RMK+ea5fjg8kD+u3SEZKsXtql2Kq94EhHMD3zFaC3fRRz4hLEC?=
 =?us-ascii?Q?iIPU+/v8icuNCfvl4HN5ZssypzecSmbO8rJss/hyDDWtGFqiJHmU5hwp6f6l?=
 =?us-ascii?Q?HA2NFfRxnzjbQ0VN0uXIfiQqmRPVVS/+m1so8Q92yb2KegTnVyHY82wVz/e3?=
 =?us-ascii?Q?oaTq1X8pOYrWiPfFPmuvUT78r+v71wP4rQxkfZzYwoK62UVmVUYSc7k4CXUU?=
 =?us-ascii?Q?ciiTohY2l4O2RhOW+yLNMj8wIyyH83J+QcOm9OWIvO0p09PquJNkiCeA14xl?=
 =?us-ascii?Q?SkPGxk8SVzVj/AUNlpQB3sVUTSGFFCtnbbwR/Sxxb+7wyLSB3mqBCB9/Z/Qw?=
 =?us-ascii?Q?6jU4pivo272FxD66TkcQYMwJcH05ikeLKU8x/SyR6K3upWjgTpznEDbFGi0d?=
 =?us-ascii?Q?QZKxPimFthhF1kPAfKpy0lfntpJH/9//vDRusZOtm81BOgvllg9GBMywAjT3?=
 =?us-ascii?Q?S0vDyqN7lLVygjNohC+SkVejUoqx6hffKrJ68pqRnV8U4flCVPoe03lx3Kqq?=
 =?us-ascii?Q?mHr54Y7RIgemaU8lHccCpDeepsKUxttbTNhY+PSSRnhY2j6MPgMM5zB8+R9P?=
 =?us-ascii?Q?25ahG/ujVfszZNZQLxNBoegcF0fM1iHpg520xfm9br6absPNXHtZJS7Je75t?=
 =?us-ascii?Q?7MltipafvlJp5LAPxTFO73tRQfvuz2LPrIYcNVkkSTAhK4x2sAgEk1zH7Ieu?=
 =?us-ascii?Q?R9efwzYSoSACtA5d5SsAGpqUbByVjihDox0USCuUa5zKZA1Sj0i7wynZ3EaD?=
 =?us-ascii?Q?w5ljvTEFtSfCNQea7SZBPGvBH9zMkPoFaxWc+rfvm0Z89F8uSXiUYA2s+KYw?=
 =?us-ascii?Q?vtf9W0alXygcUqK0dyHdOVG7t5Jcr54lzUPvRSISChdPRgv377mFQnBnvOWJ?=
 =?us-ascii?Q?M6FcsdtXVf9fdvN+0DPZetmZYGE5snGn+L0GN7Gw9Wzl51MGB8mKp6Zli6Ao?=
 =?us-ascii?Q?25baiwZy4MY4L8X9t+CsIIL3Bhl7QeNmweJJBhVIiWGNunvEvV3c/QMnffdH?=
 =?us-ascii?Q?Hvpa5hwzMzLk+FveAjHSVYOwMX8emzSAQQC8qTZWC0Gk7OytRpO9tdsN7hp1?=
 =?us-ascii?Q?lB6YGEkpT+vFr8KfiP0vXv6lT5HD07qb5rRx7VeZv7Qp1y1kUvEnYYlOrrqy?=
 =?us-ascii?Q?yUbFP/WOLsC6LJaYsu70fB1uaR60hUNo9sOcyl09Hgpu2aCEUNs16GudzEaA?=
 =?us-ascii?Q?+nJNeqjQ+YB1J/gt4ZkcvLYEfHKAXNZ1WcAI/EXVuYB8osQaf4UM40vg2g2I?=
 =?us-ascii?Q?W932J3QfJej1YA2QklfHTHX9QrngVlJELWczPgr8TnWuxNMDXGxiVHwKa9gX?=
 =?us-ascii?Q?PtE7WentOQzh3/GvAqLWlTMLlcgjrxkUG8FMtIl4LpnId7HXJvGV8MDUfsTP?=
 =?us-ascii?Q?6g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: LCtTVFhxOstQHexVk6m3mK+9c15uQo9dI8V4I6EWz7g9gQCNpmp14oA9QmX0dMIsYw3lYQgH7DsNKwQTrN9FByymu/u6VgCkFTEqyxAHnYl8ZvKqPu6ipo78hm1oLC6EhEQtm1dZluizZ5NMn59vg2weBaAYzfVUqTVPkfWSV3x74wNUkmt9yG5mN3x3+D3ivMKe1+b9hHSjEs9P1i8D5uPLkWJu77ZvjqY0XsOaI7oMLqcSu4u4Ij0kYOaXbTCI/KoGmDDCm4YLvglvdXbj6mYNu7dl10u+EKVDZCaSLTJReewNFnWtUwwFXqZ8VDAz6t38e7Aqy+3uBi8LYGa7oWITEpUqsqA1cG5z7XDrqdCIX1JsW1us9hM0HDrwqTOkYGMRD9MzWJTuebBmZo4di61y1V/qhSKNJ0g4yZA+7eQgPXk+qmOxWMFhR99o90gR9Emi41CXGTMAJgN+IhNcs+QIOl8orgYVnVmqq90ZHeSbhzzRrt8NuxAFBi+Qdkh1R8X2wA+GDKIu3XV9CYaLWyRtC7c4cXgLh23cZM843XkpMfWbgSysq9DJFIrjHb8+n/HhZgsd4NQLvt6jD06bAxt9S17jTM/Kh9HkkWeMSKc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e8d39c06-98fb-43d2-14df-08ddeee6a6b7
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 14:47:36.8444
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DoT1Y3dZDsE9ZGlYbQl8Q5oLjRyD7g2PKbymUn3VySFAx3VbljEIZgCJq8Tf+g70bV4n+BCZzTjIzEBcEpRdv7/CSt9F9qrKDaoXzsoqIh8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN0PR10MB5110
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_05,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=839 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080148
X-Proofpoint-GUID: 0V3blIjfhZEcAWOOGcpilVgUc5nNuPp_
X-Proofpoint-ORIG-GUID: 0V3blIjfhZEcAWOOGcpilVgUc5nNuPp_
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE0NyBTYWx0ZWRfX7Gfggdll0t9h
 wUPJXB4MgLwnOcVQj0x/apUPDtQI0TLuAof2J2Xqw6F6IRkHNh4SaU53JXHY6ilFpjAgXWLknHp
 7kkmptNajlBmzSlcEDZsZ3ePE8FikV55KfQxiHHrE4qFGds2s5xfMtERabZ9Y2MeJ73+07BKIib
 lXbV4DmoGP46WRr+rnBmHlGnfy0jr7tm8hucaNF7UYO2P3uIfQC1FJytPKV7H+SicikiQaGLTdK
 kYQHLN5wg4G5g9g9JS8YVxKqNnpBpzUa9Y+H8nS13YyKpxMdENlNXZoJNIMEsvzWNuFrRdpWgvC
 hOnLZTTbzI075/CGZY8kLY58OGq3z01ERwKVCXMfwfk8ny6RCRNgovPxQ5BGz8clCCB0cWylkAo
 1sovSl1qBQzNr6EMj9iy8C9Vb9fckw==
X-Authority-Analysis: v=2.4 cv=F4xXdrhN c=1 sm=1 tr=0 ts=68beec8f b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=gYB-7KtPnNzojsEmhjwA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="qTGF/yNt";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=E+z8GtYj;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
> > > Perhaps
> > >
> > > !vma_desc_cowable()
> > >
> > > Is what many drivers are really trying to assert.
> >
> > Well no, because:
> >
> > static inline bool is_cow_mapping(vm_flags_t flags)
> > {
> > 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
> > }
> >
> > Read-only means !CoW.
>
> What drivers want when they check SHARED is to prevent COW. It is COW
> that causes problems for whatever the driver is doing, so calling the
> helper cowable and making the test actually right for is a good thing.
>
> COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
> something that is COW in future.

But you can't do that if !VM_MAYWRITE.

I mean probably the driver's just wrong and should use is_cow_mapping() tbh.

>
> Drivers have commonly various things with VM_SHARED to establish !COW,
> but if that isn't actually right then lets fix it to be clear and
> correct.

I think we need to be cautious of scope here :) I don't want to accidentally
break things this way.

OK I think a sensible way forward - How about I add desc_is_cowable() or
vma_desc_cowable() and only set this if I'm confident it's correct?

That way I can achieve both aims at once.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/764d413a-43a3-4be2-99c4-616cd8cd3998%40lucifer.local.
