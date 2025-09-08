Return-Path: <kasan-dev+bncBCN77QHK3UIBBY7G7PCQMGQET3YM5FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B8D7EB492C7
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:16:52 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-718cb6230afsf103693906d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:16:52 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757344611; cv=pass;
        d=google.com; s=arc-20240605;
        b=iybmMLgOmuiGuPuyNoz7v0mneM06lA/pxdltTGMVEOE35s37TF4+qPI0NMJH7N68S2
         rr8xOs3CiHc0bPr6Sn7lk1I2Xjv3s5Bv5uv00/MVZZvJ8V+fNrgJAlSBbiO1BO0hUp0N
         IudiLYCDH8tqZXV2N8bcR82KB/rRF1D40ZOl7vnEqQRC4C1HF63LH67OdfIXeQHzQbTp
         YgRF7MoEzOR4qN+29htlEn2ElkMH9LZALbavYSMBbD0V3k/2BGsFCrX6OTv+Ub2/JcgA
         WrFgoqD6aLwgJTt7Rf+AVttaUNYqhgm/szLKIGSVVARaJcAxXpSVy/RCyQSYZR7eGMhh
         GQwg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Ab0QZBL2BRX47Zw1/RuorVYgUino4qBkfah1oM8QTY8=;
        fh=4xRDlHOaKkVJOTi+aDDt7oA82FhKYLSVi1BzmlEFm3Y=;
        b=lunIDvTPC+FMyJEEHPIz/e7Jedj03VFjmTNHXNS2UgsFu69caeZxEtVAVrY9xKd4SQ
         EiSuFPEjM5YD7EcwYlxWPP49I0dNZdFNYFxcoPut6ZIcHtoEBIiVlVytI2UIRA9JtL3I
         803OjixzQdX4D0HtBnP0IzF77NiLIV0uJ3xgn0zfsCppyO4BCn8I8BWI0b/33UOf7vnO
         4tK9eabDIDgcWg9zZpOYzFzuMKPNMTH6vjLNhtZ2UMldPocumm9p28xS8InFtuVc3yaf
         xuSV1QNrEg/iS0vy49TxEr38ORg6dPLoIKoBThqW0hcehbo/ofkwGbgwmGEh3XAmC6WY
         Wn4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Npo5um5t;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344611; x=1757949411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Ab0QZBL2BRX47Zw1/RuorVYgUino4qBkfah1oM8QTY8=;
        b=vBZ+oD+qlg3sLjarqUedfoPBGvPc19TqHlPRCpF3740TV5Cm9st373SOx4UhmtYaYF
         qh8BSFDKyOJpCNFP0/7zKGdX5b/sLc75ee2sNsoCBojynycNUJa+DO4rr/63CjzzHleM
         NmhxVjWsUlncFZcXZUuSsGWJm/DFoZMZJfAJUeKRH7pQCjkB1KHuWOL9Lt3Y07nVC+0L
         zzliruJQusW9ZR05NCrh/dvb6qnbXseGa8zj6Il8xpE/TFS0KGmIwmc8aec2z/e5x6rc
         ZHHaBkSC11uNjHDpLBgdqz75x1/NLfI/fqVeGMo3ttVb9iLkrkw0G+Yk22InH2hgCx+L
         PrYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344611; x=1757949411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ab0QZBL2BRX47Zw1/RuorVYgUino4qBkfah1oM8QTY8=;
        b=h0cILL2/IioMzoaDnwzc8mj/Tsn3UWnO7knf7Nf0O7l+hrNur6d6MFBu4IuTJcqrEX
         03da2Urjof/D38OKlFAUvL1v3CVundpnx0CUkAvfewHwof9ngaqhsxW8mR74cyTU8ktg
         VRk0dOoRN6ebnw2a9ynuavuv6yCOL0P8noJU3qSLqlZCJsE1mJCosJuY/7tyRVyAawy3
         oz9XP3clyzhFcVfAVdnTIi6MByVrRVkPZPqXtSUXtJik3gxfc7xsTMyHuNcmfnNMvg40
         WmzPhLwWe0XTBSDMz3WIfsfY/dbqgFL0wDPRUy7aaY6PcmToSMtBiH3G9W3noDRpbPM2
         odYg==
X-Forwarded-Encrypted: i=3; AJvYcCXVMe5PJv18/5IZNK2WRoytwgytg+FIDBKxye/4vl/G9VzlrOywrm4aEYW64yobzcHCqx5ilg==@lfdr.de
X-Gm-Message-State: AOJu0Yzyeo6BNWfwRMdl7espXK1/JQbhGTp4DprRHLT2eMwlYnK84uDP
	H90+bfk7DQjNq55XbMlPtiR7qk5vYgeo5q78WDUIGqt+qIdgYfJoFBk5
X-Google-Smtp-Source: AGHT+IEn2CqwRBHVAAP2zpjn9P33lPutVs/hDGoiPuVx4m+MLK4pdByaznqpNIjS69CzWLGsGupQNA==
X-Received: by 2002:ad4:5b8d:0:b0:70f:a42b:1b65 with SMTP id 6a1803df08f44-73943d7d1dfmr95074416d6.66.1757344611352;
        Mon, 08 Sep 2025 08:16:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7sM5Ht6biiCUDcxpsIQJRPITAxP1g8DPbfTjcILi/5WA==
Received: by 2002:a05:6214:ac8:b0:70d:9fb7:756b with SMTP id
 6a1803df08f44-72d3c4076c0ls55430106d6.2.-pod-prod-03-us; Mon, 08 Sep 2025
 08:16:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWi64Fwcz6yf60AFMtdwpTTbotYfwHW8NOVQmX5pR9IH//OP6n59t49wWzsuWvzzTQjnIXgTIIcT5M=@googlegroups.com
X-Received: by 2002:a05:620a:400e:b0:80b:139f:f61a with SMTP id af79cd13be357-813becfe9e4mr894356285a.23.1757344610394;
        Mon, 08 Sep 2025 08:16:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344610; cv=pass;
        d=google.com; s=arc-20240605;
        b=H+4htIwNvPlCVHJVko2UOLSGAu55FLtoiWvznaHvUi5aPH+nwTVB8DitDGmg7J2VJa
         RG54Fyf2S1qSaHnU6OSM2bdvTg0Gl0+G9ZABKGvxDXRc7WOwP2MFAbC43x9x6KIxLCPk
         wDyGupic81tZgvzZHNeaI8iCHazKL1NwJXVk6QBau1/JKacqeQIxJ+SaAnWKtzMs/U0s
         frpSwQIu7NZ98i9Fh1K6YqdWNP8Wijb5NL/GLWnzWjSeMEj+YZIEfYV5Etf/Pyrc3i4k
         yX2URVlXPKWeesG4NgNVz0N7sFDDvgyqCEz2RtlKghT37vf2qpl4olS+Cn4zTmHuN0N1
         Jv3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8j/RtS/D+IIx33VOOVem8cps3PsrXPIFRtoMeCJ3Q9w=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=fggu5uEua6qPwMZN3zkFXrzf2DfZcnFwyB2Mc1GDPGY+04iP263eNlx1813w4hW0G1
         Hrzcxks91VV9rC2qrhvg2W3VBIhzTtr1SrP4uWxyrgiJHEwh3kgcdvstlRZT8XD7VK88
         YOPg49bCxGR8HR/vqV8Zf0M0mc/atAVRIVjk4AQQOvLydL8ZoW6TRHISZdW8B/6zGBo7
         CPH+Ur/lQ/0BPfJTMRXFvwB1B9SGu1qh38sJchyGDGxhtRK2DfCPzPzXJWF6UIvWBfZl
         1pgbhFxe+UYAvErOlwmWvJxD77qKa8mVON5X9Gy/Wtb8bC4nJy2mRPfr5oXQd9DhSghz
         fy1g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Npo5um5t;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (mail-co1nam11on20612.outbound.protection.outlook.com. [2a01:111:f403:2416::612])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-816b6edd4fbsi16962885a.7.2025.09.08.08.16.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:16:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2416::612 as permitted sender) client-ip=2a01:111:f403:2416::612;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=evDaJW2LZB0GdQBs6qDQ6zy5mLkGsKnGa9EHmoFBDNsBlUPKSy66+k/dQ53CFiTF3v1rhCu7DiASId9cGWA6f5FUiFYfI5QqcGaz45HvMiRsZ9mthC15U42dGgZiih4keozSOEyb27ml/1JBSpsEMS8JZhugRYtwCDKnarVRRbsBX9jZNYwfeiCtxLAjm8/AsWAK3JZb1xLGKOd5pb9gpEf5hpPyASTruEw5+aVtwiz1SvEQcFFrwgLvM+oQsBb/FB5Jo266YofpPXQWsrJ1y0ENznfbyH7tfL6+Tq91Xhb9V5ljy5REt46zOy2jIy5TKBCrAu/BpVhVuoVz+XystA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8j/RtS/D+IIx33VOOVem8cps3PsrXPIFRtoMeCJ3Q9w=;
 b=nqneYLwtfD4Xa9GqBrIalAVls8ucEuseXMwKLAd76wg5mT3RMdfbASlb9ib/d3AyWlxe6PdNQr+nBM4q+crd5q8JKtHpcJEOoxi9DqPJNpuuhwGSi38mwFzIjRH0NuvBN0+RK3UFx2t3u5AsXVahvduiQW1BGSxLro+an4zG1KBXqxf1c1ebjUAm42lRUCK7NxHTy8QBnRTOQmSQkRt2DYvFkPBq4k7IRns2TToEhcdatFArHjLh9t/pBmRy/dhiuTHQLXaUEOtLMJlYLyn40pOfFhQSSpRt2ardLie5o2OZBx0ROmpgFqxX6r6cXImgFucAXuwUcbpmD6HJVtPg/g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CY5PR12MB6647.namprd12.prod.outlook.com (2603:10b6:930:40::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 15:16:40 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 15:16:40 +0000
Date: Mon, 8 Sep 2025 12:16:37 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
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
	David Hildenbrand <david@redhat.com>,
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
Message-ID: <20250908151637.GM616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
X-ClientProxiedBy: YT4PR01CA0426.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10b::10) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CY5PR12MB6647:EE_
X-MS-Office365-Filtering-Correlation-Id: 22e1bdf9-7d13-47c6-08d6-08ddeeeab608
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?GEfq8SK3CQoWgLi4/E0h7epeMmhnzKB+QTpQo3eRU3bCNz1YWdn54d1egOKQ?=
 =?us-ascii?Q?ouQxI7idFPmgB73D4qSmfeoBUsM1OAzRY8AtAOJSuw7EFVACU82/8CWfYpyO?=
 =?us-ascii?Q?oJsZQRx/1AGgDxfUJNYln3ikVNZIT+EQzK0U11RkOoQvJt8dHxzTUoDY2oLO?=
 =?us-ascii?Q?9m42wZXeyIwBMl9vXywWJWr/m0Lw6dhOJbPTR5NxrZtJLM2w29+8uB6fGVJQ?=
 =?us-ascii?Q?EIkrUuFB9w5+4AFXVmgI625pVetMfJQrNPGZyMpVjpM+DvZBo+dQ1XVQv99C?=
 =?us-ascii?Q?jVt5RGt2OhL7trHj5fu9dqpPlyYo+AhCC1LZa5coH7iIpx+ZVDQ7MD6X6Zyw?=
 =?us-ascii?Q?KICtskqJl8vQxVoQULB3K93QD7mRRoJAWcK5a0siolfP9uzPXJQj1Bufgvdj?=
 =?us-ascii?Q?tr8puh+d8Y9cgnJ2nBgZ7fRqUDV8UpVWIXWHSWrpiUM3heay/UOq4RWFs06F?=
 =?us-ascii?Q?5qZofKxCO4P0abqSxqJD/Eu5MU+HcgDEpwWoLs7esU0GWVXrZke7HaBImsKD?=
 =?us-ascii?Q?3ers6g3ZRkMKPcV3wd4GzHtkVJuCQJPNeIj7zaPf4our6Qkx5ZEiWpl/4EGi?=
 =?us-ascii?Q?x3Grr0LPDSmKfUM560GN7IYK/eaD1hTpDHpQPQzQsEDxT3zIsJ6PPwf6bws+?=
 =?us-ascii?Q?rd87SiKdGxH8meqsWDmlxGCZ0hmOmLqtGoQrcW47SCkqS/0yrQ5SxIjqcbLl?=
 =?us-ascii?Q?Gm17ReTYqCj4S5XZ7Pqg0uZFUVHNjdxNyVKqWa4pdsy4uYr5ChLAthJae/uy?=
 =?us-ascii?Q?oXxo3HRPlM9iT3DLSS9v0JI4s2osQtdKF5o/EtVJSxBOps0ys7crsWaRa2ZT?=
 =?us-ascii?Q?NY7RXtUHFT8vZ2nXKYU1/i8hAWP92iL6c+3ALGC6CxPA1kfk0mMWn5r8QRnR?=
 =?us-ascii?Q?aE7wtnXiaV9Wn1VktKE2F6TtzkcQgCyuTFOCUVqurJd+vFt6l82WJA6YtpnO?=
 =?us-ascii?Q?I4QyHqKoCRfh9h08V+jKSdG7oHazxeulPAR625JZuvZC0MRLDKKaocL8aAUQ?=
 =?us-ascii?Q?a034pUt+wOvFhDoZRcXqkftuSf7IuFH3ql4XTEJaCQ4DQypc1ttTvL6i6HZL?=
 =?us-ascii?Q?ESZl5KHq9eDfWKjH3GDbdC0AzDqURDXuw3fcg4rWlUgxqK/gywAD+E4WbmJK?=
 =?us-ascii?Q?wv35RR8xGwiLegY/A6XmSrbmKISrMiG0XzdfqDnbEjCjIQ8G3iTu8KuOEE/a?=
 =?us-ascii?Q?ZlrJDRhNpMycj3fpnNBv7l/AGXrZAHsP4hCq0yieqPWEed5DFybIjMH+M6mk?=
 =?us-ascii?Q?x9ApO7yN1h/Hd7o3ks0K9XU4J5arFOyXpDynvP31xpvxKisWKxe2jb17Jt1J?=
 =?us-ascii?Q?a1kBoxoOTNAP1Tx4+W0uipZ5ML/BwEZU8r+3d0uTsDB1iiBAWykrp4jSKF9p?=
 =?us-ascii?Q?FM0DWu43708giy2+Eww7dEh69nXIY7MWB4FaJ/lqepEN1IQS0p/8J3ngyoGh?=
 =?us-ascii?Q?9en5VPMv+ao=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?7FJCsWxOPBRG/VWdY/N8zALehIFQ036c94s9ivCv276zNmbjChxo2KwOsFYn?=
 =?us-ascii?Q?XqY0q6mLY5W2Yx5ZCI9G5ovb5piNzD7T7E8/TbZneRG3TAIRaZLHZWxR09rf?=
 =?us-ascii?Q?ZruImfcUfHQs+TRilvAaBzBhYvKaWsPz6inNSOWLsmXqkp+8RWa8QtR9bmMC?=
 =?us-ascii?Q?262VXRnY7ye8fTxj7pGuRqjpP9wBpjuXO6HbAxO1YNQ0zl9b1qkzE/nGQ4Jy?=
 =?us-ascii?Q?yS6VhNzoOZbzcLKyhNQA7QvDSsl+ZWo/tFg07T6afoCzyKX4vRzGRjoj31Up?=
 =?us-ascii?Q?kCFtmo8ZlxpWKq5EmPkb0p+wBWiV7SEFL825r9Y4P4hhk7zhwnmRz20HVFpR?=
 =?us-ascii?Q?A3NNIFn2jiEEXS7sJ1YT5Npf7SI1WR3q6Sx2qcoLObEVmg1AHUebvbmwshJ2?=
 =?us-ascii?Q?+IGWddmnOOx3/mYuaM7mFh1ciq7C28LiNxMvRFGqKCaX19qGoYePzNcCMU/W?=
 =?us-ascii?Q?4W8EcvNNgLHpTixbaS2ivj0ZkS1T1LzUNlvn3OO/k9mYdqUZ8Fbb8zKvkYWD?=
 =?us-ascii?Q?XzbcvimnUCM+FzbCi2wCBYTCtGAqGn/vT/qmbjnInjxH5JZbcrBNLTusUNC1?=
 =?us-ascii?Q?YwIrQ/nv9AOrI1qm/OwsQD9ORqdpRKcViSoul+B+Nh4pCzfcXrt1l/7UdfXL?=
 =?us-ascii?Q?fdGhXhzYU/OncOKw95ufrH1yBDa+sjb5Bzafrf0nXr+43ePun/mqJRYcHsvU?=
 =?us-ascii?Q?3wlfVxg2rAgCdbDJElaghWHyW+mLen2FY9W+Zg30zLmcKJFpxoPy+sGn3mqA?=
 =?us-ascii?Q?VZPk6Y8TiaR06FYdf/nhYEHke0gCnn8n09chJwD40ubvSHvRadgTVsRvW7Sa?=
 =?us-ascii?Q?YHYRohJvpKDX54M/NDeVgMtH2GwDAIpVk09RLS0PAB0ygU2Y1Reoo6bJzhzC?=
 =?us-ascii?Q?C3ULhdFh3pbDO7iURNfRRbG1F3IcRKxS+7cjKlbwQn1baxnNMjR9fpqsVUQa?=
 =?us-ascii?Q?hYNgCHdV6udNmTaPaLLazznaTYpdarAHoYcRofRYP3K2iA2k1uVG6XZkye0N?=
 =?us-ascii?Q?EbRTRG5+KXfd6VnN+lGlcnXCUKCYnc3/mj70sAfE0wqn6ggBipzLzZ06lppy?=
 =?us-ascii?Q?pGZFtaizIdrkv0VsTOSazzPIR0WcW5Y6TxB8x15OlP4NJd94hBQhTjLrj7wU?=
 =?us-ascii?Q?FKXkf42air+mlHRQmJG5psKDRj9Uk73mhdKweNJE/bNHv4P1o7U/map0ZRaC?=
 =?us-ascii?Q?wSW7Hr0DTJcUArP3lCh8dvO9qVHQOckyGDBJ5Jsv1uOPVJC/gO0czY/FXWUJ?=
 =?us-ascii?Q?hXdd4kmKDP+OlIv1XRptgmwNB9bfKPieerkQ+ywBRrYMKXHgzmWUVrRqmjaL?=
 =?us-ascii?Q?54EikFLwMMA+L0RckaG6tHd6fdsOkOGpmb0QU2U+WGtSFVal6daGPrEzRX1W?=
 =?us-ascii?Q?AuhrwbVd8Cm14lX+Rwl9ETbEy38JXebh9JKBCQ77HFLVa5B6vEuO7khFT3hR?=
 =?us-ascii?Q?GsCA18aJArsZefDBhsu7kto1cTDKGcUAUGapW2yL0GGpc6sdgpoVTU8aLkgH?=
 =?us-ascii?Q?N4B2lPsRGuahIkUI13qiyS9R1eA88fKYWiRUr3Jut5ESx+6PvCb752BZaxyc?=
 =?us-ascii?Q?xOrenGxP1WzbMQB2gIo=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 22e1bdf9-7d13-47c6-08d6-08ddeeeab608
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:16:40.1755
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1tpI3YIsTiLSBDyil/y84udvyR+SIk9BaK4Mip9D8I/ZS854FMCO4alMjdflmiBP
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR12MB6647
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Npo5um5t;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2416::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 03:47:34PM +0100, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
> > On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
> > > > Perhaps
> > > >
> > > > !vma_desc_cowable()
> > > >
> > > > Is what many drivers are really trying to assert.
> > >
> > > Well no, because:
> > >
> > > static inline bool is_cow_mapping(vm_flags_t flags)
> > > {
> > > 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
> > > }
> > >
> > > Read-only means !CoW.
> >
> > What drivers want when they check SHARED is to prevent COW. It is COW
> > that causes problems for whatever the driver is doing, so calling the
> > helper cowable and making the test actually right for is a good thing.
> >
> > COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
> > something that is COW in future.
> 
> But you can't do that if !VM_MAYWRITE.

See this is my fear, the drivers are wrong and you are talking about
edge cases nobody actually knows about.

The need is the created VMA, and its dups, never, ever becomes
COWable. This is what drivers actually want. We need to give them a
clear test to do that.

Anything using remap and checking for SHARED almost certainly falls
into this category as COWing remapped memory is rare and weird.
 
> I mean probably the driver's just wrong and should use
> is_cow_mapping() tbh.

Maybe.

> I think we need to be cautious of scope here :) I don't want to
> accidentally break things this way.

IMHO it is worth doing when you get into more driver places it is far
more obvious why the VM_SHARED is being checked.

> OK I think a sensible way forward - How about I add desc_is_cowable() or
> vma_desc_cowable() and only set this if I'm confident it's correct?

I'm thinking to call it vma_desc_never_cowable() as that is much much
clear what the purpose is.

I think anyone just checking VM_SHARED should be changed over..

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908151637.GM616306%40nvidia.com.
