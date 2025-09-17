Return-Path: <kasan-dev+bncBD6LBUWO5UMBBNH3VLDAMGQEXU6BJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 480F0B7F9A6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 15:55:03 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-324e41e946esf11594272a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 06:55:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758117301; cv=pass;
        d=google.com; s=arc-20240605;
        b=Djj67ccnqW2qBcx5DWJ1aSLWgdo9+/8NCfgRtgdbxkKPKj5ueIM0eY01rS6VTOVjax
         53X+7O9y7YJEuYfTXmAHskrnuljJuUA5LAKkQGgnFc/1/rEvlFn89DhBM2o2/wTvKuIh
         MHz2+IHz7GBsPLRtGAxcmeY4KwNMbJZP3b0naGUNVqpF86qrmcZlJhWkqCV9Z7qHaLM4
         vF66S/s4sHJYO5Mvo0YYahFSGBlbpFLvvN33iYQu5564TRKzJb64eO6ieKb24RcAt7Gy
         zd0T+EvRZV1vKw8nf9s5yXoQneRyPappa9oOB3h4Y8L1c4rCnVqkM3h80ZlMB3OJo9kc
         OK9g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=be/o47elTDsjDRLUnc+ocvfHYTvbDy01NfTTih/Ubx4=;
        fh=Cu1KaWG3rYqBiJsdXRfahX3YoSdG/grQ+QyNJ1ZF1aQ=;
        b=ZkzVA8bvhifjzxrM1WOwaX21nwNonwEaFSauydk9DhG6XKlealq418X3xl2/EFfWvK
         cEUyjGhNXRtpn59rqJBJ/cjv/i/A115bBgpRmGhUtrTYMQ8Jawa/2NQk3eB51sMlrY9o
         DxYBbUF+1jxKJT6Sh5cPSBE1hNlINoUBpE/9plr4oAlVKreWJ0X1ZtcRZEgBXziHIE3Q
         MXchiAc3jfaBC+eknWXG3FIN6/9FVkSLsXsmwq953lTioc1vQin/Q03SpU1ySna+iB2X
         VjEwZmMy3Pl7OPC5DunwkXssIHlZW1CwQXfQpHCBDLhWDKT4WKRXSF3rm85JXclgLL9a
         Oqmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=et9sWCdr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DDTT178t;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758117301; x=1758722101; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=be/o47elTDsjDRLUnc+ocvfHYTvbDy01NfTTih/Ubx4=;
        b=TniycPU/D6v01vHJgz5ncE/UKTJekcbUAdyxQpbdA9DOvQQY5L5EYI8dbNRjab4/Vq
         pQMAivDa4Iy2UHLh27x6zDsIJY6RVvLFgl+cBq/a/L0zfB2eoFCSXsXOdIuPrn56+yrY
         H73za7cXnB++L8t4gUel1DvWBNuXlfMipuZnU4Bbx9l0vvRkAzckh3sixPT0+Gr76Dji
         MhR3o3icIMBIRyAaU5Q4Nw5eHL3FdKXTv6Z8C2DYuS3QWXcPSUEmNqBbU3KQRn4U7p7I
         +AETuMlHqbhVewsmEC8HIB8ZsUoKQHkYxqfb3A1oYHcfgzs79Mlo46H1eSpNDvYK1VY0
         c9Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758117301; x=1758722101;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=be/o47elTDsjDRLUnc+ocvfHYTvbDy01NfTTih/Ubx4=;
        b=LSwMwWxOKRUDOu+2MTQwZ1anvPzu7YnjGSTb3EHl0mqKlJatCa4tdukx3sOzi+ZGaA
         CY1J7r/23vIm35kKxyifKqO3P/Q+v4Ucu6J6AoYtO/tfnkk+RbwBzgtVczC0afS7BO58
         R34L0gVQBDSXxw6jV5GTsKLDztbi6Rcg6EGNMVwYKEcyx551vKAgUkCRehyPM5zT1hZl
         jj7WcdnYWmPdbmtB6b9gueawwOI/pLfbGdUIeKbpVSV76YSScpSOgQ1K/DUS2A1XtdeN
         2xnPv06dcMwXEl5x9eN+BZSds8pqYUiu5t+Ej824HEc9n+GqlJmV9tBKeWiZaz6wyFGR
         f/Hw==
X-Forwarded-Encrypted: i=3; AJvYcCWzo6j1Ppy49bqK6IH8wN9WlBDsEfkDMHG4D9oK8TTWUB2EbMku3mGuRbhEiMFLSBaYshiAVw==@lfdr.de
X-Gm-Message-State: AOJu0YyfV+dKBOOa6vJSzyHtZrZvbOWND5dsERv22piCNhxXTPZlhHay
	wcXgNmMn8k4PJzNwCh7ciAaomWU8Vld1l3VyD/SLzmeeRgzYtzPJp195
X-Google-Smtp-Source: AGHT+IGZP1alM4Of2Ie5Abmbru/b173rOfepNflLMjWntFgph2Xt5HNDnmdSYkiVgDhKjEbh2/Iq6Q==
X-Received: by 2002:a17:90b:4a85:b0:32e:6fae:ba53 with SMTP id 98e67ed59e1d1-32ee3ebce49mr2537953a91.8.1758117300765;
        Wed, 17 Sep 2025 06:55:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5GzYuTpXK4ksED3lXQIhvgLf1d25+I0sISMEBZWFjKIw==
Received: by 2002:a17:90b:2cc8:b0:32b:d501:1efb with SMTP id
 98e67ed59e1d1-32dd4edf0c4ls8760518a91.2.-pod-prod-06-us; Wed, 17 Sep 2025
 06:54:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXKLqGokTTrHFp/CZ5H4q8oLdppTqeY1/5t2/xGfZBPwiktv4o6n61PZL0M1BH3JPbuqxaH4y3Rnb8=@googlegroups.com
X-Received: by 2002:a05:6a20:7343:b0:24c:48f3:3fd2 with SMTP id adf61e73a8af0-27aa308d502mr3278286637.24.1758117299289;
        Wed, 17 Sep 2025 06:54:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758117299; cv=pass;
        d=google.com; s=arc-20240605;
        b=hd+ODlHLJ7yS9qpQzzeBzCZpayxVPme1dtI3k3WSmOsIucD2WClGmNlFGkP54uZHez
         BdwczD6SzyWpYvvKgL4oDmHllUcEvdT5ivALgq4QW8603LK0KbUJF7KzaYEI6jdJ5s7X
         ahJ42AhXzl93C31JPBY4iaHuIagt9XdaPP2InGvdC0KNdFBFYf4a48z6YygJ+wDnJQ0Y
         pA2g4xhhqZmpoPntjL7SwqW3CKHgUkEHT60D2v+tzLUwxyvXuQS916At4MFwCS1ce4Vb
         fFZob06MiW5iWL3jrV1flzYaqoEd1PRmaBmudVHAxHmJdsqsEadwr7sHyDDgBi8ws5MP
         NDng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=hHJ6VBioz1MO+VxoxiNrBznpHElZFHXNpSNPXucuTrw=;
        fh=89MZ86xjJ5V7e3uJlIk4Cw39HDAdPH9Fa7YZeCAFYtc=;
        b=UutAwYjCnbHzxbXUoJmYznT54bdqv5ZsXMnXp5MARru7ip+2reaSACf/h07+3RY5hV
         igVbq73a9ao2NKNJwIT8vUX9i5ASH8R0IK39VRq4/eukiXQM5ZIvUIL66ZwvT4eS9faY
         hZ7q9rPyzfVyLlPeSmHy2erDuMNXs1Jds1oMGIxgT4FknP9Q3lZO4fd3oprbgvjeE1/f
         zpnZ8ZIMpDpTuyNZx3pJRmsfILlR7umcInX5vnEUSojgy6v97h/NjXbjMrjyOxDmNXSr
         lFVFztDFq43+2sEDFHVKSRod+IHmH+Z5U/2L9TCKZNH8SX21/aDr26CHCTTvO1IgeyLu
         KDyw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=et9sWCdr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DDTT178t;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-777c6a84e08si465928b3a.6.2025.09.17.06.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 06:54:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HDg0op020903;
	Wed, 17 Sep 2025 13:54:45 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx9sbuh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 13:54:45 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HDhoAX028863;
	Wed, 17 Sep 2025 13:54:44 GMT
Received: from sn4pr0501cu005.outbound.protection.outlook.com (mail-southcentralusazon11011053.outbound.protection.outlook.com [40.93.194.53])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2dshdg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 13:54:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=dGINr6ixMwx3bq4YKz260r7EMat2TajwjO4222wxstGgxgeD4N0QLdQomkTe6X6AlKNzwwZLJx7yj1l774VE1OLLeizQrFmQ2KmWa0yzOv+a/Ya/tuTzmLEb3BjAM08+TUo2hsf4h4XMtgbAGwCnE49KYhq2KSXWwZzT2hMcPFGFw2Q3cn0Yet6BU5w7jup1M+JQmXeSQyerA1sSQrYyScopKhFu9xXku+70qb+OMoiQB8JT1iaVrL+tADB2Hk2qDBB5M2HofKoldNYP3xrW84KzRdKdZnIhBkxHgse2/QD/UI0uu21w6BZLsQ1XrU7FTiblZbx994o+9XxbvtWVog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hHJ6VBioz1MO+VxoxiNrBznpHElZFHXNpSNPXucuTrw=;
 b=zLv78ihTHYVkwmwWycMbNQhg3XkySWPMo5apyirMB+g8Yi4KO+B5BGTX9p4GNRXv4hiNRI8VPzvb5dKZvwsLETmtF5rFiUNvGYt+UGO9EZrhoXbFivA626AcdEitEqstXjN8SF4XXQCD7BpIhhBL9MgSxdGB/2Pe967JDdp1tPnq9/3JFXk2l086YLtd3G3z1v5BgcelFHVT1Sfbg2KFqcr1iSbYpwgVHKCB0NitvWmhhpfCxO0njuN2wXNzK62S0JG5s+GizNtgwYsl+I+ot4DiLT0QRAIlQI6Lk6ochutkJlqB/EBeyf4jZQjSh01tZNRcZbeS8PJ3pGh4JQpetg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by SN7PR10MB6572.namprd10.prod.outlook.com (2603:10b6:806:2ab::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 13:54:40 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 13:54:40 +0000
Date: Wed, 17 Sep 2025 14:54:38 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Pedro Falcato <pfalcato@suse.de>
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
        linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
        linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
        sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
        linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
        kexec@lists.infradead.org, kasan-dev@googlegroups.com,
        Jason Gunthorpe <jgg@nvidia.com>, iommu@lists.linux.dev,
        Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
        Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 02/13] device/dax: update devdax to use mmap_prepare
Message-ID: <4a0fa339-56c7-4a6e-8d47-f683f6388132@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
 <2jvm2x7krh7bkt43goiufksuxntncu2hxx67jos3i7zwj63jhh@rw47665pa25y>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2jvm2x7krh7bkt43goiufksuxntncu2hxx67jos3i7zwj63jhh@rw47665pa25y>
X-ClientProxiedBy: LO2P265CA0485.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:13a::10) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|SN7PR10MB6572:EE_
X-MS-Office365-Filtering-Correlation-Id: 11844ae4-4448-4a19-b82c-08ddf5f1bf1a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ue/X8IlKv2ESluN3MFNJ6xyeMLFHrQaKCCwYtlR+ALLmeLLq4W7qLd4ARUyC?=
 =?us-ascii?Q?b2NHmbSeeyJBf74jPjEftFEn+Z4l2H4Rxqcu5ySuxC+Vi5Bk2clDJsAEEOCa?=
 =?us-ascii?Q?GAUyvtrVr1RgcIaJBGX5CKgDkltIoZS9Syu3uEznKOuGzwmudeaXQv+kV1Oo?=
 =?us-ascii?Q?H2jn76/29ldlDr26NguXxq3p7huimU7X6X3YgGXa8vBVtdoVxIWzXuuN4/Bx?=
 =?us-ascii?Q?hLXBplcGghhfo0SU9ZvdgyZgell9C7ut2mYxbgQ46XBGY04iSshorSDZiw/C?=
 =?us-ascii?Q?LzOQ4C7PB6DpVHCe2rch0f4eTOOj4wQSTeiBguJfhawOLHDJaitkv9a/Gttu?=
 =?us-ascii?Q?wUoBdlhZ6RxGo0BqUYBRIq4qo3Yh/cqFEBb3mPBbDk8xbZOCy2mUtcE0Mrpw?=
 =?us-ascii?Q?qlNcr0/XOAvJE0746+aEHoYJqa0j7gT/Ky8IGxCno5YQ1ynmdL9eJrOXBlhm?=
 =?us-ascii?Q?5NRqzCGZ192X5ZLhqZbSk64WXDc0JdsR1PIs+Wp+W0NZqvPDzHyL3rQhUza7?=
 =?us-ascii?Q?H/Lm09c86Rks/uNToF/HNEpv50tGQVsN0ENqUO/vrbKN3Rh9QR8rGdic/unH?=
 =?us-ascii?Q?1KaPXyXHxalBPouAw/myAuHYqjAB96A4bNfxvGzSVW6UNo2SlNEsE9+ZbCue?=
 =?us-ascii?Q?g3LW2hAPR+gsyNo747Zu9jiDCSMc+IVYoilMpNMVkdsRqpeCznLYVpV+N/eh?=
 =?us-ascii?Q?W5VeaHdjQWFdlvUMXVRAsPBeN6cG4+T6NWQeVPL4loMO6Yn18HG9+R/cjNr+?=
 =?us-ascii?Q?g+7LkWxaWlup08g9Q76Mq4vu6BFUAxG1K068FQNiDf7Sv0+W04/B9TrZpXr9?=
 =?us-ascii?Q?e3g/6Py0rXdKGuWAAUtNAUEfnfucFmakjb5eJdeb+G91My73xK5O+5Vs7bEU?=
 =?us-ascii?Q?9PqlgON3Yc5i/5IxFdTuHn+/hjHjgPIazdL6tE+YNn+HcotxUUAYf5GY/eZn?=
 =?us-ascii?Q?w0+yMpQx1mvJTLbCXtbvqCvyFStc9JJYw7Yw9nx/GlKhTJi12VlgUzTS3F0i?=
 =?us-ascii?Q?anV2ysNqg2KeytUL4jixoM38DJ0ndo08KChfT6qsaAk8Dx9/4eP2Skvz132U?=
 =?us-ascii?Q?gW8q65O5soFzDeyLVUcseiw7MOMCNk/14JBh76kvR8cmKDN8bt1C+XrSKGX1?=
 =?us-ascii?Q?4io8OMVihgNe/JVvuROiOyrO9nUKXXOeAauLVq25oxczLVyX1ckaNknL+RVq?=
 =?us-ascii?Q?GfPR0oc1hOvPprFSCM9pjswRd1Ko/wOychbFbojlVNGM7mCRXUOgJQA3gZ+r?=
 =?us-ascii?Q?uaYcMehWgzZjSyeacfKLc01znF8TQA23e7lbwo6+SUAAdY4vgR9fewyWiEFC?=
 =?us-ascii?Q?dCpQDFRws3wgtAuOObhhAwQ9Jxoq0dTkUghv/g3WjmK1BzSOJ99NAl+JUizR?=
 =?us-ascii?Q?yWtxGgLtO6RvcsSrt4Em3QC7kG/VUJYAiyj1QRnB7W67PKihDJt8n/+SXcQY?=
 =?us-ascii?Q?JYMGXrheg9I=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?37G1svZM+o+0AidZsy7ayS791J8qD0SrQ4E5kWfflA5or4A6oKDACwBMmGOp?=
 =?us-ascii?Q?OpX+zq2k5ezjut0O5duUGY3aOe4iJ6rErGrykBuqZXKQcp2fOrAtuopWE5Yj?=
 =?us-ascii?Q?LUi4CqxfDgQzytJQi5u2TPTCC11bNVY9pTpFAQ2TGetf4KnaA2X8+Xzk1xiB?=
 =?us-ascii?Q?4sFBXmZ7cq17q1DmAdM59sgB0EHHHkWMjJnuaY9k3Gqb1p5AaW7g+TkzemGC?=
 =?us-ascii?Q?qRUzkYivLO5EW5jsQy5xFyXYpgGNGmy5pxecH0wL5q5a7XcqUPLxD/pq9vxU?=
 =?us-ascii?Q?0yNASvHMSINYR2KPXvwo4X+8hgSGyZvknaMngdPcEm5IwSWcreUYJfOwLUTO?=
 =?us-ascii?Q?jKEzdhWOhwhk0yT6pFx+wq/WDl/kKuf3h0i+0O6FzN9aNN9XxQc02rx/Ztma?=
 =?us-ascii?Q?I9O0JAlNrNB5aldjY3JP3u+UnwpFbvKQWfTZVPPaPYELOEOq5rPCC+ojK1Sv?=
 =?us-ascii?Q?LAE3M7y65IcpFIwmlLkWxiD5W+ty9ThOqRBSeBdNBmMIUIi/c6Q1J2j3i3+x?=
 =?us-ascii?Q?ygoDHpc5jnN/btKdLZx1CUj3+tk4+A+z0YAm1YR4CIJI6yuFDEYN6KIcS7Id?=
 =?us-ascii?Q?wR6d9YguT1HHdpm5RqPEh3OgWuwdPO6pDXrh2GAjqqeP9FQcei48zA9OkSnc?=
 =?us-ascii?Q?44a69/ipe3wLFLBbvRCiNWxBOld44ePbTohAGdmb7/WVq0AlQG9CMeyttWu5?=
 =?us-ascii?Q?8r77SKnaRkUDFpMjnHpLWmyKOHjYzqK3aq8USrAN84PeeyZI4AFDVPvbtpX9?=
 =?us-ascii?Q?rRbeG1XCQ3mwO29soGI/DEv1lr972EIiBSGNWCAhy2rNLJBLY0vip+l/ibAe?=
 =?us-ascii?Q?F3xTXDODq17dg1xp9ruIjBjZG4tFjqsX6O8KZHmP4FfqQZpshbZj5v3jD5/T?=
 =?us-ascii?Q?hmQUvAKzxpDID+95v08SuQk22UtkDqEdRVezZZpSrb6JZp9VigU/xDPcDlhU?=
 =?us-ascii?Q?25SWcyQ/VPKieF3MBBUJaMzvH8JRaYkdHk4A8jHITiKommZVsm9RkJQNXRA2?=
 =?us-ascii?Q?c2qGesoko5HSd3O1OhTFyk1CUAYx7E/X1OAlavArA0SE/26wm+Z7ghBmwAa5?=
 =?us-ascii?Q?JIs8AOISkhpttBJb6Qoa61MswDGxWyPmVo27HzBEp0zhzkZfVWLOrYwaLMMj?=
 =?us-ascii?Q?5V660vkZtlGiwBBbiO+vsC2+Z1XRm6sdA2/MMG0b+Yo/9QBr5aHizfbtJSwX?=
 =?us-ascii?Q?hzl1T7zTAAtgQztGG1z7ICIfaMtJRjcDMQnbjdnxUm6+5s34pdMNAbJJNh7z?=
 =?us-ascii?Q?sDDyB9GaEw4bSYznDQ/BQaUzoZUeLWA3/Tr0rtgr57HykxICIDucMccbnnAp?=
 =?us-ascii?Q?THJp6DThfRD90j/iqRsobOF7SuzUoDSPaF/f8wNkHGnnutdyH0cLGAnvUgmm?=
 =?us-ascii?Q?MvguOpmZYjcFLog6VgrxdyGrVr42YV2VH5vOnkd+MSopva7l/J6K3fvhHv3R?=
 =?us-ascii?Q?9sNG4znRWDvhCEs4Ii1q7ecm/N6h4IP9scvOu3I4iFTUjgXPP+1eHtUKEmd5?=
 =?us-ascii?Q?iQ38IoWZKESIFQdach+jCu0bT67oc60ZRfV6ZLle31dB+wjYcYxZThzE0Y3J?=
 =?us-ascii?Q?zPR276JRzAbmSoWH1S2WXOmPv79ms1TAkbgMExcchNZbllhq0rS/P8rx6h9i?=
 =?us-ascii?Q?YA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: hxkaLiAnU9hkOGJJE2qIFrwZ296dYLnVMLR6ywxpGQ+AyjrSRd/BQydgloHnontVtjhVx8jCN+NCEABOc3kxy24f1ynE0C9obRMyEeQSf50sC4tLypHvrj03a/GVa10H7E7NSKb4sdjmh7NFaxKCX5ahJG/mwA8lGB+XGKiZYSsED01PVvEo98+ERHUesIWkklZw6yQsBBxpsb1sggd7VHHmycUgzwifUDbpBWA/9f2wLIokUevJZTPcI1OqYOHSWeMNiAkNQX+sb8u6VsFuecxK7fZ3IiBCChFi7xSGYEL6WzEcw7ySgafoyQ1gDoSh+RC9jXmLbtCSGwRv9B5KMGtZJjZ8MvxhDwjiU4dheTbgyQcKMRM+kzOmti267UcYm981FkzApy00nJ1gKkqZSLB/EciGar7R5dfp7FBunADx9nBps1+mggtbrzpMf1cgJa8DROceMC5qCIKFXTiOOobbwZ8g1Y8wprpSijtb3X26Y4SSSdu2uQyuRs7C6WgHTy0QnIoMnP81muqd4g+vFwGDa5hWSHj6v8CZAmXtcmk5LWZeqhrM2dbECx4jTMf4/toYoyHC7MbmVWVewhO8+daLcvjZ6qmP1Q4EWzHMtig=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 11844ae4-4448-4a19-b82c-08ddf5f1bf1a
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 13:54:39.9207
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5VqUy15quXP9ZRhAoCoItLdKF0rvaPyo8vJGg5zrAwiUgvs5pUvYfJF7onWZnE19T2ZjSO2TLNxbs4ArlwOD5Iexm4UNffG5CqPKPUsJVNU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6572
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 phishscore=0
 bulkscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170135
X-Proofpoint-ORIG-GUID: ZliNQQeCdJxqiycD26sV-MWbggyCDJKw
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXx0y7wwqYqLEJ
 Wr6qfVX+233tWzMCvRnBqKGrkc9SIL7dxkzr6QiIvgbhHL14z5X9K5MwCwHbHaWYfNeJ4IQPKsT
 Aqnxt7jZg0wirf2uqF8V7lHF7G/i1rjT6YO5pOOvo33s0ft2Ytj/K0lxtATP2LRanIprgf7bUEC
 oFQ/OhPCtlbehzqBrcwvBT6Q/+fQZkbsY07G7foEvGl0eszSUdmCyP9oPh/epPO82cBhyK/8us7
 VpU4zGWzJjiMTXWFC8dQ1Tov0pXvpIaDjpMzxSTgkTgwXFswTFH35BbjzmFMGogf0dZxBbtO7SH
 348YSNHyyNnTQnfDcd5L4AOZkXo7AFmF41GQuAm7AWCQNz+fhdACxesJo5XF1Qf9Hpog2rcIHCv
 FuGxd6NB
X-Proofpoint-GUID: ZliNQQeCdJxqiycD26sV-MWbggyCDJKw
X-Authority-Analysis: v=2.4 cv=C7vpyRP+ c=1 sm=1 tr=0 ts=68cabda5 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=TYjx_FbPIwLi9LQ6WlsA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=et9sWCdr;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DDTT178t;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Sep 17, 2025 at 11:37:07AM +0100, Pedro Falcato wrote:
> On Tue, Sep 16, 2025 at 03:11:48PM +0100, Lorenzo Stoakes wrote:
> > The devdax driver does nothing special in its f_op->mmap hook, so
> > straightforwardly update it to use the mmap_prepare hook instead.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > Acked-by: David Hildenbrand <david@redhat.com>
> > Reviewed-by: Jan Kara <jack@suse.cz>
>
> Acked-by: Pedro Falcato <pfalcato@suse.de>

Thanks!

>
> > ---
> >  drivers/dax/device.c | 32 +++++++++++++++++++++-----------
> >  1 file changed, 21 insertions(+), 11 deletions(-)
> >
> > diff --git a/drivers/dax/device.c b/drivers/dax/device.c
> > index 2bb40a6060af..c2181439f925 100644
> > --- a/drivers/dax/device.c
> > +++ b/drivers/dax/device.c
> > @@ -13,8 +13,9 @@
> >  #include "dax-private.h"
> >  #include "bus.h"
> >
> > -static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> > -		const char *func)
> > +static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
> > +		       unsigned long start, unsigned long end, struct file *file,
> > +		       const char *func)
> >  {
> >  	struct device *dev = &dev_dax->dev;
> >  	unsigned long mask;
> > @@ -23,7 +24,7 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> >  		return -ENXIO;
> >
> >  	/* prevent private mappings from being established */
> > -	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
> > +	if ((vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
> >  		dev_info_ratelimited(dev,
> >  				"%s: %s: fail, attempted private mapping\n",
> >  				current->comm, func);
> > @@ -31,15 +32,15 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> >  	}
> >
> >  	mask = dev_dax->align - 1;
> > -	if (vma->vm_start & mask || vma->vm_end & mask) {
> > +	if (start & mask || end & mask) {
> >  		dev_info_ratelimited(dev,
> >  				"%s: %s: fail, unaligned vma (%#lx - %#lx, %#lx)\n",
> > -				current->comm, func, vma->vm_start, vma->vm_end,
> > +				current->comm, func, start, end,
> >  				mask);
> >  		return -EINVAL;
> >  	}
> >
> > -	if (!vma_is_dax(vma)) {
> > +	if (!file_is_dax(file)) {
> >  		dev_info_ratelimited(dev,
> >  				"%s: %s: fail, vma is not DAX capable\n",
> >  				current->comm, func);
> > @@ -49,6 +50,13 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> >  	return 0;
> >  }
> >
> > +static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> > +		     const char *func)
> > +{
> > +	return __check_vma(dev_dax, vma->vm_flags, vma->vm_start, vma->vm_end,
> > +			   vma->vm_file, func);
> > +}
> > +
>
> Side comment: I'm no DAX expert at all, but this check_vma() thing looks... smelly?
> Besides the !dax_alive() check, I don't see the need to recheck vma limits at
> every ->huge_fault() call. Even taking mremap() into account,
> ->get_unmapped_area() should Do The Right Thing, no?

Let's keep this out of the series though please, am only humbly converting ->
mmap_prepare, this series isn't about solving the problems of every mmap caller
:)

>
> --
> Pedro

Thanks, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4a0fa339-56c7-4a6e-8d47-f683f6388132%40lucifer.local.
