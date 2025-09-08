Return-Path: <kasan-dev+bncBCN77QHK3UIBB3VV7PCQMGQE26ABD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C376B48FA0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:32:32 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-40babea9468sf5707655ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:32:32 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757338351; cv=pass;
        d=google.com; s=arc-20240605;
        b=NoRRNeEL9X29pEhehveT6fEOyHVfoTfmpABqnaMH84Csk+pnMXP/yYRnZUhhWxjvQ1
         K2Jzi1P043cswrCTV6D+NNWgS6/lIyPjnXs8A0QipWlWRT7mcpULz20nQo7rVjobz9mM
         429EZrbWO/j8mJ4c3Qfa3vuU369wGCFtIXiPRkHH9swnYULmFokiitG8kOvWxrcqyYPb
         O7o+mJU0imYMgpYfgz/1p5mKfvZh8RA5doidric/J+Y3A4TomD+55GvO7CncfJl0hFFR
         vwGNDfH7KqWJBWIiej6dhv6j2nGUVaeZSJK/iarvnK62eLU8vfat8MnEi/ZbqnoBzCCb
         +ywg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NgB3c/bTQwG1Hk+tcDYLoO9Tw3/NNlCqmrXCcMiyRK4=;
        fh=47VVUCjC9UlQBOnGgHunetkogwKbngLN8TgZREgpwE0=;
        b=kcByxNGFZSorUu+T0m3BZ+HeHiHGOH4BJF1r8/LuLW7/IgQYiAd2FcWpOfT5wpetTm
         k4mqLlZ2p19SO1p/Bd9d0W+7aDxIPdmMniQZNX6Q5hAkLHh0n36D9lfUxOA5ccEla6x7
         OHO5JGJTQZ48qOukFV0mkF5VDZX1QV+AP5o0svKZQ2YqUG6ApW/EVdlf0sq/+b4GpK/D
         XOdHYnsc1WqDEXQ7FOnXX+LNTfMYVwpzZlP39CbGnxjswJycAv9p+nPEbUqmgi8dh/lj
         2r1V4yh2xnl05oLtWa1aanBM2E7w9IMTSyFj81ahVoFTeASOKjGAxBNfpFo4KfcYIfDr
         oXrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=umqPj4zc;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338351; x=1757943151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NgB3c/bTQwG1Hk+tcDYLoO9Tw3/NNlCqmrXCcMiyRK4=;
        b=TysLGBQLhgvkKPQw5jVOEioqP2pAy6XQb2KnQCdt0yt/6sRin+psDZ4v3HGy6wuxPG
         eITX1eHM3w3cVEVW4Mcpdb91fVlMX4rpY+Vr64BL9ldlr8Yf5Nvp5PKN5qJxtJPKsyXU
         iWOx0idLLDJmLNxe9hFUWt9LMmZbSO2o9dmsk0deGGiOaeCQAdAST0pmndTK8epqH0yC
         2KBEuocr7PyKiWXxbp6c72ruFRrGwH3TDzsP6Bvst08tP5a7/yKLFYa7wpJAlVlDc4QU
         IwvRu5hw1g6OorBCVqMwvvzhCE+TD3ETKEPvVq9Ow/egxXY9QagvkxZlhXUoHqla9mtX
         a9dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338351; x=1757943151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NgB3c/bTQwG1Hk+tcDYLoO9Tw3/NNlCqmrXCcMiyRK4=;
        b=fzkpHnK8yLN9bVlYJrgYgJ3lbGz89KQPq0lZoRziInsDkdITktjH+xpGymzjWe3vSQ
         eMh1E4kzctXk5+1DZFgECcQmEf9iaD4yRzglfDnQBVDgROOHc9FyN6rETWEJwGfcYdJW
         aRDd9gfcjN553FZ+NuaVsuZ30ssequN8/uQ02CEf41tGsz/TEBRZ3gZ3/YK0m3nE+vMt
         i+BKnldig/6VwU8eozg7JTHuNJ+WnUEPyBzjzrsPhDDlEje2FN1RHuHcoCqw20Hn9fs5
         r4ZPbNc++pQeMpyTihDIjCNUk7ezldfdf4rQGdIqI/4PZGMDGXJnij/9EcEqvjs4Tlei
         RgHg==
X-Forwarded-Encrypted: i=3; AJvYcCWyr6LE2eToLpASGaixeuV1WEiqL/EuzpSXNhZu/eweVgkLwovGeBcPm5Q1AFuv1VlpmKK2AQ==@lfdr.de
X-Gm-Message-State: AOJu0YwKc2c10VQO/A/WhK0KvxXCAW6KT6myoV2gTDd99N50e3gOdxAW
	Pp6aF8bO2IZ8+bN75ezMF4fmQqgBBbFUAd6w8ZQmL0Y2y0HCDmmVBGfa
X-Google-Smtp-Source: AGHT+IG5Uze2cDit3Ic9TanpH4O4lc/Rf3Dliwtx5yzxrgSLZQAtjKXIuRzQRa0CjQsWgirUStXXUQ==
X-Received: by 2002:a05:6e02:2146:b0:3f1:f2:1a47 with SMTP id e9e14a558f8ab-3fd97eaf9dcmr121496475ab.31.1757338350772;
        Mon, 08 Sep 2025 06:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfo7SeMdlMa2JUIYLqBdWLdxKfDQVMNqD2/jhqVzMwhUA==
Received: by 2002:a05:6e02:b2f:b0:3ec:3033:7fb2 with SMTP id
 e9e14a558f8ab-3f8a4da942dls27217605ab.0.-pod-prod-09-us; Mon, 08 Sep 2025
 06:32:29 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX4e0IRLUv8Dq+MnTbWL2YHXE2lVkzvpwqamIu0Jg0suheNKCLKy/zMGXxrzgyjfReF7nxr3H3A9n0=@googlegroups.com
X-Received: by 2002:a05:6602:1f96:b0:887:56b5:b502 with SMTP id ca18e2360f4ac-88777684c16mr904571939f.10.1757338348805;
        Mon, 08 Sep 2025 06:32:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338348; cv=pass;
        d=google.com; s=arc-20240605;
        b=bfNbirUVHII+ipDQdHtqViQNqYydPRuY/dOrAr5cbdp5Lik0ZLKaJux1u3L3neI2Oa
         m2M3W8MRSM9Zw+p0hoFGUftH5N/lJ18uGuIUGuLHlwY8Rh5SwcKJ5++rWg3EBCfiXryp
         3xCSCWbZa7vmyviM5gY63VSP9b6xNbONGy3wuAI8vkAeSqNo8mrSL3xKc/+zsrM+Sbuf
         4CaumESCHGzEvGh+asvvYLNr1hLQMM6Ed82OOpT1+f8W8mKnJqdd6LYMpdU9AzlhTpgE
         EoXJh12jL7epE2kwhBG02x0Zq8VtZ+OzwnIquAISChUxzg0Jg4VPOrby2W9evmitEyFY
         VIFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uBi1FVpshr0fT1WbsHlc8+T7+Ir3NcjHPqPXVABKwoY=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=PVrAfshqa/RRW1X+qiEoL0daRFniCjgv9LJkX89tNRmDkTcVGHCptixDkqNiP6K8KN
         mdUge7vgxor1pj0cG4+UOstgOp5oRDtXyE2F7CxFN7HqxluS9kdeW7V1pKQlt6gjfMnR
         s+q5/RzA8KFy2ST/+rUbr5IctRHA01eWmA3Mx7+yLg+1grHEGDXthJCQypiIb5ympEQ8
         MLGOAUpRNRQnFjvQ8ZxumWm+ITM2sZ+1xsmlImvfK5Bm5x/ZLVMeM8JhFsnFUXkwy4KM
         F84vIOUhFad/tQ36bYK8Wit4NRH9VynnVbEejtkMdaB08AEkjxWsKdLNoYZm4qS6Xo8h
         sh8w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=umqPj4zc;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on20603.outbound.protection.outlook.com. [2a01:111:f403:2417::603])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-88c31486fd7si8277339f.1.2025.09.08.06.32.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:32:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::603 as permitted sender) client-ip=2a01:111:f403:2417::603;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MSXEQZKwYEaZ3VNJhatwgR9CFxZONQKMTzr4Gfrxi5W4nAjP68t2LsTlLjODpP9yj28sXZgQml9BxIZHJjcx2JkkUU5N7lpF897Hu2zeDVaWMRvE9NY8p0x6fcd6eYZUeFFD5uYkNBYWH+e2207yff4spZiw1rOgrFZEHIs/XAGfQ/M0vDtFmqcbPlhnUiDyKr3UXMBjeMy9B09Vzr6U4YMUlmbmqE0TqDxZr/EITCcRwKdrr5wsfO+YKxeofhPMDdJS/EE9VjJGeN5tZvlzoJkpMUgQJjivksuKpLJZbbocY4oySpFe4uyusq5qsJOrYPiEd+R0MSzYiR7KB7GAmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uBi1FVpshr0fT1WbsHlc8+T7+Ir3NcjHPqPXVABKwoY=;
 b=M3EjhyWj/LxvVISsAf6on0H8ARUb2Le+3CX7C9h0rp3oVNcEzEtmyjckM9fTEnWdA2qrL3Ryg2O13F+YZIvfAcvWTzM7MUz1IMNQk1OEBEXSrphymQc6L9fBtSJe15hIsnUOc9CGUYhVJ5PxVbY4jbxhvJMznULILRn+xFqlYmcGh4EA+XfB0XZucadb1BjdlozKX5tfOePkuJi/ZIZKm8wCKscS3apJDzdz2blXbUz1V7GLiE5gp2drCBdCNg6KtDMqTkiuFw+cPBcgw7jDa1zyzxzxz5tGhC66TpFiLi+lW10yqbM6XJRgZWAnVuCi82nvR/qhb4za6YSA/HR7qQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH1PPFC8B3B7859.namprd12.prod.outlook.com (2603:10b6:61f:fc00::622) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.30; Mon, 8 Sep
 2025 13:32:26 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:32:26 +0000
Date: Mon, 8 Sep 2025 10:32:24 -0300
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
Message-ID: <20250908133224.GE616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
X-ClientProxiedBy: MN0PR03CA0020.namprd03.prod.outlook.com
 (2603:10b6:208:52f::27) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH1PPFC8B3B7859:EE_
X-MS-Office365-Filtering-Correlation-Id: 1296e94b-a083-4b54-6cf9-08ddeedc263b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?pbGdCwQtUkBy1XWPzFEuCSxAdxGU6ymWkpWa7puKYk2lOQtfEGnVj4mOqyw7?=
 =?us-ascii?Q?DEqvv2249Hq4je6j1kic8/cnMwIAKU2b5AivI4NrculouXZX1S86JLng5w02?=
 =?us-ascii?Q?kHdwq6wM/064mWbKGrrXoyk9oXIj8xKBbacL0DNha0AfzfZa7hsesPwQeGTS?=
 =?us-ascii?Q?6WcCq4GQnXFDhYxVEpW5+cGzmbubab5QvWyQgFS24glDaS/uDV0yQ1Skwluk?=
 =?us-ascii?Q?DqPnKt29dedTeFwNNjg2Uu+yT6GbAhcJ6HIr5R0myY6bQa6BordVNcrtA5OL?=
 =?us-ascii?Q?67CELdskAAgtr7NJDew/NZfyk7ZNq9x6DokZzUx5KrlN8Hc4bM33Oqm0lwgY?=
 =?us-ascii?Q?JKiZYsPn6CjV7A/d3qnW18+JuJdk3fk3i3BSuapnJLkeuW86CzNSEtVMUq6T?=
 =?us-ascii?Q?nBvQtf+pJce7jriOfxgnFxj0JrCrLHCfjhDeTm2znZI3eSFKAz1gdlECdgav?=
 =?us-ascii?Q?DYJ51dZmSxe1xVaoTDTj+fWV+GqZkoYBAhAmQ6mdluQinPmm10paDnXCxYbT?=
 =?us-ascii?Q?k/RohGAQ6fwv43R14TUAO3nI4IeELSjssnPI98Noswq19gB8o6//y6n8oIBv?=
 =?us-ascii?Q?sowz3Hlz7DT4UNNNMU1TTWv28y8utuTrFPsNAngfngZxZAHG+IOrm8kFpiPP?=
 =?us-ascii?Q?MQXG5kHJo3o3BF4S2kxbJ3wYZW1FMJGuuyURQ6NBZOvG41GAC1plt7FdH+eQ?=
 =?us-ascii?Q?pdUQZRrABthEG3NvMQ57P0siy+3JfYY1za3GmnMkcwt5jVTyHyNkX3vowlsX?=
 =?us-ascii?Q?eJKyMoIDZHPGpIt+PdQ8l02VdzK8XYMaksDsLqLdDIE7OD92OyDqBA1tRzDA?=
 =?us-ascii?Q?FjUEf3tVIGHXbMqf8nJNpdOkNcKF2m2OhgfJgfo3yHW9n4j3blo+E0ayXL/S?=
 =?us-ascii?Q?QjYwjKegDLrnoiU0ue7XoZCmQYsxkZ9YfjkFWkjJMq4DfnrgErYVEd2BC8cX?=
 =?us-ascii?Q?Xt+h1HLDeGDhLsUVsyq5YzfhVy4wuNFjsZtcGJelqcaP/AsJqNPpLFMHc1Z2?=
 =?us-ascii?Q?S4q6VvwDDrTehOa9ujxtAu2XB4qnQHa+2x85fclPZGA3p6ZarfGqre1lQem7?=
 =?us-ascii?Q?7KAOP9QVhbLnmjf8Z3LEW0HVh1QWgWHPAQTZ6lhHJyKhq1Xri2Opp8gszD0w?=
 =?us-ascii?Q?rUQw5yIbabLeJ9wyabgtv6Q6hVZYq8MToiEcn4IIr1N5LdxV2z1OwKZLZbBD?=
 =?us-ascii?Q?O9TfFXuA7H7uPFlHEAS4aqHUh8p6K9E8W7CDcbMFf4KBsqw5c7MTdZQkj2xn?=
 =?us-ascii?Q?ZLzBiQNihUg/ITMDoxldx7p0GaE5tNzAFhyYBfmr/f2ee7R9C1MT79Nl4t2D?=
 =?us-ascii?Q?6AivkHWeMQSO47JExnn0e04RBG9PWA85cznHo6hnnxb4Pz08cbmWRVksrC7a?=
 =?us-ascii?Q?JIzs7eEjJ1RM0+7gjCgdexmWWSx20z8+tNsQk7fvUvKy8BDZ7w=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?cWluRfwjDRHkIbbSj/V4gzAvYEhm+rAPYVuK3KKOz+XhVc4jmgXAf0f2JhVW?=
 =?us-ascii?Q?3RtZG70f1N2c7PeMoSdlLtd8ggMtwbUA1MSDbTH+l4TrbUJ9Psk/T0nYP0rW?=
 =?us-ascii?Q?q+6NXhgSF4X5lYsfYNxrx4eDgZzHno14eN2tYg2GtcgMGbHS/lHL+sndpmy4?=
 =?us-ascii?Q?lW5vJZKnR8ULPwehbnfbUYHv1bUAUQicLbwQBxom6pbsDDRueMWV5EvZGcWC?=
 =?us-ascii?Q?Ca+xhyTK9U/stsJ5YUxZKHLAUekqwqp+WgG6mIjgnes+HXhkhv77aGtwMLiH?=
 =?us-ascii?Q?57Z2BkSvgQfbgtBjfZfFhE03HrwEPOVWrm2mzfO6wwRAumTujtQDxVaSvJF4?=
 =?us-ascii?Q?vGJA1S4gOuQK8WirrV3agNkSAuPta1C0QJOrtykiiB98m3hcTPXURnSW/3XF?=
 =?us-ascii?Q?Si0mrXTcAzQPoWj5iW30Ps62qOwZaie9fYyr9eEhVPHJfdcp80SEZBVlWyFr?=
 =?us-ascii?Q?4KSaeN9ltcNCrXl7XlgY2gMcmZZczYz7cCMFsFcYTzxpG2C8YONAw97vvVMi?=
 =?us-ascii?Q?WIEsrnVaCuYyvYTYOmQJqTZTdz3EDCYheiRkePmBpxE26h+b6Kq9xDnom3lT?=
 =?us-ascii?Q?hAU83w+Z4tiKJeymfhYnG+8BKpsmrYP4ogJMaZXWnhov4BJ0heS3V1XEEZJR?=
 =?us-ascii?Q?KFaWZXXx8r9QfruNFjArWZoBjuQEzfBtkWI872ymCnZoUPNZiI4rDjsm9NDz?=
 =?us-ascii?Q?mwIFqgm7z1mA+mZshBeVSd1vqvoOSyE86lk3VoBuINCOFuxtXLQWP8EqC0Rp?=
 =?us-ascii?Q?H+zL8GExBgc44sliX47Wjg8DDONQA0yB/l7HtT4O0DfBQKBmTXBFkxlKve95?=
 =?us-ascii?Q?dtp+0YVmBitZCDeuLsTdzR+67dEBZKRSGxRtW/7ZeBSk4LixF/3QEG9lB9Jm?=
 =?us-ascii?Q?Fb0sDzdduJIaSMEovZyq650G83cw8vba5BIiMXmCXCtYrDH4kDCQmJ7gAM79?=
 =?us-ascii?Q?yza0MF1DtNYK11cFgBDkStPmqjM7UlB89nc8xYtVecZEAak9EUitury93mRY?=
 =?us-ascii?Q?6xFXnHpnoXYqSd5wfZsYeRQNEJdQVPmIVzigF/uy2E4m2vlF5gT02ogsvZ5a?=
 =?us-ascii?Q?OjCUJc1Fb1oe3dzHuKA6bq2kkPAG8Tx2SlZ9C0pAuOrMGBshLZsb1sPmNiQX?=
 =?us-ascii?Q?qYTd0jwSWKHWOLijtLKxWpDACtXLPZYyUTzsIxukBwvEWIGbJt7ycFWKfu4O?=
 =?us-ascii?Q?8haVm00CFRdSXl5p5qlm6RkmDsSsv0r3T4yuuBxW5RMqtJ8nPULXpeimqUUq?=
 =?us-ascii?Q?AXVpjLEzkym0v5s0iHmfntLflk9tlNhJpQ/71W5TwtCHnGKdBV95CaVZLOHV?=
 =?us-ascii?Q?Bu9H0w0Y2VhjXk0QbDsfRwPQ1BVdZ1p3RyYworn/zuJvopPG8JXwOuNwG6nD?=
 =?us-ascii?Q?WZS6sniA83otjD8a4iyKq4f/0Uv6CLVqhEAEm0+kWri8PIExjxyB8R6Wa9qb?=
 =?us-ascii?Q?ZOP1NngUt1coAKwmQOcjri18j82Jq0uiU/FF15gmgg/6RCwH2ET1IKklkU/9?=
 =?us-ascii?Q?HRgMt20T0Ernl/NmX+olEjTyWxIKzreWbYum7KyYb5kI3C9dN+gi6D7jI8fy?=
 =?us-ascii?Q?DcZJvHJA20Z5dMwV/fY=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1296e94b-a083-4b54-6cf9-08ddeedc263b
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:32:26.0123
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +YdG2Z9wJsLcOm97NeNGzP0EsYJQ7Sg+4VCbYQF4vWiX9t8lrZw4zZKBGT3790aW
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH1PPFC8B3B7859
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=umqPj4zc;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2417::603 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 02:12:00PM +0100, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 09:51:01AM -0300, Jason Gunthorpe wrote:
> > On Mon, Sep 08, 2025 at 12:10:34PM +0100, Lorenzo Stoakes wrote:
> > >  static int secretmem_mmap_prepare(struct vm_area_desc *desc)
> > >  {
> > > -	const unsigned long len = desc->end - desc->start;
> > > +	const unsigned long len = vma_desc_size(desc);
> > >
> > >  	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
> > >  		return -EINVAL;
> >
> > I wonder if we should have some helper for this shared check too, it
> > is a bit tricky with the two flags. Forced-shared checks are pretty
> > common.
> 
> Sure can add.
> 
> >
> > vma_desc_must_be_shared(desc) ?
> 
> Maybe _could_be_shared()?

It is not could, it is must. 

Perhaps

!vma_desc_cowable()

Is what many drivers are really trying to assert.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908133224.GE616306%40nvidia.com.
