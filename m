Return-Path: <kasan-dev+bncBCN77QHK3UIBBF4HUDDAMGQE7UQOWDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BCBFB57A29
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:16:25 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-330c9915210sf1742085fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:16:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757938584; cv=pass;
        d=google.com; s=arc-20240605;
        b=FBkWjd68u8wyt1rU+a58E8Xph6zAFqFgFQkyZ4xzw883jfu6l5UdVIT29TwrH7exmx
         aZJF0BW/aspmI2NhWNBbimoA4ZfabCPnpzw09ob1f8c464/7AXbjhZOZSByhHvWoVlmA
         twiTaU0Fx9u4JBOF0XcQGecELgj0Kh2d++gXiIFNnfY3RfOZ8j0UpkW96rec4iCem2tL
         3cuWQXXW1iBMUHrkqHMYKNsp9GeyaDv/SXeRQNEbsH3/8zacx30kMCoAP7iFvsqc5fPP
         8GKRL/fIYbGToBZ/v/hNxGhjcd/aFJt879F/S/5ZE8Qo3oPGIkJLWb+/ZOVoIPUmlHMS
         KRkg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=garqqRRHrVtNy8P++njeWCvm9HDnWrdXwud8x9M4vLs=;
        fh=nXeEkDVuXX8YxKzez0L/Zl7+njxLO/DsjBiB7XS19f0=;
        b=lrX03nc2+9kcDrFc+cZU4FT/8/RUHBwWGpc3o0/LI4akRQrD5mFoVGcHcU8Mjf4uSh
         wgr6h2HwwtqsFEXjDNLfZOmaj27GxgN8+UDBhx++bQSuvqFCqfxWnDpBPUxwx3d6Sl5b
         iydcAoln6FlPHZV3CGbeTe4jd6zGjXsINSCkjRulWVPlCoVmPomP5QDxlGXXyc23L8WP
         SZjJZFQgjriJSQwRY7rccs1dX/Pd22jzUWc35g58ucadqj2H2PdYo+NjbfdR+B1sYMPM
         7DBZ85xzIZwnZyU2RyHJ/TpQ0A63YppxrnH+7Vtii2l52igGRfmR2n5zqy7ld+hQ/Ss9
         XUFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=rR1yMTm4;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757938584; x=1758543384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=garqqRRHrVtNy8P++njeWCvm9HDnWrdXwud8x9M4vLs=;
        b=aX2WXosElvo7VDk7NB8aISl31GWkLEcIeBxSjPjlXj68L/8ry/2R9L3mVR+XbxhOH9
         Z/+f3opHs6ZX3A4usz6nT1X7Uvp/aF3gIlukTFI2VI8wbSGWVtytIL9WwxSBbBoptzJW
         80HPiQGGEmKiIUcEAgDXWQLGePUZBHS68deNtL8JulYff822iaQefZabBPwDEgWnlJIo
         6VLHYZ8TCAdoYmpo7dbtuXSx3YF7wogOO5ICXQHPqNOECdtzFAI/x60OZpJbL+acETqX
         n6spWL2dqPvJJcbg6FKzNEY8L9+WvCtbE3d7h1QM+I6JeZv9cthrBWmNjD/Kf0WPQ8LS
         +2kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757938584; x=1758543384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=garqqRRHrVtNy8P++njeWCvm9HDnWrdXwud8x9M4vLs=;
        b=WCLtMFvhRWCRks55WE+XlLj2VvYzW5ZaaBcjBSmpbjkfdvyW7PwkQHA2ULNpdToDDt
         M2HZ7R+QRcy6yo7nWcGWdDMKbY8u1e+1WkAfUJgcAeULMG2Yll0ZgGrSJCX0fnC413GW
         /YEjNO68y7pRkTWPp0pvHXcoqJWKqPUdd9zEE9btImU61eaFCkczoNJpzTY1C4f9jocq
         miNV5aYS4MciTdkh4NsBaAlT3V2L34u+Gvczc3dXp+k45FMz3n1tyK5gZVDwBcnEV9Wk
         0taFs9KLZD6WMO0/PhH29DghdJUfHdTy/2h6QXNw4vlMgJvsrLEcSzNPvH2TtwGbu/lE
         1foA==
X-Forwarded-Encrypted: i=3; AJvYcCUymKGA9TN/N4YatYG7a6ycrVcCk6UETZb6VUlZO7aKUawm1nylqxjvJF6pUhyIGw9KUPwb/Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzg3AsW/3doPzITEImX0T3cDbxDCBURxz8gg6Jrxn4uqhKXYppL
	6hQkkAg9BRXR3tNbQgBcmGf3sBbigKVaDaVnnXphMWjb2GHBInHPWHlO
X-Google-Smtp-Source: AGHT+IE8oyxQz4yR6MzpAj88Gpar8BURg+7VUjUkLzdXTtCEgCA/LqU590XUNd/YE55wGh4l45Gpcg==
X-Received: by 2002:a05:687c:46:10b0:331:7220:f4d6 with SMTP id 586e51a60fabf-3317221260amr1947124fac.12.1757938584128;
        Mon, 15 Sep 2025 05:16:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfI0/1p0VX6oqR2w/XrzqzRSxLvFP13dfc0ZURjeUPfOg==
Received: by 2002:a05:6871:330f:b0:31e:1dff:4875 with SMTP id
 586e51a60fabf-32d055d8097ls2165578fac.2.-pod-prod-09-us; Mon, 15 Sep 2025
 05:16:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWdvZvyRpxx1B3bgb26g0dfkXCfn/1ssf0G2ssy7bhWkh78YDNc/hEAA+RiqeXm4ieEyxGPhrcXNGQ=@googlegroups.com
X-Received: by 2002:a05:6602:13cc:b0:86d:9ec7:267e with SMTP id ca18e2360f4ac-89032047f2bmr1454142639f.4.1757938582808;
        Mon, 15 Sep 2025 05:16:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757938582; cv=pass;
        d=google.com; s=arc-20240605;
        b=FI9JMj4ZR6a9hDVvkkL1zh/humW4ZHojqkoR8vv3yuLDbmGLrVc0l6tBubQkX2ng7M
         2ntIovbR9pnmZ99icbe0qtLMaYHzb1+l8emMvo8veSj2pafWh8jHjdZSJ38r0Wekmhku
         /nvTrTcaIoarHIEFycOF6FDvZ7ft8QcPm6exnGBsgJ6vYlXijJB/CAT3NsgeCDUdMeN/
         Gu3ZXD3v1t78ghAhxMUarrO9893tzMRcTmjayr2tDhKseKaryMlrWwsiUdL/o06rQQEv
         lMh0aTlJ+1xfmkvG+a8od6r6SAyqpmbxn860ROUHrLEOAEvBSWRunQG4kwBoY4p942Ei
         xjCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9L0MevsaZl4URnpEE5ruNJ+WATqAH6AxktDl4S6aji4=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=jwZzb/orGszyRXc+i63MpK63I6GNslYKXNKXNTYLwUg87788bj26dTEcbDi+BW4+X5
         anS0W7f23eQR+O/1hgmXzoVYZaXXs0H7xTeErnkp1py3rUM5jJAFdU/SXZqs6Lnw0UgY
         Z0P35CSyc5ZycDndM4XvX7DLCV8de8C37X9BtZiVkLbqhS2y5DNrOq5Wgz36sro3H1tR
         vwzfd8GiK1eFmqmc8J2x51rzPJ1TurbXThx9UwF7XiqlDqG4yRlvLJdX7iJ2K4ESlAe0
         WMJsLB0jq1qBuN7pCM7CjmqHCNAY3j8B/IWbiB4NWlp1GPSFW+PRet7PbSk+LKcUzvSE
         LUKw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=rR1yMTm4;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SA9PR02CU001.outbound.protection.outlook.com (mail-southcentralusazlp170130001.outbound.protection.outlook.com. [2a01:111:f403:c10c::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-51ea1b7512asi19254173.1.2025.09.15.05.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 05:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10c::1 as permitted sender) client-ip=2a01:111:f403:c10c::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=v16KWpkY3ImVT7qges0lHR6lT7j5DpTGpknezkG5+BUVFtHh/ACwDMCuFCks0M1M4uI7dsgQurF1BHur3WYN9tJ67vKFtTG1NNa8TDFOQiBFZEhsO1yP9g+UiSfzvmFXoFYCtFa3hTrxdwFu8NUtPGY3O3uAY1VGxogBpxnxX462w3vCTTUYLrnAZiIU5iYOiRMaDAf8GfHQxAiVBmoK+t4RoT3E6h4mRzcn4m6g9RMHc4e1+5/z7uQz1KLfq4chgtUiM5wYpaap+uV/veh+KAeSleyArSyDLk9K6SOLyoEXkUKTWWj/C7RsZy5bgEVMRHXQopGwwcqiiGaBeSq6UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9L0MevsaZl4URnpEE5ruNJ+WATqAH6AxktDl4S6aji4=;
 b=RX7ZYWqO9jflUsBRexVAGfbTW97vj9htFuwgmCTO2W9zsaJDqY4wWOHkBiqJ8D0r2IYFMNO06BZdrYBQqPnC1usoG7AN44CR4NtmheaWHXAflDsvmIGVwPpdq8JYaoK28Au37yrAJU81e3FHs0ZIYvCD3MivUNwtoKPdPU33/XCWTtatoRdLJDi0+6w9CE+Ueo0wf1NFberNDWBqkRKliwCwbxGM8iFkvq6WyxFvRK5clvyWMmfhLcyN/ChNxvxuV/eFGk3S2/KlB+mW3D1QqDf330i5m3X0UhBPG/kv921plmP7m6QVRaVcPbj5REAmgOnC6a8+X1gjiA4dxsmTNw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by DS0PR12MB6632.namprd12.prod.outlook.com (2603:10b6:8:d0::9) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Mon, 15 Sep 2025 12:16:19 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:16:19 +0000
Date: Mon, 15 Sep 2025 09:16:17 -0300
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
Subject: Re: [PATCH v2 16/16] kcov: update kcov to use mmap_prepare
Message-ID: <20250915121617.GD1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5b1ab8ef7065093884fc9af15364b48c0a02599a.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4P288CA0046.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d3::28) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|DS0PR12MB6632:EE_
X-MS-Office365-Filtering-Correlation-Id: f35a159a-93dd-4f31-8c8e-08ddf451ad2a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?FJ+GMy316Ah1W2PRNL2uK0E4d8rheS0eMVrJO4fwtwoJVvgRBslOImN624yP?=
 =?us-ascii?Q?qn/ODRZ+eoKmIUc/H8K5IVkhwAv3B1GndIBDMGBA/M2ORQkApBPyju9k776E?=
 =?us-ascii?Q?sPmiT8Cn2OcosjlMmtT9CiugaKagkVWjraWs+WUSjLf40pRrnIiJaH7qmUUR?=
 =?us-ascii?Q?D1YnJmUzM5/sKkSFbA1oYJt6UpwBYpLXAh7JD4gd+nPqoh0Vt0OgQTwCTQO2?=
 =?us-ascii?Q?pJ3w1DVazyydFZFl2tpsflpn9qZSwyWfRqxaWDU6INzU2R1RQ/zQ9IqtCXrL?=
 =?us-ascii?Q?21QRCOZLg0nI1FMwtK5xxFuABD5QHz/UynorLrHMx7g4C8/wc0jonjscEwQc?=
 =?us-ascii?Q?Ez2cXZJNjyMH6cTU/WmvIXxEauwrLLPIRRI1x63OAGB7zhXimQTj4gAFXNA+?=
 =?us-ascii?Q?dXFX49ljNP4IDBh8MqI6sW/YS7RBi32O8IW/z4aVia+Z6/MbA116VOid25qn?=
 =?us-ascii?Q?WWnDm4WwNUWVDxOyo+IL8yxp0DpA26BXsIto5Wf7MVZHArw/FOldfb0/BF20?=
 =?us-ascii?Q?+khK0J36F+nUIPZ4n/o0rDfRtrj59JU/BpXEN7BYjOE0EIJ5NANghpy1oA1n?=
 =?us-ascii?Q?T7esIJ8gzTXWF2zhIrpWsfFz7DUwIqsen6rqyYlka6JvljAQnnexWrZKidKM?=
 =?us-ascii?Q?bwsaRJ7DyYC7hR/hQ7c5MyqzErxGM7td9AEPTf5tN9BvZn6HsnzkLjqQxBfJ?=
 =?us-ascii?Q?rCFMelL0ZAu/0MVguJRRjU5fo91scmSc/i5ADIb/BHc2D3TstjxcAU0eFYqA?=
 =?us-ascii?Q?OSuiBwFrSe/Ow8MggoPW0gV+rPbhvKgDO6ZIOoGRramKN1i8sw6Mo/oAqqie?=
 =?us-ascii?Q?7hhUPSfe+KKWu6k600DNeEH4wwqglRs895mc9zS/Vf05VNajpIWCDOATw4LM?=
 =?us-ascii?Q?RMhP34Xd1TkhWfkQk6V5vsPaqjpndfnGlqinJ4M0bSXcIVPqBcpW68RyI0sr?=
 =?us-ascii?Q?IrSopJQFXWmhOOcXAC4WRJ6xO5Nsmymbvg1oHipT9KZlwozBnz+4ikzmUPXh?=
 =?us-ascii?Q?ansdYgwY+CUy7+Gn6dLYTLypjn7fyYc+BP96q3aseS1YpHn9+WmrR2EYz0Xs?=
 =?us-ascii?Q?p2kVhLx3mvujLNXztcyF9ouXiy8NJ+HWuASAC81a2N4S0JzuKDloN8BG1wxW?=
 =?us-ascii?Q?efm1gDyw4tAFPYBm75o834G3X60PnZd8nDPeD/uQaP6SIbupr2e/0zDfzRlN?=
 =?us-ascii?Q?9t6RLcgKXLFpbeUfwtjAWQjPN380JM0SoN92vky3WFaZCfq5Xuq6av/PJmD1?=
 =?us-ascii?Q?Ka9tulrWkP71qQ1y3QKWGOXgF62unORpW7h42NyJXpIccfEQAlJzSPsaXvw9?=
 =?us-ascii?Q?LJJovAtdN7zusj39sjsmd5cA2x43S3LxsWC59F16Gf2k3gXNmPOqltU/08QF?=
 =?us-ascii?Q?5gMJ4OxrVFtRxyLfoQ0XhvfAA169q4zXhcdoaBV4Er0MNKjj5LDZQkIHkTtW?=
 =?us-ascii?Q?mOej1NYler4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WgeUIJi5cY2sk5lj8fMjb+H+kNFLtDA7lYE2X0J/GN5d5Ob0yf+l1+EZdKBo?=
 =?us-ascii?Q?+RhTJ29Te8+tf3x4tbPbdBM7rBkIiTVK4ix4yblQnvO6G+L9zbhliXopHrd2?=
 =?us-ascii?Q?NFFkFVVeYNMQA/UB1NmQSJzE4NFPmO9dhzdjYo5IwmCpkQ1vYtDBNo8y9JB5?=
 =?us-ascii?Q?LOKYnrViMUuiiVGlAoQ5ivfDXViVrxsE/Cx3oreqaoaiqNjdkcs0T2F2hj+x?=
 =?us-ascii?Q?u933Qdle6HxY8QXI/Clx6OQRLFaU4w7qL+DSCETS3JD+KD3v+8ObP0hiJ7tz?=
 =?us-ascii?Q?QHfprJZyWKoC1gBKoWFQFhHnJk7nUqnHQEhohe8kFWr+ieOCFiNO/J5nh5zn?=
 =?us-ascii?Q?c14VmrL3LInJ3Sw3wb1CFw9gUjBFRsCKqYeP3Kpuyfuom2ncO0PbAorjCpKN?=
 =?us-ascii?Q?VQqgeWK1PAw69K3bCLplbimtl2qhCcyRKcoLgcCQOgHVMQTZv3hXChl3GNhP?=
 =?us-ascii?Q?jPkrow1WVCFc9ElpIqaXejhoIsPSsBG28of1LCkmM9OY912wgnVg93ycxa5h?=
 =?us-ascii?Q?kXqsYL7wDrPgEoJ8R2xBFCA6+KsqwVrXQSHOsROsW8jWAe+3BNiQ5/f1fIwf?=
 =?us-ascii?Q?LDeYaWNiMjyhiEW1EguQQABUcOMsP0fbe8yYCScBSzVNix1JMT2w4exz58tO?=
 =?us-ascii?Q?ngtwUsSXRXmL88OqDha1EivU7oyhVgXmjrndhSvMiJOFN4OiPswEX/1lFEwS?=
 =?us-ascii?Q?ZOr2gthO5JJnLqYuN+qkGt0U+/Eka3+KKoDKtSk1KtUD2k0zHq89sSOT3dHW?=
 =?us-ascii?Q?JB50Ku8O8S6zPmNR6p+xvGQYnokn6ncqaGJ/FDXyQ6hhq1aWm4UWLJ2oU4cm?=
 =?us-ascii?Q?tS/g2sM8/YfeNVWtfv/vMtfNhKPCdh0p1bpnCJgOiTrDeX3y+gxqCFzSQYtS?=
 =?us-ascii?Q?mOtawXaV2y9IbYMwRareJ/fdhJRFOD7ZC1lAGh+oFuTlpIwgDyEOj622oqF+?=
 =?us-ascii?Q?/F8J2R+GwDE7cK+ksSQEjWTwJdjqQZ4RDFwRzVXVo90323HTq4HHcuQ0habU?=
 =?us-ascii?Q?zguwnBRC5Hb8K0r04OcGoJ6PHm8MlEvb2TT5QhFfT2+aNsKYNVqLFqL899gp?=
 =?us-ascii?Q?NWwA8gjiGgtYpUFUu+Cg0ALcvic2lgHyMFdayXTQ98cynm9SmVrMD4qZu1+P?=
 =?us-ascii?Q?mIZBVI1Oa+nFyuriJnScudW8JM4zxi6T8rIlVctAoVFaV1N3vx+Km/9AkBYd?=
 =?us-ascii?Q?+PKBlXnYdcnqP9V0ww5eldolEmyLHbuCpCTVaMxS1aQ3Le6kHCrwvO6hzw5B?=
 =?us-ascii?Q?DXtVAV4nHiUarz0VQ2pwY7m8GDWFtI8itNriN9vFG1n+y08VxRsgJX9oA33C?=
 =?us-ascii?Q?4HJvlVsYd8qxMXz9jufApjap6Nxq1MqT3xpqyP4EtsL6TA0F5apODmOPnVcR?=
 =?us-ascii?Q?yS6NvJ6OMaq31dh9bsPKmxY3HHiC/cHFdE1hUwSJaB4Nyy+k43r9GSS1nK1m?=
 =?us-ascii?Q?5EIljg2pSt3bKjfdKoJFbiT/eAoy+/zrMIKEScHw6y+EOezTjqB2Xt2o4Oxd?=
 =?us-ascii?Q?IvZnZoM0NAtT81lqejPsR1wZiLQIryf6qKQ9n+qWu9RFNoBFrCApj0YGSwVG?=
 =?us-ascii?Q?tDjxwenHqv+3Ncshhmo=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f35a159a-93dd-4f31-8c8e-08ddf451ad2a
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:16:19.3375
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DEkAUuneTEE997o8Ffh1wmwK0ptrvvqE/Q+wl2h3x6DZFuitcS2eewWiuv5vGq3l
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR12MB6632
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=rR1yMTm4;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10c::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 10, 2025 at 09:22:11PM +0100, Lorenzo Stoakes wrote:
> +static int kcov_mmap_prepare(struct vm_area_desc *desc)
>  {
>  	int res = 0;
> -	struct kcov *kcov = vma->vm_file->private_data;
> -	unsigned long size, off;
> -	struct page *page;
> +	struct kcov *kcov = desc->file->private_data;
> +	unsigned long size, nr_pages, i;
> +	struct page **pages;
>  	unsigned long flags;
>  
>  	spin_lock_irqsave(&kcov->lock, flags);
>  	size = kcov->size * sizeof(unsigned long);
> -	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> -	    vma->vm_end - vma->vm_start != size) {
> +	if (kcov->area == NULL || desc->pgoff != 0 ||
> +	    vma_desc_size(desc) != size) {

IMHO these range checks should be cleaned up into a helper:

/* Returns true if the VMA falls within starting_pgoff to
     starting_pgoff + ROUND_DOWN(length_bytes, PAGE_SIZE))
   Is careful to avoid any arithmetic overflow.
 */
vma_desc_check_range(desc, starting_pgoff=0, length_bytes=size);

> +	desc->vm_flags |= VM_DONTEXPAND;
> +	nr_pages = size >> PAGE_SHIFT;
> +
> +	pages = mmap_action_mixedmap_pages(&desc->action, desc->start,
> +					   nr_pages);
> +	if (!pages)
> +		return -ENOMEM;
> +
> +	for (i = 0; i < nr_pages; i++)
> +		pages[i] = vmalloc_to_page(kcov->area + i * PAGE_SIZE);

This is not a mixed map.

All the memory comes from vmalloc_user() which makes them normal
struct pages with refcounts.

If anything the action should be called mmap_action_vmalloc_user() to
match how the memory was allocated instead of open coding something.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915121617.GD1024672%40nvidia.com.
