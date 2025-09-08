Return-Path: <kasan-dev+bncBCN77QHK3UIBB3PA7PCQMGQE5WTCQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DCC2B4925C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:04:15 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4b34c87dad0sf128604211cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:04:15 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757343854; cv=pass;
        d=google.com; s=arc-20240605;
        b=YNb7IiCByBztZseV6uohVkXNuOR2lezQjnhnrXcZnMXEd9FXfS4dcEDi6Eon9FkxN0
         qpqErOQBKAveYyiE34/71Vb4i/WSKFNPd3hzvOSnIlgF8ajM10HktEn2+T1A2JYqg3wr
         2F29qqCOS2Unk3mu+dLQ9g26NPZQ9AEv4skVaVd/7TRHg4Iy951GsAdp6fC/si5pGHLg
         OQZIPfk6W5VnS7CFAuMJxoH1Tvb6LLiWwEwIeZxlLSJWEAnuH+5ague9gK/4omq4hHmd
         s+9SE2F5FREY3YsC/lk2Cdz6n+yBF49FwzS555ZGqCn6vwYMzF2Gyp/Mfr6ziyng/KnA
         ev6w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=eE52r88RfeusZJHa4fIS5k+pXd0LGbajIjLqbWVz3EY=;
        fh=FqjPJ9SyPr6g0I61UZQqowhPt1d8my36x59jBXAQo9g=;
        b=Gcwp4dot9La2Cwl66rv6wkRXmN0/cREV+NmBbIS2UAthNCOrHmk+/BmfJx6gEPdSh9
         TwThjZ8VT5hLhNxNRUKeQNZ1/RqzfRnwXcMx/Jithz9Hw8pYmD08NpwpeqMZxltzKGl5
         gRvpzAxguDCNxJDQkyBKpInJLtA2/W3u11tVs0veaWaVP8QzOvt3VCsmLaUUkvGXq2z/
         +WQ5yZU8Gnu74nrHSwzCRk+nXE7yCnjlm2R4/P7waQdPL4QYUVMb8MnYcUNQ8gjhQn2k
         gLQMvrGAyhGU3MYM3+w2YRB2dF2VZijFXb8NYCFhTNpczybT3iI3gQ4c0PSBc+NZAu9K
         LF8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Q2MzGcEC;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::60e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757343854; x=1757948654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eE52r88RfeusZJHa4fIS5k+pXd0LGbajIjLqbWVz3EY=;
        b=jeSOKNohuboSXdk5n4tmBKd2pPiXTcS36cMYXIiD1AU25r3/sdZSzNSYM42A0eiNAq
         jsWpYaBEE4+xJksa71QfjnWDSbO5TGn92eY6q1dAIZSPeu3q4z5OHGyb6XHRujLxNWeA
         NRD7yBAkLp62xPasb89UoneE8QEIBTLd7gLeftMXIBWSV8eQrHV040np7vOpkPZt2WCM
         4fNdf8xagBA8lw2yVVdAUyPbmM0B8+H/OY0HR6XLx/adf5RsFXa7TNh9YDyC1AjSZqDT
         26jdkkygXaJ6jnzS64zkiMnX6BE2n+kfdEN5BXfC4rp5mnYj7E7Gq7KDEK6i6GQNZOgX
         /Y5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757343854; x=1757948654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eE52r88RfeusZJHa4fIS5k+pXd0LGbajIjLqbWVz3EY=;
        b=cM9pPlYFCIQgR+FCYSbbccGds4D1AInusb5gLbH0Y5nxtRKlftf02CCDV8dwuhm9dI
         CsEyijpF+3G7NCsl705wZMJDTIc/4ZpOXgC7F2LwNX2ZCSLcknmXRouQhhtchPD/DPhZ
         jYQ+ESC3d1881UwdiAYf5YhOIOSYIhjKvsj4b3xXbXf4LyZm8rNRFGIc+ucYJrP9wirz
         5tgMikCcz0OpfZwhSs5ZxrbMpMb0q7n750DUpNLudvI3UC/rF41Nj9sfNQE+npbquLc6
         b2yXcj400gl/i0yuTO3fD5sWtd05cldmixwprwlxC+Y/hepCvlcFvz1ijGhfY1spoYHh
         cV2Q==
X-Forwarded-Encrypted: i=3; AJvYcCWc8EA3D9NLoNCI6oLAd+xID03gmf17cHuUU0zAhJuZcr5yXrBfNgQ3XCMOvnMT/Wl6cow/Ww==@lfdr.de
X-Gm-Message-State: AOJu0YwbXlYXd1Q6uQcnLCFT11eQrjKKe7pY+6sLQoLnFXTf+l9v27N3
	gKTq/2Xw7FOTKb+vott/10blpOVy/gWX6g0Y9Zs+hsv1spi6UIqyKeOo
X-Google-Smtp-Source: AGHT+IEQ143b/uQbyrSJMttq5Q5X1x+IS6+nb+nlkKFYCRDmzwidyjWGQ/Chwwq/dKWY9a/1nSknIQ==
X-Received: by 2002:a05:622a:38a:b0:4b5:f7d4:3a0a with SMTP id d75a77b69052e-4b5f853e1c2mr90051091cf.52.1757343853833;
        Mon, 08 Sep 2025 08:04:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeFtuVsHFvANgWvVgOSag2sV5Mfg84lhF+FHXCbi289Nw==
Received: by 2002:a05:622a:10d:b0:4b0:7930:aefa with SMTP id
 d75a77b69052e-4b5ea9fd9efls69302731cf.2.-pod-prod-05-us; Mon, 08 Sep 2025
 08:04:11 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVhRwigvdI+9Eih7HFf6KYaiDALY65wSFNL6VY1c/31hxFArSdnKRUd+DixgFv+wBmPKaklDRJT4VY=@googlegroups.com
X-Received: by 2002:a05:620a:4085:b0:80f:da7f:6140 with SMTP id af79cd13be357-813c596fe0cmr768208485a.49.1757343851721;
        Mon, 08 Sep 2025 08:04:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757343851; cv=pass;
        d=google.com; s=arc-20240605;
        b=WyjxATglg3sLesdAdM8yhqZoicEQwkBHhi6HlasF7mCYMcZem2eeNs7sMFc2EVd320
         UM6qhpHXLBd23fxRKgBKfgc00W5x+MfI15F1hM0GxEVrHErJWZYNCBpRdDsbE0JRqV6R
         L0RzSGYEO3DFKFJx+wklfadJEZL4UfQHsKs/QHMzVqxs9HNSB+OmEMP7yQn4eLcuBAl/
         O7jXgBswln73suyu2+se3dsa1GaaH1KZFnlX0WnD+lb0W2n0Gx6AjBNWy8z/QnVba+bx
         kYW6IyRk3fe+tqQ+7Wp2oVJX5nrtunHE51mgtyTJ2z4OTskkSB3MSPG5LyqHFgbhloms
         YQVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0pFnbzELzeABeu7YvtCA3xdHcGUwbc7/fpG0pw6zzHc=;
        fh=Ps+RlL9VF21yNWcREnIb9Q7/4nHOIvGsEfxYu4BHkkQ=;
        b=M9W/aJgt9smCWer/HdFGKAVz04k02JorajCODr9LEaJNxeRCKpr+iJh8JvisEs9kPv
         ISDXnhmdnaalote1Ryk/PK8i5lVJJHu0GnpVSneHJW/RcYzaQfMSoM3ta/azCE3sMgsU
         sup3jRVokv4hnFchRk4JQBwhpaWTUy/RtQYEmQaP5T0p1J7aUy4uylF2yDA4WdJ0xA9o
         C/PA0DUvmaomWk9crM2mUETAF696XeD6ehNM/VuWZ8FcUJ+plYZpulmocEr7R/kuD30V
         9RhoMI5LnB3En3moS035JTaTt0HuBtqhwSfKlug+u2JTgKq81ZXmOTKu22Ys6NZ4zxl9
         CF1g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Q2MzGcEC;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::60e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (mail-bn8nam11on2060e.outbound.protection.outlook.com. [2a01:111:f403:2414::60e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa5fe40d7si54884385a.2.2025.09.08.08.04.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:04:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::60e as permitted sender) client-ip=2a01:111:f403:2414::60e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=cNhATiDXxoFtcXXEfZFveZtxUvaOdSgRFL87FojrjLtUX7F7YyTNjVayDqd1Ca+GWRHCnjQBSryhJVklAtfdsXWlIcSwUrOSwpaDFZJK0aQG8rAMHcXcrUpp9AwT3nesGtlOlRy9T5P5svslpKNOEV9o2pyC73xh/t1YzOQAKjOkz8noQc0FU83LKKXNC+XcgkaSzoleUNjL9DSA6PKzshUr3FhyK9bjCrRU8jOMfPGS+QGZIWqovmqSJRCbDvqRVV0Qbkz0ACiv8scDtWnNcQ2JGCs87yW8i6iDWfi9BULUBQio6L0F5Nk22BFw361Vurir1UgNdxyjt3FxCZ+0EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0pFnbzELzeABeu7YvtCA3xdHcGUwbc7/fpG0pw6zzHc=;
 b=JbNF0PEHKsiRn3ahD26ObuNuldEy05kWswRBYq1b5Pz0kUKTXH2HJ1pGR1qIEUpD0KpRJ2F3IBVKk3fp0AQdG5VKBeWvIL2e4+lgEU2oyyUE2AUpdXDy1Mw+0R/1PYk++Ccn6FlEZlV6ae6OP07MLKthe5nfP2cMs69jusJ01AY7sfqDS4X2nDkgUhP04GVQSMDVXflku9DkLsYQfd/Vzc9dJU2hWo2GRa1NzuVGFsUrZ20YTGFmlmUMpdPbK8e9haPw0HIIXm4SboXaVI1sI38KPcl2wYgdp2EaqEa3mldCWslOxBLfldkHWIitvbMeb+gGKeS1AHAZ1RlPhcOa1A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW4PR12MB7288.namprd12.prod.outlook.com (2603:10b6:303:223::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 15:04:06 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 15:04:06 +0000
Date: Mon, 8 Sep 2025 12:04:04 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jan Kara <jack@suse.cz>, Andrew Morton <akpm@linux-foundation.org>,
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
	Christian Brauner <brauner@kernel.org>,
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
Subject: Re: [PATCH 00/16] expand mmap_prepare functionality, port more users
Message-ID: <20250908150404.GL616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <tyoifr2ym3pzx4nwqhdwap57us3msusbsmql7do4pim5ku7qtm@wjyvh5bs633s>
 <9b463af0-3f29-4816-bd5d-caa282b1a9cd@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9b463af0-3f29-4816-bd5d-caa282b1a9cd@lucifer.local>
X-ClientProxiedBy: YT4PR01CA0279.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:109::17) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW4PR12MB7288:EE_
X-MS-Office365-Filtering-Correlation-Id: 62cb388d-db7d-4d65-be8c-08ddeee8f497
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4LMm5Y7Xx8YyZ3nMNGj77qXb5JeM+tvTI8NUduVrJnLlYbVIS2ygM7wuY0Za?=
 =?us-ascii?Q?ni5upQdYk8wLppaCwEffq9sBJ1ltqZuolcA5WL/M7y6lMQWQJVmmfQcGa+tr?=
 =?us-ascii?Q?fFumPC2YHtuzr5ov5ubplkLBAeNo7Xtv4cg6as3aAkmfiqaETYcfySTerce6?=
 =?us-ascii?Q?xcwBP7qXahbG1UykKFmMwtYLAf4hEXrAPhuJCyad2lRscBXnAv/fzfnIQWLZ?=
 =?us-ascii?Q?DJcxipnKqa6h18WIKJcX6Bu6bd5vTzHPqXXRGL7i/zatElgoNspz42/dLVR2?=
 =?us-ascii?Q?P6pRNCpo8SejbuZ2BDkwgxVaW25oleH6NS0F28R9OMwqTg2iwPBA4w+6oy4+?=
 =?us-ascii?Q?9Uhztg6XzN06O8VAJWIAODzM0/TndqiX32KaEmiog7ZYNazfjBDNJlB2fut5?=
 =?us-ascii?Q?bqWC90sdVtApiSZIlDc7m8AaUuw1ovmOZDVK2VjmqW+JQ0Hdqnka52vl3Lz3?=
 =?us-ascii?Q?xzBxQkli2mfUIKuQy2E++Si1riQ1+2hK/RQsC9D59ahWc+asas+WTULpeJ75?=
 =?us-ascii?Q?JARsSCclz3xWXnxBc4UE8qBGh5V9j29KxIQJPJ/3T14xEWa7bRWi9ZlX77RO?=
 =?us-ascii?Q?CMmiRKtCHipIMb9K7Axd0Z8TRsJcrz+bXNqhV97rUelGPtzy6VpGkZcvcOH2?=
 =?us-ascii?Q?zlUeBr0B/9Fve0QWlIX3WokcSg0iJf2+bCT9s1ZTdboMHAv6cxRa3PgJKrD7?=
 =?us-ascii?Q?RHsxtKMuDjQ5I7ILXvJnzCyJ1/2+9Ng0+YvY/qIM5ycDJ1g2tm3558PHWPZl?=
 =?us-ascii?Q?a3QOCV2w2Zm8h8e/stwrNLOS9b1ZsBob4HBMM79CPp2sdpEwump1wwPmUK9R?=
 =?us-ascii?Q?SUAZntV6gJOzLQYbrE7Q3W7Bd/1yZz8McI/pvNvnoeO9JJTebSSmQIlE0rl2?=
 =?us-ascii?Q?U16H1KtCsq0EPTSJUpNtsyQGY49FTmH4qkKgOHL1hjVdsdZEf7e/h5rKEQ5p?=
 =?us-ascii?Q?lNjPbwqdOh/wrsf/A/LFtuz8ghc9RlyuyLR+Y3o8dwP/V5ObCZPok2XDvK0L?=
 =?us-ascii?Q?09CLrJe4gK+beBlHg2kx87FBSbPZ9x2ctYnMAIC7UfeZ3kUwRPdZyiatZLmn?=
 =?us-ascii?Q?UBMOgmM8fOkpvmx4r1mhJnm1iUx7MC3cjgOm0/JmMIIzYZoQfeX+m7mhKB2M?=
 =?us-ascii?Q?zk7X7ucBwqcl8Af3X8Xuejl6ai37FrQcdDuhUs6giuQyFxPYJyVaLE8NeX9m?=
 =?us-ascii?Q?ZsCKpriy94Gq54th6Ii3+fTogUtRvqcUU8357k3sA5mvYOqo9/bePFaeVMQw?=
 =?us-ascii?Q?Y6jz8oDLzLiOh1JzQ8acwW5J5bOcjzL6VY3vPiyCoBamv3w+UO3yt2X6i/0c?=
 =?us-ascii?Q?OeH3+npk5UscsERBvjou6EWdZ08mIHDP4/bK0ZGmcNSJuAA30jibJBxp7brS?=
 =?us-ascii?Q?z/c153j7t3nVFKM+hTGaTWi1YYqVRNQ33xYpQu8XmXhlqS57R2D+EhR242B1?=
 =?us-ascii?Q?TsgTFMEbCmg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?RdjXWPDyZNBWQnk6yjfmYmYMos5vLyvhYHvMy2zFV1T1ANTtF9kb/Pnu5dK7?=
 =?us-ascii?Q?baTJoQjgUebzcnGg25kLlGIC4O4iFlRoI9BCnue3NYlSpYceXfxsMZ0gei3V?=
 =?us-ascii?Q?6l4UhTqgL1XsOCkrTW2R8cJNc/sSQZD1pBLRptOTj/UdtIk/jpmyNrqdkwga?=
 =?us-ascii?Q?Szrcp1yK0PxFOnkCnLTHDd3uMzi4YxXLHaARHz/uI8jc7rwYfUqync3iNfTb?=
 =?us-ascii?Q?z85263l1cqVbcAzvKCeDG9zdJUrWJwc8gdq86n24QwCLlx1FfDHJBasURTbT?=
 =?us-ascii?Q?RPGuFSIYIWnjC+ZYVsOd02dkqwS3W6WqCxQbORtExCJiRvui4jrrVgzlJoFc?=
 =?us-ascii?Q?VdYau3AqVxQxx7DKFH6V4lP3g2YGZWQBX3VLyznAzorTWcMTOVCnQSWALMCJ?=
 =?us-ascii?Q?kM1IG8GPtCzllps232vX0eXduf9A/i5yLKL+9TJyeJoGVhFE9Y9ru7ba3sV0?=
 =?us-ascii?Q?n6fkvq55e3NKz1RiKma6ZVYj4GfVUT+6Se62TuLPHq8Q9vh3X20Ft+S9xlp6?=
 =?us-ascii?Q?ixd91sLzQOKhsTxDhK1xTuJxdclsKnqjU8sO9BH9GRqoxP5em2UQLtQRkohO?=
 =?us-ascii?Q?pZDZL8szWFB/2zDkfMoUEod9K3IMMQg/uerfMUAA1rM1DN4OuRMhZer0Y37o?=
 =?us-ascii?Q?Hp4jQ7WSR374MmPP2Bun3j4Lid2uoC0LMjqZFDFVnx/xFM3DtbbkOAe0br/k?=
 =?us-ascii?Q?XnzMAAFnX9i2HiwP6GpQFZtAuz0d1QlC5IxHhbWImR8HGYp5kyVXSypQK6/+?=
 =?us-ascii?Q?Vtz+Pjn3ml9Ku3JEvj33MXfo6zdAQ4rk9IV++OzB3T3TjTpnDuTYOn2NH6Va?=
 =?us-ascii?Q?bq8tZIERd0usTMhczrzyFBJMtLH3nCI+/X7oRlWX25fLc7PkmElK2Y86m5jI?=
 =?us-ascii?Q?0DiIe7Q9jkCPJB1zTP1RDqxgtGO7Bzad2YN+DiskuNgt7ELwThj/tO3Kedo5?=
 =?us-ascii?Q?OqOpRPn1Iuh2XqLf97INXjjagwKszpr6ZwARf8kSiXR7oVsRfhNaD8tUIvtl?=
 =?us-ascii?Q?x4j3CfC7G3Jlk/xgFiQRcJcjZWMm29hX/6QWJI5OoplK6o7HWmCZtaWJ7P3H?=
 =?us-ascii?Q?u/CTa319oqFEdE6VHINnX1TieQ6joW/s3lM3s6DJF51IJpVPCe8fjzAck4LV?=
 =?us-ascii?Q?NnmOIBZEyasJIA6Wv6qWHbsb/e1IFa5399VXS/l7zEyrlS2Nee8c9MkDfR/S?=
 =?us-ascii?Q?e7Eqw1h1v5seSLOmsYpLMBEwoZDD8ov+/XjEoc4uaW+FTTe1L/ilZXgyoLGH?=
 =?us-ascii?Q?EO6x59EmtiQ1AYfzDcYL737oqsWEGrLtbpa4ORWtk+Ahkyjqjwb10zXkBDPN?=
 =?us-ascii?Q?2l5Qydrf89Sb45YttVqKFV17uXaH1Wp/I/NfMlNO87FIbiphD1xgDMDYFctL?=
 =?us-ascii?Q?VUz/6ZXVnbwYYpKnW0s8eWUGilC3bWIKbXct5VNaCgBQegNlNMB/DyNH7L3U?=
 =?us-ascii?Q?1K+jx7y0GLNdYBXZjVGwjzHLAWA9c+JtkVbK78D78hRNOTkvPk6wnBeFpSnd?=
 =?us-ascii?Q?sDCmn5r3LqGjrfxWSjqxmYqKULxL2mjj4UjE5RhXbPO+Q4NFZPTx5GFTRLmo?=
 =?us-ascii?Q?UjJ684ZdKqQs3SomQZU=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 62cb388d-db7d-4d65-be8c-08ddeee8f497
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 15:04:06.3779
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mUQlgCPve6Hrk1P15+DUvQRHcERo6HvLEhI+4lf3XlL+h/wnNHrEduK/fYdHAwT8
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR12MB7288
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Q2MzGcEC;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2414::60e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 03:48:36PM +0100, Lorenzo Stoakes wrote:
> But sadly some _do need_ to do extra work afterwards, most notably,
> prepopulation.

I think Jan is suggesting something more like

mmap_op()
{
   struct vma_desc desc = {};

   desc.[..] = x
   desc.[..] = y
   desc.[..] = z
   vma = vma_alloc(desc);

   ret = remap_pfn(vma)
   if (ret) goto err_vma;

   return vma_commit(vma);

err_va:
  vma_dealloc(vma);
  return ERR_PTR(ret);
}

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908150404.GL616306%40nvidia.com.
