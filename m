Return-Path: <kasan-dev+bncBCN77QHK3UIBB45IU3DAMGQEHQVUE7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C5D32B59E14
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:46:44 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-7438209b842sf7932484a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:46:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758041203; cv=pass;
        d=google.com; s=arc-20240605;
        b=bLC0GbMaPVHJKTb0OyRwVzc6xqEZe3t//jUsU20IFP29k6VHIa7k4D1ZW8jmVOODfO
         IPWbYAAc65etxXJb6DPGqVJw3QZleLSZaQM8r6xS0a0jezxFZ5MMx5E/BoUPVEz41N+H
         B07AAil0h+p0jI5H/kXFNFq9Rw7+Ilz+pUMKoR0KENKAh/kRLhe6Ollzxhs7EnJnnvnH
         5Nyp7ZQCphzO8bojYVVjzEm6dxuV+md2B2QHAo4LpdsA7TIQpP3r4VGq4TU8OaxnA5dX
         3S7duE4mKfcrg0NbRh9CNroFnjoiBdcfaK+uY4AHu/eKRRtY6HFxv2lNGIUGt4WkF4O6
         YNFw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tBy2qSBvczCl+CPAWmSoTehO8HGz8KFwWuhQJwCrJMU=;
        fh=hS1a5duoZSUbbKMTXeP1n4+qFJi5fB6I2IiGYLNNqDI=;
        b=O9UF58lq8GzYPfDeaohPkcjXh1LIF2HNA2JVB0LUz44ena7LYSRkTWwkBdubKeRClj
         o+Mn6M0tXdoTbybuuWVFTkzdFAyVnQplhleUjdXGJ3g4lyrktRGQeLkwPxSe6a7LJJzi
         UTfmSopjbFBt0v2XcUhxFCxau7yKPQTvDmtpciwwyphcAqHHZ2+VSLZnk7q7wQI1JtvQ
         ZFIAxNocfJU/uaZL29bj6m3Lf7oMffXF3LNRZnOROcNiNbIwzVegt37BCzHuu6Nwc74k
         LdY0gAArJJO/aZA4uDMaNG0Hwaw6Y2ZS/14Np5Wwf92P+z1/08uPQL2PVWnPHfJk4lXm
         4VNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=WthhqDh9;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758041203; x=1758646003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tBy2qSBvczCl+CPAWmSoTehO8HGz8KFwWuhQJwCrJMU=;
        b=aGmXwzYiEhGuCugC9aX7P3TBX7oxSi8XzkeC5fGXA0ePpqZevgiBErLtC/tj0VSS6R
         AJgfzeuMxFFCS/DgyBlmRT5Y3JJFzGETNeS131XdmzBDO0uCIFmuTtBlIr5L8wS3eOmx
         ooyMXTMfCFy31oZvBmy3uli2PaNJBy2whhURjCfn1i3uwgtuEhfPbpGzsi6xndgk3xEC
         pISqRRZ5mSMgrkkqgBCqwLma27jTvuj6ZVlC7Bigfk3mdoxgkSEAHsZ5Ab1BXHyu6PyT
         A0WSc5wQrBAEiDbVJg8uDY84OXg5ckuRZjrzfanqHDRBN/Nveopt+JNzViwlVuxnjA+J
         KENA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758041203; x=1758646003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tBy2qSBvczCl+CPAWmSoTehO8HGz8KFwWuhQJwCrJMU=;
        b=VyV4jIhThjy2n6/dCPXmFLXIi+b8gVNFyYEMU3cLMuxzxE6rgDObllFBLUd+hxFSYX
         NEaYFNHiSIsid9y1CVsEDMpcDaa4rJ2/l0NXDU+muaEs1mGBDukhM1jx3y7lbFkdI5tg
         DdRztRRGqAL95Y37YZk3zM0bptKGu96plPJUx9gycqm5qb4Tny+LQg3lue/kUMVdnhM2
         t72iRW3jts3VfMKnCu50KJhaxsfLqWliibmGQyLMcJyNin55SWF16ffaNfFz9ztUtacZ
         4rkIlENXbMAF2ky5m+MW7lX76U5pLwcy07Oc8J9r0d0qxayeFkNOy2ad2Sguo7rTFYv+
         0/Dw==
X-Forwarded-Encrypted: i=3; AJvYcCXjQ2cL1WL5wwpILDlEE6sdYuHvHBAK/vyU5tsLgB9a9seOKgK0xvHYr6VQuipRfalNC02vTw==@lfdr.de
X-Gm-Message-State: AOJu0YzKVLdJm9ybvp99V8Wd6bgtH+Nbgq+SLvjj3OBIhh7K/ufU3YM/
	RtVnXWJ56X4Lff/LFhOZ/Cc7baxemmW3iUz8WR1nAClwDI8BQXtL5duC
X-Google-Smtp-Source: AGHT+IHwmhDtoCl8J/M2kf3SI8SseQs2InEpunPbFINblOB6iKG7gMXpeOkSoRx6F8upRkDQC5zy8w==
X-Received: by 2002:a05:6830:82f7:b0:745:98e8:d7cb with SMTP id 46e09a7af769-75352e9120bmr10801219a34.12.1758041203399;
        Tue, 16 Sep 2025 09:46:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4g+W3XUyK4n4C4kG+ohNc1oPAbMVXHoz2Ow+yAtnYSdw==
Received: by 2002:a05:6820:450a:b0:623:4a56:a70e with SMTP id
 006d021491bc7-6234a56b588ls1441216eaf.1.-pod-prod-01-us; Tue, 16 Sep 2025
 09:46:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWFJnOhFGg0hMC+SP3AohhJjPLdMTBTXENhklrYMZP+d3DMCsMlqzVLdO2hKCgv4L4QBSfjDdVgS8U=@googlegroups.com
X-Received: by 2002:a05:6808:3307:b0:43d:3f78:3b79 with SMTP id 5614622812f47-43d3f78455fmr1546268b6e.12.1758041202446;
        Tue, 16 Sep 2025 09:46:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758041202; cv=pass;
        d=google.com; s=arc-20240605;
        b=cgjbCHMW4qb4vQLRVAK6W/9GnMM/N4Hpz7MAPnvhx+0IDChlz942Ew2srbZD+JKSab
         xL41x6S/XJPoZUUMHRh4PHkirnMIm4Lx940Hjmw8hsXdIMp2z3RIghUVfBedCGVpkg/A
         HjPZ6fdPEL09lUA3wUeeVFw8Xhb2081vs1GgDP+podWMWJDZGs2Ck6C85G0XwutZ/u9Y
         +sk8Ge5WKHJp/FkyVHYPsNRMArGrU+uqNdyXqLjNiZMmJk4tJ+kahdOocHaloh6mCAV3
         XVT82shAdiLGnsI61h94XTtJ/q+bn2HGZLj29bTQ6+h2tUhGYGhxOiN0h6+d+1qYuRaw
         6yeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fD9pbvz5idVivI00y4IBedK5vLEhUrKfz9h0Xx+4ku4=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=Pb6mgsjFp4ZlpXFKVgx9LbQl12SAv5EH3we7w3HKdtQ9m7W44G6YYHvFCp+ON/59Vp
         V9HK8dxIn0oG1KR27qzYfO0ddxXL+G3yeCJl0AGuAfP4BJkQueTHxFjYS+eoQLxYrGyM
         PeqAhl1oa/7sMKP5cvqTMwfdC99Z+bvYTYwzONwsxK4NhS8s/q8J5vj7OsgczS+Icijr
         8V125w8Akuhn6wTh+/SUxLC/gZJ8lwjGPcqW5J+c6KhoRO1B6vVuRthM64bWJhH/fXiO
         1/5xwJHb3ZWlapFXnRQ5KOKndD832zgF/rQ8kxfOs9mBlZ1ERoxJw7T6YBy72mLXiCkP
         /E1w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=WthhqDh9;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CY7PR03CU001.outbound.protection.outlook.com (mail-westcentralusazlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c112::5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b8dbf9ea9si59538b6e.2.2025.09.16.09.46.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 09:46:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) client-ip=2a01:111:f403:c112::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HlIw7WZt63CFHbMZGXBeMQdCkHNb+HI8H/puesywKRO+L8ocWThDUCckE2eWT6dCw8pTG3BDfXkZyvdbYmZHtCfun3+rYn75ZRGcSsXfRr0rIUWosWVRgCvsjSw48g1AdwwJ40FoTMMICUKJTfq6F0LAv7iIwjbCPwR+3DplwY273qex0WBkC/7NAkyQB8zA8tIQyIjmdObKr9r5HV35Hatg5tXJJpJ+/goDTG33edveSgoS9kPal4oTYHxqt85Ut1pnQ/+5qaIyegoQeQ3L+qcj04upHUkaWiL+2V6KWVICWYp3GieOzSliDiiLlTEs8ltwLjvD8UEJSgfq4pCG+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=fD9pbvz5idVivI00y4IBedK5vLEhUrKfz9h0Xx+4ku4=;
 b=MuF8O00avmFQ+3gJnqLmfYJdcdXcU2XQHYhu3Es5MHc5iPO50Ed/GALUh59co5egkd9TV0v434c80Id9FUy7JFBbThDNcWNqE5EkFC+78MNrrs5Yrm5jods5YYfbr0yNBB8xTzMNvl1IeKrPY+Zj5HKI2/rl/UYIN1izQE2Ch71D6USJ5iTzqMVtyVjonsMisS9X2SBCf9nU54LDAaLHclQXi3jT1SGryJvOeuLZ4iBN8l+41xjJ5kxMOPf+xzB5gmIGhYXu6j8GBFb7L9CPjX7mIIH1tIvLR40DMeLn2zeyHKHaMgOZpo1pFsuyXplJLLfFNt+hGx85L7jg1Ub9LA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH3PR12MB8257.namprd12.prod.outlook.com (2603:10b6:610:121::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.18; Tue, 16 Sep
 2025 16:46:39 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:46:39 +0000
Date: Tue, 16 Sep 2025 13:46:37 -0300
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
	kasan-dev@googlegroups.com, iommu@lists.linux.dev,
	Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 03/13] mm: add vma_desc_size(), vma_desc_pages()
 helpers
Message-ID: <20250916164637.GL1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: BN9PR03CA0291.namprd03.prod.outlook.com
 (2603:10b6:408:f5::26) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH3PR12MB8257:EE_
X-MS-Office365-Filtering-Correlation-Id: 05ee3b0a-c146-4ce1-7e82-08ddf5409b9c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?8U4K2L3LdZvOnLMw7JBvJvb9H5ue/hCOzaScbILF2thhIE3LVVseiK3Uuh7M?=
 =?us-ascii?Q?YEsvbWIHJ2xrVKY0S0e61InPuuJvawraafzC2dKoBi7LAxzp0T3YLK0Awh5+?=
 =?us-ascii?Q?KbhBCJJ4IEEFIqe+p6ZEqbzhSKUL/EYU1Z6+TtitBx3xGY0W9zdBlPLGA5wv?=
 =?us-ascii?Q?P1v+K9mW5dubdD6+rrKbQv2UKMDsx0BSyhO0h70ShCOtXloGQ8VeVELoNfB0?=
 =?us-ascii?Q?1BiAivGJqERm16pAYiIxe8kukQA1ljOSd1TNWdV0T3hq6Skd7XH52aeRbGWx?=
 =?us-ascii?Q?UjCHXLLfh/jZJuQbDLgbAC+0HodFCOw+vW34IF5HjG4T19WwJ4zu3l/DR4Wc?=
 =?us-ascii?Q?Mkl6rasAT+ZBPLVqHwYNwMUmnzynH/sNCe9s2Mb/uURXRTHiHCLV6qhJtJ8u?=
 =?us-ascii?Q?DQ2kA9Kcwp+Qv8Nz/lTUBDzUjy9NG541Sd27ob4IS8nbXtX8Z27U9MqMd6wt?=
 =?us-ascii?Q?jsacWeN+A4O0/Zv+v/6vFzfvwMkkEPKT52dymb0y/eUv0tQQm1x9eMAH1wZ3?=
 =?us-ascii?Q?UqwypNcy9Szw7epNleBnriGQI3OavReFNsq99lAJtIyJVuZSdCwyFtgVM2Zi?=
 =?us-ascii?Q?jthoffFiAxfhs9MZOFA9HXMajuCl+OdQPZFLAyRwO0wNh6KQchHIjIVeWWfo?=
 =?us-ascii?Q?E+qa94yunxUZzbPwDfAf8EnCJ4d4WsnogJ4jYT0tQcKl9QBkm4jV6WVRA8Gp?=
 =?us-ascii?Q?/wCnLhJdsTQEdU0ZYTghhQ5I974iBdFMY7j27R/WBKBYCJJtYEsArN8uyIrT?=
 =?us-ascii?Q?R2o+iJmbAYPQL4Ia+nbXRBcolOTlOgxLwRtEJtE48RucG5g4l+irtUTIdCTB?=
 =?us-ascii?Q?DA7azWzphBdUb8wIRk5/u4VJJRBaioW4ywoBwYv0w5emj+H0EpBxVt2/qjId?=
 =?us-ascii?Q?0pwEODHvD7+I3Y8TGEaM+viQfG3Cx2Y7YHCHdWbr3VQpVRQ+2vJY2tbb7SC+?=
 =?us-ascii?Q?HcqZjPT0RfWuyp+WdgGoTADdjr/ZRaLu/wLmETxG4UpmOEnqZL0qATNKk92a?=
 =?us-ascii?Q?1WPpNJS/AQEeR+maZFoMavrnrEwHq3ItW49rhaJa5XojSoIMH3xbGYwXGAI9?=
 =?us-ascii?Q?2GTO3ULeZJvE/Y5ORfj/msKANUIi+Wds8QXgG7bS3xeRGO7yE8MxbtgOWxGb?=
 =?us-ascii?Q?U83EW7ZODj1V3r1SGK0cfK+68U0GzxGs+8oNNKbtF0IgeHQUUgVKhAty0gqV?=
 =?us-ascii?Q?ec8UPNQbIVfBxXd2Kbtx9CBpGvDTzUHrC6gcPnMt8g7C+pHVcDGbF0ss4vzF?=
 =?us-ascii?Q?uD2ZeH2wdKIk31QniN9uZoGoXyxEG0frHHXF9Yodn3N865Itzw2pT/BgFZFz?=
 =?us-ascii?Q?tq2utIDn6kNZZGqZf7/jaigCbhQcn8Ck5ujAwXfXvYk0j6Q+Rcnqjtj6f4ZR?=
 =?us-ascii?Q?9lyesLcFgi9x+Xur1HQOiDEQ50AzVYGreA9HfBAutBrhSOkRWq1/gCkvZr7D?=
 =?us-ascii?Q?GuYJF4knzf4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?EMIPA/Q1hjehLU75UDvX2LwzPpgCsTyItNZV0LcS1+m5rvoy2TgDwWyoqukR?=
 =?us-ascii?Q?rRL5d+cHq64wR5ZFopetRZJSE1iyVMAwpqEKFund4w1H6csVWF2DZroreJD0?=
 =?us-ascii?Q?VhIi3s6dQ0WAtSx79hlUOq7nBs1mfSJwuLpgqzNScYbDdas3r7RHoI6py1yu?=
 =?us-ascii?Q?g1/bs26fLeBd5wUkVRp6Fs6iGdUlnTQxBOffR9K6fK8ps2IHZZx64uLLcARc?=
 =?us-ascii?Q?xehIEK3xm8xKZ4ev2FRnNN6FpAdSzQWkVS1CIcPT52JMQlmBwvdU32DkaA9m?=
 =?us-ascii?Q?BIBzJpQYA7TNAROrwuihzgBU57tklVkZIJngIny0P2/hyc1heI8Q2C8gx627?=
 =?us-ascii?Q?MTg1q4K5U0SUQoIKK8VK3TfpnndOu1NKbsFVsPPbIgoxIm5tnmyyIdR3VwmY?=
 =?us-ascii?Q?lBMRZnUMRPMl+rlniHkxZMB15mrS2w/65HfYDMC+oQPKujhVVxXBgHm+sdHA?=
 =?us-ascii?Q?wkNuJIiJ0y3q/NdQY09ZJ50Z+yDKineAzOjZ2WfpltL/sedPxAbdaYXKwePK?=
 =?us-ascii?Q?h6vH0D2pHKdm7ARKPiLRDi/HhmVMM9JgyDZFG5smLXeyu7hkfpyNSQ91vCr1?=
 =?us-ascii?Q?dR4lgDedwAfs3bdgprQjP3DfU5FsLeKgiI4QkRZWLXuXVoaEM9MZVSZypil2?=
 =?us-ascii?Q?cxT/sWa27Lp3FfE045LKOxM30qZ1f8KWXQ9U9ETT39MxNOTCcc/SwV4DjqPc?=
 =?us-ascii?Q?57flG7m8DeMXjlcpvhjjDPnj4VSl1Knr0IjGpVQlP985AlXnDuYaC+OZG1nL?=
 =?us-ascii?Q?sqx0WofSoJgeVScftrIMl5UI7IOvKzbYRPzIkxaxb7mg706AlvTf21eZy+25?=
 =?us-ascii?Q?Nlv2i+2RYWaCgQWV3++GydrlWY8zW53NwYSLjk6/xrp4tSvjpBJxXMixiXSv?=
 =?us-ascii?Q?CYWMXTXH040tqYCNV5IdgkF4rQx/in4lBzRR1e5QXiMqjrV7YuE09C5YgD1/?=
 =?us-ascii?Q?pOrC5rOq5zb+jtBHkmwGCM9GJR61bjUL0piIRWRjPIxNRtKWl1UpO2TiKKqe?=
 =?us-ascii?Q?RvGcC5eRE7YYjuyvtSbgb7UcG2/HAwCMs1/Y7smfE2iNUgXm7NKIvzODzuSX?=
 =?us-ascii?Q?432XwR5Q/uyj3z6qaiztFAOsd2RsziCMq95Ef42TgzpRe9q59qTYSkePtHVq?=
 =?us-ascii?Q?PTqNnua2dzUiRi2Y580TKJAP33XyvLEvQpuS+b4UAnHaCkm4mH8hzrT7p3qm?=
 =?us-ascii?Q?9imYMwTAwbEMiz4EZzb1WE+Axdosx8G29C41bhSR1zEHQZrN3waqh0FY56UQ?=
 =?us-ascii?Q?XXfIIX1A2ahMLmIALrd+hPFn1KDvX6lZWVEZ7SmbLi0H602FDjIGKBxkCuLB?=
 =?us-ascii?Q?ijz8G+zTvupIRcYvbIu5vJQyvG9uzkogm/pTS5RIvWAy7Fadx0JzWYRL41Gf?=
 =?us-ascii?Q?0RTLkmMvXSYI8+NpAlfMBRBZunWcRCB0u4NGVwmrC+1bNjzox71icrezDCIm?=
 =?us-ascii?Q?HnlzvOEEFqOdhTa+ol1dg3wuMZfBu4LP1IC1lMzZkItL69DmsfSo9/NMcKAt?=
 =?us-ascii?Q?zLIINhN/WgIg/GZv6WsWrXMqGa+pPWIlZ6jMzcjV0VRPTWcYh2xzp9WlF6Mo?=
 =?us-ascii?Q?FKEiU7Yp4vsEnbIn4C1qANL8WeKebS3wtrsAGGXL?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 05ee3b0a-c146-4ce1-7e82-08ddf5409b9c
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:46:39.5819
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KYEwjTCmN5a537Xg/7/eea1z/fHEYq1OuBBBCM1K62t6N8FS1ndcy3+msldZ0Agt
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8257
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=WthhqDh9;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:49PM +0100, Lorenzo Stoakes wrote:
> It's useful to be able to determine the size of a VMA descriptor range
> used on f_op->mmap_prepare, expressed both in bytes and pages, so add
> helpers for both and update code that could make use of it to do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Jan Kara <jack@suse.cz>
> Acked-by: David Hildenbrand <david@redhat.com>
> ---
>  fs/ntfs3/file.c    |  2 +-
>  include/linux/mm.h | 10 ++++++++++
>  mm/secretmem.c     |  2 +-
>  3 files changed, 12 insertions(+), 2 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916164637.GL1086830%40nvidia.com.
