Return-Path: <kasan-dev+bncBCN77QHK3UIBBQV5U3DAMGQEE4DGEOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id F3F14B59F4B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:30:43 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30ccebab467sf6347242fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:30:43 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758043843; cv=pass;
        d=google.com; s=arc-20240605;
        b=jV4xA+zujVcqfAKtnEBgpHmrS5Xuta3yiiFqHicJgk42RuexmY7EohsC1VnSWOM6hz
         EcE5Oq9hs9J1xLeSuI3ZvK53ckGQIeKIaCtlrDfqIaCBzERNlPgUYrcHfRpJFYioEEeR
         lX7qhF8Gy9KSts1ihbGak4mVCeWuN0JCyiweUPr/u3n5PUdSv+Jw/PsqFOnlXmRlCqQ2
         gtetoO5flgkMQZPjxmDa1FuSZNEAVAxEmqNvTcYX9yWnv3PXlXRWzf8TcE1rciWDM4mO
         lKTN7H+pqUQQe62a7P0KzFrt8CPY1P7ocHR7rgSmmCo8e59vrHivXgufBF4J14SvY5sO
         GI+g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=CxUd20dBXBx0vInCHouFphH+mVHM91S4tVsIdJz+dlM=;
        fh=gRF/40WP8+2f3Bx8lBG0jjpjUfDKV8Q44rhlZPU2wjs=;
        b=lNsUwiEvc9ABo6hcQm0KmZbRuBQVDIafgqCud2jcA4jbWbI/dYBUGfwa7UQ5dB7nS5
         G/p4SV9f86LvacrTrhrO3qj6fMVGPcg4g+CoDLbHRjB2tc2WJVG52OGWUqAUVhad0Y3O
         lGjU2BGzUEL1ifp8aLLEFNCIpMmMa01Riw55B/IeFUjVqJczVkuKZyNdr6bjByXYf1Bz
         rsq8rJlLuwZuOD/MLtLuhBxUtQl/Aw6mAMlLLMV5r5+oWCfXYvNAXT6HmYtkeni0IRR/
         Bj+wJYnFtQogC4e1MrCUOX80Gj9+f4AKsLvvGI9jhm/Z77j+0Fos4jy4ByExnjmpwHdL
         wRuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=fLXHGS37;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758043843; x=1758648643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=CxUd20dBXBx0vInCHouFphH+mVHM91S4tVsIdJz+dlM=;
        b=Il+6b7Xtw9QhBZ7dCjxlhW99XGXNw+kzEHfdfH/7BesQGulTpKoqRoRDCesECNrv9Q
         e8DdAK+IHe+5SmEMOBbU1lL4cqjBaP7UqYSwbOWYfT/ET4mWVNHFdnEMycZ6VaKLNk1U
         KH/Cnmzm9vXUA84nE21aovE7FHhAisIQj112GuH7kTzS3xsE53XfUJ2DU+rwr/NGu2Is
         R97+NaxoKcGQllMsS3TjRol9XXKmVS0Xd9CVTS+/lr4Sc334hBlpHJ6Gg4bshOCYnBfW
         KACAXmjOxmSYj+P8/E51J+xkUvbj5jhbIyUNvAMJ2qhUE+PDhXLZY2GmjiW1ZFN49es7
         NLLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758043843; x=1758648643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CxUd20dBXBx0vInCHouFphH+mVHM91S4tVsIdJz+dlM=;
        b=WoMcxqo7HAttyelYMcRwUziMlyn9ru4DqLmJ0/qha8DcjYpzSXKNKAGeMKMjB3ClUv
         2hF19uK9vcwz4xsN9o/uIUSkNxLsb4lGW3roVGBdjpmCt99C1tsIdMOqe9rrxMd9qbfC
         j7AuN7JPKoKZTt8pqZvBCKqjv7XtaeMbQmZhSbb84unLp73cwJCR4deOVGGVLPUkT2+o
         VyIHJHbVrEVvk3VVezf1NYQTrD3IZJRaaMrBrFlI49Gi/2WrgkT01uBrGYxzRsfBEl9t
         NgcdTwVcL3bZK70ja5WqMOv1T3Y7a5dFIfsfnSlb6FxTUNPB1lk7yI/EjmchJDO6BkHb
         lYQQ==
X-Forwarded-Encrypted: i=3; AJvYcCW6RfKBbmbO5/KzJ7HZmct0qrKI+yd2PvL83pUWLhMOZS9zBMAP2A0JSXCxvrzdWTkJgWgx/Q==@lfdr.de
X-Gm-Message-State: AOJu0YyqBAS6z6GkwywUh1JWfxLjYa4fe/qwARP0Euf0scRoKt8y3RUC
	ZQouyxvXllasxV/iKt3qY/aMfyiPxQ6EBa9boSGExOrHgLnHEBIj9Mx8
X-Google-Smtp-Source: AGHT+IEDQCqnOi3Pnb0Fmni0ip1jUsC7XccZ4aTqyKB72U2KpwZuuYbEsJXZweAPLVg2UeNVsEr0rQ==
X-Received: by 2002:a05:6871:2c20:b0:331:8dc2:914f with SMTP id 586e51a60fabf-3318dc2ab14mr5993036fac.44.1758043842699;
        Tue, 16 Sep 2025 10:30:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Geod4iIykJA9GGgQlpTnuPuphsLkOObocog2URdSUFg==
Received: by 2002:a05:6871:330f:b0:31e:1dff:4875 with SMTP id
 586e51a60fabf-32d055d8097ls2936626fac.2.-pod-prod-09-us; Tue, 16 Sep 2025
 10:30:41 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWVF2YLeN95ptkC8KF8pGoBebMYudLwV6Y28LlXk+P8atAaxeb5kfiJXPPorYg5iPY1XTCwShAjmPA=@googlegroups.com
X-Received: by 2002:a05:6871:2947:b0:332:75df:ab8e with SMTP id 586e51a60fabf-33275dfb9e2mr3982139fac.7.1758043841686;
        Tue, 16 Sep 2025 10:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758043841; cv=pass;
        d=google.com; s=arc-20240605;
        b=XAosT1gfQuie0YT1jSZwSTxaYs8O617sy7Ikuqb+dNiOfjUX+KS9V12BmdS3wCcTMo
         wEDQFIDAIUVpc2svev5Ac7CLn9Iz+ZSTA7ZJfz5srklIvPbx/HG9tyEyoq2t5SzfgrXD
         yOwh9MKHLbksiITxaYQxCWh3TliR+DD8BzLjr/me/Wjul4vUOEab4pvZEynU4T/2qics
         YKFgQGR934AgSAjtT/+52xIQhMGRgzdxQfRhJgKkPZ6+hbd10U3AKWUuU6Gj04qE9XEZ
         Pb0ZE1yJzRuTYIrx/8DuLk+nK+MGYB5MLyszcjNA4k6ZDx0973lSX/FSxYYqnO9l4Rox
         J2Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UGvF3uE0NRf5Vl3qX8UIfBj6yWhD93uUo5GAySOaYOI=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=SuNGCMBTcw5RFXisvhs3yzmPRXD4cpfx4ZmicnK7fMTb0Ebt7++r5zx0zlEOFJJC1E
         xxctA0ItJk1CEfM9btDvOcn3CrWwi/275yjmrVYVgSkhYXg0z8jJ5vkajMMcILJPozaU
         EncrFkYRZSBnTCUSQKeEs0sNIBfs+e65Qq/fjIJYMjwf2TQiq6hGLPBmib95LiVPRsQ8
         q9ZpIEKNqh37WVbYZUUA07eHCgtOdgM298h5bbAWFT/ULjjH2DXQ8SJ/HwhcwobXlYF0
         4NFaY2ZNszBaQzhlxR+uJagNv6ySfWPiNlxQqqWJPQtO6rzzSw7V/W8fWFmRhsANrJY9
         4Ifg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=fLXHGS37;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CH5PR02CU005.outbound.protection.outlook.com (mail-northcentralusazlp170120005.outbound.protection.outlook.com. [2a01:111:f403:c105::5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-32d2f52aa36si695582fac.0.2025.09.16.10.30.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 10:30:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::5 as permitted sender) client-ip=2a01:111:f403:c105::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XKswpc5RsVybVYjeG/ENteaOmkKEU4LhNjeImbfDiUo6dg7rktJsZhm8XhhPWgXOJnP4dkjpFtrhICm77oYeWSmW6+4taBZfcZctoo4kmxj2v+0AEymY/yKXl/WwMmMFb1Y1ISWx87N+1s5mSuAjxJNYc3G7lQ74mE+Om3C0jySceQ5DF6UyEudnVbERt56LyGaN+b1/7DbzeTVP9RiFc4GHSG+jBHDBcRjMGTyBLdgdjmlWfprUzN3+sSTmnOWXulXVxdF7QYggusm9pnZb2gPtVFiLyPTJOoHryBMXUXJIbe9TcSY2f0isS31HGmBilqodoqwOjZGFea0ZpcpQHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=UGvF3uE0NRf5Vl3qX8UIfBj6yWhD93uUo5GAySOaYOI=;
 b=f7Wu/9WIldYlPZUH7KedSfDxplETFyqWEUlyX31LACcM3b1BMldZuDbTZ6gg23QMZhp9Eg6rTkj0oCzojgQuaBn/cy9rg0luovbhOaxcVdhwpgwhHhehgPUyRo0rIpmrl4my76JzdZ+ZcWaGV8AgIvO1QQYO/leqOtMO85kT4WHKKAd8+35QiF29QJlP4gCrDfDP9rf+CY8gynTZ70W0mxnnL4LtSPSo2CNjuxyvtSKCD+lzoYoyog0Jseu2O0VMCu3J+wGti8SzDqTAzxWLZuMRXKjBouYqB7jj5Iyc9QbpAsw6N0yowTvhRGNOYhOhp/B/k2v4EaOqxuYKBZr4XA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CY8PR12MB7268.namprd12.prod.outlook.com (2603:10b6:930:54::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 16 Sep
 2025 17:30:36 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:30:36 +0000
Date: Tue, 16 Sep 2025 14:30:34 -0300
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
Subject: Re: [PATCH v3 10/13] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <20250916173034.GR1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <8b191ab11c02ada286f19150e5ec3d8eae4fe7e7.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8b191ab11c02ada286f19150e5ec3d8eae4fe7e7.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SA1P222CA0054.NAMP222.PROD.OUTLOOK.COM
 (2603:10b6:806:2d0::29) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CY8PR12MB7268:EE_
X-MS-Office365-Filtering-Correlation-Id: b32c7160-bdfd-4eb6-cca8-08ddf546bf05
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Q8+hBhREbfIvmN6GWbtwSSzQjwRq8vhs+psMzzmJ4wR/j4NRyiDVbcSSRS/x?=
 =?us-ascii?Q?OBfOiK1AGP6kgKi+QnPlfA794E023NQItp7hJFteWhxlS7GrtDAAaFKCESUZ?=
 =?us-ascii?Q?F9s5ozVOE37sknBowV8ZjBHB9ERrXJG/jxGlhGs08bOknqXAHM/mDCCJG5o8?=
 =?us-ascii?Q?49aNKSiCzCJZ8HzSPiuwhdkmT0Rbo2Q9jYHR0fx1YObFyR5G8UxS+SI16YNm?=
 =?us-ascii?Q?xifAqr7yfKYhCGZwgYeFzMTY+prOpdAJWDu4sho62pxUATy6JTV1yG66uxUy?=
 =?us-ascii?Q?aOoQqGVK6uHZ6O2HBtQ9s+feEvUC85eR76vFDflYGIgQbU9R/H/nADLiSzGC?=
 =?us-ascii?Q?8tr4SvzwRVKNL1+3p8q9EagXzWiIITv7nP155lGIAr3bQ8ecsnvC4vQZqrWb?=
 =?us-ascii?Q?T7Y0876bJChAaCzJvkHdVuMAYKp3j02g1Tb3Nc/wgFOSfiO6u/ZOqDmwxh9U?=
 =?us-ascii?Q?RiRX7ek99cpRMt8tZ5dfI1e9CdeYl2pqNVfpK8AEhOIqbk4H3EnU4vI7dfVt?=
 =?us-ascii?Q?XiucRg2iGLUbiVgTcXCtxOahm5OxeBlopmSY1DBjZi4yUFkptNX5vhkXnpiF?=
 =?us-ascii?Q?0PdFcrejz4oPkUzy7UMF2wS3djHDyVUBKnuCckPwstIFC2qqsMNlilYhXjJa?=
 =?us-ascii?Q?lf6u62s0ftZmCLM5bA8amC+xRhT6Bz2qRymMFJpe8xw7bkeZ6/kJQj4uN9xc?=
 =?us-ascii?Q?bWGnJSL5KMPRGGF17B/80jR5Y92rdGga+J0DWY5yfLdIImuoNlD026wAKTIc?=
 =?us-ascii?Q?lQMdy7AwwqbWtGnoRWkbodHSCiKiK55OBV/lOxVSrRmrDuVh9JkQua5JKtAo?=
 =?us-ascii?Q?x5mG2ZRvHVmm9XTxA2/xwH7GJ/XvYRMzq1o56acW+zvQZRNpIKQ91IFip/G8?=
 =?us-ascii?Q?+TpYdowkDj2pE0FxFyb/8MwpzaloPpEVmCxwE2/Ac+eLzbwwfWaeqMeOlS0R?=
 =?us-ascii?Q?t6kjtrV42pK0TjabwAs5/iEXOS/epRdQj2G20Jr4K9i7E4OgFTgHDXpgX2x6?=
 =?us-ascii?Q?Hu1nldUAdubV/jK17G/MiMGoylU4SMuq2UIW1Ai4LK6OwgI7xFv7zmG/WTdZ?=
 =?us-ascii?Q?rQVIGqpYF5GKBhZ3Pv/dfyBEdlyNPmzQ8ZHbfSEzuxQAOjmznoAO2l3ihnWY?=
 =?us-ascii?Q?eB2A99ZxhLPwxlWjTwQYRgyMYAAX+nLcdyfoFwPYG+C4PmVmC0uiSJCRjjgf?=
 =?us-ascii?Q?YU4wan4nxD24WKhoU+4uIctHM8x/rUq/fjJIoncdKQVOUFR21qBzl+sunbXT?=
 =?us-ascii?Q?wrP4DI5D78c0bX1cNGrhcGQgHazlRjyCSyTfMphO5klD5A4Uh3RuwxjVV6gQ?=
 =?us-ascii?Q?Bw9MtyWzUPVtkThYTFHguiY4iWpqVo5SVtwzS2pQwdrmBW40nan01nyr+sZT?=
 =?us-ascii?Q?73BX79nZF73tRzfPZXnnsbZRPxoa2WZVYTXMrlzTqZ3rG2LqRA8QCVWsbOKo?=
 =?us-ascii?Q?GGMhLQdNPMI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?RAO2f3WyaavOY8WChuTXc8BZ6vsgv9gmkj1XEJQedvqYLuY0jr0C1b/URUlp?=
 =?us-ascii?Q?wPpBqb9Ja5QmzoqNHRB8SVP1SkRcI8DX3OJIFA9+vKVF64Xe2xzIy1NJpTRv?=
 =?us-ascii?Q?fL7GO6OYuU5VxYS9m1nGYNd9T1OGsSnkC16qh8MQxlomdD2D+5SRLHsTk8bN?=
 =?us-ascii?Q?4kwy+KNiNfBYQSkPdksdr31hTLY0PVO1BNvInnO9Yqdesq8y5oGwD54lt4fn?=
 =?us-ascii?Q?0MOvN3/cgbPbcSEYaNRirwG6itSvyo8ly4MG1F5aVmqk+BmNDppFQKgi6DE/?=
 =?us-ascii?Q?gShCidgiIbLShUdJMl9QsOm8m27GQ4yg/hwJyb3RHI1KKEiUGrDlmjGNuhWT?=
 =?us-ascii?Q?BV7CRLZizAH8wUkvgztBhVQT2M7YWvMxvB2x+0eQn6su42/symigDw55WNuc?=
 =?us-ascii?Q?UNqXvNYDLvaHlPEMFCFuCdGL2J5vpb//v8nhNCSK7ObwvfuMbR4lmc3lfeHo?=
 =?us-ascii?Q?g6W4P13+h3VhIenV5xlYJsCSosvaKI5dzfldfKVGWRTe6jmIovoKxjmijSOQ?=
 =?us-ascii?Q?BqQIYaTRd9dBsUyYPgyOhGIium5NLjUs4zGjPVxg9q7y9OypgyVFm/VIGgJD?=
 =?us-ascii?Q?6+sGM+keXlgQmslVExAKKsvmW1dBWdEgCCMuPU4zFeCT8RiDYB/yAVWU7mA9?=
 =?us-ascii?Q?0jpWY4Xg3zPDM9Uu77GOU+j4Xp4KGC+kNR4qVj66xgdmgFzRXGSftEl44Ykh?=
 =?us-ascii?Q?jwLsYN4yNeQRsd8hkmS8IfAvQm8riCN1pVOHp20m5dD3Px2dE3WEKqf5kISD?=
 =?us-ascii?Q?cMJsbrQv8LKqRvc+4tKhfxe9tdc2zFpNJxnvBoEj+hjIwzbt1IQ4gyQTzhnc?=
 =?us-ascii?Q?7x80WhGTKgmIbdFcTEHIMDIWcpv8GWTCXAsZiD0c+X638sQLyvEHcD46Muyp?=
 =?us-ascii?Q?iOkFnBuURt1qMiKbkdnCnNHdJPFyBebmxItcvPe9Ha29mqZg2VQPk2GlxTap?=
 =?us-ascii?Q?bA1RPZiLHAG4httGalu55LwWIjGW5U7fB+P5aAOyigrYE0PJjZvK/PteG16z?=
 =?us-ascii?Q?NvJ4TaNQDVo1hu7AVwpUDZH8Z4qt6V0MFBfzj5LJtLsxH4ccrkFW3wQxRLOn?=
 =?us-ascii?Q?Z0FS2kEEftLcwFsRKdIH9V/FDlbSZXvXNqTnn2OTDK2ZxO+wbUmhxS+OlHLF?=
 =?us-ascii?Q?pG0kF251FdCNRRwlCPRhUlUZ9KSm23Con9nmckpIVTGTsoqQrfKxY4oxVA4Q?=
 =?us-ascii?Q?wpQscqsC/LBOOvrFZ8QC5tK1gxDZCeyDZ7rI15xW71nFvvwTLJQowzHMBmH4?=
 =?us-ascii?Q?m8aR4Zs7KbPImUtSgix1q/C6ZAA3LEiuQj5TbV/Y3vpF+hbO1tXPg33mM7E9?=
 =?us-ascii?Q?ci72VQfgZYiBwVKYrztwsWpDRF/zpzJefMT6hOEeD0cz6pRMg2h7/waVrSCC?=
 =?us-ascii?Q?TQTttrWgJuvlPPn2Q6A9ISeMoK3wWj5PbV+T4QZr4dG5LRXK5nsRKYy6MDq2?=
 =?us-ascii?Q?y0yxr6Y8cYXjTfKRphOuY72U+aFa4mQ+uBZbIxjw0/QX99Tx8citbqUXiHAA?=
 =?us-ascii?Q?2hIQo4S3015TNaznwkTK+ByYJntEhycl9gK17tRs8K5wCGYbWdc2yZ5Xg0wG?=
 =?us-ascii?Q?l5gISEiJAovQl5tk/9FBHjAcYuckSW1Bh+g4rohm?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b32c7160-bdfd-4eb6-cca8-08ddf546bf05
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:30:36.0210
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: twzIP5pGgX2QiNLXmr6VCgqSrfRueGWZk21rWBja7VVqi7GmuKAS03ltWPfAnW7A
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR12MB7268
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=fLXHGS37;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c105::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:56PM +0100, Lorenzo Stoakes wrote:
> Since we can now perform actions after the VMA is established via
> mmap_prepare, use desc->action_success_hook to set up the hugetlb lock
> once the VMA is setup.
> 
> We also make changes throughout hugetlbfs to make this possible.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  fs/hugetlbfs/inode.c           | 36 ++++++++++------
>  include/linux/hugetlb.h        |  9 +++-
>  include/linux/hugetlb_inline.h | 15 ++++---
>  mm/hugetlb.c                   | 77 ++++++++++++++++++++--------------
>  4 files changed, 85 insertions(+), 52 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916173034.GR1086830%40nvidia.com.
