Return-Path: <kasan-dev+bncBCN77QHK3UIBB3NU7PCQMGQEKW2OOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CB87B48F8B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:30:24 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-329dbf4476csf4039532a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:30:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757338223; cv=pass;
        d=google.com; s=arc-20240605;
        b=i9NVx+CJhnDDVnEC3U7xYvjtGkAT5iDuhraJPUNY5HnQYlZ6E7hXdZO2M2wxaiLYtu
         j5yrdTixqMQ5TIeBzs9K8Vy0MfI2/+C/Ixg6OAPQqdtfhVHNz3e7Rs/UBIHBJ5dfeFUm
         bm1wbw8DYpsQDcfBMOqObV66Ak0gGwi6JqoNTLuMWWftbTxivur/vXDEsjxPYeO9/c8w
         sivV9xBaJEQwnYN8hKFs5jBY30UxY2fGRTwt4Q9kWTMB/umKhvsfjvLPAEqjXKAJ0jMz
         2wWzwO+coMiOJ1M8C1sysbgCHs26exzlgNd4u0TIAtNk0Xnjfzhoe0p0be7cvpcCoWrv
         urrA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rMFQovxNJVuCFtgSgKhUsFmWwL86cptDtxs3It6I/I8=;
        fh=JGrwSHN6/m71FbgdHU/vQBeqejoaroCzf6Pon9bF438=;
        b=M/V3cBQeAfJePyn93EIL7b5qLlKRDq5kut/sGtqJk0jgYnfTecRGOfyrt0S3ri9tuo
         FkflwrpN34Ql2rVk14uvY3NYR1ghV2nDdxM6FKwAg24OgaQcfy6ktbByqFhc7gOB9Q+2
         a4pgnmGJUkPLKs6hsT7h2fgszPwMSZQ5+lH9UQi2G1LeEkJpckuEIzducn5MNPry0Y5I
         smGpvowLRWQL850aKJ7gvsVX0wFq6C9jzTlVSeiXvDCTiBZJ87jGlS7wUWs0jxZMeg2L
         s/IOpHL98vC+E7EuePmmnnfJPGQkwnSaoIF3N4BEYBxttlDeRATpzQsOFRegS9djGgsW
         SiGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iQirvYqD;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::619 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338223; x=1757943023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rMFQovxNJVuCFtgSgKhUsFmWwL86cptDtxs3It6I/I8=;
        b=PjGqW1Fd5QBo0svYyZ0DQRTlThfmVyRoehxHc5ANQB65Cw2QikNEw5XZYKjc6wNFYc
         SxH8Id0sja+M7HwMBH+XSdAkUFQ4vdTVA0rMD0lkEeMnqqE97iP6K9BmlhbNF5vLhY/p
         E/kMDEcMLYxPLU6Rcttr/6bFb2Z2kZEypajMhJ033MOg6zyVix/hLtszjJf0j15aANM5
         3d0NAvF+dG06PvTWh7R6gMulu2xrS/0wx+tl+ZXmzMamUuSqAsbBBPMktu1v8it/BhuB
         8srcsdKIvUfXJTRbw4umwuDoEHEOVyTJ3IywB8BflHlcrIfoOsr2DDxN0VtCL8YreAUj
         Z0DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338223; x=1757943023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rMFQovxNJVuCFtgSgKhUsFmWwL86cptDtxs3It6I/I8=;
        b=Btl7V9N4uXhmZ/x0S1+mmcy8nKfZh3t0SkY++oloEfFgK4HFeMq2KB/n/lKZpJMIL5
         1pIHRg2TwMnBTrr9sioa0I5VuOk+Dx/4+l95Aa83hhlOHn92nLrsnl38lsQ4KvcxGcnc
         o1DGXCGVX+ssZBu/4Ao2gHjaosBV3wiVo5/6aP5OTaaYqUozYdk/S9+XICzYsiHpMkq/
         6YFmj/afuqMWrgC2uU5h70Ax44AteDiAhejT9Hp1uDd//XG2xH7ilmxK2Lwq/9sjVUPf
         dyUYxOKYFI/maIAyhGfJDFB62G89wgPSezrtkh7K4t0nJfAtto0/pxq7PAIIQUh106I7
         MzLw==
X-Forwarded-Encrypted: i=3; AJvYcCVYoAWyv+0eJnMseipi4GHS7MDfaZGz5HQQ4MCB8mw5xrG3Jh6q0DYs+ilsKruchkeOW2nX9w==@lfdr.de
X-Gm-Message-State: AOJu0Yyz8ZPmwvl5zuKMdHk27d1V4mw7w4UBW6hLwxP3drIYEQXP6arH
	RuONeoweBxbu4ga3TUSFPtpkEUjTTVZ+4i33opF7BQIbL48FkVoRuThX
X-Google-Smtp-Source: AGHT+IHoPa3CU3MFoktF2pkqLJBC1HFYeTq6Wn4ElinSS4vYyqNSS+ZKecK/ETeCKEI8jYloiw7ARg==
X-Received: by 2002:a17:90a:e7c1:b0:32b:5f76:9e29 with SMTP id 98e67ed59e1d1-32d43f9a56dmr10263103a91.32.1757338222408;
        Mon, 08 Sep 2025 06:30:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6nWBEodP40UED72F3tSGXZqgB8wCa6QU4NHlCYcwv8ww==
Received: by 2002:a17:90b:38c5:b0:31c:c0bd:10f8 with SMTP id
 98e67ed59e1d1-32bca936ab9ls2858310a91.0.-pod-prod-09-us; Mon, 08 Sep 2025
 06:30:20 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVTWwAM9UHt4NrWZIkgAyTDTZpKyROyqUrPAgXOmuVHZn7DC0jTWdQwXPt3FRtm9bkO2MM7ptLPBXA=@googlegroups.com
X-Received: by 2002:a17:90a:5182:b0:32d:4187:7bc8 with SMTP id 98e67ed59e1d1-32d43f98e22mr7859207a91.27.1757338219942;
        Mon, 08 Sep 2025 06:30:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338219; cv=pass;
        d=google.com; s=arc-20240605;
        b=ErgUluR2RIBmELlk3g7/5UTM04p2FMkSxkik7KRtT58LyFs2+EqfB+ThBhv20HAawe
         6jNspzDbPLOgRdpVSPzZbRiC130JrbJK+V6Xe7fsZF3MBan/j4o8EhYOPR6+FwpUlkWb
         jJYD3M0HZY7TzGzr0iraDvVDvavv8IsI1s3zO7aDu0wu/7P2V7EjV3BbnF8jcw57Oj2q
         ZIwtlxH2G/Dtv5tIgUdyKf0kGzy6oeTukbPf7rLkY2o5u61V0o7jKwCfjwnpIy6XZ13T
         9+d5sD/JFXU/UU3a7Z3NSaUPYeP4qfpDXbC/gMhW4IzTUpDR7OJOc5uJ/MVXaInXo+Yp
         cJLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bH5z14Q7B0/QBoBKSG4ijQ+GXDi/bIgvHpB8s+ilDts=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=MnTiAtu/eJBGiQLeitp2PSKue4q8HIiNA1TduMWoA7N18gd89T1rcaCHnsOoiiEwtr
         MV4OfSRJheYLpv9KpprNDKEtQZFc/sh0aqDdBhCIbdxnbelbEJTJLF4/Dy45LABvhtJ0
         YxiJGTHMPll5n53ES4+h6ZLoerP/czUSlkDzcCPRPv6Z9fb0hk0+Hat1XevGy+W5PRF6
         PvfgeyO6CI+QcHJfYeII7Mb22h2JSEuXdwSqpJBIkE9Fo9hvV+dtv7D5tD7ub8fKevpT
         xwKOv9ClkzN/Ti2Q2z3bXBXxd32arwqa+TG4DUdgW1SY+jc7klbrTB5DtlzwZs355kHf
         Takw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iQirvYqD;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::619 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on20619.outbound.protection.outlook.com. [2a01:111:f403:2418::619])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b4dd94d0esi678203a91.3.2025.09.08.06.30.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:30:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::619 as permitted sender) client-ip=2a01:111:f403:2418::619;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kcR4ZZAnxPL4+qjTSpLlpOpkWcqYjXVcvbLIh5fedEYBfLAuebB3RLQ0l70terCCR/ENXWMSAk6Rlx3kvz1h518QBN+o7kPTMV6/FqhUNODCT0BFsnfXZ/q21RGA25JxsudhZ/qh9+j12L1SzcIH4f7q5L8giYzH61M4RdkkYzJgpfr4gWJFVD+RUOoTVGZBP8GxCrbZINPYzJvyAKkHKI5ePB0g7sjwaXPch+Fsjf2ju/AxBSeT5elYqPiYOpQkrC0hC5xJlgZKgo4X/LOrul/LQerFLyEZ83VZbmxd9U+F59cSNTFzlL8mfMD2xrmU79Hlet9t/z0ku2LGulX51A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bH5z14Q7B0/QBoBKSG4ijQ+GXDi/bIgvHpB8s+ilDts=;
 b=GTfFHdr203mPZYKA4iVYDunM5nyIYdFfnSHc5pjLtqnDHdtoOGVAM5Dy8wERKXcKV99Gfh8tINsS9qWOkc+1nhx01Susj+KDvnGHS0JZoUYG+lSm5V7CfjEGUuvb6640bl6kgR9qzHIHi+v+ZgndDFWXUvV1LNq4McQ373zGtZEbX7XCIiUxu39jhQ9Q9ZfMBHWTww6lemXerSWNNOsKBLP8YBvOCyu2Af7H8MEYs6RbsO56z5iofiPAXrcZ0znKHQEj6lGuP4C3cm74Z1jGlQxaNy7F2RcoWKZ5PhgIbOzNlV2VPshSrPmDWdkBlTmxQQWdRRFbgMDF5+/1ORDc1Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH1PPFC8B3B7859.namprd12.prod.outlook.com (2603:10b6:61f:fc00::622) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.30; Mon, 8 Sep
 2025 13:30:16 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:30:16 +0000
Date: Mon, 8 Sep 2025 10:30:13 -0300
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
Subject: Re: [PATCH 16/16] kcov: update kcov to use mmap_prepare,
 mmap_complete
Message-ID: <20250908133013.GD616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <65136c2b1b3647c31bc123a7227263a99112fd44.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <65136c2b1b3647c31bc123a7227263a99112fd44.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4P288CA0037.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d3::19) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH1PPFC8B3B7859:EE_
X-MS-Office365-Filtering-Correlation-Id: bf7383e5-907e-4c0f-a384-08ddeedbd866
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Sj1fgNpRfUmLNNjPrzEpci0TKovNAgdDYgcGqJrQrDbbdWCNAyNCku5cFa/9?=
 =?us-ascii?Q?UQFgpnicV4F7I9vGBhehKsT6eu0DiGu+l2ODJJYsAd7byI0ekxZC02HbfqGW?=
 =?us-ascii?Q?bKumacH15Qh55npj6xTLLc7WV8EkriXjl0Gqpy1V5LjDTQkxESFJ3DBI6ark?=
 =?us-ascii?Q?TFWr5qJ+e/70y/zV64Dtwlt6GHHuk4Fe+zVyRWmbdRikhI2hAhAn9S8tmZVN?=
 =?us-ascii?Q?ogg/TeZWLDK1luWaL+db1RKWeqj86a2E57TtpJX0COKD5/B4q9TVGejyV6ta?=
 =?us-ascii?Q?8lMZa7I1AfmnWtscBkiJjheR8vhu7hiW4fF1Y58GYN2JVVj3OTUvGZXNDEp3?=
 =?us-ascii?Q?zEsnG/NxZK/0/6p38etAAHlFIjER6lQpt8uRtaStBTRvNGZEOl/DB358jS+C?=
 =?us-ascii?Q?eyUeJ1uwggYKHXlKGeW6Z6oz6RwT7Tf1VhL3yNscD3rsO5mUgEj6/rXMLgbJ?=
 =?us-ascii?Q?9G6kE04+0MJPzw7GHZFfZv5NhtNpFKBAfv5iPy9fvlnSNAmZ69EjHEsEbWC7?=
 =?us-ascii?Q?ufRXP0qvQMAOi/e8yeNb3Tn8g8/oeWY3GE8di2peGno7VPtDUXxoiY/LKzxW?=
 =?us-ascii?Q?aaZwUmz7nrCuorxjQhSxcliP8hBY5KZ5DUCZgUdszm1oU5UGXAgAyt6+hH7c?=
 =?us-ascii?Q?JGnVXQkbBsB9IxxBPi1H85SbTUV2vpipEh6Cr1rgS3gOVRWUsqVwDjZEhU7z?=
 =?us-ascii?Q?8W2CPpQPM12YacZqLqRUgxAcKJ3+z8zt7sXizKFrdCV+vnrk4rRej0jtzuFh?=
 =?us-ascii?Q?+rc2sAV+0/4q2dIt5Ux/4dlg06SaLe3Ey2uB37G4Y1xm/bLHjeTBky/i4WHE?=
 =?us-ascii?Q?/Nr9WoOR78DUC0wWz9z/VakFfM/d16YKLJ7+ZWflybUR2u5smWZdSNBfpu9S?=
 =?us-ascii?Q?4uIq0OZ4uKLNtAwPBMz8Qrs/Cb8MlFfG9QR2e7g8o3M0lyyv91uUG8RE36AM?=
 =?us-ascii?Q?/AF46Bi75SFgkyHxfsJzbHKTavPH+wfL4dY28qNPZ8i2JZwlnps01vgsN4Q0?=
 =?us-ascii?Q?IY9pw35pOQwDDovnqr4yDfvw/1q2Pvv7BBMfe691GteJ93qY6n14D4N7DY3T?=
 =?us-ascii?Q?LgBLNBnt9xyy3jlBBdecnL8qjlbMCycWXiRNicLOHI04XFFkpKBYB4cZVXW7?=
 =?us-ascii?Q?LfWbzZcHQciXczSe2D8agxe2TfPZ03CEeqZNC+kxD3iFIeqq9Sd6hPW+yVT8?=
 =?us-ascii?Q?GVT8LPxseQmDoLsjBP9t14hC87qvTCkxL4rEnquQ7Vhk7928O0LZzo3VFaQs?=
 =?us-ascii?Q?wiBS7PB6Nt4Cd9l+eulf9dVm1xFx0+FZJXvOjsHYswLiv0mgkdX3RZ0TMghF?=
 =?us-ascii?Q?0Q0/U7aK3jYyqMGNaB/mx/FS+k4oi7y0viAK859gn5C5GXscpVT1zvq8bMrW?=
 =?us-ascii?Q?AOzpeBYdaFbsVSP7DPYdbPA90wzITysOQBVg26JLh+XyGO9mZrAfM5BJUBqO?=
 =?us-ascii?Q?0WpUYjnJRes=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?r/zKPyCfBe/6J+m5XEar+lXDZ9bJMlJC54ZIXcfnDRn0pfldDdCZzorCWOPM?=
 =?us-ascii?Q?f/ugf78Fkt5y+MtRJ1Y+/eIfrhbyXvi1Z42zXaw5vZkExLO9isYis5zRctaS?=
 =?us-ascii?Q?zxFTTwIkXpzOKAucI63xu3IL0rHEh4o6NdpZ7A1C3pHdEu/AA3ce5JmetZHf?=
 =?us-ascii?Q?Uzu4VwtCc8zAtXjwKrUO/x+5tPAanTQslp9vfeNcg5fltwvGF1SDRvJvRePp?=
 =?us-ascii?Q?xTAvsRWZJzW0GfRff1FonvAI2HjSfTf3vY/8hxLVXz8viy9VPjG2EpGSiBEL?=
 =?us-ascii?Q?bHpNCqzG6MoMbZQsduYUZmd20m6GUfkZIGo10tFkHfEbYX5GQTZpkpKQjU2V?=
 =?us-ascii?Q?wWTK6Vm14w23Lmcx+dRwm+AZ+Up7nHOYt0d2tFRkpHwUWVWVIShbCSyzQYBR?=
 =?us-ascii?Q?J217cStGMlEpgX4oMr0WZ2Kf+eMn0HWn5bZabRmKyDCUMjXnMxrEd9C0Ro+E?=
 =?us-ascii?Q?QMl/sDAw91eTxwp70Sz5JRQ7hkDeL8oDeirB7n2FCW3ntwtvZriHvxp/5ckh?=
 =?us-ascii?Q?xY3UGWuRGZz10kl4mQFTTu3XM99HihRR4c4jMozo9UC0mAwvwAgsJboOZNRr?=
 =?us-ascii?Q?WkDy+dRNfENvP0d9KeFlTBJlosSe+kAlJlvZWk3Llc+DIvIO1zR500ie4t63?=
 =?us-ascii?Q?cWjxd8InLIp3tDmkWhZjeVizk6KdSGxXSMahJyUtr1sFiMBgcLxTS9wToPZ4?=
 =?us-ascii?Q?2UhJW85tTN+d4XCCRhu69WlQkXgOujC6VrbOLXZLkukyuO9FXpoC158v/Z1q?=
 =?us-ascii?Q?kppvV7ZycvSvzoUHKSanGXbyNVm1W6eFnrE8aeFLyq42Isk4yp7PrDTId99Y?=
 =?us-ascii?Q?D0aMJxkXOLQ8/QWlv8mXT+Z1oftVi5+Uc0eDBmEea+e/WaE9J36hOHAa2DGI?=
 =?us-ascii?Q?G8WF3fdXpCaK5HcK94vdhM5CCnd97KWp7lBYL0Z58/RfzTZ4rhvUMKWD3ZPP?=
 =?us-ascii?Q?O9yDJMxzZtql/uC5duHKBixFQIB+Qtv85Fj1OkuVBKpEX3mEof2/Rab+p5jj?=
 =?us-ascii?Q?sgn3x1hQyR9TM9CNN8MPd/1QRWKpD0lfxfLqtdOwTi3f6BoM4vFDgon5HVfe?=
 =?us-ascii?Q?76GakdjugnnPq3J9NAMlv3YYrLYhyWZXaLKmM48IGVUwEiJgblLVehYQONEz?=
 =?us-ascii?Q?twoLRvCyChCMMIsghtTTGTb6OAIQkcSPaL1Ia5CRnNyGj7Oeq42SSaB/s/1w?=
 =?us-ascii?Q?LSWz5qecHeqUB/I4toKcPOrsi0JFY2wMYNAxKG/xf+AV3SkmKq8gXcTw0aIw?=
 =?us-ascii?Q?vsSFN775aJlxReo5qpjuwO+97Nw6bARD+5qp0nrt33yQ5cXoZ00VZq5A6AhO?=
 =?us-ascii?Q?ivW7flb4FDmww7dHpQ0SJgUtixK9ilrgZVAn2Jq2BDpyVnWotiBXlfiIU4aG?=
 =?us-ascii?Q?E+/YPyiazMWRPO8DoI92aIUrqwvkSK9uyBs3yis3s/Ghy2wZN/D71VZBLhnl?=
 =?us-ascii?Q?jm36AByUCFGFAWRvDCkHC1bVNhsiRF8xvkcy47315xq5zvf0M8wxyZZtWUxf?=
 =?us-ascii?Q?A4twvvouLMQshWrvMkruBWRNtnj5EXD9scZfk9unmTEV4zsvl1J08cKHca8Y?=
 =?us-ascii?Q?Bou1BiARRjtvykVK7w4=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bf7383e5-907e-4c0f-a384-08ddeedbd866
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:30:15.4185
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kIPAyt1SIUharTVbKnH+ode+hdhgODYC87gyhtAj+SIGuOMjQ96I3qN3TO5FXcek
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH1PPFC8B3B7859
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=iQirvYqD;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2418::619 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:47PM +0100, Lorenzo Stoakes wrote:
> Now we have the capacity to set up the VMA in f_op->mmap_prepare and then
> later, once the VMA is established, insert a mixed mapping in
> f_op->mmap_complete, do so for kcov.
> 
> We utilise the context desc->mmap_context field to pass context between
> mmap_prepare and mmap_complete to conveniently provide the size over which
> the mapping is performed.

Why?

+	    vma_desc_size(desc) != size) {
+  		res = -EINVAL;

Just call some vma_size()?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908133013.GD616306%40nvidia.com.
