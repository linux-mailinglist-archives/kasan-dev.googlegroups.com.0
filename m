Return-Path: <kasan-dev+bncBCN77QHK3UIBB56LVTDAMGQEBBV3PUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id B0B5DB81EBC
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:19:53 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cceb0a741sf177480fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:19:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758143992; cv=pass;
        d=google.com; s=arc-20240605;
        b=MvbXfzK/S+RcbcyXfWsRnL+u/Yqdt5fNl3AyvhiN0oC3BHfmtA6WukESOUIdaHG0hI
         2Ws5C3pPRX0YRP2ZGzFv1FOBPivLVT3J9Ww/UpDAlg5pX1B07JOXirHVLCvGlQagUTxL
         xpNLmeg3sxwoa5+9oEXhRHshX4gwEcCLaNK5JMGzlYZr70tamAReyi2pwPBwLTfwfIdU
         FOu+C7MfpaG5Q2v8RKRp+AW+nRV2+1eK42pkN/LhKkrF8EDphZYHs20FkpWBwKKrZYRi
         6pIBWP7qaQnvDEeqV++GtY3WtnUOULo9Yq8KhG3mJOjjWiCOKjHry5eThC6jdbdxblEX
         TbKQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tDC0+O+ByU0g9lZLBQehy7AHK92VSbkFzRMLCEITrk8=;
        fh=cceyW1eDo5akJmgRq2MzMxRLP/S3c4wkY3Yb9dwG7qw=;
        b=Ve6zvA0mn3yKOtGRKDaA+784SJAUD2Su8X47OQ4YaNiJk/JuIuFVfgRs2AkaheGu1w
         AvMp3c2uwrhNQeF4uIjfqky1QmHGlxWA5NcyFcylHT/LDWcRMVJ6Bk8gaLfPjE1TbMcb
         mcBzPw0WcQ18zMhy7C+W55vuXPyPIZU00NwuNRIyYjXYADzAZzCuHwl93nFlinzt/04J
         cq4AaTxQ5jhbFn/hQ5bVRpCdzIjdLHozZTckhUuaJfLpinGA6ov3tEcsJlxbCE0wvfWv
         bToYqYplWqoNlzonOiIFfsSvWd6Kf+F0HGXGARg94yOgZosYaSZZRgzwDfrqIe5pA1Gz
         /Cyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=hK+Q6egU;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758143992; x=1758748792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tDC0+O+ByU0g9lZLBQehy7AHK92VSbkFzRMLCEITrk8=;
        b=SHbDDwihf3uVrBXfIz844feY9x+G7i5+QDuPpRKyROvnp/gxdAvwuHmkPwzlcFmNeB
         7pduRXfiKTNVKTkzJ7RLAAMdAO2yXWk2v1y34hZWqBPqA269CUQ0AWFxxakaWMDy6q2i
         zULcqFgfFebGRXfhKrrwo+BjM09ZOfWsEp/JHGA/IIv7voqq/no63tZrWgHqzP8X9f51
         AyhwOeeWqLnr0hCFLDLLR4gu+3k9EiZ8AZlq/9bgz4cHgb98TgNcoPLsfE+Qohg4PGWu
         AublBMAUZy00KHyNLfzT5gD/SFE7Pz2WzgBZkZLdVetX46YQJa09LhWFSMBgDjzvDYVB
         z6Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758143992; x=1758748792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tDC0+O+ByU0g9lZLBQehy7AHK92VSbkFzRMLCEITrk8=;
        b=FvMnfh2RdjX275fSN15H0eMWDe8bN3l6ezM8WBpGjPWtTrMf7SFUFhx6TD6pMIaxd6
         IcaPLCL3JGGk6p4pi2rOvKntfZhqtw8hKQWWlTiGjh2ynPyoALzqPIehsLHwOfpf64L+
         1hMGXWejhec2ZZlQP1w1KZnEkPpIox980LYyG7iuahqI1Csw1iO3rL93jjuysOzlhAH4
         LfY+q6bE2W5q7p7huXIk6IawPoaiuwnJhINAxA4JdMIe0D+OwyEsPIP4/GitmlAd5okN
         AVojE/NUFuH4/dLiku21z35Nrcm+q0gWTWo0ZncSzonz/YTAytrUpWXbXdz2OjJQtoeD
         /0VQ==
X-Forwarded-Encrypted: i=3; AJvYcCUiTkCmCN/no5qCH34hu9k1PUKdlZ7Mb1nwAh8sa1ktvN971a8VUJmqlw3Aae/brSpWA1q0oQ==@lfdr.de
X-Gm-Message-State: AOJu0YzGFLeTztylnRWT951t5Y3JAwP7M2mSNK3h+lvLIRCaDwk2IVWl
	PVwJ0EBxMZQcbvogRMwZuyujIqP+R4rSP2dWX9I52cPdWVY9Uqt4g0bw
X-Google-Smtp-Source: AGHT+IG5Ry//1m/QQSSG6CibicGOjSnsYVe5oNXDJsytpzuFRTTDN3DSimK2Qpf9fMCtKb6PM4bycA==
X-Received: by 2002:a05:6871:e40f:b0:314:b6a6:688a with SMTP id 586e51a60fabf-335c044bbc8mr1764941fac.42.1758143992122;
        Wed, 17 Sep 2025 14:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6uIld4Nr1EMeK5BHemC3HIU2XYEqfsYhIaHYBp2D+qBA==
Received: by 2002:a05:6870:5064:b0:331:852b:7a1e with SMTP id
 586e51a60fabf-33700f492a0ls84658fac.2.-pod-prod-07-us; Wed, 17 Sep 2025
 14:19:51 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXpSM2b55MNidTdc1emjMHoYyNMc/2ZB3HsNU7Se/HtlSWTiC5gW6azks2MB8nDVlFj/6He0h7kHaQ=@googlegroups.com
X-Received: by 2002:a05:6871:36c1:b0:331:271b:f0e8 with SMTP id 586e51a60fabf-335be8c715cmr2137625fac.21.1758143991149;
        Wed, 17 Sep 2025 14:19:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758143991; cv=pass;
        d=google.com; s=arc-20240605;
        b=SqKfuJZgSw3s4OCKKfxGLkb04Lt2TTnJdxCylw9Mi8VMrGpxuXL1G/fpuHf9Bc32mh
         YEeR8zIqSlSPq6YAIm/0V3wez3UlZ8ra/eVhD2/vhmxgz3aFEnVHCHLPP4m6qOU9YOcu
         Gd0LYqoHNnnZ5FaZM14ARfQeMup4hxZJGvC9kpmI1nYJjFM2RLQGJ4zwBoVUQu0yc+ku
         kSWLiHunPWAySZdIBHwhdMJGD4NTZJGU6T2LKUWyNA0HUsz3qrUPGP7etn0TebY8tL65
         3w0bSazBYSx3cDEPLCRVv3JpTP7xbnezL15/T9J5reI2ttu+uvyPmukX2OHWSsaVEyPE
         g+NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ivO8ZyXjhrVFUoG23WcAc0qIXAzKjaT+w+I3vSe6Xts=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=jvWDZPNV0nbMZC7p3xoaOFN0341LcF7+ZoTFED6kYkLQWpKCE6QAp8bet6RybCVh6y
         Je3RPZGkl420BqMzIVoQKzwoqxw2QgU0EH+dGtSiI9vh3iw9b50aOqz75wtIvMDQDwLY
         5/LysePIdgtbaWzLgD9ELx9sHNvoLPNpE/QhlgNzUhDzn2pyEIg5bQqqtrwfYxoWBSSR
         IrW9iSLEnDUG8V1f6+FcebYIxF69CELjSu7iiRgrw5ZPbFOfn/92/roDlEaQfFEx7keT
         e/zBwXequZtmrHddC8/L/h17PorM6EOpPs0GIJLbrc9dX7a9stb4w9fBg+eg85hJOgNV
         /vqA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=hK+Q6egU;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from MW6PR02CU001.outbound.protection.outlook.com (mail-westus2azlp170120002.outbound.protection.outlook.com. [2a01:111:f403:c007::2])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7691b5e50c0si37049a34.2.2025.09.17.14.19.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 14:19:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c007::2 as permitted sender) client-ip=2a01:111:f403:c007::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=cbucwQ6p156jMPx3ciQbekiQrvQ+Z+dL3RrcmkhzT5c87F3RYgQFUZkt3hCP0FOYPqwBxitOVd6ipdZZdJhPQq+Dr1YLVHAdkei7f/oBbXWRLQ7uidK0A/baDUcTlp6e0GwktHIBCzO2ZTq5Oz6k4LU4Ds2Zv77M+PNbQxW21g0He//8s+jXgMYXAEb/O0IZ31mfGmho9A5ltIykU+va4QBx4lRcMjkFuqDRtC6YKlQUlPFdxPXoMzvxjxyvtyLZpCJYPCwwmhh/KZYCwAc/LFGtXawqtF8bKGIJqQb5iZ2vX7QqLoxUMP5PuUNW/VYgbLVK3iSUoirsFS0MOBUXeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ivO8ZyXjhrVFUoG23WcAc0qIXAzKjaT+w+I3vSe6Xts=;
 b=qdwk1DA90F4WE72J1gmkHq+NggjzZJjHWFSiuBUDqTEZgxKSTlYreoyc8eVITSlYLkBONMUB6nnYn+sCj01IH4M26ItbQ4p1/dhQdyV0KLMaCsllwpGiOjRk7zyWkY6+5zALtMVwvBojMfgfLiCoAOgSLJPFmrQJcKj6VjUBu9b5qLkrvqCubN0bli63djto+OiWtSsFG5q9jbsGobLvp6XYNQQY6g9ZlcTF7KV3wQfOJj8e2XEVEjTMVLw3MVNMsYw1yZUUEsnbJ9fEfeLhC4dgTUWn+BSs/ZXdFe5bwKrJvm/FcapByTBl+9vALiI309df1kZWLmHTWuyUFJvv6g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by DM4PR12MB6376.namprd12.prod.outlook.com (2603:10b6:8:a0::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.23; Wed, 17 Sep
 2025 21:19:47 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 21:19:47 +0000
Date: Wed, 17 Sep 2025 18:19:44 -0300
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
Subject: Re: [PATCH v4 07/14] mm: abstract io_remap_pfn_range() based on PFN
Message-ID: <20250917211944.GF1391379@nvidia.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4P288CA0009.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d4::14) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|DM4PR12MB6376:EE_
X-MS-Office365-Filtering-Correlation-Id: f4b50d17-26a3-4523-d1c6-08ddf62fed5b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?3B62/4ihQZDq1ff4P2NXaoccNNc+T1/KAEbkQqiDonPA57KVi7o44OWkS1CO?=
 =?us-ascii?Q?j5BoSQlmPHwWkl5sdmIPU1vVK3VXGf+1nYihDXg+x/u5W3mEub8TtuP3Myof?=
 =?us-ascii?Q?+xZIb64ySSfijB2/P9MLDfJPVhmMrF50czGfLo+nE0jFaif3ZmxiPCsRiGu6?=
 =?us-ascii?Q?SFN3mj7uyuYw+fyhNeg/D3aI98ZDLWPHVml7u0jO67x7YrIj1SY6tcCXeTeg?=
 =?us-ascii?Q?x25bvbRcdI6yK/nFXXhpGOEx/xKpqQx6Z/yt2V0cygE9OJot30w0tUEkItaN?=
 =?us-ascii?Q?pXFUnMg4RBLuMziJBupO+aBPIZzryiGBA/mEm9en7Q2DKC8R4plvax9iZ4KX?=
 =?us-ascii?Q?eSCPC5530EnG94k9/ibLeeXlzYlxCt/fDtN6BzpEU60fBGefhLcwWjXvYRgw?=
 =?us-ascii?Q?pyS4OzEl2X5uc+izZ9YbnHYv15kYPuL8qIMGOmBgiBETJz//MWbGJmOP/jia?=
 =?us-ascii?Q?lrOXbQX9u4aDdvYtjn0JApWB2HcDj5vRN2+aN2ffHtqUPeShwK7qsYpu/WrQ?=
 =?us-ascii?Q?wktj+rxBbAjTC/7ilyzCz2MElz/kvrjPxFjWtdrhQEiwfUIgRF1gEK4Z5Zrc?=
 =?us-ascii?Q?yP1oDLRC5rZct60udQvWMTFa+Ut02KHQeuuqs7eHhLFGewOHYz/+wDvTrVD4?=
 =?us-ascii?Q?NPJ8bu7EOfmKV3jxr9JkQA3oFCa08bm+WzeAkH0b+abB/RghvpNh2Y6ncWf6?=
 =?us-ascii?Q?o1E8sqVtC51Uz5uxHw9QVvW6x7fnQXQEBn9rRUp9lxsxM5PF6CAOygJoQAgZ?=
 =?us-ascii?Q?UqA0ZfcANHQLFuEs3ZyPn7ejpak/3/EW73AY8YCdJBPoImu0/D/LYPK50lH+?=
 =?us-ascii?Q?MsAJyVu633hpoH0UK4ISxgGh1jcVofsqz1ouQjp66VJsMMtkDUH7nKfxTWaw?=
 =?us-ascii?Q?v30OGwfa/BPYrVTSLu5HPcsK4CzaE1f/HKZpMVej7yuG6dN2zlPeBx0AShW1?=
 =?us-ascii?Q?jMzt1Zeqn6PcS0WP6LDfS2ysDbk0ERCXOBasxrVeQuhVcWkdcvDfvc0mvVtM?=
 =?us-ascii?Q?Ik+TW8VglaYw0KvWsViWt49H+58/tgiSDgGwK3CnNKXlNfNJ06r9f3rCrRv2?=
 =?us-ascii?Q?/hiEODIIlZkU5yofdyldhiBM41SGkUhGvdarxmLqIhBk91BN3z+Gobs1BmFM?=
 =?us-ascii?Q?Mc8vy/avgyiiP44YtPjgWOVLk97sRBLelJTlGoec5s3Y7+1JSHXzNbL19zUs?=
 =?us-ascii?Q?llTxu4SoVhyKFrxNEmREkspnK9IpNgWhaYm4OG5Ysfw/HjYytDhi65uZY1TR?=
 =?us-ascii?Q?fD9WKBL7Ai9OjMh8hOFoHftQoot6ZNVXnBNvU5j1wxQvxDPbtrLHEMso//0s?=
 =?us-ascii?Q?ElnFbQIR9MW0C8NuSsAfXg7paoum++0mYU2Bz07hV+MhxE6x4ZeSzh4IF8Ow?=
 =?us-ascii?Q?B5bKIzj41TIo4Yc2djzeSBdCu31YC/NyKmqMy6lXg3IIvE7j9OrNSvE+m8NL?=
 =?us-ascii?Q?cy7m7QvLYok=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9dMK/p8Iu3s4Mgo7x6wA1TXLb1LDsq+0FSHiETRztPu4/gpLwh+kwy/Ro5Cd?=
 =?us-ascii?Q?X/bdEH28eZ9evw6fCCHtRz5HhVxYlF5AEpHD69apOhhyVSl0nFPHV9gy7GhI?=
 =?us-ascii?Q?rX4YbZqGpoEhfHGpiMXQ/NZRLTKGTJQz3lg27oKYgg5bcIruBLQHR+OxSrSK?=
 =?us-ascii?Q?PDHBQWDup4GlHaE90RULRAmmOq9CdEbU/CAdFY2UcsYO7vpSIh8sGrT3wXdi?=
 =?us-ascii?Q?VnBGTvpPEmOaZe4/qI/d+/VrvbmL5BbpUgF3XVv+Cx61TfLzBpxfS29MSQBg?=
 =?us-ascii?Q?aQ++MoAWyGE/QSD62OEqb2hsDHhX2EQIl4dMyvWMv+25C81eEYIMzZ9QyJVC?=
 =?us-ascii?Q?UPLajGKD/41qnGtpWojF3TYLSmyqGMUq8E4sXsVrjhvJGzNWR/XaJrN0FXYV?=
 =?us-ascii?Q?FneaBeZN4GkQtT6iz8ipEtc1q2muS7TprxgxHPxxPOf2a81uYkh8TExJASaf?=
 =?us-ascii?Q?I5Tkw3YHYfkWlnTNwh7dCQ1fNFeYOmrVXTZwrSFpX94TU38+EzBHwHMehlyb?=
 =?us-ascii?Q?w/BMFpfJNkaQPX1N198OH9yRroDSF9jePxulfgCK+U3MmwwkW9a08xC3Pi/v?=
 =?us-ascii?Q?gvaOiyQsSY2g9douepvybNT6wYwP7i40VEc2Td+PaqwINa9Sjf4L6OJ1wclp?=
 =?us-ascii?Q?DV5YQwQdn2OSvK4rZ2/e3EOIODyluEv4gjJ4Gq6dNbf6G5A4BZ6GOIlHv1nK?=
 =?us-ascii?Q?huQtlS8JuXZWhDlystrFuYp6dZKe8rInhCtzYuz8K2xtOJiNAWHA+bwpgjfU?=
 =?us-ascii?Q?3jODfCRL4+6dr9DfJ0vAMmyDikU1/J1sulJGdty2bCj4gs4KK1IG4Dh/C08a?=
 =?us-ascii?Q?8HiGoWngEKPOMK6La6EYO2FT9dKgb5afl3VBER5DX6oj9rIXMN3gVaCOdcHU?=
 =?us-ascii?Q?WxJTm+PAItO2gaDrZfpiuC9Q2n5Pj6SR6XI6RQ2EXG3I/ryUHN6pr2bxPtVB?=
 =?us-ascii?Q?cdF/4tWtzDttzCr+I2G8ubQc+wbRAgybexyq2XbmmjalxTuAoPwZgzSiN9qw?=
 =?us-ascii?Q?6JWFGYpu4Cj+huB3GXnShTsrQlIuUe54S0IhxeiIa91ykw5VKVpRW2u+oo+Z?=
 =?us-ascii?Q?zg3iEfrFLL7Jd9HL53tSpDi1vBbl6UC1QYYLwc/G1YnqYvhsT+Up21pGSMsl?=
 =?us-ascii?Q?GGH07A/X5qKTqgBgUesE8Mw5/H8EDtYc5hrqaimztD7/ccMZDsgFUhcPAbfh?=
 =?us-ascii?Q?CyZHcxiI31hRq1ZQQMX1oE24o6Vk4gLoIGjZWD/5JyfD5c/MAY09LYf2tMt3?=
 =?us-ascii?Q?5X6F7UQFChEhZRd96cUUMc7y9SrjHvHrXnlmPemMcOcCEschlpltk6QUlB50?=
 =?us-ascii?Q?y71FKiWeOE60EPHhReDKmt2IvaHoCQEw1VuzkRxmDB2GaXp0Rg8dxBIwyPTy?=
 =?us-ascii?Q?B55SKxF7MTyO6T/j5RgyNcmRYfCta+9NvgEaBSD1uw9bkQE/H3QJGLf9YdOq?=
 =?us-ascii?Q?b9uNObtzlNCeqaRhK8DZuYYM2SZtloOJNWqk/VeobeFHOmlQp3y+0ne/7tLX?=
 =?us-ascii?Q?7WBGeyx4sc4Y9J9CFAyFlGZE5zSCDyI21Og0PvNpfbhsRV8g50dlAMP/VjxN?=
 =?us-ascii?Q?UPD2EzBNVVFzSoIVnaY=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f4b50d17-26a3-4523-d1c6-08ddf62fed5b
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 21:19:46.6773
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: be+TFSjYy8XT9dattliDuHoDgNRD7xE6VoLABPr4kF6WWTDDB1QK2yDPO6sFeLHc
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR12MB6376
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=hK+Q6egU;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c007::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 17, 2025 at 08:11:09PM +0100, Lorenzo Stoakes wrote:

> -#define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
> -	remap_pfn_range(vma, vaddr, pfn, size, prot)
> +#define io_remap_pfn_range_pfn(pfn, size) (pfn)

??

Just delete it? Looks like cargo cult cruft, see below about
pgprot_decrypted().

> +#ifdef io_remap_pfn_range_pfn
> +static inline unsigned long io_remap_pfn_range_prot(pgprot_t prot)
> +{
> +	/* We do not decrypt if arch customises PFN. */
> +	return prot;

pgprot_decrypted() is a NOP on all the arches that use this override,
please drop this.

Soon future work will require something more complicated to compute if
pgprot_decrypted() should be called so this unused stuff isn't going
to hold up.

Otherwise looks good to me

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917211944.GF1391379%40nvidia.com.
