Return-Path: <kasan-dev+bncBCN77QHK3UIBB6NGU3DAMGQEYCJMCSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 85912B59DE9
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:42:51 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-ea423f034cfsf1922848276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:42:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758040953; cv=pass;
        d=google.com; s=arc-20240605;
        b=E8mW3/0oW4428+u0b+KGRpd5WS8Ch1kZSh0z5V5eZHbqqOcFEX5hOtaRb5mIDZpn9J
         aLXezIGd6IUaEVivI8zvHdb0vOpqUaDFxAhlJ0oA/4XQrjFjMIQb8Mt9GgZK+AR+0PVp
         pzmoP22c2JK8HWoDNxd+Ex7SxYn7BwkGrTbxAa4am2TYr4S42s6gQqbFwpowhkHZuea8
         /s0YdhswcbEqFWFvYjlyOMl//0uO1kGMBLECdSXzpmIWFC/Fa+VQkmQ9fdIbUXL9bZdy
         pVTIALUYnObVwVSLp+ps5EJ0yqOTLWFrYx3MMb62AKxYI9KeGYDTAowLwUOj5RRoKbPP
         oPcg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dUtKpHUpVLwvFzM60Ujap8qcXIn/u98tTdxdSjCiLk4=;
        fh=DpXtp5Mqdrdp3UfEiJK8BRN9gHxCU6BqfY+aZGK4x9k=;
        b=Vmd8/8Mpq71gL/XFu8U2bEwpBSFS/PqPMyZhzRlW4NptUr0iQx3j2kUM3EEPQtOWFx
         4aqJTUiY61BG5A4PfP2VIFXkKG0SdvL2WUOCuc6EdsEjre7lwFc+KzxanckMLHEEkuIl
         gQFXR0u4PyB5nWLZWRSYJSxyW36bTCJe6siGZ0trBUVEaCANw4RJwpJT794u5HOttvt6
         FiHK9Njhiiaq3vSy1zW0ghJVQDY1PBNnKQINazlJuB2C1QutOeQNgHIliHrYfNEuJrB3
         udLI+AoikbCZgJNJLs8wPowpem/Jzn860zZv8YDLxc8ZjPheJPpYHIka7NOIsHndha7f
         NQzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=KYR5s9rN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758040953; x=1758645753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dUtKpHUpVLwvFzM60Ujap8qcXIn/u98tTdxdSjCiLk4=;
        b=mNaYnLVNjLZ1PjCpfr4vSyX7Ei9I3rIb/lnCXQ45RZPd+nWarKKSMlueyYBLMjHUEG
         srxF29t41rYee2XeYeH6JrrfF8WMSMfCf2vpb7rygbllXkKLziBg5wGEIFp0rauvClYW
         oYkWHL2YxutuGQvKTctxct2t9tBTDPnpSwU31jMo8z4OSh0GWw0h5fiaZiG1lxqJcige
         Wj12B39cFjgUr8QAk/8m1AsxJVaYKbi364dQlzm+n17gNxZa11IrVfNRnSgNpja6Uok4
         1K7MjJVoWrVojNOZBGXKR2Cqmd0mlKZhqVR911zSWn5ciNV8Yh/YvVtpnQcLM5jrfFHp
         HsQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758040953; x=1758645753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dUtKpHUpVLwvFzM60Ujap8qcXIn/u98tTdxdSjCiLk4=;
        b=j8FTYUFvOB5j5Xy7+IOvsRl3uD2IHJwCoZAO0axocSPt2i+WpBwZQJzFJE7Ep3yFrN
         JKkmHS7E+gp5G8wbWWStRAP7/2/nH+CEI+Jq0Sxk1yyUWdajC4e4qZa607WWXmXjApos
         FoS/OQHv0VkWzs/iMt83PjBtUXLFYAtS56V/YVWQ0DN7Ukz/9HVGUDm6Q934SRhB9uZO
         Nf4E4zMiHvLAY6VdXhTMDTVjRzocirwOWe49VU3WHPna7cUOL4TRJs4CJcokyRmu28K9
         zUsMi+GtLfiQN4v26rQLqP4FQDMLHXbXQDqLciFzQkQcPFXla8sqTyxMCux71BhB6Xd3
         4zsw==
X-Forwarded-Encrypted: i=3; AJvYcCVdCbda6ypv1sI+3FqRCC8H7XoXyGVfCM4JA20MjMmkE8XXxJWR07dSeIqUZGxiVUZUjjbUOQ==@lfdr.de
X-Gm-Message-State: AOJu0YzEvab0KZYKHDQKIeGUOSIH8RdsQ6jiosYAjy5gCQvTEtJbLPjR
	r5lWwPs9glWPx/qV2MDfWwMxg8Q1hgKqcc1BWb9Vb3a7M2h6uPe82JM0
X-Google-Smtp-Source: AGHT+IGnoj6XzJLdy8468janu1QqijCJm20pcOVEeVecHF26fF8B7yQlYK845yZnyN9cQrTzvmZKzw==
X-Received: by 2002:a05:6902:18c7:b0:ea3:eb02:bc8f with SMTP id 3f1490d57ef6-ea3eb02bf28mr12186496276.41.1758040953310;
        Tue, 16 Sep 2025 09:42:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7WM1hJXlLxA+EI3n0vUHU6hbBzpDkZoRFdBRIuDuxkZA==
Received: by 2002:a25:d609:0:b0:ea3:fe5f:bd2c with SMTP id 3f1490d57ef6-ea5aa8ab6cals719056276.2.-pod-prod-02-us;
 Tue, 16 Sep 2025 09:42:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW5qH1jhazrHExqnupatKaIcIYBcA6te34ynRmhfPbU0JCeCsjMnyDV4vkhPbUqSki+e4mWY5rzg3k=@googlegroups.com
X-Received: by 2002:a05:6902:72a:b0:ea4:1008:f563 with SMTP id 3f1490d57ef6-ea41008f918mr8082853276.8.1758040952305;
        Tue, 16 Sep 2025 09:42:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758040952; cv=pass;
        d=google.com; s=arc-20240605;
        b=axy4kQUkLfhDENcjbhBjhCqEA6WPMpOzKx/fhhfiWHM82z2sbuZxE3RfGQm05rb36I
         fTfitTYYgxVrR6rAeTnaKDs8HbwEIMQXHX1DaJK0jb9f2KzvC5ue7Xz1ASS/VBctI6zp
         kSf5tscDx58/2yFpH7j43rawZ4QpDeOx/ZPqyNxXlFf15lyipA2CmYOiJxGap97KKivY
         +VyR4D5YlJy0KrEftzgeTJhHqX8NghkUC3WhkxXXEdjUlSGrgPI1+gyr3hMlFkuru9SV
         Zhjokd3E+W/EZBxTz/8PvIodjsVPHpm86xR5V+QOO52HhtrgcBsZmAcGFCdrmzGNB8JG
         tsyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5KqOnXqPOMSfIQFsq0XS4880CpWNHNyboO2Dq/ZbBAM=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=RJ1eUjabLHFqrdyVkKsU1QveRY+Oj+84k/QMeG83o9HclgRC7+0OUyZiDFMfjf7KsF
         AE6zP7XkShvIBJMKBnHW0hZ2A5wbmrLyEucT/lKhQtOowc2cH33gO8QpDzGgMdlBhcUG
         YTpLUovKK4BZf2F7HJ5ZEpRfM9QxuKTMtmiAp6HcMsOWQrRNDJLRJNBfudeq7XKUAqJ6
         TOfoL0jvxO6JxBb7A8menpj8OlsPUjC7uazG/zavL6bYqp7+RhPGaATSLe2/vMzK4sVm
         PFSedv1j9DiGczYlys7y19bUpsrBk6aWpUphoZ8c3U7LysB+2Hg0uZIwzo/e4VG/9Ux0
         PH6A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=KYR5s9rN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from BYAPR05CU005.outbound.protection.outlook.com (mail-westusazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c000::1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea40bd16f7dsi50911276.2.2025.09.16.09.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 09:42:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c000::1 as permitted sender) client-ip=2a01:111:f403:c000::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=i2n5dOzrM86zyEcyCLmjnRLDKofZQ9K8KlEUTKMlYD+epqj3uI0ytVz03hgEnDyj1ryrEhGBQoE7BLDZ7QMqAdr15WJ2D1YajkigxhLq5p29qFRGWqZhy88LikZfn74zwPx5YtEgcyQ4UEIKl1cSJHTNGc8ON4IPDUBwI9E4UFGSszMSh2C4o+pAbCIU7LtZrGVBI+cUqRJGgPt8kSKofGrE2P5ww35uqOmz5jhUytIsPlYoO34Zx3THQ/1yGIMc5Fwi9OxmfNuFUsw7kPZbhsFwmk7vkGmVoZd60I+8z4AJpHjcdqEOwHubozlwl5IA6ZxOUU33TdBj6Y8me5VUUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5KqOnXqPOMSfIQFsq0XS4880CpWNHNyboO2Dq/ZbBAM=;
 b=W1ai+o/r0sIYXJ7R2sugxO8ipE3NS85sV2gbxmSxDNpvOy+7EyaC6ICDREDBvhSrMOSt6GS2YO/ohUCqtPByjHb/n8dyRJdt9EAiEy1uga7xRs3QJ1l2p2283aj49tONNmUiKoRRwTbjuNuIntOb5xEkJ3Piz+YVx7Roz/uH/6WdQl65+4O70wIun1tfA+UEXAPnn5XywgnpGPsG71ydU5UJy0/JgoB52Izxmp03ZbO4GdF6YtymnUOdXp14m4neX5wAfi10KXate0NxWCZgUKHff+kWcSvW7wPuFUj8vwbpeEJZpaOrZ3Yy1yjz8wmddtjQXL/YGj+eKLPGhaSKfg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by PH7PR12MB5595.namprd12.prod.outlook.com (2603:10b6:510:135::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Tue, 16 Sep
 2025 16:42:28 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:42:28 +0000
Date: Tue, 16 Sep 2025 13:42:26 -0300
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
Subject: Re: [PATCH v3 01/13] mm/shmem: update shmem to use mmap_prepare
Message-ID: <20250916164226.GJ1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <cfefa4bad911f09d7accea74a605c49326be16d9.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cfefa4bad911f09d7accea74a605c49326be16d9.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SJ0PR03CA0019.namprd03.prod.outlook.com
 (2603:10b6:a03:33a::24) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|PH7PR12MB5595:EE_
X-MS-Office365-Filtering-Correlation-Id: 9a7a71c3-c75e-4ed6-582a-08ddf54005fc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?sd9HXtsSlL2q2iqz6tdA6IdfRyxLl9LC6bhDPzFsJZYBByVHdzKGuxc33skn?=
 =?us-ascii?Q?N3MDtde+VUhXvbZrnh3ySCtZ4Z7as7G5S49fBq32eJA0gKLK9GJfNNuV1Le/?=
 =?us-ascii?Q?Uz0H5krl+XdKEZkJYTMt6W032f8TOejir0+BYg/TjcGElFd7GTtloIjGF2qb?=
 =?us-ascii?Q?/tVx3f8oRSU2wM5XhxFW9Yp2uKGyYAxothr75yAaD0cYOD5tQ49cxyjZC3Am?=
 =?us-ascii?Q?Da5rzO2O4duwYBY9L6bK+G2u2SDBSbpitQ9szx76SMTyichn0JjqGIYo4nHz?=
 =?us-ascii?Q?Z1hBWSGhw/H35WnpCafgv75lBEsDxuRDgdFn9+zWeTNbmLLG5B01bm1Ykviq?=
 =?us-ascii?Q?/om3Do4TDrifPrvypuI1Lk0pnnL2ghRsGvXHcVvxuepKDBEf8wsnz48NNnAZ?=
 =?us-ascii?Q?e+8YrlryYIcLqiP33t8Aetpi6DAqEXsp+U0nSFXuFoDNADPmc3HNrhhL0viF?=
 =?us-ascii?Q?P607ELh0VMbxD8fJnBuLieIl/0yc8a1UyOBCohUcz6pbx70NFd9y67yST4kc?=
 =?us-ascii?Q?D4U8QFaIEWUt3ptZF+guT/iXFEFDQveDkiDmV3rkvKvLD40gY9xoISMHpcWY?=
 =?us-ascii?Q?olg5sjsVzCkT7DaVumkjOwTgO8g0Vk5Nr7xCSoBIibgZncdvlpN3Bt13S0n7?=
 =?us-ascii?Q?86mBWv+GzWfRTk8U/+3MRiM4vLgfSGdz59p3zEhDyylN926UiSwTNEoKFfbN?=
 =?us-ascii?Q?2BIaRXDCNJB9/eQxk+UY3AEwvK2EtXo+sj6Qa1TUV8YK61G2orgNjaMOlHt9?=
 =?us-ascii?Q?iFDadk5g072nBUkUGhfPyGIiNoOWOZ/uvJfS1//Ucz1XBekdzpPPVzdOtKE0?=
 =?us-ascii?Q?51lD3kTRi3GvWVTX6CYj2iMlL2j8JZwp5Z30P3PQoRkfPP+WzDrCo9dov8F7?=
 =?us-ascii?Q?qIe8eJsqnbnpAKFNylMVf2aJXZAI3KShG4KzjHj7vcB5T52tziH50F1LbBEP?=
 =?us-ascii?Q?UbZX6NzPrxF6mfOoGFaVVqMO5+H3Zny8fr1YrxjDDbZH7mMDmwGHS7t10lJw?=
 =?us-ascii?Q?/AYSOxmjv2sZeslSYn6ex1nYc9qQ03YVN9tO4BxG7RLDerqRqS3NhfByoBNl?=
 =?us-ascii?Q?f8qa8b2Wdq7LCg/QW/P6ngmxGni9EhzI2X9Na6tAQSvZavdRKe3dZWK6wcMc?=
 =?us-ascii?Q?DjCSx/dtqZgN358Ge8qeIReU0QOK+q5X0Z/B/s39k/ixQ6HeNHUrnG7pesFn?=
 =?us-ascii?Q?C34NNb3FPuR90Vnd4gUEWV162KgQn8IegTuXBEVMgAcusgq9+QNcb5dDZMHM?=
 =?us-ascii?Q?rOpZSl86NtE8iNaVWh0+AiDCg12zChA9kQnz2UOtkXISjrxfcRiCYkJ194kN?=
 =?us-ascii?Q?I2M6YL0LjBd8oUCGDnprdV+Gbl0BgAukywog5hR4m1l9Dg7yTVhn82JQQgyj?=
 =?us-ascii?Q?UnUAC1KfahgH8aome3Dmp8cDZIyiTURyUq99zdMwinqCMkrpzENTHYz6HkGB?=
 =?us-ascii?Q?EwfjScWUjoY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KCdByN0QhiLb5OlrdFihIkThYGoggvanKwgwW6C/AEeZA9JI4fe+kyWXV0tc?=
 =?us-ascii?Q?CQwgjDNbrRKdEfCExBYQYlx/AZGuC0skyFsJJjy/v9uFIp9bjhDT1HMMvwdL?=
 =?us-ascii?Q?n5/8RZDqoG3yW7n+mqEHj8WVaW8eg4ccpB//E9f6ip9m3txTKPP0AvrVRRX1?=
 =?us-ascii?Q?E3kvrf3Q8Qt6QrS2M02BO3fPFFAGLzqdf8tLP/Pf8cI1Eyl0KT9GyaJH0cdU?=
 =?us-ascii?Q?4Tq/otLFdWAwZcsa4MG7Dc6tHBSBuWah6YdYJuvuOo1RKHG5lagQ0VBWRJzy?=
 =?us-ascii?Q?izO15eskMZYHl4x2YMRghaHg8bh/9JpOgVaG7ho1Yikbe8VcaJVNvEQuDEDP?=
 =?us-ascii?Q?zFlP9fy4IaUVoPN3DaPvWQnByu92G1p5jfDHAU9UEbry1EAf65uq9MG0LzXC?=
 =?us-ascii?Q?sAgkO9c1d4HoILXkNWyJ10tO/3uWFzh3ikFNQ/UDOTexbFeSrL3dBBzakS1F?=
 =?us-ascii?Q?b5v/B5I1zk78e7sRBWrJAF+PGF7+jlnGxKq2koP0TG9UfRgGuRx7ihNXcu9T?=
 =?us-ascii?Q?+PL/q8gGfOCkrgUyZuyYHVE/wiLUOwwqaFf4beBEVE/raXCpY+62X+iD1Qx8?=
 =?us-ascii?Q?ghRaGVqctyEv8mQL5f01Ur/gdjYQDQdh+oXhAiNtTEnYaQFtcT7aIc0DjZ1h?=
 =?us-ascii?Q?GIiGS6pjU9MaXF1PMzeYNjvmur3roceK9LamwFlu3mDGya++nHiom7rubG/y?=
 =?us-ascii?Q?YErLy0heoFZh+mCzY9coLvCuzFzpW9+JNcrW+FaTtONTms8kubxNdhXoUSOf?=
 =?us-ascii?Q?cBs0kfGakMCtUAH0gGb2ujM4uwE0y9dnSi9xpdogO7AWeYMigncHmgbSWUJV?=
 =?us-ascii?Q?ESsNII7IC25JMEvJ9caJp30RzeNwT9G6TToODuwXQ+3v2szrk+fwJJMNg4Xe?=
 =?us-ascii?Q?/ixL+q3z/slu0ZKBZDaKNuFb/oZe8NW+4AVlQoVmxGynjPt4f8BkBisrDbyM?=
 =?us-ascii?Q?3fQzjJfTCYtB9sQ6+JJvqwbMJvBgE1UEz2H0F7NKrMuPHxTyPUTtUcNxrNRb?=
 =?us-ascii?Q?/rHgU+qrscgSCOYmvhjTTDoEvi0LpAxxvUR9xSuZAiB94VrIp33AkW7Pdg9r?=
 =?us-ascii?Q?s7skCHxIQYdM9/mgoZ03IPIvPaWGogksUKgM6CeV77xbLoVGJmPcVbiRBxFv?=
 =?us-ascii?Q?mafm4mvz9T5KZ/dxfMjxfp0e+akAgNa+xsZsCfulFWvcnmN/0M0Aq0/xH9En?=
 =?us-ascii?Q?CfFOcHgD991cK2ZWGSxmA5iPPHknsxkmNsjMG3GzpOf6e1MJfIotfYbTcRHR?=
 =?us-ascii?Q?JUfbhgwf3TZRUiXttt1Xf7GWf+rCKTgRkM13f5osarsnW0mdyLDbhmBG8uhn?=
 =?us-ascii?Q?5PWGSADPLywiFADwdB/3kvH2OcGxNzcpd7dsGzkpVLgtpVD1sCq8BjmSLfu8?=
 =?us-ascii?Q?asiq+y7YMnWJnWBTbO2lNQMD9twkDIEmlN3NB6tVO459qKDURPfCWb2tQqb4?=
 =?us-ascii?Q?7xeU1aP20577e4+hOJ46LcteMUGEPwgXJ3AGWb2f2jR3ZTo9ixnJi7bicuaK?=
 =?us-ascii?Q?RRQI4WKC4vIIGJNuKDxPx8aeTTk8oJKwxRCJywH/alt+n8GwCFQ5RE8k7We5?=
 =?us-ascii?Q?btTXXd6kHZ6MGurS5gXx0ci0q6fOduOYcr5DovbT?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9a7a71c3-c75e-4ed6-582a-08ddf54005fc
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:42:28.5660
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +m68z2J+2A1ECjQmSxhoqHS3Tot4XUstM8P4PX2h0vZRSZH8DRgZgHixl2Qsk65C
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB5595
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=KYR5s9rN;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c000::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:47PM +0100, Lorenzo Stoakes wrote:
> This simply assigns the vm_ops so is easily updated - do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
> Reviewed-by: Jan Kara <jack@suse.cz>
> ---
>  mm/shmem.c | 9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916164226.GJ1086830%40nvidia.com.
