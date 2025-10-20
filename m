Return-Path: <kasan-dev+bncBCN77QHK3UIBBR4E3HDQMGQEYX6W4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E9F1BF1BBA
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 16:08:09 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-430b0adb3e2sf56664875ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 07:08:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760969288; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nhs3V4jefXMZmOnE5Pd7OiZods4eN+AbMqzcl74FQyiwGzVCV3jwicx5rzsvc3wn4O
         DZToz39y/6LKW5Oid5yR4CP0y20yb1L1iyExg58ybkeNgrvaVXpMjdSU8PRj1tT/9CM+
         jtDx/0tCVHXtKpcS4U5rJyxeBF54N7L76B6HboasxFMXeeuox5rsiHSzdgnDn6WYL9fv
         bteFd1KJ9+GBEYvyeb9kc4ZCAWnwgd/KXF1Luq3zGsvCiukuhciXCk6+cy37TQrsNsCU
         j9xdDCd7wG/EXdIgwbGiqcPyCGnPZMQM5ay+gXF9naxAMhKwy7mytFzZIM/EWE8IhrRC
         QEtA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NSgXZnjHJ+a9bPlwYVZE9fQXyzOyhbO9NJGQ4dG0JGg=;
        fh=6aSfmGuHQAjrkDKOb8wU3VSSX2+U0+JMDqY4wP/sJvs=;
        b=eFr7YttwaaCWgeKndt8HpnuMBTcEtZy71nzj2YNtz5bte+/VfAX+Z8AqrzlD5j8d/x
         eiOhkWBYhz2WVgDwTbFAYQNPZTU0ChyMB9N+kWcpoOtiSwuGlA2/NQzHCd+AaqH1urVb
         DKW1KWVr3mh8Eslg0qAhQC9i1YBo61p2+S6SD3B7H3smVIcN/WjJ9WSMfXToDQhs7qtA
         7Dj7mROcRQmdQsgEJAutpdVVxu2Llh+ad8Px9UQ/PhXqxfZe513QirP6wXkUuzgnmred
         tQ030KnfryAbO0TDbdFYo/NTpPk4Zr6DliG3sG6S8qX84iyihtBnEaGUDQMAqQ+C9G1A
         b8cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aKNns40I;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c110::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760969288; x=1761574088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NSgXZnjHJ+a9bPlwYVZE9fQXyzOyhbO9NJGQ4dG0JGg=;
        b=KfsaW+bZVf/5rkIbyn551HfChBY5RmDz6rBw6y3wD4dDE28SsPvXUuEzg7Xtu2JMDG
         s3r3WOPdBvtvISiBR1BI/4c6v0N/aMEVXSxBk6rpOPA1uPVk+VQiDLAdaY0MO3645h4H
         M4GuN7bUD+iR7c7PGLFfDen/MJrp/63g8GClOX8zm9z8G3dyweBosVHoOxLpYrJ1Er2E
         NxSGuWB1zu0Tm+aZPTs05lZKKOaDs3IVfbNogjM0EEU8VF/rDoOSX5LwlDAfXsLWkI8T
         4s9zOR+KkbZ6mClvOHsLqXx8YtslBEUWdU1IFKnQt8hsagMJablbRjZ3sM5XxWcwgBTv
         evSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760969288; x=1761574088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NSgXZnjHJ+a9bPlwYVZE9fQXyzOyhbO9NJGQ4dG0JGg=;
        b=uhiu0zVFSfUWmQJsenyNaQQw2Z9fsj9PIH/LcJ1IthrdxVZQ9ObAXzeJYkNAkvUPuW
         Abs7s/O0sq+TT6E0Y81PwSZAZXnQLMwuHVMIJF3A3tJ2hVs/EeBrTKVs/+ic9fGZMY72
         jM9LhegHwxuOl1IiTcB/RWK1lqaxjfX+RUGxj9GMtFs8GuevjGtYOcc5ph9rRc4a8JpG
         fzeQn16MY3uip9UMelZ9CxG/0fkvx7nBRiRLDR2yMqgOtsHrV+oqFsrYRTBPEeuvynS5
         wrPcm/F0IHJ262LvqvkkGeuXJuHPY+pnW4YKgdIzM6lntClWwbBIXi2khig/b7meSKzv
         WtZg==
X-Forwarded-Encrypted: i=3; AJvYcCVVYwxAijSmrIVKxmDz1Uq8WEFkS/vYWycuwMluVcfVBdh+5MnZ210pePB6RPyHPXW+WlhH1g==@lfdr.de
X-Gm-Message-State: AOJu0Yzaj8VyzFGNA1iWogwm6AIxPGvL8sUApSbXOSsSz7oU7+Hn71bO
	15w1+po80SDxxce1SXLtDyErbdcUm7rIGgw8VeKyIReA88IRx3H3ju7s
X-Google-Smtp-Source: AGHT+IF2G1neokYjzxgWlqsmZdEM6h6KUBQretRn4XgxyNsIk6DvS6/z9ImHavVHgbvZp/1tWdgIPQ==
X-Received: by 2002:a05:6e02:258e:b0:430:ad83:6354 with SMTP id e9e14a558f8ab-430c5199ee7mr212031005ab.0.1760969288040;
        Mon, 20 Oct 2025 07:08:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd76YcXeiIEOMqvYDozuUmukqeuFErvqzPuO539q7nPBsQ=="
Received: by 2002:a05:6e02:4d1:b0:430:d124:bbf5 with SMTP id
 e9e14a558f8ab-430d124bcf1ls9035565ab.2.-pod-prod-00-us; Mon, 20 Oct 2025
 07:08:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXL6xhLQH1J0nP89F3j18LJlkUoapttJjZWWa63cBUIcf71XVxr0u4W/Gi69PudyL02/GKAZHsun2c=@googlegroups.com
X-Received: by 2002:a05:6e02:440b:10b0:430:bf84:e94c with SMTP id e9e14a558f8ab-430bf84e9e5mr157439695ab.13.1760969287057;
        Mon, 20 Oct 2025 07:08:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760969287; cv=pass;
        d=google.com; s=arc-20240605;
        b=R5LVqUsJue1pIO3YX7OIGMkVwkhshCpUxOv55EK7yg+jsOsOiCoTWUqbaF1F6xT46o
         2QmhT4scVlEr9qdPtqGURFCMfb0z3B3p8DiQ9yBGgf/Sgy6oqKhH2ZjOVP4VaWXP2WPx
         aqftyW0Mo1w8qtve36IKpQ3deb7de2B8dujPSo3nZbqW6ND9e2fWpkxX7oqF9Q3V194b
         jQSEvVAO4an+l+K/pCoCNju0NZB0OHEUAyD+HIf07rH5oGobXcKpqgbf9NrApvQ2BKJa
         ycC2lnkYY0x8QZJaYSeDC8sjhMOgUX/w7FVuXnOZZaDZGMA11zAJL2FwjjZRF7SyEigN
         Jx3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ffE3S7eV2NquZuNccTOETeouskHDSr644Vrofs7AGE8=;
        fh=teGKKSJsM5H3dlQiRGBASySuL9qZhVPyj5pwuNj/ik0=;
        b=LoRUSbpXhXlldkD1MgGrnbK9R0/XVPTDSbqVi2+VDVNCzzytWnx8itmDs6fMkigKGO
         UO5L2Cgrb10Po4Ye04qZScscsxoOdDb7pfaDPNZzrmKqJpEHhNO1Xzc1Vpqp1QjODbsp
         BnPai6UocHgjuwvkQXHkmg+cvRVJRW/tyJgIizu8pNCROAkGTGt+1KQrjtFRab2QvdzV
         dygLzpc7UHHAvphn2tkO9ZTGJI34ulOG5JYhhTDq9oI6XtcplbYZTF4loDxNL3P8tG0V
         6f/6KflOjBRAi6NQJyIh7ifad8l4z9erIxUPzw/ydsR7qTBkx2fb99c0/nGX9/tg0HDz
         WZOQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aKNns40I;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c110::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from BN1PR04CU002.outbound.protection.outlook.com (mail-eastus2azlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c110::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5a8a95e8f2esi275972173.1.2025.10.20.07.08.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 07:08:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c110::1 as permitted sender) client-ip=2a01:111:f403:c110::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=y82TM+Uzi8aBznkHMFFC0EOhxIl7xrqeOnEWIlUvAg2x/3qBUrdRkoxsO60BKrl5aMGxzNGwF5CzjQt1TR4I+3n7FS7ZdCCIYjhjiJMd7BuGgUeKNb3tA8WQ0U1uTWhE/vR/T4WvoFcRR8ua25isMMa1ruMwf7v7/GxwbYz1BjWy571OxwMjJhnAaNywKxcZw/SE38wklw+NBDmoIl+ATRNx6jiHmYP8IlUnRqOuAz6CGYeSryNFN+Mxxtb9Ayil76lnpAcei6zqTxHAI0vf+j9CiIFGAHcVwo3Jx2a24cx1BKpHJ5d+RjshvVIRtwbVSdLeIxrv5bzI3rkx/SIMMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ffE3S7eV2NquZuNccTOETeouskHDSr644Vrofs7AGE8=;
 b=I7ZbYVJKg9oiGJrjYFtu70VwMrRt2sLZPYUlgf+QCJEK3LpA6eVYRpcQbEMZkzB5nlejMw2ye0x3wcsh7Nisc024yduYDNjj2D+jSSGy1satIOJGJ0Klk8P1A2z0vhebWzCqIh6ddl2NBh40rclXfOgB+smgFY4GBMiVgHmvyJEVhym2P/rOZZF2P2kSC9iDQcabBZfjcNv7EcU6SdOUO/3PW1/V2eY6BlntCNXWIrGEwTX/aG8Kq8e6L0crzeHcNp5SrJl5NllWaA6cbMAm8IZJJkWd+R0CQyqBe752o5TEBB6wiBuTPKoNTurutiJp1/D/e2JrLT7NWbGHmNwpwQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from MN2PR12MB3613.namprd12.prod.outlook.com (2603:10b6:208:c1::17)
 by CH3PR12MB9315.namprd12.prod.outlook.com (2603:10b6:610:1cf::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.16; Mon, 20 Oct
 2025 14:07:58 +0000
Received: from MN2PR12MB3613.namprd12.prod.outlook.com
 ([fe80::1b3b:64f5:9211:608b]) by MN2PR12MB3613.namprd12.prod.outlook.com
 ([fe80::1b3b:64f5:9211:608b%4]) with mapi id 15.20.9228.015; Mon, 20 Oct 2025
 14:07:58 +0000
Date: Mon, 20 Oct 2025 11:07:56 -0300
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
	Robin Murphy <robin.murphy@arm.com>,
	Sumanth Korikkar <sumanthk@linux.ibm.com>
Subject: Re: [PATCH v5 03/15] mm/vma: remove unused function, make internal
 functions static
Message-ID: <20251020140756.GQ316284@nvidia.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
 <f2ab9ea051225a02e6d1d45a7608f4e149220117.1760959442.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f2ab9ea051225a02e6d1d45a7608f4e149220117.1760959442.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SN7PR04CA0017.namprd04.prod.outlook.com
 (2603:10b6:806:f2::22) To MN2PR12MB3613.namprd12.prod.outlook.com
 (2603:10b6:208:c1::17)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR12MB3613:EE_|CH3PR12MB9315:EE_
X-MS-Office365-Filtering-Correlation-Id: aee44070-5705-4b56-1a43-08de0fe21265
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?I1G7H3QzzTzRzakzerfbdfgT6dxNneIlP8beVwcJEnU19TCF8+2rG/r3nxIO?=
 =?us-ascii?Q?JFe884TehnJAu9dFWXdna0sv1JW6jHJR1eOnVE7QK4lNodB8W84hmWdOJBVv?=
 =?us-ascii?Q?lNARyHXdu7FBWdy6hn/JY0JMF6FrfYjs7fJjkYGNElo3wsg/H8+sGWZPb5mm?=
 =?us-ascii?Q?r7opXUia8pSM3Z0fvIf13d3ksZwNwtvu68ucOzvAJqJTvuWBSzBxsUtQvjav?=
 =?us-ascii?Q?a060oRNAp5+q+hYMPXsCCHouUd4bFoxNocu7lAlfKEc42ZAgqy+linV26YyK?=
 =?us-ascii?Q?02Dhntuk4p7eVCeVJzoHYrXWwWbnn8mXrFjc7Quqjz6nf6JPD+Ju8B9JLcsU?=
 =?us-ascii?Q?3jy4f/8Iw0Ug+7y2nW0jrf5ZWKs0CfMDBe5wTc/PTg1ueSNkbofeZT1sqQaF?=
 =?us-ascii?Q?cpvGEK4T5nfGxwUmpUSgUHo9qhxKv1XIg6FrR29j6Vh8PHtPfAG54wG3DaiK?=
 =?us-ascii?Q?A+99q0qHDcEXfPT/n4Bv6gxNCJdZ9hGR+DA71JGsAS/HBGprHVKTMlByPPKR?=
 =?us-ascii?Q?fGcWN9Hln/vYI4b+OW4/Zg/1/fNWxPJz/CbNPgvt7lx8yvJo3p+TpknYuE+/?=
 =?us-ascii?Q?v/MKFnU9R2fYyafrpnonjBZc9K7NfQbmnHeVUXfGQCA2VlnpCg1kL06hEgDC?=
 =?us-ascii?Q?RVvRxQ77+2sGQvHX3JKp7joJepIe9OElGQ5jinD0OkRVefwUjTgw4j9X1o7p?=
 =?us-ascii?Q?IaAXOZRPa6CKQ9Gf7m9rFzxnrcADWnJB5ykV3xSitp/2mSa5TkYkMGKvAcUH?=
 =?us-ascii?Q?+AXvXOPxzsLEj1nu7OIkjHWg8h9ik/lBi2pZEcnS6zUYxJMoOKSDHWKUyCBr?=
 =?us-ascii?Q?fNzNC7A3DBHNUxUKBknOQxAZpUevAxZ+sDfoPTWs9lHsqP3aQ7HZThRYG0HT?=
 =?us-ascii?Q?LsI2IFPYwBv9fzM8tJqgpl0xZVmO8CkCyEff333vVhdGyXJkJ+ON7WQ4sssi?=
 =?us-ascii?Q?Crhr5ydDlk//NuIAjIApY5eNb6tcwQhYCa9Y8x8loL/388uitkenok4VD6yf?=
 =?us-ascii?Q?bcJVZBuCug/+3GwVs4/xJg9nXhDHXo+9PonetSVnB2OqHTFT+4O+AMoNy9ss?=
 =?us-ascii?Q?Nmfy8oxqrLaPJwp5U4pLHfuEOux4SNICMHpoY41CkjIm9ZeOBRxhDwtY0ZCD?=
 =?us-ascii?Q?rRAMw/9MflRkf1IgjiTHFxG23LiWZN6SqZ9tpxJ1WGmxLIphRlltWm1r8ytK?=
 =?us-ascii?Q?N7mGQukZbIEQVQluRqskOEw5GrwMYHx/54jQHsvqmX0TUV/yzp18c/xTS4J6?=
 =?us-ascii?Q?yfsc6VKFxhwN125UYp1+44jG2a6K4KRSuxF3wgcajM+tTK9AYSvutShzqVdX?=
 =?us-ascii?Q?xz3ypxgiJIbaJn3t0Th+8h7wqG2mlu2ApZlvAMeTpqbF3AVtfCv8QzalsaCK?=
 =?us-ascii?Q?6CCZR6vWgpkmsMlJTVmkE63KoCpdl2PvgApqZoMOkMDbpY7agPFDErYg04Ko?=
 =?us-ascii?Q?UwIVP48N/npOcg5fYkzRIW3sdRf6dmU6?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR12MB3613.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZibO+wB07mSnxnaDI/VyA4JQKAtB3rtb08Rw8wA2AGFu9nbTNo2B+0L1mO6a?=
 =?us-ascii?Q?xv47wl+o2jXscUBaq4Rad36qEA/QPSMu14lSDnJnuSdi4sD9hvNaA23Ig11I?=
 =?us-ascii?Q?6ArApgCvsOzZ+UtGwGsY4rwKKA6MnEW/rWE+x4DtBe6ELKh62S1NJ0iHtRge?=
 =?us-ascii?Q?Vpn09ljeCX8OIJsUoeXhcozEzd2jqCivWz8CqJGFQEjMgtmNBqagOJ3oFcQ2?=
 =?us-ascii?Q?NwppFFb2EXHQqxwdoyQXx+5aKVNmZfJ0N7tSOWRZI2p3TPesI+HHYyvdJjXy?=
 =?us-ascii?Q?bMVYYvhlJsmpf0lDWL7IiDL801MX3zS46jc0IsN14C52m5kp8Z7DgQhpVVnK?=
 =?us-ascii?Q?fOLgrTzTP5Ngo/OPZERQ6lsgaOSNqjbwf6uDu38Bq+xV+dA0FKVusC/pK8nO?=
 =?us-ascii?Q?MF7fJvbgfSjqULcNovil71Q1yI3uap+1B0RbRkLN21zaNAiOC86MsYNzeDV9?=
 =?us-ascii?Q?+js2nVZD/tQhoHn47HGn1EVZPxVpeiBt7jtja46FLwDwYlyt+XFzbd/0sk4p?=
 =?us-ascii?Q?31I25fDjgSRgdqGrBEecs983vbYePfbUTv+7N7ykHg8ImNsQuCFoMs0D/m5c?=
 =?us-ascii?Q?QDd/Z7AQ1SrqhbTLm1QATxGMKHHmcXiDIstrRV+fX9bII/rzWPrfIchGWa/i?=
 =?us-ascii?Q?hosLyAs+xZyDqOP50QXmf2HN8Svirhw1AC3FwxwddCfhZnP2sNIlBsGCmXso?=
 =?us-ascii?Q?SY43EmMxs1aRb6sCgJ4D6TMbQw/90mlGmwmpO1r6BS7utf7u7fNmlG94hp2E?=
 =?us-ascii?Q?mwx2X5HJ+VyiZycbnsBEofQNcGySYXdbu0JZN86ZDQ0WDdGdN0BDzl/FSnAO?=
 =?us-ascii?Q?EMe8IeI8P0qSCJj5okFAsJZyxUHaOeyBZ5JrAr1+sM6BgAsKX//HMxNpZcs2?=
 =?us-ascii?Q?biWNnHeMKwcyefnxP+O38kivdpDeaoHB6ocxM8H73C3LXO3FalnRP996BjuH?=
 =?us-ascii?Q?km3s0s6YLKDsNAjmQI4dzdjxQUty18+QMXLc3kWYZBxbUxk4XmFizamIfYKV?=
 =?us-ascii?Q?8m6mqSAaNYwlmyB37+Yr/B6GmjCKjcKVxyOdjtu6CyfwJ5yiUcSFnNrUWlwD?=
 =?us-ascii?Q?Fhn0MN+jSH4oM5W+pO5BnkrR4WM/nfGaXjtx4NIrqk+wdHoTYMB8t9QPadEY?=
 =?us-ascii?Q?c2pq8eLa9eKccx4tJgeVBBtnK8q+cqahlI6yrcVDfqZFycvOxjbwUQTQX5gG?=
 =?us-ascii?Q?lkHz6Oz0T1yMOEiQ5YRZcItllGMppLnAtKVKinhp3gAVeVMf5b0DwGq6rJhw?=
 =?us-ascii?Q?BL0uff0wAo+FuBj12k1goT97UDJsAHhGIa8EP6FjJ5iWovMXZwdGreV04F7k?=
 =?us-ascii?Q?nlZo0wqZtc5hskCrdg9zjKJ/wMNzcTkYNRwny7oIlB7Qvg8oEz8/EZIJC3TJ?=
 =?us-ascii?Q?9ca9NPT3TC32MdPiaHmy9CqGjqMLVSyMtJUZodxlRdQk/W4zLweHEr4bILyh?=
 =?us-ascii?Q?fSrYtPjxF5pglEPWeGc0Vl6cLJZRps0BX3b5i6Mzegr1Mx6Ccskp2AeZUNQI?=
 =?us-ascii?Q?Fp1meKrc9ehgCP7ZcVP8oIfWoJZ/zNI4/+/h0Gzqb19OkmPRHyo1BkWsom1L?=
 =?us-ascii?Q?L4YphHUdMz5Q0KmStgjOyRGN6VWGGboHeKg/xwx7?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: aee44070-5705-4b56-1a43-08de0fe21265
X-MS-Exchange-CrossTenant-AuthSource: MN2PR12MB3613.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 14:07:58.8192
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vdPFpJwY6uqxYCYlmIkkyEChF0VLLh2rXtevOJUqGJmg8B/PbPJTRjlxcMJR1yVt
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB9315
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=aKNns40I;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c110::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Oct 20, 2025 at 01:11:20PM +0100, Lorenzo Stoakes wrote:
> unlink_file_vma() is not used by anything, so remove it.
> 
> vma_link() and vma_link_file() are only used within mm/vma.c, so make them
> static.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>  mm/vma.c | 21 ++-------------------
>  mm/vma.h |  6 ------
>  2 files changed, 2 insertions(+), 25 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251020140756.GQ316284%40nvidia.com.
