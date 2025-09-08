Return-Path: <kasan-dev+bncBCN77QHK3UIBBJOM7PCQMGQEFCMVRQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 96263B49123
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 16:20:23 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-61db445a925sf5650182eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 07:20:23 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757341222; cv=pass;
        d=google.com; s=arc-20240605;
        b=OjjWxX+ak7H+SYSNUY/CJw8pbs2gv1VUDGTy4+MhGSrX/dqgNfETHGGHlLgMw1J4Jn
         cg+zLRsQnJblWG7bLWwPPMoqkDlkV/xt3+ypQYsZMwM6TYUkbv4KqbjInEPM4SeReX1h
         Cx7p4Nv4AHXBL3TxQyI7yDTt7Z+3+10NYq1iL51yWUITj5S6ADjW47Gb4bl0PPxKQVvp
         CgqLDV4+aHMsxny0ax3ZVO96k1MFrQi+LiDTDsOPJTTHxoq/IZOXGgDs5Q6gwgcbWGkS
         sveomAHJoDixgzEaCk+qUM2yNja51y6UUL2OEEzWQzTaI+ISURjQtaX7ByMf3L3wiExB
         hMzA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=iw2/RGmo5qsqU5RmJRZR41bISw1vciFMLseSnxnfVZk=;
        fh=zBBmEpgS5EBlYIFI86isdhYhb/BkPMHcRaH4lXJKTio=;
        b=cszl4SO01nZi2uyqT2oVq3p1G7cfZDA2vYM2cizkiMc2iwi0JheiWhddycEg4+yBUn
         YfHwQevLetD/mAaH5l9IFm+7SnQ99ZQXXtNCOc/sCLCOuqwYuygAPgu+lS5Zwj0oYjuA
         0mVvLD7cE6yJomZBxlWZ766qvIyIHCsQW6zo5/xA0jV0pUCgMAgetFBBwqzl97+MhUQb
         UVDBavyaNpSDKao3jU++vcLQorEFn88GCxJRM6YMfzEjcBkbJnAydAJQHzqETEfN0idn
         pYTNRutW/G8YsanW9VpSL7HBwZslZNaGRMbXGxLgJ58n5ikQXNE+XbQ6tnOr920g0oHU
         wrwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UFYRNqXu;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757341222; x=1757946022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=iw2/RGmo5qsqU5RmJRZR41bISw1vciFMLseSnxnfVZk=;
        b=F5Kn3iCrJvF91T3KP3ZMWEKQ4PWZq3U5NbW6SZswh5euJ2jwzGeVpPCkwv3gWbAGio
         Lic2VB5S6nJV73+if9EauwzkAwXqoULYQWFT6vbsTPLpwfFFiYmU7nhjk5q87UXFehPn
         F7cFO/U5fqnnH/aSD+cSu0am6ioiLmasQbFGG3L+vGIqPv2RmPQrGOfw1H54CGD3B2lX
         q5edXNZyMnv48SgswzNkCcvlK6kMhUll83PokR71Xs4jnJ5KfaoK0wC6fM6MK7+s9Y6m
         EpWJcpxHPxqfa3Sn/A6/TWPFm/XhEhqFckjGV2wHGIJNLMzyH1Cip9vHLjuvAy17RJ2d
         HBig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757341222; x=1757946022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iw2/RGmo5qsqU5RmJRZR41bISw1vciFMLseSnxnfVZk=;
        b=HDNQwMlXTcN144fCoACrMbU0U94c/dg1kQsCqdVcw63fJzmDsD7iid2DQoGcGN8MD+
         IJ2mbd0VLd5koYJrtwXE944RhizfCzqSaeMM+SaChQ66ZJ5Mz5Dvy/VxOfjbm4ZaqZs4
         Ms4Sh/CjOfCR9bvaWaVweN9sVqs8cfIysRdXxHdlapBQ03zGjY+ufdgvjAzyTojY5F+w
         9pBaZB4u+D81FxSJKH0NkgEmIL3sDYDdDqQYpvEtUuuPabUidssvIxAb60CJfvjmRmsY
         6rUILEMdxbR67Cnhx7U40QZUwTLbkadNrpDUQ1ZZayWgEn+21cO4OZgujGECfn3iM2F5
         lbew==
X-Forwarded-Encrypted: i=3; AJvYcCUuQohb8sDm3VWKk6/I0D16FY5yyClYNeXHKE95YMIMUqfi6CejfMCoFtJvy1NKT1hpMR1XSQ==@lfdr.de
X-Gm-Message-State: AOJu0YyDSVq2uPYSxoyQlJDArEJMnjoSZg5qWUmFkA86tfLJ8f+7JbMJ
	6d77LkEcT/tofxZdABkFRTVVPVlM4fdtxluwc42YgPZlVmMvje1kctf+
X-Google-Smtp-Source: AGHT+IGOkGZ+y3QFJX6QNehzXAwpnQVcbdVHnaz9jPs/BbfDuLWVybtse8ihQPJoFpiC+3LStQxbAg==
X-Received: by 2002:a05:6870:1cd:b0:315:87dc:deab with SMTP id 586e51a60fabf-3226480e8f6mr4909906fac.26.1757341222037;
        Mon, 08 Sep 2025 07:20:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6V3BSsLd4LYtxHY8T+7gBmJuoiSVsbBVZRXOW8Z+VBbQ==
Received: by 2002:a05:6871:e4c:b0:30b:b8a1:c8d0 with SMTP id
 586e51a60fabf-3212724a566ls921797fac.1.-pod-prod-07-us; Mon, 08 Sep 2025
 07:20:20 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXOknxWs0iqmv8SR+DkK0JQMEezIO36u3zR0INkKsCu1b/Zpiyg/X/4Zs3CpqoknfOzJ1R7HrNXfeM=@googlegroups.com
X-Received: by 2002:a05:6870:c0d3:b0:315:3035:e379 with SMTP id 586e51a60fabf-32264e2d45emr4255713fac.41.1757341220712;
        Mon, 08 Sep 2025 07:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757341220; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fh9qTYhh4U3mwcodv/GwqxrsAPDwLyVtsWR37eRxyDcHAo7Z9373e1J/h2xKPpM2I+
         sbaOfjFAz0H6G9aEEr4Exh+VCJXKe8aAgkeqMKyzYlwsoTonfSmqi+CGD516AhNAui7C
         FvYQ/1aI1OzhAHVyg6E49PDhDP8OWJikIH7zDiUH5679DTdxNK34rrNoVMS/IXiWh4tR
         QU+Iad+oqQtSlJdDRHpBi6fU7IcxyyhxadfQXkrmKLKA8IlYrPQdp8liTRrknsnm/669
         Ll11mpRqFj3jgzrJXpE/87GUpz5xYBRpuKjL2h7L0Hq4yliOYY3qdK09o8YWCekX5v8n
         uGYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xBtjK2xUYRThSvljThoLHjNrXDf79zCXXd6yIWgqAlc=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=iwj1G6E5AJcVke4+s/3lVp2kr2SThigeL6D59/pKXPN6LvsnrWal7aCo6zR99ounnU
         f4buhCcsscHAyWo+H/1WpOyBTN1/DtNxFv073ydhrteCZNotFAhKUb6ZvQk/sz9Ct8/e
         /3tkhWeqEh1l+tlphtIAVIEoK6qjj852akD2Kl8QWpm0ClZxf5yly4c+cnoFAXZAA/ri
         5YplTUDZhQO8ksYcxWwOQEqEhkro+5/RN0QBski1m7K/CUyceE+S2oTlObcS4pIrwmkK
         a1//V7lxqE2dQ8AzDIRxU0gOMiQf93A5XxDtv1yHWfNFzqAxksylQvkQpOh3K4mJJ3BO
         caSA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UFYRNqXu;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2060d.outbound.protection.outlook.com. [2a01:111:f403:2415::60d])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3223f6d0d07si280621fac.2.2025.09.08.07.20.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 07:20:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::60d as permitted sender) client-ip=2a01:111:f403:2415::60d;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RNH/kE0p6m/E0nWgExMvUaM2ySQsCmnXob1z3rgw+SEmOQ5wIE4v/sBJMtnsw7utCrCpdnKfSTQaaIQXhtPN/YJjFUzW5uy2gi1uqMmG8KfQFmXLMENQH7Bv+QLgQKio8I+NqtEU02NbaDiMn8eM6XhC0ej/sJHO5+Rr1xMXKjsU5fNuZnVwBIdL/w93gPapqmFYY7XhQTfYe9OWyn+Wb26cUEBUOMj44OBZmgp7yjFJkk9NkKgK3iYuTR/XC42i9x9J9aI56zH0C0l3c+szvaI+DtztTUAOvR7Ltgv0gpt7aOsDvKLa9CbLMf7ut8KcdhLusnHNMO2tZ1Eyz2bWLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xBtjK2xUYRThSvljThoLHjNrXDf79zCXXd6yIWgqAlc=;
 b=BPE6stLqcVZhc2nYOb/Zo4bS4f9o2jCgBhr/fMD0Ltl3tDJ82ctJvMyazoX00K/1FEIaPSbCcme0BI5glwj2Bx13IPM/Uc7oThs9vd/9PR+JsPr8p5+s/almpN+eENW2RPcJ0lPUWbOSBzSKsROoPYrLKd0XOSyMln2jJql2B15uFFNss8iHnAZtF4k8tgVtJ3xdGi86MJRdlUnyyWDnOPzR8Sw7Oqy26WAaU58yku2EGI3nnGiw4GkFtw0LPw1iFHMdNlYuFxa9j71koub5Sxnb1w2dpkwuNxAJLzCyTOoJkaF0KhU4KQHV98aDybdXvD/1SkDhCjgryacGFo96Cw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by PH8PR12MB8605.namprd12.prod.outlook.com (2603:10b6:510:1cc::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 14:20:13 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 14:20:13 +0000
Date: Mon, 8 Sep 2025 11:20:11 -0300
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
Message-ID: <20250908142011.GK616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
X-ClientProxiedBy: YT4PR01CA0476.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:d6::16) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|PH8PR12MB8605:EE_
X-MS-Office365-Filtering-Correlation-Id: 433c19e2-04b8-41f7-f273-08ddeee2d31d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?2/e+sCnBbAJlzNRhx38zyvxidUk6CswXCQcXZ0MlNvez7/S82amVq4uzFit1?=
 =?us-ascii?Q?PTh/wEpu5oFaDZZ1qU7VNts8KiMN37g2tMnL2ohZiBea3z+L+urKiyBMKcY2?=
 =?us-ascii?Q?/un6gpXM0wIIfgEMxsR0YlR0YpFtMnqwcfzk0aMNyIobsAJt5gntFH1FAI7W?=
 =?us-ascii?Q?h3RY5zUEEvnaGN4Wl9KBNMa85zcKzAXp31IeNRDLS5wuJRvwWZ5ei5CqCO99?=
 =?us-ascii?Q?cw9feOH6m9adddcGUWwNWFDFn/Knkq/7i2/0I8hIXI1JM9oAUD5ybauCI+LD?=
 =?us-ascii?Q?Am2mzukuWl1slpEAZTEfIMesyAJWv5MLekTlHOv8qDcA1JFTaVI9n0m/mstH?=
 =?us-ascii?Q?ya/c++px5TAlrMUjd543U8j9mjZmxrXdVyTLR69bcCpT5qCDfGeXd/9q92RF?=
 =?us-ascii?Q?sfQiUxc+vB1/GBSC8GLBFbKPeYHvK+pP4fbiuHateKpnX6M7D00kkheLHPK4?=
 =?us-ascii?Q?YqbDDkqk2Ggsl7Oh/xXtnryNsq3spCzpaWJI0rbO3ozgQY/2VmpRwNxj5XPJ?=
 =?us-ascii?Q?Vq2OLJrP2hFFa4WUoV1nXP+dUtd88UNbNy0s56tD2EOkxtChiN58rDd4Z/u1?=
 =?us-ascii?Q?y/OYAfbjSV+JDv7pnYw9LtF716VNmYvslhkwpL2O5g16SVjs9M/Po+TCKkIC?=
 =?us-ascii?Q?+tZx74XBMVVumjxBpHWYm3xhEVEIOLRBAv8uVs6zvgrv5v2yTxtlV4bvIx5p?=
 =?us-ascii?Q?PvN3FWS74u4G9QmCImf/9gEyeRTWRH2ZrYcJh6VJmziiZ9bZfWakmpBCRB5h?=
 =?us-ascii?Q?Vw2lDPxHqfG5LH/9CWH9lawOiS+38dP3jxOodOZdqGWFbydlcordg5mfU1AB?=
 =?us-ascii?Q?2WgZF/5FSEtaaERf9652uwuJUbboRx+RWInPxwBWTT7BQaMTw8o87Cu69heM?=
 =?us-ascii?Q?9c+FD7YgCsrHQV5VdFByGmTQmOfNEYUquYQAHM7QGvbhezI/Jz2Y+gf+Q7hI?=
 =?us-ascii?Q?fmMkikBkl3esOKBXcWpc/jIg4CWCxIpecSIgdZXRs9l6AThnn4CsqgqdH6Xd?=
 =?us-ascii?Q?VKUsLzccusIC5FaoQWRi8tTxSP9XPmdGfFUL90qlRZrKE4H3mhIR/i+bGY+H?=
 =?us-ascii?Q?A978hVBWNcbH6CC+wTPsOURc5UE/z1bCestZOgCfpqt/brk38RkC1GnBsLCs?=
 =?us-ascii?Q?zg+O56PdId9qmuOpfiqrYAvlJu9J/XVV+4XVn4sMFCXDkPVDuOA2139CY9SY?=
 =?us-ascii?Q?cwi69ZUm0ATkUL8wwUFZUsdaIR8P1D+nZV2WC++OKDSYNSbrnP9uddNECIH+?=
 =?us-ascii?Q?6TZmobnsu99ytyvT6ry2b51ifTW6gbRoD1pKgUYcynHQ/YumDBgQC8vMjAjM?=
 =?us-ascii?Q?dbYToOHOzIgzy3FY5vOvT9Hzve/7L2RZjCcm0yebpcEV78XgwBupiDi7m2/Y?=
 =?us-ascii?Q?LnDTmdvc19YoLCVAJqYgEvwFnwld9+EuyTPDYzoHJkrdRuWujg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?SOsWuvp3OXQPEbafdV2Ah9UA+sA+AYS5XicZlvVGDU/WB3IjOP9trBr3Rrmp?=
 =?us-ascii?Q?klpuwijHfTBO/vtVH0lh5pW4BBdZeG0xhhRqxuw0I6bwFvDSmzdiSRw+BSAY?=
 =?us-ascii?Q?OX52q2SKJnqX9Lm7wPVYBSWRMHjRpQDcBS8XxXV3oQRzNjLGJo0b7oDucPbm?=
 =?us-ascii?Q?fDzlUmddfk7qSK+EQ438HALg9i70ahaEnzKl33NHIzLzknzuokMLo4Oyvd96?=
 =?us-ascii?Q?Q3SrTvmfgBZ+Wat+3IP8MlD0zEa9f/qeihDeGl//yf+9MBibPbQJW9Y2Gv8U?=
 =?us-ascii?Q?mdeOYK3HIgvWjdruunXBJjA5ZOd6D8o3G0wr0gH3hGCTiqaKJVVUmzzeH2tK?=
 =?us-ascii?Q?8/BCL4kzFsAMKiJ1hNXJw7fdn8CYbSnsf9y1tnujF/n41CcuPlny57LU6ri+?=
 =?us-ascii?Q?iFsq/W7rdJ9LHpGuoZibwJ+QSHkLPIIKCn+3SHwhba5+GqU2ue7pI6suBmih?=
 =?us-ascii?Q?cBRIpWKSlSArS4DXWYkfhyEkkc7Kr6/0PwC0DM3eju8pHWYtlDbiVQoIKCJD?=
 =?us-ascii?Q?OrJL701gNmldYiJ4FHBD+N1qVAj+kiCASawyxx6hcYA8hG06EqS4mPfrXZDt?=
 =?us-ascii?Q?O6cUGdoMWNGcz+r3Sqj2KtW2BYExEN1UMOs6I5nxCy0s+M0i9gKhmLfwtF+U?=
 =?us-ascii?Q?+GtAoo2uOzNAnJDSZ6ve6bjmUHpT93EuzjFi01jEvF3dL/XXBbyt0HcGhA2F?=
 =?us-ascii?Q?FV4v2xM9MGZa3KOGWYpMyQryAzz06I+PSI5BeZxHYGWMBk9/7pknlXjjj+Kl?=
 =?us-ascii?Q?jnq+JhT8VMLaBUwCZvOjkfcAlRpwz5EzgnyCLY3xPt5Vr5jQiUBM9i2YVfY+?=
 =?us-ascii?Q?A8HBckXDUbxR9DkWoXMlBN1ncg4WpegCPiBivQweLB9IveIM5wDN/DJrxhsJ?=
 =?us-ascii?Q?Tk/poBYgPMvVgfCZiC5mLcRW6SReflBb+3LuLpvgm9t+rGOT3u5oJBkVjk5G?=
 =?us-ascii?Q?I6VXXOMQIVdcpF8Ov0yrSY/T1+SgiDTnA/ixc/ZhVrwUHsPtyHoa8mtfMDhZ?=
 =?us-ascii?Q?2dqOxKp5Cu68gCnBBdm9lGdLBuGtiwEQerGTTUw8Q6WpePZT2o9U5Es8HLA6?=
 =?us-ascii?Q?zhzGpXPU6VHaHl5X0FWYYEQgJycS/o88ijNsgAFnxyoZtxUQ8KwjpO+DdF2S?=
 =?us-ascii?Q?uWB/ZVS+645rHaNVlxO4cYLcdatA4CxFsMFzSiJoyRK6UsbnZWYUUG/yY781?=
 =?us-ascii?Q?hikhaSKrI1+ihxQL6Res/Lr0ZhDMEWct61VQ1/i6hLNQeeVZkLyRJXU+IuYZ?=
 =?us-ascii?Q?UUts2yb7Z0hsCtt0AtRqtbBb4u4IJX1WgnhTzqzndVagrfhv7vU/Rpixylzr?=
 =?us-ascii?Q?KrdmOG9qTgB0vfcPDPTXLE176aXV8WntG89Rc5Z31zpmKgV9Fgc59ybmYRQh?=
 =?us-ascii?Q?kNRTuzd5iA1invXazXoPYD/om2sI1V3bIUIFk1H3l2NwAstv2OpS8lCeMMV5?=
 =?us-ascii?Q?2PTv2pli8F7pU01Cvv2peaJsaCFkspYD4/6JmuXes53HkfK+fSClP8dQqw5e?=
 =?us-ascii?Q?3JTefc+eVtVVjIv4Ihgj+iiNNyG0FtHvHS7TFidrdMBzpAgLI2gmiNbF0AHE?=
 =?us-ascii?Q?P+ma8unw2vjJghVfkus=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 433c19e2-04b8-41f7-f273-08ddeee2d31d
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 14:20:13.0048
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 18fGkzI2lV+WD/XXMN3z8O1dmPyKXRbxKrZo49eWCtNN2fPiVvl6m7u0ZZAUjgnC
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH8PR12MB8605
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=UFYRNqXu;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::60d as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
> > Perhaps
> >
> > !vma_desc_cowable()
> >
> > Is what many drivers are really trying to assert.
> 
> Well no, because:
> 
> static inline bool is_cow_mapping(vm_flags_t flags)
> {
> 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
> }
> 
> Read-only means !CoW.

What drivers want when they check SHARED is to prevent COW. It is COW
that causes problems for whatever the driver is doing, so calling the
helper cowable and making the test actually right for is a good thing.

COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
something that is COW in future.

Drivers have commonly various things with VM_SHARED to establish !COW,
but if that isn't actually right then lets fix it to be clear and
correct.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908142011.GK616306%40nvidia.com.
