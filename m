Return-Path: <kasan-dev+bncBCN77QHK3UIBBQNHU3DAMGQEC56UFJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B662DB59DF3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 18:43:47 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-718c2590e94sf1000596d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 09:43:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758041026; cv=pass;
        d=google.com; s=arc-20240605;
        b=BRSIxLb49OZvwXkTkumOXQMMjp/2+3JrfRjLkt5Rh6UckjtFVDu1tL/DWia6ok5hmX
         NEcU+iGMs671vlzjDEFTYTRXbrumReSt2Zi/A59MqGFMf50cpclp0mw+DDFddFa8N8kw
         UOKAhWej3OKDJEADCOP+kFXWFaL+ig6EAElUnsX8vuDz7WTDxWb1tw0e7LXAMx5wyjsv
         CXp0JCwZgtiWzQRowijfMtTD7MihJRCs04FnnImiq3wwPTUkiNNK67ZRyfZ7j6nRgRfT
         DCQ9GYmHCzypI0ln+wN2sDWaDzrofARzFNHCjsvfhmPTY0yFl5lJplrsTiwdUPZ2KFxD
         ctDQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=6BWNt/giTcMlfcA5PIv0vkbTR5bvVSww6upZerlwHq4=;
        fh=2q8xQsdZwCq0FCrCgRZuN0ulBHhkhYAihrG6obPdcoo=;
        b=j19FOglInS8yTJothXmnUWypIRHpFqL/QTS1OI5gfkukx7kvumtMVqfRofTUMjDLbz
         +h1R4sj4O9Ai1Y+hzgUohg8euA35qIDJGlRQKxHtlpJT9R91CTpIzg8dyPiSWZOITU63
         CqHbRlBs5VRtnV04HBl1yd5I/H98llURC/QssluQRBOyFyd5UlSBt8QfqvOvhzGuPtGo
         4CIwKpnk+dAR6r3TuD79tq4IFOp5NQNG824marnuDeEKT+RpFLxeaTS7OsE95wJNNXoy
         2cIr8nZeGfa66OIObrAhFXPUptb6G3na7RXV3Ut2Q2NE/4LcmDpbQ36qQQEjdH03ZSrR
         3NgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=S4G9XcaO;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758041026; x=1758645826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=6BWNt/giTcMlfcA5PIv0vkbTR5bvVSww6upZerlwHq4=;
        b=MMzBpU55Z7jBHObI6ZCMTK+1KFh9upVYXwaMtJtAga47J4K9XydWFD8l2zHX0Xsa5f
         rjK8Eq/q09owRSu0crxJtsDq9w/B1CtP8Wv5IVKvYAEa121y0h3smSt3G5pmnvEt9OFo
         xrx5Y9dcFW5YwBfX+8NlK9MGZymHWSPLaUA6Tk3KgfvM5hETbA5DBVYyOSVbheZSlose
         HPBBZmWd9RLIX32hiLgUzYu4B5XSb5oCuVceozX9G2imMJoP7F6/Ygat0VVVZaKa3HyM
         PFiocAWjmuTZTFsBEPrBYrwVla+2iCTgAAB2j6IEBvBbLYYY5is2om+P1vdnF4pOK7nj
         2bbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758041026; x=1758645826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6BWNt/giTcMlfcA5PIv0vkbTR5bvVSww6upZerlwHq4=;
        b=Y0eksdE92wW8/QnrR2fW2Q8KgbvNnwHsqbcFZkErz+qyuHzSjc39YevpS7KxPs24cZ
         tREMaIRvYETvsni/6TOBmJBXC8nICbck1DxT/cEmzkMTHI363wdFEV+p3HtCdVy+ZU+K
         rr6lfLpXHN6LUQi5ouVZpWZSx0SMwBQ2TPtaoMQhDLgc/YFtBXX0vRN/GPdaVQ2PyrDD
         dho/8shDwLV67xBOPD9PHnG7zqA5GRfkRvbfAPn+TLuTuDSAGz14svzNLrpV84wxt/+8
         1duHWvXhZwCHtOWo076RFS49jGAiLFL6FpKZ9BFYmy8Vfjm21wylYsUvb16Kr+MatJNA
         MfgQ==
X-Forwarded-Encrypted: i=3; AJvYcCXsOU0mbO1W/avYZNX7JWT6ZQIJpioVun+NTdxYt0BB66f0NEoTfC99wevLRQUFeYfBRwwsTw==@lfdr.de
X-Gm-Message-State: AOJu0Ywwuy3VJCpr7ewKTgV50APu8z23WtKrh+XvSu3Va3He77hNq2yg
	4WuKcDBPctbOz4zIlKXzM39oqawyNo8bAfTOMo9y3OtEg8Vt7KtNz3Pj
X-Google-Smtp-Source: AGHT+IESAvxJj1Libsyw1u5K6h2L+VeunqR4WC0e4+8nNqb1iEKAlTHM/dnFqJ1s7A67AY2dQRbViw==
X-Received: by 2002:a05:6214:252f:b0:772:45a0:4e28 with SMTP id 6a1803df08f44-78d5cc6a881mr33011486d6.5.1758041026263;
        Tue, 16 Sep 2025 09:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7Yx/ltsXont164TgCJRUisLZdBMLj+QtxVHUtq1FxojA==
Received: by 2002:a05:6214:20c3:b0:709:642d:1566 with SMTP id
 6a1803df08f44-78e686717e7ls1225106d6.2.-pod-prod-00-us-canary; Tue, 16 Sep
 2025 09:43:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVrKZH+hR5zipNNwN0bupDKD7mqTd9D71Jn4hwalnka1Nphn+kR+kDwAJVSr/jYKIQjuwQd5UJgOkQ=@googlegroups.com
X-Received: by 2002:a05:6102:30d8:20b0:4fb:fbdb:283c with SMTP id ada2fe7eead31-56886a4cc4emr1165680137.13.1758041024199;
        Tue, 16 Sep 2025 09:43:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758041024; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dsf5avyetjxoNTBD21cOiN2mILLn0DZMGQn9e/fZnYfolDl9cyiIm7c6x50lCjqu5+
         QTmYEe3SvHOWBScsJIeBdD9/FqwEf+fh//JdxIgbtTWgxAEuffgkB7muWxnzE6FMr37w
         tos7LDwik1JEV8ySf06Re7BSKCzv/qKP8kFiFlRUUSBMHPzmQ8ZICPq2rEtRHy4hMywh
         /PM85GUI6WWYZ8/4ai2PqjwPQ771QGXpOvJ4SaV0Yn2dY3HuLOqDjJoiz7wUrRyQFhLt
         UvSjTaVOCvuIwx2AKdwJF/sZ30FJTNvfNpoKMByT0KQ2+EAgwJvWY0AXGOI1mJQgRng5
         48NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=usxY/R9IoVuCaLUlcSqu7NzNmwDdBVlmd87OcSfDKnU=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=jVwQ26GwpcyvVW7V4kVUDevXgqydGRStYunEqETAhF/uf5w7hO6OD04NNQ56x/+QHR
         SleHp5SiUcpOFDvcfciQ16t+AVsWSBL403An1un9yyzcNOtQun0dzloY3f6hhfsIpOC5
         6sb++lTSpZwaB5a0o39GE2K3N8Nyt74CD/x5Ku6ibCdN5hUy8lzdvbQnjGrTiOnZzkia
         mNuDw4BJ0DQp3J9MY949wK59wNRseD295hPk2+2dOtSppj8rc8CpNzzp/i2ZLseGhmHd
         1b4i4zGO091/LpYcEt0ngdsePMnGVo7Tet0OTQ4RCVZkPmQhyX17ji+dBrXozHPwCACd
         9fmw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=S4G9XcaO;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CY7PR03CU001.outbound.protection.outlook.com (mail-westcentralusazlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c112::5])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8d769757209si334844241.2.2025.09.16.09.43.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 09:43:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) client-ip=2a01:111:f403:c112::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ftth4/29a7JDcEeiqqP3YvGHyTczTbv+KEAxbuz3bghVmriRK00TusxT2WNvQxQUNALFZG1qYn67uMua40pLVNX6OJ+Sgn5MI41DJyMrMieZHqLe6TwRBIaRv723XX9NEq3y+5kOFupyX8ejnCcH7OlpFnGa7LxI31alhN+NoM91si7cbuXbnh1R+/4GD/Zn3ImR7xbFjiW69ugKd2IoTqP4aZ8CAbGJyJY/xnnWfkmwic0DfXBINdxapvLQKCyVD7yg3m19U6PQDhq3aHy+02CB3PoEKChAkpqH0pUE2dD/6hwX6bdVw9CPzSTBeSqi81mxuz8G00QtPRL0cGGpXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=usxY/R9IoVuCaLUlcSqu7NzNmwDdBVlmd87OcSfDKnU=;
 b=vblExU8+R1wudsYWAwvIf31VKvAu7epRAyErO8qwTi/lsYrWYEkKEVsSPLz/TYEPHnNabLkmYjbImhsqmDcgfPEM/EeXyKOLyQSOCT2uGxyF6OtGJGlwcfM3rz4fkBQCswUKmiIkJ66C4uUZn17keqqCYY471SRoD9aRuQERaGwsQZzCQuHIiXbdc5KMpBEe75iqL98luCfud258tzLbQqa5DMrdnu3ttg0Urn07vcv3eJgP9AQmQVEsiatZ8ZEV/QyctpNKFQMOda1hPD4e6aqV3UfQkPcH2/jbD29Hul/7KCZsZrmE1FB3tjLmduJ0Wh9HVi/JXfpZ/NhVDvCidw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH3PR12MB8257.namprd12.prod.outlook.com (2603:10b6:610:121::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.18; Tue, 16 Sep
 2025 16:43:41 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 16:43:40 +0000
Date: Tue, 16 Sep 2025 13:43:39 -0300
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
Subject: Re: [PATCH v3 02/13] device/dax: update devdax to use mmap_prepare
Message-ID: <20250916164339.GK1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: BYAPR04CA0016.namprd04.prod.outlook.com
 (2603:10b6:a03:40::29) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH3PR12MB8257:EE_
X-MS-Office365-Filtering-Correlation-Id: 4ab686af-c530-47c7-cdce-08ddf540310b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?UGluIaMn1roO8kS1EOFzKjzllrGTqNtjKJx96SEchbPuSv+AtZun/VdZM544?=
 =?us-ascii?Q?cgu4ZY9F/svVvdAbDlFh59e7npgo2nSRqwkybIsFJmGhkV2T7JvUPCjQ6Fw1?=
 =?us-ascii?Q?ikW+vsbqdkD1I0j93Z1Meyx6UasKR2dI1rz9nE8pQFJIv/a4gXvvclrXgNdc?=
 =?us-ascii?Q?jFg8kl9UnXHaydb16c00f8rB2vMzQ9RvZj6YzNDkqkVPfqohZf7H1RUha9Hi?=
 =?us-ascii?Q?uWjbe4Lmf4DnyCOT3C1uWVpY4hwqS0kr2jy5a3l7v8hW76o5EhpNvH70+NbT?=
 =?us-ascii?Q?EAyYYXN5yuwtEQ44BktqXq1VaN8mqRN1k/6bjQHxQGNV9NWJ3sMINRzbwDca?=
 =?us-ascii?Q?kc6zr8FFmcDWvxLeF7/ewvo+Yk1xfsjjivOWzwZ7te00uA4jE7am1HGTLolR?=
 =?us-ascii?Q?lr+yjqQK4YGfrUHLoiiErdUbGuc7dZXgPN2ajO9InuOE/1bpldkRKS3hzaIf?=
 =?us-ascii?Q?D6pFF3AyUbaFtvf++XiAZclV3iwovr8C6s1xMoIuUnVAUmtzapFQ8emBNCM9?=
 =?us-ascii?Q?ouuM40ep/53CHf5jkRIVObebRKMPYR+AmjgxaLpvrBSumXJAHq52klIPx4hU?=
 =?us-ascii?Q?rerYMHJb+Pkx7zX2Ul5WUzpErh0HRY82utcaTEkj5Xow5MkeQrKKjJdftylO?=
 =?us-ascii?Q?VU0lCe/ioJvJRnrnAiTaqs8N0DoXLuHUiX+9APNN4V34EkuYCrVpsxd/tlm2?=
 =?us-ascii?Q?V97hPPW2HYqQbBXsqXReo+NBRI3HVBXA+NHJOV5WXPsH0gg5zuCO1MG2HE+p?=
 =?us-ascii?Q?xijAWNGwfz+1QfbPNlLsWy06uQzTg89WAMSTO8v0SERoyJgYyhCM2LClbU+S?=
 =?us-ascii?Q?ceTfFBc8gMZumbJRS8odYT/cS3XaB913EOS+1DgkBAIXnTlgAN/TY4votKYf?=
 =?us-ascii?Q?AgZdbbz9PXpLvaqKA7191bbbMkL+VU96BsRkK2yJvJnJGlgDQxvQ+UJQmB8z?=
 =?us-ascii?Q?VyvvWnXTXsOxfLQ73e1p8QNM+HGjKIxAm5UtrBaTMnMwTFFbkPUiv8hroqyD?=
 =?us-ascii?Q?xaMwr1QY7+DKtQhb539xtj5qH2tr9UJRYfvhilXFUFEAW601mqyf2kby5B6X?=
 =?us-ascii?Q?E+PytkdyFMGEhN5DgDfvcnZzCOVWFH+zLwDScSO2KRmITmngErRMlfPYNDp7?=
 =?us-ascii?Q?TjkCib6XZnBY+vA1WIaR6WfoM13Pz0d3yVgWxu9gMiA9zdmGYZTTDivDn/zF?=
 =?us-ascii?Q?4iMZv5+nrVv8woWnwQzX6gh9m1QF3zmEr/9FLpj1ZqLc3r+1+HCM8ufsgg9z?=
 =?us-ascii?Q?hystYcPYivMw52bGupmncvLhVH/6YIXthijEwyxJxxJTUnMZ62qfp1/2cb5X?=
 =?us-ascii?Q?dR9R3s5WzRsSdf2oi1vg+Bs+MM87O8/NpiU0+l+WQ9kjLPvtIml9yRu2j0uE?=
 =?us-ascii?Q?ifEtwUy99QAZi4YOFElZ/FPwalgYpi4BeBGcSOYV0cwy7sCV4xBpFnKI2isB?=
 =?us-ascii?Q?RsnsNAt+lCY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?hdbBWQFOj3hx68F5NsFguxGdZyCDMHCWRUovaDtuKA6aAfxrUk1+x+ou5kZN?=
 =?us-ascii?Q?lsUpIO3ubPxX6coomqijwWngVpJ0oYRaRQFEBH+RwpJq7Nw6r/ctM5cXavjD?=
 =?us-ascii?Q?IM27x3Ncqd5M+4vEzqZfl+xYYZco6x74c1doFJxa4kU/cWfKntr5Z+WN3zpw?=
 =?us-ascii?Q?VqMIi/cauFJ33kYczr/PH2T6SPPClp1aZ2W0+m0rTB2ac93n+Iew5kt+FzHO?=
 =?us-ascii?Q?+2mI3FOzD9WBApEcKfuAlZv5qWHBhSjLhGvqiCm5m/q4Usd4Y9IGWU4pSI1E?=
 =?us-ascii?Q?kGZJcLUFU3THlI0MyMol+YCVes7d5juiHLeR0Fm1Lrt5pHwwqJLPdBe5WfwZ?=
 =?us-ascii?Q?1bDLTMhaukJEg3Nz/sxUIvQa9kEBc56bpWRi/EVE9jDPXAtSL5TutLyfay8l?=
 =?us-ascii?Q?AomxI8Qyaeu+bfh7mNxKaAC2Gzuh10D/p/Q86JAiaSAMS/YaS9Ah1iiVmiFr?=
 =?us-ascii?Q?zkWZlM/VWTXwB3RCyOPvOrhsdoEYYvbwQ8kHi4I2z89bBrECzn+9wm89vfOn?=
 =?us-ascii?Q?DL5UlpDEFgq05hu/vxX/VyN0HiJC8PsMB9bIF30NNKDWrhDGKFNEhdS8dMD1?=
 =?us-ascii?Q?SZEEyfArsoD+cF/K2fxCarbM+qUP0kilYhI9WG2sOFVAA/qbmcV8iBOkHfTF?=
 =?us-ascii?Q?6ov+jRQpdzopCOR05T6qm5GqXrQBEwiAFJciLuvsUSkN74m4pvQVukAcz/AR?=
 =?us-ascii?Q?Il8N3wYX5OVVxGhP0T7J38WR50jnrYaQurouSovMhtSmUAZ9cNAqfSm0BI6r?=
 =?us-ascii?Q?QTdlr2HXqgJ5V/DAcTtx+2o+QLUPybmMO/t7eUWvyfiPySw++Unw+6PqrLLU?=
 =?us-ascii?Q?DxcFExkFyOImYnf7fG8h43dqM2EOCqhiN9IC1waNmWQOm5p/ZxNG3KleqF9z?=
 =?us-ascii?Q?A/LQa4FrQRy9ZDtezROYMq8ZrRauenmLG+hMruKHTG8z5UjbJfPPyQCeAG5B?=
 =?us-ascii?Q?+Dc/mAlBDYHFbRsT2axT+qtKsVE5mdAdMTxpXgpRW/BgQ2W3rcfBHyKCZ7/e?=
 =?us-ascii?Q?U7wojseLi7z/nKKjvWQqDwcaM1lvPlPF7ekBLYMapS8H9+p5cOrYebodEsxi?=
 =?us-ascii?Q?pCCLWUBy5CqyE1e2ugggNp3xhiv574nDerozUlmsjYEmxoZeINpYjx4pn27J?=
 =?us-ascii?Q?T1nTEWIeIup4KAxsiyImrQxfVewi+7blLJ5lHv2qHDXYUuQ+60yVZ7j1eFdB?=
 =?us-ascii?Q?rn0gXLxBVsrfoAh2uHrIrJTHNWJXWsOcthgw2avc4eoySGL+hIBN9RIhddcb?=
 =?us-ascii?Q?iLqazghcDvz5/5jPAJNOZuYkHOZJDP9fUSShT+mOf1FQYhMGOilYK3KAqZDI?=
 =?us-ascii?Q?/H2fRMkmsZRhohoJBPRPtgnPd0fW+aH/7wZmV/HQwoaIK/ddtWrhnXF/NsZ+?=
 =?us-ascii?Q?8oNhicYhAqCZLI0fyw12rfRwACmJ2xN7LPpZ99FJZGrzLd2pe36diTA1P34+?=
 =?us-ascii?Q?02J/kEJz2mF3MpCa+K2ulvmKRWgOd0Vs8if5pQPapBtmYeds4o/cNOHAkegr?=
 =?us-ascii?Q?cttW2wJBCgtutPRR7fMPF67bKLKubMcfnKw9dIv2p9kPFLmcnzFRZuV+XCaf?=
 =?us-ascii?Q?PQg1vplmxlbNG5xwUhsLuFEvoYK0wQ/mC6hhz1xD?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4ab686af-c530-47c7-cdce-08ddf540310b
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 16:43:40.7498
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: bokguXZbVGlLUUAbJhMpWJWC1WOdQHqQinZUArf4K68juWQ4bpx5gKV9yRZlAlni
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8257
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=S4G9XcaO;       arc=pass
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

On Tue, Sep 16, 2025 at 03:11:48PM +0100, Lorenzo Stoakes wrote:
> The devdax driver does nothing special in its f_op->mmap hook, so
> straightforwardly update it to use the mmap_prepare hook instead.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Acked-by: David Hildenbrand <david@redhat.com>
> Reviewed-by: Jan Kara <jack@suse.cz>
> ---
>  drivers/dax/device.c | 32 +++++++++++++++++++++-----------
>  1 file changed, 21 insertions(+), 11 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916164339.GK1086830%40nvidia.com.
