Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPPHR7DAMGQEQCSR7CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56DFEB54953
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:19:44 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b522e289a39sf2345551a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:19:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757672383; cv=pass;
        d=google.com; s=arc-20240605;
        b=N1zqnVMZ/W6tF4QbLCIfozBcKq9krym7asMhNFq3cAK9qcXYW7CR4vW0rT/+4/1d13
         rrYb//yAZLIFaHhO2nEWg786mS1TGQtXz7DG68MMor9kBggaYAVDHdjNjnceUeqe9opW
         6cFT/H44/sJLPEc+qRaJkgXxhIUnZkUrUPl2CrT5oH14vOArpZI9WSQEPBRVKlAgQTh6
         E3wJK4zb/QamvD9UNt0ULV4gPt9fBpHBXCExtuYiOzryZjgPfJcPsfJh7n6590Rl22kG
         rQWVJ/sbVhCCGY6ylIqMTWxtYRwTsEKGMRrzVXMIrDjAhyaROBFoh8dc9F3CMrIKKUDu
         5/Tw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=sz8Ix84Z/nqyXhpbQpFRev5UbY8JAEzQxH8MY3y+k74=;
        fh=jW+drpwM5ue+7DQPWjCt0qD7lxIsm7dTdx++xaVbYZY=;
        b=ca4miCppP69IvOCb+621TYXiMKL3kau1eL2/Pv0AA3GtYpTJZt0Ce2okFGFVrWvkGr
         HEC2I/r8lXo4QkmV5M/V33sbAk5smt20hcSkma8gy1D45wkvwxJnH4zEVeRsysgP8gDB
         4EvtnDLBbn3UIEY9TNdzvVnxi3N8ZCm+Agmp/Q0RGKs/lJGM3U5VT/fH6lS9TJj4DCUs
         3TE+kT/LBVqlgwTddNo6dZsueqjDFQn9+ZsWXTSUZNTPlh5UvT6+qvU4Le0wle8BhDFB
         jtt64nZ4EjjMNy2FFb0JUQd6hNyn7pYSFLwsJLeDC4lhIAmmmXiGN4SjL5HKYGqxRn/q
         9pzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rmIcqMoL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=J6zXOZqg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672383; x=1758277183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=sz8Ix84Z/nqyXhpbQpFRev5UbY8JAEzQxH8MY3y+k74=;
        b=aV9MKfcyKMijF9AmAvnu/lwFxdX+1xrnQMN8Uiqt1BMh6lE+/pJn4wsV4iE+quqJnp
         IqN38VlT4LZKjsE+BuY6E+YwRre1m2kthIL/IwQwZ7HqSplt4PvQqgmxC/X5hIFt1ynn
         9+HvifYSTmWFpnNkShKw1sZJqu8ROIMbRbd+38NQWXwUmyWkLL4gD8ySOYKxaTVDluZF
         ClbK2AWXKXky5lO3LQvvNxemWSo/Ug7Kli8ZR7SGl0ms62L3IANzmIzTTmJDkiwxR4hK
         KXcQdAYpa4GMI8JQD/dmAns4Yuo/8gg+szlj/WOaVi8YKaTwz6ldymWzm+2iL/+odjVe
         QC3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672383; x=1758277183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sz8Ix84Z/nqyXhpbQpFRev5UbY8JAEzQxH8MY3y+k74=;
        b=wDOY/eTM4RlF/f6SNyuvqfEbTcDBhv2vi6xYLySceeyAly6iTb+xkSBheHQM97Z3A5
         oAZSkOBk7JzWBS87vC+BYN6XQ1P0ng5xfjN+6ILyT3kQ7O9XH6T6NAk5Afk2+yy/LxeS
         McJ7Tk2QGhTLDDNdeJqvJzKGzLxpQr5EMSS/MjXEfmhg1I8fhUI8272XQE/qtNczuAok
         m1MTrzgJGn/+qQkHepS5k5J4ey89Ivq8RGh8TcJi+LwwheGw/Xc/TVIxoOjLRlEooJqa
         wZNcUdrGIBhjxNNnpXk5W1gKn+zVFC/hfLotHNJyEJWwl2H2nInay8a9cPW6AqEtDPSH
         xEoQ==
X-Forwarded-Encrypted: i=3; AJvYcCU/9ItFavWQo+9OohlXCWU0curbdlJJ7yNta2qD7rzllg+4gQJ4jQ3yqefoJ2NatEXdlfi9Pw==@lfdr.de
X-Gm-Message-State: AOJu0YwNFcvQjdxtfvMGtWOL+0AtonOTbPcDGdyW+ZQA83jhw7i+3QEa
	2g6ABFGRgN76tWJcHLozIAc75i795KuOSf4EBt8Nk5+ewkbkofanQjNE
X-Google-Smtp-Source: AGHT+IGw23jXA70i4XGAvgmR/cXD4KjXj9CSuNdOwUrpH4PNTGrjKcfRRakZNnTsFzdNQfvsQ/iA0g==
X-Received: by 2002:a17:903:1aed:b0:252:5220:46b4 with SMTP id d9443c01a7336-25d26764238mr26487955ad.37.1757672382589;
        Fri, 12 Sep 2025 03:19:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6eqZit4UFpLhADWtcGovtJEPob4QSnfztdldyTNl3JVA==
Received: by 2002:a17:903:2683:b0:248:96db:5c48 with SMTP id
 d9443c01a7336-25bec1ae752ls14816935ad.2.-pod-prod-06-us; Fri, 12 Sep 2025
 03:19:41 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU9n3m56LlOMcGuYcBog2n/fYCkIH4HNcRdL7r1C/+TSm7n4TVgjg36Dj8MyVvZyfTzp7t6r03z8tU=@googlegroups.com
X-Received: by 2002:a17:902:f54d:b0:25d:5d1d:2c6f with SMTP id d9443c01a7336-25d5d1d2e4bmr24466755ad.7.1757672381005;
        Fri, 12 Sep 2025 03:19:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672380; cv=pass;
        d=google.com; s=arc-20240605;
        b=BEZlkQAMZliybl5TacPqnXGoBTk0PpKwewyjxO5EgS34stWaNTmxbbO18GrJgqv916
         f22nFZkNLKumUykww9lSmVKbX7qVuKTvxgJvvV7Ge9OtE8TiofnecKF5XAEsED/CLS5e
         irnHhGatog0cTxvD8yANmMcH91BL6JvYK8Q/3eJcMeqXfzLNFdId9rYNmjpppu7LJuV9
         K7gkkiRMyKiMdg174xs7Ujyoy459x1BWk5RBPR/CH/sTvfgDJXLW7CLq+46VTT54rcjS
         cIdO3vL+Vkwja/atBb+jmtrsIuRjuZhNTSAbOCAeV/VpRv9pGJxib2oDPG8/jRdX6F8Q
         IAug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=yKa73Gsl4bvz89OKqzrOSXSbArRBAyQPc/ImfyWY2K0=;
        fh=n3eyO43oimTN9O9CBrRuK263+udvrM8H68zwZ84KScw=;
        b=BMdnqGPNBhNL4OQ4bTY7aVeN3nuR9p6aC6VDdEaxLiTvv9KziulZGvtTHL2uI2PJUH
         BAy2lt+tkdkTxWaP5DtOjrFUQWmkxLMCXjqSNbsXsZuWFu9106BWO0bHsOTTEN6g9esx
         721zqzEJ2E0e3IuXqhO9xpTvS7/mGTSKHoKpw9lWLze1NWrZtU0lf2MZh/JgVw+FO5p0
         sBzqQdHtsIUCkMi4MDvqcr6331AWJgxjrNBuCDMFK95eZ6CnL9CF6kNnodeuTVsbPRAs
         /lNJ0m5VTleznSeDlpHcqPTVfl4OX0XIFHBx8pqDQS6mOS4VtOWLzGKbEEijqzjCwVH5
         3KPg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=rmIcqMoL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=J6zXOZqg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c370a502fsi1665855ad.2.2025.09.12.03.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:19:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58C1twPl008871;
	Fri, 12 Sep 2025 10:19:26 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921d1r33f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:19:26 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58CA4OfT026170;
	Fri, 12 Sep 2025 10:19:25 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011020.outbound.protection.outlook.com [52.101.62.20])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bddqn4c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 12 Sep 2025 10:19:24 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IpnbpIXoBkddKBclHm6+KdasCiW9MuY349n22GX+9gAR6JacsBkuh56QxFznGNkyqYV6NglgL/biEO1RHDijF41j8vYy9LCqGn5f7gS1a/rzflV8bfStwuargQXHJ9LIRRV4/JrC+jU40fdvzTLgIREBwPmaxEX1qfNX4C3XcJKhVorg13DZm6Ag83x5hFiv6liHPRuNrMpXbbgPrBsl1D106uN5LqLYpaTHEKRQgBvKZkVqh16KlI9lPBdXLcMtVL8Z4dZBzl7DtyLA9AAut989Oj2lz8TUeskB46DRMKG/WBfA+oDm3xOihrgBjGfFxUtl30uof7n68NR3Gr93Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yKa73Gsl4bvz89OKqzrOSXSbArRBAyQPc/ImfyWY2K0=;
 b=Zw/0Cheo5jXIGG5foqz0Ssk3kMBbfqJx5/vx22U41QuK59VRu3RoueTHYb6qlFf8sNzwKQYLYeDMHpZloiQ1hv90g5fcfEqO2WAUXNE+6g/utYbDBeMLvbOyZ98Y+XmySBfuFExKtGOh8turc/2V/4DFXjd3jqwN0HFYrd0WSNVKyaDU+1geU+3UqDS3XNYdnKrULlQi1LfCL3ev6KpHoYmGMaaCKRbKvxVWJ5Vzirz4l6QKavDuHXiHvOIqGOosLdIiDljwOBznpcGLzzthX+5FbDGElTufWCuv1cceANQjL1ZfdbI6bqssh++XAYOk21kGppbBe3KuHPcnShS05w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB5566.namprd10.prod.outlook.com (2603:10b6:a03:3d0::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 10:19:20 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 10:19:20 +0000
Date: Fri, 12 Sep 2025 11:19:18 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jan Kara <jack@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
        Guo Ren <guoren@kernel.org>,
        Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        "David S . Miller" <davem@davemloft.net>,
        Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>,
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
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>,
        "Liam R . Howlett" <Liam.Howlett@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Hugh Dickins <hughd@google.com>,
        Baolin Wang <baolin.wang@linux.alibaba.com>,
        Uladzislau Rezki <urezki@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
        linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
        nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
        ntfs3@lists.linux.dev, kexec@lists.infradead.org,
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 09/16] doc: update porting, vfs documentation for
 mmap_prepare actions
Message-ID: <88627f0d-85cf-4095-915f-96f7091e3fca@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <e50e91a6f6173f81addb838c5049bed2833f7b0d.1757534913.git.lorenzo.stoakes@oracle.com>
 <xbz56k25ftkjbjpjpslqad5b77klaxg3ganckhbnwe3mf6vtpy@3ytagvaq4gk5>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <xbz56k25ftkjbjpjpslqad5b77klaxg3ganckhbnwe3mf6vtpy@3ytagvaq4gk5>
X-ClientProxiedBy: LO4P265CA0287.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:38f::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB5566:EE_
X-MS-Office365-Filtering-Correlation-Id: e4e20781-b382-40a5-edc3-08ddf1e5d6a1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?K0L6jUdN+aNHMDFl9C4Dkz+vOlpGW+jC1SFNy/fUJ0Gd0G/ve+sitRrsT7oO?=
 =?us-ascii?Q?0lBd2iYM91ciWMJTkeXvqn2V7ssq/9znjjb2u89iBniPrZQyvNeiyjAIaO3m?=
 =?us-ascii?Q?nhYDChvCqMLG/QwKyCPSP7FFRZ1Td6Ans805Hn4q6X0LQiQ8DkOZL6FqF34J?=
 =?us-ascii?Q?p6lpfSIQE9sSFeYYKlLEjX4uq60p1rkG7pXfr7YBOlDV2VgwFu4NBXVNzppX?=
 =?us-ascii?Q?7kLWVCp7ZJoEkeWnI/5hyQjO98eRq+xzeqy8WymF73mH/3LdaiXvk+JDTZPq?=
 =?us-ascii?Q?BKJO3JHDNr1HYmx7anvNTycaDSP0YQjVjVFzMxjdReYdsLGGeHX6rzyytdxl?=
 =?us-ascii?Q?8844bBfSM1iu6rliPQ2YZ3rFG5XT99sFIa0KzFBR+LX99FQWqGBaNbL9aFiL?=
 =?us-ascii?Q?hBs227Cq6UDbpS9L/wkn6prWdCZZCW0yFME3gtGLR+/VhV6M41MUrhBHRDw9?=
 =?us-ascii?Q?F4GnvegspBDggKSoCbh/WOwZofZ1iVWVrUrHD572ZxAUlbDpUcBEVkKStaoY?=
 =?us-ascii?Q?4/9lFlW4Vs4Sk0pOxHmbnk1oqAOKOlyZO7DP04tkkcC2/AXNtt/CKgaiv8jA?=
 =?us-ascii?Q?o/T22iDXthVyQ3zIicP9Fs5WerGor3B441mqcBT7WPpVhWw89Ukv5srLLRbQ?=
 =?us-ascii?Q?UT5G7ZM8cs7J3CK4fmrdI3AQDOTR7HVmBoXTlTiZ46pu0MPasc+L1vTd2Ys3?=
 =?us-ascii?Q?GrHrT/x/YqD5HKz5coPsFaQLONpAnRwVH9BJdsYh/dMyskWk/iANF6/mbOQx?=
 =?us-ascii?Q?YhrtOcXmm671n/Dsi/QxQPNdPi6RIJ2SRXOXrcGk1j8ZYO2Kkl8r/ZYWtL27?=
 =?us-ascii?Q?19sY4plBH42iVj6fltNXypBdrn2vdCq8lHG3+j978zEu2WIzFJX18IJOoytX?=
 =?us-ascii?Q?nbE6MAwdH2yrccbXIGeJ7MGZNZYbqz+G6YkDMSGa5HqC5BidW4HdJbmDh+Hj?=
 =?us-ascii?Q?AdZxm0loebw5fE5NsLxOhD+lL4mJSs19CnADrR5eqX+lxqk1wqQiIkyZjz8W?=
 =?us-ascii?Q?fgSNYobrBhjHt4q/5VE5jBEENMrkzlSB5jK53/phWw1XeEc6BVOVxbZf8nlf?=
 =?us-ascii?Q?rdNxQCWWjNIyV0E9usmyeBLg66/u6B48l52qjSY2aV9wQPzKKObpcnUYgEfF?=
 =?us-ascii?Q?xEQ6tAos5enlJaMKsEYXQYEfD6DoaZGVbxYzJEIAO5JqV/KoIN+m5vfZnp95?=
 =?us-ascii?Q?SIn5KjRO5LUQc1cuBr4XO8ZCpReUxjyS8Ajdv10eWxabzLU3ZFLGKWwDvJ4Z?=
 =?us-ascii?Q?ENP/EWyD7S0p9rxPFhkDPK+GbZScViQ0pH2os1ObSMwnvDSohymRaX8tsyD4?=
 =?us-ascii?Q?zf6VqFkrUzFveqHQW7fF5AyzkVaDsQW/osjRp7/ZLUSYO/or/iCGAOuHgC2W?=
 =?us-ascii?Q?H6FfyhhxlXa4Db9KAMGRRfSN3nmJ5DqgopuhB5WlPkOqNtvy4n28pKKIVDlV?=
 =?us-ascii?Q?0F78gkuUhFI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?FGNM2WiepXHeREJs1PYxjA4R5X2A5/MrLgXIWhNAqx9f2BVXiRTo1IfpqPQf?=
 =?us-ascii?Q?HgncEZ23FIC/LJmHmxGvr5PEztv7Tmn1j0aEXljUrIzGMTwknSvtsApOeSxo?=
 =?us-ascii?Q?kwboQfcZg/Y9RYgVbmwcUYRKqaZj8jnpn0f3d+o344knwPuS08KJ//uhQ6Hs?=
 =?us-ascii?Q?cI9olH7GPgZn4XCc0Rog0r1ULXa7+BKhQ7eRZpIHSzdClDwY7k86MW0zhjpl?=
 =?us-ascii?Q?mB5q9bZ5Bmc9NswuLP8QNyj9pwdZjhqXUnsC7uFmfLcEmyeLmZsKbMPL/il7?=
 =?us-ascii?Q?0gYL0NM0mFGUuA8f5wafrcJLjVp9IpOxM6z025n61DGvq59MXSTzdEy2DNDn?=
 =?us-ascii?Q?KzmJmIVcCEkB8lTYr4KTFT/1iz1Nr4poHc+akX/MVsAvadqdX9AiQ1aVCMgm?=
 =?us-ascii?Q?5cH1JbWpPBoYsy14rosRpJZP/yv9/PxG50YaGYq/DlmUIQC+0PRJvpp2VBew?=
 =?us-ascii?Q?bguYuJACAhrrhtHH9UF33Y2raVwMs6NYM/M9kJDbP8+jS7S2FomL6yfcwt+b?=
 =?us-ascii?Q?CIQu86TghykcvUtfha9wyhaSPiaGHgA2VHaLvXK7hOwhPPvPx7Gg1cI01ozP?=
 =?us-ascii?Q?7pP4osolCvGRnkocsewA5dFs6oucRFpcBCHwMn4HZ25mu9ZdXqulUpMw7T1s?=
 =?us-ascii?Q?wnf+1awiPlbP1LbhIin7MsIi9aX2L0bmprktD1/RNXnbd3xteTNmXXHJA1mT?=
 =?us-ascii?Q?ni6BzsBf4NE1mkh+dCDpRSjg1GPUMEhAOiedTFaYUQrFN7Ut1+JjOtaHt/+8?=
 =?us-ascii?Q?qL0NqxIA2IBoXbhWfKe8E3yK3eAaIktG7i4IWc+EV5DXF8itlopTseZta+jj?=
 =?us-ascii?Q?Yw4WB4LPfDCDLqoEWd9B3AxTCcV8lSiS8xZmuTGrh1CXK7OLLL4QByw5i6rb?=
 =?us-ascii?Q?LDsg/Bddttgz7QRjS+9n9d0Z4T8tmXSRZ84+cha+P65FMV54u1+QofRF8HNQ?=
 =?us-ascii?Q?E53n8s6/sI8+KMAFUzYQ6Vgk32Jxz4t/8KAwdHIURI+G97fDQLTS+jVhuZPk?=
 =?us-ascii?Q?ryY531xmkynNZ6r1YGa5SdKyDDDvCcanjklMVhPpRhlH/Iyph5PgJRLIkzZi?=
 =?us-ascii?Q?EXK7W9jAKDErxYQm2BYTPbYNOUhfrkztshxmi7ohuLA/wUJt4cCxI6eG5SU5?=
 =?us-ascii?Q?o3ZAmN5/dkhf6izFuCqJQFCYJaDq6WQwF9vNRV0DNUS09UzSLLohAxIcVzDi?=
 =?us-ascii?Q?sg6HtRX2MdCxExz5k56HPsoI7KpaqnCPX7TcTb6gdx+4lW/M7RGUGtuy1aJX?=
 =?us-ascii?Q?p2Z5PvkapdTBjMISiSCMoyn9/kihI2nGznbR0h51Sqac/bZ2UeH4P6utCNA8?=
 =?us-ascii?Q?oRUFpY3d9T3HDKN0khMRX3UYGrC+3akS06u7yk1XiRStcnbu9fMQ9gXpTqyH?=
 =?us-ascii?Q?KxUjzeHRcgF5Ca3Tk+1rcOsPHrnn4clVsob+HF1+WBZN9g1dkBkUOg7PEVst?=
 =?us-ascii?Q?8i5JMPbbVsVwqj/VRYC8LP6om3k7nztawp0txDWHFG0MKazE0ZQ+vJ01n/dS?=
 =?us-ascii?Q?y1D2ZxuDEHFMyfyCNk/PHcApDuV8VXmQZdpOBgRF5k3S0VhCZMk1/XI+ZJkh?=
 =?us-ascii?Q?+WSxGqRFTtTZEHl5keXZzhiqJuypJsp6z9OJBOp9muYdIrRC7HEdVZKjmBrF?=
 =?us-ascii?Q?Yw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: nSw5krD6U+Cfisq3z5YmU4r3giAhMkiZzIiX4+c/hVB1xKmbkiWu3yNHw4AX8ZP+i9uoR2tHTZtWl+HMfXiA+SNZYQqn3FlJMmOgBYTUwh4ktsreiX+hDiyJcGbUI2b/8UPacVQDeE5QewdbR75vSo4lrzuM5adO25xI3Z8tqb7FUC0PI6HZ2Mv2oaat+To1aPLd7Sh6Ru416u0w6/jZPcP5GszhRK7FCV+nekYXcmdMiOnp/RqtN8Z8MO39fazePmiTsPaHW+PsihwPDQHzYKnk7rYWGLoN9eXCOUELG/IZRapxHZcHBKavhwHDLHMdO3pBLa6A6dUVmI+26stTr0Fn6kDt2IFdblpucWAS4YG2e7P0ov7Sa9iDanoNZVDj+PeZvwf0C8v1grZG/Ir0H/SBheYyRjMWYbiDmpEg6A7GlcqJn6I4ZGA7TR9+7wr0p7svuiw7lBKGwfkjA2zll151jVUVfjjhLY3eK99MBbUM7EWpmOxgryj9pROGY9G8dI4zBZBCxNLSH1vQ7HVc/IY62zP8GOA2q3OfqaF3ttRMq0ce/ArvVLVPIg6BMyK6Oc+3oronbi25nsAmOrO+aqQtq3hi0sWiPhVxORNorpQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e4e20781-b382-40a5-edc3-08ddf1e5d6a1
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 10:19:20.7828
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UqX3TKV+D57UhNGXC3ZJOONnNjRjgnZofbRgVuGnwSXrPEY+fgtfpStbaTNzGS0Yow60M7xuHcPjKTZllzeQqzlMnML+40Y2p6MrKhRsi2s=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB5566
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-12_03,2025-09-11_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509120097
X-Proofpoint-ORIG-GUID: YNCIaFHUWl1XEzjqD4f4CMPq_UDOrSvX
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MCBTYWx0ZWRfX2eFvzNz09mPF
 IniS/VDS0rGRCGgvbA6/GMdTAaVevaYbPT/rdOf7jkQpqTJNDwi4ADwujckS6eanDtRgN3HNkln
 R4O9UblxhjHNHcjSjFRl3bjCbv2BIgnzCEMoq0sfC3YndtI6tqq50a8OLq6euf17bYZrQqKNdno
 lCd0/51xL4+h35KHw7nLZM0vc3kLGFbUQGxOzloWN0cCsEwnW29jNQaTZQIsYGZGgToWrmALhLy
 xePeJshvhB+bGpcKNTDmuFsFKs/Y2QT8td3QKJVfbiyYYzYCQpZ4puRcMdKLviP321cUgB90e7h
 e5XSw/iv1TyKrx4E20BwHxO3aKTFnpfaxjAM0qSnc9vwaWZoafQt34iA54CJtJU+8VaAoWyhvK2
 mY2iO5v1RSbpUhjJDDPzRQi4so0dcA==
X-Authority-Analysis: v=2.4 cv=d6P1yQjE c=1 sm=1 tr=0 ts=68c3f3ae b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=0N1piJMG5rTSDL6AYfEA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-GUID: YNCIaFHUWl1XEzjqD4f4CMPq_UDOrSvX
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=rmIcqMoL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=J6zXOZqg;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Sep 11, 2025 at 10:55:42AM +0200, Jan Kara wrote:
> On Wed 10-09-25 21:22:04, Lorenzo Stoakes wrote:
> > Now we have introduced the ability to specify that actions should be taken
> > after a VMA is established via the vm_area_desc->action field as specified
> > in mmap_prepare, update both the VFS documentation and the porting guide to
> > describe this.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>
> Looks good. Feel free to add:
>
> Reviewed-by: Jan Kara <jack@suse.cz>

Thanks for this and all previous tags! :)

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/88627f0d-85cf-4095-915f-96f7091e3fca%40lucifer.local.
