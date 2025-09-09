Return-Path: <kasan-dev+bncBD6LBUWO5UMBBZO777CQMGQE7FXDOSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 544A5B4A711
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:14:15 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-248d9301475sf99884665ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:14:15 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757409254; cv=pass;
        d=google.com; s=arc-20240605;
        b=TR3+Ubol9lDogFoiUUsgHndQPo/lVRo1ckoYYONp0rEtg9OM6Eh6z0HIvCwcFa5uxz
         hJ430KW9x1G9zXoXPYsXK2DpXWt6A1VZX+NRtIjztOoFkdPcQOnSK96XI/+sRzLuJz43
         SYndENzFqN8K2XFimU3CR2Gz8OtioVfHZlQ9Ru5NH+2IZNuImdlorXP6BohE62k2T9hL
         ksXjN4+Np3JHsAG/fNFVdwWI3DEUJpQw6xlyI0KtWTQe27KRD/lqa515wl83FmR+uWtS
         B0ReSD7bU3YcIsdJrw0MPLynX7BPq98K2By2vWekT2HJ3RCUF4Rrre7SShDJEJK/nAc5
         ZMTQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ul1kawQJPl8X/g3LGX4RSSf9jlUFINnKnbEyIxeuhYw=;
        fh=uqIa8Rt+y/emFYr3Au7t8VGthOuWEmp5Z9t9O+que0U=;
        b=aw/0xVUxJQZb7xSVXeDwIwJ2EywD4mpeSpNz4T/lCMWOyxdjoiu3d5th3pyWos39gq
         iYVFoDgTpPcnl1hX6/kJ8jq4FhEDAB6puEEI/caMq7/IXis1s7iw/JmMhdr0/IkLGmS8
         /IitlOnisn5MkIQYtH46RHCKATJ/1dmLgtc1twTGfAPqNyYJma9AyvkPPm0LRcUtxa0g
         aYb/Hs1FhTBJt5zil3VASPWoBQ0/Koe6qB0rrkc7o/XuBZxuz3md71oIwWc0qOmeOz7F
         E+cSYGMcPTwkX9pTkd8caCb7x/9f1IEBgd4v0PejGeUD2SI7OkNAQQQ6T2bbvBiGH0yV
         d9Rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=q4GQzwtO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZR1MgS5l;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757409254; x=1758014054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ul1kawQJPl8X/g3LGX4RSSf9jlUFINnKnbEyIxeuhYw=;
        b=d4Yb7FDd23BfsXM2pjnsThTttNQHFjLHkMsdrvljZjuZnueePMrMNry0K9OV1sUJXA
         BOl40ZxD8D0Nmc6cxbdjEwpFTCmwPpq2AKh3D3DX0MQD4F6vdAJQih/XD5ok2tahdNd5
         AG0hbiVHzzdXa93S5t8CLN3+xYEKwpXSQBahEAnnZI5ExVaBqivaf7oSDbc9dTHuDmBP
         tncI+kbnOSqtVFOC4+dm0Kr9kL0f2xklK4nr9RXFX9EZCwoJwZVrVPJ1cXq9VPTGKwkD
         HOMu+/Evn7aB6HGxtIlNVJtLCfn10FaF/60Z5a1t9Ki8j2p5cfN3m07g9jd4MTQ7xxD/
         5rFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757409254; x=1758014054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ul1kawQJPl8X/g3LGX4RSSf9jlUFINnKnbEyIxeuhYw=;
        b=nplSLMQgolzGYZfKtPTP8gXAL6a277wH/uE0vedYsLwNCf07yHll8ZDgkOmqy2kUkv
         L+PrWKTu1dlCfUlwY7anWGYQQnWUUz9xUG5xFiVqZHm4ESghmJwhrvtq15t2gmXXR0Zj
         C4mS6OEX1LkDGuCak87yGtlX5YYusfy2OVZGbWrE7oh5qtSYna/0hN4Tkwa5H/sww2JK
         O1o/i0TWJH1RyHZ4OGUAp5XREp1Zm+k+JjsvEjc39jG0Xkd4iFcDHwKSwB6p2mOd5Ekv
         OVLgrpRNW4PP5BFuZsFvdntBcclx8zyEQyx8GlzBuyoztV6idsCwYGKQoLDCdYaMMFT5
         Cy/g==
X-Forwarded-Encrypted: i=3; AJvYcCUQLq4TZJjES46yQpOhRmhguNCoM5H+arD5uUgfZLvfHfwIi9UTPLlkgUVckM8A7Z5hX3WfZw==@lfdr.de
X-Gm-Message-State: AOJu0YwSngDB/eOyY2El1DtETsN5ZYq9Cumykll5zdyl501/ygiJrnoz
	y3RXx9qoqmIQdRjOyU2YdvWLn3q8WOMlTq0sVWNfBRXwgzDjcIXQlbBK
X-Google-Smtp-Source: AGHT+IFmPbNsZjLi5hoN/TldVeCoA5LjDOgo9hY4nHfH1a3tSz5CMBOzlgirOpXbK5yxT5Sg6XNz0w==
X-Received: by 2002:a17:903:90e:b0:24b:1785:6753 with SMTP id d9443c01a7336-251734f3e0cmr125252585ad.53.1757409253673;
        Tue, 09 Sep 2025 02:14:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7H8PQvCaTPcgZBOyanlrMI0vSGK0YM/8jDD+Wnqk7iLQ==
Received: by 2002:a17:902:cf41:b0:248:8490:feaa with SMTP id
 d9443c01a7336-24d57beb11dls44508705ad.1.-pod-prod-03-us; Tue, 09 Sep 2025
 02:14:12 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXhGUTdQ+ZULOXnE2n77ITCrjn/gBe1vAN4atd43jgavAp/mcg2qDgYOf0+CYHXQX2MvcMJf4pvuOY=@googlegroups.com
X-Received: by 2002:a17:903:fa3:b0:24c:d0b3:3b19 with SMTP id d9443c01a7336-25174374da4mr159531545ad.56.1757409252124;
        Tue, 09 Sep 2025 02:14:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757409252; cv=pass;
        d=google.com; s=arc-20240605;
        b=hF9Po3DvuP/xqFU+nePTYKYL5aUrnLf8Eq23wIk66WWfPiz8KEzDVyJawl7G/26cza
         afC7e6qsku3ZWVBhRkNQwBNmrjHQ/Slwrd/AYKuB6WU8sxe5z6/r3ENdshYuMw7S+hjQ
         cuXumi1Ummk2LdvWqYFUEo7QJYwHp4+OVKjxZx5dB/nBK9r+c/MJG6I4548djWozm+nD
         RVgV7/JrnmokAqZbG3JoX3TDQuBfDWKccwPTaB3+cU8V5e8JcYCLYgRnw+NopdnD2ITw
         Uq4damoApEjG3FmXepqcm16Nqiq3aUcCuYmcU0nvYEGQaaWSsPYUkInWMVVYHIZY7f2Z
         tdZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=2JvyOpLxZVWdQuH+bThWmPjOPZRAFQERJi4cx1UNUK8=;
        fh=rBgXewyurrOnUosxB6Y1BSdBMLv7NW0sq4bxnqF789M=;
        b=AEwGelumdUaqpV27TQoFw0g8/tTBqsPhXSNOVO71l7GiDdwDc3OaIJaot/dKUDdX5u
         KaLwY7tkYuQmZxCB0EQFwEqGGlw5WMQOvvXr4WplymchWAEXfE2OJDml5Cl7iSChK/5N
         iJ2Lvfwx8C/dHDkUDqCczq6Rw3pm/o4daFIDZ0LYCyRG62dExy+j9dtzqdWLqlVSra9A
         J5mkUg0N+0eJ5lQMXWfEL2rDy9+VvVPs54EC2FojZ31/XlDasLWaJpzr4v304OsVqCBl
         8PkYtVgEP2+NEVeYWxSDBaLhKfeKiSg1WJ0r5/RWDr7m/8BTHh7UzhqQBuW/GDc+uZJw
         9cAQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=q4GQzwtO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZR1MgS5l;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24b105f38f9si7842095ad.4.2025.09.09.02.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:14:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5897fv9P031644;
	Tue, 9 Sep 2025 09:14:01 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4921m2sj7t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:14:00 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5898UJF6032837;
	Tue, 9 Sep 2025 09:13:52 GMT
Received: from nam04-mw2-obe.outbound.protection.outlook.com (mail-mw2nam04on2060.outbound.protection.outlook.com [40.107.101.60])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 490bdab6ed-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:13:52 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BdwxiRA/8Z+jGpQJs0gerXbWEz8KyOe3VAhoQO/6B6+G/Ce/9sQLnmeRQyRn7WZuzJ4sHO24990irqFj/jXb9ZXgEyGK15y9jYaovT+bOtMdUul7YVsNqeFzPJ2NtGDhLqeSmR0R9vEv8dk62EjNu6X1zWqPPj/r1Vfh3t0NGuyqFxPF7PPEtM3im1u8wGYZqv5WujcHi4FV59MhFcag9Yqw1ehS9AA33RThRxl9Imq/04LuSozVcXBEdqMBJLr99fGXlnD2sf2IbVng49YMRUkAwkwjmyn3dpBkL/LUnkYeaV1owbMHLGELRlMRvz7Fna4PM1Dp6FMMQDFkWRzsQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2JvyOpLxZVWdQuH+bThWmPjOPZRAFQERJi4cx1UNUK8=;
 b=Md6/fUrc+sldxcjjC/Hl4RltTiLHxOheLGNeAQxxfhL1wV+RzbrO28dqH/IACggCgCTJ7xORhVfEgbGO15WvGHYgk9KZEseEcbXwSDlB3w2ZAhL6QQq5uLGNOFup2ClLom3a1MZhQvgQp6xyZR/TmUyW1RsLfwOrzkc4tHK2lh9x9VrZX4JIP1oDs5792glnFUH/cW24SCFzmt7aeavsiUsyHO0p09DLFLeVQFilKw49ihWLSfj5ISxVPoH06Eg4VXKOgVUB9ZemJmZ/woeBOMCwIZP/fbv2O6KJ7UIQmEqmfEGCgJa5Ecqkm9OdhSrZBKHxPVd0dqWjacgjvMFwxQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH0PR10MB4969.namprd10.prod.outlook.com (2603:10b6:610:c8::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 09:13:49 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 09:13:49 +0000
Date: Tue, 9 Sep 2025 10:13:45 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
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
        Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
        Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
        Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
        Reinette Chatre <reinette.chatre@intel.com>,
        Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
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
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
Message-ID: <c04357f9-795e-4a5d-b762-f140e3d413d8@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
 <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com>
X-ClientProxiedBy: AS4P189CA0005.EURP189.PROD.OUTLOOK.COM
 (2603:10a6:20b:5d7::20) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH0PR10MB4969:EE_
X-MS-Office365-Filtering-Correlation-Id: 519ef78a-9ca8-4d28-62f5-08ddef812ff8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?b8bmLpbA0FEY4B491hCY/gvAHL3VHQE3mzw7bg4sMF43rN4jjAt/2U/KgFKO?=
 =?us-ascii?Q?BChh7hvHDm94DLW7Yc0Pa17zCK4IuJH4D9+7WLVb6UHsq0hQTbOj09Hg95hC?=
 =?us-ascii?Q?GUgF5tlRhKYONZE9jiBxX2QVl4qJMqHZZGxZGpfA4+loALUNE3OfXVzXziPJ?=
 =?us-ascii?Q?jpUaag05vf5/H10G5RXJBhmdmFfNKrqVYObZSEAzNRbqJcrjtxpF0u2NpIFf?=
 =?us-ascii?Q?P+2u0xj+s0zFS2+OuaqvnpnHw28HPrsBjKsSUq1FFZRCPu4wDlKNhB17Qd7I?=
 =?us-ascii?Q?/v3OG4C9wr+GmwCxL0qLKWMz9MAaWmKVmEkUse3DSUgP5WI6+S677yMZs+Ic?=
 =?us-ascii?Q?bRU00Pe5n0D8Q4EYk0ObNZZG8iwY2GsIYiOt+MUHwZWP53iDSg1hK/zm+iO8?=
 =?us-ascii?Q?EWkxjFLmbLdQygA580EpdkjW1uoMZFa8+VrthPqtpFFVdZpVUiILBf5L0h8G?=
 =?us-ascii?Q?Pd6P0wrMM5UIw5thEm1hftRp+8VyKapKXrvLXavk5zHqYIJD0PKB+fhiRNC+?=
 =?us-ascii?Q?uTgx0NhZD2vNJbWnRar7HPd/ihcnBOFkJyvTmCKaSMNVjFQgCf9+aaIkN8Ic?=
 =?us-ascii?Q?6QsM+zeV7Kd6NAA7l4z8b6Oi/s3ahXLwUTefNU54TqaG2VX6NfpYXdHjOrjk?=
 =?us-ascii?Q?dLYBMFSj+w/Is2Ps5d6amlziKWet4QDO2TCQuTMKuqIjkTZKSH+deIzIMHtz?=
 =?us-ascii?Q?fidAgDRGV8ZJl4/s+Kho/2BRIyXjGTlKYA7wH2OVVdtiXlaYIvn5sNnB/ghI?=
 =?us-ascii?Q?iZYhtgrrsGLgv2k+wLBIjAbmpYYcoWmC2mP2VjG/T1V/DdzHZvObv7SVcYjk?=
 =?us-ascii?Q?FhqI2mMoM/z3zV+012GUntdwuWYMfnYYSiaBMNJNuoV42LzLJ8l1iEPOj7/k?=
 =?us-ascii?Q?qlKd5wlDTGs/1NWyz6PJS58q7g6/uCzd8gFhNO5xMwBUC9QKfqyau1OfMK3R?=
 =?us-ascii?Q?Vxw3ASaSqu2NfmyFtX8uNk32uBo4f7JJpDCqZUp7IxQtzLEYgSTjB24StJso?=
 =?us-ascii?Q?TDUyD5kApzUHF/GE4T2X/5vVso1XGQAVCIGKCtLjB4wtm51UpjVBQxogAi04?=
 =?us-ascii?Q?uNLjwX//ZbL9n2sVPG71yj807kUHhx/RWPL3xUjjAr+CvARFRMYj33AeY4SY?=
 =?us-ascii?Q?wFYYSE/Ma3oBH09lqrnm8MV5YhyKQ4PRHdvLmX9ESvStCfcboFUkQYkt9+zC?=
 =?us-ascii?Q?9VQGwlZJ+iLm+/SOlyO9jxCFvE76tHCKrRmgleCTC7D8/Dgyk7gcApiAtPzB?=
 =?us-ascii?Q?j2w4ZOl4JS84KN6LMF/T16t0JK+5Ri1085cHcEl1f3nzlXv3niki1b9ninOl?=
 =?us-ascii?Q?IMjDd60VRdH8/RPRWuXxsI9vtq3bKr6ZQs3a6TaYo6fmGsHoTpqk4f7rQAn7?=
 =?us-ascii?Q?vZYFnxvZXal7T7QqLmQo9gWdThnHQ5hT2jcC50sBia4PDDrIDMNbv0mRVcxd?=
 =?us-ascii?Q?YAiIY2v0Vag=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?LN7xkS5mLvj8oXatoklIhguWQYABmku+LNGjDuh27kqKtPMedYyhYGKjCfVc?=
 =?us-ascii?Q?tYJnrHRiq1W4OV84hCnvrlVpYSDuphP8dZqRxd3edhBQa07aQCD5hsUaVxiA?=
 =?us-ascii?Q?yNGwkiD0MpogcX7hBYLnqLmfxxbxcD2IF1hOybdGllvPyadpMxG29ozX/iOv?=
 =?us-ascii?Q?VHC1HiDj2wGYDAc/f9kzPtIVEiMK7Kjze71n+IA7lbP02WKGEuHXXSAlx7Lt?=
 =?us-ascii?Q?DVhrjGEipxy/2VqrZWE5IOFkrHWeyw+ocFCzn/9hhPxYYu7U/LUMyQdwS8S6?=
 =?us-ascii?Q?WyBPkHOZCs4DcmVjBKZ55/lotIYPnK0QJuWZcWrifMmatkJ458JkIOU1k2q8?=
 =?us-ascii?Q?Qpw7grZlYvc7nul5no/YSB+mksjg6+7GCchXW4ZHPHJ8guS9GHsrFjcRhyHD?=
 =?us-ascii?Q?lbf+VujuHIbu3X0Sinb2WvWiBUJDmrgA6XeR1d0Du8eJOvavHCDD553T7nCj?=
 =?us-ascii?Q?MrPaX4tU2HGtNNIml37abM42pKPqH18rjt03NYYlNvDAWO2Smt9/n2wVIPyh?=
 =?us-ascii?Q?xAw5xXAbU7JuVXE9na7srKl2WIeM6ehNaFRPRQzyQPEfjluD0MHdyvOg8uQu?=
 =?us-ascii?Q?xg5Sj0mnHgL8XIHh9RqVEoQJlJ7D/65qWfWj0lCA4sbD0Fwoew4gbcipPplX?=
 =?us-ascii?Q?1A0zygEDgkiJ3WBBbKz5sNKrhhkZZ+jfPmW1ARFfq8zF4R5Ndnc3ShA0f0Og?=
 =?us-ascii?Q?CtwaDck4ziEFiR0HjSJgnNd4P16yRlHJw0SFm/tnI7OoFhzlXpjgtsCUHDyW?=
 =?us-ascii?Q?0ohSHvu4RJCx4/qA1/UI+d+vDyp/eGzUVbeXdf/EbNYbYfLwbVkToPxfJ1vD?=
 =?us-ascii?Q?r66obONfIKncuW0OceAy79cctA9vQ14edWLA6PfXdTnQ0Kifa8SL1m75Gkuz?=
 =?us-ascii?Q?iSVmqp1QP6L5G6Ucdos3qQb6A3geyHj3MCkA3J6uMwmZXYm6BjfI/HXNeHDa?=
 =?us-ascii?Q?hVefG9EauMkrlTfFv8WfX3tMERPV+pEqaeemjiY7FOHv/7ByHz948JZSMSaG?=
 =?us-ascii?Q?oWsVtAzFv60UaJtVzZ675LrPWB05bv3KydzWtxngAWB/la0G/A8zz5Tc2AVE?=
 =?us-ascii?Q?AtZA3SI0WJ4GaPq6kXZyQRk8/qo0IgmOtz0o57545QnaO2zy5Hv9XUhK9dau?=
 =?us-ascii?Q?NcXQB8lsbi3lpza2qer883wA+CyX1uCcrqHmHp3B4iUtNBDCgUQWrmmGC2kS?=
 =?us-ascii?Q?WjdA3XZ+ujzOu7ut/Ii3ytyoAdSB2F9j/iSlzmKAIykSp/FCXIxTxtqtOvVc?=
 =?us-ascii?Q?Fsd597Hi7KRuKVKx0+ktR79eIF6dh083tRoeLb+1AQodNU1jyv/9BH7vOeC+?=
 =?us-ascii?Q?T8Lfv3iwCl5EuNJ2d0JjTi31qGWWxltAbyf6+GJXRG0lWd1EdzWYEt5uUA6y?=
 =?us-ascii?Q?Yoo45AxtbkdWOxKNYokj+3UocrFIxZ17L6iaAiZ57wcTjqM0fx3QPzf11J6u?=
 =?us-ascii?Q?ELaEEVIAO7hgYKvLlxk9rjDnkBGZ03Oh8sLs0Lipl5uNmUhsuvygYjzcxLus?=
 =?us-ascii?Q?XcOIcHwNrtW5C8aFrvKcHvGkqjk92otOL0ErMbraXHAXmnaoDUAUS4WKjTKc?=
 =?us-ascii?Q?ggXIYWm1sFHLJ/2ci1tVBCWXwVFkQeWUXvtUnlNSyZb1+nEsfDF0MkFKNckH?=
 =?us-ascii?Q?Bg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: yDFH3eyZ0Os9r295RqTKqe44MMunbk5Vkf+ODkR/BHSJqxY7NvmsHBWdsuk6tEkTFqQNHTtWUqG23S+ruLaxRC6+4WULHlxfsoCQckz65NuCMmVap5bDRf9mwoF45Bg1DdpEQxtCfu/cmrWdXDslDlBE3Mw6/526DCbEW5Cnm8ajL2W12HcX0OO1N+PJLxhpx1oLgEgVEGQYMSvdqz527tXHmELQTYV4an2EFFUzblXf8EYjBcFxO4OUo7nZJmq5Gev2KTEeTIM+si8ABtAgXRftGgpgMatTsC67eWtvkN6FUTUpOl7lKa8cexc7XQIj6DDOMNGbuNtjUY+8lJ/hJ5576kb8aLNiHQr7bTZHNymcnIYKmwzvGzpeAaHtZOuRypsMORhGYlf8Wm9JejbWDBDoAx8MEaZSJxsD1D+LIwAzZ0BamKB7GC3j378y6wcUy6LlrOmILkqFKpU0wgdHy8v8fXqicJhJz/bLZCdE3CVZ5KO7JWn7hmweS7NWFreMj8R+kzKFzt2uAL5WGU63Z5wbPSWSKpTn7aR25DfsTq1o9tHHdDcNliJoOh2mYZKfVT4rHXnUNhgsFdRnXl4UMixkyNwPhzyTpTY473uEWI0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 519ef78a-9ca8-4d28-62f5-08ddef812ff8
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 09:13:49.2814
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: dHSjZSs7wS5RUtRd90MjMzBzwbBPBaMStxRJRTn75lq4Jh+YsILCwDPfJRh3qXAOa048gaGD/vFagp0ZkjPWXnEVayk5VZ0jN2L8hVfiQz8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR10MB4969
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 phishscore=0
 bulkscore=0 mlxlogscore=999 malwarescore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509090091
X-Proofpoint-GUID: pD1WS1ng4CO31s0em3AHiuf8l4ETSbTs
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE1MSBTYWx0ZWRfXyjWXbM0MVtgD
 yCk7GecsvespPKsGh0YcDw+63QbulPLJ4G5qx2YZm92LHC75rCQg8M0THEu4gJiBIJ49AyUYevv
 japM9itaByRjxGOH6o2Jfl6M8bNdHmi2NBemhbrMZaH3nAdM7LcF+aFIw7OyhB4tezIWxafacUQ
 /YX9Z7fWqHIMi9S4x9ID0lVGhM9eAeI9uA0v/I4xS84Qo6v2kEf5ZkWs0siHKBfN/UpR/bZ5Kt9
 mzssFbj6LYVXHXD8Ou906snsNNtWZNVcDoUuT/V4VUo0zAwsJ592zSagrQO6hTv41egVizc+FF/
 GTIt1qRtOMaWXnPm88bpNm/64KVe8aBrDDjJYyXCcxdjfYUvHVznFXsj6oM5cfOI8VZI/OkHTF3
 tSqAdsKL
X-Authority-Analysis: v=2.4 cv=Dp5W+H/+ c=1 sm=1 tr=0 ts=68bfefd9 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=hOJakRjXQ98C3HGjIvAA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: pD1WS1ng4CO31s0em3AHiuf8l4ETSbTs
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=q4GQzwtO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ZR1MgS5l;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

On Mon, Sep 08, 2025 at 05:27:37PM +0200, David Hildenbrand wrote:
> On 08.09.25 13:10, Lorenzo Stoakes wrote:
> > We have introduced the f_op->mmap_prepare hook to allow for setting up a
> > VMA far earlier in the process of mapping memory, reducing problematic
> > error handling paths, but this does not provide what all
> > drivers/filesystems need.
> >
> > In order to supply this, and to be able to move forward with removing
> > f_op->mmap altogether, introduce f_op->mmap_complete.
> >
> > This hook is called once the VMA is fully mapped and everything is done,
> > however with the mmap write lock and VMA write locks held.
> >
> > The hook is then provided with a fully initialised VMA which it can do what
> > it needs with, though the mmap and VMA write locks must remain held
> > throughout.
> >
> > It is not intended that the VMA be modified at this point, attempts to do
> > so will end in tears.
> >
> > This allows for operations such as pre-population typically via a remap, or
> > really anything that requires access to the VMA once initialised.
> >
> > In addition, a caller may need to take a lock in mmap_prepare, when it is
> > possible to modify the VMA, and release it on mmap_complete. In order to
> > handle errors which may arise between the two operations, f_op->mmap_abort
> > is provided.
> >
> > This hook should be used to drop any lock and clean up anything before the
> > VMA mapping operation is aborted. After this point the VMA will not be
> > added to any mapping and will not exist.
> >
> > We also add a new mmap_context field to the vm_area_desc type which can be
> > used to pass information pertinent to any locks which are held or any state
> > which is required for mmap_complete, abort to operate correctly.
> >
> > We also update the compatibility layer for nested filesystems which
> > currently still only specify an f_op->mmap() handler so that it correctly
> > invokes f_op->mmap_complete as necessary (note that no error can occur
> > between mmap_prepare and mmap_complete so mmap_abort will never be called
> > in this case).
> >
> > Also update the VMA tests to account for the changes.
> >
> > Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> > ---
> >   include/linux/fs.h               |  4 ++
> >   include/linux/mm_types.h         |  5 ++
> >   mm/util.c                        | 18 +++++--
> >   mm/vma.c                         | 82 ++++++++++++++++++++++++++++++--
> >   tools/testing/vma/vma_internal.h | 31 ++++++++++--
> >   5 files changed, 129 insertions(+), 11 deletions(-)
> >
> > diff --git a/include/linux/fs.h b/include/linux/fs.h
> > index 594bd4d0521e..bb432924993a 100644
> > --- a/include/linux/fs.h
> > +++ b/include/linux/fs.h
> > @@ -2195,6 +2195,10 @@ struct file_operations {
> >   	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *,
> >   				unsigned int poll_flags);
> >   	int (*mmap_prepare)(struct vm_area_desc *);
> > +	int (*mmap_complete)(struct file *, struct vm_area_struct *,
> > +			     const void *context);
> > +	void (*mmap_abort)(const struct file *, const void *vm_private_data,
> > +			   const void *context);
>
> Do we have a description somewhere what these things do, when they are
> called, and what a driver may be allowed to do with a VMA?

Yeah there's a doc patch that follows this.

>
> In particular, the mmap_complete() looks like another candidate for letting
> a driver just go crazy on the vma? :)

Well there's only so much we can do. In an ideal world we'd treat VMAs as
entirely internal data structures and pass some sort of opaque thing around, but
we have to keep things real here :)

So the main purpose of these changes is not so much to be as ambitious as
_that_, but to only provide the VMA _when it's safe to do so_.

Before we were providing a pointer to an incompletely-initialised VMA that was
not yet in the maple tree, with which the driver could do _anything_, and then
afterwards have:

a. a bunch of stuff left to do with a VMA that might be in some broken state due
   to drivers.
b. (the really bad case) have error paths to handle because the driver returned
   an error, but did who-knows-what with the VMA and page tables.

So we address this by:

1. mmap_prepare being done _super early_ and _not_ providing a VMA. We
   essentially ask the driver 'hey what do you want these fields that you are
   allowed to change in the VMA to be?'

2. mmap_complete being done _super_ late, essentially just before we release the
   VMA/mmap locks. If an error arises - we can just unmap it, easy. And then
   there's a lot less damage the driver can do.

I think it's probably the most sensible means of doing something about the
legacy we have where we've been rather too 'free and easy' with allowing drivers
to do whatever.

>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c04357f9-795e-4a5d-b762-f140e3d413d8%40lucifer.local.
