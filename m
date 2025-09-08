Return-Path: <kasan-dev+bncBCN77QHK3UIBBJVS7PCQMGQE42FH4EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A9DEBB48F56
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:24:55 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-72048b6e865sf93040056d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:24:55 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757337894; cv=pass;
        d=google.com; s=arc-20240605;
        b=MFM+4ft4RP+4NJD3nFd5WIpU1VPM4wwywvzBlzd8tOBwjXuQV4syvBwZitPA0y9dXk
         +2mZ004MI4IWuI/hC7/lJGkMu8SUVsevcGJ6Q0lQG3X6PENPJ2QEnL0l/77qQfFbf1LL
         boStUqZutAIEa++veXXGarjKjrk9qhBxsJ3fSmMF1NCW6y2d2slEnW/5IbU113EUnpEw
         YsjyhgDbBwag1m5oASyiiL0f/5s6IItJmtEL+vimMHkJ2lcO+mPTJEb+RBwLew17aAQ4
         Y2V8+tY7S86ysO2NfFxyGKpsVdG99Q+redXhcDMyaTcbnAi8SAUL2K6vJ6EJb9+vW+FU
         qRaA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=84SWj/jAeNpUjC0NZnzuLFK0sWCLI+nCpW5KO+KDZ74=;
        fh=jC96h4tyRN5sF0Me/fHJmiqBnf33ZN29PWUxKGJa65o=;
        b=DhWIchygVPECkl8W6MnYy/JmzIfY+QY+Pglj1s3NoHIKGhIEwHzHoyVcy/ukPyobni
         SUApRYPGdeyENIkyiFEpOvX0iyl57ZTKeaJmtgBAonnISYgPO/4CAq1DY/lksbmC1qXp
         R+3Yh1veQZK20hjyoZi9Cjx2YUJIHrVjMx72rQONoFJ9rP2NA0J4LfuTtrzELLYKgohX
         zBk0hVfzc58U8MACiXCHg4ovWMep70sgAEPMvdB3oW2OHbbiuJmICJOVIKDV9RpZ0HVH
         1Q7Q0NqIVGszFNXJydv03y1TZUnUiwvtnma0gg4JE+qTX6BofKok6T66ABJHqAk1jYqQ
         62JQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=row4tRFN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2409::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757337894; x=1757942694; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=84SWj/jAeNpUjC0NZnzuLFK0sWCLI+nCpW5KO+KDZ74=;
        b=g87taO989QztSTFFz7xk9Kr5zSApvKSNhIf2ZjDXn1FWdvzqC+jSH+ivM3Ti7ZhOGh
         y8Rolg52OHCLqu49hEiwCaU8d2DNSymqklRpPKesOEiHQvxU7M/gVHoRh6Ao1Wzg+xCG
         sCCOP1eY020YeUvDwZWn1z/v9iPycLXaABOv7TL43DYz0+Q+uwW6isUlcjwq0okG9csk
         zI3PLHsivUPGMXLiP7AhfunIgusBBeN7JC4QAcAfTiqTrheTc9tD75GkVu3FZBZ4nph3
         gmRb5rhaiKDkbiwlBm2R9vok+tosfZoldJlLmuSIVY8KYnLQU7IBbhddUobxEWd6A9US
         gSIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757337894; x=1757942694;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=84SWj/jAeNpUjC0NZnzuLFK0sWCLI+nCpW5KO+KDZ74=;
        b=PSXlTs63tGlyeeR2Xww8pDgl10sOLPo6/UMpBzk3zf7stFAiJaQqzKMHXabp3gcbXA
         cEDP+A7ZEMXuAsbXqZAohiSdvnQLmIxVTis6gnWjc/duCLs0Sfo4taPOJH3yFsofBG1f
         ipiE/MEVbwkohdallUJLqmrHVf2/+TJFTNqZgJw9OUxItBGB/0CwDK01cra+nf0jQPCG
         ri2NahkPJ04QGu1RTaQX85qCdiMWZM1ea6RnQy8LNtmKynP0B+xn1GG9x4u0EkDoTtt6
         8/gPrsbXTJv2Detp1z/YC3Da4W0gj9mzfilDb0Y2ZnleeOZjFbfC6tHhschOek1PEu+z
         HNng==
X-Forwarded-Encrypted: i=3; AJvYcCWPilx7pwxxOkALpHMG9sZ2S2RRHWWIfCRfcMHbT8LGIZovDj5GNsWfvXvnyZmdKU+xT++36g==@lfdr.de
X-Gm-Message-State: AOJu0Yw8KtsOPO1kYQO5GCYXdtxp5lq+SsLb3qI55IA0KToAavNQvTJB
	ng52cIZpnTKE3RXnbdZDzy9qbMYlYkdCAR0YYRppvAh77ebYjeAagyIF
X-Google-Smtp-Source: AGHT+IGvf5ZnbLySTb9bgnU/B6XWp6ElOuC6XwmYBn9clfuoh7GGaZm5+GLhoO9VN+GYESYK0Fbz/Q==
X-Received: by 2002:a05:6214:1c41:b0:70d:ecf7:2102 with SMTP id 6a1803df08f44-7391f9b8290mr84075346d6.15.1757337894429;
        Mon, 08 Sep 2025 06:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5Bi8QFhtVy0MnBW5IYo2g/Ot5tsSzLXVzc7XKwBBN4eg==
Received: by 2002:a05:6214:2269:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-72d3f7a31acls45592316d6.2.-pod-prod-02-us; Mon, 08 Sep 2025
 06:24:53 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVABxg0OIAmJrJBXXU3w9ueCq82J3S9f6EYtVAjGndoTgSb0ovspvMEEMsz2xmZV+2ZdAQm6M8tCGk=@googlegroups.com
X-Received: by 2002:a05:6122:1825:b0:537:3e57:6bdc with SMTP id 71dfb90a1353d-5472c8c53c2mr2148694e0c.12.1757337893497;
        Mon, 08 Sep 2025 06:24:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757337893; cv=pass;
        d=google.com; s=arc-20240605;
        b=kor7OMW4LTtwttehmbrxaatc5y/UHUI0uDM8xkv9RFV+bk34/6ydRW/ct2MV1KajBf
         hqk0C32nQKiYTH+nEgFABYfvSfeuAbEcXsseWnLM2NEkmAUtjyDj7Ox0VfKs4DAQzOmY
         LlZeUQe4iR/kOhndlNsJ80HpQyRlY4hZj4tIA1JRgMK8lXjdtliO+DHzjFX6bcBw/Q+/
         MPrxCByxviy8hcLU+NgiAplG/FLJrj5cIUFJa4DGAXVTf+ntB5bJ90ib/CDRvaufTF1w
         ARE0kjhkUTedG1jm41dgIeMEbyInUN1YYiDkXDrNpa58yJBM5tmZzbsCDAPRWRUDDSgZ
         lJmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tZOK3gvmwqWnhlifB3wIuA1W24Pi0oLtgZexkL4geK4=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=RGZ9iB28qBLvR/rQF0at+cDuT6jYhQrnEDOuqpeKj7cP8i7W1HQWp3/nZ1oJ/EvhiP
         hEmq8QgVU5NQgB6/iofDAWPu+2llN5FCYQpqbuOZZqa/GNXsdP3+Qg1gYhB1LeSwUd5R
         Al12P+sB2E95PtpHfSdmN9BLLOZ5ftZ0Sfhw2uErgbi4kmWlXGYWPEx9BYLfXUvu6nql
         ctx0jw21pHl6zzwYrK95kxe2qDUCIg+GYTvp6geLRpaiKbEvoS1KdjxMRlhAWNxqJesK
         DBfTb5u/ih+pMVTpUysYn3Ug4gEJJeAQ6FFbASv1lk/zaX6IuENbcf+Ut+xi+YqrgFlh
         z6zQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=row4tRFN;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2409::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM04-DM6-obe.outbound.protection.outlook.com (mail-dm6nam04on20627.outbound.protection.outlook.com. [2a01:111:f403:2409::627])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914fe552si1099146e0c.5.2025.09.08.06.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:24:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2409::627 as permitted sender) client-ip=2a01:111:f403:2409::627;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JOH61RydzvcaeM9rI6ARSluHueDIcJYly5FkcVwknIA0GOEzgf7aLZ1S1L0ksavB2qpniAL+1t4WMHDT523Z6YWLL/6XwGJJYbsYB1HGuktd08MPLbrItI6kI39YIqFle8ruvHukWT/ZqW6MzZd4Tg/Vy8cPFDgz8gKZ7GQLGQsjjGtsK9VsZih0XOalpNs02RXxVYhhJhEVVTpd38HSN5SI6/+UDmMSO/OG9IcUPf3GdQjPm4K/PPCZJS0bATWHqp6u855ou6zwjFTt4jpLViH7k82AYqgm0knBAiV4U9CDJa+nkqKp14FHAtEzh8HBbaM6Y3aUgNlenSbpZTdcOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tZOK3gvmwqWnhlifB3wIuA1W24Pi0oLtgZexkL4geK4=;
 b=UWsvj69Ou1aQsVHBOCWobjFCQsIbob7DE6vin7+stpZ9kxgOd9jk8OWg1DcOhhO9+KA6Dt+hUkTsdpTV4rjgYr+7HDeQSkUU5vY6ZsYN0Dh8lJsx1OR1rChOZlGJNZkTvJXNLHoCcYCxzj7AJsmL51aLkbJcoRaJaZfb/b482xilsRLw2dQqyQtkjlD+hAg5RV4MTN3oLbLuXoTlIOKfDYLBQPVOIVFwWwcJb69N+r50p5hXKSCzCqRObDGRycT5rubpC/U08v9wnga95pLKsq2uil/ycxprWZLn8Mb4Nsrci+aMLpnWYEWS3n//iDPa8YKuXZIDIHc2FpEYdhDzRA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by PH7PR12MB6882.namprd12.prod.outlook.com (2603:10b6:510:1b8::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 13:24:49 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:24:49 +0000
Date: Mon, 8 Sep 2025 10:24:47 -0300
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
Subject: Re: [PATCH 12/16] mm: update resctl to use mmap_prepare,
 mmap_complete, mmap_abort
Message-ID: <20250908132447.GB616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d9e9407d2ee4119c83a704a80763e5344afb42f5.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d9e9407d2ee4119c83a704a80763e5344afb42f5.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT3PR01CA0051.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:82::22) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|PH7PR12MB6882:EE_
X-MS-Office365-Filtering-Correlation-Id: fce15a36-c8f7-47ad-070f-08ddeedb15fe
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?oPZKHxJAGK769bWS22UMAkhJgHN+y1pyccrY5DKaBgzbI+GTnsUTjrPDKTr0?=
 =?us-ascii?Q?/jUvCN9otRyNkju7bqaQ4jf+F3Is6FCSLNW3vYjDBWsmGw0f9XCCpQojTKvP?=
 =?us-ascii?Q?DhUnZZ7iwSfXl1neyNh4oQMk566NOApRdt1MIOmJCXKyJfmyVFeyf6bZcb5f?=
 =?us-ascii?Q?t4E+GHNMYdmPKNQ2/7CeypAObAzcqIUyQnA1ek9iO890CWKHO5qYakuMBqtX?=
 =?us-ascii?Q?kTeiFHxQnANTkksp6zXRbdYhz9vVSQgb6sVl8xofitzsx/zGG9aCO5b81GRF?=
 =?us-ascii?Q?aNFQugSrq1C/M+XdDjjStlk8BbvjXv8qeeDrawSWsS1sCouGCsFSc/XpOe6y?=
 =?us-ascii?Q?qgwHKpTkdxIeHcanFZMaeO9cKYp2tWmpUcSqHvCUWs8CmknSvtbV0XLdkTFA?=
 =?us-ascii?Q?4IwreVkBpTjE2LnC/KZg8FnDQPhHOO12wh0vwWRQ2Q+aWp3T0gF6Fo13YnqY?=
 =?us-ascii?Q?6oYVycx5haILgxaF7tPUVNW0AuvQjU8cHnAJHi6DkZceYPKzjIODHieRGoSd?=
 =?us-ascii?Q?9L3x91YtjOYTpjWPSFyRbuNN4aD8TpumAqPCjALVtCuB6S+KGKyAvxNNvET2?=
 =?us-ascii?Q?v7nEp2g2U1HxFbWMz2WJIhmNshtUrSsnHTLHFT6V7E+S8f9+IxTDuqFRjpzu?=
 =?us-ascii?Q?uaNKSD/+E45AXk+YPheLuzuiFeiE84AKasXTR2OfbJ2zyC2ymNkVhHt3jIaJ?=
 =?us-ascii?Q?yc9rYeCfcss7Y/k5k2FcPp/6FmdaAkXU1Kg0eNYDMLvJWUo28EJym/Z8Itol?=
 =?us-ascii?Q?z6AVfBBdv2HP8CdXaaUJlclM239HI9Q5cltDH+oVOLOAdy2rqoBSIowvmTpD?=
 =?us-ascii?Q?hBwA6XxWhI8bn81bkqQ/CXJ7VCdnsJ3QLnll0SnJ3IlDtj/Nn0ijnmwuR0bn?=
 =?us-ascii?Q?QdKmLVwis61AbqK6DbmGovnWgBErbnIr6LoXMwDB4/KUGmDXXVmmO9ER9hbE?=
 =?us-ascii?Q?P5lzjBxcAzhrEBkgiy7RIBgPJE+ThKmbSyDtIT+Kr+Oa8TSUbbcOLgeAzfdS?=
 =?us-ascii?Q?Pd+N2dg0+iZKIo+o8SSED28PVj9BHP1ZGdg22cCnwT6/fiwtN9S5ApDXpREB?=
 =?us-ascii?Q?3WUjUc2ac4uoxkU6r12c2YeKFOVGC82s2g5ofT62f33FEUo5e4XOwkDVyj9D?=
 =?us-ascii?Q?NWs9eFimI09RFWZfJRgg43hvsENUFtZFiWXsZ5nDjspedtIHB0QhOEM77u/c?=
 =?us-ascii?Q?e7rseGb/1WyJgTZOEiDDBq4k9W5QiDigp/Cx8JRhbORHsTYhTvO9qDloS1kY?=
 =?us-ascii?Q?gyNShAiTKqq91OQw3ov1m408RjUuDO3ptzYSk3ahCXdR552kcPn2uV4Cl1zF?=
 =?us-ascii?Q?viOSUVSf/lnC3JpT6jMpriWtAYcU/Cak9YlDyqBorbmz/dikSfv0Z+cL14KV?=
 =?us-ascii?Q?FFyBXsqVNEuE2C+9IClTPrq8c88/j4AYNgn9Yw75D1tGU1mguENXOfYnGYtp?=
 =?us-ascii?Q?c2Zi7ZPThVs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?hPOq5cGXa+8xF8pPAdL8AjcCIuuYLm6eAWDqVUglAWxmInkUTP4CbqTTG6AP?=
 =?us-ascii?Q?tWAsFiNd+CauxIp7XOzYRtbGK/YQvIz7wkOgCsjtG/N4Wap1yJ2cFdZCtRCH?=
 =?us-ascii?Q?VEg9hoHHnjQ9BK5INxkTZ6L7AmCkCD2TAXqdiplRZvFMJpZXx8OCKey5jREc?=
 =?us-ascii?Q?XLgDd31Cf3jN1DAlMoESwp3ZilMyMz9wmg8e89pmFbruL5YLhO0kFhfon1v3?=
 =?us-ascii?Q?vuVJjogrFPWK98yWSy5m80ZyayWD7b0BNHG4xH/2qJxMf4auyEkFyDdQuT08?=
 =?us-ascii?Q?PbRA6YpqFpLFbTim+Eyc/FPiex+Vyx+X6Y6FqLLWxcBO6hZmxrGtto2jfGlx?=
 =?us-ascii?Q?nb6AaJh5mlOSoyIbO690aAgBgR6xP/Gqyfd2EHD0vID3/74xQyDu8NxpxSQT?=
 =?us-ascii?Q?2LaluNmUfsIBAnOeoz0NvvJo5+WRdBTBByahq8P0Y3MvyOsNTSAM4yj3zeqL?=
 =?us-ascii?Q?HC54qhteagR9gZwkpOH0zFRKi2WCc1pmxO7ag6HDknarrvuudNJlc5Tooc3q?=
 =?us-ascii?Q?IU53+m1RjKFfzCBY+FfobHz91gqVxdo0W5umG0mHeQkVxPYo43/F120rOw4N?=
 =?us-ascii?Q?jIuyr+84CXXR2PAa3+jdu/cBwG0JA7ecl6Fm49CbKevyeK8YXUe29E3XtHIf?=
 =?us-ascii?Q?iTspGTpbPB8gpTw37o6El3sxoWX19/oEbVhgXBhlS2EmAtlG3mUgXWC2eF0J?=
 =?us-ascii?Q?bHCh5sIG4wo8ba+/pP7vFQ3c4kRwTrsaFnoMRjaakWTTiKy1PL3XY8X1PuUX?=
 =?us-ascii?Q?+xdLy4E4kvu528Lz1Mhezv4kcnDWfv+Nxyz+zxyjGwWdDJ+ngzHdV1wTpJb5?=
 =?us-ascii?Q?jFhljU6fqNBsfrTlgnqXTyHA7FcVgBrWRxsRMaw+EkmbQPh9pUxNQZt6C8ot?=
 =?us-ascii?Q?bh3DU+w5a0cVhVnKiYu/vgsRWPJVVxG+1uo67gh+JQPkknsFtHJJXrqrsvu2?=
 =?us-ascii?Q?XXZis+v+mWMHdrcax264rFbnTYXBWQ+nooZuCpiIRpniwT35M3Z4fY5TODuC?=
 =?us-ascii?Q?x5Xukox04dmVx7QUgmUJUfBwUEcZSWWKdxbItmiVo+IprLQrCuMndgOSInKx?=
 =?us-ascii?Q?xiYmSRSk8MxsYY37C+TTzAquKnZNzg5xnRmf564O7O4B83d7gny4KiMTZXo6?=
 =?us-ascii?Q?mjNoo7pG94ONF11cTLFyUcSLxLPCQokO0b4Z2+2vCU6j1UPJGpoglP9ot8tY?=
 =?us-ascii?Q?KYjFDWpJxKxc1a4p9go3MWsTUiEPiQc0N3LV3Z3+Ixg2BQhySAVz83Msssay?=
 =?us-ascii?Q?6S4BWAkDp/HOZPDANNPImoH6A9+97tZtawL+kfbOqlIKFntWbjRA7uBQ0YI4?=
 =?us-ascii?Q?pUiCKYRhmTgnfNfn/A4cKLfokscj+apNv1xZUT26zP3HtZLWTK35biGeYdj8?=
 =?us-ascii?Q?i4ONxBNLwzkoiJCr2hVuFW+StXWryJs/UJ3SUHHxb+jWDofjpE48NKKYKnQ/?=
 =?us-ascii?Q?Fe5BhyXNjBajebb49R8IuOZhM+odthwjSHUqpu8X7jl5Sy3PJTXV8pqozZCM?=
 =?us-ascii?Q?4XsBwsAjdPttBcGVUNMDy+DB92HBSOhL6HUgrmUvsc+cIDtNM8Skms1h/X1d?=
 =?us-ascii?Q?4BsdQ/K0M2AV60Dvaxg=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fce15a36-c8f7-47ad-070f-08ddeedb15fe
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:24:49.3190
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YUX61/utz8GYeLqVs/Ti+CneK+qRE7en9MGLKTzmGxSu1WYpxtyqb0UgjHj7TOs+
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB6882
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=row4tRFN;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2409::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:43PM +0100, Lorenzo Stoakes wrote:
> resctl uses remap_pfn_range(), but holds a mutex over the
> operation. Therefore, establish the mutex in mmap_prepare(), release it in
> mmap_complete() and release it in mmap_abort() should the operation fail.

The mutex can't do anything relative to remap_pfn, no reason to hold it.

> @@ -1053,15 +1087,11 @@ static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
>  		return -ENOSPC;
>  	}
>  
> -	memset(plr->kmem + off, 0, vsize);
> +	/* No CoW allowed so don't need to specify pfn. */
> +	remap_pfn_range_prepare(desc, 0);

This would be a good place to make a more generic helper..

 ret = remap_pfn_no_cow(desc, phys);

And it can consistently check for !shared internally.

Store phys in the desc and use common code to trigger the PTE population
during complete.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908132447.GB616306%40nvidia.com.
