Return-Path: <kasan-dev+bncBCN77QHK3UIBB2NG7PCQMGQEZPFHKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B756B48E71
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:00:28 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b4e63a34f3fsf3295802a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:00:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757336426; cv=pass;
        d=google.com; s=arc-20240605;
        b=lbWQr6rQMfFoDLnddBGgoOXYQNWejTuhlc1wm16RZjpTx+qfI/FE9xIYhQh80/qHHa
         kO8I4n0yWLx/Ez9AoqaVIwEDVkInP0LT404CrCQKVxML5MKbu+YnK94+s71x6InZDOcL
         2oxWauddnIbAlp3reMIMED0vuKjOwmDT7srXLncBIL9K+LvJF8qZyfT57AZDuch1lBhC
         RluHsMtsr02PSTSwaC0IboBWd+jecBheFsN/YoYH+YNNFBkJcEgMCbkTF5AhWi8u2UVB
         hdExB5ZhjewkzgSalRKqPsLOctFwgOYJa0EHEYIkVhE9w2HAe+rjXntXkA4dlGI+XtLz
         sgEw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=oODFe9v4rDq2+CixnUL2wpu86QG6nA/rrfI/2IswkKo=;
        fh=QGC99yF+r9YO6uiSHe7xC2vSZvRXpobQjNS2e+KVXQs=;
        b=K5a1jW0MUs+e761C2A/gbDY1RpeeAKRqDFKkBmGDBAuV+45Z1a9oZJMKwPn867sLzn
         h2FUvyJYYaKR9Le/COQsp4JYRbDE3Gq9d3PDhvU5K07WGooSyM2UhN8Ibjz3ViSY4+zG
         vMl8YrqFjMylM0RvnLDEuFFgWfDvplEvNFyDcBphhmoQsg+7ZPKWfCG/EiPe39s7lEzC
         NTmB5IH4cg4+vbNvEkthwXXpR4G9cWxymWjb0OF7uVbpRZJeG0sVgEmAOSBNA88rXtyG
         JQpj+xZdIgZkixhxNwRy+S0mr5eDOR86UxSxHEaarkcxZ+I7XG39zRAyY7qlRoCBxucr
         QB+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="h4q/HWaf";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757336426; x=1757941226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oODFe9v4rDq2+CixnUL2wpu86QG6nA/rrfI/2IswkKo=;
        b=Q1+V+k5la2L00unZd76A7IEle6j+A2knJgMa5T+0L5Yr6Xud55e1WxTdCOlvoT+fCS
         ylmON2TiwOelMoOlvaThnsaB/WFJaFvPQjOWT5/UQMMR8MX6sOer2j4xK988DeW6K8qr
         2CHTTWi8MCVF79JWHLobXBgy4uFMvZvjri2J/iLouymNLSRKzxZLv1SRA/S7Pm/0IGo7
         PBGRgsYAxaggWkaV6ktyQVx+w9yZVFttgSKW0NdKcwA8QUXyeaSygMu9Gl3fpBWwnkmD
         pGj/81qybC52lip8FSMYtgoA/wiN6SuyIQu4AW5D/ZPdBOzjsCao1JMYBxXzKsl2M05+
         viGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757336426; x=1757941226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oODFe9v4rDq2+CixnUL2wpu86QG6nA/rrfI/2IswkKo=;
        b=WKD/9fMoxSMwySX40deh42xjlELTVjPycU33up5hpHOJHihQ0o6WYEhM08VjXTKsTu
         lUMpIxA10BQKFIdWYFL/OpSUaO4koZDGmySogASCNO6bxX1VyJjywF0P3BH0Zb1anCDc
         Bh1dyjUaGR/aqk2qaEpkkkbilwBZTHQtptdMVdKOcnb4mtomTEkMI234YZzkOlL9RWsL
         hoZQF1tgp5rNn38RNnhr+Sw0L8ExpcRBS46LYQboYKjDM7wAetv4y3M46BXRavvW3kcT
         /6K/+kIIYTnNOx4pft+/d8NcT/Sn8HthDVf9rQKt9gry9PqMcycE8RLyziH4dUGWrJqn
         bqFA==
X-Forwarded-Encrypted: i=3; AJvYcCV1rFxYqVGHAo9Iuxix8zX2TvNUQw21u28UWU5XKJk0F+1WS7REA11MtLPxgafza3SZWM5DIg==@lfdr.de
X-Gm-Message-State: AOJu0YzANlNQD4DRzi3QUVu8GGcp5rwBpmu4wLkcSKnA5YICIgeOl1Y0
	v2GClAwTkNw47QzgRpktapwoJDMejLXNHgnI8H6f35fDJkWPX8MiCDnw
X-Google-Smtp-Source: AGHT+IE+s4ZQx1uU1gfUNFqr/FX+COl8Z0VaG0WlDtukg/sjU/M8aPxR/WNuqF9ZN3yjtfphQQ+Q5w==
X-Received: by 2002:a17:90b:530b:b0:31f:ca:63cd with SMTP id 98e67ed59e1d1-32d43ef0790mr9498419a91.2.1757336426270;
        Mon, 08 Sep 2025 06:00:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5cORJvDcigkyLsQSYIdR2nw7jz1fd4zivDx3FOqbf3Pg==
Received: by 2002:a17:90b:248b:b0:325:c01f:f69 with SMTP id
 98e67ed59e1d1-32bcaa031f3ls2314905a91.1.-pod-prod-07-us; Mon, 08 Sep 2025
 06:00:24 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUz09ssbrzisWiLJvuxF2Vuwur74yVMGdSumOuAEwOiXjLf1kiqGBLDWjpCQBFq7o2aj/cktEgCR4M=@googlegroups.com
X-Received: by 2002:a05:6a20:3ca7:b0:250:9175:96db with SMTP id adf61e73a8af0-2533fab656dmr12436936637.26.1757336424029;
        Mon, 08 Sep 2025 06:00:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757336423; cv=pass;
        d=google.com; s=arc-20240605;
        b=c/fRbpPti2gisXp8lG6c6PuGzF7E9jQW2zORO6W+Od8EVHso/1FcSoAVlz/j57kh+s
         Q/PU8TFb2b5+cLzS4r5Btjlz4GYxygQHYLmQRIYlfUoheXPWPLCqT2HMmYgUpWI2FbYI
         RLNrscYgCfPqfEswxuU8IqzKVLUuhtN2Q68R7VzwdGbuADGrOoZzPxlb5bQrR0QuOkHV
         lErt337AF/KeKSxVBEsqlRDM7ZlU8RD8eMUOQelyh4rsXXn7Xsy6ndCSbV84MCAinJvD
         ece8qPazhJu6ZTxi95UilYi4Z99CSTZCnwvBzbzQR58AhTC/IsV486hetP1DHIK74ald
         b3aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nXKGV11o4F6/A/0Lew4K4pGO87ezPNwqe3IqSqZlpvk=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=N8YkcRslz7UwAvPhdgPowc9ExpnMbJ7HtzwdPlISa/noGq3nHaIJHlxdeByVxKyWPd
         alb+5xfeTL3OnbBzoxYnZppXGuR+V3DWNLW2NjIxdQp8iFvkFV8nbWV4oaWSYzYNSH76
         6ZxTRWiEuQkDJRbk77JBirumn8Wmd7ZQZDdiIvbASy2EPNpl3wONwcrn7O9AZWfoo5uK
         A876ttecbpC0qZxygAcOIyWw8ZVFJW57pCATFbOQX6yrExSoH+c1kRECS+Z+c1EpcIAh
         u9YrmQ9TVwfTXtsAZMn/IzdfMtjVCCMC4A58RxauOBezwFSQ3tXcfDULa9l4DZMslQKj
         bDIA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="h4q/HWaf";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-BN1-obe.outbound.protection.outlook.com (mail-bn1nam02on2060f.outbound.protection.outlook.com. [2a01:111:f403:2407::60f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b94708c7fsi381112a91.1.2025.09.08.06.00.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 06:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::60f as permitted sender) client-ip=2a01:111:f403:2407::60f;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=hbmTU8arglgFRu/Yvn6JMfMSZlxyq5LumninzrKoP6yk4exc42ozNWC6WPVZELJ1MIqVahK5Qz5XMtBPFfcszRjNX1/uoK+/aAnJZdBc28sOSyPVZaiLIpawwQqbY4SoEtHjj1BxY6/IOzaJeFqRVVTDWmFH7sC8UXWJEVTzunilhFUFQiDqf3pBP8xg1/Ozz/cGeO/71mViyCjLQ0vOMc4smfIg/7GB/8q8t2DUvmKupDsCW2pXTU3WBvAAVspphcmTsEOc57P2oIjs3O7EXGkZTVVdXzX1Cxnmtvr86BlPBA7umQQrrQijGUtuPqVzd26m+kbHSdvFuaVLrzmhQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=nXKGV11o4F6/A/0Lew4K4pGO87ezPNwqe3IqSqZlpvk=;
 b=KJwev7LSfCR4Y1AKY+p9++T/+Fd/p9dEwkHyiMLfZrcOQwGHHqplyjOEkQgqxgtujmPbUHPNZtI8gUX/dGXvSBSQBzD4zdRivwXBwvDx51wGbQgBD3p6Ff3FucxJExkWjBFtxS4YrHvpZEoaJXX+u3Ag8Wkq4Eu1yIh0t1H4R+bhhoPWuVnFptiHpZQUw1Q2YogYwWhEjWpeyxNHaycZTVyDoqVcAN+tD6u3JR+i1VHbBe5BkOqxaODDjmaK/QMf+4Z4MXaYqqDavxX51hEvgEnuWl86M7DC2ni8cOB5WK0sGMZjQzr/V6jrOe3WPZBOdEv2bR4dHQrDURUbyO5Tpg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CYXPR12MB9320.namprd12.prod.outlook.com (2603:10b6:930:e6::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Mon, 8 Sep
 2025 13:00:18 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:00:16 +0000
Date: Mon, 8 Sep 2025 10:00:15 -0300
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
Subject: Re: [PATCH 08/16] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <20250908130015.GZ616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0111.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:d7::18) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CYXPR12MB9320:EE_
X-MS-Office365-Filtering-Correlation-Id: 0394b5ea-d592-4bc7-e06e-08ddeed7a852
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?lrQn4tvnesoKrzKbjRXz9KjZnXnSTk/3UJCwZ12lWfJEUXWmkXhl5LTbzJLo?=
 =?us-ascii?Q?iUeftcVzA4WgIHkzrwmSyaPnFwplHFjUrERLcjaNYrKWgNNgg5fOErejfEUY?=
 =?us-ascii?Q?6e4WwlLsGLnK5cPLv9WIz9n0+1QtqpBCNtaUTMvD/9Uh6nxmS+P/IQzmgOe3?=
 =?us-ascii?Q?evfWUaj3mDgi8E9RsAMu9MkXWfJH5ydmV9uYBaO4mEuOpxch4DvhfLhldcW+?=
 =?us-ascii?Q?Evxx1rtP14kByrmy5W3WclnJ979/zEEoJdCQJdjHVpLHpJc7qJnNr1HCNqVp?=
 =?us-ascii?Q?Js64koTyp15iXMwypxDNkXaB5sYY3OV9111giL3lQpzmYHLUMcRZYGFeQxmM?=
 =?us-ascii?Q?zjGjDv2NcIead1lVnpYSOHJpMXv78vFizWv9r5YOwdTLjD3nE95lwku7IMIu?=
 =?us-ascii?Q?mNNZuMq/jBmYgX1Cy5KgJ/Wmjl8/dmaFebxCUfUuEr5Cuynq2pdJGrMDym7X?=
 =?us-ascii?Q?3C4VwG6ZToba+cADOuShSxKj3WviQa9V37XC2ucMs8dm8m2fa9UCgs5XuTpt?=
 =?us-ascii?Q?YffnHiIo7UWc6grUDBmPAzLjpHu31yGrsOQwXhI2jxb3HbeOpi6k4zIkGPb1?=
 =?us-ascii?Q?b1o7utOTrOVkq6wo+bhZpnIy3uW7tuvvOhs/iKuLjoUJKV+VNaFfJlp/m+Ij?=
 =?us-ascii?Q?UsL7boqo5PWNsiBDPMfauuLTwAg2+9SjVOvTnVG3Ux0run8DY5KsiJp1oGp7?=
 =?us-ascii?Q?SfXsKOxAKQ6uOD0Zacz3D0UPM5I+1ocpGBsu4/SXYN1FL0mUOUF+tJkljoUE?=
 =?us-ascii?Q?dYxzleBQN3d6r+6AZfnIWlBusje3ewUQWpSWNeyOgmq3YdqfoBOdwiLvqYAA?=
 =?us-ascii?Q?8xorkhgabd9MlAnJfWH+ptLZytP7eyVIwbFKXyBlqYvTI80/unn3+si0zJKA?=
 =?us-ascii?Q?3QK50E9dFl4qOv4/aFSIaeI2CPvdpNXv7V3LrIiw+5riL9XjAY/ci2iSZTpk?=
 =?us-ascii?Q?VqmcWw8toz8waDostRy/5t5jB4nVX97yJQfoJ1CArFDN9IBO8dEkvetpDVjn?=
 =?us-ascii?Q?VvIMw5CldVIdbR9lg6Yd1B0FGnmUvaOwNon8t1Y5nOHhTf8IT7jnnG1ghgxc?=
 =?us-ascii?Q?Jlh7/K/m7ptpIyTutmDAXTQV6d36K0hPnD6V/9nnXUUPLReteXdXBv3E3IkD?=
 =?us-ascii?Q?IHCgTaOuqiNBpq5cqZsDrDxaOLuz0ch7RRHWWsNrNvJ8H2vIUZzrtYlKoMvF?=
 =?us-ascii?Q?lM6+1cxvh9ucmWO6HohWiVRiqlv6eehf0GEuVFMfLMnw/FnezAOXdlW8vsLL?=
 =?us-ascii?Q?hZc2wUVhhNCFxyFsIwGYe5LnXmmm9xisqVEzzYAuNj1lpcjxqlMYvWkQKBOI?=
 =?us-ascii?Q?QltKBjnxhIAtMBiyZiz6PXvlE6E1EI6LZe2Raj4tXKn4ucdrFT1yRmAh4RTl?=
 =?us-ascii?Q?+SCyviVjUzk274Z805dBnhHyseFL5tVvCTCjMZ0AB4t0oa1MuLac1IsK41Bm?=
 =?us-ascii?Q?qwA3OandXEo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?IbnqqFt1p3xNch9KkSX6StllMlsl/M0mELgVQV60YbON76BXSvjUfJcundoM?=
 =?us-ascii?Q?fmmpw3s8vStB/nm1diRvT/JdLfK8ShHrQCeG5BlT9TfjTFFit52bAwXQJg2Q?=
 =?us-ascii?Q?DWhnamBYodc3UEiEXRpnYxbQITzBvuCp6eC7SyflqqaiJFoxCWiD8ASop56p?=
 =?us-ascii?Q?jOoXpXy/mtHyeaLYviDGch0I8WUnOlHA3Mk/639e/1MSSVEhiNUEGxpbKhLV?=
 =?us-ascii?Q?27LWdLgh7nOFEyxcJN2XYhbMfXvtblghGEpQwYtVV1ne51I/tbr8Akkkqgzd?=
 =?us-ascii?Q?44iffHpypUZbfs7B0l7zN31+CBTVU25/pHDp3EeupWbBg6XLJE6TjLWFRDGu?=
 =?us-ascii?Q?/hcfoFeV3PepGKuanVKaIlnqXV/9l5pV8LMDdVN9W5w+8hhQpGjITIL5AEIj?=
 =?us-ascii?Q?J7gVzWVkrO44+Os8GsOdDJtMEOPfalVM4arBCcGhVe6s/jCb7wNcR6iCBiYL?=
 =?us-ascii?Q?epZdtRQutvRP2j7F6MaZfKbSlmZRD4XFXT/e4k0uYm/1NSdI+aCThaC4x+VV?=
 =?us-ascii?Q?YKWPJuJqPXtpUxCl/NXgQYIwVDwMPb/icm6HlZ7SNG/2FQFoI92wHrepwfRr?=
 =?us-ascii?Q?aB+6U5fBYZuICl8BuYItHJDaFR5U1rfPS15nrHY42/o81vjB9MxUkr4/ibzw?=
 =?us-ascii?Q?nf+mxkYo+ISKWiC7NC6ZTbVvMFtpSEAH+fId3arDrRpXGi6ZYSSRwsfzgVj2?=
 =?us-ascii?Q?K4gE40ylF4ZDtl2IeomVw0tNSr9TaTP9j+1LQKSjFY0LU4HjKYkIUIKao+tU?=
 =?us-ascii?Q?UfEEhMXtNU2hxJgOOv112avpmBC5Ik16BSWGOQ1DN6dIsQYsMKvUOy/nfYOP?=
 =?us-ascii?Q?nrM6TTKm41eqN1aU6o9vvmiypZ0E3e+Q81TEgvFFyY8eI5ISofC5h2Ed4kk+?=
 =?us-ascii?Q?2pwcPuosFN2r8uzNQXogchrrgCZO+WHwa7nFSmtaPPDKl0r1KDsQs3wiWrRd?=
 =?us-ascii?Q?gLnGIncOQP+rc2IsBGnCi1xl/zvmLyowP4So60WArdPT83yCF2B066Pdh7EW?=
 =?us-ascii?Q?0sA8sWOW2XkZ3DvDQnL6ObIeoaG14r2tZr7ACVy0LDXGeWUi/vnzbQeNPMBU?=
 =?us-ascii?Q?3Cj/PuoitbWfea7Uh8A+YH8y7fSY1ujTolo5dnqOqavDapr8jp4ftXKv9o79?=
 =?us-ascii?Q?Dwf3K641XxZBs1li6fX6isWocCw5yFWijU/I8ZSx+QqeoPkT1NMUgozRkAkK?=
 =?us-ascii?Q?N/EoB6hs/W5hazcMwCeq24AASg3p3kJphTE/+v9zI+R9tcf5YTymag3Ffv+m?=
 =?us-ascii?Q?1EAyybS64eJUhTrQ9nBRQ4P5BADF6O886qA/oLt4nHkyFP5boJjKoeXXI5RK?=
 =?us-ascii?Q?FHXCGSijxG9+PKnjnZt/MjMFc66DSQMQfuYyg7yPmQaNlGG4q3EATRK+mWKl?=
 =?us-ascii?Q?O2KigioZwzS31TurmtMigGCD7IDzDwVOW/qq1JPUjOROZt+uYFNoHIkJs3qo?=
 =?us-ascii?Q?oHNf7bcodLu4RdDBG89yaZSPV+VgzsdToJYUYcZrxSiBeDCFad4i6np2wLwL?=
 =?us-ascii?Q?HWVCtvUepMIzKf6wmnS3vL2CJux7u8OEI7WDr31c+9G1muzcI6QswUGUUnMs?=
 =?us-ascii?Q?VxTzNQvuae7dIzq+/bE=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0394b5ea-d592-4bc7-e06e-08ddeed7a852
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:00:16.7402
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: k6/5kOlWJfQ1Zv/4iOUmsF264tZPcMAO8P7nkIcIqxDgBt+oPWzW79jwXL+P2MW2
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYXPR12MB9320
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="h4q/HWaf";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2407::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:39PM +0100, Lorenzo Stoakes wrote:
> remap_pfn_range_prepare() will set the cow vma->vm_pgoff if necessary, so
> it must be supplied with a correct PFN to do so. If the caller must hold
> locks to be able to do this, those locks should be held across the
> operation, and mmap_abort() should be provided to revoke the lock should an
> error arise.

It seems very strange to me that callers have to provide locks.

Today once mmap is called the vma priv should be allocated and access
to the PFN is allowed - access doesn't stop until the priv is
destroyed.

So whatever refcounting the driver must do to protect PFN must already
be in place and driven by the vma priv.

When split I'd expect the same thing the prepare should obtain the vma
priv and that locks the pfn. On complete the already affiliated PFN is
mapped to PTEs.

Why would any driver need a lock held to complete?

Arguably we should store the remap pfn in the desc and just make
complete a fully generic helper that fills the PTEs from the prepared
desc.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908130015.GZ616306%40nvidia.com.
