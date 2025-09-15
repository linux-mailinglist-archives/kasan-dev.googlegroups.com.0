Return-Path: <kasan-dev+bncBCN77QHK3UIBBZUEUDDAMGQEE53XNWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id A3E21B57A05
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 14:11:20 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-816a52d9a6bsf443847885a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 05:11:20 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757938279; cv=pass;
        d=google.com; s=arc-20240605;
        b=bhFYglr7N3FomTy9AZaTWuHcguc52ukUausm4ErtgUVzNyS4eLCFs3j3E2XmA03OHM
         GHyILe0nwlgJQG8OcEl0htQ0G/NNdIXGNaEoMlsqDBwdPJ/dwVu9Yl1Q97tRzsx1YXaY
         03bGvs/nhvOloyrb1+fvDwnEtkxXggRRpfdsn1QgCBd6YIkWldEFa1qsLZPnysEzPF2h
         TLkXPueaWHBs96LEXdx8vT63zqdcIxzl+ADzCvwk1wMogxalEthLPVdac2aTAmPJJUdP
         kIpqFn0DMkaIdWtrP4+T2kA7kfYBkU8WDtk70xhs2S6kDYQj8AZmvYMNXdjPX/LsG7hX
         v36A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rfHmZwFCt/SlJufxyLK3K/pu2OHLZGEo4FnS6BDI5dc=;
        fh=V5xBhJWoUh5J9L5SfA0bc5YHpAaaw80OdVxk5WF9fhg=;
        b=Z030qHQge3+gtlUU8hWJi6DrhEd8MTdnptTTFwvK8892j78lN/9xSc0SDAmxGqiamj
         T3uXVqvGD7HdHFfuy7mXw1FqvR62W3FBsBdJv36ak/6Dr/fIRulos2NOyakVL2jh5zUT
         lirlNRlsdFiTV7mpRweAxlyd36B0Hv3fm5FUseTgk9ljnIjvdRk5wrUG/swQZV+Z4AVJ
         dfhuOlKFIACcj7wR28EQvOmImOeS3E5XdEhMsktL6dnsAbG8NeDZJEY/kylEazIKWljr
         IeiBibNCOtSLdPulcKxv2PKkIACu6x1wKUWYgqbFXVJUFJvE3ypHCaODDYzo7ARu8qqS
         hxUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=IJOhYeDv;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757938279; x=1758543079; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rfHmZwFCt/SlJufxyLK3K/pu2OHLZGEo4FnS6BDI5dc=;
        b=cFtTJaoQW+uwFzyXf38AwK+zxkp2EVyF91Kq0ow8w8rQWuPJwjVH346a1bvXE7Omzu
         U22E66FQVye9iCBxjNll8XBHkvWDTm61XahgMZ4tfhUR2EeQIHOF5mAYZMLl1Da30ft+
         Ws+QH+1sN0U1YMWSrBC0fouI4aSM/oS2gVKW22tL0VynxSLPmkPmf5ok7C+khfmMtSEB
         qfmTnuExd+xSRY7dp1uuRaZ5bLw1GYhbRatfpE2VYZ1b6++leALIKOyByBTzPuD2woqF
         02GQ7oCpugvJNTImZOw4LGFwBKMN13PEgpqGNFa7t10GiMKaO1XsX4j6ffZzopQBy3Vm
         CNaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757938279; x=1758543079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rfHmZwFCt/SlJufxyLK3K/pu2OHLZGEo4FnS6BDI5dc=;
        b=XU07IZaC4pEp3J/7FuhOW+/8CLgWUvHKiKEed2ft+3sCy0Oj4cHFyNqbQK2vvhdYUQ
         pkpngFEfJJz66BB5z9AitNktY4eolIGFVs1LZbwB8YOfdU8Th2XMldhyIMldkr3Jcbqa
         Kh7wuVqdBpmnxEotL9y4A8m36tJ6retmJw6zjCthEHZj9gHzirqqGSt89s4cw1p4jsNP
         m06BwIZ6LY7waQKAZk3zyZd+Xq/GpUwPj5XMhIolIc08YbyYnPz3M69Qshz+7jm9LqjP
         FmXje8t4ZBqk80m0evtJvEllTgN07vcJ8t0O/yznsTY3HteLDCAS1SQdr01kzFX0aIMd
         pHiA==
X-Forwarded-Encrypted: i=3; AJvYcCWF4YGb+4OGmUXfB5af6xgeGUS/gH9EnRC83eBsm1NV2kiIPjRlD6Mr6yItibdOCSeKEwOloQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx84fXQqzr146HdDenwdUw9h/8kco2+tD7lw25AJ2INqpskYwgI
	rIbxamTs2SCqqxb5rEPdhVjuHRoRNeLS3GWg5VVNu7OsTMKNV0X+7qaM
X-Google-Smtp-Source: AGHT+IE2n3IASZ3PSgsNXn8cncAXcJGOq+8+mSPECm0dcAVBnQbkkQ7W6EIG42L54KjjjEnKPSUr3Q==
X-Received: by 2002:a05:6214:f07:b0:786:2d5e:fdda with SMTP id 6a1803df08f44-7862d5f0013mr24263986d6.18.1757938279010;
        Mon, 15 Sep 2025 05:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7BP2ALk+QUTbnr6A0eUpcJXTjB+1W6qqMfZKYulPkHUA==
Received: by 2002:a05:6214:ac1:b0:70d:9340:3384 with SMTP id
 6a1803df08f44-762e48bd695ls62504836d6.2.-pod-prod-08-us; Mon, 15 Sep 2025
 05:11:18 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUzKS4EbPadipzG0chtSiWyzXeSqp2zPrPhain5B7hJnSMt+/GQAjqdgl3qvrHo3S1A90EDGeIB4oQ=@googlegroups.com
X-Received: by 2002:a05:6102:3e12:b0:537:f1db:7695 with SMTP id ada2fe7eead31-5560fb43c96mr3418176137.26.1757938278025;
        Mon, 15 Sep 2025 05:11:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757938278; cv=pass;
        d=google.com; s=arc-20240605;
        b=VBCZVjqNzSl0H6sYM0nJH0tROdavkwH80W80XDomQzOS7/6y7tjr1opU4UXbu6AJFJ
         rzD1XxI2lFWgi0WnkrWZCYWx/hD2rYveOhZXTKLwi95M1WEx+sFq6xQ/FlRdNO3CvWlj
         sUnJnGa3aGqMyPCMaWxtjPl1S6L1TwMDR2xAMXfxqXZDMDYviBNYV29XB7atpOS2AlSw
         Fba9cWhKnEcwf4HxRM18rRNQa2PiKjTVnrnMpd3FKcdFLbvv4aX5tXXrkFKIZdSOulog
         G3PYvZgIRZkFteAXwYvgLh/0uQ/nTEbjgZMAGXTM43KhH3GHPYXDzD2gFWgyJXySoU0O
         yL1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Bx4uWWlu8yYCugcQZW2osJLjgLaur0EGG/CnxUsdqwY=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=FPF9YeOoKOQl2phw9AqXckhBnDHi7+r9/6vfSemSdzSMCvqS4F8i3C3CWo3swoGvjz
         4ui34HQNX5Rr17/z4NKQhHemD7kHVIycpVayOdCNe+GecHC1OpQKOpJQY27Ij77B9d2q
         yNoNThuNJKAswFm4wvBhmoJxKjEfRMf0J4OGzMlAYbggvCZQKqVD5GTR1/KXt7pK+Dkx
         ZPBh93KSSuWX+nYLOfx7g+Rp0HYHck0Ocur2XJPC8Jn6lDFo/P63SmLUDo0GtNLHXJNW
         SJSngc4rDIbUjHXP0RO9/P4j2VirFFUUQSUq8DtYF0NEtXR/9vp+qIh7B6UeygDpNN+W
         iA5Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=IJOhYeDv;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR0501CU005.outbound.protection.outlook.com (mail-southcentralusazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c10d::3])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8db2d6b7e99si149237241.1.2025.09.15.05.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 05:11:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) client-ip=2a01:111:f403:c10d::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=FQrQAg8fwI5o0BvmZDCf6ejxPbckcuaEuPFHgzp+/YlfS9GfsRR93RKMBs0dRfo7uoMisVc9OFSCC0UXqkwx3sx1Jl1/zKDkQSVhm67UqR7u9pafURXw9SdH1ImES9+LWLtVJuGImJSlN09HdIvaYoPt3exBdQjiLEayJ+Np22Q7rUiFpTrSDnehV3GtVI/mmtklLMjZYpaO7M7CwQBVaJSSL/AYeuuhpq4zi8Lg+f48eABtincCLpTyyBdJQmElouv582v+dJKrdEsulbiVl3jfmffTdyR8d9cHUclGyCQGo17Y07ciOxH/1SqlWoTm46YvdQKtkcsE0aVULILVEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Bx4uWWlu8yYCugcQZW2osJLjgLaur0EGG/CnxUsdqwY=;
 b=PKmTj/blt8jcKrf1rlc1cK/EO5bkvltofj4ygUhG9D5JCd975xU5tIpsjfapmVj2kOEFgWUGL3mtoWGi5SXTkxb9JoeHEH2V3wBWMbrTLhlGvTu712WXPhulMfzULn7tWSMDeXMKfvVayKmiHTlfcqomck3VDyf55dw4hfEgVl0sbsAhycKQ1nmamEdHuam+e+szHqEU/JG+FwGwTnNO5zH4+/x123/gjNzGIN6r3RCOw3cGLXG/xTWE9XCHK2y0TBGZqURTdN3AKhJg1IqDW02aIzt8S5wG3COpetkMQTzdihsMQebCu98U+/BJ5bFCgdhA3m/OJv746PfisyM6Lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by DS7PR12MB5790.namprd12.prod.outlook.com (2603:10b6:8:75::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.19; Mon, 15 Sep
 2025 12:11:14 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 12:11:14 +0000
Date: Mon, 15 Sep 2025 09:11:12 -0300
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
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250915121112.GC1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0188.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:110::16) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|DS7PR12MB5790:EE_
X-MS-Office365-Filtering-Correlation-Id: 4082ca6c-3820-453d-8a18-08ddf450f784
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dzsySAwkFVc5J7k/gJGmr9YXF6rld3I8L7Y9nzDZoHSX+fOgM2GPdL7EA6Vo?=
 =?us-ascii?Q?uEfz5IMOPZhiebdbzHEQqpCp0DIgrbnKx6Gg1VLLudlPB812S0nRIZZdn2N3?=
 =?us-ascii?Q?2v0qvhxj5uhB59qpfseTP4JXSuHKBhVCtfTbGBUBBSSsPSZQf/vLzC0ABy7u?=
 =?us-ascii?Q?aWFLqLYcSNBanp3S3/DxXqmq7Zc/F+M+/kJtGMEJWsRIp/zogAflhHMANvI2?=
 =?us-ascii?Q?gpjQDXq3RzrpWHonIx0jZwZmSGVbSdYQp9s0DkZQkOV8khbb5Gunr9IxXTPs?=
 =?us-ascii?Q?s6hjVz1EVX0j3A/MUM5n/etizjl+dkPV94A6JSem07417uQNyisPtyRdUwFw?=
 =?us-ascii?Q?OjNTmbKM76+zMjs+SVaLoGIF75dtN7fxxGubaqWuvJngyrNop5Ha0md23JH3?=
 =?us-ascii?Q?VNqrT+FZ7PBmvSCxDB4H02PXnhczW0cDZc9wDeg9tiYIxMHC7ElibLqYlj4K?=
 =?us-ascii?Q?BxLa0G5d9IWSEx6TQ4mLx7utF6aPJ/6MQ+Pd+gQAIJbu7ePahUgxUIEmuBx9?=
 =?us-ascii?Q?qe4OIG7RkoCuv6S1gg4Z2OCC/v3unmoEFG7vsUAzwCb0S6qQAVNlglYsR6JN?=
 =?us-ascii?Q?hDwRVkV4SucBmWUdtNTAkPzgZQ16W3zhFEBH9fufRf1K3ioe5ofyEhNBNmyz?=
 =?us-ascii?Q?k1gI0ip3MEm4bqv33iltMrFkluE+qG7+5qpzLX4OaQ3N98zoegTuLp4eipGn?=
 =?us-ascii?Q?G4sAesxdDI3LD3wJfKjF2aUmqfl7aB4lkiIp5DxoyePdaX71pvkTYZctJebv?=
 =?us-ascii?Q?Moe5bGlKESGR8OC2FxkP99MZ7om/VsJjgyWCHzEsYAg3dNF+wSqMhdLKT2bU?=
 =?us-ascii?Q?5lFfWtpo4bOKJqdH+gJPQThIdwww73g8kcCyBxHY8X6U4IretMj1eY1buWEL?=
 =?us-ascii?Q?vWr7LvY2UlvGk5o9WZQxrNmaASoauxkCMSPqA/b816c5XZj1Cza8tq4tCHCX?=
 =?us-ascii?Q?13KSJaeFyTVbGt2sFthvhM7jWpsGI6al/VPfMkHtBMU0rpnf1I14ogSP2ozH?=
 =?us-ascii?Q?CM31c1Y9842aL5l1uCArrjJeB5SUNZUcicoGvQiPR6qg3JKBm94N5Ak9YHTz?=
 =?us-ascii?Q?mcbtm59LeiPUvWGizY3/nD6LAUvKcd/U2fqwojr19p5Ws6uwiHoDAHfHFMpV?=
 =?us-ascii?Q?gjFMlCaOqXJmyb4PE8wAcwj6kvAEl+ry3hgtWoIOrjxSSBYrnMijXHtvpauO?=
 =?us-ascii?Q?Icpps3DoUt11a5X6jK2EeRj/R1mTEbAjLKCXTlH5Zbh5WP1dEDcMwsPThqgK?=
 =?us-ascii?Q?vaWFBvPIpkfzXsT55X8OJNo3sxHZff5bs9Ostg6jQREMZOk7zUnwkp5ueGQz?=
 =?us-ascii?Q?Rro070McqwpY1VxHxZA+uIZA8gqlGcadtmgo6OZF1t76qM3W73M8YEfV1Oeo?=
 =?us-ascii?Q?GHaOt2yVk4xozs/fOg9Tn7eoK62JpndnV38f/1SuQhR1IHdTxFF2KtIqtgsv?=
 =?us-ascii?Q?450zTlfE8Ak=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KVKj9+BouTdnTX+BdH9uwWNlRf9+k8iuqaBjUMna9pcCNwfSgbFkdKi6mnDu?=
 =?us-ascii?Q?0KWrnnPW5mBGhx3N5ojzL5bio7BSpG+yFFG3ATjikBcXTpdRqv7cIjiNo/qJ?=
 =?us-ascii?Q?EeAKVN7kEyc0ipGhxEJj+C6i0pe1hWFUOGDqR4G3e7IcmBAhU3xtYMr6QsZr?=
 =?us-ascii?Q?DOXPiU2zBdknVJToIxQFjpG8kRepn7u+FgXhklLePUo7JTrIUbb5SQzSxZT4?=
 =?us-ascii?Q?M3VehJ/Mqwnz/JyBYW/DSVpQjc78jWNX9EOBxRt3FVxHkGYlCdcy2ZECydal?=
 =?us-ascii?Q?SYKdLkbJA8Nhof8L/6DYa9C1bvG/Bux6TV/1aq9s7fWSuMGN7DaiZS1rlAAA?=
 =?us-ascii?Q?g/fbF+/Pz0laxRCtEOxc9hoKz1DKiiGYPBTC9jIOfjQk7pyZD9+5ZbV+zXpy?=
 =?us-ascii?Q?7VGq9Uztn5fCim+5jXc6T9pwFW5wYSJmSUqbukuo4iod5lk4IEWqe7/6zzDl?=
 =?us-ascii?Q?nPFT2iKrR9LceG/0EvAcJEuJG7pByPcMg2Efp7zLkMuP50waGHq/PpFAorfK?=
 =?us-ascii?Q?HvPq5jikhZp8XCFYeYzMFnotwJpj6gzs/8k4STa+oxrnd2UAfOq1ZQ0bfVHL?=
 =?us-ascii?Q?Yu/DS4OULMx4D8VI6B1AAI00+hoyNAt3vJCQbzLhAPG+ot851P8FCITNvBgB?=
 =?us-ascii?Q?owphiWVU/VAWls5uwEtO/OX1u6mo1qO8tErti0AWa45JqIbNxcjX37pp/4Vr?=
 =?us-ascii?Q?f8mpZMQzTwGKOCLaK9fn5V7XbcPUGqRGJk25bMJuJ0M2Jhx88EHRPUxXRPNf?=
 =?us-ascii?Q?6l24bvhY/l7qhrKYq9hMEnqEvHABfSmx6oMOne6dBh5+ghbm0JWm4Kgc8Lbo?=
 =?us-ascii?Q?aPmuO3BiJIcmi7kx8WIPiLlrwbc3bGNLimhzciIXYh8GKaBroFxh2SGntcUf?=
 =?us-ascii?Q?m40Jj1YNgW8VdTdyfwVefbVeTuQ8s/Fm8msHqZlfoz6D2sTdNfXzmLvD7at8?=
 =?us-ascii?Q?EP1eG/dgaz8ijPbA1ef6WP7a2CkjyjDGomOpytuHEqHcjlzg+Z1Z54ptov4w?=
 =?us-ascii?Q?yLiFAU0csnjarMQcN0ZBICbQcHQpqJsKeMseNJkM9wj2EowGhICS/c3qoc5o?=
 =?us-ascii?Q?iXOp5DcaEwX1Au4dW3Q/h5P+fRyT9/Mp33e6qnve2DRO4+7XRGjIX2+vpl6r?=
 =?us-ascii?Q?UStMCjVEOSaNqubJJwosATdQptN2ZPgx8Y9Th41jaW81ttGgehAW7gxEUEGv?=
 =?us-ascii?Q?PahBSxPzmHwUv2tjbZ/bqQ6L9U8f+CLPx0RB6PVvnuH08ii0byYqIF+SU59d?=
 =?us-ascii?Q?XRyRmkpq34ONsM7RzSgFO7uT+LOQsSGvRCcBsE53lAcSbz2k4psjoi1tLejl?=
 =?us-ascii?Q?QkVX754z23S5iQeTP8T3uNBfcYA0JFGo/kNW88onTJ+i7xTgXWq4Sjtw3yA+?=
 =?us-ascii?Q?IAS4fWs6gw46kTfkI3mIsk2z/vqm//0Dubcv0Kl//PMoWUHlnKQSwGt37ANG?=
 =?us-ascii?Q?li3Onq3S7Fy4H8wE18n4C7amp6T44Ia7KJLWxHU5xhqhOItsMm54ZxMUqc8Q?=
 =?us-ascii?Q?+XXSHM+OuSmfl++PuzBOA1KATMc107FR4b/poyW1UnjKPxX3DrsQcAZAVnmu?=
 =?us-ascii?Q?IKXCdpSj7k6C3fdSZPc=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4082ca6c-3820-453d-8a18-08ddf450f784
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 12:11:14.5370
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xRRlItnu8SXrt4No5ZKs065QCVFt6ZERgEYfgL4f5Cw3eSNI3JMMNoyv9KZ9Q9ns
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR12MB5790
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=IJOhYeDv;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 10, 2025 at 09:22:03PM +0100, Lorenzo Stoakes wrote:
> +static inline void mmap_action_remap(struct mmap_action *action,
> +		unsigned long addr, unsigned long pfn, unsigned long size,
> +		pgprot_t pgprot)
> +{
> +	action->type = MMAP_REMAP_PFN;
> +
> +	action->remap.addr = addr;
> +	action->remap.pfn = pfn;
> +	action->remap.size = size;
> +	action->remap.pgprot = pgprot;
> +}

These helpers drivers are supposed to call really should have kdocs.

Especially since 'addr' is sort of ambigous.

And I'm wondering why they don't take in the vm_area_desc? Eg shouldn't
we be strongly discouraging using anything other than
vma->vm_page_prot as the last argument?

I'd probably also have a small helper wrapper for the very common case
of whole vma:

/* Fill the entire VMA with pfns starting at pfn. Caller must have 
 * already checked desc has an appropriate size */
mmap_action_remap_full(struct vm_area_desc *desc, unsigned long pfn)

It is not normal for a driver to partially populate a VMA, lets call
those out as something weird.

> +struct page **mmap_action_mixedmap_pages(struct mmap_action *action,
> +		unsigned long addr, unsigned long num_pages)
> +{
> +	struct page **pages;
> +
> +	pages = kmalloc_array(num_pages, sizeof(struct page *), GFP_KERNEL);
> +	if (!pages)
> +		return NULL;

This allocation seems like a shame, I doubt many places actually need
it .. A callback to get each pfn would be better?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915121112.GC1024672%40nvidia.com.
