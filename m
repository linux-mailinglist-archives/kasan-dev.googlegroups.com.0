Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPFT7PCQMGQEVDZFNIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id D09F3B48F69
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:27:25 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-32145ecd7basf5471327fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:27:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757338044; cv=pass;
        d=google.com; s=arc-20240605;
        b=bNXXUS/FOjH2NO6cuLSuC2l9cP9u0b5WlH26u6eD0M+Jclp9xYkwIZsY57A0DFa090
         o6klfNnIqeIfirRjUZiWFkp3pahbfUVdimyMBh1aL54hzTRcfQqC9hjZdcZRWXionWy0
         osDGSRk+3fz1k5JJBNeWEi/Dp5A313lFelmYp3rYyk9ShKdDhL0OlaWMKZYrsUZsOhVo
         W/8D2isQJtjWmtz9jfthydzcKjSw2reNBbwuh7ip5z0JvX5LVahORksr+IZERcKOX7s5
         9jbYmnGJoE+BaadSz0YfthnJz7Ua2VGYi0MPeIewhhvm3ConYZTvWCkuMDa221qIDpMM
         O8Rg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=miDLkXi7uvpEoVBXuSjQgty4CQEyTzFV9qHcRFV8tJY=;
        fh=+wUKIxtE4cVlIUu9sBm5FEKNrBCbxuZJ0EADiZYqKLc=;
        b=iKyeW/iIhBDdPqsb47ae/TMJhAuLVqQXK5XvnZ1YDv8dywvS4E1Xpc4aaUlAmYiZx6
         smuejsSYF4Q2Z7LSbFfiOiNMIcqAJxFfFWcV781miof/O/ESOjhJnY3UEUlJlWwyudDX
         NcXcbW2M0m8PRzWq9RlYQI35TcRPB/Vn1GBMF3dhTmNTAB5Dgy/ByenrrJnKIJypQiEm
         nTO2llcZz7wi+FqioBxTtZFjetzdZYfT5O6KsbZEKGyX21HxV8kcG4lAPNsBxsmpWnjs
         iWOuL+o7GgWGMDIVWvCfQ8oaGKnW77+YlAhk5MLw5QmIHER+TP8990ed3anP8BmEY8ZJ
         oXYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Mfzb9nOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=EwM84gmT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338044; x=1757942844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=miDLkXi7uvpEoVBXuSjQgty4CQEyTzFV9qHcRFV8tJY=;
        b=CFlbPJnX/VDMNbaGNzb8n20BzhyxgN/nYLFHSztY1igtBbA4lo5qdYrKH9nJwWO42h
         RcaEKsO515nUlSia23jAJytt4XPIHPNlPaTFjLAOTJif5oXCjWWBcUGwMge0tqNWV5Bi
         GasLyAFztXK6F7FppqZ3liWKvzGNcTmCu7YXoEiAwkAVdWaDF5/Ov8NNUzAcvZP26gU+
         y1ZmzbgMQL8HWDqXmvt+0n2L3IOvq+WxbzjMA1A4cgo9d/fA0x8tnXEIA+dARiciNFJR
         4b6ub9tZLi1bgvIiuku8SxXzWYc5pt0L36X6wyDwjy4kA8caxkQ3gvxwiQeFdCmOdQ+U
         XZNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338044; x=1757942844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=miDLkXi7uvpEoVBXuSjQgty4CQEyTzFV9qHcRFV8tJY=;
        b=EIMpn0s7d0onq6YF1oJVxcPmjp02MtH3qSa8wDI99T6+JhimM0cXDtU+t31raWsCgf
         sAtmH+h3emSa8d8UedhsvHYLOMsshvGMUcXeqKfPj0GYfaqPQkmyL6ltL0FqhwnlTfDe
         9Ae8PNzZ7d9dONvOI4hGMcU2FRTKG84+6GiUONpl0P+DET15y3YZnPykuvbxzVGprk6S
         oKEEbC80rTrfktIplHq4vDUxKbOkkwHnm9cbeFUfYvgLDnrKXm8zUB3sfXRkN3scfffr
         yMGRNCtbzGEGQR8MArT380BkTdV7WScK2Busus11VdXFqTOr5KjSdmB8TfZyTzdoV/Pf
         9SYA==
X-Forwarded-Encrypted: i=3; AJvYcCVRLnuYGhLSxVueV1VJLK2o/QdGoObChjiMFj7j0Edl619rg80uFTNti1RweNbBFwogxgUhCw==@lfdr.de
X-Gm-Message-State: AOJu0Yy/tz4imFBQHvmbZSRrttOq0jP4Oqhws3boIDRcnlbv3HKYy+PV
	JVRTABKZ/gmErHZLBad5hYNqCaAhq/LDfNKKSZj2+MQFq4K0q6Qz6FTG
X-Google-Smtp-Source: AGHT+IFy8NU1OYL4XehhuddmAks+Y9J1kECDD2z1EOV2zggp7EGYSGuQHO3ZuAuOkM+g/uRvmG9zkQ==
X-Received: by 2002:a05:6870:b4a7:b0:31a:eb87:75b8 with SMTP id 586e51a60fabf-32265243396mr3613691fac.37.1757338044530;
        Mon, 08 Sep 2025 06:27:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc1fG8fmoWOvY/wXHk3rSEW3DgemWErP7WDv+3xE2abHg==
Received: by 2002:a05:6870:d2d7:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-321271fbd48ls2414527fac.1.-pod-prod-05-us; Mon, 08 Sep 2025
 06:27:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW7kAVace47zPybRqdmwvUaWQC/4dqnpCKsxkQ/jF7XvM0dbmpfNundqZGqg6O5j9oV2G50cfBbpnQ=@googlegroups.com
X-Received: by 2002:a05:6870:b4a7:b0:31a:eb87:75b8 with SMTP id 586e51a60fabf-32265243396mr3613665fac.37.1757338043532;
        Mon, 08 Sep 2025 06:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338043; cv=pass;
        d=google.com; s=arc-20240605;
        b=EcWh1CtS6EdlSOxP7c2oycR41nJMWdNxnfRSCvBaZuBZd7jWsSK4yQtD5TAXVYd+wP
         9FHsW6dR5VrIod2hER/P2vREsOy4n1Y5awUw2RmYd2/mCObsVRJlVIBRYY7szFxmyFxO
         wtaY0aQ6ObpkYAAKIN3xhC3tJ84ce8eBsULlNy98YJ2B4cy8Ufs2dN4cnhyCf6aq+NE8
         lcQHTWcDQX0ysYs/VK1rdYrdMVylu3Ln8LajOxchH1++G0m9U+O7i43DlvdbQgZLsyc2
         OMX1UNtcSJcONWp/ucpHCN1UdINGYAXU4DXGYG/U2wQL3wzlwuvf29m8eMUgeytmvyFm
         G/Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=HMzv8XKugGqGn7qgeMMGiS/LXBlIBe/qFbulT9QUnME=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=BwH0A4m7UVyJ0vV6th5h5fSSQNRwN8vfbtxp0tDjk4BslfY9NUbqm6gQrubiVe0Mkb
         4WoePxSU2tX+R5KrBrStoSIrbN+ZcnGRoU+Hl8Zp6NYcLQQxiX2RTZwGs2mEbgWSpD3/
         t/9CN0z5Cc23DnpvPNC9H0vVAHWBcC+7hqUbIcE+8w7PD4CvPiEFT616niXagLeCa07t
         N6qa09sOA/EGcfcoM0rcYZ2pL1wu+gFCIJHaDhct4xd4vfUBbxxRhaOaKF/daLwoZFzk
         t5+pSqaoQd8y54STiIxQXWK1SRy+BUEeyy28IFB9Ijlee0wPa5ybG1msbon1oJnOi4il
         VoPA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Mfzb9nOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=EwM84gmT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-319b588ce55si733838fac.1.2025.09.08.06.27.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 06:27:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588D0mHj005766;
	Mon, 8 Sep 2025 13:27:22 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491y4br4ek-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:27:22 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588D3hAe002807;
	Mon, 8 Sep 2025 13:27:21 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2080.outbound.protection.outlook.com [40.107.243.80])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdepx7y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:27:21 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZknDdWkHCI/v8TE7ygXChUBLu0LmLvtGv8UD1kaxncY4pGrRdixGSztGYqh5pUoGf+0hye0Wfdf97fLZrl9rtWMzwssfuk1QwrH/zrh/IsRgG06XMkES0zuTZoJpgD59gCGKYJG/tIUHXnSfxYQtVddiUkYjHX384D2Cl/roOZV9mF2lZFIY8fmRoDwXyJvgK0BhNb5vOjTtysyliMWTYkYzmGqAPDnsu6SBxQpzsoRXIb3DYOFI4TGdy1A05mUV7osLHQVOjLOHTwcNg7OIiFo5FoBrOcT/LD7d72uTUZff8YRpVCHbKkJz3KDTiaLv7q389L7uLtcPcj8w9/doEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HMzv8XKugGqGn7qgeMMGiS/LXBlIBe/qFbulT9QUnME=;
 b=Flez2/lkt0YpQSTdzssm/2RtWmhRLkpHuzH+XC2RGVdggcE6e6YnCbkhwq5WLeRho8y/t5C6hha16qJDHa5F2j/ZIJoxn+goErsPrGQMtRzY5mpVo+FtfcB5TzrqxpiB3idzsMuLD8GT+V28+iTTxyGvWOZIiP3dTixEi9Sa0QRzNxCKdcQeE6dAyyJKPPxfx+1s1keJwik//WqfAlnUhpbZQVWBu9ivyZzqedyd/C+7F1yHtsc8uE8rKYbDo3/0A3d2Fh1y8unj3Omdk9YnltA8WieMczlWpS/ZZDLtSOahsUUNcNl+N5GCs9ckvlNGyTxfMHzehTOYGf1htsGdWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by MW4PR10MB5726.namprd10.prod.outlook.com (2603:10b6:303:18c::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 13:27:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 13:27:14 +0000
Date: Mon, 8 Sep 2025 14:27:12 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 08/16] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <f819a3b8-7040-44fd-b1ae-f273d702eb5b@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <895d7744c693aa8744fd08e0098d16332dfb359c.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908130015.GZ616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908130015.GZ616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0408.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:189::17) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|MW4PR10MB5726:EE_
X-MS-Office365-Filtering-Correlation-Id: 133c933a-03fa-40db-626f-08ddeedb6c5d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?5atIs2s3CNJWBTOblvDPmJ56TI0R20/ETWyGkaeqdkqjD4IVEPJn8+ZI1ZBJ?=
 =?us-ascii?Q?kApKoX2GpruLkMuOUmVoPjsdyMW6J8/ouXr1FMGbXJ6U2V2j7xYXzJjO4Fr5?=
 =?us-ascii?Q?FbB+a6Sb4Ss6Z0cnzINNZotF+sLgIyXQ+sbs+jbCYoAp7laLowK/OrLgkb2l?=
 =?us-ascii?Q?S3HCssz9HTXKAAw8Jq4xAhwX/BDwz0joFNKHI4FViIPEkotAZPDvokOVMKzQ?=
 =?us-ascii?Q?aGNEhU4oOW30KAXEedarnCePxNc8E002tq5Ox0QFP1o4ow6xNyOIgokFJyo4?=
 =?us-ascii?Q?rjEg95PGVn8LSp38YTay0NeXHqf4l77cqi3EIQtX1wBG142XpIdqIQXMWmSO?=
 =?us-ascii?Q?bNoEN+CCIw4JTKU/w+a1Sjx28n30xMi6RLskW/nTbE8VfIMj+tkK7aZLtqLY?=
 =?us-ascii?Q?fow6QibJd5ZGMayifSg2fVqRZ7UyKtLhQu5LeCLxwRijf0MIVeFxZXkHLq24?=
 =?us-ascii?Q?kAbPFiriei2nzSlGOB9wsNnu8wjMq8SNh1bF5+77E6SwDUPB/jk0FW8GRPDF?=
 =?us-ascii?Q?MuRu3sVJIjoYWrdQEO301rh2rVVsD2j5SRob6nbNuZdlwrLRH0u3r+TpKIEz?=
 =?us-ascii?Q?zG5TuglwgbHTPrSQCP2Jcl45kb+kLGTi//uCJIdeQpfAeeUL5KiRVe+hUfcU?=
 =?us-ascii?Q?kPlEqFQoxkA8tX/QjBHKqcqRWGjluE/+TPYoadNlqRkAKpZ0hA1YEG5kDckQ?=
 =?us-ascii?Q?Aa5yH7sQXKnF5J3/i6OXTNfbnsZwFFxuOooFr+9ReKm/SfydtMXXF/kJgczC?=
 =?us-ascii?Q?gqnmlXp/hwyS5MLdO9UJGAgoAwwsUQ/R8iAmh/xfDdqjuVb9on3R7p7JJKhg?=
 =?us-ascii?Q?syE7IjEd+SBdLFAXkSJfMh3pu8TYMX7sJR9SEngrnX1SpzdqA318aT+9LuFC?=
 =?us-ascii?Q?DxJbWv5V6R0aYt2aL53499PN7oHNV74NwHnrPrjS2Q+JaCrWHwzVP6aKHkJy?=
 =?us-ascii?Q?+UEX5VJyWq7KiyMMy+76SxppdlimkreCbEtzgZQQ8Zp3My1Ar5jXAc6aO31J?=
 =?us-ascii?Q?BJpvI7HoYJ2KZ7F/NHfhI9Z16oYTKgGRTKi7bFurzOBUe5LewuFyIEHjgzlI?=
 =?us-ascii?Q?iWaS0f9C82AYiqWbmMPKaT9Y1hTXKHfCfIdEF4ZzAIoFP17XIcD3jpsTMD7l?=
 =?us-ascii?Q?SRr+mSQjzchwjsKFiNrGY/6OOTGEfkqMgJ6JZEFKl/I+7h2QflD200n9XdfI?=
 =?us-ascii?Q?OCfFlnOJUyFIAfM1AMVK/mg0TzFPmOJdWmC/Iqu6Bts/rJzp6QJdNmW+F1Xs?=
 =?us-ascii?Q?oLjiVV7gl04jiuqwhVRzPxp/aakCfYvP8I4MC+Wj1d42Q0AmL5y0klzSHbdb?=
 =?us-ascii?Q?4Od+3UpqEi2EjbSyfEmxzPbXVQmw8tKO877xh+xlzdDYJy+sOmAd142CZ79k?=
 =?us-ascii?Q?4uI6VA5Jz9SixKlRCA0pcTlvIkHXozFS+ii0vqzh15GjLlUgnxJ06jKrhm9B?=
 =?us-ascii?Q?H0ewjVuu6uY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uLacIjlNwHbxTnYzbsKp1HEo0xmQVDajU4i3Kk1RJtDvOP9H+1EuW2zImK1e?=
 =?us-ascii?Q?mJxX4XqUEBfwMCHjBBw41azGUXPwqbjbS2f6p6Lvbps377szverU4RZoj1AW?=
 =?us-ascii?Q?sY4sMHR4Enq9Bidsw9ckZQ8eKWqu5zGT6iIgqSQJYmXG85GloZwKaV1hhBEc?=
 =?us-ascii?Q?upE/4DOLx78pT8TNs/t2g0Fl51ah/22yH5q1MdlNOXelpQLwfKj0hTwVz3w3?=
 =?us-ascii?Q?GrjcaIoiT5DVPt/qdYSpvo4P/duwLlH2vDTk5glusTaaCrwA7MSllIeUgu4U?=
 =?us-ascii?Q?BUApEgD3UFbGnByfwpieC782vVqmosD78f0/4LwLLi/WJ9X3jn770Y+qInFD?=
 =?us-ascii?Q?pSWrhlJvs89tgESDKlvOoG+f+ASMJQlx4RupTNLxS1mDlwk1bNi7aOHmlNBb?=
 =?us-ascii?Q?qoSx0HgOhGopZBJBJ5RjCHjpYcwxmh/8htDTGkzEoXlOlBIoMt2nG3RHkLsM?=
 =?us-ascii?Q?kf8sDFawBWe/AtbyAvI64O9olgpNHz3BzWFt7kLG75Xr2WmDlvImd5+Rtjmk?=
 =?us-ascii?Q?xVXjRPP53wdQ+hGjTFP/Ie4UYA/OPs1IK8PVsNQNSG9K27O25ZO9bPKOKqsz?=
 =?us-ascii?Q?rm2eCIyZZnrLzoXZDcF7v+V8xwsx0qBghgHxfOE0tOGzNKXsoFwSOU0FwLU0?=
 =?us-ascii?Q?TI0NYmgAey4eMC94fDNX/t1gfWELhiYzABok3EZ5PXXdKyB59Sq0bK7PDUwN?=
 =?us-ascii?Q?84QznrHIMnUHD25HVU8KFid4PvB7ZkPvcAAUFm1pB4tsVAGmi+KKdPBCE1aS?=
 =?us-ascii?Q?jGhGoehiyoLhRHYEsJ3bxT/cyk08e2LGdi0yO05cJ84yPd/24zvuRrZTKTni?=
 =?us-ascii?Q?rzdTIhLOQuq7f94XT2zypR2gZhzOkqgO3ncnd2XUPbY3drge0aTLb/qaZeIh?=
 =?us-ascii?Q?hycnUaBzDSMmZB0/zsPYayhmpiUgn9cSP3WmKlkUAVEPmPEgwM3zh886WBu3?=
 =?us-ascii?Q?dh3IMxirfL/l/JGu/iXzSfRWGu7yPSLWKkeJyINgbN+11WME8W43N0Gl1iZk?=
 =?us-ascii?Q?d5QjDK6p6OUlywf3ItFDjDAfVKqimU9H167+aICvFZe1+fBGH0AQ0jlgh2FX?=
 =?us-ascii?Q?KPNze3v5Iu1U3B/0QSZRsD7dEPoKqQ4+Ys0NnfD7kyZYHRyh9ITxwozHexqI?=
 =?us-ascii?Q?GMNy8LDmVBR+lLmlzp5HoBFIraIQpqzQc4U1BHgFZCd4vo3aJkRcvXxii7aL?=
 =?us-ascii?Q?DXHWgPuZYmreQtg4v2kndx1uIBlET1KExxwf7YYzi+HzU8f/r6fc3WMe0qZI?=
 =?us-ascii?Q?Nke3BGCkqevD13I6G3RIHRqK9fcv4YetQnsrdgg2omt4cTCsItqju+llxrBy?=
 =?us-ascii?Q?LzvFE+euHxb1F2r3Vf70SCJc8Vxx3CCEnN1eczDdQ747Gdsuaq9kUC/Yvy9p?=
 =?us-ascii?Q?mPDtqaApzKTzM72DMJLJbCvICXNlGIAwRrY7RlM6pgEI0VFZ7DkK9iJhMKGG?=
 =?us-ascii?Q?/gboHc8zS3gmlPZxKL5QECbIrZk1C3KT9E7PyPkt+rVBmHFisiuNuWZCSlQL?=
 =?us-ascii?Q?NhjYHRvMk4OhH+9FRsvYylA8s8StivHQbiCdp9Zo6H3n0n41v4cbhKrO7vNW?=
 =?us-ascii?Q?zt/7yVp62NfeOD5pFNXjMirKSN3SNKXIclqSNR01v6n59ZgOR+ZGBVNCuDno?=
 =?us-ascii?Q?sA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Fumda+tCXkZERSOYoBFgUmGBAeHRJpCU+Vi97K2AymnCnODuaE9OGjR8/vg/zHmRnnF21CwLz1jgUAHo1QUIRHE76Oe0SbyhOTns2OERliTfGCWcygFcyefTXOR4J8msw/pwwgN51M4ysjnWlZNo8ISGKavpdpS9weUnchSOEcXk5a4wnXDW/BkKUGL3Bl3js1lmNVo80dfydUQYPG6zrBTZzG+e6ehFwCU8XvMOD6Qnp0g4RxFIt8fnwj5bLA0uQJkrIE04CURTJkqCtVvgjpfj6kGYEAhosDBHJnurt8axIE9f5WHQ6/OLQaCG97zgsraVXTuXXtzpinx1JBOn4V3LIFPSQfhrZdfk8EbcOKiT5N0xvoIEe/XbhvvPoC3u/If6RkfyOhefC3FGdNIMoz2WAtiN4VXtHtomU7nug4JYNXZUsmPeiFVry1sE7waITtEIlcxitjqYpv1YezN5So9iP8LmG1k8a9bh3vn/JDRo1DD0+nhEaodBwrXD9vBg0w48TZKDE9SK0HXHCZBOzhhz1H3J8v4Eyiu3EEvjReb3q/Rfzejmw8/7DI+zl4WiTZAFzCOeZZMFBGIVI9hWBEjyg2S9MtTM8o0jc2Kwq2M=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 133c933a-03fa-40db-626f-08ddeedb6c5d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:27:14.0547
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: byW/WQKWZQz5xUB5GaGBJLpm5ACIZ0WfKIZMqfgEQE0ENbXxxX/tlZdSp1aWgrtTdT0inpWI83boLqNHnfvG8I1LrZW9ny0NcUBwcGny9mo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR10MB5726
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=848 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080134
X-Proofpoint-ORIG-GUID: crFYxNw2gteMeQTxNeQNATKoMNMymI7d
X-Authority-Analysis: v=2.4 cv=ILACChvG c=1 sm=1 tr=0 ts=68bed9ba b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=RxYD6jakDeLc3v1POJUA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDEyNCBTYWx0ZWRfX3d6PSVsC1dDY
 KZ2hPUckDDpYgYOrOXWJQFo4GnnQj1J0UJQiSv/vTLWCgXS7lBCLeG7b5CgMeGZqLoxQfzIxlIk
 txOO69NgezqDBfBQIkwleqQgtM09urb7687qEDdFyd3reuiAWhSQ/O4+mFpMnDVzV9hpS+ix8d1
 CnnCgM2DWwYXcFqZgkpDzMBZuzC4i2p79KpqGfM/PtsH4PND0tgz/iXRSe4Ns3MT7OlORE7OM+o
 34T2QH3LIgcb+78Ms+w2/4QiZlJZTrEpnKTvokD9/xHY5MB/ukUJGkPQit6BmC2G25bTMARASOt
 qWCHkf89g9nwzWpG136X0kGVwsuVtg2fN9ZohiSPPrUil/Gi2Ch96wVlCDNiF2zgEkd/a3zKwMO
 1ZORL5vnQx44KTmdZ2y5dKimlb32HQ==
X-Proofpoint-GUID: crFYxNw2gteMeQTxNeQNATKoMNMymI7d
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Mfzb9nOe;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=EwM84gmT;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 10:00:15AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 12:10:39PM +0100, Lorenzo Stoakes wrote:
> > remap_pfn_range_prepare() will set the cow vma->vm_pgoff if necessary, so
> > it must be supplied with a correct PFN to do so. If the caller must hold
> > locks to be able to do this, those locks should be held across the
> > operation, and mmap_abort() should be provided to revoke the lock should an
> > error arise.
>
> It seems very strange to me that callers have to provide locks.
>
> Today once mmap is called the vma priv should be allocated and access
> to the PFN is allowed - access doesn't stop until the priv is
> destroyed.
>
> So whatever refcounting the driver must do to protect PFN must already
> be in place and driven by the vma priv.
>
> When split I'd expect the same thing the prepare should obtain the vma
> priv and that locks the pfn. On complete the already affiliated PFN is
> mapped to PTEs.
>
> Why would any driver need a lock held to complete?


In general, again we're splitting an operation that didn't used to be split.

A hook implementor may need to hold the lock in order to stabilise whatever
is required to be stabilisesd across the two (of course, with careful
consideration of the fact we're doing stuff between the two!)

It's not only remap that is a concern here, people do all kinds of weird
and wonderful things in .mmap(), sometimes in combination with remap.

This is what makes this so fun to try to change ;)

An implementor may also update state somehow which would need to be altered
should the operation fail, again something that would not have needed to be
considered previously, as it was all done in one.

>
> Arguably we should store the remap pfn in the desc and just make
> complete a fully generic helper that fills the PTEs from the prepared
> desc.

That's an interesting take actually.

Though I don't thik we can _always_ do that, as drivers again do weird and
wonderful things and we need to have maximum flexibility here.

But we could have a generic function that could speed some things up here,
and have that assume desc->mmap_context contains the PFN.

You can see patch 12/16 for an example of mmap_abort in action.

I also wonder if we should add remap_pfn_range_prepare_nocow() - which can
assert !is_cow_mapping(desc->vm_flags) - and then that self-documents the
cases where we don't actually need the PFN on prepare (this is only for the
hideous vm_pgoff hack for arches without special page table flag).

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f819a3b8-7040-44fd-b1ae-f273d702eb5b%40lucifer.local.
