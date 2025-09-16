Return-Path: <kasan-dev+bncBD6LBUWO5UMBBO57U3DAMGQEXZWR7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 46E5FB59F59
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:34:53 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7760b6b7235sf4292920b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:34:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758044091; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nf64xQbFBvKy07hAhuZLaP26lze/p/W2TDOgTuxtwQQ0a8D7lYEoTbBqadZoHfptfj
         TD6ahdrur93wRgP6e5qeWJAWwUS9jsw0WvZb0FbTpPqVfCjmo8v98Fbj8qOiK461em/N
         owQmFsmjkUHUIBimo1fcOOxnwWQGRCs47jA+T9MOnbAYshweWmbbK7R8aBq14mngj4sL
         r/Apbv8rtVYQGNpeNfqMUvKvXY3sSplSdiLwXNG6vHnTAJrfp54lMnqIQgXes082x+aT
         Kw91TDIxlGGDzl1TjNg0XLBqSVBbD+jqEbgyb6kqhFYJLr0bDm0suPvASmRUe56ZqIyK
         mymA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9aWY0upbaXvRBpepvCwIHlKeVCjchGK7Qehy7Y6GDgA=;
        fh=ud0UdLlith507pxcMEEjTFpYBLaZrvP+nj+awyGBewo=;
        b=dNGC7FdCFRrnCInUgv+UySECU80mhV3qescLfGifTnCunow/w3imfv1OQSamWEE3cz
         vJYKr+SE+2nMqXBS7pAC0yQ1RaCY19EDhn/n75VmC7Biy5anHQflKW86SnFLo73CcOwZ
         9EGwJVUasqBgUCtFcPERc5EzuPLi4owmMwg+nAaad+GnTuNgmEYf8CCjU2qjhTjpaKom
         LAP0ahsWhp9EhWD3jLXS/TluCwO0rz0uPzWp4zpOWL+rE2tA3+yNvbc9qcJ2LbDMaCov
         q3hbud7RN4jNLdMtnY4hJARXfWpzz97aELcWCAfZONwtqljGiC041fPPzmbM9zE/h/vm
         bITg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cRSLDayP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=RReHtjdz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758044091; x=1758648891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9aWY0upbaXvRBpepvCwIHlKeVCjchGK7Qehy7Y6GDgA=;
        b=he8MLSz0EdYIS9k40ubQ5N1c0NVch6F8ZfgNafiJ+wpCR4KWvVyWQRO2DtFil+7hsJ
         fIctiJWjictzpTlLA/NDtJyVK2EJ86hlSKl5uGw0ECPo9an7Opzvj02+ch27zAA60pNh
         r6+tZUcTGi6CY/U9nP+3YcBZJ0FNMAT4oBzy+EWrc5Lpb00CMEPIpK02Cfzl5ReVL6lo
         3us9zjxzxb/9DoeYNxlSPmu5mRXy2Ph7EZZqqlmWsXVXSDzGylhZRJvcI44IwMncZnxB
         zMaKRwTWiFhzCzcP+W19BT8BYdQAMJwiIYFQDRCgjwaopfZFBOLzlaViua8wgpnh/cct
         2yfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758044091; x=1758648891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9aWY0upbaXvRBpepvCwIHlKeVCjchGK7Qehy7Y6GDgA=;
        b=eumT40ekIfQX0cSdXuEnK8uln3gt56b/p5Jhsvb+FQBHszUpBlTbA5O8J+/vwZSVnC
         OH2+Kur82p+4eTcAsMvMABat8cl3halK5a1BKO0imG8wNQoD0Q5X4bEIHMNMyZx/crPK
         5k6Q9cUaHUIUFpMY8CqgyZuWOOnhPr9yvTYOF+GR2CTfbDbWoZXwVwFLygCoHFvGkJeu
         mKt099lqETf3F9Tw8bvAp7xp5divMGdlstZP1iW7PnDzWSa79EXI/wbzGuTsfta76Sp7
         HBNL0Us4v1YOzvLwlnhl06CIA81iNjPPOM8zweOOKXLUfA6Ra3BAIHcLVmooctRBzwKH
         ktTA==
X-Forwarded-Encrypted: i=3; AJvYcCU6bOax8qHrcizCsBRHCrs7fBiaLIzPBQa72oHwtn/S7HiEi5Hxn2gvhENhza0EnNH2Ot5ztg==@lfdr.de
X-Gm-Message-State: AOJu0YzYLkcwRB9r1drae91qlcNGzXjFPNX8Jo7uGhjrZLDJWEoSN1Kz
	DCFkKsbJjEOu/ZfmkQdH/ZZms7WPtrtb3FaBSv0D4z6AmTxr+LIgwKwE
X-Google-Smtp-Source: AGHT+IFBKnFaXH+vOoWDGzV50NNK4vyQj2QpazsATG5Y/wDJkdMAkNEIEu5KbXwHdfXPBGmrmSsQdg==
X-Received: by 2002:a05:6a20:2449:b0:252:f0b6:bd8 with SMTP id adf61e73a8af0-2602c240d9emr24140835637.36.1758044091493;
        Tue, 16 Sep 2025 10:34:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7ifbMyVtvgGKFCvSZ682ECgWxV15tFdz2ZXf8Frg6Uug==
Received: by 2002:a05:6a00:e14:b0:772:437d:60ca with SMTP id
 d2e1a72fcca58-77615879eabls6122809b3a.0.-pod-prod-01-us; Tue, 16 Sep 2025
 10:34:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVktTxvMskk/70ZCfdyeJkXWhpI2arwgJB8ws7ZpFMZSu5tB82+M4uab6AvH51yo67wpEpSEg4uxCg=@googlegroups.com
X-Received: by 2002:a05:6a20:2583:b0:24e:7336:dac2 with SMTP id adf61e73a8af0-2602c14ca4dmr22604032637.29.1758044089907;
        Tue, 16 Sep 2025 10:34:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758044089; cv=pass;
        d=google.com; s=arc-20240605;
        b=MLbaOc6n8OL/EqeBimXWNZbuN4LfQlgI6MMF0EsbovmLITMKkrxFu6wWePOLNIS0A5
         UiB8K+gtjY3/GHc7FU6ajXW19elpE0yebLdOG/Zs/vqsQZHdEi11Oxu3LcMEc+KS5tJ1
         kkfBNwot3ntZGJ1vbLLlITjJ6eGnkGzfxmgKtAcvcz341Q3MVWSGb24+YiGzkCNjgJ3a
         /HH8mFVEDaQUHbbnq1iXZwjtn7Ua8rcxN8MUHKAouQBBCERLTLcRo3ltRkCM2hxQg7Bj
         9EVUr+tXtYywORHfiWpM6897shAkx3exuKZq/tlPtIismbQa+PRPWLpv5jtP/V9byXdz
         jOpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=McApbIJyk7JoTiNouCo3jTLW2l1hz95cZ0yj5iWkaOE=;
        fh=xUviwb3uuLvfmo/fIFWQyuSDmRei/NnmmsQXdNNNLAY=;
        b=lDGrwFfFoivXL4mjpMTM7j3itYqna4Gacq6JjXY5dTxj/6A/VtvorjTY5wgu3YfjbZ
         UrSDPZDLjMRXAkdbWG7q3KQR7OEPRaj6Hrlh7c6HeM4enRpVGhbdk/y+lj6E753nG7AT
         OuiYoUad3U7tUJD6ZYN2HPtgUIBWagGkHOsARolgbcHvZof7RZye/pFXau0i5RuCCTns
         JUrBxedtFKjyMNnL3AHjDz6L/g+k7cPAgThVopPoLnFG3V9zDZv+QGiCTT5aHuQaP9lV
         Z0V7C6+4200sSi7sZmS7MNifSeB+YTUSlv5sxOF38ooiySOudWyAY5wOasfLGVZ7/Uzm
         bXVQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cRSLDayP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=RReHtjdz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b54a386bcdcsi567571a12.4.2025.09.16.10.34.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 10:34:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GGNIPU025405;
	Tue, 16 Sep 2025 17:34:33 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49515v54v0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 17:34:33 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GGcgbq036763;
	Tue, 16 Sep 2025 17:34:31 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010006.outbound.protection.outlook.com [52.101.85.6])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2cqufn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 17:34:31 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tkNdtYYaHlQ/iES5CPLbmS+xwWOwoTebid9TgzS3i8VJv3X+lCKk288MUZEToEVSc+aQmjR07Uvlwe+NtgoI2NZ9UHFFgmpKxL3hJyF7J0YKO1P9WOJAZkBgYhKE1B75LxNQyh3k/crdzCIzG061czjemSeog8KI96t31BuFtOrHyy90Zt+fOFhjxbJAmFBW5KV6cbCxNx99yb9AymWF5r4yWFWsK5b4uMO2AIYEsTQtkcuACnBLxkZo7fbCZjjo+NiYCMuXXcIHckf6QK21zymjvAVeSHC5Y1Vu9fDCpBJSs4I6DGwFe0emtmw2QckLhghXJ1VVZwGKctYSjaIyWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=McApbIJyk7JoTiNouCo3jTLW2l1hz95cZ0yj5iWkaOE=;
 b=vqaMcn3m1p5GzXVfw/ttUzX8drlKIoohNqiA+ZuAGcT9J9ieALu/Hx5WtcQ6sLXAxS4ErXzSE59Xw2VR1NqKGucZtOKFxBwzDOJPXuEZ0Au7f5Ph16zSTz9hW5/55nwYL0BnFEspaiI8ElYERPjOQ8O04c/yYduk2u4b3CNoX14/5LnbxQ6031vV7wZnPosrUeLb8puA7GDI/1bimqvbxJadwtWJJuq+JwF01c0Jw5ok1ZJuN4WUquCl5vG5+mZIRz1sP5S6SglLN2FnqjhiNJeNmjc94X0/o8TbWgfgV+KXqU4VtDqUFtNNarcE4gykpGKqp2hWztxT92ypsVYaDw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB6474.namprd10.prod.outlook.com (2603:10b6:806:2a1::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.23; Tue, 16 Sep
 2025 17:34:22 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:34:22 +0000
Date: Tue, 16 Sep 2025 18:34:20 +0100
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
        kasan-dev@googlegroups.com, iommu@lists.linux.dev,
        Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
        Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 07/13] mm: introduce io_remap_pfn_range_[prepare,
 complete]()
Message-ID: <07448a14-68f9-4577-9c00-36f63c1f2e90@lucifer.local>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <3d8f72ece78c1b470382b6a1f12eef0eacd4c068.1758031792.git.lorenzo.stoakes@oracle.com>
 <20250916171930.GP1086830@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250916171930.GP1086830@nvidia.com>
X-ClientProxiedBy: LO4P123CA0302.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:196::19) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB6474:EE_
X-MS-Office365-Filtering-Correlation-Id: 487b859e-1e92-45b9-2dfd-08ddf547464d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?EC3ZOLdcIDN1AUPFORsVz4qP6DsQ0XY6VcurhdegazhGPFtpFGsptPmORc9A?=
 =?us-ascii?Q?vh3z8whPeEHHsXA3mm05NCG/5LhZB4StYkFFoyjQfCoH4D3cupIQyNxfZcSH?=
 =?us-ascii?Q?v0rY1Ibq8w1TK0BbKwcj6lV4s9wM+YMF8Ib5oWTPm3r7kzrb3ycxNFmgb5mL?=
 =?us-ascii?Q?zWYpOixIWxGrn2MLwVDqdpCA/+zdtlJ8z9aI9owRcauz4bXU14eGRSMsu3fD?=
 =?us-ascii?Q?IUoMnCWQUFgcJ+rIuFR1TY4HLXkxTghTSaNFoIu85DeHd8b+RKaNpJhGL2hp?=
 =?us-ascii?Q?xAJ/K7FZGxSmgjAq19SgkY1frChB07zVkSeo9mbSyz2Trq2q6meR7W6Uba+/?=
 =?us-ascii?Q?jiVcmKBP2YD4868ZvOgP9YU9NCIpXQ+duV2SdzsszWgRQpNgbYkRiGSrbgT3?=
 =?us-ascii?Q?k+hppkYEqDEA3LH+PFMWgTpw2iDLdz/y+ayNUtI2qbDVKdjZbcEI3kXB8Mnl?=
 =?us-ascii?Q?PQrepD1+ojK2ckH5k5QD7Qe30+n/iYUGo9+Qfp9Myr+ibUvdOZZ+SdH/IxiL?=
 =?us-ascii?Q?KLYkWhSUdpab3cUBdPxHx76DJsDvk1NpErdxXaSs1oStZ5QqoYLJREMuJU3I?=
 =?us-ascii?Q?hqDLoIsPrPq/zhoUsNyDUxPser2CT/nuQQMiTkEDhrsEE8rVHM/USgT9B/JS?=
 =?us-ascii?Q?RPhD/bPFTn+iU7Wc8mQND9WL/+atzBzgZG6R4l1XVjRijGo4XkVPsX26kwqb?=
 =?us-ascii?Q?cL+MWUfOIKZZ988nV0P79mahLmCDnJ5oCyv6SA9Yl60PSKdYTgGcnymCIGjv?=
 =?us-ascii?Q?LFAKcKYWOhjNKdYTxrqVao6DVyKJsfhsRYnCqlnTDpKI0X+umwUSiiDCULMl?=
 =?us-ascii?Q?47i5b2+QeR5Wo4IQm/LoYLyoZ6BkS5vwlWB3ZAdCPr0SE/xP2Mby5lhF1P53?=
 =?us-ascii?Q?jpbjxODN17BlQPpwnAxfk+OTyBVusurPbn8eqWz8dKfGUal8XxgE+DLMumqo?=
 =?us-ascii?Q?zlvCbSwyeIgIjQpz480/00GFbTw2E37YWDAOW/lhhPJGWgmfLXmtZuUiZ2BQ?=
 =?us-ascii?Q?D7MoOzznw7V/9brc4OKPeVHCJ1PvWyKX5WPKgFlvT+2CTR/fS87Xrima1xR4?=
 =?us-ascii?Q?8DtLL9k+dosU6Hu+I6CAEvCe6SEg+vu+8sgNAti5MxLguI8xaqsjrOOgHsyB?=
 =?us-ascii?Q?yjgF1Qgk2y1gElOLcBwM5SdfKFNdSsMSryR557ksqGHYDoAww+ju5aGzTHEo?=
 =?us-ascii?Q?POJZcWKjVxWCpeikbAIXKgjQrtazbnJpYn46as7WNfmmaZCbR2qQAOU/GYQN?=
 =?us-ascii?Q?cbhB2rbuxyzMw6pflaUBrt2a4CPAVuh+VulWpPPChkNICBnaefiRL/EGIYrv?=
 =?us-ascii?Q?q8FqZ1lw9X4VnnfAXXPOFRJTRBYv460fMMAfbbuWK8eSdJJWM3hGRBjTtph4?=
 =?us-ascii?Q?hTujJmKVhX7Pb1biWzjFd8lYwV7O1PHzdjc9w62BOBLamxltWG/F0LglFVDQ?=
 =?us-ascii?Q?zLg8l4xrqzk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?E1Hvlxc6nE5ghtaC1WdF6Dp6EU3crJnjrVJEqbpN/4dRuxv/DooBqUxxqXQU?=
 =?us-ascii?Q?ZaXydMWTaTMq9ua0Cr1upaO0lp9Pa78rkOvQ3NyvXtJXDQDklXaG5f+WBNRe?=
 =?us-ascii?Q?8rg3sLkImKGFFJ0BKY1n47VoSdaenbJukIM61E5MtKQET3rhk6V6WJEZPdGy?=
 =?us-ascii?Q?6zTQ3wEVuFNeBDqFq8XtmHjj1PDNGRu3HB/WOP6QWf5Gpu19FkpXj+vmYyyk?=
 =?us-ascii?Q?jUjA9c6Ic28cZee9Z6s1B1bu7CIsGoJmhnEQfh0GF2UK61xldus96uGK3jfE?=
 =?us-ascii?Q?K0QyfAUFcwFAHcbsSrGL/gGx2cULPx1+mFLK1RC62pEwCR5f35pyAtUc8B+9?=
 =?us-ascii?Q?c6uWB1+f4N54y1Pd3Qoy31F/Lx4Hy2VJMR9GEEJQPp+nbwAdjH5PCAZOOI6p?=
 =?us-ascii?Q?I/hlFEmqSbQRSOLdta2wEyZ+JaGGMV4B7PsH6spKTWvdveplO82YT4DQOb95?=
 =?us-ascii?Q?n8w29wy1KqVr4C9aS0vPev5jzCTvB3e/0KDcVhtzpyrGPK8AZ910D894CkCR?=
 =?us-ascii?Q?0zK2X6lOGAL/13EhuY9obqmFQfRPpkWGZ/DVqCj6Th2tP5ItxFjglRIfOjnz?=
 =?us-ascii?Q?ZXNMuDH2eb/Mo6jBJE5WNC+aCUvKZPt8hkFkLBgUmk8sfrnakEEYwY+RVFKs?=
 =?us-ascii?Q?1+ePb2gTdz01vEaoiBtUx8YtPengvHFqfQbm4IjOdmvJ4PoEQkx3qKJVBePh?=
 =?us-ascii?Q?cquU7QAnXdqlAMQLmE4j57PKVZMiivnRmjtN4ZGrM1W1qXPwzaCxBK5lwCHO?=
 =?us-ascii?Q?t54u7ihI2EwRoE0Z/XyZKz274BwNsXeTYz+v9qVqZA+WKqM629OYVxDBCfz9?=
 =?us-ascii?Q?AL1yY97miy4jmioA3K480ALyb46WOSD1fyd9YbvKDXbk5x/rZrn+Frj9Up8b?=
 =?us-ascii?Q?3Irczy71j1M+n5nMcoqG5swVUhxewOLrTZNAhFanO0OsDmobRA2TXhtLjVQN?=
 =?us-ascii?Q?rVDhvqZS4qJQpA/bJu+eyw3mru4s++yJ3bXsKBWzrlSGcJEwqf43EtxeJyPO?=
 =?us-ascii?Q?ZjGkzDwLzHquucSPjGYxiip47lVNJha9Qi4dL+oM996CwayaCuVuuJZnlSNX?=
 =?us-ascii?Q?TUXHgapOY176PU+pNW0Bj/fKwUVa4iOcZ3eQ4upfSmshv9BWvEF+rY9wpxMS?=
 =?us-ascii?Q?O35r2XCfe7W6vIzZKyaCK+LUe4+/bA9L3GKwiFHfdlPYXEgVJQ7h/dA6/NcR?=
 =?us-ascii?Q?889Vnsowg5ruyu3QErC05JDKI3THpAaE9qzZbJeLqp9kXnfSNVpd55Ydr68G?=
 =?us-ascii?Q?qEx2XJv1hG7Afg7xNbtMBvtrS1jaz/ScwJxtOQ3rX67+Hgu86xFUl55edMTz?=
 =?us-ascii?Q?+y214a1z7OYW3qL17uCALwLXICQkd4vltL6F1c+Lxss/SDvx+DXeyR3Aubu9?=
 =?us-ascii?Q?eIeB1fA9/nV7VmQRcUbRUIWoDawrI4Qy2pcqJen20voY7a+E4t4FMo73lfra?=
 =?us-ascii?Q?CyCGseS8WtSXJwtZVHnHAQh21BgdeHdjsP5s7QEpNJu85ytzJ7IHF9xAuNrB?=
 =?us-ascii?Q?G6dBpZPkpOcr6rt1hicEZ2G7HnFWNdgREWjMDudoP8PhqnAc9/rHUfTVNtyy?=
 =?us-ascii?Q?Xgu/+SdgkvHhpaCV3ZzVoxf7CV3wIwUXBrfG8pNwfB5IC5LZwvHKJDzRSSnA?=
 =?us-ascii?Q?zQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 8V8HnWJG+noNB0E2cFocpsxWGpAJFjFJ0slNYfnED9kvMecLKUG3vVM6CXXJ0q3oKWG7okPy+0GphWEfL46g4PYcMyP6U/65xl6xVAqRfx5WRxPm8nWxzxGGdqzKZu0uz2JIgPd5y5c3DTuc1S3MfOtG2SPQrg7xjcipwUtVlT+Zi2j3N3qoJOg/vTKM9CADxPG1+8BvKwKtjesvjK7MX24YQSLffec9YaLHAkpFSCSPohYLGsF6yzWdCM28mNtvGXPJW5teJohQiSqhMcFf5hlaeDT73pQ1so5LpoTAW4QTN7RohQKwNbU2N9+7RX0ooilxaH0IOMJbn0PKnthQ4YUkl3eqKLjge2jgj35SDOjHRZo26HYwTqxKJXP4SyzVyKp+ODwljb7jDZR2At7rLESrnJpKWQ1SmVeNx54FLp7XZF+EG7MfctxpA3uQo/DLZGEIvwtaPleM24Gu44o2tHR9rnx3/oQX/628pgjhCPet1BUy9mmXtIkiOYj0Fxx2AKnlqATj85ow+cSt1Eno310Zuxi0ER+3UYH0DgswH8I0K7LYR7SskmSIejddBOLJDPhF2RrOYcJf3dR0rmKX0xM5jML/YpbA8xxrqmlJYgk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 487b859e-1e92-45b9-2dfd-08ddf547464d
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:34:22.8217
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RbftQxYddvxirrDPm4mNPzsWKfmRTwY4loMJLCAPi+VihB195cJct7hj/h7ktHnsZ4sFCgrB+JW5ozikf7R9MAC1XS+VZ1qpqUOP4I6qXds=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6474
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=938 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509160163
X-Proofpoint-GUID: 8Aq8d2fE8qigvEjkqxvnKTA_79srTI3F
X-Authority-Analysis: v=2.4 cv=RtzFLDmK c=1 sm=1 tr=0 ts=68c99fa9 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=-_BMN9QQeijdksKfcvwA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAzMyBTYWx0ZWRfX5o8UyLZGrpZ6
 HAWDfq3A6S5X2Gczua/xkl0Dp9O6F+NUi9WS5Yo3l7A5Sv2vb3oEa3nV5NM1YG3CdhjN1BE+/P0
 yQDDjGuzG5H9fw7MzYfhhYcEbURXbAo8IRRIC902nABiV2cPzT7wL7wdVqkGztvpsXK+d7oe/dW
 fxpP8zKPRP5hYwbjN5sWR6rtL5X10X1waHw1sRVC3gRSgW5DiROgO2mTjeiw8+RbSsCpEtti4y+
 GfN2weJlIweuoiBnSC8UwBaCeveJ2H+zolud+QU2Bx//KNncJvKEYNzFeZwzWQkR3oY3fgsVmLF
 rYy/ecgS/ZxXkfNudgCZ3BcYQonttUDbbvXiO79d+14AtvNvSr1TKEz/r+rqRlNdkjgT83m4vGX
 BK8dS4PBN0HEMDJxKh4LpO+Tn9PZRQ==
X-Proofpoint-ORIG-GUID: 8Aq8d2fE8qigvEjkqxvnKTA_79srTI3F
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=cRSLDayP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=RReHtjdz;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 16, 2025 at 02:19:30PM -0300, Jason Gunthorpe wrote:
> On Tue, Sep 16, 2025 at 03:11:53PM +0100, Lorenzo Stoakes wrote:
> >
> > -int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
> > -		unsigned long pfn, unsigned long size, pgprot_t prot)
> > +static unsigned long calc_pfn(unsigned long pfn, unsigned long size)
> >  {
> >  	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
> >
> > -	return remap_pfn_range(vma, vaddr, phys_addr >> PAGE_SHIFT, size, prot);
> > +	return phys_addr >> PAGE_SHIFT;
> > +}
>
> Given you changed all of these to add a calc_pfn why not make that
> the arch abstraction?

OK that's reasonable, will do.

>
> static unsigned long arch_io_remap_remap_pfn(unsigned long pfn, unsigned long size)
> {
> ..
> }
> #define arch_io_remap_remap_pfn arch_io_remap_remap_pfn
>
> [..]
>
> #ifndef arch_io_remap_remap_pfn
> static inline unsigned long arch_io_remap_remap_pfn(unsigned long pfn, unsigned long size)
> {
> 	return pfn;
> }
> #endif
>
> static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
> 	unsigned long size)
> {
> 	return remap_pfn_range_prepare(desc, arch_io_remap_remap_pfn(pfn));
> }
>
> etc
>
> Removes alot of the maze here.

Actually nice to restrict what arches can do here also... :)

>
> Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/07448a14-68f9-4577-9c00-36f63c1f2e90%40lucifer.local.
