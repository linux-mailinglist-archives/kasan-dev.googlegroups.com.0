Return-Path: <kasan-dev+bncBD6LBUWO5UMBBVVDYLCQMGQEWYNIR6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 677CCB3A7F5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:28:56 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cce5d0a34sf1391441fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:28:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756402135; cv=pass;
        d=google.com; s=arc-20240605;
        b=OHmaGV2iPnzo1JjSgRE191sBeFDMztbSNnsQBPA1iEmsZO+QS1+iTrZ2JYQB0W3R7d
         4f+Gon+dSUfNLv+8aLd2fjT+9FhWpYzV5zZojFSmnrH7v/tUoJHME1HEPm3ecvMdfU3j
         rLKbh6KQa65Oz2Dmdo5NClxmXOhm1+nagT12uJE3Xp4Tb8mTUkwTLSrT+hDNqlLabx+i
         6hGJGm+mFXzRZFAw+KLVLVLithcDg4OOl2/ygPjCjrDEOLf8RXl2141gVShgslliLBck
         ep1V+lWN8j3lqJkiboNrTrEnWR20WFAWhGqYYSilkHeGNA8JbV+OHOOFrYjPgust9YCa
         BH7g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=cO9gn5lWD7gfC9EXh43gg4mYGd0v2x/QsCIUv5lgjk0=;
        fh=OdWTM6h3QGUyPudW4XK+6RlHmN7TZ1NY5/yY0aRlLh0=;
        b=VQ/XtudK8tXP3e9aGmFcoXvTwYRnWRDvKWmK56vF5e6GjBR7lZRnpWh51Wl0CquDdo
         qzEYAK2Lrp4mkBL8Czfp6fSl2xBmN2c7aIqnFDhraltqGrWm6Eie+xg9zWf4TyMsn6lm
         uo1WeBmGnBITlx04wBAJuEEuqcqUVI1wGnXZCRvRlfCKm1ZEWhK1GeWyBOHk/cMCLU2A
         HwCbfsHKWAWgDTT4WIcJ2bkW55XncCzeFJn3Wa+6k/MhRJDVtd9iXE1TsSBDBGRoxyzm
         Kyfhleqgs9htHe/Q8Gz9kzfOClJHm1OrPuzN5lbLndpGBC/sVhe8OFbWcgBGEJ1p4fIE
         DUyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Aba0JhH6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kDlrqnvj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756402135; x=1757006935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=cO9gn5lWD7gfC9EXh43gg4mYGd0v2x/QsCIUv5lgjk0=;
        b=BhKpnArJLxCIQm6tQHpBoGhUQjiPgBfaDewQzzwz33edf0ud0X49hiaanbqeYrZh93
         CzSV6ZlVoUOgT61F36alGGN8aNQXGn8c3QraV0jQzxOmBKBtaeOkrnWi3G37/B1AOHJI
         AO67ZZu8HJUgpGQlifzwNsI/UL+u+QY4r1r4UIDFa57V/yFeAtlZi5MTbB2+nfPH23Wb
         AFB6qUOlNGYwYua1KaLtBuZPyybGSqw7LBbRUDfWdidnOzxCoDbb4e8TgAxi2fTs9Dya
         NIGvCXcgP+WPpIfGpSCI0cwGs3U8QY9ab1PZ3bOmmcY1/b2UgXsJZPnMYmQcNOKoLvPK
         SzrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756402135; x=1757006935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cO9gn5lWD7gfC9EXh43gg4mYGd0v2x/QsCIUv5lgjk0=;
        b=nFWm5uHZhewJU2dxN54bUBuEdWUwFNh2/uDNjBt+prI9UGdLAEBlbk6EQJo599gjXt
         xRZSDxeStaAG8Q+qLovgSyYneTCsO4sIufeKER6w/AYd3JpLgnQ83OI5Id/IiIa1N2uR
         elHBQl9/d1lzEU/UPwRh8httA5ijlLREB4yxmFTgJ5vDAmG+3oNVnFjQU1NiVLeR9hmL
         fK63hPKqfGWsVujvC3fL0K532JLzySib5TUgWptWTo4eO1S727Xv5umfCHiK8tvBVZaO
         DIaLuXVU7l4m8Ejpm8icJBAaD/1dcfdkPg/rOknmmJha/bAvDHUuDkavkcTXfuXdGXY2
         vFWQ==
X-Forwarded-Encrypted: i=3; AJvYcCUuHsRgCYDYdkiy07NQZ8gbmsk9oGlc0FaV/nolTutWV4n3dISrYhbFXJAbDtcGdpH4c8Pipw==@lfdr.de
X-Gm-Message-State: AOJu0YxS5SFifiOxxCPRo3PlOldVqenX738mnEH3uuWaEynf2IGHl4sq
	WLSjP8zFa07KCHyVGWACgLm+csjDAv5zCw6o6CStBZ9ououXeyOtFZR4
X-Google-Smtp-Source: AGHT+IHTiaAsIPosLBAQcujn7OHQgYJXdjIHc1EeMValxNVW1kF29/emjJCEPXDEWKbvICm1dEiAPA==
X-Received: by 2002:a05:6870:6784:b0:2ff:8e7d:1d9f with SMTP id 586e51a60fabf-314dcc8b1d8mr10727003fac.13.1756402134968;
        Thu, 28 Aug 2025 10:28:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdoZeb/hCSz/n2arlfAWLgmjcyPiqVo3ShruqNXY9jH1A==
Received: by 2002:a05:6871:a1f9:b0:30b:af41:d3a3 with SMTP id
 586e51a60fabf-31595ff10e8ls309825fac.1.-pod-prod-09-us; Thu, 28 Aug 2025
 10:28:53 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUGijS5O0pkihLyZ0z4FDSlcOBiLCPe+PLlyGoCLsSzd9LdsEgov6JfTL8P6/nuqh1oNgZfz5qUVSQ=@googlegroups.com
X-Received: by 2002:a05:6870:ec92:b0:301:eb97:1f7f with SMTP id 586e51a60fabf-314dcc14230mr12268610fac.3.1756402133727;
        Thu, 28 Aug 2025 10:28:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756402133; cv=pass;
        d=google.com; s=arc-20240605;
        b=SJLVAUMFMxpHAh7eacBIDAMxXGOht4GhMRJjb/prAmxKaKtFLmhCSGWGM14SEVrj84
         TZiZs4FkqtSDVVO01UXS1Y8iYxhFCcicuiQQSPI8Yu8x/yrZCMGHlO6p++vgZxNs9t9w
         OP2hYKqdKX8El86HbhcObY0fLg0dRjZiHyrDjY0JzBtUM0K5ux0D6wvGpHRQ2AUUuwgy
         imF63U94lyr7N47uDoRlfpFNeE7ghEe+UwwVFLOotne9vUUpkS4KFDGGIW0u6STxTNhB
         rqoaj/2YANHi5CEOyXp/yRK7sTIqsoG+2Um+ywllyccsIQGwpEivgvdtK+Kny73YOBZY
         /klA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=aBXDY0NTB8rucW4oTjrLu1rphld4LyLS5443kqp4HcI=;
        fh=+xTNNBOamASgnCRT4K1yFqtdeDwWZrhIqy+ukx7GsME=;
        b=LZ9H0nZmpP0FPWXthg8Wqi0gGqUuqLYkYhmQNDo5C0oyYJjal4hJDDdSF6IuBwsevq
         s2Sy22k9N1Ywl9I9QFGpkFyPld/1QwKeNmRDqxO2gVGd3jqS9BA9p+Ax3tcIGLnJX0eK
         mUiwHDs6pi1r5e3lmt50CMXLlpa6NWH1XNSgQa5S+2SSG77LlxVp2Jfc4QnoNut0dHP7
         B0LzgcpDuPaBlEuX4gWZsE0eagv3up8cyie26cM3bAQx/qx74mZ0n8DahZSiY13Xwa6U
         dRahmd2awAR2Vl8svkIO/GbedvGrLTIKKizVDxleDlyWPPXbDQwknukW6HmMdaGp8Clr
         IWxQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Aba0JhH6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kDlrqnvj;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-745582b708dsi573a34.1.2025.08.28.10.28.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:28:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMwQg006641;
	Thu, 28 Aug 2025 17:28:47 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42t8vtj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:28:47 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SGR2Ad014568;
	Thu, 28 Aug 2025 17:28:46 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010030.outbound.protection.outlook.com [52.101.56.30])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c5yk3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:28:46 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EhpaW2SkrbizqQ3DU9miokzxkS0zQrtFExnPR2GR/qG9E2F5ZSGYoIqWKR3l2/OZd6SjHCFf5pvG1p6r9jxboHhwLBd8kaN/I8bw5xqUQwgtO+YJKpmKF4UG3UEDcgItfu8C9d0pW6P2qvDxbsfs7LCjea5XPzHnJeLSFSlxumnBxqnC1E2MZrQWPlEDnEexVw6MJOxLNxRulILmMRxDblJNhWqGTbIWshd7Cayw/dUMf54gWW2zBZA2SgSRSb1tpqsSwSXYIT8Ny0NIWN1X9RMB7z7p0u6mppcZGhu8HT+DeQmKykP7LLqN/S5+z/UumC7bnWMbhFKkKHocdHdCdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aBXDY0NTB8rucW4oTjrLu1rphld4LyLS5443kqp4HcI=;
 b=mSezt8BRUSspp5qNsnIVWJ8DuEvXlVs4QUCT9M5s+kk2qR9ic697spHsmzgOyaRhO7grWfKFXoRyGDXP0wWjzHbIPPuQSniPERX4OVEBHbkAYVDhGfSWZXlxET5PkafCjU+hYByuXqerxtU6d1zIxQuETfh6mZVF9doRPCFD2Qa1J8N/cW+f8qvb+sXJiSOnqippMLeAP+lEwp1QYHQCD2XE5rrH/cI1wgmWKHaFAArx8ttrE/x+D1Ga+RRqfgISfcOHQ5oiT40p4tIcjju6Od8st4syrlwMqznBe+b/47oCN//A/8tf+rcftdEa5oEcKCVRh5QBsCHHLMw8rHA6xQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB6499.namprd10.prod.outlook.com (2603:10b6:806:2a6::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.19; Thu, 28 Aug
 2025 17:28:42 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:28:42 +0000
Date: Thu, 28 Aug 2025 18:28:33 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexandru Elisei <alexandru.elisei@arm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 21/36] mm/cma: refuse handing out non-contiguous page
 ranges
Message-ID: <b772a0c0-6e09-4fa4-a113-fe5adf9c7fe0@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-22-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-22-david@redhat.com>
X-ClientProxiedBy: LO2P265CA0327.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a4::27) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB6499:EE_
X-MS-Office365-Filtering-Correlation-Id: 5408e8aa-2030-4953-b2ec-08dde6585556
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qZKVy86gluGSmp09IVbZXyrpnl4cQLV5IhkRx9jqpoQXwIl3Y0ELdDmPTXiQ?=
 =?us-ascii?Q?1nM90Ak/VbEllpVuMtQ7cNDAHTZQFa+Ex3iDmmyiEYd0VcB38W7Zs6FiB7gq?=
 =?us-ascii?Q?ejgaNNmIWH0WJ+Jmt7XNx/dcCU+fbUyTjsSH8v8GsAgrTyN6eXuzenyqrz6Q?=
 =?us-ascii?Q?0zxNkCJOs+huxA3Rb+Rohl7+JGr5JFGnvNDrvWZCpEgZh/gHYNOXGXocciO0?=
 =?us-ascii?Q?BNFTQNLcA8ephX/eynKVYk5t1M4OALDNdPGTPihbLHn8kg4GCVN2zLLHuDDA?=
 =?us-ascii?Q?mZl9CpfHmlBiW2n5HhNbFn/8rxP9Q3SrpxKklHh3zuQarEvVi9DCGYsJYWKX?=
 =?us-ascii?Q?JGk61tOwl8+oxmfVIvEPeiNU97MHE5rxGYOCyh4R77Aa4ficdgasa5iX77U4?=
 =?us-ascii?Q?I0P7BTnEiC9RstkbPnG1n4giQACzy6ih9siB6rR3gaz5eb2VmfrVD7UBCB/H?=
 =?us-ascii?Q?J5s86sUJpUVStnUI6Yiqv3qHgPWqavYEyPC/j4P7JzJW70XOE9IfcctYSUlJ?=
 =?us-ascii?Q?FcQ8CQWHl43k5l+Q3Nv/Y6JKZD/i6PyfzvBYl58keESjgHhSsVQgAxpCC6+P?=
 =?us-ascii?Q?+EsJRqRHmJeyfTZqKyBNXYDWBc80GVF/xauJ+g9J6b0J+b9Afy9mAYi3IEvC?=
 =?us-ascii?Q?vIrV5x28/crH7ayLvaZ55l/T6V6Sh+EYQ7JMk2kzTgpyQDd1AdgjrM790bZ/?=
 =?us-ascii?Q?WUjX+Wm1wi3bSQuu+5I7egpm9L23fZI70p/lIHUedBUJ1nEOCo0bLsX8tCYs?=
 =?us-ascii?Q?CRUO7nTi2CI0IQRgjtA1qIIH0ZeaHi7EQwGpcT0S9FC45QaudqZu0aHGx/ct?=
 =?us-ascii?Q?SN1JRmI4NL1AIYMt5XpdtmeccEy0MPHBVlyZMCS5Z0eYQqdGLCaYBmFf1pHP?=
 =?us-ascii?Q?mprz3mxuDVZQJWha8s3B3zDBEkJRovcp1MpuOheMFCulWIl0MA3XZsnEViCa?=
 =?us-ascii?Q?05m3ZzQpmdlu9XHWJmKFyup6pCuH3p/wmJ+6rVkZBYNr9DCTe7vS108HoYdE?=
 =?us-ascii?Q?Vqw5p38743ZbW6JcyhRlnrE3ATeGH+A/54kCAnpt4fVtfkWXUW+XcCJ2WXLH?=
 =?us-ascii?Q?Sy2ABIf70IjoqmI/FR0fzfJLML4R5gu4vkBEReN6hurSN+zuuKgxvIenpkVY?=
 =?us-ascii?Q?unC0GhpgWVc22eQArkEeCiCd+TrdGtjUdFI9IQdCT/3D5ug+bspMsJ1cwGL2?=
 =?us-ascii?Q?eCifcQa90L7/Rm1bKDd5rCjwULDJAMeCuVbhchYC5PU8xJLgEYa2LzmsUUgl?=
 =?us-ascii?Q?2EVQmwbGGcZiCCz7AUEOOioIz8Pt4sVBzR4rHNAWJnZeDb7RisWU1GHBMtM+?=
 =?us-ascii?Q?tZ8tLOpAhv8R7u/XNfDEntu7dWHVlOfJSJH5vhS92ltuL6QMZUlnE11W18e3?=
 =?us-ascii?Q?zGGNXTjUZg72IFX4AK09AXJtbXXVlnyPe66A8p5tdzuw9YnhLw=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?UWrySEt+LgWrkMr1yh1iK6qOpDIXAZ7YLhsaQhc9GAES+aC0D02ZXviCbESM?=
 =?us-ascii?Q?GBVZMZBlQ/0UlbOITjYvmTxViHx/HGjSa7sMvvcXN0U+EM9HZ/I3uM7iy5c8?=
 =?us-ascii?Q?O/e1Zv1YQJlOQJrgsLWmGRR7ELgPHzhwMUofzW/FjGq3WY7iPuWYewQjPzOD?=
 =?us-ascii?Q?qF8q/lMc58Jf95Jj8j1ujm3ZBlA6UqqVIvV3srAGZ52bwzRLnttapkDbCHWQ?=
 =?us-ascii?Q?7+hu0560+mH3Fz5M0OcjqmHndWxgEw8GUQZpxHVnPboC4Y5VxV18OI57WYee?=
 =?us-ascii?Q?MtdD5SBO64y7ggU3L8qN91JXdROsYS8/HaT5q42MPoMRT7zpiwXL0rNTWEbs?=
 =?us-ascii?Q?fhQJ5VgDqWmz/kXylWVH+eSW/W1j1F78O/vwibzf9dC4UeH21HEcPTRz2hlI?=
 =?us-ascii?Q?PqJvtBHwOGk/KkcaP1+fCB/fMe0R0OdnzkQIm+RldCNsajhFnwAqWHvilGZq?=
 =?us-ascii?Q?57ZHfMmagxjKH/15p7yeZaVLAcZT1WINAQUQ2YUKyIjo5YNbVQfjzo27DWQt?=
 =?us-ascii?Q?QNso4OABluUh5gNKKRMRwraPIRVCaF/Y4aBGRIdQedJ2VqZ0Ck5tAfaEEK65?=
 =?us-ascii?Q?T26M2UZU1SYH6UWGF8w3YAFmYatZG9MBQ0tFXVX4wfpLgJ0Os8UPAxDaqF1b?=
 =?us-ascii?Q?E8UZ4bi89A0pbuCnym/iURkT15X04zpzX9EYs2HcdMIYO/Iy6/zrmJOCC3Xp?=
 =?us-ascii?Q?dmmVFunD40V/sM36uuB3hU6Q0fns4SMs5YPSIke1c9Rneb2tdN9FbZ66ClPC?=
 =?us-ascii?Q?Z1YSIo7LB8ZqkDhno/n+qwzFhSQxCJ1aWdo92g2yB1/5UZtGiTl6IdJn4Dqq?=
 =?us-ascii?Q?CA1ipvvNCA2k72OqKjAShl6OlES1m7GHk7o7iNuTL7Rs//6GY83QLMlsau1F?=
 =?us-ascii?Q?VnYacefF7dtib1YBgWy7J4CiVmSSuGve7LlhVf4aXfSLtqUCehrkolJt+S3U?=
 =?us-ascii?Q?4K042ltfucrq2K7/wpofAxWFBbUytYZR2il5g2tvkoG4zEx5cLJ6312S0Zf7?=
 =?us-ascii?Q?q9gCkpzi5M2LG9pQdRzbCoY+Egsr0c3SzMlkd2ciZ1J8qUwYTaDmqeNf+MBU?=
 =?us-ascii?Q?RPR2FvLyE/VkhdyEpr8lNz7wAejvgx7gF4WQjGNqNN9oMKd19nOjMahp1sAh?=
 =?us-ascii?Q?ZfzeQysOAI9m8J4avNdKmPYqkmF3UzHHK7nHPnIAWPbI9SZ+v1ES/Rtn920c?=
 =?us-ascii?Q?GDKaTnTKSzcFtEpPr8Rqcudb3ysdJBOugaeyNHqQr3V+gty/Jw403Abdidq3?=
 =?us-ascii?Q?7eDrHOpQ0LrffxCDlb+VMe0JXN7Bjmq0hiDVFBN5m84FrSfAf7M/9DSq3aGB?=
 =?us-ascii?Q?5/6cZhuLjG0rc85NBqTNbZw27u3/iN+9yx2aQrYq0CUhgjBWBNIjzLS2Ml1c?=
 =?us-ascii?Q?GoVZ9TbDqQp/7N99jPYfO823F/4tPuFPPQR9MJc6BrCQ1UiP8gGAD3LL7zhz?=
 =?us-ascii?Q?LCC1sxv6DzEOVtZPYVMTaB20zmSMIPbrSPJUuedBZ59pAOOGudmmN2w/ZVtm?=
 =?us-ascii?Q?2TcFVH7sf5BQ5oYyIry6AJJgCPGob7hYOBpdc9f32tcIt1LjGCAFad03hSTC?=
 =?us-ascii?Q?4flt7OvSFWhPfXlEaV5MCwxrDSeUyXmZngt8fHxsRrJ3RA6OymhXKZccRZmG?=
 =?us-ascii?Q?1w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: JLQ0LKdUmMuyW1mmlq/c4zweu0Kpku3B1JOFNsW7nZAzJPl/v0EKcTgvqanQEgOoy63qpGvwDYNRjqF8Wr+sTiBtkLW1qnIEoj9PAgTnFi1Cz22cAaBrxrXN/mRVQ4lYfY3e7TWTE7byAMhOsFR4nb0S8PzpGwfULERCxv/0c3+H2HMMzEuyp4bujc9usXb0WB2gVdh2xLVHa77SQaPdiJcVC9dyByMHdmPXdaMruOObwb40SkrIanLxsmAe+07nltVc+YxdTmt0jv+KCj1EKdgocmJ2MQj9SM00cpBrTB88FIe0/FWBb93IzQgVANG2QgMRwAVLm6CBRbynfsLcDlSbleSc8jrKQanbAhD5obAlz4+38Kcj9QL7ZHVpTpS8RlOX0tD7BMn6fXaraQ5DcXyEJuXaCuQuIDIgRzxuBXybHV3OSpb1g/GaVuXe4/dOS98wSWRTax4OPd+jAYblpPQNc1XWVjjWgkwBxddJGFGq5CCwdj4oA+aE8Sj7zKUWt30lFG7jF2wz+smODdnlnXryeX1bFrmZE4VGwB95HPhikrCWADYSizTnb/nvsYNIxkjV5nn2fHGUXwMKQ4goj+7weifhCEBIQ8eHdoeSxH0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5408e8aa-2030-4953-b2ec-08dde6585556
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:28:42.1453
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: IO39DEeMh8i5aoXI1XZuRamjwY+UvO5Uyjiyp7Dmce1rR9zcRPuoPXe+OF/fNfTpfvDI6EVAglvQI3DW0b/0GuVd4znA9hdzkUvBr/G6iFc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6499
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 phishscore=0 adultscore=0 spamscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280146
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfX2d5TY2SwmK0J
 dHyJzbSHvJtqzuC0uMIYZqJrnkKppCGNLXfLJTiYTJvWXk3P3ue8dFTurYf1WIFP7CHD1PP/in1
 Smy0xph6UkGLuo6Ch3H0rJ01CHmAOyhEylG0C/o3qMN67up++2DLnQ4BLAkTTxkrSfcvZpU4Gua
 zcsO2mDFBujCbbih4sA5sjVJFHc5NVIioEdPTtD2gG0nlVgk9a/SH+Fi3zS4odnDGcVTfuDNjk1
 SByxzFNUF30fkY+L8Genb1lZxBEWaCdF7sGJN2Gl3MwGW81t6PzLedCdt3Tei+/csS78vCa6qkt
 pEwBCfOPQ7N/0A7jn/KbFWKfbVLzrT7dea8w9JZtMQ8LH+FfgDz+v3YARkO9htgQEx44FiVx4xk
 TZKfYTLe2IF7JHO3m0e/AzWLWC7L0w==
X-Proofpoint-ORIG-GUID: iD1Kdg9z-G30NaKfqAMtDFVuUaAQIz1W
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b091cf b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=7CQSdrXTAAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=GHHY5ymhaPZS117lnJMA:9 a=CjuIK1q_8ugA:10
 a=a-qgeE7W1pNrGK8U0ZQC:22 cc=ntf awl=host:13602
X-Proofpoint-GUID: iD1Kdg9z-G30NaKfqAMtDFVuUaAQIz1W
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Aba0JhH6;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=kDlrqnvj;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:25AM +0200, David Hildenbrand wrote:
> Let's disallow handing out PFN ranges with non-contiguous pages, so we
> can remove the nth-page usage in __cma_alloc(), and so any callers don't
> have to worry about that either when wanting to blindly iterate pages.
>
> This is really only a problem in configs with SPARSEMEM but without
> SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
> cases.

I'm guessing this is something that we don't need to worry about in
reality?

>
> Will this cause harm? Probably not, because it's mostly 32bit that does
> not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
> look into allocating the memmap for the memory sections spanned by a
> single CMA region in one go from memblock.
>
> Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM other than refactoring point below.

CMA stuff looks fine afaict after staring at it for a while, on proviso
that handing out ranges within the same section is always going to be the
case.

Anyway overall,

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>


> ---
>  include/linux/mm.h |  6 ++++++
>  mm/cma.c           | 39 ++++++++++++++++++++++++---------------
>  mm/util.c          | 33 +++++++++++++++++++++++++++++++++
>  3 files changed, 63 insertions(+), 15 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index f6880e3225c5c..2ca1eb2db63ec 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
>  extern unsigned long sysctl_admin_reserve_kbytes;
>
>  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
>  #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>  #else
>  #define nth_page(page,n) ((page) + (n))
> +static inline bool page_range_contiguous(const struct page *page,
> +		unsigned long nr_pages)
> +{
> +	return true;
> +}
>  #endif
>
>  /* to align the pointer to the (next) page boundary */
> diff --git a/mm/cma.c b/mm/cma.c
> index e56ec64d0567e..813e6dc7b0954 100644
> --- a/mm/cma.c
> +++ b/mm/cma.c
> @@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  				unsigned long count, unsigned int align,
>  				struct page **pagep, gfp_t gfp)
>  {
> -	unsigned long mask, offset;
> -	unsigned long pfn = -1;
> -	unsigned long start = 0;
>  	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
> +	unsigned long start, pfn, mask, offset;
>  	int ret = -EBUSY;
>  	struct page *page = NULL;
>
> @@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  	if (bitmap_count > bitmap_maxno)
>  		goto out;
>
> -	for (;;) {
> +	for (start = 0; ; start = bitmap_no + mask + 1) {
>  		spin_lock_irq(&cma->lock);
>  		/*
>  		 * If the request is larger than the available number
> @@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  			spin_unlock_irq(&cma->lock);
>  			break;
>  		}
> +
> +		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
> +		page = pfn_to_page(pfn);
> +
> +		/*
> +		 * Do not hand out page ranges that are not contiguous, so
> +		 * callers can just iterate the pages without having to worry
> +		 * about these corner cases.
> +		 */
> +		if (!page_range_contiguous(page, count)) {
> +			spin_unlock_irq(&cma->lock);
> +			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
> +					    __func__, cma->name, pfn, pfn + count - 1);
> +			continue;
> +		}
> +
>  		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
>  		cma->available_count -= count;
>  		/*
> @@ -821,29 +835,24 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  		 */
>  		spin_unlock_irq(&cma->lock);
>
> -		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
>  		mutex_lock(&cma->alloc_mutex);
>  		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
>  		mutex_unlock(&cma->alloc_mutex);
> -		if (ret == 0) {
> -			page = pfn_to_page(pfn);
> +		if (!ret)
>  			break;
> -		}
>
>  		cma_clear_bitmap(cma, cmr, pfn, count);
>  		if (ret != -EBUSY)
>  			break;
>
>  		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
> -			 __func__, pfn, pfn_to_page(pfn));
> +			 __func__, pfn, page);
>
> -		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
> -					   count, align);
> -		/* try again with a bit different memory target */
> -		start = bitmap_no + mask + 1;
> +		trace_cma_alloc_busy_retry(cma->name, pfn, page, count, align);
>  	}
>  out:
> -	*pagep = page;
> +	if (!ret)
> +		*pagep = page;
>  	return ret;
>  }
>
> @@ -882,7 +891,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
>  	 */
>  	if (page) {
>  		for (i = 0; i < count; i++)
> -			page_kasan_tag_reset(nth_page(page, i));
> +			page_kasan_tag_reset(page + i);
>  	}
>
>  	if (ret && !(gfp & __GFP_NOWARN)) {
> diff --git a/mm/util.c b/mm/util.c
> index d235b74f7aff7..0bf349b19b652 100644
> --- a/mm/util.c
> +++ b/mm/util.c
> @@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
>  {
>  	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
>  }
> +
> +#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +/**
> + * page_range_contiguous - test whether the page range is contiguous
> + * @page: the start of the page range.
> + * @nr_pages: the number of pages in the range.
> + *
> + * Test whether the page range is contiguous, such that they can be iterated
> + * naively, corresponding to iterating a contiguous PFN range.
> + *
> + * This function should primarily only be used for debug checks, or when
> + * working with page ranges that are not naturally contiguous (e.g., pages
> + * within a folio are).
> + *
> + * Returns true if contiguous, otherwise false.
> + */
> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
> +{
> +	const unsigned long start_pfn = page_to_pfn(page);
> +	const unsigned long end_pfn = start_pfn + nr_pages;
> +	unsigned long pfn;
> +
> +	/*
> +	 * The memmap is allocated per memory section. We need to check
> +	 * each involved memory section once.
> +	 */
> +	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
> +	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
> +		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
> +			return false;

I find this pretty confusing, my test for this is how many times I have to read
the code to understand what it's doing :)

So we have something like:

  (pfn of page)
   start_pfn        pfn = align UP
        |                 |
        v                 v
 |         section        |
        <----------------->
          pfn - start_pfn

Then check page + (pfn - start_pfn) == pfn_to_page(pfn)

And loop such that:

  (pfn of page)
   start_pfn                                      pfn
        |                                          |
        v                                          v
 |         section        |         section        |
        <------------------------------------------>
                        pfn - start_pfn

Again check page + (pfn - start_pfn) == pfn_to_page(pfn)

And so on.

So the logic looks good, but it's just... that took me a hot second to
parse :)

I think a few simple fixups

bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
{
	const unsigned long start_pfn = page_to_pfn(page);
	const unsigned long end_pfn = start_pfn + nr_pages;
	/* The PFN of the start of the next section. */
	unsigned long pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
	/* The page we'd expected to see if the range were contiguous. */
	struct page *expected = page + (pfn - start_pfn);

	/*
	 * The memmap is allocated per memory section. We need to check
	 * each involved memory section once.
	 */
	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION, expected += PAGES_PER_SECTION)
		if (unlikely(expected != pfn_to_page(pfn)))
			return false;
	return true;
}

> +	return true;
> +}
> +#endif
>  #endif /* CONFIG_MMU */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b772a0c0-6e09-4fa4-a113-fe5adf9c7fe0%40lucifer.local.
