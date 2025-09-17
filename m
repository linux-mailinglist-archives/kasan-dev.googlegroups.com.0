Return-Path: <kasan-dev+bncBCN77QHK3UIBBYORVTDAMGQEVY4VGGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D9B95B81F94
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:32:19 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-42306862fc5sf2666275ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:32:19 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758144738; cv=pass;
        d=google.com; s=arc-20240605;
        b=I6gQcaayPBHQZIPZ/Fzjv78SxycYfZyGf6gHlUEYDPK+S0ytUqxocEoxlOjcgGSQ0j
         AC/dcoUQChsp77+0xijQlhpI9NEuec9rDrvNOSvQJPB/9R59AsFVKpQeoKDi8dJOi4lH
         SPkyjQ1W+cl2H69Vxqf+EEqvcvEL4Cbqz/fupdCgnfOzAOp1cC36UtG0YwQndxcIdaqb
         DoD2+ENPEOBvVGFkzrt/bk3a/N5+Z0c4QSo4bzhCh5Iwo5CI+RjURNqHci5BzDj2VKwr
         Iza14O8+qG6hlLZWVJU2m8H4q5O24hiGRHKQ65aT4TSDZuxxUryDcF+qdtR7/VgvtpA5
         YcbA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MCzrT4sjcY2nfF57iMBTOEPv0ZfoEU0M/r7sIrr1l+Q=;
        fh=ItyH8JQPzI0VuzTpFqnWqPZ2tKHocoGDAGpN9g7tzcw=;
        b=WJoJvm+MGaqXUGv+wXeEaLZfYf8+q+Y8Ia1HVsj/YvGzsfHI4L5rXHpGr1yiOM6ZlE
         4C5MoRQOz2nbuNCevYXrLhR7fgJw2DFxKMl+Z8m27yNUpIUseG3/WhBjTYp5bkz+/5MR
         GpLniPUAOD+ZYG8Qoq7Ija+rQYWNUmupwpgaSn3etr5804eyb8+AUQeTjerHwWTiC7H4
         a0KwcYmwRRnv/xseHf/cIGlqvCN3C00JeSUU7+qNwCIJR4kW3o9zagF8bke0iXBIiTMU
         rxk5o4wWMP0F6glkZ0MFLRbVJGaVrMLmRN55kgDkoeRQFRRLKzGu01dQqzhImOHTabMd
         86+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=qDEtYj2r;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758144738; x=1758749538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MCzrT4sjcY2nfF57iMBTOEPv0ZfoEU0M/r7sIrr1l+Q=;
        b=SGh0yavL8PUCHapJMBzCcPDFNN4L1ponvNEYRrgdSQoMMJs5omMtFVzHo0uGaMOQY0
         +8cdLBPld19guLt59JNsBPhr58KatE6rjSs7ZSerS2RRIPtHAp1UZ/PxsifYCx/VoI4u
         Z+D8cEmIFEkHGaMDiZ0V1rpmEzKieuXc/HtegD6eD92OBFU5Do6Qcdhn25zgX/bLsd0V
         ExvydTLjR6Uo4QlQgga77jjFdhI1847mw9/3O0VL3q2JG9g2VMt7XMfAjEJ0nfds4DoP
         54abuoLprPjKGF1mvAyTIxzcCFR7QbbIz/TPJtCKDt2Ajo3azrKabgtc8MyPgGBzghZL
         jJwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758144738; x=1758749538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MCzrT4sjcY2nfF57iMBTOEPv0ZfoEU0M/r7sIrr1l+Q=;
        b=gI44n3ETTB2xhg92I0ifEvmMLx6Lbg6iO3xvy1UHQfsa3DG4e8i6Qao06syM17KdFb
         YCHP5Zq5nwTRoP8tv101AstNAmsEM87vggBeYBjfqZ6XKWUjRQc8sOqc3vidFIyNGwZ0
         cU/RdhEdaWxpLDExDS3eNntDH5VU/lzCI6kIXVrTtt/V34Ktm910mimj5dYJ5EnAxDrj
         Lpu6wU3JDTip4sUHdr1XsIkYeG+DhrGOySjhpEuv5Fav7sneLj684gVmqCmfPnkRsJwx
         IOcTv6p0n7MO7kbb0roEbYVNq2H73qvfmb7c5q0qzGDeELbxUX3n8wgX/bocgFj5TSxQ
         XLJA==
X-Forwarded-Encrypted: i=3; AJvYcCWaKo8nUWObCEX0PfgX6UKk4pjmZGoO4gPjM7feK/Ny32w/hroTnB2iA2B+g4Mbh2Fmmjtqfw==@lfdr.de
X-Gm-Message-State: AOJu0YwwKmkYboG9f5ijmDbOCj+SLzLVbx+vIpRvLCjdD6tXNVC7O+PD
	g94klcvBn2mjpYEFSFvApBse5DQ1f7qVx4OPl7yfo+xdhW9H+9VENK68
X-Google-Smtp-Source: AGHT+IHGu60Us97GG0X+6arDqk9ciEOifJvz0QFZtE2MEtnGv246Y6ZHfe/ZVWRsB5wS0VZ8rCkzHg==
X-Received: by 2002:a92:cda5:0:b0:424:cf7:7d04 with SMTP id e9e14a558f8ab-4241a4cfcf6mr47509625ab.4.1758144738230;
        Wed, 17 Sep 2025 14:32:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4h6ZthLoRUP7br7Ne+9adorHprMm/cG6zMnM7+YtNT2Q==
Received: by 2002:a05:6e02:5e01:b0:407:3f76:fbda with SMTP id
 e9e14a558f8ab-4244da29004ls1325625ab.1.-pod-prod-04-us; Wed, 17 Sep 2025
 14:32:16 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWQ0YbHx457Ht7AYBIleBht+ccooCNQLn2ulM3rx9Z6Ak8iIzL/uL2rpvK+SafRkRqULoPmp1QjRpU=@googlegroups.com
X-Received: by 2002:a05:6e02:1b06:b0:423:fc1c:1369 with SMTP id e9e14a558f8ab-4241a531fc9mr42597665ab.15.1758144736590;
        Wed, 17 Sep 2025 14:32:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758144736; cv=pass;
        d=google.com; s=arc-20240605;
        b=ckpTPKH+ciBFdCnaDrT+ef9xOvjGJWfP4bOY1VGd0Or2OEZjslThqYPE+TuSvxTu7y
         d2EGTu4N5UvX++vJ8yz3j2y2Wp6H531CifTd0U8hJySSBsiSnbHTIKTl2LvyYpjXXjkX
         RmYe1bYFQXH2VqCNFfrKZ1kk+uEED6Ioh+VILrKoF7fP0OTVl8c4Tc82+vILtskxL6Er
         /WRx+6/5GHqkFu7JQWdBLNTIpVLJo7YjLn/vFU4gNZ7C2S8C4sGtZ7dBqc3Q5yca0m23
         LRn2G8Z4szAlRAyANsPary85KLl2s9yaVACA4T75mVlSJTaWtLkrPB6AaGa1wbFOYo9T
         t61g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Fg+98tTegNerBM263uZEtTcom+RrVSGH9ZWZ4syminU=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=OU9DU8jnH6PTPBQw1OpDFeBLozClaugHwzzpEaNgQSg+lopVKJ4YPfpFKUKPh3ZP1p
         M4nPBq0V7/Cy+ZAB4bl3J0MWILONQw9WR9oW9uBCYWzT+VMMbt/AKxoEtYGLpiqgbvIu
         6JJH8vDu5KfI0xWA5BDDdwUTcccgjKQVwC6yRLfVWP2UsMvOkFYO8qRiZTJft7+MaBMr
         o6s+8Hmlz9p4/8Nh52EroRc2JdECptA3QlkG5Fk8A2rpyKYHy1VicHIs1NMFJecac7PU
         2Vq6BrXOKmZWrIQEBo94QKgfwiyuBdiFlxvjBu3PIPgqe76k0bIJ41SYdzxCtzX/xJRW
         bV7w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=qDEtYj2r;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR2101CU001.outbound.protection.outlook.com (mail-southcentralusazlp170120001.outbound.protection.outlook.com. [2a01:111:f403:c10d::1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244a36a70dsi215665ab.2.2025.09.17.14.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 14:32:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) client-ip=2a01:111:f403:c10d::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=zJyBWfxHS9tnvWzVqZzFkI7OaTGQGREs89pigQCPKRvvx9uMFUYQMDaFEBTkfGy6DnaP2kZgfraazi/7hCej0BYILtlRs/FZM6G2PK/xToMdw6Vr08sl8qwkMrqx8+qIVO0q6OUqjlThkrBqKdpKqJ9oc9EC+gyBZt2pkAw+XBfb+ZyRcBLoE5zAkYGMW+0KodKYoqDN/tyW8WOi9VzQVvdKI/fsZbsMe047w5lFKe7nm7LIp8PXY+6LkcGzVOZlELZ/fkxwfgnX8maG9M6k6K0gn4Dc522bqY41KNuOWQ0V+FE72Dlp+P6vb4OmX9CVCXboIk4mm4XoX416UvoIbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Fg+98tTegNerBM263uZEtTcom+RrVSGH9ZWZ4syminU=;
 b=xTEOzTgyhdiIDIbuXE/lx8apcXJFoOe/GdcBtETJtuTedmhBhuqp5/6vDDWP8coS5WaNxUozwia4Bo7U7eOpaFfFfsg1cgCLpAWVFUSOLPUTHvv55clI5bAI59u845bGrT2HlqxalVgM/zIVu0rBQNF1nnv8t5b4YqSRhHfqTHSvxk6tVleDQYPDMT3JLD4kuIUFcPc+7HwP5xum2f1Q1W9gepjte2hCNA6WnY4ZuCmxQyl1WbupfaYX+q8pw8wflboo5dNKXBU81cw6w+S4BJQFDlNCISJ71j5/KvZpxUG7q4jGQd5NPlEHiIMVJpelZWtgOriLunX53nlVsIITmA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by IA1PR12MB6579.namprd12.prod.outlook.com (2603:10b6:208:3a1::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.23; Wed, 17 Sep
 2025 21:32:11 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 21:32:11 +0000
Date: Wed, 17 Sep 2025 18:32:09 -0300
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
Subject: Re: [PATCH v4 06/14] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <20250917213209.GG1391379@nvidia.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <ad9b7ea2744a05d64f7d9928ed261202b7c0fa46.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ad9b7ea2744a05d64f7d9928ed261202b7c0fa46.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0271.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:109::18) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|IA1PR12MB6579:EE_
X-MS-Office365-Filtering-Correlation-Id: 639f8dc2-f2a8-47e8-7b0e-08ddf631a955
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?pJ45+/caKWnRywXZqrPOiqlVU6nevB5xbvSc8DLBDVGHRFHHyljnqTcf5GOT?=
 =?us-ascii?Q?rsPfO9RnTE/mE/MkkR+tceKjcHo1s9Ulf3PAr1vH6JXJMalF5yYvnOkIU8Ra?=
 =?us-ascii?Q?rD9MS4OuUgdcIdt0t6PiJ2ZOQhR3E9nB7MMRS2q27b7gB82kckh9djmHpQV4?=
 =?us-ascii?Q?w5PznvCz5l1Ph4WHmEkyGR3ezBt3OQc8XqfLTPodJhXIhKH6ZUKEldRsCNsi?=
 =?us-ascii?Q?UYscqIJRKbYu6Nz2qMYEpN1dpPOciK9RSxsSZ24AB4L6c9PJdSPQJ7uJ4NHX?=
 =?us-ascii?Q?20cbg1MRziQ5853xTjiHpNlm7LaV5OGldmWlhexeCOuBzR2tanh/jvNOA2Bn?=
 =?us-ascii?Q?/e+1i/0yY0yR/QQMy6GHz4TF7dUs16w2CoXPPfbg4Ej4I23xkU7InqPpksr8?=
 =?us-ascii?Q?yRMEQJtrrHcEnuMvz9CqYKjRCn9gKQ8XaNhG6OXs8I8nGptxydJ1VsSFffsx?=
 =?us-ascii?Q?xZrYBTkkMvJGIYJV2TZSoenVY/Tv8aT+LVIrzb0W87ILOWkJmCDc0czItESO?=
 =?us-ascii?Q?2kIcr4q+KI1Z5ToMovxnbbwQPQRt0MsbYGfhtGfWsui8LWNdm3YYxoLwI4n9?=
 =?us-ascii?Q?uBf0KlwEeXZMWgO2Cjotc7oAq93HbmKcZRJA7MqCXqmhDeE61kgPJmaD/P/D?=
 =?us-ascii?Q?HcGffUn11gpadt7FbEAsYFxy0Y5gLAnywgbi/+GHgEF0sLho6aGVN6eg2yDD?=
 =?us-ascii?Q?uyBIc8DeQK7r0dF129eLA+JobVobSgTKytnjSiKml0HQ2z+8FHdTb89qytfw?=
 =?us-ascii?Q?cQRxVHBdHs6dtDaCsuHdieyIdQ2BW7Vrigu+cTsxd6w3fUZkM5U7Hm3EnwaV?=
 =?us-ascii?Q?gbsZDpmAzTd42rFaUMVJqOyZtou/gkH+NsQj32dI2CsvQ10GNnh7r+9f10Rf?=
 =?us-ascii?Q?aGfDGGK1metNFvB/UP5AX65z7+6l7wC6yMLmL2m+47MEG6UtukdJz3xkZQh1?=
 =?us-ascii?Q?nGDbHGQk1MSJEjVdxaf0/yFarq4ZqwddcbSqMagjfERypdcEDxgmrm0S5mLK?=
 =?us-ascii?Q?VACPDV6K0SxyhBtud2LZP3dd4YdKKkGhHKwFcHK7b9mFYyBokSEyTE2Vdvtq?=
 =?us-ascii?Q?j57q8zEUGCTS0pEb76sTeMnLwTT4FfdbnKOsjLOImqNNOXafkJi8YD6SRKsK?=
 =?us-ascii?Q?vj3b6JCusav6BJhPXxPJhjvP6iqEQFn04YiA/tQX6HJtiJgyO2MYhrsFYf2w?=
 =?us-ascii?Q?Y9ZUSLG6ST/tT+4El5EwvMV+nEq99hqsYr8DYJ8xpoObtalMrkpBOU/fRNHT?=
 =?us-ascii?Q?S9Bm+uO7u+CNtDHhOQNgcAF/JBCtuIaGsN5W6z3Mikmc+qcXfh3SAIuQN8cV?=
 =?us-ascii?Q?DYZqhtaEn3Dy+ALokq8j1ow/vTYrc1ureU1Bgh37pxOm6Dx0cJsxSy3yR/iI?=
 =?us-ascii?Q?B/CjGoyZEmTKhBBOa/B06WsfkKCzwgTU7HHVYyTsCdYy4iz5vYsSJRoMXxlu?=
 =?us-ascii?Q?hyjR2yisLLA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VE1M5nI7CHqGhXFCR1h3SwjboeR9TDhDAS6cltLkVKUjpaIkBBbyPp2Jo5+o?=
 =?us-ascii?Q?latx4mQqsG9ecOG51PfljBdbnzY7l38GrDWxEOF7UzocMJoGftMPw1iOxStL?=
 =?us-ascii?Q?3v15sl8ieDcT1EprXi3L0Q78WVFzWsQZHPSCKOwOwh+9o8RmTFZTqZGdWPdp?=
 =?us-ascii?Q?DrOmhbT2icS1L3vqZeNvz//AJNxvM0pZiRi+3pqic7dZslLDX8D63Q9b1pH8?=
 =?us-ascii?Q?u5ljrzOdOxj3+urb2zEER00p8IN5mGFiMF3Ga0TEPDI5lBqJ3VTWMgWmZDu3?=
 =?us-ascii?Q?x7EEG9/IqF7bmn3s3uvOQ99M6zyG0nTt1xPxvjB/Si1+iVBbd+qyGs4l6O2Y?=
 =?us-ascii?Q?nqYb7p1Beav/QI0mHKQn8+iCE/N40x4xeW3XtSkOF6sc8HQmaK1ufm75aogN?=
 =?us-ascii?Q?NcPRSBm6REouUZjnjG/5QIssRxoR1t2nLUEYIVUDtd76nUQS8+/vZZ47ppRJ?=
 =?us-ascii?Q?lEcZHm4XykgwpXdWKT8SXEPe0/r4uYjBym5xX5XRHPinIOSdwVixEWkAYmey?=
 =?us-ascii?Q?upUv9g71WfHdiw1ae6hDOJ0GrjqNMZxAP8SkU2upAyKbxuiajxnZuTiLMY8R?=
 =?us-ascii?Q?yS2dPHOEt0B05GrENhkPsuP3W/o9D7tu5jlP+nnHMqRZ/UW3CBLKaa4DldqV?=
 =?us-ascii?Q?osLVZXydG8/Rwb9hqg4ej3ZQJmmTlZWi7lHJ1v+BWmw/5m6V77YrPQGILUcZ?=
 =?us-ascii?Q?LD4UtmWi8XgobvxKKdHMMNJAAn9Px+WKSfQBXorYfEYwcMJnk03pPuE7EiNg?=
 =?us-ascii?Q?BifZTNEj85cmfPE89Y64xekY67l8sjNel0b69w18IROAidmpjciB6vlbtVPp?=
 =?us-ascii?Q?VXt5vG6hOhXpCavjsOAyT5V/Bl7vTcofMAr3NWEV8YToZMwHg3Nnqjisroyx?=
 =?us-ascii?Q?F8K5c9dlvAu4TTUDr1fAxDqR2SPGd8Neaqz20cipL4j5UJt+ngnBH8b4KgrP?=
 =?us-ascii?Q?YhwGaa/8R4DXH0/lGTsmLP7MdtddR5ZGTr5iDVvFNQ6RmtRpBau10aUDl+I2?=
 =?us-ascii?Q?Hah8i4UMSHMmfENjVmPoM31phoMydeVgdtB6xT+10ZSP4jeaNAvLAVcC68MJ?=
 =?us-ascii?Q?i8zv8CsrrpUK3SCQiM49hoawkzn/bKJatXLykgAvIoSytQjre2HaNg9ePD2q?=
 =?us-ascii?Q?dg5/QUXlXUPYXGGZMibnTLT3JSVS8ZkOjFc/qrjNDq8lQJ9cH/H9FdFCCm1m?=
 =?us-ascii?Q?Qc8N7VzXKbJgHS8OjRJT9yEE5CNgW6Nd0M++z70EbhAVChljO63x1XOwB32H?=
 =?us-ascii?Q?EM1lfmGv/HKp+r945cXAO+HvwK9o+zPKTxAMX7zV6UVFhzVaNP0PODsD/ZQv?=
 =?us-ascii?Q?YYGL77PB+TtQcbOEK7UZBf3zVlVQ9lA1y6dg31hFMdYkvFESxtn2KnQEPLG/?=
 =?us-ascii?Q?toSm3wb6pEA987Q81quh7fvcFaDsg/7ZbLxiiWFPE62IjuON+VUjMsoIXkvu?=
 =?us-ascii?Q?Rr5f7O2c06w2UZmpuwjn/8PkqC71dg5xbFH9zvvUyCh+LIn6sQHsodz+yKWY?=
 =?us-ascii?Q?/fMSKupUMVb5ANSXU2ObnwjaN910ovIAy/qy11MIs/7v2lcedwR6Pb2Y5Bx6?=
 =?us-ascii?Q?SRjW+JDilZdPwP7qKEY=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 639f8dc2-f2a8-47e8-7b0e-08ddf631a955
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 21:32:11.2905
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hAcPgQzT+7q+cXbQ14vQdUdeWVMtd4UMmJsscqqOXQ+L5WAf+ODkmvyg93UIg6II
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB6579
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=qDEtYj2r;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 17, 2025 at 08:11:08PM +0100, Lorenzo Stoakes wrote:
> -int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
> +static int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
>  		unsigned long pfn, unsigned long size, pgprot_t prot)
>  {
>  	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot);
> -
>  	if (!error)
>  		return 0;

Stray edit

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917213209.GG1391379%40nvidia.com.
