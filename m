Return-Path: <kasan-dev+bncBD6LBUWO5UMBBXNP7PCQMGQEYOXGT2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7183FB48F40
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:19:27 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-24c8264a137sf55770945ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:19:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757337566; cv=pass;
        d=google.com; s=arc-20240605;
        b=IQyi4f768aneSH2Manw3xL4rjqlN1J+3fVsQlL1varOCOZa96SRItReibc7Z+ik8+o
         9NL9iAbaLDD0hZiebsbYC42zRcX6RK7TYBK6vrhvp6g0WtRhqlv6sveU9teTjHH8lPjy
         GjRcUn1JdFuBht0fZFSmHKPUtiDUp18uBZyaYEEGwSVaPol4l4JGFnZgCj7PqsPYf6jk
         rSR/8KdOQcUJ/AABqqT2n+47wsOC6EqSyWUEbDKFSK0MzVhFJqkgvVm8/Z9S47Ahgs3v
         I1QaFe3u6VkXEfN4kvKg21FPoLji0b1ltARW7OOG0pDXoEUO2+fC5O9t/oXK8WYlIC8p
         4+pw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9T48ypW4BOysfDhEhb9RCNTqsbKFRWPoZPrk0zRmY6I=;
        fh=DjGFul0tci4ckQtfooqnriZa06wWDTh8c/gO4F6sXNs=;
        b=CiucMm9X20vUAFEtJ7my8+oZIbhD9LrM/ynLzFL8qHCu5/d+3otc+k+CzdSNFhxCL9
         lYdpKo9FRtfZRXDp6tkAAr0aprghxMp81SPeJTa7BrxFIsLoTFGDVnml1vOlxe2TClqt
         1npym8k+tqaxZgcs9ixNPkQBZkIvUeXHq1YygrOj4fuE6FEvcK5Vx5H8JvzO36Ufjca7
         dl7xeVS9f7lj9OD1Hwmm+dB5ECxgSEDZO5BJbbcSeFJ6t9J+Wu6QFHRf+ueF2SXqby0/
         mF70fkwnyuFGqD+Kca8DkS6afmWUcquQH283KKw2qgf4J/aFSYwfDQEth/+UsAu10Mkq
         bknQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=i3qlpWmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XV2pbl8d;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757337566; x=1757942366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9T48ypW4BOysfDhEhb9RCNTqsbKFRWPoZPrk0zRmY6I=;
        b=XknPU/ndKuDUlRh27OfjbcsaiFFWfQRHy29MbD+QdvBEnjp5dMrJRrIoz099tpet3D
         JZewYx3BglvUEZ0DFTE5Udk8UlA7TLjg6bgudD1rTkS0nhcA5EKj2YUeYGvG3VcGq0ep
         lQUCnTm4DAzu7COcP9CJntuOcQvsKKUnBWEpISbyGgUOkV2AUwFX2kDd8oPBwRSgxRYm
         FPW8MiYbKzEHNSq+W9iMqa610si0wCm2/e8HJ1OAtXbOPPHxM4T9lRclNsYMk+wFWTwV
         +Hr+BOIPvzIGmUCJOY/AKNFJn+9Gp8IcwSoCodcXonXw7OkV2QBNN3AT6I9QnpLxc5lT
         Ejyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757337566; x=1757942366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9T48ypW4BOysfDhEhb9RCNTqsbKFRWPoZPrk0zRmY6I=;
        b=TSEC0VRI+zpyf6w0ecMr3pJfBNwF7AB0xtNh0D/TcuBPzcxT7gO+CqFUmvf7xcRFTU
         LWWHci7Ww+zZFV/OK43YvV5OuD90KApiP7WdRa02WkWB+635alhrnq8dQqXePjq9HJ/8
         aWm5rFkJFlTsXyEy6oGDPqamWi9x6kJAEXmmZ1Sw8/weV9eG+pchVeh0dA5FbO+rHlSE
         7VZxwrLP3EYHlb2ZzpKdESDWemqxn/brV9HIe9XZUr6YMNSuYLH0zyExyAJZWyNfTMzx
         C5S0ItW9001+24mUfmGfAl3OFgqhmrmy0ODFRXG7kz7Jd9tuvymW6XQKrW8jD9W+vPBB
         eiIA==
X-Forwarded-Encrypted: i=3; AJvYcCUujU4ym0k6Lsn0wOt5a7mEpXnIytLmiRBX434xmOG1pgFx3KqFng1Q3nC0ZJVvQ3AJCDwDSA==@lfdr.de
X-Gm-Message-State: AOJu0YxhPhhgZLersKNUdXGV/ilf89tBbJ/2Hf/+dufQov4RUD8wFwGg
	3UQzkJN4MgV0m6Mhaoexqie9RK/uRw2fbNcrrtpZS+SYNbUsUIxe3Zc/
X-Google-Smtp-Source: AGHT+IFG+1LlU6MCU5Bw40wEoCCVJPW9uZ8Vq4lj+iCTzJUfl4I1ul7RUZ/Kb8NBtpN9UarXFQu7dg==
X-Received: by 2002:a17:902:fc45:b0:248:fc2d:3a25 with SMTP id d9443c01a7336-25170c416d0mr99711545ad.38.1757337565458;
        Mon, 08 Sep 2025 06:19:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6jp96wgFPtyG+BlvdqT2QvWQy7zoeKVEKDoa1zsokIuA==
Received: by 2002:a17:902:fb43:b0:24a:990b:75e5 with SMTP id
 d9443c01a7336-24d53f0f300ls22069455ad.1.-pod-prod-01-us; Mon, 08 Sep 2025
 06:19:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWkanmkhHd6t6TMcoizVuJkrU62e1JSIFQ4ywRDuKHtDKXdUNKx8sVBGlojC0Do24/gUwdqei8PfvA=@googlegroups.com
X-Received: by 2002:a17:903:950:b0:24a:9475:3db2 with SMTP id d9443c01a7336-25170c47740mr101934885ad.35.1757337562946;
        Mon, 08 Sep 2025 06:19:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757337562; cv=pass;
        d=google.com; s=arc-20240605;
        b=g3BsGg0GSQWJFlh/4GjzL/xEkmfBv+FcZUSeZecy5TiKuZuMozvIXsFJTie40Trh1U
         5k1MZx0FJfJXyd/Zc8h4tByyCuZe77T174pyIYKFPk4+czgrdtbzOfhnu/xz/+k4v52D
         DKerg84k8ToeT6F6NxLpMl5KJicaZVrtt87oFwKUYn5YLW1dQnrRMYKb+lbefHnvPcZQ
         PgHVHxhDmtnd7xgQ32fVMyFYGMVTBM5JlMbepsrv7pNqu2oSXexmAsQJwVZg5WnOAu9E
         zQThO8IBHfQVZsZG4oNWsV6u3pbaSHARxpWBqc69AqFtxZ2bl5/taiDfd80GAbQhgpEs
         4qVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=gwIxBqBclQv86/ati1fbZ0mVGj+PzEqvYDzaI6mk2fg=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=gRmudkE+FbOTnCe0C9K/KL1slJchfnaWtuYCUcULUp/zlYu7wfaQTQSnWgxx8iMNkt
         7epvL8PlyNqmYNBd7EZ1wFzkBh+Tzfn8Auz4qAdURkAGDahWAIWO0eI7mYo+TqYbgwnQ
         GSmD1S5Vw6w0hqllRs9bIyO+iUdSFIWDgANjDsp47A04qBVK9jxJzemPWffPQSDgPKu6
         HKOwQ024es8UAyc9rlKe96JDKkLbrEJxOJIlFOHNl6AAiq3PXy394JiDh1bNEtdfSPCE
         234+OLZdHDq36Wk5hgY91UlDto9VXdED5UL/VP2W7ARSq5k/Mh6Df0TQibXj6/4dnkXY
         doag==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=i3qlpWmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XV2pbl8d;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24c966877d4si2908655ad.0.2025.09.08.06.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 06:19:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588D0rGq006365;
	Mon, 8 Sep 2025 13:19:22 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491xf8r55y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:19:21 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588DGkof002759;
	Mon, 8 Sep 2025 13:19:21 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2048.outbound.protection.outlook.com [40.107.243.48])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdepn38-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 13:19:21 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Fd8q1BvVLrJIjZZkYkj5VetzTsU40c/eNENS17rSakvZG0cTdI64RfTkBxBph9Sn/HS3Ty17DCFFaw0DxV7j7Rhyc52jUjTdmKjOauJN+jYxGrznvGqy5cLhpUx6JTgLPJ9nZqzOL7GF17BOO6eCcxKut+RS7qM/nS+bp+Yfu5sUUNmtI7yBKJa3BaPtP5qWp27n/ug19MJcuK6Cb7/8hcYJcrTBbny1iGO+tR7Osoj40GqWc36hOk2MSTVFNRXrCvxcOl/M1RrQkPdw/tliUVOz0isRqZ/1XUEPa3aqi1bQjqFzyMB3OOxlg46dV7LIXXDMxo6I3mK/Eg1J1mCZpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gwIxBqBclQv86/ati1fbZ0mVGj+PzEqvYDzaI6mk2fg=;
 b=MvXfEuvgZXtto2o69gjEMhq2qy3IZEDT8CabjfPV8pDHqtVsFscae1e4hewldjZFj78XFWl1nu2XE/6eVAQoUIdX3mJTHIeIsekBB2mWVUWE65BZAfzaIbA2OLp9pFbXO5jGRVzLYat0yE1sd2/umYncDYZ68ikinPbJsI/DW7MKW6cPUe5ztmSIW/2ZTh7aUEF6bOv4reQQ7XFKMqwSRaquma0arTAJLyoll1rwJWLtuR41kaOF4NM129p/+YnoKbBVbjsQzGl4jnjcWFYel7hmTsf8Ev6BkNTgcCWApBrMwhGKawu6yWxGcaEW7n5QWwGYDjX3YZ5blVedB06aMg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA3PR10MB8465.namprd10.prod.outlook.com (2603:10b6:208:581::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 13:19:17 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 13:19:17 +0000
Date: Mon, 8 Sep 2025 14:19:14 +0100
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
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
Message-ID: <0df59b0c-dd8d-4087-9ddf-3659326f57e9@lucifer.local>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125526.GY616306@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250908125526.GY616306@nvidia.com>
X-ClientProxiedBy: LO4P123CA0186.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a4::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA3PR10MB8465:EE_
X-MS-Office365-Filtering-Correlation-Id: d3b508f6-bffd-4656-45f1-08ddeeda501c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?cOQtH+YWiPInnydj3XcA6gtlIiwdxuhhtUvPbTOUmUYaZ5YChR4SruE863W/?=
 =?us-ascii?Q?/ZUoRXXK0EYoFrsp7y5biN1UOs6TwVuNAa0QrXAfIL/B3MCCgVXzw4Jf63Qa?=
 =?us-ascii?Q?k9EVRoNA3BNb0kQv069IUTPB7bH9pcfAYTIvxBQgX3df6WNwQr3rFPqN/kUB?=
 =?us-ascii?Q?0NN0guNAPEe4nFxSzLgEXSqIxNhYM8KXFdlPwel4ronUt1FPVzbhGUqpgTvq?=
 =?us-ascii?Q?FzWIsuOaZ+y4GOFikdhuMT3PIVw+B1SSHgvejXI6HpBVYOAXQLuVuRSdmWQM?=
 =?us-ascii?Q?b/wfswQOwipCJNv58wy6gYhXvGT9DHc2QHCGc899WXn+Kj9kiFNB6v40zjBN?=
 =?us-ascii?Q?QRAY+efzWGplnhrgQ2G2Y7XFE5nMnxvWV+CHWngSwNmT2aZGGPYWmcVVxztz?=
 =?us-ascii?Q?uFFvPqpj1JXXBQKIHj6g6AlbWOxiBCxgouuSiHmT1NGuAsCvBgN4vTeZYubT?=
 =?us-ascii?Q?v4BZ8TvyBES3smEAnYtgXIf/P5lKxv8LuYdcN0U0W7cRV9emHdcU7Xq/vM8F?=
 =?us-ascii?Q?dwZGpCQ+s2l6tCs+pvlKc0J5aCLkDuv7GNGrV9H6w9V6LwIqMWK1qKMt3TsS?=
 =?us-ascii?Q?drFecKC6MnMCKvDIvXESr1/pIA7fOAFj8+/8XCWOvozIDQAXm76P85B8io6k?=
 =?us-ascii?Q?AD8c28n7NMMZDQAl6TSyTG6NQ8meuXgK07ogG0PY2o63THgsJqpiGGcah+U6?=
 =?us-ascii?Q?aw4PkvwX1Iej+17UqTYSdsSbbeBJgJewY4ikQ8VBVeAsQQn1awPbPvMQ/R9p?=
 =?us-ascii?Q?pnjPrsH7QPaEOL7pBokUGn2/+f3nD/gOSpEId2byctKvQ74HKXwonXOWtyJc?=
 =?us-ascii?Q?P0VHsIRLitZbMdVwtVTxWaubHjD6hCVOtMklRZe256WDE/rcDTDXesselrn9?=
 =?us-ascii?Q?YuKW5Lp+2Q3PN5z7wpVx7Ydflg8I6AVJ/0rU7Lz8vjdCQ/Htlre/lFx3BEwF?=
 =?us-ascii?Q?WUtsI5hXROPRpstNno6s6adn3ujIJ1xgYRcy0j5loCry/5lnlytG4DWwE3P7?=
 =?us-ascii?Q?dvmNRULx61KKVApZQf7sek0CQxrnjRzGAY+dcBT7ZUdzWEf675wTWRE3Mg9B?=
 =?us-ascii?Q?w4VM02ZFHv/EdqRTNUq/7mBK3PlCjYDsJB8Frm6U4OyYjysqnY2ziJRl4sO+?=
 =?us-ascii?Q?rNfEguAuM5sMv6GhATcPmqCo9jssKSBhTHBlhJ3/3DCaqYoZrEv0j6YSUne1?=
 =?us-ascii?Q?CPwMxV8BjF1xrKWsqujv4cOw/lcHt5dYmdfqpT9WMGo2xomw881XfZXX3I1S?=
 =?us-ascii?Q?nDSRGoWhcpn0j1DWfI0kNe2tOV5IHWBzqPrVeU7b5YWl9DC4SviEZfSR2vn/?=
 =?us-ascii?Q?3NbnRrFDvW8MFxisE0SJbm61i0vFUb5q4WgVKuIPudTXDkX2G9LHq9eCCf53?=
 =?us-ascii?Q?ytMEeQuAefA5KOd2xHKczN+ZVGb2riUaXHJDF1IUAUWU64zv3cWLUAAFNkgP?=
 =?us-ascii?Q?28Sdf1ltdR8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?0wQ5+KHgwYZMGzu7PdJolbi0UNaD70M2cfzqnRikylhdzvugpF4C7b3A4C/d?=
 =?us-ascii?Q?G7LUV6eztYwZn4BwykvUeCHBjvZqXFBMC/x61gZtQrCcp+z8OH5tkh1vi4Xg?=
 =?us-ascii?Q?Uqp0uvBfazz9D59NPd/KlOoFEIgXb+U8w0TdskfkwtTRNuVb0Nb6QQSZFwnl?=
 =?us-ascii?Q?0q/aPIjHSxOFIOgG9fSlcyG44YB71bHtRK1PHS1jleaNBdqhbtzB8BmxVKQl?=
 =?us-ascii?Q?3a4kWFDSGAX+nqJsGyrMNSmYre7TuLnxn0S12lMBpKna35DEJ4VacvRVEgiV?=
 =?us-ascii?Q?mLCAdAgiZ9ugfMVmvfxISJaWWSfH20H4+iMEXTLgpAXHrdbUCXzKnI6ySkfl?=
 =?us-ascii?Q?h/hd/HDoAbaOb/G3Lnv1JgmItMRnpPnYSz8IZHVZXTb9qeNpFbLYQTBmkouS?=
 =?us-ascii?Q?mBbFSoFEPkJ+6ldyhvWP+q0tDMVyi752cY/gQir8R0f10aCtia7MsbUOY/+2?=
 =?us-ascii?Q?N6LDF9krgJpIcCpPnWZt3/lafZh2w7pOSFdqV6POb/KYoKqF4DnnwjxL+Z36?=
 =?us-ascii?Q?KCyW57Z44PqGmv9rx9FyScu7mjOyvrHW9NSZg8cgvQBeyTW6vdHrrY5zijAo?=
 =?us-ascii?Q?sjkI4tq9mrseCkP7g6Qazix7vLtCA8SuBwuI2cVmeBgc8i079surcLtZRf6e?=
 =?us-ascii?Q?Bxi10nt3T1z1fMUuEA92qu3R9JsPvadzO6HcU6C/3WtxxsL1EePbrwnc2M/V?=
 =?us-ascii?Q?n/2RqKrx1j/Utq/C6wlolBSacMVyJDX/SnsnmAnXvB6qAhZrm2SYtVS18gqn?=
 =?us-ascii?Q?OROjKkavaBvGAkcB8zSkAttu/oxLNoy7pe/048e6JRStLAMyUeHHyz/+16I+?=
 =?us-ascii?Q?jeNSQnj+G5iFtpK6TLUxumT25ItUmpwmxQs1Lv2PU4ow+RVqOZSP/+0ieXOv?=
 =?us-ascii?Q?z/xtL/KNVQTCkhZ2Dg09bL19xo48crj5d58HcRfBt0kyBkEiLce+SZDp87yX?=
 =?us-ascii?Q?LUOMz4MEV/n1/g7bMb3CLBNS6fY+Xe45XNBbQZ3oFm33+gws0Nqijvr+giG6?=
 =?us-ascii?Q?5QFJa6RVZgIYYXr9VUHj8PTARG7xEwoj9hCLT94MP+jYb2fkZ+04i0WAVB2q?=
 =?us-ascii?Q?3TH8b8K7ENt8aPjWFAymFMkujWQU3eCoc0nsi1Unq15SnMI3tXIS+gAoXjxO?=
 =?us-ascii?Q?r3CHNfwkgAxzcwpWj/jOA16TG8tnhnAaGc4sq/yZRqPbRadrGJ5nFvlc/Swu?=
 =?us-ascii?Q?9QOIh1rjwnx+hB/lh7i471ZjIUGnJD9jt1ccBVWre3AuWq0rQkosOuU+6/Fm?=
 =?us-ascii?Q?0AMpsps+V1P9OpG97Fl2FnC0hihdSvNdh1USYsIjjLubQ7HpN8rP96mI+fRy?=
 =?us-ascii?Q?BgHqdWRxcGRK01WyXGxVmdN/IdtYQOzbNxV7jT7YCW0Sz8zSSjUlSn4wkYOP?=
 =?us-ascii?Q?CWruFw+PNfz3JIHfNUbICdWTx6rDJ1SNN4vPyPCBKgs2lrD1K2hY2e2IfEAw?=
 =?us-ascii?Q?yX/jSBIjjqdonlUCoTaKeiK3S0CtJO651t/9eI2tvnPC1ILtUkjOHrt5vpTv?=
 =?us-ascii?Q?2PYw4ArzMj9e6/eSRfHxvTygIBecEIg8hWZ15029VFlN3ZkkMAcR89v4O0FP?=
 =?us-ascii?Q?tuDYSfWRNsgTQiqmQhretxvDETr7mK17CiJAByvjSweescXgvzuCk8+F8TC3?=
 =?us-ascii?Q?Hw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: uUcUXiX+kJ1gjxVzAwzrHlGcW64V5mOBed2mkCeIDaCBhqiWyKyCKLZVKawK5cXu5VhKWMTbi+cBWxSWki5whXDCRA7gAZodFa6uFTnkQKIlEkjm1IR3xs/OOCUyLbBI41zWClhIMaReEIS06IUEKZn4ZR3KBYrl7D1RBDx3DOn3jb7KIm3n8Fyb9FMisuVA8heCT2q8NOtvI6XZ2GcffkCnC+lk46IFs3M2tzU36o0k6gij+827LAU8xc+hKp++qvBQAC/k+jsZOUb8KN72J61iqM+TEdJr9aeHdK4pTewb2lQ4/v2tMdzcrmnqNwNX4rMY/NFiQ3GjHrLEjj/l50Z7EOQ3jrL/Y2cIyAAlZmSSFa2OpBBGUCQHb5L2xu0vwO3b3WvctP+aTnu/jp3ikwP7BlAYBoQlYrzppado7k4tzU5g1Yr1FYiSj5i7Aphb8sMT9s3GK8OQBnB7JOb1biUeYMtuadZqvwX7uH7eojGxIqxpZGF+B3mTtHZ622YwHxp4Loh3Jbymryh5PW83W8UMlRDeDPFLCbrY0mo3+MdEshVeC8Vu2iip0+0tCn/Zaz18B4oLR6V1/tCrxB+db4n0TomsSeYTmx45s/Up6J8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d3b508f6-bffd-4656-45f1-08ddeeda501c
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:19:17.2648
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: uzS2Y5s4KexMsdva0kHUIrHXWXr8/MtjxUaZPK+3Ksm7cTHEizy+PN7ikmCzFhWqAjOWRk60TPKWVHSZTPjggDP6T7uAD1UnovryvhwRLB4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8465
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080133
X-Proofpoint-ORIG-GUID: aIIXxOv_6SmHByCTNzYghha79p10htNo
X-Proofpoint-GUID: aIIXxOv_6SmHByCTNzYghha79p10htNo
X-Authority-Analysis: v=2.4 cv=KJFaDEFo c=1 sm=1 tr=0 ts=68bed7d9 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=Ikd4Dj_1AAAA:8
 a=sd7PVl68wqFViJiyaNUA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExNyBTYWx0ZWRfXz57I7/vzJCpy
 vCt8X+NtVWxiiSE54pgz93LpGQ6QmxS6w0FgdQtI9szWu0I+XREdF8ifhKQ+Op9mVdxWDwi3/Oo
 PA9dim1ylM2HJfojmXyEuG8U2EeQa3IZ2+T8kze+IzOPVhnI2tY2To3MvfXatV+e+K/QFv2cppN
 AdGSKj5Wr+YyFofIFrxLUTlUKgTvgphRstGCLhVewzj9tABUcO68KqI8MXQ7h6hp/ratgtkGJXi
 OsL4nqIX4jx7CN0hanIJDMlEV2NSULrTOaowfIhB5r9KyJW75QiGNJsPensdVC3hmJg1d7aKKei
 nndGGxO2qcySnivUOkKb6xZO5TUdkUWItUf6GFA1NEiw4lQHZcz9FBF8hZTwTVjBxsO+0fgwNRN
 elbDxzHVoyGSkCdI5pntfp9d9mTWMw==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=i3qlpWmh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=XV2pbl8d;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 09:55:26AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 08, 2025 at 12:10:37PM +0100, Lorenzo Stoakes wrote:
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
>
> The commit message should call out if this has fixed the race
> condition with unmap mapping range and prepopulation in mmap()..

To be claer, this isn't the intent of the series, the intent is to make it
possible for mmap_prepare to replace mmap. This is just a bonus :)

Looking at the discussion in [0] it seems the issue was that .mmap() is
called before the vma is actually correctly inserted into the maple tree.

This is no longer the case, we call .mmap_complete() once the VMA is fully
established, but before releasing the VMA/mmap write lock.

This should, presumably, resolve the race as stated?

I can add some blurb about this yes.


[0]:https://lore.kernel.org/linux-mm/20250801162930.GB184255@nvidia.com/


>
> > @@ -793,6 +793,11 @@ struct vm_area_desc {
> >  	/* Write-only fields. */
> >  	const struct vm_operations_struct *vm_ops;
> >  	void *private_data;
> > +	/*
> > +	 * A user-defined field, value will be passed to mmap_complete,
> > +	 * mmap_abort.
> > +	 */
> > +	void *mmap_context;
>
> Seem strange, private_data and mmap_context? Something actually needs
> both?

We are now doing something _new_ - we're splitting an operation that was
never split before.

Before a hook implementor could rely on there being state throughout the
_entire_ operation. But now they can't.

And they may already be putting context into private_data, which then gets
put into vma->vm_private_data for a VMA added to the maple tree and made
accessible.

So it is appropriate and convenient to allow for the transfer of state
between the two, and I already implement logic that does this.

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0df59b0c-dd8d-4087-9ddf-3659326f57e9%40lucifer.local.
