Return-Path: <kasan-dev+bncBD6LBUWO5UMBBZHAUXDAMGQEN5EJFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 306B1B59902
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 16:12:54 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-77253535b2csf5056276b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 07:12:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758031972; cv=pass;
        d=google.com; s=arc-20240605;
        b=kPSaMqchMPuqsUW13QUHHd3n7x1LMiZGcxdJi7/PeGygP/FcmI6LvGBKa1QmYLdYnA
         +9A9J8REC2XFRJmpN2hNiys6tvAlo4tf3lHE20qg9B2TufzbTamxUlRygmaEYBHomjOu
         1MR2Aaij+VF9mZizOEsg7SvSU3ccHSSK3R5/ybf+YOrqhMRCMvNg30IOA5t3F1N7ePV0
         MEIIik/xrhCr21wc0lNd3nXhMMZ3XJFvvF9lZgDSAPbjGEduT/Gt+ojCSEb+6fXRgtVb
         3cVm4YLjiLZzG0ZZFMSi/BQv+sH7IavpR3Lf3N1wC5PFIQyI2UVJPwT7l2zXW6GNN1vh
         jdjg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7oZKdRQVsqp4HQXuvvIPVThGqRl+ok/R67XDEU/3arQ=;
        fh=FOt17YdPG/N/YYeWKpqr12IkK6zgQhXqGULO7GgX0m0=;
        b=RXsY/SxmxAGmtjvQjGIikcA0QpWJntbttoCCQZOqSwanipLbuiCKvNax/co9B7BpCL
         ylS9+Pq/vgv31+Od3I5zca2XzpB79OzGoAqC9ZT7mlgXST2TXZT07mlUjf23KUvvrN1y
         NZHVCBtwRGhebsUhTfQD2s6fcTPq+2L/soYWGUh/qsig7ve2bqzNVX+ANl1mTI8ZQ6b8
         dOGSgzFHmvNynUM6gRukaTxdVq1YaKzZEHn0XfcNtzzW3mf+TO+D146nqTkMfg1cjZok
         MVm7y4fyK8xCjIWuOpPYiRS3gB6I399pptfORW4jiLIGDcvyWL6aWsA1v7zZltbnY9jn
         VVsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cympv2lc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="k/hNoVaF";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758031972; x=1758636772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7oZKdRQVsqp4HQXuvvIPVThGqRl+ok/R67XDEU/3arQ=;
        b=a50+OmmV3AdpDJGWHI6ALKHyT66tu/oqIw0+XPw+6PL0+3D6di9jkbt8d9r3jUP4vF
         s/kQRimiPlWpHRVrZATmZ2tvxZtNuMcIpxAVIo5zCsvNMi4gw8NzKfk0vyqW+KuCSrlD
         2vgffZMqRFRb0yjPbG5rATB25RzYSo/t6M4Witm1QbQgIQCFLIMT7CQGQBR2gMhkcdAx
         P9zfkmZ9lboSK05UFSTA38E3yanBsIb990wH8BN/P8+6bR/cRMwXAeBQDGfX2y9t6drO
         Xc3U98NJftT+MVYN95EQRuVvfg61YUQOUxef4UeJRst17O4kr2ExcMl07K17Atsn5ifj
         1jTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758031972; x=1758636772;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7oZKdRQVsqp4HQXuvvIPVThGqRl+ok/R67XDEU/3arQ=;
        b=mcvQy0WASZBVNfVOH5MaUwWQ9QUjMINzcr3Qr+ilrAepMu26KJEc/6Pv23ssPjvOBx
         aA1Ex6J3UPcsd+K3JkzqSLjqNQIbBMOZtp/yuLsn7qUnuhTpZc8tO3YKkQvxBKY5PfwF
         g1HeFKkHEenSRmTwjJh/mJuzTvsYtRLMYgWX2nX40lI8NPsjrKqWBEtalE48aZf5WsHn
         dEqpP+oKJ/JW4TrzW4+pFSrB/8cd0girk1MWnqCwwe9CU9W3xdeX8t3VzudvhJLecWd2
         PPMKaRcayZzK+OfTeUHUrGZzuRbQWnOlIf/Vuaz3F64imlnZSpNU5FAE1zzEJT7wbaW5
         rWBA==
X-Forwarded-Encrypted: i=3; AJvYcCXKF0TVQwO7FGas+MLSgyhrPk1XtU6Uzd19d7LYqo6ArJv442U9pSsig1YwXNP98ZxhcrUa7A==@lfdr.de
X-Gm-Message-State: AOJu0YzA+BfDWe9QnY+wM6XdJuTM/Tc3Shz/UB6hDm1LCG8zfFvc2raf
	qC21yzoUO/BlbkwpyqQCIZcCstyOowJ3RO+BhtvqG8kiwtzn9kEeprA7
X-Google-Smtp-Source: AGHT+IFQXuXlz784th5hnrzfqI7Q5g9hzehmt7ds3H2XVrT636WuUke7DCsWNeekrlS+CI9gVvZoLw==
X-Received: by 2002:a05:6a20:6726:b0:24d:6501:b49c with SMTP id adf61e73a8af0-2602bb594a4mr16752845637.29.1758031972392;
        Tue, 16 Sep 2025 07:12:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6K5PngVMjE0oQyiiGsnagMs+MRiSNUptfgbZLehwP/Jg==
Received: by 2002:a17:90b:278e:b0:31e:cf05:e731 with SMTP id
 98e67ed59e1d1-32e64cce2d4ls2105995a91.0.-pod-prod-07-us; Tue, 16 Sep 2025
 07:12:51 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVJdX4OB2rfkAIa+bMRuNJEC9wZsMaQHiJR9rOyNuCfKPG9H1Mvp6yyE8SFe7DPnXn9aUdzVxkj6Zw=@googlegroups.com
X-Received: by 2002:a05:6a21:90d:b0:262:1611:6513 with SMTP id adf61e73a8af0-2621611673dmr11206880637.49.1758031970728;
        Tue, 16 Sep 2025 07:12:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758031970; cv=pass;
        d=google.com; s=arc-20240605;
        b=dw01Ol04bU30ytUn9RoGuXfnida+g7nyZ8bR4t8Yj3on6tD3kHhU02e1fRgr43O9gp
         A8M6i22utO+ryDwd4qbUrHyR2pxGNf/riehaj5jA3UgYeCFA8h1jHOdlhZ7lA8ssp+VW
         pzyqOJtGzIuUzTr2zetQmu+7IisGqPe1S4Nq66xHaG+3KpJAYPrEJ0ALIx4hfwz8DnN3
         Tb8b4ULWRvtXGXosyyyvAng0BMsQdILbpIZR1u8hvGybsEByV1+cWqTyTIKuA7gQRmcg
         VrNgBQmxZkLGk5sMbvnIpFKjoB5VOaYkvAxDuPNg1awwpO9ApE4G9OoWpN/LhIpwnKjj
         VhjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=4n1tbqjxTyyQO0i7/XhuJt46u8uzfK+br2j5/R1a5pU=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=CaoPqOYu5rSbOTzvJxV+9fH/8YiCVGzRdD/14fH7QzGGEfaPUHvd80d02tnB1C1nxb
         LbYMejriCbglyw3pu2Ro0FqdW22L4nwHyn0Yso/ge8NY8sfTxjr+Pq/nzq1359YcEZPF
         XMc20w0aTAmoRFBuVZ8/UvKLfhdBh9eM1ECV84hKqlCeJclY1oPnhTAPRuPsE2BqRonP
         Mp1IguVpS90HU58zvgGQgSi9l0PCGiC/hf5RPUxEl9V0+vTadt4S75xYSzybLXJl1cro
         247j4Z8CkuNGYEPLb8RlPEEiUmEXhNsoBI6PA5djLOPRRA5CcnAzAA9qLOMXuoHLXdEJ
         z/fw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=cympv2lc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="k/hNoVaF";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ea08553fasi85585a91.0.2025.09.16.07.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 07:12:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GCecqn003101;
	Tue, 16 Sep 2025 14:12:39 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4950nf4tgk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:39 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GDXMaM027287;
	Tue, 16 Sep 2025 14:12:38 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012012.outbound.protection.outlook.com [40.107.209.12])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2jqp6t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:38 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yl+0b81Vb71I2jmvrkhWUQo1ID3dhVu6jLp47sX3wLLa2T/78Hw/Va+V/WUAGLnImF/XOYgyDt5HfIZoPswkfZipNfLwU8VY4jXCnJfqW9BY9/foPlNel783UQ6Ve+mkPwBAWeoWCF0WA41TA2PayM7SPBrv8N7hG+n1DgMr3zt9Iqh9zwr/HcJD6jp5FVBz28/+J9+R3qcfoZAYuQoQzP0vrKwB9CSAOyFzfyfeQPGTtaN1j7qeUMyyiOc/Vv+OlP082OGypCJ9PFBbPecGQUJ2uNcNBPx66loDXa1cKjAII9a4GscWQuhp9wKBcYQh24AylphoZpNElJeNAvNg3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4n1tbqjxTyyQO0i7/XhuJt46u8uzfK+br2j5/R1a5pU=;
 b=OVlYbaxUdKQFVlZ01klxLNriytr2K2LJSlD8Khlkiwa8LLyafzlmPUqCoW897JB92Zr74xsaT9di+JeJZhsR88ntyTsXDRsApENPb/df5TAGOIwXYqimchEiI/GD8ebqECR9WCmg6woiSxgV1QtIQsgi9xfB8upQ2IJwVF/wJotTTYeGl+reDFJu7zVT+oL/cluz5zi8t1BPvqhaERrJuYb+M//L2h07d51z8uwA+oshX0c58pYsjS/8BsIdbrEUsHOa+oc3XcXVp01+BpIWhpOUdv3yjK8GidEBaD/DX3xz00Y4sIQpuwBx2oVH6JZq54j4d6iL3V4V3sJx5ylsdQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by LV3PR10MB8108.namprd10.prod.outlook.com (2603:10b6:408:28b::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 14:12:35 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 14:12:35 +0000
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: [PATCH v3 02/13] device/dax: update devdax to use mmap_prepare
Date: Tue, 16 Sep 2025 15:11:48 +0100
Message-ID: <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0330.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18c::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|LV3PR10MB8108:EE_
X-MS-Office365-Filtering-Correlation-Id: 3b39e555-793f-4b3c-bd07-08ddf52b156f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?eXSfR65ME9QvPFSZ6dVO4dEMMT04xTlF5unzktVSLevr/rZfeUvKtjKS25Va?=
 =?us-ascii?Q?quZYmx0mbrTEen0bRRr1YByaIjq2hIP9kIGOhfYpkad2iHtjyY2KiP1/zXMy?=
 =?us-ascii?Q?WPUgxWVQzIGf7yu8Z/eBOoewJRo69iAzhUU7mrxoNKXWR8WMHWWn8UdG2Bl/?=
 =?us-ascii?Q?tSJvuXQz4BdR951VcpjIhjxWC0FgerYtgn4IQPxyvGInTHpaXnaHFloYTBQK?=
 =?us-ascii?Q?Nw+jK1TNTnfxZbKb5iwBcT6lGgktsmZLgzzaWb1vn6zgXJGbQ6Oz0Y//JQM6?=
 =?us-ascii?Q?Y+/Aq5UTRzzls80VFoSnmQkcgNT/nQv5bvJ7whzoc3CMxsheOdQXsmKsfjGV?=
 =?us-ascii?Q?tAy+kArA4XsKSGABb5ujYVYDX1kLZXMro/MnApWecLQHQ5MO489Qb1CrT3DA?=
 =?us-ascii?Q?no0Al/D99vWQuTfZYxYEdYUP+UlHw56KWpulHonu7eXVTQcer02mAtkc05yU?=
 =?us-ascii?Q?hOslFkjaPWLqRexVGvFyLkDRHoAqKRQdMPDGKUYX6I3rm9pOyyceAcI6aoom?=
 =?us-ascii?Q?6P4FWe6z12RbckMtK1AHALN75egmNO75kH240kM2wQLSvxkGimUp1qzx062g?=
 =?us-ascii?Q?Yjx0fmvWKPj2FfHvQNDbEXebc/tM3LO30Cpx1auL3l9PwiYtKxvf7mThB6v7?=
 =?us-ascii?Q?lYHfWj6FUDpjjccZcEkkJFkGdEOBftMGDae+qtpJujmVezFp/rA1M2ZJ0I/H?=
 =?us-ascii?Q?9MMzz1nzG1KO9b8cZbPpKmo7b1m93JTOkpN3nboaTLiAwvsVUftOWER+05bc?=
 =?us-ascii?Q?rYH8jCpxSsIVKOmNYKIB4hOvnBY+qWrHZj9Yp6oF94bvodyijdBa7R62YGPe?=
 =?us-ascii?Q?npePt3eV/U6Shsi0u3j+K95XPK4pyjnGxgmOx+0M2vPrq7c6mLtzjQ1eKFkK?=
 =?us-ascii?Q?DH6NdQkpj7ATCeE+aCQ0xp0E9Ob9D0DY4bkdmfewhDJUPEer8JshVPa0gRpF?=
 =?us-ascii?Q?SUTMRxtKiwRGvG+ww6Udv2JTK+aLfuA6FPEkV7rSdqwx0Zy1Nm8IR6Mmb+Ns?=
 =?us-ascii?Q?tJ5RWC43hMBJT6Nt0jt55mCRFmNgkbCdcGfhODJFA7xQTZdsQV93kRKsylMs?=
 =?us-ascii?Q?vlBE+vlcRkKiLjmyqUv5CQiaaHMzxvU1OMhg8P/HcNJ3pQzfNyjgXzBECEkO?=
 =?us-ascii?Q?6O7+0HqNS+3BXjhWaXT3CFVbkxxbfWIMkQV6N5Oymaxj+0pKZFE/CgvhI00A?=
 =?us-ascii?Q?M7Ih1v9wthOQuF+jAJFlXEh/K1wFpqYAZSVfha+IBE5ElSSxkgeX3PKfCvOi?=
 =?us-ascii?Q?kcQnONNtKWNIBjFxvxamzIhkNrIL0G0BIpKghVJ0R9Sml+ZkfrrN8WzKwtbJ?=
 =?us-ascii?Q?3jHu2j2ZeAyTzWV6N7lfLVILwcDDTuovhqX44QroMUb4OG3QRoVNZ7JZfNdK?=
 =?us-ascii?Q?gywZXrwapgyiA9rLCU8qsqH5aeE2xUBmcZuPjy6fqdzrSAskITBqEInywGvj?=
 =?us-ascii?Q?e0VsFPUfjw8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?02FPCzrsFU/5airkN1607SCZcSeELJMSNm++EmDxaJ59ujkShT4uFRzJim9M?=
 =?us-ascii?Q?3oT6gUDK6/auBSmPQ5i86U4mFIhsC67OZBtppjKbqZ+xDABF46rfBUNxPPFS?=
 =?us-ascii?Q?cgKu2gxqCwIyjoacoUSKlSQxTmYyrMkn5RL3qMeRKkJ1URizCz6+UEifsJEz?=
 =?us-ascii?Q?WyzzZy/OM0sFZGFJ9gEI6Jbnig7FbeiuxG3+kNct+gH9xosrQsw3W+aqXwG5?=
 =?us-ascii?Q?aW2Xb9mBtESCWgbT6F7l8oXHr2nlJx+IAmXyql7aI7etf9Lq9Z+0umf7pw3N?=
 =?us-ascii?Q?iYmiHwKjTayHQRrl0LC3EmMPFtYgvxRHza4PdTNjQ2kgXf76CfiJpylXMi9v?=
 =?us-ascii?Q?FJXdOSalE788cXskRTy1qXMj+EPOuv/QkhgPPyosHJMyaK6Xj7/jcBr2gRii?=
 =?us-ascii?Q?gNzYbcxpQki19jy8hI3KcE4GKsnmQpokUJOG6V24f/Jw7eZYxmv/YK9oGaXu?=
 =?us-ascii?Q?/OY75L2BEkJybzzTBZyfeQFYZMs582PsjOYt2mpgNmUmRpGZA3HQ+AMbV2HG?=
 =?us-ascii?Q?xC9PGOGJEpPB07rhBUjk9x3TVemRJyGwFlKWoYhCa4//H/qdY4x0gGVZOLR/?=
 =?us-ascii?Q?L75nYsaAdGWq8gGpdPwT40r3/ZByXaqtqJJKGd4M0zQdbNBxdF1hJjPoi93f?=
 =?us-ascii?Q?bPBQ2D2q/eN1qAem12b4PTo39vZ4/vA3LoY74sGil2/SN3B47KcVJVVoa4ca?=
 =?us-ascii?Q?vYy9N2HCSWYgCzRQr6f/28uJ+Rd/6/aQ334s69l+kv6G6k575IpjU5qZ6bSL?=
 =?us-ascii?Q?tYnZTQSfQWfzUF8pZoHRRDiyfnz4bJ+MvW6zs5xHUgOrcR4fXKTnSGZVsoRh?=
 =?us-ascii?Q?IYjOogrrHU9Lo50OyOiquPgaLF+01Yr3/dJwh+aQ3Qc+W2tjKMepwgmUWmiA?=
 =?us-ascii?Q?0G12uA4D+wjSLvF9nzKYY2WKnuRZBAzZlI6KcWc/VmeBxKMrKVEqFr2h4nxv?=
 =?us-ascii?Q?ZWPBr/OEvQ9UAc+NVd1Ozu/so/lqXZH+lCi9Nxl83LX6CsMoNqMNrl9KpIy5?=
 =?us-ascii?Q?Py4aVxJn0sr5pbTT7ZkEoWvrhY9GkhsCceJ12MPq2nA6p1+2Bmkan28VB1tC?=
 =?us-ascii?Q?Sw4AinSJGjmYI1XWNNsWWftqHJ+2V8E1NvnIna2XRv+/V3VvFE90qHLZ06Wz?=
 =?us-ascii?Q?IhTrPQfu/yf4Y96KfTKsxFO8zwhtyOuaPanO8W6YLxbBdSTFtdfWCwA0n+x0?=
 =?us-ascii?Q?vazP8otr7MWwgqTiGIFHGhYAVUDcZRMmfKKHOsuhYmhcFKpLJkNGeT4cN6vz?=
 =?us-ascii?Q?I6N/3BjNYuqh1x6yudIOMogSfTi7tDLQIJs4ZrgWDmG+x/2aKexnz8uvT2pT?=
 =?us-ascii?Q?32dGqImEF6JNPF8UlT/RkdrOqLE6mw0YtuGtqV57N+B6E0sQIa0pefnOY762?=
 =?us-ascii?Q?BAj/EJztpC42wqEOyXAni8WuSIaKi13nSQ77vgmPN9tyv+uc96p35RjEbzCx?=
 =?us-ascii?Q?XBLhmiCZls20MGgzzIHzp28sA9mpb16JP0h5KcBtSB1h7k4kZnZCxsuc+SgI?=
 =?us-ascii?Q?LZnMs1CreTaRdD/wAnI89sabrOS2gJ2ew2im0J6gFasIlhR5xBXMl3nLQx7z?=
 =?us-ascii?Q?7V2dkTOS91gvUS4xNKnxdT6wo47ToMcJTKEc1uvmM5fU+N0xEDSagW9UnQO0?=
 =?us-ascii?Q?mg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6OIXxobW4ox755PsjgSlu9FipLxrH2kaGzzpIFcZtF31543h9Wn75nLYz32wNZUgZ/i0ymrf7SPaZyQG/xvAjqXk0LJ+l4+gNbserpUP8nnGS1wTchdaV0fEUfooieAMoy+z97t3TnsJ/E/OxG9X32oNnApNNbETVz4/b1eoAx8ndYFGmqMNYRp/51cB0ByPOw8bRfSV2pINiO8D2RzT1yoOkJrjouByCZSshGHEhGtJ9fzju1Ci80/glEimlQ6HE4ST9wAIo6C9A5VZc108IrNsAvlsnDSJuCgRxk4H82r+5jR3rdhfmPaYl6KnmRiTd3UGK5FoAdEQkHSR6WgUlKmOL2tsueUqRyL6HW5GX1fFotbIwqnv540bBTw54Pw0g8tLSYHFVgIBD7xFMIb7tQETQ1vxTB/vu+a4DzYQodt5roFO65QRs1zzifryH/6dk97YKfATBjuiCEpfb1ttIZuAAHPXxMbYmtRmtCLtvD7vL95XpFwkchnf9NZGlNQyRie4spuow2JsYDZ7jb67xzOW5xkWM3dKKDcH2DXr+sp95n9IYc0dC9qJMDJDre2h+05wiP24MWBprgqxEin3sCIzImXTBNxaKB5+8un+Lso=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3b39e555-793f-4b3c-bd07-08ddf52b156f
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 14:12:35.0238
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: JK36UE3XTaH7XSTc4DY/Zv73Yo9TXUfQUv61fvM73/0Wup0kxM2TRG51MjeuL+CtdLh+/gtrEemgjE3/6wkUrghGDglt2/ZoqBYM0p5Ggjc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB8108
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0
 mlxlogscore=999 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509160131
X-Authority-Analysis: v=2.4 cv=S7vZwJsP c=1 sm=1 tr=0 ts=68c97057 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=PCzo9pqqgWVvJ042w5QA:9
 cc=ntf awl=host:12083
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyOSBTYWx0ZWRfX6jqrq+fhMkBP
 U4gkinsty1gsJUvzQrF8QWLguKtJGea4j5o7qWAWTStJQ1IBUaS9Yn95xb4UEBJaWQ8zpWns30e
 e8S8s+vZzizpCfJV9ei4jSuqG3SQYyVesdLX7tiCOXs0vw4R71bJN1xyQncBH1Kma5ITMGg/38N
 3mz/kXBS96fLSpwobCkggweOEovTOCiZYJMvvW0oXZ/8ZtWjBqtyzWdRIi43xjqprRm4+3GEJgJ
 H84G6/pjV0+YIJNOJwwDM2WfU1JDrIgpQ1It97ncTiICrCRNjazfGGfFoMXBrNTofWsHkHv3s+c
 GUb/Egxi8re86IV2KPS1Dw/y4SM30Q8sttfi7AWfxthSCHth2S8jNbrypCHaV83nxUlXwH1bq/r
 pXjm3SDDDbm1D8iei8LhSKn3dSLkJg==
X-Proofpoint-ORIG-GUID: qLplfE7WJkhGpYLhnoW8ohC1RC3MKff8
X-Proofpoint-GUID: qLplfE7WJkhGpYLhnoW8ohC1RC3MKff8
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=cympv2lc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="k/hNoVaF";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

The devdax driver does nothing special in its f_op->mmap hook, so
straightforwardly update it to use the mmap_prepare hook instead.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: David Hildenbrand <david@redhat.com>
Reviewed-by: Jan Kara <jack@suse.cz>
---
 drivers/dax/device.c | 32 +++++++++++++++++++++-----------
 1 file changed, 21 insertions(+), 11 deletions(-)

diff --git a/drivers/dax/device.c b/drivers/dax/device.c
index 2bb40a6060af..c2181439f925 100644
--- a/drivers/dax/device.c
+++ b/drivers/dax/device.c
@@ -13,8 +13,9 @@
 #include "dax-private.h"
 #include "bus.h"
 
-static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
-		const char *func)
+static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
+		       unsigned long start, unsigned long end, struct file *file,
+		       const char *func)
 {
 	struct device *dev = &dev_dax->dev;
 	unsigned long mask;
@@ -23,7 +24,7 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 		return -ENXIO;
 
 	/* prevent private mappings from being established */
-	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
+	if ((vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, attempted private mapping\n",
 				current->comm, func);
@@ -31,15 +32,15 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	}
 
 	mask = dev_dax->align - 1;
-	if (vma->vm_start & mask || vma->vm_end & mask) {
+	if (start & mask || end & mask) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, unaligned vma (%#lx - %#lx, %#lx)\n",
-				current->comm, func, vma->vm_start, vma->vm_end,
+				current->comm, func, start, end,
 				mask);
 		return -EINVAL;
 	}
 
-	if (!vma_is_dax(vma)) {
+	if (!file_is_dax(file)) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, vma is not DAX capable\n",
 				current->comm, func);
@@ -49,6 +50,13 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	return 0;
 }
 
+static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
+		     const char *func)
+{
+	return __check_vma(dev_dax, vma->vm_flags, vma->vm_start, vma->vm_end,
+			   vma->vm_file, func);
+}
+
 /* see "strong" declaration in tools/testing/nvdimm/dax-dev.c */
 __weak phys_addr_t dax_pgoff_to_phys(struct dev_dax *dev_dax, pgoff_t pgoff,
 		unsigned long size)
@@ -285,8 +293,9 @@ static const struct vm_operations_struct dax_vm_ops = {
 	.pagesize = dev_dax_pagesize,
 };
 
-static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
+static int dax_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *filp = desc->file;
 	struct dev_dax *dev_dax = filp->private_data;
 	int rc, id;
 
@@ -297,13 +306,14 @@ static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
 	 * fault time.
 	 */
 	id = dax_read_lock();
-	rc = check_vma(dev_dax, vma, __func__);
+	rc = __check_vma(dev_dax, desc->vm_flags, desc->start, desc->end, filp,
+			 __func__);
 	dax_read_unlock(id);
 	if (rc)
 		return rc;
 
-	vma->vm_ops = &dax_vm_ops;
-	vm_flags_set(vma, VM_HUGEPAGE);
+	desc->vm_ops = &dax_vm_ops;
+	desc->vm_flags |= VM_HUGEPAGE;
 	return 0;
 }
 
@@ -377,7 +387,7 @@ static const struct file_operations dax_fops = {
 	.open = dax_open,
 	.release = dax_release,
 	.get_unmapped_area = dax_get_unmapped_area,
-	.mmap = dax_mmap,
+	.mmap_prepare = dax_mmap_prepare,
 	.fop_flags = FOP_MMAP_SYNC,
 };
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes%40oracle.com.
