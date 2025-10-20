Return-Path: <kasan-dev+bncBD6LBUWO5UMBBKWO3DDQMGQE53MEQGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D794ABF1022
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:27 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-430d7ace0ddsf16804225ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962346; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mi7P9BNlfgnBwU2iaiG+nRHwmyeTCuS6BxoTP2v0rB+SmhOqJy84732AylvbmM+RHh
         z3rOzpqDn6hw6dfiTGIGdk+W/3MVCUJg4pg9WdqzW71tLkWoBJ5di+76qtd4mLooPM5k
         qAcp/uRMW3lrJUxOwZqtnTs87171OeyVdKSSfoIde4+kQ4RROode26zR/EHc9xVVb8Io
         5czzp+O85ptaqMNiAyYM1bsiR4MCySuCrzSSqxYlwXX7QVdeajoxCS9hcEGG+XbO2U8y
         rKNS/uP3TeBWLKNSP/D20Ngfw3qxd+TZQnkfKbU+l4z8WEnrQo4oMP9tC1hJMfDGnyc0
         ZJLw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=EfJ7LEtGLoPOTWXoXoHwbArNC5s+3M4ZnSpawrtHEzM=;
        fh=SJw2ZHSyIDrdjvJiyoa2Hx2of4Apr6aqqHhIWQXhoXQ=;
        b=lrrjy9lIpuuRJ/Kt7+dveD6m520GrxqxvBAaOJu800EbZqEMBe29TTKR4VAc+pOIyS
         db6ZA9iAHHzYW1THLptVoB3J0nZDkQKSvXd59KYPYPJ4sD0FaQ0yb8+7atES5Eh5mPDT
         XqNWep5iiSTC23LniYq3MTxK3cSN4paBw7EtqsmHJvplqJ4LdO+W1gbEjdMRa+Oxem31
         ATzphV2Pygb74jB/+mgRVUWnBL/0KJYMNSXbmzqGHdTGXeXXkW+XiEVfgrRl5FWvOugT
         GLHKvWYifu53BJIbAHlSe4NQLXawObzN2kgF+ynac857l1shLKjSoH0AYnIP9HUi8G7Z
         z8Lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=EVexNXhN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DeaNG0oa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962346; x=1761567146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EfJ7LEtGLoPOTWXoXoHwbArNC5s+3M4ZnSpawrtHEzM=;
        b=j40TOXuuMNgyHfduZMGKbpD7iB0lbhnv9KsTRaeJG2cMTu6RHAw9N2PgKQ5xh7DIyj
         aqGjglOamGtb7rmsoP8v1wPl+swpAGkeSntn/VpHyav0VBSoHSHz5KswigdLJK/vII4m
         FZp9FuGgTh/M922K8tW7mgOH+El96+NxblPq7lK4BkpZn3pihV7s0Ce7SOBawx41XFNd
         E4bQKPnG6n8gQC0W9ZMFDnaH2d9VLK+uywR5n1thZsbzl4HaR2fTAjN2aFk68aNPdzcK
         o6wYqc/Jaj75tZ5zIEsmkbqdzXFr1DArdcRqCBgCgm5lzE8jD9yFrFZZLZYL6/Cyqzue
         3zYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962346; x=1761567146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EfJ7LEtGLoPOTWXoXoHwbArNC5s+3M4ZnSpawrtHEzM=;
        b=X+RS6gBnjzf9rc5mOBBLG5iU/vj+2Ck9rnn34otyyBNt1XAE3/5PswbjPr4sqaa5XB
         exE+TvFhJahtmbgDJPu4sYibg+Z/g3L63eQBuUl16wNNJBMRLS2eeW+yhhKzZRK47ubD
         nA5Ro9uNvFUeuZLFF9Bf32u8OPY2i70UJgeMUXq+s8s04FutxVMCRwwa+AGPvJXEi1e2
         jThIbkC45XsXERbf3An84FimLNhkWh9f5T1MEMRWwaLmQPkMo/Gan00RdZaUzGQzgnex
         SgxYvfzLU+HwXDMHFmRZN8mqa4QcNufcINCK8yYxhzuFfQq1wk3qUiQ0LV3n8qACin9f
         MBYw==
X-Forwarded-Encrypted: i=3; AJvYcCVU8qh+ThWD3QmlhCK84b59ooaSvzj36XAJwTaJwQdcTlgLDf6Snw6XxLNldaBaGX19Wb51oQ==@lfdr.de
X-Gm-Message-State: AOJu0YweiyZDwABcoYI/TyXdad/rLKdBIQb57AsdI7LHZGhsutXPrbRa
	q4EbpvXJm5RbrYpMgqvoqSePoDlZXsD5Z9BkNoFWXTKgpSbvOuqEb9jK
X-Google-Smtp-Source: AGHT+IEtDf88iqSFy/c7vthFqTlyRDGd0FbpxcfHXL/WIT/vgBrO/z2FvPKPkIfns9jVx/kbYT9m5A==
X-Received: by 2002:a05:6e02:3e06:b0:42f:94f5:4662 with SMTP id e9e14a558f8ab-430c527d356mr173989645ab.18.1760962346414;
        Mon, 20 Oct 2025 05:12:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6/+7rC99Psu2qCvhdI0Jl/VpeAk6cdgTRFActDTZctLw=="
Received: by 2002:a05:6e02:50a:b0:430:a5e3:5b57 with SMTP id
 e9e14a558f8ab-430b76e27c6ls35375005ab.1.-pod-prod-03-us; Mon, 20 Oct 2025
 05:12:25 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUhSEs+tRjTUo950ZcwqosYR6ByyXUdOMk+ZLHBQ4Jlw6b4MGuZECrhu9bWckGv+D1ILrb/g0/otpw=@googlegroups.com
X-Received: by 2002:a05:6e02:b43:b0:42e:72ee:4164 with SMTP id e9e14a558f8ab-430c528d9b2mr181558985ab.23.1760962345573;
        Mon, 20 Oct 2025 05:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962345; cv=pass;
        d=google.com; s=arc-20240605;
        b=KvugKL6a9AGZZoc0yLAgLt7T7zFeKKz6BhYQWeDWEz8VR4oIUVLn4F/ReBk2h3yThU
         P9TQjscD9cTrRRpAH5z98nP7kMcEmXEoSI25tykeGOixusJ7SGDLE2MrXMPKpr4Oi8KK
         pzrapdx5cc/juMkF1lLemHOrMPSuJBWcwCyrTCxfx/9a84zdJ9FabnzLDd0VU6sYq5+e
         ZqGWl2f8JTuiRjj5PrYc55UHJ8WHhdTgqKki4VrcbJ0pWWVMGIkGd9G3A1HMVlN3gkJE
         BdZfYWN1+mCxpLx/5cCWIlr0Dp538cnT6+r+OPJH6/oYx8LxbCIqy68jEIl1wUVSO01J
         xusQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=NllZZRB8yPovYXPAo2Hk2Gjm4hq0NgzvzjYEIa1h3fY=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=C0pAdO0iTgEYCokrxeib1ZtzH0uYxcoB1me5/f7SusKOwBLgjUk9YC1UVFjxlj2yp5
         GDAevrx4uVLdk/qNxRrEp/NT1wz7JDcUR7fQY9hbcw9k63EvQxQpCLApm7gBbib98/O8
         3jQh/CrmrVsfPOT5itV5IE5VBvEMDXQPPZXPxuRGF21jdItrXM8mdnD/o6lW3Wq493bU
         DopR8HEUJuc+pY8E78a/Xe5A/TpIkPYR/4rShAsTvdHhNHv32YtPf59/KqTIDK+CBeDC
         mkGdCrEfUicTrnMo7PhVE2kJwCGpNaZIdNpv9tsPqzkfG2raonNdczgntf0+TotlrtuF
         SDdg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=EVexNXhN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DeaNG0oa;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-430d07bb12bsi5731465ab.3.2025.10.20.05.12.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8SA9E018290;
	Mon, 20 Oct 2025 12:12:16 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2wat4hq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:15 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KBVZKp013696;
	Mon, 20 Oct 2025 12:12:14 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013000.outbound.protection.outlook.com [40.93.196.0])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bam2vw-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:14 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=TAAl4psX0lijjU769j+9eX9+pUmEwjVfVgU0aICBjAmNXrfXqqNuYrWsRFYl0qPoCsW1W7jghXUJTNEkFNy3pefoCSfR7nU/OM9UAdMR7rqAqzhm0YgJJaDgMYQbWR+7BWUFJ72gB80Y3sRxSoidujfTcI3qVY9j5tmA5Y5sGYYkfBwiZ7LfPNvqLglEbFR/VxNfNwPSsrVqTr0egLXXKDqMPQM0UTd9rPwzlckaz6q/W9k4dthMsdMm0dFs//X4cqzXiL6oQjDYrd+mXSR5u8pXj/r1GGmkGXvnlTH/yT5U+FBOSM4Wzctlk2LKcoEGYWOWHi5SfxaMhxXdyH2MoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NllZZRB8yPovYXPAo2Hk2Gjm4hq0NgzvzjYEIa1h3fY=;
 b=joh06G/IqWQnSbUITrEyPZEn19uEfukgfM25RRVyBTLCP757bP5A0AmQbYm/obKk9OPgNAnoJBKmyDf8g4cl1JE/PNwil+VvEMEEyjNXrbFck2/1P+shgu6aH4MANTJeIw1IfI23a3ccWZgdVMrhrqdh4AOZ2135UPlB7UE9ZSyoR/CsfQ7EKhVPMzqT3jSI9cFa0m0lgaQlwp92Wgml1eJ3kv3cxZbz/LDfqj3fRo6upBFI6QvMsik/n6NSpAUuYa+Spp58As0+M6fU5V1lOypf5wSnKmXR9cGOSZy0s4JFUmZDoDuIFA7nxR/Y5T8jl8gAAo9x/1qHK1kc7VYPsA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SN7PR10MB6364.namprd10.prod.outlook.com (2603:10b6:806:26c::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.16; Mon, 20 Oct
 2025 12:12:11 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:12:11 +0000
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
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
        Sumanth Korikkar <sumanthk@linux.ibm.com>
Subject: [PATCH v5 15/15] mm: update resctl to use mmap_prepare
Date: Mon, 20 Oct 2025 13:11:32 +0100
Message-ID: <95b28b066f37ca25f56fa9460a9367f1a866f88b.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO3P265CA0009.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:bb::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SN7PR10MB6364:EE_
X-MS-Office365-Filtering-Correlation-Id: 803ba0dd-912d-4b99-adfc-08de0fd1e5b5
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?r6AEBtkgdCboABB0nXn1T/7bG1/0RCDAVzVErCVee3511rTD8be6ca7VVY8Q?=
 =?us-ascii?Q?30csX8FJNXZ+6+8dGWGFQA3Sp/fZyME1KtoRBfbB66e6HjVVGIrsBJxLP2xO?=
 =?us-ascii?Q?BUctGqKBnVffkpYlYRpWQN6OL9jBDcX0qdd/OxlDKF56JSCW9K9486GtMTiG?=
 =?us-ascii?Q?mxjzlyqI2p+TZKhHmjaXZ206tIjr9RDhwSK++JFYMQwNrcg1U/i37FnXTl8U?=
 =?us-ascii?Q?P5+JfrfclUCzDm62Ow4i5TEJqFFdrwIhqqLS5udJQ+4FUROhmUVVYzzkxcLA?=
 =?us-ascii?Q?fY/wVPhjg0J1856c9VcSrRyv4YOtYpl7sB9j8O18mrZpwJNYZUJNhdQagYJ/?=
 =?us-ascii?Q?pPt+b/xZBs8P6STvaNkPUQN8U/PsBXy5LWzzMbv26dyXlP0p5u6OEAyfhqAn?=
 =?us-ascii?Q?tsqkfFw4RsCQhl7rgj/mmr8UYYETQ51Qxb0727qoJu3sFYqu5K5Ln0J39Zmr?=
 =?us-ascii?Q?Wj7QLWwQsAmIsAllx0xYhdHoGksztAEkhbjI9iu0ngBm67Pv2ukFl75gmIhG?=
 =?us-ascii?Q?bNgMc1V39iDqs80Dj4Xot0EN22PArmyCh+11yjMsDFngUubnHY/8GTHiHdOs?=
 =?us-ascii?Q?StH4tVFe3/z/YI2K787k8oAfvNQjrslOmCSkANMeq0X8cftEXUFZUjqZg+en?=
 =?us-ascii?Q?XRVqqyRg/1pLjXZco0ICGEb0CwT2Y6sCZYsfbHt1YaMDOyMhgQXn755OhJD1?=
 =?us-ascii?Q?iTsP5BPU7Lxev+wjOmxJgdIDnUObZyR/eiL8LM3pqePTgLjW53gYDz2zNkXN?=
 =?us-ascii?Q?DJu3P1IXGM87UJfAIHX2FnIa91izQZVmxabKPT/pVFGqrZPwhwj93S1gJ5FZ?=
 =?us-ascii?Q?3PLMdu8Qnxk/49HIOVpgsWaYUStHd1F7U5cT7bS17sTq1cjFkafG67ZKQGOi?=
 =?us-ascii?Q?gVkidIzz47z/heZitFXBbkRbJbPA4/p0WZO4epryzsLICyPonAQU3/ByivZ0?=
 =?us-ascii?Q?a8tb2txN5S8fji20arbEwNxuEgEkNif1bGwt3iHDrtnpHngrYrONyKInoQeT?=
 =?us-ascii?Q?LRtj55jpKvUAUzC94ItHWqhWUIttWAgRucYfENFj/lxfZhw6voWL+z7ae/zM?=
 =?us-ascii?Q?R7o/UlMyQLG1bdIXQnWesIOKlAiQctZ5/VIVd1E/cRpvXe3uMNXcTTxZ3lFb?=
 =?us-ascii?Q?RuHde8JiWeyCy3czvFhf9Qr9CTKVPOeSv5r18fsmtO0o8rj3mKV/aJYDN72N?=
 =?us-ascii?Q?sLYhQjza5+x+cEpGh+kPTzRq9z0EsT/KhIu0Wo4lGbNnLen2JF5hslU0Hjlq?=
 =?us-ascii?Q?phEhxk59oSyhUCMvU3U9w34IYYgEhNMyCQvtLuCCgRn1EbchYAp6kd7e9Dwa?=
 =?us-ascii?Q?mKNjR40s5Z03wQuG/zm0DruDO/9P+0QG8wL/oKeXaQGa/RwrhF3QlrBGFEVG?=
 =?us-ascii?Q?0USoZeLyDIwPQmZhcfNIU8xGQ0u3CF7gAptUwT85r43NU67Vp0Guhes1wowF?=
 =?us-ascii?Q?0Pk9jXRmbFOUpPkJImXAKOXCJDEllH3o?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?TuWvfWw3TsM7XpfpR/om0D39d8NsYqYMYUIv7+ycVsvZBvFffb3drgAWUZW6?=
 =?us-ascii?Q?EMEzE9NzFfpScpW4/USCHzwsEuJC7IujjLlGg/l772X0q6o9bvPcTWpu0893?=
 =?us-ascii?Q?fZC8v3MbjDF1ieSMM+26osCJCP4dMdEmf0iwUKKIgYNU0r1Yf5udWB/JYVQS?=
 =?us-ascii?Q?eCdIfJUmULuANYZq5jHG74e9p+vnBcBXJ9atp65FROhk2vwBaezjaN2pmPFP?=
 =?us-ascii?Q?HwZlDBijfa/ZtE06gbViptO7NGKfYNzvoXDtptGLGp8K/y8IDvSvN9/lpzj+?=
 =?us-ascii?Q?JSLoAIpvHdKpnix3cuSUKuvQEdDRz4gC37WhMFNTmJiqT4qImB/jgHJKORZD?=
 =?us-ascii?Q?qnj1ct7vB9+CxJwQQ8FyTbbqqEV/siJ5mSAwt8x5j4baJ9p6d5DAN1GCMLk3?=
 =?us-ascii?Q?dcf/8jNcu4eTQSZxZYY2lPyCwfq7nA38GJrnO0KveO3LNhH3NogfvihYzh8R?=
 =?us-ascii?Q?hRuCwOv258blBH0B1E4XgHQcCxl7Bbvwt8uUALn2QarYG5Oyuh+3qetxxJXC?=
 =?us-ascii?Q?8xfU1GUGF+HewBQpEVDBNnzA4sJirzQAtoonUfo7nsFVzDVjdi38V6EqwtW9?=
 =?us-ascii?Q?GTiJFeW51h+n8jLphMF4SCI8Qh3Fr1Xr23/aCsAr8PYgV2BTPsvOKZooe1BI?=
 =?us-ascii?Q?iHkFMX1ClqLvS8NcxIMeV+mwcwhuzV0BS4HmlwOVx6Dq5PHBndffZ93YHvrd?=
 =?us-ascii?Q?rFLyjkYXNg5Mi6ZBvmx1A54YT6ujFjfitc0dTxY3UeypXc3X4nXzgBSoNQ0N?=
 =?us-ascii?Q?6gjgikptvDKRKmjQZi3VqvY2wirnsry6MXYJKIuUg5o5P44OVCI6sch8u6Vl?=
 =?us-ascii?Q?DxWNLSTpuYASergXE+oSRt+WRh67BZ20GtJZov7bPo4YPWBgH1s1ZevHGPpf?=
 =?us-ascii?Q?mw/UPjRLz+58L/H7FZ6/sQe3qEt2TcytHBhBtun5k5EZUmjTQHn2msm07RUu?=
 =?us-ascii?Q?2LpeSa7zh23x/O9b7VcUg08U5fJ/SN+2sGXFMKDaeWQGg43t/25+msU6n1F9?=
 =?us-ascii?Q?4PO67dpa29G88hNJfh6+if373JmcGJwQuZaSPV01K7rThJy2USazpPRbzM4N?=
 =?us-ascii?Q?GB853GaC/pMHtMfziB71QsPG8MnA9pSua15dxWb5al3eZYkx/99X0CU0+mjY?=
 =?us-ascii?Q?xat/MxeQG7CdwUbX0+Y4mfWWR7jGyQHCGXk+XBT6OEXmKJGU9SoNKT7T3rsL?=
 =?us-ascii?Q?yBFEJ4GrqSERbUTzpHEisoheTIpsByNRt22Uzmr71Dc951kDmDvzt+dV/dXM?=
 =?us-ascii?Q?NJaWtfUzjrbXg+m4oBFruquoRXbY6lrApDkn8mWXC7eIraY2rw7sOWhogRsf?=
 =?us-ascii?Q?t22UQuKmgb9KlqltqGgbkktFp3iIwYbPod9DclOPUqLs6uEYIN9yZ0nZ43Xu?=
 =?us-ascii?Q?C1ZSVpuZeTB9lzf1Q4nug94/Cwy+wDW4pxQ3vZpwpVy+djGa0aPBbyXwq9P+?=
 =?us-ascii?Q?AJSzjvvEQRH3zLcTia3Y7r1arq3SUhwW6rYDhyoRf51WIRAqAE3T4bVx/H3T?=
 =?us-ascii?Q?x5ODmVq4K6oajZ3sv8g/n2ZDb+L1u/5ZW21fvxPwhXqNL2uENtjEVy2KA/QT?=
 =?us-ascii?Q?GW0NPjTBpBz7bXFWc5wjEo8pfDWMLaROVFQXS9czWejt0QrClkOiFIr2/sfd?=
 =?us-ascii?Q?CA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Z8L5spY2uMk3Md41zzlx5qx6gslDS0mMsh3Zrwn8fluB6OFynLbWL3OZEbOCU71U3HCYprg1/Q+iu04KGeHA6jLB4ZhfHODSMtQcNDdCBuy9Xj6hfAIlME1p2Z07+jpPi2KTnbD8Nceocjf1gMz0a14G0oBf8I/o0wQztgXOMHB9eyra5esE1fPB2MXbNxqF37g8rK7mFzFGSnfvMcnC4ZXUaTxVrNap1+8GrTgVvJ92YhHTRKvBxYoic1erQZXZ5Ov/sCrgNDyqmUtBZ9LawVHfenKNR0s8b8yI1u8yVyjq/1+6Ipt+0Kvyde+lSMjuETBE12WDr8qe3lVaX/j24PN8DBpBx5n8+nIwxbtuyFj6wz5Dznf6XL5jD9NYoIrT60HR8nhS4KLn5xi1iZ3PUVKuYcgvwuOlpw6+fQzmfngNmqK5Jt8z1T+t/uPYe9V3lWfdalnM0yWGyx2aUQ5A6SprHZVTSY4xU01NC/iSPqZ8oLaJ5DUreflKZjfEkDUAxEevcehmGWJjrWoo9EZuN7qHrF1Tr/qodMl0laFH8oOlMUllblZiwKCH0JGtcYqKtf1ogINSoW2DVZBqrRxRNqSjOeipv9Ak5A2OlynsSRU=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 803ba0dd-912d-4b99-adfc-08de0fd1e5b5
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:12:11.0305
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: W5rcmRWaJ4JLlRf0i/2ZWEAqbCCDAuXl+AnZclA8BML2a6yR7x8IQ6OD/iHje3qz4L+0csGwPTUeglGFD6KWIMe7ryaQASZOnlLOG22J4Rg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6364
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 malwarescore=0
 suspectscore=0 spamscore=0 adultscore=0 bulkscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-ORIG-GUID: qYgsvj9sdFZ5UBQfg3HifXLxmz6ruw8f
X-Authority-Analysis: v=2.4 cv=Pf3yRyhd c=1 sm=1 tr=0 ts=68f6271f b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=QyXUC8HyAAAA:8
 a=Ikd4Dj_1AAAA:8 a=XorjO2LDAUPeUTK5CBgA:9
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMiBTYWx0ZWRfX00XMR31HKgGi
 zeSaKybmE1f2VqvdXkldzqONijyXpDdu3Wv7dPvxdWmi0RkdvFSbw9y9QIT2NRhRUMaYNigeRqw
 4Z8LCuheeOw/+7zpPuoUJuBxl72PAJZ95EazM0vsXmNxyVGXiHhFTzDCCBJOVleOB8sQXfgTeA1
 KggrQXHnI0knNEQ9TyCFO5EKL6I7e1LHmIM9vVlHQ01/ppYLYNnQOqf9oZuTBrq8pT8Hxx5IxTU
 FJXcl3lcfGaDmLRgPa6TrOjRRcnVThWvav12ZpMELj7jS/AFIElYgpYDo7cZzUjqLNM3o1RtpW0
 V26jW9VP28uPE2TXAR41r6e0mUNDWTbsIzUF7TXpmmZ6azZw81qnJviGDfDIjSgTr6FDYUsxVTL
 +rxwo1KYIe60fxcQU8254n6ysEWnPg==
X-Proofpoint-GUID: qYgsvj9sdFZ5UBQfg3HifXLxmz6ruw8f
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=EVexNXhN;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DeaNG0oa;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Make use of the ability to specify a remap action within mmap_prepare to
update the resctl pseudo-lock to use mmap_prepare in favour of the
deprecated mmap hook.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: Reinette Chatre <reinette.chatre@intel.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
---
 fs/resctrl/pseudo_lock.c | 20 +++++++++-----------
 1 file changed, 9 insertions(+), 11 deletions(-)

diff --git a/fs/resctrl/pseudo_lock.c b/fs/resctrl/pseudo_lock.c
index 87bbc2605de1..0bfc13c5b96d 100644
--- a/fs/resctrl/pseudo_lock.c
+++ b/fs/resctrl/pseudo_lock.c
@@ -995,10 +995,11 @@ static const struct vm_operations_struct pseudo_mmap_ops = {
 	.mremap = pseudo_lock_dev_mremap,
 };
 
-static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
+static int pseudo_lock_dev_mmap_prepare(struct vm_area_desc *desc)
 {
-	unsigned long vsize = vma->vm_end - vma->vm_start;
-	unsigned long off = vma->vm_pgoff << PAGE_SHIFT;
+	unsigned long off = desc->pgoff << PAGE_SHIFT;
+	unsigned long vsize = vma_desc_size(desc);
+	struct file *filp = desc->file;
 	struct pseudo_lock_region *plr;
 	struct rdtgroup *rdtgrp;
 	unsigned long physical;
@@ -1043,7 +1044,7 @@ static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
 	 * Ensure changes are carried directly to the memory being mapped,
 	 * do not allow copy-on-write mapping.
 	 */
-	if (!(vma->vm_flags & VM_SHARED)) {
+	if (!(desc->vm_flags & VM_SHARED)) {
 		mutex_unlock(&rdtgroup_mutex);
 		return -EINVAL;
 	}
@@ -1055,12 +1056,9 @@ static int pseudo_lock_dev_mmap(struct file *filp, struct vm_area_struct *vma)
 
 	memset(plr->kmem + off, 0, vsize);
 
-	if (remap_pfn_range(vma, vma->vm_start, physical + vma->vm_pgoff,
-			    vsize, vma->vm_page_prot)) {
-		mutex_unlock(&rdtgroup_mutex);
-		return -EAGAIN;
-	}
-	vma->vm_ops = &pseudo_mmap_ops;
+	desc->vm_ops = &pseudo_mmap_ops;
+	mmap_action_remap_full(desc, physical + desc->pgoff);
+
 	mutex_unlock(&rdtgroup_mutex);
 	return 0;
 }
@@ -1071,7 +1069,7 @@ static const struct file_operations pseudo_lock_dev_fops = {
 	.write =	NULL,
 	.open =		pseudo_lock_dev_open,
 	.release =	pseudo_lock_dev_release,
-	.mmap =		pseudo_lock_dev_mmap,
+	.mmap_prepare =	pseudo_lock_dev_mmap_prepare,
 };
 
 int rdt_pseudo_lock_init(void)
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/95b28b066f37ca25f56fa9460a9367f1a866f88b.1760959442.git.lorenzo.stoakes%40oracle.com.
