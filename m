Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4UPVTDAMGQEEGMLVYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 76789B816FB
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:11:48 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-24457ef983fsf2478735ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:11:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136307; cv=pass;
        d=google.com; s=arc-20240605;
        b=D1i7OEvXDB7FXvyrZQlGFfVS7d4OAB54qfYMiyUWPlfmKIYfxgjDwEQoZj8fvr49Si
         qD7RCx5B63XeAICVgELZYCNjxLc8Kk3MK4KJKLPAahcjg+J+l2HE4swvzLHxTdW4Y+wx
         9W2D9eMA08rfcp2x2gfPqx1dfpuHziJINYdBDE6HjX7h2HJsB7ItQsZm96ZIhej+nhbC
         EdbKwHOABHa2FNhpEaa8KHrpJ/CSnl0+zldCeYfa+yXuhhpA/qkE8Jhuy1AZ1W1uMW9g
         11is9YVkyEi4WSwBncVT0qwwdq0W/NOvr4S2bnPIgo7e+mW59z/ddel9nkXos+kwcte7
         7Jow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+nETzsen59bGuJ+7Ui81/jcd9yFBgHxScYRI12euddU=;
        fh=hxqH0suZPCMN+dzRoGAhFcbINSKZVmhrMR8oCQjP/pI=;
        b=A4E5xt48YI1K+OsOuKFmGYbrQXOukakFaYkTa74dGnZAV56A03hyYKgqSiXJuluXzB
         5eJg7HKRKzWzDrii/JaU5IExMvHMNsv68ez8vIMZKUgKry0LQD3L+nOiBqq9AJ96oqUU
         irqsUBNaz3yw/sjRya3ttv4ZTz9+XEgqAGuNWHVvLWrdEl7+QNDlDwWADyhSC/dyifEn
         WIxMrVtogASdaeAWe4i2pFcpBv8orYC6TMUkp5TNQzo43Ok/FT+6GWjv59O9LDCawns/
         tO3D0vR0K3GeQ/QOdSlo7Cz+hu2ZyPkx353y5/sdDN7fg4SA1/6N0j01ZLPOEzRol3mR
         uegg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XlqLeIbt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=esii5Yws;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136307; x=1758741107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+nETzsen59bGuJ+7Ui81/jcd9yFBgHxScYRI12euddU=;
        b=Onu2RokdQKf6Fv6j9olpqI9TvcoDIxMmMFS6hp7hscui6iEKXPhjAEMqQX8rQz1Ab1
         Ox8MIjmg9k2GppOb73SC2keBhBdZ098/hQOmEslzIVcHyr2yoJ4dKm3+9FQ0FaArwfIK
         lwimJSUBrdueRH1kzRRd0lWxfP3G82wYudVcbcSiwoBJRloA5HzFfz1uQx346RgNj1G1
         OQkZqpx6qPmFSOW0pLH7GW9umiHG4lrud6a4pDHeGr4M60wsAgPGdUqOwWHJhu1Va0Vh
         TgZnp6N0a1wELOp7anq09YIBitGRradpTq2vgieEG7iqht9ZVlvOUYn3sam9GCTLuGJx
         s4Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136307; x=1758741107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+nETzsen59bGuJ+7Ui81/jcd9yFBgHxScYRI12euddU=;
        b=sbp8biE/qHyoDlEuFlrGY3x8ilQ2+HLfrIpZWfFWatoUZgN6TZdORRvpTf+dlMDVwU
         XrQQqgMTQmR7You0AChoVPe3eDvPf8sf3A2X40lFuxIyjHRyYapNXBVeqhOM6udd2wpx
         Ygye0VgofRx38I8buDNxARDMJprgKcdksQ8MR1hQqvt15UqHQljZ55sv2PG37ebZsT2w
         cqScHyu5lZleIpqblXMhuHkhQZLVqKKYC705WMC3eiz4HvmK0JHUWP18v/mqQ4haj1sy
         dwV8HtfzGZiMA3RCvPYAkn8O5SJFYy/ZRhADMYsrM3KWwyO0pLGBU2+6CiEpUa0i+snF
         AwkA==
X-Forwarded-Encrypted: i=3; AJvYcCXEgYhKf1YC+Rntmg5A6rWRq3UgLEwvqofLPsnHw18C41TG6UXzGMr5sQvfIy9QLGWZOECO7w==@lfdr.de
X-Gm-Message-State: AOJu0YwXPz+vpho86aP4qrowuMkfkCLOrTxZNfYFszvIiptC29TbsilY
	DVOGVYeSpWFKNAIx6MeR2OZnGCRWAVIYDfN3vUFtriopAkQK0e6CcBVk
X-Google-Smtp-Source: AGHT+IE3xYEnWodbXMNZarNaR9T2s/oCWYhIonIfML1MhRRe72qxCH3FtX+YV+5LpLlti+JEANDZdw==
X-Received: by 2002:a17:903:1108:b0:267:8049:7c7f with SMTP id d9443c01a7336-268118b3f91mr43051655ad.7.1758136306475;
        Wed, 17 Sep 2025 12:11:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7+yXWC5Si13UDdMnd/WyfEOK09f96hfDUtlmTauVFbfQ==
Received: by 2002:a17:903:a4e:b0:268:589:fe0b with SMTP id d9443c01a7336-26983fcc95bls173275ad.0.-pod-prod-06-us;
 Wed, 17 Sep 2025 12:11:45 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVIqmZSfH3JrakEaKas6o4ZZEvBxggTCEhAz8ZjR+tvRh9+61/bWZGcDzymJz3FGQTKfuejNgGP3IM=@googlegroups.com
X-Received: by 2002:a17:902:e882:b0:267:d2f9:2327 with SMTP id d9443c01a7336-26812289becmr39208845ad.27.1758136305010;
        Wed, 17 Sep 2025 12:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136304; cv=pass;
        d=google.com; s=arc-20240605;
        b=FzxVoT6AxmJkkJ/Dukp9Q6dKx3Z7hPqqcmqN5hhGepDq14C/KuS4q6CL3fzwL7P0qU
         ZhLeiJmnHd5yDkRMnguS0MOdc7oBnzjTCGWX0Sn56blbG7yiLNeDXkbn2oI/Fyn8fBOh
         354YqLGXMing1xNH6aenVHkE9XY9QVNm+/0ITa0s03w1Y4OnaZ1Tsy+D6lCxqd+kJw1y
         wyyhAdgUzwS+GDnxM6jGqMYCCRb1UZVkSzZfpnH/KxFXpOtsL0cPPOdnWXAD1JnjrcS+
         qutSbOYG4qanZ2irQL4miiywSmO1d12Z6HDzyCDcdGegv7TdIm0Qvpgqo9TyOvD5N691
         6xfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=cRrT8kxAEV89n2rq1tA2Vp7IFr1cOAltsr49McoQNM8=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=aKCkUpdLx+tDzwo3VX5fv1RicyBzvzC927CA/hP3a/YDbOqziXlhQbtovi8hMWnR+K
         rPGTZEl31u61S4n0Ge7V3PBfypE4Q9G9fT1XZa57nIU8izMZPyl0xEYWKoxYZp7LPQ0Y
         J7VgmOxLGwHZBaDg6sM7+C/0ivHMTk12IJTx9Z4hjiLUdnHvsgykDW821dVXzZlEJVXK
         2HPkMOjHABc3FzyG0/cWZXs9LhOsEm3iPSDr9CiDNTjJkXPglRem/ZldZyL4pWHV6E+E
         cc7ws6e3PYQaPP7ZLlWU1A23qKgHAjl1lSLFBSuR3GF1xpb+qLgDZAmfe5+4TIh5qfoV
         qGCA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XlqLeIbt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=esii5Yws;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-269802139c1si216085ad.3.2025.09.17.12.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIRmp001776;
	Wed, 17 Sep 2025 19:11:34 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fxd2071-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:33 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHHrJ8028810;
	Wed, 17 Sep 2025 19:11:32 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010000.outbound.protection.outlook.com [52.101.193.0])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e5fkp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Bi+79b8U6FmCrTrXIQqi51YhOIQkMN4aEdMQJ6AIwdi4AZdxJLd41lRMi/d6q58MXq2Y1H/xsEdZ2INxZFKNrsDoo7cRG8KuVL/4cfG8DhdMgdpMZn/1sWPZpYiqbi4IdscXsIZ4rq8281IDKWFCsSBWFBBU0d+ZykVNB/VoqPO1sp4+61jWYCrmvwaY5oEcyYSfEJ3iRJbQOP+Otsy4NrwtJnIU15XkFPwvOWUBjEQf/3O5K4YrgTr+fXqWRm9X3ekb3Qmz1x0sYqXU+n4FsL46W87l1e72QqSmbMGOhBuNxzi61NFF4nOPN+C6odYnf9Gaow76VtU5dKyuDy0Ylw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cRrT8kxAEV89n2rq1tA2Vp7IFr1cOAltsr49McoQNM8=;
 b=b8vgATXbrM3vIUdmo4Kyi50aKXWI+9pulLurfbN3YZxJEWDGBr81+0ij2RKvX9AhC32Xw6cOIV6t9aeky6cFdYYZOW/fxcmpwe45jYIzlQLFuwOGHwI853awSZm1rRXNnoww5CQ+n1P6+c9GXXLfl7O+ocd8C7X9llYx61+amobZDvceL6ZjVb+scfAX4M//1qJdXZzyYZ7MPG0N8M33FvekaWLyToMmv3M3LjYeg8bmFiS5ghpkALUB9oGVE1BcikVBfe9wEWC4zBnykwL4o8rLscPe35aUikFOzkLF+FUgV1LTZCdcyK8HkKHhbWOkdTNKbwDa5dRtKQtfx45+zg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by LV8PR10MB7774.namprd10.prod.outlook.com (2603:10b6:408:1e8::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 19:11:26 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:26 +0000
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
Subject: [PATCH v4 02/14] device/dax: update devdax to use mmap_prepare
Date: Wed, 17 Sep 2025 20:11:04 +0100
Message-ID: <d3581c50693d169102bc2d8e31be55bc2aabef97.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0314.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:390::6) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|LV8PR10MB7774:EE_
X-MS-Office365-Filtering-Correlation-Id: 2dca9c49-8c09-4f9a-71cc-08ddf61dffa2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?hp1MJKxfeg18GA9nX79Sm5L/4uC4suZUMUiwlygi5/l4i33n9rmnMCp1l6YW?=
 =?us-ascii?Q?EUTmvvpSozyCqvBPl6Hqk0gPi6VdpMw5xG1NEyNGuWbY/OBHdyduTCBW35wO?=
 =?us-ascii?Q?VTXHEhM5Nl2tMAY6SviY6GNf2zIn8ebPvFWAF0w/6Wp2esiuaX8xGGAO+0ce?=
 =?us-ascii?Q?1elL5cwRQ5kcKQ/DugqyCAZ7t7gu3ngJZEv7bIrjlLOU4jW9vhSZBJh3kYxE?=
 =?us-ascii?Q?C6lITUwWZDWaQVAWEHSIBnZZDUlk7Cy/vhFRV6qB9tyd/irgW0NoQB2pWQiz?=
 =?us-ascii?Q?3I2I4A4uxOYOkyM7QW/zgnxGj1Evc/EX98ErcKBDaarwxX4ie/0SLoX1TXfL?=
 =?us-ascii?Q?dHICc8Yr+g1GzYY/EfS70NDZw3JHvZ1Hc3Z1nqi0dYlSVZNy5JFzAch0CdgU?=
 =?us-ascii?Q?mpRCAXtfofOLocdqUziWdIS5TUnUwhTT/5fAGdXWmfNVTMUjlyBu4b54Rqow?=
 =?us-ascii?Q?48lPDY6lGo1z1KviJBKhbaM9/7ER5R2BFykfh9TQK+vZFNq2KcEIokogN95e?=
 =?us-ascii?Q?PqaOdleMMBh5lulS5/mmms6XXA5aw2qpNwLb+5NWSBZYNfPP6DJL36gFIexz?=
 =?us-ascii?Q?7uglkkVB+3ksqZHV/HEjLwtream3GnoOevcohws81YeUolfRXGYj+YuflYfI?=
 =?us-ascii?Q?VoSfqmQs8wCeRuMB9gnuW1scUpFuYq2qeBmO/Wb6MBAQk9wUNfSpdTm8EIXk?=
 =?us-ascii?Q?5WMEqZamPyQv1Rkmz5JogHbiWCVjlqAqhEuawuDredQixIhfhFMtdEKjNa8v?=
 =?us-ascii?Q?SRjJ39EwH0oacODdrd0N+v0UFDqbyko/OuETPeXlgbi+jtVw/6mQsdhSDKC2?=
 =?us-ascii?Q?+JPlscvA1yZiV0t+4zYygJm0A9qph1VEqWODS3kTmmOeYbeFvlK8sVsv/e0z?=
 =?us-ascii?Q?bpDFypb4vaNqEGmNySwry0qZKzNk2P5UYT0nAE8JNbIatCJY5l6Uu16WLgvp?=
 =?us-ascii?Q?5QT3ghQ66/1DGY23BSCyTCuzd6gPe06Ku6gsVdXBS1cmqIOri0+QAKsYjbL/?=
 =?us-ascii?Q?Hcq4aG4oNnR86L7wnmb/VExz1f2KcAfsBZxxLJA0e0b92tFnVYKDQ1Y64uuA?=
 =?us-ascii?Q?ui25yBdmNDc8pW+gyhH2yW0OCvBIrPE4PAprOgXp87C1qcl7zQkeQ2BSlOwn?=
 =?us-ascii?Q?Dx6QMYr39ymsxgv5KTec8tEnYd2STU3I4Z7lz5h7UfT7WTOWLNJBsErjopxu?=
 =?us-ascii?Q?sL8bS3LnhB/LyXtiVkW7XOTRX2yNy42VG3j4jT4J8azMe2BEaXd6cHZ6K9aE?=
 =?us-ascii?Q?gBqHBC6qce6/VXGn0KCLhA9mcJTNtQxmhg6AsOcCEzXbXaxQpeMbfKTlbRHR?=
 =?us-ascii?Q?C4LBUF/oYpveMEGyV7RChSHEp+XlkuthXtjt9OXQkyQ2Z3rMfLoy13raHOZn?=
 =?us-ascii?Q?JqQz4Wk3okNQLd6suz/YD1bG5grrg3+QY8Ji5V9y98PCIgdK85jpD8IiYAlJ?=
 =?us-ascii?Q?GqiO8wLD01Y=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?2zQyqqlW85bNRAhAqi35SIPN3Ez8elTvzlxICYJdnO7Kmto8C6jvU58/6MP5?=
 =?us-ascii?Q?LPYzD7dsii387FlntqSDncYA8BYOuFYyfyP/snflwapLC4XXyznIiqAWBx4G?=
 =?us-ascii?Q?7W/ILb0Zp6O2onzJf2MRZEOD/maMPZBtqFb7QF0djTDHFkdkS5xqDrTlGyZM?=
 =?us-ascii?Q?X7dAPzYj0KRFBntAeIHaB4MtnbdIN7yz5GwF9ip34ta/DBsS0hQUuX4dvcua?=
 =?us-ascii?Q?qZGOYS7acKeWmfdM5fPxO/chXuzY6C3Cp4uyA1mx/AkJ6RLpMp/AN2XKBtPB?=
 =?us-ascii?Q?4HWy0nmAR4T/b2+A2N/B2TPMXnLZx1qrNlSaGZVWZyp0kdJXUoQ2jjagXaya?=
 =?us-ascii?Q?d9Q7kHXpgWyaI14ntq/AIonoxqltxJLrTxBsdixVdw7JU8nASc3VyV+ONXIK?=
 =?us-ascii?Q?4yxj9Ug64Z7Hu05J5fC0x6qnzoqJvgB/MJUJwFz8OmAWjc2NI+qqCTI7tMCa?=
 =?us-ascii?Q?yB1WEIIQvtZIx77boNA7rjqTI+oNft7kOAK/BMbYg9YoL6LFyId3RbCQqOaC?=
 =?us-ascii?Q?4clJTugkmzJFYuCZItFzc6bqdyNkS1BD2vq0eq0nu6e78T4X5L9dIxbUx7n/?=
 =?us-ascii?Q?x9qHLyzjESfML1Lb6gIrlDyXUypiTJKWvfnMKA43m52pzZZKAieI7iDx0TB0?=
 =?us-ascii?Q?rBha1tBVjAsQxe1sGusMGDZ75zQNviSuKjRInzttjASlVGS4LJBYtWGsFFFO?=
 =?us-ascii?Q?SBO6//exk1SXejgdKTJmXHzTA0oKi1BpeLGx8V8QlU8QDaDjYvquWqUrIdtL?=
 =?us-ascii?Q?hYZZqTohuYATZFyTFN11YAtxgyIMuWQNaGiePkLlXHzgEjn8xg1AOrz5tWAY?=
 =?us-ascii?Q?z0I26DrzsOaZU3XOyLVaVHrFENIzzDGhPeascStl/vi9ZWB0TyyI4RldXnTc?=
 =?us-ascii?Q?pX7QqXn0wX44vROqf3FMDPeIcGkDf7/7EUi4sA487jGrwXVJvRfDY8sl2ZE7?=
 =?us-ascii?Q?QqUsVIcj86FdsPJxvkMlP3kp0fgJ5aAfo2UjUOm0K8cHL+D5JN/1Jc6xHLVr?=
 =?us-ascii?Q?by/x71ALBXmZfJo2TUoorUmIyc4MR/RKoBM5+ELoOqBWCyD/Qx5fd64MOEXr?=
 =?us-ascii?Q?th11j4bOOmD+4K1+Jn/c4U3dT3V6KnilZYnvAghdru0A02hpNTc2oSv5v5aE?=
 =?us-ascii?Q?WBIMNmyroCcS4eM2/MJkLPviNhDrHIBnrYbeCtje10OgRStrqR7AX1xSPwZK?=
 =?us-ascii?Q?VUMNkkGaoZwp9QACexLIP4WNl7UvHj3Y+8nI++7FzZKXhWNhLbTAFMTzf8d7?=
 =?us-ascii?Q?mgaLBfaOoowtMn01WuVHvrxCUfX162OFjwRFbbF5zoxbEMp5L5PcE/iulHY/?=
 =?us-ascii?Q?jtJ5+1zJtCMBSWWo0L/mqGqvAAAhiK2hA6VcMujB1ZnoUzUi+LCJwMRPRLgZ?=
 =?us-ascii?Q?sxB2umM2J2SgPBlMU2lZb5IBPimMUF2GuGBZ0ZdgYjW3Tfq+iQiT3zXT61O2?=
 =?us-ascii?Q?dTHN1O1tBK12dgX6w5T8lwKu+FUPDokVayBV6gwxtaZcApYsBw+Am5dNB5J7?=
 =?us-ascii?Q?RpWR98fCaqqXEjO0We3QUUbcPZiNaCUDA9IIwwKb+eFThgjTkAIb/m3N9MbQ?=
 =?us-ascii?Q?A4apSv931vSTRRfN21yWtb7abLbxIHNad+Nb1spoE/W482fKMUOTHQNAC7Jb?=
 =?us-ascii?Q?cA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: idDHcPtQyfUoazZeDrgbikTwzUB1VeLGPm7ZquzLL14yvHikozUBU8AWYmTNhfuRP4GU/9OD4pOON+ol7blaupYo7ceAne3Y2E9YMLzBGlPRPESAo7kW0s7wn98QifRm/Ki1lVtRzvH5ePoKtHYFQNQVs+ZREI9l8x6eaUwU+umxqPL0KtTXYEIx/rThrPQpq2eSgfBkSNj6nLdhHJjqHp7vDv4pVNPjUcOD5AM6V8WbpGb0ME/lwqyAM4PZ1ObhLbbDwe0VehEUAsWlTWcg42jPLVvPjhrR/QoKnZrCcRJXbieMOGVkHm0YEs5qA1O/6gxiTXPHCdci9qmhJSBMulKiwmAN+7ecC8agH0C8Ns42FinxuEZESKQWVmhS1iO2VvbiQhU6ZtL6bdaaa9EeiPIAjNPBcgXDV28JfMDnftIQ82DniC/bHGM0vC810jsjv6LBK9XMGqf/Oqb1zvAeLtHYSPKI4sWiBVDlpSG5Qi/DOxis5C2sUGwWhZnWq9HLjx2e5XPiLA7I3BUIvCAEwyt8PxoGach97cTVDg0Y8CAYnYbCZFBckynJKe+yj+RrXDKCm1j8jp5IkdVfJnO6iR/ViND8SKxBL8fSyUcxKrQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2dca9c49-8c09-4f9a-71cc-08ddf61dffa2
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:26.1135
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: E5A/dZAVxlqGscyjL+HoRc+qyPuODgkD0OqeRW0hKu04HYEcsTDiwy0/ONst++dQU/MLJyFiaFmiCf7ZQtUsmKZXf4tAqUcJsTNjnewPrjg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR10MB7774
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 phishscore=0
 bulkscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Proofpoint-GUID: lNDe-b5pZ0xmZt9wS6VzxvJJIwsL726_
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX3UMCu+50mxkT
 nmOQy4SatZlVeTqZl+aZlrtgitpeuUx6CIVAk3y2f3sHbhlH8CwZjLSOFlNiOArxgWBFbwEAuu+
 35fWdDF1iffiI3D06KJCtvhlS6kQGwv9+Rb5+Giz4UUe1Cr8drfGAqczrnc8cztgtAf5EgCCZ1x
 eLvp5veGqnOQ833XWFTp5XK40SYxa3mYX/9NliPqgm0aDba4G2jy9IJ4tba+Nt6hCqnYzOm7vq1
 ZgVQHA2GcJnmxVIOaifNfQ49UAerRr59p3x5ODuPFvKpqMtzCBY0jwYNHfZ2WfLZqiWUWxgQGjZ
 8PBWPKFrqObr19NmDfTwlY5JbXX0rS4JdacRXAxkPwkX5Jyi1BWe8cXeHN4LDnD/DzpgAF1yTdd
 3RkRI4rP
X-Authority-Analysis: v=2.4 cv=cerSrmDM c=1 sm=1 tr=0 ts=68cb07e5 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=miBipihQI5mFMOzj8b0A:9
X-Proofpoint-ORIG-GUID: lNDe-b5pZ0xmZt9wS6VzxvJJIwsL726_
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=XlqLeIbt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=esii5Yws;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Acked-by: Pedro Falcato <pfalcato@suse.de>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d3581c50693d169102bc2d8e31be55bc2aabef97.1758135681.git.lorenzo.stoakes%40oracle.com.
