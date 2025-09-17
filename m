Return-Path: <kasan-dev+bncBD6LBUWO5UMBBBEQVTDAMGQEPGC7NZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A60FDB81729
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:12:05 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-423fb9b0ceasf1313005ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:12:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136324; cv=pass;
        d=google.com; s=arc-20240605;
        b=geocuP0qOsAd0uLN8t+xTWS8rhKvJfpkIl/nUuitZzDknuuzmNYPS8Iov9HcTVig7h
         jb9VCM5IGqQ8cIS86tc0u6K50ih16zhkllW4mnxIvKVrajtXaC2887zD5v7HZp44Dtp2
         wIkZeuxrQfBPnyvxdSXd8fwUF5VLUZcV9VDQG3YYacxT4bVED9ZZB9zEMmjpcr6cIfAr
         XCinqxTPVxJfExPfB710IgfB1J3c77tay3/6SilGbCf++w0CpyQnE+SB8Tv59+JNC7au
         jhAwg5aSkZnqHp1BAt4iI/fOJ/nC6nH8mKKcuHLUeq1UterxMivCewSxUHkch6BLkjaM
         cisw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fAxi0KZbD2Q5RUR+Yw+0LRoySpIy2Ek1DuE1sYCIBKQ=;
        fh=5ciKKWHTchM/QtF53exNHtekbdpUTu5WkEeV2zjDlZE=;
        b=G+JcOLShdy9sQBsUH06UWVSBU/XTioKEqtt97iQgA8PQUy9N+FjYZoZqmt0c5NIaQl
         Q/A0CHBeDrl0mEBVP7fgb3FWdWZr6i6TKP59k6fb7tQgVbraxusrkyc16MWiSbATsZVl
         z6gPekxqhHZ4bVI9TSIe6VSdb2cJeCp2qou96GV5U20suQpcUc/KW3eg41bAN7ZJsSOv
         Knw8YpMsXHrt/EUhOwK0/MqzlV5eWmDSuPVrDGL9u5vo3vwlX7R+s5/9ep3FFChay5H9
         Lrl2LkCbb6zNfLVqB9OazdzOUcHwcFgfdi9uSFZdqDdAazswkQDGSECBvgb817JgKRav
         4Hcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="rrOmB/ZW";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=wuS+5FlT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136324; x=1758741124; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fAxi0KZbD2Q5RUR+Yw+0LRoySpIy2Ek1DuE1sYCIBKQ=;
        b=d79ettM7e+C4RNh+fdzqjvb91ep2PiUT2K8hCxBXZaDZ23RzPucrzRMQ6Jm4YjnBg6
         DTDhkLNLEt6S02Jp6+l0K6eNaRr2Co4v00dWhuunXoA8I0p5vjS7RWvHOP0e5raYZJer
         Ze2cF7+VZjIcti2nkYXjDGE2KH5qLvOsyKDaeHZHjl2MW+LdQV6GvvYx6J0VmFt25mAm
         BDnKdK+V9RUNNs3ZQRi5uPGGgFrU5hDle5ibjnFS4A2D9jc4Iz3d+/yqJvtIyMV8dE4f
         tNqvY0GKKNYWCC/8aTt2y57jNhwgM7KNn/Ajd+Hg6x0EZBgrQCZvaVJPquK+5Ne7xZou
         IXPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136324; x=1758741124;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fAxi0KZbD2Q5RUR+Yw+0LRoySpIy2Ek1DuE1sYCIBKQ=;
        b=pOGoDxBROMcT9vqbwTA9NC4yZgnuM9XA6LTyJNFUBfFl4/Vtaz+5fDqHMeClkOSZzZ
         9oiKKN5TVAmv42c+jclpg/JIiBJqQxe9rDp5JLCrBNYYsHj9+vrGd9FN00j7tgWHZjhQ
         VXMx8lQlpdDVnT2pRuXWYR5Nl/2w4DWmog0EzS9TPZn8USXmNrzuHc6wVQ/Fj7tyIg/Y
         nRoXSHTAAPxfMMxUq9JL2vDl7he0aAJTdkg6dpTiGRXF4mirFryd6p8tAawcj90mT+AO
         3MfsvcVGfexdJz4Y6PPz4xqaHsdJMjqNUQhmlZy2ICvVvNz7dwliVUik2xsr0Q12ekub
         hOMg==
X-Forwarded-Encrypted: i=3; AJvYcCXYv6O/SG0IP8AWAEQLk9H9sM2K1vrrNpBJqtBp9KL/3HJ2IujlQhbeOF/43BBboJn2truwYQ==@lfdr.de
X-Gm-Message-State: AOJu0YyA0vNg8k8Aku2L8WdGGQhdxvAG1O1e+/aXT+HICyCmVs8QWPvt
	+vzT0uqzjOnrOgEvaEla9kgf9lovxOkFpbQjhZezSCAJoBOBRaGHsnZm
X-Google-Smtp-Source: AGHT+IGqn8OyZXvjGYJdkD3LDVpRSIuaUv/zJ/CAlv8oxrO5nghAlNdK40/OYFB3ednfCoEXolxc7g==
X-Received: by 2002:a05:6e02:b26:b0:418:a784:5e1f with SMTP id e9e14a558f8ab-4241a512672mr38642445ab.16.1758136324311;
        Wed, 17 Sep 2025 12:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5upjT/3DHW9wf7JX2UJsvkh8c4FIt/NhtQLDiKksASAA==
Received: by 2002:a92:ca0d:0:b0:423:fdf2:c003 with SMTP id e9e14a558f8ab-4244da33b0fls550775ab.1.-pod-prod-09-us;
 Wed, 17 Sep 2025 12:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWT6xPzIRyNSobwTnVtbYuJGqJ+RL94tS54eyI5M6IRqj1rFaNl3/3zMO3ujmW/q1HduKNVpM+Byxc=@googlegroups.com
X-Received: by 2002:a92:cdad:0:b0:41f:6b74:e238 with SMTP id e9e14a558f8ab-4241a488f5bmr42780115ab.1.1758136322925;
        Wed, 17 Sep 2025 12:12:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136322; cv=pass;
        d=google.com; s=arc-20240605;
        b=g6yMSKs5zlRZLQ1AnSLnsQUOW9BQPOrRyK2sNINe9Hbtd8x65qI7a7L5lr9AwYwUpG
         aqo+WpUqNVO8XznFzRLXc2khHC+13BJaqQLnzMa8+pzA5ElYiCraPh0ss9lh7yoHh+6t
         Bb0E68l0yvNrpyn52UXlVSXKKkg0odHvrtjVhajfGrZbaRDi/fGdGqkc+yukZaLTlSFx
         M2rF4cwkth4ImxgCaHUHBVA09RoBp2pbnCY+YZX4+171LMnMVdlYvOFNLGu0cnNLCe3a
         0BRrcBw7hkeHMdM2RGDmIFtUTDrx230uXYvJx0h2cQ7wEeC9x0tzaMKgRcgGQgKeVNlI
         v9Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=NllZZRB8yPovYXPAo2Hk2Gjm4hq0NgzvzjYEIa1h3fY=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=EGCsgDEW0VPgoFdVRycq3oNHgHMwznV4ZgyPesUqCRDH/SdIOWUSvil2+pWp8djhx+
         qX5DqqbJQI2WUhOeA096pKBln+Wif2OiUxciBl7618KawEYCAewbC7xGqx5yhXsTXMaV
         v3MLQfzx1djatJq6krhB9QcBohFBp2uBw4ElFKaTNYkfEOAxJ6TM5NSAbOzJ+01Kz4c+
         9MWPWn5VI55lCnKjn1WUbvdc14oPXDZ5JTcn1k8Gs3p7x1xvFDM9kDgo1Dhp0GRQXRYb
         +3XX7kdrA+GTaWtKcmdTDeMZ2fC2IKRBOM91zhIk+mZwVz5rN2RLyl1Ud9sxjrl9PdhQ
         EBKA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="rrOmB/ZW";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=wuS+5FlT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244afaa229si91315ab.5.2025.09.17.12.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEISbb001843;
	Wed, 17 Sep 2025 19:11:53 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fxd2082-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:53 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHEIel033687;
	Wed, 17 Sep 2025 19:11:52 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012009.outbound.protection.outlook.com [52.101.48.9])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e5fqw-6
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:51 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=VUpGGsW8cTEDjNfvlHnh3NJ3rawNztqkaAJLfkDvtZoHW2REFXJybmO7rKBNngb8h5cOpcbnPCyjl63yEH1nqWf7WfIjnRWUQz4qSlpzObwf4GiPjhS3IGWEeQZQwhp4/kDGk6fkjJHQQ93cMpJ+f4NZJBwYAr71dLunPhacL1GGIRXNUV4Y8h06+khf7nfasKymo8+5yALtuIEbLUgwAshnQGVNGrLjfACHgqbyLVqvSidYa3ZnJmVFYHUcCDecmXWdip3xKaWW5Gf+2XFS//EgcwzkCTxEkARekI/x+P1NIZU7vyVjJdCsZ/Hr49R/wTr022NskqXH39SoOY+/jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NllZZRB8yPovYXPAo2Hk2Gjm4hq0NgzvzjYEIa1h3fY=;
 b=Ft00nP+hmLsVEEJOOxteYLsVkQD2gGKDNMfrhZLlRyASsfgetdBmnoVUgQV2BiMQNmMOc8UJsxQjep8Nu0LDHMGiGhU+3AkigTc1rQCC6hYAQtfxK3QpsSAn3QdL8wIL0BaDlCEGv5qLvW/8TVbJp8Qu+2GtDPw0GEeNwG+uOKv2DD2rg1ZkOg3zoFJonTxkOw/ZO5otyqDrM7b/J5dJtU/+ajNuQ+6SBN3A3qf/6SDBQC6TPXc9lB6htgTsRZ0+xbqYBVA6tfnHcrD78/MN+aVCaOoKwv0OBM+BOk8yk1apL6xPZLdrcMeQjyp5DPMwgLv9QXJ/a32Cu5d1K3RlzA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by DM4PR10MB6063.namprd10.prod.outlook.com (2603:10b6:8:b9::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Wed, 17 Sep
 2025 19:11:47 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:47 +0000
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
Subject: [PATCH v4 14/14] mm: update resctl to use mmap_prepare
Date: Wed, 17 Sep 2025 20:11:16 +0100
Message-ID: <ed05dfdff6f77e33628784b6492f66f347673b50.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO2P265CA0178.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a::22) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|DM4PR10MB6063:EE_
X-MS-Office365-Filtering-Correlation-Id: 0911ee77-428d-411f-b005-08ddf61e0c08
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?f7ZP1KAoZEA+e2bVvAWE9whSZOH64PqNar5DdIa01Bon8T/VVa4yWMseq+MW?=
 =?us-ascii?Q?U/XyVAIbayJsiJmcWrQw2fqeY7HU8TnlgA03CRyE1oB80AvCgHKIHbZy5Tfb?=
 =?us-ascii?Q?351oCa8fBWKMLj88PMnzf4lsRBunRR8I5zeLvz04edfG34vzf/jzSO+n+lUb?=
 =?us-ascii?Q?86lpK5ldwgO4MwmejLT7JVTDieUys+p4U6K6HVQro0ikqm7GDNR6RX5yCPUV?=
 =?us-ascii?Q?HZ4XB1gkXCrVYe5NSwsILtx6U3ltrKaiT/StpqQwVssB3L8tQdHgOHGDWUj/?=
 =?us-ascii?Q?oRLQ9FeEHzAqJe5iRbXgN1V8Dx/toKT3nDMjix/077Iy3nl7B0/u1P6BhVPx?=
 =?us-ascii?Q?tYZR0DWXF39am1Ok6slKR0rGjm8DnucTqAv6dmGEb/gdlUUr6ZV/z32WSrig?=
 =?us-ascii?Q?fLPa6+9jNfW00o7ltxY3gSZ6Pz2WP2Qw+37sHYGsKQYdT1r4lKpsEfGMBp0L?=
 =?us-ascii?Q?sG0stoEbVnhHNuzGk1vJ9hx/UkWiSv13LeVc8twUpuZyyefKqeHBlxilVyAc?=
 =?us-ascii?Q?XhaICymvTiWEVvbSZKuVtoUAIGU13cXUIp6E9500B8mbHTgjmIGXySV7lppE?=
 =?us-ascii?Q?5gH+MSUPZlGzatdy9UGrhEXaJNVlSm2/jJxDUIkOYx7ukmWEHmsE4mTg7tyW?=
 =?us-ascii?Q?ZsRa2/b8mlP9f4NQFYDzdsMq5n03sIhBkltBSzyjCs3s4zHQpX0jsq2fl4Yl?=
 =?us-ascii?Q?p97xWkOZYmNORE3GSeoGyrjisIsdLqs1r/RNOJESfRs2r8stlom+0QReIOs6?=
 =?us-ascii?Q?aO666s/XS0T35NIX1EMWG6GGDgNexIW70OpdTk8doZOeptQpVX1Z273s2N4K?=
 =?us-ascii?Q?/+RNbAulUaXIkqNU0I2fZT4rKXf6Z2xuPrPG4LqYBMaXzeqqY6zSiuOHbNAB?=
 =?us-ascii?Q?Uq1pGl/djNgJX3epMkFG3LbQ7BIM8XbeYYzOvNigHcn87meP2wQNgGS4rV0S?=
 =?us-ascii?Q?TwcUROMSZXpXT7GmriEIemoXW4oS2gy18FmjJUe2lBfvplvf9ISafNJ7O7Cx?=
 =?us-ascii?Q?AtJGLh9XT9uaMdw8TqQJE7FeT9IRk7ttVnutAjmQeJs6jhoQ7X4bAiXzgjNf?=
 =?us-ascii?Q?du/0OBge+9tgGTmPscgNYXHMWazTqhOx9+UFTbu7Ox0qboCTR8lC8MaaSkfG?=
 =?us-ascii?Q?hCTXIWXrYR05ui/h4jtObZoMnQjRJ2/GrLdFBL9Pxxyum3fGbRlgb9HCkeoH?=
 =?us-ascii?Q?BmQJFq2fSLgY1BbgN7HZZDJbpqrj9x7rz4R2o2J+OLL9YH8ofaAuBxksMtMQ?=
 =?us-ascii?Q?4MXFNexLGpOLyXFH+PJhQqgHMHyxUV7uBx5ZL72dIRYbhT+RHrpQR+O4yIWp?=
 =?us-ascii?Q?TUC7WX14hPdb5f9Wv9us0MFLNvATLrCgom8lM487VOn2CC3lVbxkeX1sw0hC?=
 =?us-ascii?Q?Y7bzaii+amj/g/Xocfqo4+9ouloonBrT6F0lHj6FRIITc75gK2EE7VAzKtCy?=
 =?us-ascii?Q?lvVhGi0NB18=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?g9jYWgukr7XltkJncRHiMq9JNJ427kEGMYhIAznaagnjhafsUQKyKqXVuCBW?=
 =?us-ascii?Q?3uG5soltIPRAWmGFBXGUybUhDeeNSuGnJeBtsBomAEkoWxkjo849QZDP6UL/?=
 =?us-ascii?Q?7rXPssCrLw8RjDOU6tlWuVZuetzFrmUWiEOq+7DLC1sB/qxaUdUXhhSX3M/3?=
 =?us-ascii?Q?OIJH+4y9Lf/jjfBvl2OXIaOzUW0hOpQ/zi0l+VrwdAcAKt+kZcTcP5vdYNng?=
 =?us-ascii?Q?QcyS/wsuds1puPeBk1Gxj+g9KoWBWDZ+whckrumtamj82N+OwZ84EjJPjhMP?=
 =?us-ascii?Q?66eOdhe7OmY/vib8lzMOioh7/HmbidfTmNGZdyAJBuG8HwO6UAM8/not/Zfd?=
 =?us-ascii?Q?8lrGN0jnIUorfbJIzzJlEsBwy7lUBoK51WDJob//RUf1n3M+w/pjxtc7jaxG?=
 =?us-ascii?Q?59ZrEhu4G33VFfc7pBZRUrgGDhopfgvqYDj8fXazatslxI0cCdjpPxSKod/Y?=
 =?us-ascii?Q?i0LF0YeghsaZFrDJCQXV/Gf4D14PryzCtJDjasrKQynv2cecYKUPOLVh6vsf?=
 =?us-ascii?Q?N3xUgLFI5pJ0pUG9sLQq56GCfBzcIzA+VH1WlMUngv3IHBlTv0YnGmknuinv?=
 =?us-ascii?Q?/mXvAIPAWDfBhDXPs639Dk7IIdYBOPuGTCVZNtoo4ukplk3Q3KsRv4Ds9rju?=
 =?us-ascii?Q?NuH6cPcAJr9KJldWoVote4rGvX9V6f8FNHldIH/H8jssctdkt1VVbNcXTsl8?=
 =?us-ascii?Q?/3Lw+TfpEdTfpKGJLd8JNGnZARW3oHG613UvW5CuDXtzZljp2xwRqgeNWmjk?=
 =?us-ascii?Q?OjwToD5P2AQNXpnutpUGUvPN5mMqTWtUoicQc8luhdVQtKesZQyz3u2aYGLF?=
 =?us-ascii?Q?vkko2GF3XNKHHBzvyhnyZMPHmAA+bGAYYkOcW8o0689bcTgpbT2x103P+xkJ?=
 =?us-ascii?Q?We/V7swqy86Q6ZZa1wdupcVnPHB405Qg/psPMj0ybAd9NZAl+XIe2vVb16z5?=
 =?us-ascii?Q?LZ5Pok37UzmKV+FxRsJHcAHMkUJY6SlHtwwgJcc7IM5Cl8QIDB4fJF/BZ0bY?=
 =?us-ascii?Q?k1l3GNwAlhU+T1RQj+OEev28DCMYtFFm55XY63GkN7Pnyti4Spr94Ro/PF1J?=
 =?us-ascii?Q?XWeXE5Ij1FszXDytUOJOe73Fxprq7ZCz3r+bSgkAWFVw/68XKxrSQSw29q24?=
 =?us-ascii?Q?JcGSK+sgyPYGOdsKflBhB60V4kFpPTBk4zL53IViwYpOw0Ab9+iuvmvF/8cw?=
 =?us-ascii?Q?InsrifIwpURayJpjbYm+1Y0yhNPV+rljFvciE446kz7STbmbkwUv5XoN4r2i?=
 =?us-ascii?Q?Dv9EPlQ8E97+9SY8nY5vpl1kJAOgH3CfutWw6CiY5OTZXMC702qJxvACdfR0?=
 =?us-ascii?Q?Htz0XjuiMA3duhwmwGYhuBE0/hV0Ekrynveeyu2LL4mHlt0gtgIBmshRN3Wd?=
 =?us-ascii?Q?PLnRlD48tJ4VNR6OzM5Rmy+vYzA8fEYWok1IDudARHpuCAZAo6ww5/4ZQy3t?=
 =?us-ascii?Q?wZF3+URT6KbTE41cJtIavvP4NFlNRAI63UHNV5pOH/MHHgvwNGfetQE3FO1h?=
 =?us-ascii?Q?Ivhu1cyNiPJL7fS90VNlyYUaZPEuxq2J9HlClHUUNKs7cMb2hogb762n5CJk?=
 =?us-ascii?Q?xTkC7OAI0PPoNJzQ3lwfAsR1iQw3eMQTyJiQ/O/zD6Whd2JFdF59LkT1CIFQ?=
 =?us-ascii?Q?jw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: CXCuaX2lhVAB03vqAkFeijd0jD6vo6CwkmXbedL03c1lSKrrnPl4udj6GYcqiiMLalNT7pjNbgMQhDvIa7GtsODrIFTUfoCV38yEibRYh6cdgkrb3DGXOCa7g6htIBX1mO15sX36jOk7LdJKavI9nFrxnmuSBqUGEIK2I2HKtDP/XBJGvBDPan5u29twnImWnHduq0eNon5pTp7BVgmUhx2d7wHH0ng8u940hjbIJROgePO7+y1T2GZcRY76XyJTY9CGXpTUAu8uKBvfqaAqf5vHrnSyKiZyUGs5tgKKzl843bgg/7N1y7c/EwwaixY3OsdaInCDaY3R6rtzMRGa/NV5eljz3BqJzMAgGSVCzAvStV4zUKo1xtCWO7kMCbW7bhb75ZQI4A7nn+bT9mKUAyfpPAMkPYMN5T7aEi+TcV+1mfCqSx+iS07QCjRtvJFBBGq4L7hauacmm4xTWYt+wWuzEWZBjjUDa4sD6jwvFwXbEhMEMbQIqoYZWwCotAMjNU3q9iNFsuQeZrFEwD+e5FN/IXfSFDXBYHxo3sCnx0dx+BST+Edwc3tsCSD6tmCFxPR0WLabv/bDCr5oI9QT42l7uk+of9DWtf/fkakLUZI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0911ee77-428d-411f-b005-08ddf61e0c08
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:46.8295
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1Ox6ZW5qWcAKqpciK2RMtz5bTsC0q4VN3TcPbWKKqJOun4dOs7CHpnK4lPpgN0Ht/0+8GUahPuubK1kHs2Qvssa7v5I4emSEULNVLrco8f0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6063
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Proofpoint-GUID: 18QcOGpbamh04A70nYS_NnOLfz64PkjT
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXzZ3JM4n+tqbG
 k77sY5rl+sGTOhmwV6zXLUnmhs9QKJ2hMo4SsgrslLYNIWPGQJIhDCHoXkLoVQPMI5moJEFfVEo
 PaCa2bnN+WtZcC54HRw4jowLjonVV9T7bSoWpAZI4yWyMxQXutLAetRQM6VTPJPIhrh7ZzjiO4F
 YME6uDyO6CeCg09AfxCT+zKEzYHYBNzIxMFR4K8gDaTvyhq3ZXvL4iFxcVKIsrhP++ch45OcWBy
 p8snmNoTMWIe/0wZ4RDa5yl1yP8txC1aLFOGDlhUnElUpcG8oGyNp+FVzzOY4NO687nAm2tbE3J
 T64QBtGYCeCrq0p+tZ1lraZ6AuLEqL0Amn6P6DVgbH4oUPDHrFjnPs+Qgu6JEpr3jvMr7dNBaJu
 FoqqlzZ/
X-Authority-Analysis: v=2.4 cv=cerSrmDM c=1 sm=1 tr=0 ts=68cb07f9 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=QyXUC8HyAAAA:8 a=Ikd4Dj_1AAAA:8
 a=XorjO2LDAUPeUTK5CBgA:9
X-Proofpoint-ORIG-GUID: 18QcOGpbamh04A70nYS_NnOLfz64PkjT
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="rrOmB/ZW";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=wuS+5FlT;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ed05dfdff6f77e33628784b6492f66f347673b50.1758135681.git.lorenzo.stoakes%40oracle.com.
