Return-Path: <kasan-dev+bncBD6LBUWO5UMBBAMQVTDAMGQEIG5VYXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id DDB0EB81726
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:12:03 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-32eae48beaasf107237a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:12:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136322; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mass2NTgZ3YrU8mmuGs+YQxIiBXaRGSmbTsrbG8R+64C+fsTJlGDLhMMDbqWu4ZZlg
         A8es24HKNCw/TlK9rIDCxtXYn/DaAA8yOAp8Pcoby7tCCQQPeAt1ZTus3e1yjHgUXR5r
         U9YinhuXzqdg0p37GhGRDOQnL6zFcex6mwEJ7ITwiz+iegDoe6A3M8vBaRFZE4O+msll
         rqBRS/Mr5dTUU6WylxzuJtiJc7GXfziClX/5DzYLHnMXsAFxWLMTVij3mA+QoP5F4YWE
         RhalgcG7+AbmVtwcxZu2KonvCZIzljfSik34ecVDcHBxQegKVow5sSa8v/LGFis0KGNA
         r4KQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZJSgmFcs0O16tsBugLtXvTOC1uN7FHGyTNGtYHnSJww=;
        fh=k4mPX2oLY6DUM9VIBF1Rtl5O6z+egUM8PEIXgbpTsI4=;
        b=L5xZMVscK8S/bPk09SWgW4nwOT4mXI9RBMCfpKYdZEOfuwZ4DQyWC2RFt8Onsi7pBU
         BiNiTyCoUyLuXUa6zDgIa0n9f7bmt07meDOhiLDRY9tftbwA2uoHjjfZx7QWXRicp/Ha
         Tgu+D/Tv9SvdOdRrgOdSxLJWrdx6HWojjqzqwI5AoNTuLBVVCwqb5DC+hrTPdKqT3r8D
         3FadON+jVmhOo2D+GDnMhffvxrIeNFLj/jKm2/KCeObi8aeHDdMVRH0H9ySYOxntIDMR
         84fCLYxw4hH0THD0HFWYnyBDI4lMeaul50bxM2h9FWXzvGAn3HFskxYB82was+buk69n
         LvOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kCcYTHtz;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JvHqzdL5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136322; x=1758741122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZJSgmFcs0O16tsBugLtXvTOC1uN7FHGyTNGtYHnSJww=;
        b=CIkfCnQ+A3rGkQau8gRM98mLTCev089FvIXz9x6C1wzl+81mqRxfz4K5LKQSXHxQ2p
         UE/0Yjn7AwLIMxi9xziW7GE5lYIpP93WT4fyCTSqbclOOL1LLIlqg64GxpgDSDDVh6bm
         QccMWrqy/vMNrIK+ccyTpQzqVM8E9pndosrn41cwEdRjgnoOGSSK4yBQsweib0WYv72n
         7I8s5Ia+KJzF0v1UuvglP9yOfqBlBlmjhw6Di4tGfyKwTtYMDDMfkKkVAcOafO1Slb+i
         3JnrNcT1g5rKbaKmZV+qvs06dcWXPDhrrw7R/cYZh1sTId2ZLp5rmlBm6+GjvhllFw9D
         AEYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136322; x=1758741122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZJSgmFcs0O16tsBugLtXvTOC1uN7FHGyTNGtYHnSJww=;
        b=ftfv5aEk4C8UeIa81002v6JAW1vj/DGdF7JniZ7e0YYLQK/56PYrYODtR7D0JHTNXX
         3C4ASQjj27WgDW38KjoCVVd4aeRnTI74n29KHzWUgnPg4nP3Pn32SaYmewCI5vlY5rO0
         KFSZpB8AaPW5WF6Es6/Vu7ADqdEKAZcJZdJnQQ5E8wJU0gsN2DmbtnzCT623nKVza1tb
         cFJ14+S7VKG6Q72qkbzKMpV0sH6oKw1rx8mStTqi4hF3TN4zmLeBgsP72eBb8n1tYney
         o1jd82zr+ugwr1n4UMNZSd9ikDrEEa894GnsF0OxFwc9/8dlvov5t9Lx36pBog0xlWXm
         ub6A==
X-Forwarded-Encrypted: i=3; AJvYcCWdS07qLFGcne191sX9G4BuCMegWQpvAQgVRzqtTlQEhl5TCo+uvsNC7AgAqjpAiD9e4hcEGA==@lfdr.de
X-Gm-Message-State: AOJu0YxMIiSV3r8SwF9k2BC6OeCO3DF211/9vc+/hVkAmgbXoLkDxEIm
	CWVFvU+TQ31dpHVpwMEVB4Hra0Ih2qpAuRg6ocpwVt1BnW0bFDuxBXgx
X-Google-Smtp-Source: AGHT+IGkhIe074fkBsnJlXfOD7VwI6UxuXmSyeB+JsuZmpI+XmmnB9qhbDYrimIPR/cqB35UTo5WGA==
X-Received: by 2002:a17:90b:4c4e:b0:329:e708:c88e with SMTP id 98e67ed59e1d1-32ee3f1fc3bmr4018656a91.20.1758136322119;
        Wed, 17 Sep 2025 12:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7mlYN2YG9Hx+fOEEpLkeAze0BYKFuKZy/qHBd80SZRhw==
Received: by 2002:a17:90a:ec86:b0:32d:efd9:d13a with SMTP id
 98e67ed59e1d1-33065233139ls28748a91.2.-pod-prod-09-us; Wed, 17 Sep 2025
 12:12:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVsFtqK9Xj30t3N6JVs9dlE4uV14l83EBQABdhxqJ+Ox97mHl7/YJCUa8xN0VhJiLvPZSVSB74Z8i4=@googlegroups.com
X-Received: by 2002:a17:902:ecce:b0:25c:e895:6a75 with SMTP id d9443c01a7336-268137f23ddmr40020325ad.28.1758136320821;
        Wed, 17 Sep 2025 12:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136320; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZU9/USg0oH0uZ1XWrrldFbnNKrQxLaaS7IUOfLbAja4pVHI9ZejgaeOXnTIef0iAdT
         XkSR0Uk1mY7ugNu2AR519WTN41DEn8fj7rLsDL//6XGBX79+bWtp02GNWa7pPySs5QcQ
         Z7MtGNiSLfnSkHT2SSfPTujX/1O+bJm9ZveCjBp/+pFv7DQWKgOHRwBsDA36VMVgcVym
         DSw4TjGgG9r1XVq8H7u2yDMxFu8Zi/P7spj4tjjyzyuWM3IgPqad9aHrUmJAfH833oGB
         74P/HQ59g3hDuBgMhvUWqsIHDFEalmpxN1NCy8vDbZPw0Uic4ReNC4l1qoGeena7SEGK
         Pimw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=/35NbNXafzTqTCTdBBLOYGZizsI56qn6v89SyRTgQfA=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=dinksWp3DZEQ0VtxC1NvnPDCwV/FVaczoB+Xcb/OdjJh29+71n04egJlFk2xIKIepX
         yuM2LzjZ0wJByXYPQIMuYVMPTOLbvLIx2+Ku+RC02zo7/3Fg1vxaHtPU7bBULqu6r+C9
         WvMBfyj0ORF3KK/X5rIBvA5ceq2go3o52x1Nf5FblJL86tUjYql9dL5oDbKOLOVgFdsj
         KtkheiWqnZh3FEf1RmZJ5MBoqizCXoouX08xcgPlAC0IlUhxKS84vFoLNNAUGQ7rg7HK
         EKcVSr/I47zwbTGnZF2vPJTPqZT0xHdLOKvbNI4/rGOH/80+Jyk714I3fdyQr6zhMMIA
         gAkg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kCcYTHtz;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JvHqzdL5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-26980246d3bsi173405ad.5.2025.09.17.12.12.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:12:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIVQG007508;
	Wed, 17 Sep 2025 19:11:51 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx9200q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:51 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHEIej033687;
	Wed, 17 Sep 2025 19:11:50 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012009.outbound.protection.outlook.com [52.101.48.9])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e5fqw-5
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:50 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=LxtjVQBEkOg1dcgcstBTC5eOYS/wQ8xulH/VWu5CRujSOKaksKfnAxty2pOD76i82/DlrdcDn+kprpJBfiotIhhSZ+5R+9CiOuoYgDzGReEuhsWHWxIQSC173AgXhPKAodljtU7Z5YjcuOTB/UrTPmSLZ+m3H8ANHibdg2SekizvRbEptrZl9D3fAzuRyiWusEdM7+MqlP36zynV82ZPSWIjdZtPpSraH8nhduvtBs3p5Me5L81Hj2goCZA1pxFoPTUc5BrQInt3hnm09V7E0fyPokCOOB3KDPhsV3rXkmQvZlJPeQqfVAt8P+90mWWvtQbvKLwIWhnajfmkn8eUZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=/35NbNXafzTqTCTdBBLOYGZizsI56qn6v89SyRTgQfA=;
 b=HCp8+O3Q70Ej/15ZV88jEmzJiXEg82V8G8rXPLN6BH1lQMTTX+q1RZuGRnmrCFHKYoW/sBzWqT/dRIUceWxEoZIpJ9GOq/K7G6T8q06nfrvflqgAKSqjKAOiOKI8KTM4tf99OUe8wV+adv5fBzLB3SaejGxFR6SgTZ0YO8BNE+bXc29K5FeASHeDOX9LS5qWr1rR/gmBCK689WxHpi7LMvv1PUeJWnW3oKATf/sJ5y8dl0kuIMxG48iSC5IcrLwlgzwCT+sIIAO2QLFntGjsiSUXPGqyQMMSjndFyQC2echXFHjoRsI5c25Hc9mfzI5/hEawY8gX0/2wWuCY55EhbA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by DM4PR10MB6063.namprd10.prod.outlook.com (2603:10b6:8:b9::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Wed, 17 Sep
 2025 19:11:45 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:45 +0000
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
Subject: [PATCH v4 13/14] mm: update mem char driver to use mmap_prepare
Date: Wed, 17 Sep 2025 20:11:15 +0100
Message-ID: <14cdf181c4145a298a2249946b753276bdc11167.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0223.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a6::12) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|DM4PR10MB6063:EE_
X-MS-Office365-Filtering-Correlation-Id: 898774d7-01ca-4c65-bdd2-08ddf61e0b0e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?jiE/8mTFDw97FOeKykZHQkdxon4tiKGUJzgcCLYW1++Jeckuk/pwEZVf7Rst?=
 =?us-ascii?Q?pIZCQ/duRhAMRsDucDK/br1GQgAZeTB6wnYiggAhzf0bKsyqjjs3CyPg2SrC?=
 =?us-ascii?Q?jRFgHgy92oumkE5hCpSD+/hiGp4pVE+vluYLr4TXyi9rD78ZdR284XUy/CtJ?=
 =?us-ascii?Q?EhPp1cJwo+dFJMT/XqOkeK0YTfKSh6CZkTAHE2ngHcZnY8980YnJ51vEJSvW?=
 =?us-ascii?Q?uxoDO/LHFh8BPBJtUgZcBE6xm5+Vs4gOh03WX9iUs1KhXnbYmUtByhtlCyn5?=
 =?us-ascii?Q?vNu1EfXiI2LQv+COyRuLmSYPwQB1y+p6XXvAqaaNQ9E0NjXdq/Q1Dy1OBzvD?=
 =?us-ascii?Q?W22aWrQg8xjCrpcXE7TpNsRdUEXvdbWluXM989uJYjkeUHFuAQMEfBfdksoG?=
 =?us-ascii?Q?0kbIyVV7jQSbWCPpxbkg9t0LFponwlewBKHB7i7Fq1JJVugn5Gg5zO8PBXyO?=
 =?us-ascii?Q?6e6RVRQmkSeDQiUufQQ5D1FPrxPP3qIIFoXnmc/j7Uu4/A/wrlsDs8tgFR0J?=
 =?us-ascii?Q?QTktVZYWom+tQFJ6zpjevLm+SMAKWo/ftyAxC8guRvrnbQWLth7eX9v5BLjP?=
 =?us-ascii?Q?AbWmXUwDCheVFOvwmEd61V6Nz1LRk9ZxVnvZ4+EWuIUdH/A/5+10C/sFsvvn?=
 =?us-ascii?Q?LjP8nsYiMAxFF+OoHhP5nSvRNGymVVPW6qDNB3JIW/lNiTSG/2sQNK0VsJHQ?=
 =?us-ascii?Q?HEbb39V+hjzwvls7162Cw2PwGwAr6VUp8qKaMj5l7psqGNTtjAX3NfQbltF9?=
 =?us-ascii?Q?QAyHimilPCx4rArlMiOCrc6psH2Hg9q/jf9KpGMEXxZt3/gtE8WhjYXt0/cw?=
 =?us-ascii?Q?tnGHQ5pzsZ/M0lXQ/YpKUuoYGWIOVdNJZ06nFI2Pjvbn0MI0EN5QazF7VxhX?=
 =?us-ascii?Q?jtv+OaRGEfB0aVjYJqyV/7AXPmJbP2rDF2OphPoLyJcu3qKM80maM7ZKv2ik?=
 =?us-ascii?Q?6sprstF2yFiwG4APF6GXOxWCOfucuN2cweWPjuAVRG8GG9NKHfYH7CbREXWD?=
 =?us-ascii?Q?RPYFgeEde53cHD/yqJEwwDcjwF/8hXYVBBEzYspbQiRjXxFUczZUFkPY0cLI?=
 =?us-ascii?Q?BEUP9p/pj/XQ65nlOW4EVSZGk+Jzw9twsuezwsZ7coq8rEux2PVrEw6ytE4e?=
 =?us-ascii?Q?vNzibrBSyKWKcyA6Nm15gNsbLVB/ABn41tsQPPAG/e42Z037eTfqMVWd/FoO?=
 =?us-ascii?Q?sBv5CcBgmaFyI6K9bdcVYVWWevNUmDKLO5lYCpS+GeLCTLDCe6doI/Lw5Ut5?=
 =?us-ascii?Q?iTuM+xbfgkTpma/I2Reqmn1KMyGzP1jnqmU6MJXXr6tUramIgWvQnqhwzPyk?=
 =?us-ascii?Q?1sblfhDrfX/CK2NCBmum3fL8lRyb8+92FdzHaAj1YaXfOr65D/EZzyBC+Wg1?=
 =?us-ascii?Q?3BJuQanFTvh3+U27ZVDODJqk5ZUw7Y/GK7Qcx1n92HbcNBdyHRbr9gufcIUq?=
 =?us-ascii?Q?Bakdlbpnr1M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?b9eE+ydtitg5DD87b06XfKgNhSuJq2qeUs6Yi2OiZTovGExFvdpJ53AqMPQv?=
 =?us-ascii?Q?KA2hJy8U8I29EN6jgsCrMLqHJ6yu5jQrXmD964chhBoIs55OY+THNC7R5boA?=
 =?us-ascii?Q?hoqI1AeR1kH0cF/EznimrWKB3bdmVb5YEVFbluzPVoPVY36N+TtQ2Tdd7FTx?=
 =?us-ascii?Q?NVs1A+ybhJtW2Ij5yX5+1EnupRiN49tB54p5A3jV2rFgidMqx8gEqKEfoKYx?=
 =?us-ascii?Q?CtbGOhlWC7f2f0qGMsdY+qkB1Gp1CY55By/i9wMiHQUdxraAXsmhbW+U501V?=
 =?us-ascii?Q?gBl68aMWgmLqVCuypn+tr8Wo3A2LD5SP1Y0T73k+JoiWXx8OKGBYHZSjeWw2?=
 =?us-ascii?Q?PUZ7HNnD01k9Fwa+dM/nm60fIcsTFzmRyFBaUpw6+Gf53/qeo0swo2fy+6Pi?=
 =?us-ascii?Q?MyNGsa4kJjibpodXp/ajAZGPWmroZ93YYyYdqoo9qUBSSWtyIgTxmuyy8AYi?=
 =?us-ascii?Q?DZSwwM0Y+2r3HN+02y3fYZ7rTnP3Nl71CeSivydewU+dSgZkq8fbMQR39E41?=
 =?us-ascii?Q?DfgongAK073C6YGJx3hCRAMPvKwI071NnPeVDqFZHH2xT0fguG1jXAJkR1Ay?=
 =?us-ascii?Q?C807iQGZVwcnOXn2ZPWqz36ckJbPUv4VyXetWa0fCsAL60HVQMl+NT30EH+O?=
 =?us-ascii?Q?hVoNPVoVwH3TOlHi2ol0R5FqdiYBZrFzbWK+F61mox31nAVBWH5hbxvj9Gro?=
 =?us-ascii?Q?z1cNdiOGsnjSvRGYdDjoER7zS5/vyzq4QhiFRCHTxuiG8z04A5vczijLhgML?=
 =?us-ascii?Q?7ifp61w5F1hEiQqPJ+EMOQ568tylxeJtoPwSrMAuHCHXi5CRgN3g014gPoXH?=
 =?us-ascii?Q?A6WlRUh+jPMKyNT3cKfLRCJXAUnbtTzpnVqNmA/nXKfzDfqFjo9eAF7+t7SU?=
 =?us-ascii?Q?lLlrqQaTD+8YbvWbbFECRHvzeBTHXBclG9j3Qd2n52DeR97UsNw2ni8SyH7f?=
 =?us-ascii?Q?UzQZyzaLoGsQD9BeGNp1jliLvFbiMfNfepsZxYq0Y2/KbQQ3fneJ8AbNS4aS?=
 =?us-ascii?Q?i5fH4qc2n8HqIKjsTi4oPUuHecENWdioGeBunZTsq7KmiDxTuyCv9Ab3GJgV?=
 =?us-ascii?Q?cOPYckhfIB5jDUjXMLCUimog1hNpOkVB+hCTj9pPDRt8+yXPlKIhJFm1Yen1?=
 =?us-ascii?Q?pWkkNVAglUVrYHkknwdWA6kI4LLBiCx1Fm63rPUX1bE1k3cjO8GoqV1XKHTZ?=
 =?us-ascii?Q?Is0OQO2MIeU24VhBmIoveiKXzn+qszduO/tPdiGoe5kpCdQDzbejevez0Kw8?=
 =?us-ascii?Q?8nvIMyr14vlQwyuIcRsFHHwSabgjbRzVqk3TsIvLb/YxN3lyPUCZ6lludTSz?=
 =?us-ascii?Q?+rYy/a789n9Gr0aJGVLmb72vdGuVgZNVoMVaW1/y4/Rc6bH3f4gngQyidAxf?=
 =?us-ascii?Q?EpLo3i2Dd4lfsPnJLzba8pDWRsdNAoClNLWWCr7LTvLyYVZafqV/UtkdhigQ?=
 =?us-ascii?Q?pPfTN68wWaw6ZydMeA8x+AoXWWuARXZSpPp/m6ZR7VDDKWz48UXMBwaT9R2l?=
 =?us-ascii?Q?09abQOgEZix8rQsGKfvz+WWAMLv62iSmsky+bCm3xBPmFjwqqmUz4DoDs+WU?=
 =?us-ascii?Q?pCAvvVHFtP8Mb72SPIKz2UhlFsvr5MKmz/DYXwoVpcrHN4mpFOtykk4oHvt8?=
 =?us-ascii?Q?qw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 13cp3WG1reE0QSHzg3kDDvdulAH3xaIR29ip9De/pwyOFcmohYgMuj0Q6FLufo/b4FJJNo1YrNRX+eMN1uduv16RPp2gEymDNBTlVtfaoiUXLF1QvGdZ5wbsAUjmdAUBeLmG4A0Mv5F5j0wM7PXQSWBdmFiufiu1sC95e6cepEqOftZYayIEKnzj3mPPw3M2WZ1bhZZe6nYSZg1clBuo+i4Idz3INh/OoVmhLC63c9brCQ5GvwALfFxDWyzl8bw7aBELKaoQE3p0qWS7NPT/0O8NlWZ/Il9Y708BGHPatzHoRZfS6dbLHhQHSdzI1ay78yw3RED6jVXRJWdRLeeXkRm8IoWurHsUpONDke91JhevRSjh0kJ8V+d3MQMGQE7MHAKXy0M6PXO+U8fU5V67gxUSIBnCqEZqWq4DD7jLKduYQY3Ta5UePl17Ex6/UNjkwF3DtvP0KrGN6EBzg7NRRr/owtPi0pC7QzOu72qtjxh9lcqw5nY+gS0ZiX1LD8KemVH1AHTgesl652XaBjPIKhzYl3djpeVR2qhqSEJ/EKajgGbNDRXGfCrwDhz4p6jTzwRFUs1lnP40K04BWjwt76BTbJem+YpWB6jnfpczqiM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 898774d7-01ca-4c65-bdd2-08ddf61e0b0e
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:45.2071
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 2JAtkvv7bKRfCr47OLX50OxEsWr1zakpwE1IY6ooiLlSohzhZkyNFFLLl6MPLCxoGz/ibW0IpaRMMMo1r7mOunlYD3zz6sCe74DVGz+Mjk4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6063
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Proofpoint-ORIG-GUID: ntpcZGVnzBXfK1yRjO3xkGmtgtEPMBTp
X-Proofpoint-GUID: ntpcZGVnzBXfK1yRjO3xkGmtgtEPMBTp
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfXz87W9LQidiD9
 BE8MB6srEEwBVtt5T5y3t1x6xRuhwHWznGweRBO0Dyj/IWqgJbj1glO7JWnPjzYyWChH57PK4jT
 658lcer3yhlc51STho3DyM7UwUKnFKLz3ZAUmXiyIis3K02jrsPauSqIJlgsNPkIOE1BnyWPSwr
 FmaZjW7rARuiCILUZQOrIz+9sq9CkfBsCNo0cel4QP7ZLmOpxSYAYXedgT5D5JO/LB3VtE8Ne90
 Btuf2L8En5uUXGPhntvx0vzFNXTwouuVM+xeylU6EAObm9S5UG133ghVtmHASEbbtg8vVs4t4x2
 1bM4xTc6IrzNO81WxnSXAfhvwFqmzzfePVB0PJGxwBHCDYIRVYqnZDP5DaO7+frplCBJ6iRqreu
 NDj6hrqv
X-Authority-Analysis: v=2.4 cv=N/QpF39B c=1 sm=1 tr=0 ts=68cb07f7 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=Ikd4Dj_1AAAA:8 a=x0R6ikhiTiIxgpotQrQA:9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=kCcYTHtz;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=JvHqzdL5;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Update the mem char driver (backing /dev/mem and /dev/zero) to use
f_op->mmap_prepare hook rather than the deprecated f_op->mmap.

The /dev/zero implementation has a very unique and rather concerning
characteristic in that it converts MAP_PRIVATE mmap() mappings anonymous
when they are, in fact, not.

The new f_op->mmap_prepare() can support this, but rather than introducing
a helper function to perform this hack (and risk introducing other users),
utilise the success hook to do so.

We utilise the newly introduced shmem_zero_setup_desc() to allow for the
shared mapping case via an f_op->mmap_prepare() hook.

We also use the desc->action_error_hook to filter the remap error to
-EAGAIN to keep behaviour consistent.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
---
 drivers/char/mem.c | 84 +++++++++++++++++++++++++++-------------------
 1 file changed, 50 insertions(+), 34 deletions(-)

diff --git a/drivers/char/mem.c b/drivers/char/mem.c
index 34b815901b20..b67feb74b5da 100644
--- a/drivers/char/mem.c
+++ b/drivers/char/mem.c
@@ -304,13 +304,13 @@ static unsigned zero_mmap_capabilities(struct file *file)
 }
 
 /* can't do an in-place private mapping if there's no MMU */
-static inline int private_mapping_ok(struct vm_area_struct *vma)
+static inline int private_mapping_ok(struct vm_area_desc *desc)
 {
-	return is_nommu_shared_mapping(vma->vm_flags);
+	return is_nommu_shared_mapping(desc->vm_flags);
 }
 #else
 
-static inline int private_mapping_ok(struct vm_area_struct *vma)
+static inline int private_mapping_ok(struct vm_area_desc *desc)
 {
 	return 1;
 }
@@ -322,46 +322,49 @@ static const struct vm_operations_struct mmap_mem_ops = {
 #endif
 };
 
-static int mmap_mem(struct file *file, struct vm_area_struct *vma)
+static int mmap_filter_error(int err)
 {
-	size_t size = vma->vm_end - vma->vm_start;
-	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
+	return -EAGAIN;
+}
+
+static int mmap_mem_prepare(struct vm_area_desc *desc)
+{
+	struct file *file = desc->file;
+	const size_t size = vma_desc_size(desc);
+	const phys_addr_t offset = (phys_addr_t)desc->pgoff << PAGE_SHIFT;
 
 	/* Does it even fit in phys_addr_t? */
-	if (offset >> PAGE_SHIFT != vma->vm_pgoff)
+	if (offset >> PAGE_SHIFT != desc->pgoff)
 		return -EINVAL;
 
 	/* It's illegal to wrap around the end of the physical address space. */
 	if (offset + (phys_addr_t)size - 1 < offset)
 		return -EINVAL;
 
-	if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
+	if (!valid_mmap_phys_addr_range(desc->pgoff, size))
 		return -EINVAL;
 
-	if (!private_mapping_ok(vma))
+	if (!private_mapping_ok(desc))
 		return -ENOSYS;
 
-	if (!range_is_allowed(vma->vm_pgoff, size))
+	if (!range_is_allowed(desc->pgoff, size))
 		return -EPERM;
 
-	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
-						&vma->vm_page_prot))
+	if (!phys_mem_access_prot_allowed(file, desc->pgoff, size,
+					  &desc->page_prot))
 		return -EINVAL;
 
-	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
-						 size,
-						 vma->vm_page_prot);
+	desc->page_prot = phys_mem_access_prot(file, desc->pgoff,
+					       size,
+					       desc->page_prot);
 
-	vma->vm_ops = &mmap_mem_ops;
+	desc->vm_ops = &mmap_mem_ops;
+
+	/* Remap-pfn-range will mark the range VM_IO. */
+	mmap_action_remap_full(desc, desc->pgoff);
+	/* We filter remap errors to -EAGAIN. */
+	desc->action.error_hook = mmap_filter_error;
 
-	/* Remap-pfn-range will mark the range VM_IO */
-	if (remap_pfn_range(vma,
-			    vma->vm_start,
-			    vma->vm_pgoff,
-			    size,
-			    vma->vm_page_prot)) {
-		return -EAGAIN;
-	}
 	return 0;
 }
 
@@ -501,14 +504,26 @@ static ssize_t read_zero(struct file *file, char __user *buf,
 	return cleared;
 }
 
-static int mmap_zero(struct file *file, struct vm_area_struct *vma)
+static int mmap_zero_private_success(const struct vm_area_struct *vma)
+{
+	/*
+	 * This is a highly unique situation where we mark a MAP_PRIVATE mapping
+	 * of /dev/zero anonymous, despite it not being.
+	 */
+	vma_set_anonymous((struct vm_area_struct *)vma);
+
+	return 0;
+}
+
+static int mmap_zero_prepare(struct vm_area_desc *desc)
 {
 #ifndef CONFIG_MMU
 	return -ENOSYS;
 #endif
-	if (vma->vm_flags & VM_SHARED)
-		return shmem_zero_setup(vma);
-	vma_set_anonymous(vma);
+	if (desc->vm_flags & VM_SHARED)
+		return shmem_zero_setup_desc(desc);
+
+	desc->action.success_hook = mmap_zero_private_success;
 	return 0;
 }
 
@@ -526,10 +541,11 @@ static unsigned long get_unmapped_area_zero(struct file *file,
 {
 	if (flags & MAP_SHARED) {
 		/*
-		 * mmap_zero() will call shmem_zero_setup() to create a file,
-		 * so use shmem's get_unmapped_area in case it can be huge;
-		 * and pass NULL for file as in mmap.c's get_unmapped_area(),
-		 * so as not to confuse shmem with our handle on "/dev/zero".
+		 * mmap_zero_prepare() will call shmem_zero_setup() to create a
+		 * file, so use shmem's get_unmapped_area in case it can be
+		 * huge; and pass NULL for file as in mmap.c's
+		 * get_unmapped_area(), so as not to confuse shmem with our
+		 * handle on "/dev/zero".
 		 */
 		return shmem_get_unmapped_area(NULL, addr, len, pgoff, flags);
 	}
@@ -632,7 +648,7 @@ static const struct file_operations __maybe_unused mem_fops = {
 	.llseek		= memory_lseek,
 	.read		= read_mem,
 	.write		= write_mem,
-	.mmap		= mmap_mem,
+	.mmap_prepare	= mmap_mem_prepare,
 	.open		= open_mem,
 #ifndef CONFIG_MMU
 	.get_unmapped_area = get_unmapped_area_mem,
@@ -668,7 +684,7 @@ static const struct file_operations zero_fops = {
 	.write_iter	= write_iter_zero,
 	.splice_read	= copy_splice_read,
 	.splice_write	= splice_write_zero,
-	.mmap		= mmap_zero,
+	.mmap_prepare	= mmap_zero_prepare,
 	.get_unmapped_area = get_unmapped_area_zero,
 #ifndef CONFIG_MMU
 	.mmap_capabilities = zero_mmap_capabilities,
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/14cdf181c4145a298a2249946b753276bdc11167.1758135681.git.lorenzo.stoakes%40oracle.com.
