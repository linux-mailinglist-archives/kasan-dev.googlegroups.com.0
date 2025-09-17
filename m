Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4EPVTDAMGQEXMLEIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A769B816F3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:11:46 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-61e9f2870aesf147434eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:11:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136305; cv=pass;
        d=google.com; s=arc-20240605;
        b=L8gbX4VoBBp+PpA9XNNfyqXYVdP31CJV5iGc8AcxhjUecc0p7kqPbGdOgXfyZGq2kr
         2dbZEK2WWhdmbhMB6FBZBQejKVxCPdlsSeBTtH7PMBzqmSsnIXTrx1Bnxqu1NrAhqmVb
         TbIYvBppoZ2fBPBAAsFUOOkfdcwDAry2ixXfzexmKJM+4EYnN9XkeikT+Mocr+d91a1G
         yQTCiC+Vyuqr6v5e0b3cB8tcyNe0ERglclDukgNO3CFWvoJ6fdTPQXfWU2DCqEx/GjRD
         aKooi/f/EUGEodqKrFFwN9/9qLR2zGJUz0ytGcBApvD3s2ERHwzXHzwDTZMC/mrpZ72B
         gPDg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=aoG/i626Bxk36KYlR2yBzAZrEtdtSOu3RaZhwQ07XPE=;
        fh=vcYBoV8cGKXmm9l1hmtjb/ogXUBfFVCHsPxJ1cDV6LI=;
        b=BfJRCp5vPnVpbUzmEpwWrCmwTMT7gP5REIQ2/q6Vs7qUibUCFLZSsRAk/CeWjIdgX1
         HCOkvrREnpYvDbt3lSugeSBDzFw4Tug1P9dedpgYJ4YUqeWHc0V6zs6ZogMzka0yuUvF
         mqMJNe4MQbjD1TwFmIY4Jbe2BB3HKw81xzb/KSHm2/gZ8E9mdvZM5m02OjR6LnAuyTrO
         qaSRTPql4pwaMeD/CSSNZHUNrwDEoG3HIA/bAkbY5oQAkJ6I5ZSnUbLrDL7xhqI1Zsls
         XpdTz5mITDK+pQCfGZvabRKawVesQcqvrTQe6w/LiiAXxGTBwcHDrlRFbe1wWy/yPTEw
         S6iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pfO6OLZD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=zrfqA1Ma;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136305; x=1758741105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aoG/i626Bxk36KYlR2yBzAZrEtdtSOu3RaZhwQ07XPE=;
        b=ZmLKn46+WwwFBj/c980P+vi9HNcqvQLHBO6FoGgf5F99eesQzlwQqOSJZ3j5KOH+NZ
         3Y/gGOC+huHINH+znVxjf+U3khMoCR6pwvg6PDFKJdAgfZcgxGSWBPbNk3sLuitkX5N+
         0K5622NVYyHajLLxTLfmCl9Un5Ejj9wJIu8RI8EJYQ8R1KuIAcU90rNeNNcYM+b2I8Gi
         pNDUCgCVzDnAlNUsFlACVWNO6hYpbdm8zEQx52AQLhNufIcdCMlySbot/NNbNG4zDUcc
         DXsIQvZq9T9Whpm0fUDR12qHonmdVMqcW6HQdOxpSrRaJ4+znDwZUz0gcBIbP23URxM4
         kG3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136305; x=1758741105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aoG/i626Bxk36KYlR2yBzAZrEtdtSOu3RaZhwQ07XPE=;
        b=PRyA3aQ8/bM2p8CuGs6r1syamy14xdnME9MgXnSSFP5bTLepHklimLfr/sQS1LKdc4
         8o9mEZN320d3nPYyErb7WqqTxsm+MRiZfFWawnCCgu37+hQZzgzbz4wxcm/ecUyFq3qV
         ZjPTk0f27wSAyk42TPyPLX8V/OfWMuIXUGRH2XnPoXKAX6Yy7ekWFrsihSfSk2TeZk4o
         vQqX8tQRNA/jVquFytTO+IsrgZS2NrekfCI4yvNCYfBTmRUaPLlv5jFwuJpRPhXgOwpw
         LEy1InGfXlDAqK9ElYfW+/n2PRMpTxQbRRSinzRon2YsBXxh5K1wX5/nnpBmIy3hI5L5
         fuVw==
X-Forwarded-Encrypted: i=3; AJvYcCUN08kOUf25xWsm9mbP+kj5emjqv7RiBykOj0QyrVstELTEhUR2mPUKZF2SV92rXkiB4Mz9Pg==@lfdr.de
X-Gm-Message-State: AOJu0Yx4AFbN3LsoXK/gDCnnAbBrZy7tz/6iRnXYmtOfNFSTH9blW9Xp
	l1sjUTWLgvJiQ/uzod14A46qH1I6rz4SGUbmb00Bc8yYgKrhTaJwypLm
X-Google-Smtp-Source: AGHT+IElo1KNDkckp3ZinFH4LoLzJOq+kwG8Q/rqoPThjnVEYs/jSwP5SC/24T1Cd72wyQctuWmOIw==
X-Received: by 2002:a05:6820:555:b0:624:4118:ada1 with SMTP id 006d021491bc7-624a825691amr1641733eaf.8.1758136304643;
        Wed, 17 Sep 2025 12:11:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5gpQNTyB+jpKOJ4Je57mY6wWj8eZk2lc3DGkdurCQGlg==
Received: by 2002:a05:6820:c08a:10b0:623:4d59:817b with SMTP id
 006d021491bc7-625dfabf7d3ls23793eaf.2.-pod-prod-09-us; Wed, 17 Sep 2025
 12:11:43 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXMmUsbPqDvVKjh4PbxxC5An5+Fs7JAD5GZTNIM45InsqpP0xozWYhyKaRV+pXTOzI6T5mBLdi1OKI=@googlegroups.com
X-Received: by 2002:a05:6820:1686:b0:621:b78b:6c83 with SMTP id 006d021491bc7-624a48a2b60mr1716783eaf.1.1758136303459;
        Wed, 17 Sep 2025 12:11:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136303; cv=pass;
        d=google.com; s=arc-20240605;
        b=jFP+FhecDz5Q87rTJ+MAvpxuCzkoZXDIyHqWnle+K0NK0OViH3zqq5ocb/WDZv6cbh
         xFilK4VH5lRfyd1i4BRLanshmPgINOgTKG5IZywlHCXtRLSyXO9scECu8lVU6N1KEk6W
         LguORKtodTGK7SHkentMLcrVf4D5RRcaqo/JCQzQQ6ZRxGWtr30AGsuDk+E6cJRbIyFm
         vhmWokD5nmTpSGk+w5pbR/yqz0r1AaTTFvcxq+x+XAo8CFi+CO8zZf7xDChqYx/aSIj4
         6DJOYnDbqZJS7PNguL7hECfvJugDjxM7YwCEx6ykTNhLLGDF+AcqZpBbZG0ka23AUOre
         I4UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=04ZLkxkHhCodYQAhIC3JkoW8/kMpL+Uq7UOByGpvuw4=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=YCmwl/yRu2Kc9TVqVG9gLTzCi2dND8SNx0vSmBPhjlPHxAcHijx3ppfmVH0gDvotdN
         ljqgjcXBl8iMR6dWSumP0n+8SjYJL3m8zSUf086GPMi0zkTxS5YgJRv5C2NQPddWXPzo
         1TQJ5bUne/EQd8B8zhsV7fw04e8qpO5WOcftrbI58EcY5mtKpUP4GegI8JS5WCw9+IrF
         U5HgvuD19jcjWYlhQDzImTT413lpIYDAO/wmosT6Teyo4T4KZUs9NkBy7S3oQ66v1rzn
         10CiLCHVG7sNhcAWPWqQQ4zT2sf8pjWEEMUoZ4dsmUdUPvzVYyjCyilMyBWrphSAfaZo
         cuDA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pfO6OLZD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=zrfqA1Ma;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-625d5367109si8271eaf.0.2025.09.17.12.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEIVwZ014271;
	Wed, 17 Sep 2025 19:11:29 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497g0ka2b7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:28 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HIf5xr036751;
	Wed, 17 Sep 2025 19:11:26 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012014.outbound.protection.outlook.com [40.93.195.14])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2e76fp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:26 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=G+ef/s4MuB0OpSVNEXF2b+uchPjfLixJ1MS1VPw6FeDtN2yRgEAgEODxsnPdEOPJsoqSl/vrQg5L2CDooIF04IL7s/0o5pz2oLpNmBkS5aOjU4yoNCZU/1515t9t21ifQGustijlPAes1WCUjA5RAWEC1vb49Odrw3CTaKHSMaFfmcGT3LwZucG2eOqtvSNJ2yLCnmezzK+bJVQ3ywB70AsRvb7TFkW3wSJK2ElDtEFK9qzVBdhlmH6BpmBNmoTHK/rHiFRfhLXmpXFOS7cgPOKe7N6jBiNeWa86V1gRLhgKn9Xz/Yva0qYNzI//q+OXKNb0ri57uzTu5sBywNV53w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=04ZLkxkHhCodYQAhIC3JkoW8/kMpL+Uq7UOByGpvuw4=;
 b=pRt+6aoh9tvWc4CfhLLSA3COaD6cljzSTNFdz97pOGW0t/G+6t5LIQOScPOu/ChM0E/dp8iWmD4sQ3Onirktp6Rbnwktk1d5DG8xxkynxjqz9pHbeue3SK3Q6gBsbiaUHJkCvbn697NGg+6c4KcJXqTLv7uKo+pRCCtz2oV3sryAgbkxNlIzJEIkIaVFXBR13YuZH0uXtkfPSBvyvHzZDYOvh+LHv3BSyzTNap9D1Q1MIusSVkdPKiDI86xAYmXjq6BzAZEe9BPV6x6DDRLBVsbLO82reGUPAhg47rtE91n9OEf594ycOixE3RH0TaAm8j6YabG/8MtBcji4XtfmYA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by LV8PR10MB7774.namprd10.prod.outlook.com (2603:10b6:408:1e8::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 19:11:22 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:22 +0000
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
Subject: [PATCH v4 00/14] expand mmap_prepare functionality, port more users
Date: Wed, 17 Sep 2025 20:11:02 +0100
Message-ID: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0324.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:390::8) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|LV8PR10MB7774:EE_
X-MS-Office365-Filtering-Correlation-Id: 81c9f065-7f67-4a93-7943-08ddf61dfd8c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dcMM/GL0lN9Ayh1CWtx5zme6OS+HzSmoFjKaxZlrah68U+xNg4LP2VXzWFsL?=
 =?us-ascii?Q?3M4rxIYqYx3hE0EG3uLCmWa6N8vZ3K3Lz5FyGtdTC01p7QWcHZQjz+MA2xRm?=
 =?us-ascii?Q?2HCzb61+6X0wVcDb/r6a1qDq9XMSas6H7lQzmdHPj0av07ksjQvwtdecUNxP?=
 =?us-ascii?Q?1M+181aISllHAudLnLrePoslinqoJJ8Q3b8tsiosJr62Ow1En/8yJTnKb97q?=
 =?us-ascii?Q?hDFQWtcVZTtCzDUzu3iPYaheCeE9ajv67wHrFWGOeFb65zlDlML2nfPtd10O?=
 =?us-ascii?Q?C9JlwbNSQFAvnsUJaAmT7RBvzri/QI9Ura06aUzDUQWK9avla+AEvNoidZY7?=
 =?us-ascii?Q?BZZaX9gQrHO4CuNpXS43LnjPU61qkJhmSrg/HbPwG80ySl+c+fBgcPcd5+l+?=
 =?us-ascii?Q?3JdWQRnYfJ/QMB4Xx3ALGwMA7M6xoQDh9cY/ilEF/zusS99wFwAs/xwHRgEx?=
 =?us-ascii?Q?6EprNCaBEb8cUBTllqjlVyxS8hgmBuTfKsVJ79kJ7eeXMfEqjH94TuyMldtj?=
 =?us-ascii?Q?1rf7TjAmGbBcXIv4TrAY1qj4VWSndpF08BAlrNoxVU4SfnfidemjPh7dXO+f?=
 =?us-ascii?Q?Ppdt8aYYP+TGJrZnlZ0fhKqFusgZF9vAARUGCXR/RR0STCeSbCl0tgthar3S?=
 =?us-ascii?Q?1CinELwMpMWsE04yrVK2Iuo9lPcz4LGJF0pgY8O7P8MU+ECOY+WxuJ1suZNT?=
 =?us-ascii?Q?hZJ4CoYBVOYiqHe5ohmassje02x665GS474Z08RK+3mjWtRiefI/3Snyg53/?=
 =?us-ascii?Q?IHk6A55DYMxOBNDqsWpt4fdZd/LmwvMlt2WB4rHzizrdtQetzKmKbnMcXXqE?=
 =?us-ascii?Q?Rv7s5f5TjQjrRzHlue+NEYBXJO9HipdEfmEBus1E914AFWLfbeLF6eGuBnhc?=
 =?us-ascii?Q?INQOxk3RtBFX1RqTpptCs/S0+ENlqqbQnUYokL4xoWpglemS//oRFTXVseqT?=
 =?us-ascii?Q?dCzUpLCejeqRUx8WLiYziEElPAogmuXUzuTLVgIAq+mhHvowNEMOqgSuEHm0?=
 =?us-ascii?Q?iMDSkTdC147NNL9AFVN5OtxAc1KS6e6gR63BxBjw0R8H5cRIVzccMP+wxU09?=
 =?us-ascii?Q?hAS8IONIDfh3quEO6W4z/fKmYX0noj1EqZUdx3Ear4rLZgVCu41o5WHYNv3U?=
 =?us-ascii?Q?dhzdLJWcUxyEaBy3jEuyqaiVhgIUum44W/D+ifzC/cJ3o3ZFXZoBSkbfKPO1?=
 =?us-ascii?Q?vW3fmwg5n2wIyzqSl2V88p0GRhHaQny3vM4beXXfoasGvMOnEkPuCPROMW2S?=
 =?us-ascii?Q?27FenuzEvvAahISkLO7wbD99uWhArDsPJWKAWEaNX/n8XucFHgmb6m27rgai?=
 =?us-ascii?Q?KYBMxEEz/ZzXhlpPkvHA7LMj+7zi8RyZxSwPgRktkTq5iL8l8Cb3yLbUp6YJ?=
 =?us-ascii?Q?BmgynGd/UdsqtFg2NSsw7/Nnyf5R?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KwbiteC396uko9UN96VMZI9zp9NKVYhDye/uyPuqqIaYgZTNJ6xNCIUjzIHl?=
 =?us-ascii?Q?FyY2XWuXavVECwK5qR68tCQFVDnHdiMW6+v1pW4zGOZQMWQNWA6oH3H1ogRO?=
 =?us-ascii?Q?BVBap6kpClTiDH50I/oEnam0ON0V601yIl7Xb9N9xwBcswkzTb18W/OsArBw?=
 =?us-ascii?Q?FNzr4qvYYbHKFg4mvmI18caxXXzCxoer1QbM9VvBI4isKVLT3Ktokrm9v9sV?=
 =?us-ascii?Q?63J8j3iYjXw23mxg9OFi0WPIQU2PbW5/YcpFkQNLdwREWVo3d6LBijXVbbVF?=
 =?us-ascii?Q?ALcUqqbngZOViUi+v/dEgFfTGKcQdS3YcjCjIPDU1rW8kSdZBwI2oWl45zNc?=
 =?us-ascii?Q?yikyRt1Lj1MX0OW2ar0+D/CHQydR8GCHwUmNJi9LSpG/zR11njO9LkE1zG1W?=
 =?us-ascii?Q?TyNQzACYlIyZJ68w7vcsGY0x+Goa26PKHiq4AUWX+0oVEiUOgnt16I8rH388?=
 =?us-ascii?Q?2AhzN1m7AsVO3ynNABKGrhpQ2LPYJOXTtgOSP7G3tIc+S67NJVVAHXBTS6Qv?=
 =?us-ascii?Q?7KyYaEB5n+Zzyvjf14DPkjdemTiLuMsMUTzERBMaEyNKv5Y7FUOLw0gsPult?=
 =?us-ascii?Q?Gw6fgjpwThV58PnKcem9QiKwSBuTAFp+fDKrGKJvstHCQfAFbm6X5Zb4HflJ?=
 =?us-ascii?Q?gkwmSEa/lZdO+R6Eaaxqm8TGs2ItKapiJ50Ni+0XN/8EBaORfrrfjwuZe5Aq?=
 =?us-ascii?Q?1BOR82MkWlmL9SSZYeJAJi6SosR0+Tm3HGKoBbOmCG4Dp4fvGi0eDaofwA4v?=
 =?us-ascii?Q?RnjnTVXm1uwufs6uk7PyvVo9ffo6784prR+RBvDvTep+FXGgqLkSPp2L8ux4?=
 =?us-ascii?Q?f6V98HTBU3mPv4KdctBuJqDP88j8iy/xlJJfuNnrOx9/wG2Ns0Rk+c01Vhvw?=
 =?us-ascii?Q?iIi7po31X7gX0v2KVdAU1Njz6umOe0UekRp9T2DAfRU8YjNS5v/lrTWwWfOG?=
 =?us-ascii?Q?WSTSohNt+c2V7qB4LPlFBiUr9XgXSB0KNXpg94JPHrhhOscMRKabPc6IVCy3?=
 =?us-ascii?Q?+Ox2Ld60Qs+l2YvrxrUe7pUDQNoU3fIA9+Gs6wpMxMnQScDUhYQIw+stpF8D?=
 =?us-ascii?Q?WSomZiwhFl83JgYVpF/GGgZhb053Xre/J4plgfPHQvt/ISI2wZrVZSgHo4Hv?=
 =?us-ascii?Q?Yj7iQH5R7sXgzAp61Iwt07ecxqhvNGeFW7fyCjmd5bVvndgM3C/FtEXuzDuJ?=
 =?us-ascii?Q?TxxVn91oEkz9YOfhKpbs+mqAMT5bsErDdKAr8LmxwWoK7pYfn7qt2yQ4pXVf?=
 =?us-ascii?Q?/k+8KV6+v/Z15DcG50QU1/8QopZI/lyt6uM7BqEHndfaAaLPnlvUJcc2ZoXV?=
 =?us-ascii?Q?YwOOKXqB9YFpZ8VRgL+Rp4Qb8QCgGpx0jViOGMbQohb9jmKEDiU4zQnB+0HQ?=
 =?us-ascii?Q?8Zm8Q0xehQGiLEQNWHM5ocgtun0vd7VwrmPCjOEixcnxlztEernETwVOzSa0?=
 =?us-ascii?Q?2iBiensq52lrn8gUsXWhfyWOU79aIQs6nk3B5uYFT3DksdHdAHgkqk6yuG4p?=
 =?us-ascii?Q?13ylMMO7bQtPSlycOGc1uGz/m7gAOL/HH/KBi+zMD+FUNm6T0fAcjSgunQnr?=
 =?us-ascii?Q?s/gjfVTs082nGVelEMYKLY7AXRvQHv+UC5s6ODWz62UKUlf6IeRKluo7F2wd?=
 =?us-ascii?Q?SQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: OL9bPBElBFkbVR79FocwlQ4TGZAFUrpnwIs057qv5njiMVBXMocUQZzl8M7joHelhHBrLNPySOu93bB9ZhfjjIENDofX23HnzAJ26jyyIwFqBtUgq5rAe5qTWGYUKcsvuut1aepmDwaRXygI4ARrIv1Wx1WaeGYYtV7Pff+aNp8qQV4Mu/McJFHHO8CufruEQcAROekDSnEvndiyBPQGKefJILGlmjLcQhHwSB9/ft9m7U9oaMh9vsndeXo/MpH3WDDpT3egIq1sTTmftgucM2ECibfSWu+Sjia3c11OS0w4sj6rHoi5mK4kgig2By8QWRgaGS4x6ildTDr7O7FP+4kuk6UouOldCt7iT1FWn66WsH25XBSoPvomG2Ll5xSb7HBcGAi4cR+G23H7MCDbZnhfLM1bz91y7MQ2hKi/1tVMFO6pmG6a4jSCxatMVs4Njudn372MIY/TZEXOamsgKScm3fWZQ6HDWy5lO3SQ6rV1xN843PA8uJngU+CHULpj3GFE2yhQEs7u9G5Hzjb93hsL3O0jFuQRjvGMw3C9nz82Ug9GXTyUDdkXhSFcMaIHdVLavKq6LLCbJOb/Bt72jFnKtud2rfIJmKF975lVBOE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 81c9f065-7f67-4a93-7943-08ddf61dfd8c
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:22.6112
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: DA5hJc5ItX83m/N+imESlWElv8WdmO5GbYcpS/jaUrBPow0BrkFQhabeKUaSSnUiE1m71x0jAd8iDWb61edqWPBnt+vYO6QM2weu0ksu7TQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR10MB7774
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509170187
X-Authority-Analysis: v=2.4 cv=b9Oy4sGx c=1 sm=1 tr=0 ts=68cb07e0 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8 a=Ikd4Dj_1AAAA:8
 a=KjnsR6uzOoiuVaV4c1wA:9 cc=ntf awl=host:12084
X-Proofpoint-GUID: OLsaZ1LAXqnbMw3FiN7fPHbs7bI9LZ9O
X-Proofpoint-ORIG-GUID: OLsaZ1LAXqnbMw3FiN7fPHbs7bI9LZ9O
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMyBTYWx0ZWRfX0Nqau0oc10oM
 cocCOqpmKLnMks31FzBqKxsRDvaYJ9OKQ02SDGU/4K/qh5qBD+gEjrj6pekOWwIu9zHqIoH/f9b
 dguzCiP+ppxf0mve9AuWZlngUfJlwaYbgPtkXNW6U0Cw5/4+RMH8g708EUjr/8Xva/4F/b80mdG
 gXmIWm8xY33jKeRejWqyTYpPr6xMNvr9jQWXfAa9EC0N9DhZ40CKR0BhOGkC5oiURFTB5E9RMxf
 uK/JVxnQIEiFZxstTCeiSZbQdWL5G50Lr7U6B4kZFpgaTnMnyeDu3CbLb8X6xeX/ZR9fCS6Z2hy
 /dIYQA2GpEnodYPlQDokJYq0nkaX5IKQeaxKBUPN8tU1TzTv9eLYX/x3IMg8mW15eeMo0jqcF+v
 7WmOWxc0OAvlgdPvQj+SVr2kLNo+hg==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=pfO6OLZD;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=zrfqA1Ma;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
callback"), The f_op->mmap hook has been deprecated in favour of
f_op->mmap_prepare.

This was introduced in order to make it possible for us to eventually
eliminate the f_op->mmap hook which is highly problematic as it allows
drivers and filesystems raw access to a VMA which is not yet correctly
initialised.

This hook also introduced complexity for the memory mapping operation, as
we must correctly unwind what we do should an error arises.

Overall this interface being so open has caused significant problems for
us, including security issues, it is important for us to simply eliminate
this as a source of problems.

Therefore this series continues what was established by extending the
functionality further to permit more drivers and filesystems to use
mmap_prepare.

We start by udpating some existing users who can use the mmap_prepare
functionality as-is.

We then introduce the concept of an mmap 'action', which a user, on
mmap_prepare, can request to be performed upon the VMA:

* Nothing - default, we're done
* Remap PFN - perform PFN remap with specified parameters
* I/O remap PFN - perform I/O PFN remap with specified parameters

By setting the action in mmap_prepare, this allows us to dynamically decide
what to do next, so if a driver/filesystem needs to determine whether to
e.g. remap or use a mixed map, it can do so then change which is done.

This significantly expands the capabilities of the mmap_prepare hook, while
maintaining as much control as possible in the mm logic.

We split [io_]remap_pfn_range*() functions which allow for PFN remap (a
typical mapping prepopulation operation) split between a prepare/complete
step, as well as io_mremap_pfn_range_prepare, complete for a similar
purpose.

From there we update various mm-adjacent logic to use this functionality as
a first set of changes.

We also add success and error hooks for post-action processing for
e.g. output debug log on success and filtering error codes.


v4:
* Dropped accidentally still-included reference to mmap_abort() in the
  commit message for the patch in which remap_pfn_range_[prepare,
  complete]() are introduced as per Jason.
* Avoided set_vma boolean parameter in remap_pfn_range_internal() as per
  Jason.
* Further refactored remap_pfn_range() et al. as per Jason - couldn't make
  IS_ENABLED() work nicely, as have to declare remap_pfn_range_track()
  otherwise, so did least-nasty thing.
* Abstracted I/O remap on PFN calculation as suggested by Jason, however do
  this more generally across io_remap_pfn_range() as a whole, before
  introducing prepare/complete variants.
* Made [io_]remap_pfn_range_[prepare, complete]() internal-only as per
  Pedro.
* Renamed [__]compat_vma_prepare to [__]compat_vma as per Jason.
* Dropped duplicated debug check in mmap_action_complete() as per Jason.
* Added MMAP_IO_REMAP_PFN action type as per Jason.
* Various small refactorings as suggested by Jason.
* Shared code between mmu and nommu mmap_action_complete() as per Jason.
* Add missing return in kdoc for shmem_zero_setup().
* Separate out introduction of shmem_zero_setup_desc() into another patch
  as per Jason.
* Looked into Jason's request re: using shmem_zero_setup_desc() in vma.c -
  It isn't really worthwhile for now as we'd have to set VMA fields from
  the desc after the fields were already set from the map, though once we
  convert all callers to mmap_prepare we can look at this again.
* Fixed bug with char mem driver not correctly setting MAP_PRIVATE
  /dev/zero anonymous (with vma->vm_file still set), use success hook
  instead.
* Renamed mmap_prepare_zero to mmap_zero_prepare to be consistent with
  mmap_mem_prepare.

v3:
* Squashed fix patches.
* Propagated tags (thanks everyone!)
* Dropped kcov as per Jason.
* Dropped vmcore as per Jason.
* Dropped procfs patch as per Jason.
* Dropped cramfs patch as per Jason.
* Dropped mmap_action_mixedmap() as per Jason.
* Dropped mmap_action_mixedmap_pages() as per Jason.
* Dropped all remaining mixedmap logic as per Jason.
* Dropped custom action as per Jason.
* Parameterise helpers by vm_area_desc * rather than mmap_action * as per
  discussion with Jason.
* Renamed addr to start for remap action as per discussion with Jason.
* Added kernel documentation tags for mmap_action_remap() as per Jason.
* Added mmap_action_remap_full() as per Jason.
* Removed pgprot parameter from mmap_action_remap() to tighten up the
  interface as per discussion with Jason.
* Added a warning if the caller tries to remap past the end or before the
  start of a VMA.
* const-ified vma_desc_size() and vma_desc_pages() as per David.
* Added a comment describing mmap_action.
* Updated char mm driver patch to utilise mmap_action_remap_full().
* Updated resctl patch to utilise mmap_action_remap_full().
* Fixed typo in mmap_action->success_hook comment as per Reinette.
* Const-ify VMA in success_hook so drivers which do odd things with the VMA
  at this point stand out.
* Fixed mistake in mmap_action_complete() not returning error on success
  hook failure.
* Fixed up comments for mmap_action_type enum values.
* Added ability to invoke I/O remap.
* Added mmap_action_ioremap() and mmap_action_ioremap_full() helpers for
  this.
* Added iommufd I/O remap implementation.
https://lore.kernel.org/all/cover.1758031792.git.lorenzo.stoakes@oracle.com

v2:
* Propagated tags, thanks everyone! :)
* Refactored resctl patch to avoid assigned-but-not-used variable.
* Updated resctl change to not use .mmap_abort as discussed with Jason.
* Removed .mmap_abort as discussed with Jason.
* Removed references to .mmap_abort from documentation.
* Fixed silly VM_WARN_ON_ONCE() mistake (asserting opposite of what we mean
  to) as per report from Alexander.
* Fixed relay kerneldoc error.
* Renamed __mmap_prelude to __mmap_setup, keep __mmap_complete the same as
  per David.
* Fixed docs typo in mmap_complete description + formatted bold rather than
  capitalised as per Randy.
* Eliminated mmap_complete and rework into actions specified in
  mmap_prepare (via vm_area_desc) which therefore eliminates the driver's
  ability to do anything crazy and allows us to control generic logic.
* Added helper functions for these -  vma_desc_set_remap(),
  vma_desc_set_mixedmap().
* However unfortunately had to add post action hooks to vm_area_desc, as
  already hugetlbfs for instance needs to access the VMA to function
  correctly. It is at least the smallest possible means of doing this.
* Updated VMA test logic, the stacked filesystem compatibility layer and
  documentation to reflect this.
* Updated hugetlbfs implementation to use new approach, and refactored to
  accept desc where at all possible and to do as much as possible in
  .mmap_prepare, and the minimum required in the new post_hook callback.
* Updated /dev/mem and /dev/zero mmap logic to use the new mechanism.
* Updated cramfs, resctl to use the new mechanism.
* Updated proc_mmap hooks to only have proc_mmap_prepare.
* Updated the vmcore implementation to use the new hooks.
* Updated kcov to use the new hooks.
* Added hooks for success/failure for post-action handling.
* Added custom action hook for truly custom cases.
* Abstracted actions to separate type so we can use generic custom actions
  in custom handlers when necessary.
* Added callout re: lock issue raised in
  https://lore.kernel.org/linux-mm/20250801162930.GB184255@nvidia.com/ as
  per discussion with Jason.
https://lore.kernel.org/all/cover.1757534913.git.lorenzo.stoakes@oracle.com/

v1:
https://lore.kernel.org/all/cover.1757329751.git.lorenzo.stoakes@oracle.com/

Lorenzo Stoakes (14):
  mm/shmem: update shmem to use mmap_prepare
  device/dax: update devdax to use mmap_prepare
  mm: add vma_desc_size(), vma_desc_pages() helpers
  relay: update relay to use mmap_prepare
  mm/vma: rename __mmap_prepare() function to avoid confusion
  mm: add remap_pfn_range_prepare(), remap_pfn_range_complete()
  mm: abstract io_remap_pfn_range() based on PFN
  mm: introduce io_remap_pfn_range_[prepare, complete]()
  mm: add ability to take further action in vm_area_desc
  doc: update porting, vfs documentation for mmap_prepare actions
  mm/hugetlbfs: update hugetlbfs to use mmap_prepare
  mm: add shmem_zero_setup_desc()
  mm: update mem char driver to use mmap_prepare
  mm: update resctl to use mmap_prepare

 Documentation/filesystems/porting.rst |   5 +
 Documentation/filesystems/vfs.rst     |   4 +
 arch/csky/include/asm/pgtable.h       |   3 +-
 arch/mips/alchemy/common/setup.c      |   9 +-
 arch/mips/include/asm/pgtable.h       |   5 +-
 arch/sparc/include/asm/pgtable_32.h   |  12 +--
 arch/sparc/include/asm/pgtable_64.h   |  12 +--
 drivers/char/mem.c                    |  84 +++++++++------
 drivers/dax/device.c                  |  32 ++++--
 fs/hugetlbfs/inode.c                  |  36 ++++---
 fs/ntfs3/file.c                       |   2 +-
 fs/resctrl/pseudo_lock.c              |  20 ++--
 include/linux/fs.h                    |   6 +-
 include/linux/hugetlb.h               |   9 +-
 include/linux/hugetlb_inline.h        |  15 ++-
 include/linux/mm.h                    | 136 ++++++++++++++++++++++--
 include/linux/mm_types.h              |  46 +++++++++
 include/linux/shmem_fs.h              |   3 +-
 kernel/relay.c                        |  33 +++---
 mm/hugetlb.c                          |  77 ++++++++------
 mm/internal.h                         |  22 ++++
 mm/memory.c                           | 133 ++++++++++++++++--------
 mm/secretmem.c                        |   2 +-
 mm/shmem.c                            |  50 ++++++---
 mm/util.c                             | 143 ++++++++++++++++++++++++--
 mm/vma.c                              |  74 ++++++++-----
 tools/testing/vma/vma_internal.h      |  90 ++++++++++++++--
 27 files changed, 799 insertions(+), 264 deletions(-)

--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1758135681.git.lorenzo.stoakes%40oracle.com.
