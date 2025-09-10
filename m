Return-Path: <kasan-dev+bncBD6LBUWO5UMBBHF4Q7DAMGQE5CUTVHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B0929B521AF
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:22:55 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b522037281bsf14714a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:22:55 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535773; cv=pass;
        d=google.com; s=arc-20240605;
        b=WRgtUfF9LS/01lvQh3dwZirO1R/GpQcQyD1x8zuhCCYOFAYSwii6yDIdlQj4vjTMYG
         W88Q+1twndrb+0JCx1xwlWAfzPzw8xl051u52qQ8gcMZwWLror38HpMYsVN3tIIWKeQS
         3U/pzQBn1OibXSE608z6xZ+I8BS9zN9YUa6Y9fCb1pc8Koc2KwyEBuB2LRi4HTg/y9zk
         NEY6QTdiZEEctnXbm03YBb7NULgT6Uc9EyKaE28nRIy67bi8G8WBQ7489f6UXXvSNJnQ
         1BM37MzTC6GCPfHfVerPaRvHgNSF4cOO41Bj2EDVHIMtLytVHs0vWzukBWEkzI418EkE
         N+OQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dnuZEr2wNr6PdcSvSbTWrWvPLeQWExrvpT9YXboP2kk=;
        fh=lhIzwdE4L1WGfjoQCtaPSXWwqYnO6rLLtF/w8womqAs=;
        b=ZtxVWUhgaGf/c5UoIk6BlUsrFHwsXusz8DLWyNSKhyZPNGMmez/yHtVWQp008cZ89K
         Mn6KKn8Jvad9L7ySZQ0WTA80IayVps4KsgXm/Dtyln6mSd4OESBgSS4qXhDIPbniDBfq
         nOSZlhjYhjWT9bKLsPtS+1sVF+3W7AD/Vv5foZp3HFWss6L36agv7OGTCh+gpVFBFev/
         Mm2ahnIFPiWy2jPt3e4AICCmbT4tInz6Wuv6/0il5JewgSgLYJXyPJfahKh0Ru40Xko6
         9QdqVRvbJSd+ot4jvJ9tXbYKd46xkmKup/emVpeQtPgIeO59mo/thlamlSM0i7acdDvk
         KQGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lj8xAgLI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=luJiU53S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535773; x=1758140573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dnuZEr2wNr6PdcSvSbTWrWvPLeQWExrvpT9YXboP2kk=;
        b=hufNiQaBwXEHLKD/ycb19IYvk+aTpWNOvWx4zCtboKw4Jl7o/y57i1kP8LVOTwZg4L
         Yqd9A14g7SP9wVsXE4wjCmrcJVKcM3fHAv6TJtKsaw9MT+xdbdktPe3MvL8H//TJd8a9
         CMfbHao0tvlOKcLyVjEu09wtC+3D2uxZyiibWuhxXaSj6GPwW4C3+k3/1Qw7htwlCeSM
         fXUkNahEEeLY5I77saYF0jNgGV2Hlu3LQDQ0QrXNucmVHXFHW8u7a5g79pW4NcfYFdnV
         gRpHYg80krp8Kg+q/OgasxCL0lqHCpCnfrljy7FW0inFnQGeZo3LO0RZgg2KY954x9F1
         wyRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535773; x=1758140573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dnuZEr2wNr6PdcSvSbTWrWvPLeQWExrvpT9YXboP2kk=;
        b=UF3A1OK5mPOJFZURs0CuboIAhsUoQ5maFJHz4d8b4t5Zcaz6Z/V9R2cw/ttVuu1qPX
         rV2vkqnO2yGmFXSvnyheU7MMCCzIvyVPjxyuYVEKjOv9Vc4CizDFQ2jrUBlZfbDfOrn8
         MsE+KWrmekfB9k/8HPfDt3V4yR+d61NYhDtxLfAvRQk/fTDRyaToan+xvA3rk7MgE7+y
         FTa1JokDiYSoylC/XGhrBnk8/7wfweeI5I/IuuMMOjRxi+GmkmUYKgZFxZofh+3yYMKH
         FxC9HwV4xkrygV6hjSoRYKhURphDvcK6hkuWCPFkUwRdKfdV1jCvbpPfEvlQHakWNVQ4
         MTjA==
X-Forwarded-Encrypted: i=3; AJvYcCVH9//qIAG0n8hTDyTkYFxUNJs+rj7GJscnCu3hvtWj7hRzr9qWDqKTO+3kQqvPhL/6j52jKA==@lfdr.de
X-Gm-Message-State: AOJu0YxvFvw6T7CmmqHOpcuVkHNifEr43PAT9Lylt211Fp5kD7Us+fIg
	DApla9eSR60kcoJyO+YliKU2YCTXDjYhlj8fSkEzsFOkaJukMkq9s36g
X-Google-Smtp-Source: AGHT+IGPcmc3fY03rtIFYSve+aRilJGGKMmI6IqtfjSBX6PJ0a6cpWMtqMJ9d8X2j1MEGKHnYhf/LQ==
X-Received: by 2002:a05:6a20:939d:b0:24f:f79d:66bc with SMTP id adf61e73a8af0-2533fd956f5mr26358586637.24.1757535773460;
        Wed, 10 Sep 2025 13:22:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZddgJzKZ1h0+uirqSfoSH9NZu6DSPrHt/tFUY1DvYhzTg==
Received: by 2002:a05:6a00:17a4:b0:772:4235:4c0d with SMTP id
 d2e1a72fcca58-77604e13bbcls41891b3a.0.-pod-prod-05-us; Wed, 10 Sep 2025
 13:22:51 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVbL5xJEOM7EGCuXcRnJRzO4LrmyUqOnQ/0jTttnuffsdCiCzuIeGPRNorEpEnu5pN/2JLRRMKK7Pw=@googlegroups.com
X-Received: by 2002:a05:6a00:3d4f:b0:774:1ba5:91df with SMTP id d2e1a72fcca58-7742dc9eb0fmr23155719b3a.6.1757535770739;
        Wed, 10 Sep 2025 13:22:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535770; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jr+kFHxqQHW2KR+ORHE26w3lODV6wUjfsQUaITBfGRpV1m0CqJ25AlTA8CI/v6bPzn
         0DwEAVAUqvOpMGP4yLzGu9D3KktALpMMmoThUyl87NrcmBq/rCMW4eSWq0urbj/+59Jr
         +0s6x/aiQyy0H03rWrGAB7fYG8+zaKz0z3ePNh2SZG7f73q52JP98eQ5XNbEd0KKHx75
         2vxoBeS0gqFalCUzU+5/yx39ESR/muXjICm/nBYsegwG0hO7bl/DqzGKi3gvrTcZsKvf
         4vGSp5AgOMgwIjKRaW1XIUez4Yty6e0CP8PoAV8p46kH7rlf90yjQgZ1jpzT9hrf2+hA
         rkZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=0cG/XxwNz5xQssOe9Mru2Eu/iCohBsLiNJ9+rdrZYTo=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=gcrnpXfkkrloe22se4QIFEpG+q0D05l9XvSzYiKX1e9qZNt1q8w/bJJDpWc18Woi6y
         PYagMabZIUzgA+UeqpWRVAfQf/zQqE8Csq3gCmyjmKTA8UXBmQJH2sdNXiwRheBPGpP3
         ZBTZywAYje6h18T0wmzAWUmero71MBB9heKMtSNQduEnlCn2ql0Ilsi5y+CnT09qKZgn
         59V/eUGLgB0QGmaYjor8GVgQQdippUNaih0YGbgoMeUtds8oOQzzAQLxnuzyJvN2IaD0
         bxXVxNDOWtJkkZYe6f9L5FfQlkzfpp/uIa47LaGzuXoQZp/SfJ9UDsgynV4gXXyGzRUz
         VNZg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lj8xAgLI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=luJiU53S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7726452229bsi578550b3a.4.2025.09.10.13.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:22:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfiDh009732;
	Wed, 10 Sep 2025 20:22:40 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922shvv1r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:40 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AJvaTY026078;
	Wed, 10 Sep 2025 20:22:39 GMT
Received: from bn8pr05cu002.outbound.protection.outlook.com (mail-eastus2azon11011001.outbound.protection.outlook.com [52.101.57.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdbhb9x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:39 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Q6rRZq7/WihSnRViSUn84VUpngOtv2PpNx82xWZhePStJ2uatw4liElf61qO9nPqy2nnYHAFMcpdgFVseAblYTM3Gw99QH/hmmXWENGeQdihQFcldmpeI4zulfAxw6ydg9vJHc9HQFTt3UdM6B7wiPMiKQZ1pGc55/7Z6uOrzLahCwkcPJW/dfdNmkU0pF+bUkZEJ8hu5RMKEKg9Dv59Ue75hyur80EadsQ+2GBCW62yOGfh5n3bTjRzznNm9m8Dn+43xrlnKPncZeHDQWA0flaGaLkrrSg6Gcpyt9OHsGarQhBWIvmXBdNi8CF6GdBNlot6HFI5PISfVmbE6nBlJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0cG/XxwNz5xQssOe9Mru2Eu/iCohBsLiNJ9+rdrZYTo=;
 b=PpUtLVwthEi25soaJg7PKAdNIkKxExocmlxIoIti/kwBrR5hk6lHa2ROjP9i7PXnbyhzOcTSsWgxiKK3/FuhM6BYcASLWwVRaQjaR2w7Daj11eix+JNf6QOfg2MurWbuE8Acbhc1Z5/P4T31B/mOvN7zehD3AhHDThYXZ7eizcJUklrfgzjnc/AS2+vx0UCeSGDBvbl0c4UcQxMRDjtlUTjTFzjxvuDFgItAcPQc6VgKq9aK/aeVMFi0CLmHchz2ThVcz+8UZ01RcrtR/MVdDqX8buDPNZe6UdzLmm6jbxQckbGuHerdErXBeejUgiNgRJS5mWuP2u6wVoTmBb2B1A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CO6PR10MB5789.namprd10.prod.outlook.com (2603:10b6:303:140::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 10 Sep
 2025 20:22:36 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:36 +0000
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: [PATCH v2 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Date: Wed, 10 Sep 2025 21:21:58 +0100
Message-ID: <5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3PEPF00007A88.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:158:401::615) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CO6PR10MB5789:EE_
X-MS-Office365-Filtering-Correlation-Id: 80c6830d-5a12-45f1-1b9f-08ddf0a7c7be
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?RPpCrNp16cOF2S7rCLqWC0KWR1dIx03OZAFJJgwpcW4/8IpXlAktM33Rb1xq?=
 =?us-ascii?Q?ibwdcduAA/gVEebSoQbhtDUnJfHcF6pPp6O8vBJDMyyLseZ61Pxvjko6In8M?=
 =?us-ascii?Q?ptjfftnMSRuMhuRXbs3dd5wka+LLriga9dtgUqLwdfdlCS0RwZO9znvv2ZMM?=
 =?us-ascii?Q?ODvtmWCxvxMm78R3yXUGH36ulIKwGwvuyj5yadO+YNZi2KNOo4oV1Szk3hxR?=
 =?us-ascii?Q?AJ1zbJ7BGXFiOD6mJt7xXplkHEZPVfxSCl6jx3S1p9698Il2Ighn55iv/5YL?=
 =?us-ascii?Q?yE2hQcaYnYhAHv7S92ML7CKEK5UGzXSdL6SnX2ApUIhmdG9pBhrlm9ZzNeUo?=
 =?us-ascii?Q?rZ/LcXmzyUZpbYBEDLY6L5O6vIYtj2tVBZlRBuIyH/NN9PilA9iKWfhAO83+?=
 =?us-ascii?Q?E+PptIVkOr2TG2YaJgaJMppuzNVPV8+3pK4y9kd/gNx/al/jcu3zaqj5R7RD?=
 =?us-ascii?Q?Nvpf+sTie8kg8VKTC5HBPBS7aoFaOq9LKRmIrjWvmlEbcCVmP3Jzw1X+M0Fj?=
 =?us-ascii?Q?fr2Sm0PDfnsWRCOi8CxzixWcBPbbizZzC/3lqRFSzQzIiiSQNuFy9ENtEoWy?=
 =?us-ascii?Q?xMnSMNgU+brwgJbCpsohjyolOSbKcqovhMcdd6evY3LJlpVSQl/zJ/J2a6jh?=
 =?us-ascii?Q?zp5iqx5fDcouoWPe3pni++dGFw2PW34qWjDJrK25ufwf4ur3UW6xIfyOacjz?=
 =?us-ascii?Q?Fg19I5PMoaRv/8vEgVB22wUwTyMCMfMJ2YwzkMuAxiXoTd9MvIsrfq3gynVJ?=
 =?us-ascii?Q?Oo1WeUC5V5QVPv79dQikBm6p2wKggJ0soQ+QyYf3sDD043DOdPxhSxbdEAI/?=
 =?us-ascii?Q?z1kRTXCmnhELNrz04rzPPgZAJjsM6sq5aZ/j1A0wU9x4+aBdp6Rl96QBn4N6?=
 =?us-ascii?Q?o9CSepY2eIYL18k7JoxppkIq7Rha84YifmqhM1DuI9cXepfh93Q6IfdPiDKk?=
 =?us-ascii?Q?rdE42Y/pi3FTlIvxn2+ToXBwwNlBfPtafWYo9Sgx7r6y/ojCVLEhQ1r4EIEQ?=
 =?us-ascii?Q?T+yeCLFA3a49JAuE1K+56cSoO02jRYrdkc3ehRyTtTkfEqKCN0T4PXA1+rDr?=
 =?us-ascii?Q?qeJqKotH6eVFTg1bksjZFeDS3iGzKWIXbJCwXqip6W6MRgN6FomFBA11UlO3?=
 =?us-ascii?Q?/eeHPYOb1acNRlHArBcIs1h8l+DzCAJO4VO2WyfVIGwRg2z8YjeSqN2mfm/t?=
 =?us-ascii?Q?K3Jqc/zpmZPlCdR7UM4lzzyYh52+NaZAzea3oeQHlnChG29KhJn0rmkP5kHw?=
 =?us-ascii?Q?Hg1wc4sp9VgLx3gvcB2OV6ZSUgFFMtx+xj4JIv9VxsSXChI5SWt9GFeCklH3?=
 =?us-ascii?Q?LWqsKQ4fzdrSbA7lO635/GRJLcNnRxY1bAB9vmUWdS8VJCjVwQhcotvIWkwz?=
 =?us-ascii?Q?lZWsjpecqRgkrOZEe65QP+2VO6wVJzd0j16MPLDxLjjAVK6lCGkJ7sD2VUA1?=
 =?us-ascii?Q?Ss1YY94VI0Y=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?/cMYCpoC9cubvWYVx+Y4H8PT5er2B5xWMu6RQkf0Tt3lzygJYio3MaPsBpaN?=
 =?us-ascii?Q?tlh0C7+IqSZbTBaNE0qRrBpiE6lm2szbD0+7B8arUlNbggLu/PRxJ2TDLOxE?=
 =?us-ascii?Q?9WkYV19T0mK+yscuxdISVBBWJHdQk0aIw5ZrerV2a/Nq3NNFOYAXVtFMSa8q?=
 =?us-ascii?Q?RshYMDsStTGZHOluyt9HhYxWUkMsHM53kLxWYEWpZvBxnLCDOe9/v4Rtav3j?=
 =?us-ascii?Q?M4hzWfbaWA5BUPiK96cjgm6pDTBE+Gs2g9c2yBeWq4BaLVUnZBu3P+PdPPv3?=
 =?us-ascii?Q?v4zg9b0MXLPAJ/CQYJlqJfEnLh9brubbW0eRNwY/AMarxqaQkgFhniQFLyEL?=
 =?us-ascii?Q?CrGy8ajf80fqbozNQ2Cz0nWY79VN9pUde7PMLPEmmK0roaoPoZyAPS/MwBMk?=
 =?us-ascii?Q?eYfMaRMgwzEYEVyJn7HmRie5pHAwk1edsXJGzS9L+66FqQLuafrgtXEe5Fop?=
 =?us-ascii?Q?tEx5AIn38cE5DwDNVj1ZY0FeoAJA+7TPWeCUlvdPJqpVar9o1+B7kxsXj9vc?=
 =?us-ascii?Q?4zazp3EVWga9TnZxuqUPSlFrkc3IoxAQM9vZZ4cf7WUGYxVJrdg5hHZTtfYx?=
 =?us-ascii?Q?4sx3OeuMTZq2IGu5pGeT5Vo05me4rBivU2b0xx0EVQ1rV/Q58sDC+BDhFqak?=
 =?us-ascii?Q?6IDpmmwLmwkLcLT/luhuNW7yoN4PTk6YvWlEfiNI7ICF+S7dcqPRC9UYH/0d?=
 =?us-ascii?Q?FlHew4G9jwFU/dW7PEoOiotScZY11EPbHxa5Wko3PMX6KJ3/yHiFKsPirBUQ?=
 =?us-ascii?Q?yoZ352hdzNFYmlxvL5bp0iRq9Bl3SPVg2Hkgi0liCOCedD1aSU8kSKB+6fUI?=
 =?us-ascii?Q?IjKv1R4/wi7m6Oqk9mg1vGPHs9H61w5KcNi4dakgYj57l9JWAgLU2ZVEPKIK?=
 =?us-ascii?Q?8IZwTObwAi/SrC7bMVh2EMaPCnPRA8O/I9J1guxZmEg7RlMSXL33dalC7dfd?=
 =?us-ascii?Q?LDxraB00JQpgifuS0X+YYoaSKkSQgjsIdhXQilMHHyrTBvbwDvhkGSPy2eHD?=
 =?us-ascii?Q?mz2zznLSQSyErWVaTKLOWtbZZCS51E1FcV7w+T7DuLnXvG40D6CAqxdSgqHg?=
 =?us-ascii?Q?xvMgtHJfsFziDVKOPxkKOzKLownFem8gwywJgyiAenLtQRxrGX6cJsC5znUX?=
 =?us-ascii?Q?yK7K3gmifThlDGTUJWo5c6zIArCqQzV9hdJuO4wKwZ+q62O+Hh9H/UW9CgJX?=
 =?us-ascii?Q?EUldpRARVGcUSfLGSqvlClcOcbjUPTIrT1B4DuYDrGEW9mBVSjNTjlzArhmA?=
 =?us-ascii?Q?J7cqpAFMbz7sffMG0Puj2GzECPkwTCaz4vjZ7JR0B3mudas8VpanrsWDxEsN?=
 =?us-ascii?Q?RtJ2fKomqWBPuxmbP8ueU0vVceyxzwp+nxTYQDJitCV+4LiaCU1bPEWkAnSa?=
 =?us-ascii?Q?I92pJTDL5w4+EqOrpMdlG8CCyr95nP/OPphTZ9cV+yfbpkcyQQa537TAUFo2?=
 =?us-ascii?Q?kPupAq3imLrFez2ERCA8BIZTVerGcF0oMpKQVj7YbxMjN/aVVu7V0GowRt48?=
 =?us-ascii?Q?Og4J4PtnEkN0AO364qyfdIM5SHnaxqkEgKzFXL4V3U9O/oP9rdiNiI/UkBcf?=
 =?us-ascii?Q?/MopYQVAPxRq2eJd5GUzwg/MtuLb8fiUyWyvjWsEYzubSylyN80A5ITLw2yq?=
 =?us-ascii?Q?rA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: e5QL+UltWhgNK55CQ4Vdx9W9ZxpSLyDyVK6fY9DCuovKgOOSapO3+bPIJQMtY5rj1R7/IqW+zEN+afxRwk4R5SlbtRG82cg8NR0XGhbSEGeazuXVWr2sMWKXE1iBqhG3gnFbtdJLy3CcmyLGDVaBSGXJJ5mWRia9gGc39EYC1x8Oc7TcnJksIl9J/mI6hfv2sBqkuTXmNAEF9dyL9ZdVwidMIpZ1FgnjYx9fvJF7ntkSdDtrcxYWGBTtQW3oeN1EUeaj3iqj/BWesfhjsfmb0olv/DpJJtCopsNx4A9gTRCr/FFAtuD9hF9UevmqIu8qDX36dZGJGvyNUnIOKj+m40TjxZRbK3SoINEPc2lbMum2muifWhMpQPoNRdw+NWl3xvrLPO/Q0CxwmaaGvTIGwH54UGVXwswdwlj5t5Src2OpWOjUJ7YNyIDqCxnHKLuL/lPRZ7wgBK97aDjHVjaLe4ol3TPNNaJd1rpVPsNO0ZERyDB1ty0eqrsUX8/nAYTRPsgO3J30PN32KpU09Koo+Z37XEy/suO+CZGP5fava4+B/9Z5fsTs/hWFF4Ip9Di5KDcvnjjr+3A+k4fhrKFq+BMKxPyOlakkit8CCjQgKiQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 80c6830d-5a12-45f1-1b9f-08ddf0a7c7be
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:35.9639
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 6ZMr4UfGVvpBLrDD9mwJEuoXh3Epd/aFmFW5cGmHA4YOAMVpamZ0QFdZPchXOxxFnFNhkrWAQDT/324pWRoA8J/WuXc9oOLOyrLljrhpQSY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CO6PR10MB5789
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 suspectscore=0
 mlxscore=0 adultscore=0 bulkscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100189
X-Authority-Analysis: v=2.4 cv=esTfzppX c=1 sm=1 tr=0 ts=68c1de10 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=V8PVCHvh7cpLA54rH4kA:9 cc=ntf
 awl=host:13614
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2NSBTYWx0ZWRfX1r+yBw/PKBbE
 JuzNuRhiahSbCxapF6nIwYRcrkXrGSIdRS2sSsm6WRAa7/L2KrYgH6mfVgDlE0MWCi2YBtc6gMg
 BUfqzLtXYfi0tZqTlwhOeY/cHVuHMunezOPBMVkpB26PKVRz9C3KYLCUk+UHJr5hJ22pBVNBI9x
 X9FYTdDe08lEm/XaHJnxz8rlBQJt2uREWTkCqAfLhbuPkXbH+AsZfEL1swY0EJYOnp58oEb6GXl
 Xs6MeZ22kITolBXA8goNM85jkAjfuZw5/loSJcLjCiDH3Az4Yr0FtkIr5ccNATP9xCeHmft7ScQ
 0RDReZHdy7QRcMLgewFYAPuF3P8LsIOrym5T9RBPnJBDqulQ0FPk6PorV3CppYtScA/GD1X+Z6O
 7wPXqzd7WYgRrjs9NhoHVALUqqQhTg==
X-Proofpoint-GUID: 9zhFaUdicrhfnM6rPj9dikALdF6Jz3Wl
X-Proofpoint-ORIG-GUID: 9zhFaUdicrhfnM6rPj9dikALdF6Jz3Wl
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lj8xAgLI;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=luJiU53S;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

It's useful to be able to determine the size of a VMA descriptor range used
on f_op->mmap_prepare, expressed both in bytes and pages, so add helpers
for both and update code that could make use of it to do so.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 fs/ntfs3/file.c    |  2 +-
 include/linux/mm.h | 10 ++++++++++
 mm/secretmem.c     |  2 +-
 3 files changed, 12 insertions(+), 2 deletions(-)

diff --git a/fs/ntfs3/file.c b/fs/ntfs3/file.c
index c1ece707b195..86eb88f62714 100644
--- a/fs/ntfs3/file.c
+++ b/fs/ntfs3/file.c
@@ -304,7 +304,7 @@ static int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
 
 	if (rw) {
 		u64 to = min_t(loff_t, i_size_read(inode),
-			       from + desc->end - desc->start);
+			       from + vma_desc_size(desc));
 
 		if (is_sparsed(ni)) {
 			/* Allocate clusters for rw map. */
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 892fe5dbf9de..0b97589aec6d 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3572,6 +3572,16 @@ static inline unsigned long vma_pages(const struct vm_area_struct *vma)
 	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
 }
 
+static inline unsigned long vma_desc_size(struct vm_area_desc *desc)
+{
+	return desc->end - desc->start;
+}
+
+static inline unsigned long vma_desc_pages(struct vm_area_desc *desc)
+{
+	return vma_desc_size(desc) >> PAGE_SHIFT;
+}
+
 /* Look up the first VMA which exactly match the interval vm_start ... vm_end */
 static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
 				unsigned long vm_start, unsigned long vm_end)
diff --git a/mm/secretmem.c b/mm/secretmem.c
index 60137305bc20..62066ddb1e9c 100644
--- a/mm/secretmem.c
+++ b/mm/secretmem.c
@@ -120,7 +120,7 @@ static int secretmem_release(struct inode *inode, struct file *file)
 
 static int secretmem_mmap_prepare(struct vm_area_desc *desc)
 {
-	const unsigned long len = desc->end - desc->start;
+	const unsigned long len = vma_desc_size(desc);
 
 	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
 		return -EINVAL;
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes%40oracle.com.
