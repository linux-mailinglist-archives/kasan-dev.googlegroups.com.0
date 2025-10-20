Return-Path: <kasan-dev+bncBD6LBUWO5UMBBE6O3DDQMGQEWM2UCVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AA5EBF0FFE
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:06 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-87c08308d26sf154254796d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962325; cv=pass;
        d=google.com; s=arc-20240605;
        b=P8G7imn8KWWDpcWru1o1Ab3o0xb/dBmktVQ55sbbSjpdIt1DxYuDTf4dszTrFU9s4C
         tOWqBky0u2onQ6bkY+1rkrWJITUHWAdMsjxnmO889R9aK/GQ0aE+LQ832WxsTlYywo3g
         OFVD4xZUnf3K1Hh9wBiPvR7w3grKkgCHEFDMBGJYJyCWexXqhe2ZOscgdC4dL82Dxv4U
         /vke9n26t/CX+TchZPjxUlWW3rSD+7CjjQl7ZQbPz2roygDBREJgmmKSTrm+CuCj0p48
         dnRkfY4hAPPtV095WfupTF90PbTM1GM06UhUEfxE/aTxfIn+AQiSEjkY4wlRrGIfTd5T
         fmQQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jcnonWi9ZFj0fOkJnSMG388q7XQGs0k6RLKtKd4ext8=;
        fh=I2guxtiM+ZHmUYsX2w234xsSFu8sCsu8TRIHSmFZjN4=;
        b=kF6vYcxIaXcWWpODkoVZjCWpDezoQOzU4oPxqA5PxPGiI3+/dOyH1guga1yvDI4lCm
         3NdIhpsh/gZB5t1TlxZ+zf0A4XiQXmOQ56Osb9yPoDZHsXm1r/DPzoQqAWYT3fAfvjXp
         ios5VzTTPMUvYaBOZjxKXwUfpSjbWLzTZLukahcDrXYdhlcg1Io3imAIHThM4TFJsrQd
         9w2ASfR7yIMj1hHGoiHWYVeN0+jPsLUH542/475njHy5+dLMR26Y2EBVvi+x+OMpLXL6
         jjBv98hS0nh1pbGuCz7h31Sn8aA3mhor2lI5Lme4wl7KLLMt9IZVxMLi825ERw7GAvAj
         3+vA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="F3mLBv/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UXy1KdbP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962325; x=1761567125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jcnonWi9ZFj0fOkJnSMG388q7XQGs0k6RLKtKd4ext8=;
        b=MjBWOucKVT72d6EEDmfi1ODZ7RDRDDxpyofA7NCXmvcMYUKQMHWp+8hrqQuF6t4NHx
         h79z/iudwLgBF5G8F/Sn3o07fS52lWSkdmRqkxt6dbv43CL0X6z+8SC8VqIqUKPzfNfJ
         rkRYrNc9t7QVZPoKKQtBnUh6y/bIjV1xJTqHfbpM/mPZAOqeNaNUJeG5oiyaXMgBbp5f
         oeahNYXZWl4yVCU9kWlcIV5CfCyhBCJ5mzdP1w607oq2dw8+XOKSUnfAK1wvPvRf5tVN
         Q+vhD6mc4LDAQCv5WkakYn2ETkEwhxHQ+x7rwvpI49iHgzLuX7wZAopYd2iv896Au3HI
         NfqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962325; x=1761567125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jcnonWi9ZFj0fOkJnSMG388q7XQGs0k6RLKtKd4ext8=;
        b=QIH0KYSUVIkMWzNy2ywOC0sCW49DpqhYIFicibWKN2tufeB8TPWpajbD71P8yk6nOK
         9x2Ixh/2lyNlWuFMTsjW4d7g/5QvrGzJBGmIVGd07W8Mqkkm72GlZ1/8Fpb86tj5HfJ1
         6pLOSqWm0A7Xt3FqvHNYqHCIdUCeHhFrrliy2dbFWbeN9dN1FSXaxVAwI5myIFye/yrv
         iAaAlu521AvBu9viMbVr1zKZ57ewpS/edCI6C9W0remHSlouengndoAiQG2APVJ6lbfe
         HfXb/VTpDYBj9PoufRN6DObefAKaZ6jNce9Q4wwnpUyLsVqUpuEnf+x+g5RNWMvHOZaT
         WyAA==
X-Forwarded-Encrypted: i=3; AJvYcCUkNNbN2ByINOaGSN3hjPIXXOzb5R+cu+QtYBmlF+EMNs0JprIzqrAsOVg3mvVMWHYWlD1nFA==@lfdr.de
X-Gm-Message-State: AOJu0YxOr+s7QGmhVCs3pM4Ddp+NCGXitYB0OS/9IUMr4NAeuEsA104R
	aNnXcDW5MW/gvL+LAQDuG4AlD9+FbFczGHTf9z0ra7ajt81xB0LC/51b
X-Google-Smtp-Source: AGHT+IHT55WcTkoQC8b9iydnagcV4itQmnp6+iOm0fomLiG4qyf/wP27r7ueJ9S75NPVqEwIPp8fYg==
X-Received: by 2002:a05:6214:4015:b0:87c:2847:f7cd with SMTP id 6a1803df08f44-87c2847f8cemr109800846d6.65.1760962323913;
        Mon, 20 Oct 2025 05:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4YQbaMJ8rZL8/NW2OF6TyURfEfYh0uto8V3uPvo7RRoQ=="
Received: by 2002:a05:6214:e8f:b0:729:c1d:d07d with SMTP id
 6a1803df08f44-87c14fb0c03ls69036806d6.0.-pod-prod-01-us; Mon, 20 Oct 2025
 05:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW1AaQGS46cwyfVsgrfUfrshSecwSEw+8XXNtrz2IAVwP7yddzBKoH8qoUI01skFe8ZQ6JPv8g+nt8=@googlegroups.com
X-Received: by 2002:a05:6122:3d06:b0:552:47db:ba83 with SMTP id 71dfb90a1353d-5564ef639c3mr3311428e0c.10.1760962322921;
        Mon, 20 Oct 2025 05:12:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962322; cv=pass;
        d=google.com; s=arc-20240605;
        b=UIIknkldBw+4LIxQL3y+JDWdirahrED24z0edg3I+QBh+tl/FcEQaBkwjei60T1CnU
         fhCOh53U1/lxY4kXIuEcrltcHrqkzIg2KrZB6OE8tt1stLww7SWA7C2tn0iFrjRaUP5E
         QFZIY9zKlULp4SfzgOz7tvkQpeGYeQCd9/NhzOZjs4ggpeRJUEKdzHjHv8sx3/I3sEAo
         MvX2lTQx28gRaiprl7LQMlOyZUnpFyl3Izaqx7U1BuWPJu5lOv1Tq1dkiH9nFvQG+hWb
         VoZTTnwQGboF/H0/Pi6eAFrMZMLHjpxkf5i+2exFvCulLLXEZMH+pjtam0fnEPDazXz8
         zoIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=0xcIb388qPEM1/X0hYwvL0uL9TtDownOzBym+N+W8xQ=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=WqN01kT6YmdjyVxVt6QpZvoCi3GfuQbFHMaRbLOF7eEbOdYUokck34//QljToeiXmd
         EzBnrosPk6U2qquKPoSBiBtpcMfHP/T/pUZITWpwDNnepcq7QBhpMDviwmO6QyRppIIB
         CXkCFdfoWHg/IYWHvGsIbFc91CBTVeW/TYSN0YAzi17l/Sg/QE/O4T1iWTk1ptk5HIgu
         h783fy1yO/G8DS/U5IYERZwrrvEUafsqKZAGY+sJ0DlHFjbvODabpBqcPNHkZUrwToYr
         QyD3io378jwLEEqbNkkfYdCi6TZbGblLeWfXXZdYc2hNOP10xeG7Y8xSRc0u+Zmq7Jp+
         w34Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="F3mLBv/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=UXy1KdbP;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5567db01e8bsi125309e0c.5.2025.10.20.05.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8SGSh001297;
	Mon, 20 Oct 2025 12:11:49 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v30723gx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:49 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KBb0J6025395;
	Mon, 20 Oct 2025 12:11:48 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011040.outbound.protection.outlook.com [40.107.208.40])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bammup-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Ql1xta0Ao9UbDWsHLA0SMBzFjE3TnoQwOIvelMzH97Rhv7yV9abbssENQU2zXROVzMbSyNsUVjF6yOHMyv7q+giDG+DljzPrPHi1r48jtk8n7Ym/JXypwJMWZrlmVguX/+26+T5vfYc3A/u0Yw/pv8fpim4gZXi/Oje5NrLRfCTTHm0M2DO6iS/CwXUoYqfXIDSE0FnlTGqNgknDmhNpmByDCULpXTKImxqL83Wrnb/iPKMyJKlAof58fyf4UPsqdgh5lIPVeIgQvDPAi3mh1yk9ZKDNYlhl4qRpiRHeQZjDBslVyEX2aRar30uwbpFv31lGp2cS738tGotPtBbHcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0xcIb388qPEM1/X0hYwvL0uL9TtDownOzBym+N+W8xQ=;
 b=f/28vS19y7xdo3IB4Xs8fbsdF92gLVpMJTH1oZG+uwjmN2HlYnlro8eGsgGGxkh09cZ4MpF1wkUrCJf7Sl00cvdNwtydWzJ7vqPc9QdLffm3lmWlCNfUVSAVwcd4/r2oShkEhedRtPGN23fZelEkUbFYPh+pLNKFFEP5nAjsb0v+S53HmyCEvv4j9bqSp9T6cSniUTDIcLSMnE48nEl/5EH4Pqv8PUURDVCoXWTxUcX/wzzUo8ybCBjm8o/dkq76y4+L0FofwU/XwtP+0xRHGplCXzeRtSFpFeTBxM3VGTwNF8eQlOmn7fBMY5JfW9TZF3dzW8njf9Nh2MdGlGbpvQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:11:44 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:11:44 +0000
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
Subject: [PATCH v5 03/15] mm/vma: remove unused function, make internal functions static
Date: Mon, 20 Oct 2025 13:11:20 +0100
Message-ID: <f2ab9ea051225a02e6d1d45a7608f4e149220117.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0361.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18e::6) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: 67c242d1-44b5-4878-6220-08de0fd1d5f9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?E1UYPyz4QmXIMm8paJ6Em+f+9ZWmOO/14Ek9JNtCMsp2ypJEg0CJKhW1rrrf?=
 =?us-ascii?Q?6gM4I1P4nFiD/qQ6HJOEUfiYZGsRqA3lv3yNP3fOy3BK/2HN+OTituAiB+ua?=
 =?us-ascii?Q?dYkK8mwQt8JmFW/rfzBy0bM6ergcXeHIs8cCgylwscGvPb8XYazdCRfFsNRT?=
 =?us-ascii?Q?XVkyJd4hPc+FVjMskbMDbO+0NtsU9JfBba/hRLDURth8+dtCHxqh2Bn90e/n?=
 =?us-ascii?Q?0j/R/yXtyM+OyvqKDOPq/SO3PrCye+DcrzzRe9xqTu/tqi8f6J7nbET4DP5K?=
 =?us-ascii?Q?y9vGlDrL50lces8l65JwJlzF3HmaLDHHKA8y5jC9dgEzUpTA+NhqkhfUg6cI?=
 =?us-ascii?Q?GXn6QWRQ8c1yoHqQLozRLR4HV5iuzvOWZIBS1Tjx2pf5HJiVsx1Y+D8SSKSU?=
 =?us-ascii?Q?XSHEN9rIvuIXgRFqFrgIqMbiYGyaQNLLbUiyf14ysf9mhWr8tbbk1krKOt1s?=
 =?us-ascii?Q?mcCyIwpSNcnFTUChZIFqJa5pgA430weqkW5nXlqZONu+OENgdiN3O58OKq66?=
 =?us-ascii?Q?+Q0b+pgRF0iPnXoe5Y028eVStCFJhQVnbIQk2ogtjsWEg5hg3OqO6uk8FmTh?=
 =?us-ascii?Q?Ew8fq8istdZcC6Mhf9lb+nmMB0IfbSyI2gDX4+F1B9+zJhKJfQacsQ9biLa6?=
 =?us-ascii?Q?3sCRl0t3x7HXgOTlJO84oJiHXNPKihJZEC3jGiaApO3Qq+jeWP1kXNR+zjiA?=
 =?us-ascii?Q?ew6Vpsn3HqL+FLYyA/edvRRcQmRPG4VcCWy2vi1gbpfBrkpatgvrY/ICNHc/?=
 =?us-ascii?Q?DjhI9jQHzb1nypZVBOQFvFxaaOjlXEsTAjrya6Z/JL2Wg5ve6J3bhraiEA00?=
 =?us-ascii?Q?Z09M3MwfqZcSGDr1brhMhDX9yGHI/XJLZz2/AWPnmAzFQXuGsGoxTEWZgHHQ?=
 =?us-ascii?Q?DATo2ovyuxxOmFEMGpWFcsoIrlXHstdAEhJB5W6JSaiE9euOF0tEK+blcA5O?=
 =?us-ascii?Q?TYikLPHpK5SFmg8LkMmQYBbCAosBEyLvvWRVVK5Wc8jTv4ceARa6nUKdTU1t?=
 =?us-ascii?Q?RYWNf8VArFiweS3vpMwXrQ22aMxqhYjHqZhbUkZrULmfEEtNgKZATjQcv8gO?=
 =?us-ascii?Q?ZKtNEWJcIQXSK+0EO06MkuO7dCvN3wMJhSSPzcAULO7/BgEabuvJZWEEaXT9?=
 =?us-ascii?Q?TzAmszL20ZLzJYdO8BGhTf1rM8AKJo/klXkbTFXv0juItKoe/Y4DIWd/+yxH?=
 =?us-ascii?Q?62H+GCh1uT7TB0OmzVl5sbTgEMpXzNbh/8YyhF87LQ+3ezW1ckwimLJgZna0?=
 =?us-ascii?Q?XHLT4N2LtbOwNuqzx6Ip/qhJpOiwS0CqF78uXy2UI0XWWnlj5JY2U0D4V3uC?=
 =?us-ascii?Q?RPxCdScBYRydNJqX0HZxL4lv+7oS8qqszs/LipLmWJPG9q9R1b7ZVVoqtfb6?=
 =?us-ascii?Q?hxzHT3zDK+BxxWFsTBxVoX9v7vwADj/hxyTlv6+XucO0x2W/JaS+JkriuEjd?=
 =?us-ascii?Q?7y8kcRHx9hixUYIoh1NCf3bS/pDhw3gO?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?iXSRpPjk4QTvTaTW5lNJD33s1ye35O82QYkjGpkHNRsy4X+FaYMC5AF19WOI?=
 =?us-ascii?Q?Yq1W/wA3+Emg8JXgce7vzbR6wTwPRtIBXxPcbdKD1ZgfTWy+rPiZHLQVBz04?=
 =?us-ascii?Q?Ccqb9+Z7vhKqVulPl8DphbSJuzeKZD8oC5C7+cPu3L9D6px6NDlDVAcxVBBj?=
 =?us-ascii?Q?Eugtfs98a4Ny/u6UTqDq3cCREZwegZ8aTm7VNLndeg6Z0Yn0tkk868CTgjn3?=
 =?us-ascii?Q?xFJxXHYle/MpVMswsKpay3K/BQ0aIV1L9msKPafOWl5I/zUDiAi4ljmL4iuC?=
 =?us-ascii?Q?StZlEtLPaMH7vaYUqwvLfJg83rZpGtvqvLkZUb1MmhkvxS3voAbz8d44FCnp?=
 =?us-ascii?Q?hHVMn2+Y9TMFlwKY1niG0YlGT4uFPIBFIbTwGmO6MKpW1wei6Y7CHOuv+atv?=
 =?us-ascii?Q?DOF3nAXBBeQyUPd9K0A60PuxGAu3htNVdoKNkKl8zV1I4PwtZ8rDjJF1CQDm?=
 =?us-ascii?Q?4zRUnGsVnT7qE4qXLAo28AndkDIY394xUgD7bqKQJNk+6PeMJYFy55LzSgSB?=
 =?us-ascii?Q?K8nLiMjjTj+vbJnchQEI1FeoV8vYPwUNdxgEGAqkMjRyxd+1wnzSHmeE5yYO?=
 =?us-ascii?Q?R/XfAK7GwRzlnQogSugS7YaTAMdOyd0vsW25M5uZjaUrZ59DQVBjwQ84V71O?=
 =?us-ascii?Q?FqHkXCP36UzmcGZ/09BjNDeVFkwnT2ymo2Ar6E0yMzTXj8GvL4N65UEtU/Ud?=
 =?us-ascii?Q?m2TOoB7GcwPj14MHiDsCLEfKvolAqYEpEoteN2N9ldn23yclVSINvk7Yjlx/?=
 =?us-ascii?Q?G5XrFhxRehGCGW+Oi4UmI+bV1gLsZZlxwBFFp4piHBgJ6SA+dEg8KNIpltzC?=
 =?us-ascii?Q?fp2wI/14ko7qfJb+ntKik/LhXqHAJxO9YI5jVoValfHgzmhPYbX2zmWb3ghP?=
 =?us-ascii?Q?zKh4R55tP0imqxeb163JZoBjp1HABTkdYoqsfPYTBQAlbWhBIaxFDEAPBwzw?=
 =?us-ascii?Q?dl57LsRGOJt7/Y+pDrw86E2vpO7fdxVixY3Y3I+jT3MXmPQd6kU6FjYCQVOK?=
 =?us-ascii?Q?DeRRKPTdwqPJtk9PVhVF1OjQoTQmfol4Clfeh8qQb1fnv7HLvyUEr8+ScrFo?=
 =?us-ascii?Q?gAFT+PhDqdZrZuj3jLpXjkn7CdErcjvcuNpvVrAaCXalxwbLHUlGYzobeACB?=
 =?us-ascii?Q?DdYJFLGVDqwPLnVHP5JDtohp/MP1AUfPoqS0NJ/xQfIOXUwz9pp6SqA92cLq?=
 =?us-ascii?Q?oHH90f3+FK1/2KGH9lcmXP9dJDo1OX+GnxRiz0w2ypTarSVWmpGOLgbEJbUw?=
 =?us-ascii?Q?WAaLqrY4h9SVpFdZvG5SftNICyeJEvP7P4lNhaGy1Ql6gAHk9sHaImRrd1+K?=
 =?us-ascii?Q?LH3DiIeI4itVNMEDuZ39hX4VfoyDCoc27+wy59aV3Ov8cklBjGPLSKMnwLnw?=
 =?us-ascii?Q?dxMgz35GwU83kWPAAzuZ4YCRAZgqRpK2oaLfPvBRAmD20yl9idjgalGeb5Mu?=
 =?us-ascii?Q?8mRpzHpOpYNye9bTio+eu21kUqYXomRw7S9x3qr6F7YHzFr0HT7g9NDE6Mve?=
 =?us-ascii?Q?F+SxHRz4g/mOxF0yP8JSvjGr9h84nDKgFuT9NEJCMFw1zSELemZd9yX4/qXa?=
 =?us-ascii?Q?mboJLKXTloJNnxiR/WhPP/FupC31iTeR2xPgNHMPrCY0X5xjxoB9WLyZcJcc?=
 =?us-ascii?Q?4g=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: gdASe1C3+AdAS+val2brnM0d66M1ggoJhYggYPjUmxDbUJ1eyFW9ylAucGoMKbTt+2zR5CORZS/1WE/EKN2BNck3YNuIpMVobsjMh3ha1Te25TURJ0cHRyeV0yUZaGm3c5zo8nF/d4TzVcieEPMLN/Y/BpaRPabYu0S4XuRWxYxyT8Xwl3DCFLBKQehYoLKpa95Kq0zsxnBxKiRlfUBFQt9DAsXimEcINUtbZpMDYT9LFiFbzXLvq0g319uAnJqTQyd2hBuxe20Y8zTWsCVdQrmSz8BUpHOoQ/BeIWV6ZBtAsicQVqqbhAT64b+W40QK7WE7uajmrXKcEmvY9MZL1Ri1R5N0UHDVhJEKSG8u/OrjggiiwmGDC82j6hsHs7JyN8QQ3Z9aVoWqBK+MrsOvMzL4ODStdOntBndNixgMAUXo1tUYGT5k5exdmKTJMnoy/a5k8YDXJKaVhdY5O+JhHlnatdhxcFwob61CxWtYqln0HJDEkksqRNm/VFNPh1ciLtuKINOaKYuDOl9zcsU1YfJWwQwnQD/Zg3mt14tNoJdyeQbJufeImRoNWy384w4CUz5D22js00qGV0JaRwkYx37Hid3rqeSMUxePPDWjPHk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 67c242d1-44b5-4878-6220-08de0fd1d5f9
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:11:44.7365
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mCwNwjfHFE38ETXE0IlHi1QAWiYkBSJ900mjabSLeb5dQjNnJtcD0hWar+Qx4+68HOeMBgRe0RTU+7CvXY3LXCSZsTOeuY/ViR2r7hSdPkI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510200099
X-Proofpoint-ORIG-GUID: cFKaYyJtOSZOrO1Jjnii35utASlZ11tn
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMyBTYWx0ZWRfX7zvjSNqTVcDw
 S+3Z8RZnj/dZ9L+2CyP3Q1UERWCbdrud22iZ6oyWnZ+gxWzvLo5z0/LRGYVdAOm1U7loYBu/ulf
 F1/JMCdnQ/3me5SGI1BB9ucq52DTsW20hXH1A4sPZtciEa+7ivM6K82py8XkKteARRX01aivHGG
 V4CrLoEevpSaTVZpmm3V40FnpdZinvFueYQVqHgrHsOingqK1E0FwfLApLUsAkKKzOOpqvBklis
 0eL3vn3J8lfgCVN4DtCLOw0Ko6esA32y7ZrxK7jNB1IbycnS5fFKDAuTMUpKC0V1O8thiXW6zFC
 ed+NLlZwNa76zk8OFiahyhTgrsMvj3JCrWFsYF02YOtjSMT4TRLmvxUbcDztFSJ5mL0nEI0Ca5Y
 nLfX82pdzvb1Z26JrKS9CkxVjLaY8w==
X-Proofpoint-GUID: cFKaYyJtOSZOrO1Jjnii35utASlZ11tn
X-Authority-Analysis: v=2.4 cv=csaWUl4i c=1 sm=1 tr=0 ts=68f62705 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8
 a=3Kn3S-nDrHPywecsLO4A:9 a=UhEZJTgQB8St2RibIkdl:22 a=Z5ABNNGmrOfJ6cZ5bIyy:22
 a=QOGEsqRv6VhmHaoFNykA:22
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="F3mLBv/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=UXy1KdbP;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

unlink_file_vma() is not used by anything, so remove it.

vma_link() and vma_link_file() are only used within mm/vma.c, so make them
static.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/vma.c | 21 ++-------------------
 mm/vma.h |  6 ------
 2 files changed, 2 insertions(+), 25 deletions(-)

diff --git a/mm/vma.c b/mm/vma.c
index 9127eaeea93f..004958a085cb 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -1754,24 +1754,7 @@ void unlink_file_vma_batch_final(struct unlink_vma_file_batch *vb)
 		unlink_file_vma_batch_process(vb);
 }
 
-/*
- * Unlink a file-based vm structure from its interval tree, to hide
- * vma from rmap and vmtruncate before freeing its page tables.
- */
-void unlink_file_vma(struct vm_area_struct *vma)
-{
-	struct file *file = vma->vm_file;
-
-	if (file) {
-		struct address_space *mapping = file->f_mapping;
-
-		i_mmap_lock_write(mapping);
-		__remove_shared_vm_struct(vma, mapping);
-		i_mmap_unlock_write(mapping);
-	}
-}
-
-void vma_link_file(struct vm_area_struct *vma)
+static void vma_link_file(struct vm_area_struct *vma)
 {
 	struct file *file = vma->vm_file;
 	struct address_space *mapping;
@@ -1784,7 +1767,7 @@ void vma_link_file(struct vm_area_struct *vma)
 	}
 }
 
-int vma_link(struct mm_struct *mm, struct vm_area_struct *vma)
+static int vma_link(struct mm_struct *mm, struct vm_area_struct *vma)
 {
 	VMA_ITERATOR(vmi, mm, 0);
 
diff --git a/mm/vma.h b/mm/vma.h
index 9183fe549009..e912d42c428a 100644
--- a/mm/vma.h
+++ b/mm/vma.h
@@ -312,12 +312,6 @@ void unlink_file_vma_batch_final(struct unlink_vma_file_batch *vb);
 void unlink_file_vma_batch_add(struct unlink_vma_file_batch *vb,
 			       struct vm_area_struct *vma);
 
-void unlink_file_vma(struct vm_area_struct *vma);
-
-void vma_link_file(struct vm_area_struct *vma);
-
-int vma_link(struct mm_struct *mm, struct vm_area_struct *vma);
-
 struct vm_area_struct *copy_vma(struct vm_area_struct **vmap,
 	unsigned long addr, unsigned long len, pgoff_t pgoff,
 	bool *need_rmap_locks);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f2ab9ea051225a02e6d1d45a7608f4e149220117.1760959442.git.lorenzo.stoakes%40oracle.com.
