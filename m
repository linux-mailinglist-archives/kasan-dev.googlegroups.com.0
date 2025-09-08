Return-Path: <kasan-dev+bncBD6LBUWO5UMBBBHU7LCQMGQEN3NS7IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FE18B48B44
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 13:12:10 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b4e796ad413sf6767771a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 04:12:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757329925; cv=pass;
        d=google.com; s=arc-20240605;
        b=DevIQRtB4w7SbYvKRhQVhSXXXps3FMu5lRWcvkSengqrqzMHbhkDaAD/O2SgMsxwjW
         0PSZdZAY3mIaNTFi+eN6hKWvfCk5z0nYPZhdOocY5A3z6V8OHob5y3ecytPtbiefeSjp
         eXmIzZw8GvQS7LZujOrRrf5KTXoh190hQ/aLEYKhRToIRpdHvpWWGrrpxZn5IoBIfdfJ
         ZhKf/aq+d9SVRKqo6V6rfcEWsBq3rBsrY9/7y/CX+UaCR5+owihpI1UJUHCX31qUMd+M
         5sZ1zYhA0JLTd8vA77TdtaoJExWFk6Dyl0ElraaVRKfnLcej1YMmZGezgDOexuV6qm3T
         ibvg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0kVDQ7apOuwSZpRByWl1I5Vd5VjEwxbD5CvJ4QUWU4w=;
        fh=W88xnL1kewlQ3e+/0g90/Gcws2HO+XgqORjAW6xu6UU=;
        b=DO2xHtjrMSSh9T2K3+kbfEO+9O8UAgu7v4fypeUlw3ZJVs/FzblSWLl1bZBPOXDra2
         H3nImkj5SX6dBSA+QcZ41RsPa+JR35p+aTLzhEk6uq9z53bHyHVgDYuKFRxlrbdH5+1J
         MW/BBoYX/qP89IL5zYI9RUahSWkS4nDJUzlL4hAydeeDUyEBEmWFV9+5Ts74CgNQ2lC6
         WqGZ1cr1SDMpTF6pWM0gyaH+a5uoUfkzawr9jsMj4lV8H7BX66mrwSjkOPlJvhIJC+dB
         9n4Ys39j92GXKb1bvFBts2TC4bNOfKwWz1cTS5bfszOUDe9CbsvNrYePoh5uecPPXMA1
         SNfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=MGu1i1x0;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=PzGYFjAG;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757329925; x=1757934725; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0kVDQ7apOuwSZpRByWl1I5Vd5VjEwxbD5CvJ4QUWU4w=;
        b=lvjPbK9kZrHb828lQpVtg4YS7gUmKe/nKgrSXTBBGDENYxZ8+yVW2V359Xxl+TeVwI
         KqWhM1OgqRcQQ0zQf3y5oyPDZFmhuIjn7nzx741MxNpwS54dwsIik8m/s0ru7mC76qrS
         3ay3SopAOsK21QA67mSBEMGm3nWX4h94TBVOp4lvtVzlyU69I5kHCglGnVPEmuakpyMu
         hG2hvMdJZPDXbY/Ksk/7ASQnIbo/g0FPchnykQqK/lEyMMM/4xxa3erz013evasyN5f+
         IOar2O31qznY9D6Vaf+KKFNltCDi4uLKoCdup60ZmLNTl9VeEPDHf2F3b3IrY3+Kiqk6
         F5ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757329925; x=1757934725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0kVDQ7apOuwSZpRByWl1I5Vd5VjEwxbD5CvJ4QUWU4w=;
        b=XR60rf+bu/Ivzt0klzzddV8NmzYK2U2GltjadAfM+SDb5fMZaUMxnsRX7SIqjAmFBw
         QfdGb+nuOE4c2OPO6uLtB6m97x5LvJ0GSMcenZW/f9oVHDZzrpcXWYPpA3TIyrMXMG1f
         FWoLDC0EfuXzcgZ9/e+fXjf5wLjvqk1B/JB8seYOq6fbiBwL8trFuzFCxXxQ+1UZYGuJ
         c51u9fBWe1/89YdD5YJvBKRzwl/kMzEUvqqzq+QIgEB/Km8u6ZdhnmswHStAJkm8Sldw
         MRSy4DdM8JXN9y2O4j5eBOJJatjYF+ir/MRgpwhIIUyS50MBaZVhlHCHQkwL0+dPfcQU
         UfWQ==
X-Forwarded-Encrypted: i=3; AJvYcCXO3spEMbBsW1iNLaEyFVM7e0MtNLhSNTKmt6vaVQl6cLXwfTXOi5BP/X4mFAcb3kGUJDy4ow==@lfdr.de
X-Gm-Message-State: AOJu0Yx1hgxxz6qeQfAjCimptGbqUpod8n7ycdoJg3agcoIlaBFKakeG
	zj8R/2lMbCOeGFClaC4OBktLrfoPdtUDrWRIjs2KavbB0CrXoEf0CNhZ
X-Google-Smtp-Source: AGHT+IGXIFx+djJbnz8KHgR/JzimfTaJdtCFSwsgyALKOT0gunm/hBnh1/Xm3cfPHd5TGGLQhD3qww==
X-Received: by 2002:a17:903:22c7:b0:24b:e55:334 with SMTP id d9443c01a7336-2516d8187fcmr78745215ad.8.1757329924600;
        Mon, 08 Sep 2025 04:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4bOEvV/pwvzrWoxkDWm+LIhZQsgeIvXPojdhNnznlY3Q==
Received: by 2002:a17:902:d2c4:b0:248:894e:7740 with SMTP id
 d9443c01a7336-24d4cb36eafls31426305ad.0.-pod-prod-06-us; Mon, 08 Sep 2025
 04:12:03 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWkZXZfXerPHJf88m6IvSyurHD9iiCRNZBjbk/rIvUqiEl5eTdggHORFe8PsSiey06c0wkr7XzCIig=@googlegroups.com
X-Received: by 2002:a17:903:2303:b0:24a:a02e:43ef with SMTP id d9443c01a7336-25172862119mr105170245ad.41.1757329922859;
        Mon, 08 Sep 2025 04:12:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757329922; cv=pass;
        d=google.com; s=arc-20240605;
        b=I9kvdnbpTgECmnLeIteG3OWvLds5ZBjpzvt+ObsVd9LK1p4S45W4Qg402LoGVw0RDK
         EN0DL2nL5S4LLt+YCi/OWSyDcvgfLoaVl/jFHWQX7B6EVWBA5oDlbh8OMVASgfk4yBtx
         9EC0rshicGLvtosTgUis8XRvHSSfOsQUfZE+r10J6FMuvXdjMHIg6UN+sxsvtvGL26zO
         HVJjeviT2LORT0x3tuVNlvT9uXup5B4DWaaHfrgvC92SR9Tcvp1MMjRvxNgAMI+OO0MS
         8tdkERjf1lAx9gWkJRpp3W8OA0o4r528qWuNt81P+f5kKLtPVIGPTjLgitLAEOGKfLPg
         kLjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=k7NHmK2TGD4XyjTbCZb+2z7qPiXM07rCkbATVrKOnt0=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=L7FVFNzL+hr5JbxclNgI8NhU04A0/CloKf/KaBXPY2ZBZ6k0RewrfCVBhVml6+fLaK
         3Aaaq1CX1vlaxwl51IgcMrS8Lg6VGg6ZLyy84HBpthD/2FqwLryiPeePgzrFwk4wYY3H
         y+q9m2bvmf1NuZTIjWqQArutxt+lD5CjzRUQjrFoKYOuXzKHIm+daog0dvM+HPDqJY1c
         gSuiRfo4UtkeNSrkwgFpMh1trEnQ7Q8r4cQ73kpC5R0jJ4UfHc+iDhdaSTVAMjebGPaT
         MLm/Ok1JIQZd83UJ83MvjbtUjag1rqgfKyJYNVoZhvoqh+qDHQGx6SKJNeUq3UI/JWOj
         WG3g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=MGu1i1x0;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=PzGYFjAG;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24c822e3707si6570125ad.8.2025.09.08.04.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Sep 2025 04:12:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 588B4vAu011881;
	Mon, 8 Sep 2025 11:11:50 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 491wxvg082-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:50 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 588B6gso002971;
	Mon, 8 Sep 2025 11:11:49 GMT
Received: from nam04-mw2-obe.outbound.protection.outlook.com (mail-mw2nam04on2085.outbound.protection.outlook.com [40.107.101.85])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdej0mg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 08 Sep 2025 11:11:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=WYKG2DWBifR/ciQVhxKj7JukVxxGI4D1BW/VzYj6kJaNlF/nkygPm0HO1v7+n7+Ce9RH3/GyxnDHgyg/cAoq6LPMeoIp0pxyJ6FFPIc9Do/kdSuGpC0WXhy6BKt/dTZ9xEtLrNUCszBc5OuXMA4pcM0vCnCR0Kga4k1oSi3aE+VERjVJjCSRf9KG3vDIUbCp4OV95p9oqZOjnDHdCXD5F8TX+9bmpcsn0gCssqCNvGUOts5txIP2BSTgiBzUe0aDklY77wqV9WvEkvrIzOO9GDMZob9UbnPcAqyIQlvSFunDLJs4CfbE/8cEewc98P8eV2zj9jYSuOLbr1Gt8g1Jcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=k7NHmK2TGD4XyjTbCZb+2z7qPiXM07rCkbATVrKOnt0=;
 b=vLWYVv3VOhS4HePtKiJ7ADKQEwTu7mtlh3R3avBA5sdyj20cb5WXpB+PyhBU2/zkOES6Xci9wq3IanYuTMfrlt4IdiUEeM9YeB/UBYgpLhPyGYhQc1blnjQtc1wXWsfA4JlYOf7U39g+UVReP6toXadGf1vm0Nl/nsEWQiZr5bG6HBL8RaX6Lt2PcW3XasMUngn2zRsHwIRBNwaVH9BEYABzwibH6t8jVHGxzgajUuyALJrRwHue2yoMOOMcTXw7jSm9QC0LV6MyJxNOg8jxQqPWmF20Y+LWqOFjynvC9IChss3XG4fDutCXW7uK7VzKXK5HyVYgdjll95ZpcbksOQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6588.namprd10.prod.outlook.com (2603:10b6:930:57::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 11:11:44 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.018; Mon, 8 Sep 2025
 11:11:44 +0000
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
Subject: [PATCH 11/16] mm: update mem char driver to use mmap_prepare, mmap_complete
Date: Mon,  8 Sep 2025 12:10:42 +0100
Message-ID: <b9956df25d4fe8ae34df4e3388e5adcc9cd151e6.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GV3P280CA0001.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:b::31) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6588:EE_
X-MS-Office365-Filtering-Correlation-Id: fcfe828b-becb-4615-f25e-08ddeec87ed1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?iMQ9qGjGMi98GjmHDoGtFTNN4m3aTohUbyYNITytG21SJ+G0gRbj0uCmci6d?=
 =?us-ascii?Q?eVZCMmHaijml9C47VoVQW28K7fYD5ag7B7DbxVKmBCcjIWgmqnKQ/XFMLSIY?=
 =?us-ascii?Q?XPRixbOUUjSqQjkfG9Y/8LHnyqwOBGKeBpJhAuFe2LZeH7u5L/GXJyV5hUT7?=
 =?us-ascii?Q?v8xwM7ZNMTNOqyDCKw7xMN5//UlKvLVuRgKpgWTDSOJLMmiUQiyiFJc5WD+M?=
 =?us-ascii?Q?wSalo/KZxDpj/7cOWmU5SlhEhOYujpuMrv/r4+noUKFsvaoipr6lqfqaWL8S?=
 =?us-ascii?Q?+G/WNUfOoGxWwC0i/glmhYbkR7X1OobvoIlI7mJxqm9vHbMG2x4nDyAXC5at?=
 =?us-ascii?Q?lHPQ9MHM8P6HsnSd5SQN/PTBqFsiWDmuEQ8wZuVJoGclkA2IkQQKrQXAWhoH?=
 =?us-ascii?Q?xfYSR4/iGv6BNzBV+PqR/oEEdbSZX9/H+1SGEyKrOe3/esViFFmPzKYVqysN?=
 =?us-ascii?Q?vkLuykZmA6bftwgwiN++eMQOCRL3L51xordzQtjoRPr6fmnxYhsZtCOzyomj?=
 =?us-ascii?Q?/dkkjxQ9m70EW+7fiVtNxWVgQ3WojJL6NJZHS3eC3za7oWMg//REuGxuVUrZ?=
 =?us-ascii?Q?TnIenjY7QZg6D3uLqczZiot/U3daA663xSUi3pvl5ctDbDE5b5u2y4D5VfcU?=
 =?us-ascii?Q?JD5SN3JwSR7Gic9YzoBZQvRit5+46Prm2s042wDp2tjsyWdCpTSAzb+Wk+B1?=
 =?us-ascii?Q?kLtiLfUT0QvFnjcVVob8W6t+o6r/dMxoLXSGx1b5ij7t/kc0HrE0mcAttA1V?=
 =?us-ascii?Q?NKh35ugpb6fDMS4OjSzQggafOGALlEcJjtQueOMZT6Nog6qjEq/35HiDp1Mb?=
 =?us-ascii?Q?wrx1ESQQ1E0IgRZkN1JdKSfrXSdIfkxabsibGAn1p3uLGhvpbWh4aJcDXKTy?=
 =?us-ascii?Q?UVBtI4D4FLSCIWUVfE23LEg/WDP+wSI3T05gRwDLghjbiEr02dLJ1hBboyCz?=
 =?us-ascii?Q?gqUjk8TnMm96Upiiqz0TQlb1eQrcpRS9agK8xV64ZTNUN6yQM4C+0Z0P9v1C?=
 =?us-ascii?Q?jnl6LnpjmJcoH+rA9oeOlNzkLpSL6vqi9PHHVUpiPUXi2zxYSd1BNeHS2J+8?=
 =?us-ascii?Q?/MB4JdVfQzjgnBkejyBsdw/Zqx9PT9NTUIlf2wq3zym6elc0nxuatiJMqMZC?=
 =?us-ascii?Q?xRFTuDMGbZs0luYWEWlPFuDs+RbSiQ14jRkBYt7e88oeZqSstAVfydHSGUHC?=
 =?us-ascii?Q?mvM/l69VzewNvMnqom5YVAkcZszH986NBWbKC0xqeW6vT3y+EtVSxyaHE5LF?=
 =?us-ascii?Q?BL5c+YjKry3dawfBb+/vP/9K7IVZKO0Au0lkS4vs+npE7pr/AZqRAUrmxeaS?=
 =?us-ascii?Q?kfusjR465QkZesl7sThkyF076bF6pgbC+TawOopGDkE34XfckdOKLDHzQEf9?=
 =?us-ascii?Q?WBKWcRDj0L0RqirXZBUZxpmSJVeLqp/CNk7W1ayxxbnJ6H8WEMk1KkXfoy/o?=
 =?us-ascii?Q?8dRZanw/o6c=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1bu40oP5Kqyx2XA0E0PCK8Qp0eo+KAUFmvAZCP/8OqsXicRaJsLrENwgcJsG?=
 =?us-ascii?Q?VllBu9lZsy5wsOS2nr3RRCZE3ar/q9pHS1Pbu7IXx7aiBOeQmkBYwIZegCii?=
 =?us-ascii?Q?TM4o4gireISGXIRrE9WRFSXzg6aJaRIehA+FyUcjMdkxZdzM1rv3QEebpPj1?=
 =?us-ascii?Q?YhbDE1pLAEU6x+6bMZKjJ4A7bnytPiW3auVkjzyhbf+SekfAEhioyrwoRfsd?=
 =?us-ascii?Q?Bs/EoxoRPkF11VBFdq+HbYZqQgFW2j6xvdlcBxDcfjlR2UOgu0BRJVGU1Jjn?=
 =?us-ascii?Q?JhBdH/9xo3+y3W/DpE2Nl6HhO2P2xsJGG1f0qEUxc2Wfu4Zz8vGZpWlPrd+0?=
 =?us-ascii?Q?9RhrvC1mmyQ6Ho0uCb9Jd4D8VnmQb1e8oGU4/4OZcAWnkbaJNFrPR/2pr7E7?=
 =?us-ascii?Q?jAB9vzILrdWOCmbwqxxY26lVp+dMODnZcduUFlmhSUDnTenuSd+bhY9EX4OH?=
 =?us-ascii?Q?2jXQzbfFQRqPs3B6+R6gl2XYS/LV2ylDF0bW0MY8RHxrMc3ZWOeGDihQW2wz?=
 =?us-ascii?Q?/7iiFJ/ReXinHtzlMuiWM5O2NSCIVjx2pPRkbAXnhTObYO9G/qa+bE2ApWpD?=
 =?us-ascii?Q?0iK64XL66OGxI/uRXZe52tXYk8pXrqifcW5qA38zqHLxcGSSJyaKDpY8jMqi?=
 =?us-ascii?Q?+Ium9vaZJRd31k9g7w7k+ME6XUrs7xcf+WRQq1TsYlVuSc8HnCh3sfZPXAB7?=
 =?us-ascii?Q?8YZfPgVThXTRp7PwHcaFh1bLhtpv+lFSQ2jEd1N1RG809WkG1alR2IyswyON?=
 =?us-ascii?Q?kGzwVqbN8oZRsdYbGRX30qXdGitu/kKRYYam/bfJ8ze05S3NWCB69nnPa46y?=
 =?us-ascii?Q?+5nOGhOMBozZY250QUoqpyq15nS8q4tvOnCg0u0GEYpbFzFeRsNvgpEPvLGD?=
 =?us-ascii?Q?OrF7W1BXkwMYS8vgBN2DZ/WPhI0UHCkaU1Q+8wuWaso7ECoY8eYmEF/UvDVE?=
 =?us-ascii?Q?qvOnqzfyTo/trvGz5dnOPmDKcoapaeX7HFAg665whs7QY6fMMlSy3kYkwG46?=
 =?us-ascii?Q?Mz0GQuQlN9gUanzkPnUd35mVbx2oSY3G1DyrbeXnSkLfjeu2UWt999Gjy5ys?=
 =?us-ascii?Q?kmyzY/s7FuFiFpxXMzV2Uok4i7nQ2IdGjUarqi8QmfNX1yPAmdbERLs7FqOT?=
 =?us-ascii?Q?A+HVCq4TROJPI3TosdEsL7d209q0uG09L+Rp3g/QL6C9glVl11l8h3Zb9Bli?=
 =?us-ascii?Q?SOtqb3FldRNgu2VoEPAi+jc+ioNUWuhpMegEE7dnx1+pEh57sC7h0WyNd3l8?=
 =?us-ascii?Q?cWuNRGJXntoUlup9S4AHiyi74dMvS8+LLxqLao3V/7pcWLJJEUnuzvzvdPb3?=
 =?us-ascii?Q?M1GN3WDhu53wwctcSpW2znfJLU7zpJOdNCSt7JUAIbXmxs4rA8LE88GnC14c?=
 =?us-ascii?Q?f6vwqANOp0U4dsbj9apwrlDB327FL6gJWxzgNs7Wnp5Bmuih+O6eSAua0cfy?=
 =?us-ascii?Q?+hx02ck5WPZ6tizbc57ogYmsqtF+5lo8SW8aqctXmy0ckA4TQBpPYeAopsex?=
 =?us-ascii?Q?nYUKDCH2s/dNUYQ4j0HUv/ckkN2H6t6zjZz2q2+lo0gwXluGpd/wYaHdnZRn?=
 =?us-ascii?Q?Gyo3gCQOsdVi3ejytilDY8AXMTpC4OPANT7dts7TgaZ2hzeFnHe/EIcuBoyT?=
 =?us-ascii?Q?KA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 39ds6jMpw8XEX80pcReOAYTvIWijnHzaYeeU3/xnkn1Cw8yCOeC9rGP9qllZ8dq5JS54IA7yhFOXvdYjpkWZ+P+kXwg26DwMtUZzccoU8VlW1xuveP0DWGURN7duI8K6sA5X3gWuJTL5cyuXEtszMFWh9hpBODeujDCayzoV3dBH6XaTcpUtLD5oEzBfk36CIMoah6pHxSJX/kBBILZhdCL1nXxptfSksiV3Cwp8eDlNLIHvNO7t2OqpsqNmSRNrD8l3A51pEs+45Yi9tJaa8imqLKlK45XSgsreT/jVJjQCHF4AiA70/wOegMLQngsldUnjuRoUWR89shrYvuYuZFhBPlHRUOZ6eASJXqaGOJK3vQSlPl906RER3IeAbYNSpWtv0mH+8KWlp96iXvolIzNPFJ0c3CcEfc0CF9qaJVdSBoPWaSzJ0cVEQ2vM6zeLtaianXIbsvPDRXc8f6nsPZSxXXSUSLm7sEHLkibTRZiodX51nBY3gXOye0ZZiHTjrDRhOeoyny/uoWoSFcTOqLSSv4vdPBiOtgOUjJR1iy5EIjHHdiIE/oozeIUpG6Xi4GrrAWEGsNzxAam8NJg536wRtv1PNMunYQMKhVieeDg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fcfe828b-becb-4615-f25e-08ddeec87ed1
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 11:11:44.6848
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kctUhkmvvPmaaQfkU0eAizRW7EnFGEYaPPUSA2Kn9CnC1Zo/4HQMTy74mrW+sbpQ+rcrr5Hbrg/qMAoIUB6JtVsxFx9Y8IhY2Rc2JwjN6fQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6588
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_04,2025-09-08_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509080113
X-Proofpoint-ORIG-GUID: WfnurNvUuBii38BfUaBm5S7040SPU2x3
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDExMiBTYWx0ZWRfX60SlbKjBoEyV
 agpN2Dr8no/FBukqvsuj/zIaGThb7GCOIcucTt9So4KmFaJ/cpnQ9pgGXSnohDBvLN9YuFYFoaj
 XinSOSZ41FH5fZetAreFypYVeiF2gLAUKzPaRHqjGxYFfKpPbrxs9nLRWv9ZMqneOKISKIJPPIb
 F5CJnznG8D/lIXRP524iYPXGZpv7PaON+Y65KjkYHAlzriJiZsV9k91nBRF0dLNLLCj3jRGBvNl
 SkGwb2XJNrVPo6M8vEcupSDTKSvtMcRWUls4qtRZDvwiQD5oV6XSv6gSFqBm6eXPQFampvd+kml
 sY1y/LwdH/ROk5ijqJv/XfQzgPUcidl2ljoUEWUrzfPiNx6cJ06VTMEl3QfKMf7m9HiP+pcShlV
 M5LmyD2thP39+rWUwd4/QgPk7+YJCg==
X-Authority-Analysis: v=2.4 cv=MIFgmNZl c=1 sm=1 tr=0 ts=68beb9f6 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=7X8Cq549UNVAXTOeWE0A:9 cc=ntf
 awl=host:12069
X-Proofpoint-GUID: WfnurNvUuBii38BfUaBm5S7040SPU2x3
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=MGu1i1x0;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=PzGYFjAG;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Update the mem char driver (backing /dev/mem and /dev/zero) to use
f_op->mmap_prepare, f_op->mmap_complete hooks rather than the deprecated
f_op->mmap hook.

The /dev/zero implementation has a very unique and rather concerning
characteristic in that it converts MAP_PRIVATE mmap() mappings anonymous
when they are, in fact, not.

The new f_op->mmap_prepare() can support this, but rather than introducing
a helper function to perform this hack (and risk introducing other users),
simply set desc->vm_op to NULL here and add a comment describing what's
going on.

We also introduce shmem_zero_setup_desc() to allow for the shared mapping
case via an f_op->mmap_prepare() hook, and generalise the code between this
and shmem_zero_setup().

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 drivers/char/mem.c       | 80 +++++++++++++++++++++++-----------------
 include/linux/shmem_fs.h |  3 +-
 mm/shmem.c               | 40 ++++++++++++++++----
 3 files changed, 81 insertions(+), 42 deletions(-)

diff --git a/drivers/char/mem.c b/drivers/char/mem.c
index 34b815901b20..b57ed104d302 100644
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
@@ -322,46 +322,54 @@ static const struct vm_operations_struct mmap_mem_ops = {
 #endif
 };
 
-static int mmap_mem(struct file *file, struct vm_area_struct *vma)
+static int mmap_mem_complete(struct file *file, struct vm_area_struct *vma,
+			     const void *context)
 {
 	size_t size = vma->vm_end - vma->vm_start;
-	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
+
+	if (remap_pfn_range_complete(vma,
+			    vma->vm_start,
+			    vma->vm_pgoff,
+			    size,
+			    vma->vm_page_prot))
+		return -EAGAIN;
+
+	return 0;
+}
+
+static int mmap_mem_prepare(struct vm_area_desc *desc)
+{
+	size_t size = vma_desc_size(desc);
+	phys_addr_t offset = (phys_addr_t)desc->pgoff << PAGE_SHIFT;
 
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
+	if (!phys_mem_access_prot_allowed(desc->file, desc->pgoff, size,
+						&desc->page_prot))
 		return -EINVAL;
 
-	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
-						 size,
-						 vma->vm_page_prot);
-
-	vma->vm_ops = &mmap_mem_ops;
+	desc->page_prot = phys_mem_access_prot(desc->file, desc->pgoff,
+					       size,
+					       desc->page_prot);
+	desc->vm_ops = &mmap_mem_ops;
 
 	/* Remap-pfn-range will mark the range VM_IO */
-	if (remap_pfn_range(vma,
-			    vma->vm_start,
-			    vma->vm_pgoff,
-			    size,
-			    vma->vm_page_prot)) {
-		return -EAGAIN;
-	}
+	remap_pfn_range_prepare(desc, desc->pgoff);
 	return 0;
 }
 
@@ -501,14 +509,18 @@ static ssize_t read_zero(struct file *file, char __user *buf,
 	return cleared;
 }
 
-static int mmap_zero(struct file *file, struct vm_area_struct *vma)
+static int mmap_prepare_zero(struct vm_area_desc *desc)
 {
 #ifndef CONFIG_MMU
 	return -ENOSYS;
 #endif
-	if (vma->vm_flags & VM_SHARED)
-		return shmem_zero_setup(vma);
-	vma_set_anonymous(vma);
+	if (desc->vm_flags & VM_SHARED)
+		return shmem_zero_setup_desc(desc);
+	/*
+	 * This is a highly unique situation where we mark a MAP_PRIVATE mapping
+	 * of /dev/zero anonymous, despite it not being.
+	 */
+	desc->vm_ops = NULL;
 	return 0;
 }
 
@@ -526,10 +538,11 @@ static unsigned long get_unmapped_area_zero(struct file *file,
 {
 	if (flags & MAP_SHARED) {
 		/*
-		 * mmap_zero() will call shmem_zero_setup() to create a file,
-		 * so use shmem's get_unmapped_area in case it can be huge;
-		 * and pass NULL for file as in mmap.c's get_unmapped_area(),
-		 * so as not to confuse shmem with our handle on "/dev/zero".
+		 * mmap_prepare_zero() will call shmem_zero_setup() to create a
+		 * file, so use shmem's get_unmapped_area in case it can be
+		 * huge; and pass NULL for file as in mmap.c's
+		 * get_unmapped_area(), so as not to confuse shmem with our
+		 * handle on "/dev/zero".
 		 */
 		return shmem_get_unmapped_area(NULL, addr, len, pgoff, flags);
 	}
@@ -632,7 +645,8 @@ static const struct file_operations __maybe_unused mem_fops = {
 	.llseek		= memory_lseek,
 	.read		= read_mem,
 	.write		= write_mem,
-	.mmap		= mmap_mem,
+	.mmap_prepare	= mmap_mem_prepare,
+	.mmap_complete	= mmap_mem_complete,
 	.open		= open_mem,
 #ifndef CONFIG_MMU
 	.get_unmapped_area = get_unmapped_area_mem,
@@ -668,7 +682,7 @@ static const struct file_operations zero_fops = {
 	.write_iter	= write_iter_zero,
 	.splice_read	= copy_splice_read,
 	.splice_write	= splice_write_zero,
-	.mmap		= mmap_zero,
+	.mmap_prepare	= mmap_prepare_zero,
 	.get_unmapped_area = get_unmapped_area_zero,
 #ifndef CONFIG_MMU
 	.mmap_capabilities = zero_mmap_capabilities,
diff --git a/include/linux/shmem_fs.h b/include/linux/shmem_fs.h
index 0e47465ef0fd..5b368f9549d6 100644
--- a/include/linux/shmem_fs.h
+++ b/include/linux/shmem_fs.h
@@ -94,7 +94,8 @@ extern struct file *shmem_kernel_file_setup(const char *name, loff_t size,
 					    unsigned long flags);
 extern struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt,
 		const char *name, loff_t size, unsigned long flags);
-extern int shmem_zero_setup(struct vm_area_struct *);
+int shmem_zero_setup(struct vm_area_struct *vma);
+int shmem_zero_setup_desc(struct vm_area_desc *desc);
 extern unsigned long shmem_get_unmapped_area(struct file *, unsigned long addr,
 		unsigned long len, unsigned long pgoff, unsigned long flags);
 extern int shmem_lock(struct file *file, int lock, struct ucounts *ucounts);
diff --git a/mm/shmem.c b/mm/shmem.c
index cfc33b99a23a..7f402e438af0 100644
--- a/mm/shmem.c
+++ b/mm/shmem.c
@@ -5905,14 +5905,9 @@ struct file *shmem_file_setup_with_mnt(struct vfsmount *mnt, const char *name,
 }
 EXPORT_SYMBOL_GPL(shmem_file_setup_with_mnt);
 
-/**
- * shmem_zero_setup - setup a shared anonymous mapping
- * @vma: the vma to be mmapped is prepared by do_mmap
- */
-int shmem_zero_setup(struct vm_area_struct *vma)
+static struct file *__shmem_zero_setup(unsigned long start, unsigned long end, vm_flags_t vm_flags)
 {
-	struct file *file;
-	loff_t size = vma->vm_end - vma->vm_start;
+	loff_t size = end - start;
 
 	/*
 	 * Cloning a new file under mmap_lock leads to a lock ordering conflict
@@ -5920,7 +5915,17 @@ int shmem_zero_setup(struct vm_area_struct *vma)
 	 * accessible to the user through its mapping, use S_PRIVATE flag to
 	 * bypass file security, in the same way as shmem_kernel_file_setup().
 	 */
-	file = shmem_kernel_file_setup("dev/zero", size, vma->vm_flags);
+	return shmem_kernel_file_setup("dev/zero", size, vm_flags);
+}
+
+/**
+ * shmem_zero_setup - setup a shared anonymous mapping
+ * @vma: the vma to be mmapped is prepared by do_mmap
+ */
+int shmem_zero_setup(struct vm_area_struct *vma)
+{
+	struct file *file = __shmem_zero_setup(vma->vm_start, vma->vm_end, vma->vm_flags);
+
 	if (IS_ERR(file))
 		return PTR_ERR(file);
 
@@ -5932,6 +5937,25 @@ int shmem_zero_setup(struct vm_area_struct *vma)
 	return 0;
 }
 
+/**
+ * shmem_zero_setup_desc - same as shmem_zero_setup, but determined by VMA
+ * descriptor for convenience.
+ * @desc: Describes VMA
+ * Returns: 0 on success, or error
+ */
+int shmem_zero_setup_desc(struct vm_area_desc *desc)
+{
+	struct file *file = __shmem_zero_setup(desc->start, desc->end, desc->vm_flags);
+
+	if (IS_ERR(file))
+		return PTR_ERR(file);
+
+	desc->vm_file = file;
+	desc->vm_ops = &shmem_anon_vm_ops;
+
+	return 0;
+}
+
 /**
  * shmem_read_folio_gfp - read into page cache, using specified page allocation flags.
  * @mapping:	the folio's address_space
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b9956df25d4fe8ae34df4e3388e5adcc9cd151e6.1757329751.git.lorenzo.stoakes%40oracle.com.
