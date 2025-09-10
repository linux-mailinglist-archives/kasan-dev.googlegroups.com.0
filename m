Return-Path: <kasan-dev+bncBD6LBUWO5UMBBI54Q7DAMGQEEKBUNVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 73211B521B2
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 22:23:01 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-30cce9b093bsf22845fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:23:01 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757535780; cv=pass;
        d=google.com; s=arc-20240605;
        b=MzjIqZLzTnfZsC7ipJwDUaTHtYLYHOQaVLwkcgugxzktqZy64ZQjroShnlZ/2bz3+F
         dPfuQbB1nFCVncJE51HwpGoSLRE3aI1VcchbdnFkdMMFYB4iNIfu+2Pu/joZAZUFEK7s
         bkmABOYM/Rmwzik+yT37xk6TGNkpwgpC5v2Vuvivrjq16ZlbdfdgJerMqBrMHSioXwy3
         F8SsxxB7CTUcZTLkcDS0KaKARzSjObb3RjdlIrD3o1rAXpjQK8rwihy2bjR/iCJKDNue
         f95830zek0IYzzE/Vmnt0KaeHwzUDIIuaUisk5T40e49uMz6ZMjSzNqyC7fJ3DP6IOOa
         wGPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kxnO+gyjNoj3U38PElOIR1ajC0OcI4oNNYnaVL6GDxg=;
        fh=rsgBGh2Z80yjO9NJ0NK4lBOIdniZ11Aly9+LtZtnnpQ=;
        b=cV+/cYclYH5azdRR2JWYtLjQeg3frnvKeJ24xPnHiCRXDjJefQniIzesU96TcHy64e
         yxReuwThSMsgaYICpyWXOlRgPvV1WhXEuVwBEO6T0Mqc69PpxplO38B2S+a4LWQyBkNx
         6WxwJi7eL3wEKtiXHTWblrwwBYUGfQA09G+oSsYIAhElJ/tHrUMBFj2SHjusJhoogwKh
         YkoLWXx9tRFpw8nEVJXn9lHjUm9lZTR3yWXd5iyu+1hUKv8xyn6xUYbmMVShWPlSu8+q
         sCHnWuIqWKTCHRmYtxzVVZeYj570Cmd3KJnGv1BAAp4d+ikPMVMaI+fauf/BBXbTXddl
         tEIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=PAxM6SFO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dYkIJSmw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757535780; x=1758140580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kxnO+gyjNoj3U38PElOIR1ajC0OcI4oNNYnaVL6GDxg=;
        b=bce8at0LxM0hP0TCXl6BBXuRy2JnexR0k/sl8hxOb3wIrYDBCxzaDytuYRzxZa+cIg
         mGxF7EIQkW/9/xEpbPwsff0NRiU+8AQ+8voX4w4j7BNsCU9v4R8n4pmp3AEMSN3f9CBf
         QetN79xdTLzGk2hja3gPE9wYq2NVkz8NhLqjZ4qvM71v2aiZdkd7qwxtoG8VsTYr6v0L
         SYy9jXmHi6TrpY9Rzb/nHj4x8yBb5DkNov9LdH3CGi0qCRceVOs1p9XMbChjFYRA4N5+
         kCTGR2N1JBdsuojd0Q1U2GyKRP9d/kLfS24RreF8AvXnMN5b9bg/p2YbFveg/37BES3T
         iiQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757535780; x=1758140580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kxnO+gyjNoj3U38PElOIR1ajC0OcI4oNNYnaVL6GDxg=;
        b=laTdCUvKV2PfnIh9FBaD3HdDu/weZ8IZXFQrVpC9jrMB9QIfSv0argH5mLRP2XAyc6
         nbllozJ6BTHfIt4QtIdSLAUWl6vYEmf9aKsnucV7jlSiZIYidzGeti/ifMf5zLs0c/DO
         ULPA7THlbfTGR2Kk6PuuhIAaHkbmgb4rgoK5P3nlD2P7q2/9/N4NM3iH/tHGVxa74aS3
         7NiXtb1lTED2wGfmkxpO+vxdU1+3/r9d+uFtAvugdc7QmUpC35VYGoCLEIj89udKVldc
         LjaT77xz2kRrDG1GAYed39vJ9T98cQtIFGu7oh7PPG36Vgf0pZvlIGnRwbIEA4vhrTUI
         YM3Q==
X-Forwarded-Encrypted: i=3; AJvYcCV6g/Q7taYT34KFGIE9gCqMb2j8nu93C85P2BltOernQ/qR+lCaUkMdyfpUuOZut+8gznX9eA==@lfdr.de
X-Gm-Message-State: AOJu0YyeeIq8uxlHQpwMBiiVpahZvYI5htztt6ySEd0Amu0auCssNDK8
	xucFhZ19C/DbiDO0fq6lxCL0oJtj43cks2BTZjSusidinyu+x3JMLpVc
X-Google-Smtp-Source: AGHT+IF3ClOMVKkP1iD38QpfUsI5xVPipazFwiz0vjbbJWHbrq5AGr4RrhlJomuaqL9dnyPH2KpTcA==
X-Received: by 2002:a05:6871:6ac:b0:319:c3ac:dbdb with SMTP id 586e51a60fabf-3226512ab26mr6899346fac.42.1757535780136;
        Wed, 10 Sep 2025 13:23:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5EC7Qe3GhozQHUs5ccgMYbfUolyX7+nHjnHg//YpBhtA==
Received: by 2002:a05:6870:98aa:b0:30b:d6e4:3de6 with SMTP id
 586e51a60fabf-32d0682737els9614fac.2.-pod-prod-01-us; Wed, 10 Sep 2025
 13:22:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU6EAO1Yw/W7n6I4D065BSrs/gpiwoSIhrzlBcn9hMQiSItyNPS6ZKkYzlaxnRBAAXYtCzhVIF9j6w=@googlegroups.com
X-Received: by 2002:a05:6870:7d89:b0:30c:2b4:e332 with SMTP id 586e51a60fabf-3226253bc71mr8161496fac.2.1757535779049;
        Wed, 10 Sep 2025 13:22:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757535779; cv=pass;
        d=google.com; s=arc-20240605;
        b=DoM89hoCiIJU8aGfoEmx9zRgZr+T1FLKyhXcgKTGtRL5lczyRpQmbhgUrsUR6HZa1r
         LCtu57lQdnmbRvUXm8qgrM8i04RjR1J5dsg8AVDFiiCvY2CjKKK0d1HVE8HqO1d3yN8u
         lrzxj4AJYfzh9yJLQ1leMcjky2XxFlDq2nuckQvr5xNidfNHTGTeKZIEWIaOYZfa+GLD
         3HeGTwfgWjULn/4Agg35JPYO30mANZzvHKrWlTr0JMaCu9V9BbUFOBgrFnnWX4XGf+3c
         Ny0Ih5zFXoofs0qK99vPi6E27gRFWma3FzWRJTmcnMcN92jpovGOHgoaxu1loSRrglNT
         4yEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=HmoYH7UtjFIU7mwG50sNABYBbWEke9S7Scd1ARsxMAg=;
        fh=Fy25XhJU7QlqdcGVDRt2pk4lLppnvj9d28jpEhmW5DQ=;
        b=ltosLmV1w43eGurPXAUfTqvKlasUZWmRytw+Qf7H1OdiPtFOfwyZl6UTiX2J3ko2OL
         EWy2gkJgxo86+dQx0ffLwjSFJPWTpqCwRBoaYOCijYOZsW1QcEQ2eXayLR4Azb0WiIYb
         M80kTDw/pSBjvgnC2OWuK/hiUScoihq3IUUUDMbz6QXstxb3QyUa7xjYDUhEBA2J0MRr
         coDds4832NWgJ9ihSssrH3PNoWXdcjgAWbm4qyfhDn0Xk6o+Lm7ePwCprkeHnvjxpaeB
         3CQ5oCkAT9476l++dZkrvmOTqkX/qkCTHmdkeTQNDSm6Hw5rmv5/1yFtw7qZVV4Cv1s3
         193A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=PAxM6SFO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=dYkIJSmw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-752033be3b2si17966a34.5.2025.09.10.13.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Sep 2025 13:22:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58AGfjHn009713;
	Wed, 10 Sep 2025 20:22:49 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgvy33-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:48 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58AILQCL038766;
	Wed, 10 Sep 2025 20:22:47 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010027.outbound.protection.outlook.com [52.101.85.27])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdbgtpk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Sep 2025 20:22:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=E1lTFGNXZFrbTflL6ORyVe2q096AjzvOgLWFJJ/Ke3Q8ly5FSD9QJxzlMvDZXmnsRArJqcEj16cgr4/zKBJXLesBonpLcasfOUCp0r/aRr90Rvm9wwAxzUHWbtiZwrxTYicP4XJ/ZP/pITh+K6y5B37zGXoQN1l2km2VaB5GgilRFs+pLXjM5GO8pS/x7pNuh3/M4xjV8FikzWZrnOzPSIVD/6cdHFhj0tqll6xbEiEpIlqrmsHAu3fkokxLFp7ACOcLaTPKcrB6yBv4tBScUu8oaFZ4Tu7AhxfE2H9ccw0/lGCk6m0SXZMBQn8KijkENQUbqzX3oVcuxQb010qRbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HmoYH7UtjFIU7mwG50sNABYBbWEke9S7Scd1ARsxMAg=;
 b=X9Th1m/SnAGzwfcyqRBQqHVFADHy/9RST4RntfJ+ZqGlNKrPBx9e+9rOhJ9e1pONOsBd/8KgcutODw1gYQuXPW9Jrenb7odqITMoR1dPL8mRg7BIeP/zTFA/UmyCF1fiIFwQvQ4YPWFRmzTYS62/HcOlMJkyDAVPpfDkAELzJvYg6+yms7dS/pUEX6d2Zyg3wyM47xewDWGZxX15o6+jw2lk+CX0NzOFUv/xGi3ec7/kIWnLQVHcgQ+YaSpM324SvMcfsciY2T9bW/75J0eVvp9e5zfJJbU6QB9Q2eO0jmwFmTfT1cMX1qCB7Jy3K3YEFu2fHzVmRHWhy+Lldt/DFg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB6278.namprd10.prod.outlook.com (2603:10b6:8:b8::8) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9094.22; Wed, 10 Sep 2025 20:22:41 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 20:22:41 +0000
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
Subject: [PATCH v2 05/16] mm/vma: rename __mmap_prepare() function to avoid confusion
Date: Wed, 10 Sep 2025 21:22:00 +0100
Message-ID: <9c9f9f9eaa7ae48cc585e4789117747d90f15c74.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: GVZP280CA0008.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:273::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB6278:EE_
X-MS-Office365-Filtering-Correlation-Id: ac61e260-936b-4db7-5259-08ddf0a7cb31
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?g6Icrwe2boaOTxEgAbAmKu22biysduJ7wtbVo8Fu7q04IVlVxWUCnaNG6y7Q?=
 =?us-ascii?Q?u90RyCqU0UKDaMpzBRiAGR7V7zoGNv/NlNAzp/M7roaV1VL6KFKQzLHD/gSo?=
 =?us-ascii?Q?/bA/QDr69+QeJSw2by+Pp5P/ge1flY2V3xgmeQjrFTBN3I4fyReXMHX8FwKn?=
 =?us-ascii?Q?jKEDHCfk9sAq2YMA5AolagBixhB+J2CQ3WyG2bsPYgZlOiGqKe3B5jNRFna3?=
 =?us-ascii?Q?/vdz5J10WiydItPlkWedUoQRU35a1QbPL/AbTcQvwB1hsVwEFCqN5h1fXJ5s?=
 =?us-ascii?Q?5cj30AY8SFhtPXfbLdbrGyyLXJdRItUMqeKy22VJe4aZUjiObWMT/GUl31La?=
 =?us-ascii?Q?WCU++e6Waw74U7XmKr88GR6H/wrfQfO1ePw9/EGUvujDdVEXXJUa9MrPjs40?=
 =?us-ascii?Q?JMfP3XoYH1OfIIfuBb3aN0jPLpF7IxoqW1UotUmpgH2qXNVcUZZuPNnx4VOQ?=
 =?us-ascii?Q?M7SpcFhydeIEr+VHsCtbybMQ7InjtGANnG55/5jF56wGxI1qeiLEcKZst5Js?=
 =?us-ascii?Q?b2K6ly4kwXsMc6kjjwco+R+uoTyah2exGb4EgSTAt90s3Pr1XP2foJYw3G1b?=
 =?us-ascii?Q?RUmHcP3TmDxbXwPzCM5ynQRaCD6iX3uC/SsAp4UevxWKn4B8AFtDkIRdS7Ve?=
 =?us-ascii?Q?eXelTrnNGtHeO/BxEUz7+wUNmaIHnfJapnNsUKPFBE24Z98BYSluBliGn4TV?=
 =?us-ascii?Q?rloq4HLmRT9bigOIfrnzAVJROHrIuo3vBQbH4aIcO8aQAqWE4BqixDqXW7ED?=
 =?us-ascii?Q?DdhPdDUy01RKOMSKtKPu/NPvgtcvlNXh/0x7Vbg6f5zBne/lc8L0ef689z4c?=
 =?us-ascii?Q?nl0e7UysA7aldDkByg93Hs49JfWNPPXbxunWvPBsvXHMwTOE6n65KLMgsxVM?=
 =?us-ascii?Q?OX1WR/OiyLIa+2A5h0tH8AyQVcuPTM98O1I4QNeKbBzR7EtxRTYoWlnVEhkr?=
 =?us-ascii?Q?OXzgKjwX6icOTr54UnLjZpIRptOHgnzX4ksgcJtQ5JQy1RsJlkt1W1uvqppm?=
 =?us-ascii?Q?rfk/PqHZiGsLTATzgvT97WkF7huS/kD/FQUayeXqJvfh1IS+ANIA6JHlMZPU?=
 =?us-ascii?Q?dJl6t2Y6PsGKjiyINGpLEV4MmE5IvMATyrsB8ml8Oz1qDq9YuM+vlBHUPdAa?=
 =?us-ascii?Q?dZPx9jIPD2lyIWlZVKGrHy0m3wDMD75Wmhft3EhPxxEHEgRL7tbJ+/xgd9Rz?=
 =?us-ascii?Q?8MuSfc9eAwR//Z0Pkf4QZHTQWiWm8pikOXz+vzNkj4p4OJ7in+akKvhWeZaN?=
 =?us-ascii?Q?6F8wMbqPXWkL/A9SqnpfeflBdB6RXvLa86TLmNEG2OW7aivBx2eqT/ONeDtA?=
 =?us-ascii?Q?Wdh1q7+wu9oEpLQyV5LHimAoMO8n2ITTFv1cqWahaSrErECjLtYWv0/0ImVB?=
 =?us-ascii?Q?zVGbBzy0GbPnyisnxTIfcXNzOJInPEZWW78S2ok9x10GMmS6nFL+x/CexL91?=
 =?us-ascii?Q?0XSbv5I05WM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uMTSWBBJXnxCYHpYtjT0F2a8+kTx7Wf8Kzu64TQgPR922fOAdVWF0G6LI8ph?=
 =?us-ascii?Q?+yTcVaKbMZkZeJqfu98SwDb2Io/NRE20SIBD+V6TzX3c3MpdtW8wLEoUE+P0?=
 =?us-ascii?Q?owNZGpg09pMdmQtYCBlirigpWwn/WF7uFnj/9LRYo15sEvSMByFzSOn2C9+2?=
 =?us-ascii?Q?igVy2+JhK4n8r4UohMlfdmr97xH/hI6yEklyyjViJ4u7yRNH4LGiTKy1/dtc?=
 =?us-ascii?Q?NFtWs8LPhKpPh5gcXSA+0k5k1lyAerRGysalvSrjeRurqwxlJKgXr4ekayhw?=
 =?us-ascii?Q?18i5/3ncNqc2jo5Ij1GThvwvs6i8EKsoVn5pY7NHcgdD8WWejafROe1LrOk8?=
 =?us-ascii?Q?HlPw4ZuNUd8gEannN+BvoTsVO1u0wQX/eb2ZKkNpNaD3XqJ/irlutxjIE8nx?=
 =?us-ascii?Q?NWqcdfmf7IHgbplh/mPDCKsIRHHg97Jp/NPAqJ/+hpYywTsBLFCs/WoZ+sf2?=
 =?us-ascii?Q?EuJzY+/tcjRbUxJilKa/TgGNYxxDhKm1kl9t2nGEh8jx93UodPFOS6ZH4E5R?=
 =?us-ascii?Q?HTmmX2xDNpkvSwjV+Hvc/4ZLsPDB+XKcWiTcMMQXsnoXEpA0IdkCHXlGbIuj?=
 =?us-ascii?Q?fJh9tPCih43gMNqD1wtkG+Cj6DtPJYx6389EvPKS5F3rQrrg7wTz2HqS6XNa?=
 =?us-ascii?Q?JL4rBBzTaiIN5CWkGZKFlhkB/HlWLvDGYn30ldvUIL1ZdQx2+QdSJva0SxbS?=
 =?us-ascii?Q?I1KIHvy1u7lRNo9PQDRL61Ag/qA4rNULNpcCIDuves32AKJhWpqK2bXJmpzA?=
 =?us-ascii?Q?X4c/0UelFkMGyiOwo6Vd1LFB6SkzpZu69GdBiYM3Tt2IWqbRDMLaXSOcNIGb?=
 =?us-ascii?Q?emFRfWwMhNYRuAAt3xvs4nIuVcMC98F8BYuWVWaj3rU1VVuwP2D1q+iSbsDG?=
 =?us-ascii?Q?Nn8bpxjSnGbDHvkw+61/sIY3ieITKC8KWPVz05p7ms+5w4t0zdxO+Djf3MUi?=
 =?us-ascii?Q?2kRUO4LESWP0VxOXKzvAWa0CaElJBd0AbDjOwJxtQrkqHnS8Clk+Bf61QdW3?=
 =?us-ascii?Q?/ntLJSeu4ykLthN5YRSUnTSTkDovchjgT2cI8EwJQsmrOodp6HuWr8uqeMsq?=
 =?us-ascii?Q?Ew+mBTwsu7ViLntWQ80ywGFIUGoP94QbXkt8w+B4i0nhkcB/uBngxiCsYN9Y?=
 =?us-ascii?Q?ZSVM1UuttHra8gNUGcuzRJ7YCLNnGciW2FJmjv/e3L0XWRnG0pSuNuIFQVuI?=
 =?us-ascii?Q?c9s+IPt66k7hshIA7V4jg5aY5IzI4QJlc8GN4i+3bLK86PSyWjU5YxUDLZza?=
 =?us-ascii?Q?J1e4MPSf8duw3+GsyJIrm7CScb/Pjicj5KBrKulr65IVCksllxJOCQXxnb6a?=
 =?us-ascii?Q?swAx3HoSAVjn3vcLwNEOa6EMTY9w4Jt5/8y7uhWwpNpnCXrGeD/RiA8qvnVv?=
 =?us-ascii?Q?25hBuzl1d78Tp6yNIkQAjpTnd3K9i+b2Xoe14rW6LZjxz1BNP9R3kf4xn5tN?=
 =?us-ascii?Q?EAXJym7prGK/IVQ/a78b4LKATGl6O4Eds/ObxzX/zRaUkmByIcJA564m2Xpg?=
 =?us-ascii?Q?NeIrWNo3RUOxMHlkkHjQwQMECC/b7TLkEc+kUxOEvh00jWcpTnaTvShc6IVj?=
 =?us-ascii?Q?h1Fp2/zP82TpYpxhVVg+DMd1Az2xAeSPvIedjkOxMgOP/yJrDdzz1Q8ONLJ4?=
 =?us-ascii?Q?Fg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ZeXLEffZPZT8E34kjWumrvE6UiORoXjcnQjkGY7MOuUJJgk9MqTeP2CpDabh+dDKIPtYFpW7VbzqRd6aYv7Jn7qZ30REzW4s9nbZJJQPu9nM0mJ3uEx30LuOh+LrSHHLb+IuuceW76p1N/zO7J4N1wg4C9fpbgl0VdzL/ONHRBxicoqbD1I1dpWxYOKbn1ujjKswFamIUJn1PMSTLK52pyv1Rnp7GDkGexuX0KMocg4kPOGRewlGxUSe/6SBQFJ1CAYhHxiCtX3MTdcEPse4VccuRC98NlTsSsvJvR9sUZU9EfcFmhVo8V/O1M5nADR/gkV251XefZcHZobAJZ//7itk5kogYe9fCKQs1gY4beldxKo8Qzo+WGAc37cWo/jkJ4/xkhPlKReczLaaUqMuUqKKidJdZQZrqZhFaZBNceoGDysIGWbPeKcWuPWPZfAyFAe6WvjsI0wp+UMC6ON2GlzOedcEeWZOsl/E35Jd9JEaUm8hPBOsE/+9qK5+CwqSl0WAi83retA/ukDBKDxyinFienvNwUKHJK+8xL6baz0evZoPcnizhAaZRN5md3nJkl+eEcrzJ8lcmFqaNLdn3poHcyGRRhWFjspT7iT6fvg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ac61e260-936b-4db7-5259-08ddf0a7cb31
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 20:22:41.6342
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rRc+Thtjbz3QHdTeWUqb9MCOVdV0bLzzSVCF4jX5ZSC/A/GUxDDRoJzx8vqbR9T7aQtcURr2VGIUZ5h9HqQ9FvudMpiD23EfjYjThL4wMqM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB6278
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-10_04,2025-09-10_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 suspectscore=0
 mlxlogscore=999 adultscore=0 spamscore=0 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509100189
X-Proofpoint-ORIG-GUID: 7FItodJgzAfiVy7vvOjF8qEIDObzNs2D
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68c1de18 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=9WrioahaYVwPZVrL5YIA:9 cc=ntf
 awl=host:12083
X-Proofpoint-GUID: 7FItodJgzAfiVy7vvOjF8qEIDObzNs2D
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfX6jXtVwR+YrKG
 XS1wmBVZcRHfUONBC9yeVTn+ZYT7iLhRu1rSq1/SNvNtw0HzDtWK+rFDlvwvdhLxb6e/+kgXOza
 3kCqOl/5nrK/6+30L/icChkful+lBwdu84ApccWjyWcJLIqJMQwnDBWBI6CEKQE/3T5ukvGZfh5
 n0qDVuHu68O+Gtw1z+Gw08S7oQ5nOTdhktgdQDeNkGLKsxMP65ZYilBxUxhIGtCXbGmZD9JsX5y
 rrpn3BREu6EWLCr3u9K6/Db8gfTsjgz0j6MOvNkP5DmogLQlvL4ntHDLrBiKYXAKAOzJs8p222I
 avRbvgyD4OCHd1STQYpxIkmeFTC72bsq4c03Gm18ZDyxz3dFCTF2eFECAJHsn8Mkgo4B1jbktIg
 uECItm/z+A57Z4zRlty9ulC802Seew==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=PAxM6SFO;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=dYkIJSmw;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Now we have the f_op->mmap_prepare() hook, having a static function called
__mmap_prepare() that has nothing to do with it is confusing, so rename the
function to __mmap_setup().

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 mm/vma.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/vma.c b/mm/vma.c
index abe0da33c844..36a9f4d453be 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -2329,7 +2329,7 @@ static void update_ksm_flags(struct mmap_state *map)
 }
 
 /*
- * __mmap_prepare() - Prepare to gather any overlapping VMAs that need to be
+ * __mmap_setup() - Prepare to gather any overlapping VMAs that need to be
  * unmapped once the map operation is completed, check limits, account mapping
  * and clean up any pre-existing VMAs.
  *
@@ -2338,7 +2338,7 @@ static void update_ksm_flags(struct mmap_state *map)
  *
  * Returns: 0 on success, error code otherwise.
  */
-static int __mmap_prepare(struct mmap_state *map, struct list_head *uf)
+static int __mmap_setup(struct mmap_state *map, struct list_head *uf)
 {
 	int error;
 	struct vma_iterator *vmi = map->vmi;
@@ -2649,7 +2649,7 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
 	map.check_ksm_early = can_set_ksm_flags_early(&map);
 
-	error = __mmap_prepare(&map, uf);
+	error = __mmap_setup(&map, uf);
 	if (!error && have_mmap_prepare)
 		error = call_mmap_prepare(&map);
 	if (error)
@@ -2679,7 +2679,7 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
 	return addr;
 
-	/* Accounting was done by __mmap_prepare(). */
+	/* Accounting was done by __mmap_setup(). */
 unacct_error:
 	if (map.charged)
 		vm_unacct_memory(map.charged);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9c9f9f9eaa7ae48cc585e4789117747d90f15c74.1757534913.git.lorenzo.stoakes%40oracle.com.
