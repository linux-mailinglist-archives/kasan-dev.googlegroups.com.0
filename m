Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJWO3DDQMGQEGOCZF4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 27002BF101C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:24 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-43f7bca4787sf1790266b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962342; cv=pass;
        d=google.com; s=arc-20240605;
        b=JQdJMM7JI+KiHwkjdfurFTnJBXBskE54NiLnDnWYcNHu71d3HCF8m8o5SNWoxeITei
         ng0nFLlxuMAwqUQiCVyve4pYSCubsgahJR2T7WvectAmhTVLjlsd+jjr5ygeFlSxZJjF
         EiXzlNklGvT72PQqycYmFdu9Jj5JUhYKBvxI3T5LdgGJKfgLjNvP1Ju2E3hVeupsHwIQ
         /owkOJ/vfyOi58+IptBiRsI+FXJKsvMKON6klUgZ3hDR7m9mII+RebU0WVRu0P38oyuK
         W0Q0OijbL5kFE6Co7k8SOTY36XD3ByxXAWqm5fTAvCXucPzeT1c/U2rt9gPiyJDpkVpj
         EN2w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IRdk7WK3tI1m4nMm69pvsnUFYqpJQhg3v4srU7IfX9s=;
        fh=a393NH7ludHCObPg+PLNvo7w4UXFHsqk8FPKajirqCQ=;
        b=dw5d9QRTwXGBzdGzDteUon+IQ9XDAIZT5Y7BMvLtGy7PM/x4ZvJ0sQxINGnrjLFmqk
         mHoCv3RxD7waLn6SHHqwDryhG2u1C4E1eogyzTRQw5RAG2YpuqusVBKINg7Zp0Z9Eclk
         zOuuXG2VbtftnyWL6hDJ1sri9nD8V3OHT0DBkQn4ntjPrpE/c9WiS+cOqysJGkRV/awI
         QSVgdQcAT6ncMLqKMr30IMDsG4cmWvg8FjSOapxiITkfpZW0EN5ZngfUxqWmfJvCfjzA
         e5lRRdj7Qzxm2Iv6FIIrZB8y+ZhQxRuLdVWAlbD1jFReuy3vuJYuUjY9V77FZfB1x8KL
         Rw1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DFLB0HIP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k9TOFhEB;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962342; x=1761567142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IRdk7WK3tI1m4nMm69pvsnUFYqpJQhg3v4srU7IfX9s=;
        b=fAsbMPElL8q2yFsDwJK/rzlURqTlnTE1N3CRwKTOJwtzDo9Dt9RIbz0/pn4cm3yuE7
         MxCRw5Kzq3BREgTUqkshnJ5v/8ONhSsd3WT8xmFwzP4wvIs5FHfkVb++6yYa78v8HT+8
         /UplnpIYydF3D2xs8JNNqCgOogQt1jCVeXMtTJ7/wJKOHIcACrvoawSufMd7zIH1Z2lb
         j0oHeifC6wNY8HIcibuWLR13VTW4REGTl+tfLftc3LmjUBoLTYBR4+cSuGJLx+BYwoKM
         eecNBJT4IljDqbJoMx0GwNSY/0YagnSUVw4k92v7vEVu4VZJRD/wYmTDK+HwYahC54J3
         RInQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962342; x=1761567142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IRdk7WK3tI1m4nMm69pvsnUFYqpJQhg3v4srU7IfX9s=;
        b=VTuFNTwlfEbW3KFJMWMOwSp7Gv2kbr8gBNpugXJG3nFTzxh1/UNlomVe4MRac5gSSQ
         3WZmAH614nWZozQZCFa8qlinEFbTjJVqmebO8IluUN/jfrQqv/SCwtBWswRl2M6DpIH7
         dRZ5VgKhCgjkTMCD0poFYk3Sk2gSgZ9QFkdy5EG8LpKWO4NMNHPpeTugKZFU3Cm7HgLR
         ZjViBSlelCIgg3RY5JdA9MZ2VdmlfRSQfAD7+Cx0qB3iyoqNpaDzW3TQsJAyCp2v+4Zw
         ubKedNSgET7Ti98DSvbh55MIxpFov53khfckxexBHe71sz6EvO0xC1GBSRur0JsI/5zS
         w4/g==
X-Forwarded-Encrypted: i=3; AJvYcCXMIJFH0HIO45U/q8ZZ1CoWDK+0uPqpMl49fVZ/guyXnaCAKbvqJOKWRlLrTACI6TqUA7Ti8Q==@lfdr.de
X-Gm-Message-State: AOJu0YxQHQmoxWXqGHKiIWEeKg3WADjspRtnHymaQhps0gKgFlJlfRUa
	+E/XiC7Hyuwdx7ZHUolsbCD8wYtwHxLQ+yxJQSwBiuOdo98wAF4Ahgfu
X-Google-Smtp-Source: AGHT+IEMsq6rjtFA+M6zcs0mnkNgoinKtVTtaUkQQrhlrZ/SfNomC3EM/jeGIVIG/hJWHcdgcsU9fw==
X-Received: by 2002:a05:6808:309b:b0:43f:45a5:c3fa with SMTP id 5614622812f47-443a2babf85mr5851016b6e.0.1760962342545;
        Mon, 20 Oct 2025 05:12:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4BfFONwlkLP5vxfdw81QODGVVrvyzSkSXD4PtzLy2J9g=="
Received: by 2002:a4a:ea98:0:b0:651:c07a:14bc with SMTP id 006d021491bc7-651c07a1568ls1257252eaf.2.-pod-prod-06-us;
 Mon, 20 Oct 2025 05:12:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWEzoY52zcjC7wJ2+WapAzk4MuPRAuzclFKrk5WoexXjwzaRkS3dc3cAnHfpDY87MbBNwD1pq9gGP4=@googlegroups.com
X-Received: by 2002:a05:6808:1998:b0:442:2ce:46cf with SMTP id 5614622812f47-443a30b033dmr4870487b6e.34.1760962341706;
        Mon, 20 Oct 2025 05:12:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962341; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y2BaMDBiQF40jKSDdS8gvxtdzFFWdwouv7xsl1j3UupTqtRMKtXMZKsYT/I7rMUF0b
         yExhwVKBLshvpHNekR/+BfTT75SKpo+rbUq/PmdQFrqhC+Ws0Na3Z0ue2HuT+w/G1R7k
         d62gxK9Dp8ySy7z0Lw0WuL7wNXbvDEaYErk54JJHKZty9dxiz3PgpdoEVraIh3qwI/JW
         PffhEnvy4CkICDV6ZIX84Mtiq48clFLIRf7adXKga7rmcvJy34QnKtr1HrjKRRuCFGuM
         /ZI1tsgmElxZeDyQjlUtXqqws/a6RQUuoeAcUb411bR8PO6eC6R/KskL6QMXRIp17iHx
         KfCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=DmtmxspVYK8qiZlkLGCcNvk+7f0tzFC7tmh1hbziWeM=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=HsMDOM0rm5AuE/FWXTyRwTWFjKWakZFmj8KPFReZb1DAU0hZld7/SH3kK2ay2/hnbB
         CGeBV0XucA4CBW5O22PRPeFQ0ECtAIGVR5leSi/ym8WzPSfhPzm05LJx1fmGG+8Gblu1
         RrYjZ2Rc45RmVeBI0E8fCydN+am3sMDo+0ePkHDL6ZwM6u62r/TYtPolnbJsfOUGs5Sp
         4kMniSsa9gIJSsfkYnhdGYatWeopUUZ5eEgbxtTthuYG52bHugz+5aMpETBkVvde1hZ/
         sF3Hgm+qIpAIOcCA+FsMLFzcF4GSgjC94JUF1rBwBwTXHYFSyJz0keAE2GgRPppNBzMc
         tn/A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=DFLB0HIP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k9TOFhEB;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-651d3af1983si410119eaf.2.2025.10.20.05.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8SChQ027930;
	Mon, 20 Oct 2025 12:12:13 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2ypt5k6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:12 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KAgp85009470;
	Mon, 20 Oct 2025 12:12:12 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011044.outbound.protection.outlook.com [40.107.208.44])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bbvbac-3
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:12:12 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ruOUgJ4KGQrTeTdb5enhfFmbgg7QjqurbEOQ1xCSicYM5L5K3soIUA7zsQwwhul9ZXkqnphhFik2hnHXjgTzp9a1HJ6u37nFkGtRY//zcbD2e13CL64QF4cD7V9X0IKLx9v0YjPdZn6NrZZvn2Zue1Tt01BlFomSCcXWAh1S7Blj0srD0L0lLavJKv2w3FdqfUwJSymabczVfv3kAPqdYr4Fj+4t/Jf9hSctBylvcTfm7X/6FuHcq1Ko3IoXyyec4JNCtOK8pYWGE0dIyRf82phz4ikCEsoVGu6sysWDP4lrfYV3VUqH5bZzAUlPqWtFVfZ9QxoqGvjDNm/9950I1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DmtmxspVYK8qiZlkLGCcNvk+7f0tzFC7tmh1hbziWeM=;
 b=cBv+cUNr+4wBHSSsJSL5OKDVI0gUYdXeY6Prl5FIcGzF/J/Z+wlxzdyCNINCOt1swAxvPqsrYIJKZky99lk27UbViMLLEB0YB/8/IL6L1HNqTyr6EI6CisAw6WPf/QoRZp1Tk1ckfJjAmWg4cUEmNoaZ8afuiMhqiUlG1TGAUrBWuJbx4eDxGc30qfAjPWippoW8ODkGavdGje++TjDJgp9PmNcckkytavG+7ayhU4wDODJG3EgCpDyT+N9qfOJse+f5O/BlptSMbHW31B4IdqJeVA0ls5mdeFgz6HUrK5/WyTpXqsoLKtSxd56SG31Qr3re1TZJlIahL+9gfbFb1w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:12:02 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:12:02 +0000
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
Subject: [PATCH v5 11/15] doc: update porting, vfs documentation for mmap_prepare actions
Date: Mon, 20 Oct 2025 13:11:28 +0100
Message-ID: <472ce3da7662ed1065cc299d14bffb70b1a845e7.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LNXP265CA0064.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:5d::28) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: 2d0d344c-51e5-4236-23f7-08de0fd1e01d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?vkDwPOpi5dUbjq8GMV+KH0IsQdk0kDeWTpIVYKsSyppFVP+j7AOJiBq6oga0?=
 =?us-ascii?Q?HmHUMpTsT9EOsHVXWsShPx1R5tkqLdHq8Bro0Dafer6bkWDX+ugua65p9x8o?=
 =?us-ascii?Q?RZ7BuvXKU7+0gl83FHQKEegJVk9p0Qj77Fro8T7tkn7gUaZlUfv+PuGdIGVP?=
 =?us-ascii?Q?B0lb1kuOKPXgKx6M5+DJP1mjQAuK6tcszWpCqRtI/e2V3J6BRqQmqnqLMHUI?=
 =?us-ascii?Q?1+y9mPwdhfb9xjOMlfF7nTJJqErlVPXdgkH9hP+S2tVBPXAEm4ubnLTI+TNs?=
 =?us-ascii?Q?OVVPhLz5ab+Y5uExncw30gZmV5FYS3VPjMED4qdJjPcfrpsEhUClZm50mNVK?=
 =?us-ascii?Q?xCJhAKMcBWdBcD41uJq9rI9MD22BXtq+DBoGREXZfxiNMcPttCXE+C3ZHlyN?=
 =?us-ascii?Q?Hc9B/9jQsj2zFpi9TFS9u48eBKJiLKmaChsatchA2YGWTSEqib7iWoj6/ZQ6?=
 =?us-ascii?Q?YlySzTVhgJGWnq8FQ39vLdQ6X2y4+fIjiKvd6XEPZGzRzI9OPp0Z6A1ckqG3?=
 =?us-ascii?Q?zgkyjudjqFWONlmXDiLRtb9CJ8pNFIc40Hh66QNpBoUGRAMay0UpD8lQanfX?=
 =?us-ascii?Q?0PwchsUKflTlfmjr+zp5HzSmSW6fZdTyLrpyvsQRkRxBG0naYCcWIW/MOhJx?=
 =?us-ascii?Q?CPHAN4Su2n6JnDBxWxA+4AYSu4jDHOg9Sib6V6YxyV3jX6N+0hhDOxaONosW?=
 =?us-ascii?Q?6SUDwHNeoooK0Qp6xGhD4XSQTwaHa3iC2ZRIBNm9ttUmh19r+jEtY9ClSEqo?=
 =?us-ascii?Q?dlMiZ7sjYFKaHsZcgj0fr43j6WByuBcrLhe0E50YktjIT5fTC3YzaVGsv3eL?=
 =?us-ascii?Q?/buW7VBqxSon7Qqko9crfrcHG6byq555oPC7Dx++DwfXW33JuxvuLxAMn820?=
 =?us-ascii?Q?uhYTpSFznhWKOf8noLIxX3THEeW/wqrTFEqW05zddv5RC3WZ7rAGZLp4DzSs?=
 =?us-ascii?Q?z4U16BbbfobfepPH7ZhTKlBKRNslNWmUnVm9LzEWvTpkO4fLgpG18zKtKd3R?=
 =?us-ascii?Q?3K6nlyQvLfszKeFSiHShrGjxK8a1K+ax5pOiGVYe5unxr6Qp8G6yXGIew9sL?=
 =?us-ascii?Q?3o0seRLyqyBucp7yc+WssOPXPZfnarMlzU2UBcDfiw8CwN7gRVAmdcGvrJRA?=
 =?us-ascii?Q?2wITY96UXooRBp4mHwZqWZUyPGXXP8W7awjX8rjx8ARqawnq8FVCUyljWdjJ?=
 =?us-ascii?Q?m2BBi55BbpwYQRYaXXuiFvT0qjmhQODkKFdEPO2wbGhSX+v8/DBA3ydbslKV?=
 =?us-ascii?Q?DG62Yj5g1VHTN433ZHaQ3TJndRN4TxYUcULQpvchjepNISitDGYFNktaZ3T9?=
 =?us-ascii?Q?cqQskPJrJxE05V0n+i0WRkSQhwQELfSo1GNaJladrZvafEiHoxv4gaupEyjv?=
 =?us-ascii?Q?TTHh/KkiHugDhTNupwsIbjQbkiC99IAIxMm7BfaHh0a/MsAcVqXNGcBn0Wn9?=
 =?us-ascii?Q?naN9+nMcFvNxs7rzr9k+CyAAA2qarSYP?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xbRR4SAMCdJj7+Ucln69ksBD1MUTgIJwfVUGGaHagupbMLzWWv69AFV3w8rv?=
 =?us-ascii?Q?EZSpQuHoLkXsTtaRRh0drpdvEHnkyI4jggwJ8zAfrrqZJbSfRHPOuLUXZEpn?=
 =?us-ascii?Q?AVYg6QYcTChE21fJFfZ0GhqxZCKjtILnvLIyIoCTSmbwalCdw3yYo17RnvXx?=
 =?us-ascii?Q?xIQtatfbLbchMi/N72IHWLy7sKNAQUCkgA4nKuMOBLI3/zxU1xa/zmTmSA4v?=
 =?us-ascii?Q?rqz97GRru3Q0zUc7JDmwZpuTzImkpq4QsMRXQp3f/8g0lLh8jCwH1mI7h+y1?=
 =?us-ascii?Q?DUEBD/E2IlT4d5Nh5fvgCqOC24rbMi26s4xNc6MBZFTlc09qeW/LYSYHZAmp?=
 =?us-ascii?Q?6awFgqN54GKdW8ZyyEnDS683yMgwlX7H3HV/ytC/v9LDpqPUAr5sQM3vKJqA?=
 =?us-ascii?Q?9oZOygHhR1X+WDjtdnZ/9lEl+FCOmJsDViHw8Mmcz4wauLSrbMzjQ6bn9mMq?=
 =?us-ascii?Q?t1q+81hQyeq+Bzthppo2JrOla784Wq2RhsUQ4TKn1Qs5m/bHqqwGCkiwWitF?=
 =?us-ascii?Q?wUJ4V1iOXAYUbpwMMSxWtbFFAqtuoVCraBkEoU8NZRU9h9UgE43bySFwjtcV?=
 =?us-ascii?Q?L82fTTkVVjUGD/Vo9TAXsXcRlzfHWerfe43ZANKYDDnLuCrJ9IPzWH2m5LkI?=
 =?us-ascii?Q?xaohPhG9cmSadn90loEkrHXsERJ1SvnbB/hCDRL/uISk7WxTg6JvnCSsUbF4?=
 =?us-ascii?Q?bhbC3joMnpwGBeCHCezU3QTSnBivD4nJ/ojF+4YjYDuHw30EWxZxWceWQz+t?=
 =?us-ascii?Q?Qno59PM0NC5fruFfh5nKLGZz1y3l1QBf133q8pobrgIERxhRg80Q6IkPGXFa?=
 =?us-ascii?Q?/qMiZS0HpNNeOyejAGIPyjbYcJ9voL2gKzOwoFUX/znIggRMj+Lopg6sB1uH?=
 =?us-ascii?Q?i6s5H6RyD1JxPZbVGRZBY9jTLQ/17QobPDyaQ18lme8cHo83OiyIBrZp5Onn?=
 =?us-ascii?Q?6+AfZWbkkUifey8P22kS2u9nQaZAl4yMD51K2ROxbuohJxp6aRdj3kDbn4wg?=
 =?us-ascii?Q?nt2mVMWEr3M3/yGspbV+XNQH0e7izp6K1uRV3AtgOeNPyRjpcVsmrxpyVb83?=
 =?us-ascii?Q?/1Mi6gyJDlfKlj1ogCCBfza7U7CMlhmPA1hMaZgAN5/T5HxVmz1kZ6I65nti?=
 =?us-ascii?Q?l5OefcvRMFHmy5kZZpH4A0fhs68zq5bChws3VCECumyYNHX4o4vTv5bHxy3A?=
 =?us-ascii?Q?gnhED+F7wTyKYrTFOAFyqgzHnCkvZyRAjq/wUVBmRmfCmsWOwjq4SY2hxJgx?=
 =?us-ascii?Q?lHJxgYngLE+JK/ug6h6Jmm+HAmIqiJ/Lj+x1JJB0/XFKZW2EI9I1zXx41ewT?=
 =?us-ascii?Q?e3/YTB5VMpuByOm2oNt39tQWqhgrdbk/O3UHNAkglBNWeren2DLqKS14gOKC?=
 =?us-ascii?Q?pfka6e3k6puqPLZ3GDnT/CmpK+AC4CL6fjPrfg/3mAiyUzA821BxLirSDHYS?=
 =?us-ascii?Q?zTzvjbjI5qLSrNuKrbtP3fVAoD+qALHMIkPhiDjMFa9RJ6Xf908CJTNAKsDA?=
 =?us-ascii?Q?7JnMesgWDR/OnZuO6WxvfuN0irKRIl4N5RtMosoS+f2tKxwrOKlOH4ivjUr6?=
 =?us-ascii?Q?KA2cDW3b8sOknVh2UxeUfeRoNbbSKpJOSgoJNqcS7Z6n6KTDcPSa2Yj4X3LR?=
 =?us-ascii?Q?fw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: PcJTQIXDjFHM7tl3hxl6k4aoARcQOSgXZcnh8TRfz1g0azc238S1Z3t8uv126GMNwK0X8SGCmWsCg8jGY+TWNwc/uMyuWPWzlRlnlM7FrNCckAvgzipj2geAwUcbLr2KhRDteP9PTt7kcPLvDFuKNSdjMX6AKic2nipLRsMwEavD8PKsUNuP+BD5QIfc/OHzgRsa/TZFou11/GyshrFosEfDFLd4ImNp3Lbfihwq8IR8LfN90yOvxQyVnJ6DIX+8a72TOIE5iYxKz58PK/D7dORI3Dh35YEISQKAABEC0MXmM8G+BNR10ZbkwzFj7kPK7aUZqHyZz9uwFSLr4W9HXbNHWPq64WTaH+u+eNus3NMzP8CNoihiQJECekF4NibVoatz4E60Crm0N3EZGNYmc3+zoqnP06tpb7YqwmDdVgebIEu3W64K5+k2blADsMOKCy66VDoJvhyuBYqd3irFr2LZCe7rguX5B6rEfveqWNloJDaaQYMJ7Tl5POUHMRm0WzOtRypWYfI9o0SIEb4/i0cS/oXwW4HMudfwIbrZkYGPgta5TLaITwHKv+5nOKu63WTbclVM9gRxbQbZKX5vzAH4Vyv6iPYsCti1GjDP1bs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2d0d344c-51e5-4236-23f7-08de0fd1e01d
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:12:02.0958
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: J7ClpnrAZuW7IzRBDQ7mj0P1owAf9UFVk72vm+VrEIz9hHFqGhredNkK2fnhj18M0N19kGIZQb3/WSIdk+59wWSE4lKN6SON+tJM0Wb6oGA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 mlxlogscore=999 bulkscore=0 malwarescore=0 mlxscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-GUID: RUGEhq87N60b7YOxJM7p9t0iPCD0rg4b
X-Proofpoint-ORIG-GUID: RUGEhq87N60b7YOxJM7p9t0iPCD0rg4b
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMyBTYWx0ZWRfX+IoMew82B3ae
 qcM+NVGj148HIY0duol5rY+//xfInVomMVDDgkBwEPZIRqFBiCQCnQk1l4uf1NSDZA/u++pF1F9
 k8uaio1F6ON0VJV8oy5HWTMITnJkoXIqhN1upTqvzpN2nohvdtF7ZG26fVCu3ZIexLR5DgFJIuE
 UyCseMG+6OUltExieCiy489D1BOymgHeR7a57TdHfdSNcxUtl6bx07wLqglQ9BAgFMXmMRKxM4+
 svUWXo1hsNQIKXg17OqdtIFC3k591X/n+mZNDJ2H6dUVia26WtP/gp6wv3ZxV5i40ExBq1GBHUx
 cDM92qWvtY5hVgcH0F81piR2Kz/KCUdD+SvzGQ8I3VbhAXd8TZfikii4VqCRRpqPeFYc9twqU+9
 1mSz5r2mQkGJwJWJSIhmDwqx4mSACi2RiLdtaSBUkAyaGVm9vPU=
X-Authority-Analysis: v=2.4 cv=Nu7cssdJ c=1 sm=1 tr=0 ts=68f6271c b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8
 a=CxsoVSIMbwK9moDqu60A:9 cc=ntf awl=host:12092
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=DFLB0HIP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=k9TOFhEB;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Now we have introduced the ability to specify that actions should be taken
after a VMA is established via the vm_area_desc->action field as specified
in mmap_prepare, update both the VFS documentation and the porting guide
to describe this.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jan Kara <jack@suse.cz>
---
 Documentation/filesystems/porting.rst | 5 +++++
 Documentation/filesystems/vfs.rst     | 4 ++++
 2 files changed, 9 insertions(+)

diff --git a/Documentation/filesystems/porting.rst b/Documentation/filesystems/porting.rst
index 7233b04668fc..b7ddf89103c7 100644
--- a/Documentation/filesystems/porting.rst
+++ b/Documentation/filesystems/porting.rst
@@ -1286,6 +1286,11 @@ The vm_area_desc provides the minimum required information for a filesystem
 to initialise state upon memory mapping of a file-backed region, and output
 parameters for the file system to set this state.
 
+In nearly all cases, this is all that is required for a filesystem. However, if
+a filesystem needs to perform an operation such a pre-population of page tables,
+then that action can be specified in the vm_area_desc->action field, which can
+be configured using the mmap_action_*() helpers.
+
 ---
 
 **mandatory**
diff --git a/Documentation/filesystems/vfs.rst b/Documentation/filesystems/vfs.rst
index 4f13b01e42eb..670ba66b60e4 100644
--- a/Documentation/filesystems/vfs.rst
+++ b/Documentation/filesystems/vfs.rst
@@ -1213,6 +1213,10 @@ otherwise noted.
 	file-backed memory mapping, most notably establishing relevant
 	private state and VMA callbacks.
 
+	If further action such as pre-population of page tables is required,
+	this can be specified by the vm_area_desc->action field and related
+	parameters.
+
 Note that the file operations are implemented by the specific
 filesystem in which the inode resides.  When opening a device node
 (character or block special) most filesystems will call special
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/472ce3da7662ed1065cc299d14bffb70b1a845e7.1760959442.git.lorenzo.stoakes%40oracle.com.
