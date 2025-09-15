Return-Path: <kasan-dev+bncBD6LBUWO5UMBBKWWUDDAMGQEOPWHBRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id AAEAFB57FDA
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 17:05:16 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-24458345f5dsf51600655ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 08:05:16 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757948715; cv=pass;
        d=google.com; s=arc-20240605;
        b=WZ+XBWu4t7fVPDWGIeKq0SAwzQ9Lk0xH0PSJXQjaEo7S37wEwQHnTL2LKiuNX52+AQ
         n75c/zG/KnU/o8LDH2zad6k3wzLp6lrBqTagd7NgulNWjivgUQa8Wu9sMdLvCxIMY8n5
         k/2Knu8pHBNyHcA3zU/Mb88atLqoo6yn7rkFRDQuU7CcAPX/v2RPeYaA5qQMgI0TCqYy
         kK/Ser0b5vBkCtmNAkgezVB+/X9K7m7aZZW6wYg875tZB8FL/ZmGgO4J3Z1Mmud23Ze+
         npBf0u+4kwVmO4FZ+w/ArU9yA9vdFTcqtAoTvP4u5xJXDG4LidV7yyM5l8djPo1ERVbW
         Kctg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JxMiQaDBDM8rbflhtvDeb3XSD7DTrDo9CX1VBuUo6cc=;
        fh=xW07Tz7xOy2RbrbzzP8SI2ypqsoNVWJWEAkOjmAngvo=;
        b=ZqP6gLkbIuhBKMS0WCP7Gif1Y6QjBPyY6n7RlGBDav89ntootb78qafcllmW0cnfWb
         VrJ9lKzlQ+vonN3jbv+z/Qqs5tYgU3f0Co2orDmBEW0KCkD3RDWy2OdZWK4RQOVJskij
         zhQchCRtZmfcvbOczy1tq2Zgc8fUWo0rdtF0SaKateluK/TeqI7jhznLheNQ0lvyxx47
         DlYr57Tiwr7Nx1VGSVLmDfUs3h2bqfo8xnoi/X/lhU37eZhiH7+m3EKd36cLChXEN9GK
         gjN+riw8DS8GbZhSajCQZkLicQl0nHIitOwOT0lg7dYCn32Tm2G+6q8gg+0S/JiyWCKc
         vn6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Sn77ifHc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZNJyof1r;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757948715; x=1758553515; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JxMiQaDBDM8rbflhtvDeb3XSD7DTrDo9CX1VBuUo6cc=;
        b=dPLDG0nlFR1udbEqXn7JQRWY00ATANTjKQ4I/Bt9C2GEiozPY0HWKzsl7kmVz0Qh+3
         oCVS9VQ4E7eVRS2LfJaNVHiJHbl3LMzihjqTo1Zcbo81OFHLkR4pZH8U8RD1PCDiAV88
         v4pP5BkPH9ddg+gtPVn0GkI9J+7DT6uuifgg6Z2pZMr5tzbfq713juyJFIe+wxvIFpL5
         P8aJXXmh49C2Nh8tzZ7X2+4iShSNOtNF3TPzNtZ2RGVdLEjkU6P6Sl2DCoR0H86buCx2
         shAfUCa9aBQDj6SIliYw2T9XRAawce72H/xOnBWH+t/kJO149xeYGeSxGjOXtkmoc5qk
         +lbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757948715; x=1758553515;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JxMiQaDBDM8rbflhtvDeb3XSD7DTrDo9CX1VBuUo6cc=;
        b=v3mHIrn/hzM7mcUq0dnU0tH1oBgPjsZnBmyx7PNXa2zDRI0xIr9ghGMGwMxJSc4H+n
         FH8Dh6RSgPFM2Y/7zTSWRWfghvWzf+1rYcisCS1khCK60jY5Px/VJED9SM1HiNnJ56NR
         3BBbNMiZFU5S5DwCAQWVExZLzvHvNRnQKY0n1RxVC36RuPHuPe1qM8XRDNV/3+uWdZQc
         4sihTn7rce5K8zoQBC6RrP7RLncsM6gddlKOI4vapnwmwzD91YzMEGA0iWFBTKIi5S9n
         CXZWT9h58o0FtMa3yM401awKe5y2btt7ePSkqP7MnfPcYiTGnhz+qjVrHFnKmYvaR2Eq
         ac8g==
X-Forwarded-Encrypted: i=3; AJvYcCV+q7fd6jDADPhFJmLD/YLlnBh9E+kVv5HIa4OBl+WjIOxCg1QxydhGrmk15oWaxNMruhlsuQ==@lfdr.de
X-Gm-Message-State: AOJu0YzqSCxJXIHthTygp4ByIE8DHcsBsCX2udRRulC8ceWvJ/gY+74a
	k04rhxrlTsYQjFLgbXHt4V7Ykpt6GysN5niXFSSH7sIIzOpwQlnRaoYI
X-Google-Smtp-Source: AGHT+IHd/z5ZWgsndxBvsqGyWhwaoFv8PVLigIdBzGtPPS+mZlrVJUowlDoTDLinIDfkF8KvSgTeug==
X-Received: by 2002:a17:902:f54f:b0:24a:a6c8:d6c4 with SMTP id d9443c01a7336-25d24f95c4fmr138906355ad.26.1757948714806;
        Mon, 15 Sep 2025 08:05:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6GueCNz2HreBsCOJU4BwQx3nDKhE1wcf7zvRH582JGDg==
Received: by 2002:a17:903:b07:b0:267:9e78:a8ae with SMTP id
 d9443c01a7336-2679e78add0ls7067295ad.2.-pod-prod-04-us; Mon, 15 Sep 2025
 08:05:13 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUGGGVUpPod+CGnPwytS8BywPRUBjKJ5hbSYVYnvP3WcDe0DU3Gb3ZKNsIy/c201IHIyg2w/utZEY0=@googlegroups.com
X-Received: by 2002:a17:903:189:b0:267:b694:3a31 with SMTP id d9443c01a7336-267b6943efbmr12250675ad.55.1757948713158;
        Mon, 15 Sep 2025 08:05:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757948713; cv=pass;
        d=google.com; s=arc-20240605;
        b=dHLFtvoi5wmJGG+st+guPp5kOy9qTeDmFCuHawTdxKNfL7zNiwSBg+yiFix29wFtTS
         HLrUmJc1FZSFdyd1Lv+osvuB37IiOfc+n6HAM6NtlPmC6QZW6k7WK8gekuW1xoTCfo5h
         OxjhA5RbhqRPAWfJ22AjMGknX0AgjoTSIiDJF7SWw+SMSYt2wJDR9VNFDj8Y4nJPrOSp
         j2ayX5/u8glQfz8b5lagLeCkAaZtl3zM71ulbGV5oVEPZCpTz3TLU87wuFH+Z+9f5M4G
         tUVm9KyMmOWH3PWk5mk9OW/wrDukYXfcALvAXw7vB8pYCEKvRjZyJbrBrcoHznpyKe2E
         D0jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=9zi855moYw2KbC3ZX0OCjYwrIf9mR21txiFBMDTcDv0=;
        fh=COpyHq0QOxjKsBdfUS899OYJ1UCzIDxqgKDArEZBC7Y=;
        b=Tr9TDSzrGlsc6KOPwRPbb3LFUh0ztwGOt5iIJg0BFdSIwLifVZrxDfc3vlMMk0dzrd
         nSt+1Z0BrXT7fZOAU1+MwVLrtCbUmxvz8xLyFXkdUxBDUHdT10qtfPcr0q9FbaWN5LWY
         Xf0TPDmXK0E9PUiegjQ9rwBtwMCDEZPBk7uwjbaOO8S1ny7RojVrGGUMcYJrJNcXl9K+
         HT7Jf22B2lSNcoLwrKMjwYlkPyy/7Z/7MU3VXnN2s6hDaxFdNLNlW39AYDMmD7mQzIi2
         1htLjA1z6BOsecqc46hWZwRDQ6bpla8WGxfpox+YYPv4HSW4NSDyVui6BxF+3koIYE1t
         B87w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Sn77ifHc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ZNJyof1r;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25f31869f46si2588185ad.5.2025.09.15.08.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Sep 2025 08:05:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58FENDnx002903;
	Mon, 15 Sep 2025 15:05:12 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 494yd8jmkd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 15:05:12 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58FE42iW015298;
	Mon, 15 Sep 2025 15:05:11 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011056.outbound.protection.outlook.com [52.101.62.56])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2he78s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Sep 2025 15:05:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PfMzvZd8XodgwW3KBh5w8g0Us5Vq8WVLzT8VZjqtUpoAKuFHBz6Lx1xG1J56V1skLVB996qtAfxQoc2Q2HJaOrifaNasLI+qn254UeQFs9ZPKtYnt/mbz5rrJ2jfN3NMqfmTxjsV98HnLKNTrEkxqdN8O3pa747tA9C8R91R6zf1HVZ9LRC7+BxwVc0Yy/Ao2FhXOC3tOtCW0MKlbZYi2s328BQHXEoBk9cF5CBDy+8XW2BpmapmDE/heHEBBRW2qU3Y3znkV6xFfUg12/L0dlH5nRJ8FmIF5J4pm05GpwRT3CBmehnZZst/M7qhW1QK8alXIsocmY+pOXUuJ/Bc7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9zi855moYw2KbC3ZX0OCjYwrIf9mR21txiFBMDTcDv0=;
 b=W7nS/5Wbp3DwnfVdj7+I16rlXCPAYPbffAf5coxEjJsdjmYghNygURQkJxnf4GAAdYOoikht4/KarK3kfwqy2yVnfvFlmjhkKriJ7sej/7LWV/InKx99+cNBoKBt6Qhbrm8Xxk1FMweuP3wKK2QQGffZpNWz3wrXd8Ln6aYiXTr93DN2znWZ1W9+dSzLTwwozCwmMyRzN7k6g805b/6ZJbaEclYzruxQNyWIgcWLDAfEkb5sGOTYbUHMiNfPvifLSatt24YhzZjHDwkAPpxJvYGY/hQ+CRP7wCluZ1eALWZh++iOdVgtqt0xf9FCXc6FaFFGFGLNcACIi7KtUTi7WA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS0PR10MB7430.namprd10.prod.outlook.com (2603:10b6:8:15b::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Mon, 15 Sep
 2025 15:04:47 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 15:04:47 +0000
Date: Mon, 15 Sep 2025 16:04:44 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
        kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <3c968a23-cf25-4b95-bb44-f7cdfd47c964@lucifer.local>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
 <20250915124259.GF1024672@nvidia.com>
 <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
 <20250915131142.GI1024672@nvidia.com>
 <c9c576db-a8d6-4a69-a7f6-2de4ab11390b@lucifer.local>
 <20250915143414.GJ1024672@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250915143414.GJ1024672@nvidia.com>
X-ClientProxiedBy: LO4P123CA0526.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:2c5::12) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS0PR10MB7430:EE_
X-MS-Office365-Filtering-Correlation-Id: df62b800-e704-4760-dfb9-08ddf46935e1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?YpZ4FA9Tu9aRn9wxD1uu+x/6JA8Unni8i/1eX+zZ0KzCaO2U85NVrHOdAQze?=
 =?us-ascii?Q?ua/mR2LvwgC0VRIh6SaFk/YrigVU9krt/jExgR7ARSTqSnoBF1tfL/IdGUMT?=
 =?us-ascii?Q?PKH3K2FF62erzrEQNWwb5KHBOAlb+Aw+NOFfBO4DeF0R5MJAHkC5M3dQBx4R?=
 =?us-ascii?Q?XixKogvhnWLweY8mkNwN11aM8DlVTOTevUiHluRCn7ACrQhii6x5+24EbRsc?=
 =?us-ascii?Q?bryD7fmv5SuWC6xMjPZ1toUTB4JBUEQTpPuVqyanJVBu7O3sSImyJwvk3CKv?=
 =?us-ascii?Q?leFMq2IjA6P8YODcNtMEMHqoAh9NQsb5KTZ8eQJFYNrbVopSPMOTJs/bzTou?=
 =?us-ascii?Q?nL7dkiZoCcx2SMhW0vaEclFuWzm0bv4j3LdnEAwyn1s5Ps0STlIc3lfDW9Q7?=
 =?us-ascii?Q?mqH7gewh5/BFIc8gsis+TsAv5uaMszA99A+WfrBa2g4d99zXbNLsr31k4jFF?=
 =?us-ascii?Q?hT6RRkXKNhik8NOrNpVBKpjfhzr49dypVwg2TWZX8nYMcZLuZrJrjPWwkTQ6?=
 =?us-ascii?Q?m//rijDO2/38abTpxpzDQn6CC91fa4IeujZQDGAMxq+EphCl7xsmMRLiZ5ee?=
 =?us-ascii?Q?tkiUW54jFKnDqGWs4/ympd+APAkoyqk14okQtzB08r21ggQkVVEpgu0Aa2Ou?=
 =?us-ascii?Q?59Js01AAoWTWzch8ICOwRxLWcNrWAOY8YnzGRrjyxQC2EE0NdH8Zyld50R6P?=
 =?us-ascii?Q?SO1dPThbYtmFhsJsKvCZIoTWzXbXPstI8kCfHe25oAIVXbcZwWiUIJDDboST?=
 =?us-ascii?Q?8h7pAVttv9JMJ7e2LOlPmHSxXOMwPPyxr0o1rZUoEn2N9j9zAkEJkJ02hOCM?=
 =?us-ascii?Q?etDjUoDA1cPEI9EJODdjAdeenR6NugZUd4NG99z4ddQKzK7r0fJ2aA+CE3UQ?=
 =?us-ascii?Q?6CbT65aJvy8QzVu7Oo+8P2gscGcBJ8CKAzQW/M4LEoKfZ6qYGbkM0ly13apB?=
 =?us-ascii?Q?OjUEAHG8k7+O4XwEJvDBaJ0q4YfcNIA3P455/NHLrAC20F9JiS2bM7V3h0fe?=
 =?us-ascii?Q?/Y9f8II0+TYR9DVsxyYh7k3fv3JglnbwCy28KD5VQPf/BFi83E37RBdE47+o?=
 =?us-ascii?Q?jClK51YAlOtRtJiNwYRhaqgzB2Wg7ajNyFxJQEFSpnI6ocrP38ZJnpJvJ88U?=
 =?us-ascii?Q?FAxnxsEYYqUabEAiNrCY8ViWUsnZfTkns4CZM5xHNtJLYU4+tPiZvRc+6VUW?=
 =?us-ascii?Q?HfopLmIEnEsjfOlY5fTNkWpTPkK9r5ECT7taCuhkG/neSoZzbpcZUi+tFv3D?=
 =?us-ascii?Q?F4nNuDTs0oSLZNz8pnjNQPtg/+t/HVebDtK9jQ3EezhsS0fSiwfJUwFtHhpN?=
 =?us-ascii?Q?MIAvcYXR5jB7JyZppbLc2mAXPsAqZ9KnUR7/Xsqw2bt9R6gmEXTjzyJIQlaN?=
 =?us-ascii?Q?489wzxO7vZciUbu6QaIXxbDiLsCflg9Xd8bxVhgyxFCLPYOTDS3NOLpP2BkT?=
 =?us-ascii?Q?oYtesUFR0s4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?qyIZAj5xz/8d3bystBZevVhTWIq3lS8NkSAahae9kc4xpk669KOQtTNVNDUo?=
 =?us-ascii?Q?CAGCUHm5k/hKwt//sXhXh1bNLrUc8rA+fKyXLTlnYptBdRMmxunF7Bjm6ZpP?=
 =?us-ascii?Q?OlwXLhdnPlZm4l9QRs6h2YRWbKVWLUJnK31R9V416Oi1yk1ezXenyqGSYAe6?=
 =?us-ascii?Q?5jtWFCUpJGdp0EALs9Tkl27ZBzvMaTXGAfaUEZhAcR3/LTpopXJDzTwEgmD0?=
 =?us-ascii?Q?6l8ylT5NxqyQaXz6+z/2DvEmnP3St8Eee+VJXJNrRmfzAiwcumcUkp3rb6yg?=
 =?us-ascii?Q?dxLLv9Pk9VSmdmSsNzg48R/6NhOjveK7+S+2TqPeEqIQLtjgk4wrznymCsza?=
 =?us-ascii?Q?WVmCwJ5UrU8OilvVH1jUUGCV0pZSSYpTvoJ/1nKS03EQG6UXuruxbnz0Q+wi?=
 =?us-ascii?Q?9DzhXYo1uEdCsd+aKYHUmFiI+dbeHKroLgsLEro7Rk/rjy93Orgvxrhm8x5t?=
 =?us-ascii?Q?Rk/vZcvI9gKCDobZpmifoxH3tNNKP7DfFei+llxPg7rPMe8unvKlIpILAtUx?=
 =?us-ascii?Q?1W7uu7bQPEWiM0X1wNd0T/4alupTUdMe2G+B2z3XuFI81aOlfWKDSq3c26ER?=
 =?us-ascii?Q?XM4P4YXjZu6AOYYw01QXUp51vtjUtydS5DzOmSTdIb4BjczD4kg6G9KHjJhh?=
 =?us-ascii?Q?+P6kmfAC7A2nK6NJpxPZCAdRscpt4cPrfcvg5WJYrQQifKjAehsIm+gNz1RB?=
 =?us-ascii?Q?idKDnDGhwxyJ6PU6rDWYtwjwDlRnXMCWKtOf4PboNR6dNDqnFPJUybtwA9BR?=
 =?us-ascii?Q?InPe8Utbpv07gYIKaD2jnhKWqaaF7GpePROjGb7SakH/nqhNA+06jv5pKl4u?=
 =?us-ascii?Q?Yplfu6yUIZ6D+qa/ViDKfqYg1Di4gvKz2SBp6LUKgYROnX35vvo8MgUN83Fv?=
 =?us-ascii?Q?HdXkIRtPlVdJmGCI5Nd4XPA5AWRy44Ki1V2i+5RYZJrMTznh5MPRFXH8ypsG?=
 =?us-ascii?Q?wZ6I6cX5tGVNXNAQCpyFfPJ3DFDB5EbB/amuUz77y7f0oi6L+FnF4M6ZkOQ+?=
 =?us-ascii?Q?3SF41gQ4FhcULsy+rmAF8tlbD6/x7slJwdK30+Y3PKMRht9aSbhzAOzjQ2Zm?=
 =?us-ascii?Q?3RKbm4GQSA118pVuqzGov2FMCa9TWwWSjbRaTRKH2aAo4hkj+2pRNGVFmhm/?=
 =?us-ascii?Q?qfp+9ba07f2aFFTJjkFZthD6ODppudZIDbyJzLjWMJMEsvlL2A70R9EWKZO0?=
 =?us-ascii?Q?VyOUd+7zZVDFQj2IParSz5ZsO1HBISW3Jkm3z2ytH9pQF7sswVm+KdfDowz9?=
 =?us-ascii?Q?JjUGL7Cq60KO5h5ZmuDOH33WHGFZmRCfZ+DReq+ytbQAz2FJcFgofcM61pNw?=
 =?us-ascii?Q?acmJhfW9dxM/ltCWk0+dJ2BvBZFqXuX9jIHXQAewkt7Ip7LPeAUDNxDhrvHC?=
 =?us-ascii?Q?j0+oVPzaEY99rYFW5jR9zhG6rRm98HFJ6GQtL4UjwCFVCz0tEjaaww/VjfpN?=
 =?us-ascii?Q?h/zeLxWfD/qEKOFq4F3gWAA9bJBohu6cfAz74LZVShfy5+5/cch3EXKhCw+A?=
 =?us-ascii?Q?8JqPEfb17OwvEVtwQ7R6HO331WazHTT1pjMoFf8DzlI1juKOo0BS230mO8YK?=
 =?us-ascii?Q?y+tAE0iCI6if4MGVIjrgnnkw8/peWiDW2jmQrjMCYJrcptQJe77meSaeXfA+?=
 =?us-ascii?Q?rw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: RdSHP8JynCFQSzEXbIa8F6Pxqi/bRRo1nrHQSoa+Y8KBeV8L7w6PUS3Z6zez9tAwvjeUvWl+ojVBvp05IffMJvyHAHely+ERClaUXGmMrwQ8amvQP2esdf8HqwRXmAT0BFJlKxF8+IN+aOGrZGzw3WWB5kqzkJpMBXKBLFtkLK2hJJERyJe6N7HoS4wzWVV5kvOi7g7djA/17ccieB+orv49pBaPXKRxAF/OEP/chdc5S0tqFby4dGYFvjB+DM6x9Q5//u4dzZ++2labwG6jYWH16hOpEmTvqe8CCKZleX5uOuroc3PBx35mPxPDo2hr3vhAh/kQ6Kbyt2Bw3yBPDrAMoEmSEFjZIZtADEGgeWjvlaR+F45FNHiqyNIH6DKWsYByzKdCEZ1so3Kf69fxdyDq6aTEbBjPnc1BivNOKvmeHfoMmPtdPhrehxE4dUBz7eTSC4qgRyIz8LJbMgFMooBnDelmxGJgDPA0eYO+atl8TOHxnEGjK+T2s/v9Kps5h/RQoPpF5d8XSFm50Lqbh73LrXzK0Gh9LNc7qq9lbPOo6QGtIRzv5oY5GCugsyvljv99d8JaCdS8Bwl2RsLgHv2ZTa4IFbwizBl0q/r2KV4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: df62b800-e704-4760-dfb9-08ddf46935e1
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 15:04:47.1148
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lzQr/RfVA8jKjcnFLpbkEa+T35n8j3u5Fc9VyF9xRK3nrVm+JQARrJJcH8/GhnXnLXJPtoaEqKvEy1i9n6hh5ktDES0ojZ44SATAKRJU1VA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR10MB7430
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-15_06,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 adultscore=0 bulkscore=0 suspectscore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509150143
X-Proofpoint-GUID: rwpz90gH9gpO-vPHaEwOzKMsNzzfT-5w
X-Authority-Analysis: v=2.4 cv=M5RNKzws c=1 sm=1 tr=0 ts=68c82b28 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=xsfo4qHKq2V8f6MN6hQA:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13614
X-Proofpoint-ORIG-GUID: rwpz90gH9gpO-vPHaEwOzKMsNzzfT-5w
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAxNiBTYWx0ZWRfXxj+6t5m4f4Ry
 XBKxLP1V4Cb03q/yNJKN87x7ZzinEj+5656I2+uN5Tk4jYDM/zkqUDuw7CuXIsV6xMlGr4+HuzG
 +ByWxCo1aL4NVu/iSiuOcguwee9p7WBnCKT8i8S5MMehsLvCuKWfXLqPRI1oT1hCQwG9BQVerWK
 /WugM8UHl5H24KDZQ+Rcx4U76iVYRPHrjv0ss1KbR7kMS0i3IdQkcTmrRW8ncfDwQb0T/bqo6U+
 j3np6f6WIrmacjyliVBfgzFlL+MAkfXWMSpVIBtSjQ/9Z/zyYq2qmPxle9NuEepdYJYvl02S04F
 A6qrp22duFMbhzmlo9dUyZs9qxo6ka5BeIDgtnRXQGtfdqfPucVtS2K7FSZHGFVjWxJ8NyNZ5Z/
 WfCxrNPEyI4+bdXKF70YFxQHlY7tuw==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Sn77ifHc;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ZNJyof1r;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 15, 2025 at 11:34:14AM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 15, 2025 at 02:51:52PM +0100, Lorenzo Stoakes wrote:
> > > vmcore is a true MIXEDMAP, it isn't doing two actions. These mixedmap
> > > helpers just aren't good for what mixedmap needs.. Mixed map need a
> > > list of physical pfns with a bit indicating if they are "special" or
> > > not. If you do it with a callback or a kmalloc allocation it doesn't
> > > matter.
> >
> > Well it's a mix of actions to accomodate PFNs and normal pages as
> > implemented via a custom hook that can invoke each.
>
> No it's not a mix of actions. The mixedmap helpers are just
> wrong for actual mixedmap usage:
>
> +static inline void mmap_action_remap(struct mmap_action *action,
> +		unsigned long addr, unsigned long pfn, unsigned long size,
> +		pgprot_t pgprot)
> +
> +static inline void mmap_action_mixedmap(struct mmap_action *action,
> +		unsigned long addr, unsigned long pfn, unsigned long num_pages)
>
> Mixed map is a list of PFNs and a flag if the PFN is special or
> not. That's what makes mixed map different from the other mapping
> cases.
>
> One action per VMA, and mixed map is handled by supporting the above
> lis tin some way.

I don't think any of the above is really useful for me to respond to, I
think you've misunderstood what I'm saying, but it doesn't really matter
because I agree that the interface you propose is better for mixed map.

>
> > > I think this series should drop the mixedmem stuff, it is the most
> > > complicated action type. A vmalloc_user action is better for kcov.
> >
> > Fine, I mean if we could find a way to explicitly just give a list of stuff
> > to map that'd be _great_ vs. having a custom hook.
>
> You already proposed to allocate memory to hold an array, I suggested
> to have a per-range callback. Either could work as an API for
> mixedmap.

Again, I think you've misunderstood me, but it's moot, because I agree,
this kind of interface is better.

>
> > So maybe I should drop the vmalloc_user() bits too and make this a
> > remap-only change...
>
> Sure
>
> > But I don't want to tackle _all_ remap cases here.
>
> Due 4-5 or something to show the API is working. Things like my remark
> to have a better helper that does whole-vma only should show up more
> clearly with a few more conversions.

I was trying to limit to mm or mm-adjacent as per the cover letter.

But sure I will do that.

>
> It is generally a good idea when doing these reworks to look across

It's not a rework :) cover letter describes why I'm doing this.

> all the use cases patterns and try to simplify them. This is why a
> series per pattern is a good idea because you are saying you found a
> pattern, and here are N examples of the pattern to prove it.
>
> Eg if a huge number of drivers are just mmaping a linear range of
> memory with a fixed pgoff then a helper to support exactly that
> pattern with minimal driver code should be developed.

Fine in spirit, let's be pragmatic also though.

Again this isn't a refactoring exercise. But I agree we should try to get
the API right as best we can.

>
> Like below, apparently vmalloc_user() is already a pattern and already
> has a simplifying safe helper.
>
> > Anyway maybe if I simplify there's still a shot at this landing in time...
>
> Simplify is always good to help things get merged :)

Yup :)

>
> > > Eg there are not that many places calling vmalloc_user(), a single
> > > series could convert alot of them.
> > >
> > > If you did it this way we'd discover that there are already
> > > helpers for vmalloc_user():
> > >
> > > 	return remap_vmalloc_range(vma, mdev_state->memblk, 0);
> > >
> > > And kcov looks buggy to not be using it already. The above gets the
> > > VMA type right and doesn't force mixedmap :)
> >
> > Right, I mean maybe.
>
> Maybe send out a single patch to change kcov to remap_vmalloc_range()
> for this cycle? Answer the maybe?

Sure I can probably do that.

The question is time and, because most of my days are full of review as per
my self-inflicted^W -selected role as a maintainer.

This series will be the priority obviously :)

>
> Jason

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3c968a23-cf25-4b95-bb44-f7cdfd47c964%40lucifer.local.
