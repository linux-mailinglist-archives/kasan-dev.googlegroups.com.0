Return-Path: <kasan-dev+bncBD6LBUWO5UMBBH7D77CQMGQEQGCMO7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id DB054B4A774
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:21:36 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-8186ffbcd7csf67573385a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:21:36 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757409695; cv=pass;
        d=google.com; s=arc-20240605;
        b=Te6+9qHhzxE9upcvzqQLJ/QccMzow0IRFvhUyTFZhJtilgQZYlXwGXsx1PMFEXawxr
         YR4B6sBvK8Xe5BL+Hyczk9Vt0oo8ftmB2aKPlDqk0TnPfF3W9tUGeYjE+Sxga4OEj9YR
         L6zho4Ky6dx7vhu5MUXEoY8D5RFdvpJnV/xWasMElYSC5tYJD1NxubYdEEzox9XEb84g
         5LztURhIECmzW8U0eLGOGPBnIKjzqZ7107WvJdAqRgZRJSARYKdMW6CPzFmmOJsZqG+H
         ztSr5qwYgHcoNtuxGKDsqz8iiiQY7Gd3gDtj+fVbYTrVEWdqlX8BIiuAFasrPnu3ikoq
         LE3g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=B5jRv8QWTPj4CGK08pl8GijVfTxU1PzY77XDB1e8E3g=;
        fh=S4dDxA+STDXyQPDVf+8XCx3Rw4I2+EGA3WEThhh3ySQ=;
        b=gpdWYiOR/6mhzLf3qaIinRO2V4SpoyNI39+9CJ9ID2qyzT4TaqI4i/IkZb6I6nVVWJ
         zDS2dte9eyUl22fG16GORHev3jG4/eKFH4ag/FX9ycfyNEmRu/q6AH8jOG6aRSu0AD3l
         uy0f0C/KvX/Iqv0H1uSs2Ho5q0DgNFE9YQVKx4vjsUXj45VX9ja/O0ingY9YLgtOqkr0
         d9stzI6mlo1ewvAWppXBme8K4MV118BBLP+iWxnygItJnU+NzYV4JyxXh8lR0AJhhW98
         vuu0yYgdSSWFGo6+bkmZpxFDbY9TxR5wbso37q3hnqGMix8qdEpkdG2JMIEibCWED8Qm
         ih5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="rJoxywO/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HIT3+zuI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757409695; x=1758014495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=B5jRv8QWTPj4CGK08pl8GijVfTxU1PzY77XDB1e8E3g=;
        b=lfRYfdenKvQOhR4rnu2h79P/Dpm10/x9B13zAsoYv5IBMdCM/I73JCFuEvxTf9IKvh
         g9MCgJ2r2aj1LvvQj70DelANyOZ99XwQVBcQzr56i+Yln0g57zZJ+0qiXYmoxhRx5fim
         MGU0tLmJa8ZiOLcHf+F3Wzo6rdwFyNZBbnBzffRYylJZ/1T/ZuKRNcl1r2lt2uMcyjEP
         CtqGVNdwVYWHLM6oFqdzfL0h8rzzUHOWMaYbmAFcvgtq/TsxVxcLr1njzh1aZlCEkoHL
         69Tbo447u4m6/Msk20M/xALC+imQz7nHQNrtKGmaekIPXapdGBNGZEheXNgS47U/ti29
         juag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757409695; x=1758014495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B5jRv8QWTPj4CGK08pl8GijVfTxU1PzY77XDB1e8E3g=;
        b=S+AS1AahR0CLgmBH16XiVd3yq8QEWE/rH1LfWTKVmCX+AyvsUCMwoqr/hj9lJnR6If
         ZWtGL8cM6j0FsxiAqwf4zm8QEPhbuIibU6BFP6VumzfJBKpbUUTTBOm4cCKNByrd0/ia
         6lqXW65DJS2w59N3pg70EtOzfOtVsd7LkUOhjkLWeVYuEy15vqI+OAYLh+ga332GW/yz
         8SRqmtuln8oSHkdVdu0gkObgqeT+xoNcYescQKvkNcoDIAWZKS32UhR/i6vCmA+G9DVZ
         ZfsdoA4f6nrQpG0eKxKS0dg3FvgQAT/gSPKOGNCqwC/9tsGajQgTUjQvxZjUQQBGeN8U
         Ijcg==
X-Forwarded-Encrypted: i=3; AJvYcCXmqiYgH6K/r6ctVRpCXts3G33vKLT8jwv6UPbBlIfmgdwIcisHs/A5edYDLwILIBVWp1ZVbQ==@lfdr.de
X-Gm-Message-State: AOJu0YwTcPxkrtUml/8ipaq47ZlSSmJqebeuNn7O6cEQmz17xTb/lnyR
	xsVa4M337L/hlDlT7ABEsrwFwrV1TaGYSaN9A284xzGqPbsl9mxn4chi
X-Google-Smtp-Source: AGHT+IHGriWjFV3yZ3j8pIvJdxCW0YQ68bOUgmtLKET06VL8UkitbWyqZtSdOLg40gGEZsVu+Sv2MA==
X-Received: by 2002:a05:622a:1787:b0:4b3:4590:ab6d with SMTP id d75a77b69052e-4b5f848d05bmr75623261cf.7.1757409695344;
        Tue, 09 Sep 2025 02:21:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcqot7CaBtBG5Jy2W97sPWSpACGgNpKxbRI4H1eHEaFSA==
Received: by 2002:a05:622a:10d:b0:4b0:96d1:cd63 with SMTP id
 d75a77b69052e-4b5ea99cda0ls63901201cf.2.-pod-prod-08-us; Tue, 09 Sep 2025
 02:21:34 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWqt4n/RuMP9Q0+DBh2ipievmVnz6iaF92zFXloUbI5TP2qMfhfxVpNX52r0zrHYTtPj29nCmrONd8=@googlegroups.com
X-Received: by 2002:ac8:5fd1:0:b0:4b5:e8df:f21c with SMTP id d75a77b69052e-4b5f8382945mr104097221cf.30.1757409694437;
        Tue, 09 Sep 2025 02:21:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757409694; cv=pass;
        d=google.com; s=arc-20240605;
        b=DihZTPll3YqcknQPyU4sKn7JVB67ncHnHmgDPK9epMV8dmcmPsXKqGShFSwI+K5+Sl
         cKBO7Y3GI8y/p4MXocPeYNL7Z51XiIYgOF1jru6FQyyBVjc+6OTRWTu7XY+MI6nbXmHf
         FT9IG6WrA4xhHFWZHt5waJFgRW0QrHh6s45lDOr19Rix2hKr+rlPWZ5HFASmL9Yr9CTk
         ZwuOiIbqKyEEmMBzRzgdp1GXn1XvFcD3WI+cvnmHIflXWP6XB/DtbgN0mxJsIomzMYjA
         aA2fqimY0Mjh7ev4t48ou7mY6zMnJO0fbszIrk9GOd1LF49kGLo+GLX2AXVQaQKJca70
         1sww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=31gLRNrjbFDKLczjXZyUbDsvkbA0iZ5t+mBrqJdTkio=;
        fh=2af8N68QYnJpd17/7xhpiRlIgvxld8TIWYgdTT6ZNWU=;
        b=Qg1wBoKO+6pvQhk54z82Wo2bJEJRGMpqbqvJeGr3pZAmGeNMfGir+KQCKfYI+Xf3zk
         7QvZ+D/1IdbWWlmLMHgI3pfHlb/rIrkqMTLQDwmiLQNNp1eF/VgPaPgdZ5x34UUbqFBz
         XOMszID63R+iL1t/OPNacfGYlcHSWtt7SOulP/JiXSdhYsfkWjw2WIg19WB6gokZfzUL
         OVt6/fehTgD62rjj+Bfs6El3Fu+92pb3v9cx7NLVsVYCAzV8BJV1VYHhr0R4CbUPaggr
         0u+pAprE+HeygZajFQ2CnRoOUGj74rrbrtPrcWRZy0qi2IpT008CmT1ZcizYqFKbHgay
         n+yA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="rJoxywO/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=HIT3+zuI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b61b92f953si760341cf.0.2025.09.09.02.21.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:21:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5897fsVI008617;
	Tue, 9 Sep 2025 09:21:34 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4922jgseff-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:21:33 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58981Qvs002897;
	Tue, 9 Sep 2025 09:21:33 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2044.outbound.protection.outlook.com [40.107.244.44])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 490bdfv3me-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 09 Sep 2025 09:21:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QlPjvtemWHvMAlGof0t/JlJtzFfZafUPNu4HappUBEkkkQh8/eviId9/OlTuGXdK3nv7fORENh3a1JfF0pMxpQHnRpbpTV2mXLyAlwizBFf+zS702QsYYuy/aPuw31Y8lLmZIe1/1QCZxphwm0GXubWsdE/YXkR2set7kgYM5BMDO2hrh7WwqSm6FBHLxgqy6x6B+ed4haD4UeOpnFjeKTlF7Zlb2qSCcDQ7kxHoX4m2syz+CQVUkTeaBSGpABdodJ14ozc/iIwmJIPVsKyeMeIV1I2qU0BaclaYSkJni1Pl5NXr43GDGpsC/M1h6duNbwMNS7CM1Wm1o2myBHlEUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=31gLRNrjbFDKLczjXZyUbDsvkbA0iZ5t+mBrqJdTkio=;
 b=DtF5zI2LDrWBKCi9o5eExbmsLLxEkWNWNxqTPtVkG+ju+w/7Q2ncmOca8W9Qdm/TUALVZmoybBTNdbew8bW+F5PVUZttTHl8u0OoGRp6wCJ1Wy9A5EitLjeB52mjikvEFqKVFy5EAbCambTuBbpY0UyMX8BrJoJ/MzYkLshLd2r549QrsmO9VBYJ9MgoNawk5io/c5/RKXEKK++nw+HjykqaOiEG1pm3kTx/FhnZ6ggx3UkKs0AFeAiWYYxIo5gnogbYlYnTdkc2SKqumwMrbRgPVw2/k1hGLV+ZtYTfQcOTJSy4/t4MaJBKOuHhGoUbfpNQG7MuFy9GvWVhOizLpg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH0PR10MB4969.namprd10.prod.outlook.com (2603:10b6:610:c8::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 09:21:29 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 09:21:29 +0000
Date: Tue, 9 Sep 2025 10:21:25 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
        Andrew Morton <akpm@linux-foundation.org>,
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
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
Message-ID: <731db7f1-5a0a-45a3-8173-be1f19470bba@lucifer.local>
References: <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
 <20250908125101.GX616306@nvidia.com>
 <e71b7763-4a62-4709-9969-8579bdcff595@lucifer.local>
 <20250908133224.GE616306@nvidia.com>
 <090675bd-cb18-4148-967b-52cca452e07b@lucifer.local>
 <20250908142011.GK616306@nvidia.com>
 <764d413a-43a3-4be2-99c4-616cd8cd3998@lucifer.local>
 <af3695c3-836a-4418-b18d-96d8ae122f25@redhat.com>
 <d47b68a2-9376-425c-86ce-0a3746819f38@lucifer.local>
 <92def589-a76f-4360-8861-6bc9f94c1987@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <92def589-a76f-4360-8861-6bc9f94c1987@redhat.com>
X-ClientProxiedBy: AS4P190CA0038.EURP190.PROD.OUTLOOK.COM
 (2603:10a6:20b:5d1::17) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH0PR10MB4969:EE_
X-MS-Office365-Filtering-Correlation-Id: 89999ccc-2fc7-4e20-bec3-08ddef824249
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?RlSe/aN/nSDTW6gazHuL3KOb88hjJ7iO+2/GVOlUJs703rYKhNzOhwySIP8+?=
 =?us-ascii?Q?31aXOYRUCYvikdAxt0Q/OKbGqjBIDTTYLvPPbEjpOhEhaFTZrMVjcjooK+1v?=
 =?us-ascii?Q?1/yWwmPl2pZJFWP8aT3bUu7Me+B/O8uFuAXEs9WFHt0BuK804uqTc+PS3yAk?=
 =?us-ascii?Q?SaW7PhGb2aISdA2J2g5LzW4XulK9Gs7GmGXoZwn5X1FEotfmfT36ZA6NndAP?=
 =?us-ascii?Q?2A8KRQl+S63VMqREW9R7FdNqvbECiXpFadFcHQWzVzzq+hTpdo/g8KENJS4t?=
 =?us-ascii?Q?m8BHEVDyNd06ugn/GCmwiiox8OxbtQ3kPM957wSTDNErS5yFtuFHOfyWbxfs?=
 =?us-ascii?Q?SoaaBV2SpTwSgU9Ax3q5B8hGoVHkYyDX/tOffqY2WXcckjhYrXPdh+9J2SMC?=
 =?us-ascii?Q?7MuO20frEInwSbwR0Tx2as9pFfLjmIqMAKfnO/qntM/WuGbKQNZuCuArS3iO?=
 =?us-ascii?Q?nVRuGEonww0u6yxzRS2k7KbuLSa6d2WCbF4VTLPBIVKZpLgqCEY7JlovllQk?=
 =?us-ascii?Q?6wr45BPKJoErhuSKLatV5NCNIyiTeLMmr1UizPSI3NUwJ6+zgX37yiEhAMRD?=
 =?us-ascii?Q?VilcEcwkYNpTDVaUhQFYI+8B84y/a1AH4FTfyjOujalGb8qIy8ydH39AZ5Z1?=
 =?us-ascii?Q?W14ZmTj7vFds1/BrMIafVL/m8PQGTMi1hcxMXK+zQFYQm5/K9ZgkTCjvHc9y?=
 =?us-ascii?Q?8a0nGLyBxhOZIm0F95o7gcscrEVnVeHLMOID41xm9WczpWmBs3fXNR06rFKN?=
 =?us-ascii?Q?7b1lsZfM/0ZcIHQ6W8X0VhVqS6ZNDgAlMmdpmsTPPDrwqmFBnVVjmqWrrT8K?=
 =?us-ascii?Q?rq369XjGkJsbInWDLmIPW5xUrxZ4g2jOdCz36sgH4hWUosBNenppN049OrxY?=
 =?us-ascii?Q?udfuKqrCagR5Vknzx+6djYcbbtUZ5TKWA8oEUBS3Sy8s8q8VjEBFruREQOjl?=
 =?us-ascii?Q?WyYijjZGBpElyVeIC7HXQdampz1kBEzKMlOEn1qn0sRtQTfjUlbvCpdWwaGv?=
 =?us-ascii?Q?RTwMF10z5U5Ew3t/JTJM2+EVcCiNvgBor0FfMvnfemlKVuGFcp3xTZazc8K2?=
 =?us-ascii?Q?5wc05Vi7IcmY769qGYpTkA+14yGtdQTzkDZZQZagkBSsITcWZco18WZF3SQ8?=
 =?us-ascii?Q?Dw3k3JvktAlfVfC6esT9fApSOPCJBzOYo52jXu3AsmOdFYaYYXemdwv0umhM?=
 =?us-ascii?Q?4C4l0sXOFTM5MwXifpOd+RRMWw8D2mkBacAl3/+4QWrW/bmnWVw7GMwCVjb4?=
 =?us-ascii?Q?uIxYioivXH2B/CReSDzgfdqZ0cHPs9qYZM15/djQH13wVFAthmLD12tRhE2f?=
 =?us-ascii?Q?JUUNGTHVQDcDIH8KaHgNjL7LAya6gvnhKb+f8gjOe0482czlYrQdwF+k+3D3?=
 =?us-ascii?Q?RYsJJUjU3A0tK2m6GH0k04JzJsvKHfyfkUAI+1D/UvYLzfNiD598/7yKQBLQ?=
 =?us-ascii?Q?067Q5YUfqXs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?mL0fAdqDD8Lnk+vNHpR9BxwR2dv4py0mqp5p9+ak0lkk5ZHt5AqqTVgok1KN?=
 =?us-ascii?Q?jQ7BfxSCyvEsthgra5z+1Fh0Ay2++saACBLLJgc0h3E1X5cCtbpqlE14vQGv?=
 =?us-ascii?Q?VtXPFmlhVIsjKyQzbyb5WT5nzWbEu9BQJWslFqHbreY3anUafaLtQ62hOIpE?=
 =?us-ascii?Q?CTSSq5tEK36W2R3zfxiioDgvGhOS4ORYRn8CJlQc+PDC3hoKwxYLmCPaAirV?=
 =?us-ascii?Q?c8Ajg8/OZKZO/3HwA8vYGyGj+5023BTWZC6xsjszg/7ra3+LyB65LnComF3P?=
 =?us-ascii?Q?SEd+4Eiraiww6zhJkw0wLS17H3YnnuzjMZciqLoEj7KJO1mAObw0dCAoxZlo?=
 =?us-ascii?Q?H8lJwCbYeUMg3cQxxfr6il9IkgSpEoyhxPAcZ7+u/ZW66VoHspnqSYZOrZry?=
 =?us-ascii?Q?rTjg4JHG+hE2yDxuzFtEQJiRBBx7HIi2Cyn9XOsg+iKoRSx/HfVbr+mQDQQW?=
 =?us-ascii?Q?Fy8f3dRMYXuw22T0vo7wRKYGO6qbISWzTzIT/G9aSvypcFgKJLACxVVuHA6j?=
 =?us-ascii?Q?Sb1O1MostqHovwNQBh7U8re3zDSrzA1hJ88c+n9ppYRceU7p3M9Dpj+FLKyj?=
 =?us-ascii?Q?3XdiVOfSZTxBxldgnsTv712JpTrUhsAOj6QRQ9FHPE15PjbDRmysF31f5GA5?=
 =?us-ascii?Q?fzaUcJQMjCj0QhJyPFDnBrIyUUb4Vm9HPUHP6e9ed1orGZKiuoFruWpk0hDw?=
 =?us-ascii?Q?uKvXqlJSdiNvXFuY13YryTOttCWiFsia1bgRTFRbkRIfJa2Hb/Jzd5QvE5MZ?=
 =?us-ascii?Q?pn+Qv3V5Spjf3snv5dRNUaD68ydJKElvyOH4T+ej+E5u4aGQ1gt1leBYJzw2?=
 =?us-ascii?Q?DByTBhnB7ZGzTOfqkwyvM09p9LSUu1Tq/tJwCG+ZKkUSJ70weB4tjAUAfbPI?=
 =?us-ascii?Q?T/cPxBgvmwZ1g3Z0H2QgIbzf0414WL6rvj1nJ1FmXll1iZ5aB4d/NdnipR/h?=
 =?us-ascii?Q?m30W32MJYn8IjqB9DRPx1aA0xgqBWw8hzBhoMjhHtn4YGZMvFwWEtFQdpobW?=
 =?us-ascii?Q?lo5CplNU5oPp3r/2fr0yTcgBqXGspFFsVautABxnJ0XTMCVziu1jpD+BK8LQ?=
 =?us-ascii?Q?MLZBAiie4CsoiBmMYWfpww7puzIiKXfv1uETCou4tpv7LBw+yTDMCHG3rYBn?=
 =?us-ascii?Q?PCJr8z5z9yrAwpWyDzw3pZLvj+BnxurcfPhNe/AmJvo/vXsDjsb96VaIdCWT?=
 =?us-ascii?Q?rn1BQuxAwmq9K/l4FrgrsTI7zVWu9h7yPqTzS0SQXxwo51PS84FQlSoyM1jE?=
 =?us-ascii?Q?cOGzJwXExdi6bDutH1KCjwjGPLnKuA29N8S6Am5UDExH2UP+lx1AhWEEq2C/?=
 =?us-ascii?Q?f3J5ofs5nkssV4ndms+QOaVO99/Lg38FjOiTg3BLdsiOoIeWRgifhR6GiutJ?=
 =?us-ascii?Q?c40EVNqmWoBs9jzfcYTwE6eMxnx2OnZ1JnnPdyzfIFNf70ksV7ZD4c3saoAQ?=
 =?us-ascii?Q?9H39c/w1tV/QJgMJmdilB1nEOirGi+CIKZXfvrvZmzCjjWZPNTd6KjPk28ps?=
 =?us-ascii?Q?qMDVrhWY5Q5jd2Dvry+2GKjkoATupxXbdCwcEqkmQZJaOkHvPVNRvdJkFmom?=
 =?us-ascii?Q?U6p11sNNndncM10E7/WGAYP/Xb494miw1ZK/y22za2Nb0UeHRG26GjDN57c4?=
 =?us-ascii?Q?8w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: UedZ9jt2h5O15BrCEIeud8484EJ+6MYaAk6kq/3+g3ntZNC0aGIHfrYEaBc7s4ermyl90nKhDYNIpO5XFIEJjYgKdBl2ig9ZjN0Mmjz+rWO1c/Ls9V8SilRgzHiPxfWebvNsNDrdAETZAV0/+BHYVRNb/ByqgdIW1AENwsC5NaJhHbiIn0NiP0wfveqmapmUlTTytmRbshxqWu1M0wk9t9+kPiJ2mihajBl5UsJWcGnmS/5A0GrDuUv1G+h4Z47u7Xo8T8rWiqVzalee/76FkrRm7VghkQEfxon7ciFuEJnX1Ieq4WQsuPDHI/HCq6tuwKpmYp4JYMlft7X9WB6S5GmhI/jKaYsmRDaqS3xpfCoVonFz3ldnHoecD1I+zm2PaYPapInNtwJq/e2toxg1PoiF5vh68+NRJWBF1e2QcqL0UQIs75GGeuMRHK8UDusSVQ+oIpIlLfCt8DitJLnivulv5RWJCrayaPO/kSDEcMwoXki1F5e0iG6MXwoByXjpYe8EmJ+1etthaaIvw8IP8Vs/fu0HUTDsTlOGkED3XnITwmgnYWniKLflmzTLz2yTylg24Ux9lzmtgdIqsG0zWAtSmYoEdzC8w4z6kZZJBWc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 89999ccc-2fc7-4e20-bec3-08ddef824249
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 09:21:29.5200
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tAjFS+zCRBAHAvKgwyfUWRAqGhCVYr71cwgrE26+ThETfkZo50bYQQma1dSTqL2CG6DPEeCiZ5TLKXAeE7BgVyLKayF01YUkD18oyJ29tNI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR10MB4969
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-08_06,2025-09-08_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 suspectscore=0
 bulkscore=0 mlxscore=0 mlxlogscore=935 phishscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509090091
X-Proofpoint-ORIG-GUID: y8PXBCHBtKaLzkZc1RYO3YkLvEJgytLM
X-Authority-Analysis: v=2.4 cv=PLMP+eqC c=1 sm=1 tr=0 ts=68bff19e b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=2_v4jMvWlZbjAAE9TA8A:9
 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12084
X-Proofpoint-GUID: y8PXBCHBtKaLzkZc1RYO3YkLvEJgytLM
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTA4MDE2MiBTYWx0ZWRfX7CKCRGJhaW8v
 AGJ3NdiHqdnH548pn0GfjzRKzmGupfx0VOvH54/U28P35na9ZfCpdi9nrXd5M+zIyVDJnwt8tnM
 hAF+CVclDEkt19JpXU+vTujkAUWs2hODJbojVAIH1BjMhFgzfI6DAqDUcx6jYghW/PBY8OvQ6rW
 pm6o4HJqLgoIPOpjhta13yjiHJIzsJKLO596yRHToQIzm7pEEXep4wk8DZ+/vzcTeB8eMuEYkVw
 w6SDhKO3sqlT64PC3W2SHtUIYYvXfdCBG+5P6ChqOYXkUPx64NXpbr+GGPEKUKt5e38rS+4ALie
 flohJh7j7os6Zh2l1H1scJjgVVd/C+4V5op6X2gcJrIVDCGluBoclH1Nfsra03XmvW1TxNocHTS
 sb1p8OKicciQ0WQj6LrIi7dSw0TphQ==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="rJoxywO/";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=HIT3+zuI;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Sep 08, 2025 at 07:30:34PM +0200, David Hildenbrand wrote:
> On 08.09.25 17:35, Lorenzo Stoakes wrote:
> > On Mon, Sep 08, 2025 at 05:07:57PM +0200, David Hildenbrand wrote:
> > > On 08.09.25 16:47, Lorenzo Stoakes wrote:
> > > > On Mon, Sep 08, 2025 at 11:20:11AM -0300, Jason Gunthorpe wrote:
> > > > > On Mon, Sep 08, 2025 at 03:09:43PM +0100, Lorenzo Stoakes wrote:
> > > > > > > Perhaps
> > > > > > >
> > > > > > > !vma_desc_cowable()
> > > > > > >
> > > > > > > Is what many drivers are really trying to assert.
> > > > > >
> > > > > > Well no, because:
> > > > > >
> > > > > > static inline bool is_cow_mapping(vm_flags_t flags)
> > > > > > {
> > > > > > 	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
> > > > > > }
> > > > > >
> > > > > > Read-only means !CoW.
> > > > >
> > > > > What drivers want when they check SHARED is to prevent COW. It is COW
> > > > > that causes problems for whatever the driver is doing, so calling the
> > > > > helper cowable and making the test actually right for is a good thing.
> > > > >
> > > > > COW of this VMA, and no possibilty to remap/mprotect/fork/etc it into
> > > > > something that is COW in future.
> > > >
> > > > But you can't do that if !VM_MAYWRITE.
> > > >
> > > > I mean probably the driver's just wrong and should use is_cow_mapping() tbh.
> > > >
> > > > >
> > > > > Drivers have commonly various things with VM_SHARED to establish !COW,
> > > > > but if that isn't actually right then lets fix it to be clear and
> > > > > correct.
> > > >
> > > > I think we need to be cautious of scope here :) I don't want to accidentally
> > > > break things this way.
> > > >
> > > > OK I think a sensible way forward - How about I add desc_is_cowable() or
> > > > vma_desc_cowable() and only set this if I'm confident it's correct?
> > >
> > > I'll note that the naming is bad.
> > >
> > > Why?
> > >
> > > Because the vma_desc is not cowable. The underlying mapping maybe is.
> >
> > Right, but the vma_desc desribes a VMA being set up.
> >
> > I mean is_cow_mapping(desc->vm_flags) isn't too egregious anyway, so maybe
> > just use that for that case?
>
> Yes, I don't think we would need another wrapper.

Ack will use this in favour of a wrapper.

>
> --
> Cheers
>
> David / dhildenb
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/731db7f1-5a0a-45a3-8173-be1f19470bba%40lucifer.local.
