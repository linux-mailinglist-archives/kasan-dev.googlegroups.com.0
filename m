Return-Path: <kasan-dev+bncBD6LBUWO5UMBBD6O3DDQMGQELF3UIFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CC6D4BF0FF6
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:01 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-430cec27637sf27945305ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:01 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962320; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZQ5kOBP+V0Oo37nxAY8lb0LlJy0US8NYLkdtykObInBylQBV57x7lLCKST6achohQ
         DQIu44fTm2O0ghVb6igIuBWWt3J44Cm91zYpxNkqfsjuA0Rh1l4KWvPuv8IdixbSyl5F
         du2JDGaPeI0q2AVbg7ac9dfzH6kSWRg3cy//sPNYRsqLa9qOcrhM7YaFSZ8VGMcn7Ue3
         lK6Hw1A6hPdrAsCI/WzdM+AbP0AfVqcOqHqPI34nrF7A8TVeY54wkwpOIX0R/WRcv4ai
         kybn5saPEynepE3LEBfVj9Lvjbp+Via/CRocA5YPRSHZVhJgMAv7+AA/PvxbqWME92xY
         4LcQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GiexWQjAMsy9oykwAtIWBkkE+Z75KeYhm9ziUeqKwyg=;
        fh=Lvh/MPWRCnfl5yTFRTsYut8uqYqzww4HqAFc91e2gnQ=;
        b=CN2VSVMswR2m8K0/xLEeRy+r3SqnthFthWq1lZYSKMxa2y5OGZLtM7HyeNEDQ1aZbE
         OaBc8zAieQSjbS/RbPs7jVYmEoXiog5aNesNUskZSnMUMQaqd7+DqS7+FmgNm4Ku0JCC
         cJkkD9ZU4M2I7klgq+Hsni5LSpzzfSftjGZS1VgVpsF3ZSMqvNpFZItvXd5xRUkoNfzg
         zZ0WFMBoci/Qyp+fqlMk2q22DVUeiZjmbFDVClHZ2jGm49eVTfPbdTn/YtSsvniB99mi
         6Vilz+dDrqEYyi3z5ICdRc86JaYiyz/QuKTvU08OhcqUfE0LzMkAe/hV7EmFu1sXQUHf
         0lVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=p6jthHOT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CQtZjuEr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962320; x=1761567120; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GiexWQjAMsy9oykwAtIWBkkE+Z75KeYhm9ziUeqKwyg=;
        b=Maq5FOzM4UipyVq4bpl4voTV1G660++NEsJdy8+O+OE51WSNJ+4VcBYq2iUlYLTqEn
         adUmPylg5PjqmbuzgKyLZMAhseWpsIcZWB2OHMAPOK4ANa7MHAL+r+Z9jw9xkhMEE5Bn
         3sk374UACFtnKF7nm8V0TyuCrGXp8eQ9S1qzfMhEiGRnAkX+1t29GJz8pqft15Krv8G3
         sKyThXvn28knujwwU6t8OCSmsK/a8YMMek3BdJPQqi7a82PAF8j6o15642x1arJVdFmQ
         d282axJaZJAaLPevoW0awloTx6skk2rkj1hIMV/9DTXG2Sw6KJWr9Zfpp1ybZJuIxQ8w
         24Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962320; x=1761567120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GiexWQjAMsy9oykwAtIWBkkE+Z75KeYhm9ziUeqKwyg=;
        b=qAT9Um6jxRjT669zZnYS6GjHkHIkJZB4LwdncP7drw8Skzoqh47FnSSkJSV2/wb+u4
         oaBZS1/zfRneZ6ekEOLgjrffA2/ggRjiPpDV6dnVVnQCJ9k30mD18ioRz3kXjjqvbE49
         Sxp9pJket9KOFBDGHOW5jXV5/krLBXPy/1u2KYUfEdKCyRNKwTZhT+kxcb5Gy0ybzuPh
         mB5ILxibVVGFRqzJ5w5zU53m5iVI9VVmul6pJDg6MiWTNuPuNdNICyC+H/UyHuslaaGh
         gNAzbbwo96lXX4C5Tgu9j9k29+99nEU8UDh/jA6BZouzSWLBx5PLE6S5GeJZAtBTyd7k
         sW8Q==
X-Forwarded-Encrypted: i=3; AJvYcCUdaV61nM+lHw6uRfU0GpeCvPXS19oqFTeo0oV4k3YKvRYxaHneuiO0ojMtK7K80dpwYyn4nQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw3NF2TfIMvdrxfdGY7bj5EOMOcKLhxO+ZPS/eFG1q4b9J1VL+L
	8pfR8wFBxxCVUQTA4o1QejufvWmmO4JzXKF4MMvceTCMvbhJ0NJcnP3j
X-Google-Smtp-Source: AGHT+IGUy5bYVoFR7+9MVzM5ub7D/NDIYatgZi8zkYOiNUWEXylx43sND/lEaXojRy/djxEFOPqQSA==
X-Received: by 2002:a05:6e02:1a27:b0:430:cfe4:6e61 with SMTP id e9e14a558f8ab-430cfe46e9amr143130415ab.14.1760962320104;
        Mon, 20 Oct 2025 05:12:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6XOchAy9pt10586J7jEU0yYeY/KYxYftOto9T8OnFVnA=="
Received: by 2002:a92:c704:0:b0:430:b4de:58b4 with SMTP id e9e14a558f8ab-430b76fa9aels33215155ab.2.-pod-prod-07-us;
 Mon, 20 Oct 2025 05:11:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUHZNWSk6wgc3arFuwfhvbxJNuGRXAvO5hZ/28ytlqufbeQMVccEcXuEnPHavuFHc8vCQ1K9Xt1tQI=@googlegroups.com
X-Received: by 2002:a05:6e02:1a66:b0:426:c373:25f5 with SMTP id e9e14a558f8ab-430c527dc0bmr177307515ab.17.1760962319225;
        Mon, 20 Oct 2025 05:11:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962319; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fj91JWXtPE3W7ElrIE8J41MIGoTekMhpIhQiWOpZKO4skyonB2SmPHuUgxBJZFu36E
         4wHu/GEv1t4RmNJ/NnEW2ydPT4ZV/KDAMhTT3YBoj9DbFgR0Jj2LOu/L2rGzn1LN3idB
         Q5DeluH6dIzWbENbZfjOBQqdO9DQHzS9w6QXzOe8sPchl+WVjnNcd29cu52V+xhG5JGS
         GrPNGCfVGkyxRJMSfSMuUP86nlLCJ6VUM2n7crXgQgCZ3chfUCM/s5quW9IN78zLnINE
         JiHsCw/xoN/Vx2Tw02R+CSYNnIXZLZpERqJfurdycooNyYya9DJipkN9HJVjny3wxg3S
         mklA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=zQBd5J+bTyqnurPcPzG16hZ9knQTk1Dp+BRxC4fYcbc=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=givl73CYig487xzyJ7WWHjf4WpJuVZJyfGE4gkTbDB7PK6NAwBhMWtCUP/AX1UCJe1
         C6+KFkh3UuEU2iZviaHxo05gL3dpdj25nTqQVrj73RB/KofhSBsQHrJDUTyyp4s/xZin
         5kjPE4oyJvYYzHzP9mP0MtoRNYsQxgDtck6eahY58SJoOGzfHnh9GcOcLI6ubM2NooKi
         KhK4g+Mga3NMqkGwhlQYvTk8lWPosH+NVZZPWFU4KSEjeU7oiTGrqsVyfodShawsm/js
         xlPeaYQ3ex/A8vG88ylC93iqpxQJtgHWw4frbKgLpmIYrXqMMUsf3NgxT/kSWTBSOMHl
         KJDg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=p6jthHOT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=CQtZjuEr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5a8b25f5f78si281116173.2.2025.10.20.05.11.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:11:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8SGFt027953;
	Mon, 20 Oct 2025 12:11:47 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v2ypt5jb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:46 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59KApBJU013726;
	Mon, 20 Oct 2025 12:11:45 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011007.outbound.protection.outlook.com [40.107.208.7])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bam2hu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:45 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MPrS++sZubDvIv+nsCZt97nQOPi6ZkFyNT6+Kr3Ueg+BQBxfryq9tR2hQWmJdC8y3FaJPUU+OkKa7X8b1Qbk8YtApHo13DTiWwK12UIKfU2FqoWWFqCbuBQSpcmC+f/YFlGuzi1fm13/zuo13g7jCG1NhKPH0wHv8B8v+Oz+hrYdMcbpy2/bKUX52m09ha/q+fcLsvPZ9yzSlRbXXUTETnFlwUdJa07/n5Abk2Y+hNc84knaSlndGIyi40ww/kcMI1txQTXgo0ejS/+vikkkznf6QaUxTRhgC3XIuUvrdzfkHGRe/jitJNeqYY8dYfDjbWKQ2fTf5X0jFyoB9WbpVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zQBd5J+bTyqnurPcPzG16hZ9knQTk1Dp+BRxC4fYcbc=;
 b=wgmYKRiDJL7/aaLqaPTFo6suR1E7eXX3/d2dMNSDX2FTiNP0Jqik+vLaInxbVkErx0X6Nutgv1SNkw/QOWVd8cU61sbRGgFvGuMLS8sIkHmgEVFj6GHTk5L07OR+kktYfWnqYfAfYqrD4cDMbfopdILH1eR1VIP7TBMFQNte5almRPvh2/oTOMfnYEov96ebbGJiaJ8rF+bHCYO7/1HfpGWIUQ+Ynl+9imEMuH8naIEttRtzrQmf09IwlLlWKG7XB95dxJP7uUb1fmSsjz6AQKDaqhDWRM09XQVDDhgsVZv8Ljx+gzHp+YpB6Jb7qlufSvBTtYuUSYOznRe92YXhCw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:11:42 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:11:42 +0000
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
Subject: [PATCH v5 02/15] device/dax: update devdax to use mmap_prepare
Date: Mon, 20 Oct 2025 13:11:19 +0100
Message-ID: <1e8665d052ac8cf2f7ff92b6c7862614f7fd306c.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0075.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2bd::16) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: ca26e281-6617-4f8d-6980-08de0fd1d4d1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1I66Wg9R7uSaJNYg2xRDmIm2Fdb94uMg8Uid4+6JoF4JOzvWfDnf83gz3hOz?=
 =?us-ascii?Q?ZtA6dt97ezpz1oOEr2OY3KI7H52ma8LDHVtUEKEFPoyhVscpIx/4ctuRqbMi?=
 =?us-ascii?Q?ylrjdhi9mBHimutla4sGOo/ranzU166zpgudj9yd3ieaco34BUH+qNRbd7CX?=
 =?us-ascii?Q?ScC5kfvFtCDKtzUo9WIjnZGJBTDqAtx0sDbULN3CUFIELzX8AwoEkrOQKS+v?=
 =?us-ascii?Q?P/lxNYnAvY1Rhv/HHtDt/7tSh+D87xF2UBySQsG4hbI4FLlkQ2M1i9b8dgTO?=
 =?us-ascii?Q?VGsSutSr6PzCDDXBRpwJh5DW4mGgYTBFZqtFGqWk9EMFYJx9C+C4iPpkQ8g5?=
 =?us-ascii?Q?bQ1p7MOI/0vIKTVivg1jdYKFj58tTSc0SecmqfoUTKBVEr1Lg+Fl0IBlmQsJ?=
 =?us-ascii?Q?eOXTxoGG4T6L0x8+5kgZ11NFu2TXDRo0RJtyjwyGjSw3bSzklJzniE/zNdiI?=
 =?us-ascii?Q?oaPdsCko9Wd33h2e/yyQLgIR+tqULtR+F/rmQB3z+mJ4NKEy1JY3fI6xlulY?=
 =?us-ascii?Q?cH4y2xCqKDEdgp1R0lGuge6zTxWN0rk9LyJ2IL8B7vxBfXBdcF7GPA4Rl57e?=
 =?us-ascii?Q?LIqYVyN8jab/TMktEw8rsFeINR4poMDd+6tY33pA1tRyzrxJcIjo6xV/mSNc?=
 =?us-ascii?Q?1JsPjuj+z7Kifr/7cZxuaiTVIbATcwp0huFuJk+QcA/Zyc0aVevAFKSm1KKS?=
 =?us-ascii?Q?KEc99dwLeAIkG3X9vwSxrApTPkm6JUFPM0UY7Q+0f5Hb9GxFLyBKuxay5JWw?=
 =?us-ascii?Q?Oe+pMNJqA5RdQiz1bxLhRPwuUqaQ4kS7qCeag/i0P00VfPSb0fvUKqORxYuP?=
 =?us-ascii?Q?85kX7sWigIDSFjR6aPxqJiHkVQawojm45P0+ONC/53pkUMVLUIDCpx0EweOP?=
 =?us-ascii?Q?YpSpdnRmgR27Z1Ozsq7YoP1/eNm0m2Wb8H0N+Lfusb243zD7FLfV+4q3ONgO?=
 =?us-ascii?Q?xvvTYGa8ibmDuW/WU05sfx67jUy6w20CPaOjl9zpkO4w0Hs1X8Eg6LJTdoMG?=
 =?us-ascii?Q?oc1bJHZd95HVBN58wfxmm4VKQVISZEYf0REesPJM1eAq2IZOldwFEgg7SsOE?=
 =?us-ascii?Q?SafM1EHLTKfY0Rej01rTccIxlZGVRdtu5/dSIAxv/YPPCB6TeUUzrrHCTW0D?=
 =?us-ascii?Q?QxOvO+MdCb8EUkIokLUuGm9G7txCVkfhPlbtLQrjDpPF59RCXRzk3UrNLgm6?=
 =?us-ascii?Q?rI1VpbUuLqDsXcysLu5RJdlvNU0hdGEmRcqv0IYPxpdxmZac/5yUqOSb5OPU?=
 =?us-ascii?Q?QFYze1O6cPb00+k77SiCr7Ddsv43oM4iK4Yg8ppcBrpFUlzNtYdcWtHDVZKB?=
 =?us-ascii?Q?lMK45nBq2fKRIPP3SMpUpCliFJDQTrQB7FItliA28Wkba+WyV8bdwQdW1nZ7?=
 =?us-ascii?Q?VSZGqnzS0ax6qM5x44ToiJaSK1PI/IPWs57xZmfYAT23EHyTzlcdMGzK6WlI?=
 =?us-ascii?Q?C/oc2m1ULt4dNBHy5FDaU36Pc69M7+hw?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?8sPaAQY3lbz3f5Xe/HKJyMMTW6jhDd1Xx26fjJ2NTf4ZILYaFR3mXfSF7N0g?=
 =?us-ascii?Q?7HGp4g2oQ0ZrtpWznWCztSCbgp64qYzUmzDiKKQDiDkndjXj8IaKYTnXoilG?=
 =?us-ascii?Q?RpTdbS4LvNna9AV1KRAN8GJ/9qxDmPQXb5TiE7UaUofviyK47yU4MZNHDTWL?=
 =?us-ascii?Q?cA7SDT4h2zRKQhMEvVMtqWCLt8/7F8+f/KXnA8CMAIysKdDADBI1W3c2Hw0c?=
 =?us-ascii?Q?3ZQn8XYoJyIFRJaX5bn/eEMFsvCt1t19oPGIDaC6GekSiAfhNpd5vPAefr8A?=
 =?us-ascii?Q?Peoh2UtFwVA92nUmLKPf++t12EPs9wTcRHpXf5U3eMZgGPalXluqPorCeoGE?=
 =?us-ascii?Q?dnOOVnKe3KfUNq+bpxEkrp6KnFdD8nDGoRFjwRgwRZiVrzgF/G8rK8FTRXBx?=
 =?us-ascii?Q?myQtXtlIzJZ1ykO1xVVEf+JRLVHZ0YIA0Fd46i0PVFu4Yex5UOZlGcOVur7C?=
 =?us-ascii?Q?8ciixANJqNgzd+qm6ggh31quBTR2cbihS3o3T1hZuNqZgL8iuUIfljn+DHh1?=
 =?us-ascii?Q?P6SFsUdFZTHWxJG8HTKx3JydxTCdK/YLROJfNqVk12y8soU9NzUezQAlKz1v?=
 =?us-ascii?Q?unX5saNKZR5cjFw6Ok0Hww904SVcmlDfn1m5gYKB3phniFgzVCdlJLVNgaJn?=
 =?us-ascii?Q?twFoG8hHOgyfHPisFI4vsh1eWtFoeT3LLkwmJVrE9FvwuS4f5CZ1ipO49sC5?=
 =?us-ascii?Q?CC5a3a8l70+BGLicFPrmZBwmbFgIUBvbXOv6HLiFnNEIkLVcSZOhC9WBvXxe?=
 =?us-ascii?Q?fmQEPGJH/FUWD5IAXO500xuBC/vAnpTn5b+AqLUHkQoC4BjKwuYi4UVu55lW?=
 =?us-ascii?Q?VgaEKpW8rYpY7OUJTLfvcakmYVO72Fu0XkPfYucVZQWQlHcpx1ME8nQjuoyb?=
 =?us-ascii?Q?IgkG5IFRr8W6X9odLhLOrLmbUQdZsJp2MsvwzJIfCnGf8P1c06m0kxPn8VUB?=
 =?us-ascii?Q?Rz+eFc08Gd1m13rva06ZZGyyeXW2dEWLkLs1AzesD7jlknG7J05oNfEexwF+?=
 =?us-ascii?Q?iCgSyr1VtQwdCcr4TknmD3Q7FVKcHj6eCU7/IA3VPrRlkXBJsTXhHi3Rj8Fb?=
 =?us-ascii?Q?fLS4b5fGRidBYwx4bbWoH92noPVYvJxmhf9Jw3/RmHC9McvUZ53+RmxNvX2x?=
 =?us-ascii?Q?UN7C4KWDktaExtTqXnie1WRi3lPH9BHJlSxgvCmRXgNOMrf2lgUpG+NVPKdP?=
 =?us-ascii?Q?R+RTolQy//qbdsuTkFhyVajFiEZxSLqDisEPfmMOMmSMXbMSwuIHiWcEKu8y?=
 =?us-ascii?Q?YqdVCHaErmzrbEd8ivHxbv7rl+yCsqgONTFdKXhJenHzkjlm+BUJqx9ctU/E?=
 =?us-ascii?Q?jvDSeWfQ8wF3luHzNqGg9YYA23bMJfiVA2Ii87raohM7coAFHzqPM4pgWwcw?=
 =?us-ascii?Q?fsNpU8iwfmwDfttRsg9QMvpsZdts16935Y5HMT68MN7osDPqKevNsv4Qx6Bi?=
 =?us-ascii?Q?ZXzVEv5PJemHsudRFjD8VRGNjKK8fCs0I8snHJj6gsvb1JrTD0dvNM9IgyYp?=
 =?us-ascii?Q?62aM0rX7X0AxPr1T7ynUOmu1iyT/8KOFHdiZoKiWljFkdc1TB3rEZeoJW+Mc?=
 =?us-ascii?Q?/RiLWPOcnwVAag8UK8nq3OUfx/D+fo/6sBoxZGi/cLalFaduQouj3+vLCagD?=
 =?us-ascii?Q?QA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: cAeKrVcMU0tHmNZYdEOutqfPSVE+HaPtGfVrel9OXl6Y7RvagZhZH2UWhJRjkGs2k8O1ObdHMW5mVhl5C3K4w5B9355HG/hBXgqcAodiXoy4HfcEwY6DngsDmymjoLCIrhllfL9irIfhhk8i+RWIsgCnxzu75tCGA5caRnWDKcA7XXdowxKkdxup+Rs4ZtcIYob1xbnybvn3jxdl3C2l8B8pKjJO3mEbWVTogq1aH63p1+8ptPNHTDzs1S0x8070kBac/QxqtATDA60mcdbNmszIC0et/X1Q3ygXzDnhWEhJ7IWNVhuoLBihHY8JfGBFelIeVwqRO1hhgm8KzRrBYueUjP5y3HiB28QAXxEt5w1L0rHJug41tS0YzAtnmQRg1KPzQY+zrPRc3E47CcsUQX913Ib412Tuwz4eSZ40i5vaTuC8gj6G8ZrEhkXQLfpBvf443sUjlPoPmKi3ZfojppNe4shzO4F27Wu4b40labxcno3mp1SezKQC2ZwDqSj6hBkFT6wxrd48OdDH8v3tU1gQziQAq5vzpSWRfmok0nRaVY9TLqp9p0D2MeZOHkStDSLbEZccIwBrQG3lhBmRhTcEH6NWe/63Jib5New5bWk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ca26e281-6617-4f8d-6980-08de0fd1d4d1
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:11:42.6929
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CnCHuPYGO/is8y4GHcdfdeZFdknqlwQrTXEfBHGoPuzfrDCAkw77xDuY85vRMcfG80FUfPzWCIcanNDcn3rvUxfziOP9e/chIYEGfpkL3Bs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 malwarescore=0
 suspectscore=0 spamscore=0 adultscore=0 bulkscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Proofpoint-GUID: rgdLFWu9ctaBHhqVftN3jrDXI1S9JUAA
X-Proofpoint-ORIG-GUID: rgdLFWu9ctaBHhqVftN3jrDXI1S9JUAA
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMyBTYWx0ZWRfX8TyWL4+Mgdsp
 s3Commw35POHu8NMKe+Z9j+VANrHCcYogEAaqPKwh2wxbEmp36CUVoEWwgFUUEtexRg5FuB+2MF
 W2BpaKsZE6/KR6MkIcR4WCQnbdnHloNiy5if2ApIv3IStlmeWcHeSp+KbYYIM4Zil6NV2RL6G/j
 p/z0h+DbkzvRrzn4ayZS3qI/nZimQ4MCLgKzDe2wr76IYIfa3zSQtS8LMAg9ckaeAS2fTUtEgvH
 +1fSGNcXs9nhIipqBhT69UquRwT7bQw7sDzP8NBJb4taEhWhc55LJTA9njXdYPJROh3QH3b2kg0
 7Qmtvbh27FOV0VXwUkgpf6cSpk5/QzeTD0AmnUedWXPMd+JWKt6EcVTADILfrzexR/eXIBLoJsX
 anp2hnm6pxO5DWLvAOF2wpYO7CKJLA==
X-Authority-Analysis: v=2.4 cv=Nu7cssdJ c=1 sm=1 tr=0 ts=68f62703 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=Ikd4Dj_1AAAA:8 a=miBipihQI5mFMOzj8b0A:9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=p6jthHOT;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=CQtZjuEr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

The devdax driver does nothing special in its f_op->mmap hook, so
straightforwardly update it to use the mmap_prepare hook instead.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Acked-by: David Hildenbrand <david@redhat.com>
Reviewed-by: Jan Kara <jack@suse.cz>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Acked-by: Pedro Falcato <pfalcato@suse.de>
---
 drivers/dax/device.c | 32 +++++++++++++++++++++-----------
 1 file changed, 21 insertions(+), 11 deletions(-)

diff --git a/drivers/dax/device.c b/drivers/dax/device.c
index 7f1ed0db8337..22999a402e02 100644
--- a/drivers/dax/device.c
+++ b/drivers/dax/device.c
@@ -13,8 +13,9 @@
 #include "dax-private.h"
 #include "bus.h"
 
-static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
-		const char *func)
+static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
+		       unsigned long start, unsigned long end, struct file *file,
+		       const char *func)
 {
 	struct device *dev = &dev_dax->dev;
 	unsigned long mask;
@@ -23,7 +24,7 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 		return -ENXIO;
 
 	/* prevent private mappings from being established */
-	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
+	if ((vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, attempted private mapping\n",
 				current->comm, func);
@@ -31,15 +32,15 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	}
 
 	mask = dev_dax->align - 1;
-	if (vma->vm_start & mask || vma->vm_end & mask) {
+	if (start & mask || end & mask) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, unaligned vma (%#lx - %#lx, %#lx)\n",
-				current->comm, func, vma->vm_start, vma->vm_end,
+				current->comm, func, start, end,
 				mask);
 		return -EINVAL;
 	}
 
-	if (!vma_is_dax(vma)) {
+	if (!file_is_dax(file)) {
 		dev_info_ratelimited(dev,
 				"%s: %s: fail, vma is not DAX capable\n",
 				current->comm, func);
@@ -49,6 +50,13 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
 	return 0;
 }
 
+static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
+		     const char *func)
+{
+	return __check_vma(dev_dax, vma->vm_flags, vma->vm_start, vma->vm_end,
+			   vma->vm_file, func);
+}
+
 /* see "strong" declaration in tools/testing/nvdimm/dax-dev.c */
 __weak phys_addr_t dax_pgoff_to_phys(struct dev_dax *dev_dax, pgoff_t pgoff,
 		unsigned long size)
@@ -285,8 +293,9 @@ static const struct vm_operations_struct dax_vm_ops = {
 	.pagesize = dev_dax_pagesize,
 };
 
-static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
+static int dax_mmap_prepare(struct vm_area_desc *desc)
 {
+	struct file *filp = desc->file;
 	struct dev_dax *dev_dax = filp->private_data;
 	int rc, id;
 
@@ -297,13 +306,14 @@ static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
 	 * fault time.
 	 */
 	id = dax_read_lock();
-	rc = check_vma(dev_dax, vma, __func__);
+	rc = __check_vma(dev_dax, desc->vm_flags, desc->start, desc->end, filp,
+			 __func__);
 	dax_read_unlock(id);
 	if (rc)
 		return rc;
 
-	vma->vm_ops = &dax_vm_ops;
-	vm_flags_set(vma, VM_HUGEPAGE);
+	desc->vm_ops = &dax_vm_ops;
+	desc->vm_flags |= VM_HUGEPAGE;
 	return 0;
 }
 
@@ -376,7 +386,7 @@ static const struct file_operations dax_fops = {
 	.open = dax_open,
 	.release = dax_release,
 	.get_unmapped_area = dax_get_unmapped_area,
-	.mmap = dax_mmap,
+	.mmap_prepare = dax_mmap_prepare,
 	.fop_flags = FOP_MMAP_SYNC,
 };
 
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1e8665d052ac8cf2f7ff92b6c7862614f7fd306c.1760959442.git.lorenzo.stoakes%40oracle.com.
