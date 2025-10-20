Return-Path: <kasan-dev+bncBD6LBUWO5UMBBGOO3DDQMGQEQ7Z33GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id B2FD5BF1008
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 14:12:11 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2698b5fbe5bsf69595435ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 05:12:11 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760962330; cv=pass;
        d=google.com; s=arc-20240605;
        b=lqFeXRX+osA6uECZpzNd+t47FxuQFyml4OHYsPhaP6VArfcghtkqeD4dZ8QhBQQhql
         CFbf7EKyeiImRd/Gj27ixewY4tjN+sYdG2hDoiSpiY66xuV6YYDsiGCpDkaICHBcVVOt
         4vjcC7OyZ0TGrnFTuWwwie2JQx5VbYEhUGzbHQ1SGJ3t87VKUW5lM2u7+djPGVR/0uUt
         ENh0b75+Q+hrTuI4xd8Q3xKUlSn1x6B4Mclkl++MysXa/c7r8+/+Uzv19SSglYVb7hdW
         wwD7Vd3sqC3P8p4wD/aw46zWapcauo9ZOhBZeBkRLf3VpvrPNHPkaMI1sqxIvir6vRG9
         voTQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=pCCOjLpjnO4YZjHY+cG06hiQPd37pk7D0UdUDKPdqxw=;
        fh=UqtX6zrZuY997TAGJKjx9Z4Q6ArW7KH86yxCQBZf/18=;
        b=lXatIq8R4Yd1qGEPDBKpe3zrQIwzXlxtLFbVkiKjk2nM4Y/GbAUPg78zieECWYiNcs
         RrAwiVkyTBXTcHyaMd3Rifo77JI6fwO2MgC3UCXQwLN5HZDi0Qj3Wvr8KxVU7rpL7v1T
         LMaE5FFoLhjEIBR+EggeSpk8kbm4sG1ZxX3D/HDmDgIeng5/zGIgdQySba8rKNDy3xzj
         GRPVnG8FtluGv6o1kqb2TWvqL9jujtUKRBAlV9DGrGb24N8Eqb4+4fzYRE8v/86SHDLy
         p0EoPGNaMTWkDzLZApGTuCgnHO71Y+axnIao/Da8ozvxJ5P0312jFBYdqyIc06VGNT6n
         mS7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="I/K6j4lR";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="qbR/xHxw";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760962330; x=1761567130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pCCOjLpjnO4YZjHY+cG06hiQPd37pk7D0UdUDKPdqxw=;
        b=XiSqqYRidq+DcVTbbmefnWmQ6iRhEVWIR9OSwkJQ3VoUwCl5U1atxQpUTkMTwGQgif
         9vLsjCK386r2utQm4qEAgbaempiTH2acA2nMxalvJldmXgifz0j8gGUmJ2/ymd0p6RDV
         Lj02+pxxS5vZZZTYx1+XRAZ3RG5klOkcUyB9IoGsR9uLlZMIjSEqyEj8XjniL95uYWdD
         GH0MJoKp/I+gXMnPGphFrdmqY/qGjP1/SiDhoOwyedOq8lDxhNEl8J683IAmHZn8k7zH
         iRbVKnxzXBoegyYEwof7EtejBxhh1PHxe6Htoij1cfp4ux3CivbrVa2mMX5AtkZ16Rx6
         CjHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760962330; x=1761567130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pCCOjLpjnO4YZjHY+cG06hiQPd37pk7D0UdUDKPdqxw=;
        b=qC9ggLovyinkgkLjyT6zwL2CkDLnM96EW65QxIvA9v4fihDMugQmAjhN0oO0583acH
         NHOa4/CG6qeWPFGEdnn3B836lXJC/A7GGTsvfBo3mXHVcrmj5GSwg5u09NrluvRSjAha
         xF0XsGxgLV4k7mJYlUWHyJMBe2N9+HQF8HT2QlUJsgHmQizAVjoHIl9Uy3HgHEaBAZQT
         BbUV4w0LtrDSXRz7iCVTKBY5FFNBrKeFQU2ocn+j0cucQwbPUHwAhCiDN+CAl+g0oAsG
         JteNdWWmn9/DKmu3jaDcXq1LmdXZtjNg/jYr2+9uevtisZ6g6DNahjmUSBs0laaVbMTG
         KazQ==
X-Forwarded-Encrypted: i=3; AJvYcCX6vt/G8ZdYy7Q1QKAR8z5oG7s1Izw2/zi1zl6Zn0IolHyOF0Vbd5aMf6N1S16Qj2gtFivtFA==@lfdr.de
X-Gm-Message-State: AOJu0YxDH6Y7lpusRNwV4GHGvJQ6U4IyoyX2VUeJ/NhFbxgBmUxziJh1
	HfyBi5gADJPd3KTZoslauXvceY3uXPzWJdV9Yq1VzaeXuktVY0YE+sX0
X-Google-Smtp-Source: AGHT+IFx0M9UEkbiGDKShwus1uJyXw2ZkysapI/5sDpqjUYzy2KiYRk1iXnLNwrzw5MKhOY0jJzvQA==
X-Received: by 2002:a17:902:ced0:b0:256:9c51:d752 with SMTP id d9443c01a7336-290cb65f0e5mr184231465ad.56.1760962329902;
        Mon, 20 Oct 2025 05:12:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4jNsHhLfmKbeVfn3/phXEecRr8qYXwKWY3mAcP7z+4Aw=="
Received: by 2002:a17:90a:f10d:b0:325:9869:709f with SMTP id
 98e67ed59e1d1-33bae4778dfls3062445a91.0.-pod-prod-08-us; Mon, 20 Oct 2025
 05:12:08 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWhxVHoVknLFk2OXpi5wZ7le4E+0WX5+7TKep3mUuxK+omrYj9fi+UFRk7a9Uq6GYfWGmiGmG/MBtc=@googlegroups.com
X-Received: by 2002:a17:90b:3fc6:b0:329:e9da:35e9 with SMTP id 98e67ed59e1d1-33bcf84e3e2mr15092017a91.2.1760962328671;
        Mon, 20 Oct 2025 05:12:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760962328; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q5sLODJserCNY00+AMVvz5FvwNnoSTjkqfI23TpWPEjgwCbqIbRIySqig4H4aLCmr1
         1omb5tDT6cYeQ4zZ90CTVmm4n7MzS3ncRLKrCfxiJBKrFaLMQeFYfdJC+S4t07QjW6ep
         9yp69roa0to8KkCJWGkhXBokwX9IojjhagknlgUnHvE3evetBOmsFL5Rneh9INq9ElCI
         +LNzSAGjto8pWMhq38ojJApCHKGPtU5zns4HulkIHzRIFzC3zM82LOxyWhaMVHOkY+yf
         RHscSUknB1bnCK94Fkv00iRtRKRxHGbzTkA7lpv35WA0FUa5xKTJF8e3h4yWUZUlv4a4
         pvDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=UmwwB34Cfl4q8IYPPXnlikGAudVZFC89KME5ssrJlVU=;
        fh=lFphNsgxsf9lbvW3YSxEH7FYFRIMHG/Xc4IkZcmZkiQ=;
        b=hrGvOq2hyhN9Wx2G6l9muQXbcakDBbiLcz3WP1iaf7LISzJ018+AxTnG9wuVYcJQYF
         tlQaukMz9C1G0XX/bagRPkbs81pwTaEQoWcqGNqo/x2RZJsrLLUqWvY6VkaJ9axwLhRu
         8z4nW2YjUnHM3EQlORoiEtP69mOo9inaGsYcokDxXXIGDEnnj7YXcDZ/iNIQAMxYytkq
         Em+bBuNSQD+9xEfIl0O/TtPCxupGpBji98jwul24kJLyswfOgmYxKGtYUYvdA9RC5liP
         eIhT98P3OX7OofGGrXyyLmdtoxEEdbHFpL1fUEvp4ICVwCxVqDkf5HhB8GUws6vECGE8
         hSLA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="I/K6j4lR";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="qbR/xHxw";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33d5dde3b9asi86424a91.1.2025.10.20.05.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 05:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8Rl2V025507;
	Mon, 20 Oct 2025 12:11:56 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v3esj3g1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:55 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59K95vYt032333;
	Mon, 20 Oct 2025 12:11:54 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010009.outbound.protection.outlook.com [52.101.193.9])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bbmf8c-3
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 12:11:54 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Miv5vZhUqkr2AqKF25zrT+0Mb4z3/2wgdlSahEgEjWnTrUR9LjfMXoyWmBWtVUKMYxkXUK00SGK+rUQnLjhmztnFAxgHQlK5mvKI824PKmy+R4X26/QLwvTqUC3UAoU9nR0HhAX7F/oFfXmar4UHr30GHvk6IZP872A+BfKUv5INvwfWxLfLH329EdSYRV9zzDLGg3uzMRxc64yq9FA/XGxRu02hvUBLBjOb4VrMZATC0b8L4fggtNzAHnKTVuWppGKd5+yQmBJsIhFOBSxPsCRW9VECJQVlWz7egzK6ENQKVkQXbCRnle0shcfLfK1/6ghrohtl05lWrcZK9Xz4/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=UmwwB34Cfl4q8IYPPXnlikGAudVZFC89KME5ssrJlVU=;
 b=HjT1OgB+39da8lM4B60YgKHsKMr8CyqLpEv56eaS3k6RbD+OPHxJxp8BmMpu1x1E9XktXlw3Q9m/j/heTKdj/bZ75Rs4LLBUDG+4PV+bokHRaKMjXHb2vlkAoPLHTlzPMr/+6TmbjsmQC2bKdpD4JttXRj78q0iBfM1mnFiLNwFiGu763MHx0T9M9DAFNwxhedjSUGk/jNY+PQwGUKnUVNtJ/qdwU+cvagKAeJ5xmZyDD4zcJC8oGf1zDsF9y8fvXSmbeBTX39aOsQGMMI4fabXc85TZmiAbGM+ODY6APnQrL7xeJPBi4TqOEoA7SWXyNZeu+8yeJhoBLJAFR3z2Lg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM3PPF4A29B3BB2.namprd10.prod.outlook.com (2603:10b6:f:fc00::c25) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.17; Mon, 20 Oct
 2025 12:11:50 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 12:11:50 +0000
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
Subject: [PATCH v5 06/15] mm/vma: rename __mmap_prepare() function to avoid confusion
Date: Mon, 20 Oct 2025 13:11:23 +0100
Message-ID: <d25a22c60ca0f04091697ef9cda0d72ce0cf8af3.1760959442.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
References: <cover.1760959441.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0671.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:351::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM3PPF4A29B3BB2:EE_
X-MS-Office365-Filtering-Correlation-Id: 1350f77d-6fd7-4c94-a48d-08de0fd1d9af
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?iF8aAYvJbhWpiLMauTvhaxzbNr6I7cJLtkE9xvSt+ieCOWLbqWRwAueZoEzm?=
 =?us-ascii?Q?egzKpSpt24NCdlUjrjdPtyzNhKD/Qm4qIQTsw1gZexRxLiNRsLpi7QatuTyU?=
 =?us-ascii?Q?NDy4HpUOFsj5nwYLJyuECJQci+EyXCM+cNUleBLsQTHhjqcdy7ncebhYMZ6E?=
 =?us-ascii?Q?GQMwQ55zkDV7z4hMWN7rq+TOtvwshKwgirLG2cQJNzjGL56m9sbsvAgexJn0?=
 =?us-ascii?Q?UOMCSE8KOQOffxlVcJq0gGpnYLHh83lnYeAmA0z+fmzfSA8kChk+kHObQTkJ?=
 =?us-ascii?Q?ZwaXffGoMKBZkYb4S5gdNYa8KhS/5/94nwqQjHBSb4iJsvmq3G5Vl0kxPtI4?=
 =?us-ascii?Q?trEuDSMLtz0ja/UpJrtz7nkQkDHNGqGCzvOdxMfDVyQaKC55RodenEINlo7+?=
 =?us-ascii?Q?RmPYrHCR/gJ+7jYBuc6AjDX4DAlOKpqiDJuuLGMApWGbs2s17ZSELdTVK8bL?=
 =?us-ascii?Q?Vv/22pauvBbIF6dBWaVqScl/Zp6/ttaAmX0E0iUCB+q/H7riaGfqQrZxuhQb?=
 =?us-ascii?Q?C5bUBsrtfw5uHTvjJ4dKP8WOUf99OpURvP5ZUXDMuMX2uhVG9fRy5gzdMMMI?=
 =?us-ascii?Q?/g698rngR61KcNyaiKYHC1he79TcYGFvSET5QOyTd/yEv7Pjv97otzErv42M?=
 =?us-ascii?Q?IlMGtpa0dfvdZB7LaEazPytKs/qNzvFqtQuVT2GcJRh9uRTbIaq4wPq0d19w?=
 =?us-ascii?Q?ZZu5ihLaWQhNJnfEg7dBGSkfxADPV9FFIqGauQ7helj9rikY8GnjviROl9WV?=
 =?us-ascii?Q?BRDMuwOTg4I6vqPn5ZI4j69EmFFJ2muxZvnBhocvIIoN9ZWQ6qb8xbyBaN05?=
 =?us-ascii?Q?hGH20CkTNy0TCAXPZFfFX35cuPuHZvUlOVJzGGUi0i3KFgrK1Q8uy5ljQvdo?=
 =?us-ascii?Q?43s2VG4JzVYtGJ1pmqC4VvG/zCNsnBYc4WHx/8Hn5hZEJ1Sd+6jegnbd3wzs?=
 =?us-ascii?Q?ui0th3TJGS4Mivxwk/9dpoj3GZ9DaUE8CNxfLwojFWKsFCj+p96qSRHWPGAo?=
 =?us-ascii?Q?JK+Jqp00dySbW1T4mwtOOeYmaxUrvVxSHBfyj1zpHv+cOpAPEuuA7OxQr23l?=
 =?us-ascii?Q?hqs95K9kZMJYF89B3SvOdXxNPC62QPpJCledAkW4TXsaGSseUKQ2WiL2EqMv?=
 =?us-ascii?Q?aquiiCPTI0NFbpAJpYIokxI86APzqmpzCBM/enanp0YVuE+s/sjwyY655LuN?=
 =?us-ascii?Q?Rbzq+RvwN/r+YbLZYp9qkPwidKPx7g+cfJRYA5DVnvMSkU/JLxCupLaxsZw8?=
 =?us-ascii?Q?3bDWDAU805bk0oNGBBWffJkkV/LC+4d2hvIp0cIbHsmfyJOaSfaskd3aWfa6?=
 =?us-ascii?Q?GYJ4QY2UyEDyippUegneVnd0PyKacMnuspGa4z9pROtGQaRHN4xNmQh0WWXp?=
 =?us-ascii?Q?RaM7jm3mAZs4kDCVk12rizeidL+Y+lL92S91gyToavDEwIDTJd4puHZr2ueZ?=
 =?us-ascii?Q?cc77mqJYfAgstwu1mEZzQsZhqMFmXeVa?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?aBJA4GYrkduPW8IB4Kl897U2+OO4g9L8FiVPanMz/1jE5T3PD7yBJ0S8+3IK?=
 =?us-ascii?Q?VoYuBEgDdxJHr66sJtFSqXSzco4mnS8U1AGffIjG31h9Ht5Yuzmv1AsTE7Xa?=
 =?us-ascii?Q?21tCAmenBVyMVndZk8enjXSUJCn1diT8DjQQPZKuZh9o67uoyjMU6QY91HU3?=
 =?us-ascii?Q?hlgMfFpGYNxfrqjOJatd2+H5bCReWN6TyeUk3bo/n29VWfdw6eKKHiwgjYra?=
 =?us-ascii?Q?cgCNBSRuBS/iNtCBSnuQ63ksIGLH+PUtcphVZqKHbi8exakBKNyKMwDtjR/o?=
 =?us-ascii?Q?E7iobi4iVpZBxWJxoeYJODcAjudsf8LjAMe2hpMvFGVCpsbZTaRn5ckq0h8I?=
 =?us-ascii?Q?QT+u1rFtJt+2FfxLWXdYHfXCFsvOsVpSZuNR/z3EdLgSVkU8t9tfvooqjIik?=
 =?us-ascii?Q?xb59ftSqFwqn0cVAQ2PCpFFJ/Q0st9kGxcIL0/Xdr0vYmGlgN8pS4CwCj/C2?=
 =?us-ascii?Q?o2SnwBYZctCL8NUY9B7zYRSr0m7i7dtXgL1moJwtwqD6L1DSgC5pyQ8HFq6t?=
 =?us-ascii?Q?fuE57qFnO333Y/nAEORE2KnUnfLvlZu1lMoXRNd/1YiKeLhhpugjKBf0K2ld?=
 =?us-ascii?Q?XyPP4/vR45AtRhhGBTpt9a+X535AIb4nlYskl4xuWmVLBmPTPvwzakEj5mJS?=
 =?us-ascii?Q?CWwx4qNHSwgWrhmu5m5ARgTLQ2Uce+NIJKOxkp9H0OVzxhVDNnEnrnXp20XF?=
 =?us-ascii?Q?Zzv1F2qD88fQlEWqjoGu4h37ANfod4dQ2nTEEdqGtvccGpKO8kaGSnrUxVnc?=
 =?us-ascii?Q?mPE+vF4q/A0buj2TuA0gKIzp5G0Oxxx2huEno+SdWWrjFclJQ1GJSZHZHdQg?=
 =?us-ascii?Q?YOSBVWrO/APpZh2IhJ4Vv+BrwknaqQjRRD1kbOoPvSsWXVAbh4F/1wp70Itx?=
 =?us-ascii?Q?qRavdH/Cd6qsfwTq+TzAmzNbgDS3RtUsXcF61hJYY477btNG9bqjLbveA+YY?=
 =?us-ascii?Q?mW20Vvitq9FGXeFEX/HGPgr7JRa+vd5Vz68YR2QB+UTZNtzIyZw4PEe2gkUb?=
 =?us-ascii?Q?zr0hMwIY3oBtW91UXdXmC/9/k02zAVGTJM7et9m8X7fh4/pgel0ZfnLVRHXj?=
 =?us-ascii?Q?Z1xM4QYjftolbzOhmVGxxHm53O/gGdkbsXxeKP/MzDhFisY3ynTCCPD4WVOd?=
 =?us-ascii?Q?CA8okGjj1OacZ9uuOzGdeTrxly77pUR1rJjO81eAyr8XmLNfUsDTybxHnr7L?=
 =?us-ascii?Q?1s3R/eLae5XNQgDDlzvPhQ9V5Fs2EMQreoNW+ffTCoOjDamDiixCGjwnpnGJ?=
 =?us-ascii?Q?21mrAtexXGjrIIkHgh1/JmmM1LhwNCQmYdqZSLKrkvp9r0yAXQ+BHDASGPMT?=
 =?us-ascii?Q?VRgPK20s9oXyEWdX04v05jvNyRAdxiLENUT/bFmqULzNa7i93QLtTeQohPfO?=
 =?us-ascii?Q?zfvwMEiskNr8pbhdCQE8uvOc98fHcIaVw4Yrzp/nUKUU6jERjr7/Mzk/CsY5?=
 =?us-ascii?Q?AAw3FZzXZ61QYTjV5hFqeUDG8F9++FM705GkT2nhxiVtgQZzRAATyiV74a+u?=
 =?us-ascii?Q?KvkSKEU22FTYmz/skT8Hy7FZ3QYw6GB0IjQV/JfwAMjWQK7kLUe1AKqSOqNl?=
 =?us-ascii?Q?JRIXIusx+wk7CB4LS0OSa30DGDlZWzqakkCkHxjELAkW1BsfiaBDyB3SOPI+?=
 =?us-ascii?Q?VA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: JgQitrBeXUM60c9uW+KuWq+qC3UsuDsaXPkRNJEV0zMYdloe43EOeOxoN8pIworUJkJmbPRiTMmhLX4AwAsIMTFalzaRtrKTjKFiwzrUIytHjXePwYhW6CSXQcP7Jx/I6G5DnHwJ9FKDeIFsAGonzC5kaG5rJAb4wdtq62hBJ2vJHtwQd7VIrybTOdGwM0lKLc48g/2G+1iOWBYl0nK0ZnLJYwEF84KJFrsaq02s2s7DwFmegHdOKZ4cyVQLrpkowpZYtvri1MFpE6L/4FbA+dQW3NB/dtsaDrt8/bTM03drds9CDri1LOxI84HXF+SOMcVkTucD/JQWBDFXdXc0dOxCq+u1SOSOJCKDSgoJOe/S4Eb8Xxyh22feAUKGoa7HDyluymfoLir+vB8eStbu0NnG1sZlFmdHmNZgCUkZsD/IRBW1qxR1b1frdlAX71xH/4x0vnO1WqnARkNHbjkU7zhEZuJYAzrbkspSjJe9rL/e49+aEanb/unhSyq468fcj1FXA61I0/shNICF8Fc67yT4kH2kXxnuHESsnZ1hB4OI39wpFgi5Ra9BF+8fCwNKIltTwX2tnYLZUak1cLETx0e32mpKZ9946s61iRgeSRs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1350f77d-6fd7-4c94-a48d-08de0fd1d9af
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 12:11:50.8564
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: QTh3RtQc91+hBMfdKnUQ/a4KBvcd9Yk6MeNcxW07ysZhRPbdhO8mmHzhtzPkwCbcoddjYphNVMy1/TwU/uZ5Qp83pe07q88+T3ERvnNhVd4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF4A29B3BB2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_03,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxlogscore=999
 phishscore=0 bulkscore=0 mlxscore=0 adultscore=0 malwarescore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510200099
X-Authority-Analysis: v=2.4 cv=N8Mk1m9B c=1 sm=1 tr=0 ts=68f6270b b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=x6icFKpwvdMA:10
 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8
 a=Ikd4Dj_1AAAA:8 a=69g8Iwx80a-1R0TaFSkA:9 cc=ntf awl=host:13624
X-Proofpoint-ORIG-GUID: 0feDPgv78MvtMg_wLrHFAk7lxA2Wbl7K
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyNSBTYWx0ZWRfX5bNuAqKL/toc
 8Opbjsw5K1oNPhbgNxmh1icS5fq0Pr5mwKtVMXbXydhyfltj9x29Gaz6X8I3zO0cy3M97C7eJwH
 akRKgXK8BGljtTDgP8f+wuOo8Y/H+9eXPAz5YohwPkV6jHjh1VTuT+KgX5LyNp2LEyEQN0dKjBc
 SFeVNCCJsTz0esXT++/onZf1gd0/g2XvjTX/VCwxnJh/etCqD/QrsgaMoAFk/Dm0tng6K4ON4ss
 05+GRraVssYc2mBdvEWiYVzVG5Kn8cYMCyIOnDjNiqOuxcVUORKiFbRwDpG28niYcDwnoC73nKe
 EeJAVen4yIwBq5cWhn//mQJxbWYAX82+gAaTniJTEIjf9vuhEAtJwqcqBwoRMrDmLNYvv9GtYTS
 boxO2nH241llS8bjyfI15wIaaPt9K5p+cTcLT6cNEACa3rsFeaU=
X-Proofpoint-GUID: 0feDPgv78MvtMg_wLrHFAk7lxA2Wbl7K
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="I/K6j4lR";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="qbR/xHxw";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Now we have the f_op->mmap_prepare() hook, having a static function called
__mmap_prepare() that has nothing to do with it is confusing, so rename
the function to __mmap_setup().

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: David Hildenbrand <david@redhat.com>
Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
Reviewed-by: Pedro Falcato <pfalcato@suse.de>
---
 mm/vma.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/vma.c b/mm/vma.c
index 004958a085cb..eb2f711c03a1 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -2312,7 +2312,7 @@ static void update_ksm_flags(struct mmap_state *map)
 }
 
 /*
- * __mmap_prepare() - Prepare to gather any overlapping VMAs that need to be
+ * __mmap_setup() - Prepare to gather any overlapping VMAs that need to be
  * unmapped once the map operation is completed, check limits, account mapping
  * and clean up any pre-existing VMAs.
  *
@@ -2321,7 +2321,7 @@ static void update_ksm_flags(struct mmap_state *map)
  *
  * Returns: 0 on success, error code otherwise.
  */
-static int __mmap_prepare(struct mmap_state *map, struct list_head *uf)
+static int __mmap_setup(struct mmap_state *map, struct list_head *uf)
 {
 	int error;
 	struct vma_iterator *vmi = map->vmi;
@@ -2632,7 +2632,7 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
 	map.check_ksm_early = can_set_ksm_flags_early(&map);
 
-	error = __mmap_prepare(&map, uf);
+	error = __mmap_setup(&map, uf);
 	if (!error && have_mmap_prepare)
 		error = call_mmap_prepare(&map);
 	if (error)
@@ -2662,7 +2662,7 @@ static unsigned long __mmap_region(struct file *file, unsigned long addr,
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d25a22c60ca0f04091697ef9cda0d72ce0cf8af3.1760959442.git.lorenzo.stoakes%40oracle.com.
