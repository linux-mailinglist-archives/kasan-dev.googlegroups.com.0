Return-Path: <kasan-dev+bncBD6LBUWO5UMBB44PVTDAMGQEGA3GYGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id C530AB81702
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 21:11:48 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-71d605205a0sf3559327b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 12:11:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758136307; cv=pass;
        d=google.com; s=arc-20240605;
        b=aV2aF5KoIVXVPrU+2m+ISm/CYO8uT+uOfE3mrSoSluKCXkoEbTIf9DF8rLZuO2civk
         aCEqIDTnhOL+riZoSIQHthNe6l7JFQgrIYG+mIwLA/SLPtxg9VBI/0Fh3d7WdlwJYVwz
         cXo43mNsvm/bRHiiti4LT4xTaAYmUzQK+Ljq9RQe5MHZDoK+EPnV2281Db4a7aKxZnh/
         7Gh6+dcUfjcBxJziM22DQnyTj5ATWZkvedo3rsbWafVVzHxJAo3hD6sdkbU3y0xqSYRj
         Z+QMQFT8cpPyeD0bFJBi0yLyXjXKXbCnigAePUGb536I0WNKXBX3fRQEHlrd8BbbwznU
         Cv7Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dQWvABZ96qyEVtzSiZwP5cdauTNGEyX9jGGvCy81PJs=;
        fh=rG8cF2v3Pt+L3kv/vwrGY34CLaYfTBtUEacR7Z4lE8E=;
        b=PnH29dWblNIdezXd3sSuxLWdgz8Fi13WQgo3ABvNe21vW8tnn0c1tNwS0iR3DqCYdh
         XNaCJTULKBo7YVEuDmchYN3qXwmKs9m8D9jfbPeUtPrj8ToIyq2sN83gGilNTldvQ3Aj
         jV0pyScD43v0BCdUoa3xId28Gf37ax+Q6A2gx4YxoAGcMf0c/S55K5EnmWVjjn8ZD5A4
         aVKueI4NLmmBDeyFMXPJHix+d1tC/swEjCIVpimUk2D80uSvpEeyxKk/MHssYQ3JH/Yd
         2JYAARe7+s/A5YlPVZaHPvdzPTzBZw+xnAMCIBINgcEc11PoetS5oc+ml/6LHLhwwbAX
         lMnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=H7wKR6ev;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="bY/R6Q/s";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758136307; x=1758741107; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dQWvABZ96qyEVtzSiZwP5cdauTNGEyX9jGGvCy81PJs=;
        b=cyqxUflADrnIyvZziUbpgv1Qsx46tGAS8iL3I7qfPRF5ZyzwvYItQ82a70X18SzuUG
         80RBS0UvKdJ74o8CpDsgJU8l75m8CAZUON1n2R2izOaeptfGaaRrsAlA2p9yBrv/vSC8
         PDvP46XaZtEZZyoPNsYnJAO9x2C21S5YcETXBkrs1QiHYz28tnNLjoyzd94B8Q/P7xph
         1VsEmM2P3+aJ7B0/gJg9bTAr1gM4bi6z49sSmSq7eao/x6oHHuOfIALIBULgn8NIgb6D
         jB+Tdait4NjzmYy3qKAYewOaotSDe70V8QvCrBdD3NEUp1zyM7O3jixrJTDOk9+EyUsh
         bHiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758136307; x=1758741107;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dQWvABZ96qyEVtzSiZwP5cdauTNGEyX9jGGvCy81PJs=;
        b=uTNAeJAGo8gr/BfWZ2vjb30s4ik77mn9MX4BmAs9gnI/6P0Rs6QiTz37vyH4oLwvIE
         ioRh4IvIGxywfbIZmY5Jjzx/bYo+1fIDyTXlvWF+bum+3QDGx81JwQ0kIOy1vmgFo5ZP
         Cuq4Gm8mNKwvrsYCnZ/YbJIfdOyAQnI2/mWO1YmL0SZ/NWOnSTFxSt03FoMRuHYgfL5o
         4kvJpa2Y6TVJPB580Uc/ic3ViZ402sK2WkCp99YRmvnt8jQasZgVba85OEVheDK4rn50
         fMpQWEoAxwsUm9fYBOh0eOJ8XlGwhX8KHd08B/AZ2zoI+kZCajB4i2kN2D0piY1eQnQ1
         QlKA==
X-Forwarded-Encrypted: i=3; AJvYcCWoTuwTKvvcZ3qIZt9Y9vaqb3d+EnN9+5PqVOUH/WKOE0yjExBf+Hv4V+P7T1IC3GoFJJKxLw==@lfdr.de
X-Gm-Message-State: AOJu0YwKMcDytdqxrPySrlOD15emAfdQn7Tm10n9eQoX3TD4pv98k7Aw
	5yQcsanZ1rwNzpS2MYZYP9JCwDUhi+k0IQ6O0MWU9ZBElSa1xyk3E1P6
X-Google-Smtp-Source: AGHT+IHha3pwdonQ6e3c6oQpJK71YlWorsk3XvQh8ytgyhXMX7bRfbQycFZl/FyIG1CJJIh4rbTkAg==
X-Received: by 2002:a05:690c:88b:b0:722:77b9:705f with SMTP id 00721157ae682-7389284e615mr28271777b3.39.1758136307305;
        Wed, 17 Sep 2025 12:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd67oObQRI8XlEGIQ8a/g5T4H7stEkaqV3z3YmcyQaWyiA==
Received: by 2002:a05:690e:4304:b0:633:a0e4:d222 with SMTP id
 956f58d0204a3-633bdcd9fcbls31561d50.0.-pod-prod-01-us; Wed, 17 Sep 2025
 12:11:46 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUj0+gPXpx6vzkubzJCYlXhnstwEWNv3IJ2vCMxVm7CjTgYThGFo+JjuDm/qdUKCRkDNggBGhXe2bo=@googlegroups.com
X-Received: by 2002:a05:690c:638a:b0:721:6b2e:a08d with SMTP id 00721157ae682-73892357082mr29455877b3.30.1758136306350;
        Wed, 17 Sep 2025 12:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758136306; cv=pass;
        d=google.com; s=arc-20240605;
        b=U46G+AaJePfFTnNZGxpMLVk+7q5Ksaa/Gp5cVMvICu57McvPZqPmYp4fxS7tKa5Oy9
         lmLc1KmEInhCnyCiXlt64iZY5EAoWTdvNCLegUQPIUcHqoCjCjVS3Qwje81rVj1R09hC
         tL/CM66xkNELWQh/hGpVXf5OExJIxTYJ+Bgcaft6BoTQMSYPlpvffLOpO1Aqf4vz/rT5
         fjfZUY5w+HV8qqyUOLgRwijKlhYpUWhI2scSG1Yt16EutUAGnoseqkj552HRccVQU0Z7
         mmzE0oHWaOcnJWgytJWBuIYUYmIYWssBa7pkFUwd5hwCuo+kDax9pRtclGxtMUnnsOFy
         SlRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=hb/gfX0JwVYnbXTvQa1ZmKzCKlseHRvNPsGowFPJR8g=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=hI4j2K1Mgh/TwQ0qiR+8H7HvGD7K79Z7KU8fDU0tlrIgOmWNz0ULOSs7bNuizwrohr
         J246xfPQuQou54taLa/Kl8xxSHsg3ON7GeByQ8ogQzS3QHLvTZJhDkdAQBHZAKK6jADk
         2GEE5psaOU4fu3IP2eTI/fJoWxf8Bua06IvaE2OaGuc1a8WzFaR1+XND0sn6gCjQBrvL
         ELL4QLvQzjk4k7fae9fYBkZvnzu+0ok+pJGIYDX6s8S7eQFzYIYlpn2vP41NgNYws9ds
         7A9fzV6/XuXqc/deTi/E3S8mhppJFPsMzXN4QNlYW2bS3hT5N1Zu9wnRH7bi/A6qD03y
         aNxA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=H7wKR6ev;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="bY/R6Q/s";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7397186e158si147947b3.2.2025.09.17.12.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Sep 2025 12:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58HEISvD007336;
	Wed, 17 Sep 2025 19:11:37 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx92001-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:37 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58HHmk6Y001628;
	Wed, 17 Sep 2025 19:11:36 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013068.outbound.protection.outlook.com [40.107.201.68])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2edr1x-3
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 17 Sep 2025 19:11:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=YzPP4Sp8ZqF7MMgoDaS9EmGF9YpCQCjwf8Zbe5K4IaCq7oO7FxBCKngDGH1X2sI564C9mTxkvgEef8CxrH4o4r10zkCHhe6gw5BK2tMnw9JPNHTbUMQrHlWHR01VVQ2OuobqNq0vaNSJPIImnW3Ah+P30xNqWiMOm2eXVRVfNpY79RwWK2P1Yq64lOfPmteEXRSaVicsDj9J/BAdhGuSr64gyLguEfjLw4KBs1AyvA98yeUu2ATP2nlO1sCpQT9E6W7ukqJHpf76EGKHc5XWyv8FPegffEXP1tI6kfM9V3q0sZW+CkYnJ1LAAqbNCbNLKuaNVCE2gWdkZMswmDU0Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hb/gfX0JwVYnbXTvQa1ZmKzCKlseHRvNPsGowFPJR8g=;
 b=j7Ud7xijXyBw7iejsaL4pCTkkflLOdneF2p4yft/46A0WGVwnY+CeWoeEiU7c8x1rr8zR8VsQHwjXHth4o9j0Put+DHPC3OTrTf/eg6sUCUygtDLHEUG+MHy3fP0dD4Xa2qgVLYUGKlXEsjyHjHqvBjnH0pfFtmOSKrmgZGaPxfnCBuIH1be+zXpLGge7jP+V9v9RAXGMddpNU1by7lvrYruIpan562mbwXfrz5DC9u3NOMKm8Ari7ufwF/Coi0qo0SINvL7P0st5Mb333C3gcqTxVzBrLQhGzFEe2HEKG4U2eCXoYj4Q8AElwN1WmfjDzEM5w7Jmmtmhz6kVmTI/A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BL4PR10MB8229.namprd10.prod.outlook.com (2603:10b6:208:4e6::14)
 by CY5PR10MB6189.namprd10.prod.outlook.com (2603:10b6:930:33::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 17 Sep
 2025 19:11:31 +0000
Received: from BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582]) by BL4PR10MB8229.namprd10.prod.outlook.com
 ([fe80::552b:16d2:af:c582%3]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 19:11:31 +0000
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
Subject: [PATCH v4 05/14] mm/vma: rename __mmap_prepare() function to avoid confusion
Date: Wed, 17 Sep 2025 20:11:07 +0100
Message-ID: <24cdbee385fd734d9b1c5aa547d5bbf7a573f292.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0398.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:189::7) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL4PR10MB8229:EE_|CY5PR10MB6189:EE_
X-MS-Office365-Filtering-Correlation-Id: 2da66b6a-a778-4712-5d9f-08ddf61e02af
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?DuZyueFJy7XVQDSwgaUob0+sInJwJ5nG2r8sulQnr1VFx0/qKaQDQIabbyxh?=
 =?us-ascii?Q?3vK1p+WIctZeWU5Y/294cH7NcHZLBrXGHIcavNpMxQtv81eIDqduGO8+39Lb?=
 =?us-ascii?Q?JYP5ya8oP/dQOOggbTLc/kJNinuA3Usb7uYMmRbbwQnS/H1dw6BX4eAHftlR?=
 =?us-ascii?Q?Ug9d/YacixkPtXFcr8L8BZ3vjiUBbWVUVH6+pr06u53Z/0EweJDL22NiYmy6?=
 =?us-ascii?Q?x3+5gqr41P2QZLjRyAVArBsP3rG5re72vUS5H+KH9DopJQPlqJqDcKri2VJv?=
 =?us-ascii?Q?i1aZLSXexNrE27YnE6cMXKhLpAkWfFejZq4Qt07lBPlZm3oR3SzDG4gMBsNe?=
 =?us-ascii?Q?Y9kNDIVMyq0y9FHgtyn9FXXTmuUJZ1rkxH3tuOnONgDWbyP6E1PybmPTCJsE?=
 =?us-ascii?Q?uDoMvNPw/W/TiBd0v70CqJQIqCfSLrs8M99JCLlT7Ope1/nH4qHjzQiaPwMS?=
 =?us-ascii?Q?zf5LMW48E7JPzNm4DGk13OVCH75uknHSTFtbqVPmRQ7pbnBk9FmV/UoW+ufB?=
 =?us-ascii?Q?xR+OnupeaY8z6xidOUFdbPNkyVtBRerSqUWetcqK5Ci8ZW/VcV/QBERwAKtN?=
 =?us-ascii?Q?Y53WA/ehp1KPHB0GWq6pPPfZ71hFn7qhO1hyWi4O8S9w6iRwgrjWfnMF6ZMp?=
 =?us-ascii?Q?HypOKf07hN3B8C1JrbTcnBLyxMarEcCMlAwVFF+DQzfcBcDGgP65TwAOJ+QW?=
 =?us-ascii?Q?OrSeNMX27V7tCjqmEDoji93877EqgIMMKpUa05C+ku4kJ+eF5KNPQLeUZgpu?=
 =?us-ascii?Q?BXhD+13N3P+K6kbSADaVeSLmCYDBTqgdqI50IKrLfIXghJ2HaB2hndAMc5aL?=
 =?us-ascii?Q?FJ1Od2wsVSOgJAEWhDZnINdRh1VihRi45LQespn0F1SXnZ38AMpSxtWhrorZ?=
 =?us-ascii?Q?QoHqR0Bemi49s44/mV1cLiRoLD1TVtYNwWP2osIVkzxl5uITONJDm+cyjuFo?=
 =?us-ascii?Q?gYwTkXMz1Ps2zG8gQRf+INqNpUWISvDCL5cbk9ilBlt1cjG6fvAt8GlrGNhE?=
 =?us-ascii?Q?xbCRv+/DMS3Q7gOmmhLL95K4VNApGG8etFLV3h2B12vJQo0apgW4zTvohGdV?=
 =?us-ascii?Q?uOBN7fd5c+Gvi/4q+mo9fQyekYmd46FxNGpiJUuYpkB9HJYR9CAix03/PS4N?=
 =?us-ascii?Q?7GI9jz85N4pCUXl6DM7BFde4yPhjzZvsl3w/X1xC6qfrJeLhST63qoRr9oks?=
 =?us-ascii?Q?ORhWdiRbuVOoEbRHvIGiae1WJm3S1KekrefIBmcAsrruq3sTcXPE/FfOM6MG?=
 =?us-ascii?Q?I6/tXxj7MG3kRh7VGMZ7VoPf6x+Z4ifkfxUljFpm99FOfyJ4xp+DyYV+/kwM?=
 =?us-ascii?Q?bBguJ+D4DLE+rzuNpICmh8bY8MELxsKPuvG+RpSiPftyuwFrq1dA/PvBvtOj?=
 =?us-ascii?Q?P+ybIGT6gIyjfpWMewm8iFMVo+C3Hp7biceQQm3Xl162gIErr1Ag1Xi14k8Z?=
 =?us-ascii?Q?LagVQq0BCnE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL4PR10MB8229.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?qXAeT40Eq+2p1mkkTFXMAs7P5ie+aYylfmBjQJ+hvkrZzJSe6Lb8cFvKyPEM?=
 =?us-ascii?Q?69kL8+6pdtsBB/Es0MpknUD74YKDbbal6QDevsBJSAGYWWZYKuwtPi1iS9br?=
 =?us-ascii?Q?tV2P8ylX47wTYekX4zyjCBBHBdvIm1tus0A5HRXa7Fp6t6yDthr3GJPkW5qY?=
 =?us-ascii?Q?tk+iiIeVAXuUUJQobse9KmLHpvDGj9chqBRexyqZFJTXS5zx7w48nWE/K6h+?=
 =?us-ascii?Q?s09UQp9l+1PwJiWG2hCUVNbm20SY+rIcEEij8imuz0bfbEnF+n3IlubQKtVp?=
 =?us-ascii?Q?fivypTmhnHj7z1Cv/WdvPXT6dMoezEzRCaxXdNyh0/BaxdPnxplsrvuAP/td?=
 =?us-ascii?Q?cbJxLFWrCDrDkeEeGWIA6uw5KjPfylCjN+8kiojaY3tNbnZjdKpei3x9GSTh?=
 =?us-ascii?Q?RHT5xsk+FehzSWUXllZGYIUYSOO21kNSvEXihnBUegfWrT0NJvtScgt+zS3i?=
 =?us-ascii?Q?2n2LtDydbUXLFS3PXlwcC+SreE0gdF1cCaadFZ4eXCq5TwtSzT4iWxcPxxi3?=
 =?us-ascii?Q?QUAa8hFwTNmVzQwEsW9BjaZyd1xwZ+ocuuOUwh5gbePLvJjW/4XncsJYabrI?=
 =?us-ascii?Q?dtF2OEHqrrYoxBpqa/nvM3di3u2BDy2qmbwYv1Py29tZZxDQAr4WTvKHEo0H?=
 =?us-ascii?Q?kBym32ABLPRBaM8oAk3og6dYHSBZ7yj/5yKYg05VdTiOj9usMfZCy8Z1qHwt?=
 =?us-ascii?Q?Mrf+F5mh4kJQ3IDRez/2VaDU9KFuyi9NIxfUlFlhhFkvYJQrfzVcFDnMN8dZ?=
 =?us-ascii?Q?gNNASSZWLTe6d6PCJ3GIfYGpwP1Qwz+hM4AZzbYYrjnphm1tqyDs9htm8EVb?=
 =?us-ascii?Q?a3VybpC2ZmMdaEp3xKf2LDGpwr5qZQBl+dFLfT8VDzCdxrL+aQ56eyzPLy0l?=
 =?us-ascii?Q?Rwnr1MTWMKXkgnk7783tfwEcLD/ZQekmI7PIKvGVilVHFm6uUJekWqnIxYEJ?=
 =?us-ascii?Q?LzJjA3Dvt7JXTPIjkSzgyO/SGeu+DlII8AEY9n6rst1pq5xH6inNxRcXCk/p?=
 =?us-ascii?Q?zuyYEtcIl07hLV6TOK2P9EN09a+NeiHJgjLgjK0Jg/DN/SA5oeG0/PGpGAAK?=
 =?us-ascii?Q?jr/ayx/q8Mc69fIEKS3wuMLY6ARg4Ux0ghplGaq56TE99Dv7sMI2TiC/2mLX?=
 =?us-ascii?Q?Gi+h/hQWvIVH1Z5zK14diU/JZiWTOX8aMZnxhOe7fdACz6wzS2DSukUnTEDb?=
 =?us-ascii?Q?Gd2k2x/Pey/CswvtPz9Pi4sFhVVC7z2oINCoVwzYUYTU+qQ/PRYzDPvcn7eZ?=
 =?us-ascii?Q?CyKiE8OmF92iq3G49WNSAza8KMwDxFuFOPf1GkiImxEiq55aU6n8UpXOiQcb?=
 =?us-ascii?Q?wrX+aXVcOfzmkUCbtaykDYXPfc6Zrl3GoItWGLAO5S2Iver4ZccGxWZB2L6m?=
 =?us-ascii?Q?p0qdtlqXhR6vjXuiVzLAmO6e/Ian/zUDOmBZ1202Ki5fi4/fSSSjqk5E4a2H?=
 =?us-ascii?Q?wu4eY3FNm0Apdjt1/FulcnHPE0ZGorc+EnyaE0RI5ylYsmmncYCK/wOSii2z?=
 =?us-ascii?Q?hrERp2lM3dvLyZ3hu62dZ54O99UJcV6J+khAaHaA97ldSW6e1lfCVo8hQvP3?=
 =?us-ascii?Q?nI7p+nHYj5hkSSn4HAZ3S/Hxb+cu+U3EtKxJNmmZh/9YEBEcfAq5MQvVXOud?=
 =?us-ascii?Q?DQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: LJ6Q/ogLgc8daSnjDlloXHI/pPCrywg28J6lZ22ipSlcIS3NlsUxcaYZgHbO1nsjRoOk9qWHMkWq6/+XdAXAMFNjsaeTkqdV7CUSzLltQGGfjGhwnvl7DhPAOYDZqEJt33XqWPGuLBfHuqgzAxjYaEjuA5iOrqs2K6Nx72bABibVL2N/HQUa9P3zlruPkcPzRqPPu5NbV9e3kAfU4OkfrB2/AeyfRqfOgS3CaB1xQqEUwlC7p3xu5spoD3/c5pfyJMfxvEfE5WyWkXkwRlGHl4SOvEu4TzFF+lPf0i7RxGdYL8m3Rd6hBfwwbQimOmm0vRbpfurHJbbYiWDGrnT33afQEVj/+vPrGXPVpPiUP52+YM5VOn4Clxvp2ipfSPITEtoqi+Pqt8D8C/gRbleGN0TTOUfur0iDzp/f8i7UwCEnPY9k0BRJLvSwK8DCIqojNo2yrgqXdDF6Cp7/NPDjsPCqL1nKC3WEJ1dcn/GfyDU+rp+XvT8/CxC+f65aIc2Gha+AVXp2BkMmLILMW8TWYQ5T3J5TbidZvN6WeAlGbjx2MMZ2eMuYHoRtsuERWm8Tw66KirNQ/nT6cqDWzeHD/ZRmHdTRXRdPp4/p3kw3dgE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2da66b6a-a778-4712-5d9f-08ddf61e02af
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 19:11:31.1518
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: yvOQadZ/0nls7jLTVdGloupOtuWOBWvAhBo4ZGG0FnMV5KrsqFWk/9rMOO2d2DovnobjCywPQ0NQHceBqP7oM3NUNsNeQlVJUqyoaeqtkQs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR10MB6189
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-17_02,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509170187
X-Proofpoint-ORIG-GUID: JGRnfS3eZXM2RRlIlhDXyX2fRx_MmBcL
X-Proofpoint-GUID: JGRnfS3eZXM2RRlIlhDXyX2fRx_MmBcL
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX0VbOwMXznAyw
 UvG6FCJB4d2OvOm9QQFFur/fvr3sSbvRp9XGcEekolyIOpxEMApbFncQ4GixpqoSdHqXoUiwW4Q
 wDX28Tcob0714n7vCtNJ1fi9B+rhgtdvNPilaFu7qj+wcY8FV69xGR8lu9DeyztuTtbrWwXhONs
 7eMlfRBSdd5Uv2JB4LPjfetr8OgUHmcVI/l1BoYCHB1WtQQpLPekXcovGEdAzG9IK/NdILfkvwi
 PnQsNK4IXbDVlbYMbNtW69G1IrtK/N9KjU+0ALG0w8RD2i4aKDCOZ94U410wvzoWnYx5ggqqMs0
 Hjn/wzwyMMRBeKguhj6kX8go9DPXxqAzhx3Ybcn+lIZvf6zq84GsLmwU6x70zGzCHlavOXULwMS
 qJ1+zRcV
X-Authority-Analysis: v=2.4 cv=N/QpF39B c=1 sm=1 tr=0 ts=68cb07e9 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=Ikd4Dj_1AAAA:8
 a=69g8Iwx80a-1R0TaFSkA:9
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=H7wKR6ev;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="bY/R6Q/s";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
index ac791ed8c92f..bdb070a62a2e 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/24cdbee385fd734d9b1c5aa547d5bbf7a573f292.1758135681.git.lorenzo.stoakes%40oracle.com.
