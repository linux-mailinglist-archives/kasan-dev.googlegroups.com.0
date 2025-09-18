Return-Path: <kasan-dev+bncBD6LBUWO5UMBBTEZV7DAMGQE4GSBROY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id A9458B83B31
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 11:11:56 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-756fb6a59f7sf762666a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 02:11:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758186701; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pw4Ikd73Ve65vCzVH8biMhQi/qL2MCRGLzWINQbdGuk4EwX6FrLF9rasRwrbuLxNW9
         0pE/zqlwjIbYY95UoCD1LDROsHpXiO0HqI1d5A1VR1pomJWzBo3wC2y6K9dtHkHWMOrJ
         PDbDgdFZdqex1gYl+WApBj9ZCfRTbmCUApGgFxJDDmpeT8aFvKPwH56/Scuazm5ElAHB
         GbWppc/K9QtEIDEAg4i4QhQgaMQ71h1GfdVR2A3Y4RunQFADojgRxrli5dhZmWrZ70B5
         qRxejVDNv7PehiSjrp7vVpyI12yabgIUNKXdncnIgyFKOjw2TCuOiLIra/vSn35XEGIT
         U6ww==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jMWF5fdzsGN9n8Q7f/wnsGe/zchNOQxM0Zd0wETUFZ0=;
        fh=QjE3KqdJHyKQRTS8cmD08+WmE2fGgvpyB6TQjjV/h90=;
        b=AvAcykT9neuC5Kw/2FVQtcU1WpGtbKFqEWfY/WkFmcRnj/nPwbGcoKTpZmhnIiEmel
         sWWlGh9UCXDLxGruXL52ENMrunEXJAC/weYZ/Px5FhOGOyXRRIWLvArPk1b5ODPJurp3
         U+i+FWlutkwjUeOMezQSiADSe9bWE6Kg2Tk256K6wm6TRlGOyLaJKTw/LiO7QFN62wQ+
         w9W1keysKAVSG9LrOBQS7WCfgXpHtrREgCWQZ7vg6+Baw4+jkqbfFh9XlBAJQAPGnBRL
         BCvHF3eHywWTvLo72wpZW74HJWpOw37yxVu/75eBTZg7AYcRM3r8WJMzRkVTwwW28Mno
         s8kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FFjepoht;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=epMPGkoV;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758186701; x=1758791501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jMWF5fdzsGN9n8Q7f/wnsGe/zchNOQxM0Zd0wETUFZ0=;
        b=ebQLEyZkqEI2hI/CRqjCCAOLYB0maEDheJ3wQdEo/qVAix2XE+K505FEizxB/VRyhs
         xIkfcDah1DOmAN/Rs4BS6/K+jb4cSN12pBgE0MR1FVLv/Y9tu+KUVPP6wgce5yZOlPlo
         beFMfeNPn77vZ15w614ztgHFF5CsqxSXTBA2aFwtH1bfDFJN1bsE2aTt9R1L+zaSmbvs
         jsHx1rZC4nJUkizMr6TFB5GdS4rb9SsHnjJIghLaX8sEuwEEbozN2rDwni9bVEwmH9RU
         J1vXVBnWn2qVd/s5RCD2la/fv64j16tzVYNsaPNYgMPaJLrvQuq3sKfnRrl/FbTZbUL0
         c/pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758186701; x=1758791501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jMWF5fdzsGN9n8Q7f/wnsGe/zchNOQxM0Zd0wETUFZ0=;
        b=eSN5DTQlf3u7AMDpt+V5jiuy8qWg8iSeZj9YXoCvEIp0druezeTjo53yb7Q7YmE/k1
         Zuk8jI4hxR/IYuzf3sAoOVVcmtLvmXMDtjdUcJAFpBuH8rNDa23KcY9zTn91Txz3eb4u
         B6yap0TxUKzuynlyHRs2NebaA9UrdRNsfCcrUqRsgFRLP7O/x1WhqIGVK4dimDD9ErHH
         8HlOzA3XhgkIfHgmw515M1CvF/CCBqJDffABGyx8ptN8fP1dogFrghi+u8MEzk1MuEtl
         dxFDMLEp9dSQq60cPUBrtTzL1RWWTAtdlwVbNgL2lpnxmPTOBoDvrbmjp1h7rkyqMJp5
         iIGA==
X-Forwarded-Encrypted: i=3; AJvYcCVVlq+FnT2CsHVHs7taEmmu+cHwleI1C6HrfQ93AQwZ6aIzIHBGmuAfMGDXtZUo94O4Fgka9w==@lfdr.de
X-Gm-Message-State: AOJu0YzyWr4MolDXAtttqvG+s/age7D5eqH0YsG+PLvfK+hdV9uRy2v0
	LvQVWO6dx6HQROkHA+doI/z42t+cFdUesPsyUPoGamSYKz9uBxiLSwkm
X-Google-Smtp-Source: AGHT+IHugNT029dKBovmKUumELWcMvE0cVEAASzNSawzA4sMOqrkyl5YMYLWZNA9QswcpAUJIGpTLQ==
X-Received: by 2002:a05:6830:7110:b0:744:f0db:a1b0 with SMTP id 46e09a7af769-763259c4696mr2981850a34.32.1758186701037;
        Thu, 18 Sep 2025 02:11:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4vlVt5YsnosreQJZYM24t8LiwHQ/X59b3fRHDE1NHxSg==
Received: by 2002:a05:6820:450a:b0:61d:ad9a:b7c1 with SMTP id
 006d021491bc7-625df4db16fls351198eaf.1.-pod-prod-05-us; Thu, 18 Sep 2025
 02:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWiOGYOZuDWnU+Rmgdw8ZMZ4TZceu1qL68uCQNRhaz9Z6dAKKFQmIvTATyiWdnX/Uwof3Z8Ewlh9Vs=@googlegroups.com
X-Received: by 2002:a05:6820:162a:b0:623:42cb:243 with SMTP id 006d021491bc7-624a66806fcmr2452316eaf.4.1758186700129;
        Thu, 18 Sep 2025 02:11:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758186700; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvCW5OeZ3EX8oLzM3dU5ZHCnSYqyS1y8anZ906qWOjmD6WnWZNA0YxBkwgBui9VDBC
         9fJITz5mjosuc4O1v8yV2jJfI7Kfcl/7d3i59bwNbPn778zCBgv7RBSiJpZqPcADhVh7
         4KjIbAsc/5ptC3Jz/B5KQjClyg8fA3onGSkAEpVFKCVYWAGlKG6/hmKDAKe5vbTSaLgp
         6xRZ3fYUAos9iD6WpuMr+WScyMEEoDAIen5mNrzY1kVzUfa8acAvhBDWeXTbS+CnzbkR
         EIoojDvPcUcxI9MNJcD3N4wgCf5iws/iBVCgKQzjjj6xEI23Ev3Pn0ZiZedqaYlYwDIB
         rxjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=dKThfl2gC+53Tuq0Ogy6vch39D32nM24wAfYWTCszDY=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=OI19oyKDDxbJPlSQmDl2pWw+FYAcz1oFj9Rtdi8Vh1cto5/Izujz7B6D1u6vlUKepO
         p/DZAUBngMwTxgxk3BaxFXXJXkVL8L2yvaNEKU2WcGBKgNpx73jC4jmBZbkLYUQ9JxJ+
         eFYzve0osHhWzBiAtynBzrBsvBFh1NQzcJSnyIrQZnDW49Mg2h5ed6p1Pqj4eInnmS7j
         ASsbrpMCjPjz4YNNLzbaHw5GMSFp8v+v/aMTHw3r9cHWau8/eeBNriqh/2LvYr+tzaze
         yPENzg6DEI2htvAkOAURqjyEsd75mCicl3TihWbR6awtlU/T30N56ko7EQzTMTxNbqoE
         kM5w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FFjepoht;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=epMPGkoV;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-625da075f2esi92171eaf.2.2025.09.18.02.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 02:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7fuHO021221;
	Thu, 18 Sep 2025 09:11:24 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 497fx9u3hs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:11:19 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58I7Y9J2028755;
	Thu, 18 Sep 2025 09:11:19 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011052.outbound.protection.outlook.com [52.101.62.52])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2eugmj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Sep 2025 09:11:19 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=oyYF2TuomaxkzzMubLk44d7+w6LrTSi9ILiXh59VPltCTbp6oHzb+EY3LUpHo9JvnknUsyDnduBoKuzWcIoC2T0IDqrcBTU6tIBTySkFt7fhuu+7vKaeXlKDyOp0kBhQ98maFvtnFMuScDVB4VIvgXBB1tVSk1+/RxMNFNQAdkkicuxD7ABaoh3nsXkbp1YCSA+LLwwSECaJKI+NzKE3/W6lx+8q/OEoCLISdYg5FwVmh1Ut4tUIIKhqw4i8T/mG2/4Qq9LBd2EKsJIpp2C4pEURQqSGdgEWlv9An9ycLyNfWWhF5Rei9e+N1gMDLXQWl8Fz4UVeYFSgJ4voukPpwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dKThfl2gC+53Tuq0Ogy6vch39D32nM24wAfYWTCszDY=;
 b=jUUktKouznQBK7U74899tG7E0cQ86AfO8piy11NAB4uOgx5kBj+my0yG9mfmsetAbQWRKRtbfgaZrQne/oA4Tslccdyg/dQHRFvP7UNwRUAHv0yue/gcl42rbm3+BAflKO94VqgyxGLB89o4EFQZpdmOsKam+7AP0Gf7n+GD84LiXb6BPcEqb7Z3KRAXsFSSipZqdinn2J84ccL3uOWz0IZYaxwzs3aEOUWhFa/vICJv9Dkjt4p6EFooZ4n6OPyi5lGhS2nDS13nzJbPae+KaOhHf0l2VpyRNZe1GD4f0NMox4PDlrO4i79MEYhnHHJ669XBJfpf9Shn+d/iZ+wLVg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DM4PR10MB5991.namprd10.prod.outlook.com (2603:10b6:8:b0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Thu, 18 Sep
 2025 09:11:14 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9137.012; Thu, 18 Sep 2025
 09:11:14 +0000
Date: Thu, 18 Sep 2025 10:11:12 +0100
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
Subject: Re: [PATCH v4 07/14] mm: abstract io_remap_pfn_range() based on PFN
Message-ID: <96e4a163-a791-4b08-a006-bdd7ebbecaf9@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f01f4d82300444dee4af4f8d1333e52db402a45.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: LO2P265CA0122.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:9f::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DM4PR10MB5991:EE_
X-MS-Office365-Filtering-Correlation-Id: 9c54b5c3-4c76-4aae-051f-08ddf6935190
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?MbqbgAf9n2oOb5W/NzemYhbQp9MVNOh7J8qTV6ZqyeTgAtrTKwqASvD9VRXy?=
 =?us-ascii?Q?kgKVjTtgXvaw/ObwXWfi2y4CqnkobuLCdZdXdfb+lS3VdyNaJOpObzyKLTNS?=
 =?us-ascii?Q?C8naXxfnVqx0owPp75gX++UGvoZ1BttGZOwPYmszi9L/M8hYQDoJxzkb3bqu?=
 =?us-ascii?Q?HCZZhexr2PcZwNIiNwHhDhv9nEbfnw8W5LDuyni8j1qINv+Lpf+xWkRkF+PE?=
 =?us-ascii?Q?o5nNeW+USGNJP2Ucia1V+dyUf3+jkd9wSYXVvALuUo+YqZ93C8/BuwaFXjml?=
 =?us-ascii?Q?o66bRqMiZcFj/WhsJMrkOtmdDOVBBEXGBKSv7QVDKx9F1J+N7Morg5gQTpfC?=
 =?us-ascii?Q?lRPqSrfeWZ28zs6NojCCpPtKRPsYZqv2ZHq0AKXbQJiJQtMWNTCtuUDdQ2QY?=
 =?us-ascii?Q?Cfv/SDIbQX7vtfgRpRJpCwFjve7zlP/CNF52NJJz2enq8BPjZGX2nQHfyLBZ?=
 =?us-ascii?Q?ktwhgZm+jZz0i/KsSRvxdZpGcZPs4r/k5llOINBjCiCMqGp5a1kw/lENVagG?=
 =?us-ascii?Q?EWkGYwnCDugjGK65P80tHcwx4CQE0iiHp6Qj/ii83ykJvsGen12ZwEm02nxO?=
 =?us-ascii?Q?7FbJ4ry2P4YzR4hOfkiRwVBznoMDXbxu8/tJcoZS1ktgDhEPx18Q5U59y0Hf?=
 =?us-ascii?Q?kK8Rq/28/UHEx73b0tOCztMJmnD9iY+hVgIyvxA9nY47qX8eXdkBdwRnyVh4?=
 =?us-ascii?Q?d5IEgyT1MqkZSF3rdSmN5QXrD/aduDAsKBDJjgS+oH/DYzwmRiqa58LXIRDC?=
 =?us-ascii?Q?czSv7OpCtXlVNUVIVEbWU/HcuGrGd0RZ89Cuz6FEMSvfyjBkPWwrSuXu30WQ?=
 =?us-ascii?Q?++lVHZLUVREsmbXF3Qem1EvC1tTtboT3/1aWpxsGz4ZbcQ9VjDvynrSS+/pP?=
 =?us-ascii?Q?gDWZm0azgHuebjSAzdjRwjILWiz9fTRSiJS33R1C6eF1bIP6DVNb58f2Q8S7?=
 =?us-ascii?Q?vtcNYDSS7CNIUW+OxhnCLtaip3cyLdE/Z1mxf9HuWQmIjGGZrm5mvnVVmKGq?=
 =?us-ascii?Q?pzh3kPBjwAbPrsf2M+beSADVXLHU5v4u4o30aqbaWsVNgTHeWLY6FTNV3JCv?=
 =?us-ascii?Q?Xjh+Zl5g0w/q9Hn5qm6+uPiYc6Cw/iOCSSqh2SLTqpt9l+wZ3XFF0gRqpwiR?=
 =?us-ascii?Q?lzyKSrdJL7VTUnXa4tgpB6wXAiDGyCsboeIAkTCTbr/r0CXj6OcKEa/8MqZ9?=
 =?us-ascii?Q?z8MVXx3E16Chm+oHUwKiVUnDmEUl4+I71hz583X49aSY8EDKwIyhg2nSgaox?=
 =?us-ascii?Q?/SScm2IQFX3r8HSd/HOKMlQa66hwFeoF71sziqLVuNx4ckVxXicSm5UTqeH7?=
 =?us-ascii?Q?Gm0bg70NrvjYfiOfGgrfbe5rKr0UgNtywY/ypwYnfVURy8IEP8k2eMkLEWny?=
 =?us-ascii?Q?QRpDNrvz4SPvFWqHU/B3sfwfQ+4sQMOERNoPPvZwxgblonZyq/AraJ0jh2kb?=
 =?us-ascii?Q?i0r6TJdkHMc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?tZCoePQpNjFfqBigTY5a7RP8Z8BHR+riCGcrMrO9Ve0kM4fV+tmZ60QU3e5E?=
 =?us-ascii?Q?zKbo9clMa2+XVXUYpEDPAof+bZmVxqZj8IHJ+iM7j/c3GxFvuJpH1wDpTMUZ?=
 =?us-ascii?Q?BmjNpUITzYPhfy2Mttbq1szgIv1e1n1fKJHDMyKeji/vzeYSaVeMyzNv4XX1?=
 =?us-ascii?Q?H2adEKJ8h85v0mrl6F2iIDbOMQf+td/wr4yUVCfcFLH5Nz9/rZwE8dNbSwX1?=
 =?us-ascii?Q?F+Eh+0Po1QMqp77xQCnTxLPx9USciRMWncubla+YhLNNQ+a2PWuoVc2qmKza?=
 =?us-ascii?Q?zrtb08l6FhWWhFjd3ax4IygF41QHl6gy8WabV1Sj4Z+YdUenGE89lhQuvRJa?=
 =?us-ascii?Q?0+YL6UBGZuNYMlX621ILLdXXJ8LAK278xRH9BYavoYbOWA38F8gA/7XA1buK?=
 =?us-ascii?Q?WJrzba3bSglrHrRp4Coj+ennhhq04xYyt9qzbA5QEjV96CYJ9VOw4mLyMsEQ?=
 =?us-ascii?Q?fEI2gae6+u3JPKKZyghTvp0uQIdKWgLwKhwMxzyjQTbhqcQF57h06Be4V10f?=
 =?us-ascii?Q?syaGoqysKXP7iMaYUDhWZKR2ODhTYz9w2bIX/d/SBdZ23mglQtf1IrAp4OKe?=
 =?us-ascii?Q?ae838qV1t9mHPRfMBuDGQd/r//BOPwBkDIYXA+krFgCcfduwv/O//8NB+Xeh?=
 =?us-ascii?Q?o3nFZqO6//aIM8ZgyYc+xA6jZlSNiq1d9qaKfNjeKF6pESk9uEYZ632PSCiC?=
 =?us-ascii?Q?AW/C0We0etozViyi28sm9gLVO9NIMilwCPLira12ooHrPwpobj37o2MyrFrW?=
 =?us-ascii?Q?YznGSzw0Bi+QgL+pWSJxLgSst4L9jzWBl/VNme8KLobkGUDfGtPcoEbtwZQg?=
 =?us-ascii?Q?LeSxV7ATeZ+tMdkmk37pJjCBMmWPUDY4TSML65s/5ChUoiUSmonEAQgK2p0t?=
 =?us-ascii?Q?OGH58ReDet5ITfgdAlB4fJpXI7iNnrNJAYzGRlFaMRJs1ZYyifw0WU8aUvWC?=
 =?us-ascii?Q?dHqDC9pBugmo7xGvLRyMr1pGmT25cjQ+HbaxJ4KRASSCNFN7XuJQGjJBxDsA?=
 =?us-ascii?Q?rWy4YIPvKx+WWxExeQbwcrf/zLbUGP6Mz8h8LItHMZ4AoxHjt0Dh9a2m2SAo?=
 =?us-ascii?Q?L+aYzaxXl6Tg9gS3AG5nN8oiQ5I7utQ918FjxOQZysgGaIPM4h4G4FGs2N3o?=
 =?us-ascii?Q?HI43/rLGJ4zp50yGJ35S8abwEZdOpUeSFOMCDM5Fuxtim3pKQuzX/1jDKC+9?=
 =?us-ascii?Q?IcTusY+2DX/SAC4Ohm3EGng8Um+d8uOawrF71J8v4/QnHLWaZZiRwV/TrRD3?=
 =?us-ascii?Q?HjuoNHX+uNOX3ebEzfDUhuY4C2epL3R6MIHoIIRpxZaTDzj6Dv5y2mU0DsEO?=
 =?us-ascii?Q?/GNLl08ZoFd1s2y9nfehOjQcFPDX+mwYUl6lwfKALnPssh1MM1Dr0dJZTWl8?=
 =?us-ascii?Q?nheSv+zzXYsvUGn6mKrUcxLC97Nncb9214sH7nSSNTZIKBxi7NBdycHZa6Vk?=
 =?us-ascii?Q?UA1IZistCKZVLXdUHuNUhnDnfMrwOPM7gVmA8m3lIzkklRz/P7jC72zkuJ92?=
 =?us-ascii?Q?qxsWbZ4iG9CeEbjZprlIkPk08LgIpVZFXt1lY0cWs8mUHSmtFbCmADUiHpvj?=
 =?us-ascii?Q?yUhKeYYLFSuW05K6GVRwuTWulS5bOLECOJ1Je2YbgRrP8xO1w8twgGf/aHEA?=
 =?us-ascii?Q?VQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: PInHGD3yEJo8Eh6IF+iNjFuBehdyCyFyE3jCrViryOeeiM5WeiqPfjMEMTGL5OQ0kgUO7bCMmYPE8sjJVj6NJfPQRwG6e18RPj+a5ZxxBJKxwI9v5K0qqDScPXxizGyhz5N+P04U9ujJoKvY6+SWMUpocJq3iYoYDThnBj3J44MQ9qLkKs0rN7gnjGII7Zvbm+ha8W7ZFTerAsBpRCGfhC8CIKCfaCT9BYkhRQdmLlMdA9jFwoISij+wvBGg13kDRzPEbSzGAC/5Jc1926TcyVM9mq8nP68djOwGHJpevEdLFO/wKtdioJ1rgQbgdbi9H7H0ZwdBgKoqAmcYzl1TkYijZaA4FHC/Emx2xA7UKyW5rzqOaSne3YeUdRmoMmtModQjP7MBakXhigLeIud0T6dlblDJKyvaaBAZvIvbYBcGfR2YyQo87yXx8imBY+cW/BCnLCTmx+xiB4kJU1bvWf3RjBUbELMK1svErykD7HkRyk60xcV9ymz1JsxRpXRDNLsmPtpjIhgAOUeG2EkkAvGOg+jjCN/GwzFFuyOcEd86Lm+phno6aDIKSwOc2ejHNUFcF5yh/GnI3qqM/EHFJ9eBc1apfIgyTk2ZNyz4X8s=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9c54b5c3-4c76-4aae-051f-08ddf6935190
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Sep 2025 09:11:14.7198
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: XndcjCiyQUEfHHACKH5NNrZ4pnwQ5nHmSIuxGI5a+hp6iBrSvJAujQG0ySYx8p3QjyT+ncEzm1bw4e9ccyPPmUud+8VzLl9cQbWaj4IT18M=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5991
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-17_01,2025-09-18_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 spamscore=0 phishscore=0
 bulkscore=0 mlxscore=0 suspectscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509180084
X-Proofpoint-ORIG-GUID: s6DuGrahn5g7J2SPkufbrdTVoeY07u3x
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTE2MDIwMiBTYWx0ZWRfX5QNGX8zfrhYJ
 jo/FV0+ezAnDE3SP+2bJnQBrMCw5gOsDdfxELeCGT72qTC7cDHf5XmyE86IZ+nf2H8PxyY31ft2
 JOGurbxRn0QlkLFBkgiZyvdd63Mf1U/Ib2kJLjiwafxWfQAiTcm+wgb1mqbyRfNmuhgWvie9mbQ
 Yrb64KZSDPqpR5YgaQtCdFGSwxc4KzQ7GUW/wkzkExutuTjHpSZVi8Keld3wucM/BkMSOdAIFZ4
 Ccfinmxk9H6h8wiSZ3yQ8okLeZyErNFCMR1vwlHfjLzkjY4IQRATqweLKqLnsgfWaw7Fy4NA3yR
 4GMgCIjJ3PvwLpIIe8yrE2pnw2ps6vWWl2YJ0iHRdKUASKP5YIRk/2OSDjTBoj/Pp0gqbU+i25Y
 XBn4qiOx
X-Proofpoint-GUID: s6DuGrahn5g7J2SPkufbrdTVoeY07u3x
X-Authority-Analysis: v=2.4 cv=C7vpyRP+ c=1 sm=1 tr=0 ts=68cbccb7 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=fqlvQJdzR9ZGhYB2XEwA:9
 a=CjuIK1q_8ugA:10
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=FFjepoht;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=epMPGkoV;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Hi Andrew,

Could you apply the below fix-patch please?

Jason pointed out correctly that pgprot_decrypted() is a noop for the arches in
question so there's no need to do anything special with them.

Cheers, Lorenzo

----8<----
From 9bd1cafa84108a06db8e2135f5e5b0d3e0bf3859 Mon Sep 17 00:00:00 2001
From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Date: Thu, 18 Sep 2025 07:41:37 +0100
Subject: [PATCH] io_remap_pfn_range_pfn fixup

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 arch/csky/include/asm/pgtable.h |  2 --
 include/linux/mm.h              | 15 ++-------------
 2 files changed, 2 insertions(+), 15 deletions(-)

diff --git a/arch/csky/include/asm/pgtable.h b/arch/csky/include/asm/pgtable.h
index 967c86b38f11..d606afbabce1 100644
--- a/arch/csky/include/asm/pgtable.h
+++ b/arch/csky/include/asm/pgtable.h
@@ -263,6 +263,4 @@ void update_mmu_cache_range(struct vm_fault *vmf, struct vm_area_struct *vma,
 #define update_mmu_cache(vma, addr, ptep) \
 	update_mmu_cache_range(NULL, vma, addr, ptep, 1)

-#define io_remap_pfn_range_pfn(pfn, size) (pfn)
-
 #endif /* __ASM_CSKY_PGTABLE_H */
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 9b65c33bb31a..08261f2f6244 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3672,23 +3672,12 @@ static inline vm_fault_t vmf_insert_page(struct vm_area_struct *vma,
 	return VM_FAULT_NOPAGE;
 }

-#ifdef io_remap_pfn_range_pfn
-static inline unsigned long io_remap_pfn_range_prot(pgprot_t prot)
-{
-	/* We do not decrypt if arch customises PFN. */
-	return prot;
-}
-#else
+#ifndef io_remap_pfn_range_pfn
 static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
 		unsigned long size)
 {
 	return pfn;
 }
-
-static inline pgprot_t io_remap_pfn_range_prot(pgprot_t prot)
-{
-	return pgprot_decrypted(prot);
-}
 #endif

 static inline int io_remap_pfn_range(struct vm_area_struct *vma,
@@ -3696,7 +3685,7 @@ static inline int io_remap_pfn_range(struct vm_area_struct *vma,
 				    unsigned long size, pgprot_t orig_prot)
 {
 	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
-	const pgprot_t prot = io_remap_pfn_range_prot(orig_prot);
+	const pgprot_t prot = pgprot_decrypted(orig_prot);

 	return remap_pfn_range(vma, addr, pfn, size, prot);
 }
--
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/96e4a163-a791-4b08-a006-bdd7ebbecaf9%40lucifer.local.
