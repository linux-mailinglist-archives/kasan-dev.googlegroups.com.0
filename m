Return-Path: <kasan-dev+bncBD6LBUWO5UMBB5HAUXDAMGQES3236LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 411FCB59908
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 16:13:10 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-32e7c3608f0sf1561996a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 07:13:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758031989; cv=pass;
        d=google.com; s=arc-20240605;
        b=YsQidGsC4ahewIVbMMI/2i0bpIu7U6VQQgcJWPLoYCCoYKZ7uaqEpMN0Vm1StASVYp
         DpPIFJDC4ccbipgSTpRR/evIEcQaJztLHWYixt3fuBguVRFNO3jT5kjVHgAUdksy3I5d
         oGFl8bnhfqZUl7/v7XX0tmiutPuqQKXHEC735g63QmDO6xW05/FUbW8V1kTkHYI4n+cG
         /y3Xn1YS8Q7ft5VtGCvXqygQGu96SdOd+LM9havl5yS+ZBLWjJSm5wsdWVmdvWPf8TJv
         yJNSxr3L4dvNEMox0bDzW+TpXKnE93CkhjjmQku2g64wIvA27xHbI1bYw12PAVPblSW9
         tgMA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=iz5B00HgAdu29+ZmeiJqWssn1ZjlrQmt1ZFG5WVrJ7I=;
        fh=Yg32Dbto1r2jhUCKojdsEMWLzCtYFXvlFitjfbujO3s=;
        b=Y5PLQagkBlEA/OOtH3qvmQpkFqL02dl5QXSKVKzOuu85nIhJ0yKtU56AlJXRaIhc3Y
         hHNX+pReNr0oVKbmRffs90Kqkxwuk1WWR63KsoouLsOeZwcH8phUQoC2F4qG/Ihfm1vj
         gohyZmckz8qNN3/94Gj5zYumyiaP0pL5eQ9Re6w4m7SwnMV1I9O09T7EQ/iGk/5AZKzR
         Gsvh97l/co5j/rI668nuoBN+q9rRbQjWKpeZoNKsvtbxocsvJF5KBt4NIZ9hfbJy+Hoj
         RZO3lnWDuJNP5h4vrjQ1Y9GdF/rIkhWUgcD1zk+EZL/R5BDRcAylVOkIUaaDtLSIPMc1
         jVWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ViCxBXDx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=MgwDGF62;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758031989; x=1758636789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iz5B00HgAdu29+ZmeiJqWssn1ZjlrQmt1ZFG5WVrJ7I=;
        b=IShGTCpBRAzIYMbApu0m3JBTUPD0YynxdfbTabPvtiOtkHkbyG3G79o1ur2OXttoOA
         pHprs7nJmBstRVikCt3Rfk4dxdaB+J4xvXxKwLlmls+pKg8Yyw5Qdvanztr/bzRwZv0L
         aT81ATeKHO59yYp/yID1TPvf6PcvjRJDheiXPyVhYxdwU3rkcM13wFrTVqRsV1PPfCpy
         xDauEOi0oPM39bHilK8J7lKtFzag2IF5bJwU97C5284PYGR7DVwIP6Xz7x4wkw1Wq7IF
         1obi4poItINRwLgnKEmJn/ATgUoIMQBxPEBUp7eYd/xxPBGF50Zl++F0J0VOOsRviJJw
         nJFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758031989; x=1758636789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iz5B00HgAdu29+ZmeiJqWssn1ZjlrQmt1ZFG5WVrJ7I=;
        b=NVbbOIjsdKcQt01KlD8NU6yCWmC/d4Zv1bj/Msh/xLt89NEMe0vkYNu/DbOCHdDBIv
         b5ZSyhK4NbYlvp4cN9rgVJL1drJ5b9z6EnxQqEUs5Piwfmh2YjhgqueKcwFTNWqwioD9
         R128WbmTlyYjdIqqGJ12TngfX9DI5i3JAW4yOQCInmTIcwglkQ8AKBXUi3tEdEV4n8tT
         SSS79IRUDPZdcauCqkxeSgvItoCYKftQOI4vV+RPdNY1balxzagPgfd2jQVOHwW8DGqM
         H6b4zaBguWI9kiRCQrW4Kl+1rRNUokFywfIdvqG9WeAUaj3S5LDgQu5niNGImUBR1uLU
         /r8Q==
X-Forwarded-Encrypted: i=3; AJvYcCWjhUVm6si8tCCx2AQoNQhqj6QqEYHzgrAwY/RfwrPqpsOKB9Z2v+sgXzVDfS5WbYLA2wfIlg==@lfdr.de
X-Gm-Message-State: AOJu0YxsV1MxoIt/S5nB1v0YFaxQxMQo6XPwO3jKUCxawwjaEt4GXNqO
	ro5slBbDCiVl3MZgw5G0iU4NpCPdoR2PFM0yCv9ur4W48k8tkznRVryA
X-Google-Smtp-Source: AGHT+IEMezXJnPwRpV4NhNxJGowuGGhRWegvEYmE6n+2Bsh3SZUL5be9EBGBO85/pJiYVQ7PgaGA8g==
X-Received: by 2002:a17:90b:2701:b0:32b:bc2c:f9fd with SMTP id 98e67ed59e1d1-32de4f87771mr19315889a91.24.1758031988524;
        Tue, 16 Sep 2025 07:13:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7dm51GimbLUlZyUzXGov8XhM2zpk+vTxUaHwJtavcNDw==
Received: by 2002:a17:90b:49:b0:32e:43aa:41e2 with SMTP id 98e67ed59e1d1-32e43aa43fcls2204094a91.0.-pod-prod-02-us;
 Tue, 16 Sep 2025 07:13:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWtkt+gLgY0X7S/jel/676x38v2VSJLvXhAhpELsnluWa0dxRYix27KnjSBPxtswp6cIumNo/qpIsw=@googlegroups.com
X-Received: by 2002:a05:6a20:4322:b0:263:7cc6:1c4b with SMTP id adf61e73a8af0-2637cc6250dmr12253566637.26.1758031987044;
        Tue, 16 Sep 2025 07:13:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758031987; cv=pass;
        d=google.com; s=arc-20240605;
        b=OBMMI7ol7Sv9NiUIstQkxM1qMQv6LJMZap8IcRzY8fqNIImLrIwfWxfjJq0j4h5QBo
         MlnniK1Jjb836ahOQRc3bcaSFI87igmV91BzcTp7x5Lo3uc9EtQmS1GzacNJK5gs7+TD
         dx9mQZq9ovNdIYo59xmPQpyeALK5mU/9DfnWUsovuTruO/r/MywLOU3iHYMibdzDc0OU
         Tte7/tn/39MjXeT83MT22IdGWNMB9T2VBkkZdORG+xnnMVQs+43OLdODfGEvRVNiX8dC
         62XFpHYN3Tz7DnxdWaGv23+dVDuklfzPMosufsXPCr8c04uJfsn1SDlNnFP8bdjVNLwO
         Iqug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=kaejTggbpKxcHjcDgLIXGGUeTCj/gRXeUUEBDBJ15y4=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=hjpoRkpWPmBeYsbkVvbNWBKy0AthgjTR8bKg589rnwtniaZ21wd0oJw3B9KNsHvIFH
         Q8+TjmXcQswN/zcCB9iEXgxsM0ustMMtBmHrPQG8jifA2AZtmbF5cZw8mCAfL6SsqODx
         1ATiTjZh1/rFTLpMkaZ+mahQK4HYpLX1/pXVJ+e9tIClZiXxTLqKhbJZQIBo1nDyXh+k
         eNxDZIBJgJmpLRlODJM89XdtlFad2uMZv7DN+IgciMbELkWJoPL4yK7yV+OfRedQpxB5
         1p+JzzEMmoNeXkhg6fCto1hqj1aigZR4yISdphD5jOq1GKc3d1VcYunpHmicEA0jQGtF
         QE8w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ViCxBXDx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=MgwDGF62;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b54a386bcdcsi547362a12.4.2025.09.16.07.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 07:13:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GCvvlw022050;
	Tue, 16 Sep 2025 14:12:56 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 494yd8mspd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:56 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GDiCAh033752;
	Tue, 16 Sep 2025 14:12:54 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010015.outbound.protection.outlook.com [52.101.46.15])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 494y2ced60-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:54 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=E7CKapTled0wiAOlrOKSxSs7E45/G1lhUZvWWWS1r0dBfWcz6XB7ykHoMJ2AJw0RQwPZvfNp3rd9qZeppaKNKQzfbYGrVRQJwdNSVW8gkE8LMaG7vaHrOjD9T/8xGzXaUjsohE7aaJu9MJmF0Kf05pU+7TYNRvuOt0LvmmTik+JiStK5yMSnIZvrXixaC+dENcRIDmyoNuQ496driGuG0y0ujyDPZD+UZX94yEhw+1W0+ycEdpcKNwR8qsVV7dl00kT2rP0O8sHYT2T/DX9eSGK8iIT8nIV7fSfBCmi6KM1GyvJM7wV0sk9YZdyRShAPUDmSVTrWdyGfudeYd35FSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kaejTggbpKxcHjcDgLIXGGUeTCj/gRXeUUEBDBJ15y4=;
 b=kx7Ej+fjCcyJ5yCszEehnbsRauCEcsd+wwE0goDEL7GZL0N6Vqg253os9HnTUfrXys07gvmE9NThbEqmhuFK8vpgbZ9kLYrTQKMFOMtVwuPy9Bdhfp00ZMNlg5wYTsOpO2pO2O5TU2Cdh9m4IFC7+q1VnLGvbBJ45qtyhh4pcvafExisGs1OhfKk8jDTz19eQzAv0aBpPPYoNyLblMsiXih6yQS1X6ejU6+h4kHoKHyyj9l5UYrwdezqCsyoYhTA8D+K7T7YthQVTmoEViXF0vzb0N00mwFM37vqA+CM2AVdBvDkvk+1K0legW+B0L8NfIaskz0xmg9uol6pHiTYZw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by LV3PR10MB8108.namprd10.prod.outlook.com (2603:10b6:408:28b::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 14:12:51 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 14:12:51 +0000
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
Subject: [PATCH v3 06/13] mm: add remap_pfn_range_prepare(), remap_pfn_range_complete()
Date: Tue, 16 Sep 2025 15:11:52 +0100
Message-ID: <7c050219963aade148332365f8d2223f267dd89a.1758031792.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0279.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:195::14) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|LV3PR10MB8108:EE_
X-MS-Office365-Filtering-Correlation-Id: e467cb30-4381-4a81-aa76-08ddf52b1f0a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?eKAJEz477xMKZa84fYVXvVo4fGMtJh9ajTqBdWV25xyFuuNCUTOtukMo8HL3?=
 =?us-ascii?Q?M/H8ME7dha8WXl/744vZ5V9FuaGwJaPVFBbVykx7DWrfz8ZlAMACeMLjEhHe?=
 =?us-ascii?Q?ALvuNiWafGtL5kMAY7KS0CwLEILwVdSbkIa3C0vjIoYsOo0zn/ZR88NkN59z?=
 =?us-ascii?Q?BW3VWAYKFEi3DjfQCncMM3tanjlE4fN3YOfv6ATUOi+mM9Lcmx7VBwBwunRQ?=
 =?us-ascii?Q?zZSHlCsVPGfEvWv9Q4QW8QXWfnuTQbPdDLlmmIfCnWDJ7gWSuukGHJtrmrDb?=
 =?us-ascii?Q?lkzzqU3b8EKFseZOwyp0IOfbnb4AEd/K7uPHsF1rj3MRyGpeTR/JrAwkXhN8?=
 =?us-ascii?Q?JWfYuThO9fYZ7kCgvNpANjgGMFl5celpb91fdS2IrbqfIPD7esdGqX1GtTDG?=
 =?us-ascii?Q?7TewcvZGoaStX1ux6gYP6By2k74cJZJf/DYEReA0UJiJlW8vrlgKox7BJwGu?=
 =?us-ascii?Q?DYkqn4sABHKC8X80p9s8UiF0Tv1hFIOpeYWoNkmWVTG2v710q1voW4FnJQ82?=
 =?us-ascii?Q?ubu5BQwiSQBojTMh2V9Vb07sp4hRpNWNQ5yYVx7mszGdtN+gciv+GeeH6uWt?=
 =?us-ascii?Q?eHnEVm+GaT/Bil6Rg91iOKr3fVa56/om1qsRUNZ5yztqqaul4ENxv8LqA0sh?=
 =?us-ascii?Q?k4MLYIE7gdA8RDhhNxg1jQnkHyPvWCL1RE+GfaMFH/R72Lwz6MpzDv6bZ7kR?=
 =?us-ascii?Q?5iMCH8TfwBXoMnLkJc+fC6U58p+MFfrOBMEQ+gcIjWR8Ld1pcPcFHIwPVklp?=
 =?us-ascii?Q?aRA9w+q43yaq2X8bY1JWhlZB8fSppf/+r76hPuZRd9REtp7KUGyjS/F41Y2R?=
 =?us-ascii?Q?Qz08GCdFP5llbMIivQLJ/GVDfWeY690Kss/2ppBZ3KaVHo5etCOBnaG8nsLy?=
 =?us-ascii?Q?b006jFACry3h0ZiA2Nwk68AVeQbCmhMcKSOFxa7wY8J/zheAOLUwj0FL8kSL?=
 =?us-ascii?Q?5+bhcEsz+y5R+R/y8MmAadoakRxZIW/i+spFq1hmcrs8Ka91cvqVzsDQOnuI?=
 =?us-ascii?Q?uFSsKnr03U1NrgQAh2M26mxMVYhqyPjdy0XKTilj13YiAnMnWBUBgnyB0QSY?=
 =?us-ascii?Q?azQurlLPEcy6QG92sNu3LGgZ8h7sx5L1NVWeybUDIUn1MsIHy5Dn3qdeGsRd?=
 =?us-ascii?Q?KlgRi8nm4Atd0O8gHp5QuDJhT4RcOtrOZlGSkK2GzT448MufPt1aBmWK1NgT?=
 =?us-ascii?Q?GTQRvlvPawbM36omLQ9r2z4yWndV83SIN2l0DRk5et4TXXv1E3QSEWxufiB5?=
 =?us-ascii?Q?BXusRpjIZMWucmjudzhgapI1jueU0Ej5wp63t+eExdH9zzdI2Rvl+IIypJKB?=
 =?us-ascii?Q?3R99PIVXgt4pwZg2bdAb5Sn4dfsbXEfYz0F80jguuw9JyFrtjSdkmo4SJzhe?=
 =?us-ascii?Q?KFYIHzXF7B28NNlEfPtI+pJHBx5ZZWTuFGm483uPHeCRT0YB9hQRYHgH+WTf?=
 =?us-ascii?Q?6kGCACSAhGg=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?n8pL3zgk/RTVEcp/UFl+G01azkswF1hrKV4uLclKunyXyWT/6p97coLQX00q?=
 =?us-ascii?Q?08N2V4F/5v6FmxMhG3XMXb6n57uuWXGxYY1JZ5LrHI86FvCCizoIoma/RzZa?=
 =?us-ascii?Q?EB7poFxh3FNjPCVYuoMssbeM3gd3CYAmH1exaWLUUJrUax8jpz7ouw+qe9zj?=
 =?us-ascii?Q?eNQzJrWDYS819nbffztpjDh0CBn9jFM+d3WHN7hlFzBSGi2lqY/G+xDXdkBH?=
 =?us-ascii?Q?7N0MS0fUeQig//+TdAwYrKP12SrLBcJO+U1VeC4uO+AOJZ7dm515+xEG4eWo?=
 =?us-ascii?Q?8e8RdgN4mSbIdIzTvfRO5ugMBvyHW+xphKJfhqNBf9SCXks1nf7PyQ5NYmev?=
 =?us-ascii?Q?Nlubm+pBleioSk+RumZSJdDQdZPPyVFNHoH84EIZkGkgLPSQaDOApojZiaIh?=
 =?us-ascii?Q?Ve2NHlTcaZGl9Rz4h/mJpboZv5w5byhEtgYgBDwFeKEHDGIbQdaBIXG2xOly?=
 =?us-ascii?Q?lOL+Cgcy5GrbT6iJtim8ex543XtAobzeGBI8Yy36ZhRJgTbKXh+2gY6t6f2a?=
 =?us-ascii?Q?r6kDF9z99O0CCyN2HP7Y3skm2Uwn+gMfxmhpWGv1EbBCV4tg7sL9bDPl6aqS?=
 =?us-ascii?Q?5SUqZHGqwVq2IDmaRyzZEFA3WpTKyngjVmzSRxhwwH7QiBlwJXrocBQFidau?=
 =?us-ascii?Q?EV88BYorElDFLg028omdvzDajYsEtA3y+Ki8hYTmuMx4bM+bJCL1Esfb1c+4?=
 =?us-ascii?Q?7CBeL2tpXycmnLxrIvDRis/biSToq0JwWA+Gg/UYbEthYRDtvff7wsoPbw+x?=
 =?us-ascii?Q?1IupMD6suKvk9ukxvfgbkj625e5ETEYLhUCgY3GuLrytNvw9YFikZW3E5fpn?=
 =?us-ascii?Q?eyT+I430mHSvxQ52K24DfjC9LkMj50uLPStxa31MIxDbaDM+0o3U4vPiEmo1?=
 =?us-ascii?Q?wvZqho7UeOiHwADxgeVlvXaj6MwF34lai9fpYCNbKnqzL97h0mfBJk5zDtgI?=
 =?us-ascii?Q?Au5Z0O6/DMZto9tq5vmf1BsEk8x/fskTxPCnRHiCFTRI/nQveUUouGKXcwPX?=
 =?us-ascii?Q?WskA7z5PXdfUz9WhG1/1PsKC9tID2lLesfznj1RodNQhRXbbxhGfqBi7GtM1?=
 =?us-ascii?Q?zCSOKeiHLc/VuyGucAhFagzFsPNg4xfCtSHr9+38Z+ktuWKPvVsNbn3KJ0KJ?=
 =?us-ascii?Q?TRE4j0NDoqpBWL7kAR6WyiBAB2eu0MlJ8onZL36YF50iuRh15HvzcIJzC/Xz?=
 =?us-ascii?Q?M4P9iN+oehxTG0ljPNylAwqgdYG2oQcDRmQL8aPUw8cPLiVagik+t3YkZrT/?=
 =?us-ascii?Q?1uGQQtCXmeay3l0Q11YVgiWF0A1pj7341t9oeVRF95Gw1XSMWsNdOF3jGUJM?=
 =?us-ascii?Q?DIq7VCcxN20zUcfSybdEsEU88tUEwRs/+bcka6qnPVc+JzrG7LBaqKUN+qjp?=
 =?us-ascii?Q?oPt2b7Qz/H1PlalZuMushlA6yQlsWYUYlAk+zuBSWTopH2DKGO/aE61gfAT6?=
 =?us-ascii?Q?eGQkGJvUbDEmI8d02MJlqBn1BVw7yX77oW1Oi/YruXJgoC6Sn1FGgOParb0V?=
 =?us-ascii?Q?izSpxB+EA25R+O/Ajpk1c+N8HJNk90R8rJUX+1FV9ljYpC0YWekgXfxhJC9V?=
 =?us-ascii?Q?u6J3qKfNQ5N6MLEN97eSyBP9PDCZkbl+mKFqa+ib4O986SCMQupb9VBkh3F/?=
 =?us-ascii?Q?eg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: YYKUJq9ans6FhudAFM5SsWO6pkKolKt/9fMtbaY5UNCO9rAhH0bQnlfIXIh/Xhj4PWqqRGtsFn/Q7ZaxQeZlLry+cqLEh2kl6TYFVU12zLMYTWSKORaoPKbNhTxUzMguMBR9St3pF0ScPYdTrwvCH3oiOOskQuBkyR1fPdUqu8y73rDKp2WxvSolwE3ShdsZ/weQgbNG6xCCbMUFjTThQen7OwJaRpN/nfYd4A0whxk6LdukcouBHyRFOgoXxYNjaTLhF7nsCi/oGDaTnTsiiTw+B6DcmCV9rGeGF4PR/WY2XrvUly8g9oVqNL6hbE3JDs+T6OlB1LHvSz9sHGnbY/nNnFfmW3E/C/r/Hdk1ObMjv7EMzjKQVkhelonvxrA4Zi2JkaxUzSqiwL+rIQ20TweNi4lETHZAXVJ92jOqeuEf1XfS5SzRx5uxp98wc/AJriaLmvM60fPJdoTM9rGtiuQqF9PysfdFREq3ZDoNU7ud0lkEp7jmXX/6yYlbNbj9jFTzOhOWk0zgTDik2O4NJ54JgCCG8R25ds7kVYVjuo4JzPw72N0fjKlcyxH4zMlqyaFJqqBs6huFz4ibV8QbNQ561ucw5mAoNyMzJ5k2vyY=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e467cb30-4381-4a81-aa76-08ddf52b1f0a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 14:12:51.1517
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UQm76dRyVCaoF2/m/aCzPOvcfpbJOnQ4RRwzOia7FdffCAV516xm85W5OPmGnT/vAf9Es/X194fWKV7w7O/KNkv0FWt4xcUjYemg6pslfao=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB8108
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0 adultscore=0
 mlxlogscore=999 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2509160131
X-Proofpoint-GUID: l6d6i_p6ERrzcTo9uqpK64d-0gRpPHRb
X-Authority-Analysis: v=2.4 cv=M5RNKzws c=1 sm=1 tr=0 ts=68c97068 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=_Jg6trKoHIQy0Easoy4A:9
X-Proofpoint-ORIG-GUID: l6d6i_p6ERrzcTo9uqpK64d-0gRpPHRb
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAxNiBTYWx0ZWRfX1aYZnkjIz1To
 gwxk0wKamLHEZAV4RwkorISXXHDNFUGQ7XhH+bGW1knYd5MPpk1o2gcjFKoLxVTtCvGAuIIZInd
 vZOXumu/bzQX2s9t5zsNmNwxA7uQJeKdh7bQuikQ9Yt5wyiythbBx0I/h6tXPee+lBBOsXUmT/4
 TqVAvhw/njlcekDRjPskS3wH5u9pB/ZcNNvDLKhSY2xU9Jt7VMmOYVjkmxAoF5o0jGpPvZzlYuT
 1tDoWtaul3HU/pkLcEzBpreYdoAA6DcyoOw4/J4QMPORaKQ+q/E4Mi6Co4MAzAQUb+U3snswfZ1
 2FmlUO4qERpGpS37eCzxbP7AhhAKTwF8miojSD/62/FslMSYt1goZKV23yut3SSwdhM/uk2L29e
 DQ3kHaIe
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ViCxBXDx;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=MgwDGF62;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

We need the ability to split PFN remap between updating the VMA and
performing the actual remap, in order to do away with the legacy
f_op->mmap hook.

To do so, update the PFN remap code to provide shared logic, and also make
remap_pfn_range_notrack() static, as its one user, io_mapping_map_user()
was removed in commit 9a4f90e24661 ("mm: remove mm/io-mapping.c").

Then, introduce remap_pfn_range_prepare(), which accepts VMA descriptor
and PFN parameters, and remap_pfn_range_complete() which accepts the same
parameters as remap_pfn_rangte().

remap_pfn_range_prepare() will set the cow vma->vm_pgoff if necessary, so
it must be supplied with a correct PFN to do so.  If the caller must hold
locks to be able to do this, those locks should be held across the
operation, and mmap_abort() should be provided to revoke the lock should
an error arise.

While we're here, also clean up the duplicated #ifdef
__HAVE_PFNMAP_TRACKING check and put into a single #ifdef/#else block.

We would prefer to define these functions in mm/internal.h, however we
will do the same for io_remap*() and these have arch defines that require
access to the remap functions.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
---
 include/linux/mm.h |  25 +++++++--
 mm/memory.c        | 128 ++++++++++++++++++++++++++++-----------------
 2 files changed, 102 insertions(+), 51 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index dd1fec5f028a..3277e035006d 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -489,6 +489,21 @@ extern unsigned int kobjsize(const void *objp);
  */
 #define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)
 
+/*
+ * Physically remapped pages are special. Tell the
+ * rest of the world about it:
+ *   VM_IO tells people not to look at these pages
+ *	(accesses can have side effects).
+ *   VM_PFNMAP tells the core MM that the base pages are just
+ *	raw PFN mappings, and do not have a "struct page" associated
+ *	with them.
+ *   VM_DONTEXPAND
+ *      Disable vma merging and expanding with mremap().
+ *   VM_DONTDUMP
+ *      Omit vma from core dump, even when VM_IO turned off.
+ */
+#define VM_REMAP_FLAGS (VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP)
+
 /* This mask prevents VMA from being scanned with khugepaged */
 #define VM_NO_KHUGEPAGED (VM_SPECIAL | VM_HUGETLB)
 
@@ -3622,10 +3637,12 @@ unsigned long change_prot_numa(struct vm_area_struct *vma,
 
 struct vm_area_struct *find_extend_vma_locked(struct mm_struct *,
 		unsigned long addr);
-int remap_pfn_range(struct vm_area_struct *, unsigned long addr,
-			unsigned long pfn, unsigned long size, pgprot_t);
-int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot);
+int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
+		    unsigned long pfn, unsigned long size, pgprot_t pgprot);
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t pgprot);
+
 int vm_insert_page(struct vm_area_struct *, unsigned long addr, struct page *);
 int vm_insert_pages(struct vm_area_struct *vma, unsigned long addr,
 			struct page **pages, unsigned long *num);
diff --git a/mm/memory.c b/mm/memory.c
index 41e641823558..4be4a9dc0fd8 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -2900,8 +2900,27 @@ static inline int remap_p4d_range(struct mm_struct *mm, pgd_t *pgd,
 	return 0;
 }
 
+static int get_remap_pgoff(vm_flags_t vm_flags, unsigned long addr,
+		unsigned long end, unsigned long vm_start, unsigned long vm_end,
+		unsigned long pfn, pgoff_t *vm_pgoff_p)
+{
+	/*
+	 * There's a horrible special case to handle copy-on-write
+	 * behaviour that some programs depend on. We mark the "original"
+	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
+	 * See vm_normal_page() for details.
+	 */
+	if (is_cow_mapping(vm_flags)) {
+		if (addr != vm_start || end != vm_end)
+			return -EINVAL;
+		*vm_pgoff_p = pfn;
+	}
+
+	return 0;
+}
+
 static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
+		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
 {
 	pgd_t *pgd;
 	unsigned long next;
@@ -2912,32 +2931,17 @@ static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long ad
 	if (WARN_ON_ONCE(!PAGE_ALIGNED(addr)))
 		return -EINVAL;
 
-	/*
-	 * Physically remapped pages are special. Tell the
-	 * rest of the world about it:
-	 *   VM_IO tells people not to look at these pages
-	 *	(accesses can have side effects).
-	 *   VM_PFNMAP tells the core MM that the base pages are just
-	 *	raw PFN mappings, and do not have a "struct page" associated
-	 *	with them.
-	 *   VM_DONTEXPAND
-	 *      Disable vma merging and expanding with mremap().
-	 *   VM_DONTDUMP
-	 *      Omit vma from core dump, even when VM_IO turned off.
-	 *
-	 * There's a horrible special case to handle copy-on-write
-	 * behaviour that some programs depend on. We mark the "original"
-	 * un-COW'ed pages by matching them up with "vma->vm_pgoff".
-	 * See vm_normal_page() for details.
-	 */
-	if (is_cow_mapping(vma->vm_flags)) {
-		if (addr != vma->vm_start || end != vma->vm_end)
-			return -EINVAL;
-		vma->vm_pgoff = pfn;
+	if (set_vma) {
+		err = get_remap_pgoff(vma->vm_flags, addr, end,
+				      vma->vm_start, vma->vm_end,
+				      pfn, &vma->vm_pgoff);
+		if (err)
+			return err;
+		vm_flags_set(vma, VM_REMAP_FLAGS);
+	} else {
+		VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) != VM_REMAP_FLAGS);
 	}
 
-	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
-
 	BUG_ON(addr >= end);
 	pfn -= addr >> PAGE_SHIFT;
 	pgd = pgd_offset(mm, addr);
@@ -2957,11 +2961,10 @@ static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long ad
  * Variant of remap_pfn_range that does not call track_pfn_remap.  The caller
  * must have pre-validated the caching bits of the pgprot_t.
  */
-int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
+static int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
 {
-	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot);
-
+	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot, set_vma);
 	if (!error)
 		return 0;
 
@@ -2974,6 +2977,18 @@ int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
 	return error;
 }
 
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn)
+{
+	/*
+	 * We set addr=VMA start, end=VMA end here, so this won't fail, but we
+	 * check it again on complete and will fail there if specified addr is
+	 * invalid.
+	 */
+	get_remap_pgoff(desc->vm_flags, desc->start, desc->end,
+			desc->start, desc->end, pfn, &desc->pgoff);
+	desc->vm_flags |= VM_REMAP_FLAGS;
+}
+
 #ifdef __HAVE_PFNMAP_TRACKING
 static inline struct pfnmap_track_ctx *pfnmap_track_ctx_alloc(unsigned long pfn,
 		unsigned long size, pgprot_t *prot)
@@ -3002,23 +3017,9 @@ void pfnmap_track_ctx_release(struct kref *ref)
 	pfnmap_untrack(ctx->pfn, ctx->size);
 	kfree(ctx);
 }
-#endif /* __HAVE_PFNMAP_TRACKING */
 
-/**
- * remap_pfn_range - remap kernel memory to userspace
- * @vma: user vma to map to
- * @addr: target page aligned user address to start at
- * @pfn: page frame number of kernel physical memory address
- * @size: size of mapping area
- * @prot: page protection flags for this mapping
- *
- * Note: this is only safe if the mm semaphore is held when called.
- *
- * Return: %0 on success, negative error code otherwise.
- */
-#ifdef __HAVE_PFNMAP_TRACKING
-int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
-		    unsigned long pfn, unsigned long size, pgprot_t prot)
+static int remap_pfn_range_track(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
 {
 	struct pfnmap_track_ctx *ctx = NULL;
 	int err;
@@ -3044,7 +3045,7 @@ int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 		return -EINVAL;
 	}
 
-	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot);
+	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot, set_vma);
 	if (ctx) {
 		if (err)
 			kref_put(&ctx->kref, pfnmap_track_ctx_release);
@@ -3054,11 +3055,44 @@ int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 	return err;
 }
 
+/**
+ * remap_pfn_range - remap kernel memory to userspace
+ * @vma: user vma to map to
+ * @addr: target page aligned user address to start at
+ * @pfn: page frame number of kernel physical memory address
+ * @size: size of mapping area
+ * @prot: page protection flags for this mapping
+ *
+ * Note: this is only safe if the mm semaphore is held when called.
+ *
+ * Return: %0 on success, negative error code otherwise.
+ */
+int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
+		    unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range_track(vma, addr, pfn, size, prot,
+				     /* set_vma = */true);
+}
+
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	/* With set_vma = false, the VMA will not be modified. */
+	return remap_pfn_range_track(vma, addr, pfn, size, prot,
+				     /* set_vma = */false);
+}
 #else
 int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 		    unsigned long pfn, unsigned long size, pgprot_t prot)
 {
-	return remap_pfn_range_notrack(vma, addr, pfn, size, prot);
+	return remap_pfn_range_notrack(vma, addr, pfn, size, prot, /* set_vma = */true);
+}
+
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+			     unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range_notrack(vma, addr, pfn, size, prot,
+				       /* set_vma = */false);
 }
 #endif
 EXPORT_SYMBOL(remap_pfn_range);
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7c050219963aade148332365f8d2223f267dd89a.1758031792.git.lorenzo.stoakes%40oracle.com.
