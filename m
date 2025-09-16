Return-Path: <kasan-dev+bncBD6LBUWO5UMBBZ7AUXDAMGQEWNJFLJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id DC459B59904
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 16:12:56 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-81b8d38504fsf1896697785a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 07:12:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758031975; cv=pass;
        d=google.com; s=arc-20240605;
        b=EfWwjQKG9DZN8i/WkLl3W/5ybWjT6wk3jnSFzL/nofyhaFTNiJtzXf7t8HO+03WEbw
         6Myiasn34V9KXPr9obk+8dNCAjbxQ/DHHL4SGH5/tDaJmqrOmtY7l3XiYQ2p/tnMxBlL
         U0zzAM4jUBK3PMoK5wu9e6aTWXDEITqc8HBBK0MUq6rTzgkJ48hfcG9wPu26VY1W0yYz
         6BzSRj0ndsmhCrJTgoqTvdscWN8xsMvolJsf5IMP5dooqd7I5WO7VnZv+C2T4QjaJ/Kh
         aQILGWkW5SQSvmqqJlYIXPkQYBx219E0o6DLGWJPyY9LHvhrAx9x7qXuyR6/4lGVZgQL
         NiPw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=oe6l6uJHD12WKqwWe75JMI4Oo9tXtv1Pgloa1oDLxJM=;
        fh=ZV3k6e3Utf4r9je//wFKseOx3BSu4uzTJ+BRhiyaGIk=;
        b=agk/04cbDtw20hXKCHcrT/NtFi/ZHZZV7VSFR0TvQxetAzi7oQP9JoS46Z19HrStr6
         zUyzO6xLh+I/6LTvA/OuskyOfTGFVKNwft1Sx5uM2zO3/u6EEOuCXUSpupXCbFtBDR0W
         MZdAzJsG0gjKQKr45yNydRVzTpGnm0h6QcdzxU19yOcwchy5zrDLhrhSXXbbVgGm66nr
         kD+82Eyi0qFvPMqhxpHxF1yKydvnjyXLbN9XMdTF/DpKZPWimlovAc56qqVBmA02XVbX
         ErDlJKtZONGOBcfira5vuxibUCJ2S9nbg2KujlV2/hhuVzbF98Xg0oBLClHFllpFHE6e
         zU3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KCYh2ziZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=b4c0nAEg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758031975; x=1758636775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oe6l6uJHD12WKqwWe75JMI4Oo9tXtv1Pgloa1oDLxJM=;
        b=VAUEGapY8bL5rOg2ib+bX7kpqjkP6x6AIU41VoBgmY/yu11c8owXU150hnY/KpGkTm
         M/ydAfU8BplrtTqW+kfMTll+xiqZ2jKw6zEHN1qslVUKGie38QflD43aiW3H6DuMH4OI
         haMiId4ksdqDaGctyva/NstHK/0bf8eQwKfRPZZAnvlII1DdQWgI+sDR5UExq174MYPY
         GjvdAjyHRDyPhBdmQEenkntwj+f0buuSJsx1TZhfxuLujNfwLpP3C2XsICHsrdvbEfZF
         zKH6GJG6Uh938INykLKtpCB7zFBGHX6gdN5YLn4/qWF59629ve2TbWRnreEhBi6uaWBz
         V4zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758031975; x=1758636775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oe6l6uJHD12WKqwWe75JMI4Oo9tXtv1Pgloa1oDLxJM=;
        b=uR11+mmYG1EuUl+QZH1VzelsCVpmtp5j7bIctY+BSTixznl65eBq8zPwYYWNjGsCRa
         twPqe8FkrnMWDxL3sNQ3wrCpLu7gNmVrMi3RMb7m92ns5ubZeLhvVYLtUXJYLcWoQzUA
         4k0rh2VbT8ZFj3Ew/JW1B1M59aP9gP6ovvmQv7j+9MN7c4lIrVAv/LhOGXlhfxbaeBVt
         nzxTj39hqBDYP2uBau88Ex4T38yprb2IoS0ZyJ2C7e9XF/p+jNBt2Gh5jpHGL5bvgFY/
         DLZK4v0r1HT00DlEe7X1M5oE6WtZ4J8Nlov31c4zZUQvsJpvaqvqov1M+JSZ6kKsSnRf
         7Kpg==
X-Forwarded-Encrypted: i=3; AJvYcCXb7Dx+ONAUVwY38HdAgLWuhHhcblztPgqqZrQU5LzQD3RjfxN+onMOoXd7fE2XkzuX9tVv4A==@lfdr.de
X-Gm-Message-State: AOJu0YzWdg5zHc/p9UQdtSgTSbDmwyoRmOn19ZWtfVieS9+0bkU/Ngjj
	lBAZfKjTfFoZpofB+POjNlypgwgJtOCbTOQBAOZx++Po+VlMidgv/ITU
X-Google-Smtp-Source: AGHT+IFbBYrs7NHKuXbJdd/4TLEuC0G9CadXNECO9K9w+bWMee0sl3rONRlQ0Ij/Qa4cIMFCFFBU/Q==
X-Received: by 2002:a05:622a:4e0d:b0:4b7:aff5:e8bc with SMTP id d75a77b69052e-4b7aff5ed4amr61851281cf.81.1758031975330;
        Tue, 16 Sep 2025 07:12:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd40vSa0dnZr3LqOGQHdgGPHxH5PA6Igz/9Cdz7D9i82rg==
Received: by 2002:a05:622a:11c1:b0:4b0:9e11:a24b with SMTP id
 d75a77b69052e-4b636b8631fls100611231cf.0.-pod-prod-06-us; Tue, 16 Sep 2025
 07:12:53 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXqnNwSYoTDRFnP5uvf6X7bdvVGoOs3TOq681+yV5pkFnSYjikPVfmLZtdG6A/2Wp7S/rQ0nhiBcwo=@googlegroups.com
X-Received: by 2002:a05:620a:a909:b0:803:a33:b135 with SMTP id af79cd13be357-82400943775mr2046878085a.67.1758031973516;
        Tue, 16 Sep 2025 07:12:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758031973; cv=pass;
        d=google.com; s=arc-20240605;
        b=Np38GQarLCHReiHHFmjx1ziX6W+HV2lObwgfDHuCf6q9HdmYuI5bt6H+10sGEv2krb
         ceyaix9w7fbN+yT6Nm1LdLKB0g2hik2TbGitcXyhSU+wBFsrAHt3/IoUfqzTzDtQEDTC
         9k9bdDrRK8V2JKoIe1v26wn4Sb1bx+Mg42e9JGO3oyYOSIXIT1riclAXmiK5M4uz72L7
         bZsLJfKG+Or2FhGxNdCdbt3StS2ZCL/kSmhcVgYa9v9YT2HetZYHRXsk2t3yLohXmKdc
         aO3tRDdhJfOfzJsjuPuWDVcWH1rrh6680oL5TQQui6gKwrDMqxVx+nb1b3cJ2czHe8Hc
         wOwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=F7R6PkNElHoEy0RyA91jd5SCVekku5k2j2iVpNfTz9w=;
        fh=Ynk8/lzN15FlaC37uGzkFwbArenmC37DDZM12Bu0ByU=;
        b=BD9VjpFzj9zWudzVFhUiVkaw5jE07xno2wI4NYnV95OH7pcrdf2ZWeGU5Jnxuh6LH5
         ld4BCBhmBo+8jE2xGsZnlXSskgTK/r3ulRN1+CT4tJLGzK9sPkHU2+WUezQ8nFw14/Gv
         Xvwd4aU1/U0Vi7YM5cZEsnVWbo5apJ0JXgyLqyGkAQqcvogfZrT3+8g9W7CmMwfQFFrI
         dgrV1dCh4wLb5Yl9zTL5RLHtzhaur6uSj5qtZYP7fW31YQXZZCvu0DGh+d1Nv5TalGY+
         gnfrn+CeJpugU61kK/sWCAvsoJGjgneO2BfDSTrA5CJ2VKqPOgg4e/5t2ZTWODpWCUTj
         fHyQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=KCYh2ziZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=b4c0nAEg;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-82a5cc17cf0si18679985a.4.2025.09.16.07.12.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Sep 2025 07:12:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58GCxYJH029086;
	Tue, 16 Sep 2025 14:12:43 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49507w4r8q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:42 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58GDKAEK027247;
	Tue, 16 Sep 2025 14:12:42 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012063.outbound.protection.outlook.com [40.107.209.63])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 494y2jqp8e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Sep 2025 14:12:41 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PY3HCyjNlO4nVQb/iCf57q02RdH9X/RRcO0chVlXJ/Vi6oUMscCsA5gx8d8dwDPmL3sMDusC0SbVQ0JNZVn/2WGIkzZk3IrDaB7w1kL6TX6uf/nmKXBAVFCkOtsfXI9wQRbXFSAc/zJDKsjYTp84xkb2OhJxq/TEN/4FfNJgz48knyHnxx9RGS8b/2+yXqTUIUDrZtUrkkhZSjfcLBoLtlku9W8CN7E1zJm01Bj5z2w7ntQSg59mR1OqmbQL+9rmhKXajq5U0d9NiUvneoQkSCpn0KF/PeC5VB29chlziQDk7N8YX71cMIN2Q1mN8zEjEXhuPCzboy2nYhVfd2+Tkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=F7R6PkNElHoEy0RyA91jd5SCVekku5k2j2iVpNfTz9w=;
 b=iWJkeqHRZ93sKOPMn2n+sdxjiL1UH+/asWJbaoC5WHrFhBtaRDpPd9dmnEtOy0TB/hIP3xVhOQg+wkh39PjsgH2bM1wvactaGQ0ACAu/lKVJrZmLKF4BPO/CPbm25nldlpE3rbUqWPGdusVjnyc2UgJANojTbkTfkurJdSTS7JxWSTcRy8TT3HBZYq3kCC2ZOdCzIZfB+ocXPDubEOOseiaq2cjCN6kOf7RRYw51wZuQcI2cgyK/4+5czS3WUeX3U5MAKlobBepl3aJA4HjaxBVOR5dxv3w8Q51HNqppPOzZwqnhXzHq0Q1MXKJVnX5zBjDONSn2cDRqMOysCBcOew==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by LV3PR10MB8108.namprd10.prod.outlook.com (2603:10b6:408:28b::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 14:12:38 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 14:12:38 +0000
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
Subject: [PATCH v3 03/13] mm: add vma_desc_size(), vma_desc_pages() helpers
Date: Tue, 16 Sep 2025 15:11:49 +0100
Message-ID: <011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes@oracle.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P265CA0193.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:318::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|LV3PR10MB8108:EE_
X-MS-Office365-Filtering-Correlation-Id: dafebdef-8283-43d6-7ebf-08ddf52b1771
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?dcF7tl2wUu7EWxmJtcJxBhgP6p9TX1MvVpau0YgFEhr1c4Gd2cgNNecBM0ol?=
 =?us-ascii?Q?taHS7vKQPiBMhMy35xwTRudIhaJP6qvJPvJXzXwiXWl+fdxr7nQM5nqW2AhI?=
 =?us-ascii?Q?0mV+DDT4MCfaGbYS25fRcVHbmB2mwUtG+12LGbA8S7NjuVYHLmX8KtOEpK1m?=
 =?us-ascii?Q?QJ2zBYMP+BsJHn9mFSjCR1owysPilGrqS9hQ4vY0X+vPAUgbf0eWneEcWqlE?=
 =?us-ascii?Q?yY45mftEpH5cXkD0iiXoTHJgk+UXcfipREfmcZ5hitbPUfxWHmG/Yj82+tDR?=
 =?us-ascii?Q?szMrEK2uutvR35dJ1PYrIXqlzHHPcKieQJwhKXkHU1j9qc+fsnQ3ICXJNjsW?=
 =?us-ascii?Q?JFfXE7gBnjiKsxfJeosjSjdrvawdy6GSqVpIDgVJF/KmbRzOIeHptZQKEDHV?=
 =?us-ascii?Q?LjTfuVahUtWiFNKU4wcUASwaJcA5DyW06DSNyjvpti1skNczOrESkmxtvANE?=
 =?us-ascii?Q?JreAhnEXwSsEUan2JjzS/FQqaoUTix+YPaRLh80mV4Fx4obu7Gh49DcMbAMN?=
 =?us-ascii?Q?WYPLYPofVTyhQo2Cd0NmsxZnN3zh+xQt7odOS4n6Wn8N/n0JJqsa6zYhyjSg?=
 =?us-ascii?Q?FtMRA8pU9El+8IK2aPRoPXFoU7r5FG0ogYnCfirlIeTre6gUgAp+phuCj0Y8?=
 =?us-ascii?Q?oV6j+beHfcljF4sW7ix02pALxKba/53kl9Vhf0s0ZXXUzZyzhhj8SZQ4Khyy?=
 =?us-ascii?Q?GDozcaAW4w8NU4Tht1ISlRwlPJ18ymVgAp9TinS6pVMDrO8D39+nL+oUwNQY?=
 =?us-ascii?Q?Q9smbYpu2GiegmntaHkzAo3HC1OnLkKXzm+xj/YKeZhYU909Ebvenkjdq3Sw?=
 =?us-ascii?Q?sgYjEywvQqeyfhbz1P6BkBYBVD3JfZ9Le3hkH0rCjQk28IFlLy26Auk3cVIE?=
 =?us-ascii?Q?HD0VWba9SnfCNoTuKlPE01N85oFPaDUfmImVzUNOXjlKQpUPe04+y5Ln3dFN?=
 =?us-ascii?Q?pu0k3vqIJ92oWAunMSMaMM7cM+0rHlNWIXojTJ2TM5O7sc16ViDt9Ls4tvTa?=
 =?us-ascii?Q?1eT0oOYIx0FBO+q/RnCW2GWhi6kkH0IFFWB+eAaT5vDiiOg9367ijhvUMVt8?=
 =?us-ascii?Q?0YktdEh8ajg3xS0IZ8AdWldGWHWy9SZj9nSLhIQewo/qZ778W4MG2MixUEli?=
 =?us-ascii?Q?redGqPWYrHr3onPtLZi/wW5o0eearA6cUXe1/5tKgcRksW+wd4b0dYdRboFC?=
 =?us-ascii?Q?LZt5jfk6GFb+gCQQM7QGyP6Q/5QRaVWkXwOsLDHgDQfzA35jqUq516qnsu79?=
 =?us-ascii?Q?/c7HCFRPQ5+hhBB1ZVp18baMBgH2s6wRgUhQvh5sEOcBYBy2XaIj6X/qQ1F2?=
 =?us-ascii?Q?5aADVXHrU2GizT/Ags0R0KyNqts65hP5E+1tZKeYhIhjS6Ed5KaUyALcX5yc?=
 =?us-ascii?Q?ew8XN3ul947Q5KdXt0zoXLORUDx8jQc32oUIjFCsFNSgD2QDpiWa9ZBqiMKr?=
 =?us-ascii?Q?f8Vp8LBPRfI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?JA5W5rt73k64pFJ9H6Wf88fj+0MhSnSG9pz9H6jGSy1IYu9UsvxZFEt6qqaR?=
 =?us-ascii?Q?wN+i/HpIe+13LInK6Iqlvd7QjBetM+DGbZQXQE/EFFpVUBYT7f9lszmvxvOu?=
 =?us-ascii?Q?poE8ngjqwrBX1OYz1/+YiFrlmqSiNq9XAOW/WljrB2uWDsEIpWbsF+5j35ci?=
 =?us-ascii?Q?WyHfb2hL3LqGwHuIrY4zVGM75ipsRIzIvwFlGD2Hx4sCqsw6hRI/I1EqZ/n5?=
 =?us-ascii?Q?qYDRPHelfMvNXNvQpOyCdaE3pOZX3jbxO+ssgtfeuyzalEnL+7c+Py0Pjz90?=
 =?us-ascii?Q?HOA/GXaq12MQojlCkFWpvulPoxkfgVMtdrCiZaiVIJqR/xCDvzUaS95dCuR9?=
 =?us-ascii?Q?IlOESvEYfoYs3YZ5RMaed617fDYDFJLsLKS7mcp9ukk6yPZWUIp2Aj66uLde?=
 =?us-ascii?Q?e1GX6xvwzwhWrgegUeCbLHAHEP959RfjpLWtwp1PYPuCQ77+FeAgNTz/hLUz?=
 =?us-ascii?Q?fuAZIGhxBbP2NpBSpyzTCAzCI1aOreIsN7llQio8bjJwtpc1wOPRLCOpQzNC?=
 =?us-ascii?Q?rnunQLDoE1oMeBD+AsCuo5t1mGCrBzBQY5y6EmNPHBaMpc80mKvoZ3DoFIc4?=
 =?us-ascii?Q?wfOSWInIRY+D6Cl1toATul2NKki9QBgiB8aGJR2zfR/8TxbTROoH3xsqh47o?=
 =?us-ascii?Q?XDcaqIxtI6JW5jgZGDD2MMdH4QeonoeOjdqI0vMEw8rIYEBxVeccdOgDqQSN?=
 =?us-ascii?Q?ndBfGTqBFKkOmbe0k3fKKXiji1LUT57WLXgzAal1e89wE4A/ciSWxLWIj+6C?=
 =?us-ascii?Q?fH1oms8Y79DMEdI6Z/z0eoyART6rpha5wkfDUdpfnj2budbvMSBamHFd5Ivh?=
 =?us-ascii?Q?2gvGGWxZrQuwpwkcYmOQEFGPdv0/134CIYONKVM7o0JvBYwNeVsxCDKsUJyk?=
 =?us-ascii?Q?sOIMrlCTII9mvZsHD8iCXWpeOzorqHl2rkgtoxwqoyg3i46C7s2jPRmK8NCz?=
 =?us-ascii?Q?pkUVElCl0qnwSuKV7iTmxWNOqWY3HI14e5Nh8Xf9gkyuJz/eY7JIlXD+qxrQ?=
 =?us-ascii?Q?wytrM08O1lIAFSQPhh/Lr1ogit/ym6IsrQcK+YGpnKlqb/qfSIsxrstwQlz1?=
 =?us-ascii?Q?uB4BIbD57cGRdIQjMwFVv02/QCBaHSBopgA1Ap8r9S3CzQFXf8v2BeaaNPX7?=
 =?us-ascii?Q?C4eEL86UQzacWI8VXIn+Pv/3b1wi4Qy9MBAlCH7PoliZUtE+fZak1zCoa09b?=
 =?us-ascii?Q?E1h7KwCiJj677ReSmJ+M5ECW8cbIqLPZCqICx2kfzCV3imMF7f38BdMavfK3?=
 =?us-ascii?Q?5sbipZ8DvJKy8T20feEYIAYeuOLbJ4V2uEF/NfBRYamR8y1Im4/6ZBt4NTc/?=
 =?us-ascii?Q?ZRqlJfOkGBHHJcESCAt2Vuvj8yTPYPiZktcUshqWbBmi6hsDoe507Q6H41Lb?=
 =?us-ascii?Q?xtstGdDlOHW/pEm4j+2DF9dNWOOBHsX8p0bxTrQgzBHEO5CsQ/uQ0qnM52GC?=
 =?us-ascii?Q?MDecbpdHRMwldGH1mAv1bWDcBk4ftcbLNl4PEfDWE0TEqCAzmbImbc5gDdet?=
 =?us-ascii?Q?EmSHrZGx8Qv76jfLXMyMhSqKAmPrmNlOPH4ifdx5vlhM74ncMJE/1C0XYwgP?=
 =?us-ascii?Q?zFP00TpmpHdU8s48c8XvfExb0UsoW0f72D5C4W7a2cthRL5RX8TI9rqvalx1?=
 =?us-ascii?Q?IQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: D9BlWiEAiiAPbXo8tLMB393vV/bauTaJoP3GwhwWd2IAeBD4cdqp2S2Jww3bUKNNZVOk3Vsms22iceNYLttCR9lDkIHGx7/oHyPUhBJ+SJilkjP+PwL+Mg3O0NEPVQpPZ5evO3sVkxjZw9FN1gCPuW+YxAN+y3Bh6s5TwSVHKiS9ygW5pq628yb/Chwrhz3ElbYZ5Eq9dhcoljdgvMmxHHv9ggqzq1TmaxOIataVBAvLdDkyTvPyoCqkWz993TPXU7Ia2GWrYDTO3cjrDwhLoYWezrVckxnFmxGajGf0bnxoxAsHPfjHbCcVAhNXXX8K8usBSzn6CcYMCg5GbD2C4NfYARGeuQRya8sweZXwZDApGz0in8sWu+vWT1JdCIJvLK4ON698nYMYZ/+B5Dy269N5OuSaZgqkwP1u2126KUCZyEpPWQkOkEI84At08rl4EjxhzZiMSO/K133V4X68INxGmb3DHo/d89LHs4djBTdxdT1uKoeZZhlI4P6agSwUH0it06ys2nyegRysLgjvATIaDFObaSRYcwrVLdfQv55CpLNljenO4nHMJ/1mR5T/7oErweSxCIlVVUgHUzK/eock2uYg2MNpEedvns/+Xyc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: dafebdef-8283-43d6-7ebf-08ddf52b1771
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 14:12:38.2892
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: agAvJxLa3q+oDsUcgCODPpu4VZx7+C5nltpSxWNdW4Qsdb05HQt0eV270VdY3kCK0Do/ozJ33+P95gnYl4Ny4GAYj604hbP9yqPJI3X4EqU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB8108
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-16_02,2025-09-12_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0
 mlxlogscore=999 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2509160131
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTEzMDAyNSBTYWx0ZWRfX9uq18RVvuAoS
 4tjB5GLldIZRNRDWYa1n8vW68wJwBbLkPu1z5bOCZ1+nlDU7LWawZ2Ka05hSL6AGXP536EyRbwF
 HqySOIKoUH7Mp9tK6/96Io/3qI8D4Pkm5/vj0xlJq5sjoC1Xbv6tRff2YdZmw7MU8pbzCXCSZoO
 U+urJfUmj9wV/BDUjDb6m7NmyT0X1sbltkQWORW3Vgdwot/UD7Ed6De7AxcEkclzFsjuh1h6KC/
 CvM3nsg4qr8277VsUN8oZRnRfEpqgn3SKoceFS1UrMpT6Sk1UseugV+BdGHNUlydHVW+ZQjiCIr
 7Lk7YOw+1yvr+rlx2/LS5kFUNBDM6cmXx8L4igpAGD4O/NDHS9IFQ6M6nV9nieocjm2RQyzGxfQ
 NBARPUZ4gzmd0JYwEw/iSzLO7k6o6Q==
X-Proofpoint-ORIG-GUID: uKDAGDXDgJHbd8_dVW2x1F24MfznRWPR
X-Authority-Analysis: v=2.4 cv=RtPFLDmK c=1 sm=1 tr=0 ts=68c9705a b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=yJojWOMRYYMA:10
 a=GoEa3M9JfhUA:10 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=V8PVCHvh7cpLA54rH4kA:9
 cc=ntf awl=host:12083
X-Proofpoint-GUID: uKDAGDXDgJHbd8_dVW2x1F24MfznRWPR
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=KCYh2ziZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=b4c0nAEg;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

It's useful to be able to determine the size of a VMA descriptor range
used on f_op->mmap_prepare, expressed both in bytes and pages, so add
helpers for both and update code that could make use of it to do so.

Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Jan Kara <jack@suse.cz>
Acked-by: David Hildenbrand <david@redhat.com>
---
 fs/ntfs3/file.c    |  2 +-
 include/linux/mm.h | 10 ++++++++++
 mm/secretmem.c     |  2 +-
 3 files changed, 12 insertions(+), 2 deletions(-)

diff --git a/fs/ntfs3/file.c b/fs/ntfs3/file.c
index c1ece707b195..86eb88f62714 100644
--- a/fs/ntfs3/file.c
+++ b/fs/ntfs3/file.c
@@ -304,7 +304,7 @@ static int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
 
 	if (rw) {
 		u64 to = min_t(loff_t, i_size_read(inode),
-			       from + desc->end - desc->start);
+			       from + vma_desc_size(desc));
 
 		if (is_sparsed(ni)) {
 			/* Allocate clusters for rw map. */
diff --git a/include/linux/mm.h b/include/linux/mm.h
index da6e0abad2cb..dd1fec5f028a 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -3571,6 +3571,16 @@ static inline unsigned long vma_pages(const struct vm_area_struct *vma)
 	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
 }
 
+static inline unsigned long vma_desc_size(const struct vm_area_desc *desc)
+{
+	return desc->end - desc->start;
+}
+
+static inline unsigned long vma_desc_pages(const struct vm_area_desc *desc)
+{
+	return vma_desc_size(desc) >> PAGE_SHIFT;
+}
+
 /* Look up the first VMA which exactly match the interval vm_start ... vm_end */
 static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
 				unsigned long vm_start, unsigned long vm_end)
diff --git a/mm/secretmem.c b/mm/secretmem.c
index 60137305bc20..62066ddb1e9c 100644
--- a/mm/secretmem.c
+++ b/mm/secretmem.c
@@ -120,7 +120,7 @@ static int secretmem_release(struct inode *inode, struct file *file)
 
 static int secretmem_mmap_prepare(struct vm_area_desc *desc)
 {
-	const unsigned long len = desc->end - desc->start;
+	const unsigned long len = vma_desc_size(desc);
 
 	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
 		return -EINVAL;
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes%40oracle.com.
