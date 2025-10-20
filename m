Return-Path: <kasan-dev+bncBD6LBUWO5UMBB4NL3DDQMGQEQBARPBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DD7DBF0B27
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 12:58:59 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-33ba9047881sf5188094a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 03:58:59 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1760957937; cv=pass;
        d=google.com; s=arc-20240605;
        b=NpbimlKJOSVV4bqMmsMu97jWY7GxwksybAn6hEo/5g9V6UkAybHq1CjBEES1s6Iv7x
         Sx6FpTZMrs1B/nbAfZ0L5LCuW5KVhZEF/cIKx7HZmo+zCDSqBeMj2Sn4HdYClPrkRTTM
         Nx6e9YTneJ4cckjxgm8VCiy2v+cxPp8CopJsB/yBrdnoKIO4JEVnbQrUt3cPbywLhGoM
         mYxxyRdqiDEjPsCWSRrHWFGOICLB1J6je80vR/MzE8DFvnr7pQnY608azynZ/BJkEHun
         zm7qQdhxXoNylHb2DIGKtPQ5d9GWHt+ZqmhjvJrlRyUAunOizRKbKJ2PCf/jNBInkuUw
         IgPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lohfMPpeq8rrjAhXl+NmoqzxT07dr2hS17PiwDqRG2s=;
        fh=C6Jpu3goxpMdo0ZQ1J9Cg8gE0xMieSclA3Y9vPGBNgI=;
        b=lcwLgLVtKJAdwRblzPgNX19mVJhdzHltBdg46gg/m4PIEGjsF2R4OmBBILcStjMLLY
         OePZGmP7z2Hb34kXcHjP+HCskFqIuBsjyYRa6vM+dnOO3OjEZlxbdyyXNNqGCAXanx7M
         qINvCNjyZM8m7SjfEkpdeRVwdLopqL95Q7lLjliuhGcE5LMx8Eznkc00BtDuEUcm4Kkg
         x0TT0NI6aAQ41oB2IJC8SqYhXCGGyWz2g5L6urTdoJHggVwpnEPCNpF/KtuKhR8FXlaO
         68Lcfwq9u6FtxJzITi3bhjzWcJexdvfQSJ7QpWe+iGt9GBpaT73Nd0oKyyke153C6onj
         cIyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BDSGg3f7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=vfW3hsuI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760957937; x=1761562737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lohfMPpeq8rrjAhXl+NmoqzxT07dr2hS17PiwDqRG2s=;
        b=nXh6AVAAxxX8i2xEp3IRqX/t2TKPIQ+6/99PxEGS0l+A04I4kJSj/g0jrKKaOjvAIa
         +uvt/AaFM12UDBBZqwWm2LvOA/tlkcXdCSqYz0gX0XNZx4/HBD6Oy/xSk4sASy6Fb9hW
         alu9cbRmWRLoHI8I3TlPMuDKuBVE9XnaGxsVii8Ucvaxcz82/+I5OqOK1KLW1f/eqmX1
         rm5GSsWlGVhGUVXDe0VuL/mIb8k6zSfZchA+3ouM4Wjd3UV7tN+6SZbwdp4Tovs+N/TA
         i2Ks+YKwIdkxekt4iZ6aeffs/+6xwf7CKuEQx7quOQAWRcFfhoKxrAj0ByZhQoRbgut6
         zDtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760957937; x=1761562737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lohfMPpeq8rrjAhXl+NmoqzxT07dr2hS17PiwDqRG2s=;
        b=HZMLLsrGq9NIU3IhcNRCU1PaWoIsEf8ES2AE/r+39jB/SD5hb79girkM38a6FzBpof
         1HQyq5qja0BkugwSyVMB7+PpPlbxy6PoxADPT/LaqpmgXWJhlcC3Ub1JlkWsbVSOe9al
         mTUSOLPHIz8DnG2USbpxWC1/kiSXcxIEHS3rgUHdfUs2wyXH3UKRdTJ2B2v6NpaAsAIr
         rS33leIPPg47EbLlOTzwhsrPgBLlI9P4oqFIip3f5WIgPdUwbDZgLJ9cV/9kpJvDcyq0
         QEzV5HJTotf1V8eMkGnR25F4ndsmIhenad56kFRyxvN/QalvCNfmIlpLSli4IWex8ST7
         oCBA==
X-Forwarded-Encrypted: i=3; AJvYcCWxxGh/PcK+dpIfn5z+7aPA6tV3CaitITB4RoDK0ixLzkrLmQE10wgk51DbWY5ZUDGKZPYXlg==@lfdr.de
X-Gm-Message-State: AOJu0YxjR1kJlpspAHbcWqEdnEroGbKjAswqfBIn0v70uB69hUKrxJAC
	DUWT3cNAa0UzS4p58+JG8r+r4L1MJRKP46dqZ19eIN9M+Aow3GqgoIXu
X-Google-Smtp-Source: AGHT+IG7hop9/Ny8ZPx2YL2afqIKQ7nyJOc98vlt6x3+0Qa9K8qAk86B6KObULiElgMAu+HzDLb/PA==
X-Received: by 2002:a17:90a:d406:b0:32d:e027:9b26 with SMTP id 98e67ed59e1d1-33bc9d1a8e6mr18429295a91.13.1760957937490;
        Mon, 20 Oct 2025 03:58:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6ykRzlDiiec1j99P5dRDqIezNb/kA7lGZDGduosLJHFw=="
Received: by 2002:a17:90a:fd13:b0:33b:cbaa:db4b with SMTP id
 98e67ed59e1d1-33bcbaadc61ls1401444a91.0.-pod-prod-00-us-canary; Mon, 20 Oct
 2025 03:58:56 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUdnNT1UzQAxz9JPynNY+t2K0JHUsCXB2+uejIVFymsxq39M0gByoFeglNGD/d30D+mbtPdp556V/c=@googlegroups.com
X-Received: by 2002:a05:6a21:3289:b0:32d:b924:e5f2 with SMTP id adf61e73a8af0-33495e997eamr25213054637.28.1760957936058;
        Mon, 20 Oct 2025 03:58:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760957936; cv=pass;
        d=google.com; s=arc-20240605;
        b=lKLVwteDhE+jJYuRN3f7dUAUqL6sL7xj1XMLAM5a+/YXmFbKBi+sjCeHuryh4luKgj
         W+JTKPqXbI9IMCogxWxg27ujbaWIyNAEUWH8VTj7vIEV8m+lcH2tHDMmtwRzaMbMTCuc
         F3srBjTETSbJJqri3Eep4w+tmBtfaFaL8PHKb8mwoaCyRvAycTfOcIhyZACDvNmUPWLC
         YBN7iiHfJUnSTOtU5dJ6CsO1OpNF0Edb75SlOt1hOF/A9l2a7e1uSAy6qrsIt5rkrB0U
         Y0NMbdEoAZ2QBC9rCMvXgnONVANShPTP2qQCAm91pHjNzwDBjcJmMFRkyHai7WOIqqNB
         zE0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=6DeOj5B3hqVtP8eDz9b4PIGraAXwACunXvQ1wQN5n/o=;
        fh=8lNOV8uDr2VTmczN2n/RzalrcIupURSrGqhSN3ZqU3E=;
        b=GXGTRBMgCWrfeIhErBZm54MJDmNOegYhhXf2gRX0HDgD4INWOIigzpKi3cwFvUVQI+
         Wh1n1xRoyIYCzq55zjPKSDRtJJbXj8e9eOrYAB/3vbGmRAU4fceLMQZjB+MPLbRNGEHN
         Cu3b/sbI9qqzQDynKsEG83ThhTM4UPugmuYeuTRfNj8U34NxaIRK0pM6QRGG8998Gcyg
         fMQ49tbEvHz3X73Blml0aHjLRGLUMgU0NIZ8NI86lYK9YgJDqwNyvgSrWn7+8GvVyj6i
         xxyBUwDTN+gbxRYGY9kHRiWHpbVW8yxlIleOCvekbYntqFNnWm43YKPiUJYbcntAx0fp
         pFeQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BDSGg3f7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=vfW3hsuI;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b6cb341a8c7si206392a12.1.2025.10.20.03.58.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Oct 2025 03:58:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59K8SGpq001292;
	Mon, 20 Oct 2025 10:58:41 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49v30720mu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 10:58:40 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59K814Xf025454;
	Mon, 20 Oct 2025 10:58:39 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010037.outbound.protection.outlook.com [52.101.46.37])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 49v1bajn10-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 20 Oct 2025 10:58:39 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Ig+FUkrr+8m/Gxp/3uAlx2mXF7tM53TatAdaQii00n3QnT1c/g//o0jqdd52+jMGFSeP3IRhqDc6+E+8Uv2nJGXwOSLCUMjl7nGYQ7l7+uqSM2Hv2dU7yLOvbQvhQ/g/34NwUMm8rry0eu4XLqkAVUtPtHlYaMILVZWlxsFCFYiPa3HXDMPlxhmPEWfVKmS83wT9XYNn4PfAA3+e3Iz8gFjgRrbF0mA5npOUSMwRzVVOE1/mwGrq3iAKN5hrQpGF+N5sy/vNcowiLX+mp7w2fAGlODUAP2JA4HEa33HyUXBGFNNhhM51bhbZ4+TjnmEQIGvsLw1YfJfocff1Vy7GUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6DeOj5B3hqVtP8eDz9b4PIGraAXwACunXvQ1wQN5n/o=;
 b=s1c2FRt2JkkLY7tit9eoZoDVL8ZNN4e2rPMSrVqWqQ78pbdjWwDBtB1p2moZC8nNrKkRRlGg6JZ96oIh3Jb5Y83Ad3q5kQolN9Q5hr3L4SBzBpRtvS09Fef5LfSbKIJgM1x9rs0TpPJnqQhp01diLx9A+vGZJL+eTr8dum4hb4b1Atu3ZaEzQABlHEHk9427pHHOX2KHnpeogzCdUjlwT1hjn2qCDnTFBvd66pFiD+AQukTaXDTDHxRAUxUkmo8z150af7sqBSHB9DyOpSDieWbKyMbiSfSu0ZKI6TezzVBG8sNegzE/sLXDlScbFctvZmLmntlGTXxSG+wFIW2Txg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by PH7PR10MB6309.namprd10.prod.outlook.com (2603:10b6:510:1b0::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9228.15; Mon, 20 Oct
 2025 10:58:30 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%2]) with mapi id 15.20.9228.016; Mon, 20 Oct 2025
 10:58:29 +0000
Date: Mon, 20 Oct 2025 11:58:25 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sumanth Korikkar <sumanthk@linux.ibm.com>
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
        kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
        iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>,
        Will Deacon <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-ID: <2e65cc96-5fb8-4197-b4c2-188c4378c417@lucifer.local>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
 <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
X-ClientProxiedBy: LO4P265CA0152.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c7::15) To BL4PR10MB8229.namprd10.prod.outlook.com
 (2603:10b6:208:4e6::14)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|PH7PR10MB6309:EE_
X-MS-Office365-Filtering-Correlation-Id: 0241265f-b17c-4ace-9c98-08de0fc79a22
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?HQurt4UF2aIWJaNVGFvqs2SpSsbwJiWpVGOJnQXEeErG/k2y0BlFqKdYvBdw?=
 =?us-ascii?Q?5zZmynjUY6h7UfEDvDpcMTZJAHhah+lqrtTwLekdA2eRfaKveaV7Nc/e0/kC?=
 =?us-ascii?Q?/USeHaFwx7gXl6qACU/OVgL434aKQkF+tCdtlCb+AiA1vm3Ev5J8o6u36tpC?=
 =?us-ascii?Q?HvtC7IOJ+bq4ms0106HJmTMg9X5mY8kbJdvRUAm5A52cAd4xlynxjFmjIT39?=
 =?us-ascii?Q?CEMLJWJmoncF6tpFM3bgxeeLsTnwWnu/GPsxZdgZB82NRSFOkt6/hQvnt8nq?=
 =?us-ascii?Q?o5OI0KfDiLZweL2b6NvuC3kkI6XtEy3Z6hJHGNu8M/R7Iz2dB2PLbjrImrVq?=
 =?us-ascii?Q?K1G7LKNkHfAhC5Ro1bP6KgRbPUjs93H7d5jCZSllRar/8W0qXSMOJWEWLfrY?=
 =?us-ascii?Q?ScqsCItkDytWGdHxjDZmwho5VzmbgM7+1d8iXns1qQJq+OADTdyTNYwLBBb/?=
 =?us-ascii?Q?chEeaj+2hQH6jE8LXuc2mri75Ic+MeBMlG1zhs5orj+R9vYIrb9cI68CtqY+?=
 =?us-ascii?Q?+c4pdYKPnJTVs6OMNc/pHTSsMSZlDEq2RzcTCGc4gx0i+/k5dVIRS9awcMRZ?=
 =?us-ascii?Q?wAYAvcak7rPjY0wMHIl+6kJtNJO/LWrvhC6hGywsfZ/XXJhRyjVW5g9biExk?=
 =?us-ascii?Q?nnsEWduhHAPmi0LvDFCMSkLgVGX+HC/bTUffw2wDsu+xP4kZwEXj/awdXjtp?=
 =?us-ascii?Q?KeOAIPDXfmN6lBV6jDymNcAifZ1xxjoATLCcJE7pJa969Nyt4Pv2zef06mWf?=
 =?us-ascii?Q?bnrl0lBinqjx30rWgsL1KuxczOuj+Ou87ZBRBgggdSFP+lI1OFMQPIz7Fbry?=
 =?us-ascii?Q?FeqNYmON0cg70cs0hNKOGbL2fh0Vg/KYRAwFYgRwRoJsobljuJF22pOR5jww?=
 =?us-ascii?Q?od5YWdZYpezQkeefv5ISqf+wRo2ZaUC7tIJbKBC9s6xMDyKbvmTW1nC4GOTw?=
 =?us-ascii?Q?Z/NIi8bljuvCf2t6xZz2km5dIyWTKwW4iJAKMsiRKXVXxU9WO69ntmFBauQa?=
 =?us-ascii?Q?pjF+7RVYIuObAnw4igPZbcrTilGyKidyIBsOa0D5cuKsbtZ8q7C6OEPynUaO?=
 =?us-ascii?Q?0MgEdx7wiYU0GtgkRbZPMQWK/DWB8R+eFTVpJpBkFsQbpcgHt3CkbN2ebBwN?=
 =?us-ascii?Q?0TVjGM53QUqSUKaWXCUuh1pjjeQazzZt5e20nsqDPDKOITr7v/AfkPZsZvx+?=
 =?us-ascii?Q?G1viR03SvyazWnNAoeE97bbOFQveQozqgg0vnuiMt0LjDWhUb23blMvCo/Q3?=
 =?us-ascii?Q?oDNKpM6cRqsPo+nPAOnou922oUKmAGYpHDLqRvbhg9hwKuxwicpF7OJ7AYy7?=
 =?us-ascii?Q?LRM8h/aTPNhQcE3LIC90W1GSuKIekRJvnOzzUe52UA0M8xVCZhItPww+ZMDl?=
 =?us-ascii?Q?LjQmpPHsQ+MXCPHiBR7ZK9Ieh8AScdfIJnTEWjhSgV9wND6grzmWjmh/Yrhi?=
 =?us-ascii?Q?e3qd1E+UuyJsbl7FIcLy1jQa5p31Kev3IpWnDjc+v+MBH3HKugX98A=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zo//R/AnIwfxZir8TqmV/s+8ra/Wz+EfZasteBUse9QYixIPdoSoLuiMkaZl?=
 =?us-ascii?Q?FfwP23tovYpXI/g1gytsVhqnxT5R41IVjbVTFF/AnEIiyuW8ABU17MlFAtFI?=
 =?us-ascii?Q?Sx9/jJ3ERMuscEEegfwZMBH5R5S2wcZdOoy9Bb7htbp1xtHfr/wotSbRunwy?=
 =?us-ascii?Q?YwYk2OYJAbYUcLs4vvsaWGthDoemvEUGyLlJBpqo822frq0akDgcA6/g/qrl?=
 =?us-ascii?Q?YRGXY9E1W9rkVwGZaNKb2vZaaBQ8SBn4y8DcvdpLXD163zj4tfb0h3kaiI/u?=
 =?us-ascii?Q?+WzkYQ7TDMNw8kkclRGTWHvuUztT/vqAiaJXJ+Q+a4QVoTbCeomnxHdcFJjK?=
 =?us-ascii?Q?ryuFpz6471uR0nJFAkz/KWXoLsSb/yT91U5fM3IdSKwOlWexp6Xx99gfpiKa?=
 =?us-ascii?Q?iDr1GSthOxUOaAqO6YBrObrX+MNEliRDNs7y6VSLvUVD4P14UjK5hYfFDUdN?=
 =?us-ascii?Q?M/vRTN+C7o9/+PREEyRviUKgzLkQoh8WW7fKYcZCarAL2MDzybkPwrTlWMfB?=
 =?us-ascii?Q?sjBqnBb00CrFVu3pH/VMW2hxOmyd7LXpHFsE7EC7i5yhNDoqp07Dh9SAV/qr?=
 =?us-ascii?Q?AU3Xko1kdx7JekXPpfLDCgDHU21ZseZwYk+tIBAPAAwn7P+H9NLvNsMY+nTu?=
 =?us-ascii?Q?go+YKHABILgQussLXiqjJcQIHFPqNAWyGi7aZ5l/7qsldzbNend+9R0BvAFY?=
 =?us-ascii?Q?XMP+PwTj4BV8151zCNn0khQxTgT7nHtuF0clXi7yEW5BOsALDobZCnWAyBNV?=
 =?us-ascii?Q?YEHOQl2laK/ZxAGokXa7HEf4Gaqz9SoqcojVDNSYjx55hQ2ZkYLokaG6273E?=
 =?us-ascii?Q?UnScLOPBseBw0PVrt7VHKCJOgi4n4guB5XvWWa5G6rYkx6JZGEYI/jdcVCoB?=
 =?us-ascii?Q?LKi5X3yWhuaZYsfPBGxH/9Qd1uKUSb6vV12XfYL9lWDcbkEUEk56+VFBqxc2?=
 =?us-ascii?Q?44GJNekdj44+DG9v22E12jh0PhNnOJ4oUNT+duze7vwWSLTY0qENw8I2p9KV?=
 =?us-ascii?Q?Vgs4VBeFZCEHWMR448ltbt9AhQ+Hvmqb1BcFJ5fOI/wR5mPlolvqSDDILOtr?=
 =?us-ascii?Q?HQWIWFW1jrblXEqv1GNR3kDYdDvSInx7JwDeJN42hy7mz0MwUthi6XHDgMuk?=
 =?us-ascii?Q?DHhtdopyhQdd21TYaUvFtT7088tqSwLvEjPD0KxbZM8cMjmki0jyFbLIIejz?=
 =?us-ascii?Q?GSGUVTm3wJhsn5i+6IVt2V/fFfGa0uxLAFQ+fVX3SU96hybr9QWKV+AAXrdo?=
 =?us-ascii?Q?lRZlyUzj3u5MYNTuTLFqLVNJVaShe46xfYxoKymbTSfil12lm/twIHbuPpJS?=
 =?us-ascii?Q?8hEZWJxSrEhsxZKcI9E8g02iZ6xV8mpS1gQHsKrvBXP6TvkCklWG+KGuAU34?=
 =?us-ascii?Q?SLts3B3HMUDqqz8eNHrNhY3DBgSqPRQ31fy8IxU4PAatM/Tnq38pXI5PRuxD?=
 =?us-ascii?Q?dVlN4Kfs788IRxMn/g9vSnLBTG6D1G6gzahz6qjJ3Q9beKXrSmv31sDHnmGh?=
 =?us-ascii?Q?lSAWXst0TaHNfiK67B/cm04V5CZ2U4yCfACA+xABRt6/Y/0adDvfvxIIn304?=
 =?us-ascii?Q?t0XWQMVBqDEInm9FMn5ECY37Sld3Fwq7Vs4TYiaxuEqqWLZLgiePqwqXAQw5?=
 =?us-ascii?Q?fg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: SLkgNDVThStqekoXvuQqPteLAnYJeqGWZ5m3R+Ka0yQgOPOvN+1QVpikCdgR8BFImiarvCtwhaau6qLEg40GBt7vwqbPl8smZ9QKxvsIJ1jMk8RJkcz390AeVK6qk23JfCw1HK3sLLIPJnXYRtkin3kkkfLUSM0hrx4v8LYGiAmV+2Suvrp9j/FxN2kgujhxP1tttxyTBXiUStYMkeYkQJ4/88YYV8CTr5cBJIlDcPzgONK28SGwLC4ema9aHGFK/JnzvNEtnv5R3ierkEqYXK9GrAK0HWqbIe/KChX6Lm1lGx3SMtYvx6iyXJHe7RCIzlIcF9i0DN63lQjSi+suidHEId7YnK/tljAqAMy+LtPnOOl4oS9KhJWzPMT9g4SJg7D8ewz6TOop/VlhN83UD400e0yN7fRVOUu+onQXQNmJBs+ywTyQDGe2CtfK7SXQp3xnwNBNXV2CWTXPXcWK4RC0eDxHyokZ9MaAc8tgZDQ876+Ja6QdTR4IosswuyKPOddrO6ujdNdnzfVcB4xa7uUpfMNGgjKlUeIBH/PTDTh/GUIWqh7f0hNIiZnKT2V22CWm01gcOUpV57/+fVZGNs9Is/6svbgmhfAi8nqqv8s=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0241265f-b17c-4ace-9c98-08de0fc79a22
X-MS-Exchange-CrossTenant-AuthSource: BL4PR10MB8229.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Oct 2025 10:58:29.8883
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: amTDnaYqfpZIL+7zDPfX0Z6CpTe7kRSL3RLg+E/Z8nsL9WfIsGU9K3z/BgHDa3SgaYc2yeapzcOlsc/mYgMvFeZEvun16pGakhvckoN+tg8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6309
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-20_02,2025-10-13_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 spamscore=0
 adultscore=0 suspectscore=0 malwarescore=0 mlxlogscore=999 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510020000
 definitions=main-2510200090
X-Proofpoint-ORIG-GUID: Kpcu5MVePK-Pq5pmBKNtwZ1to7mJX6iG
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDE4MDAyMyBTYWx0ZWRfX/LngaFjWEreo
 5HfQ1vqokBUioRyQwjm4diV2gyy6AqaBZ9xloSZwQD4Pg9d4s5+3fRpCsx71oAJD9G3Bgkrz1/u
 2rOOwABRDT6YYekgAMr078/P+XVxgGhbYsxP8HXu5p1ImYqYzyPP/EWn4xBN/zLD0AOrgzQtjMy
 dxl0qR+8rmm8Bg13NumdhtVv9IQVnTaScojviMQCWkDXKiTW1OzbuV+DLvfwpeXoM7Xxi+hE0mu
 GToUKhmtCkyCU4jdxIC+JWuXr/tgmtZTaGF25/Ulxu0Rf+KLIgGgXm/Tambb6vSSC21FJHEvfL+
 EUAXRImVXCsocmMH0cAC2yhdtjP9hCTnbR0FpCfUOsuTKGmp4+H44xFGQ/PoQFm95h9OESmWLOW
 ZInahqGr2kJoHopijSPx35zEmc0Z8Q==
X-Proofpoint-GUID: Kpcu5MVePK-Pq5pmBKNtwZ1to7mJX6iG
X-Authority-Analysis: v=2.4 cv=csaWUl4i c=1 sm=1 tr=0 ts=68f615e0 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=NEAV23lmAAAA:8 a=8vbGaJumKrr2nQpYZncA:9 a=CjuIK1q_8ugA:10
 a=UhEZJTgQB8St2RibIkdl:22 a=Z5ABNNGmrOfJ6cZ5bIyy:22 a=QOGEsqRv6VhmHaoFNykA:22
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=BDSGg3f7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=vfW3hsuI;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Sep 23, 2025 at 01:52:09PM +0200, Sumanth Korikkar wrote:
> Hi Lorenzo,
>
> The following tests causes the kernel to enter a blocked state,
> suggesting an issue related to locking order. I was able to reproduce
> this behavior in certain test runs.
>
> Test case:
> git clone https://github.com/libhugetlbfs/libhugetlbfs.git
> cd libhugetlbfs ; ./configure
> make -j32
> cd tests
> echo 100 > /proc/sys/vm/nr_hugepages
> mkdir -p /test-hugepages && mount -t hugetlbfs nodev /test-hugepages
> ./run_tests.py <in a loop>
> ...
> shm-fork 10 100 (1024K: 64):    PASS
> set shmmax limit to 104857600
> shm-getraw 100 /dev/full (1024K: 32):
> shm-getraw 100 /dev/full (1024K: 64):   PASS
> fallocate_stress.sh (1024K: 64):  <blocked>
>
> Blocked task state below:
>
> task:fallocate_stres state:D stack:0     pid:5106  tgid:5106  ppid:5103
> task_flags:0x400000 flags:0x00000001
> Call Trace:
>  [<00000255adc646f0>] __schedule+0x370/0x7f0
>  [<00000255adc64bb0>] schedule+0x40/0xc0
>  [<00000255adc64d32>] schedule_preempt_disabled+0x22/0x30
>  [<00000255adc68492>] rwsem_down_write_slowpath+0x232/0x610
>  [<00000255adc68922>] down_write_killable+0x52/0x80
>  [<00000255ad12c980>] vm_mmap_pgoff+0xc0/0x1f0
>  [<00000255ad164bbe>] ksys_mmap_pgoff+0x17e/0x220
>  [<00000255ad164d3c>] __s390x_sys_old_mmap+0x7c/0xa0
>  [<00000255adc60e4e>] __do_syscall+0x12e/0x350
>  [<00000255adc6cfee>] system_call+0x6e/0x90
> task:fallocate_stres state:D stack:0     pid:5109  tgid:5106  ppid:5103
> task_flags:0x400040 flags:0x00000001
> Call Trace:
>  [<00000255adc646f0>] __schedule+0x370/0x7f0
>  [<00000255adc64bb0>] schedule+0x40/0xc0
>  [<00000255adc64d32>] schedule_preempt_disabled+0x22/0x30
>  [<00000255adc68492>] rwsem_down_write_slowpath+0x232/0x610
>  [<00000255adc688be>] down_write+0x4e/0x60
>  [<00000255ad1c11ec>] __hugetlb_zap_begin+0x3c/0x70
>  [<00000255ad158b9c>] unmap_vmas+0x10c/0x1a0
>  [<00000255ad180844>] vms_complete_munmap_vmas+0x134/0x2e0
>  [<00000255ad1811be>] do_vmi_align_munmap+0x13e/0x170
>  [<00000255ad1812ae>] do_vmi_munmap+0xbe/0x140
>  [<00000255ad183f86>] __vm_munmap+0xe6/0x190
>  [<00000255ad166832>] __s390x_sys_munmap+0x32/0x40
>  [<00000255adc60e4e>] __do_syscall+0x12e/0x350
>  [<00000255adc6cfee>] system_call+0x6e/0x90
>
>
> Thanks,
> Sumanth

(been on holiday for a couple weeks and last week was a catch-up! :)

So having looked into this, the issue is that hugetlbfs exposes a per-VMA
hugetlbfs lock which can be taken via the rmap.

So, while faults are disallowed until the VMA is fully setup, the rmap is not,
and therefore there's a race between setting up the hugetlbfs lock and the rmap
trying to take/release it.

It's a real edge case as it's kind of unusual to have this requirement during
initial custom mmap, but to account for this and for any other users which might
require it, I have resolved this by introducing the ability to hold on to the
rmap lock until the VMA is fully set up.

The window is very very small, but obviously it's one we have to account for :)

This is the most correct solution I think, as it prevents any confusion as to
the state of the lock, rmap users simply cannot access the VMA until it is
established.

I am putting the finishing touches to a respin with this fix included, will cc
you on it.

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2e65cc96-5fb8-4197-b4c2-188c4378c417%40lucifer.local.
