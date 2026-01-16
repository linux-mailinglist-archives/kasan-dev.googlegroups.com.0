Return-Path: <kasan-dev+bncBC37BC7E2QERBVORU7FQMGQEB3TPZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id A3EE3D2D33C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:29:26 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-890805821c0sf64951116d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 23:29:26 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768548565; cv=pass;
        d=google.com; s=arc-20240605;
        b=LJemXxmwY0+MUAi6ShESnMxws8eJuQKWvwJiZeuwTduAFB+LKJPQuWaOPunrLazIgT
         urvudDNEZH+POqe7DWtE2b6jeCiz+NsYrPPz/c+lQtd0YTPTiQiq+Oo66GPYjqJjYFdI
         dgNJIfGRuJmH4eNk7ljQv2uopWQJ9mA1S/LX4ie/k4uiILNboHVuzJJJMLqKdCuTD80U
         ZfzJu/cHw6MuxKJZEjw9Li6LHiW0RKAzMXsNLkkGhvVDNokYuKERJXt2yPFpWLMpmzt6
         XV39Me30+8WcOgmZlvoLk80pqJsuYAvCzWoCXM5r32Q2arFt8vq9tNHq4XXfDVK5tH8q
         ZHHQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9YF1oWCtA69pecgcj888pCzvnXY272gAPbB7JqV2xy4=;
        fh=j9lBSBlRffqKUPvsOF0/sl3jMh5gwxk21Gj/zXD0MaU=;
        b=aSokh4RL7sTrEM75woVUxgYaffuT0MHd8I0MBE6fmoTDQiDBgr+aceWrLCydFwV6Ow
         /GqLXKv6L+VnIxkp8vSr9qRpq5BFOxai3WuKBYCt2Lqo4v80d4Q2ZrrqfhshYeSRV24+
         74HJSWQ0HYWntMk2Ber6tpIpCImY+egXIV/2gOZSpDtihp+E13XYWiq8bMS9SImT6c4E
         HFerT9vKwNgkjl5Y5ZlsAe05kc3XqOqOBqVZTP8I5UvDSHhCbYhGFxg13bVLw79kKWeW
         GDWMqERdQfnyX+S8Pb97tqnr+a8OaleuwClCX1gSRjzwxpfaDq9IapTlr0t0kEqi9wLZ
         tVEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Cibzc/Zl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="fqR7k/2m";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768548565; x=1769153365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9YF1oWCtA69pecgcj888pCzvnXY272gAPbB7JqV2xy4=;
        b=S07Y4ezbYOPhcbN74acnWVf3ZsEEzp2cUqF3JaXi+NsJeSF8ldGR0cnJWBra0GS8tw
         uVwmiX4lwPN0g4dFcy/fMMVy+49uUbu9iXc4jNlfRO3ka8AJjGghjWb8dYRC/PGrLX/4
         X0LqYbDlyg1YhrZ6rM/sSdxkrN+69385pUuhJhrx4W019l9epgsfjzEUMcndCe8WZ/Q5
         LalxYVk4yW1emTk77076gMyl/K6OqtL0cYjDVqxJYNxTuBzJpwUjNDVa1It4ie920Drk
         73pDL2j/1QpwVnsjzIXajSEwGGBOSfMTUd07PNRfe+D//99bLpic9OnkHsrDb3/IQMDy
         WSGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768548565; x=1769153365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9YF1oWCtA69pecgcj888pCzvnXY272gAPbB7JqV2xy4=;
        b=Md/Pl5yP3mAtHs0ez+4ml7XLWEHcHr6H9TNnYdozxx2s/TPGFI4V+QTf2h22Mvnxfv
         XQoutJb/zV1+h/23Spbwpno/Oqb3X75HTLakriJKSfW3JFwHoYsI0Ro1BW+n0Obn23hL
         D0OahTIaXvuZl/BkX5OSX8Yrd/r8mjP2lqJoHpVjQedo+TbpUrNywk789K7ZSiqLPNeH
         yFm0b7eug+OQKIv/zZ5gQTJ3XDi7cUGXEv+aVjE0t/xq+V9jRcOrPWZQFImf/uuAG6FD
         si82S8AHyl991cMJUNuaIFLeKz7IKNcicgcjMxXCW5pMztD4BOq8TF5tRFiBw9yS48Qn
         hKcA==
X-Forwarded-Encrypted: i=3; AJvYcCWzQBaa8CvB2TUw6XzB0BhQnfZ38cUgWN7uHfFj+t0nzQU0fk/aujMK0Gob+bg47GSdVTqpgg==@lfdr.de
X-Gm-Message-State: AOJu0YzEnIChrY73VBr3GiPZ7ykHVYCOjH5p8CWPg0KX22TtGgFcsPgv
	zrZAHEKZBjDn1yT8R094bI0879YTjFsjci2nLlekZdLiqqumwZZerzbk
X-Received: by 2002:a05:6214:301b:b0:88a:4289:77c9 with SMTP id 6a1803df08f44-8942e2d2bd4mr28984526d6.10.1768548565261;
        Thu, 15 Jan 2026 23:29:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+El9/8suFxYRbRShLhzqlcelb+9egtEgkJfRTKf3w7X4w=="
Received: by 2002:a05:6214:1c84:b0:888:1f20:6a87 with SMTP id
 6a1803df08f44-894221f03aels42483146d6.0.-pod-prod-04-us; Thu, 15 Jan 2026
 23:29:24 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVmEgMwFSYC37/X60KrkaVlccWojBXv2DJIvhJZqQ80UiIMsFq14CqkV5xM//f4KlQm2wkjfwyISa4=@googlegroups.com
X-Received: by 2002:a05:6102:2ad6:b0:5ef:248b:d533 with SMTP id ada2fe7eead31-5f1a716fcbcmr660173137.31.1768548564439;
        Thu, 15 Jan 2026 23:29:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768548564; cv=pass;
        d=google.com; s=arc-20240605;
        b=WFL5o+d/1pm57I86qSgRdWq3EpKh4r5o1FsUFe1OG7KNG8E7PsWd8RXNTKDBiM3z8Q
         Q9tTMjbxcuJHXcf8GwwbrA2DVAeQ0AYFMbrtPmoejHOY3G28TphYFSkTU6AuurxPtKps
         0I5kSER3XlAD9fUhpLYiys2XcP3+JwlieBb9AHoUt+uGY14+uMHP1wmd9o7AQ/fCk9Mw
         JcetZrleGRBLjQUqbuglaUMCLoxsxFvYKnN+Dra6Wf7Bj7Zj6IEOwEPSgLcUGGPLVqeq
         RNMDhILtc3YetcaFJQPRoAIao53B8VVD3+5bhvKjU4DKTZioW6Pq0hvsnw9Qy4cin69/
         vvoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=wjrLOZCCXcrxOqasdE0kfxBLvr1EjRzh4KDykcYPDBQ=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=QMypd45LpbvMEmF1O3vJ0JnakOXaFiMNaEyz3lkHE4o0UR4QPryMllD7qxVUWtIauL
         t5hhajRXWX76D0maNjViiZaHk/qb3d4t2iApV/xPj/gJF+Jtnjs4vzBSoDcWbx5hi6a7
         hKtytJJCbyKZrHYIeM8X0aIrWR/6HE0zoG4htI0DtcGRTsU1Q2O9LOcaf5kDLduaIUiJ
         3a+zYBgZwZzEB4YwOJcNrvlXG23zPgfUdYPuOFWRbMfKxkJTOFmxHi88W5cEdfBXp6cA
         KXiHCICf5zjx2RmCUZJp9aDFOzXhtMwoGoMpT6ViNfbFIKn1+WVZQtTt4elWloqJpC6E
         ukDw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Cibzc/Zl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="fqR7k/2m";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-947d049c669si64126241.4.2026.01.15.23.29.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 23:29:24 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60FNND0h1817752;
	Fri, 16 Jan 2026 07:29:22 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bp5vp4rxh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 07:29:21 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60G6k7Fd032777;
	Fri, 16 Jan 2026 07:29:20 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010054.outbound.protection.outlook.com [52.101.193.54])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd7ckbwk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 07:29:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MvaQeb2/f+MmahpveHR/IOepMgsDCxTHVBdVVhmPVlVt714XMWXuOS7LHLNZfbrFu8v4Cdpq/O74BNaF15fzaAwxA/EQ6u0u+4fxRSZSsATB5hBD9btcn1b8kUVqZqE7DSS0HHJIbRY3Qdv6nIWMdiIWOLWbFEEAhyiaFaL3xzDq0f0HPOTIbQhRnGWoq/9kVHqBdx7FT67mNx/qrgmyrTBb5Tktj/PXdiDbnOu0ntRXsHLhNZdaI0WaWIZIRhVIdin1HRq1p8FjrlWe9dMDED3buxJf3xnqrn7RTIZcBnITo7q0Bew/zgaiv2c9+Zj/BiVBygVPT0BxM+PnNXb5aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wjrLOZCCXcrxOqasdE0kfxBLvr1EjRzh4KDykcYPDBQ=;
 b=c/idx56NXbELVhS5uVpYmYXImUgysOa8LLnLoqThLZTJ5m5De7pNm03BhPpZPkL6f4cNMeyw7H60NsqgcEMosaAyaW1xp3Yuzc3W7UdKw7TTAlMQa+STXnlhAUVy5NOVBxDKJ+JrLl6fOA/z1DVXMS+4i06wApsjMKQdcwLheGqjFZYKI30EXHzjHu8zS83Zdb/+Hp6t991lw50ffXhVft1NU2EYqSwJH+fxmj5yenR86QxiRb5V/3cbGVs8oAJqCVDEIgRzASvApyksGGvXxyHdTAG7hM1MIhwoKpQl9hYXg1YtFVVa5R67qaRfwos8KweIUp3AuVOe5peri4UDCw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by LV0PR10MB997636.namprd10.prod.outlook.com (2603:10b6:408:343::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.5; Fri, 16 Jan
 2026 07:29:18 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.005; Fri, 16 Jan 2026
 07:29:17 +0000
Date: Fri, 16 Jan 2026 16:29:07 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 05/20] slab: introduce percpu sheaves bootstrap
Message-ID: <aWnow3tQv0KxSOMe@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
X-ClientProxiedBy: SL2P216CA0168.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:1b::7) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|LV0PR10MB997636:EE_
X-MS-Office365-Filtering-Correlation-Id: 40ef7198-b446-404f-2207-08de54d0f505
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?5DtMEYTxrN+wDh7ipENws3hATLatWOlYM0jbu/CIEzube41137CK2WLNN3DH?=
 =?us-ascii?Q?D5EJ0Hcst/qlJz0mwjI2Yu42ISbFt0HiWdxqCkh98lXyw5CdZwB6DKaRCGO4?=
 =?us-ascii?Q?7g+RHexiW7Ulbd23k5zUDN9AXAqxyh21/3MB1Flzz5wPSrNDRCryMMfs7P5W?=
 =?us-ascii?Q?SbWvimhaKUu6/U5BSC9lk3GD4IIMZK8VWjPAKY14Wj/BiZKEF409JtKGehFs?=
 =?us-ascii?Q?kdyDUiJznAnf4ERNxivLQwqhUY0rA95+HwCgLR3o2Pp8xk7o2haUFBw/CHT+?=
 =?us-ascii?Q?xxHdE0GV1VNEFk/NSc8UQGJKS012NAtif3ICfUzkbA4lOYibKlQMHY010yG2?=
 =?us-ascii?Q?RL95Or9BoKveJi0AQep1sl7JGdIdTX7MVTkFbUPp9SyTJcsB/vY4yQEXxp1B?=
 =?us-ascii?Q?Aau120yOhmOXifYBoQdb8DWYBY/s64+MxMjTeBluVXXGRvY5LbII9kzv+SY0?=
 =?us-ascii?Q?+QLGDc4zVJA9NJ+m3iZ6H85oFPJTOpUqhqx0nks687jofQLXWMcgyqoJWjC5?=
 =?us-ascii?Q?fo0LW4+RML5EhUv+4+xii3YvUvbN3PjYiwaJPI5hEmZiP8gsvlxevDdqgkjs?=
 =?us-ascii?Q?CTzv6A4sNQhABjFbDGhPkd2iLL6TxT3vbh3uc1M92uMnR6g9JMeInt0bABgd?=
 =?us-ascii?Q?PNcJjW5JRL6AfEGsIwphW3WApOKib+qkvYGd6tcI2ANT09Sizxl3xzXxL6HU?=
 =?us-ascii?Q?h2FhD7kkd1isY3ZkrUvxlczP2lbKhl1rw6VuusGKAzweAGC/4vHCR2x7lxbX?=
 =?us-ascii?Q?as7CdMOgWirTCPBZggphDiYWSZYsvPYV4JNiAzURmVgtpyyhoBjfuQaBmqHC?=
 =?us-ascii?Q?HiEOiNzUFcOffbK3ZTymJreq1z3SzBxceYNeJ4QyqW4Hajc47x1qKRZxN0/8?=
 =?us-ascii?Q?88krKfJ7k+x85iFjA4SVpvzGhoVCgeO80dSpxJLuqctatQFYO1UHg+j5V+Qz?=
 =?us-ascii?Q?sbn/LRuI/sN3pxau4Lz5SX+Fn+6YXlWYKqUQHXmfE2F4YGCJB8S+XhhLIE9C?=
 =?us-ascii?Q?0aL/OZM0/Lrqhs8aGPror+Npxvq4lc8jbhCaX+uhqCF2sJ+pXMT8/Wp53hCK?=
 =?us-ascii?Q?rrEsvS0llCHX39TaFHN5OCqBfcckzubyqvm7AlbSuNYPv0dBE9Wo1e6YUQiB?=
 =?us-ascii?Q?D3JQSnm2sSFLOZY5FbwmW6QDps/UIv6DB2evmmSeuLtECK9yZPMHoFgqLctI?=
 =?us-ascii?Q?ODSEY4lHuDP7Qomy+9h+kNZoH2dpNJh8vXHvrnFvZoTjIE8GFTB5TzVdoIyz?=
 =?us-ascii?Q?561IvNJaBuIFtJbxQCUNc54hb0EczZRVIjYUPrwL+5SKNBNmBPyQp7ZX8/GZ?=
 =?us-ascii?Q?TdxlnuLI2SRA0j8poLjabjp3ikFBrErMUK0KRoWFEraYkWRyx6E1qyeu13+q?=
 =?us-ascii?Q?pzcRVlz9WeqF2A40YUTMIlKB5a9vGqyvrccXOt+0RpFGSP6oyxDaswoZJGUn?=
 =?us-ascii?Q?g2mlS1pBAP8kGnuxb1qdTFZobgYvlWo3nMtmouu+aS7HZXRP6mhjH92Epdre?=
 =?us-ascii?Q?eggozCSO7r0jh0+1OI6kt+M69lVylBVIJZ/vooSXLpppM29k33I8/NbxgwxU?=
 =?us-ascii?Q?CSp8h9Nn5CUElxMz238=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?R6HG1FPAf3VNEpxB4zkLnVejSgYvIl00dBqM671hirX0z2EtkSqQvedFi6y4?=
 =?us-ascii?Q?RKcNlEt+WY5ubXJ59cRQpp/niAGw3djhBwzLnFcQ5GZpbDRlgsR3gsnE9onE?=
 =?us-ascii?Q?sadix4Fdu8NTNIIN+QUAP57rXjbTVZ0vdSA9iFh4+yhu/7xzQpQNoXI5XRIl?=
 =?us-ascii?Q?TwV0v5jktvyEFpat90oJaaFN15Cu5UudDuYCX3q1k19924iy78h9kTm7fWaE?=
 =?us-ascii?Q?MkQte27kAM5wC5wo2f7aZx5BZrc0G4PikEFBQGQlR0g2O7bK5ta+01mNdZQx?=
 =?us-ascii?Q?93rLmrKJ+RCIW3gsG4qlAbiF+npMakfPc/yJOCviKnFsyvr5cCr37GLkyxJs?=
 =?us-ascii?Q?FvBRmnZSl8u6mQizDOMQBcKTDp0sfyk99WwIOecAPPP1EtCnVYleGGamasP/?=
 =?us-ascii?Q?mFQV2Bd7IJ0py4lhgqkFDQQWaq4xJiB/uEZVMYutcmUvpEfV3m87mcGrD7Eo?=
 =?us-ascii?Q?o054UdhdD3C680ncoSg6fPhfN9UZjH6+dw0uks8A+fI4bOIt0+EOeSHBgS7p?=
 =?us-ascii?Q?R08cFFUYT9yRdrsVguUFTXd/AaOdTbnWpCuc8e3qLR6lXMFmahECp/6/tXFd?=
 =?us-ascii?Q?oGXzS4UQmXQ3NinCMeWOTx+HRqzMUkZqvQ1fYvhh8Iz6LbZN+odNQXJQs4VE?=
 =?us-ascii?Q?6hVr3Tf7xR3vC0avlWBaCmJG92XBmQ/KU1aD6tQEE8kzbpldj2Z65Xh8i5J5?=
 =?us-ascii?Q?JMRiMOOiuWypGh7R/YUx5pXCxIoPL57g6np1LKuDxA/T59vSR0bUZOVGea+O?=
 =?us-ascii?Q?udXsYQhHe6E3SRkLEobXlHtinwyeD+dCePHWKV+sMDmQKMUYYiRrSanFGZpm?=
 =?us-ascii?Q?AZeRawaiUEaLIteR6+2C3xO6jLWQE5y0fdq56hjPE+cXQnqtKbyv6SUinOs3?=
 =?us-ascii?Q?O2i4FlpQnY2JlTePWxQxiu0KMD8/cnh1/PIEfs4LaNkxJ9jZB0bp9ikXL33g?=
 =?us-ascii?Q?bm2mpM7knByuw4K9FU1m0i3qXsu8gLDZlRVRI9fY/NKwHCZugPiaSuwh6owY?=
 =?us-ascii?Q?LqqukdE91/gdigj5R4rB4gg7dP1Y1CQ5lmTYY2IUQi05lBTx6IITvmoLEoMm?=
 =?us-ascii?Q?tnmYPY7eJFGSvvsE0ZKzxC0k8bWF6xxyMRULtIE7QSn/MzrO1CEbf0Uuw9xV?=
 =?us-ascii?Q?MlcM5svaF4X7bIMTzqREW+kOS5NCm5EE7roIx5C/oVNFCUVAdgC2bgSFy4kl?=
 =?us-ascii?Q?EiRCPmBCyA6xnLQAlhD6FOOZ1hiUSQ/mPJ7G67jtVu2B2dse5lih/SuWfgI9?=
 =?us-ascii?Q?ydFqEw1OXgvtF9yQmG/QqFMqCLBrO/u/1eLAuAIXJkHmsPIwTfVqeIZLPOYJ?=
 =?us-ascii?Q?voUfClf9oPMeWmYqn1aw4ss0wM13yk5xB2Z5QKyarR2q6ZARQ2Xa3caGqccc?=
 =?us-ascii?Q?875BgszKFThFub8dW739bJNX3ycqikPDMQ7f2SC61TEFMGthiO2iV8Hu0ZpH?=
 =?us-ascii?Q?31gGjslCfi9sh8GzzqUEKAtlTbJIxVBqHGU8bHTRSFfYiT09dNT3Bj4/M2ej?=
 =?us-ascii?Q?4cRxQqLASJYpJCAuyAFxTkL3R7S5HCkF0fcNrlTMfSlCbaYhRPwcVqnFtGCp?=
 =?us-ascii?Q?8W+d+wt+XuaQ0JkaWdbjNbzRl4144f6m2auW4KGhuonyiwsOJH9VOTXtzDAY?=
 =?us-ascii?Q?SwjFiolbGVLJ/fQJrQtnU3B8BwHfnjYeOz4ZHN5n17PIS4TMWbA6t6gWmlWl?=
 =?us-ascii?Q?pgFPoDZaGaVf/JRpaXsFHZJNnG6VzltzLkoW10h2xgq0CrSQ5Ckw8078Ue47?=
 =?us-ascii?Q?ktA/2kGk/Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: cBUSucIchFHXqD7hiFDAISC4t6UovXTFLDx9Xj5DzLtsls/Y+rom6aUu1RdJYDgDzDgVGZ/5mj/qdHegMux4ayXKngOEOowbjihGNRR0LfC0SrAkODpTT9FImDtQW03lgr6FOdIuHRe4cdyHg/QA7m2NauxBOLp8UWGqGa9XNdf9nLNbZ54TFoNsEjSSOBmt0gLr9BGKBhRksxfss2PWDIlM6CE0j5VSMNRLyfdU04HHfp0Y4oHtY1eG2qwKF7fTdmnmA5kblKBUIF4fJhas39Et1uxDJ1TBE6rW6bnmmviKUqBACvcnY+U2RuBqRPdDJF8/hPReAA03tXSY8ZDnDFP1FjX9WbZIj/jNGMujozdRfc3cdcQ6ng1nX99F4u2T9NdQP43D9sCXo3rzg9T/r5iy8p1XfcV/DJZvyMT+jvSLWLpF0ULd0JM80Ek9vTDMHxhOD9tu0JTqPzJ17HAI4C+0VmFBTPLrov/DcfWXlDS5OZBQtuNnmb3qiH8Ed7ccAqnKrb+oNrLuAHPrb0SjQSTyJT+NBNLE5g4gzJkwgmo04agJFbQGZl31miZYPHRM+T3JsEPv1aZkf2YH4eAP6jos4k7aUDpxPtK0W9VwJGs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 40ef7198-b446-404f-2207-08de54d0f505
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Jan 2026 07:29:17.7094
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: lY8I/qBX9gNmeiKct5tQN+8MhIM6WWry/R50f41nbS/Gh5WkQc1kuvziJQRhx0tR89sH7K9WBnWRoWZd8MzsjQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV0PR10MB997636
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-16_02,2026-01-15_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 suspectscore=0
 mlxlogscore=999 bulkscore=0 malwarescore=0 phishscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2512120000
 definitions=main-2601160057
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE2MDA1NyBTYWx0ZWRfX0zrLr+4kWYOw
 LjPoLezDw+gfTe/wycUIzicaDoCK+8+fcHPKtCXKJCp3AXhmoMDWsCi8NtOSMtSx+tECaxpLXWY
 qUSXKqCCUiQEzWlzqr+AaWRYVrD9m1zKipvdzYe07M4a6HiFvpk0LH+nz8uiTvgiWom83LsPVR2
 GS+yeggKraUatVh5Q0BosPx5VC0gHNs36GWQXUtEqN2Eaqzpuczl8MFY42HFq3AVF0pvJyYVODC
 fQtJlNgpQ1mhSE7KGjsB18iIUDgmj1qbde98tn3J+Cymb53l/ZFIE39UWGCIUxfnNfJ9St2aH6H
 mEfoelZ6/pWbQsGYUY24csYiQ2bejLW+HbenyfNaIzlANckwf1xzjdG9l3WBaD2w7iB/aGnC2sh
 7Hvp4Gj2kZHjfWMoMU5XiDgIl/Tt0ntxDhH8CV1ETm9fB4YiuJjCry7EYnleLNB2GNkKENfUW70
 TaeZG5Ct7oylUIqJ9FA==
X-Proofpoint-GUID: yQBaaDwFzTxfhgmYr2U3Fg9BadBIxLEi
X-Authority-Analysis: v=2.4 cv=aZtsXBot c=1 sm=1 tr=0 ts=6969e8d1 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=yPCof4ZbAAAA:8 a=dBbnmaIThoCBKMIWZm4A:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: yQBaaDwFzTxfhgmYr2U3Fg9BadBIxLEi
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Cibzc/Zl";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="fqR7k/2m";       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

Copying-and-pasting the latest version of the patch to review inline,
https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/commit/?h=b4/sheaves-for-all&id=daa81eadcd0f9e3b8085dd7fb8bb873f4cde88b4
> commit 36b6dba09fee446540b8bd6dd771859aedf2aafb
> Author: Vlastimil Babka <vbabka@suse.cz>
> Date:   Mon Oct 6 12:13:33 2025 +0200
> 
>     slab: introduce percpu sheaves bootstrap
> 
>     Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
>     sheaves enabled. Since we want to enable them for almost all caches,
>     it's suboptimal to test the pointer in the fast paths, so instead
>     allocate it for all caches in do_kmem_cache_create(). Instead of testing
>     the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
>     kmem_cache->sheaf_capacity for being 0, where needed, using a new
>     cache_has_sheaves() helper.
> 
>     However, for the fast paths sake we also assume that the main sheaf
>     always exists (pcs->main is !NULL), and during bootstrap we cannot
>     allocate sheaves yet.
> 
>     Solve this by introducing a single static bootstrap_sheaf that's
>     assigned as pcs->main during bootstrap. It has a size of 0, so during
>     allocations, the fast path will find it's empty. Since the size of 0
>     matches sheaf_capacity of 0, the freeing fast paths will find it's
>     "full". In the slow path handlers, we use cache_has_sheaves() to
>     recognize that the cache doesn't (yet) have real sheaves, and fall back.
>     Thus sharing the single bootstrap sheaf like this for multiple caches
>     and cpus is safe.
> 
>     Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWnow3tQv0KxSOMe%40hyeyoo.
