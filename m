Return-Path: <kasan-dev+bncBAABBD5H4O7AMGQEKWKXDRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id DADE3A665CF
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Mar 2025 02:59:45 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ff7cf599besf6064682a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Mar 2025 18:59:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1742263184; cv=pass;
        d=google.com; s=arc-20240605;
        b=EC6ml/aZALTEJE9xhwOv+KNilG3gJwMGzPnUEe3UiBtReWGKKdJZKur6p4Ctw/7eub
         AzfCRVztXHUTx+0V5ZVJx46WVQn/UAixeyGBbE89uqkSSEgspIfsTYdsICzfXGSZep8o
         LZAXGMwsZe8tAVyWZsTQdmLDmp9u8+4o5uHXhXUPa2KpHj8Y5XlHYboczPBLsBk3iK5x
         uQsAIcQoWyhG8R6SGr9k5uXEd2qCbFt2gr1BCyPxmhkCXhtv+fIbt2pjl1mYg90Zvht2
         jlKvp/hChE+JRMZFpj5WAsSJlz8KvVAedKYEdbLvOEJJUmtlqxwuRE0HHDxkNXknjGwR
         YKNw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=UdEkH8/fW929iuVwHnBfbPyvxl80gX2Djb33FRKKFqs=;
        fh=ExDp3hvT9t9j3Pq+LDDok3xp3Og9p3mNzMV10nbwAK0=;
        b=MUFDPVjOgoJDequiaznFWFJPX6niI1bgqjibA5Yqh+2WYLnapmR7oJrHCKfEo2bywT
         nEZ1DJwclZ10PoVARnr4IBySQV1gguxag0Nyy+X341yJkZF1JMsw5XgX0Y5eRGRmC62D
         D1EnrDomATfmrPua+5KylqHLUwE+kOW+SNUY+87zwk/SMGl4DT6limXcyY9NhSRrh4lA
         mfjYz3w66gC9xQVReGarAxgQV0CvWMcok1MeEpWqOPZHB6HP8/dTERcoD2dpi1riL09d
         1ObMLknnRP+6D1ojSdz4DH3saFoUxunr6/EaguKP2iXenad6wtfM8hBWK9/RGOg/+UcW
         MzsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b="T/lDe39b";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="D/iJq3D6";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742263184; x=1742867984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UdEkH8/fW929iuVwHnBfbPyvxl80gX2Djb33FRKKFqs=;
        b=szGQ/ozQoaaksBwYOAaAByl3CfwkcGP6PTzwq3cAvImBNORA/Tw2haAJPHbQzV6l3Z
         QlDk0BbM6x6ZGQuWNYioOi/C3RCd7uEynNZ55q/WaomhyTD+j6pNsXbL3C1M/y9Cx5aB
         ZTZENnSotkBVa/xcy2M4fFNsXE6lsHQQwLaCa6QKTOkVcdE6gjsKffHMRbZ6vnjApp5t
         sgYWYLm4LJ73sN65NzEQRJUlXTJgONeE9oU1563Y1Zx1CXwOi2ueFoGly+c+oKh6fyfo
         Er1iN4qhyJATOHEKsR2TJDqnMbnFwTiWBK7WOdAE7MvK5dM1aovMWWOWksFKDa9SUFgn
         rjvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742263184; x=1742867984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UdEkH8/fW929iuVwHnBfbPyvxl80gX2Djb33FRKKFqs=;
        b=pW8WnP6KK6d0o/2naTICjlSPiHSzwvLllmq/lkXmne7z6U0+CHhxKWyoESxZyIpq6Y
         rWfJuzTER2kjf86yWeGykPRQYUv8lGpSZiy3DQMoOcNiJzP/zhJBAd9ttfJAT6cMIMpN
         aW8BFxJdEy5RWG9jS3eYJ1NnQAF9ue2g0/xInNT0ocB50Q6Kbp3rLzpllAYTD1j5YwWH
         h0pfmIUoD1Z0zBml6+dXKrdQRbtXcklx6iBk7HNV5qMH0+ZTboDjh0aSQrIUQ1raVJLL
         GuWPSFeuXGJPwdb3k4fdugVl3IOQxJ2blkldUcYovczPyRUsJm06XnYpXvjg3ZCnEDMr
         wfJw==
X-Forwarded-Encrypted: i=3; AJvYcCXc+u80aU9ETYmmaoA72BxXV59G9oGC2DFMixX18KH3P5YVOoiP+DpnXF9Qxyg6AO9vDaOnUQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy/N5tXAK81HQ0nTag2HXZbVVzN/IkYmEltcW+iUY+QDBpDyEux
	NhHdsnR9hgYQgIXCOxrem2elyK6txyErn0vi3iFKj1lm6ko6gxTP
X-Google-Smtp-Source: AGHT+IE/gyaRrrm8xRqkNBY3BDUmye486WaojMe3OKi0sjIhr/rzIB5PfMlu4URueTUqy/TmDLM9BA==
X-Received: by 2002:a17:90a:e7c2:b0:2ff:784b:ffe with SMTP id 98e67ed59e1d1-301a5b1304cmr719261a91.11.1742263183897;
        Mon, 17 Mar 2025 18:59:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJGok8n4rx8wdsvRBVLP0OM6FcVopRT0TcW3uCKhFD1vQ==
Received: by 2002:a17:90a:5806:b0:2ef:9dbc:38e5 with SMTP id
 98e67ed59e1d1-301531c40d9ls805231a91.0.-pod-prod-02-us; Mon, 17 Mar 2025
 18:59:43 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX5kvDl1KI+0MFmrj2Cc6eyVlWRFoKSSvmYlt0IJ+xDEBT05NoKOubs90rzk/wZehkWEulYeqt6tMM=@googlegroups.com
X-Received: by 2002:a17:90a:e190:b0:2ff:570d:88c5 with SMTP id 98e67ed59e1d1-301a5b12d27mr719162a91.9.1742263182289;
        Mon, 17 Mar 2025 18:59:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742263182; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+CLOeAFrFRoQLnEhQisbPzdWe4IaOCnib+PpE940xjmW9jD/odPaq4u3+Vyq5gVHC
         K1SsIWjzNxIPmp/FOYosQj9w2tRU+Gm7vtkIXprWhtZm3ihxnk1XL7kclBfN4f2zmxal
         fLtAUW/P0s+3FZUQfLpac6dK1IbsnjylCq88g3J6FkCwRlMXTjVVz6PgV42pG5Kx6ane
         Vg7/q/O8elX/JEbYjmoTuKyRAoExOSxzT4IZ/AOrwN1xAt0tF9p2/rWYJYpxs6H+DRus
         m6YTEwkdSt0FFIa77vvXZnVftW2DRLgcfwYLpqyKirGadhTi9kVDpcyhxNV/Qrl2t8Wt
         QYLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=V6PHt35mQ5mg1ThXXmkSmgl36JSZluCXoY64qfajUyI=;
        fh=NleINQGwlKiSC72yQZdtpY012c4EM8yKCgjcVRN5UWA=;
        b=ayo1KW7nF+UYZjoiD0BvLhPCC+M4FfhoCJgPqdKd1zJo4HA18q5E8OxbaRwFgsMLsi
         i9x+PsrO5HxOEcyF+18RliXP3Zq+djKvwI3sOs7FffEyzbMHXoblFtHrVJ2VJ+xma6mT
         8GSBTqF8KXy03UplEFc41DVF/AYneFl3awSUgvnP/dKQ7WO71EoHk/GPQI+zTD578z83
         2FzhCINyMFbR8AbKf5oRaW5hpoWzARkwy3kqWuaP9GCRQMKx8vpKjGG+CURc++d0ZnBh
         UKVbc+Z1j8IUs1LuBNCZ1RQjbnWDBKOMeRu4LxMMAE2t3RVg9avIh2m0W3z2EZfCw530
         epBA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b="T/lDe39b";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="D/iJq3D6";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-301a5b7007dsi26384a91.1.2025.03.17.18.59.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Mar 2025 18:59:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 52HLtumI007190;
	Tue, 18 Mar 2025 01:59:35 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 45d1m3m626-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 18 Mar 2025 01:59:35 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 52HNorOk022438;
	Tue, 18 Mar 2025 01:59:34 GMT
Received: from nam04-mw2-obe.outbound.protection.outlook.com (mail-mw2nam04lp2174.outbound.protection.outlook.com [104.47.73.174])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 45dxc4xa7f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 18 Mar 2025 01:59:34 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Z1c3gx+lPQHBRWsP144trFy4quWeaWtSWdBAE9Wblqjyt3OyDtHm6WpYqctb+KLwuVjrfgIB01457o/s1R6fFWKCyIHGQh284ZubwxGp50AbatDqCsQljxlKSmHEgLFxz+Nw2hlHRVUuTT0D408RrWxakNBM0seGoOkkbau/NZ0dcZqAvmrdSY40n2r7t6w1kD8AP67LvbBHNDByspnJa59EIA3MRBskV+PqXHZp4b059auyNwql+qPE/4gzRTg9KPvQXPzrlicvVPIVSi7XpUKeMTyVTgh8Uuiav0XCZ4iriMSJAVIiHhOYGxQjtFhyOJdhXzYG6tPFmwZ1u9jssA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=V6PHt35mQ5mg1ThXXmkSmgl36JSZluCXoY64qfajUyI=;
 b=LuRx1cTxjs78edlWX3zKf0eCPAnMvan1M4IlDqQlPqhbWEZWs5h9dVt318y8Dlw/m5NOe3bwdWTqCAjM5OB/Hdo7ChB3ittdROVgwQveuHPbvJY/htwGqUgOIn9A3L9DN1I3O2qCpZpoeyTZKUAHp4jnarPRKpYAVGa04YLz4fp11Lh4auDRvoc8ivUSu9yF9krCM7tsUNMN64qZDEEN2eASwBt35Cdfd/942hGyEvrUncepfCGe5ojlP2uF2lMybt0OWQhV5XAUVQqFZAtiuwD0VtL1Q1a/NixfpNvaRC8qkQ3rY/YrNwGatxClJag6nTMRrLfCiAVHNNJ2L7Vzng==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA1PR10MB6218.namprd10.prod.outlook.com (2603:10b6:208:3a5::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8534.33; Tue, 18 Mar
 2025 01:59:32 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%6]) with mapi id 15.20.8534.031; Tue, 18 Mar 2025
 01:59:32 +0000
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        Harry Yoo <harry.yoo@oracle.com>
Subject: [PATCH mm-unstable] mm/kasan: use SLAB_NO_MERGE flag instead of an empty constructor
Date: Tue, 18 Mar 2025 10:59:26 +0900
Message-ID: <20250318015926.1629748-1-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SL2P216CA0206.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:19::9) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA1PR10MB6218:EE_
X-MS-Office365-Filtering-Correlation-Id: da4fb964-4da0-45fe-8722-08dd65c08644
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?iBTUqad91wl08lfsgf14fFSx67zMmivDwXDiRZhvKEyc0P3vN0dRw3OOsskP?=
 =?us-ascii?Q?r3TdFOjtDn2Ve5IwgnV+nQeFO3+gnGTK4IcXNFxEAq4NN/rDWgHFYEJmtzTy?=
 =?us-ascii?Q?jZzoiPKYBGjb+poZ+GZAUTn0U5wee2lxPggCs7VLPOexepNYZbVwYdwUtTkB?=
 =?us-ascii?Q?ZR9BFX7hL2F2ZbU5G0WqUYSm9JLYcgLqZISGlwCo9YexaTcvMpwasAIPPWNV?=
 =?us-ascii?Q?aLTKkJPvZNaJPyV2c/uIRuad/chOca1pQOc4livVKNiKQwxcTWFdmnvO6Zni?=
 =?us-ascii?Q?Z6kCRD+dovltDAnYB5wm5l8ULHvLgJHrCLDfBUZ95yRRuN5RTDRJZ+/x48b0?=
 =?us-ascii?Q?s9IXhEBzz+nU2J5w9HoAAHYhBg3gYHbBJJhWBMMuzTukig0cz6vZFtiMuTHk?=
 =?us-ascii?Q?7n8ZCihQ9rhQLDpbc/rPW8OI8GOrLFJmL1q5SYbQm7L6dWlcRglDBvxmtTVS?=
 =?us-ascii?Q?OrxVFGfInBrPLqyFtrLY4Kw8Ha0WTcuxc8b4fCBeyHLYR6ApfkShleO20of/?=
 =?us-ascii?Q?/xk8cvXyQShUVjK7EZ5ruH7UXr5RsM0W7gHci4CoadBU69xokr7vCHNdTrKv?=
 =?us-ascii?Q?j5gQNq/Xuu1sH2XWBtSr6aS6D1U8oXwZny96NjtF0HOegkTSqd/B6qee102Y?=
 =?us-ascii?Q?0Gh7oXoT9sOheZibJVQ9164ptx3ZSaqyviVBWjsdHx0Asj/9APDEd3lYNSje?=
 =?us-ascii?Q?kBOblBlhYhjIBmqNQMDipZx/vGeq4mMVtsnSGVOi050HYCXrFCYrr6ohkSSG?=
 =?us-ascii?Q?3Xl9dEli23Za5M279L3fBGgmouuX+L7PqJw+BfiImHdvCJraRb4Hsqz3WEd5?=
 =?us-ascii?Q?Iew5sr4je5a+ZEXNfm+D9GOm+zH/0NEMJT6ZLi5EN3IdUEiLQtmPz/sDgI/F?=
 =?us-ascii?Q?IoiuwtOivtiVBrN+SFZD3aeE7pv49nzd7iTxzHly7/bMXP0UoCUGQMl5V4vr?=
 =?us-ascii?Q?SSdg8DdLCL43MbB9cvqrL9OMWgk4W2vFxurGH+Del5qZbMc/hEvEWHpTWPUE?=
 =?us-ascii?Q?bYgEb6CIZLI+q/GyQ/XdeQ+ggHuee1Y/VTSPD+G20PeHi2CbGovHl79Mrhx7?=
 =?us-ascii?Q?Ti6QwV+/QSep0Anqm0wu+qT3L3qG1xCCvA6oYtLw0IVdDgm1fSmL3Wb05baj?=
 =?us-ascii?Q?FXPoyEvZNUR9FRAcPWz8KfmHcVRwKWEvvzs2Q0lZVo1Uzj4buSoXvsl6Qzlq?=
 =?us-ascii?Q?IUHWm7eniL3iG41Ytd+JuKXW//2+DBfHjcGBJt5+JJI2bH2RhesNO6Ur3WqS?=
 =?us-ascii?Q?TQfpbNlvQmHqtRfN2mWDBIgTTYM6/ssHnyWwNSOaGt6jGVvK3iQBoeEDcoeY?=
 =?us-ascii?Q?u+E4RoLWzYE+YofAgoSAW7tK7/xSGA/02hFp8xsceL7s6y3KEhVoH3wFCig3?=
 =?us-ascii?Q?gYb/oi1iqYvKVA+GFOfNTKAZcxP6?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5izPCIEn1bP+lW7jMIhScX/XCdp4rKwIGnzrJBYPELbfKToR9svQQiI5nLO9?=
 =?us-ascii?Q?CkaIHut61FGir6vbJATtSi6g1MOSPiT7Un9S4oyO9ZNhmKHNTu/SOruPnL6O?=
 =?us-ascii?Q?kmk/MWuCkcR7xyusmAKbloa/EwbuD+lQKQzTYFguH0j+3fDY9VDiJBw8DmOe?=
 =?us-ascii?Q?PdMS2gC7GGMk3rE6UDV2X87nBLfkDqMABy/xUjEn9wWOzVSPRQsTi/h4ND+2?=
 =?us-ascii?Q?hmvREJ1uJyCuA7/RD9UqsDnfKMmU0cIM8HYZbPm8RB+0Ynoc2Ht0OxAiESeG?=
 =?us-ascii?Q?/nQ221+lAgzBdFaA45AUi/tdDC/o2fiHkjQ+bLEkHIWA04WSZlAuBMtU/re1?=
 =?us-ascii?Q?EKoNENwChj/7ChmPuIRJKNwcJf90boxQUhyZEJal6HmglFiToGe56xLZNa/I?=
 =?us-ascii?Q?3bGyjZ2VwrAcv7JNR/KLaBlMdh3lHKI6YQNvZRCsnYgrWVykka0BW05/GnYl?=
 =?us-ascii?Q?sc8XQE7gaG9rYdszT9sLTQCBzbFiFdCqIxYr2bRjU8EEPBJIOJ039z3TXeVO?=
 =?us-ascii?Q?jw1Q1aHKCMiono+JYi4UlQSqiJbVsmH+CH6kfsDn6dPcvfUtlvtwJtFspvKS?=
 =?us-ascii?Q?uPiDBWQaSIW7/WJaPh1+WPLAUv7bx0wSPVEbGXbIgBCiuDB3NInGHFDKVvyu?=
 =?us-ascii?Q?4JzELVLwW1VQ4D0rWXdek4Xggwu9ncBUcjwp9MfbKEkICTvvh6QK+zTCctWw?=
 =?us-ascii?Q?Mc5GS9e4Bd9WIzEWMlnHOTeAcAajnwdFzQuDKAREhzPNnRPv10ShJcQ2PCX8?=
 =?us-ascii?Q?cHpftXqIdYse0/q8YMHqSY0tR3+NFtG5ou25NtIUORgz2RIhGnQ67ZBKbo/b?=
 =?us-ascii?Q?ZDBYYV3F3Pqrvh3vklEcjGmi+m+k0Cm7h8Lk3r1oIeTy0j1/wb28vC/vqqYe?=
 =?us-ascii?Q?H0k4uYw6uL4GEZ3kCryGbzkitT5a4EIILeb3TyqZ0h3jHoOPY0gwmWJKIV0O?=
 =?us-ascii?Q?sqzip/yAED+kmGWekE0rj2EcPaUU1ZgI93qBvehuuZE5DMqTCfhEXn6RhTG+?=
 =?us-ascii?Q?xYBqOGt13tLZjWvmvZVyy2xJnJjuhaLpcl3E4I5EF2Ki18/EYq6M7iqR63IS?=
 =?us-ascii?Q?V2nPFaeOgEHA7rdlU6E/bXuW289h3rI5K15CtDNKTiB+3MY5c4jGRFcOyGNz?=
 =?us-ascii?Q?N4uX5Ed5Rr4PviXqLfDyrjUN+64IuWPPaxMji1hLD5S4SH1fUQ1bnzMwYmrc?=
 =?us-ascii?Q?689cZwvPhwSYzJ5p9obMXVuyVa7VVliJMyOQyKUZnnLetKauUdarH+gA2tmQ?=
 =?us-ascii?Q?J8pbJfSD1q93vn584PYc34lzjLIocHgzIfg7w2nNxfhgB4oWdACO92Zk3yCD?=
 =?us-ascii?Q?FKxch0jt8SQ9hXzbvhQTryBCVyk0yO6XyW8gZRUweXKNJ/S0bMXoOxnYovFF?=
 =?us-ascii?Q?q651egSZL2o30LWCjE4bpu5jJAH9z4oGDAQlqAJbjUdAk4OahKzSlhKXEo97?=
 =?us-ascii?Q?tUUTZ0a87hiKczNzEFI78AZkphTn2zs7Iv3YaMuJyaKD9zcZYkgc5YZ9L7y7?=
 =?us-ascii?Q?+fD+TuPMSG7JQf+fGN7hUuDhFbmR9RMaO7uvmRAdGSFtDF9PQAVgWLsyB/Ss?=
 =?us-ascii?Q?7N/2W96NG9rAmEuB4VJEM+uY8+NDqR0mXGx85YZI?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: KGWR3I2x3N0qDzGwe+JLCxE7JfQ414zGAsgqBm+YG7L7BdV3Xvl1XbgvIGUbiTUc87lR79frYZB/MytUMWWmUAnytE1u1LaPpLzfoKQDp74gI0LmIO3AxhSdQY7CkbryKvISgu9w4xRmtJNSC2gnr7jphAZCBcW749HKm4uN+2Mf7lG4c3RZNHPTwmpOTWJA8gMcR9lgBwPs6053XMrFgWR7PUognaRT+OUUor3HDCCzvTMA9+u1GblMNb1qbjFKpP3rd60X5gl5HzDV5g5PGO9JJd00LgDoff3Wxb0VUE6fg9iceRFOivqR4K/JK96BqQLT6BTzUpK6T8SacdyjubdtkhEZNgTXfyGFfdA8AppnVJjayYRWEqQIjpOTBtmXZAOsIyzdpzFMYEgJiKffcGzPmqciTMT8MXKcmgYLzlLJMA0EeqiHPvkdukese3/9OEghgFoli+n7LETjPZ9aeTOXyo8jys7i8NAxqzHonH89ntiD/veZQyp0Pjeoc8u8F1BVsIR95hO5nkEg/KMso1tH6beuKJEa1yqxlE3BGcMoF2k8oWv311vYHfSpssoewVHtteHUuypktkxDL9kocIK2sO12+PSjxKCHITqMwoQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: da4fb964-4da0-45fe-8722-08dd65c08644
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Mar 2025 01:59:31.9645
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: r5iCknTvziyqVuQZTMvmmKUQJbL9nnJv4t3vdVCk1TyA6WuRgpayywlSxdEg2PoNAUR+zmK6MiGFBqQ7Cm9qzg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB6218
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1093,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-03-18_01,2025-03-17_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 phishscore=0 bulkscore=0
 malwarescore=0 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2502280000
 definitions=main-2503180013
X-Proofpoint-ORIG-GUID: B79onL_W6UEQE8yoWu0EZ6dceDoouH4c
X-Proofpoint-GUID: B79onL_W6UEQE8yoWu0EZ6dceDoouH4c
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-11-20 header.b="T/lDe39b";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="D/iJq3D6";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Use SLAB_NO_MERGE flag to prevent merging instead of providing an
empty constructor. Using an empty constructor in this manner is an abuse
of slab interface.

The SLAB_NO_MERGE flag should be used with caution, but in this case,
it is acceptable as the cache is intended solely for debugging purposes.

No functional changes intended.

Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
---
 mm/kasan/kasan_test_c.c | 5 +----
 1 file changed, 1 insertion(+), 4 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 59d673400085..3ea317837c2d 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1073,14 +1073,11 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
-static void empty_cache_ctor(void *object) { }
-
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
 
-	/* Provide a constructor to prevent cache merging. */
-	cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
+	cache = kmem_cache_create("test_cache", 200, 0, SLAB_NO_MERGE, NULL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
 	kmem_cache_destroy(cache);
 	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250318015926.1629748-1-harry.yoo%40oracle.com.
