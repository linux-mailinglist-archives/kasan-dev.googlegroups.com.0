Return-Path: <kasan-dev+bncBD6LBUWO5UMBBNXJ5XCAMGQEJ6GVWBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 93FF3B22E8B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 19:07:03 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e566614a5bsf927855ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 10:07:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755018422; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZCJ4a2Mhasz84nCiNkj64ss/iBcG+JdCiR2389QYvJj8PlaO2+bvgGMaj1S9tm5eEx
         pGoXd4qhrnHOGpY/rrVbhbJNahIE9PKOXXSD//dDzZajJTMU5ju4ZxczphPo9RsYeLOJ
         xfmhZYO1MZsBOXoy0AGPNl5KhHZirqnxQjOru4DT0Htr4QZP95jnQbuaFQuT0OWJ9B32
         twnlU1363RcwqRu1gvZIWHb0YWFFInOw32Zsl2I6e0JkmV1ohPgyZzKDwri45RlpXZGK
         SDB/gujVpX9l6OGV6/bV+UetcNX7mn3ZhPE8SB8zLK7bz3iKuf+qF4rnCbox+mNBElWW
         J5KQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=t9+FfoGKzTUTXeCPoIoWo8wD5XJ8FUBrJMK9rpzRXG8=;
        fh=pv2CdkNSG9BkrNGaQiOarsjnyjRJiR+Kt5bhLY5VF28=;
        b=TZIcZHJ+rcDP7oV1JBR3vc9moPx+0faKVuPULYBY6JJFIfSxkB241ix0uEFN8N1h0m
         NKCKv0YSIt4IeoiO1PWUV5NAqtenaam8lLan6jq3o4g6F+RuCa6qX33zvECBVzYZDne/
         wxeK50y88rmLdqiszclzZLZf5KyeC9iivd4S5iZsIvKCIH9hjp1TWEKkKh79SxC3Zl/F
         Iv6nQBNMW+6cDEeKQgOhPFI8ZeUzB9sJ1oq4TjL+T1mrgD/ApVs1wDU2YXO4DAeLsIIx
         aUG6j/G9exuEsTm03LQwRYmGPUepp988aLzqfhQKh67dCMmxJMc/hG18IpMpUVoEwvtd
         Ub4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgbmVKNP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Hhptruq/";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755018422; x=1755623222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=t9+FfoGKzTUTXeCPoIoWo8wD5XJ8FUBrJMK9rpzRXG8=;
        b=vMb5z3o0mibeZgXG/+TQkEjOTdLuMhl6ZoAz8d6hg3taEssAA4HUFlZ+9GT7wIKuGA
         Q2X4/KOGP6CsjaGblc5myDhc0QcoPmtTSm5qEnC6SRiUprSbIBkYN2KYfjF/z1Q/gAGa
         oe4aw4DmF+Nh3Rs5TRTzPMN3MqjW4dEp+u7k3/VEe4g31VCuO9a5Tj6hvNGJt92jkQqp
         5N8HCn7z2b4d4QW2Mb4b7FG5jh1HVhCEqF3tolWMxtkmNl1F7M0aKSrDTuv0iykP1uL9
         XYQmJV6p5tNR+ZcVH16JET59FOj2GYVZ0HhSqXJFOZcEEU2V1ro21XrGX4WzWulPsoyh
         OPpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755018422; x=1755623222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t9+FfoGKzTUTXeCPoIoWo8wD5XJ8FUBrJMK9rpzRXG8=;
        b=K9AYEgkVoeh6xC6mu98Df2mmDU+rnlweNeS5aboDM+UxI42Lzz7n4PltMHafJzu8MJ
         3pvF2YC9DVs1XjDbS8Flp03c6OYSdkwHNy8DEKVLICQT9GVdppir9UCJzRb4lZ1GvXPn
         qcHZQp8qL1kHFe2OAoBMOjhhCUzeElB7dSV8tTtvO8WhIalMXBEnBxruPbDWdK4OsY16
         N0PL6iMxX5FVNgdarszPeuoeLK5RlRW1Wt7KiZrGcdX76FfRhcPiEQCwBGwIJp1CaHzH
         06MMbPBY9Bulk5PhB93uHn4iITlDWLQsBV0AdDFLIIShec/uMyzVkzp/gq74F1fqfegh
         ZYTg==
X-Forwarded-Encrypted: i=3; AJvYcCX6uCbXO1Eg0zQ+mFhcNg773zqgosHV1wWJbJHLTY30gMTnhJkcjn+6e0NIRw+NQ1E6hSp3dQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZHTjKU6PGwEPOM2nIRBtgQ59vXbBHqXM5mdsAqWBmu20lv3mg
	hBz98vqRtk3kPuMhJ1dNpJ9izdTvaB2rLRSA3ri6CX4aKgtnbxExPET7
X-Google-Smtp-Source: AGHT+IHusJtvCxcHxJlZDK+RlJi3q6UxBWYeLK50H7nGgvnbY2QUTHfA1SEgSd8YVUw5sUZj9TZbAw==
X-Received: by 2002:a05:6e02:228d:b0:3e5:4631:5477 with SMTP id e9e14a558f8ab-3e56585f81cmr8870565ab.11.1755018422167;
        Tue, 12 Aug 2025 10:07:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfnTkuBGXGe9bbkSqyNXWgNTJIh4jJmLRKvbIOKuUYpKg==
Received: by 2002:a05:6e02:e11:b0:3e3:cec6:58f0 with SMTP id
 e9e14a558f8ab-3e542bb35d9ls20222105ab.1.-pod-prod-03-us; Tue, 12 Aug 2025
 10:07:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVBYIdFwLyNwzs7BuYPCVHSN5Py/KQXiMnyLrJam842DnxPjZWrcPn62sOLUmTFgptzhbwTnY7zUFU=@googlegroups.com
X-Received: by 2002:a05:6e02:1449:b0:3e3:d44d:4d12 with SMTP id e9e14a558f8ab-3e565631d60mr10242085ab.0.1755018420390;
        Tue, 12 Aug 2025 10:07:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755018420; cv=pass;
        d=google.com; s=arc-20240605;
        b=YQ5gm9IiF1XYI7mwdyC7bGNk3JKIKNTy+l7eAvZjOaAov9W5cD+Q8tZrYtlWbpMezS
         f6SxQ7iwA1Q8N+c5ioKvPySb/7HVJkWZSDbkGfzunhhAnmOAgAno2DaQi5M78YLg1qJF
         Ql4n7XIaVl+Lqrf5vkJoQby9CUM3FBnXMOLHXtqH4Lmv0e9f+qk7FtoPt1cggz4T8pW6
         Wvp1UVISzBnDAEBMJkuNH7cVm+i3o5p7guXv1LR9rWi87qHdLEyKgJIkx7hiJiieIBSS
         NYePACV6amkI7xga91ZVO+GkCoiVzPAXRVmm4OODFFqFHU2DETli/p+sD3FIjf/BOJbv
         Fppw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=ULm+Z5W2dJUBW0QlOg/cxfxUjmH31m+ETbSrRjeFt68=;
        fh=4Ecr1l/hmhigpMtapn23TN0EzSydaoz0q4WGwZaekvU=;
        b=UxN3kYOyF2J4bMbDj489T1Y9L+xr8FuSmzR8Y6tX1QjJHyAQMSCPTnQgbOsVEJU68A
         mgtxq+m4mF4i9N05DbmPsQcfbiqPLIFoDwOsjSXx9Xka0i1mLJ7/88TDCBt3fRPKFVSE
         kCpBWuTKbjcAprzG1nWVbu68DCalLHGl3QVMJQmQSNi/JaXHNSBX/xmwEpwUDBwenDwC
         6/y/I6bZX0sd9ZIseZEHCnatft6xk1Y3b03Z9n/8UKVp9hNMGez5NE8J0pLy6Wg+vBAE
         RMHr8LWzLenxi90jHDm0um/RANjaRcsfPcHuhjuvAqYtpa3rNKewAOiMv5Qpzh2iSymu
         cTsQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgbmVKNP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Hhptruq/";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e55d95478bsi973415ab.5.2025.08.12.10.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Aug 2025 10:07:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57CDC8ln010988;
	Tue, 12 Aug 2025 17:06:54 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw8ed6cc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 17:06:54 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57CFe2wA030104;
	Tue, 12 Aug 2025 17:06:53 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam04on2070.outbound.protection.outlook.com [40.107.100.70])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvsa8dh9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 17:06:53 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=FSC9/bZ/8n+rC+8NUua7saEsD/SRxfpt+lhTFTB/DlCOCiWzougsEh2GdkBIRP6Qb5KqxrA5E7pQtRUEaJMuy8xyvEyeXozMnmc0TmbsK3vloO3BO8684KjteccuoTlcHKyfmqsYfM9Q+ftxhbT6u7i2D0+5GZqZFmNUKZCeByEAzeqfM5Z42WbR1jXgn4alNVotXAJ/lwz00hjk8q81DlM1UmrZGC2glh3ve0F39VF0U0A5u8E9WSYGz4Acc3PGx5Rs2nmksEaZ2R/0qQ0mUj+29E9mcN7ex4DZvD4MKW4EUzKH5m5zClN9BdwN7pQ3Ggczq9+F4xRGJIEuWIDMgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ULm+Z5W2dJUBW0QlOg/cxfxUjmH31m+ETbSrRjeFt68=;
 b=BJzwSJ+3UbugcN84LyJjT6pr136VOM/p4JppELn72g6aCAqp8lt3QtZjyDvM+Wzp0ensa+A6f1bqEFdMmm9WGR5zicBuicFCGkGKFnt21brWrWfYT6Vsa558uWpeRdDOINviM8TdpA5zZ8SGX16NuuGP00U4ca0XgFZNDAT9wQKcFT72dhOl3oriZcEziypX/Q7YL4fqQpbPFkIQwLctwBkV+7FyW77Tb/sC7kyvx00RxbKFTLYNRI93qAtz72Qgm1l4JG4BmOCV0TuaVwu8fcE2gLmqlVL1nWekcz02rJNJlEwNhxI9yhsDd/A6RzaiddDQw/l20fIFzH0jw6JWIA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by BN0PR10MB4886.namprd10.prod.outlook.com (2603:10b6:408:114::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Tue, 12 Aug
 2025 17:06:50 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9031.012; Tue, 12 Aug 2025
 17:06:50 +0000
Date: Tue, 12 Aug 2025 18:06:44 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Baoquan He <bhe@redhat.com>
Cc: SeongJae Park <sj@kernel.org>, linux-mm@kvack.org, ryabinin.a.a@gmail.com,
        glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, akpm@linux-foundation.org,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <6a77525e-8ed9-40cb-9c56-053e38296906@lucifer.local>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
 <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
 <aJX20/iccc/LL42B@MiWiFi-R3L-srv>
 <b5d313ef-de35-44d3-bcbc-853d94368c87@lucifer.local>
 <aJtBJgC82CpUkwTi@MiWiFi-R3L-srv>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJtBJgC82CpUkwTi@MiWiFi-R3L-srv>
X-ClientProxiedBy: GVZP280CA0017.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:272::8) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|BN0PR10MB4886:EE_
X-MS-Office365-Filtering-Correlation-Id: 3ea8a0d0-ca3e-4955-20ca-08ddd9c2a0fd
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?naYfaydcSbbvky61E+9f4+Bav733nCB9W0PoXR3ybUmKNb+X501SeZrHeweG?=
 =?us-ascii?Q?MtIds+KtNgIPyLCODdSitTRmKA50MZ5O7A+NtLsDBvEoOceo7kvPnk4AtnsN?=
 =?us-ascii?Q?ueUxuKtD1NL83HbHOqpEzEX7Vfrzl3NCb9sAMXHRA6VlcV7mP3M5b3z4P3Us?=
 =?us-ascii?Q?cPA3sEL0ig4dLriEpr8uWC1ywFSD53b7XZg/3sF8cazEXyAClYtnZAVvvjnf?=
 =?us-ascii?Q?laRw4tROalpkevlEXyrv7omm40L9aHxCFUo+WA6qDPIYWnpauzHMky15djto?=
 =?us-ascii?Q?VZh8+IApMFtthyuvwkXraqynmYQ4w2iTgFWI3MM9haPOpzS0WbzII7cXgttU?=
 =?us-ascii?Q?LgvacYwnY7eSI7zVRX7HQ4LTJYjJEvdfE/V64Dr/G8uylXpP4/JED8AI0Adh?=
 =?us-ascii?Q?ZdUaFQBMl7Vy9usQ2P2EiypZEHvwnMDRwXjPI7J0UkMMM37RAeK300rhIOMo?=
 =?us-ascii?Q?Uf4xXYLw0v2eXZ4YYxTzMEMO6Vrou1pUAD+J/D/na5n+APlfAYJ6phTRBegL?=
 =?us-ascii?Q?DD5Pt6uqUCDXZb6JYJjdNbbKgn8AHAVnhDvDDhj0xTr19Z7hSPckKVaafhJg?=
 =?us-ascii?Q?1F2p6roOlUfvjsVCKjiEeotnIt07qyOzEXbVU6YtTEQS+dywIPQbinsv8mWZ?=
 =?us-ascii?Q?hDEoZ09kEQav9CKyfaMJuIqZv4SkSfJ3nxDLUFbEb8COZBCfS5/so5rF/QXI?=
 =?us-ascii?Q?p67ceypr2rb+r50V+5JuJ04Yl2lhCpqmUH6ihO4zQ1Pu662ww2NdI7nDYwXI?=
 =?us-ascii?Q?APa2OgviDmFMJSIItrL/3okDnxz1HbXbvgOvse8XwTst6PW8+sBhRStCs77V?=
 =?us-ascii?Q?OnwJX18UV0ons5r+46x8EB3Dk6AHr1a5p+v2zLA5nMhBHHUkbwQL29Sb1C9m?=
 =?us-ascii?Q?F4opwD8DAeSu7RzW7ynZzVvPMkU72K6Y/PpXgS/Z4KXzONUe6CZERyqkeohV?=
 =?us-ascii?Q?6O1EvVIqWt1fxW1xdO04YkyVWMPdL/zrL8cX2Wgwc6LuBx6UZ800yS3/phis?=
 =?us-ascii?Q?5tvKK5HUYcCf825VLT7LuTbwixV2zsEaGiex9oi/Ow5vR867mVMzTEHJd9xP?=
 =?us-ascii?Q?CeM9sv1PoFg7sJ1T0krG7/7QuhRnTrq1hk0QbR8R9oqJlR14z1Yhn7N/z8l3?=
 =?us-ascii?Q?1ebbumNL314Qv5WSL708LRjIRTgZi1Nd4b/Va5Kj/GlzVv6cHC8wiTVL0t9Y?=
 =?us-ascii?Q?f3k9MWT0HKyK5XB106zgyikemOXu6mGl0OdmuF7smWVNGcXegszn3SaNL5sj?=
 =?us-ascii?Q?zVBjIZNYdsPcIrR1SFOH9HI41YmOuq1S0ho5YeA95HuP5AuFi8CA08mLGP0B?=
 =?us-ascii?Q?vEaLfMsxJiBvG7mhPpWECHFkHD4f5JzeMN+lEOoHiS2DiIwqVM/dhBBbRPbR?=
 =?us-ascii?Q?P31PR0+YsGtZAmS04uvHL3Ub3P6RByjQ5LHZtlnL1W9X2vEvhwmzK3slOLaS?=
 =?us-ascii?Q?fV3x3JlprQQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?V0n8CwnZI5gIJlOhel8DBTqPQWmYilknGP8m42jBugqYe1r3W9HK75yFHOgo?=
 =?us-ascii?Q?Gtf9S93mkUwu9kiP6DtEKLiYqp0XMpCMeIhHIUDscJkbrjufGbSXayGm1UTc?=
 =?us-ascii?Q?qqOh//+kSLemAXOpB48UuARz0gblEQ/dFAHgT/7/PG5DpuQMkAKnA2JSa/ZN?=
 =?us-ascii?Q?bNODXwWbGBdM+wpMfAs1/RtkZWIpa9RezTsPtWqcUn88TpJjhgfXcHkdwVly?=
 =?us-ascii?Q?LFiqnv3HV4arpGzZMU52e69iFX9tL439d2xlW6YL7QwMEOmvgC82MjAHRqxE?=
 =?us-ascii?Q?FzgLckR3eWKvgAYwMXFSt6UbPOqZeKYkFE0tWsWaCDsMGZ/B2w+hWS9Z4Zyx?=
 =?us-ascii?Q?XrRqRWYWpR1ukbaVC87gocJqkweVpL5C9xLsk+I9AHk5Kzu0N4/bLam0eEeF?=
 =?us-ascii?Q?NP1aSC7LQI8Lx7Xh1XfOmUj+x7gRZURr20seetDaf0Io++jRApM8STdZLj8V?=
 =?us-ascii?Q?Od12o/eSMffjz6SPP2eQ9CRJsASrVfBw7P2fDZ51zUjZVEdre92IYF6+qJ0r?=
 =?us-ascii?Q?9ExHyBnBFX0CPRyQNNCAZvoDhcKIpwWb+EFrN7SG/QPIvowBmh0kpNSwPBM6?=
 =?us-ascii?Q?2/AHdnP+OfKRRtVK3Zp4ZwIUmtdfZFmOJNWfXC1JveAAggPbVkz9tcwe5yWy?=
 =?us-ascii?Q?y5HdrW3qZya6ivt8y1YrtSJyGrxq0+iJa5HOn+Lo/1XwF/Ryu0fwQsMZu1FP?=
 =?us-ascii?Q?cm3MF0OWaGmA3YBpDY4Nk1YBEpX8Av8mXEWG6ZUBBIbtS4WMjNlIJSo/tD4t?=
 =?us-ascii?Q?RhwV6f0cYv0ColXs0zo+nNcBk7f+mRlMs7lTQEmvSJ1cShiylKYMY2XWV7M0?=
 =?us-ascii?Q?roBF+S6pEUPvxR4EH/xOaPWpMSt7u/warwBaAa7xCDLmgkdTVml9KksdGrKe?=
 =?us-ascii?Q?X8q1kU0ACT069NmVEBibfXAOepMH/9OvyH8+kjunXPIEHxdxUKN0QAz00NC7?=
 =?us-ascii?Q?5GqmPnfzFUJP/YqeD4soZ2rHa/OuVO+y0ZOlMYIt/N37gIHRfOcULSDMg1EH?=
 =?us-ascii?Q?VcEZ4sjvNVm6W6FJ6+AbG/WG4og1c3pVL6g/tHaDrv3GkAtBJnj5p1nHZwb0?=
 =?us-ascii?Q?6rppochx9shbVZn6mvcJ6CHuokMgOnVLslv1qmraGtgyW4c0wrLXPmv7I6LP?=
 =?us-ascii?Q?1i3AtPg/yOwKivLI2VcBckuLXxxyheyYkY/X3gGO6f2lAIQCyCoYr20X12Ev?=
 =?us-ascii?Q?DvBwFsRWTx9nGBi5fNIILr/dGVXhd2BeTkJzBKPjJXKR3SifFqRhkDoiikEj?=
 =?us-ascii?Q?Gv6AvXWudytB30bnBENn7ElGBWnN1RZtMMZpGPGCu+pxl4jP8wVaprkrFKhS?=
 =?us-ascii?Q?j8oMPeOYHJKWm1c7RaDkAnMlBAa4TNxat92C0omYI8pve3oxOxIyXWCTHWj7?=
 =?us-ascii?Q?cRMi4tS1SPH5nHddjJp05o3JJa3/sIaX+TIUGWDkFapaujO6saS3Dgev55Nk?=
 =?us-ascii?Q?kDVvC1AhqjQYlhX70jdTA6+I9W6lQCj27lmD4c60G856fWuz+6Hy9wsZjRfP?=
 =?us-ascii?Q?X/+lus0HVHuCQmFS13HyjWeNYnC0wx9V7ipuOxUMyscx86YAERLRinhYS2ru?=
 =?us-ascii?Q?IDUk/odShpX5Se+6iltD4b8FJbphU3N6f7jiNIjRKhKjEWAojiCw0wlzoPmB?=
 =?us-ascii?Q?eg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: z1Ole54E3ePISKRkerAYMS4ufpbx04TquWj/4tt/LX5gkSeu3jExpUQbjRci7AqMQEIl3R7yXRk6IoS/lRW7vAOlF5vuvJAdBrwpfY+bZ9DtdNnNhFXjjDQiXdM8lPam9DPPz2HipB6ZQIfq50KlyiSXEeq1cIfhTOMYBmFysrh0bQ52KNk30/1MjGRRKHLDf82seVw7kHaYe4haAsfYu2bWotT/A/NRHGN+N3+eMzyrw9P3qILDVpEsEyScGkoMjnLc1PybMD5MEFjIiBY1nmMQAEZRrxRa7UbfgP43Wc04Ka6MhNblaiCfVt4T3+vxEA80WR/YcK4z6ZsQrzR3f8+zSjSl3ZyX+y3ATMyK4cCCX8aa3nJi5teS+KfVd5Wksr/USlsqu1znQ9ETmlgvYfkKjoPF/9RZPLqZSln5aZKZMWMpFVt9OIUPiDI8gZVdo988PXzuRGpLd+G5yCpLxqrkjRqey5pJQGIHFLPlLdv1JK7UGf8jvbDo1yH4bI0h1pxf65yE407sTr4NkOCn7CZrMYIvwZ367vOKCrcn6N2ITqJdaXIA3/y4WEQJ9kdPCN4zvdyhlOIgery+6hyUtDK1a+C9G74t/UxE1RpVPpA=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3ea8a0d0-ca3e-4955-20ca-08ddd9c2a0fd
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Aug 2025 17:06:50.5153
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: TczTZ/aOgdw2R81LH2g7n/b3SkQzdf/HslnUl1fZcpTNj90Zgqz3jtYuACNH51eaydOLq09P1wXnssCDEQG7oiD20hwXboTXvkK54MqWxtM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN0PR10MB4886
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-12_07,2025-08-11_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0
 malwarescore=0 spamscore=0 bulkscore=0 mlxlogscore=861 mlxscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508120163
X-Proofpoint-GUID: -7U993NcxNUSGsnW3eIO1NRx6iHNCRpO
X-Proofpoint-ORIG-GUID: -7U993NcxNUSGsnW3eIO1NRx6iHNCRpO
X-Authority-Analysis: v=2.4 cv=ePQTjGp1 c=1 sm=1 tr=0 ts=689b74ae cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=Uv9ryoJrkueFjJXwpicA:9
 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODEyMDE2NCBTYWx0ZWRfX4u8rDzfnELGP
 BJfFE7ciWHPhtohC0TjN1kTUjK1OvuxIVm5fZwkesJNwFw2cLlD1PPSGEYN3XZGAmDCU/bidQz6
 R5xLZj9t+8Jiv8O1J6WZBtPZFLR7FcDKQgz5NZUtcn9ZU/KXhmXLUYynoxwrPhu1zxr3CsmaAA+
 Qxl3lZ5Uj3hNXuSduI3fMxmgPIVnOLQ/KN9kRTYMvcn3m7ZXgxEDoaptArCf++/8igOPSxbr0Kj
 0VdesQSRnjMfMlAT6A+3Jv8V0hgSRKTYev37YswSFR8mxwmalQF7g06tPqTRmzNsXPkGVGS71RT
 7+LTMAOg9Lr8hNUYdkBIB1SD+UtYEixMqUz96Cx5R7X7dS7uyGFMjqtVnP+KAIg+e1nrPp+J/pW
 IT0uIRbt3e76wEPTDGkbOaIhGVL00Es9ANZ7moOjwYKjO9c7v74xy4c39TBPkcDxmeuJ3bmM
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgbmVKNP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="Hhptruq/";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Tue, Aug 12, 2025 at 09:27:02PM +0800, Baoquan He wrote:
> > Firstly I _LOVE_ the term 'ifdeffery scope'. Fantastic :)
>
> Learned from upstream people with expertise on both english and kernel, :-)

:)

> After investigation, I keep the CONFIG_KASAN_HW_TAGS ifdeffery scope out
> of CONFIG_KASAN scope. Otherwise, I need define the dummy
> kasan_hw_tags_enabled() function twice. I am personally not fan of the
> style. While if that is preferred in kernel, I can change it.
>
> #ifdef CONFIG_KASAN
>
> #ifdef CONFIG_KASAN_HW_TAGS
> ......
> #ifdef CONFIG_KASAN_HW_TAGS
> static inline bool kasan_hw_tags_enabled(void)
> {
>         return kasan_enabled();
> }
> #else /* CONFIG_KASAN_HW_TAGS */
> static inline bool kasan_hw_tags_enabled(void)
> {
>         return false;
> }
> #endif /* CONFIG_KASAN_HW_TAGS */
> .....
> #else /* CONFIG_KASAN */
> static inline bool kasan_hw_tags_enabled(void)
> {
>         return false;
> }
> #endif
>

This is fine, as CONFIG_KASAN_HW_TAGS implies CONFIG_KASAN anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6a77525e-8ed9-40cb-9c56-053e38296906%40lucifer.local.
