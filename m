Return-Path: <kasan-dev+bncBD6LBUWO5UMBBVPCUK4QMGQE326OJVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F9899BB37D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 12:34:48 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2e59d872d09sf5336129a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 03:34:48 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1730720086; cv=pass;
        d=google.com; s=arc-20240605;
        b=LkJ4D0meDCj2pKQSy1S8e/4YAcqFSUxPlgGEWJSuC0KWDNxWRGszoCogz2m4k4oaCE
         HMaytD7ehbuP9JTcNDI10PRovxPHAl/cNvG7u/cNkKtxx2AdK3qboJg9Q7rZbFvC9mmp
         t7qOF5P/C1Yo5mESH2zJTrtu4g3PyIEsGyLRqMHpjR0PhcHScMY36DZ7ogpKl6A+FCRu
         zp15MlzesjTS3JHy6OrOSP3vo75x5zdtvtUd9AFRhK9GYwgAntbyI5hwMc7+B9c0YLk+
         6f0UemM8mHR2v1Gmr9oJOMq0jEWFf2K/m65XN4qmDqz/6dpkpWOTM5PrYF6R2JcKaZ1V
         Ru6A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Vu0Z+jWY+WPHzozAgWZ5axpiOWPLmwOJJM8nVpUA08s=;
        fh=JnGgyzkLi6ONVoplU3z5i2QusFZnDDxGV0uF5JX7C1c=;
        b=K6Jn4L9t/SvjKJXhy0JXPuk8VfHMIFw9y+KHWsCWHalcZdocalddxyoiQszOnRduVg
         9o3oel+p3tYIJzJSS2UA5cB+w2Bim3DCmQGsjPGtIj2xPA3XBZcsAL59Gbu39A3fAjgg
         ecpYX1KghPq4WewLFZqnhGhgNjydfiGL4L+dHxNgChBjw5nLSnNVGEEwEDZqVafAXmUF
         kgef6p5fJM+QOBc49Zlx7TxIuFJ9nOoO1AnuX9xYgJWPeI6XPwvBoJjKAcP8UdY0SJTQ
         k4WFfR5YBEAJ+Hi+m1/MBVWs0+D2rlRPxVCdn4crfJJkKb/AJT3BM6QxQG+7IM/huyHG
         C29w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b=W7ByAZfL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pj9mbk4L;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730720086; x=1731324886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Vu0Z+jWY+WPHzozAgWZ5axpiOWPLmwOJJM8nVpUA08s=;
        b=hZNHHZxydZmimMgzYhJeELf291GLtVsYq4JEgAS62F1xscwwVWDXB3YwQXPJTuGY4O
         rDEhbe8cJCDTLyP/Stdov+Gskjja/I0EtpKgbxW1G3lMs/dUE3FlGZjxuaHjIVgyOUxL
         VnY6lEJoW0/DTmazHAWmBzsujJdVbqIgXRYKVDp1L255Hxbj78EgfFJ1GXTWw3GpAdfl
         2pBDaojV/7iLU1WC46XffvEZfKCcW+M0lA7g4abMi6A8VljCtUubm2QeNqv3Vf46/kF5
         mTOUdX8U/1fo6xy5k8EcmKHkVLXEy5xxx5m4d9hZBsktOQ5/9pCqpcRwztBb56OvHQAY
         MYdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730720086; x=1731324886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Vu0Z+jWY+WPHzozAgWZ5axpiOWPLmwOJJM8nVpUA08s=;
        b=gVCSKmRTOuodPWdQB7hL2Olq8ErH3SQqu1U5lVAx/Dg4EW95Dx46Trpnmq78XAq9Uv
         lFoYPo9DfTQgYYhVclvoPsUOrq7B8RByzh7rty/gOJJptwe4Ld8qkKNcFN5LzEUjLpWG
         Y3/S3zcLJZ8xx0E7CfvpXwammDfcntB2oPBXSlcPzIafST7TBIACMFKcIUDgLjE8muRb
         Ke7RmIRZAHCjG2UMV7DRuckpD3fvQD2vh7AbQ8hPb7LyeKoz9d6VKUh3Pq0KRDWkBdnB
         EymCGQZyRg+ZMUFKYdMZ3ZAO3pgDjmY5lWhAQoiee1tvj7zCehqiblZOJljFHK/aQyAS
         bW/g==
X-Forwarded-Encrypted: i=3; AJvYcCX16nw5x7AuXR7bya+mmwNf/FWlxsdP6Dh/g44+i2/Yffn3g0dd+7fiwTvMWm7VlIo3T9arPQ==@lfdr.de
X-Gm-Message-State: AOJu0YxcYFXcEGBH2h0u1HyrBR2aA292tRBYtCqZHOVFsxhglNazJJMa
	LEcSPrk7zoipKFglHefWf3/Y5oKoo8BUcx+8epepNaTjjDeRMdpk
X-Google-Smtp-Source: AGHT+IE6QooeC529P4PwfBiQRU17UaHBLYyhGY3TxRaf3emquiV2JtwM0Cn72tcShaCY7jXHRv1/vQ==
X-Received: by 2002:a17:90b:3b85:b0:2e2:b69c:2a9 with SMTP id 98e67ed59e1d1-2e94c517a2bmr17379166a91.26.1730720085977;
        Mon, 04 Nov 2024 03:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c883:b0:2e2:bf86:a540 with SMTP id
 98e67ed59e1d1-2e93b11a9a5ls311463a91.1.-pod-prod-05-us; Mon, 04 Nov 2024
 03:34:45 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXefg2h2y7AiJnHYYCeeU6CLlPDcRyb8oh07IUF048vA0cQohRlDl2ldfkTcLsJ9VXkja6azuk6De8=@googlegroups.com
X-Received: by 2002:a05:6a21:3382:b0:1db:e0ad:8ff6 with SMTP id adf61e73a8af0-1dbe0ad944amr2459733637.1.1730720084704;
        Mon, 04 Nov 2024 03:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730720084; cv=pass;
        d=google.com; s=arc-20240605;
        b=XAGyKUIVlln6A5LIu9z+plAf9/CZYyUXZ2oT2aWvg6c0+J6ahOTzhoMSuH6RgTrz15
         p6oqAHWuIuGJRFBlJMPl6nM0rNxkygocjw3ct7XrM64NqZBVvyCioLeqmynjz3ov9q8x
         a1zHBwZBqnvmEWIXCZlQgFIy5vQrmnPEc0BI0LNitIb2kPJ37SHLBifsBXldGpvR/Pas
         hHOP1H8sMIC76k7HGxWsVVKUUE6CyMLLhu1vY7OujeuDOGCjMS4gNrDAu13kwexVAk7Q
         p46AWI9VoNoxZxwDP4KYsDq52xJWCE2/d6t9rX0MMz8JX3Gi25GZ8QH+wa7WCtBHq1EG
         l5oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=kpxMNrz8xhaC5YHst6x97QP3InKYD/iLY14MgBpA+eU=;
        fh=o4jKwNcuDDXTSDbYHrKSr5wM1NzaLGdm+VQfzEfA6jE=;
        b=l1Z7pLyY9wtcoOOwUzUVusZUP1gooFgsGDBcWVNyI4bKjkkpj5TUt7q5eOOYx9J0Re
         B9XCFILScPDI53gUA0ZfMK4bRBn/1YHn3piCkcWKlcPU/kG9/qRraSGRbDKe++A5u4iJ
         UWHpGBaMCIBOnwpAV/Tkqa3kGZUsK9uNlHzwYOS11bmLddwWOMV+VkqfzW1a+oFWJ+R/
         FhK1UDv93Z06bJ7GlNp5UIChhbG4O0ItqWTNG60w0VAmpV2wTFW8wO2pOxtefzqHMnV7
         aenZw9ZieWhHZAtSY9qEYYjLPkUjezo5kRJT7JiB/g+0mKXsNCNyvdp9TfjBueExe7oL
         t2HA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2023-11-20 header.b=W7ByAZfL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pj9mbk4L;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e92fc11aa8si408275a91.3.2024.11.04.03.34.44
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Nov 2024 03:34:44 -0800 (PST)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 4A48fca4018156;
	Mon, 4 Nov 2024 11:34:42 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 42nc4btfsx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 04 Nov 2024 11:34:41 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 4A4AR0Os008574;
	Mon, 4 Nov 2024 11:34:41 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11lp2175.outbound.protection.outlook.com [104.47.57.175])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 42nahbw67w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 04 Nov 2024 11:34:41 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=u9hWGpucy2l9BAGlYI/XA/nva8JckhLNHVskcr5PVZt4sV0HARzZH2FfgdT7buYP2hzfOy5yJf23KUap0YUb21kUwuaUe7GoYmbzgrDsRP0eDEwgLsLtJDwVzoccfVzn/7NU+7fKSyrDEPfaXzPinbpE494NMup4VACYk+wPqX1NCRnZP0kxwtKPLdIWfOBRR891Ilum9WaJdK3sifonAuq5Xpu/vEG0SQsOmH/XM+qdZAnW7PZmbpYke+nefd18pIu4SOLuaSmj4KavLM641dY/tkIV6d58ndKgqNFprD1wH9YKKPs1IlTeXNSZy5SRmP3z7zkZxmbC+Acgl0d4rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kpxMNrz8xhaC5YHst6x97QP3InKYD/iLY14MgBpA+eU=;
 b=easlqy180XPz40eryhnzJfnfPHbhCMzuOC3FIMAENvk8lMS6OF9M7CGVL0hvwfH4NbnTL0xSe0g6haNJMvwJFuw6RkCGylJWwEJp+hmyEcTDykj2q5iQKXeFJSNEEyDqAYHg6UAFZ6cRaJiAQ8GfJ4Ai+7oL+MwJ3KKBmcB76Jro9A4JWF2/JsiPDq0txu5W1zXBRHD5MAFmsNiJa3Z/mcs8l464jhqwB2+Cn8E4uoyqBxGCSFfEwZiWGUfWyCDLBvZ2xNuqVaSK4cnMRi8BFm+75Aa3dgPPOH8Gb7AGUQw4UsbcHfcf0bxPQAUksUl0cuthxLI0c4J2nNRhO6ZFNA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from BYAPR10MB3366.namprd10.prod.outlook.com (2603:10b6:a03:14f::25)
 by LV3PR10MB7748.namprd10.prod.outlook.com (2603:10b6:408:1b4::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8114.30; Mon, 4 Nov
 2024 11:34:38 +0000
Received: from BYAPR10MB3366.namprd10.prod.outlook.com
 ([fe80::baf2:dff1:d471:1c9]) by BYAPR10MB3366.namprd10.prod.outlook.com
 ([fe80::baf2:dff1:d471:1c9%6]) with mapi id 15.20.8114.028; Mon, 4 Nov 2024
 11:34:36 +0000
Date: Mon, 4 Nov 2024 11:34:32 +0000
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
        Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        syzkaller-bugs@googlegroups.com,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Marco Elver <elver@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Peter Zijlstra <peterz@infradead.org>,
        Waiman Long <longman@redhat.com>
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
Message-ID: <2acdcaeb-23b7-4088-8014-bc983cf5423b@lucifer.local>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
X-ClientProxiedBy: LO4P123CA0216.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a5::23) To BYAPR10MB3366.namprd10.prod.outlook.com
 (2603:10b6:a03:14f::25)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BYAPR10MB3366:EE_|LV3PR10MB7748:EE_
X-MS-Office365-Filtering-Correlation-Id: a4b81fae-1e4a-4913-29b2-08dcfcc4a928
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rv6IDpmPbT6zRNV0pjlhNaCjY91jPA/FanfbhYmudWa9QLpucOthfkljMRCl?=
 =?us-ascii?Q?tIdh5DYMOa7hvT+sv0yX61OX54dTCF2ZWZR8lZxHEN0VSGxAshQwr+B1QV9+?=
 =?us-ascii?Q?X2kHULkYJxScoJHbOX19iSu+Cbgp71tZYawYZxCAJLNpADO1n0GH3b6hHSb2?=
 =?us-ascii?Q?ZCtuNYQdEYQB6eE81SJCB9FzIPrqguXEv54r2TB7Xc/Yf3SIc52bmFZeVxxL?=
 =?us-ascii?Q?PiEqsQZ9UQlrodFmXKOlfV0QfE3IuwdV8Es/3F9HBeij+ldClsMWCMsYsFmV?=
 =?us-ascii?Q?Rlu7GUHO0Ch6OgMvoGemkGg0eSeHmDFRbFlTRfSp8wZXKD/0SiuDlwVDmpWn?=
 =?us-ascii?Q?7iuXpbnTVold0RGByRJtucLy79NN/m2JzVU5CcS/CcMt9Q2wkDj56GmRZIfb?=
 =?us-ascii?Q?mo/25tthjIEJLOJY+F6pvSA7lGDE133DbNh6aMaBqGZmA9jnvsG8UHhfWo/r?=
 =?us-ascii?Q?Q3EzxcrnjRQkN152TWjBpZREBHUDj8GgJII2LYxSlZDoWuytfPx9AGuczAAo?=
 =?us-ascii?Q?scpQ4hEecKPjHQSmIso++56+njjH4U+ZEazTCyah8b9Wsw/SQWhjR2r6zE7r?=
 =?us-ascii?Q?vK6GzLI7ygwlN2SCi/6NbSE7Fwr/wyPATsdD7rQrVRT8mL6QMUEyQkllAik0?=
 =?us-ascii?Q?gw6WXV//ZSlwELdJ4ck7Tj5xqN3Q4nLZZWD8+6Zs30Cm2w2JMI+EWtc9m7xr?=
 =?us-ascii?Q?vvF9E9HcOhlZVbkZxcNFNy1Q2t3DAz6EY/hTWebIZ+ilc5bs8qp5gE7Kbg/y?=
 =?us-ascii?Q?rnXFOzCnDw2xjSqTRN5qJwf9l9BtX5uEL2XSv6JzHReCDS+K4BhnR/0EFvlm?=
 =?us-ascii?Q?jWs5Zt29GROupxmiscbN4WZrYhLdB2sVdubbke2PtuwxWY7Gxb2vrV80FCr8?=
 =?us-ascii?Q?/626Hf/MNbikOcB2TKaIyPkk1UplbBMqeY79VjvqOXWkNRLJkk1Pgp2NM2h1?=
 =?us-ascii?Q?FppGGkAM9m7CXZOr0XzJK26VOm9nftnrUIPPjE/NluTYmj71nY0vXCqfXCQl?=
 =?us-ascii?Q?IiB6IpLpB1Nz85xHaCt7AET4fj/MxmgikiJJzB5/Y4ukuY1g2EQpXXgJbNfG?=
 =?us-ascii?Q?T+LwnGUTXRTqxh/WLbldCuFzcihj6x1i/b3zBxEYBfOUTT1z/lfDbYGs58+7?=
 =?us-ascii?Q?oYA0I+vixpXElu9OPT24lBve4GS3ljYxg5e9crynQJ0PRZdYBg8lXDwm6oM5?=
 =?us-ascii?Q?FBJHlLxlHgXoySQQ26NUtyV0RUaYvQWwAc7LC4N28HzOU8Bx+lGrzYBcvAHx?=
 =?us-ascii?Q?AzmgV1pAYn9HWlo+5NxBgw8mwP7fpOI4q/co3ll3mw=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BYAPR10MB3366.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?J7INbKmCSD3abPo+q7hBA5lGW09C7NPkXQRARBwoxmsoOVzg/RosvXtyRL6s?=
 =?us-ascii?Q?+g5MsEkeqsF1O6fNMTbkIWAHWMdY0Ec/sQvM4NkSLMZa6pDg7A9/rs0dD8hH?=
 =?us-ascii?Q?bHXRtOfijt3zWLiogqPNYHzrie7Lehg+YDvu/PcUrL/lFXu4liOBm+zpyYRf?=
 =?us-ascii?Q?+yfRN+jMdhOduT6NKNnVcezt3WowCIYwVcsLmiyzFuIS1VqHx3P8vieQtoXj?=
 =?us-ascii?Q?LzOEFegKHF52LFdOfbxTt8zrbzKSj72yUoCAYuzxp/RYU75Ua2bWh+X9qt11?=
 =?us-ascii?Q?+2R1npF9C+dm6b6dV8M1fJYel6hfH5DTlBVF5hBeQOLS7l3aAFdeX3mkaqQH?=
 =?us-ascii?Q?yA632UgxGfVyQBel0GOFhOfsdNtRfZk7FfVRA47mhNwyIjnuwriMZCQs4OHV?=
 =?us-ascii?Q?PZP9u7NaqIcfXYNFMGBdvfoX5CTJUlMm1fcky0HfC+CZcUE6NI/kTvBn0rmu?=
 =?us-ascii?Q?7yQ8Hg8SiH+F9ZWxmO9zthhZtGBzgbkuSIPU1nGDT2fO/pjwNvoE76TNhrsz?=
 =?us-ascii?Q?KrR117cnjjJEAa1pWHa5klnbgdlRs3TzxgmczqG2up5YcEueNGDhKpoygPdf?=
 =?us-ascii?Q?dvt8JT4NhTmvMk780WUHkJyEH4gl2Il+ioPW9DMPzHJhvdYv1E49Ch7HAQIP?=
 =?us-ascii?Q?+7gsQjAz8PHOAai14+KNzJi4sz1Ch9NnEtIObaw1+qDov0TewK0PA8J9w2dA?=
 =?us-ascii?Q?mjXQIIrNu24GC+h/xZLPLyPQRGWg7Mrn9SxAVarv/ckL9WvTUtq+ampDIE6I?=
 =?us-ascii?Q?j3JevW5cimmXFjTiQwLj1rntxY4krU5MjpPbDc+dEziBEvim1eqaRF9Ny7fM?=
 =?us-ascii?Q?NVs0eX9F4SHS108CqjH1Rem2NwohMEhW6Cz3LJr8sq8RZpuirRquLtm61Tos?=
 =?us-ascii?Q?Y5de8YNLwK8QiJaGcfHfs700OcdQRW3r7Gx7hQFPNQ1JQrd0cwFWOzHRbQ5J?=
 =?us-ascii?Q?tS6ytcid/YL5HhojDiPPaSeR6daBOu3w+2FrhtUaSzlPo6lKyAnluZBXfj62?=
 =?us-ascii?Q?Dauw2jueo1TfRJuW7SKZ3tH+IDvFnWJkCRWEfkz0/R0Y3gPI6P9A7cuxDanc?=
 =?us-ascii?Q?QdOzdtczkNtdCcwL6kPpf/+s5PEyr7XT5Fz2yVQ0erRn+AIwCCweisZQEd3v?=
 =?us-ascii?Q?n37LuisJ2EIjxcxpFqjz+sIkdwfSK4I15iuUCDqL27cijHjBEdimyKcsh4bX?=
 =?us-ascii?Q?sqe+xgy091OCStD0QdLSBLHQ8vyAxF+M/c40/Wlq/ioYtgghk7FRNTdxSMpX?=
 =?us-ascii?Q?7olu9khsFdlUDcIdagm6ygCk9wAY5VYabYAGGjD6Sy7CTw52mG6/4HwpyH9C?=
 =?us-ascii?Q?+M+9ZmeQQk8AQMdpRc8DyFZZkj5LCGoYvsByYzD4hcz411gWc3npKSZMjIq1?=
 =?us-ascii?Q?gan8z7koIQ6xNTy1kx/pKILmlTSrilG2oDSVVdf6YGZTuhdlFisBVMriRBGR?=
 =?us-ascii?Q?I0dOsdEb4jV3mSzRVSsnWWKVj5L8dQMGn93NhxJd6JFex+cAjyKBEkiwoYS4?=
 =?us-ascii?Q?QutdYySPe88KTVNb9PIjYLOmLAyfyw57Xf3XDaaLuLJABfQWNUDJAFLVDh/j?=
 =?us-ascii?Q?Pi395OBOmSYKNFNOsefJ2t7ysKz6hj7xiKu8Y7eYpjB4n66kROGI2c40CkcK?=
 =?us-ascii?Q?9A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: o5/NIFV2p71cPk188W6hh+JmLgO2Q1GnCcayBZQuGEGfyidDSBK8m90LVomlkIfgPX0KbvhCdIXMKGRuOlWpyYEUI+iE5JU/SeIW+rifiuHLR+oJRpNoh/mHrYVxQQXNmR3xQGEQweRIpTr450jJKXwjU2HxutoW805ZNL9aaPvu3lb8WikdPJ8z8lA3Gf1mBijs9EXNFi1RBwc9NReKC2ZefFcOdD+MYAhbSnQkQxtZmYSepytR8d4Pg0k3oC/4khSwo/VksegD2k8vuP3Kaktjby46CNZKn/ESWQkraFfJz6kkD1GcETwpddGNSRLKEFMCer/RP1Uvr5RvMyC9ZZXHxW0JMmPs4F7CtFhQ3nrNz7aIoNQCKJ9NeD3W8M4JZ5/X/7kSUsR8xqh2JY+ZYlm2lDOliVT9oOMEKOCvC+PGXR+zpXwNbxgWglDBLxCKlKcBjWJcKr1RfNZrA9zvq1b8Cvsxprx6vXh/aQ67uev7aWhIgG1SUNYeSFaBtUQoiw8F0UYjCLtfpCrG8Dgm37m7ldAmh8vZsQGmLlRsH2J9eqdJCIDtBIYzFZpx5zojfyOdJi7qmrC71pL2+D3bwuh4QDXNH/6r7hzbCU+5I+0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a4b81fae-1e4a-4913-29b2-08dcfcc4a928
X-MS-Exchange-CrossTenant-AuthSource: BYAPR10MB3366.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Nov 2024 11:34:36.4267
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RtrL3XwcwLCB6nKHF5voeQPJOgIl8HJMQLxiCP8QWZjMNkImkt8l7Run+s1dmJQw7IN+VQ+IWzBY2RZbYfX4Ws8+pZO+PvPh4XRCwADnwDE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB7748
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1051,Hydra:6.0.680,FMLib:17.12.62.30
 definitions=2024-11-04_09,2024-11-04_01,2024-09-30_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 malwarescore=0
 spamscore=0 mlxlogscore=999 mlxscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2409260000 definitions=main-2411040102
X-Proofpoint-ORIG-GUID: OBsrKzevRhb0E5DrnCz5wztkUVgDaELv
X-Proofpoint-GUID: OBsrKzevRhb0E5DrnCz5wztkUVgDaELv
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2023-11-20 header.b=W7ByAZfL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=pj9mbk4L;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Nov 04, 2024 at 12:11:22PM +0100, Vlastimil Babka wrote:
> On 11/3/24 11:46, syzbot wrote:
> > Hello,
> >
> > syzbot found the following issue on:
> >
> > HEAD commit:    f9f24ca362a4 Add linux-next specific files for 20241031
> > git tree:       linux-next
> > console output: https://syzkaller.appspot.com/x/log.txt?x=1648155f980000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=328572ed4d152be9
> > dashboard link: https://syzkaller.appspot.com/bug?extid=39f85d612b7c20d8db48
> > compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
> > syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16806e87980000
> >
> > Downloadable assets:
> > disk image: https://storage.googleapis.com/syzbot-assets/eb84549dd6b3/disk-f9f24ca3.raw.xz
> > vmlinux: https://storage.googleapis.com/syzbot-assets/beb29bdfa297/vmlinux-f9f24ca3.xz
> > kernel image: https://storage.googleapis.com/syzbot-assets/8881fe3245ad/bzImage-f9f24ca3.xz
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
> >
> > =============================
> > [ BUG: Invalid wait context ]
> > 6.12.0-rc5-next-20241031-syzkaller #0 Not tainted
> > -----------------------------

(reading some lockdep source...)

> > syz.0.49/6178 is trying to lock:
> > ffff88813fffc298 (&zone->lock){-.-.}-{3:3}, at: rmqueue_bulk mm/page_alloc.c:2328 [inline]
> > ffff88813fffc298 (&zone->lock){-.-.}-{3:3}, at: __rmqueue_pcplist+0x4c6/0x2b70 mm/page_alloc.c:3022

Trying to acquire in LD_WAIT_CONFIG context...

> > other info that might help us debug this:
> > context-{2:2}

... but current task only allowed to have LD_WAIT_SPIN or below.

Which implies via task_wait_context() that we are in a hard IRQ handler and
also !curr->hardirq_threaded && !curr->irq_config.

So we're not allowed to acquire this spinlock here because presumably in RT
you can't do spin_lock_irqsave() in a hard IRQ?

That does seem to suggest maybe we shouldn't be allocating here at
all... and it is stackdepot doing it which probably shouldn't as you say
Vlastimil.

>
> Seems like another fallout of
> 560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")

Snap was just looking at that :)

Found [0] which seems to be a similar kind of situation where this change
is finding new bugs.

[0]:https://lore.kernel.org/all/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/

>
> > 4 locks held by syz.0.49/6178:
> >  #0: ffff888031745be0 (&mm->mmap_lock){++++}-{4:4}, at: mmap_read_lock include/linux/mmap_lock.h:189 [inline]
> >  #0: ffff888031745be0 (&mm->mmap_lock){++++}-{4:4}, at: exit_mmap+0x165/0xcb0 mm/mmap.c:1677
> >  #1: ffffffff8e939f20 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline]
> >  #1: ffffffff8e939f20 (rcu_read_lock){....}-{1:3}, at: rcu_read_lock include/linux/rcupdate.h:849 [inline]
> >  #1: ffffffff8e939f20 (rcu_read_lock){....}-{1:3}, at: __pte_offset_map+0x82/0x380 mm/pgtable-generic.c:287
> >  #2: ffff88803007c978 (ptlock_ptr(ptdesc)#2){+.+.}-{3:3}, at: spin_lock include/linux/spinlock.h:351 [inline]
> >  #2: ffff88803007c978 (ptlock_ptr(ptdesc)#2){+.+.}-{3:3}, at: __pte_offset_map_lock+0x1ba/0x300 mm/pgtable-generic.c:402
> >  #3: ffff8880b8744618 (&pcp->lock){+.+.}-{3:3}, at: spin_trylock include/linux/spinlock.h:361 [inline]
> >  #3: ffff8880b8744618 (&pcp->lock){+.+.}-{3:3}, at: rmqueue_pcplist mm/page_alloc.c:3051 [inline]
> >  #3: ffff8880b8744618 (&pcp->lock){+.+.}-{3:3}, at: rmqueue mm/page_alloc.c:3095 [inline]
> >  #3: ffff8880b8744618 (&pcp->lock){+.+.}-{3:3}, at: get_page_from_freelist+0x7e2/0x3870 mm/page_alloc.c:3492
> > stack backtrace:
> > CPU: 1 UID: 0 PID: 6178 Comm: syz.0.49 Not tainted 6.12.0-rc5-next-20241031-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
> > Call Trace:
> >  <IRQ>
> >  __dump_stack lib/dump_stack.c:94 [inline]
> >  dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120
> >  print_lock_invalid_wait_context kernel/locking/lockdep.c:4826 [inline]
> >  check_wait_context kernel/locking/lockdep.c:4898 [inline]
> >  __lock_acquire+0x15a8/0x2100 kernel/locking/lockdep.c:5176
> >  lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5849
> >  __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
> >  _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162
> >  rmqueue_bulk mm/page_alloc.c:2328 [inline]
> >  __rmqueue_pcplist+0x4c6/0x2b70 mm/page_alloc.c:3022
> >  rmqueue_pcplist mm/page_alloc.c:3064 [inline]
> >  rmqueue mm/page_alloc.c:3095 [inline]
> >  get_page_from_freelist+0x895/0x3870 mm/page_alloc.c:3492
> >  __alloc_pages_noprof+0x292/0x710 mm/page_alloc.c:4771
> >  alloc_pages_mpol_noprof+0x3e8/0x680 mm/mempolicy.c:2265
> >  stack_depot_save_flags+0x666/0x830 lib/stackdepot.c:627
> >  save_stack+0x109/0x1f0 mm/page_owner.c:157
> >  __set_page_owner+0x92/0x800 mm/page_owner.c:320
> >  set_page_owner include/linux/page_owner.h:32 [inline]
> >  post_alloc_hook+0x1f3/0x230 mm/page_alloc.c:1541
> >  prep_new_page mm/page_alloc.c:1549 [inline]
> >  get_page_from_freelist+0x3725/0x3870 mm/page_alloc.c:3495
> >  __alloc_pages_noprof+0x292/0x710 mm/page_alloc.c:4771
> >  alloc_pages_mpol_noprof+0x3e8/0x680 mm/mempolicy.c:2265
> >  stack_depot_save_flags+0x666/0x830 lib/stackdepot.c:627
> >  kasan_save_stack+0x4f/0x60 mm/kasan/common.c:48
> >  __kasan_record_aux_stack+0xac/0xc0 mm/kasan/generic.c:544
> >  task_work_add+0xd9/0x490 kernel/task_work.c:77
>
> It seems the decision if stack depot is allowed to allocate here depends on
> TWAF_NO_ALLOC added only recently. So does it mean it doesn't work as intended?

Yup kasan_record_aux_stack() sets STACK_DEPOT_FLAG_CAN_ALLOC specifically, and:

		if (flags & TWAF_NO_ALLOC)
			kasan_record_aux_stack_noalloc(work);
		else
			kasan_record_aux_stack(work);

So TWAF_NO_ALLOC not being set if that was expected to be here.

From analysis above, given the issue is we're trying to allocate here which
requires a LD_WAIT_CONFIG lock probably then the problem is we shouldn't
try to allocate here.

As not doing so would avoid this altogether.

>
> >  __run_posix_cpu_timers kernel/time/posix-cpu-timers.c:1219 [inline]
> >  run_posix_cpu_timers+0x6ac/0x810 kernel/time/posix-cpu-timers.c:1418
> >  tick_sched_handle kernel/time/tick-sched.c:276 [inline]
> >  tick_nohz_handler+0x37c/0x500 kernel/time/tick-sched.c:297
> >  __run_hrtimer kernel/time/hrtimer.c:1691 [inline]
> >  __hrtimer_run_queues+0x551/0xd50 kernel/time/hrtimer.c:1755
> >  hrtimer_interrupt+0x396/0x990 kernel/time/hrtimer.c:1817
> >  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1038 [inline]
> >  __sysvec_apic_timer_interrupt+0x110/0x420 arch/x86/kernel/apic/apic.c:1055
> >  instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline]
> >  sysvec_apic_timer_interrupt+0x52/0xc0 arch/x86/kernel/apic/apic.c:1049
> >  asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
> > RIP: 0010:variable_ffs arch/x86/include/asm/bitops.h:321 [inline]
> > RIP: 0010:handle_softirqs+0x1e3/0x980 kernel/softirq.c:542
> > Code: 7c 24 70 45 0f b7 e4 48 c7 c7 20 c5 09 8c e8 c4 6c 6c 0a 65 66 c7 05 32 53 ac 7e 00 00 e8 05 67 45 00 fb 49 c7 c6 c0 a0 60 8e <b8> ff ff ff ff 41 0f bc c4 41 89 c7 41 ff c7 0f 84 eb 03 00 00 44
> > RSP: 0018:ffffc90000a18e40 EFLAGS: 00000286
> > RAX: 959a1636e72c7c00 RBX: ffffc90000a18ee0 RCX: ffffffff8170c69a
> > RDX: dffffc0000000000 RSI: ffffffff8c0ad3a0 RDI: ffffffff8c604dc0
> > RBP: ffffc90000a18f50 R08: ffffffff942cd847 R09: 1ffffffff2859b08
> > R10: dffffc0000000000 R11: fffffbfff2859b09 R12: 0000000000000010
> > R13: 0000000000000000 R14: ffffffff8e60a0c0 R15: 1ffff11003cec000
> >  __do_softirq kernel/softirq.c:588 [inline]
> >  invoke_softirq kernel/softirq.c:428 [inline]
> >  __irq_exit_rcu+0xf4/0x1c0 kernel/softirq.c:637
> >  irq_exit_rcu+0x9/0x30 kernel/softirq.c:649
> >  common_interrupt+0xb9/0xd0 arch/x86/kernel/irq.c:278
> >  </IRQ>
> >  <TASK>
> >  asm_common_interrupt+0x26/0x40 arch/x86/include/asm/idtentry.h:693
> > RIP: 0010:zap_pmd_range mm/memory.c:1753 [inline]
> > RIP: 0010:zap_pud_range mm/memory.c:1782 [inline]
> > RIP: 0010:zap_p4d_range mm/memory.c:1803 [inline]
> > RIP: 0010:unmap_page_range+0x1ffd/0x4230 mm/memory.c:1824
> > Code: 02 00 00 4c 8d bc 24 c0 02 00 00 48 8b 44 24 48 48 98 48 89 c1 48 c1 e1 0c 49 01 cd 4c 3b ac 24 98 00 00 00 0f 84 44 14 00 00 <4c> 89 6c 24 28 48 8b 5c 24 38 48 8d 1c c3 e8 50 01 b2 ff e9 ec e9
> > RSP: 0018:ffffc9000303f560 EFLAGS: 00000287
> > RAX: 0000000000000001 RBX: ffff88803023b5c8 RCX: 0000000000001000
> > RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
> > RBP: ffffc9000303f890 R08: ffffffff81e30b9c R09: 1ffffd4000333df6
> > R10: dffffc0000000000 R11: fffff94000333df7 R12: dffffc0000000000
> > R13: 00000000200ba000 R14: ffffc9000303f7e0 R15: ffffc9000303f820
> >  unmap_vmas+0x3cc/0x5f0 mm/memory.c:1914
> >  exit_mmap+0x292/0xcb0 mm/mmap.c:1693
> >  __mmput+0x115/0x390 kernel/fork.c:1344
> >  exit_mm+0x220/0x310 kernel/exit.c:570
> >  do_exit+0x9b2/0x28e0 kernel/exit.c:925
> >  do_group_exit+0x207/0x2c0 kernel/exit.c:1087
> >  __do_sys_exit_group kernel/exit.c:1098 [inline]
> >  __se_sys_exit_group kernel/exit.c:1096 [inline]
> >  __x64_sys_exit_group+0x3f/0x40 kernel/exit.c:1096
> >  x64_sys_call+0x2634/0x2640 arch/x86/include/generated/asm/syscalls_64.h:232
> >  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
> >  do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83
> >  entry_SYSCALL_64_after_hwframe+0x77/0x7f
> > RIP: 0033:0x7faae5f7e719
> > Code: Unable to access opcode bytes at 0x7faae5f7e6ef.
> > RSP: 002b:00007ffc97dbc998 EFLAGS: 00000246 ORIG_RAX: 00000000000000e7
> > RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007faae5f7e719
> > RDX: 0000000000000064 RSI: 0000000000000000 RDI: 0000000000000000
> > RBP: 00007ffc97dbc9ec R08: 00007ffc97dbca7f R09: 0000000000013547
> > R10: 0000000000000001 R11: 0000000000000246 R12: 0000000000000032
> > R13: 0000000000013547 R14: 0000000000013547 R15: 00007ffc97dbca40
> >  </TASK>
> > ----------------
> > Code disassembly (best guess):
> >    0:	7c 24                	jl     0x26
> >    2:	70 45                	jo     0x49
> >    4:	0f b7 e4             	movzwl %sp,%esp
> >    7:	48 c7 c7 20 c5 09 8c 	mov    $0xffffffff8c09c520,%rdi
> >    e:	e8 c4 6c 6c 0a       	call   0xa6c6cd7
> >   13:	65 66 c7 05 32 53 ac 	movw   $0x0,%gs:0x7eac5332(%rip)        # 0x7eac534f
> >   1a:	7e 00 00
> >   1d:	e8 05 67 45 00       	call   0x456727
> >   22:	fb                   	sti
> >   23:	49 c7 c6 c0 a0 60 8e 	mov    $0xffffffff8e60a0c0,%r14
> > * 2a:	b8 ff ff ff ff       	mov    $0xffffffff,%eax <-- trapping instruction
> >   2f:	41 0f bc c4          	bsf    %r12d,%eax
> >   33:	41 89 c7             	mov    %eax,%r15d
> >   36:	41 ff c7             	inc    %r15d
> >   39:	0f 84 eb 03 00 00    	je     0x42a
> >   3f:	44                   	rex.R
> >
> >
> > ---
> > This report is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this issue. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >
> > If the report is already addressed, let syzbot know by replying with:
> > #syz fix: exact-commit-title
> >
> > If you want syzbot to run the reproducer, reply with:
> > #syz test: git://repo/address.git branch-or-commit-hash
> > If you attach or paste a git patch, syzbot will apply it before testing.
> >
> > If you want to overwrite report's subsystems, reply with:
> > #syz set subsystems: new-subsystem
> > (See the list of subsystem names on the web dashboard)
> >
> > If the report is a duplicate of another one, reply with:
> > #syz dup: exact-subject-of-another-report
> >
> > If you want to undo deduplication, reply with:
> > #syz undup
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2acdcaeb-23b7-4088-8014-bc983cf5423b%40lucifer.local.
