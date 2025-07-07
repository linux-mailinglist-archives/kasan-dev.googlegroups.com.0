Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB7NAV7BQMGQENHPF4EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AC39AFB51F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 15:49:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-55629c3a5dasf2478602e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 06:49:52 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751896191; cv=pass;
        d=google.com; s=arc-20240605;
        b=jjjXSuv/fiKMBIQTAKP25rjznROw5m1y9qX7xJIgz1IGp6mVMZ4DcWjO2zlY/ECkgf
         Y9yi3YB6WfB3GbMGkiQjY99DM4QGkB0Xu/51Z3dXhuPtCcKDIOz8AefFYMtgEVj6S5DS
         2MHnlE3uHJ1FBwM7I+2pWWErhKw0RXtrf79hZBg7fm+WEaUIPBzhgk0I8PWsHdFxMUip
         VZcBFtAzhyWV3DwTQpd+1ikjkCl2WPxVQELLT7dj2t3TBiW3ZCEtJQbwYuvzQJZsTZB1
         HmIVmMQIasL/Lo8ij1Y2z8ExtEPHQHf14UoxZ3oSLrHnsnbrPTx6VnY7n8sXrvN326T2
         sjng==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=7RSLsPmd6slmeyvboBfeTm6e6ObeFyo1NKRew079H1Q=;
        fh=XMatVXmQ77JT05abuA/Gg7JMXPCHipjc/zyfXrwGhO4=;
        b=EraWDiVrM4HWI+ErVUk9mv+/OJUeBz3Y1Yj6HW3YwnQmuRxKCAeT2uso/9nK6Ou7JJ
         Kxt2Oe4siL7YqC9zVNNoLvDZHfUs5AhR23zqm2Q72F32XgnlcYRSlbbnfddYihCQRdmx
         5hinDBUDQcuoi8kRuN9cso3mBno9HffEqtT6X4ghv3HmzPxoyjI25Hku4GAXhuGkYeG6
         gU8m3cZELActhUQGHvHssKbvb5CH4oR++5r0LAxSEjGcj68u44L2DKq7z6KQOJby9BrY
         +ERzuBxQYaSRZn99s6hVmD731hq+p0Faa7SMihyeuYPXARsZkgZKyw+w9G1iUueBPj9R
         vL3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DarnSAiw;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DarnSAiw;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751896191; x=1752500991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7RSLsPmd6slmeyvboBfeTm6e6ObeFyo1NKRew079H1Q=;
        b=mzm6E4p/0r5nXWLkkHzCivmrKwEN11nKwPs168ZtOfHXvTng5IKnRADeJCx7NZ0cxR
         nSTkfQ12UlN5HG/0CN0aDUpldwzRBNfmeVBsrdlLfvFez/uivDyCOxgA1wEht43eOq61
         wcMXPn+1/9BniPM3We7f4Ne6vj8Wk3tzCeWJ9biHp5gTNWfvz2dA7iQjPtYDTmXN5CPF
         ep3xYY0dVHBqOMv8a9susBhSE5LvCrHVCWAhq+2jPM3c00d7qtD9T52S0BwSDkOpcGLn
         tRXqJpaP/muhIdsBHumwCop/aVrlHURPUIJX1OIE+934h95euoZJ8hcjuAHeRAxUJhdL
         Nu3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751896191; x=1752500991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7RSLsPmd6slmeyvboBfeTm6e6ObeFyo1NKRew079H1Q=;
        b=R4JIpOMnUbeeqaC/JV0phUGVkyF/ii2b/qyZ+1PDWtdNOrVCRR8SYNp5RVQhAhV4ow
         2K2FTkW4X1eSet0Lbymu/19IEyI7fYCkiVPM79U52hUmAZXckTK9x5o8uERHeyEpqkPt
         B+6tO7QLbY2gwTsLljqdzW8UaQ9RGf7Jwc8KeOtenXiL62unT9eW0Plht6N8z59aCvXG
         rSA8y1eJp55XS5iLi1mJO2B06k8cS6q5NNp5+6Y92VqRjdP00IyLfYg9H3KtjKbqoG2q
         /mtD6TSEdBWY9UGrsvz8ioBwykn62NGyrNp+GT1rSvKx5/dwI8pKb5ruev6CVh7GFNQ0
         hTgg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCV+GpVix5LiQqQODIWiChVNAcJgHulbgA3ncklP0ENirgq9ajaFIu+T7i3fdw341bharsp6gg==@lfdr.de
X-Gm-Message-State: AOJu0YxcGnYMVOfx0/lBYDsZ2Jt79GVoGBGokVcU7j59UEorITzbrDDh
	0SuYoy+V3CxUsUEMIu5590ExyPijQUFTRS10iG9IikEyrHsJCdPRXmvm
X-Google-Smtp-Source: AGHT+IFr/C3ma+lK+rum70ZGw338t28JEOytLkGrfDzY8iU0vVuOInuDy9UpJ46gQa5rsi2alBP9Qw==
X-Received: by 2002:a05:6512:e93:b0:553:2ef3:f73f with SMTP id 2adb3069b0e04-557e5528af0mr2280257e87.3.1751896191049;
        Mon, 07 Jul 2025 06:49:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcPDt5q2PvgtXfALLn4nLsjUxH+ncD3SfNrVvesN9wESg==
Received: by 2002:a05:6512:650e:b0:553:34d7:c3a3 with SMTP id
 2adb3069b0e04-557d2ccf17cls636194e87.1.-pod-prod-02-eu; Mon, 07 Jul 2025
 06:49:46 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCX223M46rNuw2BuIUQPaKkpgynrA3QcIe05CrQ4wzred/Zl1Y1Wo/HdAxQPQz9D0kh1CBBZN+Cwv7g=@googlegroups.com
X-Received: by 2002:a05:6512:3e0e:b0:553:5d4a:1ce4 with SMTP id 2adb3069b0e04-557e5528acfmr1832723e87.2.1751896186573;
        Mon, 07 Jul 2025 06:49:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751896186; cv=pass;
        d=google.com; s=arc-20240605;
        b=SBBgyS8vhbEPy1jbTYpbtZrtWdzT+cpMaOtDtAl1LCmGWdx/gu41M0PYXVLF5h0P3X
         CTOfg0O6Khn439XTQ0UsEirluPejsbNz1y5xrua7ALJEfwfgxM6o1B6spdn5qI1rS9bn
         YfBbFA3xheTz3upkxSMccOUrhyLwVLOO6ypfqu6TmINwzq3GzD0tru1rabxHExvIpC+h
         hwQp8c+jh05MGruz7MK/bNmEC3ohzHwYZ4eRWEid3+UpN8XxImE2Zo4zXY42XpTqCjOz
         RxYubQFjrXSq/KUeb35emX5CXQTb25SXv3T9SBCypMmSY+vneSVFCxqVeQMZ2jUUlg8t
         yydA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=1pvKJflPTtna4BeEr94pcY8AALUPGeayAmKR1Br9wXQ=;
        fh=X1g3Iduv1LIhUmA5gkv7QBP9KVJ5fgEQUfZ5/GeGTr8=;
        b=E02FcA4FAhy27/KxlXp2qpzLZKbMSjkScm66xlXBrWcrX+qLt3BaKPUgU9fKz+zEbf
         e4vlVkn1qkexGqZ9nTTpTYhQJariPqdIKf/g+835pIcdwVMOkuwLPDZqdU3nhmgfGo16
         Di7T6JU1mLG+miBhPzdT7ltNjJMGPauXimd6qzI4L+fm69vEsNoykNNnbOpYrETuInvo
         TjitIvs1Vp2Y+SzE3GV7UlGZ+ZarjJrgZs1rJOGHNvDeNjdDpC3Csp7m7x7B5FQCpT/o
         aMJLHBvFAl5SkYMVnBGXbZIm+Z39fI4LU3LZsDFE+0iZAlJDSjkY0Ikv6W6wDgyarwDo
         Td+w==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DarnSAiw;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DarnSAiw;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5563847b1b8si290378e87.10.2025.07.07.06.49.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 06:49:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=nYsiyXs/4u6mHZCziTHedR8U9opA8F1lY9l02Z/XV6QE/LxVY2aJypRm38NJT/6Bpy50SEFphZ1IrQlcg8P4putKy9tVKsv+2pGN7rji8PfKh/7U+R49OKMoeh7LXeY2NeEKtgfLuzqK25GVsNjHqVTLWNJ52/YeAJeqBcmQIkku9x+H0e+5LXcvSo9BzawVvsppcv24JOfTn4ier8sLjRUDXSWw+znezDbwM8Ws50/vnaM6o2wr9U/7+z8x4SBjanj5sZiFhyRtCFEJEmBhRfwINPNZ3+NGYXT2gbvjmcnGeR9BTcsNYg3SGzAS/gajgZ9yIp/XMPVWjxDIzukf6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1pvKJflPTtna4BeEr94pcY8AALUPGeayAmKR1Br9wXQ=;
 b=uLowg75kMv3wVE/0iDAK5H5AJllPy/ZbsLCLdCoK3Tj9GlaROr/0ddV0r6+cl9t6a5F7g3/0oFEsLErg7oMOSGQ7XDD6lVYyjhx+ww163tBMs3UvJ4D/aF4rC4nX/96k9kIqYECwVnhAu4YTOBnEtV4XgLGv7o3tmnEKMu7XBdla3u+3qhPG9fXg2CN5pA0IhS2LOg25wLF83mC8bOGlIQl11nd9gpLOU04O30E8Q5Is67h04BD1dc1zsSYF9gVHYt2f24OXrRH8WvgwCVEqH06SnXiiTO9W7lJEN98/ZDvDikHy9Sy0dlacksoStjBR4n7Ej9tgsTnFVgj3I0wehw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linutronix.de smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AM0PR10CA0091.EURPRD10.PROD.OUTLOOK.COM (2603:10a6:208:15::44)
 by AM8PR08MB6515.eurprd08.prod.outlook.com (2603:10a6:20b:369::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.26; Mon, 7 Jul
 2025 13:49:43 +0000
Received: from AM2PEPF0001C714.eurprd05.prod.outlook.com
 (2603:10a6:208:15:cafe::ce) by AM0PR10CA0091.outlook.office365.com
 (2603:10a6:208:15::44) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.26 via Frontend Transport; Mon,
 7 Jul 2025 13:49:43 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM2PEPF0001C714.mail.protection.outlook.com (10.167.16.184) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.20
 via Frontend Transport; Mon, 7 Jul 2025 13:49:43 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=UEG6B85ZAwKThErgrwM8thKsGFvRdfBJtm2LJnkbO7moGqt/WSdfmo4CMB1pi+60gdxImex6mJLa/+4Wt0zDzcDnXAnIJDU7bFe/sK2fenBmphag1tWw89cQxDB6KYf5KiM7UmjGHLRjFcaz1vR+UR/uj8nOX26KG+lXQDjtY/Jif06JuDw/zpKRTDAsUEKko86UUaKJbszzwYd+Fg/1NWewgdZGAFxlvmR0Rrm2tdIYGU85G0EQbOgR7waG+VJVfprt9jXA8eIu0Lms6fddZQGfUHk+vLjSIhFYsO5swUdmdksK2FkO917cZm79qvAR9fuxVIthZVQK4UwXhJX+hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1pvKJflPTtna4BeEr94pcY8AALUPGeayAmKR1Br9wXQ=;
 b=fSqwGkS8AWBNIX+e1IXUlF2jKPu36btH9MbN30/zI/hAA3yuZSQtaASl+9Tnc5n9nHKgtIH+rshIfeQVXNiTEV6jQ9ICRiEd5FTz19Ue+uvBZTTORYziN5GmvF2O+RS2eFfX+ClAwSmT7QqJ810uiDjhDgJIEh3XrsqMPGSzKBSe0s5bigXMZGfgT9b8HLIv4awFXgoZt6w04kYsAT4oGP3uyuLpmm6zaOPV95rY6tirxTX2tycZavPVWYl9W5Gk7dN6zqBSkxrmq1AZ41TZAyD9dJ9mKdxhXrYBwvlQqBDd5I3xd039qynV4T2idxvFBT4DXBBKuWOR3Cwc23TNAA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DU0PR08MB9297.eurprd08.prod.outlook.com
 (2603:10a6:10:41c::13) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.24; Mon, 7 Jul
 2025 13:49:09 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8901.024; Mon, 7 Jul 2025
 13:49:08 +0000
Date: Mon, 7 Jul 2025 14:49:05 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	clrkwllms@kernel.org, rostedt@goodmis.org, byungchul@sk.com,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <aGvQUXfNcnRfU0jg@e129823.arm.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <20250707083034.VXPTwRh2@linutronix.de>
 <aGuGcnk+su95oV5J@e129823.arm.com>
 <20250707084440.9hrE23w0@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250707084440.9hrE23w0@linutronix.de>
X-ClientProxiedBy: LO4P123CA0505.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:272::15) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DU0PR08MB9297:EE_|AM2PEPF0001C714:EE_|AM8PR08MB6515:EE_
X-MS-Office365-Filtering-Correlation-Id: cd6569b5-250d-492a-4d3a-08ddbd5d20c2
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?kBoOWVH1uaVbuCEBz945jhxVEvgSDPUj618EM/P64q2/ev4+pzAMiy+w2Ixs?=
 =?us-ascii?Q?usz6VfBpk3z9x8nfwLbri0fdhfKysEY6aYEIZvwqz7j+cu/GNB/9eh4h0wp3?=
 =?us-ascii?Q?hDJGSBTU4NuU0n7wZ91Ej4umnMzRlMV2Nizh6Epz+flr2E9aJeFQ7V/jCn5I?=
 =?us-ascii?Q?F5O2dqArLsMMby9RAXbvqqKd6vTqUtUSJGupaeO3ja9v1yx8ZCM9wP2tnVth?=
 =?us-ascii?Q?hrgs9PFdu1tAF8Lr1RDAbFxThGawJa6RG3ji679AzGtZFdIZDw86ghn3SG8N?=
 =?us-ascii?Q?t7mE5AB5K/KismSzc7qCaed9VigNiZN2asgFp7Z7DTzP9wEIz23xa4yDfy+f?=
 =?us-ascii?Q?naB4IYv7vx3y5zBvOtCteW5P0UwsT207XCX/Vn6+dxCth5bUlCykNCCLLOPT?=
 =?us-ascii?Q?MCjfh/1bpOg8DjSpO+sowDs14J77P+yawbLlNz7NId5RTayy8GRo7EM3cpZT?=
 =?us-ascii?Q?9KaYCjFR1ZgfPjAdj7mgDQNcUXG1xjFWKVBSV00aYqpXHCEXtDz2wgbcbjV+?=
 =?us-ascii?Q?KwmIs83bVak4DKg99RB+BLP3bDS4QDDoT+6DNHphvlD3Kpx5Nyc48M2sPsuV?=
 =?us-ascii?Q?jwWffLD8GQQqqcblGDEBvLKaD1XOTl+OHJHRahd3m3DA6vJ/6q3Id38aOqsh?=
 =?us-ascii?Q?8qxx0/64o8BWCb3wmrS3mwYY3NrGPJVqa5B+E4zH5YCK1Eq9QcUFlvEyiWm0?=
 =?us-ascii?Q?/UNqR3NrBusVhELvYvaajFYzyyX5H4dSfNndGvY5uvuBkVk+lps1Jh97DcYZ?=
 =?us-ascii?Q?DxPVPpM8WaJUgUhr9u0VsM2tfqGFtR47RLyyeD0gtd4kgsSa578VGWvMLLEE?=
 =?us-ascii?Q?vC0l2wkyNVK/J2+zzS5zHCIYuHaLMBJR1KUhbaxwuuxGvBsuD0MTf9yfGv+x?=
 =?us-ascii?Q?ymWVXS8HmchG2NyDdUPDgJxl4uddz0DEewgauIJXUAmBsG6c64+Qp29GkC1I?=
 =?us-ascii?Q?DooRsk90nChJan4vsZXxFEYU0toLiulfj/Wqv6cFSr8jHdLeEgjYh8t2nXLc?=
 =?us-ascii?Q?0go+L9eSYBSu+4TUQndQyz2v8c741hdxoKiIDx5oGa+BKqJm1HnvRYjuFw5p?=
 =?us-ascii?Q?kaYpG5hIoSBeHOuvgnOvXslQ2gVTtzL0tmhHK6D7HgmzyNCAo07otBaDK6Ie?=
 =?us-ascii?Q?rWPe1tYUTTtAGJnvp0bXhwFJNINGLgWQh9ITDML2KjBSNL0fsW6jNfxOCddj?=
 =?us-ascii?Q?I8+pDkvdk5bouQfKBA8TkUyP2KgvGtR3d0n7YgRPv/JKI5DLGug7J8aCppO/?=
 =?us-ascii?Q?kHDvzrYXyMoOUPdMw0Mi9C6R+Yc+7VZFhkqy7kBp1fonwm/A2MTUyUHjo243?=
 =?us-ascii?Q?CPNdz5bKNrDp88BIGCEk2Aty5YevqVazdhkSQ8M8CgJaMe2TYvn23m6HpbzV?=
 =?us-ascii?Q?yHLDcJOfaYJALocvLRPkUYVcd+i1vrTgtT5y3UqJfmf2beAbgX09QtvOPJv4?=
 =?us-ascii?Q?Y1deFou4y+4=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR08MB9297
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM2PEPF0001C714.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 8c475ad0-df1c-41cc-159b-08ddbd5d0bc7
X-Microsoft-Antispam: BCL:0;ARA:13230040|14060799003|82310400026|36860700013|35042699022|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?lS+sR+s/d6PIP1Ym8kbmA6ZbXgQpMov5hrfd7hqdRb4zx+V400TyY8JQeXQs?=
 =?us-ascii?Q?hI3KR3YrdDFDxgsRpMrexMHs9Ejg7hI8Qg2WZLRpJymZvXYVud+kGWqoHTFa?=
 =?us-ascii?Q?SRJrBF6VrAYfMJCVHIvwzY91VSpx7VL1pZlR+ZTPKZCG99h8GnPvZLWnlvsi?=
 =?us-ascii?Q?uJwzQdI27vfxZSqEt5/rgyoHRFPClZjjhUAzOVKTWxUjutQtAX5U28HvVK1T?=
 =?us-ascii?Q?b7tbPCd4lu/r57YUjulUfdj1KaHR9N58Tian3wzP9wurkwA3irdmmuubuwn1?=
 =?us-ascii?Q?yY44UNVV6eV5V7xOn+cDX3gdJA2E15hQWTiv/M7SNa7vEtNCFhdngsUG5TFw?=
 =?us-ascii?Q?IsWJlhB7O5VnzpLiBpVA9OH3vefgTbyv5gzFhy5Y80rCyNjgoPgd7u6ZSGGC?=
 =?us-ascii?Q?LTxbvzTbs3kKQ4BM0gHoLAeZskTaCg/b0tN8+ppgTjZZQP2RP1N7kHWiB9UX?=
 =?us-ascii?Q?UhQKLQPQY64lfqVbRUn+Ni/oQGvGbYwlwMl+gZslRp3PvVMrUbgH59qg05Ck?=
 =?us-ascii?Q?fhEH6+eILevFQwrf2Lkek9im+eOuc2N7umALk0bSefYqK7VbQ2K834ivAevN?=
 =?us-ascii?Q?+iGrZQdlvgqDc7mjnhEDOPsQInxVbe6xG08KMZpWUUV1QuoeUqlEVjNSkAX/?=
 =?us-ascii?Q?Quo84Oe0KVKCW4rbfi1SXAHCa9a8Pt1/Q842LnZDnrW9ovb8Fp+HrB00ESrT?=
 =?us-ascii?Q?MWYO7iGGRmhn2tdidjS/c/H/x+SZp3TufWfKHl7KDv7GG+QPSo850UQM0EvE?=
 =?us-ascii?Q?Svdcgm/eF08a1UXRBnuIIlP771QMxmuueKWzKZQSRIjzLyS4CcFVk6qHQHgv?=
 =?us-ascii?Q?/62gZKBuFsc64MsXn6/4I38gWOAEuwf6gLb/xc3FZc4Vd5klwUaUFIat/n6U?=
 =?us-ascii?Q?k7A8JFwtIKs+1vtcinxzxB/F4PGiv4w3Z8vF9CjLmG5mdGmOVPg6M8FqVuo2?=
 =?us-ascii?Q?DrFRk3rcwviow962ZzZKoW2H9gA0ws4v/tYCJmpBblZtpffWIb1k5bIdVG+2?=
 =?us-ascii?Q?EO7MP2kMNWkzFbjSHd9jvaNZtluLMeqehg30OR7IMws1rDOtQPLsSF189M8r?=
 =?us-ascii?Q?9FsPTsoqon0pXgz7ezPQM8iqiA9NEemwBABL8rOmmknkbDvP7tapo6G3EogK?=
 =?us-ascii?Q?mZNTu1Nr4pVY/zeagZ53r7nQEbiEyRXTZAXD9YsFC/oNG7X34e8YBI5swIlr?=
 =?us-ascii?Q?mnbgEeQXfixOIaNc99O6Q+crGQO5Y/EGF5//sU8G7G98AtLVotYdzdHCE3Y6?=
 =?us-ascii?Q?PP3IAYg6bbHDqpGQgtsxmLQwa/8fnmMyYl+ypqe52ljyUT3kdOkiWuolJGxG?=
 =?us-ascii?Q?aSFZ+wQbOdX79nRjQe1AzUC+CYEpoHZJ5ACaB2hoSJ0EVn+q0Pto8lFJx5Y/?=
 =?us-ascii?Q?QRpz8xpZgzSM3bDwhd6jJ/vqWS/R/ZlIg8P2eZn4pJxQ0Wf0JFAF33IDhQ03?=
 =?us-ascii?Q?KvLcw5Dn9tDLVA+D8uUAgGEKPNQxmY9kx8fant/iIOUKqL408GpORAZ9P5D4?=
 =?us-ascii?Q?X20YU5aIXwNx7aYH4jTDjHpwmzly8q6SCjl4?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(14060799003)(82310400026)(36860700013)(35042699022)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Jul 2025 13:49:43.4804
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: cd6569b5-250d-492a-4d3a-08ddbd5d20c2
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM2PEPF0001C714.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR08MB6515
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=DarnSAiw;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=DarnSAiw;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Sebastian,

> On 2025-07-07 09:33:54 [+0100], Yeoreum Yun wrote:
> > Hi Sebastian,
> Hi,
>
> > > what is DEPT?
> >
> > Please check the below patchset:
> >   https://lore.kernel.org/all/20250519091826.19752-1-byungchul@sk.com/
>
> Thank you.
>
> Would lockdep see this if check_region_inline() would have something
> like (minus missing exports, just illustrate the idea)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e76..c74e8e0863723 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -171,6 +171,11 @@ static __always_inline bool check_region_inline(const void *addr,
>  	if (unlikely(size == 0))
>  		return true;
>
> +	{
> +		struct vmap_node *vn = vn = &vmap_nodes[0];
> +		might_lock(vn->busy.lock);
> +	}
> +
>  	if (unlikely(addr + size < addr))
>  		return !kasan_report(addr, size, write, ret_ip);
>
>
> ? Just to understand if lockdep is missing something essential or if
> DEPT was simply enabled why this "bad" accessed occurred and was able to
> see the lock chain which otherwise stays invisible.

No. I think lockdep could print this error situation without this patch.
Since lockdep prints other cycle in test enviroment. I've attached the
DEPT report.

Thanks.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGvQUXfNcnRfU0jg%40e129823.arm.com.
