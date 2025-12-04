Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJWNY3EQMGQEJPAOZ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id CA9C3CA4377
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:20:08 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-7a998ab7f87sf1494369b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:20:08 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764861607; x=1765466407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QSnr3Kg362kp+NH7Qm8Fspc00Yj8FGXgDe4INSqa7Ps=;
        b=CufMmj4i+SGtU2hEK/xi2qwJo1JLlLaSQkizE21c17x7dv4SYrLgT4Qcw3NIHIJj7K
         91lDT2+mxemLyQ0MPgpEap2c6arjT7yUMIQStzPIIUOY6bz7ZRVn1dt5qxdJpzJ6sdxE
         m6IqJh2B1x67vLshUbI/yOaqUM9B97/1bjGoNK65Jdhd0Y3rf3pOMyrndUBHrZaAME29
         r5RXI2dQvnjWKdsZi0+YhXY2ctDZIalHwwTk1xBJgOLCzt9RW2WlBf61K5xqUijGOUDw
         vlr4vdQYJNkqNPMEM31C2HXUzGcpVsJ7aEAm+5M+l2TMQ8LZjGj2/QHJifdWb9DL5jVL
         v2+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764861607; x=1765466407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QSnr3Kg362kp+NH7Qm8Fspc00Yj8FGXgDe4INSqa7Ps=;
        b=eDgo/JM3+ohM2kywToKQ4XMT9C38TeIwfx+Bx4g5ETNdXMf+LJ448WxUoZJvwB6tOy
         2UkYyYJkeM2C8/fa6kLub5Oy0IKWdZPKsgw4lUjo6PK12hViiS16ccLuSPjxBEMA1cS1
         mA/glel1uLB+EhW50PkqSHpBNMF6rCu3qcgBKIqwV/T4IOLsUZxUOrKmgZ3ZL96fAJOX
         zZbBVgAXaNtbFpuUhrjPAUzivTjzEa5X2JMYevC01wgJSPvV57fJ6M1cjAK/t0rYj3OL
         1CIDPJlXl9fYRzCc4AB+qyEdSQOxtPhRP+MARCAHKqK+YuR6uKjs6TW7g00r2PiXYn1A
         MPEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUEySK1L9U+Yva8Ck89AKKYRpLoG7FLFe1y68B/p2z8oIqL3Yso03pnDGVKoUPpaMXOzitukg==@lfdr.de
X-Gm-Message-State: AOJu0YxmyZsJOre5febbKT2Q0ND4IZvLVz6MLVaDfJvxBXv88sgrNEUf
	kGiKGqlLc/K9vo30ed94e53vdD2AS+Eum1O8AXroe+YFdei8fOiEsZbn
X-Google-Smtp-Source: AGHT+IF8jn2Uu58X1+dMnlA1HF/1AuApsuh7K6Jaa1uFv9WMWU0NNsfOnlXM1kAudRCZ6EI3zuvRQQ==
X-Received: by 2002:a05:6a00:1950:b0:7b8:155d:a5 with SMTP id d2e1a72fcca58-7e00a2ca31dmr7249119b3a.9.1764861606763;
        Thu, 04 Dec 2025 07:20:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aad+e+l8BakijWZQDWBLRZJxZxzUlM5ZaxsTgwzVZ08Q=="
Received: by 2002:a05:6a00:26d4:b0:7b1:eb6:10db with SMTP id
 d2e1a72fcca58-7e26787a57als918571b3a.1.-pod-prod-03-us; Thu, 04 Dec 2025
 07:20:05 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW/pNCh2fUYAzJb3UjNKYFuDH0N/syA/pGnEtw7QNgAo1C2C+R93yByTJybexRykdPdlGOddAb9RXE=@googlegroups.com
X-Received: by 2002:a05:6a21:99a5:b0:361:3bdd:65f7 with SMTP id adf61e73a8af0-363f5d3f2d4mr7667839637.13.1764861605352;
        Thu, 04 Dec 2025 07:20:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764861605; cv=fail;
        d=google.com; s=arc-20240605;
        b=PodiecR6ulfOc8mUFRSyuJEauvCyoUksHQz28nrfRDXqa5h4Jeh3jl2gkgL8XrIrzV
         oOkgRhnVy0Eg2QbaUeZRgMgIMmBsxh5dZTmBrz1IOTDYT8GJwQEKQNacmYGiVRta7tFr
         KkLywRPkAuCU9YK+6Tab7/fiAd5P7CIEHzNfDy8BjIqDuj/qPdnWWaoefHmTFiHCITVW
         7jmf7SbAROc0cu1MJCKDWPV3QRchT7hPkiHeE7rREAu+VV3bWm3TbYLHEUKSjAkC0hui
         k86P2SccfDGYu/zW7WbAffwzUDnTJSV22IToVusJ5CwZFeDOckdxP7lierZQ/tpaLwsH
         GBbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=28Khn9w5ufXYzjll8WqLV4IgXPs6hGDjeWtWQJw++zk=;
        fh=KUv7xo0m4wVeF5Z7LCeUxDK321j98b2R/XpZAc2P3bc=;
        b=MOpw8hVtvWXtfpBSeB+RUPYGgcnqXPBno9l2vDmRjsAjPa3zeT4cXsX2sE1fBrLvuM
         4AOn69WUtL4h8AS3Pwe5se8iSkORqrAjSZq9o2AnTOfNJoboRFZsdgVCFPBHX1qqIUwr
         cP//twJvP0GhXZKhbC7TETuRtk6TamnI6g2mPvyShEMEZqN1439DgzqS2N/s7pHLGC+C
         zrfw1hE4cuGMSlR5iRbAcictryjFQQQaEcT7aGOBUcdfFAN2cLP73X33h+tFZPyBt/ve
         HOS1uAWt2omEKn4PkqTnWr7IuPAuvQlaXFzb7M1ic9NPS4CQcEHXqQhliq0EsucS3JXg
         n4Pw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QX9Gg9bE;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7e297aa1a91si51271b3a.0.2025.12.04.07.20.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 04 Dec 2025 07:20:05 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: NBvyR4biSZKyv3l6id1V6w==
X-CSE-MsgGUID: drDYZOu/SDS2frjlNZIf6A==
X-IronPort-AV: E=McAfee;i="6800,10657,11632"; a="65881468"
X-IronPort-AV: E=Sophos;i="6.20,249,1758610800"; 
   d="scan'208";a="65881468"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Dec 2025 07:19:53 -0800
X-CSE-ConnectionGUID: hLYUHxEDQbWi4LjJuGUgXQ==
X-CSE-MsgGUID: WSaNca4tQVWUznX0u52pnw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.20,249,1758610800"; 
   d="scan'208";a="232346817"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by orviesa001.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Dec 2025 07:19:53 -0800
Received: from FMSMSX901.amr.corp.intel.com (10.18.126.90) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29; Thu, 4 Dec 2025 07:19:51 -0800
Received: from fmsedg901.ED.cps.intel.com (10.1.192.143) by
 FMSMSX901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29 via Frontend Transport; Thu, 4 Dec 2025 07:19:51 -0800
Received: from PH7PR06CU001.outbound.protection.outlook.com (52.101.201.12) by
 edgegateway.intel.com (192.55.55.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.29; Thu, 4 Dec 2025 07:19:51 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=a5tNp2OI+yR1CkP788tViZGrcb8mm5HdSW8M8TnpXAwoe4Vm2fieLkjTUL/wc1nocOnmHdSS4n2QDervyrhtepS+0gB+RVNhOtUclEVnoFrFvwBD5zF/kh12u9tfHTbEp8SiD9t5qMVQoQFZeY7ApVqnH8Rb8EdeCpCtD3yPt2vLwoPQp1CYscrQ3KPADmrU5kTdYxKYt7cd8N3geq0oITdEo6JiYmV5wxmFGbsBwkJu3aDzjhFBoUCZE7TTMO84EFQt96dsXX9g6P+EZcFBzD/DJl5ntufyTI1/3XBj/BjrQ1C5S6pkcbg9ubsDQYzmSGUI0odt9CYtHEpL9Z3Zcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=rSnNiXkXFcSHefeMIiGZiuGLSX9u3caeyPTWyqQhMgE=;
 b=SFiyzmmBFYVAIkbkuiOn4r4CntmPfXDmhCO7+kUHL+d9MwoexgGszeE3+bbIdVv0Li1kjbFy97Asbu2lmtefvx81gRoYs+RofDMa9TNdnqsPIdairodZL6BZiaoLdzRE5NjMD9K4m5DpOU5b2yRrmKuWEpxBiRlBfFxaAZFyQ9aM8HbVJeyXE1xINtSs2CKgvYm+ZROddq/cDtTm7I/fc8O38dG+jUHp8cHlUg6cEBJmYDvrvUEZhd8BN68faEW7s/hPXMatBtOP3gs7Kx57TAgse/1AyIQ+n7GPuTLsrVEYbBxmrKgigURKqskCIiEpMgaxaBQ8/3g7I+33uYmS+w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from BL0PR11MB3282.namprd11.prod.outlook.com (2603:10b6:208:6a::32)
 by IA1PR11MB8863.namprd11.prod.outlook.com (2603:10b6:208:598::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9388.9; Thu, 4 Dec
 2025 15:19:48 +0000
Received: from BL0PR11MB3282.namprd11.prod.outlook.com
 ([fe80::5050:537c:f8b:6a19]) by BL0PR11MB3282.namprd11.prod.outlook.com
 ([fe80::5050:537c:f8b:6a19%4]) with mapi id 15.20.9388.009; Thu, 4 Dec 2025
 15:19:48 +0000
Date: Thu, 4 Dec 2025 16:19:41 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Jiayuan Chen <jiayuan.chen@linux.dev>
CC: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, <linux-mm@kvack.org>,
	<syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, "Danilo
 Krummrich" <dakr@kernel.org>, Kees Cook <kees@kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
Message-ID: <7tpdpvjdcfcujdlkartvbx5m3ngqanwa5brclxnytsrzcvqc2a@n2mnvjtmpzuv>
References: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62>
 <0FXl31cx1KiP0tp1scQSFD7bD_qTnsT7aWdk0JBsUiAkvTgsHfSfAwcqihepAd5R7TweJ1ClN8daEGlJzS8UCQ==@protonmail.internalid>
 <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
X-ClientProxiedBy: DUZP191CA0009.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:4f9::17) To BL0PR11MB3282.namprd11.prod.outlook.com
 (2603:10b6:208:6a::32)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BL0PR11MB3282:EE_|IA1PR11MB8863:EE_
X-MS-Office365-Filtering-Correlation-Id: 7d603882-5125-48d3-dd2e-08de33489014
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?l4Pua/1oXtlO3+fbYyo0rxmc8sErfGuvF4VxpjlMvkctVG5QDDi+Ul2miI?=
 =?iso-8859-1?Q?YXzZYRQkdRJ8PRkGyhcIekjVq6aooa/se0o76pzIHftbGXYc5bHX1WHgHt?=
 =?iso-8859-1?Q?tCRrHqY95ArQr2/Hv7haKGkOdPCsXJW+ZGQlQrJd884PPogvtzz4ykxKli?=
 =?iso-8859-1?Q?GypCQi4MxVQXchfOVO/+R7jNDkg1/EyTrenTSo901WSKhJI/TEdyzSaXue?=
 =?iso-8859-1?Q?eWJjnPH5VBem9RmIGMUaW9dsSete/a9dLpXQzTGtJHUNmhY7GS/jWpo+Lw?=
 =?iso-8859-1?Q?3N4il+oyvZ+o4CCHpR1Tk+CYXKAJNfSbhUHrr26zFE5RjHmq0eqTrOMPgx?=
 =?iso-8859-1?Q?jjEVPuQWnXlSP7g0hauXt7q2BwAABajze3lN1BiVueG9alsDTdQd3P+QYN?=
 =?iso-8859-1?Q?Sau/QTQ9AXH+7Yf6BLhNR4jyraZh9JjrQvqWiSp/PSxs8eKdjaROWKATvo?=
 =?iso-8859-1?Q?L3PrerYHHh+ljEJLOBTYbhsFWeOZQWOeBE+uZgIp2uqwVsL+hS9kzWm5Xf?=
 =?iso-8859-1?Q?fNmFU8EpXRrkBs/NENzhDym6F+y0an5wMgI56I2DBDzsetJ8o8dxK0S4qW?=
 =?iso-8859-1?Q?zOKLAM/iMYB81THdejnwhBzWA1MV/aJCSsF1VjBw+PGtsgE0/dTfd8mr3T?=
 =?iso-8859-1?Q?UE54+1HjAMta6TJjD3UNPgplEq6UpN7jVBDSC4beBNLXRMcd8iNnRYX38+?=
 =?iso-8859-1?Q?pAbUHdKKD9qz0Vkwc62HxuKL/pul4CbHZOrVAL8I9dJ5i9QqoKgRtPJZul?=
 =?iso-8859-1?Q?n9tO8zRJqaLKi0uawrFcfJbm/v+DtKyRo+4cpIw+DjvnliQ7BLHW8QLy3C?=
 =?iso-8859-1?Q?UBlomF0eFaHNoHZ5ySkXbuJ0zQr6G7lu+pQFSVWjsp/8hAH5GzJkNUgvMO?=
 =?iso-8859-1?Q?G2hfxFIL49scOgmhx9LQYp2A7JZACWuFQZZTDthJ1R68pdvy5b+e0H9wwH?=
 =?iso-8859-1?Q?OR9Q/pnnMijZXlrbykFzITISI/2nw8GzTOUTMvKMxUuLtRXB+TGnikelPR?=
 =?iso-8859-1?Q?cwnZ6ktPo8TQuEVMzZEyo7ZgTPKWvIxizPZIW25Lvf5dF/0DwDsV7KuPXC?=
 =?iso-8859-1?Q?yPJ4FUOzm0NwZWyE/NSDkv6OY9G0oYhJ9M97IAFdMa8dsss9PzeYHD02Ck?=
 =?iso-8859-1?Q?v6oIrkArnmjUTgGC2mQR7cnU8xBdQ6CEFHl8JM+6kYghm6bvkyiYDdPNY2?=
 =?iso-8859-1?Q?2ZFpS2t4kgMhaBvl2jiWE3CcJcG69rHysCIVurMHJ8v/odnqxbCjK2kOTd?=
 =?iso-8859-1?Q?lmOuyIRL3I/YSetgl8WCDCsXCxgK9Zv+FZx7AbHsfsXw+iHd+5KV5SlUVW?=
 =?iso-8859-1?Q?GMDrfjEooc4GfEERPHuN8Xkus1eJjyBDNchCcjVcpbfL2efE6wvZMWLs1/?=
 =?iso-8859-1?Q?XvHN+II0JOg6rRUqX7yYK+U9lrFPODgAPMojyblLv7BelXEqbbXjFK5yqy?=
 =?iso-8859-1?Q?xkbwmh8VIN4rOicN6Gf1MPTpwaa8fs1LztqtBg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BL0PR11MB3282.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?CVtoohbERnyoqZcM+gCn9kx4INjPp7hRnBtlVP0/vlGxh5tO+0B+KuG/bQ?=
 =?iso-8859-1?Q?ORdJ2KX08NeUJl3Jb5QYKD+Kf8JdJ1zKYuR8MClf+sac6nZat1XuTIAb7N?=
 =?iso-8859-1?Q?d+/VExGTRMgd4U0dfZ86atLR5FVc6qamVJl07uHcbC7PXNz0IdniBGKNMQ?=
 =?iso-8859-1?Q?OmFkWGn8+NqSWe5xmDJdEcjfAuj9kPenhCK5WuY/FyvRsd76ofUyeYdNaQ?=
 =?iso-8859-1?Q?zsvnB91FgD4VyuGnx03fTtiIWGJWT5qivKwtHkVGZdC64F2I6EcW3N4MNP?=
 =?iso-8859-1?Q?B19rmiNBB1w723zZk4kzozRRyn7DIYpLybAgU67cXAGIjQBAIAi5purLMt?=
 =?iso-8859-1?Q?AM8UKP0QgokV2BywSgB9SyNQ+0tJihQc5Z3TGZ6C/nCqQBO1rD2ygD8MDb?=
 =?iso-8859-1?Q?VHO0yAq6EzdACfNlcOKiqovZvodNF6hguV9LC+2bh7MTop6trdsZ1gVrfc?=
 =?iso-8859-1?Q?WcbqaWv3dhDYRqV0kGVvsPtIT3weHcVu3vxsrfE6Y7UL7ex/47I4J+uf1e?=
 =?iso-8859-1?Q?dWdDEkKiAzFubkkfeCn0MpDRdp0aCpdNOnMYCKhmOfMDpZOy/4WqtkMEtg?=
 =?iso-8859-1?Q?KNgNGjvLe02oAkXJooMHE12ATmoJa2vJ/Gz2DVtsGBFs7zCWP0FNXGtOfj?=
 =?iso-8859-1?Q?zUAF2jdSsdpsXMWNcvaXxNuQppxC+y7fyVQik7xRcTMoX4xNJg5XXrzwPw?=
 =?iso-8859-1?Q?bseYvJZkyTGTg2rf7lPp5J1na2Z2fmYhCONbFKOqv0iQ0uZmhkuZk0ECO7?=
 =?iso-8859-1?Q?ePb++4q0m8sELLOs74xeI0wcW7YkfoMjCKm0VZXi3lsVKpOYlqusTBDf9V?=
 =?iso-8859-1?Q?R+hTvpDLw++tquo/d0gwljXiWyiV/xzvpXIMrVBZe5Cb9Do6/B/82wLfWy?=
 =?iso-8859-1?Q?ifOqJAsTh69ckZPhbhWuxkb8t0bIfWItVBvDqNovM4qxZZw9eqn8nct2A2?=
 =?iso-8859-1?Q?89D0uomuTpPnYiggNELtHFaXghjSZ2wDyRFlmpWXpyFB/lfzrccVvILSUl?=
 =?iso-8859-1?Q?j8ZlRbuS6GyI8LkOMRJPoXJdaaTZumU+GHdjdXTYUXmrNnQ65vvkdISTLy?=
 =?iso-8859-1?Q?uK1653RdD60cB3DiaCSaZzOWAV4SYjbd1Lp8q01E/edPM1NCKLZ6j1DPA+?=
 =?iso-8859-1?Q?LrGFg7qqpKCfFNr0R5MpJkXvldgieJ1p17CmB136CgBYUZf8xou3z95hmX?=
 =?iso-8859-1?Q?y0jtMqZyKBfHfqHmtlnz0YvIcIbVs7J/Xe4v5qYqZN/fPXXJzxP9W/b+cD?=
 =?iso-8859-1?Q?p7cNstr9q6Xu0vNof3On7Pc8GFYyj+hb3JzDsxk4LWE1g8LrBOHod2p+8G?=
 =?iso-8859-1?Q?+QeRBHXn2mA+h8Nax6voCjXzk54leHjwiaFJnlotv2V9gYDBhGHQBng1oE?=
 =?iso-8859-1?Q?THUPuzD4kn+DPU54aQ+pvpqVtFJSgHA/PiU0l9SPgFwpovcppus9SUz9Pu?=
 =?iso-8859-1?Q?9P6dpcyASYolGeP7Sjqg5KDevjgA9BiYMz7If75VKPBntEsKGOA7naqt0F?=
 =?iso-8859-1?Q?WS6DTbwaUZW90fNOf4mGZmUNWAoZIzCG+kiMOdPscC4uf1IWp43vFr8aoW?=
 =?iso-8859-1?Q?OwbpKCjWQIyNUXXW4Aqd8apGhzy/KJqonN1enyI+zyYYIXUSt6Xgm1wKmY?=
 =?iso-8859-1?Q?eKcUtQPRhk2DKrG3PX8sgtkfdIALpPLzcYISatj4LU2Wn7d1Bt0qHd/U/g?=
 =?iso-8859-1?Q?FJBXi4rE7bwdZbC1N2s=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 7d603882-5125-48d3-dd2e-08de33489014
X-MS-Exchange-CrossTenant-AuthSource: BL0PR11MB3282.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Dec 2025 15:19:48.3214
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mZwfaBh1tOet3hB12DhVGSKeqhROKFI/1QEdnbjDe5l8kQVr5xb1NIVZy32+Qi5CbKor79K8r6H71AR+qjOJTnvani1oP+hUoknZHKtWdkQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB8863
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QX9Gg9bE;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 2025-12-04 at 14:38:12 +0000, Jiayuan Chen wrote:
>December 4, 2025 at 21:55, "Maciej Wieczor-Retman" <m.wieczorretman@pm.me =
mailto:m.wieczorretman@pm.me?to=3D%22Maciej%20Wieczor-Retman%22%20%3Cm.wiec=
zorretman%40pm.me%3E > wrote:
>
>
>>
>> On 2025-12-03 at 02:05:11 +0000, Jiayuan Chen wrote:
>>
>> >
>> > December 3, 2025 at 04:48, "Maciej Wieczor-Retman" <maciej.wieczor-ret=
man@intel.com mailto:maciej.wieczor-retman@intel.com?to=3D%22Maciej%20Wiecz=
or-Retman%22%20%3Cmaciej.wieczor-retman%40intel.com%3E > wrote:
>> >
>> > >
>> > > Hi, I'm working on [1]. As Andrew pointed out to me the patches are =
quite
>> > >  similar. I was wondering if you mind if the reuse_tag was an actual=
 tag value?
>> > >  Instead of just bool toggling the usage of kasan_random_tag()?
>> > >
>> > >  I tested the problem I'm seeing, with your patch and the tags end u=
p being reset.
>> > >  That's because the vms[area] pointers that I want to unpoison don't=
 have a tag
>> > >  set, but generating a different random tag for each vms[] pointer c=
rashes the
>> > >  kernel down the line. So __kasan_unpoison_vmalloc() needs to be cal=
led on each
>> > >  one but with the same tag.
>> > >
>> > >  Arguably I noticed my series also just resets the tags right now, b=
ut I'm
>> > >  working to correct it at the moment. I can send a fixed version tom=
orrow. Just
>> > >  wanted to ask if having __kasan_unpoison_vmalloc() set an actual pr=
edefined tag
>> > >  is a problem from your point of view?
>> > >
>> > >  [1] https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretma=
n@pm.me/
>> > >
>> > Hi Maciej,
>> >
>> > It seems we're focusing on different issues, but feel free to reuse or=
 modify the 'reuse_tag'.
>> > It's intended to preserve the tag in one 'vma'.
>> >
>> > I'd also be happy to help reproduce and test your changes to ensure th=
e issue I encountered
>> > isn't regressed once you send a patch based on mine.
>> >
>> > Thanks.
>> >
>> After reading Andrey's comments on your patches and mine I tried applyin=
g all
>> the changes to test the flag approach. Now my patches don't modify any v=
realloc
>> related code. I came up with something like this below from your patch. =
Just
>> tested it and it works fine on my end, does it look okay to you?
>>
...

Thanks for letting me know, glad it's working :)

In that case I'll go ahead and post my two patches with the vmalloc flag
addition. And thanks for pasting your code here, I suppose mine won't confl=
ict
with yours but I'll check before sending.

kind regards
Maciej Wiecz=C3=B3r-Retman

>I think I don't need KEEP_TAG flag anymore, following patch works well and=
 all kasan tests run successfully
>with CONFIG_KASAN_SW_TAGS/CONFIG_KASAN_HW_TAGS/CONFIG_KASAN_GENERIC
>
>
>diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
>index 1c373cc4b3fa..8b819a9b2a27 100644
>--- a/mm/kasan/hw_tags.c
>+++ b/mm/kasan/hw_tags.c
>@@ -394,6 +394,11 @@ void __kasan_poison_vmalloc(const void *start, unsign=
ed long size)
> 	 * The physical pages backing the vmalloc() allocation are poisoned
> 	 * through the usual page_alloc paths.
> 	 */
>+	if (!is_vmalloc_or_module_addr(start))
>+		return;
>+
>+	size =3D round_up(size, KASAN_GRANULE_SIZE);
>+	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> }
>
> #endif
>diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
>index 2cafca31b092..a5f683c3abde 100644
>--- a/mm/kasan/kasan_test_c.c
>+++ b/mm/kasan/kasan_test_c.c
>@@ -1840,6 +1840,84 @@ static void vmalloc_helpers_tags(struct kunit *test=
)
> 	vfree(ptr);
> }
>
>+
>+static void vrealloc_helpers(struct kunit *test, bool tags)
>+{
>+	char *ptr;
>+	size_t size =3D PAGE_SIZE / 2 - KASAN_GRANULE_SIZE - 5;
>+
>+	if (!kasan_vmalloc_enabled())
>+		kunit_skip(test, "Test requires kasan.vmalloc=3Don");
>+
>+	ptr =3D (char *)vmalloc(size);
>+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>+
>+	OPTIMIZER_HIDE_VAR(ptr);
>+
>+	size +=3D PAGE_SIZE / 2;
>+	ptr =3D vrealloc(ptr, size, GFP_KERNEL);
>+	/* Check that the returned pointer is tagged. */
>+	if (tags) {
>+		KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
>+		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
>+	}
>+	/* Make sure in-bounds accesses are valid. */
>+	ptr[0] =3D 0;
>+	ptr[size - 1] =3D 0;
>+
>+	/* Make sure exported vmalloc helpers handle tagged pointers. */
>+	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
>+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
>+
>+	size -=3D PAGE_SIZE / 2;
>+	ptr =3D vrealloc(ptr, size, GFP_KERNEL);
>+
>+	/* Check that the returned pointer is tagged. */
>+	KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
>+	KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
>+
>+	/* Make sure exported vmalloc helpers handle tagged pointers. */
>+	KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
>+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
>+
>+
>+	/* This access must cause a KASAN report. */
>+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + 5]);
>+
>+
>+#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
>+	{
>+		int rv;
>+
>+		/* Make sure vrealloc'ed memory permissions can be changed. */
>+		rv =3D set_memory_ro((unsigned long)ptr, 1);
>+		KUNIT_ASSERT_GE(test, rv, 0);
>+		rv =3D set_memory_rw((unsigned long)ptr, 1);
>+		KUNIT_ASSERT_GE(test, rv, 0);
>+	}
>+#endif
>+
>+	vfree(ptr);
>+}
>+
>+static void vrealloc_helpers_tags(struct kunit *test)
>+{
>+	/* This test is intended for tag-based modes. */
>+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
>+
>+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
>+	vrealloc_helpers(test, true);
>+}
>+
>+static void vrealloc_helpers_generic(struct kunit *test)
>+{
>+	/* This test is intended for tag-based modes. */
>+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>+
>+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
>+	vrealloc_helpers(test, false);
>+}
>+
> static void vmalloc_oob(struct kunit *test)
> {
> 	char *v_ptr, *p_ptr;
>@@ -2241,6 +2319,8 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
> 	KUNIT_CASE_SLOW(kasan_atomics),
> 	KUNIT_CASE(vmalloc_helpers_tags),
> 	KUNIT_CASE(vmalloc_oob),
>+	KUNIT_CASE(vrealloc_helpers_tags),
>+	KUNIT_CASE(vrealloc_helpers_generic),
> 	KUNIT_CASE(vmap_tags),
> 	KUNIT_CASE(vm_map_ram_tags),
> 	KUNIT_CASE(match_all_not_assigned),
>diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>index 798b2ed21e46..9ba2e8a346d6 100644
>--- a/mm/vmalloc.c
>+++ b/mm/vmalloc.c
>@@ -4128,6 +4128,7 @@ EXPORT_SYMBOL(vzalloc_node_noprof);
> void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned lon=
g align,
> 				 gfp_t flags, int nid)
> {
>+	asan_vmalloc_flags_t flags;
> 	struct vm_struct *vm =3D NULL;
> 	size_t alloced_size =3D 0;
> 	size_t old_size =3D 0;
>@@ -4158,25 +4159,26 @@ void *vrealloc_node_align_noprof(const void *p, si=
ze_t size, unsigned long align
> 			goto need_realloc;
> 	}
>
>+	flags =3D KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC;
> 	/*
> 	 * TODO: Shrink the vm_area, i.e. unmap and free unused pages. What
> 	 * would be a good heuristic for when to shrink the vm_area?
> 	 */
>-	if (size <=3D old_size) {
>+	if (p && size <=3D old_size) {
> 		/* Zero out "freed" memory, potentially for future realloc. */
> 		if (want_init_on_free() || want_init_on_alloc(flags))
> 			memset((void *)p + size, 0, old_size - size);
> 		vm->requested_size =3D size;
>-		kasan_poison_vmalloc(p + size, old_size - size);
>+		kasan_poison_vmalloc(p, alloced_size);
>+		p =3D kasan_unpoison_vmalloc(p, size, flags);
> 		return (void *)p;
> 	}
>
> 	/*
> 	 * We already have the bytes available in the allocation; use them.
> 	 */
>-	if (size <=3D alloced_size) {
>-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
>-				       KASAN_VMALLOC_PROT_NORMAL);
>+	if (p && size <=3D alloced_size) {
>+		p =3D kasan_unpoison_vmalloc(p, size, flags);
> 		/*
> 		 * No need to zero memory here, as unused memory will have
> 		 * already been zeroed at initial allocation time or during

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
tpdpvjdcfcujdlkartvbx5m3ngqanwa5brclxnytsrzcvqc2a%40n2mnvjtmpzuv.
