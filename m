Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBCNIRPCQMGQET4YZ23Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id E3882B29AB0
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:19:39 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-323267bcee2sf3645650a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 00:19:39 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755501578; cv=pass;
        d=google.com; s=arc-20240605;
        b=j4y5HEtmfhbh2xKQrltcO5F2SZZozm88PVkVdWP0/1QDWD+YCT7lrDYo4JQV2pH3rF
         V45Yxh/AqjEJPpLqKiTHRZbQOpUo4pq0S0UXt0UTRChsMYBxn3+FMBEgMl9swiKS28dv
         RznLG9c+hLc3EsqK7UW6N/yd6IeVgSe9Hx5F9Ksw80XZfGykFoovogN9QWlSoiDrFggS
         DURiyEMtAq5bhu3nQEJswVO5F6Gw/KOHDUPQOt8i4o72kww3zTbxix8vUVKGjik5cWnd
         2iiqkW1RrzFz/pH/QxxBDX3FK7CWNqVwJQXW/IA+W9j1vWRCQ8nFxf8kV8S+VXuWAOQJ
         Pxbg==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=F5KAl6w8WU7mn+4LBLsxKsoYRqzG/giURQyJX4eHW3o=;
        fh=dZpXx5HB1X0eW35xsjH26G5i4nwmX3zE/ho2VS3lBHQ=;
        b=HHNekfj4gQNP/eit9d4Ddtql5CxXbX43KaiiOTY+H3xvG2neq07kMg7bwdDwCOBBFe
         8bi2UzpryE70JTq3z+QUmE393HoaA3MI3wxtTFkTW1Nt0GsCPbPyCByB4H4eYyTJLcDi
         h+NDMdgvig520KW2Mzl4MdWN/i2ZMCFMV8h9Z+nQu/2anUKKz4ZumfUtekeanNr0WquA
         bvpv+tMors6Kgvpuc2jN90s21TXpd3OqCcUaLKHX4uUum3Ke5T9hRJwrUs1PgRXX8FuM
         cBx0oNq2qUU/p8h8zz48tCIYtN9D6zZdEM9ZGOnEoUscIzZAf8Jptwcfo1ycDTAzoqt7
         x/kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755501578; x=1756106378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F5KAl6w8WU7mn+4LBLsxKsoYRqzG/giURQyJX4eHW3o=;
        b=Zk4gfaR91lA6LfXRpnMHhOE9rbWJUTKXg2w2oN6TkbTfjZoE2oJjzbY0nhBlpHz6fJ
         DHZAeBZXObXjxw+sfKvr4IIF74ZtKeCfIgJs2a9v9HFUiPoJ2J4uuqQ8YmAF0UFHoVQe
         +89sti3Q9xpDQuK25MCetmf8EXHfBvD9iq+eC+5BFAUyvAzx59O6fu6xAyfQGgOAZDKl
         KV798yg2NL52JuqUaa+b1o7Egp9lpt+OoSI1cvnDpc1p0KrsyhhpHRXPWZ/S5JojrwHQ
         Go4KSHsUIGb+54RwKLkxG18SQq+VtRZuHSUWYx4azKzJsV+zt2+ty4KEF5EIoaPVibyI
         Dk/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755501578; x=1756106378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F5KAl6w8WU7mn+4LBLsxKsoYRqzG/giURQyJX4eHW3o=;
        b=gh8Pgy7lQvW64L7WRVYAolJTWmbOjNQfmwt3W1wz/MXFCMhUq/aoEbijW+MKoAyJFf
         /C+kK5HSkeTc06JZC5HrqUqr3htMdU9Azqtw8Na/wXWbL562t+V+1JfHoYvrt5aafbM1
         lbcaFVMhVJ2RSxeB9T+S5PimA/ueW6yrrvZCoE23uLOBhwBTJeq41sJGGzT3JQFAa2+N
         aq10TW8QZ7zM2+oV7DLoNOTmPoR1e1oHwwsYQwESh+UOyCYb2TRpAsh5adNUV1aBqIr0
         Via0PLecgpV02K9/n3b98SDUMLolC9+DBCYxHeG95PFsVrUlobSlBkc8fSZ1vdBdidtV
         BhMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCUEHZ6oMUJeA5QlNqOQlVCZwGkSGdbJsIuJV7P0m0GsZTb6yLB7avL5uG/lirLTznRw8MgTbA==@lfdr.de
X-Gm-Message-State: AOJu0YyM/gxymadwI+I13j5mTDfDc2GWXWEwjVAFNBms0Xu4OyX6UyGi
	wYiMd4sdHoeUleXiqHECBDKtZh+rT9FGRMVnadUexLdD/OasjcEkFTMJ
X-Google-Smtp-Source: AGHT+IGaHsulPQb8EbM4a0CuDCj2H0mSeSUyhiy+2zwHwjng0wuMhVSN+nIsmsg9seC5vjXW4DkpYg==
X-Received: by 2002:a17:90b:3903:b0:312:639:a06a with SMTP id 98e67ed59e1d1-3234218be40mr14672395a91.31.1755501578078;
        Mon, 18 Aug 2025 00:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZejiqioSs1PDnvxasWxR0eVmgSqLBduYuBwdtUj1GTT6g==
Received: by 2002:a17:90b:5805:b0:31e:f3b4:707e with SMTP id
 98e67ed59e1d1-323265a9bc6ls3558376a91.0.-pod-prod-02-us; Mon, 18 Aug 2025
 00:19:36 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVYKEUh86qCxflIbOkf2fP0TvX+kmahizXTLfJ0p9oNzyobiAiHxhU5wrXb7/EPTUAstdBhOTCW+IM=@googlegroups.com
X-Received: by 2002:a17:90b:3903:b0:312:639:a06a with SMTP id 98e67ed59e1d1-3234218be40mr14672307a91.31.1755501576227;
        Mon, 18 Aug 2025 00:19:36 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755501576; cv=pass;
        d=google.com; s=arc-20240605;
        b=D/uvoqBM9PMwEwayxh0C/2uk3/8cuP421CgV/CaFeR8Ir1zpmK5tZ2Y9kMqUNHFp0x
         vkxBjJe9eEOezVq8YYbqfBcqOQr+Q247MBw5cjPUcyYJztN2QmwUaMSgYTYTVwMPph/N
         kHdD6FpZCwL2zO2ucufaBskwLfrsAKKEjuY5cYsQ2hW3LY3DrFUUrYoxps4AYN2ZczRX
         YG6AUVu1hQAHB1dv6n7Yk4aPwDxWQA0L3GULWo+P8V/7kSlm4K2hbD2C71kDrPj7w2ae
         KLMLMD3Xj6oOAVaym3vthsCltyCaD0vmJ21b07XBQ1/Yg50N8c7MCxQiCef7oMW4+P/8
         SJjA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=gqKY0MeuypYSfQWJ1mHeLVl/UhkDbaXtOdK+5KbGf2w=;
        fh=2DGScN1toeExjdl/Sr+btyy/Lk8U6PsAYUEuYD8OFhU=;
        b=OswZwr8tVfPp7UYrRSmdzAMEp9CBjw6SANq3d2OUEMEjsCEJT0vkn/PHFySgoGpIc1
         p/Oa00OUetZU3Fp0V9blEpjR+0IM8rw487F3/L4bi0leXiv6fA87seUGToJQZhHDyH8h
         PLp/skuS9z09Md9v8CHgPd8adAeExJQ615WAO2E+UfMj6nZGfhPheQg18hSZU9FiiT+R
         ecD6aXFplfGl6LZIoWbgeeKgsu8B0+VogcCemPKxffz8Kjdl8U/YXHCI2cOs6gSo5m6j
         wFn7sko89ue6oay9V0DL0+U6qQ0rLbiTMIVFZGXYoxe8rNhz/4aMgVqEW2n5gOsKzOhU
         q6Ag==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from OSPPR02CU001.outbound.protection.outlook.com (mail-norwayeastazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20f::7])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3232f4cbff0si311391a91.1.2025.08.18.00.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 00:19:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) client-ip=2a01:111:f403:c20f::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=mLI6nTE52DlaXtVCRQQmXd/1Q1W5Jv9GVrjGXla0yyyWsuUROJv118zYcVlvIjtAB6DeqHOUuEqkKHIkHzy5aPZM4RGm49pjdgENFfgf+cF94qQt7KCb+valQY0Qwec1txt1meiOIYy8zCOdZYN0HsKSDrbgjhdtjjsqMZyqoz74DS2kcgDv1aVpd87BQ1puhiB3SbLz6HYXkExgcfx5gahU5I6yPVGnfsz7bNULvJ2D8Q2TyAW1OLKWsd+f8wMfV15YnhZeiIvsOASCOY6XDW023iaGLxomRzF2OspNG3oTA4nWPmJlljFliu0depnL/luIRcH2jOEchoaz+o63cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gqKY0MeuypYSfQWJ1mHeLVl/UhkDbaXtOdK+5KbGf2w=;
 b=ednG2t08N7j1dgLJGWveAj5aU1AA4ylFSGTHofdooewohSC7Q/nyuOhNmtm2zb50YjYQt6rY8ZoOMwHCM9izTXc5xQcQWnatVxUnt9bigDt302gZjjuDN6LihIc39R+GxRvp2KDESlPyB/3nGzqxEXLr4wuCczCrHBaOdEMJabtlVFdiHkWqIkf9TLGOdlf3RYfm2bllcEDC5uxXpwpjbMIw8anvSNZuNAE/j+lLTZLtUro/dy1e0r8Dln41I8WF1b2B8EAQTsovFtZD/BAmcrEeZs3E1RlgW6YaMorJ3jm+ZlTrmPDnP9KHBBHa5TO27uFuuIgsPJlqW7z26cWFBQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=intel.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DUZPR01CA0078.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:46a::20) by PAWPR08MB8887.eurprd08.prod.outlook.com
 (2603:10a6:102:33b::14) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.14; Mon, 18 Aug
 2025 07:19:27 +0000
Received: from DB3PEPF00008860.eurprd02.prod.outlook.com
 (2603:10a6:10:46a:cafe::96) by DUZPR01CA0078.outlook.office365.com
 (2603:10a6:10:46a::20) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.21 via Frontend Transport; Mon,
 18 Aug 2025 07:19:29 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB3PEPF00008860.mail.protection.outlook.com (10.167.242.11) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9052.8
 via Frontend Transport; Mon, 18 Aug 2025 07:19:26 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Wa+12+DxJoHRe4YGTFp6OQcUnwCFRDVPW6vK7UETvY0o2woyuUUZz8HE5BQdYJC91zkVRKOr4/x9UEn7UcmKkbQp92WiQO/RTkgupOSjrQwJH2YDgvORxEsDzgeLp+rLXdaPr6qzEcvjaEn1hPkOfh0qFgXCf3/+9XYNb2KCAYAQ8F/xsx05tDZlZXENbpcjfAwtaJLb7mA5V6SMDoduqLyx6zUFjf9EkIZ5nvkrh6JWnDHDuQiM1AwWSv6Vz5OGbe7BCtI4MnxydeBt3ZxoGqxBeIIOhpxcVanN738Y6B3gZ8jRojrp0a3RGpulkOan++bb2jW3PqSscUJmDSq12g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gqKY0MeuypYSfQWJ1mHeLVl/UhkDbaXtOdK+5KbGf2w=;
 b=hoVB0yKQPuYS7tweuwEgRvRPOHWAFKpgYwG+l1sb4vgP7anmEbLoWnQaoQ5FSdGGqC73cyGdp++fQbH2J5FuU0o4xYCJGZDCilp/yaDaEemlyfKHVxhY1fgLFBRaI2f6EAWACz1Tu6QMUuX/EQRKtUftDTrfU5rR6WjGvh5MnaQxuq9n4MhZmjx8+ZRDgJcGv6Xe+EpbsIliWJC4kGU2ETzCwkq0BJ2iUa7iwkdIfGckgjcdgXGOtLlORjg4OKd5Hz8G/o059VoHZyTziaSIYwqVPYSmF45wIVW6IxlnD9MaahPTQ3xy/OnMfd4nxtqc347xJmfCFtclpTXpP/Mf6g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DU0PR08MB7439.eurprd08.prod.outlook.com
 (2603:10a6:10:356::15) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Mon, 18 Aug
 2025 07:18:53 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.023; Mon, 18 Aug 2025
 07:18:53 +0000
Date: Mon, 18 Aug 2025 08:18:49 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: kernel test robot <lkp@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	catalin.marinas@arm.com, will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, oe-kbuild-all@lists.linux.dev,
	kasan-dev@googlegroups.com, workflows@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v3 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aKLT2QobergBhExD@e129823.arm.com>
References: <20250816110018.4055617-2-yeoreum.yun@arm.com>
 <202508180747.PxkbPnyA-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202508180747.PxkbPnyA-lkp@intel.com>
X-ClientProxiedBy: LO4P123CA0604.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:314::13) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DU0PR08MB7439:EE_|DB3PEPF00008860:EE_|PAWPR08MB8887:EE_
X-MS-Office365-Filtering-Correlation-Id: d49688d4-3551-49a2-01fa-08ddde27904f
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?8ABSb3r1vKQaV6UzLO5SKo6rnDMgJtw7Kr/I0oa2INp5xX/JD8sDxOOZ3gZm?=
 =?us-ascii?Q?4KgwWKtDp0jE44lD1mZWyaMdZLEnW57jEhgwJQDM46ZOiP4PQHZOz2QCa4fh?=
 =?us-ascii?Q?1VKLHIdjPz4pu1ewCKzEaKi+r+4+Etb8EmzUeaspGr+4WDMqIy+B3KL88Sm8?=
 =?us-ascii?Q?ro6hMi4kvhZYKoz7LLj/DhaXu4/VxFFnxeo23c+zOoAQZ15ZpDTJ7YNvQJ+D?=
 =?us-ascii?Q?4e0Q6SsWw+tQRkHMjmhH5bnhdu1Oqf6hcu7RWmE9P7a24O641gfrQmYz/67o?=
 =?us-ascii?Q?dqZGz1/xKphkkDsxf55U32ofrYFQ2AhX3BzEFpJJzNl4W2EmTo9JDKWrXSsT?=
 =?us-ascii?Q?o6Z6aB4tTMpqHplpOGDtU859nBqA+B6B82tWNtdOYTp9ngohL15aNy+HFoTv?=
 =?us-ascii?Q?xiIR5DKIHpFHfaxrSqDanf59jmVzcK3Rt1VBGi7eR4TUt4ckcPx3+U7ymyD2?=
 =?us-ascii?Q?Sp903YvHonLHhmePxjgV/7GRbtdgti1NfEtnuAbOhFBoBRNdBpdp07ZrF0Sr?=
 =?us-ascii?Q?Se5qNH7+0hvcXCORlxvgUOQKYYwUMoozIOkvE3g/YHTJOhJAt4QeSBqu4GmM?=
 =?us-ascii?Q?MNTR7bJMNBd0qWslAWehuecGWebJ7DKVwFcZDlwKsOmsopeks03b5q59fxq0?=
 =?us-ascii?Q?rSDH9dz5gTu2+t0ZDy1GPBtTyx9tHDwCZ68UZQce8t7krHiKcMNJZTmEDtQX?=
 =?us-ascii?Q?QLok2N4Y08m7Vn76pUu1IZMrYl1c4cqOzmNt1amgqOkUIqMossAW4mreuqP8?=
 =?us-ascii?Q?Af1446u9CoIncuh390AG2U8t+xkONyAQHPcP0BX7fhi7kOlsl5OY7H/eOB/c?=
 =?us-ascii?Q?ugu0KjKr7cnfOFi+lsoX8oSv9iGgHhEUA1uQI4QvqLbH+1EgACZLwu9PB66o?=
 =?us-ascii?Q?CyL9Z7+PfGkOxsjXVKTzVJG2gyw6wxFmDspaNd3t7HSVpLx1oDNKTlcPkHei?=
 =?us-ascii?Q?0PWua5nRFZxhW0p+EP+n/wqjX8cDPNOLTg+Cb+fAFs7t6c11yPnHJVppoBIX?=
 =?us-ascii?Q?PRInW5T+E4BRl7wIdbic0cKffQtkd875ihbGaW5BpD1KZf0zt4EalsuHPiqZ?=
 =?us-ascii?Q?xtTcFejpRuDsyaDwQhrX4Pf/ckr++O/cfLL/tIscQksMH893yNL/zxCycuyL?=
 =?us-ascii?Q?5gH1houUk6W/qfPt0nDo71B5bUbS5BZ+mbPVRUP2feLeTd0o9kqlvG0me0J1?=
 =?us-ascii?Q?mzTl9X99UV+Jl/hYn2kfZ/8cOKN8dYyoAaHpyAM/rEHs7jhLt9tnPxJPsl5x?=
 =?us-ascii?Q?OtXnctod3WpgheZXBYsYTF/uWHuavVGNj9Qx35OOwQoik89cWpaQrTHiRYxz?=
 =?us-ascii?Q?yt8WTQ7tOrsCi5tZIt1vu+CX/qOs8qjPmzHBz7WbaWl2HwRr25pxffT/ST8i?=
 =?us-ascii?Q?riZbf7b8StPk4yzqiwFHtO4KOl6P?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR08MB7439
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB3PEPF00008860.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: dfd91b71-368f-4801-295d-08ddde277c75
X-Microsoft-Antispam: BCL:0;ARA:13230040|36860700013|14060799003|1800799024|35042699022|82310400026|7416014|376014|7053199007|13003099007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?6EInhdGRAXNsbi9QLuzgXtPnuuJSKqQGyzeJPo5yWWfmZD3libU4oiIl/6PR?=
 =?us-ascii?Q?tDsOnTArhr32huh6hShKre++GMHrQqX6B8kZsh+t6MV9oy7nB6v0dTbgT7J/?=
 =?us-ascii?Q?oUcGBwsvQ6zbUoz04ZJmXZxXUPRgbJbjoLKC7rolUtMXewjJWwpWMNZQMUUm?=
 =?us-ascii?Q?fqWzlMo8tlid9ouhLFhMnNNLQHdGWcCVeIkErUVOjulklQaqs7iLsgNE2xSE?=
 =?us-ascii?Q?2ZgLKpL9XOlyXxS5NzW7brXgRrAWTtUYSowLBd3YVm/IdOCV0sJMgDe9Ys3V?=
 =?us-ascii?Q?A625KilaFZpWaE3MHS8ot4xAPG2Z7LxJaGMR4fxJ5hymcKBGccGm23bXuNAB?=
 =?us-ascii?Q?SLJJEA6S70y66WMQLyzrQ1CVFnF/ZaCyIEQjLMoPFseP7G3Qa9V/Qvxcv1uE?=
 =?us-ascii?Q?4hXmAzkbpZnCZxphtvu6L15sUfeiST+1h+s2SBDgaUDlJJACI47tudQ3GoOg?=
 =?us-ascii?Q?W0nj11HNQUCf7m51fRTqPthBD19Lg0yTDgFTHHfMTooHzdF/9NgNlM8nG+EQ?=
 =?us-ascii?Q?pGhBqs3CW6UDq0jyezHftrz85Zj5QA32rydUF6u7YZUMqUXEi+1ES1hwahIz?=
 =?us-ascii?Q?hPTXcyUGV21BSHd8dW5O47YsiBqZHXaTIY/DVpOJoaG6lTyS+On1jEpBuXOQ?=
 =?us-ascii?Q?vmVc7s+mRWq4p5S3o9u6VwkyF4g+3+Im6hjblYa9MQqoEbg3ywNYOsvQ+rUt?=
 =?us-ascii?Q?yyXwAsmaJsHsDYbYCn22kf4iIM+W1YZH81/Ue5Ky17Cmkq/Vp7Zqxw2e9bb7?=
 =?us-ascii?Q?sFYm1O04oXEluXvo9/4XZ8j1xt+T54FhYEo/s6bIiRB9ujv4UMXWv+/GsmG1?=
 =?us-ascii?Q?GPvJYbQbwRJdNOkZzPZsduSq2rnkekbcWKeuRf7QPfoJPPCnUWejApzD0Hud?=
 =?us-ascii?Q?GOBHtTpAjbKnZcfwvcKcCW50ww/2sBjojwkdGOaKhodZ1lTTJar5dhIWJ1ZS?=
 =?us-ascii?Q?3IJDw0TShyzStim9UhvgJ/SYyZVGZ1aOCjFCg+ty3LvDfQvIYZdLQv8IpggG?=
 =?us-ascii?Q?Kbs5yjBxypWudz4TOdImCiqWKuE9n9IF9yLz2BkRlpUC7jlQymLiiTQ+okF1?=
 =?us-ascii?Q?leFU9J5BQRU2SyZsjd+OU6P2FGHMcoPxfjMBl+dOGqjwVWKiBbKDYs0iR3/N?=
 =?us-ascii?Q?CGE203ci/sXGkTkbTQICwnHVKm9wt9EBi6DGFv0BS1yL0mWhesC/vOk6khxS?=
 =?us-ascii?Q?kzi44ywWkvFeEjqLjKb8c3mdHpb47LPHEjGNi8mLaRahWtuDnPXTfYlxPHuq?=
 =?us-ascii?Q?ac9wMEYm/VPM6oGABUZq2936bAuR/Eh5XITc+utybbRjRO+gevXzoNNgPLVj?=
 =?us-ascii?Q?7VtChYgtj4YFSsyPN6EBSCPE8hWh790oxwqy8e/YCiexD1HeNAddS7UKwhf0?=
 =?us-ascii?Q?1Btk4aVGWeA4lEl01Fp7CDC3FjAxsENaB6yqwP9L/ebw0NKlqPGlKeQNnAmf?=
 =?us-ascii?Q?hBeCyUdl7IE58SsQ5ADU616uNZpZusdGsPcXXq9ltlziHkrAZiJedg=3D=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(36860700013)(14060799003)(1800799024)(35042699022)(82310400026)(7416014)(376014)(7053199007)(13003099007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Aug 2025 07:19:26.1638
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: d49688d4-3551-49a2-01fa-08ddde27904f
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB3PEPF00008860.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAWPR08MB8887
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=NHfsh3XT;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender)
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

Hi.
> Hi Yeoreum,
>
> kernel test robot noticed the following build warnings:
>
> [auto build test WARNING on 8f5ae30d69d7543eee0d70083daf4de8fe15d585]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/Yeoreum-Yun/kasan-hw-tags-introduce-kasan-write_only-option/20250816-190300
> base:   8f5ae30d69d7543eee0d70083daf4de8fe15d585
> patch link:    https://lore.kernel.org/r/20250816110018.4055617-2-yeoreum.yun%40arm.com
> patch subject: [PATCH v3 1/2] kasan/hw-tags: introduce kasan.write_only option
> config: arm64-randconfig-r053-20250818 (https://download.01.org/0day-ci/archive/20250818/202508180747.PxkbPnyA-lkp@intel.com/config)
> compiler: aarch64-linux-gcc (GCC) 10.5.0
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250818/202508180747.PxkbPnyA-lkp@intel.com/reproduce)
>
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202508180747.PxkbPnyA-lkp@intel.com/
>
> All warnings (new ones prefixed by >>):
>
>    mm/kasan/hw_tags.c: In function 'kasan_enable_hw_tags':
> >> mm/kasan/hw_tags.c:433:21: warning: comparison between 'enum kasan_arg_mode' and 'enum kasan_arg_write_only' [-Wenum-compare]
>      433 |  if (kasan_arg_mode == KASAN_ARG_WRITE_ONLY_ON &&
>          |                     ^~
>    mm/kasan/hw_tags.c:435:18: warning: comparison between 'enum kasan_arg_mode' and 'enum kasan_arg_write_only' [-Wenum-compare]
>      435 |   kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
>          |                  ^~
> >> mm/kasan/hw_tags.c:435:18: warning: statement with no effect [-Wunused-value]
>      435 |   kasan_arg_mode == KASAN_ARG_WRITE_ONLY_OFF;
>          |   ~~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~

Grr. Sorry I think I've sent the wrong version.
I'll fix it.

Sorry to make a noise.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKLT2QobergBhExD%40e129823.arm.com.
