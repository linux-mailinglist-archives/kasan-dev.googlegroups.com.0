Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBNMF3DCQMGQE7TCZDWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 0488FB3EFB6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 22:32:11 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-24abc029ee3sf15487895ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 13:32:10 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1756758710; cv=pass;
        d=google.com; s=arc-20240605;
        b=krScT1LQXNw5xaTDVlrtsjR3RDphfzWzRYn48KMh5VyE+1fkxFN37pM9NiLgsPld1l
         u6Vrk9CpsW+QHfrmTqQUBQ/keMlr5ym3kEBu49Pr0AZ4JXI+VGRNsgnbyeJNi04ETlYr
         tCWKlRWIBhIY8uCAuaapbCuGKiiPVofQ7LSj/fhXkVN3mN6vxzWeWbOs76N0kvJGhjLf
         AmrRWs7PvENl8RTKcjdfdDjOi5rnyHeqv1L+ZDysyCDEkCyO5G/dpi3mWsp4MlAMnkX0
         Gfrx4W/4KlToy/wGLLm+HX0RSWwtQhdlkZCPWL0LOntU8GUi3sFcOhwa8Jcdf3LFqc2U
         wIxw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=RZGsYf0ruLwUt/7MswgHGySFE5WlS9jG7hJkjsFk3hM=;
        fh=PIJGl5vanpNhIAxnqwBer2YPL1AivrUkhfdLDP/W/ZM=;
        b=RMhUdQFPearx/NheChnRJrtOo4SqJYs51KRL7N8CANLh6EHR7cbXdiK4GzodcjPA87
         TZ0zmWiy8cLDMjjwxpIxkWjVKSNks++ELDdjU4IoKtxYg68ULXF4j5KdkpJjgVrbD2I/
         k6cm3McCWw3qFV2i60FPXid87c5fc8EEm2kwwGzO0M8zs//4S9oDikOLU/5UZvYes/XW
         tiVa5R0ijYnUpj5gL1zxPh0Y88wrSpMj42XnSz0OrTC8s2MDJ6YKuj1vlJd36SBFEQpd
         L6YVu7um330X6UvVfBd2reNMSsQdfsM9yxyh9zplpjBuX0/EpZgwolQGck7J0Vddn2QD
         s0zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756758710; x=1757363510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RZGsYf0ruLwUt/7MswgHGySFE5WlS9jG7hJkjsFk3hM=;
        b=vE1tDATYIDhiLQBP62cQOqXo8NA69j09G62oraCRdgEtiHcCQEnmdFnVe98kHV08bG
         yyxQhguRoENzJEhxPTxx/9XjEtsCnEBGEMO5h4sHyKt0B+6u6BsWZThTAdjNWlpHVx5x
         5rwdfJLGlu60jQxqk/AwVhriEpgkXvBVZMUFzGmvH+s2NG4XfBG5vbMv3mmcjFyOIqXL
         reJ0DS2ia3/NWtmFVsUiklAA7GPsEb5bDL20Yf/McD1wEAaE1UIE/lMAiycqLFIScVs2
         9gwRjiQikJP+qCjCAge0l8YOCHtVDeIvLVtrcE/OIFVioQ3OrBJya4TYVESjcI/Na76f
         QRBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756758710; x=1757363510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RZGsYf0ruLwUt/7MswgHGySFE5WlS9jG7hJkjsFk3hM=;
        b=C4X7tgh7BBLZsYpEjdif+Wdho4eSOrN8gzzWeqeM0nyNtzi7j78vEZJocYLnJ1d5EQ
         W+y6GgdmsiEIK100fg/LX3J/xG3p40LtfW4mvfVRZXerOAOrsXo9FoM4tAFkoXGjWQZM
         oJDOSthuqUBBj920mnctZgluBxV7T841CSL74rxBc6/S8PvgjTRa8laQ/J5HvYMiK1hk
         IR49DNsUg1+UI5r6IdEd4S6r2RlGbv4nCFhTYM8zxjZmDV1gfCqn1NiZPmNF3qQwJJLO
         LXI66GDTZvczHkh2LwQR5NwWVtWppWYx/qX19dv7sveZtXT3jExsj3xhkY3zniaGYol4
         eMfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCWktrcQwpYKUejR6ew0Vxi3cbHDk5XTJVXJrMRKMwJL63L6s+8EYLeOWEGc84x0jlXUq97JZg==@lfdr.de
X-Gm-Message-State: AOJu0Ywcepod5csocniLFw0mzwDQkF2XsFB47CE3x932+7RYFhJiTQrs
	hGYFOfLqNgQzC+ONWB8x/o2X2OwzcXRC7N/QKKT2OmQVQIh11iItUQtF
X-Google-Smtp-Source: AGHT+IHDHPj/398YytcwOH9sdlEVv+6VD8aiQM5wz156Kaowi3rNNhnJeq+xi0If+KBXBv/sWSgTvQ==
X-Received: by 2002:a17:903:2a8b:b0:248:fc2d:3a25 with SMTP id d9443c01a7336-24944b0da8fmr131209495ad.38.1756758710093;
        Mon, 01 Sep 2025 13:31:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeHlogoP/U8pjqtB1+yLox+DIXzRIdZZVe2UXcZzxMo3A==
Received: by 2002:a17:903:2c06:b0:248:87fc:1545 with SMTP id
 d9443c01a7336-248d4b1b733ls47874015ad.0.-pod-prod-01-us; Mon, 01 Sep 2025
 13:31:49 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCXkHdsaRY0B+Lg621Pr6VmErNnrhPnOf1rGdXxrRTQfzID9bUFTdUHq1c538m1DQFx9arNI9roi848=@googlegroups.com
X-Received: by 2002:a05:6a20:938c:b0:243:c2e8:f4cb with SMTP id adf61e73a8af0-243d6dd0ce7mr11672381637.6.1756758708803;
        Mon, 01 Sep 2025 13:31:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756758708; cv=pass;
        d=google.com; s=arc-20240605;
        b=PfQ0cgi4Bgw6x4GmpqLryniDXc5793eMnvDUk1N6CXhxGmyHKL0W/EtZ39S0Xfq+mu
         Admwxd5pYYBy3EoNlWRnC4kroIaiU+fn30sXeRvstLwx4WKntg3BrUugnq6gSFPprpsc
         LG4cfOl3q1o56OWOWhFKC2+KpPrOamFva1VSeDAfeXjWl6ahfMfsfEa92phVKT4sJhi5
         Iu5aNKWC/OfrbfrUYoNhM1pjUGhgQ4D6cHCJbQ2B/IRNTZUI3O4E6WxKGpSVoLO2lI+W
         T2yql5NxjSlEWZxLXlQw/eDocmF1q7zk9uP/I0izxZwK4p5zhBzNze7U4Zkh/V0B80Tn
         nbPQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=aQ2x+3MS5gDTxu8o3VSwltrsVoMV6pB5dJN3oNHyH3o=;
        fh=Pae71PWaipemfd2rpsB4L9rxML3ymU7+ItAO+yKzrXo=;
        b=NEgLeiBkrsRPgfb+ZrcuJpheg8IAi9XyanzLq/ORmQREwKCTECwnn6//uqltJMDDWp
         XUeJtNzoVMMsFzaXZcdEpxf+3pvaQMtQaD8JSLhnZEJ5Rl+HMm9SdIxc0oKZnBIymd/U
         HzX+NZUyFuGtr1PyrCR2VnqnuUtoePrex5SNoy5p3SXg4fn91AGKCVLlcrbTn4DKwsmI
         KzonlwqtR8TZD0FFerQtD24f6loxcZLicJoii6rKZKWpeE/NiIfdI6WwGKrMzP95Kx1M
         pCmBJWr/XH9jLs2tsnNQTWmSqoZhfIe1fhfL+mqljoCd+e1I1fvT9cm4nDpg+jyUqMXO
         vz7A==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from DUZPR83CU001.outbound.protection.outlook.com (mail-northeuropeazlp170120005.outbound.protection.outlook.com. [2a01:111:f403:c200::5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327d9f423adsi505389a91.3.2025.09.01.13.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 13:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) client-ip=2a01:111:f403:c200::5;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=wJ9yO6sgVbQSCeuSwi5RZY/fflBjufDVtR0CP0Jkf2o1fvEn6QOhSiL/cGgSdEvzZqZCT3C3oGCLGSMum0NgDZXGZ02a5I8w7sYOJjJiACcZnqAjFJ0RSHYmwnr6/SDnfwepQH6my1mRHTTYY4BWWobvg5kstrnSwNDik4xUPKn7SpimlZW2mrXo++PAbMtjT4AezDvqWx07MVKGBH6pUjv6YGckrYvKeT1RDr+D+hv1sBVWjaHhe5FcpqMgzZsuQNISue9QwVcZFb7FXGuTRMEU8Tc1rB1uSPXN2XWCDPp2tIRugeB7/EpRfiQ44fMBpw9ANgvQPArQc/re6gKxyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aQ2x+3MS5gDTxu8o3VSwltrsVoMV6pB5dJN3oNHyH3o=;
 b=pZa0TMIfrEHOnDRvOvkuL7LYxwTG2FJORkHuD7xxENQ8YNBLnJnOkTy4cFq/9xLu31yx3l2FvzY6PHkTtYZzSBTzkvR53jvHJ+aqseufq3+6JjbKbYdWHpjjqSfJerGdQSLQMv0x5JSL4tJKJJ3eavgMQzMXYkxW875XByEDfKj86Y3rcvmW/mPjli05Mdu7aO7VW9ZQ+Y5QMxZBv7Qb8mu4Mk27h3rqurdPRlp08GCajzthAVjP0vvpC91L684miv+q1SrZUIjkUF7kUhodw6N8IGok/nQe5Hn8+hpUPFMXUINkGYUDRUpxJZtBM++AN/GUw22l3tRhmsDV370koQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linux-foundation.org smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AM8P190CA0024.EURP190.PROD.OUTLOOK.COM (2603:10a6:20b:219::29)
 by AS8PR08MB6264.eurprd08.prod.outlook.com (2603:10a6:20b:29a::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Mon, 1 Sep
 2025 20:31:42 +0000
Received: from AM2PEPF0001C711.eurprd05.prod.outlook.com
 (2603:10a6:20b:219:cafe::ca) by AM8P190CA0024.outlook.office365.com
 (2603:10a6:20b:219::29) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9073.27 via Frontend Transport; Mon,
 1 Sep 2025 20:31:42 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM2PEPF0001C711.mail.protection.outlook.com (10.167.16.181) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9094.14
 via Frontend Transport; Mon, 1 Sep 2025 20:31:41 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OsbY1qLniVFJfT19teZWxfoIvTi3PCiF1TOjppICSy8Z8FxcbRbNhj99IXf2BkrdKLyvHKX2rTkz7AU98zI8gXd8WNzwUyk4A2smH14cqJcmEld7VzrVIEvJfQq1TqAOIXGaMimKVwVM4uzaBnt/Q9tmE1VuIzIgCEVfSaIJ324OK+dxKUrQPBCnETfwPUAmDlIbU5Vy/aQ69BdvfS8n/PiQ13f3WvejzqWGv1b6zqUGqdrekrCyZW/kXm+2mIoLdd5fa467haMrWaPawGj4Rqs209+urFs9utXNaI81nWbaSI+3AvIcY6u+wU3YN1DAYRV+aSKTMc2f4e32YAE/mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aQ2x+3MS5gDTxu8o3VSwltrsVoMV6pB5dJN3oNHyH3o=;
 b=gimZ21igAOFvrEM1o0N8zOFTC6NZh1XEehVbPMHjZGYuVGhjYXw/2SamXVKY2q/OAnK6odC6W9X9hUG7O/DYRj8VZmS0BvpstwSzdiVJMolfWco7S6l7IWd9VvdFCbQCoQh1cH/5nkdWamnToAaCXYF854yP11ro37lEtSO/RhcTcF18/0epGf5LbVFmS7GpjxI1IyUNUCIatY6G3v3EZjXPDjgSCaCO/BF83HNh4knZYRep2pPtV66f/OMKqrA23vfsOZJrTTKVLSy5LkFxY7IjCc/MFuc2jghzXcIW0uF3gx009qBNBC1oSga6UdM+oH3k2F7mZpLXlToYdSg+Hg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by PA4PR08MB6032.eurprd08.prod.outlook.com
 (2603:10a6:102:e4::12) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Mon, 1 Sep
 2025 20:31:08 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9073.021; Mon, 1 Sep 2025
 20:31:07 +0000
Date: Mon, 1 Sep 2025 21:31:04 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	catalin.marinas@arm.com, will@kernel.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v6 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aLYCiE6lGlIkIJX+@e129823.arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
 <20250901104623.402172-2-yeoreum.yun@arm.com>
 <20250901122316.6b7d8d7fdcf03bdb2aa4960a@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250901122316.6b7d8d7fdcf03bdb2aa4960a@linux-foundation.org>
X-ClientProxiedBy: LO4P123CA0372.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18e::17) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|PA4PR08MB6032:EE_|AM2PEPF0001C711:EE_|AS8PR08MB6264:EE_
X-MS-Office365-Filtering-Correlation-Id: 8c75e5ae-5eb1-4fd3-a9b7-08dde9968f3d
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|1800799024|366016|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?qVWHHSMqV7xnFfvFuePmwQobxJ0fDBBNs2LTo1iXKox2tGScR5n1f7p47/qX?=
 =?us-ascii?Q?IbElvk8EzBVqOEJklZq2WDnjG5IDnmziNebY0ofvXasQVzDHdJJSqqlVBuYg?=
 =?us-ascii?Q?XyLFsvJSZgKvK7FK869T2fbxQBQ99mvtxyjI5r2Neihs4DT3veNrxc+upz1c?=
 =?us-ascii?Q?C9O0UJzzWBjeXKDXp7kfHWQVnRrjDe1IN89KdI1xtzOvsuUQGUztKnW+WqKE?=
 =?us-ascii?Q?unfKOno3St5q+FngmmCOnLDi6tyjky1cooOxNZPfTvwXjSbo7SwM7xfFt3En?=
 =?us-ascii?Q?DCwOObbUTdSu57dcMXfvNkRr7WzeGe522aqtJ2fAPpzjBso8aQlLTmCruqHp?=
 =?us-ascii?Q?gPshAebmp92zulndtAtOie1Xm2ZJqE9J1f8SnVCXRLGlL4Vh0w5352500fnq?=
 =?us-ascii?Q?wsFzRTfHIY4PSDT/v55Ffbr5T5XvXlRpP0YfzNiejbZPdeuYTgxpznarnAr3?=
 =?us-ascii?Q?eXYIqeCtjyW5FKsyMKpujPXrMOPZQhL7U8kSzN02kDAkupSgYJVPo/O11Nap?=
 =?us-ascii?Q?2n7aBX/yUtuV0h1YZy/oIldryj8bEeUA9CRXwUEp30AUDz7umR1PS8Ln6rwA?=
 =?us-ascii?Q?low2+tJ5O4ArwwPh81y5G1YWPKVzjCUEwIpQpmGZUN8MYEzQLaj4NIpsTxFz?=
 =?us-ascii?Q?KKWDQhk37xlqaJGciJF+2TeVVREgMw9M2QitZ+t8dpWvxMlXmYXVgm1qaJbq?=
 =?us-ascii?Q?48I1HlVsdYb5h2koYww51rx9WvsaOdHOWvW6NdEteSDnOqsYqtsq5Dg+wXcR?=
 =?us-ascii?Q?VFNY0udw44CeMWEOrxL4C2VYpgu06sC0tM5Edmf4z4bcLDCMmb2JMsTProlF?=
 =?us-ascii?Q?d1nHw6vKJEH4b3/DYt/7q7ILDx8XpEeE26EL9CanM2liSJb/UCjOoGbqoZP2?=
 =?us-ascii?Q?fHg9WEIv8gCJZzkfsoKc3frkvisvlGMra/cWF1BKU2NNS84+m9GTiexwix0R?=
 =?us-ascii?Q?0XqePG6AGuw7pAcEy3jaBgpOVFNiNyvdss2b3M1HPM1H88ulLZLpGXH6swjG?=
 =?us-ascii?Q?iNmVQvGmz9avciqsvXAlyqxXTnPFDJb9r/W2WWCmnJE6+UAkY9s/OTa0rl3N?=
 =?us-ascii?Q?OaRyA3OqyZ1VEcuI703V7TSAFKY2aEPi10OlsAfIZoDx9oecVCanfsmtneA+?=
 =?us-ascii?Q?Ncf0PkzCCd4jiniGsoacxkrrF/us0RRVoupBwL27ysltH0+MGq5m5Q7F1lwS?=
 =?us-ascii?Q?JLuczMlAK8CAQm77kvPC2R74Foyv+gIe6zDW6+NTZm5wmuZBgmaJBxPa0aLW?=
 =?us-ascii?Q?gv6CSotYMR+pyDAoFrN3jkPBbXlHE8OvGviL5Y5zVBMN848rDdWqoubjk9uG?=
 =?us-ascii?Q?NM7o6Xhr8oLlfBgGvogK5+gCOMJ9PcPvJ8u23ZyCd8Agm1Rjg2bNRdM4lUbb?=
 =?us-ascii?Q?Od6ddzqfsOJylYf2BGQbeu9ZwLmQeM+EVk0VY13BHgSRiiilzqhEvUmJGpwA?=
 =?us-ascii?Q?QxHMJ3eWQ7w=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(366016)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PA4PR08MB6032
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM2PEPF0001C711.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 9acceecf-0116-4269-693c-08dde9967aec
X-Microsoft-Antispam: BCL:0;ARA:13230040|14060799003|376014|7416014|35042699022|1800799024|36860700013|82310400026;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?uRoGsnXionhzUX2Bo+Mv/Hcd0Wc8LPIi+GneEN+KvDzQ3UIYUkGMnAcfwCru?=
 =?us-ascii?Q?VU7qVYUYN1zxtSsnxvRELH52YBo3UEWqkFgHvddkx6YUQ0xAz91YoD0DfCKA?=
 =?us-ascii?Q?+57UMd7EgB+vB52r9LYcoK5bjMzEO1+Zffx7duaJuyiZghLG4mcjqNPUPRCU?=
 =?us-ascii?Q?au0KX03VY679cLYKu5Huu5Cys/rWlYrZxnPARTfrQz5s4faIneaX3wta8yEk?=
 =?us-ascii?Q?w0h0PXHRqe2vNS2bAq75rs3wIVCq45kcpDjI2vytnOGzhpt3/MT3zJECcaNb?=
 =?us-ascii?Q?LLFcucJuhIRvbViUlWgn3XoUa5HZUTrDWLoV0ng7j6XC1dYjDu6cqupeCpjY?=
 =?us-ascii?Q?8i8TmwQXmUd3Aejr0cs7YDkMouQFZBLlaUAV2ekDWjcEYNFq7ms11Cpv4gKc?=
 =?us-ascii?Q?WY6/kkI2bqh+n7E3LaBEjDp8Y7kaY9WWHa+gqyt7icu9plS6ZBwvfAhqQHPh?=
 =?us-ascii?Q?2VHLTjh4Zr/tN7VRMcPDnU4n5kybivQnkKaIH9ARfZPNCIJeK3SyQUnDpnL4?=
 =?us-ascii?Q?dEr+kjxLXgjjsMtLITAZh2O2A8RCQs1ySYwYABB1Gn7fqq2EUFAOHixd8mQx?=
 =?us-ascii?Q?MQO8hq0EorvV5ZvydJ/3ozbPvKVvQ9m+wH/3L9oMuopPjmN37x/GLv83J4cO?=
 =?us-ascii?Q?RUIvLbBpzYF+kE+/xc2QnnjEJVXxECJIWUya/2qm6Ln3BIcevJe/Clf9CBcr?=
 =?us-ascii?Q?fx0tq53sdK/YkP3siEm7wJ8h9D/iIJVsz/c/OKZCwJDc7UBtKRmExbE2TtOW?=
 =?us-ascii?Q?+PJbe8qvLiv5EVXDMz/LKJewTz1xuwpoUHgQpPZ8ttU1CcNazjeZ7iyN0TBa?=
 =?us-ascii?Q?vCi5tvan5ct/0cPrz8JMcJ0KUOi6mbH+RQfPTopYDls28VsW3/MWYU5xj3su?=
 =?us-ascii?Q?iAY+UNxpeVQ2LBaDFPu4RAZ8P9VgFGG2hihoBfwrmhS2vNyg+3M+sBSKHNGZ?=
 =?us-ascii?Q?PPwOrBwcN1jIajHU9Mcg8EzSUp5OxiIxBhv+UpY6lcNF+rwSbg2ouaXQS3QP?=
 =?us-ascii?Q?3FwTnpfo3EFwp+5XY5LdHCCCqFkJtJsfp4bt7zOoULM+UxPlT8tLGjI4HTma?=
 =?us-ascii?Q?K5Wg1jY9EkepnB3PnYgYtaDKBoFD0rd7Lo5WPwlaQYrXhObF0oERCbUCjs5T?=
 =?us-ascii?Q?8SBXMe9171PQ6l7fF449F1fWSH7V32q0c+QgIsKAkxbxOCbl/4J68SuvX1zx?=
 =?us-ascii?Q?tseO5ualJq8GirQ6gIP5a5juhC0Zk11LUTq0MhF33jvGCkw29bZkQsreVVK1?=
 =?us-ascii?Q?j7EwVPz4xz6qrQGEs8WF1ysyy/wwn5JzOEhAcnsKpXxwck7SUaQ4kDiWs4W5?=
 =?us-ascii?Q?E7TCPkO/l61okGNvP6Yz8i/ekg1OzhwDEoyFMkI1KY3dfgcTs5Z7s32CdfTd?=
 =?us-ascii?Q?m5Q5f7WGiju79JHxFAKnVjpU3PbogUKSUw2USluqDXeve5itcgT5Qz5Hk2rT?=
 =?us-ascii?Q?NyhGfQvl5+QxS9wbazUrhjvUV5qIXVQqPk5cgNEU9VFr/t9jXrBORqfMuMrx?=
 =?us-ascii?Q?DXwN4M5xXcN22cZINlyRrNiqcSydLZHv27Yt?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(14060799003)(376014)(7416014)(35042699022)(1800799024)(36860700013)(82310400026);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2025 20:31:41.3157
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 8c75e5ae-5eb1-4fd3-a9b7-08dde9968f3d
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM2PEPF0001C711.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB6264
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=WHx8Pr6c;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender)
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

> On Mon,  1 Sep 2025 11:46:22 +0100 Yeoreum Yun <yeoreum.yun@arm.com> wrote:
>
> > Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> > raise of tag check fault on store operation only.
> > Introcude KASAN write only mode based on this feature.
> >
> > KASAN write only mode restricts KASAN checks operation for write only and
> > omits the checks for fetch/read operations when accessing memory.
> > So it might be used not only debugging enviroment but also normal
> > enviroment to check memory safty.
> >
> > This features can be controlled with "kasan.write_only" arguments.
> > When "kasan.write_only=on", KASAN checks write operation only otherwise
> > KASAN checks all operations.
> >
> > This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> > ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> > with other function together.
> >
> > ...
> >
> >
> > -	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
> > +	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s, write_only=%s\n",
> >  		kasan_mode_info(),
>
> This lost the closing ")" in the printk control string.  I fixed that
> up while resolving rejects.

Oops.. Thanks and Sorry for my mistake :( ...

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLYCiE6lGlIkIJX%2B%40e129823.arm.com.
