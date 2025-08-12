Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB5XE5XCAMGQEMNJ32CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 45790B22E5E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 18:57:28 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-61996c91264sf916058eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 09:57:28 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755017847; cv=pass;
        d=google.com; s=arc-20240605;
        b=lQ6846hwQRZuaNzqyqLZH8qiEeyn9J5H41caEYQ2lILjo5ZR+L7CZUu6bhJPxNme5X
         +qVWHpP6o72sNR/6lSCbk+VTrX2Ue7baKuIfMa7MUsEkxVLRWYa1Xc+0pAfCsNFFDFpZ
         i2w4d6pyWk2pkyZuwFod7It1PTuWjrWk5dVrvh1xWKIei/rdkpZQn+PKmVH8V4M48IZF
         rtngex4PrORMIFCEf50Zk+UhfgmgeibnMaQFbzY7y4Yvs1/U3f4MxZIRmEBzRomZR3me
         I+MUkPkFwIw8c/7VT2u1f8ih1IxdmLGN90bhyBUrYTpljiaAg/Fbhh80BJg93LVGSeuf
         19kA==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=C4yuxCXkzXqSxrsC+HdblFzipvIlsBAeqnZzASTESEU=;
        fh=UKjeHW2DQHpTJi3ZI/wQPHi0Bk4pCgfKCMLpYzChbN8=;
        b=KsHGDyvj85fEfr4XF8sMUqhGN03VlqifUFuU/rSY3m6Z7c15FXfYLVGtwRcmG8c7xj
         GV3rS0QzDv9KxVcxa2UB1k26Foxk2UVrOOQWa5WVXxc71SWSBrBMg3k6F1H8vvKQW/OE
         FA0UG/aJITKEIKH+AZnzGX1fEP45jR7iYssOauf69mfB/9+oTYKtTBED5TG4Rpcru8m2
         Eta6yuhselr15+N5raaBtQo6kce3fys+wYsQETlK/j7QmcIhDOwyO6IyK/cUPZ1XQQwx
         DYseDwDOPZ8jCGGrahlY+ZcLUFqSEmtCT/ylpIswFUlj/DNsjRFxOQMBGGb/+/yd3RbD
         hMeg==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755017847; x=1755622647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C4yuxCXkzXqSxrsC+HdblFzipvIlsBAeqnZzASTESEU=;
        b=uYSOdDWrKVx3Q9Tm/28n6RY3CIdcJCWoeEupBf8rEVItmAwg0KiwSRgFHDfS175jyQ
         AsCD+yt/uYbuC98MfwIdbnioYBBbnTJqPnTYsQ9zpRh7NM03mogyZ/vWtH3JJKm022wQ
         4XQS8TU/OoFbifun1HsVEazmsz94s0dHDX++/oxbYoytoDNGzqwIEv/YKHNWPdlfZRTs
         DKOEYW21QBtKBBBFH7myEeSAMR9Xn/2qPTo8291ySXYU9yLfRd8PNQgSCCsh7AeA0EVb
         OS7mgA4JR7GD78CQqTg3CpNzLcR8gzZ3bNTj8RzHZaKGyVNSKnPZq5l1IdDlYQo1foji
         A7mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755017847; x=1755622647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C4yuxCXkzXqSxrsC+HdblFzipvIlsBAeqnZzASTESEU=;
        b=GqiYgXoom5vl4C54tiXcbLb7/fYmNseP/MyT76LRw6qEQqQHriNSWCcM+NSIRiKAu1
         2xS91bqVZnblT0zyLCGCSd8nGru8WV5twencx0/7yCmNru42sg7ZYLDziudnR+c6Y1l0
         dSLJlUX+YmcfaSMCgcM40lVurrpTwuDLl50vtC8P88CtmGys3PE0HJZ27BiYWgp2Z4ir
         VEpZpGzqDfurwEUm1FIm48RdJAoG6iwMj3YNYhNIERHAC3H8ezQusqDIZm1AnopKW29f
         0G5MF6arkDZSRO4aCV6Qq63LbV12bgzK/9t89vn+14XYUit6HNJEG03jGWnlMzlyAz4r
         +IIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCUt7VHsNWGBo/0ZOWquMtMhM03BzlSBS8iLzzP2h8jnkZ5bHhORyTzV6Ymj+mZMdTNUKtfppw==@lfdr.de
X-Gm-Message-State: AOJu0Yxc+cVo/LHN2TwEJC4nSrj3KRS97AqKYykd6mKkYNk0HrNQ8FME
	DlV6Wrj+DAFVFmEaAy6FObb3jumnUqvOpeyZKWIfomuX0cZ+CCAKs7VA
X-Google-Smtp-Source: AGHT+IHHRGKTxHqpsicDPfbIPqnlTXQZl9LcXy1nS3YJ0bHciwDsv4XzU21U+gFTsbnSB8W98ZC/9g==
X-Received: by 2002:a05:6808:8284:b0:434:d39:63bf with SMTP id 5614622812f47-435d419d2e5mr16537b6e.14.1755017846744;
        Tue, 12 Aug 2025 09:57:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevZ32kBnipjlo9RUfS8h1qf0d/Nqej925Js2jBMCg+Aw==
Received: by 2002:a05:6870:1090:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-30bfe351b2cls1819955fac.0.-pod-prod-06-us; Tue, 12 Aug 2025
 09:57:26 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCX00FNIRScxM/H/bBZL1t5c26GATXBRUJbfpNQWX0mPqOtne/AeBhWXdCzaFfYirasRk3xGwJ1Ibmo=@googlegroups.com
X-Received: by 2002:a05:6870:4413:b0:307:bfe5:481e with SMTP id 586e51a60fabf-30cb45aa116mr99588fac.27.1755017845802;
        Tue, 12 Aug 2025 09:57:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755017845; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZUuct8lcCSHLdEz4KOe3S3aV7CLnjRYF4BhZT63WQe5BtrBE7I/TWBxrTrdyc8E1ex
         eMllrsgwX1dTLQy+Y6k15+Om+JshU3rl8wtpn3v4f1ComIzNVta2Y+sS6pBntxa15sqg
         ywrjr2uaSG+JqNgeFrpAoXSIgv7YxLpNSk19BGeuuHzWVIEiB3eeE7RKKql9M86rFq+J
         EJfgn/dDA45wXnL6nnAoSyzejlkaVg8zGJhgzZ5gVpYkikiaXaNtr+GEj+uh2cXE5zm6
         EF+U0w29m60dIV3vxJnn6zVM8BE/4WgWwVoXA2k8ou2mU2ifY8WyInf4De5mYViv7/8C
         IQnw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=TM44Cf3hg5taaGacOpIErY7NmByAGW0Uqap2daYIDvY=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=NTXLcpXaHkqk7fGyealfoTpBLO+xQweMw/MMOPoyamiu+u1dq6bJAl7EDPIBVYE4iP
         EqMnXy5ZOnzdMCMf0zsdfVvzEZQMV0wB3g7fab8//PGFvbIW1gr7FidEmetUJlhf1WCv
         ME+WnsYrzlZl2Nz3AIYFLHkAH7BkhTEkF4X9fLWrcovjGm7FVGj54UTx0oFXFZe6xbag
         WffLkt8FcOSxmQ+kMVUi1gqzCblVNsQuafN6GwA5wO5O8tc4wNmWBqbNWW27oxlelUec
         KscyKhPBTd36ZO0MxW0XHLpjsX0VuMCc//nTzz2spZYTSw6oUjaAJtppMQpyEn0h4cqE
         Htag==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bbf723243si914878fac.5.2025.08.12.09.57.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 09:57:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=Tv5ttJ+hCXhU6M+I4cleut5hdm2hDMmPW3qqNuLFP5S5XaoTP9zcziSI+hD75SturWQtt9v7SUMU4xc3qz6yYdF/q4TS8nELaYReHXMaItFr2rHdW3Eh5Z8s+gQS2KWzcXelz6W08YlBk4bEAx84cF0LBgK7686Y5rR0Q0hSYYbRHMw3/S1Att3zr64eGCj86MkHE24h1lUyXFtInZQxVrdqydS1syz7gdXXTD/+A4p2UEjgExN8XMHY2oYcKhqng2GshN8oXBdiF9GC7RAqTZERofqCwfJokQozBFxyUmbKUwUMYEFGr3j1lw3k6LJ8jvhO/xKRKMK+kcDUGsWJYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TM44Cf3hg5taaGacOpIErY7NmByAGW0Uqap2daYIDvY=;
 b=MJA5WdB9negO5mgsKBwrjg8+zu237E+U7RRMB6PoUrKqbak2JiWrquYuKQYRgtJCPnRTnxhoP3nJUlMVGer+WkIqI7dt33QvlBjEYLkLV51TLgcTBcn4Sey/cEBIlIJbkANsp/NBiRpNICnfGg4mxqtpQ9h2xWFTfwVaxiagjSoIAf7RLIQ7CCZa5+LHrti76/ijguBAUdut7JukmLbJikA2Af+/wKkb65gyz0SGRGGx/RiWwZRkg22BTWBqnsb8/aVKIsG+UIYSp27AMo1+f7Y7SGycCHLzqXWnWVbs7bBeRrYKfxlOvMf2svK/GZhEM+EZxPBWkHDQJ9D1VNhjfg==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS4P192CA0040.EURP192.PROD.OUTLOOK.COM (2603:10a6:20b:658::16)
 by AS8PR08MB9387.eurprd08.prod.outlook.com (2603:10a6:20b:5aa::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Tue, 12 Aug
 2025 16:57:18 +0000
Received: from AMS0EPF000001B6.eurprd05.prod.outlook.com
 (2603:10a6:20b:658:cafe::32) by AS4P192CA0040.outlook.office365.com
 (2603:10a6:20b:658::16) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.13 via Frontend Transport; Tue,
 12 Aug 2025 16:57:17 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AMS0EPF000001B6.mail.protection.outlook.com (10.167.16.170) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Tue, 12 Aug 2025 16:57:15 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nV3oTPtV+TdTjpHPCCiyRSLRPSr0dPRzGrGOd5aztz68XpBNB5WGAqb+xPl5Hq95mVPz6NYI6H0zOMJqk4d20Aly6SBe2cc5h0ZK2eBLuNDe/AVUe3sZrAmdxbbTACkECFyEz8SPusYj2fvOnFnEKTTObERX2VzHCsCC1yyQ2TgLp2AlUAxMwq1C0Jt4y2rpPpYsaqSr9oVzF7lLDnQjftjip+/m4qD7vdbzfP/ys6sdVVcsz748dGYWl9qKLC7u/F0C4uXeRHP0ww9WmrYpqLBRWcnO++aodACGC8Gjz6MquxklHN1DsFzrvGen4afpN0LN1+b1jGhd4CVPdjMZuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TM44Cf3hg5taaGacOpIErY7NmByAGW0Uqap2daYIDvY=;
 b=aToLQF7O4re5NtZYJIJ4u/admd0o7woPEJggBrQr45V+aG5xS08H8KCYm+TJwOSkqDEWxnYQp7BoxXfYbKF/LnxexhDVWVJxqNk2WhdP/y5iVAxU8X42Hy76GSF2I2ItAU74MpuPpMIKi4yfmjLkyw8CLdLWDvd5SfhUxnsSOkrUn6xgXAZLdV0tyef4xR9elQ+P9nQmCGf1GTSOci1Vj1C4dH5SKaLk0WoOJCRnefBRDLirZntQqt01NNkVSo/0BJYMA3UizlrhKY8BFvjMEC45xUZyTEL3E8yvLYTKeJ45SmoXT2ixCvPesmacQmhKbgw5mz9+2V4/clrRCTuBsQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AS1PR08MB7585.eurprd08.prod.outlook.com
 (2603:10a6:20b:471::11) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.18; Tue, 12 Aug
 2025 16:56:43 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.012; Tue, 12 Aug 2025
 16:56:42 +0000
Date: Tue, 12 Aug 2025 17:56:39 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH 2/2] kasan: apply store-only mode in kasan kunit testcases
Message-ID: <aJtyR3hCW5fG+niV@e129823.arm.com>
References: <20250811173626.1878783-1-yeoreum.yun@arm.com>
 <20250811173626.1878783-3-yeoreum.yun@arm.com>
 <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
X-ClientProxiedBy: LO4P265CA0126.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c6::17) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AS1PR08MB7585:EE_|AMS0EPF000001B6:EE_|AS8PR08MB9387:EE_
X-MS-Office365-Filtering-Correlation-Id: 10efba60-7522-43a4-0b7a-08ddd9c14a81
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?veWiSnyrpHr8Y8kKNkOYrMA57HWrNzBN/GE9O1JHQWbfCX2xO3IEtYrpJOk3?=
 =?us-ascii?Q?Je3qWs8r1Wxu5gfQIRpMx399sLM4FMAjK2Zg1sKES+j51xEQW+ZcYXAnLs5+?=
 =?us-ascii?Q?vi8d58+h6X5B6Gw2Bq8GYYGNxKIwMfddCj870f8vA8F8dAimBbRBtf7qHn9u?=
 =?us-ascii?Q?yTh0MZ6xs6m/BFZV1881sdoylHSqIK9JqV8TKz0kWJTc+urycGVHpRcNTIew?=
 =?us-ascii?Q?d1doRUdyv5T8NF6WehELsbstxoHU7CQwk2rTalkbLG/d6j6g2sZeDZq1Utdp?=
 =?us-ascii?Q?JxWPiA4WjHG0akFrnCtnAZCK8pKASAhdM4xJ3e4fhujp8sKZlDQkdJIaoxmj?=
 =?us-ascii?Q?VrlFUHojVc1borLTs3uwCuvacTzgTlZrZznHbcJXAuXYVtUAzaPEJxBffhWZ?=
 =?us-ascii?Q?+FJc2cKRKmFtWt5WGm0WBQTsnn/aCmry3/JMCU65pKU/a8UbxX+AN8V5y3c/?=
 =?us-ascii?Q?7Xd6T2GicfLedALKvR+vuO58MVrI+AzyBefPDoV0V1V/lUAgbLR4Ku5fDX4Q?=
 =?us-ascii?Q?bhvBKCR4VGcf/4ncgf+NWynfG7FoDxKjXEasDgY7aDOqe+vD0oQxCIoi+WFA?=
 =?us-ascii?Q?0orZt0Gc9cWLVxj0MsoulMqdeotScIxrFUScTX7+uRR6dRWJJODJeE42dRfq?=
 =?us-ascii?Q?7CERIketFExzKkMj/F0HPVKCs7H0M38o41s4KW1FBVAu7FLNLyEhk7LHMcP7?=
 =?us-ascii?Q?e6zeYyZbJoVu+nNltIeIJqYcOiEEF4gG433p2wSpkp63QWr12FbVqsWNwreZ?=
 =?us-ascii?Q?w5MLDVoQpzOEsnkkNZRfIQXuIgw4pspDjvEWWtEIPCWZUfIAZe8l0Vvt0wAc?=
 =?us-ascii?Q?MZN1nsphI5/RfRO/YalalI7O13ik9OWiUwnhYpuT0fvZqSr8EnduyW+Lz8J1?=
 =?us-ascii?Q?wecasE4+yfrok8o55VqkG/kpFXrZTulREqblxYSdY6f0GhtxEM0uupJWk7HG?=
 =?us-ascii?Q?jwCPUKdk5kynZrKNvzv2pVTP6kvvF1fyCRhEo+omPw24IO8xNK3PDgNq268l?=
 =?us-ascii?Q?fJRNndWNfjSdm9dhe0CwfxbaViz74kgue+Pha36rH6U3uKBsFXlKWDfDd+Yr?=
 =?us-ascii?Q?iUqrJsy0sFuAwVE7I9issTWetGa7bf9LuQvb++eiAVkVIvY0fTyDWfja+GAO?=
 =?us-ascii?Q?32TL71WH0bgDCCx+SvnDecPEr87EStzNrpTPWIQwuKiXpkh926amn/lJ4ql7?=
 =?us-ascii?Q?VWtHxfy+KQeSvA27zxj13S/n8x0+ZqsFdTpotmFOaNY82zFU+oYBCviBQyAm?=
 =?us-ascii?Q?dt+w6+bF5VONjU8Qw99dGJC1c4KjXSHHqiqmxbNJ5tWprp6YOOo+YJc1MA6c?=
 =?us-ascii?Q?fgfviC0eI6XbsZTTZ6Honjm9VlEkNDutQIFrNv3byyi8DYWsgAxSnkup9wua?=
 =?us-ascii?Q?13qxyFh2U0zLHJOWkDaVVt3aY4aJAfaQ+JFMVQX8GHyffUb0rJK/Uh2/yj1h?=
 =?us-ascii?Q?CMt7VgOq2yc=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS1PR08MB7585
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AMS0EPF000001B6.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: c530c7b4-2eb4-4bd6-80e1-08ddd9c1368a
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|7416014|376014|82310400026|36860700013|14060799003|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?vMr1QGUBBUpMLPOrof12tVFWdxEU13Hkmb3du+VbGS6QwmLPDszRzp6qmHrG?=
 =?us-ascii?Q?FSY3hJ+rZmk+zF/7X8ctGiln5AcsC+1Dh1jBX5r5Fb+6Wsny4A/tM7HhPjwI?=
 =?us-ascii?Q?8DWOuIdyfflp5cy1PER4WROmkInJNX2+vn8gtQBIaMUYJTJyVP1ba/IH25+B?=
 =?us-ascii?Q?uaG1A1Yb6cVtMGOLdWeNGCuOkC7P8kg5L50TEB/rAuTVxnS2N21dXljRNNMg?=
 =?us-ascii?Q?JWJDoc8t8j/5xyhejUjEQRX5c0D6j0HXaFIH+upqCH7l/+o2RLyd/yj0wj4p?=
 =?us-ascii?Q?8DpgAwaSaJvM7sj6DBWzOxsCX40rrYgbzUrie4l6ksDD7gJkwXArtkQIla0H?=
 =?us-ascii?Q?hdneUDyk7xH+mjd9TbgrwrhylIwELCI7LN3qGBcQJ2t06XuyV5bo2ww05dZU?=
 =?us-ascii?Q?ks+yD/4M0VPVG5x4Pkfc9QeYtSY36MfsQxCyOsHotUiWHZrEczMFVmRDglr8?=
 =?us-ascii?Q?/CCl86HXNuyLkORzzeydqJXW6aeiONIXMlPU5hazWxeT0lesSt49O2Jdo+3M?=
 =?us-ascii?Q?dAA28+HPTR4iN2EK1+rTAMBN1mOqcK+W7kjee824rfHoEgx6/e2SbV/4FTiO?=
 =?us-ascii?Q?XW8ywi0UbOBhKBVZuWIkRPCCanL1BBs6VbVdSmOVWDB65052wDPZJ8hk0/Ck?=
 =?us-ascii?Q?BhGU57worOgrL4O9OaUruUZYvbG7sp8JUUlCfKEXkxIdasYR0suAqsIxmspM?=
 =?us-ascii?Q?7id/3P3D0kmJ6WlAZ1BvjUU5QWt/kZtDOMx9dWPsKNEfh8yC+U/DQftt0msJ?=
 =?us-ascii?Q?fK9P7z2hfDxIS8U3m6/kU/qQLDLAGc/v+BAJMxeGLx/G6S7v1FSSfC/gXnw2?=
 =?us-ascii?Q?wsb05rTKUVE/kPmunNmbBxUaejVvdUhohAsINnw1KMUNHRnjAlsIq5tkb/St?=
 =?us-ascii?Q?IoLWoscOFlU2ahEP5aD5OWMYD5t7zeEqBXX0JcopKYge1eYp7q9kxm3Fc4qX?=
 =?us-ascii?Q?rp3vMbrtJ+djNE8Rq2Fb5dvp5rcHte4dhYp/HWM+ymP+KKQPZVVMk1LUI5+b?=
 =?us-ascii?Q?qTZbIYN8hy5VT6A13LlSpTEJ15IiTqK9g+Ca3B81/P7zgc4hY57Od6nbgcno?=
 =?us-ascii?Q?5G7SeMV53wW143plSwLHDzxNUDeOVXGExJbe7JKyUQjMhvtsMJl5bqazCFC8?=
 =?us-ascii?Q?14679puYAvCk/bbo4HnnTkTRJdVH5kILpReRZbBnL+IyQaQDwgTCk69dPNM8?=
 =?us-ascii?Q?xfLg41D7b5UU4MIpFtEwGdG081TqU9lvr5g3ZjjN9MFw+fnfONXiXMd27GYq?=
 =?us-ascii?Q?HbqsSUz/ar8UkqdBQHGQeP9H9rHmkF9oFPVtRX5I8Exwoj9UE2s1/81NDk2W?=
 =?us-ascii?Q?ueBfWHK4YazOUn6k04hCyEBA4ncNCXofsm1ar35QFS5YIWBbdJf4il714tDE?=
 =?us-ascii?Q?2ysERSOK+blSlyayOWgDPugVdto07tN+SRRdpmXX/4+SvkQv9oAyf3J8h71a?=
 =?us-ascii?Q?oWZXnL3WgePyWMvK8b2NxUOJYtEXe1ZawLzHrsAZ6bTyXea17sBcmpsRmS3g?=
 =?us-ascii?Q?th9o4cfpa0axlGbkouctjJynyMHYsSKilQnt?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(7416014)(376014)(82310400026)(36860700013)(14060799003)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Aug 2025 16:57:15.7262
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 10efba60-7522-43a4-0b7a-08ddd9c14a81
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AMS0EPF000001B6.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB9387
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=bo59sG2Y;       arc=pass (i=2
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

Hi Andrey,

> >
> > When KASAN is configured in store-only mode,
> > fetch/load operations do not trigger tag check faults.
> > As a result, the outcome of some test cases may differ
> > compared to when KASAN is configured without store-only mode.
> >
> > To address this:
> >   1. Replace fetch/load expressions that would
> >      normally trigger tag check faults with store operation
> >      when running under store-only and sync mode.
> >      In case of async/asymm mode, skip the store operation triggering
> >      tag check fault since it corrupts memory.
> >
> >   2. Skip some testcases affected by initial value
> >      (i.e) atomic_cmpxchg() testcase maybe successd if
> >      it passes valid atomic_t address and invalid oldaval address.
> >      In this case, if invalid atomic_t doesn't have the same oldval,
> >      it won't trigger store operation so the test will pass.
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
> >  mm/kasan/kasan_test_c.c | 423 ++++++++++++++++++++++++++++++++--------
> >  1 file changed, 341 insertions(+), 82 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index 2aa12dfa427a..22d5d6d6cd9f 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
> >  }
> >
> >  /**
> > - * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
> > - * KASAN report; causes a KUnit test failure otherwise.
> > + * _KUNIT_EXPECT_KASAN_TEMPLATE - check that the executed expression produces
> > + * a KASAN report or not; a KUnit test failure when it's different from @produce.
> >   *
> >   * @test: Currently executing KUnit test.
> > - * @expression: Expression that must produce a KASAN report.
> > + * @expr: Expression produce a KASAN report or not.
> > + * @expr_str: Expression string
> > + * @produce: expression should produce a KASAN report.
> >   *
> >   * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
> >   * checking is auto-disabled. When this happens, this test handler reenables
> > @@ -110,25 +112,29 @@ static void kasan_test_exit(struct kunit *test)
> >   * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
> >   * expression to prevent that.
> >   *
> > - * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found is kept
> > + * In between _KUNIT_EXPECT_KASAN_TEMPLATE checks, test_status.report_found is kept
> >   * as false. This allows detecting KASAN reports that happen outside of the
> >   * checks by asserting !test_status.report_found at the start of
> > - * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
> > + * _KUNIT_EXPECT_KASAN_TEMPLATE and in kasan_test_exit.
> >   */
> > -#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                 \
> > +#define _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, expr_str, produce)    \
> > +do {                                                                   \
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
> >             kasan_sync_fault_possible())                                \
> >                 migrate_disable();                                      \
> >         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
> >         barrier();                                                      \
> > -       expression;                                                     \
> > +       expr;                                                           \
> >         barrier();                                                      \
> >         if (kasan_async_fault_possible())                               \
> >                 kasan_force_async_fault();                              \
> > -       if (!READ_ONCE(test_status.report_found)) {                     \
> > -               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "  \
> > -                               "expected in \"" #expression            \
> > -                                "\", but none occurred");              \
> > +       if (READ_ONCE(test_status.report_found) != produce) {           \
> > +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN %s "       \
> > +                               "expected in \"" expr_str               \
> > +                                "\", but %soccurred",                  \
> > +                               (produce ? "failure" : "success"),      \
> > +                               (test_status.report_found ?             \
> > +                                "" : "none "));                        \
> >         }                                                               \
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                         \
> >             kasan_sync_fault_possible()) {                              \
> > @@ -141,6 +147,26 @@ static void kasan_test_exit(struct kunit *test)
> >         WRITE_ONCE(test_status.async_fault, false);                     \
> >  } while (0)
> >
> > +/*
> > + * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
> > + * KASAN report; causes a KUnit test failure otherwise.
> > + *
> > + * @test: Currently executing KUnit test.
> > + * @expr: Expression produce a KASAN report.
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
> > +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
> > +
> > +/*
> > + * KUNIT_EXPECT_KASAN_SUCCESS - check that the executed expression doesn't
> > + * produces a KASAN report; causes a KUnit test failure otherwise.
> > + *
> > + * @test: Currently executing KUnit test.
> > + * @expr: Expression doesn't produce a KASAN report.
> > + */
> > +#define KUNIT_EXPECT_KASAN_SUCCESS(test, expr)                 \
> > +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, false)
> > +
> >  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> >         if (!IS_ENABLED(config))                                        \
> >                 kunit_skip((test), "Test requires " #config "=y");      \
> > @@ -183,8 +209,15 @@ static void kmalloc_oob_right(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
> >
> >         /* Out-of-bounds access past the aligned kmalloc object. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
> > -                                       ptr[size + KASAN_GRANULE_SIZE + 5]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] =
> > +                                               ptr[size + KASAN_GRANULE_SIZE + 5]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test,
> > +                                       ptr[size + KASAN_GRANULE_SIZE + 5] = ptr[0]);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
> > +                                               ptr[size + KASAN_GRANULE_SIZE + 5]);
> >
> >         kfree(ptr);
> >  }
> > @@ -198,7 +231,13 @@ static void kmalloc_oob_left(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr = *(ptr - 1));
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, *(ptr - 1) = *(ptr));
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -211,7 +250,13 @@ static void kmalloc_node_oob_right(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] = ptr[size]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = ptr[0]);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -291,7 +336,12 @@ static void kmalloc_large_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >         kfree(ptr);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> >  }
> >
> >  static void kmalloc_large_invalid_free(struct kunit *test)
> > @@ -323,7 +373,13 @@ static void page_alloc_oob_right(struct kunit *test)
> >         ptr = page_address(pages);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ptr[0] = ptr[size]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = ptr[0]);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
> > +
> >         free_pages((unsigned long)ptr, order);
> >  }
> >
> > @@ -338,7 +394,12 @@ static void page_alloc_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >         free_pages((unsigned long)ptr, order);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> >  }
> >
> >  static void krealloc_more_oob_helper(struct kunit *test,
> > @@ -455,10 +516,15 @@ static void krealloc_uaf(struct kunit *test)
> >         ptr1 = kmalloc(size1, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> >         kfree(ptr1);
> > -
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
> >         KUNIT_ASSERT_NULL(test, ptr2);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, *(volatile char *)ptr1);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1 = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> >  }
> >
> >  static void kmalloc_oob_16(struct kunit *test)
> > @@ -501,7 +567,13 @@ static void kmalloc_uaf_16(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >         kfree(ptr2);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, *ptr1 = *ptr2);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, *ptr2 = *ptr1);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
> > +
> >         kfree(ptr1);
> >  }
> >
> > @@ -640,8 +712,17 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
> >         memset((char *)ptr, 0, 64);
> >         OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(invalid_size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test,
> > +                               memmove((char *)ptr + 4, (char *)ptr, invalid_size));
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -654,7 +735,13 @@ static void kmalloc_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         kfree(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[8]);
> > +               if (!kasan_sync_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> >  }
> >
> >  static void kmalloc_uaf_memset(struct kunit *test)
> > @@ -701,7 +788,13 @@ static void kmalloc_uaf2(struct kunit *test)
> >                 goto again;
> >         }
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[40]);
> > +               if (!kasan_sync_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> > +
> >         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
> >
> >         kfree(ptr2);
> > @@ -727,19 +820,35 @@ static void kmalloc_uaf3(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >         kfree(ptr2);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr1)[8]);
> > +               if (!kasan_sync_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
> >  }
> >
> >  static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
> >  {
> >         int *i_unsafe = unsafe;
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*i_unsafe));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, smp_load_acquire(i_unsafe));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_read(unsafe));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> > @@ -752,18 +861,38 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
> > +
> > +       /*
> > +        * The result of the test below may vary due to garbage values of unsafe in
> > +        * store-only mode. Therefore, skip this test when KASAN is configured
> > +        * in store-only mode.
> > +        */
> > +       if (!kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> > +       /*
> > +        * The result of the test below may vary due to garbage values of unsafe in
> > +        * store-only mode. Therefore, skip this test when KASAN is configured
> > +        * in store-only mode.
> > +        */
> > +       if (!kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> > +       }
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, atomic_long_read(unsafe));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> > @@ -776,16 +905,32 @@ static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
> > +
> > +       /*
> > +        * The result of the test below may vary due to garbage values in
> > +        * store-only mode. Therefore, skip this test when KASAN is configured
> > +        * in store-only mode.
> > +        */
> > +       if (!kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
> > +
> > +       /*
> > +        * The result of the test below may vary due to garbage values in
> > +        * store-only mode. Therefore, skip this test when KASAN is configured
> > +        * in store-only mode.
> > +        */
> > +       if (!kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
> > +       }
> >  }
> >
> >  static void kasan_atomics(struct kunit *test)
> > @@ -842,8 +987,18 @@ static void ksize_unpoisons_memory(struct kunit *test)
> >         /* These must trigger a KASAN report. */
> >         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> >                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[size + 5]);
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[real_size - 1]);
> > +               if (!kasan_sync_fault_possible()) {
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5] = 0);
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1] = 0);
> > +               }
> > +       } else {
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size + 5]);
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
> > +       }
> >
> >         kfree(ptr);
> >  }
> > @@ -863,8 +1018,17 @@ static void ksize_uaf(struct kunit *test)
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> >         KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[size]);
> > +               if (!kasan_sync_fault_possible()) {
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0] = 0);
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size] = 0);
> > +               }
> > +       } else {
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> > +       }
> >  }
> >
> >  /*
> > @@ -886,7 +1050,11 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
> >                 container_of(rp, struct kasan_rcu_info, rcu);
> >
> >         kfree(fp);
> > -       ((volatile struct kasan_rcu_info *)fp)->i;
> > +
> > +       if (kasan_stonly_enabled() && !kasan_async_fault_possible())
> > +               ((volatile struct kasan_rcu_info *)fp)->i = 0;
> > +       else
> > +               ((volatile struct kasan_rcu_info *)fp)->i;
> >  }
> >
> >  static void rcu_uaf(struct kunit *test)
> > @@ -899,9 +1067,14 @@ static void rcu_uaf(struct kunit *test)
> >         global_rcu_ptr = rcu_dereference_protected(
> >                                 (struct kasan_rcu_info __rcu *)ptr, NULL);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> > -               rcu_barrier());
> > +       if (kasan_stonly_enabled() && kasan_async_fault_possible())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> > +                       rcu_barrier());
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> > +                       rcu_barrier());
> >  }
> >
> >  static void workqueue_uaf_work(struct work_struct *work)
> > @@ -924,8 +1097,12 @@ static void workqueue_uaf(struct kunit *test)
> >         queue_work(workqueue, work);
> >         destroy_workqueue(workqueue);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               ((volatile struct work_struct *)work)->data);
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       ((volatile struct work_struct *)work)->data);
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       ((volatile struct work_struct *)work)->data);
> >  }
> >
> >  static void kfree_via_page(struct kunit *test)
> > @@ -972,7 +1149,12 @@ static void kmem_cache_oob(struct kunit *test)
> >                 return;
> >         }
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, *p = p[size + OOB_TAG_OFF]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, p[size + OOB_TAG_OFF] = *p);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
> >
> >         kmem_cache_free(cache, p);
> >         kmem_cache_destroy(cache);
> > @@ -1068,7 +1250,12 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
> >          */
> >         rcu_barrier();
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, READ_ONCE(*p));
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*p, 0));
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> >
> >         kmem_cache_destroy(cache);
> >  }
> > @@ -1206,7 +1393,13 @@ static void mempool_oob_right_helper(struct kunit *test, mempool_t *pool, size_t
> >         if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> >                 KUNIT_EXPECT_KASAN_FAIL(test,
> >                         ((volatile char *)&elem[size])[0]);
> > -       else
> > +       else if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       ((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test,
> > +                               ((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0] = 0);
> > +       } else
> >                 KUNIT_EXPECT_KASAN_FAIL(test,
> >                         ((volatile char *)&elem[round_up(size, KASAN_GRANULE_SIZE)])[0]);
> >
> > @@ -1273,7 +1466,13 @@ static void mempool_uaf_helper(struct kunit *test, mempool_t *pool, bool page)
> >         mempool_free(elem, pool);
> >
> >         ptr = page ? page_address((struct page *)elem) : elem;
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)ptr)[0]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> >  }
> >
> >  static void mempool_kmalloc_uaf(struct kunit *test)
> > @@ -1532,8 +1731,13 @@ static void kasan_memchr(struct kunit *test)
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               kasan_ptr_result = memchr(ptr, '1', size + 1));
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       kasan_ptr_result = memchr(ptr, '1', size + 1));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       kasan_ptr_result = memchr(ptr, '1', size + 1));
> >
> >         kfree(ptr);
> >  }
> > @@ -1559,8 +1763,14 @@ static void kasan_memcmp(struct kunit *test)
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               kasan_int_result = memcmp(ptr, arr, size+1));
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       kasan_int_result = memcmp(ptr, arr, size+1));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       kasan_int_result = memcmp(ptr, arr, size+1));
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -1593,9 +1803,16 @@ static void kasan_strings(struct kunit *test)
> >         KUNIT_EXPECT_EQ(test, KASAN_GRANULE_SIZE - 2,
> >                         strscpy(ptr, src + 1, KASAN_GRANULE_SIZE));
> >
> > -       /* strscpy should fail if the first byte is unreadable. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
> > -                                             KASAN_GRANULE_SIZE));
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
> > +                                                     KASAN_GRANULE_SIZE));
> > +               if (!kasan_async_fault_possible())
> > +                       /* strscpy should fail when the first byte is to be written. */
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr + size, src, KASAN_GRANULE_SIZE));
> > +       } else
> > +               /* strscpy should fail if the first byte is unreadable. */
> > +               KUNIT_EXPECT_KASAN_FAIL(test, strscpy(ptr, src + KASAN_GRANULE_SIZE,
> > +                                                     KASAN_GRANULE_SIZE));
> >
> >         kfree(src);
> >         kfree(ptr);
> > @@ -1607,17 +1824,22 @@ static void kasan_strings(struct kunit *test)
> >          * will likely point to zeroed byte.
> >          */
> >         ptr += 16;
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
> > -
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
> > -
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
> > -
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
> > -
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result = strchr(ptr, '1'));
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_ptr_result = strrchr(ptr, '1'));
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strcmp(ptr, "2"));
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strncmp(ptr, "2", 1));
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strlen(ptr));
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = strnlen(ptr, 1));
> > +       } else {
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strchr(ptr, '1'));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_ptr_result = strrchr(ptr, '1'));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strcmp(ptr, "2"));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strncmp(ptr, "2", 1));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strlen(ptr));
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = strnlen(ptr, 1));
> > +       }
> >  }
> >
> >  static void kasan_bitops_modify(struct kunit *test, int nr, void *addr)
> > @@ -1636,12 +1858,27 @@ static void kasan_bitops_test_and_modify(struct kunit *test, int nr, void *addr)
> >  {
> >         KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit(nr, addr));
> >         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_set_bit(nr, addr));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> > +
> > +       /*
> > +        * When KASAN is running in store-only mode,
> > +        * a fault won't occur even if the bit is set.
> > +        * Therefore, skip the test_and_set_bit_lock test in store-only mode.
> > +        */
> > +       if (!kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_FAIL(test, test_and_set_bit_lock(nr, addr));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test, test_and_clear_bit(nr, addr));
> >         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_clear_bit(nr, addr));
> >         KUNIT_EXPECT_KASAN_FAIL(test, test_and_change_bit(nr, addr));
> >         KUNIT_EXPECT_KASAN_FAIL(test, __test_and_change_bit(nr, addr));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
> > +
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, kasan_int_result = test_bit(nr, addr));
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, set_bit(nr, addr));
> > +  } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = test_bit(nr, addr));
> > +
> >         if (nr < 7)
> >                 KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result =
> >                                 xor_unlock_is_negative_byte(1 << nr, addr));
> > @@ -1765,7 +2002,12 @@ static void vmalloc_oob(struct kunit *test)
> >                 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
> >
> >         /* An aligned access into the first out-of-bounds granule. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
> > +       if (kasan_stonly_enabled()) {
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test, ((volatile char *)v_ptr)[size + 5]);
> > +               if (!kasan_async_fault_possible())
> > +                       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5] = 0);
> > +       } else
> > +               KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size + 5]);
> >
> >         /* Check that in-bounds accesses to the physical page are valid. */
> >         page = vmalloc_to_page(v_ptr);
> > @@ -2042,16 +2284,33 @@ static void copy_user_test_oob(struct kunit *test)
> >
> >         KUNIT_EXPECT_KASAN_FAIL(test,
> >                 unused = copy_from_user(kmem, usermem, size + 1));
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               unused = copy_to_user(usermem, kmem, size + 1));
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       unused = copy_to_user(usermem, kmem, size + 1));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       unused = copy_to_user(usermem, kmem, size + 1));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test,
> >                 unused = __copy_from_user(kmem, usermem, size + 1));
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               unused = __copy_to_user(usermem, kmem, size + 1));
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       unused = __copy_to_user(usermem, kmem, size + 1));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       unused = __copy_to_user(usermem, kmem, size + 1));
> > +
> >         KUNIT_EXPECT_KASAN_FAIL(test,
> >                 unused = __copy_from_user_inatomic(kmem, usermem, size + 1));
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
> > +
> > +       if (kasan_stonly_enabled())
> > +               KUNIT_EXPECT_KASAN_SUCCESS(test,
> > +                       unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
> > +       else
> > +               KUNIT_EXPECT_KASAN_FAIL(test,
> > +                       unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
> >
> >         /*
> >         * Prepare a long string in usermem to avoid the strncpy_from_user test
> > --
> > LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
> >
>
> This patch does not look good.
>
> Right now, KASAN tests are crafted to avoid/self-contain harmful
> memory corruptions that they do (e.g. make sure that OOB write
> accesses land in in-object kmalloc training space, etc.). If you turn
> read accesses in tests into write accesses, memory corruptions caused
> by the earlier tests will crash the kernel or the latter tests.

That's why I run the store-only test when this mode is "sync"
In case of "async/asymm" as you mention since it reports "after",
there will be memory corruption.

But in case of sync, when the MTE fault happens, it doesn't
write to memory so, I think it's fine.

>
> The easiest thing to do for now is to disable the tests that check bad
> read accesses when store-only is enabled.
>
> If we want to convert tests into doing write accesses instead of
> reads, this needs to be done separately for each test (i.e. via a
> separate patch) with an explanation why doing this is safe (and
> adjustments whenever it's not). And we need a better way to code this
> instead of the horrifying number of if/else checks.
>
> Thank you!

Hmm, as I mention above, the testcase with store-only/sync mode seems to fine.
But, If the "testcase" is failed, as you mention it makes a memory
corruption.

If success case is fine,
Please let me make all related story-only case be seperated
to each function (but almost simliar to pre-exist testcase) with
sync mode otherwise, let me seperate them just checking it whether
it success when it accesses to invalid memory with read/fetch.

Thanks :)

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJtyR3hCW5fG%2BniV%40e129823.arm.com.
