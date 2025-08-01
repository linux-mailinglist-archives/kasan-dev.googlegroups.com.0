Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBRWYWLCAMGQE7IJWSKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 40229B18161
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 14:00:09 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-7074f138855sf26919106d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 05:00:09 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1754049607; cv=pass;
        d=google.com; s=arc-20240605;
        b=fCde9Dc09C+g9P0Q08mMt220tSX0B0WpgzJK/U5kVqhxUt7nERn264RzyKVQGjS9vw
         +iDv5VN/U66h7wYiIRb1L0gunkGFcexnfiXHUGp0UYN4xlYt/aJrwRTMU1vTDYVvpZ4K
         p8KWyBzXfvhWoQWNsYV1iELKG3wGQfubMOzXQnPCKngLy+eH9g0OFJRgVgKJWGWNMRrw
         6r6TomDPzdQpozd70AsncmoAAtU0oewI+viEdj44zrDoSoPjSD8IFoWVsGMdb2ryEqyd
         H6aRb/qYg4BGZdV9yHdwpylXTx0PPHsBRYLylrpwt+Q4AC5lqdjw/LAX9Qw82v+uLWJP
         RsNA==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=YKkgiXTt+LhCXgS+oo6iD/5vmsUOWE36zFdYoUXlk30=;
        fh=+EL5LRmsl2/FPSUj76JY+aRwWrZjGM0WZVSzEZEPTHI=;
        b=PC2UlP4kqd2Ehm2e5Ou7PK3HPmXL7G97r4orh9Wsrt1MLWiTsSKcgyOrP6qMmGxX4H
         b9FLNE+DEcaIdzEV0GkpuqvU9bv6Kl7XWNuzcELRc3XDR5CvNBSafoPrMditG7zNIkSd
         1s7o5fPmg4pSIczB7XYnyVZv4nOF5GScWk+mfO3Xe1eUCOhxJ51jaH/TNuCFRe4RZvnW
         nCXWEIef+DKJCWLYbdOlu2xyZrbXAymUbF9ESeG+bewClYHtW420GRVvaG2laRyHI2bX
         0mVXqa4Qsv6S+xYnZGW6Oio/IwFBOqJmhaa0vu9aVMlw/TYsPzXu16to69ZvjH3JtnVv
         Ud0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=ME442LoW;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=ME442LoW;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754049607; x=1754654407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YKkgiXTt+LhCXgS+oo6iD/5vmsUOWE36zFdYoUXlk30=;
        b=pLRzeKBNwkc79TAJSEF9O3ToIm/JlIZu3warIkITrJE/jS1yHIgd1FpQGgzR3Tb3SL
         7rVlzt2mt2PBCRMvBEn/7VA2gqHfs7Bwk5b6x6IJIIdjiH8hQ4zMXR+HHw4EYCI+mqsi
         uEiibA1BiduA3lwtuDACDbP9AGOGCCDQ7gCIEGJ0Or22SHiQWK7DxwtxRhEeZq7YsmUn
         58SltJFPbi3K4OwTwGG5s6Vxbuh2jEiAOLJpmSAoAvLrA20VLPBOt/Ed9zmhXzcKDIDV
         9m/dcZZTbVP7COLbZvPmjQAuYhrWAYwY5Vx661LxZgFtXe2Ei/EogKohxsiVHrOeMYcj
         +AzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754049607; x=1754654407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YKkgiXTt+LhCXgS+oo6iD/5vmsUOWE36zFdYoUXlk30=;
        b=hpKlbSothwQqxob3PnJYI2lYAl2rjWKdAIQefOMV2Hl/pC0NWLqutUU1ePqTcO9sRN
         KzoR2AMIK5JyxUrXwlehQev/Bf64QCOIAs7p9P9Dl5Ov4SE57P/Bj0CcN1unO5abTk57
         956w1kFBSNJdj/daESUIwLa36a3sMJ2mkuh5MAKzqP4oGQxrHBOvGg8up70UtK8ndGHp
         WqcTN6kG5KetBAKFAWaRJwCtirIKfU3w8w/HGc6UZ9Hx/N1U7jOQQKnQNaVL0mQDDwK9
         a0gvBjvMy0UZg518sxu6RUJf9VbkeQM27RiyoXF67loT/PS2RjwafZJZCwYILxTF4imr
         gzOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCWOCXdttt8ChXnbUkHnACfc//MNnKuGKS7HHcxtECKNzS+MdtesQohu0f0HhYkT6otxIrKlng==@lfdr.de
X-Gm-Message-State: AOJu0Yy0VE8sdNFWr/kzgWf6N2Mnaq8kYUBg5CnLSj2p32qfkTkw0rSJ
	+T0BO2rKYfhdobTLCnF/QSzuH3dB8qgx57T4RyWq/TDVQewQ0Arf9lmF
X-Google-Smtp-Source: AGHT+IG34KWfGxYQ8iN8eJDZvzXTTAfNV6oANFP/jSr/wFY3P1CRkwpgs5vHcaE5xlZIvE4K2qGiWA==
X-Received: by 2002:ad4:5d4d:0:b0:707:14d5:ee74 with SMTP id 6a1803df08f44-70766d865f6mr141146036d6.3.1754049606682;
        Fri, 01 Aug 2025 05:00:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEOkn/k4K4qb2/EyJp3iFBf9hjzqYDijJGsIG5yeSewA==
Received: by 2002:a05:6214:d66:b0:707:56ac:be47 with SMTP id
 6a1803df08f44-70778b36c60ls31545936d6.0.-pod-prod-01-us; Fri, 01 Aug 2025
 05:00:05 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWb9VERERE2adHbvf+EvnzAPHCej10o6ftGOz6mxhtI34QP2eay1TdnBrGZ4CTaEVZH9pWi6R2Uycc=@googlegroups.com
X-Received: by 2002:a05:6214:ccd:b0:702:d822:f8c0 with SMTP id 6a1803df08f44-707671960d2mr153063296d6.26.1754049605442;
        Fri, 01 Aug 2025 05:00:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754049605; cv=pass;
        d=google.com; s=arc-20240605;
        b=ecQ7EHvVM3zpl5zXMWKXvRc08LWrA9/kSNiU78xeqB8cvIEqwF01qb+0OVPoFpbYRR
         7nl0DFUQM1VkSt7OUBBXQfmZoU4qANB87kQ4VVWLMEMqa9U3QYea3rx+ca7RyIJ5K/Yu
         U+YCxjl5Z0Ov7XiG+sEWSA7P1BFP5aUgmgUy0EQ8r+VWU0rAJQ0p4dwn75eKTL04UA12
         RtdjZr7P95qDAW+lhetFo7csuVYLNOHxnWX96VoGlRD6KwylRMhATZeyWfn2qnETtSGx
         LP1lez+zzjgX3TIXBvQCotPQj+S0ylNy52okByRYujzTSSjExK3BpLHL3JYuCjSXjieh
         GSRA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=GerBoo9YYMKztWZljHsS0T5qv6yaH9BQiprdhoSYt/8=;
        fh=dmbR7M11UiSeCN262el87RQ0DgGma52LhbCZfnmx/LA=;
        b=ZHX2zayOHXxAtZAm32mG+9G9qp/t1Aa18janQdERrYhB2JS49RfgW4KIQBwWI/6g4C
         QwDNfhahRzYmmxdTJB3mVwKE1haK5L9nJ+Hn+kUU2AjpsDtFqQglfT8gzWxWdvhLkI4W
         ti/usTve9jgyFtr8+UCZk2MAmiter+UVeTUwNP0Latqqd9QH68X7nWCl/agJ0xRv/w/H
         FTg+vZhZuBZtPJGXfZimovSw3rXLnPPHEgNqXsML1L261walI/AxxEdlhsM5Q5z3Bi26
         te/75EECmts0UMaQyoQsiVwoo5AttRPvUtQYW0wsEZHGmh/ysgsn1zV2GNf8bV4WOdZr
         YVJA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=ME442LoW;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=ME442LoW;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from DB3PR0202CU003.outbound.protection.outlook.com (mail-northeuropeazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c200::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c95ddefsi1452616d6.7.2025.08.01.05.00.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Aug 2025 05:00:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::1 as permitted sender) client-ip=2a01:111:f403:c200::1;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=Xdw6EV/mbziOMFRa1fz2CTpj/CHkf7GKCdlIpfwCkijk2kNZ3JFsD74K5EAyHrU3I28/ovLnYBGj5bvQloE/PRlDtbY+nRiimicdMrEmc/f47U9uSYRNiu09Cvu4G+EShbQoNV2/BHHs1yIBfAALpHEzeHTD0kJrx9tXwfFPntKFaI6LhwHN/7+dCzKUfpZQi/K7m/U+j6nDswpYjxESzy6sNWA4gX57554zLGSva7kFLz1t+ULmXStVoBR5nsjPeqx2j/3CABi+UuJpxQxmgeTLOh+LHzSRi936tAhNyznhzkf94W+lj28lKIFQCBmOsAEUmeezwXtcGbAFPvVaZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GerBoo9YYMKztWZljHsS0T5qv6yaH9BQiprdhoSYt/8=;
 b=pItG4+qj8DFxexGFkJV6oDPLG2noLKgZRVChS259NzShIFrTnzsqoRuf0foLWYplyUyU6XHkwjcqRsohL9XRDxxFA7TiooFLFoMhL3uVeAQQR94VLVxn0Bks4HUpRhgIgMjCYBwstdDc4ELG7A6H9gWTdopgyXT3HqzQ2KtTFNUvM+0PEaTEmU9q0rosbn4msF1i6KRK2B8/O7iHvSWK/ZGE+5z02eofqWUMcaXtBTWmtBqKyU44Hp/TPJ8zwB3l/dfA059/cP8F5kw4kKB+ywYx2PDE0J8JoHHR6chPG5pmlF66NvpHg1U0lBgyyJXV7LbTHAvINCnc0k0wVKCSfA==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DUZPR01CA0117.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4bc::23) by DU0PR08MB8066.eurprd08.prod.outlook.com
 (2603:10a6:10:3e9::9) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.14; Fri, 1 Aug
 2025 11:59:58 +0000
Received: from DB1PEPF000509EB.eurprd03.prod.outlook.com
 (2603:10a6:10:4bc:cafe::a9) by DUZPR01CA0117.outlook.office365.com
 (2603:10a6:10:4bc::23) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8989.16 via Frontend Transport; Fri,
 1 Aug 2025 12:00:08 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB1PEPF000509EB.mail.protection.outlook.com (10.167.242.69) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9009.8
 via Frontend Transport; Fri, 1 Aug 2025 11:59:58 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ElQ0sZdnc5UffWF2D9rVmbYzBHhsLj2H+ZAP6cgioaZ4qPOPN23UOueNEtki5Mv+MfDxkFtYU+Yc/EgK7sWSCY6O2+sGKVYuEcsCSnMgkqJT06NgjGr5135eONwHD1OvD9BTr4eLQ+G0WymucuLoEH4ug1CTknZ519ODNBS1cWONmT2XlHWiwgxpOngRbpnHvLm7XJpNA5BxljfO8QrbXGxRsojRJyCgX1t2oish9NWm4YLV+B0iR1rlpLGrbZTe0+trb5slSejoi+y82HEvYCxzZHzDUAIRLEp7t6ww85L1WHen2zNdOivw0vQCQQbZav+dFZ7djeR6+sHhe8n1Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GerBoo9YYMKztWZljHsS0T5qv6yaH9BQiprdhoSYt/8=;
 b=xaSA3GAwCYd71a5JGTTSXDOB7n1LKMFnxwMH1zaQIci1UmOYUcDHmo0QO8iJNNzMpXy6mpJS8D+04olF7Y/thQb+V/J+TGD/1Dy3Mh190T48czL4yLEirRkeiq0mreLD/27sVpeiFICKnytUzG88vOidK8FqRRaZ8fJs2/w+raikRYt97ItFoenyTyhDjsAPPRd/XZyvcVe9siPUMCyaBL2dVBiliS3tEXzVAc7Nq6cFt3sO7opcJqNh9eLPJYP9jrneXYiEMfIav0CHcbhZNhSfVafPOsMJiWybGF/AQO4GpcC/o4XHC7p1XJhVLF6p9aUtS177GAdOcHR4TF9KTw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by GV1PR08MB10730.eurprd08.prod.outlook.com
 (2603:10a6:150:162::17) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8943.29; Fri, 1 Aug
 2025 11:59:24 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.8989.013; Fri, 1 Aug 2025
 11:59:24 +0000
Date: Fri, 1 Aug 2025 12:59:21 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: thomas.weissschuh@linutronix.de, ryabinin.a.a@gmail.com,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
Message-ID: <aIysGSmWKIhQYid+@e129823.arm.com>
References: <20250801092805.2602490-1-yeoreum.yun@arm.com>
 <CA+fCnZdiwXXYmW9a0WVOm3dRGmNBT6J5Xjs8uvRtp7zdTBKPLA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdiwXXYmW9a0WVOm3dRGmNBT6J5Xjs8uvRtp7zdTBKPLA@mail.gmail.com>
X-ClientProxiedBy: LO6P123CA0005.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:338::10) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|GV1PR08MB10730:EE_|DB1PEPF000509EB:EE_|DU0PR08MB8066:EE_
X-MS-Office365-Filtering-Correlation-Id: 11ff348b-e561-4830-d79c-08ddd0f2f020
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?0lWFv0Ygxr1r67WZutuOZCvalUGmnCNeb2VJAfUKRU0Q4f73QdN3VKX13mxl?=
 =?us-ascii?Q?rh6HINEpiG6Z42JeF6VqXVdsRqFZZRvPld/u7IfhdN3ioNEFdSeQ3avgEUmZ?=
 =?us-ascii?Q?HGJ2luo3F17WXFYAZ5At0ACLqskuF2dfgPOxILJr9OlBMbomSqhrI4sMttiR?=
 =?us-ascii?Q?ojb1PvuDlMpehym95ePxw7Vf4hmDmVpjY96uDPSsRvm+52Dn577DP3XAuceq?=
 =?us-ascii?Q?w/GQceAx31J9uoCXgw0E6wulZMPNGbFmYl5WbwOKbO+H0gZ0WqDtRzMOEY9v?=
 =?us-ascii?Q?dp7xZOUf/c72fb+lu1kmh7LwNqajxR9XWYssZyyV7SEew8d1+x2fwgxF50qW?=
 =?us-ascii?Q?t2Mkl+FrwwnW/4sed9VskosZ8Pc6Fh8MDw8rc9iQYbBorR8YCywEkl0JNNqd?=
 =?us-ascii?Q?7YvjpSdfhf7Z74Blnyt1zj70zZHsvhkKe9YetyA4OlYAGJzz8UjPIUMQEv5l?=
 =?us-ascii?Q?I4MogW9Y4FeBQ470QD+xAeoWzl7JDp6zj8lkzqzzelJqZNknW9bxNSG0jXNT?=
 =?us-ascii?Q?xW5UZzuBdrD0T9j/JL/tWXi+XhU9Ey4Dycad64o2zayegqCPT7n5KzgP155i?=
 =?us-ascii?Q?iuI4KsvSXEyiuV6Rq9vna+Q5dyrPNH+toT0YHJ/Dm4DnKUDWIXhDWUANzNyJ?=
 =?us-ascii?Q?f9z8h1LadCUN68HU35Wsja/i/tF84QX93Qkeafe+eAhlziuV7gK4uU8HSBS5?=
 =?us-ascii?Q?lBxRwh9rhwv5bAafZNK7a3LHPbMxoGkgS3qOMIoLgXZm8XOOzSOieqOndcnN?=
 =?us-ascii?Q?dn/pvCycVpLDIf7IC9hIlIvCVzw7H9sfsF/oht0QoCaz9Y1v0zIP3028nEgE?=
 =?us-ascii?Q?orUu2bjJ9bMtveXpI4NRq285Yfww685CWQJjeuy1IV87Y38zkeOJAGfXgwvP?=
 =?us-ascii?Q?J5TLDqFYmLxiSWQSWWGGeWHXIYDIdsdntH6BCVcgz3Xyx3S8MxS8GPUOvG3a?=
 =?us-ascii?Q?/I52RUKnWuYfXHw40dPzN76umZkDWQjyCJl5imxjRpX1NieEPfZBaFhegR4S?=
 =?us-ascii?Q?uu8Tti90QvwC0EWWvUsDzxnFBmZOotlGTzihGT1hoaMXEfsK3y+8TkOrYOFK?=
 =?us-ascii?Q?zHnXN5lKgA2IioYg3FafrXmrDAl+TEMh3LvPOCq/9/3IMA6XWz78XxmVo1wZ?=
 =?us-ascii?Q?glJtXY+FAiyOcttXRH3hOQHmlqX7vNTyueNOynHCueWdQDRqetuB6+fzZ/WD?=
 =?us-ascii?Q?FW0lBEHQOoMKuU7RCLj2wWG7w1nV4mnQBchdx7tAfU77xo0Zw0E6GYZ0EvAa?=
 =?us-ascii?Q?lXlGksJv4wZuA70/ecdB5QCPs6n0qmboVFE+F5sD64c55wILppzdvTxMj/ep?=
 =?us-ascii?Q?zEsyeiXxUAQpWNcAqQ/1oUwTA1B8yL+orAQC5SNkJlFXc3QnWA8MtmZc9LgR?=
 =?us-ascii?Q?SzFnE2NDt+YjPPXzAx7MRZP1JrMZEVBEfQFKFBoiGhRmMwcY9wSQ9uA5VSpV?=
 =?us-ascii?Q?VQsGDQ8MSQE=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV1PR08MB10730
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB1PEPF000509EB.eurprd03.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 795b1588-222b-4a8c-e126-08ddd0f2dbb8
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|14060799003|1800799024|82310400026|36860700013|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4FEjbiUe9u0gXS0+kNMo10/XemxWr0Bs9QOX7H/AdwZuKYCdCm0ZsrxA6dgo?=
 =?us-ascii?Q?PgRygpQe77V6TTzt/Vg/AoV5oRW32CFIsY8qjnEeWMFPPjbvm062vo16MTun?=
 =?us-ascii?Q?u9cv0S7GHE90waJys0s3HjuN68kcnir6FAhD1hYY0CB6HcHFd0yUSFBH+8y0?=
 =?us-ascii?Q?zTNiWSO6HHFiRy5tj6q1072b6o9VbSn4pamw7HHAEHHwfFG9d245MovrLm4d?=
 =?us-ascii?Q?GW35R5KjZ3OKVSmxAt7gNGQzpKWhs/SaIIxyvtkU+86CCBGU/kwZGsyYYqdW?=
 =?us-ascii?Q?F2wmp/2s/nYguuFhCCSN5uIrNVUQZfhd8LMUGUiCQGYDpIY0eeQMW8VRIxdt?=
 =?us-ascii?Q?ZevBv62Zdgt7mIZ7oMLO3yIdBlZ9TRRv7vaq/gjaA7gKiu3nh0mItWtWQnWM?=
 =?us-ascii?Q?g6y4EoQ0cySVqVB/5dvAQDZ06R5XcxhvHfltW/HJfNlC4t7BF6X1ESyem2oO?=
 =?us-ascii?Q?nfEYm14rbBf1tct6K0BcYN0pjoZzyCbl75WpjbyVLgskDx9GnztNkJ3k+Hxm?=
 =?us-ascii?Q?p3QMCnnrJEP2Oz8CobdUDBpDLCkggofEW81dbijXiIxt642yC8EdVui6jGn5?=
 =?us-ascii?Q?xL/4n18fS219UOSdE5j4PwQsOoP8A7fK1cL24PIXt31R31gEMFpaGKLDqzpJ?=
 =?us-ascii?Q?PELHzEjQY3v9lVoWI1pcYuyjC3vTc/Xom4exzCTkZFKydopNkTwI2menFPoo?=
 =?us-ascii?Q?URzR4rG8Ncjqw9fFNWaFnmjDpU34Tw1R3SmOBHfTdTUswsmGQhsV313YR7OY?=
 =?us-ascii?Q?Pi8dUFcWfxkcjrso3KZ4k/mwNPpCXjYVVq19OPPFQ3Sd4a/zhsrLjW9Xhjkd?=
 =?us-ascii?Q?6evDtUUgljNiYWT6Y6ACMKDeujHCMdQ3rjYnG7qbPffg0B5iY1mUsdEStzLU?=
 =?us-ascii?Q?iTE+vvBrEs26uUP3SOLrEoMaYmtOgS/vigWtThvKX8/qAVFdDhOJDexe46yj?=
 =?us-ascii?Q?N6sk7T04HdWVs0rugZjNwRh4kuF0TAbG8ALD82FAxaR7LXApSqfLEhTZKFdG?=
 =?us-ascii?Q?WG4XYweshs/Yk3lWw0064SGty2BvCPN7beHklGrBIEZcrEuLlFYKgR/zV2QV?=
 =?us-ascii?Q?Q1u9JpEvk0p/ZicM6qmYBeVjLE7V8IzIDyLDSiLXqKgiRo/6nq65IWUNLaWG?=
 =?us-ascii?Q?abtgikQU4ud3jMWn1nRHJmliqZcJXVP41Fx33YbL7NP9Nw/Fs3LuaWU7KJbX?=
 =?us-ascii?Q?GsE9/tvD9O25Z+CTyw91bm5Pg8Z86EshzPCok0IFCPahiWj6T6u545AfMrEg?=
 =?us-ascii?Q?h6TRV9CPiG1F6AplDHWeIYySpJY5JaS7QB/JqT/XJDarNtF5rOJe3csdlT5p?=
 =?us-ascii?Q?NP5znV7XvCRKX3limZ9GAKcQ820dh1Oty7+WvBvUMuhY4bvEnlwK5aIHq0pH?=
 =?us-ascii?Q?dPJI25XFK0ct40wpA876pmnuq/6aH0nV8o7QtrAA/TYVO2lCTuWxYy/hxYHC?=
 =?us-ascii?Q?npNPFKaLiwLff5iM2hA6gCfNXWOj6pSlIGpyoaK6H031+AfTom7184Z0bNwo?=
 =?us-ascii?Q?jAI1/sg4dORhqUlGwNf2mnE+mtq0qtWN+ULC?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(14060799003)(1800799024)(82310400026)(36860700013)(376014);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Aug 2025 11:59:58.4728
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 11ff348b-e561-4830-d79c-08ddd0f2f020
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB1PEPF000509EB.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR08MB8066
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=ME442LoW;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=ME442LoW;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c200::1 as permitted sender)
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
> > When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> > triggers __fortify_panic() which kills running task.
> >
> > This makes failured of kasan_strings() kunit testcase since the
> > kunit-try-cacth kthread running kasan_string() dies before checking the
> > fault.
> >
> > To address this, add define for __NO_FORTIFY for kasan kunit test.
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
> >  mm/kasan/Makefile | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index dd93ae8a6beb..b70d76c167ca 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -44,6 +44,10 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> >  CFLAGS_KASAN_TEST += -fno-builtin
> >  endif
> >
> > +ifdef CONFIG_FORTIFY_SOURCE
> > +CFLAGS_KASAN_TEST += -D__NO_FORTIFY
> > +endif
>
> We should be able to use OPTIMIZER_HIDE_VAR() to deal with this
> instead; see commits b2325bf860fa and 09c6304e38e4.

Thanks for sharing this!
I'll update the patch!

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIysGSmWKIhQYid%2B%40e129823.arm.com.
