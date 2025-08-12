Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBZPD53CAMGQEC234KIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 04507B23AAE
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 23:28:07 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-30bcbfea9d3sf11682602fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:28:06 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755034086; cv=pass;
        d=google.com; s=arc-20240605;
        b=Di2F3MeGImBo0jQdDDLsWLLCcXqgTV7hProTel9cn2/fdj9VczG4tHxMdrtHRguhDs
         L6FCp1U9Zwx7/q3x71oRUbfgXgvmV+fazH0cRwzCTgltWaCe9uFMn1y/QHFW6NScf08l
         Y4VTdg789s+sIXZIQzAua272hkOSCZuMmWxMRWETVT/NpemmT7EpiOt60fxkdALawwsk
         p09oP64BNehNTdo+NPtKkE44RJm7K39Ud7DHSDnbVw0vykxYt7RMpv6A9kah6KPDXlLV
         iZhPAOWjMbBpnhysVvbFKyUfd6ZTrA+MkGm+iuawWMxMi0mV6ibvsoy9pyt2y3fbuKHv
         95Gw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=Usf9GWDtp0Q4eZyLz0nbHQ+8af1rl5aDpEDXL7JneDI=;
        fh=bViDtIBiOG2UoZZsvwJAwtUjtc+IUmmY3PRqKg/UJd4=;
        b=TbR0CAb2XWLhlxvs+SyY8LQsNrTqHiN5aCqhTPMPC7V1IW/NW24V8KByZfxnrpUh8h
         z90af6HM3VDobixl/6SKnFTOn0SjUkA66uxsKxAeDR4HLb3SX9b+hsRlsProel3VneKC
         94yLF1aIn9A5aWQcN0Fih4LUZDxSdCxH32WWy/hcS0NSphmu84nhGwW74T/s9Qjhe+MV
         9uQwdFAuzP88NjMOi52iTktKaF/8nggr4IyE7m+XMoFnEoppdItHH5m91vxnFYaWUBOy
         RrEFspHb9g/1OIQOsRry1hnysFqNgkFBvxZHcATGS+uKPL0BhQjjaUtVpOSALLQOQcdf
         yxBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=qElVVzuq;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=qElVVzuq;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755034086; x=1755638886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Usf9GWDtp0Q4eZyLz0nbHQ+8af1rl5aDpEDXL7JneDI=;
        b=gysNHUoJvrFtgJdHZBUKZkg5gdHc5IKwYFrWPgyTTWM8VSJrP3KuyoWUfVgu3jVk+w
         8CX8ejxZ99SjimaCvnA87RZCXZiOfWod2jSoIE5RXR3PijBm8BQohqWPWm58zdz84hcx
         TipnLkc3UPdn4RDUYd9jYoTYqYY/Tg81CqiVmTu5QF8N+scStcp7tnrrDkjJ49wi+f7y
         ttDC+2wvye2IiqnZemt7+IwZrL7xbY9PmgCy1SPT4uJ5ikxEsxJ5athcieXgSdqRu/Ni
         QDW/sCG57IGnJYnsCJZkbkJSu2OuNmRmH36E7zGuVWXzPM4E6IlzWZ0nwTKtDuan5DSx
         2/2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755034086; x=1755638886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Usf9GWDtp0Q4eZyLz0nbHQ+8af1rl5aDpEDXL7JneDI=;
        b=MHsmageq24M5Ob7JWaGbkclvLHk0JLEg4WjOZcj3QD+vG3PL0FrAi8qSHHQPd++OeR
         oE0WTNC0jWlHmiF7w/2BfGlXwM57j3GCCpEx4WSshRnwb12mC+7EqYcM07OdD+cOUh4b
         ATyt1gLG0HQEm09uaMd+PEEm/kjlC0oFIEVWzVN2cEITO9on08G6S9EYWH1GhLt+rVXS
         4t6XM5Bq6POrXua94tPHB2YJ9jTuf8wY0k8NbocG63xXhM8Us9ixo6hTWVUZvZBxMFAY
         rTQUWZo+h2R76GOYS4lKxIv619d0UaPTAhHOZbO9Jv3jGB+rHInKOzEclfw65e+M45uY
         1GfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXqVprfEt7N9qshTMH+GMup930LTxNLU0rrrVwTFQAjMrXMGUcu6IdGKbnYMO4wuoSfmaOgzg==@lfdr.de
X-Gm-Message-State: AOJu0YzP9axIernP818RQiBj7DwzonFqGggHO7scY2AUyMvvhiF5FjFX
	XRcpWkWa1AqICXArjicUGt7Q6wvEDowA9D4TRRC91elCKS9LDzINjw61
X-Google-Smtp-Source: AGHT+IESfONg1xMpkZemcvF2ZzxVu0QYUzW8egYs9zY4J2615w/mhPCV7YFQkmGpg0kKsQNyTmnc5w==
X-Received: by 2002:a05:6870:d608:b0:30b:6dc6:d5ef with SMTP id 586e51a60fabf-30cb5c38782mr491880fac.32.1755034085588;
        Tue, 12 Aug 2025 14:28:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/BEYLYlfzqOPjp9GrtpRzQjz2mrgku4pEMMmQDRWfrw==
Received: by 2002:a05:6870:63ab:b0:30b:8494:7c37 with SMTP id
 586e51a60fabf-30bfe33a3cfls3143272fac.0.-pod-prod-05-us; Tue, 12 Aug 2025
 14:28:04 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCV5TRKn3wg9h4tdGWJQQrAZ/Eydhw2PZ29J1mlD1eYiFkOYHpgtSbYtUOy35CU0xFJyuTCMfFLPu3g=@googlegroups.com
X-Received: by 2002:a05:6870:414c:b0:302:5dba:5ae0 with SMTP id 586e51a60fabf-30cb5bc8ac4mr501375fac.20.1755034084678;
        Tue, 12 Aug 2025 14:28:04 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755034084; cv=pass;
        d=google.com; s=arc-20240605;
        b=lYGraG11ZKuAumNDI/CTSVqJUTDU5RC92OgL8GL++/oRTovNw9Fao16b2c+OxmHI0t
         uid0GX8pN8la1+A7pUCtkha0PYWs3Pts/wALGhMWDNAEAubQh7VwMzu7e6r3xAYMstos
         +JPiv4qx7OQoP76wfhPQBQzhqQ1VTKSQpIGRfyYMXPmNq4y4BzcBD1Zhr1nBA9R+5kOB
         upFq8Zkz775Vkba7p0yHZY100G1oShdwB58m/MV3L9pXJmatbGM2yUJZho/Z+cm6iXof
         Ltmjf0nAK0qgV6Qw8gHKeFyNsjMJCbu+GuU0l24ieIsA6tkvcbTCP7CFEBbTS21+K8uJ
         g2MQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=0JIAlrahIoJb7vyj3+4Bn+Rx3tUFGZvO3fHQ7vDOLPY=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=MbmoLSb+6E6JJ3EJdK5s8lQg0F6ceQaR1sKOvf3pmlf3YFPVwMpSqxTweHyz91QrM0
         8ot+MSZCoGhGGa3mNSgfNVukzY8VyXqyEThobYcNlANtC8jC12KbOUpFfCadCvcCJqaX
         b97cUXOIgKnRhPzdD0mhbpDMmsvPJDgGH5vDviWlY74UO5w03ThtQsP5sV9qyksxFoCS
         JAcryRLKObXqfofEiMzK03yX6588SfG/jFo1AKuksAv3Q536MpyYWDSZmQwfMXxUcfwK
         LCVKzx7sRrPZCRLmTVVE1puAwaORmrLudvHD/qiRri6LDX3CZRcol9Q38Nk8TT9Oewp4
         pseg==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=qElVVzuq;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=qElVVzuq;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from GVXPR05CU001.outbound.protection.outlook.com (mail-swedencentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c202::7])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-307a67f3040si1408579fac.0.2025.08.12.14.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 14:28:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) client-ip=2a01:111:f403:c202::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=sactH41ffs2HHpqpTQ6tDSbWDSQeT8BMY/edLg6fEJPAza0PZlY1selk92fdMLi4bpo5GnhIiCuraXg5oW4VYAdnltgA4Eox2bQIvUqQi6d9r1WQ9QsPtXG4UWX9ulKgH39boBTdCdXu5nvWdvTKwoa07UO57mPYoopoG/OLIzt4u1HiNStXwBZ9x5BGWyUf0a9qt2JKXVtg4NxNTO6JTDsSG5l5ucw2chvuMsoTFES8bjoS9V6nKS/a1i/sTqAh4b5+SrcWR0XKSFu1Ehex452wEJSJT46f/xAlCzgNPAaYVvitOE4j+jloT/xNnoBxZZqK5/zUiIyW9382ZrQnqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0JIAlrahIoJb7vyj3+4Bn+Rx3tUFGZvO3fHQ7vDOLPY=;
 b=WHI8bB6NjIuTZZKAdoSHn4nKAUcPkVGkZSUMQN+XIjWU4FC40iHb1taQNVlv4oKQh/2CkiyDdXd29FAvgQGC1jSsh0AgTytS6vQTmte/9yMB3uxxItrTkUiUU3DizrJ26OneV8nZI+vi9ILJG/tCN8LKJEKoiBawuVgmNXgcQP8CAR02pVC7Bqs6VAmQMMR9rD5c6sRTPMoX7wlAzBhhwS19E+nSmKYzk1o4uNM06McHZMVX4TBXoLQPXAgR6DRYYWVn9tlVcNviF2mPkqjhMiDbNxecmhXpKBGIeomUqhXhs8Ixcgo0cYO79NMbZMxbO7lmf+WKYgO+P2nRzBVPFQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DU7P250CA0005.EURP250.PROD.OUTLOOK.COM (2603:10a6:10:54f::32)
 by AS2PR08MB9618.eurprd08.prod.outlook.com (2603:10a6:20b:609::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Tue, 12 Aug
 2025 21:27:58 +0000
Received: from DU6PEPF0000B61D.eurprd02.prod.outlook.com
 (2603:10a6:10:54f:cafe::43) by DU7P250CA0005.outlook.office365.com
 (2603:10a6:10:54f::32) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.13 via Frontend Transport; Tue,
 12 Aug 2025 21:27:58 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DU6PEPF0000B61D.mail.protection.outlook.com (10.167.8.137) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Tue, 12 Aug 2025 21:27:57 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=S9iAaqlNao7VihahFm0lxi44+NORtmKvL69h6RPx6MemJA6CZG+n20xPvf+5+77uWjFSLxWkNRWSYfzKpCCa61j1/F6DRI/aXAvQGZrxEs4g7pKi3gLQu1igSpxmyxVnGDqpF5SfZUe9HDwIpEY/UE9SdhJI14Sc0bz5zsNgjc+Vh2woMwUZFwgmSWNiYKj6RfWrsDKUpjLz1nu4OZSp+OPWt4dc8WPBaPUmgpqzYrlRMO+C4w9PerCBovElW7s9DLe+8ztRXTJRjmkIBZIiauzDX9GbLjg2Xf4cqAiSUGIK/+SFahuFHFB5TVUFO3tp3cMFZrzl1IHv59BDVp/h2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0JIAlrahIoJb7vyj3+4Bn+Rx3tUFGZvO3fHQ7vDOLPY=;
 b=UZ1DBYYlY/n3XuqKqfWn3az4AL9N3o7yrL3eLxpkZ39iFhwL+b5Oh9lKnGNVvWsQUFUaV4Gsb6JpAfQhRxoxVyXFcWaZ9cc+NreXOuogqgjqui7jA5tjnGWkyw6I2YmHo8FdSuHJht75dqyxHjB5ZKkemJd3q9tfpx4LL7gw+AbKyBq/RsVGRTLyKsrLp4Lr+Gd0hv1nScT6g6nX1dlAB1Uon1uSisTDMnKtyVpFNmT4y20ySvsp04AXtU3S7yj3SnMny93kmsM79OZ2gZIiuuj7j7VAPy9bxoVKN809yV/M1V2Sk3g4SZoebxAWDIJwjsC0rKHr3luZLXiyLKRwVQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DB8PR08MB5372.eurprd08.prod.outlook.com
 (2603:10a6:10:f9::17) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Tue, 12 Aug
 2025 21:27:24 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.012; Tue, 12 Aug 2025
 21:27:24 +0000
Date: Tue, 12 Aug 2025 22:27:20 +0100
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
Message-ID: <aJuxuKBm9qfpVkBC@e129823.arm.com>
References: <20250811173626.1878783-1-yeoreum.yun@arm.com>
 <20250811173626.1878783-3-yeoreum.yun@arm.com>
 <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
 <aJtyR3hCW5fG+niV@e129823.arm.com>
 <CA+fCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0264.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:194::17) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DB8PR08MB5372:EE_|DU6PEPF0000B61D:EE_|AS2PR08MB9618:EE_
X-MS-Office365-Filtering-Correlation-Id: c1d80ff8-cd54-418b-1cff-08ddd9e71b2a
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?UBEVAalBsjrxdPVLcgMjSg3A3Ls3mUg1dGo2YV4pV9KFB/dNzNvqUK8Z5eag?=
 =?us-ascii?Q?CCpD/r7GM/reXXqdcfzddKaqLob08JLKeX1Gc1a6KaewVkdAqXOaUd2EsOp3?=
 =?us-ascii?Q?yKpVgJB0+LAF94CnJfpVwopnMn0/p9jl9DqBeyBEibrvLVafB3oUYat9Lzi9?=
 =?us-ascii?Q?+PlboW5yyPM3v8R3tF6ZyHiRL9Exitm4zZdijmjDyRibG9NHC3a7OCT+u8oK?=
 =?us-ascii?Q?7jqBCFDT56QbaRNqpO1kHPx7/srpjJdW575kB3GQRatg1PdC9cj1S/SN0dT1?=
 =?us-ascii?Q?oXX8XU5BepLrvBr467NFhUMMmG/0lbcjUeaP6kKJUIIvvzLdfUXq5nIMeAHl?=
 =?us-ascii?Q?lcwPfxAjQBhFD6DjXIIRr+1HSuPjbNH8Lx2HDtTiICoh6uHlwsTWoP66u9mS?=
 =?us-ascii?Q?Gv9iYhOL+P/08QzaoOlSxSXG4ZlYOv0eFNYaRwK/+xB+DDGIGUxjI66RUba0?=
 =?us-ascii?Q?KYxnvPEj57XUCmmXTK/4n6LPwJeGLRS9ps7yKIdCB6iWkQEPqnyeBzqSW9Cr?=
 =?us-ascii?Q?muTnQ8Yn2OgxJcVs4ryzYoFiP7CctFKmTZuDfeIXh3CLI2sL3QheIATDhNnU?=
 =?us-ascii?Q?aMB5dgWZryDv9GCa0zPm8/K/KkJisw9crdjQ5/aRRoQ6P7ZtaQh9aTGBDiGW?=
 =?us-ascii?Q?wk7f9zF4m9CJnHSc/SkcHUQl2NqxDP66qDwKTgaQKDJolqKLD0fwA4yoolaK?=
 =?us-ascii?Q?j19GtYi7m4QLndpEeLRQA8HYXEPwZstJablKY2MJVkoJLIRfIr09SQ6xcU8a?=
 =?us-ascii?Q?nuRiQwaT/4WkvAwYryFTA6ZdxvaqXZfj1ExBEHmlpQhVtEvAvBDnxQ4QaP22?=
 =?us-ascii?Q?aW1cJY9aepQKQdHtEDJCp5ltyWSilcVYrTqYnmdf/Nx3qVc85EXd0sZHjr+G?=
 =?us-ascii?Q?VQCaXhQ3Q4HeHKnxy053s1kJDrVdAJ8+Z0TDPYcl1NeK9OubmP/nlumGRN2I?=
 =?us-ascii?Q?ykvMIeMRXmskv+veOJky8wjqIhCBNrw6YQvMEJSPQn4rFIMOqJi8+OVjL9GJ?=
 =?us-ascii?Q?l4R+qv3XgIrY0PrxBG8cN0CNEDgQh+Wtf5eSdBDnNHeRH5Aqqx5qxPv7kOMv?=
 =?us-ascii?Q?HRcEOGvfUAhYAEnZklTtjQbFrIvcAWoAv8J66SuxbJ4N3BttkJFh9l3D5+2Y?=
 =?us-ascii?Q?pduIyHlw6xHnIORZWySnmW76irQrh79993lISc6hh7NylrDm571z9iGg5+yC?=
 =?us-ascii?Q?13eDgmhUWu6KrV8rf7dVY0munn7EyfPpo9Db9pVi95hs+Ibjp+qTtyuquUu/?=
 =?us-ascii?Q?jefIyg240LuGywBV8u3HG7VKItQZZYB3d6eBG3nnkGySAxVgG1AZFr9LT1wJ?=
 =?us-ascii?Q?K25+EkavAe2lkdbMRP1RNncem0CcNKxIetUpvt223kMpZuck2Skc0YRlSMG/?=
 =?us-ascii?Q?RP4C3ztLydD7+1HZxijUKwIvgeJFOgJ8Ct+QcD7kgg6na65ekfNeSUFJreV/?=
 =?us-ascii?Q?3t8YLeDx0ec=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8PR08MB5372
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DU6PEPF0000B61D.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: d8123d43-a49c-4054-1cef-08ddd9e70727
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|14060799003|376014|82310400026|35042699022|36860700013|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?31zhvKgLcGkV9ytnAPiPKDt2w+LeHWdzDSF/vS8qa1M3cylfFbNTo3Sc4XzG?=
 =?us-ascii?Q?ePmLyN0iPLNBey9Y5WMK+WxpemV2SrQCiXg+CTbcbo1OG4Sv8mEL2kjj8GpR?=
 =?us-ascii?Q?Xidj90Xppx5hCo1V55YBk4PWYQLpcxbHoYSdFMW4lkRJa8wX9r/DO1ukRDbf?=
 =?us-ascii?Q?odu+q8FZHFDTpDV8EY/HqgwPxCRjHiZLYlTZZmcnydjTYO7GOnKCbDFWx9kN?=
 =?us-ascii?Q?S3YWCcYZVj9zuMuVsbOYHNo2G7M0hXZBw1rPDITnwCo1wKyLiJ8is6+ylapH?=
 =?us-ascii?Q?X7VZfNlWC6uaX2FAKzPo0jrFoAdlpLAWaUwwOjcowj9aqNa36l+Kbzvh5ZAu?=
 =?us-ascii?Q?z1xOMwlFu0uzN2AfcTU/XGx4VLlriCboHKLnvJzTp9bMrSNpwD5ybqgr148b?=
 =?us-ascii?Q?c4lxgLs2zHSDv86qpZKEYDrjk1jaTM1WTFOPvV7XVk/3PFx07LMgyMQZztL4?=
 =?us-ascii?Q?xhmq01PEH4Z65E1L8M/GD5Ptu1BDO5D+wy31MCLrC3hXikDWTij6o2sWOl8A?=
 =?us-ascii?Q?hYIY5PmrWC1Cn5WUz3m1olgLSEzd1C6n7gvzBCqqbAhcy9vNNB2bDPlZFLqE?=
 =?us-ascii?Q?7upGeVw3lyDwu64sR6QeWXgUd3JwSnH2MfmZYOWt5mu/zW4a1+HNXgP3Nzcf?=
 =?us-ascii?Q?ep+yE8+s5XBDDDEOzhyhmySzHHAiaXUunlYGoKd2Hlpg7RCx1hC5q3LmisUx?=
 =?us-ascii?Q?HQ8GYPoA55fYuA0HSpOBsCsGDmCHwXoWdEHs6qxBthK3yCjVK1qcgyEJ1abY?=
 =?us-ascii?Q?4zqlqto6Mfr/ZCSKIHkIh0WVOSpJFcpnz2HNdCe2SpD1aWy/XraCfLPDybpI?=
 =?us-ascii?Q?/uU8p7jlyos5NbC1M27Bp+YU16ILuvgpE7hvvT7i+9BaMVwJG9XFaVDi+Dxt?=
 =?us-ascii?Q?aer1ZASEtZviv3BSS6pLlkH5p6De34ra4txkz0nTw/zam9wQke5vLuq535aO?=
 =?us-ascii?Q?jCKFMxezx+FlKNsQ4IP4nKBYsxRJxfhCeKZ32SEvqqq8A0KFHsZ7qs/IUXKY?=
 =?us-ascii?Q?BMWHzcnj71PkNzfoMiCtf3muS8ckb6K+UyhSulz295wx9Jmn+JLuDLL3D3Ze?=
 =?us-ascii?Q?B9+u0Y3YFy1J2aZhulmQ4vwTWpeHMQYDagjPTv7+pOUVZZDN0eQb0fpsbvsA?=
 =?us-ascii?Q?LRYjJgbYa7W+KUsQ5C7IybivYbOVWB/3xHrt3Kq6neIO8Cnz82n+BWv2qCTc?=
 =?us-ascii?Q?3hVD4fjDPzKvFr9SE7SWLcZDhMOfb5wwydVe0RCB/EpObIvkEyKK2/wUyeEF?=
 =?us-ascii?Q?ylJWuv5tSGOQ/YgAUiqPE6nMW3Uweus/o4Nnghq8Jn8sLLY9A/WVFVnz7a5H?=
 =?us-ascii?Q?GquCZQ6yMqvbxdIacmupADm1CDb0qJG/KxFV7+PXQqekNU+M5X/yaTrdPFxg?=
 =?us-ascii?Q?WcLcwVAxP0B7ySLZh1MIM3+e4sq0BQp5iPjw/Ql/G9XhX1Ts9ZbQrdUKDJZh?=
 =?us-ascii?Q?lLQ2gyn2Ly0FfDIvgavFfEYRrnUnMie4IyECJjcvr7wSN0RGt2Pc+0pmju4e?=
 =?us-ascii?Q?MlWD2/PeDWJFoIRQFZfibQWdhK2VZR4FHSIP?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(7416014)(14060799003)(376014)(82310400026)(35042699022)(36860700013)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Aug 2025 21:27:57.1824
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: c1d80ff8-cd54-418b-1cff-08ddd9e71b2a
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DU6PEPF0000B61D.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS2PR08MB9618
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=qElVVzuq;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=qElVVzuq;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender)
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
> > > Right now, KASAN tests are crafted to avoid/self-contain harmful
> > > memory corruptions that they do (e.g. make sure that OOB write
> > > accesses land in in-object kmalloc training space, etc.). If you turn
> > > read accesses in tests into write accesses, memory corruptions caused
> > > by the earlier tests will crash the kernel or the latter tests.
> >
> > That's why I run the store-only test when this mode is "sync"
> > In case of "async/asymm" as you mention since it reports "after",
> > there will be memory corruption.
> >
> > But in case of sync, when the MTE fault happens, it doesn't
> > write to memory so, I think it's fine.
>
> Does it not? I thought MTE gets disabled and we return from the fault
> handler and let the write instruction execute. But my memory on this
> is foggy. And I don't have a setup right now to test.

Right. when fault is hit the MTE gets disabled.
But in kasan_test_c.c -- See the KUNIT_EXPECT_KASAN_FAIL,
It re-enables for next test by calling kasan_enable_hw_tags().

So, the store-only with sync mode seems fine unless we wouldn't care
about failure (no fault happen) which makes memory corruption.

However, I'm not sure writing the seperate testcases for store-only
is right or now since
same tests which only are different of return value check will be
duplicate and half of these always skipped (when duplicate for
store-only, former should be skip and vice versa).

Thanks.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJuxuKBm9qfpVkBC%40e129823.arm.com.
