Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB4FMTPBQMGQEFAZI7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id D88C2AF8126
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 21:13:55 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7d3cbf784acsf42069285a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 12:13:55 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751570033; cv=pass;
        d=google.com; s=arc-20240605;
        b=eXqLwNCr5jrM7zo0E5F3xNCbo6nMAltQ7UAFfb4ZrSOn2UiuHE3rVRfw2xbAdGhdpg
         80wUb4B4kpNTjnaHZHAVJFbsL97rJhSd7DKWul55dcZwEAlAlzurPmXXJwIYZJjCprDm
         LkHUyubTF6SytITeGDf7NdZVOWTR0vJ/xOvBHUXoLifNNmih5VAMiVxKX5ziCaJAiTS9
         N5VBHCpZfyIfbY7T/sDzxyISLOIhXi7RLMDkTdxwityNih/vB2ZXao6GiKrFcqD5bkSo
         2nkPno65Dqm1WFh9iGXEXgubS16QdDNDBllUNIer5QdUQqFrl9X6AC+tOnMmsz4pfZvN
         5jhQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=GZF2vUfDrPYk4jrWm1Y9kZgVsgAhCt1LLWcLa9t3u5Y=;
        fh=N67nbIlMT6Ql03dYKvDSyKD7/qpO+H/4lCmZE2C8h/Q=;
        b=ThIucuEwCKzcCFesew0riQ4Prgx8jMz9M2ioe26/GJBvc7FsiI/U4dVsh8MBV7p43A
         y5UN1CLZMsFMJ5LoWNKzKYQyx1Ij+781pfoCycOFe/F0PJSNJ0q83DNHYtlOCcEh20TI
         yyB8TqKDtnNoAxWGoQWrOe/4U/ztpyEeL0Fdom5DNIouV8wlbjOz+GU9eZ/Lx6B0xcow
         ED/7TqNbDzpqba9idJsdPKRiq6ckNKkawIWttxZagnq+1j5jWzPJxjI/MoJGZ7ZIi95o
         5VTlvu3lnWJA4n+UIBhvAUaXMeITWUHNAfiYZsXBK8hN208qyuO8edFKAd+KZ/ckx9Cu
         06WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=atCnQyNa;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=atCnQyNa;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751570033; x=1752174833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GZF2vUfDrPYk4jrWm1Y9kZgVsgAhCt1LLWcLa9t3u5Y=;
        b=ur4u0R/o6RVeFYcwbMEsG9zPNXte9+9uDs2oS7DPjpDJ8wHWpbUIBUZh+yStWrIWnM
         tAv06cRMgkIJMJi/tyupEDao2mufRTKfOOsibmnQvIlNwYYlClezaBZcCpheaWoWuECn
         tVorthvvUxjQguasITF8sMCII4cX6uPGfEExP/o7NPjRvjCeEcrSUOHqtbEUsQHcZ11E
         TYTPlcXzk7lXhyfNTmP0D9V9PC58cEAYxRl4hme0+bMF5WuvPNPDEQRfsOf5MgC2ZJPM
         bPSRV7TXeMwoWUvx1p9ERqx5kN143wpsPxru/a4Jnb2joiRg9IHWfZywI4WW6xV7EUi/
         RtAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751570033; x=1752174833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GZF2vUfDrPYk4jrWm1Y9kZgVsgAhCt1LLWcLa9t3u5Y=;
        b=OlRQseYuK1clEffQgVvINlXS717C209GLFK48bdVkTLhMKZJl/2P96QpLvdre2nziI
         xzQKgbJwEFswLbhhL+fZhexEqndLA9nRN1g9s5Qd0PI3Fir8nXuvNnwwzOHfAR/apnJ+
         2/Uhj7wQno8DU+tzvD5lwiZW1p+mWsS4mYNIWN6hGSiF6V/sBIo5sf5+WzTjPMqZGcRX
         ZlnxmLduvS5u4dJbjTo9WWDk9aes4ay6KjrQiszH3xyKLSIBlLzXBI/plvCh9TKl0qkx
         Eyu5OLuHW6UntZnfCb9i47NBEmhwrK7z04Qvsl5u0M0uEcF/66UMN3L3/3X8tk3S3UYD
         eB1g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXAf7wAC53bXGLjvdaefIwjjv0qwsARLZUS09WuVeE6AsUc1UkMJjuk9iqzkcxZg7H48o7SaA==@lfdr.de
X-Gm-Message-State: AOJu0YxoLzIsbpGx4XG4BMY50/mKlFTSt8tsQAW14xrqN0bfEso5PvbB
	mL0dS38axKLq3CCC48Lk+FPuRRZhScN7U2gWFMV81FMC2QLymp/K40Ac
X-Google-Smtp-Source: AGHT+IGnFvh1gsTkCgGJyCMq9iCytz3/y5nCLyKFZPBZJsvEdKxV7mExyaVTf+POhpj6UmAUfwc0qw==
X-Received: by 2002:a05:620a:24c2:b0:7d4:53e9:84f with SMTP id af79cd13be357-7d5dcc470e2mr12432885a.3.1751570033211;
        Thu, 03 Jul 2025 12:13:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdoBlUwmVmP0jB3b/MNdyLWhIjPFKVjXXvfycZnTfMnog==
Received: by 2002:a05:6214:ac8:b0:6fa:bedd:25e1 with SMTP id
 6a1803df08f44-702c433a51als4642606d6.2.-pod-prod-04-us; Thu, 03 Jul 2025
 12:13:52 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVByNLqQhBc9Hir6qx2hRM2/5J+x3LV0fKhHTU+29JyK7kJLm/a5pQpVsWD2gRK7gXSzJDlENq9XfY=@googlegroups.com
X-Received: by 2002:a05:6122:3c89:b0:52a:9178:d281 with SMTP id 71dfb90a1353d-53466733bdfmr4970348e0c.2.1751570032280;
        Thu, 03 Jul 2025 12:13:52 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751570032; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nqdka+tP6jO8UGVOZZNPkHrbJT0zDYiuoZfuHiRHPbLgxmKsvYYj339jE64KfoN8gi
         x0r0NvJ50vCjUsAsELCZSls/omm90itBbcGRPSggGyiDHt6LOSUE0V3dgN0+qjo4C3rN
         QogOQO9XvHsR5N9hrN75CyujhY2DXh5HBEGDDTGwxJmVhHbyJTQ2SlE2QYRvNBXX+9X9
         T7kCvZEDjkppJ366NYPONd/4MTTklZ5I7qhJfW2hJ079R/ZxjwOu4PVZvbOvxg7Bt7V6
         dg8OwnWLwWOJBYvtsSruDkioJwLN/WY29LG4FSzPSoxX0OND7v4JbzyzA9sHVrwxQ9HK
         bzJQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=h0sOspPCZI0ROLFeFkyrpTd/6rokrHAH7S/twcOb0Ck=;
        fh=teVbU8nGEqSyPTWfyAPTyK/MKJgTufGOm9BjLuInOvw=;
        b=fxU+teIHvsV15HE5CWEIFJo1ACgq2fNcajLajeP8GYjxm0JaTC4JilmzLefEbaeLiT
         stPrl3fnYaJc31swa0lOGLzfeDc1n9tH0vY1eUFzsEkOX/SqtI1h725B+GesXhQWdEzL
         5hBPRHL9Z5+0VS3D700mpztywyVx6qHU1/CoWFF5i/t6R0KmJemVyf4Hpqu7iLLGIjPG
         bbwFvceKIZlwppaRwSQnqtXmIU/ubB8fwhsMpgY26zjLDC4Z9Mz9rqaShWpTD+GGwxSM
         a0vX7EtMvhRswshKywnb9e8EXHc1nZYIdaeAhylqhuLw969uu1rWyp9Y0C2criVHzRza
         38Bg==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=atCnQyNa;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=atCnQyNa;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from OSPPR02CU001.outbound.protection.outlook.com (mail-norwayeastazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20f::7])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53478da5560si15217e0c.1.2025.07.03.12.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Jul 2025 12:13:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) client-ip=2a01:111:f403:c20f::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=DA1uvufoQxtGhiIc/IEUYEWIGtTZCu8rqTZJlCLSarLQmHAkMbOz2is7CpGwQPC+EQ7kRLhAzOQ0+4PWK6xxswUbPQXa+CfMBVy4G2nsxtjPwHxG4T4C8cxLC7w4zwsQN74g/on5q5Eul3MzXWljYIpSYWxp/NvmkjbNhrdvi0A/MWpZjlfEVooTfVfQQONxNGazmyObXE5VKIc2cgN2/iI32ko3n3F9dZxu6W4cAZMhT3s8fLerZHVHhuKIiWVbB62qYKzyW3vpKE3bQ3Fz0uIdXVJ6Dhhj7En5EhRFxt4FOgIKTgQYLlIPUOV4bpA4spGc1vbqNAm5WCzDUDyILA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=h0sOspPCZI0ROLFeFkyrpTd/6rokrHAH7S/twcOb0Ck=;
 b=ki8LxLJ3Zh4iDBugnWIKe2lbiEXcLYBfdefui/kDWqn04BsPrqxnP7YHcijL8XC9CZTLRT6VrM0vaBmzo6geOcKWLzt9DK9R4bnmTxZpQv+xCwJ1cCmfnOky2a76CwHpY2KM7IRbbhhV5UaPLkHHJIDYYpt9Qk2ynzFNFaXfKLjk1J/9K2oNuorTDTwHNwR/BUFwjL5hXN0vBboDk9qySeZCNFkGHp9S1nqsZj2NBB/BNZ/6tlwwKoe0BRM6GHo5bRb4wFvDZE9L/1RS02zGMZl2dkO7pTQ+817wTPqdYQpPNO5OlzJZEzy5vr59zybXdKryb1ajjA80RRURbBuRfw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DB3PR06CA0012.eurprd06.prod.outlook.com (2603:10a6:8:1::25) by
 AS8PR08MB9905.eurprd08.prod.outlook.com (2603:10a6:20b:565::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.22; Thu, 3 Jul
 2025 19:13:48 +0000
Received: from DU6PEPF0000A7E4.eurprd02.prod.outlook.com
 (2603:10a6:8:1:cafe::43) by DB3PR06CA0012.outlook.office365.com
 (2603:10a6:8:1::25) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.20 via Frontend Transport; Thu,
 3 Jul 2025 19:13:48 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DU6PEPF0000A7E4.mail.protection.outlook.com (10.167.8.43) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.15 via
 Frontend Transport; Thu, 3 Jul 2025 19:13:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bOlXuJYn7pydu8fDoOh92bjDDrlsgWH5zQdq+W6sujdyOGLjhdyqoJ6zYLXpIJEqRiUHESrexEdxwK/g/BX3eXASyolIbkvPGczpZSYSevS1pMViPqq6roSpyY36WwoiassQGk1m8O5QkvTE8x59nTK8Xw+u1qrfECuEneRFmKxTg02u7RC5WmawjOwVVIVRQYuT7HHoum+CaaTBpJsh15Gc7ew1TYcs46AVo2ucUhNY1jnHtCIGiGoiVz242qrOwMnx4eImiz2/wxnSdkMeaZUqukhaan9Xv9ivYfJDYHBsAH+99ASKYW+4UJVI2DYqzed4IfIRTZ98ibhErZDB7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=h0sOspPCZI0ROLFeFkyrpTd/6rokrHAH7S/twcOb0Ck=;
 b=IYDK/I0dzREWUphq2jn0cVn3F4hkHoJkzxKnQkHQ/WEw1TjTS00gnvpenZ+28Dhxy2YyVs8B/44fcKgBY9FRhpzzP4Vl9cJYaHAqOpOOGuVMXCQX/458Q+ZBlyPIJReefth+ctFBPkrF+vr5z6wvoLRgPZwoXPZB3mXQFhM/Al+CHdTUkB5o3FZ95x2l0imXXeZhGx5R4VTg4VfzBS6TjM4/pRGHDefsYxowsKCKskRdgu2LAKB4zQZQxb8N1ctGv5SwhzDKrLbo+H+Wc0wxXhH99IBPyV8gbBIdNOZqm3kj5UeDBm+30uKK2jVfTwn6YQAPlbveNkLhEj+RN+Kr0A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DB9PR08MB7557.eurprd08.prod.outlook.com
 (2603:10a6:10:304::19) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.20; Thu, 3 Jul
 2025 19:13:15 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8901.021; Thu, 3 Jul 2025
 19:13:14 +0000
Date: Thu, 3 Jul 2025 20:13:11 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, bigeasy@linutronix.de,
	clrkwllms@kernel.org, rostedt@goodmis.org, byungchul@sk.com,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <aGbWR+Q8XHtpdc8P@e129823.arm.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
 <aGbSCG2B6464Lfz7@e129823.arm.com>
 <CA+fCnZfq570HfXpS1LLUVm0sHXW+rpkSOMLVzafZ2q_ogha47g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfq570HfXpS1LLUVm0sHXW+rpkSOMLVzafZ2q_ogha47g@mail.gmail.com>
X-ClientProxiedBy: LO3P123CA0006.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:ba::11) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DB9PR08MB7557:EE_|DU6PEPF0000A7E4:EE_|AS8PR08MB9905:EE_
X-MS-Office365-Filtering-Correlation-Id: f0f66b24-01c6-444e-4797-08ddba65bd0f
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?Ad0/LpFCRHKhs89PZHxxlYSD/8MScxFPm2fR932ncrkavc8XuGv8Ug6TMYC6?=
 =?us-ascii?Q?j5YfIhse/T4YD6HWGT0EDsgnMuzoOJ/JERF3YAKZ58Th3y88qtm6b27wXok/?=
 =?us-ascii?Q?GRCiuXQgBseWbDm5ri+AECr1bfhD0LvKjwnXn1KT7kTUzOxU6G5AONvR/vIa?=
 =?us-ascii?Q?ufDgqStPN/RkvAz/Km5FBJL8x4Az2MUdCzgDjZaq6HjMfnS/JavY/BtbK1UM?=
 =?us-ascii?Q?fV8GxDWptYGbi1ylKCGVtH7D0J80ilJ06PEtCUk/zWRB+roK+bpXuP+bhFL0?=
 =?us-ascii?Q?HVzpccVWISZWg6wqzDykvXkKBQ3CaWmSR7OBZyyReHAvKdNyjeK+JgzStto1?=
 =?us-ascii?Q?WfGd5vlfjR2DFTMJ05vGEnlvW2pEMOkQqkDuizLE7xm/FAxC99SXp62vLlsn?=
 =?us-ascii?Q?NXbJJQk9oWXsyxiakv+4t56oCTo/kb+jxIHIh7zh7AABnmf1QN7yE6eti2e1?=
 =?us-ascii?Q?3YR2lgXEsf6tCEetxRoa+nBb6nDLIuStfR+6xrXWH6V9NCDuivPexlJErXzj?=
 =?us-ascii?Q?jWJ1YQSy4L10LmBS4IGBCRbf7HYZdFeKt0RLz5tXIRICTviDP9O855AeFCCM?=
 =?us-ascii?Q?YhYgk6wEnf19hQUjupR3Mib4yShv/Tm8eaCQp+luDTaRxIRfLPCbWaUB/1hy?=
 =?us-ascii?Q?k9x9BThUG4EBpgcuXfbkeKSoqNGPRe+iMO8mV+gPgzsyXb+Js/MMPfFc3KeZ?=
 =?us-ascii?Q?yqX+dJukYoAZUCnsLdNWhilGTD1GUadJ2GBnQlqSHIFPgwrnfxDS5+KAjZkJ?=
 =?us-ascii?Q?/JGBOxX32zTplznNVvhZxrzfkE2VhoNXYe90s1DqCWW+/KC0rwQa/Zp8sL3S?=
 =?us-ascii?Q?7PvyawTV7cNBqx5l5d4Bb8dtinLyQ2lZ+G+3bh+ueaEWUpd6fdyGi8AMrlgb?=
 =?us-ascii?Q?3H6PBM2NjA0YkgOttXTJwJDl//mniA0u1RiwBnAk+MA6x3bNzBj00ShU3jzX?=
 =?us-ascii?Q?UpePECvP8xrppMl53tqMJct+wNwzaprM8rXP61u0JumuA72yw1/zogYUftXB?=
 =?us-ascii?Q?yjufOCNpzGHZ+5VwLUcCYJHur8TNo/UaSfKSnY/i2wP/FnVX8pkBWTkZ/dxM?=
 =?us-ascii?Q?jClYd/S2wqS+H7XwRAYICFblXRXKlna0zXhCHeb7lvXGPPDDPlgwRmzHPkrZ?=
 =?us-ascii?Q?GcdBX4Ql9CiiWzBF8qmVM1AN+XC3AMjo4oPNI0fKJWXFTmP6TQpBDHPdYDK9?=
 =?us-ascii?Q?EM6c6T0Tm7eqUHwa7maKbx+RqaFLvl2ab/MmGf4zwinWK8XSU7757+TEdNkh?=
 =?us-ascii?Q?HSoOw/CDLpwXdeownj88tp3NhXSa6UGdEqkgcENiphBynctTegipv4AvDCWn?=
 =?us-ascii?Q?G4MfEwJXX7RWviEa47BdM6VSkAwxHuUXF5tCdQoeyKcHM15WKB0vk/xhov+e?=
 =?us-ascii?Q?Srdyic2KYCQlWHZjdUzVOnn6hBcWhn3UtNZydURd0XzUXVY1d8vE8aDS2v8o?=
 =?us-ascii?Q?4YTpo5ENkD8=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9PR08MB7557
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DU6PEPF0000A7E4.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: c54d4424-9172-4258-88f7-08ddba65a8f0
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|82310400026|36860700013|14060799003|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BBLztpCKyGUG5lzUY2HRbFHz6MD8fwzqFN+Vcnr5AADFOLXViW/w3zbgjLj9?=
 =?us-ascii?Q?655uwqqKso8XNT8MRwvuhI+5OSdzyD4TNu3DNt1fxLjR0aptW7vL4yxtXBVW?=
 =?us-ascii?Q?++r7HrSmf+dbY3qS474BQAqRRUINsQOPIwSas5o/+qZxj9y2ZvYGCV/1OGtm?=
 =?us-ascii?Q?4OH3xkTJYAS9lHGNCwGt082oeVzPhDbRkf+u0CtJbMCdr0gSl2utd96tgntz?=
 =?us-ascii?Q?nHJ2LQ4CKYkboLwjw/ysw6V/bmE4XuXMzR1HdGLLL9gf3PqCwLnmtM8Whd8F?=
 =?us-ascii?Q?/yt1VThxZ48RSIKGXoZVzRVKODcZ4etjYJB3jLT/FzEXcOjqndFrxrgBiqD4?=
 =?us-ascii?Q?J+JzMZBqW9sH0QnImhj1+oOMRJ3Omkt1ZNlaBMCdP/jk+V+MNpAZ/dbXPHTc?=
 =?us-ascii?Q?W2dWG/2EGoz4qaGvgysVLhxercFjs+jm8oZKWIVkvcbh2v7nWE2ssTWL02kO?=
 =?us-ascii?Q?ZS2gRm8ETUFDhhR+s46j7deQnRzj0myMgTwoj+yHj7cud1oZ7b0OQNFPUNAm?=
 =?us-ascii?Q?/WyiNwSfmFbvkdJqG2H8NOgPfOy4/6F4282It9vZIaHZa524TOJATHkWr1F+?=
 =?us-ascii?Q?9i75K2phSsRilKe3AScEFwACGE4voUhooE75WhG6hb3AnSDzXH7TEceQgOEE?=
 =?us-ascii?Q?90cjpkUyV5lDG8YzLStbAIoZ8eUHBZ2LiLvDqSzuTM+j/cHmIh+xrGlzdqtl?=
 =?us-ascii?Q?evNsWYQ0rpdFGSwxHzxOfoLpiPtJX7uY/Wdo4rXLJa4mQrI68LScrMhPzG4i?=
 =?us-ascii?Q?NxiLpMspu1gyHLsgFhOp2PCsvumNlu0ecwJcMEQ8ShuxS/QlnHZbiz/12zsL?=
 =?us-ascii?Q?J0aSqOrQjmBAlSFZBH5PCKWNnWk5MxGetVqFkMOwoN6OGwisWJw+GUL4AhyG?=
 =?us-ascii?Q?Tt7sLp2jSbA1KG+6PlQabuTnvu26tC5Qjrd0ZT1KASGeMNXcPBmx8c0UWyPU?=
 =?us-ascii?Q?jBZKMHMxHV2OwYfEe2lgZ8vs3Q7E5al2E3GzCYbs8lvOozb6Pz2lVlSs15ts?=
 =?us-ascii?Q?sVXZJiwmNbgT28F59rduGw0xSvgx/079OnzC3E+4VhVydimDU1veWZVHbplH?=
 =?us-ascii?Q?cC3Lr3izI+/lVtKo4CjV0YVx0iJYHaElweovdujcpKUFgPms/r9GWWpNAKBY?=
 =?us-ascii?Q?QZNpZJFd9dCPOI5OGgwtHQn5w61fex2wpsbN5bcradvNtek9infCKzTp8Exw?=
 =?us-ascii?Q?kEKPiV5Lt/ipMSU5cbZP1qaQ/Uw4AV3I+9LhyOU/i5vVPVrnQ6wq9LQGK3HP?=
 =?us-ascii?Q?MQqNyveslXxOvGuk+CU8A+YQhQ8XhTLg6h8a0GZtwbEgW5p3Q5i8YbEipsDD?=
 =?us-ascii?Q?Kn9RU4EoYw43RKhFIZui6G4qYZoTONbgTJUQc5Y95hHRc4YKU86JU3zVVT8z?=
 =?us-ascii?Q?qNDBuqXN7+U1PI9lKLDBa4YrVtTm3a9WSuWmigrYoGB/eJ44xotpsthfDatL?=
 =?us-ascii?Q?vNJI0tj0jQNXv1P2KbLFsAzOGT2vtfYKtqXpxn3+3J2Uon4iGjLLP3WWGw82?=
 =?us-ascii?Q?ihiBPIF1anuzQVvAJMkYVvnwNn4qAEIiViYvKtg+zBWj7C/wkA3EPMHRrQ?=
 =?us-ascii?Q?=3D=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(82310400026)(36860700013)(14060799003)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Jul 2025 19:13:48.1871
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: f0f66b24-01c6-444e-4797-08ddba65bd0f
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DU6PEPF0000A7E4.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB9905
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=atCnQyNa;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=atCnQyNa;       arc=pass (i=2
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

Hi Andrey,

> > > > find_vm_area() couldn't be called in atomic_context.
> > > > If find_vm_area() is called to reports vm area information,
> > > > kasan can trigger deadlock like:
> > > >
> > > > CPU0                                CPU1
> > > > vmalloc();
> > > >  alloc_vmap_area();
> > > >   spin_lock(&vn->busy.lock)
> > > >                                     spin_lock_bh(&some_lock);
> > > >    <interrupt occurs>
> > > >    <in softirq>
> > > >    spin_lock(&some_lock);
> > > >                                     <access invalid address>
> > > >                                     kasan_report();
> > > >                                      print_report();
> > > >                                       print_address_description();
> > > >                                        kasan_find_vm_area();
> > > >                                         find_vm_area();
> > > >                                          spin_lock(&vn->busy.lock) // deadlock!
> > > >
> > > > To prevent possible deadlock while kasan reports, remove kasan_find_vm_area().
> > >
> > > Can we keep it for when we are in_task()?
> >
> > We couldn't do. since when kasan_find_vm_area() is called,
> > the report_lock is grabbed with irq disabled.
> >
> > Please check discuss with Andrey Ryabinin:
> >   https://lore.kernel.org/all/4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com/
>
> That was about checking for !in_interrupt(), but I believe checking
> for in_task() is different? But I'm not an expert on these checks.

I think below secnario can explain why we couldn't use in_task().

CPU0                                CPU1
vmalloc();
  alloc_vmap_area();
  spin_lock(&vn->busy.lock)
                                     spin_lock_irqsaved(&some_lock);
    <interrupt occurs>
   <in softirq>
    spin_lock(&some_lock);
                                     <access invalid address>
                                     kasan_report();
                                      print_report();
                                       print_address_description();
                                        kasan_find_vm_area();
                                         find_vm_area();
                                          spin_lock(&vn->busy.lock) // deadlock!

If you call in_task() in CPU1 before calling find_vm_area(),
it returns true and try to call find_vm_area() so it still makes a
deadlock situation.

Thanks

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGbWR%2BQ8XHtpdc8P%40e129823.arm.com.
