Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBMNETPBQMGQE6W3GHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EDEC7AF80C6
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 20:55:46 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3df40226ab7sf4708525ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 11:55:46 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751568945; cv=pass;
        d=google.com; s=arc-20240605;
        b=SVcr8op8ggKMVfFstevJCuSB4Kf5xk9k/TbNpSleNT1Jb5pzsLdU0noOnEE6XYsYuK
         EHipcoeJwnufqlTvrRS8lkBnaE++ugmRXp0XvowZeG0z/alRO4dAJawN+/IFgPPpUVxA
         lhFNNrRy9xVhCsDW554ndYbBYhPYQwL+GBZo+S7rX1XOvpf1bDbQfQIZfwt6CFXMF2RX
         ijvbrREXA4eO4B5QmoavJbhRKalkf+2enLwU4hvwRVqM1d8gSNOhFCeLg5A5ujufi5Zy
         vOXkmGpcdAmoBPa8kP37oHJVMX6NOzflH2he3YqHkl3ucas310GVov+Ykwf7oiZQ/GHI
         mmCA==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=qZmbasnNZiSR/TNe2xcEgfmR7K5gqNA2cShiUDnBHIc=;
        fh=pB3fZaq/3lz/NUKdqJPl1ePmcz10j/K+9GIR07cmk2Q=;
        b=gRBzT1pBAPfNp8jSxWDu+0n9/j24RRFruwjEk1TMaKR4cS2ecb/9exesMg2ESTJH3G
         Hj1KiTIsxgSb+YU4OCxyUq2j9HFqWYrImWGMAfZOLrU68KuG1xojF+XL0Dnyt56UKNJC
         BjHsGz4LzLE+nR7CS1gbWD2KQqPCKtvi8Tmj8/9hDot1OfVxVHUmYqwi3RoRn04sdjxr
         FBlSOHbanb3aRhqmVSruc/FDLiKcWu1+IVr3I7q9Sa3yqnhUR6sHGD76afAozn/v1BD/
         un+P9mDs8khEHBovVDUWt7McSUL0vLbUNGByo/z0ediHWE4DqI9CfSo1KO09yHmt6vuF
         VUsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=RChKMpUx;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=RChKMpUx;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751568945; x=1752173745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qZmbasnNZiSR/TNe2xcEgfmR7K5gqNA2cShiUDnBHIc=;
        b=Tvnfq9oqriEnyVE9U5XjCiT8Pc9/TFBd2rrAqsfeuGtN6JlfhbIcaTKirJ4MLzV6Zb
         Yk0f0tkE9KuRUgSPSOPwpYXCblABg6hCwSy4MJJwlHMrLJLlY4b032sESBOn/3lHCeKz
         mgrppuc8YQsWREqW8NnMny5VX6Pc91G1pc6WFXgQ2dkWrkTtW+KnVfgEwzNrGCpmT0l2
         EY2iTVd3cAD/grOXGd0h7MkUkS0I8aoyV/gLdlAUPzHVHSrv4OXP7bWQyrYNpQv/yiZp
         ISDBm9DMn/IlmplaFrKxvraraZ7WA4tsF5Pe2zQ3HXPyisTpgRz1+jfE1+84pvGYm883
         w3Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751568945; x=1752173745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qZmbasnNZiSR/TNe2xcEgfmR7K5gqNA2cShiUDnBHIc=;
        b=F/J5b2wsfHCe5bFATa377S+1598ZUUte5AZMiwJOG3ZZYZ5Oed8ScXnE+nADg2g0Dv
         leBlRLJvUND7KdPGm+fCWyH8jZb6w2vwNQmAIa6s+QgDIQYBBokt1mYw49+KJnSWOGGN
         gmrxjfZneJmJC5+TjTY86nJbffvFa34yogom8KYC2dV+M6XTjGHxmb+1A+UkVZBKZ0Uc
         O2JMu9rcf38lWl788tfsTlGdbQi7MfrJxUjqBBHkDzALhjrSCCQYOR0eOf47/qvXBocW
         Lqq/gPTxy7WMklHT4NfefeQhhSvP4V/E2li3776M98nuaC8cwx/GLMiUW6Lg01Emshhp
         BHJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCVAgv8y5RcDJsTDkvOYYZVuE8bdmkONzLBWt4NTHMYVzVxYg920XwIx5jtAJ809V6cguS2nTA==@lfdr.de
X-Gm-Message-State: AOJu0YxSon3hz1AVcPFAGbsEQqWF2NW3G02Dw0mFO/poaRJOzGBrHE03
	3QmeXHpKu8fFE28qIpq/Yt1ejBbOEyvOtnxibwDhCYZMDad2QUmYxCWo
X-Google-Smtp-Source: AGHT+IHglf+uh3dWY3gkaNauHK5W1n33XtIJauBeLeTJMQw8MT4Rkm07/BDuSR68tYIVFHIyU+Ed4Q==
X-Received: by 2002:a05:6e02:2403:b0:3dd:ce9b:aa17 with SMTP id e9e14a558f8ab-3e054a36b8cmr101150445ab.20.1751568945334;
        Thu, 03 Jul 2025 11:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdORqH4/JPdXEh4GPpJiuvJ0nvI1TcYnO4r2I7M9iOT/A==
Received: by 2002:a05:6e02:4708:b0:3de:12e2:fba4 with SMTP id
 e9e14a558f8ab-3e0d222357als2895055ab.0.-pod-prod-02-us; Thu, 03 Jul 2025
 11:55:44 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVI8+YOn9PzY29k4BqEkOgGrL2jokueNBdL1uPgw0C7X2TLTB4bOXp6Y1lExbfTssam/yIaKkgnPLE=@googlegroups.com
X-Received: by 2002:a92:ca4e:0:b0:3df:3bdc:2e49 with SMTP id e9e14a558f8ab-3e0549e5af3mr101762705ab.12.1751568944479;
        Thu, 03 Jul 2025 11:55:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751568944; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kq50ih6zPbOXr97ajHZqiLFcm6oT/9tjvkNZVME/FynooALrjQx863fXKx+qVkx6RR
         1D4uxx67Q6AZaYGgRYmMEz2vFIZEl7Ju1jfBzgFAkmaPAw2QCjR9r+hrsgcU0vZpnI7L
         duA0lsbVY/1rswIUD52UFqaYi7VhNLWJUaSTzecI0MxtX9CNWsQv20vR4XNeBv3+QgKu
         KOSsJ9ZnEmThfZKWTrXz5RQNalxgqMnWW/dCJ/oU9/XjdgnxhYnSQkhs+yn0/im7zwcj
         ic+hkI+WgDMR0N2H3MXWU3Q/j7Qck6TKhgLyWK5Rev8q2MOKPBwwnni2q69hfrS/lAW1
         VQnA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=gZw4qscm6Odl02eAKUFBl+K4BWWENTOF8o7MLivTahk=;
        fh=1X3XrfHOzKEo1IarGcqbZugxljYA/D5wEIEQU1e3iro=;
        b=gbZepB0kr2bq6STmCKxSi65gGtGP0rgFQ1GQjzwq0kzoxRDFPwEUiOj2skz+DF8Rw9
         55hOJtPZGgUCkYe9KYLxUmyeVvc0ZlOGYyWpPNaxxu1B9ko4z3+DV4xcmFUMCgmMHPYv
         Ba46II+K8N5w04W/4TYiUCbyYv0JlPEPEGRcaAg8+y7YfM/lcmYlVunCG72sevJCTM28
         mNJhx+xtCnYU5wOFtLsV03sT2gO73QGp2kB62Gd4Iiq2B3o4LjGmBwICcUPk5Afbooqj
         69NY6g1WCzYHasEXIbkiK8FiVHylFHPGFv2CFBpwrMYf2USPt/6xQ3/teD/vZeg33QDI
         zHfQ==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=RChKMpUx;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=RChKMpUx;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from DUZPR83CU001.outbound.protection.outlook.com (mail-northeuropeazlp170120005.outbound.protection.outlook.com. [2a01:111:f403:c200::5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-503b5b953e2si12939173.4.2025.07.03.11.55.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Jul 2025 11:55:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::5 as permitted sender) client-ip=2a01:111:f403:c200::5;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=ZP8CMtMlA9MWEamwrTkIORvbCkBPY14hYLpKgrTfuUlMGYdWWEvS5xD+itHaMiMDPw3kQwLrob4MheBrAq+QIFjjZCcWfsc7BSeTwv9OQybyfIxQUoQANSS4TU3M4x/EJKr1MA5nY4jEaa6OLcbcAl1v73MO4NnC9RytN7uv+skMUlOrV2mjJgdoBvQguASKPPAQENEAK44Pgq6PeIsiIPlXAa0r5NYEAErW8rTESdQWRaaMjYSoMql5OKCCiJhA2iulRTgGWKVBU8sHGghl/IxrDx/x0rM5zEdea//VLd8YmSa9lCmGh6ID/CLPxHkKgOrPIX5Xtw/qMJxDZkDfEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gZw4qscm6Odl02eAKUFBl+K4BWWENTOF8o7MLivTahk=;
 b=AX4rB1l2iu3uWiOnoIBVvSFhX/13n1u4CGQikX6VbR0h/tv1vuyLItrGwRcPHimso5YYwNmytcNJD/5EXm7cOcj4D/3t5+iQgxqAYmCXI4OkBmXzf3yBxR6eKs47RkC6wd/X73GzvGt/cz/bgc6nUi+MNUMmVGvaqSLZylsGgHzDUiK5ek5ufnfQwt+VJgNWxgsyehlAnX2sjhwrsy4aC9kkkPE+cvs1pIHeGgdPUzWztmXN7weymtmfWJWTFF4R0GMC1B2gDECIbQEiWD8fJ67XSv1ewwOOpVlIewD5rI8k9fytO+/Kgjj/UrQC5k/qwbqCycbl57lx+hSjowP+3Q==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AM0PR03CA0024.eurprd03.prod.outlook.com (2603:10a6:208:14::37)
 by FRZPR08MB11024.eurprd08.prod.outlook.com (2603:10a6:d10:137::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.20; Thu, 3 Jul
 2025 18:55:39 +0000
Received: from AMS1EPF0000004D.eurprd04.prod.outlook.com
 (2603:10a6:208:14:cafe::35) by AM0PR03CA0024.outlook.office365.com
 (2603:10a6:208:14::37) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.21 via Frontend Transport; Thu,
 3 Jul 2025 18:55:39 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AMS1EPF0000004D.mail.protection.outlook.com (10.167.16.138) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.15
 via Frontend Transport; Thu, 3 Jul 2025 18:55:39 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IGNOfibb+sZM84Z0SMQvOdN0j7hb653XqzcYIiLeOuIcbXDORhXuzNjYrZRJrV8Z7axf1sK7pdvmht6DXtnIZCd0Ky0Agi5CZOMzKUo7C41EUZuUxmdQPwCNMmxLSrADFWZ5azh4vC0K1knd4Y9Emv0xok8cfIHH0TiQjgPiJY6j9MDQWQTRAtewBr1m3MUZdf+dWgIB0P4xo78QZpnoqzaDcYA+/foem0rjyFNSgGUsJosDQhcA7MYRXbv4HF55lX6RHIl2MWEnl8MN489jsUTow8A10p2cg9bemdJ9KMm4UR+FDZsHkeoh7J42aFfSPAGCeM8RXqzpKLfmlkBBQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gZw4qscm6Odl02eAKUFBl+K4BWWENTOF8o7MLivTahk=;
 b=IMaKevwB2sprsD0KbjGFbloYmwc5J12jw9i5QtcZRniV4qpcEppQWd7EChP+Q0IMUbd19rKp0wV9l6iHupA5a3MxUl+hUe51AVikCO5OQDDqu8iMeMfGkXjysnN+6YiJi4QSp48rPaP2ojbpR6FX6/eSVqClOxA/AKinhUhkEulkaAiC3miitsJK3+gGkrfeBv8B3UsAFoJnm9dAb3/VIC8NhR00G6lL2xLd3Qyp/cJDU5vcKGAde2vgcRR/qQwstS8uaY6Q690KMNSE9Mu5WntVvpumWMLgFEb36u16UF/UkBXSX0pzIheKrxNebkFpcYa0UpPbldN5gw5i5cVs9A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DB4PR08MB8077.eurprd08.prod.outlook.com
 (2603:10a6:10:387::10) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.22; Thu, 3 Jul
 2025 18:55:07 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8901.021; Thu, 3 Jul 2025
 18:55:07 +0000
Date: Thu, 3 Jul 2025 19:55:04 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, bigeasy@linutronix.de,
	clrkwllms@kernel.org, rostedt@goodmis.org, byungchul@sk.com,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <aGbSCG2B6464Lfz7@e129823.arm.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
X-ClientProxiedBy: LO4P265CA0118.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c6::8) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DB4PR08MB8077:EE_|AMS1EPF0000004D:EE_|FRZPR08MB11024:EE_
X-MS-Office365-Filtering-Correlation-Id: a8f47e9e-88e8-4222-b6db-08ddba633422
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?btdki1ZELYEVhsFrjZ1om64lXz6dO31IxQSW7diTMxiyhT2SHgKzUusBFj5h?=
 =?us-ascii?Q?0iFPa0x7yOMcD8wa7E5QNHHDRQdsrG9Dm0M6hwpKT0YLoDX/Ybq3xlozpXH3?=
 =?us-ascii?Q?teiqu0FSl5GIEqQOOi7MfX5tHdz9FBRsgt+A8NENOC+lvnGylxec+rV6KQbw?=
 =?us-ascii?Q?t54YaiW2odsHsNt15KKSDn9W2aNnvIkbAE7zWg4i/yZa4lvIvX9Eo1iNWpwu?=
 =?us-ascii?Q?ObhheZFxr/xPuKJa8kTqd9ENkjplcuge7U6xV0U8lD1MTz1vXPfxB64By1Up?=
 =?us-ascii?Q?0Xr5YjVOFmP0I/9NghKC+6F1SNEuwHJ/4ZWioWqBNmA0y9ylBtMeXJOt0SdX?=
 =?us-ascii?Q?h+iqYsn3WvK8uCGup3zZhrOpsLA70QmKW6g6mgjKMTGuqLWUzJlxCh3GnEB3?=
 =?us-ascii?Q?ZHvwHH9bsAUIh8GGu67UhwLU6s7RkMi2+M1RE/Mi6tC7ZpAwGd6h3IYPSmhv?=
 =?us-ascii?Q?tPQzdw4lmEijn0oEkCAPrsFBRIK9haPm8P090ORsDSViaTCejlrd7NvXbx8S?=
 =?us-ascii?Q?VZBHUFCD3CP2Itgm4lGZAxfn7nDe4pdXQmg9KV8Jsg73TZTUTj6uWP/Ie7/L?=
 =?us-ascii?Q?JvHzbEZtjcHksBJKupSgE+LYS+Vbsr0EX2xx+wK3pVKiFI7FPigkudpIHdPO?=
 =?us-ascii?Q?1YQ562E1b9GF0oCmE536lxVybZVHikL1F/Gtva1Aj8qjA/7mbj5mZZJoOW53?=
 =?us-ascii?Q?PTS7VzvzFCxzq/F7JWUkXOf2jVcdKVWszqAU4m4g48iaiZx9AoZdvkCtEZoz?=
 =?us-ascii?Q?AkPI+IbqkfO1xYTA0B3zSqk8fu6TlUExWlyIVutaMHCt2CWSpbDgBlR30OMZ?=
 =?us-ascii?Q?OvrFdLH0qCWQH+0BSjuaJQRTJyM2fBqc9AQ+kRNck8sLMHAsiFw+H+DInSOx?=
 =?us-ascii?Q?xGdq+qI8uXNuBRq6FbElFhLtwSmo4Nbct85REu/QHhkAw52vRejif5Rd0B15?=
 =?us-ascii?Q?maYX5HN6c1wZU49Qt2haeCgQjg3bDoPWG7DXj8NXZ0Ik/rj3/Mm+vT0GkpG9?=
 =?us-ascii?Q?fLgEu15kJjamZy9JZuB1PymaMwKs9ZQ8+Q/vmY4GcbinEi4EyXkjaJTz9rGE?=
 =?us-ascii?Q?u38N3YOUExYiOYFgABeeP9sL5vX4YNfsM2yj2Kj0PP4wAPLNKgM1JfCYbpWT?=
 =?us-ascii?Q?pIi2yNEv3Q9Rk6Ue8hiWs+Jk8Ll1l22rmv+vF9Yz8UTrt1WGL5wsnFDNfFQ3?=
 =?us-ascii?Q?R8duMVfgy77bTJG8YhRRleFFR4gJJTeTkyyDx9NH2zaLXTmlpF3jBlCWrfYu?=
 =?us-ascii?Q?PrP/pkWe18JZV/kuAs01u9N1JaKpQTqu/rd2CM0J4XD3s0tPVoVVVNnUUO6Y?=
 =?us-ascii?Q?sLR9KC4mIftQmaH2puJVscyKH6FZmMjhKFyf/644f6f1SE4uhHlwPceLp9wy?=
 =?us-ascii?Q?NJw21DlOJgbeHLLxUzPfINICBsi1JUkq6tPX0k5k4eBG2YEi82LBDsNFf7lx?=
 =?us-ascii?Q?Ztkeq085NAA=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB4PR08MB8077
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AMS1EPF0000004D.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 14534c07-9a58-488f-7397-08ddba6320a1
X-Microsoft-Antispam: BCL:0;ARA:13230040|36860700013|14060799003|82310400026|35042699022|7416014|376014|1800799024|13003099007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?HnMHFhlFNScq6yV2vZ6S3/ku0RTpbkGEYYHK/XuEG9jJNzYXpseTlbqLAaKN?=
 =?us-ascii?Q?MxhYCmQiZrDzKB24sIG3lIa537HATdxvb7aTQy7Br6vHr7O2EBsMBbEX0Xg4?=
 =?us-ascii?Q?5wRw11fOuWpWS75j8YxlqZVqNVTPj7I1sSz2yS083gFEWctjKbcCPLeeuq6t?=
 =?us-ascii?Q?CO4VhBJGuNzOVlihexLkFl8QRzqFAMYO0EEHES2dI4iV3FbIbsEMZvS68tQY?=
 =?us-ascii?Q?2b6MsmaenboRBt9NAGxCvFmxQiBMstkCuR9tW3ebkGY1c1Sfta6KZG+pOHGE?=
 =?us-ascii?Q?Exc7T0CYMgluuR3Izd8VS7+xE+hYLGotpwUz3Hp9AG3T5Vi6/v6bylBVLf1D?=
 =?us-ascii?Q?lKv25lzc7XXy6ICizW20YyXzGXTlxYa00c8oq2SY+NDT+bxPsTxzOWQjqpLn?=
 =?us-ascii?Q?+Oxk9WdN75lI4/c5mvdaS+GbQGdb0HsxO76vMQPqqCsBFyle/8GYBsXCSu9U?=
 =?us-ascii?Q?9yR9xRvScWt2yYpKRZjlWjBJmzK4xi7eO0v5O8vB/RJZoPA+mpn/7qOmcZcP?=
 =?us-ascii?Q?lSfG/ZK+fkJuOWEebMJOXABjoeFTnkiUaevBHVei+85xfRgrG0Wuuq+5vQoC?=
 =?us-ascii?Q?f9DWwYHZwoFO+8Oo0jlzexQ5DjRsy6lbNkgf76w0si2KNBS2GTBrwIgNUQJN?=
 =?us-ascii?Q?+U7BQcn2QLuIW/ktZ0gipMIITsaw+cLmV/bkCggAhtF1QFhmU51u0kE8dLTn?=
 =?us-ascii?Q?E4KapyMlo0nm3jrkC2eDGtsixrr4byqYwWrn+3DdSNIqotQNwIfCtLbsaCIw?=
 =?us-ascii?Q?a0Jo/atcEX7MxZ672mEsMTPIOaKlVriaYeMaOi93BPw4khX4MtFzMuyXwCwm?=
 =?us-ascii?Q?G5pp8dzFFWnxO0yPO8cBHsXRVe0WmNIzpmrhEeYgLQDttEacR2lYodM5kS82?=
 =?us-ascii?Q?vnUPe0ql1UIOnsrek+2kdauI5cCH/NPnAx45l7tGoXoxZxUAcMJ92UZa1wMa?=
 =?us-ascii?Q?OU6UzUZD9qd4JslLAoHcudDvuB9LlcVr4vKzXoWyId2Dhy2FFnyW2GG8q527?=
 =?us-ascii?Q?JB5DlBsidZR9LoLs7xnpnqZ6MXnIBV5/LkKsivVoAeLTRWmmeZR96WxumcO/?=
 =?us-ascii?Q?0OBBwBUUlbSmbhIKCdVbmxMdbZBU6Gckg7js2wTvB43lII0jNGlS9suU/0la?=
 =?us-ascii?Q?Slvwit9V7VbvB420wxe0hh7S/PvLk+EmjljiVI4VNTTl7uXseGn2Xv1Qu9Rs?=
 =?us-ascii?Q?1uQpcPLYnJtzo51ZOWuRRb03LTH6a35MdtBBfUTjgahIYHAEm1+gNGm5Y5PR?=
 =?us-ascii?Q?h3Nahmb0CsIVL/6iMBxPNvCNYHhoymZBsqxd8xBjMC5hPwXntTOg0Q/jsAr6?=
 =?us-ascii?Q?qXYVMpqCGsNgDzw6g4RrvkMr35rYIFhBz6SbAqUZ6yLZTZcpcP8MF9iUr7cg?=
 =?us-ascii?Q?wO83laRlgCIA70JgY/36VTrLhUolNNKZblmfEcNDhnFJdgVNtF6emy8hXq3N?=
 =?us-ascii?Q?r6qI10klrK0ZJX9rhd79zRKN/EPEXobkNUb+hCA1+seI1a+hzNpBaqGykZZ1?=
 =?us-ascii?Q?cpDYKxQUGJmkaPdEo1jDbHeldj/owqB7NaaR8d/HNqN6c4u8jZGM+r5fpg?=
 =?us-ascii?Q?=3D=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(36860700013)(14060799003)(82310400026)(35042699022)(7416014)(376014)(1800799024)(13003099007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Jul 2025 18:55:39.4817
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: a8f47e9e-88e8-4222-b6db-08ddba633422
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AMS1EPF0000004D.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: FRZPR08MB11024
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=RChKMpUx;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=RChKMpUx;       arc=pass (i=2
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

Hi Andrey,

> >
> > find_vm_area() couldn't be called in atomic_context.
> > If find_vm_area() is called to reports vm area information,
> > kasan can trigger deadlock like:
> >
> > CPU0                                CPU1
> > vmalloc();
> >  alloc_vmap_area();
> >   spin_lock(&vn->busy.lock)
> >                                     spin_lock_bh(&some_lock);
> >    <interrupt occurs>
> >    <in softirq>
> >    spin_lock(&some_lock);
> >                                     <access invalid address>
> >                                     kasan_report();
> >                                      print_report();
> >                                       print_address_description();
> >                                        kasan_find_vm_area();
> >                                         find_vm_area();
> >                                          spin_lock(&vn->busy.lock) // deadlock!
> >
> > To prevent possible deadlock while kasan reports, remove kasan_find_vm_area().
>
> Can we keep it for when we are in_task()?

We couldn't do. since when kasan_find_vm_area() is called,
the report_lock is grabbed with irq disabled.

Please check discuss with Andrey Ryabinin:
  https://lore.kernel.org/all/4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com/

Thanks

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGbSCG2B6464Lfz7%40e129823.arm.com.
