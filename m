Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBZMCV3EQMGQEPCDP3YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id AA5F1C948EC
	for <lists+kasan-dev@lfdr.de>; Sun, 30 Nov 2025 00:27:35 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-78a712cfae6sf40377737b3.3
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 15:27:35 -0800 (PST)
ARC-Seal: i=4; a=rsa-sha256; t=1764458854; cv=pass;
        d=google.com; s=arc-20240605;
        b=RXowyiZLEUNhNrjvDO6eZYxKDJd7k5ynQeiRw9h3d/cEP0WTt1iSvrFCqOdg113TMf
         eewSfZPT8UPtR3Hr98Mrn+pUArQJC9fMw+FBuI6TeJ1vddSBga1voYl79ehs4J9rHaS0
         ZN+ZoTjLNGPjSno41jCC+qF7N94KyBt1V+VR3BjuHlOQZPPkAFXcrocFyQkhsnGWzXBS
         Boqb9CwsT4kqBlBNwl874OZI6q3Jt6GaJxzGdPZvXuE/Xm28E4263tIoTc6S2AYqOjUO
         AjVJy2Km62A9Kd1ttapeIxd4Ol2H0/SPRFZM4D6TVJr4LOlzBEOGRtJ5tDYeVu2E91Hv
         1Kzw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=fF96GGDKM8cVNAPP7omdfXbOtVOOF6uN5SqKnnwFEjE=;
        fh=rNdtx4W+45Gm0xrNeJI8ZglFeNhT+IX6ROwvEMv+j6Y=;
        b=Zlpm6Ip/oE7hIzxTtgc/XsUX7XMWulrrCNVucc/APZmgVwrFyGGlbBYkdji3D9PF+/
         cIxCmqN3irRs+hpbn/+81s56qkKx7FWCrPkfGTfnA9gV7f5du0epxz9g85UEqmfiNv3X
         rvPjrB29IbWkL37w4gcl/lDe7cHC4tVYS6Og045NORC9tw1/x57mYEizUbx+Se80c2pc
         Vam6rzPOFqHhJm5SFWdCBdfeVZPb16/bXAxQQeWKG/FAmIUzBg0OBORcuoPun53M/kNJ
         tKOkIEaadmzhK/zDxmxf+u+hFZetZVLJIKB1hNOoluvUdcOp2fnDQZHkfJbuPxQo3dRr
         GfKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764458854; x=1765063654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=fF96GGDKM8cVNAPP7omdfXbOtVOOF6uN5SqKnnwFEjE=;
        b=TSRNy6tNAddPDfRUp+J3vw9ZwQAOmgNgECu+no0i82o/TonkLAxVR6lz9n6yCpdaq8
         Buf00+rzwegk17bUL5/kICBI07nre3zlJrDU061CqRXjfbmF0X/8d7k2YqHi+l1gPOFR
         CatZWAMJju4jnBx8CBgS/ls/NVRdc6ACt0HMaisXZC7ei6tVDyqYsKuyanvo2HIil1an
         O0lsMJX3O0/bJ9cyfKdEpM6rWDTSOsDqgabFgwFxcQQGSnMeCkxKIHrr0hHqhaLgnMEq
         MC7Npl3VkaFok+4WRPJVbrkI9RhsGCMjqfjo9SAnkhTA7KfTmj48ST74UWk06j6XOqVd
         bO3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764458854; x=1765063654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fF96GGDKM8cVNAPP7omdfXbOtVOOF6uN5SqKnnwFEjE=;
        b=pM94XGu0CS8FKx29hj5lpkotYhGtCUVyMUyJmKI3mGFH5p1Qk8ubTGH2/90yOIIZ5o
         CzAz2kRyQwIZXRsN8Mfs7WPQCDo88Q50t8d8GH5GxQtUv/JYvMuYTwRZYPNx0Zw7PuBc
         exNmnks2bykRHXdIASszQfiN+ovkF9jkojs5Dp4GrK/aCbg/xsBOZe0qoIh9fG0r8pNj
         NpsBxFSdcpOw6duecmt/QB8N1Hfahr94VZkch9X9B6r+rHBcCI3VKvjl29JmihpT0R9k
         hDNWh6AUuOLZ4wN3AVwp1dCowVPY/rT9b+CUDJ0NKYgbWXbz45X3hSj1NsZsgUBL9nsB
         NcBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCUVWIP08s06nbU5y7ibhXN9+wa78qYzBvVB4SzfbgMbFnRQ3slkfZ5VpberXzgMjVay87dFIg==@lfdr.de
X-Gm-Message-State: AOJu0YzhQjT9BQYQLV1SkGUDOKJiH46pfzk0+0q3ebxw2Z46aBxvegbl
	UZMF3pSf+XgliLeI+Izcxc4zAORu/8W3grRw0cM2j5n+4eELlxOSh8xX
X-Google-Smtp-Source: AGHT+IHwLbmb4h0Rvejb9PIZnSNZnEdaYavLYGcoYAuNLm7a2C4vQ/1623NalplSow5r4ccZSPPi3w==
X-Received: by 2002:a05:690e:128e:b0:63f:c816:1171 with SMTP id 956f58d0204a3-64302a2a3e4mr21310596d50.13.1764458854122;
        Sat, 29 Nov 2025 15:27:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aV/em75ZzPpSs/F+ebfmAlVmndesEkuQHaUGAy40/JPQ=="
Received: by 2002:a05:690e:210f:b0:63f:9498:be0b with SMTP id
 956f58d0204a3-6433952cbb9ls2053031d50.2.-pod-prod-06-us; Sat, 29 Nov 2025
 15:27:33 -0800 (PST)
X-Forwarded-Encrypted: i=4; AJvYcCViS9fIr9EW6tA3aFTcIOhCQqupFCqw45wuj+a/cfmhgB6lpEC40gjw08wb8sW0kPIrrPJXRlrVxDY=@googlegroups.com
X-Received: by 2002:a05:690c:688a:b0:781:64f:2b63 with SMTP id 00721157ae682-78a8b5664c6mr294324557b3.63.1764458853262;
        Sat, 29 Nov 2025 15:27:33 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1764458853; cv=pass;
        d=google.com; s=arc-20240605;
        b=MVN1J8neE6uOOZDuVKhDUPMpwKjhpeo4ZT+UjR+WJdYbEXPO+U86YXNM3Wn8p2atJv
         mE5jYH20qEzrnO9klvZLIYDLL4sjL6M57lVttWMqPVJQQezU2zQMxVQp7MrL7FhKkWE4
         y6aEm1kslcveKK5mUehDEd8b4fs45l+jdtPkhf8UsbubHrNE2hOShi/XcUy6X9dHqtCr
         GS7jBAz981ld+WFKuUwl/I725smgWSiPomxMbHe7dX5pBuDRGFYffh75HYBxOzJ5l+/3
         BMMlYy/lmgcHHZz7ltOOmj3Zka+hgSYbFRacbqp3bfDIBWvbyG6o1nSzUdIGSgfHnFmc
         G1RA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=TjNJcKoKJYBrQsf6XqBfGKnticOgu1mCtlg11HZny6A=;
        fh=c54AdcBo8xamvR8BAXybICDSayM3F4Ruwt1CtUp1X4c=;
        b=NJwGxnxXs7Eg+x6stOXlH7pb9rvvcMewwWlDUXIGAIKHy+dD9daJgp/H0zDfLsjd3J
         RG/62hb0JoOBldnklaWQvJC9sd1KUSNmAwWjwveK3Wua34Mht+IHKHQg5cb0hV2xLU1Z
         QQ/9K3jQbE5OiFqSnnmqMPEz772ytMeyX9GAGlehDrz2LzND7SMyIw0aBJdteVz4I0TJ
         zogKdjMXPKiNwUKBHMZnXD8SC9nbZ0qy77BMevM+nvDjHbgzdTzPo/TPzBN5qsgoX1VH
         SA2NBMHhvMzHg0IA/Q4LzuXigIjo91SF2YPjC5klShcDk2IDI2DGRq8II0Gh+o62iXwW
         qTKg==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AM0PR02CU008.outbound.protection.outlook.com (mail-westeuropeazlp170130006.outbound.protection.outlook.com. [2a01:111:f403:c201::6])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78ad101620fsi1752707b3.3.2025.11.29.15.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 Nov 2025 15:27:33 -0800 (PST)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) client-ip=2a01:111:f403:c201::6;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=o6p/+Z9jjjklQc5NOZ6L8Bq79W4mXAqUMQAr91T0AWHJ+zEGtx8QufJD6qG+od6I1BQpuV96CS1obZ2b8zXLkej0NRthsOjofZuX2EbziiNVOfldU17K6jutCfwlSkt2O3CCgKWvKEk/4ZrGhVyMVwupB0cg3nnLbpyrLukOcOFYLtx9D9KH9HuF7E8ZWDmgKmH2jl/MjbkA29gtYoTL/BlSfjzcL0BejuX3l4ImdDXLee4OcIuTWnONezcyIOnzfvqixYBkeJAQPHDWCPCQJ7lEuTuZwy7th4npWh/Q4Bm0lM0BtBdRM7+Fw9kYeLjTXNE/Hm8mU+527qP7moF78w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TjNJcKoKJYBrQsf6XqBfGKnticOgu1mCtlg11HZny6A=;
 b=ZpS0vGqS6chX3YAYGVlrfpeJJduJJTtysftmak2bArJltMQfrM3WGFaNfXxZvfZv+aAZ1wJpzTFPGNQ4rSAA/KLtAvRmjZf2FrIQqzsenVEefF+Xa4UGgH3UJxlIBLFDSD4x9XRQ2x9psA+bShnSn/oXGS8eR/EnD9NEGxDtvpf5ZcAIuMd79dS7u6acadrjluDqcFDkTbQzOKP11EAUAeIEb3MYEpaKTmY4mpG8sl73L5666pGxOUAF296rnd+o3VayGkRmi26G7rQZbPX5Rsm3LoNqokZl5B0exWF2A3MBJQd+hlQDQs4obTliUa7W9M6ZUekceH09T41SCcLySQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linux-foundation.org smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS4P191CA0043.EURP191.PROD.OUTLOOK.COM (2603:10a6:20b:657::10)
 by MRWPR08MB11234.eurprd08.prod.outlook.com (2603:10a6:501:78::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9366.17; Sat, 29 Nov
 2025 23:27:29 +0000
Received: from AM4PEPF00027A69.eurprd04.prod.outlook.com
 (2603:10a6:20b:657:cafe::6c) by AS4P191CA0043.outlook.office365.com
 (2603:10a6:20b:657::10) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9366.17 via Frontend Transport; Sat,
 29 Nov 2025 23:27:25 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00027A69.mail.protection.outlook.com (10.167.16.87) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9388.8
 via Frontend Transport; Sat, 29 Nov 2025 23:27:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=EkeRwA6X8XsyVQvWqYrCU4YAJ7W/HZujzZCD12WtASu7AQmRwHnd/SYC3ZgQQSCOTq9lJFodicaAL1T+Y58ufSywYxBD86U/U/g7TGfS0y/S82Q8dH48A9alMdD7etoB0ZxRrRLPyfRJPqKLZbjfbfDo0o2JjcHZkKmiABmraSAoNLMzr8TkGlfOCwoEj/t4m5Bkf4z/gSMkMk8jdKwe3Qya2LFZqKUVhYmvYHRxeSSXT4fwr62EB5nH5vek5K6GAqyz26VAGp16Ty4l2BZ+7puuE2jdjvextiklMwQdF9ic/rV7GncU1VADTBMWl049uIRlmsPT+ViI6BpyT4Npcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TjNJcKoKJYBrQsf6XqBfGKnticOgu1mCtlg11HZny6A=;
 b=Ou+uIfVO3/o7XerfJ1KSEkDwg5IggQWJddapiWI0U5k5C8OvsqKOq/c02ajrN8PZMKR2Yl2ZX3LPOf2aHfITRQqVJHMf+PNgwMDlxneQRCzuJQ/j56nNqNq+pKA8fcFhCj9IVsAjj99fvekGpYThB7sg2EqjBkTSFu36WmUBiD7v0X81DuARvnWr9ULZupdPPemBh1lNxKVbpy/p0QC67lotRQrQos/1MGA8npAlP/bzmlLYs86jT7TqzJm2Q5feNixqS7DyVMxAlH/Q5bcF6VTjngGzN3WVULb3hVObWoMNv6K+ZrE6UdLnMTlv8pNxhtKR+e9OlmQIaiAij+uj3A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AM8PR08MB6370.eurprd08.prod.outlook.com
 (2603:10a6:20b:361::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9366.17; Sat, 29 Nov
 2025 23:26:25 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%3]) with mapi id 15.20.9366.012; Sat, 29 Nov 2025
 23:26:25 +0000
Date: Sat, 29 Nov 2025 23:26:22 +0000
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: catalin.marinas@arm.com, kevin.brodsky@arm.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, urezki@gmail.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, bpf@vger.kernel.org, stable@vger.kernel.org,
	Jiayuan Chen <jiayuan.chen@linux.dev>
Subject: Re: [PATCH] kasan: hw_tags: fix a false positive case of vrealloc in
 alloced size
Message-ID: <aSuBHo7fpQxQYgef@e129823.arm.com>
References: <20251129123648.1785982-1-yeoreum.yun@arm.com>
 <20251129100658.6b25799da5ace00c3a6d0f42@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20251129100658.6b25799da5ace00c3a6d0f42@linux-foundation.org>
X-ClientProxiedBy: LO2P123CA0004.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:a6::16) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AM8PR08MB6370:EE_|AM4PEPF00027A69:EE_|MRWPR08MB11234:EE_
X-MS-Office365-Filtering-Correlation-Id: b47f18fa-915c-47f2-b3bd-08de2f9edcb2
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?bFRld0lTNmRINXh4elJuajZRK0lzZXRDWE5SS1FpQXN1aE4vbjd0K2prdkdR?=
 =?utf-8?B?MjlyZ0daNmtkVGE3T1hEckVWbGhlNG5wQS81aWxpbjZ0V2tsL1lkZ1A4TEZ6?=
 =?utf-8?B?WlBrbzc2Wi9rK2pRNnhWMVJUQWhrQ2hndlVVY0lyeEt6aU4wLzUzU0t4V1dN?=
 =?utf-8?B?T2szeDBxMVdTNWZLbmo1V2k0Zlo2ak4ydU4wWEg3M3pQYUtQOGJFa0RpNmFP?=
 =?utf-8?B?cmZ5ZmhQNjU4eXJhaXZtQitxY0p0RUJYeEszWHIyNktoalVpTzVHQlNZQmpk?=
 =?utf-8?B?d2tKYytrSmViNElpZVJoL2M5SHc1U2lnaXRlc2NEV0gwQVR2c1NsQzNFTCtX?=
 =?utf-8?B?ZEJmYmJwbHZFQjhQQ09YQ1VsamdiMElnSmM0bkpKa3FvL3IrbUNXK3owSEQ3?=
 =?utf-8?B?Tzcyc2lGYXhGT01XUVdsd0k0MHdNTVdaeWpadnFzM1ZXc0YzZGdEMGtPcEFM?=
 =?utf-8?B?ZFpvWlQ4VVQrZVhvKzk0UHNHNytpTVpYeC9UdWtqN0liOG9XcEJlSkxVVHpT?=
 =?utf-8?B?ZkNwbGMxMXpMU2d3d3c3eWhLb0ZaNklIME05akNKRHd0NVI4dFVwOFZtM3ZG?=
 =?utf-8?B?Tk1mUUNUc0wxdGR2MnBsMmI5WTBkckRLOWpsTCt5US95cXBXVnRzR0JoUXV1?=
 =?utf-8?B?NmtNOWk5WG1mWExUU3A3ZWVxTEUyY2hUNTFheGJrelRSSzdQaTIveEdVQ1p0?=
 =?utf-8?B?Q2ViZWRzVEhOWTBIeXRMQThHRnZ2Y0V5ZGlsWVAveTZtNFpuaVg4cUxEcEd5?=
 =?utf-8?B?c3dURU5DT3N5WmJFTUVGR2hsUVNRVERJTjBSb1ZoT2ZqektrUmRzQnhyQVBx?=
 =?utf-8?B?M2dUTUoydFdqSmZZaHg5ZFRqakNXaUt1YSsrRG94OFdNZEp2bjdwbFJqR2Rx?=
 =?utf-8?B?OE5MNlpqNlhZakZyUFZjRFQ5KzNPazZGTm41MjNWRjljblNhSmtlTzFpMEtv?=
 =?utf-8?B?bUlpQWE4WWtuOWdLcE1LQzJScDlHdW1pb2xIY1BaYS9JYklxeFRLendqUjZO?=
 =?utf-8?B?Tnpvbzl1WGVPY3VENnpWaWFIUmpSbC9CTFNHRVFjQUwyRkIycngrU0oxUFMx?=
 =?utf-8?B?NU9hbjJLSHB6UWY4Yzg3NUNhYWJRRWZxMFgvcFpXenBEdTlBT3NFUXFvcG12?=
 =?utf-8?B?aDJHT2RCcUZMTVhSVnRLZ1hRNEo1Q01mS1ZvZHA1S3plTFhUVEtJRmNhWFhL?=
 =?utf-8?B?Sm5yeGdrM2xkUi9UdjJSM3R1SVZhMVN4OVZ6bFBGUk9uZzdjOGw2b0RKaWVp?=
 =?utf-8?B?WlJGOTJFUi9xTEFWSkl4ZDNSK3ZleG8yNlRuaGVHa3NzdVdON1YyYmxJWitO?=
 =?utf-8?B?dUlFS25JRWZEcmUwaGgyRnFXU1RKb21wU3dQVW9RLzJUYWlHSVAwZXRCMXNO?=
 =?utf-8?B?RDJVbUo1b1RrRGJjcVUrRHNsNExVb3FZT3hLWUxVTldzVkxxMVM3akFZbDR1?=
 =?utf-8?B?TXBnK2hYQXNGalhBbkJJK1JQTVVTVU42ODJtNXNobzNTNEM3K0NhMEt6NUFX?=
 =?utf-8?B?eURxUkpINkdMOWlpamxDeXhOQnlCSlNZaXJCYk9JMGdVc1ZaQkl6ODdNMlA1?=
 =?utf-8?B?b1dXWWVIaHRLbkdobFJ3dFFNbnhmS0ZmbEVRbzdteGE5TE1TTE0wQ3pZVjJ0?=
 =?utf-8?B?OFpSTWtNOTJQK3FnR1pTaDRycHE2L1BLK2h1YzRnNUh2UzZHVEVKT2V0dm1Z?=
 =?utf-8?B?OW9RMzk3cWtaZE80N3NISmpRRm40STlJeFFxTVd1NXFMdzlkUm05aytuRFRt?=
 =?utf-8?B?VGZnaFl3Uk56UVdib1MvTmdMaWtYaWpGVkRxWXJGMXVrNElXS2hZcFRkRXJl?=
 =?utf-8?B?aGp6dXF0NWJqOVZxR29vYkx0dE1LU2J3QTdoaEE4clgzNXNOUGZMT2Rvenoy?=
 =?utf-8?B?L0h1OGN3Rll2VlRXWjNBRnNoUGFnRjFHVjgyZ3RnbENUMC9MSkRtd29DUTF6?=
 =?utf-8?B?cHBRKy9iK1o1RWZYUGgzV0wwVzVWY05zSGZ5NkNxUVVoTjlZVy92cVNuTmM1?=
 =?utf-8?B?YnU0L00rM1JnPT0=?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR08MB6370
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00027A69.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: f805af29-4ea9-46dd-3011-08de2f9eb6ae
X-Microsoft-Antispam: BCL:0;ARA:13230040|36860700013|14060799003|376014|1800799024|35042699022|7416014|82310400026|13003099007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?c2Z5bzVLcmxyaXY3OXNDTVFoaXZneU10M2QzQ0tTT0UxQ1psekpnYkRZaE56?=
 =?utf-8?B?c2gwellUOExXR1VDYjFKY2tUTEc3dDlMNGxxRnZKeEpXekxjd2hWY2dpS0xP?=
 =?utf-8?B?NHNQNjlaaHlkUjBvckh3TEJWbStLdi9VQ0JiS01Ia21iY0pLMU1aNkU4cmFt?=
 =?utf-8?B?QUs3WkpNY3ZyMGRBb0J6cERadzNIOUVidG5aTG8rcWVvS1dZbytYK01EMkJG?=
 =?utf-8?B?Q0xXbWY3K2RpSVZhazA3aC9IdDc1cm1GZXl3NnQ3NHBHTXp5TVUxWXkxdHBr?=
 =?utf-8?B?L0hCdy9mdkdXYm0xanNTQ3I0bkNZbjhENFQvTmJIY3MzRmZweEFOSTdjeTZM?=
 =?utf-8?B?VlFRRTNZM2oxRjNscVdRWVdncE9hYVBMRXFwZkxYVmJURVQzOFdWblhqT3Aw?=
 =?utf-8?B?MHVIb0tkK1BOSjlLUWJUWVZMblkvRkVwWUk3ZXVFaytvWnFlNktRV2RmK2Ev?=
 =?utf-8?B?Ukhrdk03QTdkMnhQNEJuY3lQVFFPbVlSNHBtVStDMExGRTQyRXIvOXVTMy9m?=
 =?utf-8?B?UDZnYVAzamVMZ2VMc0xneFYrN1RGTjVkNERvbHZEVDl0RytMTThxZ0VvRkVo?=
 =?utf-8?B?amxXeGJkK0tCQTlMTTYyK1ZlbDJIeXA4RFFvQXBDQ1ltenY4djM5MVVENXZw?=
 =?utf-8?B?SVp6QTJubTYxL1d4WE5GNEdjK2EzVDY5MDVVc1hBcWU1UHhMb1N3bU9hclMx?=
 =?utf-8?B?dEQ2Z0NJTDUya1R4b2RuUTY2Ylo3OTJnRE1wQXhDRTFHcjNNWjBYTW0wZ1Yz?=
 =?utf-8?B?d2V6NnF1OFNLUFR5Ym0raVNaOWpucVBvTXZBSmhadlhtemZoWmlIMGJaeGF3?=
 =?utf-8?B?TURrRHBQVlVVejRiK0poWEVkMC9iWUc5YzEyREE5QzZuQjdnYjVOOTk0MHBM?=
 =?utf-8?B?eWo2LzlCWUxYMVBPWlE3Z3Z1aUp3N2Z6U3JtTDJGV2Evcm52dkVGaGtjdmhB?=
 =?utf-8?B?VG4rYXJLbU8rZkNROHJQNDIwaWl6M0s0RzlxWk02MlhEVVYyKzlVOWhwY3lM?=
 =?utf-8?B?U2c3ZkoxN0ZKcldXclhNVEZtaDgxMFgvUk9PK3VxTmRub1FwbnlZcWYvZGNz?=
 =?utf-8?B?aHFIUDZtUEM2NWVQSVFzdmkwZzh1UGdVU2NZbmJ4Ris0dzhKOXVUWjNvTzdD?=
 =?utf-8?B?WFZGUWMyTnhXOVAzanNXb1J0dzJYY29BajVFQlJwMExKVGp5MEUwUTAydVJn?=
 =?utf-8?B?bzdlSEowSEcwNUNDK01zNWNTRmRkUnRIOTVwNm9MUFFHdmxuRGY5TG5jZ1Zp?=
 =?utf-8?B?aEtyQjM2YXBjRW1Talh2QUhaSEF5V1hhcFM3ZHhLYXArelRUS3FEc0tnRnMx?=
 =?utf-8?B?SThhMmR5NU5ueGxxY2FiazcrejEvWmJYeW93VGMyR0VVd1A0ZVRMekVxNWtT?=
 =?utf-8?B?a0JORnZNcGhhVFVNcTlJRnZlT2ZBYUJwS0djVVRBeWs5VHFOMkxEWnVNc0ll?=
 =?utf-8?B?RjM0M2J3ekpoOVE1RFJBT0RtOXRsMnNxb3Y5WVZ3eXRhQXI0Qk9xVys0bk9Y?=
 =?utf-8?B?dEFBUW1MQ0VTWHJYT01WK3BqMDRDNUhJV242eFI1K1BMaFQ1bHMzZTBQZDBo?=
 =?utf-8?B?TEZrV0doOEN2V1VVRDdMN1M5QXJSYVh2TG1XL252dEErcmRBTThXTlEwa2Nt?=
 =?utf-8?B?U1I4aGU5ZEtQRGljMWNRcVZmUzNuTGNMLzFTaC8veVpkcFllWWtTaGhUcW9U?=
 =?utf-8?B?TzluTjB0YnhVNElYUkFkb01WenMzWi94NWM3U0RaR29vV2VZejhmQ29RdExu?=
 =?utf-8?B?WkRwUjZKQ2ppdlJPODlGSFZ1KzljcGZJZGdSNUtobEpHWS9ZclQ1WjdVdnpJ?=
 =?utf-8?B?K08vUEg1WDhXVHNKSUdTZk81dzRqVU03YnA2VHJlcVE3Y29jVTY0ZmVESDdS?=
 =?utf-8?B?NThZVUl2MjF6UHVaWU4wbzJJOUxHQUFLOGkyanJQN3pxeEgraXhTNDViWU5P?=
 =?utf-8?B?YXpMNmJkZFZ2RHp0bkRUT2F6VG4wc3ZaNmdwQ1RRMmRrdGM3S0VET21tdzNh?=
 =?utf-8?B?QmhaZE5nL28rODlrUVA4Rk1xV2w3VU85ZXFRaFAvdnF4MEJkMDltc0JPd2tq?=
 =?utf-8?B?NmZqL3laQ3J0UzBGMkpGaEpIa2dsODhrb0J0dkpMak9qYkUxT1BxdTgrN3Ur?=
 =?utf-8?Q?s+2U=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(36860700013)(14060799003)(376014)(1800799024)(35042699022)(7416014)(82310400026)(13003099007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Nov 2025 23:27:28.6310
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: b47f18fa-915c-47f2-b3bd-08de2f9edcb2
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00027A69.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MRWPR08MB11234
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="h/gUXFzv";       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender)
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

Hi Andrew,

> On Sat, 29 Nov 2025 12:36:47 +0000 Yeoreum Yun <yeoreum.yun@arm.com> wrot=
e:
>
> > When a memory region is allocated with vmalloc() and later expanded wit=
h
> > vrealloc() =E2=80=94 while still within the originally allocated size =
=E2=80=94
> > KASAN may report a false positive because
> > it does not update the tags for the newly expanded portion of the memor=
y.
> >
> > A typical example of this pattern occurs in the BPF verifier,
> > and the following is a related false positive report:
> >
> > [ 2206.486476] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [ 2206.486509] BUG: KASAN: invalid-access in __memcpy+0xc/0x30
> > [ 2206.486607] Write at addr f5ff800083765270 by task test_progs/205
> > [ 2206.486664] Pointer tag: [f5], memory tag: [fe]
> > [ 2206.486703]
> > [ 2206.486745] CPU: 4 UID: 0 PID: 205 Comm: test_progs Tainted: G      =
     OE       6.18.0-rc7+ #145 PREEMPT(full)
> > [ 2206.486861] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
> > [ 2206.486897] Hardware name:  , BIOS
> > [ 2206.486932] Call trace:
> > [ 2206.486961]  show_stack+0x24/0x40 (C)
> > [ 2206.487071]  __dump_stack+0x28/0x48
> > [ 2206.487182]  dump_stack_lvl+0x7c/0xb0
> > [ 2206.487293]  print_address_description+0x80/0x270
> > [ 2206.487403]  print_report+0x94/0x100
> > [ 2206.487505]  kasan_report+0xd8/0x150
> > [ 2206.487606]  __do_kernel_fault+0x64/0x268
> > [ 2206.487717]  do_bad_area+0x38/0x110
> > [ 2206.487820]  do_tag_check_fault+0x38/0x60
> > [ 2206.487936]  do_mem_abort+0x48/0xc8
> > [ 2206.488042]  el1_abort+0x40/0x70
> > [ 2206.488127]  el1h_64_sync_handler+0x50/0x118
> > [ 2206.488217]  el1h_64_sync+0xa4/0xa8
> > [ 2206.488303]  __memcpy+0xc/0x30 (P)
> > [ 2206.488412]  do_misc_fixups+0x4f8/0x1950
> > [ 2206.488528]  bpf_check+0x31c/0x840
> > [ 2206.488638]  bpf_prog_load+0x58c/0x658
> > [ 2206.488737]  __sys_bpf+0x364/0x488
> > [ 2206.488833]  __arm64_sys_bpf+0x30/0x58
> > [ 2206.488920]  invoke_syscall+0x68/0xe8
> > [ 2206.489033]  el0_svc_common+0xb0/0xf8
> > [ 2206.489143]  do_el0_svc+0x28/0x48
> > [ 2206.489249]  el0_svc+0x40/0xe8
> > [ 2206.489337]  el0t_64_sync_handler+0x84/0x140
> > [ 2206.489427]  el0t_64_sync+0x1bc/0x1c0
> >
> > Here, 0xf5ff800083765000 is vmalloc()ed address for
> > env->insn_aux_data with the size of 0x268.
> > While this region is expanded size by 0x478 and initialise
> > increased region to apply patched instructions,
> > a false positive is triggered at the address 0xf5ff800083765270
> > because __kasan_unpoison_vmalloc() with KASAN_VMALLOC_PROT_NORMAL flag =
only
> > doesn't update the tag on increaed region.
> >
> > To address this, introduces KASAN_VMALLOC_EXPAND flag which
> > is used to expand vmalloc()ed memory in range of real allocated size
> > to update tag for increased region.
>
> Thanks.
>
> > Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS=
=E2=80=9D)
> > Cc: <stable@vger.kernel.org>
>
> Unfortunately this is changing the same code as "mm/kasan: fix
> incorrect unpoisoning in vrealloc for KASAN",
> (https://lkml.kernel.org/r/20251128111516.244497-1-jiayuan.chen@linux.dev=
)
> which is also cc:stable.
>
> So could you please take a look at the code in mm.git's
> mm-hotfixes-unstable branch
> (git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm) and base the
> fix upon that?  This way everything should merge and backport nicely.

Thanks for sharing this :)
But I think the patch from Jiayuan still has a problem
since vrealloc() can pass the "unaligned address" with KASAN_GRANULE_SIZE
and this will trigger WARN_ON() in kasan_unpoison().

Except that I don't have a strong opinion whether adding a new
interface or a new flag.
But, I want to receive a comment from KASAN maintainers to
check what is better.

--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
SuBHo7fpQxQYgef%40e129823.arm.com.
