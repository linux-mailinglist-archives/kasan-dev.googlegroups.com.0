Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBWPRVTCAMGQESGQSWZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FB28B16EC2
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 11:35:23 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-451d30992bcsf4644615e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 02:35:23 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1753954522; cv=pass;
        d=google.com; s=arc-20240605;
        b=VFkRDzfKhRHMp8D7QOphVv0MBNNbSlQxB/q/bJU93zyazMh29nu5wFbjqxnBSwRXKT
         PDUQ+l5Epq4X3Rp4+b7+jLq1X+ygf6H2DP2k5GlsBj3YLeP0rir5rmVVFX1PGQIXg2Z2
         +6jB6EwgCmRBLkWr6S0JA6M4qL1hdyfCZYHXl3MUJZGGW+QWucQsXFt0E0mbF8RYUR7w
         QaR3BRMwds0LunaRpR/e6s8Hi6wPmc06hTY7CgNOkiM4uTCEsy2/gtdZ+fgM6b+Ue7JN
         HzcHdJ2ePG6vy/OnN2QETUumOs6n8CTcocuYQy1EyB1NHjj3UTZJK4r2WL4jcqIgBqX6
         OGjw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=3QzVcQayxwBUl4fuqAuLqQQ4NZMpzBAEOBpKYaFuOiY=;
        fh=94pXz6xzMmPVaD7KiY1r7my8xQ8XFSXlvB4PswuTudM=;
        b=FQ4G8SGMIGW4M4h//08EuSuPJ9sEuwHaVa+r+fV1U9Kch2xmoGKuLMP1LqUdPX/Yox
         AbJoGCbs6TqI52HDE9aLSLe+31rdNN6u5/P+MG2g6eQ04gmscWL+6aAc5karcmh5U6cI
         GQqIBTLSwRJPxo6EvnzU3Gt0ry85TI6p3tGXrfKXMXPAhJd4HKZOhp1F7oZhONP2bhRG
         88zFA/tG3hx/X82KlV+rREwDeOptWGB1eFaiuqioh/bjtjt0mFcOlYLae0Gjc3+uS1QZ
         ZrCyrHa5Qwf+Tu627jdhhaldB/lxCWWNYa1gTDDKVzmiHJCNL68apuaJ82hNR2mLeARM
         L+Kw==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=fL5BxanV;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=fL5BxanV;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753954522; x=1754559322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3QzVcQayxwBUl4fuqAuLqQQ4NZMpzBAEOBpKYaFuOiY=;
        b=eMVl4STCKMMzO4XoKXM8Qb6X3Xk92tRB7kCMrwBOk7+WYVBv4qjtBMmHpNkj9Aq9f4
         GHc0qnL3EBxje14AAJ6O7RAu/ndlMiq+POD1SrR37qfyUAKxXDMYDOSWQxsfaik4K1xA
         vXJSDSDYdpwJtawPprJfIZnXDVMYd6liAQNF3FEGROqZE1vwixI/IGJrjkxQuSijzxle
         59iruPVdiPxinuelYSVX6UPfFoxUVUqQCSAvS97sgCv7IAHHB4/O35JsiGyWcDgaEbvb
         x5PEnzpuCmJKrPZQovDJyKvHHivzD4e/tEe4UsRmt20DhdCcJWaJsO0DYcFbadwMlIv9
         shYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753954522; x=1754559322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3QzVcQayxwBUl4fuqAuLqQQ4NZMpzBAEOBpKYaFuOiY=;
        b=q6SYFKYZahkHobUf61mUxJM8MIZnSV4kY6IyU86h8HaUVSEK2MESuVyMst7nBzbg4X
         9zLPQqgw+noyTz5GnTfhIO6TdrAjhlgAejsxebeTXu65OII1R3+kBAl+N4x0W6cYeCu0
         4UVH3je4vqlWrTgtzSzpYMit2qLaP37PIOQw5iJZfs2Ltss6Lee0wJ3VtppR6RqbPRqP
         DpAbFgwvTSaEw/MkqOz98zny/F2Ftq1jdQzqFRYReKSdkYDjgJtgZE/wrFIFdPJuWeh6
         iEFdTAkcs+Dj1DLWpMQH6u3EeF2k56H9PXVEhH8ENfEzIbBh9DhGpJ3Mp0GEMjdAvlOf
         LeVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCUcQEOo3Sm9eI3yrDiku5dBUM485xJnt7FNCEDF0vQiQ5qc6HuAgh3sLVxuf4CqvtCCR0SUgg==@lfdr.de
X-Gm-Message-State: AOJu0Yw5bCxxdnfZTnW7zVyRkpTJ625xRx4dgN8k4tvUwL/Nemenboum
	Mm+ECSRfMZ6y1rU1Sntt6JRBbkoSrqvNwKwkHIXfTxaSNBe5cqCQaMdY
X-Google-Smtp-Source: AGHT+IE8fenR4kDtBfJaPuXxhT+48nFNDj82evemoGFaaz92P0L2qWz6FFbJrQp9Kmh1YSEeAH/SGw==
X-Received: by 2002:a05:600c:810c:b0:456:f9f:657 with SMTP id 5b1f17b1804b1-45892bcfb1amr61542585e9.27.1753954522160;
        Thu, 31 Jul 2025 02:35:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzr7hQvnW/NeNXlq6xkXA3pRc1ha36C4r9PSPxB1lLhg==
Received: by 2002:a05:600c:3e88:b0:456:241d:50de with SMTP id
 5b1f17b1804b1-4589f0a1876ls2517585e9.1.-pod-prod-09-eu; Thu, 31 Jul 2025
 02:35:19 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVpZmp8Oa1zY1pNPlrgL1K49f+Pr0ljmCeA+5KqdtFTQHAbtlZQ/V0j6YqEM7p9hEXlxTkoLc0pEZI=@googlegroups.com
X-Received: by 2002:a05:6000:1889:b0:3b7:924a:998f with SMTP id ffacd0b85a97d-3b794fc2af3mr6078378f8f.5.1753954519404;
        Thu, 31 Jul 2025 02:35:19 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1753954519; cv=pass;
        d=google.com; s=arc-20240605;
        b=QXCnOhYHJsjtUtvS771rfD7N1Ch5sODs2NxtD12aM432ExqHNX/hVSkGj2o5LvSsdN
         SBdG535v2vuTgrjDKEDv5yuOuaFcy/ZJi05BTy/ZAREErfaGjbVWZFHgrB3fwYPVDCnw
         soJ4g3vG6zNGseLmBKWO8lTnF7zekyAmrGfwcmtj2w0dZiCTrqtO5y7B7RugB0VYpbIE
         vF9Z8ji5B3TlC3enSSBosb6H4+krOkWtSS+VFBfuY5mT/zPWjgSdLkXg9kevxK3v1jpT
         u0K0MFuE60uOEZC1V/88jAX/b1maPttPpDgCSd0jYqQnGB8uAAgfN9FZcWpj5ONPPIsE
         GjdA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=ruIpSZUqfvMrmnWE1xn7+5VUSgYg7TssEEKOBw5dck0=;
        fh=fogSrtGw3HTrWuYyv7kjD0gNtPGZ7m0NHAQ/ZwFMMx0=;
        b=EM1PWbLVJ/frHO2LXJMJQm9P94sBfiw6SR1Yv3A5pesI0XazJsPjHvBWV3W9RDRjoJ
         WqVi0uSIzs2pll4qAXjd/9NmVYwdInXfND8+ePYlb7a0eTdWcebXH5p2MxYnvCQHJC+q
         Cp92yDQiedlChJeRilUWyRDb4o7n5a9LFr+Cj1q9nbTm6CecEhR6yIA23uQdH0+Na9el
         ew4J1doYMRJdy4gciAt/mrULA7cFyo/85abu9a/CauyBkPTaVmeLmRTdFMf/i3BwitIt
         /tJFYxtKemMyoyiqPc0SA8dbYzLIsMf6Pb6c14AmQZCSIRjNRuFCQxxIUL5prku1NBXA
         egYA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=fL5BxanV;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=fL5BxanV;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c339ca7si37098f8f.0.2025.07.31.02.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Jul 2025 02:35:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=DhDLGvMUUinWRrqEhXTFAgXFhyEWsqs5En0I5+UgvPAIPfPZU8CGy81XYbPZ5touA9+HQfMsb9BauCVEntbMwVpBnfOBrqgFv7ClZdaGSiiyzq5wJ+wAVJtIb7MPYmxuanH5rjkYyDNPq1Lv/KYYyOPd9IUUioula2EXNWa3gIKBLik3jHha7o44FV3s2ZmeeClVdeWtOlpU6gnxh8MkWHGPopx4z+C7NLizpY0O6lTBbYD3wPO+ItB9PsFgi4PheZnQt/8O3rd2W3vboMbhMGrfwW0HwTg7Sj+luxZaHtBRwXFCoBo1zOWQnNO/i0B+vM+DUYaRgwlm6pI6y0XemA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ruIpSZUqfvMrmnWE1xn7+5VUSgYg7TssEEKOBw5dck0=;
 b=Xvk+TgKXOyYzCx5Xbcivn8uR7O74IHK4a2hPVlXAwpOFB35hjcQBlipDYzSk33c8Sp5qyq+Cr8hz9XDxV8oEd+IRxPpBmrWuj0TqU/L/m0EQ3/lo9+vkvQhSRmz6N13APMwG2Qzp4A+N/MceOUf/6yVq30ZMF6DBjfQejluBKibwwXtSJHPkyG6ZjvsKKkO6rHhbxNMYwfPF1YJY0lhrZpw76gBD3KkFFcHN1j4C1N3pADR+36oD/9Y7bem/JCYBIgSvs+QNKKlAvoTfFxm/h7IWvxE3opcaCrxm/9UDTDLEX9y4rD+mV1GP0IxTpDW5wzQlA/RDanwzFjvdAInfzQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linutronix.de smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS4P189CA0041.EURP189.PROD.OUTLOOK.COM (2603:10a6:20b:5dd::15)
 by GVXPR08MB10714.eurprd08.prod.outlook.com (2603:10a6:150:159::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.11; Thu, 31 Jul
 2025 09:35:17 +0000
Received: from AM2PEPF0001C713.eurprd05.prod.outlook.com
 (2603:10a6:20b:5dd:cafe::c6) by AS4P189CA0041.outlook.office365.com
 (2603:10a6:20b:5dd::15) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8989.12 via Frontend Transport; Thu,
 31 Jul 2025 09:35:17 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM2PEPF0001C713.mail.protection.outlook.com (10.167.16.183) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8989.10
 via Frontend Transport; Thu, 31 Jul 2025 09:35:15 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=eINLlb4a7l1/B+KRDe92F6lM+7kk6PGQX+OfVBAS469XsKe8BGuU8ZjN0EC8nkLd6KMFfUsdVsJSwKf0sMASchVgkFXm71mVZpwuVI5f8R9PC8rS4ATS8Wk4Hy8pt9IFabbOYqSWCTM9P29gd/ZMw5YBO5D6d6AsKStHVTD6QxWN00ObLDQcss89L6BojAPKfzj3Of4t5ZzNNim/Iqn8oXae+Q5zYkUcM2jkVcN+Z2rfhsAzbMVoLU34EmTIshHiB+916NAH+fjpJF0XGhlccyMLDkQwJRRidDPy93xnKhpDiHzHIsF1ywBW2aFHq8rO7yzcgTKiYtzC4k7fTraxIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ruIpSZUqfvMrmnWE1xn7+5VUSgYg7TssEEKOBw5dck0=;
 b=ssMRB9p6Lviecc2g6a2Qtx9bTST0+MXYPJlGzxNvSRDEGe09Ck83TXjoNtEg3VlAsxs/Ae8CExUlhLK0CICVnBQUOcUwbGGcBtYiTRjxHVbL071fpNE4IJ5tkzZrJtXjPhP0hcZINXSBD//VSaAKtGIvPtaOakzIcTWNwVKyx+QKbOX4uTCadStsaqM08w/44Vpl61aAWw1qNa5wSuM9HZpaUXmN/2NVy3t0YovO4G3Roim+Mf6llEM9pk68h35OfnGrFuk+Qm1iMx4w03MHGwvxhv119oKskgOezf4eRT1UsANVYH5BQOoX5BR6vGkmqr/wrxEgAlbJWK79ysPvkA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DBBPR08MB6011.eurprd08.prod.outlook.com
 (2603:10a6:10:209::13) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.13; Thu, 31 Jul
 2025 09:34:42 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.8989.013; Thu, 31 Jul 2025
 09:34:42 +0000
Date: Thu, 31 Jul 2025 10:34:39 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Thomas =?iso-8859-1?Q?Wei=DFschuh?= <thomas.weissschuh@linutronix.de>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
Message-ID: <aIs4rwZ1o53iTuP/@e129823.arm.com>
References: <20250731090246.887442-1-yeoreum.yun@arm.com>
 <20250731110823-9224fbee-6d66-4029-9e92-19447cbcda64@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250731110823-9224fbee-6d66-4029-9e92-19447cbcda64@linutronix.de>
X-ClientProxiedBy: LO4P123CA0640.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:296::21) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DBBPR08MB6011:EE_|AM2PEPF0001C713:EE_|GVXPR08MB10714:EE_
X-MS-Office365-Filtering-Correlation-Id: 807c9022-3348-4c68-6d42-08ddd0158e50
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?Yd/Sr9sr4rBUduJ0nfMtXHVNAq3tfHyo3EALKeOIU6gmZy+DotfbfpPRbMdm?=
 =?us-ascii?Q?WhC8815ldH2MsWksWSKMQB1q2lfHM3kimTxjCvdzz4ETfyOaqKln6uape3sK?=
 =?us-ascii?Q?Cfy2OLBsvtvHKT4l5hme/Oap/F8Uduz4ZCzdhWRSHM9sR+Yw8U3A9+2IC0c7?=
 =?us-ascii?Q?Zt/qLJfUpdo0TUCW65O9XRmJ5wDUu0fGL9bmjzZFJvMlDoTnGfUDJgpYnSS5?=
 =?us-ascii?Q?itfkT3fhGygOdnhVIDsjt7ejPpvMMDBGilaWDyNgAkQVglKmXxIDdfgeNmBT?=
 =?us-ascii?Q?5EJnRohKtDvczIDARBDtAIfAddoO+uRKra4Fcq5c8C8W8K0n2YynBq+h+Jal?=
 =?us-ascii?Q?lgYokKmiyTfHKmW8Au8T/usWhbG1eWbrGuWaPLpGrWT8/ld1PqLuZuslW8u5?=
 =?us-ascii?Q?1p2CMxULhuENzLMs22XyPq2z6GUXspAFa998+EU85v4Q81KvFpZ0EVHDYeO4?=
 =?us-ascii?Q?3Lgyx+Aq1uZvv7INmUB9+SxUbe7HtBjzsf6bhcjOf5pryq8TMVzxDMNwxvx4?=
 =?us-ascii?Q?XoRJWGRfnauxq4J5m8IY47y8kZReP9Wd+DP3zIikXJauPz+LOcLMR/NWoHeS?=
 =?us-ascii?Q?yRJWdNp3LdSX6MUX153xXXhWRIb32ulJ2eFTCo2QoZdKOV050vV6J3VgV0EI?=
 =?us-ascii?Q?JWv45tCcyHaaQnkAO+bPevm4JB0u+rurAHkbCERH92VX2uiifGmyHURNV5He?=
 =?us-ascii?Q?aWExQ7cQjpDCBe6YWHQ+bvzm9zWr03KqwvrJ18u4m1kYkt8i2EibWRhuwOzW?=
 =?us-ascii?Q?p8pe1/mTBsVhMq86xIWNE6IE/spBys2tSwXku41I0t6AJ3ZORbIeD7HC3/HT?=
 =?us-ascii?Q?cWw9fpasy9w0SQjSXIrNsWjq35SmwAhS0ucSTzs3DtRW8bBNlmkHw3i98WuJ?=
 =?us-ascii?Q?F/zDDhWwkERx6+e0mmK5UqeTKosToZU/anVxLOurR8uHfvP1kDbVv0ppN89i?=
 =?us-ascii?Q?2PHWve0lT9N0pBgL5cq8fXqmzUy0EHq3LVft2u/s3IrkbQrp0ujudqxMGqs0?=
 =?us-ascii?Q?8dApdx/ts81QprYQrLNqjyNbGJnPnsuoI2X6h+PuUOcjuf4j9focm5lUTxke?=
 =?us-ascii?Q?tJhTqn2vJEIy/g2hI7p7CYwndl4ukfGCE0iZnP8LA+DLOgLHmoB9XWuLi4xJ?=
 =?us-ascii?Q?u8UU1ycy6/sfktxN9LpKfWKkqHiHgdnw/5FIcE47IWQgKrSi4sUhChsDhPGg?=
 =?us-ascii?Q?casG2XCULd0tNXeytnLsQswvfGpDZFL4lmC7EDS0oQq0/ossXY47O5hJgc+w?=
 =?us-ascii?Q?LWzCXo8XSv+4bbG8cvqgOJ9afc+O13/f5q03g4MRRRvHmNaGuuTvQ8nn12Oe?=
 =?us-ascii?Q?gn7anJTYC/LgUILazUOAELuvILULOYq5IiBjN3wlIvD/sIc/t8fc12BGDpX6?=
 =?us-ascii?Q?9c8iIR/2Owr8DM3EmlxnJg3ini6W6B4+hDAoNrwRzZd+CKPxLoiNtkCd+Jir?=
 =?us-ascii?Q?ugBQukwJ14A=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DBBPR08MB6011
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM2PEPF0001C713.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: ff4e2618-4cd2-4190-9e48-08ddd0157a1f
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|35042699022|82310400026|36860700013|14060799003|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?uzuZpYLQWH8c8xrc1TY3qGUz20s6ibi9kBENoUXMJdS8By1iyqZ46isY6V7v?=
 =?us-ascii?Q?+Uai5RtC2eB7erRRlS6QrdTjeN+fPNaKAgK78YF7WgvcJmDpOWwYzTQkH+pC?=
 =?us-ascii?Q?CWcOMBUJTGUGx/nTF6eacdQZAkRWNavgMnAQO5m24pd67KRSbv9qmjxNfRlw?=
 =?us-ascii?Q?eCqumFN3oSZzb/LD7paGdp1pJrCu/T0aGAztzJCuJQEk0M+aFngDm+5m/HPe?=
 =?us-ascii?Q?mmNP389G1rcM2Vt19ZA86OJrepggwt6um1gmlvsZDZ07830qF1qP23iD0Ma6?=
 =?us-ascii?Q?hsJeqS62LrseDLJoep7F7rKwEr89CKCNhUiaVgVQHwESTffAFJRxpW0iAJlv?=
 =?us-ascii?Q?cf6VBwcuR9wSnTfUqFax3FqakjvwOLeTAZ+/ymrI76Ml9FkLY5+yalWjn53U?=
 =?us-ascii?Q?1V6RiNrFgor3NAepd+xVtsMApu1mTAwRtxMsolwxN+XJ1inDtPNo2mSIqsC1?=
 =?us-ascii?Q?b2XKd+jOVP6Ufm7t8TOFDrGdiGxNDxCmmK6Gv0l1ZUCCmUCwzGgiK5GJwbIi?=
 =?us-ascii?Q?9xrMs/qeJFwbnY23bllKXaQuEczmlsA6xlFxEQlkWkVpHKrHTYi2C5zF2Rcm?=
 =?us-ascii?Q?cGYyhRe6VkmXnlZ5StfksYfkopVg8+V5brVg0XL0dOaqDt1RJF0fDn0o+7YL?=
 =?us-ascii?Q?zGsGxETsKj1jP2rYYwhiJZJM+78CrO4JVvMP+uBGdm8Hagc2BOx7GdJfNYjD?=
 =?us-ascii?Q?NPBRg+gX9FTllM8JDfNvECYdHfCtlPjlabqcfQ5zTONyYqPXrnY8cAsjMBfP?=
 =?us-ascii?Q?qllJE1N+MP8ai6nCAJ4KFas60RwqXD38QGqc1HnouaLWeXnuTy2DwC1WG9zk?=
 =?us-ascii?Q?7zOvliwBqL2WiOlUgWScX1+jNz78WDckYXPWBtnqJfHVViUQtPnGfdUt43E5?=
 =?us-ascii?Q?SX1RDroxc7mT4WQKW/9lwUJPMiUdcVHEX3xB0S4kmbun0029C0Tm/QFl+Ert?=
 =?us-ascii?Q?tBuVpqHx9ozWyUfCfvHsV4TtXQEuYiKSgg8sCN4tkOzESf6/TRnV2QvNv3qr?=
 =?us-ascii?Q?02cA6iYXZGSTq/ikeZeTVBF//xkBpI53oO49a9z28A2aMds6ogDKJPS2ka8e?=
 =?us-ascii?Q?2uyzdhD2HlADtSZLdeWKKwMLasd5KUSICQol5mgU+qu6B2qtPE9lhrFaR4kY?=
 =?us-ascii?Q?/ofZG4Cr/B4hC42QvsB43vCulnsaNtF84Eck/Fxq7NPTaK2HuPTY3sBj/FCj?=
 =?us-ascii?Q?RneQ4obbVegofxOOaj6ezUtt/ZYD7MCXC18+y7mhErqNk2kG8IJ70x7NP09I?=
 =?us-ascii?Q?RxqzTtfKkHs0gRHvgLbu6q/B/JzxHMxrd1f37Ixmg8goH1ZbnSLwsHC3QaXg?=
 =?us-ascii?Q?ZDcTYc9hwWKg9Y4GgT6lwIoUmQ1Zrs8eq3EJ7GZz+f9laI4LSQZ1qOlmoouV?=
 =?us-ascii?Q?uGZTv7mHPHXfkhngpqn80Qd38Ibz7qVfTlUF2BZwlzNMwzPDln3yHwPpBBF/?=
 =?us-ascii?Q?KSIWkr9m3s9IQ86FpWfhwQbXOCZgj0+cJwZFdGsPxnvu5nFjrKhhdOqxul+Q?=
 =?us-ascii?Q?dib44MDcHmNhQuLoGetMgXR5PHOtNzLnjP2S?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(1800799024)(35042699022)(82310400026)(36860700013)(14060799003)(376014);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Jul 2025 09:35:15.6098
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 807c9022-3348-4c68-6d42-08ddd0158e50
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM2PEPF0001C713.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GVXPR08MB10714
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=fL5BxanV;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=fL5BxanV;       arc=pass (i=2
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

Hi Thomas,

> > When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> > triggers __fortify_panic() which kills running task.
> >
> > This makes failured of kasan_strings() kunit testcase since the
> > kunit-try-cacth kthread running kasan_string() dies before checking the
> > fault.
> >
> > To address this, skip kasan_strings() kunit test when
> > CONFIG_FORTIFY_SOURCE is enabled.
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
> >  mm/kasan/kasan_test_c.c | 6 ++++++
> >  1 file changed, 6 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index 5f922dd38ffa..1577d3edabb4 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -1576,6 +1576,12 @@ static void kasan_strings(struct kunit *test)
> >  	 */
> >  	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_AMD_MEM_ENCRYPT);
> >
> > +	/*
> > +	 * Harden common str/mem functions kills the kunit-try-catch thread
> > +	 * before checking the fault.
> > +	 */
> > +	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_FORTIFY_SOURCE);
>
> Would it be enough to enable -D__NO_FORTIFY for the whole of kasan_test_c.c?

It would be better. I'll add it to Makefile unless other comment is.

Thanks!

[...]
--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIs4rwZ1o53iTuP/%40e129823.arm.com.
