Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBFUBV3BQMGQEZEBDCLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 1068BAFAE39
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 10:08:57 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-3138f5e8ff5sf2830975a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 01:08:56 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751875735; cv=pass;
        d=google.com; s=arc-20240605;
        b=OIHE0M9dLRyQD4O98uwdcJJVdU82nOTAMVgTvXjTgYam0rH34wxk6e9pbrSCZBg1Xk
         gWiRmdWxOB8DmB1+/NQuAvU4rMN8dsKca/MbxqnUcSuIkKEm40ymkG3Ns6zAhv4ap7+x
         ETbNeJX2bext6szv3ku6dKBFWX2Nks68nKPrc2hMpld1gA3vmzmXt57mq8yiLibJZYXt
         cGMqK9H38nna+oxf9SWcmSAjzz+iFohG4/2nFqcaalvYQf6s3+BX2wcPJReemPZLyNYR
         SJ9XhQ60ONGbQzDv4JjCHmZ5cxbSpkrvlIZHPQuG4s4QP/OY4lPcFHq71GX6Q+TgXhXL
         7QYg==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=b9Lfo76eRq9z8xq7svcemrHU1+WYI1NGfdsUtDRKs7Y=;
        fh=TVOGCNEXlrxgbC1GxkwwYJgE7EmrPl459NfAXfZXtJk=;
        b=YFlwpv3c2PbGmv53/PccPfASGOQEwBynkRfrcosa39dHKLx2ZT72RviwApDzmTy/87
         JFenOFgHvMHuAvkkkz98sF+h6KU2BNblHaSbStX/gee7HA57B+znP810Xgj2shi2FYuT
         jP/1CkalvptsjH13uF4Za71kzVCr6KJAw5tNQ+dCeFmNqmONjltLvW3ciFuLcWnxSn9d
         HgLy5nuQQdkDXQIrk1D93PU02p8DzVv0MwhbPmHmMuce4x5AG3HBW6VRO9nGVfFJH/a0
         MHOY7mhZJWKj1yn3XuMYEElFnNwkKLOQhMEYj+m85LjdKh0zNyfya8BiB6CnnWwBjcJl
         kppg==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751875735; x=1752480535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b9Lfo76eRq9z8xq7svcemrHU1+WYI1NGfdsUtDRKs7Y=;
        b=bcEvTNo446jM+ZYNQZ1LhOOZxWzkLrK7nZQw1XqSvhvsl0tZmiJWDo9db2wWnrQtzz
         cecooEAkJR5Guq93AUm4oxIkepYgsG39MGeKhuzXWQCrv806qsgGwmALT58za8IIBw+t
         TONdXrwERRFQ5auG/bvUbRBZVGhMHCJuKITwRZlMCjrTT+gfoS3W7iYQkVzpr3hVpT+b
         nqiN/sM2qyk9rBylCM5Dta8KqG0CrNjTpkLqN28qj96mq5QuC3dD/qb5uE+ZYr5B/4O1
         cqVBq+vT6yXuUc5Dy4TgiRcld93qBydf31pSqMhv1dAthZqKCdVMDYFYcLbFF/Pi0Q1f
         CSVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751875735; x=1752480535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b9Lfo76eRq9z8xq7svcemrHU1+WYI1NGfdsUtDRKs7Y=;
        b=GJc6mAmDPjGCfDLBlN1wtFJWrmsn/c04NwvXX6t3bKZlLxNj74EhCu2Zwqf/M7dlAJ
         JvMI21zoz5VyG5wGkKT+5B/7ezmpNd8Ptzc46FtUsCstAXcOTzxo5Ar1oJTkrOV1/MzT
         hzaN3qOvYySHUiC/cgK0IFnfXZZY6MjYUlA5tTLDkAs/cxYORMRSai2FpNfDd4X0GEW5
         wQAy2MRfETFcVIHelRpBOpgHZth9YUPxI9BCKTNLpsYU3/wgU2DAEPd7QWhf/pIX1HKR
         DVnxhilkCSECeRzAhnWswDzB2WIrEuUmt9pao+thtmZzNUkkIeI/kKvdewqPgDShPT6f
         SzJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCVHTUITMwfoQIR2o6NdjXzDXOsq5FQYAmQFnoqkqlwz+9dyvwiWVzfH2l80Vw3DOzfUuOf64A==@lfdr.de
X-Gm-Message-State: AOJu0YzrHI6JsOY/ODUozSvhmRydx3y9CgMEa+PFO6zkzr1BkThCUghB
	Y9XDWjNYUHC9W0qkB/HIszbROTqnOt6/aJk2teuUAsgaYb0GzwfgVx0V
X-Google-Smtp-Source: AGHT+IE3PDBKw+b79h9xeRpGyffHcHpClmBRadqvwWBwcLCQrO36n+sVXdG96l921rcL+Lt1HLizCA==
X-Received: by 2002:a17:90b:2702:b0:312:1ae9:1525 with SMTP id 98e67ed59e1d1-31aac44ad53mr16229580a91.8.1751875735285;
        Mon, 07 Jul 2025 01:08:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGijvBVQBXdSh8Mplk6JmiyqBVVik+TXh6wxa4xTr0dw==
Received: by 2002:a17:90b:50c3:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-31ab03359cfls2432816a91.1.-pod-prod-05-us; Mon, 07 Jul 2025
 01:08:54 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVGXhV1aiJE/MhZtDXHWm3xCCLjUKnK3z4e5Rhc/vOSE0fBCDw96/J1a+ZrPtpFpmZIT4cswtpR4aI=@googlegroups.com
X-Received: by 2002:a17:90b:1e10:b0:312:e445:fdd9 with SMTP id 98e67ed59e1d1-31aac44b747mr18119542a91.10.1751875733959;
        Mon, 07 Jul 2025 01:08:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751875733; cv=pass;
        d=google.com; s=arc-20240605;
        b=gVof8ryMqijt5tix5MeUG23u8dtHuRVP+w9YhYDiQHsZJrwhUo/Tf8FYNbnQTFummL
         TMVlT0DntqsJ0ix0T16Lpmm7WlmnsdhQpC2gPekwFuIO8oUOdlthnlzac5E8EaM/cgkr
         cZaDGBV029mdFRZVZ3kTM0u2BUdDFtGkhLqacc3dTXXAqucMafoa4VnPUHsvAqXgf0Tn
         DWrPuV0ejU+sXCDh1/Znm30PifZT6QDeGPqfRyXbmWomd9Np7iAp/simpPpClC2Xx9cg
         elwd8kagMaltR0l1DiTau4mkLp4gko6pkQ0/T9O23Ndmq8EMa25UA/rtZ1qkioulmZbX
         7KkA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=HQm/vMkOh3SiXontS9l4CPD/mrT2/oQ9/GBHmQvIx4w=;
        fh=UO4z5M4FHttAXY7fXc8C/RFbkTI6rlxXxWjv/r5J5fQ=;
        b=igyuTcWuIXVK2JMw/+Zm3FCjRyi4kJ2tD0QloYrXqPv6ldRj8MoEM+qGrxhl/Ddrtk
         bA8UP2fQqOqTliCnYheZcSzoWl+UPoDh0XhySWBbsH1qPXuJpDYk93AHFwuYsHJ9n5Ny
         /ewoWTAewWQIgfMgZtEPSxsVF3aYn6D81yiXbfxEgws5ILOf6eUawVJVnA3jotfe0qBB
         tiDz6MxIYQ5YiUT3NwfIELRT3oGLPr3hd0WG7DxKTygXhakHmb9yMSAPK6z3q9GNnORp
         x5diXgIDBH6O8+uFQWs2BV14PGRWtkyn7pmI1PMlaxHdmiJiOJiHU4hyPZ3T1tA3S84F
         H5pQ==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AM0PR83CU005.outbound.protection.outlook.com (mail-westeuropeazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c201::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31a4904fd5fsi681015a91.0.2025.07.07.01.08.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 01:08:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) client-ip=2a01:111:f403:c201::1;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=BcJt8AXrrGtxsKMHv7jq5JLO2ggw+mp5ICzXcJbwieqfYrGb4NTtD+zMojnHlsPpiKUtlXIhIOJO7VaDJVjnpr88Ef8MiBOz6d5zy8pEpJhH1C+x9b7PedaUbUhrsCGsZtOZfH6L4B0AeF5qyegEycWBl+bnSu9yPYbfQDxDOB4DVnfPq5R2RshR63ehKK21ebLTwEpUxIPXtYjFzR/V9xovbaBGRlmh3amxsEI/NegzrK3lgwiYXkkU3mjG4nX8HWD8uAyhB8r2Bi+bSpRcciCgdYbXp8VEvNE2irxGSczq9lF/WNeQdcl20GkcpY/TugMiRMfLrwMRB5Vy6QvpIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HQm/vMkOh3SiXontS9l4CPD/mrT2/oQ9/GBHmQvIx4w=;
 b=APi4vp/ir2P531Gdnd2Vqrrw28nFZ5DVyF1c/Pup/aL9pSBlGIF6iQtm1EJ2qbMnYjfQl//7+5dRn4nrBXVUY9rH1tWyqwzQ608mmg1b0uFBkk5aedu6SFjJmlRknpX7SxOOIxYGFWxqzFlxPvuqGIoMFc4/D9CCeC1EIaJEIUIZ6RcItJvpBry4ciBi+fTN5vTvXlkXp6hdPq584qB82cpBLvrDgBQWuqFjotuRZ7cLEffD8vmZkPWu6+pV60QEmuvpHM+0OyCcmbSdsS4VAtlEcwHxDV+dgjKIFqOGB9Wxm8MT3VezZnbdC6eLiJHGsUQznIyZh/sTM8cSZ6FaEw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linutronix.de smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS9PR06CA0574.eurprd06.prod.outlook.com (2603:10a6:20b:486::12)
 by GVXPR08MB10812.eurprd08.prod.outlook.com (2603:10a6:150:153::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.25; Mon, 7 Jul
 2025 08:08:45 +0000
Received: from AM4PEPF00027A61.eurprd04.prod.outlook.com
 (2603:10a6:20b:486:cafe::6) by AS9PR06CA0574.outlook.office365.com
 (2603:10a6:20b:486::12) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.27 via Frontend Transport; Mon,
 7 Jul 2025 08:08:45 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00027A61.mail.protection.outlook.com (10.167.16.70) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.15
 via Frontend Transport; Mon, 7 Jul 2025 08:08:45 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=u/fMn/RTZqOL0PbOgSjCrSXGJGglXHKFmu3nzh5CeeAkMc2pghMVFq4RSOfxbmzq4jv4l9NmiXry7K/ES9Hv3sN6Y334lmXazFSvtV9vPUW/Ffzl9YGk5a3Y47COCRnok8gGxEivM2ei0owtxwb4uMsCgb8jylyjHfsbvl/jf5TFIU3ZgK/vHVmizukTjS1JOtuH4PiJMeNtCMYsh3oYl0hwqKYcWd3G9sCedxtoUVl4IFBwwZJOWrpmN5N1cQ5I35+H36HCepdpUHmv/hKmKdhS1jrCzILNmCbDrnX1czTYhKo2pgXjz/TckowFW9vfcDjizHNiTm4RX3xeKqCaQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HQm/vMkOh3SiXontS9l4CPD/mrT2/oQ9/GBHmQvIx4w=;
 b=pvxSc8lCmxrC4pSZlmQ4wrmNWh1HtfNacZ/FwEGrbNzl/n+b6E4QfkqxckGW0L3Fl+XeRHBwcgESj6Rg/mp0QWlpLNR2TkUUorv6XtQtpQm9SmraIiUgzWXd37tuF+eAcIDyImz03fUruBa5JA2g+uyqbX5fmFRDMnE1wsLIEqRVBjBbSowqC8at8vafIVvXZok+Pn/JUIgonpO+BIDCSx5v7rL/27txY7wKRTeSVIoof0V6Bbjj2ctJ9NlYfjMBaNfcZ2GoKYgR21ygPtljhha53pxy3E7MKkmaOWQbqXsFgdJKALZ+0khwNcXhGR+yeFWlsp3c1K0nGktc92BOkw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by VI1PR08MB9958.eurprd08.prod.outlook.com
 (2603:10a6:800:1c0::10) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.21; Mon, 7 Jul
 2025 08:08:03 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8901.024; Mon, 7 Jul 2025
 08:08:01 +0000
Date: Mon, 7 Jul 2025 09:07:58 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	kpm@linux-foundation.org, clrkwllms@kernel.org, rostedt@goodmis.org,
	byungchul@sk.com, max.byungchul.park@gmail.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	nd@arm.com, Yunseong Kim <ysk@kzalloc.com>
Subject: Re: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for
 possible deadlock
Message-ID: <aGuAXup8Zap5pvMB@e129823.arm.com>
References: <20250701203545.216719-1-yeoreum.yun@arm.com>
 <20250707075946.2lAwc0OR@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250707075946.2lAwc0OR@linutronix.de>
X-ClientProxiedBy: LO4P123CA0630.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:294::13) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|VI1PR08MB9958:EE_|AM4PEPF00027A61:EE_|GVXPR08MB10812:EE_
X-MS-Office365-Filtering-Correlation-Id: 36aa721d-fa0c-4aba-8345-08ddbd2d7eb5
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?xz/10+fPXUts04dBRGNek/OvfgK8KhEHIoGFkbskaN/O7+wewempmyhE2pMN?=
 =?us-ascii?Q?WqN7r9AT/F4mVB+XNqupGLiUPHT7Yb97rcwBtpT+/IdRiJ7F0+rUB6qRngEE?=
 =?us-ascii?Q?tbtdYmFKDjF1KYCqim4bqHLMXv0MqjkuLzavU4ph5LmHUau6Gk7tg6o1o8vM?=
 =?us-ascii?Q?+tmtvlR9wiQmOeBSukXwLN+53pGGZr1a3EKnfwNB/iLA6IxbbYYPfCpuyqL4?=
 =?us-ascii?Q?aQZejbDkB+DgUxMA0bV51IGmS7Sgho/E4Sl7hPQvvLElvYEmRFXUHP7iQ5zO?=
 =?us-ascii?Q?X7RoQaM/YR85g4gos38bIOd2cABRAQCeQYrM5sUzy3alP07vGh8IRNvk4MGh?=
 =?us-ascii?Q?AhfHrEct7DjCYF7FuMFdKQFI2vTFefreUvjuiD7q71w0GjBVCCFJJjjkrfaU?=
 =?us-ascii?Q?jhmQUoLKH9SAzHuvLUjy0MLTADaf+jobQjMk1GBsZTkvKfVsi0iLEdOXqgmp?=
 =?us-ascii?Q?iPDL1iikTkMiX8CQ7YI3Zgyt8F8yLtAwtWacRY8pa049Pq2yqKUU6I8KFIOP?=
 =?us-ascii?Q?rbreHPda6BnayZ+RheJ5+OM402kHSmZz3ct6xmI3/xZb3UHMCsrGzWVEMuQV?=
 =?us-ascii?Q?d1jFk551hMW6TZ7qxu1dd3hjQYZlbHpwv2v/YQ0NAx4gAT2Z+h/VKS9WJwBl?=
 =?us-ascii?Q?GPyt6vyQJpKs/ZYofEH0MI4rZHZ6RPEK+FqCZn4grtwuFrP5G2noEpQuikbP?=
 =?us-ascii?Q?tbPpWSDzHIFzRjVn7Xd3ji7ERjk5DiUTemLYAXflnloj82HGSL+AnPYT5Wu+?=
 =?us-ascii?Q?+ak7jyvpwiPPP5KGo2tKCiJkL9EDIoUuwyUpYNrKp/Tq2luNFW6Ij8kiIFia?=
 =?us-ascii?Q?9VkfvNR0VMdoOybuKCKGD8Ifv9akrEYSgdyRQstGvqsKuGIoT35siiq+vU45?=
 =?us-ascii?Q?eD7yQZmosQ4QwypQAN08l+o9Pbbs3IYLyvFCNNSoSZ0ebpakVV+D9LVQLfaH?=
 =?us-ascii?Q?o8uX2SgTs/PdYdltZgf3JBxMfJwhO6XKUcphinDpPt59L1Z3Gbe51hRZA8xm?=
 =?us-ascii?Q?ee6Vuiafdztuy/wR8mMG0F5/n9Hi+a3UIyqBHwjtgnLgCFrpgkOAN8BgyCD3?=
 =?us-ascii?Q?u4a14mIunCie8AZJfXWoT74AT1VSiiQkYfWfjAPl78p2jAagGh+EwV84NvMM?=
 =?us-ascii?Q?1RlU1eGJWuYRU41tD+8S8nUFokgqq0WxFp59+G9qcX6gx5Re9ULnd0Q+nJ3i?=
 =?us-ascii?Q?5vMvHlHdfrrMGdRsyDQw0VD+4Y6Lvd33+GeQuBYgyORd/1WcqA0sNtaXrpOL?=
 =?us-ascii?Q?oMIhZMn4HmObQEsui+wC0o7GjhkYviPNU5T76bvTPeo3lF97oBE2SpuAqKAN?=
 =?us-ascii?Q?oDtgFEphz3XQeF7Q9Adk9RW50NCL4tZ/7WUzd8A4D8D1C7M+eek/55hzJp8R?=
 =?us-ascii?Q?kCPm0t4wivKcuobwgPJjmyyY0XEXx7MqyJKSJvkW5RMoj+1KrvzSoBtioo7N?=
 =?us-ascii?Q?Z1IlUBRrlpw=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR08MB9958
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00027A61.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 46fe3ece-29f2-4120-e7c3-08ddbd2d645f
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|36860700013|1800799024|7416014|376014|14060799003|82310400026;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rO1BgD1kIsBYD/7XvsoeN7ibC2arsWV3ekJS5v49ibdtZzDo0t8CmQmD+Di0?=
 =?us-ascii?Q?PbkJG5K1+epYAVlnQq8NKTIQAz1B73kDLxLtPs38aMzdU71J+XLFd1GzUn8A?=
 =?us-ascii?Q?67iB8yTAIHfC3H3fONQpRVP+PLef9QMpScLWfNiGDKun25mawB0l+iebEGT7?=
 =?us-ascii?Q?QrATBbTkXPQ+z1SUG2nt39EQHcUIvjKk67OzE10VkixXCNp4DHc3+NS8RL3l?=
 =?us-ascii?Q?YQ7qgBsR/qDYEWe3ywC4o76z4LBLEVO6GrcF9BgBjkJYaZWFtMAdHlas7nKM?=
 =?us-ascii?Q?1celD3iY6YsH7aiCIKs4IekFTl6iP442zKbkOi5xxSH4JK02o0NmwkAYzA69?=
 =?us-ascii?Q?ayeoVVO1q6xLBXKnrdqDCU7DdoCp268IWW9+BEqMPbvj0lX4iE9/Q99jyxVi?=
 =?us-ascii?Q?+FNizfhsnzssDnko0T+R3v7K59dBWzl/ENhFF0EZze1kNOeMwWUh7FWBh0ew?=
 =?us-ascii?Q?wdvd/CWQ/QuaIpmqPJKPtRKYpWxg/eNi92RCsTorI5y0G5F9IN77wgQ/CJj8?=
 =?us-ascii?Q?TcVp8rG6SKtooN85sZEZMxDASTIZ3XeS3i19POwIlDA4iXbV8uaNMMNOcMFR?=
 =?us-ascii?Q?FatQAELsrv9+Utxdi/YWhwxHE1M2y2hJy/WoinEqUDFe4hrWDI/nZl59864l?=
 =?us-ascii?Q?IdG/UBXBQb9+X6X42Dz2OjCv542dJkXhUwipXWY6AxBSIEkFF01QKt6je+v7?=
 =?us-ascii?Q?+B0d5TCg8WWt3DMG/FWT8/gSSzPyqtWPR0yOELkKkvuo8SW1CEhqmkg26sQN?=
 =?us-ascii?Q?BcgVWFTAR2MyRt5+kU04Lq5muTCuCOQmzboteu3UstVb5d/gU4IeNHJ992k5?=
 =?us-ascii?Q?PUQTjUMzheaNNLBd0VlH+dL1ViVkVUjNDc0rrPmlIfC6UE06UP5//5hOPskw?=
 =?us-ascii?Q?WmzvnFeu2OteYPLsnQe2ufGlVvgQA7YjABcLWt3P1acPgtj0fHhTfI12atrS?=
 =?us-ascii?Q?UAl6gCDxYTQ67bDib2Rb4ACnkLl6bh8GlProtidzVwCDULwHLv0x1kxzA/VR?=
 =?us-ascii?Q?NnYFJLhPexVfY4MIoiFPW35Njfq8/ABn3nD11aUEHAX/smFfrucrmgKtOdlM?=
 =?us-ascii?Q?m7K3TMKrpjHZbv41FXa/MlphcaDK37R9EcrP2Ubex0CUdGP6Ww+ViBAZTNup?=
 =?us-ascii?Q?floriaayjGJLV9uYl726xZF8nanSpc+w5QaOn72mRAFM8D0OPPk0/4m0raX0?=
 =?us-ascii?Q?NvQcrk8+wQwCzn3jh0hXYP++dAwYDFX2ceOlxWFv+JaHKSUycG8/fgaGKK1m?=
 =?us-ascii?Q?foKOB59ur5k9B8amHAxVTeJUgKwc1Syix5O0k5yVLL0lPubQm8pxgNyJy+zR?=
 =?us-ascii?Q?sdWEuXheLJE43CebXpn2bz7D2j/38R7AOILsJEcf4wPzVQxgqxH7DYkb0Qxr?=
 =?us-ascii?Q?sJ+Vqn4Yj8+hjtFOKNOkqAfFZ86tkHEOINq5eD5NxOfnxZ1CyuJmMORG01ql?=
 =?us-ascii?Q?CxhVy0TfJIXC1CJElU4BydjnG/+VoLQRD/jSl7J9HzQmRYZsbVKnuhR2I/pg?=
 =?us-ascii?Q?XQ4cwEVPnYFVkf+7+rye2nOBfLYLzt9sNv1T?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(36860700013)(1800799024)(7416014)(376014)(14060799003)(82310400026);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Jul 2025 08:08:45.2497
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 36aa721d-fa0c-4aba-8345-08ddbd2d7eb5
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00027A61.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GVXPR08MB10812
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=DoEUPHnp;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender)
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

Hi Sebastian,

> On 2025-07-01 21:35:45 [+0100], Yeoreum Yun wrote:
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 8357e1a33699..61c590e8005e 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -387,7 +387,7 @@ static inline struct vm_struct *kasan_find_vm_area(void *addr)
> >  	static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
> >  	struct vm_struct *va;
> >
> > -	if (IS_ENABLED(CONFIG_PREEMPT_RT))
> > +	if (IS_ENABLED(CONFIG_PREEMPT_RT) || in_interrupt())
>
> Could we stick to irq_count() ?

I determine to remove kasan_find_vm_area() since there's some case
couldn't be avoid with irq_count()

Please see the latest discussion:
 https://lore.kernel.org/all/20250703181018.580833-1-yeoreum.yun@arm.com/

Thanks ;)

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGuAXup8Zap5pvMB%40e129823.arm.com.
