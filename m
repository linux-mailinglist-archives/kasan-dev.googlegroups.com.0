Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBL6FWTCAMGQE4DK6SYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0752EB18818
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 22:25:22 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-76bee0c0157sf69203b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 13:25:21 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1754079920; cv=pass;
        d=google.com; s=arc-20240605;
        b=M/Rdmy2Hl2pAH9GdVh7pDx/XM3NbBuy9FvQ+gbL+pAgQ54UHbwTWj6comhAOWjaNqV
         QDcUdsTnKzeIC0i29YyRfn/U1MZnXkDHGPafH7aNBx6jdiNYSw5YYGfr5hyy7pVTKWpY
         e8Y2Pev06Mg8sTyCqvxLC2KOxu3aLZpWoW4M1qOCxBB4N0pQqA5QWvipstS6e6Efi3V7
         KHlkjLd0zPAhqRTCrOlj5U+nwGXMWA+dh66etV2rcwG6dRPyDLblR/tO2+UFPh0GfbH9
         iQC6fpYQtL1fLpiQZwTxin8Ma6h0OBZi9z3WXenfFccmQqFwHaPkDMUQogiaf43z1YSI
         583Q==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=pdL9CfRdh/hC66yXk/xsAtMvUO5LptwZNgazqm8MXDg=;
        fh=4lJroiUOByOcxrcaaLIHfZXLyNqgtM4nHneUj8wBxKU=;
        b=B+8I19TmDMS45M54XktRERBkbgit50myrerfMb4unVUtO2cWEkv12sUzsPysN3ZGJH
         F5TR2XAN513m9QBWGiHjXUbGlukyWxS6L8QUt0d1QH82rBsNw4VWiEyiMdizqjl6OP4n
         IT/oJnLhJ8j2II/NTOexWPONBjhQaxEZItvkHbyxCaRZqcnA4j47Hdzf2omgz2J9kXit
         72qd6edvJ8fPG91RKHHEWpJ9R/HJQO4/3WtdS8ZGeGOLwIAQR8QtzM/+lim/YJExb0Ym
         7Kwx9HZNkXpBwu1BFp4rXTCIWqRMGDFo/WgCeSepgBbookxBTNxAVhDSZn9duCJdJr2L
         uWgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=nnF2CINA;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=nnF2CINA;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754079920; x=1754684720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pdL9CfRdh/hC66yXk/xsAtMvUO5LptwZNgazqm8MXDg=;
        b=QVP1zPj+sNIv+78dU6AzoVsEMVptKq1zTjj0xl1eeZUrDzD2JYHh61zUYp4gbgZ9jg
         MFOjjgvkVPJhA/aZor4bD7fypAeG5rS1g+QEG/b32GDaPldIpOsNfV3D7jdXUHEhsKQT
         YgCGQUV69s/ES0+/6elbroIrPetSqoj2ImiC+QaIY9UKtz8V5BJOaI/9pDLsIjij88X2
         tain2qjeLKFmq/uccaMyp8qAP1uAzmHuI421KXBcuCy/O9BSDBB93fS6HHozJ7GBfCih
         HkTzEwQGkAW5R6XFkg1a17yzQX7oZr1QfNTwp2Y+fLfcc7LeuqW5enkyaToOqamM+qQz
         8pzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754079920; x=1754684720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pdL9CfRdh/hC66yXk/xsAtMvUO5LptwZNgazqm8MXDg=;
        b=UvQcDWr1hJIS5OMS4EURZAaoKG1Ps5fzFcL+2GEDlbWubKzXFDJfguEM3Xva9S/gne
         Ag73vk2WfmX6Ie47qUfD5PJ6pm2T5JVGtTPtRKscf3W+YfV/YpSxN62FTWq0wAC5muga
         ImEgBUFswTEgUTnZntChPiP0P8K0JyAeM8nsgX2Tky1FX0Npwec0BgM6w55Kbjuz3oem
         4z+3jJB6XBGvup9/fs5zf2a4oGSt8GyBvIL5gS0NmuWKDUupP+YYZOEoP6Z8UKAKG9B6
         cJIknyurJ05uq8K5LrpkFutyK01VMwjyA6RhCDML1Bn5J298806LJZL6x2bJGSUG6Yhu
         KPnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXUKnzo+Ic9r7IljiUtGTjYg0e+jvTMr4m/Q+rWznahN9hl6EwtBUCXF1uFZO5l0fAKX90pCg==@lfdr.de
X-Gm-Message-State: AOJu0YwCmd9+ywK4FEqfMsrXBWSIWNBcd0GC3KGah+QxG4X/OD5qEtfn
	+Dh3jlEp96E5o5GYI3srwQb80udFj4RzxjF/0+tPGpLUM3ETK5P344u1
X-Google-Smtp-Source: AGHT+IHE4v+rK1ORWzSoOjFBuQ0SewbFFsYkf3DqrG7ww7H46tcFZNaq+QgwCurGyYwPTPAfe8oNTw==
X-Received: by 2002:aa7:88ce:0:b0:76b:d96d:a9c9 with SMTP id d2e1a72fcca58-76bec3082c3mr933245b3a.6.1754079919871;
        Fri, 01 Aug 2025 13:25:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcurU2B+0XZI8HYFgRTYRL0SY6T8LM7t988u7ZIxtCuBw==
Received: by 2002:a05:6a00:1810:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-76bc8cb744cls3395191b3a.1.-pod-prod-03-us; Fri, 01 Aug 2025
 13:25:18 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCUdSFWdPU0/aiFms30zqYrsUlGQZWPa1h4VhY8o489PkoyMkeSToQSdny1skT4cU34YsOdiq4kk/Hw=@googlegroups.com
X-Received: by 2002:a05:6a00:1ac9:b0:74e:ac5b:17ff with SMTP id d2e1a72fcca58-76bec48bbddmr989804b3a.13.1754079918463;
        Fri, 01 Aug 2025 13:25:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754079918; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkPoYcQuvzk0hlYiv00YH4qD0Ho3TRJBA56lpORyGJa5Hgl2XzqFIAQEpYEODQ/5S8
         AAqslHznDD6EB52F896kZeGlzt7dWfFxQIm1+/hPTpvLZGCkHtA9wlRpOU8TyftOc58j
         +1gMA7IpFlxEfAj86r0kgyP4z+y5UT6OUF0snyKiawn7rWj1GVHwcjQGIU2oyGkQBIVi
         ghNX3+aeSjz9bXbswlfmEQj2cBIrmwvsDVpbbQtRc7T9zHxh7/BjG/eU7xw3pRmn1nuG
         SwbZ08cZrHxoD2vXOU7Li/GV6ONxHBKKUIJ0jyUpPoHQ45UOhgXbVMrG8r1yxGhT+2/0
         pATg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=sCssUiag4/GGfNeV2+HZ54KE8qE/7uCnWmcENsIuhYc=;
        fh=cLB7AsqtSSU/L+wfETa04/gQi4+M/Oi9NkUjCAhHXEg=;
        b=NPr+ZdV445ccSS+kV+wDL13NSqK1bHmtixe7a0QQZsLwu4dqY6eEYDfqLffG1Z4R0J
         wKLc2AlovuqMIRg1zkdT2Yhe12F2MaRpJYTZz9lv6zL3o7TR1Ka5EFn8xPNSsBrUPEqv
         JuW2+EdZDYn66bDCsySHq9j7Wl+dnAb2qp4THOaXM8y2cTsPevNYfSekxwssrMI3IC2o
         l6GRw1SNnlyHfg8t6i/XbJVTQHa2rBIz1gaHLdlQLw79CnK5eJ1aMgc0TjNcHRGeDwjt
         zTyW9XRXutiQB3+Yw2Za+OU4tgg+KlKwwE8Y6CPQVH0pUtSkfvHthTQ1ya5HXldhgVRK
         LIkA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=nnF2CINA;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=nnF2CINA;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AS8PR04CU009.outbound.protection.outlook.com (mail-westeuropeazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c201::3])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bccffbb16si192984b3a.3.2025.08.01.13.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Aug 2025 13:25:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) client-ip=2a01:111:f403:c201::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=Mv30PB4YMTGJmdFF/k5vtuCYeOe7SM4qZ6LOIS1iowE5cews2EUvgfji/+Z1lHdwCONI2ns9eRZzyRpvA8mswxHz9sxg7upC8H5s7Lp3l+RQAL1TiAGUXhlwac+o9+fjn60RjRCMH6IoFuArMvR28bpMkNrpJAci2c7AqFRr9uxhlrymOgVVlqx9GIXWb3BwBjiHqqQ+5LPWn7gjgN9mFq7DfqXKWbN5HM7q1wftemabezkDpjqhu7OvZSjCg1JaKVeonKciWlV2vJqPXJKqOJpQLDcDmef6Y4cp12e04FsbUiwhHtO3AVgT19ZrKZGjQSEblq9Pyv9GUIlLCDB2oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sCssUiag4/GGfNeV2+HZ54KE8qE/7uCnWmcENsIuhYc=;
 b=inVXcb5VIVm74YnUImoFNUSD8XdneY8BFuEKRfGTjFgDjedViF+I4aDZYQwyAjtcggItccxgRiYqgFfYBOUrej+QHwW9osiQ5pLM30LPAPdQHDPexwDfP7O5a5rKp+Ey9rGUzRzcERsMnG6YwuN0MuVthty7PQV3g33GhiMv8FXUTA8U7Sl0ZOrDz6B7viklgtevVEhsKklQqlk0QecgqUeO0TIMihdS8I/j95aAgKDx4891ZacZYMeTlJSheWyQtavuJnTdgO9rZZOhFJIgBpf0VXOclvhBvxK8zs1RuSy2gEK1A+D/YDXVjqpVij/UX1uJTe5QlELvSNnplzWEGA==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linux-foundation.org smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from CWLP265CA0488.GBRP265.PROD.OUTLOOK.COM (2603:10a6:400:18a::11)
 by AM7PR08MB5302.eurprd08.prod.outlook.com (2603:10a6:20b:103::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.16; Fri, 1 Aug
 2025 20:25:12 +0000
Received: from AM4PEPF00027A5E.eurprd04.prod.outlook.com
 (2603:10a6:400:18a:cafe::cd) by CWLP265CA0488.outlook.office365.com
 (2603:10a6:400:18a::11) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8989.16 via Frontend Transport; Fri,
 1 Aug 2025 20:25:12 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00027A5E.mail.protection.outlook.com (10.167.16.72) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9009.8
 via Frontend Transport; Fri, 1 Aug 2025 20:25:12 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=c5w9QJJUcYw5bis+gIm5llMGkElwIRT3YwawDN7LzSi/mGBnNCcPfWxQ4PCpuRZ3yImxGWyDEk94jV0fI4KSFO5xN2NZB+32NRsgbz/rZfiWZK09NoZtVDZGMIuhxyjZGb2NpCBT+Ss3vTfhZvcBpcC5OifEHfoDqj/Xc00iqG/DYxEhdeQVF5rg5n9MTtLror0JGzIHX2j2QHQtKhLHuO/lI6rFpot4L2X6lvymiWk5Aoy1TIYejefZzsWQDFzNDiY+/N0JOEe7HM9XWOVb0GPYmxuPTe0iZX0csm6IR/ZYSxZ75+ZTP+xWsu5nnPwbn/NYpvt3uwdbBNskyuBDow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sCssUiag4/GGfNeV2+HZ54KE8qE/7uCnWmcENsIuhYc=;
 b=oi9LgwIy4W7/4sL1sH697kuSXP29l1OUwRZBVMZNY0Ibq06Bgj2vFXL3NCD2BJzV8B987009Tc3dmVGclkKVwnLthyHpNfzZ7F2yEJ7HNZ5n5psk2qs1E3SMJ6hp0w7lmSFdVb/4X8AKOchGkk5eHnrGuI+LyHV+d7zkTSEz5bUiOR5RyvjdvfU3mwM2+49TpkxUDj+NhH9v5RxNWXe/4Mqlql1/tPwskG4hcNG8v9U3BUzaA5CWNOTEJ+d8kFzPGdCLsRpS55aMbsNbfSB2ZlmUqxWErNrbwXuR6GB1/jrS8bQhwEqw1hVy9rhJGwWn5LEbK9r2J0D6bBYDhavLYA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by VI0PR08MB10711.eurprd08.prod.outlook.com
 (2603:10a6:800:20c::18) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.13; Fri, 1 Aug
 2025 20:24:38 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.8989.013; Fri, 1 Aug 2025
 20:24:37 +0000
Date: Fri, 1 Aug 2025 21:24:34 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: thomas.weissschuh@linutronix.de, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3] kunit: kasan_test: disable fortify string checker on
 kasan_strings() test
Message-ID: <aI0igs82mj5Qowxl@e129823.arm.com>
References: <20250801120236.2962642-1-yeoreum.yun@arm.com>
 <20250801131327.8627459bf3d94895d42b95b2@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250801131327.8627459bf3d94895d42b95b2@linux-foundation.org>
X-ClientProxiedBy: LO4P265CA0259.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:37c::9) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|VI0PR08MB10711:EE_|AM4PEPF00027A5E:EE_|AM7PR08MB5302:EE_
X-MS-Office365-Filtering-Correlation-Id: 22acd63b-cb25-4cf5-68aa-08ddd1398463
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?SmxKK013Zk40VnpqM0VOVG9QSUZHVDNiMDBIeVR2T1h2QWp6WkluR0hscWNY?=
 =?utf-8?B?akM4L1VkV3Mzbyt4TkdPOHExYjJ6UW85KzJTRU11TXhrSkd1bWZUcHZPU2Nw?=
 =?utf-8?B?KytMTkJMaDdBRW15MG0zUU5wNXV2S1JhbnAvU0hnQ3NHUjlrNkxiZGRTUC9j?=
 =?utf-8?B?VFROZStTdzZzOHh2bVdyQThiVitEL0xnUFVRRnZUT2ZQWlF3S215VG42anBK?=
 =?utf-8?B?ZUtBRWNhV09aYm9MYmNaeDJqVnJ3dmloSGRpMklYN3VJekUzRjczMld1MGZx?=
 =?utf-8?B?OW9CaHRlMjJRMGpna1ZidXU3U1g0aXFKVENaWTdFNU9wV3RpY1MyeTZpaTh3?=
 =?utf-8?B?Y1JTb3Z3TitqR0Q4U0hDbXBHRncwSHBLVVpKKys2WG83SzkzSjNYOHlWc3Az?=
 =?utf-8?B?ZEFrQXZxTHlITVNLODQ4MVIrL21VVnJUWnRScUtwRFVHM0Rra1Z1QUpHblpN?=
 =?utf-8?B?M3JQSXRQdXRoRVE2dkY0RXZ2eVFBMEtaQzVCbVdoUzFjVnZYYXJYYUgvY2hi?=
 =?utf-8?B?ZlA5eDBiT3JzY3hiVE83UkM1MjlwWVpRUWduUWVtVXQrY281ajVza25xdjRH?=
 =?utf-8?B?RmpvaS94RGlzY3Z3Ykd2aFFqNmVUOHF5TUJrUFpTaWFTZzNpODFTN1F4ZXJ5?=
 =?utf-8?B?MnljQ3lscWFTT2pWK0lDQk1sYmEyaEpmaWZYUHlTaldxMlF0bmowS0MrVlpj?=
 =?utf-8?B?TmhUMWp4REdnYnVuNG5Tc0tqeXNNaGlLTWZYTlo4a2xTQVAzR3F6akoyUzRH?=
 =?utf-8?B?ZEd1UkFLOTJrMFg4OXFPV2p0TlVObnhnQ0prNytpdEVWMVpqaXJ6bkgvdG1h?=
 =?utf-8?B?WDFQWmE4eXowQzcydGVaMmV3Y3Fkb1NwVmN4aU9tdGNPcjU3T1VHeExuVTAy?=
 =?utf-8?B?cW9ZeDZkQWtKOHhPZW1jblU3UUt3VmxSVzRMYlptdXp1ZlBUL3ErV3d0ZFNo?=
 =?utf-8?B?NVBJdXFXU3FUUUhwQktRRFpxTk5XbTdwL3BvbHVYNitTeW1rQm52a3BXWTY0?=
 =?utf-8?B?bWEzcEFZczNJSTR0RUthL3NuWnpJUEo1VTgwQW8rSVFZeHNwNk9oRTIzdHRo?=
 =?utf-8?B?TUg2ZDhFVGQ1ckQ3OWRsRGg4SlI5SjJiV1VrenE3UWJSOElxZVBVWnVQZ1VI?=
 =?utf-8?B?UmpERWxGNG5mQ2NPSzhkWWJGSXgrV3FGaGxFQTJHckFmUWpqN28xa21NenJO?=
 =?utf-8?B?cGduRUc4czJTR2twdkZPSTdOdHFDWGdLQVpSUHNybjlCV3phbzhpTW1lQ1V2?=
 =?utf-8?B?bGtpNXZkZXh1bFJ3OEQ4YnRJRUlQUFhwZTNDN1BTMWFDeDByamxBR0dvdkhM?=
 =?utf-8?B?QW54OHdjUi8raUZKSkdUdmZVMzgyQmk4YXJJZDNGRHNzd2xwWDFvTEdSWEd1?=
 =?utf-8?B?WURMbDI2US9KNlFBbng2cW1jaVArUVF4UzZFQi9wbi9MU3g0K1lHRm5KbjJC?=
 =?utf-8?B?dnJmV0VQU3dNVEQzc203YWhrZkJuUEI2TVNHTzA5eU42R2VWRS9Vb1U2dndY?=
 =?utf-8?B?V2ZXUDVmZU5zTWIxaThyRVFLNGxPSFAraFF6MlVCblJjZVFHUmNqR3cxOG1U?=
 =?utf-8?B?UnhQVVdJQ0k0QjZwRVNEQnk0bDFIZGF1VkpnMTdNbWJYTU9ndFBIamtDYzNE?=
 =?utf-8?B?ZnBNWVFXb2V6QTA3RTNFbXNwK2FGRW16emp1V1FpK1lGaWQ3MERaWFMzdkQv?=
 =?utf-8?B?TjN4aWZ3Z1BLNE1sZ2I5NEs2eHlBdGRDRXVmY2RuOXVQUUF3S2EyR2VtZFVl?=
 =?utf-8?B?MVRXMzNYMk5pcGFsVHNVR2tIWjgvUERGUExpeU1IY3RKcHUzZGFhQjNwY3Nl?=
 =?utf-8?B?OWswUjJhWlhrdTdSRGVxUk5qQm5zOGw5MnA0NWdxT0VxdTluRDZYSnRPWEkr?=
 =?utf-8?B?QzMxM1VUd2JjZnlNRG5GbDdlTC9NWXdsNnhsZ0dyNHZzNS8xODFwTkp5M0VV?=
 =?utf-8?Q?ktmVgmxRrKA=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI0PR08MB10711
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00027A5E.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 62da765e-6a22-4e0d-8d49-08ddd1396fbc
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|82310400026|1800799024|36860700013|376014|14060799003;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?dWJRc09OWlpiWVRFY0tHVkNhYWxhNmZCVmFLWDFrd1ZIaGFhSGg3ZWZYclh5?=
 =?utf-8?B?OUpGbTZMZ0srMUxZdUVLRVBiRDRqYTNCWnNCelVkcFlWWTE1NEszZFprMks5?=
 =?utf-8?B?OHpLMjNxQ014TmRGK2Q0dVluTVMwbVVTYlR0bXk3aU1udnpqQ25NSDhZa1d4?=
 =?utf-8?B?UDZmM3dLdnJqNjg5U0kwWHE0ems3WWxMSmZYYlRtaGkzdEh4aEhDempMckdI?=
 =?utf-8?B?RUk5djE0ZGhtbW9hNUd3ODNOa0lrbldVaFpTYlpwQTlhNEl0bWZYS0VkRGZu?=
 =?utf-8?B?ZzVzSTB1YUNxSlZOUVBhSk9yUjdycVhIbkJqVmc3RUVkamxxcm9QQklndUdo?=
 =?utf-8?B?QmttcFlHTVFhS0lscmM4aXlUOE1BeHF5QzVYVS9MYkZCSk5wMXB6OUVHTThs?=
 =?utf-8?B?aFJQUW50RDQyYVY0MVZkUWJET3JoVUtyRmZGTVdoS3BUT1FtZmNPMzJJRCta?=
 =?utf-8?B?R2pGRGxxR01ZaEZHeFQzSlVGU3BBSWM3THRxNXEwN3Y0U2VDb2xQeFo4V1Vv?=
 =?utf-8?B?bmJTcWRMYkU4V0E4NjVNMTBXbHRYTHJPeFJQK25RZEFmdmJOaE9Sd1ZReU05?=
 =?utf-8?B?bGRtbWoxbkJoQ3g1VjE3UDRkamhTcXVJNGQyNWxLTGp6dkJybFZ4VkZWbHRl?=
 =?utf-8?B?dTlvc1gvZG9mbXdGR3RFdUYzMEJ6ODZaQjZvSjVwNEhycGpObmNtOGxwV1lF?=
 =?utf-8?B?YVI5blBmUENpVXNMbWhIMWFPTGVna0dHbVFzbGZNZDlwN1lHV2hodk15WDl5?=
 =?utf-8?B?ZnU2NkFyaThLeDFlQkZlSkQyRDlhUTlCRDJWODU1aHM2Q0h4dUdLVUdJYVdk?=
 =?utf-8?B?cEtkeFpoaEJsaWFWbnVpVjdNeVVCaXRzdXRCTDFQTG9VMW9VTnV4UDFrYk9V?=
 =?utf-8?B?YVdlNS9nRFdSVzNqamNORm4zaGlsc0pMb21uOXJqZnRDK1hOZThyR0RBTWpz?=
 =?utf-8?B?K0IzNGF6S1pSN2dzVWVqTkZNUXk3cEptTmgwdlM5MGttWk0rRUQraTZNTm1D?=
 =?utf-8?B?NTFBZG1jaXhjYm55M0w0NUlVVXpmSWpzVjQwbDR3VFVZNHVHdVgrZTNlSDhM?=
 =?utf-8?B?RU9Ma2NOQm1nL1lGdUpBSTlmWG90eENvNndNU0RrR1FuOWp2dzQ4TktTQWtR?=
 =?utf-8?B?TkMzT2piNDVKekl3SGcyM2xVOXZ4OGhnUzYrQUZ1Vzh4aU5COHFrdXdyK3BJ?=
 =?utf-8?B?NHoxR0NuZnV4WllzTkZYWkU2eStNZUcwaWg2ZHdQUVdiSFltUldnSFREVTYr?=
 =?utf-8?B?MXlYK01YMk1xMnZodXgxZENidWVXaGcva0J3aTJsSU5YanpqYnRWOXhTb3g5?=
 =?utf-8?B?Uk1xaW5qSEc2U1VZQnRYZjNKdUJiTGlCSnFWOCtodjY3TE8ra1VlZm4waWxy?=
 =?utf-8?B?U1Q4V1VreWR0bXhFbDBpZHdFUzNKM3Nhc0pweXN6REg5N1JjZlAvSFdJQjBX?=
 =?utf-8?B?WGpESWoxMnczUHdvRDZsOGljRXhzNjU4Q2NSRURGRythakdCVjlxN2dZWE9H?=
 =?utf-8?B?RXJrcXMxNFpRbXdYWlVQTnI1Vy9CbkoyNXhRQTJhcEE0NTFqSXJ1SXBEaDZU?=
 =?utf-8?B?bWt1VURxaXNsUktSZDZNMTVDR0dxQktVQ1liZS9iY1lLOGpyQWtKR3pTT00w?=
 =?utf-8?B?WDgwLzJ6ZjBtaFV4b0NhMFdRdTJyemF2SVIwV3NJRjNtZ2ExSFpwVFYya0No?=
 =?utf-8?B?N2xWNmRoZmZuVnk0QXF3T0Y0emN4OE1yTVpaakNOWEd0TnE1WkVDZ29sL3hQ?=
 =?utf-8?B?WGVLU3RRZU11SEdsVmJ3dlViR1hXZ20yNDJJWjQ3M20xS3RCNzBnZGE0Z0tk?=
 =?utf-8?B?dEJnYk5NTWFJcUx5bjV6OU5GWGV3clZFMXJyYVFMQ0g3VFFhOU9PQk5pRU9J?=
 =?utf-8?B?cTJZTEVVVmR0RjhwL3FuRzUzamg4NGNjWjlKUWFLRWRHWVdzRG4yTmsvUGZH?=
 =?utf-8?B?YU1td1c0ekorb1Rkem10T1RCRjd3SlhpQ2xMS1RBdXhrVEI3clBjWVZFVXpQ?=
 =?utf-8?B?RGUzRDRIaWFINHhyWGVnY3lWZnJCekxWWTEzRzZxcldPc1VDTnlXV3ZHSDV6?=
 =?utf-8?Q?3OC9rQ?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(82310400026)(1800799024)(36860700013)(376014)(14060799003);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Aug 2025 20:25:12.0045
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 22acd63b-cb25-4cf5-68aa-08ddd1398463
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00027A5E.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM7PR08MB5302
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=nnF2CINA;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=nnF2CINA;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender)
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

> > Similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
> > FORTIFY_SOURCE") the kernel is panicing in kasan_string().
> >
> > This is due to the `src` and `ptr` not being hidden from the optimizer
> > which would disable the runtime fortify string checker.
> >
> > Call trace:
> >   __fortify_panic+0x10/0x20 (P)
> >   kasan_strings+0x980/0x9b0
> >   kunit_try_run_case+0x68/0x190
> >   kunit_generic_run_threadfn_adapter+0x34/0x68
> >   kthread+0x1c4/0x228
> >   ret_from_fork+0x10/0x20
> >  Code: d503233f a9bf7bfd 910003fd 9424b243 (d4210000)
> >  ---[ end trace 0000000000000000 ]---
> >  note: kunit_try_catch[128] exited with irqs disabled
> >  note: kunit_try_catch[128] exited with preempt_count 1
> >      # kasan_strings: try faulted: last
> > ** replaying previous printk message **
> >      # kasan_strings: try faulted: last line seen mm/kasan/kasan_test_c=
.c:1600
> >      # kasan_strings: internal error occurred preventing test case from=
 running: -4
> >
>
> We don't want -stable kernels to panic either.  I'm thinking
>
> Fixes: 73228c7ecc5e ("KASAN: port KASAN Tests to KUnit")
> Cc: <stable@vger.kernel.org>
>
> What do you think?
>
> We could perhaps go back earlier in time, but 73228c7ecc5e is 5 years
> old.

Unless others feel differently, your suggestion works for me.
I had considered including it earlier, but wasn=E2=80=99t entirely sure.

Thanks

--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
I0igs82mj5Qowxl%40e129823.arm.com.
