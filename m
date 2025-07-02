Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBSNRSXBQMGQEOCKJIPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B243CAF5E06
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Jul 2025 18:05:31 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2e926f54767sf47547fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Jul 2025 09:05:31 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1751472329; cv=pass;
        d=google.com; s=arc-20240605;
        b=j/zzrMOoKsnnbvD7cSagKDSuZLrPhn5CzOJP+QL9J9MTq3zdGagKwb3//7sqOU5tlx
         lMzEN8rrcHIC8o3+inLjah1xxXt8Ua3Z0JKN+lC26vX5km/rtpFl6cp5LknrwYvt8ifr
         TdwhqryTcgaN1G9iNExELZrJWavkp42QuLF6RET7OVb3/5KUmsYfF5JYYI3leTZzRnxu
         /A7Fab+tfyYwAa3uOIDU6YNdg1Uum+Ki2bVYRVo4cnXmL9mUTk5DmxqW6bR6bk0yQSw+
         myh6L9ItlAt8sPmaRVPBU7Jj7eaEUah3mbDMaeiPd2Y/Nj3PpZ8HqxFtNVLfkxgOB908
         /Sfw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=6xfxTcAvI4r7XAarVK88Jga9ErH5VVPi3HhPu1Z+f/4=;
        fh=LEMmvM7fhbNtgs7/n60ReiXluoV1aB+aQxcT5LMVvbo=;
        b=lr/NA4geflhrW+0l64xA8HeiU18B4ua7yMjcmTHGiWxSxp+weCBN7KgK+AC5SqvzDH
         AYsQNv9uHVXIM++CrwGLBA43uwYU5iEMGYztrGcoAm4ykxrZnWGG2lWELQ3v4X7hqFwy
         JInRADbiwmxqIITnwpmGARHtVnAntlUFjPnwedLSa7cZzJ748LLlC4nE2VwiFcJapBjC
         4buCN3TSGnaymuwVb5e8jacstZ8JhJCoTVBuTGeodYIyJK7m03GZD8HO29+igioK3qh/
         E21V1DJmwkG0YuX6te7Etge0IeroLXYabwbStuZ4jNaEglJGIGUBR4Er1xgQr8RPRyJ0
         acdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=lhWWobyM;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=lhWWobyM;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751472329; x=1752077129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6xfxTcAvI4r7XAarVK88Jga9ErH5VVPi3HhPu1Z+f/4=;
        b=Acoozf8WJaRQGedsPu0YurITClp0tU/KnZfDA9euUZuSo4VdSXjSE+tvKaZcl7ZzG7
         Ucd89UpXpnIEy5keOKgYLCMQ/Kx+X3Tsae21FQfcm86EDYcS+S6DsMRoLKQNBVE57Dzs
         q/3NgRQzRamJQcp0Q7Ov++/v2TfBzS81HiDNV5xDK6EUvuHLDYNtCpjGyKxCoHAUiKKu
         r8WPdDo6VcUW6qu5k4ouWIyAFFR9dcG0qubhPXf44NGVnMUEsXVLn+Yi05gS8NA0aHFs
         l7hVCN6uojWYuoWuGkMSTz+xSJOyPVsXQ6sZ6vgG2m+9FFTF+0TEqmSstXjdfRytJ6pw
         Us0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751472329; x=1752077129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6xfxTcAvI4r7XAarVK88Jga9ErH5VVPi3HhPu1Z+f/4=;
        b=JkQqyCpJBDPg4uorwCdXWbQH8CrkOEV9cF47Xsv4qsuHU/IcPDeFJSV/nqs4cU3NyP
         jHkdmgFrD7mD9ANMV15CwM+rJFw4u0hQrGLTYfnTafje/ddixGYis9iMW6m/rYYw0wPD
         ePFFOz5lBTvX4ZNOGhBES2QC05v/0ahV9AQpxI6ih3zWrk8GaP0HaqcmZlEj6ODrjWwt
         5jcBp5dVfB/vK+1cAEwv28Hu7wYsvXEqLt2b11lSBudjLCjKcMYH+3dkna86s7bUOcY6
         THPUNbaJ9gkCGXk0nbeN+kLCqzz/DyNchGmwj5YU6uI7jeQrHOOLXFb3l4U5jBJHQge3
         mdXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXbqsk8fyAvJQvsvK1xMo/zPlWLcbr8M03362GVKFI7IPHmGwlU+ABTzIA+kM0biaXwl7565Q==@lfdr.de
X-Gm-Message-State: AOJu0YynKCgy029Kz8GMvKFNDyt94/KqXCfnPk8IuayyaxYKf7V31n21
	R+8t2Dg8Vyi8c1qknWvrRsy5AEDhR8ly4Rl0HijtWxvIXxEeJN82XvL6
X-Google-Smtp-Source: AGHT+IG4Iy3cygb0w1TqmhoU+k3FTLc6rZbStyNmC6/D3ffSyOiex/cJgkJ6aR8w4NpAioThNlN58A==
X-Received: by 2002:a05:6871:580b:b0:2e8:f6d4:535f with SMTP id 586e51a60fabf-2f76bf78457mr70821fac.14.1751472329421;
        Wed, 02 Jul 2025 09:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKlJhC0qN9F/joEcwmC29XtZ8JVxsu/0gNhLbHiTTyKg==
Received: by 2002:a05:6871:200e:b0:2d5:17b7:9f8c with SMTP id
 586e51a60fabf-2efcf7a30ffls4927757fac.1.-pod-prod-00-us; Wed, 02 Jul 2025
 09:05:27 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVGmmeMpSwWiVCaaf1+MqcOI40FK16x2iP9mc3rAEyj5LmWrXKJ8JnXZQVArx0HwntruKl9gSpEXAA=@googlegroups.com
X-Received: by 2002:a05:6870:e38c:b0:2f7:53e7:1131 with SMTP id 586e51a60fabf-2f76bdeefdcmr82585fac.10.1751472327425;
        Wed, 02 Jul 2025 09:05:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1751472327; cv=pass;
        d=google.com; s=arc-20240605;
        b=l15dEm3BQm4s2JkaPDJjaEG39LjHF75GP6HmwFaMqeHt03YOu5xpPwDzMB4eAkVvoH
         iWFleK1TFvLH1Wji/ceLhzhGml6dI7w0TCwlwIeppvhB/bZBFl8tkCGsICa7EqYOF2hB
         /Kui2+GQf8l5ngZoIHXrScbr33hKMRDmgQuoGSZ6YJsUYq0vGctgUCc8rrBAuaZaVosP
         isCh8dwJsngwJA/srdObPzgemOKzJ33Nm63QWx+HI9hDkRKz7bzqbAAbHpEWASFtlMXo
         nXqXBDNk/qnotMSfoy2oeDWJdpNgMp22Yub0zS0DZkfa63z3NiSogHi7XNysBd0Iqbhi
         rjIw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=Jd0LN4d76BfimfewCr+2SSbA5uUsl+ULDX/iasFx/50=;
        fh=UaeQY3bZca3NVDmAQ5qTQoQNVbKXCUnJdSw/QxpvlUQ=;
        b=F8xF48DoAzD9f5b8JCMngHxYL0HjqtcERiZ3nBWdveLJneDbBLwsDg22HYXN54LaGF
         0pul07oDIVA+zQWdias3ab6H7WFf+gKkwjRnwMTA8E+8NnmbRl07ngr1nu9ADX1GISK3
         l5O3tuBb2eMSDy8pd9SBdHJ7AHGCXHiyizYUh+l/PPPC3tyIn0tOolI5qPant1+TlSbj
         18pt5cpNbq9uBcqEyrWVAaDeme3WpSdlVu7idfvk6w4NiEDcHZ2kgHIL+xpG3Y6tB3zr
         763gqh0z903OkTZrxeE0SVrA38iPW0leiMRdzYgIm7b729NIF4iUBlfkZ1mvUZjozQst
         X3uw==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=lhWWobyM;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=lhWWobyM;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AS8PR04CU009.outbound.protection.outlook.com (mail-westeuropeazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c201::3])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2efd50de3e8si795742fac.4.2025.07.02.09.05.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Jul 2025 09:05:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) client-ip=2a01:111:f403:c201::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=i6k3kjRafHN7ratnEM5ga3dN9NgDcfabAQMYCdvyGMl9zoklLt7CsL1hDJ0+VtGFn6ub1W8lV91Q6sPMya7Am/3inQ0lodR674ycP6VLl1CM9wTYaNmWQM8hiLdGxR4uFsB8HTXhf5FAAwwpzV6DavWKsPoA6C/dMTw73k0lV5zBl7NXJkmWGrveRka5TvsazeDK7eOXo9Zjgem7TR6EF6KsfvPlWBZXkfXZAdt02ZGC7Mi3rl668+Fa0SjHU1ffUzTlTM4AizLcevemeQaA3nUfuN5zBwTuczEKuAbBN8zElMhLG7Oviqm90SyTXZ6iTZFWokZqcmnvjks7T7UUOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Jd0LN4d76BfimfewCr+2SSbA5uUsl+ULDX/iasFx/50=;
 b=VmjNteDw2hxoYL/9WFFT91ycBMtw0jD8MO+h+IzLsZ7QaNO3BH+DpA/gJbSJnt/UlzMGGFnTAmjkoXoKwEVSUbXzFVK93paCt5ZE+/DrSzvptNdovCXx0+Sxnjm423Sq4Rii8xYMTIXZSmy0B+0d2aMX8+cHIJkovH9am/LpTBaTwUpX59QQZzNrtL0IHog4U2HYqnqrtc9YudwjCfUlc7Gc2569foKtNT5v9O5Gh36qnOP+SxudAJZOZN/ipZuFnW2I22RYYCLi4xTQLwVCqgWgzmGL7/lM+0DwsyqV593hpyB3ZuGHbMayZtovGDzf7gc+ZXseK/dFycp9hySSOA==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DU2P251CA0003.EURP251.PROD.OUTLOOK.COM (2603:10a6:10:230::13)
 by AS8PR08MB8734.eurprd08.prod.outlook.com (2603:10a6:20b:564::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.19; Wed, 2 Jul
 2025 16:05:24 +0000
Received: from DB5PEPF00014B8D.eurprd02.prod.outlook.com
 (2603:10a6:10:230:cafe::f8) by DU2P251CA0003.outlook.office365.com
 (2603:10a6:10:230::13) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8880.32 via Frontend Transport; Wed,
 2 Jul 2025 16:05:24 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB5PEPF00014B8D.mail.protection.outlook.com (10.167.8.201) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8901.15
 via Frontend Transport; Wed, 2 Jul 2025 16:05:23 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=kR9wqnZ4tMuqnXEzyn9/Nl+FSsimlXtQ0yLgJR4s6OHoLQJPSXGlefIFrLL7fmGrvfY1j52hsW+IJ7U7VisCZoZ1lJIey0mpwxXtGAI5H4K/eLvb+DRC0sbCjhtXq28cT43pmsbtHEY2S0BiXOqHkItA1yHG7/NpUgMNxo2CNUZZ1YS3caqMbm5RizIK0fPMGM+Q81TKAWYonfZrm7pwiUGqBB2XGzyZAJzqlAb5+2q8fqKgFGF12LVSAmTPOS60110yXeff+MGMd+rTXi2uIRdMiVKAgIcT2AFXdXCYEC3p386pbOlkVcAK015qQCIrxvo7v+22xuO1t9zV+N5QRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Jd0LN4d76BfimfewCr+2SSbA5uUsl+ULDX/iasFx/50=;
 b=PXa+xpFyZuOe7GMwO++SFf/VGDHY0CFHCLBeG+16Gpgu3S4RWvisqYnaKCgsqy35qyD+RTJU6Y0FZc8Zvr0HSOkpXJWBuoTJRpigFvNZ3V0EOce1Xazr/3TsiKQEZNllUaRbC0S/NieFqgxcYWh4LueY2/P4IRgd7PRYt2o8OazR6yiqd49j42yVzWPQlf6VO0aWVTT5E1TjFkSKwEWxIO1LPvHUEt/LVLhlZke9gdi8GYetCZfVKWCmiH/C3O3og1vQ+R4fj3zQvhioFXXmUpnD1mQj9BHaQtTfOcNzSJ++gyMkvpkluDqwelyKjQK2dK8V1/ul9a/2jjrxF8dmNw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DU2PR08MB10015.eurprd08.prod.outlook.com
 (2603:10a6:10:49f::5) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8880.31; Wed, 2 Jul
 2025 16:04:51 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%5]) with mapi id 15.20.8880.027; Wed, 2 Jul 2025
 16:04:51 +0000
Date: Wed, 2 Jul 2025 17:04:48 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	bigeasy@linutronix.de, clrkwllms@kernel.org, rostedt@goodmis.org,
	byungchul@sk.com, max.byungchul.park@gmail.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	Yunseong Kim <ysk@kzalloc.com>
Subject: Re: [PATCH] kasan: don't call find_vm_area() in in_interrupt() for
 possible deadlock
Message-ID: <aGVYoEueYjoC1hQh@e129823.arm.com>
References: <20250701203545.216719-1-yeoreum.yun@arm.com>
 <4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4599f645-f79c-4cce-b686-494428bb9e2a@gmail.com>
X-ClientProxiedBy: LO6P265CA0017.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2ff::8) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DU2PR08MB10015:EE_|DB5PEPF00014B8D:EE_|AS8PR08MB8734:EE_
X-MS-Office365-Filtering-Correlation-Id: 6b2232ac-cbf8-418f-1c45-08ddb98240a9
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?mxJOFFoUpaiH0+gEhPOjVxZLD9N16j3Gyy5sbhS88NQfKUQBN2DZ81zbcWtv?=
 =?us-ascii?Q?e6U3OthCPByhRRvaJRhugwzQR+7COWrTGWgzA5vXWh6C+9cFwQJcKLNVZKgG?=
 =?us-ascii?Q?gcvwhO9KqtfgwR0vcq0FGn458Oxjj8X7j5bqrOj9tZlzXyE+3ZnMAn1KjMMS?=
 =?us-ascii?Q?lqikCvOclBwqZ8Q1qwDkhtQObsaTu/EqQvMsrRYdZAsA5Bx7isOdIb7/Sm2B?=
 =?us-ascii?Q?AUjYEjmMc6UvrvGbH8xlnZCVKrj8TjY8lIOsG4hHt23MrSe2ukZRq+g0RZFd?=
 =?us-ascii?Q?2cSXpfUbZfB7/MGj2TnO+KZs0EVwLjLeGjpwZtfBRVYBB0HNCpLDgxNt0uUI?=
 =?us-ascii?Q?yGugdg0k4Y1vp/3e5Nh4+YfNQrUKWas9Dh8ZyuXftuSwlv50tRS+8BkSEHSj?=
 =?us-ascii?Q?Fb326GgrBBbT5tsLl5xJrH0uz6zX7HUL7csCGfsq8dh1iJSOh4jfCLMpMJUM?=
 =?us-ascii?Q?n4uKQALldfO8u15rHSAWJ872hNsNSi2nwSCJzQXvRkmNwqsJ485uL3j6e+fc?=
 =?us-ascii?Q?LwUkttoaG8CxI9XnF9fws/MREYnAjUrMceYRsT2nEF4vG/lh8YrP7suIaUNC?=
 =?us-ascii?Q?kUwwXNel6PTaay3J1GJzFt4WE1RrMoztJPHX5XxjDpk1qOYGo9uMFsj2ienj?=
 =?us-ascii?Q?DCUlEKkJiBvNEtZ+9OlEJFsJZcVQ2umyrlhgJZb5yFfRluGLp/u/3iCziT3m?=
 =?us-ascii?Q?NWD9kjKtpNmpevSOrwdfM43D2ZP/tDSu+YjVmus+R0lD9VMiMqIzeKGA0B5t?=
 =?us-ascii?Q?vUn8PU1s5+iAEtK0ktQmAiQHMYCSnHC2thE6HmEfXIRLSMDUgJ8zSxnwiRvQ?=
 =?us-ascii?Q?zCwNiIGdSDgl8bhNAekWqemBmMRYkDFVlixljvHbZKVk0zQ9irSGl/hJhOHi?=
 =?us-ascii?Q?fm6iKXlkBLp7L17x51RUuYzI7+LRT0zPFgnUO0ial9bezmxYXzCiuvTCnU/F?=
 =?us-ascii?Q?AoMVz1IPT4JNm0gyVvS1s7c1M8tPpvmi/9H9ilz7ub7BXDU8R0T7IFKUyd6O?=
 =?us-ascii?Q?2E3JRV3IJIlJg+9LQeeMor1P2vc6ncaHW/Z6cTEyUGYIMV7TGbV56LqIoH+Y?=
 =?us-ascii?Q?j4VSFkLHj/QosyX0Cn7U8zrTUb+YPCKEE5c52nVHk30ZwjU2f4QQkgbbgZpR?=
 =?us-ascii?Q?Si+TtElxFiiv1/AUiN8zyKh5lr68i0UJGhM0HdjOc4ts++ZtxGAraPIctx69?=
 =?us-ascii?Q?vtZo64raML/suz7oJvFhn/L+iz9DOiylkgULSz7dlHN26/5KLwMNhf24C2ur?=
 =?us-ascii?Q?E5goU2CSV6VfjEz452kt9KlJ4Wt7maCZrajLN7FCo4H029wtYiqCk2hBYb6k?=
 =?us-ascii?Q?2reWJuRhCVWqcVCYlI1ihkLHHKPha6vZgtHgZ5lVWBKfrdIYwVTrNlhkbwQM?=
 =?us-ascii?Q?74Ce/q2llL7FKYqhiHhwqUnWmTTe8HHQHPle2ZxAQGQFmEqRUPi1UwAiSyho?=
 =?us-ascii?Q?5dc4QIvUL0U=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU2PR08MB10015
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB5PEPF00014B8D.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 975ee4ef-1a50-4fef-f05c-08ddb9822d14
X-Microsoft-Antispam: BCL:0;ARA:13230040|82310400026|36860700013|1800799024|14060799003|376014|7416014|35042699022;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?7/Dl+0HiEo+vPnpnLAWaudZnccKWR7p91c02fFU3Ujo8Dm6UDYn2lNa4KoqG?=
 =?us-ascii?Q?9offP250V4xlLsa0Cd5IPsC+/s7jNEQgBL97xv80JlMewCcxEPLGwuelQZ0d?=
 =?us-ascii?Q?OXCgGJ/GCl6NI0H17K4+FkJJ9NVgg/Yq5ZcRD8rPFOR32RvtKxoDOFw+cnOx?=
 =?us-ascii?Q?3JM5eiHdpxFXBjKTSaJL6kO0mRZWm18Fkax7z9fRLN0jHzQQGyrQyXoQFFGG?=
 =?us-ascii?Q?YGQmCcsBDABXGBaed8cr260+jA6T5f2hNIVZU3TYiwWNthX6KnlLRQ91N/my?=
 =?us-ascii?Q?YV7C0zdKxf9SHP7SvNLveO2pS193jZiXRvnx9m/D+eWmD4c54qesV/3MlPGu?=
 =?us-ascii?Q?0QeyJeZvKBZjCvh3SlWflrXnxhgw6od19UbevZ2rJKrvRRcP+t6Fib8uqacJ?=
 =?us-ascii?Q?kUCWJeHPFOqxQEUepq9TdwKDM80AFrRg31SkezH+yZOU32jNn8W+KrebpmIb?=
 =?us-ascii?Q?CNYwOdvCBFkIBhERBEtAqVWUKDVkWSCsNXWLgx5LsVrbkFk/gxENwHSRtcv8?=
 =?us-ascii?Q?QprAe4gy38OcAGVIb7QJdd8vc/JZ/lcCfW8P8VWtql1O+KtlHd651ZsZvT/7?=
 =?us-ascii?Q?xS26O6cg839DkXJl7+0tiPaL73Yar5RyahestDq6jvX10sN//Tq/diWjcCag?=
 =?us-ascii?Q?96u4OV1NhV1MYPvXNMM1Cf15MRSBWLz6MnL7W7bJcYjeYZZq8srgNeex7gLY?=
 =?us-ascii?Q?Ddl87vTIHuqGCcz7hVvG7PCvbokn/S1K18fLq6gHH4Ng20ZOUOgV9IU9198D?=
 =?us-ascii?Q?PN1YPeAEpDA+8IXLsvo3A+puWfpiokejA9e1iEh7oJbj/XdM98aZxyCziwUI?=
 =?us-ascii?Q?UOCdO8KZTSXqFrSg1+Y7XNhBCZyGPey8hFk+Tt/Qk1KPQz8pGRzEX851wJ4z?=
 =?us-ascii?Q?5WAOBp9VHN02tzA9fbVhx06WLv0wxvK9isCkHUOCbQc3RPUFK7AWz99CRPhK?=
 =?us-ascii?Q?slqziZmNxzMF9IWz8et//M4IN6/vpwbJMO5umq7EdnE5sMQVqGqXmHkGYrCM?=
 =?us-ascii?Q?HwDGUHFsTIWeN9tR8XFrOU7g5P5MtV13mCJFlBc9LmcqLpY+wmDaGE7iZFLJ?=
 =?us-ascii?Q?umfvrgnReUV2vAzrKoOFZVUavJqlvw05uliylk++xKOb20Dm6UM2ixL+Y3tZ?=
 =?us-ascii?Q?MmMumEv/YurD0MmGWC8t+yjhNPlgdfFVY2kiuV4B6og6DLFn1CJjRntAA/7B?=
 =?us-ascii?Q?zr7N8iy4kLY25XS31jrnnqf97Df8QpSsPaL6v5aMjCVKQuQY5vckvuaBLEQs?=
 =?us-ascii?Q?/0K4ZFGSndRVBgDcgeVs/g6dMLp0dyVA2IRTyNUVvHO70xI87DNaJ8R8WKa8?=
 =?us-ascii?Q?RUdNj/m8woseuLZBnuLdoGaKprZwOvGKzbdLsp30J+2fPtxHIMgx0qpfh6mL?=
 =?us-ascii?Q?taMn50za8N8rJBvz2M+KzsHvlaDN0K3P/y+7V1g8kW8uNiUEIK9kEZ1CR2SM?=
 =?us-ascii?Q?89FDNByzpyBgUDAhEK3H4hGPVmwf0otH3gTLR4CFWKjoJHYNkWF6Ig2StMty?=
 =?us-ascii?Q?LCIi0FKwMcTZW1USuvAwcWtSNDBHcD/Lams5?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(82310400026)(36860700013)(1800799024)(14060799003)(376014)(7416014)(35042699022);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Jul 2025 16:05:23.7228
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 6b2232ac-cbf8-418f-1c45-08ddb98240a9
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB5PEPF00014B8D.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB8734
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=lhWWobyM;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=lhWWobyM;       arc=pass (i=2
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

Hi Andrey,

>
> FYI some of email addresses in CC look corrupted, e.g. "kpm@linux-foundation.org", "nd@arm.com"

Sorry and Thanks to let me know :)

>
> > In below senario, kasan causes deadlock while reporting vm area informaion:
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
> ...
>
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
> in_interrupt() returns true if BH disabled, so this indeed should avoid the deadlock.
> However, it seems we have similar problem with 'spin_lock_irq[save](&some_lock)' case and
> in_interrupt() check doesn't fix it.
> And adding irqs_disabled() check wouldn't make sense because print_report() always
>  runs with irqs disabled.
> I see no obvious way to fix this rather than remove find_vm_area() call completely and just
> print less info.

Right. unless there is API -- find_vm_area() with spin_trylock(),
kasan_find_vm_area() should be removed.

But, I'm not sure adding the new API used only bv kasan is better then
just remove kasan_find_vm_area().

Do you have any idea for this?

Thanks.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGVYoEueYjoC1hQh%40e129823.arm.com.
