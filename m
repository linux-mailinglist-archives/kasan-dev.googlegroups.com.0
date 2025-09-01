Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBHHE2XCQMGQEP2IAQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F178B3DFDF
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 12:14:54 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e953a49de25sf5644571276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 03:14:54 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1756721693; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pt/xpQf5+o8+LSQNUfsPe3ifywYtjwNZ4xITw+ZObDlnEtoXjDLiJEiNtOuI11Ybhk
         oUC9IrW0hIpsC30Y2YGcr65pzMqfAAZhd1v9CJ/D27cRcajmMlVYtIX6PKEP8vVJnB00
         6Isj2asq3givXdf7P8v9kq3gGY6d0CrmQxhMJdencYlolLNJ0210ieC/v8ANhBc4OtTN
         PvVV+75VTBvCQlLYKmGxY0jiZgRMFjHPNz6WddVhSZDV/hYIlclRHX7l/dIliQ7e2toW
         1eT58cowXruaNyVXPrXzW70u9QaywCvCvwum3KUOPywX4g81XULfIjyyRA8OOR4VDKyV
         0Jyg==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=b6BSESNmC8dp+SzDuYu60KJ6gprOgtC/Rf6i0Xftggc=;
        fh=di+h86OMGDhvnrmNs7hSU2wRHqS5L2xLbcS9n6TCt1g=;
        b=j7vK/bzOc7Uns57XW9lEupazquU57JbBCzZzN/32kOutGqVhJ/xgI50FpGlLEPEy8/
         enylgVr4k1PqE0eUFRyWcZ3DpOEaazaU3DjFI2eqGJknhXDjyO315ff7nKCpMTDIax5X
         RQKuG4pWDl1W1SJUhoOfeg0hSfFgrDF6I4tTW4WYGSLfbPUZU0/eGGeXWIts2w/lDiQX
         BM/Lvm2QUzsNnOhxVivX64bpLDm0ji0aFAw1T2mGupC3/rpkrWPRgYB9MgaIf/rZLqiG
         A3GgG98CIrkjx0RAbzQUDKhDPnSNPCxU06Uaoh/m5HtkONGqXwCJdGHd0EMJSDo8Wd9W
         4/4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756721693; x=1757326493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b6BSESNmC8dp+SzDuYu60KJ6gprOgtC/Rf6i0Xftggc=;
        b=ZCSFGtv3UWGylZw1v/akLfkPCthRdoXV85ml9E2RinZ6UlcSGRYWhr4DUU0yrZUJ4A
         gKURi5G9VZc7VuLfiHGY/2HCCs1sAbt/IBF/at1xY4vUjtd4siqafUOrXHzG7w1yBHQs
         QUkQLPevEV3dzdM3BjoTO2y17eyeajAlY8YsiR0rm3VCUgPwF+mdFlQEkjYEcI4yKP1c
         BpjLDl3LmAdzeLzCbA6EAZKV3WFaDnHLQC2SJgoOVaNb2L3UsR8iREhMENRooeNyfl+K
         wfvV2TYQ8xXfymU1DUSGbSWbRE4kfKX6sporduKPawqBD5jsqX2srMP3+EF2GwVvLyhE
         bJXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756721693; x=1757326493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b6BSESNmC8dp+SzDuYu60KJ6gprOgtC/Rf6i0Xftggc=;
        b=K5LbSKVj9DmCWRFeaAKDKusGFjldUFlcxXzJyeFxOo84z6WjsqiKI3zAyGLjIWIVSI
         Zs3nH1nBrGDRumg+gKMxXIPMEaGMbdFHMSaNV6oX4Tcuzy/1QTqPiOSrw/BCBR6L2hzn
         kkIDSCKxqfziRrpAu0IPSSE9EkwUeoBrkLLg1rMWIQ2Q2c09dq/fDsZc2C8ka7+9FD6s
         Xr7vDtGzxFMC3QlPhqT2KaV0FqGFprX5jmR2+ePaFG2faU5DaUdt7un/q6+n3hMJiEY5
         fzIkwEyocZbas5HI9lQuOUKmdHwVQFxHfwcw6lJSsKtI5Qs4YHSpYhnYQsms7zeNCqPi
         pLuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXjqLuSXb5O5kfePmHP+EBIwdIq8Ujh8CThr3cMv1zLXN3hew04H0i8QNXG0DtLNwBw4/utYg==@lfdr.de
X-Gm-Message-State: AOJu0YwzYSLsNSjYkSmZxq5Bf7khBFpUtlMIih7PC9X1MnSX2O3MopnD
	LK3AQxIBIdw239GJxit/Mtr0l7i9iWVzd/OOpJsaNXkXrZ3VDZxddbIp
X-Google-Smtp-Source: AGHT+IENxqNc3uHOnCemrqXJMmUhtBx/RPuvJJSe9R0AxqtVFpG/R4TbWhNnJoCOhoEIAHWYEkndwA==
X-Received: by 2002:a05:6902:100e:b0:e98:211:c035 with SMTP id 3f1490d57ef6-e98a575d473mr6728437276.1.1756721692623;
        Mon, 01 Sep 2025 03:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZezaCZaD/rt1LHarNIZqBGUSy7wXd73ZGPP28eS61yldw==
Received: by 2002:a25:dc11:0:b0:e98:a130:6d3 with SMTP id 3f1490d57ef6-e98a130315als2014831276.1.-pod-prod-02-us;
 Mon, 01 Sep 2025 03:14:51 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCUR+qddeWPcIuKCGNUpOqMt2XxFTWJbPU6SZD3J9R2PA9aHwjejOsMCOutgWw4njriDcuN8ZBkM8vg=@googlegroups.com
X-Received: by 2002:a05:690c:7009:b0:71e:7803:cbd1 with SMTP id 00721157ae682-7227636b73amr83839117b3.15.1756721691575;
        Mon, 01 Sep 2025 03:14:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756721691; cv=pass;
        d=google.com; s=arc-20240605;
        b=JXc7u6pysktFqCSeLEp/MpU+py36I1oVHnUwEi5Z/cbf+fc802h+JJs0nbTXiBTFgO
         b/XCfo+GdlKwe4sSioKlBxfJGAE4IBwZ69EuJzG1ZNPbuCh3lqT7uG1jbFvnf3vFj1Cl
         3oFkfR1oK3ajoP/y9g+fuCM0gWvVOr03JOsCNkgDnunLOtbVZ19Oprg6GCapgB27AYd3
         bw1Jk5VTvxkfpfxVFcVb6gC1Xf/Vmfg7WLR3PD3z/MuIRkyZ86Q8htPXqOy/ms2QddCx
         4b3OShmCVOzia2eKWnrtWs1MmGYGmh76RA4IXpnBGkaf+aHO73LOjgPAQnfYrYkkuAXk
         KvLQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=EVA01w4bi/NkBxEwXo2razR+P4a1alwO7TaelDcNZa8=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=bkkiQkjMRUUX7bKl7mWtvIxYD8R9Djjw3h9xpk76eVauv3TXbSbq+hIFCqVhuj8MHx
         4OZk1Fxk9g43u6NOusAEFQzbXhrYv9ORfMw16QZ3tt4pNto8wPZTcclRxwfUYw6d7kKE
         xTWmx743ltW2POO+ZT0iPD0g5NBiVcHQiwvHYjaQsRYigu0ULQlw1JP8zmbY3WfO4rXr
         5IgaDi0QZb4qlJytlcC7S0GEATer5JPsC7q20V4QcfWZk3SQhU1NK0zY9NTFoxFxYVAN
         /I3NZzWs/DNMw0b8dSap4N7PZtyR/1cUGUAgpwD5Rhn44uZ2W8Zy1WgFWDYjdB3vtSFO
         fj5w==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AM0PR83CU005.outbound.protection.outlook.com (mail-westeuropeazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c201::1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7227d8cbd71si2028277b3.3.2025.09.01.03.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 03:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::1 as permitted sender) client-ip=2a01:111:f403:c201::1;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=SLSrTzLjBCn6HxVvHPspwv6AG2SQ+5kQn0t6iVgP6Jmmrf9+7SdMV/j53bLzKl42tYLsuZz2j4CrLUNy+OnAuL8hLds4NWKOGKH8PMZCKCJHyzyTSWI319yM5SiAMCHBm4NffpLekJ/Q8MAvqAdTWmTzvK7v2YTMi0nKHWBLWJ00EUOiV9db0hJ4lD1SZF/DSFVF2cXxo9LkDpkTTGPn9/haWRDwBhLRRYqpofpfnrqrrA8oTY1aju/gFDgw5ep8kaXQCokOl7mKEELQeH1JRXAlPOXSKlMRhzMgzpt3C2tKNoS9m2bE0w7PAeCAx0buPq+uQoRbtFTLTbd9gMIENA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=EVA01w4bi/NkBxEwXo2razR+P4a1alwO7TaelDcNZa8=;
 b=mFRFMsHN1ndXITdlteleoiOEZfEVb/G2NHVykcsWCHvLYT/3/6UaNjNBebQHi+UcbuiJZJcGPbaU5sGb/HX3FEoln51h4zkO4L1E/umRoq3WwqInYNxttNmL2HfbMoJpNvowWEhZDvWqf8e1KGHr5f9w//yoAqBhVnW82Atni0gtpsOiNZaHAtIE8TApDs9fCs3POHroSaPugdGNcCRt6aotroeXbDoNE+kxVWYwh6qjpQjnjuMI0yQOAo66YxUGuogL5HEX3PWHMFkJbMFoWjetmMEYwq+AdEuu3oQBllgUjB3t2bC8+bku63CeizkYTNAEaCmZVhGF7gy+nKDUUw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from CWLP265CA0392.GBRP265.PROD.OUTLOOK.COM (2603:10a6:400:1d6::17)
 by AS2PR08MB8877.eurprd08.prod.outlook.com (2603:10a6:20b:5e6::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.15; Mon, 1 Sep
 2025 10:14:46 +0000
Received: from AM4PEPF00027A61.eurprd04.prod.outlook.com
 (2603:10a6:400:1d6:cafe::23) by CWLP265CA0392.outlook.office365.com
 (2603:10a6:400:1d6::17) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9073.26 via Frontend Transport; Mon,
 1 Sep 2025 10:14:46 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00027A61.mail.protection.outlook.com (10.167.16.70) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9094.14
 via Frontend Transport; Mon, 1 Sep 2025 10:14:46 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=M1Hm1jkhM4KhYDz+H6HRrpl1Vm7qWFiUnS/FR54TtTXHKA7AXqtnFXu2M+qgq79EBrttfRYeL6K84ASdFl09lsuqlNCESn8CFcfb+iAMVFQ5/JeGuhsB9xg/Ofa5hO3DwjruVwUVZQlyV6oNjQbnByUKCSt7bd41xK5B39PWN+uHJV2/cl8foaw/EEF4r/UHH3UOU1WAFCcgFe2IYBPxkYv9DXmSs/iKjQqnnkiKG0+5E8/jY/SmOablIFbEVz6jMKnFXuh6hUEQZkYuHYA/4zyqmyIVr4slvuA2Pt/Ue+kwubvUq0tGvyJQ8HGZ+H+xDa3unV1GmSkJ87a+MKoM8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=EVA01w4bi/NkBxEwXo2razR+P4a1alwO7TaelDcNZa8=;
 b=fKeF6XbzNPLGMIYB0N4ARDbfDW5s1zE0T6hEBEv8X1PB16ot6yU+BTQNMLnmMbCejaTcnRLy91lOftIKNTJ4AGLg3prFMLxaEM1Q035OSO/nYGnE6QvkYWQVSQBL1W5CWGKe5kyvRTGUyqAfaK9TeClFrMUbH2X5dm/tmLFgFA5hoMfAnFFapCnZkCOLg64uUrby6KwD4FZCTDbVUgNlBzNFhhDCs0O694jiLgqOvRTHv9Tg+wr6waCKftF7zblfqtyZH8itb4TkzU9sjsGze1tSjs8lgWZnk2UOId5zLEqD+cDufMH5YyrtWXJdMGIU9wYn+FUfawYq6EsF2nnyZQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AM0PR08MB5298.eurprd08.prod.outlook.com
 (2603:10a6:208:188::20) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Mon, 1 Sep
 2025 10:14:12 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9073.021; Mon, 1 Sep 2025
 10:14:12 +0000
Date: Mon, 1 Sep 2025 11:14:08 +0100
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
Subject: Re: [PATCH v5 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aLVx8Pxq7eZgu/8A@e129823.arm.com>
References: <20250820071243.1567338-1-yeoreum.yun@arm.com>
 <20250820071243.1567338-2-yeoreum.yun@arm.com>
 <CA+fCnZfv6G19P=bWqEUpbA36E9zaHBqDBZyDYV5YnMuAX1zGug@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfv6G19P=bWqEUpbA36E9zaHBqDBZyDYV5YnMuAX1zGug@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0650.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:296::20) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AM0PR08MB5298:EE_|AM4PEPF00027A61:EE_|AS2PR08MB8877:EE_
X-MS-Office365-Filtering-Correlation-Id: 0d8f1765-4bb7-4161-3bde-08dde9406087
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|7416014|376014|366016|7053199007;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?lZf0P+jk8MTKNMTGMdsYUdXrqM62xfWK9Oyhjo/boqha1slEW8Z7LKlp+1M/?=
 =?us-ascii?Q?1NxTmSPNo3nWXJ3RJQvkKR6xjGGeg4xBuv3j97xlfuhAzPWjwsp8Ec6+Xl54?=
 =?us-ascii?Q?9TST5IFHfCCDaUwggvD2zh8bU4iRbexmQ2yB+ityrXyS38kzN3T67f9ydmRz?=
 =?us-ascii?Q?BVX23nnfKBJHrSzo/vieRZmaa415bdgrzJ8BqH9cJPNERhKruNt5cXOvzOKq?=
 =?us-ascii?Q?I9KlqgQHSg8yZnv4EKIyxJBzEiuMYYedY/mAzr1TlVFjWLCVjuuiZY88tY6K?=
 =?us-ascii?Q?yhjCr9o7xqjzsrv460LYBH+Kq2wML+LvocKvx2gw9Zk9bIXLmlPMaoJ6hy/u?=
 =?us-ascii?Q?8OwiUoaO0QTWyGHUcei8TJiZhbMJGdOLgmpy53u9X7cBWbfZ/IzkJQ3X2x2p?=
 =?us-ascii?Q?1HqDOYcHkoFdpzzxWvbhZ2bhO6hrCt/E+tapI5SD+6En/STgxZRHDic7rkbW?=
 =?us-ascii?Q?AhWER888CeALYarfIb6zo7QhipWvdlbAnI584jnTenzAbt+TlVaddswY2921?=
 =?us-ascii?Q?ZlqTeLqBLs0oDQDxWZsukWXzcRFKrkMnBKMq1cjKwj4yBAVkWH6xtBWvngMz?=
 =?us-ascii?Q?AqlELKZ5A8iPFS5Kb4DCGchU765xJeftHOh4px8oe0n51N104oSN5oODFO9C?=
 =?us-ascii?Q?ECe6giWcCh5UUEK2nuoLaqdqZinKsnWtKT0OX2qtq/7V+98OoPz0WV/9FEE2?=
 =?us-ascii?Q?H5hExYHEllgcDUEKEB7/qSxxngWGm9xzpiTGkpuae3UcALeByr0oiAMSz9c1?=
 =?us-ascii?Q?l7ERUmwW+4oZoxYb2nX33u3crTEbEVeIGhYXb5QcN/KcQWuOi6wBERbDjmR6?=
 =?us-ascii?Q?RwGK26pSgahIPNdNFksXw0O9VFYatsQ+C/TZMSBykfZLqqngcc/q4qMxw662?=
 =?us-ascii?Q?iOtx9YzY42tEUKgVxDtL7o6h20mV9FztBGdbiHRaKPrfydLCR25jQVj4t2jY?=
 =?us-ascii?Q?smTVnn21wyk/tNs+SFKAJlC5rYMfOV7nQa4udjYCnLHpCs6Zfbsv2fq+VZe6?=
 =?us-ascii?Q?tspOMys8nNLd3lbGxVWgSbPXSNUZeeBUxNg6c/C7Dncpyu++xQ78bPr/uc1L?=
 =?us-ascii?Q?OHFJLcjhdsU9T0DfKql/BEhmyW6oWq1NZtlTuKpTIpnY6klifY2AzgP0/Xb7?=
 =?us-ascii?Q?jHS/TvEPAwbe7yhk2Leq5Kd4spcBb9k7VvjLRIbW1tOgCyt33xc0/jHuB6kd?=
 =?us-ascii?Q?UKFNsplYDT8FDgs0DuBMjSd7wvzJBztbZtAEMqUF1Xd/vEWqcs1J4XW2nVHA?=
 =?us-ascii?Q?GlqeZVAinIJn3xrr2A7LIcIS6bfCYdFhpsnyJj3egLsKua9DHUHkklFZVQRD?=
 =?us-ascii?Q?aBsIMqfKeMKxSqdbjZ3l4uR9K6763LavigiS8ojqSOe6rcZNJAK4hG36wrp+?=
 =?us-ascii?Q?GCfkom4UzBNhf7iPuoKdzEoVUedBC3qZsicJq1mqCxObELLwrA=3D=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM0PR08MB5298
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00027A61.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 036e298e-b700-43dd-5fa8-08dde9404c46
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|82310400026|376014|14060799003|7416014|36860700013|35042699022|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?TEqRFksL+no/8lMry7yvt+tiym80o3ioPlqNPMe83m/JIhbRoHdIU4RncxJK?=
 =?us-ascii?Q?2vJR+EJuKvNdM0CA7HwBQOianofK5K0GWb6i8L9/MZ4sReC2jNg4ogV/hjLH?=
 =?us-ascii?Q?F6E740N0dZ9qxAjFrWSmy7m9Pgv4qOO8PKNEjB35R/OcsKQdxYNeA83PHgXl?=
 =?us-ascii?Q?6aIJS/+8w+Bv/LZH1Ei+UFEOMmECm4nFVIjRIjAslIZFdJwdrukMWe+B+Qo7?=
 =?us-ascii?Q?+ZzXQ4TscZizKzW9k8Q0KybiFa1jTodJLZt6jKXQNzp0Bw47TFvTVQupA4kb?=
 =?us-ascii?Q?z5tnjUYqpVvrgURAobsLSqw6V58GB4uH3b9Czoyny0PH9Zbispe+/zT02+j4?=
 =?us-ascii?Q?fBRvAc3JKfHwt8US1qasGTEcb76jXFO9WzgqTWR9qGQH7OMuRQvUJzhxvhXV?=
 =?us-ascii?Q?XsTE4aZx68mJyVFnnGH+xYx4w/gEQubl+U/NAJWFUk0Mn4h7Gel+T1IIuESo?=
 =?us-ascii?Q?cmVXmsFmrVFW1WU26vVT90X/OJMhZjC0cmHYpPnKaHLAA8fmTv4Ji0I32Afn?=
 =?us-ascii?Q?ygiSAtQ9Uhho6e1ZUUKEgAdwnM71Ea7CfsbtO8ucTHdnnOZ8Fl53lzTfzcQB?=
 =?us-ascii?Q?Z5gXCT5/V0TFkScb3d73mmKHbTIs7uqyoLsJp2k7N6UZ+3oi+/AHs5GCm6L9?=
 =?us-ascii?Q?zYIBXstE/eZL56/49YI3Y0inLK2YcVa6Rl8VanH21G0VTyPxp5pjg2jJEFMZ?=
 =?us-ascii?Q?wPcwsrLISERdd6dQ+4B7J8Wsq4FQvGKinUZj7UHpEUdejb9kQMZs8mZFtfs6?=
 =?us-ascii?Q?YTrA8RSZjRlgafmzjiokY1Khc9ZEPBbaV4nuLErj/gejmHB8w+nMLPo7Kev7?=
 =?us-ascii?Q?At3j20J3KxbZmm8PFBH78mRXCJ5cMlT7HcOiqnHvmGVTN6Wd373W1DUlXFl/?=
 =?us-ascii?Q?1B+Wr4XRac9qzBUVBEI/eO+0HSx0CNeLVd90bbU2Jc6yarhZkuH9oqzA8XoJ?=
 =?us-ascii?Q?L89vGvh82ofcbb2n79pt/onxK8pROId7Tgv8h3SnPDNIXvNYDDS1JCyDpoH6?=
 =?us-ascii?Q?V2k3o4IH1seQOefwTSiJN2ruNxrv7OESGd3bvG6oneyLcuhFfW+dxZtGVF1e?=
 =?us-ascii?Q?5aQWsX8VuimhDFzSJEcmu3OwFoQbaUe4D3rZWtyU7hG1KpQpkKIpkdOtDZsK?=
 =?us-ascii?Q?pBRkKsEsNqUCNHfxnxdjHy91jcqiAMXL8kdlCtbLYQqkEkJP8BPwLD7psGsc?=
 =?us-ascii?Q?T/9qpAqI425rLUWLIRtP97yUpYK9j169PDyv+V6s+PEDughoX7S8L+OI9tIu?=
 =?us-ascii?Q?K9+lxLnBlOv83qDXZuvgjf0zRViG8B0oA675HwNg2JgdFiKyhTGuco+MTbOe?=
 =?us-ascii?Q?LBs9fbVLyTEcn4tGwxtIceanNLp71WzKbDa+OetFnXxvJzv2MpfPnZNODqpB?=
 =?us-ascii?Q?f0NAAFswX0akVeXOHOfB2WeriMLZ69RxR5CSbgBnFeB8JSHxc5EX7SBzHNyE?=
 =?us-ascii?Q?JmDwmqsCcKUQtOHza5E7rRjHsXUYBXgFSJicefKrQuEjNjTIcVZ8Z5Ph67bd?=
 =?us-ascii?Q?j6Ki2pmdtkdS75Tf8bp+KQdbK1UsvASUzIA3?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(1800799024)(82310400026)(376014)(14060799003)(7416014)(36860700013)(35042699022)(7053199007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2025 10:14:46.2284
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 0d8f1765-4bb7-4161-3bde-08dde9406087
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00027A61.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS2PR08MB8877
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="X+cx/0Oi";       arc=pass (i=2
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

Hi Andery,

[...]

> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index 0a1418ab72fd..fe1a1e152275 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its features:
> >    Asymmetric mode: a bad access is detected synchronously on reads and
> >    asynchronously on writes.
> >
> > +- ``kasan.write_only=off`` or ``kasan.write_only=on`` controls whether KASAN
> > +  checks the write (store) accesses only or all accesses (default: ``off``)
>
> Nit: a dot missing at the end of the sentence.

Thanks! I'll add it.

[...]

> >  #ifdef CONFIG_KASAN_HW_TAGS
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9a6927394b54..334e9e84983e 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
> >         KASAN_ARG_VMALLOC_ON,
> >  };
> >
> > +enum kasan_arg_write_only {
> > +       KASAN_ARG_WRITE_ONLY_DEFAULT,
> > +       KASAN_ARG_WRITE_ONLY_OFF,
> > +       KASAN_ARG_WRITE_ONLY_ON,
> > +};
> > +
> >  static enum kasan_arg kasan_arg __ro_after_init;
> >  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> >  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> > +static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
> >
> >  /*
> >   * Whether KASAN is enabled at all.
> > @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
> >  #endif
> >  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
> >
> > +/* Whether to check write access only. */
>
> Nit: access => accesses

Thanks. I'll change it.

[...]

> For the KASAN parts:
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Thank you!

Thanks :D

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLVx8Pxq7eZgu/8A%40e129823.arm.com.
