Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBIER7XCAMGQEXJWRWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 73AACB28257
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 16:48:03 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-76e2ea9f05esf1578747b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 07:48:03 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755269281; cv=pass;
        d=google.com; s=arc-20240605;
        b=G3LtOo1YbMpw0oy9cwXLhXc9q73WqyBPVzgfngjuLflugSb0Ac2ZG+rxjXwUQyyW0A
         3OKxXq6SBImQ+QkwoOfskBfTOeYMZI3xCt0CuPOvo6Z5TGqKCuVo/rRv7BQSnb7zmtCq
         Oagth+jgNABRg6yZrdLJO9JMFTSG5MmWB+OlUtSk98N2Yj5ClAwCeqm3IgwO3IF4/zoB
         OE6Q7jknkKjRQNM8O0cpN1RBvOtqUeAV6hNim/FD0G8YW08XY1JPtt1dMeMKVtEYKwC8
         E8b4RU9MH8FBqJUU1alJxw85Z4tvuhvM46pwUd9X2Ln3sgrR9MhB/8DE7ikfda3km/ZW
         8Mjw==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=+Uluu73fRFnn42W5AO61LhJOYqivdYJggKCQOQZugu8=;
        fh=PlDa2PDLFXYqNl5lYM83G3Te+wVcWmes9rZwXcRlMtQ=;
        b=JIwhW9GDwkWkgiX8hJTFEdLS0JHAkpi7Ea4ilm6vKCG7W20ONVZM44Ats33tTJHkiY
         yhECDdrC3iN87p8siO9mmN0fUjKWcVjeClrtyMMwWM4GJVm5Gx/zxHRbqhsSXZZgYXPb
         Sg+/95oNbv61vAmpbxfCK0/WSQ6kyl4lWUFcm1plhfpGa8C4lKQnzYT0WoH6TPIZsODM
         TNSazZJLP9kfpZlsRuSuAjGtaZFoBzwMiIxnzvaz+pSBYuPZhvWNtwQ5qCoISnDdhFmn
         W7w8oxznLGaVtbFQT5uXSFRJXtxwnLJlQ6eTAiX2zI2WaZLbd18R374H1WXTR7Vtq49g
         9zNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=kSN06oMF;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=kSN06oMF;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755269281; x=1755874081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Uluu73fRFnn42W5AO61LhJOYqivdYJggKCQOQZugu8=;
        b=rLo+RTAWq6Z9BCwKpnLG3EW0Mb/lBkh8SK58ipB7zyeoH+yYseFiE1b2ViXNqsggQ1
         qOP7Mz4HQ2dQAZtugu44Z95+v3Eo0ZQ9VnxPHOJUi4NtGnTriwJ07LqdNTClz9jdO5v/
         ozTvGcvjFofshgCN6QYSOGBkdQP4qpSdjBoKPizGPhDUoKwVzppZne3JnpkuVVoXbcCS
         l+FAReo/tYaVzGV44LJPFViCutzPZDm0Cw48zIdGKD7qjSziK6dLRrR0cQxNCO7/Zrjo
         +eUzn3mIIO5qNkwOvcMUrueGF7TBpwYCrNg+B8BCjiXf6MgtEb6wGRU2XsffK5ksLaEF
         hHDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755269281; x=1755874081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Uluu73fRFnn42W5AO61LhJOYqivdYJggKCQOQZugu8=;
        b=hmzWM+1pwvOwneErNflXtD4Q7t76q8k/Gr129PX0+UdvmuMvGSMY5SiU1V+eI/BvGh
         EU4GWdQcMDHvS7B5woFXbx8V5hkGgYiJWiClnGjNh/K66N9MPmx0/mhePm5+cGZNz2oL
         4K1r0Oev0M5c3yMmxF0g3Fp+O++iXq2Fk6mIVVaemYuFQ/UbXUGRWafL17zVUwwc7UR6
         Uxp32HzRQywew6oREfth3MtUeT+gS6T/TOkrSd1CB2G3ZgwjL0xlrFnwyIf/fUjYpMTR
         i2eXmEKxTZyhMgaQFAomMly7yQ2zrHCkKWo1o3PFpRgvP5yOEkWKH2fsK25+j3yumauD
         s6hg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCV3foIWTqTKI2aIqsst6ZTcP4dJwKnJJs9Gv4HaYqIWWXdkvsexU0et3MX62xbmznl2lpolzA==@lfdr.de
X-Gm-Message-State: AOJu0YxLs1Ei82ZS2wdTzm2qj2HDRH4z/VzSWnwbzHVakkLiCJ9o597S
	wZ8VlmlnG59hRWj0/9eLYMPioAC2D9dEzTuI7O94Lih41puyiqTJIgYA
X-Google-Smtp-Source: AGHT+IGXBDo6LcCsWx0jagORzrsKyFVxal8ityrfcd1bgYr6sSwo5c8mFY8pMoCICLBoYBgkwf6c1g==
X-Received: by 2002:a05:6a00:2d12:b0:76b:d363:4a3f with SMTP id d2e1a72fcca58-76e446cd082mr3770966b3a.3.1755269280991;
        Fri, 15 Aug 2025 07:48:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfg2HTGPw+zUhG5gxUyveGCijR9WBYpZyovQMnTMz39mg==
Received: by 2002:a05:6a00:3490:b0:736:b063:5041 with SMTP id
 d2e1a72fcca58-76e2eac8818ls2166595b3a.2.-pod-prod-07-us; Fri, 15 Aug 2025
 07:48:00 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWiBh6FRZxsAmOMA9goutz+i5L4qK1C2N4MPzIg8L+3/oNt4CB9DqiTv15yUTTNR1CtZkbF0uAvWQE=@googlegroups.com
X-Received: by 2002:a05:6a20:9147:b0:240:af8:1784 with SMTP id adf61e73a8af0-240d2d8171dmr3737470637.1.1755269279707;
        Fri, 15 Aug 2025 07:47:59 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755269279; cv=pass;
        d=google.com; s=arc-20240605;
        b=eW8Mh/11wr7O/cl7Fu/KQB0aC0ebOWA7zxKFTvJ5272vxDVdMHAHGyCfIhzlmFTOyZ
         sFCc9Ntgds/jMInp/KSuXuOB5oevSZywKq+VVXypwjQDPdCq2ht8oiy0dCVuNofI1Mmx
         ZQPQx7rTKPf01z+SjQywnHP9UG5AqyvFRk6tJzyDd79vsKmTCOB841Il0ArZsMeM8BP7
         MyfoDPQf4ULmWxX9Mw3iUKv1RP8cpxYR5CFBwTwPQc8UKxrV0tLG/e+DSaExpv1WQI4f
         XjGtNGndUPlFxb0nNt7EHbaDk9jqWZpyJAv9QDQRVvGLpika5PsjjVQCUVsrcCZQX1pX
         Ji1g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=3VF1i8XF2IsUYPCj3uTJMsr5kBgCn0MixVn+SU9EkX8=;
        fh=sy1/T+hZ0mz5g5/9lgWaTur7TgGZ2Tl7HUiVtGJX82k=;
        b=i44vgF0xGC2bv8zJN3SlqfBswpC7+BbR2kVdnwyb0YKCQMeziqgl4nSHQXVmFCSChH
         YVIp4y0CVXBPgdpZAAojOHctxidJfu0g0LHN4lo1qbOjFft/hYnXRTW9yuMzx+G/4bQy
         3/j4/iBSEu3vEujxhNkzeN85etlcOxUPyMxVnT0AOPCq5URqMpZQOjOgulyl1q7+Dxso
         LFryON2BzKv17Mda4ELlOXiUPlkjcgUwm/hqvfpvs2jp2iUACZoUCvn1MUPAttJEF/BL
         LMKCwrnV5YlHj29TOdshsjWoNwGm6ti/V7i8ka8QYItA+GiTZUSGdfAiHm6scU4eVZTy
         3Vvw==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=kSN06oMF;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=kSN06oMF;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from GVXPR05CU001.outbound.protection.outlook.com (mail-swedencentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c202::7])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b472d7b1789si52973a12.5.2025.08.15.07.47.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 07:47:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) client-ip=2a01:111:f403:c202::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=WfZrTUGfTPbYgzslChiunqwW7T0cdcWBdYNUx+lAIWjNl1LMOoogAqUJu/JpV9802cPx/1f9EXhncBIGcrMpyzDrKMVmmqUZ3Mw5t4ybpzxf+xWAj47LHDy0LPYbYIwyXFSNDHy40m3rvGu+92AehMt4RRg/KwWNY2ii0JTYTqKa/1ArH0YBXN1KVNQgiBIfy5Bm3Zg1x/uM1SkOXMaTfIMWDr4VQ4HqvsdbNyeZYWCQSp+1DMSahAe6m9O4FscWovQ3W3R2WllRWxTLFxB1NSFSpXQHqEA06w2JL43KYNecwN653NVEPSdbK0ethpvAbEuv1mtcfxGTKS8auUPXkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3VF1i8XF2IsUYPCj3uTJMsr5kBgCn0MixVn+SU9EkX8=;
 b=DZ4YAeJY//U4UUEvCNMEIi7uEngrgIQ1wx8raVhCW3rS+hMesCEpiRXo8gEs+HB99N8e1zSMMWIFrER08nVSU9Wz8HLXPXc+z3GUS1G1RC5uEUjOywNZYFU9YEqhoLauxy2zsqjkYoKhsz6l+CWMLNmGRH9SC/+3P+sRkPTtDYgV6Sy9IcR0Z0YaZOcDyCITr1atC64LX19t8Obn7mjTy4ZaPmugNFB9+U6Dfrt6Wn2oytJLCY1YILMUfZJoN7BNc4P/maeeRyaB6Wubhfgg61OYX2YaFqBCW008p8aMkY79QotfMICe1NNR+ANYQmgEhjrd/JqYXxHKamyZR5gmhg==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from PR3P189CA0007.EURP189.PROD.OUTLOOK.COM (2603:10a6:102:52::12)
 by DU0PR08MB9749.eurprd08.prod.outlook.com (2603:10a6:10:447::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Fri, 15 Aug
 2025 14:47:55 +0000
Received: from AM4PEPF00025F95.EURPRD83.prod.outlook.com
 (2603:10a6:102:52:cafe::2) by PR3P189CA0007.outlook.office365.com
 (2603:10a6:102:52::12) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.18 via Frontend Transport; Fri,
 15 Aug 2025 14:47:55 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00025F95.mail.protection.outlook.com (10.167.16.4) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9052.0 via
 Frontend Transport; Fri, 15 Aug 2025 14:47:53 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ykmMdFV0g5DXc/yRPs4oyHBd02X8hlTqphguMeEOkpvu9D1wdyaV7ecHYtHPmVYp4e71YNimL5e2uOIT3IN3+kdjOXf9M4wAgbJ28s1BueUxumtFtw6I0HCRDqWC8lB13H/QNhMZ1MegXLxM0mxavRwBLnXG1ot5uD0XcH2KzvihsVEXBGySXe5r2kKeiMEA0DjtXJNDOWTDlgwnHARoc27ShPMIcQYEZXFb/LiYxzvgI9IZ5G8LZMwDmupqluDX4YN6QMT+vxtWj/kPMaHPJJu7H9e0kAvk2HHFMLVj52MMMLYj6/ycRC06DM2ZvvYWynHltFTkzYBBvndjp7Rz2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3VF1i8XF2IsUYPCj3uTJMsr5kBgCn0MixVn+SU9EkX8=;
 b=vDpV4tZqSZest80m1KqQZQI60UxZm4aLkCclXHwXhzh4n+2CViYTOjU32+acEZ38Ud5fWskwtOx506rjExmWcsnBXRbKh1dnREZouWewE8YM6xhXYWVQgSwXS6Euuv0lOSodniwLTVuiXUYzZnUUC0s8vxX+1lsawpvUFsZTb1p9uolYqw6xMlHgXHtUlveqIdNX1CkGUGeaYd24LABRDW/atXzGqL7wd0j7jXSlIeWnnOeXVI4SwGW2Y+Nq9xgTvofehu6s9QDWWTWSKi0qtwk/82Wx1CoQAiqw783BHckekJ9DIEz6ZJvI91eMgFANtnx+Z1cePwddIro0Nld35A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DB9PR08MB6731.eurprd08.prod.outlook.com
 (2603:10a6:10:2a4::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Fri, 15 Aug
 2025 14:47:21 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.014; Fri, 15 Aug 2025
 14:47:21 +0000
Date: Fri, 15 Aug 2025 15:47:17 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
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
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ9IdVsSxppYh2QC@e129823.arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <aJ8WTyRJVznC9v4K@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJ8WTyRJVznC9v4K@arm.com>
X-ClientProxiedBy: LO2P265CA0266.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a1::14) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DB9PR08MB6731:EE_|AM4PEPF00025F95:EE_|DU0PR08MB9749:EE_
X-MS-Office365-Filtering-Correlation-Id: 05decebe-c7a2-40ec-ebda-08dddc0ab715
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?w6lz+PBEALq7JAfJwRNm7ZIdmODh42CAA0QDW5zhawuIZZzPpuogM/qByXGz?=
 =?us-ascii?Q?zLlvvYuOuAyAJKEo9Z1/V5zXM6WVrypmV7Y0FdCqE4VabbrQnMSdQnYTnUGN?=
 =?us-ascii?Q?zU6B3TfvKZ3Ugkzy7KUhjRq9swmXcaV5RMLLdG8y83jiwyiWHhChhvc1mb2m?=
 =?us-ascii?Q?Vxr9kwGRz9+SvDg1mw6ObIKjWu5hBT1BE3Kr8k/+oypWwqZ0aM9oFTVshTFG?=
 =?us-ascii?Q?RhdTKygrU9vCc5g/IxLhzgMd/kxn3i22LyM+8b17/xNP+0oOlJZBwIz+p7P5?=
 =?us-ascii?Q?/SGbDtdQxkx8da2Pix5eyFeKgnOPT8bPeTmAEeINKsB3z7zMCatE4IAL7RkY?=
 =?us-ascii?Q?CFxNf94oVEUXeaAw3vdxk7MCuuFGDpxceLGd4t96Ksyae8v56qcEDF8gdCdk?=
 =?us-ascii?Q?4KRf/qSwVrvtqrf0WGNnr+tzCC4ZtpedBwRwNaGbRFqIaDarBzmQt4e9GA07?=
 =?us-ascii?Q?HBQ/8EVuXHAq+qZnqWahCBfnIR8Gz5sNR2C2A1QY/GLocdETnP8y+qX0jX3P?=
 =?us-ascii?Q?flOGaouCWRKhQH3KkU4Yc8/LshVzEowI6T4rL7fwDTSxb+Y1rMFzlNSg/Gho?=
 =?us-ascii?Q?0cvWXsfmJvpKfdcu37jcw686bmbB/RDepQCugeX/6bmf+C0qINiVNWRVNnpa?=
 =?us-ascii?Q?c/2l7GGJj9U5H43c2bzJ2ZEuwXopQkxOwfrpg9Y464bvypi3CIQ0TO9ANQhQ?=
 =?us-ascii?Q?taTaNfuwE5RYQfEfY9lc0L5etRKX8MSZ1m3uNxjH36HYGNb404hX4eerS3UO?=
 =?us-ascii?Q?bN1bF2oc3ncTBKcQV60rGJlSCTr/k+l9LMZ9EhRx06WPdeZt0UWnaIJ5zy8J?=
 =?us-ascii?Q?3A99GGjzifVD6v60EBf7CheCe+kb6VVazk7okk0SKn61Ac98s8tREv6PoDWk?=
 =?us-ascii?Q?cJC0NwyhYUkh7Svz/9k/YRubRtjiu6rbgRY+F7biJRYR6G574eThTq2m6OrM?=
 =?us-ascii?Q?ZxzkHza25Rhug76woU7ruXVn/Qeuvrsk4KsqLfPpBtpwOhbkvRvs5G4V4X3/?=
 =?us-ascii?Q?Gc77y0tI8gGcaiOWMHc0W/d4A0LlR+CTFu33Ju3eAc+oqDgmTXrdvi1KfPzy?=
 =?us-ascii?Q?l6vFY8F2V7WfN2f07LprVNmNhet8ueS0VYTQgQ3hUfK2gDRNFbdFeDpI1eOx?=
 =?us-ascii?Q?131eoIX3q+XXByelJnGQQcWBFkhAOgu22pQKanexVom9cKvsOBfEsPFlUPpj?=
 =?us-ascii?Q?3ZlzTnOaeyfCiB1l1IR8DMaVGK9asY17Mjsz2m6oW3lgThKjKmZmTIQMzSS1?=
 =?us-ascii?Q?gPGwVxLp6r84b6d3bwlW0VUn0WZd1Aq00+xycbVFoXHJHVTdhu8vmyqZasl+?=
 =?us-ascii?Q?ml/QvpZ6zqMV0EJK0UYIqe2MLJ/k4g0oCxTegqoqz8VTGjp781O/+OsW2JU4?=
 =?us-ascii?Q?IY/okTGMNtsamYmLBGQznaGWhEZn+f2IORdSoYhnt9gHBT8/DVETBvEJOBI+?=
 =?us-ascii?Q?NHqlju/diZ8=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9PR08MB6731
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00025F95.EURPRD83.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: ce15e0bb-112c-44c4-cf35-08dddc0aa38e
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|82310400026|36860700013|14060799003|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?pAYxwjr9MJ49+dVltyvWrKjAzdN0bDjOMQ6j5vUwjvad984dUokaRLah+omQ?=
 =?us-ascii?Q?MX2sxuTSSmnEx75Tsgjblk+jdrCs6pXxoNPQFmsoqIRM9IqWByVlJvrzzZw3?=
 =?us-ascii?Q?mkXtjgW7jp7XQFIiazbalLszKwSgWnXvzwQRbPuwqGWD3lx8lXb6NohK22Zr?=
 =?us-ascii?Q?hGtXIGrY4axl9vxd317x1hKQZsA2cM+V9QA+dvssKnTXKGZ98jNi1zjoDmn/?=
 =?us-ascii?Q?FYqx7mWeP7SNNqIrm1FLRg7Gg5LgzQ2m3Y0w7QlikZbZldv1CPFL5v9vOrsb?=
 =?us-ascii?Q?noQ9w1yaL60Ntmyp4cSj5fBJBUz4IFN2cz2e1acwK5h4tKKyPIXrlnawzGS/?=
 =?us-ascii?Q?mJOvLOpT/xOAuoFMV3Hj92TBuEh+obaRntRCgSc6rsRIp1ztH4ks4cb6XrCe?=
 =?us-ascii?Q?tcPTK5n9z7oNml0YkUqK0nmHl7d/l/QuJlHBMC1AdZy+eIvVGOlLwTeITKYi?=
 =?us-ascii?Q?BBZdjKPopa4ARWl+Ou0g+Vk0+wbirZBYIXhVLi28MI+dDxOCBhRkDaoQ2AQH?=
 =?us-ascii?Q?j/jyrpFCTXisP/efx9o7Md+R0sYzT4d/Qk4FpE+PIIzGQD2lp1P15vBYBR39?=
 =?us-ascii?Q?U8kOIXBw/QXfHVR1su71ApYsb6L/+1+PBGo8w9Qwtf11hbCRE4l57xXbI5bV?=
 =?us-ascii?Q?ADfCp1AiExnBV6XgpKk1mhGuLvsd/25CUKrQbkvBY3e3LfSl69Bn/SOQyrJ/?=
 =?us-ascii?Q?3+78sLyPEo6CilscMDumEfq+QOoSz9KZqwXLbkSrYAZEGueK+Ka8ZBquedPZ?=
 =?us-ascii?Q?a8fImLMDZ94FLreUYUDMal0RwQKywttTVp+g6G61ylJf9JXOAxbJgfCfHfYd?=
 =?us-ascii?Q?iRFplwpwqEbAPEsoFNwER9+Si0moHzU8ZXwPP/00f2gE0jT2iNDMg8buV00U?=
 =?us-ascii?Q?WObcQTmIHtRwVyTh+HLVSwbv/hidpK+01URKHp8eOYuv9L3CXnDCzO5qJijh?=
 =?us-ascii?Q?r5jdTQWgH3Dl6xEf/psvpg6ztmtOTPieQp5UHNTW+7KtNCVXFwW4bEcW0uEn?=
 =?us-ascii?Q?gX77TwLGnvZoNnB4O+Kl9IKbY17Xkzkc7TDnxjdrOt1stDqBkKzvE9ULybj+?=
 =?us-ascii?Q?RmRwK2tAXKUGcYMr0iV2sJ3fDw/I5oeZsw3gY647h6qA+PIFgOe1sfPUTktX?=
 =?us-ascii?Q?4M41T39IhAfFQ2cLSV25k7oHSV7Pwdq5/GZFxTGxM80drnQxX60HelPIWFmY?=
 =?us-ascii?Q?JIEAim8CKjxxELszAVYDNYlkmYKqgTi1lnUFHTk038B4oxlVyfUNeu+VnBNb?=
 =?us-ascii?Q?cJBcjFqBtDwqlyrrABQkkyNOKeTDHHYG/WW6eKNIoIE3uZ1ZRESugfeebt4h?=
 =?us-ascii?Q?JUBkiyLf/ulUK9XC9mC8siAIMX1pKMQiL+ocsANQQaimSMm+eDZKdVdC8TeS?=
 =?us-ascii?Q?790XZN+SaSe73OvEJXsen6CZy9XyyuYsMOlMTmjGqZtCNhPfjSoFWtUSZ++s?=
 =?us-ascii?Q?oRZxjoaNYjfjJJKnwkrGSwu3X+WxUXqCFrZvaqi0jryR/doiMszs2kaPlzy/?=
 =?us-ascii?Q?DdYU2TXmNnD3g2ipDyROk5ePI6lIYSNqv64Z?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(82310400026)(36860700013)(14060799003)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Aug 2025 14:47:53.4982
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 05decebe-c7a2-40ec-ebda-08dddc0ab715
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00025F95.EURPRD83.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR08MB9749
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=kSN06oMF;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=kSN06oMF;       arc=pass (i=2
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

[...]

> If we do something like mte_enable_kernel_asymm(), that one doesn't
> return any error, just fall back to the default mode.

But, in case of mte_enable_kernel_asymm() need return to
change kasan_flag_write_only = false when it doesn't support which
used in KASAN Kunit test.

If we don't return anything, when user set the write_only but HW doesn't
support it, KUNIT test get failure since kasan_write_only_enabled()
return true thou HW doesn't support it.

[...]

Thanks.
--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ9IdVsSxppYh2QC%40e129823.arm.com.
