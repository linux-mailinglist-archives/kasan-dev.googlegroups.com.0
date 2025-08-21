Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBN63TTCQMGQEB2UTV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 16806B2FCA4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 16:31:29 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-74381df95a6sf367227a34.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 07:31:29 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755786679; cv=pass;
        d=google.com; s=arc-20240605;
        b=GXgN/F/hQmZZYgvg9Fg3c2RHnSoTh3Y/4vP6AKOidtpEedsOfC6opjOAk+TAXzXPDV
         Laqc8GdPArln8dasnczLhDP1GN6M7Yvt/fOvefhRPigPfPTOuoKQcpXPaqG+Yx04kGBt
         w34FhRAceX2Gh2WAIV4pnw6dYHlOTA3fMFu7r+dhXw42bds3mdXTWqUIP7qMSjNfMNWn
         VriuHOoCb0dLXo1m6m1oU84BYOCFzWAFU9zJZkUONdRj/eh7ID2NYiFSbUEtWUAaeMbZ
         +AG6nE24n0ZjITUY5ckO4th6Ps0xO3qMw7pkFOOGa2tpqXfIrR1z5arY0ed1UrRC+zWo
         XgvQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=EqxKeeS2VOcUYmbV24+OIOVjabohIlC4KTrH/U5YxRY=;
        fh=8uuOemtcskaicA3GFZb2piwmhS2TjQGJJr2/utuF8RA=;
        b=M+uI4OknI/pQUovyUj/9FedjAOBKQUWJAuXfL5b5aqCNixKdtB7qxI+GfP8/15BTid
         1MC8zoAkJPMGVV5KOu1Kr6KAW+gICZx1h+0PzZh4cydgVOroBQKquvyTrKBJsxk4i959
         ABsBCl0DSSMWgufgydat64yFHO0G9uJuZc9y55A4BrBhRSfNgIFmFSKRAJCc/oBqTaKI
         /5ZVe/SxeBrwNis97YfgJPUR+H6segevJiNq0P0lX3vgaGqkvZ75oMiQemfLiSYzZ1Do
         rqoQ+4g/31Xc2FMXM+m1Vme0mJ3waA4YT0ueHWZH/S1gLKvRlcKYu5K0EPhH/M8ofu83
         QioA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=Oel95M0c;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=Oel95M0c;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755786679; x=1756391479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EqxKeeS2VOcUYmbV24+OIOVjabohIlC4KTrH/U5YxRY=;
        b=XX7/04/DJ9liJvORjwZj6PCOqHdjqSv9DZQkJohn/alVnRu9t6TvPof1B4ZlorWLg7
         X2yGaQaQ/4b11l/hocACmFvs97Qfwi9jly3FyLStQRrNTCM/74mvdA9nPqBMCbsauEB7
         gKLu7uyv/zVM9IEmqFDw6J+bHkf3AlWAn0XHf/Cy/dQOxaVjUT2I7SQIJQAu37FPowsb
         pFJdvl+GL6kLu+nFrDG5K4Wp45KFlny1Sa72vBBsYlfdRtDJKtqtYgRvHJgBrn+1KIaF
         5eYlqInnUmrrHaPjN4gVuudVqYhQgr9JI7Bqx+WBpFtSc0kzFrwMDjt6QgaSewwFjfwU
         LZFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755786679; x=1756391479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EqxKeeS2VOcUYmbV24+OIOVjabohIlC4KTrH/U5YxRY=;
        b=ZcOgxTujKCzATdR9bTjuNLI2bCL/Gq7x54IRSjOSt/Cx6jnmi0U0pnVGJYWNmkDTcI
         lnBrY2xRjspRKkJoSqxZTnHirlzXnaYJZ6I3CpK8P66t61L0439t099ErzKcO+euw0Z4
         s2Lj4en/JwyPZVuvmL3nckfs67yU0q6fuJ6MqrLq6fFju6tLGBXszVuNf9yjdK5qaKHL
         uWOYJS90nL4EARAUNEtsC8ncM9RCgsljE97eO4WxmRI3GXGL1QJyKPUZudkia+V+BIOl
         bn8fBUBbViH9b5RR5fYbvaHPIUlsQYejf01bC840D1WPCXaGPLOVWtyYyIeGShmV5Q5w
         61/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCWaHKMylyZIxyTEwQzZgNWanPOjWPvio/CPaCIWmKy3cOcxSk/4oOVyujuw/afW6YYpC+IEHg==@lfdr.de
X-Gm-Message-State: AOJu0Yz59FGb1f+HJ2OTpYYSkZFCm7G/3l6oUDaMTxPhAPy1n2Bi16KB
	pTEKoHOuPa1jZVaX3tYqzfzufD5m3IIJ8HsNgZZV5VZbY3hKPkQ/pWMe
X-Google-Smtp-Source: AGHT+IEpP5gSFmr/Dw4hYQEZVQELUXm2Geu2giU+2dzXl9ioUViqHUsQBr4osSFWEGgN+w5B2b3hsQ==
X-Received: by 2002:a05:6830:658e:b0:741:c038:f51c with SMTP id 46e09a7af769-744f6900d90mr1468312a34.11.1755786679189;
        Thu, 21 Aug 2025 07:31:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAjV1NH1m329mNFQwpLCEjfwzbrOGvwe0qGSgrcOHpkA==
Received: by 2002:a05:6820:7408:b0:61b:bf13:2b97 with SMTP id
 006d021491bc7-61da8b59824ls149778eaf.0.-pod-prod-06-us; Thu, 21 Aug 2025
 07:31:18 -0700 (PDT)
X-Received: by 2002:a05:6808:190a:b0:434:136f:b29f with SMTP id 5614622812f47-4377d79bd9amr836932b6e.33.1755786678141;
        Thu, 21 Aug 2025 07:31:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755786678; cv=pass;
        d=google.com; s=arc-20240605;
        b=S3KpKvEqf/xK671eyq6v+IyZxguoicUJkhDTir1QEw1j5UQ2zS/JJ/pk7msmGGdFpv
         oJQCf4VdT42bzqAVvdzTFvnWaZgECAeu1RUFiIHw/LAOZcsL0fX003XYWQ5dtrRjbFn1
         kWYz9ju5Pvb2yX+bUp1DKXsVce0o9R+ff9hhiL1B3sDLOtbyo5qUyfatibIU4hPQKrEU
         6HcoSdKIq9zVxmbQIEXGZBlPmwNg0m2BLCXY55hg+C3GPgTgSkOd364KmpFfjObfBbGi
         QGwSLjkxcJc+Nol6kV2Z7fDTtjOhpLhHpcXG9gS5K/m1f/HKUZp+b0LekSNVMyIMgvhe
         IOsA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=0YAaQpN8SasQefWgNfGjOFLbctX2/HktuXOWTy87R7U=;
        fh=k4d4b9fD/D4HYo5FeWfRdNlxvx3UJs5fKGvoR/m6zBM=;
        b=RNSTrtUmceIG2gh9NReXf5cBCgs+CloN3ekdLM+y7E5JNLsAj5YOJV8ADzNRaROegZ
         shrzRpZTsSPUvO8QPHci5BO9X7qXywb9BSLVBGN37+jShr1zR5RR6rFAWOdCLpKykKSJ
         WRJcT55f22AjqdYcgxz81+T4TtKBEhPEVt1JnuIo810fq9sjtt2AwYPtKz6vLjqP41V+
         IX+rnwQjiDf+AOcAXN3scvN06Fs7Ughq5sdRki9CuwouWtrPMv5grF+mnYcSzZ+hZUlP
         FXPCeaL8FFOVUJAM+Zs/Hfble8iubw6VHXT4kA1J5ziS8+kyPng7IxzWUNR+MxCBeJYe
         hVWQ==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=Oel95M0c;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=Oel95M0c;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from MRWPR03CU001.outbound.protection.outlook.com (mail-francesouthazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c207::3])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed1496d7si777122b6e.2.2025.08.21.07.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 07:31:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender) client-ip=2a01:111:f403:c207::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=KE4AvAigMM+cCUew1u2awn6pzk7U/WLr0HmN9Za4k2aRTEqDsQCCwnVeWGy1ruNnJmGZlm08pQRWbCvmFpNN5lpL37wsFvys2mVKPIXGBlu/Rtl9ZpZntCBw6xWwamoNbSCNaQTHVPIETcC1Po3+CIX4OSLeTrywUesvscPEWvyS6WTJPXRna0RGYicBSnbCvKIdblG+EykVOBJr+6SW+kc5LU9020PPyC5BDEPbVBDgp5ag0v4SvIfEO8yzOZb/tYqJ0tnVqSSJTg3Y3LYCSFwibH1qhRKxtwsLqP0KcZfE/2UvoMg1sb6ikFKFgDIt9oGsQ7UrHO8xuuKQZiHbFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0YAaQpN8SasQefWgNfGjOFLbctX2/HktuXOWTy87R7U=;
 b=xDCau0R+R73mvfW29acN9E8Q9tYb1CcCyG6Vi+l12Vk1rxTPZbXwxExgNrnGked6AfPAL3IJ9e/T0Fq8b68cxo6FdK1AV+aRxkE6irgslq2BRSEi1DvGw5haVdn48E+aQcnAzTIBXk4ktfrdi2P7C+AQwI0t1JxoHM3Jam8DMkb7hRPGkPIbuUYf+7+uBplYlR9ex3Yz5wHMb3R+mKJEhnJIOWLVZE+7vHvloTkVRL1f8Cnc7xnHvuRNijlZB9WqtvK/EehO/q8Mhc0/we9NusivA0dpEygDdMD+PqQTxN69JX4NEnVCIMpGHktM7ITPFe9Kgzw6LWCoQh0HjNj8lg==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=googlegroups.com smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS4P191CA0050.EURP191.PROD.OUTLOOK.COM (2603:10a6:20b:657::26)
 by PAVPR08MB9186.eurprd08.prod.outlook.com (2603:10a6:102:30c::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.15; Thu, 21 Aug
 2025 14:31:12 +0000
Received: from AM2PEPF0001C711.eurprd05.prod.outlook.com
 (2603:10a6:20b:657:cafe::32) by AS4P191CA0050.outlook.office365.com
 (2603:10a6:20b:657::26) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9052.15 via Frontend Transport; Thu,
 21 Aug 2025 14:31:12 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM2PEPF0001C711.mail.protection.outlook.com (10.167.16.181) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9052.8
 via Frontend Transport; Thu, 21 Aug 2025 14:31:10 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=CnNOoa/ngTKKgGKghT+0BQACKetOQeOFgpCBaaiFtPUPMRObWpcYwmyad2hFSIacrngh+0ct9OLs0gZbrBtQEQu/kQE7nj/vafow6TIo0IqTZCVnpb26tHxK94zNvcx+Vv0ABYb3L7kiP6OAJ/ici7KnjPj9KABIKomSFagGsHg8HuAHb3GQ9g3LGmYTRhi+i/zqBgYUgFmeFC24Vbi3F2zDDpVLw7PERJS4vfPPPzQ+0B9ZAADdQCsN9LEPbGXlLvhJrYb/9B6VukiA1XQuSsdxL03IYaLZyRppPxlCzXwkmirFCkbV/3RzQwWf0GZljAxNEq4U5QhKmnU6tgYD4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0YAaQpN8SasQefWgNfGjOFLbctX2/HktuXOWTy87R7U=;
 b=cjYMBhNFfOLW6TaaoOYO8S8s+4LyUfoEovbhbOJtY7ILl+/cJl2tjqmK9vmNia+J/7jhs1droF1WnLBlR7LtYnSxPXsqzVBP5pOiaHwbCV2MAla+ggPZ2T77yKowsCdnG2ujSqgaq4WZAcXz9zlBTr1YHVlRbLsOQoGRMNRivL1L6D2Ojevx26V4sAo8CCgeEbrOMRjhnX2Ea1+8DyXlv6BbAc0mPIvJJ6juUOzmxaP5uqapXaHDnow69zdDWGMeMucPx6uFtWV2JdNK2GAvJVYocaX4Vk4LnOHQK1JpINmDdqmUUKAwaNCMdQg1bG2Ga2nloNPO3jNM0qZJd63snA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by VE1PR08MB5597.eurprd08.prod.outlook.com
 (2603:10a6:800:1b3::9) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.14; Thu, 21 Aug
 2025 14:30:38 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9052.012; Thu, 21 Aug 2025
 14:30:37 +0000
Date: Thu, 21 Aug 2025 15:30:34 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Cc: kasan-dev@googlegroups.com, Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [PATCH] kasan: fix GCC mem-intrinsic prefix with sw tags
Message-ID: <aKctip0/nVuirL4U@e129823.arm.com>
References: <20250821120735.156244-1-ada.coupriediaz@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821120735.156244-1-ada.coupriediaz@arm.com>
X-ClientProxiedBy: LO2P123CA0081.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:138::14) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|VE1PR08MB5597:EE_|AM2PEPF0001C711:EE_|PAVPR08MB9186:EE_
X-MS-Office365-Filtering-Correlation-Id: 512497b5-4c43-47f3-39e1-08dde0bf5fc1
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?lDrijyGYgE6kV6wL2CHrzNeKcmVZw2w8sIgLw8nIjTYisptEZ3Hkp0dFpuZV?=
 =?us-ascii?Q?X/mgSrA1nYicpsN0HMz+Q6AVz+N2eoOleisqcIr0unJGwEEGv+Whl6kaVFUq?=
 =?us-ascii?Q?RsiI1TmkbmTN6A3UXjTmLTfH3WNPKYGV/U/v4T9vaMKEsXQal49Y04MYDUep?=
 =?us-ascii?Q?sA7u/PYJDXckaqoqvYDyBOw7NXJ3Vv7iGzWjDMz76yZi8zmGUsxClzyhtAJ0?=
 =?us-ascii?Q?iHUrQOg6nZq9rWQv73Kgd7+Y4itqLCI2XSuZWdqO2h8XhckfBqHSLx+ZvURT?=
 =?us-ascii?Q?iO5ybmi1MuxYXqn/zoXTO40NIo6l4Gw4plVTqB1ie8E7z8sJFNXKM4N2B/Ix?=
 =?us-ascii?Q?hCsH42atgsTjPoV0ODwEmAUwIP8jSZmnZr5z7tL2OQKbRdo9EG7utpyjdrrJ?=
 =?us-ascii?Q?dAKbzS3Vhi5fBkPoOQp07jreXMTOksG5SDO+y+/GF2aG49ZPdhyeM1qrh7/g?=
 =?us-ascii?Q?joREVuDxjQHXon46cLvTDzbkcDNtdCJ+bhQhOmWhHfCgiKjtbk2LQayLpZhJ?=
 =?us-ascii?Q?1PbtdOmtDlM0//L+thFjxRc1R3JKS77AufPLvaort++l1ljDN0p1VN/a6rNS?=
 =?us-ascii?Q?rCvx76yoPLJIZoc4T/KYPF5wZTvu5F/+8IyjtawEL2aGEs08mCJ4J2e7tJyi?=
 =?us-ascii?Q?GbbHrJkTQdB92Wd/H2p0y/UhNm80rq37MwgGH73YvZfADXVFOiWGKNoPOmuE?=
 =?us-ascii?Q?oyxCYKyJrWUqcvTNWJkNVrJkD8mbkbCgpCY/ISwZQTuDoS+Vit/D91h5S2OW?=
 =?us-ascii?Q?7ZDyF6ZCUaUyYE4Fn89Q/Dp0TriLFQwZHpaDfppih5HRk6arqAVkiDtIALt9?=
 =?us-ascii?Q?FvzVqr5lM9U0aMj6kVcf55+9aZmYS2mgXDwPdDNATTsePEsLfM2fZkOsJ6Ds?=
 =?us-ascii?Q?SWaZvBPjRks5VxTMvNYlO/eySGI2KkHJ1R/oOjoCptXMatW+zGklajNrmVLb?=
 =?us-ascii?Q?XKoTKO9qgQ68P4ca70hIGam6Wxw6G+yOTk405AewZ69XdMX97E0ecRDky325?=
 =?us-ascii?Q?qE0voh1Uo2JakQ0UGFNXIc9iq3rLIKxXxjORBTo3ONcdhxknYeTwz72Jdcpg?=
 =?us-ascii?Q?VRTWaDFk+B0HyThz/CkWGQiKEdFNcRSIdyhKADkMIlkPQhpYjS24GEFg6XoQ?=
 =?us-ascii?Q?WxjxZTXXEI3m3SClxNBaI2fiATiTmJBJuObEthixj8WczfJwuGS5Sb5jqBiC?=
 =?us-ascii?Q?yeTdF6qGSO8IhpM4RicvaTRT2r9gxklKUIs5txISoQ1gaotlsrDuOATEkAic?=
 =?us-ascii?Q?dhPd/dL4gEGk02VFpIZAToQkP1W0YRW0fkTsP1EQeyfWC0HdfuCJPgOGQtJO?=
 =?us-ascii?Q?KCwbreWcpLSlSnUOVoWEmJ9FhxoJQD1PkQfSPdOzvB+i9JuuCO0cxjE4ndlD?=
 =?us-ascii?Q?KN77f3fNfMLEf9IShakD7uqS3KQFSEMECU91cYfTPFi6yr+YHcjEAxev73t5?=
 =?us-ascii?Q?Hto9eai9h8Q=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VE1PR08MB5597
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM2PEPF0001C711.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 3a5fa8b7-8727-4bf6-7818-08dde0bf4c0f
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|14060799003|35042699022|36860700013|82310400026|1800799024|13003099007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ULoMaGXbsRygXx3Ag7XfZosJbjLgng5EH3kxgJsGaDzeGjbdBDcF36wQQxlt?=
 =?us-ascii?Q?vpVfZS4GyZECOyWPyTvXWQp/Wl2GMxV3v1nR2hC9Ld6H2IiNGNGApIeR0fzu?=
 =?us-ascii?Q?wb3bPidK2YnHCwWZGtrRBgO9tZ9AZClFlpUp41BoGCEx0RSITgLPLwmpar5j?=
 =?us-ascii?Q?RggVsfH71PvJHLbgGUDBL3TU1u7hQmJ3HCerQdOk7/CbXFNiIjdfR72jXQOi?=
 =?us-ascii?Q?NzsIuur/iW/JuU1C9BLll0csNQniql/UHwtkaF1vNeP0Sovxgpded9gbms1L?=
 =?us-ascii?Q?d7xTeGrFA+FifPbkwH/lH3Q4/B44QWgiLrk4VOoMzvl68qMteje1pohcFmlH?=
 =?us-ascii?Q?fx6AqJwS+3ctbx3dwwDM/yjHp4MhHSBm5Mi5SUNpHeMAt7xIu8TlquTzjzVC?=
 =?us-ascii?Q?tMCaLhD2GNV4PZRuldSGTaZV8/5dN44FrlPptz6cvw2i5AGjo3RI5ffyEOSJ?=
 =?us-ascii?Q?dtn/jjX9QaDxnNfbmwIcTj5fVNN0bG2FdYuJHh+Y5nhHEw1iE/bZRJIE89z4?=
 =?us-ascii?Q?/epkyt/SYYxCbRvsVl2XePIem122ZrybN8LdKlDJ5OkpxEqJukdZJHyWxSzM?=
 =?us-ascii?Q?fBgtJ2+MuOvdv/9hkbdP7iQhnkrFq5fYtwno/aGLQcUvjHsWt6Xm5r2hTa7F?=
 =?us-ascii?Q?9NoGssejlQzEbb4Sy2gwdvyhwkrnTKzIrk2ZEAaaFBcwznoRnPPZ0bNs2TEO?=
 =?us-ascii?Q?coRalT5H/o6Bh3CXxWIw/5yv9QxevO46sjmNCtQWrCx/cZJybFSUJBwdo59o?=
 =?us-ascii?Q?UO+HViD038r3Oq8xwtR/kn2YampKWKOXn14TTKLCYZOV9Kfhrna06tIF4gHN?=
 =?us-ascii?Q?w6DnCEdxYL4xXBFCdj4bCyTY9a69zIH3da8RGimtwZa8a8CuoJo07nHTbEdU?=
 =?us-ascii?Q?v6m3erl+dOimbE6Wtwfj0Uv49QX3eyKhefn78GPTP4rIPbaJ1ZzUWiGWdnDT?=
 =?us-ascii?Q?S2rnFjBQH76nTghph2Jh6i9AtuYUgtYk3ow1cVflBIgF2XWXRyLYiNUAR4XG?=
 =?us-ascii?Q?E+pOFB1uux967ZT8A5GgLvc999Ulzsnn/6/2mYQ2aJRJcZ+ODac/63iT4M8X?=
 =?us-ascii?Q?1ucBo/sg1Jcaj4vp8b1gsEXvzzAb02YyUq9YwpYT/rLSYdAj4hTfWnDkJDcP?=
 =?us-ascii?Q?8SRrsLtZ5B4fcpeOuJ6VezddEGsJ4QCL9Pvc5n8CxhE1t92MZPAzMGIVFNAO?=
 =?us-ascii?Q?aRcl1WxSUIY/bhM58O1IOz6JfmxB8LXt+iEhtuvJJ/HV3EyBPCzjklAxaF97?=
 =?us-ascii?Q?StMKDB7SGnnpzKnP06H1RSsF2ABV9GHGYas/7xEXnnzgKrc1Hm8U5Ak2UIvY?=
 =?us-ascii?Q?OshNtpNdC49JZ9L4k+1WaBbRzDffq/rD6Zu2Nal1UbL+Cwt0gba0ddiPjHS7?=
 =?us-ascii?Q?zewZxIuD1HgnfubrbYVWxJk/+S9BCwotN63XBlIErNTXc+tz5j0cTSyNnPWV?=
 =?us-ascii?Q?IY1vfXdKQb293hYjW7jYeVEnchE5eJwyGF8tcwv/hHF72YHi6vH9AAac4OBY?=
 =?us-ascii?Q?A3HyVWIQH9Tx1gU0nh6Gu38VkrnpEafWZ5ZnO3M6T2X0J1Irs0SBGENIsA?=
 =?us-ascii?Q?=3D=3D?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(376014)(7416014)(14060799003)(35042699022)(36860700013)(82310400026)(1800799024)(13003099007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 14:31:10.5227
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 512497b5-4c43-47f3-39e1-08dde0bf5fc1
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM2PEPF0001C711.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAVPR08MB9186
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=Oel95M0c;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=Oel95M0c;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c207::3 as permitted sender)
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

Reviewed-by: Yeoreum Yun <yeoreum.yun@arm.com>

On Thu, Aug 21, 2025 at 01:07:35PM +0100, Ada Couprie Diaz wrote:
> GCC doesn't support "hwasan-kernel-mem-intrinsic-prefix", only
> "asan-kernel-mem-intrinsic-prefix"[0], while LLVM supports both.
> This is already taken into account when checking
> "CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX", but not in the KASAN Makefile
> adding those parameters when "CONFIG_KASAN_SW_TAGS" is enabled.
>
> Replace the version check with "CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX",
> which already validates that mem-intrinsic prefix parameter can be used,
> and choose the correct name depending on compiler.
>
> GCC 13 and above trigger "CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX" which
> prevents `mem{cpy,move,set}()` being redefined in "mm/kasan/shadow.c"
> since commit 36be5cba99f6 ("kasan: treat meminstrinsic as builtins
> in uninstrumented files"), as we expect the compiler to prefix
> those calls with `__(hw)asan_` instead.
> But as the option passed to GCC has been incorrect, the compiler has
> not been emitting those prefixes, effectively never calling
> the instrumented versions of `mem{cpy,move,set}()`
> with "CONFIG_KASAN_SW_TAGS" enabled.
>
> If "CONFIG_FORTIFY_SOURCES" is enabled, this issue would be mitigated
> as it redefines `mem{cpy,move,set}()` and properly aliases the
> `__underlying_mem*()` that will be called to the instrumented versions.
>
> [0]: https://gcc.gnu.org/onlinedocs/gcc-13.4.0/gcc/Optimize-Options.html
>
> Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
> Fixes: 36be5cba99f6 ("kasan: treat meminstrinsic as builtins in uninstrumented files")
> ---
>  scripts/Makefile.kasan | 12 ++++++++----
>  1 file changed, 8 insertions(+), 4 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 693dbbebebba..0ba2aac3b8dc 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -86,10 +86,14 @@ kasan_params += hwasan-instrument-stack=$(stack_enable) \
>  		hwasan-use-short-granules=0 \
>  		hwasan-inline-all-checks=0
>
> -# Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
> -ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
> -	kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
> -endif
> +# Instrument memcpy/memset/memmove calls by using instrumented __(hw)asan_mem*().
> +ifdef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> +	ifdef CONFIG_CC_IS_GCC
> +		kasan_params += asan-kernel-mem-intrinsic-prefix=1
> +	else
> +		kasan_params += hwasan-kernel-mem-intrinsic-prefix=1
> +	endif
> +endif # CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>
>  endif # CONFIG_KASAN_SW_TAGS
>
>
> base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
> --
> 2.43.0
>

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKctip0/nVuirL4U%40e129823.arm.com.
