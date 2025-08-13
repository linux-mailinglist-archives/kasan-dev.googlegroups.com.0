Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBN7A6DCAMGQEKTRDHXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id BD772B24166
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 08:27:05 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-619af4fc57fsf8335756eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 23:27:05 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755066424; cv=pass;
        d=google.com; s=arc-20240605;
        b=lI9X9G30TQepT8xyndD+z13vB3E0MDpvYffBvLVLCkJ6HUzJqvRgt4a1wlOdRnAMje
         7xaPO+bGHlnT9XlppdoW5FQWd12IH2ivWsTzNohmDFSdBMmvh7MLU9p7HWgYhN57Xl34
         sdzP7OZZ0ChyLZLrYfFJLe+oWwbzWeBbYm7FwLbU8yxOIZuRCNc3QOvHcQ64m76ThDsQ
         zQb2ISXAPdqibiRoo9uDrkSXsk/mrWOY9lKNsEEYLazqvYEvxlO4ePkY6VA6WOcseh45
         zh6rPegT+sSo6gKYqEUOCYuW4amCEB2cUxk8NnmwgNChyV6jb1MBv4OZfUVyqLe0IfBq
         0k0g==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=HMOBilkWTchuKkeECbNxzXnPs+JRGZ0V7qGthhT/EZ4=;
        fh=5AntPV6xHmu5pNRoMImhRl771Sl22gK3IUxXuwpbGWA=;
        b=K8t8Rnuzdx68VOg0TU7gs2n1Od3b9+c7E6rgIsiXi2wGFMA5v+F7CVNvN6x8G0IgW/
         cOxR1HTANWa2lUg0DKzNnfRp9Wq61nG9XRkfVYoxTU1g75AxQLw4BAS+MrpL0mX0uDtc
         3Oyfg/KmDiuFlFa/P+ZFWtP0Engz/21p/UBpjuqArlc8o0JXnyxAqvxQgw36oKrRa6dP
         qpsBi470I0ykTf5p90E7zkGvvrAyPW90yLwVQ7d8G0JyFJl1JBFCMKxUOX99Kmb9fWUp
         KPEHL2UMAvbiOFn6iUMpDZ33//vtj5d9ssy5hs/9jmlduT7u+TBEC6XxA1tdNdmpVDQ3
         DlMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="QFJXkta/";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="QFJXkta/";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755066424; x=1755671224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=HMOBilkWTchuKkeECbNxzXnPs+JRGZ0V7qGthhT/EZ4=;
        b=OlvlyHNKet40qBuqFB7UdUM6OoVqjSqPY41G6AIA7vpCIa+qmhzxoVibU8OXm2KAD3
         t8wAzqDJSmAAsFVDb1qpgLuUNyDeKtr9F2+TeTBg/2hawRelFjobKH3hhdcTMcJHDNBv
         oTNSWpjGrZBC7usFlItMfbRADdCpxA4UHBFPZLGCCImgxC2KoVqtv+EsPAcWm8tjwPkS
         FEIKlr5lkNt2MA9Ihv6PX+ZblzAahzRMGgFK/vNRqDK2McfGpW56BZuh6WZkFZRtAoHW
         vDqXfRLS+55gMgxfg56C8FnPaQCy+u+jgonAKYJz2o00iLOp+oewtOQwf4B7/lWxDqh2
         LiIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755066424; x=1755671224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HMOBilkWTchuKkeECbNxzXnPs+JRGZ0V7qGthhT/EZ4=;
        b=gXNblSoBgILs6CCYa+KP4eMT/8z5CvUev1QTB1IZpP8K6erXA4XrdKA7hXcU4w5/iw
         7cEThyZw626f6QcOMs0c+DrpNX+WQ55tUrSCj0bzAaYR0KK87fKMglO+4Mr401JRFPx7
         ngsWNJgWx8qzoojRoCwKb7F+aifbqcoqg2trTTAkTVRo1frJ9LdYQ8UUcIZBaQ7V841i
         flk4eszj7+7f5fEN+oJmtsMPOgnyIaLw+4esHD6+eoNAbWn6O6iqLfyPrEZpitzh8H/6
         TK303iNCsnCoPvRrhrXCngI7bjeJoAmBZOJl3q9P/LBFUY7o22zHjZLSn952FaHYKeCi
         3/6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCWyQW1tgNVzzvPgBoK4uJJKzNQBFY6Fne2+tpBkj0emT59S7d7HnG/09LijsLaRieXjgmAR7A==@lfdr.de
X-Gm-Message-State: AOJu0YzoZVOnZoohwt6bMRnz/0044+Fl6F0axQKJz2y7Ng7Mh/MxdkMn
	lWeBM3BSXEXBSMlHLLUPoKjTp0GN80GBydo6G8kWO5ceiEppmIx57tIu
X-Google-Smtp-Source: AGHT+IEd+gGSFWNoem26fpMe1lZ0acTEtQrEVKxuoJ4npPWc+5gpBjnSP7ADlIF74+yo6yXtOTIsYg==
X-Received: by 2002:a05:6820:1ad1:b0:61b:5d05:1aba with SMTP id 006d021491bc7-61bc73aef8amr933019eaf.1.1755066424058;
        Tue, 12 Aug 2025 23:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcOOLVL1CgZ9TsvRK4PJkbo0MzaGMNFVFKOT3WCzQckCQ==
Received: by 2002:a05:6820:2e8e:b0:619:9afd:8a79 with SMTP id
 006d021491bc7-61b6ea2cdd3ls1661225eaf.2.-pod-prod-03-us; Tue, 12 Aug 2025
 23:27:03 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVpHiqNVyY4/yOC3UXC1+G6tPVaAiZTRliTcBg9GD2Cl62vKTDFpb5cPH1nVm2Oh5rYDgC3JzVUQw8=@googlegroups.com
X-Received: by 2002:a05:6830:2112:b0:741:c51c:9e3 with SMTP id 46e09a7af769-743754b01c0mr1276923a34.23.1755066422984;
        Tue, 12 Aug 2025 23:27:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755066422; cv=pass;
        d=google.com; s=arc-20240605;
        b=hqFfMUOqriJLZEJjTE9cGJsSrvievadRsbDqN2u390411SKTYy1vtVpir2H5OmIkIH
         K03dlRRAnADPkhzsmxvt5e0r3+gpE5XbfRTaJ/dmFdU0R76CGswb+dFMHZWRon+44qZo
         cerNoH0o5A1eWb9b1LHn9LtkaPMzUErTTyljtN2tPOGhzvw43ef2dC9VUyLCDhx1xUYL
         zAG1BD8AEiBKmfv0iVg2EdpHDArtAefdnu25S9e6TH6QOHxLqO/kQnhO+7SeCHEtVzEg
         Xx2Pm1DaM191ZNC2Jf2JaBqvKy3FXBronKmwNLlbCx4ljJkGpayAGtktD55Ohoo8qOgv
         Fx5g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=bgsnuYhmf4nbO6Kttw/oLMavKD4JKFavy6PjPHgHCSU=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=OjgFndS6fo7nYvZCicW8at2if299du1jGnHxlopcW7qT7ZXb8JGY0Z0LCsyNymyPXo
         Kq9aZgYdufZSSe6/ADZmsDG6qaTEbNWZieHUIxWnKzXyN6JzZ2qyg/eLLO2xl3gH9aBa
         2EEDmB3qvHeKJOCQWBoV3XEk53rl3RoGk+TP8aFhFBmoPKdK9SNXC/llr6XN5oFSLdrU
         bWlyRQ2a2PhnCndrXnZck4UqJ5lmfiQIaQ/Av0+btpm5tT7ZeOMmak7Li1uT2CZ6Z527
         nNybEvHjLg/X3/fL0yiHx9y1FaYZHYZErYQMFIErT9ztNrv9wWW9ZK+p0bv/+gHM5PGx
         98gQ==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="QFJXkta/";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="QFJXkta/";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7436f866c3esi126442a34.1.2025.08.12.23.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 23:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=X84Jlx/p2PRhdduHcskf0RAE4GMYJhjhYlRmm3p9akkmDvBXq8NuyJ52UK73TcTX8Vcd8ce6oa4ubKNJCuy0U+PWK1b9PYZIumTjDta++Jt8M5V0OyhJ3vpW4doKVek8kP0KlMemHjgt52xU8VWnFBXkbAZycbuazDMtYxkUo5uSJwxgPmRR2nStUvrsFSI7Zep7v0zRsOIIkikTqG/b6lf2iDzmgLm3tehb9FYRE65joBkxTWmFnR0Ix8aD8kOYB+yE15wTRUXo2XtDYiO5VHwndIDPdMW0ZGGxDmlrIJWsSAo/+Ns26Hwdld2ErW5t4o0ewy+NzT2fPjcO/YQFlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bgsnuYhmf4nbO6Kttw/oLMavKD4JKFavy6PjPHgHCSU=;
 b=nnn+bkC3fw4X235UtQSuL1Ad70X4W8FkDWRDX3ptD9pPvhHFZAaWBQtjZwjo2cK3ubeemaEmuzLV/9NlVX0YtZfbvRgvYvn1+C5HUMco1zH4okx51DQETE1vBZR50mSHRAZJkMjtUuxICOe7Xf7rOOK/HA3VbFSBbUj/rQvG0CZLqOkX9oX0bd0pUHVbmq+iKZi3ghWqUlGuyNm+XVJON3CW7RTezhSI1knFFRllEZM0O+kv2j0B3/JRnOfJ+HW3+C8AabT5gjm82cj/0LH4fiiiDaIqdcyklcEHwFMPyL3L7U7/TUK8MSq+1Gc71xJvKMygwVJc5twQIs0HXgNCUA==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from PAZP264CA0207.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:237::25)
 by DU0PR08MB8977.eurprd08.prod.outlook.com (2603:10a6:10:465::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.13; Wed, 13 Aug
 2025 06:26:59 +0000
Received: from AM4PEPF00025F98.EURPRD83.prod.outlook.com
 (2603:10a6:102:237:cafe::d) by PAZP264CA0207.outlook.office365.com
 (2603:10a6:102:237::25) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.15 via Frontend Transport; Wed,
 13 Aug 2025 06:26:59 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00025F98.mail.protection.outlook.com (10.167.16.7) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9052.0 via
 Frontend Transport; Wed, 13 Aug 2025 06:26:58 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ehRyYh0G4+RAbXI4u91OJkNMcfjaH2E7nmX2TQpyLaqt0FSpKG+1Kbxgr7RmD5B0t0oIkQ97fXa6XkxclSbqjZjPzEuaYa8Rb8iuU6uaTlcCQh2RYf2jnaUl9bDkE5GdOY4vq24iyJu78w6EcoXzBpmW3bUxTvGdNJxUlv0sYJRawvRoq9lNxMbRUkOd2iZa31eKQMly9HlG6hDU1UUrhpCFaASlkX14o3dAaFvmcwo9hVxtNtq6SxOfCESSD7CgORLZMVsg9TAMbDMoyU/d7Apx29uCX1gCLqoLPY1rPlljvVdo0KbuVXHXWCfFFEsoQ1PNOfcI+9ESg6WN6Z9XDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bgsnuYhmf4nbO6Kttw/oLMavKD4JKFavy6PjPHgHCSU=;
 b=PyheTsSeAB5bmB0NFUQ8EQf/8+MAqnvdupWJD94PIl9tJ4dEcHGCLSYFVQuzRP8hryKuNdNLrcbrbNRQ6dw9MQv9cnQp7/m2DfMHWEYWJHCsMWNXFr7NPHJWvwBUHD/QIlr+qskyfeehbxr0qdYmyHSXcP9NkKZj2XnLgBPWqc9XyaoCArWlahs851ltMHr0rgzBRIYHYJs8w6Ul448Xan1jcVkA0lRS2zR3uUYpvuicrVpvEzWV9C9ts1C1q8BB0bWRByrvlmz/LRzTsWCTlS9phIAvnkNcDDJHAuV6MkWdEVYoSdj5SBnbBY4HSyzBHbotfcH2WgjQ1EMUZcPZNQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by DU2PR08MB10230.eurprd08.prod.outlook.com
 (2603:10a6:10:46e::18) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Wed, 13 Aug
 2025 06:26:26 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.012; Wed, 13 Aug 2025
 06:26:26 +0000
Date: Wed, 13 Aug 2025 07:26:22 +0100
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
Subject: Re: [PATCH 1/2] kasan/hw-tags: introduce store only mode
Message-ID: <aJwwDs9bGGFSYWTk@e129823.arm.com>
References: <20250811173626.1878783-1-yeoreum.yun@arm.com>
 <20250811173626.1878783-2-yeoreum.yun@arm.com>
 <CA+fCnZe6F9dn8qGbNsgWXkQ_3e8oSQ80sd3X=aHFa-AUy_7kjg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZe6F9dn8qGbNsgWXkQ_3e8oSQ80sd3X=aHFa-AUy_7kjg@mail.gmail.com>
X-ClientProxiedBy: LO2P265CA0045.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:61::33) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|DU2PR08MB10230:EE_|AM4PEPF00025F98:EE_|DU0PR08MB8977:EE_
X-MS-Office365-Filtering-Correlation-Id: a1d20319-bf3d-4599-67c6-08ddda3267e0
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?RSt1V3ByWjBuR2hyQUZkeW9pZ2E2MkhFT1VkS09IUXVHZEwyNFY3NTdOdWY1?=
 =?utf-8?B?dkVld2k0b01IYXV5RmdjMDIyWDJYOGZRYjdkRHFaTWtqN2RpYTAwWnlFenZv?=
 =?utf-8?B?ajVNR2VzaWxkUnpPSmtSMXB0akxUbVd0TmpDUmdqdTc0ZEVJclVKVzhaNEgv?=
 =?utf-8?B?RFZ2WEUvQUh6Zy9VWWFTNkxpak54d2ZVU3NuV2c2VWZXdkZTT01qdmg1RDhw?=
 =?utf-8?B?NWQ0R3l3cVZ5WmxvSnFoMGY4MFMxMXUvYld2MXpBMm1Tc2hRYjZlVzNZT1Fh?=
 =?utf-8?B?eEpFdnlEZHppRVZ5Rmg0MmQvS2ovMDVPUkltcHJvcTN2akdkYVhOY3ZHN0Nu?=
 =?utf-8?B?dmVId1Zrc2dtVVhDdEpuVWdiYiszRSthVWZjeUw4YityN2FjbXQ2dkpwcVVx?=
 =?utf-8?B?R1FsWVlXSkYraHpKdmw0T283aTdCQStZR24ycEhpMi8xME1zNXF1VlA2Smx2?=
 =?utf-8?B?MHFXaTJ1ODF5UCtidENyVklwVktTQWpycDFWc1B3YVpwN1VEcmtBb2dIQTFq?=
 =?utf-8?B?U2QwTFhYcVFUVmMxa1FsMEUyYWNaRDRaQ2NpWUFKYlUzbXlicnF3bVBIdzV4?=
 =?utf-8?B?SFAyTjRuQ1VRT3YvVFJnVVhBV1pVTXVrRXM4TzV5TkwyNUY1NTZudHo2cFNX?=
 =?utf-8?B?ZGJhUVhOMnMxZEg4STN5VEI4bVNNMUF3MkczaWtLNkVmS3R5VlMwTGtqcDUz?=
 =?utf-8?B?ZnYzdDR0c285ZHNveno1N2I0ejRtdmFUcHNJOWlyMHF4QUpFNDNUQ2swbFpl?=
 =?utf-8?B?K1IwQURYd1grZkpWNHZacXV0TnpOem5oWVR0cVZaRnpJYmMwRE51MjhLRXp3?=
 =?utf-8?B?OXRjZ0dGZ3MwcWhBZ25LZHhVWGh6dDhtMEJaTlBuU0Y5WSs3S3hzYUVuak5H?=
 =?utf-8?B?MFFKZjRZNWhodnhhVG5XQ1RJcUtnK2QvOExmbWhGOEhWSXFRRGFMemZxRzVk?=
 =?utf-8?B?Wk9EaC9ocDU4RGJFd3BMN0VVUXRCaGs3M3ZyeG5hUHA5bTk4TmYvWHdDTHRJ?=
 =?utf-8?B?MkxtbmtsUklUb21TSUloTFk5TENHMWhRaGUyY3QzR2Q5Y1NPNVBkTmdMOHZi?=
 =?utf-8?B?d2pIRUlYZXRxcWNjY3lTUTc3Y3V2MGVIVE5CTVdPRzdlMnNMYU1GVno0N2Qz?=
 =?utf-8?B?NnhycEt4T01mN2d6eCtkTVN6bmVrZFF1MGZ2bDEvNUgrbVQyMm5TendZQXlP?=
 =?utf-8?B?WW5MY2s2R1Q0MkRLamhJczdrZ1pTQndIK1RMQ0RpRjFaVVdmbUJUSExSbVhX?=
 =?utf-8?B?S2lpdEhITHAwd3FnWDhNZDgzZ0k1Q0xISmlJdnQ4MGtLazVaZFJSZjdhcDN4?=
 =?utf-8?B?VWZubklhVlJuWDNRMGtBVHI2RDVaUWFoUGtBZm9ya29XM3pZek82T0hRTnFM?=
 =?utf-8?B?TmdvQ2d2MXJzS3lwcDA1SmpMQkRKUjgrcXFkcXlleUwvYlZhWUV6T05aRGlJ?=
 =?utf-8?B?RkJ2TDBRSmx3a1JDL2FtZVJMK1lwVHBaZmw1R24zVlRMa1JBek5Cd0s0MXI2?=
 =?utf-8?B?NlhvcTFtWUtlWHBhaVBLVkFRTlhkeWRrcEZrMWhTVDJ0ckI3UktNRkM3bjgr?=
 =?utf-8?B?eWFiTGw4RG0vV3ZRY3JEODcvWG5uenZBcHNlZlIvTVRKbUdya21kc09OU1Vq?=
 =?utf-8?B?SURtVVk4elkrci90S0ZoSjFPRUJ2MUQwS3p2eElQNEVONlZicVg1djRQZ1Ro?=
 =?utf-8?B?Zm5XVmNDUGlDelczdHRqTVhncWRZQ3BzTTY1djJ3ZWoxamdKUG90ZTNnWkhO?=
 =?utf-8?B?aWRpTmFvWE55MUVSK0pRcmpDU3hPRjFvanRxdW44UWIxU2RGWVM5WE5OTEFs?=
 =?utf-8?B?NFEzQyttT2lUeCtzczMvTGQxbG1hMFJyM05xZ1JjUWV3S0lSQUQrQ0NOMkhw?=
 =?utf-8?B?enFPVm9DOGdIYWN5K0ZWcjhCS3BLS2c2Z1ZKSWFOZXFYb1RqT2FtSjdvWU8v?=
 =?utf-8?Q?+DO8nP1aRzg=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU2PR08MB10230
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00025F98.EURPRD83.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: d36912ec-9cc3-4a3d-49a4-08ddda325499
X-Microsoft-Antispam: BCL:0;ARA:13230040|82310400026|35042699022|14060799003|376014|7416014|36860700013|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?L2c1RXd1Uld4SlcyVllFZlB6akN2MGNhSXlZdHRGUVpGT3R6R2o2Rktabmc3?=
 =?utf-8?B?YlU1M3pSSWdiaUdIdFhscmJ5RDY3dzdzakF2QzJMcnNTMFVyOW9QQXhxSTlN?=
 =?utf-8?B?bGUwTm5VQkJMYmg0Y0F5Q0FWcnBxdWVKT29xUjVnN1p4eHJrTWNicFNBVUVn?=
 =?utf-8?B?R3lhaGtWTXFQM2tXRDQ4ZVZRSGhvbFNOOVQ0YWhJcXdUYm5EeEM5aWJ3WVM4?=
 =?utf-8?B?eU5RNUdsc0R3TU56Y3QyTjlDc2x3cHhrSEN0bS8xWm5MM2lGcWw0aEgyUWsx?=
 =?utf-8?B?K1FLV0plRW05S040VGtFYUdjYU9GMVhZVTdTRncwRzROczNKak1PSHBZWHlP?=
 =?utf-8?B?czFTdVNvTnd1L1ZtOW15emZuTGgrZ0R0UTVUR1NuZ1JFWWRqNzUvVGdTdTRy?=
 =?utf-8?B?OTg0S2c2S01oMlY1OUR4ajZEQUszOWhSL01XNW1ZZEowd21IQUFBRncrQTdm?=
 =?utf-8?B?Tnpyc2N2Q1F1ZnVJUFpxaHJDaHFGVzQ3UnAzNjNybEhRNU9KaHJMU0lGRVR6?=
 =?utf-8?B?TVYzcGk0ZWtGeFhGQVhRaldxOFJxaTJ5WERUUlMrL1pGR1FnUStlM0paSWp2?=
 =?utf-8?B?OXJUc1VXTXN3eHN4N3MvMnVuOGdMTFZhTVFlcjkxcWNha0gvTUQ5S1FOVmFH?=
 =?utf-8?B?bUtrM2hTUXdpWXRJRHNXcnZ0bG9EYzJCRncxMzJ2dHdHQy9LN3gxcFZseG56?=
 =?utf-8?B?Wm1tcEtSalo3cWdWMmVXZ0xXZHVmU3FpV1ZIWFF4LytPdEwzS01XRndFQXNT?=
 =?utf-8?B?YTM3VVVIL1l6UVB6WXVkZUVIOFpzekx6aE9FdGtWK2YxdjFrUW5KbHRPaGla?=
 =?utf-8?B?RnZRMTVoUUZuR3diWFBDVGxaTXJPVU1CVlU0OWp6S01rWitZUmc4SmdOUkhq?=
 =?utf-8?B?SjJkZVU0L0RwazBPZkcreURSd2VSRnU4SGR3cWo4YU9WOHNmQ0ozbS9UcWJW?=
 =?utf-8?B?cnpiNTRlUDNzaFNZeWIvNWJUUTRSa1p3Yy9pRkluaFlxTThNbUFZSVlHZWVP?=
 =?utf-8?B?UXQ3bCtUdHdieDcwS2dMTmZ3R1FuQlhWSVloWTkwdVdjQ0RlMFZKcWUrcFh2?=
 =?utf-8?B?WTBLWDBIelpXeFpoTHFrUUJ2ZjcvL1R4UG42dmNCdDlyU0Y1THhuclp2aEl3?=
 =?utf-8?B?TzdnZlBwVTQyU0VNWWRJTU1EMG5YV3lVQUY2UEFoUm1SemhzYmNQTFlXaEgz?=
 =?utf-8?B?c0drRlVnVWMyZTJLVUtYUEFtaXNMWVBaRWN2TkdRU3ZkWE9zT2ZrbFJUc0tl?=
 =?utf-8?B?Z2FSdjJvVjlBMHFWL1NBSTVrS3ovU1RBajczajQvbVJyS3ZrMS9rZzFtNlVh?=
 =?utf-8?B?TDZFL09PV2tiZ0hNWGF6Unc0UmdScXlaNDZOVG5YTzdyU0hkTDVHbU9xY2dX?=
 =?utf-8?B?cUEyWjJNZmFhN2pORkNncGRKdjFCZ25PTDBXZFBXdmJUNjlmeGc4Vnl2NHBq?=
 =?utf-8?B?aUI5aGZBQlpCeDNRNGxOUE1aZ2EvSGFMUXNNcWJ2M1d4eFZwaEQ5VVBrZXd1?=
 =?utf-8?B?dzVoZVpWTW52LzBQZkp5Y3VyYUNPakpmL2Z2SEFVaXNpWGNVQkxMYVg2bkJT?=
 =?utf-8?B?dnYrR2oxODNCbWF3TTgvUFU0bUFlT0RoZWJ6Rnh3ZVorUEdZcEh6VUM2ZEp5?=
 =?utf-8?B?c0w3SlgrWW44L2U1NTZ3dCt5dFIxYmt3SGQ3VUdPbDZjWVhCYUNiMlF2a2Vo?=
 =?utf-8?B?Q2FiUE0xTS9pc0RzYmt4eXdrOElDNm9vQW1PcUxvNzZaa2U3cTRQM29zK2or?=
 =?utf-8?B?NEhWNXQ4dXJKNGxNT3ZWV0k0TlpFRGQzdTJjMDVoblJwQWR4Z1JSUnl0SlpW?=
 =?utf-8?B?ZFo2TmF4d01pY1gwUnZEaFNFK0ZHV1pRVFhGbk5jU00ra0JXeU1WMUpTNDMw?=
 =?utf-8?B?MS9KYWExb2h4Q3RUUVIwSlFyTGxqQ3FQMGpGenMySmVtOEx0dzFVNmthNjgy?=
 =?utf-8?B?Tnd1dXQ0aGpKUENycTgrN1pkRzJxMUw5YXVTNmRMbVVoWnF6S3lxK0RGZ1FU?=
 =?utf-8?B?TkFzeWlCSUZsT09ZQTBqTzFKQyswdExMcjVINlZaU0ZPZ0JyWnN5TEJRa21H?=
 =?utf-8?Q?ABz5da?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(82310400026)(35042699022)(14060799003)(376014)(7416014)(36860700013)(1800799024);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Aug 2025 06:26:58.1399
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: a1d20319-bf3d-4599-67c6-08ddda3267e0
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00025F98.EURPRD83.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR08MB8977
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="QFJXkta/";       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="QFJXkta/";       arc=pass (i=2
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

Hi Andrey,

> On Mon, Aug 11, 2025 at 7:36=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com>=
 wrote:
> >
> > Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> > raise of tag check fault on store operation only.
>
> To clarify: this feature is independent on the sync/async/asymm modes?
> So any mode can be used together with FEATURE_MTE_STORE_ONLY?

Yes it is. the ARM64_MTE_STORE_ONLY is separate SYSTEM_FEATURE then
ARM64_MTE and ARM64_MTE_ASYMM.
0 So any mode can be used together with ARM64_MTE_STORE_ONLY.

>
> > Introcude KASAN store only mode based on this feature.
> >
> > KASAN store only mode restricts KASAN checks operation for store only a=
nd
> > omits the checks for fetch/read operation when accessing memory.
> > So it might be used not only debugging enviroment but also normal
> > enviroment to check memory safty.
> >
> > This features can be controlled with "kasan.stonly" arguments.
> > When "kasan.stonly=3Don", KASAN checks store only mode otherwise
> > KASAN checks all operations.
>
> "stonly" looks cryptic, how about "kasan.store_only"?

Okay.

>
> Also, are there any existing/planned modes/extensions of the feature?
> E.g. read only? Knowing this will allow to better plan the
> command-line parameter format.

AFAIK, there will be no plan for new feature like "read only"
and any other modes to be added.
Also "store only" feature can be used with all mode
currently, I seems good to leave it as it is.

>
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
> >  Documentation/dev-tools/kasan.rst  |  3 ++
> >  arch/arm64/include/asm/memory.h    |  1 +
> >  arch/arm64/include/asm/mte-kasan.h |  6 +++
> >  arch/arm64/kernel/cpufeature.c     |  6 +++
> >  arch/arm64/kernel/mte.c            | 14 ++++++
> >  include/linux/kasan.h              |  2 +
> >  mm/kasan/hw_tags.c                 | 76 +++++++++++++++++++++++++++++-
> >  mm/kasan/kasan.h                   | 10 ++++
> >  8 files changed, 116 insertions(+), 2 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tool=
s/kasan.rst
> > index 0a1418ab72fd..7567a2ca0e39 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -163,6 +163,9 @@ disabling KASAN altogether or controlling its featu=
res:
> >    This parameter is intended to allow sampling only large page_alloc
> >    allocations, which is the biggest source of the performance overhead=
.
> >
> > +- ``kasan.stonly=3Doff`` or ``kasan.stonly=3Don`` controls whether KAS=
AN checks
> > +  store operation only or all operation.
>
> How about:
>
> ``kasan.store_only=3Doff`` or ``=3Don`` controls whether KASAN checks onl=
y
> the store (write) accesses only or all accesses (default: ``off``).
>
> And let's put this next to kasan.mode, as the new parameter is related.

Thanks for your suggetion. I'll change it.

>
> > +
> >  Error reports
> >  ~~~~~~~~~~~~~
> >
> > diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/m=
emory.h
> > index 5213248e081b..9d8c72c9c91f 100644
> > --- a/arch/arm64/include/asm/memory.h
> > +++ b/arch/arm64/include/asm/memory.h
> > @@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *add=
r, u8 tag)
> >  #define arch_enable_tag_checks_sync()          mte_enable_kernel_sync(=
)
> >  #define arch_enable_tag_checks_async()         mte_enable_kernel_async=
()
> >  #define arch_enable_tag_checks_asymm()         mte_enable_kernel_asymm=
()
> > +#define arch_enable_tag_checks_stonly()        mte_enable_kernel_stonl=
y()
> >  #define arch_suppress_tag_checks_start()       mte_enable_tco()
> >  #define arch_suppress_tag_checks_stop()                mte_disable_tco=
()
> >  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
> > diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/as=
m/mte-kasan.h
> > index 2e98028c1965..d75908ed9d0f 100644
> > --- a/arch/arm64/include/asm/mte-kasan.h
> > +++ b/arch/arm64/include/asm/mte-kasan.h
> > @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr=
, size_t size, u8 tag,
> >  void mte_enable_kernel_sync(void);
> >  void mte_enable_kernel_async(void);
> >  void mte_enable_kernel_asymm(void);
> > +int mte_enable_kernel_stonly(void);
> >
> >  #else /* CONFIG_ARM64_MTE */
> >
> > @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
> >  {
> >  }
> >
> > +static inline int mte_enable_kenrel_stonly(void)
> > +{
> > +       return -EINVAL;
> > +}
> > +
> >  #endif /* CONFIG_ARM64_MTE */
> >
> >  #endif /* __ASSEMBLY__ */
> > diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeat=
ure.c
> > index 9ad065f15f1d..fdc510fe0187 100644
> > --- a/arch/arm64/kernel/cpufeature.c
> > +++ b/arch/arm64/kernel/cpufeature.c
> > @@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capa=
bilities const *cap)
> >
> >         kasan_init_hw_tags_cpu();
> >  }
> > +
> > +static void cpu_enable_mte_stonly(struct arm64_cpu_capabilities const =
*cap)
> > +{
> > +       kasan_late_init_hw_tags_cpu();
> > +}
> >  #endif /* CONFIG_ARM64_MTE */
> >
> >  static void user_feature_fixup(void)
> > @@ -2922,6 +2927,7 @@ static const struct arm64_cpu_capabilities arm64_=
features[] =3D {
> >                 .capability =3D ARM64_MTE_STORE_ONLY,
> >                 .type =3D ARM64_CPUCAP_SYSTEM_FEATURE,
> >                 .matches =3D has_cpuid_feature,
> > +               .cpu_enable =3D cpu_enable_mte_stonly,
> >                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
> >         },
> >  #endif /* CONFIG_ARM64_MTE */
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index e5e773844889..a1cb2a8a79a1 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
> >                 mte_enable_kernel_sync();
> >         }
> >  }
> > +
> > +int mte_enable_kernel_stonly(void)
> > +{
> > +       if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
> > +               return -EINVAL;
> > +
> > +       sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
> > +                        SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
> > +       isb();
> > +
> > +       pr_info_once("MTE: enabled stonly mode at EL1\n");
> > +
> > +       return 0;
> > +}
> >  #endif
> >
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 890011071f2b..28951b29c593 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -552,9 +552,11 @@ static inline void kasan_init_sw_tags(void) { }
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  void kasan_init_hw_tags_cpu(void);
> >  void __init kasan_init_hw_tags(void);
> > +void kasan_late_init_hw_tags_cpu(void);
>
> Why do we need a separate late init function? Can we not enable
> store-only at the same place where we enable async/asymm?

It couldn't since the ARM64_MTE_ASYMM and ARM64_MTE are boot feature
So the kasan_init_hw_tags() is called by boot cpu before other cpus're on.
But, ARM64_MTE_STORE_ONLY is SYSTEM_FEATURE so this feature is enabled
only when all cpus're on and they can use this system feature.

[...]

Thanks!
--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
JwwDs9bGGFSYWTk%40e129823.arm.com.
