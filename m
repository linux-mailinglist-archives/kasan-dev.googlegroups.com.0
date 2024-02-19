Return-Path: <kasan-dev+bncBDLKPY4HVQKBB4G3Z2XAMGQES5CRGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 86C9185AC1F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 20:37:22 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d24093c2cesf8420581fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 11:37:22 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708371442; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+B7P8kQ8EFaZLlE0BuRKdh39H2K7WNvMhlhYCd/SfZckA0g5Dvn8nkUtKGxkXmOS+
         RxuKxmGs9QLjICR1i4VqJ8loSWqzEJTAiqITj0tMq9+0exXcG9NQbAcRgfyQMoFHJKiY
         CQsTIm0RWu7/qw14W9bH6I1EzkIy/Iyl9upwuPJWbXnEDtxGHBEy0Log4ycDINDShOfl
         nVAw/e5e/CJ6XhVvCHZieSylSxw7y6/gP3Ns4Hu7lzdM+60dxdCbHcfJR371KyzCkSTA
         zrRTrXnIpF2RHg37ZUe+REfSljNkYRiMEOEu3QHJf9QdYIsQufHcjxB2zQOU3rP66yr+
         vAHw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=hRLyAFd43N8P6HZLXH5W6Uq4qLizVruOJwJlEkD+3iw=;
        fh=OOpV+Iqo9Os7+sfns4o/8HE6NTrQuOTwkJrc1+XcZus=;
        b=fir9lKpFQkIdK+g6UcYX12BddzHTkh+gBmAfN5OM/SYFmimeLDvHZBvRL591yHHTSj
         ArXiUMZYMq5ELlrDCcVwyXcj8B9lJ7ZbsrmiwChbEIGrjgRGhSI+f2+MTalWm92qYOjb
         DO9RgM4qqRSO+Tz4Sb3Rw9fVYwj2Pmcnr5o6ESm26lL/ociT2e7xy1L0c5lGMEPimTU/
         /E7Z2GNqvagVZIWx74kR4US6+SsU1nr3pvJAXD05sPwBeg504wIpg8F63vz5S505wpFJ
         clA2vRsDEANVkG8XkgWiLPKWhwZax0ZGnywAlKSSMsvzOpYBlA/L0/c7pZ/i56RFMH9C
         3s1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=RNlnjOlT;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708371442; x=1708976242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hRLyAFd43N8P6HZLXH5W6Uq4qLizVruOJwJlEkD+3iw=;
        b=dWKKy7fO1+uZW/0TFJx6j2FmwmEynqItBdMgjsU+r0mr69/hxF5NUhK96d1GgtA5fw
         bU8whDZgiNIpvq7baWcCrYTfmYx8MF3Y5QfRzds1dN/yDLMha//zXpu1JkuO+n9gqHPm
         uzeQpsOMog3cy4DKfbnmPh/rcf/flVSGYyx4OmDn4rdl6nvLNuVrr38pG71IuS+BsYac
         74IMn12KGaIF0CTsQOYYl2hlpnfiQsZtKMxXym6MX8PcO8dOlP9PyEEDzHQvZUTVGLt9
         DNAZJoGlBDAu73A03C3ZvUATassgtEuKSl08Nwb7XRQS6ZIm6A5GAJDPsAYz/QOqNDLp
         Rokg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708371442; x=1708976242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=hRLyAFd43N8P6HZLXH5W6Uq4qLizVruOJwJlEkD+3iw=;
        b=liqgpbAiU6zZCYGE2VyTm8ppSh0XZyknal6o9pk1eEl4OFEYlTDlj890UUCA0WQchc
         IKxWzovtIYwIjkGMBw34nkWyrXO8zTHZFsEPYRPZI2BqrbhXqUzrmhj6cNfhL7cJPRT/
         HxSsdvJJ/o/nSz/0/wBVcVDWn2E71tnldHNygwgrj+UOjoT5JPx/DZWdTzctBvTBSolv
         FhjzI2cGokdZ3JhzsQxSD/LLrIezxWNEy4TG+UcQlR+vtZSG/yjVsaCR5thGI09qZ3zb
         CauAR/JY7dQ4gJlYMcAmZcW1fVUe1+vkxrv9yGdrt4WPmD+FWOr1Y20dxXHbNH6SMqTC
         OZIA==
X-Forwarded-Encrypted: i=3; AJvYcCU4xvb9XzCcYIUfJXZ1eGJXL0is5SgX8L8umQwWUJcWnvV2tV2x/HugsMAzvcg055Oef3xpeMSo23Kgz1YbPWhvE8CjC6BxWQ==
X-Gm-Message-State: AOJu0Yz8Voib9pAZrJPWYBed34FcT8BVDrrQ2UMiYy3ma6568K1BNiSE
	3kEndXK6hEMXzn2S2ejIy4Wu2NLuEVKfR+yl9uayVbifsLfzyDoC
X-Google-Smtp-Source: AGHT+IEYQF0gcHmb/kUwX/AbJcVz1hz665zPCvm+zpuPvD6q3MqthwCArB0x+flE4F9PxCZ+Lzeixw==
X-Received: by 2002:a2e:b0f9:0:b0:2d2:43ce:4189 with SMTP id h25-20020a2eb0f9000000b002d243ce4189mr912808ljl.42.1708371440996;
        Mon, 19 Feb 2024 11:37:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e85:b0:412:689a:1c6d with SMTP id
 be5-20020a05600c1e8500b00412689a1c6dls515402wmb.0.-pod-prod-03-eu; Mon, 19
 Feb 2024 11:37:19 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCViLGISDLWkZfnvC7XOrsCRLyE/hB/+VBl0DWn1J6s2ESlJaDFlsP1GuFbrbN6Wj1CE1fA3wnboe0NgwIoxvcO1sbV8mInwOxCRLg==
X-Received: by 2002:a05:600c:1f81:b0:410:4a4:6cd0 with SMTP id je1-20020a05600c1f8100b0041004a46cd0mr9837997wmb.33.1708371439003;
        Mon, 19 Feb 2024 11:37:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708371438; cv=pass;
        d=google.com; s=arc-20160816;
        b=CiJzK4S1tv2IIf9hJ3qOnjOhviywjaQnOtkViwt+dKPdTYclJodZb6+Usbwcda5Y8q
         lCgFCB7Isgv23/ueGZlHwBBgjwPB9IzniwkfcApVqqU1olQtNLyhVyYNvGUoAiJNWVRa
         IGTja0t63tXO9NluPxdtKM8dFTxCyyKoKNlYv1Zc6PWz4LyLdRvCH1Tu7/lMYBZpKtSV
         IAsN39HbxuW7/qxERMtpYFNIII56hlOqWN9mJ6rEqz2JGObq/JQuThi4vEmUxnBSnSGk
         fSF2Z1cRPYgFepIemNU3d04OJjFYUzUzvjAuVNG80y8HVTMkVu1uWdHQVAYf3a2Y8nvc
         0aRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=m2Z2mvMuoxNNdwhEPust+2q6gJFIpi+h/Ujzq+0we7k=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=HtIvdD4VYYtoU9MyhF3Budxg1zt58ZPrn1BHeL0DzFTTdEtyw/e/6nFzr0sW4HX8tW
         //ElqusGivBwPED9XoWan7RGNdqGIatsYAXTBRk8RuRBrJORKjjROohSchsCz5rB+FpT
         H8quhtain/8WG87243mOlALQmMEX/ZQvDgtwsScTmvQC1TF3MaDHHSw4TYFUKkOasGvl
         27Y5IxeIb/SMNmubXxI1w0VVzM1WpBgNaXA8cDSEkBHb6kkbY7RhjRjYnFoc/anWZ5ni
         /Rvd4fvhGIt1Eo74CUZZp9RR1vh9650wxzzWfj0/QSlYsufK5bCBdwlCFOHe0FXXbH82
         nryg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=RNlnjOlT;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on20701.outbound.protection.outlook.com. [2a01:111:f403:261c::701])
        by gmr-mx.google.com with ESMTPS id n25-20020a05600c3b9900b00411c092ef0fsi305602wms.1.2024.02.19.11.37.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Feb 2024 11:37:18 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted sender) client-ip=2a01:111:f403:261c::701;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=UBvhX6iuOwLW//FlRPFZq7AKfNh3xrs2i1wQfgGkeb++14viNhuBPbUkEi2Fv7URHkQtiifiYGTz9ZbumOzvXFkSx42MrGNfkrjLtJ1VobKuoha6eZGlaa33hqdl+I+MtigYQOpkCh+qrZ/F9DHPQ4JzP8KcAAY/ERf9EhN+B5bmWWHiBbMcS7W5jwkY4ucBwURsnYwr3rLggBqXEKH9tG4p0TBsCgFkatQsHZJVDqawbuVdX8b0Uqlzf0nfuuwFFo0jdHup91ybA0Tf8It64AV4HayA50M8XW9tCANULc8idmnr3P8KwevFYxWqUXj3bzRCTrWSRRQdTzI26+SIug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=m2Z2mvMuoxNNdwhEPust+2q6gJFIpi+h/Ujzq+0we7k=;
 b=BCsRCBCfonic3fJHHCrL5LUrGHqoInlMcO7M9zaz2bIuGIuzNPv9KZyGFLLNq6LrrAyDpj1avGhqUmiFlXRREq6zGg6PCMyU+8fg+5MhSYhf00CencW9vIOZkyG7sudpHn5vrH5Ky4na4C5Ky7bnqPAo2/wrWfekSE7dBbnE4P1Tq5yiyk2j40mRrTpQZywKnlN1+q6GJTcsodSLWrFOp+wuQjc1thPYGNWjUknvPUKk8GYL4DRrRgHLT31ZQ1pgu1s55YEITOrhXqyIAOtsBDBoXE6a+PPJPv5bihl73v1Dqw6hrQU57uVpV3sowPnd39RpKUsafUyHCCeGHuxT4Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MR1P264MB2980.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:3d::7) by
 PAZP264MB3087.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1f5::20) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.7292.38; Mon, 19 Feb 2024 19:37:17 +0000
Received: from MR1P264MB2980.FRAP264.PROD.OUTLOOK.COM
 ([fe80::91e3:2737:5a73:cc27]) by MR1P264MB2980.FRAP264.PROD.OUTLOOK.COM
 ([fe80::91e3:2737:5a73:cc27%5]) with mapi id 15.20.7292.036; Mon, 19 Feb 2024
 19:37:16 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nicholas Miehlbradt <nicholas@linux.ibm.com>, "glider@google.com"
	<glider@google.com>, "elver@google.com" <elver@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
	"npiggin@gmail.com" <npiggin@gmail.com>
CC: "linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "iii@linux.ibm.com" <iii@linux.ibm.com>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 01/13] kmsan: Export kmsan_handle_dma
Thread-Topic: [PATCH 01/13] kmsan: Export kmsan_handle_dma
Thread-Index: AQHaLlLqGF6G1r00j0eFh2nARNDtb7ESeXAA
Date: Mon, 19 Feb 2024 19:37:16 +0000
Message-ID: <b1b0e05b-099d-4667-a54e-16575e83a327@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-2-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-2-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MR1P264MB2980:EE_|PAZP264MB3087:EE_
x-ms-office365-filtering-correlation-id: a97c7e72-7100-422f-93a2-08dc31822e23
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 8tHmjJKJ23zxmk0bQaw9oTg9PlXz++Yn6JmXIcgU+KuNA1ATZFYYnbLgbygnDvJjqIlZpTMfcNVIN4DRSwV2F5KaupzzVUjSvDVKtyko23HgmkqizFcTJyx3jfnBs8OtdJqEcXpxABf2+J8m6u8zIiAj+3jNfHIa48WfDNcYOZuLM20KolSIEAjot4HDi+ZHrAPOps9wS15zdnWkXbporXZZCdOdUolXE4VF8pa9kG84n5SZ9ZuoVdIWPunA9vpj1v2e+kFhdpdsllwf9T/khdJi/WnWKfOxRMdJ2uoqREhjpHzDHhrca2Wva8+6HbHdY/t7OE75y9wFyGtfbVTwuLAPAmuKZJQG1F/7zYGhSN6CY7H8LySBEw/bfYnXCp21qI4j+aNCzxlSfJyxbacYmyozDxYLf+wEloctz+/yNg3h7hpFD7at4nlDV5+tv1pTKFxUuxkwkSPgBHDP96966KR6FW6UjYy/hp0fwtJKt5gL02Adpua75NibXAxyW8ZVrw1G+3j+B+ORpJSx1cX3wTYPLyHbYA3VAZSDt8Sbm5DYwUFT+vU4LLHw9sfUbDUVVkOsAC5hpJPH8IJuMA/5sCEEcjKF3VXrcmGyZ8fDxDhD2cQVidN06sIWso737Xls
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MR1P264MB2980.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?ZWtMRC92M2tCL3dzQ1I1UFFxU1hQK242dVBXclpma3RGTlM2WFpBOFNMS0hx?=
 =?utf-8?B?eGtsdnJydDMxa0k5VHk0TU5mZnJFcmdHUUpIY0hNZFUrb0pYRzV3aWtpKzNZ?=
 =?utf-8?B?VXc3YmRQcFVqa3ZRVGE5SllhY1M5czhuWjNCWC9nOGR0c016YTZZd3FQYzlK?=
 =?utf-8?B?V1RpRlAxaExveitKanFRT1FmZzcyUG1wb2RoaGJXWW9yOUN0Z0t4aldsVXN4?=
 =?utf-8?B?clBGb1d0SU5PMzl5RnlpK0RhNzg0cHdpd0dBam8zQ0RNaUwyY3dRLzlydFpy?=
 =?utf-8?B?ZzhhMXhzS09Cd1B5NnBvc1NKeEZWUWlCYzRwdDY0N0hFdTZPRHZaL0EranhF?=
 =?utf-8?B?NTI1T3NFeFFCM2hlT3UxbEJyM3h4Slhsc2ZPMzgvWXV3bGZTZHp1RHY1UGkv?=
 =?utf-8?B?aEFXdVVDWmM1NDdhZXl0Tml0VHFuYnZFYi9naUFWb2VVcVJKV0cySmluTzNQ?=
 =?utf-8?B?ZW8yRGRZeld3RGlObXg2cnExTUJuaVhBZWptenVCMi8zQUZXeDlZcEYzQlNG?=
 =?utf-8?B?d240MEpaM1hIY1JPSXFTQmZwMzhmbi9LYWdxR3lzYjhlT1VVaERDcUNWOWNy?=
 =?utf-8?B?QjNXem1DVHk3U2pVSXVVMmV5czlXSkxhbm0xU1pZcHAyK1orM2Z6dkVNZUR6?=
 =?utf-8?B?bk95WmgreTRicUlha2JqYU8xd3hCQ1NldDI1d2xXc3B6QmlJb1hrYU1iRlpM?=
 =?utf-8?B?MGJ6M044Ym8wSmFxcUszdUpPQUlhajdNMW8yd3NBSitkR2hZa3lwdk1YdUxj?=
 =?utf-8?B?NzgwV3NTNWNmUWJNM3RiNmZaRlpZZFMzdDd0SFU3Q3lqZ2hwNExlRHRJS3lM?=
 =?utf-8?B?WmxHMWNuazQ5K21WdXdzSXRpeHplWDNycXMxV3BVMVVDUDlEa0hhZVZOWDdw?=
 =?utf-8?B?UE1hb1BIam4yaUEzSEY1ejZtUk9xelhxMmtFaG1zN3gwQjNhSUZUaGgwOUwr?=
 =?utf-8?B?a1V3VWxMUUpEU2t2UWMvSnU4dlpsd25kck1sUnhlUFlWVGgzZlppVkYxVTg5?=
 =?utf-8?B?bGkzY0FRc3JaR1E2QlJmdGMrYW1VTXhWdzU2L3YvMTZvOUlLenM4Znhld2Mz?=
 =?utf-8?B?TmlTOU95UUMzNU1qNGxsUWNDdW9IK20vNUQ5dTNYdGQ3UTFEdkxRNjJPQ2ZX?=
 =?utf-8?B?VHIvaXgwd0tiM3BZc1M2K24zQlJNVlllQlVURU5vQndsT01qK255OEhOQnJG?=
 =?utf-8?B?SXhJeklkT0QvQVdOeUJoZlNWazhSTUpDMjR6SDQxaWRjNXZ5WC9LbmxCZi9Z?=
 =?utf-8?B?M01XaHBHcnVnMnZOOUN2L3lQOXh3ZzZ0YVBnTE1pbHRULzZ2UFRDcG1OUTcv?=
 =?utf-8?B?NitmeGViT3FSOFJiRTNYS2plQ202QnArUmQ0QjFOc09JdGF5enUyYmRGZmJl?=
 =?utf-8?B?bkhKZUpnK0JQMk1rOFZnVnVrZnBEczRaTm5ON1E1VHZ1Zjh3Wm5QV2M5Ri9z?=
 =?utf-8?B?YkMvc0l1aUQyTEpDUWxOV2dBbUtQT0xla0xPVk1mOG9pVEZ4M0R6cXpGOGt5?=
 =?utf-8?B?WkYxVWhOc3BEOVRHbGJQL1ZTdnN3SkMrNnNmZkpaUTQ5Rk9iUlpaOW9hSjNt?=
 =?utf-8?B?Wk1YYXh2OWlpK3M4Tm9LTCtWVUJxdnpKTUtlOG4wRUg2Sk80b0UxeWtpdU9h?=
 =?utf-8?B?VDBVeWkzSnM1YThVLy8zUEl3dGUrZXk3VW1PWk9BYXFRL1hCRDloU2lkdVdL?=
 =?utf-8?B?NllUUEJlZ3F0QlJCaG1tM0V3VGh2QUZPbytLdXMycFhmSDJOZUQvRnpnVitz?=
 =?utf-8?B?MUQ0YVpienNlUG1FSlpnRGFqcTRIUjQ0bHBJb2wyWWFiTnFkZHdKY0dQU3kx?=
 =?utf-8?B?djRDT04xRndsdVJ4cGhmS1lFSGRQTVcwcEowWnVqMjdaaXo3UWhCL2RVV1kr?=
 =?utf-8?B?UXRWOFNicEZoYlczWk1UNHozSkhUZ3l5aVJWTUN2YzFSVGFpMEZyMmU2QWZn?=
 =?utf-8?B?SnJrWGNyRWxJVHFLMVpPbXRhWWxyTmErelZlVE9MVWk4anNRTHpUMS9nUkc3?=
 =?utf-8?B?YUlGaVFhdi9MT21naFQ5MkprM2ttckhiTVQ0UGNId3I3TUh5amlBUjNab29G?=
 =?utf-8?B?RkdlbnBJLzhaSU5tbWE2VGtjR3pXNGQ0bXJRVkNJN2Jia21yUlp5aTQrQnVq?=
 =?utf-8?Q?Mck1xvAeHXUZg3tP9kUiCZ5eh?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <6DBF264256FE114EA010ABEBC0F35806@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MR1P264MB2980.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: a97c7e72-7100-422f-93a2-08dc31822e23
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Feb 2024 19:37:16.8810
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Gd5KW6zGeEGqGUf3ibS/n55GuppiX4pX0xwc+UisJX2D3wcYPAbDMo9XTb+qS78dkZmDVm457x46WnEv8j4soZLEdO62fJXCvwJcoToPJq4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAZP264MB3087
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=RNlnjOlT;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f403:261c::701 as permitted
 sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
> kmsan_handle_dma is required by virtio drivers. Export kmsan_handle_dma
> so that the drivers can be compiled as modules.
>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   mm/kmsan/hooks.c | 1 +
>   1 file changed, 1 insertion(+)
>=20
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 7a30274b893c..3532d9275ca5 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -358,6 +358,7 @@ void kmsan_handle_dma(struct page *page, size_t offse=
t, size_t size,
>   		size -=3D to_go;
>   	}
>   }
> +EXPORT_SYMBOL(kmsan_handle_dma);

virtio is GPL and all exports inside virtio are EXPORT_SYMBOL_GPL().
Should this one be _GPL as well ?

>  =20
>   void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
>   			 enum dma_data_direction dir)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b1b0e05b-099d-4667-a54e-16575e83a327%40csgroup.eu.
