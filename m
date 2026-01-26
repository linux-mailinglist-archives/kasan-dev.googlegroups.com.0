Return-Path: <kasan-dev+bncBC6ZNIURTQNRBEEG37FQMGQE6AQHRWI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6OGlCBTDd2nckgEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBEEG37FQMGQE6AQHRWI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:40:04 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E9FC8CADC
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 20:40:03 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a090819ed1sf30503975ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 11:40:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769456401; cv=pass;
        d=google.com; s=arc-20240605;
        b=RUuhd79ZESFtG0DprKKnE+xSnyqv2RU018Q/tPyYAiUOUJZmlcogLyyJf/4oY0ic3R
         oZ/JN4qgTJv36g2+BEHh3TkwrCkxoAha/wAfCKP4ioco08R70Y8G5NjH1qapVA3/Oabm
         gen1+Ro4es6pVb43+joNi7lhbg0aqIkORvBUW5TRTQEfa797DlG5WTH52Xys5vl6wR4P
         hHzAO/dK/Zk1Fdjzs3pqU6xbJhSmH16LpamO6gUp0C9DgjJ51rhItkIhSbqtRT4PCWTQ
         b064/7rdJYjtdGfuGYUfUcXql+UuuUQG0NTSpsoCmE215KnDcG1RacOWHHH9JhtZl97o
         /tbQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:dkim-signature;
        bh=EdTxlqL6awFIL5oIPdxAaq0s6UV2zFN8iiGEkmfgVGQ=;
        fh=5tZ8iLvXb11ZxeL+AgeuTPAObXpjKI11t1AddaRG1cA=;
        b=j7sQHKYL3vZySLoaYOZRdwJ4Gml7OeQmzrawrDio53KrWViQSQpPnHpQeshLUbcaSe
         Isv4GqyrYRJ2lcZkZe9m4J/ec4NLXeULA/4t0V+ibmFaYsUd/1fz2IWULAi4SEUOnQ5R
         iif5d0oQQVfzoIw2LgE2tX2XR0aJFxDQZ/XXakEJJP0cJiPEMwEF+0WWMESVCTIaS3Zk
         3OYewHpLCj5wPV2J7QZTTgAkIuetV9uEMvif7rZ5n4UCLwJN8G8l155h4wfnKeUbssHI
         tU7R6XONpUFW8jH8wdM+HVMFX2t5HrbWDgy3f4O1kxChJozKGhmv1zzqzOmSaW1nbNyZ
         Jocw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=FKXtJhsB;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769456401; x=1770061201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EdTxlqL6awFIL5oIPdxAaq0s6UV2zFN8iiGEkmfgVGQ=;
        b=e5fJqnLYxTok1UlWjwCjf7dl2jAcKBMqpr64g0odQzBCd2bwDR1tdmuPTk9bdYiMw/
         WHlDkKw0GoBhOZQMPiy/wA3AFT3XAMqF6u/t2qR5nghC0lp9QXfjQsYkavzJmS9SxxwJ
         hNRjMFzLBAv5l+lKAzm7kaw/FxmIJA3SH501mihyyMFRX01kd0G6ecwdOS9sZmwuqzui
         USr9eYaStCqLwc5rN1fU4KvijCTWH1wwUK5TwHn+Ckb63heI5tApcGdF0MAP+4cFNRT9
         UXHEUd7PaHu5KTs1UxE8aVkDQe33MY83LuG7J193Mg+gRw90azABhqNKD8DCYPEikzUj
         OQKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769456401; x=1770061201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=EdTxlqL6awFIL5oIPdxAaq0s6UV2zFN8iiGEkmfgVGQ=;
        b=PcNUy1U/EEzDknQ1aIucmEDF9olCvr+XBlGPJnZS511lYn9v03KRUR9TDrz5rpjcf3
         +XzTkMI1pm9W3rRuA7MBjHLI2EusmXKTxZmgmEM9mcDNKVUwd4gY2OAUwWstZ9BJVz7I
         HwOrhn4mouTcu30T8tJqUqNmCF1Qk3D8FLtEbkAHgkZUfPfwUk9b9gFBwrgnG6AC2rE5
         tnbrWdWo/r8qtJmBb9HTwUiOJIjr6KZFVxTAN/VRqqw9NhsLvn/6tCbADDDs5Wvya7OV
         DfHjpJ2UUez/Q47EO1fcbmYcDAN2eMaH1guFFg+0rX+QPe9hY2OvZpa2yo9NeFggZDTc
         SDaA==
X-Forwarded-Encrypted: i=3; AJvYcCV5hLb+34Xh9ZLDL/DmBBnmCJGTq+2qEGGxKgdoHI8j7MrcUm7PS3R9oJ6XWtIfx1Kf1maLZA==@lfdr.de
X-Gm-Message-State: AOJu0Ywq4VTrhgKt2IXuBtuhEDA133QclfcjLKMUnBZVJ8+xd92OjnUJ
	W5SVFWLR51oc9gJpVJkarAaMUmHNHl0ywJYz4/ROALaWi3C+ONUsMVlz
X-Received: by 2002:a17:903:1a2f:b0:29e:c283:39fb with SMTP id d9443c01a7336-2a8452f2951mr50648775ad.52.1769456401294;
        Mon, 26 Jan 2026 11:40:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ELP14JDo230/ks1VAqcHi2Q/yreCJKaFFV7dnrH6tYVA=="
Received: by 2002:a17:902:f0d4:b0:2a7:51b9:41ee with SMTP id
 d9443c01a7336-2a7d2f85aeels28380565ad.0.-pod-prod-09-us; Mon, 26 Jan 2026
 11:39:59 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVKlN1CCXtYFTV+X658dGPA5YDJDLQFVYpcvUVp1U5krjTIB8Gswd8iADayuL1zNdH7SM29yU/5txM=@googlegroups.com
X-Received: by 2002:a17:902:ec8b:b0:298:4ef0:5e98 with SMTP id d9443c01a7336-2a84530b188mr50366055ad.56.1769456398900;
        Mon, 26 Jan 2026 11:39:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769456398; cv=pass;
        d=google.com; s=arc-20240605;
        b=PboKpbDLHiliKSWysSuGX1KKG3djkwqxXwjqMseCPpAd8CXBMk6pX9GmwOZPb/2AQK
         f7XFTqTCGbSJaqQxDqg4sgnUsvRCEB0qgdOHPNL47id1IILwxxm+SHuz4gYShl9UhirZ
         WvfnGCY96FYAcD+Bx5JAi1+0/5I0vFmXgvAxi2Aj7GV0cIlPHyDV6L8oFhUhZoPWPsZn
         msbGfPpIf3qQX1LmZwJ1EDtPvvwQkOaK8ie9evJHy987xPTg+er6hhem/riUkN9Ird2u
         NkU1qK1nByLN60jCqsCCPLcgRwOo75zu3BwVssrs8sghD11g3KRXobO1nVU2RrphvlGI
         haQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=qTm+nLSvmMclimXTfu+R9JRdwakClT9lDrQVQtqktzE=;
        fh=UICLlqFaIkmgSdjymDjJZBWOLpy8EHLC+RJWXvqbOGk=;
        b=HwNPzf4m9JNwqo2lRJLR+wspbDkqY20djdIfgMzfv+3xbHa7xyHjKYrI53VgQmuPm9
         QJrPsgQ3qjF8HZ15FFgqvg2cL2nD91fCFPgaYB9gLgz7U0wF6X5vLc206wCUHhZZYxhA
         lpnCn4EyrFZiYCkpawM6rlYNQznsSOBSfc1AQimjd5kj2143xAow0u0ZvHn6qjHQQR2K
         xQxkjC6Mb/WIQ4i2FQidcGt1j0kZhMOX8fHbmciGTTuL27vM60EYBPCh4mZq5Skh25Mx
         p1xFUyW3qX1qZJQVOqjLwummjtwvb29WoLAdgd/jg/GR9JCJwRPbe907yaqNpLKW9Vnh
         4GcA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=FKXtJhsB;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from SN4PR2101CU001.outbound.protection.outlook.com (mail-southcentralusazlp170120001.outbound.protection.outlook.com. [2a01:111:f403:c10d::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a802fa264dsi3340715ad.6.2026.01.26.11.39.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 11:39:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c10d::1 as permitted sender) client-ip=2a01:111:f403:c10d::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IvoduC1kRVOIb/mQzCDCCFzHLmeKuVdLwiVeqEEXwy2GdtkQZVbYAMkmzHG29YbO8mz3se+nDvBzR9yRsYJrCckSvhe0ZR4enBuuzXkYXn0HnfB/uyVzgoG74sYN83Js2b7wvwmHehvi2ahjTpGy+r0v7uL7ebZaej3bFpgMRF5vEWwQ+E2ucZsrVaMD1ygX/CdZvk4Ovbn5g/CFqKftpDNZGo7Yv6tJkiz2ramxYbFJTgvZKmDshuJ/YgkCF55acYOdHZJ7/H2/HCv5hDLBLKJNWB2yznDXfDp06DqM06ku8P3GsEBgwPXRzC1XfajmuT4bmE4crkifftamncrhag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qTm+nLSvmMclimXTfu+R9JRdwakClT9lDrQVQtqktzE=;
 b=cb0fA4MJ14YTfMaNCPj7JNjixFyva3y97Tgdi8oVfT73S6dOwFr604jkUaH5uai5fU6g/RDXAAodByK2jxtvuCKX9G6z0dSMrm7PbBlvwcqIgQHqjhaRoWqKXSyN2iDa7we3SzSSLXMyz5w8kxdUqHgsnlpSHogXgvvZxCf67iVInAm0CTeTfzNOA5zDLFpBP4NGdIglP55uzB6w99TvF/nLjBbE7eKoOUxGE6auW0wPJVzaU/urhg/p8O+CaTOjbO2nVi3eV7ljOZ+4DfKyplU0P3BfxDfSN0YG9+GEZkc0FJimy04rMuIEcG652kgKmv0/fg/ltsTXsMuMI/FA9g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by DM6PR03MB5113.namprd03.prod.outlook.com (2603:10b6:5:1f0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.16; Mon, 26 Jan
 2026 19:39:51 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9542.015; Mon, 26 Jan 2026
 19:39:51 +0000
Message-ID: <062eb8bd-3d98-4a0a-baf4-8f59b7643041@citrix.com>
Date: Mon, 26 Jan 2026 19:39:51 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
 LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>,
 Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Ryusuke Konishi <konishi.ryusuke@gmail.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: LO4P123CA0503.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1ab::22) To CH8PR03MB8275.namprd03.prod.outlook.com
 (2603:10b6:610:2b9::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|DM6PR03MB5113:EE_
X-MS-Office365-Filtering-Correlation-Id: 2fab5a24-b747-435b-02f1-08de5d12abfa
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?U0tFVUhzVXk5UFcxYzg4VWViOXdJRWFQdno3R01IQXZ0b2dTZDlsNnIwUzl0?=
 =?utf-8?B?ZXI1QmUyNzFyalp1clYxWE5OTWtEUjQveGlZQ2wyN2FSQ0RzNURWMmJZT1hI?=
 =?utf-8?B?MkVnTXlTb2k1VElidlRGdFBwTDhja29YUUhJbjRlWW1pTDJ4TlNZL21sNnVG?=
 =?utf-8?B?akJwQlg3eis3S3Z1bFN4R0gwS2pFMytlZ3dMeDMxS1ppWDBpYWR1M2ZqNG11?=
 =?utf-8?B?QWdDN0ZSRU8rbFdPWGFRNDdvdDZ0ck8wNnZKeEM4aXlWbURuUGh6MHFCa0pk?=
 =?utf-8?B?U0hheE92NVdDN3pUT0l5d3pGU3Q3MnpTNlVYVGFVcDZsZmF5L2tpbWdVNXZV?=
 =?utf-8?B?bThIWDF1alpKUnZ3bkRKLzVJbjU1eGc3b213S2lSU05KU2NJbUhFbWl4b2tq?=
 =?utf-8?B?ck5hZys3MW0zcVhVZmVSdDVWSitPYThPOUNvbWN4eGRneGdWL2FHMzZVbXR6?=
 =?utf-8?B?UVREV1p6dlJ2NHpMVkxZNjBLaGJrTEpYZjFFOW13MzdJUGZKWWVXWFZiNlA0?=
 =?utf-8?B?NWMzYXVsckJpdXAxbkVrb3MzdnUvNDRiak1JQVR4MnB4ZkJoNUNqZ2dxWm5p?=
 =?utf-8?B?aVRkSkNJVDFFREoreFlYbk0rSGJKMFVJaTF0cllDRzlXRUQ4Tm81bGtuaUlq?=
 =?utf-8?B?T0hCR1pqTFQ0dDUwRXVMb2svczQ2eDhYWGNsNjNkV1p6NjRQc0NIWnVLOHZz?=
 =?utf-8?B?WExLbTYzOGMzcWxTTDFXSHFMU0U3dU9mN3ljemppQko4b0RwRUU0S285bUpT?=
 =?utf-8?B?SXRiUzQwdEU5dmxxSnBpSVhldHJPbnZadmFrakNyY3JvNmpuTXExRFFRQmlt?=
 =?utf-8?B?SUY5QVo3Q0lDN1Jwdm92VytpZ0I0UTBnOWF2SUplV09EbFVMWkRBYm5ub1I5?=
 =?utf-8?B?UkpKN2lzT0F6cVNaSktwdDZTa2JGaXdNN2JOWEtVdHh3Y3hEK3JNK2Z3bmgw?=
 =?utf-8?B?OGYrdTBEUU1BM1dIUHJqSE5IQnNxaDdETi9DYm5lQXBuWVJaSEF3TkZFWFRq?=
 =?utf-8?B?aEplSjZkV2dhMC9wT0x6ZjdYQjdFcnlpeTUrMUFpUHMrZm9QUmo3ZVgwK2lK?=
 =?utf-8?B?VEVRYWp2ZjFhUXJ0Q2ZFTEZtWkpmb3drQnlTZmVBNmhEcGhnMWZzSjdCeCtM?=
 =?utf-8?B?TFFnYWF0S3FRbkkyVTc0ODhjNFFnbEF6eDVTYUlyTHhEeUVlc3UreDU0MXlW?=
 =?utf-8?B?dFBlN2RmeEpoUEg0OXh2b1Fmc1JVNXltSnZUVjJ4ZW5OQ2dmWlp5UStsSnRI?=
 =?utf-8?B?YnoxNzByS1liZnk1RW0vL3Z5cTk1clJKOVcwMHJmNmtmNVhqeEhvM1FsQTRo?=
 =?utf-8?B?dTRXOFY5Mmlrem9rM2R4WHY4am1YTFJTS2owL2w3RWJCREtneW9kZWNGMkpV?=
 =?utf-8?B?UU1WeHhMb2l2ZjYyc2NxNUVmMUxQQkZkNGJiY0R4dk9wbTMyQzUvQzNLc25K?=
 =?utf-8?B?TitxOS91U1BnWkF2blFMcmZ5RmtEMFZ3N1l2U2xqaVN5L1JBcS9kV09FY290?=
 =?utf-8?B?YmRQQ21iTE5LK1pTWXJUU2ZDUTA4OHYzR0pQNXJrQ28ySnVFY1dNM1QvR3ZZ?=
 =?utf-8?B?MGFHY2IrTmNtYjJQb1Vwa1FCa3ZKUW5WRzRFRGVCbUx2SjgrRXpnbEs3dDN0?=
 =?utf-8?B?TjA4M3cvNGt5YzRJTExhUjNrUW03VHN4a292eW9ybjBodjNoRGZmajQvYlFG?=
 =?utf-8?B?amM1YmdKTHdQNmYraDhqQkFaS1dJVFFubVZVWWNrSXFtNmJmVDBiblVWNThS?=
 =?utf-8?B?VXY3c3RkMDFWZDFDT05pUW15NENnZGVwelRvUTNweG9BeUQxWnYwK3EyMWpo?=
 =?utf-8?B?a0FHbVZqTnFRTUNJZVdBVXgvTFZqaUszWEJpaC9hT0x5ckhnK0pXQUlqYmMw?=
 =?utf-8?B?WXBsTkFXWUFQRCtIVndIdGRsZTA0bGlJWHh4bE5PMitJeW1BUk9HZGhVOWVl?=
 =?utf-8?B?ZFpKdGsyYXRSRWppK3hGSFNCYnJkWjdvSVVIQVRQdHlrR3JvaThjM1ZqUU9C?=
 =?utf-8?B?WnhMMXJaMGpzRlEyTWd0S3VKUXRVZi9LbXFYbGhZbGZIdWRVVzgxd1dlZC82?=
 =?utf-8?B?OXBlWUNGcnFOdXpkVU11MnZqcHZrTmF2cC9UUGliMDMyeGJRc2UyU1kxWXdX?=
 =?utf-8?Q?6h2E=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?QS83VVNlK0NGbDBkemIyWUZYYU1LOUk0ZHZzbzZZVGg1azlhbEVFWm9nWVdP?=
 =?utf-8?B?NUxxTUcxSld1dnd4R0dtTmRZRmNDYm5XeHhhbEVCTmdJaDkxRkwzVVpWVlBv?=
 =?utf-8?B?ckpRSzVzTU1IaGxqT2h0aVFsVDkyeU9KVUsvcEozQUNmNEwwOE1KbzFkSktr?=
 =?utf-8?B?M2NSU0F6M2NSQS83YlpnOXhrU3lReVZMTWt5SjFrMCszWmM0ZU82Y0twaW1x?=
 =?utf-8?B?Mk80WXdRV0ZqdGN3dWhaYjNyK3JDY2k0eTIvM3AyRHhJYTFReEE5aS9TUk1t?=
 =?utf-8?B?Z2lVbUNyYkZHRW1BNCtIT3B0b1F2bURqN2lkdXl5eFc3STRsSkp4WXpQZnE0?=
 =?utf-8?B?M3QwTkpMdkZ4emFyQ0RGTEk3RTdrRy9qV0svd3hIWnN5ak1vS0QrUGN2b0lv?=
 =?utf-8?B?Uy9XaE9MV1dRaWpjMkppM2ozTWNOejdpTjdNUEZCak5peHhFREdYRllMZXdq?=
 =?utf-8?B?VmUrUWx1aTVTd0psTVF4RDFzSm9kcll5VUxpMm1YblBoNWsrRS9EZk9TVUhL?=
 =?utf-8?B?cm9NTFRmdGF0eUVhWlc2OXZDVEMwZ3ZyK04vTlovTjBTRGR3b1RhQ1FYRUxG?=
 =?utf-8?B?RW14Z1J6eTFUSlBSNFZLR1VJS2p6cU11L3BLUjhONWlnY1FPREhPZnoxQkdK?=
 =?utf-8?B?ZzlvNnNES3Rja3ZqcTJFL05tQmU2MkZoTEYrRFhqMmlRNlhMR2tzOGtGSDNJ?=
 =?utf-8?B?czY5ZDdieUEraGd1QUhMajgzNTROMHNPNjdUMExwK3NTSjFtaldGMkVCbFNl?=
 =?utf-8?B?UEtZeS9zS2R6R1czZ0FwN0kyNGYybnBId1NDZTQ3NURuOUZnUmtuR1VlQk00?=
 =?utf-8?B?SDdmbCtoU3VGREtNdDVvNTZXOEpYWWM5NkZRN2NrT2RpdHNLdlhEbW8raWk5?=
 =?utf-8?B?bWM4RHhHUFFIZ0hYWDBkMzNYbEV3cEJhYXFxU1FlUmQ4enRPQWdwZlFmbFhX?=
 =?utf-8?B?YnltdXozNzNoZFJ1Z2UrNVlPV1o0RzhUVE1Ld1dhL2VVYndPTkNlWjRuTlVI?=
 =?utf-8?B?dE5qQjRBV3A3MlhyVzhpNFlxcE9YRGF5WWMydjlWT21nZFg0UTNiZlBjbTRj?=
 =?utf-8?B?TW9YcVlUZU12OTRZR2FGWEpvL1oxTTVmcjBhZ01zQ3V6T24rK3RXOGtoU2ly?=
 =?utf-8?B?YTJLa1FHamdCbU50a1hwR1JOZnk3RWpxeDB0M2hSaWppQXlFMGRNT0d0WUh3?=
 =?utf-8?B?enpXc1NVL01sZmxlYTJvUjIvSmQrbHdla04yMnVpaUY3REhsYVdjSmJiQjhr?=
 =?utf-8?B?K2dMME1ONFY0UlQ4U2I3Sjc2bDV2VjUwTDd5SVJwL1BldlN3Sy9CT2REaHNm?=
 =?utf-8?B?RkdyQjIzYnE2MWxMc2ZPeEdSdnQxZG9xUktJcGVDV0dXZWZ0ZTNNeitmY0dH?=
 =?utf-8?B?S3JzaGpqbWpad1oyZElwS3Z5Wi9OZTNZZnArK1QzOVg4dXNwVzlISVNmYWpE?=
 =?utf-8?B?SGFmWmcyY3hnbDEzWkFPSlFtWG9vdGtZczRHTlpFRjZOc0hYeTB0NC9ZZzYy?=
 =?utf-8?B?MDRiNDV6RzVFMVByekl3VGZLdzI2NEIzNnRzeHpqaWZMRzU1TytoanNCTW40?=
 =?utf-8?B?NVdnNXRVQ0ZFa2x6QzVRRlJHU0VwanpQaGN5WUVSaHJEV0RORTVyQzhOb3Jn?=
 =?utf-8?B?TUpmZHovWjVvUUY4QzRHQTBKb0dYaG0rb2trd2VwU1dycHlWMkprZkdKS2Jn?=
 =?utf-8?B?NmJxQSs3TVhNU1EwMng3ZVN3R0VxK0RJb05ZTElWTjRhbm5SbkhacktiamlN?=
 =?utf-8?B?VDBNdi9za2lTQUhGTXVFWHpNUVM4Z0dRM2RsSWdnNnErT2FwM0lHRkUrN3Vz?=
 =?utf-8?B?NnN5V2NoZTcxZWE2aFZkZS9TTTJoUW9EZU4xbXcvelF4cXlFY042R29Wa0xN?=
 =?utf-8?B?clp1QWFHbUw1U21CQ0JYeGtIVGNGT1F0R0Y3ZG1zSXUzNUZxQW0rNGhKeVNu?=
 =?utf-8?B?OHdwUjZZa2JZOW03Mlc5NTJhOEZibmtudmlPQ1pGUDNOLzd1Vmh6QnhuWDRn?=
 =?utf-8?B?YzlFOG9zUUJLY1RXR09ZU3ZZblg4ME0xRDd5MExFZEZiK1VpUDRWOFdTcHYx?=
 =?utf-8?B?ZUJabFVhUGRPYXBvdmF0VGNKRlluL20wcDRGVGJFcnNKZFNqYjVYMk5lSmhy?=
 =?utf-8?B?ZW0rUU1NRE1ybzlpRW9uQWFpcmh3amgxaldrWW9rTFc2YjA0OUdxNmtTL1o1?=
 =?utf-8?B?UUZaL2ZkeldSNjYxQ0tSZHVPaitFK29UV3BZYWFhaGxpKzFWaFZ1NFp2QTB4?=
 =?utf-8?B?TFVuVXNmMzFWUENvSjBQQjRnZHFPZE5Xd05TT0VqejhzM1RRUG5QRHZUTE1D?=
 =?utf-8?B?blMzRFN3M215cVNIUUkrUTlRSU9Pa3ZKR0pUTXpzd3hHQ0hjdHMydz09?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2fab5a24-b747-435b-02f1-08de5d12abfa
X-MS-Exchange-CrossTenant-AuthSource: CH8PR03MB8275.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Jan 2026 19:39:51.0733
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: uEYTA65ToATS596yypTXV6oI8qr2iZTG2hdR5GT/PlkdlzXVHbYLBs4HBylYi74O8RXS44UO26iYw0Aq1O3sns9VuBZSZrzD88td86iwaOM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR03MB5113
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=FKXtJhsB;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c10d::1 as permitted
 sender) smtp.mailfrom=andrew.cooper@citrix.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=citrix.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_RHS_MATCH_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBEEG37FQMGQE6AQHRWI];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 8E9FC8CADC
X-Rspamd-Action: no action

On 26/01/2026 7:07 pm, Ryusuke Konishi wrote:
> Hi All,
>
> I am reporting a boot regression in v6.19-rc7 on an x86_32
> environment. The kernel hangs immediately after "Booting the kernel"
> and does not produce any early console output.
>
> A git bisect identified the following commit as the first bad commit:
> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
>
> Environment and Config:
> - Guest Arch: x86_32  (one of my test VMs)
> - Memory Config: # CONFIG_X86_PAE is not set
> - KFENCE Config: CONFIG_KFENCE=3Dy
> - Host/Hypervisor: x86_64 host running KVM
>
> The system fails to boot at a very early stage. I have confirmed that
> reverting commit b505f1944535 on top of v6.19-rc7 completely resolves
> the issue, and the kernel boots normally.
>
> Could you please verify if this change is compatible with x86_32
> (non-PAE) configurations?
> I am happy to provide my full .config or test any potential fixes.

Hmm.=C2=A0 To start with, does this fix the crash?

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index acf9ffa1a171..2fe454722e54 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -67,8 +67,6 @@ static inline bool kfence_protect_page(unsigned long addr=
, bool protect)
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * If the page was protecte=
d (non-present) and we're making it
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * present, there is no nee=
d to flush the TLB at all.
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!protect)
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return true;
=C2=A0
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * We need to avoid IPIs, a=
s we may get KFENCE allocations or faults



Re-reading, I can't spot anything obvious.

Architecturally, x86 explicitly does not need a TLB flush when turning a
non-present mapping present, and it's strictly 4k leaf mappings we're
handling here.

I wonder if something else is missing a flush, and was being covered by
this.

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
62eb8bd-3d98-4a0a-baf4-8f59b7643041%40citrix.com.
