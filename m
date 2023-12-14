Return-Path: <kasan-dev+bncBDLKPY4HVQKBBLH55KVQMGQE2TAUL4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id F31C2812A7E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 09:37:01 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-67eaaae3761sf92934346d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:01 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702543021; cv=pass;
        d=google.com; s=arc-20160816;
        b=e7qr5E1VU6vSf4yMeP3SF2IEXo0zKjGSGaGGualcIY/EuVVnPZC4MbbCNl8Y77sRHA
         cvuBu6GUbbiMk3PLTp4PRbYUPLpqlJluXmzmN1HnOhtiKYhjiZmoJRAGrp72QWmMXrcq
         oqZuVzICB+Qm7+20OD3FQbDQ7aiWa2XC5aa3e415DE8L9XZ1a2/zrFBr8Nru7Ioa/dts
         Qb6/xyvTG77YYe5sR6WeFlaqYncXUCeDA+hw4vT9iRG8auxbVFLsIcWia/70360/a1OZ
         LE6CUEwD4+3fCOE8qkrU0HF4TRVIZ5A1DLfuukgFjxhi5wyq/zXI9Y+DWfmwrY4arCyc
         eqYQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=UwzPoJPTl7GgoDyWEz5z4dvjO3bcPITMUEuTJSjXjuQ=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=HJLLLevp8Y+R1QEDlhJfYb51MYnbPG6/Mw0j4txIRAJn3v0SnpHHKoOVFBUq13YTML
         dQWH52DQq4yEiUdTL0fO1727QIGLZkdjQ15tuJTSv7OK911QsJCNtsH7n1L3TR97r5fw
         xTvM4+Yxn46AFVEGiNWyP3tOgBE+Nml4mKJXTLANfYiDqFe0OvcghlHUtkjuhMuVjrF3
         L0P4AK69+KSXjiBofqBBq9NXbYiKDgpnIu/XYe8Ud87SIHIZIUbb/ThSEGjzl+r8+NgE
         132r0RJd+obYGAPBg89g9hqVlCmvVjX3tRHaoFvdMQU80roB8G7ljV35VR9+CNmYckHh
         T9NQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=Y7SW8rSz;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61f as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702543021; x=1703147821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UwzPoJPTl7GgoDyWEz5z4dvjO3bcPITMUEuTJSjXjuQ=;
        b=ToSpK9B6uwzlBbCZNFN6AKYjDRnWB7Z2Pi6aDFAhSMGRG5fwbkHYiX+P3OCtdgMDn2
         OEcV1BrRelhoB31bMjlQ8JqPcc99AtlZtiPdCraxi5uF20qMCLk/i8bMdC8TcCxAnj19
         COHVtgvlWPbCcLn2X2BmPYIB2dktu5w0NMH0JOGiGkxQTM2Jh1P/EDJA3awtiacAylvo
         B9M2Bjf+3woQBFLXAqfyk/zSFJLwT0cyFrWdFgZUwHrLO2vDiiGWASqvxRuRtWSBafwV
         ezkMJZ5zRbpicHfR361c2P7VGcVgmLEYJQYVjV8XDc6WzNARpEgByEJJDUNuauXKtyUr
         5MmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702543021; x=1703147821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=UwzPoJPTl7GgoDyWEz5z4dvjO3bcPITMUEuTJSjXjuQ=;
        b=K7yMBSwFzKpazFe8YPU3MM/LYMWlgDP2M0pbdkIN0ULbDj19JwvVBxUPBGUlYnruqg
         3hNRIM78yoDiiKaBOp4ylTGFELhenmK8/UTQE3MHJoDUg4UZoQrPripAsuTLr0l/vLkp
         qSu9ItQyJtga3m/xadHBJPzpte/Q8zlR46JXY9/TrxZ5pdnCAndzJUHKromf23y8sP9l
         JrA/V0uMrUmkREEQgmVnCsnM5Oensr3sLzo6Ov5f0Kpu1+mdGSyxY5opnaRe5S88Ga5J
         vRg4oJoRSY2x6bQNKP3BltjzNawCmTOKRYIFILvj9b1iIbkxvjXuxQ1fq8Su0CTGZdwz
         8l3w==
X-Gm-Message-State: AOJu0Yz1pa+oHvt2SmjVoqxoq7BTQZFk5w/9A2IsWsgtqF6Pcmuqqb5N
	GCtIrHfhjD2Ih11pzK96lA0=
X-Google-Smtp-Source: AGHT+IEpbjuTR721UiwZZdya/7/Gmy6sGIkQ1NNqL8EROb0MJQQpKp7GbZh1BNSV0CK2tQ2UjO/EBQ==
X-Received: by 2002:ad4:5961:0:b0:67a:a721:e13c with SMTP id eq1-20020ad45961000000b0067aa721e13cmr11995371qvb.105.1702543020905;
        Thu, 14 Dec 2023 00:37:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee66:0:b0:67a:1a58:78fc with SMTP id n6-20020a0cee66000000b0067a1a5878fcls4318395qvs.1.-pod-prod-07-us;
 Thu, 14 Dec 2023 00:37:00 -0800 (PST)
X-Received: by 2002:a05:6102:c07:b0:45f:3b30:9c95 with SMTP id x7-20020a0561020c0700b0045f3b309c95mr7084725vss.7.1702543020144;
        Thu, 14 Dec 2023 00:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702543020; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hyb7rp/8ZklJEiPUegdwkSQKWNqK70QitZuOSyJeJwRqpfjqY2qS0EoFi4zENrBqVj
         Gf7Z8iLOsdko2xPdQ2OcaDPJeE0LOye5I2feP3JEGhYA6dUdEWUlMUOKMnalARHDU4hF
         AsNgaBp8xkWP6PG2gUjqB5PZEoXMsU+S1mpJWM+eTozHiXZOVxVtuAsAVrT05tUfItJK
         DW2hua9mHWp8utkzECE72J4PVbGVz4w9X9yW+MB71DCvbaO6npcaXGImY6aEMi8zl9ad
         Gll9y8WlXA7zLyXV9SxR0zKLmvRne1ySrYCoWDrrMR7XNJcmoMLaX+MTSegYyfhB3Py3
         Re8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=NS3d8j/q2pm5rCgu8r63d9ByEtjQ/QwPpQkJ7ZWOuho=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=p5E+l8KyJTtJwbm7KUdXjTE82t1W+Y3+bYOhcC7s1IYGBdmeDkULtd5eak9z+c7oAP
         oLAmO65ZyKvPu1LvjdjafqxzTQGDb9K1A6Q0i4SB6pTXB8hfRA4lt3YZ0itDCG3fc+NN
         shD+l4JNWBrLaTA6W28aGGyYAKBeoCcC5PQ3IF5CQTJw9sUBvxHEBXwHQ77V059ryhmt
         DytApRsta38ZnVno7nyu6IFoxNHjgbhuAwVVgUisulN7E1n5qTLENS4g3wH2f+w4XG6e
         RC+7BsKkeoIAFK+si0jeMcwm899SBHJCuZuAO/UoBGdtOPlay/z3Q5jjOUUQ4w327syd
         1KVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=Y7SW8rSz;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61f as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on2061f.outbound.protection.outlook.com. [2a01:111:f400:7e19::61f])
        by gmr-mx.google.com with ESMTPS id s39-20020a056130022700b007c4705fb21bsi1503476uac.2.2023.12.14.00.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 00:37:00 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61f as permitted sender) client-ip=2a01:111:f400:7e19::61f;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Qc6Q3tGD6kLEorqOBALGc3APMhsiouaEcyZjlYvByKLpGJ/xWyavUL/eEfLRKG3BvDB9EJgTxagmFE30mrGb2J+rgZRUAu7nmgx5zX62lrU5fkulXMKYHHFbmJjfTxHi0sb75EarIp9PGrJ67v2zBrT91JWxHBUkgaBANw1xkW+SW9zuqjlb+FkDwNm2Ctr+2lBJVhuPe+LYlAgnghhZlEQYzkCOg2MYJ4dkbkqR0M8AGocToR1TKrINt4B/Zcq4mNKUJ8PykFtxNhHTW/tRwh+LiWqByYs5CwXXOWrvNSXy5isAND2haJWwUMIjUxwmntqDBLMLu4+uAOSWx/MbbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NS3d8j/q2pm5rCgu8r63d9ByEtjQ/QwPpQkJ7ZWOuho=;
 b=TmgiMKLaYjuppI7mIpslvlJ/GtATYcfmKWhtsNTCHPSSyM9pldTudB4+KqKgnNqYGyciWHeHgpEfRiv+JmGbDCU8KF5Ljh6bykb4nM0vpDutVqEINgCRrB4wrvdnG/DGflG0wR4mK+QVPn4RjAUppATJCOKsHtstFF9tMMGxVTFY+uHnJIu/W289kPLc5saAzfiifpW9xvdjRyIxbhu8ZjD+IgvEGZX1FXsXJjJsU3iMBv5NZmHFXWgwGPeVCxNI6UMlwhoLeaZ5Hh5SHV98nv2276PH/NCdxM0zPKxuyIdgpsZiOEYjAHfKWQQzFtfVpawJmeQOQm4KR1AOK3CbIQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB2370.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:33::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7091.26; Thu, 14 Dec
 2023 08:36:57 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 08:36:57 +0000
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
Subject: Re: [PATCH 02/13] hvc: Fix use of uninitialized array in
 udbg_hvc_putc
Thread-Topic: [PATCH 02/13] hvc: Fix use of uninitialized array in
 udbg_hvc_putc
Thread-Index: AQHaLlJJ+Qmq98QSSk65tBcfvtQ1DrCodL8A
Date: Thu, 14 Dec 2023 08:36:57 +0000
Message-ID: <aab89390-264f-49bd-8e6e-b69de7f8c526@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-3-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-3-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB2370:EE_
x-ms-office365-filtering-correlation-id: 789fd0ea-574c-4686-f86d-08dbfc7fd5a4
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 4XAnzuvBVDh+P85ZBeUGN7YAx3PO4U7gkdKhAofs0TPQGuMXQEfgeJnSPkyn8bo9+nolZP3UNJHBDA0X4ylgXXpLZKkIx16KyBxPcwRfkW4fS3pVLgKuI4twXXHWtWi3LW8J9yksOKBDCP23JNNp/Le58948tI+OkRu2IdyYYk2pjXmzAMZz3nThlrhoayIkRN51Swbz0Pih6b/1GMt1PkZYcAnP/V7IeQcUfYZakshb8NxSR6PzpRTQEfkPAm9wYaukSozYQvaKLfWjlD16b32+MP11kh9iVsmsJta6JJ+d4QiHFywrqvpfghNDSE4DAVyPS3sgcgXdtBSNK6V1B2v3N0sSirVgpNHhGU89XUT0R3FAgaKR50I+6f4YD1l0gZ7GPiClCwVhi35gat1mFji2cKuxgub/aDlyZwcNqgH/2bKh/zM5pk8Z9KweiVDQ8vOiDttH6bji4yju2990BRaz8aTnQYaFrv/pQoTe2hX4K3ZD6i/UXKuVbiTySz6VPkxDYhlw9q9rFBIUPNtbleMfvxpytlkgmrR7KJLDsKYYKJpKcCTLUNdMHwdiF0wOgWnXrq/ruoHpbBgUJk56grah+iNlwDV2swEeqR7eR/f/BB9QObgCTUsRXjTW9LjkWfY+SWqq5kPri8oIV7mWYEGdTU8q0ueUIqwBzNE+F4tNrJlyfUa0w9gZlnRZpV/7
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(396003)(366004)(346002)(39850400004)(136003)(376002)(230922051799003)(186009)(64100799003)(1800799012)(451199024)(31686004)(66574015)(26005)(2616005)(6506007)(122000001)(86362001)(38100700002)(31696002)(38070700009)(36756003)(83380400001)(6512007)(76116006)(5660300002)(7416002)(44832011)(71200400001)(91956017)(8676002)(6486002)(66556008)(110136005)(64756008)(66476007)(316002)(66446008)(54906003)(66946007)(41300700001)(2906002)(4744005)(4326008)(8936002)(478600001)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?bVpnalpXZWJhR2RmZER5Syt2T3p3V05wVGxtTk55NGkrU0M3WUxqcTJVZHNy?=
 =?utf-8?B?eWhvbFRwTVJ5bHNjRDYxOEQxZS9ZNmxPUE83Y0dnRzl0WkFvWE9FTlNEMTBv?=
 =?utf-8?B?WGNaSXNHaHd1QnpuWkN5ZEtRQ3N5M3RtTzArdVJVTzNQYVN0MUJvbjdDODNj?=
 =?utf-8?B?dXZ3ZDlSOVhCa2tPeUpBWFg5WCs2VVh4QVRzS3NpLzNURkJ3V1I2ODNYcFBt?=
 =?utf-8?B?aG1tNHRhRDJUWjNiZWtEWHFncVlMTjdhOVRibCs1NVBHOVQ4N1VnZXdHQnlD?=
 =?utf-8?B?TVdqK1U2WXdhSDJIMmhLSURSYnR0N2Eybk9rN3p5MlFNdm81NzdqYkZ1Q0xY?=
 =?utf-8?B?T0wxdlpmUzgyeThIYVpTamRWR0xPKy9VZFVmdjV2MEg0VDVIbFZZaG04L2RO?=
 =?utf-8?B?T1NJMnVuRnJEK1lFeitBckFiWmhuWmJwUFo2bHVzM0czZUM1NUhYSWEzM1Bn?=
 =?utf-8?B?TnFrbEc4ZTU4L21wU21kZ0FuY0s1dEpJcHhqcEFNOUdjNjljNHpOeGJEMXFR?=
 =?utf-8?B?T3RJUkpseFJzWktwK2U3NU41TWkveTdtbEljMVB5RklLVFBoQW0rVUJqaFhw?=
 =?utf-8?B?OGpxM3FpYXd2R3RwTjY3ZloxYmNFOEJYenVJaGlQYml6ZmZyTVNwelFhRUc3?=
 =?utf-8?B?K2FkUlFNOGZXT3ViZUdPbFYrZ2FxMjREZjdlOTk2VFpCNWRhWTMydG5YM3d6?=
 =?utf-8?B?V0d6OVJFRmdoSXYvdnRYL2M5WFZSa0hkNG9GVFRMNGVMS0haSWtuMXhLSURp?=
 =?utf-8?B?SzhvMnJYSXNCZ0dFYUpBSXNOR0lNUzIwR0ZYdXZqQ2NRMlNqZmU5VWNtaWpu?=
 =?utf-8?B?LzJnRnBMa1N5YW5ZWjVmQTIvT1dneEtEa0dKVjlnay9TQUZxTXZsTENrOS9t?=
 =?utf-8?B?TENaRnl1R1RtQVEwN25lR1JjMldBK0pYNVhEWDczNk1Qc3ZMNDVIb090UmJX?=
 =?utf-8?B?am5MN1BteGR5OHNrV1E1cG9GcjN4TXFVU3NvT3VabjZQa1UrOWFHOWs5aVBv?=
 =?utf-8?B?RTEzalNOYzZ4YWZjSE9Sb0hDdmlzbU94bmNvcS9ESzJlSkFLUEVIMkVuK0lM?=
 =?utf-8?B?R0svOEQrN1ZoOHZtVDZqUVYrOEdhMnlvMzBMRTV4Y05tU3h3OFJXT0ZyWjU5?=
 =?utf-8?B?aFlmd0h1T0xnY2luNDZvdEQxMzViZUlyWXZzWFFvQmljRm5WVjlMdEFpeTIr?=
 =?utf-8?B?RjhKVnZNeldVVW5uT0Y2eWFmV29LaG1ucU13NmRDWi9HdEVhY2pDdU1leWYz?=
 =?utf-8?B?ejRXYjJwQWhlNE11ZUlmSG9hVkk5eExCY1JQQWh1ZklNdmo4RDhsbkMzbXdT?=
 =?utf-8?B?NjBIRUJ6amtwd0dDTHpWYnZWMldaeWRYWkZ5T2RKdXcxbTk1Mm80VEtmQjBL?=
 =?utf-8?B?ZzBqcGx1RDNSN0VqVml3eVlFYUsraHBLUmJBUFozWGhnQ2x1LzEvc2IwK0dE?=
 =?utf-8?B?VTM1MU1pc3VNbEcvWVBYb2pLY1R1ZC9QWjVrRXM3czJYQ1pkai9jQnU2c0R4?=
 =?utf-8?B?R1FtWGwrMHRIckV3VFRnUkxFY1RqbFJGaW9OWjBYZHdmS0ZqTVB3QnFuVTlG?=
 =?utf-8?B?OFQ4eENlVkJIYVBMQ3dvYThuaTdLdmN0SGF1dXNpVllhaFpFUUR1ZGkwQ0ps?=
 =?utf-8?B?bEpIOEdXbm8xRTF6U00zSFRwMFVJVFRkMDR4NW9DV3lsUmlNUUxOTWVpU251?=
 =?utf-8?B?QlVwSWhDaEFYbEJtOUFxNjZEM2NWRGZlazdaUnBkb201Z0tkY04vdzlDNVRZ?=
 =?utf-8?B?b1dHa3IrRGpnVW1jeUJndTNxSWs3U3dSTmZsTjgrWjVhTnFUbmxrbWFyWjFC?=
 =?utf-8?B?N2pMNGxiaGZGSmZlR090L3g3MUpWTWRtRm9lektYbDFPSm1qempVS0RBVGZK?=
 =?utf-8?B?K1RDWTR3cWZzZHU2emUxNUdZUmZpOExvWkhpTEJ0bUZWNXU1a20renh4MXlI?=
 =?utf-8?B?OFovbXlTaXI1TVBWc3dRTElSaU9kT1B2TERQUC9BdVZvdS9LQ0t4WjFreWxv?=
 =?utf-8?B?NlVscmVyZ1IyYVVOOC9weEZGVFdnTDFHY2Y0NzZleVRNc3MvanlBYTE1ZDEw?=
 =?utf-8?B?L2VOd05lcUZRZTFIWFV5Yk9SQWJnNFhaV29HZEE3WHF0cGdkd3VDRkNURWl0?=
 =?utf-8?B?b1poR01IU1ZHbzBxWFY3R1JmVGZQRlBVSWVkZEcxR1JIT1Bnald1akdFOFNH?=
 =?utf-8?B?cnc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <729BB947E358D8408A7216C0B2179CE2@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 789fd0ea-574c-4686-f86d-08dbfc7fd5a4
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 08:36:57.8188
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 7+KqI5d7rnwmjPdLJAJwdm+fFfBb2XnPZyHM6mrmpdZv73hturKPjsFe6xwjx77942J3vXxCpZhCBlwVD1vs5e2H6AqXiAkhAbetJtBLyMo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB2370
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=Y7SW8rSz;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61f as permitted
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
> All elements of bounce_buffer are eventually read and passed to the
> hypervisor so it should probably be fully initialized.

should or shall ?

>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>

Should be a Fixed: tag ?

> ---
>   drivers/tty/hvc/hvc_vio.c | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/drivers/tty/hvc/hvc_vio.c b/drivers/tty/hvc/hvc_vio.c
> index 736b230f5ec0..1e88bfcdde20 100644
> --- a/drivers/tty/hvc/hvc_vio.c
> +++ b/drivers/tty/hvc/hvc_vio.c
> @@ -227,7 +227,7 @@ static const struct hv_ops hvterm_hvsi_ops =3D {
>   static void udbg_hvc_putc(char c)
>   {
>   	int count =3D -1;
> -	unsigned char bounce_buffer[16];
> +	unsigned char bounce_buffer[16] =3D { 0 };

Why 16 while we have a count of 1 in the call to hvterm_raw_put_chars() ?

>  =20
>   	if (!hvterm_privs[0])
>   		return;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/aab89390-264f-49bd-8e6e-b69de7f8c526%40csgroup.eu.
