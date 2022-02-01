Return-Path: <kasan-dev+bncBDLKPY4HVQKBB26S4SHQMGQE2COH5JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 81B1B4A5C61
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 13:37:00 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id c7-20020ac24147000000b0042ac92336d1sf5862322lfi.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Feb 2022 04:37:00 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1643719020; cv=pass;
        d=google.com; s=arc-20160816;
        b=sdL5sX2y/MYtQz439D2MvGzUhAAjqRQjxfkgI4Cn+bzLeZifdCA7+nKbQ/NjBO4oIt
         3NWFvIwD9ag7FVdIULTyY+BLZsUK0AtPl+8eZAIAchWMLlXfXwVcJmE14pJv7W67ctnq
         O9NjKwdJMKHLXkE5mQd/blRTzz72TXos4gNRoU3oHTG/3QqT5o8sl9rbO+DFLqOgl78Y
         29yNVKRIM3XzFTSpYDaDGH7iBfdh/LA7GFur0lgro3g7CynKKENpANVW8KgKrfXeBJkT
         PbIkTgKekEdgbpGorlqlWfpCunZu6eDqe9H/Gv8FUU8po24mZPX2/gRPPJyGKaOaAufs
         78FA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:to:from:sender:dkim-signature;
        bh=hNg3gceJn7q5Tx3AFWHRxQ0C2Ze+VgVEy6+QBtVnf+8=;
        b=tX+KZ1NlBPOZciXJqvMPpY6Pr2pYjF8/qZMGbqQx0sV3hOMUoiYsRzHqcPYse/0y+0
         ETDQjsNN5yggRB2mFcDrdgxe5ndDzCocV5upaVUP/W5a/b4z5Edg57cwC4mhjakMWnVS
         IGqdp8lnf99MdA6pzIlxYjcLkgCWPt2iK8YP/XsIxf14K1IhO4RpVed8v/LFMSGKR3fR
         5uAOr/1y1OuCjO1VHMuBgeYqgsBGJRFBShh8glsNChWdQR+9exOkuSF73nPN0rHR59nq
         qQy/XWGIt1xpjnC3+ZoqsDbw0guh7FHonI0DaZ/8FAlus61UCKFNfXURibRhfk78xtta
         t0Qg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61a as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:user-agent
         :content-id:content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hNg3gceJn7q5Tx3AFWHRxQ0C2Ze+VgVEy6+QBtVnf+8=;
        b=J2bEx8jGhpYgy6/GcokSDLExk2xEnweuLpqdMxszFyXg8i9/mRfa95fcaNmJqXBUqD
         QyMRdfT/mfxRMFwYNsWUApGE2uQnQ+m+jku2mdKJ2Jm+jlHmA5PkRGePsNc11qdU4Kz7
         pUOXYZi0crCdFnVbTPy05SLwSzLpDjnm9RhOlpZDBNCnsMW1LozyLw4h3iLTFxXyvkwW
         yz7wZVAYBL9EeNJ8qQ42y37GHl/+5nUB6V11rFTBiQZ1kxf9UIUfMkQ9kAZO92Ofyphs
         jWjCum3N6bvM+NhWOx9TY32krS2USh3+270gOAYURZtGew4KBTzxP+JRqN6YMHTawVPu
         HrcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:thread-topic:thread-index
         :date:message-id:references:in-reply-to:accept-language
         :content-language:user-agent:content-id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hNg3gceJn7q5Tx3AFWHRxQ0C2Ze+VgVEy6+QBtVnf+8=;
        b=LewZRBGOuLZFT1ESTOUMFFN4J8EjoqDK/qJtdFsRROJRjP4A6VPz6+b7qyiFpNAO5E
         cqBdCqjMvpFTMF3ps8e9eKR7pUiRrJb8GEu/e9VKu1j5k6Ar3xD5LVW32HD93CwCDDz8
         fHkAn0pJFo/6Lv2vkoPYhb1K3RtJZR7++8yluusldywDjKxeQkyIL/ycegPYbk2tnr8U
         Q/ClVNuJRycFG0kWcyxBPZRNMV6Y0ET3hUHFixzN2hBcqtI1h+SQdxKRFYzgNTzjF3sh
         omtLPwxpODXsqvx9ygvIz+HGRFxcWVzUBa+w/tu62Tv9AY+9/v0Uq9FlXeIL5lmTJXdt
         YQHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VkU+n31tgqY8hqy9YIV+jDa84qedelmEmy/EGOhLPg0wG3s5z
	sJ76HwhEtZts0QfGxodrs6s=
X-Google-Smtp-Source: ABdhPJx1tUrc4j9r0BG2KINM/1DP0Q36t10sG7REFzM0BU6a4EpELYh4QdSP/GK+QNuc0plq/4+XfA==
X-Received: by 2002:a05:6512:3403:: with SMTP id i3mr20398902lfr.342.1643719019846;
        Tue, 01 Feb 2022 04:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc08:: with SMTP id b8ls2107448ljf.0.gmail; Tue, 01 Feb
 2022 04:36:58 -0800 (PST)
X-Received: by 2002:a2e:834b:: with SMTP id l11mr16391298ljh.336.1643719018862;
        Tue, 01 Feb 2022 04:36:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643719018; cv=pass;
        d=google.com; s=arc-20160816;
        b=XLBIl2C9QReb9HcxGXflImikFIerkWiWQACJy0jdI3d5Emrk/acFVq67QBiy/ZAiTK
         oDZB15LWV8IFQ+T56mBPo1YYvCrPfy9cGe3QAfxugY03+22Dm/fnM3ABJdZq0cmCDEAc
         jHGyhxXnSW/7ZLX0vPq9JG16arzMchj6zoP6vWimRCaGp86TTDvSAjEChQXYzSREeUA8
         1Bxov29ucty0acI8IkG4+7B0rO15q9UKKouL/+TDGAxuWxGzXGiJFYNgNb6BOYZO1tv7
         xNxYm7WE1u4fnW3QS01lq0vULdUBh2PlDmLjV2uK/aTWmTZnt9kfY036h9/tKJ5c75EQ
         eTUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from;
        bh=6x/jsBViquIsP1CNHwap3oz/JpLSM+hnzA+o/6OXfpo=;
        b=q027EuMwISKqyqRptzBFMIcfijfLLVSk8Q7oCdCbvKmZQBhB8sB0PPzkOgODPSqnhj
         UxTxY5qdNQNWCxVX3U+pHrD1Uw2quPVvp7aIfuo7+QFm3LuOh6aHQQqfiCRBPAUAugFU
         siw+DAv289xgh+ru2i8ykMIbezvI4VygPIzkZEIUFSOosFKZr3BzhHOmYAx9/qosquBD
         8v3KeS30un+9WTF48U9cJvbo2N7nbl1648AM2whmx664ILzo42B5bxYAl6I6dEb9bFUF
         wm+nJARATVN4jBCwg0g2dpScSqvA+5bZikG1sEXkAKyN6ck13d7GnbWTtv/kihgXiiHE
         2H7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61a as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on061a.outbound.protection.outlook.com. [2a01:111:f400:7e19::61a])
        by gmr-mx.google.com with ESMTPS id w6si812851ljw.6.2022.02.01.04.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Feb 2022 04:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61a as permitted sender) client-ip=2a01:111:f400:7e19::61a;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=JNpfdW6Sivk0MNngKJ3WtSy81fHtBso7fpKCnyPCCRb8yOGwDBV9jx9aRjhrp3BoNtCMmsHFqrqXELvIpd4W6mKinORaheD4NDtDO3M6+DKDjM0QUESYeP13TxCZae1CU58TuFXs2ysm5C5G3uJaDuvt3h56Ago/yf2vEOWT+TzXpokdxr1ntpxOhd+737gcV36Czmv83rclifbJrfwPZLv2JfYLGkKAohqQZ6t21NMeop9UgUCBm3l4uOIWj14IF9IX2O/6ZBJgyRu54jr3Wl5CFSYHt6/cn1saMrJQ+eJ0EDPUoW2T7zBmDuzgmwDRF0VDibiNnhRcPBKkQsqYgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6x/jsBViquIsP1CNHwap3oz/JpLSM+hnzA+o/6OXfpo=;
 b=MggcQtAlEECZr5FlhZ9G0jK/yByRZ/68ZyGbJxWcLx0gEZ1DOqmKi1ZIwWKkVk9NSz52g1CKBQmZYSfTaJ3qIGe8Sm887wPJGN3zZaQQlTRjwimgH53OuSVEoeTXScmoJ9x2y9VzYlYiWpC8mQ9P1MmfCJ8hHQJj3NK5qgXY4GbJfSkT5ROavw9wjK1XxwGjV4gPaxYLIQWYeZ76RFuDatwlTZzCT7FpCW99vK93REEmo8ze9+Wo/jcHKv4X9Roh254zfM8RWiNFjlE53YBjEUl2F5123dHfNmcstrpzVx2JE0LP+kW+7v5Xt5YxdH6ahRxGas72XOCxL4HZ4VT6eA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB3515.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:165::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4930.15; Tue, 1 Feb
 2022 12:36:57 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1%6]) with mapi id 15.20.4930.022; Tue, 1 Feb 2022
 12:36:56 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Chen Jingwen <chenjingwen6@huawei.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul
 Mackerras <paulus@samba.org>, Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan: Fix early region not updated correctly
Thread-Topic: [PATCH] powerpc/kasan: Fix early region not updated correctly
Thread-Index: AQHX/VN2itFQfqRijkarhHKQTpqeC6x+1iOA
Date: Tue, 1 Feb 2022 12:36:56 +0000
Message-ID: <f8d60f39-b78b-798d-f91f-53e0c6bf30a7@csgroup.eu>
References: <20211229035226.59159-1-chenjingwen6@huawei.com>
In-Reply-To: <20211229035226.59159-1-chenjingwen6@huawei.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 8af5dfa6-aeb5-4fd0-0f53-08d9e57f88d6
x-ms-traffictypediagnostic: PR0P264MB3515:EE_
x-microsoft-antispam-prvs: <PR0P264MB3515B0AB178253B188902B6AED269@PR0P264MB3515.FRAP264.PROD.OUTLOOK.COM>
x-ms-oob-tlc-oobclassifiers: OLM:8882;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: pgw/NjKjOdzm9aBeoRqVeiD696RRWpgslJAaPaEYLuO5KbcVvIKWVDIbrugrMbeyda2dcWGgf7ObMgF87B+nuvORFpGarszDBQW73wu6sUpfqMq6RuxmCFmugTFXtkWjcV8CBM+bnQDN8WwXTlqujsrxu20dOsZd/UhQvPF/Txqf9RncT5Og78DfM/U8wY4AFKdAM1i3oT2AW+xmwSKa3s0Ncs3IR97KXZ5XhaSx3tRFIcsO6wFXGYhRTL0qkDjRGsK2CenB90vIr5nAYcL8IK9J96wrs5khCDWxgw0vUb8NhVSspeG+QnnheUS9iC/2QOieFrJqivu02tsjai2cHma3hhu+84uC/hoUabmx0Ynx1ILCUakehXFWCWULgF/OhP6yaP0C9Xh6/pyblNjfC84vo3hoHjE10/LMPIx4CVSMKK9BHWHLt3no0qCW1AZ4Y2/BqkXM+i4CahNuKrXkIGFAXWcQLeNzkpgHnw1QwWvZetpOPycl2VCTNRDcpMYdb6YFJmHQm2QrNcPhO7/w5mNLgFUmZV9z1bqaFNg7J5PtaToGAQnADnoDgWA+eprRzzZ9hYxKB958snlgWO4LoCfnGYikf0LNtHuC54YL/RGm530CtUWv2kvVvbvlw9gVXZhI5Ug4zkpvQVu/yf7AlOJG97pJ9jxjnrtQc6tDusQyInrwqSJX6RrIZiBDAAgaHR60mPBLiOpqtiuttwlcahHcCvWm42Ayh7K/yHKvu+zSTHBu/B+OdJpG8DNnNehjDSKy5Lx6TS7FL26xV3WYYw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(31686004)(91956017)(66574015)(83380400001)(15650500001)(36756003)(44832011)(5660300002)(66446008)(66476007)(64756008)(66946007)(316002)(66556008)(76116006)(8676002)(86362001)(8936002)(110136005)(6486002)(26005)(186003)(2616005)(71200400001)(6506007)(508600001)(122000001)(31696002)(38100700002)(38070700005)(2906002)(6512007)(45980500001)(43740500002)(20210929001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?T1g1K0J2Y1RiYnNlWGdsc00yTitzTkdoN2FXUDRwbVhweEkzZGJzZXhrWnY0?=
 =?utf-8?B?bG9vSVZVK09ha250VlJ1b2pWN2lDR2o2VWxncGJ0eTBWa3YyYWhveHc5aTBI?=
 =?utf-8?B?U2NNL1FYcEphcTVLL3hPNVRwQkFIQXloUEowUFZobnZpMXdFYXhQaG1IQlJW?=
 =?utf-8?B?NEF0dnRsOXdQeGhweG1Qb0VLRkpHWDVJUGlnTUYybkV2b1Bta3FzRHlJTkdH?=
 =?utf-8?B?T0JXaTZWTUhkSlZFWmJ6SlRhY1JiWXNlU2ZjKzFBc1JkQ1Q4ZmY1Sno1Ykxs?=
 =?utf-8?B?L21rbVFNTHBHbzh1M29SY2pSWkhIeWI2Y2dmNS9JYjY3d3pPRnVnT08vTnpH?=
 =?utf-8?B?K3dId041bWo5QTB0b3RCMGJMemtzQWFTVFJ1M3ZseFRvaDU0VkhDWktLbmw5?=
 =?utf-8?B?TklhWkhhR1AwaU95aWtHZ1M1NldTTk1vOEMzUWRDdXBBdVpIUzlPc1VCSFMy?=
 =?utf-8?B?NENDNzFsOThUQnJMM1RnNURHcS9naEhtYWJZZXlBeXZxK1EyNWRkNEQzakVO?=
 =?utf-8?B?SGNKOXBpUDUyUzRKNFh3bmg0N0xNTkpGbUs0WERieU9TaUY5RFphekpoM2lx?=
 =?utf-8?B?U09hcXhzSU55Nm9iTDFmWkxUSHRqRERrdDhEOFRPUVVkSWFmRHEwM2pCaWt4?=
 =?utf-8?B?WDRoeGxTUWJDbXhTelRRZjlmeFc4aCtTZXcvNlVmMkkvQnk2U1htb08zalpL?=
 =?utf-8?B?STRUS2FnckFUWUVZNUJiNzN6SzRQRmY5d3lzdG54V2VPa1g2RERUeG5ZT1lY?=
 =?utf-8?B?RGlXZXgwK2dKNGhHZHBlcHd5dHQrZ3BiZ1c1R1dDQ21oK1NqOW9JVXRacGJa?=
 =?utf-8?B?WUgvNlN4aERObHp5bTRmRmVCcThGV3lmRHVqZ0tSb2s4UUV1ZklHYkpkN2d6?=
 =?utf-8?B?cjE0SlZBUE1WMWJxeEhYQVl1MnV4RjlVUWlob3NPaTU0UXl6VjFjT3Q0K2hD?=
 =?utf-8?B?a3NEektjZ2ZGcEFFRDJjZENkWVprVjdadExIUCtQc0lSQ2JJaUlUUzRsV1Y4?=
 =?utf-8?B?aGVJcGVIUkxLMk5JT3JxdjBXVUl5M0dSYjBOUE9tcHZPbktZVmNGbkw0ckg0?=
 =?utf-8?B?WHBuQ3NXZzgvNytHZlBST2FXcUFMa1VCakRGa21uVC9zSDdBcDFNa3BPeU42?=
 =?utf-8?B?YW5LbFRLK3JORTIwczEwVlN5anBjMjZwa3ZVendXTHl2SEdSaTA4T25WUUMy?=
 =?utf-8?B?SCtXcm1OazhNRE1EZEVLOXc5OExwR2JHd1Jrb2ozVU1qK0NIbmcxUmoyUUhw?=
 =?utf-8?B?QTBTS0VuVE45eEhORGJwZzBLek5nbDU0RFEySVVHellTSmRjT2JKaHJlOUZ2?=
 =?utf-8?B?TEpNN3BIaHk4TUVWTWw0VysxVE5vVXp6WlM5bTdQTUFTSkJ0ajZFTVFzMkk1?=
 =?utf-8?B?eEZ3cGN2RWgzUURFbXNqMTQxbGk5Wm9rTFZHNm90WVNucDFCbHZJMGw4QlNM?=
 =?utf-8?B?bnNYejBtODJxYUxtaVlBNTlnaS8zTCtpNzlabnBNOHM5THVnM25XN2lVQTJI?=
 =?utf-8?B?bFZSays5OVBJdXAzQVhVUmxNOS9NVGJMblBDUEozZ1Y3V1ZXaDgrdExQVWF4?=
 =?utf-8?B?Tnk5ZE1QLy9URjU2SDBsV0FLUGdGZEM3M2ZJcmlFdTZnYk1QQnJaeXg4NXhY?=
 =?utf-8?B?SlFZL0I5ODRUQ1RxQlFFV0FIais3ZDN6Q1dkSFdwM3QzNTBPWXMvWTJpNG9x?=
 =?utf-8?B?aGM5MUlVZ0ZoQk84cGxhNXBVcHBnZVBGcnVCdkJZUDBmT3NIOGtQcDA0YWg2?=
 =?utf-8?B?U0g5czRQcVFwbDZ2ZlIvY3cwcHM2S0kvOFBVeGx0N1BWK1RWc1kvYWVoK29R?=
 =?utf-8?B?eWtIVFhPRVdCdUx0SGRDYnJKZkxrbWhVN3A0MVd4Njc0RDV0RjNXRXJ5ZDVE?=
 =?utf-8?B?SmRRTFNmZGQ1dW54YWFJQTg2b1h4dlc2QlVCMis5bzZYK1V2NzNhSUh6cmFT?=
 =?utf-8?B?UmF1U2J3eFhSdW5Yc3Z2clBVQkxNQXBBbmF6bm1Ua3I2MFBidFVpSzJYUUlD?=
 =?utf-8?B?M05qZDdvNUxKOVprNkEzS1JjYzFMUXFlWTlEdEtlVmtlbzMweCtTcXlabDFR?=
 =?utf-8?B?Y3gvMG5qbmllU0JhTE5VMkRQaUNEaldHTWczWnd5YnpWaFhOK2FGcVFSZ0tU?=
 =?utf-8?B?MkttVDdFZjdLaUswSEd1SGt0QnI4QjlFRnpvSVEzR0J4bE0vVG1ERkRTWmRx?=
 =?utf-8?B?aFlnVzFNYzdSK0JqbVB6OEhIY215ZmhnV05pUjBuUVNPQVlpNTdVRUJXSnZn?=
 =?utf-8?Q?PnI5cd+S+owTRFhxMPUCDa8gW93e2zbiPnPJurK1Tc=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <5B164636F661E44EBBA66BEA065FED64@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 8af5dfa6-aeb5-4fd0-0f53-08d9e57f88d6
X-MS-Exchange-CrossTenant-originalarrivaltime: 01 Feb 2022 12:36:56.8354
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: /2FA5AID+ZtD7zfDNioltfyyHWw02zH0lIdUMxKbeO2R5cy7MabCJCjFwcfz38aOAAle/fbkwK31zAqiiWX0Yi1EPuJouYRv1vpwFOC8kgI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB3515
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates
 2a01:111:f400:7e19::61a as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 29/12/2021 =C3=A0 04:52, Chen Jingwen a =C3=A9crit=C2=A0:
> The shadow's page table is not updated when PTE_RPN_SHIFT is 24
> and PAGE_SHIFT is 12. It not only causes false positives but
> also false negative as shown the following text.
>=20
> Fix it by bringing the logic of kasan_early_shadow_page_entry here.
>=20
> 1. False Positive:
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> BUG: KASAN: vmalloc-out-of-bounds in pcpu_alloc+0x508/0xa50
> Write of size 16 at addr f57f3be0 by task swapper/0/1
>=20
> CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.15.0-12267-gdebe436e77c7 #1
> Call Trace:
> [c80d1c20] [c07fe7b8] dump_stack_lvl+0x4c/0x6c (unreliable)
> [c80d1c40] [c02ff668] print_address_description.constprop.0+0x88/0x300
> [c80d1c70] [c02ff45c] kasan_report+0x1ec/0x200
> [c80d1cb0] [c0300b20] kasan_check_range+0x160/0x2f0
> [c80d1cc0] [c03018a4] memset+0x34/0x90
> [c80d1ce0] [c0280108] pcpu_alloc+0x508/0xa50
> [c80d1d40] [c02fd7bc] __kmem_cache_create+0xfc/0x570
> [c80d1d70] [c0283d64] kmem_cache_create_usercopy+0x274/0x3e0
> [c80d1db0] [c2036580] init_sd+0xc4/0x1d0
> [c80d1de0] [c00044a0] do_one_initcall+0xc0/0x33c
> [c80d1eb0] [c2001624] kernel_init_freeable+0x2c8/0x384
> [c80d1ef0] [c0004b14] kernel_init+0x24/0x170
> [c80d1f10] [c001b26c] ret_from_kernel_thread+0x5c/0x64
>=20
> Memory state around the buggy address:
>   f57f3a80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>   f57f3b00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>> f57f3b80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>                                                 ^
>   f57f3c00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>   f57f3c80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>=20
> 2. False Negative (with KASAN tests):
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> Before fix:
>      ok 45 - kmalloc_double_kzfree
>      # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:1039
>      KASAN failure expected in "((volatile char *)area)[3100]", but none =
occurred
>      not ok 46 - vmalloc_oob
>      not ok 1 - kasan
>=20
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> After fix:
>      ok 1 - kasan
>=20
> Fixes: cbd18991e24fe ("powerpc/mm: Fix an Oops in kasan_mmu_init()")
> Cc: stable@vger.kernel.org # 5.4.x
> Signed-off-by: Chen Jingwen <chenjingwen6@huawei.com>

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>

> ---
>   arch/powerpc/mm/kasan/kasan_init_32.c | 3 +--
>   1 file changed, 1 insertion(+), 2 deletions(-)
>=20
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasa=
n/kasan_init_32.c
> index cf8770b1a692e..f3e4d069e0ba7 100644
> --- a/arch/powerpc/mm/kasan/kasan_init_32.c
> +++ b/arch/powerpc/mm/kasan/kasan_init_32.c
> @@ -83,13 +83,12 @@ void __init
>   kasan_update_early_region(unsigned long k_start, unsigned long k_end, p=
te_t pte)
>   {
>   	unsigned long k_cur;
> -	phys_addr_t pa =3D __pa(kasan_early_shadow_page);
>  =20
>   	for (k_cur =3D k_start; k_cur !=3D k_end; k_cur +=3D PAGE_SIZE) {
>   		pmd_t *pmd =3D pmd_off_k(k_cur);
>   		pte_t *ptep =3D pte_offset_kernel(pmd, k_cur);
>  =20
> -		if ((pte_val(*ptep) & PTE_RPN_MASK) !=3D pa)
> +		if (pte_page(*ptep) !=3D virt_to_page(lm_alias(kasan_early_shadow_page=
)))
>   			continue;
>  =20
>   		__set_pte_at(&init_mm, k_cur, ptep, pte, 0);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f8d60f39-b78b-798d-f91f-53e0c6bf30a7%40csgroup.eu.
