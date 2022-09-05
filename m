Return-Path: <kasan-dev+bncBCJZ5QGEQAFBBKVL3CMAMGQEQ6BECRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0243F5AD65A
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 17:28:43 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id i7-20020a1c3b07000000b003a534ec2570sf7575223wma.7
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 08:28:43 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1662391722; cv=pass;
        d=google.com; s=arc-20160816;
        b=j3HYpAIDZSL3O858aV4qFBf3iEmfgrFShIde/y/wB1aNlFsEOTFp+ivW3SfKQy0we4
         nnRUBdc+NgaK6CX+UZTkpiMcCrrNBvJHCnub1j+g0AkZGu/OmOnN9ECzyZh7cXHq6j2X
         l0FTYug+chvQns19OJmCzphCvKrTWuUL92fz7FXULwAIZKdNbZd40+oVWpTOUtd5EhyF
         8G6FprrWEztID+ulkSIhxiZq6iHQg7/bgfB534QayCnouAzp16WdznRQpLdFsuwHwiOY
         xTQzo2cCGLEn+eHvHhwVjoPRsW2pyqux4rK49liOr/4TvgJYtXL/wWWKPVCHm7pxoCxq
         dFKg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=S8OlF9hPcsvTlVu8IzQhYszI3L98pS8ETZnDqHPh1Ko=;
        b=Q2c/waIMVGG34xUESByJ1cnZdTnA45044VuqwwlIhwsuNT+r+WFCISUL3brCHgXSuZ
         eXRwskjK3qrPG9ultbeENyNYRGgO8ttagBBpD5outjZoznI0xja2z4bwttJE1+JjL9P7
         PBsTocOCIBNxKPtylt/MEBjVMuzFbfwynq1efSL5qN87eZ5Yyp1bJ35KaEjRXvR5mzYM
         kuwTro1dLxSBPtVhXnDqAFn9Si1P8iv1vAzNW/CqNKcaiJauu5bTW+AktglXo9aB7vJd
         7qIwqhUzqo2RcluQZOzC124SsPLjaJtTZ4UZWqTRiywvgIOQy7xSzStHeLQkOXHhB5QX
         JX+A==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=w5NR5yYA;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.14.128 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date;
        bh=S8OlF9hPcsvTlVu8IzQhYszI3L98pS8ETZnDqHPh1Ko=;
        b=Pn4OnpVSo4SwmMxrxTYXxQVh1M/APC60ZnWdTu0C1BmF9Nv1OWdBwXJupmYhSwXrbP
         VTGmDw2Ea7SwF/rvEBXYnmqQsGQJQn/fnyTz34/ZAKjU/kW3RdTCvaEfuTJbDh5AmJXp
         gA2d1t3ZxDWOiosdcs/rXJ8ocqz5ffT2CfzAgOMe6/EAEic6goBdqZ11YwdqPPb1OJ/L
         DW7h6NvIBSNqvCMcFsgkk4Y4Ck/NzRLO0ftEYSsqtN/VIgKhYAG/c8MMxVc1lB7u3S4D
         d0iHxNK899ENpQWKCplTvvLPVANLJ+CuaoUBX+wUiVBqnwVtaCUSD72UzZV0n2sVvUYW
         zrPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=S8OlF9hPcsvTlVu8IzQhYszI3L98pS8ETZnDqHPh1Ko=;
        b=xFXIQs7BiMOoQMg1Grsr85opxDm3CCAwnDqmwyYi3FGde2S9TWCr5a/ukSAtVyFC4w
         1vU5hc6iriwGZSBeMFLLZctwrci3ZvAgqap7RxrNXXd53thftcAn6t4ge2kstCTkj/Zf
         RG6NTkT0O5vC+MzjI/dO766UpI/tvTOrFfCZB8J2a/qB7vOp+ipyfumUT5dwTfrt0Xci
         y/sjQcu48HjuVT+Ck52b12ZII5+ZK++NShqNoBIt0zrM565FNIgJ+LqbSKiP4QD44DMI
         JQO17doccyqeiUQEIE4gXBKjzaZw7QOdYaNjXdyi2BjsyZFS+jcUCSVVoSXmLGIsnV31
         6A9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2AgsYdOU0D1jv59K82bXA7IZc7WitPM9+l6Y7vSTmQfYLDx6lz
	d4OEYs8bTFJRMJ3Yc+VQKsY=
X-Google-Smtp-Source: AA6agR4zoE/j6eRWX1iHrwH8/G9l4Smex8zOTGv3TZVF+am2wTvMyqKMOnxGNqDWwHpM2jbCy0R9ag==
X-Received: by 2002:a05:600c:4fcf:b0:3a8:437a:8d28 with SMTP id o15-20020a05600c4fcf00b003a8437a8d28mr11132180wmq.197.1662391722426;
        Mon, 05 Sep 2022 08:28:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1483:b0:3a6:47b:13c7 with SMTP id
 c3-20020a05600c148300b003a6047b13c7ls4944608wmh.0.-pod-canary-gmail; Mon, 05
 Sep 2022 08:28:41 -0700 (PDT)
X-Received: by 2002:a1c:7703:0:b0:3a5:aefa:68e3 with SMTP id t3-20020a1c7703000000b003a5aefa68e3mr11536853wmi.158.1662391721360;
        Mon, 05 Sep 2022 08:28:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662391721; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8eLM2zGKXZ9fyGJmlyEdzpxTYBHcyW6krG0OvCY48UN0nCgCHfK1Pg3u3sqtLp/cP
         Ca+V6e8GZG/WiMET1TCUe5QQ3lCfkX2BDL4kLkpDUeKElUT921DPRGMrnKv0PeAzoWqI
         pZF6eqLAG+TBuIlLnIuqrFCndxeBMRbLai8UxApTQ63ERlU2ekjhcvvuiFxSSM7j19g4
         XC8H+siig0i5Eu+f/f4Hq8pyyH+LnRPnDnyKK4kEhrehHzOJ29yF3oECKZdnuH/Ybm/b
         IOYXN7DWO6wiTm5E86q1hpABNNNO6sTeDx2C/nAdXhIURL+zKT6Bpj/IiQ6iuhQeHg5U
         vtZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=oqqFoZBeOWjlgGBY8whrOB0QCiuQvuJPZI1cf/8bcig=;
        b=MbVPUKwbho0xARJ1B0A9/0Pohv4tCjmHgo91PC6K6L4s4MDjP9CghQp2JG2UiFUlgb
         gXpwyOrCRHZihzFEzGhy2sqUmnyXmCzxsNKC403FeRrcB7al/elbF5L0/iB6mswtjFwF
         gc+ECs2nfb1kKIrQQHozK+ToQ/HszCdwoUD2OdAGlR8YJZefdZtPkler4i8SEXyMqr/e
         SoEuiw0uziimshYKkPN3OlT4z+DTvbnl1t5whAdwokZ99TiKwS3GA3w1mo3JomFFtMuk
         OtUPBcscz4Epty7HTRZLMrv3Q+2WUouShrKwDVWoei9glpKvez24teoKSEwZMUdT2wg6
         D9iA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=w5NR5yYA;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.14.128 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR01-VE1-obe.outbound.protection.outlook.com (mail-eopbgr140128.outbound.protection.outlook.com. [40.107.14.128])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b003a83fda1d81si901400wmq.2.2022.09.05.08.28.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 08:28:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.14.128 as permitted sender) client-ip=40.107.14.128;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Fqi51JWAbWqf0veDsR7qz/PPhHv++LqujMU26OTwApFWyRJv3k9aP3uEzvXZJ6quZHyo46GDy7gnRs+EQ1zJf0IlH5yS4YUS0ApSC4WkBfPHe5MllyTIXN11xUI4W0qTZIKsIghZaJ+fMhj9lkENHaqef7XfzIdffegdpl9E7Qs/6oQqNSoGf1n651Uc7vsLcJr4xu6xaHr3o/8VnfC3GiZ1791s11NnvtEwd+bsWx2v19goBnoG02MP1hakEISyZ7njE3ZhnIENRd9tIrLYbrZz2VbJdCZUU8CPBqBf3C8rpCIBACoIDdOm5XVll3StL+YO5dUMhffh6axS9Sx5wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=oqqFoZBeOWjlgGBY8whrOB0QCiuQvuJPZI1cf/8bcig=;
 b=fbQc5pQp7xj7fGhaTPRSJShh6ZtE2bohEe8ch56gj2NxekXz9TkUDPmdMeqTX0T8FBqJfJPoyNN3C6IQ/L0BjgeeeMrhv4DOvtCrydW9HLHebZYdPjpjwjE6mMFu8l0j64rwPsttti/BOqLTisU2aFJVgq+5+Wi6jW3VYcF1j4KQq2KmeYsULVHwE9IC+tGGtHtr2zjHb5skGQ2PDlnL+e7h9tEhhEBubJk+TII29x9Ln0c2UUuv0nV6y4pkQuPXw132YMuPTjFn7tr3k5BxbXP4tXXU0y7ehwG7wumh4B+EfYG/RFrH5MnsehDxf77u6/9XKl0m+z6fqEw9wusOvw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nokia.com; dmarc=pass action=none header.from=nokia.com;
 dkim=pass header.d=nokia.com; arc=none
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com (2603:10a6:20b:4cd::12)
 by DU0PR07MB9161.eurprd07.prod.outlook.com (2603:10a6:10:407::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5612.12; Mon, 5 Sep
 2022 15:28:39 +0000
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::b333:1f3b:1b01:50d9]) by AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::b333:1f3b:1b01:50d9%3]) with mapi id 15.20.5612.009; Mon, 5 Sep 2022
 15:28:39 +0000
Message-ID: <66a173c5-553e-8788-7e9a-153382f1f9a5@nokia.com>
Date: Mon, 5 Sep 2022 17:28:35 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH v2] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Content-Language: en-US
To: Linus Walleij <linus.walleij@linaro.org>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Russell King <linux@armlinux.org.uk>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20220905122754.32590-1-alexander.sverdlin@nokia.com>
 <CACRpkdbdKAWfvpG2n-eJPagV3Sx1faaxC9cEFs3PTyDaxETwyQ@mail.gmail.com>
From: Alexander Sverdlin <alexander.sverdlin@nokia.com>
In-Reply-To: <CACRpkdbdKAWfvpG2n-eJPagV3Sx1faaxC9cEFs3PTyDaxETwyQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: FR0P281CA0098.DEUP281.PROD.OUTLOOK.COM
 (2603:10a6:d10:a9::8) To AS4PR07MB8658.eurprd07.prod.outlook.com
 (2603:10a6:20b:4cd::12)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AS4PR07MB8658:EE_|DU0PR07MB9161:EE_
X-MS-Office365-Filtering-Correlation-Id: f9485fa3-53b4-4f64-cbbe-08da8f534eea
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: UMVZ2011ygruPfpBmLQOH67/XLvgPkQQrn+pYmWvX1Q9Q0ZcPvsmIZNhxK4tZoab3UKEimkootpf+GeOglKCnU+Ru1BgaE2ff50f+2cSeSQWYyvZloKpSQACfvl8cD8PPtLZc258WYqtglPzakbgC6GOxOe7vG9LPrlZECrJOu4xBudp1JR8CRvteajQWHwyKNsK0mVI3MrwE21NWMlxWoFA+QSmPV/89rEt2IkpzHbnzdhI1qjoOnhaSUzLhf3r07V2BCUc8d0wI1E/QcVisgF4FNMuAcwRhGDcOkok2pme2pGNxQPuVKnteH19ZDS5fAwsUXumgoZ2sApOLKfQBYsR1YdLVHHid6GiQYfzmJ9Ue+nhXAAyO7k1eyiODZZ6CQOmKYYtDPWlgCUNhHmiCj59TpeDYB1T8SytNM4G1op+pIvv37Yun3jB4M90bA0VChf2a6oMEvWSQayODK6zmqZ72M7cJ6ZPXvIWH3xj9MoESZK/Laui4edrYQ6ULvMCbZ0YPhHwcZjwccicmdopKr1PB26UerwYbFLGmbyWXXm2kSNen3veyQ7ScGdFHjT/XNnJw+bFdqP+D0pBxrnJ9S5AnDJ2aScp2wouyDkKO/Ih0Co/wm0WnPx5bk/OKDJKA9N4b6a1Z2R6lKxSupHGXYPrkwF04JCWct+DEP8b6WrM2cdhjtPtEqgpBKROvtFE2aM9nms+97YDs/BdLRcgpoi8RLcrILs9d2hlyXE9pp+UT2nnDiCIkwkI1HHq4SFISLv6DJH+8ww7GgllZYiDeOS2svmQk5lxaEXQeanvR/mCG6mEEJ2VfIxo41+vbMxiB2HSmgo2sApcixOQsONbMv0xvKnxDlIXCi0cSXfHncM=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AS4PR07MB8658.eurprd07.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(4636009)(366004)(136003)(39860400002)(346002)(396003)(376002)(6512007)(26005)(38100700002)(8936002)(66946007)(66476007)(8676002)(4326008)(66556008)(478600001)(2906002)(6506007)(44832011)(31696002)(53546011)(86362001)(41300700001)(6666004)(4744005)(5660300002)(7416002)(82960400001)(2616005)(186003)(316002)(36756003)(966005)(6486002)(31686004)(16799955002)(54906003)(6916009)(43740500002)(45980500001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?WktYQWhneG5tTWpBY3E2U1RwVjVac1E0L2JubmhrV3lNV3BzdFBjU0hwQ0Z5?=
 =?utf-8?B?TGdZODllUnRReW1Ddk04TlpCNjJIRWc5SkcyYkJKV1RLbU9UemxPbHUzVHdI?=
 =?utf-8?B?T3QxN0VTRUhrQ3RHRDR1RVZWODdSZS9pK0JBMnl0MG95OGkrbGxDeUZpZ0pF?=
 =?utf-8?B?TnpoUjQ4MjJLUCt3VEc0MXVIMUczRENldm9oVHVNUkpHclR5MC9yQ2xDYVUv?=
 =?utf-8?B?blErNkljQzVpRGVKRWtJc3QrZnVvWWZBY0lsVXV1eUVhVE9VVDlrMzZnSHc5?=
 =?utf-8?B?UGRHOTFpcEZMbzhUT3ZNbEdDZ053c1pqSmNlSXd1dXpCWis0UDRrSUQ2V3Zl?=
 =?utf-8?B?cHdISkJRaERsdlBWR1JUOGU2RFNXY1MxZzJYR0U1TWFSVUhJWDFENWplci81?=
 =?utf-8?B?UmhYbXZ1T3Rpb0d3SVNpUUJteE9rUk9OeGtKcUt3ZnpjbUtSYm1KV1Z4TlNv?=
 =?utf-8?B?Z1puVHNrbjBEZXVBUHVicjFuTXNHbTRqclZZQldQQ215T2dZWjBjQ1BsUGZ0?=
 =?utf-8?B?OEpZYUcvamVtZWMydHNPT2ZJNTNaTVdhaDZLRTdkSGs2dXVtbDdPczJEMTVa?=
 =?utf-8?B?bnRxL0JFZUd2WG9IbDVtYmZmZU5XbDNJNWpoc2MxYkhiTXNhWXF0WmdGOWlP?=
 =?utf-8?B?QitxSlI2OWRtcmpVa0RvQVZCV0hMZldDaDZPWW8waURlWlZUSENmVVpja0hN?=
 =?utf-8?B?cFByK0wyZzBQc1p6eVJUMnduV0FzM2NEdVYyN1BwTkx3OFpFUEVLNnFGZ1J2?=
 =?utf-8?B?UzlrTEZWdDg4TDc5ZmpQNndMdXM3bmdSUmdycThobUdIT2F3ZXVpU0Y2T05O?=
 =?utf-8?B?ZWEzbTV2UXY2ckNGYWdJWWNvTnRjRGFjdWZBODJ1STdZbk8zWk9pZUR0TFFU?=
 =?utf-8?B?amFNVEpjRHozRCt0aTU5QW51a2RlbCtnV28zZURDYkt0MGRxZGZGRFRLVE5l?=
 =?utf-8?B?d1pLUC9Va1BCT2dhMW1JQjNOVDVpaFQrWUY3dUwyL0ZrMlZWZXRHbmttOStt?=
 =?utf-8?B?NDBIV1pTSE1iN0VnelRSaU5ENWlBYk5RTEh3MXg3YUtZZmN3TDlzVWx0cGRx?=
 =?utf-8?B?ejAyeEN1RVdZTXUvN01WWExJSUc4c2lCUW41V2Ric1dtTkh6NFNUR0gyRG50?=
 =?utf-8?B?Z01YTU1wcEFCMWx0SSs5T0dFRU8rYnBEb2JjREZYVWw3cjFxVTU5SlRjSEw5?=
 =?utf-8?B?OUZNWDdxK1hlWHF5R1h6MEtPcjFhRkN3bE1JQS9mZGNROU9VWHAwcGltTUtN?=
 =?utf-8?B?V2dORzRhTkpKYTFWOEVmQ3pDM0wrcXo0Q1NFRkJvRDZBRThYL1FodkpyRGdx?=
 =?utf-8?B?TWVQd2pzZmlWRXR5L3FDT01UOVluN0lLRFgwTFl1b3c2YVpHamd3NlFSMzVy?=
 =?utf-8?B?am1RTnpWTDhRdEN0ZDN6MWs1NnZRM0N4dFpXZFFiN0I4d0xubFBoWHNrT3hn?=
 =?utf-8?B?OGkzWjBiejJya1BJaTVIRzlvZ04xUUxOQ0Q5bkFPN0lwaFRHc0tjYkdNWGdn?=
 =?utf-8?B?Y000eEVCVVdnbkNhZ0ZqL0ZESjFjQ2lhQzNGclZVbW4wYVczeVl3dlBKSElS?=
 =?utf-8?B?clpqemsweE5VWTZyc2lwcXVIL0ZNZDFTdG5zK2c3NWwwVk1PZ0l1K3lnM2x6?=
 =?utf-8?B?c2lsVXpjdis4SEdkQmt1dTYwVnJIbEc1WmNVakwwUi9tR056MVFVbGJnQktT?=
 =?utf-8?B?WUNvRzVYbkxlaXB4TDNSb1ZpUEZpKytkY2RuQ2dKV1VRTm9oMlpHdklsTDU5?=
 =?utf-8?B?cEdUMEo3MDRpRHFHczlIUnQyVStySjEyVnNHWXFBN1JGc0FPWHNJSEx0RHMr?=
 =?utf-8?B?ZWJ1ZHQyemVyZkF3OVBNeG9xOFRxUFIrK2hoWEFLem1XanduQXFrdUVWcVFi?=
 =?utf-8?B?TTNBQUdpc3hyWmpiYlI2ZlJsSVNhc3UxeklNTTVlQUtCa3hvYlkwanFBZ3ds?=
 =?utf-8?B?clJrVDJjY0FnbUVBczh6UXpoQ21XdWdGY1llZFVBUWNPQjJyL1JkclkzTXZI?=
 =?utf-8?B?OEYzMVplay9EQjhwSE9lR1NOWFNNNDhCTThoNkJJUUxxMnRLVElpRXVob01t?=
 =?utf-8?B?OFJWb25Mb0psbFg5YlZnSEtZT2gzUHV4OGRVbUxEQnZKWUhpWW02WnBxUGNa?=
 =?utf-8?B?Q095Y2NVRHg2OVZ0RCswQW1iVlk2clJHNks2SWZrNm0vTzMzRWFtWVg2Q0lo?=
 =?utf-8?B?Ync9PQ==?=
X-OriginatorOrg: nokia.com
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU0PR07MB9161
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=w5NR5yYA;       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass
 dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);       spf=pass
 (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.14.128
 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
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

Hello Linus,

On 05/09/2022 15:38, Linus Walleij wrote:
>> In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
>> shadow pages dynamically. But even worse is that kasan_release_vmalloc()
>> releases them, which is not compatible with create_mapping() of
>> MODULES_VADDR..MODULES_END range:
>>
>> BUG: Bad page state in process kworker/9:1  pfn:2068b

[...]

>>
>> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
>> Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
> Thanks Alexander, will you submit this to Russell's patch tracker please?

done!

https://www.arm.linux.org.uk/developer/patches/viewpatch.php?id=9242/1

Thank you for the quick review!

-- 
Best regards,
Alexander Sverdlin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66a173c5-553e-8788-7e9a-153382f1f9a5%40nokia.com.
