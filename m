Return-Path: <kasan-dev+bncBCJZ5QGEQAFBB4FPSGMQMGQEFHN2FQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B2D5BABF4
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Sep 2022 13:03:18 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id a5-20020a9d2605000000b006554fc97188sf12049884otb.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Sep 2022 04:03:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1663326194; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDYx8K4Y2S4SeF4OkfludsZvmDhhoTtfHavQ6DG68HGo02+K/R1owN1/8/mP1SkEtd
         1BMkaFGUk99s6+rhvvOslR/FSp6WAO1dL6EiMZepVh6Xwn3zNbLy/rznJ7BffygFSGXU
         2BZdrD1SL4APo0FX+d3JEdav+0JYtZIpcgfAK+Mte+JwHBRd2pFWrMQOzdKvW5F2yEu8
         Cs/7oyAFhYN+EdQAogr1/u8FgwCmwUqRsYnzSEU4S6Bbc16Tc2Bpnim9t58fprG5YqWQ
         ExO+cf/TXXUQugEBVIScA0M9aoh3ETHIJ45wcry3r2jp2lFhZ8aQKB2cMrPhywLkYmeh
         2K8A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=B69YQtbCkU+22nIyMOnd+zlZkMGlaD7OwPVvFlEqHhQ=;
        b=UFFMxFbSvdbSbiy/0tsQHlQwxnpg6hPLAAA5U3bPpfm18DdQtf29ogxE1677B+gBJu
         ojbxI9ZK8j1+jPAxUiqv/0r/XxcxS7PrUB6wwPBWM5JwhWDY8xOuTidn0I9peL+tC/Lq
         Mtvr0tPMOxPFc1HSUs0UJ2PevTJ5ljH97DGrJxGX8hW7tII3jeroj0wqAM1PjTM+HJtq
         t14oid2nT9FJv0EttvcTpc1chMX9S+PL+X0BayOwLRYlmU1w+fPYmwyenySyi5mvlPiZ
         aKuv0jrdOSWGcKFf2yzFp5sllL+Opul1CWiv8EUmUcK2+Bt4XGpmxLM6B5VdXbA+u41C
         M7jQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=LYHZK5Hv;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.6.104 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date;
        bh=B69YQtbCkU+22nIyMOnd+zlZkMGlaD7OwPVvFlEqHhQ=;
        b=RKuAUazw3ydhDcyaSqlQcfBYubv6WsVO4ZRCQMyV3g2DQkKoWUH+J1JwacXth9c+CF
         4gvjbUJ0DlKoAYez8dbgEr4IhLyyGBBvUsHCS8bkBDj9HGMXpKV8JTEZ2OFmqFAZluHk
         ImtaZ/MaNUUxzuDNqwFKAdwGf0lDa7r3EkBPZ0FxR+5gbRbpd+l40MynoUcalrpwhWW8
         /LCelqdp6HnLv6MvaktC23PUiCL2Yncan3PW7x8cHWmhi0lCsYt+5n8j1Cqt6BsJzfyf
         QmrwIg0lP5z0xPOdNN+cs7gWZyeUZJuD2KxDuSYI0Jnm/fJazkiHC4C4tkL+eTfzsyp3
         9Rkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=B69YQtbCkU+22nIyMOnd+zlZkMGlaD7OwPVvFlEqHhQ=;
        b=VRy9SR5tjHLF3Oy09IeSnhfUkz6YAGjW6FZivHfYFt5EvctAeITEycj98SY3A0pZQK
         1sUt7Lh+PbCrR/UCdBYbvArkuLjTHOw58KRjVC7cLI23iJs95HB2kFxoRReNoB2SwTzn
         r+DKPA0faP0l8Wo0/ODqS/R0NvorMm8FLrzt2GEGA8oCSqaHpiSlqCVVxhW12oqBmVfJ
         ApiSpcI2Dlg2gfobd26PusPpFd3VyziYUghiaO7hb0K474gDqGZJwdNd+GmtXI3Xum2Z
         xE5fg2IxOUL+c8D07GKhps7EbZekIZDzyWNgHI+JchLJeSPR3s3MDvvj3dPZ9i9/8gvC
         PIIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1rVTZiuu6p/UaU4iuww+R2qPyr/Rz88B9waLhzszNw1Yh3DneP
	bxwGBcpw0X4xF1Zy6lUMc/o=
X-Google-Smtp-Source: AA6agR4rwG2LmeF+9NjVpO1dKu6T1igX51ex7/I0tEDgZmPpA8FsUEsgilM5H/nRxcqXO7Jh87lBQA==
X-Received: by 2002:a05:6870:b68f:b0:10b:ba83:92d4 with SMTP id cy15-20020a056870b68f00b0010bba8392d4mr7791908oab.130.1663326192879;
        Fri, 16 Sep 2022 04:03:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:605:b0:10e:c5cb:acd1 with SMTP id
 w5-20020a056871060500b0010ec5cbacd1ls9568707oan.5.-pod-prod-gmail; Fri, 16
 Sep 2022 04:03:12 -0700 (PDT)
X-Received: by 2002:a05:6870:2422:b0:127:642c:b2bb with SMTP id n34-20020a056870242200b00127642cb2bbmr2370282oap.148.1663326192538;
        Fri, 16 Sep 2022 04:03:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663326192; cv=pass;
        d=google.com; s=arc-20160816;
        b=s25Ya+SMNVluPiWGABmeSyZtuKwqpRnuDkL75cpnpE6LtZDJeC0z452zFGvWegTJbK
         n/YCkMZpOCcyzapClB0ASbzo/A7569iUrQoY8O55EFRB9/btDyt2JbiVnpudSokr/VGw
         7F8R+29B9GRjcxVBUOJZEOUARo5DIYO1mk9riNrp2vZ1vmf2GPgXMf1Q4obE8vU4tH1l
         yyS7W6zPggC7CqWCPjGa3LC9rZGmcNsOEBJarG5wBE1tWhSfTijSZJpN+1fmf15rGcQD
         k5Wc0IxvrBSnkqpzQOF+0rMdCfvL6UFX1RRxWkRYOJBjShlulUTVCtekBEUrGseZLe1H
         +O3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=LCWMSmcN2TylT+ST5RhLYJSqQsrgD1vdiU7nmdjJ69M=;
        b=D9WN1/nfNqw5+5wpk3zbI6OUbQxY7Ybjng24gofhZ4EKIvgE8qsvjVMXdtQf+ZKgyR
         +2THSSyZvc9MJA4PzAbPDS2D10nV1FXRx+5FG5h7T3m0D+DmRZtwcdhoSmkjXyHsFphK
         jCVggrRRUJtcZw+VP6Son8W+7ip52yKVpNZSBJ5rnEgHZLJtE+8auwqgeMvC25jryg+3
         pdS8WaqUoCgyh95QVhNJT7bjgLnqTzCKpPAkSDy6vMJrDQZWy6UFdbekmSOghb7tstw/
         /SJdHdRpDFkkl0esHovfvTdAl/YNlP30iIanAYtneyzk1ACqiqvSXNVsyyaKrOZ731/u
         hz8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=LYHZK5Hv;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.6.104 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR04-DB3-obe.outbound.protection.outlook.com (mail-eopbgr60104.outbound.protection.outlook.com. [40.107.6.104])
        by gmr-mx.google.com with ESMTPS id g17-20020a4adc91000000b0044dfb9bed1bsi616048oou.2.2022.09.16.04.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Sep 2022 04:03:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.6.104 as permitted sender) client-ip=40.107.6.104;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Vz68FNU3uP1nWSes/ZSJp/Fej53uc90gxFNfRlAoI8X1i2/pey05kZwddKOj2FFxGx/pjB6aK3EIzlquW6NE2ItBDDvDeV7hBQjXzHEZNJoofmevzSuZfzLoKJUqORhlXFGKH/Ame+YJ0ZtsCPI8NRT6UKLsVBDoonskJESfCzlAs/8Q+mkgfgbyFXRkEMY0qWOPRM5D+KLFmjm8v6LaXpsm8ELWWLwlR3yEMFhowD7yz8CvxccFhQTa5/eZMNzpQRA295g09GM8Dw+TEBW4czCEuM8xaSaSQMTEkb95V5Cers7i1vEat5r0B9ivSOU8GJUByJts4U4bzNLEOxNBJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LCWMSmcN2TylT+ST5RhLYJSqQsrgD1vdiU7nmdjJ69M=;
 b=M+Nr1GyBJIRAU7Yh9HomYBFCIWGQkKxFlPxAZv2JeFbwhbE33216IJJmmgecjJJaTSqb3BV0b8ht6p1HZHJMPp5B7nx4MZPuUPHyn9PpLqObjjQmRkTM54wWlmZLv0LdaYIOLHCpSLx9DsBK1EbhWBrJYuAKe+zlyOt8WMokSFSlDlnk1N7gbNGwwf+UrE3u+kOyNZrsr0WuNQuLOiNvgUoSXCe9sQa7neJin5nlP0wxasTxoTJQrXoaaYiKFPcujPiHYTvbF/RcLwu45zSJ1o8OYJGqneJ7sv25tnJ2a5a+KbMr10uDgj1ZLrMPyzJwXPA5VkYeRu7gAd7Xq7TfKQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nokia.com; dmarc=pass action=none header.from=nokia.com;
 dkim=pass header.d=nokia.com; arc=none
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com (2603:10a6:20b:4cd::12)
 by DBBPR07MB7625.eurprd07.prod.outlook.com (2603:10a6:10:1e4::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5632.12; Fri, 16 Sep
 2022 11:03:10 +0000
Received: from AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::5a5c:9cd4:c674:a6e8]) by AS4PR07MB8658.eurprd07.prod.outlook.com
 ([fe80::5a5c:9cd4:c674:a6e8%7]) with mapi id 15.20.5612.022; Fri, 16 Sep 2022
 11:03:09 +0000
Message-ID: <5a53ee90-d49d-afb6-050b-4649631f8910@nokia.com>
Date: Fri, 16 Sep 2022 13:03:01 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.7.0
Subject: Re: [PATCH] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Content-Language: en-US
To: Linus Walleij <linus.walleij@linaro.org>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Russell King <linux@armlinux.org.uk>, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org
References: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
 <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com>
From: Alexander Sverdlin <alexander.sverdlin@nokia.com>
In-Reply-To: <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: ZR0P278CA0130.CHEP278.PROD.OUTLOOK.COM
 (2603:10a6:910:40::9) To AS4PR07MB8658.eurprd07.prod.outlook.com
 (2603:10a6:20b:4cd::12)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AS4PR07MB8658:EE_|DBBPR07MB7625:EE_
X-MS-Office365-Filtering-Correlation-Id: eed1528a-b2c4-4813-bd8d-08da97d30a7d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: yu02b4lpeSp+314DbQ6yeNxPvEoS7boYqQEKYFkpT/OtsjeqzBRwc6ZpppUspujQwiAWwQY/I0HHpNaOVvcgwx9MD/9pjowQB2Ia6jCIe73Ffiy8Pqqzrzdwt7GQnaEssM1MRfQHGMpLCA4cd838rEq2fdAbKyXCya62yw6NpdgGfzM0WsNdM2f7R6aQ5V8gP0I/ybhEHR6xHC97DE1F7WioTrCVqSVw8aSKjfxKZ/VeVlURNSl+wK8JP3EulL5kKnd130GtK67sjRi3JxmHk6ZljCegfPSn6THV4bQhWXrtzd6OkEsP/dvI7TPgUCJxJqy48GM7p5JeGq3orpKnDGGQXNMFPag1n7SjV67sjBITy6PhANsJRAQDIUIdwkdl9SgY8O+Xu/zA+fMRDNQRWiWWRcBP/TZ8ch7c6OI04RmvZ3HEi1EK2IRWwD3QWRwxk26pdc7Tk5DRhBu/DQ3HJzuXYRcmLQtb3Sfkc8FWmJ7eHrgfo80wGpkVlTu/foYWBcEUGgK53DuiibZwFlpEeuCJB/6PGId/Q+T8+PwfMdVWNehAAgFfzk+X8C5+VHJNzUbe5Y4dBVmneSjCy9shDOyDeqCoaZTe8Cr6mnE2KBG7IvYEWjhKCnp2mPcCjEJ7u+NMzY8fwIgKb19CTyFeLCIFl4peazH1ewBRH5l1s4IZC5yekIQwLblCmXRUeZopCYOulxqWP/ubY0TM/Rc5dcRAT2j2k1k7s82glrHw2PzNF/fiuDI4unrStwUOpAODuHH4MmGKDfoQtW0rQDY0U41w8CthUoeMi+S486VZ0QNyOkRbWm3So3VOiQvOVWgvs5jcM5WSpk5rZF69GUTDlA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AS4PR07MB8658.eurprd07.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(4636009)(396003)(376002)(136003)(39860400002)(366004)(346002)(451199015)(44832011)(41300700001)(7416002)(66556008)(4326008)(6512007)(4744005)(66476007)(36756003)(82960400001)(8936002)(54906003)(86362001)(6916009)(2906002)(6486002)(53546011)(6666004)(31696002)(26005)(38100700002)(966005)(5660300002)(31686004)(6506007)(186003)(316002)(2616005)(8676002)(66946007)(478600001)(43740500002)(45980500001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UzNnWnRUWVNnZTVIdGlWb1pkYVcySU02VlhUMk5FRnNsdC83bmNXb0hVcEww?=
 =?utf-8?B?dGNQQUY2RDJqcURNaHlkcVAxTzhSUnRtTzlOSUtPNHpIL0lOUFZUMkhYb2Iv?=
 =?utf-8?B?cUVBNXcrWGN3bTlYRmhUNHVmVmFJMWJyZVI2dFVLOXkwNGpqd2xYS3RZWXFp?=
 =?utf-8?B?UWJ3bGdMMVVsOG8wTTdKQy9yYzZHQm53MDFuc2tDbllHdWozTFJOK0R5NG41?=
 =?utf-8?B?KzNEcTdueUVLOFRoNzJqdFVraWkyT2xqVFFraUZlajFsZTc3S1o5dzUvMmVL?=
 =?utf-8?B?RENVdkNSUkUwZmhSa2NNVVJiN0E0UnVsV1phRkw3eVp5RXAzSERYYlBWLzVa?=
 =?utf-8?B?dDNEZ1BFWDBId3YxSlJTS2x6WWQzd1hQQk5OdEJBRjZQeEdhVklINjdneVpQ?=
 =?utf-8?B?ajFDRkpuTnROaGdtMW9nUk0yK1k4WC9vK0ZkTVV2ZTJ3a3RyMTlMeGo3ZHJ3?=
 =?utf-8?B?d1kzNkI2QjdBbC9KcFVvS0d5OW5OUndGQkFCRWRrbEJDNExQY3J5Z1Q4ZGZS?=
 =?utf-8?B?MW03ZGJ2YnB6dFAzaWlqU0ErYkRmTDlaSWtmWDNkMzRjd3JNdnpyeC8wZEpi?=
 =?utf-8?B?SDJnb2NlZEdOWmZsSVAycnZiRTQ5dEYyVWpiekVYa3ZxSCtnMWRuOEpnOFJ6?=
 =?utf-8?B?YTcxaE5oa0lTbkhwekpTbkdQV2crZEF5R2FldStSWGdxNmpvOWJSbFAwTlQx?=
 =?utf-8?B?OUVqNldHeVNnUjVTdVlNb2Z1L3pRSVhIeVROKzA0dzNOd2c1MWt4TktiNlAw?=
 =?utf-8?B?aHRRcWo3cFNsOHF0SEJpamNJcjlJc2RRV2FYaDloOWdZS2dQUno2WjIzL3BX?=
 =?utf-8?B?SGFkTUFJSHdlUm1oVkpjV3Z0bUc3R09TN3orSlVQRHkzMEljd3VubFRIREFo?=
 =?utf-8?B?aVRpdDFzeXY5YmZFaXlSbmtoRnM3dDJ0WEpHNzBhR1FLVldPWmNENkVPNkpQ?=
 =?utf-8?B?aTNDKzJRdkEvbDVweDQ3RHpldmxpV0Vqb0xDTnlQZlhCRVpEa0ZZUDFWSmx5?=
 =?utf-8?B?eXlDQXZudmx4eWRMbVF3clNWaEp1SFdncmNDd3dnam9BK01sZnNLRFdqNFF4?=
 =?utf-8?B?RzdPTFBrMGJrRk80RjBWNUJoc0xpQXRJVXRVVzVJeFBDV093aFB2QzlWUUYw?=
 =?utf-8?B?ZzdQVHczbGVTS1kzSTJmdXNsdEFPZEVpVFFFdUt6V1h6NWlQSmRQcUp2SndF?=
 =?utf-8?B?U0dDa21kYTJFdFQ3VXdpR0ZJWE5UWkhoNUI4RmNBSmRDN0V0a3hqemN3Mlpw?=
 =?utf-8?B?T1Z4YTRpT3dDcWh6L1dQajlaM0RLeFZ2anFsYm1GamVvYVRRWkFNanJHZUkw?=
 =?utf-8?B?emhHcmlJbWpKWSsrN3VlWVdWWEFaSTBXYnNQQVRmdm51V2oxeTNRNmpYUU5F?=
 =?utf-8?B?dGsxUUs4ZHg4RWV4bGtPZXByc2Z2VmVMUHBNbEZFK3Y1a3N1WmhzVzBtN0xx?=
 =?utf-8?B?TUV0emFsbWhHRjhNOVUxdWlLMGpFcm0xRzdpSnBtMnpHakxoSzQxVkptSXQ5?=
 =?utf-8?B?NnA0Y3UrNEcyOFlsWmorUE5KSnE1UWZrZy9hdnZjVzd6Y24yTlBRUVZXRGtj?=
 =?utf-8?B?aHNJRmlmNnZYTytqWDRzNTRJTkdtQVRCTVFBRWt5dTVVU2JmY3pUci9SdVFy?=
 =?utf-8?B?K3Y3QWdnSlNXV1MzZWhuSXgvUXVDcFpYS2dQRHlBVmhtMGs3STNsaTdMYzRJ?=
 =?utf-8?B?d0d1YnB0SVluTFRlb0tXRDJJMFhNRGJvSDN3NGtwUDRQeXE5T05tNjNONGxy?=
 =?utf-8?B?YnpMUjZVaWsvd0lPOVZ3NE9CdXE3SnVzWS9waVNndHM5K2J6K1ROVUdhZkpQ?=
 =?utf-8?B?Qk5pL0Roekh5K0VLMFcxNWdIT1FlaDhZMG5GZTFDQXdXZkFWa21RVzdjbHlt?=
 =?utf-8?B?ZFV5eVZFQ2NPVGd0RGJLaE5RckQ2cnBoSnF2aGw1U1BrcVdSUGlaUldyYVoy?=
 =?utf-8?B?SUJSYkhkMnJqNXVzdDZqK1lNSC9CaXUyTUVtY2xOWnNZNzMvNXdybFlydXF5?=
 =?utf-8?B?TUc2UHg4cWlUWGNKMGdGR1krTjBIZmpRNDhhZ1F3WG5FZmdlTVpDK05Camx3?=
 =?utf-8?B?YmlMQ1NydTMxeCsyN0VRRHV1b01mcUt5RzgrWnY2VVhlYStlS3FUOXZqM3VW?=
 =?utf-8?B?c2UyY0ZyQ21mYjNLbjdRREFHNGRqcThJZU9UcEsvM3MveG85a1BlYUI0N3kz?=
 =?utf-8?B?eUE9PQ==?=
X-OriginatorOrg: nokia.com
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DBBPR07MB7625
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=LYHZK5Hv;       arc=pass (i=1 spf=pass spfdomain=nokia.com dkim=pass
 dkdomain=nokia.com dmarc=pass fromdomain=nokia.com);       spf=pass
 (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.6.104
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

On 31/08/2022 11:30, Linus Walleij wrote:
> Pls keep me on CC for Kasan ARM patches, thanks! (Maybe I should add some
> MAINTAINERS blurb.)

there is one patch which barely triggered any interest, but the problem has been spotted during
KASAN usage on ARM ("ARM: module: Teach unwinder about PLTs"):
https://lore.kernel.org/linux-arm-kernel/2bb016da-363d-5aac-fe7c-066cfe52d738@nokia.com/t/

Would you like to review it so that I can add it to Russel's patch system?

-- 
Best regards,
Alexander Sverdlin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a53ee90-d49d-afb6-050b-4649631f8910%40nokia.com.
