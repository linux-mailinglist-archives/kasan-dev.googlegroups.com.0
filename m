Return-Path: <kasan-dev+bncBAABBLXV4HWQKGQE5FODR3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 51FEAE8E83
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 18:45:18 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id bo12sf6760622edb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 10:45:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1572371118; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMuZNvxhWAjLMfG19v5seuQlLA4uwlnPhUNsL3zUAkn36c/9WRgAlNj4IPZdk5lZSA
         jITTHiKQOPLzBPCTcT/GqjFuvwCfXgX89BPP82u+xrsx0KLGuOogQ6SQlbvN/suKCmCq
         I/GEPNeY76gXJ4rA8+hy5J8HBrMS0J/U6ahoEfzDmjEA9V7TtxvJnJp0xEE4TGdVasDQ
         +4fwRTafKPpUhWR59DEwfXLgQG3PQFvPXTIopqgQsY1wphJoxzF+GRFYTHYnLY/tWnOs
         R0+E3BstD7mMq1EhG6KmTKKaO9LMBtZcxOpv7qrUZKK9wvyoO6D/XPsNHuXUs2w1fycw
         r/QA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer
         :original-authentication-results:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=2pwZuVbP1UcI0Dw6+uLcEGEleoH3VwusjL68Ux38pFc=;
        b=fjIYrjqrOagnIHetePybjRhzTd3LPdxUCqSku3CwsnHYDZ9A/YMgUrAAEA9BB6lPZC
         9V3XBuzUqnOHnfr9cQHBO2x/bJ4smV/xN18KAB6hSiswh8FzBzWFQqYCx8bXr/fzSOT9
         qRQk0ymMAQYvCFHGyREFSvSJrJKBJH3RG6uhPgm0tiaj2nY/SaAjKIzCIJGR5B9oFYEj
         8laA71MlD3U4V6KdG0LP/MgQ8ugx4Lgrv9yqEsUiFwAW4fY5yJrslZCrvQig+0OKmI+c
         chRJ1axYoN9DJpD0UeMjQJ9BVP7GNAoiyYuzoLjJu8v3fM0EIMIQ387tGtDPuENBOiXc
         cMCA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=3MXtJgI1;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=3MXtJgI1;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.87 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:content-id
         :mime-version:original-authentication-results:nodisclaimer
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2pwZuVbP1UcI0Dw6+uLcEGEleoH3VwusjL68Ux38pFc=;
        b=UOQtNl/p/RqqDJoekvtPErD3HZ3LBoDp0dPIAvTMZeh1OKYzY9egWnUQO7tftV4C1i
         QdnUCMk7yhqNJ9x+rLVMVEBGMSnWM92HF2Wq7R4tt1SEj8lzlFDfZCizUVNURIKYyneq
         jYh01j0LzroE4T80iu6HV7ORVP1FzjtfN89TGBFGTu6EAkcbZhmP6/NEI7enuCiMJL1K
         fh8//jqUQj4RBH2Uklf9od80JqbJScFk0i/11b0iWhK2I8CCzZ71X4/EpuOBXCDF/aQ3
         p2mFZtTVaJNfOCCExZwmriFU4HOnY1NNR/gqBQJJ3CwUx/LrbwpVIN292sUbs71fgMJx
         9ZHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-id:mime-version
         :original-authentication-results:nodisclaimer:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2pwZuVbP1UcI0Dw6+uLcEGEleoH3VwusjL68Ux38pFc=;
        b=rG+ZBxJSMF5dtQV6U54V4ocOxfv36h88jmvVTUJ58Fn6iLwOacZsQ0egMuUcC7Y4VQ
         DwkESPvy3ACFT9t74JPyas+XfYkv6+cs1p2UdEuHEl7FFKBAfGaQYrDJbBcmsBA1CS05
         blrzaOauSGXGsWZ/tdmwnnKwZ9wzeTUZNBzB5C2UQXEmIQUVaD9tUXaRFP+6fqf8X+S+
         6e/lLou+N5ykvtlwPNhn7lEB786Bisob/qDzjKOQdbtHhFY53PvgqBq4UVEgUKtJQ1vS
         xvqwk25WHoZFofvDeSBOeolQKMB+FL+uzsEk+S3sMV+1ShjGMKWcIGHD524ATjhisxCN
         h2xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWCNugwqB2UmlbUxXc34hgEN3luKIBV78I1oJMaam9GFIX/wYIv
	rN5NVlKkSdL20yKnNXOoP3c=
X-Google-Smtp-Source: APXvYqykWu4LtoI6DRw4fm+f1o6/gaqUdpIInt4xV4i+GMiFUcI4AizQfenYOud5Ii+HEIRnFaYz1w==
X-Received: by 2002:aa7:c048:: with SMTP id k8mr16391107edo.254.1572371118093;
        Tue, 29 Oct 2019 10:45:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cd10:: with SMTP id b16ls588873edw.1.gmail; Tue, 29 Oct
 2019 10:45:17 -0700 (PDT)
X-Received: by 2002:a50:9b43:: with SMTP id a3mr24245247edj.73.1572371117785;
        Tue, 29 Oct 2019 10:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572371117; cv=pass;
        d=google.com; s=arc-20160816;
        b=snF3vaVwCxDU4I8p8OmKzm6DAn/sdsPTrhx3xf5GJEnEsPA1CL02WUUbcHlV8O2o6c
         MI0BpnkGjrl8VYPG6sdw+eLjPWjoEWHXp+HohHk4x1d7wmaAAbsAGApPWB+8KlL29KIG
         +4olWJL/HKUQW/ClTtvZjHB0pHeXOj8tCR/1CKHn8I06U6WrjaOi4LG/TNruCK2ddHcg
         IqKdQarvDaXpUzjzkpdjvm3yfbOlG6YaVFQHnIIZzqSF4ZSWkEdj/ZavuUBhlW0POf4Q
         z6PXY8BmCIzUOjN0GE7pCgctXbzuaBA/Ht/04poYgoMcI09fWVhlbtvzcV4SIorqOUH9
         FzfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=nodisclaimer:original-authentication-results:mime-version
         :content-transfer-encoding:content-id
         :authentication-results-original:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=C2f4ba0+DIAXbTcDvgKBAPqZqycbeLVhalNwhvVIA8I=;
        b=DsxL3i+9zsFJ1YY6GYaFcxs5J+IJsdOgUcq8vewdTCwAlH3MPhsXaCUQ7rdpJwUpXD
         eKBeO9rNflEKUDxGk8cX9Ic3QtcSqVMF6QstVQIw4md0Hg1vbWd7jZRuJY7y/Wkg5vxP
         uAljXJgukBMJMTjZIbpwyRpBuVFyuHhC+RJ85bzjpjTvnjLG3+JrZeBVuo2OPmMD1e13
         v3oPO3/xuMJri0fVzQlabs6WVtlU5pjXUPSDdpTLu2kdsq9/aFUIvz01dexeodjQtjP3
         adk8NxYbjREBlZ+9Eo9Xw6h2c/JqoRb/RybB13Oi3w5DAUbj6wcAgH5GPi8JJhOYjDEI
         FioA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=3MXtJgI1;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=3MXtJgI1;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.87 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
Received: from EUR02-AM5-obe.outbound.protection.outlook.com (mail-eopbgr00087.outbound.protection.outlook.com. [40.107.0.87])
        by gmr-mx.google.com with ESMTPS id y21si594144ejp.1.2019.10.29.10.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Tue, 29 Oct 2019 10:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.0.87 as permitted sender) client-ip=40.107.0.87;
Received: from VI1PR0801CA0089.eurprd08.prod.outlook.com
 (2603:10a6:800:7d::33) by AM4PR0802MB2241.eurprd08.prod.outlook.com
 (2603:10a6:200:5e::15) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2387.22; Tue, 29 Oct
 2019 17:45:17 +0000
Received: from DB5EUR03FT022.eop-EUR03.prod.protection.outlook.com
 (2a01:111:f400:7e0a::206) by VI1PR0801CA0089.outlook.office365.com
 (2603:10a6:800:7d::33) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2408.17 via Frontend
 Transport; Tue, 29 Oct 2019 17:45:16 +0000
Received-SPF: Fail (protection.outlook.com: domain of arm.com does not
 designate 63.35.35.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=63.35.35.123; helo=64aa7808-outbound-1.mta.getcheckrecipient.com;
Received: from 64aa7808-outbound-1.mta.getcheckrecipient.com (63.35.35.123) by
 DB5EUR03FT022.mail.protection.outlook.com (10.152.20.171) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.20 via Frontend Transport; Tue, 29 Oct 2019 17:45:16 +0000
Received: ("Tessian outbound 851a1162fca7:v33"); Tue, 29 Oct 2019 17:45:16 +0000
X-CheckRecipientChecked: true
X-CR-MTA-CID: 891c0c033ce6f360
X-CR-MTA-TID: 64aa7808
Received: from b3e228b35fd0.1 (cr-mta-lb-1.cr-mta-net [104.47.10.50])
	by 64aa7808-outbound-1.mta.getcheckrecipient.com id 0AC1E519-533F-4C5B-B19A-7E7E3063B207.1;
	Tue, 29 Oct 2019 17:45:11 +0000
Received: from EUR03-DB5-obe.outbound.protection.outlook.com (mail-db5eur03lp2050.outbound.protection.outlook.com [104.47.10.50])
    by 64aa7808-outbound-1.mta.getcheckrecipient.com with ESMTPS id b3e228b35fd0.1
    (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384);
    Tue, 29 Oct 2019 17:45:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=gnwVceDliHauMDh38OmktJcYSVxalmH9RjF+OE9KRzLYYX/OI5kaZSOf/dbP4GYFc1qUdIwuxYhLUnrXEOAIIlVtZOeGU+s4Dc+uN+NIeC+3Rgr42EUygF+scWRHFIdefckiSb+MidZtwsV+4IIP6f38f4cmeiVOesg6o5StXLHfIcwUs7+f3i2VvLa1UUZD9iR62IlVOL8Y/oquu9TVJy89DrCGetW5vB1Xx0qOnXoUiB+2dk7A9y/l3BSGcsMqxNz9mfS8yJwfYYm1tOym2SG14Jr/aG1F5adojwSVoUVUdovLKRneG5hvGn/RP9Q/T/2K1EH7Cj8qJbXDPLeEmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=C2f4ba0+DIAXbTcDvgKBAPqZqycbeLVhalNwhvVIA8I=;
 b=fubzXrGr4wIWDZqidpImlUWzpMM+XwdSEzDPeHlJ5WElQl7Wgz7UyyTGrnyErvZ392QwrQGOnFb4d1DSseD6qqTpODsWrgygKzTrru2rnKKJ/9arOECeSCk7hQL6mSRdBroj+Aax4NbUhQruGXW60euHBuvqoGmG+PGoz3tpf0sXz6BrY/4OaX5N3SkmlnBV4Mu0JsqWI5R6gfVeC1MQZUhmla93EeAvZ7sgxCF1+tANZ64Oy6pm6vbAf0vWJvyhKBb8peNOWYkApBeBCiU3AVpHpdTczD/usnslH160FmGN8kgSTD0q7NXZeSqz6g+Z3QQkiv2XcG19bun9tw7oWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com (52.133.246.83) by
 VI1PR08MB4096.eurprd08.prod.outlook.com (20.178.126.87) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.22; Tue, 29 Oct 2019 17:45:10 +0000
Received: from VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339]) by VI1PR08MB5471.eurprd08.prod.outlook.com
 ([fe80::6c84:4a3e:f1fd:3339%3]) with mapi id 15.20.2387.027; Tue, 29 Oct 2019
 17:45:10 +0000
From: Matthew Malcomson <Matthew.Malcomson@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, kasan-dev
	<kasan-dev@googlegroups.com>, nd <nd@arm.com>
Subject: Re: Makefile kernel address tag sanitizer.
Thread-Topic: Makefile kernel address tag sanitizer.
Thread-Index: AQHVhCNNoOSr1ytgiEqSG00mmgt5mqddSDEAgBSwtgA=
Date: Tue, 29 Oct 2019 17:45:10 +0000
Message-ID: <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com>
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com>
 <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
In-Reply-To: <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-clientproxiedby: SN6PR04CA0075.namprd04.prod.outlook.com
 (2603:10b6:805:f2::16) To VI1PR08MB5471.eurprd08.prod.outlook.com
 (2603:10a6:803:136::19)
x-ms-exchange-messagesentrepresentingtype: 1
x-originating-ip: [217.140.106.49]
x-ms-publictraffictype: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: 55fc6183-3b78-4a4f-c4a9-08d75c97c27e
X-MS-TrafficTypeDiagnostic: VI1PR08MB4096:|AM4PR0802MB2241:
X-MS-Exchange-PUrlCount: 2
X-Microsoft-Antispam-PRVS: <AM4PR0802MB22410DB06269E73013AD60EDE0610@AM4PR0802MB2241.eurprd08.prod.outlook.com>
x-checkrecipientrouted: true
x-ms-oob-tlc-oobclassifiers: OLM:10000;OLM:10000;
x-forefront-prvs: 0205EDCD76
X-Forefront-Antispam-Report-Untrusted: SFV:NSPM;SFS:(10009020)(4636009)(136003)(376002)(396003)(366004)(346002)(39860400002)(51914003)(199004)(189003)(66066001)(66476007)(6246003)(66946007)(66556008)(478600001)(316002)(66446008)(64756008)(966005)(8936002)(14454004)(186003)(11346002)(446003)(2616005)(6916009)(7736002)(26005)(52116002)(76176011)(2906002)(99286004)(386003)(6506007)(102836004)(53546011)(305945005)(54906003)(4326008)(6116002)(5660300002)(476003)(81156014)(81166006)(44832011)(486006)(3846002)(31686004)(229853002)(6306002)(86362001)(36756003)(31696002)(14444005)(71200400001)(6486002)(256004)(71190400001)(6512007)(8676002)(25786009)(6436002);DIR:OUT;SFP:1101;SCL:1;SRVR:VI1PR08MB4096;H:VI1PR08MB5471.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;A:1;MX:1;
received-spf: None (protection.outlook.com: arm.com does not designate
 permitted sender hosts)
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam-Untrusted: BCL:0;
X-Microsoft-Antispam-Message-Info-Original: dLSKkafpwWbAQ13lwTImZjFNoGNfoTIVcnN8MzcP2CU+58B9giGqqProQe0eMtugFVW4zUYnvI7nRVzJuk6MDVHBnyJNZ/flNRYOGM+ILmHxmJu35DArF3nm7k3pyJ5yUaDLmkAcheInlTmIz6CC5fi7kr03kf/yWNpFT8tQLlYu2cYWFr/zatYAFgOuqn4b4CMTtLyqEoTBFLvbiqYn1E36VVQ05Eqy4CpUUoE2J0SSlRLWhSx/gkxhPGY95v1+FQ8UMRDywwF8ucDSwGGJlKyCoYNtr+IDq2adhKDDv7G19Rqvyc3+neNT7eDXUXkEtj9vBT3T8NueTXOHACilBwAOgtODlD6ziZhFbRiCwwKD7f0sT+/2ic9WXtqXNZkwQ930IYgpTY2gtYOctS8YPeWL9/ZG35AkgZ0Fc4ppm+n/EsapzdGCUAU5kPoAcSg0Mip3W7aeySFyURBJSBbXIfUd6K7UACHeAW6OvoiDN5I=
x-ms-exchange-transport-forked: True
Content-Type: text/plain; charset="UTF-8"
Content-ID: <2B229F439062E84CBB528068120BD8D5@eurprd08.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR08MB4096
Original-Authentication-Results: spf=none (sender IP is )
 smtp.mailfrom=Matthew.Malcomson@arm.com;
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB5EUR03FT022.eop-EUR03.prod.protection.outlook.com
X-Forefront-Antispam-Report: CIP:63.35.35.123;IPV:CAL;SCL:-1;CTRY:IE;EFV:NLI;SFV:NSPM;SFS:(10009020)(4636009)(136003)(39860400002)(396003)(346002)(376002)(1110001)(339900001)(51914003)(189003)(199004)(8936002)(305945005)(7736002)(316002)(26826003)(229853002)(47776003)(356004)(22756006)(4326008)(6246003)(81166006)(8676002)(966005)(81156014)(14444005)(54906003)(14454004)(6862004)(478600001)(66066001)(6486002)(99286004)(53546011)(5660300002)(386003)(6512007)(6306002)(50466002)(23676004)(70206006)(2486003)(76176011)(31686004)(6506007)(102836004)(11346002)(3846002)(76130400001)(105606002)(26005)(436003)(446003)(25786009)(186003)(336012)(486006)(126002)(2616005)(6116002)(86362001)(36756003)(2906002)(31696002)(476003)(70586007);DIR:OUT;SFP:1101;SCL:1;SRVR:AM4PR0802MB2241;H:64aa7808-outbound-1.mta.getcheckrecipient.com;FPR:;SPF:Fail;LANG:en;PTR:ec2-63-35-35-123.eu-west-1.compute.amazonaws.com;MX:1;A:1;
X-MS-Office365-Filtering-Correlation-Id-Prvs: a2a5a633-ef40-4ced-3b87-08d75c97be70
NoDisclaimer: True
X-Forefront-PRVS: 0205EDCD76
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: VOKzN4N8C8aAgk+aAF5bHa1tjCL9dMSAvQSbX2aLOcf1nOSqME4ec0f4Y6QgK/WAKxqNgChxPdA1xCO2REjGrGxWVgsEkwx24vCaR32ImOaxhIHqmYBU9UwuXxMZzIMSTSqQDsWnHXpTbjPnBltu3xsu3wsQC7BxVhxQ/PQDfpRKUsfo3L2fOBSE0DKLsBxCaE4r9/6HchA3K0kB1KQvRgawW73+K3U8N98VF2zMT0J7x5goLf+R0ToyzQz8YGkN/G8pJxU2dTF+McfQiFppMtHTHuHPsuK037808onJ0IS2rPdGe8UNNX+blUUKxIZ7sOJyFGnBsnk3aXYIY5VrsyNkr5wvrRPt6upq8zUEjYxPh+yEY1qUXzQ7PlonnxJ058ROSDD8YU07B/edEhe6RQPyrsw01+Gyzf1wYsTm+RP1KsARtfzY8pYBDko/WxJIJ3alhfyKzm4GVu+7rjFtJZOlK6pUuANm6L9VujXvYn0=
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Oct 2019 17:45:16.8598
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 55fc6183-3b78-4a4f-c4a9-08d75c97c27e
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[63.35.35.123];Helo=[64aa7808-outbound-1.mta.getcheckrecipient.com]
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM4PR0802MB2241
X-Original-Sender: matthew.malcomson@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com
 header.b=3MXtJgI1;       dkim=pass header.i=@armh.onmicrosoft.com
 header.s=selector2-armh-onmicrosoft-com header.b=3MXtJgI1;       arc=pass
 (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 matthew.malcomson@arm.com designates 40.107.0.87 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
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

Thanks for the clarification on that bit, could I ask another question?

I seem to have non-stack compiling with GCC running ok, but would like 
to have some better testing than I've managed so far.

I'm running on an instrumented kernel, but haven't seen a crash yet.

Is there a KASAN testsuite to run somewhere so I can proove that bad 
accesses would be caught?

Cheers,
Matthew

On 16/10/19 14:47, Andrey Konovalov wrote:
> On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
> <Matthew.Malcomson@arm.com> wrote:
>>
>> Hello,
>>
>> If this is the wrong list & person to ask I'd appreciate being shown who
>> to ask.
>>
>> I'm working on implementing hwasan (software tagging address sanitizer)
>> for GCC (most recent upstream version here
>> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
>>
>> I have a working implementation of hwasan for userspace and am now
>> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
>> CONFIG_KASAN_OUTLINE for now).
>>
>> I notice the current scripts/Makefile.kasan hard-codes the parameter
>> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
>> variables, and found an email mentioning that stack instrumentation is
>> not yet supported.
>> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
>>
>>
>> What is the support that to be added for stack instrumentation?
> 
> Hi Matthew,
> 
> The plan was to upstream tag-based KASAN without stack instrumentation
> first, and then enable stack instrumentation as a separate effort. I
> didn't yet get to this last part. I remember when I tried enabling
> stack instrumentation I was getting what looked like false-positive
> reports coming from the printk related code. I didn't investigate them
> though. It's possible that some tweaks to the runtime implementation
> will be required.
> 
> Thanks!
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f9fdf16-33fc-3423-555b-56059925c2b6%40arm.com.
