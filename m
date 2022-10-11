Return-Path: <kasan-dev+bncBDLKPY4HVQKBBA4JSWNAMGQEGFAFS7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E5E05FB061
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 12:25:08 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id s30-20020adfa29e000000b002302b9671fesf1691650wra.20
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 03:25:08 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665483908; cv=pass;
        d=google.com; s=arc-20160816;
        b=SOfhCHGwBC1KARi6P9JTw9DpI6hTWPjIjhnr2wjZdC7Nth1EwbbYKZcpAd/qG4Xli7
         G6zBvo/MlOlPxz0X58DN3wd0I03wucGhKbhpdZlrGFBOimBlu1QdBsYVog2ttt9w6jxe
         FGgq8fceclL2hywez14RLHM6Z5kvuu8Onzvmb0yr1xHQsDDo1ev4OgipTwVlTHYd+niu
         On9FtI9vWkqnJV8TsPEVSRLEg1Ux6XlmPKHofVO+DH0Lt3by70L7VFkZPIY71vYnyBgE
         M89J65pU5nVC7sPXeeFOTKyg+ehol6s+5oCHu+KUXtcvd8sicKwDMotURKN1y6dk9mnE
         HZCw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=Oev1FwVuRlOzFUDg+1TYkCabv9pJXOfIOAjzBnHAzpU=;
        b=Zaik8O/Kp/zvk41PaO7ew3/V1zD10WDddN8yAcLfo3/Y2LYpNC5tKH1kniSDmLlYIk
         Ezs+Zm4dvMwIscP6hdVZAO8IDeqEEsZNKtqPQdy9NTYe8TFi6uUoAIOVICDNMkt1tdof
         0YCKnTlpR2AiSOo82xLS6nJH1GhPzilBMj59FuM++Tmhe+cQC8V75sbGq7LC5DZpLkms
         m/UB8c4XSva9pz6MVGE0i+ItMrGOXwijoywID3nWTCo0YvibpQBuQO/a/ldFFI0/+8h9
         PGepwDmKlZjIg8J9MeNYk9wHxo0MkPnQ6KRI4qM72HQquKP7B3x3Xe3zfm1cLg8r8lCo
         ZctA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Ry0Gc4Mt;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Oev1FwVuRlOzFUDg+1TYkCabv9pJXOfIOAjzBnHAzpU=;
        b=p3HcQJIebjV9ledcRx8dAjsG1IJZaaGWkCBgyIfJDs7PQiJsfyfeCIzFpuUi4wwSdE
         v0hN7BZuedD5DaPwB8WHzhIpuNl2fxgnJRDyNnLN5uBApPlCbEaLdTzuiLuRrksysaqC
         mU6jlPnazd7JWVOJjRMcjU1cQ+sHnxUDsCC09flBnR0HCw7Ja2TZrJKkwlZDSok4Fkip
         zbRu2CayDXLJRjZ51QmpAniUReub77cm0/ZFNCS1Ja8XSvQoyOtju2GHNRMiOd19ssK0
         zI4glpD8rAE1+CV0PHHry1lQyrviRahAzZWsTr36qDca5juKn1EGH2usIyh6PYkAOHj1
         ckSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Oev1FwVuRlOzFUDg+1TYkCabv9pJXOfIOAjzBnHAzpU=;
        b=eLN3kdzCBQeFnWkztsNDF4U9gNb5xfIgiTc+QWnjzJOQsgcvifVPmEy/u265nq75zM
         PZfspVk06FVrVEBOXCtMSgRCOFpxdX6wT/ZhjbYjXZCSUWJGNqr3mIixZL2mmK6utOTh
         Jw982xnXaVDhAQ8DUkwe1e1CiympNnXoW7L64ymwXUjozRKlWcI5hfzztHa2hLNz1Nfc
         Tinupxb7AQ25l1kFEQ0Bn1g5l4H4BwS6+2io8KcwacFW9acov2Mc0JZcTHaX3997s0k2
         t7poRXRmz++h4bIzQ+eO2AiuWk7PJPXICOP/9bGq1enu/spXQA+YHyQG5uq+Xus9G4uB
         Lhgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3buY8Ajnarpo+iO7FdmqL7s4L8FaBQJmCPrnmjO7KzUPAZXi8a
	Q28iSzzybjy4aylbvRf7HZ4=
X-Google-Smtp-Source: AMsMyM4lyA87NqNbv7GKm3rUn4JiOKJd7Nfm0f9+hU+lvGStnerzeLqaR+vpzN/ZqxdJGJxNunUGUg==
X-Received: by 2002:a5d:5109:0:b0:22f:ed4:65da with SMTP id s9-20020a5d5109000000b0022f0ed465damr11180110wrt.688.1665483907949;
        Tue, 11 Oct 2022 03:25:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:70b:b0:22e:5d8a:c92d with SMTP id
 bs11-20020a056000070b00b0022e5d8ac92dls14421100wrb.1.-pod-prod-gmail; Tue, 11
 Oct 2022 03:25:06 -0700 (PDT)
X-Received: by 2002:a5d:6dc3:0:b0:22a:bcc3:21c6 with SMTP id d3-20020a5d6dc3000000b0022abcc321c6mr15310594wrz.450.1665483906852;
        Tue, 11 Oct 2022 03:25:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665483906; cv=pass;
        d=google.com; s=arc-20160816;
        b=x9hTR9q7EyDVmYzwB6qT8KOVXeTuOB2QgaESJFuhr1nXBAFJb8oFsSDBQg1QVJ02hI
         6TBMwXqATaOaqoynLfhXMUKSYCx2O/bLW38iEvdaVNpqBlWS9j4p3aX4J731/bCnFcVY
         yVs1NOAs3INeRvfTlD7GQrSP898LJvjd1CIMa6rnbWzIabXCOaq29kO5goBlNpho21KE
         c7GOB4KuQtxZl7bMxnrS6cExFA8SrjN50XR2jcIpy1KiJD7moWgjTiSbmaF36RnIueth
         ivY/Bx2OP2V3GglHuYahznrbq1cEX7yjpAshJuO6ueMH/7edtrElpVGB1LEjW7e1SJ80
         W1tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=cgd4mnY7P5DmOXSw4Lg++69yeLfjIjcq9KZ2asKTS24=;
        b=PDD/9OnZ+EiHgNt+GCpCCHOZUXSAPaMuUO41wGWFIp7z4ns10/LxKGzIZQ/mz/KcfB
         8F88iz09YlxY4HV7hn/NltEiWJI94R7zQ4f4rLaN55KBHyeSFfHdBYcrRnWo7a0Oo3Uo
         O0dnG6mx+pHS7OmpShH7GGp9spqaSm5jiwEJjZinmrI8xoOiHy+fIDlwC6/cv6OTtRRq
         QHe5UY+sfNaVQOaH9QqtcCPPL17efH/77f4QTX62Bqc5pzAnwsSmgH/gO7/k6FWQW46U
         olz/2JUrEj1qvTIWYHPLrivQHxlrUH8888PfjIZmoLCL/H2EODi+zwD/+px2xPNRWbVh
         nZ+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=Ry0Gc4Mt;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90073.outbound.protection.outlook.com. [40.107.9.73])
        by gmr-mx.google.com with ESMTPS id ay28-20020a5d6f1c000000b0022a69378414si473706wrb.0.2022.10.11.03.25.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 03:25:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) client-ip=40.107.9.73;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VRYcE4n4P9JPVJbrsCNXZwVl7d2Ar/sHe8fXl9PS/tQbmMLslR/pTWOJFflp+juh11P6WyKs/ZtwFlxFtAjlTfojEa43GE7rkV7VOHFlkGWiZMRDKZI5pnUNFDxLpG9vCt8Y6MO48uw6khBwgxvIG6ZIr6AZN6/GUkPwqtlyWJoqDxdo3zLIbXJdB6rUsKnOOTOlehn7490O4iU4UNXspoymkKPpJrJGtR52RwEtqMYz2I97EePC6p8jvndAPtRFMLkr1nSs7D9y50iGR+R/sqQ45giWstqGFTTKIDBGZb4qVeUscApmz7nVPUI7GOcMVt8suu3WzUBbuRigkaUpWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cgd4mnY7P5DmOXSw4Lg++69yeLfjIjcq9KZ2asKTS24=;
 b=dfUXK8u391JP/6w/c4EYZTJwCucNGNpOYni33YwLCY9sNQTcnhjjflOCoH/Fp7UGvePR2XrmFwWv4jxjPjEstqzo75xvdutUfD26Uzlylf9oLFEQxkJ9H+Kf5s8z0sor2GQWIHklLQwk/b6JbLUdOCtmrVc2buqsx1kUPMR4wMEBVcAc/ky3AwVFWFo7SWCTxZxM7P92N1nxOd6ZaYmSep/7gbOthtKvjU24kRZzS0Zt66k895BJa1B/x0SsnvO5GassROAG+Tl2AjZOHK41xS4yLwmsqd9WcWztb5bidku1iR+Ndq+1THbRGhjWDFGapVFNfygui4T3Tt6K/Krwtw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB3289.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:110::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5709.19; Tue, 11 Oct
 2022 10:25:05 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%7]) with mapi id 15.20.5709.015; Tue, 11 Oct 2022
 10:25:05 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Michael Ellerman <mpe@ellerman.id.au>, Nathan Lynch
	<nathanl@linux.ibm.com>
CC: "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Topic: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Index: AQHY2EIBh+iraNEA6UKZa+r/wPzLXq4AwrWAgAAPGgCAAfBWAIAE8XqAgAFMbYCAAAbegA==
Date: Tue, 11 Oct 2022 10:25:05 +0000
Message-ID: <0c46ba45-1fff-d067-159c-1951c5985de0@csgroup.eu>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
 <87h70for01.fsf@mpe.ellerman.id.au> <8735bvbwgy.fsf@linux.ibm.com>
 <87v8oqn0hy.fsf@mpe.ellerman.id.au>
In-Reply-To: <87v8oqn0hy.fsf@mpe.ellerman.id.au>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB3289:EE_
x-ms-office365-filtering-correlation-id: 0e6bdb7c-7bb8-49a9-1990-08daab72dd36
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: mH7k/7ON1I3KT9rMoyJzzVTlDT6dJJgmeu6XPMsIntqIMGY+Eb70vFBtTb+CtdE/8Q05rXfhKP2GCtNpV4oe2oVaJWihW37+8plE1iOUyfIdnbPEx3MKBvXx/30IoPgZF96o6amMdjbZv92ef0dKHYji3kUN9pKHamQ6AGQzBULgE2i/SBZyN/Hr89wgrRi7q1BXbed1de+vnUuZPcQ+xMm6PTR0mcEGhPA+BZljqQB4c5srphFqrEvX8QImj34DQ/e93U8BR3iIhvqLmLqPKtnuttfyH7lTyPz58pjfWgVb+Scknetz+kuvOmG487HKpAMhPaZReubbfchQeYTWPQ17/7nA5uRRltWa8uAScaref2gclnogSq4KkzqYq/tbXcIK55Bb4oxFX/mrhsz2QxHOsfzEYzn5md91n7Zl2Z+PwHM2c0wwaVuEVhv208uoMYQTuJQ3bS968O3oW8MKyv9Srpl3/W/8T7Oqec+qjUJ/kDLE+8bUs+/NZFdu6s48fzrje2LBeoGhoCuE+BzsZqcpCyC9iASrAXIoeAgYMZB5gvRMM8Z78kxdXgCMvbSgHl1RasTF5Qe2yT534si7+LYxsWddhQzxeZ+4IierQ6y1a5K1kVelyM9iC0x6h1fWnZm9lcc0VfjqVlm5bnBCFeZHbjehspNDUp4txX7aeEWzIOnS+QoWDgSd7SPle1qZQBcwcXSr5qyvudx2dlR/72uI3l9LKWUqcpjYeVXhhCatLDCKkKEjWHvWJgBtbyYlj1SLI35s9nAi0znE5O4Eqz8fEIreKmRkewjusNw9irIhHpOhFXpeiqMeSd4IYmoV33h4/0qIHvdGAUmUWn7kAw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(396003)(136003)(376002)(39860400002)(346002)(366004)(451199015)(5660300002)(66899015)(8936002)(31686004)(44832011)(31696002)(66476007)(64756008)(54906003)(66446008)(110136005)(86362001)(91956017)(76116006)(66946007)(66556008)(8676002)(4326008)(316002)(71200400001)(38070700005)(478600001)(6486002)(36756003)(38100700002)(26005)(6506007)(83380400001)(41300700001)(2906002)(186003)(122000001)(2616005)(6512007)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?MGdwREJkZWliRWZjekw5ZnltRjZpVGVkOUo0ZEhMOTVVSnhtMHM1WE8xN01O?=
 =?utf-8?B?M2ZMU0dsOFFlNnlMcUNUMzl3L0I4R1FSYjZkQzFFNWhRMkdUSWxzaVFYTDND?=
 =?utf-8?B?MzNzYktXeEE4azBEdk5QRUtOc0xzSjBUQlJFMkdUWU10d0hBMCs5UEV6OVFq?=
 =?utf-8?B?aHkxVURzU0FmRzJ1a01CbHA2b3gveGFoamxWOHFxaDJUVGpYOW9PaCt4VDZP?=
 =?utf-8?B?WS9ERkdwNnRNTUpaZVRCVWV0S1J0K1RMQlo4V2pjZjJuNWZvdUxhOXZ4OE1T?=
 =?utf-8?B?RGlrR0JpQXBvcGhpc2k5ZytaN0kzMGV4Y1d4L1FDWHk5R2pPWVFiTk9DaWpW?=
 =?utf-8?B?eFBKclRDRmJUd1JzRkxKYThoMVUyTVFsdFRJWU9WTSt1UGJCeCticG5aQTVW?=
 =?utf-8?B?dnBhR1Eyd3QzbzF0RlNyamtOYjZBQmZ4bXRqT3psRnU1OHZuSmZMb29TdU9O?=
 =?utf-8?B?bER6VkdJSjhrZHFsQTJ4MnR6a1BHSjVrUnNTMk1OUlhWUlRtNkR6ZDB4TXVp?=
 =?utf-8?B?Sk5ld2NPNHhsUUJ2dkd1T0JSY1FVNFdZY1V4dW11eGEvTUY3SzVVRy9UYUkv?=
 =?utf-8?B?elYrRWRtb0lpbktZRHRTcHpRdWg3VlJGSDdIM0FTbUFick1iUHNjYjhzN0xZ?=
 =?utf-8?B?MjRJK2o4VG91TjNhMHQrTDZVR2g0MzdaNzJxQjZRb01QYlZRS0FLMjNidytS?=
 =?utf-8?B?eWtkTzR4aGFCZnh2TXIrTHpSRDVyT0tnTXZlU3F3R085dEJmVmF6MEtuY252?=
 =?utf-8?B?VDczNHIyeVJWMzVXT2ZhaGxLUTdIMjhHWVU0Mmo2NUt4ZXNKL3NiSUlodHJQ?=
 =?utf-8?B?dlNyL0FzN3hsUE1ZSHNyQU1sNU8wbE5sRmswdWtWK3dVbUpMekJOV0x1TnBx?=
 =?utf-8?B?OHpaTXRlc2ZJaW9BbW8wQWoyR1UvYUtqdGordEdKbGM1d2xyVlpXZytCcG1h?=
 =?utf-8?B?RVBSeERoUzE4SFhkcndjTnJVOXd5TEhScnFlS1Z1VEQ4ZVJkajRsQyt0ZFlC?=
 =?utf-8?B?VFV3V243OFdNb3ZZdi9wL2dIS3hSbGpYQkJuU2J2eEpaQkNpcTJZZDFmYUNt?=
 =?utf-8?B?bkhCVUFONmtXL1pZUUM0aU9ySFAyT2E1WkdTUzF4eXJxckZiRWdGMnpIcGxI?=
 =?utf-8?B?Y2pVS05UY25TaHJ4L0IydDlqeG50OXdXZ2pkVGdLSlJEeUR5SUZBOWhEK1dI?=
 =?utf-8?B?R0k5LzVZd3RUbmRHdVExdUplTXVKVzZ0c3hHT05kOFUwb1BNRVpJVHpVUXd1?=
 =?utf-8?B?NGtzcU00cE8rY1ZYZ3FzNmtCREl4TzZ1OU81Vk43Mm1KQkx3MU9CZktsd0Yw?=
 =?utf-8?B?R0l2bnUyMmhWQ1NYZWVBdVlSOGVab2tGWGFXRkVYdndoS01DRC84V1lBbDNY?=
 =?utf-8?B?aFpEYlVQcUxnUTNVUCsvMmxYSWpmeGVHVVNzeE91bXpkd1Q1bU56WFo5dDRk?=
 =?utf-8?B?NmNNY1A1YzBPdk9TdjVhK3Z1S3UvUEtjc3FrZDRQLzZLZmwzbUhJTlAybFJ5?=
 =?utf-8?B?Zmw4R2k4NmxzUHhkY2Job2c1dkRZUFQ4Sk5nTk1FTmh2NThjcEpTNG5xQzgr?=
 =?utf-8?B?MzROcXBwSjcyRzBqWGxWdXBtUHdwTmdqbUhkcW1oZkhtWG41R0MySDU5cG56?=
 =?utf-8?B?VU1EbXd2Tnc0VTN6QndFSDBvUkZmeDhGUUE3UEpwcXdvMFQzSnVTOUR3N3Bk?=
 =?utf-8?B?NDh6U2pHTDVZeGpiekpuTnhIMUJuV3dZdS9ya0VKZElraDlUNDEzUWNYSjUx?=
 =?utf-8?B?K1JhRExLVzFaUkpjcWZZeURMcmRheFdzd3AxeXNXNkJ3M0pUY3UyY2RMdjVS?=
 =?utf-8?B?VFA5Ymc4ZHFZb1BQZ01tVG5LWDZpZllRc1lzQ2FCN2o1b1l3dDBJUEVoSS85?=
 =?utf-8?B?cGF3VVEwMFYxWWdva3JUQ0lnY2E1enlQWmlWc0NwQWpEWUZydjFISHprMFBq?=
 =?utf-8?B?S3p1Ym9RNmY3SkdyTmJxaUl6SXpXUlNoQUUrd2I1WjhpVi92bi9oVHE3cjgz?=
 =?utf-8?B?TDZsdjhWa3RsMWdwWGRmNmh6TFpQcHVsZ3dGSERNd0NpZHRnYmZLM1AzTE1Q?=
 =?utf-8?B?RjQzRWNaYVFuYk1CRXZkVzZ1SVJlaVRYdjd4WkpFZVU0QTFVeWcwWXc4RUY1?=
 =?utf-8?B?K1RrREFhQUJoY2FQRjNLVDVpeE9ybXRaK1BRbTFrcmNjck1BNEhnb3dGTzYw?=
 =?utf-8?Q?00DH4qRLhFwQzlVz3WoG/CI=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <1C43762274521B42A6CC8F7BBAC45A4D@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 0e6bdb7c-7bb8-49a9-1990-08daab72dd36
X-MS-Exchange-CrossTenant-originalarrivaltime: 11 Oct 2022 10:25:05.1653
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 9xkzBGhRCkAA+tMW63EtjJgtC3Bost0CM0rtvXK8jIXdxx1gYBbywPhGrSOjRd3oFKAcw7z2HE3z7UHEhSy5KcCkYuV2Zw0Mv+v7j0RTRIY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB3289
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=Ry0Gc4Mt;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.73 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 11/10/2022 =C3=A0 12:00, Michael Ellerman a =C3=A9crit=C2=A0:
> Nathan Lynch <nathanl@linux.ibm.com> writes:
>> Michael Ellerman <mpe@ellerman.id.au> writes:
>>> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>>>> + KASAN list
>>>>
>>>> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>>>>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>>>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>>>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>>>>> KASAN support"):
>>>>>>
>>>>>>     A kernel with CONFIG_KASAN=3Dy will crash during boot on a machi=
ne
>>>>>>     using HPT translation because not all the entry points to the
>>>>>>     generic KASAN code are protected with a call to kasan_arch_is_re=
ady().
>>>>>
>>>>> I guess I thought there was some plan to fix that.
>>>>
>>>> I was thinking the same.
>>>>
>>>> Do we have a list of the said entry points to the generic code that ar=
e
>>>> lacking a call to kasan_arch_is_ready() ?
>>>>
>>>> Typically, the BUG dump below shows that kasan_byte_accessible() is
>>>> lacking the check. It should be straight forward to add
>>>> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?
>>>
>>> Yes :)
>>>
>>> And one other spot, but the patch below boots OK for me. I'll leave it
>>> running for a while just in case there's a path I've missed.
>>
>> It works for me too, thanks (p8 pseries qemu).
>=20
> It works but I still see the kasan shadow getting mapped, which we would
> ideally avoid.
>=20
>  From PTDUMP:
>=20
> ---[ kasan shadow mem start ]---
> 0xc00f000000000000-0xc00f00000006ffff  0x00000000045e0000       448K     =
    r  w       pte  valid  present        dirty  accessed
> 0xc00f3ffffffe0000-0xc00f3fffffffffff  0x0000000004d80000       128K     =
    r  w       pte  valid  present        dirty  accessed
>=20
> I haven't worked out how those are getting mapped.


kasan_populate_vmalloc() maybe ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0c46ba45-1fff-d067-159c-1951c5985de0%40csgroup.eu.
