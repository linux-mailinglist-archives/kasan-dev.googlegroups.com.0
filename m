Return-Path: <kasan-dev+bncBDLKPY4HVQKBBOES7OKQMGQEDGZNMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D51D8563120
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 12:15:21 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id bq4-20020a056512150400b0047f7f36efc6sf923119lfb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 03:15:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1656670521; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/dX/xD7968tNnbR9HdEkj+XupTx/JJ0odhLFSCA41AS4hVenTPTwy/ZC4yhopKtm1
         Xv61Jh3V482XQJaljzZc2fNC5MIZHQWSb6+QeqZWTjEiLPIl5WqLNJU7U8gz8NT2wg/l
         yEAT6gVmCp4WTdCg3yT4gsRtA8T20xbxZXZkXXM6Mtvw/GuOw36Bj7se0syHUM4eZEeN
         ogIYYjnRO9gFd8wp5tsFJ9FB3Cnoj8U8XJKnaSeZlTshwYiOFpoLthJo79WNRFJsLvG+
         KDbv2gPlYS70ldntmkCG+z5xmNoDLI8drkkErDqmgHHGessZMVl9VVtu69s3Xkxc91Ux
         ayig==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=qufB7LwBAg5hK5uih29A/XgmCeEnzNnWVhZpZfaod9o=;
        b=WyzqSSpmxT+ehyCCl+4YB+TPsj6Ftdze6TFqxyUwX+kaaFkl0IxpmItmCt4g+FMffg
         o8v11cx4UrMykgnNfS1e+pAyQyWhA6u+QHTizvRdmwEEcjpMp9byb781Au+/6yFHlEj3
         tWopDjfIyLaC/6Ej0DziRu7orTHN+It+lfAt+HA4m7HoBjMydOK0muIs6/xZBuTN0AKu
         IuRQkcxVkBIfOunRh+NhYe/WmP4WCPgP0NpgthchaRR4cmNdqMXuhV1yj/5iyyBkScfp
         ETAQHfPzJiuh4PSPrzglOBbQ0AVLH8KXkSNGCeQpoyT4mvG1kx9IxhZEGmnMvGY++my5
         nFjg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=kOoTarWb;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.40 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language:user-agent
         :content-id:content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qufB7LwBAg5hK5uih29A/XgmCeEnzNnWVhZpZfaod9o=;
        b=oJvHz31IKH7YNn8pJzf+3EZnLDcEiw2u+LLn8ZQBD1Oze7+N9fm9KuGiMu4TVMc84O
         E6FQgSBW7ejjqie8Nq7UUShd1zqgHobYEFh6vv7JN17rBE/Hf+Zma7qF0eNQU+vX/E2e
         Xu2K8mTgwDCW7JmPvHmvrpTBdj0SI07+J9QOzbvRqqlMsTdYnixo0yy1oloAaoeY2lCw
         3bnF5TvxqSpDikKn+aD73Obu4Fqw6dRtPkwqdxefDfz0idKuU3A3qJvsnjAIvRi4tcry
         XA3fccuFJ9YeYN2bqYhR6vzoiboyOPAuOX4Q6PineMbQNnwcWFDo5VM1Xj6lqIIWA8Tp
         KVhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:user-agent:content-id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qufB7LwBAg5hK5uih29A/XgmCeEnzNnWVhZpZfaod9o=;
        b=QanRajqS7pdcWpurCTKeMzKMknOD4jPhKJHmTOEQXLtIz3zQpe+SuXMcsZMAIR5s+A
         nTm230f4NwGj7hBU1a5nIIq7N8EKQ12RjDDu4oFR43vQZPWW2TLNf2pdK65iU0DJkQoo
         DiNqSTIGh+Ov0nW4NaDJglZ8W42slpZdN6INTgriQe75ef54zv5lyfgKn8lqzzr7gd4n
         5ijSWMvUVED9SDgi95L8vN7kW74sYGvG/c885aBy+kN5uPH/TGK0/d7Ct2G1NAIHLiAd
         NUQ0WsSnMrN0okegu2DuhFVs+zzVmh6/zTlBPGeG5o1h+yfaLB/BsV69+x1/897BHpw0
         dGHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora90I9PgB71fKnRjqHlbRVf3Qs/8WdVFDLti+S4Wzzz4E+754p8Z
	mVPQlQ3S/Z1ASHknBkuz0H4=
X-Google-Smtp-Source: AGRyM1ukY02iFW3I8ceF7DNfTb12KSgp46dQQXwwZvpuVhaNPqeJNCloQ5frUeyEI3QPEo/6mL7tMQ==
X-Received: by 2002:a19:ee0e:0:b0:481:4727:be80 with SMTP id g14-20020a19ee0e000000b004814727be80mr6317274lfb.162.1656670521179;
        Fri, 01 Jul 2022 03:15:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b041:0:b0:25a:7050:86fb with SMTP id d1-20020a2eb041000000b0025a705086fbls5633837ljl.10.gmail;
 Fri, 01 Jul 2022 03:15:20 -0700 (PDT)
X-Received: by 2002:a2e:96c6:0:b0:25b:ca29:4cdd with SMTP id d6-20020a2e96c6000000b0025bca294cddmr8085881ljj.407.1656670520044;
        Fri, 01 Jul 2022 03:15:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656670520; cv=pass;
        d=google.com; s=arc-20160816;
        b=VyGcTOdV6q7S+DBDROK1T5NLllC6gppfGSgvxhJJawQkbVWJ+0Q6NJOLNCN7zm3VaN
         3E3k9p9I7wlTbBh9VBxJUNsLPFBDnoOldEDzszxkMJjTpsjcZsYnHhjIiuWQyi5QS053
         yK/zI36mHv5W0upxDq/kcmC3ZXIjDazLqyiW2QTrmEcdmTLPWtwVI1oTT7e5lAZAqANd
         gGg3v4BS4oYl37arCQpsaJEx3UrRUoJd7+dFp4Bjo2bsdc7yIM6LFWPyPDx4eWIf1CiU
         YWSrPSjmyxmQziS43DfjQlMb7+XfOjFSyEY1pyzFAmcNwYUHIkajAeHzizu4oyyRkhzZ
         SPtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=ocCRJjkqO7buL2mBeRsOB2SD34qpk9FTwN+Vhknt944=;
        b=RKJu7fAQcI/JI3eDuXtcjfv/wCKZ/2skR1ac66aK9QNkha2z3muzp2b+L+yVk93VmP
         OSVKaLDUr0fvUD3KCRqcyabVSB3ksXNLFCTU0Y02DL1DpwedDWpLAvTbHnu9PYO1q+EX
         Zer2bu3xyZg/itH8LmNa1Y8eTAE4KEfWS1xJmzaiXxjuJcN4DSeu/EH1L2XvGI1plFRE
         IRMWf5hk8dccm5OFvy3X3ymDSi7Umz7HWJTs61yVblw8Po9J41XM+LfPK8HilYzOTi0S
         8SNHxUKfB4n1QDVtB0GvCe8dehtrMRkgOIEYCl/8+Qyg6XLcwM8YyVlwF1NigpvQQN9R
         cpwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=kOoTarWb;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.40 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-eopbgr120040.outbound.protection.outlook.com. [40.107.12.40])
        by gmr-mx.google.com with ESMTPS id g14-20020a0565123b8e00b004810be25317si682951lfv.4.2022.07.01.03.15.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Jul 2022 03:15:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.40 as permitted sender) client-ip=40.107.12.40;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=UxUzIG0ynPRDwqHrTyl/Mu4VUHpYx0Y4jiDtBGWKop8ycdPTA9rBFToQP1xU5y1+m9EUHQIZieNfYmAn7o/vdaFSKFPTDCTf1Kp0U54kUWaOdyL4bspsh5MtzU6DRcDxqC6dQ77xDPMijfGQW9ZQL3jFtS6jgwyqkRenbQIQwR7DUK/xPat39KpzmpPq3mIFaY/oWn/oMtj/n40QhhGmiVZ1ILUWOwVndUR3SiBDRVGXtPs52ajwkXZfl/J6EMYmEuk1sWiwTVINWcdxOYpyYuLnBKnWl1GHgYCkouDKM64kPfuEFsnARm/8YSPns/zMpUaTE47Bm80og03tQJzCWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ocCRJjkqO7buL2mBeRsOB2SD34qpk9FTwN+Vhknt944=;
 b=SGazAHxv28n3ZYElqCHMsenA2/8CTuALwK7tGz0L4M9Xc6QGNSn+D3j+H7EgnXIoaFQambjgpwG8d085heQlOk66ozjaftNqAzUl0celOidKFgaONgKKxKuNovh0xTWv4wFpS5UUhzdVPaR5xccZHvniYj+LcwSl0cctPqOnSPlT0gcGy/YKaBxgSioyKSvYEKolX2dmkrjuuVSZt3jxZzg6xyw3ckXkfN6ZD1zkTM9aHK1rWRSAOoG11XQwLs6IhoTcCzeKex+d5NrDSoLmjf9X5X7ZU3Jwuqd32mOWoMFRKyUWvA2GPuGBWzXGNqA6T75JnOUKoWkJwDz5Dq1Gfg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR1P264MB3759.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:142::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5395.15; Fri, 1 Jul
 2022 10:15:17 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e063:6eff:d302:8624]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::e063:6eff:d302:8624%5]) with mapi id 15.20.5395.014; Fri, 1 Jul 2022
 10:15:17 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Marco Elver <elver@google.com>
CC: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker
	<frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>, Mark Rutland
	<mark.rutland@arm.com>, "linux-sh@vger.kernel.org"
	<linux-sh@vger.kernel.org>, Alexander Shishkin
	<alexander.shishkin@linux.intel.com>, "x86@kernel.org" <x86@kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, Arnaldo
 Carvalho de Melo <acme@kernel.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-perf-users@vger.kernel.org"
	<linux-perf-users@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Namhyung Kim <namhyung@kernel.org>, Thomas
 Gleixner <tglx@linutronix.de>, Jiri Olsa <jolsa@redhat.com>, Dmitry Vyukov
	<dvyukov@google.com>
Subject: Re: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller
 synchronization
Thread-Topic: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller
 synchronization
Thread-Index: AQHYitZo2ef+XoeA/keVuMHbOZq9GK1pOsOAgAANBYCAAAl3gA==
Date: Fri, 1 Jul 2022 10:15:17 +0000
Message-ID: <45396b77-4acb-817c-eeae-9a672a92611c@csgroup.eu>
References: <20220628095833.2579903-1-elver@google.com>
 <20220628095833.2579903-9-elver@google.com>
 <045a825c-cd7d-5878-d655-3d55fffb9ac2@csgroup.eu>
 <CANpmjNOeyZ0MZ_esOnR7TUE1R5Vf+_Ejt5JRQ1AoAmhkCrVrBA@mail.gmail.com>
In-Reply-To: <CANpmjNOeyZ0MZ_esOnR7TUE1R5Vf+_Ejt5JRQ1AoAmhkCrVrBA@mail.gmail.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 4e66d82a-4ea9-4191-7136-08da5b4a98e8
x-ms-traffictypediagnostic: PR1P264MB3759:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: /ZvgGXbY30ZUl0+WciWToYiBqnw+jH+n/7aMH0SVNDmgFzXuMAP+IAa1dglBwFbIqOhluckt7gXtaqwMbq4k5bUGprPOuSXFuqRFESH/3yfz/flX/YoVDu02O+/HBUzPs2YN4/M1N2hZIdoD3ZI/OvxeKomEwtmfBISf+2aJz2IdteU4z7rKp8m5OUXuDNxZ0+oq3EHcf8lV4OGj/XZeR9vv2C6rDqNFIz/m53b7UUxuXFMJApFUtzG8KaJRYFTaawcp3YzruuYJm/Tc9MWAM0CObVM0g7fC2V+w7kz9uMfxDG4JNwu0tTKKJWTiajvcFmB//+2R381b3/OBXVn/cmsQjcjXPaZrk+P9vxJT+olgOi4+hKObwZUv6OoSoEkQmIilfKhyqGE9WOUiLQvVgw197IFKgHjPoV+9MlOtwAJUV0qwBWszLziUwGXQcIWwdWg1aKuCDqZz67F1HyAEqZULAg7pr/ayD1tEiPSLSGwpBSqEmfrJpU+cqXjjeUoSRu06bQGrRv7DlDQv3lU7+a7kRHv2Ubw3o136V/vYVqpaqHm7iVQGXND3oGDz/TSnEgfQsceN8/hbsCBFeTDt4bAAabGGzoezmM/feM32Vt6/4cghCQ7wjUM2UprQy3meyp6hmNbvoH7qoJzUXu+oNc1mgO63pR//9dahjHCnrjcGlm6sYtEeJjQFH0zX9WGHZ9GQO8FlUtbKpnObS0ImlquXrWWqyHmMnl5XoPeq8ye9VF46+HQKII23ogUfLncWB1VXRZzOx20RpsPlZj2+tgCHmKdM1NrkvEeodmznbGGawFTiZf9AaHcVxDQ5rNJdRtde+E1WlaTCrZk6n/rQTW8TvwiUJ4SfrKhAsAcQQFNDN+DluT1qhiqQlyScQG4v55yMBOBDfceTsqNjNK4wjjMSKokcvdqkX5UdhHx3JvU=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230016)(4636009)(376002)(346002)(396003)(39860400002)(366004)(136003)(66446008)(66476007)(4326008)(478600001)(64756008)(91956017)(8936002)(38070700005)(76116006)(66946007)(8676002)(66556008)(966005)(6486002)(2906002)(7416002)(83380400001)(41300700001)(44832011)(5660300002)(71200400001)(36756003)(2616005)(6916009)(54906003)(86362001)(66574015)(6506007)(31686004)(122000001)(31696002)(38100700002)(186003)(6512007)(316002)(26005)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?WUJXK3NKYjZpYXhIMlNzTUw5eTI3OUNSWHdRUHlaZHFYMnprekVlK2JaeDds?=
 =?utf-8?B?WmM5c2hEZzcyN2NNRFNsRDZ1VXQxU0MvNStLMFJRd095TlFRYkFYR1BjVXFV?=
 =?utf-8?B?Ym5sZDRKWVBMdDVaaW9BVnUxZWRpQksyVVFFbmNpamhNOW90WjlkSzkzaWFP?=
 =?utf-8?B?aXBmQThTK1F2bXZNUmFGQ0huR1EyYTZ4bzFmcC9lMG5vMi9nSmE3WnV4R2M4?=
 =?utf-8?B?am50VFAzeTV5RmlDYk1YRHpLSFBRUm02ajhLWG14SjhMS2xvRVVjZE1ydFBO?=
 =?utf-8?B?anpFTC9hMVVzSE80V3E4YjE3N0FSR2UzUzFmdVY1bEtjcnNHbDF3ZitoMlpV?=
 =?utf-8?B?UXUxbFR4VS9ZRk5iUEtvc0Q5eHBCZGgzS1FlMHNVRVJiZC9QQ3J4SG1YaVRv?=
 =?utf-8?B?SnFvUHVFcjk4RncyVSs3QTV1TWpjdEpaVEw4K3VpZlplRXhOdEJibm5tdm54?=
 =?utf-8?B?TjRETDBUbjFBSGZVRU8xQTJjaFR5K0dmWEZYME4zNkF1UnpLSHFwcEw4cTZN?=
 =?utf-8?B?T3dyNng0azRUNUhkNjVyYkFtQWFpUkNkcGVnSXh2eldXc2U3SUEvNXhtTlFF?=
 =?utf-8?B?SWdqUjRtZitFY1JoV05vemloL2tPbWtFL2hnbDYxSGc2Z2xYT1MvSXEzWWl4?=
 =?utf-8?B?MjRxRWZxRGpnd1Nza015eFNyS01DT2oyRk1KdTVLMVJmVzlOVDMwOTc4V2ph?=
 =?utf-8?B?RmFYeEM4SnFMZGJLVDFSVTJjbkFja2RhUjlxZCsybk12b25OQ0MycFBEMmRy?=
 =?utf-8?B?UStlSzJrQ1ZxeHZ5UDV4STJwYU91TzZkOVY2aCtyUFplWDc2TGNJS3lQb3Jy?=
 =?utf-8?B?V0RQRWF5bEJBaElqTWV4cCtsOGxvZHNYaUkyTVlnb1E2T1RjdStxcENwakFq?=
 =?utf-8?B?WlhwNWhoYVd0WERxZUROL3ZNRThQMTRuM3BZLzNQNnFFWWx1bElseFY2OHZz?=
 =?utf-8?B?REU2NDUrYVV4M1NmMjNoMGYxWFR1NmFiajlEOGZ1YjZHRkZUTTROaGVmV3l4?=
 =?utf-8?B?MGk2UGtqQ1l5bGowMUJzNnYxNXRyY3BSeTYwVjRLeWdZS3VxMTBYVW4yYURa?=
 =?utf-8?B?SWFwRXBsUjhCNkZEb1hNZWw1bDg1UUU0VXpQeW11MzZvbGZoSmdJYmZMRmg4?=
 =?utf-8?B?Wm5GaHdpdUIrT2htUTZTYXIvcnlobzdVYkxUS0tuaG0xUExjV3dqZ0wzN0Vr?=
 =?utf-8?B?WXpGbnMxeVV2Sms4dDZTelZpRjloYVdyRHZwVlV6WE4vMHB6QnRINXdsZFNr?=
 =?utf-8?B?d3NiMDBDNkFyR3hTOUozRkJialFha0pSVGhxSGNiMjIyREhYU3IrK3BkeUx4?=
 =?utf-8?B?TE1neWM4ZUpVZnNSSjIrSEZHdkJDQXdFZXB0VTJMM2ZieEoySFhNYkNPc21S?=
 =?utf-8?B?TFZNb1k4Zjk2bjZ2L0RUVUxvdndVdkxyZ0dxUGRpOTlrTlpHYldPZjl4aStH?=
 =?utf-8?B?TG9KV250THp6dzhES0ljdnVCU1B5Q08vMlpNU0IvSjdpeDcrbVRVUFFuQnZ0?=
 =?utf-8?B?ZFprNlV0YWVNc3NYQWVXWkV4SDIrbzA4WDQyQWFqTmpreHlzZGtuRmRObXYx?=
 =?utf-8?B?cU8rTmhPSDN1WFpNU1JRelVQamR6YUoxbW5lM3BBMWVDK2VOVmd5WWp6L0N2?=
 =?utf-8?B?MGkzalVyQ2JPakQ5bjlxV0lXUnVHaGM5S1BKOG1jUUtPQzVLSmF0Q09ZSENL?=
 =?utf-8?B?SzhkdWVibU5xYWV3Q3Nxajd6eGlvNjN5MzduVmw1ek5WaHZIVGExNjBMNVpa?=
 =?utf-8?B?L1RKVnhIOWlIZGNuUGVCYXpOSnMycENjeFpib0dvbHhRUlpqZzVBZHcycm9K?=
 =?utf-8?B?SVdJdkVaZm9FN2hpZU1SQVpkNmYvM2Juc3N4bWJ1K1k1S2RPN1pCNmVTWURU?=
 =?utf-8?B?ZUVzL3ZyaVZNR1cwaGRxRkppTFUvcVpIK0w4Sk5QbTBQanl1R0hvS1lkVFBz?=
 =?utf-8?B?RVJlb1R5ZVVtYWgxcXlkZUZWS3p3dGR2WC9sNU5SdjlybVp2ekg5ay9WZXhZ?=
 =?utf-8?B?TEJ3bm9vMzBsbzVEUmJvQ1M5Tk82NG9mSkJOWHBFUlNmQ1RxSFE2VmI3OHo2?=
 =?utf-8?B?SXVGK2s0T1QvTTRCSmpSL2pSWm9WSWdJQ2drcVpQMys2RGxBdDZuWXVDbzlJ?=
 =?utf-8?B?VHAxb3d5emMvRUdOUEdKYUE1OHJIT1I3cEE5ZjhBaUJSOVRqNFZ6RWpVazEr?=
 =?utf-8?Q?38SpEZ26RKfZbNvpcQ5tpd4=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <48A37FA002C14C49A2E2CA16C8FCBF9E@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 4e66d82a-4ea9-4191-7136-08da5b4a98e8
X-MS-Exchange-CrossTenant-originalarrivaltime: 01 Jul 2022 10:15:17.7268
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: qgiqtQZuNzk+4zMt2P7lEbskDMOTOOfh7GX87C3rGGSWKCv/sLcNa6Zg22pPcTejz4eYQL4KCl0Osx2sGptt5zEGlsgRbrzVFLRyhkme+9c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR1P264MB3759
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=kOoTarWb;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.12.40 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 01/07/2022 =C3=A0 11:41, Marco Elver a =C3=A9crit=C2=A0:
> On Fri, 1 Jul 2022 at 10:54, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>> Hi Marco,
>>
>> Le 28/06/2022 =C3=A0 11:58, Marco Elver a =C3=A9crit :
>>> Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
>>> implementation have relied on nr_bp_mutex serializing access to them.
>>>
>>> Before overhauling synchronization of kernel/events/hw_breakpoint.c,
>>> introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
>>> thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint=
.
>>
>> We have an still opened old issue in our database related to
>> hw_breakpoint, I was wondering if it could have any link with the
>> changes you are doing and whether you could handle it at the same time.
>>
>> https://github.com/linuxppc/issues/issues/38
>>
>> Maybe it is completely unrelated, but as your series modifies only
>> powerpc and as the issue says that powerpc is the only one to do that, I
>> thought it might be worth a hand up.
>=20
> I see the powerpc issue unrelated to the optimizations in this series;
> perhaps by fixing the powerpc issue, it would also become more
> optimal. But all I saw is that it just so happens that powerpc relied
> on the nr_bp_mutex which is going away.
>=20
> This series will become even more complex if I decided to add a
> powerpc rework on top (notwithstanding the fact I don't have any ppc
> hardware at my disposal either). A separate series/patch seems much
> more appropriate.
>=20

Fair enough. Thanks for answering and clarifying.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/45396b77-4acb-817c-eeae-9a672a92611c%40csgroup.eu.
