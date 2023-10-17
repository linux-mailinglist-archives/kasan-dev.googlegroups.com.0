Return-Path: <kasan-dev+bncBAABBFWGXOUQMGQEADT3P2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C5397CCC6A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 21:40:07 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-581debabf87sf1198752eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 12:40:07 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697571606; cv=pass;
        d=google.com; s=arc-20160816;
        b=nB7/l90/O77U5+CgELysTS82LD8aWC68wrTqvA6TAsw/KsezBFifg9elloJm3xa5hH
         ydUmVXOUWW74k1NpVM2q+F2Uv7DjhlVxHyqzE/nRrdg54Kvp7ViZ1jC+CiXZPfqQZPRr
         yH0vjrdavlG2OM0dFPg1TWrUIIfnFYuPysh5z779Gn0L8MG7yxli6x0WiwBPl6ie9MiT
         ncylxOWUyZO8I82dK5+0yeGL4LRmgd8KeGHfwWs5N3jr77MBY2MrZTFUnwVOP0kta8DP
         O4k8TuRXAeNh6Qwnyzu23v63nrap7sRfx9MFTyY5fAQsFR9AdPtdu7bFMBI4XWqoqvVv
         yKCQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:subject:cc:to:from
         :user-agent:date:message-id:sender:dkim-signature;
        bh=KnPopET1kcO9VdWB1SfXvSYD19vy6zEjfiSQkMe2htg=;
        fh=V/OUNjwtRC0NG7gaVdOxxhHiU9YX61qgVnqXTmJw9es=;
        b=zoxFrNQRSNiAqS35pE99Uld1ge8aSsvscbjmpNfp0TRPRNQvI9gyTZYOcnC6Sjk68g
         y6/9XID/wyRamN9E1cGbNKXN4PUeSGaApaEizXmQGqtaUwXbUrftsl2vnPXwEZvfikuE
         Zh81WBQK9qyY4UWhWIRG1ZoRFFsYwweff79be3utYkiBdZ/QORxOJWMJzzmPK16zOUhk
         uw/sS4YAZ/0U3G9xcRxY6agv7/JMI55yDO+Vu2S79Qm2feazO38tXDRmROJmo+iQgXe3
         h5QCWi29x0Tk2VolxFz2q6KWv84M20VBM4zWwZ/KqlwwvSvcgAYbQJEI5a/BhW7WCmEZ
         p3KQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=dGDyKoxn;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697571606; x=1698176406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:subject:cc:to:from:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KnPopET1kcO9VdWB1SfXvSYD19vy6zEjfiSQkMe2htg=;
        b=FLaZx8Fh0nhKz47NlxJKuCK/KV0g+HtBBr+D98a3hM+iB92hV0ZszfcYvoI6zM1RV1
         KKfov3pi9dyA6+q803cEYx0scJKmX/Hcn6RoJ0D0zb6S4d8zAS4XmOndMKda5WxnQUx0
         EiaWkYDLEzMD9NMS/OB6Is/sPvkDKBqDMcptSicg46f8yB8XAivn1sink9gClTCxYYyK
         8cdyazKHB0tJgLPaErunfwzBeHlA8FjA0Wlsvo26a32+O83J+akracxWWOlsB6lF1sHQ
         irgZ1xQF1oMLjOG7MNwtG3Xvb946AXhu4KYFU6Dt4th7SNr0R32NHbQ8EA4MjvNUK8mg
         Tacw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697571606; x=1698176406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :subject:cc:to:from:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KnPopET1kcO9VdWB1SfXvSYD19vy6zEjfiSQkMe2htg=;
        b=t7IFKGvtBN2jvxAZCZwrP7ktQvWMj/mp90cXl0NQFAbSzyd4YbYe96fp98nY6asTy2
         U2lCkOPAEiOWNhZnXDzyUniSg1yiy0o/cD8HT1IyTMUph2L9LrUarHzZi9TCIE54zdWD
         fWBG2lWgI/yKJt1g2Bm4keEqz44oydPdPf/kTRKdL3fVL8aXhRcbGa4lFsbbVYhU6Jta
         /Pvi+v977JAJblvpTNf0n4E/1QSp3u/2J8UeqyIFqsl1dG7bjI369hT5Db1Yz8c22feT
         VcaGKBTa2ELPJauJLadHOoIdBlLORIuwqGYTyPXv7pXZf+efKZN/GNwwrrkMCb5ghyJ0
         v3Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwX2QuZKBRdTFK/7O5lpTSh2EBfQsMv99u7BRig3MAdPJnBUM2A
	PTqFTvvIRSdyF8Lam+PjF2uJ7g==
X-Google-Smtp-Source: AGHT+IHk4Sp5rhd7a0skYURGkuWRgnc/uwtkFbmnk5z7gep20lAdDRdzuGbuCoS0ePcmzCMrt371hg==
X-Received: by 2002:a4a:ddd6:0:b0:57b:e5db:7a59 with SMTP id i22-20020a4addd6000000b0057be5db7a59mr3113652oov.8.1697571606423;
        Tue, 17 Oct 2023 12:40:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:558f:0:b0:57b:7aef:9d1f with SMTP id e137-20020a4a558f000000b0057b7aef9d1fls1183986oob.0.-pod-prod-02-us;
 Tue, 17 Oct 2023 12:40:06 -0700 (PDT)
X-Received: by 2002:a05:6808:1597:b0:3a9:307a:62aa with SMTP id t23-20020a056808159700b003a9307a62aamr4643438oiw.22.1697571605781;
        Tue, 17 Oct 2023 12:40:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697571605; cv=pass;
        d=google.com; s=arc-20160816;
        b=YuStNKj1E81p3LOnOR7I/OlzcUCx/DUQs44opOOCTQmlEkLY7a+tYmb0bBjBKHsZXf
         4HRRWmUFMQyyQysGOvdk2npwib0IcsEb8Se+QlXoOtIon1QI5TKhxb9qWRK173rYPlCI
         u9h9uHGSHsBtj5Vsjsf5IIzxk9EgwoaveTAB/E2pekZ0Lz8K2NnW4fs9dnZTZrVHTZmM
         gsazQJoR1GBTL5kHwhCtNI9U9cNZCQ6kdfU7hjvdimXio3iTMBbKd4BYQQF7UZVe0YZJ
         oNibfKBYMU+OfOWI3Yd/jKUU827miUzKJru8R9Vu/D4dBjf97jtvsK1UfA/mA9mxHA9c
         oSmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:subject:cc:to:from
         :user-agent:date:message-id:dkim-signature;
        bh=s1ZEJfJwgCo78Asz1ZD2KDfn5+bZC8UTiZ1X83PPJ98=;
        fh=V/OUNjwtRC0NG7gaVdOxxhHiU9YX61qgVnqXTmJw9es=;
        b=H9qsMLet0XkKZIyMy8zGtFgcEV2pVUWNJuf01A7T4ntp84BCFUl+4XAX46L7WJT/Cw
         AyOb3chN+WYPLR04ECjTWOsXm7u00bswJupob+4bhsnfHZ7qN6HOK14nbnk9a9aOI66B
         zQ80u/l+zc3zGOGEDR+JUUShkon+RzKVrZo5ROAsB/F9hOuti1usQuqfD7YfnONLhuBG
         +4IcE2s0r1QYtFmwC8nVZumkzxnVETXnSub50naWHhf/jU6D2lkApU8wjzsp8h5vHTQi
         qN71mLo4pq+PneXOuUWAKCauV8ReEalL+Xh7rp/lp4VkRdKL9fTJAZ0YFpN0nT7ZFdmK
         shgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=dGDyKoxn;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-VI1-obe.outbound.protection.outlook.com (mail-vi1eur05olkn20802.outbound.protection.outlook.com. [2a01:111:f400:7d00::802])
        by gmr-mx.google.com with ESMTPS id y20-20020a056808131400b003adc0ea0dc4si205665oiv.1.2023.10.17.12.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Oct 2023 12:40:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::802 as permitted sender) client-ip=2a01:111:f400:7d00::802;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Q5sol7ZUCTRO6Z3/4Zz4xf9jlFHDKwrb5eMKrcfY0ZSkc96WjdTFonFI3AGn0hCrKJeQeb3OfbjkQS3wh73m+Dvt6Kwp+MDCQb7YC0tEyjHcnwfnvlH4WWNRo7dkZZnM5ZHIwiH+81DGYPLGvgfPHEIiyXDG5AoQhcdZhVrOOfMX7jG/AEL8pH1UE+7sUQjezORbYtx2gngJ5aNLf/F4PHDM3fB4s+JaC00DV6fhWWeRJqhYxD9BN2bXMLPwcmMoa1t/an5KZN74X8ot0kLkDmPEW0cLzgUhhjj8YtdCvQZGbLjwNatCRnk272leU0+El5pgnMN1zcdVDPQZh50PpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=s1ZEJfJwgCo78Asz1ZD2KDfn5+bZC8UTiZ1X83PPJ98=;
 b=B15MMiuoZUyZWCvnhqdS9B3TiIvuHfMILQ7Nk4aHVJhfSWwnY8OWmXCxmeMqyErEnXtxAn5bgnCbFEO7NS4JcJBX3GqMo/uAc8iapCwFC7lZEuRx4msdnxdG0dQud0XtFVlkveK9G+V26imt95oBPIM9ZehhXznG/Sgm6wEuGSnAMPLzV4f/GZO2bWJiGWKPadz8rntrMc47lnHxXlzSA0iUTEIRISo4kapbldPdkXjaLb07uIC2vB/mXU9IV/OP9RdWjRrfzZY3tPrqRZsWyuQTVkh3QWBm5DEWeFmlBq6HI/3TYAMBkmbOQwOGbADF8+pIKl4ouxHrpXCWRWkLZA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB8P193MB0645.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:151::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6886.36; Tue, 17 Oct
 2023 19:40:00 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::af68:c2a:73ce:8e99]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::af68:c2a:73ce:8e99%3]) with mapi id 15.20.6886.034; Tue, 17 Oct 2023
 19:40:00 +0000
Message-ID: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Wed, 18 Oct 2023 03:39:59 +0800
User-Agent: Mozilla Thunderbird
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>
Subject: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [n68INaFdX0AQ9ixRWTnYzMxHobQbJ5ct]
X-ClientProxiedBy: LO6P123CA0001.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:338::7) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <951f648d-2dcb-4438-993a-c9fafed0128b@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB8P193MB0645:EE_
X-MS-Office365-Filtering-Correlation-Id: bf333dce-9b20-4534-f3ea-08dbcf48d9bd
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: j1md31kUyyaT7+1p69ggEWbAqYF5o4s2dDXa/WSmHrH/WL09w/KkL++6Xz0gWnGDitUU34XBqlzj77V/rMdjj1DfGu+u1Wk3gEc9rxb6q3FeUR+Yj2Yt84btAoPvjv5/Ude9Z8fWKcxmEH51LJ0Emi33+u5iM8G69zpRi+m0RjRTfZaWlRLTyFNX0wVCqlzAimN96BRPt2xXqFUi81DPJqcJMv+YtnmwfqO3YbTXT8vdsltAGGxh4ZjrYi6nEKapsE/AQgRsKCqpqMfEzf4Oh4man6qmL+vS0O5njK19s4t6S2rqzPuP5stXMpc9Jw8ttrfDd5QVVPT8kjcZwKDC2L2TkvNMB9KsMRWImMXHhTqJ9HELOfdQBG8qiJzhyXkIbbFyNe9MpLzoZTcq7+DZIB71SdLmygzHCwVq/YNPMMy1M0HAmcws01rxDZKz1PuBR92So76S+M+5sWtr0DxIiVruZkVfwJvA5teysKFD3qyLcgCX+jtv8H5cfwQ3dv5dBCjc8EP+G7dPINdNjj1CNxF6FBFry6nuwogLxm6RS2siFLcPVHwAby9mThlSp9xV
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UFdPdHo1STFYa0Z1TEdPUkRJN0NiSzRJbHpaTzYwTnJ0YVZaUVJ4eDM5OVJN?=
 =?utf-8?B?NXFJdkFGZkNzclV5a3p2WlVpcWY5QTBPMkpUR25vc1p3S2J3SXF6QUNZTEZv?=
 =?utf-8?B?OXo0UG0rTkUyRVo4WXdzTjdIQUNlTkU3TDRJSEZYRnBjT2E1aW5zNkFhZjgz?=
 =?utf-8?B?eFFBY0NHVUl0ajVydWQxS2xYaHc4R0k4My95aWo5cisxMkppQ1pESDllNVVN?=
 =?utf-8?B?NmRLV0JGMFdLc1NKcEU1dnhSVHdKelB5RXNhZytDRGl1R3V4cFJIYWZuTmM3?=
 =?utf-8?B?dUdvaksyc1BmWGFqN0FTK0Z2VWhxb1VZbXUwdm1RdndRY0VHV2MzYmxGYWlh?=
 =?utf-8?B?ZUplZTN5WUVrQUpOZ1ZiMGRLbU00VjM4akYvZUpYNjhTRGZPNldVUURrVEhW?=
 =?utf-8?B?NUMxWno0SlNRWDRTKzhaQTZYeTVqSFVTRGVGZkZQL3JGa3BSNm5mWFRNWENp?=
 =?utf-8?B?a0tadEhPNEhJZHVITGxYU3ZZTFZ4V0NWYUZNNG1HamVSQTJnUnh6czRqSDVu?=
 =?utf-8?B?UmNEVnBSSm0zTGZWUDU2MCtHQnc1SVZucUxDQ0VCejVpaUFVcGhjWTZjVHEv?=
 =?utf-8?B?NlkyL3lmL2ZraHBlc3FFcHRNVFJ1S29NTmJlYkJhYjdzdnRxTjRweGRrRGhY?=
 =?utf-8?B?R1krRnMweEZXeTREbklmQ1hlLys3Skd4OHd5bXZnU1hmNy9oaVNDWmtmNmxH?=
 =?utf-8?B?U3ZqN0RVQWdhWXB2OXZVeFM3WXhIVjdHTmxlbTdIVEV6N3VXMGtDaUpPNk42?=
 =?utf-8?B?TTAzdGVGTjBRM2N2ZkNrZ3h0eENNWnBOeGkzRGllVlA4NWNuc3FlRjl3Y3Ni?=
 =?utf-8?B?Sm9WNVNuSUVLOForZXhOWVJFN1E3cU5LWVZrL2NmQWIydmgzaW1vLzR0Q0N2?=
 =?utf-8?B?elBGcFpZY3JlQ1c5dTRCNHdFT2IxWkVjSER2Y1o1ZWtjQjlLbWtJYUpCTGIw?=
 =?utf-8?B?OG1IbXMweEZSTFNjVmxPRElZOGNTSGpLd1FyYVpZWHc3YUxCLzBpaW1XZm1D?=
 =?utf-8?B?eGxEZlYvSnA2V3VaVkxMY3Vsbmk5bE5jSzhFZW9FZWgyTHVsOEhkN0pINXBy?=
 =?utf-8?B?eFJJTFVVS3oxd1djYU5MdU5keUdaNlpIandpcnBhV29nN3A3Mzcxa09UQ3NE?=
 =?utf-8?B?MVlvM1FmQ0ZTZURXVGtGNnZ0RnMwSVpRVlp1NmoyTnZhcnQva2hMRDcrdFdX?=
 =?utf-8?B?aUlod2hYR21VNzlsTXJBYU44S1JvOHNFbkEwbDFHcXpUbzZ6dXBDQzVGYUJp?=
 =?utf-8?B?aGZONkdiNEV4UkhIdXBqZGhTQy9WZXZ6MzhEa2JWYnphZkJUYWxXUkIzL2Vr?=
 =?utf-8?B?cEUyVXhrQ0toS3JZVHBPU3J6OXkwNnNCTEUxUEFRTks3WHpFd1lXZEFrdHdO?=
 =?utf-8?B?aWFFV1o0Y1NJTEVweFlRaUdPM3RiUFR0NGp0YUZDWnU3dzRFaWxLdnJXYkJQ?=
 =?utf-8?B?SFJtb3FxaWd4SGxpVkttRnBwOEhVQ3A5Uk9UZ3NpbGZTbThVTkF2cU5aZ0Zy?=
 =?utf-8?B?dWdncm9WQi80UUE0cVpCV1NwNjRWdzB0dWZVNkFwUVY1Z2E0NXJTL1ZxTFRY?=
 =?utf-8?B?SmNZd2JEYUhZOW9qZHArMEtPeDFEZ201TkhQMVhKTXJ4SkFvcWVuWE5RcmpP?=
 =?utf-8?Q?ENv95TQUg7ryBMVEkHHFq/s64UbPQM7T2ouJrOwbrGYY=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bf333dce-9b20-4534-f3ea-08dbcf48d9bd
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Oct 2023 19:40:00.5837
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8P193MB0645
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=dGDyKoxn;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7d00::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

The idea came from the bug I was fixing recently,
'KASAN: slab-use-after-free Read in tls_encrypt_done'.

This bug is caused by subtle race condition, where the data structure
is freed early on another CPU, resulting in use-after-free.

Like this bug, some of the use-after-free bugs are caused by race
condition, but it is not easy to quickly conclude that the cause of the
use-after-free is race condition if only looking at the stack trace.

I did not think this use-after-free was caused by race condition at the
beginning, it took me some time to read the source code carefully and
think about it to determine that it was caused by race condition.

By adding timestamps for Allocation, Free, and Error to the KASAN
report, it will be much easier to determine if use-after-free is
caused by race condition.

If the free time is slightly before the error time, then there is a
high probability that this is an error caused by race condition.

If the free time is long before the error time, then this is obviously
not caused by race condition, but by something else.

In addition, I read the source code of KASAN, and it is not a
difficult task to add the function of recording timestamps,
which can be done by adding a member to struct kasan_track.

If it is a good idea, I can do this part of the work.

Welcome to discuss!

Juntong Deng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB075256E076A09E5B2EF7A16F99D6A%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
