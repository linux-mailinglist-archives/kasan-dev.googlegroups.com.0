Return-Path: <kasan-dev+bncBAABB5OA7CUQMGQEA67TOKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 87D387DABD6
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Oct 2023 10:05:58 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2c509a6223esf5791991fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Oct 2023 02:05:58 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1698570358; cv=pass;
        d=google.com; s=arc-20160816;
        b=cH3hhWtv/BNy/M/thpsn/aQBAxlPvfRuKN588aLY8Cipwjgb/KwGYVkxEmi9RHKDnO
         upSaZ9BB8qbAKMQNkrGpZBmb/P5Ht/iwPyOs/JuoQv7S0is1psDQvBo1qgm9CCoFFAZM
         AP4cskvHCnxNW1mmpBwHFhRQBJMLtRs00QaxXhAHIulM/87/NjXyo137h/R3cB0fer1q
         E7wIOPhxyvnzFp1RXA2bYRVa6IQPJjR3NT3DEPBGsKoJ/kkmejTBWsNTRIJoeaws03Z8
         Af1cwYb1F43hT0khE2ko01FatJJiIW/+x6i69Af6GeXPxnpfSKskx8n+fr1sig4YToCY
         Qc1A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=WZkcD7WGDAI8kCj9jmcdTPS8d8mOxUrgx6ZCdM7wxCU=;
        fh=22ucgggqjLa4fRcph1tw6FvM//txr3YHf3uIC6vaA78=;
        b=quSZ11MB7PoApLsuVcGLhEZWPzMxYBmkIdQQmqzeSafVApMah0LeVmARsF4Cqy6y+L
         7Ik5dQ05p61i+qOqk+A+nb0zeX9Wq36I6jd2v6naoW0+cFhzWLvy5JK2bAmgnxfu0cFG
         tvlRSpSq3xmQTvY5T0SGAn7667aUl7Y3WmicWQfP+BIDWmvP8Omc4AfphdSp/yKixrJl
         /Z4pq0+3V/EeGQwToZCA66Rz/44LkASF8yd+GWgAQOSeHiSG/8XYcMEUflEYRv86gx97
         xlxcA27fwlOk4P4UnblylHZOX9ygIKVglQ5qPMJ5jYRtQUJk2NGiB5xrCsJpjpCAhUKp
         /UeQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Y6x7U5dJ;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698570358; x=1699175158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WZkcD7WGDAI8kCj9jmcdTPS8d8mOxUrgx6ZCdM7wxCU=;
        b=vIbg7p4L19FLMggGHhlxqCQHLIpUB8V4juEjB3P3mh45LhtuoflLlq6HjJY3dTa0kh
         DyESlrlYoQjMyrvBpBs5T/erBv7y48h7pPuyyh1DpauJ1bom5PQCzTWulJWay5jkQ/YP
         tQypgEx4OQyMtvkKC0OnIEhbIX5CMrNPWNfTxK85ybUopInE9AzbOI0roKmmuwsY23tL
         ZtgJzy0aICVzkcR+GoFmKs5fp3VHyd7b7XC/sdc7rkEd7W6q8cTeX77ivfSDvFeVYvND
         10RR+7Gy28EWEL9ga4L8ihVI2sCXO2dmQOqerhxPXmS55k6nTUC7xEry917MT3kVB7Jj
         QVhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698570358; x=1699175158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WZkcD7WGDAI8kCj9jmcdTPS8d8mOxUrgx6ZCdM7wxCU=;
        b=G4JGxbk3orXiYVU1vGttK5IhkLkn8T8Lt501ZNeHv1Yn8OcCQZm68pnRZg0ecsENZi
         Kc2G7yTxjrzw2ON5JgjiGoajOETQNdIz+9b5zpgvT29sMYg8jvyx3NaUbOgztOr5QMdw
         SWFvmIDPDpZGckKG4mKXrNMUn+Vp6YtqFhl1vBAkP7CViz9onMS8S9Cby3UCP1InZ00Z
         Nw6LHOrbcbwKAk9b/ZO+BBLRgiwp7Y4TcPkK7rKtQ7vkSgajEdp39WqRHU1d4/yKaZ90
         C6ex8mNWufIOiv0j1IquDwqs90RSBaHhKFOXUL02tFUH2EfO7FBuRGAd+BbL7NyeoKdP
         kQQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwZADXif3CtVVK8ZRi8nGEvNKng5XthdmqQM7Qjcz67nFnX1wU4
	CjSZ6JkXmdgbbhZ3ulBd26o=
X-Google-Smtp-Source: AGHT+IGqCTIzMJ6VMwVrUr/gqZB3u0DB17yi7rwIb8fhwrOyhyqkvnli9BOtNWpaIsapbO2nszL+hQ==
X-Received: by 2002:a2e:a0d3:0:b0:2c5:509:c080 with SMTP id f19-20020a2ea0d3000000b002c50509c080mr4726190ljm.3.1698570357282;
        Sun, 29 Oct 2023 02:05:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:be9e:0:b0:2c1:261b:7353 with SMTP id a30-20020a2ebe9e000000b002c1261b7353ls544429ljr.0.-pod-prod-00-eu;
 Sun, 29 Oct 2023 02:05:55 -0700 (PDT)
X-Received: by 2002:a05:651c:10b5:b0:2c5:884:88a0 with SMTP id k21-20020a05651c10b500b002c5088488a0mr3264973ljn.21.1698570355570;
        Sun, 29 Oct 2023 02:05:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698570355; cv=pass;
        d=google.com; s=arc-20160816;
        b=VFjttecNTRLe+axpAl99O2KPAZi20F2tOKyfpjJYO8M21ETxu1OEjC2UXZ0NmRdKJ+
         stjaBnGGoH+KNTAQwYEAMESSvzFzJYyQlAmBOplXwzWdYHvv6VcoHlzd/AD+lYTQSXdt
         us4qE6j1pnddgyUb36lwMkS/Rrw3xtHoV856k81BzesOnhOe7eXXw59sQDmo/knmClOv
         yjUAiuZToJiHFpHWqlYIFPzD+4LrbCCH9LweaF870nZBa40p0W28GnuM4TLrg9Yl3NEC
         vzLKZqrqb1CbqTTJf2DH9clJkgXPMNqAbDrC3hPFR5z05lgqFrLQdaYTyO/QkqhQMOrN
         zfPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=BcwMR/IiMmMF1IndFxlrpqJNTzSSs2/w/qmy+PcxA3o=;
        fh=22ucgggqjLa4fRcph1tw6FvM//txr3YHf3uIC6vaA78=;
        b=NX/NFvm0Q2NV1lOJAX/4YKaEJlHg0ZeMQ6eYIMYRbW/zBiEMCi9av1tsDlO2JNX6CF
         boyAqLnBIyJjjwVgXfffKXEDGtUDnAKdlcdvD5ShLHh+JhwxCxkuGemNtcHTx5WNqsFj
         leObrNpjrYqpEEHU+PWwotzvWGZ6mMAYrH+aMvLZGaFmQq+hB1JSKMMXYE8AIsZ9DcM4
         eQPoDQ/rWPot1xDNVBBOIUpegpvhfjbgJHQH7mtlpJUGTZA2/9ZBTWMvutLPdZurNa8+
         GiChS4Tu882uxq3khb5ZN0h+g4DgrQdIa6oFM/MLEJJqcxavzleYTTueoVLqXKqbg92o
         4x0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Y6x7U5dJ;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR03-AM7-obe.outbound.protection.outlook.com (mail-am7eur03olkn2080e.outbound.protection.outlook.com. [2a01:111:f400:7eaf::80e])
        by gmr-mx.google.com with ESMTPS id z21-20020a2e8415000000b002bced4ef910si297327ljg.3.2023.10.29.02.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 29 Oct 2023 02:05:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::80e as permitted sender) client-ip=2a01:111:f400:7eaf::80e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LTsRuNwZWOw9s/zmBwyVsdN7ICK0E5YNWi/TQgmgvsKI6RgPc1yngVCqULzDbnJ4B019xPGyrRhGEmTh5YX2pJXY4fXGkkVflsb9gXbfPD8z1ipuYQniG1E1mH2TUsa/TRVGUp0E9cgK2AVc+VP675N3tJOyCAJJXUkoklp06rSnZqHXNNNfPNLfz8/Ia5zy9QsqoAubq/FvAHh0pJNmejPGRMUgb8g2UTc0ToZSzdmaSF2EoRC/IJdDaHIcUYEWiM+vkEfClSC+69DId8DN8zF+Zduc50hDNCZfF+oHHx8ipRj/NZDVV297yAn22s9FY/9PjnY22jYNl0bP4CWi7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=BcwMR/IiMmMF1IndFxlrpqJNTzSSs2/w/qmy+PcxA3o=;
 b=COUz0dhvyYJ/5dim8K8HgeLiJoTM8VVn/5t5na1RT35gtRuhsYLd3YucEN/4Rs8P8YYV3h896EtdE7+tuZ/nS5v9xm8NcX/EQJUBLBc4zSNUjUtjSdqZdgYtlEfYwfQe+iyHLLaX8gt/Y6DnhscpsNFArM52Pp5y0NYJNSy7BYMsItWRu7p2ft3xigu53pGoOXYkJQOeU5d6k9DmymuMiOnIByZeRIyz7LGb5NXdm7elQMJQrlKNyn2VBVnDk9UcB3MomH4cAnjroTnQfE0/VzLVpD08s2ouzD3QLtBLTVi0ewp5cBvSVDaTxGg+1h3pw7AiQdiO8g2Pil+J5cM4Mg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by AS8P193MB2301.EURP193.PROD.OUTLOOK.COM (2603:10a6:20b:446::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6933.26; Sun, 29 Oct
 2023 09:05:54 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e%5]) with mapi id 15.20.6933.025; Sun, 29 Oct 2023
 09:05:54 +0000
Message-ID: <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Sun, 29 Oct 2023 17:05:54 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [X5MALjLVTbXzlHngHlRqibWkaWE/JXzO]
X-ClientProxiedBy: LO2P265CA0140.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:9f::32) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <c973be13-6cad-48b8-9dd3-8fd1ab737a38@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|AS8P193MB2301:EE_
X-MS-Office365-Filtering-Correlation-Id: f9e62cf3-f40d-4a8c-1997-08dbd85e4166
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: uR4YyAFowSATC08xdLw6JLLMjjBxztUZ4zgUEcgVueiKgEafB+LzlhlIwGW8rhWQMlyatYtmNdSzMsJZwk6VkgrXePDuhFo6mA2g7RtAZeFN3Iv6Wj5Jen4htN/nQjc6gKwmR+b5xt1aQMEr4qPElidviKWho4Q4n0I/2CwfFJr1U+QPVl5jmWJG73rcZJnKjq4GGI6a2FvbKkEAVvhw7ziO0TilLdVGItvYaWA+NkWkLTRWBbVmIJfUPgvS+PHpVtGj583Nc4Z+4j4nULhE0WvlD8O6azFcGXVoYesfCR/wybB+VwtLffdRSAeBGAqqj70VHlq9hT3cLFCe4gRBL9qMu2A0Xw+407gOr0c+ABRmEEmN/QqJOepfA9zP5vPRLqmqsliTUuBPWYDkK0xuTHWr0RX9C5+k/b+iDkLsxYJMAbMWxXOGL43Mgtw8zUOhPGCsFMZAoYXfN8drFK0utryFgDGy45wEX+EUIgI3PYkEgDM+9OBxE2UlizCypZdCY7mUeck291PsQOkbtIE9r0+26SMJRRlZzSZzW7yDnp2egGqEiX8M1/1cqt9VnFvf
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?ZjhkT2hkNm9IMFM0WG1LVXdtRStRWlVJWnpTQk5vRkdvRkcxaHJsV1Yzd2tZ?=
 =?utf-8?B?WlB6ZGs4NWdFM0VEc1FSd3Zzc3JpL0p4cE1zOUI4WHhSZitsUktBWi9RMXB6?=
 =?utf-8?B?WnJhUUt2Yk9xRlA1d2REWGVlSFNSN3Jna3dtaXBCaHo4MmkrN3liOTNsaWNM?=
 =?utf-8?B?TTBRdDlkL0Mza3R3S05PSFJoMit4aGhxR3FIbkhVVjA3NlpFN1dVbEhzakJR?=
 =?utf-8?B?Mi9YdExyeHFiMVdCR2pBMWJPeENUUDBYRk54Q2RBSmJNN2ZhQ0ZxeHZmMEND?=
 =?utf-8?B?Q25wSzVQdEVnNTJKMytubitvdmxYeEQvTjJqR0Z4R0MrMTRmTE5ZNTkrL2dU?=
 =?utf-8?B?blR5T2RBSTJ4Z1paUGROME9GNjBwUnN5b25CSXVkcmVSckE1UEtTamw5bDBi?=
 =?utf-8?B?R1ZtYkVNenFYdVRwL2xuMFA1SHpwVm1ZcVh4dUFhdWFxMXpFQXo3bHhZQkpa?=
 =?utf-8?B?R1hNYW1vazhhR3I3YlNvWUh4eWhHajQ3a2h0Rjhuc0dLaVJFaEdNSnBCbnBa?=
 =?utf-8?B?YUx4YlZjRmt5ZUJLa3RZRXlaaG0yWUxld2hWUUxCZUFJaUhSdjBzL3dwREJE?=
 =?utf-8?B?dE5mbzVTZGVzTDRtTktrT1lhZEtMOXBOSmZxdDY0cWJyTWJoU3luVnJMcWxJ?=
 =?utf-8?B?MXVDd2R4L0cvNnlPV0I1MEpZRUNnMXcyZkQzNWFYMjU2M1REaVhySTdZYy82?=
 =?utf-8?B?REJ2S0w4VHFENmtST1ZkM1dFN2hCczkrZkdPay9pWFEwVVFDMXRlV3dqYitP?=
 =?utf-8?B?Z1VLTE0yUG1yY0ZzSGF0ZjlZemRKTFFQREE2NDFZSnlPcnFMREN3YVY5UWdQ?=
 =?utf-8?B?K1RPSEsxb0lBL3Q5OHhkbThOQmFhRE83N0JLLzQ3bXViRGgwcjdhU0Rpc01s?=
 =?utf-8?B?aG4xNzNGNmhObVBLUlRJZ0RPUzZBL09NZnRIN2l0NDQwVVJSYkY4c09sc0Vm?=
 =?utf-8?B?eTR3OWp1bDlEbDVrT2pKVmtTSDhZYkRqKzFuc2lyS2sycW1JbjJZLy90V1U1?=
 =?utf-8?B?K1Q3UEdob3laelZTM2lYbmdjK3R3czhjUktidkxhZ1ZTeUhBTUJqaitkNTMw?=
 =?utf-8?B?ZlUwblEraUY3OWFqRENwWFI5c0xzSG9rRlBrSWhhMEI0UVF6RkNLMUt0ZTMz?=
 =?utf-8?B?bzBYQWhuNlBORVJscWFzN1FEVFN5RDdUaERmSTFDdDh6K1NQR1lWQlN6Z3dw?=
 =?utf-8?B?SFdHMGlrK0F4M3NpUVhjbi9Qem1LbTc3ZHVWY0ZYdERvWVVBRzJTS1hESWJP?=
 =?utf-8?B?cjJHQXdobWUreEJCMXl3ZWtpVVBTaXZwdUx1RFFodmpHdzhtekRhZlNxaXBr?=
 =?utf-8?B?ZDVYMy9naW5lTy9UckJTNG5wTm5DeWFoMEE4QXpMMHhidURsVnBmY21BOHhF?=
 =?utf-8?B?emdkTitGUTNsYUI4a0tNcGRMM3lqZVVKNGpMOWtnQVFhendGNENRa2ZjUjdN?=
 =?utf-8?B?RE9CS2VlNm1uYk44dm5oOXFYOWdKVjVKUVY0T2NUdjV6ZVR1OUo1aVcrcENS?=
 =?utf-8?B?RUFWZ0tja0FpNkdrajV0Vzk1dFZQNnFqT2d5NXRvNWcrN3JtQWl6bDF3bkdO?=
 =?utf-8?B?YlBsSndFeFRBQ3pxRkdOakVQWldNNUQ2TmRKaUhkTWV1emZwK0NNTTVoZXJk?=
 =?utf-8?Q?XyCnZoD6MmDboJxROAGwAZwvdvlEctRhI7szVah+gSN0=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f9e62cf3-f40d-4a8c-1997-08dbd85e4166
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Oct 2023 09:05:54.2744
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8P193MB2301
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=Y6x7U5dJ;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7eaf::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/10/26 3:22, Andrey Konovalov wrote:
> On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@outloo=
k.com> wrote:
>>
>> The idea came from the bug I was fixing recently,
>> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
>>
>> This bug is caused by subtle race condition, where the data structure
>> is freed early on another CPU, resulting in use-after-free.
>>
>> Like this bug, some of the use-after-free bugs are caused by race
>> condition, but it is not easy to quickly conclude that the cause of the
>> use-after-free is race condition if only looking at the stack trace.
>>
>> I did not think this use-after-free was caused by race condition at the
>> beginning, it took me some time to read the source code carefully and
>> think about it to determine that it was caused by race condition.
>>
>> By adding timestamps for Allocation, Free, and Error to the KASAN
>> report, it will be much easier to determine if use-after-free is
>> caused by race condition.
>=20
> An alternative would be to add the CPU number to the alloc/free stack
> traces. Something like:
>=20
> Allocated by task 42 on CPU 2:
> (stack trace)
>=20
> The bad access stack trace already prints the CPU number.

Yes, that is a great idea and the CPU number would help a lot.

But I think the CPU number cannot completely replace the free timestamp,
because some freeing really should be done at another CPU.

We need the free timestamp to help us distinguish whether it was freed
a long time ago or whether it was caused to be freed during the
current operation.

I think both the CPU number and the timestamp should be displayed, more
information would help us find the real cause of the error faster.

Should I implement these features?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB07524EFBE97632D575A91EDB99A2A%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
