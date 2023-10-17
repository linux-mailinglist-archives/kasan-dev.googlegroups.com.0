Return-Path: <kasan-dev+bncBAABBUWYXOUQMGQEANJ6RXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BDFD7CCDC9
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 22:19:31 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7913a5d6546sf456261839f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 13:19:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697573970; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzSKponbZKjPpNwp/NrlfinS5z9tUMiZhOiAQT6zIYW7yxBBS+gTcsTC+9MPORYOJ4
         JSmkazVVsfURsnIFrT00vBNEpTkd+aVt+KPdNUemROeDnNT8YMZnt9t27rDIChypflf4
         C5q9AlC2gr2Shm8IVH6ZkvLdIf7jaa4W9KZwSQOroQ99aAiWeU1HQp440R/wT0Xaxwc9
         hWGAbEnruYI4g0gZXi3j0KoMYivonKM3mLE3IIHsAlvVxUzCVVhSJ+VLI6pdanwjNSbN
         FVhy2oqi9rox4rF9BrMbPvxdNN4yI0BKyk0HxyZttvz8IfGksLlEpR6QvGfkyTUr3XT/
         YNfw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=RYtaGnegEEjDBiXIuzWm0VwSl0fb8OFZ0tmKv7lXSjk=;
        fh=KwGnOaESi3uEdSZ4dtKbj5c9dwQbcmGvMKzH1AjxksQ=;
        b=Hta8Zh19VsgQ5irgAGe3lhlQW3ev+mYpnqPwefGXQ+GvLyWJJBrJNOTJQMUdmuM+Q9
         lYp2AQ08zMKABu0/oBiTecazFv2iqGoRLogkOW8FzMY6foW0zj70ISq6bgUssFruAnpH
         6Ne6boGQYHaQH9k/nnIl4202t1dWIXX09P/pTUVLT2x7/4LRGMjR4UD+z2gGwHeCciz3
         wi8cbDWjz6dHHZEb90e3RpeFIwmOB1OxTj7GSH21s2tpSTp4fFHvjJrOgMfY19+Rgd1O
         YTWBXm+1ObGZ7JCBC34eiVzsYD+gIymE9rQN8MraOhgAnqbqEZNd56I2yWPs98dz6+Go
         xuhw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Kk2C6qDh;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697573970; x=1698178770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RYtaGnegEEjDBiXIuzWm0VwSl0fb8OFZ0tmKv7lXSjk=;
        b=kdBUU7o4Bl9JiOJaIuHZIYhZb8Y9Ff0Rh+xSdE43xBG/bipbjGV2DA2ptdHjUC7X61
         rhKyEazLQnh/f59zPqtQoUNrgOM9HNjzJbWGFKhpa1zppNKe137fIiLcF4xJ8IHlAIUH
         ZgzwdNWLl4tqiRtwzidyS5wsWTi2pLSzGiXj8+iUonOYOqV0+DfT+6pxnwBKNtR863v/
         sezTcqSZVwx/Upx041yvOAyMbHuX5VBVNWXBBIAxQhUIfG+XDDPYWp/OWDfjCb99XjSa
         8BbW82Q6hHxp+BrOAgme5BXSASHAYyyova992VfRn//8NQvHwcN9QaZIdqmAN+jgRKM7
         suVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697573970; x=1698178770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=RYtaGnegEEjDBiXIuzWm0VwSl0fb8OFZ0tmKv7lXSjk=;
        b=q+15vyasysbEWMOQ7y/NEPWC0frXgYn8JDAQLwEjCn1h+WVsN+murRPPy13g/H25G6
         BoW65lS4U3aiG7lLckXqjrQMsjudFFScMmT7pQrfup3eS5XhQOkj1iHlEu4krggYK0Si
         hoAMDICY00vza9zQwtrVdASnLAa5DfFc+Nn6xIM4p6sv5dU7NXzlHHfATUpEWv6fTYmV
         Xh6m4wNI+pkSWkfZOECEVOaaF6dH7T987nQLbcukYcMK5aS2RmnmXZUmSyu81F5mUAjM
         3GYlmngHVC68RaZRm2BPDYKDPDiItDvb6RXCkvsflFcDxFaVh7M3cCJ4DiPrwxVZqdvY
         zkWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxIx7WhIsqW/X8Qg0cU8A6Z10P9IprpUpRRZ2g2rUW1TbUlcE8/
	3F9FyXWqdGZvaoTz082iyew=
X-Google-Smtp-Source: AGHT+IGtqF0XEJJAN0l5Ys5r8uqehazLdDpNS0eukkFQVkGX58QCfc8sAAqtajLkyj58U4NItIf0Qw==
X-Received: by 2002:a92:d604:0:b0:351:526a:4b6 with SMTP id w4-20020a92d604000000b00351526a04b6mr3805218ilm.18.1697573970154;
        Tue, 17 Oct 2023 13:19:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3203:b0:34c:c302:9f98 with SMTP id
 cd3-20020a056e02320300b0034cc3029f98ls839878ilb.2.-pod-prod-02-us; Tue, 17
 Oct 2023 13:19:28 -0700 (PDT)
X-Received: by 2002:a05:6e02:1d9a:b0:357:9eb5:15d6 with SMTP id h26-20020a056e021d9a00b003579eb515d6mr1814507ila.12.1697573967969;
        Tue, 17 Oct 2023 13:19:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697573967; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrMWUBjed3z5TccTerQkky+ZP7+ect8qqR02JFavs1D8CyK9qmnHg46GrWDIXMRssB
         uRvcwrZvj/kOhwQPKCBybOkgFnqQo6J6wiEcsUD7AJBIpcXvHXtvVx4BEjJzqvFxRtgV
         H5OJE6EIg5bk7L/cPbio/XKaRSlYRQgIirKpiByssoTyYL2kLPMi387BlegITGOBHj1m
         VVcLTt1pZL/agNwJk8nq5fW2X9r31s3j5F3k2nzcoX8lwdnULZyoGJhP23XqtuPM7hKT
         9CcIBhE3b204lXL6jr8SEbk35ZHicJrfJJqY06Qq5wAWFr7umXLXtAxM/j2PXIB81FPb
         Yeaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=cDw4QNRhrpdcz12iAryqrnEdVrjJ07EfuZ/2BL8T3/U=;
        fh=KwGnOaESi3uEdSZ4dtKbj5c9dwQbcmGvMKzH1AjxksQ=;
        b=uk3L9rQZW7UzBw6/YOfaokdMJlnPr+EYARg03sit6i69KJXkue9NSguTsF1DK2AF9/
         euyW/x5Og07jWMCHOSpZg75uAPpXo1dyBw4xIg7ocepH5vxtDUiUfYY7K+rdUX5m5CIE
         2RkersPzVcixN7UPpuS2WWW/jeA4VtLrMHkGLjopbyPIq793yJwSyDC/y2Em/A7lWx5Y
         Skpdn886eJqiK8IL3E6vxTL5fYh4eWSTKi9SkS72g/g2Zw517lFchqH/neq2HaCK6mkF
         M3OcYOlr8DnDWWAGmFCBq3UsVQ8G2scyAQUt8oB3sD4u+O8jYqLjtMjSigAgy+BhF8de
         Vuyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Kk2C6qDh;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-VI1-obe.outbound.protection.outlook.com (mail-vi1eur05olkn20801.outbound.protection.outlook.com. [2a01:111:f400:7d00::801])
        by gmr-mx.google.com with ESMTPS id i3-20020a056e02152300b0035250544598si114143ilu.1.2023.10.17.13.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Oct 2023 13:19:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::801 as permitted sender) client-ip=2a01:111:f400:7d00::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=HchAAx481mdhwic1lrvObpqnDUWNR2wcCunlkbBxhCaP4A3cEFGzwHPZ5houPf7o/HGAKf3LTSojtByveJln0ObzXMnMhh49CfRiwbbI5sabAgg4o275DOmqZMUBjdb4SarMKnmV+3C/BEr7msnoC+5DpqwVRp1fFNQ2EeflqvBRY87xLHdZ9fVf86uFqvbh9G7St2UGab/F1USG6pHu+w5YTuO7gBYwm32hF6v19VaKrBOrYtG34ELSubHbEp3x3SVqd//H3Ty1B6teJrsD6zkwkzhAg8wDmvlpHHrMCjheoERvW7xDiP7GsEnKYLcimuw6naVp1atuv54lU5JOHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cDw4QNRhrpdcz12iAryqrnEdVrjJ07EfuZ/2BL8T3/U=;
 b=ih/fFLFM+nX35G5EzVDhB50diQu+A+3LOC9HgByfqZ+eXOIbC6ihrVrIls6xXPwWYaIQfXOi5DZt37gIBaLiawPmE4KgQzqY7SgZtQ5sQOHsKJRWhsUtnC8NywsCu89xY0U+k3MLzOm1luuVcgR5cXgFBRifc8RX2kVw35g3Q5K7xm6lcK4SfUQHghpeQyUF4W8ul72hrAkTEzMFMVhy2aUT3qUzRa9sRM6+MmvwZvaEcWbbKeTtnwb7wVuE8YlL0GIDlk8P2xsDPoxgr7rW6Nvpe7ImfRZp5FZDsiTFtD/fiXT7KK1MCTBVBzcu015L+gBHURDtfSl9cC2SbUMeOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB8P193MB0600.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:15f::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6886.36; Tue, 17 Oct
 2023 20:19:21 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::af68:c2a:73ce:8e99]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::af68:c2a:73ce:8e99%3]) with mapi id 15.20.6886.034; Tue, 17 Oct 2023
 20:19:21 +0000
Message-ID: <VI1P193MB0752C500BCA9E3193366E7D699D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Wed, 18 Oct 2023 04:19:21 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
To: "Ricardo B. Marliere" <ricardo@marliere.net>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 linux-mm@kvack.org,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 kasan-dev@googlegroups.com
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <eqinp4exznpgclzgz3ytjfdbpjffyyfn62dqfiaw2htk4ppa5p@ip25t7yczqc3>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <eqinp4exznpgclzgz3ytjfdbpjffyyfn62dqfiaw2htk4ppa5p@ip25t7yczqc3>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [YAWcUX6F5uacVXMXsIpXKn1iaTT7wF4S]
X-ClientProxiedBy: LO4P265CA0281.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:37a::13) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <cfcf488a-3267-45bb-8cdf-bddd3320b7b9@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB8P193MB0600:EE_
X-MS-Office365-Filtering-Correlation-Id: 70758ed8-4d02-4a36-fa0c-08dbcf4e5956
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: ActTe+xHh6WkP3aW/tJQpEyG7+RSvBO1Co1mWEtQZiuEYx9J1c8Ia/7/uikbJnleKkJiidUt+kdwAr7WOduV1tz6yW1cdh7CbeYIl+XoLkmANpw3dsTkSX7775RXVoHhWp4qPXqFsZhFNC/kwNBuQJsS4HUKyeajSoWkhc627PU8sFsFX4CT6Z8UbbZviyk836T/SeEj0rCItxGfpouJu/hZqzMWclH8twyWjR4PiQ8a83zkaantFVlw60/QM5NfdGpx4Q84hZM8kek8nwJK+P34zY09BJFjLCiI3k3QOgWpmMPOGfr2fArH8DPRTLcopkNBKf8YbkqxCH7I+eDjLjHxyBgaNrz2rjMWBUKmsBXCUyb8/8A8U4W8kbWZVwlgBknPvEpKy9xObKlMCNRdDqyW0qElStiQkwRCm6S4n/8+3HGJ+rG0AfDAxNgEFZTXZTxb4hncYTO7FvXh+P6gS/JDcfxbjaMyR61mVUQFcEFDTqPxrkUEuL74sii+NPGaQ9GjD1QOt3h8g4z352qT0M2MBErCPfooy9W7qCnAKE+aSHr5f8WUwR/pBGxNU7JV
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?TmxhcnprWk9GeWhNem9idWkwbmVMVkxhSmExczNHSnZPUUNQc1BobllpcUZp?=
 =?utf-8?B?RXRORVVraDNOK1U5aWdlVXlYZ2k5ejdpb1JGSGFyMWFFSWFtWllFb0hEaHNk?=
 =?utf-8?B?TjNmV0FYRGlhMmFEWTRETGZRMVhpSFk3cUZRRkJWL0Q4SGI3TGhlSkMzRzdD?=
 =?utf-8?B?MFZxY2RkcC9kYU5TQ1ZLV0tLUjlsVG5WZ1dzSXg4TytkUm51WGxIZlY2bFM3?=
 =?utf-8?B?VEJ5bGQxZ2h0YUREeFlXZStHd3FHMlNWK2NSZWVYTzlsUit4M3RlekQ4ZENk?=
 =?utf-8?B?cVdaaE11YXpqOUhFMzBHbjRXdU5CWWYrSHViK3RnQW1OU1UwdVVMQUQvK0hy?=
 =?utf-8?B?UUd2SDF4UzVHTGg2STZKQUY2dzc1TlNjZnkycWtCc0ZPbzhWQmh6b0s0Nkpj?=
 =?utf-8?B?NDhpeVhNWmNiaGNKLzdGazlUZUxnVzB6S05kVWM5eXVDUDhwSHVpNFozclRk?=
 =?utf-8?B?aVVFUGozVGRoNW8rRENYUDF3RThxNzR0d0NHUmxZQ253NTllS1pvRjJNRnlV?=
 =?utf-8?B?LzU1dSs0cjVMOWd2SElxOUlUQXdwQkdobG9ZMEs0dHcySU1UVFlnTE9rR215?=
 =?utf-8?B?YTN3VUhsTTd5RHc1dytidlIzek5iekovdUk0Z2g1MDF0RDBPQjBsSXNZZWxk?=
 =?utf-8?B?MWhkUW54cy9yMXBPN2Y2ZGxiMW5YWE82SjZWK0dLT2dXNFZUeS93RXJVWGlW?=
 =?utf-8?B?VzV0RXB1UGhTV2w0NGNEYm05WDV5YmNJblJUR0lXL2xwNUZFYnFwbU9aSXBU?=
 =?utf-8?B?aXRlM0pWS1lZc3RMUEh4cTZuZ2pkdklnempQeGR4MS8wbk1zbWRoa25rRFE4?=
 =?utf-8?B?RzZqZzZjOFVRNlJRbXlPcllaOEVWV2ZrdFlGanpBSDIrSFk4d2dibzR6K3Vx?=
 =?utf-8?B?a2pvUWVWWkZMTGtUbU9CR0JFOUlTRXFNTkx0RkdyWE9iNW5LeXViTlhnNEV4?=
 =?utf-8?B?Tm5aRWVVMlVtZjBYQ0xjRnF1RzBwdGJjUUNzTy9UbFY4dGs4dERIVXJyZWZ6?=
 =?utf-8?B?WllGWmtKQ3hMVFF4OHZyWFRvU3ViT2FEUEhyM3Q3RmFZYlk4RTUzNnp5S2dw?=
 =?utf-8?B?NExwREQ3U1lya2t6bElLYzJuL0s0YkRBc2hNb2hzMFVpVFRuMGJ0aFRDLzly?=
 =?utf-8?B?ZWNVSWhYV3RrdmduRG1nRStNKzVvcVZybkxGeEF2MFE1b2tyY3lDSnZtQWpo?=
 =?utf-8?B?eWY1dE5QdW1uKzdEZE9zRGVoSXNBRlEybExTdmZtQ1ZUbUxDN3gwMHVCOVRX?=
 =?utf-8?B?WitzcmFlbGtOdmh3MllTT1VIdVZlRlJSOTIrRFNuUFY5Um5kOTlUakNPeVgv?=
 =?utf-8?B?bmRQSjRCMG5Cc01Pa3RONUZiSnRaS0ZZMHo2ZE1IQXZDUkF3eDZVTkp4Y2Nw?=
 =?utf-8?B?aXJ6eW9rRmlya3g2Qll4OXRoRWordExDaHVvUEV3M3RjOFBYc1VWb3dIdVBo?=
 =?utf-8?B?UkdGaUd3a0VYYXdVaU1uV3A2dlIzdi9Ea3NNOWJNeHZyOEZicks3RG83MUha?=
 =?utf-8?B?NnFxOXF1SFZBTS9BQXFRYVpqT3dzUDQrbHZBckJqaktNVHN2bmR5Rm1jbytP?=
 =?utf-8?B?Y3U2V2dOV2g3c0tlRjFINDJkNjNwWjJlVVFmbk81ZVFaelJhZ2RFSkxrSXpW?=
 =?utf-8?Q?1iYt2nsbadS6MAN377Z7b8BYOH3cj5n92154z2/vCovw=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 70758ed8-4d02-4a36-fa0c-08dbcf4e5956
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Oct 2023 20:19:21.8791
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8P193MB0600
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=Kk2C6qDh;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7d00::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/10/18 4:10, Ricardo B. Marliere wrote:
> On 23/10/18 03:39AM, Juntong Deng wrote:
>> If the free time is slightly before the error time, then there is a
>> high probability that this is an error caused by race condition.
>>
>> If the free time is long before the error time, then this is obviously
>> not caused by race condition, but by something else.
> 
> That sounds a bit arbitrary to me. How do you set the threshold for each
> case? I mean, the fact remains: an invalid read after the object being
> freed. Does it matter what it was caused by? It should be fixed
> regardless.

There is no threshold, and the timestamps are there to make it easier
for us to guess the cause of the error.

More information (timestamps) can help us find the real cause of the
error faster.

We can only fix the error if we find the real cause of the error.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752C500BCA9E3193366E7D699D6A%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
