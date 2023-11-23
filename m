Return-Path: <kasan-dev+bncBAABBHOI7SVAMGQE64UMSMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F7917F5BDC
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 11:06:24 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1cc3130ba31sf7076295ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 02:06:24 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700733982; cv=pass;
        d=google.com; s=arc-20160816;
        b=xdmSbhxdZ8t1GhNV1l24UPdiAimdT8rdpitayyiouDA/lz42pwyh0AedPDAI1fZTf6
         O4ncjPuyeyJCg7mjg3Wd1Ud+wDFCi6PPAMarEg+tVPlsygnIDG+VUa7eSkcnpxjxiBLd
         8xGhQhDqrL768QFLd/0vGrqcZ9RNhB1qMOJR8jYoRTd9l+fA6XKqc1war6dxnTcoLDeS
         9qG/hybGxhRl9fcmZnDAXlMNFVNw7UlxDT/yOcFu5AVELuRhHjjVqHYH8pAU+/PZ6U2j
         NfeM90oXkSl50sTm8GOF1E1NNqpgixcuSt9lZAGNC4Ik6498mZp8HVEpfrAfO5cVsfPG
         TBkw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=PDZ8Q8YZ/L1oxF6AF8LD+PbnYKIigoaS+3GNtCmtaLs=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=w6JF29EFs/c+NmBlkEpVk4C4HpucrDGST/PSOtIw1iJb7VYOR7haiDQH7KVQdpzRvU
         PdRz0Ll7pkWBAKvuMoRF0PhLEFfddoWwh0/YXb9jiOERTtPSFliIoTkcX/gCQGyUPAL8
         5IeXPFfY7yTw3X3erl/qmAODB8YbJnFBq/e12QWjxaFSgfgyv2yFpyVC88vmY8Ko3RMK
         z4VCpAX+eCkvnVtt1XVukbyqdFJJmQBqQ6VqUwaAJcT+q09Br9tSJGEmWCIPieUBOhss
         Izy+ZdTiygQJpdrkY4bGBRUG25DTr5Cr26cDAhMfKoIzi/6DOgv8nIfIpiMAF+W8SKdn
         HJjw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Sc4CJFDY;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe02::822 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700733982; x=1701338782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PDZ8Q8YZ/L1oxF6AF8LD+PbnYKIigoaS+3GNtCmtaLs=;
        b=dA0aFzkC4Evm3e1ePvALCF3ppFAdlk5thUDEtaVn9qYNS948ZaspQb6Y8lDoxJPfqS
         DCqR+jqoCylHB+yT3vhWcKPCaJQLoqF05XVZHiQ0rxAa1/5mTP9Irt5JqscvHYsDkArE
         tl727+X5U+beVZ+GSMr/P2GASfKCE5scBgddDclqtDHNRstwtj7hZO/1s/b89J3RmEhW
         u8C9DfTB2s1DFFf8tRk9xszkmv0c2E5wrOzx8qyoM5F3caRBS4epfFYy3or3S3nkSdrz
         lJPiX8WGB+ew91uD1ETSfMS2m335H0CkleZu5J7dR38CoEO5gYN6UIH9L0rqSgUBorxJ
         5BaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700733982; x=1701338782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=PDZ8Q8YZ/L1oxF6AF8LD+PbnYKIigoaS+3GNtCmtaLs=;
        b=TL/B7cWfLFT/ZIw5lYVze9gSGMbTCmqV8IvKP2O/STa7gJb/CtCKrmllqpVgOfBioJ
         QqFc+X/KDJynRkW8fSPQJ75Esg28ViFi7pmqrgDvZo3EF0vm+K31pe1vKauDhVmjyZNL
         6o9vdRh+O0OTo6yx2flMoCRZJQxMLGtpJqaBisvtx84H1C8Xl24A9qJgC9/6OVgXAZeC
         b82mKOmNAvVwAFL7WF5ikj2fKft76NZ5iX9sWg6CwAtwMz4sWg+g+4nNh03S896WHwXH
         d7PL+8XV2tBgN8oq5GWxGCsJqqflCtnoW+0jLOa318ZsaO1dEz6ppHVtpIACIXoueQIP
         eFpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxFQjPuRlTwyY5IJkpFoWARxte4X4+e4EGIMskvCaq4KJe/DAZ/
	z4YmlBU0mYabF/GlY+ShDyc=
X-Google-Smtp-Source: AGHT+IGMV0jqLDnF8wFn2LfOAcCtv1m29yXAksYBSA5nEAfp/tFJ4upLaatw5NKvlX/w3FBhqhei3A==
X-Received: by 2002:a17:902:efc4:b0:1cf:8a91:a84e with SMTP id ja4-20020a170902efc400b001cf8a91a84emr1404480plb.50.1700733982083;
        Thu, 23 Nov 2023 02:06:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80d:b0:1cf:6bb1:fcd7 with SMTP id
 u13-20020a170902e80d00b001cf6bb1fcd7ls462371plg.1.-pod-prod-01-us; Thu, 23
 Nov 2023 02:06:21 -0800 (PST)
X-Received: by 2002:a17:902:830a:b0:1c5:befa:d81d with SMTP id bd10-20020a170902830a00b001c5befad81dmr4423012plb.10.1700733981031;
        Thu, 23 Nov 2023 02:06:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700733981; cv=pass;
        d=google.com; s=arc-20160816;
        b=i7aHJinRQNm9fwWcZJgZaTKyumUC0w0YauS9rUmEoNX/ByFnNJa6dOfA6Phqk6779v
         0Zmjyclqz7HKiMEzo50dGL5ROstFPdlR2yagtNuTmtDAs+J9ZFJPr2VB9p1JW+z+VRgH
         Wfy9nIGnBH2GsEf58ylWzYlqBlCoU+Pzj0Pp7fF8SrUzGTlAD4HeCbIgz2308HU1bvwn
         vWD2CD7qbSsSJcI/zCpheMaK4si39msKrOVX5fn4zn3TIbG5WnUmaxWWR4gEVdxZ+NgF
         P06gIRmohXkHcAS+/4obLCF31C/XRS+E74axPvJW4IaiI6eOLEUgUUmTXUrPFzc0vZgG
         AeIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=B6bR/IFOw82mgJYNFjjPT5zeJmdfBxerdImFv9Qm7Z0=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=J4EvcBqhakQ6HJvw9vneCy4DIq0ut+CzvrrgVh8YzVt3kmatydljQPJoCZZepkNJDj
         9uQk0JYt0IdSw3vNaKKU/PCy3Ce0vHlSdWmZiLOKhl7szZuWtDL2rKFBHX+8alq5GNG+
         qMEdr6XhBStEZq7Ym9rYFM6hBl7IYmQJ2hLKL07uT4Njf59RqrzUpYpPlFCXoSt6onYY
         NllHu/EXJ0rvgLaDVcFv01tZGPBHH8Z8UjhuL+vxg6etXkbdz5clUrLSKXUkK/4gCIE9
         4eCROkDr1zAV1rWiuNemNBdFtwrvEF4vcqIGyo7Zp9AqM4K7OUfCvSmIiEDO8owjHidF
         UUWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Sc4CJFDY;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe02::822 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR01-DB5-obe.outbound.protection.outlook.com (mail-db5eur01olkn0822.outbound.protection.outlook.com. [2a01:111:f400:fe02::822])
        by gmr-mx.google.com with ESMTPS id u19-20020a170903109300b001c60e01c522si46071pld.7.2023.11.23.02.06.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Nov 2023 02:06:21 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe02::822 as permitted sender) client-ip=2a01:111:f400:fe02::822;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=oOn0C3EIc1ubWUe7E+P/uuW7BGe+z0ziVY0wOp4lq4B1Ki2Q+8fkee0cmziSgHFfdXjvA/3L92qh58ohRCEEVxuzhv07ibsL87ymzYKuKlilE4dkR7qpJpGzKaooHY3i7lc8p8nowyhCs7bEgZaPL5einzL1vQSN8doH3qLeQx5mjYMeREX0IozcyqYmvylebPIu/16PeYiOqYJBJHlA8RrlRyYmLGmf8FhWJdIpHUnDE7DX0cLdtK/hcT3GMr3FUMPrXHM7crCDcO9TH9YZxmL1xeR8cWuUlnU9fcm2b/EchFLCm9w8dtZJRopdcCyGVOjTY/O548QemeN4xhY0+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=B6bR/IFOw82mgJYNFjjPT5zeJmdfBxerdImFv9Qm7Z0=;
 b=fOvfph1dndMEiOMbnbYBbirm+jNlMHGqbyan5BHzabRx/C6WbR56PJPobOxk98g19KOg5x8x5xL9WaQFH3ee874tfgsrAkX1eIm/ypIIux6u0TZ4kzXv3aRBUAp/pYiPofO95p4YcrXmiR3ulXCyxvlylnw23IArCIEt0qotgln8GGFtRbeov2hzCZzjOkFjwg+RvjtG1QwnU327sNgfjk/JeFH2cxL/3XK0VXqMDVaFBnVJGBOarnISRMiswd9gS8B2UEBpeGWun9j+ImarxDPF6KKepUteI6fqzZFaXOc2w+oJXkNg9cMFdVixLDqoNVNv6GroLAPR245hLMXRJA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB8P193MB0757.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:145::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.20; Thu, 23 Nov
 2023 10:06:18 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.020; Thu, 23 Nov 2023
 10:06:18 +0000
Message-ID: <VI1P193MB075296EFE305E5A6C3A4701699B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Thu, 23 Nov 2023 18:06:18 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC PATCH] kasan: Record and report more information
To: Dmitry Vyukov <dvyukov@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <VI1P193MB0752058FAECD2AC1E5E68D7399B3A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+Ya4yTvAmaELJN5st3GJYo1KKzC9qw9sdD0g3jb48O7tg@mail.gmail.com>
 <VI1P193MB075265616010AF82CE201ADD99B1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+ZE8DO1u6NHATXC9tfcVS4diM0LO4r3cQ15HaGHVoFAbQ@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CACT4Y+ZE8DO1u6NHATXC9tfcVS4diM0LO4r3cQ15HaGHVoFAbQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [4kCbHZwt9ARI4aFKbKUlgoB8+hukrqur]
X-ClientProxiedBy: LO4P123CA0513.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:272::23) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <e96345d4-6313-4f5b-aa75-c5e08df18a7a@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB8P193MB0757:EE_
X-MS-Office365-Filtering-Correlation-Id: a7691dfb-4934-43c7-9f92-08dbec0bd59b
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: tPSEWYlGUTxoTLGi7jqe/H9GbvZnH27BKIkoA7dGwlqaDjS+2KaBFOhEEdBgtGFdl2BsrZ7WXBc7wQblcdznywAPrNcdxTkmN+W1SKgrvy3wBAGINhhQ8OKPZaUWhrDyO0Owl68lp0JONiQocXYPYC9gGGbKpgrxKe0yp9u9sR7dBfpKLr33tKfMtI9fUeZ/uIQ/kfCX+V1PI5+irlXl2p0rOU9NkcicsiQ088vIAXM2uYX443qONVaVwlkhHcvNYdyTQJWwnS6T7CxdM+KctLObBbttczR0ZW+q82IrGxG2SuCYOY2DBjS/ANax8yvmQCRKXPjm79+cRkzhM2ly8z7uy1Aduc9LVOUM98TzsZxbsc021z8URFEQTLT0N9jjtYxYWFtfORWXRH8JUd0/A27Sozh226gSNgG4ySdj27zeOkZDb2vYS+Bxnc/wHf+EazZcjCyTv0lEWnQk1OQADQhxwDWkNlF61TZIBpKDiC5jsg0eJ0fNDmntxbbIoJK7+XPqwFHmiGAtrgipcnzDPSvG5J1MfhQ8CPabB1VFaBE9+A9CVOKtXO+YBZH6QWWRGMLqQrNWbR9ZHZWIvH2i4P56n7z8hqAVmL54PK2LXKA/KxBnzRq/3DUJz6F0Zlph
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?dURUek16dkVRL0dSRzh6MVRzVUhLNVp3RXNGVEh4WHo0SGxEa1ZhQmVDT0FC?=
 =?utf-8?B?aVJBcEFVZC9LL04xdSs5ZWkweTA1SmNhS2FzcEFwT1k0VjRrYmZjaW1lYjEv?=
 =?utf-8?B?V00xUExFZmU0SWlkYzZNb0FFT3FzV1NsQ2s0elppQWYvdVJzSEgvbWtpaTdI?=
 =?utf-8?B?VFpxWjd1ZGYreldwZzNYK2pQSE42dHBZTXkvL0lkNmFZUWtyaDgzelV3Ri8w?=
 =?utf-8?B?T2p4b2JhNWdHWnQ0MVVaNGRwTnpwa0doVjg1MjVaaEx4VTFQUmg5cW1qVlRK?=
 =?utf-8?B?K0xZdkNoVy96cG9xSE85a0RlQ3FPYWpUcmtidVdqd3laMGpHMk03Z0hkRnpy?=
 =?utf-8?B?bnRrcVFsWVhEQkpZTVdCSVU5d0JtRzNpNkg0VVFDS05oQzdtZjZUeis3V2Vj?=
 =?utf-8?B?dmkra2VWTnZzZStXbmVDVHI3VzBnUnpTeG9xVHNJM2I2bTN0QktiMXhGYS9o?=
 =?utf-8?B?NDVLamluc0NtNWdTTjdhQmlOWXdPL3liS0FCM1NOejNLTXAwQXhNd05HdXgr?=
 =?utf-8?B?TUJ3UlIzeFJBeUtSNVphcnRnTS9KdUdTNnBLZUxYK1ErQVB4anVmK0VvUERD?=
 =?utf-8?B?anpPaWNDRnpwWDcxR2FweWVyMndxU3d0RHNRb0NOMElwOHRnd2g1djF1SElw?=
 =?utf-8?B?T1h0d3pjNlFudk1DUVZpRkh2T0o3cDRnaGtka21ianhERzFaQW1iYTlCQmdS?=
 =?utf-8?B?VlVtTEUwNDNtZ2NjK25qUFdxZjVBOGpMaDRMRFFJM215Y3RRcHZSTzRTTEhk?=
 =?utf-8?B?WFk2WjEyVFJVVUhaak9lODl4dzNubnhabHRsVk9raGNGU1BkbFQyMTlaTVZi?=
 =?utf-8?B?clZ2T3F3VXQwUnRQNzNzRFJoVmZXa3ozdnAySy9rbWx4SE5OYXhHOWhzTVN1?=
 =?utf-8?B?VzdWYkVCWTBsTEZQR1hlb3p5OS9GSGREbzI2M3VuUUtxNExsYjRsVDcySk1I?=
 =?utf-8?B?Uk1hUkV6T0VNaUN4YWtWL3M3QTdBMW55VGFHSEVyZERmUW5YV04vSkxSZW9G?=
 =?utf-8?B?SnhKbTBqbkxya0l6enZmRzRoWFl5dEtoWTRsQTFIQkFONm13NEpYNlMrM0Nj?=
 =?utf-8?B?RTdCR2xUa3QwWStXN1BZbkRUYkVoWktXZzNxSGdQSDN2aVBFY2c2dkc5VDgw?=
 =?utf-8?B?R0xuMExZVTMvaTFhNFJveUJ6MWZKWllPMzkzb0RTMGwrcVZZSS9sOG1BSm5z?=
 =?utf-8?B?TGhOSXhXOGMycVVFNU1aTEZYdjIyNE0rZU5ldmJqZkwwNW1saUMvWlp6c3FT?=
 =?utf-8?B?U2tNTGNEUDhzdUdMQnF5QjdUT0JqRWVxcjU3UnU3ZVFSRk45MDJNdFcvQjMw?=
 =?utf-8?B?U2xHUEdtd044aUZKaCtGTCsvVnlXZE15aUpNTG5LcUhkZUJIaTRBWE1UclFl?=
 =?utf-8?B?OFY0NWZ5MlBzOHM4RnI3dmRtSTJmQVhEcklCWG1XVmVKTjZoN1ZqNjRmKyty?=
 =?utf-8?B?TkxseXlRZTUvVTRGWjF4dmZ1dHk0OS94bVZLM1IxZFBXNTJsZjljUkJrWjNM?=
 =?utf-8?B?cklYb2l5NXhDSzQ4N1dldVZBc0lmZ2c5b0RzSkJFSm1QVFB2VDZqUnlSelM1?=
 =?utf-8?B?TGFBR2VITkhnS1BuaFZjbjFkVG52Y2lvNXlqOWVLQlA3emhQY0pobG5YMDZL?=
 =?utf-8?Q?Pu5tBXLk0JpwERK0SA1/RDOMrfQ3rkXWuGN5X6IZE2qA=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a7691dfb-4934-43c7-9f92-08dbec0bd59b
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Nov 2023 10:06:17.9955
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8P193MB0757
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=Sc4CJFDY;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe02::822 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/11/20 19:06, Dmitry Vyukov wrote:
> On Wed, 15 Nov 2023 at 22:53, Juntong Deng <juntong.deng@outlook.com> wrote:
>>
>> On 2023/11/14 15:27, Dmitry Vyukov wrote:
>>> On Mon, 13 Nov 2023 at 22:17, Juntong Deng <juntong.deng@outlook.com> wrote:
>>>>
>>>> Record and report more information to help us find the cause of
>>>> the bug (for example, bugs caused by subtle race condition).
>>>>
>>>> This patch adds recording and showing CPU number and timestamp at
>>>> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO), and
>>>> adds recording and showing timestamp at error occurrence (CPU number
>>>> is already shown by dump_stack_lvl). The timestamps in the report use
>>>> the same format and source as printk.
>>>>
>>>> In order to record CPU number and timestamp at allocation and free,
>>>> corresponding members need to be added to the relevant data structures,
>>>> which may lead to increased memory consumption.
>>>>
>>>> In Generic KASAN, members are added to struct kasan_track. Since in
>>>> most cases, alloc meta is stored in the redzone and free meta is
>>>> stored in the object or the redzone, memory consumption will not
>>>> increase much.
>>>>
>>>> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
>>>> struct kasan_stack_ring_entry. Memory consumption increases as the
>>>> size of struct kasan_stack_ring_entry increases (this part of the
>>>> memory is allocated by memblock), but since this is configurable,
>>>> it is up to the user to choose.
>>>>
>>>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
>>>> ---
>>>>    lib/Kconfig.kasan      | 11 +++++++++++
>>>>    mm/kasan/common.c      |  5 +++++
>>>>    mm/kasan/kasan.h       |  9 +++++++++
>>>>    mm/kasan/report.c      | 28 ++++++++++++++++++++++------
>>>>    mm/kasan/report_tags.c | 18 ++++++++++++++++++
>>>>    mm/kasan/tags.c        | 15 +++++++++++++++
>>>>    6 files changed, 80 insertions(+), 6 deletions(-)
>>>>
>>>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>>>> index fdca89c05745..d9611564b339 100644
>>>> --- a/lib/Kconfig.kasan
>>>> +++ b/lib/Kconfig.kasan
>>>> @@ -207,4 +207,15 @@ config KASAN_MODULE_TEST
>>>>             A part of the KASAN test suite that is not integrated with KUnit.
>>>>             Incompatible with Hardware Tag-Based KASAN.
>>>>
>>>> +config KASAN_EXTRA_INFO
>>>> +       bool "Record and report more information"
>>>> +       depends on KASAN
>>>> +       help
>>>> +         Record and report more information to help us find the cause of
>>>> +         the bug. The trade-off is potentially increased memory consumption
>>>> +         (to record more information).
>>>> +
>>>> +         Currently the CPU number and timestamp are additionally recorded
>>>> +         at allocation and free.
>>>
>>> Hi Juntong,
>>>
>>> Thanks for working on this.
>>>
>>
>>
>> Thanks for your reply!
>>
>>
>>> As a KASAN developer I understand what this is doing, but I am trying
>>> to think from a position of a user that does not know details of KASAN
>>> implementation. From this position it may be useful to say somewhere
>>> that information is recorded "per heap allocation". Perhaps something
>>> like:
>>>
>>> "Currently the CPU number and timestamp are additionally recorded for
>>> each heap block at allocation and free time".
>>
>>
>> Yes, I agree, that is a better expression.
>>
>>
>>>
>>> Also it's unclear what the memory consumption increase is. You say
>>> "potentially|, so may it not increase at all? If it increases, by how
>>> much? I obviously want more information, if I can afford it, but I
>>> can't understand if I can or not based on this description. I would
>>> assume that this may be a problem only for small/embedded devices.
>>> Can we provide some ballpark estimation of the memory consumption
>>> increase? And somehow say that's probably not an issue for larger
>>> machines?
>>>
>>
>>
>> How about this expression?
>>
>> Currently, in order to record CPU number and timestamp, the data
>> structure to record allocation and free information will increase
>> by 12 bytes.
>>
>> In Generic KASAN, this affects all allocations less than 32 bytes.
>> In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
>> boot parameter increases the memory consumption by
>> 12 * stack_ring_size bytes.
> 
> Let's go with this version.
> 
> 
>>>>    endif # KASAN
>>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>>>> index 256930da578a..7a81566d9d66 100644
>>>> --- a/mm/kasan/common.c
>>>> +++ b/mm/kasan/common.c
>>>> @@ -20,6 +20,7 @@
>>>>    #include <linux/module.h>
>>>>    #include <linux/printk.h>
>>>>    #include <linux/sched.h>
>>>> +#include <linux/sched/clock.h>
>>>>    #include <linux/sched/task_stack.h>
>>>>    #include <linux/slab.h>
>>>>    #include <linux/stacktrace.h>
>>>> @@ -50,6 +51,10 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
>>>>    {
>>>>           track->pid = current->pid;
>>>>           track->stack = kasan_save_stack(flags, true);
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       track->cpu = raw_smp_processor_id();
>>>> +       track->ts_nsec = local_clock();
>>>
>>> What does "local_" mean? Is this clock value comparable across CPUs?
>>>
>>
>>
>> No, local_clock is the local CPU clock and cannot be used for comparison
>> across CPUs, I made a mistake here.
>>
>> I delved into the clock subsystem of the Linux kernel today and I found
>> that we have two choices.
>>
>> - sched_clock(): based on jiffies, high performance, but on some
>> hardware, it will drift between CPUs.
>>
>> - ktime_get_boot_fast_ns(): based on clocksource, highly accurate,
>> can be compared between CPUs, but performance is worse (seqlock).
>>
>> I tested 100000 calls respectively on my laptop, the average of
>> sched_clock() is 17ns and the average of ktime_get_boot_fast_ns()
>> is 25ns.
>>
>> ktime_get_boot_fast_ns() takes about 1.5 times as long as sched_clock().
>>
>> With Generic KASAN enabled, the average of one memory allocation is
>> 3512ns on my laptop.
>>
>> Personally, I prefer ktime_get_boot_fast_ns() because it is more
>> accurate and the extra time is insignificant for the time required for
>> one memory allocation with Generic KASAN enabled.
>>
>> But maybe using ktime_get_boot_fast_ns() would have a more serious
>> impact on small/embedded devices.
>>
>> Which do you think is the better choice?
> 
> I don't have a strong preference.
> 
> Re drift of sched_clock(), do you mean unsynchronized RDTSC on
> different cores? I had the impression that RDTSC is synchronized
> across cores on all recent CPUs/systems.
> 


After discussions with Marco Elver, I now think that perhaps continuing
to use local_clock() is a better option.

The full discussion with Marco Elver can be found at
https://groups.google.com/g/kasan-dev/c/zmxwYv8wZTg

Because local_clock() is the clock source used by printk and is the
default clock source for ftrace.

Using local_clock() as the clock source for KASAN reports makes it
easier to correlate the timestamps of allocations, frees, and errors
with the timestamps of other events in the system.

This is perhaps more important than being able to accurately compare
across CPUs.

What do you think?


> 
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>    }
>>>>
>>>>    #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>>>> index 8b06bab5c406..b3899a255aca 100644
>>>> --- a/mm/kasan/kasan.h
>>>> +++ b/mm/kasan/kasan.h
>>>> @@ -187,6 +187,10 @@ static inline bool kasan_requires_meta(void)
>>>>    struct kasan_track {
>>>>           u32 pid;
>>>>           depot_stack_handle_t stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       u32 cpu;
>>>> +       u64 ts_nsec;
>>>
>>> This increases the size of meta from 8 to 24 bytes.
>>> Can we somehow store the timestamp as 32 bits? Maybe compress the CPU
>>> number (it shouldn't be larger than 20 bits?)?
>>> I see below we report on microseconds, so we don't low bits of the
>>> timestamp as well.
>>>
>>
>>
>> Maybe we can use bit field.
>>
>> struct kasan_track {
>>          u32 pid;
>>          depot_stack_handle_t stack;
>> #ifdef CONFIG_KASAN_EXTRA_INFO
>>          u64 cpu:20;
>>          u64 ts_sec:22;
>>          u64 ts_usec:22;
>> #endif /* CONFIG_KASAN_EXTRA_INFO */
>> };
>>
>> For example, 20-bit cpu, 22-bit ts_sec, 22-bit ts_usec, 64 bits
>> (8 bytes), and the data structure is 16 bytes in total.
> 
> This looks better.
> Can't we have a single field for time instead of ts_sec/usec?
> Both sched_clock() and ktime_get_boot_fast_ns() return just u64.
> 
>> If the data structure becomes 16 bytes, it will not affect objects
>> larger than 16 bytes.
>>
>> But the bit field can only be used in struct kasan_track (Generic),
>> and cannot be used in struct kasan_stack_ring_entry (SW_TAGS KASAN
>> and HW_TAGS KASAN).
>>
>> Because we need to use READ_ONCE and WRITE_ONCE to read and write
>> struct kasan_stack_ring_entry, but READ_ONCE and WRITE_ONCE cannot
>> read or write bit field.
> 
> If that's necessary, we could store both values as a single u64 and
> the manually pack/unpack.
> 
> 
>>> I see there is a deficiency in kasan_cache_create():
>>> https://elixir.bootlin.com/linux/latest/source/mm/kasan/generic.c#L412
>>>
>>> If free_meta does not fit into the object, we add it after the object.
>>> But we could overlap it with the object.
>>> For example if the object size is 16 bytes and free_meta size is 24
>>> bytes, we could increase object size to 24, while currently we
>>> increase it to 16+24 = 40.
>>> We need to place it after the object only if we have these other cases
>>> "(cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor".
>>>
>>> Currently it affects only kmalloc-8 slab.
>>> But with this change it will affect at least kmalloc-16 slab as well.
>>>
>>
>>
>> I completely agree that we can use both object space and redzone
>> space to store free meta, thereby further reducing the extra memory
>> consumption caused by KASAN.
>>
>> Of course, in this case we need to readjust the offset of the
>> alloc meta.
>>
>> If you agree I can make this change in a separate patch.
> 
> This would be good. Thanks.
> 
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>    };
>>>>
>>>>    enum kasan_report_type {
>>>> @@ -202,6 +206,7 @@ struct kasan_report_info {
>>>>           size_t access_size;
>>>>           bool is_write;
>>>>           unsigned long ip;
>>>> +       u64 ts_nsec;
>>>>
>>>>           /* Filled in by the common reporting code. */
>>>>           const void *first_bad_addr;
>>>> @@ -278,6 +283,10 @@ struct kasan_stack_ring_entry {
>>>>           u32 pid;
>>>>           depot_stack_handle_t stack;
>>>>           bool is_free;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       u32 cpu;
>>>> +       u64 ts_nsec;
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>    };
>>>>
>>>>    struct kasan_stack_ring {
>>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>>> index e77facb62900..b6feaf807c08 100644
>>>> --- a/mm/kasan/report.c
>>>> +++ b/mm/kasan/report.c
>>>> @@ -25,6 +25,7 @@
>>>>    #include <linux/types.h>
>>>>    #include <linux/kasan.h>
>>>>    #include <linux/module.h>
>>>> +#include <linux/sched/clock.h>
>>>>    #include <linux/sched/task_stack.h>
>>>>    #include <linux/uaccess.h>
>>>>    #include <trace/events/error_report.h>
>>>> @@ -242,27 +243,40 @@ static void end_report(unsigned long *flags, const void *addr, bool is_write)
>>>>
>>>>    static void print_error_description(struct kasan_report_info *info)
>>>>    {
>>>> +       unsigned long rem_usec = do_div(info->ts_nsec, NSEC_PER_SEC) / 1000;
>>>> +
>>>>           pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
>>>>
>>>>           if (info->type != KASAN_REPORT_ACCESS) {
>>>> -               pr_err("Free of addr %px by task %s/%d\n",
>>>> -                       info->access_addr, current->comm, task_pid_nr(current));
>>>> +               pr_err("Free of addr %px by task %s/%d at %lu.%06lus\n",
>>>> +                       info->access_addr, current->comm, task_pid_nr(current),
>>>> +                       (unsigned long)info->ts_nsec, rem_usec);
>>>>                   return;
>>>>           }
>>>>
>>>>           if (info->access_size)
>>>> -               pr_err("%s of size %zu at addr %px by task %s/%d\n",
>>>> +               pr_err("%s of size %zu at addr %px by task %s/%d at %lu.%06lus\n",
>>>>                           info->is_write ? "Write" : "Read", info->access_size,
>>>> -                       info->access_addr, current->comm, task_pid_nr(current));
>>>> +                       info->access_addr, current->comm, task_pid_nr(current),
>>>> +                       (unsigned long)info->ts_nsec, rem_usec);
>>>>           else
>>>> -               pr_err("%s at addr %px by task %s/%d\n",
>>>> +               pr_err("%s at addr %px by task %s/%d at %lu.%06lus\n",
>>>>                           info->is_write ? "Write" : "Read",
>>>> -                       info->access_addr, current->comm, task_pid_nr(current));
>>>> +                       info->access_addr, current->comm, task_pid_nr(current),
>>>> +                       (unsigned long)info->ts_nsec, rem_usec);
>>>>    }
>>>>
>>>>    static void print_track(struct kasan_track *track, const char *prefix)
>>>>    {
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       unsigned long rem_usec = do_div(track->ts_nsec, NSEC_PER_SEC) / 1000;
>>>> +
>>>> +       pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
>>>> +                       prefix, track->pid, track->cpu,
>>>> +                       (unsigned long)track->ts_nsec, rem_usec);
>>>> +#else
>>>>           pr_err("%s by task %u:\n", prefix, track->pid);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>           if (track->stack)
>>>>                   stack_depot_print(track->stack);
>>>>           else
>>>> @@ -544,6 +558,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>>>>           info.access_size = 0;
>>>>           info.is_write = false;
>>>>           info.ip = ip;
>>>> +       info.ts_nsec = local_clock();
>>>>
>>>>           complete_report_info(&info);
>>>>
>>>> @@ -582,6 +597,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
>>>>           info.access_size = size;
>>>>           info.is_write = is_write;
>>>>           info.ip = ip;
>>>> +       info.ts_nsec = local_clock();
>>>>
>>>>           complete_report_info(&info);
>>>>
>>>> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
>>>> index 8b8bfdb3cfdb..4d62f1b3e11d 100644
>>>> --- a/mm/kasan/report_tags.c
>>>> +++ b/mm/kasan/report_tags.c
>>>> @@ -26,6 +26,18 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>>>>           return "invalid-access";
>>>>    }
>>>>
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +static void kasan_complete_extra_report_info(struct kasan_track *track,
>>>> +                                        struct kasan_stack_ring_entry *entry)
>>>> +{
>>>> +       u32 cpu = READ_ONCE(entry->cpu);
>>>> +       u64 ts_nsec = READ_ONCE(entry->ts_nsec);
>>>> +
>>>> +       track->cpu = cpu;
>>>> +       track->ts_nsec = ts_nsec;
>>>> +}
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>> +
>>>>    void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>    {
>>>>           unsigned long flags;
>>>> @@ -82,6 +94,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>
>>>>                           info->free_track.pid = pid;
>>>>                           info->free_track.stack = stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +                       kasan_complete_extra_report_info(&info->free_track, entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>                           free_found = true;
>>>>
>>>>                           /*
>>>> @@ -97,6 +112,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>>>
>>>>                           info->alloc_track.pid = pid;
>>>>                           info->alloc_track.stack = stack;
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>                           alloc_found = true;
>>>>
>>>>                           /*
>>>> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
>>>> index 7dcfe341d48e..474ce7e8be8b 100644
>>>> --- a/mm/kasan/tags.c
>>>> +++ b/mm/kasan/tags.c
>>>> @@ -13,6 +13,7 @@
>>>>    #include <linux/memblock.h>
>>>>    #include <linux/memory.h>
>>>>    #include <linux/mm.h>
>>>> +#include <linux/sched/clock.h>
>>>>    #include <linux/static_key.h>
>>>>    #include <linux/string.h>
>>>>    #include <linux/types.h>
>>>> @@ -92,6 +93,17 @@ void __init kasan_init_tags(void)
>>>>           }
>>>>    }
>>>>
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
>>>> +{
>>>> +       u32 cpu = raw_smp_processor_id();
>>>> +       u64 ts_nsec = local_clock();
>>>> +
>>>> +       WRITE_ONCE(entry->cpu, cpu);
>>>> +       WRITE_ONCE(entry->ts_nsec, ts_nsec);
>>>> +}
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>> +
>>>>    static void save_stack_info(struct kmem_cache *cache, void *object,
>>>>                           gfp_t gfp_flags, bool is_free)
>>>>    {
>>>> @@ -124,6 +136,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>>>>           WRITE_ONCE(entry->pid, current->pid);
>>>>           WRITE_ONCE(entry->stack, stack);
>>>>           WRITE_ONCE(entry->is_free, is_free);
>>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>>>> +       save_extra_info(entry);
>>>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>>>
>>>>           /*
>>>>            * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
>>>> --
>>>> 2.39.2
>>>>
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB075296EFE305E5A6C3A4701699B9A%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
