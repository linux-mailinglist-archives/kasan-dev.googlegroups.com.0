Return-Path: <kasan-dev+bncBAABBS7I7GVAMGQEXPU4GDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5682C7F52B2
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 22:36:13 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-5cce4a6a3basf2674827b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 13:36:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700688972; cv=pass;
        d=google.com; s=arc-20160816;
        b=cbShkYytRzYSjulR1nUeYa9y08zPDBNUIBwM81ZQXyheTNYp9K8wEdWxQmq0XcAyfD
         YyoYhJApQjBtWiATNJwyRQDfJHRI4NFVNdGigSEj6W43wAH3TCdN/WtdJF7oFUnlyv4t
         OpZtFjEfHSNPTdSg01gg5XYoJZ3bGFmVZbQu/oeUsJBv5RjJ45O87YqTIZ6t/GGzjBVz
         mMLLQJ4SYeZs/FmQQrOsQrKx8IaGhg+AZuNMcE4d8tY+WA3XkS+ygV4By94PYlcSPBfQ
         vbebFctkvy8BBjMFUwxwX0WPxjtnMAGK5DZblunQXBgCCKOGMG+GgQJf+4UuelHIBPC7
         TZxw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=DwX5By2bd/6NpEEqTeymxOjSIZcgSqcjj8gYm8gXAkE=;
        fh=ZPR0T8cST3w7zq2qt1LodueNlO+CD3oD3KyLDysf0ds=;
        b=Z0o9BN8hJ262wtFIPGegsUCD0d6qc4LWJvScYs+4yMRAeRy3ZRySJT2D31mGLr2KGt
         nznOICir4r1BuEpfRE6reRLeIngNWMCBp+JvCz3qoKFJZiq7NcQ3OhNTN33m3K3A/Qwm
         l0y++Bi3Y1lIEVRX8htsGooWKMbF6vgf7qK9GihCdYeXoM/oJeV/7fPSaG8G2Wuykoof
         QFgcj+AADOPRTqkgcuGs7fHT/13LsFBgXs2sT0m3/gMZk4Ly2PVae6bJqcATAmkpIgMe
         roKsuHoaSF2dOaIrUxt2l+4CAcUE66dIkKfE+1wzgYtsQJLc+B4uASOKxIvQKB0l143j
         DIIQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=t4hJeKLH;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe12::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700688972; x=1701293772; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DwX5By2bd/6NpEEqTeymxOjSIZcgSqcjj8gYm8gXAkE=;
        b=mFMab33EGepDe4f8WDybb8OhiDCFzFMG9TxvfHLk9bBNBH5uAG+2w32zUQ3MBx9i9z
         5Yqgo5pBb+YlV853QWkHn7YrXrGEb/nCQ4zXf2F9NuTq6Ex4Lkn4H+3MHk57cQCbDJ9J
         FkrOK3GCFFvnzh2XZkLLhw4l+mW5NGhHoNVmxiYCpv+LPc+mlPPWZP8ER0PlMsqkQ1r6
         ZFvche/CqRienvEJ6QijR3ygdNLwWEvKaa5hSKwU156plXFlmWWp1Iq78e3QcQQD4dBE
         +kLkdTbVb2cZbWWccVy6cOqPFoPs9B+z++gf1qaNC4oGG3+cTwW45zmAbJHLbLs6mwW1
         Y49A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700688972; x=1701293772;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DwX5By2bd/6NpEEqTeymxOjSIZcgSqcjj8gYm8gXAkE=;
        b=rLcjlPamdYvQBtukG8h7v6tuQ5I6YBg3QhsyERsntniwao+id1ci8Khz3Bgt2s46gl
         /fGxaGz/joMZapGYPLlZcwpMCWPn0w394ZC0YwEsOkdEWKR5gGoD8PmeKD7lGfIh/mOZ
         2Mz5gHo+QCWanrh1S8MNq6nbty1+v3+AcjG3BBW9BTBLAYy0rbb4MxMchrTJmT+5hW9E
         Zr6/jHP+FoBSf9qJ6HqECdILUED7ByWhxsuA3UJlUNSkARu2jx2rRow/GKOJdhWix70o
         t4Mg4FtWWkg6sbxoJEXkL1H7Vc6lou6kDwja4yXYSMoN25+V/J0doMWvnPfk2KBYiKUQ
         Wpqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzkOuAvUyONC3ZU6gU1AB/wrWuoW1Iq6mkpViBCIgBKkFfmQbFM
	bJGHJcWgkiAIdO2xGmpXH5U=
X-Google-Smtp-Source: AGHT+IGJsqmiDG1IF0wtAOaAoL0Cd9bdci8Q/h/tNv2AWkz6OayOR7Udnq0bPZsCYJf4azXpRyHPfg==
X-Received: by 2002:a81:b726:0:b0:5cc:d0bc:fc24 with SMTP id v38-20020a81b726000000b005ccd0bcfc24mr2035767ywh.22.1700688971898;
        Wed, 22 Nov 2023 13:36:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:43c1:0:b0:679:fa52:346a with SMTP id o1-20020ad443c1000000b00679fa52346als255420qvs.0.-pod-prod-09-us;
 Wed, 22 Nov 2023 13:36:11 -0800 (PST)
X-Received: by 2002:a1f:4b02:0:b0:4ac:5a8:f45b with SMTP id y2-20020a1f4b02000000b004ac05a8f45bmr4042844vka.5.1700688970977;
        Wed, 22 Nov 2023 13:36:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700688970; cv=pass;
        d=google.com; s=arc-20160816;
        b=Up114IXcHZhefaYlecElJewfnoDgtvA7NxzXSN8DUeKEYjbFI5vilaQ+fXdSOWhs4N
         ny5+opL2MgC/0VG+hqwr+hev09DAygbTlCd1IbOYE/EolPHElZHTx07/Vmo3zfX9rHTh
         3SIXxFNiH+yNgFAnUNRO6tMHMw0nfP/XEUrMH1JMLo4kgGg9hQV69uunpaA7SO3JmQFN
         uIe5+QO/eqOM76pCUn8bcwCng73L3IeB3r8p289ehz9oMkAbe7+fZc/YoSz3I+qr9idu
         lg/D1vbH59E9J9sLvLdzKHSuITUsgbExtw2KHWE9FG46M9SfBZ76VFzfegaDWumeMgfc
         9k2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=OSqcW9CLX5X/DMZdqxALz09AR/LoG2nzJ0XH/yk6QwU=;
        fh=ZPR0T8cST3w7zq2qt1LodueNlO+CD3oD3KyLDysf0ds=;
        b=n2Pfn6cc48B1JpqHVm8DZTruX30ZxKhcn7ex6dRHJGcK4W40owz2KtniuF5g4UzB1c
         kNRMyw+yXYTluGUHFfF3dUklYwfzeI8DFlens/W2hC7afsoM2QVsawghIg941ddyDkUD
         7AMshgbnBdZnnvsA5V+5fB4BkKuYGWrsvOpSF4mb0UrkYMhtpb+TB/3E5TFQIxwVX747
         GLNjNdWQIn/3oA7QH2l5UzVtU14s9Q9pIt0qSXLWva2Uhr6TonUiMRWiCfMC+rhHfvds
         sk6W7HMUeeXtWiMRckq+RLNUqZTPBoM7R05WKrpk8fOtCLoMp7ucdOwzVAdihapGmp6i
         oFyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=t4hJeKLH;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe12::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR02-DB5-obe.outbound.protection.outlook.com (mail-db5eur02olkn20802.outbound.protection.outlook.com. [2a01:111:f400:fe12::802])
        by gmr-mx.google.com with ESMTPS id ch5-20020a056122318500b004abe61eb6fdsi31861vkb.1.2023.11.22.13.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Nov 2023 13:36:10 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe12::802 as permitted sender) client-ip=2a01:111:f400:fe12::802;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=CMtbjaaU9gJXbHUlxBzoNrHU+4xL9zEMSW9HTzVcrTJLNvY6KZWmnP7M+gkjrZx64pC/ZoalkLIn69VwF5xvdGbcZwxiIlCQoqR0K6fSzuYFDAMWsYSRCA7plpiDby4cnVcIKMRuLgXxaD3RPgpxNXM3MRlgPGcIhfPx9N+ys/J1vy2mCbsnEvWKUoeVhFoEjYi8d+n6l+FxUvH1f6YriEEivir5CVrFDpOX7Sl4nuRDmoSFGm2pwpkW161wuWzY8ppaaEBjbScI+JbkV2cHTnmyOMkbVOizIRjRrW4t9gwbPNk743ZG23PWH1fcK2CB8JJrwocubGxugur2KofzmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OSqcW9CLX5X/DMZdqxALz09AR/LoG2nzJ0XH/yk6QwU=;
 b=eRsxFHV9oVsAy0GlJYXINc9HQgE4/L6m7SBuGePpeeqS9LQv1l3plISoenvF/efW58ZE6yRUFgNnvftCFIJtdw2VMkkCMAooyGVA+dOewimMoDmhxP94iXsNs9lFdww2JMnvqEa2A7R4Z3JKP9jkh/snsEhbEyUR8yUYJ7LSRPId3ANYPcbsa9PS4Fxycx8iuW35T2fDEmP3nQYrluL9fdSpYm6H+oXHo4I4v9+C1sKiWuKLKosgk4AC1/OyOQzSzlDe1m0GebKWosK4upSOewqJOGUFqiA6NC0l+GxouVi50ldpe7F+JYdwZTrxeWxW3h18BScrSuGhNJSl6PhUEg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by AM8P193MB1041.EURP193.PROD.OUTLOOK.COM (2603:10a6:20b:1ef::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.20; Wed, 22 Nov
 2023 21:36:09 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.020; Wed, 22 Nov 2023
 21:36:09 +0000
Message-ID: <VI1P193MB0752E3CA6B2660860BD3923D99BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Thu, 23 Nov 2023 05:36:08 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kfence: Replace local_clock() with
 ktime_get_boot_fast_ns()
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [ARpD+7jaLWsVwXQ6CNIBsaM+1KFXvjcn]
X-ClientProxiedBy: LO4P265CA0227.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:315::13) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <db5cd581-d646-4a01-8aff-a166e9bed259@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|AM8P193MB1041:EE_
X-MS-Office365-Filtering-Correlation-Id: 75cf1ad8-294e-48dd-42db-08dbeba30a65
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: pSOu6HuNHaUdDZ78UidPyHkGa76MJPWXToqWn+ul60UQO3Foa4OJzLNUv6Ge6F03/J5enoKoXSvhh4XQfKZsTCWhxmU184lX4rUDKWaBaIH56yxwuZm+3BwHkym9XnxidS3KOUEETK1YNTKyt9JOuPPU4Orn+ZDdJSn9V4XNATDD8F70KWFxsZcXCB0goGl4KaPX+s+uYnwXoScw9VLze8YyojweqLC7drOV04u6w/8itmvevidayUljMA/AzNi0Mjh+igB/D2ID2v0utv6iyBMZ+CC1th+jTEsPFzpTK2wqp2KZ6tS5aW5GnoBGO8fnGPF62xxSnLLLpAxhkdcXaAYc2q2sbhiObG9WCvWwBYYgRITSGe1kG6tEIuACFG5lIuyLpF/0Yq2w1dEvKUulsZuHTKlBwcf5LXKGwCR7Zlx/FSbapfOGx9bKm4oXBM+n9YgfSDKzQFIfo4jYpJDQeSaxcg6cDKFaGMnDgzPTVKYRF59tZGfKoo32pXmT2e6EsVvlVOurqYcBXSCOlHjPJubAev3ZVV6TXXPtqSk4OyzOXaplpKdrdfsqzFTciKSu
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?aE00ajQ3Z01sanB5U0pWWnRUY3FpcG42aHJwYzFBMWxUaXNhTXpWbXNZZzR2?=
 =?utf-8?B?RTRZTDMrYXZiTitXa0ovR1FDUWI4SUZrTVUvd1RiTFN3MklNenFSUTJkQ01H?=
 =?utf-8?B?MzJHaXBGY08vbVh2MTdDdmFma2FKZTVBTCtRWEdlcXFDQkZ4QWlOSjVNUVBm?=
 =?utf-8?B?V1kzWFNwSlJnczBkcUxFTHVraTk4WENhWFgzVXBtS0ptUzJWd0NuN0FwUG9x?=
 =?utf-8?B?V29pSFlIajNiVGNZL2Rjbk0zVUJXaXFvWnprbXAvTkFPZFlNeVBvN05Sc1Y3?=
 =?utf-8?B?WUZzMmZuRStDeHRUcUlPTWVOdzJ0K04rVHF3azNyem5BdlNkaWtaSU5uYVB4?=
 =?utf-8?B?bCtRYUt3SGZZWmdHWGFtZ0lndG51QmZ0SmVRNkpSazJQMjJUb0IvTFhod2lT?=
 =?utf-8?B?cUV4ZmlJRmlWNzBBWFk0L1JQZDB2TVlVU3d1RjNIYmgvNjZnRUJNMWF5LzVs?=
 =?utf-8?B?Y0VDZXRvSy9POTF6U0hzZWh6T3kzS3Y2SlZ4UGVSVEFrRmNIbFhxQjVldFRn?=
 =?utf-8?B?ell1d1VXUGIzTFdrTUhXWHdjdktjcnBzcko3TGFhMkp5dHdQTUxVRDg1Tnp4?=
 =?utf-8?B?TExsUFhTNzNDaW5sNFdsZGk2UFV0emhGOTRjUXo2dDhMTDQwUk9ReDR6dTA5?=
 =?utf-8?B?eVBtZkVTMXJLbHd3dVRMRVFjM1FVODhLYWE3TzR6aGJMd2hTWGRUb0VvSEcy?=
 =?utf-8?B?b1piYnJxOXBzbENrSkFxc3YwQkRFbitNS0dYRUcwYlZuNHRSWWlVNTFiTU03?=
 =?utf-8?B?RFdyaTdUc0ozTzkzcHNUdU5VbnpWdFZxNFduQkFzOXcyT2Z5WFIwbllTTFdq?=
 =?utf-8?B?Q2FVTldZTGQ0OTVybUhVaHVrc0dROVEwa0RONTZWemwydXZQWGx4QjdqRmJL?=
 =?utf-8?B?NE9mU3hLZ0g4bWpaNW1weUJoWmVzUGFWaXR1c25peUc2TmNVTFFpVDhoVzF3?=
 =?utf-8?B?aGZIVlV4WDhyZ3JjcEtjOXg1NjREb3JVSmZOZ3FlcVg4RXBXcld3djBwVlFh?=
 =?utf-8?B?VEgyWXNia0d3b1cwd29wMk9vZWJHS1BxeEZNNmFMRlEwRmVGajdyeUkrOWdo?=
 =?utf-8?B?Q1FxVG91N2FlRWZYTU9iY2FHczloN3dqZnlVVVpNZFFremEwdVZqVnBZaFdK?=
 =?utf-8?B?N0Q1VGQxM1lyMllxc1lyL3ZlRXRWdHVlbTVwUmNQaXRsRnpWZ1RNSEUxc0Vr?=
 =?utf-8?B?aWQySUpwdElKbHVOR0hHeStvNlRoUHdMdDJYVVRuUVdKSGY4NFA4dFkyQjMy?=
 =?utf-8?B?Y2wvL2hnbWNEVndSMWZGemNNWHBIOGgyQm5YMklBUTlJK0o4cy80bTAwaTVO?=
 =?utf-8?B?a1UyOHNqeS9idEtvb2pjanU0VXVzdE8ybm55SnFVY3V2T2x2STBWdFNKcTM5?=
 =?utf-8?B?UVJadjI2UndPVHBUM1ZwVXJ5ZWVpSzJFa2lrWThZY2V5N1pWeVpFd2NwSGkx?=
 =?utf-8?B?TmFtdkVvdnZlazZlZi9IQUFNM1pCRGdsdjI0M21OeEkyVmZvZkRaU2xlUXJy?=
 =?utf-8?B?Wmx2RmNEUzlIUjltQ2NJWmRvQWxHL0lmWlBCeTV5RHBLYkE1eTc0LzJjMGtp?=
 =?utf-8?B?Rlp0Q2REbzA1dVFEOTM4ZmFSMHRsWUVlaTkzUFV3bFN1K01JT0NIYWt0SkFF?=
 =?utf-8?Q?HyDoPnyDFSv5BveIzkwx9Q+bujTAthngLbDKvcsL80oc=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 75cf1ad8-294e-48dd-42db-08dbeba30a65
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Nov 2023 21:36:09.2508
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8P193MB1041
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=t4hJeKLH;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe12::802 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/11/23 4:35, Marco Elver wrote:
> On Wed, 22 Nov 2023 at 21:01, Juntong Deng <juntong.deng@outlook.com> wrote:
>>
>> The time obtained by local_clock() is the local CPU time, which may
>> drift between CPUs and is not suitable for comparison across CPUs.
>>
>> It is possible for allocation and free to occur on different CPUs,
>> and using local_clock() to record timestamps may cause confusion.
> 
> The same problem exists with printk logging.
> 
>> ktime_get_boot_fast_ns() is based on clock sources and can be used
>> reliably and accurately for comparison across CPUs.
> 
> You may be right here, however, the choice of local_clock() was
> deliberate: it's the same timestamp source that printk uses.
> 
> Also, on systems where there is drift, the arch selects
> CONFIG_HAVE_UNSTABLE_SCHED_CLOCK (like on x86) and the drift is
> generally bounded.
> 
>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
>> ---
>>   mm/kfence/core.c | 2 +-
>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index 3872528d0963..041c03394193 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -295,7 +295,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>>          track->num_stack_entries = num_stack_entries;
>>          track->pid = task_pid_nr(current);
>>          track->cpu = raw_smp_processor_id();
>> -       track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
>> +       track->ts_nsec = ktime_get_boot_fast_ns();
> 
> You have ignored the comment placed here - now it's no longer the same
> source as printk timestamps. I think not being able to correlate
> information from KFENCE reports with timestamps in lines from printk
> is worse.
> 
> For now, I have to Nack: Unless you can prove that
> ktime_get_boot_fast_ns() can still be correlated with timestamps from
> printk timestamps, I think this change only trades one problem for
> another.
> 
> Thanks,
> -- Marco

Honestly, the possibility of accurately matching a message in the printk
log by the timestamp in the kfence report is very low, since allocation
and free do not directly correspond to a certain event.

Since time drifts across CPUs, timestamps may be different even if
allocation and free can correspond to a certain event.

If we really need to find the relevant printk logs by the timestamps in
the kfence report, all we can do is to look for messages that are within
a certain time range.

If we are looking for messages in a certain time range, there is not
much difference between local_clock() and ktime_get_boot_fast_ns().

Also, this patch is in preparation for my next patch.

My next patch is to show the PID, CPU number, and timestamp when the
error occurred, in this case time drift from different CPUs can
cause confusion.

For example, use-after-free caused by a subtle race condition, in which
the time between the free and the error occur will be very close.

Time drift from different CPUs may cause it to appear in the report that
the error timestamp precedes the free timestamp.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752E3CA6B2660860BD3923D99BAA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
