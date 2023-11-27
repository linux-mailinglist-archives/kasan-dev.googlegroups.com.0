Return-Path: <kasan-dev+bncBAABBX6FSGVQMGQEC7QXOGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id E6BA97F9CBB
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 10:35:28 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1fa25d81aa5sf2892260fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 01:35:28 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1701077727; cv=pass;
        d=google.com; s=arc-20160816;
        b=l4E/hOdON3OlmCtMGlJ9YMGtwkGp003sf59UH0fIqOZ/SyaSXaOE0y3oTq0PGnBpIM
         HYAVOhqANGAyxb7EqIfNXVvW+F/I5jyphjM6kfiI/rToF2kTEOkl3w8milTJG4+5jRwm
         CSuAs1iod6ElBmJ3H1HRdHOiBsoqVH5u+VrqFLXTTl3bS+2xeCTDhMtVcyeq6uTQt48v
         4ZCW0jba3LYzAbEnZX7wON1VK98HQRah8Xwn5bfUbiAIpTxNkfsc+RAgueJ56aCkaZcY
         o8GpAbIOKHymSivfMnlNZNacCUr7ELl0p8iR10/6M3WRYNuqNiSLY/dtcHQG7ljvtKsW
         k7lg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=fBG9F4nZg/Zcw5/pPa213AGYvMUwG2wuk5t8XAt0PlI=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=SJsVClPGc8/1dm0gOs7zyGqk8EXCCHTlZ3kT3ucZh6zLnq1+F6vgHZDbEcNeO2lqrc
         MSe6hQtHXUjEMRTnTIVKIoJ9fWrof3TQgOUo90EHEzYWRDM0j5fQWneDRRhk4LFkYKD/
         PKwuQC/C7jmkmxJ0qeAe1MOu32SilSiJt2JpppwTqX6ynSDFz7KVzGw587vZ0BZ7NJIp
         X81LTuNRDD+dwPtZJL8IPNH4sX8A0Z6poL7L+T8vi+WEblaX2zAneCqHI3/83pazmZBw
         45+UBqc5yxgQ4w0Ahz9KEjKxaKZ2sNfNNJ1ghb+9L9YbFk3jS6rjPTPnWs3Dj95mGM30
         eKBg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=lLHpb34l;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::810 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701077727; x=1701682527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :subject:user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fBG9F4nZg/Zcw5/pPa213AGYvMUwG2wuk5t8XAt0PlI=;
        b=dL0jw10s/l574acCvqBWrm1SRV6LoCFpSC7f8Jhw+egIdN6HTsFCoBwagLTumdHuy+
         zMwfsi7TqNIedd2XraYWLWtLmXVVW8k19Y+/urgfWzDi4e+1j2eM6sZhNs25xUvTK4aL
         ZvNNCbgXl/1sP6nknilBuPTn7NbtcwX/sZ7ugd1RPSpE1XaHJ+eIIrJl6xmru+nr1A3A
         VJ8HdJnp0lX2tuPCM2u3EBG9mJEfu2x8KQFShgsUez8i7nSkUvRKLNbc62a/YgCHpCeY
         XhPIOr7oZ9cEUlir73ZlAMispQQDYE94y4BuXznfJD42gLbKMH3qwGqrjXQipa0994QB
         OOdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701077727; x=1701682527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=fBG9F4nZg/Zcw5/pPa213AGYvMUwG2wuk5t8XAt0PlI=;
        b=Hb77bCBpf1bl5LuJwilVecjpGyjXCQKFYgQjMdJu/uuT18+qkww400QSqU/qXJKR3w
         sqzIcbPUqRdvEymZvGid7FWhK6NKbtkcs0em0CcpAx+sZ70a05ZcVJqgNZW0PlxOTuyo
         knaI1OALEdPQBY80nc6b3n3v64PD3AWUKphEwYRYHbWTc5ruRoNDrwQnVtchC/Ca0oHw
         mGKvX8oSzBc7seVnCF/2FRkpg0y0cdDknv49Q3XPtkHFg2WnkUMId0dOZ28mdswnwHbg
         OPZ2KHnviXv4NKCLeK/FT7Xjbpk7SvxNSIBnHGFsAJX6TYf7gB03icD1JxbbQ6rIM41o
         R6/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxdtPCahSfCWmDb0oCv8omzfho2SZqqQHcuKfPn3pYxJmEV/ppz
	FP1t1TNuMMsSL+/uJACHiUA=
X-Google-Smtp-Source: AGHT+IFCcO00jB5f/eL9ONdyKR1aPJp6bpcEhTIn+9oCNTb6uS1PUfwH+z59IwXPndgu0jv9wfcUOQ==
X-Received: by 2002:a05:6871:4097:b0:1f9:697a:69e1 with SMTP id kz23-20020a056871409700b001f9697a69e1mr15332996oab.16.1701077727428;
        Mon, 27 Nov 2023 01:35:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2011:b0:1fa:2fe5:f77 with SMTP id
 o17-20020a056870201100b001fa2fe50f77ls2412789oab.0.-pod-prod-05-us; Mon, 27
 Nov 2023 01:35:27 -0800 (PST)
X-Received: by 2002:a05:6358:528a:b0:16d:fb2b:7463 with SMTP id g10-20020a056358528a00b0016dfb2b7463mr11852075rwa.1.1701077726903;
        Mon, 27 Nov 2023 01:35:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701077726; cv=pass;
        d=google.com; s=arc-20160816;
        b=kM1IJHo7wDwE2v+5nJOR9vcC4rg8wkdejkrlR3mYTLB223UULUW5fi/yj0Jophvm3I
         1cnmF/MKKtsfyShwTkAT89ziypEwiCPm59d/RQRabPZ6kOejqAAmpA2KzRjNrmI5/K0I
         iCiTddFsThMnP7iePz5Iu0kYu7f+tZDhZ5IbdVTtT0nLJIzx5F76LqfBut+SmlhFb/WA
         TBqmIcBhgCAYnYkmmWuQOAGSfVmlokvZgYMWeRr4t0MUGpUrPCiEgDK7+YmMsKeepka8
         vOL0sic+Lol2QERxtKy6quM0XL3o7uwBe3Hm4GNHh/6hF1FEHSurz68f0m/hoGNv07ff
         4v6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=3Q2vw4Ll8tJuSsg0hmeSuPivR5Xa6L1BNuQNpdA3is4=;
        fh=jbVJpa6y1kFfVaEzIZIbFuVdgktfCZfUyP5Q8nXqkFQ=;
        b=CW9vFEHeqj+G0Pkyrf879/iN+X7w3uufaN9n1ld75E5pVChY1FaNZZ94vStU7zzHvi
         zzCWElcKv6gpsJgv0r2hyzFUgCs9IHAWuH1kDgdYBhyhQa3nwayfaZs/0uM1dcC1BdES
         QOX6SkPS+k1zRHrx1SNcqmPxg68Q/ULvdF41c88wpH1T+L6b/3/lkiLIfX7LXxYcc7Ac
         pcDpRCbXJhS1Ni6Lfq9EIAaozzSIrGuMfigaQjoEJUStT1N6VjShIEv8Jkzht2ukvzZS
         H8aa4vLpOgkPHJ+vKlsmMeTYPUGHgk+6sye1xbjDzhyk2KjBobt3xA2bIUQMz5wrsTiM
         SNWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=lLHpb34l;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::810 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-VI1-obe.outbound.protection.outlook.com (mail-vi1eur05olkn20810.outbound.protection.outlook.com. [2a01:111:f400:7d00::810])
        by gmr-mx.google.com with ESMTPS id cd11-20020a05622a418b00b0041790471199si1606384qtb.4.2023.11.27.01.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Nov 2023 01:35:26 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7d00::810 as permitted sender) client-ip=2a01:111:f400:7d00::810;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=dU7Do8WhVoNht0BDladXpP1sdsA5Wk5WL9FaiNOY913XxYlLnQgc/3GtL/6XUVyTq2D8Piiu+fis6OaeRwQ29Sv+VHngKXm6N1UbRxrwTE7HGoA6fqYzr/FnEJuGpZVRMTamYRmaHfFR0fcRpMd6u9NmTTmfQrN7HUFhEouCGo4h3XH0m+QJbN1526q9hybrhbZTf9cFWHce4LH4C2I34DnL18ERvU1BXOFKARqAuF2mvLs5xCiMQA4/mSCp4XvjAbZ3LJYdXTwf+OtJpRyuivI41a4ERLatHOcZxzUtPKp03sr0w8vUwy3lvDQ3Wl2SPcBduOGKvvXxfnofZiz0nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3Q2vw4Ll8tJuSsg0hmeSuPivR5Xa6L1BNuQNpdA3is4=;
 b=ncD8AVyaeW7JZCwS4M7aNfySujUNvV3q9MRIErTeEuN8kEnWqE3SVpAxVc1o1j8cycnSxMZcUEiPTzntH5/20CaiFXQI2qH6yZ+nLQUmqlRhbYVjVe3Ua1qrc7TmD28cuOEzImRl6gJ39dVNQWtXdDku3Iz0QAF+q7J5mrqnsWw/2NKeExUTbJ1d+1ekeMQcWU1d5q2WsLHeU6wzizjJTKgaVol+kgEohratM69LaWq9nBpPR9Pi2GvDPh306oDlxqSiZS+0R13qiKUp0Ew6MKvOB4PqUhS6xwlK/MX+pAE/lNWWig4u0OSStOsV6YZeHgF4QhUC0aOLcVfQFqvoOQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by AM9P193MB1924.EURP193.PROD.OUTLOOK.COM (2603:10a6:20b:3ef::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.28; Mon, 27 Nov
 2023 09:35:24 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.022; Mon, 27 Nov 2023
 09:35:24 +0000
Message-ID: <VI1P193MB0752C5B781EC2A351EDF62CC99BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Mon, 27 Nov 2023 17:35:24 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Record and report more information
To: Dmitry Vyukov <dvyukov@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+aVjKTxTamnybC9gS7uvSodYjvHst9obo=GjJ_km-_pdw@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CACT4Y+aVjKTxTamnybC9gS7uvSodYjvHst9obo=GjJ_km-_pdw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TMN: [jvqnkt7khMLj0+NRrQfWoSQc8fiUbX8T]
X-ClientProxiedBy: LO2P265CA0095.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:8::35) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <f7d1077f-290c-41ab-ace5-99c73e0ca230@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|AM9P193MB1924:EE_
X-MS-Office365-Filtering-Correlation-Id: 03a3d65a-5c20-4165-91b8-08dbef2c2e5b
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: HPNwE4Z6qcF6o4m6Hb1OBEhaYu2WJit1Bl+7YZ6eQJZAs84hkdiLbcDz/MNWd1rfgrVCN+ECFit0HdUV6su0ELhR/98g0KY0lA76esxzyEJxG3onTTHN79q4NwUQ77u3pyvLBPURbKvvPadEKE/UpORCqQXv3+x/cmwrdc62scvILqxvrmsjnVpJgr/VA1kSrd6Wy94NLPt8I7dyKT1S+IzRF9pqq6Lw+6NA61M/ikkEWhNIqWNZZesgLKXGOBZ5/zEJIJxPdnltfRSwhlas06GJ9N/Otm7DpKIuKpdzQ31fUeoMbmkrKiJhlc2FBduv658HwN97whEWD45lWB9GfXJaNUUjnH0VAiZNMeV3bus7P2m1fzwafT/Pdz2gYlwevNzGleykTtxoX12scO9u2wgutkh+QJlSo5J75cq+hr9Lw6uR0+XgIWQYPvOVk513whDcg1/inXybnOiFI20SvaaHpXvpUoZF/8KEMu9pbM9LjRpv/+Hv1NcQDbjj2pTkjEPoQDjOv6LSfTCSQnARAGlFXC+C2kpZgFhb5vE0mmIK1AX9SwnilxMg6PwqHoNi
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?MW5nQkJiUEJxUTI0aEt2TXVsWEFSZ3J6ZlFWWXZWa2xjSm9IL1dSVkpSdnNx?=
 =?utf-8?B?OTEzZFBOcVQ1UGsycjI3Mll2ZDMyYXdpcDdSUGhsdEMxZi9KeGFzTmZqcXlx?=
 =?utf-8?B?OEMvelcySmU0Q056ZW4wMStHd3A0NDQ2N3RDNE14cndmK1hqSVJrUmFYRkZL?=
 =?utf-8?B?eDB6VXhMektMTVFzNEw0QUU5cVhvRWpBK3BxS2YzQ05sWG4zV05vSUk3VFJR?=
 =?utf-8?B?SFJCakRMNTM4TWNzdjNpQzZuK1VrSlVRV0Z3SUV5Q3BzbG8vM3BydXMzaWpD?=
 =?utf-8?B?QldlcDlEMkZya0EwYVFIblpjak9MY1dZL0xPcDYxUGZ6NFI2MG9CNEdKSmM1?=
 =?utf-8?B?bjhOb1dRajZMeWlvRHErYUxObW5lVFlIOUR2M1g0aDNuaTMxQWJoZ2hqMTdu?=
 =?utf-8?B?cnRkUk9lMmh5cytEYU51Q0hlb1BmZ1NwQ2UxN0dTcWFIMzZGemJnVzIzdWlJ?=
 =?utf-8?B?SWtzaCtaRjBLckRvczR6NGttdDQwYjY5eVFFZThoU3BhcUhQbEE0TDJyV2NH?=
 =?utf-8?B?bUhvWUwxdy96SElSOVZlUXIyVGN2OXJrWjQyRWtsVjltdnFjRjhxUUN4L1Nt?=
 =?utf-8?B?TVJJNTI2am5qVks0aGlvZ3BYc3N2TS9Yalp6NkN2TVZNOEF1UzhUVWFGK0tD?=
 =?utf-8?B?NHRWeTZGa0VSV2J6Umk3ZmRmeTJjY0E4aVJNQ25LSy9WODVXSm5vMG1hMTNO?=
 =?utf-8?B?TmVtVGdYNjRBN1hraE1GcW9mRWMwK3NLVDdkdkFWZkduQ2EvUkNNVTJLdSs5?=
 =?utf-8?B?c2hZUDFEUFdKMjN0aXRUMmpNaWlDdzFtaVJPZmdGRlNxaUgyQWF4UmdsMTFP?=
 =?utf-8?B?UjMvTnV4cVFCS3hRSjhsbk52Skpjd0xpVWdiR3JDcFhNTThEbURQQ2NwWXd4?=
 =?utf-8?B?ZXlHanEzK0p6ZUFlWkhPT0hkY0xPT2dEZE1qd2g2RmFmTkRoZEhXdmRoTk5i?=
 =?utf-8?B?RDRKclBxeDlQT1JsSnJwTDFBek5KbXNtY3lNRkUxZmpDOUZpRFNrd21JbldH?=
 =?utf-8?B?MHRibHovTDlETTJ2OXJZRE9tMGZkcGFZdjJHcDhvcCtxVnFHWGE2V1JPS3VC?=
 =?utf-8?B?RlZhQXNTY3RBUEJIb2JVRkg0OG5RSVBFemJ3S0JXRG5NMTQ5VzgrTzlOSm14?=
 =?utf-8?B?NElOWENKMkNXSnFaL0E0NVR0QTFrOEpYWW1HNE8wZ1VzYmJJNkRRSGtPRXk5?=
 =?utf-8?B?KzFyNVk3NGRTZ2pSZi9TR0gwdGsrbmRKdVhiZllzZTNUcW5jaHdCaFBZZ0lS?=
 =?utf-8?B?YjUvWEljcVhzeUdFR3dtazk0VlZ2eGRvTy8vWnVNaXJUQXdhQnZxdm1wVWFm?=
 =?utf-8?B?VW11N1lML0lHbzluRERCY2NSdWMrSW1NVXkxM1hDL0plM0lOQVZXcklZVjUw?=
 =?utf-8?B?OTlPdnpkT3lReHRIRS9zaGRRamYvZGdEUkR6MHVrOTNoNzlyQ0pTMnNJby9Z?=
 =?utf-8?B?NW1saGtNcXdyaTV3aG8vTkJ6bHBDWENQcmtaYVdLTFN1d29RUzVkZzh5cHJt?=
 =?utf-8?B?elRKYkJXSXhXaHRCd3ZYbEhSOFBpU3pSaWltckc3TXF4ZWIzQ2llNmtiNWd6?=
 =?utf-8?B?WGVSTk9sVTJhWWVpY1FTQmZjQWdOL3NHUTh2TzBuMXp6anVEUFNHVUswb3hK?=
 =?utf-8?Q?jAtS7uNUM/LIfoWjsuNv2fTvTxJHEbFC7S4+0Fp3sojA=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 03a3d65a-5c20-4165-91b8-08dbef2c2e5b
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Nov 2023 09:35:24.3483
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM9P193MB1924
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=lLHpb34l;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7d00::810 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/11/27 12:34, Dmitry Vyukov wrote:
> On Sun, 26 Nov 2023 at 23:25, Juntong Deng <juntong.deng@outlook.com> wrote:
>>
>> Record and report more information to help us find the cause of the
>> bug and to help us correlate the error with other system events.
>>
>> This patch adds recording and showing CPU number and timestamp at
>> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
>> timestamps in the report use the same format and source as printk.
>>
>> Error occurrence timestamp is already implicit in the printk log,
>> and CPU number is already shown by dump_stack_lvl, so there is no
>> need to add it.
>>
>> In order to record CPU number and timestamp at allocation and free,
>> corresponding members need to be added to the relevant data structures,
>> which will lead to increased memory consumption.
>>
>> In Generic KASAN, members are added to struct kasan_track. Since in
>> most cases, alloc meta is stored in the redzone and free meta is
>> stored in the object or the redzone, memory consumption will not
>> increase much.
>>
>> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
>> struct kasan_stack_ring_entry. Memory consumption increases as the
>> size of struct kasan_stack_ring_entry increases (this part of the
>> memory is allocated by memblock), but since this is configurable,
>> it is up to the user to choose.
>>
>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
>> ---
>> V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
>> config help. Cancel printing of redundant error occurrence timestamp.
>>
>>   lib/Kconfig.kasan      | 21 +++++++++++++++++++++
>>   mm/kasan/common.c      | 10 ++++++++++
>>   mm/kasan/kasan.h       | 10 ++++++++++
>>   mm/kasan/report.c      |  6 ++++++
>>   mm/kasan/report_tags.c | 16 ++++++++++++++++
>>   mm/kasan/tags.c        | 17 +++++++++++++++++
>>   6 files changed, 80 insertions(+)
>>
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index 935eda08b1e1..8653f5c38be7 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
>>            A part of the KASAN test suite that is not integrated with KUnit.
>>            Incompatible with Hardware Tag-Based KASAN.
>>
>> +config KASAN_EXTRA_INFO
>> +       bool "Record and report more information"
>> +       depends on KASAN
>> +       help
>> +         Record and report more information to help us find the cause of the
>> +         bug and to help us correlate the error with other system events.
>> +
>> +         Currently, the CPU number and timestamp are additionally
>> +         recorded for each heap block at allocation and free time, and
>> +         8 bytes will be added to each metadata structure that records
>> +         allocation or free information.
>> +
>> +         In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
>> +         16 bytes of additional memory consumption, and each kmalloc-32
>> +         object will add 8 bytes of additional memory consumption, not
>> +         affecting other larger objects.
>> +
>> +         In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
>> +         boot parameter, it will add 8 * stack_ring_size bytes of additional
>> +         memory consumption.
>> +
>>   endif # KASAN
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index b5d8bd26fced..2f0884c762b7 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -20,6 +20,7 @@
>>   #include <linux/module.h>
>>   #include <linux/printk.h>
>>   #include <linux/sched.h>
>> +#include <linux/sched/clock.h>
>>   #include <linux/sched/task_stack.h>
>>   #include <linux/slab.h>
>>   #include <linux/stackdepot.h>
>> @@ -49,6 +50,15 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>>
>>   void kasan_set_track(struct kasan_track *track, gfp_t flags)
>>   {
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +       u32 cpu = raw_smp_processor_id();
>> +       u64 ts_nsec = local_clock();
>> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
>> +
>> +       track->cpu = cpu;
>> +       track->ts_sec = ts_nsec;
>> +       track->ts_usec = rem_usec;
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>          track->pid = current->pid;
>>          track->stack = kasan_save_stack(flags,
>>                          STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index b29d46b83d1f..2a37baa4ce2f 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -187,6 +187,11 @@ static inline bool kasan_requires_meta(void)
>>   struct kasan_track {
>>          u32 pid;
>>          depot_stack_handle_t stack;
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +       u64 cpu:20;
>> +       u64 ts_sec:22;
>> +       u64 ts_usec:22;
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>   };
>>
>>   enum kasan_report_type {
>> @@ -278,6 +283,11 @@ struct kasan_stack_ring_entry {
>>          u32 pid;
>>          depot_stack_handle_t stack;
>>          bool is_free;
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +       u64 cpu:20;
>> +       u64 ts_sec:22;
>> +       u64 ts_usec:22;
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>   };
>>
>>   struct kasan_stack_ring {
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index e77facb62900..8cd8f6e5cf24 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -262,7 +262,13 @@ static void print_error_description(struct kasan_report_info *info)
>>
>>   static void print_track(struct kasan_track *track, const char *prefix)
>>   {
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +       pr_err("%s by task %u on cpu %d at %u.%06us:\n",
>> +                       prefix, track->pid, track->cpu,
>> +                       track->ts_sec, track->ts_usec);
>> +#else
>>          pr_err("%s by task %u:\n", prefix, track->pid);
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>          if (track->stack)
>>                  stack_depot_print(track->stack);
>>          else
>> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
>> index 55154743f915..bf895b1d2dc2 100644
>> --- a/mm/kasan/report_tags.c
>> +++ b/mm/kasan/report_tags.c
>> @@ -27,6 +27,16 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>>          return "invalid-access";
>>   }
>>
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +static void kasan_complete_extra_report_info(struct kasan_track *track,
>> +                                        struct kasan_stack_ring_entry *entry)
>> +{
>> +       track->cpu = entry->cpu;
>> +       track->ts_sec = entry->ts_sec;
>> +       track->ts_usec = entry->ts_usec;
>> +}
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>> +
>>   void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>   {
>>          unsigned long flags;
>> @@ -73,6 +83,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>
>>                          info->free_track.pid = entry->pid;
>>                          info->free_track.stack = entry->stack;
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +                       kasan_complete_extra_report_info(&info->free_track, entry);
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>                          free_found = true;
>>
>>                          /*
>> @@ -88,6 +101,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>>
>>                          info->alloc_track.pid = entry->pid;
>>                          info->alloc_track.stack = entry->stack;
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>                          alloc_found = true;
>>
>>                          /*
>> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
>> index 739ae997463d..c172e115b9bb 100644
>> --- a/mm/kasan/tags.c
>> +++ b/mm/kasan/tags.c
>> @@ -13,6 +13,7 @@
>>   #include <linux/memblock.h>
>>   #include <linux/memory.h>
>>   #include <linux/mm.h>
>> +#include <linux/sched/clock.h>
>>   #include <linux/stackdepot.h>
>>   #include <linux/static_key.h>
>>   #include <linux/string.h>
>> @@ -93,6 +94,19 @@ void __init kasan_init_tags(void)
>>          }
>>   }
>>
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
>> +{
>> +       u32 cpu = raw_smp_processor_id();
>> +       u64 ts_nsec = local_clock();
>> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
>> +
>> +       entry->cpu = cpu;
>> +       entry->ts_sec = ts_nsec;
>> +       entry->ts_usec = rem_usec;
> 
> I would timestamp as a single field in all structs and convert it to
> sec/usec only when we print it. It would make all initialization and
> copying shorter. E.g. this function can be just:
> 
>         entry->cpu = raw_smp_processor_id();
>         entry->timestamp = local_clock() / 1024;
> 
> Dividing by 1024 is much faster and gives roughly the same precision.
> This can be unscaled during reporting:
> 
>         u64 sec = entry->timestamp * 1024;
>         unsigned long usec = do_div(sec, NSEC_PER_SEC) / 1000;
> 
> But otherwise the patch looks good to me.
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> 


I think it would be better to use left shift and right shift because
dropping the last 3 bits would not affect the microsecond part and
would not affect the precision at all.

In addition, 44 bits are enough to store the maximum value of the
displayable time 99999.999999 (5-bit seconds + 6-bit microseconds).

010110101111001100010000011110100011111111111111 (99999.999999) >> 3
= 10110101111001100010000011110100011111111111 (44 bits)

I will send the V3 patch.


>> +}
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>> +
>>   static void save_stack_info(struct kmem_cache *cache, void *object,
>>                          gfp_t gfp_flags, bool is_free)
>>   {
>> @@ -128,6 +142,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>>          entry->pid = current->pid;
>>          entry->stack = stack;
>>          entry->is_free = is_free;
>> +#ifdef CONFIG_KASAN_EXTRA_INFO
>> +       save_extra_info(entry);
>> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>>
>>          entry->ptr = object;
>>
>> --
>> 2.39.2
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752C5B781EC2A351EDF62CC99BDA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
