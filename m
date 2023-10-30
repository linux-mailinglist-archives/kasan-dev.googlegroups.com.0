Return-Path: <kasan-dev+bncBAABBM7O7WUQMGQENODOKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F23727DB61F
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 10:28:20 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-50798a259c7sf4579909e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 02:28:20 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1698658100; cv=pass;
        d=google.com; s=arc-20160816;
        b=OvRCGXmAigexcP4JEn0Nyosjd3aqMccRVjn3ptExlLbTKQBY3eWLCaOOBwuGJ+lBv1
         w+7SoyeBg8w5ok0myOSWMY5wmyyD7UZnc6TDBeGmFze8JmEuh3NlYe/JoMLZ7D7d9qAV
         37zjkKGm4cPm/YM+cbJl1Ppiw/PBvHzHtDyvJZpbb2LL1tOcEMYIBX4kiwEcKSXnbpX1
         J/R/zwV12uEeRRH5Mi9znuicbDXRy9u/PNVvzbMGPm3itBEbwfuUyymT3RGCSYdfKP7h
         EMbuIbz8j0AmIW9Pqc+j/fAKbaA8Mcu6xcC7/tz/tDuyqLwR5fnRm/+OuUDBAJJmVmtG
         3YXA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=rslZgpHil8BTQKW+fvWPrL0D3PZck2egFpnjohP7ZG0=;
        fh=LWa2cBJS15l6HICmeAHPfNMRsjFSTs5tQYPE7n+sM1I=;
        b=cnYFZnULgAUfcP3sha4hjNVyWSIXH3UMQqqMEgcq1KDHtvmqx+62zNZnFWajo1Cx6p
         3wyZrQm5MroGBwe4gL/LsnxzDa6g0W2OEovKQSwKBMO6bUZTv9hrn4vzMFXHTuD/zfH0
         iOguFtVh/mL9W8+27gwtheNz5O8f0LcjZgdrkso+IKr7MkdZXZ9iy2nRuKvISrwe/fj9
         GC7n7LJJngknGpeEEYyOq+4zoegeELVG71HMgk3vWMEfUBCCjifmYOZZ5B+5cHpsBm+i
         wQzun0VV+eYyjeT3kBg1+hms/Abw8cGelc9kudY1GGkLTAMjNFqt3FxT4vdh7STSOaTD
         5VXQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=tpW0uOgq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1a::808 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698658100; x=1699262900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rslZgpHil8BTQKW+fvWPrL0D3PZck2egFpnjohP7ZG0=;
        b=o8hXhu3d+yyeTEfxMbbOwxLtbbMCEYta9XcefTQT4LSkMYfKGirHCyPfdCONII1Gr0
         hfMhH+1ZEWkujvqj1li0Izfm9uWNZlAE+P59BgHrkAvv4r9q6TrbMZFTe2AhXANuWYQm
         i9F7lgZyxo6YwmfL4psxk5zY81h0un1nWrhTTQIRLiaFYrv6YJFHD83WB+kSaqDOD1Zq
         ol1Ct6y5EnoRbSMNntNu1fS9saWgRFk6O5KDHSVU/1nJ/y+rlik0DJ1l3/QjwbGBn8TT
         KaM9bMyADS7rVpQ171IkY+aLnbuv/uWiWRGYj7P/sulhNR7dzbZqSbD61FZeFT0rdWIo
         0pTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698658100; x=1699262900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rslZgpHil8BTQKW+fvWPrL0D3PZck2egFpnjohP7ZG0=;
        b=u9GCLDf9okAVspG2TbvZXicfD3JdI8m8W9iEfwfyipN8VERJgVGxc2ZZSyvUohIKmi
         YB8Mzn7BmyapEsxp27a7x7b825skFWyR7f2tr+f+dUtldtGk1ELkSVFfYztz4VtuqB4n
         9I3kdnZ2/+GLFkMK27REpKWKvY2Xz7Iweo7dNeK2U5Y4A6PHKf8KNQ753AT9/CtdvpUy
         Efw5PxCZh630nEB0aDr5zaidEAgGYgjxQa4x8mDu5Htwqy6MBBZgEUESxuQh/X8hZ2HX
         VbvABosCfNq54iBShSADcbvBVwzgpXAlqfJav4KDeq/v8cS6xeFGH438LO/SJR8x9nca
         5yTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx5U9gy+Lj7n2VGDB7XMKpL5kalJ9hAMO1FhEWdEEAEWqPzKVph
	ldI1mR48whLw8O3ClHJF8fk=
X-Google-Smtp-Source: AGHT+IGdTlEXRQ3kHSoqwLeCLpzUF/leQpKNGj4CLlaBA2b2ZUxOZRHYSZbs3Y/R+m7+nhSsGOADog==
X-Received: by 2002:a05:6512:e9c:b0:507:9a13:1fca with SMTP id bi28-20020a0565120e9c00b005079a131fcamr8796918lfb.27.1698658099602;
        Mon, 30 Oct 2023 02:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4a9a:0:b0:507:cf9c:aa7e with SMTP id l26-20020ac24a9a000000b00507cf9caa7els1610560lfp.1.-pod-prod-07-eu;
 Mon, 30 Oct 2023 02:28:18 -0700 (PDT)
X-Received: by 2002:a05:6512:398e:b0:500:b7dc:6c90 with SMTP id j14-20020a056512398e00b00500b7dc6c90mr8561199lfu.36.1698658098033;
        Mon, 30 Oct 2023 02:28:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698658098; cv=pass;
        d=google.com; s=arc-20160816;
        b=cgVgDygKpiuFXb0rDry2DeuRj7h8l0pakzy7/unOCg40dyAx8E8bQsL5n44YY7SKes
         lP8kbekBWJTF6a3Esu8WOrDfbCX6spQ+GRto72h96Z4SnnPM/SNUJmyjD7JfaF2+AY/P
         BOe687zUFoNCI+yp0K3dBqSSJJo5PRj3ve+ShyV3e3QW7DrYNgsjOATCb8ahwxLKOF9T
         Do9K+yF7mY3ptm1a3bTq1s4CAFmdttNgQEsekKgf4UwuYLfTys5OAxbFEfBrbo3isG4j
         Nxr/AkGlmj8+ar14jzej6/lthQXXURudPzP/wtycLvP8DeBX0UfwvK240Yk7xtChwf+5
         neuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=ZqT/8YncguOhIyosUBuYGPfPwNGl65kK/vqaQ9wFNKo=;
        fh=LWa2cBJS15l6HICmeAHPfNMRsjFSTs5tQYPE7n+sM1I=;
        b=mLhTGO4actjipsqlpbtTIdlK9Vgn2MNR+3DHDMNVzkeXqct70dKhq58pcN3Sddt17q
         9dR3DxMrSlPqsAnG0Kut5nnKsXy/u3VV+edO/oU2sJu0TrTHrMrn29GItyNCJxO9XihT
         5P4Yj3Lkd+7dg3x1xv4vcCLiexKNjAS5h6e19/6jPcqmIo4Qkl8MSo4XqxZGE5DyzkWv
         /OiVY2sE5LeBiE7Ju4q9gky04zFrZir2kW39mgQcOIMDuqQcnlvd3G73Wzv63ILiCF73
         jnJCGq+HRaIsVIIo80YKXE8SXRxMyy9kJr/0/MGqQgC/bGGF7Sthbujsr8iaBeY3yRUP
         LAzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=tpW0uOgq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1a::808 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-DB8-obe.outbound.protection.outlook.com (mail-db8eur05acsn20808.outbound.protection.outlook.com. [2a01:111:f400:7e1a::808])
        by gmr-mx.google.com with ESMTPS id d32-20020a0565123d2000b005008765a16fsi472308lfv.13.2023.10.30.02.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Oct 2023 02:28:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1a::808 as permitted sender) client-ip=2a01:111:f400:7e1a::808;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Ibd6hGvhs2g9tl859UTTjiIigyKdQfPSpHXena2pcKk1yxfOqjTXaS48CuWmZxzdTMPxk79KKNRXeAddqEgItG2IOG1cEQxFh0CLcJFvGuAbiRQ3gsOavPEuCwGzfmUDH0nMmN6LO1wrTrV6Nyx6MFFWB+WQRL6U6gk/Z5/xKr6vxgDd3fo0TV7Ft/T92rt3zY6K7NkAQswk02I5FfgpF7N2wOVBjY3MZ91mZdzlVciw3goiaJcV/Fo/hKlMUaS5gaPl7KZ5NURTDRGCC/IemtHvUpKCY8cFqLkDMLTi7tO1HFDa0CSCmstytODulmQscShj33oQMj5UpcxiKp6Wsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZqT/8YncguOhIyosUBuYGPfPwNGl65kK/vqaQ9wFNKo=;
 b=V3ww8ri6VwKt5LfTBjvlROCt5ddCCpfG+Ta85d1yifA6IrO/omRwcfK1ibBiM9Hv/I2ukzWruE0fO3fM4I6+anNXJUazWoUXSSbuurnFSMVPWmrT6wwtcZrQIdzOsNXH4tE5sLfIYixWaBhyrc7kobrHjtYFsA+LwFCP34egbr5KzOt0xLHAMqzqbz2A0LcVG0qIyRkpmqRdnMj0pNkYF/sZFspEBfL9PLxNDZ72OX5rGkbACSRXQTV/xligkOaPaMYvV1Pb/2Xu+VNryEOVzfHZVplCB72L0Z2FU13mi1AY/AW48h64c8o/yHP1anGYai9DhyxMS/xrZhdcaj9/Tg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DU2P193MB2276.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:2f3::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6933.28; Mon, 30 Oct
 2023 09:28:16 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e%5]) with mapi id 15.20.6933.027; Mon, 30 Oct 2023
 09:28:16 +0000
Message-ID: <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Mon, 30 Oct 2023 17:28:15 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [KAEsTGjx5ST3o4Xm9YGpFWbUHuXe4GVX]
X-ClientProxiedBy: LO4P265CA0069.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2af::12) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <403c50a2-8ae8-4f0f-95c7-d1962016f834@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DU2P193MB2276:EE_
X-MS-Office365-Filtering-Correlation-Id: 403546a2-f2d7-440a-d2be-08dbd92a8bd3
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 6jj0O+5M3fyW3HfpNRjX+qne1OtKcUUCcBSKFrpB+cUvq+vMuaVqjDap538Xq/kPu7WURP7+knPrK5z63t9fCJrTznNHRwmpwbU9XJRJnKVz3tICKWedlYx5a1vmlrHleK6HQF2o1prQvht1MiLENJgeC0WHdSbFY/XQVPZ1TMfeEreVHaa6VOiEMyhV1Hvzk1xWomysvmhjZMzwSiz7+aXL0P79sEUeAH8W/NT6fug9c/Ff4vAgGb0FxX8ZG62U6QpNcgcMn8lRVNe2isR4rUwGqjcUz5AtozyataUht7H1KY2kYD/MuG9CTxppE3rRB7JyMjqflz6crs2xxdk1c9J64I/vTRvbispeHsg6VWZP1VEFxV2iaetRRPfhGGw44SZ1nCuahk0DWZhVciSwgj8ELHzrKhacXMczoGlJDEs/WU0KSAvMSCSj5KZl+aFTMgsB0v4JCDEpE2opZ7IIFHZo2dSfoNXjB3PSc7iDi3kG//vc/oPPCt+SiFu3g/Lm8wsAMD82IfLxkmP/w8TVlGMQ7RHVIfd34tWuvWQzngUba3/32f+l6nJ43S3dPoGp5GSA+YD4wQiQxU2v1Nn6JBEwXcmYVZqLXsM9gDMLMa0=
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?NHR2cXlmS3Q1N2xkSHYzWitkc0kxSHVBbnMvQUZYM1FRUHR0TzJIc1VoWkVJ?=
 =?utf-8?B?RVlscFhSZzlGTDJ6d0ltVEd3MmdOZmJ2VWlvVHA5a1czNlRhamdmLy9DcU9J?=
 =?utf-8?B?dkxXcFhKTTNVOVpuNjB4eVRJMUVTbWdnNHdrUWhLSWYxTVBpUmZmMWFBWnZV?=
 =?utf-8?B?QTkrYmNzVkJ2WWFpL1lXaXdQQkdvWVd2OVVUMHRsRnUyS0RUWEFOUWpudDF1?=
 =?utf-8?B?MzArWmNtSUF5N1RTb1hrcGh3Y1FmMnZvbnhLZkhhVUtwaEVudXNITDExZSsw?=
 =?utf-8?B?U2doNW03WGdiUmZ0eG5LNy9lY1F2YVBrSTl1ZDNqSzViYUtuZmVRSitpL0lT?=
 =?utf-8?B?dk1GL1FaSnljU1JNM3JmSGZVOTQwNENuand1VSs4NVNmb0dMT2ZHbXE2cEQ4?=
 =?utf-8?B?elU0bTVDbkhybWJZTFRCVTF6YlVVSnBIaUpBVFBoUDFkQlJjU3QwWnhENkd4?=
 =?utf-8?B?eS85M3VybUcvVkxSejZRNDEwZnZtczQ2dWI0VC9TWnREYUd0N1lQY2lyMFNx?=
 =?utf-8?B?VlU5Vk8wZDk0YXU1OFRsTzFVeE9HQXhhVVhHMHcwNXVVSVZ3OVp3NzdEbzY3?=
 =?utf-8?B?QllLRmhqc3d5SGFJSTJvZjBPYmtWZDlZcUlTOTZMQ3pMMVBmb0Z2ZUlldVFQ?=
 =?utf-8?B?Q3dyb3VreDhOZDgxekpTTHIvdkJ6VlZsdzFqeGdqUUF3WkwvYmFCS2ZNaU96?=
 =?utf-8?B?a2NrZDFqK3pxWEpieUI3d0FOb3hETU0vdGc5ZGxBRGk4UWVrbENWS3FhVlJj?=
 =?utf-8?B?bCszQU9PV3Y5bEdhYzV6TmZ1WXk0S1duOTRDK1lZR29pYS94VDladnBuMnRk?=
 =?utf-8?B?cW9sUWpwZm9XZXQ0TFRzUWp3dmtBNkVibVJJNktiTEVoc2FObURIZkU3N0R2?=
 =?utf-8?B?ak5seFYvOFpQMkY0WnYxM2krQW04K2VsNHplZkI3bjRTamRIbzk2djMyOWlQ?=
 =?utf-8?B?RnRtV0tNTDlJVFF6a2FWMHpDSUthNzFzOFVvcXFEUDArSU1RcGcrOFNuQW5t?=
 =?utf-8?B?WFpmc3JvbU9lSUFBZG9ldWVac01acFd4L0NZbEtucjFpRFFNbTJ3TzgrUkxY?=
 =?utf-8?B?SnV6L0VjYmR0WHA5TEg2akIyeHFSRVpSMXRQVkdLajdid2tlVC94NkczSUJY?=
 =?utf-8?B?YlRPc09GQ0FZcFlYVTRiRGFNUTY5OTQvZnF2MW5xM1Vlcm00QSt0UCtaZ3Rz?=
 =?utf-8?B?Qko4TmFhT3grSk5TZGxwdlZCQ1NjR2NGc3lGQ2JIV3g2OUVRL1FGSUlCRWt0?=
 =?utf-8?B?bXFDNGYxYkNXbHdObW9HYVFUMGFEVDZnbExRaXRsajJadWZWNVNoOS9GRTJn?=
 =?utf-8?B?UXA0VWJsSU5ieHNIT20xTFhlRk15QXlzYmRZY29FR2llM2pEdWlsSHpoOXJo?=
 =?utf-8?B?VWs0dGZ1bU00cDFPUGRyRVh2QUpSK1Vhd0RSU2RMN2NESk4ya2xabjBQaVJT?=
 =?utf-8?B?eFF3WFpKcCtaZ2t1TTNTb09lZ21SekUvSXBoRDVzRUhjWTl3QzNPa2RsUGY1?=
 =?utf-8?B?dEQ2VHZQdDA5MHVUUE8ydHdkcGZxRGVLcnZ0ZTU5bCtQK3hPRCtGc3NURXdG?=
 =?utf-8?B?YWVqamNuVlgzcWRHQ0JXeU1XeXFRVXQwbU9xS2J5c1hmRHM0M250LzFjV2V1?=
 =?utf-8?Q?qy5ddhwhGul89ZE921o2LgRDeB33UQV5tXdLWpUDzins=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 403546a2-f2d7-440a-d2be-08dbd92a8bd3
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2023 09:28:16.4223
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DU2P193MB2276
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=tpW0uOgq;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7e1a::808 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/10/30 14:29, Dmitry Vyukov wrote:
> On Sun, 29 Oct 2023 at 10:05, Juntong Deng <juntong.deng@outlook.com> wro=
te:
>>
>> On 2023/10/26 3:22, Andrey Konovalov wrote:
>>> On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@outl=
ook.com> wrote:
>>>>
>>>> The idea came from the bug I was fixing recently,
>>>> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
>>>>
>>>> This bug is caused by subtle race condition, where the data structure
>>>> is freed early on another CPU, resulting in use-after-free.
>>>>
>>>> Like this bug, some of the use-after-free bugs are caused by race
>>>> condition, but it is not easy to quickly conclude that the cause of th=
e
>>>> use-after-free is race condition if only looking at the stack trace.
>>>>
>>>> I did not think this use-after-free was caused by race condition at th=
e
>>>> beginning, it took me some time to read the source code carefully and
>>>> think about it to determine that it was caused by race condition.
>>>>
>>>> By adding timestamps for Allocation, Free, and Error to the KASAN
>>>> report, it will be much easier to determine if use-after-free is
>>>> caused by race condition.
>>>
>>> An alternative would be to add the CPU number to the alloc/free stack
>>> traces. Something like:
>>>
>>> Allocated by task 42 on CPU 2:
>>> (stack trace)
>>>
>>> The bad access stack trace already prints the CPU number.
>>
>> Yes, that is a great idea and the CPU number would help a lot.
>>
>> But I think the CPU number cannot completely replace the free timestamp,
>> because some freeing really should be done at another CPU.
>>
>> We need the free timestamp to help us distinguish whether it was freed
>> a long time ago or whether it was caused to be freed during the
>> current operation.
>>
>> I think both the CPU number and the timestamp should be displayed, more
>> information would help us find the real cause of the error faster.
>>
>> Should I implement these features?
>=20
> Hi Juntong,
>=20
> There is also an aspect of memory consumption. KASAN headers increase
> the size of every heap object. So we tried to keep them as compact as
> possible. At some point CPU numbers and timestamps (IIRC) were already
> part of the header, but we removed them to shrink the header to 16
> bytes.
> PID gives a good approximation of potential races. I usually look at
> PIDs to understand if it's a "plain old single-threaded
> use-after-free", or free and access happened in different threads.
> Re timestamps, I see you referenced a syzbot report. With syzkaller
> most timestamps will be very close even for non-racing case.
> So if this is added, this should be added at least under a separate confi=
g.
>=20
> If you are looking for potential KASAN improvements, here is a good list:
> https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&component=
=3DSanitizers&list_id=3D1134168&product=3DMemory%20Management

Hi Dmitry,

I think PID cannot completely replace timestamp for reason similar to
CPU number, some frees really should be done in another thread, but it
is difficult for us to distinguish if it is a free that was done some
time ago, or under subtle race conditions.

As to whether most of the timestamps will be very close even for
non-racing case, this I am not sure, because I do not have
enough samples.

I agree that these features should be in a separate config and
the user should be free to choose whether to enable them or not.

We can divide KASAN into normal mode and depth mode. Normal mode
records only minimal critical information, while depth mode records
more potentially useful information.

Also, honestly, I think a small amount of extra memory consumption
should not stop us from recording more information.

Because if someone enables KASAN for debugging, then memory consumption
and performance are no longer his main concern.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB075221DDE87BE09A4E7CBB1A99A1A%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
