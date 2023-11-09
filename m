Return-Path: <kasan-dev+bncBAABBPXLWSVAMGQEWVUEXYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC227E726B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 20:40:48 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c73f8300c9sf12622541fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 11:40:48 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1699558848; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKEwkhztr63YyAwTZsT9fDtJO0LH0AFWnWkYqKbsooQqOUW5F+TGEDAPq0yAZZu0Ln
         lSs926+meVbZUIDq38ro/pQTI1et/18+WimIakJFf/KMaeQYE4sUaGBkXWMmh6i/mBuj
         NiSYMNK4L4os2sANKdfmjPK1c+4yR1L5K938Gl5vAOms9KV+Wa5dfanDlv5oRux6Riqe
         EB+XQnvbnJGprk3SF6lOMVWmhe3zfrsQBiNIdOGrvTwtL9o/pBCmGt1Jr8MFuScjBrQO
         /3z731hnwXlHWsRObEPx9I5pWIwMEVuGw7ZzyDFnblP+KIIB5y2L4Zr2hgoWD8j5zwDG
         wvxg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=kVUSmJ++ZMPsRC8L3pYA/P5whBzFmb1HhwaYsVJWzW8=;
        fh=cL3GvM2qydNKpftzWl240LnIwGP8vPJKXkH4kCPuTO4=;
        b=gqey6ZFPIBOtZmekBW/ByVRQ3Ag57csuMROMJvTa9r6ktMvOV0H7+sxWN7VpFJ2OH0
         TsaIvPeGK8531sW+FvnFVqH/+4fADpJL0YgRJbUTMjDaSlyITgN85ggeatmtynGzc1xF
         3cStoUibrROSgse+DyxbpGIZTtCBn4vqWNhuotHKfNhk7D9HaZ2xOYzUGxHy5qE07cI6
         tV+j3NpWevPum92dvdbXC23GMJRdF7S4q55G+ObLfYevlO0yhT/q5jIR9Ht52dTHnQgK
         Qi7lGHljpnP9KHEFcpq79XvleGtIDEGc9i/ruKSAkkJom7tlF0DbON/BLYwzf3J8J7dz
         kmRg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=FlJeYPUj;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::819 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699558848; x=1700163648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kVUSmJ++ZMPsRC8L3pYA/P5whBzFmb1HhwaYsVJWzW8=;
        b=SDC0hyQXcLR29NlRuAr6Yd/b20e5GurANGboimTZTlAX23ywm90nbphr4G7TG4a0oN
         sWpAUjG2eydP6Z+JoEl5I/MhY/G2NL7ykIphq5vrxBjaTIzdccJrRMH+xNPWpWLFq94H
         gAF9w3RtracQCr4mDk3zKP4Tn9ZSw45+Y8RJrF9+5kbd4doG1nq2apzsG+dDDe/ZbGEc
         5I0dfa98LoOALnY0dQ9RnZaU2korBcKNAO1l7dydHi4yqbwm7T1Co0PiMSwozjBhKd53
         UTDua+/uMozDWjH09ixk7twInASXXf9U2kXmxzYg/9Z82u2bOIjAQfAaRadNzzWwzHgY
         O7yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699558848; x=1700163648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kVUSmJ++ZMPsRC8L3pYA/P5whBzFmb1HhwaYsVJWzW8=;
        b=WsGVi485SD8qc272Iq71GNbiCF4cvhra8BLTo6S2rhAmTs9UCPUvWlduCS6/3qJTk7
         bEkyDYkaaAo6uNg0lzOqPU2tEKr6NQQ/rQfXK6v91ft8gSyxRz1KeXbUkx+3LAuBoW+b
         siEg5Pd84BRthI03d5DvyTS5kv5gg/+WR4ODyLvxQ6CtYZYwyZ2ex/iZJ2XnN+uH2M5q
         xHpiawmX/Z8i/8qYY2JZJ7iHpTS81Yp8mxMu4XqzsRZ0qR+WBCbc/pV45wlNthVU1D/O
         Gfek+3Zr6Sbm2v4YCpCu6FypM77G5vMQtY7qZNnq25c8a5MPWobIL+3syrzKA5ijXgS+
         H03g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YziU917sU/PQbhICs1NGlH1F1WGF/dRHdTvSYNCSz8m7C6O3r0T
	iQ1enBtPkmdWedi1OGucgfc=
X-Google-Smtp-Source: AGHT+IEFHaCB7iTbGy+exRNqkYWHqqxtKFe5QMeqKdakERNNyQ7niqseervBvjEl1k+X0L6Dk7gdMg==
X-Received: by 2002:a05:651c:c7:b0:2c5:234c:86f2 with SMTP id 7-20020a05651c00c700b002c5234c86f2mr4972718ljr.13.1699558846621;
        Thu, 09 Nov 2023 11:40:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:99d0:0:b0:2bc:e36a:9e4a with SMTP id l16-20020a2e99d0000000b002bce36a9e4als682141ljj.2.-pod-prod-03-eu;
 Thu, 09 Nov 2023 11:40:45 -0800 (PST)
X-Received: by 2002:a05:651c:505:b0:2bc:dcdb:b5dc with SMTP id o5-20020a05651c050500b002bcdcdbb5dcmr7001772ljp.39.1699558844690;
        Thu, 09 Nov 2023 11:40:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699558844; cv=pass;
        d=google.com; s=arc-20160816;
        b=hJqjArRMxy4EpKxl62KHW61X+fBxn2HYuAyWeVaJ9lKY6CJcO78oxzmxNercm9w+Yn
         baUXP6gl2amh6ZdYlnP3axL9DbStrNkizxpndVcMuth5cRHvjDWgWu8d6O1JJ3RLeZOQ
         ThJ203QDtYE21B9D4MbGe/Wt2nevWk6WMVyAzmYCP4kUyR8rKgy9oGHGDuR0BfTu9ydG
         faD1zkyOGrAnEtzP8jpJv+WW6ka1LkgQcRq+SrKIJRdfI/jNujch6Aa6DMu9/7DiCE5Q
         JYHPo4MOqRtIhCw97kDEKqE8KFS3R+kY5lh9jqjaV5kD4+VQr8jLNeZn18gZIZ9z71Y0
         FWYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=Ju3R0st0ZQn+AXhm48Knsa6M6ne0uCfsimXRBRZj5Uo=;
        fh=cL3GvM2qydNKpftzWl240LnIwGP8vPJKXkH4kCPuTO4=;
        b=OesVZR5QBNhiAUK5+Xbn1O6tQGdmkrD4MATBj9PPoe1hXX6bHMHhDjW68U576P2otb
         fWQHlNttfv0toUFGkazRFGYfALeIg9heFlTkEaDoaf7/mFZPe9VuqgdxUSmXEN4NppJ5
         vk7twnNvaL2ytKvpNbTazRxym06mmVdO39zHrkWH7kU5ANjRhAi8mjDewAWgcG7Oq0Jx
         J/9cRurds0f4Ig5J0/a31Xmg+UWsZhsTV2bC2YvyVhsiDpZ6rJVVTQw74SiHz31AxA+m
         LKohUr4blNbUlU0/glxB7Q9al8R4phqn80a11Y4Mm7mH1YyLeqOvtooA89qw6PXrBvCa
         WnNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=FlJeYPUj;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::819 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR03-AM7-obe.outbound.protection.outlook.com (mail-am7eur03olkn20819.outbound.protection.outlook.com. [2a01:111:f400:7eaf::819])
        by gmr-mx.google.com with ESMTPS id x42-20020a2ea9aa000000b002bced4ef910si993967ljq.3.2023.11.09.11.40.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Nov 2023 11:40:44 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7eaf::819 as permitted sender) client-ip=2a01:111:f400:7eaf::819;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=EZbupBHvb92vBUFavxU4JKjZFGUxqcaDwHjwqhKqbAs05KFSlq0NqYCZgLupCmF2NqIhc9n67xgnZh6yNd1UvYzUeuS0RQI3rCVXciaER6HR+53Qm+hVogdYtNXnfIdX6O4fsrJOHFqSTQgxGQitPyRuCqNIVetQuEhuxva4YS83VelqHgXdhlZNQ7OD26biDE8GVIpZFhG0JEfA+xSMu+oeKoG0QL+MCx2okma7VoevzKrZFeX61pP9a0MZcOmz5uWPuLGuS092YNY85KCaKWk9naJFFXswawDJXg9YHlGCqd1pHSwEdIAwvzBJ7njg95ZpaQqtqluGAS2mRJW/Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ju3R0st0ZQn+AXhm48Knsa6M6ne0uCfsimXRBRZj5Uo=;
 b=KFUKeQ+C1rF/BfS9DTqS+L8QjdnI7ZbuhQdG1bJeESHo9rgQRhzw9yPjb+W3b9XENgpuM/73yp0zQcPz7ZPKcAQVBWW0yYxIrJQ1/HjXTcf2hOZTbvM3gqZq0octq6O3IJwA7xFwn6vRe1cshx5vPsmSuvdIgFHdiYuEvkpmWaf7IZEjzU0sHDqSkDE77YSEZTDY7mLFkEd8ZQ1TvcEIB+0v4CJTM5DOzIXlFDnWdzNf0dMu7/7nN6EjBMMb+HFHFQVk+E+a59i7RRjTfGE7fgX3uisTo+hmmExoxmrHQBWvDGgcXflzfd9wJP7YZBMhdBJhA1+aVRM71xxFhYmFUg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB9P193MB1274.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:250::23) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6977.18; Thu, 9 Nov
 2023 19:40:42 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e%6]) with mapi id 15.20.6954.029; Thu, 9 Nov 2023
 19:40:42 +0000
Message-ID: <VI1P193MB07522256FD0E0F148F19947A99AFA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Fri, 10 Nov 2023 03:40:42 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
To: Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, vincenzo.frascino@arm.com,
 akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
 <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com>
 <VI1P193MB0752753CB059C9A4420C875799A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+ZS5cz9wZgxLVo2EsGtt-tkFXkFPA6CGAA8Gy7+sEyDUQ@mail.gmail.com>
 <CA+fCnZdRWs=P4EgzC9sSDLfO=Bxbs9FyeOcqAiY8pzvMLUX=Aw@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CA+fCnZdRWs=P4EgzC9sSDLfO=Bxbs9FyeOcqAiY8pzvMLUX=Aw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [VN+pHvkej8G0MIcQwQqeCZ+1nXckMvoM]
X-ClientProxiedBy: LO6P123CA0048.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:310::15) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <d5686cc4-27ba-43d3-84a6-2baee5d50f46@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB9P193MB1274:EE_
X-MS-Office365-Filtering-Correlation-Id: bd965661-6d58-4290-49ea-08dbe15bc230
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: n3N3czyPIgl66vrLWbawbkOJIeGIf98lKKi9PFKtwUeJCNHKPSVqXpBG2iTTWwoO5o6woUk0KTsujwOLL+PEVuJ8H7W9c+3YKB+OfY/WsNKPZlDEqKmqX27CJ5BowtkKud8p7SphK9RODQLe3pyCc1uOyQVjH/XnfiuSu/qYbBebhGaRmtyHwGpKE2DJkP7FF7KoCMdoSu1DesH20ZYRjn61IAZdBoCGL5a0Jayz+aEKa37d0F1d0iRW7NXUBVHIWNvTNW+AJgQwWC5lFK6H+93purst4ZUuLdbFLkRdkzJcEjD4KuLo9+ZpLb+pCK/o8EgkfxhC0tyCt9KbMJ59eDZI6gXpuukiTcwNz09bgaHOMbqhrPFuQyYcka7o7t6W8lElCq9MIHNkvnEt/XZuHZvTOQI6yiSLJxrTkEArp0IoqT7jaonmzmT1ROOp8q5Ru5eLy+gNW9KL0+FSPgcYJrvE1a1rDxBmeU+m3CjmELxJ66q86p1Ims+lh0S1DQ9NRS8TNfvTwZBl7xIwN89z5QF6gDfCZucKJ/hQPh3XncDuy5ApZY2b8rSNOMhnUEsc
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?RTRIa3IyTHBFYzVpaEhOUmU3eGIwcmxhQUN4VHI0SklTQVgzc1BaUTZ0RFZE?=
 =?utf-8?B?eWtPamp0ek5nSnBndnMzcjFtRzF6VXVhNjRpZ1JVbzNRSFBKM3ZmallkaENO?=
 =?utf-8?B?YktrM3NVWUUrd205K0JTb1FGUFBFZ3pweTJNSFJmcUVyNmJvMTQ4a3N0bHJQ?=
 =?utf-8?B?RVR1aS93WkFpait1Qm80UGc3ZlI2WGsrTEVFR2RjMXBGNDFJTXhldFZibjdw?=
 =?utf-8?B?Tks1RURQQ0tOdkNGR0g5cWNCL2dpT09FYzRmcHhFZEJlZm9aUDdEOU4zTFkx?=
 =?utf-8?B?Q3dhcHVoa2hteW01Z0pFTzRBbVk0c1VwYkVWVTZEQklZcnhzRzRyM3IwWkw0?=
 =?utf-8?B?Vm5LdVF5TTZ1VlJOTGFSbXhFeHNUK2V1OWpOdnJJbUNnVnFOZXE1ckVmWXhz?=
 =?utf-8?B?QWg1NkZ5S2FLbUtybEdkdVc3TzNzRzlZU2wzMGdtYS8vWmJCSGdkQ3Q4cW04?=
 =?utf-8?B?QVFlQWV5bGRTQmR5ZVhNNnM3YTZiVUJVa0RVWW8vTG0rYVMyVU1HZ2lGM0lx?=
 =?utf-8?B?aHgvdm13V1U0NWM1ZmNQQlRMNnUxeWQ1ZUZlRURiSmV5Vks4eDZ1REtnaGt6?=
 =?utf-8?B?a2JrMjJFZmI3SktvMmxuRVFnSDdJRmFuM09zOGtVcEYrL0ZPakVCV1Vaclph?=
 =?utf-8?B?R1E5YlhLY2RRWmQybG4rYjc3Q0xxUEhpcVBGR0dzeEg1dVl1K1k2YkkxNzlG?=
 =?utf-8?B?aDgwNG4wMFFFa1BEL0g2Zlo0TDMvZmhmN2pacEJpeGM3OGREWkNxcVVWQzVp?=
 =?utf-8?B?aEFhUU1semJ2L0k1L3ZZUzYzdWd3eENRQUp3endrcmJCQnpzY05GVy9MZ3dP?=
 =?utf-8?B?MmsxQkJJU1Q3KzNIT0o3MHJmYzZyT1kzbnBJNERqZEpJdlB3cjdVM2FURWtX?=
 =?utf-8?B?K0sxZmpXN1N3WVhxT2dabTJKT3pnSC9zSUlVY1pobWViU1NWSDUyQ2tXZjNs?=
 =?utf-8?B?TE02V0NPOGNMallBaXBCdFNwenlvblRkOWZQd25XYllGaVcyYmVvWFlUa1cw?=
 =?utf-8?B?U2hQNjJHRW9yNlplSzRyZWNwVzN2VnhhanJ1b29ldlh5Q3c2SThTZm9YUWtJ?=
 =?utf-8?B?RXJpSUF4RGU3V3k2T2ZFYVFxL0JBSE9MblpHUDQxVkJqenovOXBlbFNlNG1F?=
 =?utf-8?B?WmpHVEE3OUxmNHVRSTI0aFA3ZW5sK3lnK2pkQ2NvSEw3QjNNUXJkS2kvSHdJ?=
 =?utf-8?B?WmUzUm83K0d2Q0FocG1Da3hHV2NSZG9pSDB2WVBaWFIwNC9aa25EMC9BaCsv?=
 =?utf-8?B?cDdnRjhoSHQ2NTdMNnFmb2drdUpHb3E1Sm1vcTcxT3dETmpQSzB0OHBIL2pG?=
 =?utf-8?B?bjM4Uk1hWFRHdmtBaWdLeE1ybDROeFd1bndqUkVPdE5ZdjhJRHFmZGtSTEtW?=
 =?utf-8?B?dDl0bVFOUTc1WDAvb3dPYnM1RzJPVkJaYUtxV2VYa0RoeDhTZkFJMzdnb1BI?=
 =?utf-8?B?TXJ0dnZiVHNvTGxmZFE4N3VyM2EvMDdEQ1M2RjI4dUhUNVBwb3FxYUZoWS9U?=
 =?utf-8?B?a0Z3dXJwVCs5VTJYN3RuUHpSbU9nUXByeGtUS0d5VGc3VzR1Q1B1cU1keHlh?=
 =?utf-8?B?UG5PQ21nZkNPSVBoQmtnOGNXT2RRaFM1UHAyVUUyYUJaSmxEYkY4MHVCYWtp?=
 =?utf-8?Q?jlRxX+bYmueb2aavr9LbRT7BZLPODcLGy5gCZDCep6Dk=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bd965661-6d58-4290-49ea-08dbe15bc230
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Nov 2023 19:40:42.4396
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9P193MB1274
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=FlJeYPUj;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7eaf::819 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/11/2 22:58, Andrey Konovalov wrote:
> On Tue, Oct 31, 2023 at 10:46=E2=80=AFAM Dmitry Vyukov <dvyukov@google.co=
m> wrote:
>>
>>>>>> There is also an aspect of memory consumption. KASAN headers increas=
e
>>>>>> the size of every heap object. So we tried to keep them as compact a=
s
>>>>>> possible. At some point CPU numbers and timestamps (IIRC) were alrea=
dy
>>>>>> part of the header, but we removed them to shrink the header to 16
>>>>>> bytes.
>=20
>>> Do you think it is worth using the extra bytes to record more
>>> information? If this is a user-configurable feature.
>>
>> If it's user-configurable, then it is OK.
>=20
> FWIW, Generic KASAN already stores the auxiliary stack handles in the
> redzone, so the size of the redzone header is 24 bytes. Perhaps, we
> should hide them under a config as well.
>=20
> However, the increase of the redzone header size will only affect
> small kmalloc allocations (<=3D 16 bytes, as kmalloc allocations are
> aligned to the size of the object and the redzone is thus as big as
> the object anyway) and small non-kmalloc slab allocations (<=3D 64
> bytes, for which optimal_redzone returns 16). So I don't think adding
> new fields to the redzone will increase the memory usage by much. But
> this needs to be tested to make sure.

Yes, I read the design documentation and source code of KASAN
in depth today.

Currently in Generic mode, the alloc meta is stored in the redzone
(unless it doesn't fit) and the free meta is stored in the object
(or in the redzone if it cannot be stored in the object).

Therefore, I also think that using a few extra bytes to record more
information may consume less extra memory than we expected.

I am trying to implement the feature to let KASAN record more
information (configurable) and test it, I will send an PATCH RFC
when I am done.

Thanks.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB07522256FD0E0F148F19947A99AFA%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
