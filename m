Return-Path: <kasan-dev+bncBDRYTJUOSUERBM5PYPFQMGQEMXUHF5Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id ELmYL7XXcGkOaAAAu9opvQ
	(envelope-from <kasan-dev+bncBDRYTJUOSUERBM5PYPFQMGQEMXUHF5Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:42:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FE2157A95
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:42:13 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-6455532d07bsf9245380d50.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 05:42:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769002931; cv=pass;
        d=google.com; s=arc-20240605;
        b=h94WG32nVN1ydmm7mbjA+dB2mWDCX8Q1b5jWo3ssuMsQyNfBpXeG+JKjrNtSIHvLjN
         gIxbr6yPV0JqaAF6jnzuxdW+B38+JT/YIbtp1YOsjKEdjwn1RR5Z8+ZVNi6Ton/Te5H0
         gvKxAStlElXqT4QklqYZPkGHQqsJsXyo+0Dt0uj9YEOj/Zh3vrcJe03qwshqysVucFce
         nU7nJPaYD6fwydO6xNtUwoJjbjBmYQVFqTmFBnSmKamFyrfjg2lr6fucPW3/MSJi9RIK
         CJw4VsWB59Vc4RYZFhrfXUbc5GBAEGaar0hpn5OXFbAhpxks/7/aGWZppHat/A7Sd9gF
         Nveg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:references
         :to:from:subject:cc:message-id:date:sender:dkim-signature;
        bh=dekReyp6UJzS8Eoi8ti4ESYPBV5qJAYuZc1XyYiM63g=;
        fh=J/Odls1crx+dLC2lnnphibcp7btVQkY2Yx8gEhBHTAA=;
        b=d2FgbzHNxWz7TPvZlvTs5Da421wPjr8BZVI3TvlzEgi0iJ8+8+DbOU5m00qwHAM0vH
         /dS1GbSfxgPUbirnraXf6yNed3XcsHSGAzB8YDiGSHkHdLs9fsmOp9RIlrt+Nf2hv6ef
         MjyyKSjmBQLym6oO+Txjo8Zd5NlM8AIBQRuWx+1EBXCyD/GieHzCPp2rTxY60hbVyIao
         myh5tNM1m/w2YCxKDfSmfpanSJRO3jD8jRzCEZYP00vVXKnd/zBvqUJo1pPC8AHEs8Sc
         e2+YC5aFYwD82LQKute/wzOQ3IaOPa8rpY7MDLC9CYd0M6Qfz5q/uE2tHrGly3EZ/VLS
         IBqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=AZjPvugu;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769002931; x=1769607731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:references:to:from
         :subject:cc:message-id:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dekReyp6UJzS8Eoi8ti4ESYPBV5qJAYuZc1XyYiM63g=;
        b=xG/QemwBC5bxNeR1UgOpQq0e+62EIr9jC3jMJc6XKcC1V7lIl5NdFciqJQba1m2qoU
         VM91zr0JmnRCo+C5e/stbzFUVQ8nDvpRJxz5YBd8xO1l8RlS9A8xj3iTi02xO+woH639
         jcHjg+9QFp3dISiSeotPUUHWdiyWByZX37yG2zXzc5YpcqHwq/TtKvJno3Yc074qku8/
         rzlbG4mvIoc3Xg5hHL+cswVYuGhdyaC5l3Sk4pTReYnNryojpeLMPyGyQnQUFnYXe72f
         CR1o2mdhoua0ENUfq2V86ntsUnuhGmZ5Dm/uyg7Zrxsrewv/dLrVaHTT3NIQ3h2Rt9gp
         bviQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769002931; x=1769607731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:references:to:from:subject:cc:message-id:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dekReyp6UJzS8Eoi8ti4ESYPBV5qJAYuZc1XyYiM63g=;
        b=E/Uz3oBkGuRvxTjFYkll8aQA44pTRdzhjxVGmATtjCtIpFMErNHc5fiV/TFmxt6Vhn
         068Kn/TKAgoEl46cP9gG5tynuO//pWy1HVIcqndVq9Erz6hBRHhFkvogrccuslUnqXf/
         3YRtkuBVf+x0PiwHtGTnH3QjgKhbhxqDf9vfxlobrLAqb0Jxtguh0MWpEOcHpEtHi0nO
         GAbXBCG5IL6+cl4TRECwXDYzriMlG4jqDr2OrychJV8znbJITUVpNINurvVw1JIAbCQB
         xoy0ZrTukGdmHQyOhkz5fERqLKQ39dhFrhLCHM5rRjIPq+ALyeA1knt84ZnqKkDf9cib
         UDWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVHVcNdxj+zOXrT3NFMLNF2ptEJuBmYMe/TT4awGnlgvvA+xPShv+2Xj8XtTlVkLbSbUTqr2w==@lfdr.de
X-Gm-Message-State: AOJu0YwntnXWTHu/xj9o/j2VufLDeADGNT7HORZaaHJVntrq9cwmIFOv
	fJV6z4Z2XcqKpRVWejbUMeSb0u3fdE6m6Bc9JahkoDoZDpJqkBcKJSsG
X-Received: by 2002:a05:690e:408a:b0:644:535a:65d4 with SMTP id 956f58d0204a3-64917722cd5mr14179962d50.54.1769002931599;
        Wed, 21 Jan 2026 05:42:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FUOB4MOEdCYBlYAmQefuT6HiM5qybLRYX/0/oXO6N+dA=="
Received: by 2002:a53:cd89:0:b0:644:730d:6219 with SMTP id 956f58d0204a3-6490b89fe6fls4667852d50.1.-pod-prod-05-us;
 Wed, 21 Jan 2026 05:42:10 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVtS8nHYqXoV1EIQEwKEvkVQq5YZESuX765QWbngMc2DmJUsDOQ3fqOrFz5d96wA3EnHGZG9d9Cb3Y=@googlegroups.com
X-Received: by 2002:a05:690c:c507:b0:794:1473:82a1 with SMTP id 00721157ae682-79414738626mr34673867b3.45.1769002930241;
        Wed, 21 Jan 2026 05:42:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769002930; cv=pass;
        d=google.com; s=arc-20240605;
        b=NvWVXqQf03jc8IM1bTizoj0LafEtBNi6J0IleGb57GEgvCj/KQYvesvdZmQtLZ2mFw
         QeEkj2KmYpNJRY4JF09KNFwKIS5suM7uNHIDDwT+l+d6WS9qLjWHeh/p3ZSNgg8G9Rjr
         SxQPwO1s9JmKXO1Kqdfjq/fwABXnNcZmAD4zNUVe6wiyOAnRRiIj2XWHRIWTkCtYe+4p
         Wxes774CvhF4SRXUafUbVudu8ITtddDq6smReKRwh39a/puBZOcsV6fn5yPPZ3ccVinm
         HQ9m3eH00R6cYkG9yXZDHFQ1j3XqAo+BRMPgNzkfR7odnCMk4Z8fTZaWWv+5pRY4CDCH
         596A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:references:to:from:subject:cc:message-id
         :date:content-transfer-encoding:dkim-signature;
        bh=7Pgu+Uo2bsjg3kTS/e9dc7ORtuYCeVeuuFrYSA1l/x4=;
        fh=3iOr1YskoHRrIx2Ydg+Vo8ktFUbeC8RIUFMYBiappJM=;
        b=OwUVSKCrYJ0Qo9XdL6BcWEhbtqZJUuIqhgo9/7BbmBo49vJs4xdNF3fJfUCSDAsQNm
         RN6iKL3e/RayMeGzbBMJhC5OiPZG8IP0OaqSP1OVvGmD+goHSuE7SWrgb/z/QYpW3mdX
         ccQKy5hBZKhk3wUiXWuIG77yVO+C0SlZE7IxKJ0aD+nRBwJPji87mcuFLHC66mXaYM0I
         yYtWNcCyLeuY/OLUekyUkLi8VWVFXNtgmhX1FjqdYON7dPguohvUrB6kuswz09l4FBc3
         CSWrC/kQnV/dicNP4T8wWwAFcjFqWiseAxYyZKrXywAXxwwEFgPasJ/e6oDYTe6ujp1e
         c5Xg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=AZjPvugu;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) smtp.mailfrom=gary@garyguo.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
Received: from LO2P265CU024.outbound.protection.outlook.com (mail-uksouthazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c205::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-793c66e09fcsi5727197b3.1.2026.01.21.05.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 05:42:10 -0800 (PST)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender) client-ip=2a01:111:f403:c205::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=cb6GRsimR0pehQZGrxTu+aoCzUE3B+2tY61e7k7b+aDvveXLhLO3PI+/cybtuHI0wcvwkfpb0M4EvBa/kipVZFQ5TwaKuaGSOQYu7hu+a2ZXPo1ePlHkz+LqWYgWZN3TzVYobeyANSDOBaqMzbgoBePlpX4SawZ3BHjMYDeW9mOdAxnrg95OFhd3F/97B6dRuwsjnP0UTStG9aXUaIec0GeIwNXfBRnwyIpmosBaI+ctE9qeyRt3/IKe2W6/tn94xQOp5amaYi0j8WO9FwZZPCR7VkBdFUK5Agil9/HjG2HCSlsb6rGXeFJdEO0c1yEYX3AU4d/E7bfMkKIsjucWFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7Pgu+Uo2bsjg3kTS/e9dc7ORtuYCeVeuuFrYSA1l/x4=;
 b=rNos3Mt6Hai6pW+BwcVrneFkkl0Vgg0ZalRsvTy2JtnFKpm0fwZmosrjlsGco95Yfq8mim1xRCfZnJ9vGXX1+CYn10QsmkEwje6lI0RYOHlphP78phGnhkDr22lrDwrQHV3US/5cSKFI3ay9OH7VeBtdp7Z8nK4D3qKm5l8N3HzmRmHLlyiTUiB4QKVSQwDdCxkaoiq0KmUiXqxrKajbaGld5gJS+hCaTUdety2m+5auU1mk1uMQ3aqnnsJHjWUktkJYeF99UmYLPEbWv4uTF8mAVyp4yvT130FZLL0Fp27vn4kPewULHUNVepoAFEKrjx2gs1dFAw5+V1gSdVKjmg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:488::16)
 by LO4P265MB7390.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:34a::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.10; Wed, 21 Jan
 2026 13:42:07 +0000
Received: from LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986]) by LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 ([fe80::1c3:ceba:21b4:9986%5]) with mapi id 15.20.9542.008; Wed, 21 Jan 2026
 13:42:07 +0000
Content-Type: text/plain; charset="UTF-8"
Date: Wed, 21 Jan 2026 13:42:06 +0000
Message-Id: <DFUB79KG8MT9.3F6QF7R8I3FGP@garyguo.net>
Cc: "Marco Elver" <elver@google.com>, "Boqun Feng" <boqun.feng@gmail.com>,
 <linux-kernel@vger.kernel.org>, <rust-for-linux@vger.kernel.org>,
 <linux-fsdevel@vger.kernel.org>, <kasan-dev@googlegroups.com>, "Will
 Deacon" <will@kernel.org>, "Peter Zijlstra" <peterz@infradead.org>, "Mark
 Rutland" <mark.rutland@arm.com>, "Miguel Ojeda" <ojeda@kernel.org>,
 =?utf-8?q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, "Benno Lossin"
 <lossin@kernel.org>, "Andreas Hindborg" <a.hindborg@kernel.org>, "Trevor
 Gross" <tmgross@umich.edu>, "Danilo Krummrich" <dakr@kernel.org>, "Elle
 Rhumsaa" <elle@weathered-steel.dev>, "Paul E. McKenney"
 <paulmck@kernel.org>, "FUJITA Tomonori" <fujita.tomonori@gmail.com>
Subject: Re: [PATCH 2/2] rust: sync: atomic: Add atomic operation helpers
 over raw pointers
From: "Gary Guo" <gary@garyguo.net>
To: "Alice Ryhl" <aliceryhl@google.com>, "Gary Guo" <gary@garyguo.net>
X-Mailer: aerc 0.21.0
References: <20260120115207.55318-1-boqun.feng@gmail.com>
 <20260120115207.55318-3-boqun.feng@gmail.com>
 <aW-sGiEQg1mP6hHF@elver.google.com>
 <DFTKIA3DYRAV.18HDP8UCNC8NM@garyguo.net> <aXDEOeqGkDNc-rlT@google.com>
In-Reply-To: <aXDEOeqGkDNc-rlT@google.com>
X-ClientProxiedBy: LO4P302CA0009.GBRP302.PROD.OUTLOOK.COM
 (2603:10a6:600:2c2::17) To LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:488::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LOVP265MB8871:EE_|LO4P265MB7390:EE_
X-MS-Office365-Filtering-Correlation-Id: 895c1949-0703-4ad2-5010-08de58f2dea1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?bTBpalRoeERBOFNZQXcrdXgvaGlRRDRQM2MzcVUweVVlMXZtYXcxV0lJUVNp?=
 =?utf-8?B?OVFaQXVtS3pxbHNGdkxNNU9CS0tDYzZxSFpvQnFBM2xBSE1OUUhsWWp4dHl5?=
 =?utf-8?B?Qm83YzA5Y2NYdzNYN1lDZmF3bkMwQTdPY0FRWDBjOWRyU0hOUlFCcEY4SVdr?=
 =?utf-8?B?aUc2ZVc5S08wMkF1U2lLR0FVejJBYXJDSDVBV000UGtYWFhDTEtwSTlZeUlX?=
 =?utf-8?B?NVY0ZmtnTWNlZjhDcGMySzJ1bHJDVmkydmFYOVBVVCtqcUlRQm5SK2FrWlBJ?=
 =?utf-8?B?U0UvNUtjS2NzZENCMHhlUVJpZGh4YjhJbFltWldXb29yMFRTTlVKbVNHQzFT?=
 =?utf-8?B?ZnVZMlMza21uY3RzNTJ2YW5Ma2JSVk1lNmh3aGMxVXRPRTNNS01rcUdhZk1N?=
 =?utf-8?B?WjNOWUdmSUM3RzRPYzNUOVhJY3Q3L3lwK3JhM29IM3pXVmY4UDFpWUxiakZD?=
 =?utf-8?B?dGdVNEpuOUdUcDRBQkZIQWdiaTFwOGNSVUlGYVJSUXNRYXFOTXFqbERFamRs?=
 =?utf-8?B?UkJIWXd4MW1IL0V6M0dHdzRjeXhUSmFCYTdhSStJUXNnc1ROQVJOcGd4Y3dE?=
 =?utf-8?B?eG9CZ3JYcWhoNHdhY2NDSFhMeDkvM1BmSjlVbk5KbGQ1akVmYWtFWFM0Qk1h?=
 =?utf-8?B?bW4ydTF0RU56K082d24xVnU0SHF6QWxLQ1lteVp5NkZzbmJtQVZzTjlvYzRN?=
 =?utf-8?B?TVdobUpjYVV0YWk0QklLUGlFbWE0clZ4bXpWbm5oUUZJak1DVGJKMzhlbExK?=
 =?utf-8?B?Q25UdkwrWmdCU3hGVG5nRFBaR0UwR0VySVJlTmZoNWprSHhYY1pzWDl4Vi9k?=
 =?utf-8?B?UnRDYU9GNTF6aXlLbEFGcTBMNWNObUkvQlVpTU9ZYnA0YU5FaVg5MDNRTHln?=
 =?utf-8?B?MVphTkdvVHo3MFMrNE5SZG9XeTZqc0tUdnVOWGlXRTJRTHFHWkNNUGduSE5v?=
 =?utf-8?B?dDBaT1dST3VoK1JhV29sZEdTalhvVWp4a0s3ZVZ2cVBvVWlPeEJjbFJHSzFC?=
 =?utf-8?B?dFJFRVVEYjU4bHliYVcyQlVGbjEyTzN5b3N5U1FpR21ySHJTc1RVQ29Rc2xY?=
 =?utf-8?B?dE42YXFXMDVzRWtYdVdHMUxXZW1lRWNnbWVUeEgrSU4rcGxaaXkrTWVaUGFn?=
 =?utf-8?B?MjZFczlINncvZi9TT3pUL3lyVnZEcllHWkFlcGM4QUVwdDhPbnNCTXpxM1RM?=
 =?utf-8?B?QzJJYTc5S1VhQk1IMUVYN3pzMHF5OCtxQzE4MFlsMDRWQThFd2RiN3dYaXhp?=
 =?utf-8?B?bWtXMXJqT25LdmZpa1dmQXljaFkyRzNhMmhoV2FsWDdCeDR3WmZTQngvSVpK?=
 =?utf-8?B?WXBCelF3VkwvLzgwMDNhREJVWkhQY3VTNW1FTXQxRm15endRbGlmbmV2aTBP?=
 =?utf-8?B?ZnFpVHdGK0J6blVnUTV1VWZoeWdJS2h5U2dTaXNYdlM1d0szYnpjUkp2c29o?=
 =?utf-8?B?TjU1ME90NVk2NzdqNmx6dUV0Vjh5bEZuaFFpbENHVzk1WnpVcTFVdjFDanI2?=
 =?utf-8?B?bGw4Ylg3a0ZYMUh2Ykh1MlZ1MkUwdG9RZ1dxTHU5REFUMFFFVzJ0KzhpQU1B?=
 =?utf-8?B?ZkJrSG9mZjdUZXFRc2YrSjRBdDhReDZoL3NsZ3JweTVlSFVCeURXZmZSUDJj?=
 =?utf-8?B?S2U2MEM3U2NXQU9vM0pkYW1XOWdXUG9IbnZzY25BWTZlRDZCVmhza3JQektY?=
 =?utf-8?B?VkJuS0FGWjQ1UHUyUC9Zd1Yxa0N0N3lTeFhLQlZ3ZE5yTmRSdWlpcHk3Y1h2?=
 =?utf-8?B?S1c2Mm8wRldtblZzbCtrSDVKaDlrZkk1RlpTemhieVlHa054UmwzMVJjUkp5?=
 =?utf-8?B?eGZpVTZmWUs1NmUrNlpWS3NuTElSMGJqTjREOEIzQWc1eGZYWXkwTm8ybzBo?=
 =?utf-8?B?NEM4Y0wzdHNSazV4b0NVUlVOeFcvTWpKMWlPNk43Y3ViVVl3S0lQbDRvdnJQ?=
 =?utf-8?B?eUxCT203ai94UFU2ajI2M0l5Y0NWL3F2UnlGdWNnVnNsZkg3ZFRwT2JPbXVZ?=
 =?utf-8?B?b09hcGx5OEhNbVhEZGVualJoVUFza1RDRWo1WnprQmtsclM4ZUNlTmszMGtI?=
 =?utf-8?B?VDNUS0hFU05yVk9LRXpoR0pTUlNNeVN2eXltbG5oMHdWQWFNelJacEVoUEky?=
 =?utf-8?Q?KITE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?WCsvZTJYNHduUmtteUdRb0dtRGhGUGdqaDhpK2lBZmVhZkljamxXcS8vUnBS?=
 =?utf-8?B?YjlkSUpRVm1sS29TQTM3Q0p5MjdBMWd4dWxZdENiL1dKbDFoZTdMM3pGU0Uy?=
 =?utf-8?B?WmhGZzIzV0JhclJ0cW04SXgxT1YxaHd3dXppTEt4eGpwNzM4RmhYWWE5UTVK?=
 =?utf-8?B?ODJnMU81VkRabkVtRFljT3lpRUFwR1RmNkVJajkwRStxZkxiMkN3RnlvUHBQ?=
 =?utf-8?B?Sk1na25oRFdqT0VpMGJndFEvdTNTTHpDc0xaNmZPRENldnZBTGl6YzVlKzMy?=
 =?utf-8?B?REUzTTFhc2p3SkQxUEt3ZmkwQmI0MEZ0SGY4Q0d2Um9ZdFRaTHFIbVFUZU5N?=
 =?utf-8?B?bnFGRUJpR0drazFuZE5XQUFEL0VlQkZuVUo3b0VEaWhhajhPUXd0Nlk2UzFM?=
 =?utf-8?B?QWhPY1FQWnhjWjlkOG9XUFFMYzBxa0xxQ0l4YitubDM0d0dLMHU2MW5oWFNj?=
 =?utf-8?B?M05ESnRDK0RKWXNFbjlobzFpc3ZpN2VVUXVRS2RnM2NvZ001cmtlMUdZTVhx?=
 =?utf-8?B?NWIxWjZsYTl4R2t0OTdHZTdhWmRGOFU5eFY2U0xYUjlBU3lVRnJFbXNlU1ls?=
 =?utf-8?B?cVpwR1NDNkdFSkhwMDdTZWwxckswcTZRdysyckx6T3RvdnMxcGhNZ3RGemtK?=
 =?utf-8?B?ZzlBUFdTYmR6ZXMyMjZpNHNnM2EvT002T3FMQVlnQk12NVBiK2E1NXBTRElj?=
 =?utf-8?B?cmNoMXg0MHpoeVp0RzJWejlRemxiMStqcmc0aU56M1BZa2F0V3N4cnNnS29j?=
 =?utf-8?B?ZmlCbDAvazFQZTlaVEFFMTFtaGVERGt1NDlYNFhIRnR1enprc2paNENFYUhk?=
 =?utf-8?B?a29zSENoUnA0KzJaMjVNMlJFVThkSUFYVVZiMGIxNWJ2QVFyckUrdFNVcWVo?=
 =?utf-8?B?aVY2T05FNEgwZWFiMXYvclZvd2l6bFBMZkhUUWxtdWJJMXVXUk1TdW01Ullv?=
 =?utf-8?B?cExTMi85ZG9SVFBOV1orZGNqR3dtT1lPb0JPeVY5eDVqc1dYazRUZVhuclNR?=
 =?utf-8?B?WGhOMGhBMjlVTms3bE5oNVY4anVDREx6TGhxOUJGR3hUZUpyd0t0amNGbERR?=
 =?utf-8?B?NVFMVDZrckMwWWYrYmpwakxrcUdjOGpndEhRR3BLdm1IT0d2OG5GcUVyOCt0?=
 =?utf-8?B?cmViRE43RWh5Z29CZWpZdjhVa1lGL1VvU29aY1ZrNnVVT29QRmZWekZZcXhv?=
 =?utf-8?B?ZGw1QkgyVXlUQytpeWRhbXJDV1FuV1hpUU5UdHpBN2ErM0cydDh6UGRYVEkv?=
 =?utf-8?B?ZXFBeFFEQW5ocmdoOXJQbkhYK29vdGJ4bTRIUTdiR3NMaFhZS21VRHkveWJF?=
 =?utf-8?B?WSs1U1gzSWpDZXRTcjIvZXFhYkhMRVRTT1cwSktxMWNCQmh3QVdOZ1p6T2M2?=
 =?utf-8?B?T1BicjhHNzhRd2xpblpyL0dUdko3NFk4Rm5SSjVxbTlkeFA3ZzR4bkxQd3BE?=
 =?utf-8?B?aEdMQWhMdFZkaTB4cS85ZVNiTHhrSmJNL0pKUDVHYmJiWWgzNnFFakMzVFND?=
 =?utf-8?B?NnU5b2lYSWtGL3N3Zk9wY0lFaUlLejFBcm9VQWUxSHFqOEtVZGdiNll6TERQ?=
 =?utf-8?B?NjdVaHByVnVqUHk3eEduU3V6Q1AwYjV4NFdMVWpqMGRrNFZZRnB5VmxXQitW?=
 =?utf-8?B?dlErMVdZWFZHZFR6VytDUXVKV0FVeEIxcGJ6V3RobGNXWVdQWVhjNC85djBZ?=
 =?utf-8?B?Zmp0VzUyMGUvSDUvSXc4WGkvdkNXRTJ0UWZRNlBETFo0R1FoR01FOU9wUUQz?=
 =?utf-8?B?ajhFdGRsZEtaNjREdlFOTkZ0Znc1eE5MOXdHdzJoVGpoQ1dtdmRmQ2U0YVcv?=
 =?utf-8?B?N3N6WG5CM2tqcjFDTTRrenJoalQvSnowR09JaUtmTEJrZTl2Y3dyYXEzV25H?=
 =?utf-8?B?R1BPQy9NMkxaMHY5UU95M0ttVmtQdnFGRXZBMmc3Y3JuNUVXYTdJbzdlOVY4?=
 =?utf-8?B?c2xyZG91MWJzVnNOOUswRFJkQUlPK3pHWnhPSHdjSGZxbXZ6eGt3VVBEQ1JX?=
 =?utf-8?B?aUphZEJFNlRMdjU4U00xSXA0SUhYZHhpOUJQT1ZFU0o0Z05JTWF2TlBrWm95?=
 =?utf-8?B?YjZuNlNrZHV4VUFualFqemJySFFBVDg2cmlYZFpVVCtvUkFzdURzdjNIdm9y?=
 =?utf-8?B?RitUcEtDRjJZTktQSjNvc05JbUZqZkNJTjN1NWhHd0QyVVBBOHRVbjcvaXo2?=
 =?utf-8?B?N2s3YmlNcWROZG1iL1BObm13SlE0QWI5dFhyZXVjMDJjSmYxQlRVWUVKZFNO?=
 =?utf-8?B?bXBXQTd0UzUrN2NFQmFUeGxzNTlBWkc4R29aeUQ4RjU0ci9kU1Buck54UWVS?=
 =?utf-8?B?QzZPcllhaWJPbUtUQit5RzRsMkkvR2E2WEVJRFRka0R4N2dMODlMQT09?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: 895c1949-0703-4ad2-5010-08de58f2dea1
X-MS-Exchange-CrossTenant-AuthSource: LOVP265MB8871.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Jan 2026 13:42:07.4569
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ly3y5/HgnYL3APMIrQB8z6KlT0jHS4IZgbwXtaQJJsqFB75Wnydw59a+HcVvD+ErtJOYc4Q3dG5pd9krNKYfug==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO4P265MB7390
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=AZjPvugu;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 2a01:111:f403:c205::3 as permitted sender)
 smtp.mailfrom=gary@garyguo.net;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=garyguo.net
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
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	DMARC_POLICY_SOFTFAIL(0.10)[garyguo.net : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDRYTJUOSUERBM5PYPFQMGQEMXUHF5Q];
	RCPT_COUNT_TWELVE(0.00)[20];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[gary@garyguo.net,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[google.com,gmail.com,vger.kernel.org,googlegroups.com,kernel.org,infradead.org,arm.com,protonmail.com,umich.edu,weathered-steel.dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 2FE2157A95
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Wed Jan 21, 2026 at 12:19 PM GMT, Alice Ryhl wrote:
> On Tue, Jan 20, 2026 at 04:47:00PM +0000, Gary Guo wrote:
>> On Tue Jan 20, 2026 at 4:23 PM GMT, Marco Elver wrote:
>> > On Tue, Jan 20, 2026 at 07:52PM +0800, Boqun Feng wrote:
>> >> In order to synchronize with C or external, atomic operations over raw
>> >> pointers, althought previously there is always an `Atomic::from_ptr()`
>> >> to provide a `&Atomic<T>`. However it's more convenient to have helpers
>> >> that directly perform atomic operations on raw pointers. Hence a few are
>> >> added, which are basically a `Atomic::from_ptr().op()` wrapper.
>> >> 
>> >> Note: for naming, since `atomic_xchg()` and `atomic_cmpxchg()` has a
>> >> conflict naming to 32bit C atomic xchg/cmpxchg, hence they are just
>> >> named as `xchg()` and `cmpxchg()`. For `atomic_load()` and
>> >> `atomic_store()`, their 32bit C counterparts are `atomic_read()` and
>> >> `atomic_set()`, so keep the `atomic_` prefix.
>> >> 
>> >> Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
>> >> ---
>> >>  rust/kernel/sync/atomic.rs           | 104 +++++++++++++++++++++++++++
>> >>  rust/kernel/sync/atomic/predefine.rs |  46 ++++++++++++
>> >>  2 files changed, 150 insertions(+)
>> >> 
>> >> diff --git a/rust/kernel/sync/atomic.rs b/rust/kernel/sync/atomic.rs
>> >> index d49ee45c6eb7..6c46335bdb8c 100644
>> >> --- a/rust/kernel/sync/atomic.rs
>> >> +++ b/rust/kernel/sync/atomic.rs
>> >> @@ -611,3 +611,107 @@ pub fn cmpxchg<Ordering: ordering::Ordering>(
>> >>          }
>> >>      }
>> >>  }
>> >> +
>> >> +/// Atomic load over raw pointers.
>> >> +///
>> >> +/// This function provides a short-cut of `Atomic::from_ptr().load(..)`, and can be used to work
>> >> +/// with C side on synchronizations:
>> >> +///
>> >> +/// - `atomic_load(.., Relaxed)` maps to `READ_ONCE()` when using for inter-thread communication.
>> >> +/// - `atomic_load(.., Acquire)` maps to `smp_load_acquire()`.
>> >
>> > I'm late to the party and may have missed some discussion, but it might
>> > want restating in the documentation and/or commit log:
>> >
>> > READ_ONCE is meant to be a dependency-ordering primitive, i.e. be more
>> > like memory_order_consume than it is memory_order_relaxed. This has, to
>> > the best of my knowledge, not changed; otherwise lots of kernel code
>> > would be broken.
>> 
>> On the Rust-side documentation we mentioned that `Relaxed` always preserve
>> dependency ordering, so yes, it is closer to `consume` in the C11 model.
>
> Like in the other thread, I still think this is a mistake. Let's be
> explicit about intent and call things that they are.
> https://lore.kernel.org/all/aXDCTvyneWOeok2L@google.com/
>
>> If the idea is to add an explicit `Consume` ordering on the Rust side to
>> document the intent clearly, then I am actually somewhat in favour.
>> 
>> This way, we can for example, map it to a `READ_ONCE` in most cases, but we can
>> also provide an option to upgrade such calls to `smp_load_acquire` in certain
>> cases when needed, e.g. LTO arm64.
>
> It always maps to READ_ONCE(), no? It's just that on LTO arm64 the
> READ_ONCE() macro is implemented like smp_load_acquire().

If we split out two separate orderings then we can make things that don't need
dependency ordering not be upgraded to `smp_load_acquire` and still be
implemented using volatile read.

>
>> However this will mean that Rust code will have one more ordering than the C
>> API, so I am keen on knowing how Boqun, Paul, Peter and others think about this.
>
> On that point, my suggestion would be to use the standard LKMM naming
> such as rcu_dereference() or READ_ONCE().
>
> I'm told that READ_ONCE() apparently has stronger guarantees than an
> atomic consume load, but I'm not clear on what they are.

The semantic is different for a 64-bit read on 32-bit platforms; our
`Atomic::from_ptr().load()` will be atomic (backed by atomic64 where `READ_ONCE`
will tear) -- so if you actually want a atomicity then `READ_ONCE` can be a
pitfall.

On the other hand, if you don't want atomicity (and dependency ordering), e.g.
just doing MMIO read / reading DMA allocation where you only need the "once"
semantics of `READ_ONCE`, then `READ_ONCE` provides you with too much guarantees
that you don't care about.

We'd better not to mix them together, because confusion lead to bugs. I have
described such an example in the HrTimer expires patch where the code assumes
`READ_ONCE()` to be atomic and it actually could break in 32-bit systems, but
probably nobody noticed because 32-bit systems using DRM is rare and the race
condition is hard to trigger.

My suggestion is just use things with atomic in its name for anything that
requires atomicity or ordering, and UB-free volatile access to
`read_volatile()`.

Best,
Gary

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/DFUB79KG8MT9.3F6QF7R8I3FGP%40garyguo.net.
