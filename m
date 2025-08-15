Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBQGV7PCAMGQEQSQUNKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 16914B27A88
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 10:07:30 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e57004f324sf40465795ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 01:07:30 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755245248; cv=pass;
        d=google.com; s=arc-20240605;
        b=VKDhQ4VECDnI9RQiOWHhRYX5t3yCMomTyvBD5fCnu4/R6K6YtNWJdPZhvjpUNCjB4v
         YCUlLidqisIzNTq/L/xHvJ8ORsjfZDXd1GkrFvs1OtDkU7quZb3XmI0DCurwQJ7fbhQF
         fTWjFRFMuyiz/rOOfy7h0vxVZPBX78U6aJG+WkGPWqDiAw6Kh7sJzx9Ws9pq+oWrfWik
         MpI4+KiWYYJqTQk8+xEMOYZYCxN8kcc9nXNnaSIHbQQmN5QYybFNtJQZfCWuU7n1nHAS
         TLfIRSpLO0a1akhw8HvR7Pf2eudHfNXjb5drtEo0xNHGjAPBukoxdrw4g6IKmQuU65Ur
         oIxQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=DqNBhiBgHDTQwK0VzKsx20pKWAwF2mmIMCX38dbfiqs=;
        fh=zFy4lvxvqaFsItgSk0lSL3z0IPTzdqP2s3PoEyI+NII=;
        b=jw4jIQzn46wWsIFo+eVCEgRp/Vdmf3tmO/b/nAh3rv7G1upIw2QwDKrjESovnQgegA
         +UQ/o4a+tEzA+hHAwEY0PRFKFY4PfXsRgpAx7p2+GoAHKVC+wuEZeKDm/tiPysxhJhjr
         3Hp3tiHPbN4OIWBgufSUlizmnyBQ0lYl0FW7WBeDUHgJSiHfn4wfEndKkGI0iN46l6hd
         2reNaIqYAT6Wu7AISphM6bZhBdsVyvMZCakLBlmYlL3eAQjsO1EyI6FbVpRlPMOYli0E
         Y5lzRSRSRYVhUmXnt+kXPAkhRDx6U25MY0+jA0ZT1HEE5Y+rq5QNWMC5DVQD+ea/f8UD
         eo2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=haJsGhC2;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=haJsGhC2;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755245248; x=1755850048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DqNBhiBgHDTQwK0VzKsx20pKWAwF2mmIMCX38dbfiqs=;
        b=LxHeWqOMAXVyszCDldKEuGU3YFs/BjenDa7qL0JGuI4qDecsV7ooPwlx506bgkEwaC
         vGyI96VGxbuLUcxSwmcqnzgQyx422XDvhlmbJ6HcBUoQyA8uHkcEvPsrWBpufADBC6ai
         IBdCThJflxOFPT6UbTUsJP6tSnANDuwaG15X1TPbvdOx1nZijfY/CBAElXehuqE3t+YM
         5QQFK4h1o5Xp4QN5k6sA9n5fPIdrNNSM/EgJUwhLTMjnL9o7WHhrC+YyUUZh10V5YoFM
         FeDgaaHhq8Rwf5Wn0RSXSabDFWBEm5v7f073oCeCicU+jXRKS9s06G7Teqyr0ibtVdB1
         B0ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755245248; x=1755850048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DqNBhiBgHDTQwK0VzKsx20pKWAwF2mmIMCX38dbfiqs=;
        b=vo77Dz1jOr+TI1bxvD2O0/k24A0O40XktnwfD+nZ6wNC9tbjAJWj2kjE9RNggpbAE1
         DVS4OMHt8tAAHCszj+AmPzeR86txOHoNntzWn4hTEihn+ipzPXcoy/vOIgdAiEJCSOSH
         XOaeW2tRBUtqxr7hUc4LhqBgQfVMtaaKNnVYaE5KOQF8uSUrZ1IM+oEiCUl4ntch+1vG
         ZLNGOkr38/G1nXls2wKoEluMkTjEF3qQUVy6vhLchABKbZHnk1v86XU3Ol6+jpkiifsD
         n07mn+oHde0va+HGb+Tu5Vdntw0wI+W7t7Lr2ScLCI//9KxOKVq1LyGmQwmC2maHOK62
         XCqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXz6XzfhoUByKnlrEI8w8zzu5rReMwqb2pNrgxVDQqG5Dqj2byiR8iBsDsSYGB3IYsy+4VHUA==@lfdr.de
X-Gm-Message-State: AOJu0Yykk0KhZkGTgJUuznLasSY5ykPEXcUFmUWuObJjlOx1hjo1fJAb
	Yal9fK5KW38I6NDcJRuVBrNpZaTPB6JUAwGX0626R+KybeCrTsf4OZZk
X-Google-Smtp-Source: AGHT+IF3HxCYZ3dFhdQgQl6T2u5kRDKRewtKMJ1PRb9htObfWMggt9ci/SktnRusDP/BsIkxBd5fVw==
X-Received: by 2002:a05:6e02:2705:b0:3e5:5937:e576 with SMTP id e9e14a558f8ab-3e57e8a895dmr21127485ab.13.1755245248454;
        Fri, 15 Aug 2025 01:07:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdANtEx6wosByyyirhwcRm1SrH33Cqr1+s2dr4zRHH2+A==
Received: by 2002:a05:6e02:4601:b0:3dd:b6c9:5f59 with SMTP id
 e9e14a558f8ab-3e56fb9b562ls17872395ab.1.-pod-prod-05-us; Fri, 15 Aug 2025
 01:07:27 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWQSoYVfBWIJciTXG4fDv7aUrfo+y+8foKEu86zDl50O7i1hJ9U41grooFDqn1ctcNQCWxE1IXSHoA=@googlegroups.com
X-Received: by 2002:a05:6e02:3c85:b0:3e5:7e26:2f90 with SMTP id e9e14a558f8ab-3e57e9cbd87mr19493365ab.24.1755245247665;
        Fri, 15 Aug 2025 01:07:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755245247; cv=pass;
        d=google.com; s=arc-20240605;
        b=OQZAne7yn/DpQbDgnoGU2g5uPRZAT0wkrI+z843QRLvTkN9PQHixJcuWiw/hqr4Mmp
         iSFNGG080RRn/cXAeQUXcX5w2nozjGMscZ9MgQZyv34MbIyZ/5sMavVJHogV05cl5n6u
         7sAMnnEHhdXWkPQNT7RBgriMOo+JrqZ+9pfHHEgh1S2L9/QY5M28d20nSZSqPQl0gd0G
         6Vp5//5Ym3XLJ23EINVTbkMClIUPA9JktvZ3tqABRxMENjf/AcS4SJQkkSkteddQNKXt
         yh/e2L2Mh6uvoi2MCewqS5Yk2UZKeQFz4eyGo+XEX3aaNgB4d1t3ZcoD+1/LDVhSlHGE
         nx9g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=xaoMl/Smp3Dnv6i/e1UFNzlS+9QMXvPz3nluE3uu6dw=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=KxmvUdGs1aIzDjpp3DXzHSGAkDJQH1Aw/QIjLDU4Biw860pDOxVuFjhjfH534fk1eC
         aqE/+xv7fLcwfLvKxB3v43e3lmgkEvJ3nJ3kTtanwR2Cw0kVLeip8OAA3ybCAPTyJM5f
         xA8r5LEA9+byG7XtVvfzowq/5faqXeWMCcy+iK5gbgsnOAXesXSABuMIl9tk78Qf90Cr
         zrncDtdiNfmdtba1dlD3CRUW4LDtjarmEj5zRB204bndmNjAGiwLrgSqO2sEs59s8rK0
         X2IYr3CWD1R/1XnHFDr36zex3uMWdMv4mZnuZx0304QYK6sT7VsOH4Qc1unA9E+NwvFv
         Dvcw==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=haJsGhC2;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=haJsGhC2;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AM0PR02CU008.outbound.protection.outlook.com (mail-westeuropeazlp170130006.outbound.protection.outlook.com. [2a01:111:f403:c201::6])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c94ab20f8si28986173.5.2025.08.15.01.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 01:07:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender) client-ip=2a01:111:f403:c201::6;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=ofsLh8Rm1PYPt8pxF+MLJCOtWZODBoSOQgmaGoCxKjBFvdmDnTRaoeeYwpI3RtVIOol2Zc+UAAfRkYf739WEqG9ghzte3klfgMLRrqBfLdvtN1WIAi40Yi2gbaGNGf5+AImVR0lkBbm8dDeibGQ8yT2t3xNAX/MbTaDLFIa15xAl+aSjI/ntuHQKEBlXinloijbRih+ZNKHHsswwOd2Zxr46fGUmEy4zYdv9+9hkOXDwXvBm/+EaZyVkkggsRWwQ3wWNKfTdFV8vNKAkwSL41eaUdrSYpao/ud4tH2KECOKtp3Krxrn72KQ11DNtWAwZ2nTja/PlLzaQ7YfyJiVMCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xaoMl/Smp3Dnv6i/e1UFNzlS+9QMXvPz3nluE3uu6dw=;
 b=WgSDbepfkJTXsJeX9yopqFh0zoNEgg47LoVJCRhc7JxLT8V2P+wdcBE+QWFfMd2OUUCi5+Ws+k24XFdWvue157jHJ5Wo/NHYMfxWnS1UdGLEmK7Sjkqu3lDdbfbzqfM2T31VJPk+nI51zlDlV/lStr2DKIBu4QE/r2aW1/i3I9IcFlDRZqj/JfCUI6E1V1XfGPhJ+1frukxn5/93WfQSCruzAg1GEgj8TnxdjmMH+qoHVbRKETw9G+9EmyBm0kJi7knhZ3vSY2ZNp/hy4AEATtMiwtesZGakT7V1Iw3Ga6FCHYvwx+8WtL+qV88Ouj4tQDzfWL42UgkUnVCDAt9xUw==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DB3PR08CA0008.eurprd08.prod.outlook.com (2603:10a6:8::21) by
 AS2PR08MB10374.eurprd08.prod.outlook.com (2603:10a6:20b:547::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.18; Fri, 15 Aug
 2025 08:07:23 +0000
Received: from DB5PEPF00014B8F.eurprd02.prod.outlook.com
 (2603:10a6:8:0:cafe::9a) by DB3PR08CA0008.outlook.office365.com
 (2603:10a6:8::21) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.19 via Frontend Transport; Fri,
 15 Aug 2025 08:07:22 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB5PEPF00014B8F.mail.protection.outlook.com (10.167.8.203) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Fri, 15 Aug 2025 08:07:21 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=t6/jedL2M2eZ1W7SNo+a7+2ksFuwQcfzI7WWHgCG1SGhx+ALdzASBEhQkpCq08oJ3YoY/wdpbkQGDmHXhT46jlOdr9m5ZtQMdz6mYtQg0yklJJrKkvS+2gu97oTMSfOlQGVbpZ3bBk25CmkVfQM3qS/mqREwe0IAwa1sdESUjVTAs3bNvWr8cRTydl+i30vgZDzCzDjkWV0aqPdbbJkU5X4m6ICYHcYXt2nM2Yv/vWdXonILFy4hZdnwba49IkNVVfRfZxFeybrAvWbw9wqEk5zI9RuNDWGYMlVvuhy6P5j2eW/kHQvPFdMcrevIUCacMOVXX0DgO1kJG+5yVaW93w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=xaoMl/Smp3Dnv6i/e1UFNzlS+9QMXvPz3nluE3uu6dw=;
 b=rumsi+96u4KyVFHHVv1JdYiJIGGRDM50zRAarRSrFEhITib3qJrZkM+tkmLCDg24mtgZDlLyf9++SRF7R19rp6aqIxzV1tqReWypgCxU+nLI8UdH81Ki35I1VrOAGs7xVST0LinQ4jr0ZwU26VEq5v2/+KfISVpyZy3r11IrChZpihq7tiyIym6RWIPx5Jo0o64fUq43MVKYbnZ9v9TH7NKR/sa3EtorDKR07lq61Higqehc2/59hE0mGJknzl7th2Xl/MAzs9XC+O14I8550vo8hFg4I4Jm19cbSUbpAYavbQHmcew+wsIMItA4zh4A72yMaD3fBV4c3JEU8jHSnA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by GV2PR08MB8294.eurprd08.prod.outlook.com
 (2603:10a6:150:be::5) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.14; Fri, 15 Aug
 2025 08:06:45 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.014; Fri, 15 Aug 2025
 08:06:45 +0000
Date: Fri, 15 Aug 2025 09:06:42 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 2/2] kasan: apply store-only mode in kasan kunit
 testcases
Message-ID: <aJ7qkpVA+41HSA8j@e129823.arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-3-yeoreum.yun@arm.com>
 <CA+fCnZeT2J7W62Ydv0AuDLC13wO-VrH1Q_uqhkZbGLqc4Ktf5g@mail.gmail.com>
 <aJ3E7u5ENWTjC4ZM@e129823.arm.com>
 <CA+fCnZdFVxmSBO9WnhwcuwggqxAL-Z2JB4BONWNd0rkfUem1pQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdFVxmSBO9WnhwcuwggqxAL-Z2JB4BONWNd0rkfUem1pQ@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0657.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:316::6) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|GV2PR08MB8294:EE_|DB5PEPF00014B8F:EE_|AS2PR08MB10374:EE_
X-MS-Office365-Filtering-Correlation-Id: 154c35a3-c186-4f54-675c-08dddbd2c2e9
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?gC85I1FuZQy8mPdQ4fx9Qrhj/Y75H0e6IiaObvKJ3VG/+yzODrJAf/8hziXG?=
 =?us-ascii?Q?Rqxf+wr/O+32RRQW7NNo018KLrRWBYWhXrbfa8ULBO/PRG9Pj2Ffe/js2pdB?=
 =?us-ascii?Q?1rdq60D6Dd8wGlQhoFe17WgtsckILvST2TnQH4eIY8R3zw3xCP1FTBq5akpl?=
 =?us-ascii?Q?+nBZegcNTox4zY/3LNTwhfIxtawn4EGP7eGnx9lJ0AkLzjvT45BzQVJWNH66?=
 =?us-ascii?Q?HNlToCkiCmg2Ch5rcJCHs88EqBbb23Oq8Ybz6RSJPDJYNG2bCGy049sR0AMN?=
 =?us-ascii?Q?Ux5XkRt+L6fkP2yCc3pfMguhRLWGiZGaS1VHDHFn1etkxcjuECbDnRQKAthL?=
 =?us-ascii?Q?c6QmFy0qh8eNncG+/w8D3Oav36MiFS/ML0dCwYSpjoLJhSGiEF2F9Dawp8Ee?=
 =?us-ascii?Q?XkFpp7iB2nkG09tqPunRmVODUpE/1fJiiffr8oJQsxqEIC6GCItIqFRKav00?=
 =?us-ascii?Q?4Pooge6o+J6bH14vQV1sVkKPvxhwven+m17SeLF8KsJZ21iT9RrumR2e4EF4?=
 =?us-ascii?Q?ukDAZDbb6ZvJQGu2ZPZYZ6OaLGsl87sVLe3YUJj2v/rFqLqRKE4dNBsMmq1o?=
 =?us-ascii?Q?O1zZs2lMDca7mcFV4rt7Bvqz0vXTeLXH20cskmwwaOxL6276DyuXFo9HboEL?=
 =?us-ascii?Q?NpIBbpuuEcR1LqSMZBe9485LgnXx21fm4sqoHzzHFUMqA1J2qeibl3nWhuJY?=
 =?us-ascii?Q?caIJAbI7OD8OyfV569AMedl/kdMceJS+SnOz5NxKFiIdUWyNmU723HKr+c1/?=
 =?us-ascii?Q?CG72IfbyGOweQ7svpcIUaclu2XFk7basvDA3zWSOpmOD+iUvONmpT9fTGx78?=
 =?us-ascii?Q?xk9Ruv+loawhvWPXGgiYBkw5GSXqMtCwsVHjQP9c80qARZ2t7pGKky1z9GT4?=
 =?us-ascii?Q?uS8766z/6F06MQQSE6qUWodSlos8p3n99Ac/qLDIzxPi6B+AHGU9aKjx0mWw?=
 =?us-ascii?Q?Rax2GJOWcO7aI+zRzNuViCP9DMtE+0PuHtAPZv6AgvfBSM1pKBClbmxzOcmh?=
 =?us-ascii?Q?WzfOdg6+fqt7dVfIaklQxhECGmPGYz8Jf3QuRtmBxAGeVCaan/mvEWxYb1we?=
 =?us-ascii?Q?N9NDNJo1PXUgQieeWDq+y1wpKkG7fl057OmXWbeIEVEu6YrahEz3HG2hG5hF?=
 =?us-ascii?Q?oYn7K7czgW+28o1IDiiFz/3C64hCxKKZPalxbzrMOtt4BexXGRI4UCqf42RQ?=
 =?us-ascii?Q?//PuNJZ2RzeEcpQCtzfJ6ISJ04Tx/waAHfWjFO7hxe29oBva/v4eSe//qY+d?=
 =?us-ascii?Q?+FzqLB9l0JYrnZ2FGasX4Nl0UokB4Fhjm5c7c0oA/aCvkrF0ELlw5VCzVyie?=
 =?us-ascii?Q?xJRmWZFOEouVKmErJ7UxX/V3XWsH9S0gZ/iEcWJkUttjpi9eLU311KN4D9Xf?=
 =?us-ascii?Q?GPb7QN0g7cqVhij8mpmWVIfr2OLQKH2BXeklxuk+xWZGMH/V8jMjaeBSEVTn?=
 =?us-ascii?Q?tOpfIEAYDSE=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV2PR08MB8294
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB5PEPF00014B8F.eurprd02.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: a5a3df2d-44b7-41c3-113a-08dddbd2ad3d
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|376014|1800799024|7416014|82310400026|36860700013|14060799003;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Q8MnY2nWZO+gqIIDHi2wuBBlCIJg2qJf2jhu823zwiSJZ2EwsPJGQSsyHKZl?=
 =?us-ascii?Q?QlP6z18dnCv1+plainFo+937hLTjXCHcdPumyZRebG7yT6KtlKWXz0fpD91J?=
 =?us-ascii?Q?oVeb0r7F5LWN/+mUH7DoPY1q8IkQqD0qwi4X1VunValk78faUof4zcuo6eAI?=
 =?us-ascii?Q?9WcQcVkiwRuFMGxFB2TxuC+RSeXRzBdsTovszyRDQ6n/2nBt7XqwtJVuwZrT?=
 =?us-ascii?Q?Kbl/eto4P/PeJW/dCgYyVwVggxHNOWf17LAEi+xaq3VJxLg2/alR2VPN4MPi?=
 =?us-ascii?Q?D3qctLh8KTK+43zpTllXj3qpl6FUCs3XjlJiNSFHT+cHX/HuQo5WOYGFKLOL?=
 =?us-ascii?Q?bh2X9gDeSxLj/6oSBEq+4ytT1fgXs+m1COkvzCHMdedQ6UsIdAQFhSxeLBdF?=
 =?us-ascii?Q?JyFJ/I7byVesVUm5Fu0JJ+BepxWSszlGv1oBKcAEZbnpTAiiLsVEjAJ16ycD?=
 =?us-ascii?Q?FN8aPr7GiJQojlrpFFx13AsUFFnjeOoYJ2iGpd5f5Fxt12pf66rlPlCkUsDY?=
 =?us-ascii?Q?e10irGlIXG/6SqhacSqvUVs7K3Awvz8/J3cVYbLJog7aWBe29ywVtDY7gX8N?=
 =?us-ascii?Q?oiOZIxEA4tEhxILbIi/vE2YgXK0EaSird908YDx/GI7k1crSKBfRQp5A0JUQ?=
 =?us-ascii?Q?2ftihZVSG4uMDvRFfP06JPT7T+5Gy2qiLVoBaEh8v0UP77USYlFTK3fjO/ka?=
 =?us-ascii?Q?91HdgfAL2KQaejih5DG8JjFX2KeO6/dVMzIBcHi5f6z0VUC3jN7OGbLNwCHd?=
 =?us-ascii?Q?L/w8VIlZrIa1HE7GCFoA2s2gx+j6sA8QiZu8XJTSnfQ7i2pN+Xerck/Wy5p3?=
 =?us-ascii?Q?+zbcEVAp+ky8xzmkT+n7TGRsYWqREfqpmS5+arZ5h50DlUfm/RQ7gIwLWOY9?=
 =?us-ascii?Q?kra7PSoRAw/e0CTkQvF4h/UNrKh3RwvBEwuylk/waMtQ/87qq+n4VhzZHXo9?=
 =?us-ascii?Q?aB77T8HzZ9cAP+wfCdo1wyqqMJDwQKAu+uVD/ghsqrpxhrj83JiIyKZBOq27?=
 =?us-ascii?Q?vS0l3Cvf+wtbrRoZLzS2EmPKw+kx15bjdFd1+WDWZ5JfvEmUuBU9RvRktRsm?=
 =?us-ascii?Q?CILtJl9tOHjCxhw2he3zDklge0qBPDRj3rn6247bPgRu5rdqPBJV1VJfXeC1?=
 =?us-ascii?Q?/gcHgRBFWPYW5FA+HFVdbr1imZXMiaqxUSiKA5KDHuwP24EJRSrXEbFIuKoB?=
 =?us-ascii?Q?dfdAJWMaV10oBajyWCZ83AgXQZxYsDWusA/pUo/HnUNRMjTV02bdo1BCLCKe?=
 =?us-ascii?Q?JyM9IszRXURZCdz/6gh7KXfe1CMWIunBikT9OW7GWgwYo4h3I4HkxNVksJ1y?=
 =?us-ascii?Q?eqjJI/ClkT7CBMQBNr8xCHMnatcudYIRlN2nCJ/U97v6oAkxYf8OVIsN8Q0q?=
 =?us-ascii?Q?Di5zERlRnvAUyt3r2dw6eJbn4TtXcoJQ08lFyp8BWZbo66VHm2H6fdMWdGpO?=
 =?us-ascii?Q?3Y5fKSCh0pG/aQ+lJs68R3FrahMjY9D7aFLZ4P2Hdg+Q0dtZ+yrpmej6sbus?=
 =?us-ascii?Q?+Psp4PsHWFgEDZgcIxwkLtWAbKMx4eD0G2DQ?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(376014)(1800799024)(7416014)(82310400026)(36860700013)(14060799003);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Aug 2025 08:07:21.5083
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 154c35a3-c186-4f54-675c-08dddbd2c2e9
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB5PEPF00014B8F.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS2PR08MB10374
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=haJsGhC2;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=haJsGhC2;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::6 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

> > > > +/*
> > > > + * KUNIT_EXPECT_KASAN_SUCCESS - check that the executed expression doesn't
> > > > + * produces a KASAN report; causes a KUnit test failure otherwise.
> > >
> > > Should be no need for this, the existing functionality already checks
> > > that there are no reports outside of KUNIT_EXPECT_KASAN_FAIL().
> >
> > This is function's purpose is to print failure situtations:
> >   - KASAN should reports but no report is found.
> >   - KASAN shouldn't report but there report is found.
> >
> > To print the second error, the "TEMPLATE" macro is added.
> > not just checking the no report but to check whether report was
> > generated as expected.
>
> There's no need to an explicit wrapper for detecting the second case.
> If there's a KASAN report printed outside of
> KUNIT_EXPECT_KASAN_FAIL(), either the next KUNIT_EXPECT_KASAN_FAIL()
> or kasan_test_exit() will detect this.

Sorry for bothering you, But I'm not sure whether
I understood your suggetion but that's sound of implentation like:

+#ifdef CONFIG_KASAN_HW_TAGS
+#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expression) do {            \
+       if (!kasan_enabled_store_only()) {                              \
+               KUNIT_EXPECT_KASAN_FAIL(test, expression);              \
+               goto ____skip;                                          \
+       }                                                               \
+       if (kasan_sync_fault_possible())                                \
+               migrate_disable();                                      \
+       KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));  \
+       barrier();                                                      \
+       expression;                                                     \
+       barrier();                                                      \
+       if (kasan_sync_fault_possible())                                \
+               migrate_enable();                                       \
+___skip:                                                               \
+} while (0)
+#else
+#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expression) \
+       KUNIT_EXPECT_KASAN_FAIL(test, expression)
+#endif

and you expect the "Error print" on the next KUNIT_EXPECT_KASAN_FAIL's
  KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found));
or kasan_test_exit().

this maybe work, but it wouldn't print the proper "expression" and
seems like reporting the problem in another place from it happens
(at least source line printing is different from
where it happens -- KUNIT_EXPECT_KASAN_FAIL_READ() and
where it reports -- KUNIT_EXPECT_FALSE()).

Also, some of test case using atomic, kasan_enabled_store_only() can
use for KUNIT_EXPECT_KASAN_FAIL()
i.e) atomic_set() which allocated with the sizeof 42 (writing on
redzone).

That's why I think it would be better to use like with
sustaining _KUNIT_EXPECT_KASAN_TEMPLATE:

+/*
+ * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
+ * KASAN report; causes a KUnit test failure otherwise.
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
+       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
+
+/*
+ * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression produces
+ * a KASAN report for read access.
+ * It causes a KUnit test failure. if KASAN report isn't produced for read access.
+ * For write access, it cause a KUnit test failure if a KASAN report is produced
+ *
+ * @test: Currently executing KUnit test.
+ * @expr: Expression doesn't produce a KASAN report.
+ */
+#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)                       \
+       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr,                 \
+                       !kasan_store_only_enabled())                    \

Am I misunderstading?

Thanks.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJ7qkpVA%2B41HSA8j%40e129823.arm.com.
