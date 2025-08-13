Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB2W56DCAMGQEUWJEXWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id EB57CB24154
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 08:21:32 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2430c5d4d73sf7494775ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 23:21:32 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755066091; cv=pass;
        d=google.com; s=arc-20240605;
        b=I3IlmxjOmAKBV32Kvfl3Y5WNa05B1wjEqUm3mtZJo+gscJBpAfXeXbGeSeF3Zz1Nm7
         2CBPgKjH6pvXw0/CZw0f40kyIqYHfhDlAOI+ldIiIOjcY4szaDa1gduT/ZKEB+7CqD/i
         cGDHgKzQt0BXLhk9d9+LFNFnlrfhKCJnX+8DZJFf4IlVLu5dXSiV2IPEjEvelrPtpKVl
         CllpuJwP8a9BEz07sdzQG+XG16HwcM/7QCbaahvmTYRlpO2/sAtS2FwdqlwGEVjF2DOK
         XMmNkGKfCWkbIunY1+cLoWV/9/VOi2wNBxZNzqx9X2BEYf25tIy5w+oZMwGSABxRu5MF
         HvHQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=/lV/M0jLaO/tHN3UW2b7i8kkb4V664VBAUxWqmq0Jbo=;
        fh=ZBRcVL6DAA0mivWQA+K2q5ImSGLb/0WfkeuQNzNdm6Q=;
        b=RYwBmoX6W2yzzJWKCSPlZE4kglvIYnnLywO+fJ7+ObbEv0fAr1n56YGnIZwLo2J3e+
         jmcprqW/EW9PeDaRXECZWxSxuKRgj9s0YdD2u4tiyuUf2dY4SPjz9xQORL91mmGBBo8T
         jcXk59geGQvAw9orBPqbagbqQzXs0c+FMdg6jvKtbPVolqCOEJgWJE4ComlknBLsOkYf
         BRCIedNa86/gY3D6mD9ArNKD99maVhoAgjaia46/ldR6ijQIsZusZp1MT6cor0SAFU8r
         1VXvuEE/PwX7F/CUxcC0Y6lq7bHKANjfuf/t0vrAb6QXxH6BR3jzt7IXolhynprBFmBy
         quJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=El9ev+RK;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=El9ev+RK;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755066091; x=1755670891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/lV/M0jLaO/tHN3UW2b7i8kkb4V664VBAUxWqmq0Jbo=;
        b=pKVQ2LaJhfRpFWCC4DLBDxfQjH2XdAcCtWZwzF2hfXKVYHD1ZnH6ZszTaQzF/+q8+d
         pQlMFe4S+f7pNzwoQsgX+sVxPZKNOoUJ0YREGwB5lQbY4v9H1+st/4QQoiFHk+Cs8Bj3
         5dGj3qF5F4bkehlqr5LfCCAm5NvUc97T5RC55mnNB4+czPxIUoqDxV/WbDdIBcKTfPhR
         2XUA5pQjOAARdCYhnEz+jSVogc5V8V+NesHnZqV0ZgZq/xEIqnlokJg/dpyhe5XOaa7H
         yhUIrqcX2YhBlaYhMNq86h9w+DOa2oErtFqAunKMFtrdNk7AHpRB5WKygDEOLH44W71U
         2RJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755066091; x=1755670891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/lV/M0jLaO/tHN3UW2b7i8kkb4V664VBAUxWqmq0Jbo=;
        b=fLCRKtmq8Tsm+tmh6ZxgspWbtldUbsEQfKBbNp5uHTt147tQy8qW4Qbk0VrFx1t6h3
         9Fu+9OrKDP4RhhUmLq+6Xxf2FT+NoLHwyFAhI+jUdCtKuTYglEYAKBNPoEfrXcIr1JS0
         4rD3GacDamC1PsvQvrMAhY43GiG8Qy5kBtUqTJOTBWctOMQaUUXkafXXAKEfwyyU017K
         XLoPBKSAXx9TvxZGo7EdDbafsLXXccoVLWsJ07jAShnP7PU9a7NRdgTW13lI6i2bDkKL
         wFuKAmntbCtfHHmU3I/ptcF6sbZ3P6G7sh1jgBlBVCE3mzXGiVDE5eVzufc692hoJzdY
         DSsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCW8p/v6ij/Y6W9QnMmUK4JlFQzGMRp7vZZz6mc/8QoQLmc8bEcFz5eXtU4arRUCJg3ypbMCWg==@lfdr.de
X-Gm-Message-State: AOJu0Yyc4ORo05E1MewJ3z1pRZh9lm1dGSMTSkUwG0dYiSqGdWcPNUHO
	wynRn/k+kpM1T6jcSRtTWY0mKFV+lXkpMatf8ucP7kFZ5gSKdEN5O0+a
X-Google-Smtp-Source: AGHT+IH9tFbXxAoixd9bWwwuqgzsWxYQzbXA0HD1RybGpAX7qW5XOHZ5IoWgZc44RSFQ1vVMS/2MXw==
X-Received: by 2002:a17:903:1a8e:b0:240:20a8:cc22 with SMTP id d9443c01a7336-2430e8a8a2bmr16973765ad.4.1755066091053;
        Tue, 12 Aug 2025 23:21:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfYIJhg+hYhfmULseBuo2JH5LUt1M/dBF0Urp41fcUfGQ==
Received: by 2002:a17:902:f688:b0:23d:f00c:10ef with SMTP id
 d9443c01a7336-2430c7be0cels3993345ad.0.-pod-prod-00-us-canary; Tue, 12 Aug
 2025 23:21:30 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWXd7r5LsZpW5FfcTuH/gk6dDFoPPhAJH5JcsybFqGJVLx+PTHgKuI+qi+5kYkwaaMQU1bFTpChIFM=@googlegroups.com
X-Received: by 2002:a17:903:245:b0:240:b630:e600 with SMTP id d9443c01a7336-2430e9ba5cbmr20064955ad.11.1755066089780;
        Tue, 12 Aug 2025 23:21:29 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755066089; cv=pass;
        d=google.com; s=arc-20240605;
        b=iIb0T8eHdBUOUvompdxls36W/POBB4KqlwJk3Ya1DscNy5jZcwdKbXr4tfTVr/hMhl
         RaGTjof+VN0pL6fjtG2GkayzNtkvVG89ZJ903fH53o9D0L1JutPX1az9NyMLXOppCjNo
         +CuLDBwTdefWkgTffDwcP1oxNFHU/T2BYAkb1xCAj6xcj6UteSk7pyxihoHnAOk/boVb
         ee25zbFUiMWVBGZfYBFXMJuB4Cu1wyoOoA651tib6RvgrkYJJ6Co0ix4cOCGFdGw/fnk
         ePMFhqSSKZFW7s+d2I3avVuHJ+EhjHWO95JyhHWBcml1x3gxzvacdgv6EGJFOwWitwXg
         k8kQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=7/btdfuEn5mpFbYu6SzHbvZ/cbE5Wfn1/Qs53yMSXro=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=UoLDVAliaCnbXENjhxObtnztjBlcwSR2jvrBXhJnyoG0ElLqFuws+yVyGzLvWVBq0Y
         i+75s+wOcPZPahjXajDYKNQyDN7Vf6QUYOgZyWcH0YdaFbYXiNCYFM1J+wnfoshH7aV4
         LVjLWpN86UIJ/08JNkfMzA+Ji9Bu5FLg0IBajNaAJLD+hTEBCdA7fMFzNn0C1qQ/um4Q
         D0uKme0Lkj6Sv98BjKQtWLTag8QCyUfk+M+9nqjXJpVsbTfGJY/tZgy9X5rZLkbAp64D
         hadho3kqGtrwRBCurR98uhn9Hysf9GrVwLsLeYelymCgKeg+QYQtxuQydpnAQMUakpob
         zlKg==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=El9ev+RK;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=El9ev+RK;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from AS8PR04CU009.outbound.protection.outlook.com (mail-westeuropeazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c201::3])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-321c2ef5e64si53800a91.1.2025.08.12.23.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 23:21:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender) client-ip=2a01:111:f403:c201::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=SKlVRrV8Q1YhHK2HRb4lW2eudRdp9qOkCJElokgubcUJi9rBqrmH5qEYIF0NGlGJnk47/vY9m7CU5CK0EQyIqUhyFvELZTAKGnXG2wywuCr2bWw01FSiYp0K3lLjiRB8L+eKdfawsXeb4+fvI7mWvOFhHuw1J+VGpDVavDKCod97+9MSVD8lDg8H8vn0MEx4Y4BphT5AgNV/xIX2d4LNRsFEcyU9d0zhti1d+XbmZuT/l53iTtvHanc7tLyc3boE4Jcjz9D3SAmWyjGGYTB/fxafWRw3PnjoXtYR3w7HotIDZti8SEciwpsU7TcvSTJP7zPDNVIpRbWXNLOUBtwMFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7/btdfuEn5mpFbYu6SzHbvZ/cbE5Wfn1/Qs53yMSXro=;
 b=Y+VXmoAV03qa3YGhla7YuTIt52nHbeirqF7rliPTM00QcWOEW70OGMAlpnIUe3U8NKyqGPSns2laTX31bEy4+Ki8JqrLv9OwWxL3o7ZdSsVkFdIurBmTgQ9xl5yFWNa4C5nE6TSYTa+eZFvZLgZ2IZiMVjKieIdhSMwPZRfJogVuiU4Roby06ImNstXshQ2FOAaAvRKTlkO0OU5mTCYbGPT9IJG5dsbEHeHDC//lzzsBXGcTTXD5gVfSCzFQgYzVjMWZ0Ub6IAQVYQIRKVXvAD07juZd4okEzapWmSsAe4Zx9rXAmZ4/ONVdDkxJ2SPv3r/As18DiLWzVRm69icF5g==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from PA7P264CA0045.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:34b::7)
 by DB9PR08MB6649.eurprd08.prod.outlook.com (2603:10a6:10:26c::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Wed, 13 Aug
 2025 06:21:24 +0000
Received: from AMS1EPF00000044.eurprd04.prod.outlook.com
 (2603:10a6:102:34b:cafe::63) by PA7P264CA0045.outlook.office365.com
 (2603:10a6:102:34b::7) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.15 via Frontend Transport; Wed,
 13 Aug 2025 06:21:24 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AMS1EPF00000044.mail.protection.outlook.com (10.167.16.41) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Wed, 13 Aug 2025 06:21:24 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=UKk8Q4PtHK52MKk5+pK4+Ycj2L9W4Q4Sb1xXTXljCh5D/dXkpTyZDOFgcdHKeF8HNHOfDHYTUiY1Buc8v74/zks9EALjX1Jky4pan6tqTk3PPDKE8UlEFUh0WTstFMyn91zDDuFKZgyQQzwa2M4+0tpBaI54zRajdiEtJTjONjZFr11aO0lsiFh25prg9rb1SI6rdbqa3tMFVAPxeWpQ98WXBqgI38Z8E+NcWYdo+PmM63bg4Eid8BBhT4zj2M3INs0mnXKtoLlF5nOFwluce708XiM8BQ+droBie+nGyvVnodr9zPa6Y29gD23aDogWD4xzRbROmo1MW9O3UaLRMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=7/btdfuEn5mpFbYu6SzHbvZ/cbE5Wfn1/Qs53yMSXro=;
 b=lC2SnZSAtRyDBXKYlAhbAeLq4AjPgNoPRLkJvKflsGYCZQvmEvsR4tXrUTN5KT+WOHyXlVsfv0g4xSX3Vvs7FvU6L+qfN8Al1WQritrlqr6mDpcHdEGfbyR4ig4oqksl80yar0Xi8qn+nrKst2+ZwPlA82zIrO4IMd4L90rb1CczrRekPGr8oID4q8Ly4Ap4BaAzWJLoqcpxqMypJ98MNFCOfvhMamcx0MJei6G3x0emNd9eEhqm6/+dLpASvx2/9HoaPRC0ioMcJilRY/4nSX8eySXFcGZ/b8y8u6mB7o3Fnb0sajpH8Xgf87wRrS/donrVGytSwNxNopAm5OIXaQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AS2PR08MB10112.eurprd08.prod.outlook.com
 (2603:10a6:20b:64e::9) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.18; Wed, 13 Aug
 2025 06:20:52 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.012; Wed, 13 Aug 2025
 06:20:52 +0000
Date: Wed, 13 Aug 2025 07:20:48 +0100
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
Subject: Re: [PATCH 2/2] kasan: apply store-only mode in kasan kunit testcases
Message-ID: <aJwuwBL+Egh3Fivv@e129823.arm.com>
References: <20250811173626.1878783-1-yeoreum.yun@arm.com>
 <20250811173626.1878783-3-yeoreum.yun@arm.com>
 <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
 <aJtyR3hCW5fG+niV@e129823.arm.com>
 <CA+fCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q@mail.gmail.com>
 <aJuxuKBm9qfpVkBC@e129823.arm.com>
 <CA+fCnZdWOh3=KkM4AL1ZYfhyMhdSqgW97Rz+uxO88mMkqT6WTg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdWOh3=KkM4AL1ZYfhyMhdSqgW97Rz+uxO88mMkqT6WTg@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0021.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:151::8) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AS2PR08MB10112:EE_|AMS1EPF00000044:EE_|DB9PR08MB6649:EE_
X-MS-Office365-Filtering-Correlation-Id: 33435f38-c872-4616-8ade-08ddda31a0f3
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?cHqVttO+CZ1szyQdgeC/7aymTGkkmfNXpnpuFQBT+BrnpjFGt8hzgcaVJt8U?=
 =?us-ascii?Q?znK+qiZjvKcZB2oNHji17LzkzJ3tZXTy6jtrJfu0Cs1dbq3AEWr9Llu45okS?=
 =?us-ascii?Q?ck7HSkrJ4RTkArl7g89Y3+q4gm06uALUEYH3pgtTsdR96UHdZgPPtto7iebf?=
 =?us-ascii?Q?OV5bXqB6wDLV7+5VSi5mOCF62bBRU2pOrVuXTSjUBep0xKlbm0rY+T9aQKWy?=
 =?us-ascii?Q?+EqEJ4NO2XdWbY/RYSX36AXyA/cMnFSww653br6kUxsgLVpMN8TJhbBI7aD3?=
 =?us-ascii?Q?oGjaTsQyF+Qb6cSV+n0jJ5UqbdCY3l/UlLFx+YxyXOJ9rAp6Zi36fidSIMdn?=
 =?us-ascii?Q?MRPP3Mar3vjT9TWHmFBiZMItTWemSVG7VtKj52RON8WATESDcUGnmd9Vgypf?=
 =?us-ascii?Q?gTpztbMYwuu+MyaGFm1tnPqZ0LvLQgLwWJUyilm+iiMBKp8K6ZFQO2Fgaqxg?=
 =?us-ascii?Q?u6JAW1yF1AQU0MxmTGKs2SMinguYd5WOeTLqYHxidP2CBTlQ5wgJp9l9mKL3?=
 =?us-ascii?Q?t2U8hKNlVqeAt7bwp3r5S6zTQaK2XFMnMvlKZxj5yV7nDeZhjrWBLKG08ItP?=
 =?us-ascii?Q?E1aDNEdU7tcmje2PF4CxizBV97s4Kv2hIlpMXalUZse6qXESA+wEeFSmLiDR?=
 =?us-ascii?Q?sa4WgxjW/zsWvqngm4XCPgTmUggau1ho5RThcbgAluRVPlDy8SgTt/Zt+rBF?=
 =?us-ascii?Q?H7HiHxHrJvMVw136uIE74ces8AOBCc/TObpvkoY4JYmvka9tqzza3SsAb4cv?=
 =?us-ascii?Q?WLGZbHtxSJD6k2thsjLLRjPx400SYueEELfxBHYphozrDNbUiTr9NyNxkTVz?=
 =?us-ascii?Q?mguBNR/oZwLMz8bhQFU9d3KTeW2/gChejuMW4yTZ1jGIqFiXSCGBWWahedTf?=
 =?us-ascii?Q?yMCX9fmVNMj/Qb8EHrx0WxbKhDPAHWmW8eEidMApAv+bFgDIAAswFGUM5gI3?=
 =?us-ascii?Q?rdOlUqp/04o3STxkmdvltS6OyNpuvTO6hkz1ySc0Ly1qMkyi+6BbFz3LKMcU?=
 =?us-ascii?Q?HBwpCsH5l1StFLCTk2UY+Lmgs9RKBnTuJOi1ZAbjNNmEZNiL/TinaClQ9h4f?=
 =?us-ascii?Q?RgyR2Z8uSTQ6kxXjMCji5cp3dcUAkKw0jLXN9qG+F6ISupl8+8xKqqeLqQAt?=
 =?us-ascii?Q?LL3yk2dOfhLyAgbW8adoU4wjmz/8NcszqAqhRYUQZsRU0JFlb9/ft2kVGaSk?=
 =?us-ascii?Q?TpFv7Y44sMuMSWGNuzLPMmv1Y43LzzocbMCs8JnPw1iU71S4auaWHNHA34w4?=
 =?us-ascii?Q?9RPiW2wgR8qWkwsvXJiYrljhx3au+OdQm8/oHY8wSLxP6FC7ihyBbn2GSl13?=
 =?us-ascii?Q?Uyms9lqNkHoF6ClApceamw71FrCe+XiV4A5H4KciAOY2P28TEX54yh5QkXis?=
 =?us-ascii?Q?FPJzB4kZXSSC4S8k+wi99METzBzaMdhMQgakMthuFcj55iPhegmJhqil0VZE?=
 =?us-ascii?Q?/viAwftX+4M=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS2PR08MB10112
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AMS1EPF00000044.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 9ca05dfa-cff9-4297-03e4-08ddda318d8e
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|35042699022|82310400026|36860700013|7416014|376014|14060799003;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qNJ4mFGlDFtDcTyD2NAySx61M0/dQ7oJcLsKRThIXlbIuvG3opJmXe4AkOSB?=
 =?us-ascii?Q?2jDArnMU9yazr5OdvCWGzBCwPIpXaLOsJXVT0WGwixf3U/Fk2o6HwAJbghtt?=
 =?us-ascii?Q?O2ZEgjM/SGnEJTZ/07qd+F+GemqCVC/zvuDyN4xsqJSHc0Va7bDg5OTBl47X?=
 =?us-ascii?Q?3hxlvi0BaNZCTL5aCMpQ3MChFR0dIc6P5I3H0i04fsTM4Z6hCOxd7MqgHkRb?=
 =?us-ascii?Q?f15Ei71zTTQpmB0E1ZKSJkerU9hYVA/uHTse7CnPrijBT83YJ/WhulATbcHy?=
 =?us-ascii?Q?SjQ2Xukf97srbhuL7wPzaG88+8sNlhCzIta/t32BeyiVGStM3V4hMhFg2bPy?=
 =?us-ascii?Q?tmcGc5nEzxt4hhyaD9I8ecBvBiVYvMQ/PTUUGaEJvH83oQLIi89OjAqeHi1c?=
 =?us-ascii?Q?5yoUkHw+6gqo6NhgbI7T9mDXMxRs1hFeFg0ZteNDBBsENTcAYlJKLLcv7zQu?=
 =?us-ascii?Q?w1aJwON+L+4OeKoUWaZODxEB6wYkrU1CIUZmE5JlOZmXl7dyIwpOLVOEW9GP?=
 =?us-ascii?Q?TVsxpDUYQ1mz/RwRy3//DNRASqf6wSOcoi/g7ZB2yqCeZm21shUnmM92+rCE?=
 =?us-ascii?Q?ixA+CM+Rj6OIZ+TmnMtxGv6KMnTtIKE6Eu7b9d2sk/s/g8YRMX6fMtH7nMjE?=
 =?us-ascii?Q?8mkFnK/RpF+YzRj2KR33B5pfNnsomHdf86p38qzaqw+Qgk3xUcmfXZqr6ApI?=
 =?us-ascii?Q?wPF/Sjwb5CMGbea5o2DQ4OZZ6v048lwq8Hu3AbSxVNGyINuGo0DSADx+05ib?=
 =?us-ascii?Q?N1FG+VIXxiwvPzOAUhYWEVIJZ9gTQCWEv2q1UkjR9Y4zpAlOvtDTCzwm0GOj?=
 =?us-ascii?Q?XDXrUMkjSfdyMvzs3BfRhsHxFcZLRXoiLIvY7YxB34kEGBZHFXlCTiSraNAl?=
 =?us-ascii?Q?/q0dHiZ1otGZcKtBN40Ogx/+NqkQIZrPAgWvBpCaem/hOMiDXDl4eD82HNvW?=
 =?us-ascii?Q?+HftCjet204G+0BkwTcT/4smdUFoZbNawafTXqnlyhToeX00bFEXk8FGhWeM?=
 =?us-ascii?Q?D4C7W5BtZ9sJTMb12DI4W04pS/KhJv47sXtsk78Hb2sxJfKBJaErNrsAyqap?=
 =?us-ascii?Q?qb8StcsAGXe2OV2i3SpXp1M0OJImsnlc1WFbiALgXq7ReSTdxbuMg8KTVMtI?=
 =?us-ascii?Q?mydyYfHfV+R/1KBskpr42XTwfOPHztd/9uxdzlRyJL/uKJv5v2TcEJOQPuRm?=
 =?us-ascii?Q?ksGdnz6WdJvlTIGqA1oHcWQotnMlBguXVOYBi54ZMFTBWmlzTfD6DG3kK/t5?=
 =?us-ascii?Q?RNELMPojm2xbZg8ptyH1CikUcUEnFY2DKlstGgVGd0SwdwJjvXMihlBhrcfs?=
 =?us-ascii?Q?UP/BAL74+cRIELcvo4NxdVugIlGvBBPXCOS4beh3vfsuFehpKJuAFR9DRJ1O?=
 =?us-ascii?Q?kNd7+dH3qTa6uKPvEyAt0mNc8B37Q5Nvk81cQqUIuNzbhx+yrabAIe1dCRsu?=
 =?us-ascii?Q?snOSQRwTL1HzFKkRLGQ8OJqDO+0X7CueWxnDAUhNDnWUXIh2jDyw2EEA8I9f?=
 =?us-ascii?Q?RSdSUGf8TmWqOXGsFN0us2aUlIZSu1jPf6nK?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(1800799024)(35042699022)(82310400026)(36860700013)(7416014)(376014)(14060799003);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Aug 2025 06:21:24.4135
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 33435f38-c872-4616-8ade-08ddda31a0f3
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AMS1EPF00000044.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9PR08MB6649
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=El9ev+RK;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=El9ev+RK;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c201::3 as permitted sender)
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

> > > > But in case of sync, when the MTE fault happens, it doesn't
> > > > write to memory so, I think it's fine.
> > >
> > > Does it not? I thought MTE gets disabled and we return from the fault
> > > handler and let the write instruction execute. But my memory on this
> > > is foggy. And I don't have a setup right now to test.
> >
> > Right. when fault is hit the MTE gets disabled.
> > But in kasan_test_c.c -- See the KUNIT_EXPECT_KASAN_FAIL,
> > It re-enables for next test by calling kasan_enable_hw_tags().
>
> But before that, does the faulting instruction get executed? After MTE
> gets disabled in the fault handler.

Right. in case of tag check fault, the preferred excecption return
address is the instruction where TCF happen.
I was lucky when running the test :\

Okay then I'll remove the invalid write in test,
But I want to keep the if/else on each case with the reason I said.

Thank you.

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJwuwBL%2BEgh3Fivv%40e129823.arm.com.
