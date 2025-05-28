Return-Path: <kasan-dev+bncBAABBBGD3LAQMGQEJIHHO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 76649AC614B
	for <lists+kasan-dev@lfdr.de>; Wed, 28 May 2025 07:39:18 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-60212c73868sf3017191eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 May 2025 22:39:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1748410757; cv=pass;
        d=google.com; s=arc-20240605;
        b=FR9XsA9+ICqbK6afiAXJAlrj3rnwbXoaujINrJvzudjmgkpX0Chp2BHd2HkQQFE5gU
         LoTvIsE4nM+6PMk9CP1DHg7q/asCmbarMRk8vh+fMinon35nYfaAE1UlnL3bg5PO9ggk
         6zwAz+tA7Bcr0hItJ02ViksR4AkvzuqqULwDz3GfYmeWWskiML82tpbqlRRXSaGQ+ncM
         RZaYb8iBsACBU544FEe3eAZAZ4sMdhQ98vEuaP0350fax7Olr15mXAK9dmRnc6Gn+C4c
         bFD1HcoHKxu+gj3AndvVwdA2EdXk8gs8iShEH+T4YXpR780VOXJ9Eg5RkixcNjfDJWQ8
         ZMPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=6dZQyKGXOWR9nY9DxPA1lyjU9vygx9YyZNcpXSgVYf8=;
        fh=FPx/zUVXkfuQ7aEA0bcV0tdbrFL0+wW95+AFNsVpcHY=;
        b=LvAtbefS/fDfeX03aJvg+lhUU+cY6wJDh557kIA8Z4bXEMnj4zlV2mce1pg85S/efo
         YUE2bjUR33VfgJkV/iRqF28IalaJ4oS9Hoota1AOqp4uuQkHkVfkqg/aDKj0c0LnoQYL
         4xMGMAh12wY9n86JNdSIlKG0Qi+NS1ml4dp516gBoO40nwoVkuS8iEVz+YZSKdItaDcA
         LMGwf9OTWgQgwZGUC6EDs8RQtInP8PPtQqqmBD/S63NiCkDI5ZmWIj5cZ28YoGPLEFRs
         s/ISTSt83aqqZu7IqoLUIVhy4Dp4SGnQuLxIOnJUWxaEjaQe2SCTbPJEv4FuIh2rCD9r
         AdpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       arc=pass (i=1 spf=pass spfdomain=starfivetech.com dkim=pass dkdomain=starfivetech.com dmarc=pass fromdomain=starfivetech.com);
       spf=pass (google.com: domain of jiajie.ho@starfivetech.com designates 2406:e500:4440:2::717 as permitted sender) smtp.mailfrom=jiajie.ho@starfivetech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748410757; x=1749015557; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6dZQyKGXOWR9nY9DxPA1lyjU9vygx9YyZNcpXSgVYf8=;
        b=rlD29/cVqRgdNwhqdQ9YP4lLYTi0sJASEW7RsbECwrmp223dSsmbUcd9LILAnaIiFj
         /WH/Mj2jO5BWlDOhl/ezrfXOKLyBLKllFIW+fjTXnWxVIxG5V1Rdhpd0mVa/JtEA212Q
         ZiXzJMu7T51DZy6bTvheGVyNGigpCUtwSPpe+I5s8dqe0ff/jgLnq6iEWUtiDlM9Q9rZ
         A2mP4NY/r4+rUVbiSsp1t0qKTEK88yUf3g/f//fdQfhxGG6OXxAIQw44MbP++VVWgmvM
         7lsRl+rLTnGAKdZRqJWmdNFzUY0UOUUSSo4zolw1uygulZn6lTwDQTHDouXKZ22s0xdM
         x1xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748410757; x=1749015557;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6dZQyKGXOWR9nY9DxPA1lyjU9vygx9YyZNcpXSgVYf8=;
        b=n7w6C+RIYuAl5kSDCx3Tqwca13TbqygdvJBqjIvEKvF1/2e6n8iRjgU31pPifVkHdE
         Gn3VKvlDaa4T9PbaHpWsw6GGFpudE7TRCiKq7ODE17OkTKfuvQ7NziE6TPm2lwNrwgqg
         CHmzPOGD6pnFY6CJa+LG0lIsZZfqxUt0hdYuCzOp3s247ruCnr82BsJx5HKtZxj3Kf51
         aAS94RZYCCR4LzQ1XvAWdGmF1m4dNuNDT4cVwFlLI9N9yFsP81GSM+d/QZnWdLD7/riZ
         /5scp82XEJk0SPLHvJF8XYZ4u0A9Sx1UggfYdel3QB9O0Peq+RWibhAS0eBU59CC96xZ
         eeGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVBudCEMSPKZ5yJrtqSmvQqv2Up8V2IYQHgf0mDvXYlSiRFhnPMBw/fAY90mcTqIPYJSTQoCQ==@lfdr.de
X-Gm-Message-State: AOJu0YxZ0+6AG71KCZwGrT5jBSf9sC4+Zmmb60+WmRIITYcQywJlqF6k
	LvIbrzazoDupREXVNUrQun552N4s/ysuHZiDUudsWMngk/5h2HDBbGs0
X-Google-Smtp-Source: AGHT+IGNiOFOVAgHxB4D/shjUapOrPosoXbt/tJExap4jFhVlT/f20Ylr4qEneiu+9OZAh5epF+6Vg==
X-Received: by 2002:a05:6820:4d02:b0:60b:c9a6:1d3d with SMTP id 006d021491bc7-60bd9b36207mr394632eaf.4.1748410756868;
        Tue, 27 May 2025 22:39:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZem9pjr8vVDGpNuH7ZMEzaklaDs9Fsr2nOTn0tfMEMn9Q==
Received: by 2002:a4a:e219:0:b0:608:3554:1a64 with SMTP id 006d021491bc7-60b9f4e9bfcls1347394eaf.0.-pod-prod-01-us;
 Tue, 27 May 2025 22:39:15 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXGiIufTmLC2E4k2CDA0pPFanv/SJ/1uRTSTjpEnqCBRZ7J5rA8Q3HaPFNjSR7Ixmq7lrD0df3SzdQ=@googlegroups.com
X-Received: by 2002:a05:6830:6303:b0:72b:84ab:b1ad with SMTP id 46e09a7af769-735a14f1efdmr607939a34.1.1748410755205;
        Tue, 27 May 2025 22:39:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748410755; cv=pass;
        d=google.com; s=arc-20240605;
        b=CC2J0xzbVF8P3KtiOtktID0182PlwDbfRra19ct7PYyNROa1php56Uibm3UBzFQCpY
         iy02jefkICcFTmuPCpISsm7z3X2HaW5+kwA+F3pzFAN5gUkm58hqcK/8kNNVvBAdc1u+
         b+TTs1ryaE8wjClTRRuXnrnyqcEMuvr6dvVEgnFYHgsXpohZTnu2HtqdKTKvgeKtyxZ4
         wDMb41m6ciAeNPYAeu7oSvev6jqKHP9pv2lCBXzV+k+1K5EMC4iBHiFlf/OCUwH7Pf2X
         haE2KYBm3iNxXIplLBP/vtx80G/EHna2aZ7PBJsD71HmRjFkDTSOxvpukXrXW1wgtr8h
         w94Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=WP2bed6KYhDQM4Gwj5U8y2Vuscv4EwD2xZpPlSeTXVw=;
        fh=r78gbVE8L1R8na/AFmsKCLbTuxu1of3zc8uL8ZhQV+I=;
        b=gj9L+cZ7z6J1BNv4PZtgJ1BwNQwEZR+UKC5kMYOMWUfdGh7+3APu+myoQyyi6RnV52
         pB/QNLm8flvjIxocqtgzf7Y5Grm5lnN0+iomlNtTIIwBldDjJYaI0cXVBdgGSun2LoCW
         4yqF95g6oOB0DQWMZadkgs7XK9UcFe3Wm+edqwOhxl0VVoryCcyNfTXGaN6LdqzzF//t
         acKejd7MxazDfhw5OuHZ1RAPfRn1aKcg3qOnRji/RtHpYkTX03m4SiDgqsvI38jiAGWL
         Wtq0LWV49rCHx0bXH8yQ5WH53X4k4jc5eHFYPyYn65AwvW8cxW1i7JfcFQS/aNoJPIMs
         tKWg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       arc=pass (i=1 spf=pass spfdomain=starfivetech.com dkim=pass dkdomain=starfivetech.com dmarc=pass fromdomain=starfivetech.com);
       spf=pass (google.com: domain of jiajie.ho@starfivetech.com designates 2406:e500:4440:2::717 as permitted sender) smtp.mailfrom=jiajie.ho@starfivetech.com
Received: from CHN02-BJS-obe.outbound.protection.partner.outlook.cn (mail-bjschn02on20717.outbound.protection.partner.outlook.cn. [2406:e500:4440:2::717])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-735a1ca0ce6si19166a34.4.2025.05.27.22.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 May 2025 22:39:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of jiajie.ho@starfivetech.com designates 2406:e500:4440:2::717 as permitted sender) client-ip=2406:e500:4440:2::717;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=X/dV9mN2XNBkMP0sb0kGFB7YASIV3aRQm3DV8R1qNuFNM3wa4Z2fcMvBMDsQrYn0BMr0EBMcIUC6tpJVkHONMAD35vkF2IebvnmXNUcXup8OhXmZ643ANr1hJBXWN8kbjLZNfhwBijMJNckOJnhTl4YqbrbPtEBbZm3WuTaM/yRsZka1XV5MzrTEaQDy0eM5u/w7enFsaeEPchmak/gz3sPvd4smM3Vo0sfDBOAY5cPVo319Ju3AT4qliV9/ve2g5dQTBusumun2phQvEg90gjOzVUWbUHlN2rb/50kNf/BM0vScaNCcCHNgqAeVSVK15JHygoFI+iHc4CSOs/JCRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=WP2bed6KYhDQM4Gwj5U8y2Vuscv4EwD2xZpPlSeTXVw=;
 b=HvBYCDv2ZpCjOHhtUt58dKtk0v8faFIX9Yzono/djX+Y1DVJ5wi7W0wXlpZPZ/6s/xtpjIjg3Tr77S+i2nb/H2+6k3cL4IJ1Fb0KbjnVW07aV5EXaU+wKsPYW8awY1pH1VYG/BBak5zUFS3ukXsBnnIu04J6dPw0aTFz6g2zDMVe31Yp5cJSp768wK5EbLlcF3sQCWs0AjJwyxJN918J7zUvvjxqfQU0mDZ2DXeBumjR8OEGG/Nn0bc6nh+1tH5rlZ+LPUX1zrY60mFp+nNeBeZGMCs/lwHKi/Lwbjf5rhdrQ212oqpqH1PId7lqzadpYS70ZQgkXHZp818ZcJItQA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=starfivetech.com; dmarc=pass action=none
 header.from=starfivetech.com; dkim=pass header.d=starfivetech.com; arc=none
Received: from NT0PR01MB1182.CHNPR01.prod.partner.outlook.cn
 (2406:e500:c510:10::10) by NT0PR01MB1006.CHNPR01.prod.partner.outlook.cn
 (2406:e500:c510:7::5) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8769.29; Wed, 28 May
 2025 05:38:37 +0000
Received: from NT0PR01MB1182.CHNPR01.prod.partner.outlook.cn
 ([fe80::f92e:ed2b:961a:ffca]) by
 NT0PR01MB1182.CHNPR01.prod.partner.outlook.cn ([fe80::f92e:ed2b:961a:ffca%4])
 with mapi id 15.20.8769.025; Wed, 28 May 2025 05:38:37 +0000
From: JiaJie Ho <jiajie.ho@starfivetech.com>
To: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
CC: "llvm@lists.linux.dev" <llvm@lists.linux.dev>, Catalin Marinas
	<catalin.marinas@arm.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v2 0/9] kasan: RISC-V support for KASAN_SW_TAGS using
 pointer masking
Thread-Topic: [PATCH v2 0/9] kasan: RISC-V support for KASAN_SW_TAGS using
 pointer masking
Thread-Index: AQHbz5LCggCRyeDhFUyVwdwWhSEppQ==
Date: Wed, 28 May 2025 05:38:37 +0000
Message-ID: <46458788-54e1-4b4e-b7ef-852d9fb09ca6@starfivetech.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: NT0PR01MB1182:EE_|NT0PR01MB1006:EE_
x-ms-office365-filtering-correlation-id: 9957ff34-53f5-4b73-4ecf-08dd9da9e550
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;ARA:13230040|366016|1800799024|41320700013|7416014|38070700018;
x-microsoft-antispam-message-info: Xc3KyDUF/tpXGwQVYwbX9utWh6W1HksN6qW51B02Yj/8Fp5nakSLLd5G4+bA20CN13m1POe0bmDgZ2zr9+XKft5yuWyfef2PN/foLOY6t5H7OrPlEYdEO8s6F5juldP+QXKf0EChJ32L6ND1MY6BfN0CkrGKQ1wUWdpxKLPFowWpjI7iZ9u6IWi9F7QRVHVzpthHx5nO9afTZ5dZqHHB0VFL6Jn2gd2mYz47RGGf3JCXBCTrXrCms+CRhYuTAXvqXlChsk3lsc9HQ6pL9nVGoCO/2jZUi/evf+9QuJmL+YJU31O4KBCrRWHxC4JzZFXmZc3w8o7d15joj0ZBOGrmwvLWBYVl8qMhiqBRyhlZGJuVX4ZzFIl2RBJT60lftvkmM/5j8vcP5geeKvUAofm5kFFg4Z/g3t/ul6k8K99T+xPGb7B8Hccvr7mGLDU5aoRQJr3ftrcAq4bKt150VhzRtKLYra7CL4uyp55r/xDeY71JFeA9fB6m5lGEvr635rmZ63OqQ2h6UBDX9KSQXmuZ7WuSSJ/iehUzF0eeCnzjUzVxtSF8OED3Zjl0EtWSsi8Sarw2jcYSB4Uw2SAMtLIBZw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:zh-cn;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:NT0PR01MB1182.CHNPR01.prod.partner.outlook.cn;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(41320700013)(7416014)(38070700018);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?Qm9sMUZvMldmZkNXOGJ0N2pXVXcyMy83N3BBZTRITmUwUlZqZVdXaUJ2RzBp?=
 =?utf-8?B?WDNUclMwMVd3TC8wa1Nja0k1UFIzbXkyRWVybzIzUFBLSmx3ekxpT0I0VUcw?=
 =?utf-8?B?d3hHNW1UMUo4eGRRQlJyYXdHWWNJOEdJOXhvODZBeXVNeDZIZFEzRW92VVRU?=
 =?utf-8?B?UUVBOWlCQ05HSDBheUM1K1pvZVNCc2Vhd25Nb2xwaGVZdGU4QzRVcFVjbXVC?=
 =?utf-8?B?S1hWNGFyd3ZiWmVyNlQrZ3ByYk51SVBDa0VoQ3VheVZRak9BZ3psWVJFc200?=
 =?utf-8?B?Q24zT3Mvc2QvL3diWUdQWW9ocDhicVpDeTI1dTFzbWdTY0k1WVF5aDF1YjZ3?=
 =?utf-8?B?cUNJQXVFMlhaVmtjMThRT3VnYVh3OHU4NURPR29TbGcreDY1SU1IR2V4VnJS?=
 =?utf-8?B?d0o1TVFkaXd5OFRlZWEvS0l5OEpUZnVrbEpqRWRMYnlLOHRBZWZuZUl4SVli?=
 =?utf-8?B?dXkzc2Nqb1dHbUdVeDBmWUN6OVRTTjJXZVBzbmxxZ1FSQzhDRnhFNE41Szdw?=
 =?utf-8?B?TXNVTjJVYmZzaUtvUlg0MlhLUFphVU50dWl4TWJSWHc2Uk5Tb0dxV2cwRjRH?=
 =?utf-8?B?NzIvRG9KTEh3cnBHd3pXWHByY2JjQmtBaVE4YXN0WHZjWGIyWTZQbkMxSnVi?=
 =?utf-8?B?RHdGRSs2QW1mdDhMYlZVR2grM3NIeER2ZGlBSGFQVy9qLzRzR2hHWFJIVmc5?=
 =?utf-8?B?OWNzMVpzSTZqcXVmazFvbG5xY3hxTlVMODFtY2JCZ3hQRlp3Y1NiMG9JVW9Z?=
 =?utf-8?B?R2xIQmhBS2F5Wit2T0ZNSFZQUVBMK0dBcHZ2M25qRnkwSEhldkh1a3E0SXRV?=
 =?utf-8?B?dG9VdlNDOUg4U2picHlKZmxuY09BSDE5a2ttNTB3dFh5bHNqUjZIUmRRemE1?=
 =?utf-8?B?cjdLZStKelduYnlVZi9WTjMzNlJ6VzdpT1pISVFjUjZ6MEtrRjB2aDhaK2xw?=
 =?utf-8?B?d1VNM2s3eGtFby80QWdyM29paUxwNFg3d0RabVMvUlpsREI2aEVmY3pCZlFn?=
 =?utf-8?B?SjM3Q0JxZGRhMHdTZlpYK0VYUlgzaG5vYytXU0Z4OXdyaFhGN1hESyt2aG9U?=
 =?utf-8?B?R2V6cDdrK1RxWFd6QVQ2SDB2S0w3M0lRR1h5TDA3MzZRT295VXFXM0lKblh4?=
 =?utf-8?B?UThyQ21RclYwRGJOMTRrWktIWDR1NlZ4cVY1dnBtOEZjV01QSExKQzdERHpC?=
 =?utf-8?B?aGpIcUVtMG1IOURtNFR0MTlaWXZKclc5VWZwQnlNLzZhVVJabWsvc1g3NWQ4?=
 =?utf-8?B?ZDNCYzRmUmp5UTNLaGVjVU5WSWR6RUVtMmtTUmZxSHRmL0dRa2RRcGZ6NXBy?=
 =?utf-8?B?MHNERzU1eGhyRisrU0VaQks4YUVNZjRCa3ZtQnF6cHpPQmMyaTRCbGczZzd1?=
 =?utf-8?B?VHJQTFhHTTlRRDZmeVgybFZRd0ExcGFPeUtLaCtRT1J1OUt2OVRNTWpVTHhP?=
 =?utf-8?B?N0pzU1J5MVdLNm9iTk1HYTMrclJhZ1R6SG81dDBYYytoSWxZU1JnanU5UHpq?=
 =?utf-8?B?Z3gzWGZNNnUvZGVtVW9VUFdUK1dzNlBML0dQT0FFc2pMWGF2RkRaSFlLdXFZ?=
 =?utf-8?B?Zmp5N1FEeHZ2WFVOMHBacTRHM05sQktESysrK2sxNlVLSFJ3TWg3UTk2Q05k?=
 =?utf-8?B?WFdaMjJ5ampnR0tQTk92dkhZc3FNbFEwZDZLK3l2STlUUi9UMTVnL1VsMEpV?=
 =?utf-8?B?cEY5bkR0eURhSHJDSzFHMzZLQUcybWhpTDNhVU1HbVJWWHFyL05PSmE2VG1D?=
 =?utf-8?B?RGJxZmFZTTdUdytkT2ZBdTRlN2dIdkIrcWxrL0xXY21Eb0NtYmdYNE1XcXRq?=
 =?utf-8?B?YmdkcmJXaUtqZEVpWDNUcnhndDl1amE5bnlyRzZYRmc5c3gvN1ZYOWs2R3g4?=
 =?utf-8?B?LzJvL2kxNVlzakhxanhBZk9ZaDRNalVZVUZ5NWN6ZjhXUEh1MiszY1VJc1NK?=
 =?utf-8?B?TC9TRitxamhRR083TFdNR094V04xVTJ6dVFYdGFVRCtsSUMyajZlTnU0Mi9q?=
 =?utf-8?B?bEJuQTlLNndvRGdjVDkvU09sM1RITmg5U0M4c1NiQ010aHdHVE1nYnpsWEZk?=
 =?utf-8?B?ZC9lK2h6eFFzUnBiczVSOW9POVYzdXJOSkJZY3NLK3pQVC9WZCtPM0ZzajM3?=
 =?utf-8?Q?GpaxMWjuPba/J7wAlAsG6nRft?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <574075A7DDAB034190582EC40F87D767@CHNPR01.prod.partner.outlook.cn>
MIME-Version: 1.0
X-OriginatorOrg: starfivetech.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: NT0PR01MB1182.CHNPR01.prod.partner.outlook.cn
X-MS-Exchange-CrossTenant-Network-Message-Id: 9957ff34-53f5-4b73-4ecf-08dd9da9e550
X-MS-Exchange-CrossTenant-originalarrivaltime: 28 May 2025 05:38:37.8514
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 06fe3fa3-1221-43d3-861b-5a4ee687a85c
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: QtPkQxX8YtA2y1vlaU7nlBs7kcORqwOpJo56CIZ9ViIXM7daOKrk5XN/ruAN6js0OqY0auEOx/ket3hZstydjYonafBGUV8TT5kI9jz6Fko=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: NT0PR01MB1006
X-Original-Sender: jiajie.ho@starfivetech.com
X-Original-Authentication-Results: gmr-mx.google.com;       arc=pass (i=1
 spf=pass spfdomain=starfivetech.com dkim=pass dkdomain=starfivetech.com
 dmarc=pass fromdomain=starfivetech.com);       spf=pass (google.com: domain
 of jiajie.ho@starfivetech.com designates 2406:e500:4440:2::717 as permitted
 sender) smtp.mailfrom=jiajie.ho@starfivetech.com
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

On 22/10/2024 9:57 am, Samuel Holland wrote:
> This series implements support for software tag-based KASAN using the
> RISC-V pointer masking extension[1], which supports 7 and/or 16-bit
> tags. This implementation uses 7-bit tags, so it is compatible with
> either hardware mode. Patch 4 adds supports for KASAN_SW_TAGS with tag
> widths other than 8 bits.
> 
> Pointer masking is an optional ISA extension, and it must be enabled
> using an SBI call to firmware on each CPU. If the SBI call fails on the
> boot CPU, KASAN is globally disabled. Patch 2 adds support for boot-time
> disabling of KASAN_SW_TAGS, and patch 3 adds support for runtime control
> of stack tagging.
> 
> Patch 1 is an optimization that could be applied separately. It is
> included here because it affects the selection of KASAN_SHADOW_OFFSET.
> 
> This implementation currently passes the KASAN KUnit test suite:
> 
>   # kasan: pass:64 fail:0 skip:9 total:73
>   # Totals: pass:64 fail:0 skip:9 total:73
>   ok 1 kasan
> 
> One workaround is required to pass the vmalloc_percpu test. I have to
> shrink the initial percpu area to force the use of a KASAN-tagged percpu
> area in the test (depending on .config, this workaround is also needed
> on arm64 without this series applied, so it is not a new issue):
> 
> masking, the kernel still boots successfully:
> 
>   kasan: test: Can't run KASAN tests with KASAN disabled
>       # kasan:     # failed to initialize (-1)
>   not ok 1 kasan
> 
> This series can be tested by applying patch series to LLVM[2] and
> QEMU[3], and using the master branch of OpenSBI[4].
> 
> [1]: https://github.com/riscv/riscv-j-extension/raw/d70011dde6c2/zjpm-spec.pdf
> [2]: https://github.com/SiFiveHolland/llvm-project/commits/up/riscv64-kernel-hwasan
> [3]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
> [4]: https://github.com/riscv-software-src/opensbi/commit/1cb234b1c9ed
> 

Hi Samuel,

I noticed vector instructions failing with sw tag-based kasan enabled.
E.g. running the rvv_memcpy example from
https://github.com/riscv-non-isa/rvv-intrinsic-doc/tree/main

Error log:
# ./rvv_memcpy.elf
[  354.145633] Unable to handle kernel paging request at virtual address ff7ac00001078410
[  354.146334] Oops [#6]
[  354.146511] Modules linked in:
[  354.146791] CPU: 2 UID: 0 PID: 134 Comm: rvv_memcpy.elf Tainted: G      D            6.12.19-00023-g6ec23f450118-dirty #200
[  354.147771] Tainted: [D]=DIE
[  354.148350] Hardware name: riscv-virtio,qemu (DT)
[  354.148888] epc : arch_exit_to_user_mode_prepare+0x32/0x80
[  354.149334]  ra : irqentry_exit_to_user_mode+0x1e/0x9a
[  354.149659] epc : ffffffff801b8836 ra : ffffffff8213db8c sp : ff200000007b7e90
[  354.150173]  gp : ffffffff82c2bbc8 tp : 9560000080c56600 t0 : 0000000000000001
[  354.150709]  t1 : fef0001000000000 t2 : 9560000080c56600 s0 : ff200000007b7ea0
[  354.151082]  s1 : ff200000007b7ee0 a0 : ff200000007b7ee0 a1 : 9560000080c56dff
[  354.151658]  a2 : bd60000083c20800 a3 : 0000000000000600 a4 : 0000000000000100
[  354.153212]  a5 : fff5ffff080c5661 a6 : fff60000080c5660 a7 : fff5ffff080c5660
[  354.154668]  s2 : 0000000000000001 s3 : 00000000c22026f3 s4 : 0000000000000002
[  354.158327]  s5 : 00007fffaac623e0 s6 : 000055555eec6de0 s7 : 00007fffaac8fcb0
[  354.159481]  s8 : 00007fffaac90008 s9 : 0000000000000000 s10: 00005555844b1bd4
[  354.162673]  s11: 00005555844b1b48 t3 : 000000000000004a t4 : 408a03c3cac3a788
[  354.164378]  t5 : 40659b6a3963f6d4 t6 : 4083e9c60c55738c
[  354.165117] status: 8000000200000700 badaddr: ff7ac00001078410 cause: 000000000000000d
[  354.166137] [<ffffffff801b8836>] arch_exit_to_user_mode_prepare+0x32/0x80
[  354.167201] [<ffffffff8213db8c>] irqentry_exit_to_user_mode+0x1e/0x9a
[  354.169119] [<ffffffff8213d4cc>] do_trap_insn_illegal+0x5a/0x92
[  354.171989] [<ffffffff82156bf8>] handle_exception+0x148/0x156
[  354.174056] Code: 0593 7ff2 b603 4615 0693 6000 a073 1006 7757 0c30 (0007) 0206
[  354.175524] ---[ end trace 0000000000000000 ]---
[  354.177344] note: rvv_memcpy.elf[134] exited with irqs disabled
Segmentation fault

Thanks
Jia Jie

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/46458788-54e1-4b4e-b7ef-852d9fb09ca6%40starfivetech.com.
