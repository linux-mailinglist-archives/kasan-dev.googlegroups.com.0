Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBHHX7TCAMGQEUNPRJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C98D6B280E7
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 15:52:34 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70a92820fd0sf19824656d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 06:52:34 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755265948; cv=pass;
        d=google.com; s=arc-20240605;
        b=NK4GKN1c1CCvhnhrsL27W+BldSNpQXa2Z3F6GVgSzB2/LAScHspVm3zQqfbs7p6/kC
         6rwcfmImacY5THW/Ohducvd5OyQ/CJ9pKR7czQUSbz2H+5ymQ0uF+pz1odHzfWD9X2OC
         cix0004HgouHnd9Stdqq80uq5rFu2QJniaGmL+OD3UBWo1CXbm06aXHfqD3WxQqmpsup
         JKsBSjZVFGjjYDoNceq/aFYR6LYMYDDuP0hMEBvshyJySjLUMpbTOgRLs3Q+LxOnn3w6
         BmmCoKKJJUoIzvvUnWAIS5CDQ7DjodGBjT5oKhdHTN+RtxtYVFRLzbLY9aHouf7empOq
         BRrA==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=g0bBIn51w3MfV4GGvoe4nm9tNXpFRxo4U2ezjbSIx04=;
        fh=cz3O0Ld0eeTcyBKi2sgcPpZ9PyIsKbQq9hY97uGJe34=;
        b=J3TpK7+3NTEiw9TNaS82m84CyHp1g9JmBNaF6H75orKOUH+AoJwx/N6MdtEFDggYga
         G0MtKfnvOabCYsmPiiuhTU+FhZN//VIn2MpWK3k4/z6UUkzRcZogFvHl0BDi5PwZo1IN
         w/F2z7lFN5TGhMEBvt84Q7Vptk7J2nZQ/K3ViiNCDDbQLPIfRSigyzv/fBjGHTO7HFoU
         y8Sd086ACTeQW6K/D3mP1DY28wbU6vAnxoxrGA6Qj648vJ65rdCSnMSIXAbW04Ue8y/O
         tv/9u9sMXYOaX+Z9vHJ+xCHLW0k5mhuQKnSUYMqAkaCYOMgmBMiz9sa5BLiAKd2M5rlp
         TAoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755265948; x=1755870748; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=g0bBIn51w3MfV4GGvoe4nm9tNXpFRxo4U2ezjbSIx04=;
        b=KzNc9n+JpVbT+GYYgWHsR/4obG6Krq0o3d4Hiax1ifFp4jW7iDc783ocg9cJYJtMUO
         WnnpPu/g0butwExqtIjSTZiVhpbkrlBKAMTXtvx5K0zw39ZF2uRzQuZzYFqP2TBw01+P
         LFrcdCcQTJtdjO/yiVfzeqRdKDB0JGqSixyArOqaA23YP0y7PMRveZFw/R6/PiUnq6jP
         g5Ck9VMhqmaDoqFp9uq5wPYGVQtIF6tzVOlNOw3H/u3jMmYX/izZQFqd6ixiNQMpV5TO
         B2ykANx3vj0s1MzwCbTkk6l57u+GogSjMu2VK8u5SSTlF1fHKKQAbdbU+qC/tMTVyLNN
         Pwug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755265948; x=1755870748;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g0bBIn51w3MfV4GGvoe4nm9tNXpFRxo4U2ezjbSIx04=;
        b=AKDIbHU75B36sVfTlnvCAP7RTtRc261Qsd0fXFv7voEK9n2vJz1eqqL+ehmGMAV1QV
         edeg6ZTAcTmg8/i8wY3Kfh2jFP/0/bEu6nlWFojV45o9WG0QFu36vmxEADKt/fxOP/83
         FnqBgLo7IUvHdCw724cxgtnAXA0W5RapTat5BxgL868Y2vMR41G+53IB5CPOhesQtDfl
         5OWCY9QDZjZJ0XY0HycTeb13uHuCwEa4nyyyqPWJI3i35JaNFqiD9koXOeWwSXYYOjpx
         JSOvJUqjOJNOcVts/iiiwbBh18m6+tcnWo/tR7E+u+P7i+DTBUSt60zBHaOw84dVEYow
         a6yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXoUVDHHZDaUccbwkhsFhK45t6ejqKwPMjIArLImGI/MVe4O0JS4FESa7+pksVKkoeZ25A9ug==@lfdr.de
X-Gm-Message-State: AOJu0YzkudeH9aykd9uKYJevt0Lw8ZZ+PSKhoHkeEJ84CioqM1L2Lhoi
	B+wtvm30EsumK3yCBAyLzaNby41jmOutmjC/re+aVz9VfuhZvV5+L79Z
X-Google-Smtp-Source: AGHT+IFRc+7hoPp1jUkTAufsm0tL8UbbA+cADzmzAXL/tQWmtFtEa81Crk0aup/K2jRtDAcv3hYskw==
X-Received: by 2002:a05:6214:e66:b0:707:458a:a1d2 with SMTP id 6a1803df08f44-70ba7a8bedcmr18989206d6.8.1755265948319;
        Fri, 15 Aug 2025 06:52:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZew5VhTSoKAa6jSt3qlNwYsieMfeMMgk0Rt1tjghdJUTQ==
Received: by 2002:a05:6214:d6a:b0:6f8:b2f3:dfb9 with SMTP id
 6a1803df08f44-70ab79eefdbls28987866d6.2.-pod-prod-08-us; Fri, 15 Aug 2025
 06:52:27 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWo4Y8VJKeToZLRM56QgTUw2NNpwD2GTTwvn1qLK4+/W/s9fSvUGVbfxxwCAhXFmDW3m9SI3MqdhTI=@googlegroups.com
X-Received: by 2002:ad4:5bac:0:b0:709:e326:6ab1 with SMTP id 6a1803df08f44-70ba7c63aa3mr23565036d6.39.1755265947375;
        Fri, 15 Aug 2025 06:52:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755265947; cv=pass;
        d=google.com; s=arc-20240605;
        b=jcJkmCMOZQxOPjASM524vrsR9jMmUUj/k7CCaKoWElsZZPGHvjBm6ld7k2YDaJ8rgO
         iDWSLLUgLdR9XBrRMi/YY3wOHZOJoZ21dsAIZDCw2WMZ3z7xmZ6HufHmesMiRVBXPJ1p
         fkGVyTD7E+A88HXRVTLhAFftVywC5R2R+r4HV49vNrJOSLjP0kj+YAbeAwQWNu0vd2HW
         w3oXBDHUmL2KnzHlLbPjJMBUZ4D0VwFfqjhrJlIDOShwwVnahFu/wzByI481ZFqE7WMR
         QjE9Vqz+7YSPYYC13FRwOqP7ScWRnmlaf9Q/q+2PJyTyzS6tYOUg8hcIKIJscr8OTOpK
         IEgQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=KCRhv/I68s4f62iqEFDB0hO6yTgdfs8DgQ+YMwzm/Ps=;
        fh=sy1/T+hZ0mz5g5/9lgWaTur7TgGZ2Tl7HUiVtGJX82k=;
        b=aKp94qgK4uFbi5OmeSRC/JGSYnOeDh4o2h9Q0srCh7k9VRMRliCO3MVoHcgcRmJgvF
         4jshmwd6BxoiU0UuLLLK2kI9+nNwsQrRimdeXNDbb9/h13FKs8f+nvTtT0cBxwRK9oCz
         BUbjkpEvkkYNbvg6E2Sd0irRoP/WJZnnwRgK5BJW42dZaUVc1yIfPB/WwxjT8eFaPVB2
         EknFFvwRdaRsjD/+nXRREqr+ONI8Brb7/zw/E5fg1mHXtA5x0Y3A3OHNLrW95Wkkm6U9
         un14Q1f8/xE1OkFkizLrf1/+JmT37T6kWn9fcotd4oPBUftZJpngvDvac2R448ICPZeU
         1cfA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from GVXPR05CU001.outbound.protection.outlook.com (mail-swedencentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c202::7])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba91e59e2si428536d6.5.2025.08.15.06.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 06:52:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender) client-ip=2a01:111:f403:c202::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=fH7MOu+iwXh7k3qGfmMfAx4cIWUnCy2smeTdC7SsCFUvEAJZnEJ8FN8gcd0J87diMeEdDLDEJUskWX1DZ1mz7C5IZ9WJOl3Zfl293j52wfi35SU02AB5L57iC8Ns8bBkGHknbH965OiCusz2EZd2CfwGmh03lgB8recuK7FyfGz86ykMw/GzDLNOonqa4jQvGFPIBLLFxUxzNn+h6KVtN0izN3kypwypmoilzb4iiKjL0vTWlLl0mAQnBumaakFu7ju9UKUYBiWMewgb25zxw1IZwAHeo3cGFVSkHmt6q9I9KQ8d96r++yn+eirSOl/drVeHg1VCmJEWQwKqQXw4gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=KCRhv/I68s4f62iqEFDB0hO6yTgdfs8DgQ+YMwzm/Ps=;
 b=FxXRH4uwTOWzFk7wFmj/JF+47RA7472UBkQXbIpuA7v+ZnPq4ejfapeej07cV+paVRiqCZCGIxAsqiE/TEVjZsUHsgjwPuHIHd5SdSin440kMUPk0w7okGP0YVxHPM0fGD4yahIj8PHoHHk3vDp5VBY22OduRQBMUhKjbDR7k9K6YYlRCqlU+apRuttcVA+kxPWjzx62Kh2ar/0IPfjowRsqBEALORteALyovj4p6QXtSv7zmFavQ7+qYXtZJQNoNfiEKxpAL9hg+HE3FMO1mOq41LLrXXrWcrK6lOzgrkfjESgr6JJ1Ne5LiUXiz+zNgUcnxTTj6CfUO26ARMXZLQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AM9P192CA0005.EURP192.PROD.OUTLOOK.COM (2603:10a6:20b:21d::10)
 by AM8PR08MB5604.eurprd08.prod.outlook.com (2603:10a6:20b:1d5::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.18; Fri, 15 Aug
 2025 13:52:22 +0000
Received: from AMS1EPF00000041.eurprd04.prod.outlook.com
 (2603:10a6:20b:21d:cafe::ec) by AM9P192CA0005.outlook.office365.com
 (2603:10a6:20b:21d::10) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.18 via Frontend Transport; Fri,
 15 Aug 2025 13:52:22 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AMS1EPF00000041.mail.protection.outlook.com (10.167.16.38) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Fri, 15 Aug 2025 13:52:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SBxmEKYS8OeQm2X/f+dRI71HytlQuc3HBepbnrRT4YX67aExfkkq7k+EU77U3qj5IWAMNw/iGrrU3C1r3gCC5qxE7LgeOQr1iys2Du7VPREXVIjiCoMz5oh3N7ICBj+LrhzAJ9ynPFjwzNkOCgAkCnAVR8QSD1TmcnHwNNHoBdqF2IckUQWxk3v3BXkVuycRVoYGSEbTzkV0e+GPx/KlzYJ5Bo/iLz6H7wWBls32c7fM4FDrTI2lniJNAQezv3rRmhnfw/WwMC8NKrA/ZEcJy0J4bo6A1M4hCV8sjeRrY569vjJBYSDZTSJcjhbBWahc+4wt1r79Oft4SE/01bTPYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=KCRhv/I68s4f62iqEFDB0hO6yTgdfs8DgQ+YMwzm/Ps=;
 b=yq++zZsdO0/tGjvGRxAM8Q0x2KhGEUbfza45SBJ62H5lkZgyJtHEpHjD6d02XpCBikir14WrHKCdxmNNtCt1SNSPdmDy97vb1yH7PFUZ7s0uHVfY5a37DMi96SJAShj55MMJlqyGMstkWL9p8fUqRiWPT4gc0g9gWICJ9jUgLI29do2w3QsqUW3hxrh11MHxUD/bF+treuKFa8fKd/hMLfW+B7BZ3hhrNEs2961YH5MLSONhumoiTJ6uHcYTkw4zR40zzg1OEtbrvu9CFPXWYySzKwYxS7wK0WI2glTj+EAl0zFs6NR7tWQM5iYPAJapmyOfC5qmazcdQDuCebviCQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by GV1PR08MB11148.eurprd08.prod.outlook.com
 (2603:10a6:150:1f4::19) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.18; Fri, 15 Aug
 2025 13:51:48 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.014; Fri, 15 Aug 2025
 13:51:48 +0000
Date: Fri, 15 Aug 2025 14:51:45 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
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
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
Message-ID: <aJ87cZC3Cy3JJplT@e129823.arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <aJ8WTyRJVznC9v4K@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aJ8WTyRJVznC9v4K@arm.com>
X-ClientProxiedBy: LO0P265CA0003.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:355::12) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|GV1PR08MB11148:EE_|AMS1EPF00000041:EE_|AM8PR08MB5604:EE_
X-MS-Office365-Filtering-Correlation-Id: 4d954e59-041c-4523-915f-08dddc02f496
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?enNsclhUSjl4UFNHcU1mTG5wVGRIUzZFMEpFdFFDb01MRGhibG9rN01IVHA5?=
 =?utf-8?B?dFdUaGdqV0hxVVR4d3psMW5Xdy9qMDFUZjg1Y1JMMTY4bUEycmtGYzV3alZI?=
 =?utf-8?B?dU9vMWd2ZW9FVk1RcXF1eGRKOVF5V2VDYzdYaUhidFA1dTBGVXlzMWVPMjhD?=
 =?utf-8?B?dVVpMEVpZ2xmUHpNL2Z4N2VnTGZQZGRMTVJCOXdnZmZ0Wng2NENXa013cERm?=
 =?utf-8?B?VlRpeTNhQ1cySnlMWkg5cFpsOVJlOEZoR2dnYVpOWS9Rd0x5bjdsa2Zabkll?=
 =?utf-8?B?YmFFQXpFVFVOcVh6VDlmdHZKUlp6eHVNSDBHZXROYkRybmk1ODByaFAzdm9h?=
 =?utf-8?B?VG8zbEkza1l2V1ZHYnhhWG8rVTkvdnF0Y3VJSDk3VFhuQkNTUGREMWdvb3BY?=
 =?utf-8?B?Z0xCSUlQemRDMXZnZUV1aGoxRzBmekhpN2JkOTBLSThQdnNvcDlVKzRUdmV1?=
 =?utf-8?B?b012VCtRT1M2aHdhbXFmbGdRVUZ2d1dOdXFQeFF3M1JZai96cStJRm9qL2hn?=
 =?utf-8?B?MEtVamNBUmVrN2ovc3ljbjlvMHpVTmg1aXJFdGFCKzczWGJBbHlCbTlpWVlZ?=
 =?utf-8?B?bVMvZlpCM1BvVGFhTFN2VmVFRk5Fdk1xQTM5MDIzTTRFTm85eDVNOUFXTUQz?=
 =?utf-8?B?c0NLTXRZUXBybnBMUlR3d0Z4UHp3eFBkOXQ0NTNFUzZTVDhOUTlKbWlIdmNK?=
 =?utf-8?B?bEZBSHVoK01OdlhyL1ZXaDFNTGJuc2dDTG4vVGlDREEvTCtDUmtrU2hvckhV?=
 =?utf-8?B?RUJtY0dBZCtYQXkrMmx2UFVIZTg3T1Y0K0FJNTB1NDg0dURxNERHNGwzemtG?=
 =?utf-8?B?alpkMUVZWGowSGNEVGN6Um5renFNN0xQZHk1cG5Pa3pCNS9kajlTZWsvd1E1?=
 =?utf-8?B?a1dkVWtwc2dOZTlUbDlRVU80c3JhSkVNbGI3WkkrcEtjd0V2NnRUSUs2QjlH?=
 =?utf-8?B?c2E2UHl1MHRpVHo2WHUxZU1ud0k3aXUzcVpvNThKQkdlemNjbWhiSWpVenZl?=
 =?utf-8?B?dEErOEtrQk1mVTFUNEZ1U1B6YTRpaWcrVGMwemRVdk1qd2lkQmxVR29Uc25N?=
 =?utf-8?B?U1VKNlJ1ekpKR1ZJYlFiYUp4a28wTVZuMnc4SU5IcTFNZmtYSDFMUlE1UmNn?=
 =?utf-8?B?bEhueEhKN1NCMlVLb0t3aEdwY1o1OHZadGord2pZTzRxQy85TEp5MVAraU5J?=
 =?utf-8?B?b2pZa0pnV1FjaEtVM3BvTFMxU1B6NytCQXZaSnd6cHlzTy8wT3dMWFRMN2dX?=
 =?utf-8?B?ZnFXM2UzZVZUTTNydTlXaUsyWk9oRzhSK2JEWXVMR1RkNSs1THpadXRLS1ZB?=
 =?utf-8?B?VWNINVprOHFUcndNNExYa0g5NGxqdG5sSmVKczR3ZzBCczhONFJVK1dUdk0r?=
 =?utf-8?B?bm9zbEIzMmJIVDhEM0owQ2ZtMC85dEo5c2tscDNZSTQ5RHNZMk1HZm81Q2xj?=
 =?utf-8?B?VXh5UE5USS9qaFRINjNNU015UGtHS0VHbjczQ2Vjd1Z1NUhRMlFIQXdjaDRO?=
 =?utf-8?B?aHFsSTJEMXlIOU5BQitPWEMvRTRZR3FGTWdBcTc4aWRGOS9Lbkx2TzZSdGxv?=
 =?utf-8?B?enNhRGNleW1nWC9nSDVITWg2cnlIZUVhRy9jeWlyOHI1S3o3RCtSRjdhdWw1?=
 =?utf-8?B?RVdKdSt3cUZGcmtzWC9ub1c1T2x6cS9WdGVUN2E1VElpeit4cjkwa3NXZFJ0?=
 =?utf-8?B?VmhuRXhEVHZqL0hrMkJ6bi9OenNXaks3M2pvU2xCWVI2Q0FVNHRya01iZ0Jq?=
 =?utf-8?B?cjJJV0YraUk3d1NxakkvQXUxZlJuVk1SS2R3aEQ1clRlV1Q4WDc5Uks2d0Q0?=
 =?utf-8?B?dmV4NjJQNzAycXVIKzJxMEZHSnRMTHdSS2RHQjNQVzhRT3hnaE5HZXdXQ1A4?=
 =?utf-8?B?dVRhZVcrOVBvSDB6NXNnSGlSZkNmdjJHdDU1YW5oMnB5anpwL1NJMXg5Z3Q5?=
 =?utf-8?Q?bx8s58GZ8a8=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV1PR08MB11148
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AMS1EPF00000041.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: d13cd2f1-336a-40e6-a752-08dddc02e112
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|36860700013|82310400026|7416014|14060799003|1800799024|35042699022;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?clRIaUtpdFExVjRNOHBObW1zR0JhZWxCZ3dmNy8wZGpBcG9nVFRtV0NSc1k5?=
 =?utf-8?B?WTdvWVFXWnBhRmQ0eXVmMmtiYTMxSzRBZ3JsN2NxUXBzL2NZSzEvUzdGckx2?=
 =?utf-8?B?Q3M0WTVyeEIzdmREUFJta0JwVlpHWDlUdVk2emp4VVZHWXlBQllnWDRtZmtV?=
 =?utf-8?B?azdlTnBYTnlkbWc3S1ZlRHZ5NXg3b0V5NGY4SlN1bHd6WlUyOUNTbVRVWUto?=
 =?utf-8?B?RTF6QStUZVB5L3NHWmZMK2IwSk02MmgvT1N3T05vb0s1RHBRSnpHTGpaejNG?=
 =?utf-8?B?K0dxRXdoeDZqS0lpbkdEV1RNUElmSm00WUxoMWE1Y1h0L29NS3FOYkRCWERj?=
 =?utf-8?B?SHF6NlNqVHo1aEw5UldRRmV1V0FMYm95Q2J4bTlYdDJnK2lsNmI4eFZTaElK?=
 =?utf-8?B?NzZadHo3OWxMWmtrSUNBUWU5d0k5L05nd25ZdjlyRnR1UWNzYTR4bk9FdG1i?=
 =?utf-8?B?c0xVMTVUSW92cFJTQm1OQmlhdERlYlB2NmhuNFpkUlYvL2ladVBETE5jeDNG?=
 =?utf-8?B?b1ZsZXVZNHNBeE1WeTFLRTZzcFpsR2h1RXZydlByeEE3ZHVzcVRXQUdvQVB3?=
 =?utf-8?B?Ynp4aHpQOW1ua2h3TW5rZG1XclhROFV1WjI2MUxwbk9tVWVlNWNKSVR3UFdi?=
 =?utf-8?B?TmltZ2F3WVkyRzhSaVJvRjg3UUFOZk1SVWRsT1R0RUNGMEx5MmZNOGhxZG90?=
 =?utf-8?B?Z1hxY00rek45Ulg3Qmg4Nmt0SEJDTEJoZ3JLU2drY1BFNzdMUkdNL29EcDBQ?=
 =?utf-8?B?UG5JOHVrMUFFT2pCT3RwRVk2VzlobVhab0VlUmR1UGJnZ1dBemk2TWxPOTdx?=
 =?utf-8?B?aERmT24ra05sTGdQOXRGRExzYkFlOFVGaUNPb2d6enhERmU2V1R4SnlMTXda?=
 =?utf-8?B?amY2WWFIMGpqbWpyOC9mZjlSL0FMdmtrT05lUWRQbHkrQURWM3d2cnNqZlpT?=
 =?utf-8?B?RnVzT0pKYm9pUzU4MUhCYzV0SVNUMytSQmZUWGlpaHg0cDY2WG1MQkxIYmo4?=
 =?utf-8?B?TUlkU3ViT25tL0pSdU02TzBBYURnR1pWcWU4ajFySXBIWmxPWGdCYko0eDg0?=
 =?utf-8?B?aVJVMU5ac0o5VlcxUlBsL3V5eDUzbGswRmxsVXAxUE5UUGc5S2l3T2RRbG5n?=
 =?utf-8?B?akNrTlpzdngwc09LVGt3OGYvdDFPQy9DbVVOTmxaNkFnYzAzbHJTNHdrYjJ4?=
 =?utf-8?B?dEdHeDZlcC96b1RmWmRqR0crMG56ZUZZVkdsWXZyVkZHVWlHK3RYaEJ0ZHlF?=
 =?utf-8?B?a3hRZFFvUUc0azU5TzZDMzlwMlZ3UDduOU1xM3UyM0FlTU96TGJDZkFNaXR6?=
 =?utf-8?B?dVg3QkxGeS9NNGxaQW15ODIvdGp3cDZ1clRIbEgxN2FLSnpLV2Y2OU8wRkx6?=
 =?utf-8?B?d0tHVCtKMVM5RWpaMlBPTVRuZ0xmalpybkxoZFZ0MHIzUHFBZzRpWEc0bW4y?=
 =?utf-8?B?UUpMMHhiM0VXczdMalg5Wi9XRlRtWDI3OUwwcVZ2Rko3eTloaVJXaGd1N3hm?=
 =?utf-8?B?dXdYK0dvUUY5Rks5dnZtTS9ML3NVZEFiZ05nVnpYdGJoTi9QN1lSdndxNEpt?=
 =?utf-8?B?dEt5d1JEUFZBcW1WaXlidE96OU9aSy9nQ3BCbnN0bjFzZjVMSTJTVmFCREd6?=
 =?utf-8?B?c1FBL0czVDlkL1libk1WS05uNXhNOTRGMHg3b0s4MkdqRkYvUlVlNldFUmFi?=
 =?utf-8?B?VlRIYzUvQSt3VUk5WEwydTU3UDJoVGpqYnVIM0p1dHRIMXFON2wrUklaN05H?=
 =?utf-8?B?WTRrN0hGL3RILzF5aTVZV3J5Q2NST2ZKcVAxTDZGcFZtODhwVytQeDNSQllY?=
 =?utf-8?B?Q2Q3SXFFZk16RFJjMEZKZW9TbzJ4V0p4VENScHdzYlNSWll1RHN1SjJRakxU?=
 =?utf-8?B?NUoyY0d6TUNqS2c0THZweGVtdS9pK1AxeTZSS1JjaXFNcjV6SHpBT3ZkRTEx?=
 =?utf-8?B?WStQamloN2szaEJ4bFdwVTRqdm1yMHRvWUNBWkNEZlU0RGRlR0tpVWFnL1Vm?=
 =?utf-8?B?SHFqKzVoajBXaVJJZk5ZbHhVTmZub245Q2lnVGwrT01idmlzTWtJMnpybXJM?=
 =?utf-8?Q?82UWTb?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(376014)(36860700013)(82310400026)(7416014)(14060799003)(1800799024)(35042699022);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Aug 2025 13:52:20.7028
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 4d954e59-041c-4523-915f-08dddc02f496
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AMS1EPF00000041.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR08MB5604
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=h+yk7oRL;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c202::7 as permitted sender)
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

Hi Cataline,

> > diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/as=
m/mte-kasan.h
> > index 2e98028c1965..3e1cc341d47a 100644
> > --- a/arch/arm64/include/asm/mte-kasan.h
> > +++ b/arch/arm64/include/asm/mte-kasan.h
> > @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr=
, size_t size, u8 tag,
> >  void mte_enable_kernel_sync(void);
> >  void mte_enable_kernel_async(void);
> >  void mte_enable_kernel_asymm(void);
> > +int mte_enable_kernel_store_only(void);
> >
> >  #else /* CONFIG_ARM64_MTE */
> >
> > @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
> >  {
> >  }
> >
> > +static inline int mte_enable_kenrel_store_only(void)
> 				^^^^^^
> This won't build with MTE disabled (check spelling).

Yes. this is my mistake. I'll fix it..


[...]
> > +int mte_enable_kernel_store_only(void)
> > +{
> > +	if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
> > +		return -EINVAL;
> > +
> > +	sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
> > +			 SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
> > +	isb();
> > +
> > +	pr_info_once("MTE: enabled stonly mode at EL1\n");
> > +
> > +	return 0;
> > +}
> >  #endif
>
> If we do something like mte_enable_kernel_asymm(), that one doesn't
> return any error, just fall back to the default mode.

Yes. I'll change this.

>
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9a6927394b54..c2f90c06076e 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -219,6 +246,20 @@ void kasan_init_hw_tags_cpu(void)
> >  	kasan_enable_hw_tags();
> >  }
> >
> > +/*
> > + * kasan_late_init_hw_tags_cpu_post() is called for each CPU after
> > + * all cpus are bring-up at boot.
>
> Nit: s/bring-up/brought up/

Thanks. I'll fix it.
>
> > + * Not marked as __init as a CPU can be hot-plugged after boot.
> > + */
> > +void kasan_late_init_hw_tags_cpu(void)
> > +{
> > +	/*
> > +	 * Enable stonly mode only when explicitly requested through the comm=
and line.
> > +	 * If system doesn't support, kasan checks all operation.
> > +	 */
> > +	kasan_enable_store_only();
> > +}
>
> There's nothing late about this. We have kasan_init_hw_tags_cpu()
> already and I'd rather have it all handled via this function. It's not
> that different from how we added asymmetric support, though store-only
> is complementary to the sync vs async checking.
>
> Like we do in mte_enable_kernel_asymm(), if the feature is not available
> just fall back to checking both reads and writes in the chosen
> async/sync/asymm way. You can add some pr_info() to inform the user of
> the chosen kasan mode. It's really mostly an performance choice.

But MTE_STORE_ONLY is defined as a SYSTEM_FEATURE.
This means that when it is called from kasan_init_hw_tags_cpu(),
the store_only mode is never set in system_capability,
so it cannot be checked using cpus_have_cap().

Although the MTE_STORE_ONLY capability is verified by
directly reading the ID register (seems ugly),
my concern is the potential for an inconsistent state across CPUs.

For example, in the case of ASYMM, which is a BOOT_CPU_FEATURE,
all CPUs operate in the same mode =E2=80=94
if ASYMM is not supported, either
all CPUs run in synchronous mode, or all run in asymmetric mode.

However, for MTE_STORE_ONLY, CPUs that support the feature will run in stor=
e-only mode,
while those that do not will run with full checking for all operations.

If we want to enable MTE_STORE_ONLY in kasan_init_hw_tags_cpu(),
I believe it should be reclassified as a BOOT_CPU_FEATURE.x
Otherwise, the cpu_enable_mte_store_only() function should still be called
as the enable callback for the MTE_STORE_ONLY feature.
In that case, kasan_enable_store_only() should be invoked (remove late init=
),
and if it returns an error, stop_machine() should be called to disable
the STORE_ONLY feature on all other CPUs
if any CPU is found to lack support for MTE_STORE_ONLY.

Am I missing something?

Thanks

--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
J87cZC3Cy3JJplT%40e129823.arm.com.
