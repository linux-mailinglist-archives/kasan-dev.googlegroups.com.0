Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBLU47XCAMGQEBAS363A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF71B282B6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 17:11:43 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30ccea6baa0sf1809938fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 08:11:43 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1755270702; cv=pass;
        d=google.com; s=arc-20240605;
        b=XkoAAcUm0y5In3mHS5HAyn71skXiy3ydUbKXK47q83XniXko6yWwZXqmOPEcaFbhUz
         urwVpm7qNWIk5FvJgn73MVkS6TFTAJO8OoGxtd2UEWN+5v3NYb/nHkdty4/vNJqoolTE
         wIuuiMQ6liuoeQIujtx+0LsQcftNS7kNyPi9zx7uxXRmYrYs5Ck6m7bKUfLh/oHHa4lf
         pv/J4F2FfI7mwi7hLF0czAgurTPbjl3Npdym4XOgSH7dbi34zkI39//aou31/Fwy9ZMC
         XPvQFBDi//nXDXbpDiOfFhRqWcJ9cGmPI5BaHSrNXOD/zFSdXM1IGckkmRcJrfQNDl2i
         F1NQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=Bm58dt0B+pALaRxFTaWfxdXh6MyxsLS1Qpt9/wCQ0qE=;
        fh=P1E0t23FwXXijmX3KG5XCjEGZmMKif02OkCd7da4PgU=;
        b=cY/5lL2nDejnR1blxif36jIAv1ria3M16PNuB3+knYl7jcbAm/TSU0BMqew/Vp7YO5
         oGx9V8fzVpoWFeXshkqiXa6G3Q01eo38K0+TWoe/TP3IxPhPflivgXwo5mgQD2+bdre2
         vGV/VrkQ/eyHSeYCBn2YGh6l/PtrH9CDCxXv/4zM3p2xnZKWV90z6zZeYg57ebWHIql8
         lOHRDbXF1mpwlNmTSey+fiKBT+/RD2MHbhAEjWOs/YXEMQeq0+9CkeNctoYoxMVdtoh+
         ddoGjbj1hg7V3mevWICmtK60xjk0qlELe+pTuGVqQe+otDrr+V28+1n7+NHEXA0stMqr
         opdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=FArBhRyR;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=FArBhRyR;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755270702; x=1755875502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Bm58dt0B+pALaRxFTaWfxdXh6MyxsLS1Qpt9/wCQ0qE=;
        b=BMotBG1zZGnQTh2yeevOy0TuuRQJ4SeXF6ZT7xMK3zoXNKDEFnh2NyRVpAKRwJszM9
         SM6a6CXp+UCICbDkd+mYRfQra2tvTZBeZB6LuGVAsp5/7+11c8qliLc7wDMvvsfPaAU8
         EDn/ilfWXBrNBXBovUvoIwBnGYTX03rLBhK+4oHwkSZ7pharxIYUTLAKD6EvGeDf5ZDv
         GG2w4jwNO+wC8Afwi4ed+85ehwvUPgtRS+anV+KEGVO0MqblCiqEim3FCPu9+Dxc1WFX
         RFI2aPRqcXGFRsMahKyPyF3DzqDkjqzowHHI9GwcTn5bJZdE1OdOYnHTdk0TrdNZwOPx
         5bqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755270702; x=1755875502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Bm58dt0B+pALaRxFTaWfxdXh6MyxsLS1Qpt9/wCQ0qE=;
        b=SB++BoEuadh8PY+SNAMzOlv0ZluLvknJgiwUC3/cZUu4UPRlkqVmISGjwaP1wwWjgB
         CNfydqzPoPaGkXa1NukPkd7RxyMAnWV7IDfa7k3TEDF+Qi1/3ikXBAXSfVc/KNSHIcEP
         anm5GwRyhqmvU2VRz7HSdCqNZhzEa/ysPq17ZgpNO2lO3jPW2rZJXBhLmuTonAepJYyN
         QaHoH4dMEEE2n8dMZveITjzzcbilDVGk1YLUwnySw/i3F6afWdW71riVRCGqyhwugK8N
         FbTndUX5wCx8SB28YyWo0v6EQWw+mO87+Ws4kNfpvzZQ0p2swLRJdm6rq5SGd9KGha88
         dqug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCV46C7u9LnhthxUKEisBrsvW5N9pFs80442vqXrBC05wX0wOvbJmhnTX/8dONjrX98J1xQ5xQ==@lfdr.de
X-Gm-Message-State: AOJu0YymuCuovqXswZ9tnBGRrUsoIYPHgnB451Bd2waesQ8KklfuN0U7
	AhtresFh6EpZAXEdS0EKfz6ACGbXaAMGM682rsTHatvMilFnHvxObYVO
X-Google-Smtp-Source: AGHT+IHVt3zVxFsMKeuRhorinSi9kWJCs+o3xyJe4PqjRIkuIq8oRUBpN0uJ5OyIO+imBIG1/vXg6A==
X-Received: by 2002:a05:6871:3388:b0:2d5:1894:8c29 with SMTP id 586e51a60fabf-310aaf0fed5mr1432940fac.23.1755270702428;
        Fri, 15 Aug 2025 08:11:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxVP/8p9h2tFRZ9u47rFNkUT0ldbubcfB6vb3P+K+UCA==
Received: by 2002:a05:6870:9e93:b0:30b:cb7c:ba90 with SMTP id
 586e51a60fabf-30ccebbda7dls919224fac.2.-pod-prod-02-us; Fri, 15 Aug 2025
 08:11:41 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWgUBJLfXeBLSpweBVjZegaUheMl28R5xKjthfHC8Ji7EvQVkwH+jOaxKw4ytQlsNC+YriESAbJtvE=@googlegroups.com
X-Received: by 2002:a05:6870:5593:b0:30b:aeb8:fa62 with SMTP id 586e51a60fabf-310aad4cee2mr1388317fac.16.1755270701527;
        Fri, 15 Aug 2025 08:11:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755270701; cv=pass;
        d=google.com; s=arc-20240605;
        b=DsxUfjAjwq9Yxe35wuDELqg8yIAoco0xDL7JasUfzvzolMEoPWz/6DufxjEpISrLjT
         YY/9pxVX+lTYYyTLebdUhjFVbcZbIJK5B+R1qa7VDq0z4zdCy+ohCu80ItuPqvGFOde7
         bS/P6APXmTaw0pxqp9kotFueAIFgt+MOWwpBkRE3/eE9cP0jtg1OmahOlSpJJRnN1gkW
         JHJP+dP9zNL4M1SRcupv0TDLEXzMGqCWB6RKsLaXLBw8EtgzfghJn/v7L1aUfupPqgTP
         dEytHVtuhBlNGLhRVSmMxsvQzZ8EQOVu5OfIOGd+E9H+sbxPfzxnQIr2Y2ypeuJ2pCu9
         Xq+A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=9LyzwvjqH8zDyBmgBULVL1FOqczlPPa6/80Ho9a3qv8=;
        fh=sy1/T+hZ0mz5g5/9lgWaTur7TgGZ2Tl7HUiVtGJX82k=;
        b=OZq8HfMfbMUX6UrwOVpPCN9F1qQA4HmudJuPxohjzIVgYUNPGRocUQPlkyPOBu8qmp
         IhXl1PwVRw9qxekikkG1EdAA79hsefA5X9mqfvonf6MVOy6sFzZ0ToWp4zb9v0WyWjsG
         rQkVTiHNV335tJbp30klwyh0/CNvDfT44Z7NWFXv6D4/tCLGKRXTzJVl0gTfancIBheF
         J1N0LJNtpT4yRyN0xT+KfExVZONvAP5OrTBjr4ta+skfmVFUPon4ocJifiB1BuZkSl9K
         X9xWhCl8EqIn1w4UDTRZSMO1AiiRuu/AeSukJVOHpoMagO9tzhjxWKI+M8B0E4hdXlWC
         vFMA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=FArBhRyR;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=FArBhRyR;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from OSPPR02CU001.outbound.protection.outlook.com (mail-norwayeastazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20f::7])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310ab91bba3si66951fac.2.2025.08.15.08.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Aug 2025 08:11:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender) client-ip=2a01:111:f403:c20f::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=uMSs2Rp97sHDj7k9n3a3i/nVvijwwiHuw7eyKaomiiJfCOuM4F+rTyFNzs97RwsE2jCrQ6NcTb+YsezjJh3gzcv2D4d9j8AcfU999GdLiVooP4TY1uA0PaW++mRs55h4Tvo1zv6SDOk1nG8iMIIaCjvLbn06LVTJ9QlIjgpEriPrUHcxEJnezICyzUB5zx6zZz4QFXSciesCREwWnfnm5tMPCDLSlUISJSVSDgrtJ0pTMTEBNXXBsn9Ae3VNbgxOjbP7rTqAl7/jgsKqhj4Xam//ny0ZDTQIFbz7WC4e/RXMv/v/iRxf0xirzQdOLVxWJJpP20qBomYyUgp73UCJEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9LyzwvjqH8zDyBmgBULVL1FOqczlPPa6/80Ho9a3qv8=;
 b=MsjTawyQ/qKON5F/KdWkQ/yugWdGhoNS84tMV4PJf2gsAB0QhbNuf45CnV5suu6rZ211kM8Q2lbN4QAF2JOepVyFTJ4zTMd9WBr9sjYNf9Pgqek2dm0JxBDp/sY6yj1MgLdOcZK7Qy/YTAM0leMNOuHL7FJwf0dELBYvQ+sn0e9WGCKAhPx2BAASQtK/sWUCkCNoHVLDHJjg8Qcy1D4whW9k0w03pOnoPIgJlMTojiyCECFXUe9MR4m0S66X9CCIKgnm9WJsn+bVl7rapgzjoY98V3HUfruRpEWE2IimuLLRSRWrRbCzXBIIMFKUrz/mjDy6uEhVX2xrNW8wWKR6Ow==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AM0PR04CA0092.eurprd04.prod.outlook.com (2603:10a6:208:be::33)
 by DB9PR08MB7675.eurprd08.prod.outlook.com (2603:10a6:10:37e::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Fri, 15 Aug
 2025 15:11:37 +0000
Received: from AM4PEPF00027A69.eurprd04.prod.outlook.com
 (2603:10a6:208:be:cafe::b4) by AM0PR04CA0092.outlook.office365.com
 (2603:10a6:208:be::33) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.18 via Frontend Transport; Fri,
 15 Aug 2025 15:11:37 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00027A69.mail.protection.outlook.com (10.167.16.87) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9031.11
 via Frontend Transport; Fri, 15 Aug 2025 15:11:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tWf7GIEX3Bk2CeYPCNzwpDIPmTOSvdMNaRhIzwCJ02TRyB1VT+gBPzA2s5gtt7S3wp5cQuSCR30ZxKY4Ie8ixGC85eE7qDAkEMzZrVLG8K7kSnw7xXG2fIwQhLKjrBYmh2vbmp6K9mB5QUguqRiOsPosgRhvSGXqq/ZgYCxARurl7axuMi4VZouyA8B3fNQzQGu1/RGm6uI1ScQ2ioYyoYHXL5GEb4tTCvbmBxrSe7yRxw+StyDxnHXcsn0a7fh09FA3HabaD6wSEEptg2gSljejJo+o8ZqbEd+708SmQoFXEigduAXWSQst+hv0gtRWgKwWxC4kHAEFcN8ZbhBWdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9LyzwvjqH8zDyBmgBULVL1FOqczlPPa6/80Ho9a3qv8=;
 b=KKcqlo+iCE+pmOSGrJQG3HRw5J1KcA6FKpGf+kRyyO/aWzQQOnN/lR/biyEra7e6gL5OoYDWSrjvK9r+lkVuge1exw9dk2m9LLrJ5mGH0Q/GlEZXHJuMNQZB2FGs5Pr7/iYigyKiMLZdCTqiXQ7nLMPSwexWPWgBLGzV+bhYy8ylA+87gPLhbECj9WsC4Wc3Qi5aqe8JoWaI1aHrLL/1u50T3FkvgryuSBy+bgkg9h1yE9f5cjslEA/07yjdeCdUJfKw59QRJp4Sf4/HfW30+zxFRNC77H2112ris156tetPa5FxiAwE9dtryqc6CJR8eQkJJEI6AqtSNmRnMWOQRg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by VI1PR08MB5423.eurprd08.prod.outlook.com
 (2603:10a6:803:133::13) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.17; Fri, 15 Aug
 2025 15:11:03 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9031.014; Fri, 15 Aug 2025
 15:11:03 +0000
Date: Fri, 15 Aug 2025 16:10:59 +0100
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
Message-ID: <aJ9OA/cHk1iFUPyH@e129823.arm.com>
References: <20250813175335.3980268-1-yeoreum.yun@arm.com>
 <20250813175335.3980268-2-yeoreum.yun@arm.com>
 <aJ8WTyRJVznC9v4K@arm.com>
 <aJ87cZC3Cy3JJplT@e129823.arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aJ87cZC3Cy3JJplT@e129823.arm.com>
X-ClientProxiedBy: LO2P265CA0374.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a3::26) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|VI1PR08MB5423:EE_|AM4PEPF00027A69:EE_|DB9PR08MB7675:EE_
X-MS-Office365-Filtering-Correlation-Id: 7db7fe2f-280d-4677-c312-08dddc0e07b5
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?SmhXaGhRVTdObVF0akRHc2psbWJ1OWpCVjlPZGV0ajloL3JmcEIxeHdKYVh0?=
 =?utf-8?B?R3NGTkVxQXhzZitFZVM5d3E0eHBqMVhZa0wyVkM3bEZpKzRoQTVxM2hiZjM2?=
 =?utf-8?B?ejhWRjVpQVZsTGcxaGRyVHV5M2NudmNIeUlLS3M0UVkxMEc5THpCMkdxMFBq?=
 =?utf-8?B?ak5IZGZiTUlFWmFqQnAwUE1aZ2xlQ1pYaWJVZG1nMG5Sb0RLOG5LbkFvTjBO?=
 =?utf-8?B?dlpKNCtYaHpQNnU3SFlqUFRWbEJWdEpBNngyQi9nWkNMZmtYelhBUU95VFFn?=
 =?utf-8?B?L0xnZW03OEdsOXNpRlAzS2pzSFpGOVJhZ1dNZk9iNU16VzVSWmRyWVhCa3NJ?=
 =?utf-8?B?aTlvZWNWVzQ2T0RmTDZ0WmVMMHZ3MDdkZ0c1bmRHSldEUENXdnNVMG1Eam1T?=
 =?utf-8?B?SnVZZ1FCOTNJUzl5MFJVNVo2VEQ1K2N6UG8rOWxLN3VobDhNeGRxSnUwTnll?=
 =?utf-8?B?ekFwcys2WlFUNkRkSnlVNFdvNzg2aUExQmVtRmxQWFhaYUJiUHNKODJ3L1Uz?=
 =?utf-8?B?NUxLMDU4S1V4N0t3Y1VMYmhoMzBGMDgvQ1hKSkZMQWJOek1jbFpjWEhxcmxh?=
 =?utf-8?B?U05JUENnby9TZyt4dWw2NWVjZHVhVFdIMkZOeUlyQUZJNXNzeEtZc0I1em9h?=
 =?utf-8?B?Nm9RV1I5TWNrQTYwQ2ZydDhiNnNCVmpPcHVTOUlseWhKQUFZbUkvSTBKQkNX?=
 =?utf-8?B?TEU1NkNZUVRNc28rSmRGOTREYmZ5VFFyeEFyRzlhaWlVMjVUS0IvYU41SEtU?=
 =?utf-8?B?aDh5dGd3YlpGSGRZUjVZbTBMQXZKRWhGMGJhL1VWOGlEbTRROGluTEFUMmsr?=
 =?utf-8?B?WHc2QVFzQktZRzUrV09ZNzBGb3Z3ajJFZE9YNnpzelJiWUFNRXl1cjdaNGNR?=
 =?utf-8?B?NVk4NTdvYWNiTzQ1dER1WUNOYkVVVG5QUjArdWNaOTduWlR1ZUhjRTlMTmF2?=
 =?utf-8?B?RVhZcjQ1NVQ2UzI4MEdSZmpJbVpDdzdWd3h3eHY0TFpuNU1uNGVuRG9ZTktL?=
 =?utf-8?B?eFRULzhLWS9SZGlva3N5ekNXTHZ0bmV2bzZYc01xbFR2MWFBN2lHMDFmODZK?=
 =?utf-8?B?OE9HTDZTTW9ISE9WdzQvajU1TGNjRDFGdStEenNucmZiOGc2cFdkcm56TkU4?=
 =?utf-8?B?MkUrdXk4VUNta2ZkQS9JaDJmbDcxOVNJYXdmdEwra2VNbmtib20xdSsxTk9Q?=
 =?utf-8?B?WTQxOGFaS0VrM2dMYXBDcWFWdE51WWFDOWwzZk9jMXgyc1lKRVRUNExpbzEr?=
 =?utf-8?B?eDBIYkpWL1hCWmNWY0orQ2JNYUtvZmcvTENuWDhUSm9CbS9hdlVjLytDSEhB?=
 =?utf-8?B?U3VzejJqd0hHaEpSYnFkcTZLTjhWSDJWVXVjVi9YSEU4eFpEeVRialpDZFRF?=
 =?utf-8?B?UUI1ekdzYVpLdlJLQUhITnR1NXMvelZHa1VpaG9JY2xPdGxacjJpamoxTm5Y?=
 =?utf-8?B?bG1yMllFbTFnQjRUUXQxN2N6cFpvYVkvdlpQb25xRFBqejJjSVg2Y25OaDFl?=
 =?utf-8?B?aXp0WlpYT0VEQ2pIbi9wSDZmdkFQbzhnNkZvZWwvMVk5YXZmSFJ2NXlRRzFX?=
 =?utf-8?B?M3RBQkMvNmFlWThvMTdkZ21rcUZ6bXBhUmc1Zlk1SWFNN2hBckx6MDd2VTBS?=
 =?utf-8?B?Y09LemtzQkdTdFVTNlNKMmUyS2ZvMHppT2VhWWRoNHBTNkcyRDdFell1UHgw?=
 =?utf-8?B?ci91NG84SlBHMlVtWCsxUisxeU43K0hpZEp0Yy9NUkxtVjdoelVOTjN6SzRP?=
 =?utf-8?B?Y3kxb29SZURJNDltTmRrMkFpTUl5S2hoc1E4ZmcrT3AzUDVYYTRiZjF3WVN2?=
 =?utf-8?B?YzJ3cFd3V0wwMWR6MFZhSjFCN2dQaHYzSEtycDZqdXBFVjVkNjVjOFE1U2My?=
 =?utf-8?B?N0RJYVhSKzJ4T2hMcnJVZTVJRjM0a0t6Ymhjd0p6clhEN3NDY05mcmh5NE5W?=
 =?utf-8?Q?pC9rMKmxgx0=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR08MB5423
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00027A69.eurprd04.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: 3248e2de-d1a7-4b1b-5eb6-08dddc0df38e
X-Microsoft-Antispam: BCL:0;ARA:13230040|14060799003|36860700013|1800799024|82310400026|7416014|376014|35042699022;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?enZsZ0FmZ2NkckVaNy9YcGVTWWo4R2xHb0d5TFhVUW5xaFJmbVExLzBBQndG?=
 =?utf-8?B?V2N1anYvaTNZaDFJTEp1SVlZV05zdEFRMGQ2RWVvUUhUdVdRdnJKWWhIYjg0?=
 =?utf-8?B?Tnh0MkJlS2R2T3JCb0Z5NmRXOUwva0lmVWdXdWszM2R5WkR2VlNEV0dGR0dP?=
 =?utf-8?B?bUNCUEg2YzJtL0V2Njcwd2xwalFDWEozWFBFNjhOb1QvcEkwRjF6Wmh2YUNL?=
 =?utf-8?B?L3NIVkt1dlRaK3E0bE5zNThVV1ViRjk5YnRjckVzeldLaG1BcUZxbnZTdFZp?=
 =?utf-8?B?dkFKM1lvdDVuSzc0SHg0TUt2bUNjRDZCdG90aktwOE8vWUJrWE92WTc3RVhG?=
 =?utf-8?B?VE1Hd2xWdFArb0xObm5yMndGd0ZoNXRtbDR3WFRDWVB2ZnpqMmdTenJxdEkx?=
 =?utf-8?B?SnNNMFdnenpsNEFVNVpXa2FNV0N4MWUxYzc4czhOMXBERTdYc0M2SE1uMGFn?=
 =?utf-8?B?SUgxaHl0RmdzbitrU2RwQkY0OG9COFJmcGJCNDRWaURTbWlMdmVCZlhzRDc2?=
 =?utf-8?B?L0VqSVBydjd2ZVdPS2tUMURoaGcwTmg3eW0yYU1QZXRITlJQQmtEUW91ZmpG?=
 =?utf-8?B?QUExUnByTkc0OU5mOHhicUJMM3VSTDZmTnRvclV4ZGM1UFV0cWxRSGpnMi9w?=
 =?utf-8?B?NTVCR213VnhEWlUyalNUMW42S050MXdma1ZFUzJ1cHRCM2tjUDJobGw0K1ZS?=
 =?utf-8?B?WUZ1UldKTHBsTXltOGpoUEtNOVlrVkNjNnFTOEZYSjBpZ0RRNFU2d0dxMHlF?=
 =?utf-8?B?dFN2OWZGRjU0b052YWx1b3ZPU3ExUG5ENjZ6dEM0T3JEN2xhYmx4UFgwK3kx?=
 =?utf-8?B?ZytQQXYrUm5rMktleDQyVjVxRXZ2cmxCamcyazU4VmVHbmlPQ2c2TDdoV1RZ?=
 =?utf-8?B?SXIvK1czOG0ydS9COEx5RVBsV1NGZFMyTFN3UlN5M0xTWnRuTFovbjR4RUtC?=
 =?utf-8?B?THpBTmEraUtSeGMxZFlscnZRTVVFa0w3UXdGOU5IRm9WVXNPdkszU2J1UVM5?=
 =?utf-8?B?N25wOUxweVdkM2htRGNSc2VnTEt2Y1NSaVMwVXVBMndLaUhEYkM0dVBzaGZm?=
 =?utf-8?B?NlI3TWZtcmlyNlVTTGxVMVlnbEJHeGNKdWxmMG83bHlSSythTW14aGs0V2d5?=
 =?utf-8?B?RW5HdUxEcldhWURTcnNGVjRNaTV5TTJOUFRqRVRJVVByRC8rK2l1QzNvbU9j?=
 =?utf-8?B?QlpCRHdES1laV213Z3Jhd2YwdXkwZTdvTldWc25NQ3BRcU9xaUdoSzd0bm9B?=
 =?utf-8?B?RVF1cDY2N0VWNTFJTW9GVllUa2hKUXJMM0dwUWpJRGZmTEVsbjNxS0Q4L1JV?=
 =?utf-8?B?dXVzdmMyd2pOSGx3NnBHWXJudEVZV2crRTFqSjU0VVNFN2piQzR4eStaTENo?=
 =?utf-8?B?dWt3eDNqWFNZUjFhY1hVYzdWOTdINHdWMW5lWm1oM0NEd1AwdDZ2dVVucytF?=
 =?utf-8?B?ek83NFpDRXRvZXdRU25kK3MreDRWVWw3YU9rL3NRMjlxY1BTL1Q1M0lGcVlT?=
 =?utf-8?B?SlZvZ1I3MU56MVAzczU4SzNHLzc0VWg3VTF1cTJSL1FKQ3ZqczlOR3JDdkV2?=
 =?utf-8?B?YkZHek05WmV2RTZMVnJOUnRKZHZxbmR5YndaNDJMTHhQYnhLVjRTZkNRNmpr?=
 =?utf-8?B?M05jSnR5NFAycG5XcGUzMHV2VGJkYy9zTkJMOVBWTU9vY3NhYU9rbVFCMmVX?=
 =?utf-8?B?M0xiaTNCT2xjWko0Yk9uWlMveHhTSWRhNW15VFRyeE5YbG9yUUJqZGhvYUFU?=
 =?utf-8?B?VTBiT3Q4Vjc1YkRKQW1sYXE4VGhIalVBMzFHdFkwbDhseWY4Mm1ENFBTYWpt?=
 =?utf-8?B?MTRJUkcrN1VNWEZlNnJKZ3dnY2JZbUw4c1BZSkRROVBpZXJxN042UEx3bGlE?=
 =?utf-8?B?SGdhSUNOQzBRUG5GV0VpQUt2MFRQOTFMMFp0YU9oZzVmTGdQZkJabXRlbjFN?=
 =?utf-8?B?dXR4WFZtdG1qSnZXNEJkdDcwVjNtdys4ejV6aHdoeHFvU01zY00vSGdaRk9x?=
 =?utf-8?B?YzVqbWZ2MDdtajJPcG1jblgwN0RyZmppa2tkbU03RGVOZ0cxVW1LL1dYcTZ6?=
 =?utf-8?Q?ZkDYew?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(14060799003)(36860700013)(1800799024)(82310400026)(7416014)(376014)(35042699022);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Aug 2025 15:11:36.1249
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 7db7fe2f-280d-4677-c312-08dddc0e07b5
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00027A69.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9PR08MB7675
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=FArBhRyR;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=FArBhRyR;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20f::7 as permitted sender)
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

[...]
> >
> > > + * Not marked as __init as a CPU can be hot-plugged after boot.
> > > + */
> > > +void kasan_late_init_hw_tags_cpu(void)
> > > +{
> > > +	/*
> > > +	 * Enable stonly mode only when explicitly requested through the co=
mmand line.
> > > +	 * If system doesn't support, kasan checks all operation.
> > > +	 */
> > > +	kasan_enable_store_only();
> > > +}
> >
> > There's nothing late about this. We have kasan_init_hw_tags_cpu()
> > already and I'd rather have it all handled via this function. It's not
> > that different from how we added asymmetric support, though store-only
> > is complementary to the sync vs async checking.
> >
> > Like we do in mte_enable_kernel_asymm(), if the feature is not availabl=
e
> > just fall back to checking both reads and writes in the chosen
> > async/sync/asymm way. You can add some pr_info() to inform the user of
> > the chosen kasan mode. It's really mostly an performance choice.
>
> But MTE_STORE_ONLY is defined as a SYSTEM_FEATURE.
> This means that when it is called from kasan_init_hw_tags_cpu(),
> the store_only mode is never set in system_capability,
> so it cannot be checked using cpus_have_cap().
>
> Although the MTE_STORE_ONLY capability is verified by
> directly reading the ID register (seems ugly),
> my concern is the potential for an inconsistent state across CPUs.
>
> For example, in the case of ASYMM, which is a BOOT_CPU_FEATURE,
> all CPUs operate in the same mode =E2=80=94
> if ASYMM is not supported, either
> all CPUs run in synchronous mode, or all run in asymmetric mode.
>
> However, for MTE_STORE_ONLY, CPUs that support the feature will run in st=
ore-only mode,
> while those that do not will run with full checking for all operations.
>
> If we want to enable MTE_STORE_ONLY in kasan_init_hw_tags_cpu(),
> I believe it should be reclassified as a BOOT_CPU_FEATURE.x
> Otherwise, the cpu_enable_mte_store_only() function should still be calle=
d
> as the enable callback for the MTE_STORE_ONLY feature.
> In that case, kasan_enable_store_only() should be invoked (remove late in=
it),
> and if it returns an error, stop_machine() should be called to disable
> the STORE_ONLY feature on all other CPUs
> if any CPU is found to lack support for MTE_STORE_ONLY.
>
> Am I missing something?

So, IMHO like the ASYMM feature, it would be good to change
MTE_STORE_ONLY as BOOT_CPU_FEATURE.
That would makes everything as easiler and clear.

--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
J9OA/cHk1iFUPyH%40e129823.arm.com.
