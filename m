Return-Path: <kasan-dev+bncBAABBKHGYC7AMGQERI3CQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C2CF0A5C1B0
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Mar 2025 13:57:14 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2b83e537ec6sf4819855fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Mar 2025 05:57:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1741697833; cv=pass;
        d=google.com; s=arc-20240605;
        b=D42ss1t6mPRBuj3BPJsqHS9+Fo1qyopmR37+QI6bePO3m9BjagwzAC+OjX1+Zc9dQz
         OwNO+Canyp+1Rpa629O7sTAzdU291PSKXGUkniRLAbjSwzcGXqh2LhDDoeAiRmNBDGko
         H2L74EuARiJicAJQqb51qyq6W2FwVmaafOZlEyhxwhTaWJBo2n+hIr5KfM2lLFsmP5UL
         Mub+yORwW11iwGFboMyG89MsTSAnTJkfhtpotJN0HoJUIYevqgnF33A00O3OAku1CI8s
         4q/ODcSs92/wFG3ySoHDkXKdnRgnKcQheoQVuWGj0uhpvxM2m508AGPKRduiBqJIUtN4
         jOTQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:to:from:sender:dkim-signature;
        bh=o69j6QL3PfmE1okY0uizLaqbUvSCeflB+H+IrvlCe1Q=;
        fh=/N4a+NYCU9K+ZW2B1aao4gT2iheqsqM8M3a9Bu7deic=;
        b=cDCjREkJQH77IaGN96k+SNVE9J2HqQZVyVdejDOKPd8K8TLyWFoUBhYApm18zJDD4F
         j2kZ+DC4XZHI1094XuGsLyFotej0AfnWS2DigQGL1uWryc1m/lDYa7I9gl8U1yPJjksT
         a0Ci4KXOiz34nUaij0jU8GmLkaa1v/CC3DjqRIct1/8lSVhKdbhS8VkQvBefnsP70QTk
         WPkj9+qOND9deezgnQ80fb5NtgwyahunEF4sYtGSfa4aJdobcfEd90EXVCHq0OjnmxqZ
         LizueDwCSdebe+D4un3LbQgq/nT5bxvrEvaalqC+aNHwzDMMMs6RgpD/ME5f0QxVJwrx
         gzOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@bigfatlinks.biz header.s=selector1 header.b=FoFh9X2f;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::1 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741697833; x=1742302633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=o69j6QL3PfmE1okY0uizLaqbUvSCeflB+H+IrvlCe1Q=;
        b=GVSbU271fjVXy5oh3HzwntvEt1xq67rlyuRBEcdiTEtKnfwvU/5Q9JrdUusw1cgg9A
         JHUekGyBpm6J6sKr2JPr6Iqta4VHolmn+a6IYUxDqOcJnvMiwKA5T7I0nULTk0WxYGVA
         jJSJGHlnySTc09tkDdTAL/e2kGQzn0xHHZObMgPpvnapL1bFY22qqooFzGlKRFY25jQT
         oQQeUgKFgaKbwBnt7mhFtx6EG32zMEmxel5IQK/i2WRYANQBGwXnnJ1pP/ONECxVfGZ1
         B2QbdD2lxKmdzy1eALOgRzGyjM3nDgi6JRi/ciVW/IsFUrgcLoKbrzd2hLxGg0SPBtmR
         ZpNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741697833; x=1742302633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o69j6QL3PfmE1okY0uizLaqbUvSCeflB+H+IrvlCe1Q=;
        b=GtC0Mqg7tW9f3SgpiMucoBb3/Xuc7kgaD6Pt6dBW5UH8JKUoUhDZa/rQRBWcCCIrvT
         TYX54Y3Z2PrUVIqQ6HJaH75u5YOtBCCIdVodPinb5rUvOW6OQ2TYv4p7fU+bilnly8BI
         5Kx7mkGO555RYZYr7I+FWkehujqS9aepHE3gDyrTIBiLBcLXsMW2w85xe/q4dNVNx6bA
         Mfmt2yUcqYgDN864JpRWyovZGZ2Fpf36IKeIK+7UQ0csypgQVszKlbVOkqhlk83PziOg
         yu1skalsNVIxZm1c3yQJPjcw8W8Ecfnle2TuU81MbVokH2r4xhqGgPdLr+88he3hHQYa
         l5Zg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXeUmuZZKPbNBzlcBTtdsPsc4R3KR9/cN3Hm9CsDRN6dg30kZaETgFJK1xoG+jC7R95/9Kegw==@lfdr.de
X-Gm-Message-State: AOJu0YwCvaGVVIcJ7TBa/novAzctiQElE80pLXzXFZC2W0fJnel8ukmm
	iUlPVCiPMXaS50CFi5eUtb9faUqtcKAZWLqtoTuzroErJv6wsBJ6
X-Google-Smtp-Source: AGHT+IGcw1n9edKpE2apLKCn6QW8DbcPOXpG1jJCp8B/q8ZkBOJpMfmW/iWL5hs8/Ia0Of273TQC2g==
X-Received: by 2002:a05:6871:8906:b0:2c1:a810:d697 with SMTP id 586e51a60fabf-2c26102c6f7mr8642975fac.15.1741697833249;
        Tue, 11 Mar 2025 05:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGCQSInP7FUms/qVtMmJiHzXs0wGqRCWJU+V/oCCEjF3g==
Received: by 2002:a05:6870:3c0c:b0:29e:3655:1970 with SMTP id
 586e51a60fabf-2c23f3ba85als709630fac.0.-pod-prod-08-us; Tue, 11 Mar 2025
 05:57:12 -0700 (PDT)
X-Received: by 2002:a05:6830:3890:b0:727:876:c849 with SMTP id 46e09a7af769-72a37c52cd3mr10148138a34.27.1741697832318;
        Tue, 11 Mar 2025 05:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741697832; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvjssl77QONq8Ts+53jl+i1ao8SCwW4KdvIV7eo7REzAiF+125WJjZU+9k35/CU6Cp
         Q5dYvfPhZEp4XWrSmJRWFAanDOW3WFlY310fRE4vw4hke5pUb9nInvc7q4djbrMxQd6p
         YqR3fkF0IZ4KHKk0z25MgY/3lZYlPnICtXJFk17LuYY5jR+06FX66uRElmOmgDghqTIa
         pJgwsYKHwMlZ8zbT61GzeI0pCaH4PmN9KveSbTjjLTfP2btaZGCE/vEjI9LBHuFgRWtz
         rMnDgWY5EhA6qkE+HjGyx50c9MTXguQ9ePBWM2qEcMbqsmDrA/dO3Z9d86wSL01Sv1a2
         dfAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:to
         :from:dkim-signature;
        bh=f+oG2eLVI4PgKMaojnbERiDy4dH43hoWZukmMtLqGCc=;
        fh=OrU1A52QFlqzmEXHI3jZ4sFKB3jfTCSfDFFkLeQriR8=;
        b=iH63ZgO6FM0PJs3+FhsP/w+ZkPp/J5iydGvncrv00OVFlNkEwg7t9sbUxeAGFZX+W8
         MjHIk8A2zpfCRGZqKNE4Ofv/vUyscSATWd+uxsaAZfu6/AmqaR+Y7XbC75XcOWtJVCe0
         pTlKdCkfPJI2kDO21wmf+rkCTmsXlT5nvE4C3yY4A1vzSr0RxAeTCkmhsx2cC38z1yn1
         ve+8v1pAlYKUdZDmo6YeQgziMfVOMpqK0rVlctKkWWoE6n68eKQGt6YBwxDhFYTl2psV
         jWR00GUQ/YTxuBwDeAPNz3pr2bOgtW3ALMvhZ68tblTW2b3fvoybKVuHTcMuEIkQc8+i
         B2Yw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bigfatlinks.biz header.s=selector1 header.b=FoFh9X2f;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::1 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
Received: from LO3P265CU004.outbound.protection.outlook.com (mail-uksouthazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c205::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-72b9f971a18si48681a34.0.2025.03.11.05.57.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Mar 2025 05:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::1 as permitted sender) client-ip=2a01:111:f403:c205::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SlgIE6G16q2IkW10WiqSuJIqn6GvwPv4GDDEh+dCgIDFM8WEo51fUjoGjlv+NUblQbJnvC0wlaTgupux0GMbo3bAgbcx4TlAnLeKr4VpD8xLGb41gXRpUgHr5eSETHwmCXBGbfPT3Nf+953LAIkgju4bDN3v3BZm7qDyu4foMHPBc6X4w5Wx8+/N0fRJdEqBIcwV2S0hd84MV3KlKJbfNq0+AqB43LGk3iIICNIlUC6Vu+29njzBs9RAzqThMgdbHRo2cCyC3/EaUOVdXAcrxVKiSpZLZO4OysU9LcrNx1bUfrUn2sG/xmQWhHuWuKLzWqD1VeSSReRprZ73iukWRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f+oG2eLVI4PgKMaojnbERiDy4dH43hoWZukmMtLqGCc=;
 b=KKK+yv1pCIFLUhME+joUqCzyEy5Rc2rsix+g21ehZVVDEqtHOiHjCAv0XL8wadk3dG167J6vqwZwFw7hdc082BE7YUI25b7XMweXAI4Hh5iP6dzuLM6u+M0wsad05GkT2KSmUDI9563ItiFZYXBCQr3l1zWiDrOM8PL1BhMx/pE2Q7rFNHGZkQj8B9WwTVetsIcHCzGK69NWzaMM0WUKOwHj+Gbj8YGnw2AV1A8fN+yplVYE/dlVF2bgFagwBgyUuKaoLCa94yWCpLFH1WieAkQR0OC/xS28oNRlYcwRwapJ3K/n3WWGNXDgpEhGxK23iwJVwjViVE2ii73vpvUorg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=bigfatlinks.biz; dmarc=pass action=none
 header.from=bigfatlinks.biz; dkim=pass header.d=bigfatlinks.biz; arc=none
Received: from CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM (2603:10a6:400:e2::10)
 by LO0P123MB7008.GBRP123.PROD.OUTLOOK.COM (2603:10a6:600:334::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8511.27; Tue, 11 Mar
 2025 12:57:09 +0000
Received: from CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM
 ([fe80::44ab:afca:17a:3bfe]) by CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM
 ([fe80::44ab:afca:17a:3bfe%5]) with mapi id 15.20.8511.026; Tue, 11 Mar 2025
 12:57:09 +0000
From: Lewis Green <Lucy@bigfatlinks.biz>
To: Unknown <kasan-dev@googlegroups.com>
Subject: RE: Unlock Your Site's Potential
Thread-Topic: Unlock Your Site's Potential
Thread-Index: AQHbiRsJl/AXNKHKyEmVVkigubIxbLNt9/vY
Date: Tue, 11 Mar 2025 12:57:09 +0000
Message-ID: <CWLP123MB44525897F9EFE77900C08D86CAD12@CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM>
References: <LO4P123MB669517786E95BEA70A33EFD8CACD2@LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM>
In-Reply-To: <LO4P123MB669517786E95BEA70A33EFD8CACD2@LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: CWLP123MB4452:EE_|LO0P123MB7008:EE_
x-ms-office365-filtering-correlation-id: aafcc8a0-342e-4a5e-d3f2-08dd609c3bcd
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|376014|69100299015|366016|1800799024|7053199007|8096899003|38070700018;
x-microsoft-antispam-message-info: =?Windows-1252?Q?XHZQRbAhtxqiEn7iTIObcnxaTbD9/o72WlxKPpCr/70AEukvtmZ6tNy3?=
 =?Windows-1252?Q?oSNiEnri3QUIsw6CI9GaSlxUHajIUnJgR6dXC5Onb953Ja3X7Ixm1Pcp?=
 =?Windows-1252?Q?2+fQwsjRmoVDfPncNxLXibavXw+rSlp3KjiwbauBG8VpGNcxsFrn3kEB?=
 =?Windows-1252?Q?zZygyEHIhnCnOEnpdqn/tNZlO22rn+vwL95DX1uDIcjpoS/retxw96T6?=
 =?Windows-1252?Q?0/PeC+Dydkj04AS2mIWcPMZ4j8Cb5H7Sk5KYW/NHj4IyrX40c31cRA9H?=
 =?Windows-1252?Q?DS6LWBgz2wFz/ZkDX2K4KkMMVhlSHO5pWkyX0ePS/BQUHuMcPdx8fGyf?=
 =?Windows-1252?Q?FTU1XNevXqm0QU/sMyNct7XL6jw+tY7wL356iuhffhJw581q+z6dv88b?=
 =?Windows-1252?Q?1GD9bZLj7oLC3ENCL0drmBdjpwR/USKfvsxSrfL8rca87pz3lyMORSVc?=
 =?Windows-1252?Q?eE+AVgEXz7A4ikAAtdaD49q8/UCgqvl823c6H6MVTOv+XE0AToI+yccI?=
 =?Windows-1252?Q?AEMCGztIXuxLqEs4AUZ/j3fnuzaXo8l5YEuz3WtY7zFsz+SiZ8jmJ+oa?=
 =?Windows-1252?Q?BGiRZbAgbsKQEx2Wu6KhWFsoXuj/amZWBjhjhftJqSn/f54A12Jxpk5t?=
 =?Windows-1252?Q?1JOCX4riroaD3wEpngOjkq0nBOsNh0SFVkbZtoBaFmrKF0V5BXM4XagN?=
 =?Windows-1252?Q?fw4y696JeCTnEQmwHT1EmvvsysZZXGFsNZMWC/giALwF7NLONpaPQLti?=
 =?Windows-1252?Q?RGI7CXJKIznv7awQg8nucP02rvKA5bareBxEFa1fyC7rXInW3mQMYrwH?=
 =?Windows-1252?Q?psrx6YenaManYrR68g92oTACJLItthL0sG8AzlEn7OZhBw6ROY0kvOiY?=
 =?Windows-1252?Q?KjoRdgXB6VsQFOTppFJiDvrSiyB3eksTD3WrgXQ5Pqmc/k1WjCpYAVJd?=
 =?Windows-1252?Q?sgmYrPH+BDMX3F/4lIjauI5ExfH07VIUDgpw02bNKWIr8kuq3ZqmtFiR?=
 =?Windows-1252?Q?5IXB9BQbJP0hi5gOUYsJo4zIRcro9qipAnvP6Cge7joJiq8+9GZGZRkI?=
 =?Windows-1252?Q?U7YDfAfW9IfagysxVzF5BNgi4V3IEXVaF14zgK9eAYw4R0IwKV2kdf3q?=
 =?Windows-1252?Q?pSYDH9JKPQ1BXwj2jgHXoyP1c60NHYjvoxWI6rXi6y/TxpWJKRJtYq4I?=
 =?Windows-1252?Q?JCncJoZDhsiPJVqj4+X7qfWJOv+z1OjN16Z67SJ1lTk2qkr+skHJoatC?=
 =?Windows-1252?Q?aZ2dQfPA2xHEUqY1imuPdLpiZIvvcfLpJqfLByL+HPdDLpyWYlkaT8sW?=
 =?Windows-1252?Q?ey5ZhBUPDw8VmkvhokN1j7TgJcFwJkLJvtU4W6QpeXZNbdG2wRJ/oziQ?=
 =?Windows-1252?Q?okpDj++EOZMEdyca2CHrTWg7i7R3hQ0f4sBQJ4Nt8RZ8JiePvZCEBaqQ?=
 =?Windows-1252?Q?Ft3zKpegM74JJ7IdTmK7xwZwyaNWIEA+drOfxCrqfhcsgcBwL5Fv0V/V?=
 =?Windows-1252?Q?jvCkme8L?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(376014)(69100299015)(366016)(1800799024)(7053199007)(8096899003)(38070700018);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?Windows-1252?Q?lw1v846DDQpQL7m1PB3gzow6TyTNJlMjVMctXD4qs7ul0A62HEdyEIsR?=
 =?Windows-1252?Q?r1+uJ2KRxfvjCl33JklgoK5+o9xWl4o7MCdpcH8JjQfSlHpuX8taK9gJ?=
 =?Windows-1252?Q?VdiY1xAX/mtvyDGhBhRHljm0mILv3pJGanJQJ5odtX829A7DHJAGK9BL?=
 =?Windows-1252?Q?k+4OX1hMDpM9VtuTTPLyFvoGf2jq3JpZEdqb7wLBYUQYbowkpee3HncP?=
 =?Windows-1252?Q?lPu8yZgUecl/6X9KMmq+euigHj5EcYoBtG16YsDBSTZAQy5/WWjtnk/n?=
 =?Windows-1252?Q?L2UNMBQlQG7o82AuojP0N9aL+u+ISG3DLS7lD60R7JJdMY2/Fl7oxo2e?=
 =?Windows-1252?Q?H4yGyGVru7RYZD0lG30YwT2zv3S3VdMzA9ZzvcnErKjp1ulvnkpxyyl7?=
 =?Windows-1252?Q?nAN1UzFyUthvNM7W3mmZaC9LV//t1fv4To/Jc8AETBC8gsfDyWxKbpI8?=
 =?Windows-1252?Q?YpUfVwwhzVpOaeiHCWIaGd+sH9VKMWseEupiNg79VTisQQzpbuFhVP7O?=
 =?Windows-1252?Q?Ms7eiNoOUUODrhUBNug77RXj48smX60jPHmIh/vzeU9YOj/ddBg3RIDn?=
 =?Windows-1252?Q?QkSIVX8TjKEM1UV3FgvJDUOut71WtZl1P2VlpQj2pBlLYahvbu3jEaeM?=
 =?Windows-1252?Q?1YWP/5XqueNrAETr5solCSpHbY8DVixtPqvzfwaNpWFb4vmMY352w1vw?=
 =?Windows-1252?Q?X0Rh+k+mSMStEP9/bfEfz9MwzMx9h8Mlofd+E3+0N4G+8AVRnAcJagDj?=
 =?Windows-1252?Q?/9Hs2xyJg3QNfx5gcowK+9Ls6JB3d2mfSg5ZhTn2qehFtmBt5CHI0BBR?=
 =?Windows-1252?Q?EGoOlCpA3ZylGrNRpbgVnUciUNq6k1EgclU73zN95FFhCvYvcOUN/Zoz?=
 =?Windows-1252?Q?OIS4JdiCn00L5AaN7ZoH1p0wGRYGoSW4Db0Qi3LAEm/aOITYGi4gjA2F?=
 =?Windows-1252?Q?p4Br3XZnVAZM86sHt/IRqIJ1jkt02WmhY8dgkIoCVcFdwtOviKf+J6wZ?=
 =?Windows-1252?Q?euYez681v93FnpZ+dbUdew6yYX3kleSanRuRK7D9SLhj15/gw6NKmdoq?=
 =?Windows-1252?Q?wO/bGDjm/0WlDFzfanezLjmZy6aETrlvIsQzGbJLbbteq42l+tHgOpQ4?=
 =?Windows-1252?Q?6ZP1S57YB68ch2pKodYS3bypMOvdzzXGJ6EuqN88U/p44Ig+GB2VLKKj?=
 =?Windows-1252?Q?3SzxbQzh7Kw8+oQnuDVPahslOBZT63sXn+DjhRZ8uEcKzWmQQ1BQW6MH?=
 =?Windows-1252?Q?ykDD7UuqGpHWdEjAw517k2BukggofeZFBu+MWzi7ycGyHzmPd5CVJvle?=
 =?Windows-1252?Q?bQ6w3UmfWVKOijBL8s8kgrByA652WWo22qqv25otzRGts6fkvQEJCWA1?=
 =?Windows-1252?Q?aSKxRltk2yYZkw7xLfjgnH2UdfGSt0LVedGJlApUWXjrsp4bVR9vjFO1?=
 =?Windows-1252?Q?WMzJ5ELmaYjV9nW6714MyouR8r1pJqZ7DDwQXYpFG7McE/BaSM+J65pw?=
 =?Windows-1252?Q?fQCtZf3ewXTzpcBrqVnk0hHteaUX/QJC14J0/Uzs5deg7wgojBJwYX4K?=
 =?Windows-1252?Q?UfjtJmFWSRjnvXiVH3/08zei7fjKH979C1HEepeR5ZCQ9iyLeatcLB4R?=
 =?Windows-1252?Q?DF7fK+1muMoE1vx6HTO5nBIPe3bpGBSYwUA4MYUS1dJ52i8UilF0sX4l?=
 =?Windows-1252?Q?ht9XcTNZaIkfFsujsLOP8KILktNQosDs?=
Content-Type: multipart/alternative;
	boundary="_000_CWLP123MB44525897F9EFE77900C08D86CAD12CWLP123MB4452GBRP_"
MIME-Version: 1.0
X-OriginatorOrg: bigfatlinks.biz
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: CWLP123MB4452.GBRP123.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: aafcc8a0-342e-4a5e-d3f2-08dd609c3bcd
X-MS-Exchange-CrossTenant-originalarrivaltime: 11 Mar 2025 12:57:09.0791
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8fac7e88-f5f2-4021-ad1d-c104f3f1d3dd
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: PNnZ9XLD10aAr1HB+v44o9Wc2iNezDP8rqnHXe/KSpJ55B+u0rEmSzapNfYOjj4hyqZDJFBcFWYgC9mPhq0WWQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO0P123MB7008
X-Original-Sender: lucy@bigfatlinks.biz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bigfatlinks.biz header.s=selector1 header.b=FoFh9X2f;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass
 dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates
 2a01:111:f403:c205::1 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
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

--_000_CWLP123MB44525897F9EFE77900C08D86CAD12CWLP123MB4452GBRP_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,
I hope this email finds you well.
Following up on my previous email, I wanted to touch base and see if you ha=
d any thoughts or questions about our SEO services. At Big Fat Links, we=E2=
=80=99re committed to providing a strategic approach to SEO that goes beyon=
d just backlinks.
Our SEO services are designed to drive your online objectives and deliver m=
easurable results.
We are here to be your dedicated SEO partner, ensuring that every effort is=
 aligned with your business goals. Our track record of success and our comm=
itment to quality, backed by our money-back guarantee, means you can trust =
us to help you achieve sustained growth.
If you=E2=80=99re ready to take your SEO strategy to the next level, I=E2=
=80=99d love to schedule a call to discuss how we can work together. Please=
 feel free to respond to this email or visit Bigfatlinks.com<https://links.=
bigfatlinks.org/b?y=3D49ii4eh26orm6c1m70pjipb675ijcp1g60o32dpgc5hj4cp25gh74=
8hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f7tqn8ravednnasj3ckuk2s3fdhm6un3l=
60o34djlehmlurb5chknar9t8lmm2qbcbhqj0c1i6pqn8ravcdgmqs31d5jmsfa1e1nmor3faop=
iscj648=3D=3D=3D=3D=3D=3D> to learn more about our services.
Looking forward to the possibility of working together.
Best regards,

Lucy
Big Fat Links Ltd<https://links.bigfatlinks.org/b?y=3D49ii4eh26orm6c1m70pji=
pb675ijcp1g60o32dpgc5hj4cp25gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f=
48=3D=3D=3D=3D=3D=3D>
[https://links.bigfatlinks.org/+?y=3D49ii4eh26orm6c1m70pjipb675ijcp1g60o32d=
pgc5hj4cp2]
If you don't want to hear from me again, please let me know<https://links.b=
igfatlinks.org/u?mid=3D67c06839ef9e6d000170ac23>.
________________________________
From: Lewis Green
Sent: Thursday, February 27, 2025 1:25:16 PM
To: Unknown <kasan-dev@googlegroups.com>
Subject: Unlock Your Site's Potential

Hi,
I hope this email finds you well.
It's been a few months since our last communication, and I wanted to follow=
 up to see how your SEO efforts have been progressing.
At Big Fat Links, we are not just about providing high-quality backlinks; w=
e offer a comprehensive, fully managed SEO service designed to drive your o=
nline objectives and boost your digital presence.
Your domain, googlegroups.com<https://links.bigfatlinks.org/b?y=3D49ii4eh26=
orjge9g74s3gc366dh68dhg60o32p9h6cpjap925gh748hq49k78t3g78niuprfdtjmopb7e9nn=
as3j5phmur92>, has tremendous potential, and our all-encompassing SEO servi=
ces can help you harness it.
From on-page optimisation to advanced link-building techniques, we cover al=
l aspects of SEO to ensure your site performs at its best.
Our link-building team secures backlinks from reputable sources that enhanc=
e your domain authority and improve your search engine rankings.
By partnering with us, you gain access to a team of SEO experts dedicated t=
o helping you achieve and surpass your online goals. Our commitment to qual=
ity and results is backed by our money-back guarantee.
Let's discuss how our fully managed SEO services can take your domain to ne=
w heights. Please respond to this email or visit Bigfatlinks.com<https://li=
nks.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh68dhg60o32p9h6cpjap925=
gh748hq49k78t3g78niugj9ctj62t3cd5n6mspecdnmq8g=3D> to learn more about how =
we can assist you.
Best regards,

Lucy
Big Fat Links Ltd<https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3g=
c366dh68dhg60o32p9h6cpjap925gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f=
48=3D=3D=3D=3D=3D=3D>
[https://links.bigfatlinks.org/+?y=3D49ii4eh26orjge9g74s3gc366dh68dhg60o32p=
9h6cpjap92]
If you don't want to hear from me again, please let me know<https://links.b=
igfatlinks.org/u?mid=3D678909880f3bd60001e1335e>.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
WLP123MB44525897F9EFE77900C08D86CAD12%40CWLP123MB4452.GBRP123.PROD.OUTLOOK.=
COM.

--_000_CWLP123MB44525897F9EFE77900C08D86CAD12CWLP123MB4452GBRP_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DWindows-1=
252">
</head>
<body>
<div dir=3D"ltr">
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">Hi,</span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">I hope this email finds you well.</span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">Following up on my previous email, I wanted to =
touch base and see if you had any thoughts or questions about our SEO servi=
ces. At Big Fat Links, we=E2=80=99re committed
 to providing a strategic approach to SEO that goes beyond just backlinks.<=
/span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">Our SEO services are designed to drive your onl=
ine objectives and deliver measurable results.</span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">We are here to be your dedicated SEO partner, e=
nsuring that every effort is aligned with your business goals. Our track re=
cord of success and our commitment to
 quality, backed by our money-back guarantee, means you can trust us to hel=
p you achieve sustained growth.</span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">If you=E2=80=99re ready to take your SEO strate=
gy to the next level, I=E2=80=99d love to schedule a call to discuss how we=
 can work together. Please feel free to respond to this
 email or visit </span><a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4=
eh26orm6c1m70pjipb675ijcp1g60o32dpgc5hj4cp25gh748hq49k78t3gect2ubr2d5jmcobk=
dhkmsqrj5phmur9f7tqn8ravednnasj3ckuk2s3fdhm6un3l60o34djlehmlurb5chknar9t8lm=
m2qbcbhqj0c1i6pqn8ravcdgmqs31d5jmsfa1e1nmor3faopiscj648=3D=3D=3D=3D=3D=3D" =
rel=3D"noopener noreferrer" target=3D"_blank" style=3D"color:rgb(0,0,0)">Bi=
gfatlinks.com</a><span style=3D"color:rgb(0,0,0)">
 to learn more about our services.</span> </div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">Looking forward to the possibility of working t=
ogether.</span></div>
<div style=3D"line-height:1.50545; margin-top:0pt; margin-bottom:8pt"><span=
 style=3D"color:rgb(0,0,0)">Best regards,</span></div>
<br>
<div>Lucy</div>
<div><a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orm6c1m70pjipb=
675ijcp1g60o32dpgc5hj4cp25gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f48=
=3D=3D=3D=3D=3D=3D" rel=3D"noopener noreferrer" target=3D"_blank"><strong>B=
ig Fat Links Ltd</strong></a></div>
<img src=3D"https://links.bigfatlinks.org/+?y=3D49ii4eh26orm6c1m70pjipb675i=
jcp1g60o32dpgc5hj4cp2" alt=3D"" style=3D"width:0px; max-height:0px; overflo=
w:hidden; display:block"></div>
If you don't want to hear from me again, please <a href=3D"https://links.bi=
gfatlinks.org/u?mid=3D67c06839ef9e6d000170ac23">
let me know</a>.
<hr tabindex=3D"-1" style=3D"display:inline-block; width:98%">
<div id=3D"divRplyFwdMsg" dir=3D"ltr"><font face=3D"Calibri, sans-serif" co=
lor=3D"#000000" style=3D"font-size:11pt"><b>From:</b> Lewis Green<br>
<b>Sent:</b> Thursday, February 27, 2025 1:25:16 PM<br>
<b>To:</b> Unknown &lt;kasan-dev@googlegroups.com&gt;<br>
<b>Subject:</b> Unlock Your Site's Potential</font>
<div>&nbsp;</div>
</div>
<div>
<div dir=3D"ltr">
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">Hi,</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">I hope this email finds you well.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">It's been a few months since our last communica=
tion, and I wanted to follow up to see how your SEO efforts have been progr=
essing.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">At Big Fat Links, we are not just about providi=
ng high-quality backlinks; we offer a comprehensive, fully managed SEO serv=
ice designed to drive your online objectives
 and boost your digital presence.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">Your domain,
<a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh6=
8dhg60o32p9h6cpjap925gh748hq49k78t3g78niuprfdtjmopb7e9nnas3j5phmur92">
googlegroups.com</a>, has tremendous potential, and our all-encompassing SE=
O services can help you harness it.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">From on-page optimisation to advanced link-buil=
ding techniques, we cover all aspects of SEO to ensure your site performs a=
t its best.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">Our link-building team secures backlinks from r=
eputable sources that enhance your domain authority and improve your search=
 engine rankings.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">By partnering with us, you gain access to a tea=
m of SEO experts dedicated to helping you achieve and surpass your online g=
oals. Our commitment to quality and
 results is backed by our money-back guarantee.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">Let's discuss how our fully managed SEO service=
s can take your domain to new heights. Please respond to this email or visi=
t
<a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh6=
8dhg60o32p9h6cpjap925gh748hq49k78t3g78niugj9ctj62t3cd5n6mspecdnmq8g=3D">
Bigfatlinks.com</a> to learn more about how we can assist you.</span></div>
<div style=3D"margin-bottom:8pt; margin-top:0pt; line-height:1.50545"><span=
 style=3D"color:rgb(0,0,0)">Best regards,</span></div>
<br>
<div>Lucy</div>
<div><a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc3=
66dh68dhg60o32p9h6cpjap925gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f48=
=3D=3D=3D=3D=3D=3D" rel=3D"noopener noreferrer" target=3D"_blank"><strong>B=
ig Fat Links Ltd</strong></a></div>
<img alt=3D"" src=3D"https://links.bigfatlinks.org/+?y=3D49ii4eh26orjge9g74=
s3gc366dh68dhg60o32p9h6cpjap92" style=3D"width:0px; max-height:0px; overflo=
w:hidden; display:block"></div>
If you don't want to hear from me again, please <a href=3D"https://links.bi=
gfatlinks.org/u?mid=3D678909880f3bd60001e1335e">
let me know</a>. </div>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CWLP123MB44525897F9EFE77900C08D86CAD12%40CWLP123MB4452.GBRP123.PR=
OD.OUTLOOK.COM?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CWLP123MB44525897F9EFE77900C08D86CAD12%40CWLP123MB4=
452.GBRP123.PROD.OUTLOOK.COM</a>.<br />

--_000_CWLP123MB44525897F9EFE77900C08D86CAD12CWLP123MB4452GBRP_--
