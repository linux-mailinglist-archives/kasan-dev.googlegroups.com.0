Return-Path: <kasan-dev+bncBAABBGMWYCUQMGQEQO2WA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 403AF7CE31B
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:43:07 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-581df11b5b4sf2296984eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:43:07 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697647385; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlF2S9h26NuwdZpckkEviDUdl/MaykCLEkzsMCPX4dGX7yM3s8AVtFA8AGAq17ngQV
         6Tx8QgSUaopTqF54fxH6QIzxw08/YKwBPMEsj2QK/ZL3AslNE+B2kNw8uaPwsP7Ynz50
         IaulzcBBSq/IJtl9TnhxVhdm0XvzQrrE5pUyKc1+84aN+mXzvKf90NEOWG5M4HnwFRmp
         wR6qEgqs/EdXPsSz5Lp+iNtu3qLE7vCLYWn+zLXQqD5IQ54vOy9Ez+N8TKcdnEPAZfwk
         GeOmPOkhUVID1dmZNddY47JUGl3AgWKBCRRKEHDZvrY4c6EMQNEox8W1JJuvhWrgZgex
         GdRQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent:date
         :message-id:dkim-signature;
        bh=xSHhloy2O8j6zwAyewDdnw+20JwbeqJVroE0dkG6wyo=;
        fh=QxZ+KF+sWD59LBrOLTboyLXGhK0zCqGcJ7neO8VfIAQ=;
        b=j9KUaWEFTROASrLeZHG8xzrUIJGeAO71pBtgeMVEeI6QErLa1BR7ouexpxU5/JXRa2
         ptQxTUTIpZw77s9NMqdIPxkCkZl49oQXnOfxP+ZSv6RiFXm+8JqUlv9zwhMI99Dzp51f
         X9P4xk5YcDo0kKVFvYWkHtU1jnTXxbzBno48iSixW/9bODLlE6OviUXix97Umie6CQ7+
         o7YcnVCm4/hdfQHPpKPBM9fpqHCsuMnNH9hJh/nYaFfQk8y+h+UfbTyZqrNgqZJ/msha
         1knTsCLRqKB5g7q6s2ZcPXYFFpyL8anBh0RJfvIzzMASC9MHHwK0Nx+eGf95Ht4ty4jr
         MtOQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=pd6D9nL9;
       arc=pass (i=1 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e88::60e as permitted sender) smtp.mailfrom=Hamza.Mahfooz@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697647385; x=1698252185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xSHhloy2O8j6zwAyewDdnw+20JwbeqJVroE0dkG6wyo=;
        b=Oz3vQFiAQtR8cy4YUHejp/9gaq0HkpZ5NJz0+QtPprSovKpAYVjZSJ1OB+F4Uz5aFm
         g9aUIthV/p12YaEXocigs7D1pen2G8Laasr3W1mEQBu1UtwCnxEh9nr9nqZx97ZfmCck
         YccgTt8tw+zORr3BFzgwvc+4qELwWM+ZfDYMZAepeVjLCRzpt5LhZj0c5BnF+Fmpu61H
         lBjpfLUBSeDJeaScoc0KqxtnYuMtT4esH1qcFsPlXvTdrNyETXYwhu+4c1RxCn/fjgiu
         drDucXJkLF6nM7DtEDNZMzFY2xqqJBjNJiCpqU058YJSwpeLXKkQ8yk4XHiU/lFC8vkl
         QccQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697647385; x=1698252185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xSHhloy2O8j6zwAyewDdnw+20JwbeqJVroE0dkG6wyo=;
        b=EDkT0xUbslRdwPK+3iYzi6f9xUJEIPDC6xeo0NAtXFiRTiWRMjvU+Ub0fq5nOvUzgG
         bnoeLKKEjYN3vtnrkwy+nOEA0FyMWvtYS2sUtt83sLI2SxL0NYUCV8DupEsFrClcM1F0
         BhycfhgF7xNxhwZkdlitVs6viz6CebT4UdH+as9WdWc2Bd1938ZCqj62VljSYblVeScA
         a9LVT3ezcVuYYwgE4VbVEQA4IliSIWzt+uGeu+r+TqfqCk19TwcyanvLliAKGEsKE5io
         nO/TBXm8qi6S3p4cE1WSPzAwvHPKl5+sLMQQEArm0n8zzpYggzt/IkAfg7Caxn1gLYEV
         ZYVQ==
X-Gm-Message-State: AOJu0YyF2liVrKLLnm0m+wPN6Fs8oK8dgFVz3sHimuRB/cLjWHf3Iod9
	A3OhmvtYYGYJFmTAhtz9Hpc=
X-Google-Smtp-Source: AGHT+IGKeut88cYf6vb/7N05QXH9xHpaTMAtIhsGhooIq2P1T0Qr+deA+Juxn9Dl89Z3eJdPvnBKtQ==
X-Received: by 2002:a05:6870:1f0f:b0:1d6:3d31:fb4b with SMTP id pd15-20020a0568701f0f00b001d63d31fb4bmr6754203oab.24.1697647385633;
        Wed, 18 Oct 2023 09:43:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f786:b0:1e9:9551:4f75 with SMTP id
 fs6-20020a056870f78600b001e995514f75ls1016989oab.2.-pod-prod-05-us; Wed, 18
 Oct 2023 09:43:05 -0700 (PDT)
X-Received: by 2002:a05:6870:2183:b0:1e9:c315:9d66 with SMTP id l3-20020a056870218300b001e9c3159d66mr6811274oae.40.1697647384826;
        Wed, 18 Oct 2023 09:43:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697647384; cv=pass;
        d=google.com; s=arc-20160816;
        b=fYa8np9yQFQ76laa09CFscTfCarYbSjhXSoJvQewuFWubo1WzuiGq6LrpDzVsL0qc3
         SbsgsNsWTlmaPqVgSAbGIu93QnEJjSLIS4n/zL+1dJtLSiyMXp2SdxOhmWAraI/UXXeK
         m6nVA0T0gy23v+POnSou2f2uHruVQNVZ++yqL4DudT05fvBYebrcLRGRSDWFhIlZ1kbe
         NRe6oTg2ARmSsOiSnRMBYK4jlvzF8RUVVG3YMyIbgnf9wIj6PrynaB2/mKFpRSzsHYJv
         /3rGkZXYZfHnbjBHhuTtJEkjY2c1olSxXeR8gkwBRrFq1VE08Oe6wbpgPFjhcOlpzW1w
         RxSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=YYOgGSM5VZwjEd5LHq8+dVseqn7AD+grlWvPNuKeuXY=;
        fh=QxZ+KF+sWD59LBrOLTboyLXGhK0zCqGcJ7neO8VfIAQ=;
        b=H+ct63Z1F7Xb0Hy5AGdg1/r1FlflxuGqoE6v8kJ5Jk83RKQr+sxs4udriK26rwcixO
         NEUEtlSZsOSrmJSDzsZ4ExwNbuASGWsxVDU+grN5PAwATH8S9J42ejbWoBswZuMhJAAc
         4Dgb8tKw8sTTqh/D03V7g1Nu3mIdFNubgJ7JjbeGMV5SdHoDKkOJn6AGIkdlUpvBI60v
         gRyBHgOXi6NH4a1J5M+aZJO1B80xNDYQ1nC+Ok6YAngEFmF60m5s+4ACF68G3o5VllLe
         bIXGJvnFzy5Y8UmumEkf59SqUtSzst0JVpSlOPnX/8yq3Jfr1n4sfkuFa/Y3sdcG7Nzp
         iTJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amd.com header.s=selector1 header.b=pd6D9nL9;
       arc=pass (i=1 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass fromdomain=amd.com);
       spf=pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e88::60e as permitted sender) smtp.mailfrom=Hamza.Mahfooz@amd.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amd.com
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (mail-dm6nam10on2060e.outbound.protection.outlook.com. [2a01:111:f400:7e88::60e])
        by gmr-mx.google.com with ESMTPS id y18-20020a056870459200b001eac55e3d6csi11424oao.5.2023.10.18.09.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Oct 2023 09:43:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of hamza.mahfooz@amd.com designates 2a01:111:f400:7e88::60e as permitted sender) client-ip=2a01:111:f400:7e88::60e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=GBaQnhf9BJIhvHJ7GGQuqRTNBCY2Ta7atb0KLVPHDDYxkspFavLLjHIlzIfqmugOjkgtNqulcyEQQk7Arhpp4Gf8LF3ThywXWXjgsNVgrL/Rb9X4vmlFpJ4wJas0D0lMmZj5qmB48GbZAF91YVaW7GVo2rSlZ4QlS2KAYLE1CVGB69QH9TfvqT5k6CLm/m9wzKwm1yG5ICcdy5Hi/32mLX55WA8q+MmM5h+CydzKaVkCN9iTt+17/7G96/KXueJaqs3g5Bhv2fldBPIjCI6LB/L0/u4owDqimHMvQ+zJ6jl9ZYZdrzFL0b1oLbUA2faw9p5LB9dqsPJaFcMFDoBBHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YYOgGSM5VZwjEd5LHq8+dVseqn7AD+grlWvPNuKeuXY=;
 b=HdSfjBbTOLnpy7RJiw0lj+S4U5qKW5jbJu2eWgthpmjbO036okZiKpmMP8kVeEeqGLyzfaMslmugXcJotMnI0ZnX5UjwehJn1MVIuDWQdRYxCZOoAqUhN7pPTKkeEGzEwlkH9U1WbZVdgN5KjayU+F0xk1ZpBU2cZvHNSAarPoigPn7f67eFwIGjifU+oAkEfThxAXc4n9/o98co1Au5zgJqkamknWJzxbTeqDZdwNkLCuanBt+8bVvpg7u+iTOI5BjZ8XXSK7fPETs13SnsW17AxnQCsM1IPRukoWYk2rqxFQLkLkHf+TUjfL5u4QhIsRjKL7CdCnbigPeFQhyGBQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=amd.com; dmarc=pass action=none header.from=amd.com; dkim=pass
 header.d=amd.com; arc=none
Received: from DM4PR12MB6280.namprd12.prod.outlook.com (2603:10b6:8:a2::11) by
 DS0PR12MB8478.namprd12.prod.outlook.com (2603:10b6:8:15a::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6886.36; Wed, 18 Oct 2023 16:42:59 +0000
Received: from DM4PR12MB6280.namprd12.prod.outlook.com
 ([fe80::5aa2:3605:1718:3332]) by DM4PR12MB6280.namprd12.prod.outlook.com
 ([fe80::5aa2:3605:1718:3332%7]) with mapi id 15.20.6886.034; Wed, 18 Oct 2023
 16:42:59 +0000
Message-ID: <c7a80dc5-d18f-4a7d-915b-1803cc3e33ca@amd.com>
Date: Wed, 18 Oct 2023 12:42:53 -0400
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Rodrigo Siqueira
 <rodrigo.siqueira@amd.com>, Harry Wentland <harry.wentland@amd.com>,
 Alex Deucher <alexander.deucher@amd.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 Arnd Bergmann <arnd@arndb.de>
References: <20231018153147.167393-1-hamza.mahfooz@amd.com>
 <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
From: "'Hamza Mahfooz' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-ClientProxiedBy: YQBPR0101CA0026.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:c00::39) To DM4PR12MB6280.namprd12.prod.outlook.com
 (2603:10b6:8:a2::11)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR12MB6280:EE_|DS0PR12MB8478:EE_
X-MS-Office365-Filtering-Correlation-Id: af30a825-6e02-400f-9192-08dbcff94967
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: VIhHlTpBif5JjUYePR6m6K9NXDzxuF3xhRZPAlIAy4hQjsf2DCRQv/Lu/uUiCIx2pfnv+HtwmScKE1u7kOplBOCjwq8HxRCxqjEo0j6EnWe60GsV1R8y1wsJni2+3r1EZgds6XVYpP7msy9yhCESSVNn589m2oo57b2vekKtufzV5rdH97RFh1bc+V6/ll3ZFny0Sg2d3pkiC6Fj9CA5l6i2v1dLoaJCiAiPSx+mGM1wO9GwfbAaJsx8ZzD4ZGW07X9klYJJlRHXoWfo0cKy29WBvauCaNDz7yLx/UrSkukK1nJBisAuv84shANWt9ARG4rUJlH0UhiX8XOqbUHFgUz6TDAegrrcqLy2Q248fuFMNyG6IDbq3xcwN9L5yO5uwyCG7uI2ukvUCOgJpXmcGsnXZDmcbwPuVJrjdPCnSyG8jvYkE3C1H+QL3h1v/qNUc7pgi9+UxmdVQmWz1k3a5+INSYPytFNeG7nQTgj222kGJFsUdVpTHvXgelCBushFCwCq7hUCvFJLlrs82YvstDcox33xv8pqF6gn7b9+eynpHFbqOBzJI50eVmae1I1H+Yg7RRUu1t6mG/dh82vQkB39mg+HDFJ83QYaqRIwo/H8hlTk3ED3hgG7igh36X7Yp8XTllWRA8OE+5bwwFEI++7sY5TtmA7Ck4FtaqTDI3/vLgke81v5dahaCXXTBxkZ
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR12MB6280.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(346002)(376002)(136003)(39860400002)(396003)(366004)(230922051799003)(1800799009)(64100799003)(186009)(451199024)(6506007)(6512007)(2616005)(53546011)(83380400001)(31686004)(26005)(966005)(6666004)(6486002)(478600001)(5660300002)(41300700001)(4326008)(2906002)(86362001)(31696002)(36756003)(8676002)(44832011)(38100700002)(8936002)(66476007)(7416002)(316002)(66556008)(54906003)(6916009)(66946007)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?bSttd2xtT3dqOVZoNXdLZVJKOTU5MDRwMG5jZmNEV1E2cWk4TTEvZUkzeitT?=
 =?utf-8?B?dWRSa1VDY3NpSnlMQXNUS2tDRWI1YWIxdEh1YkJySHpuWVVsdjVtVlh5Wjl1?=
 =?utf-8?B?Z0pOUjdEck5xU0J4YjA0dlFxRDE1bjQvS3VueU00V2x0K1NKd2xEYTRWbFND?=
 =?utf-8?B?all1WkQ4L1I5WFNLYnpBQnFsVU1lTW9NNFBDKzZWNkl5bGZxeEt2ZEExREtU?=
 =?utf-8?B?V2hncWgyYktJNTMwNExvRFh5OVF5QllkZDRIY0RFTDVBRUxVLzFtWEY1S2dO?=
 =?utf-8?B?UzZ3ZGZUWG9aN1RvdHZNT2lCZDZGUzJyRG42R1pPOUxMREp4TEZmVGxnaVdw?=
 =?utf-8?B?S3RBREJRWXVETmkxZUozT0lxUWc0TjlBb3F4TlEzV3U4WW83MkJrTU4rWDIr?=
 =?utf-8?B?S0JsYzlwNkZwUVpJdVppZkx4ei83VUltc3Z1N3dTTUt5V3BqZjhVeVdZZnV5?=
 =?utf-8?B?TmNIWUdpZE1nMzNDMDBsOVVLMDdKSSsrYXRWYXZGM2JCSGVkNWVvdnJSekJi?=
 =?utf-8?B?SXdHUW1BZ0hoZDNUUmJGTlhCK0l0TjhSaXBaM3dqMDRRd2djSHJnK1BITzVE?=
 =?utf-8?B?TVZ0WjIrbElzQnQ4SXJTekFYV3NwU3VlRUdyL29ORHprTEViSW1NNEdEZ2F4?=
 =?utf-8?B?ZG5YODdWUUZ2V2RPbUtVQnNKRXRJdGVlcC9rTXlzNjNDNlNFWnlkemljdUFX?=
 =?utf-8?B?Vnh4U0lWZmJpTE5vVVU1QUo4d3lESmtsSjIrSkZUbnBPR2s4NWJQdnNEVlFz?=
 =?utf-8?B?QWtTL0hkZjcxMkI2S1Nrd3JwK01hUk45eExRdFQvK25WR2N5Wmo0QnljNlVi?=
 =?utf-8?B?VzhFVXYvdkNPKzJmbWNmMzkvU1ByT096TFlzSDdzOEVGcm5CZWJqWWdUSmVl?=
 =?utf-8?B?TmxpRWpZbFBNeXpzRWN2eGFLUUZLZXJsUndnUmhPZ005bmcyVVd6NjU0RmhK?=
 =?utf-8?B?SlNEemNySkJObUhiMFFCZnRmWVVHQXQrcDAvS3V0NWtSVEpiMmZveVlNZlU1?=
 =?utf-8?B?dEFDZitRblNTaUswR3pEa2pibkprWml5dm1vM2JvaXVMekFCckNQVCtOamdS?=
 =?utf-8?B?WGhPdlluQStqR2xyU0Qydis4alMvSnhETDBHK3pyNjRzZXFJUjQ0NlpCc3Jw?=
 =?utf-8?B?aDhHcGZJWUdzSXhEekY2U3pyUTEveW92bURUSkhOeDRaUW15SzlzSmFySG1J?=
 =?utf-8?B?R2ZqMXNTZjNpc1p2UnpxZ0NOVmRkbng3UEZ1S2dQaFBGU3diKzVKQjhwUnho?=
 =?utf-8?B?bFZJZDRoSUhkKytBZUVNSU04M3JZZDdXNlRsZmhMQWhTcFd5MXhRTXRXU3pE?=
 =?utf-8?B?dnRjT3c4R1pWcXJQL2wzN2R4WDFtWEhBMlJkYUc1TFEzNmRKRVYvMjRPUGdF?=
 =?utf-8?B?VU12bEdPWFQ0N041UC9jUzVaUVVKSXFpSkY2V1pwLzhhTVZPSjNOMUx3QTJk?=
 =?utf-8?B?R1R3a2xiWm83cWpLRGNJV3NrZFJuYnJRb1AxZzNhc3BVRC9sN0FsOEVNdS9u?=
 =?utf-8?B?QUp6U0dpK1lIZlJNTTJvQlNjSlB6V2VqMWRndmxDem92cVZvZkpUbE5hTUdi?=
 =?utf-8?B?a2hFNTZoZi9iZXdLSUlpUm1ORmdNV25vV0x1K1JIenN3OG9yZEN4MzRkUFQw?=
 =?utf-8?B?UEd1ek8vSWJpTW5lVTFWenhzOExwMFhtMlRwUkJBZXdwQnQ5aGZkSElsQmlI?=
 =?utf-8?B?TzRZWERiVm8wcU1DN2VqYnR0UTZuVEFJaCtaVHZFbTlVWkVGNThLbWRvUTZn?=
 =?utf-8?B?RzlKQ1pKaHhCZzAyUUlNbjJBVE9xOVN4U0pmTmZzc1ZOQmJyS0s2MWhZdjMy?=
 =?utf-8?B?YzM3Tkx5MEFieTd1azZTZnZpb0ZZNjdpV2tsSWVIVmxadmlJUWxYZ2VMMXlD?=
 =?utf-8?B?bXdnNytPYXNnNTVsYWc0Z3dhVGk3SS9XNVJQMnU0Z2t5Mk1nbVAxY0lkVm5w?=
 =?utf-8?B?T1NrQzI1QWI2a1BtYzllQURNNHVwRHdoaWZLYlpjTlV6QnpnVWZ0UVNEVy82?=
 =?utf-8?B?UTdUZ2k4MVY5cEhxc0lRRllFaGo4KzZwYmFyU3pqdkZQa0Z1ZVoxb3RKNFFW?=
 =?utf-8?B?NWpYaU4zQ3dHRW5GVDI2dFRpVHhLUUw1Z1Q2N1VTVHd2ODBPUTZoWTUxREpy?=
 =?utf-8?Q?j3rocLC6wdDQ0B0l6tbv/qxA+?=
X-OriginatorOrg: amd.com
X-MS-Exchange-CrossTenant-Network-Message-Id: af30a825-6e02-400f-9192-08dbcff94967
X-MS-Exchange-CrossTenant-AuthSource: DM4PR12MB6280.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Oct 2023 16:42:58.9741
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 3dd8961f-e488-4e60-8e11-a82d994e183d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7ubtQNYmqU+L8u38Cu2mOH5Km2C6SnVc4s03xDJhPcoyt5ADYdthvEmc9+VjzhTMWkaKeVgdXW+0q6A+3VNMPQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR12MB8478
X-Original-Sender: hamza.mahfooz@amd.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amd.com header.s=selector1 header.b=pd6D9nL9;       arc=pass (i=1
 spf=pass spfdomain=amd.com dkim=pass dkdomain=amd.com dmarc=pass
 fromdomain=amd.com);       spf=pass (google.com: domain of
 hamza.mahfooz@amd.com designates 2a01:111:f400:7e88::60e as permitted sender)
 smtp.mailfrom=Hamza.Mahfooz@amd.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=amd.com
X-Original-From: Hamza Mahfooz <hamza.mahfooz@amd.com>
Reply-To: Hamza Mahfooz <hamza.mahfooz@amd.com>
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

On 10/18/23 12:22, Marco Elver wrote:
> On Wed, 18 Oct 2023 at 17:32, 'Hamza Mahfooz' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> kasan, kcsan and kmsan all have the tendency to blow up the stack
>> and there isn't a lot of value in having them enabled for test builds,
>> since they are intended to be useful for runtime debugging. So, disable
>> them for test builds.
>>
>> Signed-off-by: Hamza Mahfooz <hamza.mahfooz@amd.com>
>> ---
>>   lib/Kconfig.kasan | 1 +
>>   lib/Kconfig.kcsan | 1 +
>>   lib/Kconfig.kmsan | 1 +
>>   3 files changed, 3 insertions(+)
> 
> Do you have links to discussions that motivate this change? This has
> been discussed in the past. One recommendation is to adjust the

Sure, you can checkout:
https://lore.kernel.org/amd-gfx/CADnq5_OyO9CHqahFvdnx7-8s9654udgdfhUntyxfjae+iHey0Q@mail.gmail.com/T/#m5d227dc1ef07b1f4953312287dce4568666c5e09

> build/test scripts to exclude some combination of configs if they are
> causing issues. Or we increase CONFIG_FRAME_WARN if one of them is
> enabled (KMSAN sets it to 0, 32-bit KASAN increases it a bit).
> 
> That being said, we're aware of KASAN having had more issues and there
> are some suboptions that have been disabled because of that (like
> KASAN_STACK). I'm not sure if Clang's KASAN instrumentation has had
> some recent improvements (we did investigate it, but I can't recall
> what the outcome was [1]) - maybe try a more recent compiler? However,
> KCSAN and KMSAN shouldn't have any issues (if KMSAN is enabled,

This patch was initially motivated by KCSAN (i.e. I am able to get it to
blow up the stack with a minimal .config). I don't mind dropping the
other ones since I only included them because Nathan implied that they
could cause similar issues.

> FRAME_WARN is 0). And having build tests with them enabled isn't
> useless at all: we're making sure that these tools (even though only
> for debugging), still work. We _want_ them to work during random build
> testing!
> 
> Please share the concrete problem you're having, because this change
> will make things worse for everyone in the long run.
> 
> [1] https://github.com/llvm/llvm-project/issues/38157
> 
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index fdca89c05745..fbd85c4872c0 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -38,6 +38,7 @@ menuconfig KASAN
>>                      CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
>>                     HAVE_ARCH_KASAN_HW_TAGS
>>          depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
>> +       depends on !COMPILE_TEST
>>          select STACKDEPOT_ALWAYS_INIT
>>          help
>>            Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
> 
> This also disables KASAN_HW_TAGS, which is actually enabled in
> production kernels and does not use any compiler instrumentation.
> 
>> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
>> index 609ddfc73de5..7bcefdbfb46f 100644
>> --- a/lib/Kconfig.kcsan
>> +++ b/lib/Kconfig.kcsan
>> @@ -14,6 +14,7 @@ menuconfig KCSAN
>>          bool "KCSAN: dynamic data race detector"
>>          depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
>>          depends on DEBUG_KERNEL && !KASAN
>> +       depends on !COMPILE_TEST
>>          select CONSTRUCTORS
>>          select STACKTRACE
>>          help
>> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
>> index ef2c8f256c57..eb05c885d3fd 100644
>> --- a/lib/Kconfig.kmsan
>> +++ b/lib/Kconfig.kmsan
>> @@ -13,6 +13,7 @@ config KMSAN
>>          depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
>>          depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
>>          depends on !PREEMPT_RT
>> +       depends on !COMPILE_TEST
> 
> KMSAN already selects FRAME_WARN of 0 and should not cause you any
> issues during build testing.
> 
> Nack.
-- 
Hamza

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c7a80dc5-d18f-4a7d-915b-1803cc3e33ca%40amd.com.
