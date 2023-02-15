Return-Path: <kasan-dev+bncBCYIJU5JTINRBYVJWSPQMGQEZ4CDVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id F2F6C6981D7
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 18:22:44 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id n3-20020a654cc3000000b004fb8d5b8aa8sf4122585pgt.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 09:22:44 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1676481763; cv=pass;
        d=google.com; s=arc-20160816;
        b=InsHSQ203rxLfIFIQ2J20Xzu3cfQW89oW7bxtoFUe/Z+W0JP+XJ0nEFov1XADz7taG
         czOFZdwWCwfPosQ1eU1/JEHAHXoKmYLofkoTz7E2dx2Xa22HR2KAAyWAsgf24yEFsmHs
         UTlAIuz6hkmajyNIkUrNvG2FGJI7k8w5WthpTX9eF2geZNy+VjlDjs7Hg2w873LEXUbh
         u+aE8B6YXt5jWgDsgLI7utyCw9nYR2T/WOOLPw1IgEizMvj2ReY9eNs6WLRhMOdlsRqu
         FK+BZMu7tm/e5q8/P/nU/fDKEyU25TNK0cgCx+9vQQPDDOZDjB5tHLTBwZKDds3NCMs0
         YCtA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:in-reply-to
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:sender:dkim-signature;
        bh=U/ndUZBdadua3Yp/ULJuD2zNvBHiGkyfgvbRd4rdFMQ=;
        b=WzR4cuCgHxBk74HZMPHvPyIZROSR4SRR5koYmFnzsCjzarNDA6EVhp7Q78f2E9E+Oq
         oCgreSysLXGs9AgEVM8puuQnoCTOk2KylJQ284Tw44QeJFZRAzwQKEGrihLBzlHVEYmA
         b+vWQjcTDpCh0+bB67m6H0EZZua9QE1qMkB1Uf7KALe90Snb5nG3LdXfjO9b7/4Zfpb3
         xPoa7rTIdLU2Mm+BORH743Gk+20foeAiaR5xORUb04aNUOTxNYduzVabveulCO/e6vki
         miNaiooVWH18HJfvp01uyN7hMaS+JGIHIJwMhnlssUz/lsPgNytVGrHtHRDD/nRhmE8K
         UfZw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=hSx9ubI1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="bxx/9iNm";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:in-reply-to
         :content-disposition:references:mail-followup-to:message-id:subject
         :cc:to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=U/ndUZBdadua3Yp/ULJuD2zNvBHiGkyfgvbRd4rdFMQ=;
        b=j7yAv178e9A+llffds2dWOmtNFltJJ3f/ci3odiDdotGK1aEXNUANSHnWEMIUmlAT7
         UB2EhfcTI3DAXNKH4/z7O2OXc1EcEeIc7iEpaG9E6OWbhmnvDpqUNh89rZ9ugS9c5vLy
         YkMyaDeOfIKMRk5vx1BY6bQon7AjcvmPV41tdzYkbFt5fZLhySTOZZD6lCJMDLjFnV38
         IorEfvquVe+qOLzfrTy0q0aduytu/DiM1xu8IQvQDO6cUbpRVOUWLYGQHXNGyBcrMk5U
         wsklWkXrcpUZPEniIsC6tO36QK2IhS4GMy/qJ4J/6eGy3D2EO9TYn0//Q2eGWbX3DmCP
         SyBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=U/ndUZBdadua3Yp/ULJuD2zNvBHiGkyfgvbRd4rdFMQ=;
        b=iEoiP0WkuX14SSo9l4GYnMVnd+4FOqdee6p0+J9C2hncwQH9BaTWrLgAwivQ0MD5AP
         JuUcpeWZZnvdIolNdNJf0KwrV8sV8nsh0pW+wr1muLYbv/zpUbo3uAe1DGZ549WqYKyh
         EoUvFxVISZVXweCuv/OFt4Wq90rraLTA3WxrfOg0Sh1Jg4tHUGdxKbS8ItkFEKQ6sShL
         8db80YoOZZpxUMIRsJlRw1VYozv6uVi0RSCfZObDhAsroZhav2Gf1evHiTeCEORhpPto
         9hb09B+1gMzGrjgptb9bwOkCJGlVJ3vp5y8GqRNJsr5U6b8YyWGiRduQg/bNFFeR8VVf
         LOzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWZKgMJqbaRFdJnHw/e9+vwTArLuuw1lOWVys72z+9i0Jisb30I
	2ZfII3hkLzolvzvKmD7unNU=
X-Google-Smtp-Source: AK7set+2tjoXIdN3AkTOauadGLwizNnYjA82rz7mpGzSgCEpBjVS2Ufo2fJ4fAgTHX1BkGDTMl8zcA==
X-Received: by 2002:a17:90b:2249:b0:233:c407:8b47 with SMTP id hk9-20020a17090b224900b00233c4078b47mr5228pjb.67.1676481762188;
        Wed, 15 Feb 2023 09:22:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c8f:b0:233:cf4f:61f4 with SMTP id
 my15-20020a17090b4c8f00b00233cf4f61f4ls3154678pjb.1.-pod-canary-gmail; Wed,
 15 Feb 2023 09:22:41 -0800 (PST)
X-Received: by 2002:a17:903:785:b0:196:1139:39fc with SMTP id kn5-20020a170903078500b00196113939fcmr2502242plb.56.1676481761074;
        Wed, 15 Feb 2023 09:22:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676481761; cv=pass;
        d=google.com; s=arc-20160816;
        b=jZE1YTreE91ZL9oG/tnKK+pU9shHg6P4mvtXmrQa8xaMrPag8EDZYDRpETV3oGqfi9
         x/z6eCts7nYQD1rP1Le1S1muYjByS2r5hwSuWcY1BKbaiVA9YeC7y4mjNVsdOa0pvl9w
         xET/ggmHxAVaSyLbuMhR0xVtgySKSsQGSXHutkyNG2dVF7bGgPsTvWwwRRVrACyOM01Q
         hzjVjcZjDf0s9pwZECn65mufwRbxA7q0XqK3SA/T8947jxvncWYO+jcMR5JHMQ9YkDW/
         DLzAv88sVRbZU4kcE8CONKPt7TB5p+S19Nj2PNCfIzxemCmDJW1sil6TaKIegS/2Xqxl
         5NOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=m5cg55FRJJOr+DWn70aVHkHFBO5wl1Ew2m5Q09vUVFY=;
        b=W8s9Ez1IogKljpL50yBGgr3htWSeVPBPDeDQq9teN8ur7Isxpd0lwjgaYOXgBNc8KD
         zJHPEGkghnO25HwcefSLr8coRxA1fhZUOrTMZ4tYeZ7E3U3DbV5uEmrSnkg32mE3KHnM
         TxYzXdQhApa41IEgH9pZJz6FQgKYCIL8niyG0cYoDv4yWrKGzZCWvro1eNGddGov/vb5
         QF+rOI2PQ0SyqA1SQ+SJxX1tuJns32hzXl4ycQgzFEkeLIB10bF7QKBjx+zFsM1iAwog
         1lCzfXH1Nn/vnusEtxQDATi0yfSdUiRy7z9ORLnoZueyAjoaaCTBClA5EZzgWpsG4s98
         BjGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=hSx9ubI1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="bxx/9iNm";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id f4-20020a170902860400b00199482e6f8dsi1267934plo.3.2023.02.15.09.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 09:22:41 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 31FH4iNe014000;
	Wed, 15 Feb 2023 17:22:32 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3np1m111g2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Feb 2023 17:22:32 +0000
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 31FGFdtf013504;
	Wed, 15 Feb 2023 17:22:31 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12lp2169.outbound.protection.outlook.com [104.47.55.169])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 3np1f74sv1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Feb 2023 17:22:31 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TtdDI55NSetPlq93kWAhUmQ0TlV1ms323bqVlWCqhcusgbFhaSSEsXRXmaPThk36LY7yFLq4qWsYXZmdRmRL4giqFZS5/0Ime4YE1X3fivOlnRktVSop8Z1jAovLiTjUa1+cuSbZa5pzh808xrAP+L0w2ZeJpyjXE8I0MrQMLOq7pVmEsZJChGzEB+ApwVqEf/Ab0MBuENbjTrIRjiLTmpBIWjekhS1sxJEAvI1VP3E3HviuUt4radn5DwRJTcBPGMHm8304/6QRivyEScyP91Hl1jphCPON6nsTb1g3cvr3+GWKAAXqfCWZ7smw+r0VE/vUbB8HamNxN/EJnzJETQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=m5cg55FRJJOr+DWn70aVHkHFBO5wl1Ew2m5Q09vUVFY=;
 b=K8r6A8/L2TgdE/tYfPGfDq2I8t1767GxLBha5mV7MKPaplpJflN5dXvehv9+5RPAC2Wm6JzKXSU/aqqKQDz9+I6wh3QHcRIibVAUVCRpwdS41ClG2/il6gjFC4tUh2f7eBkq42wb6jHibqQI+7m9jP6raI1NdnMeCa8++iy6z5A28RjyWuGYQBCy70lgtbw++snAX+oy2NJxR5wLrX8Bz5JOQVpBQ78veeA8k6AaOidAZqUBXhv/avZkRSYF+9ZCmd4p7G0srmwhDQSihcJ2G0JO1bLzgroMlioX31MHNFD7+KA5NhrEAJ1fwSsqUIG31Rie/KyywSQ8eREp1ryS7w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from SN6PR10MB3022.namprd10.prod.outlook.com (2603:10b6:805:d8::25)
 by SN7PR10MB6363.namprd10.prod.outlook.com (2603:10b6:806:26d::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6111.10; Wed, 15 Feb
 2023 17:22:28 +0000
Received: from SN6PR10MB3022.namprd10.prod.outlook.com
 ([fe80::7306:828b:8091:9674]) by SN6PR10MB3022.namprd10.prod.outlook.com
 ([fe80::7306:828b:8091:9674%5]) with mapi id 15.20.6111.012; Wed, 15 Feb 2023
 17:22:28 +0000
Date: Wed, 15 Feb 2023 12:22:24 -0500
From: "Liam R. Howlett" <Liam.Howlett@Oracle.com>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
        Vernon Yang <vernon2gm@gmail.com>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Subject: Re: [PATCH] [RFC] maple_tree: reduce stack usage with gcc-9 and
 earlier
Message-ID: <20230215172224.joi2edqzippydiet@revolver>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@Oracle.com>,
	Arnd Bergmann <arnd@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Vernon Yang <vernon2gm@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
References: <20230214103030.1051950-1-arnd@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230214103030.1051950-1-arnd@kernel.org>
User-Agent: NeoMutt/20220429
X-ClientProxiedBy: YT4P288CA0016.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d4::29) To SN6PR10MB3022.namprd10.prod.outlook.com
 (2603:10b6:805:d8::25)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SN6PR10MB3022:EE_|SN7PR10MB6363:EE_
X-MS-Office365-Filtering-Correlation-Id: b2a62027-1e87-48fb-8b4f-08db0f793690
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: iLSlcpzhCbrOtI9I5X6sREkkwaFk3G/F4C4YRaKHNtq9yFcMdP0WczgXIoFls4rzExCxg33kXx4nxT92/MmFhf9+zpssm8LDdMh6W2qbfvvQrUi3l/G1BW6LWdD11Z666HLzpRg+Ezh7II27rLIwLOcG2FAPGrOP/pdA42uLxV5SFBWhdzFl6WJ58WAC/3p2f2ifzNN9O0XhrwE+q3ySz2zUxLMVn9b3RnlXmoeKVc6wugsSjZevxWbieamasLora7mO0mZcKqIc6vQlixTgHbGQP25QW2K8NQYBBYYr9Ah2c5FrUQACGzeUlnaKuu3IZRLXJoAea72BnG7GKrmIqx/Yufzc+foT4XiyfwarJVjuohiceUREd8uCgRGnXVK4MjJYjZgh0SZbyHeFUrDCbkNkg6dHsaAFOKG3ZuSV50O7q9Zm8hgtXgtgrk8TeOmLenxHRlb6+o7PyzINlUzikm0zmdE4HxGx1QIGzpPWSP8OoImDub0tWtgNfcVGwVHjo3n7KaG8Sg42o33NEnD21oEpII7l8IqHumlvAT6iNoC5repDj79i++MNCH5T4aKxyVXRszWwiIcPw1uvp75bJTIQGyxsYOS674wdIOlYLDine8beI/hvYC9zk9YhLsF0OtYvRCcDYr7Vpk94Pc5Irg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SN6PR10MB3022.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(7916004)(346002)(136003)(376002)(39860400002)(396003)(366004)(451199018)(478600001)(8936002)(316002)(6512007)(186003)(9686003)(38100700002)(6486002)(6666004)(26005)(7416002)(5660300002)(1076003)(86362001)(6506007)(2906002)(54906003)(41300700001)(6916009)(8676002)(66476007)(83380400001)(66946007)(66556008)(33716001)(4326008);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?c5s3iJUXfviX8jg7DIt7PjLL26CVklehs/vBiBmHdJo4SW6EaKpaeWzasN6r?=
 =?us-ascii?Q?/BNC4JsJt6DwDHbt6DI5Vt474OyrBDPj7rAc8ZZRufY1uzNVZnD1C3CTTEVJ?=
 =?us-ascii?Q?8k5NgorUE8VccpPslk3d7FL/MIr86Q4GCdWQqqG+7xQR2SOYsdc430JEw+rz?=
 =?us-ascii?Q?sYM2mTnW044vjoANV3m1dxkRWpe2uBIST8FQHAyWHVTYyQKfB+Cc7mMmLLGA?=
 =?us-ascii?Q?taLHrhrvNo421ibrEBzXpX3VD+pD3H2UX/excSxetabys9wix2W6NyL6P9lP?=
 =?us-ascii?Q?JID1ekAmJPvmEWm8/nQgrpt0sX1PK0GYjxXAc3iuuQYnab6KOkcWVn75bLm0?=
 =?us-ascii?Q?JyR4A2YAr4ryMnuzb1Hl4TmufReiYxpxN5HfvQNA4GBG8aCGTGqjSbbZnd5J?=
 =?us-ascii?Q?PcFXVryvejPNzQwuMdKPD/02wvYPmxZDgVkfX9IYieihH4rh2ZBtO/wTvl0b?=
 =?us-ascii?Q?Z9VOyGvSm/qUDE0mWfVa4PgLKAvUmn3dCpHbjI41iYoz2Knxzj9tCWLbwINT?=
 =?us-ascii?Q?rrMSbOHlxmfgNw8hXw32V+TU2iifmr60/V5FzsaSD5Uc8+Z0krAMadK/4IPt?=
 =?us-ascii?Q?P4RIZ2RrxPHgfrImquCZAPTvJ0wsZmcI9vkv9jgYgt8SSOdCehTPFzuRByG2?=
 =?us-ascii?Q?WzqD1FA2K8XJhA7wqsiSCS8j71wAH5zmBYi1fdVA8INXzMzzM+JajmCLc0nz?=
 =?us-ascii?Q?fF0yHbSGPippoy1L8PHeK6uOrl1Z6w5TAaKGLhjFlKVhYSZ/BSZCRG0WutCd?=
 =?us-ascii?Q?oaVI3BY3FZCOJjEyj6gQEWaB8cRnl0RYGJ47/XZo9l/2nrChL4r6O5/kB3t1?=
 =?us-ascii?Q?eyQV06fZNgYNb/hwOR4fiOho/br+0jy9eVRwpWklbBwcxRqISkYxDZEsxBzA?=
 =?us-ascii?Q?ebSL4+8y7KPHFmK9kufrFbP1UOzvSmHaipWfKKyfnmrxP5NJASoIJlf6SOHo?=
 =?us-ascii?Q?txv9zbVvY1FsSjUWzKHKRNZ+U8aKIExZNjr5Z2dVZ8aXvFZMqWaKy/KAbfBh?=
 =?us-ascii?Q?js2/VafviQ2OroFmHPiv1dC1RzF+LF/Qhl/lLjQB/Z7JHwzDgcotoJN2vSHK?=
 =?us-ascii?Q?/QXYaAKVofFlsMMo5K9+qgDfm/s85nVmzont9U/xVfwg6k9TIqnGQfJXaIP6?=
 =?us-ascii?Q?0mmbysDDD3KwZ6ZJhizBi5WBftt9NlPum9L1DUzfRcRCFQm5ilQJwVBr+r3s?=
 =?us-ascii?Q?QpFHC8xVFUlcS9EG7afYVddhQoJeNwZm6OOuHf/V+xgdE/zDgviqlMr9WzB4?=
 =?us-ascii?Q?+6wwbuXQMtxWJYZOTHXG4w8vkTjzQR1j28S3KDIesOFVW9xTAAToGq6daC0K?=
 =?us-ascii?Q?Pa58oElPuhGeBeI9duBNBWlGKexKABqjUxSZkIRbe0XvQ3ecgNwVUmZwpB/z?=
 =?us-ascii?Q?OLz5fYnLgR26KY1mU9R3z633Dg0dRRxwtLs1hsOzdJ3ADPYq+nytLFHtrU0e?=
 =?us-ascii?Q?ZPkNoza2P36BlM27Ru/hYqmdTciXwxRJP/H7wo/JZFvC7yOrI0+DMUcDUqRp?=
 =?us-ascii?Q?9Rr7/UWfQSlRdvMawRJdC84b4oN+7PIZHW79avyR0TzafK3cgR9x4W+ao3DU?=
 =?us-ascii?Q?Vrhspuh4zfyYZXZgy0RyQpiJaSAcJTbdzO8S/2gF5cB0soD6HYHdzza8bAcq?=
 =?us-ascii?Q?rw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?us-ascii?Q?w7q3qc7NadnF6ITpFrbFwaFYHZQ2sDMxDnzv4c52KrOAGsQWGpmvrocITiDZ?=
 =?us-ascii?Q?f+x9fObMSQ1zycwzcMtAcSPu6APK6y7FjqodJNq0PWLzwcq9Kfwm/TwQ5FjW?=
 =?us-ascii?Q?fwYjYVLJu9cczOhrPckE4IChBmABQBJkojWNQcG6YBDQSLn+E96cEA3SwodN?=
 =?us-ascii?Q?DqjdXIFM2Is25NgK/3EsUiHXsn2lkJt0AvGn0RW4UPZPSovARyEMMNbklTfb?=
 =?us-ascii?Q?OTPT5Mzix/wWnQ3KYrzxeQQQGxJEtGQ831+XkeAIIrKPDxZtJmYvVCd6kLN8?=
 =?us-ascii?Q?5o6PXkcMLesfCsoM8WPevog9j9oSK+mb2X2AUZBNpqZpjdpcIls0YSDcKmrb?=
 =?us-ascii?Q?AiXKiB6AxqSRVLp+vcCGmJPnbVFU9/iRKlhuusUSh1SkyyrEBlrSJetYf2DP?=
 =?us-ascii?Q?YR+/UsTrYxpkA5yVKM6zwC+zPw3VFjAw4Sc73/QPzn5wQ7F75DqbS1J1FhNC?=
 =?us-ascii?Q?NKEw5h2d4bRwT8uth75lmbiQM9x4uW9W6tj/vh9QJYjpmRCw4WLBZPqjPgdL?=
 =?us-ascii?Q?okgEdXl0sE1pX7ic19FkvdrNv0hikOev+R5EAUellgbwA5O6YAZA+zlKxFLB?=
 =?us-ascii?Q?2eCnXohZ2yHWIDvPRDiL4bCaJMjfGXL1I4dmt7HAE4+xWFHmp6VzGDKkv/9U?=
 =?us-ascii?Q?sHaRqJN4ZVjRIefly/b6jP0F+TQrwOCPV7rNEjBEbQgpKjDjJU9d2iDFntbH?=
 =?us-ascii?Q?vENGv52vgIV4VJUe2n5ANwa1423ejXT5j5iQhLYolsDiyKcqr0dxcegLKzV+?=
 =?us-ascii?Q?rCZ0rNXeFkWUWGWsK2pwRQHc4VYa53lfNiMYs1f5Q345VZhqlZLYpa4z5UHv?=
 =?us-ascii?Q?VaUwVY8aiaYmuAA2JUt64n7cFhNmCE8w3nW5h++qXay7vkHI0L7hJzVK3Cqc?=
 =?us-ascii?Q?igfkU+/Bd01iPPxNDhgbYKjr1qfbp1pKrN0t+RDY72Q0aLVLzhwVLOcYbVfv?=
 =?us-ascii?Q?xzq29IQLRhaX4yhMjJ+BsjAFpeORoeqsaF9xS4UOY4WlaJVS9W/Dv294xwlX?=
 =?us-ascii?Q?pOz7gD8PKFQxOQAIKjSaNHKKcg=3D=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b2a62027-1e87-48fb-8b4f-08db0f793690
X-MS-Exchange-CrossTenant-AuthSource: SN6PR10MB3022.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2023 17:22:28.6458
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 71s4o2EnS1YHHZZV9nRNNBAEucbDyTOid2gYH7R3TdobeHNJY6qjMMM/abuSuU1LzDBgcnspVTTb0c4H2MDnmw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR10MB6363
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.219,Aquarius:18.0.930,Hydra:6.0.562,FMLib:17.11.170.22
 definitions=2023-02-15_08,2023-02-15_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0
 phishscore=0 spamscore=0 bulkscore=0 mlxlogscore=999 malwarescore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2302150155
X-Proofpoint-GUID: SFosIgNU2Sr1V3BfzGb5PVsM1FIxghMT
X-Proofpoint-ORIG-GUID: SFosIgNU2Sr1V3BfzGb5PVsM1FIxghMT
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=hSx9ubI1;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="bxx/9iNm";       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

* Arnd Bergmann <arnd@kernel.org> [230214 05:30]:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> gcc-10 changed the way inlining works to be less aggressive, but
> older versions run into an oversized stack frame warning whenever
> CONFIG_KASAN_STACK is enabled, as that forces variables from
> inlined callees to be non-overlapping:
> 
> lib/maple_tree.c: In function 'mas_wr_bnode':
> lib/maple_tree.c:4320:1: error: the frame size of 1424 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> 
> Change the annotations on mas_store_b_node() and mas_commit_b_node()
> to explicitly forbid inlining in this configuration, which is
> the same behavior that newer versions already have.
> 
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  lib/maple_tree.c | 11 +++++++++--
>  1 file changed, 9 insertions(+), 2 deletions(-)
> 
> diff --git a/lib/maple_tree.c b/lib/maple_tree.c
> index 5e9703189259..646297cae5d1 100644
> --- a/lib/maple_tree.c
> +++ b/lib/maple_tree.c
> @@ -146,6 +146,13 @@ struct maple_subtree_state {
>  	struct maple_big_node *bn;
>  };
>  
> +#ifdef CONFIG_KASAN_STACK
> +/* Prevent mas_wr_bnode() from exceeding the stack frame limit */

nit: Should there be more info in here?  You did add it to two functions
and it's a problem for frame-larger-than=1024

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>


> +#define noinline_for_kasan noinline_for_stack
> +#else
> +#define noinline_for_kasan inline
> +#endif
> +
>  /* Functions */
>  static inline struct maple_node *mt_alloc_one(gfp_t gfp)
>  {
> @@ -2107,7 +2114,7 @@ static inline void mas_bulk_rebalance(struct ma_state *mas, unsigned char end,
>   *
>   * Return: The actual end of the data stored in @b_node
>   */
> -static inline void mas_store_b_node(struct ma_wr_state *wr_mas,
> +static noinline_for_kasan void mas_store_b_node(struct ma_wr_state *wr_mas,
>  		struct maple_big_node *b_node, unsigned char offset_end)
>  {
>  	unsigned char slot;
> @@ -3579,7 +3586,7 @@ static inline bool mas_reuse_node(struct ma_wr_state *wr_mas,
>   * @b_node: The maple big node
>   * @end: The end of the data.
>   */
> -static inline int mas_commit_b_node(struct ma_wr_state *wr_mas,
> +static noinline_for_kasan int mas_commit_b_node(struct ma_wr_state *wr_mas,
>  			    struct maple_big_node *b_node, unsigned char end)
>  {
>  	struct maple_node *node;
> -- 
> 2.39.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215172224.joi2edqzippydiet%40revolver.
