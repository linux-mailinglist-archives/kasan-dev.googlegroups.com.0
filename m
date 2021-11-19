Return-Path: <kasan-dev+bncBCLMXXWM5YBBBS5O3SGAMGQELOQNV5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A89FC456889
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 04:17:32 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id s18-20020ac25c52000000b004016bab6a12sf5586181lfp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 19:17:32 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1637291852; cv=pass;
        d=google.com; s=arc-20160816;
        b=TXXvafB1SeoybBES2yJYO+h01Pq91sAWLVhL6isa8mrouYUBLkG8ZEJ/MyhYHex/5q
         AA3v3WLcOg7ChL9shRB65rli2y6AIQpDz3k16+uySLtKZmnKbDbzCCs6VGNLsB9CcUVF
         AXISINxZn/Vp0QY8V0EOLtdr4QhMeVt2QE0nVepj7XcZj8AtHM3b/hWt6FFzMqwJ8vaO
         67qMC8rkOaWOeCLB7OoHNTYETWicydV+caJfOJBLjSlboj04W20cgSGswbLeIOltkHao
         8phdhj6KnuoswoAScd+F81+vr28Y2veZRI6b8Ysh39whYVlcHPQoCaquclfGN+TuHRgY
         ACWw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=cE520n3W0hpX6L09JonHGpIXoTnJN/OkBNOA8OYasp8=;
        b=hCKdwmMph8LwUG7lRqxZ49MhKHjKh1PsVev3bWUcibWFajdXspAYnnjQfJOt60hwon
         dvhaVWqBjNxDF/e11rgu2Q1jTIl8HrkTprRjpA63nLqZw5n1sic2UKZLSYZD0NFW25Oy
         plbFw7owz6HHWclONeIar5q/tDlOvIgSMn6jToWPHpyORqsFjFYlSEe3iYrdznjVj0k/
         2SRM5JP0V/lMLVpQy92Q9jlVjMzDuKQLasyg5Pt8j7PIIrRniaKYQPySwDDdwLlhlGfm
         NipB8sRShW3PwcRV6WSValqt4QDAkrryItcPngJy4MCs4PhnnNMgXFX63uAonJx7MDqp
         WALw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=0kdpbDLb;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cE520n3W0hpX6L09JonHGpIXoTnJN/OkBNOA8OYasp8=;
        b=jy/VYz8JByV1I2Wk9Gx4q+8urmPjnrjpQg1PcJGhDAtPrcLBIe7TEKH3dJr6urIXi9
         GxzU5vcBn0WyLKdfWuSmhAkTRq/SIfzQwWRIG53nT/cFvsGwMUQ3wyCcMerukebdiy+4
         i6Sf3LlOtyNAJP8tmtI/Ownp62jWX9ajJb+4GD4H9QQJZ9c17S+DzkCQfyLMMh3KtFe2
         mdrT6S8Yqc10touW77o6ndRC64jKfoDVqdUhAYNtALe56Tit+32oJiOO/0YL7tICBzrH
         WSvPkMCObeeykuD3A3q+hmspzPIcMsyQ+8tMg2NlBhEhYtXnjTVabEC+rM77BGWxHRdv
         wjkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cE520n3W0hpX6L09JonHGpIXoTnJN/OkBNOA8OYasp8=;
        b=ySA78GNqHM2ZEdkehsweBdhDLVhWMCxCvdtr7Q+ISIqNdmOS5N+/0FfU/LmgUTKsHH
         0Tt0GqOm5kXfJIuHyGpUrbFHdBPNunFnA3T7dIhjTxgowNxeDwgrDlranwvcO8w2I2Fr
         ZftkwGoKi/1kV1nrGc3Tu7pcZSfVO1abf0B/+e78vLnQxHzk4dDUUKG5/9g8c91AFXy/
         osJW62k8m90Cd+fzyc+tNxsHsiKyxaszlO42xK6iYXL6NjLviOhwxuyY7Vs4aZsDNDpR
         XrvS4oEiMDQcwL88mjMV/wR4vsh3ESaQTWlxT9LF6B+IOFIbbZtkM00ArqwVGeLkaJnS
         3urA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304VY/3fL7sNWSJZpJ/s3tIp6t9e99TNFiDSYEVlPeLvYBnCjX+
	mcphtIvy7OXdSroPqHv82r8=
X-Google-Smtp-Source: ABdhPJzl/uPdMNi82Kc6oy1Hw1ZC2GWuAuxXD3ZjN40aKSTSLASugMqsI2o4QaYAwH7hPez/d2TWOg==
X-Received: by 2002:a05:6512:318b:: with SMTP id i11mr29661756lfe.359.1637291852125;
        Thu, 18 Nov 2021 19:17:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:898c:: with SMTP id c12ls276368lji.11.gmail; Thu, 18 Nov
 2021 19:17:31 -0800 (PST)
X-Received: by 2002:a2e:4e1a:: with SMTP id c26mr21580737ljb.27.1637291851113;
        Thu, 18 Nov 2021 19:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637291851; cv=pass;
        d=google.com; s=arc-20160816;
        b=rWC6KAj8jcsmJ3GJI8l6Ql/i23Kiu1oPblWqdR7lHLLoz7/8oGjFHtJs02xIF5/r/a
         WCe/RNbavA0yU2VkN8bps0ipL3YmrzFG7V0UVmjsQ28u+JrgXMvtT+TeoZK/ZKFwhAw1
         f5pMiSlz9GZMd3b8s5iRw9Y+gGHGJQ7cUMEFFRWu8fBySDER/Q5B8C6It6u22r9wwAKu
         UhtgwgH7nwsAkm5roDdX7vuvp7VDHMR3JtNYU0jC/9jyMQvhWwfKcLmQ7/IrCIpwY5wj
         KZFSugNn3AI31pRUVrDUeqv9+jZ+UcjuUxHBv+PzF6TDsGuWy09jL6ZxW/VqWzoE9jF8
         wZmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=ivIMLCOQ+De/GuucIgIiVQD9Zpi+OqcF3uzi8N/VnG0=;
        b=dlU7h6xMQgZ7zoWmZ12QsP0nsJi0kr+tn4RBh1Ko1XQ1ErKKFiK0cVW1xSneFsVxWE
         TzIuiRLU8VLLXyyqE4vvyNe/nF388QKtgU5Thp/HKgDKVjFINfCd20jNeqBZiMRuFc7m
         QDlj11WDLB7I+WUy/ayKBpS7KOoZsD27b9xNVuMgNqKYxVJOeCve+QtNYPlML+psEskF
         +30t2WXUhYXnp88tb0rFaDPBNJRSwKTJFH+JUTOq7HkjbvvUCiB3c/rqdOkDvb8z+sy1
         hnYQZ309KAY/91rXxKdsek7p0MjxmBfAPPaTRAT6ILXCZx+mqF+FA9+j+lQE/nofgyEj
         jIPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=0kdpbDLb;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from esa.hc3962-90.iphmx.com (esa.hc3962-90.iphmx.com. [216.71.140.77])
        by gmr-mx.google.com with ESMTPS id v25si105790lfr.1.2021.11.18.19.17.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Nov 2021 19:17:30 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) client-ip=216.71.140.77;
Received: from mail-mw2nam10lp2109.outbound.protection.outlook.com (HELO NAM10-MW2-obe.outbound.protection.outlook.com) ([104.47.55.109])
  by ob1.hc3962-90.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Nov 2021 03:17:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=bUf8rkZogKW6j4YtNc02TFbxm9PlYLB55QH1VUVhQ7b2YGQ37hg3jdVfQplsXKEjDkhCJ+oU3Uf5xv+fJ1QYldzaC5TIgVwDOFPb+67UuY20oEwIBUW6zzGrPpcoaTLmjQT6osdY/0Xdlr+IqP9ECenrIoY6E4Ld1udPZa6rG0De8ufORtbLk+4bJAKUohNnWwKqGxddLYImUPGjWY41zI3FPBtsh1qSOS4++RB2w0gH21fpT3L3cbzUYEix/6yizezCOLvDluAYgjuiBJApGpE+Ol67k3BMArCBTcEshQL8OOUDjdeB+M+twS5ttTw1c+aBwyekAtVmILAwbNo9Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ivIMLCOQ+De/GuucIgIiVQD9Zpi+OqcF3uzi8N/VnG0=;
 b=oe01ZLnlVfM15BNnt/fnWOYLEoAq8+CV5FHhNORVEcJeIJ4V5EakNpRLDrlgacPaQR7SB6+NV7H/lveUo4hnKNEUJx+rTQ6pTgww/ipLAH7asHfZb+2/z6r8zy0qDCkIyx12NB+4y1R+HGD26sZLv922hwyf0yJy+9A/0xdx32YPQBP4jWXLdHfvvVawtvJtmphFOsHIKmOlUUlcy6yEkG3DeYU5z0ITGhjVLnNs+Ex2AAvyX5+oOfl/4k8h8pGuusxBaLiIgbmxdW1uM3VxQdavfSZFgFYbEZz8fRQpSXcV77VF00R4Gdg2fO/yZchYgbZ2wM7SK/P5s+NUmnu0yw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=quicinc.com; dmarc=pass action=none header.from=quicinc.com;
 dkim=pass header.d=quicinc.com; arc=none
Received: from DM8PR02MB8247.namprd02.prod.outlook.com (2603:10b6:8:d::19) by
 DM5PR02MB3831.namprd02.prod.outlook.com (2603:10b6:4:b4::21) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4713.22; Fri, 19 Nov 2021 03:17:26 +0000
Received: from DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3]) by DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3%9]) with mapi id 15.20.4713.022; Fri, 19 Nov 2021
 03:17:26 +0000
From: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>, "JianGen Jiao (QUIC)"
	<quic_jiangenj@quicinc.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Alexander Lochmann
	<info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vD2nRqghWy5Eq5zUX4/l1PcKwJUjYAgAC3OuA=
Date: Fri, 19 Nov 2021 03:17:25 +0000
Message-ID: <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
In-Reply-To: <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-messagesentrepresentingtype: 1
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 0eed4dd8-93c3-4a4b-2b05-08d9ab0b1c7e
x-ms-traffictypediagnostic: DM5PR02MB3831:
x-ld-processed: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d,ExtAddr
x-microsoft-antispam-prvs: <DM5PR02MB38314263921BA7AE764B5754849C9@DM5PR02MB3831.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:10000;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: pVRwP9yAp/Rg4iWTfmLaUx+CTQ4UJxSzo2x8k6MIp0EBU591y4zEVnHI4dGeyEQR6ou0XvBt/ANPzO18RdUETD6oD82aGXRHj3ni1667hSJV8I8cGYsvMempDjWlB6jYpOvoenlVILOX93bkvQTT1FXK2DAyYRgHqEiXd6JXEWqWjJzYZ8K8kFp65iz/FuMNzmOB8K9e04UOcWzj597buEUgh8cI6queDPx3WdlvuekI8/2bgGK9kmWGK/cgJgGaFtG8FSmdvJ0LqJ8DzhtUOKQSQLlMYetDHlPsjoljk8S35FWYuRGmxFEsrff9xTRO/R11aZFwLKi/i4t8Gm5+W2ECrgQEGG3f2TVDKBFt//UJt+wrn+SrN0y16Ba7U3RQJCoYVqbSikfD+6wWw7e4apcWWh8bxKkswGCzV3JD2CaMRCww9C4asv2xx5/3poq7VnTJRzPKVo1hr0JcLBAzSM8HH0B8AqHPonXcPldGU/4s/hMxOXnmGuQ9CfciDiIbFGmzzfsw7kXVuZIKYboFZV8nHs7kgolbE4mgHHGiH9VvByO0eOyJvDK6Ywj7F19RF+aUSGmXjfzPADx/Y3XNb4GxwXnUq7bZeCAHvU+G0VTVHzFaJm9ZNmFt1dNJXBMBJG/8+ywiUi+517qL0BEy+05J080D7sNWUCv7IYdFWnZ7xjWxRqzbq/iyWM6xjn+DGW/XLH2f26k0wNGSqi94YL8paggNWrqckjH1QzXWlZqaio0aUUp5CMmhriceXFBvDflZ+LeFZokYQtp4n1pt+mFoEeLiFcR/lgb1hRmOsIM=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR02MB8247.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(2906002)(71200400001)(55016002)(5660300002)(110136005)(76116006)(54906003)(26005)(7696005)(64756008)(38070700005)(66556008)(66476007)(66946007)(66446008)(966005)(186003)(86362001)(33656002)(38100700002)(8676002)(4326008)(53546011)(83380400001)(508600001)(316002)(8936002)(9686003)(107886003)(52536014)(122000001)(6506007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?RVVWNFpoZVlrSkdkcjQzVzBhMnZuQWdXVWpKSFB5aDE4ZmtXSmtNNlhQc3Ix?=
 =?utf-8?B?QmNISHR3TDEyK052bFZLK3VWSE9PbEJKWms1WGR5eFYxY3VEeTRJWFVKb0t1?=
 =?utf-8?B?cktVbXhUTTEydUpQRjVna0FvU1FGNmpnd2xQZnRXNEs1aE1nYlZxS09QRzFD?=
 =?utf-8?B?WG9pMW84N1l2U3lEMmlQN3lrRlJLRzFOY3VOSDVVNHJ1L0xQVVZGZ0pIeDFS?=
 =?utf-8?B?cTd5TFZxRFFoRUM2WmM4QjliOWZ1RjRmdnNDUzRMSU1OTzdiZ0FVWHhwdUpD?=
 =?utf-8?B?ZXdXYVd6Uys0ZTQyUWJWYkRhd01BblhGMi9LMEgwMW93L3hHNzRLd01UNHk2?=
 =?utf-8?B?Ym9YREJrR0ExQkozdlQycGFYUTlPdU4wWjh3SW5zTXQwaTVVVzF2Z0E0a0pG?=
 =?utf-8?B?NmtWZHhIZ0hKdG1ZSno3a24zNWdrd2VvbEgwY3BZRUZ5MlJlcktUTmI3LzZl?=
 =?utf-8?B?R0hUMFJ6TzYzNDVZK0FYa1NqRzlsZ28xQ3FuTzZaRHladS8rVHduNlVEMW5W?=
 =?utf-8?B?M01Hdnh1akk4Y0NWcWhSc21PdXBWSVA5Mk1QYlVYNGpNZUZyelJ6dlU3TTRv?=
 =?utf-8?B?WVBoM3Z4bWpUREF2WnpOZ0VNMVNESjRVNWhlWDQ3NzZqWFMyYkE3dDR0bS9V?=
 =?utf-8?B?K0RDODlXOFR1MXA5QXQ3ZTZvY3dwRWZpczBESkNsMVlMSEFzQXB6TnBLUkta?=
 =?utf-8?B?UGRhd01KVjRzY01JQk8zdW5SVVhNWHczQkJRYmFhS2w1alkzYkFTbUh5SWpS?=
 =?utf-8?B?RXFhcmpIYWR5UVBSZllSOERVWlRpdWpOMFl6czN2Tkk3b0gyTDRVSlJncnRp?=
 =?utf-8?B?NDFVQTBCUUN4cFg0VnNzaEk5d3J3bWpwVUFPUmozZUIyVlA3c2E1RHJ4NGV6?=
 =?utf-8?B?dzFVOVVBdC9kZUNVKytJRlNUa1RBTW9MVVcvWGxoWURleUdCSWh3ZkQ5bFNJ?=
 =?utf-8?B?bVRLOTF6YWpCeGwxSGdsb0lCYXBPMloxMkdiZUJRY3lESGhGU1A4Nk5nVE1i?=
 =?utf-8?B?eitCN0VXY2thcmEzWm5PZS8ra3ZiY2tXWktacy9WdHlVd0s5N1VadWROSEVO?=
 =?utf-8?B?TXpQZWtGVWlJTVlORWVTZE41RTZ5bmZpTzlvRGNEQmw5Q2IvamRsclBXem5Y?=
 =?utf-8?B?YnZ1MXBTbFFFQjJTMDRYVVFFUDZVOEp1ci8yWXlzeWU0alQ5MVhiQkRqZ0RY?=
 =?utf-8?B?TXBjZXlRblorT29Ia2FhRFBkTEl3aDhNeXNNQW9LOVp2RUJWbHhpTnR6R251?=
 =?utf-8?B?SEl4dXFwSWZGd281WmtpVjVRbmNyQ2dZOVFyeHNmT2Q4M3FNVWVkeUJ2Uktu?=
 =?utf-8?B?ZGdDdDR0QWlFUjJ6ZDRETlQ3MHNOWHJkdXk4c3oxY2FIUWxxZlJ5OWNxTW1j?=
 =?utf-8?B?WU9sR0EvLzBtL1NRZmpQTStxNnl0TzREVnA1a3ZiSFBoNlp1b29GRUZvWnJw?=
 =?utf-8?B?dEg2akFKZEhXaVVjNEw2U0wvc1ZsRm5aNWM0RHBYNWI2MTh1UzFZVVdOb2tW?=
 =?utf-8?B?dlJtMjJBTTB2dXk2Ympkb1JTU0ZDS2gyR01hb1BSM0IwM1ZRRnYwNksxVytv?=
 =?utf-8?B?M0RuKzFxM2hMQzZ1Ny9vN3QzWUZINjhtQ1QrMXlPSHVUL24zSzFWM0FPOXA1?=
 =?utf-8?B?WWJpYmtvR1V3M2NLYjJmdVZraEhpOE9CVS9rQllOR25ZYzBQUHRvZktZWG05?=
 =?utf-8?B?RUExQ29FQk1uTGxiMDA0a2NnQmpNUi93S3RJYUd3YWltY3IzNzU4SHc2dDBa?=
 =?utf-8?B?MnVVRVhmaTVSUHVncjBVZ3FpM0QyT3BMTmYxckZESWMzTWpvb0pqUytTSzYr?=
 =?utf-8?B?YlBwU0FPYTNkU3cvWUgzRlIxTmIwRnBQbjNaMndHajZMd005UTk2cG5sRVlU?=
 =?utf-8?B?Q1RrMnlmZWJadkFzbGkrZ0VMRDRIK1hFZFdyODZCQzN6akFOcWYyY2pWVy9Q?=
 =?utf-8?B?RzJsdFUwM3RLbEtJWlh5ZzlEY090aWlCOXlXUnFoempLOTNhbE1aalVwNHdX?=
 =?utf-8?B?a1VHbzRDb21uekxtejdyOFFMckZBcHhZNGpaR0I3ZE1jMmJwTkduQXNaSlkv?=
 =?utf-8?B?Uzl3VFZzS0l6MDRNMFpmL1MrbHlwTEpYWkVPdUZFQ0k4T1h0Z3o3ME84RG1F?=
 =?utf-8?B?ZVIvQkM0cEgzRVRLYThheWJQTFkwTHlQWkV2UzI5RitEdzc4emJ0TCtSL2Za?=
 =?utf-8?B?a2JKbnNOWTZzQkdQdFhIMTlFZFYvNzh5bHVzZlBNa2JvdTMxK0F3Qm1lMmo2?=
 =?utf-8?B?KytvK3daTTNYalZGNnhkNCs0eVVnPT0=?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: quicinc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR02MB8247.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0eed4dd8-93c3-4a4b-2b05-08d9ab0b1c7e
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Nov 2021 03:17:25.9242
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: lg1vndee/gdKmzAUBlZ2oH4BroLeHPyUyoQRRaprSedWA/M6QATfw6eQhUBs4119s/o9bOta+cjMd4E9h5o9Nk01ZOwx1c15wMnt/MARrrk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM5PR02MB3831
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qccesdkim1 header.b=0kdpbDLb;       arc=pass
 (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass
 fromdomain=quicinc.com);       spf=pass (google.com: domain of
 quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender)
 smtp.mailfrom=quic_jiangenj@quicinc.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=quicinc.com
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

Hi Dmitry,
I'm using the start, end pc from cover filter, which currently is the fast =
way compared to the big bitmap passing from syzkaller solution, as I only s=
et the cover filter to dirs/files I care about.

I checked https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAA=
J,
The bitmap seems not the same as syzkaller one, which one will be used fina=
lly?

``` Alexander's one
+ pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
+ idx =3D pos % BITS_PER_LONG;
+ pos /=3D BITS_PER_LONG;
+ if (likely(pos < t->kcov_size))
+ WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L << idx);
```
Pc offset is divided by 4 and start is _stext. But for some arch, pc is les=
s than _stext.


``` https://github.com/google/syzkaller/blob/master/syz-manager/covfilter.g=
o#L139-L154
	data :=3D make([]byte, 8+((size>>4)/8+1))
	order :=3D binary.ByteOrder(binary.BigEndian)
	if target.LittleEndian {
		order =3D binary.LittleEndian
	}
	order.PutUint32(data, start)
	order.PutUint32(data[4:], size)

	bitmap :=3D data[8:]
	for pc :=3D range pcs {
		// The lowest 4-bit is dropped.
		pc =3D uint32(backend.NextInstructionPC(target, uint64(pc)))
		pc =3D (pc - start) >> 4
		bitmap[pc/8] |=3D (1 << (pc % 8))
	}
	return data
```
Pc offset is divided by 16 and start is cover filter start pc.

I think divided by 8 is more reasonable? Because there is at least one inst=
ruction before each __sanitizer_cov_trace_pc call.
0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc

I think we still need my patch because we still need a way to keep the trac=
e_pc call and post-filter in syzkaller doesn't solve trace_pc dropping, rig=
ht?
But for sure I can use the bitmap from syzkaller.

THX
Joey
-----Original Message-----
From: Dmitry Vyukov <dvyukov@google.com>=20
Sent: Thursday, November 18, 2021 10:00 PM
To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <linux-kernel@vg=
er.kernel.org>; Alexander Lochmann <info@alexander-lochmann.de>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

WARNING: This email originated from outside of Qualcomm. Please be wary of =
any links or attachments, and do not enable macros.

,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com> wrote:
>
> Sometimes we only interested in the pcs within some range, while there=20
> are cases these pcs are dropped by kernel due to `pos >=3D=20
> t->kcov_size`, and by increasing the map area size doesn't help.
>
> To avoid disabling KCOV for these not intereseted pcs during build=20
> time, adding this new KCOV_PC_RANGE cmd.

Hi Joey,

How do you use this? I am concerned that a single range of PCs is too restr=
ictive. I can only see how this can work for single module (continuous in m=
emory) or a single function. But for anything else (something in the main k=
ernel, or several modules), it won't work as PCs are not continuous.

Maybe we should use a compressed bitmap of interesting PCs? It allows to su=
pport all cases and we already have it in syz-executor, then syz-executor c=
ould simply pass the bitmap to the kernel rather than post-filter.
It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander proposed =
here:
https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
It would be reasonable if kernel uses the same bitmap format for these
2 features.



> An example usage is to use together syzkaller's cov filter.
>
> Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> ---
>  Documentation/dev-tools/kcov.rst | 10 ++++++++++
>  include/uapi/linux/kcov.h        |  7 +++++++
>  kernel/kcov.c                    | 18 ++++++++++++++++++
>  3 files changed, 35 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst=20
> b/Documentation/dev-tools/kcov.rst
> index d83c9ab..fbcd422 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -52,9 +52,15 @@ program using kcov:
>      #include <fcntl.h>
>      #include <linux/types.h>
>
> +    struct kcov_pc_range {
> +      uint32 start;
> +      uint32 end;
> +    };
> +
>      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned lon=
g)
>      #define KCOV_ENABLE                        _IO('c', 100)
>      #define KCOV_DISABLE                       _IO('c', 101)
> +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, struct kco=
v_pc_range)
>      #define COVER_SIZE                 (64<<10)
>
>      #define KCOV_TRACE_PC  0
> @@ -64,6 +70,8 @@ program using kcov:
>      {
>         int fd;
>         unsigned long *cover, n, i;
> +        /* Change start and/or end to your interested pc range. */
> +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =3D=20
> + (uint32)(~((uint32)0))};
>
>         /* A single fd descriptor allows coverage collection on a single
>          * thread.
> @@ -79,6 +87,8 @@ program using kcov:
>                                      PROT_READ | PROT_WRITE, MAP_SHARED, =
fd, 0);
>         if ((void*)cover =3D=3D MAP_FAILED)
>                 perror("mmap"), exit(1);
> +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
>         /* Enable coverage collection on the current thread. */
>         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
>                 perror("ioctl"), exit(1); diff --git=20
> a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index=20
> 1d0350e..353ff0a 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -16,12 +16,19 @@ struct kcov_remote_arg {
>         __aligned_u64   handles[0];
>  };
>
> +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range {
> +       __u32           start;          /* start pc & 0xFFFFFFFF */
> +       __u32           end;            /* end pc & 0xFFFFFFFF */
> +};
> +
>  #define KCOV_REMOTE_MAX_HANDLES                0x100
>
>  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned lon=
g)
>  #define KCOV_ENABLE                    _IO('c', 100)
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote=
_arg)
> +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kcov_pc_ran=
ge)
>
>  enum {
>         /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c index 36ca640..59550450=20
> 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -36,6 +36,7 @@
>   *  - initial state after open()
>   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
>   *  - then, mmap() call (several calls are allowed but not useful)
> + *  - then, optional to set trace pc range
>   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
>   *     KCOV_TRACE_PC - to trace only the PCs
>   *     or
> @@ -69,6 +70,8 @@ struct kcov {
>          * kcov_remote_stop(), see the comment there.
>          */
>         int                     sequence;
> +       /* u32 Trace PC range from start to end. */
> +       struct kcov_pc_range    pc_range;
>  };
>
>  struct kcov_remote_area {
> @@ -192,6 +195,7 @@ static notrace unsigned long=20
> canonicalize_ip(unsigned long ip)  void notrace=20
> __sanitizer_cov_trace_pc(void)  {
>         struct task_struct *t;
> +       struct kcov_pc_range pc_range;
>         unsigned long *area;
>         unsigned long ip =3D canonicalize_ip(_RET_IP_);
>         unsigned long pos;
> @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
>         t =3D current;
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>                 return;
> +       pc_range =3D t->kcov->pc_range;
> +       if (pc_range.start < pc_range.end &&
> +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> +               (ip & PC_RANGE_MASK) > pc_range.end))
> +               return;
>
>         area =3D t->kcov_area;
>         /* The first 64-bit word is the number of subsequent PCs. */=20
> @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsig=
ned int cmd,
>         int mode, i;
>         struct kcov_remote_arg *remote_arg;
>         struct kcov_remote *remote;
> +       struct kcov_pc_range *pc_range;
>         unsigned long flags;
>
>         switch (cmd) {
> @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsi=
gned int cmd,
>                 kcov->size =3D size;
>                 kcov->mode =3D KCOV_MODE_INIT;
>                 return 0;
> +       case KCOV_PC_RANGE:
> +               /* Limit trace pc range. */
> +               pc_range =3D (struct kcov_pc_range *)arg;
> +               if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kcov=
->pc_range)))
> +                       return -EINVAL;
> +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> +                       return -EINVAL;
> +               return 0;
>         case KCOV_ENABLE:
>                 /*
>                  * Enable coverage for the current task.
> --
> 2.7.4
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM8PR02MB8247720860A08914CAA41D42F89C9%40DM8PR02MB8247.namprd02.p=
rod.outlook.com.
