Return-Path: <kasan-dev+bncBD6YJ5EM2QMRBBMSTKRAMGQEEUMS5AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BB16ECF93
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 15:49:58 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4ecb47482aesf2182663e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 06:49:58 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682344198; x=1684936198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UyOYqvEsdj6Du7PZ2dm35qZc/PFwTDknV12QFQZBMOc=;
        b=qh+UvREKpqKRb8diu1yJDl+OnamjUGydHRdjsV9KDI3GkhNlR+akzlBEGImGU0ePiO
         qcIrmzGbvmWaLtWY1ABGaK/+BvYTZ3CfJg8E0Xpj9+f76r4QWn2cNqtfsjCZNl/oumcA
         wBcs6sqIMNvpahFsYzjwCHRW4xmocj2nBrxFhBTEv7itt2fc9CeWoUB3SmdSZ9cN7dn0
         y26RQ0Ch3umCFePzUoh8Slzm41ye6cLUzTkqO1E4fRJViH3AJ2Y4woHmwMqiDkvi3EaA
         g8SJf/a6XocK0zcb2M1edA0t9otI3c3PvwfTDbi/VVQRSStZb5SAu/7LDyuUIJsAHH1T
         uksQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682344198; x=1684936198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UyOYqvEsdj6Du7PZ2dm35qZc/PFwTDknV12QFQZBMOc=;
        b=kGKgMSbfm5lmbE+vP+GnLkXn7r2jmbRRgt+KD0ldiWebapsacCaqImyUVosWrodcYK
         I3XNGhIffeTb0LhkprRXuktAnn21QyV1zxJ6he95lXXv35WhX+S4OwKvPF0FPRHonjT0
         5A6aZtDrHtmTKxZ4R2uj++uedJFiisVCzHS3ILhf1zE9eNJPi2+yh44bHd0Zt2w8M1Mn
         tOeR8FMctZVRcGLJVSex4riWg9B4+JlpR3ms6tUVP+VnscrhZtlYXOZKKwhsgmdQF3dS
         ug/iMH/jTTO8PKc2WlhyN9geeCdo66n6/ltKAZ72YeeEl+AUAm3e+rhPzydQ0wOPOnqa
         DoCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dz25vu2JR9FmdOHAbWj50I95RQDDfbdoUjYBc5XhG6ilhuUPi8
	wiP2nSssppzgD9JwVpW9s7s=
X-Google-Smtp-Source: AKy350YVz9RM81ArB+5dienCqShUA6y0cR8tC1CGL8SGvhmDERzPZrAH8otA+m4RnrfjucPCfvvbxQ==
X-Received: by 2002:ac2:5939:0:b0:4ed:c608:d859 with SMTP id v25-20020ac25939000000b004edc608d859mr3202478lfi.11.1682344197615;
        Mon, 24 Apr 2023 06:49:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e86:b0:4ed:bafc:b947 with SMTP id
 bi6-20020a0565120e8600b004edbafcb947ls767234lfb.2.-pod-prod-gmail; Mon, 24
 Apr 2023 06:49:56 -0700 (PDT)
X-Received: by 2002:ac2:4204:0:b0:4ea:e296:fe9e with SMTP id y4-20020ac24204000000b004eae296fe9emr3238502lfh.9.1682344196120;
        Mon, 24 Apr 2023 06:49:56 -0700 (PDT)
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id h13-20020a0565123c8d00b004e85e286f65si716203lfv.6.2023.04.24.06.49.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Apr 2023 06:49:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of aleksander.lobakin@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6600,9927,10690"; a="374403528"
X-IronPort-AV: E=Sophos;i="5.99,222,1677571200"; 
   d="scan'208";a="374403528"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Apr 2023 06:48:25 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10690"; a="939332988"
X-IronPort-AV: E=Sophos;i="5.99,222,1677571200"; 
   d="scan'208";a="939332988"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmsmga006.fm.intel.com with ESMTP; 24 Apr 2023 06:48:25 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23; Mon, 24 Apr 2023 06:48:24 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23; Mon, 24 Apr 2023 06:48:24 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23 via Frontend Transport; Mon, 24 Apr 2023 06:48:24 -0700
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.168)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.23; Mon, 24 Apr 2023 06:48:20 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=P2hHkFMUPW75Uf5UXsrv9SrfWE1HP9L5/84ue142Dl3CEoGkFW5e9k0HmxIqg+CfGwdSmjYPPk/cxv+RTvXHMLbTOsqplK7XbNahVxyAXXm680/C5PNDILuP1ZnnFIaf8Blut+weuG3rq9wqE7opndkcFakE06XfGRTMC16yCACLu4xWQBSgtnrQiDsd24whiEB4sdRe4s9rZsV7BEpTs1LKmXJM4YKReUkxXk8b5OAUYfm5C2qcAvjplr09rYJmL1r2dNbGDslM5ymU4Es1FYSYaceaKp0OpGIISjPsr3/GtnaOOLBY2hREiwmDdDYBzYtWcogTycxyqV80q6vDTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dcp9STYLO2yK6BgKCtseqlqGb7m7fprOdiUKhmTwUmg=;
 b=fKdU7B6gizqUeRXsMdTX4BNkOKAj/flC1KQf/XTXiqBEYK/+aTEhe6l+SvVi5Qo/0hMyis9WI974UQZKL/qLbKzko7/MW5vQft1Z98ehhqXBb7iyf0/lWDNmo+ue+tj/N1jXSj8FDXknFjHXF/IdMJePp782k6pAYMiqvoLVxgZwii4Wi/i1xxELkvf7UA2hdovpJaFWNH8d2IeXRxW/xDJmQ/JVsPQxMXMX+5vt3UHBz0nHpBQ3IE4ObVbCSO6gBTuIjVlw662p+8r27bRu82CknF/tBpWW6kbQMXIYP6PApiGW9RLUjj2tbY5TKX7dQpmmaKxAlyyivGjufob6/Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM6PR11MB3625.namprd11.prod.outlook.com (2603:10b6:5:13a::21)
 by BL1PR11MB5447.namprd11.prod.outlook.com (2603:10b6:208:315::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6319.33; Mon, 24 Apr
 2023 13:48:19 +0000
Received: from DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::4c38:d223:b2ac:813e]) by DM6PR11MB3625.namprd11.prod.outlook.com
 ([fe80::4c38:d223:b2ac:813e%5]) with mapi id 15.20.6319.032; Mon, 24 Apr 2023
 13:48:18 +0000
Message-ID: <ce1c307e-b7ae-2590-7b2e-43cbe963bc4d@intel.com>
Date: Mon, 24 Apr 2023 15:46:30 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Gong Ruiqi <gongruiqi1@huawei.com>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dennis Zhou <dennis@kernel.org>,
	Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>,
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, Kees Cook
	<keescook@chromium.org>, <linux-hardening@vger.kernel.org>, Paul Moore
	<paul@paul-moore.com>, <linux-security-module@vger.kernel.org>, James Morris
	<jmorris@namei.org>, Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng
	<xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
 <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
 <36019eb3-4b71-26c4-21ad-b0e0eabd0ca5@intel.com>
 <f5b23bbc-6fb5-84d3-fcad-6253b346328a@huawei.com>
From: Alexander Lobakin <aleksander.lobakin@intel.com>
In-Reply-To: <f5b23bbc-6fb5-84d3-fcad-6253b346328a@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: FR0P281CA0211.DEUP281.PROD.OUTLOOK.COM
 (2603:10a6:d10:ac::6) To DM6PR11MB3625.namprd11.prod.outlook.com
 (2603:10b6:5:13a::21)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM6PR11MB3625:EE_|BL1PR11MB5447:EE_
X-MS-Office365-Filtering-Correlation-Id: 69454748-e253-4595-5765-08db44ca8f41
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: WfnM/suNFEt9asxGVmy5fvO0F48tJ6O7MJq2LL/9CxXALz9jkC/DR7SwoJlyfX5/C2TLSLWXLMkyiCu4wnybHqN93AgvbUNBzcHJ5eHeRnrhhcEdMQYh34yj+kK0PtYZU29PgckhP88M/3AX3/LqIKUyczrY2GbKIpm9R4x7szuS+R1pd28H/1nQdGiwI6Tb5D2DXkAfgLLVA0bh93k9Qxdcl0cViu5+2rsRSS31lQofCSsxbZEohP7ghplH5ABCbT86nYWqhpCVCVva1lrxNncGWiJFAGNNAFeSZ/nDhRn5WKybDGJt+neCRqKjySB/x7lrutdyEIdXrScPZWfJw8sYXGsp/USJQK49VpqMDTTkWlR9Vsni5SoIYCTNnvNn1mvwP/y0SfyvewOUj76he6n9GQ2XtjSg6saxakDYxBR1CKXjSinN6OgYwz+bZoyPQ19LzyIzJvw29VxX7SztZfx0fnzsIeRoq5nOUHNJxAmG2L9rGzTOSI3i4rUdS2OzxQvhv3CmQTC6Sfk868c5pkTMXmtIctsPfr78qK/g3WoRyuvFWwX6ruigJaatNt74WxqjT535FXeCSY4dWNZl/xSWPRQo/kJ6quqW82m4imDbNKZxB0uAwHfnggM0BLCQpsrAwxovqfpViEI+wutVsA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB3625.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(136003)(39860400002)(366004)(376002)(346002)(396003)(451199021)(2906002)(66476007)(66556008)(66946007)(6916009)(316002)(4326008)(7416002)(8676002)(8936002)(5660300002)(41300700001)(36756003)(31696002)(86362001)(6512007)(26005)(186003)(53546011)(38100700002)(478600001)(6486002)(6666004)(31686004)(2616005)(6506007)(82960400001)(54906003)(45980500001)(43740500002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?cDZOMGFneFZQVjFHZnd2SHdBeUpSUFl3OGtrV3gwV3ZqaG9KdnlwRVBGOEdq?=
 =?utf-8?B?SzRsbEdXaTd0WlZyVDRseHp3SEx3MHdTV2dURXM1anBHV1hNRUdMYUVCTDl2?=
 =?utf-8?B?am52WjNyMURPU2xYanYyZ0ZCNm42Yi9BWXNDbFlSNzdEbEgzZysvSjE4OFQz?=
 =?utf-8?B?T25qMGlFUUlUTkdxT0hBWmFvaUxEMk5SaGV4dG1DUGFudGdXQ24wWHhua0l0?=
 =?utf-8?B?MSttb1JYOEQ1YXk4ZGYraWgvb09zUTFRQ0h6NWNvK3ZXRkpBTzc2VnZJSU1S?=
 =?utf-8?B?MWE2MEhyYm04LzNsWDRyVy9hZDlpVXhsTFNMczJ5bDd2Wkh6VGtDamZCMWh2?=
 =?utf-8?B?VC82WEx3Z0RKM09hQVlGODFHSUZKcmNRTVFpTnFzenBDdGUyNnZ0YmdVd2Jk?=
 =?utf-8?B?Y1NQTmZETGN2bnlJU0RnZFhRMjlqZ3ovVHNUVDlkcDFUUjRIYU5DK1Y4RGhJ?=
 =?utf-8?B?RDFNN1hhOVVuWm5ZVWZtaXY0Ujg4QnFGVlAzYk53bnJWUjZKOEwrOFkreHlF?=
 =?utf-8?B?TG5INjI2V3pJelp4YVhOMkMzN2l1VUYvdllQa0hmY0UzMVBDNE9ubVBicFd6?=
 =?utf-8?B?ZU5PRE1hbjUvVlRNTytneXoyRTg3b2tjaW90U2lhdGZwNnZibnh1VmRqbS9C?=
 =?utf-8?B?cHN2VCtqcGVybVpYUlhPenI4RjBrclhXZy9PbVlWL05IZ1gyS2dqcmFqaTFx?=
 =?utf-8?B?RjE4ZFVwdnliUDlDeldNbnp0RVh4Q29TNHRmNk50M1VqYU5lY1dqM3FURTlD?=
 =?utf-8?B?TmwyYVNzYjhKZkpRVDMzWFdwM1FmWU5Rak0va3VjM2JGVWZzeldOV3oxNTRi?=
 =?utf-8?B?RkIyRHV4RE9pQU5pdFN6VGxocVVUZmlycHdnRWFrM1VBYVB5Sm1tRmU5bUpY?=
 =?utf-8?B?KzhPbG5vZWtUeUFqVXpKenY2U21saWNXbXNFWHF4aVNoSGJFWkpkR2lvWFRV?=
 =?utf-8?B?MktlQStCQlcwOFFaSFdnL0VxSkZteXZLVUMvNnJCSG5lc2tFcjgrVU1kQm44?=
 =?utf-8?B?V1pBWW9oSHhiMG5TbGYxWTFFYWtHM3hEeVZQSm5XMDUyTnZ2dnNtVm9vRHg3?=
 =?utf-8?B?TFY1UGtkYWF1d1RpOUJZWTcwN0Q0enN3T1VqWFNDRlBDODk3MmZ2cVpjMWti?=
 =?utf-8?B?c3VmTEZERlA0em12b3phRTBhcmZyVEUwQ2dkS2xPR2pBbEZQR1llWWI1Vk55?=
 =?utf-8?B?QUJJYXlaZVZUYm1UWGhWOEduaXBpMTRMSEdWdncyTEloaHF3c2JZRWdRTGt2?=
 =?utf-8?B?OU5BbjNBbmtvbHhISXZSdFIzNjlBbDBOc3hvYzNtblhQaUoyVTBjMGpkMEM0?=
 =?utf-8?B?UG1NcXBmV0hIaWdLYUxPYXc0RmxPb1I5OUp3WXZEYjhWUHdDVHkzRWZINFl1?=
 =?utf-8?B?cGZsZnZIQm15dTVvcGNVQlNGaXgrNHJuRmQwcXNkS1lyYXNMR2xWUkUzYmo1?=
 =?utf-8?B?TVZkbDVqaU5qeEQ3YndmZjlKc0RGMkNQdmUyZTZ1N3BjblV1SHdLUWQ0Nktu?=
 =?utf-8?B?Vit1VWJSTm9SeUhUSzZUd0FzVVdiMWFaMjRHY3V5Ryt0SkJySFc3YmhBQ2Jw?=
 =?utf-8?B?alhRYTNJeFVZb0JLYmd3UFVTcjF3NFZoSWpIM3FvUUVMTWNoU0RrSXg4bjJL?=
 =?utf-8?B?MVc3NmxaaEJCd1JRaUlPTUVjbVpZZmxoRXBsOXYwMEpCektod1RtQytHU1l2?=
 =?utf-8?B?OUk1SHhRSHMwbHpCSTZZZU1XQ0t0dU4yclFXSzZyVk5GalBpc3lDb3RJNlJ3?=
 =?utf-8?B?b21udjNwNnd3bUsvQ3g5UlRwZ292ajFxWHZwUXdQbzVyVlFkek1aQ2VUTFdy?=
 =?utf-8?B?YzcyMWRiU1JmVjV1YXhpN2xwYjY5Mk9hUm9naWxGU2NaQXJUamZNUWJJZk5M?=
 =?utf-8?B?ak81OFdCblVxbmZTMzQ0RTB4VGpEVlA0bncxL25ic3VwUFhsM2YxL2Q3SURw?=
 =?utf-8?B?WFhQQktMeUZxUXVWSW1JcFdkSnJqME1BeTFnakNqcStSOHU4TnNja0U3dFlh?=
 =?utf-8?B?QW9Cd3BxeVFLNDJYT3pzMDRRVzVjaEhxWk1JZzNoSkx0bmwwcHRjLzI4Rjcw?=
 =?utf-8?B?R2NmYm1MdWlVUklDZ3FFVW94MzFDUnovWk9PaGFhOUlUQmgxRVRTVUcwVlFy?=
 =?utf-8?B?bERGdkVNTUlkUVkxTUdoOEFYdEl4aUtUSTRHdFBSSk80MFI3NGVBajQwYWc0?=
 =?utf-8?B?d2c9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 69454748-e253-4595-5765-08db44ca8f41
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB3625.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Apr 2023 13:48:18.5578
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: bBEUQjZYgrSsCb4qLNjexKvAOM87Ta/ONZv5b2ppNQXN4EQ58SZeg4U13QyuF5BYlHthQFiBh/9nO2RdIb2vM1y/i8UBgoRucxenxkgvxQ8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL1PR11MB5447
X-OriginatorOrg: intel.com
X-Original-Sender: aleksander.lobakin@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NE5sA556;       arc=fail
 (signature failed);       spf=pass (google.com: domain of aleksander.lobakin@intel.com
 designates 192.55.52.88 as permitted sender) smtp.mailfrom=aleksander.lobakin@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

From: Gong, Ruiqi <gongruiqi1@huawei.com>
Date: Mon, 24 Apr 2023 10:54:33 +0800

> Sorry for the late reply. I just came back from my paternity leave :)
>=20
> On 2023/04/05 23:15, Alexander Lobakin wrote:
>> From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> Date: Wed, 5 Apr 2023 21:26:47 +0900
>>
>>> ...
>>>
>>> I'm not yet sure if this feature is appropriate for mainline kernel.
>>>
>>> I have few questions:
>>>
>>> 1) What is cost of this configuration, in terms of memory overhead, or
>>> execution time?
>>>
>>>
>>> 2) The actual cache depends on caller which is static at build time, no=
t
>>> runtime.
>>>
>>> =C2=A0=C2=A0=C2=A0 What about using (caller ^ (some subsystem-wide rand=
om sequence)),
>>>
>>> =C2=A0=C2=A0=C2=A0 which is static at runtime?
>>
>> Why can't we just do
>>
>> 	random_get_u32_below(CONFIG_RANDOM_KMALLOC_CACHES_NR)
>>
>> ?
>=20
> This makes the cache selection "dynamic", i.e. each kmalloc() will
> randomly pick a different cache at each time it's executed. The problem
> of this approach is that it only reduces the probability of the cache
> being sprayed by the attacker, and the attacker can bypass it by simply
> repeating the attack multiple times in a brute-force manner.
>=20
> Our proposal is to make the randomness be with respect to the code
> address rather than time, i.e. allocations in different code paths would
> most likely pick different caches, although kmalloc() at each place
> would use the same cache copy whenever it is executed. In this way, the
> code path that the attacker uses would most likely pick a different
> cache than which the targeted subsystem/driver would pick, which means
> in most of cases the heap spraying is unachievable.

Ah, I see now. Thanks for the explanation, made it really clear.

>=20
>> It's fast enough according to Jason... `_RET_IP_ % nr` doesn't sound
>> "secure" to me. It really is a compile-time constant, which can be
>> calculated (or not?) manually. Even if it wasn't, `% nr` doesn't sound
>> good, there should be at least hash_32().
>=20
> Yes, `_RET_IP_ % nr` is a bit naive. Currently the patch is more like a
> PoC so I wrote this. Indeed a proper hash function should be used here.
>=20
> And yes _RET_IP_ could somehow be manually determined especially for
> kernels without KASLR, and I think adding a per-boot random seed into
> the selection could solve this.

I recall how it is done for kCFI/FineIBT in the x86 code -- it also uses
per-boot random seed (although it gets patched into the code itself each
time, when applying alternatives). So probably should be optimal enough.
The only thing I'm wondering is where to store this per-boot seed :D
It's generic code, so you can't patch it directly. OTOH storing it in
.data/.bss can make it vulnerable to attacks... Can't it?

>=20
> I will implement these in v2. Thanks!
>=20
>>
>> Thanks,
>> Olek
>>

Thanks,
Olek

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ce1c307e-b7ae-2590-7b2e-43cbe963bc4d%40intel.com.
