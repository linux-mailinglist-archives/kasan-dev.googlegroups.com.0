Return-Path: <kasan-dev+bncBAABBQ53Q6LQMGQEWWRKCRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 970A5583611
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jul 2022 02:52:20 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-10e46ccc8f9sf256173fac.18
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jul 2022 17:52:20 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1658969539; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lsy1WISi8+57LV83oEOaov+ow//p7KcqBxr4RG9jJqDAY782Ae9I5t44zgbNzhs01L
         tdlZozoflLGJty/GjZVjUz66h1azMGSEUWVMgMvspiT/ie9EJDArqcJgCoVFP5KDMf8L
         3O7sKtIV68SktUOPXvbKogAhZA9LGeemPXJGm3dXXQC650QCsVuGPRdyNnQJoLkX1eJF
         cHzqevwmJdxQkr2EuskYZV/TLlSrafzOVdI3iIaseLtn0qOoayAqxnYqY1CkvXWFN0S5
         ONsg+PjhO2LoKY3Nhy5XK6GMIV+k5GUaSeQm0AXC5tQk45t4TtDQuEStD8lNEKag4ovW
         uocQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=2+u7zkP+cEn7k+m2HhGwG7x9b1DjeKweEcnDX/IWr80=;
        b=V+ZVgqQ8/0I1MZ5HLkoyTj9CKpjUahoJJf0A0UOK9GXesbSXO3rtoImxcIFQbSBQ1Q
         Tb3GrDynt5l3qBX7ptmo7XfrnYh6Y1E6knraGyeyYzDPVSQxHV4y+gW27wC4veatbUxs
         gKnmfuO14+nTPjeC64u0Vqcqy4itV42lJhsnA6wY0w2k+GGdGUjTdKYWf+OdRS74jHlZ
         SqIp6/pISEyXCnzLpHh8LwBeKO8YV2czjikeF1vBIDDsWRzxDeLQFlVyF9lCm0l8jTpb
         DDEfbXBwEnyNudWMAabsEETU2mUIYtSlMFIJPTkTYhkw/EtLprYrC4/GkR/ROYFJejbM
         xeHg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=pAjc6d65;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kB53Xkrp;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:user-agent:subject:content-language:to:cc
         :references:from:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2+u7zkP+cEn7k+m2HhGwG7x9b1DjeKweEcnDX/IWr80=;
        b=dtg9+SspTOO7NFf2Ol8/5hwlRK6sMgx1A3J0wTIkZ7uoTe+KuHGoL7ANpSyEJV1edv
         NR7OUHrGyPvZAx6nXkrrvIFxde0+DfOqHqd9BsOMrHVhbrlL8Go3P8aD81oLTX3e9Axj
         SDCaa4gdzN7Co+jZ/Kmh8WmFtwnG5WXaw/YbD+QNoP5hHcvDxnH6xfufZpvVYQIma5wF
         nUCgzeCJwwQWwmrZEC0QDt0zyH8ThBkhPzVtED6L1pPi8c+BVsX1vPjZesiJruTRreQO
         HttUU0zrGAnag/mI53aNT+GcWiUYhcjbEJRmJbxozkwd2DPzc06B3TdyjR6S50t2Fo+p
         3ZCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2+u7zkP+cEn7k+m2HhGwG7x9b1DjeKweEcnDX/IWr80=;
        b=4trrUxVFTpDXJnrWj6edNazf/tn8cPfe4lR7aIJyayDLmEN65rbr+ZgguWAvrmJxEK
         ZMWFbcX4jRr6O5IjGr6MNw2RC2kWpb7NZiLtnvs6s7V6568WmNiwOY0tca6CkSLAN49g
         4Gy0n10eZyBY1bvINcmz1V+8q7DlItgpwVowvsjb8KjVmoeeKvF13nzywu1iNftcKNVs
         RQqKg1KJ8fjnH9wXVdBBg7sDGGHfGDMhGP7wua7hByd+dQh6XoKEhDmaPmphyIdSpd7b
         FNXApJk/kZhcAnP1v7XhSQ4mvUloRVYVZv/Ac3maNjrGj5mWLX0pZYU6pGAeInnzWGIv
         SJ8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/ofA8vf1GuQKvyvNiB2qAJWdvNdb+edMAg/TTKfVLHBd/TbqQ3
	yC8sO9NziK0k8tcgw2GpTWI=
X-Google-Smtp-Source: AGRyM1tTdTf5gkLTmnO430vQ7aenyaYUtOMVf4I9H5BKHyUN2+IMDFp5XeFXVzYsfc4HRFCN+RuPaA==
X-Received: by 2002:a05:6870:40c7:b0:10e:609f:dbdd with SMTP id l7-20020a05687040c700b0010e609fdbddmr2349830oal.226.1658969539365;
        Wed, 27 Jul 2022 17:52:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a8a8:b0:10e:6b7b:7dc6 with SMTP id
 eb40-20020a056870a8a800b0010e6b7b7dc6ls268535oab.10.-pod-prod-gmail; Wed, 27
 Jul 2022 17:52:17 -0700 (PDT)
X-Received: by 2002:a05:6870:458f:b0:10d:7605:6db8 with SMTP id y15-20020a056870458f00b0010d76056db8mr3533051oao.34.1658969537547;
        Wed, 27 Jul 2022 17:52:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658969537; cv=pass;
        d=google.com; s=arc-20160816;
        b=zuFE1YYkEn3xFBkplLWgKwiCQ6fB2kL3grsE9KpLtW4IVSC2N3pZ+96+nVxildtqyd
         9uUCTSi/MWYilY3LqgbdcSqzW5KkTTJzxzkjyo1gcEa8F1uqJpCkKNvlOkx+ReMTcgyI
         ffkZEw7VczMVVDg/ezfBrIdkgibQpHo4cAcqFKJuJW1UyL2HfsQhz9PJqG/nGzpcue5f
         RGHnCf1F2Ot1Um8mK2UBwRUyr3r6mc2aqd01SFXpMJStFYCEP3aED7IkuS+hbvHRN6ux
         U6EFeVuwEGN+/y1G2ZUyGmGEjBD7RIRmHU6gQeiS1uOLOb3Id2HW/h2MoPfDjQ4ZHRLA
         Q5UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature:dkim-signature;
        bh=mTd2oGPAy1b7Wxgpaw/Zr6QItLmcyRuYkWAFSifEHqY=;
        b=cm3u6TtdVzJdyz+aO+Hnqoo6DOef4SPBV/9u7UCiFsZfHu1PAFMarkgiXwoz5WPQIG
         zlr5kfUeQjNrbeQVIzBnE7qDissswcAHn6RJXeeET8Nwy0EvOSkI+mPzySEjDuVQqznZ
         KbjoN9RoZyEKB+PM98zu1Lb8u4pliL1VQl/vvR3WcjA+Vr6jbf+OJp685Sf9Poyxtz5R
         VlH0jdtry4GOyJu3IApg1gRMlKurAbCP6aOLSh9PjqRnRqluKbExHrIF1EDhJ0UWDTS7
         P0XGBvmg5W1L58OfllrxCBxVja/5HVARSa9hu1c+ttwEOPjC6Nxl8qNeMnVPn1+Lemk9
         dfAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=pAjc6d65;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=kB53Xkrp;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id j3-20020a9d1783000000b0061c67f83202si599945otj.3.2022.07.27.17.52.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jul 2022 17:52:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 26RNOMVe017508;
	Thu, 28 Jul 2022 00:52:14 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3hg94gk4rm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Jul 2022 00:52:14 +0000
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 26RN0IUp031502;
	Thu, 28 Jul 2022 00:52:12 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11lp2173.outbound.protection.outlook.com [104.47.57.173])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3hh64u1am1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Jul 2022 00:52:12 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=PhCmvZ3rIdxSiNMhs6Mj7bz9AhRe680nTUwvWqk7syD/NxIx3afa44Ym7BcgoR57hPTYaxL9F0Rp/fMRzJwFrnRwx0UIHZMW2Z085c1walsKAHe+EiqlWL2ACnIMvd8cjcnmX2J3spZtNaSCaUibwx2r2uajtHbwdZIm6hwWjgv2EZjvFqaWQb6LRMITx+2BYDkPHVjiAVPxCsXBiO0Q6RF+bIzydwRdRWlgkmKsmY/UgS+HQ3CyMkEjQxlb7kRkAEG61tMDVzXNDYD6FtzXlssL5qXNS8XV9Vtzm4FSR5Giq8+YeaZkJTcK+4Oj172gmvHvyfMWBxTrYXG+VFUf0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=mTd2oGPAy1b7Wxgpaw/Zr6QItLmcyRuYkWAFSifEHqY=;
 b=Q/AGmHjbNfvT6RUQGOgs9BwFpfj4JtO1ebVPfVCfD5Cmd5c0sTRY7YAUfvDch6LIjSX2IKp6w6jiSHDKSg4BgjAfZO0LVUy8YeDhxtTx4ZC7IDV6IeqsCHKcNCaUuitMJoLlHxzh934UMKjVTTGDlyJzQ9UoLTfHLyTg2BLfzChdFcGNN6pJGbsdlFnmATLzDJDd/qhaItMXWumRE4Wx2T12wYriyGb21fa1lHIRYkAvnuiMMlefaRTMY8AUURxYGEwDk8pQX/PsiQwPkKtj7UayCDua6vj4AKMEKnPHKoI/GwfkbKFDwxd0KKuT5aTrQXHre7toSGqmFq8CmoY4OQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
 by PH0PR10MB4710.namprd10.prod.outlook.com (2603:10b6:510:3e::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5458.19; Thu, 28 Jul
 2022 00:52:10 +0000
Received: from CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::dd9d:e9dd:d864:524c]) by CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::dd9d:e9dd:d864:524c%9]) with mapi id 15.20.5482.011; Thu, 28 Jul 2022
 00:52:09 +0000
Message-ID: <6a899346-f9b1-dc3a-2da0-f3271c85327c@oracle.com>
Date: Thu, 28 Jul 2022 10:51:59 +1000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.11.0
Subject: Re: [RFC PATCH] mm/kfence: Introduce kernel parameter for selective
 usage of kfence.
Content-Language: en-US
To: Randy Dunlap <rdunlap@infradead.org>, glider@google.com, elver@google.com,
        dvyukov@google.com, cl@linux.com, penberg@kernel.org,
        rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
        vbabka@suse.cz, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com,
        corbet@lwn.net
Cc: linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20220727234241.1423357-1-imran.f.khan@oracle.com>
 <08da326f-3fe4-3342-bce8-bbd94bf8be97@infradead.org>
From: Imran Khan <imran.f.khan@oracle.com>
In-Reply-To: <08da326f-3fe4-3342-bce8-bbd94bf8be97@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SYBPR01CA0115.ausprd01.prod.outlook.com
 (2603:10c6:10:1::31) To CO1PR10MB4468.namprd10.prod.outlook.com
 (2603:10b6:303:6c::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: f267262a-6fef-4f34-bf7d-08da703366a1
X-MS-TrafficTypeDiagnostic: PH0PR10MB4710:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 6brHHJQokFdBCO/GhNARPstpgR3C2kp+FfH5ohcVQwj8PMBKNlr1f0ceGw4/CewlVT+ca3KAWLIg5h0Msk450LfyJW/2kYD4ESVJrbE84tTwNtuiUM3M70bdan7hF15pzJKYesRHDVqfxfdnjUZNRcOYCcLQAMqdI/f9o6gm+1IJiftD08dFia0CS3brql2R2MNsu8tpVvCqMs4OBK+WkwLZM6exBoPyyOCa3bWOLiovW08bX52Y+DiQwYQ89FDAE18SAMJ2JDicg5YMeq7KpC7TWB0aXPJTXPYruygDxjScbBdU+4FmXiXxuUCad9/8g1BcFIfEJgwPS4s0N4sMOVpbTUTnwYl8qx4lqBB1sBKHqPDJOD0ZuOlERnVdv28gYuXp9gs9SRhAOpW4qQXoPGZoHtPc//EpjZFm/BNREbsyh1VBAKDX9S/g8q2ynwvblDZ/EbAs7Fqy1aWPhX2AAhup45NAU/Vzkqh4XDYeem6InRxQXdk98x4kTXJdhmSkskUwC5KZq2qKN1eeJ+WDEqPKFhmsAVON8DYwa5k1/EADFSBSxjA22F1qR4VQvitZpFvJ76V/HRJA2DYB9rWqZRwJEvmUyCAt8xvKlPk9iL4p5RnYYd0uP0FA+9KEoZrHLFINiuY4O8TuBH5yH7hdL9FFaMp2sjRwDOoB02QyP3epqgJyk988oxRXzzwL/B703Gty76kyYtzaaAScr4bL65kyctARc+LuH72arUypLgO2Y8walSe8kEQx9cg2xhD4AdV83G8yZMezQvTQwEaHlY4gm3TiHx7JabFOousOzkeoPyMJaYDM+7YZZ9CaPV5nFaiHW0awWQUoHzdGcrkscEQuP1A4AKDXcJrtAq8Ks+o=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR10MB4468.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(346002)(39860400002)(136003)(396003)(376002)(366004)(186003)(2616005)(83380400001)(6506007)(66946007)(4326008)(36756003)(66476007)(8676002)(66556008)(6666004)(2906002)(53546011)(41300700001)(31686004)(7416002)(26005)(31696002)(8936002)(921005)(478600001)(86362001)(316002)(38100700002)(6486002)(5660300002)(6512007)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?OUpOak10MUh1Y1RSbzRwZlhwNGlSZ3lLZEthLzgwOW85UHNrbThUdDlmQUcv?=
 =?utf-8?B?T2Vkbm5MSDg3WmVDeHIySmROMUZFaENpUE5MbmJQMWpZMklyUjdUMVdDR0pT?=
 =?utf-8?B?bFFhcC9ORUZXQzFoa2NERFU4RTIvYytFL2Y3dkdoZHN3MjY5YkRNcXRHSXZu?=
 =?utf-8?B?U1hoVHdBemduU3VtblhGSGlvU0FNMWtVemVsRWpEdDBZa1UxZFJjQnY4ZnRa?=
 =?utf-8?B?UVhFMFBaSEtqM2V3TTFyTU5hYW9UdHYxU2x6dEl2eW1BZXoxQUV2R01SMFFz?=
 =?utf-8?B?ZW5QOXlvUk0vSWxDa3prUVNRZklNZ0sxRnA1Qis3WEwvQ1NPZDZ2OWFxQ1Yv?=
 =?utf-8?B?ZnFMNWVqQjFYY2d5U0pGbVkvV3lWS21iVFJJc3hMSUowaGF4dldhempGT2U0?=
 =?utf-8?B?SVJXWDAzc2ptVEtTWFI0Mk5MMENQVFNrVkZpWWd4angwKy9ZOVM5ZWlXTDFv?=
 =?utf-8?B?UGxBemNlSEp1c2JCVXNvZy9lMGdWbUxpQWhyMndwRWFSQ0ZRNlZxSS82VUFB?=
 =?utf-8?B?U2k0L21kNHJzL1F3SC95cXRHRjBrSHdKcHIyZVFIRTdWdW9WVGFJR3hJckYw?=
 =?utf-8?B?S3Z0ZGVSZEIxc3VBNmYxenc2d2pYUVJGT0JTTXViWjh2ZHluelEwQ0gxTGNF?=
 =?utf-8?B?MTZUTFI2NzhMTkh3VG5MVGtCbHhlb1FKc3k5ZW5VOHV3QlNSb1NRSVJBUVd1?=
 =?utf-8?B?enlGN1h6dmpYQTY2NHhNM3VSeVFsQUZsSHJ3T1YzQU9UbldwNURLblBQdjZu?=
 =?utf-8?B?TXVUOTZQSm1PTVlnME0xSTRHODNUWlMrSVpMK2loYVFqQ3V6bXB0SDE1ME92?=
 =?utf-8?B?Vzh0aGxEZUNqdVNyOCtabXVSbFpvVDN4bnQ1ZUtEUFlLUEx2YVpFNXIvS2Va?=
 =?utf-8?B?MFhpTmhTVVdySlAzQTFzSHpwd2dvZlZZSnFRSzVkdUF5RWZsS1g0SjJCVlht?=
 =?utf-8?B?RDd1T2YzYUcrLzFnR1BZbVZiSkJJQ3RPQnl4RVhGVmxycTh6ZTdVeEhDNkNk?=
 =?utf-8?B?OTNLOE9RbDlPNFpvQ252eDZmdE5qajdmREowbUhsM051SEdWNUxvMCtVelc3?=
 =?utf-8?B?M25XK0Q4VzdtZGpURi9ybEU0dXViVkZtUXhNd3V2SkhVMFdpcVF2TCtCNEwv?=
 =?utf-8?B?eWpFWlVseEpTamoraEF6TGJwUWtjaS9pM0tMYUpFd1FiQjd5UERmajRlWElt?=
 =?utf-8?B?MEwvWFhabG9nZlNmMHF1Y0JFTENDT1JNeUg1NmE5bEtQWitGZHlpNmhCdkMv?=
 =?utf-8?B?NWFselhDQ3g5RFFCcHA5Z2g2NmtialZ6SnRBMFFZOFdTWkF2dHBDWUNVZUla?=
 =?utf-8?B?cFg1cE5ra2FyWURmTG0wSThid0ptSEpwQmJMZ21RZUxpbEtYQndSa2ZiN2xD?=
 =?utf-8?B?QWZDamE1NEEzWUo0L3pRQXFmUzN6anBuZnN6WGgwVXFjeU5LNmZ4a2lTQlRN?=
 =?utf-8?B?MWJhbklXSk8zbTFiZ3lxR2x4T0ZMNVpQTE1iZHpRd2h3OS9sOGRBM2lBTm1D?=
 =?utf-8?B?djZWS1U5MmE0R3labUl6aHZuVnAxWHhBMTY1a1NYc2hza1ZXWmZTdWNYamI3?=
 =?utf-8?B?SlhOQUZlQmRyRlU5R2NLNzFBNjZaMzFrT0g2eW9xNXNUWTZSWm43WXE1R0Zw?=
 =?utf-8?B?emMzM1VpYW5xQitDc0wzVUd1Y05aWmcwQ0ZxNFlFSkMvUnByY3lycjR0dndL?=
 =?utf-8?B?ZEgwOTVoYTdsK2M2Y1c1TTFoU2lrQzUvVDV2bDROY2JZVFlnTlJPWG9oU2J5?=
 =?utf-8?B?VzZZNERMR3ZsREUvWHdYT2lrS09CYUZPanZCT200TVZiMmpmWGhlbXVUTVlz?=
 =?utf-8?B?QmppeWd4WjNDaitveTZxQnFpWC8zbFN4bjZsblh1WXJ5ZFFBUmFkeVVhbGNR?=
 =?utf-8?B?REpGaWlxTFNPTG56bUdwR3pIREhEc1cxcXUrYml4M3NJR2o5K1J5T1ovWnB2?=
 =?utf-8?B?UUFhNEErWU5BUlR4NGhxZHNPWWZpSjg0czN6VDJjVDRKV0QyTElJTE9IZGcz?=
 =?utf-8?B?VW5jRHBFUGF6cEJMWFNwaEMvb01hcDVJWUlWaVhPc1dDUkV4K3MxRDRpWU9B?=
 =?utf-8?B?eHpIVVdERmxsL25vS3Z4VzZOdmhTbG4vMHlWdjB4Qi9GN0VzS2dsV0FCdG4v?=
 =?utf-8?B?bjJNemxPTlJTMUowclB4NlpSNnl2QjRic0dkc280cnRQVThlODYyQmN0UGls?=
 =?utf-8?B?ZEE9PQ==?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f267262a-6fef-4f34-bf7d-08da703366a1
X-MS-Exchange-CrossTenant-AuthSource: CO1PR10MB4468.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Jul 2022 00:52:09.7142
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: pH08+VlHAeK9RGLz6szC7nO2O3odiw0IV6YzE1KRG3wDipNAKgUzmew/W+VRM079e9WrajP0QXpp+3xmjqE4YQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB4710
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.883,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-07-27_08,2022-07-27_01,2022-06-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0 bulkscore=0
 suspectscore=0 spamscore=0 mlxlogscore=999 malwarescore=0 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2206140000
 definitions=main-2207280001
X-Proofpoint-GUID: xwuPV-5pFBTF588P0cOGqvWHh97VPG8A
X-Proofpoint-ORIG-GUID: xwuPV-5pFBTF588P0cOGqvWHh97VPG8A
X-Original-Sender: imran.f.khan@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=pAjc6d65;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=kB53Xkrp;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
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

Hello Randy,
Thanks for your review.

On 28/7/22 10:00 am, Randy Dunlap wrote:
> Hi--
> 
> On 7/27/22 16:42, Imran Khan wrote:
>> diff --git a/Documentation/admin-guide/kernel-parameters.txt b/Documentation/admin-guide/kernel-parameters.txt
>> index 98e5cb91faab..d66f555df7ba 100644
>> --- a/Documentation/admin-guide/kernel-parameters.txt
>> +++ b/Documentation/admin-guide/kernel-parameters.txt
>> @@ -5553,6 +5553,11 @@
>>  			last alloc / free. For more information see
>>  			Documentation/mm/slub.rst.
>>  
>> +	slub_kfence[=slabs][,slabs]]...]	[MM, SLUB]
> 
> I suppose that 'slabs' are by name?
> How can the names be found?  via 'slabinfo -l' or 'ls /sys/kernel/slab/' ?
> 
> 
Yes 'slabs' are by name and names can be obtained from slabinfo or sysfs or
using kmem -s on a vmcore. As it is a boot time option user needs to be aware of
slab name just like when someone uses slub_debug.

> It seems to me that the boot option should be listed as s/slabs/slab/.
> I.e., one uses 'comma' to list multiple slabs.
> Or is there a way for multiple slabs to be entered without commas?
> 

Yes, 'slabs' is a typo above, it should be 'slab'. The name of the slabs will be
specified as a comma separated list for example:
slub_kfence=kmalloc-*,dentry,task_struct.

I will make s/slabs/slab change in next version once I have gathered some more
feedbacks.

thanks
-- Imran

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a899346-f9b1-dc3a-2da0-f3271c85327c%40oracle.com.
