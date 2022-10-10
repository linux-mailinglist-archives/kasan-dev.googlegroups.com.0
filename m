Return-Path: <kasan-dev+bncBDLKPY4HVQKBB6FASGNAMGQEPXREKVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id ABAF35FA261
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 19:03:53 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id u12-20020ac248ac000000b004a22e401de1sf3050256lfg.19
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 10:03:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665421433; cv=pass;
        d=google.com; s=arc-20160816;
        b=U2Y4KcWqL9bqtybWwMUQEhwvIOFSOD4AC/2+6cYnp1u22lo8XWlKGQ+CVXpJofIBnz
         UFxCFj+6mhPn6pk4dqwISqPsfkxVFvFPzrMi/Kw6YGVeftLPll7MosdZBTmyJ+MCmPAm
         Rn/rXahbfCRuBHc1n/wINZsPCjEhA94QCT+0ldFDmsK0FAyR/TvUT2oSycj3pYyLGa9E
         vwmqlfswck3CPKgI5e0aBhz5lwypYk+rynaMOpCPyB8jrZsH6ixNUPtqWaEW8ZGNIBs9
         LUE8cls0HIG8zuz2G4AhsbTV19b4MoeIoe6QEWjzf2DLW1yitaCHEsos9bBogBYsVTcR
         kXRg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=BuTi3yJ4Zsdh7SGXKUaY5RH9gCcRhysrey1Smy4nBis=;
        b=GErqqKSrvJ4dwSiebnCwxqu7CVb3YeYdi5ZIvqXSyVxRh5ET1i28+E/xaEzIJtrRbK
         oKLhD8PhYKWKpCi8bNBdEN8P9DYKLF0d4dWnTe6ybfcn9hhmYC4mGhInOPcyduAUdT6S
         zsYws06izubJAAA7QsGEGy3Sohr6R/K6CevUnMq6Xi7/J/spd1p8fT+05jgrKa+3VVju
         VITWD1p1fubnE7VW/XSpf2sdfAdg97NteMRqTjj4kaz/15pNiF/hHdJ4x7waXdKboiwS
         9OA+q+MIGknJNm9cagURpr2XXSceqAsmbm+qzGUKqp0kjsLua+H7TXtZKGhX0omB4/r4
         u7eA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=s7muJrPv;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.78 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BuTi3yJ4Zsdh7SGXKUaY5RH9gCcRhysrey1Smy4nBis=;
        b=T1ZeKNVPSoufRtUwHw5VAUXKy7viTF3190R4VUTZZzBn+8aqTOQuC9WPE325p4o9jW
         lrLDD8ITiZke1s6kU02YQeWCz5zEDEFQPBlv+irjuKblheyknujdzbuL8iUdvx9++00c
         pABK6a5Bs/nfrQCG1yRDPRstlXNIb32Zgr3PMecUDHp6DCC7y01j+XVDsUW0We09XU+0
         g2rC3lEazv2wq21P90ROl+N75sfOvG/Hd3RbnsAmWJ70IpqES6B4NxlQCZ6SAEa4v7Ff
         xgMNotjqevTBD7yXJSbWehCtsX6qFff7ZuZN9XYamghiCmmte/p77YRfQjxe1dKFfNLi
         MAEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BuTi3yJ4Zsdh7SGXKUaY5RH9gCcRhysrey1Smy4nBis=;
        b=ZEe3jouKcuNhdwT/3k5Wjb7SiD0ovb5BpROqPYptP2kDxsl+92yuYez6oYKzAU1o/t
         kfZMisyQRg3HsVQfBR2UbtnybhHkY0eWymNCrqWADLtxML4MpBATz8OgQeJWW4k87D8z
         LWcoRPA1lowWTQ+eI5ErVG6cZUSUzmja4x+cOLD9CImJeoeFeNNCRTk2lWzuHuCL/gAs
         1Jh8dB9ElYJYiTs3qOEhbxwlVZ2dfjEscBetj/yPUpvBpKclG/HqFC2r2SEpOpjwUcFQ
         w1FfiYxC08IAzZgaQAnaFVOLljl0qwOt2xNvcqFeOONJRGAPdft8S+NQLFeJcvExEbYH
         0OBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1X2M+z/7Z/th3Stg58bpZy1QXSUgYr+OxWUEqtwGZUNnTBOCSL
	I3lR/zJqQQqHFPxLnEERgig=
X-Google-Smtp-Source: AMsMyM5sLC+YEts4wL8fHy00oV22bZersNsyfl5Y0tNCeM3WA1rT53wVBugIjKUzvRbDma/j6BiNJA==
X-Received: by 2002:a05:6512:159e:b0:4a2:46f6:eea0 with SMTP id bp30-20020a056512159e00b004a246f6eea0mr7430498lfb.451.1665421432888;
        Mon, 10 Oct 2022 10:03:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:720c:0:b0:26b:db66:8dd4 with SMTP id n12-20020a2e720c000000b0026bdb668dd4ls2167271ljc.8.-pod-prod-gmail;
 Mon, 10 Oct 2022 10:03:51 -0700 (PDT)
X-Received: by 2002:a2e:9e8d:0:b0:26d:ffa1:2653 with SMTP id f13-20020a2e9e8d000000b0026dffa12653mr6965684ljk.439.1665421431633;
        Mon, 10 Oct 2022 10:03:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665421431; cv=pass;
        d=google.com; s=arc-20160816;
        b=mw0R0zCeY5QbOsfTI3Y+AfBl0DfMPlNxv2/TkBIc/FVWXFs8vxw2Z5iQRgTZDiirun
         epqFa3oXMqFVyK7//vngifp8Te/I0X2rS2pjvVWKwKXMZt5z/Iq6Nx4+t/+Dyqg59A5r
         7/qNs3EcEruBRAVRGqjNfSup77dyQ/YWuH8wgiMrHv0BxK1yj/H2fh8Hel8Uc/Uidejx
         lo5J+HCVUo8JvGkDQwLTfP3GTqkRBDu4nkUUEkTMlyqf0Fw3jJ0WHhSqSU7IID2YiZdN
         VMLR0r+xp37zo1EewyBtdGg2vM7ajJhG4F8+cUP5iKKakYyyYwNg+n2Fx/+kmoaxsCVX
         M0oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=lJ0XXbbEKTvIaTw5DVDXmgqgrUowwljniYcCyrv8nog=;
        b=iw82ucjTA207AOJATAfkzlcWiLUaGwQvBaPyD3obmVuTy67ze5i1Yhh1G/f6CZSSBf
         3wPb37ugnK5IGmhoIym9KIM8AMbYo2J6UEEWT4kAS7tlCTcZkgCFxAw3Kyrciy2ifFlv
         Oc6uhtUdTDOCR/bepX7U4Ww1OVqsmS5VXEO1YWSUPV9Rk9GJZ6eS9d0LYhZZEAXaFM8b
         NOtoo6oZ7ws2UXq89bj4oY98GIwYpCKiDNTeSvS+upF11D3Qc3T66cC1rGNS5yxOx8+W
         cP4JrknELUv/enruKJ03ByTahMuIdsGdjXf76TaLulvSfF379b4TRIz3EA478d3v5I04
         KhpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=s7muJrPv;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.78 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-eopbgr90078.outbound.protection.outlook.com. [40.107.9.78])
        by gmr-mx.google.com with ESMTPS id o10-20020ac25e2a000000b0049ade2c22e5si375650lfg.9.2022.10.10.10.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 10:03:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.9.78 as permitted sender) client-ip=40.107.9.78;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=hxvLOBnYYtvrPUP7e2HtLYAbLcLlSaue9b61Kb+9EMWD1K762qWWN6f0HoxryvHBuvTKZlsew9fq83Y++aVw0XsPLuXra6X0NLzVREGCgOqomFtzb6t6+kjFFvOurvgg4NjJWDgZ0xWO7PGY13t05EiextwEFJKoTok5k+7BLbuGqSUfPhhU0d9xTOQ0bzGOop/Uh3cEmNfV2e49IFqyO12kG4YmZNgriL9gO9ga59WnRgMKMMYKMVIOFsxfXky2/37jjmAGhzxpidZm/utwXZ77AIeRHmtEAzpz6rc2kK2VUfht59FKIWwoGvFiooXFWCyTu8/oWqi3/wpQyEiugw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lJ0XXbbEKTvIaTw5DVDXmgqgrUowwljniYcCyrv8nog=;
 b=SArtbWFU8LBAy3oxyXGdEb4rz9bQZjjd6RXB5dWLX3WPygfH66Q57iKz6i9evTBwl5MpsG7D8HpOUBrxGTg1sRWt6hv48m752cQDQDcjzQu3KZVzoYLDsF0PWLRMzd49vbmz/xzkEI6XsCOEm3zMx1vQA/+iA95duu8U/kqxgw3itrSHN8A1q4mLLumpSVPZNuosGNrJlpqPH+NSb6jEg/YTPaHZBpJQOxoeK5bqO5LJcGi/L2RhGU/D4IXj6bx00yXX7kLa4jEcGyaloKi8t1EBUYtGys8ylZ5DiIzNbF0i4UcXT8Ljy+rjZs3mZSBZkrVTyK8ZHiEoLCYIszdQuQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB2328.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1e3::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.39; Mon, 10 Oct
 2022 17:03:49 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%7]) with mapi id 15.20.5709.015; Mon, 10 Oct 2022
 17:03:49 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Nathan Lynch <nathanl@linux.ibm.com>, Michael Ellerman
	<mpe@ellerman.id.au>
CC: "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Topic: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
Thread-Index: AQHY2EIBh+iraNEA6UKZa+r/wPzLXq4AwrWAgAAPGgCAAfBWAIAE8XqAgAAwYIA=
Date: Mon, 10 Oct 2022 17:03:49 +0000
Message-ID: <6deea219-32c1-f5ba-4192-620f8321077d@csgroup.eu>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
 <87h70for01.fsf@mpe.ellerman.id.au> <8735bvbwgy.fsf@linux.ibm.com>
In-Reply-To: <8735bvbwgy.fsf@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB2328:EE_
x-ms-office365-filtering-correlation-id: aa5667dd-430e-4b20-64c1-08daaae166d4
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: Hyq/aZB5e656B79BIR11HTewe6hjQEXaAnhtBEfIb2rzUaTRYFoudQXJVpymHcIc9Kh2+NeSbQLX5ScQilEa+I6OoPPtW5Z4FaQJFFIJ+gd9F2IucIr6mOHbxrvmGPbxC0E4Crps0e2StP1J4Cd1NYvRj8rb2ip4eDRaHafmfcVqv23Sh2NIZrGV8MZ9qdLYjOBhaVumG5VyDui0o6Pu9tkkW+W+Qb9t1HR2KqDd9PsL63ovim+VF+ZaOcknNuk5gpL5NRq1SVUNgx36NE97JU+bRsSO6uT8qUJr/IPxqs/BeKxT15IxBSIY8NZPxcs1BoMs6KHdvhEspMbp5yd5nKN50GHj6BliMrMpdSj1qR4RZuxK1nbmBsSe9kNnwybfMttzmnHPm5dmm1ggsYKJb0nJdZGtirhzJA+DdJw4+Bkbt8VFjAYB50iK/iUi5R4hJyZTGMkK4x/DCJ2N3xgh4sfD702kaPBmvtSorkocGe9f3NtdXI+3K9qXpAN9yUan+Y6HX2NzRf1OEf5PUhdxLEWjDexGTDMHpXNxYwFcy6UWEHmP4wvsb3woHDL8GhLaRdO94r/wmdQH0HZP8YryEjrbLydEH41t2ZOoUzzP+V3q4OKBljwbGLqxT7wOLrJXdIq+UelvS6eMXXddwFuem5qAuTpxUhUyBFGBC+Ml8BTgA1voAEoI3GDvLkGUX+YWP5vnbpfZaGoU/+0i4fz9I772jXeHeqEumXR1fnmraL7KXat82EyG69dDwt2FdwocQmJfIxC9ylbToyCA9OKtyho7aodeg7UlyZL0CBoU36rDEMV2z5vA3lwmYY1BkrEnGXKgh1Dlf0uCkNohZyb9Qw==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(396003)(39860400002)(376002)(366004)(346002)(136003)(451199015)(316002)(110136005)(478600001)(31686004)(6486002)(54906003)(71200400001)(66476007)(66946007)(76116006)(66556008)(91956017)(8676002)(4326008)(64756008)(66446008)(38100700002)(26005)(83380400001)(6512007)(8936002)(6506007)(41300700001)(2906002)(5660300002)(2616005)(186003)(44832011)(36756003)(86362001)(122000001)(38070700005)(31696002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?L29pOGVjNGJnN1hrOC9LWlZuSXBabWV4M0xwc2ZnQ0xta011aDIwZ0hVWDRp?=
 =?utf-8?B?QVFEaU14RlFEMldHSEl6bTJ1c1hMd1FJTjE0cmtuWDF2SFpSbG4xWWU2VUZX?=
 =?utf-8?B?Z0gvMDZ2OVEvYmpoZ1ZDRmJpYURSOUwxMG5hd2JkbnVGRWVaSk91NDZzZm1E?=
 =?utf-8?B?bTh0TEVuaVdtMlFDc0JUTXp4T0dDNE9zZWNuclc0L0xucTBWNGRGM0ZUU0VP?=
 =?utf-8?B?TUZnUGc5VzhraUIxSmNSVU5hN0Y4UXZ6Y0hqSzBjNkFnaHN3eEh0MHE4MHFM?=
 =?utf-8?B?Qk9qaU4yR2F1eXFZd0EydzBDVThNL3RkcDFEK2U2RWRFaVMrd0pUV3JQV0w4?=
 =?utf-8?B?R0RkTU1QSEtYMXdacDlKMUJJdjlGR1RqUDRJUGtFN0ZKZWNKRmEyV0JNVE16?=
 =?utf-8?B?eUtjUDFpZEhQRTVXeFRSS1BqaU1USXNMQmFmL2tsZWtZaDY1YldaaW5sWU43?=
 =?utf-8?B?ZnpwK3BRNGRGMjh5dFZSbUdBQzJIcXhlTktNQWkwVU5WVmYxQkEzRElYWElv?=
 =?utf-8?B?SWpESFBjbis4QWFnSFFqMFJqSlY0K1loU1VoS3JNOXF0N2ErOWpDdGZhTk82?=
 =?utf-8?B?cEdoTFdkZ3pISkl5RGsyUEZ0Ym9QUWFmbCtjdHMvRDhqRkwwS2tPOVI3UGtQ?=
 =?utf-8?B?RGIzUFpKRlNsR253Tkh1UUVLcVk1cDlCUk4xMGVZc1lxUmpDNXRZbmRET0pa?=
 =?utf-8?B?TVlhUS82c210a1AxaXhXZkZzWWR0bXFHVmk0NkxFWmxSS1JDbVZwcDBWU1dq?=
 =?utf-8?B?cUJzMEJuZnFJcTE2QU1NK09VbTJ0ZThNNVhVeVlqcy9vWXpMc252c3BNTzkv?=
 =?utf-8?B?S01MZGtVUEc0NWVqcFlVMU8zNTFuMW03RFlFdFQvNitOVjB0c1NCVGpBeGFO?=
 =?utf-8?B?cmo2UnJHb01kUzhnSzBuT1JsVWlVbjYwU2U3WnMydC9ZSlpHNGtQaEdSNzJl?=
 =?utf-8?B?NWZQK2thQUp4eW9pUitBVUFjTE91UHdMK3lKKzExeU5BTGVadGt2NFRtQXdq?=
 =?utf-8?B?Mk9XeGFCVU1aYy9VSG51ZGxxYUFTMHpLM05jL0Zrd0d2Vmx2RnRjeE1GcmJi?=
 =?utf-8?B?WkZ0NWZiS0M4eEFRTlZYVUREMVl0c2NNVzkwWlBCQ2g4d2lqc3hNWS8yWGVu?=
 =?utf-8?B?eXZSeXlGSkdKQS9YLzlIS1JVY3p6cEpwMzNDaW1ybXIxYlhuMWpjQ25wRWZh?=
 =?utf-8?B?Q3JVdTZadmkweCtndFdQdEtkY1YxNDg2RnB5NGlhM09YM3VXRWFpTHQ4OE5U?=
 =?utf-8?B?Vk5pb3JURjhQVWNrOHo1bm1qbm1JR1BBcWpzempzS3hiR2tOWnk5WHFtZkFz?=
 =?utf-8?B?eGlvYTFJS2FuZVRTazB0MjJlTmlEZURlbktONE1KbXJwMk1HMi9tUjl4bUor?=
 =?utf-8?B?OW9ueDBBcUlnT1hDRzBhWlE1SGVONjIzQzBtRS9jeVZGWUE1UXlkREJpRkcz?=
 =?utf-8?B?dTEydXI4VHR4NloyQW1oSmpzNTdRZ0RZZVVGc0dkNWN1YytDcHFtMVBzbTdL?=
 =?utf-8?B?K3p0SzA1ZGZLVzIzQVl0cTNrMHF5MlZOUnk2bHhhZVgzQ2NzVS9OdnJWelo2?=
 =?utf-8?B?REF2ekc1bmlYWmRhb1pLc2RBSXVyU2RnSFlQdEtHQTI0dU5YNTJOUXVPUTNW?=
 =?utf-8?B?VE5ONlFEanBLQ0tpVXpkSzBja3doMzFrYTV1K0diMTI1M0VORFd1aytFNk93?=
 =?utf-8?B?Yi9YTWJIUTZvTXlXbEJXVFdjd2FEUEMvSU1uSnZ4cDlMc3lTdXJRS2RxVVY4?=
 =?utf-8?B?SldNTzArVlU2YTdub2J5dEFSQk9jUW93V0RkaFZqYUZRbGpyOXdmUFN5VSs2?=
 =?utf-8?B?T3prbWlaQi91YkFSbVFFd3hyN3oyM1NYdVJ0dUZ5ZitxMjJEZjNhTTQxN25Z?=
 =?utf-8?B?eWxxejNqbW50Z21uUVFVTVNxM2ZDaStmSEFNV0pGaGRKa1F6SklDQXdNam9W?=
 =?utf-8?B?eWkyVW9yTzV2RVcvVWo5Vng3aFQ0VnlESmhRQ1cwQVZDZE01OTdvVG9ybkVw?=
 =?utf-8?B?cFhwNFVPVjZIaHFkdGlOamdBZ1NNT0hlcitRajJHcGU4L2E2bVlEQ2J5cXRz?=
 =?utf-8?B?UzlBeVQ0WG81NTVjaVZlVmc5cDJUQjlSR2tORlJjTk9UaUVoVTQ4eEFuNUs2?=
 =?utf-8?B?RmkzMEJ1UUlUQ2VUY2l4SUtCbGw2cjZWV1NxT0dNeEhBOVFxUGE3TlBIT2pN?=
 =?utf-8?Q?YXXud0XoJwr9r8wPYKrzJJo=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <EEAC9F90E28ECE47817708B8B41C03F0@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: aa5667dd-430e-4b20-64c1-08daaae166d4
X-MS-Exchange-CrossTenant-originalarrivaltime: 10 Oct 2022 17:03:49.5280
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Wn2NoOEv05oHMQ721NZDiMQni2LY++0B1Qk88fV4tU37OohaINZwwh4fRBfnkQTZKNS9bbGkU05gJpDpV1kTfgkHQHL0Qa/D7XG5ZRgtfvo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB2328
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=s7muJrPv;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.9.78 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 10/10/2022 =C3=A0 16:10, Nathan Lynch a =C3=A9crit=C2=A0:
> Michael Ellerman <mpe@ellerman.id.au> writes:
>> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>>> + KASAN list
>>>
>>> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>>>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>>>> KASAN support"):
>>>>>
>>>>>     A kernel with CONFIG_KASAN=3Dy will crash during boot on a machin=
e
>>>>>     using HPT translation because not all the entry points to the
>>>>>     generic KASAN code are protected with a call to kasan_arch_is_rea=
dy().
>>>>
>>>> I guess I thought there was some plan to fix that.
>>>
>>> I was thinking the same.
>>>
>>> Do we have a list of the said entry points to the generic code that are
>>> lacking a call to kasan_arch_is_ready() ?
>>>
>>> Typically, the BUG dump below shows that kasan_byte_accessible() is
>>> lacking the check. It should be straight forward to add
>>> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?
>>
>> Yes :)
>>
>> And one other spot, but the patch below boots OK for me. I'll leave it
>> running for a while just in case there's a path I've missed.
>=20
> It works for me too, thanks (p8 pseries qemu).
>=20
> This avoids the boot-time oops, but kasan remains unimplemented for hash
> mmu. Raising the question: with the trivial crashes addressed, is the
> current message ('KASAN not enabled as it requires radix!') sufficient
> to notify developers (such as me, a week ago) who mean to use kasan on a
> book3s platform, unaware that it's radix-only? Would a WARN or something
> more prominent still be justified?
>=20
> I guess people will figure it out as soon as they think to search the
> kernel log for 'KASAN'...

I don't think the big hammer WARN would be justified.
WARN is supposed to be used only with unexpected conditions.

KASAN not working with hash-MMU is expected. A pr_warn() should be enough.

Someone who has a kernel with KASAN built in but who is not interested=20
by KASAN and who is booting it one a HASH-MMU will be terrified by a WARN.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6deea219-32c1-f5ba-4192-620f8321077d%40csgroup.eu.
