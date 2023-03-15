Return-Path: <kasan-dev+bncBDVL3PXJZILBB3GTY2QAMGQEM7ET6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id EC1C96BAF0B
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 12:20:13 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id az31-20020a05620a171f00b00745746178e2sf5817985qkb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 04:20:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678879212; cv=pass;
        d=google.com; s=arc-20160816;
        b=IpZeeYjZeOAYCN4ZE2+5Iy/aRCcbfC9rLs0N7gUaMdO0g+DwPpgwfBFzKPEeRIdnvM
         PN6Oi6lzIHU6sGlik0O+HEWgadKeuNd2fOZ8gMBog07CFlHVo3dhUeeX5yOb0kzeD1n3
         pe24J7C6w8f0uaedK8oaQB9X6wwmWS5UPWCX4jcYvt6NgRxHc69CtOmK7Sb4clyIbZrv
         1XcphWDFXQbSnv5dQQGsVez31sS9Fk08NdyD0Z7uipG4PXjgYdFl7Rc0lhIdANo3XTo7
         ONH1sWMmcHTYABQQKqZlR4Inx3TJ4YFQEAjGSzNJWaYZ2KtS57Xo8KqaV5JQvlwONbPR
         /nKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=j2TIFbe6lVHbt6v3r/Sm66VppNOFH4iVIaPSjnsGONU=;
        b=oNHl4DyT3hLKfhepPdVWqc1RmG46F5uXJ0wqmcjPjOcCFWDRECF/sXxDm4LxIoxRLx
         cYUybpfxJJtKlEn9CqNgXu6ok0w5BGmN3ODTqznduLwiRJth8VdjUsXJjCSv9tzLwuuH
         mQYqyNV2PCaZBw2jQGI8KMXe0CGQlDaJJ9BNjBFM75GSjrf3RBhBrxlaa1kUFfzybJkY
         XqxbjzTF/HOjkmbL5CahQTADx2hjo5PnS73/6xSYvezMFjGfAw8efn1nnXfjhIQ8DgwO
         XkkiW3/awOeeARf84dOS22RRhI4Y/Iv1yqEj5ZD5t15Fe7FmqqZjsxhlocsWKpYFK43t
         H4vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JODU+NKT;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678879212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=j2TIFbe6lVHbt6v3r/Sm66VppNOFH4iVIaPSjnsGONU=;
        b=t9D/DCGUNSH0Fq6rvsQKN5EUqoJ1bwdHi7Lm17QvKxu2ynRE5a6eNNWaWRbfpxKgo+
         cQojQG9TlYRP7uJeKp/WmX+zgz3KyQjHRkPvGKHeLHbPgwZaALuMMSlcpqVtVS452Z/A
         BeOABzfTYCGyxyqrrLRYjXUyVPy3XXw/D/LaYtOSAXmWhwn7ajUDidmHDUPCIZ7uNDDj
         sIeO7f1wE/GsSooU3jMfcD7k57hgdvs3/p4RXsGDVJlBn6/uS5zIPS4zzHVT1yQ96jYE
         UXqdFQY3HlAq3jECNdOlh8b9rRQuK9pVxFnmQcE2EF99kUx7q4VOelkrx2IwvUZ5n6j4
         Mbvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678879212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j2TIFbe6lVHbt6v3r/Sm66VppNOFH4iVIaPSjnsGONU=;
        b=t9AhQSxs+ALzxbRj89x32g2VZCmClWue/BEfQdIRUogT5PlGTzDLjkvPJ67CnmHlSq
         ZC8exhL5W6J1OfqCQBHG3BR/6WcrnPJL9FvIC36jeXKSDCYhSdtgZNtSOmk+z+8I2rEi
         j8AMMzfdQBC9RN2DNxJNAUQYilj74BRvsPUQYlSPPt8CdZtZaiQd7h5abryaxnzlfMI3
         YTYpjv1sd67bjwerkSSL1uteLSRQBsFkW3iTeUWgXGiE9nnySWUsPBKa1kj1j+yU3kcL
         jY6FlEyL7qnkYtPHAWt9AXxzjTLrjcU2E3Ee+GquCWG5lK/O0eCz6LG9WawufIhFT4wt
         jbIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX4I6zeQm8gxx2q2ZUp3MkvXNdJmwKqosEeUPlAPOdFYx3JeeTA
	mVIvloMIti3BVBoZcATFsyA=
X-Google-Smtp-Source: AK7set/Hgdi9h2WAVd1q+kLVsEe1P/FD4pwK3RSfJX9OxcwGHm0nV6LE8fx8rDhiGIne6Y0ChtTDag==
X-Received: by 2002:a05:6214:805:b0:56b:ed36:ffb with SMTP id df5-20020a056214080500b0056bed360ffbmr1910715qvb.1.1678879212718;
        Wed, 15 Mar 2023 04:20:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:401c:b0:56e:8a76:960e with SMTP id
 kd28-20020a056214401c00b0056e8a76960els14192958qvb.9.-pod-prod-gmail; Wed, 15
 Mar 2023 04:20:12 -0700 (PDT)
X-Received: by 2002:a05:6214:2342:b0:56e:b347:8df4 with SMTP id hu2-20020a056214234200b0056eb3478df4mr25573214qvb.11.1678879212036;
        Wed, 15 Mar 2023 04:20:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678879212; cv=none;
        d=google.com; s=arc-20160816;
        b=JLPSwOwh5zOiVGgISg6ELax1/nKezMRpMeXfZBJ4mBejCR7HUss24lf4+h9vGSosj4
         IVs3/XRZsQE6Y90hyPhpZNrnbvlLSUtONSDXERLogS5tvtcspidnLQSuipjBkfDzIrMi
         o0fuLxwD66stb+0dPsLj5MXDboo6n/5pPjMf8n3n0maQPoft7Njxe0ZA0A9Q+EoMnE85
         OPSYm5C/dVxvTjq66YIuGv3Irp1oHtqhc58DgA8RjRDXHREJJ6NuaV36JsOJSjLQnxBP
         LygLOFuHFM2pXbu/o8otheH28uZiqjiplfmcscjtafdLdIzQ0FT8GV0fO0ZflGI/kH6Y
         DQ3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=nAmy6rM43Ucr5kkv/7b/BMijHMw5P7vDYkyBBuCOLVU=;
        b=eJvLtEryilAobIW6uu1Af8EiAyFMnhPYIpney4OdIOBt8LSGt7iakJqNcWDpu0lsBn
         0+mHdjSUUWCIaj2m0s5v7LoRiePy+hMRQ7mD+oNnVhegFxtsCunBe2lx5uLnex0D9tVd
         fweaVX6lAbksjBt3HRaDQDeHBIHKPraKzu85LzcX4jKqyTdmClmyv7UGIFe+9wj4odxH
         jYoXBX/M02UULJhlMQX6utx6z8ngqtOIVyXwUccrvzQlb7vbClOzEIb/ThiN5DPvF3bp
         +MMTmFQz7nqyebs52vH2kbhR53MUZvrgGHp8FLqsBxWgRaMcEzYTt39zRcUvquGqPERQ
         4qoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JODU+NKT;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id h3-20020a37c443000000b0070650f71b4asi258886qkm.1.2023.03.15.04.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Mar 2023 04:20:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279863.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32FALQu2027036;
	Wed, 15 Mar 2023 11:20:05 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pb2c21axg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Mar 2023 11:20:04 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32FBK43U005147
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Mar 2023 11:20:04 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Wed, 15 Mar
 2023 04:20:00 -0700
Message-ID: <10f77045-e3b6-3a12-ed6f-0279c155c462@quicinc.com>
Date: Wed, 15 Mar 2023 19:19:57 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v8] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: Pavan Kondeti <quic_pkondeti@quicinc.com>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <glider@google.com>, <dvyukov@google.com>,
        <akpm@linux-foundation.org>, <robin.murphy@arm.com>,
        <mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>,
        <wangkefeng.wang@huawei.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>,
        <quic_charante@quicinc.com>
References: <1678777502-6933-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230314083645.GA556474@hu-pkondeti-hyd.qualcomm.com>
 <b1273aad-c952-8c42-f869-22b6fd78c632@quicinc.com>
 <20230314111422.GB556474@hu-pkondeti-hyd.qualcomm.com>
 <3253f502-aa2e-f8c9-b5bd-8eb20e5f6c5e@quicinc.com>
 <ZBGHUYJ2OY9Pz93U@elver.google.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <ZBGHUYJ2OY9Pz93U@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 59O3P8cWaavlzXeXE_0lMYTW0IIQl3wB
X-Proofpoint-ORIG-GUID: 59O3P8cWaavlzXeXE_0lMYTW0IIQl3wB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-15_04,2023-03-15_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 clxscore=1015
 bulkscore=0 spamscore=0 lowpriorityscore=0 suspectscore=0 mlxscore=0
 phishscore=0 impostorscore=0 adultscore=0 malwarescore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2302240000 definitions=main-2303150097
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=JODU+NKT;       spf=pass
 (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131
 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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



On 2023/3/15 16:52, Marco Elver wrote:
> On Wed, Mar 15, 2023 at 02:51PM +0800, Zhenhua Huang wrote:
> [...]
>>> Is it possible to free this early allocated memory later in
>>> mm_init()->kfence_alloc_pool()? if that is not possible, can we think of
>>> adding early param for kfence?
>>
>> If we freed that buffer, there may be no chance to get that page granularity
>> mapped buffer again.. as all these allocation/free are through normal buddy
>> allocator.
>>
>> At this stage, seems only additional early param can work.. Marco previously
>> wanted to reuse sample_interval but seems not doable now.
>>
>> Hi Marco,
>>
>> Sorry, Can we thought of the solution again? like
>> ARM64:
>> 1. intercepts early boot arg and gives early alloc memory to KFENCE
>> 2. KFENCE to disable dynamic switch
>> 3. disable page gran and save memory overhead
>> The purpose is in the case of w/o boot arg, it's just same as now.. arch
>> specific kfence buffer will not allocate. And w/ boot arg, we can get
>> expected saving.
> 
> You can get kfence.sample_interval with early_param(). mm/kfence/core.c
> should be left as is with a module param, so it can be set at runtime in
> /sys/modules/kfence/parameters/.
> 
> However you can add this to the #ifdef CONFIG_KFENCE in arm64 code
> you're adding:
> 
>    static bool kfence_early_init __initdata = !!CONFIG_KFENCE_SAMPLE_INTERVAL;
>    static int __init parse_kfence_early_init(char *p) {
>    	int val;
> 
>    	if (get_option(&p, &val))
>    		kfence_early_init = !!val;
>    	return 0;
>    }
>    early_param("kfence.sample_interval", parse_kfence_early_init);
> 
> Nothing is preventing us from parsing kfence.sample_interval twice
> during boot. At this stage you don't need the actual sample_interval,
> only if kfence.sample_interval was provided on the cmdline and is not 0.
> 
> That will avoid adding another new param.

I'm fine with above solution, Thanks Marco. Let me make the patch and 
share further.

Thanks,
Zhenhua

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10f77045-e3b6-3a12-ed6f-0279c155c462%40quicinc.com.
