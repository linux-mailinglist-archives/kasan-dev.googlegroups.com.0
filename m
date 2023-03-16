Return-Path: <kasan-dev+bncBDVL3PXJZILBBQPVZOQAMGQE6TIW3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A22926BCDD9
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 12:17:23 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id p9-20020a17090a930900b00237a7f862dfsf2406062pjo.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 04:17:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678965442; cv=pass;
        d=google.com; s=arc-20160816;
        b=ns1ixmiQrv+ESASIN5FO+XkeKng1RNhsdyC5b35cTCQxi3/d9d7pwLZrC6tZOej6g9
         2/rcqObCouGFe/wQLPbBGNeQTIsVLrPLTX2axYPp9VIHbUnlv9VTycwdzk5wiIxpreHs
         sLLiNEdZFw/4l/ktF4F/MKC9csqnd0aqUtKwhsgUaRt0VBEWOU9mTQE8knMn235SYHol
         FjJEj0+OAexkQQu60hhnBPfrdJmeA3DjZOc1Nz8XEG6G8b3vXHAclxmE6/idyktmC8wi
         OJV4RKU2o4AD3KrYGHL6mfDeiLlZsLLO5LwfCFW7X7wBYaE2e/YNW4/Iohu2v3YS0Ulx
         KJpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=cFN04U1vVRUWKKoG5gkaQuSXNHBMSrRVrNakKonoDGE=;
        b=z0vTlAyZaQtfhuE+L1x9LFrd7nO4HKZSRZtqaCk9zOod/sG3qCY5yPE7GlumK6F/5w
         twDkAy540gj3E02OOL5Qb0WWuW5w6oSTVmm2/fWCICRJ41oH2e9I7LxJ8pwGyu7Fa1+7
         ao9lwS9pwYmCZaDNIh6BdttqZh6MALF/ELc750/BbzBcwOfz6WSaTFd01P61g88enT2K
         7Yw9jzJRfHKKYvoXzyNJASQNxkM78msZlyHTfFfYPbs3rFK2aFnhkBURWH+feZcGsELS
         3MNZLmNtHrbkWJRNFi92sgneMQPr+9sfe8sdFkRoVs6WGJSkMkPI4domrrGF+hKz+WcC
         uUMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JAZP3jAx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678965442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cFN04U1vVRUWKKoG5gkaQuSXNHBMSrRVrNakKonoDGE=;
        b=snzGv4YgdqMDvhEkfad57zIaDAKUWpc0mRjzD0he4fBsaFdKe4NHZwVC2AUqsP+GQX
         YSgxTJH2rIHCOgzLks5QHYOQvLm8BMY/e73eoHU/VZEqfQKKaUyHu2buS7V1UY0ZfCED
         JnK+XXSGVg09vRqgvHIYOeZEInu/nvmXlalrr9yAjdWngTSBS9dRbUCyyPXPJVma4ubq
         JdzNB6Vb69HKGd9+LxBm7NawzixsiHC/X7+mNVC558i4YUZ+gEwH3tf+xhCO60WrU2ur
         /1vIxclkpSkep5OzJj0gsd4d3XgeixG1xzaQYlbRIPHnCaLo/O2dKh9Qp+jsRku3Ra69
         QQXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678965442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cFN04U1vVRUWKKoG5gkaQuSXNHBMSrRVrNakKonoDGE=;
        b=0k7o+28XGLnyybxs7f2sO0/6iaHbzXHlfreavFyy7FyZS3QJPsv7ubKt++A/HAAZ8p
         nB/JkEnwGygYZnihdpJ26X3IYL31Gk5VbLlJCyEcBRbp/D7xWWpNdqteIila7Vk9XdcU
         hM2tdrHH0OtRegdtvEKh7wUIT6JHH1yWZfULyy73HLXE9dKDGIa9CDojRTNyTT7w7SVC
         qzrBmJk+tGQ1ixXw8ZP/vKrLaSiDxNCKT9zLcEHDD58KM1eTa25Dtaa7RUMNH9gd8RpZ
         EZR2ORajUuD1fhYGgRYqtBRhLaN+ugHEf+T9lXMYUh/+1Ek2GuK9y3HlU/he/MUgXbg1
         XklA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWU+oEfkv9aRZ5T+ttFn9frNkUVBGl9zsmk2yJv+C9QegGVihtT
	xF3M1kj6I1DLeQa7xtvAvZ4=
X-Google-Smtp-Source: AK7set+s8/6Ha0atFylLu+Pzzsy/hKctgnLL8KqLpGw9rqAQfZ1qVckggp4QZMyTT+/bAvOgYOfNiA==
X-Received: by 2002:a63:2dc6:0:b0:501:f894:ae62 with SMTP id t189-20020a632dc6000000b00501f894ae62mr884849pgt.4.1678965442080;
        Thu, 16 Mar 2023 04:17:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d242:0:b0:50b:ed87:84f3 with SMTP id t2-20020a63d242000000b0050bed8784f3ls340090pgi.1.-pod-prod-gmail;
 Thu, 16 Mar 2023 04:17:21 -0700 (PDT)
X-Received: by 2002:aa7:9803:0:b0:593:ed9c:9f07 with SMTP id e3-20020aa79803000000b00593ed9c9f07mr2663956pfl.27.1678965441295;
        Thu, 16 Mar 2023 04:17:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678965441; cv=none;
        d=google.com; s=arc-20160816;
        b=fFuaJIf5R7Ana+UzTyDJxCMTzeAF5hZEt7CvI86CLWq8AywWTmtNfsTMLQFYlhpC99
         dxMcHhjFj3kj8pWgqhq8mDD6oxPtQ25hlCCIXjshqSf9eIWQGXf0qAMAjQ3Fw2ejLPAU
         Xi2jfdcgFoAXb/CR6IYe0nkyTX+cevsquL+NcAErsw6TWRcLBFgFbCwgPbSlOuT49640
         PX0fNljtYAwJEggc7VcjQRNGQ3e55JHjxM4I8J+jRMs42kpc0axfACqxzi4Cf+V5n6ZQ
         h/dqc8itvQeWFXjqx030kQQx3ofvSyY3CrTSB8bgKux7m6/DM9dxepJCEd/rCUWy3e70
         5yWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=upmBsZgsLImCaMA1prwsb9RFr8WfsLuQGm9H1zzqgZs=;
        b=ngA4VvGlGNl2cn/tlFleLb3tXkTvYoETk9V+2NExa1qcQsxbuz8b5yiqvKUuNrj3mx
         MGI5UfsHj0ltHJrLaL/5gu++HCAN5AHQBlI8mFRfpbFBubfMlTNRSsXc8AhVs/AgsG8j
         wuTRfgCHqVMPeQB0fAso5MXwl3cN8A/5K8Y+ahx371SCEdYD3L58AqHDsgbMtmcIgUQ6
         XL/rIfWfK+bp1hxw2JlKss1RKG7w+sSFshWMCfvhEHrJRnoPTJQQVkCMAWeybvOUEUwn
         /LTUVSjuvqSSAmmmm43o/jpRz+3ReGZjhQIkA54R6R78n0/psHzSXpj3LTWZkBO+QAde
         2O9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=JAZP3jAx;
       spf=pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) smtp.mailfrom=quic_zhenhuah@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0a-0031df01.pphosted.com (mx0a-0031df01.pphosted.com. [205.220.168.131])
        by gmr-mx.google.com with ESMTPS id bl24-20020a056a00281800b00625965308absi195459pfb.3.2023.03.16.04.17.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Mar 2023 04:17:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_zhenhuah@quicinc.com designates 205.220.168.131 as permitted sender) client-ip=205.220.168.131;
Received: from pps.filterd (m0279866.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 32G3q35V022413;
	Thu, 16 Mar 2023 11:17:14 GMT
Received: from nalasppmta02.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3pbpxjsn0r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 11:17:14 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA02.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 32GBHDbg006838
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Mar 2023 11:17:13 GMT
Received: from [10.239.132.245] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.41; Thu, 16 Mar
 2023 04:17:09 -0700
Message-ID: <5815d357-042e-2739-6d7b-960c81a50432@quicinc.com>
Date: Thu, 16 Mar 2023 19:17:06 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>
CC: Pavan Kondeti <quic_pkondeti@quicinc.com>, <catalin.marinas@arm.com>,
        <will@kernel.org>, <elver@google.com>, <dvyukov@google.com>,
        <akpm@linux-foundation.org>, <robin.murphy@arm.com>,
        <mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>,
        <wangkefeng.wang@huawei.com>, <linux-arm-kernel@lists.infradead.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
        <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230316095812.GA1695912@hu-pkondeti-hyd.qualcomm.com>
 <e363fd76-67fb-5a0f-5ef9-59d55aa2f447@quicinc.com>
 <CAG_fn=UigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-99VtA@mail.gmail.com>
From: Zhenhua Huang <quic_zhenhuah@quicinc.com>
In-Reply-To: <CAG_fn=UigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-99VtA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: 4112Lw9nuVKk6S1_yXK3RkNTiIv7VyBT
X-Proofpoint-ORIG-GUID: 4112Lw9nuVKk6S1_yXK3RkNTiIv7VyBT
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-03-16_08,2023-03-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 priorityscore=1501 phishscore=0 malwarescore=0 lowpriorityscore=0
 adultscore=0 impostorscore=0 mlxscore=0 bulkscore=0 clxscore=1015
 mlxlogscore=662 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2303150002 definitions=main-2303160095
X-Original-Sender: quic_zhenhuah@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=JAZP3jAx;       spf=pass
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



On 2023/3/16 18:56, Alexander Potapenko wrote:
>=20
>=20
>      >> +=C2=A0 =C2=A0 /* Kfence pool needs page-level mapping */
>      >> +=C2=A0 =C2=A0 if (early_kfence_pool) {
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 __map_memblock(pgdp, e=
arly_kfence_pool,
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 early_kfence_pool + KFENCE_POOL_SIZE,
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 pgprot_tagged(PAGE_KERNEL),
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 memblock_clear_nomap(e=
arly_kfence_pool,
>     KFENCE_POOL_SIZE);
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /* kfence_pool really =
mapped now */
>      >> +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 kfence_set_pool(early_=
kfence_pool);
>      >> +=C2=A0 =C2=A0 }
>      >
>      > Why not wrap this under CONFIG_KFENCE ? early_kfence_pool can
>     also go in
>      > there?
>=20
>     Because I didn't want to add CONFIG_KFENCE in function.. in the case =
of
>     w/o CONFIG_KFENCE, early_kfence_pool should be always NULL.
>=20
> Please no. If the code is not used in non-KFENCE build, it should not be=
=20
> compiled. Same holds for the variables that only exist in KFENCE builds.

Got it, yeah.. it seems not make sense to have this variable w/o=20
CONFIG_KFENCE.

Thanks,
Zhenhua

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5815d357-042e-2739-6d7b-960c81a50432%40quicinc.com.
