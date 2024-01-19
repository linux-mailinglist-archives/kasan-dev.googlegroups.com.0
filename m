Return-Path: <kasan-dev+bncBCW35TVV54DRBO6VVKWQMGQENUSDXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B05E832D9C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jan 2024 18:00:45 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-5ff7a73e8c4sf1821497b3.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jan 2024 09:00:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705683644; cv=pass;
        d=google.com; s=arc-20160816;
        b=fC95Mb0S6KsT39FibAwXJjscK+QrOuQm/HQ73oqUtvGoQTciLOd3eXNllNsnp1C+bI
         oqEeG+N6xrC/KHM+3oTPxN6sLaxqhhPHsW6hX9dfDXauybh1LEwGW1aGUow0+Rpu5U5S
         0vSHSy/C1+ByClukNEXFJDU3LUBu4e1IupQpHdJorebQUtm3AG6d+BTbr5zARE2JK6gq
         RsV71N8z/QUWoNzYDHnFyGVaq6Fyrd194RKoUeUiVZ5wXrz8iFWe4K6JiYnQdMfJhkjK
         ECzeiHpAODh8wCsuuZ8ep+b3EHoVia/V4hq1mZYJsZbd0kS8Er4EQyUuRDvh7JfXCFD+
         /1aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Jv68tIdcha03rLhxFjuLVT2t69MmmNM6tlu3FgizJ84=;
        fh=hPe+RQtg0fG3w3ohrGiJ8hqH+ngnJHcVHhogV7C9wtU=;
        b=FXH0r07BLoQX93jiiYs1IfiwLfGTraBeCrluxhZM4WdTKznmj/uC4TuiwPdaIuivh2
         LdNC14nBHGBLnXAIXNRFneVcAnsQ5QB/lr/vQP046K7Zg59QYY36A2uPOOrZX4u+3cqR
         XW9IKXUuQ/xM8hxdP8MGy6OOsbodwKyZnDxADorZ0A9C1wJMYZ+FecsXnCEOHE4snIc6
         bll40nIPnCcnoAPlBlidJRLUeC48L/1oxFG4tNqHBfNFX81SqmKLON0nNdD1+cVu/HtS
         yzH8CweSK/5zqqERKf7+gTBxHiF1tJkXA1QrDjQFleFvRvDo7X7vwaCKu6z6NGfc9veN
         y41A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=M1OURMWY;
       spf=pass (google.com: domain of quic_charante@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705683644; x=1706288444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Jv68tIdcha03rLhxFjuLVT2t69MmmNM6tlu3FgizJ84=;
        b=XjeL+eaerRuAymJ3Rwb8D/bT9KNEvQTrlrj6US0cEo9ubJq5k/fa57yk6MUkTNgCiy
         fjj1lqsyl66t7m7aDr7qpYmVgAsg6h/2OYeFSEOOJQjNz3YT+UKMR/xK1oba2VWFks4D
         iDxRXdZ0+ls3RZ9HggFMzvl4go1Cj3Ltp3TatygCWDWeVCTZGR24tJOunuEEk52In+5O
         3xjrgj2SsKNw+ANFkGyH7QNRbTmEVn94VFqovG2Zb+tUrGzz+Mqk8ZsCtwP2C1P4e+RZ
         jyOFOGh8Tr23XX58YWe0xP7UNJtY4A+TNQjH3SzAkm3+oVl/QGTMFB+x/KZB5YDGpSFc
         40Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705683644; x=1706288444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jv68tIdcha03rLhxFjuLVT2t69MmmNM6tlu3FgizJ84=;
        b=vbi2O3iABj2V0EF2d0CMC3Bg66eAgEGx4cU9FCcaNv/qX6KAFhI+07xQTIfxIHIoBr
         kKuGENQsxokGxQ+bS7qt53VzrnkHxGt6ucmBiPe40BWHYgb4O1cE8+t9eutNHvNu6daL
         CH5cgTKvRAwZKUeP5oT/qMJl1WtFLY/XhWdw/TaptQvFQg39BshENysmJGh3gSOLBU9v
         J2kxpOBf3mZQMAoqKFUkRhdBYSMFcpBcKyz6SxWUUtVXlOlI7z5nOOcL9vWGq2tbitus
         tOvIKALAYA1Zves+dHUHAO8XJJlyYllxlVPihloRseJUgR/ayWhEuaWnmjn87FjSlIlU
         +FeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxazoLN6G+ESE/syLR1IQ6Lqvf3VW/JBxpSI7LaXnT/XHitqt9Z
	2OFEjeoPTI8H1yKxk+O/zZmCkglMrZ3VE1uk2SLYVVV0qHKiD6uo
X-Google-Smtp-Source: AGHT+IFODIi9fk17TSqxD5zSeRzHYkR7RcvLU+BW8uXuglLwlgXXk42sriyl/YB2Ags1X273QM5WDQ==
X-Received: by 2002:a5b:60d:0:b0:dc2:23d6:ae3a with SMTP id d13-20020a5b060d000000b00dc223d6ae3amr342951ybq.1.1705683643802;
        Fri, 19 Jan 2024 09:00:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:726:b0:dc2:3107:a9fa with SMTP id
 l6-20020a056902072600b00dc23107a9fals374941ybt.0.-pod-prod-02-us; Fri, 19 Jan
 2024 09:00:42 -0800 (PST)
X-Received: by 2002:a25:df14:0:b0:dbc:43c5:c227 with SMTP id w20-20020a25df14000000b00dbc43c5c227mr158304ybg.114.1705683642715;
        Fri, 19 Jan 2024 09:00:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705683642; cv=none;
        d=google.com; s=arc-20160816;
        b=yY/qAw1UX4w9+cm9+vPCwysNAXdypuT8yw5cL7vuCazm8Z7w1BnSZYpRFO8M9yyvtw
         w7dkH5a6hgOvhqAx8nL5Qv59rj5oPPk1P0AU2r0aRazDt+urKSSG8KjryGnJbN8eRld/
         QmY8fs1PyvS49onjMvvwgjE+cBsjI2Ul6JhD8wVe6lS7mA7r0WoKZiPbwNCiFx+ahE5O
         ogWFia36L/9eNbGoFzJsULULkfA9CobMlmHouUdPvUt02+NXxgIiuL9SEgcyETsujvFj
         6mjmw2V+QDRiIXKaq1dfacebZ1oFT3xEmGT8OO/UQdNs/N+/mbjp1Bf0dbKBhl/+FDta
         PqkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Qy1pMhP/rRJ1IzNoHsuqbIjw26g6hcRy+ObDQ8oRG60=;
        fh=hPe+RQtg0fG3w3ohrGiJ8hqH+ngnJHcVHhogV7C9wtU=;
        b=NUSifhKpf7XZkYlMaGYX6UVf/arwQN4GAmUKg+KsHu/OV17iuvrxmAsktWjPWx2dQy
         bisJjm/NLcqShK8cFw50MiptU2UxDUk2zimbvG+QM37yYCb9Gu2+9R31xcrpzJfuQF7E
         rElYr/QvV2RDvbaQmm0B+piHRYAMy/wEpNJnO8TkDZ9CIvAy+rfreMDtp+/x3D0yLN6+
         iyjhCE4YGqgkZF9FJwO0QsYVGrBiiALjc/3n3BPGe8JfW4P5zM8pOIfHVBbJ0b6T+bRz
         2HnSzaY2AzJDLBRYgw2rJ3fi7CRSAMai3jgtBGHxeTHJWDnJpoLIaFAW4Sq3xN1b0fZC
         g/vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=M1OURMWY;
       spf=pass (google.com: domain of quic_charante@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id o200-20020a2541d1000000b00dc2340ff8c9si626559yba.2.2024.01.19.09.00.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jan 2024 09:00:42 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_charante@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279868.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 40JCbQb8010388;
	Fri, 19 Jan 2024 17:00:32 GMT
Received: from nalasppmta03.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3vqpkvguj8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 19 Jan 2024 17:00:32 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA03.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 40JH0UMe027236
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 19 Jan 2024 17:00:30 GMT
Received: from [10.216.49.108] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1118.40; Fri, 19 Jan
 2024 09:00:26 -0800
Message-ID: <a6f9a1fd-0ce2-b6be-6efe-181c54f950a0@quicinc.com>
Date: Fri, 19 Jan 2024 22:30:22 +0530
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH] mm, kmsan: fix infinite recursion due to RCU critical
 section
To: Marco Elver <elver@google.com>
CC: Andrew Morton <akpm@linux-foundation.org>,
        Alexander Potapenko
	<glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov
	<bp@alien8.de>,
        Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
        "H. Peter Anvin" <hpa@zytor.com>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
        <syzbot+93a9e8a3dea8d6085e12@syzkaller.appspotmail.com>
References: <20240118110022.2538350-1-elver@google.com>
 <CANpmjNPx0j-x_SDu777gaV1oOFuPmHV3xFfru56UzBXHnZhYLg@mail.gmail.com>
 <cd742d1d-70a3-586b-4bf5-fcfc94c75b4a@quicinc.com>
 <CANpmjNNZ6vV7DJ+SBGcSnV6qzkmH_J=WrofrfaAeidvSG2nHbQ@mail.gmail.com>
Content-Language: en-US
From: Charan Teja Kalla <quic_charante@quicinc.com>
In-Reply-To: <CANpmjNNZ6vV7DJ+SBGcSnV6qzkmH_J=WrofrfaAeidvSG2nHbQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: vwcSK_orfgT8C__2D3CJHzd-MY-j7Ask
X-Proofpoint-ORIG-GUID: vwcSK_orfgT8C__2D3CJHzd-MY-j7Ask
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-19_10,2024-01-19_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 lowpriorityscore=0 mlxlogscore=739 phishscore=0 bulkscore=0
 impostorscore=0 suspectscore=0 priorityscore=1501 adultscore=0
 malwarescore=0 spamscore=0 mlxscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2311290000 definitions=main-2401190097
X-Original-Sender: quic_charante@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=M1OURMWY;       spf=pass
 (google.com: domain of quic_charante@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_charante@quicinc.com;
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



On 1/18/2024 5:52 PM, Marco Elver wrote:
> It would be nice to avoid duplicating functions - both options have downsides:
> 1. Shared pfn_valid(): it might break for KMSAN again in future if new
> recursion is introduced.
> 2. KMSAN-version of pfn_valid(): it might break if pfn_valid() changes
> in future.
> 
> I suspect #1 is less likely.
> 
> What is your main concern by switching to rcu_read_lock_sched()?

No concerns from my side. Just wanted to know the thought behind
changing the pfn_valid instead of kmsan version, like for some
functions. Thanks for the clarification.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6f9a1fd-0ce2-b6be-6efe-181c54f950a0%40quicinc.com.
