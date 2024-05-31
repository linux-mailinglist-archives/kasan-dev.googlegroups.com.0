Return-Path: <kasan-dev+bncBCCNRMPMZ4PRBAVN46ZAMGQEWLQ4Z5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 45B608D639B
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 15:54:12 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-dfa66bec5f1sf153831276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 06:54:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717163651; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Hlus6zaW0w481BfOoHYG5FuUeCFrwaiLVEQ6WUJsKs1OIF2q1i6NHjsrHav2uALBP
         nTDJw89E3nxyDf4ib1TcknqO8CZE15XeOL1K9e9y8oN5NKsD36WyyBQbkM60g8zdTY1p
         /1iCEDiApkL8vmZRFz/WBHmPuZFjjdoIfrVooi6rN8kulO4++9YzdEguEl4MVbno/3Od
         RQg1tPl3dQIYmyta/9ogeIn8OfhVsn/ZjB0oPh6N28OLohNtuwggLHoZnmOl578fMH6S
         3CDNMdj/5TkVJGmHiQS5cUvIEWK7GrW2xthNB4xZC2xdrXuiQ2qNkALjrjP5qvw01B7e
         3hlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1ju04BP7Re+1UXbUwttRf2DhvNws1ubp6iBAoyBpHiw=;
        fh=17s5w+b2plJSxw6qdCxH/9SKEose4WAihzqBYkVFGec=;
        b=PbJ9CXR11u+YcI92+aqOWFW+LV/tE9jFI5g30AT5OamWAhjno/CFedkVWWIfY+UNKD
         G8Y+FCqZioGGQMMAy6EP49tBVQW5sv18T7ju+6Zzn+2cuQMfg8G0n0SX5rdiNMB6zqK0
         AOzBTYupx1xdJRggnDFoVugs9lQXhEfraEIP8NfPPd950xoAEI8ATt5/2ttxj37BemhE
         zrMuBPp9V48zs4xGY/SfqwWR14B+krOnffUpPyr+c12HeiBKZ6zO1W4kZzqaZnUOyJiQ
         j9qVye2ykmipGWd+1CcmAkv4fuuZWBGOCnSJ6J4IkMKGvVOFNiRGvKT1y2Mq+n3e+zqH
         DP8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=b8ZktriU;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717163651; x=1717768451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1ju04BP7Re+1UXbUwttRf2DhvNws1ubp6iBAoyBpHiw=;
        b=VQznzXn2C3pzoCYVqcvy87CsCQmu/YkgxeBakyaFI5Yt0XdaIAkRcrzPwdFQV9ONOy
         JpeIW7/vWRr5QF4Z1/dnBkDCoOlIFiEfQuljCVf85OPaHc4kRmZlJBFhNiCMiHAS9PDH
         W4fQcnYFuR/r+mXZ3MyEE6BMNxx4VscBB2OP32gjx+HWDon9dcj23hXtStRRZLVUtiBO
         6SiTPMdAgJ8Y5awt+ng5yDH2mmF3kBdTL0OAvqwuENlaTmfgzoOGRSymAGfCXYhadGaz
         slrc8f31q0e2jCGzXdkqUGd2uuBEt+czLIm5hJ5pQpSRNXDVs/78yR6EsSb8KrpKbxR1
         /qSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717163651; x=1717768451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1ju04BP7Re+1UXbUwttRf2DhvNws1ubp6iBAoyBpHiw=;
        b=kTxoPDfG8hbJ/huoJXsxT1S4zdr7b8mcJM6+L8e+srsFp2D6p2BFeLQVbGVQV4B0hg
         crvxvLaLMKHv/h5gN8boRvGjZNmpWu6I50lm9Y2BUs+/LH9x1sIBCqN1cud09JSmUb+I
         WXRl+46gJSl2/gWi0HRuE/jSP3UsCgwR3cn+WWk443dBCi+0F//P3NNtJONVKB1bQwaL
         GKua+dloSgxY0FUdPpI8wDt3I90z4OrQExRR3UWriKFudn8Eee6kK8K7sPW4ozyz/rGl
         hKK6B/XeGnZIEgXRdWObjXU/LeZFQy7G6DRBjnZP9CC6QKNhQ2EwX1frmsn1wK4KjCVb
         WPHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBfRpCEp86U1RPzwDpQrkC7GscJexiI7RnLbLPKJ0UXfnwi+z7ZR1CW3yht4ZSsgmKwaIjsKVb4Q5unT1ldMVdGvG6v4m8qg==
X-Gm-Message-State: AOJu0YyrrUctVFXajzMa8BCdGAjMsI/h2xfE0+YzvWHy0luUdrzQ4Vak
	t5ZbQOonktb4rN9cbY+8Rze0HnUs4HKi/C4UwHrcUYOcPUrEd5Iz
X-Google-Smtp-Source: AGHT+IHqCUdYbUSloyUPysw+aUlOgZpnVQZW48ANKVBvSENJcXKHCb0qfKY9Fhn3gZ5BhITIsgpofw==
X-Received: by 2002:a05:6902:220e:b0:dfa:70a5:e3fa with SMTP id 3f1490d57ef6-dfa72ec9826mr1573361276.0.1717163650839;
        Fri, 31 May 2024 06:54:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b54:0:b0:df7:930c:b0d8 with SMTP id 3f1490d57ef6-dfa6e40491als1191749276.2.-pod-prod-01-us;
 Fri, 31 May 2024 06:54:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4Mxqt9pKWmbS2NOYi6kA5J4d03Z+gtFwRY8T7cMNSwcrmVkiYAblMcLr8+WRRS6K0da4ZYBVLmlzrBTmLdo/IkYBiyAoWa1s/zg==
X-Received: by 2002:a81:4917:0:b0:61b:bd65:1538 with SMTP id 00721157ae682-62c7965b4ebmr18334787b3.3.1717163649957;
        Fri, 31 May 2024 06:54:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717163649; cv=none;
        d=google.com; s=arc-20160816;
        b=YxLCnQ5U5S6XFCgS7nantoz578pUnTJOYdAtmAHJ4DlPTn5YTW+SMmu9IObnMMsMDv
         3dP3BiUNd7sSRLKrku9sUXH4D6SoK12NRES15VSjb+TrkkqQsWytzhnYv4WEHboiPPNT
         PHn71OBiwANKJvTYbtEGVHADIx/3Zdm/IF0HWiM8UTyW7LbCdHhXphVQzlCvwgCd23TE
         fZ+mwEeo5Xaclvq5BG6XgXmFSvXr24ywJ2JR955cm4m3yzOzpkeJ7MvZtBfPLmyJrsbM
         e9PF6MHndkkjx7CjqaniE8Ld0pqRpfGNJY+VdWid9YNdZkBIzuCyg/G0rVwhVcO3jqhD
         xGkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=PYcMr99pnsmRTjwDC+d550mFjpzxJZe2o8cYFN49Ej4=;
        fh=d4cGhYzl35QewiKGAnJgSkh44alwHDkI/LJuPzNFNZk=;
        b=TqKxu+pXil5NwAvo9j7j2liDqkmF22kh+Q+oR8rrAZsTpvj9EnggBZJcVrGzX53mwR
         MAPauf3eK38C3sm6+5aV8WRwfxwQZXizrOPFUOB3CwjR1gshUD295l4NwipFrgQBxvI/
         OPolRmOEpbx7mY8XxaFi2UN0Xi6GHx48v8IyRhaNpgfEU0GR/ZjwUjcLNsb/jCDduF3L
         WkzmpMrVad9S++sxyBFxyzYsDhUA8mY6sAXdJTvmTatdvG8aVVGtsJ64EWCjcS60ha/6
         kP3uC7LHS0u0LS48eE3BupDJ1I/x4QFNt2y2SotzhdiuIyHxdWtPMRmSNTcpgRj0kYA1
         5uzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=b8ZktriU;
       spf=pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-62c766dbcfdsi1208247b3.3.2024.05.31.06.54.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2024 06:54:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279872.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 44V711r5001099;
	Fri, 31 May 2024 13:54:07 GMT
Received: from nalasppmta01.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3yb9yjf43t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 31 May 2024 13:54:07 +0000 (GMT)
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA01.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 44VDs6vH013000
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 31 May 2024 13:54:06 GMT
Received: from [10.110.11.230] (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1544.9; Fri, 31 May
 2024 06:54:05 -0700
Message-ID: <e9b4a22f-1842-4c37-8248-4f715d70a6c1@quicinc.com>
Date: Fri, 31 May 2024 06:54:03 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kcsan: test: add missing MODULE_DESCRIPTION() macro
Content-Language: en-US
To: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
CC: Dmitry Vyukov <dvyukov@google.com>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <kernel-janitors@vger.kernel.org>
References: <20240530-md-kernel-kcsan-v1-1-a6f69570fdf6@quicinc.com>
 <CANpmjNN1qf=uUnetER3CPZ9d5DSU_S5n-4dka3mDKgV-Jq0Jgw@mail.gmail.com>
From: Jeff Johnson <quic_jjohnson@quicinc.com>
In-Reply-To: <CANpmjNN1qf=uUnetER3CPZ9d5DSU_S5n-4dka3mDKgV-Jq0Jgw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: PtadWKTq_N_dP2OxVw0_73w4rDO_TUW9
X-Proofpoint-ORIG-GUID: PtadWKTq_N_dP2OxVw0_73w4rDO_TUW9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.650,FMLib:17.12.28.16
 definitions=2024-05-31_10,2024-05-30_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 mlxscore=0 phishscore=0 mlxlogscore=874 spamscore=0
 clxscore=1015 impostorscore=0 bulkscore=0 suspectscore=0 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2405310103
X-Original-Sender: quic_jjohnson@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=b8ZktriU;       spf=pass
 (google.com: domain of quic_jjohnson@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jjohnson@quicinc.com;
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

On 5/31/2024 12:47 AM, Marco Elver wrote:
> On Thu, 30 May 2024 at 21:39, Jeff Johnson <quic_jjohnson@quicinc.com> wrote:
>>
>> Fix the warning reported by 'make C=1 W=1':
>> WARNING: modpost: missing MODULE_DESCRIPTION() in kernel/kcsan/kcsan_test.o
>>
>> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Jeff, do you have a tree to take this through?
> If not - Paul, could this go through your tree again?

I don't currently have a tree. Kalle is in the process of relocating the
wireless ath tree so that I can push, but that is still work in progress.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9b4a22f-1842-4c37-8248-4f715d70a6c1%40quicinc.com.
