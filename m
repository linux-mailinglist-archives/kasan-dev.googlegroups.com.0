Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKUHRLBQMGQE2KOBYJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B3EAAEDCCC
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 14:31:43 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4a589edc51asf65000161cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 05:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751286699; cv=pass;
        d=google.com; s=arc-20240605;
        b=R1BEA2aqpkmQi5ASivHnP673bNYeGIbDybVwkhop9dewgrOmWiq6mlikOkOhhkZW41
         dVOSmXZp2+wwmX200OG4f6Ku58Yc2w5gmxZWeqOI0k2ALui2YlZyGd364c6VtbOddspi
         xir6kQ+TY85ASCKbHG48LqO3jT7KtwPwvxHp0OtUM0rVf+yCJK1uFYdUTmGudcadbV5K
         iW5oj9uvCYgBHH34K2L17Rob/6OmvWFlHQN9WygCuljockPUXJmDAPHSxEzfPxQS5AxP
         gl3xbLZh1Tw3Fu/y/oekurzJOlbXfstWSGWBPlyJXk+9xQ6gl34KUkmsWFMeB/5aa3jc
         efYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=k3Tg3FhaiX3V7UqOcBTfO30DvUIIo2Tz1TpHODyJVjo=;
        fh=TqUYMlH0lQ7mA4tPMABQeF7ij5t5FXn7lnb7k5K/+BA=;
        b=RA4OKG1SsMUmefkoNxDs4SeavTTxCdjOjquXWKCUJOa0EslMNysJKizVLgkPTwQKQL
         ktmSofdbqfjMD3K7y0f6xhYw8m3OboWCoUX675x35DRTnRECNyaZpOjqQT5DcUCTXmIR
         gBuwMQ0+hjHIF0GyIkb+O5hGHA3tOhUmopmIPGJs5G31kNUKADS2Ot1Gjj9zEiWc9XEd
         j6Fcla7BpBsgBvCOab8sTLBzJ5ZuSJfcho79GdyfnUb/ejZTSbr3KwFLVlz94UFzhrAh
         J2N8qtUMZBvs/9+DDgWQi1ipU2KcjHMgV/PtQzVZ7cCk3z11uNo5ZaV6a8DfglwR+w5f
         B9wA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LB8Vi2OA;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751286699; x=1751891499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k3Tg3FhaiX3V7UqOcBTfO30DvUIIo2Tz1TpHODyJVjo=;
        b=E2ilteyqCf1h3QM9NitTw/p8yx0GNJ5jwtYGB+eBEo28UvWCY/jBJ4J3xPTuur8JrE
         lFskQVleuCjmczep+if8DD4PJSZBCrnN5DuNjT60/V7RV4BPE6flNUjvXeyIpuznqHLR
         qmLRiqE7KUC512vMPi2fdw5pQoNrBCrtAVEvOO1s1SBpgZcZebeJai7vF9de9IjUONzu
         oR/jwaz/4vaTNqlDeAZrlVYeWfXnKlLxwBnvoXWop9sWEVXSn4HV/h7m+gd0YlO3cBdP
         gHay4C9EFdVPlUyUAPasZdXm017A77RH1gsSx+NCR3yBNNjLZDlik1DzopmJ+XesvV4X
         +joQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751286699; x=1751891499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k3Tg3FhaiX3V7UqOcBTfO30DvUIIo2Tz1TpHODyJVjo=;
        b=eajFXN2UkDkxgXlPAdzyw4/M7ez4RTVHTOS1oZ3lzIU6aV6L0YeOUZ2jtbElGqpN3M
         jq3XJYjtwqToeQlvYsiPPs6YH07mGALhjI3ZVj2/P5lGJ0FLEZUP9Xu3Xp3MhJdnDITn
         UQQClTQOL8Usv8ox7L0xRmiCeukhaocGt7m0KNHboiLv5FPzAHiN900xoPJgDS84/ArN
         3YDoJSb7FU8tsOgyX+W30Sg7aokwGW6yMQ71UM3hKC8obg7s6IpdgbdjgxuS2yXerq5e
         UP5/2zAsHXmI5dA0b8W/UYXuZeWtzKDQr0/ZDLq2YqO2/ZWYBEqq5WtETaDgqhDc10l5
         /trw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcRa+CaIAIpXru6O6jWv7xVQKF7TmsTPKr8GR2fWuENAQ0LS7Up6m88YxsejLC+fH4tplobA==@lfdr.de
X-Gm-Message-State: AOJu0YwYijUeRVkNpFOIgBIzc1JZLdreo3QsqL2KIbeIm9gjP3LpSRxO
	HDEceR2aE4FMTXxrslu0kabdoK4NiCoNtajNwTxVkOpqMd8oDEo/zvM+
X-Google-Smtp-Source: AGHT+IEFWjkoAVHQboK8u6J8WxbnFYlfvFfpxdLHxgITiLjQN6q1HZmFRLtBsdYqlcSGyZCjo92Vlg==
X-Received: by 2002:ac8:574a:0:b0:494:7e69:137f with SMTP id d75a77b69052e-4a7fcaf5a34mr173907361cf.42.1751286698896;
        Mon, 30 Jun 2025 05:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc/lXshJRXaELzWAUIEGpj7QDieESOpfEZhOGpoQyVbDg==
Received: by 2002:a05:622a:8e:b0:49d:9658:125 with SMTP id d75a77b69052e-4a7f32157e3ls69200151cf.1.-pod-prod-09-us;
 Mon, 30 Jun 2025 05:31:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRsB3f+iTpVayZyhv47CAPjkUrKFncT5CuTEv4XYzpplAnNlkmjgJwTnETzdvdDiNKNEd3mSEW6hw=@googlegroups.com
X-Received: by 2002:a05:620a:1713:b0:7d2:284f:e471 with SMTP id af79cd13be357-7d44394fd4dmr1814095785a.33.1751286697206;
        Mon, 30 Jun 2025 05:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751286697; cv=none;
        d=google.com; s=arc-20240605;
        b=P9GbCxib0tFRtHtcSjR1/61L8SKjYTr5t7v8LoR0Pujpikk1xailpEM/IlBXnmJcIE
         g8AmGnre7XHWQVFQKSwNWjbSBruNJiVGRyEqaEjPm8PSnI/tY/2uoSo0mcu2ypkKH041
         Ivg6LMRtk57OoS1AA9mQ/07vqTds+nRsK7WuA5C+BN9MqlogSipu2ohlfHy/XKZtwbYo
         4XSleR45wHiFRjPQ6i/g9F1MgCZgujiibRagkylnHYJTApMeNXeqpIizb831dsNupxtM
         JwgrYhffteD566dC3eLMXjuMZrsPHykdm/MDMVkDcCI4btzkolK4Zshy7MAZYkAXjgqs
         4sZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4/4W5HOVsxTPqI9wS6wr9RV849JR3+7l1M8P6DKnK7E=;
        fh=FiYfylAQtzs9sTyBDc5ePJArEFksfHCIqGzd8h56vvE=;
        b=T0mNfd2CikvrDze8PXOU07VtP+n3Vj6d3w8OVnSuR7WGdEQtx7rw5tjs9skD3nctxx
         FI78bRC3JQk2HZQ+afX5ZwIpDaFEYgWqMP14rTsa5CrI4jUBZQ8LLZQxeaB4dwdV8led
         H+4paYTVQJaraR5n7FiedhbvZKHy4sfdHfkFTbZgoKwQAWSN+gFjyFb2W52b3fJhG89s
         7OPZkXppZK/LV9ym32RxBjAk+d+x0kA7xQ+a+6ejNvcN2x1AtSXAUd7JrnEpU0CyV6Bx
         WiBleXGhTYkF/7sLZwCpdrebUgu2CgWSWBuleTQwXS9/KJkfi3Wcqi/whpljqkj/DaWn
         M1mA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LB8Vi2OA;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d4431b902esi40844485a.5.2025.06.30.05.31.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jun 2025 05:31:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 55U6gHw4011086;
	Mon, 30 Jun 2025 12:31:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j82fh257-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 12:31:09 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 55UCTi7R021773;
	Mon, 30 Jun 2025 12:31:09 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 47j82fh254-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 12:31:08 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 55U9adWG021906;
	Mon, 30 Jun 2025 12:31:08 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 47juqpdspx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 30 Jun 2025 12:31:07 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 55UCV30356820034
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 30 Jun 2025 12:31:03 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9FB8B20043;
	Mon, 30 Jun 2025 12:31:03 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 35F6B2004B;
	Mon, 30 Jun 2025 12:31:02 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 30 Jun 2025 12:31:02 +0000 (GMT)
Date: Mon, 30 Jun 2025 14:31:00 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
        dvyukov@google.com, vincenzo.frascino@arm.com, linux@armlinux.org.uk,
        catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org,
        kernel@xen0n.name, maddy@linux.ibm.com, mpe@ellerman.id.au,
        npiggin@gmail.com, christophe.leroy@csgroup.eu,
        paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
        alex@ghiti.fr, hca@linux.ibm.com, gor@linux.ibm.com,
        borntraeger@linux.ibm.com, svens@linux.ibm.com, richard@nod.at,
        anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
        dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
        tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
        hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
        akpm@linux-foundation.org, nathan@kernel.org,
        nick.desaulniers+lkml@gmail.com, morbo@google.com,
        justinstitt@google.com, arnd@arndb.de, rppt@kernel.org,
        geert@linux-m68k.org, mcgrof@kernel.org, guoweikang.kernel@gmail.com,
        tiwei.btw@antgroup.com, kevin.brodsky@arm.com, benjamin.berg@intel.com,
        kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
        linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
        linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
        linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
        linux-mm@kvack.org, llvm@lists.linux.dev
Subject: Re: [PATCH v2 01/11] kasan: unify static kasan_flag_enabled across
 modes
Message-ID: <aGKDhPBgDv2JjJZr@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
 <20250626153147.145312-2-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250626153147.145312-2-snovitoll@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: R7Lk-5oMpjro9s1CXJZKtYujyDGXFMxp
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNjMwMDEwMCBTYWx0ZWRfX2xhLgGojvA6t r8g7/ecZ+357bnq+V4oK+PEwZaj+zHbXyN+Ru1n3DrFdaSLAos0buS5jL9C1tta7atkJYiZIQaF 9sZWyxHNaJUrQqIMbo0QDjD1aBJf17TqXpAKHau1WcUR0r9MB3HXL9faXzF4lvrkQdsuGxUK17d
 z3tORR8HbmqzluxydjcIqwSK3SZaH8E4vH7dXCceoC74KSHRAZLLwuOQaLM4i+tX7f/u/Ckvpml 5uKodiLIM+IjigsvvYu04D4oduCbahyVPqy6GNw4VE+yf6xOzYsj1s/uUrTjsgyO/jp3mfjTdFr /qtf53aSQ4op7pY9TqPllefkk/R6721w5VzJc11hrTLtAQeHUx9tUD6J7VDv5TGalxp7Ob0FALy
 f7LBwFKXJq+utLCJBkCcPsmtnhAftjy9J/oYjEBrOgpvCYmkO++L/gKuaTAOTK1/jfEyvMMe
X-Authority-Analysis: v=2.4 cv=LpeSymdc c=1 sm=1 tr=0 ts=6862838d cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=kj9zAlcOel0A:10 a=6IFa9wvqVegA:10 a=mW8dxBt0ZUAMIGVGd2EA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: UVJc73yvgF4Y4S9SoMFvV1Dqh0my0GoM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.7,FMLib:17.12.80.40
 definitions=2025-06-30_03,2025-06-27_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 spamscore=0 bulkscore=0 lowpriorityscore=0 adultscore=0 clxscore=1011
 impostorscore=0 mlxscore=0 mlxlogscore=999 phishscore=0 suspectscore=0
 malwarescore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505280000
 definitions=main-2506300100
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LB8Vi2OA;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Jun 26, 2025 at 08:31:37PM +0500, Sabyrzhan Tasbolatov wrote:

Hi Sabyrzhan,

> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e..32c432df24a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -36,6 +36,17 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> +/*
> + * Initialize Generic KASAN and enable runtime checks.
> + * This should be called from arch kasan_init() once shadow memory is ready.
> + */
> +void __init kasan_init_generic(void)
> +{
> +	static_branch_enable(&kasan_flag_enabled);

s390 crashes at this line, when the whole series is applied.

FWIW, it looks like kasan is called while its state is not yet finalized.
E.g. whether calling __asan_report_store4_noabort() before kasan_init_generic()
is expected?

 32e0a54:       c0 e5 fe a9 70 56       brasl   %r14,80eb00 <__asan_report_store4_noabort>
 32e0a5a:       c4 28 ff cb bb a3       lgrl    %r2,2c581a0 <_GLOBAL_OFFSET_TABLE_+0x70c0>
        sort_extable(__start_amode31_ex_table, __stop_amode31_ex_table);        
 32e0a60:       a5 ac 00 1c             llihh   %r10,28                         
        init_task.kasan_depth = 0;                                              
 32e0a64:       e3 40 2b c8 01 71       lay     %r4,7112(%r2)                   
 32e0a6a:       e5 4c 40 00 00 00       mvhi    0(%r4),0                        
        kasan_init_generic();                                                   
 32e0a70:       c0 e5 00 01 e7 3c       brasl   %r14,331d8e8 <kasan_init_generic>

> +	pr_info("KernelAddressSanitizer initialized (generic)\n");
> +}

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGKDhPBgDv2JjJZr%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
