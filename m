Return-Path: <kasan-dev+bncBCYL7PHBVABBBMPBY3EAMGQEVI3KI6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF2A3C45A48
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 10:30:27 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-8b2657cfcdasf137761985a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 01:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762767026; cv=pass;
        d=google.com; s=arc-20240605;
        b=URda0iRtx1BGVXraEbIjLdbY+jkIn+OKV7OH0S+NuZsfGRlS4PgEjqrf0T0QClod2T
         jsumwxAC/dCwEdgoLvV1M/E6F3vvGt6uATdXkTpNcDmQffyHeNJLY3qMaeugR+7RNSjl
         h9jS69BU05nUnAIgHRW17iteJ82soIvikVwcM8ysfbA4BwSgZIQnLQUGdKyNWOlp0K3L
         MTJ2OAus1N4wQ3JL/OC/nGigjjAl7Mdod/Qn8MyT1HkGyxxYbo5lpDgMOR6B7tQ2XiQP
         7wDqzkM4GMsiXan0aBgs0tYz1L3940orL3RATE0ua+pvlOFL8b8pVEWgdZazAya63+Oh
         dWhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZosjKNHNLG2S/eLOeF/pYKCDTyYaJG2cuc0opOQQ2sk=;
        fh=I2We/FdwEA9MRYW3s5tqMqFv95yDIl3/adKD5Mvfbqk=;
        b=jXdMKRy8aiYWUMO4IH+MsGXcaNZDL10gLIRh77WC4gUY9enQ8bQodQVioFofEh6VKT
         gWYsEqk3Hhe1ja2K+uMeKyt9A07nTSLY/kket5vWf+hobznWD+MBTZsU13koQmnvOq8g
         z8mqPjKtW7xxSqjh4wtmiCjE52AsitECY9rzpZrddNkwiXeqNIqneAKuyTIS09PH/fly
         sVOwyPvXXNndpd7L+tuIde+VWiU+Mi4a3zQ5+p9mI7ys7TvlybJgfCHVbELrDl3dxjOZ
         1oVMedTZ/UjYWPv0Z5gVMWqgEZpJXML1A/eGF8WJVRO3JWZRBEo0eZKFz3ISGxwdJiP7
         SDZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PFC8YN+0;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762767026; x=1763371826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZosjKNHNLG2S/eLOeF/pYKCDTyYaJG2cuc0opOQQ2sk=;
        b=dFXkiEse8iJwKS7fM4FQsoA6twV+iYyMKKjpmm4L1KMlGO0vUchFSsZ5MXKTA9T7KM
         sOkUz103Op85BqcQjzu3YLFEiiiTfUwJlejQIeEuQkn27UMEHbmeLj9HN2pTUswdXzRc
         H8kBqmTgDVnl75hTHV5hAnWzpfgdiclAR6biCSSSuL+Ma3WMqMCFB8taqlk7GapH2mHI
         KjdVnT5G8VRhjMMM55kZzLspYOeYU+4R/0LxmJDeSMRnuiMevb37eIZHNDr6tg0w0sQN
         tyGxM9UKFrA1fEcDPB5LVow/+MeZfWf4iK8tUr/soNFbjibOJNh8iDkSX48bcZDzJ+7e
         NCUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762767026; x=1763371826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZosjKNHNLG2S/eLOeF/pYKCDTyYaJG2cuc0opOQQ2sk=;
        b=JiAZEdah3PJ4jwm2fLYDu77P9Y7stOAOHlPTHUP/lNscvHDW/pRJv91ytl7y8GZLng
         1q/eDk2VXHY6NVI+KjU7q8zzuNrqoNA94LUr8D/dMRrGeJfMGZEentYRLTzpSI8iO6/z
         IWrwb8dNZG+F/ahvRF+zDVJ+jOiUwrFVQGwsSyExkZmPzejXgLqom1bLYxCUzSWaLjE0
         vd0JJjvP1rfg64a8ZqnCuD7EJ/6IGIgiQsXUedA8oKYpn/rPjlFob1SskOdMRHoPChRp
         xxrrW58nm22EtcF1CtJdiyDizNUM7rVrW4dFNytQtYOGe/4KZkw8bvDNguzFQWRgDJi+
         S9ZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1eJfnVKdKdigkvrYfwefh7D6OCqaZeJFkPOOwhLWGzaXGYFLhVlzbZ2Drpa0gw3smuhpM9Q==@lfdr.de
X-Gm-Message-State: AOJu0YzcUwjz4NND1UEWKiwps8jYp18ItGpzcvFQNhCP2Ze/TOb0rETh
	VMLcbazqtdcG4WOHTYHVKrTJWzsDK879exWzjVs/aqlAc66kLOJQI11G
X-Google-Smtp-Source: AGHT+IHu/MzrR8DH4jQjs/tHS0ijOXlzMC/2O/nqytrwKDDOQ1picDl2yZZ2G3+S7jBmxMN5J7QRSQ==
X-Received: by 2002:a05:622a:4f:b0:4e8:b56a:992e with SMTP id d75a77b69052e-4eda4fad027mr80877671cf.59.1762767026132;
        Mon, 10 Nov 2025 01:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+abP1jGsaEQz6Olgn19unOo/bmZKWsxhutWc3eK/Riaxw=="
Received: by 2002:ad4:5749:0:b0:783:6e2:3e57 with SMTP id 6a1803df08f44-88082dee851ls63327956d6.0.-pod-prod-08-us;
 Mon, 10 Nov 2025 01:30:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVYvjX37UjOepIvyOCDy0G4mludNAGSQ98xg7tlzIISnD5wc4725ielLMRtPCZg2JgqlvaP3vfjkLg=@googlegroups.com
X-Received: by 2002:a05:6122:220f:b0:557:c50d:6a14 with SMTP id 71dfb90a1353d-559b32a747bmr2213078e0c.9.1762767025298;
        Mon, 10 Nov 2025 01:30:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762767025; cv=none;
        d=google.com; s=arc-20240605;
        b=dBM1XiH9mAlIkfE2eBNT0R5zjI6kkExSnKGaS878Fzv/UR/TUCq6dStoHTBss1SmjI
         dUd3aVoMWATIib5f7E06PHcLWiWZ0o5R7QTe58PBYa89qn+aQRTufhF+a9iLV6uT/WxH
         yTFVBnOQIBA6Vq/CwR6Wog/UAsAOncziVCUq/wcjtTUuPDw/FU6Y3zIghEvCnubY6JkJ
         D8df73DXV6JmH2x0I41GsHw18RNaTPB+AM4roD3Er+J70uIH1gH0cMnCJ1TuDkpAt28w
         0f4wbz/gk9UqTWXplH9iZasQwzQMkEU0s/KNdJx4vPinWdSSKUHm0Xuc0IWnAqYcTi97
         HCLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VaM3ltU3Y+jrUrL+P4EgR92tGTJUnGs24Sssjdacj7E=;
        fh=zVnkhLj6EvdBo1mo6IsDDGw6rA1hOrBNb+3ssnQ2VJE=;
        b=GKCUvAXvfhVT0VMYfMvjJ5iLn9VpV2MR3oSEaSbGnZs+Bl4MiX+omoh0P85Dtgrdzx
         Lo8zcMCnU+vWVCTbtETRAVMJO74amAqzyllgRR0U641LQq4SXQNZ8TuZP+SqXAwZRk/m
         GZy3MW2PUGTAupr5MRCwQOzcle10NLSzbhK2XOpHUtEboCAGuL9yHPrkhpNxUAq8j4Os
         5Fh1G+ohMSVJi18OKMcOVgZjH4ULwLilGJ+Clgfk5iBVNVBbnrNO6RF2igWvsIIdmw9X
         Wk8VKnpAZc58F1uE4vz4Iu8aJE3x9fXg5M/1h8XUmTfKu75pZWH0Q1Vr3LNtjflIl3P9
         AV/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PFC8YN+0;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5599aca45cbsi334755e0c.3.2025.11.10.01.30.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Nov 2025 01:30:25 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5AA87ZWP028610;
	Mon, 10 Nov 2025 09:30:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4aa3m7wqbs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 10 Nov 2025 09:30:24 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5AA9RiIv023550;
	Mon, 10 Nov 2025 09:30:24 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4aa3m7wqbm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 10 Nov 2025 09:30:24 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5AA98nS1014779;
	Mon, 10 Nov 2025 09:30:23 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4aahpjvuq7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 10 Nov 2025 09:30:23 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5AA9UJ0S50725350
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Nov 2025 09:30:19 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6D2AC20049;
	Mon, 10 Nov 2025 09:30:19 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 828DA20040;
	Mon, 10 Nov 2025 09:30:18 +0000 (GMT)
Received: from osiris (unknown [9.87.148.55])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 10 Nov 2025 09:30:18 +0000 (GMT)
Date: Mon, 10 Nov 2025 10:30:17 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: Re: [PATCH v2] s390/fpu: Fix false-positive kmsan report in fpu_vstl
 function
Message-ID: <20251110093017.15528A26-hca@linux.ibm.com>
References: <20251107155914.1407772-3-aleksei.nikiforov@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251107155914.1407772-3-aleksei.nikiforov@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=MtZfKmae c=1 sm=1 tr=0 ts=6911b0b0 cx=c_pps
 a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17
 a=kj9zAlcOel0A:10 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=bXxCFtWIKm37yWNRadsA:9 a=CjuIK1q_8ugA:10
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-GUID: a0sNEDIK0Gr--rLC5ZSC2Y2pLdE44ef_
X-Proofpoint-ORIG-GUID: YUzRASJ9uQFIpYFhIfz1zgYQR8wytDKp
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTA4MDA3OSBTYWx0ZWRfXxogod00QcIgV
 uxzUe+g7lz3lHaOCnwEIxcVHN5gGOWoXZ4HO3AaCLusqFGOjBDLJPqo/nj5V2QcMXLdbuQ3yzeC
 yGjUrcMs6PFrGTOMLe+ryZ9gwyXpsEcTxMbyz3n0IVCUZDaK0PzPSuflo3MqHl/AF47x+HjBiZu
 mArNAPbyOFpxPmK6t3OMmQZMRf8yBdfaMub4j/NXDOoGDu+TIFDjFd0UcUIBO1SbIGQuLR4ziBm
 QKZoUS4BGk8Psx/eGR9wV16pq2pi96nq6FAALcmU+W/zFnBc4fK1mW5WZRQfHauKspnGi5bFOwv
 5+1XmMwbTAeR1j2GWHDjDQCIJ06lgkAv+BSao8HI5bO7cvGZVJ7kRqKqyEKbJyu0lyC8wjD+V/l
 2KO0TYZNxD90EkhEXnM3isnZIJT3vA==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-10_03,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 malwarescore=0 adultscore=0 priorityscore=1501 bulkscore=0 impostorscore=0
 suspectscore=0 lowpriorityscore=0 clxscore=1015 phishscore=0 spamscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510240000 definitions=main-2511080079
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PFC8YN+0;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Fri, Nov 07, 2025 at 04:59:16PM +0100, Aleksei Nikiforov wrote:
> A false-positive kmsan report is detected when running ping command.
> 
> An inline assembly instruction 'vstl' can write varied amount of bytes
> depending on value of 'index' argument. If 'index' > 0, 'vstl' writes
> at least 2 bytes.
> 
> clang generates kmsan write helper call depending on inline assembly
> constraints. Constraints are evaluated compile-time, but value of
> 'index' argument is known only at runtime.
> 
> clang currently generates call to __msan_instrument_asm_store with 1 byte
> as size. Manually call kmsan function to indicate correct amount of bytes
> written and fix false-positive report.
...
> Fixes: dcd3e1de9d17 ("s390/checksum: provide csum_partial_copy_nocheck()")
> Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
> ---
>  arch/s390/include/asm/fpu-insn.h | 3 +++
>  1 file changed, 3 insertions(+)

Applied, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110093017.15528A26-hca%40linux.ibm.com.
