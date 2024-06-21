Return-Path: <kasan-dev+bncBCM3H26GVIOBBQER2OZQMGQE5SHNVEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E444911742
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:42 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-705bf7653dcsf1292682b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929600; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8ioh4TtfOpe6+tsT4WWI9AlTpNSM/o2snZoxabGrYX+cjAnikjMJ4Wuae8PPwSoM/
         7R3VCnJtvvz6n1yC3leZV+tILahmogwwrGDw6c6qA8r7k8sMeV03T4czezIwfLU4C7RR
         5ikqcBKL+e/N5436WrvkFZnjV6o7mia20yPSO7WcZZCfg1mYZNWMw3OTxW1SD61j8WL7
         LQOcUbtuXAE1a1YipkKrwnbQnazQGYvM+EhfBXAwxxMvOalIL3X306aiJWS6T+Ird0Vq
         UEp+fOnXRYK184mcYMqBm1PusGPvbMGO0PLFsocmY+uJ4opYTcCDFAjSP5ZO8cLhAhd0
         15nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dEYra+4x4FcMYvPTi86i9l/dmtnyxXpk4Mt4rU3fomM=;
        fh=EPuoT+UPtbOIF9A3jPF6k9i7wBfWK0LLdT+OW/icRHU=;
        b=axlkDvenE2qiOHp7lvnvLdl+ucSDi8oMNUXn5p2Ju+baISOgFldH3xyVriejF2z14P
         Dv8osBdQ9Ds4RtJ7H3+1pxt3HS8V14uutUbjbMWL3eXF8jygSC1n4UiZSODBXizSIV4j
         iRze8I9EXKaecQf8ZasAOIXSAZICOeVc9tuUvcSrWkNiHBWcMWh1bSwUg5JZW2aFIojt
         SGN2muksh1vGVLy6kZ8LaKhgWxVYJ46k5T91cJfaZ08yqap8WA3xC5GUf/9bqRlbyxGl
         kO/TMcEdRVduJelGo+wI9NeVcTSdUTtJ01cw2OvXXEbRvb9y+Hq95+/5HVLdCNsilOw7
         aXiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Dvg4EDMn;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929600; x=1719534400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dEYra+4x4FcMYvPTi86i9l/dmtnyxXpk4Mt4rU3fomM=;
        b=MpGOz1wtecjaKIvp1z/qBJXNxIswA9+kVTnU66bwvK9TRuf7N5G2BRqQHRHsFHJCVf
         xkCmjNuYLCDwvqv2y5bbdFTiIHifhO1opCykq9HhHZocuKegux0cYeA5KcwOvHeCz+BJ
         TYGPnkKoXIt5ACJOCm0VlfV3bM7TiYPdKcHvBmjSzaM97RpeELr62cEfEcXrpRo88dCE
         poFaVXsXi4AjXO0VZKZghSOHwNVR75vL1Shy8ZqLGByd2x1IgQ5iMi24HVH95z7kP8ua
         jrtbqTeXkNozZRV+PaCeRYUdb0egfFdett2+6IFmrZQGkIVoVh2GRUUgeQw4diOe2YDv
         dbmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929600; x=1719534400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dEYra+4x4FcMYvPTi86i9l/dmtnyxXpk4Mt4rU3fomM=;
        b=P0Bz2Z6kG/4dL8smbMM4qdFhFFa2sVzu6Z0827la5wfqXCMxmwlW0iHyrK060nHs5f
         q78wndr00WE7Mt6McBziY/Z0HjlP22O5zxQJOO7g9zEOhAnYJ5sq6wXFSh45XrVAp4Q0
         gqQdmyR3MYH+mMcd+OAIilngNZxungDmIPdQ2JyH+FdajO77lW6dXQ5Zq2xUp1A2GXsH
         EbrwLWFJIayHXydV1FboCgRwZdr7olj54mVtMMq4D7dZBxm3usFK5p6SaNo8xuB9N6gq
         FZOhyxoTZeogEbkvMr8IChX5rNX7z9OKncuD05hgZVsfe66K6R+mCTFEwisFCXo/m7ph
         2ApQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNEYmDHPTt3l0jCLE69pCBTQmy7u7l4H339OWtvG4qU4J2T3cqC/aOTrTesDxOFVVs76GGrCg/QZmF4LDLFAfjiLzEHPVaPg==
X-Gm-Message-State: AOJu0Yyis/CXYKerNkL/EenMIKUbRTSdW0Lhl/uNbIwcTGAfG5gkX4ny
	txjZmajMNrueA26GkfKw9C+w8EZXrFKNBNqq3Hu7RDPkO96V/Q0s
X-Google-Smtp-Source: AGHT+IGw0c0eDtTdqT2Qy5oS5GMTkGgTzUTVerSJpWD0bUKUgkXGuF6U63bMM8zqAO8ThDXv+s2uBg==
X-Received: by 2002:a05:6a20:f27:b0:1a7:a6f3:1827 with SMTP id adf61e73a8af0-1bcbb5d4d05mr6427273637.46.1718929600420;
        Thu, 20 Jun 2024 17:26:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:224d:b0:2bd:f439:c1da with SMTP id
 98e67ed59e1d1-2c7dfed94a6ls896483a91.1.-pod-prod-03-us; Thu, 20 Jun 2024
 17:26:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjQivNOUi8R/OwtN9lJyOMLurKsney5AajT17D1wdvuOPz4+Fm7tG0H5T0+4v4YQIQGjbd5W/pNg7gnp9KJAOVh4uEbnFinzayDg==
X-Received: by 2002:a17:90a:4a17:b0:2c8:893:2c1b with SMTP id 98e67ed59e1d1-2c808932c47mr2094304a91.21.1718929599171;
        Thu, 20 Jun 2024 17:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929599; cv=none;
        d=google.com; s=arc-20160816;
        b=tf7ctYrG48h89buvXdDE3iLYLIRhlvl/bpGjKkwpj1YtLDXeEc0Ms3jGDjuquuhZ7s
         F37KWIEK876/jN7GAO24ETFbCAJKKaaKPGUis9JYTefbtbXlDNppcYyekzAuR257b4zI
         onleo3dxngKlNruLBE8cPJCD/6lboPqrfNHswQHGDYKSlsMbrhjV8C9ix/RxiZf++BWF
         /50W97bMc9zKvv9k/IYtehfRILlfQYDOlRCfuLWb0FNSaiv9lQtAqceZSkJBIAng0MF3
         sxg13bwdkz/7jLR1y8eJHOBmzYzczySvGNp93+i0nT3erWMdqIZ0BJh/qAI1kWakRMZr
         PylQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B2wiMcD3tdJRzJi1KnXmn1aGmTaVwcFVLNTdCb0XDUM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=OM7q3Q6ZR9rcmecVSGb58w+Z8QUUnerymDT0EmDrY0Tbz/u2fEpKRbugp4tRXIFI9l
         tTg3ETgjAaR2vYL4HOJineNMJTrFJbVJsk4UH6Z23aplo2tdMI6kv23z9znjieFzqB7I
         ywjIALWt9rb2vA1gDyz8bM6JSAo20q9XWsOj2MbmnNMlJpRQ1fAsLq/P8yZ9q+BXpB/D
         NwAxriGwmiA6YbCyaiykEjNnJoE1FMABbk8iZl1AGY+hjyUtRGiJoo/MAAmy6GuAqLT4
         iM2dzpLnLEWuPczGU2hmMbCD9iZOnkrvYiJvrDnrLNSyuv/c+lPprXe37bUKM9dvCUhb
         HgnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Dvg4EDMn;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c80a9809fbsi103526a91.1.2024.06.20.17.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNugHF003832;
	Fri, 21 Jun 2024 00:26:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07sk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QXEc016863;
	Fri, 21 Jun 2024 00:26:33 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07sc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLdxws007658;
	Fri, 21 Jun 2024 00:26:32 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamnb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QQxH34406974
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:28 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1EE3420043;
	Fri, 21 Jun 2024 00:26:26 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EFD2B2004D;
	Fri, 21 Jun 2024 00:26:24 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:24 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH v6 05/39] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 02:24:39 +0200
Message-ID: <20240621002616.40684-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 9QFAGDh13kKfs4BqxB3pEmUaOBJWzMM3
X-Proofpoint-ORIG-GUID: ACz1EGDXb2ZVjiX1siUU-04QV_ZgtuuL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 impostorscore=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxlogscore=952 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Dvg4EDMn;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-6-iii%40linux.ibm.com.
