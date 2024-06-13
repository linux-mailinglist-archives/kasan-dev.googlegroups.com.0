Return-Path: <kasan-dev+bncBCM3H26GVIOBBRFFVSZQMGQEEG2APGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5847B9076D3
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:50 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-25443e5e1basf1239140fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293189; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJ+FXQy6NHsPpCazz8zQ1iylF4l10I0w2cIiGSo6QRrHeC4XF8DsIxforMGTx7G2x3
         +Zcksv95+riO8sAFW1E5p5aOkPTLuT9LVFcz2PTavGso9w7yVJlcXQMHlLw80nYFIuac
         P4Wjetangang1vYf9Y5Uf4sQRxDigHfpjvtnplgd8RgIQ5QvqLEgWpgAMRujo57ws83y
         0yxtMwe8O0tuKQWvJEiauz/CcoG//s28fxKRdsWSiQzsDwz7k1jUqBEyweEgAbwoVrdx
         wxgqbbFOvfn5CZT/MUQ830cRYvDjHhCWALavqWkfc6OB2IYU25MXlXe47Fs0eCprIgub
         bgCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5rpfE7+Kt2HuLwjtD8a0tR3rrmnNcCJ1l3LrKNLrKcM=;
        fh=bo5Idw0opT+6UYSJviDA8/vPU6MyuSsDymiPRkISYuA=;
        b=zHL8idJQYigZd6+nnXSfvwJDJUpaiF50itoH5PNSwcaHih/TihRCmfuDZmMXsslGdR
         41/KMCl0aGoW6VIfVg9QQNwnoDMUaa/T65xlT6gJVAYeEdTdyh08b97TV85eG7bxp6B7
         vQRAM3zcMd86LrXgs0Th/3DtPrZsoDx6Z16Sr/B3eEju6k/JW13A+2V1/3wFHmE+cGNb
         ynNxlcTvIZVc4NDu8p9GEPML70pwvWq58J9RZ/AFpzTTNGrfrvkOA/0LI4szRSrg4z4H
         ATRRVcqND4TodPZcCNdFUrU8XNaE17tJZ5/kZmpnV+j3ACcSom9i+MA8/V6jLX5BiZ+7
         TpFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oLMpNDAG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293189; x=1718897989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5rpfE7+Kt2HuLwjtD8a0tR3rrmnNcCJ1l3LrKNLrKcM=;
        b=vkkaud8Z7JAadVHV/PIsSduGOeOuxyB/zQOUx+ggKYyiZoO/M2p4R0Hf+JkIhu7n7b
         sq1IrJKNhM4q5UV3RMm+ua7QO41UyYwiBJRj0xVFEadxR9HTzel0ID88dm1sOoqdc3r+
         1OQeFbXwhr1lujc1g21Z8arjHBc3tzVn+LasdN7y6Ooao8OMqRs9bWFuPyQpRG2VXhtA
         J+tGVK7zsNE3JNs+WJBbvgPyDVJYG0QFQeantMyb/oh2puFMQ9/DtE2hkhEsPW/v6Khx
         SJw5RPdpJKEOdfrE0WLSQXVxtO1xig+wqEyMiRVQbx6F6KyasWa7xVG4aZ089E6LrtSg
         TSow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293189; x=1718897989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5rpfE7+Kt2HuLwjtD8a0tR3rrmnNcCJ1l3LrKNLrKcM=;
        b=F5Ys+U8UFrF3Z58oSN6GMVZzoDFLN7JDKh/gOD4gHC8kZo1+vYeSCTnausUcXljUFV
         xznw1BgMRlIB94Y1PPp2AVruwNImkY4CVM3Vi3B9pX/gSRx7R7V7Vy9i5WRV0bWT4TEy
         5x8Rv9e006jKhYhUT0t/kgQcPnxK97cphSP7Q41sYlT8wmuekgz5h1hL1ek+c3VV6YKG
         jjD9FBkKgG2ub79jV9M0FzK+vvuttDCB4q8fPic++Usg0GIbHy9xR/u0PrA1J25fkxL6
         9MtNSuLja1EqWhT39nrd5rZ2Q8drHZcpwtrF1rSOAuS7OSQiqNro3L2WbcQFZSWBQ+Fa
         DIZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/DdLQ9Dre8ADc073W2hYVTxx9fY1Fi6lfsHGZ/dR9Zi3S+xW9JWGqc7RFqA8T7Tbe/9VR4nImGwMGB1lJ2APN0yFkLfDLfw==
X-Gm-Message-State: AOJu0Yxi4lK1WRsCCOxG5E9RQt1ceGO5tIYf5JHAWvMq9foNTmUAc32r
	EJ19P4OnYBMtQrtf7utymArfnuEj6x7h4r+xevm2d/SYKcwZjq9o
X-Google-Smtp-Source: AGHT+IEcU3G0hFZLmVxjzXbqQGHnuMZh6z+nVQSHw4YlH8aZAiaUO9wBvzn7H4Rpbf7/PbqeDSyCGw==
X-Received: by 2002:a05:6870:40c7:b0:254:8c7a:6c97 with SMTP id 586e51a60fabf-25514d23f24mr6291135fac.30.1718293188910;
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8191:b0:24f:c2cf:444f with SMTP id
 586e51a60fabf-2552b6a41bfls1115327fac.0.-pod-prod-08-us; Thu, 13 Jun 2024
 08:39:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVscMIqT8c7cI2q3opjr0oynLU/Btg9FHignQgu9AqFxNitBUrf1dh0lRou1gtMrmH13Xn1h2tcikwzJF/WubDZ25E9hdunx9mnTQ==
X-Received: by 2002:a05:6358:430c:b0:19c:334c:4ff9 with SMTP id e5c5f4694b2df-19fa9e77d1cmr14309155d.14.1718293187891;
        Thu, 13 Jun 2024 08:39:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293187; cv=none;
        d=google.com; s=arc-20160816;
        b=c3/1oEc/dfCEy2NMu47u0XnkilaFaEn07ysnXTU6/TB25yXGJsOeuh8uyZXWWJRQEp
         ARUqEhBQuNabPe28jSpid2JiznHh1XrsdFK+76jZ1PqUQ+LqgipV4Ow5uDrcpSZ8lZ4k
         tCWLxuDvfGVeqFPKkuz5rFi5O9Ewq5PyGWqurGJevGsKY9WDZmK3Gu9hWyDSJ0B/hRsB
         gQ9fYmRh8FeoZDmOvQW2Dl2v0jXoK5J+MqLOal42UvKDBg+k3nNKn5KVfxeHlb8ZpH1t
         UMyy/QVZp/op3MvD9N9uYfZuMdVrUIBL/i6jnwMxqHM7MB3Fgkfk4JDtVfa/9hUt1ZNn
         qciw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Scz6uta8wJUcmkDwOaiOL8UogdsQpVaK9UJlhoWG7HU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=wT/WgBitf17vhwhviH0HDqFEH8bN7k3ugT6yRdGAot2oEXzEeCmuYEW5GVlIv8HZC1
         CA6exSe5DYYyU7Qv0d3z+MwDYK8zxB3/YBj6N/ioFMzuJl6UdWcHd7b73pPGrmBu1Lp4
         c1BXTZUilNH+h2j3lU2Z3WOAclWpXQs6YpJx1N4oqCARbEL30AhZBXnOo3QW/oSuWqGY
         SyZd/cmDBGJAtLfR3EC5eE5ymF29HcJ+frsqgDCPg2oZ1OVBYTe69lZnpidTOcQTVo8X
         a9sZX8y6meL1PgBVpAcTCzWL2+2GCdm8o0uvr6ymMiCGoGkDl8D5XnbOnzec7sRP3gGF
         sfcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oLMpNDAG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fed4d08039si84980a12.0.2024.06.13.08.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEHJou025389;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt36k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdfK3026738;
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt36d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAZNj008701;
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk0b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:40 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdZ6i53084524
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:37 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1A0222004D;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9AE382004E;
	Thu, 13 Jun 2024 15:39:34 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:34 +0000 (GMT)
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
Subject: [PATCH v4 04/35] kmsan: Increase the maximum store size to 4096
Date: Thu, 13 Jun 2024 17:34:06 +0200
Message-ID: <20240613153924.961511-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Rjws6SciTz59Dde6VDV_aw_xavPEr1pZ
X-Proofpoint-GUID: Xwy5kU6ucR_kMY8jtxtA8RihxWWe-8mA
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=742 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oLMpNDAG;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

The inline assembly block in s390's chsc() stores that much.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cc3907a9c33a..470b0b4afcc4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-5-iii%40linux.ibm.com.
