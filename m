Return-Path: <kasan-dev+bncBCM3H26GVIOBBTWW2SVAMGQEI762GXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 95F317ED20D
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:24 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-5c1c48d7226sf113247a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080463; cv=pass;
        d=google.com; s=arc-20160816;
        b=YBHBtWEIvzaSRAk+utWacch5cTR2EP6h8Zo7Qq/6KQq2ZWJFP5Oc4i7SI7fkjotDQD
         KNtFPEKFvixtIUoUU17Fomo34CMfhqp4lgBLHFL25HDQfoO5PbsGK2+b0jaetVbStnp1
         //2WNtQSJFG3Dut/0Zi50rci591IoFJDN3hCgWZvt8grDqacdc0B0rcdwcqpahx7bEsa
         B4IinZnTJV/PSQtbWhuCZWrL2DR8U6dYc9xtNlM80zk0G27U/H9BfFx1Ng9FxHsQeDp7
         aArlnDk8m/+2Ty3+MhaFPQp9doSLTtm4Z7qjhbdaC9sfD5G2o9fjBEvHj9Evpz4E2gm+
         fbRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WQOP37xZRfcn3hNi3HA5HWZKcoe0tSemR77bUaaYXCM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=kI32R6p9cBM84xHAqOlSl3sx5/RtCWAcA1KjQUZ77Bzux0eRiQGuYMgwsHL7KY9aQ5
         /CzsQupd6wZjXaBKZsuqXgKnTxtD520GjxRhik2YBM7YnqguJiSQGtGoezfq03mefvjs
         LZ4UeMBVUVDffPN7EblUzsuRqQ8UnUL8a56M/Qlzr5Awuz3k6ciuGYY+JtDgnRzhNNcw
         SLK3BEUdO+Dbf3Fj/LPYdno3sgeCzCZgXKm1vJjZvGsWrNk3qzQunbm9FBMoNG7qcSQO
         k1CA9wNUUZHxAhjhN1VZz7y9R+VM0aRvPn8mmY8GMcKVx6APS2gShzPMhKx1jSDHni8L
         D5vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lLa75Rz7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080463; x=1700685263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WQOP37xZRfcn3hNi3HA5HWZKcoe0tSemR77bUaaYXCM=;
        b=LeD4lHA8gq78yNQPL6htca1ZcgdV60lQN7lGQRTnNTqnFt00A5B3dqmy1gv0sSCHLY
         WNXHd+l1An+rr/SESdsFgXOzvxl+ofGlGjJhjF+PWrRO3KXl1sqyU3QsQu6NA2v2MJcu
         i6r5YBvHMq0665zVJy4f9vx7+Q/CJy2MxdjGmja+mdX74hp+ylOEH27zL1326y6wi3MD
         efUWD81mKw12C3FsfNZ+BCzw1tlKoOuXXUKrnyZUU3u+DlyIacYii2AuKqwChvIJ5HRM
         mEbCXmKtqPK72UvQKf3iXGuaeUvgHEZejhokUxTXCFh2A6dMp+A7EEqTrhucNE4xxNor
         QokA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080463; x=1700685263;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WQOP37xZRfcn3hNi3HA5HWZKcoe0tSemR77bUaaYXCM=;
        b=AF/9/zoCGODOUAfpqtHcl070JrDiLrAh9UlP9903Fxbm3KoUrQxuchoylncA5SebxV
         8AQCeUden+HL+OdDWctbHw2++dYm+4acFJHlARc2FURSinS4n6G96sfST/U5SLx4sk9e
         GWuw5oHQQWGiN83uOoYBPsuefa07U49NBk0dzTwzHMDhiC8YDNdRVl3680yoPuR0kkp3
         tsvNIXu698eGM1mzMT1Eg70ch1Vg1qOaMj7MY/Sp9bk3o35XC3rFCZ/b04j3zYqyiYOA
         32mL1RaeG9qyZDDoPnpOGy2EtzeS/U5xAmAUkjYiyTqOJZWdN0QZJ9zY3mKIBCxP/OzI
         YQKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyMfYuxfzRSwOXCPYCCnHU7dhHQBxBm2ZPHRQQRprtUVKqXHTgq
	IWbogXcmoSVARhwpHGGuTeU=
X-Google-Smtp-Source: AGHT+IHglOtDHE2jEwaeOWw8MLg1VJGbINQstmMHwz37Ik90G/FT11HYvFSIwQtUHWt6i59NheR0RQ==
X-Received: by 2002:a17:90b:1bc3:b0:27d:5562:7e0b with SMTP id oa3-20020a17090b1bc300b0027d55627e0bmr14300763pjb.7.1700080462961;
        Wed, 15 Nov 2023 12:34:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:270e:b0:274:60b6:c873 with SMTP id
 px14-20020a17090b270e00b0027460b6c873ls138330pjb.1.-pod-prod-03-us; Wed, 15
 Nov 2023 12:34:22 -0800 (PST)
X-Received: by 2002:a17:90b:3886:b0:27f:fa7a:a7b with SMTP id mu6-20020a17090b388600b0027ffa7a0a7bmr16854515pjb.33.1700080461861;
        Wed, 15 Nov 2023 12:34:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080461; cv=none;
        d=google.com; s=arc-20160816;
        b=gZofaEvtB8Bi9sJabRtqpD3UlYZFJVDXPRGJSGTenaSyS6KQa2636j4LoYr6f+wB/4
         Yke3eNyxDtT28Hx3uCQbq/PCW51H45csH23XjaaOuwxpVUM8IvoY5TPBgkvTuAb5ENl9
         U1WQmcjq4pXATFLqkX/hLGURjsMDVkVODGtaZWWKy95IFPHK8s5ypGKFU4QGtlqZoy9g
         +BQPuyuIWzZdhGdQwEissUWrIJ3uMAu722wyjxMogLeOUhjU06iGolUGXmP0tOuj3jkQ
         2h1dtv6Cu0I9ORLjsOtVvFoino+L0MXEoppq/RS+89JoGZKBbpHKaIV60nPMxca/XqB2
         WN5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ALe+orXRFp48K8J9UFekuIwy9fPV1PAP+S2ziEgYlpk=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=zzmAQLKv8KMxoUmwJnvRVOPw+J+E2neCxPaCPjjRDo11mR6bV58azi2a5kH+/rmQR7
         Y4g1YsFoENvF1wpDy3YjGZAvMcKhOQMxcW9A56PLg/7tAZ+QrA7R+zTpaslPRGuE1I8n
         j+X52yDUbLhufpsSn8cJE+eV4gUbFgggJRaSp47Gfr4j4nsICPTBy26ttgYuHzVNskOu
         ylK9T9Nv9AzPdLV740yUs1ZPeWkELXkpA6DaXUyT5rPWWSnqGwhYFZ87314eKXyDF0sz
         oLYLAqBzS6hJ04H2psak8vT4dYiCifM98jEf4JsokAFP2Wbf/inqEN0HRMZdeGRZI8UO
         KXkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lLa75Rz7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id cl1-20020a17090af68100b0027ddcc6164esi155306pjb.0.2023.11.15.12.34.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:21 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKQk3k031373;
	Wed, 15 Nov 2023 20:34:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8ffh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:17 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKQrZH032053;
	Wed, 15 Nov 2023 20:34:16 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8fer-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:16 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIvbd015477;
	Wed, 15 Nov 2023 20:34:14 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnj0hr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:14 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYBkA20447746
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:11 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8A2772004D;
	Wed, 15 Nov 2023 20:34:11 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3EC0620040;
	Wed, 15 Nov 2023 20:34:10 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:10 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 02/32] kmsan: Make the tests compatible with kmsan.panic=1
Date: Wed, 15 Nov 2023 21:30:34 +0100
Message-ID: <20231115203401.2495875-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: o7Re1uLxrmfZ98PzFum0KnGUcltBzKIe
X-Proofpoint-GUID: hXQ9t0DNpe_h30_zYtji1RDR8Sah29gx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 phishscore=0 adultscore=0 clxscore=1015 mlxlogscore=999
 mlxscore=0 bulkscore=0 malwarescore=0 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=lLa75Rz7;       spf=pass (google.com:
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan_test.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..9bfd11674fe3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -659,9 +659,13 @@ static void test_exit(struct kunit *test)
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -669,6 +673,7 @@ static void kmsan_suite_exit(struct kunit_suite *suite)
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-3-iii%40linux.ibm.com.
