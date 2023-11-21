Return-Path: <kasan-dev+bncBCM3H26GVIOBB7WR6SVAMGQE4GOKT7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1754B7F388E
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:40 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-db3fc4a1254sf248648276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604159; cv=pass;
        d=google.com; s=arc-20160816;
        b=RQHB588XrUEdjVyZD0FVVuNm0OTiAsIPEx85sn28YkMws9ydgGxOO7EsY0gPEW1ozF
         BLlvHwMQD52NjYzSkkl+k4/Xy1zo3lA7zgX423oE/u1dMW5na/jBiD48Cy2yP41BGihY
         j2Oz6TFZXjRULuxSOIfqPkWyzvQKfBmTGI9LkS0rrFD5xi2LagKHg/wVd2zSqrejljqx
         u+nZ+XhNENFQM1IpdqBKR3NmRBhGvOeWRokfvjWBC4jw16fpDXCKrOiDul4tocqT2EwL
         cowa3LwYO1/fR3zhmAK6DoMq5Hf+Y6jLQDVO1chUSBm/7fjGL8rrw/hiwumyUgIB97Hk
         xvdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=10qA/s/KsDCfCdsqGirt7UFI4rFAnL8+sar224v5JOk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=QQiwMVuKg/zL97spOupd8/4mo2P8H5BG8PV5A2HlY9zdoH/1rUGyJ1FMPR7UuWISeY
         +fQ86tmlqHp+xzvTyn3utnppj9ji+alCdgNa5fABlqZRr36fjCEIJEy+TwgrvwP3uNQN
         D6oJBmiQTQO3G621xCDP5CltQN0mY1ipF96eJ169u9AOwWhfIqwQI2SAOBSkQBrGGxIw
         o/HEelo0mJBTx68fzRbcUWlaC997k3V7gCcGjrQWdfdsFQIUWHB7xM0eSO42ct6n7pvA
         waW8iMtcnsMgyl4OIyrMQhVmKWZKyLlCT3oV1DQthfj32IgfrGOn53XSo06Yy0/cILhc
         XYRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FfBMOJW7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604159; x=1701208959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=10qA/s/KsDCfCdsqGirt7UFI4rFAnL8+sar224v5JOk=;
        b=M5AYXs/6yMCT6UpBaAqs1Mqyxf7NlL+dfhTLj+XVFeQuiVXuZ6ZZoON6MbMi6eTVeY
         Co97hYZv5e0yz956oTrnpnxxFsKxMLTb4LHGK9bqsEhtp3bx5fIrLxlz04eQsaLoEJvz
         ei1+0yn8yLNPzgAPfg6QQtwoRs3YIQ9rUZxUlTBl7zpwXiMouKduwBgs+FITRdbaRTzV
         rgbEGD+SuayTjErPHw6tbDa+JJpH2OaJkJfGS0NM0zXwItZvus9pKsF2NGQeBNDqVxBw
         E2X78ne6xMf1ek0wyst6HZb1bEQ0etTVeRsj6FPupd6n+OuXoOe2xpQ/xbbBCevrzA7m
         jmhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604159; x=1701208959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=10qA/s/KsDCfCdsqGirt7UFI4rFAnL8+sar224v5JOk=;
        b=UyFJsNhqE7opM1xzepYdjNEauHLi9g23CpcL4y1AGZjKEp+J45iG32CHoRdZ6So56I
         mL8KYWAls7rI+v4y5WzB9t02wdXuOOECIn7XJBLY3UcScqrSijNQ1i4W/tcCFNYGVcPy
         WxKETTwBm8f+aZBwV7+L8YSoRym0UNmM/QZJzGtw3refCm7vAnaAch30kxonwteQfioU
         tyGfJsMcEpOOq8HTi5omDpK/gUhD6skSsiF2EtSxNk2OV5Bhyqic8RYiwkNa9LgwwAx4
         unyJiVd7IXgyjr69GlMRK8lB5JIFUg4iLZoiJevqdKV4428CQFnGdMM7YPBDYzQDUII5
         l2nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyjDjramBmQ7knIAWknImbJZ46asjSEu3NY6Q64F8E7b5tM8Je+
	2Kkcu85gkWoYPrvHVDw5d6k=
X-Google-Smtp-Source: AGHT+IEA9vjoQA9I9lrpz6B9dcFF2bBISCfJGDBHbq8pJhHenuhVxg3md6xUF7+d6EhfRWFw3nf9FQ==
X-Received: by 2002:a25:860b:0:b0:daf:579a:79cf with SMTP id y11-20020a25860b000000b00daf579a79cfmr299506ybk.59.1700604158808;
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c884:0:b0:d9b:dbb4:f667 with SMTP id y126-20020a25c884000000b00d9bdbb4f667ls9566ybf.0.-pod-prod-04-us;
 Tue, 21 Nov 2023 14:02:38 -0800 (PST)
X-Received: by 2002:a25:ef07:0:b0:da0:48df:cb09 with SMTP id g7-20020a25ef07000000b00da048dfcb09mr298259ybd.54.1700604157823;
        Tue, 21 Nov 2023 14:02:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604157; cv=none;
        d=google.com; s=arc-20160816;
        b=P2cuh7ZOliagJP919IJ+94Fs/anXhv1f8Yne7MMemkXTTXcuxJp+HXqct+AIM3mrVO
         dw0fwy4v72a+yPiueuVw9BtmDy+dSTfq+9JpjtlXJdLIr6tROya10x+UPQGsSR1DAu88
         O17LOO08tVio/M8JMGBlyDkO+TKW5g8FX/smqFuFo3oXwBF8FJApgwXrjvTSKPazcGz6
         e6uH7po+Bu7uME/9IffU5gZfnpBtQjoTcld3A9gJWmpgcLLbsal6u09+WwYhB14mKRxE
         CTZ0XhvvWtyk5KLw11qoW+tK5aQBw/wQyvBVes3m/AEPVo7/FFeysLALiOtxI7Kx+8bu
         ziLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vIzYVZGtWn4qEhgFBaUJQVUNFd8KsI1vjZZcF37K7Yk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=UHVB66P/JDYxLuW4BDfHmvJZbDJ4CCTQHNkhQbihuxuIS1vOi6cJldFuUMkK68Qi25
         3bQ4WPzuJubTeQWcB01731kPiX3ScyiIfpIfpa6oVxGS1qU/GAU9GZcrdu2Wap79N5ew
         6jq3MCkJ1Uw7sbxuTuzolCBOmY2PulX3WzQFZ+i641MWQAKedJ4l7ZUX07xFMVHuCoys
         Wq/bzhNZeQABfBRGiXu0WbVgEmfwUmejYmDDsxFJHxoXvuyTK/YRyNzeSSV5qY2DNKCv
         4aPluUBFYbuI6vvJ3T/NwP658oV3wGC4Q5trgTnKX5SuS2mgZSuLH06C4g/gthPeGQsQ
         IXJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FfBMOJW7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id c16-20020a25f310000000b00da06a7c4983si135101ybs.2.2023.11.21.14.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:37 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLNq8L004940;
	Tue, 21 Nov 2023 22:02:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vp3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:34 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLNd0h004794;
	Tue, 21 Nov 2023 22:02:33 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0ve2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:33 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnbrD007085;
	Tue, 21 Nov 2023 22:02:09 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236dt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:09 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM26xB17629824
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:06 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 670C12005A;
	Tue, 21 Nov 2023 22:02:06 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EB7C820063;
	Tue, 21 Nov 2023 22:02:04 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:04 +0000 (GMT)
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
Subject: [PATCH v2 02/33] kmsan: Make the tests compatible with kmsan.panic=1
Date: Tue, 21 Nov 2023 23:00:56 +0100
Message-ID: <20231121220155.1217090-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: F0Gr-ImZBuLQsqLgWKYFAuGuX6uvUEWS
X-Proofpoint-ORIG-GUID: unXBtwpdlIVx4NpqCio10Xz4H4TSmNdm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=999
 spamscore=0 suspectscore=0 phishscore=0 priorityscore=1501 malwarescore=0
 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=FfBMOJW7;       spf=pass (google.com:
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-3-iii%40linux.ibm.com.
