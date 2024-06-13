Return-Path: <kasan-dev+bncBCM3H26GVIOBBRNFVSZQMGQERP6MU7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 419079076D6
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:51 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f711de167esf9936515ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293190; cv=pass;
        d=google.com; s=arc-20160816;
        b=BkfTdoQESnhaxfP5XvidHJZ/We0wty9I6nj4HUS2J4lqoWi1QEoJ531VxhH7I3Rv3T
         kDlVPYjFkzGIKKJ6sLK5QEyl3s/4SDPdMZu+xfU1HcEzFbVPco65MaMrWwb93MI9Ev1A
         vM4PtQvNr194iuinWNS19iK/K2/nAYD1TKfRgImePet2WDYzzivHQ89DZNMNAbIlZjkJ
         FyVJD9nIbHQwQ20GIRFWf4dY2VvoTjujCLxAx839Y7j7JMXUxRubRtmeAWA614pn/wVC
         LmpsfUdhmcxsl6U84EMEL4KMLtBz2XRTiUxXx1KMOAuq9f7DfyF5cN2tKhUUdggvHgNv
         j38g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wcdzqlaJ9PrXTBlamUP8DSb/pxiGSBQQY1X3rbuh00s=;
        fh=Bv7+sRuXNC6a6U7HZsERx8oheWbzwmC+L1K4zil4GI0=;
        b=jICwzsaITvN2xF6Ihbo9cNF4ZmxNbn9BDnIqyPGZPJUSuq2/NwRb0P/xZAUy2QV9O2
         renXFIckxaBydAl+kGZdX/+d3olog/ZsBveZelyktR/HEy76U5t+UwXg1Zuv+LwUottu
         a0n/CUHvulDUDe9DghmLOJ7y+/gUoF5xeJKWZrjkec0K54CIH4OwAdpfmBpoU37A22Qs
         0b3EdxYr+9aZzKYD+IwbfmrOfAbTHteXxx/mn2AOPvzhQEizVNmNGHUg8jSRVAVQH6gO
         0D6275QWmvGMojMMqhLIyCWkABG3qIUsEoipQvbBYMWGWlk0D7vvfKQIFSXGgJh1lt8h
         Ha2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ryxyigWW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293190; x=1718897990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wcdzqlaJ9PrXTBlamUP8DSb/pxiGSBQQY1X3rbuh00s=;
        b=r9+Hmhj2Dq8OEJ8BwPkFwaQkWlRCdT74tWVJaWNxFdr+JacRi/7/1CPbRLSALbtzRW
         5G3xZ2UVi9jVKiaolB6tNSj4JSpKYMBTwu91wqi4+AxBS443sIajTeEGZ/mam7wqrlfE
         Yd9kvLnjxg/r8nhggZA1yDinsX0NGYIu2vX+UBgf403dcrAXV21RWpXxNRGsCG/9aDZ8
         +G7Oh1tcipkvhM3wtDg23v4KCVS0JAeDwvWrF1ankcLRqOBsmDHpzBub9cJ87aUJ2X0r
         5GkLJlOL8L4ktBOWL/Fc868sTA5RcAcTLztxu222OvqYPDaymTu2NN+sHiyKNe27A1Yb
         Tedg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293190; x=1718897990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wcdzqlaJ9PrXTBlamUP8DSb/pxiGSBQQY1X3rbuh00s=;
        b=ltfiJ3I1xs4XtNIjLE/US5o2/RMuhnqCjAfENdZ59FOXZ9U7Nfehp2USRF/T1nCaPQ
         aaWl5cUVTNO5i1swLVQGtC4DeCrUpXZfsrAJhnTk6L852htdSWvdbBApx5s553hSsU4a
         VrrKZH52yW59fvfNC4yzAc90IattxRAynwLiTGpNAhJl7wYH827QDCCn/qF78MFoTOGU
         jRXuBLWga8312LHOqempPc9zBOyoVR6NyqbeQEXLNkBP8ePCequfNhOH2NSv8xOKcLlc
         /kEAYhtKZDtsQt2s/Ef2YkMR8MRtYh85s+4U8ybnBlcEX2eWVSG+lkd+yVPjzXBCnLq+
         j4lA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUV28yRv5oc7A+AA9PgPkJdG1PjR8kFOp8tHi5diRvrDUWgNH0doRf17LMUa7odvFaMb7v8sw/5HJ5Rxgpz9weNcbRjaBbynQ==
X-Gm-Message-State: AOJu0YxrkiJ2KZlQRKFE2I8R7thsp9d2VDPy65BBWFE8697x/3czH4Vj
	RrJ9GaPmRHBxT8Qz94iZZwQwvNo64tJ8HVEKkCLMtqG/ODmkFvu2
X-Google-Smtp-Source: AGHT+IEiEMRXUWzkqi9GbxssIhw4mN0hRZIlcVP8rgCNe1ZRm2p1DgnZ3R+Gs9dIiaaLhT3xlnNm3A==
X-Received: by 2002:a17:903:32c3:b0:1f7:317e:f4e0 with SMTP id d9443c01a7336-1f8625cd6d9mr535955ad.12.1718293189536;
        Thu, 13 Jun 2024 08:39:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec81:b0:1f3:39c:8baf with SMTP id
 d9443c01a7336-1f84d77f2d2ls9086795ad.2.-pod-prod-09-us; Thu, 13 Jun 2024
 08:39:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIHneBLuNRM6o6zbU+caTD/9fu2eH90udjPdNXv1XiBEPhz2rVjGvEkWkW+ycOqONTYVt7KmAWIx9Hku1MX+HMadLUOFDz2YCXjA==
X-Received: by 2002:a17:902:f70c:b0:1f7:3763:5ffb with SMTP id d9443c01a7336-1f862a0cdc8mr62825ad.59.1718293188350;
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293188; cv=none;
        d=google.com; s=arc-20160816;
        b=xf9P5D/wK/+WaV9uqzHAqygAINK0Sl21pw2teK22bjzYTKqSEolXk4Imquqtxu6lfm
         zt8m5nVFJLSNYQq72PJ202VuTSp2obsG9nMfY1nQvrnx4wgPPTB1wq2lZZ0FJb1hcuH9
         vz2i80uUPft1Ka49AuJ6w4VAlR8NMXKt3Ubp+fHAl+xdxQ07ZTjCg1jlazbtT6I/6iGN
         M/ZDfLk4X+HMpVzhn29h4htpOlnv1xxpPwAq+nZxolhXc4p95hk3VUGzWIIVo5r8PYG6
         tkx1EoWbXseMs+glrgZAc+hMVI4wYGOnWs4TFZ4IiRZRDrxY0Tqt5+zB1Yjxp2RqDym4
         lPGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1qF7H4bGHDZ6iOOMBP071rdyF1q1YAWA6gRStiWbHSM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sbnCq5rtqWnlN/stecrP0XHS5nBK/KkY5CQi1Qtsumgk2El5zH4mqx6xJGlWtDKUKm
         aiAOAPdQtQ1q4r2eI8Sp3gtaitM84tFyvMPhxypiOuO00Tvc5ToPA/ioSbhIl+Upk89C
         RXY5UieWRdX9rrEEW8GZqpkkrZgXWafRtfeurJ5hJH+5fmYxPbmlRM4XyDwIS0dmk/i1
         gXzJkvwr4h5TUedtKhFCY0AvviKXQUnEdYD/fPBiqwbsbQUMh5knsX54mKq2yOHM4Mtn
         yDMNu24FVfcJSD7ixUOUbwiOZMzuXta4z5GDontX5oPgpjF4+3zvE0FM//CQbJOHPthB
         c0RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ryxyigWW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855e5ec73si561185ad.7.2024.06.13.08.39.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFSfR3005622;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11ymw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdgZ7026429;
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11ymj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DELJwo008711;
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk0e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFda8o48038272
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:38 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 310F220067;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B32ED20065;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
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
Subject: [PATCH v4 06/35] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Thu, 13 Jun 2024 17:34:08 +0200
Message-ID: <20240613153924.961511-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vlPBHhf6wo8Wwm-gnrID75BnVJjJBeF8
X-Proofpoint-ORIG-GUID: vSngS5dm6lATwFHi4uKxppdf7UV1X5cJ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 malwarescore=0 spamscore=0 suspectscore=0 clxscore=1015 lowpriorityscore=0
 phishscore=0 priorityscore=1501 mlxlogscore=801 mlxscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ryxyigWW;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Assume that we are handling user memory access in
this case.

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 22e8657800ef..b408714f9ba3 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-7-iii%40linux.ibm.com.
