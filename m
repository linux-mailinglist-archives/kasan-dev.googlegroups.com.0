Return-Path: <kasan-dev+bncBCM3H26GVIOBBC6S6SVAMGQEHGSIJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C5927F389B
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:53 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5c1b9860846sf7871585a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604172; cv=pass;
        d=google.com; s=arc-20160816;
        b=aHKRzCvqtgOlGxl3wacWCzFBlReBvoFJNme6c1Qfy5J5F3C4GhpVs1MZV2Tz1oH+83
         DuxQzrBX8GylHS0C7VQ7getr+0SlPSxSHxhTMX7nn8s4fjXy6H5pFU5RyFCdbQb6BYtP
         U2aDc3+lNEyyuljVL+ZSAi9KZA9jEH4J/1m1tNcsGYwCryygRJky2qR4PZOYYzypYyUf
         jBA1V5bDDgb4e5M8Bsc4CjKnh9AQhTRtbakHpsYk9+wd3Owar9Fuo/LXlax++AiM9Mbz
         sd227CcrDZrNtropZXZTBwq+B4If0OybT4JUbBB4ALpJp7awIPW98M8AP73oNuP31u3A
         /ZZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tIyqVUfHjqzPu+QsP5cMwvQWdCYiwKd2im83X8HoPpE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=LsyuGxa7t48smfBHZ5ZJQpW2Za0KeZYSPP4zFD2bVYDQnat+oxFzv63ZlmOYQEdGUP
         k89v+1YJOyH9xXU6C9/svfYALxkzt9bwhmSpvLGyyUHloUGw7F2dWIU5Sf+VEoAarXc2
         TONIEEMn1fuP1ixhP8Oqz5fZl3/+i460BbOmhMJUii05ov2JpYYnn+2FTrNjjj6GKAaf
         tEAfParbom0w4mcdJotmm2x2FaUtOJyj/d53DPqLnGgd1Wc+UAym7/RJLlTKGGX+I8oq
         q02buUlDKZyzYGV2ni+8e0d3uJHLQNGvE9P5iAtF3gAUMTPbRkhG61XGyB7fmE1JPCbR
         h2yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kvOhNmDE;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604172; x=1701208972; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tIyqVUfHjqzPu+QsP5cMwvQWdCYiwKd2im83X8HoPpE=;
        b=pu9c3vMlfAcli1vk+4cBz4Yql4A4X8Ckg0a7IClYqEx5X4XB0nrRVJUCFlr0Bt0p4i
         gmV9n8YLoqGBmIZGwX+I0znDUkSnEu1wje7OE7WViqzoFGWdZljQO8tQN52pCoY+SvcS
         mIVXS9bIrq7lY9MhdBzyKj8UHmUHUZMHA65gMz8FvEm7CgMqkNQKTmEaSgpHC8t6CiGu
         ThULNJC0xMRVPUtnIvTfhufrMCjOPXHrVxbMaR+CYIfo2lLDJlDTYNMpJMmhnSRb84zB
         2KYylYy1f0jQjbYfywvi/npOW4FoWdqm+6NiMjCuCz+epqi0v3l+5QH4Pghjrrao05UA
         C59Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604172; x=1701208972;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tIyqVUfHjqzPu+QsP5cMwvQWdCYiwKd2im83X8HoPpE=;
        b=inFyNfUckQEypD1+4+BaPiZo6mDvw5yBWNOy11oJygzejvg1yFufz2ZAqPhe6+Puk+
         PtM/qHwuK4bxurGLb09LuuIWSOueWYynKsrOcvjFsWcMz5TK8TsjfhOPeWaWqBRLtpDL
         5AZgngnIV586TdUv8V8KmNU/3w4j/IsxqzwihRN5a5764iAgzfdTWGjzL4O7YCmf44Hw
         CEiKobz2J12EeiZ1VflbOxDEtkSLiLgWNQBtsWRer+Rrlh9jzl/n+h/O5bFfJ4VvoLka
         BULEoPp9YyqMpFpOrBwUCXHo8yiFj7sVnywKk3XXb86d+GhgqLAiMh7JQX/VhKiwc4D5
         A4ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzm48uVlgJxxq60CVspGmQO9B/hxXJbyEh1maNrSD5jggmr1Oag
	F6FvHloPXl3WjEmajmybExE=
X-Google-Smtp-Source: AGHT+IEGjo4BnRAcg5Lq1PY0RD2rLEwHp0QTOtXEc9WCwiEiiHyXL4sBcO8bt61yeV0o+NoHXJAcSw==
X-Received: by 2002:a05:6a21:3288:b0:186:736f:7798 with SMTP id yt8-20020a056a21328800b00186736f7798mr454543pzb.11.1700604171643;
        Tue, 21 Nov 2023 14:02:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3995:b0:6cb:a754:aa46 with SMTP id
 fi21-20020a056a00399500b006cba754aa46ls2156772pfb.0.-pod-prod-06-us; Tue, 21
 Nov 2023 14:02:50 -0800 (PST)
X-Received: by 2002:a05:6a20:ba9e:b0:188:2b6:316b with SMTP id fb30-20020a056a20ba9e00b0018802b6316bmr338402pzb.38.1700604170621;
        Tue, 21 Nov 2023 14:02:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604170; cv=none;
        d=google.com; s=arc-20160816;
        b=fGcJWpzpf2Bpg5wOl/RZ3bs2uNdKn7WF+whWzGAz+CfLus6DPKazRJ/s6YMd/PUwIT
         kjLNx8KgXYDNKYYW1qeNcwlygh/IljPDSt1+SQJr78c/HP0GoX6iXmio0nNLMGkrRC30
         wrq7A6zjqaXk7qK576B9ChWQ0OXctVG1yuU2oTURsUeyFYTivVGCsvu8dHDq7/FaoN8H
         53OH/3s3YZDKYZYbHxXRp9lppVYssysXH/KxWyx2EEyVU0nMQ4ukOqDo9Yu6pPHq9kO+
         qeh4Sc5f5ARpGb1b9zh5uvHIwv2zh3jxOLRPUrAG9y7dGs6WKi9RB8lwtoVhqE/0V/a9
         ucKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0PRv+W5j3hmY0RY/lC7JHKrtcmpV2hH6yXsuJMvS/IA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=DNKPWhlnCEHc81xT8azerY5lNJgtdsyczpq3wncn5knijNAglVMCTwDlHtmIPDQzkX
         RBRM1meCHJ224XIFjJ80weJiv/kFaWafRMFnggvzc80QZG5oCDOd3IY3zey6dJgXdWg6
         9O45m07Mm6y3eT/ZS6j+kdxpsNRc5i/RtIkSoYg++2r/BHbY+Zwj+I47RxEUEDmwDxZf
         zpeVrpm5Lj89OMJ1K9eDcgjLr6DYE2QP+JuRXLY2XiL0s+qEzkAxC6o2uLi0Itbpntd6
         QjCheSeugxnhI1AAt9rFpme1Fk63FGgKbZe+uhc+q/WMHgyxpICAvcGtUby7sMDdu8j0
         eiEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kvOhNmDE;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u13-20020a63470d000000b005c220d4fc0csi452034pga.2.2023.11.21.14.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:50 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLfHWB025433;
	Tue, 21 Nov 2023 22:02:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1a9b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:45 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLxRhA014299;
	Tue, 21 Nov 2023 22:02:45 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1a8n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:45 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnXLc011051;
	Tue, 21 Nov 2023 22:02:44 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf9tkbbjq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2ffQ17629878
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:41 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0E3C920067;
	Tue, 21 Nov 2023 22:02:41 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9D5C520063;
	Tue, 21 Nov 2023 22:02:39 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:39 +0000 (GMT)
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
Subject: [PATCH v2 20/33] kmsan: Accept ranges starting with 0 on s390
Date: Tue, 21 Nov 2023 23:01:14 +0100
Message-ID: <20231121220155.1217090-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: S8tTCIGaU--C4RVBZPx5Ly8NCbs0O93F
X-Proofpoint-GUID: qMTuMTZ9GQusulDXz-MrPq75Kr6mBAKM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 impostorscore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kvOhNmDE;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index ffedf4dbc49d..7a3df4d359f8 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-21-iii%40linux.ibm.com.
