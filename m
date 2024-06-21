Return-Path: <kasan-dev+bncBCM3H26GVIOBBYUR2OZQMGQEWP4HH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F88F91176A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:15 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-dfe71fc2ab1sf2677696276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929634; cv=pass;
        d=google.com; s=arc-20160816;
        b=sA/Gl+wCqF7XSbuoG50MJ70Aw9VSlR5vGqacwWcV/ejN1LW9tebUegAbtmxvbyblMQ
         lW3jBCnf5DKozuzYNBNOx6PXIAQDAD5brr8yhSV2xUp0xr9hLwcKrzPFam4EQ/2zJkkH
         b/mF3gxreO8MjqpLWoPlbPavvcVw0zJvRcFLmzFxOLiiaML9j/+vh78bLoO2GVn6JE+1
         QaTV3I+9gXoQYVaqGqBKRAd0KkyxrIWc4EJv7zEafGcCxDFmaY1/5sZu4u786GC2pbwH
         C/Xg8EBwbJJx0ndbm+hnoIaG+FDI7LEnhjQayBhwVd6Nrpko2pgBBIFQXfIWnWvPIRwM
         cXUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ml/ozzeN7UIseO1J6FaKTTgYVqdlJD2SCyC76da+ag8=;
        fh=LFCZDbjWT8vSRlDl3qQpdYWoLF8BfrsR7AICWwutE9w=;
        b=bnB/ygDzebzrEAY6ueBVBufms9HvbzpkeWouo/ACDbxvBNmxryBMb3sK+n3CwOsFYk
         +pwiF65JViUUWPrkXheyFZaT60+8/mSieMgL+UJORFdUrSVLB/qWevcKpQqTrLJcnDjg
         bR/qBSLVG/TCrz85cOIJmfnXYu6lItdgb24YcSNO4Mq8SiFK6SMaiKjTytgkyMlmV0NP
         aIgxybbdtI0K/rUxgFIPt4bj8Xu8SJlusw3N4TchGDPRt7C2SU5kjZulAqcn2HgpbALA
         tACDFzCfq7GZxa2TBpQ9gB7REsaMnM8K5/2OYjdhqqNndJmrZl7kJ6hjTdKlpkBDs1VJ
         U67Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OtO9k6id;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929634; x=1719534434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ml/ozzeN7UIseO1J6FaKTTgYVqdlJD2SCyC76da+ag8=;
        b=PQSJgZh7ZW5u1XvsSUMWcryG5MI6/Ge1MhTLXsaR8DMrz1R6y/r5lobUk9TdGdt9RY
         eXGQ+6c173p18dAoyWlq3FiX17TAexuRwKj/BnXDGDj2GMvb0rq+MbkWxffiveVhOY2H
         bAMtWDWfy54Kb1plrSiiOMmxF12tHJY/UBuCS1QGzOa140lx5QhFG8MomytWWTw/cCtd
         SaLuXcUb+oZC8xLzvWHpsc1E5U+mCWG7Zru9t7q988YgQyreUMD837R553IDJqhq7pwZ
         OtEUirtJCV57ijzA3VElP3bPpWwdcWZvSuCyO3q4E5Ezc42vgSkAOd2sJIGuC4PCTtjU
         bE8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929634; x=1719534434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ml/ozzeN7UIseO1J6FaKTTgYVqdlJD2SCyC76da+ag8=;
        b=LFhPQby/MA+99wSlvqa6UFygq49BqA5rcJ2hKyoK6jyWN0gxrfv0oVXVDbzbgQtUqE
         QiWO0ms0CbCArm7oDmQ4yem8xIKwfN1Kx2MtkYMUYRmpUVJgXfmuZNh1hD2xeeQKH/xC
         W2c1CfqmMQi+pZLNfSl9nlrs0V5Bqjx4IWsa0sclXvHdQFs1wa17LxXEd88g97MfMlm7
         xb6wQa7x3UreHEA1BGE6Tc4GpK/kew3y6D/5ILmDns4BRZNeLKet9t2nPLvExA5Kqgq2
         xNK2dYdpk8lq4lRzp1noDh3anMCgywLcfdMAxsFErwsb2sXHGlm5pJLMUf7LZK7RlImk
         xZ7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVk/9OGQ6uXrJRBXk1t4eDPJ+nHC1hXZ8A2wY7s+rtex+6apekh78RyL/7ADawuHokhD7OlT5Xvo45zatAo15I+ZZzRQwrR2g==
X-Gm-Message-State: AOJu0Yz8FlXfJieTCUl3ICde0hgxy09saHn4eflaD+8c+VIT3skd+rr2
	hz1Qwu4ygflfFX4yWxxR03IhFMtpS9Ee8RJAmwWBx37KvX/w94df
X-Google-Smtp-Source: AGHT+IE70/AtqKjMAh9YYYtiLzlglEAlgAKmiu7yObmELxFonijhJney18KnqNRb2W6f/SoWpKkuQQ==
X-Received: by 2002:a25:db85:0:b0:dff:3c42:8b02 with SMTP id 3f1490d57ef6-e02be10a1a2mr7145021276.3.1718929634454;
        Thu, 20 Jun 2024 17:27:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:100c:b0:dff:435b:cab0 with SMTP id
 3f1490d57ef6-e02d0dfe06als2113341276.1.-pod-prod-05-us; Thu, 20 Jun 2024
 17:27:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQG7//KTCtpHoKMetC1ydbIflgPw4Yss2xlbR9JszKo2O0BTNOP2rU83uj9M4+NT35w5aE6DWrkbW5/Fj3wz8BUHnKxhw1+pOP4w==
X-Received: by 2002:a0d:e8cf:0:b0:63c:486a:289e with SMTP id 00721157ae682-63c486a28demr45272257b3.32.1718929633730;
        Thu, 20 Jun 2024 17:27:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929633; cv=none;
        d=google.com; s=arc-20160816;
        b=kJGaPqpvxqleoqDfXlmuLbRKqmZIP1BKvA4l/0+L41/rd8tJhpU7h4tGwZ4sREpkea
         UwjsJiJwriAM6fLMflkkvjWdRS2J+ZvWvklb3Y3uy+XoNQp8p/USbbr8GY/vCfV1qKkN
         i6klav/EswNV+UMBaOrkfnKQS1jQkH4byhYS1EXppcX1jCNd3gcm0G+nTQlehNpGMe8n
         abgzcCuHWzyH2cCvrmkhMPLNTuJOlS6IgkTtjpoknmY2r5xLjHEWzufj7ZydqalsEnh5
         7Vm9eLeKimceEKKi+rpjNkBIyioQgztcPi+E7E7l2W6GoE+dwMsCWoTrul+ShzVaHp6W
         MHiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2Lekuxa2dBCBcc5htHlKGfkEfSg9eOPP5CW8wCh3gqI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pR10w38EJKdZa2Mls+RvYWqod/lXQNhENGcIYE/iu9RW7btCUHlYPpKbDb+NEHQP1y
         Q9sncfpkYAxmBpZJy5K2ydolmk/6FiLnkVvu0PObG1mCoc+Ub+7uQd8INvvKM+zqu+2x
         CPFZAyn3BV8uFB7l3N8Zn/IStVsBvP4p6U1V4nSUTbYoai+56YJEcqoGgSI8m4LG6s+M
         ymIPH8aAx8AmI6LHg/vtbltKo51dO1gqdEPV1kWI6rno9fju7C2Xz5BWEzRgTWt6MHZf
         SmLrpCtqTuxr33GNtPZu/cFd1Rz5ek+6fWbmYhLa0pxmZMoQuzHVJyM3sp2V9oFuil4x
         YDqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OtO9k6id;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f15e6eaf9si311817b3.3.2024.06.20.17.27.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNx6Ng026318;
	Fri, 21 Jun 2024 00:27:11 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1kc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:10 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0RAOp005234;
	Fri, 21 Jun 2024 00:27:10 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1k8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:10 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLeEAo032326;
	Fri, 21 Jun 2024 00:27:09 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjn2n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:09 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R4Uc51446080
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:06 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0B12920043;
	Fri, 21 Jun 2024 00:27:04 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DF4A22004E;
	Fri, 21 Jun 2024 00:27:02 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:02 +0000 (GMT)
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
Subject: [PATCH v6 36/39] s390/uaccess: Add the missing linux/instrumented.h #include
Date: Fri, 21 Jun 2024 02:25:10 +0200
Message-ID: <20240621002616.40684-37-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: pReXJqEurT5rl2qq_mhD2EICV0fd-riR
X-Proofpoint-ORIG-GUID: Tezy0GW5uUBrF3gOWCkC2HUP_VXQfi1u
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999 bulkscore=0
 lowpriorityscore=0 priorityscore=1501 spamscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=OtO9k6id;       spf=pass (google.com:
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

uaccess.h uses instrument_get_user() and instrument_put_user(), which
are defined in linux/instrumented.h. Currently we get this header from
somewhere else by accident; prefer to be explicit about it and include
it directly.

Suggested-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 70f0edc00c2a..9213be0529ee 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -18,6 +18,7 @@
 #include <asm/extable.h>
 #include <asm/facility.h>
 #include <asm-generic/access_ok.h>
+#include <linux/instrumented.h>
 
 void debug_user_asce(int exit);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-37-iii%40linux.ibm.com.
