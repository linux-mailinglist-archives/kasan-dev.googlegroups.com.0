Return-Path: <kasan-dev+bncBCM3H26GVIOBBZGW2SVAMGQETB57E3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E7747ED223
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:46 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-7b06bf47732sf1367939f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080485; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xtq406dnccxrBah/JCk62kJOHDd1kkF7hIZTo2brUpTHKSLOm+iY+Si+SW2XHbBaBf
         pkLIQjUtElmSFQujY5pjAbpCN1KRmg1TYslVqSmyUDR5OsY8N7I4BqYFbcchur8AWxat
         eT6oN9iaXaM/onIoZaoqM6kc4rQYv5l4HzkzrTcSLFsMZ+qLaktZiG1AQ/tuuOi8nhkQ
         ysAloLspa9pvZrspKr91cGEQlDopCvL78GOEmbWpI+qKMLRvuCRuElUdd27FXPDWdWz6
         WWBaFcZw1TPwXAygjNxrTs/F3peWKnKWbjmv8JwMs1oCt7GhzBUfe4IizN5CbPX6mb8r
         ob7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IrU0OevLJUunptH/wx+mJdunh0jpbQxL3TkgiB9YzxM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=JfDoai0jEGrjIeIZJ95xOyTn4AcagLwx3Is0nqivFcp0GspxK0QlCZGHmqZTG69Crm
         xrfkVL59rb+UJlZ3DNdfRYPLTBj+8/5S4w46ZpD131jdQNRK8xYftv31mVjX4zOGSzxR
         4jC1BVUIHv4ZjaZ8gVR3qMvjCYyLYTv+vUkTLpfPbqI2rVPl9vbiomGO5pzGkX1aWWF8
         YUB9z1/R60QryGaS2R1XGrSlAOLfUgugdNVrVfPTt007gVBNxferfF4MJCjuUTUzkOvB
         iJ1VWaFZ0rzsSHWlKYKEY5KuO6qsfgTvzZ39itFRpi4I5g80T8p+XcspVEfRdR0OUkMk
         m0bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L4vfRnZw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080485; x=1700685285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IrU0OevLJUunptH/wx+mJdunh0jpbQxL3TkgiB9YzxM=;
        b=GwrQwdJQGBm2PIhyANQUPwlj9LY6NzFsT2kDo5FjuUtWflm8lJ6jArZ4cl6gyeF93C
         kJZLhc6JADAtST7laLvUKSvaXdY4eYFXdhV7IWtsFPpu8S3DBG44/kW0u23Juul9OfJs
         m7oQYOfZJg0XZKvWNP+dDnoG6D8ApdMl4S8J/GY6Cb2Zj5DD7KN+jvibrZ6se8AfDf+I
         rbB3GHRUOwRu1VMJVP9KMep5QxQUL9n6x/o38P0WRWbdpbRSb0U8bWm8+wf/ZTgkmUWT
         AYrnRq87+q95DxDJEI0p+VjwTVk4icHHXxY5LQ4o4UOpHEPLVL/8y8UfFNKI/+vH4G61
         62/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080485; x=1700685285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IrU0OevLJUunptH/wx+mJdunh0jpbQxL3TkgiB9YzxM=;
        b=U9Pt7we+b0mtrPmHehtgUECpX1X1mN6r9xmPmoy/C6K/MM9nj0VvycqR5vC04weqoJ
         Pjyzy16YLV3A4XvsEUaxI4FjR8V/rne4NZIF6/Ee6GUGV5ldn9XUZvfBGm20lWQNb7D5
         LK856rlk7RsFRh5EzjVgpd9Rp7qzMWIxutyeCOMXsgaHFitWoYAsv4b6y9HnlBNQc47U
         OhutVbLNbVnOVtoA71ozvoO2hHJHzgCOjhrw9cqkI1CNKzrAoev0YehooJus/ew9XzwG
         gqxQA/UlOLy5dIyGhwGzYlomm2Tl1Pkb2bhy0wUcpeNRCgvVPHVcRNjGmGyBabGbbI5Z
         QXHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxAjpyxabYUOMsmK01wj1KWnq7FgDASSCBMVuMDrl1/gErGsrQ3
	H1h87jLmDeSJBEEc0IU1euE=
X-Google-Smtp-Source: AGHT+IHjOKyeLwRxQ1nMQDpgZRI5R4x+9uzMo5sFLILztB0X+AEIGHrlWe58I0IIwQnHF420Ladp5w==
X-Received: by 2002:a05:6e02:190e:b0:357:a8a0:3459 with SMTP id w14-20020a056e02190e00b00357a8a03459mr20770670ilu.27.1700080485060;
        Wed, 15 Nov 2023 12:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d3d0:0:b0:357:af8c:6704 with SMTP id c16-20020a92d3d0000000b00357af8c6704ls62427ilh.2.-pod-prod-02-us;
 Wed, 15 Nov 2023 12:34:44 -0800 (PST)
X-Received: by 2002:a05:6e02:152b:b0:359:4287:28ef with SMTP id i11-20020a056e02152b00b00359428728efmr20290954ilu.20.1700080484442;
        Wed, 15 Nov 2023 12:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080484; cv=none;
        d=google.com; s=arc-20160816;
        b=rCuJVB8j2H4gkkAVUXFkVeage015EH1MVAI3mFoEPIoaPS04tLPT81oa/7TRH9gxAx
         cNrloSljYC8nQmblk/MWT/+bvvu8BnZeFLQewPcE19P7FdDhKVN2sY3Tq4UGeMzxuask
         WUlt4oI+CaxZPfQqt363DHRGAD5Y0HWQqZliCcqEJOQF/W5H4xE69VSbgSmkUhcl0/Zv
         Uc9H0rukFiJlBlcYiHV69WAZEhkc/9YdYidLd2HYYNGBg6jB6yKgQnIr3MiLA64dmDhB
         DytIcDBTy9iWh+3GFM3FxxTJTofh8Hl2mk0g9XgndTtlGD2Q3c8ZPC4D9yXLmpX5EskU
         qakg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CdLKZ8qn4zwP446RCUpjk9jgcaOUrqtk3L/VG0jpav4=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=XuaUu95daJWtRizsOKp9wkyVHuNspxMLs1ZTIpZJYauoV5SFMbQTPUiyVtIO4SdrHl
         KS2e9gi2UxHKF0ZL2+QYs8J8xAou5VL24z36fhRk7Gvvklx/jgx+YUaBiLinJbJfdYXU
         1YuKj2LW+Wfy85PkDWaPEa2zCxPYcgRYmDr116XvsVWycTf9wrCCZtChGlkkUzmNnw2J
         P9snUyKMxKo1vIRoUeCq2EKJAmzBqOAYpEAi+JuGIz/mdbuokT1GtJK+uZNiUsJiNZrK
         WaiUuVZK6IX9CTPaiKYwDWWksIuZipBGA3yNmwKpdlFPce2NITDLDbT5F/5NYg4RSjPT
         KKcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L4vfRnZw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id by1-20020a056e02260100b003596cbb2ff6si1399328ilb.4.2023.11.15.12.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:44 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKCEZD020041;
	Wed, 15 Nov 2023 20:34:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgk2y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:39 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKCZk7021216;
	Wed, 15 Nov 2023 20:34:39 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgk2h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:39 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ36R017548;
	Wed, 15 Nov 2023 20:34:37 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj7ae-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:37 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYYHx44434164
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:34 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 415CC20043;
	Wed, 15 Nov 2023 20:34:34 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EC1D520040;
	Wed, 15 Nov 2023 20:34:32 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:32 +0000 (GMT)
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
Subject: [PATCH 15/32] mm: slub: Let KMSAN access metadata
Date: Wed, 15 Nov 2023 21:30:47 +0100
Message-ID: <20231115203401.2495875-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: CXyK3LQ24vo0EH6joaIYozyRUtTOEyS8
X-Proofpoint-ORIG-GUID: qdS6d-wEuyX6_5mdxK25IrNeVjaBw2Cq
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 impostorscore=0 lowpriorityscore=0 phishscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=999 clxscore=1015
 spamscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=L4vfRnZw;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 8d9aa4d7cb7e..0b52bff99326 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -700,10 +700,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-16-iii%40linux.ibm.com.
