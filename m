Return-Path: <kasan-dev+bncBCM3H26GVIOBBYOW2SVAMGQEQQRHYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C40097ED21F
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:42 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6c337ce11cesf69027b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080481; cv=pass;
        d=google.com; s=arc-20160816;
        b=sLcgJuxwBqxM3EBnnJPGz5KNbpot1n2byuiLQlfh91OjAsAbb/pG+7DqGiYaHRad+K
         lylWUSPTqTBG2/3IW4QV7smrVeRX6Q38pEPrbOkl6m9DmE7vVblhVp3Dk4N+uhMIR2+9
         Oyw9qrpnNwWaY/JA6+DEBeAI/IfGCpBrB77N35n2l4EvlsNo+EagXFo2P09Usrr9O0z1
         YYwWy3NdT8oMGH2uxwwiNczShj+M2sUbE0wtU7md0OJIrsGTCK7CvaX+lmdxEo/fMr47
         qUJGnWB0ycoDCD0ymdKDD96kVg6/Zhd5bY4kl2WQ7W2rl/mPoQkLD0TEPMY2ucop8qQ5
         1YgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8rFBydPNsVJR+2/3DWy8O+clbAw5rmGG2O9t2iVhlyA=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=BeuRJ39oTtjlBdOKGX1teU45H6OVOiHL6n70qrAAlCqEQRb7VF/1WeBJLNMpjBiPlk
         Us52o06xU40wkjuP1ghzv1bpzKQQmS/WdUqwSTRLNchcRZZZHRKQbClh36P54VOsTaAW
         37epJRPar4DoiQh/8Ugec72sJbXrN5gdM2QWiEZDce2GJE15sM7U+HGx6qqVTlPEA6rS
         mJMojFC+/nyt1ljlYCFCf1hda7wftPrdoI4SovXW8EZIeB1cOCUnCISt5SnCQ4q3mETr
         KwHR5i9GGPcRLmpDaFWjhxym1L6z6zD6jlRz0SG5QsunOmNP3EjXMz/suL6mY7wboSkx
         JOSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LLyi7dxG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080481; x=1700685281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8rFBydPNsVJR+2/3DWy8O+clbAw5rmGG2O9t2iVhlyA=;
        b=n8sagzH4BC7+mdJTQnDgcZutO+V/XcNTOPVsEvUGt7oi9wIHD2TlMjneKgiIH9NYJm
         P0W6tYrxrQd7ei7/dFjt9S9atWCHepCSxxtgsFE27BvvBfuTVcsvB6ZHGt6bdpatf6Cd
         h4alH131465zL1k8p5d9rmxeJR+BxhDCsjwi4cj/OFT+/TqyC1myTKH58JXWAkyDqhyI
         YM+63XJYMdtalwm/BsAePK50FhbUgN6lafdQZjNHqGdHmrN0yJi9Z2C0/bP/SmhpU/3g
         zIOhOzMSAiuri38cuj0APNIbrM2zyGBkhAdzrWzssOI6xdVt/wd2lVuUqWhdaBjbcBbc
         TaEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080481; x=1700685281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8rFBydPNsVJR+2/3DWy8O+clbAw5rmGG2O9t2iVhlyA=;
        b=C9ctWC7CpqC0AIuGWA0ZqAKkfY/4+umES2KgF6VFYLqCtVvDnxRafELuJ4fUxbccuK
         XFeOsDtyZs2iYtZ8E4a+WXOICizZvrotLJgVWHEekLw1lgTRmRFnhT9hufYj8uJV6ah3
         gmTbrGvlapJaiDATiBZUreGl48W5pdSuIS1m8aa+s9/0W0nnhISG9yj4s/sIlgW+JXyI
         ObCNwY4lUPY7SMRVP4eIwADIhty+1GbgDeTbfL8TpIiHr8aXIV0iA/x2kEGfpVxBVlnv
         mC1zm8qtyR+QpEdyCe7a+wkQIGdCWt+gMQBeF2jqmq+Wozb89xjKZRmwxsKFSPVUlira
         +bBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyN03S9B0G1lYTBkuh7ezC0UU5yzSNOeY8MIVEhLgCubScPZw6r
	YY6UOhx7u84Q00PByBOCP2yEYA==
X-Google-Smtp-Source: AGHT+IEBCgsAYZmSNHuEHDnpEfGeSswF3L0235TqcP86Rk2zhbdDWlcrSay0TDeYukKwZIJ1OG/XRg==
X-Received: by 2002:a05:6a21:1497:b0:187:3766:7fd4 with SMTP id od23-20020a056a21149700b0018737667fd4mr4528433pzb.24.1700080481331;
        Wed, 15 Nov 2023 12:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1ca1:b0:6c3:4984:b117 with SMTP id
 y33-20020a056a001ca100b006c34984b117ls106461pfw.0.-pod-prod-06-us; Wed, 15
 Nov 2023 12:34:39 -0800 (PST)
X-Received: by 2002:a05:6a00:2794:b0:6c3:775e:be12 with SMTP id bd20-20020a056a00279400b006c3775ebe12mr15301445pfb.22.1700080479326;
        Wed, 15 Nov 2023 12:34:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080479; cv=none;
        d=google.com; s=arc-20160816;
        b=D+jmzo9ah7GHMBrhUWUARGfJzw3iMgDnZOsu2foFjY2ktUOf0a40bVGs2mluhdbz2i
         R/8SW/HA/II8VoomCO29i7boHFo2xJTqPW/mosEPWfe+KjBD5beTOBCSALVFA96rdyJC
         kqZfhg4Ke1rfZT9nAlsRzAI68GizI0E+V42/ExjK+HWHd5Oqw6HQ5YvMfhV2ilpBkYrs
         RH32xcuH0cpgK1fig/+kvu6M47Vbh7zrfYLKa15SIuj3Ssp5gc2iBTp2+8+MC/ejykd2
         GV8or2WeXuWQ2jDjlTY7MdL+pguwoZTQT81cgzB/Zk4nX0z3U2kvxOuAWCLGV7hVZadx
         QfDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Prpv+ioyJJfZrf8ByIxPulecOh5L6EAjxoH7NJDKd6Y=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=N5Lt39fv/jwwSVtwjICvqAITqifKo8QPY5w/QzI5nrO1FgbJ3KiFxK8uQCuqC2yT4R
         hZghMvbx040fU5gDfHgzxhJib3lQoHa7cPhM64L+yc7+Vu20UDX/fus3NJWg7DtEAkAq
         pSkRUNqy6FNn66yqV+qd6KRKzI6GkuZD2P/7xbGQaDFPYcyMTxPK3ZXFpUeJyFbkx0yN
         gEeJP/m2cFV03yiIhJwaWdDD6oAwXtLduLjrx/DRFqwhINyGGOqzqIv+QM0IyN4WQwnJ
         AVgqXwIlbwHgEmBnGlMmfowUMxszmo+8YadoM0CMdDWxL1SmYV35uuPHp/g4fucsOOO3
         RLlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LLyi7dxG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bs125-20020a632883000000b005be3683ec66si773178pgb.2.2023.11.15.12.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:39 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFagp016166;
	Wed, 15 Nov 2023 20:34:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb6h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:35 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKXhxg002277;
	Wed, 15 Nov 2023 20:34:35 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb65-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:35 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ36O017548;
	Wed, 15 Nov 2023 20:34:34 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj7a2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:34 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYU8m22807222
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:30 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C4F4F20043;
	Wed, 15 Nov 2023 20:34:30 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7867A20040;
	Wed, 15 Nov 2023 20:34:29 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:29 +0000 (GMT)
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
Subject: [PATCH 13/32] kmsan: Support SLAB_POISON
Date: Wed, 15 Nov 2023 21:30:45 +0100
Message-ID: <20231115203401.2495875-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: VtMKqHRGouLJud_Z04fE9mTeehVK5PxD
X-Proofpoint-GUID: 9JnYJ8nyLC98Hq0I8m7EcHlY1F4CxSFW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 mlxscore=0 clxscore=1015 adultscore=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 mlxlogscore=999 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LLyi7dxG;       spf=pass (google.com:
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

Avoid false KMSAN negatives with SLUB_DEBUG by allowing
kmsan_slab_free() to poison the freed memory, and by preventing
init_object() from unpoisoning new allocations.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 2 +-
 mm/slub.c        | 3 ++-
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 7b5814412e9f..7a30274b893c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -76,7 +76,7 @@ void kmsan_slab_free(struct kmem_cache *s, void *object)
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..8d9aa4d7cb7e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1024,7 +1024,8 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 }
 
-static void init_object(struct kmem_cache *s, void *object, u8 val)
+__no_sanitize_memory static void
+init_object(struct kmem_cache *s, void *object, u8 val)
 {
 	u8 *p = kasan_reset_tag(object);
 	unsigned int poison_size = s->object_size;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-14-iii%40linux.ibm.com.
