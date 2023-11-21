Return-Path: <kasan-dev+bncBCM3H26GVIOBBWWT6SVAMGQEH2HBQNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 47F817F38DA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:06:20 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2801b74012bsf8346437a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:06:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604379; cv=pass;
        d=google.com; s=arc-20160816;
        b=NvaDiAB6KtgfP4N1vsUDNYy3r1gnA99kzZ6RWjH+389z8GM0O/3s4sGdnltnEXDBW+
         zjoTo30AUGryrjiiAdcHa9KkZtaRIV3jg93imcnk5idgi9kekuULDOF9GPe+X6O7N6dm
         kQbMamn93RKVnSxrJL+vt69UR4BDZE5twy+eZ7twEuKNsr9fsjB9qCFX9+Mux6D40dfg
         nyFMfpKDx/nmsLzBcPE12wFhgloHn7wauKXJ5UGBJOEEgsvsJJcP4YbIOUKGCfH2E/aw
         OWCZy/wLNElXuIwiyuO0CHkNcGJ8x0IjIu1C6omX16a9qJd3Q13X1u5f40jLyFAIx53I
         5RSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jByJh6QMS7lE4PLoJKy7AJaZtd6+/hz1kNI+m0eL7+4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ogoRck8tnsp5ZjgykyR9zrSfv2MXKC5Nx5Mhcv+qmiFCItTzFaxe+6BlkS/FQM8SMA
         WOlFTyYe7ew4zi5Ha7o5vOc4z6zYab0nFYMdyZX1nhAgWIGNgSCKchlP1ikrwUOtoUWA
         Dw0v30g78onDENSxQ0d1fisRt1vjzyZ+22ELrK90KxeAouDUs0dimTLEJcQAKVPUJA/h
         RPYK5L/gXUH/iA54vxKDP0ujGLJutbeNkb3FpCUE0wKr6ePFXfh6uuDnMlzJvpz/Quk0
         cTK2mVLTuU/0ztg2wwp+juNwq1QxpO7HSHVyVa4g/ElSU9Y4a6NpoHcg9r8339vHL6QA
         6QVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SxOEgF2k;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604379; x=1701209179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jByJh6QMS7lE4PLoJKy7AJaZtd6+/hz1kNI+m0eL7+4=;
        b=eIMOemoZcET/DiMem4WAQT5+PdV7yx6K5wRoI0h1tPRamrnoi15umN+qBajBDsm2tP
         198Q90QTLkfbPPOYbkrgFq4zyij6gxHaulXQuggMZ6HxhARH1JOaqjGoHUNqxG3su5Wx
         gmUU+k5yHcJkQgmulFxYMGb4xtHrhWaGGh1OuVhwUoYRb/lxnq6GM7tR/9VSQE+Ug/XV
         mSD3CVFbTSB0kXJWXgpNSeBD5U0X1FprUI80lFGG3PxGeaKXOmz+FDkiRszFWOM5YrCX
         R81eOLvZYVtED2MnGBmtr1lHhObOE8Ip6j6/R9LET3VGNF/zEmnIr8WazaCZIQN9EYLt
         yDNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604379; x=1701209179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jByJh6QMS7lE4PLoJKy7AJaZtd6+/hz1kNI+m0eL7+4=;
        b=WJLfATjoTeQc2CjoFNrMZyhPBsOv7FlSTpFuzFDoB11nfEu5AkENreC2dv1m2XoiQk
         P/PPPRCCOHm6bsI+E3df7TVdpjA96vs/gOEW2POhtcQm5RFwJjAxThu0BJpPapJUe5Ae
         M/AjOvEl7HWpaRguJi0sFekuXH8pJiJ5eCS8GTAJHdWABBNUCG88o8I70kEFsZA9lsxb
         ix3u1zZmgSwlGQFk1YHrjNSc/i/yM+HYNEr7Ni51Fj+yWXvHe/0AeVCKlGWvF8sd5thO
         EjWEbzXDyEKaAu5k8+ZpivYdADv6IlelooLSSas0oZjuZDx+mvnMB3fKRjruKKqP+0YF
         nDWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8Sho5igjvcysL+dIJQT0HoLSGjOEztMUPJPBKkaOSgEq5zf4H
	a6uq9MZwhuzz6SYGh/NkjNY=
X-Google-Smtp-Source: AGHT+IFGmTPXc/xbYoY4QQiyBpQMO9bHi3a//uMOmWXNcFZdirdEBA5uUrPe2S4TsgZpL0HhgT+7Mg==
X-Received: by 2002:a17:90b:3903:b0:27d:5a25:98aa with SMTP id ob3-20020a17090b390300b0027d5a2598aamr647468pjb.0.1700604378585;
        Tue, 21 Nov 2023 14:06:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:180a:b0:280:859:c153 with SMTP id
 lw10-20020a17090b180a00b002800859c153ls3821897pjb.1.-pod-prod-04-us; Tue, 21
 Nov 2023 14:06:17 -0800 (PST)
X-Received: by 2002:a05:6a20:3d8f:b0:18b:37b4:e4e7 with SMTP id s15-20020a056a203d8f00b0018b37b4e4e7mr213660pzi.39.1700604377552;
        Tue, 21 Nov 2023 14:06:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604377; cv=none;
        d=google.com; s=arc-20160816;
        b=z1pNZTJaevHFd//cqQZQpawcz4mRXmIaVASC1V4vIb705pMZLG7Rrf7+1zVS3dc/d+
         fNWk2XAsgJC7kCKRi/0wjPSnEvUZWv26sAjL+DKY5Vve3PxFbULf6bDIPENCkSOJ09CG
         wnM4PDe+8nEdYefu+VIIWf2VaqSq57kINMNieSqWPNYzdAgeS2RkWm5x1aR5ZqKe8UrP
         uuzB8SVQJX+o5OVyTHXfvrGHuUX2vImKzIbMODLGELwZV9gqk/nU3rpePcYMJRrTTzq4
         1jP6PPv3LGdjNpx4F/CJZud73RDQyBV06KDStpNHAve8VSnl0mvNapNcqKqfdrpjvHBq
         NnPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w3qU2hLQPViAb6IauvgW6Gr8yASYdUVClk+0doiSRWs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=cWgf8pNWg+cwmxAJ20OBEPCnoArjhnfgOQtWBQ/xaSskmzAzwNfMcExgyMPuhT1SHc
         XttJbb6FH92oIneexypAAH1d4cfc2LmX/n+JSlH3v2u/Qvr8L3qPUIyk7J2RTMRrWghZ
         gRmDYYk/P9YkzhUw4adAHG4ExEzVEg6JlHFfPoNZ+afIcfQkV247UWzszFaqUZ8n7x8m
         CpN9ya7X0v36sR2xg4JV4W67HEHZZRAFaFQVXJDeXHW/F7b1pw/Kh0GriWPpOdMFR8TY
         08EEkE0f1AZZcQQAR119FEwgGCRZeyKAo2MxIVaxiccQl5rqMzjYW+zWehq3I+5Y3EC+
         5F5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SxOEgF2k;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id p10-20020a056a000a0a00b006c99448fdf8si617608pfh.6.2023.11.21.14.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:06:17 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlRZr007601;
	Tue, 21 Nov 2023 22:06:14 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw10s7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:14 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLQnKe012479;
	Tue, 21 Nov 2023 22:06:13 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw10pk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:13 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSib004674;
	Tue, 21 Nov 2023 22:02:31 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvgb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:30 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2Rff17629862
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:28 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CDE9720065;
	Tue, 21 Nov 2023 22:02:27 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 67E6D20063;
	Tue, 21 Nov 2023 22:02:26 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:26 +0000 (GMT)
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
Subject: [PATCH v2 13/33] kmsan: Introduce memset_no_sanitize_memory()
Date: Tue, 21 Nov 2023 23:01:07 +0100
Message-ID: <20231121220155.1217090-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: AjHKs9P_s-EjY6PEk-BnWe3k9pw_FvZj
X-Proofpoint-ORIG-GUID: P-jmXZ89sI19Qp3IwQq4whgKQV4vNRwT
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=799
 spamscore=0 suspectscore=0 phishscore=0 priorityscore=1501 malwarescore=0
 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SxOEgF2k;       spf=pass (google.com:
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

Add a wrapper for memset() that prevents unpoisoning. This is useful
for filling memory allocator redzones.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index ff8fd95733fa..439df72c8dc6 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -345,4 +345,13 @@ static inline void *kmsan_get_metadata(void *addr, bool is_origin)
 
 #endif
 
+/**
+ * memset_no_sanitize_memory() - memset() without the KMSAN instrumentation.
+ */
+__no_sanitize_memory
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif /* _LINUX_KMSAN_H */
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-14-iii%40linux.ibm.com.
