Return-Path: <kasan-dev+bncBCM3H26GVIOBBC4A5GVQMGQE2N53A7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 45E378122F5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:45 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-203134a74ebsf2596525fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510604; cv=pass;
        d=google.com; s=arc-20160816;
        b=mCT4f6M8LHJvZbpYJYm8FfdpN6vEySgEagFxFBuiCycZnniNnQX7UQ0XxduRdJWsYu
         wvmsMLeoyyqelfidka8LlZvOFNu4OdVr20DUjpmLBDZfupFC4XvBrZWfgSpccVtHfrfp
         uJbComNX1BqlOwBOFDO/SGCD6Ps+N4mmTPrrJklFvkcM4ZDstQOlsrbuFIdTOxXwi5+9
         XiJBGNZJliDY6wgJVCSXzVPpxKbU8hXmfg51iliwaq7pbpyxJSag5XZho1a80c9k/L12
         yjA00rsHmWHyWgderHXDFvWk921mZ9nTxyuFLtgB7ZZMOdgzUpzMHNAYW+ygOr+4nhjS
         SrZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qLG6+qABPXaUyIiJj20LDwd34Xup+8kMsgjGJ6cSzvY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=XsnD2MxohfP7fcOl78J4eeUAQ6MOlzLs+XkmEBKF6X5GiwXz+BhhuNi0yYQwwbZDK+
         7MT3qgxQF5h2+li6pF+6VncUqlUDqYUxKoNPKQyoJ8qlZFudAW7hSIgpCCUhqWBmMiDs
         F2DmK/D/tdN9GKbgPY1aEhuq1CW6zccWTnTMeFRhOB4aaGR21dqfLyn1+IHTwrfKX0H/
         Z1g83vVwgNqECFmBqAjXHEfwXrmgpaxMDSFYQQSRAWCaOWfAq2Vqj8QRnzE0fyATsrF5
         9WVib6glEN5YO7QLqcLqqw1caNsUCK+jR1YqVnZe3tSBt9WSNlmmbILJVCu7jMJshTvy
         sPmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rQjQFy0w;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510604; x=1703115404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qLG6+qABPXaUyIiJj20LDwd34Xup+8kMsgjGJ6cSzvY=;
        b=udwMTSklxdrlbMJx2c0kZzgC5MUY6D+1xyMZmuyaFvQ21E5lMt+XhqGPshbHPZFLq6
         sMezTj1iH9DixhHFTUcf/oM70v5QH/+4B7xRzLns+nMfnNJNxAtGlkNBacXtAMUyrqbj
         oWeWcHFyGvMl5qJj8RXgthGsMR77UXyCjbkaqkuAa+MLugjpoWfwz4uepZMr22QEBqqg
         oZYjGjjz1sOTsjlL5RATMHH2GjFR+3o6FOKO1gwzSE+4u7kbkUXV3JbhHNmNGIgHPggS
         oYDpZ4Uy/sfi7tmuPnRVBlc5SX6Y1pvp8artNPwimpCA22mfG+c3MYo3pYF6eacRuT68
         OJEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510604; x=1703115404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qLG6+qABPXaUyIiJj20LDwd34Xup+8kMsgjGJ6cSzvY=;
        b=qvvkN0RtsCtfGXTFk0SxCkf+wimABcpwyliDQoSfsWOFT8H8/oKQW59EZo9yZO3O1Q
         Di0j8S27Su0OyJKSndJl+1zUIx/CbXu5McZKoyTtY8ifYBf458sdFMBjY6bymsCGtnJH
         MFY4nFNqzLQJEG1JJiYYeTsNv9/LP0Dp9YNbUhxavsJvHvfCWfR41r1KQ9u3t/0Zs16A
         HQeDVdd/bFGMl2ZknV05BqRWIwHAiX06M607jSGO8oOZux4Z6PnVp6rjiHccMTLjtBn1
         ocg/K0MIA6ZYiJRQMVp/5gkxYxB3hr2nY6EMYJL+euSx+f/79KSTgHzwYaKWBLoxyxpl
         pchw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhlKyBOQRBIKi/ueU7kSzc8SKNS7VBWxvdwR9sBsY3nIUTfVyG
	UE0tpg9mvV5131IAqXUC2M4=
X-Google-Smtp-Source: AGHT+IFP8Jze4w+YWTxp+H7bTBlBEvz/A038z9bAEgvv/jewy6lt1YuzIuesRswl2rHdX7Tn2uOA4g==
X-Received: by 2002:a05:6870:ac06:b0:203:10ab:f237 with SMTP id kw6-20020a056870ac0600b0020310abf237mr2837474oab.33.1702510603892;
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e15:b0:203:3b8e:507a with SMTP id
 mp21-20020a0568700e1500b002033b8e507als525276oab.2.-pod-prod-03-us; Wed, 13
 Dec 2023 15:36:43 -0800 (PST)
X-Received: by 2002:a05:6870:7a1:b0:1fa:f6a3:a346 with SMTP id en33-20020a05687007a100b001faf6a3a346mr8250428oab.53.1702510603112;
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510603; cv=none;
        d=google.com; s=arc-20160816;
        b=WAr0y7n93L5m9gC92WK+ra24P2ZtZ6OiOseCKvKMUsaZgpRew67B2DZFL8WFkV48B4
         aGtJVPqLmDtMj2kHo+uJLskHBpZNuvyBlfd4CYw1g/7mUhxI7vRMcmroso120ze3Xdlg
         Wtt9/YwNxEiPMiMxWd95efQJDUg7t4jFnknXDk2BwKKJMbZ/lpdV2LZ7bL4K/q9B9s4Z
         RW7Fi+zXv2z+8JFd88HxTwSVlL+VTuyd1dGa66LKSLnyXRF6fM6dhIdFhY9lrpOIn0Q1
         VwigSNTtFEwOefa5TIylpMEYdXlOFmxFckydd7eWv8rBZVUe8udndn+kQZrbGT02sV8Q
         F4Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VOrBlHsfakvcZe1XK7OFH4H3N77vpLrrwB2MGspTrGw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=R7ZRjBtZlSkosRMlfFu/nbIY6vgoHK7x/jaYJ+fjLsVBgxX0iYbR3vZtMYuxGS1LrU
         PhPjdQYIz8Z1Xg24HPaVoMsz+1K49BsEPvWB8SbrHJDwlncpSjQkxnW9FIHJaoqD5qBH
         aAWsusraXnqkQfKqamcfamd2nYfobh+j0hI5A0LprIbb/7VMBmyHpimzG2gvPGFu3QnY
         6Vkz/64tlnKrv/McswKG72Un8U5u1rGkHZ9Fd4b6Ue2Xa79CPyE9IeJpeGSyk1ZXsOkd
         qDwXAD6y/zkuhmJ17v7lFe03FHCZb+k8RXM5K2xWcjUYJiwaMcVF3KGuAl/O8KNAnaZj
         SmGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rQjQFy0w;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id hx10-20020a056871530a00b001fb179a3c63si1527798oac.3.2023.12.13.15.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKrAPv021496;
	Wed, 13 Dec 2023 23:36:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uym1sbn7n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:39 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNQea8021795;
	Wed, 13 Dec 2023 23:36:38 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uym1sbn7b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:38 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMk9JC005049;
	Wed, 13 Dec 2023 23:36:37 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skm9wh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:37 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaYD814156344
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:35 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D0AF520043;
	Wed, 13 Dec 2023 23:36:34 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 693A220040;
	Wed, 13 Dec 2023 23:36:33 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:33 +0000 (GMT)
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
Subject: [PATCH v3 16/34] mm: kfence: Disable KMSAN when checking the canary
Date: Thu, 14 Dec 2023 00:24:36 +0100
Message-ID: <20231213233605.661251-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: doTRKEg5slH34q2wsmPW_bB7RNQCjFCQ
X-Proofpoint-GUID: qah957R2REyygwz3vVTu7gxw-sNw3M3-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 spamscore=0
 lowpriorityscore=0 priorityscore=1501 clxscore=1015 mlxlogscore=999
 suspectscore=0 adultscore=0 malwarescore=0 impostorscore=0 phishscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rQjQFy0w;       spf=pass (google.com:
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

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented
and sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only
check_canary() is supposed to ever touch it. Instead, disable KMSAN
checks around canary read accesses.

Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3872528d0963..96138e704c5a 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define CHECK_CANARY_ATTRIBUTES noinline __no_kmsan_checks
+#else
+#define CHECK_CANARY_ATTRIBUTES inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static CHECK_CANARY_ATTRIBUTES bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static CHECK_CANARY_ATTRIBUTES void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-17-iii%40linux.ibm.com.
