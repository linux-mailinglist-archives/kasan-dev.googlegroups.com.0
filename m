Return-Path: <kasan-dev+bncBCM3H26GVIOBBMX2ZOZQMGQEA4EU7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C01B90F2AA
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:55 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-375c390cedesf80782285ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811954; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQSsukNH1yz6yjmGNsVfROk0rn/5c6zSt1/RZLkGGCMZV87tgeioobqhBkp1i/LAnL
         7AIxwgYmgePFyFnkhseEbHI/JcPowp/bsbfAthAhMrMxrX60ZKX/X8ixPrzLaghj+Ufb
         YO9y8p+aZJHfyLVnkAOZV6JAI2NGx5CeIo7apGpIOpXHd6nKYgmqy6S38UrhICY9VfvU
         im743CbEZUQld/GP0KDFQIVYu95zP/FDv/laAk/m0J6Cp4KA0VQ4bF+XPD8J3/Mre8zn
         9MxvLojvPq+KD0oX61/o31DBuWTsd+LCzPUulb32N4E8CWyO+N9z5oiPROaUDpzbAVE0
         ub2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QQuMU3atQ93fzv6fzI40S7zZtXOmaviQHNdrNtfP20M=;
        fh=RgmNZQcB7Rs/c4T9JSP4yygKcRp8RlRZv84AT4vCGdc=;
        b=i24DzeNRnOuSsFjx44/rpe05b0TuJEGkR8L51apSQZSJCEkWevf0hA3YBeUfcZs9JS
         07gpD+mh9gStwf63EVp3CLhbohf9XNxuk/ioTwugrKGrc61qIkDkCQsCNDqcZ9Lrtzax
         qEfYr7adTePIEr/CQwYzOtXVP6XuVT33cmvnKeDUmMFUkWvjtfqXFA4O1m3gXaMIeEjn
         axSTkT3oow9vIVWlGpIK282L4uobfYl4ZSID9xlG+FkzbOGpVnYlpTX3m8mvcM9K6+Af
         uEDPsuaMyvSwzD6GD2qkq5sLRRI6sAh4mLnJ0NaiaveJJ+CVmW1X6iKTF2HgmJM+jf9z
         A1zQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cbnds6g0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811954; x=1719416754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QQuMU3atQ93fzv6fzI40S7zZtXOmaviQHNdrNtfP20M=;
        b=fRigsV2Xxx5nqMcjJlfdu9XKEKGAl/3JgBBFN4Q5o8hPJh5FgG/ViQhIva59dFoH6x
         DlnQXfKb3xgfk03kDxl3h7pp0A4lBJLQcZJ536pACNHkfD0Yg8+0ijo6XAL3uhxmLKQH
         FPxIYl3Q6L9dv+UMBnhFwSHhZ1xhjxL0/NsbrWMIeeTbezrnj+OQtgcq/kUDBR2JuEYS
         g9EkVB6L+vqBTUGz+Zl65QAhAPjtwEmrGhPQZq08HAe1xeKCVy5PhqN8HztHGzA7dv4a
         +Xo3DTPHjdpArhDSBv5Czlu0Lgu/d3teDJeNLurKUvDMLGuX2Gt1QpNsIwhwjj0LAQm3
         qbZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811954; x=1719416754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QQuMU3atQ93fzv6fzI40S7zZtXOmaviQHNdrNtfP20M=;
        b=wBUqlC7h11GWdCHnrtXZO0jf9OgtzpyMHvui1ZlKy4x/IhP3OrklUnySe9twUg4dDZ
         Uo/seb65z6BT4xziP0y7MokSpQoBpDcdg3K1Bv0iJnZ88Jon9I8q2vrYrPhJkQVwSp9b
         /z//lF/IelnfJUlQNP8SChdekJimOp4L6wWrEY4XFUxAqcTXdeSFiSqC2XWxr83G9auw
         ZU/2w7f8cpnHlgGMnimKCFQkv9uQXZcc2gHSViY4dCPgbyF/hoRi2GbPIQgNQVt3k/Pk
         Au0fTebNdptEp7AEqbbUsfjs/7jOHOBzjb3BfmmbxCL6CfiJA/hu8f2eoYm7cMel4vuT
         cWbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUg8UbELhNJHO9Wee1WWS5e9SdYH1Fq4rTtJ9ve9tubpeoWix6HoXkv1OAAteu3SHbU+jVOkYZ13ydfnLd82F/2NMCncEz9Hg==
X-Gm-Message-State: AOJu0YwgoBAnNWbGTsECMq5y9y5RnLNKwMEyGVRg1uOkXh4U/vemJtKv
	gUvaTYb5FtVdKPVq0iQfy8lZWFNTGFQ3ZpPGkNhwMN3YNODnQeQG
X-Google-Smtp-Source: AGHT+IF9TkWvrNzFqjWL4SgJaLDifMBx6DMH1thH3e8wEF76iPSuXD7Mv5Vjr+XIO5ASHuLxs3wlDg==
X-Received: by 2002:a05:6e02:1847:b0:375:e1fc:aea2 with SMTP id e9e14a558f8ab-3761d731334mr29723535ab.31.1718811954239;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:746:b0:375:b071:f481 with SMTP id
 e9e14a558f8ab-375d569f5d4ls59045345ab.1.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrtix1tiLua7slpV0TxhLxdE7HZKIqnDiRDcDdh8cM0PUExobxZEitYnzSlxgUizyo5FbvzC/wgxKjbAEXbXBCHFWXU8yCwg4qxw==
X-Received: by 2002:a05:6e02:1d97:b0:375:c4a3:8e2 with SMTP id e9e14a558f8ab-3761d722061mr29442765ab.29.1718811947838;
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811947; cv=none;
        d=google.com; s=arc-20160816;
        b=QOdgbR1GQQtakJZINrCimM1SGlk3cZ6HuvOCBMx7uHSsiD0vQxJWtRvWdvjADJbtAq
         PSbYT1ibBas9WDGZWvQoVhKE4B9vLTKviiGpXsfbAYSHbGUtlc5onU9jLQlTuZpiuZ/y
         cNdetndUdt6dtK+mikV+uzrK+OXDMkND34dmGZaG40G/0iWDBqFtODHK2LsnU2pnIz76
         TCoVp9S/vduihgJRv14jPFdtJwcdwDq+L3K1GIQ8F5JXDWLxGb93Wq7Dkg786LYrJvxP
         Gf1EqbXtYSc+Zu+iR4OaXjLHnedveCe0vlbNEWBkMJF03w73dBjFyygKIYcJulwJgCMf
         J5zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B2wiMcD3tdJRzJi1KnXmn1aGmTaVwcFVLNTdCb0XDUM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=z9XRSNDE5DNWxnYvuVzPKJgICnsrbMqz2Wx7MUDUBv//K7TLY3dbhImiTClMHB518P
         1qTv1KVJvHqh1NCA7CDmmH1IjvaIyNAFNi5+NxdQyA3VyoqIYOf2hM4YMKTVW9rZmnT4
         i3EGF/oU8fK9Fn2qJl9EgNTTs1SrsIToT1OeNgR2KCv77332Ji1/ESaUQFJ/Ia/7b+2w
         eOJn/BMh+BPU2azxBocDAPqAmlI+LSBOSI6nfhrSe4xXpqn6vysjzTmElLxXw4kPdYMR
         9CqyajFe2eCjY9q+w8wMMZH1r7Ru8SZPW8hE/KqFjMZzVzicQtzLh4On6UyoYuZ0NYqf
         sZZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cbnds6g0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-375d832b32csi5390075ab.0.2024.06.19.08.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFTAFT014591;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1g4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjget008987;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1fw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFVbYH006216;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8m2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjZLU51446232
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:37 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 98F332004F;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4765F20065;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
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
Subject: [PATCH v5 05/37] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Wed, 19 Jun 2024 17:43:40 +0200
Message-ID: <20240619154530.163232-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: AgBUb1OI8aHb-BglObXYdINs0O4vxbRc
X-Proofpoint-GUID: 7Zce7bjI7bOtLpUFsyNSLmKGAO4lqyVu
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0 adultscore=0
 phishscore=0 suspectscore=0 mlxlogscore=952 priorityscore=1501 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cbnds6g0;       spf=pass (google.com:
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
userspace overlap. Skip the comparison when this is the case.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-6-iii%40linux.ibm.com.
