Return-Path: <kasan-dev+bncBCM3H26GVIOBBVMR2OZQMGQEH5QR5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DAB0911759
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:03 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-6e82b36467esf1618604a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929621; cv=pass;
        d=google.com; s=arc-20160816;
        b=PVEzZbzlqtN5TkNLsR3zHV17SQ7FaDHGpaO4TMl/RlTI2+RfiYIbvK3C5eAsatpLH0
         lJXQKsXwnT2Z6vKxefwryLiAjtG+a0/KyfVQGXTIk0yaf4QUeW2/6xGwpJejW4FUqt9d
         EGbpdiRG9rRcWgEVXGxK1YvhPoSJtRSJVWLTkrRzpuTY6vTUuWIvhAFlI0k9h7pUhtJZ
         tgrrLScC7qZNhUicdMpLFHjYxIMaPNFQn/pitAkJ1Nurz4O0AhTp6rhKlqsJIIbsAUu6
         69f+uEBgaGXbm/dlOvHILAhEXqTCEO7R11tEkNpFLAtRJfn0vuGK1afUGmP9EfZ88RYq
         Ox5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZEerb0aR6ZMGD2ypJAJ0AdcN/me9+pp5sMx4S10MW4U=;
        fh=7rcjgOPEKxQSnwGwxP+ZBHIWvKPNMbtzYiB5imLBW1U=;
        b=gXzguiFckc30897v3NrW0iMGK6CTnlS0XRFqRdZySNcZrOkSX0TEhMxzuY8cw/Xj69
         TTNIn7D+u6o8lHFGAb5E7R9nz+AC+ML43euWT2Xg5jrLqkMl1lnHd3Zddk8S9c/zPRin
         bI4AhKjXXO1CUXL4wS5ytDH5+8hlydQvorlA9nrD5N9eTw9mvD8ifKAmwzqQmppkF5iW
         FNz82cboTKUtKe8DmcNneBQ82xnj1J8V+FEz39giOA0smgrGUisCi/AjFMnsRZVwA7ni
         nljLIRX5xewv5VM6NqE8TDqf/fy6x1FLMLip0azjXcX6Qm8Q9IuxqaiRWIuIujjhzScI
         qfkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AuMzDTLy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929621; x=1719534421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZEerb0aR6ZMGD2ypJAJ0AdcN/me9+pp5sMx4S10MW4U=;
        b=pKQcYjYrHlzSztwC6NU5yODN89++9zpbw2PojL/AUaCyVwnmw74S6aZXLmFdy//erE
         JMl4v46t+/fV/xw3VUVIAMbHDwd4D7/oDmHjionJpi2QrSjsVWGe5KV6S9cwMAv2YYr+
         Qj5cJrDzpmZvuBpdAiRZ0+3kudXCJP9i2ISVm5L6yARLE3p+e39D0cwnLFQ+Z7TQ1yPo
         aYtmtBA5e1bZa5y5QPxNdqUMzxNoAJZV5PjGyD1nAVyxo/uq9djVe3lBayA38Yf8Bzvn
         LRQS8ZYbPhE1y6V5mM1rTohCFcQFjl8cPZ8qeRNA1l+Qx/hKsUkdWJNl6ko8AxcmNVeZ
         VPXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929621; x=1719534421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZEerb0aR6ZMGD2ypJAJ0AdcN/me9+pp5sMx4S10MW4U=;
        b=gUAR60j+0apcfsiFPV/pNvoSuLrqwJZkvdH1acECvS9WPRCh6ZPTOx9LWhWZDavbkg
         EEgDCV78mlaJeMcyq8LLBQQ4zRXOXBliPH6VhtvY1ymXmVBXxGN40EmxTGrTINIrdIub
         Y+qepdYLzXmY4/rgMm3IV9ZLOExpaGJNEJfBZD7bi/mImHx352zrxeVjLCaut66siVET
         GGn8Ynyd92q+mlXq50YortZRdNTk4ws5nfAP7i/7AfBJuDKgBEMkoGSDBsG6J0jHG1Ae
         sFsSK+RNvHq02fokqvE4IPZYxFcIwLZDVRlRUEpOfQGkFQXSZGWI1mbfHEP1oHqLSoRf
         Q/4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5tiyKf0BreV14E8vGvvhKkjUJNFBhygNW15BeFN4Ym7BWGGabowvIIpHZQZFxSbkVo2rl+za/nop4JS5qCZiZRnxxbMluZA==
X-Gm-Message-State: AOJu0YyPvPUkyoOgK3sXO7ynFgjiyxYh9rXkAIMaymmAJE31g1jYmB1N
	BQz1upFOnEh5khClmCSwoJw/GBxXXDyhyBv2eBEX3DKXINFRcSMF
X-Google-Smtp-Source: AGHT+IFLbWlGhMjD9DMjjeIMY6jMvBiLlekv9fQDVmqClyuuOWOzHwpgxUKqs60eVvRIvn3jHIJwMg==
X-Received: by 2002:a17:903:22c3:b0:1f9:edf6:d7a5 with SMTP id d9443c01a7336-1f9edf6d941mr3286445ad.1.1718929621270;
        Thu, 20 Jun 2024 17:27:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d48c:b0:1f8:5506:d3e1 with SMTP id
 d9443c01a7336-1f9c513f455ls11634325ad.2.-pod-prod-07-us; Thu, 20 Jun 2024
 17:27:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQil2o8EvIxebTQBNVu6TKxCbMS5CJkvruSEMcwHesWz0wrTc2y3vScGbBqW4H7JQlwwlUD46nzbUA2qoyrT4JgonSqE0lpLeWuw==
X-Received: by 2002:a17:902:e54c:b0:1f9:9691:7b9d with SMTP id d9443c01a7336-1f9aa3ed80bmr77643065ad.11.1718929620035;
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929620; cv=none;
        d=google.com; s=arc-20160816;
        b=nOeU0i0HzlYLICsxKD/KAiKcAIBAKbFOh61hPe8fUGY9L2XnXTKd4xl86x99IHGpMN
         tiERk7M7IJQv2Fx7RIfo04Gb4EcMTP2o0DKs87SnvVGC9sBim4hTYIjnPVkYtGK8bPAK
         mIQwZbau8i20/B10VpoWMauoStWHOCcT038t6gbRYq1Ym367Z0rH9VXPEx9UBfUjVKNK
         wmaKyN+aILnSuD5qP1qcDlxLUwAbp5jjV7/AxOn32O7OdjFv0n/guNeEp/5Iosmkh98Q
         MH+qDuvoyG7qzkIL7MQMmIWCCdAKcYXlgM/WBweGXXeOh1XJggjrO4fspzEuOgo52s5i
         SGQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kU/N+IjLjtGivjpGyVY04YO0GR9T1vNZaCjuWWP4qac=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zKz1EVF8qjGnhB0xvxaWlfIw43+4Qbm99Grxkdp2fgYIqJpFqlwCaFHWEg6klBiYPr
         dmK/ylboc6X7GkuZN5WmCcLrIzjfrPM+Ztt/YoYh/WFnKyHfRJy/yAOGe/R8jK7TfKj8
         Hlxs7myXgfaGpompV9rWmfNprjTb6YjEvjochxl39A3RSxmumtON2gGmVI/WozhudVxo
         DfidtDp0yAzGM03iQVkYSOwD/joVLjGea3QgBQ5BzQBz3SVVGQBYeedgrP05vktfssKx
         l3OAcK+WosqN/YjMh9xbzk0DP39xXE0ChAP5bFMZ4z5mq4qrD9yCR4mRQVou26njDHdI
         ownw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AuMzDTLy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3299f4si147145ad.7.2024.06.20.17.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0NBTm016908;
	Fri, 21 Jun 2024 00:26:29 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06yh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QSYE022603;
	Fri, 21 Jun 2024 00:26:28 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06yd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:28 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0QFe0031032;
	Fri, 21 Jun 2024 00:26:27 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn0g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:26 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QLRu22872500
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:23 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3689720043;
	Fri, 21 Jun 2024 00:26:21 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 148152004D;
	Fri, 21 Jun 2024 00:26:20 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:20 +0000 (GMT)
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
Subject: [PATCH v6 01/39] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Fri, 21 Jun 2024 02:24:35 +0200
Message-ID: <20240621002616.40684-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: McwRRv8ORq2jBJVljLDOsf_BLReXo35e
X-Proofpoint-GUID: w7z3E2lMoDfykspBMgYgM_bl-_IrxL0i
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=AuMzDTLy;       spf=pass (google.com:
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame. Poisoning stack frames before returns [1]
makes the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 65208d3b5ed9..c35ad4362d71 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-2-iii%40linux.ibm.com.
