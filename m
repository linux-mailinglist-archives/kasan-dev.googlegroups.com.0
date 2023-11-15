Return-Path: <kasan-dev+bncBCM3H26GVIOBB7GW2SVAMGQEDLTO4XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 743107ED23B
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:09 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3594fa6ef2esf111125ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080508; cv=pass;
        d=google.com; s=arc-20160816;
        b=WikQQISQyihCAZ/abnHmrVU04fqV6aAv6pVZ5sohVy8XdbcdqWeJGf23svEViEcen9
         20cFzSRXsJ31Y8aEZfCRz2q858k2oATK+wyTrd1kz70fk2serSgAKBdgRm5w72IUi/aG
         Z4xo9WsQ5MQ9nK5Kdvw10FjPPW2BPkjyRl6zFy6XyMnsPW4/hUKR6RYM5quDgA/4W4wR
         Iweu82Fdxbpsp17aFjH3g5BlLtRQkMlCwce5LKs5Tmabr9UuINPpGrGTvWIQ4/2fv6eV
         3PDM0LB2qq6tP4Oj2zU7EI0tSDnmjQtdk9EOL5dR2FVeijkJ5pQucS+y2ISVEQBPpMkI
         SQSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2T0NBBU35YTcU2f+uNNMSjQnDwBA4dY3LCczQ0jTeCg=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Ios1fVwfej8cVxxfy5UGMEo5mfwxR2p+dlae9fApYYj3bpftODCU8k4Ax6QDcvtNQ2
         AKXnX2lvwUFtq+PRK0P+nsqZKmACsQW7KBNrtFu2XE4a3AR0eDlhg4nSTDCvBqCN9k03
         HqdECHMDRBXmD2vpWQ1JHzt8kAmEwTHEVF/gjlDGV/or018vRVD47gZAKzLha6v+s1O+
         ZPICws8XYmc1yqIMwz4dxVkvu4waUdF6kE2sjPejJKWefJeWXCYBYFcOVcUa+At/AE+t
         TfH6e7MuSOSqd6mo6VV5O1XJBZ15dkpPl9244FOToGz3B155GIgODzMg4nf8vSPiw2tK
         I+Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Cdrh1ziV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080508; x=1700685308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2T0NBBU35YTcU2f+uNNMSjQnDwBA4dY3LCczQ0jTeCg=;
        b=ufuZHCfGRnh0h32ewhL9vCRlDw3xfnJldm6Bk+GHzyUvcw2dzPrrP0drt2hG24csaK
         nRgh3Et1+k4IgmEXZ25z4QDlzx34PXvmQDy5NWWB4sK2RAyAZ0Pvn3ta28+bAs13N5PA
         GlZnP3i52VFTd3QtNsAzeYpdmhF7x3SeV/UV8lExvNZjGbBWp6iyn/kNXgwtfzkRvH1z
         lI3M/IDBuS6iLfGY61oXnVQmoh4Y7rd4KARUnQoRhCEngQMpoPC/pjwBm55108bW8xIq
         VLOS3gRwHyyVBN0/gPJJwWGjl9F4H3awdqMBFbm0K7YBzSGCb491Pxx6xqHBPweRefrv
         5NEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080508; x=1700685308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2T0NBBU35YTcU2f+uNNMSjQnDwBA4dY3LCczQ0jTeCg=;
        b=DojUx0pQezANtyXdO1glpDgJSGoDYhZZbtQVo+lVU22PDlcc96quAOS5nMja3hOCx+
         UNoat8XnmfNsOoYSuC/xMnoVp3s5R8PT8DffAJjncZkLg+3JSQpBwhtTgfpkcejITj/5
         3ktJsF4njtSBMxYPyXuYP/h5oRm+rBXhU7WfcFRUCpllS0FAJUPboYFJKOgFvjIMT+c3
         Qku+Vjr1Hh/4WVGoHmbUPhGadjww8/j0S7+MqfDgJgDYwETo2Y7Wn7b62nfFNArMhnMV
         QmhiaFaGgXw4LWSCi5WpCJRU0MX2OD8kLpwZNdD0IPzGDR4i2f0FmKDoITuTNv2ZMsQd
         9igg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxXbBGQnPuFPfZEtDQkdEmG/GHbI/x+6Ua1IyEoRE2xMllJ+aHK
	MmDQey289tvBMMJ7es7vdmk=
X-Google-Smtp-Source: AGHT+IE7DomzYu4fzlzpRkXVbK9KnJ5yrAW012olUqBaHcfAZflvjYfUuz85d+3FNor/NvWBmGXMag==
X-Received: by 2002:a05:6e02:1a45:b0:349:2d91:e1a2 with SMTP id u5-20020a056e021a4500b003492d91e1a2mr14951ilv.5.1700080508373;
        Wed, 15 Nov 2023 12:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:5ad:b0:349:aa0:9686 with SMTP id
 k13-20020a056e0205ad00b003490aa09686ls60005ils.2.-pod-prod-08-us; Wed, 15 Nov
 2023 12:35:07 -0800 (PST)
X-Received: by 2002:a05:6e02:1bcd:b0:35a:a2d8:e204 with SMTP id x13-20020a056e021bcd00b0035aa2d8e204mr16128593ilv.32.1700080507582;
        Wed, 15 Nov 2023 12:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080507; cv=none;
        d=google.com; s=arc-20160816;
        b=aYiBGPsXUUxWIDW2uFNEx/driLSXwFxVCS/JuGkffA7yt6DuF7Skeu/g6lG9oaXXKo
         HDbnAVzQFk3D5d8DR7wRqXzIhgBi90n3eoHdw79pbliy73SYelrF3khhuEY+/6KfmZ3F
         xCffEwmOPOj/b2mQ6lkkv498PtvQnBAO+Y4aBjJpWo9afkph6jsM9e1qAh+m4V0r9+RO
         bVrHJm76ddtYzyKldUX4DA/1XgOacIfRlZybtVstyk+g7A3KFnpr7STjnBpKOjOB1NOn
         rd7sscqhPB6xnTop0KwfPJuG4tpMeCsdrJh+gx1/i9IZOKwM2ii3O+l5VArxpwcjTvTg
         Fpyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hT5UecKAWHuvfdgWzoNOlmnaeKK0+U2DmyJXTmInAXM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=a3JbL/9NwoNbeAaY8/sQPHvPVRc8hYqs8dyVcB16Vnf7dpSZEZFi8f+/4mA7YfbFtS
         mpm0njSjHrPxgNyNwz67S365raie/obFoUoaH6Fur7mJ/yeR3YM15Oao5VSgRgdizzoL
         2sXGBnUPkhujKGh9arnfqohop9aff35MCpJ6qfNvt+4Q2MKYOzsKSw+40xvNIoikxPy3
         CyHfiVCwsUkGEdd3AEwIrEcxWFDKpeupM9ZCfkgbpE9WrPOuxS7fx7wmYOJPI5gJ4EOA
         hhHAe1Ta+o28cbi8oTO0q6egUhdFL32qxSgPyYaXGQ4EOU5oAMfFCaLwwYJcCI+4QhGd
         inpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Cdrh1ziV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id h27-20020a056e021d9b00b00359d1e22f06si1021414ila.5.2023.11.15.12.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFbK8016175;
	Wed, 15 Nov 2023 20:35:05 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rbf1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:04 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKYHPq004462;
	Wed, 15 Nov 2023 20:35:04 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rbet-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:04 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ36m017548;
	Wed, 15 Nov 2023 20:35:03 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj7fc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:03 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKZ0rK16581344
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:35:00 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1C05B20043;
	Wed, 15 Nov 2023 20:35:00 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C41A720040;
	Wed, 15 Nov 2023 20:34:58 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:58 +0000 (GMT)
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
Subject: [PATCH 30/32] s390/unwind: Disable KMSAN checks
Date: Wed, 15 Nov 2023 21:31:02 +0100
Message-ID: <20231115203401.2495875-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: b1P77HZr7B8FJcQWaHk2afHxOWLhT2Yq
X-Proofpoint-GUID: o4JJc2oTUm0AoYvcRNRv2r_nas_qMHcx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 mlxscore=0 clxscore=1015 adultscore=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 mlxlogscore=769 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Cdrh1ziV;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..7ecaab24783f 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,7 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +119,7 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-31-iii%40linux.ibm.com.
