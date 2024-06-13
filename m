Return-Path: <kasan-dev+bncBCM3H26GVIOBBVVFVSZQMGQEJZWXJ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 78FD79076F6
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:08 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-24c487df201sf793249fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293207; cv=pass;
        d=google.com; s=arc-20160816;
        b=bNNb+LiWAKITszs/0llnlTlwJnKeMmMONcmrgi3PM2OLNcQJnw3EibXASrrx3Wwfkd
         i2qkrMUtta/NEJnBetIM3qNTbI92W72BHWrrsFwXaPGWgBMr70jaZQOULxFFuR84MOik
         yCApE18nvGpZ2QwFGqD8ac726/VkfFUdm2ZBO5XtwTJdezjL2lrQF+N15cUlYf7+Aiek
         oT8KuibAJzFzuUT0CblcAvJYcSD/An+6YYR+zoDcoswBPMqK7OqBh4bUh3dXM4VABETW
         PMpDvu73JTjN+OooEonu1FYBNQ0zFRe62ieOugKWJ+7nLu9SO9uLK5fLfYw5gdBwNBmN
         9hIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gaUqOSwgqQaKLuWhJvvc3Z2PZ5+mEhU3SgDTh29oiuo=;
        fh=e4eXYQ0Lr7pocsoavhSx62vuh8FMSavoO55a2GA4jUM=;
        b=vZ7qDYjyhDJ/QNGtkpzQh8SLKRatqmXE7mWwZ5uTG2AnHt3tFI5tVuctS+iF0H8tzJ
         t1OO8hvDZPtaCz7+f28w/Hn/opQwwbxZUABPTfsUSgveiJlqWhK3xRae1BZMTsnpVyuq
         aP6UG/XFQjihU++YHciQvI54wWmWwUG7k8dfHFQRiDVTT1nnuQj5QzvP5ZEciqLs+v4E
         TX2OE2yBlIkZSEtHoIErS6zKPXyRoFarw8LJFy28M8dQVbguvM0GW+jL1xXAkobNvryf
         qZ2WodqZWRUuXMXlEMY2WawK/yJdrGZGfWU27u7cIv9D69T4Y9TLw0ERL7JDv2CBqgEO
         ansA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RsI2daEi;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293207; x=1718898007; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gaUqOSwgqQaKLuWhJvvc3Z2PZ5+mEhU3SgDTh29oiuo=;
        b=vO8K84qYbvVgfY6TbLDETDXbJWKEh8TzrY3T/5M/aM4lfRqr7P4zKw9TGz2k2ZfQ5e
         DA0LbAfqM40B0sP8A2V3mGQMQ7orxeqFSyqifdNafGENc16vZQSgaSAh/wJw0B/L3XNV
         gJNrYaalD0ZkSRZU9IVjbumCxVcftGj5LAIA6HB2kCQJuUt0EFCjnJ9B+Igqr3+r5TUT
         Z1EJztyLz4LigiOZkqHd38bRj0p2EOosCrv995sMIdOzxu4Y1jKbmQlgwV76mGwIfbgI
         Ajm1ztWqQElU4ln71DbYotZIqvX/ev1m0WQK/YGT5s2mhhWcYga+sLKIn3dTlOdVOiWe
         fWKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293207; x=1718898007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gaUqOSwgqQaKLuWhJvvc3Z2PZ5+mEhU3SgDTh29oiuo=;
        b=FK0T21troflerIirjnUf9xSBhrnflFfwJlz7PyZuZtnWBHaV3sNCFu02c99tiyDeDe
         FCDAIqwlZj1gTn2XVjIW+zpCpNYVhdUgf3FZOcwtRXn0EbwXxFyPRGde90vTW9S8+b5g
         EbC1j/lnnzT3BTseqO3WC+aJtyQf+XfCeWLoOGK+e8Hxi9R5iapqpVKDzZphaYWL0ROG
         AC3TMOLBungnBTbzs/Q3qAZfekANiybgoBw9f8zTxus3q4N6EGjjm+IChrQmTl7cv4kI
         XE4DTig8yg8AqTg9waoULDUEgBAqnbwjWyeN6u5RYeTHxoMyAotuhz3Eu+o9CEY+KXgJ
         TNsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWX/t/T8fLMjsQQDJN2csGqtofiYIdSFdpKSPUsqdtOc+XAHnVcjfU4/N1E9SyOYY2P6eExBQS/8GTYrbZoRZ2ZRM61VZg9hg==
X-Gm-Message-State: AOJu0Yy8DDpMj+gnJPJRDN6W16ASEjUt480hvH2iq/DbO9TWoszzSkmx
	ZFG+GpMRI22XLBAIUhVwbFx3ow6lIgTg0dNIkm3lCaYFP6IGmEbH
X-Google-Smtp-Source: AGHT+IEGXEDn5Uik2tCBDbQzjpWXwv0NcADqgqBC4YjVZfhWXUU6SBJoGwKjbySIfhbpKLZOYKL57A==
X-Received: by 2002:a05:6870:2254:b0:254:ae58:c8e0 with SMTP id 586e51a60fabf-255147b8177mr5694679fac.0.1718293207084;
        Thu, 13 Jun 2024 08:40:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4154:b0:250:b7c8:7fe6 with SMTP id
 586e51a60fabf-2552b685ee1ls1029172fac.0.-pod-prod-06-us; Thu, 13 Jun 2024
 08:40:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVR3cloGdWRpeuf8U3siwBxRp4DVQbuf2907f+v8dQoUHvsdEvN+Buc1R7+gPRSl/xt6LKVa4oeG4JUPk46zkprT7eQ/qQRtvPDQw==
X-Received: by 2002:a05:6808:23d0:b0:3d2:4a4f:c0fe with SMTP id 5614622812f47-3d24a4fccbbmr1432097b6e.7.1718293206098;
        Thu, 13 Jun 2024 08:40:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293206; cv=none;
        d=google.com; s=arc-20160816;
        b=PVn/qUDZ4c2jz/kzVYnqOr3gtj+s1casvQpazdHsCulHzDjmHT3jlSzTe4j/n7WP09
         8dCKSqeI1vPAAoKr1LHrnSOD78LYutD+PbFmYCqhumV17ymdP/rKNwsT03jXkKy80XUu
         okFthMeNVbKgVdt5HMFeaqc02y06ZISO9LsmrLAisnWeFImtcRJnPhJgCMxYX9uop0bN
         /HbVq72yDlHxuiOubModwgGKeX4pZ8Rd0FXb7VPltZEArmvJtsS9hhMR5Z375+G9q6e9
         DzyiyHc04CrQ0Jf5XHY/L0zokJT46ikxVXQTG55K2FE0b9pJvXAl7xJnlspGy9Ng791e
         aNDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7JeBzaeHcq491tpoSsSSp7r/Korv/EUFDTbEVwfZL58=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FegNgPFr3F0FlZKfJwaH5EF+uSm1FAx+lT2cIPdjyjEgNaa2M3QzkmlAq+OSCDd+vk
         NWr941aMxExrXz393nITvSLMb1uWUZf6XMMDEZumczS8nvXE5QQBFwJe9Nn1SsH9r/sW
         M7gpSJi7FVKfXgOGxfOgFYujoydLnrk0wDX0i9MI4MCKicXoCjlZYjC5VoIVIbOgGmyy
         q39oQO2CBqNZMreVCPBGhHChYVAVM0NKq4tjk/ttWB1QCaU1U8jGOyhuDubOc5BG1pD0
         Hk0c7/qU1Xxn/qqNhTfFskqFnLv7Pe6eYKoXWVBCqlKJy1Jk4ES7i9p/BGkSjy/Rc7oR
         RBaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RsI2daEi;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2479698b2si76732b6e.1.2024.06.13.08.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DCR4sF031250;
	Thu, 13 Jun 2024 15:40:02 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:40:01 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFe11d026967;
	Thu, 13 Jun 2024 15:40:01 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:40:01 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF399g003886;
	Thu, 13 Jun 2024 15:39:59 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mq918f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdpLh56754580
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 184A920063;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 99B2E2005A;
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
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
Subject: [PATCH v4 33/35] s390/unwind: Disable KMSAN checks
Date: Thu, 13 Jun 2024 17:34:35 +0200
Message-ID: <20240613153924.961511-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: MBiMewjTh2VDm9je00K5k1pmxCgmdgTt
X-Proofpoint-GUID: cnW0ACph4WoIlEz2MYjl9fcGbGh72JK_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=896 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RsI2daEi;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..cd44be2b6ce8 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-34-iii%40linux.ibm.com.
