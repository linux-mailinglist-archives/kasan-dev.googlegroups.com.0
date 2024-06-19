Return-Path: <kasan-dev+bncBCM3H26GVIOBBL72ZOZQMGQE2QGLCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id D41C690F2A2
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:52 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5ba6394f7c6sf7603045eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811951; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVrNEAnn7p8d4iabhipi62O698B+BX48wsK//tXDRRcDG23KoJurPuYIjtItTgjqzr
         ljefxQtN5K95pMz9aJv5yqbHtyK7qOQIOxdAHXggqOMG6px03hT9hFEUiJovUctxc/LN
         gqT+BwZpWVVcWT1YaUUI7Y3UgD/tBNukGNDeKqskLird1dW1NS6Gw/B2Ce4d38XrEVGA
         KPZY7x15z9byu9nDKvArtxIgh7Kl3JLt2KigMt4pccPWpaxmaP3BwCQ6TMufelFxR8iI
         TNbCTfcE06Lrv1a7C1qtaPGYR6vQsNQBhnJQzCU3koXTok+V9ssQqgLLO7JBk+YW92OK
         jHmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z/P0S7/ZeMRnGemfMDNClpyiFyfVnR4z1Xl9n1xVYo8=;
        fh=qtPhFwbSav1qb7HPXoZSgnhbX940fWXI5XecUlEIzlg=;
        b=rzxMeSE9Fiofz5xCyDOeCB0KOrtR6ablyymzArJt9a/ph6JwJoJu3Uc6Fioh0/E2ps
         nDKERmqkEyUyd9SqyL3n+tAN6oxNSUvygniTVn7ybZlQ5rYZZyNI+R90yG77mEqyX8qZ
         3dJUdkVO+7iOFxidB/aqy1z5lP++en8ZRbcWNSovqHHSOL0E4Wo7nArYKoESAfcsBI0/
         id0YhlmbQ2X4tlG7SQEA/c9yxN1GSmn6Kp67ENrD0dvm95fzOTBisKwSRbdG8JXfuGH+
         /YuBPcdBK4woWF7DLNJUOP0Jeub1GRciJNJlZleTDCNfRRXIz9cw8k860fOxWXKJ/Ucr
         ol/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oaI1BWLm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811951; x=1719416751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z/P0S7/ZeMRnGemfMDNClpyiFyfVnR4z1Xl9n1xVYo8=;
        b=fbIggTNf6dTkht+lLJbLwr5mCLN6R8rMm6lbzYYcggSmBTPgf9JqVeOD4xGz5hWGjr
         UTTsZSbv4anY+Ae/5TAb5BNqewyAm35RCXUcpewZxnlkyJZDzsSS/DbD6wLrrsYz0tc7
         tPXzTj3SGoCteKLObLJ9Fs+zbs9lI0eUgzn8Yz7pBlRm67K2uKNybTAebWkEEt8ZLzeF
         y/Ftjds5aJ+Q4kWT1NzPusBOaW86/+EFCYjMWwEeeemOrjcmomJ9RcMpPFfU1jgElogU
         CtWHmshhr6ccjnvMgGE1Wx2GooiM3CGpxlS5V58+c16txCHBTHHkZig3Z7GLBdlCY6wJ
         SQ+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811951; x=1719416751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z/P0S7/ZeMRnGemfMDNClpyiFyfVnR4z1Xl9n1xVYo8=;
        b=SH1wtnPAVeUqgvrCeYOfludv2I/48NMHqE/nZMpmiHhsEN9wjnh4mgNYDGC1B8cAcm
         EIbtLImVnqvA40OOtZSXvLiTSi8SXzoEKmkuPeyot0PpOWnKwSrqwraGIVSEL2lFKoOg
         znRQhYSajWd8KfrPYejwo5EXj6ICimAVXZ2gZ+dQebpGkP86Gp9MzWnYxPg2yN0wtR7C
         u96wtDqGwTZ/I9cIdEO7ixDy0r2z461yRodCFAYVaZd4d00l60Q8Vzh/kCeWX+7/wRyz
         58Ofx+Ih0nZXP2tBll0pW19m+lAD42GPO1THNzwKwO2cfjdm0iLZsBh+D4PtFZ6ND4kN
         Tvdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrTbvku6CyFQec9JY8ybLmBUPoEZZwiM+etwDBg3tFFNQiXWd7GDLv9JB/M0WYhqc9eeQzxyCTLeELcWp3BEIPxFdGsqMGhQ==
X-Gm-Message-State: AOJu0YxpoL1nCVfF2isXf4ihftYzHPczh4CZwXD2hw/wS9iCwhFvdF6U
	9dPd3k23cnJnSwsNBsOr0Px0stbdt16Z7rcW4JkCGYuhyC7blNc2
X-Google-Smtp-Source: AGHT+IHp59xG/np6N/hjGFZ8aTxn4jPdkZzBr5NxnJpmItZRNk6EUvzc78V8AJDYAY+cYBpkbH/YZQ==
X-Received: by 2002:a4a:3816:0:b0:5ba:ec8b:44ac with SMTP id 006d021491bc7-5c1ad8a17aemr3268973eaf.0.1718811951626;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3508:0:b0:5c1:bd4c:b16b with SMTP id 006d021491bc7-5c1bd4cc986ls301690eaf.1.-pod-prod-04-us;
 Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVS7GoKY65WNKVU5VvN9Lh6XmcOZ6adTkjU9hCw1/5wNUGStT09yIGLD7ItyaLUOayhLUr1i/x+7kHemknoVSI4KL6bWcXm2RuaAw==
X-Received: by 2002:a05:6830:904:b0:6fa:11aa:e929 with SMTP id 46e09a7af769-70073b3544emr3151257a34.11.1718811950900;
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811950; cv=none;
        d=google.com; s=arc-20160816;
        b=aO46qDnJnMqgDh38q0tqcst4EHpJQ/S535ai1B2HdvZNJtH0iZ8rayjLEMm4ySZRGs
         maD0tY98/kldJTWJFCdLGK235p7IWSGohUuH+XGlJdHJP+35VjxkfQX/jdBtElQmeS49
         KMEtYRi8WtBd+oQ4/0mFRAkCfJirPB+2K/lPowEX0/Z1nWGg36nvcgvYW95LTEXThXeF
         MbFIJK8Oh5xO40EW4d/ATfcYu707HGdRoN6RUL2V/yicS8OeQh0U6TpMmC6jxuU5E75J
         Z5QX9W6huJGYS6URY14GAjEV2RoAYi4ZXQU9MpRc9nHrxDP/Wny6ucQJ+o8/QdR2Is8c
         Fgkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MbSV/0QgndyxPpucafkqjoUk93XB7CWZmEyrMAmxEI4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Vqg0XtM8VVx7oY6o6tPjADz8ErqeONwT3ElOykHe5+WOj04YdglW6dpqUyqItoEQGU
         suJ/8jxwuugqxu3tJbt8bCjtS3MYczetFK/T5PbWho5tfRPm1Y6UQEqfkHEYl/mDCMIv
         Jaav7SuH1xykYiNDVonGXnz46jbFXTpJFK2s7NtFsedDsrpom7QKBD17MWxLloRgb1ii
         uTJ/fODSIW4GAAE5PhyzfB8p9duGPbwGdMcbhs8Q2JYPrBXBkpqm6h4tjbwHT1DxTcOE
         SqXq05B1CvV1AqAXQ+VC3kpifuY8WzJ7NuB+vKMnpxXzhOlZwnEPgtnaOSiySBc0G1P0
         Kdlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oaI1BWLm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5afad180si556165a34.1.2024.06.19.08.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JCwmVF011453;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuyt98h3v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjkpC015380;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuyt98h3s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEEYfH011022;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtn1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjdqf33620576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 721292004E;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2345A20067;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
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
Subject: [PATCH v5 16/37] mm: slub: Let KMSAN access metadata
Date: Wed, 19 Jun 2024 17:43:51 +0200
Message-ID: <20240619154530.163232-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: X1A64wlGihlD-vkt6OPN4QbqSNyzZDYi
X-Proofpoint-GUID: QwrJ4a0sDZe-t-98SqnNYovNNBktH9kb
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 phishscore=0
 malwarescore=0 adultscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 lowpriorityscore=0 bulkscore=0 spamscore=0 suspectscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oaI1BWLm;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 1134091abac5..b050e528112c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-17-iii%40linux.ibm.com.
