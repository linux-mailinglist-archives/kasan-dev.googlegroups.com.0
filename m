Return-Path: <kasan-dev+bncBCM3H26GVIOBBTNFVSZQMGQEHUOMN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D8E3C9076E7
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:58 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-705c5d99980sf903154b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293197; cv=pass;
        d=google.com; s=arc-20160816;
        b=CF7FptR7GAoUtlRn5uWxh173OYvNTPiOXoyvVQE7Vr/Ed1TDJs2sF/fn28MXYHdIkw
         z2uy8pHGIgCuBoqQXkd1ZOvVL3XMXyQj2F+s/3wU15lLGygQ4OFrnawzSXDJUS18H2SS
         ylSHrTWrGmq5DQ8amdWaV5ClVbAUZsbnvlt1NeIzwynn5tZR5kHFziBqxn/72rVBBiAy
         bNW0bYFcwYFZh1e2h91FD8qhTYZGs9WAX0EGbLVpwtG9Nva7MGlhxrLajDqaOJbHtPKa
         zN/gdECiTj3wZnsEGeLcRc31uvjkOvOQEyfdTZOhpOu8cPRi2qBIjK4OX7r5HDsTWBoJ
         0yHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QVbnoHL4ptbCb00+3dki9ApiLColq0xUgFMsesTL6j4=;
        fh=weaVmPYMH3+sOudBuDpK3p0zkJYuE7DV9CYM9hUR49g=;
        b=t1+N1KzgJvjkgliAfZkYpyXuJIuJ3yVoQlPL0TlZrHuNtmvDtxZECkB5uyaQ2U9kxJ
         Tyazt+3/cq1jyBS7UywDtfoquuS35KfyJxZLkdV/z1uOy43C6L/BdC9q78BgNaL3xQoJ
         pT0bvMJ6Y7eO7ODyUvQ7h3rxXPUfZ6yaXJRew7Vk9p11fDBV2SNySOj8fls4WZugW99t
         QmcFw2O0aFjE2pCmnx8jeVNhEDP2OUv9iV5H9SwHyDs27FriY8ND6SjPH7hKnt8fj1NM
         PW6HJR070HDjj3N9LdUPE6n9hVtvK0I848qgXYo6dfjL+ruTx4xN7TZaqL9FnwjZmDvv
         dS8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VHXN9WfP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293197; x=1718897997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QVbnoHL4ptbCb00+3dki9ApiLColq0xUgFMsesTL6j4=;
        b=P3MmBRv7v4h0wRm3Ayi9cXkAC1bGLBBjWR6bHEUTZL+B/9SkOGGkRjnmSOltPPgFIi
         pVQt7WT/9nm9gaf40Vwcw5zhehD90jJrgJlg/JWZ/MPdxGcohK0KjU7+R7sG7pggxoQL
         J0LUKqWBwia5uOJV/D3pbLqQyA/nctrhqQ0o4HDv88Ph+PGSEdWXvKboZfA94yyBtnJE
         iVzR2Z7ouQCqcm3Os4Ud9TiXPps50e5uNj1eNyTnCRRPBjHPYTot877A7L9Z/Ph2Do2Y
         6eq9nj/wMY4fU9V97y1jfkfO0o4/KqvxVqJ+zXosfHwRAPkavk0S8lkp7Dc660jvxoRg
         NLuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293197; x=1718897997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QVbnoHL4ptbCb00+3dki9ApiLColq0xUgFMsesTL6j4=;
        b=Crh7yZLEd77hhzFmXbbdsTCrRYljfEfR56FB4/bC1g5R6WZRXyVRDYf29w0Cl+UJlh
         YHwVEj1QbdZP8CrIhlWNsJZ6m06UJFEOcpC62Smf/eZtBXkNduuOBylVo8/PZ1kWAYGV
         c/3Ta6/9MfaSWRl1qJH0updwhpx9kNgsqJhf50OHlo8hsnLiHObtDEZBXutvipdILN/P
         5fda5adLFY5kcogiypNHdD7+wWFzGwHpDEVT3hmobZ7ACP9MLFHhsDu+9r7fU9UvsXgb
         07wFTfy3Lxn7JMMqpqQaknvZHt+S+qz9qQlsbjPqFCN66JYuH8RnFm28nNqDmD0RoMg9
         BDcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXqDRI9i2xnoJU64woOLNnR6EVCaC2qn9IecvOkoe0iqA3UmfIh4Z0UUMIahC3VYEJ+aZfUytkFjunl374Oy4aNApgnpFyQlA==
X-Gm-Message-State: AOJu0Yy2PvJbqQJASKHnNHGs4lD572zb8m4OA+b7ybckXJOov2FWYsue
	JgaJ0nh17ocg5HBJRU7HTKPu94qf6zfd4aouiC0j2qDxqLM4MwCu
X-Google-Smtp-Source: AGHT+IGNz9NfqFjZSC18v3pSSZBH1XwKZvo3vS4f/XUFUwCC7xwyBQmmE3zx4vme0xKtRVsDbVUr6w==
X-Received: by 2002:a05:6a21:626:b0:1b2:2ed2:b80a with SMTP id adf61e73a8af0-1bae82ca222mr180797637.61.1718293197460;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:408d:b0:2c3:10d9:f2bf with SMTP id
 98e67ed59e1d1-2c4bde9785dls708891a91.1.-pod-prod-06-us; Thu, 13 Jun 2024
 08:39:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQi285tlME5+LniPHCCkf0I0ET5Km3QVAppR6l1BGATZP5zSr5aDwU1k5v47VxQSVgbj3LA0GQhQ5bH0+0+OyUp03IAiOtiKtILw==
X-Received: by 2002:a17:90a:5408:b0:2c2:c79f:976a with SMTP id 98e67ed59e1d1-2c4dbd44096mr100683a91.32.1718293196264;
        Thu, 13 Jun 2024 08:39:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293196; cv=none;
        d=google.com; s=arc-20160816;
        b=SN1lXFo+qVwj8QW3eswegOOPkgk1CTNt0J6Vfb3y61/T7Y8V5MIxiQJsbupv98WD3H
         /GHG2wRs1HsuSt4wjz1jdvMz8WP+xbvMKtfTUaE2wbLM8aUfRN61qnRdNfrLRnUhdZ6B
         7vrO/5rIazKXOeY8zy8p1KPIB1hGJ412cKvywqgPTJISaDK5SawpM1yi7KHPym0ExbBh
         HSHUlmcAwkb2SgePq16xPGhefNnE+qqkYOy1zE7PAKTgi8RaC+jUZVKNVoIS6OEWqvNL
         IoYQKSWawajA/iovadKkNanv87MN8dO/+Krb2obWSxZyMOI+M3rCPT9rrWBB0XKfVIB3
         MUUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EM2Q29X1oynbiWdgAiIUaE04pJnjihVfcXc099lsq1w=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=efNKy2CZAf7PF0EyoiRlzKCMTpGMUfUBnTOZkOUBT9iS0uy7ESX1tOs5pZLcIJDGav
         A1EinKNCs+fbINEoN0+IRb/2hcPBKly79PgyQSw081t0MzdzLJ3/6ne2PvQpqKCmZhxP
         oFaZY9g3gPHjPJRS9Ts/cIhEKIQJagC8YmbMXiXTGaXvOyg1wWSRmVmQqRtck/7xuoQ7
         N6RzhcmddC/eVtZea3ixU33r26OPnclE4x1L0nmKPYCo8nmgmAxZxIPZtpM5E2emFVNc
         4DpRGbc27jeK4JX8Xs56mZPJNMFPYm33HgEkV2l7DkvxL1lJJ0vFDhc9FX+m+jWTSoey
         MHCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VHXN9WfP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4a61d3219si396246a91.1.2024.06.13.08.39.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFCHUA026549;
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgdet-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:52 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdp23014395;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgden-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF7EKI020041;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0cj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:50 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdiU951511650
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7916E2006C;
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 067C320065;
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
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
Subject: [PATCH v4 21/35] s390: Use a larger stack for KMSAN
Date: Thu, 13 Jun 2024 17:34:23 +0200
Message-ID: <20240613153924.961511-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: lFkUDj6LN0n_-DjPlPRJL1teLrWTofxF
X-Proofpoint-GUID: TOtbwEEWWHXcQFHvMIb0mi7O7rB8fdB8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 clxscore=1015 bulkscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 mlxlogscore=869
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=VHXN9WfP;       spf=pass (google.com:
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

Adjust the stack size for the KMSAN-enabled kernel like it was done
for the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double
the stack size"). Both tools have similar requirements.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Makefile                  | 2 +-
 arch/s390/include/asm/thread_info.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/s390/Makefile b/arch/s390/Makefile
index f2b21c7a70ef..7fd57398221e 100644
--- a/arch/s390/Makefile
+++ b/arch/s390/Makefile
@@ -36,7 +36,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_DEBUG_INFO_DWARF4), $(call cc-option
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
diff --git a/arch/s390/include/asm/thread_info.h b/arch/s390/include/asm/thread_info.h
index a674c7d25da5..d02a709717b8 100644
--- a/arch/s390/include/asm/thread_info.h
+++ b/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-22-iii%40linux.ibm.com.
