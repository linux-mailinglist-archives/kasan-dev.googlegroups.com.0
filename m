Return-Path: <kasan-dev+bncBCM3H26GVIOBB3OW2SVAMGQECMECFKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id DD70E7ED22C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:54 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-28032570a00sf13039a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080493; cv=pass;
        d=google.com; s=arc-20160816;
        b=OnBURoMJAk4jkAKxFOqCV7Fv8ZmtexKGNsj5DVoy69O9CfgYdI8n9sU4kvI9/uHDZA
         VkvU9iej0RIUrpg90SftmGilHpRk1uJwHDSntRPPCHD4PXkkprd6LOejZV9727quuDyG
         M/UR9IrUOscomViZiGrh62RcC1gVYJYglbaQ5L+UBCq2LVWg5akGXPvqASCi0iFk0cMS
         YbGCVtEomUuxB6rEIYxHAfTIxm7BiCO2Sorxsb5Iv61+eqqVT/DBb5kvQ70JBWjfJy9W
         ji62rLd55QbP5JyexJKQ0M0i5C+xAYSOH/LyZSu/XT5CZTRavCp6J8VhPRagkwyZJzOI
         cFMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yWTd3Wgyj5tN4JmZxWW2JqYTwNgmYxdlNb+qgfYFoFI=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=jyvOi3SYQRclmdxc6J8OY1C3jHKXQo3MpnneOFmzyxVWjUz5EdHBUwgZIMQ4pIN7Du
         wSaDR4pjWGUT8ZXQxFMIMUg8e+acnV0zyqQX5YouGr6ZGlMgYz+xTUD8h9zNFtZy1gmt
         +VfhMQ85u45WlV5KZ4APfrgBzxBc5pAgEQxjv6/EPDvJW8E+4OI9eWARCzafEQyhO46K
         nBxZN2+LolA5n4IMDlRcuGAGmQ6MF1v7OF2o/xBtNJmITQ5SqkgIcaWazg9s5QJ1PQHA
         utKV1nCzM+Fv78cw+5SN7uLk26mNDyJ5W6vZ9g0mbBd/aqSD9hvIQ5MNRMk+gyf1f5ad
         6Xfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BBqatkro;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080493; x=1700685293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yWTd3Wgyj5tN4JmZxWW2JqYTwNgmYxdlNb+qgfYFoFI=;
        b=vQiMHwL2OFJPp6CVk76HvPDgi4XSF/kxkP3kXW3KFvQkgsDsEm7CtubCwwETFzf3qQ
         YFQ+4hIrrdhLwxW0BtBJwhP5f6HSeBOnLnpQXKWwN1vmF0UNRE5HtUdI9PZHsLw5ocT4
         G6nE6h0LOmu2CtX8WTJBoPZe6xdLAHDMTrB8vzhjgAQOmp8EjqqEIpI+Ah80BWQKN1P9
         Dw19DwkjAI+XKAwQ6aA4xw6qvSrC4/bacJxiiEAtrM2sBUPVTzHgVWhynydxVpDeJVgY
         xYkNLBzXHaLUPLHHbg2IerSVSpm42CutnQc0PVSKgOSDEpfecWureLag7U4CmmuwFtYy
         Pv/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080493; x=1700685293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yWTd3Wgyj5tN4JmZxWW2JqYTwNgmYxdlNb+qgfYFoFI=;
        b=Krr6/4l+bvVAJ/tVnmOStl3WgR/ywec+WtVbKRyIeRppgYx+vyJcYOHwteSVrzTlFe
         8UAIf0yXnlbzFJf8pWLTNhTQWMzDmNtYfBnaWbun42jPAF4++tKToZJBXi5FFlIwPg5b
         E9LY+e5V1k/Sj/6up2tIpThrZfn0QWFTfFyqxV3HIjjHS9ckrkpQmKAXgAKk393WwTvI
         75VyEurk1WCrUBvSZAMS48S8EdLfVBJz2m/cr/+RVIJ57cxu905lyQGwTEa6fbNnxEQ2
         D5w24Wh4J5Jb+sr8rSdc6bcaQTRWLb1v3HwA7g+00aV/T167xIoeahBTmfq1JAdoN0UR
         FrSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzKPuSWIlOnl+4dqz3oT5Kn8VDC+MgNFXTrL5YxzDKlBJDWNBFI
	uNTz/gMR46c5RQHX0cQn0Xs=
X-Google-Smtp-Source: AGHT+IGPzIPKIqPLOK9UMoZV0aGYtLrYevWz5JxElZSCHMD+/xkQ9sF2JBs862anuzk6LtMsf2L3uA==
X-Received: by 2002:a17:90b:4aca:b0:27e:3ae3:eae0 with SMTP id mh10-20020a17090b4aca00b0027e3ae3eae0mr12264160pjb.16.1700080493374;
        Wed, 15 Nov 2023 12:34:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9f03:b0:281:5c6:7235 with SMTP id
 n3-20020a17090a9f0300b0028105c67235ls146712pjp.0.-pod-prod-01-us; Wed, 15 Nov
 2023 12:34:52 -0800 (PST)
X-Received: by 2002:a17:90b:4b02:b0:27d:2109:6279 with SMTP id lx2-20020a17090b4b0200b0027d21096279mr12056841pjb.12.1700080492494;
        Wed, 15 Nov 2023 12:34:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080492; cv=none;
        d=google.com; s=arc-20160816;
        b=nLXZlTbmFKBW2CrJBN3cMM5Uw3dWohMF1snwypOmVAyKqk1odTGVLbKpMcmvOlZF7a
         on9O5qV4CJtub66OyVzgerGJ2AzGpnkZpKLc2WW+5/w4QUdGRyoLkfjPovkbGOkqXScR
         zJDUGe17t2lMRBsD5uwHOvnxrdyv4EGFbrk8R/X5opXxT5ekVfXb9BPwfQFY88z+wdBe
         qsVBC+MPoYxtweOly6CUom7rlj2wymAZi0ojQqmPEZ1EI5lxyXcCrIH6c81M8ePKHg8r
         Ao0waf5A3QeECWUO2ajW+XWEBhq6ENDp12HQUQsdsjsnorj3G9lB4dHBJIMOTUQ3s0St
         l1Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=P1cjC4XvfBd1ePaZbVyG74nHU4A0jWJVPPxmf/C+hLA=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=JaI2M4oyy6AI49O7GYPO8yvaAGbnwe8oLurPC40GTlf1uLETGjy/XdismGN4WU3sNq
         AGL3YgMpW+KJF8xxBVdYjNONRlFtuieCO6XN7A4EEEChnSDyHXwli/XKlaobYqxOXWFf
         Def1JvwTm1VUCSevAO+UlxQY73TyIxdwSj44Ulqsxlr6laZlYnmsidVJgwqtQVXSmoGu
         avmNqvH98qBVAlj7kadOFypPTW4cPDIQqe8SMr2mMOrfDK3cClNFd2EGWeuwyjCSKUvb
         sK5YaF8ml+MCEDNf47aJ5xoVFmwGkpasWWezIcOCFXkuA8Kt50vVmVsaqqHU8dEhFhqi
         GPUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BBqatkro;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id sh13-20020a17090b524d00b0027d3a858456si41729pjb.2.2023.11.15.12.34.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:52 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFduJ016274;
	Wed, 15 Nov 2023 20:34:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb9b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:49 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKXlFH002863;
	Wed, 15 Nov 2023 20:34:48 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb93-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:48 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKItQs021588;
	Wed, 15 Nov 2023 20:34:47 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uap5k9kce-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:47 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYi6N22348502
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:44 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 984B020043;
	Wed, 15 Nov 2023 20:34:44 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4D66C20040;
	Wed, 15 Nov 2023 20:34:43 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:43 +0000 (GMT)
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
Subject: [PATCH 21/32] s390: Use a larger stack for KMSAN
Date: Wed, 15 Nov 2023 21:30:53 +0100
Message-ID: <20231115203401.2495875-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: HoxbfhrfP30Lz0w1WSeNKxPtFqv8h67h
X-Proofpoint-GUID: EtmFvFe8X0_C13hfBo5WWBLzEHggaJhJ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 mlxscore=0 clxscore=1015 adultscore=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 mlxlogscore=905 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BBqatkro;       spf=pass (google.com:
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
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Makefile                  | 2 +-
 arch/s390/include/asm/thread_info.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/s390/Makefile b/arch/s390/Makefile
index 73873e451686..a7f5386d25ad 100644
--- a/arch/s390/Makefile
+++ b/arch/s390/Makefile
@@ -34,7 +34,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_DEBUG_INFO_DWARF4), $(call cc-option
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-22-iii%40linux.ibm.com.
