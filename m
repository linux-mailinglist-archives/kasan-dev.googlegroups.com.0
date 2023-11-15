Return-Path: <kasan-dev+bncBCM3H26GVIOBBZGW2SVAMGQETB57E3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB0B7ED224
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:46 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-5bd26ef66d1sf87648a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080485; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kaw/rJGyB2YSV/nd6he9oLaRNhBRGR7K88V2ncCh6zf+yV3JUWwlo7KK3mTKihocap
         AX39J8MDDSbGnFm4WvQ1LMPEsYzHqq8o1Z9ss2nhDCdfzTtU1Zg6Fb5XXIRHM7hDEUTu
         9DwtXgthv6CYSnWim+aY6A4oEBjSYqnEDxX2oLkAlHglA0pRf8sZ4q+sK/yECMn00nFO
         9uWa3GX718LBNcnPQFHBjJdfBbKM6UoPfvkPCJ5v0ENDbKGQvrPzpuIPp3H2EynK0vel
         mxLCIQpa6bl6uH6cx7kOaVjMLBSN4oXbberIvBOcc+SSaQ157LQD8+c0n3+TNaDySDW4
         9Grw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PazCK+qdFRXxXw8VvwYd9k+d2RRi9a30lCQAmfp7IIM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=tAG3IgEeOwk3tZsYT1MuE7XWUNfQoTeBHfgnTh3YxOQp5aOjmQMIVWHyDgJBZJf030
         YmD73yzfC3Ek5E+Uo5Gxhx8dif6SVxfx+/E+QUmE63q39GP+cCFEWCNNV8f+DsDulJ1P
         F9nDzdGFlpwJppk3V4kNHH2mIpYfwrZLQ8wxBJTWkmQbn0LE63z6L1zywqRtFXvn7nUt
         mAcCGfKYMzlEDa2/eBDBlg174lx/JBxlI7IHFQ6zKRrM+E0MsGrfTKAmYIuN2W9E8J32
         9ved33Xl5Z4j9U0anhLz9Dhx9PX7tgjpv/HQkiIvqzx4ZlZBbXWPwLFN0Nn86paxz7hS
         rRJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=emT9maAc;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080485; x=1700685285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PazCK+qdFRXxXw8VvwYd9k+d2RRi9a30lCQAmfp7IIM=;
        b=ra710TKa6K8dikWEylpIU9Qq5+1jgy7CVP97dTuLuEXsNza7NLoL7OZxvTrnPad1bf
         DIyYUPlKyX7P+71eSF71M5qTTp+Bi/Ik2WSbnShzjkitCgbnhVmXGYU3FWqqyqBFPULY
         A7Lz7DzrDeRqPhf1Z9LJYnKX8BnQj3Xv1IjdPSLrAlPumMPZNxeCWt61+UK8zHAHw/dO
         h/z5g4XVma2Ixalm47Oq75sl2/3GtiDUSmTVAW7jBXif00izz4A9O4xc83AAVKgryzOy
         v1MmufclOI/Xlcuw09nFN9CoDfguk1qjPMBgOijLX++F6W9hBPbV+ch8+vqJDX9+RSun
         4hyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080485; x=1700685285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PazCK+qdFRXxXw8VvwYd9k+d2RRi9a30lCQAmfp7IIM=;
        b=aFWN0ZWYOj8j/vxcl2SXda4cyzbgtbqrogyjqUOcS6fZsOx/YWsTmLmuzdAJDxgAFU
         SFPpYANRF1tHdUIK8ScM58CIRUjBrFM7kupS/D9MywbJjVEhqK9xlqCIV58yQaoUn9HK
         C8z01AgwnfE2Fir0ISGmpkZfNfmSSUiPVjQIgB2GDglW3OdsJZ3s5c59Pxnwj2xPw7Ez
         Q8ziV6uAbC6LxEeDJTHe/NTgKOT0UC0qxa2obX7dF9Y4Yx6iLAR8o/75WJHVMsnmBTMj
         5IfH/wKbJh0ffxvZtrpYJcn3YAufKER40VZqIMLaDM7JNIdrBeG3guQLvdseKtgkTaIA
         f03w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxvwPPky508eTlGFHtMmViZsBiCBkEEDF/RbVKJSUQDUeO0I+ha
	jcDaN+AArFgkz1xmSZ/0Plw8Dw==
X-Google-Smtp-Source: AGHT+IElL45aPLaLcpwQCnvWGrI4cHrHAiZx3F1O/y46Ul1iPiIURIWNGQ3Rfx6tggtuUzWEy5IEgA==
X-Received: by 2002:a17:90b:1d88:b0:280:4829:52d6 with SMTP id pf8-20020a17090b1d8800b00280482952d6mr14008677pjb.29.1700080485062;
        Wed, 15 Nov 2023 12:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:270e:b0:274:60b6:c873 with SMTP id
 px14-20020a17090b270e00b0027460b6c873ls138466pjb.1.-pod-prod-03-us; Wed, 15
 Nov 2023 12:34:44 -0800 (PST)
X-Received: by 2002:a17:90b:3850:b0:280:e2e1:f955 with SMTP id nl16-20020a17090b385000b00280e2e1f955mr14954631pjb.35.1700080484059;
        Wed, 15 Nov 2023 12:34:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080484; cv=none;
        d=google.com; s=arc-20160816;
        b=Rem4wfxWvytStXVLor3zyhBQLgUPJYUblRXV27bvhcXw9rUInyike25DWwuCQC6Pmz
         B25+j6C2Uf3Tn2n6BhVgGr8nM3pqw/rLDGpwJWSRk8QObEwR1rRtabf0ISlpmCKCFuY8
         G4HngjTYDKJazTWXo+q15RmCgEiD1jWKTDSHXD3ViK/x14gGm/z3y7Ulgu9l1coLEJjg
         vmBkkFih+l70eUvvfoPtFkBqnB/VUKzkYYLvJuMIazjjxULftSZDaCorvcM+W16CDI8w
         T1FyfnT4046kfaXFTdiyIElhzNYjTgCmZYmjKwUQsV8w6i/RMYCurGt7NTVI5WQRmiS0
         X63A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CK3CSFhKHiUxb3M2GZk8QRFPFYlA6+i6yOOL0Bh28Bg=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=n6l8OyIfT6yLPNGIH3tqkcU6m8dSYGOXTDYYWeyaZ9skz6wdp60hFH/4wX6Sg/DeOx
         OobE9m12vKxe2QwzsN83WFz302LDPSaOt56orNOkaVrnwbFkjR6Bgmf/IXqh7SPxqLja
         mKKk5jPCrAAZJ0t4n/gQhqYfLWm/I5fW+0rEMZeBjPIVzUU9J+bNZBnWrbK388tsQqJJ
         sCecNGi3ebzUTiNHNT0qQIgkoKKlkmET4iSZkqbdGZCfoORoIwv4M0QpoL4nOLG0z4AM
         K5PlBa4jdpZMpBFh8/q+f8eSgEa4W3oM29NuXm4y5NvZmyBKEqfc8fRKTbnEFAi/EsXD
         1kyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=emT9maAc;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id sh13-20020a17090b524d00b0027d3a858456si41713pjb.2.2023.11.15.12.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:44 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKSANo032237;
	Wed, 15 Nov 2023 20:34:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cv2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:40 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKG6nw003579;
	Wed, 15 Nov 2023 20:34:40 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cur-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:39 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ1FS017525;
	Wed, 15 Nov 2023 20:34:39 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj7ap-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:39 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYaAX24576754
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:36 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 00EC32004E;
	Wed, 15 Nov 2023 20:34:36 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AB2F120040;
	Wed, 15 Nov 2023 20:34:34 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:34 +0000 (GMT)
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
Subject: [PATCH 16/32] mm: kfence: Disable KMSAN when checking the canary
Date: Wed, 15 Nov 2023 21:30:48 +0100
Message-ID: <20231115203401.2495875-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: A7EFZ5gScxsCuOEPrsIMx7XtWnrv7KuJ
X-Proofpoint-ORIG-GUID: bCKwaI7qewBSCpfDoKVTIbT55i3gylk2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 adultscore=0 spamscore=0
 priorityscore=1501 lowpriorityscore=0 phishscore=0 bulkscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=emT9maAc;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3872528d0963..a2ea8e5a1ad9 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -306,7 +306,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 }
 
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+__no_kmsan_checks static inline bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +341,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+__no_kmsan_checks static inline void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-17-iii%40linux.ibm.com.
