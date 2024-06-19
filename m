Return-Path: <kasan-dev+bncBCM3H26GVIOBBMH2ZOZQMGQE2TQ7BSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57BFB90F2A6
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5bdbeeef373sf633929eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=zkH7AbAOLS6DyfR8dZ8tMiQQh8KLwlv7b1wxH9JD9hZhYq53JZRL53fZjwZ/jbu+v/
         MwmFhtN6/T3XZ8k4NRRbnlwhO2RI1p2jzlX6kBvHSaxhW7WLtxeaRa+b5DahfGKcHK+j
         Qt2J51ezptq9sWpaYyrWgI2ffCIM7a1nLKOnfrwoPw6P+f2A0NUR8QaycoO55ucwclWx
         l1Hmzq1/CL/aF2ftRpIlnpUhgOHIhzUsg55jBE7AGJpe4WcVevCChHY9I+CqRfjORkIt
         2rxaB8pcWRnbYowaTsKSOJkFf07gIOBuMgkOqtazbswyRydX1ERqNRvgr6wECLMjwNmu
         C+fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9b+go+/kwicKy3+7u6MeWH8akGn7UdICvIxSVWbOZ2A=;
        fh=dVzpO/emliTRuKg5x+Ouv8HXP44Mci4qr9cyJjZC8k0=;
        b=uCxqtQSPN4F7yOxVl8LVmrqJ4AJAiEFHGmwh3DPdmpPl/yuQVWgaUEmGV8YkOq11wY
         Xt86IT43DALN6nflb3f+GMzgx/6N7CfNOQPXL0R5XPW9GvpROJAA/+l3gL2Rdsr2jkaJ
         Weq8egXH7bLpxVXHPb3QUjZoyHS2P7GvrxnEWaZ8m/pINus0/oBDRBDZwYw2y1aMpLOa
         29m0MDFfp/xsyolsMD3xsM3bRCxJ9gG9e10AGIoyfWMAGidvE45XTtDEFnYCwskNLYcV
         MguPze7zlUOg1h6ot0lCKuKmCtD5r2kBkwEqK/BMUiKI8FrmckLEkyd6DMdvYtQEn7xY
         Rr1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tmoStW2+;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9b+go+/kwicKy3+7u6MeWH8akGn7UdICvIxSVWbOZ2A=;
        b=gv90ObNIKrV3+5za8SrGZJyziZdTmh+0j9WnMRWzg9QTLI/kmhXrqsRynXAZ11N41H
         ogS9nazYYBzv6MxpivOJx0s8DsHvHwHFx4XMQf/IFd0Dxkhecnbs6nYO82Mrt7Qxyvu2
         6vNBEIxhKz65iYZxVVW+iREhCtHnkQuuvi3W0BoU9eqOG8Y+JPJEldWKPRAVkrcrkFuJ
         o9KA+cDrbQCr6yUp3dIoJTNuKH7qlvVnUEtcLtOqaUlrRRfavopTBARQLeB6bUno8ful
         RhubrOm3wUVrdpFp2Zn+vDU7gq/GSCZVpgFNEUlczuHsK7U/EPvZ7reFfHewcqxRLqib
         MMpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9b+go+/kwicKy3+7u6MeWH8akGn7UdICvIxSVWbOZ2A=;
        b=EuHHef5dc2Au2c/DSBxZ8fs41P/YHMejsiZx700LXskw1WlEl/ivvYH5fzigAFjHgS
         QoJzc2AceRmYhS5ICPZdnQ1xCkacRM1esH7MrFvH6biPQV6ujHuuWiuNK3yPp7WfsRhU
         c7CEKK0qgHi5pgF8W8bojUXqGjpRfZLKPL1JsvjAame2HdxT4zE5vPkMzLXI59Gn1+eE
         24kh+ylcP2nXM8W5PDc/5891t0ZhlaTOV7tlDwJHb+7DnctMa4R9ASRNh0u85b1AufZx
         TpSkmCDOI5Y6Db16q9aTZ/KkD+2nnaEHzemx9KVaAK/BDFsPpSQDbtoch65FhFFPhoGh
         QEbA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSetVPEddCCdywPvm9UdXiqkqhNKKaIOoJP+sSMnCrWuJXrDnF6RoibAWnMloFYOutAV3taJIQzsm/BXzx4D/t9SzgeKkK9Q==
X-Gm-Message-State: AOJu0Yw07/Tmgwp+PnZfj22dh+bOrgOJQjyzgD4kAJT22Z+mhSBjN/IA
	fjX6T5FzKvvKFntn7dsBAV8w9a6cOhjB3TjBifjE6Wkt2PntV+fR
X-Google-Smtp-Source: AGHT+IF9764X/E8/dSoD+30kiFnF1eXxCwX29UlmP+xB7jxmQlUt5ukLLqBLbF6Mlu1V2S/02mt3FA==
X-Received: by 2002:a4a:bc8f:0:b0:5be:9981:bb69 with SMTP id 006d021491bc7-5c1adbed14dmr3254483eaf.1.1718811953091;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:909a:0:b0:5bf:bc4a:2963 with SMTP id 006d021491bc7-5c19ad490c6ls2298101eaf.1.-pod-prod-07-us;
 Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeCAgkFye+yot54SXweGXauB9tt/wSPyYRltUlKDpMewSHZQkPlspZ/Ukzer92DeHcoJyeAvBMhQLXXDHoq0YgKaKE1UXsXkRY7g==
X-Received: by 2002:a4a:db76:0:b0:5c1:b95a:eccc with SMTP id 006d021491bc7-5c1b95aeda9mr1259989eaf.2.1718811952111;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811952; cv=none;
        d=google.com; s=arc-20160816;
        b=tvdW3xcK3xhEw9uBTSWcXYKpmJAvlOKMcvTxILi3+KJvHK+oKD1mQ+7TOPAxR/7bvo
         NaG/IospjpN7FN0bLGJoiRKoAiGQH+MnLs29ITbErsdU4bUgEr53GwXgJmDnJ48jtINo
         ipzys+4QCudkdRFc2TFtY6pzKJ7iWSi0fGA4QBfBDKRwIr/aJE0gjxYWIZzA66f9wqGD
         qYS5Jm/ACXqY2ZrN/EnE8psiSWHkmjIDm2r204d5bt44lolxklw/+eKLYl4WsRn2Irnt
         wdyotVxihdMpMNQo3EnCoW0FlRMCX36bTiCzNfKir4MgIzNyYK3wm/C2HNAw+bWhCswN
         wHsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EM2Q29X1oynbiWdgAiIUaE04pJnjihVfcXc099lsq1w=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=xzm14AZp2wWTDV5mu85OjCUhdGc5hFJt5ZPNAlCKKubuj4bR9UaQpfBmeFDzIBMWVn
         mpZEHWIMNWatDRSELMZ1KApyO204Wn1UKgjuzttigTBKFUQyruyTwto/PL/KMUE0ANvX
         umSV3VY5IsOycPjpM4jAmuUyKhi50ayp3i8lVISBXdlZqmzQKxjRB+r3WGUsLe+nz+Zk
         sHJL5SD1CJLjue9PYaJHYuTMUeEsKT7CGXJAYqYIOf8lQ1bhe6WjUOesdfxZ5Plu7dPB
         ktYnNHSc2tZrCBsyp4A70vWg2t+mpgZHU7d7blPemPXB9hGQ9HcQZ3+8kuWE7hH5YXvO
         Vchw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tmoStW2+;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5bd62c4ca61si886382eaf.2.2024.06.19.08.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFTDaF014358;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1f1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFfAZ2000738;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1ex-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JF2MxA006136;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8my-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjfRf52101430
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8323E2005A;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 34F812006A;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
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
Subject: [PATCH v5 22/37] s390: Use a larger stack for KMSAN
Date: Wed, 19 Jun 2024 17:43:57 +0200
Message-ID: <20240619154530.163232-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 1L_rd4V-q3KJB_LuDa6HoaqIhgVGw1oi
X-Proofpoint-GUID: 7q7Ag0EXzQKdAbKqsJ0CObvDzHLKczZ_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 phishscore=0 clxscore=1015 bulkscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 lowpriorityscore=0 impostorscore=0 malwarescore=0
 mlxlogscore=869 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=tmoStW2+;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-23-iii%40linux.ibm.com.
