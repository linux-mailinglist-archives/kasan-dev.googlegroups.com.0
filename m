Return-Path: <kasan-dev+bncBCM3H26GVIOBBVUR2OZQMGQEDNQCCJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C9CE91175A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:04 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-632588b1bdesf22605027b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929623; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nr638NCCxPiWjrt7AEF574NEYum7CjWjJjar3fir4OTlvpNrUWDVb/zIvLnvzu94ln
         ECSwPSdkTGRK5AAkVgOiiaz3gZjx/NWRItP8prHY8cDFYvUU83jOvcZUfvR42IA2cM+O
         WqPMeaJ8mcZUM16GvT+SXRrVME/GHBL4ToXHC8QZc3twoBnrAOV0HVcpKeCQfzMJCJhC
         ErjHgaiDNPjYtZTn/hCTWYA6w1Py3ovQJhtSvFU2YB697EFsAeDGGfbcIJ+geBdTwXUz
         kS2Y2GLvShel6vTI/DTf2lRxBf/+d1a+b9YvlZwQPBqp3JhDSzpeLNsl23F/2w+kNuob
         MIVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Jd8dnIEfuyBRu8yJN1b9HGOz91PmTlASGgMnXGnCfVQ=;
        fh=xTLtviuReUV4uwGwi8aLcTblPEz2aS+ZOpITH5PYjY0=;
        b=a0m/GGawNJVvCtnW/yK4gwllp9v1dJrYX11lo+qdRw7mSl2lVsp8ad2/pTYQR1JbJo
         1BcFxuhL3vx+fNR/pqQpWBSdxsi2/QgMYdOl1XXxjT6cAobzV0YUW9NdeK6uZogVNLwY
         QcuhQrvD+88uO/Ub0JKVtcY7cqQHQfultYe1E9OPyZEu0z7VMhiU5ZqT/+v9xmJ2JkOI
         9rrbvkXdFCtKLsbr0UI6yt3euQv8DPlOl/NcLecH1YF6MdoC2W0Oy6EJwSBpeep32Ewj
         ylOfMkHdY/ZwPRsLNv9petUHyRiC3mj9nJS5yX5hDyEHjjWJU4sWIO8z3/LBAC+HJEec
         ZaRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cy2g/IQJ";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929623; x=1719534423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jd8dnIEfuyBRu8yJN1b9HGOz91PmTlASGgMnXGnCfVQ=;
        b=TN7e4bP2oDK5bEmj95KKVhlF3r6JFmK3TdKm4dGtan4XuPBGcVf5Yt81ze1HEkfBNm
         iM//OLkkLDec4uIDJiw4TQF9HbjJF0t5T+EepOaAJ50mPQ2lS4zpMZuPAlhXvrBmf7Jz
         UYKTeXM/sUsr9IX/Pfi8D37BQ9pMimyqspOBDU/0e1muq+R/W7pigVNM/xn47FSckxu3
         yGAX0YN/6vSi4eXFGbmFDdJkHvDnOEju4XwmP+PXwKniAhtH0VpRiGnLwe1WSomKUkxL
         EP7E84J4FFEOEOShOy4U1UjQtnrg3KgqzRV41GzxA0Gj8M4wnllfX5QN8Du9Td7SnTDC
         qk5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929623; x=1719534423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Jd8dnIEfuyBRu8yJN1b9HGOz91PmTlASGgMnXGnCfVQ=;
        b=F3Hpf2uKPTvm5x0+bA5yVDr6R+l131evSnpSli51FU2Yc2MeRZxwX4aTXcXkYW5K8k
         qH34ZpHhNFk0SU6GXayPwJHKfpmCmH7I5aBXZhYwyBnl6wWNnPm78nk7YIragMgsVDFQ
         pV87Lhe82pYa67a6/U2qCcp6kxNeuRWQ8oBvt8VC0ZBnth3X/hmSu0mxe0erqJjh0HeU
         lWDESmXqGfZhz4SwULS6G2Dn1LPhHfIRXDvO8kOdDNaWRrGgzQKyNQxQ4YA5/2CoDR7p
         n23ZlYOVQRTTBIP/lsjIPYBNHxTYjLidy5fxNgEH/c5JoXsKghaIwWMATiMju8x2Bosn
         mVYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVG+BvjAHwCHNoAsbJPGHDzI6mbPQt01OOJW+zOsvxY2zgiCWj0pfkntk/PyasUsSo6ePJJs7MYvbx7clpUjz/Tdb3kUssUpA==
X-Gm-Message-State: AOJu0YyoNK4y8RYQmrsSrwR292xko/xqIz/d2/yzHCCvZtwpzTNZDBkb
	tU0Wion+4pZTACLkqoUq+polslRmVdibJek/sd4deSSSqUzlgxcd
X-Google-Smtp-Source: AGHT+IFuogNGhhfNjRe4h1MuXdZMLpeWXXN3muW0lZImSSlqNUVrgdpbd5IeNP/ZPS1TsWuDbttGww==
X-Received: by 2002:a25:aaa9:0:b0:dff:2e22:a185 with SMTP id 3f1490d57ef6-e02be10254fmr7238517276.9.1718929623031;
        Thu, 20 Jun 2024 17:27:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:722:b0:dff:2d92:d93d with SMTP id
 3f1490d57ef6-e02d0dac54dls1788268276.1.-pod-prod-01-us; Thu, 20 Jun 2024
 17:27:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCwdDaOcTNlHAj2HcJQDjMPFAt1/Ul/NuMOiex3H37JiDid95l/C8RrnWrFSS9vb+yNx4ggrUU5J5p0TZXXbU93QSPEooARmSavA==
X-Received: by 2002:a81:4322:0:b0:61e:124c:e71f with SMTP id 00721157ae682-63a8e1daaffmr65913747b3.26.1718929622002;
        Thu, 20 Jun 2024 17:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929621; cv=none;
        d=google.com; s=arc-20160816;
        b=e/DO7tcgAIejHmxfW3lrITaCaqmlovBr4Uzdm5IciyRuGAe5Mtx8pT9ExxbWVUAUDA
         26d4mE8uLr+T6VBmeLDhBKO9uX6Inz29ZGM8bO0dTsDfX7MG9BGrLOQqmKZIPxa4wieI
         o8dfPZ8vFxLdLkJno8vWqWBAraLk7sWcdya5Wz/RuHMNz9yLGhV0ht/roo4wJF2WaDIr
         UlaO+9HRDsulcMRlB7wM2eM80zBFF4hTbLt9xZixbTU/FFTu8YfNFDOVr9xnHvh9Z+As
         PksWFpPv5CO1FDDA5J19gD329miA9ni1aXh4VOIvyDghrKT7lwvj3QUAC3fPtDugYZlx
         gdww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K/viBy/PeNICITSZpD3tBAO/npQA3ucnq3Zo5JONrlk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vTFfEyrb1jyfDtfrVXZBSjfeam3tzhssltbk3Bylh7fRTxp0VgNWuOMD12+8Mwg7VJ
         B1Wjn6G9B1TqIiYDqh2E4H8PW2p15sEKuv1VIobs/iFLFmIjcBxX9fIwV8gSrUKo8m13
         ln4rDL9iu58PXyw7LXvCl+rjgSJPKI5E/a6T2reW+5IJiGwLY0Q7WcFHPgDKvng5KdOy
         ilSRLBtrFTy/zRbYGb+HTEUlHAiNiX/L4KBxUVvEflzNirCgvOIYUNDNQRRrTg3mBU/Q
         znaxFd+RNzYjARFhC90IKw+rp7ncU1E+ZXrp5j3RDzPsoIIkrUVkR1Bq7F6xNMkSEkQb
         o5KA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cy2g/IQJ";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-63f0bde297esi335147b3.0.2024.06.20.17.27.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QxwU023263;
	Fri, 21 Jun 2024 00:26:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7sd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:59 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QwpX023250;
	Fri, 21 Jun 2024 00:26:58 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7sa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:58 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0Mhnm030888;
	Fri, 21 Jun 2024 00:26:57 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn39-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:57 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qp3M52756748
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:53 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CB30E2004D;
	Fri, 21 Jun 2024 00:26:51 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AA86420043;
	Fri, 21 Jun 2024 00:26:50 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:50 +0000 (GMT)
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
Subject: [PATCH v6 26/39] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Fri, 21 Jun 2024 02:25:00 +0200
Message-ID: <20240621002616.40684-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: pFMJ3VX5eByn_XhL8lU2OEpij4dBIlvJ
X-Proofpoint-GUID: RTniQi-mQ5NH7pBqPS4RncFDW36QzFEI
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 phishscore=0 impostorscore=0 malwarescore=0 mlxlogscore=780
 lowpriorityscore=0 clxscore=1015 suspectscore=0 mlxscore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="cy2g/IQJ";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index c786538e397c..dae8843b164f 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -542,6 +543,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-27-iii%40linux.ibm.com.
