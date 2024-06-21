Return-Path: <kasan-dev+bncBCM3H26GVIOBBU4R2OZQMGQELOASCBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 41C69911755
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:01 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c7a6ce23c2sf1541130a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929620; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yr9mz4lGv8NKwfi8cB5DnXQD2rPbOkkx79f5RWneY/qus+Pfii5qUvHsySC6wsxAVH
         yrVG2XCUHyG5UF+3GDtG0/nG92VVhOghTsAocvJ7k4+URwkvJd6Ntsdtop5GkOudV7/b
         yk169+mb/D7fNcEJ6lLxg/Ob/1kO76+o/Foui8MQ8/ImXf+Aqx9vX7ZW90wk5RAKmtBj
         MtlvRZ6TADsO+xj/ono1Xn3Pz+rELt8EvfUVzwikpcBwpa05q2pR0N2sOxkLr5QiqMGs
         AiGMK9yRcvzifMBI52pJO1/DqShrPGu/ZnC6v1MteBL5KhatGHd4xMaxBmJH9vpQE1Kb
         7XiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZBf0RCXG7Iij2EcFqwoy6Ite8NOwW2xB8MAbcdqAgRA=;
        fh=wL5yYSarZ2A9/LLaykQuZ1APreRS/a9d+p32H8lLc9k=;
        b=GTztJ/hjW5306GWpfz/2J2IfGwdRYYWLyCaZX0X3E9cngmj9Jq21lJvt/r6zFCCocK
         JYkR6QuqabDQ/ZO4JwDeefwz/al8pi3mgUWSelQc/1UB+6EhgAeSGFA5XLwD36qvGPWJ
         rXk+RMnXNNtwSzygacnUd+Pk8Ujw3cRntluv2C9n8o/D3+dQNVkhPUZF+2u1wqdwRNNk
         fJc2VqWmfnoE5D8dq1Ugu543/F6cNOlfWuk5BCIonyWs6RMuJkup7uibPYDm1PRGvrgA
         kyS0YDDPxXF2bgeMEbX4ocmufnu5j/PiGZGOXQLmbd+S+/ATmqYJsOSD+U2ZxUehRiq1
         YTwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bJH4+L17;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929620; x=1719534420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZBf0RCXG7Iij2EcFqwoy6Ite8NOwW2xB8MAbcdqAgRA=;
        b=cXezNjURIWU1yHCKDtapUME+1ouZ1/StddvlxTtnnxx/xxzMMOSg4qeoc+rYFxiv+A
         WyCES/+ysEU5Dq83G2Low3zY8StuEvob4FHDqNYhpbtO9F23fklnw+MdY7/KzBdW1ZcU
         YLbjvSV6s+XWOeEs883E8UEUwchGFRs4ww2jNcbjCpDRmxoRFpTWxB7fAgZeprDCpe3g
         gFawqT0sm+kgPBLp9PRmIjjVu5vMnlGSiENEOqYOqGlPCili+8mfXJVzmuiXFOcHx4Mj
         rUt9JyRxysGBuLPecA/Tx5YSKJBFl3/oYYGVEf132i2Zu9ncbL+zzWC0z4fZJwGbFGEI
         v3ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929620; x=1719534420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZBf0RCXG7Iij2EcFqwoy6Ite8NOwW2xB8MAbcdqAgRA=;
        b=EByW8hNyDywccQl3H9epHhGQWGqaXIy/0tG4bXzny8Psgf6f1ZW5f3pfCOmFQpUu0O
         P4/Sdv9PWkKQemc34bUrP996jrWIsP+C8L4PkyeM4mgo8LRmu7pNJqPQSxVA0wiZYZuJ
         UtoEXQ2vGYwj3XeX4WgRNTfHpD1l+m7GNJ5Cq4Ym+tpG1OCwImW74MXnKntVnuBA+bEh
         LR1ZPDo+oVQJgn334iewaP53d3hSnxtVslJVP74IxCQssYGONUiqRl4ob7QFN+OCO1Ex
         QiVPJd9sjzIJOHxCZzun7iWxUIRf/aP/BrbcqU7K3V8l20HcbIqI3n1rjPXaSrNwO5c9
         zZoA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW7NO3DSo9oXiZpGuqjgzYtWpUSSok9kFp9a7J622t34sJslPAacFTPtDsKXejhlkI2QTq10uUNJxtccHVF7HrCvdWaswO1IQ==
X-Gm-Message-State: AOJu0Yx0ZEyAvpfKQXzaLuM+kSMJzGicPKCc0gFDMhQ57D4k+xxJLZ8L
	vbwYW9nRiFofdllkMsO7d0vcDMunvPM3Rzgf22cnK2Q6hGXzJNnt
X-Google-Smtp-Source: AGHT+IHS9IFDxAT6RK0SIBxixFadZdjMJ2wsMlxIlwMeVlDds20AkmT/2D/1dY1O/GkPrxmLlwXVXg==
X-Received: by 2002:a17:902:9a04:b0:1f9:a386:2bc4 with SMTP id d9443c01a7336-1f9aa3dc988mr56604395ad.20.1718929619557;
        Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:1a9:bef5 with SMTP id
 d9443c01a7336-1f9c50c0e3els11188925ad.1.-pod-prod-09-us; Thu, 20 Jun 2024
 17:26:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9CcQb4Ndi/VwKme8buuzdoNu7dNNH6ZPWqRlhDQAbfGF5eBjIsn4OJCnRfgG9GyMvEQ7VTUMNciMOXDCofWLZcZnS78025GgUaA==
X-Received: by 2002:a17:903:2284:b0:1f6:f298:e50 with SMTP id d9443c01a7336-1f9aa47166dmr75526325ad.58.1718929618437;
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929618; cv=none;
        d=google.com; s=arc-20160816;
        b=UVjZhcf5CBMwhnlnBH4CFm7AqycwA57sp2c3a9/4ORzsEStEBIFmzdQjZ2eriMdX9x
         kVSob72ww4YeYW9seEYym8ILBL8hhyVvduxuTiLwmi4028d5RujIxcha9777zyz86Spv
         utJ3ybc65En4Ec6V1+lDCQSkoLKPHYdiKYKliFcOHW5DU8iZn9wGXwx5+IdA1ZX/BrLd
         WMj1amnIurmx8wl61a0SnOs7n27kKjXeKxLZjyZ3Pd24cuhDxwKyNhX65WztdCytqwbN
         dP+wyOAPcqHFFt7vMUsVQWXCZLIq2w3A9MMtTH6RfAGahq7kvljLOA9HSkjXXshJ5inn
         O+9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Scz6uta8wJUcmkDwOaiOL8UogdsQpVaK9UJlhoWG7HU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=0Qx5tngQPj1emPRGX57WKlyYMRDPhchvx4uzPNJpkW0oWWKX5MinaEKvDdLmvnXhjl
         sgUq7Wk7CVpcI4LnU5CMRvo1E72Ih1FxWBlPgVT3a+HjenP+WQSL7vm0DaSydsMVGdWl
         O5dzaF+w6gLCmxQjBiT0OYSk7+d2bY5pa5Y+1n2XcXEtfknAXaX19DeKdBVZkgr1gXjB
         wl7ohho7jkZvs1ThGI0W3PaebaE7FgSnO9mN988bpVzCLBXyAS4vRdTAr6/d8yQ8IG3q
         meqcszVDkEp7STQq/0fT8NionRe2snlG05TQ3LawPq3TYNBr/+MfgQ8QCJlxDTfXmkrU
         unWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bJH4+L17;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3c5b85si131275ad.12.2024.06.20.17.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0P8rv001146;
	Fri, 21 Jun 2024 00:26:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1g0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:32 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QVlA002823;
	Fri, 21 Jun 2024 00:26:31 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1ft-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:31 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLcFvF030990;
	Fri, 21 Jun 2024 00:26:30 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn0x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:30 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QPco41026042
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:27 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DC4942004B;
	Fri, 21 Jun 2024 00:26:24 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B73032004D;
	Fri, 21 Jun 2024 00:26:23 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:23 +0000 (GMT)
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
Subject: [PATCH v6 04/39] kmsan: Increase the maximum store size to 4096
Date: Fri, 21 Jun 2024 02:24:38 +0200
Message-ID: <20240621002616.40684-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: J1o-CJjYWKam0l2NJ9h0aJVuFgfwswrO
X-Proofpoint-ORIG-GUID: kF08F-e28R6tb6coPiDjcwHsdnBay0lG
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 mlxlogscore=742 bulkscore=0
 lowpriorityscore=0 priorityscore=1501 spamscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=bJH4+L17;       spf=pass (google.com:
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

The inline assembly block in s390's chsc() stores that much.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cc3907a9c33a..470b0b4afcc4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-5-iii%40linux.ibm.com.
