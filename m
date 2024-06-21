Return-Path: <kasan-dev+bncBCM3H26GVIOBBWUR2OZQMGQEXC6LSLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 279FB911760
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:08 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5bacf94fc7asf1436657eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929627; cv=pass;
        d=google.com; s=arc-20160816;
        b=xjzwOtxVZUOoOS0Ekdki2KmjQabpkoE3dHytlkLp3gDWMiu+hWgjjqC+7jwgl/jC1z
         FYWHMW3HOuejxQb2nQRaqZ9oHPYMq0JU/tp7MNasMa0w6x/wKtb53rxhg6giMPK9fWrb
         aqGvP1nhFMUjTevNKPt4NgJqQujTelEMASWIulakSdkKimdJOpjPHi3wiBswCQu0dVSn
         hQmrUD0l9ubglWgOvXa0U6kDLMXBAcQiCNLJH1/MwT4hK0I/K089RRPNcxdLFxeiQkn5
         lAsrbFnt0+q3waQa8DSxj2ZGrNuxFtJb+i4n3HnuWwLQzZ5NRCfSp5E+gJmltnYMYgiD
         RcLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cMmgF7qZYM4W7RGTXh3HWBRLbSAZcyCvwG0Vyp9WSv4=;
        fh=CBWMtrU+/jdEVZWGiMDG9CjHROWIsmp4fecLxnIBV8k=;
        b=iXiZLiONcYYZn741jWSDlHy52LQdFnw7B7JcHrZafj80pBu9TsZ7yDuEHHEuXhPeB3
         CLvOd7E0UFGIEH1IYXnFtAuoMH0s8VK/TvnXlanfQaAAwCi8Ka0g41OcEysNFikm1j7c
         NuQdXYDMlpbOc3wJZ8MvcyqyuxgimYO0xnHXdAJUcnOCVFyfiunNtXxIEFvxSGMP+6ZB
         IyL4YdPczBHGrYZVwq5AkLUQVWjrTH5DhLuw8X6qjKkjzMzrNTsd8NiE4afZyk2WVhwj
         HqVdy5HPx79r9IecEdl7AI8ciJBurOpBPvqBVNITxUH36waSyFusFYLbxi0mpRty6vaq
         75EQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PNF7gbL2;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929627; x=1719534427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cMmgF7qZYM4W7RGTXh3HWBRLbSAZcyCvwG0Vyp9WSv4=;
        b=FqD5yR6MJxZPnFNMgJYXF0i4z2Bheop+t4DmMlWLmGmyT732SzhVa6FqyoLX87bdkK
         LjfAn+uyOWEUq/n07rYG5MG5D3oO/kp/ji0HZT/DUb5QJjl9uEKJvkvrAlgE8jl6GuuI
         voE3NXch6ctGyCxza5WCwYoxGg9FMMHELjTj35S7gh+ML9mFxqxCzjYg2uM7dfsHOSqp
         obyd9UE0U8jf4iVSty9kzmt8U589QR9iFTi6NOGTu8pE4JCAcxEpAg2J7ICdq4TnphFX
         ebGfr3qiKWjnJDDuoE3ll9YBjn6jDUIZEetgn5665LJtvjYWdYA9+R2+PwFgsoDxZWzD
         hGDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929627; x=1719534427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cMmgF7qZYM4W7RGTXh3HWBRLbSAZcyCvwG0Vyp9WSv4=;
        b=YRS77KOsVl/7JbFPt+efE2AQ35rp6RiqxWInHx7xWMsJ8L8fXtja8s00wSZouBckdm
         c1GwJYuE/ZtSGpERZIbQKSREtacM2DN/lGLIVJEELAAauKaOh8aFNY2AbtLkVaEOlbP6
         3cZxkGm4Ge0z8kQzJU70gFKsGbG7FConS214nXYza9j36R7Xav9j+2g1tG39BQ64Ytk+
         Zwzv3dhzeGWdXZPFVc5HRmvhQLB0SI2iT7pZejT6b5hSbEtqaQqHAUhqkkJc6697A2bx
         rT6hEfghR1jt7g27k4Prsr+EBpEt6Wl6BPgVHVxyUb3k54bU/lp9GW8Ay+zp6ycTssLc
         vZfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgyQKgbLSlyzqaT6ns9TbvER8CV96yhgDFT558cFZ87mdiFsdqo5ldNMZtDvgs104cwg4FdlCw4n/n/i2XWGHm/jreLZnkvg==
X-Gm-Message-State: AOJu0Yw64q3x+JP20G1CS1N1MZ+xm0gHFlfvfR/K/gq9UNnavXfUmj6i
	PsECRVpqQu7oeHuHDTypRsD1ZeJExqPRm6lT5SaNjzxnB5H+fXVT
X-Google-Smtp-Source: AGHT+IHWCDkTUpIsthf+oRmVu0fppH+Vrv/yp44S0DgohYLQ+O7aoyofTjPXJSqAOMfTpHgYB3v7Ew==
X-Received: by 2002:a4a:3503:0:b0:5b9:e7db:1cf8 with SMTP id 006d021491bc7-5c1adbcb58emr7391278eaf.4.1718929626957;
        Thu, 20 Jun 2024 17:27:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3047:0:b0:5c1:aba2:f502 with SMTP id 006d021491bc7-5c1bff22b4fls1330560eaf.1.-pod-prod-09-us;
 Thu, 20 Jun 2024 17:27:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaAqdjKwy9iR5y4240Ap/EPIu+Mg8910gKvZRB7vqxTSDAC+fERz+l2vCTXFjFaa3LsF7bGXrhJh6tT0pLZCCh/ypVd7gNV89ekw==
X-Received: by 2002:a05:6808:150c:b0:3d2:1fdd:286f with SMTP id 5614622812f47-3d51badba4cmr7885103b6e.49.1718929625985;
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929625; cv=none;
        d=google.com; s=arc-20160816;
        b=BzArEzxleU7Ns2DZFp9m7IUrFV0ExvTtGS6HXavGN1m5cm4G/suE837TN4AcwXwyyc
         Mk5Zb2s1jkHdVFlNVT3iNHgqk2UtMewlxDb0V42Kn+GgKk/0pqFPD6ruv6MRc4hyn8AH
         LjVC/Jm2grudptddN/xRXRFuzrKEb7BdmfwKCJvdN70FOj5l4y1QjbF+4k+dQQmynNNm
         /yi2E1r0I1+OuhbXUUZ9El8w+q0AqWpeaLud/dNxm/tZTZ//8VBb0qyIJC4L/tgDTK8X
         VOw8DwzgtY/YUAAmWl1RiS8KRB4xHmLZtnIZmNHwyRSxiD2SUann1X3QVaMU4zYEG7Tz
         cWjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=//0Kc+3BL5cKzp2INWy7uHqYWutu2bfhjte7hQD65vA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=C+PMQ5O9uE9dJYJJI7XjruHmMXwGIbMmRkq7FvCzq0S//aizt/9j5Mjt1aQpeRpCOV
         msq1r44Kd15yZPqTvt/IERTRw5p/4DmdyXqBnYpa638wcUph/EbRn4RVjwNH/gE/tS7b
         VqxxB6NUL8VpfD2i0PvgAIPe4QCWuVXPHRi4hgJE0Kswt0SbgbwqxoC08Witrm/+3LP3
         yQncrjGc80TP/PzUbSLjo5arqNb+3RCwucMtBDMAZqW/wOsik1sCmI1rBlQHdgfYP3+P
         XbkMNw3lU15da38KWrxd29KE1Kimur66VN8JGbPV0hM8ZaoGXVM7KKVcQCzO+AU/43PB
         2Ywg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PNF7gbL2;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5344e7c93si18795b6e.1.2024.06.20.17.27.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNtjEU028042;
	Fri, 21 Jun 2024 00:27:02 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:01 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R1Ns007963;
	Fri, 21 Jun 2024 00:27:01 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:00 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0GVt1025708;
	Fri, 21 Jun 2024 00:26:59 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2np5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:59 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qsuj16253276
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:56 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 46D862004B;
	Fri, 21 Jun 2024 00:26:54 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 257B420043;
	Fri, 21 Jun 2024 00:26:53 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:53 +0000 (GMT)
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
Subject: [PATCH v6 28/39] s390/diag: Unpoison diag224() output buffer
Date: Fri, 21 Jun 2024 02:25:02 +0200
Message-ID: <20240621002616.40684-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: dR-59j4Kk4tyD4-uSWRXBGdaB4Fdihzm
X-Proofpoint-ORIG-GUID: UqQveLdo15GSMG0ihOGcB2yNIYG0gRJI
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=999 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PNF7gbL2;       spf=pass (google.com:
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

Diagnose 224 stores 4k bytes, which currently cannot be deduced from
the inline assembly constraints. This leads to KMSAN false positives.

Fix the constraints by using a 4k-sized struct instead of a raw
pointer. While at it, prettify them too.

Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/diag.c | 10 ++++++----
 1 file changed, 6 insertions(+), 4 deletions(-)

diff --git a/arch/s390/kernel/diag.c b/arch/s390/kernel/diag.c
index 8dee9aa0ec95..8a7009618ba7 100644
--- a/arch/s390/kernel/diag.c
+++ b/arch/s390/kernel/diag.c
@@ -278,12 +278,14 @@ int diag224(void *ptr)
 	int rc = -EOPNOTSUPP;
 
 	diag_stat_inc(DIAG_STAT_X224);
-	asm volatile(
-		"	diag	%1,%2,0x224\n"
-		"0:	lhi	%0,0x0\n"
+	asm volatile("\n"
+		"	diag	%[type],%[addr],0x224\n"
+		"0:	lhi	%[rc],0\n"
 		"1:\n"
 		EX_TABLE(0b,1b)
-		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+		: [rc] "+d" (rc)
+		, "=m" (*(struct { char buf[PAGE_SIZE]; } *)ptr)
+		: [type] "d" (0), [addr] "d" (addr));
 	return rc;
 }
 EXPORT_SYMBOL(diag224);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-29-iii%40linux.ibm.com.
