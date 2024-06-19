Return-Path: <kasan-dev+bncBCM3H26GVIOBBLX2ZOZQMGQELCYSHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E1DE790F29D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:51 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3762317d6a0sf4627525ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811951; cv=pass;
        d=google.com; s=arc-20160816;
        b=nlmMUxqKxHYI+hAHmSyVeStEVyYc8tvzGuhUJ7s1eNXKmOnNa2UeYAQY3f8XpK3hAg
         3FCf6zkdbymh3PE6zn2561BFxVlN94F8yLpa9gkvi6CIW0DZVyDSeAhPOtgZa1jWAGcE
         nqBmbzV56JK/oogRp3BG8nHjnCKYrrXETDepA3/O9FqX9npGQ/8q2IkpcTD59nv7Ibuh
         STIsFMWCdCG7nTIbD1ME5vm+TIsp1B1m8+apH3KWQRielFAp3tP3WcLmhu9Vp+KfoykA
         zdfgkAXgSnhFwwxEZeG4QaEBK9mr3ACIj/SRMHNV/Im44FOTx72N7qAXekNJLrBM7DcT
         HzvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tp+QOfduAxIbzhSjCRuEwYWKTBBqVJina6BF8++vAVM=;
        fh=ZzN3mZh2/WpG9cEQREt2H9ozYCrYCgnFha9hm23NDJ0=;
        b=K24tI7ADerb2N6ac/D//DS12R8zD3W00hjPWFzHcYwK99cT1lleG2pzy+27HGTSL98
         iO0o19+i4M5SBjlZ7oQ2WeHpSHiHYHyIDa5+a7XbKgE26bKrKadrQ118w7+X2eqL0nmx
         ip7zBAiZ5Pb/XYYhQ3XqB2G4wtZ3KOrueKxqxfKjzu2n2ffCCC+R+5+qYSMGSilFiQAo
         sP42Wb7VXpeFXTL5UM/RgA9C/yLIk1i8OGqHFAl3FYKjEFObzsIeG9nexkSna1K54bjf
         KcPYbtnydtWkEqA1/X/fKtY7YlzNHW59PU2s6l/gcVG299h6ISucBwGezhtb5GvuZr6U
         fpLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=i4na2fet;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811951; x=1719416751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tp+QOfduAxIbzhSjCRuEwYWKTBBqVJina6BF8++vAVM=;
        b=mCyqnXd/+YkGVC32Mmv6CiYdrTQQqo2WNJRSjXJavlh8FCujUKfChIJswWpFWQyXvU
         gc0oz7JpHjX3Xh00E5RFBa47hXtNr59JP0aAQlsdrwctoNAiodTDs4twyZIc+jNYUKlk
         miqATt/PgkDDqPAxRHQiXQRgE1uWiBXIazQSFg8yTfV7NmhKx0Fa2w46HbgnguZhuzyw
         ftMg40VQGZ404BH5O3gxInZbbMsvs+DrHQmHynmH5l0gGfPFzAK+B7X7RcrRA73ryK5R
         bFNPW7Tcpf6qfmFjd77QBQR5ffJqXkJ6d4HOJPSnriL5d5VlIEwtvozi/ieVzrWHRWsd
         7EZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811951; x=1719416751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tp+QOfduAxIbzhSjCRuEwYWKTBBqVJina6BF8++vAVM=;
        b=VDDR4GxX2aOjZEL3bUMBi6Zx1UgLJunV8TYg0qHMqQkCKeX8S1abzmcShQ+D/1zweu
         TZY36lWY4977lA7diCR2vUOwPjYdQp1cRpSLtNkY6T56zWaePsmCWEh5iLcgo+CMVI20
         5xAbf6JzGc7jyRy/Uepo5bAI6fD5+tmfz47/y2TE+LL9MQBlUJfw2NgWy51s1jSTep+a
         AirWYcJdhw87cMUzdi5YwskufPaIxWs+E1HSsaa5zZo2o2xT66cWlJsGvwwpfDtEiu2q
         y600UjTCGTzK9Fy6HxmB2PKwS6Ei4+FfS7o9oQrZCGZZG/pNjYgzn0JBPZ/Rca6U1hZw
         AVmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbFnjX9cMjhrUML2IjQM/LRiI4/wTQFxDP6qbjHW9AI7Gx2sigDS+gPeknvo0Bt5VCRPcbi9YHYGLhoWtIoH/K+5oMJ8nENA==
X-Gm-Message-State: AOJu0YzmXJgoH07ppN8p9nEvgNGBhvLQM95TnB+rzX1+Phn+YawBkPnr
	30OTVdMRznDKMZgobt7pTBq2mZsbrUEeTGlp5NR4ieLMpB4jbdKJ
X-Google-Smtp-Source: AGHT+IEDFbcEJsxbJGmsQL1liCcUMcJ8NZ65unKYaCOP1wChaw+sTB6/UIMNX6Gnhh9tlEz17KLgdw==
X-Received: by 2002:a05:6e02:18cf:b0:375:dc39:cfd2 with SMTP id e9e14a558f8ab-3761d6a2bffmr33396085ab.11.1718811950675;
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:375:c45a:cd5d with SMTP id
 e9e14a558f8ab-375d56b633dls53491525ab.2.-pod-prod-02-us; Wed, 19 Jun 2024
 08:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWb+4Hocjn54QOTXgOscD5qYy+G+q56EKtjc2Kr2gCydMuAdrCAPDKYFKE2tpr2NjAhRPnmwYlgSTSzVdTx+SemRjKS9XewEZG5bA==
X-Received: by 2002:a92:ca0c:0:b0:375:b567:a69f with SMTP id e9e14a558f8ab-3761d6866c5mr31730515ab.8.1718811949744;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811949; cv=none;
        d=google.com; s=arc-20160816;
        b=SU8hvs3ujkgZjp0XmFRlsQjed05ed2TmDCM9yZxQTqW8NVJ/UQdIbwroSSL4qYUmy+
         22KwcyunALZK9Do+0dEg8hLC5CxusOxnFTgRS4uTGD+w/Nj0EXmG7TPkIX4RqNEDtMa6
         oQeLfg0rAKANXEdBCKrYcWpMxFA/vB1rR1Vc8+2Ua5c4uuArR5M24Oy6t4znnoQm6seQ
         2evtClrYhUeHcdyX+3ZSzw7E3FbvNXVonKgG4fF/ZeMNCDyQeTSqj269ZiLvC+uKGxGa
         fbakv3YyzNPyXrBHDJcTkjjbkRCOYLOpLvuuvn6i0phbh3gTS5S+AxHj7pyF98zXPMo7
         u4bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=spW5dUefPY3wSaAYI4dxHarPRNP5jY8HpoCg9e2DSew=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=aI7w83KJSytvhrBvUchDViZMyj7hWZicGlxXQb6ssJipNwYkhTLgJ7cLsGQTZ93Lzp
         iEZUAFQEPWVz11dmaUg5QBQvW46sDHdBW1xeBk5fLfIND7ybhpvZOim7DicPpK7VGdEP
         QRMyZ0+e8AvFnT6ZLVBYzHquXSl92nB+QwveDxYaen8phy67gE6kffwEvM3FqN54Od6q
         e6TH0izyS2TVKWGL9znBluXs7O//oAf0E80jxUijMP9Kl8msAi95s6/mDAqq8WOtw25n
         7HMHW5JAOYK64vtOq2EHE7FjEqKVuFLStoJVZiMqVQa6Xoqxb/lJxrhdKtM0C2KJ9/Ai
         8Nxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=i4na2fet;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-375d832b32csi5390115ab.0.2024.06.19.08.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETBuG000638;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjiLb027323;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFVbYI006216;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8mf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjckL48300392
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 14CE72004F;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B9A852005A;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
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
Subject: [PATCH v5 12/37] kmsan: Introduce memset_no_sanitize_memory()
Date: Wed, 19 Jun 2024 17:43:47 +0200
Message-ID: <20240619154530.163232-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: imMJc4jcGcFzr_XL2Ewxf2h5FVRCtQqX
X-Proofpoint-ORIG-GUID: QA7Qu_Ntbky2iAOKmSPcLHJxbBUizN7o
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=779 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=i4na2fet;       spf=pass (google.com:
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

Add a wrapper for memset() that prevents unpoisoning. This is useful
for filling memory allocator redzones.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 23de1b3d6aee..5f50885f2023 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -255,6 +255,14 @@ void kmsan_enable_current(void);
  */
 void kmsan_disable_current(void);
 
+/*
+ * memset_no_sanitize_memory(): memset() without KMSAN instrumentation.
+ */
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return __memset(s, c, n);
+}
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -362,6 +370,11 @@ static inline void kmsan_disable_current(void)
 {
 }
 
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-13-iii%40linux.ibm.com.
