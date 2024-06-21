Return-Path: <kasan-dev+bncBCM3H26GVIOBB6OL2WZQMGQEL2B3X7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A5D569123D3
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:31 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-705f9efa07asf1986057b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969850; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+Ivw7umUKwlMwwhxikwdjk3zEtIkAnGQqqCr09Qca37BUi5miju6pBMfZ/7QZaa0H
         xk88Z3ezJPfHh2BNbd7m0uMS7XzRoOY30gcESf5WEqvqxTpMit9EhyCPRXvsIUONeuJe
         HXaOuiZMcG78rysjQdZSWse0fexirJgAOp1MaKahnvpea5+aZyncGd1jn8al/LHlVfo3
         0PFoczCSg9UYJFBc5RV+Lhi5GSpb00D8KQoxOlKXVUGtiHEFlqT6N2O60g1Xg9A/7TLL
         YxrOBSrC3TPywAU1Cs0aLrpSEzZe5EDV+O/35wldQtEw7k8Wzkr/7nar9G/7YlEXxPc2
         Wxnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vY5zQy1N64c/nNe+9MXz7XT0wu5miCEQF4++QjL31KU=;
        fh=1QbnYkWjhF0qXVgUzYxEZaoQtpr0JoqfVlNjF9k8pPA=;
        b=Qx8WFDw0nZmCL1nnvqzClt39ZWi1Ir5/tSY7AHzZXqk9PftDo/9xgZcr3EPgqlWW7K
         W05kGG+yxipN7knorlIumoQtd1iSS1OMyb/BgxXWmhjh+NsNVF2j5opoxGIw3+dmyYLp
         NkQ+4JxIM9/B77vUfZaf70g8e3XPa8oc5rgfLCk6XtQk0TUb/CRGvzs9loLL9T25dD41
         zQapwAz2JlbasbPPdP7SWiQVCTxU0p5zJDzLqKCzKB7TpHls6Qny36Xfsp19vZtFRIJM
         k1uOLKqsaaOXE1J8p8eFyIXiyOEYnP8uKApeLgWJRYYmq/pxhHDgiBq43y1eT7dxmLIp
         762A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BBq8CXP7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969850; x=1719574650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vY5zQy1N64c/nNe+9MXz7XT0wu5miCEQF4++QjL31KU=;
        b=nbGZSxKwVdrhY34ZHOXTptlcFSx/Zes5KN7ggb1mQpZgg+R2dMSNvuFpUbAWyLW7pr
         G9raWngQt9BbSsiGbae4IGt+SXII5GKmHdv5fU2kf/jtWIepGMXusTagVSkCgtI83EtZ
         3GOwj9z263Mw2M8LQbOq817BVGgBDEc0czvBwNKYEXw+7IoFZNCogXP+FrN10kXJT1/W
         nvouo6Wb1/V4jtJOwnEbls1yC0KHPGq1fWG76bV16Rp9OiXopYvFMPaQFczew9O9hwdg
         cMuPWkaldjNjnUElT75GlRkvVyReuEzFujs8EDvBNg+gU6aNw9byLtV8qoQWWlEQW3f9
         NZKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969850; x=1719574650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vY5zQy1N64c/nNe+9MXz7XT0wu5miCEQF4++QjL31KU=;
        b=nwzrbtdN86h2VD9ISgVADwnMUPmsP9DpHk0t88tLR6+nyk/o+dEWq7o+SP0fvGOHTr
         N+tR6N4nvaplP/FndmwK1dewBlfvJLkRJ9PgO9LaA8EHFJSFup20Q5jbFFvVYrR/EMiY
         sXbPdD3hcgxsqyDSAbeXVsImFmSH2hmxH8PZt/bXjURXGWZfUaPeEF2mv3Phk9dxcT0s
         Jg4i1OnvIlcnG5Se/HZUT6Q1ZQUB9dsUgp6YfchobMyW1r3oE0h8Dw5ORRvvMl//qGT1
         aGhHrTyKQzuLU6AltiWusD3Rq0Oa2w3kw6cj7xR5cHpBm4kTV1541GbU0gRaNT0jMqr9
         Qj9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVdOw4c10aFEglXjjiWB5ziVaciCxqw8Wp9Us1SSab6baXT37GR7LNKLEKIUBRa4FYhgTQAoSW7Qc1leDYmk+TU5+gP7w4tWg==
X-Gm-Message-State: AOJu0Yxp94McBsSdnC4i/zlroShG4omBz3SGsjjEvpqADVnjtkAGrH4/
	n4Y0ONsCh5ZRcF7SqSQeMMjj9/MRQ+RAJY1OvizUPGrsDpxc6DCr
X-Google-Smtp-Source: AGHT+IHclKEEexzcUtyAULpCeBkdg8mTpWR1pAqRyCmsETgm/1RGGRnIb/BvX8sTT1CC6ACVhCidtQ==
X-Received: by 2002:a05:6a20:c412:b0:1b6:63b6:ea6d with SMTP id adf61e73a8af0-1bcbb39ff23mr7974209637.11.1718969850116;
        Fri, 21 Jun 2024 04:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:194a:b0:2c8:1a7f:5bc3 with SMTP id
 98e67ed59e1d1-2c81a7f5cafls426542a91.1.-pod-prod-06-us; Fri, 21 Jun 2024
 04:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVjDqVrCD2tbVMbjeT14rE8ra3ZZ9mCpHKlXib8kgnycYJifkXMoOS51RTAYZmXfh2X4gFPg7Amzj0ccLKNrmZE3DvhwSS514FF1A==
X-Received: by 2002:a17:90a:cc01:b0:2c8:97f:9192 with SMTP id 98e67ed59e1d1-2c8097f923dmr3086750a91.35.1718969849033;
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969849; cv=none;
        d=google.com; s=arc-20160816;
        b=fuAJzgh34bAzUcI3UJWaQGq/7gMvlBSkElhD5K/qAgKqJ4GZARnwfCDtpDIdH9iUO2
         3oCXNNrrvmBMfb7JkfZMu09NCP/x9jUsIVC3eccC63KCiqQJ5r11eJg9wkamSzZLTG27
         g+qVAzyjqDHHCWYgpat3ofKuzJIRabBTs6FBUvelGyVIr/5nRnhwv45EGP6Rrl4DL5pQ
         TMnSyzf2KglAJYwACrEUf6wZqhRed+vyIrLFOgKY1fRCcDlfG6ZYe7pBDcQIKCGdVNoT
         To4syOSgD2U4Gi7nIwC3yGWqQ93OKVjDLmExkYgZiUGVRYg/UwJGOGE+GkdA/G8jvwlA
         kRvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fhyNLk4BgDYNJAsfSc8ftWCxz9OlL/4RiKPE6HJFalY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=y/N8rzmicrBjtsKMQKhuYNX9wYXmX6HrbZlVyvlhJDrDZ0/2ekhoi5V/XaVdvoMhZM
         TbSprnh4HDkZEabsIC9hw+H8YcVfVnD4fR5JHhvP6K+2ujnITgCYVQPTf5/fGK1PvC1I
         nsREY13acatLirA3Dn9vhHujEMavgUu6r3XNYiz9fD7WRLSB7D3g9pLnZHR6vaD4w+D2
         OpWUzUiXGifekvBPkrqCkxqby8iRIiKVabRzM/hvYyXCux4tApdhriqeQL/wNoIy/JFK
         1o6boBfAsTN0Ju0XaT2eNoNy+IIWACn/MvWso1DcwYBFOj9ASB68QL+H+EmUUdtOkLzU
         Ttag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BBq8CXP7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c709e9f12asi397508a91.0.2024.06.21.04.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L9amU5018280;
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrguj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbOj0011150;
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgue-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9FiFL019922;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupvyw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbHIG44433720
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BA9482004D;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 313892004E;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
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
Subject: [PATCH v7 14/38] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Fri, 21 Jun 2024 13:34:58 +0200
Message-ID: <20240621113706.315500-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: ZTHy7hzZX807u1u4MnUH3zt6Mpu1beHD
X-Proofpoint-GUID: 6UW_Ok9wX5ovm0vK7_GLpJnRXxKeJn5E
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 bulkscore=0 adultscore=0 mlxlogscore=999 priorityscore=1501 spamscore=0
 clxscore=1015 mlxscore=0 impostorscore=0 lowpriorityscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BBq8CXP7;       spf=pass (google.com:
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

Improve the readability by replacing the custom aligning logic with
ALIGN_DOWN(). Unlike other places where a similar sequence is used,
there is no size parameter that needs to be adjusted, so the standard
macro fits.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 2d57408c78ae..9c58f081d84f 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -123,14 +123,12 @@ struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *address, u64 size,
  */
 void *kmsan_get_metadata(void *address, bool is_origin)
 {
-	u64 addr = (u64)address, pad, off;
+	u64 addr = (u64)address, off;
 	struct page *page;
 	void *ret;
 
-	if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
-		pad = addr % KMSAN_ORIGIN_SIZE;
-		addr -= pad;
-	}
+	if (is_origin)
+		addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);
 	address = (void *)addr;
 	if (kmsan_internal_is_vmalloc_addr(address) ||
 	    kmsan_internal_is_module_addr(address))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-15-iii%40linux.ibm.com.
