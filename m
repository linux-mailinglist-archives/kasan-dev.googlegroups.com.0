Return-Path: <kasan-dev+bncBCM3H26GVIOBBMP2ZOZQMGQEMLXPF5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 841E990F2A7
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4434fd118adsf317701cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=k295d5nG8mQCmD7XPG0YZgwn5CB+Su5jaWgON4dWt2muM2tg1neszudW2zBklJm7SE
         DcuwlWt92OfOK/dbrXLmvWQy28A/AvZpp6Q4zP5FwwMIdLQYh4BCWpyEPDaX8/oMvPl8
         OdlM1slczGmQQKBJXMbXjhTYfol6L9tKNFnsSzKuQCiwJeDTAHg6DL8eo94asdDMphUc
         Mux+y9Zq7CqXIPN/OcG4u8DTj/Mi90byXhli82J23Xy4C9aWlyI1HpZB4fmtxxe0np5u
         QIUbgbDJJmk9LLMDPOvmpOc4Cf82q8REXysoyEpJqyu0zEQ4RvEdLr9BXZyxYCIFGVJ/
         7gRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pZ9TnTNBNTOYGFadJzfA/UdU/r+4vc3HueJ12aNmSzk=;
        fh=Pc5SlAWIsfnv4LgoXKTda5ilYzcjopxIe2PhHtdZ3n8=;
        b=QuWDr1w98Kzt7RDjqQmSrRhAQbBVanSbofRAA5lrVmcs1xBre8ajIzCs6/cm9BoYKx
         8hiI7LHoOo4BUNQ8Wme3F5fWMo5H9LiQhSGFm6zFnZFwnuXikjLRY8ULA2tQE1PWNX2k
         X9HJXKkHcr3XGtDmye2g+tibkoX7U///pggpyyjt/xERTN31bAuEa+m09HhqHfwqVh+U
         CJ55C+Y7gOQUTg0waHRfWLj8Ad4iMW1YWQnLHI09MhAFozSE3MaJJZiU+ji/astzjWHG
         5u41MiD+rzRrIHQvT2RxbfBiyFaNJAe0r/ucqnv5J/Zlv9QWUE6iKmXoV6AAgDSXoLUh
         L4Ig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mNNtOrw3;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pZ9TnTNBNTOYGFadJzfA/UdU/r+4vc3HueJ12aNmSzk=;
        b=s6KEIFf2SFh/XssltQZDFJ2i4wZ2TODTubwHWmzRYG+1JuPZvgZuTqqEFVn2i505hj
         lE7MuGwY/YQ7WEhdj7XnXhMwIUFq+AIdp35ORfoZXTzbVc3lWT3w39XCBTpm1b0BbzG+
         6oPscEKliPrtyNeU0AroyvDQ1YFnWI9YhBaQH6z1rkI4QlBIJO6eRTHjs9mLZiYqPn+q
         jn80w9gnTHR94FmZIyp328mtYem1Gj89oKcCYjLWjCggPsXzOzuFEJCcqPZ93SY5GoCt
         gOZUKgXLAcv3tUuJ9sgkySBzs5WzhcH7pInGqN1DzJbAkL5l90liup+mn15M3yPc9/0S
         qicA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pZ9TnTNBNTOYGFadJzfA/UdU/r+4vc3HueJ12aNmSzk=;
        b=WtAqFz1SmNUfd1TELUMYvjNWrvtvIM1poPcSiQvzEs3P/wFx1RJLxsLuzxJuqhDVX6
         6YZVK36omNj26eN3BNd2oXO/ZZMNI82wHe5mkYkAP3udX8NLdz+XKhst9/LtjHWKTTQf
         /ATNQNxb2qAblrJu370Le6wfdbalFeiAuQt64ij1IlvbK/0tYPdYg4Q8EEtIjU97phZi
         mhnJrT1LLIEMX8syEnWVrovPFOsSHuxU9ElFZB43ixd7TJHJFQcqmP9hv8tGME3N8cgx
         fKL9QEU2FT7ulcGiUxOr7Sd799SM03ovIf1KyGVFrsOFQPEwehwmepQenQAEhq1j1bpN
         kVeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsBBHl3456G0xB/IGeqowQLy7eDer8I0xKt2E9iNRG7ihedrWVjRgv99/himc4GD6vCGFtfsVlw3EESteyj1u5+G9Rk+X/7w==
X-Gm-Message-State: AOJu0Ywjcf70gZMwSPiugzHNDg/O+tMCrk/qTxuMgioFPgwvhFBtuCo0
	F8pAA7nNYZsQADSXTn9NIReIAsbl+5nZcKjAMqvYOhY5n6NLkHZX
X-Google-Smtp-Source: AGHT+IFgzVa966M10tGx1Jnn5EEew2diWsHfWc+/kPC8FKjY7ecEU8/N8hL6Bl6oWqFbYdhQKMNm9Q==
X-Received: by 2002:a05:622a:3ce:b0:441:5400:9ec5 with SMTP id d75a77b69052e-444aa3b7788mr3308271cf.1.1718811953351;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2d43:b0:6ad:7b3c:b7c7 with SMTP id
 6a1803df08f44-6b2a3507c5fls93392776d6.1.-pod-prod-03-us; Wed, 19 Jun 2024
 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgLE78HOqmy8gOo1r9GVAtWcw6WP+4rlM18ajaXWtUNYx4BYgGBLQTPcRI8TEXgbLYgtmR8ciRICBGNHuv6ZMWJStpgoBdHDxH+w==
X-Received: by 2002:a67:e9cb:0:b0:48c:4103:bde8 with SMTP id ada2fe7eead31-48f130aec2dmr2973448137.22.1718811952715;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811952; cv=none;
        d=google.com; s=arc-20160816;
        b=PxqDEAae3EaJiJ5RqL0UKk+ieVzOQo5/REGffMsKrW+sIrNxNt1/GUNHN+MVglmaXY
         2HDQ8DD9UW9ETPMdIYp8Tce47JyAlS0IHxSYHnMslzGReHD90ezL8ucwQH7IF2MesPCa
         2IEwztwyV0dz6sCI5x05RgdvOOgu5+9NkuqohyLZh3kY8w3QGhWsqvzKj8D8GVBnCFmK
         +rYaKKttc+BOv/BdnaSR53UGZjSVAjPHuiVwCc09PVE5g//muFogicq1EX+eHVx8uYFg
         FupFy4UaUIDocEgWZF3ib5vjrRi4asEeNtKBZXqXnwKEYuwM6RdkrT6h/MlWqiW7CQJc
         N1EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOJVqKOJuZasA86pPY8j/wtn7XC9Zj2RO1nXjWn3Mgo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=RbX0+MHpCBYtJDKKQ8+NidVJw1UraSYpwJ1/DBa7B5Hvo0UA2kf/HejziYXb2rcWue
         Tzgh4WTtzZYf4JwOJNsoBuIaKUJVhsXlPV5q1MnOD++6Ewxv+Gxut6ZUYFxY4YxX1H00
         BlaNOkhEtXjswBYuLrXk5uUevms+x2LgzqpH/d3GjCZTVBJKq9HmE1tesTnTPN3pw46T
         oYTQjQE+j7nH8ohboFBHb4bIHfjs1UJHgu/UX4ESpF9TpMfeWtjJ5oZAo3R2Uuz3hV05
         VOe0Ebjy4WRS+KC+m8DXy3yXmRaTRj1rlQy4Fe7yz/id6ypPJKsrr/r75s+eeSniFdGi
         iKmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mNNtOrw3;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da449e8c2si662545137.1.2024.06.19.08.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFQuTe018094;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg8540-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjlVE016329;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg853v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEdT04009433;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmn0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFje5c46596572
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CF52D20049;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 80CC920067;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
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
Subject: [PATCH v5 20/37] kmsan: Accept ranges starting with 0 on s390
Date: Wed, 19 Jun 2024 17:43:55 +0200
Message-ID: <20240619154530.163232-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: t-6NhsbZHDQnXiNF0uBfPW5-9PdLjO1W
X-Proofpoint-ORIG-GUID: Kj9sxnPHfaNJvrcvSASovW9PrvrbuQr1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=990 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 impostorscore=0 priorityscore=1501 clxscore=1015 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mNNtOrw3;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 9de76ac7062c..3f8b1bbb9060 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-21-iii%40linux.ibm.com.
