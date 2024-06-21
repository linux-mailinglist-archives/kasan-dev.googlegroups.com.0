Return-Path: <kasan-dev+bncBCM3H26GVIOBBQUR2OZQMGQEP4LMDHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D276B911744
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:43 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-376282b0e2bsf13298435ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929602; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4mzuFJ3E2tngQxmgLrY3W6pr84x3xHRpLa8a8eJGftn91SYocRH4itA7zpc8e8ez/
         NXQ+/j2ozlfLsW5xwN1wEQdskQJFmY7/eoq1wDL7F1hI7EVgabNtWhCYa/Dx2t2tT8Yy
         jFnEJc7ejdjgksl5TDS+Jd3aIEwNUmHdK3QdQDUs9RJJ4UH6LZzlEntX3ruhszUAz72X
         olF12ppMosOYp6CvLbGDxuAbf5DO0YEGC44wB1OrBG5Z1yJY+fY+vT+ua4so0qaBToyW
         0W0xR+bJ/IprhTGENK6CEat3R2Q7xzmTNvQKtE3gB4IRWlqBsH8x7qFkTSwOs9syOd4G
         JgjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/uQ1YyXM8phmAB+38dJP2RrFA/RHyH5wQgbSTBoezTE=;
        fh=RiipF2zEEjJFLVtGFJqoKvutHEbXf18BC4c43BeWMCw=;
        b=m30jT0MKoO44OzHrHPmHj42TZuPs2EL2CxncGdo5WGG0xwh0qLyQud6HvHEpUeBP+Q
         A0X01zhxhg1BjdFMCw5hKGVCurLyect5YNoMlsa4EBRr7k7tfZkitG8+43tQiSuF3c37
         /hQIaF6oLZgWuMkLJ7blqtgXZ+8TvIIPynY81mjpERkB/MqEgwv3gtsk68zW9dXvuExi
         FCtbfdUwU23B1FrEssFI7RhCo6RRdwMG27XaJCvbss5f282KbvtIw8zbFqcKq/obxAtI
         dAvuahclQ3X+A3bEJvzj/gberTM/uQ9QctqNWdONgr8idDk5S+cls/XGU4chdAEpEuJ9
         r8pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h0Zvssk6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929602; x=1719534402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/uQ1YyXM8phmAB+38dJP2RrFA/RHyH5wQgbSTBoezTE=;
        b=gpDFiQbCYEGWLN1l8pTkiA2w28tZJUWX7W/HFXwDP4AN/WyBB6Mo0KHfWBf2wZ61iY
         AknBiPSkvlW9cGDg70lbHcF8qk3rGyEe9qJZHsLzeC/ykGPg9OA1FAjUHBGJLxHFymGW
         KdhSO2MszDu2nQt5VondvsrGxSQBuPsFZaOUNScHGNgAwBl8jqYwWwelFw2pZSPP2Xaq
         8xlfi2D6B/vshmm/mGyUBF93GMorMRvNZSYXrwpYqDwGVTXHdKDW+/DsImNPR92SMOiM
         T4X52WpXSU5Jz7yG+oQHAMk10aDN74o4ttiHeA8ZTNqoZ3MxQS2/cb56NqqASFoBi64b
         MoUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929602; x=1719534402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/uQ1YyXM8phmAB+38dJP2RrFA/RHyH5wQgbSTBoezTE=;
        b=gNBA2b+Eku6ZHqbGEo3yreEt4NbOW+6OLE0hBpMqeWfT5XpIsk08uMXTXhgo4Xa1QA
         MDHZCr/ZCiKP7f0ubFWbt8W1KVKz6CHqJxfA/e2Z+MeufOdpkvlGRut6k8otvVVGEIa0
         auSRxOB+izP+ZDBcZu2havI/AgevqPpYIMS6WdZXtwj7BJfPeUObpqSU887Gzpw9CVro
         JHcCwHKv+akPyzHjDzyq7wjNPsaJ6xFgbL9OAzAWWdd8PE+n63VRnCGz4KRcluKdW2hq
         5z+rNG43mSNQ8CfdQlkmS7oU/W3flsNIjhrWrDFLg13UYC8j/yZfC42Oq1QxUZV6cYCg
         lADw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9AbGVd1PVerfhki4wDHlxQjpD80uKTRlrI2GWvIxJ7VSJS82FILvE6j5U/uZtdJnqIR3klPz8YR6/F8UNFInsRpp/TnUfkw==
X-Gm-Message-State: AOJu0Yy1GFDPc9mJmwek7eSFeBkANDbLx00nI4BqtZ2Taovw8zHMwkBp
	LR0LQTdnX2RpsOOYUJ0fOiCfAfSmbICxxsljONMaUqyRMbgUlzwY
X-Google-Smtp-Source: AGHT+IGelVLIyb1xvW5sM6LJ47cBrnaGAEKBY3pWHdmiORPAOxUCfc5BFI5FmsdTKS7/F1AWExys7Q==
X-Received: by 2002:a05:6e02:1c09:b0:374:b07f:6dbf with SMTP id e9e14a558f8ab-3761d661538mr82128955ab.1.1718929602533;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2199:b0:375:8917:6d7 with SMTP id
 e9e14a558f8ab-3762691dcc5ls11272175ab.0.-pod-prod-02-us; Thu, 20 Jun 2024
 17:26:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVQdfF8G54fYF/sj/kVsYGdikKXSqJRbKbGvBZL+nka1oc5ZADQpZltLhxFe9X6Qq17rqZBwlHmsfDYVk0LXOu8Gi8RDAt7vCZgg==
X-Received: by 2002:a05:6e02:1fc3:b0:375:acd1:8bc4 with SMTP id e9e14a558f8ab-3761d72ca3amr68459205ab.27.1718929601468;
        Thu, 20 Jun 2024 17:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929601; cv=none;
        d=google.com; s=arc-20160816;
        b=H8hjBko3OIpgr/dyXvWPt3uG8Hbb5qsI8EYwZMc1lmvj+nX6YXogdq9no2zs7gF7gD
         3dvvxFUSMpYFkp3Thwv3NYOg3Jt+7jYTwgrWgaXnCAv+fOvA+y7bEVpzyuL6YPjF/KFg
         dvephB0CuQPll215Geb666hyEs8NAcdJ8ZSja63kvYsv8Oj+iLHeiPKUX9VYOrNf6Y1c
         ZGWbSy7Byg7zZVKtcl+9NTCodeUTCZ97dIlb4OTEyPz1y9Q32JDMHU4RlfgfAvaokKMv
         gI1wSRf32wrJO/mtQiuw5yiPJwoMYP7tnwB1P9+L+7f/Z8MAiZI5W27vTAtoH2ALwHUt
         2C9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3hDUyT9rvjh/uqttZeOy24s2Df+NNUjOmmqDaE5+6Vk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=kzbA2wT/EbGYq71SbLReP6YEo9y8/PHj7sooWYT8lYNfpRbNddH5aIYmbNbik8oNCg
         MUwCG/iwccrTM0UfGnLL6xQq5+q9CG/hT4UQ0wlHjim8CWUppMBdgYQDIsw57xQQsoLl
         gI/avqnlNcCDRuWEvbSaIurIEpZuwes20iQ7hW9tWXgWiXwWbWrRHV/r/uMEpYFWA3mO
         qeAj7HeNtmE27x6fjH+8AoTFjQNnU9pPAMPxyU9mipbgvRMxESo8ojm0RF9iTOlIrcHy
         pB1PAiPYfhXmflrynMukcka4uvZ6xsOVrSVmBCjSmcJxYhObfATwOhTs7SopvH+nkvzv
         uHxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h0Zvssk6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f31a449si159235ab.2.2024.06.20.17.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNSUVn000458;
	Fri, 21 Jun 2024 00:26:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c0704-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QaeN022669;
	Fri, 21 Jun 2024 00:26:36 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c0700-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:36 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0G6WD031351;
	Fri, 21 Jun 2024 00:26:34 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq2na9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:34 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QSun21299646
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:30 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8A3E020043;
	Fri, 21 Jun 2024 00:26:28 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6ACD22004D;
	Fri, 21 Jun 2024 00:26:27 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:27 +0000 (GMT)
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
Subject: [PATCH v6 07/39] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Fri, 21 Jun 2024 02:24:41 +0200
Message-ID: <20240621002616.40684-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 9aqDnYqiZJrIWgkclNbtCMnokhICs_wR
X-Proofpoint-GUID: M6kl4HuHEuc2TVbCgmc2mbFwZv4B5LNB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=h0Zvssk6;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b9d05aff313e..2d57408c78ae 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-8-iii%40linux.ibm.com.
