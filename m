Return-Path: <kasan-dev+bncBCM3H26GVIOBB4WR6SVAMGQEARIR32Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id DE7CA7F388A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:27 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-67800577545sf4157466d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604147; cv=pass;
        d=google.com; s=arc-20160816;
        b=TwYzwxgVIXwiB9iPcsei41vM7eF6Duz++BWDhtVEL3gjyAqlcd/3BjWuZ+cRBaP14L
         S8KCqFpCNq0m8a/Tig1J0NUWAwAYEBwRKd/HdbP08qNcGBn++UTHSYew/kMMozIKWKMX
         m387A1eGBz/OeNgpJ/Ihiix2v+STRbefrSLOCO9fEQ4sytcu10gXT01wuvrA01iMZ2H+
         vpY6Ylh7YsoRkADcVeoSp8dzw3F928Zfo8MV+NQIcZFSUGyuHtwQ5zUhw8jxnQIOqjRo
         qQTKAuuxMmnHGk7PGwQt3BBg60hBYFwqH98WP0NYvQqaDNrgXWH44D0Aqvdw6qu1NF7f
         n12A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cCoP3JymgfR9AE0rvQJeRT3C5DEKAdPX8AaznBBmkTQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oEZNVQsKxQsbDXeHHdwWMs0QVftePYPlwZcp4Rj9gvo/xylEyptcDo1+W6ikEKYyWU
         kObie+XkjeWPcOWYlqCZuCEO6p0mLRd9FDzOx9RnAMqg+TjM0zecQ+95QQhXBhEWzAOq
         huDPcwgkAaE8K2SCz0iQsAW2Zz9+og0G4NfcTgqAJW9OkcOT+bGcUjMj22xttz9xZcmx
         InRtkDTXrZ1HzNNw0bTWuf4KWzMRPsdFdKm1KTBXri5ugCTgSjY/9ojE8Gt9MTFttZqR
         k9BVJ0ro8VequE8y1+3dWO6Cg7euAfzhsHnV/vP+NK0mdDTmQF9Wrld3zyJZa1f2NO9y
         IU4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RYRunEdV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604147; x=1701208947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cCoP3JymgfR9AE0rvQJeRT3C5DEKAdPX8AaznBBmkTQ=;
        b=Dv6byfBzUflgeRUejziamqV3ta/48QppT80NMpvv6Mm0B9rPK8SGb/ffmudWBgFtCW
         zC5y0yqOAe2T2ABcPG0OxOmpFQUvN8+gWr52lb8loyc1ek0APXeYi94+OaQj0Ggu+4iP
         x7AKV4sx/oL/QJ6BE0bY7tOvVO5o+uaJB9xnKJwz6/pF3dFj/a3vm4cTnV76uvrvNyel
         vyFGlF76tULQdkenJ92QXjAk4K/3hnF3arxUJ1KuJKQBjqGy16gy5pz3v0ffXeuPf7lR
         y5p88uW0GA2gwMBJ6FXpNPj18TuxYwWGFuHLZlSUqd7TA6i7jTmEbBNE3cLKEyzkC7RS
         ecLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604147; x=1701208947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cCoP3JymgfR9AE0rvQJeRT3C5DEKAdPX8AaznBBmkTQ=;
        b=C+mU3QloMryec963f2Mea62j349QJ8S+lhJBSegZsVInjB60M2c8og9abc7Gns69EI
         ZrdoE5PpoTut2nz+KlXTimFKcxYd0Fp/osWFo0GXJQ+KAN831+7g26HXGdxd6b11AGjX
         ON1OuYjH6Ys6f0UDN74hiAHf5djftZJ+pmsnWu2DvUtbnsEQr8KAeLJzgFLvYon9IT/E
         IMg5hKsDjH7uzEZhk1zRy0XwR+ZW9Vzz1LNqK8VdFdJYBeup6wppQyhCoa9jT+qbfzRU
         y2KBv1N9Gjrntl79cCj/wyaAx6F2gSYWU2g0rrdbFOSwzNM/Hnchqx65h4RIbU3q2wS7
         Xvdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxSzszbUFWglDKcauKcmB9wC5pjq62bwwdZH2iwyvJNo+D5N+xe
	iMjJDFFZRtopHre9XGnDIYY=
X-Google-Smtp-Source: AGHT+IG2idCG4/Yb3ru+ZZhjhWNTU4cweHVBxwEPjQD+ZzjbzepweWxliJLxtvcckSFER6Qm/AwDIA==
X-Received: by 2002:ad4:5bc8:0:b0:66f:ac98:5647 with SMTP id t8-20020ad45bc8000000b0066fac985647mr1071669qvt.21.1700604146705;
        Tue, 21 Nov 2023 14:02:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c85:0:b0:65d:b9b:f310 with SMTP id o5-20020ad45c85000000b0065d0b9bf310ls1173961qvh.1.-pod-prod-00-us;
 Tue, 21 Nov 2023 14:02:26 -0800 (PST)
X-Received: by 2002:a1f:5341:0:b0:4ab:da7a:c573 with SMTP id h62-20020a1f5341000000b004abda7ac573mr878040vkb.8.1700604145997;
        Tue, 21 Nov 2023 14:02:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604145; cv=none;
        d=google.com; s=arc-20160816;
        b=RkB+ngaBB3DcB0+UaScdIqeovP90w1tz+XGpqFrC9/natmkoPaHgWh26GnSly39l6y
         jXOgwwzyc/XFXa+KSZoOAIOS8C5PubgAe011CmY4bC1qV6rK+lm0qYxvcdXpkH7GMFCF
         ZSb8S6hGnY3aWfVSEIJ6pqdVadnYTB0or67UWKEBow+E3pDreqQivwIkf582JGPK7wD0
         onabK9UqQO1k/eNqq2lNnswKSzNPJc02IptLAyAtt5AkIMgcpMeuz4W2iXmBzoyGOf+m
         KBuLyzM0z301mxuuM0+vLPDYiqF5kFK/ytHPbg8cB0TZuVrATeErbX4pihQE9qQSQE1P
         1c5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kTguPNTtkujOx5aTw0/7lEtG7eBE+cQa3Gtf60+X5Og=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sXTL5xNOSDDQ5SaAh94PmH9A4lEzXgi+ajAaz4gEG8eaHaXQeGnt0ydNERtR94nAMC
         etd4J/2ckHQ0svcAZu1jMNY8fZOO7XuASPmP1ak0Z8hQBov9Ttp4cks3xturjc2Lw9nX
         DdJ8mr9na6rREFqg1ajIGZptHSJUigZ2s6ob0/dMUrYCralKlQFmWCy6GHPq+eqhkZ0Q
         oNrHgaSLcEVvAHQCO27hsMSqn9ESIq4K4PJ24qQBLJ5VW+KoFF38JjIo2z94scCoU4Qw
         Hf/XCvlnBgckRaFzPWFIVMlsal6XTl76RDR6kR36YHMKWq6vuLvwVjHANDu4YfWbmoVc
         y8GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RYRunEdV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n6-20020ac5cd46000000b0049d13f0321fsi934644vkm.0.2023.11.21.14.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:25 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLgeV8032042;
	Tue, 21 Nov 2023 22:02:21 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8eyu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:21 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLghtL032152;
	Tue, 21 Nov 2023 22:02:20 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8eyd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:20 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnXxd011060;
	Tue, 21 Nov 2023 22:02:19 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf9tkbbg2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:19 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2GDj44171902
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:16 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7F0122005A;
	Tue, 21 Nov 2023 22:02:16 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 07BE220063;
	Tue, 21 Nov 2023 22:02:15 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:14 +0000 (GMT)
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
Subject: [PATCH v2 07/33] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Tue, 21 Nov 2023 23:01:01 +0100
Message-ID: <20231121220155.1217090-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: B7RtM10wgoiXDWtQSzCUsN3XoYr-pcVr
X-Proofpoint-ORIG-GUID: YLsibPNprUpSVnBcQtTLu3E3EBSDOV_z
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=999 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RYRunEdV;       spf=pass (google.com:
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-8-iii%40linux.ibm.com.
