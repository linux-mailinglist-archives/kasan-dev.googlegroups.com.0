Return-Path: <kasan-dev+bncBCM3H26GVIOBBSNFVSZQMGQETNPEVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C279D9076E0
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:54 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5baddaafa8bsf743030eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293193; cv=pass;
        d=google.com; s=arc-20160816;
        b=JX6MqrQouhPPQczypcX4dsfpvqezCWtOmb4s0eO3yez6B20//q96Fz7d63u7HDlGDu
         wxAu/+ox5wTqx2qC8JhoI5lYsQt2ewSMLN721o8DAhjmv/fr/u2RITVZSE9ZZa/g7Dx6
         OdjTMDbrUllgWQr7LczVk1i0ExMbX6Xluj6HGsxaErbtwRc8WigON05Ffmf/bHP53wsN
         TujS42aviSgpxuMfEFNw1EetzeLvvVitUpFj6Vd7rRUqgfd6bGj8BJSvsduRDdzbKLCO
         8w8OOn62NB/xO+z/s+PeQ+3uzaqBxjMD/MNWFb7D2yap0q6BPFfU2oKtAgYTuQzsTI/d
         Vy3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TqsTMrcSJNXNmqb+w5E0tQmSltPtXnfql8sA9FWYIi4=;
        fh=llZXxUi8E9mCl4IYtTYNmq/nbLnLcFO7BctYKElmaKY=;
        b=QgZgo8ijqlKVNTVpDCPpdM5Yb+O1jCkjdd7bavOkkTJIiGxtJTZpLC6+ALdr8Jxcaz
         Prj/V73pHevXtNPM8ZVU1qRVnr3Wf/H5YZ1M4PwumrUc/rvaooZ6Ap+/YULsCY4cdO25
         8G8/EDVDf1B/DqsmoQGyn45zx0JqsduW0Dqrku5VkR+0f+yks28yxt9GKDAXnGc8WwMo
         W39IgL+fa/T9Cn6CQV+nM+RqOrbK8Y61gfDNfHT13TfwK8csNrmOVP1lq+69tyQx/d/x
         oQDMOjHt8ciD6Tj2h5OHT4ZScNRB/hvpVR0NxB/LF8eSpZJEFMVr3GT+n4eSobRxnSTM
         kPEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GFn9rZgl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293193; x=1718897993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TqsTMrcSJNXNmqb+w5E0tQmSltPtXnfql8sA9FWYIi4=;
        b=pt1+IZOk6V32Q2d2BpYxddM7IpS57DlCL06ZjYoGLeEA6h/FwBnDEKMMiFigDBZ5dR
         cAh8dbuM4wuaMoAM1mOstBehopln2C4LxBAfCj6QFsaiynZ77fgZRjlObwxEcvok1HqF
         AK14cyGDLtKl9OhLPi0pWTyLtZR63z7TrfXuNKkC3+MiKgTPVy//rvuOm1ctQclyVTHg
         QpLIBeCNXD6kA96KRQt69lf2YoI6HJEj7RrwxgrECVHVGxuEqOlJbFlV0REZoc18Wyro
         lDZidn1CmJCthTgrb37BMQa5YBaO33fjFin5YxL6fbDrtciThN07qUOLZM1wY5dCAmJ+
         dAFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293193; x=1718897993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TqsTMrcSJNXNmqb+w5E0tQmSltPtXnfql8sA9FWYIi4=;
        b=jPHD+KG9aiaJjT9rL6W4bGYdFDP0SO5AYsxrGFoOrrrE3pr9h0CsxexYLhAjVKnHUL
         vBowRET1r4g2W9KT9dI3OJ6C7E0ddJXtWJJih5envaeTf4FZZgLAYkHUlg6kTnW2FOQa
         LJhoVpzFDh7dahs4owb8NIARpWAMtc23cVUcLQHzgYTzj5CRRQXdYyzLs+Jlnj+0igZm
         O0B1ZHf5eLSwTASwmzAyKBccLhUEb2AFzP8JApED3Yty/rkMrPygqgRxwNDy1Is9RqYz
         tD7v1wxzrmSUj7A/CNm2Crx5FKGkuyu3W9AMgmEdzcDgcUqkSGlBMhfj0OrBX0+kKAbU
         SJHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuNeWHMg2ct6hIDc3YKwiPosFEPuSuEZ1j/vvMGzj753N1wvN+sechI3u+QPEgp5COxPMdW0TO+IF5R28w7ig53oUPYIHSag==
X-Gm-Message-State: AOJu0Yz0u6fRfK+QMN8ZZR7er5RX1rbQ6FG7JaBqrTWJWEi6F1O7fVh/
	Yy8CVNEedZh5PwOaBDVRTQs2F1AHBYCoSKdSmRpnu/GqfvIFSD06
X-Google-Smtp-Source: AGHT+IGX0awMka72uVAYT0vyog3AxDjcHNTBfFfAPUplNQjhdwZQb4DgDg/jmNe7EgZ6e/NqpJg/tA==
X-Received: by 2002:a05:6820:54d:b0:5bb:3a13:a802 with SMTP id 006d021491bc7-5bdad9f3f3bmr78693eaf.0.1718293193555;
        Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae0a:0:b0:5af:c4b3:9d4f with SMTP id 006d021491bc7-5bcc3e3e6a0ls863544eaf.2.-pod-prod-06-us;
 Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1WVSM4UN/r/v3Sp9el40+aT8WQziJpSTPl3wYuIcNZt4JnNjl499XbRW3SorTCTuEqkLtxl0Y5tlgK5HWw6iHcn7OjUUyzJfVew==
X-Received: by 2002:a05:6808:21a6:b0:3d2:277e:45e3 with SMTP id 5614622812f47-3d23e018a54mr5946378b6e.13.1718293192422;
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293192; cv=none;
        d=google.com; s=arc-20160816;
        b=OajLVzSqOlez46rHhezg4IknQj90N5rhXw6yAZcRJ9b+nXRAKfDx7j2jKNnLxhfiMU
         4MYqUWftyV1L54WNKGIH1iyoLXEzjpIWQuKMp9smS6Qs6bB/U3GRW2r8gFvYIw/UM5/K
         ppCIZU5pNnbwyJElfxiwpC2She+vmblfwhzaikCMfN2rQ2hmlQThngp0l6MRsucoabgg
         GM2PPN1L0qyb0Fk282XQwncSM6mS0gJC2ph5sRq2Umx6BZVLjvnd3aTsED06JBAzpRDY
         nkoLvX/hV0OADgV8EEyX7ZstmchkY4uQXV5GcqaPIkGcghqy6QW7bBBopvqVA6IC0T+V
         tRJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sbxyaH+wQYD9HEEyi0Dc48lc/ExEdomPXIQ5yBEz8ic=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=H/BcyO5as2YcntUKwIhJMls1RxcLJquamwcbwAgZeY7CIpt0RasqaF6PG3bDFq1AUg
         a/8YUv6XVX2JbVWHqzaKFTZAisBK6wCcQVKunQHMiPFMbju1BYqocQ4KP75qJvS2COqR
         oA5An9x+eeZEMu2oPrx8DH1XvfGa2XeuQO9oW934YDOYmgTZ/8IUQqpAa+1XZprGESO2
         9EfUTWempNA4PNkhh1IVkVmi3nqq0+x78AYUZY5VUl1TAtYAp1sswBHWXEU8pEuKtt8f
         NUbrWDwVF1xPwUPSOYBCgIHv6935mtRAH1rm5+PlaXnyKRobgVdXNuaBDx2jvVK3pbzk
         toeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GFn9rZgl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ed422f7815si31959e0c.5.2024.06.13.08.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEvpvJ025707;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u2370-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdm1e009655;
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u236u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEfGBh028808;
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9fd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:47 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdfdf43123134
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B6C9720043;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 43C2E2004F;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
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
Subject: [PATCH v4 16/35] mm: slub: Unpoison the memchr_inv() return value
Date: Thu, 13 Jun 2024 17:34:18 +0200
Message-ID: <20240613153924.961511-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: GHIorWSh7sK7NcZlcxQY6qZTqADL7ydS
X-Proofpoint-ORIG-GUID: Ac3hBXFJTla2Ds8gXEff7mGZc7quMkCQ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 clxscore=1015 impostorscore=0 adultscore=0 priorityscore=1501
 lowpriorityscore=0 mlxlogscore=999 bulkscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GFn9rZgl;       spf=pass (google.com:
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

Even though the KMSAN warnings generated by memchr_inv() are suppressed
by metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns
`*start != value ? start : NULL`, where *start is poisoned. Because of
this, somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

The intention behind guarding memchr_inv() behind
metadata_access_enable() is to touch poisoned metadata without
triggering KMSAN, so unpoison its return value.

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index a290f6c63e7b..b9101b2dc9aa 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1185,6 +1185,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
 	metadata_access_enable();
 	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
 	metadata_access_disable();
+	kmsan_unpoison_memory(&fault, sizeof(fault));
 	if (!fault)
 		return 1;
 
@@ -1291,6 +1292,7 @@ static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
 	metadata_access_enable();
 	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
 	metadata_access_disable();
+	kmsan_unpoison_memory(&fault, sizeof(fault));
 	if (!fault)
 		return;
 	while (end > fault && end[-1] == POISON_INUSE)
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-17-iii%40linux.ibm.com.
