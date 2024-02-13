Return-Path: <kasan-dev+bncBAABBM6JVOXAMGQE4HKRA7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 56B6B8527D7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 04:40:37 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2198d16f794sf4858503fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 19:40:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707795636; cv=pass;
        d=google.com; s=arc-20160816;
        b=FSExLHT+Nd/QVMbPuwF9t7YsT7n8wKJjqvvW8fFMW+R4PJxdzIxZxCY3IJQEPF/whX
         uPlcTqLzzb1lEicVvrhlyKF78stI9gAtta8Y6xqricwMggGRgXbgMBgkFMScDFuMvEvd
         aWSuxQ+lZoRMLavpgcWqLg+D6QpqLm1fMqA8HPfPodgjZTzXdE9XBvg7z0uJZaRuaYut
         lHZ8vykPBu9csC9Ad3KIezEqp+E9mizfnhdj8IiBKcZxlEmX/RKxjDpVtptHR6GtrMcF
         GLmJqaSxpjzgZDiyroWjbgKxdOhTzlW+kUMB5eqlXUwIVB987/fmsJ+Dm4d9hHKeedz9
         5P+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pqMpXQRETk1bCQXplZZA/bcP0D4NAhN0GqXqTBfD/4Y=;
        fh=IZzpC1JYKgECbbrXrWuq5wMPitWFpK5mUMFBYHsU1ew=;
        b=OFsQaZ+T/9g+aDr1JHRoOMgyuPTiIhH14DU1DOgBauf0TfTHIzkHGQI64urpIhMnZu
         Jf/cSRMo316UWlxSPcwivcQS4R0Fq306RXo8oPnSuWyTzPAG9KN2ZgxZbA6/pnrHgb2P
         zWhuoSdkyvFRr2pQXN6pfmn9vELuxBXY70J6L52FlMrttQWBORxxhK556OGhgZnUKn6H
         RI1SS5K+vsEaN+1RtU/cyUHuMK5zeasahU7miZ7dVT6ymwKhjxrvFI07prqiI7VX2VTx
         uYJ5CGASk+nmLmJcwN0VlxjX9DoDsoLYSQYr3w3RNFm78u75nuv+q+emw2bzXTZK8Oi1
         SYCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="hKji/jS4";
       spf=pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=bgray@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707795636; x=1708400436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pqMpXQRETk1bCQXplZZA/bcP0D4NAhN0GqXqTBfD/4Y=;
        b=XdfqzNbrkka/bmADpWGqjI3kelZ/nXk6vO4e+cmJXyFhhVyhrt07UMff6YiZzbNk2j
         zdgzYBfYxjyAJRN9mVeCqOI48qpXnYk2/Henvtoy/3klXLr1VtJW2RJtypgMfQFF73nT
         qkwEFaiWuo1nbpTqu+NFpf1u1jcBZnjx3i4hZw05GAiH3tOu60TBYP95HIoY35nqB5Uu
         Ud5rI+Q5tebS5Y+sj4yhF5LKV+Rg662EpNQmtBU5j8oQFXm9VHR1p+c2QxQMrSdB32oj
         CovyHAMFFc41aqPyi9WORuo5z8yGEsFGrpHaGGOCpSSYhILJz7Sri5Y1wUZB9IaqQ+/m
         83hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707795636; x=1708400436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pqMpXQRETk1bCQXplZZA/bcP0D4NAhN0GqXqTBfD/4Y=;
        b=JKnUVgUkkKKh1RL1qBTsKtNfi0Aiy9n7n1dwZWxI+gq4RlazWA7XQHt6cUisLJQgDF
         gzV6brmPd0chjC7pFtdlgTgN92XNStCzhq/qMpZAk9+btw+kIh6oTMH0WzgWCyz1gbZD
         L+klfBRhjGOX3oMJJHhqSWUlHhVA4p1q8vLChcanFy6mipf1yRmF0OerZf/oYIsoJe8F
         hlcEFQ6bbkvP6UQbjDqRTytFhgVhOjvPaaWcZ3KxgTg0u9M3H/wYj4JfFp5a8GmkFtnS
         PC4LW/mwfimxCUGCBk9wUx27Ll+swHMdmCmuOesYiSTOv7Zunj1U1mAsFCRkaR4/Q+ds
         Q38A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxGDcaoD80OkXZQDpNr61TYcTHxvkwrtuemulEnNEdj+143fTc9
	HbQr7jVMVDH7H97NWpSQZKViAoJYI2O5hdHygFW3ASr8T2IsjixHm5k=
X-Google-Smtp-Source: AGHT+IH9WArhE4HIchpG+WpeonFD94B4b3sVUw/l8agqe3bnv+tddy0FYhRAUOyy8dRP8vyGTuvTYw==
X-Received: by 2002:a05:6871:729:b0:219:3447:6ba6 with SMTP id f41-20020a056871072900b0021934476ba6mr11832459oap.47.1707795635856;
        Mon, 12 Feb 2024 19:40:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:bacb:b0:21a:4084:5ede with SMTP id
 js11-20020a056870bacb00b0021a40845edels3041240oab.0.-pod-prod-09-us; Mon, 12
 Feb 2024 19:40:35 -0800 (PST)
X-Received: by 2002:a05:6359:4584:b0:176:5bef:d33e with SMTP id no4-20020a056359458400b001765befd33emr9402167rwb.14.1707795635117;
        Mon, 12 Feb 2024 19:40:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707795635; cv=none;
        d=google.com; s=arc-20160816;
        b=sY4sxKiFoq7xrXXD4velol1qdfWnJ98mLfKTMWVtqpO3mxmJPG8MD4L3NtWCmO48L3
         Nwb6zWb4dgFHmrvyGCZBX8j2IgWEFBG0MgYOGfcZtRRSdwdCd+to/QcIjJ2UBOyXI62T
         /0wI75IldH8PeDhqA3Ai0SwaK+k2vbMaOj0Kg94DAEkRT5irSau/7AfoT4ERA2hor5aL
         dyu997oc8JzSOycFFHhxvWmlE4i4Tzwf18BxiCryEReEiVB8sec/4ivD3Dmxhv0rYPdn
         GdD+iTHQlb1HywFQSS6XlX7xHJC5rVx6WgijsYxnUOOiloHUjw1/IFdTZaPZFj9zbE+W
         B56Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=f15K4CNpPPhE1S8nlxOgksSRtzRMnVZ2Pr8/ZrLZXF4=;
        fh=IZzpC1JYKgECbbrXrWuq5wMPitWFpK5mUMFBYHsU1ew=;
        b=XjI7rZ81OglaUgsM7Bq1inCTgM2ZlhaWo8EFhIAveTysFN8UI1dtN/CUu8FEj/b4OS
         JI3qszyR5JpiNK19oyfpsMINEWq+MgWhucO08p7DVJkZ5LpEV2GHo08XFqhhg3tupd9E
         X2ALA1uJepXBUSXNT9eUzozNp8N6bFANUkQKvHXbTrppnUnEIu4gCT6imAUYqWANhgDy
         SGC0pWl+p8c1bCuU+cdrwODVhUdNW1VjO03NhGESS58wO8Ge7k2fBCrWNktlRSNaSgml
         856DvhcmcCjQSdy/DalsbTS4ypn3cUXVAQh2kA1Ff9Wf4sYKF6SRTV5viBa21AUBeLts
         OWmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="hKji/jS4";
       spf=pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=bgray@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id a5-20020a17090ad80500b00296cc9f0923si195220pjv.2.2024.02.12.19.40.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Feb 2024 19:40:34 -0800 (PST)
Received-SPF: pass (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 41D3bGrs010718;
	Tue, 13 Feb 2024 03:40:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3w80p5r1kk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 Feb 2024 03:40:26 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 41D3eP9X019033;
	Tue, 13 Feb 2024 03:40:25 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3w80p5r1kb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 Feb 2024 03:40:25 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 41D3H1Os032614;
	Tue, 13 Feb 2024 03:40:25 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3w6kftd8kt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 Feb 2024 03:40:25 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 41D3eL7x4784652
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 Feb 2024 03:40:23 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5F1B22005A;
	Tue, 13 Feb 2024 03:40:21 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E8E7820040;
	Tue, 13 Feb 2024 03:40:20 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 13 Feb 2024 03:40:20 +0000 (GMT)
Received: from bgray-lenovo-p15.ozlabs.ibm.com (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 88F5A602C3;
	Tue, 13 Feb 2024 14:40:19 +1100 (AEDT)
From: Benjamin Gray <bgray@linux.ibm.com>
To: kasan-dev@googlegroups.com
Cc: mpe@ellerman.id.au, ryabinin.a.a@gmail.com, glider@google.com,
        andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        akpm@linux-foundation.org, linux-mm@kvack.org,
        Benjamin Gray <bgray@linux.ibm.com>
Subject: [PATCH] kasan: guard release_free_meta() shadow access with kasan_arch_is_ready()
Date: Tue, 13 Feb 2024 14:39:58 +1100
Message-ID: <20240213033958.139383-1-bgray@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 9gVMgvY_SvvIvaUO2--P8KONTUtnB2Rc
X-Proofpoint-GUID: yFZGjxVENaZeNIbmGRs1g2t2xJ8qWlqC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-12_20,2024-02-12_03,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 adultscore=0
 mlxlogscore=859 clxscore=1011 mlxscore=0 phishscore=0 spamscore=0
 bulkscore=0 malwarescore=0 lowpriorityscore=0 suspectscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2402130024
X-Original-Sender: bgray@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="hKji/jS4";       spf=pass
 (google.com: domain of bgray@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=bgray@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

release_free_meta() accesses the shadow directly through the path

  kasan_slab_free
    __kasan_slab_free
      kasan_release_object_meta
        release_free_meta
          kasan_mem_to_shadow

There are no kasan_arch_is_ready() guards here, allowing an oops when
the shadow is not initialized. The oops can be seen on a Power8 KVM
guest.

This patch adds the guard to release_free_meta(), as it's the first
level that specifically requires the shadow.

It is safe to put the guard at the start of this function, before the
stack put: only kasan_save_free_info() can initialize the saved stack,
which itself is guarded with kasan_arch_is_ready() by its caller
poison_slab_object(). If the arch becomes ready before
release_free_meta() then we will not observe KASAN_SLAB_FREE_META in the
object's shadow, so we will not put an uninitialized stack either.

Signed-off-by: Benjamin Gray <bgray@linux.ibm.com>

---

I am interested in removing the need for kasan_arch_is_ready() entirely,
as it mostly acts like a separate check of kasan_enabled(). Currently
both are necessary, but I think adding a kasan_enabled() guard to
check_region_inline() makes kasan_enabled() a superset of
kasan_arch_is_ready().

Allowing an arch to override kasan_enabled() can then let us replace it
with a static branch that we enable somewhere in boot (for PowerPC,
after we use a bunch of generic code to parse the device tree to
determine how we want to configure the MMU). This should generally work
OK I think, as HW tags already does this, but I did have to add another
patch for an uninitialised data access it introduces.

On the other hand, KASAN does more than shadow based sanitisation, so
we'd be disabling that in early boot too.
---
 mm/kasan/generic.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index df6627f62402..032bf3e98c24 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -522,6 +522,9 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
+	if (!kasan_arch_is_ready())
+		return;
+
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240213033958.139383-1-bgray%40linux.ibm.com.
