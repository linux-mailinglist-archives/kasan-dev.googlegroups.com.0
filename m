Return-Path: <kasan-dev+bncBCYL7PHBVABBB2GTQ2EAMGQEWWP5OSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FC2D3D95C2
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:03:05 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id j13-20020a0cf30d0000b029032dd803a7edsf2545544qvl.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:03:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627498984; cv=pass;
        d=google.com; s=arc-20160816;
        b=TFuPFsqZ4xRJU74GlnO6NoiWSKKFIJznvqU6WzL9B3qZvRdvlA/SQxRXRwIFTgTkgj
         Id+XaFxKNWTjCKgWu1jx12eiPk+Cymcpk8QL1cfn4946n6rmGfgIkdHI7BA5xe6d/qMF
         Ln0vtucqScVdgtVrgAP+B7/zsiYvB/kT1lB7tl7D9rljaOAqYF6T2YpWTidjbbWxL3vY
         ezlZiHLqz9oy7px8/cDC2mXe6gMHQVAa9Z96wzKolRYcs4HMRzB3dsLiEgm8DclN1aXD
         OSa81bZ9q/SljM76BWix4csTljAMY5GrG1FOwEjQmSln+bz3ah+SCHBeaaNQ5nO1HNVD
         AeBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IB2vM32HCGijEV8Kym/ZRu7uD8lVLpgf5Xq59BaNrGo=;
        b=plfDjycblGwlarofBnSrOyKMeH4LnMmhC2uhwX8MbyxpxFANEx1NKOW7ruWtRpTkqx
         eK3PdkZqaAolP4iV69h5GHSkV2aRrAKQmIPh+zvleBlr2yR6B+lt91ypXO/psrlxVthK
         ZsmCR2atprPneMB07mOTrXXv45zQVRhytHA3P5wbsGSaEG/aOYzpI+M6r98d52sxUYpl
         oIFn02nYuOxsC9L5qg1Ejqefsxr8HlZyr7E+dXZCUqmez0IZvXy0MduZ7crd13yqSx5x
         n4FWzIBU+symj37tOuEpVRkeTby+XmnA6ThdNrPAjAwtvr0CMF97R3YnZC87RiM5sHE6
         J9gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lTHi+jCt;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IB2vM32HCGijEV8Kym/ZRu7uD8lVLpgf5Xq59BaNrGo=;
        b=FmODHdOqILONQtDxZAwcx7NYZ3vAicik7gDOKflp3GXj8ZDwJIYJDdmsu2EPFO4Zw2
         gCX3br+LYbwsYxxmRhPIpS24yl30/jrIHBRiRWv5K1flZ8wPOxF0iGLHH2oECeN6K/TA
         GSTCTX2607nVqNCXBlBEnqt3EqZQkePoe60b/cGHQeKLT4A7OZCQM1Cb1SerHdMW3Vw/
         77R1Fi2xh2ZYa+A/1i7O7V43vmDONSCiVJUTihowkSajnpp0kZ69ik/ANr59a+Ed2+16
         4AvlCUeWt2Iv58EAz6GQxxpXXneVybq5LS58QV+jMUQGd2X4ZErjRT1tVHGOc5qcjZZ/
         UMmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IB2vM32HCGijEV8Kym/ZRu7uD8lVLpgf5Xq59BaNrGo=;
        b=hsRSRaWWlwaaAvfhM5MNo83oVjkL3XUII2Oo8KAvNiEYcEvt/sSAJAM6KAJ9aC8WPd
         QkU7W+bmBdS9Qt8KPraIqDUF2TFSF8zuPHWbSA+heu404gL0zXoxzFe2lF+zAtS9S6Gk
         OVpzYRVVEzCUnhoZCsgwCUZhbx37GXeqXHcIxRXdzN7YVpEndHZJuB9zaAG19yw3hCLn
         RbKMDtoGwjT4alR838uicfgXIK03f4RSHUttB2Qk03RUpStVUY/lhi2KiOvrgluT0r9s
         3UOu0jcSSYVEggXEa6hhieZUCYGoHV+CS26cFK6wQHhQbOBXAV9rqqCGC7aA2OCNyyaH
         xxrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QI4LMlmsz3e5gGH8xG5TOCA2yUjIQ9LlmAU5ZA6nWkUAokkrx
	ZBfJ7yMYB5b4uiX2KNYFTL8=
X-Google-Smtp-Source: ABdhPJwiHVKBxujFNr5or4ZTy88VG6Qp97MOG1UzZfnY1KDK4g4JBXfTpH08+9MRe1Imlz5dRTcWcA==
X-Received: by 2002:a37:9c12:: with SMTP id f18mr1242456qke.7.1627498984657;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:43c4:: with SMTP id w4ls1397331qtn.7.gmail; Wed, 28 Jul
 2021 12:03:04 -0700 (PDT)
X-Received: by 2002:ac8:698f:: with SMTP id o15mr925273qtq.365.1627498984137;
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627498984; cv=none;
        d=google.com; s=arc-20160816;
        b=T0+ITJxmItfe88tt4pAlCSxT7m5Cw6jJ9R3jID/s0UHfIT0TsgeccaGu2hOOXb53CF
         JAU+Tl2xi5GLrf2wlCyrMYM+isl3lCVhIhoDhjn4GkC/7cWTHBxkzsH4XJu3DNFDsxkx
         9pdHAJzB5IjobbTHc5vE58cOWtZfgRT1zCdLZf4uSl92xlHlAnoRvHm1UuztW051o+8f
         OoQwEc8YlWGOdk3zKdQwJN30ml7cTtBxChM60hI6HL+eevH7tsiDteUEvkdECNm8vRjf
         1JCEe3tdxndFwxPMLqXrd2Vi5zHu/LE5QmzT+Iz0ZMAjXCMbNIEdZFPvTf6iab2L1kZ4
         qJSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TY2BxtcboaFxsAjIWr+bqU571UGJno7E1tOu/3N/QY0=;
        b=Om4r7Hnn87XOrSoiDARR1+1+z7lf5RsqZTbGq8ucPd59Jc9d9WMbSvJFtCTseAAVQ/
         RVbXhNT4KLbpTBd9S7Rrj5B0UMTpYqboRn+4YS0VqVa+OL3zyluMmm+BpKJqAka0BJ28
         1hylPRk74GyeAeQuybw2oYr9ajzn13Qww4k60/t6Baoak2PQLoLZwf1fid8GdkgWjZoG
         pn2QltBEWM/ZQnj0ZcaziPP5p6Dyksj+BDnCQk5yV/pirc0l07JG2X+2bj1mESLF+bqy
         Q7M2nO9mJoQ38x+9Zylr+wi2wAfcoDjAKOVAl0xpZdgP7C+zNCFzpKMmNjLo2ar0IKE+
         RkYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lTHi+jCt;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u10si75688qtc.1.2021.07.28.12.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:03:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SIdu8O117481;
	Wed, 28 Jul 2021 15:03:03 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3cbd149e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SIeF6T119128;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from ppma03ams.nl.ibm.com (62.31.33a9.ip4.static.sl-reverse.com [169.51.49.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3cbd148b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:01 -0400
Received: from pps.filterd (ppma03ams.nl.ibm.com [127.0.0.1])
	by ppma03ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJ2xYB001174;
	Wed, 28 Jul 2021 19:02:59 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma03ams.nl.ibm.com with ESMTP id 3a235yh8rt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:02:59 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJ0DBE34668868
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:00:13 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 04589AE04D;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 968E0AE045;
	Wed, 28 Jul 2021 19:02:55 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:02:55 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 1/4] s390/mm: implement set_memory_4k()
Date: Wed, 28 Jul 2021 21:02:51 +0200
Message-Id: <20210728190254.3921642-2-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210728190254.3921642-1-hca@linux.ibm.com>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: H2XAFT0iBukiW2CNa3D3fDpkJ8eIW_KB
X-Proofpoint-GUID: lyj2SiATl_2gzjzM9MnZ3TOdVVj8g_bp
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 malwarescore=0 adultscore=0 lowpriorityscore=0 clxscore=1015
 mlxlogscore=999 phishscore=0 suspectscore=0 priorityscore=1501 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107280106
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=lTHi+jCt;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

Implement set_memory_4k() which will split any present large or huge
mapping in the given range to a 4k mapping.

Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
---
 arch/s390/include/asm/set_memory.h |  6 ++++++
 arch/s390/mm/pageattr.c            | 12 ++++++++++--
 2 files changed, 16 insertions(+), 2 deletions(-)

diff --git a/arch/s390/include/asm/set_memory.h b/arch/s390/include/asm/set_memory.h
index a22a5a81811c..950d87bd997a 100644
--- a/arch/s390/include/asm/set_memory.h
+++ b/arch/s390/include/asm/set_memory.h
@@ -10,6 +10,7 @@ extern struct mutex cpa_mutex;
 #define SET_MEMORY_RW	2UL
 #define SET_MEMORY_NX	4UL
 #define SET_MEMORY_X	8UL
+#define SET_MEMORY_4K  16UL
 
 int __set_memory(unsigned long addr, int numpages, unsigned long flags);
 
@@ -33,4 +34,9 @@ static inline int set_memory_x(unsigned long addr, int numpages)
 	return __set_memory(addr, numpages, SET_MEMORY_X);
 }
 
+static inline int set_memory_4k(unsigned long addr, int numpages)
+{
+	return __set_memory(addr, numpages, SET_MEMORY_4K);
+}
+
 #endif
diff --git a/arch/s390/mm/pageattr.c b/arch/s390/mm/pageattr.c
index ed8e5b3575d5..b09fd5c7f85f 100644
--- a/arch/s390/mm/pageattr.c
+++ b/arch/s390/mm/pageattr.c
@@ -155,6 +155,7 @@ static int walk_pmd_level(pud_t *pudp, unsigned long addr, unsigned long end,
 			  unsigned long flags)
 {
 	unsigned long next;
+	int need_split;
 	pmd_t *pmdp;
 	int rc = 0;
 
@@ -164,7 +165,10 @@ static int walk_pmd_level(pud_t *pudp, unsigned long addr, unsigned long end,
 			return -EINVAL;
 		next = pmd_addr_end(addr, end);
 		if (pmd_large(*pmdp)) {
-			if (addr & ~PMD_MASK || addr + PMD_SIZE > next) {
+			need_split  =  (flags & SET_MEMORY_4K) != 0;
+			need_split |= (addr & ~PMD_MASK) != 0;
+			need_split |= addr + PMD_SIZE > next;
+			if (need_split) {
 				rc = split_pmd_page(pmdp, addr);
 				if (rc)
 					return rc;
@@ -232,6 +236,7 @@ static int walk_pud_level(p4d_t *p4d, unsigned long addr, unsigned long end,
 			  unsigned long flags)
 {
 	unsigned long next;
+	int need_split;
 	pud_t *pudp;
 	int rc = 0;
 
@@ -241,7 +246,10 @@ static int walk_pud_level(p4d_t *p4d, unsigned long addr, unsigned long end,
 			return -EINVAL;
 		next = pud_addr_end(addr, end);
 		if (pud_large(*pudp)) {
-			if (addr & ~PUD_MASK || addr + PUD_SIZE > next) {
+			need_split  = (flags & SET_MEMORY_4K) != 0;
+			need_split |= (addr & ~PUD_MASK) != 0;
+			need_split |= addr + PUD_SIZE > next;
+			if (need_split) {
 				rc = split_pud_page(pudp, addr);
 				if (rc)
 					break;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210728190254.3921642-2-hca%40linux.ibm.com.
