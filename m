Return-Path: <kasan-dev+bncBCVZXJXP4MDBBS4T2W7QMGQEI526G4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7197CA8116B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Apr 2025 18:07:42 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-af510d0916dsf2066772a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Apr 2025 09:07:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744128460; cv=pass;
        d=google.com; s=arc-20240605;
        b=d6HpP/MwFKUfKOTAtU2WVt01cjVH7SkB9C4EJd4NJCfazcXD1RWpsneQRh8As4N3wi
         DiA+eNYWMRVTxUVcdh5hVCi5TyTLduu5WqGaayg4xiF/Kv04TKCmeRrBU/2dwqoD5J+/
         9uZFzEjOQ/RCArX5eIQ3W3KW06NpqafbSC6ygVG7E9LvZQWLOzQKkj07/uU0KLoyYggq
         rpCJUjVhs04u34K6OW1ZizsvlGdsM6ZGXA8ShkPxE65LnPuMY62d2Nvj/irJ+LeF22n0
         tfWry7R7WzTBM+PXcvIvXrYge2eg2x9G8vAVTRHpC8zawJhIDXzu/xYgdUJZ3NuN3LvO
         0Wiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xDgxSToAomjXJY+KCkMYG1XN4ngtHmMUbxhT68RGFIE=;
        fh=DWD82/uQVFAamZ/HYRlqyEArO1z1J1RC0P0wLUHkhUs=;
        b=jcHXEgT8eUjpEibc/wGqymdYLWVc5t81U3FBnorjPJPSQJaR36U90tANgzECN3BQrY
         nJ/DQKKtWqTBgZqsyq/3FLDyPe7I35YmNzz2rU0HC4IHlz+FkudsCBVa6Tf8i+4+mHtY
         n8P9REbSqJpPYhNOybk5o7qNNNf72AB/Vgv+8OmIgI9fNA77Tuv8O79qChHsw7O3i4+Q
         Luj1fjPMMWZq4zDp58P5QOWvh7GTSQbf22wMPmBj+nSlrccIgFbngkNk35a5aN0g0zb0
         DH3ZddB9/Nlsw4ZvaPezDHDJm6kwU895sKT+jmOMrW7CTCDxGG7LJY/jWjDYuFJiucsS
         W4Sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YCQQ+9vP;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744128460; x=1744733260; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xDgxSToAomjXJY+KCkMYG1XN4ngtHmMUbxhT68RGFIE=;
        b=l0d5IJY4z7jDFU1eZI6j/SHW5i6mulE36sdKGWO+o0/j3n/q8UqFsOHYERuP91aFmk
         Yhnxv2ismCA6D/ukogO8ymBQ13RXsQcUouotdLyA6reppz/gYIaDqV/aKjHoQNQyyvEp
         RbZNyqdFzZrNyI40+BpIVwDqeWuCb2oiQia/Rqq7ohHdU9Gzha9Af2CExkx/v9EdeGbB
         znRrXXDVI6X2tlGzaQAOvXCzh85SCEEJc+ZlighTJJc4gSM9+xG3QimQzaWpnjdHZDdz
         W4yZ7DJqmNqLZqtm+J2adhLLzHPBxjwRn6Kh40xGN3EdRZ+daT4L/Gss2g+0/s5hcpH+
         /2rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744128460; x=1744733260;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xDgxSToAomjXJY+KCkMYG1XN4ngtHmMUbxhT68RGFIE=;
        b=D43pDWlJrjSpr5jCWWVhpD6KJ9HD1ENduBfkgWdQYzoUTKLT9FkQIDOhNoeG+R9leq
         DlJYO+ui5R7x1qGnLXf6VWrj7qZrLa8waXPcLhWrex0tk4Dy/cA/khpWUsz9YMlvcSCI
         gSAvBUkue1eh8a9nM49a+gddt3XvDMQTQ+flTIhU6m2/2ykRcf8SVhywcUjMY6zPYIps
         eD6mvY9qsuFP5Pph9WBJziLMWlsCI4Hi09aEPMEpNdRpPG1K/ojnUXyO+DIj9aGnt+QR
         gIeUsldKsckjHsiSyFyBcPwCXGdiKLisl/qoyeDoLu+ElZ/yHM2hKclKn6bt0lTumA4p
         CfFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmSiF5uyKEPUIOS7TPF0dDMLxwX4xE9IjU3ZdwkbEDOJK+oXUBzRiJRJlnK1Znougok+mjTg==@lfdr.de
X-Gm-Message-State: AOJu0YyH3JUytLgrzFbKaKDsMR4Vh/BY/j+J0E+8rKL8vw4zSe0Z4PKM
	XAdssa82bIkq5PmdQm/2Ti1o69DOqE7kvlYZaBsilx/y08925MJE
X-Google-Smtp-Source: AGHT+IGevfEtnsq9+EtHI5ikl20TIJS+JX6VACyTSZa8GtzlK2ROR+nFUxbu2CLV25KXOYSnar0Pug==
X-Received: by 2002:a17:903:190d:b0:224:78e:4eb4 with SMTP id d9443c01a7336-22a8a8c99camr241564525ad.39.1744128459532;
        Tue, 08 Apr 2025 09:07:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALaFKEAGJVCngdKIEZSv5XMcT/F1E/Yr6Key1K1iO4L2Q==
Received: by 2002:a05:6a00:1d9b:b0:736:cdfd:9229 with SMTP id
 d2e1a72fcca58-739d5c8ed1als5430066b3a.1.-pod-prod-09-us; Tue, 08 Apr 2025
 09:07:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7JfE8GEOkc2SOe+D4/eMLXlBcnkJntHMe2RuUWZtBiNFJ8WvT4yb/iiieimAuL+lIKUWy92bVrFM=@googlegroups.com
X-Received: by 2002:a05:6a21:3388:b0:1f5:889c:3cdb with SMTP id adf61e73a8af0-20107ea235fmr22622031637.8.1744128458127;
        Tue, 08 Apr 2025 09:07:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744128458; cv=none;
        d=google.com; s=arc-20240605;
        b=VhPQhd5RAkXykrq4FQrCmZngyZLGbE0uhwLXRfjQiU+JdWS/VLiW/ORBxwocU+lchx
         OrnM7BxNsG162cR5Z1HT2w78qnSKajY00vOBXbi7dn1x9zJhRWWKNmXwPVcCXh8+7iFq
         fkXcmAlX9tnvmiDbWJACgTPkTqC0FReyl1pwpWxLyenKBtmz+NBuUJR5mSJ1v4dvc69w
         gE32E+nNsuWQn3IImUgUSYXH9m8vwGmd4apI+1r18H2h5LIQVVKy6DKts+spT1gsKgDL
         got8OMSC9tku4jLiV3BbtMyHNijT9SmTexI4OHEp7CDVXZvHf++Hb08+RUg+G9nql1hy
         QsTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CGQhd4fZt/lPh+ygmPdHCsaE3Xf5iXCG6Bx4it5RIf0=;
        fh=Qpv0vZFsOkAl7OpmVhwpUC70zZ+oFSiffx6v4uyFrtA=;
        b=YMbZRJpVdmAFx56afMoX2ILPcICGwRrYynPB3vutnZlhBOWmzmQdE/2KnPVxuRwRt7
         ovIlY6wjHqBNPJ9daihqqdPNljmswkabFa9XuDxaBmW3HSD8AakcryQYbGTKT6L4hukI
         gsSmPKDFAorD7nKUoq+OoGWPyyvloNX0ZaOMZXKC4o/1O3z+WO3lOMXsDGmG527S5VTu
         qWiNWSIljNusV7SoOsjA2tAMZA4opesHOofs3GWpY2NBx0W4buWzo4tHJyLyN6uRKHBj
         PrXlzwBWp0eCQ2nWt161TfOQtuDkGWIioGcKp3lwQ3OLPbW1n/8c1/zfMJImzu7U7UaL
         VGmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YCQQ+9vP;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-af9bc418135si516658a12.5.2025.04.08.09.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Apr 2025 09:07:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5388e1Pf025362;
	Tue, 8 Apr 2025 16:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vnvq4kme-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:36 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 538G192m023979;
	Tue, 8 Apr 2025 16:07:35 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vnvq4kmc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:35 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 538CaKov013932;
	Tue, 8 Apr 2025 16:07:34 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45ufunkd24-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 08 Apr 2025 16:07:34 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 538G7WPl33554826
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 8 Apr 2025 16:07:32 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BBF2220043;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A5C8320040;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  8 Apr 2025 16:07:32 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 4BAA7E15A1; Tue, 08 Apr 2025 18:07:32 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v2 1/3] kasan: Avoid sleepable page allocation from atomic context
Date: Tue,  8 Apr 2025 18:07:30 +0200
Message-ID: <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744128123.git.agordeev@linux.ibm.com>
References: <cover.1744128123.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: LtzH8ivnniEqxi-8CvOTdzmx58H27VfG
X-Proofpoint-ORIG-GUID: DdE36rmI5XQZ4C_Epq-fHX139ivWx26P
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-08_06,2025-04-08_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 spamscore=0
 mlxscore=0 lowpriorityscore=0 adultscore=0 suspectscore=0 mlxlogscore=866
 malwarescore=0 priorityscore=1501 clxscore=1015 bulkscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504080110
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YCQQ+9vP;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

apply_to_page_range() enters lazy MMU mode and then invokes
kasan_populate_vmalloc_pte() callback on each page table walk
iteration. The lazy MMU mode may only be entered only under
protection of the page table lock. However, the callback can
go into sleep when trying to allocate a single page.

Change __get_free_page() allocation mode from GFP_KERNEL to
GFP_ATOMIC to avoid scheduling out while in atomic context.

Cc: stable@vger.kernel.org
Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..edfa77959474 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
+	page = __get_free_page(GFP_ATOMIC);
 	if (!page)
 		return -ENOMEM;
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev%40linux.ibm.com.
