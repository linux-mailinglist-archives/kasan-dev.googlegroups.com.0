Return-Path: <kasan-dev+bncBCVZXJXP4MDBB7535DAAMGQES64EO6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id ED9E7AAC816
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 16:34:40 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-47686947566sf89154291cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 07:34:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746542080; cv=pass;
        d=google.com; s=arc-20240605;
        b=fyI/wGUSg2kgOwmE3fcjIqwGM5EStx7z9X8H7qGr2xukaYmcUx2gRLGTxRfVBOJroY
         gOjVUciNNb13+CR+SE8s/uETLS9ewgONx2xtiHBb2jkmwYBGRuTTwWfSFwbRzhucsUHE
         TAlyeDLsDSGG7CRxBE2CnVNLwyO1WzPApWuYZ1wug1uiULEz7i4C1IpMkG0xzB9YjfjP
         41++PFU37zGRVZgZyk7gVeeyfT6K+u4BLSSOEq4EggDZRPLiTs+hhTEMjazM/IlA4i+z
         OFGKD2mjGuuHlNYcfOADw4IeD1wjM0dX4SahJb1WneQpz+ubDjYRxsTt/VTaDFIYd/Lu
         NG5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=aGwDDOw00dJYr7uXsLBNEEqwBi2fFObFoCvbXHgRLvY=;
        fh=Pcsxadwyj/Tc5mrR6LtkuNGNgf7c7iHrKnUGZYsVjE4=;
        b=Xm2dg1YCzSLLifqgoZePLpwnuHZDr0VQ46Z9Nmgwtj4FQQb1OL+9MaF4ijaoJjn+aV
         PvQm3sXWeso9P6rN1cu/1WSVhk7NWpRfcnSlNpysx7ISBJ2K6oBDae7vwR30Mg5DR0wf
         Jd1ABsaXB14O4JWTNUgRmZaLnpS1u3WlUaa7l+wQS3Hm+vRA+NDUeG1iuNt8AW6+n0tQ
         pg9vbcxKJ7loilfaYYPSfH8iZ20PPIfj2s+PtS8mCPdZvgvqYZtBp859HnkK5apefyD3
         3qh7RS+sUgPdk/wB4KvlWtc2ymCWPWZb0ARzh2Zz4bZFz6mXnpD3a5LEUvNMi/I36p0O
         JUdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jGVKoTB0;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746542080; x=1747146880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aGwDDOw00dJYr7uXsLBNEEqwBi2fFObFoCvbXHgRLvY=;
        b=pEhc+P8JZHud85VmHVAPK9rzfURdD1RrGC2FDt5Dml+203CIx25DEoc/dsWJeRgoCI
         kMXoZ4uQy0dYMBfN9lydj59VigWVuQSVvsPTKeytjukej2Jgh4TognKkWnPR5kxUdBjc
         q+bnP7LA0iZO6t8bZGpwlJt4Ivgg/hBdJZzQ5yv9YCgVQbX1GcJ8LJlYA1W+Rvxpqerz
         Jsi8nBWxkvhcPOjPb5tLgUludXUI/y1uU5CWmXi7l8lfkrNlcQi1sbEotxSGeHZxzb35
         FUOpWp1JvI3FY05Hdr6yh9EvBCid92Icf9/0qhRMSaxSq2arNm2d/SjUX/JUrpM9ypRY
         VwgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746542080; x=1747146880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aGwDDOw00dJYr7uXsLBNEEqwBi2fFObFoCvbXHgRLvY=;
        b=d9iB1iMBeE2El4X1l5YXVp+R9yizkklmRVeaH9aCNOH3jZm/nC1Dc7yUD9mgFmsuSs
         h/l63MRBKswmY713OTD5pAdX25ykd0AiAbQc6uXg3HG8VG8zrSUVTkj9f2Py5H1gu5aD
         lkjJn9H95NhBa6jg39LX6Af3c9r3wtutBTvfVSz/bCFIn546NkD7Ltfe+ZS3dtQeBzdy
         yS4ZHJP7mykpJe3IicfJXJtSJnlgIL+fLdO1KE++wK0dmG2nPruHZD2z6cGPl5zsqB35
         kVMdrPE2bHFYartUlwn/szTkSKvXPccB0QOW9cnASbxWt2Zd3nA+g7hS8Wsj35UwwePG
         gbAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQTzKZVeKLZ/YjZ48X5zjAH635C6mZtREz/tWG14JaXw/NTB0r4VksGYgZ4vQk62tdFPau8A==@lfdr.de
X-Gm-Message-State: AOJu0YwjiC7Ei42s4p0/UrTeWZGe+zrVp3kj/p3U+xHDcuZRejJQba8o
	MY1JCMAd5K4pVw5Vkd5WIy+eraWnGZxqJzoCnLVEM7KRVoZXcFFs
X-Google-Smtp-Source: AGHT+IHQbTE9dpEB4bcmMFKGETgeBFA77uRSTCy29RsgN8WtocjeKj3ZiFoE54pzupDATqqCklU8kA==
X-Received: by 2002:a05:622a:4c12:b0:47a:e6d1:4126 with SMTP id d75a77b69052e-4910dee5c8fmr46567411cf.39.1746542079581;
        Tue, 06 May 2025 07:34:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEF+zCxnLutEjLqRVsvXIILz6hmNY4BsXi9scpJh5wy9g==
Received: by 2002:ac8:140f:0:b0:47e:c189:a7e5 with SMTP id d75a77b69052e-48ad5e16e76ls5528231cf.0.-pod-prod-02-us;
 Tue, 06 May 2025 07:34:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE1Id7LAZ2cY8Sne5reyomfUffQH4BpV7ghmZYw+nQ1GmkmPq1U3S5L/DHnuFGNa0uKW9+4bCLgQ4=@googlegroups.com
X-Received: by 2002:a05:620a:d87:b0:7c5:95f0:e776 with SMTP id af79cd13be357-7caf110cc87mr491071285a.1.1746542078391;
        Tue, 06 May 2025 07:34:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746542078; cv=none;
        d=google.com; s=arc-20240605;
        b=GpTUex6kPEeepa0W0bumyfXW3R6ktU1bmST5Zu1iyST54VZ/JyUN+EnW1cfHRrumCc
         hPnNUJz9JHii/kNU7vNvz8LJgg7CUyiBEdivUP1Cm4E3N0LnZM7QmHTWVji+OSqZStn/
         r7ryN1W+tfyiFwzXh72us3t/RQumuh8zDddfI/xYBDEVNmohaWRkSoVf2Q0bdk8pheka
         cc75SJX+NQxByx/pasw2xvesjtH2Q2nJJe8EqkH9V8jnaFDmd8dKeZn7/htOzKuUYdjT
         +zHLLc7FiY66XO8GnD7lvlKHcJEY0Fx11XoU+EMW3quBY2jjDB5L3DT4eFlMaCjkBxrM
         1n8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=P1HEbEXaAXq6YjuhmpzawJS6s779+xGQD/mE8k/wkYc=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=BrEm56cvIUbu8Gwz8lZ04aEWkrlDcuXFcVKs8M86JecHfxeuyf8UbSO8sxLmvgByKR
         g9yFMplLYy3zQkVtOEyMbPyRvUSjkGBpYfosd8KGeFimoU/vHiP0wK4QHOW92iAs4tW6
         nSST/cP/aptTaLKqMRAdZtTyaCP82w90r7qSNbzywI08Pias+NGFvdQhK/leh6NI0oS0
         SmgoqmFMDPSC4o6jK+4DVj8h8slInaLXwvKz3MrfSU9LSJbZg9Pq5cjCzCsRlzim+9gO
         2Gbh8pVeq17X9jrkUWzfU7HCY3SDMSe3dWLwLIxrWk+8d10VsCKrmiawFqaFXvjetJ/P
         Q1QA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jGVKoTB0;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7caed12a1f3si3586385a.1.2025.05.06.07.34.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 May 2025 07:34:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5465hctQ009102;
	Tue, 6 May 2025 14:34:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fcgy2bu9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:37 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 546ERFuS013894;
	Tue, 6 May 2025 14:34:36 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fcgy2bu2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:36 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 546CD0jU001324;
	Tue, 6 May 2025 14:34:36 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 46dwftc3fd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 14:34:35 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 546EYYca49152342
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 6 May 2025 14:34:34 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5606A20063;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4093F2004D;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  6 May 2025 14:34:34 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id EEB42E0573; Tue, 06 May 2025 16:34:33 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v4 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue,  6 May 2025 16:34:32 +0200
Message-ID: <cover.1746541531.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: uFqZjkkvfkCALI169ewjM_NkFtZSpoRq
X-Authority-Analysis: v=2.4 cv=Pa7/hjhd c=1 sm=1 tr=0 ts=681a1dfd cx=c_pps a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17 a=dt9VzEwgFbYA:10 a=RptFD5b0m2ehXSuSLUwA:9 a=zZCYzV9kfG8A:10
X-Proofpoint-ORIG-GUID: dBOwxq5Zu-yxd8jD8_HyA_Y2Cf6w-Cu-
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA2MDEzNiBTYWx0ZWRfX71srGyKBBmvi ba7S880O+LNEdssjIk/4mYZeG0wY5Qa4MKBUEWBVYgIeyaXov7YR4pLNodzFXJkOUH+OwOrdzRM 33eM2XbzElWntFcpijFtHEmjJ/hXZfo2r6LwuuuNlACnVT9z+Z6/ZOEIRAcHHK77DTCA2gQjVYm
 5Rv4eSHKVedmiyyQVhxL4vnGYTCQfmItzru/4Q5dmB/6rpthiiuKux8rAd4bmEjnkxAtrsS9CUG BsYaspcRCPfeQ7PBx6rOQqCBxBi1mSCtDusSOBo4xf/DPi8A1HHxd/55RMSRHI781jalCs/vvOn WpUVOdPylq1Jbn91TIpKpiLd8tM7msv9QeaWoPJMaUAPx4EhkoZlxiwVoHRpSFI+k26IXbtXBnf
 I7xr0Bn2kb+9GMKg0sYaoB92/QU1O+ndXd1Ubd8jFH4loUIB+3FzDVbGyEkqyNvR5v5uaibM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-06_06,2025-05-05_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 suspectscore=0 spamscore=0 bulkscore=0 mlxlogscore=529
 adultscore=0 impostorscore=0 lowpriorityscore=0 malwarescore=0 mlxscore=0
 phishscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505060136
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jGVKoTB0;       spf=pass (google.com:
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

Hi All,

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 63 +++++++++++++++++++++++++++++++++++------------
 1 file changed, 47 insertions(+), 16 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1746541531.git.agordeev%40linux.ibm.com.
