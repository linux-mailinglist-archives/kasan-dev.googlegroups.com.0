Return-Path: <kasan-dev+bncBCVZXJXP4MDBBCNN5XAAMGQEMZE7DSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 17BD4AADF9E
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:48:11 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6e916df0d5dsf120623336d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746622090; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y/G4TKTYyvoh0e+oGhNKElRU1SNdhMC7eUjWphNqtvOZHOZTCXvEACnnqQvaqMyXAZ
         M1CUpCIjlXxD17rlSeKfnnhSvG2Ku3RpLC2F38pd0zSpiysRweKWHBOVcKU6rpMlM2eM
         JFp+4fJdKn+0CL1SlI0+1H2of3nnR52CgNtWXIokNxaG7I0kdQHlP4w5T7bQ7+mvETdw
         QRp7iJGGmdYvf0pHydMCT5pqWSGpfFLAXIZCy+l387J5SzmIW8klkrpJK4Obj14Eq4KY
         IIwkDrh+19eCMjMhNU90GbBXKuxFLfcKu/NrVYdn0G5C4G/fNIgwm+Pnb6oMFNYfgQmo
         4XdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ROJiXxR+/QIs1BuwIgbS98hKSxIO2fKNARVliYZ64YE=;
        fh=EmSe+SJAqikAxhjIweqOhGAScDL39P/k/navt1AF0jc=;
        b=EuvRA8u+3qHGKAi59ToBv47bE43MFG2FHX1Ea1eHPQYamgFT9jQLflSrwJtyKXyeNJ
         udWU44hhuam4vbn3kNJbD4lXEZGAUmK/+/n/DJEgaTw4xdv9cYuV70Pe9h5j3Y0ZIKxe
         cZFeS7iSH+y2K9lkNuG7Rm0sdaFmpCTHf5pm13kXr0imHv7Ppb/oD1+QglqGYMMi3gBO
         W2msod/7dQFrkbkvkC5wAuPul1xkeerC0uy/6dZHPzV2TBk2qfMQZRO2D7/hmIAUtoeM
         4b2HtYAYB0QvC9BYfp5/lrzINI96ipaCppMnvo/7nGsgmjdbqpBcM0Ly7ZpjR0ZIXP6S
         LtKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rNbcqNXR;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746622090; x=1747226890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ROJiXxR+/QIs1BuwIgbS98hKSxIO2fKNARVliYZ64YE=;
        b=YSH7+akLvfWsgKYBeLLZg6qcpEe9c/T/GAwKLopocAUlUIpLTw0TTA3g5NIKYOZhHn
         E5WXy99vuT042u5vQheJquBPT6YTsoGoYc2xEThOBw9wKazqG9MGE4so3eXqfquclw62
         FCZeW0S07eWtjNIYslBoWHXuUN3ppG2gYlflk57bpjQ3vRHhHM/3+V53NNvgQx26BmvP
         DUS1CHsWg7smMbiScv3WYuUNqgfwoZl7rKj6EmmpGus7tbWfDtxniSf/GAkwB7rVYIQL
         yS07i2qrE72uoDW1bB39CugEISU3BRLeXC5Su18stRzn7aalmumEbZ2i4vRN6ggmXueW
         /8Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746622090; x=1747226890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ROJiXxR+/QIs1BuwIgbS98hKSxIO2fKNARVliYZ64YE=;
        b=LuLlhBouIIr8fPh8cxWlz//KdnHgi1dsk2+zsIh1HBBgkByuKgjEheWqn0CkBnl3PS
         R/131138Sl4x4xK16N39gp9/J0xFbJMPpg0F1U/1MilGLqt0dLXtOBsZm75GARbsaR8M
         hgBK4g0pVPV+rghj2a7lw/+Oqxi1tJc4uLnsrgHmCVWWDf7pqFSkadlDjAOvg7UknRK2
         tYq02Jhfgi5SNQUAv9uQTRjSJjlA/OQld5Bhum6V4oPmwvED6JvowyP8KS8zhj8PTzy4
         +tBmiyaI05QHvAjm5ZYzBr4ab4QIRZOPCeAqgvBhgzJdqdeLQQG0ps+I/VovAMvtujnz
         ABZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWpm9oy4j/FKajppoOug3BYfWTPIKaONFHUbV+albqj1rqxSB6DGpoqnWqWoEDRuzvNs+Dxfw==@lfdr.de
X-Gm-Message-State: AOJu0YzofmNnLqqE9Tue45qhomUQYNaA0I4CTuNdPVQD8gtJ/ZTPaE8+
	tI7fZqxcdvgAUrIKLSvgWLH7OBjpsgXdVetLC7iXYD0oAYnSuU4O
X-Google-Smtp-Source: AGHT+IHA6c44il2sYJhk9oeSY9V7wpDYB8M8zlF4jYJxGSM7KNB+YdtfZohq1l0cMEjVTU8K7y/Q8g==
X-Received: by 2002:a05:6214:c46:b0:6f2:b7cd:7cac with SMTP id 6a1803df08f44-6f542aedcb1mr48263046d6.31.1746622089775;
        Wed, 07 May 2025 05:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGb4rHGXRCjc3xkMmbqQT2BJ6iyE+7HDvTApZSyEUc6oA==
Received: by 2002:a05:6214:5018:b0:6d8:b1cf:a07d with SMTP id
 6a1803df08f44-6f5084f544cls13705556d6.2.-pod-prod-02-us; Wed, 07 May 2025
 05:48:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBkyimn63EROOYxu5NAAVFSrZ3vnwRw7iKROyWJpA8A4jnJehGw8gB40BIvUXsO5zxT3E8Rcn+dpI=@googlegroups.com
X-Received: by 2002:ad4:574c:0:b0:6f4:f1aa:bdc9 with SMTP id 6a1803df08f44-6f542a22256mr52392606d6.7.1746622088948;
        Wed, 07 May 2025 05:48:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746622088; cv=none;
        d=google.com; s=arc-20240605;
        b=j19LCLRKA0jH8qVrZNyW2by0ucR8g4v2Vze3ASXYyLFjxNukN/31bTH4qWUFWVuw+d
         9nvNJgLDB85g+hw6zJY2oIfEieDWejymTuuVsBzCycxwt/+djyG5RyO7UmUJvEzd1oc8
         gtImlEMwSADpZS3i3qrXkgQXdor3HS/OJJjIVsiMQFlke9AnSThhAjIcbiYoN+quYoJQ
         QrTQGTUPAMccergDt5DFpsjX9i7jE0MVivfk0ExXKt4KZWqvZArT+8pAzhZmb+sOYSkY
         bXRiAYb+5c9v9x8b+bsO6KLueA7vMRBqfQr3McQ0PHifWkoI9HYPqJUCEx11+bQQ1pTi
         g/7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=0bF/6bqbsMkdjnuADJ5ycDEUAyKEb1tjELJNpbapAfU=;
        fh=PDtkZ60vgbzItUp+wpBrqBnVDtM+Vmj45Ev22YeG4/A=;
        b=PQJbLHBo65QrpNEyb7gYX4m4xbXVL+3/hm2FpNB9PdAKn09QeLenqWI0UxUyEUu3C/
         hLKuS1UwJtrjO9raB80xhotBJWE3hV3SptoUhZbM4u7JnY1WYIGglHpUNIssfhnJdqys
         1Azedktb+mhZsZEml6i8Gq4rnyR08Q+LH39EfvKJPuUyNQAvc8dtp+WDnxg78fU+VwUE
         t77FbbDM3MTF3AArIf+f60LuW52lwYL6wxmm1zuwEnCrCJUjU8CbQrn9uGaNq4OmmWm/
         jGem5qEnUYmqiq/5yc/h6f20QS0QU8zgi/9XNLpUANUMNnjKEamPh7kgm270iNDhHrT1
         Btag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rNbcqNXR;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f5427afd50si744046d6.8.2025.05.07.05.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 May 2025 05:48:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 547A4FjN012177;
	Wed, 7 May 2025 12:48:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46g5ejrquv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:06 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 547ChJjD002761;
	Wed, 7 May 2025 12:48:06 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46g5ejrqus-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:06 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 547B08MH013765;
	Wed, 7 May 2025 12:48:05 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 46e062ga98-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 07 May 2025 12:48:05 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 547Cm3ER55378276
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 7 May 2025 12:48:03 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A03CC2004E;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8CCF620043;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Wed,  7 May 2025 12:48:03 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 370F5E0610; Wed, 07 May 2025 14:48:03 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v5 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Wed,  7 May 2025 14:48:02 +0200
Message-ID: <cover.1746604607.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=SvuQ6OO0 c=1 sm=1 tr=0 ts=681b5687 cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=dt9VzEwgFbYA:10 a=RptFD5b0m2ehXSuSLUwA:9 a=zZCYzV9kfG8A:10
X-Proofpoint-GUID: ls0CSTEdIVroqRAPQ4MRaJy_bGIyuZkh
X-Proofpoint-ORIG-GUID: w76n1Ot5A2NfAgFq8dUBreGB-wgkHpPu
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA3MDExOSBTYWx0ZWRfX8fftuVRzpHmz C9OXZDcMi45ugFCLH5H7G6/lJZsCvwZDupHonClR8qSdrvG0sBJbqM0F/OrcCod5exx+Q8Md9Lw 5kSuOTzLLR/ulJfXkDqEhOMoDr6oJy4QlL3eQ67PM2fPPu7Ry0JSXH0e9gtBPkKknCfnchdYQyT
 sNEaur/fRmK0VjRgQ49JYDrZyPS2Hl+ImVWP5YKGeI0khECPbvOpSE6LZy/NWpygtwUSSdwSsTI ce35Cf76owiXIFPhrfZcfJAHPNDYfvI8dNyiBM92S62IqXWp9cgFOKo1TrLmAEsxQVcOSiTHHHr klmf5Rt4SwNECdv/XL6bF7tcpiJ7kZuFrOKOHJLsmfmlxl4rTqn4u3UMzMFrdYvFws4TyHwZuRK
 1jEI5U9u9Dh5OCQrtWcuCNp2T4b9khOaBlbBrfGI1KyVQl8Ry6PGob7dTc5u0B7vVqqLXEXy
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-07_04,2025-05-06_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 impostorscore=0 malwarescore=0 bulkscore=0 mlxlogscore=555 phishscore=0
 adultscore=0 priorityscore=1501 spamscore=0 mlxscore=0 suspectscore=0
 clxscore=1015 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505070119
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rNbcqNXR;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
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

Chages since v4:
- unused pages leak is avoided

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 63 insertions(+), 14 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1746604607.git.agordeev%40linux.ibm.com.
