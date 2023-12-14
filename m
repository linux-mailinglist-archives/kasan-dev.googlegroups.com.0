Return-Path: <kasan-dev+bncBAABBE5S5KVQMGQEPQ66JNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 64613812730
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:36 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-425f0ab06a2sf17160761cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533395; cv=pass;
        d=google.com; s=arc-20160816;
        b=klgpz7A9YXQYEyEizIjJxtlWw3uPyqvdrAmbDiTHYwvoj5NPOEdnYyDnrfnr9VSlnO
         Uxwbo3o6S3IAiALfBQXtZXHUDRvxQvydcZzHX7NILcdKbYOsWjfwhQbzKhziXm6AXk7a
         rnfAGVQFcuB5y3LVoZ22vr5Mw0cU2r0Bn8orf4jk7TsB7EQyiDohiT/RPZ3wNdE8Witg
         tyYm6KqqaXAvgzeuuuPoyBpGEttZuFt8VeR1ydUSLjb2c35QLyO300ywbPyXwxUx5oRF
         wZkkFk5GOffXz9HRhQTmSjKsijEPNNJbDRtZTkdBtWYuS7bQDyxrqWFUWBWkDsBrSwpa
         S4Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pYK2P1kd895yB9B9XnLT4w7/RvVUUB3vxgToE4xfcl8=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=VfGmD7Uf9TAWLcTQGkBiRHjukCn30SReVe1GTtZ9Oi/nOqO1JRDBWO1HmAY8RO36af
         f3ZBufM0i1dg3x3u1AIOehwZrlwuwl66kc+DaAXAV/qvd6QPvKhxGM0EVmsqKnOQRSdF
         vOv77CJdHNStBTqptEeCk+umGKbujLCttcKHEW9oLPdaBGc+uP3l1OELBDoa0H0qYwWp
         +yCLlAIlPquyaRpAWa7nYUMR1rXrskOGQG4iNqnE5HpokPqup72bVbOvBCd7VS/aXfrW
         Oq1R0qJiF7QKo/D/i2DU5bWm1SWECLsXeotIctIBkzPx1pAVSJDi5j39jxeUN7/yf9dn
         4s1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SwdBGUd0;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533395; x=1703138195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pYK2P1kd895yB9B9XnLT4w7/RvVUUB3vxgToE4xfcl8=;
        b=gigVLqd6DDFME3VXB9wsNDD6qRzN9i4CFzzBUbZGuG8+da+SnJsiAaPAc+p8rrkai5
         pLvqKbICGzAG4QDGiwDwUSmceYpgGnHuQAo6Is69yXTWycrlyzhqiz8+7nL1S7mD8Bab
         z3wkxEojSrXtRDaqfelpLaENIti9jTe/7xbFaLdypa6zbYnVo/sNck1ETBkcM9SRseH4
         /RtuRBOm5azctvx0qdVtV2DTQrlbJrLC0hdCcvNMJdWLni4oxPs45UY0p6sFA4VyYdPm
         LwXnV3lIzMeF1JK47Fj3hMHjzn3hUk9xY1mTJ8dAm487i/93EkkxdgbJK44N9z7maBpz
         p4CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533395; x=1703138195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pYK2P1kd895yB9B9XnLT4w7/RvVUUB3vxgToE4xfcl8=;
        b=ruRvgMLGDYhepbl0/OCjRaXcHvYr6gKp2F3lQtzeGCIskil4ZGCOKMsWi5rQN6AI3r
         q12VpsfcUxpLSg3BSA2oBxjk/eXrbPNwzkrrpxXI5z/+gW/O9MLvVvPl7zipsm3oDjnQ
         cVKStvM3ao6W85sYIYzCTbuRw5uJ1s1w6Rptgw4Xy/slezzAjTz/ZPkoxtHVO6WwOwyO
         /x45xxqHQVaUS8J++sxCDyp2fX4t0Hg3JGVImu3FvGFt6jI/OxwLumALhLBOZcUunxTj
         4uEg/aI9lu5Ifx2tWHO6aahUzo/VF5GkPgn20vG/FBA8W2SRvp3r5Fg7P7NmQGRlj8Gq
         FGMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzZy2eCCRzPz8lsgjRByhRtpi3bZkZqcvZc69dKDTqXddAcdime
	hAJxz8P4lEpKlxW2y4qTy1Q=
X-Google-Smtp-Source: AGHT+IH3saja/TJLYMwiltohOb6WiSHe1ZZFst7FGtV6033oaOMU0lqTk6Yj52frqfK7+v5OT1pJ7w==
X-Received: by 2002:ac8:7d03:0:b0:425:4043:762a with SMTP id g3-20020ac87d03000000b004254043762amr14112088qtb.82.1702533395396;
        Wed, 13 Dec 2023 21:56:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:651:b0:41c:d096:577c with SMTP id
 a17-20020a05622a065100b0041cd096577cls1644346qtb.2.-pod-prod-07-us; Wed, 13
 Dec 2023 21:56:34 -0800 (PST)
X-Received: by 2002:a05:620a:1aa3:b0:77d:cd94:d06d with SMTP id bl35-20020a05620a1aa300b0077dcd94d06dmr12492048qkb.17.1702533394728;
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533394; cv=none;
        d=google.com; s=arc-20160816;
        b=EUpc9JyT0i6u0AfSgCtl1Wcu6ZyRP8r9WW4hQuDvcK7oC43NrrP7J9hbTEQyNzi/9X
         gzv2N1DI7feai1sorOt5/P7dPGS6OBMk/AlF+kv/VX4CG/uLZhPn3/f+VL6FZVaErJlw
         sxG1fgySyBklZrnc196LIbTcHVy3RQxKRFMtekIkEiCGdR8s60qZLcziy89w5jB+MK9Z
         j179luhncUwsyUOf5EI9mO5B0l33sBEZ0rljuhfkkPX/AJpZDdgHWilHfs9QZjoWPX9t
         VsM/KReNNYgyXue+RDMzIePTaW9SIvr4Vj8wFrRqu6YlcNKHNzyNjV1gkZTuiP9/lJ7c
         7lpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GF2Xu/3fsj+Ht4rCs+VhFbW/wtiFglmqBDtbXn8HHOc=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=lxZP4lyIovb6f5PPT4aGnv0duvwiMM+gGuIA2wuu8UVHg9TTZWLKv6Ln0anf28rJv0
         TOxyM/bdKVN0Hrk0TnX6BGBpMWyTv/I8pif6gGG2ZCsgXzVETNZ4BPe8JQrgUShRb/OI
         pE3tnT9528GJDGjfIoLLf+1MSo7Sb1iXQk3i1sAyT6b9aOoQ8n5DRY5FNMI1fj/Syp6w
         vpa8lYwXtpekUd45BT8Ku+dJwvNatJxsqdqEzHNmFwFowYeFTYYnqGNViNy0epSPvYYL
         aeH6glwWHutzMalWAy5QvDFBfY331PKQmjBQh2WjpC5ZOHt+OO9bnN6bfYRSRIA9NnHY
         03VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SwdBGUd0;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id i22-20020a17090ad35600b0028ab0a6ab92si606390pjx.2.2023.12.13.21.56.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5a4kW018124;
	Thu, 14 Dec 2023 05:56:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6eue-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:27 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5ociZ021637;
	Thu, 14 Dec 2023 05:56:27 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6eu0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:27 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE54w49004701;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skp2pg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOmJ22151738
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 573E52004E;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DB8CB20043;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id AE47B606E9;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 13/13] powerpc: Enable KMSAN on powerpc
Date: Thu, 14 Dec 2023 05:55:39 +0000
Message-Id: <20231214055539.9420-14-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 23zToPJjHl0GSX_OkbvlWS2lZi0gZcXD
X-Proofpoint-ORIG-GUID: P3Ndr46Urugrxan-s5l-A1IaBDocsq28
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 clxscore=1015 malwarescore=0 bulkscore=0 mlxlogscore=704
 priorityscore=1501 suspectscore=0 phishscore=0 lowpriorityscore=0
 impostorscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SwdBGUd0;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
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

Enable KMSAN in the Kconfig.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index e33e3250c478..71cc7d2a0a72 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -217,6 +217,7 @@ config PPC
 	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KCSAN
 	select HAVE_ARCH_KFENCE			if ARCH_SUPPORTS_DEBUG_PAGEALLOC
+        select HAVE_ARCH_KMSAN                  if PPC64
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_WITHIN_STACK_FRAMES
 	select HAVE_ARCH_KGDB
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-14-nicholas%40linux.ibm.com.
