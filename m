Return-Path: <kasan-dev+bncBAABBI5S5KVQMGQE2RRWIMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 405CE812736
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:52 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-dbcca990ee9sf1933072276.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533411; cv=pass;
        d=google.com; s=arc-20160816;
        b=MXZXrtQgPEX8FmSl8qsqGg3g3I739GkcYQuadPhUO4ZjRmk3+bzfSeSQkykl5KMYUs
         Zf1jhqnYzgmOyeGRyTiG/FEHvp+Z8Jw/Bnlfw2xttsu/FoD5RlTgilrEPMP4G5PCxKXc
         peZZIou8Tl+LIE/QJXO5Vt2Ig/NwrrUj3t5VUUoZnOGYZA1EU9pTXgSXj+T18M8bfT4H
         o79QiequdmAmDhMVg5IvD0+AzECMZGDVeGpjMM5+U58EkLgz1sWU8A1WVnSMKZ5a9bQg
         1yi/Lt1bWiF41WG54oXRaZvQzvdI33F2L7U6CJH4izktHCWoeKBunpL0wvidANb4w1+q
         qiJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xY7/Oi5+fqJAhVB/qobRiYFaAn4j9ORHg8XndJsAQh4=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=GO9Sdl6IdSMWAOn0rHp5vNCWztiw5es93ooF445sJ/pEz2pikb+xacu2L1RPisL+Sg
         piSLIfyi1Hg2GihVNV1uolC44UUariUazzkoPsiS+erm72u6S831+20vKC/yY4Xy7YXn
         A5xqtD4TJxKjFMkFTQsnkffNf0cQFeQ1mWFVGOkMEGhp+I3UP7zVz55+fpSz2V6EXxDA
         MwMpoIlPcSaBKy2Bis264fTbwiKLd9reecwN2+5isAq55jth/e0GipYZMZfA60mgnEuU
         dNhQve3sTZpFyhV94e5KFPMHAVIuDdPCSq0Tv4k3/rlkJs9LkeDkyU9MHnMw/tEtmsWy
         d2gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NofoJehk;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533411; x=1703138211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xY7/Oi5+fqJAhVB/qobRiYFaAn4j9ORHg8XndJsAQh4=;
        b=vnBUziFSjTWGA+UsLBkCkuc6OOlvTO25wd20NinxLJfiNp98j7EiTr6wgIIIbxFs8d
         zIhtvs+aArirSki5i7PUneziRr0ghFCrN7I8CPZWe2pRqvxJBMxRy23/uWNeI9zeclRj
         kYyKvMnB5Vq2mW9j4qWpaGQvWLspL8kahyVC+UO/40wbzhiBk9W3puUNpHSBUV5VJEvc
         k3NnFgrmb7nFdI06LwVdJd3Oaq5cAxmI0AfKie8cnhPE0j37BvIyK7MGDFJsXSp4d76/
         kM6+Hhsh9ckHkt67f/ihHzb3uPHP2AHjcXOCSNhAmAlEre986QkLGZlG1egLMY7L1FD3
         SIIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533411; x=1703138211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xY7/Oi5+fqJAhVB/qobRiYFaAn4j9ORHg8XndJsAQh4=;
        b=h52YlAj54/Tyn8XzT4sDlJq25UtoNTcZS3UsX58OgSBNItC1VguQxO3NXI+cIgf2HS
         gHboAT+FL/k0zKJk0fBIcUKZ12qf9GFQs9+ryGbeuh0vel0qVSMTuOjQ2h3tPSPzFwGG
         QsYNd3ICPWAw0CFR2a2VjZg26D5YBTB2dySxkWSzQveDKD5WxiW/qKEZ+5827xQCoX+h
         mb5L1ZBWtWqro3kVhz9LaSfO6//2DbfMgZEkLl/eGyLBwsgzquBZLCAevnA8HmDBWuPN
         BF0nqow9LvMDJk6TgKsDu0WNVZ5iS2qq6D3tXRf27sHss0b18zU68TnbkAUVXDQK17p1
         aDtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxG847YeruOf5TBODTzt5g54v0zHZrmx+5MTRtfVHFcDJwvUsOf
	e79OHfHTR9uOzPB81HiBosg=
X-Google-Smtp-Source: AGHT+IHyiynfi+2oAu+J7ea/9TJS2KvksjU5ZT3cY+gzOp6KM9aaG5kgFrKgz4hkWrypWEno8MpvxQ==
X-Received: by 2002:a25:a1a1:0:b0:dbc:ddea:fc27 with SMTP id a30-20020a25a1a1000000b00dbcddeafc27mr906882ybi.131.1702533411123;
        Wed, 13 Dec 2023 21:56:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b0b:0:b0:dbc:c4ee:5ea3 with SMTP id 11-20020a250b0b000000b00dbcc4ee5ea3ls1198713ybl.2.-pod-prod-01-us;
 Wed, 13 Dec 2023 21:56:50 -0800 (PST)
X-Received: by 2002:a05:6902:9:b0:db7:dacf:2f1d with SMTP id l9-20020a056902000900b00db7dacf2f1dmr6091325ybh.100.1702533410425;
        Wed, 13 Dec 2023 21:56:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533410; cv=none;
        d=google.com; s=arc-20160816;
        b=uoKIa80+xknszo+9Z4zMkLc8tec4KgjkM1yQTIy6Tn6Xy8qFFMSTPJWiD8TVe+VEr7
         I3OluazSUjS1GushGTxfVLw2vDgi8EhM99P1sMRKFMunppfew6/8qVpt6rlvWZKf2pBO
         jb/Sd7D5zVP9X+cgOW7pTqqT5Ths1DRlnxGs0GT22P4qqEe0fwjmCIjV+6UBH9jsL1fu
         Y6n9Zm3aw+kaU6iEYrLUb5u6Lbml3zz/tk3bPityRyDA4Wk1KrwMznc6aQi0LzEepkXl
         Y1Kuo/1PVc3xmRZbw143MEb0xuhXmiWc/1US65IJfsAJi2CxMAn+QSh1TNZ9ZBI8kAF/
         zCfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4DZJYxEc4SZaDH8SYYalzXsdURynFs6mETQ32ZgpxKM=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=JFNQTtWfzSxjUGpeOfyoYciwxVXFOjNBLM1Mt88C243BMygRl5fS2eQCZK2p7Dzav6
         Zd0PPv/8J1L8XrTXrm/dERSFlj6W2B+RQ01wlTrwKJls2GRQanOXsxbtDTkYPxXDAZKd
         Ncl93+RDRvP2w99TGkT0RD4vFn8SLVqrpKWhHDS+rvn/2p+kikAUtLlk5Ova/sR3dVsU
         +dObDaqTlyfF2v3p3gEbsmi4doXSeWU23PHUnMuI+DlnmFCJ1lHSHpuLwTyZoQJ4LTA6
         b9v2de+2NmidT/7ZWHOVHmqx3EDVUvpVekP+vrsnFFi54vBePLnajmsNopyKsBz4S7m3
         Tv3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NofoJehk;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id f11-20020a25cf0b000000b00daf81fc5a57si1667033ybg.0.2023.12.13.21.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:50 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE4nXMv016537;
	Thu, 14 Dec 2023 05:56:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyu0ys81t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:45 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5M76w005673;
	Thu, 14 Dec 2023 05:56:44 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyu0ys7xe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:44 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNcC4M014824;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kggr4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOeY55116242
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 020E52004E;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 87ABE20043;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 8575F606E7;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 07/13] powerpc/kprobes: Unpoison instruction in kprobe struct
Date: Thu, 14 Dec 2023 05:55:33 +0000
Message-Id: <20231214055539.9420-8-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 3Us5CtheJoZjlpslVofjgPDJzZ6Fl4Vu
X-Proofpoint-ORIG-GUID: rBBFY_dP7t41UbfjaY26lzdS7EmDxzzd
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 malwarescore=0
 bulkscore=0 suspectscore=0 mlxlogscore=711 priorityscore=1501
 impostorscore=0 spamscore=0 phishscore=0 lowpriorityscore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=NofoJehk;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted
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

KMSAN does not unpoison the ainsn field of a kprobe struct correctly.
Manually unpoison it to prevent false positives.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/kernel/kprobes.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/powerpc/kernel/kprobes.c b/arch/powerpc/kernel/kprobes.c
index b20ee72e873a..1cbec54f2b6a 100644
--- a/arch/powerpc/kernel/kprobes.c
+++ b/arch/powerpc/kernel/kprobes.c
@@ -27,6 +27,7 @@
 #include <asm/sections.h>
 #include <asm/inst.h>
 #include <linux/uaccess.h>
+#include <linux/kmsan-checks.h>
 
 DEFINE_PER_CPU(struct kprobe *, current_kprobe) = NULL;
 DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);
@@ -179,6 +180,7 @@ int arch_prepare_kprobe(struct kprobe *p)
 
 	if (!ret) {
 		patch_instruction(p->ainsn.insn, insn);
+		kmsan_unpoison_memory(p->ainsn.insn, sizeof(kprobe_opcode_t));
 		p->opcode = ppc_inst_val(insn);
 	}
 
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-8-nicholas%40linux.ibm.com.
