Return-Path: <kasan-dev+bncBCM3H26GVIOBBI4A5GVQMGQEIMROARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DFF881231A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:09 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42593d04ef6sf60337421cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510628; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvIFKr4YTSfrknp6P+kQeZPeprrdEVUiWbh2qmIg/RHX3UhEt4m9ff/GtCZAhzyTan
         WQCQspen7JIPO9OfYa24D45z7bT6IQObG3tIVOjIThbNg1ACdFiyGyziC8Pq6CEOvi9u
         uT/XTPLVoE+FEpZo1JBYoNiFohdVu9DnWumtOkyzliTdZnd7BYR4bJA/0hsUD0a5x7hE
         mfNIC4tlYcebFEchyqkgxn4J2eScjB5zP6G3w4itmTzATMCAfrkiR42aye4I6b9k9fHe
         pSpKjwj8NC7T+6OO1TKTwCObB9aAJN0fOoKJAhlNhEIqYvZMaEYXN7v0q63Ul/3FbGxQ
         3ytA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OZ9yoLEkEkg0P/mqgk66JgktQAtbp1w2+JFGQB6/ZHE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Nnbw49CXkBQgBmPkniaXGzjV4TJorrflydNEKbgwndIODrp1E2bpy1a4LUpUOSV54F
         4ggOI8edy4pnXAYUw5gAHz8EWzu4HvlCw11t59erqKaC0NfpP5EwgcNc6H4sLiEpU30z
         QSqM/dFzOvm4mp35QXXXWKKKx/kL/+NzFEUU3cyY+ZcBSW745lB6KSienG64I7lledUm
         2UaY5zSeB3+ckkHKz3Tzd+r8HyDwn4AynAO9I3tbz79mrTTHeK50u7e+IKj6v8HEEPYx
         TU3rtAoPyyvLmgdU2yjaotIwsN8dy3XL3Z7TqmgOxmtYRfkEZ006KV2sEut/johceGJo
         AmfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=V256ksMV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510628; x=1703115428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OZ9yoLEkEkg0P/mqgk66JgktQAtbp1w2+JFGQB6/ZHE=;
        b=vEAeSkITXm7KHYnPDyLkAnM6HQ7DvIdn75HYShTTCPARQtbA+NKy0M6XsuW6bnU+5b
         znQob8w2ECh8F7RKzbpFhROx1xu122+tXE5hE7sqXOSd0anozybsIpVHrtyDZhVIqvQ5
         eUrI7ZOkRtv8bQr7/cTDQLNgMSdlPJYen6Wvf673/Eun21cAUP0EsR4OuighzZRcbnop
         NdZ5ry6OVQReiF8nvsW8YyaVOU2AdSGxFaURzFo446TbS6Mv4g3o1rNGnMxRRvYnc2+s
         2YMUiHXMK66MhXFxWJc6DLRd4Hu7Tk8ZBZ4b+L7opF8J4yAANpy5bCr2LzqH6QUm6oCQ
         dIhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510628; x=1703115428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OZ9yoLEkEkg0P/mqgk66JgktQAtbp1w2+JFGQB6/ZHE=;
        b=NlL8oQ+va0mGa7wzcPBq6x5VX1T54eQZo4LxEy9LobVpEEjI6dmrt6ScceWvCHwNj0
         +SAbRhap2jz5BXMA8d5sNDVNTCOM3wE5bpqmx//LFd4y4IB+LcI9/lDTIr+nQOgf7n6c
         k0bzUbY/Wog6T4pn9v5LXh7skk4G1xo6wCYYR/Ubo/bLdG5+j+3IPItmLoLU63AucJEn
         M44bGCEN5CNr/5BCSx5a0srSPvRUbUv/Iq/91JM9m1xJIVIEEeU2sYEMTenVBk0SHDlD
         StvvKMx2pxKj/M50uDOJ/od7WjlkpRYmSbxofsRAn3G5/CU9vh7WleDUsenQbkbcIGwu
         Lw5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzuU/XBA49G+zN7LEZYxYrRrfbNOdPGDYFq4nKUEpuvXXMHgRhO
	h9krNqET1xxqlot2v/Z5pcc=
X-Google-Smtp-Source: AGHT+IFFD8JIICiYbjnqc/AI4ggUbsq4MZ0hj7ug3diEZKt8w9gxa5bWujViJeUixyV2FKfcUj1y1w==
X-Received: by 2002:a05:622a:1792:b0:425:85eb:c2b1 with SMTP id s18-20020a05622a179200b0042585ebc2b1mr8717493qtk.15.1702510628066;
        Wed, 13 Dec 2023 15:37:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1885:b0:425:8441:6aea with SMTP id
 v5-20020a05622a188500b0042584416aeals876776qtc.1.-pod-prod-08-us; Wed, 13 Dec
 2023 15:37:07 -0800 (PST)
X-Received: by 2002:ac8:7c4d:0:b0:425:4043:8d4e with SMTP id o13-20020ac87c4d000000b0042540438d4emr8949541qtv.105.1702510627352;
        Wed, 13 Dec 2023 15:37:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510627; cv=none;
        d=google.com; s=arc-20160816;
        b=Ai2rO9mVr04inbg9bDggT+nODGFAs+TsastP1AUOXOKJJtVriZSQx6sJKzICFojV65
         M+vFepXvjjFsBf4zfRnzgRd7WVwdg+blaWXK/RSp1IkIw9qQnQPKK57VhkO/VIw6wPqb
         TleGVaiJ9nW0C9ytNP4DNWP/VWdr8J7jWERyYhuggHxaoTfi0vxg4PO0x01kmY3YcaVU
         kCpdz745YOyDe0d3IMTIS1v/WQsuy/Vfht2HoqiJomrfv/kGALHoM8xNgksBG4pTOMgl
         whDfppViuAmZaKDySaL/LExruivQosjbRh02bPYh878IWKt/FLTBoj8PEGdvzBIM2FbR
         0JLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=z5J7brqvs7iQUmi8H9IllLFRjEMOozIzZchhc/zzAHU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=CNgUkRJc4gEBVE683o0xruG1srq9EP3WffRuLpmRJNIcKmwfWLLlLcA+KAaTe+GEE1
         3RlNfAfDoAlydrD/wG8L7DfeXNPzUQnkNtZEnp6/GQgt5VnaZUYfMDWXBSl8aYBFkXKb
         pCtSiNc3o3QUCYgW/sNdjLPXURsjA0UZ6ypLr0FZ2laX+KuLCackvc6jylk1sOTQttSL
         QYzg5qFKx6ZYkq9IAg2SeFGKux7nW/JdNNHLt8g4zfIPgRI3Q1f6orVpaCe0B2mXXVHL
         tkbPsnVqi2tU/CZfL8N4VfGGjPpKrQtvzxpqi75YLbB3qKm7XMqOJIwU/2w88XPDu0u8
         vXEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=V256ksMV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ew12-20020a05622a514c00b00423f3ace78asi2176185qtb.4.2023.12.13.15.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:07 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNHcpJ002583;
	Wed, 13 Dec 2023 23:37:04 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgbe3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:04 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNSxlp029814;
	Wed, 13 Dec 2023 23:37:03 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgbdp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:03 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLCbYf028220;
	Wed, 13 Dec 2023 23:37:02 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyvrtw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:02 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaxte40567346
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:59 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7327020040;
	Wed, 13 Dec 2023 23:36:59 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0A3D520043;
	Wed, 13 Dec 2023 23:36:58 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:57 +0000 (GMT)
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
Subject: [PATCH v3 32/34] s390/unwind: Disable KMSAN checks
Date: Thu, 14 Dec 2023 00:24:52 +0100
Message-ID: <20231213233605.661251-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Ms-EhDUZl8DdVSjxar4ujX-GpVodfDrl
X-Proofpoint-GUID: oiTdss9fYYVlt96iU0FVBhj9BKbJ47sk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 spamscore=0 malwarescore=0 mlxlogscore=857 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 adultscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=V256ksMV;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..cd44be2b6ce8 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-33-iii%40linux.ibm.com.
