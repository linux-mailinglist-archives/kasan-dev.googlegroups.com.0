Return-Path: <kasan-dev+bncBAABBVOLZTFQMGQERURWF4Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oI14J9glc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBVOLZTFQMGQERURWF4Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0706E71D98
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:08 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-29f25e494c2sf21506205ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154006; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8iCP6TpAmaDcDZI1JV2zvjC253FUwZaQQK+xf+ZBi8tB6HYhsFT1L33dSG48xchYB
         r71TRr7sDJC409OrmvyGW8v97sklEnEa0Zxd+ZlEq0NwWAID1SJ599mjJLqS9F5rpRk2
         iFPA9EW1VKTDFXZwtN4FpqY0DGCL3Z9vYOdYOhwTi525xib8p30V1W12gb6bxOb0c2d+
         MiGdJrxSP8dzumXuCRd8hbtITWlwcmwnejDAVQ0e+m5Jkl8W08EN1P8olnSu6lwkRXWz
         7updiR+4g4lG1KTAF8tnCnXAsppO/20/UTbhb4oBF8kseUvABDBhJzS8dWyxTAsbyKWO
         ud6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=1Qelumvfu4b6mAhrvsf1Jg4Sc/qvXB+89TvMFF+B8LM=;
        fh=/mYExgnsB/jubKs8oBdEHP+0ia2t0jwlx81DcayMx50=;
        b=YV1QrQ7ZklELWxxqmt/oGXE+/TOQA5sNc36nx7Xeuynfv3GyWgr51R1wEqMHUPjuOl
         VUKN+N7VTkLWBfUuyCSH9YBpaUikwZfOrb2YOEP+GJPIEHAVm/JWwJEof8NQdvrinC4g
         9xrNnpKXrMq46iNTNILR8wj2NFsC437+x4xa8COxUJ7E6JShvnHd2y3oNndPiV2WMctx
         xMvAtZNINq5Acq/sL3z6FBkj1USljvWeDcS+z6lXUhh0Laah3mc3/UQpbJT5V/MYcD2d
         jorA4XXbZTIyko62rsH5JFH4ve6sZuiV2l8jtUk3rYIqp6JHvGdpCEPAV3MYkxyfjrbG
         ZXlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=la5vWGSb;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154006; x=1769758806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Qelumvfu4b6mAhrvsf1Jg4Sc/qvXB+89TvMFF+B8LM=;
        b=DPSnkcgwPNnYCmwaNUJsK7wEbOW7WPX+TdmtkcSZIKG21mhnx49pKiik0QHfo9wVQ8
         Nuy0Ev8xBGtQK5ishnHadl6WiANMf1hBOA9+7exPFqFd7aITbS3SNP1FbA9rrfu0TFWJ
         Msy0nA2b4oiy7EB+VNY1yWvhh9tSXNCL2zSt9+/9O2SbngaDvTLHAu3qjwMZJjs8gbvH
         iQ5RvWdhsUiljv7hq30477ZZG3z8hwAvKagoJpZ7eF8dFM0FljtpWPiIyS//tcoms3fI
         /Sesb4SxXG5+UInj/LWy73KdqPSjMwMscHaaacOoGYv/iwa7EeSBOvcxa+SwXcS5DTOD
         dJ1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154006; x=1769758806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Qelumvfu4b6mAhrvsf1Jg4Sc/qvXB+89TvMFF+B8LM=;
        b=VV+xJrGdwwezitQjuU5FrEycGKh4tgCZjYqnf49mX8K1jRH27uKvMcuiLYWgd4pmbR
         BBR5kN+KqPTKaxA9CHJ08YLGB56k5F76r5ZKbdNpCTknn3uINZ8najRo1Jlo/bLQ3Pap
         ESC9fmPqqxpE4+Q5EMaQ+rJ/G+OZ53El6AYI5La/pPnJq+Uc85aBjKG0eIcc+Ov/MUnB
         8fIIKYkljkoVkm5Cvc7rAox+zeEGj4jmML6myJwRJTWROYxA9UIQORt1cYm7XxqZPfWS
         YGzfBV27sN20hQeeu31L7jHjcDsyWeSkxzwrODDkWZC5AF/SsyY2Iywgs5ZAezhfMphy
         XleQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/9EHIjEYSCT3+2Eq2McJa75Yddo7MKwXtPWBtWXyUMbOHhW2yrIPF7oE3FZuWub7Kw122Cg==@lfdr.de
X-Gm-Message-State: AOJu0YzsrxMKIolk9J4j/iE+V0Fc6knnJ7c2d2z3gbF5sTNnlROfDVAT
	LTVVBoN/s7X7DoUbgEaDIc+S4vMJvfOebRhVAxiz9G9DyWlcJoUBEucs
X-Received: by 2002:a17:903:603:b0:2a7:8865:a1cc with SMTP id d9443c01a7336-2a7fe75bf21mr12862955ad.9.1769154005903;
        Thu, 22 Jan 2026 23:40:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EwQgneEw6NBimLqRjnG3uHARB0cj9DhJjKdizItyzNQQ=="
Received: by 2002:a17:902:e844:b0:298:1573:8be3 with SMTP id
 d9443c01a7336-2a7d30338d8ls8412665ad.0.-pod-prod-00-us; Thu, 22 Jan 2026
 23:40:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2y5zWsIfEcJySAZ4IJdEM5rs848eogNI0uJqgjmAlMhQcgZ94XiuIHKNl77XS1R5sU17LzGM7j3Q=@googlegroups.com
X-Received: by 2002:a17:902:f60b:b0:295:55f:8ebb with SMTP id d9443c01a7336-2a7fe809fe7mr17605065ad.21.1769154004473;
        Thu, 22 Jan 2026 23:40:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154004; cv=none;
        d=google.com; s=arc-20240605;
        b=iWaw7BuEumKMBqFkG3k8CTpS3fqJ2pS7ywR1+5s8VYCdZmKX5F0zZaYrzk4+u/Cbpa
         i8mHzakKXzLM04H8h/CX5ds/NoG+TVw0/Jay43Id/sgKhssT9EAAQeQWLNplSun7xup3
         xEABhpHcQulfb3LaorP/LmGa7nR2W43MKzcelV5/k3wpphLLZ1K1jWYeyQkDQ5pUM4hF
         4LSrDgJILKuDsV0cfOqhqZ1RMs6ivo40zyNw5dNAz5TD3qHepukc3pq+nxm1DXyLeFbA
         veUJNTXMvfIHmgmGju9Aohuk1jZiRqHuPTeKCOAQCn+I7j9q+pzKM0AexgZG+QUmCzHn
         Uchg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Ua+jLJZ3utO7LvETB/ynLEgAHt0rBss1SJxQRu2GIfY=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=P2RfdMtS9jvBUYItqzKSV1i9Acc6Frw1XTbh9ZjksY7Xd4q6JzWEBaHdoeMsQPrMwp
         PZMvBNxsZ0wepJoAsJJ+pT+cip8Y1TMWjycJTYPKmMPQrakHeRVGdcLFDwLV07jjk5Es
         Rac0lOItaTB6uRordgxynFWEgIgrQkKVMpLTYDcRDMlHBltQFO/VBJU53xoDl/ouaId/
         wID5KCuK8bycNflILN8ot1Y4/k/g4m7jOYy/2gTmTffkAmj5Ko3dL5aKh5eV+zbBb3rF
         GVihYNc8w1cDq/SbyQ0r+e7Dcphfi5iPkLS2etA9Rw3ATP7rfFr8ajYVe4Y66tqWcv52
         kyAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=la5vWGSb;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a802dc3b10si590585ad.1.2026.01.22.23.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:04 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60MNlacA019492;
	Fri, 23 Jan 2026 07:39:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br256ekmf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:54 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7drE0027568;
	Fri, 23 Jan 2026 07:39:54 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br256ekma-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:53 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N6UglK016600;
	Fri, 23 Jan 2026 07:39:52 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brn4yfxfv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:39:52 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7dmq138601110
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:39:48 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2590A20040;
	Fri, 23 Jan 2026 07:39:48 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AE9EC20043;
	Fri, 23 Jan 2026 07:39:41 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:39:41 +0000 (GMT)
From: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
To: maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com,
        chleroy@kernel.org, ryabinin.a.a@gmail.com, glider@google.com,
        andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
        oleg@redhat.com, kees@kernel.org, luto@amacapital.net,
        wad@chromium.org, mchauras@linux.ibm.com, thuth@redhat.com,
        ruanjinjie@huawei.com, sshegde@linux.ibm.com,
        akpm@linux-foundation.org, charlie@rivosinc.com, deller@gmx.de,
        ldv@strace.io, macro@orcam.me.uk, segher@kernel.crashing.org,
        peterz@infradead.org, bigeasy@linutronix.de, namcao@linutronix.de,
        tglx@linutronix.de, mark.barnett@arm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        kasan-dev@googlegroups.com
Subject: [PATCH v4 1/8] powerpc: rename arch_irq_disabled_regs
Date: Fri, 23 Jan 2026 13:09:09 +0530
Message-ID: <20260123073916.956498-2-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfXwRQ2CGv0bRSG
 IyIvY0qB2QJMxumK7PFc4MZ98IcVsNRB0an/i10mk1E2EI6FTN54d0jYea4O+9s8aHEIiBfodgb
 jH1t97dXlZ8xxCCPz4bO+LL33b4/duV+GjTZFJxaxNmdypTKsurbi5/FLy/1w3qYvxCnGpknY59
 gqQHFGmImaXB9hweGy7tBIadp//gtnF9Zr5HSi7FwJ4/g1pnHRgGkHjD+F++TVuWVIKfiKhT3m7
 OteeDFzmjNRCqYQM3VNAhVJ8FAJZsAoy/6fulRnIN1F9n+N8poGG4JQNeJJBi0W0xIogFeex9eq
 61Om6WAdlODYXEFMwB7QJcusYjMdefyRq4hrYMFMnAOzYVh6HcWujGLFHZkELlhkDNXd3s4aDTU
 G4ercLWX92nNyNSh4tR0meIzLq+Hf8D9FNAQGUckDzGLsVRMBb0lNRBsFI6N0wKP/47ThigJkt+
 865UV1BqZC4yuCegSuQ==
X-Authority-Analysis: v=2.4 cv=BpSQAIX5 c=1 sm=1 tr=0 ts=697325ca cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8 a=i0EeH86SAAAA:8
 a=8txWmKPpaVdEF_iBmVcA:9
X-Proofpoint-GUID: bzmnmhPke45yDArNZyuzxS6kuZ7viVlr
X-Proofpoint-ORIG-GUID: GH71FTZ7yDcgY7miAsEKod3H72_OT0VQ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 spamscore=0 bulkscore=0 clxscore=1011 adultscore=0 phishscore=0
 malwarescore=0 impostorscore=0 suspectscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=la5vWGSb;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=mkchauras@linux.ibm.com;       dmarc=pass (p=REJECT
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBVOLZTFQMGQERURWF4Y];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[31];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_TWELVE(0.00)[13];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-0.998];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid]
X-Rspamd-Queue-Id: 0706E71D98
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

Rename arch_irq_disabled_regs() to regs_irqs_disabled() to align with the
naming used in the generic irqentry framework. This makes the function
available for use both in the PowerPC architecture code and in the
common entry/exit paths shared with other architectures.

This is a preparatory change for enabling the generic irqentry framework
on PowerPC.

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
Reviewed-by: Shrikanth Hegde <sshegde@linux.ibm.com>
Reviewed-by: Jinjie Ruan <ruanjinjie@huawei.com>
---
 arch/powerpc/include/asm/hw_irq.h    |  4 ++--
 arch/powerpc/include/asm/interrupt.h | 16 ++++++++--------
 arch/powerpc/kernel/interrupt.c      |  4 ++--
 arch/powerpc/kernel/syscall.c        |  2 +-
 arch/powerpc/kernel/traps.c          |  2 +-
 arch/powerpc/kernel/watchdog.c       |  2 +-
 arch/powerpc/perf/core-book3s.c      |  2 +-
 7 files changed, 16 insertions(+), 16 deletions(-)

diff --git a/arch/powerpc/include/asm/hw_irq.h b/arch/powerpc/include/asm/hw_irq.h
index 9cd945f2acaf..b7eee6385ae5 100644
--- a/arch/powerpc/include/asm/hw_irq.h
+++ b/arch/powerpc/include/asm/hw_irq.h
@@ -393,7 +393,7 @@ static inline void do_hard_irq_enable(void)
 	__hard_irq_enable();
 }
 
-static inline bool arch_irq_disabled_regs(struct pt_regs *regs)
+static inline bool regs_irqs_disabled(struct pt_regs *regs)
 {
 	return (regs->softe & IRQS_DISABLED);
 }
@@ -466,7 +466,7 @@ static inline bool arch_irqs_disabled(void)
 
 #define hard_irq_disable()		arch_local_irq_disable()
 
-static inline bool arch_irq_disabled_regs(struct pt_regs *regs)
+static inline bool regs_irqs_disabled(struct pt_regs *regs)
 {
 	return !(regs->msr & MSR_EE);
 }
diff --git a/arch/powerpc/include/asm/interrupt.h b/arch/powerpc/include/asm/interrupt.h
index eb0e4a20b818..0e2cddf8bd21 100644
--- a/arch/powerpc/include/asm/interrupt.h
+++ b/arch/powerpc/include/asm/interrupt.h
@@ -172,7 +172,7 @@ static inline void interrupt_enter_prepare(struct pt_regs *regs)
 	/* Enable MSR[RI] early, to support kernel SLB and hash faults */
 #endif
 
-	if (!arch_irq_disabled_regs(regs))
+	if (!regs_irqs_disabled(regs))
 		trace_hardirqs_off();
 
 	if (user_mode(regs)) {
@@ -192,11 +192,11 @@ static inline void interrupt_enter_prepare(struct pt_regs *regs)
 			CT_WARN_ON(ct_state() != CT_STATE_KERNEL &&
 				   ct_state() != CT_STATE_IDLE);
 		INT_SOFT_MASK_BUG_ON(regs, is_implicit_soft_masked(regs));
-		INT_SOFT_MASK_BUG_ON(regs, arch_irq_disabled_regs(regs) &&
-					   search_kernel_restart_table(regs->nip));
+		INT_SOFT_MASK_BUG_ON(regs, regs_irqs_disabled(regs) &&
+				     search_kernel_restart_table(regs->nip));
 	}
-	INT_SOFT_MASK_BUG_ON(regs, !arch_irq_disabled_regs(regs) &&
-				   !(regs->msr & MSR_EE));
+	INT_SOFT_MASK_BUG_ON(regs, !regs_irqs_disabled(regs) &&
+			     !(regs->msr & MSR_EE));
 
 	booke_restore_dbcr0();
 }
@@ -298,7 +298,7 @@ static inline void interrupt_nmi_enter_prepare(struct pt_regs *regs, struct inte
 		 * Adjust regs->softe to be soft-masked if it had not been
 		 * reconcied (e.g., interrupt entry with MSR[EE]=0 but softe
 		 * not yet set disabled), or if it was in an implicit soft
-		 * masked state. This makes arch_irq_disabled_regs(regs)
+		 * masked state. This makes regs_irqs_disabled(regs)
 		 * behave as expected.
 		 */
 		regs->softe = IRQS_ALL_DISABLED;
@@ -372,7 +372,7 @@ static inline void interrupt_nmi_exit_prepare(struct pt_regs *regs, struct inter
 
 #ifdef CONFIG_PPC64
 #ifdef CONFIG_PPC_BOOK3S
-	if (arch_irq_disabled_regs(regs)) {
+	if (regs_irqs_disabled(regs)) {
 		unsigned long rst = search_kernel_restart_table(regs->nip);
 		if (rst)
 			regs_set_return_ip(regs, rst);
@@ -661,7 +661,7 @@ void replay_soft_interrupts(void);
 
 static inline void interrupt_cond_local_irq_enable(struct pt_regs *regs)
 {
-	if (!arch_irq_disabled_regs(regs))
+	if (!regs_irqs_disabled(regs))
 		local_irq_enable();
 }
 
diff --git a/arch/powerpc/kernel/interrupt.c b/arch/powerpc/kernel/interrupt.c
index e63bfde13e03..666eadb589a5 100644
--- a/arch/powerpc/kernel/interrupt.c
+++ b/arch/powerpc/kernel/interrupt.c
@@ -347,7 +347,7 @@ notrace unsigned long interrupt_exit_user_prepare(struct pt_regs *regs)
 	unsigned long ret;
 
 	BUG_ON(regs_is_unrecoverable(regs));
-	BUG_ON(arch_irq_disabled_regs(regs));
+	BUG_ON(regs_irqs_disabled(regs));
 	CT_WARN_ON(ct_state() == CT_STATE_USER);
 
 	/*
@@ -396,7 +396,7 @@ notrace unsigned long interrupt_exit_kernel_prepare(struct pt_regs *regs)
 
 	local_irq_disable();
 
-	if (!arch_irq_disabled_regs(regs)) {
+	if (!regs_irqs_disabled(regs)) {
 		/* Returning to a kernel context with local irqs enabled. */
 		WARN_ON_ONCE(!(regs->msr & MSR_EE));
 again:
diff --git a/arch/powerpc/kernel/syscall.c b/arch/powerpc/kernel/syscall.c
index be159ad4b77b..9f03a6263fb4 100644
--- a/arch/powerpc/kernel/syscall.c
+++ b/arch/powerpc/kernel/syscall.c
@@ -32,7 +32,7 @@ notrace long system_call_exception(struct pt_regs *regs, unsigned long r0)
 
 	BUG_ON(regs_is_unrecoverable(regs));
 	BUG_ON(!user_mode(regs));
-	BUG_ON(arch_irq_disabled_regs(regs));
+	BUG_ON(regs_irqs_disabled(regs));
 
 #ifdef CONFIG_PPC_PKEY
 	if (mmu_has_feature(MMU_FTR_PKEY)) {
diff --git a/arch/powerpc/kernel/traps.c b/arch/powerpc/kernel/traps.c
index cb8e9357383e..629f2a2d4780 100644
--- a/arch/powerpc/kernel/traps.c
+++ b/arch/powerpc/kernel/traps.c
@@ -1956,7 +1956,7 @@ DEFINE_INTERRUPT_HANDLER_RAW(performance_monitor_exception)
 	 * prevent hash faults on user addresses when reading callchains (and
 	 * looks better from an irq tracing perspective).
 	 */
-	if (IS_ENABLED(CONFIG_PPC64) && unlikely(arch_irq_disabled_regs(regs)))
+	if (IS_ENABLED(CONFIG_PPC64) && unlikely(regs_irqs_disabled(regs)))
 		performance_monitor_exception_nmi(regs);
 	else
 		performance_monitor_exception_async(regs);
diff --git a/arch/powerpc/kernel/watchdog.c b/arch/powerpc/kernel/watchdog.c
index 2429cb1c7baa..6111cbbde069 100644
--- a/arch/powerpc/kernel/watchdog.c
+++ b/arch/powerpc/kernel/watchdog.c
@@ -373,7 +373,7 @@ DEFINE_INTERRUPT_HANDLER_NMI(soft_nmi_interrupt)
 	u64 tb;
 
 	/* should only arrive from kernel, with irqs disabled */
-	WARN_ON_ONCE(!arch_irq_disabled_regs(regs));
+	WARN_ON_ONCE(!regs_irqs_disabled(regs));
 
 	if (!cpumask_test_cpu(cpu, &wd_cpus_enabled))
 		return 0;
diff --git a/arch/powerpc/perf/core-book3s.c b/arch/powerpc/perf/core-book3s.c
index 8b0081441f85..f7518b7e3055 100644
--- a/arch/powerpc/perf/core-book3s.c
+++ b/arch/powerpc/perf/core-book3s.c
@@ -2482,7 +2482,7 @@ static void __perf_event_interrupt(struct pt_regs *regs)
 	 * will trigger a PMI after waking up from idle. Since counter values are _not_
 	 * saved/restored in idle path, can lead to below "Can't find PMC" message.
 	 */
-	if (unlikely(!found) && !arch_irq_disabled_regs(regs))
+	if (unlikely(!found) && !regs_irqs_disabled(regs))
 		printk_ratelimited(KERN_WARNING "Can't find PMC that caused IRQ\n");
 
 	/*
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-2-mkchauras%40linux.ibm.com.
