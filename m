Return-Path: <kasan-dev+bncBAABB3OLZTFQMGQER3QU6ZY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GKOBE/Alc2kAswAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB3OLZTFQMGQER3QU6ZY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id C356871DC6
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:31 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2a0f0c7a06esf14909825ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154030; cv=pass;
        d=google.com; s=arc-20240605;
        b=HixNclBWUsDdu+FtU1LbCVC66kf2tU6m+YuT86ZSHoUT5U1i9zNMTi9kxihBXDEU8f
         jDkZn0JJNvpMif6UhHxvA9qdvYrL2uxaQY396jR8yuPR8szoSZWZplv9VfWAj2PBkq/W
         muxUn7s5yCX9U5dLeiW98ahTfz7CBOBQ7MFgv0FG1SHHVE3sNdsqUPXg2wVX8x9YjsSq
         tMnEUmVZ9TrQJyjBfFz4Hqq+KBSe8aC4xvCLWNUPmoXFqfqrhbbxkAc4fyyZrfa7Lcdv
         nfWxqbY6I0BaiHatOk3RZjmJt36/CbTM+DGrYMztDkuMPZzWVscjuxUBzvcaU1w0xsEl
         Z5xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=42MBc8qwoag60XQ0Y5/C8dVzZb3YVPuHDAfwcxVqmpU=;
        fh=5/5vq+nZ2nDaqutjmx7DrqyVZRuWrVFtWEqm5lKVexQ=;
        b=ikZRoNhIo3Y0pKE/oWaWwVTPuLkBVsGPR9uc4v0EJp9RpgdrB+KHnf/7Bnc9r3Jd7F
         78rkelVdYxvvZVM1xFoGPFohtjkvLS8PB3punenTyek490QGjnkJxcV+zwuz0Xk236un
         EMHAJHlFrpcR1YyDynufawSEdvFpqCR+eN4wrzw0QGb4YBM6sBAF7ULXgCa4XZee+ItN
         mgZ1C5KPZ4OjKIeqWWZD+wsgKK14WbUVN4LDU4PKuFmQEtysDISyMTPYc1EDp1zy8yx+
         bL+v5NStGQAjH6mvj25XV44uWg9OtBRNRCD5xnD648BgnvCprQLQZ8PmgVeNrub39N97
         LqJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c5DGdIp9;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154030; x=1769758830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=42MBc8qwoag60XQ0Y5/C8dVzZb3YVPuHDAfwcxVqmpU=;
        b=bHJXVgozlB1oF0AWZX2I3peucfA2xGww+KN45BaqYa+sD4AJrVLzX5uOnxPVP0HrF8
         /3m+xvxPXvTItUhukKlhvvjqHH7O0gjo3arFOg/hGo9bwKRXtClNS29ZR/hShNpT45S8
         oeolgFzFnxZUQv7Ms3oz4/9b02/7zFJoYJa3d+PowxyrUYp7Hv6U7vTsYGCrp/OSEzZD
         pLMHxKFwEVbMOor+JyMkYOxoTDY/4QxH+mfDA3A8ANmiRHBxg7Pi/OKPeXQHvHbHYG/s
         nG0vJKo/eaFafauRwkpOYof9CKK6Yw2iwkYfZDNi75BBMB5dtsuTciNsEDqIybNef/T6
         HwLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154030; x=1769758830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=42MBc8qwoag60XQ0Y5/C8dVzZb3YVPuHDAfwcxVqmpU=;
        b=E5kb2g/0tKOpLv1tGjZsDtxY3WCMkkM5lXoN9HYIC3rI1fgjyB8GrdMQ6OW2x+VFPd
         //CPE9oVlsZBugCKlkeTp33h/mR3RKVIIzkpZfrXnOTGVCnX8DtLxL7iMEIGi3Fpy0eu
         MEozbo1DmvaVZ6bTZdfGPrbjGytFMNdIvxUq3uYsZC5d2M9t/QGDijX3sjIH/0Gjyjaz
         RzFZUUahkV0xnx4SI9a2JtbllyJTJ1YnR+fncw3CIP3IyISnTNS3oU3QW60NXW4eUrEN
         UBDM4QAecOXoalDDArfYmv51pIPSpbhggN+60V5FRoa+cOg63gKOC6TZ/3y4dji/+xmi
         We9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCtXZVUPfXV/e25Ojg06d+j8H6Q0DeLtQCB4HFbTx7hLyGiKatrMu4LN9Ivi6JuH6pzZnJXw==@lfdr.de
X-Gm-Message-State: AOJu0YxtIBCh3xtbVHGyZdEleoXgi+IgtJVLjMmJP8YUulmscYWJZEkU
	yN1OaKYU4R454Cg/JGVS8MUwNmQiO8DeLEpqKB2EdE3r5hn149eEchBw
X-Received: by 2002:a17:902:f68f:b0:2a7:d42f:7065 with SMTP id d9443c01a7336-2a80ebee4b0mr4079655ad.27.1769154029880;
        Thu, 22 Jan 2026 23:40:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F8QUGKyv2SL246b+15u2DmfcO6atM//SMadT39YSksYA=="
Received: by 2002:a17:903:13c5:b0:2a7:a969:5e9b with SMTP id
 d9443c01a7336-2a7d2fc4cafls11296595ad.0.-pod-prod-01-us; Thu, 22 Jan 2026
 23:40:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeEdETMjD8L/i+gJnE9+KLh+XKI0xqyD+MNC/cv8zxIDq4L+9ycZYPfufTydw2rCPUR7LdBSxC6tM=@googlegroups.com
X-Received: by 2002:a17:903:22d0:b0:2a7:af41:fb8e with SMTP id d9443c01a7336-2a80ebb8404mr4237715ad.2.1769154028688;
        Thu, 22 Jan 2026 23:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154028; cv=none;
        d=google.com; s=arc-20240605;
        b=aEWdloTZ9XzE5wAx3t/me3ay04b/xuBMkpPn9AX9cTsh3D0T88m3fqLkP0uRcVvOvO
         QweM9T1M/R0OgMUt+TZh03GkJH9Of0UWtWemvnp6Rfz7zV9mpLP0/szy+3XoEojLcW8X
         qbJDsqNMete0Wgx6dAZMO9KC/PHdKQlbOyv4B0U+qR8TEsuGcIpRaduU/37mpEz09ls3
         ARPUZNfWdqZc6n8Byn6M53xendGfcAm6YMimAt2+HZHwOwPWVioxVKOAlrzn69puxwb8
         2Eu590s20cfB1jInAOQhpqk0JsIgWhdJM+n1x190qElxQA0oXgFwy2Yp4CFmdKl0m4V2
         zGzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=oSMy7jSCHlk+7wrf49CRz3G29HirD/p7Ikh3c9+dpPE=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=Qx34e6PqHPHsgcHNiEJyDhAJPOysGeneu4Ir5pclLT9b9bDlbggSTYOYc+gmcGKyT+
         9kk/tdn5oDmgPmLGjtGefdf4zSdKNY3JNdQ62TbYNiDXVxSX6JeOPhN5JBb2tYygW1c0
         Ld5BzI0Ia8xiiYQOX/rO+ng4lEx13u3q4a++8xLb62hz0oFY/Kwy0no94brm0pwKVmOB
         3h917XpX+xzh8bxA7b3iZS+wtlzD8at9YH+S4viTWstkOyyWlqmoG6ySPl1dywb85Eax
         gKDSIkBKl3j6WLVi7/4CNOBRVpEjD3QlY1nSca1qSbnZwqdThvQarAWAPlMsbTMz/Jro
         CTTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c5DGdIp9;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a802ef4ae1si611085ad.4.2026.01.22.23.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60MKGTLv028566;
	Fri, 23 Jan 2026 07:40:14 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f273g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:14 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7blOu012630;
	Fri, 23 Jan 2026 07:40:13 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt60f273c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:13 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N7IDRQ016627;
	Fri, 23 Jan 2026 07:40:12 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brn4yfxhb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:11 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7e7cq53215628
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:08 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D21E82004E;
	Fri, 23 Jan 2026 07:40:07 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1785220043;
	Fri, 23 Jan 2026 07:40:02 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:40:01 +0000 (GMT)
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
Subject: [PATCH v4 4/8] powerpc: Introduce syscall exit arch functions
Date: Fri, 23 Jan 2026 13:09:12 +0530
Message-ID: <20260123073916.956498-5-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=WMdyn3sR c=1 sm=1 tr=0 ts=697325de cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=K2hBjdrW4GR3aseOdFMA:9
X-Proofpoint-GUID: xep7M4Oh8a1rGfznsv4u2iiH8eUKcOEV
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfXx40x3gp6YmGp
 /n+EX5nrzbWHZJjzNXIgWFFE8C4t64lv3W/C/8dlUbLJ3BtXg97OaFkQlDxxhmsA27TTmbGasYj
 2Sv+k60S6zpdCpLEiXxHfeLBwlGt8VOcKXzfF+6TVS5kf/hcLEc11rTbkvotcHRz9Ej2kbuHrh+
 vSMtg1PqB/Knu2ucjIilw45ACtNsKOWjr3fAOSiuWf5yl57BQykPnOIzqvh1GXzqLxfsoSJQWqZ
 nwn1f8hM2xwrDWLMb4COrkeSfCluqXsIHNIebOqOu4F4Gu713sLwtIiKQUyQF2wN4anWV9n8PCe
 1du01vB+rXeLMZseiLbVbxLSHy6aILFGiMeoxkeSNhaiRHcTf6SXHyN42r0Tdj5bb2hx5BxLJws
 JcMFMFvkZTMpi21g3SR/rBiIJE6Wr4ejb1AJFkuCdkETYftOiARJXcUY/aYXSivJUggkc49Z/w4
 x8na4j0EXSluT5ttQgA==
X-Proofpoint-ORIG-GUID: RAxMs7eKSHxnsMBpZ30WVDw9ZnroqVmc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 phishscore=0 malwarescore=0 suspectscore=0 bulkscore=0 adultscore=0
 impostorscore=0 spamscore=0 clxscore=1011 priorityscore=1501
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=c5DGdIp9;       spf=pass (google.com:
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
	TAGGED_FROM(0.00)[bncBAABB3OLZTFQMGQER3QU6ZY];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.ibm.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: C356871DC6
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

Add PowerPC-specific implementations of the generic syscall exit hooks
used by the generic entry/exit framework:

 - arch_exit_to_user_mode_work_prepare()
 - arch_exit_to_user_mode_work()

These helpers handle user state restoration when returning from the
kernel to userspace, including FPU/VMX/VSX state, transactional memory,
KUAP restore, and per-CPU accounting.

Additionally, move check_return_regs_valid() from interrupt.c to
interrupt.h so it can be shared by the new entry/exit logic.

No functional change is intended with this patch.

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/entry-common.h | 49 +++++++++++++++++++++++++
 1 file changed, 49 insertions(+)

diff --git a/arch/powerpc/include/asm/entry-common.h b/arch/powerpc/include/asm/entry-common.h
index 837a7e020e82..ff0625e04778 100644
--- a/arch/powerpc/include/asm/entry-common.h
+++ b/arch/powerpc/include/asm/entry-common.h
@@ -6,6 +6,7 @@
 #include <asm/cputime.h>
 #include <asm/interrupt.h>
 #include <asm/stacktrace.h>
+#include <asm/switch_to.h>
 #include <asm/tm.h>
 
 static __always_inline void booke_load_dbcr0(void)
@@ -123,4 +124,52 @@ static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
 
 #define arch_enter_from_user_mode arch_enter_from_user_mode
 
+static inline void arch_exit_to_user_mode_prepare(struct pt_regs *regs,
+						  unsigned long ti_work)
+{
+	unsigned long mathflags;
+
+	if (IS_ENABLED(CONFIG_PPC_BOOK3S_64) && IS_ENABLED(CONFIG_PPC_FPU)) {
+		if (IS_ENABLED(CONFIG_PPC_TRANSACTIONAL_MEM) &&
+		    unlikely((ti_work & _TIF_RESTORE_TM))) {
+			restore_tm_state(regs);
+		} else {
+			mathflags = MSR_FP;
+
+			if (cpu_has_feature(CPU_FTR_VSX))
+				mathflags |= MSR_VEC | MSR_VSX;
+			else if (cpu_has_feature(CPU_FTR_ALTIVEC))
+				mathflags |= MSR_VEC;
+
+			/*
+			 * If userspace MSR has all available FP bits set,
+			 * then they are live and no need to restore. If not,
+			 * it means the regs were given up and restore_math
+			 * may decide to restore them (to avoid taking an FP
+			 * fault).
+			 */
+			if ((regs->msr & mathflags) != mathflags)
+				restore_math(regs);
+		}
+	}
+
+	check_return_regs_valid(regs);
+#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
+	local_paca->tm_scratch = regs->msr;
+#endif
+	/* Restore user access locks last */
+	kuap_user_restore(regs);
+}
+
+#define arch_exit_to_user_mode_prepare arch_exit_to_user_mode_prepare
+
+static __always_inline void arch_exit_to_user_mode(void)
+{
+	booke_load_dbcr0();
+
+	account_cpu_user_exit();
+}
+
+#define arch_exit_to_user_mode arch_exit_to_user_mode
+
 #endif /* _ASM_PPC_ENTRY_COMMON_H */
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-5-mkchauras%40linux.ibm.com.
