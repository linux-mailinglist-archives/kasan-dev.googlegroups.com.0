Return-Path: <kasan-dev+bncBAABBA6MZTFQMGQEPIXCM7A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +E5dLgYmc2kAswAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBA6MZTFQMGQEPIXCM7A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x1340.google.com (mail-dy1-x1340.google.com [IPv6:2607:f8b0:4864:20::1340])
	by mail.lfdr.de (Postfix) with ESMTPS id 3848771E10
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:54 +0100 (CET)
Received: by mail-dy1-x1340.google.com with SMTP id 5a478bee46e88-2b7174ab5fasf8951634eec.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154052; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jmbo6xYzG+ia2b11Ve67a3Mwj1w3AvDEhWMPz4jIz1SawJ35KxfZ8kTtx0nSjwF0B2
         tRacXHZ95Nq+iuHIIFTRUr1TpBaFzaZAiRCp80Y12ZiVArhUuXO/fpxOjUaHLJCgCC9/
         SpeLK9XVxEg94OD9MjcQVxkLJ9wea1C8H6zklorv81i0RS836eI8+MXveq/u7tLQ8odq
         8QlVpcNswjCgWokkxnc0jcml7sBHJUpcOsb4YwpPdrn04TN61pTw0NGAWIlstungtYU/
         fuXEHXLkMB5UOIm6o7KsNKhLn66LfqrOwF9lE9rCbVT3ED92u8Nnb2QZe1onVQLfvg0j
         iisg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CoA0d5cEpfU2ZBqMa0okxy/7f7SUYEhlOIl3phkjI1A=;
        fh=JhY3035hPubkPDY8b4QNemvkWoD4tceaxp62v2ZtW8A=;
        b=D6bpZNDKGxiaIlbKuMPdcDYksxd+exNS1RsoCIXAmq2A4V58FX91kezup4TR1LFnIu
         RxG5wruKBWK1aGzuV2pOeCjkP5mDNT65Pt2lyG4TJGXRHHs3P1tcqsB4+hVTsmvjoJ+V
         kDJ6ZPDi6Xo15dn1TcotMImVvw8OZArrBePzESjxLJCo9bbxTvxm4KdHHl8gZAy7UDFz
         l92bZ8+5FBPF30Z4In3AoHjY/HpCq0DalZ1aCNDxj6YrR/GY4Ah+450qlVR8HCktOER9
         Ll6E2Bwtse7FyNeRS/6L31F5Yr7D1RBYruLXDD7pqY3gbVkm9n0vJ+tjnBmi5snMJhXC
         KfkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HIgMr6CT;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154052; x=1769758852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CoA0d5cEpfU2ZBqMa0okxy/7f7SUYEhlOIl3phkjI1A=;
        b=EFF9kAN9lQzdhqx+BhE29AHUrlBJvw5DByBsXM/lkP3GUZCH7ScIfn6rT70hv3gd7t
         cLU2LFlrddQbHpPKklKPSjKfhrrYKDJk4z7PlCQ2vIc1g6MSITepWsjzmoh7dMvjS7+C
         De1HgMJjEeyrTAKM7k3ICjgEXeSlBTzNb3q/B+dUJWCn/uB8UJE8njb8RXojXWSpYkpK
         0svxwy3TMl/sljhh78HYjbn17brtJ7WcbYQQVO4kO/PXC7nMDVkLY9swej0xggH52/yx
         g13Tq/8DX3jQ+R3yuZfgJ/AAXqb/tZUmbYkxLS6Ryyfyz5t0Vy9CWTrlSKHg0SMPAbwg
         fpdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154052; x=1769758852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CoA0d5cEpfU2ZBqMa0okxy/7f7SUYEhlOIl3phkjI1A=;
        b=t8idnc8KQzSEhIPiLW4Tp55TRr6kSPkv7i/Wf6+GcOMInvESk9GBLT9+ZJQc5ugBNy
         /Dv+8BEUkjioH3jMSsuGfd2RgUiZ5LUSCPyU6ghT5igjnsQm5SUusjICXGJjyXWHbiOe
         UZml0WofgyfLSS6U104hKrCFc+tWsTj4/27zWZqnbrJ3BZMbvbTvRpxvQkY9ZfbGnH6f
         i2xr2qjx1vlJRFrHt/LJ5b6cEAi2BgVI2r/o1pTue8L/lV467SNq+lCRxU/1NmYs5iJP
         +ohD+VrMe/+TNUWc1RtvkW1MQkKa39r5mHp0+h2UmZZZEcCw5hE3ZwmzzT8f5i/YMPb5
         eLcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvYEo9gBqDc8gLh3Y2MA37zhhJIFc45DDQpO9Mx/4OphNxrB0nP0TOZv7/GfDCEs/2LnIl5w==@lfdr.de
X-Gm-Message-State: AOJu0YwfCXYObmVNNbM39a0KIVPWa7nz/AStiToEi8jox0ndtgCoWtFZ
	dBjEo6gvNQVbHBA2LXPSvB5qTF2hBpBOh3K7769KuHEuxroHyc+WVyGA
X-Received: by 2002:a05:7022:6898:b0:119:e56b:957d with SMTP id a92af1059eb24-1247dbaf286mr820228c88.2.1769154052029;
        Thu, 22 Jan 2026 23:40:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EI3Z/HBvgkpwdjAL23aZjSQ+7dCXVdONc44euuZx6W8A=="
Received: by 2002:a05:7022:eaca:b0:11b:519:d7f6 with SMTP id
 a92af1059eb24-12476cf8321ls1846644c88.1.-pod-prod-02-us; Thu, 22 Jan 2026
 23:40:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXsACsCt/w82YoboLVjxfp97WVi+xLRJPLxrWrSzTh3CMmx5MFrKLo2R6HPc+NVwMl8Opj3fAkYjYA=@googlegroups.com
X-Received: by 2002:a05:7022:f83:b0:119:e56b:959c with SMTP id a92af1059eb24-1247dc0ac07mr1012065c88.33.1769154048973;
        Thu, 22 Jan 2026 23:40:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154048; cv=none;
        d=google.com; s=arc-20240605;
        b=XIF8aFhjtrm5Tblgb+nmfcgyHieoeb8beezPAyYR0RB+a2DpDBlpYWRkR9RcjqkM7K
         7PEVS6mAfbiWuej71l8MPq3CWKxDzRT7xbjaSSnn/ANTQ19wMdQCAGX9q7xGCZ1EfcmG
         U5p0TFQwiBcBeVYywqupT3Uq4H024Js4/ZvLygXH4YcIW9pzngVVNnnHCY/AAsIE9DGf
         D5ymR3ReUF74jb32CkbqaXQ+CBRT7ZsSLLHgAh6RtXzX15lfk4NICMENTgKPqxRbVVGw
         1k7UIvCarxmSQxl58i1tPqF2ChbJDzjhooeLoXfG+cZ7gQoX89zSHkVKDr9gla4BrOQ6
         aFDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IlhhU0cb4Fdv+gXg8co9lSW2r2fccTJNCyp5vMf13YA=;
        fh=fo0uf1ka2HDlpaZBTb0XY8JZ4PPCbF0KdSaHJOs60cc=;
        b=GrrZBMfW4IuZmDJ3iB8P6BVluFtIw5tf/YnC/EhKHKGNPcwe8DswM0oxpUUwZvEdoq
         w9SzhfqrzjVLQwcN4w7DYvngBjfC7bzjcp5IPf+8i61MV3ZYa2wIwvoSah8dj4jR5kxE
         KzXR7CUL3smbFPdQGVj+bdJwF/PPCrLWKP7ob7KWum8Bzap7OrY9M+OQQ0/IHl/owgns
         tMT3T8W2DbWsCrRr6k061jo3Y1YOUWF7Pm8QSc1q/viDPM4m9XyAomERGMKK2Pb2NnyW
         JYHOXpwCNOMzU5//hTFw8zaFsUJPAWBq00uEMKttBUUYQPAjgIlW+fZRUy/Xuxt3euB3
         yoyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HIgMr6CT;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-1247d99fabesi69391c88.5.2026.01.22.23.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:48 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60N2K0nY019547;
	Fri, 23 Jan 2026 07:40:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br256ekqg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:38 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7drE5027568;
	Fri, 23 Jan 2026 07:40:37 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4br256ekqd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:37 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N7NABv009295;
	Fri, 23 Jan 2026 07:40:36 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brp8kqr7a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:36 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7eVMq21430744
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:31 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0EA382004D;
	Fri, 23 Jan 2026 07:40:31 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CFCA62004B;
	Fri, 23 Jan 2026 07:40:25 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:40:25 +0000 (GMT)
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
Cc: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
Subject: [PATCH v4 8/8] powerpc: Remove unused functions
Date: Fri, 23 Jan 2026 13:09:16 +0530
Message-ID: <20260123073916.956498-9-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfXzzrPNlJhGXXG
 Co2qnPmR6w2vVtcO/PlnjEHBu9bKZbbcwYWffuEVIMQGGpTL975dO641e9V8uEVUYQ+a5RKucGM
 9cufkwmt0hJc2J/w/a6JUBhBpGa5/JixM4FzAnEROFP9cynR2Tv+xCQU5yh9eGi2QFfpEZgN57q
 4migjSyywZZ+JET8w1x6eDwom7LE88ypDE1mq7oT3VPAvz3s9mlXdQl808nEa3dHt/HCfMaOF6m
 d9SlGDf/0A/HNPypSOZNWZlZT3AAW4nC2HK9tjIQli6+0gDwAT52bUP09cL5TgK4FBLvlRt8BEs
 mIFZ3SAkA6N+MBsYFapFuhyEnDjmHU5Cv4DHRTXbVRooV6ZHeFGCbFkyO4mnbAIcxjhgp/3PCaX
 NEC30SUUr/KR1ZG9BJQTzn6XqOQuVFLHgv31MQWerAnDf7JdOckVkJw7JfuFus02uFr9CEUptT8
 zKhfOmJ16w5+EUAvoyA==
X-Authority-Analysis: v=2.4 cv=BpSQAIX5 c=1 sm=1 tr=0 ts=697325f6 cx=c_pps
 a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=AFa1QFvt9TWlA0SYsw8A:9
X-Proofpoint-GUID: feRwsJYaDZwxBi4REYl-ZlIgPycVI7x7
X-Proofpoint-ORIG-GUID: PqIqB-LCbf289i_ierjyWMgG2aDTUzPn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 spamscore=0 bulkscore=0 clxscore=1015 adultscore=0 phishscore=0
 malwarescore=0 impostorscore=0 suspectscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2601150000
 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=HIgMr6CT;       spf=pass (google.com:
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[ibm.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_TO(0.00)[linux.ibm.com,ellerman.id.au,gmail.com,kernel.org,google.com,arm.com,redhat.com,amacapital.net,chromium.org,huawei.com,linux-foundation.org,rivosinc.com,gmx.de,strace.io,orcam.me.uk,kernel.crashing.org,infradead.org,linutronix.de,lists.ozlabs.org,vger.kernel.org,googlegroups.com];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[32];
	TAGGED_FROM(0.00)[bncBAABBA6MZTFQMGQEPIXCM7A];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_TWELVE(0.00)[13];
	FROM_NEQ_ENVFROM(0.00)[mkchauras@linux.ibm.com,kasan-dev@googlegroups.com];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.ibm.com:mid,mail-dy1-x1340.google.com:helo,mail-dy1-x1340.google.com:rdns]
X-Rspamd-Queue-Id: 3848771E10
X-Rspamd-Action: no action

After enabling GENERIC_ENTRY some functions are left unused.
Cleanup all those functions which includes:
 - do_syscall_trace_enter
 - do_syscall_trace_leave
 - do_notify_resume
 - do_seccomp

Signed-off-by: Mukesh Kumar Chaurasiya <mkchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/ptrace.h   |   3 -
 arch/powerpc/include/asm/signal.h   |   1 -
 arch/powerpc/kernel/ptrace/ptrace.c | 138 ----------------------------
 arch/powerpc/kernel/signal.c        |  17 ----
 4 files changed, 159 deletions(-)

diff --git a/arch/powerpc/include/asm/ptrace.h b/arch/powerpc/include/asm/ptrace.h
index 2e741ea57b80..fdeb97421785 100644
--- a/arch/powerpc/include/asm/ptrace.h
+++ b/arch/powerpc/include/asm/ptrace.h
@@ -177,9 +177,6 @@ extern unsigned long profile_pc(struct pt_regs *regs);
 #define profile_pc(regs) instruction_pointer(regs)
 #endif
 
-long do_syscall_trace_enter(struct pt_regs *regs);
-void do_syscall_trace_leave(struct pt_regs *regs);
-
 static inline void set_return_regs_changed(void)
 {
 #ifdef CONFIG_PPC_BOOK3S_64
diff --git a/arch/powerpc/include/asm/signal.h b/arch/powerpc/include/asm/signal.h
index 922d43700fb4..21af92cdb237 100644
--- a/arch/powerpc/include/asm/signal.h
+++ b/arch/powerpc/include/asm/signal.h
@@ -7,7 +7,6 @@
 #include <uapi/asm/ptrace.h>
 
 struct pt_regs;
-void do_notify_resume(struct pt_regs *regs, unsigned long thread_info_flags);
 
 unsigned long get_min_sigframe_size_32(void);
 unsigned long get_min_sigframe_size_64(void);
diff --git a/arch/powerpc/kernel/ptrace/ptrace.c b/arch/powerpc/kernel/ptrace/ptrace.c
index f006a03a0211..316d4f5ead8e 100644
--- a/arch/powerpc/kernel/ptrace/ptrace.c
+++ b/arch/powerpc/kernel/ptrace/ptrace.c
@@ -192,144 +192,6 @@ long arch_ptrace(struct task_struct *child, long request,
 	return ret;
 }
 
-#ifdef CONFIG_SECCOMP
-static int do_seccomp(struct pt_regs *regs)
-{
-	if (!test_thread_flag(TIF_SECCOMP))
-		return 0;
-
-	/*
-	 * The ABI we present to seccomp tracers is that r3 contains
-	 * the syscall return value and orig_gpr3 contains the first
-	 * syscall parameter. This is different to the ptrace ABI where
-	 * both r3 and orig_gpr3 contain the first syscall parameter.
-	 */
-	regs->gpr[3] = -ENOSYS;
-
-	/*
-	 * We use the __ version here because we have already checked
-	 * TIF_SECCOMP. If this fails, there is nothing left to do, we
-	 * have already loaded -ENOSYS into r3, or seccomp has put
-	 * something else in r3 (via SECCOMP_RET_ERRNO/TRACE).
-	 */
-	if (__secure_computing())
-		return -1;
-
-	/*
-	 * The syscall was allowed by seccomp, restore the register
-	 * state to what audit expects.
-	 * Note that we use orig_gpr3, which means a seccomp tracer can
-	 * modify the first syscall parameter (in orig_gpr3) and also
-	 * allow the syscall to proceed.
-	 */
-	regs->gpr[3] = regs->orig_gpr3;
-
-	return 0;
-}
-#else
-static inline int do_seccomp(struct pt_regs *regs) { return 0; }
-#endif /* CONFIG_SECCOMP */
-
-/**
- * do_syscall_trace_enter() - Do syscall tracing on kernel entry.
- * @regs: the pt_regs of the task to trace (current)
- *
- * Performs various types of tracing on syscall entry. This includes seccomp,
- * ptrace, syscall tracepoints and audit.
- *
- * The pt_regs are potentially visible to userspace via ptrace, so their
- * contents is ABI.
- *
- * One or more of the tracers may modify the contents of pt_regs, in particular
- * to modify arguments or even the syscall number itself.
- *
- * It's also possible that a tracer can choose to reject the system call. In
- * that case this function will return an illegal syscall number, and will put
- * an appropriate return value in regs->r3.
- *
- * Return: the (possibly changed) syscall number.
- */
-long do_syscall_trace_enter(struct pt_regs *regs)
-{
-	u32 flags;
-
-	flags = read_thread_flags() & (_TIF_SYSCALL_EMU | _TIF_SYSCALL_TRACE);
-
-	if (flags) {
-		int rc = ptrace_report_syscall_entry(regs);
-
-		if (unlikely(flags & _TIF_SYSCALL_EMU)) {
-			/*
-			 * A nonzero return code from
-			 * ptrace_report_syscall_entry() tells us to prevent
-			 * the syscall execution, but we are not going to
-			 * execute it anyway.
-			 *
-			 * Returning -1 will skip the syscall execution. We want
-			 * to avoid clobbering any registers, so we don't goto
-			 * the skip label below.
-			 */
-			return -1;
-		}
-
-		if (rc) {
-			/*
-			 * The tracer decided to abort the syscall. Note that
-			 * the tracer may also just change regs->gpr[0] to an
-			 * invalid syscall number, that is handled below on the
-			 * exit path.
-			 */
-			goto skip;
-		}
-	}
-
-	/* Run seccomp after ptrace; allow it to set gpr[3]. */
-	if (do_seccomp(regs))
-		return -1;
-
-	/* Avoid trace and audit when syscall is invalid. */
-	if (regs->gpr[0] >= NR_syscalls)
-		goto skip;
-
-	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
-		trace_sys_enter(regs, regs->gpr[0]);
-
-	if (!is_32bit_task())
-		audit_syscall_entry(regs->gpr[0], regs->gpr[3], regs->gpr[4],
-				    regs->gpr[5], regs->gpr[6]);
-	else
-		audit_syscall_entry(regs->gpr[0],
-				    regs->gpr[3] & 0xffffffff,
-				    regs->gpr[4] & 0xffffffff,
-				    regs->gpr[5] & 0xffffffff,
-				    regs->gpr[6] & 0xffffffff);
-
-	/* Return the possibly modified but valid syscall number */
-	return regs->gpr[0];
-
-skip:
-	/*
-	 * If we are aborting explicitly, or if the syscall number is
-	 * now invalid, set the return value to -ENOSYS.
-	 */
-	regs->gpr[3] = -ENOSYS;
-	return -1;
-}
-
-void do_syscall_trace_leave(struct pt_regs *regs)
-{
-	int step;
-
-	audit_syscall_exit(regs);
-
-	if (unlikely(test_thread_flag(TIF_SYSCALL_TRACEPOINT)))
-		trace_sys_exit(regs, regs->result);
-
-	step = test_thread_flag(TIF_SINGLESTEP);
-	if (step || test_thread_flag(TIF_SYSCALL_TRACE))
-		ptrace_report_syscall_exit(regs, step);
-}
-
 void __init pt_regs_check(void);
 
 /*
diff --git a/arch/powerpc/kernel/signal.c b/arch/powerpc/kernel/signal.c
index 9f1847b4742e..bb42a8b6c642 100644
--- a/arch/powerpc/kernel/signal.c
+++ b/arch/powerpc/kernel/signal.c
@@ -293,23 +293,6 @@ static void do_signal(struct task_struct *tsk)
 	signal_setup_done(ret, &ksig, test_thread_flag(TIF_SINGLESTEP));
 }
 
-void do_notify_resume(struct pt_regs *regs, unsigned long thread_info_flags)
-{
-	if (thread_info_flags & _TIF_UPROBE)
-		uprobe_notify_resume(regs);
-
-	if (thread_info_flags & _TIF_PATCH_PENDING)
-		klp_update_patch_state(current);
-
-	if (thread_info_flags & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL)) {
-		BUG_ON(regs != current->thread.regs);
-		do_signal(current);
-	}
-
-	if (thread_info_flags & _TIF_NOTIFY_RESUME)
-		resume_user_mode_work(regs);
-}
-
 static unsigned long get_tm_stackpointer(struct task_struct *tsk)
 {
 	/* When in an active transaction that takes a signal, we need to be
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-9-mkchauras%40linux.ibm.com.
