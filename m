Return-Path: <kasan-dev+bncBAABBYOLZTFQMGQEOYT6EKY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yJ8+BOQlc2nCsgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBYOLZTFQMGQEOYT6EKY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:20 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 8607C71DB1
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 08:40:19 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2a7b8fe7c71sf5228775ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 23:40:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769154018; cv=pass;
        d=google.com; s=arc-20240605;
        b=WPctO8hCNkOVU+T6q1Ykd6MmIL2IobiIA7vjcRttTWKft8dFyLH6rUXeXBIbJZCGpO
         CtL+D3TBw3sUeeCtBJg/xggovZ4L4MjRINoXeS01lzUzil8ab0Rz0l/SbCzaIjeEu2BJ
         c8GBwnzg5tAATux5EqEAHG2yUKOZDkwXfaq8hx3DyaKHVJ5aQF4y5O1NoFiScfUVaGMm
         Fg4GpIZng9C6eLL67dNiDbs+mnXoDYzgFEwuXWtC5vOfyt5sPcQgi3nN42Y6JNl0TSYq
         ozDIYkOJLMbtj8z/e+YD45INccxSRrGQ4H/q26LKVPSwHwPXP407okRyAfxLItJqswIx
         Olxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=e3n2n4v39kczqU5ulhmwNvUMuEf5STZFtKEWwgKBJqc=;
        fh=jKsEw0070FNjlt6JIEQUuGw5FCICalZbd1sq4psz2X0=;
        b=N3q0KtEDR3slQB2r66fX0d9aoXOX3V1PUJJBw6RHgIrqhuVz750ATzSRFha+ev9SHN
         BX0wIT50r8ZuiZaghul9KxLsgRfgJSAg0i9zJKM2FIUC0NN7PaMcWEWmU4ByvBSWS4Xi
         Exbat0KQjRHkzOQDjanqDs6Nn0bw3sajUDqp6Y1XZEdvk391MguH0smt0+/y25MNguKL
         YFEUEZ3qWlT+1xWpKcB+iaFVQ43cdzgy7T6yWQEX11bbSOakOiHz4aWze3OPJhLdvcKo
         CQHCTYWOYO4KXqLnZe9gZvju4ZlUj2QaVJAHUS0C6nmiCqkKsq1XRIO9MP27bw5EtwQq
         w7GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sQShysjE;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769154018; x=1769758818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e3n2n4v39kczqU5ulhmwNvUMuEf5STZFtKEWwgKBJqc=;
        b=Cq2bmTL0/zbgFRR8SlD//2AEE2H9iV/RJZw5WHs71orHp+Gkrb9y+w4kbfT+5Y2yDV
         Vr0rJpE1mx5RKyqkrJbseh3XoV4s9hA89KcQfgmhuyg9v4hOi9QUgQZsDBv/Ci3t7rmC
         kwOxkCyGlCYXRCFaTomT1HEfWS04+khWlrtBXYH9cp4t5j2PnDMd1JPugrVLzvuGTcpn
         SVJRRepwb5rzVUGhtz5zXYoi5Ob1HC/MBWENd/VJhaBvZD83Ix/7eKNwpZ70zb8mui5c
         VtGTP7Vn4+S91aNsaSbQdU4ZtVZ16HUTRFQ+qRIdEjhbMk5RVHGIlJuaCfJbXTLF0xK4
         7+yA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769154018; x=1769758818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e3n2n4v39kczqU5ulhmwNvUMuEf5STZFtKEWwgKBJqc=;
        b=CjNZ5TVVks5A+MroeLt5fMcpazxkbkXJPf9A/mCn984tDIenQQrRpBi1J/X4IBPDJb
         Vql8A9WWbGbjtna3b07pXVRplk6SBnBa8wiWmXkOIZbAdUaC8OYCIHwSdzGQwatB7V9W
         kg8nqMy+NGKotQwAh8R4kbOa7N4LQWcy4cPMu2uJodhVDorUQuBDscC0vQgSRda4qfOL
         g6FiaEc5499E/g3JDhiamKipf9dxBeXkPgMGjUcZSdLOr/YutZlKF2yd6BH7PNDdPO4d
         DpOodmHFqzpgPRBg+sZJfQdcM3MN02zo5kaelC29Np3dpUUxZALwXFipO9fL2XD4vK7S
         MZHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhFiY1pfN0UFjH7Y+bMOrNUnjqMdeX8eG5H9qpdyQCBXz4bMhLeCeBijrPV5oFoC81ig0V3g==@lfdr.de
X-Gm-Message-State: AOJu0YxJfaKtjzQjTfqSfHOr/8nXJOtXQvV9rsa5ArpbjuCxL1+v8W2j
	lVD21OJvmTRPErfnt2wW5y6MSMGV6nTI06qZTwUnt06ksYG5Z5BJzawE
X-Received: by 2002:a17:903:17c5:b0:297:df7c:ed32 with SMTP id d9443c01a7336-2a7fdeb3878mr14922485ad.0.1769154017838;
        Thu, 22 Jan 2026 23:40:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FJfSMPB3xFd+b05F1OsubwjtKU4vx6YjFevUmfANynBw=="
Received: by 2002:a17:902:fb4f:b0:298:f12:862a with SMTP id
 d9443c01a7336-2a7d2f95fdfls10923405ad.0.-pod-prod-03-us; Thu, 22 Jan 2026
 23:40:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVuAFQr38c9eREzT0xYfldncLfLmtu9hsvK+HUl3M/YDwqi2Iw4UNPn2Lp3GIo1zYLGI1Tez1ZCo24=@googlegroups.com
X-Received: by 2002:a17:902:e846:b0:290:cd9c:1229 with SMTP id d9443c01a7336-2a7fe55ed02mr19080215ad.19.1769154016721;
        Thu, 22 Jan 2026 23:40:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769154016; cv=none;
        d=google.com; s=arc-20240605;
        b=fW1hKJKOQPhQ17yDzuBLTyAHet09T1E0pW+85ufqPvhHBnMyoDaxqmUW+bOBkNGCqP
         5lpvJL2qfXyyPYI+UwClgBtdDI2DJJOzMbwxQg8NapzC+iR+Kun17nQcOqNSCav8xoOW
         uecxcMVLKiT6CCOaAtXNTjKZ1zNWCrQSFlrUmSvpNa8g+7LvU2CmfPvuZI13QD3JjeGx
         eJT3Z9Ts2e00naBrTJi7d6uuJ7F6Fn7mt2hgdw9I5dVtjlTyfAA5F7AiZ3WEV4R3dpDp
         uLN1sWJY2OhpeN6GRDzyC40gw2fGtJ0Wnth0piUYKlFNnEI8Tbz5c+8mT9yBRdZdQoRH
         WxUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=+dbv/uGTY2AYT4LIOG+sW6cKxWYy/xnUhN6G2aQANWM=;
        fh=4dZC5b+GxnxvIHnzjVMCNym7rZ5j81Xogzb8TUs6Lt0=;
        b=KXzJKeqk3QWDVA6RduDoLkVFBPVwNKRx4WiOroqJPp2L3nAvdcK3mO/6tOb8lpc46W
         8LNzRNRubfsgOfaKHv6aGvLvn9WvqBvXqdjDkGZlAjwtj6y0luOqWSWUFmdeXirpiIV0
         TjGAZkYCmw+5UJ8BKhkVls9dwNwdy3Rm9ZQRDUcMQ9ZldqWhHp2JvdjC4GkRU3wq3r92
         kaCl6oUS+EwhinYQ5++ONHUXNxVJ5sDerPHnEVuFwAjFUjdExLYstGNzGFELYLnaxiym
         Po8uvKF+JQnk36h58x7hmoflt4s5WoV9Gg5Vl6WTjNTriPKjKgXpw0yF+u8D1gPOKgBD
         9zZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sQShysjE;
       spf=pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=mkchauras@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a802fe6fffsi554235ad.9.2026.01.22.23.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Jan 2026 23:40:16 -0800 (PST)
Received-SPF: pass (google.com: domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 60N2HcKF021309;
	Fri, 23 Jan 2026 07:40:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt612ha3w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:07 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 60N7e62p012063;
	Fri, 23 Jan 2026 07:40:06 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4bt612ha3t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:06 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 60N7VTmk027293;
	Fri, 23 Jan 2026 07:40:05 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4brnrnfspf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 23 Jan 2026 07:40:05 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 60N7e1OK23724734
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 23 Jan 2026 07:40:01 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id ACD552004B;
	Fri, 23 Jan 2026 07:40:01 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0D71520043;
	Fri, 23 Jan 2026 07:39:56 +0000 (GMT)
Received: from li-1a3e774c-28e4-11b2-a85c-acc9f2883e29.ibm.com.com (unknown [9.124.222.171])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 23 Jan 2026 07:39:55 +0000 (GMT)
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
Subject: [PATCH v4 3/8] powerpc: introduce arch_enter_from_user_mode
Date: Fri, 23 Jan 2026 13:09:11 +0530
Message-ID: <20260123073916.956498-4-mkchauras@linux.ibm.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260123073916.956498-1-mkchauras@linux.ibm.com>
References: <20260123073916.956498-1-mkchauras@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qrbpVO3rl70azuk5utvgyyZcZ4ho3sGF
X-Authority-Analysis: v=2.4 cv=LaIxKzfi c=1 sm=1 tr=0 ts=697325d7 cx=c_pps
 a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17
 a=vUbySO9Y5rIA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=hdW59ek6rJpVHQNvHwAA:9
X-Proofpoint-ORIG-GUID: iCWsJd0cUjvJE0H8H5t-LDLDWzcHY5g8
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIzMDA1NSBTYWx0ZWRfX29J/mZte8N+u
 n8SBCPAT3vDCn8isSeenjxmqI2FbsPJaCB3DIHx8Uw7xsO8OPXR54luvxKPgWze0Fu/ZQW3zVlv
 U35R96jIJhH3zbJxdl3POGAjZrvgbag3NQlxCqRKvHS8wVFswS5Y+vUJQltLPU1Kw74vZVokrMX
 ojG7tTY/MEgu3EFZA8n/XVeGZ9S/69z/5k2p0B1TpQYPQU9IiB8QZIk3FME7Tp7L7Uwe3/qG04T
 skET614B5OGMD0/mh86aDmpsZoKuXPh/8/215koWiqo7p5jYUjqV4vGacrvXtQqTgwowLJuE5UI
 TiMUNr3Y4OkKXZmv7SborLF7sboppl6KPYKzkiIfm/b0cbiD200CI3JJRMjBOg8lsLEq6cEpXj+
 Xus6QS3hS61xIocX+aarIhc7Hs1qvZ4OC2Pw/JAkXqRBveGGuoWBeaMmLeYo40k8+17X8nNQA1Q
 +3ay+b4Qfsjc9mFLF9w==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-22_06,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 bulkscore=0 adultscore=0 phishscore=0 priorityscore=1501 lowpriorityscore=0
 suspectscore=0 clxscore=1015 impostorscore=0 spamscore=0 malwarescore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2601150000 definitions=main-2601230055
X-Original-Sender: mkchauras@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sQShysjE;       spf=pass (google.com:
 domain of mkchauras@linux.ibm.com designates 148.163.158.5 as permitted
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
	TAGGED_FROM(0.00)[bncBAABBYOLZTFQMGQEOYT6EKY];
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
X-Rspamd-Queue-Id: 8607C71DB1
X-Rspamd-Action: no action

From: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>

Implement the arch_enter_from_user_mode() hook required by the generic
entry/exit framework. This helper prepares the CPU state when entering
the kernel from userspace, ensuring correct handling of KUAP/KUEP,
transactional memory, and debug register state.

This patch contains no functional changes, it is purely preparatory for
enabling the generic syscall and interrupt entry path on PowerPC.

Signed-off-by: Mukesh Kumar Chaurasiya <mchauras@linux.ibm.com>
---
 arch/powerpc/include/asm/entry-common.h | 118 ++++++++++++++++++++++++
 1 file changed, 118 insertions(+)

diff --git a/arch/powerpc/include/asm/entry-common.h b/arch/powerpc/include/asm/entry-common.h
index 05ce0583b600..837a7e020e82 100644
--- a/arch/powerpc/include/asm/entry-common.h
+++ b/arch/powerpc/include/asm/entry-common.h
@@ -3,6 +3,124 @@
 #ifndef _ASM_PPC_ENTRY_COMMON_H
 #define _ASM_PPC_ENTRY_COMMON_H
 
+#include <asm/cputime.h>
+#include <asm/interrupt.h>
 #include <asm/stacktrace.h>
+#include <asm/tm.h>
+
+static __always_inline void booke_load_dbcr0(void)
+{
+#ifdef CONFIG_PPC_ADV_DEBUG_REGS
+	unsigned long dbcr0 = current->thread.debug.dbcr0;
+
+	if (likely(!(dbcr0 & DBCR0_IDM)))
+		return;
+
+	/*
+	 * Check to see if the dbcr0 register is set up to debug.
+	 * Use the internal debug mode bit to do this.
+	 */
+	mtmsr(mfmsr() & ~MSR_DE);
+	if (IS_ENABLED(CONFIG_PPC32)) {
+		isync();
+		global_dbcr0[smp_processor_id()] = mfspr(SPRN_DBCR0);
+	}
+	mtspr(SPRN_DBCR0, dbcr0);
+	mtspr(SPRN_DBSR, -1);
+#endif
+}
+
+static __always_inline void arch_enter_from_user_mode(struct pt_regs *regs)
+{
+	kuap_lock();
+
+	if (IS_ENABLED(CONFIG_PPC_IRQ_SOFT_MASK_DEBUG))
+		BUG_ON(irq_soft_mask_return() != IRQS_ALL_DISABLED);
+
+	BUG_ON(regs_is_unrecoverable(regs));
+	BUG_ON(!user_mode(regs));
+	BUG_ON(regs_irqs_disabled(regs));
+
+#ifdef CONFIG_PPC_PKEY
+	if (mmu_has_feature(MMU_FTR_PKEY) && trap_is_syscall(regs)) {
+		unsigned long amr, iamr;
+		bool flush_needed = false;
+		/*
+		 * When entering from userspace we mostly have the AMR/IAMR
+		 * different from kernel default values. Hence don't compare.
+		 */
+		amr = mfspr(SPRN_AMR);
+		iamr = mfspr(SPRN_IAMR);
+		regs->amr  = amr;
+		regs->iamr = iamr;
+		if (mmu_has_feature(MMU_FTR_KUAP)) {
+			mtspr(SPRN_AMR, AMR_KUAP_BLOCKED);
+			flush_needed = true;
+		}
+		if (mmu_has_feature(MMU_FTR_BOOK3S_KUEP)) {
+			mtspr(SPRN_IAMR, AMR_KUEP_BLOCKED);
+			flush_needed = true;
+		}
+		if (flush_needed)
+			isync();
+	}
+#endif
+	kuap_assert_locked();
+	booke_restore_dbcr0();
+	account_cpu_user_entry();
+	account_stolen_time();
+
+	/*
+	 * This is not required for the syscall exit path, but makes the
+	 * stack frame look nicer. If this was initialised in the first stack
+	 * frame, or if the unwinder was taught the first stack frame always
+	 * returns to user with IRQS_ENABLED, this store could be avoided!
+	 */
+	irq_soft_mask_regs_set_state(regs, IRQS_ENABLED);
+
+	/*
+	 * If system call is called with TM active, set _TIF_RESTOREALL to
+	 * prevent RFSCV being used to return to userspace, because POWER9
+	 * TM implementation has problems with this instruction returning to
+	 * transactional state. Final register values are not relevant because
+	 * the transaction will be aborted upon return anyway. Or in the case
+	 * of unsupported_scv SIGILL fault, the return state does not much
+	 * matter because it's an edge case.
+	 */
+	if (IS_ENABLED(CONFIG_PPC_TRANSACTIONAL_MEM) &&
+	    unlikely(MSR_TM_TRANSACTIONAL(regs->msr)))
+		set_bits(_TIF_RESTOREALL, &current_thread_info()->flags);
+
+	/*
+	 * If the system call was made with a transaction active, doom it and
+	 * return without performing the system call. Unless it was an
+	 * unsupported scv vector, in which case it's treated like an illegal
+	 * instruction.
+	 */
+#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
+	if (unlikely(MSR_TM_TRANSACTIONAL(regs->msr)) &&
+	    !trap_is_unsupported_scv(regs)) {
+		/* Enable TM in the kernel, and disable EE (for scv) */
+		hard_irq_disable();
+		mtmsr(mfmsr() | MSR_TM);
+
+		/* tabort, this dooms the transaction, nothing else */
+		asm volatile(".long 0x7c00071d | ((%0) << 16)"
+			     :: "r"(TM_CAUSE_SYSCALL | TM_CAUSE_PERSISTENT));
+
+		/*
+		 * Userspace will never see the return value. Execution will
+		 * resume after the tbegin. of the aborted transaction with the
+		 * checkpointed register state. A context switch could occur
+		 * or signal delivered to the process before resuming the
+		 * doomed transaction context, but that should all be handled
+		 * as expected.
+		 */
+		return;
+	}
+#endif /* CONFIG_PPC_TRANSACTIONAL_MEM */
+}
+
+#define arch_enter_from_user_mode arch_enter_from_user_mode
 
 #endif /* _ASM_PPC_ENTRY_COMMON_H */
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123073916.956498-4-mkchauras%40linux.ibm.com.
