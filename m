Return-Path: <kasan-dev+bncBCM3H26GVIOBBTFFVSZQMGQEAQKQVXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 839F39076E6
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:58 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-70436ac8704sf919098b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293197; cv=pass;
        d=google.com; s=arc-20160816;
        b=y8uk2u6/6oHYsgPgEOZzCKFsgy2i7CzN89qjJs25EnX2VkohxV3HzdUNQM43b/Jvrv
         4KO7txWmKtLVu+jAyQDokV0B+H1dsli6LTYzJ5MM3hgQnn9QLDQU7a67eajX36qKdU3Y
         RN7G+Ya3PqvYelsCLiXg5qs0tU8HevHzlcCzIqNNyoH3IZCBmItcGuSyS4qEGeL/Hw6p
         ZDYCpsG/umOsV6hKKP3G0xmSKVj/bOQVGw1W4dpEvJN5jcBADoBOaekZ5TvT1s6+jSsg
         MqptFmp9mEy/KwDb7We8OjzDEdlm+01bibyYfQyiBWsZ71xOXGgAY/XdRdJeNOG3R09d
         sQvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=29NzqVXURLbAqfoGI54uUfEm36JOthzHa4NuNGWf2yI=;
        fh=O64t2Q16UK7AT29WPS9eKks4Szu16X5mKM11KZvx/M8=;
        b=TAKW+oC3JctrEv4jjZq/kaXdABUQhueFo8sTMrP5SpYeFhIGwXr96gj8EwJZaMTxw0
         82gaRg24jbSKiazW16tHJKehTnW0RJPtv4xgJ4TnOerejdsWSkEhx9bgLDUXL/PVA028
         8y3SF8/pJ8Vsgp47KpB64eNNw9n/OYPG3b2NZ33AyEoTKDcZRV3v62jmesj5yN/9F833
         GvqCH2XQkPjnP2K0KufPQ5DgTVJT6a0Ryy3Hi1QYe28YHIHeGXZdjC/AMIGHkv1HDXMn
         IJMM2XdL172q8y1JrPBVxyvzDgu5UvUTxIAHSYPMkv2lTBjrJzCxjEDuH7fzKGhP6u5c
         WQjg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bwkgaq1s;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293197; x=1718897997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=29NzqVXURLbAqfoGI54uUfEm36JOthzHa4NuNGWf2yI=;
        b=l4kMCnuXVPsrbgsD7kAPt5YBMwIyyOwb0HXzto+TanM+9cwjXzTn1F9lXTLLLgBoNf
         NC99mbeaK82/e/7wEZMEOearbrq6ODELalM0W5fVr0T7zGJQMLjH0f6vUpTDlwt8ko+1
         3uwWws/CjYo7y7jsrCEw50H7gw51x/n9dD/v0vozlS/I8J3fU5sool1VeNQiwOuBfLDN
         J4LTGbhIqmD0s6FJdcHRFejEvSQjomjKJMZ2cLe5mSLdpHwqLemhghwDk5vwqCFFr8L7
         n5MHvQH+a3IMBllOggRXRMX/0bxhulxy22kNq2r7b+hXeV9pfOPSubSeIM27orwV+W5F
         AVzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293197; x=1718897997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=29NzqVXURLbAqfoGI54uUfEm36JOthzHa4NuNGWf2yI=;
        b=PGfnkkRcE8xg3iI5/9jCm1sWAlgh7CnHYr6fL4DVw4fPE0UfEDfr2A9FVpuefIpyHU
         I7FxUdHUPGln7Wt+fA81KheDlxW3og5k+PVckGhWmyHAbLNS+mDL7f0MghwzfY3pZWev
         1We42K6a/ClMcfSRQfx+cOGqBcb59zJP2xYhTaynOBu5twDdz/HJyugdHQLifzshzeI+
         S+k8WETQYMyden10C4i0k24pdLxwOuq/0cfFXo7ZwhILCvVbSHTGbXsrR2+p9I7+dTFl
         v9NIMV+ajY85Nhj8zcIt0l/c1p7pQ1dzQHgjOEGgka/DGvMdLV8Cs8lsKSZxAkDwrYUD
         R5Xw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULG4y0JDauCJv5v1JZq2Xg4XKsMJEnthKaZhDQ2atrL7AoYRIZerONNWSUm5mGkRs7wWK7e0gvxaFnmAo4f8SWWP74y6fhKg==
X-Gm-Message-State: AOJu0YyaByOZdQRxeg9/whyTou689lFzLxPSYgQlCVIA8hg59d5qBQVp
	yDU93KGO7F3MHA3brKgnHvD6/Pfp5eXcK2qYGJLUZC67r94hDdoG
X-Google-Smtp-Source: AGHT+IE6gv82VzOQ1lKpTx/kbxA+YEfGaTrt39QVMkBpJFvUBnZifht3GreaapEziWfvlIt2AodS9g==
X-Received: by 2002:aa7:93c6:0:b0:704:2d64:747 with SMTP id d2e1a72fcca58-705d7123999mr22223b3a.7.1718293197028;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3d49:b0:704:3140:5aa4 with SMTP id
 d2e1a72fcca58-705c9454eddls840804b3a.1.-pod-prod-02-us; Thu, 13 Jun 2024
 08:39:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpzhEPAfZ5LfoZw/7QO1wONFX0oxNpVpEWXlpKO0jkFSKK6Hd/0ofMFSffna4yuEmpFMlbdp4ANzaJz7QORod9XW9GWBr2EA2ZnA==
X-Received: by 2002:a05:6a20:3c92:b0:1b7:77ef:b121 with SMTP id adf61e73a8af0-1bae7e1caf4mr279595637.13.1718293195827;
        Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293195; cv=none;
        d=google.com; s=arc-20160816;
        b=Ef7Bqp0BgQwYmmTcSRF5WHAkjXvLBD6uqt+rmKsToKRYwdqKdPUQhdfiC+8n5LroaX
         +0g3TlGNEU9RIal1/DaM9+OQ5iC6lFF/ezrm4X5hRZumqssJS20TGzB9VMXEORsPAynl
         /gzpksnW2y02FVVGGUq6Gf283FKXXc0z1ufRBKEXaC75OciwvCLCmUPEYtxEZZG/7A5o
         5qc0JVfDu0n/tbh+jFvfSPoYtwxS6hBRNMs8MV9OjE7sCU9vyIjfdH3zhXXgaVoAD7Dc
         uG2Y99QEe9Qf/sLURHk+b7ul0LNJ4QETEnTkyCJ8uoE2Qfny1Spu9UgOQ35rbwifZqo6
         rqmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OrFUkNCKCdyNkojULrcA9z04Ys3K5qGxpLIcxQ1wcAk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fBgxnfY7Zye6AZBLhE8uuNRUcbyKCkecR5QgGIKWc2md9wyEWpID18xMLQ5w57NqqH
         zZ5BZF2LF924gEwipF+hye+bEhqs1huBXsNUz7Cb0UA9Nvy46wiuNwBFsPhcmMnUHrYc
         CImi1Iur1LxJgYCOZ2i0+1xUwHLhFeVOCS/rplFYOUqr0kskGz0tbqjjqoEHaNT20v6K
         /5m6az6yCtV3/WLvrDKFzVU/+HzXSuYVyjr065pd3gefxmk4/JHM5SdTLw9UumAT1i7T
         bRxUGSr9dZf5pBPao60WoZaw/pCdQpPJofmvSQUZ1z8OT+AgA7GcOqx/YfK2bJDjQQ+f
         rbFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bwkgaq1s;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fee39bb3c1si82139a12.3.2024.06.13.08.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEuZuk004482;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFcUxP022003;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:50 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEHVA5008719;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk1b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdiCB56885588
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E79F72004D;
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 74D2C2005A;
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
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
Subject: [PATCH v4 20/35] s390/boot: Turn off KMSAN
Date: Thu, 13 Jun 2024 17:34:22 +0200
Message-ID: <20240613153924.961511-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZmERwDat_iaHUwLFh2JI_yp4CB75f3A7
X-Proofpoint-ORIG-GUID: EQioorNQlY6wC5efdYpQfigM9KZNmuSy
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 bulkscore=0 impostorscore=0
 mlxlogscore=751 priorityscore=1501 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=bwkgaq1s;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

All other sanitizers are disabled for boot as well. While at it, add a
comment explaining why we need this.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 070c9b2e905f..526ed20b9d31 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-21-iii%40linux.ibm.com.
