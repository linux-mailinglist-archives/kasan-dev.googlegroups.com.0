Return-Path: <kasan-dev+bncBCM3H26GVIOBBUUR2OZQMGQEJLLNDOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EF79A911753
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:59 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-375d8dbfc25sf15068665ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929619; cv=pass;
        d=google.com; s=arc-20160816;
        b=e61bDbrLPjl02apbahBj9Lyeb7vFNBxMzfcD2aaYa0clsimZZBkbPe24F3seGd8z5X
         qf5h0PSQZAuebZvaRJWEJ3WJW2Uhe/zjHAfcGRB3H+HL8cSjOyS6EmAx9/pdgFzBApJA
         2huGxLhFdu6L/b2Z9F7LiEQ8wl/HzjRi5uQJ1trn13i9yxQr6jGBXVFv6h4nzd8BtsTg
         GdJvDnHs1ml3HStOTunGpJRFxHg/Iv8xaWuJLR65wpqeT/8UssrhAhXYyYckVKz4dZv1
         UXegMIqXy/qZHr+mQnBobDI5VGKcSOQHRPxYQwvQFtYEtqMdxmrnEN8vJMcDTBAZNqOy
         yf1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bIGLP5uT46B1N/bKXJN0XX3FDbR7uc1MlPcij23Vnqk=;
        fh=ukV6g3nUk+axJKg7ARdN0jcJxxmkPxOgs+IHABFmyCo=;
        b=ielluAKdpYawREAm1ajg2iWUtxODyxZiTnTQTxfqq3Pk2Dh92u1hRlValv8luMNKyz
         4tcuyDgzo3jOzWfR9EcCzT1Cip+c0Xcgt/sBKM8Olz/cqWNfvXVnCBUi7XQxNvMuNuvr
         Mhrx8aKQ8Yo4QCmKHgLTipb3T9yqwUe2nQuV39xrytp3tYundz2hjqlmsHo9re2lPZ9C
         ecGehPdamn5jAe3pSw6sgjw7OG7kmDUljyJPYxHcUs9pX2Q8niJWskdbM88c0Rxw1raM
         flrwRjPgV7esJIrFlbfnmh6jjAzPz0YOtBdB9F4O/F7UFvwAC6rU0UEb4/Uc61PDX3Vi
         w5Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KYKLp6Lc;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929619; x=1719534419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bIGLP5uT46B1N/bKXJN0XX3FDbR7uc1MlPcij23Vnqk=;
        b=Y0nu18qG4UxpfM1SoA7ZSXDTj0uLeiTRkXo0hW31WhVUPepze4o1peyaMKz2Ke3vu/
         cc0FRk0xYT7ZtWfhc1SY5fDmJBlA232+qa52xBv/zlFcS9u3F23p49cmHJKiHPBAN6Qd
         944Ers7Dj/mDcmzUn2GHS2NhtH1dfxXZQcNKPjCbMyxadStCzxe7xpVI3Lr6+21BEbEW
         Z86qORnbeR9MklSBXkJrmWcWuRyDPCtc0UUpNXxLwwGZYQKzSlEwVZdRMPzOTwtMO6V8
         OqA0NjXWlkrf5PGuQJw0jYHC+wfdrcJj3io9yqf7OyHBKHbbEthxOH2wULTuEMxu0gdA
         uNsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929619; x=1719534419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bIGLP5uT46B1N/bKXJN0XX3FDbR7uc1MlPcij23Vnqk=;
        b=PPgdADrZ2VOmRNSjyAD0e3xXuD3uGdHJEz0tQG5o4Ho+fckgER+hT4aXYIzn6YDNDm
         dzjIkX0iSeeqh0bu4ce2p7EB8xS184qwq+VcgVq7T+042kAfy2RXHNPp6ViW6FMbD3Pb
         rB58gE8wpaOaUbNkF8s1QpohHecQc0dpAFFzypa5r+UGQNtL8vcxCch5CZBq1NrDX+IT
         LII6Dkw4R+6KJgjlfZryQsgi7q7V73GUH7SUg70i837nGhTM0zepjXQMjAw7M+MXq09c
         LvLTUWuF1eTCfwRZdnpOWI7/hmumTQBkZJTQ0lPOy5onpkKOIJk8DtecHhyNVdUBazEp
         43fg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVg0PG1nMdRfF6M4DCq8AGD6nZXHH2pcWNbz3XfjgV1t+yI9iFuRY+k/jPS4/U1fMmKDYt8HrcakrXrFwktj9Mw1T5tNzjOJQ==
X-Gm-Message-State: AOJu0YwQcz9NrvVQJjb/bkYMyg8BjLSnegIR4lqSI48XLJHS/b5Wzt0J
	sjwlxJTXBrL9IMAEmPdqjyfWTbGpmBGp6WmxZgpPNGRiWBFY94Sk
X-Google-Smtp-Source: AGHT+IGGdZ6zBtCYgoW4C0EILwUB70GbfNYflFt+/jiADjugOYG9hcel7cl68OcV6KIbxFo8ZhR9/A==
X-Received: by 2002:a05:6e02:1648:b0:376:2202:a81e with SMTP id e9e14a558f8ab-3762202ae74mr65823675ab.26.1718929618825;
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c248:0:b0:375:a281:a669 with SMTP id e9e14a558f8ab-37626ae41e0ls11921475ab.2.-pod-prod-05-us;
 Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPjmpsxbqZdgKo3KyFkzbzAWFhIpJVLV6LuOtzPHKvKH4VExq1FgpD1IxfxQUpM+gbFxZFEa5BS6etSLx4Myu1g9K7Fez/6TIRXw==
X-Received: by 2002:a05:6602:1488:b0:7eb:ae17:c237 with SMTP id ca18e2360f4ac-7f13ee7fd0emr823412939f.17.1718929618169;
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929618; cv=none;
        d=google.com; s=arc-20160816;
        b=m80wS1FwENNyPvNml4bHJ4anAYxJloJ0YbHrKND0s4mx6SpwQp8XhAVMmGIaglmtqm
         BTQ26FxbXMDMVb79cVc+JcHJk6moJuuVNmqNPsC6RuOVDzEte1c3QL3hTfHnX2LlAHWo
         50kEUACEk8erctSQ798G9p7m63wRzIDymdKP7fmL4oCIJfILAtNGSV3W3XEmWnGG1CU+
         nlmnT9xnWYd2DO5m+M1/+TMfDrss95ROOG7mQbIV2py3BmHeXaZxaaUwrzuVNnCfhoy5
         QB+3oV3EUFktZ4vPFFB9XjRBN7AWt6YvO/a8LKzMXmHlT4qp+CRKXnGFF9Xzd1izYY/0
         rf2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OrFUkNCKCdyNkojULrcA9z04Ys3K5qGxpLIcxQ1wcAk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=y7UKiiCGQNCvVvdd7DFXOImzrwQB75l6IobwRfELaPYZ/9Zq2VXoxKdRuqZUgT7Jqj
         UNR5PJJSMC2iJhxKGo7Rd9kJIuOHBJ1h+MN4EweaJTDASUbwkA5gBmhoKMFfjs3t5lfW
         KXoGlvcwZGRiAP1I0o+C+7BSDSqM24dI67z3w6DNygbJtkJENv8EFWHGmKIHDj4mdHjx
         LQ47YIB0SoE4ZMha1lIBgC7f4VtUxQj8o3CCrDfyYpRu807k+PG3aA+MSWGCysT+7zqK
         W82o3NETV6VGElVawaQoERvKEA09eBaZJMvpl/eV5SOveIEINCbWKba2n4PubENKOYME
         TYEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KYKLp6Lc;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d1c10a70si9824173.5.2024.06.20.17.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNunGB003964;
	Fri, 21 Jun 2024 00:26:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07tn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:53 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qrn4016999;
	Fri, 21 Jun 2024 00:26:53 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07tg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:53 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0LpV7025805;
	Fri, 21 Jun 2024 00:26:52 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nnc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:52 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QkkW54329664
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:49 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E0EEA20040;
	Fri, 21 Jun 2024 00:26:46 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BC62020043;
	Fri, 21 Jun 2024 00:26:45 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:45 +0000 (GMT)
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
Subject: [PATCH v6 22/39] s390/boot: Turn off KMSAN
Date: Fri, 21 Jun 2024 02:24:56 +0200
Message-ID: <20240621002616.40684-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: KqfiPqK70_1rV1P1C1Gy61-oQxzvQyn8
X-Proofpoint-ORIG-GUID: ZAgRwklkhYOmeFVehQ1O8m4QPib-ljUF
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 impostorscore=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxlogscore=742 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KYKLp6Lc;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-23-iii%40linux.ibm.com.
