Return-Path: <kasan-dev+bncBCM3H26GVIOBBZ4R2OZQMGQEOC6UNJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 813FC91176D
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:20 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-44054f0bc43sf15816131cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929639; cv=pass;
        d=google.com; s=arc-20160816;
        b=DZcRzUSyiFa1yyIfo84pGRdrhzmPZO3zmHKq+3r00soz7vEKXQk0e84ZAZmD56eCvE
         axvOxQI5hMmZTBRDS98l1Axg71LM+fTBgL6iepGlY4KU0N27Pqq3iG5vi4/V/jKWazbC
         49Vdomct5vJwdKcaiiKCSMctmDILbRL6a3JKnZ9Lg4OAs4sa7XzPlavZ2VLCDDl6Ednf
         VMmNyf5y45ThtR62lYVgh4gXazSVebxzd75KhyMMB0uMdpN13FeUda3gYjp2cZqatdk+
         q+Wtw5oLr9fVCAkZTSFPTCyC3LIJ5v0f7pejaa/ht5hWZsVafTO5j+tJuT0UZBFZiRTo
         Kk5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eLHGAHVtsZ7NZtJyDHqDfgLAPeg8SsXXz1YGfyVg9r0=;
        fh=JVIgd2oPwqaVz9TnWL2Epxf9bd+iycyTLmthEMcs6vI=;
        b=MEAghUampLVdxhmTKrjztkQ3kgg/jMKYUypNOuTQaoZHAtwHh/Drr3X+vmJonr8uNm
         Jtk2mlkcpUM1/GPTr31XRwSo0NRQTKrkp5d+i9ZAwv4guFR/651Nz+itWl4f6qwfsbmB
         TR9fM52mDnW1NUPT3cFPXr+0Q1bYDX2uczlnkYmSTbi2csdTj5/y77nROhCE7So+MRAO
         Os7p2Z7/v6Bw2QUAfExXLUY5wFIW9Pf9Qh54Yd6lUPhO1SG5rEsyMBtFZPyvcoITMLjd
         fDUNLqPynObV+sLmWStLzl0nzJpiWUEfBxRRD7q2N39tvwmmFVwNOCKPpqOS2oacM0g8
         gGfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nEk7JSnj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929639; x=1719534439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eLHGAHVtsZ7NZtJyDHqDfgLAPeg8SsXXz1YGfyVg9r0=;
        b=H4Z3NnedWLhiE9fXFOL7vGD8+bENRm75kgD8s15I7nF6xdLltNOT8a4smkAE9Mqd2r
         wOPbg23oIQQw+Cz2sDGaDLXV4lH2jVkXTBp8d0Ip2k2TPLh7bHfLlF7uBysuGTG/Xmx6
         BYEou5TfIPZLL9oVrulpjQAEdWGUHC4Jql2OqnGaONbLYnec++2WHqijcNkFEoGqNQuo
         ie/DcajEgBqLBOpVE4nSJxMG1ELjU9lBAe6YRe9m3XjHTnzBXgMxL0kyyYvJ7u7Q2cFm
         FqmLMUQ28Fg8IVdPjBvpBknhACyH1vTuZMeonFhjLp7ugIBbBOxT+cpUd9wA1G4LR/85
         8snQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929639; x=1719534439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eLHGAHVtsZ7NZtJyDHqDfgLAPeg8SsXXz1YGfyVg9r0=;
        b=CShwRdQkMfhEKWNwnVg8ZVkQiJKA1D+/CXkpKN0B53cCL7GJqW8mHqAGddbKfTk91D
         d6VDc1pEzKL1EoGT8tq3Yu6pQg4NHp99lvf+XL+ygqOczE1Ugi69OYB7IHtPBHd0Ol+a
         r/kOta6lycthhuJAp1mmcRSZDQx8cehMZhHC/0t8/yMJsaoky/O5uvmYJ6Phyqi0hKfZ
         b1EtqaRYfns8gS0lFS7jURcgNJ91MLC8sKVrUVjMCPK93K4n6dWXEHc9LFpLK8Z7OrfR
         fHm4RZThoeDC6NDactqU1FpH9ClEw0r9PaWwxo4lEBFu7IJ7l813xgQmziMkTbJDulYF
         8E9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwKPMH/AWDuG8kmv8gXypmEnbEd07AbHkAnPRBssOJJegzQtMBxogCBDw23Tlge79v4X0WPujZ/uquKv42x0zNYUAM8Qqi8A==
X-Gm-Message-State: AOJu0Yx0KNOZ+oez8vrqMT/0rKjfSRfO/sXzSJPjSFi1xk5cATL/eG8G
	eTIUI5H5Sl/qy/cCWt1X5pPyiaByT1vCu1ZeUuQEcBNTY66MOTJ9
X-Google-Smtp-Source: AGHT+IGm2dRVY9Rz5yrGjxUBZ/tT8pBqZk+wsiVNKxtw7XDaiNGHnmoV2lLO5FWuVBNZVPf19qLoaQ==
X-Received: by 2002:a05:622a:1996:b0:43a:7c0d:8921 with SMTP id d75a77b69052e-444a7a60a99mr78741751cf.53.1718929639463;
        Thu, 20 Jun 2024 17:27:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:12cd:0:b0:444:b60d:da8a with SMTP id d75a77b69052e-444b60de1bdls13458961cf.0.-pod-prod-05-us;
 Thu, 20 Jun 2024 17:27:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnsrf0BidXBfTXPO6qObv4xBkO9DvGpO4w1yIenDJzx+f6sfYXCffkafRK7aL7fEPEkxoBVkrogtw1X5MCG3KGqlYtWvsa2EZuwg==
X-Received: by 2002:a05:6122:180c:b0:4ea:ede1:ab15 with SMTP id 71dfb90a1353d-4ef277c90a0mr7341896e0c.15.1718929638015;
        Thu, 20 Jun 2024 17:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929638; cv=none;
        d=google.com; s=arc-20160816;
        b=Y45Cw59D2qik+lX5+5Du8yvoFJ6UA/ARYN3GlVFOu9Dyo+LxncVJrqBQwupRLD4NWZ
         xqAHS+ydamokor54vxt7v7iCqu0h1X9aCvUdNRVfTUp9ddE903bjWUkOp6f2ATTwnA0k
         aOCWwHIAWD4AvqcnHbvGvDxq52o35SahF7Pvz57JRoFeJRXpuXdIVkQbzyGKjGWArauu
         r+JXiEjAqfgQDvEf1UOVo6ocsS4fxFKZTprr/Ra+RXQmvIU79C7ZcMNcL2Oj44XYLJR4
         nhSJ7brZRr3znefpGJUbJ8z8WkZxVo8p2moveglfo+N9/i3+gEiciuZyiki9oF/m1OwJ
         SQZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IRZnfl5kegw9DdaMeWWbTwWzCErv31wkZ0fJjvxbgdM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=0Lk6NngKuqVYZjrMMQ4SafrA9kp5Vuk8b/FwQzZOMtu1LlLfKStgDFbgW71foOSdW2
         TXmfYxrbp30yyJEYhuk4WkVJhflOg63w0vQRCCm8t2u9q1SGtyhQBnn8Y49cD4PJELDI
         q1XSz1lfPPSb6nb/yAO2J29cgIz+u6fwF4jzK4f6KtPYwUY1ElpagGzVYPEKVSJ/n8KB
         omWnUx8ixxN7NkxrwCFO5ZjXj5UPt1ZA+uoEG8x8fdQyHrKpH9nrs6iRO52LJo4usF7s
         XCf0nVItLoWd8b3oQgPIdF5uLsU512RtiHCf6vu3utzcfbteeReQn+g2XebjTNGrkiMz
         IwqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nEk7JSnj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef461d2c5asi32010e0c.0.2024.06.20.17.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0RFh6024999;
	Fri, 21 Jun 2024 00:27:15 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvwpq85fr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:14 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0RE4B024983;
	Fri, 21 Jun 2024 00:27:14 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvwpq85fm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:14 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLf02F031380;
	Fri, 21 Jun 2024 00:27:13 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq2ne0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:13 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R7eV55247218
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:09 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A8C402004E;
	Fri, 21 Jun 2024 00:27:07 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 881AD2004B;
	Fri, 21 Jun 2024 00:27:06 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:06 +0000 (GMT)
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
Subject: [PATCH v6 39/39] kmsan: Enable on s390
Date: Fri, 21 Jun 2024 02:25:13 +0200
Message-ID: <20240621002616.40684-40-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: PP4qwk9tQyN0OUNhProNnVvWgrOSmEgV
X-Proofpoint-ORIG-GUID: 6m8QoD8TaCpte32SN6f3pDfGGHdINFD2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 spamscore=0
 suspectscore=0 clxscore=1015 priorityscore=1501 impostorscore=0
 mlxlogscore=764 phishscore=0 malwarescore=0 mlxscore=0 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=nEk7JSnj;       spf=pass (google.com:
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

Now that everything else is in place, enable KMSAN in Kconfig.

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index c59d2b54df49..3cba4993d7c7 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -158,6 +158,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-40-iii%40linux.ibm.com.
