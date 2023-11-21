Return-Path: <kasan-dev+bncBCM3H26GVIOBBCGS6SVAMGQE4BUSDCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id E04567F3899
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:50 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-28035cf4306sf245921a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604169; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQEohOXH914ekBeh6uUW8sVb2HS1LTxpDu7Ljb+ra5/YxKk9Bgdh2zGPLnHF5vpEyd
         81Izxk+YtwyTD0aMGYo+uH4HlEFbkAGlgBX6N5SVQQywT88XTCN1mxMphQLkaQtMLTRD
         +/k2UZQi3dn3LF1Z+SanLWQ/hGTb4H31HBSq37O1OwgOqK/nhvvgXEuiGVNAM2b04Fe1
         wLdHicN71IEkt0HYKge5Y+35OrEhnC7/ELJRxDnrtCp21vcgV0jVgzQ2G6iNZ9a84nR0
         9HQDPb3JXVGQT9d27UvsmKX2+bvwQd0GzG2BdjQRhIlqYphII8NWe+qWD61jN1N/Qh6B
         sSkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fAz1KHpdUHvNH1JcCc9/pN3eBs+i/AGS5HaxLkY6/L0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zTV/Gv2BXWmqkvK7uWPoWllGe3KvHqJ9d7tC0GtC41ksAc3wNKlzyQCyXWqYzP2Pdo
         oeEQ3QgxIsA8/fw0m4lioZDTkeNPUiR/XLS6m1YVeknXzClcAzkaPdOuqQgyPymmRavh
         K2r0nSJeTL5CHqxzaXvZS/+KggBUicSoknYKL/sDz3g8VTp4SegNAm6PiY7zb0KhXnjO
         0I9PBEZcof0EOmdO2kmkdYE875xIp0sABxULcJ+2UFq7CxtiWClSB3bspymmPYgzmvpp
         GVe9DBW2cO8jQuz3KMWOCdinEJe3AM+3Vu3+N2kkmg0yMlTCr2b72nEXxenpKf8111aD
         Y00A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R7uyF5QN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604169; x=1701208969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fAz1KHpdUHvNH1JcCc9/pN3eBs+i/AGS5HaxLkY6/L0=;
        b=Td2b0QjthFX7VmxcrQP5VSiQBGO60bMXWlVuQP5vbLuPM06oKDqcHYxqVgE/tYixzf
         erM3KmJHMZum0mnItb+e5e1uQ8ijbqwYi1cfnXvOfGRe02LGLy/DmvWKJRs0LyRSptrz
         5evdVTRs+vyDg2FtSUTpCVOHOgE3eNS+3dBtaj9+66sXmchTqcZYknAhz89OTCu7RObP
         P6BmMpXR+kjalfKGw4UiYEyZ8aw9w9GDdrzTPrZPABAekcAIZKjXISj6a3RiAKVSuIoe
         3osV+bu8uhft7Apv4D23zxTpWAImP7xMOvv6thMnihE2sT5/nlidJQxtRXIFrVuOGK21
         OguQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604169; x=1701208969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fAz1KHpdUHvNH1JcCc9/pN3eBs+i/AGS5HaxLkY6/L0=;
        b=vJvrI/6GlVOpGE7y1G1BO4gYujTVhCaoCoVvXId2dk/FTGzsvF2XkkYhndlLtcUuJX
         rfBNXT/yYLmuHREdOHVEAzsmkKHgi7wH8gYwVKkkddXIFTHIeiZTEGz2di2srzaD4iWE
         4eDyb4yfCbiV2xsxZdlwznP5mqCI/6DEgyHA81u2XSawPiHg/bLxayqZQVToq0GX3U3O
         bsFG7nsA6WHdLUoC7ogXahYp1Y76BTmmfC4UDuG5SiW2s10Jd4UpMcxnSbjkIXnZza/I
         699SYIBCeQ2jDDXD8iSTF3luDMxOS9U9gqNwdqgq0TRjkvvU7Q09xbaxlbziKsc4W54A
         T+3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzb70CeuFkqKVwr/gDWD3SptKUS0Rm5UEL5m4s4CCRHukyWI02A
	vH+GrrnU5Js9OjPvJLKcbc4=
X-Google-Smtp-Source: AGHT+IFdV1L0yjyCGrTNSoAjGFBoro+bNZTSqp/V4TdRAkjLpwWtOzbEOWSUyne9OysBw+Hz/1CHOw==
X-Received: by 2002:a17:90a:fe90:b0:280:4a23:3c84 with SMTP id co16-20020a17090afe9000b002804a233c84mr5658116pjb.22.1700604168711;
        Tue, 21 Nov 2023 14:02:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4fc9:b0:285:196b:e7b9 with SMTP id
 qa9-20020a17090b4fc900b00285196be7b9ls159723pjb.1.-pod-prod-00-us; Tue, 21
 Nov 2023 14:02:47 -0800 (PST)
X-Received: by 2002:a17:902:ecc1:b0:1cf:6542:b4c8 with SMTP id a1-20020a170902ecc100b001cf6542b4c8mr1020750plh.21.1700604167606;
        Tue, 21 Nov 2023 14:02:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604167; cv=none;
        d=google.com; s=arc-20160816;
        b=SeNZykYswvte5P3cuO/rphtxlG2r4iJXsn6HsRhtoRkmjGKpaFJ+YeZANSfTvZ+gOc
         XyHQ3j87P50f4WsL61Tt9GnNCoXeQ9RL8cQrv0Tlc8VfcUfkIH3ZCCDaOiRI0nmJtl1T
         u1G8uDjSy2hhq2pwf8LTQFKty09U1fu+auGCPiAb1/GIzDTV33nrCpdbxUWFRJ9Au9W+
         W8fUvYYV6T6ZTNSehf2cY66QAS7cWn/E3q/KYM3/hppycATMH9MAXvR8f+rVhUCYvPgW
         su5bfGbofWEyiNEW/S1M2xeajTjoKS8KajvBY3etH7ddtMf6K2lnhrfSNBry+J+LOMav
         F0Gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FBHiR0R3HqDameObtBi5tDwt9B6xgR+xiaoV3r5rhIA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Y0fsKc7HUUqW3Aj3OcIOBL7nswAIDYv4ATnq9oeLK5jjGIOR65tlX2jwdZx2qpId/s
         i7bIVu/3WuHthj6FvViAc4rYZWw+VBuzcuBlielTW1jtey9w6PpTezyxg1/1qEDgc6BP
         Tvsw4fnIoQmd/UXqZzisSdXp7iS2e5hzu7fJcNOxoMQONdDtK98E6cHGFZD0dE9hH1rH
         psh/Yje9ZkZ7F96pXDMSqfYFBVSCFLjq4iJn+s6Ffpvqhto+uYPuIXeMH7ZQyU1DBRVF
         n35iXZTxBpR0Ius9pgqqii795zJkHxIMoVST5r9bzhmx47sAGIpiMKDzY7aV88s7NX3F
         cusg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R7uyF5QN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l19-20020a170902d05300b001cc5b5f692csi518966pll.0.2023.11.21.14.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:47 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLv9hG004965;
	Tue, 21 Nov 2023 22:02:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85ar-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:42 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLwvpK009496;
	Tue, 21 Nov 2023 22:02:41 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85aa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:41 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnWGn004713;
	Tue, 21 Nov 2023 22:02:40 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvj4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:40 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2bBa15597856
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:37 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 31E082005A;
	Tue, 21 Nov 2023 22:02:37 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BA2DB20063;
	Tue, 21 Nov 2023 22:02:35 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:35 +0000 (GMT)
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
Subject: [PATCH v2 18/33] lib/string: Add KMSAN support to strlcpy() and strlcat()
Date: Tue, 21 Nov 2023 23:01:12 +0100
Message-ID: <20231121220155.1217090-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: b6FO-wjNpOLbu-pXCF5KwWPZydmy0FRF
X-Proofpoint-ORIG-GUID: BYbwoAtxv4M2QJEIoKEhTF2ta84U2GAL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=R7uyF5QN;       spf=pass (google.com:
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

Currently KMSAN does not fully propagate metadata in strlcpy() and
strlcat(), because they are built with -ffreestanding and call
memcpy(). In this combination memcpy() calls are not instrumented.

Fix by copying the metadata manually. Add the __STDC_HOSTED__ #ifdef in
case the code is compiled with different flags in the future.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 lib/string.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index be26623953d2..e83c6dd77ec6 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -111,6 +111,9 @@ size_t strlcpy(char *dest, const char *src, size_t size)
 	if (size) {
 		size_t len = (ret >= size) ? size - 1 : ret;
 		__builtin_memcpy(dest, src, len);
+#if __STDC_HOSTED__ == 0
+		kmsan_memmove_metadata(dest, src, len);
+#endif
 		dest[len] = '\0';
 	}
 	return ret;
@@ -261,6 +264,9 @@ size_t strlcat(char *dest, const char *src, size_t count)
 	if (len >= count)
 		len = count-1;
 	__builtin_memcpy(dest, src, len);
+#if __STDC_HOSTED__ == 0
+	kmsan_memmove_metadata(dest, src, len);
+#endif
 	dest[len] = 0;
 	return res;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-19-iii%40linux.ibm.com.
