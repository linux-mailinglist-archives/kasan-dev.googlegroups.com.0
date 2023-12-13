Return-Path: <kasan-dev+bncBCM3H26GVIOBBFUA5GVQMGQE4VXG3HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id A886F8122FE
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:55 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-42597a77e42sf75720871cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510614; cv=pass;
        d=google.com; s=arc-20160816;
        b=P/gtdnna2JaSwikXBs3g9D++t16INic93rZgJbOBFA/6dZTJiMk3Gkjlgu9tRdTHo+
         HM7ixkpzxgTiLo+GKsgmXIklr00aDqrD6iGhFdMyegAAbM54SH5SexOb2GQN2tt2igQr
         y5n+148HEIJJs/44EL3qD3RDLpD4eP8aRyOd6ngYqiGlQSouwkQ66VDhpRsYcLDaCJoH
         DqN8EUMFFFDDREFfl4JMRMcq7q/NJy+4vYlE388I8SeHP1BGx2xcYCaTlTE0oX8YYv0d
         UyWsPa3vklRCEYPVvh89HLiufBufCCgGKOKAVSHK/MU4B2Fq2BVcq63FP6s8k1kZo8P3
         cxpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=M5dqVY8qYL2XC5gGb2x0QakqTPPk2d109JpRc8yUarE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=R2pt6ZKUvFF/ITBGwTcAjip4fZl2ACpvSa5U0VeRUJbZ3FN5M1LuDDpTiRvk+KqdmU
         2ZweMdLlpwfaf3e8mmoifL5rwazOgk4o3x8tM9+tEa7s2T7hkB6lg4xT0AzlGqGzn1vZ
         icazkvmk4MRFuKigLEyKsWi5X16jztyp+wRtam+LD1KMgYHRM3xsPeZYviGh5PTSOD1j
         3EyHB1tnx3EKHiFpbGsoYhRybJGKSUH1LcAalcEzUSmXNhgBlYxu4bn2hh/r5yKrqryt
         +jzi+SmrJpLSq1dHuQ25cJY4zSM/e9kloDs2EgYogRDuU1pVckoor8GGwCwGGM8sr62M
         b1ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="qsZ4KP1/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510614; x=1703115414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M5dqVY8qYL2XC5gGb2x0QakqTPPk2d109JpRc8yUarE=;
        b=go0TcliHqQAZ7+/zjQpdJ9w3rxYFEtbiCvMSt/1w36/cqMstES+a9qcDaaIG7NQ9Bi
         iEWDn7FuZBQazCNl7Yd9ivmRif2pb4IzoyEtBELbkHravhV1TkkdIBQGdBdBPGkBk2Je
         ZXJ5anzyYDmOQvr1gilHVgxaVsWkIXJYFvvL4d1xvmyfDKyrlx9eGZ4u9Je7XNtU0sN3
         FEwhg+sozcIcCZ94q49oreHUdLzsGyqXW+LHqHFuRKPNeu9S8JNR6ZUTuYPGKhs7s3Xz
         effbbMJa3gSZAJFwBtDzC+/4tLr3K3q00lwW/aw8E8u61XlECtTsr/6DmHmlhUWhP+vE
         XJvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510614; x=1703115414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M5dqVY8qYL2XC5gGb2x0QakqTPPk2d109JpRc8yUarE=;
        b=EIelJjneBXG+wbQquS5hONc29guncGUJ35ZVGsQjCEZB0Jtyhk2uVhTNp/Eb1zeXrW
         tJt7jaKELjIDKETm/lolMR9HSV+DLJhQ9CpJbf6Od0J39Pac47YUHbWlMU1Ns1Mk4K19
         loxb5VWeO0B7hbSnxhb52KmHd1eTTBn7uURXoUhge0vo1fgkxBHryv7CvngyaHCFon5F
         fYPOV+71iR7mCAngo2uDml8uI4PgNT/3M9dHjqFq46akBHJecSgAli2TjzfwBIU/hEHV
         80w1TbpYpXdSN1+n5pGzIM9RksJHMNSlUVb79xjeGBzHf4Fw1AtdWLd5dfvRpRcXoIMD
         TgHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwkTR5Z9UtqCXuxU45s5O/kpibe5s+aigQBP7fq3sgcEpbUtzCd
	5yvxlFoUaWFoApEGzZJx8ec=
X-Google-Smtp-Source: AGHT+IHC9Y8a20+UVLKViVGG1AQqitxQgUyIs/Jxsr+ZCRWnXs1hhu3Hktzqw1bJcVKoinevyPSNWg==
X-Received: by 2002:a05:622a:1903:b0:425:8d08:14f8 with SMTP id w3-20020a05622a190300b004258d0814f8mr10857948qtc.35.1702510614700;
        Wed, 13 Dec 2023 15:36:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d07:0:b0:423:a0d4:8c4a with SMTP id g7-20020ac87d07000000b00423a0d48c4als761590qtb.0.-pod-prod-03-us;
 Wed, 13 Dec 2023 15:36:54 -0800 (PST)
X-Received: by 2002:ac8:580b:0:b0:423:811a:88b with SMTP id g11-20020ac8580b000000b00423811a088bmr11523789qtg.63.1702510613963;
        Wed, 13 Dec 2023 15:36:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510613; cv=none;
        d=google.com; s=arc-20160816;
        b=v4fODd4GwbBjLVCcN0xXJiSpgL0QrJbNUzEzFq9UHl1gZkZvvuN2bJhVYULrnbdzd/
         Mi4zseU4Pe0sDqTbpAq2rs9/hdZsaOes8V2FraRTEC+V7LhFwrD8A4UwBVaxjQ/ahdEE
         A/YRUAoIYiGi+xGdz4FCxTv6KSYUEw9JhTNmHTEYlTwfUD6Cm299ObL8dJSCsz6vf7Ag
         9/+wSsUyhSRgAOe5DJCrKAPrkNFpcG6jBe/qw6tePREDYU3r7SssjnMt6e1ngkg58Urs
         hT5zm6/jgHUFbsi9no6ptbIEOzPQJwlnJm8P7mKLTJEheJrGrYa5r8REQOvdyLunwn6z
         KAKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0l5iE2aLZJPiZ5kg5yzJ1JpoP+UbHI6+msMolAdWlWU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=JCCc6HzJL9UsPz5bKsucOrSVILiUnXdSDo4Pd3u4ZrBieQnggWxDtfkPymr/0igFJj
         vpgd+gliUob7KNYk5QnCoAi23yTOkNFVKG+nYhtSEOrEkExPNZKkDr1/mFqAKlGvw42e
         NoZgbSH6KW509W/9ybmA70sNR8MAUKElcESUOCXJ5vRzIcd6BbrhdyZfSSScp8D3+XMx
         KTc9LSo3fGuJusS202rgWToZmxURztYmB+lzUaI2L9+gfBwOemvpd/kHw+FS7Dvv+V/Y
         djXL+1tcdfsUsREh7TFbEd8c2XJq44fxGaJsiHx5iX8mVUEm8hzaDbOCDidvNmi4aQQ+
         2JPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="qsZ4KP1/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id u15-20020a05622a17cf00b0042584494cb5si2472478qtk.5.2023.12.13.15.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:53 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNWvNe008721;
	Wed, 13 Dec 2023 23:36:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce81ws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:49 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNYKtw012549;
	Wed, 13 Dec 2023 23:36:48 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce81wa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:48 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDM1JcB012599;
	Wed, 13 Dec 2023 23:36:47 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4n9v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:47 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaiKq19071496
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:44 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1BC152004E;
	Wed, 13 Dec 2023 23:36:44 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AD91F20043;
	Wed, 13 Dec 2023 23:36:42 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:42 +0000 (GMT)
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
Subject: [PATCH v3 22/34] s390/checksum: Add a KMSAN check
Date: Thu, 14 Dec 2023 00:24:42 +0100
Message-ID: <20231213233605.661251-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: MHKnPyW5x6icSzfPHJK27c1dMynNcUTN
X-Proofpoint-ORIG-GUID: na0tv6_fX2z243noK5Kk-h_zifB4EtHz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=863
 lowpriorityscore=0 adultscore=0 phishscore=0 mlxscore=0 suspectscore=0
 priorityscore=1501 clxscore=1015 spamscore=0 impostorscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="qsZ4KP1/";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index 69837eec2ff5..55ba0ddd8eab 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 /*
@@ -35,6 +36,7 @@ static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
 	};
 
 	kasan_check_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile(
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-23-iii%40linux.ibm.com.
