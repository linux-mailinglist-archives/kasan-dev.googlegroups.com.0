Return-Path: <kasan-dev+bncBCM3H26GVIOBBTVFVSZQMGQEMASIVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 40C849076EA
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:00 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5e4df21f22dsf899900a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293199; cv=pass;
        d=google.com; s=arc-20160816;
        b=aqH0ZXKeRWg92zbo1mM1GTydmoa6loygg5qKTcPBni0SvHezAJb6oAEEBqlD7/AI0e
         //IsiJKw9T8UOW/vGwkRprccPERGrRpjITkBbnCv/+hp0st6PbD7lmnvS2+QxWvQ3Je8
         noznmrLaD4MaP9C/LMtr3Fs6D9YDgptYRGB6dH4iYUbXTjOhV+m0af2wX2VyEB8NioSv
         n6QZied1rqAjrcGBgyVx/qiXtuJOj6qxK6sdO3S2vri9410h9wW8toonTWoLoAcLU9Z7
         Sr5yHAzbV3qtk3RCR5CXXDMR9/pmBBmP9W5UJ6Nguwa70Rti+wGB7drMXPEhDN/7prMC
         GeNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=63tdYvF7DbnJmZyevVe4u0b2xa4Qr1unN6TsNc9X5Is=;
        fh=ynpmdppdYpk5KUOVezv7SzZP0Du5QJ1tEceT/QBr7OU=;
        b=vLssKTVnuEhOvpBZyv1yRACAddUVj5LhfbU06vJ/tPLPIWNosunQN0uVkREByyje36
         v/UDxG/imUYdjeTdIDNtQxxDcaYg3AxmpQzyfIFc54whlZ6s5npNVXxXLO56wvhyuRBw
         JbsyGaARWM/h2OHqf6qJpVXEFThUvJjnZTdU7EVVF6Q9hJOxAPTCX37H/jmo4C2BEAGZ
         Epkr82HibpyG481T7WMQOg/UPlWFyS0+qmTVwXeJ2IuRJZvcQT+9viDj7JpDZsMc7DJQ
         nt1Lua2S7o8zIljlDc2MI18aOgT2jBjMfjbmZhxUpPO8e8YZ8mVXlBXJXnAXCys0hCoM
         67ZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=U6AIDXy4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293199; x=1718897999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=63tdYvF7DbnJmZyevVe4u0b2xa4Qr1unN6TsNc9X5Is=;
        b=Vn+/eGOroTAaLHzd7jxxzL65RpXIZPbeKjtg1ej/vEbWA6F0vHZbuQLOBpNLoL+YVZ
         6jLF9BmOjaKRn26xlIsaf55sGvT5xtkEltzzC3a5IEbleFBmwh0y1UdOKDmVZQzmxz5/
         3PO911CSrVPj66eJxAAyxjfqKwC8bCoOJT5xLduKtL/qso3XS+K9jDDiT+jKsidjc3rA
         jWCi8o9m+yfopiFeRMpafYy970k97Mq6fvdbK5R6FxMiEIp/RXRUvWUPTjN8LJpRqVLV
         rlLurvV+ZVQ301FMBzh3JKpvB3o4/Jp0wDuYmI+7dV+2YXtyFyxGdlYcjIt3HS1rmiah
         Ds1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293199; x=1718897999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=63tdYvF7DbnJmZyevVe4u0b2xa4Qr1unN6TsNc9X5Is=;
        b=PGcErnn0A3jrigUbEMteJ7aCD5ud06IRxgOrb7EVnTr7M4neVqC3I9CduuGJZH/0U3
         nN+cOlw0LtWG/hEQUqlIgYfvjHLQmJHg4mVD4ixEW+st0ciNRPZtINZ3TpcJkHd3NVU6
         4olopL1DjEqm5SbD0nhbm9Eign31Almi0+V0+MY7m2YRCgwfdrZBOg3wfw/vguRYw176
         MKiXtF3+taMX3tn+0hiSf2+r89Qlm42kxwVgsH7J0viXSJ5AjZPpYLo30uaFgJMm/41+
         0CKzTqDRHbfykdJNaX34i5dxCP766H5zLCFlz2Euhq3XBOibMVzC0x8bGsQIZhW+dJUv
         13cg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWENi4A1BTZjx8uEKi3Y5FzRFjpZpV1S1T1AOr/9RVNPX1DGBQGupSEkqUGN65ZEHOkr+cn8vlPdAuCJ/kOc82ly772sOrWuQ==
X-Gm-Message-State: AOJu0Yw1cJZO/0grhjHg+FjOnN9sfvhE4ahSJ2h5VYps/18kS6lDw7kh
	uLL2wQe3Xtd97BLXYsSG0SXwbPBJoDv4VQD30+ifrcDsdWHkLEJz
X-Google-Smtp-Source: AGHT+IF6Z5FHDHQEjQ6pHuY1bbwbL7YKio4XhYty0O2qMLq/4gEWHqY7FqL95abFpheA7zWjOUk2Cw==
X-Received: by 2002:a17:90a:a00f:b0:2c2:fda2:dd3a with SMTP id 98e67ed59e1d1-2c4da806ab7mr260392a91.19.1718293198823;
        Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c8f:b0:2c2:e09d:dde6 with SMTP id
 98e67ed59e1d1-2c4ab10a4c1ls1271122a91.0.-pod-prod-00-us-canary; Thu, 13 Jun
 2024 08:39:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+8ElXvQr9ugzsnD/vgkjAw41hVypsIaQtqfUuZWrkevtjRkWa0Nrdvta9jreN7tmpYIyWIEFW2JnguvgGxrRiajjG3Y/OVMutoQ==
X-Received: by 2002:a17:902:d4c9:b0:1f7:2185:d2d9 with SMTP id d9443c01a7336-1f84df9b371mr47682555ad.5.1718293197525;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293197; cv=none;
        d=google.com; s=arc-20160816;
        b=RBuGwVWdbfJodqbTt6MWEwv0vM9qLAHutkzuge7/zsDu5Lp3YCRfNfGX0IxHyKU9a8
         kCy28USSWYSYnCkm/yzI/5mJfP+82oNnJDrmk8olfJd2ZOO7S3APOq9SlPfH7HKwmgAv
         kDLotRdPuinOtz/0CRW2Ho2PhZ3oNKlrW9W/l3Hbhe8sPCgD+E1RiuySkPelYF0VMfsj
         /QXw7HVXJukNu2IpIVhVJKPLkGoFzfld2V1l1UEqfiK5vl03Nzec3vT+WoBPWPW28T1R
         DZMRpz0w7vzJR1h/neDq08LGlX9IMPCJFFvk+CBdAVEtYkaumstWLc3sSbGkDuFCfVAJ
         G5FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=K/viBy/PeNICITSZpD3tBAO/npQA3ucnq3Zo5JONrlk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tK4ZHzzVpa3okbsLKhSfS2lTtNJysWt3FtOtOrin6tCejFZKGaukwN7dUo3wG4gTh3
         sfsJIks9v0OwMDUgYwXa8o8nvM6NmTGQfwF+3arRfRux5w91l1AEiVV+duzN6M9xbJ/q
         j9Hn686AhWkfnR5SFTdjXrhmxn2pMBssnqIkP9zCWr0O1ydNMERKyn1ZvWsh4tPd81+y
         eWq8ngXFstEcBrEpiP5LNpxb5Db3nkBqeCzdMwrZ6JQDoA8hSDuUqNCGpc/v5oNHoXGC
         O9YZgdghecjJnLuIDHxGlCNJYstCqhBkdQDdXb9ZSFCAMndSxIV9woL7OJECa5nS5xYd
         MMTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=U6AIDXy4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855d19cb6si579595ad.0.2024.06.13.08.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFRYbL002861;
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11ynb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdqOm026511;
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw11yn6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:52 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DFUHam023618;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn3un0qgy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdkq549152448
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 205D02006A;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A1FE720067;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
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
Subject: [PATCH v4 24/35] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Thu, 13 Jun 2024 17:34:26 +0200
Message-ID: <20240613153924.961511-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: NyD-y0SJac09yWbU3jUOV5qNtJcZM_L9
X-Proofpoint-ORIG-GUID: pUqzwXrVnO1fTFWRkXk2e4WzMOvYMG9i
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 malwarescore=0 spamscore=0 suspectscore=0 clxscore=1015 lowpriorityscore=0
 phishscore=0 priorityscore=1501 mlxlogscore=770 mlxscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=U6AIDXy4;       spf=pass (google.com:
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index c786538e397c..dae8843b164f 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -542,6 +543,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-25-iii%40linux.ibm.com.
