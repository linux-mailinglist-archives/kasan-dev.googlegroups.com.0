Return-Path: <kasan-dev+bncBCM3H26GVIOBBK72ZOZQMGQEO6OHFZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8388090F297
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:48 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-6f9a3dbeea9sf7589118a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811947; cv=pass;
        d=google.com; s=arc-20160816;
        b=Shpq4JOZVlmh+alO5mLGKhFUmbTYbMJit2SOc1GpsXJcUMc0ca8z7QWOOQf43JUaQv
         ju3kjcHxIB2zKOQETFOMhmBFx/U3rrZh3KDrjNN1HQ/ZpcSbeGkZKxZIASg4QF3ZiW2K
         8K3lZAMjfkXB7DISsQthgExl1xRFMDzPpcws6aSuvZZBWB94DhUKIQa4EaaemLUiqsOA
         uVS+vFmBTB5TXiUfTGJ/jOb/MevVmzKhZdRn4GIx+FKq7i32JdcvnqBXJ+JhAvEmfgoY
         MJnnYkYYoauXHDVdk6pZH9KfyhW/TgQK+Btn8sJN+0k3ZeyflToHVxAo6GjomDONq5II
         Yn7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=unwDX2wDjqDOEogdurxy90ZYsrwF1wF2kiv7RNCsL3g=;
        fh=gKpPd+Dz1onlfGHk1tqyhBRu7vohFX4mSoErTVEB6mI=;
        b=KDJkYCOCRrk8n/eiADxX3+9GnHZBY1Ao7xHmTkr+YBXBa8yDlem8KgV4uomlKfTmYt
         OlABUBLYQuiJGnH2JHMwuAtw9DCQMo8s6nyn2Wg9pfR0R/PNbYbD77DBS7oWnEhurARR
         kTk4NL2vzUPtlt/uzeVEJYDsgBZ6Vvs0OJcvh0OnohLwID9aO9kh1P098iz5h72HPlec
         MOOm2p6OTtuSLLI2jSlxUD8Ovf8EqQPPbVJTS4VbIiOPvk7necQoMj0S76y3QluZYjVQ
         8tJGsLfXLQqTBlzmxJQhgAyNjc32fAw468NIFWD9wLmNGY7LruNjOr/HVyV99u8p9rK3
         4ajQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=CtakO450;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811947; x=1719416747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=unwDX2wDjqDOEogdurxy90ZYsrwF1wF2kiv7RNCsL3g=;
        b=HsHm6v2OTTWEnMzJi6jKvoOAmLJWy3Emy6HfCSst4mesusSNOkhyZw6DTt1OWcE4uF
         VMz6wI3Q1Z87v1AoN8BNiuIDONW91zysp2wFLm3O2Ey2RZsP+z2unVA4ryhfKBfKHaZ1
         PRQTRqPHHzJgCCfxx/Mh5UC0rJ2n+7lEizMIcxEaLslClaz4k3xhoHUpH1pI4ewX/N/o
         cIETXeZlZQWXpQKiYgTgTCWGV/EpmzV8RbqRDEOREq5YOYn5AW/SMl05sKtjE+JGjexx
         B9cSwZ/g2FYXG6TM5IPGTGVvxDEs5aqHUSAlhJZ07fPZZucl+rMTCM/Vv3bph4DmrMCy
         njeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811947; x=1719416747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=unwDX2wDjqDOEogdurxy90ZYsrwF1wF2kiv7RNCsL3g=;
        b=R5z08+qSUPld5qklvmfNRmXB5w+0TY3pk6lw/ZwSmdGtWNMSENK4Rtcm1cSHvKNG+b
         tGC+rnOKOBeUUF/8S/iqykwYrr80r5shoyTS2e9PEKW2u8+ugAvONUPmaEyIKaEw/ajP
         9ZLp1KjxA0LCIkdAzln1CURmdCX3O7RsaEsq1ghOcRc/RtOq+7pSEUGq8nZxQzVY/SmC
         RPwcW6zm6bMjY98TDa3crVpynfa+z2iJN9BHesMepeyXdwqAEv+Y6GVcB69/3gLnbQ7d
         LILvuZryKwWndUBsoH6v2UtMD234P7BncZCNY9AW7eipcyCiNBc+7mVEiOJzmGDKQxn+
         Xh8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOWSgfB0AQjBwETTcpYvcXgHIyUkaXt9iMxmprw8X3CjOqIWfM9S+rGZ7TLBeCMTga+p9L0NuwoYnP5M8xBCRPKZ8/BaMX8A==
X-Gm-Message-State: AOJu0YwAG4n+FYlN0mAW7aesjOi5UxYInfHUCWJjTlE3TGNNFuA3u0W2
	hmQIpelNLeCFHugyArXDXqbn1og9KKgBUyFDyJ9GJqxeoBa718NN
X-Google-Smtp-Source: AGHT+IH2XUiZGE2xM/UYZJo8bprc33YSO85czkFMORxTpKG4Vp0qCoStDFtheqtOksEscZ9nDux8JA==
X-Received: by 2002:a05:6808:15a5:b0:3d2:1a92:8f4a with SMTP id 5614622812f47-3d51b9e2082mr3657951b6e.23.1718811947250;
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:27c3:b0:444:b12b:b736 with SMTP id
 d75a77b69052e-444b12bbd00ls4789021cf.1.-pod-prod-02-us; Wed, 19 Jun 2024
 08:45:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAKbEQ/FNtZlMg1sN6yE4BLU/81SXGmRgPKHn+LzXlgBBAHRolVL+aTbLabkmjLmsWn6iQg3PPt5pYAjMBZ0PCJjTxDFBjuB4Drw==
X-Received: by 2002:a05:622a:2c0d:b0:444:a849:6500 with SMTP id d75a77b69052e-444a8496652mr20684071cf.67.1718811946356;
        Wed, 19 Jun 2024 08:45:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811946; cv=none;
        d=google.com; s=arc-20160816;
        b=q5DIG7FWaI6b+jepUHE1dj/fym8nMirewhd6O+VV4JLmvV870HgBOiOQHyJs18c2Qv
         T44zcMC5agujAveUdRsWHN25iEv8lVr2DjerhE5hDRq+s9vbkMy5KGU5xdkwiq8MT+Yq
         4Kpu6mzuYvgz/duyd8an70GdBlCREPCCHXJVW/K60ujnQVHIy75m0tubZPiAKuxK80mc
         zeHIfACzMzweO04WAsljeY2HuD7L7rbWWIctyoloMNlQdZK4OkSnQmBkbSAnOMuCmBU8
         uGgSpZNNG0FRQM44TTGppuIlvsmb9jNFNcCLIc05URzWRvzxuo9Q4DAUX1cVuiWEYf7i
         sLKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A5/DP3QFUFkYA2+5kJImY20b3CDMSHPGwimqBdu525I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=r+EQkVC2baCa35GoK4BCGlJYQwmT5FXcYrTvW8VaxYxtVEWu7jIGs0w28TPvqBc5VL
         6NWWok/YKotCb0laeJxK05U2hZxIkCYfHT7pg6B/BHgDeYcc3GURCvi4THX4GLKarVQh
         1+14el9Pus75VOjaVHsPe6qBZq2/z2TG+8KpO/V26KfRtV7FaGq7shWY2URYxr3aFfhZ
         96kmn/Gd29EObXsvMPltcMmtA9yNKAZWB/UqKDN5+pnlwtN+qtyT+42/lfdHIFtKp0sQ
         z2frwp7MhB1ULeNTsfiDHuh3ugSCSHXoj5cj148RYGWxo17JVcA/3smD+NDjCbvstbo5
         Yr/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=CtakO450;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444a8830387si957121cf.3.2024.06.19.08.45.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JBQxnG000599;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tc4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjKNI028655;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tc1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JE5DL3011442;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtma-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:40 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjYq752101422
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:37 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DEF4320049;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 90E2D2004F;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
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
Subject: [PATCH v5 03/37] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Wed, 19 Jun 2024 17:43:38 +0200
Message-ID: <20240619154530.163232-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: U2iqZBrWGML5qKAAmgUyvul0yztgMxYE
X-Proofpoint-ORIG-GUID: 9tolQzDfTmptut_LScM49Q1sPF4ZToeh
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 malwarescore=0 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0
 phishscore=0 spamscore=0 priorityscore=1501 lowpriorityscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=CtakO450;       spf=pass (google.com:
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index b4cb45255a54..9791fce5d0a7 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -946,6 +946,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-4-iii%40linux.ibm.com.
