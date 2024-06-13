Return-Path: <kasan-dev+bncBCM3H26GVIOBBSFFVSZQMGQEF3GESHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 133A89076DF
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:54 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-37597adfab4sf10431655ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293192; cv=pass;
        d=google.com; s=arc-20160816;
        b=LN751XT+jC4ZdTul+6esvkjQUomLHg38SyD7rtZh6TI+cpMSuM8BWcztB33MHGsVyF
         +CUVgLpuOzZ0f0f1RjqYNFcj8aMPkPJ1+o+jzTJXwCQR7iF5kLa7vqeq6SFx4IVFEVtJ
         z2+46mt7Knj90uokPi9nLa7nO/001f+QWhwIgbH/PDauW9T0fLj/Ax32DZWe0gZREweW
         +PA3jDvMvKL+6HrJJgv0/6G+NHFLOrqX8WfIFo6oidQJXa0+nkg8YN0A3AkA6YC255eb
         D/E0b6hIsNsib/95s4tC5vyIFRmqFMYcxYPjjJ2w2HIwqpnsYoiEHic3ebSZntl+qaFx
         PilA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j+rL2/6cdW+BkNzPO2Dz7j2I7n8IH8l3J1MlyODdrBQ=;
        fh=vjAGUqyu+sFH8WiKo9kfGf8D5G9iO86LvN07zy/pX5g=;
        b=RmA0f8/QR6tmCuyL9M+pP61Ey9HnHT9AeIu+XI2V4SbuK9QZU2ss/mlJPyWPhPoB5t
         PioEwFNJ3NmBM9RDqSmDamxpww5bKt77LX8WNJDA6rZ339M3Kwe3hD78nOIbJHrqs1hO
         aRWNMD2PQl7k3IHZMvMiA/l1rlLnl3FKlSj1bj9ie1BeiPuRfm5rsZE1GiEq+zF/QZtk
         VHGri6THLAHyU4fn2D24iAKAdxMjlydqSiJXLRnPZWpinImRiog4JHxettULD3ZUYinB
         nwLUzC6z/gjpoBFSxqnLP/Ov862aGItivwqNHmlS9urtq8diDO/aXA9gud8gZfA3qgyF
         ilWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iLauG0BU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293192; x=1718897992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j+rL2/6cdW+BkNzPO2Dz7j2I7n8IH8l3J1MlyODdrBQ=;
        b=JtZTl1n7cvavy41B3GSBQovsAQUDDJgygPjyW8rZFPKRc1xmXiikXR6QbI+ga46qBO
         OdxvijFv8ih9kR+GALaDMvQzVAyof1CP7lvpISjvij0Lio3ezy7epaF+PVK/KKHnEugA
         wj4CButT+2VnbhpdEhGO3ySnBERrnNAhiT9rxqks4VR7oCZCVtdMOUrnonMxKfzoDwrd
         r5mUIAAsYkGdt1fATCsS1bdsQdO7R+Enx/D75OQkkCmxRpJQT+7318URbuOeGJmwRRmc
         mZRyuYws7clsLfrcDjexKj4pqeOyl0s+SH4PqDxxokYKToAfTcnFb/J+ondV5MCA18xs
         yLIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293192; x=1718897992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j+rL2/6cdW+BkNzPO2Dz7j2I7n8IH8l3J1MlyODdrBQ=;
        b=YTq9vviYAtu67EdtkrDG8WGibhKCiGGQ9kGdeRRvzm9jYyf7qWbuez52qYrTOS7PBu
         mL0c3hV9Y1ee7q5Mpzbc9Hb9IxjrEmFOb1HiXSdheqEVVK2XxpbwCTPogeg3ac+SZSSr
         GIy3KifHJ06pNcldf1D4G6XXYeaO/IsrjdMCIL7N9Q6vqgyuKBorlcDjyayUpSdkVGk/
         J4grHa6A0/YW1lB2CAGOSgxCAJx8YJ3H/wgvN8v41UriIU7S7lpzHtA/CWi0YgwH2lrD
         xNBNqTavbpai2VTlpmAW66MK/MjwabvziPzASVKy0hqc/SeSXF1DtHCsf0Xcll9IZRai
         TeHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW766V5Kc6I9+N9SFAwW0eK+ZLEkl7dslOC6MLe2sU9s8DF/QfqtoZbEpk3qky+KdubtvWGjcF5s97TMKVsEpq+joTx5OOMbw==
X-Gm-Message-State: AOJu0YyfJlbVKYdby7HbwdUd9Y/7oT8yndE6nalFvPmUer0Dk/v4vmFm
	LZbgd9kt1TRfgAgJccH941ovLOAYwdummZLJK77QFS6hlICh5iZO
X-Google-Smtp-Source: AGHT+IGkECyMDydF9KAkPfHQhPhKuiNUb9pUmFCIbFBZBFpSWgs1jHNYr8y5gnljyBAWEC7HgPYFfQ==
X-Received: by 2002:a05:6e02:1fc3:b0:374:64df:6805 with SMTP id e9e14a558f8ab-375cd1bc886mr63900745ab.26.1718293192586;
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:375:8a14:107f with SMTP id
 e9e14a558f8ab-375d5688005ls9352575ab.1.-pod-prod-08-us; Thu, 13 Jun 2024
 08:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0w9ZrjoMRkiZTn7C+R09f9B67E3rreZeTWKS+cJ8GCCcUIA+/ff4c3VxVOdRG+Hg7iPhRMkDtiRKkLvYZC78I+IdWClispPyThw==
X-Received: by 2002:a05:6602:3428:b0:7eb:7bc9:7fcb with SMTP id ca18e2360f4ac-7ebcd0a48cbmr751092739f.3.1718293191807;
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293191; cv=none;
        d=google.com; s=arc-20160816;
        b=gUMzguDc6lMrEXYQ30mY3/6zS6svypDYOxxM/I8gn+F5KWMIwhQ43CN3nSoCVJm5xx
         xG8ZjdkcbICDQQKgyIHdAjg3LfnC7bwwYubXyyEPlO0U4G9bqq1F5+GTTcr7aXs6oN//
         YSnq6mR31BtJZ1adrcI0guABU62LgQ+FQ3ssvHfZcQ3kqtvVfZ9/T0Ve4zVNjqT4+Fi4
         PK2EtjE1g9PeX2+tYJu4Jq/5u9pME+rAEg80TC1UN82r575mdsErUZMPYZNgwgJpYm2Y
         4QMF8cvObBaZT19lPt0Bo/DDupKOqLr2+VqLCiYGkj1NkM/2K1ZQ90ka/kd/0+W6KIyx
         nz5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tBymUKmYGVkfKp+NYWRuNAVgpQDLNZiEwntKKs+J4wk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=PBfYSXwAcodDTBBFPSO8PjBEIJgLqyU1OAzS+ANxVNwNrgmrDyuTVsUWp9IkaVAoVm
         PQFB0+TDTPzeezqgIgqC2M3WopXr3+BECGlmHQaOmvdAFFrk3e8jT7eWbghysu8F1fOW
         cxqP1gB2Wfs55uAUqvM60BLfLmopNP0KibH0JqGFvpNTqDNnxsTvo+SDn7mCNr7yKVU6
         RGXjFy6I2DqLTx9sWSqnO5jDMGRKqgPjBw6NXg0Litmv+wbue0hTedPgCYF8iplDuqqh
         bWk4IqZooFnkMu3SVCnnvJvW5OzRrPDwcV/4sLK5u6mlHo5/rVAe6ZQmPmmsXP6XBnsr
         0exg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iLauG0BU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9571feb12si82790173.5.2024.06.13.08.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEPwf0006202;
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdlod023951;
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DE8bfb023566;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn3un0qgc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdeue17826126
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 931992004D;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2097820043;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
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
Subject: [PATCH v4 14/35] kmsan: Do not round up pg_data_t size
Date: Thu, 13 Jun 2024 17:34:16 +0200
Message-ID: <20240613153924.961511-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 07ZKKkdK6o7tKTl5G9IR_pDdctzTxY50
X-Proofpoint-ORIG-GUID: vPXYqilIID-TtrsSk_2C-JQrK4-P1oKn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 bulkscore=0 impostorscore=0
 mlxlogscore=951 priorityscore=1501 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iLauG0BU;       spf=pass (google.com:
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

x86's alloc_node_data() rounds up node data size to PAGE_SIZE. It's not
explained why it's needed, but it's most likely for performance
reasons, since the padding bytes are not used anywhere. Some other
architectures do it as well, e.g., mips rounds it up to the cache line
size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures. This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 3ac3b8921d36..9de76ac7062c 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-15-iii%40linux.ibm.com.
