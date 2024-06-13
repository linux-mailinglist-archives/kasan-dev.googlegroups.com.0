Return-Path: <kasan-dev+bncBCM3H26GVIOBBR5FVSZQMGQEWWPCG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5970A9076DC
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:53 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7024261bb31sf975728b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293192; cv=pass;
        d=google.com; s=arc-20160816;
        b=X5Hz8Pal4GxVykp9ZqFfPGK4Y8PbioY4bII06IYDQV1Xnscm5SxZaj9lWZ/1DRllzH
         A5JVKcZaw2jMbhEc7/6WWB5zIFM2VKyXRlPrcazyZQhIfHVXyqVMafDT7ErcZHLrhHuK
         2Yr4ddItexewLcwGG0JPqeJn75XAFR1Im1Ns1qJk/E8nezFFGvlnylFvAAGHt6ROqWTl
         0c7UzSQvL7+AlX4VlgbCrskY46QTxvHE1oc9s7A3tDiaDwF4DCEhWrxaBaq24ntUHIwP
         hfow1W0EsfxabNlbb1wspG3X4297CaOmsjUC6UecxOKDPPsbqoA8RDG5ilhDi5kNOs5l
         fp5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BC5wcnq86vg3lKXPuP1km0VyQF81huzO+pBhkrvH0e8=;
        fh=vIqlATW7VaKoBkkcQso6mcFnuffF2UpqPATdV65oF2M=;
        b=gDwp3AUk3+YsJTt8gKMutgn8nzxqM5UW53NfhppF7FUfWFWrjAu62gCs7vrXaJJRBE
         EE3jVDg0hAN5d72M7va17jeeG0nita2lKxwdH5jk/4l+W2ciLYvz1Je42Gb/f1sDBCpC
         iPIcYfS6bHj57rBWMPpAAktwj5zwzKAlycsQ8gR7DFaKMJXyo7ROu50X7B1COZcHu9sP
         tWhEGYrTNVzM2vbmp5F8Y+L7rHNrtGGJ31Vk4cxu9wuxiHwm636xVeQyH453yvf0WArW
         3ooJ+vyKcImsHfMRlYmJ0bI1tgPq2uTwej5QaLeePDGfPNoALtCfxmU5gcr/JPiv82wc
         +pFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=troVXxaN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293192; x=1718897992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BC5wcnq86vg3lKXPuP1km0VyQF81huzO+pBhkrvH0e8=;
        b=FHRS4voMQLxNwzsq9C4ygH6OAE2Tz+CtZ0GiPqltkcUhKg08ILAFLHVuIqVsDZK0DT
         MoUtGvjufK3HhyLIBekC7tcUh32ONR6uliquMRCBzp47NmgsSJGvsoX/kqwzihY5Ol6+
         8WILt3qBwk9rRD5TYLpqKaAvMFFndlTrWFb3Jo8g7osAaVwPPt7Q+E1FJwFRT3AwjDOA
         /gxX7KZ95C3IFtgoABG/zhcuPMvsdV+G+kmCJAMKi4mOsdEnS1xmafZaePhl140SV5R2
         5TdFgVP1oz6bifqQfOa+9B20br58bnduA96t3dQRVWhSCu3XSYqzR8RS7SfyBgY6a9Xx
         WLdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293192; x=1718897992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BC5wcnq86vg3lKXPuP1km0VyQF81huzO+pBhkrvH0e8=;
        b=W9VHUtI/RSZPzOxRABywazWNGSnlo+C5HBIaZLQTpIKDecEtIsd9MtL9loM3oksMkQ
         c72RIgXprVl8Wd+XqXvrA55vrf/lfe2cqF4IZKQFCEgZoV3ZJgQchBBJeE+OkqEejlue
         wkfArgqPknxV7Ah+IIKuvlre/n/FwKTlFfrWP7kCwB34f0FzBogiebAynGQJCNXAa0NK
         b0IIifdP4XLgETg0RG32gYAqnVEeDeZBpmkMriCCTLDTvWu/PfO/vEBKqWXZa/oZxcJR
         zalFdJhKPC5/9eL5ycPhgy8mHbSiOO4eUW1S4In7pXaY6wMuAXOvw/dPE8cJsknkRd4M
         y15Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwJj9rCNtJo78HWFQqxrtDr+YQMk3K3DqEkw4arZ5Mb678zzIbajr1ZookQzdRcJOCblWjmEzxhzbQfrbRrXEOQKmPASW0YA==
X-Gm-Message-State: AOJu0Yxh7/+fR0iQvIs08yqTdaTubqd+dtH1vvYtW6nozFqm/HvPv47N
	ShuhS30CritGixWCcQvcmbPlm1G5wGMJZ4tzZPmtRVQjm3PRMnYg
X-Google-Smtp-Source: AGHT+IEY858PHH3NfdkwikLlsxJshJKFZh0pZWfTmgslWz1BwB8b0zANjFUc1RWb8maKPajYX7by3w==
X-Received: by 2002:a05:6a00:1989:b0:705:b6d3:4f15 with SMTP id d2e1a72fcca58-705bcec5557mr5511851b3a.25.1718293191807;
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1795:b0:705:b591:29f0 with SMTP id
 d2e1a72fcca58-705c9457069ls768827b3a.1.-pod-prod-06-us; Thu, 13 Jun 2024
 08:39:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnl2Xv+QceeMCKTG8RTPm9TlO7SlZlVA1UKE0Sg1W6/AlPpowLVL1rxaN3BPzknl0errsorQwQAZpGepOz9+dQalbMSh3E/YVQsA==
X-Received: by 2002:a62:b50c:0:b0:704:24fb:11c6 with SMTP id d2e1a72fcca58-705d715b493mr13541b3a.12.1718293190497;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=Ut31kswBnenB0fsHuLOyK6XddisBjqMSvaEwesCmHszf1wkaxiHwX5587V6QsI+GOk
         XxQ1Yu/w7zWxlnUFEOu3PlTHJxaHpjhSrCZIvsOPiqiAaAPmPWOGC4Rv9lodPPLO837P
         1gmhKNILTjM+2sxEEClSWv+ZORLn+0rDmryQP7OZvtPOd25Mq9zUOwpAS7vs3W8yyNZU
         JmsdIRcBWE7XIU9vNR8qDD50LmIrlqlWjbwQql5DXRxiJECNeSnMqGXR5jb2vfonxrOq
         Oy7/vSQwxXHUO4u6oJgr7dxsGkm8v2pvuza18caVENSB5QaHofM+RxAL6DimumcZ6Iz2
         DkWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ah4xfVCHNViASZu9OS8C5bCxAH6NMTO/t1qMSUm0DA8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zzr0Y278RPByhffaih3oXIMuKGepR+3r4EnZftjHf62Jp4FysXXr77oPnj6qQISPGC
         56F5ECJsfDJpD399/04pqlQ7wa1l67y2pZGydt3LeTiFKzYfNnp+D/YBvKhfDD51md7W
         3VRXyWq5f31+wpRJqFcD3PzyRIe1jcrlCk4S4XYybG2EoBd3IdcUrT4OeO6pryhK5P21
         9rFSErEaxeegbD2GCDDGIK4Me+o4oyXdjEwuxnD6sbRnzvEYw5bKPI5A5hEW3n6r9mFv
         n3jQe4mScNbmWiJBvD2CdNpCSEcfOOTvYM8BTswptBxK2SUIrAhR9iUPpDZmrKzpnKlH
         ZXxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=troVXxaN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fed4d08039si84984a12.0.2024.06.13.08.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFRoY1006807;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext11u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFaxqb025357;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext11k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAZNk008701;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk0r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:43 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdc7915794538
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6548120063;
	Thu, 13 Jun 2024 15:39:38 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E59CB2004E;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
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
Subject: [PATCH v4 10/35] kmsan: Export panic_on_kmsan
Date: Thu, 13 Jun 2024 17:34:12 +0200
Message-ID: <20240613153924.961511-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 8H9Swu2UbKpTOjizZoXfoiXZhZd_152j
X-Proofpoint-ORIG-GUID: 3KQYIeFe4kOCnIUd0Jz6JFn5smodzH8f
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 adultscore=0 suspectscore=0 lowpriorityscore=0
 clxscore=1015 phishscore=0 spamscore=0 mlxscore=0 bulkscore=0
 malwarescore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=troVXxaN;       spf=pass (google.com:
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-11-iii%40linux.ibm.com.
