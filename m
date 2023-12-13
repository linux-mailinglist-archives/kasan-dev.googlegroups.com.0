Return-Path: <kasan-dev+bncBCM3H26GVIOBBF4A5GVQMGQEQBWB57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EF4A812300
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:56 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id 71dfb90a1353d-4b309d9aad0sf1953429e0c.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510615; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fp1OLy5F+RGnUArdqGEpsFoe0K2iGwJ9kVkDnYFelIUybruQUTA8kmk6yXqJJuJBFN
         swY4MzeZKXqjzpJErakf00NMa0fMS6q9UbIbXUKf9J597+OHnuzLxOww9XLPVtWFkJIS
         cDgHV4DX+vUmJPlZo+syvDfQD40g5xqNlwT3U17L+cBCfqRKPwi++N5Nf9hvjYCSmSYo
         pHWiL3W3nWPErvIjw/rgPmlMStBygct5poSlPZClpev5iF7uQXXbnzwzsX1NwDeLdQah
         gZVOmw+MJwvYo+zAaTP90X0l+9roP2O+b9tlUKLGoVQQ54CrFqIGWxJvGcO5W8GAK+rr
         XiMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=inuHR5X7SBJlnLt2OGXD+i+4eMd07RNxQ46Fk7YUvEM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=PxHdOrmGYrlriZNA7g7LXwCwtH0x6UsO6Z+D+YUWo6yCHUNOuYw5PZXpGDzNehadbu
         Nx2lNQIFma8AFZYJXtOHTgAW4+xZwxGPdDXiiikyuNGStxOEg3fLwUkzVxrAuqmqkc8n
         +SxpaDAgxuRrITBsfgoRPafmYiMLBiDr/gv/w1LdSuSKQzWi+feiOcyxI555Z8PyA6se
         gN7o/Nzp+KVTi2Kqz7eezfNk79sigoK/hzWo+imn+2Pd+QLJWBEE5hZ7/N0lrdj/IgZR
         WMQeQVRK83Oi0DbXmlayteNbL5o+IvTwniNZXhP9VKfKjBlMOoHPPSTW2dVRInJLGGt/
         3SPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FfpgmgNX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510615; x=1703115415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=inuHR5X7SBJlnLt2OGXD+i+4eMd07RNxQ46Fk7YUvEM=;
        b=BDTNrEvyPTCDS9npSF1e5wyYYPtWDKc1Jdk1jSF1bRE5nDyErcsxtuUco7fkLgD+P2
         faLqulBJH8zXMyl7TcgNR43n0667A9wgMhYMLfyyhV6Lq4+jHk56gVEU4NbdG+/pzYMR
         KM3ayAxhC/XxlgvzVMa/9zfL8+tvtlp5Gs+m8IJPq+mQbgDEZSDcEKgvoWq47lBjR8oC
         ghiMNbE1pXPPzQouFE4H1dznlc8/HFh8XcHgTNXoKpwP4I1IV/jLaBnZEqC8BpT1FS1M
         FcLaM5ZXMvSoQHRx2ZwcWfLwMhkJCiVg168XJQdBaWjL3OgsmaUu5DHqDxLgu8sj5It6
         JYjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510615; x=1703115415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=inuHR5X7SBJlnLt2OGXD+i+4eMd07RNxQ46Fk7YUvEM=;
        b=oyB4o7bcfvMrtYuNs+GQ+yyV/xySxkdS8AJBkvNQKR1/nkCgBMRsbwwN9sTMSdL7WW
         97+GjxU/HMC82yTt+grzipA7Xkvk6n4OOr3Rm6H5K0VheBuNhRqZM4dZYeYgpu/nXXEC
         C1NUtcxOwDWJ4af3/BwxRPH6NJaOUsiAcWgWRw0GPNKy07HQ+SGqfaELDFsccJSt6J1q
         F5lvrt4WC9g9uudBRO+qYdLrh7ImNc+NmxtP3O57LK4UhH2IpxwLCucoJaimhnnkoZys
         SKtZCNNp/MVsCKY2U+5DSfYO9Fd2TfsP/hbcDuTLIho1zTVDJ/++KgIRbxjhX1qvm5qW
         9gJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyJhda57+tQs8+0CqHJrx8sADTYaNDtqGsHRm69EvFy+lFTB2F+
	ATwOj0My06JyaEvZ9a0gSM4=
X-Google-Smtp-Source: AGHT+IGwmBY4AfvLbrF0AFcwVPwLEmgRxOzBcWNKSvU7RBMxgYsOsh6b48XAtsOcrOBe4Bqof932gQ==
X-Received: by 2002:a05:6122:4d8d:b0:4b2:c554:eeff with SMTP id fj13-20020a0561224d8d00b004b2c554eeffmr6894457vkb.17.1702510615234;
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee26:0:b0:67a:b34a:6626 with SMTP id l6-20020a0cee26000000b0067ab34a6626ls2358780qvs.0.-pod-prod-05-us;
 Wed, 13 Dec 2023 15:36:54 -0800 (PST)
X-Received: by 2002:a05:6102:475c:b0:465:db7a:c628 with SMTP id ej28-20020a056102475c00b00465db7ac628mr3962995vsb.23.1702510614488;
        Wed, 13 Dec 2023 15:36:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510614; cv=none;
        d=google.com; s=arc-20160816;
        b=p+tTPaPTOMBvEyho2pXu2GDy6loFCUQ656ElSip4t/WCF2C2Z9nHPDO5fqk0JCITqD
         yfFMMrw/K/YeIGmABZiUW/TOmCZZirIbSHaHXXeHGm44SOQZMCVTzsxZ9I+xb5n5w2DP
         ECKK3M7v35+YTUmS0eockkk7Qvla8IYPo5h2L7rLUxepLsoXZnL1sxVSEmQLoC0GLBiB
         8+L5XmkWi9H03vAUuuDU4SgJAVQD3T1KfAlU7Ik2X2oEh9yyaAijGDppes4WutBD6Lci
         eCQ0SFOQrUTtozSM75FVwFPcTBeQahw/MQy1a/5APuhtUwL3Jk8ryVa1+RwiBNAlHBxd
         jIYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UxznJChHj/qk4O/4D3mha/igyOisfZ8+E1sbSyzHNyg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=LbfivH7311lDMbHNmkRgJD/hTXE8fmjJhGVPoumWRp5miSx2rA32GZHz+1Pxwfuf4B
         sFV08+RMQ1TXlGEVd7Aeb1f62pa4MatB/EuwVrUtTJtyKrlqwZcfldXLoIGEDIpG1urv
         5dHZRAVOJO/e+TFS+7ErVg+KfCKUvgYadFPFGQf54sDQgmbBejIPKTWktl7RYGlyQ4ty
         W0Q/ECj1LZH3n/+9MiarWrfsGf3a4gpITF7VWv4t6oYOxklIUTgZ8IGqy7Ez1sAwTiJg
         OISc8jVzjN8jlfd32mJypWRYMVMOvqmEajth9NSzLxz8Qo+zylAWMfxxPgovLTe0UfHG
         qYTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FfpgmgNX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id j27-20020a0561023e1b00b00466025e2258si3197117vsv.2.2023.12.13.15.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:54 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMN7xQ008801;
	Wed, 13 Dec 2023 23:36:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1cxy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:51 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDMmcZx011171;
	Wed, 13 Dec 2023 23:36:50 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1crw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:49 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMntFL014808;
	Wed, 13 Dec 2023 23:36:16 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1x3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:16 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaDQM8192580
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:13 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 273E120043;
	Wed, 13 Dec 2023 23:36:13 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B61F820040;
	Wed, 13 Dec 2023 23:36:11 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:11 +0000 (GMT)
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
Subject: [PATCH v3 02/34] kmsan: Make the tests compatible with kmsan.panic=1
Date: Thu, 14 Dec 2023 00:24:22 +0100
Message-ID: <20231213233605.661251-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VCykK3Okb8hn_WnDc5FlYpZFRwxwi3I7
X-Proofpoint-ORIG-GUID: 7xvJa3gpgWWQD7mxJFyGQAeo7HxdwKpE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 clxscore=1015 bulkscore=0 mlxscore=0 spamscore=0
 suspectscore=0 impostorscore=0 mlxlogscore=999 phishscore=0
 lowpriorityscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=FfpgmgNX;       spf=pass (google.com:
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan_test.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..9bfd11674fe3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -659,9 +659,13 @@ static void test_exit(struct kunit *test)
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -669,6 +673,7 @@ static void kmsan_suite_exit(struct kunit_suite *suite)
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-3-iii%40linux.ibm.com.
