Return-Path: <kasan-dev+bncBCM3H26GVIOBB3OT6SVAMGQEASS7EOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4E57F38DE
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:06:38 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-421a7c49567sf33361cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:06:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604397; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjlvDb3cN2Ede109mYjyVUNMu8PXUlCXP5flLXVATFga1KzsKttfnx97ehio2Z4OFv
         pgD/h779aWqybodMHiPUDb700s2aRmFAL48Vz6M8jY8m5OHe3a7Gp7HWWpE6ZXnMzZo6
         Lnrm77aRBgURc1knxokrNZoSUeznrZVY3h7sEVH6SRFxfJk9QihX1gpMtNbAaMbO/64e
         insM+x/RxnOmFf/XA4gOpK9Q1EuDLdKuw+60QTvHdUlHYSFutEmIIBRXKPhfk3tBnwD+
         B8ccy01RtG9L5o5/HoXUYIfodWjELmmNhACs2wa0Oii3Fs8xsEL4cmByitJpqxxSqgTC
         w3JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DIJ9RUiufxQD93MB3bd19RYqr7cAnOqQsXHYj2ESy7k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=UEP1C1KMhlNypZX9ww2iec1+XMKyPs3MAD0C81ZQ//5BeNzKyTMqyH8H2E1aU3Leom
         Ylmb4qdxgfPorI+fo7fMV8L74Y7l9DT8gZO2GYQrGdB+6o+/L08JeXr7z3OPMF6dyUWn
         dCul3penIRsdHuk02ZsbIizKC1cWlMd15/NJT4I5p8JsDAVRDrrCQ3b19P6RJorIIHzj
         P2PMZyWZKQWEJgqE7L9xhSc2Udz4gokthODtq7xdwXJ3pTI2jTVePJZdsqHvLtNFHB4G
         /9PC+IhWUfSDYmRJYGrOM3aTSDZd92YhBchtEqjjt99x2O5vFnp8f0mZBKnEuws/TZzK
         nYYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AT+iRf0E;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604397; x=1701209197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DIJ9RUiufxQD93MB3bd19RYqr7cAnOqQsXHYj2ESy7k=;
        b=H7rMrpNC+jiYPvpGlmQpXg24TUMUMp37nuDtHMtH2DR75BVmbi66sgNNMQ41lPZVY5
         +eh/f5AgaQllaU52mNlNs379mDbWQCvg7fi78B1EChLnM66RkoC1ufIvHyRkR5pKTK2R
         b9K1OjkZOVgz/2LmBO6Yzn5+/UhIG+nfhyp5O6h+hL2J4/Z7dDKwiJF5x6otV6t9ugky
         RIMLxgq+v33nkAkz+0+DwOa9/+LNA8Swya6PwcwvTdC1/DbzvcbMNkbYhlhcNjHyiHbZ
         TDJjYAcjz6Wzj7/6zH8ADYXu6rnQhGVb9DjaaIQFBIqQOwcvFjVSq9q1FgiGFzEumeyi
         NdLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604397; x=1701209197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DIJ9RUiufxQD93MB3bd19RYqr7cAnOqQsXHYj2ESy7k=;
        b=mQzL7lZufDZY4YNQXt/bpuqJdhQcgH8tKjaSlBSLYt/6Qc4fo9XrCdQW5fyG7pIGxH
         w5bDjy1+qOOfZ6BG/Iipp6AjR1q6lmpQFdtxrmwfz7RyinmVygv2ktkqsIW4Xm7fFcBK
         KYcQ/f2gjGLaa6U8RyMqPiXqhe5scLwLC1ueHgAcPEn04SMuDCuh4WkKPlRpPUhDhqQb
         9XlfoS4vKAt+4QeCLEH9iX6+1fvHTUfat0xyMaIOjudJ0YjodOyAlqaKjEY/2cMfE/sR
         13DqeWNcdq5SCxsGswCrMt0djBvnSMkySmzKkMB+R9z9oYO1UmqKlufbegCeDUX57jcj
         BuTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzJ443SmLk7bClJHniDpNaVmroES5IAPO9IEm8tNlXRUQ3KwPII
	Hpu1ih7FopBJfb2KVAhKBa4=
X-Google-Smtp-Source: AGHT+IGbePcd2KRXUUJWEaEHVxNATaJ+BjB+8Y8QNgYH01BLdpqFy/Gp/Sd1WrodubhDSyZrU0P6Ew==
X-Received: by 2002:ac8:4e56:0:b0:41c:e10b:a3ff with SMTP id e22-20020ac84e56000000b0041ce10ba3ffmr21195qtw.3.1700604397420;
        Tue, 21 Nov 2023 14:06:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:eed4:0:b0:66d:9d16:5a4c with SMTP id h20-20020a0ceed4000000b0066d9d165a4cls615413qvs.1.-pod-prod-03-us;
 Tue, 21 Nov 2023 14:06:36 -0800 (PST)
X-Received: by 2002:a05:620a:1995:b0:770:f3ed:bbc8 with SMTP id bm21-20020a05620a199500b00770f3edbbc8mr360238qkb.65.1700604396674;
        Tue, 21 Nov 2023 14:06:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604396; cv=none;
        d=google.com; s=arc-20160816;
        b=bJfK/L0LE5xTvFytAXjowX0OOa8/Om8n8U8R5blzavmpGb9gYFwXUnyHGy+83fOMlz
         jf6YjaVhcahBCSJh+rhfOG354TGOSk5wiN2LXNpCL0Tp4PBzMsDMunGOh44zpJ64IuKa
         NRrzTw46JMW/HMSSBfpt7XCNjEM38fvqPZ19Hv/AGjaCnnc36KnAt/bc6TSYLdSTiXyV
         XUYS0eB4FBg+xMnhXbxJTI/blJjjS+F9RbZMgtTC2O/TZrt3Pgp18lqDE4wwj3+eShQ0
         5oRoiDT3IQgg/sBhrrSHbGalAbTQ9DuN4JXO/tsPd7AKgrKMXOFvgVb9DicxYx/2MLND
         NgHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5NSwnOlXGjBF5jkByPXzrZliIsEVpLRGGgaxRVBZlxc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zY20Hprq/VrLZOEfsMA7hle2EMWqbKh8AqXE+bjolj4LsXOwk6Y0TKG7/gtXJZoPyU
         sHueEfVL6FSqTFuK7TY76CQ9SIKFGVE4Fhp43EZD2X68/P7jOPjPH0xxg40SgmvaheTt
         V4NYLWRJJn6yhyY+D4MsGNQnoPpeuGUbzQKIF6wMF8r3QV/IFhfyvi92O9Rf062ZVvp6
         yItl6N17vaGCtl+uORmFfmM7ojGKvb1WirpVRQ7pp6ptB6nShmwDqMWz06/1RN2O1BFY
         7xXuL+tFylN4dyc5GW18jkPO9FYHrU7I07kIlWmnGtkn41muLfXeGU3DNxUNeD2P6ALL
         djEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=AT+iRf0E;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id rj10-20020a05620a8fca00b0076821b38450si723203qkn.2.2023.11.21.14.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:06:36 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLqfCQ007953;
	Tue, 21 Nov 2023 22:06:33 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4um08k1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:32 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM6V5t010663;
	Tue, 21 Nov 2023 22:06:31 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4um0808-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:31 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnXxc011060;
	Tue, 21 Nov 2023 22:02:17 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf9tkbbfx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:17 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2Egm45089276
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:14 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7B1DB20065;
	Tue, 21 Nov 2023 22:02:14 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 04FCD20063;
	Tue, 21 Nov 2023 22:02:13 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:12 +0000 (GMT)
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
Subject: [PATCH v2 06/33] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Tue, 21 Nov 2023 23:01:00 +0100
Message-ID: <20231121220155.1217090-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: SoU0RJ6tBdwvO_1Y7haVWEfjyPSE7XyE
X-Proofpoint-ORIG-GUID: fzYvMn95qhzPNBXYSvhJrEwMaHFITUBv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 mlxlogscore=767 phishscore=0 clxscore=1015
 lowpriorityscore=0 mlxscore=0 adultscore=0 bulkscore=0 suspectscore=0
 spamscore=0 impostorscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=AT+iRf0E;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Assume that we are handling user memory access in
this case.

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692..eafc45f937eb 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-7-iii%40linux.ibm.com.
