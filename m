Return-Path: <kasan-dev+bncBCT4XGV33UIBBUHD7WZQMGQEA6QCPFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id E370A91CA89
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:41 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-375da994725sf14612605ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628240; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxtyG3SABJZ5F2o4qDuaCUL7KuY2SJyui1VxCatCCdD87Qwf1JxGDU7amsjbRXaNJH
         p/sa2DFNe5+Hwwmi1+1vuEyKDYEcWyAlFBubALBA8FGdL1XXnJsjyWe1ah3PU6TIa0r1
         7Kk86/PJJD03jPVCb2gDrdEvki1rTIRMd2NjuwwWhoDg2MjsCIW3/sUQDQET1dS7ubLr
         V5O6w5XEcDz9gGjXRWZbb1BGzC+VExLm7+ahs9kqGKywDEAWJj7BFRG+ik30xpzq3uQY
         BZWnmj0g4pqXNngXc/tK9NZP0aP5W359i7asjAtQq/nJphM/sixf55aLMDTcvUh8Ak+h
         cWpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=HQeBbi7t+EQNTu6HGvZROqnNZY3OvBTqBjHrNlcpGDo=;
        fh=RYnnfhal1T7hQICl9LOxXiBV9RcjGIJM42PugndZvOg=;
        b=iQ2KnlO1uiz8UGFW7NQUOxqf/Tg5m+oMxQuGfHopKnrGZuBxBW0nr511EdwvOcfoGI
         DNZzpJ19ybwSH1xPaNZNiBhdWGtEzlC2A4zsNVLP8mS9vOACoXZ50hN+iblgraY5WA8u
         VSonYYQDnT0mHCrbOhn4b7TZRwc5xzJi80Hd/SiUqjXCm4qNFm/xf0nwpOf0N7SnmwgW
         fDEt/YM13KEUi+suBjr7DMiN477LuIrOJZhBblsGUPBQh9JhYrUXo/aojWon9kd2xY2q
         x6jXt6Cfa7JG7ZuXW19ng6McHdcAjebyPqHa5wWNjYHgwIj0nninWfvJ2M7mXbrnbNEC
         nJpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=mGNKBgrj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628240; x=1720233040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HQeBbi7t+EQNTu6HGvZROqnNZY3OvBTqBjHrNlcpGDo=;
        b=YCm+4JBAb0hU+flLnSuJfWnwnF7sR/n6nq7QqD1SA1pgz3xKOpGOyocN2It+HgT2Cc
         E7IkMVs/wweWBn21TNy21Vsl37F/VXLj5a11TDObTkom1WNBgHy/Xi8f2AVDkYBK1Jak
         PJ3Ggs/xB7ZTSgJpRCX+WQqLlCSVKPEod4mqtvvu5hvM938YpT7aIx2Agt2kCuL6BcoA
         I5stGOdvn0aXOYR2tJd7QzeVmkig0oNOZleJm40S9d9uG0DNUX1iDRtx6RCqj3LA3BsG
         T4ToQiu2cYVvwZ3xJsrPVsOpTyrnXpF045FE+DBopriyY2S6J4rnLynSS4S5pMdsPsQa
         0EpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628240; x=1720233040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HQeBbi7t+EQNTu6HGvZROqnNZY3OvBTqBjHrNlcpGDo=;
        b=CuHtmrmE1M9qFjk5PLCSqAmBLg2LkDiK5WYXGHp9D2622n5Ey+RtJiL6H47PAV4nFH
         saZww9EhZ5HFQtCt0bXna0nmtZ44gGEkVjPmYx/eFehMk36p2xt9BpW9Nq3xei1cEnnY
         kOiIEcz6LkTgjm1vNvM5N1fFCp1U3YR7CfPZF0h9Gn/3jgGHC2RO3LxlpL+lxyrTXQ2l
         CcsWErdm0QBod+acrgqbdZXl8iF//9zD/dcvz7NwlO+dTxWfwaCrw5yViiBojhfSc0wQ
         Ft6DAZCNHQeyQcWkmTNdK9YmDTjTEj59BXMPa5j6ixx9ntwFrnmZDieSsT0DHsYCwIvC
         vRcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGo0XXGBMmx1G/5fIX0rUgbGpckdYJ1IEEgnlXCZbwSGrCjoKBodAFqslVui4uPe8Q4DsaNxZeXX6CksEL3ec3LioZz+Vupw==
X-Gm-Message-State: AOJu0YxAf/InA7KksyuvKW1CJpDV1HurMfSgPYQRyhW4x8UwhxWctrRu
	RSg0exW+opSbqYM+DvsfSjKvbkzK9cAv6+wLvDL6qwsysw7rbyTp
X-Google-Smtp-Source: AGHT+IG4fYrJzL0KhxG4BHs0OsAsakbbINgw41CbRyDXe3MAchyPdOCjeUsf61IJflboW1RSdTCcng==
X-Received: by 2002:a05:6e02:144c:b0:375:86c9:9ec9 with SMTP id e9e14a558f8ab-3763f5b7c7dmr266087655ab.11.1719628240548;
        Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c269:0:b0:375:8a14:107f with SMTP id e9e14a558f8ab-37b1385130als10780925ab.1.-pod-prod-08-us;
 Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqgw+qIuQGxtM+OiM2AUMHAoUPpwa+FvnP6QZOehlr6Za7NX+YYhXny2bH/4CoWeZEz/HzfNZN/5+zCEFw76TVTN0bfCPfUMb1vg==
X-Received: by 2002:a05:6602:122b:b0:7eb:5250:a54a with SMTP id ca18e2360f4ac-7f62ee0f91fmr9741039f.7.1719628239675;
        Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628239; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEbCUe38oC6GYiSpQe73C/8brXZFq7HsXCLNCyL4NK+dwFoN8iCdBLQRpNfevzrm0T
         lO7Ec4PNFPlBTBLTAd0C3KdGHJwuWc5XFR3s+vykEv9F8nP8iXCfFLuj8qJzdzpdnXi2
         CX7gGFiJTOvkeXItba0oLgJVWnbgOfwX8sf3RvEEJA/0R8RrFeAK8XinDF2B/uQXngjd
         XSpCqfrZtomqw4kxpHPSpmQXEQ58FNuCAN5/3TDlP4DgN1xPQKRN6J7EemXD7sQUwIA7
         sOCvM+UltS6DLqDFEa6zYsuaiZoiCscxycX0dyaoh8tEA9kJXbkKbxg/Omz08HDDWR1J
         aQAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=9fdMhgl3N1Hb0L+fVAwzEtmdbmvVoDGdWIOrcLynYbM=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=jWSeT/gBSwtR5FmTEcQ2IEONDzbk1gYpLWqcbuoiDJ/Jhq3bl9WPnOGFsUZ/w6Se8z
         rrh4o2EE4/x8N+HbZpo5mb+9JS4/F1MCmdPHxEy9VEpTBjZnOL+Iz+P2tVxTGtdPzt5/
         3+jAr1JC7hIHVsMjOftP79s3AeEhCpGfCH1wja5j9IPz6a9FmI++evL3b7+kgxKn8JDL
         8jUbw4WxiEWnB6KwlVZ1eLVOPb1XHOUsbwiWdMFxw0hb+gB0QIrlAiXi9t7cKQ8hjwZU
         CrQulHASlzxm5GVg3sMXIFeAuJMQRcVkhOtfF1B2l+2fHNFKRF1VjMLH5/L3TjzuVQJZ
         f4DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=mGNKBgrj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4bb953d0c04si71127173.1.2024.06.28.19.30.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 92646CE3C29;
	Sat, 29 Jun 2024 02:30:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BE0A7C116B1;
	Sat, 29 Jun 2024 02:30:35 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:35 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch removed from -mm tree
Message-Id: <20240629023035.BE0A7C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=mGNKBgrj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kmsan: make the tests compatible with kmsan.panic=1
has been removed from the -mm tree.  Its filename was
     kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: make the tests compatible with kmsan.panic=1
Date: Fri, 21 Jun 2024 13:34:46 +0200

It's useful to have both tests and kmsan.panic=1 during development, but
right now the warnings, that the tests cause, lead to kernel panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Link: https://lkml.kernel.org/r/20240621113706.315500-3-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/kmsan/kmsan_test.c |    5 +++++
 1 file changed, 5 insertions(+)

--- a/mm/kmsan/kmsan_test.c~kmsan-make-the-tests-compatible-with-kmsanpanic=1
+++ a/mm/kmsan/kmsan_test.c
@@ -686,9 +686,13 @@ static void test_exit(struct kunit *test
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
 
@@ -696,6 +700,7 @@ static void kmsan_suite_exit(struct kuni
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023035.BE0A7C116B1%40smtp.kernel.org.
