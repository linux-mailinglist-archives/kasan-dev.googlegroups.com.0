Return-Path: <kasan-dev+bncBCT4XGV33UIBBY7D7WZQMGQEVJVCMOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D557E91CA96
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:00 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-37629710ab1sf81575ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628259; cv=pass;
        d=google.com; s=arc-20160816;
        b=UiCCeRPUjdC0NSb1nxCghP+e9Ioe5bMXgrSPBThYYf9QvoqLPNCuEVt/l3ck8qSZnK
         4Qm/qlrSFne1kNchJRvGtv5kYeqRiFFIDTfY7+7o2hx8DFdIYK5TCRoS/N3plTsWAhP1
         RH5cfyvJsDQSYDSb+gGwFTSplVZk4hAF1Ix39oURc+9cy4yhYxEuW7xY5CHONYZzic+Q
         t5toHwSmwzDZjv01nXd2bFKMMNOLW5IPwXjYFqBc3ARxL/X0Dp/+7jYi0Y5yusxM5mWw
         mtg5Z8rO3KB99ah7rnSSOUIVGnj/+C20HikUIcpm1x/2sPgQaVUQniT5QQyAGDU94RO3
         YL+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=JUvEi20rOc0MH+wZEkDVoXm4zqHd3Tjx41x4Sn+dA3g=;
        fh=SnznNODV0McdQxhKWKbp5ni9WA72skmYNMi7NonIpSc=;
        b=VxV3I1EIRDlpFBPUf1PhvMGKPzkrKpp01SaZz8rj5XadL4wIjvZReXFo91ACCNUKjm
         BcQdyeWnkeCXdeMnnrYuvZuuozerYtyxLUEazah6T6g0o31ETZP6N16VNpdBEtx94Uh6
         H1BfzkR4gGY5gdh6WuaStpPuCccefUbunjFdCyPT35zJrakfS6Ssh4O/reXYDjtfULka
         s74Lv/X++LZ4mFbHW311coIy+1aPp9jj4ryp9bys9gBF1dnRRAEvjYshO40F6etHqd+w
         1bBG0shApqSaN9Nos/5jkI4kGLLVntp9CLdR7LsxYOEQEJujx7aJtHvr7Hi9r/0CXXiv
         HtFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zNqN5gaS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628259; x=1720233059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JUvEi20rOc0MH+wZEkDVoXm4zqHd3Tjx41x4Sn+dA3g=;
        b=sUaby0Tjzt9WPOTsERmU5RHVUNJAiWs1i6R1SByziNk7uhyId/z9cN7pExDagMmqpc
         6/VJMY13t4wZClhq/jCs2jO7vcCiS4VKxzUvezCO9mvw5JhUoz3isHbO6c9C0Cl/J23j
         oWymsuE1SWtPLGqIIFoy8whxydyYVL99lq+QlZOb5E/0a0JWLelelPNwDngLWRgxwrq8
         I6Op2rAL/wUh9k3bGjkmPOcaXfj7RKHvD19x0dAaP0LTZaksC/attnW5dvD7ImagcCiA
         9+4Eec5kS/qMtIDmBUtN+oIH+ySxyujYqWEsvgku/NfGFNulTYEHi66UNlkhEqn8vZI+
         BxKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628259; x=1720233059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JUvEi20rOc0MH+wZEkDVoXm4zqHd3Tjx41x4Sn+dA3g=;
        b=hfEB29iEUN+sEVpuZc6+48TnyqeUwV9MUNnjgr8OcLxWlcyihAgiDtN5E3OrXFESfu
         +tu8kCKYhzWvAg8QapWDbR5NH1dX+11Ejpc33uvDBC5Gh1NpCS1xZC/L7IPeBe1/4q0e
         Aoq43558faFRvkej6VqH5by91zjdhgYvC4g/AySeILPwGHOuADXTuo3mlCJKYi7I3jI1
         WiiSbUqsuiMphurOuwCM7pgvGNRLudzte6E0piz/FHdd1X8wE54PIk60EKD0fxCadLDw
         n5/tt9RG0I8G6xfzrPOSR3ffbYQ9OmYCWC7OAy+lncu3u/Y4aynZO2gieapgYfUGZAnB
         ai0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWu/RbrorJAgFaVrzNIP5fECSMEWhzWp0fK6Llbn9Hdxwov/O9SOc7YQMgp1pGmzPDMsVq3B4ylcA3P8nojc6YX4jph/5RDSg==
X-Gm-Message-State: AOJu0YzXANxd17RIK139znFdIKOleenP6UPnRkhrOI/ZaoaeXIx1oTB8
	uicylISPAlSvh4/+jkIpzdZdSd1SlEfSanzwquvUB2/iVnPpCeB8
X-Google-Smtp-Source: AGHT+IH4OMAbYhlPgM/wzq6Uhavpnkj9yeC1ul81gkvLxvRdC87ZEGJbHA6gMMEcNT2lu06n9QYTZw==
X-Received: by 2002:a05:6e02:1c03:b0:376:f79:1337 with SMTP id e9e14a558f8ab-37c6690ca9emr731665ab.1.1719628259721;
        Fri, 28 Jun 2024 19:30:59 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c2c:b0:375:c587:1b42 with SMTP id
 e9e14a558f8ab-37aec57f70bls11935555ab.0.-pod-prod-04-us; Fri, 28 Jun 2024
 19:30:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGEgdHOIB43LvPB/UqRCWar9ZU+j/XhBWS0JsNlNRwW4R/OvI4mWsTOl7OQeX5mV0/k91YeyWDcg1McDC5sQPdBXqxSm0+spE00Q==
X-Received: by 2002:a92:c242:0:b0:376:4544:826d with SMTP id e9e14a558f8ab-3764544843dmr208490945ab.5.1719628258918;
        Fri, 28 Jun 2024 19:30:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628258; cv=none;
        d=google.com; s=arc-20160816;
        b=kUkaqqV6iAXXVCSqKwELPSQKJlxWogegrFPkqBhzJbrvhCA1gL60KubwSptBag2/3R
         exXe+oD7oZPDCeJzmnNrp15fZIM6XnS89+8k2/vRg+AZL/x17NP3wtDV8BiOLqIInRLB
         zfjLB3f5eBNpyRvzXv8IKpJsoYGPWR3b7AK8ys9AMhNZFCfnzWtgwbnTefAM6v5GvDXG
         Wd8TSEhZ0Pz7QFJtHKVKjxP8NKQe1F6OOqJSsWDWfkBzXAOR5WcYQ96sEVdFZ0g5Auvx
         1QQWisEIUCAUqnM74R8+q2Fo+jVvGSiPb5DsUgVCls14a2P4P0HLbS6ma9m9bbD/vFt5
         8aUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=yCe8RfUY7VLrqBsXOTm5H891/HYAoLyxfOhlllF7+Ug=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=Wxgmsfpv2DXpHWhY/D6+VB90WsjS/fRoqHmj5/ToF9Ze6MhupyqcYdOfrAXYH40NBt
         kSZ8EXZ0avnwgUl+JdmzvgXWdshQJg/ysTQRdEOM3xbKh2UGb9NMa2sIytqQXBcdwvo7
         aLk5xA8MhDM7jPpYMkax+UhsyeH109vpkTuHSlVETAa++H2ri2q27CkfmAMRbABDdukY
         qjBUBZJm2ClMCXo74ivuQsQnEd0xiDqZnaJ1QJATLJ/MoFiL36ITlJd2gqIuwqP0S+oT
         hDPbXC9tU6rU6mRQEFiUC31dFnoOXd6vnoAER1JDv0O5Czw9EwlWTr8T15VpeMccOeBF
         7bDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zNqN5gaS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-37ad298148dsi1381915ab.2.2024.06.28.19.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 90585622C7;
	Sat, 29 Jun 2024 02:30:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 39A77C116B1;
	Sat, 29 Jun 2024 02:30:58 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:57 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch removed from -mm tree
Message-Id: <20240629023058.39A77C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=zNqN5gaS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: mm: slub: disable KMSAN when checking the padding bytes
has been removed from the -mm tree.  Its filename was
     mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: mm: slub: disable KMSAN when checking the padding bytes
Date: Fri, 21 Jun 2024 13:35:02 +0200

Even though the KMSAN warnings generated by memchr_inv() are suppressed by
metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns `*start !=
value ?  start : NULL`, where *start is poisoned.  Because of this,
somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

One possibility to fix this, since the intention behind guarding
memchr_inv() behind metadata_access_enable() is to touch poisoned metadata
without triggering KMSAN, is to unpoison its return value.  However, this
approach is too fragile.  So simply disable the KMSAN checks in the
respective functions.

Link: https://lkml.kernel.org/r/20240621113706.315500-19-iii@linux.ibm.com
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

 mm/slub.c |   16 ++++++++++++----
 1 file changed, 12 insertions(+), 4 deletions(-)

--- a/mm/slub.c~mm-slub-disable-kmsan-when-checking-the-padding-bytes
+++ a/mm/slub.c
@@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_ca
 	memset(from, data, to - from);
 }
 
-static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
-			u8 *object, char *what,
-			u8 *start, unsigned int value, unsigned int bytes)
+#ifdef CONFIG_KMSAN
+#define pad_check_attributes noinline __no_kmsan_checks
+#else
+#define pad_check_attributes
+#endif
+
+static pad_check_attributes int
+check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
+		       u8 *object, char *what,
+		       u8 *start, unsigned int value, unsigned int bytes)
 {
 	u8 *fault;
 	u8 *end;
@@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_c
 }
 
 /* Check the pad bytes at the end of a slab page */
-static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
+static pad_check_attributes void
+slab_pad_check(struct kmem_cache *s, struct slab *slab)
 {
 	u8 *start;
 	u8 *fault;
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023058.39A77C116B1%40smtp.kernel.org.
