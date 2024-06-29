Return-Path: <kasan-dev+bncBCT4XGV33UIBBX7D7WZQMGQER23MXPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E09F91CA93
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:56 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-25cb4261a5csf829930fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628255; cv=pass;
        d=google.com; s=arc-20160816;
        b=fDzVey4sf7rlpBNLrN0ik6C6713ocZKMcX2Z5wavFAE/uQBfdKopyNI/0LBd4T8LdJ
         qshRVs4q+kxdOlpPpY39cLQm2Pf+3mwpDr0c18+/zoHTOiFBEQW2P1KIckY7JNNxa8NX
         ivqdiVQZs1hDAL963tJqFDwAd+sN5lQqZZRjyW5otl4wGDmjPPc/IrE8W5VNJJdxepsT
         RipIwxr+YDeE/C63LVjxZ2y9rgL4f6IoazheT02nskSG50MUbIRpCaukmcHS9RqVavpY
         unDh1gz6IOcvS3ka3G3bEpyxSnYGxwSKjcwpUCAyi+jNOWC7cCuqT3iGOtNAQ9YBYV8g
         Qpfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=h7RAz4Abs1yo8GzLAskBMY1ShQ0ISK+R3/CDFeQjS4Q=;
        fh=Gs4OfDhBDTT7ArMksjAQdgLDNafzy0Cctj8Nmgbst9M=;
        b=rXHgr9YECgchO5AVjJ3Djjnv/thr2M6Zp4bjfrYv6GgBW+DHJ+RrR23eptTtC372gF
         AH22qNyZ8HDI/w2IY48fhEdqEhRngHAoFFeOMtVKuAZ1SEKabLZqKhmgUld421maVY6C
         G7pIKYKHUUw4cfMnkJTNkr53/RlO07vg51GOi0J4K0U/LIBQrNM5kw0mdh6EclrhLOh2
         ZnSio/YhX17pqqOT4PnW2ENTZyZClZy5FGrqoA7pezCjc1eCJ8WAcs78vab0mHMqA7fu
         M/KlhtUPSxmkUyFLt25RI3Zd7PRHaSymLQc3imarYRBEMx9MLRj6+NpjRMJTlKeflEqh
         jb9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KHUc8POJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628255; x=1720233055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=h7RAz4Abs1yo8GzLAskBMY1ShQ0ISK+R3/CDFeQjS4Q=;
        b=t31mkwk2GT1Gjdb4QrTALwWS1G2vcqkjIc9zfRzJ710saP2X1C9rsouxe2P2EDJSju
         gC7vtZmPHPudJWft3cxWPSdmEt5okgPgb0KJ4LatTkmG7Nzyo/haCfwgnKYpLPAUCwwU
         rDBBcb9AKOM/16Fm1lpkqMULMyE0/ycBA7jxvBqO1h5irUNqNdDVQ/RWShsj6jBSVnfK
         zUZMgrtGRXrXpyWaxXmhjeZaz/IRfTxy50dQ/UNkjjGOi4WJvBwq3GaqK9SimOoFhF2f
         5chxTmvw1E5nqcqVnnhFQy8x/cqHDrKDiNzq80tNsld2r7WVASYLFSzN9nD4Y30DUUbj
         6z1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628255; x=1720233055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=h7RAz4Abs1yo8GzLAskBMY1ShQ0ISK+R3/CDFeQjS4Q=;
        b=LGxfYmhFQ2y4XVuIee7ukCLESRe7mLIlOUuxJo8LlZF368KNg18fWux+zTjXD0tGBK
         MCeLTsEU3IqngKA8v7ImUuverXkDe0NKkW7g7s6PmbQLZBlnlvc1ZeTmRHjkSofuGjHu
         dwQkWdKPJWdTdvUHi9IIvHHybyq56k7Nz+RKl5zCMfcpThIvbtJKE9quGLITOayRhdSg
         Amiltci1VkkiHh14ZHvlsJ+mqc7d1fZJczMzva9e3GA7LMfKTSnncJAOav1GAKPGuRpk
         v2FGAnp4RQrnADTJBLo+zJrrj3tQ7ZQf55A+7MWXV7SnzopGJBk+KreZGVLGYDE+nPV+
         v6qw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWr/Ka6o2ZMjDpKor6s0mev9bjD2+1N1f8JZ8wcKNmQ616wD1i82uJgjjoVW8DH2aWMqGiUDXsH6+YTwnQj07PRzrEqNkzSMQ==
X-Gm-Message-State: AOJu0YxHyLEGdcWfoVLhlaIQjwSccXnFT01J9VFRI5NmLhoLTLJWA9PS
	0UDVz6Q+/9taKtWf8HbC0tnfQHwxUb+ab40ud4iN0kQXyG955zXe
X-Google-Smtp-Source: AGHT+IHYPOhqoqgd33RUm79JGRMUQUDOkztfKTOr/6otbugv4Rb3q/n8B6qVDWgKpQgjHcLISgJilA==
X-Received: by 2002:a05:6870:71d3:b0:254:a917:cb3a with SMTP id 586e51a60fabf-25d06cd6cc5mr17532819fac.28.1719628255331;
        Fri, 28 Jun 2024 19:30:55 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e499:b0:24f:f0cd:4790 with SMTP id
 586e51a60fabf-25d92c3a9bfls961226fac.2.-pod-prod-04-us; Fri, 28 Jun 2024
 19:30:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTfSzl2gBWmdWsBT7Iaent/9h2C0LgIlrd6RZZcya1pPEUarmgzI7KzUc6/oSLid9F9eenQ5Yb5vo1Q/k1UiEW0igV+V44LkrI7Q==
X-Received: by 2002:a05:6871:b0a:b0:25c:ad1f:b32a with SMTP id 586e51a60fabf-25d06cdcceemr19464862fac.27.1719628254561;
        Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628254; cv=none;
        d=google.com; s=arc-20160816;
        b=xAs9s5VcTvTgqm5+woVEDoNbWnNNCGvbZELHtChAGNuk7lLYeED1GGfdjHyy5zQTgj
         /HeMS7PsMAJ4rTmdccuDoMXStocsnXlwoGTZY2lu+SeeP/1m7mjldy6vtma4srI/q3Ws
         7goSzPn4BFDiQja58g5SyYoJjF4gC/iIRzFATS/yC3FkXN9Q2NXba44Aw0w2PgYDaeff
         CDtPNngHwxOfxgjUM0Hdm7x4oBNKdbldW7kYZF1HwQSPN5aNnHn/EANqkDMeclFfo2/e
         I18rg8SOM6eGnjoiRK/e8VYzBDG1WYWs4pc1S/xp5iR7KPODOF4+f3w1UWzv9KxWSe6N
         sQYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=YQ8L6RTbzxIOQAqj1v+iPrGetGlWQ8ZTsfamQFtQHmY=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=NTjIEzhFaBZU1DNdnRz1eKzmlOjDIwuzSyB5hpNVqlPvCZ55f7WrIy02YzQtzU+maZ
         9gn/NDpYf2gtmTE3nGcqY3WXo4aJ/4itWmC6r/fLQHgdlQxiOX62dNvg/H5fq3BalD0A
         3fiLUAd51OrL9e4Oa/wCF2yQnreIJNXNSz1hvP+kN3y3Wj+XD0fy/tcapHpUupaGvNVR
         AGCjLjDtuL5r3pzDfnUFTplZ+tX7xQnGYfOOQtnkyZR2mTwJkP1ZafT9FvI9T9iuXNpM
         Gjza18B76ICHnpMEnn9dCsjz5Sj1SmoLK0OKamirqvC8DEVO2pwEKY0KPmm6KNRcVw/v
         Wa8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=KHUc8POJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7b3ddabsi118334a34.3.2024.06.28.19.30.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 36FB1CE4349;
	Sat, 29 Jun 2024 02:30:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 62B97C116B1;
	Sat, 29 Jun 2024 02:30:51 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:50 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-support-slab_poison.patch removed from -mm tree
Message-Id: <20240629023051.62B97C116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=KHUc8POJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: kmsan: support SLAB_POISON
has been removed from the -mm tree.  Its filename was
     kmsan-support-slab_poison.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: support SLAB_POISON
Date: Fri, 21 Jun 2024 13:34:57 +0200

Avoid false KMSAN negatives with SLUB_DEBUG by allowing kmsan_slab_free()
to poison the freed memory, and by preventing init_object() from
unpoisoning new allocations by using __memset().

There are two alternatives to this approach.  First, init_object() can be
marked with __no_sanitize_memory.  This annotation should be used with
great care, because it drops all instrumentation from the function, and
any shadow writes will be lost.  Even though this is not a concern with
the current init_object() implementation, this may change in the future.

Second, kmsan_poison_memory() calls may be added after memset() calls. 
The downside is that init_object() is called from free_debug_processing(),
in which case poisoning will erase the distinction between simply
uninitialized memory and UAF.

Link: https://lkml.kernel.org/r/20240621113706.315500-14-iii@linux.ibm.com
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

 mm/kmsan/hooks.c |    2 +-
 mm/slub.c        |   15 +++++++++++----
 2 files changed, 12 insertions(+), 5 deletions(-)

--- a/mm/kmsan/hooks.c~kmsan-support-slab_poison
+++ a/mm/kmsan/hooks.c
@@ -74,7 +74,7 @@ void kmsan_slab_free(struct kmem_cache *
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
--- a/mm/slub.c~kmsan-support-slab_poison
+++ a/mm/slub.c
@@ -1139,7 +1139,13 @@ static void init_object(struct kmem_cach
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		/*
+		 * Here and below, avoid overwriting the KMSAN shadow. Keeping
+		 * the shadow makes it possible to distinguish uninit-value
+		 * from use-after-free.
+		 */
+		memset_no_sanitize_memory(p - s->red_left_pad, val,
+					  s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1152,12 +1158,13 @@ static void init_object(struct kmem_cach
 	}
 
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, poison_size - 1);
-		p[poison_size - 1] = POISON_END;
+		memset_no_sanitize_memory(p, POISON_FREE, poison_size - 1);
+		memset_no_sanitize_memory(p + poison_size - 1, POISON_END, 1);
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + poison_size, val, s->inuse - poison_size);
+		memset_no_sanitize_memory(p + poison_size, val,
+					  s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023051.62B97C116B1%40smtp.kernel.org.
