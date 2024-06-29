Return-Path: <kasan-dev+bncBCT4XGV33UIBBUPD7WZQMGQEPJGIWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D40391CA8A
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:43 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-24c501a9406sf934933fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628242; cv=pass;
        d=google.com; s=arc-20160816;
        b=rpYHzogHuuFXmFAMaxyoWQKdbp6GitT5Tuv1T9Rh3i4A2WVjx72xDMW768SaLfgnf9
         IK1zUjq3lLjLbZIw7BeTKotyAbSuDV0fNwF1RyD33c2eIaLSE+XCXeGiGZ5VtVP+paZ1
         sc4OEA9pcvNYdiYHh1U9CRqHKpzvH+PQKp3aWrFbEFUlE1XzFT2VcQ3AlL+TcqrTuj/C
         2a92c+AH/BU756TY3RugkZ7aRDXjhJ/rxkAexpTlxgPLuKuaIiYJ08CiFQOXv+AbcyEY
         fwFA8MYQLC3IdsdxZfhAXXbR88/0r8f+n2wcLotKm3uw6SeDL5kDAwEYHU2EJfrXOsqN
         FjIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=wasWnoJ/EBZ8GYXtKxk7asCVH6eLkXz/G7SgkkWPMeI=;
        fh=LpYc0vfJBlkjybHVIlMdCjX4xufrbEF7Z7Ms+Mfq1y4=;
        b=FDBBc467caOsquX02XWt6LCuj1e3OYKAo+vxgJmqhYWObLCZ4loG9mi6ZS3qAEzY5Q
         /+OxFeHyJRGxSZHRRxyONO5sng8W06WTBm8/cvVDX4oYRDMGdglJbdNUBiTIo2FaQ7qn
         3gfGy2tYmzTX2ytVvlyVdyUzJjohnBNaBkSnQBfCdWS8FqWjJy8U39b5EH5OSZ9x6QfL
         WkT3qDY5nF1OATzr2ynTZhlLTbs8SDtBD04B/Ip/slHwIj6952C45zsH3vpt/mNfKcvk
         cv1gPZU5bwU0n4nzjlmc0bBjlnWqJI0ZCO7zkJiKYkRHkPhmjEmHJlgPkkGiNmcLSicU
         yaSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=H8qDK6kS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628242; x=1720233042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wasWnoJ/EBZ8GYXtKxk7asCVH6eLkXz/G7SgkkWPMeI=;
        b=cC9tzUmrytoKu94E3btUt61Z2WMS6b3cFcSNIFNdG4SebYszmBl0GKXhJlPi8w5NB7
         rZXzlDdnMnBtuctFNPXUWoJsBeVnsaglP8UZJH3Z4yihq3NuJ7q5BQv7AlihVuyu6Chi
         Yf3f11OVDLph6CKNkmGIxNSYTzXwGi+sWnA9A/xHCoJF1Qurr1mwgdBPzVBumkriAifF
         eTDrTKreZFMWaEJX9YgeXCpywt9hOQdNSpkSFRvt/9OTq7zoTdOgPbB6cnErn8zCS21B
         S41U4MalByLi5dgBNfgP8AVNSEPcwuQj3MQvUPAIimylOa4X0dgMH17OrIz1Qv4IR7st
         JuKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628242; x=1720233042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wasWnoJ/EBZ8GYXtKxk7asCVH6eLkXz/G7SgkkWPMeI=;
        b=JB1GllxT3J9Ms3K7zakbW+khKlFmaQG8M7IAOZd77oIs24y5vh/8HFaS8LLJCqXcqh
         T4w9nnvphZz0jDDtrpuNwxza60RNRRCVVP044X6zCYkPyNYzPLrkRgrB56bbU0KShJ4H
         qEJlzV8lKC4ZbCDKX/Aiw+ArUd/u8b8U+xirqcKoRBcN+4Zwsp/RQ6F3hlk1xkDE8sYD
         ciCDWh9SljtvOfdGM6zh1xaA5XzcH/pojchr0uGAvyaZd6f4iucjgKfQC9Y+7xlNx0Ux
         J1YJkK3Gf1ojp6K707zoY3ezW/rdYVYPj+9Kmg51sAgiNw4MWbWUf6GRtVy1XCO0NFNN
         vgEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZKDZ8pvjmvv/of8fwETAgN8BlPeNq+aTMs1ddmmH3sPLMB+oGiXs+0MaqMHIkYHLLjPxh8mbk5rdqLjet3WsGRCqgqGq6NQ==
X-Gm-Message-State: AOJu0Yz6r+cfJ/9fU+PC9It0+N7YBXnmQIwoohvO1i+VwoEGomYcYuY+
	m2qi3uQ1pPAl/OAl1fbt8N+2IkkY1utvqyRh8ADflcizVFxC2PtU
X-Google-Smtp-Source: AGHT+IE5z8KCroHtOXrgBBUAp7q2RPXOjsVLbQnGURGQ2mWhfmJT8l0A6J4671No/TkJ75FcuN7BSg==
X-Received: by 2002:a05:6870:63a9:b0:254:b9d5:a31d with SMTP id 586e51a60fabf-25d06cdbf68mr18013279fac.30.1719628241958;
        Fri, 28 Jun 2024 19:30:41 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:658b:b0:254:6df2:beae with SMTP id
 586e51a60fabf-25d9261ab36ls801876fac.0.-pod-prod-04-us; Fri, 28 Jun 2024
 19:30:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX9wjGc/xvWePL5JjT87vZRwZlJiXhwJH0hd1o+s/HXPdHisVbBqerqaUioB1f51oiiH86etJvHPxLxzFxsnz9GhxwZQqqjHLNNiQ==
X-Received: by 2002:a05:6870:224f:b0:25d:8d4:68ab with SMTP id 586e51a60fabf-25d08d46999mr17025508fac.40.1719628240685;
        Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628240; cv=none;
        d=google.com; s=arc-20160816;
        b=Hjq07yKGk+0DY0vZcZdHts1OQgcxpLAL6BFzmueIV9Qa5b7IaMHgZRq3kVIneLBuoJ
         NPx5UmdO/sR4iZTneFIdUygZmpuoB+9JQzvfvAAdlso43rJaS2x00Si0Kqbm35VgjQKL
         ny83Xxd6WLpqkrrX+3UVUZMotakScOrklirE+exvpe3HKZeLrgPT0Zny5cbfxZPadVSw
         S1kldH6cTmnJXpbxDRhxGWAixCme2ro6Y2g++blxrQqRhSvUO+ooUXvlg+wfbQVBhbhV
         aGC2Y1TjN9j2fnoCx9kQuLX+bLdxhUOVFsbzNHz9e17c8nVcezAp10LiY4wV65WbifAy
         ikgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=MeIIB/2K59SLIjcFZ3wTkXPeMva2JI47IZIWp9xp054=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=oYccZ2DtcTCsIPdfR2C+kSw08dHpeKFYKmfIUQbetJ7DtTgF6w2p9xQ0SqcN+MaS1T
         5ba4rMx2jM2FNDK4NIOPAG8Jna2fkHc2MO1PRkwvqnsBBES874mn5V6tIXIW4CXw8cyO
         TwhyMGgFfw1jOcFQeBezLf2czWDO09sNGTLr+Y6RPYNdoMhntQDjaQLcRlDVLGZZVx1o
         K40PmttvATTnBZijeZCth/OwAdNH/yXe5NZNrNXxomww4+2RBdFTRFZD0oeDJqso7lli
         EotQ+n0BsVMwbqOoLvtKJII7NfEtlcEjoEVGYomEVXayLkLuEbrtorXbnz1SAbVJvX/4
         J38Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=H8qDK6kS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-701f7b3ddabsi118321a34.3.2024.06.28.19.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 722C7622C2;
	Sat, 29 Jun 2024 02:30:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1A10BC116B1;
	Sat, 29 Jun 2024 02:30:40 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:39 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch removed from -mm tree
Message-Id: <20240629023040.1A10BC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=H8qDK6kS;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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
     Subject: kmsan: fix is_bad_asm_addr() on arches with overlapping address spaces
has been removed from the -mm tree.  Its filename was
     kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 13:34:49 +0200

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap.  Skip the comparison when this is the case.

Link: https://lkml.kernel.org/r/20240621113706.315500-6-iii@linux.ibm.com
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

 mm/kmsan/instrumentation.c |    3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

--- a/mm/kmsan/instrumentation.c~kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces
+++ a/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023040.1A10BC116B1%40smtp.kernel.org.
