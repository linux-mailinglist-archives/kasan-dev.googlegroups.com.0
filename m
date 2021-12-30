Return-Path: <kasan-dev+bncBAABBZ4JXCHAMGQEKEVPZHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id CC8AD481F96
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:43 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id dz8-20020a0564021d4800b003f897935eb3sf17637195edb.12
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891623; cv=pass;
        d=google.com; s=arc-20160816;
        b=i5UEkbvX4WDiaTnP5Pntc1godB75dci0jOJedjgvtZJD1Rfc8DiviwAtScIO8xVLot
         BRVZBZQjqgxF/ieDJgRLKPjHbFSDkdm5UE42KAGiEYyQcttFcBogmnVfL5VgK4cbqTDZ
         NrAt4oIR0Py2F/mHX2EXUN03M/H0MOkQQAN/hDHxx3iRdJc09yi97VuerSC8XEqNXBD9
         +ZFJpm2P4singIHav5lxG2FTHHkBzvz5WT2yCwY/wjCsLD4wVmIv1xajuczJoX9tl1BE
         m1TYgH8X51HGTwYNArHiyfG1qy2Q61Ic5dumLI4chrYu+ZiwajTy1yckTbSsG8KBIGlm
         VAuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oNyB/3icCwJmgLefWCldXS2KFYGodA6FCr+lARPZFdQ=;
        b=cuVhaczQGWJ8DrxaHPZmh3ptn3paNMLC3eaWhr+0LziZAZJqWol3sUmtuIS0vjwb75
         javrURmHSwen8pp+qRopoRXMiEqoKtlma68XJWLrIYTS2ZKbBYqpPeYVfQNauejpNXxu
         MKNqIkY0neon+qkTFC807UIg88FaHy7a/3mTPOHN/d0GMHHwrpWB+C5v031Be7No4tv9
         lTvLF8fvLg05CXlIhfpL6W2Q4LFq/sB/atG4KNkRlWCXaJXxEFtugavNVTjlILjtb9s/
         YdjDRV3kgGrR+dTdVQG26oXU29yQ8GudWJeYQHUVuqOnc99MgEBxOxQE84YeflY//YTx
         y3ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lXV3e+Tn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oNyB/3icCwJmgLefWCldXS2KFYGodA6FCr+lARPZFdQ=;
        b=ECdBTvfz3YcsOzCjSpf2JANwcazspHBZgiEXVj2Q1IrlsibF9TK7PyZYu9ptu/Kv7N
         HfMg2Rq6R67QoYHQShssqnVIriTWbRG4rKDH5E9KZz/91xFrmwKeH/lyWAosUz1fKS8z
         s0HLQQlUkTvT9LGqhhY2fGfguCu3MtXQY0YA034FHXGTMKpmXO5huwJx+BMlMU3MoUke
         DlWTQUeZQV8uZz+Km3XVU0SYKfYGgtGlHjmgKBrGE45yMp0r9fzS2gPkU7Tk7upIUs4M
         zbjLY2q3/M+eB8ejfLL15mS6h+etk6Fiz/r8eOiggRyfzqeJe9/jvLBEFQb/ZO3WCVAx
         cv6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oNyB/3icCwJmgLefWCldXS2KFYGodA6FCr+lARPZFdQ=;
        b=JBmOjYG1yRkb9Mc1JhAnBcrJd1uYDY8o5oUNwYavmAeTZwy1BSVaBE3qps3awDyvOC
         rpndGKQ7RwoJcbfP4BMWtbmkUmyyq9eZ26+fBhB6kXYeBamYu/njmiOGkQ9OCiyzUK7G
         /PV76tiSg17eD2a+V9JGA2mWxRx3ZODmZ7d0gpOGVFiRlBP4a64IL0wBc14AbraHu24p
         m5sRFMcP1fFuULCZ98eJ4CBtyz17nbTB5VJo+IsHjfJMaGSwWAIqVfvpvxjVx1Sba240
         DNNbhvpGCNqkUtbOzxO4oSXp3HNwrQHV6ZUBtj2SJsmeGvU6Glxqwzz+bGZTfKl/F+xj
         Jd1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53212gWw2sQZDGPFjMZphRklfb6omXDIDLiSLNorIFjtyEsz3Fip
	vyRHU7sH1rxhoO5zC6TiZ0Y=
X-Google-Smtp-Source: ABdhPJwQZTBPCFRWBZt0Z1BOMAEb839u4BuW+CKSN46lZVVOBBpgetODDANlJArz3fTNJdm7qcgu8w==
X-Received: by 2002:a17:907:728a:: with SMTP id dt10mr25969265ejc.160.1640891623566;
        Thu, 30 Dec 2021 11:13:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3591:: with SMTP id y17ls196208edc.3.gmail; Thu, 30
 Dec 2021 11:13:42 -0800 (PST)
X-Received: by 2002:a50:cc07:: with SMTP id m7mr30928561edi.4.1640891622827;
        Thu, 30 Dec 2021 11:13:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891622; cv=none;
        d=google.com; s=arc-20160816;
        b=DyqGLMsTsSuaorpiuV+zjp1v1cMNdk4zWI3Ibsw0tj4PJegA46kClwyCz3kabTtN6V
         3uiqOSW9UOQH0t628qjd8zMQcFow/5Yx4zERn881Qur8oErfiZKnWL2HUwYA7UYxVZCa
         7ihfJHXJQA17AFciwOg1HWh/WLxBzC3zL2OTIzu6vk+v4GacNLZXrbcvqsqgdxXZSfTL
         eWGjOlabKmD+OKuiGedAiRZKPWT3sEcuA0vCwMknODzPsCyIYC+0YVNyPXp2cGmWpZEI
         mMFQgjQO7wO9wStYm9EL2WJuNxHVU2t3SkoeC0EtQMDr+C6HipN/NPgMu/hdBKEitqYb
         xC4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ETGtFPT9DSWIB4bf6pEH+UDYDV7ngicpRFQCLs3jhbs=;
        b=cTwG9B/mvnNktIJ8HWtF60TT2BJAH6HUKqhZU22LaOBKNylRY56qqa7Qzk/DHSbdM3
         GtYS7QAbs7DIMqvsYCRHO7avmXADuY6q9qio4OCsLB+LSAI1/87K2WI9nNxopN37MBOv
         0/MoG6zjyUJTFy78jf2WRhiVJXlULrXjGdt9+lOLeNK8gTOjmK9+x1Lf8PDDRcXGSuGc
         N+WZ3bSKbTq3eL8tmaAEbYDf0KCDG5SDOeuEE+qKaI13l8PD3KwgDXkTr46NB1pxzIBy
         eh4BTQVPKVTnias7vcGBOAJUOwCx6zW/f+a6KhAW5vVtL71pXp3FGzqJ3RO5Z3/b5cXE
         E4ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lXV3e+Tn;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id v8si1348669edr.1.2021.12.30.11.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 18/39] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Thu, 30 Dec 2021 20:12:20 +0100
Message-Id: <90916e25463e7c7e56490765eb6671aa8fd6947f.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lXV3e+Tn;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index cde400a9fd87..34ac66a656d4 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -35,17 +35,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_DEFER_KMEMLEAK	0
 #endif
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/90916e25463e7c7e56490765eb6671aa8fd6947f.1640891329.git.andreyknvl%40google.com.
