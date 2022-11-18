Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL6G32NQMGQEC3G4LTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id BD2FB62F92F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 16:22:24 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id y26-20020a0565123f1a00b004b4b8aabd0csf1481175lfa.16
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 07:22:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668784944; cv=pass;
        d=google.com; s=arc-20160816;
        b=cP+KVU5QZ8JboTTNsMBnMTOU+X+P/umO2267dKXf76OFJctGyy7yBGHqRysrryVvao
         oBIyxiwQD9XmqHOFkMqiwZ6lnGI1JZ7hSVFj1sOdxXo1mMi5ih9HG+P9wVsTCE4G+JLG
         +4mYNdCOKUK22VxH9pFC0uhsPXXnAPKu0nHFPKKIor3EpZvFlUxxqeuzm5L1zrWfW4W8
         uyK7/8+t3uRodfIqCUo0fZ027u2MJaQwiU7FSaVPhwem6Y2ILlNap3Kf2UG3OeIMF1kS
         s68aKwe3uDWxuengNEgsgRfqB7+qUAWRIqCTwbZU8rtSIEgaZk8kYrXygf5Ep3yHTJKt
         Di5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=8GIiOz6ECKIer5AIYBtcBESyBr5Ik33DG5atsX5cCWs=;
        b=OsNjMPF54Vj1fLY2rhincEwJ6/cE1qtoX9Wd9Z5WweDuBNMZD3zRTa/MOES8/ZbCz2
         wdOg3iBr6X6peORIAmlJyS7UlncVbInELUQXvDkqQxZv7zQ4UX4F89rA8I/apbyyQGPQ
         ii+QaqKUULiKxGViQy7j+ka7iiAoOGJJYW07sm1C2EC6H9wYnvA2bmEKafyvdArm0yZd
         L7lWmJmYZTR1oaXJyuH3l5BHIw4P0pVF27gYYKv824xHVdSwz9CMKjpAIE4JJWHf28Wr
         PcKmal0+xGQlWMz2BQWgfvi+WjD2yQv9w98D9S3+wa/bVQ5KPc1/nsXabB6GcQ2PKvXU
         8o8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s8dI+I16;
       spf=pass (google.com: domain of 3lan3ywukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LaN3YwUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8GIiOz6ECKIer5AIYBtcBESyBr5Ik33DG5atsX5cCWs=;
        b=cBt3lu3txRBqhSQg1I9nzn5navn5NFC3hkmxagj+/BrAMM9+IsPw/wc+hhwGqydNRw
         l1lnvqx+9gbSDrufa1dlvTdCiz2m1zLzK8c2s4KwG+RBcM/RcJ1+dsP53IZEOgScp9GM
         m/vxqN5jtZZ9rI9boxgo9RZFTyr4qTnZFLtefujIsXb1/9J6OeZ8pVXptnwxGcQCv5a2
         4bdulmllKM2A6uounJDzmeR6IMpraSRe++NNdeLCvI1II1h6YZScNDO88HMk9tNQbSCQ
         xjsPgB1I4at8HkeX+YXgDjSLuN/AomlC+OcKfuPdDcxSGyWYBB1BFbDZwwp98qTjOO6a
         IgAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8GIiOz6ECKIer5AIYBtcBESyBr5Ik33DG5atsX5cCWs=;
        b=DbWdvTQic6tJEHaRjTMAUDU+NmkMhydrfOqE+TSMVNaq+xNfhNjcJZAFKqbg+1gzM4
         KXdpz+BlHpH8qtTJE+gvTlghOZCCwdpbxp/qgcJZeSsy9xwiK2IfPQxnMLW/8HYGVm5R
         ue26mvXWCtmV8MdvrT6oGK1cg+/iiMQQWPHESctVYbOWz2P+dcBDUsSWQiPElF3aQPIQ
         lgiGvJWCe1x+K1UHkb0g/BThXvdhPVpedEfR9SehAXZyb3zS6+db/AaUszvpYzaLDdiu
         Ha6tBZ44B2bKRs28zgak1cD+dQcGmssU0wVgTlu9UmpHQEeq2Ck5aq/KGvbrVG4exNZN
         K8Ug==
X-Gm-Message-State: ANoB5pmVPjvSQqBTDJ8hv8h6iN67C026kcikCVLBmA+GUXwlOYy+P9uR
	DK24mL2eVHQXMUL42EIHqy0=
X-Google-Smtp-Source: AA0mqf6lH+geem30YXh4j3JylRDO7Xnwj9KKyRgQ5ji2SWSZ3p4EdbWYR1ztnfx9vMq8YSIhnbsAyA==
X-Received: by 2002:a2e:908e:0:b0:277:515b:3dcd with SMTP id l14-20020a2e908e000000b00277515b3dcdmr2562461ljg.501.1668784943852;
        Fri, 18 Nov 2022 07:22:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ecf:0:b0:49a:b814:856d with SMTP id p15-20020ac24ecf000000b0049ab814856dls3984017lfr.1.-pod-prod-gmail;
 Fri, 18 Nov 2022 07:22:21 -0800 (PST)
X-Received: by 2002:a05:6512:39d4:b0:4b3:b6db:8cb5 with SMTP id k20-20020a05651239d400b004b3b6db8cb5mr2977896lfu.599.1668784941856;
        Fri, 18 Nov 2022 07:22:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668784941; cv=none;
        d=google.com; s=arc-20160816;
        b=I0je7g0ksWaxZJa56ksu4OG4Mow/tjl03qVT5yfRLA+GBxjdOIGzuJ5czneJXUmwjr
         9kJ3BVA3Xqgkp0fSiskorSge/TR9am+MiAAKCFG9HdViorsdoQb357EHzg5H7wspMfdd
         45Pgu7CEjsuasXuxZJh8OCNGXhAtp8XyKbVxyYkqiGhQ4UZ8mFxOFv9XwqxuICXCqOIc
         CngZc835a4qCvihaJPSpcwxVhEt4yo32S5Zv92x3NqTR5fQqzOBnPV0BYrR1oonDI4+7
         ZElOPSFL4eRmjXGI9+1kFhs4WVNUico0fMOXagCXAsWsbfafc47u/d86Zx4XGW2xmqw6
         YbFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=PXs9oQxTshLyON7VsLwg1Sxn4Bm1fEFFQRofp2aAizY=;
        b=HOx+xacuo6DFep9NvpdMfIFvG7q8MrA1W0fCwB+eFD3VwDVa6PeLLreCifkRBplnqO
         t4Y2D1ponWgRmMrw8kRC6CMBTIqV/IZ7068UWjiO0ywONZcgh2EU5W2Wu4lXRcGB87w9
         3g4hC/wYykrsuB9GmLbWlcu6H1txjCroz9THYL8VWsA2e2TScOehtVQqS5iUro58ximM
         LXdqkkhmHKW9nXqyDE+Y091INlsEKdmBndgPev3PbRF2X9uM3EV3R4xf0S3+4hvJ4rIk
         YvdfgWf0qKwFKmy2auCSWaRVKdtUBUuC0kDVT96glc58vYQwvjDkLxsNwS/MK3lAGsh3
         CMeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s8dI+I16;
       spf=pass (google.com: domain of 3lan3ywukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LaN3YwUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z17-20020a0565120c1100b004a273a44c4asi133671lfu.7.2022.11.18.07.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 07:22:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lan3ywukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g14-20020a056402090e00b0046790cd9082so3192760edz.21
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 07:22:21 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:4799:a943:410e:976])
 (user=elver job=sendgmr) by 2002:a05:6402:f11:b0:467:8813:cab5 with SMTP id
 i17-20020a0564020f1100b004678813cab5mr6512139eda.369.1668784941290; Fri, 18
 Nov 2022 07:22:21 -0800 (PST)
Date: Fri, 18 Nov 2022 16:22:16 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.1.584.g0f3c55d4c2-goog
Message-ID: <20221118152216.3914899-1-elver@google.com>
Subject: [PATCH] kfence: fix stack trace pruning
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Feng Tang <feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=s8dI+I16;       spf=pass
 (google.com: domain of 3lan3ywukcxqwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LaN3YwUKCXQWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Commit b14051352465 ("mm/sl[au]b: generalize kmalloc subsystem")
refactored large parts of the kmalloc subsystem, resulting in the stack
trace pruning logic done by KFENCE to no longer work.

While b14051352465 attempted to fix the situation by including
'__kmem_cache_free' in the list of functions KFENCE should skip through,
this only works when the compiler actually optimized the tail call from
kfree() to __kmem_cache_free() into a jump (and thus kfree() _not_
appearing in the full stack trace to begin with).

In some configurations, the compiler no longer optimizes the tail call
into a jump, and __kmem_cache_free() appears in the stack trace. This
means that the pruned stack trace shown by KFENCE would include kfree()
which is not intended - for example:

 | BUG: KFENCE: invalid free in kfree+0x7c/0x120
 |
 | Invalid free of 0xffff8883ed8fefe0 (in kfence-#126):
 |  kfree+0x7c/0x120
 |  test_double_free+0x116/0x1a9
 |  kunit_try_run_case+0x90/0xd0
 | [...]

Fix it by moving __kmem_cache_free() to the list of functions that may
be tail called by an allocator entry function, making the pruning logic
work in both the optimized and unoptimized tail call cases.

Fixes: b14051352465 ("mm/sl[au]b: generalize kmalloc subsystem")
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/report.c | 13 +++++++++----
 1 file changed, 9 insertions(+), 4 deletions(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 7e496856c2eb..46ecea18c4ca 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -75,18 +75,23 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
+		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
 		    !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
 			/*
-			 * In case of tail calls from any of the below
-			 * to any of the above.
+			 * In case of tail calls from any of the below to any of
+			 * the above, optimized by the compiler such that the
+			 * stack trace would omit the initial entry point below.
 			 */
 			fallback = skipnr + 1;
 		}
 
-		/* Also the *_bulk() variants by only checking prefixes. */
+		/*
+		 * The below list should only include the initial entry points
+		 * into the slab allocators. Includes the *_bulk() variants by
+		 * checking prefixes.
+		 */
 		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
-		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
 		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
 			goto found;
-- 
2.38.1.584.g0f3c55d4c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221118152216.3914899-1-elver%40google.com.
