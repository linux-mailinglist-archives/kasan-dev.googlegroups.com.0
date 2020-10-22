Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB4OY36AKGQERAVDOKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 94EFE295FBA
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:08 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 1sf874453pgd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372807; cv=pass;
        d=google.com; s=arc-20160816;
        b=GmlUZKcqOFFt4Voqbih1wikSMbpF2brpytJvENjZRT1ZZPLJqJ8Aq4O8jF2Aja661x
         K2b3m1T3oWiPu6rLietMJq6UuZ/h81S2bs9RbhhvN2Clk3+QLByekV++xkZhnnF2cV7U
         RobdpGlbPruO8jhhiL3397hKeJf/4Uysv9wL8bQ6EDoH3iAMz7rL4iWj73vSpx7wiLwS
         BfydsKRZ39SUuXu1a5E1QWq7y5j2rpW+zDXea4BxqxV07CqBXztm9vpXdZEUXkuKODR/
         S17on0C3RSqmVDXrJQj9ixBJ63LOhyztwzI0aJxltjMhUuEEo6Bd2TWRZxn5A9oEQyhZ
         6CnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qpoG5AidPYG2dvQRk3CpBpsCfz/1R9XA/KZF73B6lIY=;
        b=Zm8MHb42VWcx8L8DEgQqYXLMTpyp8MmoId7Uk8EL9LNrHY7TtJdjJlqR6vT2hngmcm
         JdiDmn7GCEPQl2PpQie4xKKwBZrqi3s7HRCkfN/PTgC0EXHb31u9rTjB3cxlKLoL2Tsp
         6RMAh3Kh4uk7L5JgMITk0YN9DyeX+2gd01yNRc+9hMu7LKXXqSpsLYwixKlQM5rnY/8S
         8oh8iXBpNvmHr1VFtFQ6JjS+VK+q1F8bCV5hMKLpAiO7HuB+qpuzQyaJIemAj1Q6+VjO
         FFJOQf3kteKOVRL1YDz5rS72U3PMfV9hzGxOGd3M198DeRsRI1fovxvrsNpemdgH6J/T
         mi6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tWtwnKyn;
       spf=pass (google.com: domain of 3byerxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BYeRXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qpoG5AidPYG2dvQRk3CpBpsCfz/1R9XA/KZF73B6lIY=;
        b=aAe67OdNFC96vuXNdN5qfHtIp6CQBqiEuYFI4mV+bIOMI54hhg7CSGxuKldNofS3Fb
         xv7VB2bwFwGMUSic7S891J0VQFDvFfQPyldhzfPsCG2KUsACEe6soIrkdXERUJT8Lqca
         wjD0V+opBOIeY2RrwY2U1bN/Lhh9CXZnPZ+r9UEC1kp2eEB/TB4fVo8bNhG7rC/3FyKU
         LfKpHjexIjb/65Ls8EWyzLatgt7JfFgpUKfF5y3dWfC1054Fw1znRt4fg4ONrJ7xsjkC
         LoFmPyRe0nEIXa2ywWwxBvy0aCaw4WcKkqO1Bg+KrMI31Y48lidBRTnzf0t8ORjAvSxb
         jmdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qpoG5AidPYG2dvQRk3CpBpsCfz/1R9XA/KZF73B6lIY=;
        b=oIFb3jgBg+C3dEGFEJORhoEpuFSpZpGqFrVASOw44t8WaZp6oUSGaBh3HaMmqYqSKQ
         DpVzU9FOyUwu5jMdp8KWlyd+UYCgkkhpoalRrandF8KIGiuHfUOiRJtNm91bjv3j5X0p
         00z+t4Xb728jTPdLHZlVwxhCnfZy+sP+99LIkM/bOd83A0WDGDqXj+YU0AihrYaIpUe0
         gxHnAvgeHWehQlthXK16Cj+dKVhAvf6UPOjqekQJA25hDecytkupyKNnkthhioNwRLd5
         fdzou5kU1JGEKqE/dtvkp2q5OzgOyK1XHF8b/i4S+LeTrKU+PTLukT2q3MbN5riQd5By
         HEnA==
X-Gm-Message-State: AOAM532aIz8rqnhScuBt+VNsy+r2nXJMmUqVN2By9SQjTHNiGoWAx8Do
	bJ+7FpO/8+1pdW51f201gCc=
X-Google-Smtp-Source: ABdhPJwKlNxkamxxqeDr7s2rAHLNzXLkHl1FhrUeWXBNcqSXInXNTkeuwuvqFqCRumBgxTPjhRlalA==
X-Received: by 2002:a17:90a:a58d:: with SMTP id b13mr2252769pjq.196.1603372807329;
        Thu, 22 Oct 2020 06:20:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee4b:: with SMTP id 11ls992763plo.8.gmail; Thu, 22
 Oct 2020 06:20:06 -0700 (PDT)
X-Received: by 2002:a17:902:6bc7:b029:d5:f149:f2e0 with SMTP id m7-20020a1709026bc7b02900d5f149f2e0mr2499729plt.34.1603372806049;
        Thu, 22 Oct 2020 06:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372806; cv=none;
        d=google.com; s=arc-20160816;
        b=B2552jM4Cp1qDXpLu8i3323w7OcZWIjZxGOJOvlmEpKdGU4mRdHyFK4OVm27Ql2UzX
         ci+JTkRJDcCFY3gkis1E7Np96QGvnbs7+AzUrbn5ciyqenSz/R9Ifyzi5Sj4STfaENO3
         Td4FT9KKNE6I1m2ezCOgflVPPEB8JiLXnT1aCyzx49SxeFKaL26Ry/Bbj6tUhRPXFhNG
         YpIyGLOjWYy+PtRX6Xp0O8gGAyx3iBVCnBAvB4CIgr02n9wanG3hWgQoupfBZlTdBk9q
         MKVTl076pJ1BLljUiE1RWeLce/DRpqy2k5UZS9oOeZIUNz3OxUVkSctDWHN1HSKzrFgE
         vKCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=82GpDRN2bzlSEUUIs0zjPg3hV7sJu2/XktKPfbK22J8=;
        b=dG6uE/qcSjBxcuJ9abOgAA6o4oMu+PDQuv3E9UjXcmN7SAnI7taUApodvM5E/kap5i
         s9jdF9FiDIwwK26i1gl+zAEZ+juHce50+ZO1Mque/uM4+d+pWglUJ2wdfrLb2vmArsjk
         YfFF/uJTxc7JJcBETIAAijMRxzXtA53dqe68yoVdSkdc0if9exl8uCz+lTEQhK+xkXXw
         Y191/rvuXJ7S6b3vLL7zIjyhw94zkJECK5gVKzCVDAw3aYmdPr0BEF54Ql0OqQ1WOHe/
         wihbcGqq5NxmWs5HxC3wdQkrfqakboCwyWv0C1WwA+DIEgD+dtmtLbwsN+fwFPqY+P12
         +C6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tWtwnKyn;
       spf=pass (google.com: domain of 3byerxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BYeRXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id np11si79672pjb.1.2020.10.22.06.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3byerxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id h12so982051qvk.22
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:20:06 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4ba8:: with SMTP id
 i8mr2334507qvw.59.1603372805117; Thu, 22 Oct 2020 06:20:05 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:09 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <f7b6b3b784e80d3ff82012295503def6164be657.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 17/21] kasan: simplify kasan_poison_kfree
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tWtwnKyn;       spf=pass
 (google.com: domain of 3byerxwokcvw4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3BYeRXwoKCVw4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

kasan_poison_kfree() is currently only called for mempool allocations
that are backed by either kmem_cache_alloc() or kmalloc(). Therefore, the
page passed to kasan_poison_kfree() is always PageSlab() and there's no
need to do the check.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/If31f88726745da8744c6bea96fb32584e6c2778c
---
 mm/kasan/common.c | 11 +----------
 1 file changed, 1 insertion(+), 10 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a581937c2a44..b82dbae0c5d6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -441,16 +441,7 @@ void __kasan_poison_kfree(void *ptr, unsigned long ip)
 	struct page *page;
 
 	page = virt_to_head_page(ptr);
-
-	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
-			return;
-		}
-		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
-	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
-	}
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
 }
 
 void __kasan_kfree_large(void *ptr, unsigned long ip)
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f7b6b3b784e80d3ff82012295503def6164be657.1603372719.git.andreyknvl%40google.com.
