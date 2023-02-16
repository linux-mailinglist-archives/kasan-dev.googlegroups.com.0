Return-Path: <kasan-dev+bncBD52JJ7JXILRBC5DW6PQMGQERBGDRGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id E36BE698D5A
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 07:47:41 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id i14-20020a17090aee8e00b00233f1a535e0sf568407pjz.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 22:47:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676530060; cv=pass;
        d=google.com; s=arc-20160816;
        b=q/b5PLGWRVOyX9nn6e/pBwrCpXrQmNHpK+Yd+vpb5LMl/Qq/Oi09LFn+hu31oPyuaU
         5WBxWILM7xwvMvy/BBzbDQ9vEcG3s8ieR3Pi9nnz5i9l6Y+yXypbVGf87M+IYnLdwvbB
         jMeDvv8QuMMwAZvC2uD7vyDwTNFYqQgsm4H4p8YvdScakBC+8QLxvGEhOPszCBhiSqMK
         1X79+ZbZsPRBwWWKWswy0BO67yyYEwTBvx/DPwW/n+YwMzAikA5iluD5L+e0dJNk0QTQ
         pNf64mS9igCFCV4AVx6RLepwyBf20kMftB9SvgSUB2sa6kxI8IeyrJwhCzkYdiaKA3Ss
         xedw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=kgpAIilGbjSsyy5FKa7VJrzLktr1gedZaqZrDRUXtJ0=;
        b=cWrFxM4yR4QtV4r0QBL8EReK1TaTdfzmp+yOg44gVT6mWkf+BRCdPYzTJ4gfZ3aDJC
         3fnazc1vVD4WcgzOJaGudVDheKEfEzCvnyO1Ss5ML6TXzo3eiFvVMinc7mzAgg1MOWHu
         VO11E96GPdKIrHKKoTpudMrH19KESz7qx+rgC4Qqrh8qigFMkjGZ3SZXZoNgVgWGp2Rd
         dFs3F2ZEEj6nFWluf15gT7jZimq2GxeQY65WefJh53pauiaFIkIt41hna1LXNqG4dQn1
         qyBf86TdoUiEZtYm5HB+P50khKOJ9N0jpsZ+ZaILFE1DbhhSwJwmyuSeOmyvVDQ5ZqRY
         gIlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="OHpT13/S";
       spf=pass (google.com: domain of 3idhtywmkcqozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3idHtYwMKCQozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676530060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kgpAIilGbjSsyy5FKa7VJrzLktr1gedZaqZrDRUXtJ0=;
        b=jCg3k/cphsJ44+UZEHv5VdVOccMbsF4edhXcInp5qoH0CODH2LCt/DM51CnxAnEIsJ
         itNwLNkeiaeKu5KfmMlbGOmJ1AT23Q5t/42YDRNmZOP+VgOnlDiUq76vyrEZs0tIjQ3W
         VjcPHByP6wD1c/S9UiRf9dpAqkMgH9MlyuWAZeAL1mf3eAtxEK4lRKpuDRSCv/Lj/HSL
         0Mbk/DHgCviJtaNr3suRXYdRLK9sNEbTi9sHS4y7fULPx3hdl4xZkZw7EQeP1zKqHAfj
         r46A74JxMRNFMTTqQMx8O9Vltk5lLnms32Sayvy5kPJbUVkspprjRk5GcESER1Bn/RpF
         uu+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676530060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kgpAIilGbjSsyy5FKa7VJrzLktr1gedZaqZrDRUXtJ0=;
        b=W5CpyYRxb6Yer4gxE0U994cAlEj4Xm5M1bGgGAYAu+vssHvJa2b70MD6T8KK4cFTx8
         bkHLzWWpxxa8GHM6oKU+AnacuPbB1g7//RryTzUDWAYaO7Oiz4GoMcTm9xgzXSBEECal
         rblPoT3rpH+5QArpC/CIOszJAppssVLLZzTS3hBVjOTlFoLY+WY30DlijBjN8r2alw6i
         BgK0XnFuSK9e/wLygGIDN8OqGae+t9CjuWS0wXrw76MF8BzA4U1q7v0dABTnzPcED/hx
         OpdchULRjrTea3a0t+2klJHqlNhkmSAAGZQtH9WIu97w4geVQAzRTugw3N8DRh2+EMf/
         Uixg==
X-Gm-Message-State: AO0yUKX5ZMgSmoYJCbVUZSjxCFqqE8ONZ6ijK2UdarY1Rq3P6qI65hD2
	bUD0jYvNOEHxDufAmTWfLT0=
X-Google-Smtp-Source: AK7set9oTYrwzkN1cjkthKj9DH/yk0WRcBZOndizQWuVhaMUDKTWpiN8cvPDohYTjFTOKAgo1T3KOw==
X-Received: by 2002:a17:902:7602:b0:19a:7fe0:3a29 with SMTP id k2-20020a170902760200b0019a7fe03a29mr1042932pll.17.1676530059753;
        Wed, 15 Feb 2023 22:47:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e00e:b0:234:a618:558a with SMTP id
 u14-20020a17090ae00e00b00234a618558als171632pjy.1.-pod-control-gmail; Wed, 15
 Feb 2023 22:47:39 -0800 (PST)
X-Received: by 2002:a17:90b:164b:b0:233:ccd2:40a5 with SMTP id il11-20020a17090b164b00b00233ccd240a5mr5988832pjb.32.1676530059009;
        Wed, 15 Feb 2023 22:47:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676530058; cv=none;
        d=google.com; s=arc-20160816;
        b=VUm6dGpyK+dnntcuUOijhnXsWONB532yC4ujcwpJ8twpiq7Ed3VGpAnC6s4C73x35X
         LryaFdc52hY/2mtn8zym8QIEKF/rAF0EnulQHg6DFZlryhsukD+AVIKMrGVzSmJxAIoM
         Hk/DB6PfUr6GlXSrHW+HGtnSZk59R/zx2K3xvZ7r8uu3dqAlMfVLLMJ59ZCHKeZ/z2pR
         veRYevGqFXAf8PoUPmCabG/pxaWtgKzK7rpE3TYDlfoxG1/o5+uofD232UOjd1TTBb8b
         vaMD8fE1kmiWMilQ1dtVDM/NSBGGxjniif1VUmbLGLx15cbxIPAGhe6RNrYhc8qlR8bw
         StUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=U1KTvO9eh7af24NgSabBS4dGCCNbjIjt0zmjrEHKiTs=;
        b=bV3voVQCy6zmA+qfhXn90Gc7B/vqIxy39I5iNVcBVyQQm4wMx11Kfn/XRMmWTzoLrv
         PZBpuj6CqDeHjRlqsC/xYrspjiymyYzejtBly5pxReUmNjzpGjtixG1eEUACgXspyWUr
         9E0eda17Dz0vZpuwpb/+poWWWKvEpTG4Z/wGlClN9VpmQERhLUWgw7HEN35KLuRPx5OL
         8KbvxgHn0qyqw3p8OER5vAxFjj0NVg7h3V3yw1SBLOzxTTsZxCpi4LJuwTP+lPg0AFzR
         QcLcQEU9Gqv+uiul1nPgof9qDOZAwBWxjglk8FgkNFMlntPI+Q05O6MFW/Axti5eVn2b
         icMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="OHpT13/S";
       spf=pass (google.com: domain of 3idhtywmkcqozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3idHtYwMKCQozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id qi16-20020a17090b275000b00233ba2c16a0si300372pjb.2.2023.02.15.22.47.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Feb 2023 22:47:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3idhtywmkcqozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-517f8be4b00so10694217b3.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Feb 2023 22:47:38 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:9dcb:3224:f941:1aad])
 (user=pcc job=sendgmr) by 2002:a05:6902:13c6:b0:8da:3163:224 with SMTP id
 y6-20020a05690213c600b008da31630224mr9ybu.0.1676530057864; Wed, 15 Feb 2023
 22:47:37 -0800 (PST)
Date: Wed, 15 Feb 2023 22:47:26 -0800
Message-Id: <20230216064726.2724268-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.581.gbfd45094c4-goog
Subject: [PATCH] kasan: call clear_page with a match-all tag instead of
 changing page tag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="OHpT13/S";       spf=pass
 (google.com: domain of 3idhtywmkcqozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3idHtYwMKCQozmmqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Instead of changing the page's tag solely in order to obtain a pointer
with a match-all tag and then changing it back again, just convert the
pointer that we get from kmap_atomic() into one with a match-all tag
before passing it to clear_page().

On a certain microarchitecture, this has been observed to cause a
measurable improvement in microbenchmark performance, presumably as a
result of being able to avoid the atomic operations on the page tag.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711
---
 include/linux/highmem.h | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 44242268f53b..bbfa546dd602 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -245,12 +245,10 @@ static inline void clear_highpage(struct page *page)
 
 static inline void clear_highpage_kasan_tagged(struct page *page)
 {
-	u8 tag;
+	void *kaddr = kmap_atomic(page);
 
-	tag = page_kasan_tag(page);
-	page_kasan_tag_reset(page);
-	clear_highpage(page);
-	page_kasan_tag_set(page, tag);
+	clear_page(kasan_reset_tag(kaddr));
+	kunmap_atomic(kaddr);
 }
 
 #ifndef __HAVE_ARCH_TAG_CLEAR_HIGHPAGE
-- 
2.39.1.581.gbfd45094c4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230216064726.2724268-1-pcc%40google.com.
