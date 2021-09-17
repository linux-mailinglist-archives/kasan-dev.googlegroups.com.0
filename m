Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIHOSGFAMGQEIGQ4MHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E49C840F682
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 13:08:16 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id z6-20020a50cd06000000b003d2c2e38f1fsf8662600edi.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 04:08:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631876896; cv=pass;
        d=google.com; s=arc-20160816;
        b=kkU58x00QgZkdsWxpUrXoZ7YWnUowe+1nc34BwOB+pdLf32idsDnoELuaRUsSC+86z
         1zhvvZBq4SlkJNFpwAx3OnaCiUWsltU/dVl+T0l8nZdd2QzP9Wkx7Vw4W2Dg6+AymHah
         FKo/8Wdh4bKYfen0zJjDzSPNCA0MnuPo45z1mbiXp85bPanC3YD+NBdUhvQoBrmXbBLL
         d6ZeTm9K+/u6hMVD1qxeMTrSPJKf2FBDafvZoRVzTPI6r2Pqpk+BIW7SoT2x9ACkOtrg
         oXCpoeKIC9afwLhJQz8YObcc8S/umzeL9221vtf2GKNPraHhXXoEQgscOpyhQbS53Bun
         i2cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HbbR2ql4rAX4qCFmyVtHMu9epptrxy+cVTgQrluwOoU=;
        b=zkxJonuPiAFnGuMoKj9DapB8LNHVZyV68+0PkE2fB+r7t4MRA3O5equF9F5wDG2skc
         wax2XmW7R3IEBlccvkh7lsoCcv+oLThyIBlL0ONXFaLgIqVK9sGyqYb/XLzilrB6KH3H
         zI6q86e0V+wAL9pVFZmyZ1RoS9555RZLIH67k+Suvo3xGjQ/KZAmvJVW/z7mzG8FHMHG
         CI/vDkbUNjgP13IoEBRaZgOvYTls8c9tegozenVvKPkWvAcWNcr4QFEY2cW+l3LyI7vH
         1FN3pl4OQH9JFcZPXK0l18SGQdcmHm0wPOEHtNuU/3wPm3F0a9Hs6Dw/MFeqVcQbhnLb
         Imeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HKCkuYw5;
       spf=pass (google.com: domain of 3h3deyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3dEYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HbbR2ql4rAX4qCFmyVtHMu9epptrxy+cVTgQrluwOoU=;
        b=cixvE5LDH5vJlhS+2Cs5w9kN9/0qMEubM0/wnrQ1c1cftYuh2ab3x0ePtQO/hHYb9N
         aXMILPwaDZrw/azZyMXjTKSu8fCFjjMIdFMIVioFEeqSkKW6KwM4o3FVdF96NWF1cT1A
         N/ukTivZz1vXTfx47onmTnSLlEER883FlJEhlp7xmLjeUpVaJPvRoVYctj04Rs1tuIk9
         uTVM00gQ+j00c0aZp7SzlUlih16DZzocUYtyQ1SA/U+B/4WI0buDD7H7C15tsN0MML2w
         mjf2rLHjbZACIuRhF5/SrdLcdLHgPn0y+VeO/qayST6IPRRXkv4R3BkmM4fMvzAeZ10r
         3JDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HbbR2ql4rAX4qCFmyVtHMu9epptrxy+cVTgQrluwOoU=;
        b=KvO4daqNjVuZQlfzD845sOWGwSBDI09WMLN2fb2h8hJyyXh7XR79RBT/YLc5WOFgTX
         /nCov1dp2VToYuc26sps8U4cKLPMeQoe7dDMEFh+6LWtpeMRnG5ba94xobf/T3agS4Zo
         hrsI6PWLwY4LNz4OfXHQ7XEBgXJx3KXmsh5meWbaWwWlQf/qwnDUqe7EVbGIxJZd5LEa
         K/7nHqnYIKI+RePQ8/cC2GKwLyuGgnU8lpyP3fqr0LcDVUAV74HmRRoSmWztwMLSORci
         zGzPNMkcfKYwQiN6o+C3iDuhNjEl7JJo/yJXZqpKDdJi8F2fryeOHLvX626fC5iS6qum
         gz4w==
X-Gm-Message-State: AOAM530oogn68k4yza5FDTANUQFelGqnclME9XVwuU+PLnAxMa0rFTVT
	f1kCgJyJj+1PD50lm6XGQt4=
X-Google-Smtp-Source: ABdhPJwUDCNeCreZVFwvSpoJJb9hOAW5Indm+QPUCMEfksgDYVU26cCWQtml9QJeAmV6RBonJ3XrTQ==
X-Received: by 2002:aa7:c617:: with SMTP id h23mr11708685edq.357.1631876896658;
        Fri, 17 Sep 2021 04:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3597:: with SMTP id o23ls3226357ejb.8.gmail; Fri, 17
 Sep 2021 04:08:15 -0700 (PDT)
X-Received: by 2002:a17:906:9882:: with SMTP id zc2mr11488631ejb.41.1631876895600;
        Fri, 17 Sep 2021 04:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631876895; cv=none;
        d=google.com; s=arc-20160816;
        b=WxXKRuY4D3p/weH7f9cpyxXibpzW2fftPYVSXj0jkaOGgL3m8RGZorppozCjDdhbnN
         PrtZsQDv7LzkM8e1TzcreL1tdy8OpgiQUTnZ8MUpqtCWKgmf6TiW1sbHDY6VsytCs1eh
         2fMFXzBy88QE+BpU9zXUYrCn4Z4RBQ/r8CXjOUHN55YloLMy+Yjao7sk6MegWmY31uoo
         rpe5zNDyYRECf8iwrbqFlcyVLzfkmqCbhztw61Cl6fAfLIzMP38L1QOG/9iqWEEDz919
         y2En0NvXnzIND6Xoi9vGMX5kI/NYU1LSzyEtBr/rsaTWU9WgEXAe9zd7jRo1LjTAcjLx
         9nbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vzNr90124HBGMksCA+v8zEh8chsocOdGVYWBleMT7ko=;
        b=gxMnufuGAmT1ALcaYpBJd0ctgqmtqWK9j1eSpQaVkX6ZAOtk4OBI+TRWzg+LMHk096
         p5qJQZX/2oK1DF/VuPwXadgA1LRYD793NMTyTr3n1UNE5AZ+2DJPEE/yeRzdeTkAHmAl
         BKEYNIh26O1Boqgqv3UEwjZaGHZGuW7mcU1rxP2MoR4uJlEbOqAroRHMtKfGKOoLSY0y
         mo9Tds2olpZ0gDS5NWkHmhQhrGkBJV7GxgMK3RxHiei7UZQsf9hctUhhDP6oFdr11JzG
         lFu/Y23sS3KdsxleLMog+xf15wJ9LqA02yJjmX45UFN8WyZLkY2yU15tHB1s3ISUHIz8
         QLKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HKCkuYw5;
       spf=pass (google.com: domain of 3h3deyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3dEYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v9si576735edl.0.2021.09.17.04.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 04:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h3deyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id g18-20020a1c4e12000000b002fa970d2d8dso1657008wmh.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 04:08:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1a57:84a3:9bae:8070])
 (user=elver job=sendgmr) by 2002:a1c:3845:: with SMTP id f66mr9628773wma.63.1631876895324;
 Fri, 17 Sep 2021 04:08:15 -0700 (PDT)
Date: Fri, 17 Sep 2021 13:07:56 +0200
In-Reply-To: <20210917110756.1121272-1-elver@google.com>
Message-Id: <20210917110756.1121272-3-elver@google.com>
Mime-Version: 1.0
References: <20210917110756.1121272-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH 3/3] kfence: add note to documentation about skipping covered allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HKCkuYw5;       spf=pass
 (google.com: domain of 3h3deyqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3H3dEYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Add a note briefly mentioning the new policy about "skipping currently
covered allocations if pool close to full." Since this has a notable
impact on KFENCE's bug-detection ability on systems with large uptimes,
it is worth pointing out the feature.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 0fbe3308bf37..e698234999d6 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -269,6 +269,14 @@ tail of KFENCE's freelist, so that the least recently freed objects are reused
 first, and the chances of detecting use-after-frees of recently freed objects
 is increased.
 
+If pool utilization reaches 75% or above, to reduce the probability of the pool
+containing ~100% allocated objects yet ensure diverse coverage of allocations,
+KFENCE limits currently covered allocations of the same source from further
+filling up the pool. A side-effect is that this also limits frequent long-lived
+allocations of the same source filling up the pool permanently, thereby
+reducing the risk of the pool becoming full and the sampled allocation rate
+dropping to zero.
+
 Interface
 ---------
 
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210917110756.1121272-3-elver%40google.com.
