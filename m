Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYENY36AKGQE75WVJWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D15295FA6
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:29 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id r4sf857628pgl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372768; cv=pass;
        d=google.com; s=arc-20160816;
        b=h0nLB+NBa3Fz1Y8Fs/8QlUpmZdmb38yBbjaNNn4GbUv8QLSc0bqbbntmOFvaaYOKTy
         C3W30cJL17OzebemE8Om/d12yXqc8UMfAof1sVgu/zINArJs2AO6o1A2nmLZ9m6gkiGr
         YSstAsubOSUpRagRCesZxCEioGcnj6WXqcg5sVx4y+ZZ/toH4d4cWyN6fnIrsldhDZi8
         Y+xY/EVTjIJeIqz09pXPuRDz4gEvPj9Z6MvrDhurkjR0SpLWb7p/9esLKuC90DgWYgPS
         Q3Bhpi5srguVCIfCHIKgeLlYQjZ/Z7DWlJTBOPHVzGj5pl9cnX44i9EUs0NAeqO9hx3c
         NC/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=igAsUbJbjtuQb3NcmVq/tE9tenB4VWXaJ9gu+UHe2U4=;
        b=EGrXgUkX4ZYLzTKgCC4hmQnayVuvxbBmZDVtyykGudpUFSo5Np//w2MR3ekuHgT7yb
         whPrze92JGwpbUIAsoWJfC58STKEKgQIoa1kJRB6tLUHvTJAy8vxeyn29c1/OZG5YAZY
         fR6dfZ/6nUPrktVhmKKAr54oTOacGprptbLYYbn2H5WBWhQ4I3yG4x1fVXip3jtujzuF
         cJ9fTBhbgLEgXY8Ms16DobGrleBHrvyJSG3Q+XDOgOnw79U1B7K6BiFbLvOpbaEraQ1a
         pxIn6EyivDHAkarGIiOLce2l0vgOMPG+i+usAUFQOD6S6VMcLZynAt3/iKTQHwZBWZN3
         lKwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYz3Uex6;
       spf=pass (google.com: domain of 33oarxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=33oaRXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=igAsUbJbjtuQb3NcmVq/tE9tenB4VWXaJ9gu+UHe2U4=;
        b=SW1krFsWDsf5qLOkFK9ehTdStzlI1DNpbihyAw1i0rgxn+wehAlRq2i0Yje/soD+hQ
         V9HkHj98Mb2pMH2flzfdNl63Y0tuAOd8RIZa3RhsoKKjyozDgTeSDgbx0Zt65MDqX3K2
         yNB02ZuEkszGqNakBOdv8pZQsKsk3LdmY1Sf7/o01CKZOzPWzqYvgPM8esX2NxREnf8v
         25f2yp+ADMZnNxV+yHyFMFDPMrPA6jx/QYOjAgidVxayowrTSZHHdgPYr9m1Ju06a/OB
         nScU3cOocHFYJ19cNPSazVV91iBVF6aXsTfkbqsZ/O8mSuinyWK08cYxdwmTL5hmBYuW
         srcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=igAsUbJbjtuQb3NcmVq/tE9tenB4VWXaJ9gu+UHe2U4=;
        b=ElHOmy/ghBKUsMdJf9JjhSIfOT+qopBkHL5AFZB7hkliJYPxVPxypYpo4NgsNWt373
         t1JtKRY0s7GrhNc21XI8anIATBVzKq8DpWf+IHgqz+fa+9h+j72ydjIxnN0h/OQVFB/2
         betNJSAHgnsspd6NOq8N9cX/FX5MFhKNlFGILNofNG39m3QAlHzkVOHJtk3cstQtq1DO
         IFjhvnPdyTXQ5/sT35jekWuA5d5Pm/uimICFLeM9BUGyjoOximT8GMomGAdVHPduOKlk
         UnvpjxoaBe272D7Gw0sT/+67ly4iAheVQPcBmIH1nlZcswxyfQvZXaIBM84Oxyr6EVGh
         ihvQ==
X-Gm-Message-State: AOAM533mJDJE5NiIwspRBYCUXu95n8YE3pTaK4FjoIEMAS4XvwKQIvE8
	dE/3LDvE48GmAjhcr/e8SEI=
X-Google-Smtp-Source: ABdhPJwWjg2No+YlmP4xRBhFthA1FiIVesDXZbE3GJ3bLMdcWuk0Uf2+5q+iqDsOrORtKLtOJtx5XQ==
X-Received: by 2002:aa7:87c7:0:b029:155:f258:99ca with SMTP id i7-20020aa787c70000b0290155f25899camr2561817pfo.68.1603372768264;
        Thu, 22 Oct 2020 06:19:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:562:: with SMTP id 89ls998137plf.4.gmail; Thu, 22
 Oct 2020 06:19:27 -0700 (PDT)
X-Received: by 2002:a17:90a:f187:: with SMTP id bv7mr2378911pjb.198.1603372767699;
        Thu, 22 Oct 2020 06:19:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372767; cv=none;
        d=google.com; s=arc-20160816;
        b=amcwUvG6hO7PzURRuPGdBo85m1JcJcBDyBIJbiLnuNZWLBDDlZ35l15uuXJzuaqSKu
         fzVFYDTOLSsgjSlWTZSQ7OMUWOcoT9M2dNbbzO5dPBQUWO1ALdO6w46ZCV9dPlrpI4Eg
         Cai+UPQlmrVmNs/dc7nffrL8ibHeb3JYtzXUUw7Ji69CicMZo+vgF2gfE0INLLkWHDcN
         3J5mMtuuDQ6etrnrsqKOYNbpZ8Gi3BK4TL0WnjnrpD8uwgyo6gsrQofejbY8Hzrfu3yC
         BMJlX6AY8iJ9dE3CiNqOjSHsbS5SYF7Ieb8X2b5SaqG1AqWTFPyZ6Gy9IQFvgVswqGVI
         gJow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=QY0XewM9lnHnRQ+vj0Qh7qias3TYU7mjlYARUV896zo=;
        b=HTiKyszJkgXHjloAnMKWb5U39ib/CLKWegQ8iJKpbSqRyVJf6ZM+95hWnVkD1L3YW8
         MKT0x+VyjiafobT8s0pQovQD5JcNfHR59mBr7+Bs4QmvY016tyfmWWT8F+gTDzgPY4yp
         +J4kngDKkKg4e9HSICVHxjk4veNSyevUhgytznQh5HRn1dXKrKi6gBwI+bLW7XzPK4Hb
         bXtuVGF4MunvaK4MuYUmAJAspOCNWwXY9GSHoMDLZ5wd+8dpXIhceNL/sW6nI0Q+0sNP
         3HTeZLOxUyejs4mWYJ0eJYuaZaVFyTxM8KlQQBWzHzejPGs3svJ1FyJeu5dHCIMBb0gR
         E7xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYz3Uex6;
       spf=pass (google.com: domain of 33oarxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=33oaRXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id v24si110002plo.1.2020.10.22.06.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33oarxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id c3so1009208qvj.4
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:27 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:184c:: with SMTP id
 d12mr2385924qvy.11.1603372766736; Thu, 22 Oct 2020 06:19:26 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:53 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <eaeb053a84e82badf1ade6cf7f9caf6737fcd229.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 01/21] kasan: simplify quarantine_put call site
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
 header.i=@google.com header.s=20161025 header.b=OYz3Uex6;       spf=pass
 (google.com: domain of 33oarxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=33oaRXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2bb0ef6da6bd..5712c66c11c1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 6850308c798a..5c0116c70579 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eaeb053a84e82badf1ade6cf7f9caf6737fcd229.1603372719.git.andreyknvl%40google.com.
