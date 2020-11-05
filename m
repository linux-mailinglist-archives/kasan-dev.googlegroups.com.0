Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKUCRX6QKGQEV5DNXQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 865AE2A7373
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:54 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id a73sf17164pge.15
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534571; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5evOO2mSZw7AXPUSC5scKdG1GPWo6zSR/ZMJ4L8ThnZtwmQmzSZo0YFDvzGh/whpV
         aRP5Ey8Xa74uamC8h08bwQWX8P7g9+4r1upEdSIZmGybLgnU6KZunb+QwnRHEaVzvttz
         Y/am2QPyWUSeBz5npJjc/aPUt47Xog1t2rUxJBeDlJ1dGAUIjAI4sgOzRWKIQuWRqA8r
         9HxOX+F14dKhqix5kJmijzzPSkv+uj4Kx7Knx2HpLu3eX6RRkx2dsy/c39qmZ5JOalUJ
         YR9c8rlwiUsEIE1736AR3OZWiG5QBJkdTe8KjNxKfxfqMKT55SsVCAyhZnNSdfv1KPpm
         ZcCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MkRTqK9A/76LcflwKv+br5AK9tCvfGPs32rdbKHRpCU=;
        b=nCpGf+dTuYkf4YdA7W3++tqfpjw8nwHToUuIRaHjXAadYV8BCbU326GijuGObwGpyi
         GdbUzBkNYwG/qFj6h2UgcJm5Qz4+p0rG324Sd61fIcKV1MVfIhW7PQi2mPQIbFsqk3MR
         XuctMT9OtMD/zND2DPgQ3Fp80uJL6rliE0p+vvO2zVg4i0TDUES6QXNiY7rnlwCqdF3H
         Gtq5lFqwCE/aZoPuprDCc0O3GFCGMEUP7zqtTfmES4wJzVeS5dCn/GBfIkG934jh3kEq
         4WXyjJ25ZxtXHMCL2b8NevUz+QcBT3yuT0RsWj1d+WVG7o7Gg264vuTbEI9wO+4oii6m
         D5hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EIGseFkU;
       spf=pass (google.com: domain of 3kugjxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KUGjXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MkRTqK9A/76LcflwKv+br5AK9tCvfGPs32rdbKHRpCU=;
        b=UEV6DeNB1Ukx91gPLNugtbupRmXFmOVbko0+FWxbU4gRckfXmqzfbbty2AKUXHEaK2
         1qzOYYNyp70IDw/SQzHSsGGh4wrPtgJtWMsznrRDbvXjU6qGGwoAABMElPP/eSGpKdSC
         mpwTOX/ITOgt7i1Lmx5rvm3/Y4YJ6ROAetHcpZelCyxt4pBq/db0iJ3Pu0VCjS6fhOpx
         f20QvpALklLo8MGgpjomCSSzE9YBu2Y23D+bogIg/p6Dattmi6HKnvzU0dtduQg2U7Xw
         DXk/xGJv0hgJuNzx7Fhpv2wKMqysbKbHGxsSrjUtqtVkgCW4/0KyGlSVqKAH4R3Vhg+8
         xpeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MkRTqK9A/76LcflwKv+br5AK9tCvfGPs32rdbKHRpCU=;
        b=HRPpXSZ3YIBCsg3O7OqClVAjx23jkAFXAZqSdGWbjNn1V8rLHUCHANdD20x/PrloJq
         Te2iTapOnXUcMrgvZlAL/W6NCNdg/A9AU6/dDvYJe6QXNT9ENQX5E2zwYkAgKhK7ZuUV
         RQ/jifpvRGjZ09x07bwoUc6knmId7VfzLTV85XjmRotRoCMzFkevhtD6yjBvxzPLeIC1
         Q5SXNd2vGzMW89bg/Z66oEy8Wrg2qGiibNILpNCGHtcdztd9Qi0oXMyY6YFXSRRhnyMZ
         NLWolOKsy3Uu0+/4/DYXY8xL7KILCbLQwqLP4f/XJjKSGioCcaldRBjhVoOz6kU4YwY3
         Gt4w==
X-Gm-Message-State: AOAM533wiP1Esb69jUufqwfh4V4YqabXDJWAA5ubgbDFS6VHG+k4drVf
	7Q8+Rsg8aGBlQsu7TareYNI=
X-Google-Smtp-Source: ABdhPJxNtmjrLHQnoytOR4Jaiu0s985aQ9/b0gXzAbVALj3p18sLIDEcmkaj99ZwELjFzyGCUODKrw==
X-Received: by 2002:a17:90a:b393:: with SMTP id e19mr33219pjr.40.1604534570968;
        Wed, 04 Nov 2020 16:02:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b093:: with SMTP id p19ls1715322plr.2.gmail; Wed, 04
 Nov 2020 16:02:50 -0800 (PST)
X-Received: by 2002:a17:90a:1102:: with SMTP id d2mr16687pja.178.1604534570391;
        Wed, 04 Nov 2020 16:02:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534570; cv=none;
        d=google.com; s=arc-20160816;
        b=BIVX7yLvVB5agHnDopqj1IDU0uuWahQzafYRp/AcZ1kaqL3goLKl2bzAtUVXsWahcX
         pTc8p70EmZRWuUlEblpE6/bzymASHEtLHKHMcGA+N+avf17DMg4kwIWTjxiAmdl+4v9x
         YptUK9kJ3xLBsLUsLMvTU4z4XFgAVvlWw50pvppzbGL6d4cNJiIre5o5K5FBjznsP9EW
         6U0jTEUrGg4HNiFy5sZsjTuE9c0LWOxj26eKltUYdz4P4Xxrg933z8R/CVNOmh3Vp3Gx
         xhtbGIaV71BS4h6CjqEWGEmEK+sRYGyeC9Tmf2Nnq1ss8DSMpx6X9DNzvLb5zJJ4Dm68
         WPrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JW8D6ibToVOb7LpAkCihsputAW6li7gT66iFpWFJlB0=;
        b=IebGR0Amn4Hw2A4XprLVe+//EcdZ0a13ROaa06/hY58+WdighX6SXiTQUUGikPJeTm
         pVBvz0yPOoh5ZWyoaw4oUScD6eMi+s9HmoZTzqZCt3p3wWNHoW2IqKAnumY4ZakIGNTr
         y7PC/ZpWLcyZh2M5Stc8akREq4fjNOQnRkBgfBdQ2cguXfRPAyFuvxYt1S7wkyFxNVle
         /R9F9xIJzkYTEQwYnphfKXyJKBqYXdzxfqy9eZgJE9MG2/9NM4FmuE8RQySPE3lEuMHA
         Fg68ZTmniXNpAZ2Pr8HUih34LIrzAlUTtgGr64o7TtO4fu9oKUs+UFXFJQKzCCBmz0Ga
         MpyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EIGseFkU;
       spf=pass (google.com: domain of 3kugjxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KUGjXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p4si1020pjo.1.2020.11.04.16.02.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kugjxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id j2so479397ybb.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:48c:: with SMTP id
 134mr48783ybe.158.1604534569629; Wed, 04 Nov 2020 16:02:49 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:16 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <f5a46b4c122fb08bbe2fe25d91165e8d7aa232a7.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 06/20] kasan: remove __kasan_unpoison_stack
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EIGseFkU;       spf=pass
 (google.com: domain of 3kugjxwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3KUGjXwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

There's no need for __kasan_unpoison_stack() helper, as it's only
currently used in a single place. Removing it also removes unneeded
arithmetic.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Ie5ba549d445292fe629b4a96735e4034957bcc50
---
 mm/kasan/common.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a3e67d49b893..9008fc6b0810 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -59,18 +59,12 @@ void kasan_disable_current(void)
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #if CONFIG_KASAN_STACK
-static void __kasan_unpoison_stack(struct task_struct *task, const void *sp)
-{
-	void *base = task_stack_page(task);
-	size_t size = sp - base;
-
-	kasan_unpoison_memory(base, size);
-}
-
 /* Unpoison the entire stack for a task. */
 void kasan_unpoison_task_stack(struct task_struct *task)
 {
-	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
+	void *base = task_stack_page(task);
+
+	kasan_unpoison_memory(base, THREAD_SIZE);
 }
 
 /* Unpoison the stack for the current task beyond a watermark sp value. */
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f5a46b4c122fb08bbe2fe25d91165e8d7aa232a7.1604534322.git.andreyknvl%40google.com.
