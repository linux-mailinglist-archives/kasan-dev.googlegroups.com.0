Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNFEVT6QKGQEBAOQDLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 607262AE323
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:37 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id gt7sf25030ejb.23
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046837; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnkfq77+oJaQL4pHnRCvuTekRNHZ3yJsd6Jigpg7gfBpUchhHkE8rLg5onnbUj8+o/
         9/KcG1qCJcjyJzQtsGfeiGm6g/pgnpZIaMvfg4UhL65d58FlDy7aZW87xpvVAfJRvPbD
         FUjrr7l7voY11MCbnjbJ4Nl1s+EupyUZ9ACFaGVbibq10KFgPY1am5QifUwDLLzmSChP
         Tm91gIkl0zqEvLCJNKi3JGnkjzX8vVuXgjdZqIdbXHUVq4244mAXyXdz08H2t7iNNMpF
         oejkwOBWaP5IgcsNzjIUL6QqQQXgflDiDRghOLZ1fA86YU3REIyV13Eb4gIXcvODIIbR
         U2+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=uxvSNEsuUomeQ5403P6NxrUoDlNkRyFWNXmsCn8nM50=;
        b=irfgtzJctWsaLamfFEX0KzkkUQt8ruYKQs6uCmrrahj3YFwd408UpjUs+2F3yB8AHq
         1xqJsJUkVp6FcK6IKDNwxJiIaqf9+gA9dU3qsJYHzVuIZkISeFoCILgDEz2MYKEr2Bi6
         8pDjtIImx5gUmBSK4/ou7Rf5c1OP+hWCmj0FZMLqzpuJS+jV7AYPpUETrwVJObojJou+
         pxl7uL0vJdwQVl7iAPaeMkVgDyKy9egZwP1Wp5rJiIaKZIEOPq7AWKtXEpktWDEL0C3k
         qS/EzUNgsKC1miT5ThklCCNpbky3MVXUAiLqlclWqED5yeiCj+X0DK9CdBTk9dr/cZCD
         UAlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lCftT4m0;
       spf=pass (google.com: domain of 3nbkrxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NBKrXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uxvSNEsuUomeQ5403P6NxrUoDlNkRyFWNXmsCn8nM50=;
        b=UaHV91zXozIubxf7JwiDqYvEbpgoGMCwPmyg1MekVWc1siaIMOV9HmpYwi07yyTL9N
         wwiqSlahiNxwrLxfqgypIB5rt5TtAbQFJni6cxETUUM5As1D345+EX5QZVs8Ej+4ljTY
         9aF58uFgq/lUJreXnvWrjELKPviZk587DAv4gk5IxgsqBpjj6XbrAzQV2dvoZJfpHPwB
         9BPMNzc30WMI5iA2Sy3KAGGu9r3kdZFLAKYQiCVX/ROs7zKcfhdiHY7zbY633bGSRRc+
         WtTPiqWIixcRzU5DCedliQMMChiVg9/OLNYx+7rsGDlGOI/kioFV8zO8KBWydPePAWuC
         piZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uxvSNEsuUomeQ5403P6NxrUoDlNkRyFWNXmsCn8nM50=;
        b=gxs0jvDYJ9BBdN5t46fZ+8i7gJeO3dnxc3vN4H/E2+J1BG2F1aTS6jiYKdoXESTypD
         LlH2sS7HzOLkr29nE4lRbqum11IAT3ERhai5gthbFV7bx/CCTxD8N2xW8Msv31lCNBcj
         X3yEN1I9xJVqJZVDkimD/b++s1ibJ5RPWGEh+8ltmMgvLBA6EvWblNhO5SMz117cITfr
         kZFEJpLsIFY9vJs7ekZKPMn9KxC+7doCpru3wiuDb9ZGBxqxO2FS+7j1/UVThoCtuV17
         CFzhyGBBPoI4wr17JOaEP3kJYycoXq+eVZ7wJ4pGUU4K4q/Q3p9cgQ5Dzl3n5r5971x2
         FpcA==
X-Gm-Message-State: AOAM5313dzN+7+b7vTuD7DhRnuE88iqYlP0mmVZHC54Z+NUnC89g2omh
	5IVtFuodcwr5AbpDr9E2mh0=
X-Google-Smtp-Source: ABdhPJyPNRPX88IS9jkk6RxiNHKuGewFp938cfbAmNG92g0pUobVjDdGkKyxWOnm9b8xTKaxoXyXGA==
X-Received: by 2002:a17:906:e53:: with SMTP id q19mr23151081eji.254.1605046837181;
        Tue, 10 Nov 2020 14:20:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4c3:: with SMTP id t3ls14309926edr.0.gmail; Tue, 10 Nov
 2020 14:20:36 -0800 (PST)
X-Received: by 2002:aa7:dbca:: with SMTP id v10mr1684469edt.219.1605046836322;
        Tue, 10 Nov 2020 14:20:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046836; cv=none;
        d=google.com; s=arc-20160816;
        b=FroolSRbXo+uYkw7+6LCYLozuX/g+pWKWR+ZOrZah49tpEg6kD24EWjhMkBwQS3NZd
         RIE8efdLU3Xk/TGFM+6BgfoCUtUroEPHuvmQVr9yjKXdqSrap1GAbTr4kS17Piacg1YC
         5T/PC/OB6pYqAlVrErq/2b8BMcp+Rfd3aE1XyAiV37OM7BlHqJw/mZ442pHG17ybQwL8
         TtbfxRxULM/ac/uvwNKPfQmVQ8ij4XaSZurZLJt+1ObHi/ix3ed6640XRm4XOH5/WQCK
         kFqqQ5/pcyRcJahDkkFESQqEb/zFX9ey3OhJ8RpdlxzXqkcpNTNTj8hZpE2VkIqVfefz
         M6sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gNopVjIT8PLD1roCXuMREiwLLvujReoC9+pcOjj05mE=;
        b=iwyBjpmsJJjkYo44hjG9FPy9GkGmJvlqUoq0jLdWKyZdok6V0HQI1xaFS+tIpp0mor
         lJvh/No4wanw+/XEccNP5sPjpYnXEKKBPW0bkHC5iSsVTbr3CGjQ41C+iytnJSDFylWi
         urBHyOarYZYzuu9fN7MXAiaKrVIu6Dc9LITrj/1gSJZ/Sv2e2VefaCvHRLyp5boX43aO
         NwkzHrK5vnrk8W70Ol8MdPvoEME3waRF7+LrwFGn+jQwRoW4F8bm2OO/nlMvX/vhpyhF
         NSevZJg12h2C6VTvW/woWz/pJfeqN48eIPLxJe6bHL2t1GJ3OMPQeKAUfuVYb6GtDbu8
         Puqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lCftT4m0;
       spf=pass (google.com: domain of 3nbkrxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NBKrXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v7si9302edj.5.2020.11.10.14.20.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nbkrxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 14so1386127wmg.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:36 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3803:: with SMTP id
 f3mr304885wma.14.1605046836014; Tue, 10 Nov 2020 14:20:36 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:07 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <5302e6d48429465259bd0868a7dc357290a2e8a5.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 03/20] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lCftT4m0;       spf=pass
 (google.com: domain of 3nbkrxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NBKrXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

Add set_alloc_info() helper and move kasan_set_track() into it. This will
simplify the code for one of the upcoming changes.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8fd04415d8f4..a880e5a547ed 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -318,6 +318,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return __kasan_slab_free(cache, object, ip, true);
 }
 
+static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
+{
+	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+}
+
 static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				size_t size, gfp_t flags, bool keep_tag)
 {
@@ -345,7 +350,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5302e6d48429465259bd0868a7dc357290a2e8a5.1605046662.git.andreyknvl%40google.com.
