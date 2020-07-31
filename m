Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNFVSD4QKGQEUCA43UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 034682346B8
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:20:54 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id x12sf4606857uai.23
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:20:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201652; cv=pass;
        d=google.com; s=arc-20160816;
        b=QY9682/NYVm5I0JNqOh0kKXMkKOtCC87zYPfi5WYh5FIQuQ55ienmMxmypevHxTTMW
         m2d7rwcWdx5Y3+WcpEvIEBO3We1DbJAdolGgnhJy9D/K3fympQbemPZlGSYgpDUK403j
         4XBDkr9QyXvI561/lp7WRKmEFPA4iNARuTeGLIV6kYCkx/W51IyNlZCXyUBGOoJk2aKA
         DqEQKrZi3Mpg/UpFQlAfJRtbmaVFZoL0BdNXTniuNhzMhyZPELG8RFlcTDGNRor6qzhm
         VeXevbls4x6fpq1GyizcxjOSa6u7YM5k0A2V/xifEy1rTExhC1AOfYIVFxVcMt4chPTu
         mQwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ixOkZ9hqaf/vH03Y7UZdnqlk0jKqcy6pn6uKboVSNuA=;
        b=zQpZt9tiT6g/lXTVsEkf4f3QB5Kyk25ggOCAK42spLbVxMcftdzQrpRcLeMlVZsVkY
         NPvfhpw8T2m3xu47DUdp+/L9yUyUhXWr0OrD0PoBtm5UcD0fWwMzkTfQCoqleVk3OJI8
         R5UdQQT8n96FAld2l5RniYMD1OyreT+PdpLoxoXtLTi7AClRY4k/DzoOggb8YJVQTtv3
         mqzZBpKvlvS0e25kDEpHtLXSEgg3YqPJ2mRSBbGB5jx/zEOVL28Sw01ACRRGJ4tJRJwH
         5wh8lkcXs3PGq9lrEK4h3NulhEiZyZJlhKBKfaduPTOKBqVbwBaeJhxMbygz0uzt4ZEy
         V6yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrdVI+Gq;
       spf=pass (google.com: domain of 3sxokxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3sxokXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ixOkZ9hqaf/vH03Y7UZdnqlk0jKqcy6pn6uKboVSNuA=;
        b=Zh6teEdQTUefIOHu4w9zYW/CZlqw0WiedZDDzPNyeklMji3LVBu63IgZtNY1VKTS4U
         hf7ov4PBCgwPX/J+1JyZs7i7pwpcdV0CKrNUOt/7VjT+vl04395AdVh/zp4TQNQY4rLC
         TSs7qEGffnhNI4OZfCsgmAvoVj2uai6T/HtN3CKX+X9uwRNOmQ4H5p/Fvfczb2bY9Gkl
         xLgECju9xgVXgH1oHUOgQvTL4UfXOrC5lqEectk7dIAtvbvkR8NLHIvJSTmyT3Qpk7cq
         k+yKWH+nO/fSIM2RNA+waFNAwKBKT6SdpP3QOkuw1bsK+qSCCSogIVjOImdhUF/iHpLd
         dmTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ixOkZ9hqaf/vH03Y7UZdnqlk0jKqcy6pn6uKboVSNuA=;
        b=B8Cr8V0fDPFo9QmXrE9TtJFpOi0GCCATPTWKFh1fdHjsKNV3bikTfmy2lb54Ic8rvM
         Y0dMGeSbp4xspF335QX5i2rJ/dmRgvvl7MA2mXTp2gHcVTAzfF8L55+K4na+lU/IFXtB
         bDQU76y1aSW4H4hkah0rqKw0DcVX4InKDg26V0j2Mh5ZRNVo+hsujSWfXdrSyHEr0FRz
         xv4S5fCZXw5oguMjFkk9xUX0zZgrV79SGy6PYBBCRaQlSsctZgH6bBaVEmlmAy+jwb0n
         2HlxnJ75dpzNKZ4lKEpH5XAQLxCsRHwtls+aoS+fHWtAaGKl+mP0DEpkZDF9/FNhaZC6
         jGjQ==
X-Gm-Message-State: AOAM532uQbjd8UxGzoiII7VDZrXJCeNzmY5xmRUVJXV9ziwHzwnjt2WQ
	+9d77I/AY5rkyQas3LwSbKM=
X-Google-Smtp-Source: ABdhPJwDHgQG+MUEOTAtKjeIdVNywz8P5gBfa6jU3Na9T5YYNJ0r+H8NcffQJXUX7mYjvOA+pLa5Sg==
X-Received: by 2002:a67:6bc1:: with SMTP id g184mr3083952vsc.189.1596201652645;
        Fri, 31 Jul 2020 06:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:bf96:: with SMTP id p144ls186822vkf.5.gmail; Fri, 31 Jul
 2020 06:20:52 -0700 (PDT)
X-Received: by 2002:a1f:cf01:: with SMTP id f1mr2622393vkg.21.1596201652304;
        Fri, 31 Jul 2020 06:20:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201652; cv=none;
        d=google.com; s=arc-20160816;
        b=IPammrwnO07/K6w6aOh8bQgQd7tv6pXkONuQDtBG8q7oMKbfBo7ds0L/NiXdWZgXTq
         JNHJVpehX4TTnXX3QknpL6bEb0FroxcMsB5izI0MiBJxvF0GZqnz7ycZeQRqfPnPjTua
         TrjKQ3GT7UWMjdwYFq2zHXD7ncvztgCtYiI/HjpxOo0xj5hBsZq72KJWCIkqs0bqj49r
         Ax9fyYSQLAVYHJ7x6/MRH6wtJPdbmTXRxnDtWHuMB041UbZCqIisUDe9uj9e7hxUHHG0
         1OC/D0LNWYn57nrrPXeOc6SM9fWVHuLngXYzjiUKe2ZUIOuzOmds1IFPXVhB/nLN3gXn
         nfzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=RlSgKw0WaVPNPMJUtAR6IXtLReCVIjzNVv/S08XnLBI=;
        b=CfUcuyMnH6XnTBQHktxumRuqpc1oUl0eE7y30WkTjQ8k5dR+0wqFsploY5r31/KHF+
         RhxTrZEPnP+CagwMQb0Ud9hiTMP3cvULIEsXgGorISrAVaYRS8pL6ZcS+rLvkJlvOZkY
         b753CYfDaTn55NEly3lmcxSaItw8Msm/rtAdT/9P/8HRatsY5XjW4Be3iqOIlXqPlRqz
         FTozAWr9VM0IemCBtrGwz2y6zPL/4XAszoVpz3OMS5y14N4QjfynMSdTyvEXIVwPoqfJ
         AyZIN83mzsdF+FpjhdQnb3T/sA8z42odjS0g5Hs51MOfoAv9YZY4HNjHKDbfxv3v3Juh
         ewhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jrdVI+Gq;
       spf=pass (google.com: domain of 3sxokxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3sxokXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id x16si50957uaq.0.2020.07.31.06.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:20:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sxokxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id l18so2045504qvq.16
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:20:52 -0700 (PDT)
X-Received: by 2002:a0c:aac8:: with SMTP id g8mr4079969qvb.70.1596201651864;
 Fri, 31 Jul 2020 06:20:51 -0700 (PDT)
Date: Fri, 31 Jul 2020 15:20:38 +0200
In-Reply-To: <cover.1596199677.git.andreyknvl@google.com>
Message-Id: <01c678b877755bcf29009176592402cdf6f2cb15.1596199677.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596199677.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 1/4] kasan: don't tag stacks allocated with pagealloc
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jrdVI+Gq;       spf=pass
 (google.com: domain of 3sxokxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3sxokXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

This patch prepares Software Tag-Based KASAN for stack tagging support.

With Tag-Based KASAN when kernel stacks are allocated via pagealloc
(which happens when CONFIG_VMAP_STACK is not enabled), they get tagged.
KASAN instrumentation doesn't expect the sp register to be tagged, and
this leads to false-positive reports.

Fix by resetting the tag of kernel stack pointers after allocation.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/fork.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/fork.c b/kernel/fork.c
index d03c9586d342..9cea2265e677 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -261,7 +261,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 					     THREAD_SIZE_ORDER);
 
 	if (likely(page)) {
-		tsk->stack = page_address(page);
+		tsk->stack = kasan_reset_tag(page_address(page));
 		return tsk->stack;
 	}
 	return NULL;
@@ -302,6 +302,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk,
 {
 	unsigned long *stack;
 	stack = kmem_cache_alloc_node(thread_stack_cache, THREADINFO_GFP, node);
+	stack = kasan_reset_tag(stack);
 	tsk->stack = stack;
 	return stack;
 }
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01c678b877755bcf29009176592402cdf6f2cb15.1596199677.git.andreyknvl%40google.com.
