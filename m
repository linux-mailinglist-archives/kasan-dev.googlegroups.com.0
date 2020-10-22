Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3ENY36AKGQEH6VXGBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id F218E295FAF
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:40 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id c204sf587186wmd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372780; cv=pass;
        d=google.com; s=arc-20160816;
        b=EwA8JlOnttZS6WS7Pqj3U7kC9KyVbqtV/cZXrhbDVK0cdRq0UU7h3eWiEip0rsqlUw
         ypPj5pUdwrSLivTBpQ1Y6dWMu/If9dWkYkN2mBD7T+EaUZus7rUObPyLBfzaiB5ABuqL
         fSBYE5DwYJBvntcH058JdlMJFT+GggY0RI7eauBvXS/2TnAwwlVXUdNkpYAHAZ+VQu1C
         /XugTU6n1UsXIxPxque/caI5O8R7MOYluelwiTAmLM8LMFR1+95nWnKnk2zeb6TRTvBA
         /oo/dLzJc0Dm7oKTHQ14VFgl3T+G0VV/5zwvlWZ2+HhVMys54/nNWqgtqu2HD7b88vKg
         cBIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=++hHfjyjagW2ruNg4YgflVeHBui3jDGo9a6zKUa6FPo=;
        b=F624GjdABjSF2fFsW/4QvLH/wMh1PILFmeXLKxkG6qwTb1M2jE4vAIRUX8CZIseViC
         7a1VG48v0QeV4pQAYSVMzvm2z8wZxvtrDye/ib/h6OFcxHfg0V8wguuEilnb3m2g9TqR
         2QNJKRKCe4NxPuw8D0VifBrYMUujKf/OyC5+QEuAl+134c1BkisPGg4DNc2VlUfqQ+U1
         jPHsraLkcX14U33l9LX1kpQ8+DMoQkPU2QljRVcPDx/QO7RTl89V9AKJcBiTXY6V8tEl
         NMAuhGakTbflvw3Sue4E95+0cfHcz0LxjaN2++1SgciejnArf7f8N9YRY/LknKT8upz0
         xLcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jl7LpW95;
       spf=pass (google.com: domain of 364arxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=364aRXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=++hHfjyjagW2ruNg4YgflVeHBui3jDGo9a6zKUa6FPo=;
        b=gpdjDGKDP8Nk2sqHuiKMSi66Ckd+qB27L8ixriE9AMATg7OtxIQfJfzSxAU1vGHrlG
         2RugOtY7VlVdnG1n84Cty+B4QVhXrwRsJXjwDd1xAzM1fdlfNTCJS1Swm89m6RHUa+Ey
         hww3eRIT+nU6iI58emD+9cSBUPgycMBqQHJG9Jl+ZpLs67EEVskWHDWC2AKk73JrpXrg
         DrQ/igbmJHfY8+VRJJRB7CzBClTTv5qityRVBjBSrWS7YTUgG29fFVnnySuFqXrXmIIO
         BC5c9c6qhIzLq515NEZo85EhEjnLsBrEQj/XcMVGX0FDhC50iVFkFHd05ge5svYULe+l
         m4HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=++hHfjyjagW2ruNg4YgflVeHBui3jDGo9a6zKUa6FPo=;
        b=GpV39CT+rpC7gEzOM6xc82ZWg0vNIJcLHslz6k/xD/K4Qb1Nfhj3UPB9JFT3y9qvxv
         RS8usjcTBbrETek+DTYUEfLKrT8wLeaFXma9tV6vYW6lqwMfnB3OIU0aOsId37Kq2Mjz
         glaPAJavwvuSH7EKBpu5a8YytiGwPdtjCZufFk1jAsJh7gk21R9if0asXkWD1y3hJpTG
         M3wo3jdz/0ic5KHHgr++NA+EY0BLYDM2Rbbp9Q2f2q6OlG2uJbRq6VHhl1Kks5d737U2
         QNJgdqphaz1nyk2ErFydRcudXvFwe4wzmizq7QYyRq3VgZvzHysSkVUL4lyNM1Kiwa2J
         mrHA==
X-Gm-Message-State: AOAM532CG5TGKlG9/S1hl6Ax7bQqvOTvdZjGPmjgCuEm7eTGHO7AAGqF
	cp4ZqLMu5qG3VSxMpjt7EJk=
X-Google-Smtp-Source: ABdhPJzRsEHc1L2zfQoMu8ijQ/0mnh9tO5NpRfBxxJmRELdPzv+6VLoSVmYIoBVLB0xW+4sX/xYfPw==
X-Received: by 2002:a7b:c451:: with SMTP id l17mr2602485wmi.127.1603372780782;
        Thu, 22 Oct 2020 06:19:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2506:: with SMTP id l6ls999817wml.3.canary-gmail; Thu,
 22 Oct 2020 06:19:39 -0700 (PDT)
X-Received: by 2002:a7b:c341:: with SMTP id l1mr2628582wmj.80.1603372779874;
        Thu, 22 Oct 2020 06:19:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372779; cv=none;
        d=google.com; s=arc-20160816;
        b=r/2BWKYyQN38UuQDqzh+DlPnhwSwPQszLh9xbNtj94P+CWrLt4rPCfn6zbhwAkQ4PO
         TL43xeCpIWBm7X1Vgp9YuOYAkepFOhNH5LyCNtxDyElTsBpzk5oRPDEen3H5tyKk3H6+
         C8n0tuucjmabR3iXYmScLNM9aRHVtfy/11Oe/AJnHXkFCqDtl3UlreY7+QmR92HqkEsa
         q5HsD9S8mXvt1Y53h1TN9RsMDGHjMBVYW8q2oJ52C/+xhFOxNonuY61M596QXJPMmfhS
         uXrFms2vW15ovgkeGLrK1UTCUq/MtAF29TVMClNlNvfapLKjC58Xvqf2jswwbVuLJfEV
         /r3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zMvzayRKcZjOHIZsW9PV/RuW73K9oxGh1X5zaP2bEOg=;
        b=PlDtYD7ii5VrclNmsAKiMKmxK+gEs1yEZ6xShwoFUvbH5XE8BovcPZSh4Wavh2GKGo
         BnFOcf2dAhuxK78TsgJVZfqxmt0f1Lpww0605DWowSluH+ajhl35xNlLcj/dSWEbPtej
         3VW3CNjOS6EookrkApeDtdgSYLREzmkf5Jt1VigCBvFCq/980KIkSNuiozahc3cXjnBU
         FTjJn6Lkn/b6qmw06FAC8APjLiC7nbnGStE0f74xADlNe4in2jykEDRWS8S1tpToXwOh
         +UDDrKaNiJS20XP0jmmlof92hvXAVCUxdxHS8tiQIJS10DtBVR/QbABztQJCTPa7AstT
         ld9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jl7LpW95;
       spf=pass (google.com: domain of 364arxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=364aRXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n19si66626wmk.1.2020.10.22.06.19.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 364arxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v5so628030wrr.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:39 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c7c9:: with SMTP id
 z9mr2640989wmk.91.1603372779361; Thu, 22 Oct 2020 06:19:39 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:58 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 06/21] kasan: mark kasan_init_tags as __init
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
 header.i=@google.com header.s=20161025 header.b=Jl7LpW95;       spf=pass
 (google.com: domain of 364arxwokcuierhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=364aRXwoKCUIerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
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

Similarly to kasan_init() mark kasan_init_tags() as __init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558
---
 include/linux/kasan.h | 2 +-
 mm/kasan/hw_tags.c    | 2 +-
 mm/kasan/sw_tags.c    | 2 +-
 3 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 7be9fb9146ac..93d9834b7122 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
-void kasan_init_tags(void);
+void __init kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2a38885014e3..0128062320d5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -15,7 +15,7 @@
 
 #include "kasan.h"
 
-void kasan_init_tags(void)
+void __init kasan_init_tags(void)
 {
 	init_tags(KASAN_TAG_MAX);
 }
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c10863a45775..bf1422282bb5 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -35,7 +35,7 @@
 
 static DEFINE_PER_CPU(u32, prng_state);
 
-void kasan_init_tags(void)
+void __init kasan_init_tags(void)
 {
 	int cpu;
 
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl%40google.com.
