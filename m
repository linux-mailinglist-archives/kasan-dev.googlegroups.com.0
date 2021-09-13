Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37K7SEQMGQENQZFNYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 454D5408A17
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:41 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id w12-20020a92ad0c000000b00227fc2e6eaesf15389945ilh.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532400; cv=pass;
        d=google.com; s=arc-20160816;
        b=P7nr6UNJfHPxUDf8wGK9AkZznZ3N12L2HqdNfoJkH5dbr7mUFUZKlW1aXDEQlZRdYP
         2AvOQNB0qW2K+vXx8iVV+FCPB63579WGmvJ9OlJIDUoZnCEuPqUH8w/cPxcIz5Rd0Ku7
         7uUcH/zVfvhvbmf/4OAL1OY78gEZ/wa5tsYY46Y+ag3z4cCoTXoyY6eNWJvi9FPrshcQ
         +3WCYMhH/lka6TN0vUwXO9NdAE4g/W71nLAZYizepXgNk2D+ApoVZRc31VErm+7tfLX6
         9Gt8miua/IC54NtTAj657S2/ESd5TI1itX8DDTH6OBRYxBghmEG2MkKfqJeb45m7QEyT
         pGQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/cjnrdDfOiECl81qCqTjV3Onc2EMr0au3/1Y558TleY=;
        b=v5pqO2T3OyR5LSpXkHQIutENYSiEDNE/CRC9/zaCwBCtw/AVFp1CVBQbWMWXVuyneL
         jKmRE0RjeHIGFPqgOfhxLOQg21lnSrQKLZAQuuFOgCFC3BTVTs9g89ivgzLpcoGkz7GX
         I/w7Bb1hWWnaA8isT6KWFHWj66PON7BzF4kYupf7VgtU/+L5UDPrP+3mY4ducxAgQPAW
         414cNtZeGOuKPdYKen2sE3NorR3FiIeE74fnt8aFnKyZ8faAzgz2n/XvwMasf0wt8qvo
         RkqvLxQhDk0HJ0dpAidy3h0JwhYR5ro8FKznos4wB/c1y7WgfVwbGhtE3Xt/U7R1taYx
         yraw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FgLtShlM;
       spf=pass (google.com: domain of 3bzu_yqukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bzU_YQUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cjnrdDfOiECl81qCqTjV3Onc2EMr0au3/1Y558TleY=;
        b=mpUIMz3xSUsBVo5TsrGeSQsS1rgb/qJNKa1EUBPl/HoDpD3fTVsTC93os3v7rzFVlN
         9L5NTe9ELBeR0EfdvDyh/I0BiGV7C2jYUgNTsknjWz6p5KKuyPnQM/BMNy8uzgUvDmIW
         bNUwHhdgBYP5NzicWDpexmjSyF1bMexl/MtY+XLgTYYMZCsvSnoK7s7+2Ttytkiorf6/
         zcuHw5Magn6JGVVIWCJ6tSOrCb6gTyl/53oyn4s4ZQkl6x6rJavFScWUO9ZOxyX4F81h
         ROsocU7oxkvs993mBa+q1VgXrBEJVnry/TqsBOTZ7O9NDxrMfvH/IOzFWTz+c86Sny+G
         qcKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/cjnrdDfOiECl81qCqTjV3Onc2EMr0au3/1Y558TleY=;
        b=vM1S6QAQTdvtPEaKr+OETMYFh802Oixkna0TaaI1URAQEfPsfcDB6ghSIWGsDiFVdL
         Yf7ikWsVGsKJ/D0oZE7CWxL9nEPQP9cUxCmg3uXZRHwg01tCuPcbGcRk90ZfPXT+jbl3
         xVWVwjBsfDSjEA+Ayu3zxdFGQMQKlrAR7EjFwzHM/69m0Tpc3vutF3tlEhTZW7NNdHCA
         owTqg2L6ssJO96F6MTYzyl3wUOkS56ijBau78MiRuFm4hKpZXoF4p5jFM0m7sH95aV+n
         pJ3/VSdlREnd6oDUbwLp3VMZGRGU/VAV5aZzMIWLw0QkjiJ5uUnBEp1FuLibRNsUCsBY
         MqUA==
X-Gm-Message-State: AOAM533XW6kejQW0LvmOxwzYarSwhmh2zJTs9qBvznRxshdFRD3HhRmF
	ysfAbaUa0LKUu6toaVPyVDE=
X-Google-Smtp-Source: ABdhPJw54v4jk7kKd2V56T6eYliUwp19rXUBaKoKhyacoBFeyejoN8zZ65BTeJgtaQIIKqPeOIzV8g==
X-Received: by 2002:a05:6e02:154f:: with SMTP id j15mr7254525ilu.70.1631532400001;
        Mon, 13 Sep 2021 04:26:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:2d8:: with SMTP id 207ls776764ioc.2.gmail; Mon, 13 Sep
 2021 04:26:39 -0700 (PDT)
X-Received: by 2002:a6b:f30b:: with SMTP id m11mr8456189ioh.0.1631532399606;
        Mon, 13 Sep 2021 04:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532399; cv=none;
        d=google.com; s=arc-20160816;
        b=qyLRh8iOXCMA9IAkig7OkIyece3HW14kFpKoEMzSrzIzAqrZ8ryPJMNUG0rYpsiFu1
         v3+VEu+46FBXcRT/8uBd6S7VJ+HsNqdyHfS6ZhzZRcl/A1yv5R/10CDshUEGo0tQIswX
         LC7nHeThwhYaRUVNKjGPHmZhVBDushS09BIwoN1XdCigX47gAzU+5Nfp9MhRaV8M9+Nt
         LxUrtTjghOyHISgO0t1XrQ7IVR7ShVFVXBQr2M+md0xawMKF3lqJHxdDi1V6VQguDhxo
         A0EqmhG6C5vsHt5lNJl34dgB8/RhpBXYqo8/NjKdwWhn7RJHOdgd4Z+ghXKwnMCfJeI0
         Ukzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=RLfVSTnmaFR6BCLsdGDNNy/lIjkdCKWfb/4pjdgI7U4=;
        b=DM8P9fY7z0HlJD2EZ6vH135f0erpZ1S70teckYQoX5Kri2VBZbQWPv2M2Rt0cdj6IK
         cY1HkuGMc5288frRI2BftLj9Ald1oixizrB/Xo22rbam160+czQpvcFmOPHzSGp0Ev3+
         68IFAJ6lkfZcnU1iQLi7i43OY+eKwZpr9prQ2iGQjObiks01w0AHEizmpqARiLVA0LQt
         zmrkAApznYG9BYW9JaEV9icVG8McdlqZkNjZJ2AhEBSMnuStC0qJqfnfVHvnVEmdnJfT
         BIr4Yn4CuODWIORJsrwlqtbm6B9nr74gQ9X1ro3vuo5/ileTbmVkwUcpB4lMGGxb4wh1
         3obw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FgLtShlM;
       spf=pass (google.com: domain of 3bzu_yqukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bzU_YQUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id i29si442347ila.2.2021.09.13.04.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bzu_yqukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id u19-20020a05620a121300b0042665527c3bso40591403qkj.14
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:39 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:ad4:56a8:: with SMTP id bd8mr9898132qvb.0.1631532399089;
 Mon, 13 Sep 2021 04:26:39 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:08 +0200
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
Message-Id: <20210913112609.2651084-6-elver@google.com>
Mime-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 5/6] kasan: generic: introduce kasan_record_aux_stack_noalloc()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FgLtShlM;       spf=pass
 (google.com: domain of 3bzu_yqukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bzU_YQUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

Introduce a variant of kasan_record_aux_stack() that does not do any
memory allocation through stackdepot. This will permit using it in
contexts that cannot allocate any memory.

Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Shuah Khan <skhan@linuxfoundation.org>
Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 include/linux/kasan.h |  2 ++
 mm/kasan/generic.c    | 14 ++++++++++++--
 2 files changed, 14 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index dd874a1ee862..736d7b458996 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -370,12 +370,14 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
+void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
+static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 2a8e59e6326d..84a038b07c6f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -328,7 +328,7 @@ DEFINE_ASAN_SET_SHADOW(f3);
 DEFINE_ASAN_SET_SHADOW(f5);
 DEFINE_ASAN_SET_SHADOW(f8);
 
-void kasan_record_aux_stack(void *addr)
+static void __kasan_record_aux_stack(void *addr, bool can_alloc)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
@@ -345,7 +345,17 @@ void kasan_record_aux_stack(void *addr)
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, true);
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT, can_alloc);
+}
+
+void kasan_record_aux_stack(void *addr)
+{
+	return __kasan_record_aux_stack(addr, true);
+}
+
+void kasan_record_aux_stack_noalloc(void *addr)
+{
+	return __kasan_record_aux_stack(addr, false);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-6-elver%40google.com.
