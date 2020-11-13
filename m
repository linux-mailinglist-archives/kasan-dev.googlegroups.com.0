Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ4NXT6QKGQEA23NVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BCA52B283A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:24 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id f15sf1380148ljm.20
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306024; cv=pass;
        d=google.com; s=arc-20160816;
        b=CWutXmOhG72Hk0Y132nkY/7o9VpKA3aJi88l64w8ilYJcjIODpgfLW2cFCiqKhBzT4
         k3qkC1Qbtx0OndBAQjEwTDV3KsU4d5irRJbl7vIcw/V53agKK0i/NtEbIN1CabIweEII
         jWa5EpBc1oNYUN8ytSJYHgVlh3L0SJ3b1UsdvcYirxBY4XT09VCkMjoQMztNdWs5kse6
         HXabdlPja8Dy2Hj+SiKq5BjXniNY7DE/XWhPERSr5UE3odnYipczDZG4thc1kJ3Ib2G3
         UTCtpnZsaQiYR6gg1i1ogE1GXDCHdAPJ0VS0FDb13zUkeKI3DkxVXzDv6dAslGoQREAg
         4KBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=KFh6h0clOubGMwbwFXzyXCRtgD1zWUSFZ1tDJOXdUgY=;
        b=fwg7g/aNcg2ZoV9Oh3KVbKVHejMKab5nJvQwA0LtJ3mpFnm3zvO939h4NATWLlHilB
         aWzl3geLKi+9yS8NfSuIops2BVs3nlf1ntdRMybY5dNq1x7nRqurlf2eGxewlR/jdeWc
         fVRcEw2L25GILDlZRicCtqDkskr/L5MdMm5H/dhvgAYPMYPgprrRoaQmKBhQ2ws2p47o
         zKYBGEdrpx9pGpjvXe9lMs0g2k5ZM2P0urAZFNfaXJyCgyEJYBzhg5zocp+TOQjqWLXm
         cIiHM3sbnqHZsFXHp+xkRtQMSN7qLyW6no9wIehXtBIN+UdvMoBUK5F2SwrW56I/Xebh
         vTIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NbjGOqNw;
       spf=pass (google.com: domain of 3pgavxwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pgavXwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KFh6h0clOubGMwbwFXzyXCRtgD1zWUSFZ1tDJOXdUgY=;
        b=OibcuP4OFoPYI0S/kZXPSE3bx18CcgDDH8Pv7m6BPVqAW+znINmax2KKVUj3kjhpsI
         49j58b14GVzlyhc5Tr7KtbdH3vH3cEcV4mUM4M2xna8fMIuUAiwuoLosOEhzcztFwbtG
         zlLOblCCyQXRrXxfo4JgdD2JYySDBprbYqYyjwIaLbaTsNupygHMcxXY/voH6hXvQBaK
         AAziJYw6+408fkFn+6TAATAFE4GbLOu+6uAanA6nrFPq8n63LZP0eStBEXaqGLUrxKGd
         F52Y046YFiP0MmTuZOdD+B/93foGIJEv/GO767Z0yo70F9pQVN2CBvE8ryHbTi7Q6ung
         Ovaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KFh6h0clOubGMwbwFXzyXCRtgD1zWUSFZ1tDJOXdUgY=;
        b=Rkk7pUchWIvoKtR5bXdg1UGGV0r5kHoMUuJi2C4VjcshCMqvF34OBA3Lns6logdTYf
         eI27rUjySnXDODKAAUZH8j1UUtwpN6Q52XzKPVEqSinL5Ao3Z3toNXAaxHr9vNLXKknb
         fT4GYZ1rekspna7tWXS4Wo+JsWDtuL16xwVygKprGXy7yP9CinXtOcPNN8vGLhjKC9Lm
         lti3Yffayyn18h1X8P8/4lW8W8QfLddDMGr5Zhf1HCL5jP/hjo5lYXbZK9r8iB0pvlPh
         Um8dxq63CGe4EG0yQj9+b0nrWVWrF9IStXySXa2vf5AoxLL4SSS0eURo4k7O2gA22myl
         cqBw==
X-Gm-Message-State: AOAM530M1yt97GS6inOOXPdu5BLUieF4AoWutcfgKXD6SLM9M2fj72Z+
	NwmNZDUEHdtn0lHFW3BJkxw=
X-Google-Smtp-Source: ABdhPJwjqlkwOFmmS7jzL+KyoF0l26pZKHl+kfDY2W3osZr0vS1/xk6vb1rLDWGT5Qdn57etGICV7g==
X-Received: by 2002:a2e:9616:: with SMTP id v22mr1814528ljh.120.1605306024135;
        Fri, 13 Nov 2020 14:20:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7619:: with SMTP id r25ls1496490ljc.11.gmail; Fri, 13
 Nov 2020 14:20:23 -0800 (PST)
X-Received: by 2002:a2e:9bd0:: with SMTP id w16mr2015094ljj.301.1605306023101;
        Fri, 13 Nov 2020 14:20:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306023; cv=none;
        d=google.com; s=arc-20160816;
        b=s9/4nNA4L7Tf/cwj65bmhobRQ87/1qBFQFKDqOSRL5XtYWYoF3mT+f4fTyCBYpSTiy
         buJ2Bh9A0scfBTljA4IzXXs+ogzdheu3JAtgCEkRshlJYogoZpusDbO512nSZH2pckUy
         kBxS9N9WQpyK3CZAZtf4XTlPXjGZ8kxSk0nQJgh9MQVxq5iAdF7wB+K6IFQuWR1qS0VA
         67BQwBwOzcUN4QcHW4LvRvgf5zI+b8ACTRZPedwN4TTv/oeWvnqlIFkt4Pz2YV/vG5y9
         oWP89qcNxxHwbFEVL08Zwe2TMlwX8Zau/lcjhY+dQgz8XTN7AJkIEFCypSozj2n162rP
         qICw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mI/2rW8u6CFpBd7nyudEpTk9pqQDS3YjqZmg/d3PQMM=;
        b=MGXcUBsgMqCcTNQxGMCYdINmNZkADrQTAgiRV0Hh70hyw8gSr8tI3YwhJx8MdvQzyT
         eK7iM81q/jH3vL376GA+jf+nW9YBq9d7BmUjYMC9Lm14uNGfiGuHPxLc07XMGQ9NaKLg
         JzdNPiZP1UFXkhSVXIhrZeLpYLhbm7yabp/RlMYqDpVGllNUVXMwbRSpiyAN298vKiXU
         xadd9DdG+e6MKSkejfnRQ2vwzbSNp7qC+4WVBtxyOuMumHlZJ8LxI05ah84yPD+AWu8t
         3LQzv4W5IwRAT/j9VxYPHZVoKx1Jj2fUGPyshGLDAxVTRhT2K5xgFtmH1FNflJimFOqY
         ychg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NbjGOqNw;
       spf=pass (google.com: domain of 3pgavxwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pgavXwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f5si138028ljc.0.2020.11.13.14.20.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pgavxwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z62so5880147wmb.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:23 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f04b:: with SMTP id
 t11mr5710125wro.147.1605306022529; Fri, 13 Nov 2020 14:20:22 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:53 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <31f5366d3245f5405185a0b4057b305613ce60ee.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 03/19] kasan: introduce set_alloc_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NbjGOqNw;       spf=pass
 (google.com: domain of 3pgavxwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pgavXwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I0316193cbb4ecc9b87b7c2eee0dd79f8ec908c1a
---
 mm/kasan/common.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 8197399b0a1f..0a420f1dbc54 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -327,6 +327,11 @@ bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
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
@@ -357,7 +362,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		     KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
+		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
 }
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/31f5366d3245f5405185a0b4057b305613ce60ee.1605305978.git.andreyknvl%40google.com.
