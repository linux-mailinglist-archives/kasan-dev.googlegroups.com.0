Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOGDUCJQMGQEEL7UK3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31F0D510402
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:45 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id l11-20020adfc78b000000b0020abc1ce7e4sf3945457wrg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991545; cv=pass;
        d=google.com; s=arc-20160816;
        b=r0BTMbaBmy3gpEFmi5VE5NP+VrJXVimdDljFklrHjNmUVOog8mJHoJASgDNDqzUwPd
         WO4q9gstakLoEFVUbgKwbYdYSB4ErAme/ZakdFdKR2s1e3fc1I62xOhL8zQavnd1zgzq
         ejEbwMJDMi1gb9qwb//nOmRbFPzBSAGxdYBY951L3zqyNiuSW4vTLk8agunPaKl4vKMz
         AKNMaJvm3z6KRYOgFtSrQyXY6kT4Btae//RvzA1EvLG+mIM4l6PzLhsF9FS+Apcg9IbC
         vX1WWtcRvfv3q1Nl4uBC/oNgA4ZO95k/61hWHZIUzBD7+YTkkYvagPEWUz3CUOyzL76s
         Rj2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=diF6tSX0DFXIVyeFzLMQul4J3GwrplbYiKpUB312l84=;
        b=s5sjbBUlPP0lg3faafbkCRZYMngg/tvIB/FuCyV5HeN95gSU+GajH8zdhTqCKGXuXZ
         hc0jKhMa82tgS06/zqj84VjXyX/Po1JPjSAsHfyqyTW8WrVJar9+gEmm6vQTWTzK5COs
         Lwh9ZnGa/UmtHQmYf/kx9OEaxS74msNvJ/5oXRsiLRL8MZ41WuO/gPhM/SpXio+H6NG9
         e2sIso8JW+luJJNv0oVFTRFq/3rw2pCF/XMx592sPud+VXXbzxFbKJuhpMwMvdo3q7/n
         OkThQp6o8g7z0JIJF/9ib3DOkGU3pqXTezGIHvFYrWQT1cPqgCrYtKouGneV+f1XgIOi
         +JVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DiXJaiB8;
       spf=pass (google.com: domain of 3tyfoygykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tyFoYgYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=diF6tSX0DFXIVyeFzLMQul4J3GwrplbYiKpUB312l84=;
        b=TreZOOQ8jttCisVeVjaR5pVckSTdgfXUac9YmeNLP7trrrTHpLDGrxGtO4mxrm2TD0
         SzA3tuob8ytCSTxMsWkBUIf3m17gQLORUiLWVA8dtLRWPAq9OaAJ6XHU6E4Hn9dasQqg
         CaCuTEL5pz4sT7RqRCB9/qG65MeoZ0ZeE7nJ57HdZltivB9nfUqK2oB18plvBZCWtei6
         06eqDpT55W7b8t5SUQfK9XoHd7zneb6pF8qXtt+Ds8qV5Fw+Y9D6GTULzA5CKvEECS2i
         2lv1OVPIfnTOzEh+0N2EohV8w3sGEK2PRLmzzkTLP5Pwt49ST3+MTjA6tTHqR8CqtgJ1
         CFSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=diF6tSX0DFXIVyeFzLMQul4J3GwrplbYiKpUB312l84=;
        b=aTOVXgJN3RhuJdY8n0mYuTxxJ/WDTqxF+HKv1O9JCAyi1/w4y9lrB/Fw7FAPdjAG8h
         dQiW3A8kuWPGI4nrDTcl7r8KHeJPwmpkRCNq3u2/wklezzKEfgEyaiw9iH1VIUWJ81TP
         j6MVfyuowAbOchA/fM4B5KuoS2cv7JkZM+pZ8IivXMEQwOb899exN3Eq4Bld3rbh6xpH
         uGQzJXaapMzOsQOTSLINEV6HwYUt2tXbTdKJep3D6OQnS8cr+O+d8qG5o12X4Uf2Msg7
         fTx8bHMPQdFWAfrAqzAAJIf7G7HwSAOmH8721j6REZQlCew54e1IlZBD5QtCkbS3qeqg
         OLPw==
X-Gm-Message-State: AOAM532dsm0WakZQaR+3baPnHsAmrPGekv9ossrOEatZjWBXnfJHik3s
	WwdeNSTdMXgX67QxzxFcNOc=
X-Google-Smtp-Source: ABdhPJwBnohvLdzDrqe/T1OL+/2zY+u2g0AXemMkrn3JkQFeanSmUYAczR9shXlM3ps8KnL6swioUw==
X-Received: by 2002:a7b:c347:0:b0:37e:68e6:d85c with SMTP id l7-20020a7bc347000000b0037e68e6d85cmr32127067wmj.176.1650991544848;
        Tue, 26 Apr 2022 09:45:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls1006554wrx.1.gmail; Tue, 26 Apr 2022
 09:45:44 -0700 (PDT)
X-Received: by 2002:a05:6000:1809:b0:20a:cafc:fd39 with SMTP id m9-20020a056000180900b0020acafcfd39mr17050026wrh.255.1650991544009;
        Tue, 26 Apr 2022 09:45:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991544; cv=none;
        d=google.com; s=arc-20160816;
        b=Glf+79kR3EpZ8hUHweieqOg0k8bOssEX85qMyHrKVG4AsgV3JqNo346yHUxKdPfJwY
         2CnXgpKXbI+5RZt97wsprjJHmc2uot8A0zzkbJGJPJzrW1QLQcJKvfMgvKDcZ7QZu3JI
         /WO7GBWccXSkb/hW69DvAVLqAhiqrj+H70HxP30KsJuH4wLhfrDHPdA3ffSTcDUVdb0T
         8943vfARvXvVdvjdv8kVrwW7ge9tqO3kO/mCrvlrejtyk/37n5vaP2UbnD/C3c/9FB8X
         v2g6wGVH6eGlKldRBwhma71Fmdh1QScf3huM4aDoqkTg3h3ajEKpaDhx83Joq30Qtzps
         6lfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KgfdOYR2+eRzwy3N1nFbXjWhZjMyNN/8KPMy2HvUIiA=;
        b=OpkYG9d85Mc2T98MjN+k3Aj0zWotQNaL1ThkvhXr1WbY6Smt44FSzs3RuZl6jwfnQY
         gZaqNdksct39XY6KZ0Bbk8Rl8B43KmdYGhiPqHEoWQWzEm5C0Q6T9dmdlOVbgFlGBQ3x
         7SqKmnh50xxgmtVTKv+W22vkS6PL2qFePiC4QJtP6beDgyAgmrIm0tWKgEPc3Jr/C849
         dIM21+Bpi+oMZJ1I1ei+56DfjNV40uhDkZI7YodEHOmkEHjbwkdVyQTOMp2IANbeOvu8
         LXsXo4El5/XCqYG2rAP08QtM8t+TBqJpUyzBB0JUh9VPUB5AadTVny1niAEUZUJDRy+S
         rnAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DiXJaiB8;
       spf=pass (google.com: domain of 3tyfoygykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tyFoYgYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b22-20020a05600c4e1600b00393ead5dc00si173963wmq.2.2022.04.26.09.45.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tyfoygykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id k13-20020a50ce4d000000b00425e4447e64so3792457edj.22
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:43 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:26c7:b0:423:e5d6:b6c6 with SMTP id
 x7-20020a05640226c700b00423e5d6b6c6mr25480700edd.61.1650991543391; Tue, 26
 Apr 2022 09:45:43 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:01 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-33-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 32/46] kmsan: disable physical page merging in biovec
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DiXJaiB8;       spf=pass
 (google.com: domain of 3tyfoygykcbqafcxylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3tyFoYgYKCbQafcXYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN metadata for adjacent physical pages may not be adjacent,
therefore accessing such pages together may lead to metadata
corruption.
We disable merging pages in biovec to prevent such corruptions.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/Iece16041be5ee47904fbc98121b105e5be5fea5c
---
 block/blk.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/block/blk.h b/block/blk.h
index 8ccbc6e076369..95815ac559743 100644
--- a/block/blk.h
+++ b/block/blk.h
@@ -93,6 +93,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
 	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
 	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;
 
+	/*
+	 * Merging adjacent physical pages may not work correctly under KMSAN
+	 * if their metadata pages aren't adjacent. Just disable merging.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
+
 	if (addr1 + vec1->bv_len != addr2)
 		return false;
 	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-33-glider%40google.com.
