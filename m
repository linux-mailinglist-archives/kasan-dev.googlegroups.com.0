Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYEE6ODAMGQEVGVN7SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 920DC3B890A
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 21:13:37 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id f14-20020a2e6a0e0000b0290172cfbb4a24sf1229704ljc.6
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 12:13:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625080417; cv=pass;
        d=google.com; s=arc-20160816;
        b=dS2c54Tqzb4QU/iWCrtDSc9QbPHGJhkCp6b0EDHhx9Xr87rmOjRpBcP10rxI2Sl5FC
         5QO+562tbR+V4wkyJX4UDwgh11mqkhbMznbJVL4UDX5uAJAVh4Lpfr4/jnSL/HMvDyxz
         OPvpq6vNtY/cWCFJYCy2t1mwMwa+76+0CYEeVSLmdn3IEGQdw4cHPDNZ9McxmryyjcY7
         LeD5o86GxsvHs/kyrlv1/Vv3TVtnZ2GK/QKI07pXVu+BkCy4awTNayKLWEelt6vKXrLG
         Z/3eL3Z8n/LD50GxG9w4cA/2X26P6bjv35/ARoR7A2mcgxFi6x6nhH82TUQCc0SY7RnB
         4uaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=G3c9X1LAFiFXKPYK0tsScKuMRVbcM2Hvvc9hBKYF0rs=;
        b=FAVqNlXct4ejtFqeEgUTmWKSwJza6a2JUMvPKWd6EGJ+BUpL3BuwFOjBhHhAQT2Jlh
         EEb2xmR+SExX0QII7AhDRcEAE48PV1q6Q0BXiKYvRY6Ct8kXZAAIop70Zxo9Wjl60xDR
         ZhawiQb4lomPws5JbQZQuuaAIWE4rrtWzXot1acm2VOKHm8NxeKQBtdmJWNCN2XuuRLd
         6oRiCWr3aAmK6vE6N60Gv/KAC0dTCg8pEkc1RNQYToVWawzfJR7jI6thvCWOv11CCoZ0
         KOeYhCgTxPLCs0kOm5bVuytknuTMbodNj7N6ABmTJgnHpKb5DRn8jcB5OKPMpW5EmZOI
         zMgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r7y6xbzz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=G3c9X1LAFiFXKPYK0tsScKuMRVbcM2Hvvc9hBKYF0rs=;
        b=OlWlIPSQAkIQXhEl2l+TdlhiBCYrriRU0nSVAlnfNJ9e9YDRdTnbXw8fJ39Xhd6r1s
         M7s0SjBFy1TXWMiAWkdRnpUFoSNSNXP0l3YZotd6O+cPipMIDyV5rgIAhWmKpU8APR0u
         K9i/d6piK8obQyaQeueoEQ/32KhniWOK+jGIwX2shFSEWxwKjJZB5aL3OmgZx8AtaIh/
         1/tW1SBoObpFfNMLbfmeR2/kukX4kHzCOhrZvNSvDrqJGdpUVozkYuo4ToLEn0ERkMiL
         VrKCimMIhUjGSTtiXZ866d/Nlv+mdELfr/WFswBY8pzVi9r+iYQC/zCUKpvtiEPiH+Zv
         Xy0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G3c9X1LAFiFXKPYK0tsScKuMRVbcM2Hvvc9hBKYF0rs=;
        b=IrQHRx++tY5igfH3WDMmoUo3JEhZeuaz8YyPI3n/OtVnGQ+Lqy6uDNpAICxorZh04V
         hZuPSWGQmocQyLefVuwAzX0gq15B1BQsP/1x7noSwEEYZd7D3KVmthAjjM0m8ZvFViaD
         ROzbkxvSLXxsSTKcYuhZbMqKk8b9MR3Qi/bAM8SnuUxGmP0uhhoUawgXGriDVP8rTr0s
         KqjtWmVUmou/9uR7EsVvewv5hwambZqp7aKFFSNb+/zzkHhBX7SU/QJixQpnVPQFRaPk
         IR4KD2gdEI9HxgW9igT+IoNHo1ASknGgOSV2vDYaF4ts7kixAI0Z+GzE5tpyZ+DH3971
         z4PQ==
X-Gm-Message-State: AOAM530o0Jx8bvm/JPQm5KoHTA/F+Jz33aoi563UMGK3CB8O6wTFD7Dr
	PkUIVsYBqSyAkHkZENCFISc=
X-Google-Smtp-Source: ABdhPJxmKU5GIvR8A2g1nbNgAET2/PCD8wnCKJ4VZo3SbMIFzr7/IsnQ//yXnmdUW803sN/z7g1gyg==
X-Received: by 2002:a2e:b541:: with SMTP id a1mr8752796ljn.225.1625080417095;
        Wed, 30 Jun 2021 12:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:865a:: with SMTP id i26ls642261ljj.1.gmail; Wed, 30 Jun
 2021 12:13:35 -0700 (PDT)
X-Received: by 2002:a2e:8e74:: with SMTP id t20mr8782402ljk.397.1625080415901;
        Wed, 30 Jun 2021 12:13:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625080415; cv=none;
        d=google.com; s=arc-20160816;
        b=0zHl6iAj2bAbwW51EfXVFiTBpB+ocfa8z0LvnHdNNqvclWdt5HE0fC707ktec1SSuz
         e0WQ1qQwhgFM+r8AXWhO/0YaMvP/cqJNVTtDJCoO3FVVxDyXshV+YZJ98adLyFTXyMd6
         U0FBKFNudQaebGwgrUmKwTxQ5D401jvHe2RuLw4+gf6d3dbe3hUAf3EAteB4GQ+Yc2z8
         6vblhN/d6GLFUqrcV5yNfvpOUVrk8kmZ2Uner6GKiJfm42Aly6/39ZEnsz4dbK5wcszv
         ccwBCjvFGGKKClTwTBxY63kaW0XG+ymKbHsybMyPHcuBjYsa42bgUKelFVnrmrC+74sR
         LVyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LwMx6mpf58K+dt89atcRzUa+xJG7iS/9NXSnO3QAijk=;
        b=dRmBHYIquZ0nB03ppuIzHOwbEzk5QXiJe6AKH6qzZBwSA6iSlcgQM/RvZ21cwxJ2LI
         G1fjzjK9QtYNtROfhmex38aSDHy8/1RE2uKxwh85bzV1Sc+OH9HGqbwJcAmA+YZMB3ya
         xaGxkKzPaC8B639gTUZ/C6kg6MTlme8CgyGPiZ5Aw5Xsk2oHgxd9TmcmsHqkvFYRajnA
         /4FWRlpTIbAEQfBCFOcOyvAzJJ5wMdDb6rCIUSkLSgAqGcI8pvfvtLmFrxSqeFW8HiAQ
         mPrA4hmGV1vIwT4O+MyqB9dJ7QendKqQgKuyKh+JqiuFmnN/10ryllNCZ5FI3d0VgdCK
         W7uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r7y6xbzz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id b43si695084ljr.6.2021.06.30.12.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 12:13:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id m18so4988280wrv.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 12:13:35 -0700 (PDT)
X-Received: by 2002:adf:c18a:: with SMTP id x10mr41309800wre.193.1625080415431;
        Wed, 30 Jun 2021 12:13:35 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:8b0e:c57f:ff29:7e4])
        by smtp.gmail.com with ESMTPSA id o20sm6991115wms.3.2021.06.30.12.13.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jun 2021 12:13:34 -0700 (PDT)
Date: Wed, 30 Jun 2021 21:13:27 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: yee.lee@mediatek.com
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	"open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
	open list <linux-kernel@vger.kernel.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v3 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
Message-ID: <YNzCVxmMtZ1Kc6XA@elver.google.com>
References: <20210630134943.20781-1-yee.lee@mediatek.com>
 <20210630134943.20781-2-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210630134943.20781-2-yee.lee@mediatek.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r7y6xbzz;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jun 30, 2021 at 09:49PM +0800, yee.lee@mediatek.com wrote:
> From: Yee Lee <yee.lee@mediatek.com>
> 
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
> 
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
> 
> The penalty is acceptable since they are only enabled in debug mode,
> not production builds. A block of comment is added for explanation.
> 
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>

In future, please add changes to each version after an additional '---'.
Example:

---
v2:
* Use IS_ENABLED(CONFIG_SLUB_DEBUG) in if-statement.

> ---
>  mm/kasan/kasan.h | 10 ++++++++++
>  1 file changed, 10 insertions(+)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..6f698f13dbe6 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,6 +387,16 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>  
>  	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>  		return;
> +	/*
> +	 * Explicitly initialize the memory with the precise object size
> +	 * to avoid overwriting the SLAB redzone. This disables initialization
> +	 * in the arch code and may thus lead to performance penalty.
> +	 * The penalty is accepted since SLAB redzones aren't enabled in production builds.
> +	 */

Can we please format the comment properly:

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 6f698f13dbe6..1972ec5736cb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -388,10 +388,10 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
 	/*
-	 * Explicitly initialize the memory with the precise object size
-	 * to avoid overwriting the SLAB redzone. This disables initialization
-	 * in the arch code and may thus lead to performance penalty.
-	 * The penalty is accepted since SLAB redzones aren't enabled in production builds.
+	 * Explicitly initialize the memory with the precise object size to
+	 * avoid overwriting the SLAB redzone. This disables initialization in
+	 * the arch code and may thus lead to performance penalty. The penalty
+	 * is accepted since SLAB redzones aren't enabled in production builds.
 	 */
 	if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
 		init = false;

> +	if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +		init = false;
> +		memzero_explicit((void *)addr, size);
> +	}
>  	size = round_up(size, KASAN_GRANULE_SIZE);
>  
>  	hw_set_mem_tag_range((void *)addr, size, tag, init);

I think this solution might be fine for now, as I don't see an easy way
to do this without some major refactor to use kmem_cache_debug_flags().

However, I think there's an intermediate solution where we only check
the static-key 'slub_debug_enabled' though. Because I've checked, and
various major distros _do_ enabled CONFIG_SLUB_DEBUG. But the static
branch just makes sure there's no performance overhead.

Checking the static branch requires including mm/slab.h into
mm/kasan/kasan.h, which we currently don't do and perhaps wanted to
avoid. Although I don't see a reason there, because there's no circular
dependency even if we did.

Andrey, any opinion?

In case you guys think checking static key is the better solution, I
think the below would work together with the pre-requisite patch at the
end:

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 1972ec5736cb..9130d025612c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -6,6 +6,8 @@
 #include <linux/kfence.h>
 #include <linux/stackdepot.h>
 
+#include "../slab.h"
+
 #ifdef CONFIG_KASAN_HW_TAGS
 
 #include <linux/static_key.h>
@@ -393,7 +395,8 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 	 * the arch code and may thus lead to performance penalty. The penalty
 	 * is accepted since SLAB redzones aren't enabled in production builds.
 	 */
-	if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+	if (slub_debug_enabled_unlikely() &&
+	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
 		init = false;
 		memzero_explicit((void *)addr, size);
 	}



[ Note: You can pick the below patch up by extracting it from the email
  and running 'git am -s <file>'. You could then use it as part of a patch
  series together with your original patch. ]

From: Marco Elver <elver@google.com>
Date: Wed, 30 Jun 2021 20:56:57 +0200
Subject: [PATCH] mm: introduce helper to check slub_debug_enabled

Introduce a helper to check slub_debug_enabled, so that we can confine
the use of #ifdef to the definition of the slub_debug_enabled_unlikely()
helper.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/slab.h | 15 +++++++++++----
 1 file changed, 11 insertions(+), 4 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 18c1927cd196..9439da434712 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -215,10 +215,18 @@ DECLARE_STATIC_KEY_TRUE(slub_debug_enabled);
 DECLARE_STATIC_KEY_FALSE(slub_debug_enabled);
 #endif
 extern void print_tracking(struct kmem_cache *s, void *object);
+static inline bool slub_debug_enabled_unlikely(void)
+{
+	return static_branch_unlikely(&slub_debug_enabled);
+}
 #else
 static inline void print_tracking(struct kmem_cache *s, void *object)
 {
 }
+static inline bool slub_debug_enabled_unlikely(void)
+{
+	return false;
+}
 #endif
 
 /*
@@ -228,11 +236,10 @@ static inline void print_tracking(struct kmem_cache *s, void *object)
  */
 static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t flags)
 {
-#ifdef CONFIG_SLUB_DEBUG
-	VM_WARN_ON_ONCE(!(flags & SLAB_DEBUG_FLAGS));
-	if (static_branch_unlikely(&slub_debug_enabled))
+	if (IS_ENABLED(CONFIG_SLUB_DEBUG))
+		VM_WARN_ON_ONCE(!(flags & SLAB_DEBUG_FLAGS));
+	if (slub_debug_enabled_unlikely())
 		return s->flags & flags;
-#endif
 	return false;
 }
 
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNzCVxmMtZ1Kc6XA%40elver.google.com.
