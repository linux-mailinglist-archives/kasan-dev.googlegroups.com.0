Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQECRX6QKGQEU5TTBUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0858D2A7381
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:13 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id n207sf136501lfa.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534592; cv=pass;
        d=google.com; s=arc-20160816;
        b=cdkFdNitTcjCaXwQaf8QLeO94xcB9sXvmiLkQ46Ait3pAra0R6ysPVpyZTby/A7MTz
         WyV5V5cLYa90KPxDLY8yw7T19jen5+SXZ5nGmLJ33IJuIMVuRH+bR6k7tCLPSjFMXC2T
         A64LNSzxOgL9kzrcYU66sHhOcS8dXU2M2+impREhABd8yznkAFmFkIJwgImN04sYFj6n
         KEx3wOsLCketS45UNFOm7Yg0PCvgGPZs4BA/PpE6vmwm5fZrO2KnpzhNRKQuJKF8bxIO
         4ocGZIvGf1lxQDLB5Qyzlzq1S7BB9BbPg+UeGNN3ZNQovIiGIh5mC67cvyWSSPHfWvPl
         3vDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=am/wAPX0PfzK6JK8PgucCwLzIMa7bzGWhQKF8rR1N/0=;
        b=IRJZ2Blm9Eq23EXSoM/ZfOhA0u4CdEvJ7WSw5ykgUQ0XC5Nx+SG4eQDDdP+9oiKUii
         851Ayo5z1lyk2JkjoD0D0e5sEwPO1HpwC3QjWO/lTa6fNzpbJ3hPtkbX4qKvTpBZzuPN
         UrU50PaAhAsDtwadnLu7vKqXNxpPC6cskyg1STHzyxvAPMHFf5XqgKm4Yx5rEELcjbJR
         9B3A39j37b+nSq4Qo0arX/pUv61omPT9BLpSkBnViFfeRXOGEFKTX5Ca+yKmPb0/OwXK
         lHgZK8h31dKZJPntrMPB5GYM1eFDnWxN2Cv7tWcl41bOovNqyVfN7z/2nTjmBJg+jPip
         fAeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sFpQqhhE;
       spf=pass (google.com: domain of 3p0gjxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3P0GjXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=am/wAPX0PfzK6JK8PgucCwLzIMa7bzGWhQKF8rR1N/0=;
        b=DWcu8HxGfdRdWhk8aCR3x1HjaYcpxAKLfdyPHhAVhCBSQgP9doChEt5m0z1+Z7Pc57
         v+qIj08/q2uREupOxtazunS1ILAM9jeK4sv06JQLFOxKfUrTKHxmvA+OD/bAOvEL8NTB
         YkogKHj0L5M0LpwfloQOWGihPTq0Rk8xf/odk+sRwcBIBS5yJVBuWfCvoHoOsxzTDKD/
         An+53kEKBh26Wt4jv32ZcAQuSGEbdSwL1ePeBE017RfcFIfAl4WHYAzbWpir5eCiCSmG
         CywVyU4GOQRk3DY49fJqP8zsunql/sAl92wuN76RZGcA99NYQ7aX3DChVpoMzkI+pIL2
         OZ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=am/wAPX0PfzK6JK8PgucCwLzIMa7bzGWhQKF8rR1N/0=;
        b=Dpc16oyVFAHiiIkDFJ1cq/+G7PTD8PcXtnIVVTNTaH5O5fCue55mvn9h+1WD+ru5wb
         2th97zKfg7UhCJcAl0p4YBM0R8WyMdkvNcq812p0FNDglCkWhn3azTnn6YRMhfQR+KE8
         JKjK7lU2eFnUOo1gB0ode8uZnvy6ROOtQXlvaGCS2zror48aYFTSYFhNVZGQkBLaCqW6
         CnMO/0EGo/GUoJsA3zXkCry7XTp7daYQWC651xQw0eG0aIDPvH/kwcrqKs0+Sm486qNr
         UDcTz74TeAml0sICxe52fB0CcBB1N3v38I69mpBkRdW9qQJ6B+s6urU263aUbjkyRoCn
         p18w==
X-Gm-Message-State: AOAM533EB9NdhRXIT/zLTywo5RxqAbILWcXHI9GH6b5e2r+boaHfeHby
	1fHcowi03pRGHIN3CcGS5iM=
X-Google-Smtp-Source: ABdhPJxns28B9dW0fgvxka3l57Y+qmt7RxyU6PCs1UU8rB3MGBvIyRbeZFaSS/8QujTcuKxTDSiu3Q==
X-Received: by 2002:a19:ca4a:: with SMTP id h10mr90633lfj.110.1604534592617;
        Wed, 04 Nov 2020 16:03:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9cc1:: with SMTP id g1ls684248ljj.0.gmail; Wed, 04 Nov
 2020 16:03:11 -0800 (PST)
X-Received: by 2002:a2e:58d:: with SMTP id 135mr136276ljf.387.1604534591549;
        Wed, 04 Nov 2020 16:03:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534591; cv=none;
        d=google.com; s=arc-20160816;
        b=xfiTAHNtHZgaK7QgH+009StTEX7378roMpDhN2+KNNZ0Tv/9OjHO7HCzw6hbIEqtwh
         irYQgVOZKoe97nJ0laL81udvyKsbKggUOIpBM/N9036tcjEnH/HaMoTw01zG702Bh0KN
         uEc7na1EDoVe7GrpQT+cqeC8/DoOVglkImesB47Zd6zek/RZvJ7ek5Gk7pooZ61mNp0h
         mmV/QoNVVrf7lraQItwZptrrzU2XaDYvkWgg7TXMYdf+N/lyRIJGVjL0PvftIzM39JIl
         LfLaK4a1U8DQtTHiO3i++XenU3SnJLd/rQIm9Ig2x5jV4TcEAUAhbW6D6PLSfbiwhtdE
         e3bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0USIvWPWD+0X5uGT95blxzhIaksN6b9CBpQaBzMOnSY=;
        b=FdYCWBY9mQZ0BE8zlbXlsHXfIVw+zstd604xxLSFZWR7Gfs+cKrzsaLT0MxBXa7sbe
         xpmsvXo3bARlHVQNTP0kmHXGrHwKxdf5xvPxDGNurF3j8tjRuALyMNyBiATqn5ELw4EG
         A5e0iaptw8u1HNrl3fJps9vGjTXMdlDNvp0qH3nISYIYjeeEDzRUnC7z9rrmlJ4I6sQH
         F0mFMocn5asUJO4kO+3bgqqlqykEbcoLvG4/5UeAW/mjQFM9tAXwYmQErxeTXfjss9qY
         +bgVC2VzEuP5K1Wubfu+/i3BnNCgVypdrhsKKYbvB16sXj+MWQ8/NDTMe1s7ngWiYmXM
         G5Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sFpQqhhE;
       spf=pass (google.com: domain of 3p0gjxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3P0GjXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l28si128897lfp.11.2020.11.04.16.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3p0gjxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 3so68375wms.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:11 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4c4f:: with SMTP id
 n15mr475161wrt.137.1604534591024; Wed, 04 Nov 2020 16:03:11 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:25 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <3a3e6dfe3ad355bb5ffc3cc34769cb97aec650d2.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 15/20] kasan: don't round_up too much
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
 header.i=@google.com header.s=20161025 header.b=sFpQqhhE;       spf=pass
 (google.com: domain of 3p0gjxwokcviu7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3P0GjXwoKCVIu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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

For hardware tag-based mode kasan_poison_memory() already rounds up the
size. Do the same for software modes and remove round_up() from the common
code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
---
 mm/kasan/common.c | 8 ++------
 mm/kasan/shadow.c | 1 +
 2 files changed, 3 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 60793f8695a8..69ab880abacc 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -218,9 +218,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
 
 void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 {
-	kasan_poison_memory(object,
-			round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_REDZONE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_REDZONE);
 }
 
 /*
@@ -293,7 +291,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 {
 	u8 tag;
 	void *tagged_object;
-	unsigned long rounded_up_size;
 
 	tag = get_tag(object);
 	tagged_object = object;
@@ -314,8 +311,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 		return true;
 	}
 
-	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
-	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
+	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_FREE);
 
 	if (!kasan_stack_collection_enabled())
 		return false;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 8e4fa9157a0b..3f64c9ecbcc0 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -82,6 +82,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
 	 * addresses to this function.
 	 */
 	address = kasan_reset_tag(address);
+	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a3e6dfe3ad355bb5ffc3cc34769cb97aec650d2.1604534322.git.andreyknvl%40google.com.
