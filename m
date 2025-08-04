Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBB4PYTCAMGQEBJIPTAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A3A8B1A970
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 21:18:33 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-459e02731a2sf3177895e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 12:18:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754335113; cv=pass;
        d=google.com; s=arc-20240605;
        b=fbjCpgb6K+fo5kJruh/3zmE6OvOJfJ17xVjka3aOGBOU4QNyPwxKXxkJ1dmbNBXSkB
         EJuwPtue0SmEffH5VNNS5A3XPDsDkBLsBMgcGqczJvP8U4Etbg0zCHJKYyavYaJyFNJi
         2bSpzegNutdAvnI9bAh6g9bNXkWTsykMOTDzhm/51lc6WiLmXJ/Xs01kX2SyyrU8Yr/e
         ZdXnl8LkcYDftw4G9RfhEZeYfb2TbLPUBz3WwLheUe1Otkygjf43aGAe1nHq/x2ZzSLV
         i+ikbvEfLQs76yPEp0Ax2ytXeW2O44HNNrT5zXEiVEgO27EFyo5gN35uHvXbjdZFdNyN
         Y5VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=SCZ1p0bpcP1tWiKfltg4FUOfL1tAJQAJ1CVsj5hAhmo=;
        fh=8wh1WtRoHaIVkFfWIjH/Z4ovj3DbCRTmj+BBdX/LHBo=;
        b=D8Zrh4isH2gpzwiV48L8f/67yhh8QfUqXHGnUlHkcWX80ejACqRVdkYV8FbeZ6kJXV
         r0SWin3NjHLOpvpwXDg4DsVGICS93Io4jHeRqXgsDvlzsTnKHfRqk++YgxjPFavXdMm4
         4tebyc+A5Wivm2kRQapYAaWeYFCaGe7l5xhEV/Ap/tImEJSBp/KMk3iEf2hCCdsdbua+
         5SwlGTz89F+TI3ds+iUwYKVWZWBy9zaONO1Pjdo3d3R7nSMVpBBW7dqJgRD9N0z3lZwk
         N9VQbFa3eXJmU76v2yn5ptuZPIKEKwL5lFQ4m+lCEGWMJ74XSYTa5pmPvBlv7q3q8GXK
         OSFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uPXxlGJ6;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754335113; x=1754939913; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SCZ1p0bpcP1tWiKfltg4FUOfL1tAJQAJ1CVsj5hAhmo=;
        b=kk0dWI8eTC1UIFUKKzREoPKGKNlOq6EphEpibDCC3hW59O+5IkNlpUMZ/dF5kGn/hV
         rDVezkGPDS7wplaFaw6T3hXIM3QIPHUVWvWtV+fGeWU26vHcjb8stmMt+6F2N47O6Cg+
         Og+H1c9rWVbuYG/2wZE3cp6v/spGRtriCjR+/ByCqaXEb265+EcBTSjSIzf2NgD7FJyH
         lLgPGA/NOaR66P0Texv8zmCubut+w9bincB76kEqGCNmXV+wMGTVCunpNQfj0AlF5sZB
         XqpfmFJYog3+XF1dKVqaNCqFro0jLLG7tXx9uo28Qo7kIKxozK2sZWSKMbCvBiKi7H8q
         KBqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754335113; x=1754939913;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SCZ1p0bpcP1tWiKfltg4FUOfL1tAJQAJ1CVsj5hAhmo=;
        b=EVH+hj2jyYE1nNRtFy6r43LijiRNRLRh3tVm0ZYx2dKN3cg11KDjrj7nM89pDt0Dkz
         tmhO0NYiakRhgkBci/tJLcJ2y0Jg4U+rApder67bMPeSNWwTQ7qzi8zzGAPvFH0pLiel
         8R+pr3frbaj8XI+JLEVRfKOQao/WCu06uuooHDNmdPsyfGOrD8iqV3MIimXQWFmVvnV1
         aNRa/fMYpMFgqi5EilTJUIsQt9WHAuVaQ3ywyM0g/IuYJP9WejZg6An8sYV5OxTD/qRv
         +8Bh1Ft6hI0nkZ/n0isQUF134tngeIAjJAJDKD9UG3SJ3p+dFZGLeG6m5H6cyeZlpcPH
         2g/Q==
X-Forwarded-Encrypted: i=2; AJvYcCXNgKUVZtwTSpPLUFYxcS4daWZ+mK7ZJLOdnmfTYHHdkWXyqw75DPZ/Id/LVYKTUUkH4Sq4eA==@lfdr.de
X-Gm-Message-State: AOJu0Yz3djAXNr70Aw7KvjwkKBJ4MdMtiP0DzSPwki0lLFiMqTzgHg17
	qC8VuNM4Wv1djNGN/y2/alR/m6ctQYoXorM9Oe6UgWReMDKoOGGVJBQs
X-Google-Smtp-Source: AGHT+IHPlPObqSJT4fddhgW3uWBFJylcjt7JpIJMB6Y4QsQTivEXzUokgNX5NANVgIdPxAhI4nFjrQ==
X-Received: by 2002:a05:600c:4591:b0:459:ddd6:1ca3 with SMTP id 5b1f17b1804b1-459ddd61df8mr32122425e9.0.1754335112546;
        Mon, 04 Aug 2025 12:18:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfHRVXBRrTxkwTP9e5W91RUqth2BebwnB/wnEqoO9nQ0w==
Received: by 2002:a05:600c:34c5:b0:459:d92a:8496 with SMTP id
 5b1f17b1804b1-459d92a872bls8946685e9.0.-pod-prod-07-eu; Mon, 04 Aug 2025
 12:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqEOu26GpC02u5pgabxe6pSBg5pwzEDowcv+Qu0yjcUqE8BQLeVueEdn9kFdlJOT05xZoGwBoWVYY=@googlegroups.com
X-Received: by 2002:a05:600c:3f12:b0:458:bc2c:b2ed with SMTP id 5b1f17b1804b1-458bc2cd20cmr76828545e9.7.1754335109845;
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754335109; cv=none;
        d=google.com; s=arc-20240605;
        b=OJW6jbIjLpjCNxvz9Nia1xs1VFPxUiLJLqz442lJI5nvKO90h/VViFtSBMxfoAwgMU
         WqqJmbOP6AA2mzJ0TBz3eeg0U1lbmxEPtYwaOtiJbZ5D0QWufWCVqvaSvb/o0LvSSM6t
         uhyw2Ca9wPZimMu/wluM+KbTmaZ6pOkca9t5U9l5mDY2ldiZjwQ+JhjN8oT+AUuqHqp3
         5yG55gysvozlO4vQ6fja9gV/m+jdgTKFLz5uSraVu9Hbeyov03eOEbIX/eiAYxAQAXYE
         wZFfZYLQi4lH2KuGW+lfblQwVt9Jm5wecUqImFtBgpgOQpVgo3KXhFOokUE8szHvMDdU
         0qQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=L+ElZLVKoAO1zlP8cjrF+LYIULpb9l5O5jbMVWAEu58=;
        fh=/gc4Sp2o4FjUlN/tUkOj8djaK0ZVoTQIYXwaoCVfJWs=;
        b=UuM2LHXJOf4YIP+by+asEAYlhbyJc/Cu2tD0bZcd9LaDc3wxCmlZTOqm1O3x59286Z
         kfAeZLODeSbS8CaFEJh54YUJwlUNGFO8T6UEkNgpmeSYOox3JLayHbMwQG+aYkJmHoGD
         3/bMZb207Pf1HuAikJ9mBJd58972by/I2XH4iEXNCaB7tju8NOfPVhEk6uDjFPNZTJJl
         CJTVwwTq/UjTVHpo6RfPtB4uki7Xan6RKD8xiO0ruuR1zAYTQnlYCt0AKto85fNAeOhD
         9Nfjl4eL+n+WwKN/xk/4n7RQVAvh3FPPWoUCCtgDXE8SDzOetm8sOdV3wROKCrpln8ER
         5Gpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=uPXxlGJ6;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c3ac122si133021f8f.2.2025.08.04.12.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-458bf57a4e7so225e9.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9xQx+Q3X6VPDZtuBaGy4bQDNLxy9S7DKJZE5yONTrARRMV1SzAe71GTzUIuabraEjA9nXKuCs0io=@googlegroups.com
X-Gm-Gg: ASbGnctHI5J4y+gepPwEF+7QCquQi7pgoU876y8uwrmhttpjsaEm+3Ko5ibxptY8PE/
	RPmYHw7x1+mU06bhZ3esoJ63+vhiMKgGp5VOpDFqizbh60Tik+c9G3ig+8r2Z8z1InKO5yqxp20
	xDNGg4TTKVugbmGIVeHFJgo6i0AvR9NyicayGXPQgbmQ9igmEQoKmJRr866vqeVx5de8t6Tpj70
	jPyhdYhVX/85fFnMzkPolgSwR6eeK88tk79fEDDk2Uuut0gvyUj3QbDK1c2moDNEVU0JxHw7XA7
	0u86YX0SyOOh2XteaE/z2+6e3rIWTchyx7hNTRlcvOc7x/caAo6We+Harf/3RaANu5UXOXwbibO
	1YcurVd4nryPM9s/0qGpHbg==
X-Received: by 2002:a05:600c:4f0c:b0:456:e94:466c with SMTP id 5b1f17b1804b1-459e162c21bmr99265e9.3.1754335109094;
        Mon, 04 Aug 2025 12:18:29 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:2069:2f99:1a0c:3fdd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b8e0bfc79fsm6386856f8f.56.2025.08.04.12.18.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 12:18:28 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 04 Aug 2025 21:17:08 +0200
Subject: [PATCH early RFC 4/4] mm/slub: Defer KCSAN hook on free to KASAN
 if available
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250804-kasan-via-kcsan-v1-4-823a6d5b5f84@google.com>
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
In-Reply-To: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
To: Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, 
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1754335100; l=2111;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=rDvA4L4QbNOZZHJ9ypWKaY7n7K/aeq1dGeCN1JjgQg4=;
 b=BNMFpmS4euz1y5tN47fZ/MPB/oBGEwflQjmjyeX1N1RVfc1GB9ZCh7BojwIDDdkpsHaV00kuS
 UgRf/ZcDTKmDULwqSbKBaJxSEXdp2iwg5oMuT9N60I9e/Fr6RrmgtHO
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=uPXxlGJ6;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::336 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

SLUB calls __kcsan_check_access() in slab_free_hook() so that KCSAN has
an opportunity to detect racy use-after-free bugs, for example by
delaying the freeing a bit and watching for any other accesses to the
allocation.

When KASAN and KCSAN are active at the same time, and such a racy
use-after-free occurs that KCSAN can detect, it would be nice to also
get a full KASAN report. To make that possible, move the KCSAN hook
invocation after the point where KASAN has marked the object as freed in
KASAN builds.

Signed-off-by: Jann Horn <jannh@google.com>
---
 mm/kasan/common.c | 5 +++++
 mm/slub.c         | 9 +++++++--
 2 files changed, 12 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ed4873e18c75..3492a6db191e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -263,6 +263,11 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 	poison_slab_object(cache, object, init, still_accessible);
 
+	if (!still_accessible) {
+		__kcsan_check_access(object, cache->object_size,
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
+	}
+
 	/*
 	 * If the object is put into quarantine, do not let slab put the object
 	 * onto the freelist for now. The object's metadata is kept until the
diff --git a/mm/slub.c b/mm/slub.c
index 31e11ef256f9..144399aebdc6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2311,8 +2311,13 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
-	/* Use KCSAN to help debug racy use-after-free. */
-	if (!still_accessible)
+	/*
+	 * Use KCSAN to help debug racy use-after-free.
+	 * If KASAN is also enabled, this is instead done from KASAN when the
+	 * object has already been marked as free, so that KCSAN's race-window
+	 * widening can trigger a KASAN splat.
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN) && !still_accessible)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 

-- 
2.50.1.565.gc32cd1483b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250804-kasan-via-kcsan-v1-4-823a6d5b5f84%40google.com.
