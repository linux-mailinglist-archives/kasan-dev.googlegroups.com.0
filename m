Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDOMQK5AMGQEFRZ5LOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BE8C9D6170
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 16:41:03 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2fb44181f04sf19623061fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 07:41:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732290062; cv=pass;
        d=google.com; s=arc-20240605;
        b=laUgT9/LdMaRtCvDwerLSV6SjnsvQj76N6RkqG6vRcu86IwBrDNuicshUV6ZPmdCOK
         rTMdbPAPdGjjGrsVhwsqH0/SqJro/VC5oEcTQtKpYqCnWN2jCMZpqq1M//haMbDZSneT
         GlACp+kvl/E06WS69IF1JO9B0CiVlAefetgWaIjEY9sVeC6cGv2XUrnElQYCkFdG95kP
         SfqKzh5V1uHP08FC+1Zu7/6f2KARq+0k5xYuXLJ0XgUlLfavwwguizbQkU6o9csA3Gqr
         4n+QpX+w+7biir/m0M8QL7HBFF+bKha2hR+s8Ve4iJzhFQnWXhYC1pwiTRCvFjkpHytm
         rvfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=AkD9/SaOAk0RBNqXEN+Dh1o0mYsNNN05f8m4JRy81ug=;
        fh=Jg+u0Njd6u94zS95X9MASsEk8rqjgiGxJb+IBLVwb8Q=;
        b=Jm9KjiM18cnxYmjuU+/rOsYCCAXvZM3R1rhlIgtki8pDQUOkT01wo7K5k7h8b0JASr
         ayWnZtQRz2/zayusNcVdGZHGQrp9DS0ciQP1GjQILZlvhDgH8aqcZURfX8ed4kTvMhPe
         3rHk3sR37/tUyK9HgWhB0zTWc4x2vc/5B3TFQ0/XD0XtUit8cfroosqOKT0Y5OgMO3iQ
         S6ElfqOtTJFvogirD1oiQnmTKmaL333dTi1SU4VNJa5WuC6A42ElI1zn5s44qSb6k7tz
         CBeCnfQviHwMC1BCuITpF9ITToSXqRd89yCqmUJ3R1U/iAV5gt8HJrrQg8fgmKHvhmTT
         JAWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wsp7IaBY;
       spf=pass (google.com: domain of 3cqzazwukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3CqZAZwUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732290062; x=1732894862; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AkD9/SaOAk0RBNqXEN+Dh1o0mYsNNN05f8m4JRy81ug=;
        b=hqH8+2qazqTv7RTr7kFpzMM3e3ZboNnifvpDIum8GwSId8+KUkhloQgr7LA195c0p+
         TG02bzTf18yPpfznn/rBaB7yzn/VZyd838vzxQvUOn1nzFb09GZHfYYgmMzH4nlY31RS
         PjM/5Pc3nzAHXXo3AY1UvkepAd8G5KmxBFK5PVi5h+pZAwzce20pu5jJF/Z77tf11xBA
         Dxo0WfLWXLedoUZpqtOO5B9MzfOwRv+tc7VrP87AQxb4oHPUzqbxxmzU/7pKoMTw8Tnh
         NNLRilRm7xF7AfB/g9tGtjJz+JmtEznQWGtYfv822/0AF52iISn1Ul0iNaQMoXT3F4mg
         pPuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732290062; x=1732894862;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AkD9/SaOAk0RBNqXEN+Dh1o0mYsNNN05f8m4JRy81ug=;
        b=cmk31R0mcJnufvyNyvSPHskNcp1sFs7RO7YeLewhrfw0C+Ziy2+YHJeikSgV4Ws4vL
         LWd1O7eSPwS5wYlSkU0Xnm5eP47xT3zmc2ShaDaWhYxaNxydtL49uEpulIjpK8D2NqYI
         +vboEOcd1NoqmIhzzNzr16slX+Mi1Gx2blkmG17fVTMz9X+dbsvhoqtnrHl/uADZGHew
         Xj9CwIMeNzAhydolt7aoVX8lvsIFfjEku7XMkl9vhwh6i/ipTT77oTE1aH5j7dmKjOyN
         u2m0/2QzDVu7j+u6c3+Cv53D4+ZeVX7A0s7yrc5hAFsEB1OxTt/Tu818jgF7JKrxbejG
         uESw==
X-Forwarded-Encrypted: i=2; AJvYcCX4HBhuY9yORU92mKS3EuOJsLisdYiTqpsnyPsK6o9rff//Rmiv0sbIBrQ9A9zQGJDcbuqo2A==@lfdr.de
X-Gm-Message-State: AOJu0YwFC5UCHjwWNsW7CWau6M8kmScdIZj/At/Ew89jVqT+j9m24Hjj
	4+E98+JNaf6pAtc4M5WPoxzLCLfkPSyp40aJwzRTVNW0MWQs1lPZ
X-Google-Smtp-Source: AGHT+IFGxkzYXj4Eo4hzZTKhIisRp6bTHkF+yCesvBLWid82PgwW/BG+HjXqSyzXXhnDkQucTZKrVw==
X-Received: by 2002:a05:651c:1589:b0:2fc:9869:2e19 with SMTP id 38308e7fff4ca-2ffa7194e42mr24840041fa.34.1732290061746;
        Fri, 22 Nov 2024 07:41:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b056:0:b0:2ff:a92c:412c with SMTP id 38308e7fff4ca-2ffa92c4334ls415791fa.1.-pod-prod-03-eu;
 Fri, 22 Nov 2024 07:40:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzP72VjwD7Ihk9HXCULmvn0/ZSsSugnKgSzfYZxUSM4tT+hg9I7B1klhexW9BsiadRgL+nOokNKEU=@googlegroups.com
X-Received: by 2002:a05:651c:24a:b0:2fb:8920:99c6 with SMTP id 38308e7fff4ca-2ffa7138edamr19149181fa.23.1732290059142;
        Fri, 22 Nov 2024 07:40:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732290059; cv=none;
        d=google.com; s=arc-20240605;
        b=ey7Ta5fAc1HnfcVvsht3439hJVGf6/H3grXJRETfKBegPp3dUaoyzd5YPjfVwkHdN2
         3cDpJ38LyhFgb1mPvBfeuQdHkru3TILyOQX/62q03Bw6KSU0BAwSIr/TbhiErdQytJv3
         68sw8f8aw9qfjHQ9d01HWGDAARd8KP1sl+0a7JEE3kHju+hUe0vLxH8MsubtLUXmO3B3
         jkBvi/m90wHF4KxlV73tQinLDaTdN1Nb3GG4pbU2sSFsrfBR/TmJNiaQnLgpyXm2dUt4
         ooozB1l021LXHneKzYEsJKF+OxUSZkoOjTnRg97YLIKGy0/e7cvGPQ1teT5S2p8LIvZT
         nALA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=xTxOguFgwy9tOkyUrOPXOUVNTctOk0wNzBQXya5aVos=;
        fh=vjgdDo8hxKIaSvpJNh2Gt/HgU9uWL7ZaXbdmqfIiE4Q=;
        b=eXJ4gT/9EVZF7OuviVv9ZYKpIfpE+7ImErNc9yvE9xK13a3d1+cQW3TRdzwLWuqzWo
         imwFczGl7ce9aBBQGm3Q8e8pm2kTP4893wKntcxgtticZUXeric3heS2qOdqLzQvIOJU
         yAO/AUezzohA4XESLC5SitCi7yf5nr7iOUzL6ZMPFDIdeb0gbtFAousLsNZHY/woRDWk
         VePrL2IOLglf/qcLZLAhDltd42/J2Luaxvd+pEFFnd5aZ2ht4wFzy0gP3RFOZmNCpYZB
         2XVOo51aWz8bVJLCjp3i8iPPamVy2D+jsdCEGNUXh8yM+7wwqKThpdO5CdEDsGiYH+fS
         Rgtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wsp7IaBY;
       spf=pass (google.com: domain of 3cqzazwukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3CqZAZwUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ffad99c669si67231fa.4.2024.11.22.07.40.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2024 07:40:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cqzazwukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-a9a1be34c68so140890766b.1
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2024 07:40:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU8Ljil1Y4bjmATsFet1GXxNhiVtJDDsnMtw4Q41mMy8m4A9+/1NPILwSSG7eHZVZG2RNeid/BuKgY=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:e369:a6f7:a3ea:97bb])
 (user=elver job=sendgmr) by 2002:a17:906:f194:b0:a9a:11e5:c8d3 with SMTP id
 a640c23a62f3a-aa509bc55eamr69466b.6.1732290058216; Fri, 22 Nov 2024 07:40:58
 -0800 (PST)
Date: Fri, 22 Nov 2024 16:39:47 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.371.ga323438b13-goog
Message-ID: <20241122154051.3914732-1-elver@google.com>
Subject: [PATCH] stackdepot: fix stack_depot_save_flags() in NMI context
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, Oscar Salvador <osalvador@suse.de>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wsp7IaBY;       spf=pass
 (google.com: domain of 3cqzazwukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3CqZAZwUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Per documentation, stack_depot_save_flags() was meant to be usable from
NMI context if STACK_DEPOT_FLAG_CAN_ALLOC is unset. However, it still
would try to take the pool_lock in an attempt to save a stack trace in
the current pool (if space is available).

This could result in deadlock if an NMI is handled while pool_lock is
already held. To avoid deadlock, only try to take the lock in NMI
context and give up if unsuccessful.

The documentation is fixed to clearly convey this.

Link: https://lkml.kernel.org/r/Z0CcyfbPqmxJ9uJH@elver.google.com
Fixes: 4434a56ec209 ("stackdepot: make fast paths lock-less again")
Reported-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/stackdepot.h |  6 +++---
 lib/stackdepot.c           | 10 +++++++++-
 2 files changed, 12 insertions(+), 4 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index e9ec32fb97d4..2cc21ffcdaf9 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -147,7 +147,7 @@ static inline int stack_depot_early_init(void)	{ return 0; }
  * If the provided stack trace comes from the interrupt context, only the part
  * up to the interrupt entry is saved.
  *
- * Context: Any context, but setting STACK_DEPOT_FLAG_CAN_ALLOC is required if
+ * Context: Any context, but unsetting STACK_DEPOT_FLAG_CAN_ALLOC is required if
  *          alloc_pages() cannot be used from the current context. Currently
  *          this is the case for contexts where neither %GFP_ATOMIC nor
  *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
@@ -156,7 +156,7 @@ static inline int stack_depot_early_init(void)	{ return 0; }
  */
 depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 					    unsigned int nr_entries,
-					    gfp_t gfp_flags,
+					    gfp_t alloc_flags,
 					    depot_flags_t depot_flags);
 
 /**
@@ -175,7 +175,7 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
  * Return: Handle of the stack trace stored in depot, 0 on failure
  */
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
-				      unsigned int nr_entries, gfp_t gfp_flags);
+				      unsigned int nr_entries, gfp_t alloc_flags);
 
 /**
  * __stack_depot_get_stack_record - Get a pointer to a stack_record struct
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5ed34cc963fc..245d5b416699 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -630,7 +630,15 @@ depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
 			prealloc = page_address(page);
 	}
 
-	raw_spin_lock_irqsave(&pool_lock, flags);
+	if (in_nmi()) {
+		/* We can never allocate in NMI context. */
+		WARN_ON_ONCE(can_alloc);
+		/* Best effort; bail if we fail to take the lock. */
+		if (!raw_spin_trylock_irqsave(&pool_lock, flags))
+			goto exit;
+	} else {
+		raw_spin_lock_irqsave(&pool_lock, flags);
+	}
 	printk_deferred_enter();
 
 	/* Try to find again, to avoid concurrently inserting duplicates. */
-- 
2.47.0.371.ga323438b13-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241122154051.3914732-1-elver%40google.com.
