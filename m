Return-Path: <kasan-dev+bncBAABBS4JXKGQMGQEBDT77QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 628DF46AADC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:52 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id b14-20020a05651c0b0e00b0021a1a39c481sf3858397ljr.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827212; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Bf9HrxjrKsXlI6dIyLtoFIBhT7qkvn/o4Z88PcaDtT2ia+as9+51OCrfVPGcq84Ei
         aJw28mgnGV38PSBzFt7NCFAuCgQJa5aYiz99DLqzRjVBeD9Xqx1zfMAAukLPEXjKyQKg
         Ia140Ksj6x9en+/py0loJUZ62va5uMFVDIB0Dvcqkz7MNtnwHi3uGLBHUTt9elGdUM83
         jef97Av6ii0F0nkjwfHdemIkzMoQ70ZLR8S3RtK4Ucz2n+Dt/YLL6evCRR94eTYflayE
         tMhB4JcYzMOeJ9rStXOU1YcnDcqbzjnVw8ctZaU850B8JU9/aryEAyy9C09GbM5knMfH
         tb0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GHXiG3Q6+i0Ioto8zopyiwKg2lFXQEfJFGTQpCA/OZI=;
        b=FumQC8ub+/q41ftCeQxA6E2kg6ALD7oPPQSLyqDdatRn8RwHM1Kmf2OjsLDJayVpWU
         e0kvxRYElBoqTapkILT7kLe1pdPumUYnFJohvlS5WbIzlPxnIVPXXwG5RtjTzZnaHbgi
         SVic4yTauSB1uXmp2Y/MZ8KCd1qTJQAIlKRaU88vzxniB19amGiWnEw7YtuVXNePu15/
         LSEslaVIfzgopgyL8Kbf6FnWphZvn/oDmIH/CfeI705QWrQB/ZwMclY9Cyff+yLXXUeg
         +BXgrWQTu0SR39XtIgvZ3hy1j/eIcpQMDO32YQkSY1y7pN6fUHlvyiT8pQIXndc0PNat
         Hy7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPzPRi87;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GHXiG3Q6+i0Ioto8zopyiwKg2lFXQEfJFGTQpCA/OZI=;
        b=n+AV6DbEzipyoerboCqv7i1pQ7DzVy4vnboBdzcuV8Rd2YSf+zKm/aAUBb905c0rbD
         09j4cLSaHAelJm36v3zWsKtZ3/F3ESiOwamKW0zFwS/E+WxrIwUZGwEi0oexMxa1Zhnt
         jvDeWBnARRrEQenCulMGw2hs9dqwkY8Me5qOz1zYj3V8DwI5OyGQKMCSvmri09NLysRk
         wL4XUi7n7BjLRgQ+FSQ38B3Q9ATQpFzoweKD1eE1oav+QMnnS63qOkWXOzwrHamC7l9t
         P5xY2zqND/YYHM4t02v2HThKtjnsjozmoEcu0/IAqpJCjUQO7wy9EfbST0QWLW5LYMeW
         RGmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GHXiG3Q6+i0Ioto8zopyiwKg2lFXQEfJFGTQpCA/OZI=;
        b=IR15uzpBdTOObPwGoTFr19AlY4X2FAJesZi2jNccPM0QYxIerYpHjIj85oMgwYS+RQ
         z5tfnTqWd89oprWuibkrMgay9YQ/e/kTKO5YP3hZPL4F5xTSkjoYZZU43jXdukd8Nv1a
         LCfJD5OQy/euU8g1BPU6OSiWCZJ/essufWgLJqEitDanYm9oFFn0X4FiCWPXmkpNM40K
         qM8sr+44wVwqU0nnWDpeLHrvlf7aB1xTJZzlvjXfP8KUzKmUMMXlo5hcHQvy/D/hEFiV
         ZdOu+1/XQ5UEe5rguYxLZ0IR1c5T/zxlxpv6rkBvY6Np38NYhOhsVp6BBzL26WTxrjgd
         l9Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317Cg8nUYq6Ebk2BQyv+9tAXQrh5XOGYPcKvTDUI8KnlNrdkpo0
	aXaIMnqAGdZOcdObEpcHyPE=
X-Google-Smtp-Source: ABdhPJybXzm7BekE9RpEommm+Gq7oNBfbaCACpS8XerzgmBvLAAhH2kxc9S1wkPoYwJXvezOg9NDbQ==
X-Received: by 2002:a05:6512:6e:: with SMTP id i14mr4608541lfo.488.1638827211954;
        Mon, 06 Dec 2021 13:46:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8946:: with SMTP id b6ls2823320ljk.7.gmail; Mon, 06 Dec
 2021 13:46:51 -0800 (PST)
X-Received: by 2002:a05:651c:4c6:: with SMTP id e6mr38550697lji.505.1638827211021;
        Mon, 06 Dec 2021 13:46:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827211; cv=none;
        d=google.com; s=arc-20160816;
        b=TaZtvSB8tM5aghLzL5j4jRSbUCz2MJnzCaFUcJcJqgPjl9UrF0u1E98PRWVw0AfzUd
         SQLMFXbti96vSBOTcVyJYEiY9W9kNnTF0jihsUTDZaqeP++oS/K1UCt0x9BSMhOgmsCs
         UlHhEHGNMMfkpJkmS782WNdB6tMqX1WLhM3OhNMcGclAFihol1u0JmE5maI+QUId8Zvj
         wTW3btc4iTl245t+lQOZQAxsf4931Hl5ADmg3rJsJbw1NAjAIuBfffTLf9r9VPS+UgZj
         asLWRjqzLf8O2/wHyf8ee7afA7X5akl5wanIdAqznZkW9aUSETB5QiWdruWyah3udXUJ
         YLfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L9vUKL8lfozP3PwlMvZv+xcgDLHHdbGfzGfMbX3NgM0=;
        b=UECgugzWr4Ev3Y1GWUgudj7rA4+w4Why/c9/qzjf/CORb4Z8HWUtCC8G5bUFYDZBua
         e+PCquUrlCDqsd7YS0GCqr4TzLB17Cnz4G4SFO2C9IExeBmDjnpF7UP6Dne59nISwNjj
         UEyi5xa84uzhzZiWtqsC8X4NjgcK/gX7exO1ZVJe0w9esgy6YYGGcqwBuBijcNi8p9/I
         fw0jX4w+zG7GVrpnk4Ause+lWEmAsfbMEKmEIHN0eoo/ybjN+p9t9mUxEVq8w4z57ziI
         V3ClapAKdCXHeQvJfCgMIGrNnAayweZxipz5NB8w7j98Hv1Lk9WwW7YrGPZrF4DeakKY
         sT/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPzPRi87;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id v8si814957ljh.8.2021.12.06.13.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 29/34] kasan: mark kasan_arg_stacktrace as __initdata
Date: Mon,  6 Dec 2021 22:44:06 +0100
Message-Id: <31889507c217774d2b24fd45c63fdc4855a98c76.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WPzPRi87;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

As kasan_arg_stacktrace is only used in __init functions, mark it as
__initdata instead of __ro_after_init to allow it be freed after boot.

The other enums for KASAN args are used in kasan_init_hw_tags_cpu(),
which is not marked as __init as a CPU can be hot-plugged after boot.
Clarify this in a comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 837c260beec6..983ae15ed4f0 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -40,7 +40,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -116,7 +116,10 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
-/* kasan_init_hw_tags_cpu() is called for each CPU. */
+/*
+ * kasan_init_hw_tags_cpu() is called for each CPU.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
 void kasan_init_hw_tags_cpu(void)
 {
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/31889507c217774d2b24fd45c63fdc4855a98c76.1638825394.git.andreyknvl%40google.com.
