Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK6DTCEQMGQECMRVLRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B1E6A3F73CB
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 12:55:39 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id d12-20020a056000186cb02901548bff164dsf6498148wri.18
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 03:55:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629888939; cv=pass;
        d=google.com; s=arc-20160816;
        b=YmT+xkMCYNOHIoQeefJHlo1Wb+ds+KOxDMF1a1HSh5lNEAXukbmnh5AefhFPmHVZVu
         dU3+9ECcSrt35zLytgWz/lI9jBx02n3aBaWoOOwJyKd0BOlmaWWnFlkSbXC1e/rXq/Jy
         Mu7jU8kdVveTE1v984P63NmEBqJX7cYnK69E8a9xPiemEQ0w4RTnoQ3FdWIzjvMf9Cfe
         dh7bAS0KkiHbHYHnRFkCliCymCyByzJwzdV8AJzdQCHxIHli2gm0TeF7OXa+uYuwhYxO
         XdBgmoBpGbl7LBZKLzXPaUV+1wZeqRjq2H/VoZ8iuenhO/+ol5BKFNAqILddhmrmeutT
         Bt4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=3X/oC6IrjLqZO6r/KpbY1q/DVqs1VCw7vwjJEdFAXE4=;
        b=rem+QfEa4RjjfjvYn6nU2zux1gtNse3/xQ2+k2tZdPpqajIHyeCNATs2mni/+pbfje
         f4hjm/jozDTZcogCxbGDyBV/ek6xdcKA+t+MoLn0s1lZOJGaswpAvq9xBJu5b3rZKEE3
         86RTvwx8s5taKOmjq2+Avom2m6vDLjaWb8lgzc/2DZuvx0jKU4hT1af9qqKdvQPlY/tG
         JGZliJbAtzX2DwTxLCigmZu6DhNxuB2rwijvbgM8PJYvdX/AYy5CqRz6F82a6ixZnonV
         URCv9eVwFriax2mmn2oFCMhm6Nj7UtE9mTz3/rMiJUXjzlVvoO/4Txqecqmziyvz4clg
         lsBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EmPROQ7n;
       spf=pass (google.com: domain of 3qsemyqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qSEmYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3X/oC6IrjLqZO6r/KpbY1q/DVqs1VCw7vwjJEdFAXE4=;
        b=Y6/LFskCB8/jqogffwQY2MWR1Wl5XMR5PlacHr0DSbSSV5Nr0ZQh4kD0iw7V2MCcXU
         ex3YxE5gNhHsJ6FSAlz+XZ2poQ1X9WwEl8xbsgUyNh9mrvl3kdXksDgZ0Wdfnfec71Gp
         JqHgUPohV7Xyyd0+05nGXmBVulkuiFQp2OEDklExRArSsA0drdWOhCphAuRiNzRY1ehh
         CmDPvPz/gKOwKz5r8TLexgjDZJJkYfpZMaqciasEeQYC6N2fkshn6/jsEnpjhUuI94hC
         FyadIcDTlLrfc6hVZVyV9h6PzLQBB8sjUU/PLf3xQQZRetFqq32XlTo1/jKNflLzfw1h
         zUkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3X/oC6IrjLqZO6r/KpbY1q/DVqs1VCw7vwjJEdFAXE4=;
        b=fFo+CGjwMOL3sflVd1yIyChorrDOaB6iATPw3dKyNV9xRBayV3Afq/MnM6hNl/OTxG
         tM+aH0degNuBcm6SGOmZ+h7tS/7Y+cUl0Mv0dw7x25lpakPl9F16FqTKHJ9X3Rw4nIcF
         PMF45UIC9O51cQ0AIz/oRd0EsjiprX2L8PhHScLs7Qu9GxF2b9wJEaOeupIXSpGPIR3s
         +ZrPVYnWutuqs6yLXlCsjGj3ytnEpYF/1yqjvFkCr0AAAqIMJyNSdrVVmP/BJkM/C5Vk
         OYVk7/XeShxHVc68KXVpD2mSG/KLCx7GKO+fwtetEuqXuHshF9Wq2mRYfSps236VDt7v
         mDlQ==
X-Gm-Message-State: AOAM531nCGez1vz5C8CZGXxIGWkS2I66hjbJQo2ydYrj3qjuEmWZoJTU
	dGuRHEL9akIEuEWaCiEhVZs=
X-Google-Smtp-Source: ABdhPJy72qW4nQ3+Iyri64YLb1rnC2oN41XBC8G8+C7bEqct3FuMEDGjzYQmiwVnio9tiRHYiCd1Cg==
X-Received: by 2002:a05:600c:35cd:: with SMTP id r13mr1354311wmq.24.1629888939480;
        Wed, 25 Aug 2021 03:55:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cd8a:: with SMTP id y10ls2736156wmj.1.canary-gmail; Wed,
 25 Aug 2021 03:55:38 -0700 (PDT)
X-Received: by 2002:a05:600c:2245:: with SMTP id a5mr8668976wmm.19.1629888938442;
        Wed, 25 Aug 2021 03:55:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629888938; cv=none;
        d=google.com; s=arc-20160816;
        b=uHpIrsmo2wD/owE2Wu7DJ0mRIkVkjptT4VwJ0AhA8XTPWRmv6fOMoIZJgSX0p3VhDu
         gzIACQO8QCl86JLHZIeHY0C7O+WxGh7fLPYWJ+gpja2Y76GFgVaJK8V9YdSz9188UZJF
         rBg6TWU8FMITF/kQOGknCAv5nlb0MJA7rZYulKf0zkSxIOxJ192hRVGyLnqfyngbvQ0m
         hDZmycOkrmTzqueERAKO0pPueJA9HZzAKtjohcR0L4JcN0/ivUw9ZqFYPFn9MsVbhccU
         kqtGRDKFFfwG6ukE56U7FB8p/tVYuuNakloMZGgW0BLnzMk+hg01vtuVzTsrp22jBZrt
         bqxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=FT34ZQ0Ankpx01UihRk2kfWuKXz7jz0lwTbW9XPKkoM=;
        b=cxEjEqtxlKOaxN9aiRo/sShPjnUODlMgHYueB3PPYwVyAcim6HJAn9jb7B7c5UsDsf
         7bApn7IFLx0gZq2ohHp+ayJnfH3iltUBbovd1r2m1hctEwXBT8V9RozZUJWostzmy73H
         PEmGZz04RcMLaBK+mkuiPvlJmw7GOuZRT3fC8fA8kzVZqvMKIHgLDGb9nqdxtS8qlwra
         TgmFuD6T6Mm/80wn42XNAotmKkJCeI8gK8007q7r+Pw4Tc6gFWVk8XkCpRzogeIoLc2A
         6P/iIOQzDPD/jV37AOSurS83zhg7kkZrweToW+0/nnEIdcteA2fMUtvO9cVHGUiBDT32
         Q3dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EmPROQ7n;
       spf=pass (google.com: domain of 3qsemyqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qSEmYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w3si377685wmk.1.2021.08.25.03.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 03:55:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qsemyqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b8-20020a5d5508000000b001574e8e9237so2579607wrv.16
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 03:55:38 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2fcd:1452:4b71:155d])
 (user=elver job=sendgmr) by 2002:a05:600c:3b0d:: with SMTP id
 m13mr74661wms.1.1629888937741; Wed, 25 Aug 2021 03:55:37 -0700 (PDT)
Date: Wed, 25 Aug 2021 12:55:33 +0200
Message-Id: <20210825105533.1247922-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.rc2.250.ged5fa647cd-goog
Subject: [PATCH] kfence: test: fail fast if disabled at boot
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Kefeng Wang <wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EmPROQ7n;       spf=pass
 (google.com: domain of 3qsemyqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3qSEmYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Fail kfence_test fast if KFENCE was disabled at boot, instead of each
test case trying several seconds to allocate from KFENCE and failing.
KUnit will fail all test cases if kunit_suite::init returns an error.

Even if KFENCE was disabled, we still want the test to fail, so that CI
systems that parse KUnit output will alert on KFENCE being disabled
(accidentally or otherwise).

Reported-by: Kefeng Wang <wangkefeng.wang@huawei.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/kfence_test.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index eb6307c199ea..f1690cf54199 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -800,6 +800,9 @@ static int test_init(struct kunit *test)
 	unsigned long flags;
 	int i;
 
+	if (!__kfence_pool)
+		return -EINVAL;
+
 	spin_lock_irqsave(&observed.lock, flags);
 	for (i = 0; i < ARRAY_SIZE(observed.lines); i++)
 		observed.lines[i][0] = '\0';
-- 
2.33.0.rc2.250.ged5fa647cd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210825105533.1247922-1-elver%40google.com.
