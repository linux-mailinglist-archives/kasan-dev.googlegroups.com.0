Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZO4U2AAMGQE656QH3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id CCFD82FF099
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 17:40:06 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id o3sf2139106pju.6
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 08:40:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611247205; cv=pass;
        d=google.com; s=arc-20160816;
        b=LtJP4kKJIxlHIPADEgQ7Owng4atY5j02tUomu7E0GMmPTl5PP0cEGa50LcB2ddUJ1K
         m5asEtZhT7Ob8NSU2ksxTA8JLjXK5NhMBngMiVbbdtHbiIqw3yCEg2+LlaK5WVljnt62
         nyiMBoLUICxhLsyTbAWWs1yZQPL5/YP+kzCY29PtpyZKtA+yEjuniiWTOyLFDqaX9gXj
         ME7fTkRTinaxrXGF0RnhynvrjP/7GibaiwbSgXXVcu3N5oet3rBC/XjhTeYEAuYo2GcG
         7/0adjWsEKbbE91SBHzsaX5fm6h1IlhTEmZJdiKbV0EfrUXBkLTWSkNjeN9r1Dy2QPfd
         G5+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3RkbYo8AgLIVWX2N9iwqFaxEcKetRzqzdZsYtCHNU7o=;
        b=p5Z0skxf2d4mc6zCQ2rTci3HgdZFxhsvh+ZR+nRapzXwnXkpIG22SyabfPcj3UcAqq
         2viOo/oA+UyltFF/Hv0T4XLrhmtfomALl3i+oTUUJiA/Vop9cVQU2dzUIza1aTXsiXev
         zEMr3mKHXf6INpuuv91IPhg9qIhHMXy2eh4/KCi3KLEok1Jsco4KdO6hvn2UttP2UKLw
         001KM7VZlgekKFd6P02TyFS0iS/depctyi0ZqIcCDxDd9fhevXWGuUsg4zvRWs7CKjql
         uA3N0ktokUBUX3YffyeUeXqUHT1aNldYjhRftTqpeQCnaVZEJxnkIWSjFnNSfwItjSIf
         GwMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3RkbYo8AgLIVWX2N9iwqFaxEcKetRzqzdZsYtCHNU7o=;
        b=n5QSeur+pId1Q0S4ymWzLfTbz0oNNshXtJyJ74KHsFfIbSGF4qNDmzqU2BVaEr//Ol
         k2JWg39lHtRGTqNIqJBYHNigz1jhWUSs/U/ZQum/ZEFPsAK2eSaqD3Nk7ZJH1P/MPJ+P
         m99wQE7zbd2/HZJlet1dYkCzG2UkLqxom8Ar1BilhdmmtUmIqw70iIso+7glSAIe/V1O
         xzlEzeMCDvy/cRfoP91+3h2zx8gRKOSDFDxd8OhD2vDnM5ElEX5+zyJZYnbGCzCOK2nT
         X7dagTwXbER7byoQw5f+3/WRAnL8xMmyLyay+yr0UvOkOrIGIhlNVcgw70Qx+bVPOHR6
         xwJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3RkbYo8AgLIVWX2N9iwqFaxEcKetRzqzdZsYtCHNU7o=;
        b=sUsg/h6Xmwc76ouLh/8p7hDyunZPDsJPLo+LBKT1mkL6L7mAePWzRtQVxGvNYXQWwt
         amR/I5dZF4TspJ9HRQ2xUI0spaWvZooGdw4sn20UKHYM0Oi8yCeiYyJhAdaxn+oov3xi
         J35Othl67vktRT5wtNmIeo9r75habJa7o1up/2AXVG9TuIUoiLXZToOAtAE/ixl50GlG
         jC4xdO1mjDkb/y+Bvees+7ruE0Io/I8oJSzrtxlXzovB+/MyK298wWWQm3MBm+bEIPT/
         tYx27D2ylh7/sa2cDh6gsn5fWfe1lDXOfS4bivtWpQRShU3mxlhl2753DjT6aMz+hkoB
         KdHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eqMy92PPVvfc+cU8xQqWEeLPalrt/4bghrlZRwTj/Ey6pMFkV
	aVVeYGBsuvQr0fxmDWVbOlQ=
X-Google-Smtp-Source: ABdhPJxmnRI4HcLD5gOWoXWZRkvYdpsPG7LiZdBIfDBg32pZLr6xfPvkn0cc76hxAkS92mr8FXPoVA==
X-Received: by 2002:a17:902:44d:b029:de:c063:85c9 with SMTP id 71-20020a170902044db02900dec06385c9mr210255ple.35.1611247205481;
        Thu, 21 Jan 2021 08:40:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls1048899pgu.6.gmail; Thu, 21 Jan
 2021 08:40:05 -0800 (PST)
X-Received: by 2002:a63:ef14:: with SMTP id u20mr103224pgh.93.1611247204891;
        Thu, 21 Jan 2021 08:40:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611247204; cv=none;
        d=google.com; s=arc-20160816;
        b=vSrG1DMY43LO3764YcB8Fef13hI/+6RNYs92+arKQs/mxL1tYrL+f8Xi7L5xyzWvSH
         ZEwvld9BQT4L16ieieOIRgk75dZIgM15K/WQUhT28NALfPcsSVoNYFGPoidE1nFtDBwc
         xJCBnV/kHyigFWmVEDUJYEn0eqwHvLHLSJhCvSx5+wXtVWuRh2AHQTqR73jGv3QQde8p
         IrdQQmg5jRzNeVaOBKuYollTVg9W+Ysz7xcHa0P3i7wXoFb6Xa17eBOhp7SkdK9TWyCm
         BdFgocsj5B6zgSLr2fFHqDP0nle5jkN1R5Ua2vI/E6BiaFAzVBhTez/VL9bFMh/8ZqvB
         Jcng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=9xhmu6HAmTITAYsooFVlMQJffhsyGEIHDl9N18IikRQ=;
        b=UjHb1ZWRWURNV6hJA6FSiD8m7/9you1gOcxjIGE3P/8jrAmm6t1Ul8Qw4EpKYhxOx1
         JzV6gl6KRWfP/61CZT+V+wcjJaabAPXzWIcDDYPdLkclZvsA+zdyvAPP3l4Ef6JGEpj3
         uau3ycwTA6bhEQwC6NxzYHkfyJNfbWgdRJNXjAVaYCECKcIgIrKVRmxcjsY1BaLAYF0B
         CUqJN2yi9diOcWL2cUxDBEU6zQU2E5prUn3Rjduj2AdAuPnXpQU1LsqYvamXGi6OgeL8
         2abNitOIYdbGf8WFeXV+eLbRzfHxp7yVxF+xLos32yuQj22/M2dWDczcsYPdkWn4FsQm
         +Shw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d13si313331pgm.5.2021.01.21.08.40.04
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 08:40:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F8111596;
	Thu, 21 Jan 2021 08:40:04 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6D3BC3F68F;
	Thu, 21 Jan 2021 08:40:02 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v5 6/6] kasan: Forbid kunit tests when async mode is enabled
Date: Thu, 21 Jan 2021 16:39:43 +0000
Message-Id: <20210121163943.9889-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210121163943.9889-1-vincenzo.frascino@arm.com>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Architectures supported by KASAN_HW_TAGS can provide a sync or async
mode of execution. KASAN KUNIT tests can be executed only when sync
mode is enabled.

Forbid the execution of the KASAN KUNIT tests when async mode is
enabled.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 lib/test_kasan.c | 5 +++++
 mm/kasan/kasan.h | 2 ++
 2 files changed, 7 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7285dcf9fcc1..1306f707b4fe 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -52,6 +52,11 @@ static int kasan_test_init(struct kunit *test)
 		return -1;
 	}
 
+	if (!hw_is_mode_sync()) {
+		kunit_err(test, "can't run KASAN tests in async mode");
+		return -1;
+	}
+
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
 	return 0;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3923d9744105..3464113042ab 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -296,6 +296,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
+#define hw_is_mode_sync()			arch_is_mode_sync()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
@@ -306,6 +307,7 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging_sync()
 #define hw_enable_tagging_async()
+#define hw_is_mode_sync()
 #define hw_set_tagging_report_once(state)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121163943.9889-7-vincenzo.frascino%40arm.com.
