Return-Path: <kasan-dev+bncBDX4HWEMTEBRB64LXT6QKGQEX5I3OKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B3CD2B2827
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:31 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id e18sf4653368wrs.23
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305851; cv=pass;
        d=google.com; s=arc-20160816;
        b=VYgJSUchKazAeYFXsjf5GmWxuQNRJVZTte2xH09js0N/e9JSuf79vyUh58WOGfMVkl
         to2lxSbTk+5o1xC0vTXXkZSbqwZSafkEZCgIA3KKQvXWAmUr5XszjfjA9vV7ddg56Yt0
         oE6FJ9PbMzgaRQOQAN6NobLG4PPLOftBm9i+wXlCDvQS0BrhPLRpgXGfBrrWLuSkJKsx
         cuE5jLhOhbPvWcGkj1Oi7owUGh4ZU50hyRJg1fTA3a4l8ava7cWz1k5s0KmBsjjNLSh2
         cCsZmxrxJfjIo6UvZAv6+b02MsnjsjNLwhiBvDxcwU9gt/Ax3WIEeF7J3z6oKAk8i3nK
         GfWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=W4ZCXNAPU/++1gh3UJzQNlsQgdXugLC/dgrPQ7CUyUE=;
        b=r0kXG0DUGxmlQgOL7kk2zwJ9hNgBrkAM2u4FoLmBFx5Kjc/sMv3RWQSQYaDuTO3en2
         kN6IMv+6vg2TqP99O/f5A4w4us0EAULAM+1LYO9ucD4pUF49J0HoWp69oJBHSzGEIMpz
         X7KshrTeCweinsernBfm4l5IGrBHeisuguNQFKla7Bzz4DBU83NW0aAygIc2zfnFPlVQ
         7kvuHgjDNLWRtumKluPV6OCiVPAnuFVJPXRFB3+PPSzK3aDJIghzocrcSiVwhod8uQXb
         MCFZGVDpyEX2EQm+Hf2pwLIQV+VPUXnRmyqxu7KFm2NrxpLae2M4o3ABhOBBo8QtVaCc
         YkbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HJ+JRP0S;
       spf=pass (google.com: domain of 3-gwvxwokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-gWvXwoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=W4ZCXNAPU/++1gh3UJzQNlsQgdXugLC/dgrPQ7CUyUE=;
        b=RrKcsJ8ifw2f+UJj9m7QDxKD8ERbveEHHYCmxQ4Gw5rZCbjTVcowqSEx6gSbUbhPQH
         CWTF2Jd9H9wBI+eNMybHewMqVVSePXBbCXWe8KbaUJLKcq+C9TZizP91N8kh3X5pPVYQ
         OtXTKtv06PZmvXuplkNQg06hdMosHLl5hbPN3/qz9wgwXf0GIK+Hffa0sD/obNiWkTRt
         TiqH6TH3p6ulPG64y2LDOD+n2fTEb8tU9jg0aJKuXchnq9u/M9ar3AD7PeJvbpplsUGe
         nFqZb6GQdltFV0AdCPidkG2jD31pdDPCVLQz5/yFzEiIn96QkXuFz1hGCKlR1p6XFPh1
         EBZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W4ZCXNAPU/++1gh3UJzQNlsQgdXugLC/dgrPQ7CUyUE=;
        b=pCdhXgjdsn4DTD70Y5LdHlqnUP6gXYdd3TZ3aPg/GDAofZJngRkJyu9ukPWWqL5ho7
         8ZDY9z30k2gqqX7weoxX6quxBcykem8XQ+k5ubE6jk35MATNL5tlE539KO+zR7Ms7fbV
         bTvl/+gx6NKt5bpdSaqXHpMiDbdl//CgRADthK6N2lFk68Ya7EcYugYfmRpEgVu1XD17
         s7y6E3A8/30stmHWUh79agj46SRAepDSwJ+r6bzpPawRI8BkQjtNdKzOWz8gP0mcW/fc
         QtYZL2ta8kqpBjqhXUhtzEwwwnzkl+c6h+NZShpnB20Am89WkfPMdiF99Blagx8J784L
         IElA==
X-Gm-Message-State: AOAM531AGhMV2gJ+yiA5ynzKcBoEa8ll2mc/kdaMFBAg3Vyl/trOBi4w
	/0lQ8HPGsPokD+z/kajXHAM=
X-Google-Smtp-Source: ABdhPJxoQ0vBeJXw5g15jnDThXhsGgn1x29Nxt4EnmFItWDUKVYAnmBsV8UJIzdet6tsBUmktu2gLA==
X-Received: by 2002:a5d:4a0a:: with SMTP id m10mr6368366wrq.16.1605305851431;
        Fri, 13 Nov 2020 14:17:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls3719281wmb.2.canary-gmail; Fri,
 13 Nov 2020 14:17:30 -0800 (PST)
X-Received: by 2002:a1c:80d3:: with SMTP id b202mr4575057wmd.139.1605305850401;
        Fri, 13 Nov 2020 14:17:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305850; cv=none;
        d=google.com; s=arc-20160816;
        b=o/tawbGrCPdlxgwPJO+PGBDkYohsY0FwnhUN8yLR5pFuEh4h0UoEZzgmXW2A9+dqK7
         QIcFqbD9Hw+mI9i7y0V3pkv+FJrE71rGFKY4+DnoFzROwd2tQmkci1dY0xZa2IVJn9Zd
         eWfbXVEWSLFelzTcH2jCbwFGLEO7W1jm3jtR1ReEgZZKMfcW4g5JRvXbP93nhrh7rsi0
         VRL1QJz1EeSf+mu7LlrO+QVyVVDC8cwbit555PXKuNSBn52XUsF3W49uqWQWP71Nb1at
         kIhQkgZ4+c3ky9LUNEj7uzpT68q6GMkwx+ItRgN6Dr1jjD5TFxqcTy5SKmLXrpIWABV2
         pkiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JnUxOJIynAj3uI1y+sO3DfMh7ir+WlJGNb++LFrX210=;
        b=YJ0P+aim4TXhYpl8jy1CmRse5UHwLvN2HAaEa5941G1xAQ0X5XszNpN3TgpB8fb2nl
         M8/ihtDEUyOKP7Mq1vvuFWnQMeLPSOzXz5eLtsLLeOpvcbK+tFw2ApExCIZKPrgEUdQA
         i3YsQYWsMMS4x74DTnwVdAQI+tyGCypgszVicRtIyHq02s5jVu3kqXCGTc8cMPuCeokl
         f/5leYDQks8E0OUnqcw7uYh5/tnc7yPP8O/QNY+r+56/rXFAbPnFeXtqbDDKzkdpuUKZ
         L1KbOA24rJkcNaDGKqnPX005X52xQZ4bh5z5n0yb/2DqEUY2oJTnP3pfNYkNGbsyHke4
         ICUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HJ+JRP0S;
       spf=pass (google.com: domain of 3-gwvxwokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-gWvXwoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id r21si363282wra.4.2020.11.13.14.17.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-gwvxwokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u9so4004582wmb.2
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:30 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:1f05:: with SMTP id
 f5mr4382666wmf.98.1605305850004; Fri, 13 Nov 2020 14:17:30 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:59 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <b167fd21b86e7d728ba3a8e20be4f7e8373bc22c.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 31/42] kasan, mm: untag page address in free_reserved_area
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
 header.i=@google.com header.s=20161025 header.b=HJ+JRP0S;       spf=pass
 (google.com: domain of 3-gwvxwokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-gWvXwoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

free_reserved_area() memsets the pages belonging to a given memory area.
As that memory hasn't been allocated via page_alloc, the KASAN tags that
those pages have are 0x00. As the result the memset might result in a tag
mismatch.

Untag the address to avoid spurious faults.

Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: If12b4944383575b8bbd7d971decbd7f04be6748b
---
 mm/page_alloc.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 855627e52f81..4a69fef13ac7 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -7653,6 +7653,11 @@ unsigned long free_reserved_area(void *start, void *end, int poison, const char
 		 * alias for the memset().
 		 */
 		direct_map_addr = page_address(page);
+		/*
+		 * Perform a kasan-unchecked memset() since this memory
+		 * has not been initialized.
+		 */
+		direct_map_addr = kasan_reset_tag(direct_map_addr);
 		if ((unsigned int)poison <= 0xFF)
 			memset(direct_map_addr, poison, PAGE_SIZE);
 
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b167fd21b86e7d728ba3a8e20be4f7e8373bc22c.1605305705.git.andreyknvl%40google.com.
