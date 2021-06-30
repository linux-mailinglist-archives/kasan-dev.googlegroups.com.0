Return-Path: <kasan-dev+bncBD4L7DEGYINBBAXN6GDAMGQEOLFARZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 655FF3B8417
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 15:49:55 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id e13-20020a37e50d0000b02903ad5730c883sf1677715qkg.22
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 06:49:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625060994; cv=pass;
        d=google.com; s=arc-20160816;
        b=sQ5INuYqloAuy2x/SUSotG2zmfZkTexOkUuGM207ervFZNjMy0vTBTmecIVsDbc8iY
         2s1V4DVqO4wSJyZjABPAHjvzNt7bOd1EupbUDWD7TpQFzoI9mWm4nIgrKa7qLi58R/kd
         ZtWGCf4HGmzWAUReLsws+SJousjL+B18/9GfnoF7fi34vJ8Ve4EOekGkitu1kd8MTyfv
         Wj95jooe+eSpgoTI0s7VEqEPO0bkxDn6PmSxtAMQhHauQAoeMJ+/iHh+A0RfE761xUQq
         VsfgbXtY0ss5YzhAuDpJ26ZlmQuGzO5gZ8MFkRlUTUo1HzgSNZDbHJMziG9mHM3e/vJE
         OM2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w6Y66Zhp5MmMPg0NybAxPMsWCmnnsttFzcJUe80RSU8=;
        b=0ML5D/3tz8zSrk7O7kc9gqLtHykxo7I6kwAaDQIi7ggUrZGwzGy1R13nenOMmIibpq
         2TsUXDbo88NNcytnvI51iVLTNW4CeiYz30uLYpOaXhqvA3MO/NKK5vlJkVxb29zmQxHj
         dynxNSfOdH7voqbNLzGe3m0Wu74WetUETY724fMVrMb+dKOGpzK+ZRht3QJDh7RCCroZ
         l17axR6o9yfkVyGnFkh6XgowND9V5F9FfNf+N3phP3XMnBsHG1yAsjcFVxECT44BfjzZ
         genynk9wBN5wwOtScYSpqDkqUkCqXFMmYluGOMyj0kL+Tx/VoEx4iWccANNdH6gSj25L
         EmPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w6Y66Zhp5MmMPg0NybAxPMsWCmnnsttFzcJUe80RSU8=;
        b=awpPttKhVDsw98ZYg3F49BC7QsdQqgFhelNQCvix9+tS7ldy1m4AAiZ/yf4awnZvVY
         XDiR4eOSNlKI7bkSVVQLinlG2qP9IzJ9q2FZaKmFzd3VWapoc6XYZct4ZOZhfFcTlaKb
         N8rFoBxi+KnfIjJrXKep4akUlL2u5DmFtX3s/ljpqBmHGS3dDIUk8XPnbbtVDCgQ8yxZ
         aoY18DICRbQG6mzh9q17qACPOibqw1b3DZp6VpoxkupuoUmVZ9oq/01B2rB+VaByewld
         dALO+u/Ca8t6w7duEsVAOvDccMf7MwLIYLn7fno2mLjHPYyqEzMyktdP44vANxLzu9E6
         Cibg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w6Y66Zhp5MmMPg0NybAxPMsWCmnnsttFzcJUe80RSU8=;
        b=LhxQCe6QEDNHwJyKiGklAyvHJBIVOPr04McA9Dg1vz9brHHjc0J9ShgYlOjjQM8par
         Eb1zOhDC5rMoNl4dISNicdlE3QcklmI5hxw++TRYm47oWMI/Dq9+JEwcg/+/WuoyBYPM
         itS3Loo2FODpG3ZaN3E7GcpA/GwB5p3QEB0K2/ZJti8yCD+7OBL9f4pt84vjPUK5IOsX
         NlKAB55qL7BdcQqNTo04DHyhauKKwbJNNavDe9bMu+qN/eRYTggv4cm9hlxcxOSWcHmx
         3t9aaG4yy+N0PsX2j9LXt2IWs4jlGHXbj2w6RaWIknG+tDR3H1GByafFeP4ulHRmyLPO
         d8Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YEGcFhDE0Trdqq5GnKpwzEENgnyW6l80aXVt//rjeEOrrrmNo
	TGCeY7Bg1gm2N9pXFp7BDCQ=
X-Google-Smtp-Source: ABdhPJyp0139tDDVb1ZXJT3DJhdfHd00NFGJ4Y/QkCj9ppu+hDuP7fD3mzR14X/RYEJEBQDr+Rr+lg==
X-Received: by 2002:a0c:e611:: with SMTP id z17mr11140497qvm.32.1625060994296;
        Wed, 30 Jun 2021 06:49:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ba97:: with SMTP id x23ls859047qvf.2.gmail; Wed, 30 Jun
 2021 06:49:53 -0700 (PDT)
X-Received: by 2002:a0c:b450:: with SMTP id e16mr36747800qvf.25.1625060993840;
        Wed, 30 Jun 2021 06:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625060993; cv=none;
        d=google.com; s=arc-20160816;
        b=unvPtuBy9Mx1ozSTWE1iIFdM/KFO7OY8sB0yiGpVcT+Vz3OrMIZVEGWqSQektuVz9O
         IbhD2IeLuRqlkhDEEppxVk9sQ3vH6+RsiaYwBintkJMDSl1FyOwT8f74I8Aqkevjua36
         S6wQ9nyq5xGOVQrhvfuvFdhp7ZVKhT20Dalv7QB2oO1KeVpRFPlfVQryOd7GV5oj06Et
         K2yOTFFktN8zSAc89Zg6l55Vy4Mv1xEzG3fINpShDyBNHVw5gYvK6yZp9H/S2QeYbOO2
         ZlBp6IdnL0/kt3l/c/jL3q3lL09APh4b+H4fxfpRI0Up/T+93UGLyln9CB1inLBAr0/e
         72nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=CTq4kUSBN6FWuulf2iRn9qGOuD0hjmBJj1YRqK7dUBA=;
        b=fg5Row8QR6Am7MQrdJZolL9I6YrTCBsk6XUnf0DkzsD6bR0ymfBAdGoOSlj/C3Z6Q0
         LANF+oLN4rZLAWLt3MATF6fm5++RlgeMG78G2PwgyBtyRd81PsyEZJB75cYQI6FC/9m1
         8pz1KgXSfGfROA0W3qAC+M0Jl9Uczl+9AV84DafQ2rP980WENuVgEBe7wr078/JTd9Ga
         bQh5fvue3EqMwysn8kwo5DWNEXY33neW0mL1g7bLqET+2CRn/23jJqmElxFPjwCJId4G
         BasOxXDIY5bU3MzWn7q/yM7yaGfEQC4tPX4t8M2Wqvw/Gip/GJiCjH1SX+4Ti9IiV4Us
         nlsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id x10si2586601qkn.7.2021.06.30.06.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Jun 2021 06:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e7d4bf8d56984e219f26e258a12eef49-20210630
X-UUID: e7d4bf8d56984e219f26e258a12eef49-20210630
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1842347633; Wed, 30 Jun 2021 21:49:47 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 30 Jun 2021 21:49:45 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 30 Jun 2021 21:49:45 +0800
From: <yee.lee@mediatek.com>
To: <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Yee Lee <yee.lee@mediatek.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KASAN" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, "moderated
 list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support"
	<linux-mediatek@lists.infradead.org>
Subject: [PATCH v3 1/1] kasan: Add memzero init for unaligned size under SLUB debug
Date: Wed, 30 Jun 2021 21:49:40 +0800
Message-ID: <20210630134943.20781-2-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210630134943.20781-1-yee.lee@mediatek.com>
References: <20210630134943.20781-1-yee.lee@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

From: Yee Lee <yee.lee@mediatek.com>

Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
the redzone of object with unaligned size.

An additional memzero_explicit() path is added to replacing init by
hwtag instruction for those unaligned size at SLUB debug mode.

The penalty is acceptable since they are only enabled in debug mode,
not production builds. A block of comment is added for explanation.

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/kasan.h | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..6f698f13dbe6 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -387,6 +387,16 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+	/*
+	 * Explicitly initialize the memory with the precise object size
+	 * to avoid overwriting the SLAB redzone. This disables initialization
+	 * in the arch code and may thus lead to performance penalty.
+	 * The penalty is accepted since SLAB redzones aren't enabled in production builds.
+	 */
+	if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+		init = false;
+		memzero_explicit((void *)addr, size);
+	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210630134943.20781-2-yee.lee%40mediatek.com.
