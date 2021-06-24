Return-Path: <kasan-dev+bncBD4L7DEGYINBBBGY2GDAMGQECSL2G4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D27A3B2DD4
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 13:27:01 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 7-20020aca0f070000b029023d769dcb9bsf88319oip.14
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 04:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624534020; cv=pass;
        d=google.com; s=arc-20160816;
        b=aYv3vG3Qlbno3N02Oazk54/0VDtS8qLRlBCvx/vbQkeAJLIwYlpxRxgHDCfkT9bbUL
         tRi6lx7xt56g3CmWO58+iWXwTKGefMChzL1PUPqsm7mXonxS1N4PTGRXGBkvHQEUxHjw
         HV6uj2HfO0Iub/aNvfhCrCVXGUA5+2E2/zY5mBLc2Z/PcqnKtf4v4xMeWpvB542QtMdG
         mmdmxMt1YoPfM4m0Tp/jEdfLUGcs9n4Efh2rmNrfXmbip/RGssQvtq4kAJlxGF0FYEqg
         Jty13XzCf5a1YyMrHrUB2Tvdc0l0EjoeZBUk+c7DyzOwYsrQ+ulXtE5XHDaawpwA53Go
         zwVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LQffLgt3qxbQlpDZ8jDabx1RqdnOXtq12K1FzDUazRE=;
        b=VCLoVg7yHlbqeBbqjATVf02rtrvw4wtx2nyXXMcxIOxr1FgV+jCLlzZgfCc1/YPJd5
         mINKwsGKtnrrzTosk/VZDLSDF8aPkJfepxZRiZS4Fjpu3SiImYNqNG+mPNa3U06DGc4c
         aAYMUmxaCAZlYALIUBuhlS63bzVWjyrBDuNBPb9znE+yaEcKzas5XDw6pGrYuTkB/kHg
         whVCplr9a6cYKXoYxm0zNntD/xyGoK9GXCk6xiZW09LNs5NIbJFuqEcN0pkY1sfxpMTc
         krM7JFOMLXuj7AwBMqOIJbhol1Iujh9fu2RiBfyE8pb49m/gF5bX5MORLRm5qmI1sNWk
         CSJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQffLgt3qxbQlpDZ8jDabx1RqdnOXtq12K1FzDUazRE=;
        b=NQrndxV7VQdGbLRV/b1KLmLE6w/rrjotS3eYadrTTt3whj0K6455pXxVMvBtcBGKA9
         BdgcVjh8K/LNtOwU79Wy4jlwIklXWy5Hn8/wuoYDc/eO1KKpQjrfiTMq8ReBnpYOcHIQ
         8cqg8YaZnCPTNS21HPAIrXF+JcCVmTzTGmj3gSjcT7yzJUug9JCRnjJJiq4l/Fy8sd+2
         WSIceCl8HKHwXA1M61qHFGxYCBp1WdVn4owjTWgW/TbKXy5IPC3L/rzTy6bGBvSbJfH1
         pp0pdUOYBVgNQ7Rn/yyZ0QH7tzWsob6eXs/WW243lhi/jQB6QKbgSL4G8YXEPipKqP2C
         hVxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQffLgt3qxbQlpDZ8jDabx1RqdnOXtq12K1FzDUazRE=;
        b=rL8GUgJzi6JrzMnmOCkH1gpZKBLof7Z3Pp93YLYpAaGej4ZcTk+J5UZwfmviNniJom
         sFXoJybkJp9jb8GA3Kb9Qi8P9zYDIsebQ8WgapjBuWymQ4C8WG2O5hxGXGNmIzyiaWW2
         jdrYuppUIYdNGT4H1blpgrblIXCOIi7eDxoGjITuTfsrAUIPoUZIVkh6L552w8pPEp8/
         JNb8kLFT3tiQOzr2QgFp6e2yNtG4EO0sJFiFnAvr2BAPKn+2fp0+/JTq0pV5tZwWTg0M
         p5jM8nb5tCyJ767C+E3j1axy5JOR+iPiW4MFrlpk1MRvHN//7YeO85w8MdQFhyEPYwVb
         Plcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Zy46Eg5hH3UljxUpF9Vaik5NW1KeGDBxubTmmYz217eZEqAiI
	Jr+IOP5BCr3ZSDRbz/bWJag=
X-Google-Smtp-Source: ABdhPJzhYIBJi4y6J6Yq+fumR+B+hmRf7779pcAW/tRL3p9QFaCVrPjyhlRphW/871yprNM9ofaEcw==
X-Received: by 2002:a05:6808:2087:: with SMTP id s7mr3631866oiw.38.1624534020151;
        Thu, 24 Jun 2021 04:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1310:: with SMTP id p16ls1945212otq.10.gmail; Thu,
 24 Jun 2021 04:26:59 -0700 (PDT)
X-Received: by 2002:a9d:7396:: with SMTP id j22mr4270239otk.287.1624534019779;
        Thu, 24 Jun 2021 04:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624534019; cv=none;
        d=google.com; s=arc-20160816;
        b=ZMwegJ2nCXA2WveTVCU4OQJa03pySJDK3/j0Y6DG1jstz9X1qbOaLdns+4Ty4jngjg
         rmTZlgTS5dswiHojnmrMtkV1YaY+wzbaJwhZKfaJ8IuzNSwBT2VELAh7Az7mOhgneMOe
         N5XsI7npPphD/tUbvmdYjXZDgBaykJhQIDCnoQvGGEnJZXk0U8wMP47mLRYIetdPezwQ
         Q4+eGRx+y22dweyqhPXExRoz1rHh7ReHVAoLOeyuqucTupc1cFiPMHWccFZi6L96eqTm
         +YEA0OK8aJTGjHNz9MCeK7QqyQC0AF7eW7kV4+Xm2N/naGy+ERRO7EDCHZv8HWd2mj5w
         Vt+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=LqO86/L2SZVOotrOOINBTDmZjeXook4jMNlRWBO1lFc=;
        b=dRl5FZMSVvw026D8k8jQXs1XKeID7MVfx4IqA49bh0dkX8sV7w2qydCBJDM/J6ykjH
         J+4Ov6W95j42+OmfiRzKRG6p40Qbfqpy+oPjUUuK9nEVoWMxWS80sDK0fUk7GESFB8kJ
         tCV3URzgmSgh7zFjrO/ErwsZVEn31C+k0BK2mJv41nFi/AsK2gC/4Mhzp98BLLcAXTXl
         Ay9RfSi0pWjhpVcAws+lb1Bd5HvqiAHauITCDHcbOx8pq6QeOqrd93tzMZkFN+2mXewQ
         w4OwUrCdP1VeyIAUZljAryeJWk/IbrfpehQdFR9NwvKquqPV07a9MRsP2d5656BbAWlx
         QVtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id b21si141693ots.4.2021.06.24.04.26.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 24 Jun 2021 04:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0ce6463091c0444ab97f96ae2ebd7c3d-20210624
X-UUID: 0ce6463091c0444ab97f96ae2ebd7c3d-20210624
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 967540757; Thu, 24 Jun 2021 19:26:54 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Jun 2021 19:26:53 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Jun 2021 19:26:53 +0800
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
Subject: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under SLUB debug
Date: Thu, 24 Jun 2021 19:26:21 +0800
Message-ID: <20210624112624.31215-2-yee.lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210624112624.31215-1-yee.lee@mediatek.com>
References: <20210624112624.31215-1-yee.lee@mediatek.com>
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

Signed-off-by: Yee Lee <yee.lee@mediatek.com>
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..d1054f35838f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -387,6 +387,12 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
+#if IS_ENABLED(CONFIG_SLUB_DEBUG)
+	if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
+		init = false;
+		memzero_explicit((void *)addr, size);
+	}
+#endif
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624112624.31215-2-yee.lee%40mediatek.com.
