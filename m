Return-Path: <kasan-dev+bncBCXO5E6EQQFBBH5PWOPQMGQEKVYIK5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A90A697C92
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:01:21 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf8032909lfu.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:01:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676466080; cv=pass;
        d=google.com; s=arc-20160816;
        b=biJYUlLxDp65eRXIQiOxBTB0NbeEGteJwxVJx0jndIyDW0SnHgR/oOEGY09MkZLq6A
         P969xWShf6xtbDz+a0o8iZf/DAwERpxCD82EyFkDN6Dm+XPSn3aQnnJSRG8M/qeFexM7
         VjEfQYZoq/XXTA7md2gPREey3LhMfpTvyk2m6VU5VQxq7+v3fn5oGKk2HIktTeYE3DaO
         LiYy0kjFJRdXkwI6RIuGg2rqgJvz/fnvJIkj1b/HkQEGvtJHkP439tj4kqK/mXrdiaYR
         B1psVHKkTaYxBGw68tpDVJ1KGCA5xRwU8v9Q3NuyW44UeQcoHT0HKD6YeHZx9Hu1P2cV
         1UpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yIfXEhZYy7mhG9IchalaGEIhPAvve+nk968jlgRh918=;
        b=jctUHOL/Vh9GmRVFVJUW2lrLvZiRJj+omnR/WAYOAF733LzBZqk9su0uF4BcixTZuv
         COjVgIuANipKeZ2cVrkkdR+2+4fLUXtvKaiQaVykf27hUlPxQClRJcF2d+J15v+MroVi
         MlfMeoQepuyixpLp6UzZsXCnrPOb4MgbS4EUTDruUT7sdeovtQQ8dAYvByDkNITzvxGE
         pJ08g/LbYuW1tDM+xD286OmvEluEhoaoMuzZKq2I4b0oW15MmUx74b0pVc9hWRkA7WE8
         SKoMQ1u6738LrXD7327GlNIJJtfXYzYQ6Fdtrsb3jOUZY6yY6oOfhYE+8DTYFaRotS3q
         96Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R0VoQz6v;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yIfXEhZYy7mhG9IchalaGEIhPAvve+nk968jlgRh918=;
        b=Mh/WaEC+jjVip1qRuzJ72vrUr9QBzREPlIXLOAZQY9LSeVf+gI2ML5AGJtTLdMZhOr
         leKKDXbg3g6Zjlfo4Tll170Jx4gTZafuGBqdnhcYFtuaP98MgiJzUJccRlW9FUNLPofA
         gZY/jsnWl8bC6XPJ9LhZMogwQbSPrcycGRWz2P4nfYko3qn20c/Ur6dpjwyx07iHOZKm
         rTErIa8ZDSUI+9ZeK1oGKfdaX5lMmwSxpy9QGXM6iyqsTtDOFFV71JfJyYEbVwn7+Dm/
         qC2j59LsujlNPU4HCVrtN6MlBZA8/oks+VOp6eDfpLJXSMROEIyQlC+pifLmPcVKg7OV
         KAeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yIfXEhZYy7mhG9IchalaGEIhPAvve+nk968jlgRh918=;
        b=th4h5gKfXa5pTRl9SYSiFUh4Tb/BZH9mTfJSKT1uR49s+xKFjZmT/Dh20vVrAVu9ZQ
         DmORYhJ4uMnjxwMU+TPBP349G/K5z223VEhQtRfbx4fTcSzvdUHhRKs0k7J+7ApjACrQ
         bISjHc5BOtlOCAA4OSWrXvtaR+MuIqWNAGBDwoY5caFgLD+Afs7aKRefsZcyEP5SpxP0
         TdmJdM1VXcPNGrNo1tdhIgPA8hsFkqbDWpuq8vTF+E8cgb5/wjMEKiw+TxUlp9qAS5Ab
         KLDvZLwJrduCUmY33M9lG/28PvYbb80yWBA546a0vPqJT25D3ku8CCdAHEqmvaF0oNCa
         scqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW+n9nHjRkUreab8+2AfcZPX1w73pVWMWF7uAlsVdJ/l6MJqiYd
	6d/SBUJa/mUfCDGC3Y7dicU=
X-Google-Smtp-Source: AK7set+qhKRsC3Yiignr2tRvq/VAN+KMwg0+KXf14gzhp4dFZwO1D4S1mhvCG+av02YorTDHHjJXug==
X-Received: by 2002:ac2:5922:0:b0:4d9:8773:7d74 with SMTP id v2-20020ac25922000000b004d987737d74mr510189lfi.6.1676466079957;
        Wed, 15 Feb 2023 05:01:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:340e:b0:4db:3331:2b29 with SMTP id
 i14-20020a056512340e00b004db33312b29ls410175lfr.0.-pod-prod-gmail; Wed, 15
 Feb 2023 05:01:18 -0800 (PST)
X-Received: by 2002:ac2:5dd2:0:b0:4d8:5314:394b with SMTP id x18-20020ac25dd2000000b004d85314394bmr504491lfq.15.1676466078507;
        Wed, 15 Feb 2023 05:01:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676466078; cv=none;
        d=google.com; s=arc-20160816;
        b=vI+77oCKc1rUcd4j8XoWs5AsAZ7A7b3lsOWVgMxY/Fg2OiCp8zm1CR8BNf/3BUt4NX
         ZVwtO0TZS4wuiGm2CV7oQVL5MU5asM3Tt7vK3UQ2nx7wBBgpV5U5Fb+ztSF5JfqDbKup
         MdYqgV7QQ/CMu5GlAd/RlfShMmddNanXieJkPO/8nR7l98+veEKJNKrPyPb52nwnI+Or
         2NRyWwGMMlBUWMqz0Gj9V8pQi21M8tPA54OAHzu1BQeEUsiLT2Vu7KmJGax0XVdUAkyM
         2TN46aBATMCOz300/km/aR9xZ09LPCvBDNo1VH45OS6Lj77c9zdyVrXnM81QtN/lPMkg
         Xn6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eEGF2dhJHQrOcjGWiEp/1K3Pqyv63qcrypNyumV54Yg=;
        b=SXntKLUdA7T0VwBX6/A9MVzn92sALbdDpoXySUuXaGyxA7/ZKIargMAgdRZwUipcRm
         wOGCg5/l5bPNWR3EpghsFCCWhNwIDmqWD8HU3SyHVtoxr0mBPwpCmlkZ1qJ+iWbJtKp3
         S7UXSscUrwsSAdPfFzz69gkcd8FC7D12Jv/vrdReQrPuik0sCeBZJLS6tqr8JuNuz/Wi
         NBQi9EcPVw1eP+CkbWQDO6F+nbZ1HIgC3aYSGotB1PcQbWr6kTmSj9dtoISNaCpM8rQU
         Wz66/vVkoLKBfGYt2JabNzN/Nuwn6F7XeMZvCcpZSQiD45QcV8UWjPYcKGPGCHCg0WtI
         Pz2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R0VoQz6v;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id r26-20020ac25c1a000000b004db4502d9cesi336655lfp.4.2023.02.15.05.01.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:01:18 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9CC17B8212A;
	Wed, 15 Feb 2023 13:01:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6819BC4339B;
	Wed, 15 Feb 2023 13:01:13 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/3] [v2] kasan: mark addr_has_metadata __always_inline
Date: Wed, 15 Feb 2023 14:00:56 +0100
Message-Id: <20230215130058.3836177-2-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230215130058.3836177-1-arnd@kernel.org>
References: <20230215130058.3836177-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R0VoQz6v;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

When the compiler decides not to inline this function, objtool
complains about incorrect UACCESS state:

mm/kasan/generic.o: warning: objtool: __asan_load2+0x11: call to addr_has_metadata() with UACCESS enabled

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
v2: fix objdump/objtool typo
---
 mm/kasan/kasan.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3231314e071f..9377b0789edc 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -297,7 +297,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_metadata(const void *addr)
+static __always_inline bool addr_has_metadata(const void *addr)
 {
 	return (kasan_reset_tag(addr) >=
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
@@ -316,7 +316,7 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
-static inline bool addr_has_metadata(const void *addr)
+static __always_inline bool addr_has_metadata(const void *addr)
 {
 	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215130058.3836177-2-arnd%40kernel.org.
