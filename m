Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEHV5KBAMGQE4FDIM2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id AFFA0347058
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:37 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 38sf567768otx.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558736; cv=pass;
        d=google.com; s=arc-20160816;
        b=TS+ePGNeJdfQpmkFRLuXnJKWwnIRVITQP5nLBKxgUlSDPAPR3lpHDnr/09rjDIcw4m
         LLq9b9u9g+scOReH2jUI86icnOwVRHyL0R5wQIHjxq8Yd1aHojsxm/8H4jD/5UZVJAn2
         AIwPKOQ1DA4Z4V7FZmtnHbXzSUdbK5BrYtkziKVhvnuByPsQCjch4OhdO3roKT7Knet2
         MyG5QHyeUAxnB9olbEUkpt0W0J4iiWWMDvPUQiWpeyl7Ha2drG4jb6+siZ3XmnwOoa2A
         YuDYomSaNZFAZcfML02ZV8FrL3QpNhM+qHn3trfW4npb4c0AgkWK1v/mFaiV9WBDNcDT
         7MEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Z/2dS3TmxSPenKvHQEpdfazj/kQiaW6yAPtOqgUlOog=;
        b=R1X6xjUhMxXpKvgYDnUfAtNp38nLSs9Gq5VkSCzYdlCwOrOezj0+kAUequD+AHSGXr
         0UuBFteJjYETc8mVwjt+40nmFyMVENM4ymsKC3Vfbeme5NfwwSF3k4i9ER664pNE8hqH
         Hsy99RKfKQm3IjlAV2jbcGL0GMdmyNRktAvK4OFSFcIQElB6CZ0AAdJlLVk373aO0sNI
         ERDNUd+P41oPKfuZVJmdUFWO5mIIRBh9+GWQUudUTFFUn3o9fvuRxKDCB5TXvAB/sSDj
         TfNwZmRFC9iBggrYsMog7/3Y7Bx9zCTOmWWZ+S6HbCHqU8spwl2oE79SEFurB35t9Grm
         PzaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z/2dS3TmxSPenKvHQEpdfazj/kQiaW6yAPtOqgUlOog=;
        b=ck9MoeRiZU00yCG6fcVtstv0QZi+kuvPvoauyRZxACfCXXS5dxtN2Rv4/W531AM6BK
         atJC8Jv58S9IVckNLTPmLDkLEeO4BN9GIFzxJ9h1qslyUXHDBMS8RjwytOf3XUvmY27p
         Nn4H5dbvgORYSCVGYmpq+dWT2cWZWYxQ1jcz9+IQW7hEYNg5pAV5BZ7A6E9FX/mBytZD
         EI1eEf+GbaehHj6wn4AHiwMEODQMWbDu6aw4KXrHx8LzRS7CxN7V1h6faSufICKWotxO
         vGViV7msmQgvfY4KU/Sx9v1vmOc8xVD2tcM3xnHK5JzPzHMXmaiL1t292tI3NtYome1J
         IBLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z/2dS3TmxSPenKvHQEpdfazj/kQiaW6yAPtOqgUlOog=;
        b=CC+1R/drAUE9AlPfLWehn+voNzggO7w6GR7tv7H1FsRM4KRnbanuilkLBWwt4Pmp3B
         0nGTPBBQhmYcaY4wWz2KcXjdkFhr+dN/9WoNMuktl9mq0lKWe5DcLM47FxHooYOxyJXi
         M3/r59qDizZsTJ9gaNUwZofADHxuyOzz7UPCbcBB0CD4cUgbytantbswBmcq6sVJcsX9
         UAjRM68u2/jTufERnWQ0LMfT3265gcJCjm3/5uSvNbnbkW6pISjDeCEeuOzPZ72Q1kAQ
         v934zmz+9kPMhMDaWu8XdY9OXvo1dUmFBqLNvqLxqk/quARw3FUYjKwguGn6vp6K7p56
         js0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vmp6clNmjhfMQbwUriuIwD8Hv8S81AmMnRSuRlzKoocwer/Li
	4frXZLszLGMkHv858lxX8G8=
X-Google-Smtp-Source: ABdhPJwIu3+/sRuahpb3HY8xw1FXvSpS3XXeDERNDPX/7Nc9EYxtbW18+uKoQk4irAbKiVZv0CNPEQ==
X-Received: by 2002:a9d:d02:: with SMTP id 2mr1367107oti.330.1616558736472;
        Tue, 23 Mar 2021 21:05:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a97:: with SMTP id q23ls224587oij.0.gmail; Tue, 23
 Mar 2021 21:05:36 -0700 (PDT)
X-Received: by 2002:aca:4d4e:: with SMTP id a75mr944032oib.107.1616558736100;
        Tue, 23 Mar 2021 21:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558736; cv=none;
        d=google.com; s=arc-20160816;
        b=NLrIQxSH79ZbISUW+wu66t3/udI1uWLzsK73n97zhU0srk6/74IwwtGYo1Jz037ZL/
         tRBdVRPg/nMTmFw6DnAWEM3txAt58pRsLvg2CT4+N8L0UkK9WqgUHNNlnFuDUoyANsSy
         PJG0rabO4a93oM65+1kZmKJ80ko80gzZMxDTmlyJ2ZOerPFEnrTGGMsa8QqHLQeZeCpO
         hoczYT/ZLs6eshpe9/L6SfyxdG+gjcO2hJZ+55mcwGJ3RjXO7iSujn1dSH0N9jHrvBxg
         imgYWkE5wAfHn4uT0r4aGE2tVwW4AhHnuNb7XfPvQUSZmStSxwOW3tvibennrPY6qS4x
         l5aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=//Mof74LC82H4CtzSdSWKhaSP4EMB3659kRtNXsGK+M=;
        b=uUWwY9YnDpVXStqAhJIaAxJoE7HidZxvZO8jLmdjGnkV55Dc62ZBvyCw2XyYSX/NKp
         YN3o1xbvb2SXLSsxYd4aJiv+Z2UTY9ZvFRo2s53Ftf0i1P1lmybk+LmDb7D9BCJ1cx7r
         iSd0Xw3bqp0DqkDDb6BzXj2ujgazKzodPbE4lwWU/4tfmXO6b1orNYb7ZAmY1poRrwOX
         NaItdCbGfjwE0RArZjtUsXtCmvr5Q/VUf9VWzaH68ylqpFp9Mj8RwR4HVLr2H0hq3omU
         SnHQAKiW92Ohj3kAlkbo6llShsSjK+UU0iannD6zzlpQ6Q84ddAWUCsL19EAp72q+XMb
         jCwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x143si72794oif.2.2021.03.23.21.05.35
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e8b19a2958fb4ac385dd2697d19b3266-20210324
X-UUID: e8b19a2958fb4ac385dd2697d19b3266-20210324
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 834884717; Wed, 24 Mar 2021 12:05:32 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:31 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:31 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 3/5] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
Date: Wed, 24 Mar 2021 12:05:20 +0800
Message-ID: <20210324040522.15548-4-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

We can backed shadow memory in vmalloc area after vmalloc area
isn't populated at kasan_init(), thus make KASAN_VMALLOC selectable.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Ard Biesheuvel <ardb@kernel.org>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 5656e7aacd69..3e54fa938234 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -138,6 +138,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
+	select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KFENCE
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-4-lecopzer.chen%40mediatek.com.
