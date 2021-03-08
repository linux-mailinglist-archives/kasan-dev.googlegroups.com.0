Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBU3TGBAMGQEU4VD3MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 357E033131B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:03 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id i11sf7603470qkn.21
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220102; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZxPQ3Xsq4Ci1qAv0aFl55Ft5tmGKRiflZI4ey3tBxoJ8+7ixE4d22dX+56G9J16jG
         m6jVxj/tb05qfv5fY5oq+LcokZspGiUFo6qCOgjodrvfNzpizgEX9ZFTircKpOuBv6Ld
         qa7S3LYReXi+lkmoAAQY0m8a1p2uapuxvuPQY1HHbFp22Egeoyeiu4O5xQgozpZxHwGl
         ujHeRCGMxs+XZavRUd07bP+A/dFaBwsRgdkNWk5HrMKKq2FwXOPx74h4L7JRpOJuzOOo
         6la9EVGC9pyB797ANmrxxz0udk5TRDSNx/JhWnUSUZmx4Vg66Lb/Bk1xnXjKDul3Xs5O
         Qf0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nj31RJaHRMjI0IShSvFz9osWMGzwEWzn3QwWTYN44aI=;
        b=JhqUBgVvvKLrcyedAVaIFCG1RTi1S4Y9g5wDp35IVgyaeIKHeJMI02bWZg/2ZdNkAt
         4aWR7TLiNeCe30OF3Z61bWIghfhtJOck5YnTu7W7GgkpMb1s15az0k5hXyITuUrV46Lh
         3uCASOqI42pBEmPb3bcHJya6kJ2WGhtAfXRi3z1DrsO3N7M2TU+f2Rx5/wPI325+42cB
         0uf7j4hfJK7Pl/eoTC9Dncj+f3lwsaXTgPPmdPXnOzcDV8xQjbzAtRNKrRQvAImz2BP0
         w9azEYEJhUrdT+/2ADXhw+KAGoZTl/QOxRzWRGHcwda/q7hvIDdYM3YCq4Lz9IYFtImd
         +AVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nj31RJaHRMjI0IShSvFz9osWMGzwEWzn3QwWTYN44aI=;
        b=SNy8ILoZaPvBe9YahSCSK8GQYZKTjDJDtaOcHye9UexsVdT+CMIUO1SaU0kWkGusua
         UPFt5xRAIoShTdlU/fUVHT3CrA1DhHA1KfSzWpFYjeRrgwm7xIW8+5el7v1i0COeOGId
         P4SQJJMeG9H4lGJlXvUI1D5zA37HAoLxCRYY6FZ1qFHrUiz5lW5uflDQdOo+utJKFqtX
         qgF0Fmxo04Sv7Q6eQbKvT/g0einA4oK/fZNaowfzwvxuUj2HTkjgDFXNOKq5KtKQ0+ty
         9NVgueWBXtJPIW7MWlTZjT8D6ZmeSMYTjygS7WIgiHUXzWqO0tJC5ctC7tBWgiinpNO/
         9tlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nj31RJaHRMjI0IShSvFz9osWMGzwEWzn3QwWTYN44aI=;
        b=BcGjPhDwbkXpbJpqinXXQ59FhdnwJodrdQCseYlAt4jetpRZQE/jKUrt0cF6GbToyG
         86p5OCWJln7FX6z4m7/S+rb7NtRziMKj+zOE9OkDglJrfox9EikqjDMjBVVrwruGJvME
         /HpATPiiVm5He1o1yCRd5IYS0lFQ3rEiEhlWUh/pROPUwKbSSGN1qXIrn6NquKBBtzfj
         WTJtB3UKKwI3Onfwn0jmLVOmVn2SnS72HqAaZ6Z1jguS+DBM9cGyzIywXAbYx+ZPQMJY
         Whc/vjlBe8z4VhCuMNLdedwqt0rQ58jcW2t0NVjkBoRdk3BW1hs5EyrkMOcE3RU4CVeQ
         lMBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oveX9FdRMUGPkU9zLY8ySFjnvri3DTfN5UPUwwPsetRxJx2ga
	mxuPzWPClb9KuGOaneOUPgM=
X-Google-Smtp-Source: ABdhPJzPwh34BIGJrvY6Sl/ug5WaNFfc1/wF4GldkAP1RUZQcvbGaEh9Qj/tPXSqd2Fri+WzZyctrg==
X-Received: by 2002:a37:4a02:: with SMTP id x2mr2215536qka.293.1615220102337;
        Mon, 08 Mar 2021 08:15:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:d53:: with SMTP id o19ls9010353qkl.3.gmail; Mon, 08
 Mar 2021 08:15:01 -0800 (PST)
X-Received: by 2002:a37:a30f:: with SMTP id m15mr20946797qke.433.1615220101923;
        Mon, 08 Mar 2021 08:15:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220101; cv=none;
        d=google.com; s=arc-20160816;
        b=uK/PR+0FrBsCCrSUsgGaW11L9t+EiwdTtDPGbxp9YARVVzSQVV0tyioAIgEGw3SYwR
         MZlUrW3bRZh86P9oIlpoMh17zZ6QlYX8hc6mNPgVIxE9P7JO/rtRHdrSblXcAW/8KyRv
         dNRGlIhv+jMawqP4xrCJvZ6YYtDSzOUZUPItd/NmL8m04IHoO2Zdxrq2+r57/gDzYsFi
         +S/1JHNNMuUfXmYLqxCHOyEydzCSeDIx/HGDsaUKFa6wgdQ5SK0jA/fuAtdKKdZLSXdT
         ckf+nUEmPHvJ1QO8a9OVoSJjdqmPN29IAVkIjKGLREwoDiVlCnqpubaB3B/6tRe86rLq
         GUnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=cktgO+dx4K4MsU+jCSRJQXlHYXLfytnOpbgHzxV5nJ8=;
        b=Mzxvli1a8Ls8MhZ2p/8Rk4jWbPrcAqTZbTzM0ttdK5R2NBNl+VJZcl8WJ1RDG3PNNP
         FsVaNiYbv82NTSei0RlqWzpTupW66qyJA308qfFzw4uY9EOdy6RloehBRE+qtrygQeFn
         +R/AH4AQ3xhcCjJ51yqKHKkUe1arkWdYt1Ag3vd+S0j2uCw9hnWG+tUoINJ0MfyLl7Xw
         Hmg76uovQnrSvQcbf2nZjbj9kqQ8Oa2g4N13O2bp1y2nkfcMgTSG3VL88pIW6e5rq65m
         ZuyxGM74UliOz9xx/fwPOFgv4+0ZAdQGRAYQo+oIkRdCcm7hnvoEIxeaUPTvrcb0i9kW
         cnYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b201si360848qkg.6.2021.03.08.08.15.01
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:01 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4403D106F;
	Mon,  8 Mar 2021 08:15:01 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 612963F73C;
	Mon,  8 Mar 2021 08:14:59 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v14 3/8] arm64: mte: Drop arch_enable_tagging()
Date: Mon,  8 Mar 2021 16:14:29 +0000
Message-Id: <20210308161434.33424-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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

arch_enable_tagging() was left in memory.h after the introduction of
async mode to not break the bysectability of the KASAN KUNIT tests.

Remove the function now that KASAN has been fully converted.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 076b913caa65..91515383d763 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -245,7 +245,6 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
-#define arch_enable_tagging()			arch_enable_tagging_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-4-vincenzo.frascino%40arm.com.
