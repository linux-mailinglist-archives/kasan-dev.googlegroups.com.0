Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBOVZYCAAMGQECFQAQTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 53AB5303F14
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:44:27 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id w3sf9185763qti.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:44:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668666; cv=pass;
        d=google.com; s=arc-20160816;
        b=NrSAGfaHLAid8ASpvLMFZIkaeYQ9I/Fgy9fffjvUkrK/ehKKuj8xwiQfYX50iVqlbT
         kby1AiJasPWhLCSlr9eCFVju7/ZQNyYTToCVR3lPmyiEE6kRMU1qy5KTH7fetjRZqsDQ
         bc2EdnmQrVeZ/OEhdtGIbC4V7uC53otAEC7JCjTpzHfh+7ZD+ofawcdhgcD7YLhvgCly
         /baNxL47RUpdZmxLNPaBTg060ix6RKZbYlTfsVBxsBauC61SBUWrjtJVD9aU5L0heV00
         L5UGZIbqciAF+M9P7Qx6dXAa8DRuwnbcI7hkyrVFJbGqzSuQfkhkX1F/SgQlEZH52RYK
         HboQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w11y5a2wrHERVpfDzh7KXPZ/8rnXDnU9aQd1RigjQ0A=;
        b=yWn9bqc9RZNWZnRgUvUF5+QXQI/pj6L4164jxvp/G90fD/LovhKEzGJ9gBrguvfJAN
         BHvb+b1aIMXR+5Sr+b5jOMfbfEeWKo36YUlo4VLZSDzxjieUd/MVjOTD32OySuECGeqh
         Hm9vCazrEcJ6b+M+PWSJFF5DVW0sY2YOJ7yO/isiRHroKVGT6CfSurOkekbRtXMDb1Vf
         EsbNlRF76HKD+i2ChCF8G/Rs7cKUnvb+PZZnZ9W5Axs5I0qvQtneLM2l0mP+8fpABwIT
         nXMTA7RF7FqzVYV9EX18INduvrVwEnPymEcfd63Hqa7QEbLtARQk5oOPq+XJdvWOG68F
         AEfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w11y5a2wrHERVpfDzh7KXPZ/8rnXDnU9aQd1RigjQ0A=;
        b=GdVeL8PPgDrZlpF1+j5otpU1T5ZQXuOwyyXIZNWRA71LPu2g66lcg8vzRremZC0ex4
         Mh50d8/hx3bGLf0gRNWwHOigGDqGqRjzo4dwycVFqQRG38GKnQcQ2GAsCRJ2zgRSzmbt
         mCDB1YwtJdIKOxI6SUsysjiZQmczz6z1Ah0v6HeYll90TLykd+GJC1044pPRQeHDDbE/
         J2hkNztqYB85BS37xh3H++/b8fMf4Ie+Ni7rMfdtALmOFSwk1tmCrSF/Ni7sFZPD7V2n
         8Zvu5mX3A08t8lNK5DGfiMWNANQhVBAY3jCItdbTIxldWZ+bDSr6rAM7mHhPGkajULQZ
         OAEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w11y5a2wrHERVpfDzh7KXPZ/8rnXDnU9aQd1RigjQ0A=;
        b=JXQNvvfXRSmD5v2nqriLowpTjgEIvMr35zfpbt1hZPUq+z36rRj4cBpnPYyCNQ5zXC
         KIhQ6Xw1UpLZErM5k70WQwrGUoBjWy6Uu4a1kPi2yaqy1L9xOtXaLmx5LG8MSXt4xBVE
         d6zNHdGf8DGCCeDZ9qVsf+aP2EJGUDafCeShsOgTKJPRaEvK++ht/7PzaQk2DFSE52z6
         /ppS3f/rC09PsIlyDZB2qq+rHWRJ5HQsJQqwMIxxp2dCVKOLPmbYpTiADLsTYFkTPP5G
         HR+/pACvRaaIQR2zckrmqjoujcFWhQWaTPfgzh9zPeVaBb2cOeZpZHN7gsGswfKXSCh+
         wjQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fhfD4oTD63W+MgI9Ps/ZqG8vquAOn7+EckGJ1Hi2WD6T/AejU
	E76ccxdX+nJk1XKzBFDTkVI=
X-Google-Smtp-Source: ABdhPJyv/IjouT8LdGXNxk8lGZUmFQb1GXnJ0DgSsKpLuiaIpcCDG1kFrZuPu9eJV1WceiJ7DBEmqw==
X-Received: by 2002:ac8:66c7:: with SMTP id m7mr5036844qtp.69.1611668666441;
        Tue, 26 Jan 2021 05:44:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:44c7:: with SMTP id b7ls6408656qto.6.gmail; Tue, 26 Jan
 2021 05:44:25 -0800 (PST)
X-Received: by 2002:ac8:67ca:: with SMTP id r10mr5061162qtp.267.1611668665821;
        Tue, 26 Jan 2021 05:44:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668665; cv=none;
        d=google.com; s=arc-20160816;
        b=1AgO8inHnmuGgW7GDrBO01e0Q/JJycHaObQK8NE05fpKDKU3dfx106fyQPeyc/tboW
         wICzEgxKoNDHLjawWT+MrSk7nPFX9AQ+aegbnOkewDFvNntkrIEIU8gxk8SDedDcE6ks
         /AfeGI2d+4c7tQKfSYALydzZLmEaCs6f6YLZoxQyCeifvt72FSTbMi+ECwVcPDFI+II1
         d5xN4DYJ1DhP7/KW1QH6w8wrh0XlQFDsh4nj5rIMdl30hik4eWEzJhhryg9kge4L/IrB
         rdgq/cK1ft3NJVW+lG29AUJo1Ua2xfEUSHRmOUn0NMTb7rvwW4lIJ0OCBCfBceLbgOIR
         LcOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=MpU63P9QCXbFNZr3Ba3+ncAIjniXCur25Dqj8mRe1vw=;
        b=xWCEmmj+b88gAZhsHgqmOYTh7Ez1sh0VsEpMUsga5ToHWvDYq25i1pKJadVRAYzElh
         IPCxCkCrWSOZ9GPHYFFY0AX+FHhMieFbQk42zu0Z583FR+F5ouQ3tAP3/u4KRy+NOynq
         +8vgrmivGzRUYh6JJmQAyXJTB85DKUKva5Z6Gvo8FcETrojDCrFfUUrx4S9Wv1WPagWD
         F34UP8GkvbFQuyZfqsx5yq76UO6vS4I7bUkeGQ24Gk7gOrKEZT2uCzzQXG1l+J+fzx3j
         ioHLUTo/JuhxB3/JetJi2HB+YPylp6qIXFYBpodHcllouGKfrCBYTujSOnXqS0ZbuOpQ
         Kpjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u4si452489qtd.3.2021.01.26.05.44.25
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:44:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DFCFB113E;
	Tue, 26 Jan 2021 05:44:24 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 096E53F68F;
	Tue, 26 Jan 2021 05:44:22 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v5 2/2] kasan: Make addr_has_metadata() return true for valid addresses
Date: Tue, 26 Jan 2021 13:44:09 +0000
Message-Id: <20210126134409.47894-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134409.47894-1-vincenzo.frascino@arm.com>
References: <20210126134409.47894-1-vincenzo.frascino@arm.com>
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

Currently, addr_has_metadata() returns true for every address.
An invalid address (e.g. NULL) passed to the function when,
KASAN_HW_TAGS is enabled, leads to a kernel panic.

Make addr_has_metadata() return true for valid addresses only.

Note: KASAN_HW_TAGS support for vmalloc will be added with a future
patch.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/kasan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..8c706e7652f2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 
 static inline bool addr_has_metadata(const void *addr)
 {
-	return true;
+	return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134409.47894-3-vincenzo.frascino%40arm.com.
