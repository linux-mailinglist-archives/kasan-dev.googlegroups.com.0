Return-Path: <kasan-dev+bncBAABB44B36GQMGQEGTDRDQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22A3F4736E1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:56 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id w18-20020a056402071200b003e61cbafdb4sf15173314edx.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432436; cv=pass;
        d=google.com; s=arc-20160816;
        b=R4UxgkNwx0FbyYLROZ3d8f4PndjkeNZf0nFxaJgP4Gb6tEMPpP65mg9vGsF0BnCmV8
         e4257Nb3Xh0Oo4tYHdKSbIvQzI5zWfuqkafsgnEgbGOVBpZq6RWA2UN2ravP30KhF3Kn
         j4uXUR0fXh7npA/TAGnSGyg24+IwGjD8RpFZZR9zAnym47W1ert4V95WiUUu4jPxxf3l
         MnCMhaFoxfIprirlX1b7PAMcPiNkzFCdP26W6/b5W4W3YrSk/UhD1j8dSO4o6Hkw3loQ
         Y0f7vhLJkO9wfaVExpEo80VbRYfuxoYwaJUTMpTfxBzSMfH10FvCXQW+r9qZepwOhRf5
         1VfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TAYEO+ntpBH8uY7IeBWe6Cvkbin7UsiNZaCO31wi8sw=;
        b=Ez66lQrnSAVba1HWU54pNXQ0cMy9/jQzThuFNddp2OqLoMwR7ikJ9131z359TJp2ye
         lxwhzdlGzAtR5iSaPaK6U629jv/88hwV1WApy5UwzzPTuqA5L43PE7yH1m7r9CxhJ/DK
         9SWyn4ayiQsEtw8iVcG52uMUVujj/weXenb6HOrvCkijqhf/APcAXpCv1Wt2BAVq1PSZ
         fvWvchHKWRZT66AOJVBerl3xnXHd70Jo8lLRQ+IaBqFYrm1F0UB8k7r7aJOLCq+Dcy2g
         ecj3wr058w8jIVfb+EdBPiLUo603Zuq/OD19FD+4avv7vNowNrtSMKjcAOsCnpXGxr7l
         4MUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xFIm1kk8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TAYEO+ntpBH8uY7IeBWe6Cvkbin7UsiNZaCO31wi8sw=;
        b=cbC/2/+RI0HxgCrLL5MMYYmpfwV/qfnW/XhJlcugnUBqHI4gzQfqP5G7u0Ox5t8Do6
         mw8f77XGxeH76hBGUpCc5eqcT8cUSEPVjzFJz8Dd2RiT8GwIa1tN2k4fkXOnDnt7Fwqo
         Y+aBJSTkgke2/zlZYLbBo2gd8pL9b44nOoE49WC4Cax48xauSnYiTAwtpu56D//BEw4u
         DpC04BLKBT6aQ+6P/l9ncQ5eTGUaCowOxU7recRlkbRHUroDNY5s4tvNOiluhBBZHtYz
         7z9bnLOCNKzy4yW8I1G5C/X3SADC/GkC22g8H9oIF7o8LQdEzHXQiqOIVftr+DBc/oWO
         PfUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TAYEO+ntpBH8uY7IeBWe6Cvkbin7UsiNZaCO31wi8sw=;
        b=PmiAVGb0FCJIfrgt0zdXc88UU+fm9Mndov0PJ2P/hMNv1lIhG9hXzl3ZQTV352ZTGT
         NK0sZ6srRB5Gfg3hVgjyDIc2va1KNFxUU+/AJzykp4DzQ/P7cbXGRbpSzsvzBjSt9QHo
         Rb9YCIEPfJrjvRtj5+E2zS60VFthiKbENCeNBOGP6pG+I2M9WJEHwu3bPT6pcxctAfPS
         AyYYsi+4J37rMY4C+XUF1lJRdLDxmDYVsGS9zEoWxYZYR7eGqaKSUENzf+vn/BtfOoSD
         RRiMot3Gfjd/X4aT86LtCiFC16Sxnui1Ux4nvUTp/N6niraPN/PJec21T0P4TTbf1Ufx
         p50g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l3G3EfcBzBRmMW/dNT5xNFm59Jwxjcl7QT+rDDTpzFHlenFxr
	8WulpChZJGsTExUYUC9R1Cs=
X-Google-Smtp-Source: ABdhPJz1hucgPTq5c/Wz34D0ZJmc5vDgIF5W7Fd8cJTp/566/vIMWBQi9XhVj/PbOrTwXZyWwmY7FQ==
X-Received: by 2002:a17:907:2da0:: with SMTP id gt32mr1086931ejc.711.1639432435887;
        Mon, 13 Dec 2021 13:53:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd09:: with SMTP id i9ls2273206eds.3.gmail; Mon, 13 Dec
 2021 13:53:55 -0800 (PST)
X-Received: by 2002:a05:6402:190d:: with SMTP id e13mr2081932edz.282.1639432435116;
        Mon, 13 Dec 2021 13:53:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432435; cv=none;
        d=google.com; s=arc-20160816;
        b=t8HIsHI/T/DLmXCj8mhC3xprwMW+c0JUkxoFYEJ7IIYCjX2Gi1vFSDd2bOHdNicedy
         7HvoSi9yJBc8iFOOPN180QBiuVcX8PQjy0jzpLf82o1RvTBijgCiTMLvH3VDuxwbgUtC
         OdD9vkZC9H5Tl6AXvIX/90HLiYGBf0xC0LFqCBoB/odNeNRDQp86SOQr/YJQMJ9SWYJo
         RFSuV29ogRLWxRQm3JGcvTIuzWRMFwwUh80R2bFtdZk4dXrWxsW/QLcYDJ2KG9Zzs3Ek
         PfCmMRlAQdRIm10+X/4XB2uTc6oaXnKxVCmAm3oGQ8qTPV36+Jq/Kbj+gvbxPvLGPnfo
         PhGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DErGD3M4prwe4k38EJQv474oTAHhfYAOppngSPgJwzw=;
        b=SiAujaN9Dc1mWJJbXxUD7Ym/ARwkJmHOWVWV2/5JkzLRWxQppgSwu6uJeMvSPVJ4/a
         bXdl+vHAraYlkF1x2d7hlnkTS4Z4MM3qltnQCdJ0ugZqvDdFFlEXf+ippEPBrun9qHVY
         pF0e3vvv/ERJZA+nyWcmtzgAwJ7apvv+0zcbujJ3takiqzL0T1dNtn+w+u0f126JgxTt
         RWCd4mXIE/1IeM69NQCjqZVl4EW0chIHGkR1fAPOCsiddasf5KSKqO9fh/T8+PdLJ33v
         ct1KqwRC0lJ4ulS6et9p9qVOFkVQv1ab8hFJesGI1eaG8NqBvQU+eihj+MDn3ob/GpFV
         0+Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xFIm1kk8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i23si744480edr.1.2021.12.13.13.53.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 18/38] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Mon, 13 Dec 2021 22:53:08 +0100
Message-Id: <678a2184509f5622d4a068f762691eb3ef5897af.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xFIm1kk8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index df5f14458e46..28becb10d013 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -35,17 +35,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_DEFER_KMEMLEAK	0
 #endif
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/678a2184509f5622d4a068f762691eb3ef5897af.1639432170.git.andreyknvl%40google.com.
