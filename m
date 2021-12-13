Return-Path: <kasan-dev+bncBAABBIEB36GQMGQEDF5JJSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BCE984736CC
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id n18-20020a0565120ad200b004036c43a0ddsf8028924lfu.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432352; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GIKzRnGxD026Xx1HGxRRJ+F29g9tukKdVGXA+qyj/ttha7DE+/sYgaluRuGcXg5wC
         6hpomffnGrCFcIKO1kuRwL1aE2BF3sXUoz597SZZkD5Psgb7orgFReWARcx5PzJWbQfR
         KR+fFlyeRqE9BeY9PRSpbg5Tn3PCGCp0qDTaZn8KOcIHQh89eODKCaKBm2SVHx/Jas87
         x42hl8UCfaOW2XGEEPM1JWw1AHz+0zfuTfAUCcEZt89Dp+ucEkfiDSd/+xnjlkC2/tBj
         EZuWFH4kpxYfFKoF6uQZFZmIIv3ntclxDZO8dDRR1nMM79wf2qGVwKbaBjLBFcTCV/KW
         CYTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b6cUUKTn/cYn1rW85ydUS1mryFhJutgL33RIJO3RiuE=;
        b=PNCmXyYb/TmE3AYEWJUjrF7clYvVw86mPnlZTHTLochLlddwLSal2zRyzNiVaHhP9l
         hJZ+zxw6wLJINkmCqDsNs28pugBvmAh2nGGhvYvMB9R0PbvtE6xOF+1VONriDCUxHfe0
         0gLSEsUxqI0XqjCQGCFcl8615C/R0FP15CSXXkVSzGy97ZUSnGjkVzFz2ZsHapJhFRQ/
         vEU5ArBqPfaTNAyaSD+L7pjOKARko3XEmlts0/yD//CmUEPhpY5YuLf+KC4Q4nd28Mqw
         CXOZ8U4naDyJEpFXDiBIt2tb/RYeHvM/itCwZMQux3wcGsR+mVrfLu9SXBBglx87XhpU
         HqXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pig8o3df;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b6cUUKTn/cYn1rW85ydUS1mryFhJutgL33RIJO3RiuE=;
        b=ZvKmsBSrivPAyxMwuVHzUqQIccCcb0D7OtyOxr3WwdR0eTIZpidQ2QAlRlf8NrXOv/
         ScE2LtfsBJheg17TEB8sF4LPy9/m9Be56E8alh8AoTj1pYIncOLv5TJQu9SGAMPhNu1o
         n411k0dVuIcFO4Tc3jrhu3obuVgsHjE3ssrALTafjALnW+V2UKLDTVopIJqstFQMA1lt
         FJZscsxqdqiqWKdbMLPz1mW6gdPZYPraMZCB8uHAE6LkRYHl9VHtboubaTCsLCXJrplK
         zIpK0N01Cx9lwejzZ/xuBJ1gO7v894ytUempKfjTadXMOYNu/m6GrReqOlsd0yiykZru
         35Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b6cUUKTn/cYn1rW85ydUS1mryFhJutgL33RIJO3RiuE=;
        b=7iNrATR//hS49nvu7D588sOG0WTP8y2txMObGpFvEOS0PYFaQ4V7NXBvylvgDbiDig
         lnUV7Lj7GQkWM4vFiBAuoh2kStepI1qPCZrnRfuQeoTf+f5ZzXwCngU4UcVKY1GALlIr
         AsA9nI9CXQ/1ZM0OVWI5zvs4yebkbOSPx6DB5aUxA6JQIW/Df05whTHTq/AZAHxCtylk
         Eu+nH5XGtJ1XqxNa8Kkrhot7zbRSjxBIL3Zn+FhIjEzL2IvREHuUV6F6f1+IYLv0W351
         GsIn5B5a5UiBj37ReQxFUNpr45OGGNBqaXg5w2vwvY18Sy9GCeZElwpbaILILhU4vDnZ
         kV3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oYBrhyCfFFbY8HilfCNvLXMKJDOh2NB1ixCD7425tMiLZ5eTM
	oiwSaTgpwo+TZ9YklMNXIyk=
X-Google-Smtp-Source: ABdhPJzJvoWHgziTyTbvhS3GMC3oeVC8e5n5yMV4za1LBDdd/ZYl/hrJ660vIDLLZ3v6ipc20YAT+A==
X-Received: by 2002:a19:c350:: with SMTP id t77mr989542lff.152.1639432352376;
        Mon, 13 Dec 2021 13:52:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1550258lfu.0.gmail; Mon,
 13 Dec 2021 13:52:31 -0800 (PST)
X-Received: by 2002:a05:6512:5c3:: with SMTP id o3mr930623lfo.239.1639432351691;
        Mon, 13 Dec 2021 13:52:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432351; cv=none;
        d=google.com; s=arc-20160816;
        b=RXn8amVq4hsoIs+jkQzD1ZKOhcrGgA+4KUHMvvZQmux2mCVrD6fMobMjkx5a0PL3lL
         A0KuWVJmy0q6W4zgl9FDNvANJ6XKqRhLTMRcHwTPhPHwugH4bRXFedQ7D50/giZJQ18D
         9w5mVQWcTUnCtrrPEPt1oMv8pMqSyHdE8ZAJI6Ck4jcnpUXV6LrStw92NT61SB2YDBTh
         DJyPQomPVcgudou1+cMfqxEqnwjt8zQ8wBWpM7drf0FQcwdKWD5aXp10I9zcvtAwwRNy
         Y91E9ikRaw2kc5AzUHCWR5GJKYSg/FJ/9e8jPO8pjGFa8dVDcV29VwS3G3Zc1wrnayrZ
         tOKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SSr7ZRoKI5rosZ6c7Uop2vjIRmBUfgiDVK/L3kihol4=;
        b=usUsO09LLVyCQN7dOMaXWM+ubW3HrQj8k2SQhbVA9wP39NpneuWb4biq/VM5bBLbXR
         cB72TeaxlsEgbr2/1W+BIWvYHRtg5z+GlxOzkadWhS8Dldswx7YwPO9Rm8/ozb+cqKQb
         dzFxR2e88XLoIrQIjJ9MHdf7U7zUXdlHMc+YoKx0XikUshHAgRsV6Z4A1i+sQl8Q8L2Y
         ZZdU4t+I67OClIzG8oXMqEQX+zOKajF0p97Ae+4LqlZeXHKA0sS3kuD4moEuLTivFoQa
         7+NQ/ddgWqHff9a2NUbSrehxUtOcMqUY9OCY29Fws2siCyfkGY3IY5643ueb1uFbhUO4
         Iwjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pig8o3df;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d8si662001lfv.13.2021.12.13.13.52.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v3 07/38] mm: clarify __GFP_ZEROTAGS comment
Date: Mon, 13 Dec 2021 22:51:26 +0100
Message-Id: <bf783443f27c6ef6226fb9e532184be66bb906f0.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pig8o3df;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

__GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
allocation, it's possible to set memory tags at the same time with little
performance impact.

Clarify this intention of __GFP_ZEROTAGS in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 63292fd99531..42b845cdc131 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -228,8 +228,8 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf783443f27c6ef6226fb9e532184be66bb906f0.1639432170.git.andreyknvl%40google.com.
