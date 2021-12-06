Return-Path: <kasan-dev+bncBAABBJMJXKGQMGQEI5T2USY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2607346AAC6
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:14 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 69-20020a1c0148000000b0033214e5b021sf6723848wmb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827174; cv=pass;
        d=google.com; s=arc-20160816;
        b=uo4eUSmHHAk7FAwL4aUjw9wwr3brBk+HdXtT8DT6kcahddaH7oms+O3XrrPAbUfqyI
         gyfQ1/OXX6l07hKkzPniAI+P4iMYlnnmv7+uzyuhE57+UvzeTQX/o53PxUEIomShWjqT
         +quqc8tYG1uEIOTttm/dY6jwaYRqCU+DPgxjK10v8d1DImp3TtwOzQOZfXRhzWB9NYOQ
         AlBJ4daPxTEL5+zyPs1jJah4exeJi/JXhQDN32/rv73HLGv6AhXCvcVyMSRA7PGaksCj
         ypUknZ55APhwp3nwLJTYavRODzchIhXCdVC6McMVeQGnuPvRwlZEVVxbVLsqx1fynLFR
         wAhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GzV/boV+y0MymW8383vBi/yOQa2Jjivgo1hTTA6PG7g=;
        b=0rugbpbkfOY+x62m39pmfGdz/B91j8DUC4c4BVH6Rqc755iR43GZgF7snz0ATKQCKS
         sscgtCpwOw73T5RhiQWezTS+7/nJ6uMxia9nCRka7BL5PmOO1jEBCKAihUnQJKoQD/Ts
         qLFafeRrqwp+xmwJRPhWgV1x1ezAfyBX0R7MNn+PjHDZU9WF/3NZMzIdoSkjjHA6c0sz
         itbYWZPsq1w2uWFuSWIqK6aUxQWi3eUXqwIxugMP8juZBOdE3/0thXvGiw0lMrugyYTy
         DSXXVeI5OBhXzSpo7NkjGL6t+i7OL7VzFyCXRlD7NlyXAT+M4hHpeV/vyEQ+TPnKP+5l
         RHSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ujYKIeaj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GzV/boV+y0MymW8383vBi/yOQa2Jjivgo1hTTA6PG7g=;
        b=MDsq8lMyqNtR+IR4TyHhMr9OXWKqNJuvkqMt8SOBWw/0iMO9RioDBDW87v0TkumVEK
         5UL8X3MZnW7RG95t7Ju+FC9aYH7RCQNHkRl37B9I1G3c60zn921N07IDHZFzyOFzODzu
         nw+HCsauxvj7tVkHs4IOUZdJOJhDgN5Pt/Zlu8g6qxU6plMwmrFqwuISjTnsg797Vcml
         4RMAeHHDywWlrQ+2lxmAV4OCq978Tf4LsPl3p0qcxFXivNbyT6d4k6C17ni3cHCVLgzb
         y1AhxK5295jpvsE7S0DB6/KPSbzbMyKNcTOE8fSj4F8IN0Wo5njwItevoNEqkLCiAYDR
         2PVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GzV/boV+y0MymW8383vBi/yOQa2Jjivgo1hTTA6PG7g=;
        b=qajkuMElh08aNvFIEiJi6t8gwvlsLk20P0rKupy6nLAKLV/IpRN7ot7pbbZGpTRWxK
         mIJUS4ARsM0TJKH5yw1ua/TDv7Zp7kvElcsF426BrWe9IV+7rh53goKSlbOdeeQuOF1w
         rFKQ5gibyZWt2xwh7hysAc886GKs5Hoh8xP+TPj719vGMOmULtqiNYyhmPlHXiV5Bhd1
         NsCsHuPthrWI/Ct/RFofGtH4lnT72ILwVw/fRhS+MhwRX2KZimH/QfW1Vp8UdI4nb6Ln
         jHPQ/pEHyamdvQIbq20BVfzz1lkT5fr/0Pv/0Pth49G8JYNumDHyTiubvAa38M6oDOdS
         XgzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nZZKhXVfw2fcaMKK/N09K82dSKv/PadxrL34znWemYEVEre/M
	JdIya+q7yC6d/YetUcaTieY=
X-Google-Smtp-Source: ABdhPJwMJ3QqZhkoQsg2FgHS7fuGjsv0LBoYvkbamNM4T/HirfmkMNfk+ttWDQWzbbIDWqPWRoq//A==
X-Received: by 2002:a5d:452c:: with SMTP id j12mr45221071wra.430.1638827173704;
        Mon, 06 Dec 2021 13:46:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls224969wmc.2.canary-gmail; Mon,
 06 Dec 2021 13:46:13 -0800 (PST)
X-Received: by 2002:a1c:3b04:: with SMTP id i4mr1554878wma.126.1638827173092;
        Mon, 06 Dec 2021 13:46:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827173; cv=none;
        d=google.com; s=arc-20160816;
        b=Gna7o3Z9k7BYs5ZuDnFBPFpA+i3S2j/bcoak/sPJfgxgMlPdrLKEXya9HykOlxKioq
         XKoCFvqD7OCfPof40yy0eUK/QivpNMub2lP0TlYgnxi5vnGTwkDz1zeI4ZJEMsvFKK4P
         +gEIC+wlQVfyzQbJcI2WSiQXe0b4qa1omDk57nHd6JuRf0FWdCavbH64ceOL1X7c5Bhv
         TGpx1KDUphIuhv1XMuTmNKued9fn83kQ49RCIbRT1WAx7Q+fFMoUF40Q9XDFHJQZu9uz
         4hh/+ANG0XTbNUx5/gog/9ayijuziY1eH2o4C3l9z0x3ETags++e7LYhcukysFWzf3zY
         jndw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nHVI23+3UF63ZVUN3WDdsPua2nJbVrQ0CU8a80/ebmM=;
        b=oietBltdEBz4LHv8A/gRZwGGnUt6jjkmeadowAiTDHYXCoANi8k9VjXEIGZKJC05MS
         nUEYPkAMfaxf7PmkhHg35c+zKl1ky6OvRGQsNAxO/yq/vpN+LcMQtvBTVUy8E7xi8CoN
         /fHq42/lgXBmFPUmdwPoLKrF3dLtB8FzYDjY2djPJ1s0z32WpJnGQCoytaTVY024GYHI
         pQ3iEfhypWzi1n6ixZzNcQkR3yRFWLwCrfSZJ+HJVQ080hBmM4ysm2CBA/8P1PacX42S
         L2DXRB9rPNAX9tEd52bdc81PWP5PPbTzLNUd62PQCDN5AWb7Odv3G63bQKXtGwHT5Sa8
         5sQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ujYKIeaj;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id c2si104817wmq.2.2021.12.06.13.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 22/34] kasan, fork: don't tag stacks allocated with vmalloc
Date: Mon,  6 Dec 2021 22:43:59 +0100
Message-Id: <92424a5bd4ceaabe6412da558624f2340d107756.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ujYKIeaj;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks will start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation.

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the sp register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP pointer needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/fork.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/fork.c b/kernel/fork.c
index 3244cc56b697..062d1484ef42 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -253,6 +253,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 	 * so cache the vm_struct.
 	 */
 	if (stack) {
+		stack = kasan_reset_tag(stack);
 		tsk->stack_vm_area = find_vm_area(stack);
 		tsk->stack = stack;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/92424a5bd4ceaabe6412da558624f2340d107756.1638825394.git.andreyknvl%40google.com.
