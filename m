Return-Path: <kasan-dev+bncBAABBHMC36GQMGQECRSDMOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 836604736E5
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:37 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id o18-20020a05600c511200b00332fa17a02esf7047701wms.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432477; cv=pass;
        d=google.com; s=arc-20160816;
        b=G57VRB//RNX9+bdENtTUrNoqCnnbTpdNlWCBhNAJVBiWhxnhhM+u4mE36xg2io92HR
         z51gzbVCqQxDsf9dnHSMhj7PfEUZjbChyPmcosGHayiRWvfxFxUeeHZaZCe4/dnWN8OA
         fdn6GLzM2TjQdRdzKuRkzMeCLcHlXU+WNYw8BGQqMSwQkOIMBc1Mi8C+zHw8bcM2hbHM
         YdOS1vCQ/4UWp2OfPYxdpVAL5XE8/jVsnVtijw1X5W/Tphs4IIlttBNF8as4QdDXutLH
         FoiVOfLqe7O4DuSrNTid+UiIIx0dE7izBX+sPsusEuAepdFF9YzPPTkSqWct8SHpOs4b
         ZKGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jrDBi93txlQyigXfaQfjtl+fkH+XNcxNdFQLhFXStTY=;
        b=uQ02WxxVpB5mecWcIvflrA/Hojxy8AlfyU+CjQJxaG05QbM0NiEe0XVKUmQC9XZAJw
         NFPh63P2YVxqkqYKOAcpanWg3RnOM4VTseNo5n69jLPc1SPc5pIaxdAjQLdiQ2vZo1go
         udHxrwsLhG6619P1BhrOHOVg9u5Ork9yHIeYcX7/tkUp13Vn5MimciyhOis2BqYzgWe5
         eGMNGdEIZuvPMfyNcz3uZ+wCZDY72u8n5u8B/W4zDvjGS2xg0BPDWbY+Y0Bwo1X1Mkb6
         DI23Zd/va7OfqAj5AKQvQz8BBQQkLsCdQlcgknncMZTUX/3ngLTHwMUPm9cdAFSwRUZ4
         EE9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=udatEMOw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jrDBi93txlQyigXfaQfjtl+fkH+XNcxNdFQLhFXStTY=;
        b=GRpmGycFr7H8tfPpBQvhs0qmiZm2Q+RZEtd0Fz0AIPVj2EPJV8ykwDPR3BjHrIlSyO
         kOT/mthXLQOsVA/B4YGNxzFgxvqvI/rTSdzSthTKzUdhsbQP8NbbZ1uv6URu2ljgScJN
         j3VHprKRa6fLEXjHWR978gdd+IP6cVfGgRgFXgG70fiZYx4Fkoqgeh10DA9Xe1M3wFV9
         gOOq3qggGFdmvFMfShfcZGZDa8TZLiOmsmtCdgCHQ3gEo/cjh6Ly7fIK1540doQHsLwW
         SUwpbUG+TtgtCJcqm+a/r33HTC1YA4AyFmfWFQLOKMadDCrO0VxxQAwaa47cP4ddGity
         G7rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jrDBi93txlQyigXfaQfjtl+fkH+XNcxNdFQLhFXStTY=;
        b=eEcF2GVmBF/LeOWywPPyodkgFdzhMOnpQ3uPJqLWVr5DuhX4yEWSrZOlVqeu3USCWm
         FL1nCNMOy+s60ytetwqCOKgMSiJ4sCODkdkLHcyJE/e6W1z8YAXFBELea7+7nWYhA8pu
         fxga2cvgvXdTOZ4lYur/BWNwwai+ue+VjFA2PjOORKpTBgsFULDMe2IA344GcKKSF2YO
         iknmudypCUQeQB5/fYR5IuTxGDfZuNBmd8EiBW3UjphTAVdcafVQ1RNCssbMcxEvJJmz
         pReYq5XXS+zpwQ/KHWQPxQOhq7m8//pl10WzLOwzrTxAwxI52qaaV2wQRrhN9mrMTDY9
         nQuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pjNNhxFbVFiNMGCjkE2+Bs2q3q6U+oWhcbv4UXmz/NC6BFMOg
	q3soUWi6eomFo/kXw7YLkAM=
X-Google-Smtp-Source: ABdhPJz5BvhajbbvCayqwoBT6NW9McdpSV+m95NEf2HOIZP/qEFTQD+GkJ8q+hereWLDY7K/kmafSQ==
X-Received: by 2002:adf:f551:: with SMTP id j17mr1260715wrp.392.1639432477272;
        Mon, 13 Dec 2021 13:54:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls501749wrp.3.gmail; Mon, 13 Dec
 2021 13:54:36 -0800 (PST)
X-Received: by 2002:adf:e842:: with SMTP id d2mr1243822wrn.399.1639432476523;
        Mon, 13 Dec 2021 13:54:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432476; cv=none;
        d=google.com; s=arc-20160816;
        b=LtAUOWad66IPLtFtO/JJkZHB0fJSII954e0sfiwiPRMHao2wE+ImyZ4ZdUcNFlCj+H
         remLOSzg5Yftva0kSb1dI1EBaLgyTZzZ4gZlmTVHOhps83Y8ZNxoWb88xZeZ7TYiAlJo
         ZU/CmE5YD3Tw4mdJQZO9PUCjirtc01kQVtrUtTtOgUqLx3oWqzGF/u2+A09tv+tDt9v6
         nT3Ph6jBSLvFmlzelALn82rGZgREgTOTaJfeGM+pK6AHYe6g4N6qel5Ccu6ctuYvSCmw
         t5ZuOusIeN4uESH4FjM5y2yxavY3Nr68+cf3Yg6SoPAP3NadDiRoCUZzF0oeAstW4T3M
         hFeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IMzV1X5Nd86e4oY4hBFTxC35nepZUwTPpD8+HwJgmqo=;
        b=xLj/dZjWfZtxVjNk+zKnabk2ncFAEHsXNEN9Nu3jYhmWdc5KZ0ckrmu64lusVp8Zmp
         BDxhvDFrdv4orx0LOX5HOUSi0TBoUo6tRyz6TTI7WP+Z2UqrcDCeR7ujuYNMznj7weGE
         gFsbz9UD06MSk528FVwzXAJOiUiY5VqRMn6bjj0ex7iaOa66V3SZzuKtB+htFNRc9yTD
         lIHWDPJFPt7plVrIbU1IWDDxb1HoSjqexhELIrlCSeEXaptv9lXGgOkQcss/GvELmSDN
         P+w1mWOagHLxKQKXGPqejiDUDQM5Q+T9fDOiFtxAvNHSftgCxXWZByapeSoUCIl7YUDb
         lTHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=udatEMOw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o19si15112wme.2.2021.12.13.13.54.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:36 -0800 (PST)
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
Subject: [PATCH mm v3 22/38] kasan, fork: reset pointer tags of vmapped stacks
Date: Mon, 13 Dec 2021 22:54:18 +0100
Message-Id: <4f7e671a95dd4b2cc1b9188da0da23302a94f6a7.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=udatEMOw;       spf=pass
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

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation in
alloc_thread_stack_node().

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the SP register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP register needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 kernel/fork.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/fork.c b/kernel/fork.c
index 2993a0058f9b..9e488921424e 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f7e671a95dd4b2cc1b9188da0da23302a94f6a7.1639432170.git.andreyknvl%40google.com.
