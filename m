Return-Path: <kasan-dev+bncBAABBYGUXOHQMGQE6N66APY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C6264987B7
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:21 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id la22-20020a170907781600b006a7884de505sf2429810ejc.7
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047521; cv=pass;
        d=google.com; s=arc-20160816;
        b=WsDFt36Esdh8QfD+sjGomO9mNbYSy0VVlNyplQ2Hs6QwLJU11BGgII0lMvkKyAvEp2
         mUKy//NnfeKUeuY34x7z75bbJq6LQmf23YawISfHeYVKtc0aG7HXITQcMjbfyfVGGjNC
         6r8LAaM/txOkb94XKGw+p5dXSX9a5ixa12LXjMZWKyQdBw6Ncan1UD4pz/Z31NTtd+ql
         kY90O3gO5QDwfCdeN1xI3akJb7vQ8xqScpJ78sb6+6WR+AoctG0LsFt8n1ppXCkbKZAr
         2E0qbI3EWcnBwJijQMs9LsELdRfBsM7XIfqv37obbe5dxj3CRnwSUTEMdzWy2PWGyy/j
         xURQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EDkcnpwR8WzyyUlL6jf4f9q4BP75M6iqT05/IrVlLg4=;
        b=n7sG/INtS+goxvkj1VZqGlQdyDJSKGOl+75Uqq8UzYaon/ky4Xv/9mm8AF/NNQXu60
         ZEJ6mzlHm22u5//chff+iRhPnCFHRXdo7M835/9QJyifm9EVOo1sxaEcyguauwtf5cqP
         jVo7PjsaBHetyxGUyq5ybxx/imQVAHWaIhnrjH5NslqOtfs15zP3cXEXlkKYBBqj064y
         cMUIRF9/Ph2gK+/DPKzptMOd+9rVG3DN5sqfeH101yMjEmKuNgv6MeMb/PSRAT/dimg/
         HgAXwjXhLxfdyXDTZIfRh0I2xsgcQCok1ZEK2BiVkBT06k2MVB+EepmM+yLZNaCOqhIw
         SGcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IyNV3VAB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDkcnpwR8WzyyUlL6jf4f9q4BP75M6iqT05/IrVlLg4=;
        b=K6aDIonaKtoWMCMMh/6qBdtwxfsp9/A2qMw3a2K3CjzMAUJgBBynBXzIaUK2yZly2F
         v8P+xxV0QqUQqbabBskto0SXaiLcjjXJpuyrW7k2buzbNRJRvhSjvK4VTJBfY6B2PPpS
         PLv/f/JrLdArY92FLbPdElxY3Jm1TfBTnBPobfizZBJyUZ3Rnlf5G4JMwpGsoQlY3fMP
         QEhR5n9wDGJr0JKHekZZrtwj7zK1oC0mWMwM1MA1V/lkEyUsvF4Cu2WQLVFbHtSRJ1Vx
         T+NlrG3uvuYhUjj7xKthcrjayIOz46sifBAUWszau54AVZ0c8fanXCn7OUCslbeca2P8
         kRmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EDkcnpwR8WzyyUlL6jf4f9q4BP75M6iqT05/IrVlLg4=;
        b=8EKXbgimVps1EotpHNozAsdafYqXLUHE3YNlldwrsm8iQHBbMJEYGRQopZq78hNHey
         OmKzXeL1l/9plUTQqrD2QvcCHuNgn2HlK0wdAsGGSU5JuwEsbPoCQd0UYZEe9yMBDOjB
         oP1gEvSC9fnbB5RQSM6CiYSF/l+37dKihWb7EH7ebhnnbzkYo7nY9ijjUe+MdvZABRZD
         U9WLZDGqBq9HfS2E2IjxIeYa5PmvBX5Oi+tlI2NuhpF2gvZD5icjz5hVNO9P0BJmNLXp
         drG/6c3Badvhfy+++ee2N0LC5QyVbeEf5Z2NVwlRoaE3r0oc986GMYzUvT8qf+Kqt3Fe
         DCuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PIhtmFSd6pMPwEmPAjW/28n8ytIG9NvqxksOvIwf+/Foqk03y
	YrtWWKJwdyB9anKv3mzc6H0=
X-Google-Smtp-Source: ABdhPJwZnbQCYSrOX9TuUF1BwvTi9BfTh5OaUvSm7a6j1faWVhw5XOkDkL2Zsu4YhryvQjPhZ6WsKw==
X-Received: by 2002:a17:906:4883:: with SMTP id v3mr13259622ejq.285.1643047521020;
        Mon, 24 Jan 2022 10:05:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5190:: with SMTP id q16ls5750997edd.3.gmail; Mon,
 24 Jan 2022 10:05:20 -0800 (PST)
X-Received: by 2002:a05:6402:2706:: with SMTP id y6mr16627965edd.308.1643047520374;
        Mon, 24 Jan 2022 10:05:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047520; cv=none;
        d=google.com; s=arc-20160816;
        b=uD5Roq3RcQeoDtnOs/gmFDWJA/YPcGIkbd3IsKYZCA6ZG7DhvUR5UbK/TNF0qglQjt
         B1L8IM/RstRvP1CyAaLMNtNo6aNE+sT6xMthwtTu4tV2p032qngYfT4BXNqJ6q4YOaQ9
         ZazrOwGer+BONgiUa4KTCMyb8o9qxyA+zlBqDhch/JhJWRDuWzfBw6dceS1V/TvuGWLw
         nCaLI1WLEmY7w3mwNJtJNOCyPx1nASa5ZHOVMTdGEgZkDjGDgKtvj+VqvmVlXrHplpCp
         RofcmSPbd9VYqtlMQz5EXnnnnFt/94/vSX5BxY1a0budGn2zq40H+HYNjqY5o7cmTvCu
         RkHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/XjTstEAGTMnS2cfhATsR9x5w6K0TN8X9h4vHjvkVrw=;
        b=CwFusIXFiyj75glnrZzFPP/OcGZXAbxo59WdHVNgHlRn3s7E5Z9sS5hw4DwGVL2oFZ
         Y27XrhVcSZDvufc6IxaqdTlhTbdZj1AFixOC2YyeG0EzSRIQMHqxIQKYMC0OC/CtxDRy
         +3YmF8kUj5qKV3kAkecpcDsBX/3LUo32caBeAvEVgIq40P4ZyVdkXtw5bdeA7xwaEsUC
         FBefcQJ+IaoTIStKPjsEpHZ2Dbxb+WtdbRwaldC7uUzJoLeuuMANU46KnvQb4KEo+BxQ
         TLTfDUIb3xw6eCuEuKcBs+FPzDcRcYxBiPRJWbrYsWhFwPO76nFjBj9v67Pi4RKK6YMe
         lSGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=IyNV3VAB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id i16si649002edc.4.2022.01.24.10.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v6 22/39] kasan, fork: reset pointer tags of vmapped stacks
Date: Mon, 24 Jan 2022 19:04:56 +0100
Message-Id: <c6c96f012371ecd80e1936509ebcd3b07a5956f7.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=IyNV3VAB;       spf=pass
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
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 kernel/fork.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/fork.c b/kernel/fork.c
index d75a528f7b21..57d624f05182 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -254,6 +254,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c6c96f012371ecd80e1936509ebcd3b07a5956f7.1643047180.git.andreyknvl%40google.com.
