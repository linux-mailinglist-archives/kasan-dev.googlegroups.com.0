Return-Path: <kasan-dev+bncBAABBP4KXCHAMGQEOU2YOYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 529F4481FA0
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:12 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id a13-20020a05651c210d00b0022e1dc44d53sf413891ljq.17
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891712; cv=pass;
        d=google.com; s=arc-20160816;
        b=SHMjDuKpkY5f6NB4rdTRUy43mIPdq64EklvT/jiPk0Z6aGiPbSjAM5SdiMt4HTrupg
         cHy7OLNptWH8FtfCFpMfx/GiGC7uc9PlSSwLa3aWYa6ikcghHKseLKEB1uMmldOgR8l7
         JeSca1pLsfoVDd4k4HFLOUB7a1IsXMDrAcpOF+bJVAKuiYa5wOBfiDNvam0XCrPpq1No
         Q3nUZT/d3ldF/L1cDQKj6X+GXr/T4ufmAYPTSOziDayyyRgZGT94w8v1tniliG8n+Q4z
         YFpaYMAkxhxjcJwV+3Xh3oOKWaDtHtFu6IVL1nDCwkEhUNVhNq12YVjwJ8++OION3gzy
         gKNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ThKrjvOGs2fMUn0AAK8RnucxO18h9uA30bTCpCczkQc=;
        b=KFgq0im2YJ83rw6InTCsEgwnu+s0rpDm3U7cHGQdhDsvjTGSps1oFpS4jc3TPBGFF/
         u8rwwqtedoNFypXNzV3an/Gfo3KNRjMnOAt+UEtBV1T0+32aCaGwSbls0UKlRMEs93dm
         LGjjxVlagAaKmz+8y1zAEGRHuxwqxAlKzE359bEr2MBrJRYW7Sa5CbBWhpt155NcVidU
         KLeL3jb0sVmEAI8JfKLREimGPbFIgMNDGyL2GvhPs3Id4KliWNOAKUkh0iTk7MCV2beL
         6SBNC4X0I10HfevE7qAgRXWqD1rylA2VA0p5r9qlViZeOGkkOkqrzU7eldAMajpy9XhY
         YSmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZqQLEZg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ThKrjvOGs2fMUn0AAK8RnucxO18h9uA30bTCpCczkQc=;
        b=fPWxwBKpxrnO/mlRDhym00OPwN6XC8D13RGX9WrmnsqOskx9cYcrA3jJHz/UAtuHQi
         Zyg6baGeK7PU18QTSJgOhgA2jM7SkK0iTFQXSNvAZVFYKfbC+3qzrslR6fn20izXb+oT
         jea5B4gheboLDWiVPkFn/wsVFao5RTfjX7cIYYVf1cbM73HizgQpbWQ3/g6c/uuEm8yH
         KswTaQulTAxO7VMI2pK6fnf+WRyICw6xUxjRC+iRyRoyXCJ7M0qJxXkIRqxQF+8tToHq
         4A288Vrv2rWm8phvSpe3T6a1afFMfVCCi7YJhisSdAlcLdolc9DqIp9oJ8+91D9tfBOE
         v2CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ThKrjvOGs2fMUn0AAK8RnucxO18h9uA30bTCpCczkQc=;
        b=NCwhegvj9iMzmV+pFS7q94az1Pr19OmNhrc7RpX2bHaUAoE3daRHXdGJKQjUdit7sE
         BvQIDRVATEAAIl8+DwLOKsk4XuIW/CF8SjElbLiM+qFE/Si7nVx53vFIGocmb6O2Byd9
         z4crJlpjBQ/ye6gtKHGLx4tSg/Q8pIITY5sH3uWxeoSn0XQVN5iM4GhZ4BBwvsJUCjtF
         mBkfhJE7KyienS293fe4JiR2zIuE5Uwsi7YhcnCpf4VKkgeo/0KS1Cv4K0vaNvMg4QvC
         rxhDpUm/qNuB3FA4DPe6LkuE9pvEL5/dma7iNb+ou8Qk2cLOnJL7bH4+v/+YeMS325z3
         lVwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530d8SabzP9J1fscwxbjNQpoLifqYeay9x+XwNJSb52Xm3JR5aqn
	adPm4v0LU8k/g8WyzQ26QXg=
X-Google-Smtp-Source: ABdhPJzhu8A2w7MtZ0ePwNTJRoNzMJjcSX9/EfYELjrsReRsh+RbDvgYXEQxuvWeBMRNgNm5oMy2OA==
X-Received: by 2002:a05:6512:2103:: with SMTP id q3mr22159858lfr.538.1640891711938;
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls2238077lfh.3.gmail; Thu, 30 Dec
 2021 11:15:11 -0800 (PST)
X-Received: by 2002:a05:6512:220f:: with SMTP id h15mr28467158lfu.137.1640891711286;
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891711; cv=none;
        d=google.com; s=arc-20160816;
        b=DjrQTYqn//V4nCa8urVp9O1gPNAA6P31Zc1fqcV2JnaqrxMX93f25mzOiYZuTGVgZd
         aCZXHmzCiMv1ShfUWyx7jz0zMZ3j0Z9DjKSPHzL2+3K7jaSa1x5NgMlmRahDXss3V08N
         LCtuIdWQKFXkIkTCOgF3ewgc2e5g24QpTp5067PecBQ8Wv3rZDWDaKWzI9L2nYieGPEZ
         gG+qyixT/cx2U4M4/2EnUqOqJn4WhNqTJ/FYSbSdDD7+kyenSBS5RlXtKDkS/2UP9yov
         dB8g1I1gPB8KDCrXadp8uvEk3ZUDll1y3frpAGMWH3ZDuen32wBqPL+6qwOTNyox2w12
         To/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/m7yWk0TB8ReTTBYiN5UEq4jCzWx0qUSGwpwtza3XBc=;
        b=yIMwxkUP3f5Eo3gx9W8Oi4V+I81iBy295+G1vP2Q9kjIwk9TaFwmnJp7sI7rAKL4EG
         qS0VOPzWDbJpYMZX8vbe+ofzUk1d92o4jZC1OIQaOWoo3e9ZRP8AU8XinWwDOPJdLOkp
         Adzt4DtUgq1c89M6BKW8KYI+MIyPoUeuDv1kbh9cItJINAR2UKXT6SesIZjl65LD4wJI
         27i8ZUvykG5NUl8+nfJmlySp/JxHWENtXsUymWh3C27hu8NeR94MEc672Sl2dsOVtIl3
         4pvoWUMDQdaqVwDubmyghmwXDSzGMyqZ4bNp8kekkA6lImFmYdJ5vVo1EwykEMwLq/BT
         Q/oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZqQLEZg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id b5si893480ljf.4.2021.12.30.11.15.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v5 22/39] kasan, fork: reset pointer tags of vmapped stacks
Date: Thu, 30 Dec 2021 20:14:47 +0100
Message-Id: <0a01ad4e71a0861702922ceda87a34a1b4313aca.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iZqQLEZg;       spf=pass
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
index 40f7a6c2a710..5fdb74c7db83 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a01ad4e71a0861702922ceda87a34a1b4313aca.1640891329.git.andreyknvl%40google.com.
