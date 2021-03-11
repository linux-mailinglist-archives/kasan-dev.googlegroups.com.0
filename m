Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ43VKBAMGQEDMUHLBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C5202337FB6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:43 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id m71sf7128757lfa.5
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498663; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lt6drmvo46UEIq/g1e+9NIuKfF5PJgI9kk8jYAKGJTaVwC+UBmKdQGtrOCwWTAORoT
         XWBoPJP8SAdtxvjQjfK4kFrE+KhqKBzzHFNIsjsWTA/+MS1JiVwYipm2o4a9EWTuA3bN
         rMD3suKt9Q3u9cHctfxVLtpHOpUx19TyeOWK+89NXyDs6pF6YREESKdGj1n42/xtkBFg
         OznUIIebHFO/CiXEGgalBFqR7X9gDdh4NLWwSylIa8OlAFbWwd0OucNLQTx0AshFUU+2
         gzCeKJUlA7MULgTekeS63e2bt4x9XHnfK89UhYfdbOFZDaMvHMX8zfuHZWZQDWgaLbWf
         I0oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1AsKLf5DNi7e0xXxthYE2JG5Eimkmp133BXMdbR1WSM=;
        b=sw4KrbZWcKU5q6luoact09PvP6rh25ltUIulGq8p8M4ArpWf6WnHz/MX0tAfz8Avy0
         MPI81ajZvVss/aUSwYYgu4y13dnfD/am+sNRV7Wq9DKLWHobZYESqQ7M1rna6VCRpjUP
         +mGYZckfAqZJ8I5vi9bc5ZzTLsOld+1+BK9jLQQuTYxyiNeYui/aKEJE6zdEHf1npeIb
         vr1/ZKxEa5b71lodrtLf2exf3yUr7o3ZAGEGGi6vvV2cTNVZOHHunbgQ7PMikAtU2V/J
         etIY+/HuCYbpnV4v9D2Lgc10jl+G9vFSmFeCIpI5opnP7rw6gMr/JJCfKHBJ6zqJA1VM
         1jsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SwiE2He5;
       spf=pass (google.com: domain of 3py1kyaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pY1KYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1AsKLf5DNi7e0xXxthYE2JG5Eimkmp133BXMdbR1WSM=;
        b=lPVVlHuT3/Vli3m6SRheR3SGYhi/3zDVcSFvSGmX1l+34S8YxBzOoRo9j69HgBCdQJ
         Q6dhCKRebj983b/PrfhOvq+qY2Cu720T3kfJM+P24+63tOBHPXaM3dJHuEe4U8/GuhjM
         BaPjesv7ejjv1+5P54Vh+EMzsv734JuHsnn9ZPSDf/Q7PRxX2VwkooUkYBP18P3Mr+tx
         OrYRnLv8GCN7eeKdzXD+pit3relxZD1Xwq8h8toPeZ00IrAsLjyxHqpJEomx00WOh7/s
         uw217twewUsmmQfSmb7rg57L0sraUnEvEbeUWM0/vmikdPdCdXKOJodGODiOEf1eLv4J
         A9fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1AsKLf5DNi7e0xXxthYE2JG5Eimkmp133BXMdbR1WSM=;
        b=d+1MwaoQxmPfa5b2vBhA/lzf0+nv9+JE0SGy+vDbdR9cJ7Wuin4NpRj1JWCEtDmKS4
         eNr/HpWXvq34UbwjC2fhhzGSEZ+jOhQnjE2Kiko+Zu5BFc5kTv/DoqHUk+QqXPRh8usJ
         erMNa8wo6qp3XIDNlbwH/0/F6Lvw4CGFg7McSJk56VgJQNQs3e01UfyxLTcEDjuOb+SH
         xOPWL1+R0w/RnIC2lWKYuLtA7oHnT40GIeN5xKdQfSdImkIhkKdp6RCYiGouoPd7outu
         VcLjSLNaf0sGS28401GSCFi3FVK2K2SI7WqnqiW345ehhsK1hV3g95ZKH7zcTt5SEPla
         c5Og==
X-Gm-Message-State: AOAM532W+IeE9APn8GQVa1kb7KAc/zvPkRAiVeyIiGWPc8u+apHUCeg7
	1jEsF3lYY0KhbmiC4rMMjko=
X-Google-Smtp-Source: ABdhPJx7m6vzwfvpCaSVNBdNJjNJgGvt3LhvR78rbA7LlAupuKkZwPxMauTleuZ9BDtEV6CmS5krsw==
X-Received: by 2002:a05:651c:149:: with SMTP id c9mr502529ljd.101.1615498663393;
        Thu, 11 Mar 2021 13:37:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9212:: with SMTP id k18ls1532307ljg.8.gmail; Thu, 11 Mar
 2021 13:37:42 -0800 (PST)
X-Received: by 2002:a05:651c:1214:: with SMTP id i20mr488400lja.423.1615498662399;
        Thu, 11 Mar 2021 13:37:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498662; cv=none;
        d=google.com; s=arc-20160816;
        b=AzdnFgro1YbC8ca59ZKrp0JSotwbnyNrBuJzkBKamySSX066fe/u+S/RbJg6XrfXGT
         JvWvhBijUVI59lAXEqBJbGv5KbFvEZL9y9ZziSmUD9eGTNv/Otomn5e3t0/vKJbxjDRu
         aXQTStYgEXDBm/HXrm5Rz0HuVMdCJoLBh86oDo+SO+jdh6T9G/+DKN/ZgEesHSRsJ178
         feBQ0/vHOcxHVdZ6a6ZqLPQ34uiS2JCCfyiFB+YDIKX3NOrr5zWGQAzAKM3e8G8Lqwpp
         GmJN+TSmZgNNOqGJQ0psc6cDeoI7K6MAhc1VM0bK7EHbMHM1SNHUvNP+PWGkUUYHu6Up
         g16g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gThu0TE1qL9hnbQQaxSk/qxvpsDDtC1CzspsMmD08OE=;
        b=jTqubDEtE3ENeo6EPOgTry7wv9JJGsxv6EdNtsQGeQpugyZ0OvTpyg8ukj5Kvybi+M
         FRLxyn4/68OS28taSQ3yGpA5DbiYv3RbHjTU+Kzz/vUpu8JGvfkeevDbFBhGvkqQVqLL
         o3yL5aGRcdrCQpk3QEIt9A+KV9/HqDV9q9QOoIg5xTaBy050iOy6KFhlrxSzfCFT5xAp
         m8c5VHWhyiJkMvnWULtiw2G1WOSBgOMsRMFRwOXT+2dfre9zGnzmlSJ9+2yRnH/7ll2L
         qErpB5cq+fSv7oo/FfJb91JW+Ks6nwLDBdnwPQ1M57/88B4s6qqj0yWSpQdOTTcX2ufL
         Jbaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SwiE2He5;
       spf=pass (google.com: domain of 3py1kyaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pY1KYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id p18si152620lji.8.2021.03.11.13.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3py1kyaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v5so4556784wml.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:42 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a1c:f614:: with SMTP id
 w20mr9884303wmc.70.1615498661923; Thu, 11 Mar 2021 13:37:41 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:19 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <3ec89a4e0783ff3d345310343d7ef10d46c8adb2.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 07/11] kasan: docs: update SW_TAGS implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SwiE2He5;       spf=pass
 (google.com: domain of 3py1kyaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pY1KYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Implementation details" section for SW_TAGS KASAN:

- Clarify the introduction sentence.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 39 +++++++++++++++----------------
 1 file changed, 19 insertions(+), 20 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 1fb4b715a3ce..dff18e180120 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -235,38 +235,37 @@ quarantine (see mm/kasan/quarantine.c for implementation).
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Software tag-based KASAN requires software memory tagging support in the form
-of HWASan-like compiler instrumentation (see HWASan documentation for details).
-
-Software tag-based KASAN is currently only implemented for arm64 architecture.
+Software tag-based KASAN uses a software memory tagging approach to checking
+access validity. It is currently only implemented for the arm64 architecture.
 
 Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
-to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
-it uses shadow memory to store memory tags associated with each 16-byte memory
-cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
+to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
+to store memory tags associated with each 16-byte memory cell (therefore, it
+dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation software tag-based KASAN generates a random tag, tags
-the allocated memory with this tag, and embeds this tag into the returned
+On each memory allocation, software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds the same tag into the returned
 pointer.
 
 Software tag-based KASAN uses compile-time instrumentation to insert checks
-before each memory access. These checks make sure that tag of the memory that
-is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
+before each memory access. These checks make sure that the tag of the memory
+that is being accessed is equal to the tag of the pointer that is used to access
+this memory. In case of a tag mismatch, software tag-based KASAN prints a bug
+report.
 
-Software tag-based KASAN also has two instrumentation modes (outline, that
-emits callbacks to check memory accesses; and inline, that performs the shadow
+Software tag-based KASAN also has two instrumentation modes (outline, which
+emits callbacks to check memory accesses; and inline, which performs the shadow
 memory checks inline). With outline instrumentation mode, a bug report is
-simply printed from the function that performs the access check. With inline
-instrumentation a brk instruction is emitted by the compiler, and a dedicated
-brk handler is used to print bug reports.
+printed from the function that performs the access check. With inline
+instrumentation, a ``brk`` instruction is emitted by the compiler, and a
+dedicated ``brk`` handler is used to print bug reports.
 
 Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
-pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of
-kmem_cache_alloc/kmalloc and page_alloc memory.
+Software tag-based KASAN currently only supports tagging of slab and page_alloc
+memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ec89a4e0783ff3d345310343d7ef10d46c8adb2.1615498565.git.andreyknvl%40google.com.
