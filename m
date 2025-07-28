Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEVNT3CAMGQEM4A44CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0BA2B13E39
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:11 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3b788e2581bsf662244f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716371; cv=pass;
        d=google.com; s=arc-20240605;
        b=cgXraqPrc3+vVtmoqFPtglwQoZIvLCwzltfDrlvq41uyAM2OqJYW18zvsAu+8ffY0R
         ROkzZqJGDD9qAq3G38cbamY8JoBZYgpk+D0Eppr81M9dYH0AvYCInQ6kMSymR27Y8ZMW
         7p5EsCQWfpavyy14p2WtvmFNrs/LcCT2lrWdYMJTG/jZ7R1Z/Kaqu1Xga9u+2DNB5nBB
         xeh7OH2rKAAzzvZHloLnHx1OUZqTAl2Pqfn1kr7thdlA1dGkJbV4IAkwXLqEteU9nQCh
         dkbox5bBmVi6QGVEsLIKxMOnxLjiNoEPHmHwpEL1rm2PRzT3H8FvTL+9ocVjqUtEMjp6
         qf2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=dza/A4Cvig1JP5T41RNgY8yXQfYDG1fqeqOue2YdHYc=;
        fh=JazmpKeYWZZuFYs4SwAo9hCc10QHb28rE1Z7LyN6bZE=;
        b=bts5zp6Y5ENR53b6R3pQlz4sTMHxQYsXxaeuluE85u21nwGjm3PtkR6HAMHh1ap3eJ
         gQR2hvcFHNAUrKUwv9nBhiT7yGoeJTh2YI8zWD5oy2YabdtUcX6eatLj8AxF+Kgpd8ty
         vVmtww1UcJ/ln6cp63poC8QvwwTIjsz0ntSzN2O47n/OGa4cFMBTwCCRF+yFaHwh+bsk
         IzSD+kApleE+3dlRYNbTDf0eu1VPl6JnJm72n7zAuVzWbKMOcgldROtZcxnNmw+40Orn
         ymHwqPs2mmT7vpHJE16J7e7agko+KHVI7l98HL+76Scoa+6f1GjWE4nhWGYMjCK+8/Dh
         RuMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="I3vag82/";
       spf=pass (google.com: domain of 3j5ahaaykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3j5aHaAYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716371; x=1754321171; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dza/A4Cvig1JP5T41RNgY8yXQfYDG1fqeqOue2YdHYc=;
        b=W/+aZ5igDbitX4MfqAEONrtKdPo+Spjqwi1Ce39PFw0Oz4OOKDJHeDeP5r4a5ffFZO
         dZkPB5Dg9DtCl0YoxVAcQOfeevy1ualpXQRdF9Hq4nHN0H+831BAR7HUVwdOzem7S1fI
         lqYu5LPUPrOTWeBci/3Q05oQn2XFUaJxOI1KJNdBmBM4+B2ghB3CiUfbbxBGaIKPQa35
         wp1ucd2hYTKixJbEj0PMRByZySfKeGqAk7yd6RhxxpCkSNrAw0XvsYWcZAZv25GE0Tzf
         ioseMqNV9Yql0Le5+XolUA9zoUC7l+s3RjrPJH1rQt50DptsbDjS3XxMIAcpADwC6sTY
         irqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716371; x=1754321171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dza/A4Cvig1JP5T41RNgY8yXQfYDG1fqeqOue2YdHYc=;
        b=jaow7UpDklZkcWuIG43vJWWJhIh/u+2Nqct8+9FKryrAUZKhQSpDYTU8PEw2EcpBT8
         Pjc0dJZCjNobnkj3whIMDxOo1Ew3q3TxAIU/MZP8DXGz8X7tL+vRWLSnI1KLBGIarPjU
         1hZYaOVnc6e698RpnzDDiLPg9IBx4eUW94wPjf6Ax/CRvQ0uiM/f6ejDa8rfRiwwUs5/
         JQsww8NWxndkhTZi2fzrweGhl6POo/aFwNDVcRDAw7owp/2e0tbT6Pyx7ZlTqEfuzRTK
         GkTbN1SiNKVarKcErJ1banOvzjrlKArWd8OpI7v93E/ARjnnHN86LnqwNc6iVFKnOmTo
         sGrA==
X-Forwarded-Encrypted: i=2; AJvYcCVOPhR6Rx1vnY3YqzCrXU4pgRcqZ5U6rhyWv3wJU/e9qWprN5oDSohMMIGeN6S5FxsjyRszZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxa2FZUk+J9iYtxxfX8CO07kX2aOptc86mUDsY6v5gsEscrw+r9
	ygxAZfj9fMARAXKrJQev+ONEhvvLUtR5duX+Oh+hXolzUoFuNigzjJAG
X-Google-Smtp-Source: AGHT+IEX8g0zPOI4cL5YWQUB3UJQu4il4Zh75wtPyY6F6QAiKzOW93UWtRfWg98W0yAA3mQ3ko6X2w==
X-Received: by 2002:a5d:588d:0:b0:3a4:dc42:a0c3 with SMTP id ffacd0b85a97d-3b77668e4a7mr8522179f8f.56.1753716371243;
        Mon, 28 Jul 2025 08:26:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdVF+ZbZAyt3Mx8r7r2XVxY1o9BzHGCxD6xBtczRonMkA==
Received: by 2002:a5d:64e1:0:b0:3a3:69ee:f49e with SMTP id ffacd0b85a97d-3b76e34cefdls1966846f8f.0.-pod-prod-04-eu;
 Mon, 28 Jul 2025 08:26:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4kuta9ME/0Bd3sxjhyqvQSqcAodMEyVHhZ0o53A0yN8NmSZCFAFGEeSjTENmMNv8MO07cFM+oI6k=@googlegroups.com
X-Received: by 2002:a5d:64e6:0:b0:3a6:d349:1b52 with SMTP id ffacd0b85a97d-3b7765f35damr9902537f8f.21.1753716368154;
        Mon, 28 Jul 2025 08:26:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716368; cv=none;
        d=google.com; s=arc-20240605;
        b=SHfDwoLtYm9r6Eu6w+vMS0SMs4cuIatrtsHs3fABjtJSv+pfBvcEjyLVUqS+WAlQpF
         fssQTteNBzwaE5tigNM3oce0GG8rpfthzFsAb+gENO6KIfFbXlUl3fe1fCvQ4yunJAnu
         a/ehgqKRiM6T+jkOf9eWvHBO3TJMBhdA1ek3jVfJVg182MOb0Uq20HVw4Jogdd1JPntH
         k97l4mEjcVZjUuMGVhLhjC1NE8qusBqSD1B9nFpF9ztuvnblzvfMRKUzLv0ABkRzJdAp
         90R4d6KTpvWBQ1SboXQnkGI2E0A8tc/yJuWcarzhkDUuOQ37eTCnObZrzgFcOLyFQ6Hs
         kKQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LxbX5YL9Hd7g/YslttSYNXM3pBZCa2EzwplzrqOsm+s=;
        fh=qyWN6VW7aZuoJ6IEdAvx6SAWsHH1/vYKoU2SjFYZZqA=;
        b=MYqc2ZCD8fvG0wi36cM8MKSEwbft6BSJcJ5Qa93kAcN1bQxQCPhGbBy/BnXpiJqA8n
         vMIpQOn+152GYFRHAFsRtxKLhRUP+mrtaoULofJ7hu7x+ksSlV6LnwwvNAJ8e+8h/Obz
         cRcociE2NQ+qRUmGknkV/DdDGS4RP3r2+TsnfjN38t9hMcAuLCaLpEDjgzuRM2wKpyD+
         ZQtyuJp5WShApO8bKKZ1zJMynstRJbbbKJRdILiuToA7gtALijsybnUgJ6rRWsu0o+Bu
         Sk9TLYwS3UaMxAG31o979RGnEBTcRN6D/RRT8pZNT39HllX5oHysoQq9s1dsjyJjwEcM
         oLig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="I3vag82/";
       spf=pass (google.com: domain of 3j5ahaaykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3j5aHaAYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4586f4bffaasi2264535e9.1.2025.07.28.08.26.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j5ahaaykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45359bfe631so20271095e9.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBumvtrXxi35u82Rx2I/1PHztFdr5k5MG6mrskpG1W4cr3vHz59b1Bqqxk7k6upUqyh2K60UL9Upw=@googlegroups.com
X-Received: from wmtf6.prod.google.com ([2002:a05:600c:8b46:b0:456:365f:428b])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b6d:b0:456:1514:5b04
 with SMTP id 5b1f17b1804b1-4587643aed4mr91132245e9.21.1753716367733; Mon, 28
 Jul 2025 08:26:07 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:42 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-5-glider@google.com>
Subject: [PATCH v3 04/10] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="I3vag82/";       spf=pass
 (google.com: domain of 3j5ahaaykcsyinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3j5aHaAYKCSYINKFGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
are inserted by Clang when building with coverage guards.
These functions can be used to detect initialization order fiasco bugs
in the userspace, but it is fine for them to be no-ops in the kernel.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

---
v3:
 - add Reviewed-by: Dmitry Vyukov

v2:
 - Address comments by Dmitry Vyukov:
   - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
 - Move this patch before the one introducing CONFIG_KCOV_UNIQUE,
   per Marco Elver's request.

Change-Id: I7f8eb690a3d96f7d122205e8f1cba8039f6a68eb
---
 mm/kasan/generic.c | 18 ++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 2 files changed, 20 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e76..b0b7781524348 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -238,6 +238,24 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
 }
 EXPORT_SYMBOL(__asan_unregister_globals);
 
+#if defined(CONFIG_KCOV_UNIQUE)
+/*
+ * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
+ * when the user requests building with coverage guards. In the userspace, these
+ * two functions can be used to detect initialization order fiasco bugs, but in
+ * the kernel they can be no-ops.
+ */
+void __asan_before_dynamic_init(const char *module_name)
+{
+}
+EXPORT_SYMBOL(__asan_before_dynamic_init);
+
+void __asan_after_dynamic_init(void)
+{
+}
+EXPORT_SYMBOL(__asan_after_dynamic_init);
+#endif
+
 #define DEFINE_ASAN_LOAD_STORE(size)					\
 	void __asan_load##size(void *addr)				\
 	{								\
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e649..c817c46b4fcd2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
 
 void __asan_register_globals(void *globals, ssize_t size);
 void __asan_unregister_globals(void *globals, ssize_t size);
+void __asan_before_dynamic_init(const char *module_name);
+void __asan_after_dynamic_init(void);
 void __asan_handle_no_return(void);
 void __asan_alloca_poison(void *, ssize_t size);
 void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
-- 
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-5-glider%40google.com.
