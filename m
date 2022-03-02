Return-Path: <kasan-dev+bncBAABBY5372IAMGQEKZJ2PFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BF764CAA96
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:40:04 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id f189-20020a1c38c6000000b0037d1bee4847sf2107997wma.9
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:40:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239204; cv=pass;
        d=google.com; s=arc-20160816;
        b=ibyhXlBr5kNBj3GuzvLBCERTMV+TOIvEW8uj/Kg7tgaKnnU4Jsu7vlkvxDMkycTdJH
         Q/ia+ZW6Wq0q1RSkGZEbnZuIaAne3iKT26f5FKZzcCIn/S9Bzsg4oBoqJnOKX2azcRGL
         q53ifypT+HotqN/YNvnYaaFYkPTdd8oRSrrLoX6BYXXRJnaWu/jEXTY9vCnqVsT/tT1W
         ABo2iOChI1uyS54rHPBegfUg/gLm+XpXsK1Rqz0EYLDu1Z3ApKKJQIRu+nrWKNQhlMGK
         a5PWCEdxBgEjUt/SP1uiDXtdmN9rkre9ol+CjMAkON8Q3w4z5CPn7zXkQSXZpHSDzG0B
         mSNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=juqU5cu7rOU+MIjHsddZCTexaAcxQ1izxDQLEL/ixtQ=;
        b=Zbksb5aDKk0x3Hss4u7zzL/JoCxgW7S/hjcI9D/OpTN3RP1JjFocxKG05iq+iOZ1Cs
         e+3rb/uV2rY7S2DT+oxP+AuC+EI3hVGfbgNQsJwD+fikMselNAt9mbtQRI00dp4SM7Vt
         J5pe7F+8ma6SWn5qrx0SFVOuNVL0wl1XDYcQJkHyITrrk4SYxj3t2eI1ocR18Szd60WY
         k5gEG1VbFb31ROBPum5xkkvK5mkYLrsUkQWq7P/FBwbTS5UWx5bXtT04i6SqDVLVVJBO
         oawFDAkZxN5vJY4+yS1lRxQyG+VGvTHZYKUOzP+GCPjQEiw1Ddfr8MK2suYezR4u4LTi
         egAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eBQyizDu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=juqU5cu7rOU+MIjHsddZCTexaAcxQ1izxDQLEL/ixtQ=;
        b=DaG+HqvugV8HLN7ag7f3BFnRjiPK7OAZqPBn/CiZEsQVtu2VwYi6DcTlQbJ1OOGpsd
         VEG6HaIoVY0DkKPESpRk/NdqE+2aC0QvO0eZF0LuOWCUszewj/rkRul1a7y7RiZSRb39
         NcZRz6ycLXg4QtFCdIeH1YNHog5cjxtl4Gtk408PJNEpVYpOtdTSjLdfVqYDT28mqPCQ
         9e+xV1hpP3rRzyVxk5igsWC8EL/viQKwYo0YC24+Srscdggj5LYZvGBkUkHhJ8IbuoRB
         LyAbAAr7wuXfuhcrsiHVAx7Z1oOwB5QwGWNQheMoBsbZ8pyYOgDSoz4bUDPa4mLNAaca
         Zk3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=juqU5cu7rOU+MIjHsddZCTexaAcxQ1izxDQLEL/ixtQ=;
        b=d8PoHYUWQWu+oichvg4tFuhCEjImE77MMoBFIx+6kMa24KzTIaJw/GdCo7lbfbKGWF
         V8H1kwJtpYnSxxcbESVF0geRO3Vhzxrakp/HsH/uRNK2aErP6y4SHxkeZitgC8LqzGE6
         m2oEQRbmlhSxiucN1Eg7IfrCx3q6lQjIWLJJCsMM/y8UoABCWcLV1Cm1l64w1yfohqmQ
         67azFXbQd2lPiMXbFoQU7efAgz1SQzTI4q3esUAgtxKem+Gp2Y3kGLXtpu9shhn5qzkb
         d/JnkYe5SVOd3pIN7oXQbvKqk+GaNop+QZqZJtduyEqnapVLXxAh9Un3RFuZrxypY7Jc
         U/Kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5301foVsgnIfX5KB62f96yy81SdZ88dssWLXTzMc1M66VKqwQslh
	uQBLbN65E7FEHsPQy8jXG90=
X-Google-Smtp-Source: ABdhPJybpI88tw441zyJqFIRULgWjRu+6JsjMrodePl9n4bpGuPCna/RawPs8OPuAOu+ZIKI9dOelA==
X-Received: by 2002:a5d:47c8:0:b0:1ef:8e97:2b8c with SMTP id o8-20020a5d47c8000000b001ef8e972b8cmr15782723wrc.545.1646239203973;
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f0b:b0:37b:e8d3:90a1 with SMTP id
 bd11-20020a05600c1f0b00b0037be8d390a1ls2994934wmb.0.canary-gmail; Wed, 02 Mar
 2022 08:40:03 -0800 (PST)
X-Received: by 2002:a1c:a382:0:b0:381:cfd:5564 with SMTP id m124-20020a1ca382000000b003810cfd5564mr493035wme.103.1646239203254;
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239203; cv=none;
        d=google.com; s=arc-20160816;
        b=g/PWZxWWiwKvNH74Fmfzw107A9NZtQgAFegxFqFUNOEg9SQ496mwEG+cj9Dp8iqUIA
         4EW2o6bK1pfALg0QU6PNL55oCRz64NAfhgUH70rJ0JjPqfCQO7soWficqapQ0RTbjU2u
         VrMiYeoQl6pmVi30P7ZaXCSE/0O+JDQWSXGbY3IsNrMpYQcVHh3HkPhnILSJLTQoYAMP
         EjmRaGhcckKpg5VVYpD36JevQFMDWmSsU4XPl9NNg57T64VXXLoKm45/rA6uR07CsdhA
         mE/EWwGd1FQo65UXBOKapyZ/J3r5Z23pOnGTneAOAkpX0KrSt62wltyC3kQhnVxCbfaG
         kqUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xoA2paey3z+FS2agG9DA8SjKlQXnu1fJwhGoHYkB4f8=;
        b=Q7P7f5THtJjisSFaCBtFlvJgo9pCrGoli6YjOYLKWxUYOKV8OgfGXa363c5bn9/HQN
         N2ynQEK2PQbkYqVDp4ivgCD/KZBYbfzPJkDurpi8aMkaDh8XZU8WNZveMHbG4bnx9p1p
         1la/F5Hx4RnuSgtqA1JM0sqLaF5RoMDhiNG6YJ/ZXrHut9Uq9s55uBFkucsYj40fjtqV
         9UuEfPg1kdXiaBP5MKfbybVeuBSc1NT9yRplQB6BeBgrIlKyWsvnD7h2mu8nDtpF43+p
         yNgwawDJtGKsFy+wXioH5ESiGBRrI6l+E0a/si5DfIdh4gpj1JDsv/7M1ISo49EGteyI
         v5EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=eBQyizDu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id 8-20020a1c0208000000b0037bc4b90d17si457639wmc.3.2022.03.02.08.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:40:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 21/22] kasan: move and hide kasan_save_enable/restore_multi_shot
Date: Wed,  2 Mar 2022 17:36:41 +0100
Message-Id: <6ba637333b78447f027d775f2d55ab1a40f63c99.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=eBQyizDu;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

- Move kasan_save_enable/restore_multi_shot() declarations to
  mm/kasan/kasan.h, as there is no need for them to be visible outside
  of KASAN implementation.

- Only define and export these functions when KASAN tests are enabled.

- Move their definitions closer to other test-related code in report.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  4 ----
 mm/kasan/kasan.h      |  7 +++++++
 mm/kasan/report.c     | 30 +++++++++++++++++-------------
 3 files changed, 24 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index fe36215807f7..ceebcb9de7bf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -267,10 +267,6 @@ static __always_inline bool kasan_check_byte(const void *addr)
 	return true;
 }
 
-
-bool kasan_save_enable_multi_shot(void);
-void kasan_restore_multi_shot(bool enabled);
-
 #else /* CONFIG_KASAN */
 
 static inline slab_flags_t kasan_never_merge(void)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 9d2e128eb623..d79b83d673b1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -492,6 +492,13 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 #error kasan_arch_is_ready only works in KASAN generic outline mode!
 #endif
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST) || IS_ENABLED(CONFIG_KASAN_MODULE_TEST)
+
+bool kasan_save_enable_multi_shot(void);
+void kasan_restore_multi_shot(bool enabled);
+
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7ef3b0455603..c9bfffe931b4 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -64,19 +64,6 @@ static int __init early_kasan_fault(char *arg)
 }
 early_param("kasan.fault", early_kasan_fault);
 
-bool kasan_save_enable_multi_shot(void)
-{
-	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
-}
-EXPORT_SYMBOL_GPL(kasan_save_enable_multi_shot);
-
-void kasan_restore_multi_shot(bool enabled)
-{
-	if (!enabled)
-		clear_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
-}
-EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
-
 static int __init kasan_set_multi_shot(char *str)
 {
 	set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
@@ -109,6 +96,23 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST) || IS_ENABLED(CONFIG_KASAN_MODULE_TEST)
+
+bool kasan_save_enable_multi_shot(void)
+{
+	return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
+}
+EXPORT_SYMBOL_GPL(kasan_save_enable_multi_shot);
+
+void kasan_restore_multi_shot(bool enabled)
+{
+	if (!enabled)
+		clear_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
+}
+EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
+
+#endif
+
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 static void update_kunit_status(bool sync)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ba637333b78447f027d775f2d55ab1a40f63c99.1646237226.git.andreyknvl%40google.com.
