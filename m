Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ5EVT6QKGQEK77NBLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F8762AE32D
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:53 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id d4sf10378867pgi.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046852; cv=pass;
        d=google.com; s=arc-20160816;
        b=w0z7hIHtFO1Gv+ksc47swVWmC0sQIwebTjhq1u7J31utyHSW/Fr5ZobXEBMcqyw+BK
         0tAneiq9e/gYptx9JuUvc9bQY3RVaRBsfzSYeWIwmQhyr+Dzumgrne/yZOlGHC60VUnb
         3KVfLfxpPBK21BQg3QuxeeSX7DcQRi3KKCd1P5L8PsFFyccv/Wh4PuoR2nQ1MV3WFd+I
         8MZ6Negow/cEu16wtg2ue+2dn/75dn8OXAi0sOSmSSBuu2sRWtKm1vdzw505MD7gHqc2
         OXWLCtj+6RSf33K8K6LMZPygyNhaHsFUMFjxBgiTbWZsIKcU3t3IL2oW4+KOt9bcnPHk
         WVrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8QxJg43ikGS9hTY/267YnuFsa3Hrk+7tPRg/9r0XN+8=;
        b=j98xo+NZMPC+xvs6e/V0NEdtaNTJSyWHyI1VFyIcPOu1s1eK4jiJxKz0jjnbsWTE7g
         Az6OEpuxVIV3yHRsjn7pIritJSU0rJQJ7fMYlKS6r5phHUFnuGxTyu6y+DdO7Mw++iOz
         eS0RZhVJ7q6gvcyJRSJ5NxsY/R5vZutNPTvFJxQ6oZvWu3Q4p9c3Z09bibEsids+yx+L
         ReJRMIEk1Rf2+03HQEpkygkXWTFjvExOucZEvnjk+CvTXPRXEKKOLCl1gFMOl0d32Nn9
         yABYFh2uzturO+bwIQzmWaNjYgLiiXxsR+nkRMhwm3gh1N+3dW0BUI6E19umrAoZB0Ib
         lsBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HbmemqL7;
       spf=pass (google.com: domain of 3qhkrxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QhKrXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8QxJg43ikGS9hTY/267YnuFsa3Hrk+7tPRg/9r0XN+8=;
        b=mDxMMsWOkJ1IW8X2R8l4kBs8ZACJ8rIEHqo3eRXRZt/8l7u0X5cTbS5bja0KQ60QkV
         gwAh8ZpFNj/J9tzUBJUlFrEOElKZUOq8sNc/s7apQBUayLVYZ+iA/AEads0Zqmt3BjAD
         YjB+1DvQk83xV59B31aZdJhirNfqEroos2YDMYgKilUjplHbAMdMIsKl8tg02Gr5U1zp
         hs6eNUdkBdfdksZAjPmhLrtksOOQ6Lvsa6DCM91i83zxpQhBvYYIlYzqOiReNBi/LOV1
         nUAi0R2UDsWhYfEwGahGQSmtumvpSKHqw0EHYl7X/4XqHHWcwVSuVLtoYbHTsZhv/3Kl
         SRZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8QxJg43ikGS9hTY/267YnuFsa3Hrk+7tPRg/9r0XN+8=;
        b=UuCc+dZhTLbtIMssC7bcB6kZOprSWFa53fAnuDsIElaor8JckA7YGIgCExub8JxDHZ
         uf7rsicHkuzgu/yA/lzDqdFGdQcjJ0OM/bg1iZDClmZQqjNOJ0EoqpUP+WVBfkUDRGC4
         kCmTw0Ou4jwC8UE5YWyNRtYUQIIW0ZjDgad/KBEF+tH4QK/1PBkgbolfpdP2KZiiAZRO
         Ax89wTqsj5vGCnF+rgvFKLA/e0NzGjvema5Kyvpl+mb1DtuD3B/qK3Q8FRL6Y01ZlQiX
         RYWQcXM1nGehsDjIkWRQyQsA75wdvMt56ez2CNHFrQe2E0qz6ZJj5QGSgEpjaoeE3Vby
         mD/w==
X-Gm-Message-State: AOAM531n56D/tOoNA5IS2FQ5mlWhWX/rfS4+R4K07MZs02da0ai/bQHa
	PqciDeIvKwxIdnqkYysug18=
X-Google-Smtp-Source: ABdhPJyDs5jXZV5jBa3Me4XY8LRT00zpSJHgjqykBFKv4w6iPzl2pqctgxhxRgm2wzTUT0STcOX6QQ==
X-Received: by 2002:a62:8053:0:b029:18c:733f:fd88 with SMTP id j80-20020a6280530000b029018c733ffd88mr2004285pfd.69.1605046851825;
        Tue, 10 Nov 2020 14:20:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls2782749pjq.0.gmail; Tue, 10
 Nov 2020 14:20:51 -0800 (PST)
X-Received: by 2002:a17:90a:d486:: with SMTP id s6mr300859pju.115.1605046851303;
        Tue, 10 Nov 2020 14:20:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046851; cv=none;
        d=google.com; s=arc-20160816;
        b=vv9X96DPqsAjAbSIBRbqsNCB4bbEWTQE0UsZ1PvlgyQr1gQDXAH49WtGPwcECtLAcr
         Q+q+FJ0rvRKu3ZGJvq7ZyznRO0AvUZhkXGaFHCWwdA0Y9vpj1KzUysXL6+3FR0DUSaxX
         TFHt0j6L6coWpcIIFnWKszsoW2ih955zQxhm/uSru2mvEX536mNPFEy/OWF1qbLbtpEA
         UPguo8e0BpDclLuU0jhqfI3ztgVbf7/78TTYBWPmaGAK6366Zsb5xCAIyYKGFvH0ePwm
         rhac+iMo37NjludPkthydoBu9NEDo9LGOZ/S+ixFrykMy+Mxg2DnXe0EtDo0G6Vr685y
         6eow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=WOMasW4WeK4i4aCbvBDhnou95P0GnHEsdPLivTBemP4=;
        b=SlpBLFSidZ5EjIVMB6tX+mEQ4TkAI8oRr3+b8qYwqaI0Oj6Up3hzQmryuj3ZYZsJXi
         /R6T/vdR6eJV7XWJEJF84RXdvS0+hnWSoOiOtImfzKDHhodYPlyz5tyeD2PmWfxxxFDv
         BEfgncxpw0aQeXyIKsxMNegzfciVTpj9FCmcNQFlNUNQvQ9J4qE9jiFeI7ItEJYozNIs
         wQEfyQmRxZ1Ts6hivaWfgA/hGeX54iji6zGPHo8oBSGo3DMAQ0If4yX37YoXlvGc5r5P
         CQql/ym5EL8Re8D6bjWGraxOclyCIc8ladhWpLClwTGuLBVwZAXM6Pf0yRaEdrWb0IIu
         m3hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HbmemqL7;
       spf=pass (google.com: domain of 3qhkrxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QhKrXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id l8si11139pjt.1.2020.11.10.14.20.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qhkrxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x22so194416qkb.16
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e2f:: with SMTP id
 p47mr14534879qve.11.1605046850374; Tue, 10 Nov 2020 14:20:50 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:13 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <e14ac53d7c43b4381ad94665c63a154dffc04b6b.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 09/20] kasan: inline kasan_poison_memory and check_invalid_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HbmemqL7;       spf=pass
 (google.com: domain of 3qhkrxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3QhKrXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

Using kasan_poison_memory() or check_invalid_free() currently results in
function calls. Move their definitions to mm/kasan/kasan.h and turn them
into static inline functions for hardware tag-based mode to avoid
unneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
---
 mm/kasan/hw_tags.c | 15 ---------------
 mm/kasan/kasan.h   | 28 ++++++++++++++++++++++++----
 2 files changed, 24 insertions(+), 19 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1476ac07666e..0303e49904b4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -30,27 +30,12 @@ void kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value)
-{
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), value);
-}
-
 void kasan_unpoison_memory(const void *address, size_t size)
 {
 	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-bool check_invalid_free(void *addr)
-{
-	u8 ptr_tag = get_tag(addr);
-	u8 mem_tag = hw_get_mem_tag(addr);
-
-	return (mem_tag == KASAN_TAG_INVALID) ||
-		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 7498839a15d3..ab7314418604 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,8 +153,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -194,8 +192,6 @@ void print_tags(u8 addr_tag, const void *addr);
 static inline void print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-bool check_invalid_free(void *addr);
-
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
@@ -279,6 +275,30 @@ static inline u8 random_tag(void)
 }
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+static inline bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = hw_get_mem_tag(addr);
+
+	return (mem_tag == KASAN_TAG_INVALID) ||
+		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+bool check_invalid_free(void *addr);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e14ac53d7c43b4381ad94665c63a154dffc04b6b.1605046662.git.andreyknvl%40google.com.
