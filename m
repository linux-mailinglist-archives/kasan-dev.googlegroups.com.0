Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQNEVT6QKGQEKJYW5WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 67B672AE328
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:49 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id k1sf4868377wrg.12
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046849; cv=pass;
        d=google.com; s=arc-20160816;
        b=nJcJ8IXB8YTLK/HivS4SxN0MK2mKPnilEkAlDtpl4Rev2toiOMuIsf9jUBGSDHg17D
         JH/vDoyxUUsel8G9V2iPUBSBktXlEmo7MKliZxBwVaKn2xQopZlHSxNRYo0F/9FigtUP
         3GbeYfsJqSNuaeCuq1U3rG5t9Dit+MZnNCOoP0gC0UrLtm7sk1qzzM5smDKlokEIYEEC
         M3w3zNSLRpIplCnID7pY6+Fom0MTQVK0OgKJJaLI2t3tnphGRCMtRAdNGiudFcUgaSrE
         8LOQgRQzP8aK07hoVeO0GdGHWeI3UBAjf8HjUy+aKeNZ6oPcPA+8jP3oub1ORgrCvAZB
         9CBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=jU2rSJlqdHLQl8aRYFwnnvwLAxupEEulWJZ5q+4PpM0=;
        b=q6j1maCofkSW6PDiTosC9783Outkxnu7SsB+0ZwvcW72PoIVPBJD12gSsUhtsmEd1O
         9fUckmIyuCvqpZ1xc/NZirhHiSCV9maJzTJfLJgig5J03UDGbeED4PzbZ2vCmC4tYdRD
         kdyK7QGQ/oDjr7/mHB5ncuriq5xsB7OXpmOuR4Wbf+GCnNEpzf+O/OD7CPuDBNszeaca
         AK8OD1uclkLkjkI6O5sHATGzgr2psWq1K0jQrN8I6cT495eUgLXT0fqBu/LmUKc1HPac
         VW06vm7jrocmM6QgMlKpNikBGFmyTfbhq787TwhgReV0tTK7lUhx9XXD3AsWx/4DbNUo
         WjbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="X/G1FHBp";
       spf=pass (google.com: domain of 3qbkrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBKrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jU2rSJlqdHLQl8aRYFwnnvwLAxupEEulWJZ5q+4PpM0=;
        b=M/br4RfRBJ8ygn/CF6lQItV+2xRv1f4rg+ytZAly33vP9zDOfFBVEsPN3Lebsg/ZZ4
         cdk9UIjxoPIF6XEEMN+qzjohElNwrXBHCz8OHjAnnKZ3d4G7N2rC+xmCt94mr2xOH6U7
         SKNYMjb7XvmDma1IZ2i7gIFpT7mrn2eqPQ0LGtaoJU7XOEDbV6+Ww0Lu0hkiIzNITT/c
         W/PuLL23eUG0tNOk+eafhEk6Zi8cD084pmoTQ24RQcl+QiPNYBBEOkwbR0Rb39iQSWlH
         PyUutMTzsMKFqbxW5t471DKZPDPWU05MDhbtBbLtF6ieM3+joWSnhwXmA4QS6tRYGFMZ
         Zhhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jU2rSJlqdHLQl8aRYFwnnvwLAxupEEulWJZ5q+4PpM0=;
        b=l2cnL3yLiiZiWJfx/91JMQSGrxoT9bGaUUwUf4kinwqw7dOFzFQ4f0LO+ilB4ViOiO
         RPZWz0QuPc4hPwrHyICmb3ZanRQlgfTx2PEiZy8HFGcvPkeIAZtave7dLfUFc2PYhYhZ
         qAczw4yAeYZcTUprYcHhunMd1a0FVYIvHre9n8uwoQpDMh0FXnNIznWB7vDk/mKRRqSK
         bHjHQ7jLR3IJ5tfINwMpXGMhuU0fTAPU6y75w3kI0H4euwgYecKoGnAWzHd31yGQvnVp
         imos7RqoflJjoXDJUh0bUvFrGCkzN34h5xEqsgA4ABdsRFHlPQDqEaXhEQun4f9fjPBQ
         r57Q==
X-Gm-Message-State: AOAM533jr3fJNMNG919W46ezDqA1Dp1mUoIxdf9hRVWVuikszmrIhWtN
	HVlseSfJa/JHjeHvmrH982E=
X-Google-Smtp-Source: ABdhPJw1e4Y9t53i0L1Gr2DlfN3gJZFOI0p/zP+22G2A+wmutsKbbPWyMfqSIHQlhtVHals2ZRebQA==
X-Received: by 2002:a05:600c:2282:: with SMTP id 2mr305174wmf.154.1605046849226;
        Tue, 10 Nov 2020 14:20:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls477683wrp.1.gmail; Tue, 10 Nov
 2020 14:20:48 -0800 (PST)
X-Received: by 2002:adf:ea50:: with SMTP id j16mr20836973wrn.283.1605046848526;
        Tue, 10 Nov 2020 14:20:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046848; cv=none;
        d=google.com; s=arc-20160816;
        b=DTBLAWAbOpkWGm8AqE8uECGdqEq4wAkJe7jTdi/1IO/9DrFjcesRIRcD6AzdrayKwB
         jV4Bcvje3+nrK9AytaL7ZFiOxUu2PGWbpfqPABN90BgziVHnMsOxitxWYp3d4y59FWtC
         SEDADMAh4hQ4GQRuA3uD0oFP6Fsl4KrjqKM/F1d8ZnRlssjkABieNXZNByPFMsNLMju4
         ONZjkB+IvGUvVoZqaQWWBWjYmAPHG3DzL+Gpei4V96LCHGJdCeJbVjWwR89SGynqz4P5
         NrFmf2egG45E6aLQOXpW37+HSCMl6QZ7RWwHeXEBtBbY6wQ7p5p1tMydXBMEkUhPuREZ
         LXRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/rSFl10DA/GX54GBDw6zGUYBErxFDPI5QaAJ7Zds8ak=;
        b=UGB0nwkgSSpr8c70kJ+Xs13AiSX0eUEFrI/njtQDQQrbIgjOm5BcJqh4ZY5uM0MEqY
         uoef4sCy3Zirs6jvHTXmCbQhtxJLIwL0pPITDDFhBRu/hP1kosYZrdUnOG/mu7YKAhuY
         1iXtfn8awb94paHQYqTUPoM9Tr64DLOrimFkIG5qqpM3XUSZQEkAeizbXVQn/b0pMSNb
         wEN5uY2iHo8bJpmIWFZaatH10mYAoUdFaje37pF9zW1oAl7K0kJMNlBq/SnlVn++Mobs
         3eatCf9rFrgQpyDtRmWFJe2mc10wDA4tbiygBoWEFtIVF9n9txTCPYHkl/JwdTF+7RsW
         rUQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="X/G1FHBp";
       spf=pass (google.com: domain of 3qbkrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBKrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r21si2901wra.4.2020.11.10.14.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qbkrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x16so6166671wrg.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:48 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6692:: with SMTP id
 l18mr14959782wru.44.1605046848070; Tue, 10 Nov 2020 14:20:48 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:12 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <73399d4c0644266d61ad81eb391f5ee10c09e098.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 08/20] kasan: inline random_tag for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b="X/G1FHBp";       spf=pass
 (google.com: domain of 3qbkrxwokcruv8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBKrXwoKCRUv8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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

Using random_tag() currently results in a function call. Move its
definition to mm/kasan/kasan.h and turn it into a static inline function
for hardware tag-based mode to avoid uneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
---
 mm/kasan/hw_tags.c |  5 -----
 mm/kasan/kasan.h   | 34 +++++++++++++++++-----------------
 2 files changed, 17 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 49ea5f5c5643..1476ac07666e 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -42,11 +42,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-u8 random_tag(void)
-{
-	return hw_get_random_tag();
-}
-
 bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8a5501ef2339..7498839a15d3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void print_tags(u8 addr_tag, const void *addr);
+#else
+static inline void print_tags(u8 addr_tag, const void *addr) { }
+#endif
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-
-void print_tags(u8 addr_tag, const void *addr);
-
-u8 random_tag(void);
-
-#else
-
-static inline void print_tags(u8 addr_tag, const void *addr) { }
-
-static inline u8 random_tag(void)
-{
-	return 0;
-}
-
-#endif
-
 #ifndef arch_kasan_set_tag
 static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 {
@@ -279,6 +268,17 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+u8 random_tag(void);
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define random_tag() hw_get_random_tag()
+#else
+static inline u8 random_tag(void)
+{
+	return 0;
+}
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73399d4c0644266d61ad81eb391f5ee10c09e098.1605046662.git.andreyknvl%40google.com.
