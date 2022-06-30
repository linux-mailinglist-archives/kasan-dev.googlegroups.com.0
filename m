Return-Path: <kasan-dev+bncBDE6RCFOWIARBS6E6WKQMGQENRM7Y2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id CDE1D561558
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 10:43:55 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id u23-20020a2ea177000000b0025baf70f8a9sf2529589ljl.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 01:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656578635; cv=pass;
        d=google.com; s=arc-20160816;
        b=lhHt0Zpti36vcEu3u2ogoa04WoWU0qhfyTBVW5WeGCC7raPajtlYw8gJ/eLjZuXzMd
         /D7UogBL64cKsDqu4MT1D0wRq3Fds68j9wNmpokEFmRdCBUJ9tYxl6E6kX9NxaxXFKKT
         jZ5+KZkZZCEG6YctcP5QxAxswH4AiFPUtqC3QzioWlL6U0Q3KCDhc9fKvQavbxo+/9h4
         HVDK+70PjZrRrmiTcuryqNj8F/I05ZZoMKjzqOt/ObO8L3V4Gb2sUXHs38BlitBGJCBx
         XVLMlFzbYUJw3ceVuqeDiy411gBLNubYRs5RfKGEk9qG5mJrRENcV1AeIZomfU/o5Bqp
         vCzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p9Qe9IBYpNFYPmqziqksn0e3TvRGFaUoekiJUFNM1jg=;
        b=o+YuAivGBrh1UXUUsXES281vq50YKGdc4IuhqaJs6J75V3sBA+jVofemV/3ocksKQv
         C76Gov/ikwlmwjR9djh+d3AjEN6nO/g1MkEFG6MFq0nqxncAraOhwyYOmj08xdCA1FME
         gxitTlDp2k8GNuBmx4gN9iq5igin9b5HKwjWnb6jsldm3vvQMCZXvl+KHEWx4pKyBD7e
         Qy9Y7f3OZZBGgussvy5BwTCVuISGjkZMVM+RKiaNB651bwZUYfg9mzRR5W7HvqbAi96S
         l0rMVf88fPkB5xY1+gTlnIXVyqsQV5msWry/Hc8DCx0Kq/pfEq63xepNuHXPSLo20YYL
         aPwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OSmDR7wa;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p9Qe9IBYpNFYPmqziqksn0e3TvRGFaUoekiJUFNM1jg=;
        b=bOxBnJHyyptWsKYi6Fq6/kG0KzPUFzm7eQxW5KbkfUeMNI9Dm/EAEZtTZJ2tkB6pGu
         yTF+1vm3eRMWSTj27Y1zwXk99qZgyqHeC8huo2sO3XFhwuhWfNKaWuvJ6FQSBXCMqsvo
         8bnwUhZlCrLLvcrLmiXN4D4oLmsYU3AUn3lyyBZeIUvFeTGh3SmJvtoCHWG4DQxoYYJ3
         ssr4IhL6m6zYrHpis9rxXKAgGICvRIxzhM28AZrAge+qJWzyF7TFKc9RON4YSsTDiEXU
         tTDbCvFJIOCt/hwUcw3DJrXNOxjcN4y/Hw2C2wkNGp9lEYWWxy1JdomSY/ldgi5AC3uU
         aneg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p9Qe9IBYpNFYPmqziqksn0e3TvRGFaUoekiJUFNM1jg=;
        b=ddysJh+Mf16b6xTAWWwesXj5EAPFsHbCa2V4X3v9xvJBafVNLCwgiBR4xb8A9jQw1D
         OX8gvEmkfWEnpBqyn1MSWPZ/xdjjQ+ze+z2bEPx/ooAzXyWH5y4VqTSNBuRBvOIl+F0i
         3OcagNYBQNFF10KwevrPTnbLHhhIbAifJtRF8qaLZeN1kWdQ1xeTrdifXluBP6Pvc82p
         gy11C49lPVuti5Bb5U6tvww5QD/IUN1yCzuOpuDnh7LFh5KIA5akbN/+lIPV0gp33nb5
         aFYtqQOusWL6EWMVSD/5lGE0ifvK5j+JBdFm5MHTo8DFj/BlcDXgpGH8tMo0WLHtkLVo
         TncQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8YxixFxABgBW6oJfYpj0FWKC9tJbe8S7znQwY0HtspBGv9uzmp
	NkgtneVHKbmos2EvX/FwxYo=
X-Google-Smtp-Source: AGRyM1tdQ4H5xqQaOGShqi4HDpeojP+4G02mxZ/jJbQT0wqDOkxw9L5dXYBoLJn3qRBKTnT+bjPjTw==
X-Received: by 2002:a05:6512:3085:b0:481:182e:a06c with SMTP id z5-20020a056512308500b00481182ea06cmr4871314lfd.374.1656578635244;
        Thu, 30 Jun 2022 01:43:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls237070lfb.1.gmail; Thu, 30 Jun 2022
 01:43:54 -0700 (PDT)
X-Received: by 2002:a05:6512:23a5:b0:481:d0e:ab00 with SMTP id c37-20020a05651223a500b004810d0eab00mr4948629lfv.89.1656578633718;
        Thu, 30 Jun 2022 01:43:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656578633; cv=none;
        d=google.com; s=arc-20160816;
        b=sPdgnpKlv1gGqkJuMFVi/MKZfr6WjHmwP4ckE+u1NWXDikANmLL4vX0cagD5k0O5Us
         dXJLi5mZrwvGS6uQsCndUcrD2Ek9P6gfq2c42X8BOOSEFHjEUEUvdsPRrPxtq+vsrmP4
         xiC2Do3p9iAvQ1u45G5wQZvEM4xAaiTLnsX5w0Puh3JJv/0a8lFpprM0A7jlLAUmMKcU
         GcotMcs3s1hInyR9u4Ysi9xNPFOU1pSP1mvG2NHNtGD0t92rwB/9WM+8exzpNFehT1ZG
         5sJExKORDOLNODIzBmKPR8pDT3tpaeIyuCZzc2sq0cAEJBVHNiCZ2n9Vkiwk8DTXkJ41
         fNmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R+x4xUlXaoDhtuO4AscHrz+MJh/LM6gsUwNc9kO1v+E=;
        b=DHjFYIYzAUyS8b+aFdVHyuuIt5Fwmery3Vino9QEPQFtnL2VWXjnHkoK0Tgv1J1UBl
         wvxBOSd4STm0voySy+N8+yG9/dAG6ifzuhT3OUzpT1qKZFOynno95gIKndMFmInhgRWr
         aeji3G1C108m8nv8/jckHgrTR50w/FUDQs+R/3201TTEyYdzkFZGWhoUgChsiFtVS6RM
         AnUj3skfFk8P+jJ94hXFbHHJADPlZBMkwx24/MAcyLd6OMWRWrpjy2weHIBN3zkQZQ6B
         j6o4M4mD5IbL8LrgOtArDMdCAdWPMQvzoI9R+XWvyfdkSI8ICiIPoM8tvJnGv4JXq/UJ
         ghzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=OSmDR7wa;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id bd10-20020a05651c168a00b0025a72c1807dsi798646ljb.2.2022.06.30.01.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 01:43:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id s10so22138303ljh.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 01:43:53 -0700 (PDT)
X-Received: by 2002:a05:651c:231f:b0:25a:66c3:c213 with SMTP id bi31-20020a05651c231f00b0025a66c3c213mr4221114ljb.288.1656578633145;
        Thu, 30 Jun 2022 01:43:53 -0700 (PDT)
Received: from localhost.localdomain (c-fdcc225c.014-348-6c756e10.bbcust.telenor.se. [92.34.204.253])
        by smtp.gmail.com with ESMTPSA id o23-20020a05651205d700b0047f62762100sm2973023lfo.138.2022.06.30.01.43.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Jun 2022 01:43:52 -0700 (PDT)
From: Linus Walleij <linus.walleij@linaro.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	Linus Walleij <linus.walleij@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH 3/5] mm: kfence: Pass a pointer to virt_to_page()
Date: Thu, 30 Jun 2022 10:41:22 +0200
Message-Id: <20220630084124.691207-4-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.36.1
In-Reply-To: <20220630084124.691207-1-linus.walleij@linaro.org>
References: <20220630084124.691207-1-linus.walleij@linaro.org>
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=OSmDR7wa;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Functions that work on a pointer to virtual memory such as
virt_to_pfn() and users of that function such as
virt_to_page() are supposed to pass a pointer to virtual
memory, ideally a (void *) or other pointer. However since
many architectures implement virt_to_pfn() as a macro,
this function becomes polymorphic and accepts both a
(unsigned long) and a (void *).

If we instead implement a proper virt_to_pfn(void *addr)
function the following happens (occurred on arch/arm):

mm/kfence/core.c:558:30: warning: passing argument 1
  of 'virt_to_pfn' makes pointer from integer without a
  cast [-Wint-conversion]

In one case we can refer to __kfence_pool directly (and
that is a proper (char *) pointer) and in the other call
site we use an explicit cast.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
 mm/kfence/core.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 4e7cd4c8e687..153cde62ad72 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -543,7 +543,7 @@ static unsigned long kfence_init_pool(void)
 	if (!arch_kfence_init_pool())
 		return addr;
 
-	pages = virt_to_page(addr);
+	pages = virt_to_page(__kfence_pool);
 
 	/*
 	 * Set up object pages: they must have PG_slab set, to avoid freeing
@@ -657,7 +657,7 @@ static bool kfence_init_pool_late(void)
 	/* Same as above. */
 	free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
 #ifdef CONFIG_CONTIG_ALLOC
-	free_contig_range(page_to_pfn(virt_to_page(addr)), free_size / PAGE_SIZE);
+	free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
 #else
 	free_pages_exact((void *)addr, free_size);
 #endif
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220630084124.691207-4-linus.walleij%40linaro.org.
