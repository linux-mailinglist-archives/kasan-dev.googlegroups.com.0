Return-Path: <kasan-dev+bncBAABBZV43KUQMGQEPWB6RSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B1957D3C5D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:25:13 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-507a0904cdbsf3904925e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078312; cv=pass;
        d=google.com; s=arc-20160816;
        b=OHNr2Wgc1nWN0/aY8rCoH61u7UAvbA0yP3iHgyDPUcSzZoRi+vIxswsoEKOqSy0nQj
         7ix6xP7aCF3lykA8JL2jlfflOyV1/4C/cP4ta0YqhYf5IOfO1GQZY6buOnCcrWBHDs81
         2k18XDLTRz1AvfvMTiQmhrEHAu7fX0DpezLcwC/LevH1phmA+7ttaELLUJnKuHlJv0Bv
         9SdxXnaxiWFn2/Vlh7+oUEpcL6vv6o6d4ovXXeYw0+X1C3Fwsj18oPaSuK6U6fYhciTB
         nnVrX0gWI2xXoGXIF3YrkkVj7eNs+rBzblVxpMmkPEw/2k6o0sEdAZlXikgcHvfKKJc1
         lkvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+B/2wFdVq0mUhpveQda6WUCJ8HSqyKrxDPCsnLXEbY8=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=fzn77a/uMCz0Ck6hCvsAN7Zh9xLL5ehcUnR62ImRpHKZ/pp91SYPgFbSTLv2KLWiLP
         913TT/odR40RqXxFvUbO9BbS7o7fgLCz2r4GiP3RxYNwZhh0VX8lyg5c1WXHeU/upv5S
         CkyrY+w0PPMfta9CMRF1ZQEe8LOOok0X9KuBqZm5Gmlzm9Av4KK80KOy06vrsBLARfah
         6pB3jNHQmH+niRJJi4vIhTGXxHUeJgd/34Su3AHSShLVrf/HGgrc98Ou6iKB7XN8D7fM
         PhJenHytiPO6fJq9CyZccfnlOU0+UWqBtSnaXGmGd5O6GfYWF5V08GfFRjtATj96RxPn
         Ql1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kPoNUZX0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::be as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078312; x=1698683112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+B/2wFdVq0mUhpveQda6WUCJ8HSqyKrxDPCsnLXEbY8=;
        b=iKo9hh9kXxlB94JwYZIUcjAlTn3yp3xhJ9KlXtgsXd6OYr3F5o2Zz2Lq9P5qbzH32Y
         nokEh07K7nxPMVIIUUrUdfUNpSf2yDoDL2Hiqek+YFfa/bU+NehK2ToSK4OiAzyfDwQ3
         f5nBVTGAX3zskYLZxcLSiXpuPJllnWn6EmPSv9EudMZNP32jLr3MZSeunPS0yB7nsWCI
         yF2ZvyF7F3GQhpJJ9gdWwo0tjMpZBfZfs7jPfQVg+leWGSnWkb3UB1KozqYlEL5lCLPV
         uKfUckHMuYrXOSGcnoun+euyaHv7d7n9TBTkBGXtVJtoZHGABSD88Vs2rBIWKARWu1CQ
         1OXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078312; x=1698683112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+B/2wFdVq0mUhpveQda6WUCJ8HSqyKrxDPCsnLXEbY8=;
        b=xGvS+pLwXrSbx2DtdO9a+fN3IOA78nDJoCaMv5wSgiSXhz4mIunlV6LrUeCPk23Wa9
         0FhCWV3/fHgbO/P5JoI7VZvtpW3hDNQZuMkkmKu86hZ/2vzjfkvkz32zvMhMXgd9MW9f
         nPFQ2zMXyAJkrDFn6YEDEWLiHKX5Rg21IXJyV7KQplUaxnCt3MAsCykXyITMo01vG5J+
         zbG+PW6m+4e1HkWkiRwk/u8077RU3Zj0nlj3aBYvzelD9srM0YdhtvJHuqyUptyvxrwA
         EhuQXcWVJqKbi2WnnWcdhgJYrZpvi/y0zM/vYzW7VkqOiTMd0nbm9rSChzVChedOfz5P
         LM7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwdsGaeGwuLwxp4SH7LuRpMrHF1G4+KcP7v6H8AEey550cVpzq6
	kPe+ttAsTwggZHTal6UNp9E=
X-Google-Smtp-Source: AGHT+IFGH0K3P64Z3Df3gWh84IfzG7vVXqKhwq2d7o+yaQwhcA6wyDVVZy0mnmEXU/1/jaEH+gGoOQ==
X-Received: by 2002:a19:7607:0:b0:507:a0d7:bd19 with SMTP id c7-20020a197607000000b00507a0d7bd19mr7264804lff.13.1698078311134;
        Mon, 23 Oct 2023 09:25:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c85:b0:507:999e:6d67 with SMTP id
 h5-20020a0565123c8500b00507999e6d67ls418394lfv.1.-pod-prod-09-eu; Mon, 23 Oct
 2023 09:25:09 -0700 (PDT)
X-Received: by 2002:a05:6512:3156:b0:507:9ae6:6bf1 with SMTP id s22-20020a056512315600b005079ae66bf1mr6881685lfi.3.1698078309588;
        Mon, 23 Oct 2023 09:25:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078309; cv=none;
        d=google.com; s=arc-20160816;
        b=a7UxFaQYxU1BHbVg1kh/uy6eabmdUaaMoV/lUz/LEPHyPZ4UXM3hdVdtys46WphgsK
         3g/d7GnzI0k03nr93CpOBxMlohbzcjlawydOPbn5oQBXMuqpJ8IFhbjBqOpuaq5CH4Jf
         KBij9a5o22SRpp/iGcYsOqFukQHMM8d09T4QW5K1tEY5y9vSktjW0HxgOe4DQcbj0Cry
         otOwP/aOMRQGbu6QBepBYPl646Nd2FwYu0svwCdlv9RwNTg7yan8GQEvoVL+08mpa3zk
         qjV+xhDyAo7UFDu2GkLNMk2poDwILcI0DXhm6fSwmO+/DrjHtcY24FJHOEs3EWTs1aGd
         /axg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EAtH6mtyDDwPJA3G1u2tEpoRGlDDlV29Wi3V3trZXF4=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=q9MZgZTxfRoe0V8uINovPXEaODtbFqGLlA8bYtGdRcTltIubiojFOivJaedAqXd0zD
         /JixyI0HTZuM9hgILS1oDBg5lWIl5PSqG4I4cdwpVRgDGNlpx9kX0rzaeHpuTApFmE2R
         1zZU2JiapjF2qps9SuEob+Y7M1/v4vWDVG6EZfIajGiwmfAPpvmenKx/hfXERIjXdLYZ
         XjBObEGiGXpUjUshSWMilGXqQioI21C6vMnkJi+EWvp3gYuHjAQJp6XDSf9Y7XDocZ1M
         S0zy6UEWN84w8jFGhpEFoqEPXWbFFGdD5PXHR0SkE/BPcUeM4J2uTrJxli7B8YFSYkVk
         WBUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kPoNUZX0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::be as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-190.mta0.migadu.com (out-190.mta0.migadu.com. [2001:41d0:1004:224b::be])
        by gmr-mx.google.com with ESMTPS id b19-20020a0565120b9300b005079644d21csi308771lfv.7.2023.10.23.09.25.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:25:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::be as permitted sender) client-ip=2001:41d0:1004:224b::be;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 13/19] kmsan: use stack_depot_save instead of __stack_depot_save
Date: Mon, 23 Oct 2023 18:22:44 +0200
Message-Id: <b043aa9c2e1e076a2d9a039c62e071d3e70ad39e.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kPoNUZX0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::be as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make KMSAN use stack_depot_save instead of __stack_depot_save,
as it always passes true to __stack_depot_save as the last argument.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kmsan/core.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 3adb4c1d3b19..5d942f19d12a 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -76,7 +76,7 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 	/* Don't sleep. */
 	flags &= ~(__GFP_DIRECT_RECLAIM | __GFP_KSWAPD_RECLAIM);
 
-	handle = __stack_depot_save(entries, nr_entries, flags, true);
+	handle = stack_depot_save(entries, nr_entries, flags);
 	return stack_depot_set_extra_bits(handle, extra);
 }
 
@@ -250,11 +250,10 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	/*
 	 * @entries is a local var in non-instrumented code, so KMSAN does not
 	 * know it is initialized. Explicitly unpoison it to avoid false
-	 * positives when __stack_depot_save() passes it to instrumented code.
+	 * positives when stack_depot_save() passes it to instrumented code.
 	 */
 	kmsan_internal_unpoison_memory(entries, sizeof(entries), false);
-	handle = __stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH,
-				    true);
+	handle = stack_depot_save(entries, ARRAY_SIZE(entries), __GFP_HIGH);
 	return stack_depot_set_extra_bits(handle, extra_bits);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b043aa9c2e1e076a2d9a039c62e071d3e70ad39e.1698077459.git.andreyknvl%40google.com.
