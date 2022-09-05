Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2GV26MAMGQEPVJSMRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id BC36A5AD269
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:16 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id p19-20020a05600c1d9300b003a5c3141365sf7387106wms.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380776; cv=pass;
        d=google.com; s=arc-20160816;
        b=fOdIQn1zbfCxqQXYjyvTw5c+BjMvakkQ+6pM+Ic8TwHWWLcNTAG0kpJBTx9Bw22X4m
         Vg8qVv6hbrmehnx+oas1ReHojSRR5V7FggD/Dc7KRPgnHh+yr3jUElHsCtLgC6vfTONe
         RUvcNiKw8gsym7JK4ekD9ePmEZco9mYNKSJvw39RIOk/jh29LDu0tbqjWcwoN5NdJDmP
         NkiJy9+mEPi7bau/KQWKWdetIYpZRle+mpu5C+f1aT0lae4+gYZLmwpjU7LbbWWgH97C
         zfPNxzUgU4AdVMgb7xEVAYs2vyWQPpfwp3qjkm9UQWeKrmaQxg5QYh1M8wvME4XptIB8
         w63Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NwDl7kovXjs+PMaLfCqQF7RrzHTxdRwAO0dvYTGC8tg=;
        b=XyMVBzHnjBAlrNQKg6JOdllirFEQ8gn/HCFv9Ntbyobc85HcpIbdLAOxFjtcx0FU7p
         WBWrWw6If3dHndBn6r98lXZ000UHv6dR39nDtC2sKg8u8O18WFA+2LFtNdqw+ilucyfh
         BMOgZVIw7b2KRsflPU6bTrucs8TUJVi4/f7nUVeNN63A2g/CBjj8pqJmfqGQ3hd04GCC
         HsgV5Q9QDnWNnDAE9v15bPRSrCqT3OICNE8SG4b/IzHqHDGZ3DDqfGfLl/XKSkC+5QRC
         JwQCPESb4H2IiwBWM3uo1JxgiAt6AaU65v5U5B3mVoe9gtVTRy0a5IDiWgceH7wMA0y3
         FsGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gykJQm16;
       spf=pass (google.com: domain of 35uovywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=35uoVYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=NwDl7kovXjs+PMaLfCqQF7RrzHTxdRwAO0dvYTGC8tg=;
        b=dcD3DI96loCXk3RWszSwLmR2kRUOLXFEY80Q5StXh3bLRb0tyfLN0iA702kWg9aDHZ
         lb0fPzbRmMFm2xTfA0wMClmmCxCN9AomO5qQN+xX8l+8Zt9RSfffnFxjBRDvfMc3jB0P
         u4GAw5rM89eFUYJsWoCRsqsFca2guxzIEEBtgn8uF8lsrqHUuQZKhI8egqiheB/C1Sw0
         LZQoFocm0cAJXAq4CEjOWqGSB0UcMrIApBokba+hBp0AjH1K/bWDbzH3jOrgamGE9XIu
         QbrVIiFjPNg3R20MFoqbRVrdIVyTKJ2j5esE/vOVwtfsg/xll3trmE4hrtvghCGjVwaw
         q7cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=NwDl7kovXjs+PMaLfCqQF7RrzHTxdRwAO0dvYTGC8tg=;
        b=W2adKwpS1dMUrw1F0UZqwoMfNSfOShy22BjYnu0Lu9pWe442IoGBL/8bc5koTJiRuY
         OlAnMUK5P5FlDzTrLEUebpsY0Y/6bzzBG6z21uc6ErTlScu05r+6G4r/vbWRjK5YR7cw
         gQsqEW2N36VSP+FKfdCBK4pJUmaX4jRuOxK+rOZS6pd+Q5PZ9TMKRygxrCs0+oQzEMGp
         I7f4KXugT7GGWvo3C2O8/+cKfSng+e4A9pL/fFFJvtkrDSPeTHtqHd5W+gqifRTWbOzg
         L2+jlrr7tKDBlMvdLH6M1DjOxGQLste1jJRAONvghQ7hcvNd1Ym7uiXxPZ+b36/GoUy4
         /h7A==
X-Gm-Message-State: ACgBeo0NIRyKkhyt6EHJNaAm/YeoXeX9gerCj4ifBwBXPU2rNOEYbTNa
	pDTbLUWIbwp++aZVwtyy1N4=
X-Google-Smtp-Source: AA6agR4xMtuWt6t3kUYQzUG6XM71MmbNJ19OMgThFAWIbBTwLwP7UrTg6PNL/ozy5qj6LMYkUlxEgw==
X-Received: by 2002:adf:d1c6:0:b0:226:da28:d19a with SMTP id b6-20020adfd1c6000000b00226da28d19amr20534009wrd.541.1662380776342;
        Mon, 05 Sep 2022 05:26:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7407:0:b0:3a5:abc9:1b3b with SMTP id p7-20020a1c7407000000b003a5abc91b3bls3797873wmc.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:15 -0700 (PDT)
X-Received: by 2002:a05:600c:1d9a:b0:3a6:248:1440 with SMTP id p26-20020a05600c1d9a00b003a602481440mr11118173wms.196.1662380775277;
        Mon, 05 Sep 2022 05:26:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380775; cv=none;
        d=google.com; s=arc-20160816;
        b=OQcexbEMmB7Q12xns7r+xILSflmRHKzPLtGvOLR7j7Dx4p1MyiJ6Up81cVPrwDhMlz
         xcX11rZQ2B5hntRs3WSUcRbCwHFhzX2NEh/9e+x76NVh9cAw1vDaaHL6Mj9iFb7IP1SW
         isV2TPBRqUJt1oGGX5jsLmiWkvyC3HBGDTqfIVxXGqD+G0isUYI3DeKDP7Y/PUDK0FrM
         1kXxxpdONjB8b9/SSCDnPhDOVWvtnAaUncaahMktdMGY8zs5wjCO1hi7VfU3h1+utPzZ
         vfLKW+2Arw8XxgIro5HzLdSfcSbSD0NDkTgvfbAI4VTfo6NUwxcAiUhMtsyY4DqOoH9H
         G0EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=T4yulc1U4RDI/lAlxqlpzG4AIUYO9fQrzg+B84ydySw=;
        b=udYUQBdumMfAKN6N39inYe4FWzPmq9fF7mhyBl/ZSXr6P1qChDeso9krQxhIdvv5B+
         +7Cn7PMIAEO/nMRE4qHKm5vj5H31w0q3sqWyKfb/kSZ7be/JB3Qy9htDN+ggD4aKCtOr
         PO1itW10SgfRktpCZK8dN7Je910GJ0bs35HLSHCt4brFhnVt2Xq37wcD6iwVkxQWcYhQ
         MWXV2X4DxrxFUbcqh86QT2ayKhYeQgojF0KJB9sJbVMzOrI036LfuPGqVu1k9n1qZuIa
         BdIGDu4E+WZTYSavSyAeYREK/MgLykemAPKU3dAXZQkaoJi0xyoOBrn1hgXB9zz6lzmH
         jtTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gykJQm16;
       spf=pass (google.com: domain of 35uovywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=35uoVYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si489842wmh.0.2022.09.05.05.26.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35uovywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id dr17-20020a170907721100b00741a1ef8a20so2276696ejc.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:15 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:906:cc13:b0:73d:d22d:63cd with SMTP id
 ml19-20020a170906cc1300b0073dd22d63cdmr36111625ejb.741.1662380774896; Mon, 05
 Sep 2022 05:26:14 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:36 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-29-glider@google.com>
Subject: [PATCH v6 28/44] kmsan: disable physical page merging in biovec
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gykJQm16;       spf=pass
 (google.com: domain of 35uovywykctmvaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=35uoVYwYKCTMVaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

KMSAN metadata for adjacent physical pages may not be adjacent,
therefore accessing such pages together may lead to metadata
corruption.
We disable merging pages in biovec to prevent such corruptions.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/Iece16041be5ee47904fbc98121b105e5be5fea5c
---
 block/blk.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/block/blk.h b/block/blk.h
index d7142c4d2fefb..af02b93c1dba5 100644
--- a/block/blk.h
+++ b/block/blk.h
@@ -88,6 +88,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
 	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
 	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;
 
+	/*
+	 * Merging adjacent physical pages may not work correctly under KMSAN
+	 * if their metadata pages aren't adjacent. Just disable merging.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
+
 	if (addr1 + vec1->bv_len != addr2)
 		return false;
 	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-29-glider%40google.com.
