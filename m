Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTW6QT5QKGQED7R4MLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DB7B26AF5B
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:03 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id p3sf1503277ljc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204623; cv=pass;
        d=google.com; s=arc-20160816;
        b=hzeDiUK65pzrR3cn7D6QPsUuDf68NwpUEUT4YkfAZIZLN8URp9yp7l8JlH5CDKC4hj
         S6Hc0qtFVF809bMrOdcu9e+WaOJfRZqzw4CQ7+zrYleNnafAF//c1lNlh6YF/UmYA0xa
         x7O6yikAe0qxCrCquaawB1w5mW8iH/sRIE5Vg0myonq/BzO2X2SGBI0o4i7wLz5LNezg
         ACEaXNqTQvW0g3N5H2g4QPlroqdu4KM6L47+Rp2vR/SssqPQEPV4zRA2t7GQpH4QILLU
         HyGdXZVkJb5qFtuFm9eZkPoAAuBD0JCSadbfaJeKy2A43U2rwwvvFFzQ5dTKreyJzLvQ
         NwsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YFJaUJ0R73WNLxMWUlh1DNXDFNNc5BQ85DmgLBAZ++Y=;
        b=F1Zeu9hgKxeOe+hZTs7TTni/TwOycBKDX+BcEvf9j6WNn1FYDWsJUP8fqStoy6NJut
         wo8ANwXJXD31yOCk80VOPgk5QzpXJQ5jSYyJu805rEH2J1zpShI7AOIU+QKXd0jULwxX
         BOdzHWkFwHk1FJVPeT5gbGvY7/EU0LW0BgLp0VOvOc/K8NCvVlqiUB6cRYqGQDGmo70z
         0queApGUYkMb89dvAANY337l1OMunOXkaipkym7TdBv6Co1twrJ4ndAB8XAjllKaXdg/
         LSBdw33d7CQoe0+hRobGLib2QAxaPLuOZWhDtrioA55W99I0fr/xISZXmD+m3S+yYQQm
         YdcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vWPqCcAo;
       spf=pass (google.com: domain of 3ts9hxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TS9hXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YFJaUJ0R73WNLxMWUlh1DNXDFNNc5BQ85DmgLBAZ++Y=;
        b=UFPNHTqRZiCEroLXJspSr68L5f+8BNZcm6uh9MOxxp+mNJjSOW8HyGbJ+ortJjL9FK
         F20OvnlZq5JqkdMC+nxgHKz1IxqH/Hbo2MsqP8wbW2R6WDSPV77iA4Bx3Ecf2X+uwlYq
         MUFhRr9ip9hOW+YCfaxSp7I5nCTlIRLH3eSfrMYGVGrdZ47MOq2pUYXmoNJEpH4sJopM
         e0Kcxm6p/fBy+DU2V+v490tuNRudxkZLjQkfsR9PB+cZ341Xj9oQHcix531CJ4/+JHnZ
         rJAuI56r/jHesxGREpvcd4vDYRm7+4PV0nt0p0aurVj4uSnMqyUOa9X3vxQYoWGKHDsq
         aL8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YFJaUJ0R73WNLxMWUlh1DNXDFNNc5BQ85DmgLBAZ++Y=;
        b=CXvsCDoLh9dmSo8dLpKaAXivdU70uH8fWRaNz5c6UyKQhr1G5RCzBNInnooQB//+Fr
         WRiWFREQbnLdRCLCXir6s5jsk1F8gRBrcrXlq25LWsFBrRv/dZyh58vo6W+Lcndj3lS+
         WBM18RyPHeZf04f1Lpl24xKggZwn9VTdOxkCLrAm+FfPTvwObqBVLXw4LCcUwS/NUuHD
         tFaS/zB9GikHoYaSf/Fl7xLkPVZumQHdG3R0KQhV43IvNOFcpmcm1c0a7Z2H2auRhf6q
         kicsYQLxxMCxthi+GxrcdrIxiQgzk2DgTkO9kN9TyUbnkhAoM+j5D0XteHfQt2SQxTPX
         uNDg==
X-Gm-Message-State: AOAM533RA9ti5dE7h86ZJoTsI6YNhaP35wSy2Vk7NkRbpyHuvgxFUyD9
	Z41wcB5ExuVZBC5ULUJbiBY=
X-Google-Smtp-Source: ABdhPJwAfa5asFq69+X4PQxcjmFRQeQtjqlhzAGbhIDe/Pr3fuK+BNikBBnBSebl0mHlKzhsGnEboA==
X-Received: by 2002:a05:6512:1dd:: with SMTP id f29mr6102280lfp.311.1600204623129;
        Tue, 15 Sep 2020 14:17:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9151:: with SMTP id q17ls55788ljg.8.gmail; Tue, 15 Sep
 2020 14:17:02 -0700 (PDT)
X-Received: by 2002:a2e:a304:: with SMTP id l4mr7667659lje.35.1600204622113;
        Tue, 15 Sep 2020 14:17:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204622; cv=none;
        d=google.com; s=arc-20160816;
        b=OcNr8sM+7jG09DjBXugLPgE1EJQluqEughHZ9Se5fhP00wmue9DLWO4bu7c5RZwKn2
         HA4Zwe+HeyGGJkd6RiSaW1cvlJAaoOuZh3J1w9GZYXGxffhlGcaO/klp9JjxSjtfRtVN
         rpXnCAjHTYHr4j2ebmz4nBeR5Tx014tBX1TBV7jsdhq0KLZwZGUEA9wPTu/Qhi9KpQKr
         WsYeJ1rrDGc1JC3+Z1bVzYBnQmvw1PzdYLSc/NlY93b1SRG/vnHQcBYn7ONU10viJDBP
         qePDmdCKsK2idCF1RyebEM1kwbxp21pIWISr7GRXSQtuRVuiVgmT725nTFGnM7gaE9f5
         vd6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4/ByT/O4Nvro4TMeKsqTFF+dTSNFkXyz3Nr2NgmhNnY=;
        b=l8uFmwXdaCWRHo76VnKyXbgZqbz6e+LchrAIhjvrMC7DYT99UfRSXTSLCw1hhdp8Oh
         jx8w3hjQeSES+vnzLNNoBnuMXp+PG/ukZte0LL9UBuWpsY3aeurrD5c9djL3BcY5cnMr
         lkoq5djtcODiJ7GnTrEPcc7ojZOX9AY4kTGygTNhZQI2T3RF++BIYb6rts880Fc+H4lA
         K6pCpwLI82HknaaYyPakqMgUihy7y3HVRSFOLQHE1g1tmnwObGG7hjExQiWsciR3tuGb
         GfbJSwE3P9uSZryfV5ARsgRvAdzFt3Q7bZM0XHULdjavhwP+6NT7V19FoJp7ndgzVRvS
         SsnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vWPqCcAo;
       spf=pass (google.com: domain of 3ts9hxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TS9hXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 21si458496ljq.5.2020.09.15.14.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ts9hxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id b20so392242wmj.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:02 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:6385:: with SMTP id
 x127mr1274747wmb.95.1600204621569; Tue, 15 Sep 2020 14:17:01 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:58 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <f741b1ed6bee015a4accc2f2fdcaad8cc1c1bb47.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 16/37] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vWPqCcAo;       spf=pass
 (google.com: domain of 3ts9hxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TS9hXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8ad1ced1607d..2cce7c9beea3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -376,7 +376,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f741b1ed6bee015a4accc2f2fdcaad8cc1c1bb47.1600204505.git.andreyknvl%40google.com.
