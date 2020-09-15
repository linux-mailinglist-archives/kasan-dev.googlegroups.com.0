Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKW6QT5QKGQEZW4WIPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id EDD9426AF4B
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:26 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id n25sf1798439edr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204586; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUT9/xPxrg5OzK2rhR1i8duitvYRSyVOuF7hTJUTj0/K1wZAvwtwk9RlDY58yBEjlF
         Jrh/4xzlaC2k1mBQTVzVzwx/OodZzYwsp4BGNeCIOyWgo0/cuxcY3y5NerVvdAGRi8Fd
         TPcnaUuZb5KqYIcFJ5pWU4Js0MeYuIgVWaKsf38ejLv2HOn6cEhsgZBAroRUTF4PUdaW
         Zb4T+lWXNijqGH3+rKdIoVvY18POPLduLIHha8jF181yJFw5jSU48L6ZFspLcGektRmT
         n3nQsHlJ6dsxoseEC8vhyHFt3Cllbjr7ERB3fKaGY88bdZbVgyBesgq51ByFMfIlzpoC
         2liA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JxevF5mdydDHpNdleZvbSdNTuZ885uZCnrlV7cTMhC0=;
        b=f3pkbcF8kH76jzXQkv9zD1gzXoHgGwiXEHjvDWhVwuD+ySTbcopSCdhH8pkg/jlh3E
         sIqSPXYcRMoBxdf0B0qEHqXNnj3mJI0uwFfb0SQ/Y8drzm0RTTrI02uQEsw14Xygq0aq
         xt+7444R+1e6ZIbuYHcUoS2hXOUz/BSL+s59voZi3kGu5Fkg3d6qvwkCSFn3WHU+oe69
         3FwVq05bHxB2rLWLnk6rDMzdpz+sX/55EqQggoRA9j6luVvTe/0EKX4ImxFDT+RWTDDX
         3M963c2KJr7I7CbFOxESBe1N2CiRm+y3mRoyQjEzM6RUEy49IxjdrFpL2LmxyYzccALs
         kYzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hdJRfah2;
       spf=pass (google.com: domain of 3ks9hxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS9hXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JxevF5mdydDHpNdleZvbSdNTuZ885uZCnrlV7cTMhC0=;
        b=PMxkMf4liikygoWUpaC0xtKJ0kX9UykrBJO/P5VTszLGQJGhebML/ANwZ5UiD5AlNl
         TMVuW/aMxpwgOyJ+PEcS3Q2JxKNRZAF5Co7FxN6ndMGBoL23NLh9CSfap4dukqFSM5cC
         U878kHlY/pycj10flc2b79kPLSLhjjTnN5thZXGv1sTGCeU5U9G2xqH9WaJMelTwtUrU
         +MdEcFs2rwHPjKSjNhgxxb9sByRjzXA0DogCFJz/NNC4U2ZZTh/Skmm6p15XS1dvy72m
         puht3/8QqLuufC5TsAKDAE/Igs2/a8fhHBhxwR3JIaVeugwpZjXMV8I9WrBGaXJFSWE8
         vrGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JxevF5mdydDHpNdleZvbSdNTuZ885uZCnrlV7cTMhC0=;
        b=dI0H+ArC68qDRpyKJUHxDAHMX65d06UWY8eKt7JQUBir19/csLv6560XhSYGskv8KB
         Zrkq+H4/XEn3rP9+tIAxaBMNKpN2CKyTs7hF+S1i0iv6o+496xEpsS1ynALiLvOVoSPX
         Fhs1jKrjc3VGlxmAVF5jSB+Vr+zPCMfqvA6fFV5iLtCJ/p/To3cn0wA3z9KfefSMMiW+
         lZIXGFdj7VsNApLXdRRvEFoSulcuC8GwwSHfVTq5UXbn/8BDKUNEVz+BthnT22GgTZQ3
         3VJJps7nALUMSGR1sifge3c+z6eIAWn1V4XAxSPw0nMV/ydIhyzB21kqKmzx0ddRN4cB
         MLug==
X-Gm-Message-State: AOAM532/iHI+5EMjrxW9mSSZur8LL9agQuYH2/9FUkxLMWxJeScqx4JK
	XmkNXrMasHFPvpCj8Jh5BHg=
X-Google-Smtp-Source: ABdhPJxINfs+xXPO/EoDNvBQv8ttR37XcNHNuqcnch3ibzpocBotqXJ39rALxQGediSUSP+DaXZ9IQ==
X-Received: by 2002:a17:906:2e14:: with SMTP id n20mr22781704eji.214.1600204586702;
        Tue, 15 Sep 2020 14:16:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a20b:: with SMTP id r11ls62571ejy.4.gmail; Tue, 15
 Sep 2020 14:16:25 -0700 (PDT)
X-Received: by 2002:a17:906:474f:: with SMTP id j15mr23528126ejs.468.1600204585746;
        Tue, 15 Sep 2020 14:16:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204585; cv=none;
        d=google.com; s=arc-20160816;
        b=M19Q+9boUVhoQMQthD3SoskT0oZo1oRDv5cADFb/myWwXPlT5DPPb8JOteAi90VWdQ
         Ijlmys/IKL8COM65wI6OAnRxFLLlmSY7cvQbZdKL//hzhSbXlnuvIFu46jD92hIOHXOg
         e+YQ0XNJ4uRQRoQkRQcBTAgSDN9FqhJUD39XBSdAfQ/QP0vCgdZTdIMFRicQVAUslf6i
         fseV60VV7y+kbU5XMvrqZCgF5wXEmsSRQDSC9hwq9qEira/Wl/gT+VyYU77iYvLKCcpx
         ergEgms+abM7Q3Oq9ZDac+/SfLKYLdiTs9lk7VNcFOlgoiTlre1Rc+4WwBBqEeWpksGM
         2Qyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ssmRcE1kYrAL6ZSKtgqrQSJk1HXoJcRhQCNgYvB5iuc=;
        b=pVA2+I3t+AZtSothDHk91tjKQXu1MnDbQ+cB26bSYAR9q0gkflbP/f3NJFymWILS6o
         R64+0T0j1SsSxdeWv9b/uliKKCEYAN4u+T82/G2Dx1I24q0ZzaOaz2pZoGq6tJ3a7FTX
         MkuFYQ4C6PjmHeltZlF14DCXy0Y294NBSd+bHwuw2QkRlkoTMtoWmrhRPtgb1zjmPZVI
         xNewJBwRyItXfkL7fiKfwUwKkj7cVjKKuGgGZypRodA/oMz2gS/9NXx+nrXYadI9L0BZ
         t+q5kbjPWhZz3N51foQM2jdhvEeRCpf2ocZkKmb5ZoWdpS/YkFoU3MfXTpi4KDau45hU
         1LiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hdJRfah2;
       spf=pass (google.com: domain of 3ks9hxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS9hXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id a16si764417ejk.1.2020.09.15.14.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ks9hxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v5so1684552wrs.17
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:25 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:ffca:: with SMTP id
 x10mr15472756wrs.342.1600204585311; Tue, 15 Sep 2020 14:16:25 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:43 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <2de958570c5bccf438cde8eb8c2fce7e5a37deed.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 01/37] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
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
 header.i=@google.com header.s=20161025 header.b=hdJRfah2;       spf=pass
 (google.com: domain of 3ks9hxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KS9hXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..e1d55331b618 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2de958570c5bccf438cde8eb8c2fce7e5a37deed.1600204505.git.andreyknvl%40google.com.
