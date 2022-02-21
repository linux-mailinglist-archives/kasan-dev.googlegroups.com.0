Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBCXWZ2IAMGQETFO74LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 00D0A4BDACB
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 17:17:15 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id c25-20020a056512325900b0043fc8f2e1f6sf2562354lfr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 08:17:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645460234; cv=pass;
        d=google.com; s=arc-20160816;
        b=UP0tfmovkuXU8p/mGYNiNklWBCeXhyGXPQESgzUeRiof3ZO/CvuWNm8SrsLCu/+471
         O9xxmC7DdxJdPTuWtswKjQv6ltGvzOt2QDkBAZ1oZokWDjHCihg0R4XqAefHdV7QlARo
         tcxCgKcfb3TVlYd60kVYRW0+0c88B+KDKXVo+SHnqN7w4CdacTt50wajo7tCW1DB37Sr
         sg4zLx9BwTqFReb5JR5U0oE/cvDwwE7olN9M5jpITy4wnJOnOhqWlu/+w0l/s8aRrEpv
         va0o7bcxA28YAcZgsGKnoVvJD2fImU9yluOxPGdfe5J/OSDTK095bqWoetwD88BVre/m
         PiAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=4R33ScriXvPCPfr6VO4rOv/fnHUQkQXjvhHMkbcLJgQ=;
        b=DIEJweVSleEPVkkYiv/POTcoE2HQPqwI5EZDdCSKh7+eTJjrpmDdj9ZGQ70dzbO0Cu
         4WuCzM8G743IH7aAxRZaSrQNuH1Z8/IabX+QjVrNkFxPx28ULeU/JQ76ZLmxn9NtCLf8
         x1wI9UpBqykBaR1ozUkUKwXYhvv0WCo/HGsRZGom1TvSNk0onlQwkXQlcvGTr1WMTQRy
         jE9VIKqyWzCxhVNd5pd1Tfimlg9Y1T8SPV430SA/4OobxBEi3UgP3O6Fv/6L803PgQWU
         Xfjp+yRjNa83l33JzrH8D+4j8rJuMWhCInOlHOzE31xpXERD6PXYnO0MQ92TL1JwsAKS
         NblQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=tOhOKaW4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4R33ScriXvPCPfr6VO4rOv/fnHUQkQXjvhHMkbcLJgQ=;
        b=U+DNWyGQ3v+VzO9U6WmNnq0C7KnJtKBW97QY3oWWfqz9GXACf/I7nha3KYyg52V3/u
         ssT0f2sFg2zjf3Jwp/Z1S6iyfMzOiTlWNUx6orqQ7E7sPUM1kuGeaECTXimxqHKBEC5v
         K2Wy5LF18v6LfwqlR46f3tQBBaXgk2aB76LSgDg2wjiCREWRbgxCqvtqxbHgGThLU2Vu
         ipH6A5UOKeZVXNwYiSYqJjawNMTZBo0+WXYTjbalbZWdo1+4oB1BkVbNdsrK1zlYQQ6C
         f9G7vbHsJG8ANETLiXJjKiSn9G3UxY2ShZwiGzuz+OWpFXfMLqTl+4QO2KAU8JDxssuN
         6Z+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4R33ScriXvPCPfr6VO4rOv/fnHUQkQXjvhHMkbcLJgQ=;
        b=abyF37tLPZxUzACwayXwXq5xfnNksgDpNCOJNc6QPAojBFwreURhs3i4KCmvGJVCRJ
         AE2GIZBwm4tu03Dcv1hfBZWf22aJ9ZE1YOxDGomy1aGXINlVuTspE7wYqT0RQhES4Jok
         ZQWqhjciq9m1MIBy75D/kGWblReZo37SFICZ3UI14Z5wM/HXz2udqUy5qPjF8Jr4Wntj
         fnQPuHLtfAMNg01mtJyHlLr19JlG4waQJn5UjMG4aHK33Rn/8UaoM1J6ZnDmQejwSGna
         WiHREdRMhJt32GZlqaZniqwSvNhe1wX/PCif8u4np+5uoYcqPjYs3HOBjweyUv0bg8Xu
         SF/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CCna9iWEqW2HHY3LyfdDVMDySQY9TaH3zMK++iV35QcRvYOXo
	/ohOOsPSdQEENyMVhuxBOx4=
X-Google-Smtp-Source: ABdhPJxzPyXSLjxQI0XvTkXrUiYr1M4any7ANmO9pe8w+3pMKkEgsGFjlBsHYWUdxOEaxN6+gROo0Q==
X-Received: by 2002:a05:651c:2103:b0:244:de1e:bbf7 with SMTP id a3-20020a05651c210300b00244de1ebbf7mr14636690ljq.115.1645460234510;
        Mon, 21 Feb 2022 08:17:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a3:b0:443:7b15:f451 with SMTP id
 bp35-20020a05651215a300b004437b15f451ls811041lfb.0.gmail; Mon, 21 Feb 2022
 08:17:13 -0800 (PST)
X-Received: by 2002:a05:6512:150d:b0:442:aad5:2550 with SMTP id bq13-20020a056512150d00b00442aad52550mr14662914lfb.678.1645460233478;
        Mon, 21 Feb 2022 08:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645460233; cv=none;
        d=google.com; s=arc-20160816;
        b=CqPGIR4zSxJ4bcoHD3pLit+yVXKVLFpQKXazcFtDMOW9+WpW3KCZVe7d4zB8V99kuL
         y1Yb9LmdNepFsSy6y01kMxypnCi6FBrG/nyvYVyH1g0NDXXFsXYflrHcj3eW/WSWmSo0
         UpfoasgE9bmY5d1QEPRLHBBU/y8EYifpvL1MAKRAcDx2+V+jSsKC/usPYhyEzSTnMPRQ
         u2hGtFosgMs0n5CVrMQj64XtM9hT2HZzstLA7WA8QNi1pfFfxd2uFGm3Myv5CTNpm2d9
         uoje5Dl4TEZdeLFUmziUwf1RTlw2FWN9vEn3LLP0PT3/quFKaWOR2DCPbEDVUe3bst0k
         8SGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=JOP3F1szvziyyHwwb25WbMBDR7/phOdbs80dtO/BlA0=;
        b=X4ZihemtWq+Roc8wqbMVQ/aFCylm2pxKuHBBTKPqxqzmLkMPvfUlbzy6rJ5JYiAiCz
         b2L+K9flVp+zjg4ZsORpq22Z9pzITquUKuijbWPrp/gYVkBZuHqayOhsEQ0lo7YO1jPR
         f1p0zB2dYV5dtcdA/iLz6E08Tw2JiFTGdhGfi1f++0O1V9pdiZGh+Rwg2glZX1L8pe+7
         bpvfZJJ7wyUmgGEeaUFysZ90Kl+P7WbAt2TO2HS3z5Uwg/VdYLQb8u/cGlPzMFvLkiWR
         ZNa6hewIQiBPSoyhJDAHouyT9hkGASUK0YI6q7s7atsNZuIUIF8UDjUEU7m65LVYWE0W
         jVnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=tOhOKaW4;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id x24si352971ljh.2.2022.02.21.08.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com [209.85.221.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 9F2213FE41
	for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 16:17:12 +0000 (UTC)
Received: by mail-wr1-f69.google.com with SMTP id p18-20020adfba92000000b001e8f7697cc7so5589088wrg.20
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 08:17:12 -0800 (PST)
X-Received: by 2002:a5d:5885:0:b0:1e8:edbf:2d07 with SMTP id n5-20020a5d5885000000b001e8edbf2d07mr15598181wrf.85.1645460231226;
        Mon, 21 Feb 2022 08:17:11 -0800 (PST)
X-Received: by 2002:a5d:5885:0:b0:1e8:edbf:2d07 with SMTP id n5-20020a5d5885000000b001e8edbf2d07mr15598169wrf.85.1645460231012;
        Mon, 21 Feb 2022 08:17:11 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id c11-20020a05600c0a4b00b0037c91e085ddsm9825161wmq.40.2022.02.21.08.17.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:17:10 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v2 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
Date: Mon, 21 Feb 2022 17:12:32 +0100
Message-Id: <20220221161232.2168364-5-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=tOhOKaW4;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

__virt_to_phys function is called very early in the boot process (ie
kasan_early_init) so it should not be instrumented by KASAN otherwise it
bugs.

Fix this by declaring phys_addr.c as non-kasan instrumentable.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
index 7ebaef10ea1b..ac7a25298a04 100644
--- a/arch/riscv/mm/Makefile
+++ b/arch/riscv/mm/Makefile
@@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
 ifdef CONFIG_KASAN
 KASAN_SANITIZE_kasan_init.o := n
 KASAN_SANITIZE_init.o := n
+ifdef CONFIG_DEBUG_VIRTUAL
+KASAN_SANITIZE_physaddr.o := n
+endif
 endif
 
 obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221161232.2168364-5-alexandre.ghiti%40canonical.com.
