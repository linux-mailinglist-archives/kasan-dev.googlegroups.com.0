Return-Path: <kasan-dev+bncBAABBDUCSOOAMGQENMFIUHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EDE963AA84
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 15:09:19 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id hr21-20020a1709073f9500b007b29ccd1228sf4410691ejc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 06:09:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669644559; cv=pass;
        d=google.com; s=arc-20160816;
        b=gG6WW765weLHtCKMF2wiBzyYsVs7hD6d+tXtL48SPSWT+8v6qNGvJFXMdy2tYbaqYZ
         khd6OKrTOm7sxUHEaRJMo8xwoSeFhCDjNSPgTGdjD+pAiYC5DbFaDNChBVHHPegBQWUh
         9XsBIobmf6g7halM0fT27B22wI11Fudeh5iBwWCIbqznOzOLsPGmZHkd6QPBIfk6WCbF
         PrIBRm1pazoZxH/2/JYlmFwbD/vHaVYugTZm7TEUEYk3MOug0s5qMJ6w/W5JsFDFc3Kg
         bjMfaS/5ssDI8+L7Vdke9SUU8DHROO7f5dhaxfZvgnUygSXBDCJHivgZFvpG36o9KXEP
         Dopg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CZTksYH6/HOm54VFniuY5H9rqUroHC0g8FnaQAQ1LNI=;
        b=Nt0IPZTfcxlgGcQu8zf3jm+h56/Vr4YKjklNN+NQrHno5lkSQbVjQtM7KenE+zKt+L
         8pDbkxUP40ZuO0+r1u6jzwiFXu8jRNYJIzl4zPLH/BXMKcLD9F8/bR3LNHjN6WSARy7c
         rr2DO990D6NP4MiLSu+c+qbDDz6wxFeOytWQUAWRYQIp+J7imLe8VfvxAku134YtjW0L
         A7SpD4Xu/O43oHVK5hMRk9iSZ5IimbKTKDHso2jMdMf3DrRkDGcmM/RSVTurjvnh6gaB
         kITVexTJ5eI/Cf1LyoalJqwXzr6RBBl8TgM+ftRFsBmCbt/w4aBoy32ousPsnFCc2SQZ
         meMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="QPe/lrCt";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:references:in-reply-to
         :user-agent:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CZTksYH6/HOm54VFniuY5H9rqUroHC0g8FnaQAQ1LNI=;
        b=Pw/9zTKZcuv7r3ZQ9qC9SaSAEiWdieD81i3VLpAZmlLoKoAvcu5sQhcWdFhQg+SDGv
         6tn45Cf2GzW56Oe15NyExwo2Fol711uFkO89EGos7Lg9ShnG0QSWGrLPK/N8Gnn1FY/m
         WG7bdr17bk5VLOIhnM0CROElxs/7adevadLqI206QKhEvbMUnnByEPK0xEWxo8MpzoQZ
         BklEdw+pYY6K569bVvrRbHhJ4G+rRU47EfoPB6KuHMVjjJH05OHzHR64ol93vm49rOA5
         7imoue+2qkYNl4ta9g2p9L9H9O/2wrwbqlX04FPlC9mxKsfiK4OiVlkmku8wVB9grClv
         UEJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CZTksYH6/HOm54VFniuY5H9rqUroHC0g8FnaQAQ1LNI=;
        b=pcr99YHPhc3ianlk3fCcsRyI/4QRGOEeqWuv8UN68sk2dj9QfUrAvahFvVGEzrwpFw
         80GiSxk2N7JOejZpyj0r6lLsEXynMWhvdr9fEcVuF1JczywR9/8EAyDQ/0QzQlHza2i/
         O8lcIh3nZMtQX0vUNROM+GqjH+sXPkm0IMxPzy4ZG16JlmaRabN1fbuaf8cfNzRug74k
         aABKnxXzE/DQD9GbbjrxZgt0rZsqscVq3Qg+8OijuqdEBpk0SZNcLrhtH7/QwqiTRjid
         RXE5cuuDo8WfyjhdXvEEBBjxsTTerTFQXt1i1FK4BvnOCtQcHibsMnV9h27pW/C9CDMU
         J67Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plHQa42O6+DDo48lSjYfKIjHowl+MMyxP+CVUa60lY5++/YZOL/
	J/sIUWq9PrtbODD0UCtvi0U=
X-Google-Smtp-Source: AA0mqf7IOoQbMaj9m/NUl+oqfmIplWHsFCroH3OuN9N1CcqjVCcvRMrr47mUZ0Aw+1Qs4RxdgeuVYg==
X-Received: by 2002:a17:907:a688:b0:7ba:ba67:f2f with SMTP id vv8-20020a170907a68800b007baba670f2fmr19233160ejc.199.1669644558823;
        Mon, 28 Nov 2022 06:09:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c5:b0:461:bb4b:90b1 with SMTP id
 x5-20020a05640226c500b00461bb4b90b1ls9040709edd.1.-pod-prod-gmail; Mon, 28
 Nov 2022 06:09:17 -0800 (PST)
X-Received: by 2002:aa7:d5c4:0:b0:46a:af31:7c4f with SMTP id d4-20020aa7d5c4000000b0046aaf317c4fmr15792697eds.320.1669644557803;
        Mon, 28 Nov 2022 06:09:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669644557; cv=none;
        d=google.com; s=arc-20160816;
        b=vvZxjqBM7jyue5WzCGd+iN2VBLFEylWgx94mJBaKpNLyQoyZulz4pQhu6Y3IU/rAsO
         PS5ln2K/VF6taUjNF1iisM6/xLIT+Go8JfOKpFAT0DMfaMPoEkiEqdiadc2wT3E7zJbA
         /iF5o7HTZSkcncL8k53PYZhpAauWgxAo4nzWCq8sz4L2/fBx+QGd4rgAdxROILnW2rIu
         XvRPvYYFD1208I1ego0Uq9ebNax7xsBBpEHxeDaPlJ1VdjMOxN1Md7TlMygj7Plrcs4n
         EWavWdWMyWMC0K4mfq7VSjAmkb5xcAF7px7iRTzG2N6dpm0RuO97xQ1hQsUOXcthPWFP
         C8zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=ou4WXrD/oMyuUc5UomObD8LEVi7sU1dl5QIRvUf/T64=;
        b=zgrwRoZaSvZ5Ds3oTnHvKhgy4T3+WwjDZVJnSTAs6J8q42cl6VdejuTL3cYpHtpdQF
         9k8lOAjpDkUOoDE0Dm8zhDrzEJC/u8amnQfw9mW7FVRxBAvqeC969cUqzKmgfrmqchRQ
         RLbSlxT2kPP4KCqJR5qSS9e18pFHdAh8nsk5KsDHQMtnOlMRyhJw/K0hQpbwnhSoSFqH
         tP1yMiRoXlnowK5pNa+Yri+9NxodRzEmvOtU7XEBH2oFnVspBbaNhYIMf00r0Y3C1YBX
         E7qwvY/IbBtBMt9s78N8L3e3J6BLAEbgafbE5Yc4NdC1dcbQdOqlbT87yDj7e8W9OGl3
         iZ0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="QPe/lrCt";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id mm6-20020a170906cc4600b007ae8a4b03dbsi487038ejb.0.2022.11.28.06.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 28 Nov 2022 06:09:17 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 82794B80DDD;
	Mon, 28 Nov 2022 14:09:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BF044C433D7;
	Mon, 28 Nov 2022 14:09:15 +0000 (UTC)
Date: Mon, 28 Nov 2022 06:09:11 -0800
From: Kees Cook <kees@kernel.org>
To: Anders Roxell <anders.roxell@linaro.org>, akpm@linux-foundation.org
CC: elver@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.or,
 keescook@chromium.org, davidgow@google.com, Jason@zx2c4.com,
 Arnd Bergmann <arnd@arndb.de>
Subject: Re: [PATCH 2/2] lib: fortify_kunit: build without structleak plugin
User-Agent: K-9 Mail for Android
In-Reply-To: <20221128104403.2660703-1-anders.roxell@linaro.org>
References: <20221128104403.2660703-1-anders.roxell@linaro.org>
Message-ID: <5FC4A1FD-9631-43B2-AE93-EFC059F892D3@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="QPe/lrCt";       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On November 28, 2022 2:44:03 AM PST, Anders Roxell <anders.roxell@linaro.org> wrote:
>Building fortify_kunit with strucleak plugin enabled makes the stack
>frame size to grow.
>
>lib/fortify_kunit.c:140:1: error: the frame size of 2368 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]

Under what config and compiler version do you see these warnings?

-Kees

>
>Turn off the structleak plugin checks for fortify_kunit.
>
>Suggested-by: Arnd Bergmann <arnd@arndb.de>
>Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
>---
> lib/Makefile | 1 +
> 1 file changed, 1 insertion(+)
>
>diff --git a/lib/Makefile b/lib/Makefile
>index bdb1552cbe9c..aab32082564a 100644
>--- a/lib/Makefile
>+++ b/lib/Makefile
>@@ -382,6 +382,7 @@ obj-$(CONFIG_OVERFLOW_KUNIT_TEST) += overflow_kunit.o
> CFLAGS_stackinit_kunit.o += $(call cc-disable-warning, switch-unreachable)
> obj-$(CONFIG_STACKINIT_KUNIT_TEST) += stackinit_kunit.o
> CFLAGS_fortify_kunit.o += $(call cc-disable-warning, unsequenced)
>+CFLAGS_fortify_kunit.o += $(DISABLE_STRUCTLEAK_PLUGIN)
> obj-$(CONFIG_FORTIFY_KUNIT_TEST) += fortify_kunit.o
> obj-$(CONFIG_STRSCPY_KUNIT_TEST) += strscpy_kunit.o
> obj-$(CONFIG_SIPHASH_KUNIT_TEST) += siphash_kunit.o


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5FC4A1FD-9631-43B2-AE93-EFC059F892D3%40kernel.org.
