Return-Path: <kasan-dev+bncBDN3FGENWMIRB3NGUWLAMGQEMNX33CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A50356C8A0
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jul 2022 12:07:43 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id q5-20020a9d7c85000000b0061c32a58920sf700305otn.4
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jul 2022 03:07:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657361261; cv=pass;
        d=google.com; s=arc-20160816;
        b=avdIT+9Rxak9LK4rXvWtYAkTlJFrV5e15AwvZGYDVEaoOHYkRrG90nag9qUjoIMB5B
         7XCEVy3XmQugeXcuCcF31QSDp8dj4j8Dx0zkgOM/MeTK8Wp+u2Y+Ya9Cr9kqbcY2Yrqc
         EnJcguCehGQ5X24Zm1w2Y7n0W74BrEAirzcyfacTKVvzFCn43sOvx2+NvIo1A77TOhlr
         90o7or3bLZFFa/eBmkmojMAQlgRoAlBslbkjoeNAEQppZ+0KXfhbmBilCH1211Mt0ThL
         oUG5z+N3XSNnQ0cFg8VaF9xAfqhX2iJ1KDisSlIdtVZS0hq6Ae94H1wS9DCt0lKeRemX
         29ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2XHAlVaQMWI4CYbTscILCohqYiqY2e1N+zpuBPIWNTc=;
        b=mVdZBMId4nn/wOnXNhQZ4gqJzG2bJ3nNBDOo57Yt701PlYU5LdjLIdBlX/5Hf/r9NL
         418Fo7JDBbhCPXcFGafcGSjsbV4RqTJV6TxZFn6COzxcjuOThqy/CAudEaOzGSAOiuTs
         wd0Re/Q1nhqkFTIMlNOOFMjsCFIFSiEG+T5lOxbs0IGCDpQAY7HoY6lYVkh1FE3MuQrr
         ILE6gL2Zvf+MGiC6eL2AeDc2m8EjRfp6rXm7Rv4eRMt33f7fRSSPNHjBDEsFr11D/Gfi
         oZvziQVk+HbA5ZcJzoruHt0hNbNQ+WOQV8Iv6jy1r/H/nZ8MQ35RZRC+fIdkycA5WpCO
         KUDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FUrhBDV8;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2XHAlVaQMWI4CYbTscILCohqYiqY2e1N+zpuBPIWNTc=;
        b=KH8CI1qHwQDhXtZ9QEaG22H3CngCJ0wI0sOUjKDf+YFX0iAy5TgtvzeNDB353F7dz/
         c9vSzjGhRoQX0J7mxNwJxsClFvJh12kXtMxVp7SOmCFWiyoRAA3Ho8RUt/QpjFZT81Bk
         93Ys9+KN5BjPyaFK4zDm/SVxETg4aEDGd1Jez8/EZOCR6Z0zoexZUPvI2Qpy0nqF308C
         4VySF7wxAbIyrwUkw2xR5FFiqxfWf+WnbimcdV9+NSdmWnVsfHVLvH2txllREtDZyk+j
         q6vtYgcKHxk4bQWUfojZf3qm9+AeMUFnIVMK5SMn+etkHz2Y3G45BzdEHRIl3cNPHY9v
         /niw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2XHAlVaQMWI4CYbTscILCohqYiqY2e1N+zpuBPIWNTc=;
        b=wzR+TxZIFz1UQbn9Id+ZkUX1XnLIEhOGzgJDTZJa9z3Rbk8qEendzF/aw9CMHyJdFh
         j+eVyDYWgau7QAkx5dL/EqQDDx2PL93+tKdt0SBKelBG4f5qiI8cz++4iHLoMh+5A5qu
         vejEOaWKyiysNepx+WKUUKnR064PUTHchpTKGHmIpxGE8mbd+e8LfKzBFKqTRu8OeUsl
         U4mas6DUGX0FJzvrK1QDw3YaloH89wauFu0XpBfUhArwX1GTPzCm5hAZPJ2v9OmZIzmt
         YNH3rsicLFRpBlhaI5B1uO8EK+Mw6SxK9AmGGOblm8xzq35kG1DO6KhjAhYJyyOiTOpE
         Nkgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/vqmWD5DuLaR0F0M06JFpTyCHtbjaeCJ63qr+3TMMsDQi6o7jW
	V6dqHvAIZ7ZC03Ltk//12+A=
X-Google-Smtp-Source: AGRyM1uzxi4loDY891v/8jVsa9iq8S380Rly7zEVKjwgWPM5sV25lCbRSOGwZ9igRxX27ITvubqnhQ==
X-Received: by 2002:a05:6808:eca:b0:2f9:c581:3f76 with SMTP id q10-20020a0568080eca00b002f9c5813f76mr2253476oiv.138.1657361261581;
        Sat, 09 Jul 2022 03:07:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4b45:b0:10c:6cf5:a1b0 with SMTP id
 ls5-20020a0568704b4500b0010c6cf5a1b0ls472529oab.0.gmail; Sat, 09 Jul 2022
 03:07:41 -0700 (PDT)
X-Received: by 2002:a05:6870:64a1:b0:10b:fcf8:b5a5 with SMTP id cz33-20020a05687064a100b0010bfcf8b5a5mr2305298oab.22.1657361261127;
        Sat, 09 Jul 2022 03:07:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657361261; cv=none;
        d=google.com; s=arc-20160816;
        b=Mnitc6gHTHKaXmOQ0wtjdsRmaAE8A0/6G3yQX/iOH3bHtRQeJxwFaVoeZBRxwKhkQO
         bWf4QoBGFrOpupl5WfB3PfufRkEV7VAotmG6cJw8NdrU0VZp6oOzWhvfA0cGTLRjiqrz
         HDwjzHPtaebfXdbOEIyMkUEAoWh9Msi/JVWHhq4DtO38c1LxhLlXyw8imsSyQOYCv1Ol
         Oxt09ZkkMABY9pSADWt23u1RhKtQqeSxxunWkvHwZFkHlQs+px+eYYLMT4ENvxQrfP//
         akOZTVApS2dRWYzQHtlu8iK8T4zT0F1RSMRWAcCrWi8pQsGNuZdxGkRKD22mqVU3NgqU
         +oSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LmIxlL6xi8/dzUl6fdGgfquohvI4c0A2FTmMrBG3EAE=;
        b=qB5qh6hKP3bgGTcSzwcUG0HHyVHIyiAKMkJzXtPd6IqRCpfkXMHdBjdATcO73FHI/J
         6RcANaNzqwOQXpDqdazLEeH5fBjljcbZBX5EyMAp+58PcS75ATJjaHnkevwv2xfMQdTB
         Bkl1bHE7G55q7rjeJgzdRjJ0Bsm/vwh/LkxcvjG7pTzPnAl1G3OZBESKdCRJterW+tM6
         p1SfiiQ5LghvQUbdFkl9q98EXgbv+6Ilqokgixs0aR36ghKYZ+G8Ak8ajVpHzuR3Np2x
         7hw1A/sRHnRpODaikYGNrByvHjXvAbUPWRgYW1By7EJv/67TGUIhFxs8AOO5fLzJ2kM8
         ortA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FUrhBDV8;
       spf=pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z189-20020aca33c6000000b00339c9e7c8ffsi51930oiz.5.2022.07.09.03.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 09 Jul 2022 03:07:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BD97760EDE;
	Sat,  9 Jul 2022 10:07:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83E85C341E4;
	Sat,  9 Jul 2022 10:07:38 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.95)
	(envelope-from <mchehab@kernel.org>)
	id 1oA7N9-004EGx-JK;
	Sat, 09 Jul 2022 11:07:35 +0100
From: Mauro Carvalho Chehab <mchehab@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	"Jonathan Corbet" <corbet@lwn.net>,
	"Mauro Carvalho Chehab" <mchehab+huawei@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	linaro-mm-sig@lists.linaro.org,
	linux-kernel@vger.kernel.org,
	linux-media@vger.kernel.org
Subject: [PATCH v3 11/21] kfence: fix a kernel-doc parameter
Date: Sat,  9 Jul 2022 11:07:24 +0100
Message-Id: <4e4f3c9fa6b379a82b9647d2f4152cfb520730ff.1657360984.git.mchehab@kernel.org>
X-Mailer: git-send-email 2.36.1
In-Reply-To: <cover.1657360984.git.mchehab@kernel.org>
References: <cover.1657360984.git.mchehab@kernel.org>
MIME-Version: 1.0
X-Original-Sender: mchehab@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FUrhBDV8;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

The kernel-doc markup is missing the slab pointer description:

	include/linux/kfence.h:221: warning: Function parameter or member 'slab' not described in '__kfence_obj_info'

Document it.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Mauro Carvalho Chehab <mchehab@kernel.org>
---

To avoid mailbombing on a large number of people, only mailing lists were C/C on the cover.
See [PATCH v3 00/21] at: https://lore.kernel.org/all/cover.1657360984.git.mchehab@kernel.org/

 include/linux/kfence.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 726857a4b680..9c242f4e9fab 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -210,6 +210,7 @@ struct kmem_obj_info;
  * __kfence_obj_info() - fill kmem_obj_info struct
  * @kpp: kmem_obj_info to be filled
  * @object: the object
+ * @slab: pointer to slab
  *
  * Return:
  * * false - not a KFENCE object
-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e4f3c9fa6b379a82b9647d2f4152cfb520730ff.1657360984.git.mchehab%40kernel.org.
