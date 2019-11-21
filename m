Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQVI3PXAKGQE5B7RLJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id AD4FD105940
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 19:15:31 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id o144sf1651544vko.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 10:15:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574360130; cv=pass;
        d=google.com; s=arc-20160816;
        b=wCB2uqG6Mbzavm+ZcoAxV5EXiYNsTXiIXJ2JKXgOmEJ+YI4eqC2tt/GXFvZ7RqhOYI
         QMziZ9mDy0BmeJoaqXsjbwJD4ysMYDHdfVNDRZDAJ72/hnfM5bPXHLDlqX0AHzfQKFWQ
         UO2+fo2phlGm/NEMMLSJ3bn6k5oSliDxKQOwHVRDFEpyEG4XEgLkvWrB9G1sDfwDMcV+
         W9uaayBb23D0l1igoIXUUADo9xmbw/naBY3nybNh/A1nHs/9bfooCS1xeLUU4GMrH7DZ
         Js9Fy9eL3ppbXamFuVd9J20efdGpOKa8DmbrgdAE/2EfDoc45QPkjmEty+wrXEmqmVCE
         LhgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=CUEDmj4YxSkRDdetxY5u5tkyG5/ucPpjbtE+sl+9EC4=;
        b=lIj/1sm6kclJ2qt7/XqlOrxJOS6hA1z1FNj30XnGR7dIvOdPfEat4py7m2pHbRsKQ5
         2GsKKJseUiIUJ1oeUYbWmh/Muh0VYYXCRMNj1oyPgU4Y6h80fb0n/i7D/MWdNWuSBMa9
         yT6GYaBDcD4WhDWAS0DEod4STFKgvM3/C8vxVUK96SrYpl0PQi/D8f1/rWJ48QjoROF3
         oiIQGy5FhLxOdlsTVbaiuK6PPsXou2P/tsdMMEJvEBrl/EX0Gths43mK15ILTVQgIeRL
         uxvSi13K4M+cZSYATIe7K0h9IDXeRGA4q7VINuJuVz4SJ++GKcPs5Yghwh6ukmGrQxyB
         FA1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=XNFMoCf8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CUEDmj4YxSkRDdetxY5u5tkyG5/ucPpjbtE+sl+9EC4=;
        b=i2mFITPEtAj4lYM7VoTvhNXlnld24IX+DysJ4YBGXqF1odQy0LQ3bdYvbJgQZKpzUK
         p/pYFc+peXJA9xBhg0R9oK1zla8V27AB7RIKmFUwHPWmuir64+r7AOKFkve5wTo2JJQh
         DULIeSTWCPb3Tdy5QmeLk8FRMiPnyEZ2Rt3ieYLzwQtJ79yJB57ZOYQSQN9yvZTCIOsY
         tCWGGiBQo8B9MxXpqZWK+uK9fU4oVqvPaFYU7ECEMTKBrw0sJskT74e/9eQCtpvbbTPg
         L7rMkkMu2i2ZmMxG/e1dx2t78pdWuYG9AoWM4mp5axo1QaS5mPATi1BbxN1NYuhxgZGg
         Dk7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CUEDmj4YxSkRDdetxY5u5tkyG5/ucPpjbtE+sl+9EC4=;
        b=p+ND25RXziNJ/LYKWhHulgx3laN6fp6WWmyS+RLjU1ApMI86XBvqXE9XKHkWfq7/Vb
         qAzc5xKEzI8R9cdjKhtM4KWNUuKE9x5E3SpvVHv0ddlzO5SHXXM6WJ5ZDX9y0VHBihGX
         7lwwZ3n4N++ULAELWrWHj4RV4ApZUuyR+KMIM7S8FkWkRjB3kL/yaoZMSG1SrdlYyIx7
         YHT3GLWBSsma6yHivUMcHaYF3//8mbd3dCfVcmMljSydLtl7ZOjqdwWNu3AviELitOhV
         cTE8122qAfhh6Yafk6loirfhzNWwVlFBjXzC5hqDNA3GknUqzjxbKFy+auc3amtPkBNs
         8WcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV5KcJT3580vqHrwoGhne3lkU1IIS7b14O3XXd7HqOWle2EHMpc
	IsKdf9gPwDlsIKQzZU257x4=
X-Google-Smtp-Source: APXvYqzJBqymPA+Zv5Kq8Yr5Yn108N875KRxFgJ/MRxZ4Wm2wtWdcn+p9lxhGkBPReQp4ZdB5Q4+ag==
X-Received: by 2002:a1f:18ca:: with SMTP id 193mr6433748vky.66.1574360130644;
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:746:: with SMTP id 67ls873542vsh.5.gmail; Thu, 21 Nov
 2019 10:15:30 -0800 (PST)
X-Received: by 2002:a05:6102:810:: with SMTP id g16mr6928431vsb.69.1574360130274;
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574360130; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJrDzNMP5Q/8LFy4XUe7s7AAwJjFF+sOdHUDn+Smkg4ns8Z404t1UTIULdo6OnpZtn
         83WS9VzhWFvKmEI+5uVFrxcEk1zP3CY7B3VjsQ22+QztkOQ1aNRjghSVRNFkbi32rk7G
         47lxv8pjGWdZFEB9gxVI/jP3TjDrfMWBWF/so87znmFJUrnO0k7rU/F21fujROWHS8Vx
         hSS+pvnipM5yfG8TFrbm2Dm5ZKyTx42sXC/Wf/fB4YHH5fBHOd+/wDdYxPBRlcQAcbAg
         X8T6CiBui+SgBPo+sI/TinLTHV5bpnGSZlsm7hEkyryHHaILym3nRkjmp4x7BF3VzF19
         lxNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=kx15nKFaa57ikxrtvnW6LLNF2Gic9naPHUcFWTG+liE=;
        b=l6U5Uz5tP7Oc5aol3G+17xtDz0qinj0BOjGhHepNJOxia8JbQY69Ipb3Zuu1f9BXlQ
         rCR7FYoFyQXNaGOEI8G8E7S6YaqDb20skngG9RddexPpzwKSDKh4Ijxgcr29RLeARgbm
         amcYGCC1LLfRdZFHgV++c4e2wDZCKvi5bKPzRGEhXyDCUbDrS7eGAslubIJHfwk9/1Rp
         JtL9AZ/qo6lf2WQ5fLyG9CxU9q49XOov+5wol2KdzmsQkz2lotlY2NJ4lSWSjw8VymND
         DGXWncdKgJGUhEUaoy8vh0TaE5T6IMd8z9QDhGORECkI9ONKD6fGIskieERno9y1Qolr
         WJHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=XNFMoCf8;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id f12si150565vso.1.2019.11.21.10.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Nov 2019 10:15:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id x28so2109800pfo.6
        for <kasan-dev@googlegroups.com>; Thu, 21 Nov 2019 10:15:30 -0800 (PST)
X-Received: by 2002:a63:8f46:: with SMTP id r6mr11009780pgn.51.1574360129345;
        Thu, 21 Nov 2019 10:15:29 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h9sm236306pjh.8.2019.11.21.10.15.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Nov 2019 10:15:28 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH v2 0/3] ubsan: Split out bounds checker
Date: Thu, 21 Nov 2019 10:15:16 -0800
Message-Id: <20191121181519.28637-1-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=XNFMoCf8;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

v2:
    - clarify Kconfig help text (aryabinin)
    - add reviewed-by
    - aim series at akpm, which seems to be where ubsan goes through?
v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org

This splits out the bounds checker so it can be individually used. This
is expected to be enabled in Android and hopefully for syzbot. Includes
LKDTM tests for behavioral corner-cases (beyond just the bounds checker).

-Kees

Kees Cook (3):
  ubsan: Add trap instrumentation option
  ubsan: Split "bounds" checker from other options
  lkdtm/bugs: Add arithmetic overflow and array bounds checks

 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 lib/Kconfig.ubsan          | 42 +++++++++++++++++++--
 lib/Makefile               |  2 +
 scripts/Makefile.ubsan     | 16 ++++++--
 6 files changed, 134 insertions(+), 7 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191121181519.28637-1-keescook%40chromium.org.
