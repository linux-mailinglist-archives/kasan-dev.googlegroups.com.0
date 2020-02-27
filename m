Return-Path: <kasan-dev+bncBCF5XGNWYQBRBOM64DZAKGQETWRE6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9842A1727FE
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:30 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id n12sf121154qvp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829369; cv=pass;
        d=google.com; s=arc-20160816;
        b=hqOgyYoZ8gxGUW9WGqiBC3lCTWkQPpR7zAcGcJON94uos5JU39q500nBSAJ23mXSyt
         7PXc9+6CAhQOGDht5ARev0+5J7nE9GYa08R5Db2EBSlCmN9XX8u3OS4L0kurVyI2v8ug
         Xs5uquTmb2iJj4BRwghIiAcOEjCRggqfHu3CN8o5hOvh2PWbBGcPhqfdVKPklisP1R+x
         nTPGgcE24PyaeapHf3MMhAxRn38i8k2wtuaheVTfSsxEejEsYkMF9yomLgwN2SmyhAnB
         7EFaAtuDbZDIhmq/n2eUVJxo85jgsH0beJ0uW57eyUHbFC+jVu2iezStTUITFOvv4Ssm
         zcTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kzly9CEEBi247Rm4UhZPrjtJxqwuM9TsW16wJ2KNWTw=;
        b=t+4UX0it6jUs+pmi/gK2ITtxAP3GMU7b6WmdCe/3UYd6crEdkqchOvkrlE4pxQHdEJ
         F+5R6aEBP2j/UCfcYtG4GMUhJSKnJe8MH6QG1CxZPgDyMxIOqFZn/Qr6ahraUKwH1yCB
         XyGHi7trkmNA6bwTYVSjBU51bOMIhRgZIXNBPz+Jvl41izHdgbgXeTAx7OsO2eQtrUC1
         KiaF93EyhDFXVGRP3JnHK2vetZI5eWq4UZnYueFHcxT7848Thyyo2RSaJ6/DWGUp738q
         UQYOI/HCl39XJQohVxlbyq5L7ct4Zrks80Ow1hhOVCqd4mZ/pu5F1MD8THgyKTA+e8yj
         +mYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lTDnhmVn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzly9CEEBi247Rm4UhZPrjtJxqwuM9TsW16wJ2KNWTw=;
        b=C0rI5r5zO1cuMeKApcNSTQX2ZfzStxfDmm3mVymakw74L1W5DEBHbKiwoQLve22UNQ
         5EgITSDXsVXV0h0SRBcl0eoaOB21Jbaz0yGuPhVwKaE7SJGdsFr/R/SDvOhAo6DKcADv
         gwsdGMkXOjPcByMTQzBi+ksr8okmNVopY4SDQrQpE1tZkRYLUo4JWROG0vIDLkOueOdh
         jtFblkQvLEPegvPrH5nEDIMf1T3HxfgslwDqhzS9AcEEDX84yu5LARTaWLrfRzu1wr49
         ZN1WGZA22Q77ixp5Pfv1LWjHCOiFMCh4A4VPYOBnmMsMrgrm1/GL3gTWfBfEzCEaafzm
         jh7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzly9CEEBi247Rm4UhZPrjtJxqwuM9TsW16wJ2KNWTw=;
        b=LM8yr9uxRx8/V86YYfm8WUkOEqYAnB5H09Z979VLuRpEr53KeBOpL7wmRfNMHc6I36
         xz0fxj3X249ydDJaYzYW5vBSUW96lRUXVryx1BI/rfiz4zes8F7YOc3OtCS+gTWrlycr
         Fp2gxi4TBHbKJ9CoxPTSYUznVghF6uqw+LZ0Zb4wtEoh80dsqRYQiddl+uexgVjBpbhk
         4pND0QlRsBGq2ohWPSREudyXQz8G4OyOOCthoWLRwStTZiQoOysmIibR1BbOxvZpJJHe
         gfas6I0sG96jf3eADeTwMSoBH50VHhcCj+I2dY2YmekXwmJZcMq+3sBYpSwNA0fHm50/
         G45w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWv32Vq3/rP92iYq9D2fo28hHi/ms2tUm3fhoJp4sCCHdBfvmaE
	6OpxcdBN6obRNJEBJ1sAAt4=
X-Google-Smtp-Source: APXvYqxSKo8EXPImStT0/P897PAcjmL9pG2pb7RQuuCbiLHmT/jEV1NZsUUWfb4kKR+OPc3jrIshOg==
X-Received: by 2002:a37:a182:: with SMTP id k124mr751802qke.498.1582829369470;
        Thu, 27 Feb 2020 10:49:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3405:: with SMTP id u5ls51635qtb.11.gmail; Thu, 27 Feb
 2020 10:49:29 -0800 (PST)
X-Received: by 2002:aed:204d:: with SMTP id 71mr681971qta.116.1582829369152;
        Thu, 27 Feb 2020 10:49:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829369; cv=none;
        d=google.com; s=arc-20160816;
        b=jist/m1VywwZv35FV5Ito7dUenL4jVP4u2u+taTNQ+PSJM0q+HEMKspZd3nE+1NcFN
         EMKl9I/9dRSO3Rs4ONBmDdnu0UQNj9Yje+UeW4LyC99R0Rc9sPLjMH0spRceHI7Z7+RN
         bzsWDZma0vd0lcDHoBVnIVQLOPiFqhnLTj3KkQk/hCe5pyenecAXuSZaFBxzkGqZ5YUS
         eqjeb4WCwIKHAtBKv2XhTPVSSVjgtubyefsDVnNvzP14QDXaTidKYgmf7LNwfU5x4ISB
         TqUWEJ/XJdvo1lfYVamHTuK1wWfWJ2IPjrGqOu10ze1ohHYz0D7Pzo+AfGOGyHUZkerd
         3jPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=46Z0N6nNFPIgM2OuwNgkHRjYe659IsqNoWw8FG0hdrY=;
        b=iFMGZs5kMdI01lLM70JXfBcP/sZJALAdmWzjgh95ueK2Nsm39rYSgwISgxjQeM+Hg8
         SZ0JagCdbVZVdDmamc7+KCm6OE1/7lkaGIHbVVoKzOBTU+v2SjIWMoGOKD8sHv6x+9a+
         qimUNerWmeVt09jEcRDFkZA+s1YLkcPhlSos+2X6Vi4dHwZVIGeNXidobu2c8VOmrj3o
         2UFS7qN8wGFvIOWWA1LLP0ePAohdPP+vPKyAzdQK3JH0YsKo78pE5i+iChUpe/DqzzN5
         BXNaXByeVKOl8jW0FqQgH0VFL4Qf/p1WYyKLX5vhj2JMxckqlk7X3sSHj99n7NsXExCl
         BkUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=lTDnhmVn;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id i26si34901qki.1.2020.02.27.10.49.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:29 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id i6so293636pfc.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:29 -0800 (PST)
X-Received: by 2002:a63:3103:: with SMTP id x3mr677715pgx.209.1582829368829;
        Thu, 27 Feb 2020 10:49:28 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id e1sm7998669pff.188.2020.02.27.10.49.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:26 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v4 4/6] ubsan: Check panic_on_warn
Date: Thu, 27 Feb 2020 10:49:19 -0800
Message-Id: <20200227184921.30215-5-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=lTDnhmVn;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::443
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

Syzkaller expects kernel warnings to panic when the panic_on_warn
sysctl is set. More work is needed here to have UBSan reuse the WARN
infrastructure, but for now, just check the flag manually.

Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/ubsan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index 7b9b58aee72c..429663eef6a7 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -156,6 +156,17 @@ static void ubsan_epilogue(void)
 		"========================================\n");
 
 	current->in_ubsan--;
+
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
+		panic("panic_on_warn set ...\n");
+	}
 }
 
 static void handle_overflow(struct overflow_data *data, void *lhs,
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-5-keescook%40chromium.org.
