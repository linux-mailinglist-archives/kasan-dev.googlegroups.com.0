Return-Path: <kasan-dev+bncBC6OLHHDVUOBBI7D5H2AKGQEXPV5BTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id D9E731AE993
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Apr 2020 05:19:00 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id v185sf4139773oie.5
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 20:19:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587179940; cv=pass;
        d=google.com; s=arc-20160816;
        b=phvzTVAtm8R1623dlCIFu8H0eG2iEwLlpoG1dtk2wGwfR8oElLfHhKziwq+cSElD7F
         KiW/v0NZLhskeXT+BNPDTVqekT3OL2tfwf7YSpLozL+VAEbz7ePPXKrI3rUBfSFURW+d
         W91poW9MoO1bLi+tU/1lCbjo1QD0+Ioi19wC7ZjWZlq8CKy8yoJDu5tIns0xKUmvfnhH
         bzKi7YWjsczATubUARknbuDEItaQw/zFcP5y90Sv1fQIFsZqAwOwewtgzhPpiZ8V/zNO
         QY6seBaVFlt4epYVm7ABEnFN2X2tT1b6ue7cmNHaHYWJA1lg3Jk8Ro++t1D2jZTr6zaB
         KzbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=CTYHoP0YLdX9n4ah2WXy8Cotp6WL85QapjCwmKTSCQ8=;
        b=OB8V/RAR2DPyP0W14AoTTc9Za1/czkQT0maFWbov4a2FGWXW5GSKtcg/S4YUvA71pe
         V4JS7j8k7/X2kBV6SL8UIIQZaiS/rtsL+uf2HmcmXH0qyZnFfGbLl0nP7R8FBN0YG8hv
         ozkPGYqYsULN6tCtrh8+mSM/VQTr+LXDYe7huFhsbiPSTlvg4TTvs2bEWzF/J89HfA5s
         /CZvDA5ubGVc2PJmg8/uAiP9f2c8TDfGbILZmtKcTC/wm6urIQNBbd6wOoJYWWwbeLjB
         rVFOaTAc2FmPGAPmsdrVcCoW+h+E99OZKePs/rTCWdCZnyw9XQJPXJ+le35MYS/TRK0F
         rWsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tsvxfJmT;
       spf=pass (google.com: domain of 3ongaxggkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3onGaXggKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CTYHoP0YLdX9n4ah2WXy8Cotp6WL85QapjCwmKTSCQ8=;
        b=mDFEWxgTHp/YEVJWWW+t7UVmzTkJwd1lHT1CKNtZEuXSwlfZlMy/ZqGY4ozzwAa9Rc
         D1bRjD7ZTVqHc0DphoUye76clH7o01eS2wlEKbHgu1YQiANcT0kjZzoe8+SQR/gVeLEw
         j1uNhOnb9V4prULjFPi+VtZ/4uz7rX+U+vfz7ED2ySPx1X9XXTwT4QKvwU6CVoZHZT0V
         WogWpRR1IPZloAXOxuZGJap+qzGrUVCM/7oaPj/ton3Js8MKsmW/oFnkV2tP4ehTSJtD
         AlY3c6M8DQUB3eJ7LcjBtLLXJZeKaoSF0ebLft/7lkWW5bi4uGXZyuFJDghVI6AuJ2Xa
         QpAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CTYHoP0YLdX9n4ah2WXy8Cotp6WL85QapjCwmKTSCQ8=;
        b=K6Tsh9X/hDrjaar+T6UYtH88YGCPs9eeVdIJfTbfaC4/43cCaXvChozM38Tg9eqlb5
         6poK81NxtT5hOHmSJJ2PQ2/yr7rfRQMjSHQpRCm/NciMgLwitjq0DSLAnr13dNRoPjve
         2kBWC4a4SH2gHg7VAcXh9wGm07dTcy+8nYvYXBXluGH+kzghORxd7uVU4BEu3qn8ZdJM
         ng63XtLgX79NnxVSeaC3Dee+oiE5PmBdnlHaLKPgN/Z7IKyyiiA7AnFbOEo9bMJJPk0Z
         Wnjh5m6OtjC1AmxqR2YcPwwH9LkEjyJ2aPl9LGis7cRSbFMwQcdkq2QC43j4WKLwdozp
         iyhA==
X-Gm-Message-State: AGi0PuYy+V6AmnT53RKrPQiqns/tP+XCeNNjSCpXOHsUeVuBfOAaIDHw
	LqSORlgPasNkPA/klnk7xFc=
X-Google-Smtp-Source: APiQypIwbAP7JVzyyE8hmHD23ivL9v+NQURHjyHMkWvgCEPqGXgO6PXrLRZFDhu/uuU1DfuLNboP0w==
X-Received: by 2002:a9d:37a6:: with SMTP id x35mr1654298otb.280.1587179939779;
        Fri, 17 Apr 2020 20:18:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3b23:: with SMTP id z32ls1003243otb.1.gmail; Fri, 17 Apr
 2020 20:18:59 -0700 (PDT)
X-Received: by 2002:a05:6830:1cd:: with SMTP id r13mr1616075ota.231.1587179939461;
        Fri, 17 Apr 2020 20:18:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587179939; cv=none;
        d=google.com; s=arc-20160816;
        b=tayvGIzQwgGZXenu7/d99XyOxXz48BQ3Tbx+0AScyTefdoVtCLPyz1zvJ6Xp/vIxMs
         qKS1xhXF7ulsgMY0teiTTaDKaVcR/ilT0D5ao7UZN2T5tDO9pIE/fw/pfJKLBnVuj7ak
         WG+OBEkbn/tnT2gu+3n/zO/3AqVdo8LxMBkbOR0TGh05mAz99o0WkyBlSLCxO2y2PGeE
         zym3HB/+oNcMTqPJDVezqswmjIG19FTUQvsTugF9Feuen7J3zMZZCX+7Wnb8CQP1dovZ
         uNaJFViQc6Bvv+aAe7FxSp8UaztuH6WLlhmskLXCDHVVUf2OvFMwBhPh1FGt0tqBa+al
         Llzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3docRvuzttJC+Wkb9Bk065FrkPZtq4zMQ8pW4rPpfW0=;
        b=Z0ezRd4szlk++6GIJ6ZunPNV6xFNPvtxY/6b2TwQNYPjwEZfzX3cdgqKtG75AxJOZN
         RGrlSw7a5Hdtsw1DLcNVVfXSg6HGL66gGRg26eKIp3dsfQ32vsZq/ETiJpzJv8+USCCG
         Pn11XrriXHiLFiV9Yz7Rz6a9i8yFZESKdoGd6k9Q0nmFqzCdtTN+ztP8zMzdhvsnmmEy
         YK4C02Bk1W1Zx/Bo1niyyCyt4Ed+NsPfeQELswaXZwsZPBW/yaUF1aVcGaibVpxPm2KY
         a1csSa5yko+5DXA13yrKRDfZQSycfUOn2NuxyPS/fiBfZNhvjligqCDmv1Ga6ucQnPRB
         i9MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tsvxfJmT;
       spf=pass (google.com: domain of 3ongaxggkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3onGaXggKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id s12si1120282oth.1.2020.04.17.20.18.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 20:18:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ongaxggkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id x6so4112061pjg.5
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 20:18:59 -0700 (PDT)
X-Received: by 2002:a63:f64d:: with SMTP id u13mr6075605pgj.151.1587179938644;
 Fri, 17 Apr 2020 20:18:58 -0700 (PDT)
Date: Fri, 17 Apr 2020 20:18:33 -0700
In-Reply-To: <20200418031833.234942-1-davidgow@google.com>
Message-Id: <20200418031833.234942-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH v6 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tsvxfJmT;       spf=pass
 (google.com: domain of 3ongaxggkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3onGaXggKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

KASAN errors will currently trigger a panic when panic_on_warn is set.
This renders kasan_multishot useless, as further KASAN errors won't be
reported if the kernel has already paniced. By making kasan_multishot
disable this behaviour for KASAN errors, we can still have the benefits
of panic_on_warn for non-KASAN warnings, yet be able to use
kasan_multishot.

This is particularly important when running KASAN tests, which need to
trigger multiple KASAN errors: previously these would panic the system
if panic_on_warn was set, now they can run (and will panic the system
should non-KASAN warnings show up).

Signed-off-by: David Gow <davidgow@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0c206bbf9cb3..79fe23bd4f60 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -94,7 +94,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-6-davidgow%40google.com.
