Return-Path: <kasan-dev+bncBC6OLHHDVUOBB6HXQD5QKGQEUUJCXRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 39163269CBE
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 05:58:49 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id m8sf542818otf.23
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 20:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600142328; cv=pass;
        d=google.com; s=arc-20160816;
        b=B7Uhhm20ESJ4RtmbZRP3nunJuu9X8dRYwXENsmbsQ4B46LT2RiX7+OEOEu/0zsg2Hh
         TQ7go0e7SUf8Ag+PVB6Vg1+vF8bCe4ogVGl0EmVrH+VlYW0UtNHF4yxLFYiXIqXD0iFW
         RXQQ/v5c3S5h/UED4xLXiWizMPZDzcQPQdeCyLlnp+ZASzYUNp7cNF4XdrvGRQ2ALZHV
         2nykgyF7RgYQrqvVnkUqN5hKXBDbhAIRoQJ/qVZUAzFDIUNSiBWN/D57ymw5RY9q1J4F
         d08+ZOpHCiT9vZD3uZKK+Qsh/gy4UkigIQ7MMtQVpsCe7bf4oTgiOzw8HXvSM18iRiss
         sRhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Qq64t/6ObBF2F2a6COzJukVxu02x+0fiGvYg7/HaSG0=;
        b=hAtSe+CHyw0p8eZc9o9fHPMH2cUgz1kTydx0v0WiXWbs5vWUoAMAf+sRUHcDhN8Ds2
         uhPIMgwofwyV80Rux1hkLlP/HowvsRTQ8Lv4hSXKriGcF4yZbwQY7yJVqYw5KE6ld4Le
         VrDGqPngqS1nZPYzZ5kZ/GW3GTLP4pASr8tT16W98Tyg6iF5WsvsdmKaBV5X9dT8JngT
         pepPZmGh9ZziL5BpVAECmzfp8e5bhRwtGCo1HVu4xEIBm4ms2VlWi4Kqa9ImPwmFfxMi
         UCwa9luPok6QvupHKgVuchQNgWtYERqKneCVNUOQrpLgYQPOpN4TGmcu/dSQTsoVh3MX
         ozpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qg6CHZ5g;
       spf=pass (google.com: domain of 39ztgxwgkcfavsnavygoyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=39ztgXwgKCfAVSnaVYgoYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qq64t/6ObBF2F2a6COzJukVxu02x+0fiGvYg7/HaSG0=;
        b=Gun0jxXTE+65tVmooYWiHk7aG3Xjl0XRAME/Q9deYytCjsdJF9+IHqal4GygU5NOIb
         Jnz2rSSBOXm+5ocll5Pby3OdigZJKu4zN9FHMMQ5dft/HuVP17wWEjHH5V69ZDbYI7Uh
         POtKoEcFJhd5Ioa/vbQUnJEV9nTMrg9xPPNfqmiLt4mBPZf8TN1d6/g2jG9xEbQ/lzHb
         NpXbZcQsUl/1yRQuEZn/KGgsjOuTEr3ISJPJq0Kmv/YaZiy7k0qf1sKDJIQGzqhMel2m
         bm0vDgNQWWsoDhLh9Q//sSrXnAwNJKvEo2Xs2UdqO5kzBMsHIemiBB28j3XOAvRpgWRd
         Je7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qq64t/6ObBF2F2a6COzJukVxu02x+0fiGvYg7/HaSG0=;
        b=UWYGqi2PcWn82WyY4kCMTBkGWjaMLur/zVnJhsRaIbBnOWWqaTIQfMb3U5IYjROTVA
         jhVM/07sVeHqFOlmrcJvZ4XEl1cj5YVgfFDxqe04qCTI3cVpnBcJw8zD9lAlpZt9Q3j0
         znKRWNsDcLX6vW9KYQ61W3AKrFh6Wlus6UiBgWXE+UocrLSpzuTt2nXnkIGmeSsgC7QC
         Ly9d5Lenz30v2zRDw/YHB6SPUMxo0p45BduWVnyDSq3iCB8rZfAK9i1yJJ/899rn1Dy3
         EvDVHNDi2kxNWjXAfwvJFmmfna883EqoW7ti/RYpVHa8UDj4KNtS1uHRWU5KtFs3sZ8j
         AThQ==
X-Gm-Message-State: AOAM5312I7iZ2tSuDpwl8NHT+sXZd/WaJA7IIkohFw0BOHPAz2FxueH0
	+G8MeLpG4ruy3llIF1ujav0=
X-Google-Smtp-Source: ABdhPJy19ka+YF/ulsCIowuDEr5cGxq2Sb8VLLdl7R3bj5kf0kicHToDDQ4tSlaTV94I31Tl/q/IAQ==
X-Received: by 2002:aca:4fcf:: with SMTP id d198mr1934242oib.83.1600142328090;
        Mon, 14 Sep 2020 20:58:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:72ca:: with SMTP id p193ls2556102oic.3.gmail; Mon, 14
 Sep 2020 20:58:47 -0700 (PDT)
X-Received: by 2002:aca:4c09:: with SMTP id z9mr1936102oia.175.1600142327684;
        Mon, 14 Sep 2020 20:58:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600142327; cv=none;
        d=google.com; s=arc-20160816;
        b=nFql9gOTzzD3ilMN0xdQ4FuNdPNK/EmESg3UlNAwGjPwc1W/mgc5Gyx7HJq1jvwYo1
         M3KYKizQku9wU++K3Nhds02XdYUv3THRlf7SZ7+9u3ozzglVhq4mthbxvJYfml4GFlVZ
         1663SoyksK8DVOVoCQqUrihyAvVE0l5ICzlLWrezuSn14o25/SdI6HyjccRv2ZZBwxoR
         Y4I9PQixOhHEAxCw9tLSfINhDJPhOzIz3GzIfJpCr7e6VGRXJcsmi4ypNZXMlaQIfbJt
         8+yBt+2UmSbUzJJFQURQvaoKbr9p5jmVv4NR0Ff4v4/dcasrLkSM7FrsKQhpP2qOVkot
         DhiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jND5K7nrTIUr/jnKohKbWFO0ev/Az4T5zj9+dc82ED0=;
        b=qmOJoidWU79NujF7qhu//u6jer3zunEczOD/qfpdcMibNMpyZWY6qtWZcj/B1ccMbc
         geWL53FnB7S4JNQXKkUleAqnHwjQm2HTb+C5YdeS1WEdeW55GfxCUbseFtYA9qBkXmvl
         UqrlobauY/d44EdGpD3yKz3ZIoRKEZLEsvGqzUy4Qpf/012T9WbanYnlhu1JeIQFWf5K
         1Aada9ARAZn7ztn1TFRQtbEXuVSIWdW0ksQVpGEBzSrGw0uBrdmy4wP9N0kQJWFPPaqC
         B94oNk3Wuu9XCLH32m+44sNaejdUDH5+kxS4I/VWrN9P5SyAIobe8rBvTOvZPRi09Iph
         hwWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qg6CHZ5g;
       spf=pass (google.com: domain of 39ztgxwgkcfavsnavygoyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=39ztgXwgKCfAVSnaVYgoYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t74si889199oot.1.2020.09.14.20.58.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 20:58:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ztgxwgkcfavsnavygoyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k3so2107713ybp.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 20:58:47 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a25:10c1:: with SMTP id
 184mr23945299ybq.407.1600142327208; Mon, 14 Sep 2020 20:58:47 -0700 (PDT)
Date: Mon, 14 Sep 2020 20:58:28 -0700
In-Reply-To: <20200915035828.570483-1-davidgow@google.com>
Message-Id: <20200915035828.570483-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200915035828.570483-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v14 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qg6CHZ5g;       spf=pass
 (google.com: domain of 39ztgxwgkcfavsnavygoyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=39ztgXwgKCfAVSnaVYgoYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--davidgow.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e2c14b10bc81..00a53f1355ae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -95,7 +95,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915035828.570483-6-davidgow%40google.com.
