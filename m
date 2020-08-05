Return-Path: <kasan-dev+bncBC6OLHHDVUOBBSHLVD4QKGQELM2755Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id ADC5D23C49A
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:30:01 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id t83sf12059777oih.18
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:30:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601800; cv=pass;
        d=google.com; s=arc-20160816;
        b=MyfY1K3TyIQJWGj7rcPsO33H3f8+GgrnfwHT/e+3mwgAK6ogk8lizJ+ZGj8lwIuIvU
         oXor+sxBtsXVSriSlaDqq9ypeO16bKrTsyiiq5Ugqoc4O/aqFQbFKk85O2cNlO074NcM
         a91hhQAA30GKrwYxUTXmBDjvMV/jQsKUU7rAVv2tzIqqcz5ptoPDKzCzMhvjwBRnS+Wb
         9suOVaIK4Oec6DUVPUtBxEaJSQs7AkJQQCpdFh+224UygjEt3YhddUzZYxYjDJzfH2UW
         rPxnMP/6HCvUgx4pkHB9Pp8WeRDthMJ3oXuLG0u93mOI63mNGm+h72nxAvsi1guZh3Kv
         24EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wrCv7oU+SwJuv4kVawGFbY/p99z91aBH+2R4KYUU6vk=;
        b=B+o28VF99jBbP75djRSv1N8WLhZjHQWeLuY9SzE4JtUdxCxlajs3Fb8uesorO2OQ/5
         iVmDHyqgikqYLMv5445V6kdR9tCe0TJ3RRHOghk9f4HdS6KHS8TpN9cBB3uQgJ2LGst1
         /C6ujJMpxETPBoY4OUObBqtQzBPQ0v9/RHN0q+WaHTxIdnEuSYmGNYzyRSR1bC4JLV71
         kOMosOI26YrhBX826xEHlwSXe1U3Qan48Yd9SB9Ueev9Y1gcsbV3XSZ8OYG2KKoLC4DG
         TJetUkPxsUbAesLwLsQ/t/jO3aRqDQEibYmJH0Ap3uEaEZcbbU8v+s/JGgSSwCE+XOCD
         gu/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OtjJ7ZSO;
       spf=pass (google.com: domain of 3xzuqxwgkcdo96re9cksckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xzUqXwgKCdo96RE9CKSCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrCv7oU+SwJuv4kVawGFbY/p99z91aBH+2R4KYUU6vk=;
        b=EdoUiVprXAK/q8PRB9HkSPubO2HF343H0MKwaj2TsnXyBvP8dyfUMo+wd3xTxKwmI1
         YuUFcfO/Pc4b7V4NlloLNio2I8qOJDqBViZHJ/sAP8ImuG5qUqWSi646SNr/Ic8y8sKh
         2Q0sl3QOdR2VPdFqGTe2O8WBQn05qA9hQMuDUsleqNdxwJYqyZ2xbrtsZtvKgjUnvFet
         SvklmAKznh+wEEWCmMr6uui5aS8j5TvNVDMp42oQAIcb4I1u1JR7cqLP4nXe0IYD9PI1
         mI4SoXmVS9qzmUqGTVht7fNZfG4pMAOxrewpAfBlM6ksRBvchHlCrk3RiiV+SlKnv4d6
         eFig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrCv7oU+SwJuv4kVawGFbY/p99z91aBH+2R4KYUU6vk=;
        b=RicmVqVQxk3kgUY7dlRiNQUOppv/8MUQb/hbBMIi5zTJSIWLLLzzvProXL6/OC1wze
         sAzUHedj9itqU7HcHVFBeDGIEZ9IfH6LW8JjM4orHjOhScZIPWv8anm/XejcdveV67qg
         HwQRn1G1UnmYKZb88q/Evp2sqa0Lzk7omWqWV7aN9kqlzkTYQ65X42VX6aOZ+Qoqcj9c
         uoJTVzVGj1/lmqhEKyQGTIS5YbwzdIOhYn+dMqpWDLhZPHWfmM+p1rWJMFkb79beGPBL
         UDCrPkPXKK2wTj4YRtREuo9gh6YpJkM8ox4nnc7fq3c7waIFrufn+qNzHa1ojpwARRyP
         gqug==
X-Gm-Message-State: AOAM5306ROnD7AEE2D9bE48JfqIiCbyY/fk349ldaorYyJMOBnkD6ItM
	QhRVBMPT8nwdblIkzJi/6Zk=
X-Google-Smtp-Source: ABdhPJzxwDrIkil0HsGF70F6VjATJGSCRntgEv/3AEk4I4WcVVzW4TH5WI6du3v7vaN/5oi2IU/C4g==
X-Received: by 2002:a05:6808:2d4:: with SMTP id a20mr1251370oid.151.1596601800728;
        Tue, 04 Aug 2020 21:30:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:546:: with SMTP id i6ls157035oig.10.gmail; Tue, 04
 Aug 2020 21:30:00 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr1378000oig.70.1596601800363;
        Tue, 04 Aug 2020 21:30:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601800; cv=none;
        d=google.com; s=arc-20160816;
        b=UH6KH+wdmEJ2dE+F+30yPQBq63ltn1u5Ho5c2HaT3Za/W8C61u2Fj8ysXoMvvuSz+V
         DkWkiYL0wVuiKK/rVz4Xrun3Bm3cZSQHFQXwPfr/Ge8S314f5b7UGkyEWGE+yCYOrzQo
         RdWNPgTFCUPYBpQ5pOEhigqUdvNrdeutRVnpkLO7KRTBinTDALk7altSjFL9r8zIFJoz
         tzyhio0KnDy9+pt6LbqbjrHknDPIxsJqUyY4oSaDVEILY39YIhzGyUjvxTfIfD8C7N1f
         ltibYTQvyyMxY+2kt3D8bYt+TECRApFjn/Vuk510yYP3r3Hz9IxJedIlpC5E5oNiEqK2
         /puQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Y00REmw7cW2Ho0KOM1NABcGJpQIr8u0gXHD6A1O7ZXc=;
        b=uWZ3klLiDCjsEoZR54osZELUcgTMUTRoCMcSZ3GEoRr44LFDlDP1GbIsdBsbBoDr/6
         D4H6FL3gwMCBcXxrzHWFlo8JG9pi+RlgZ5IDwVDIE5kuYw6miqt3p4PWtMqwQXa7INc4
         d2zdqHJSD3qJvzkvwxzZIMEgtLqe6w/dgiZW4myP44wwKEi0zAfYAzSjh6on1mcucqK1
         t25lh9Hw3vZYQ07kxt+3CEzELol7jAQu0XAV48e43/P2qBqj5U8bB6ympcQqI+LqdQ+q
         QHicbSdG7lS7M7C4hMFjc3oHhALsLzpa4mVlScQoAeX8dS/3IceELK4Sdp3cvnErjSPT
         PKzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OtjJ7ZSO;
       spf=pass (google.com: domain of 3xzuqxwgkcdo96re9cksckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xzUqXwgKCdo96RE9CKSCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id n22si98375otf.2.2020.08.04.21.30.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:30:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xzuqxwgkcdo96re9cksckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d26so22707017yba.20
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:30:00 -0700 (PDT)
X-Received: by 2002:a25:8411:: with SMTP id u17mr658207ybk.95.1596601799856;
 Tue, 04 Aug 2020 21:29:59 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:38 -0700
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
Message-Id: <20200805042938.2961494-7-davidgow@google.com>
Mime-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 6/6] mm: kasan: Do not panic if both panic_on_warn and
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
 header.i=@google.com header.s=20161025 header.b=OtjJ7ZSO;       spf=pass
 (google.com: domain of 3xzuqxwgkcdo96re9cksckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xzUqXwgKCdo96RE9CKSCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--davidgow.bounces.google.com;
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
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-7-davidgow%40google.com.
