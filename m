Return-Path: <kasan-dev+bncBCCMH5WKTMGRB24G7SKQMGQEZHMKP3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1004556350E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:40 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id x7-20020a05651c024700b002594efe50f0sf506436ljn.21
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685419; cv=pass;
        d=google.com; s=arc-20160816;
        b=gzkqzY0NOQ8J1O5oLE0i7BgjvVmpJEsJiXlLtFO/0u5KnunRnaTEh7L8rqKUuhBwC1
         CayFHHcp5g3X5Tc5us+6zBkSfytqi8oAHeCAog/LekmCs7dACDHIawHVDcuT4i63GMBR
         pbPMFJ/6ZKv7W+m3JLcn/p7K1QFExeScnLHqUfXPpl0+w72n7Di6HVwyMkfDyWHdO/1R
         ERkPu4Di0a4bSQylw2Iy3NkPUS1Q5eA/kQtKFIppzbPYSSrX6zRNcW83zrEgB5/h9d1F
         O25p2djn/l01FuXs9prMeh0+VXpL+pZnlTwIAWA3msbjQ+w3lSwPa8oDXoRQaLRVcsY2
         dwnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VpWNaQpPbvrTOI1tj3gV0Fktr2YktoYjLoPywQDNVRk=;
        b=gXJvnMh8MpS9Is5tWD3MEIGK5li5pX9lhZPiWOJG3gcISkCm3N3PEo9t5DMurmBYgd
         HlShjWljVFPevP1VXChXPK6AgGz8pLwH3MiKxNBCpiX6aWHepc5O2VNHrVxJZGaHeFjN
         bzgD0yB5TVVe/j0cz/YPxxF9C7We7WyT3ItmbdXa2jACnhhwO1do1HjS6g1tUQWUPSt3
         +amNYYRiHRVcO0wkZEjrhGJL7UWUVPtPefVYfmK84OnQrAJ1YINlUxcn3a07yj6M+R/H
         hkICdjsk/UjFSmc/lMfCga5ysutCpPVPNcgANDC1NjoX7Fe14Qct0ACC7Sc1R+VteeoY
         cIOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OV7vbBje;
       spf=pass (google.com: domain of 3aqo_ygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3aQO_YgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VpWNaQpPbvrTOI1tj3gV0Fktr2YktoYjLoPywQDNVRk=;
        b=nw830FQStJ1xGdnlsPSnabVt22rVy8vXevoFzz+5HT/+vzjLW5DCrq4owxysbcBzjW
         MiV3w0N2i9amYoJ3n5vlfviKwuY8ANl3n8gbTeynSoM0SjkYxqWifUGIgkilsnrtEOiO
         vqpJiMkf+ndLHiG5ds+VeT2jEla8ogHNRaFX4DVlcAfIU7UFjcRPCym8hwYU8aVJsfCC
         jXEHQ0HO92y5HWVtk1CABdX3K6m0WQKd9QJuH5L0eTrzxRUD1lfrRLfWpXOrAIPR9278
         a9JNAdghX0aPyAHqmpAuqP+6S5QqhbcdQfwizvRzcCIfvy0Dlw5LynMa12qW1LE/ygfp
         OKyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VpWNaQpPbvrTOI1tj3gV0Fktr2YktoYjLoPywQDNVRk=;
        b=z4wClD/30CosbOJJOnbXRe18PT6WKKyOEwNzoTy2A2ruYxk56otxwEEYNkfpaxy8yX
         Jn9zvVrVqKT7s2fa2C63cWjhWliC5y0ZipTfM31IXzVtv8DmnJaXVoKnqcZR/ESF+aJn
         0gzun1jEAU8559MOEUiUmkbFgFXkxC2r3pVjCB2B9YQcAd7aBTSR35hvVlgzmgLrm08A
         XTMoi9jUFnnK5HkEA782SpKmeIC9vMV4aSnWt0g1teyOqH1OhDFPsQGWLIlOdxPuiRdf
         ThBj2d/UOXLlY9KIkqWgRMAmKkXcZJuoD/EA3rLwqJxj0mEobRc23p8B5olAqvE/Aq3G
         ++xA==
X-Gm-Message-State: AJIora/RcHqDbgoCp1b9QhcaAQZ+ALDM9NEjWk7W4JMdlZIb0AhcBMkx
	L1iPP4FELIBYbNJ4Cgflot8=
X-Google-Smtp-Source: AGRyM1sgs0fMnFdmjLowvlwhapKlgD2GYgqh7EcK4PiBPi3hBtgR8RPGCAWvM31lsDEErFIg152Log==
X-Received: by 2002:a05:6512:2255:b0:47f:6591:354b with SMTP id i21-20020a056512225500b0047f6591354bmr10123953lfu.191.1656685419639;
        Fri, 01 Jul 2022 07:23:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cf:0:b0:25a:8a25:7576 with SMTP id u15-20020a2e91cf000000b0025a8a257576ls4615262ljg.0.gmail;
 Fri, 01 Jul 2022 07:23:38 -0700 (PDT)
X-Received: by 2002:a05:651c:246:b0:25a:3420:735d with SMTP id x6-20020a05651c024600b0025a3420735dmr8818644ljn.515.1656685418298;
        Fri, 01 Jul 2022 07:23:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685418; cv=none;
        d=google.com; s=arc-20160816;
        b=JwDbXiogQp9IEUw7F2WJFNYO0Q4QKeWa+vaOaeCyOWF+QmG1U2re2WilCORDbAMlZt
         O/8HUwWsYhlugl5cupSdC1AHfgtakip4u5Mry5pDA6DklRtfPt+CtpA+Ya1PA6xxEvxz
         mMv/3LIn9WZxi0NeewTElGIgKi7LDNc7VBFlvumfwVp0LJR4uYjGAgko+wQaOiOpUYa/
         gUVBQd70JGV7MaQZnN9uyN5q9KsTzz8rWB/remFxyygAc4FsQIW07h1sjaUz+erUx+sC
         tu///sa7nvmzIlLJXDZ0d4Ue70mVT7xOie8kThXy5IUh+BEF/wd0GUgSdVuZ1qNEV+Tp
         Veuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=os0Zx5VZv6p+Rm8I/hkYFMfJuZRHr+O61ed8WspeRIk=;
        b=yFwVgOVrumIWHbWHFn0CbQg+zOlH3jNtzJw8WwpUZORxJ7yPanqnl9YXycKhUTAD4P
         y5LE3r4Z1FZ5MOstIyMhP3EitDbUh8mfJua7mPm7u9b23S6Sh84ZGrhGd7uqC1jJcPPN
         AdkFCtT4d/jHb01U4+bGfkDidalfVsIuHWUlUK1JzSBN7pRbBnT5qCwA34PT6s3noBQW
         oCiMLmeGO8uclCp65aL5HhgJ6Pn09lkkPFnb1d+7hYb+qGjo4vnx7ZL+U00OoJWQJDs9
         xv3HF9uvgGSOi7pvLpL4kho7jlVsxFN6Bd6eUm60mUai2S/SKKJyK8Qd/t750zWOby6g
         1AAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OV7vbBje;
       spf=pass (google.com: domain of 3aqo_ygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3aQO_YgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i2-20020a056512340200b004793442a7f0si1008054lfr.6.2022.07.01.07.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aqo_ygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id x8-20020a056402414800b0042d8498f50aso1885435eda.23
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:38 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:4244:b0:437:726c:e1a with SMTP id
 g4-20020a056402424400b00437726c0e1amr19866573edb.107.1656685417915; Fri, 01
 Jul 2022 07:23:37 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:33 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-9-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 08/45] kmsan: mark noinstr as __no_sanitize_memory
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OV7vbBje;       spf=pass
 (google.com: domain of 3aqo_ygykcygsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3aQO_YgYKCYgsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

noinstr functions should never be instrumented, so make KMSAN skip them
by applying the __no_sanitize_memory attribute.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- moved this patch earlier in the series per Mark Rutland's request

Link: https://linux-review.googlesource.com/id/I3c9abe860b97b49bc0c8026918b17a50448dec0d
---
 include/linux/compiler_types.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index d08dfcb0ac687..fb5777e5228e7 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -227,7 +227,8 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage
+	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
+	__no_sanitize_memory
 
 #endif /* __KERNEL__ */
 
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-9-glider%40google.com.
