Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ6EUOMAMGQE2N3VYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B21455A2A84
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:27 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id be32-20020a05651c172000b00261b5eae43esf660377ljb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526567; cv=pass;
        d=google.com; s=arc-20160816;
        b=VXZjEQz9eQoA0Y+jm4p0b8zsOR0u1bBDd7+NRwRXXDqTHaGRK27UQy10Qn+Q6eUkOi
         FlkJmQ4l8wKo72wIqX2iy7vp7yydvuYomJp0qEIKoUAZetFAVhxdijnObsioQSezg7Fl
         ev56cXkboBtu5m0zf3Em1nQd+jQaEreGsurB4pZspvWhFuAw5lVJgYUxa4kVVu6zm2jO
         ZOt656cAK6UNIOZQiacRHJZWtpV7yxEPe9zUdeWNf9gJB6b2foAQUEyN58bKw+WbG4jo
         INf/xrxTyZyBMTtuNdZyVCB8oo9U1s0g6rQ5DKcqaLNqBH9o6vk3sqIXq+ArEu0s0bAD
         fwAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=H9K2jvgaPGPo4sWiDGEBViZUU+xxjcLwgH4+MGSqAYY=;
        b=upbZObKSj6c0dWG/UmIDUmlRBTcM+4ARA6xwaxIUUGA1LtToDaUrMInrbsJlEoLqX0
         ul9dAf3h5kROTvRC1ULVwVOI8SbvPW+GZNoLEW6jbnX1maeOwM/0k9IhN96X27T6Hcy4
         DXvtLrx2e9sT51AUV1HzP1oqYwknErIBo3TzJR0wi58LaQtRt6rbEuiaBk++37l8ZIBS
         Ba+x5wC1GuIGiO061C1Dc70mQss7Fk1RAFenFwyUC06EcDGpBSaRdbVUSiJ4hbAIaogQ
         rNqXzRUUDti4R9Iqy99cZti4gVoyWi+it/ztYXIzs0LhJHDBb6kqSWr7BjQYMpGKzxDm
         qefQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=infDBXfa;
       spf=pass (google.com: domain of 3jeiiywykcswotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3JeIIYwYKCSwOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=H9K2jvgaPGPo4sWiDGEBViZUU+xxjcLwgH4+MGSqAYY=;
        b=iR2XhYAV0wmGBg2KzqYUFNgGXKDaI2ej9arad4VBmiZXRCdtTn79SdUpPHhuD1NGj9
         wSiO1EftKdLxpwEVWSXLIsl9y+6vluvrbz5x6xBIe+idG8lAiRR9nCXwazRhANz0GdtB
         U0VGoH7u5ua/1yGZN7wzph/G3Mh3dz5yBl6Dd4O8FKTDVFbnvl2wJZ2n8PWREoswaciv
         Cmvgo0hgWKSAFbaFxUzusf3zkAI3k6y/oegD5Peuz5MdpW+Hhr3qAsPUQv36FWz5E14U
         ImwbitTQqtkyMaiFCTD0DHAKwlS5HtJACvS2sI3oTpP6auYMd+h+lqc0j2B8U5tHZc22
         IiUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=H9K2jvgaPGPo4sWiDGEBViZUU+xxjcLwgH4+MGSqAYY=;
        b=ZYFZS3PrHLqPaoX4swr9q1ev6BVHwllyNmXMAAY5uNeswgIZ89woYT9nwuMsboQwbc
         1wvhneNhyPTfrqe46T6220EjIWu7qZCvMUaRVyMjDSyEUBLQ1Kin3eiJsj2vTq4mNpW3
         teHvEsyqaQ+A9vWMc6F8TbXwAwRVBIBTmV7g6CScmeiYU9SHQOUU8InutqwVXmz4CY4X
         Xq+pMBo6q2ewqOU/01VGu84EG2Zlgj/a9X2JVLJ4mrpGp63obTZIz1KgtiJDx2ASqKs3
         r3IMaAOu7NwqjlD5QB79M3T2szNJwRkpdZ7/fRfUH5uj/BxNUjFj3t4ysez4mlOVJ5WA
         91xA==
X-Gm-Message-State: ACgBeo1LXUk09bufJDN2bgKuoYMoGJVwLJRbpVsUw6izuDs0Uvh9soW9
	ZCxdeup1E5F8qoGmrf9y344=
X-Google-Smtp-Source: AA6agR6c7NI1fbKT/9AvvpxvI1a055Gmc9/AJrBltAd8F//+dofzRyM/2F4xx3TUZBdGPRI+FxjbpQ==
X-Received: by 2002:a05:6512:1154:b0:48b:3020:b29 with SMTP id m20-20020a056512115400b0048b30200b29mr2518775lfg.338.1661526567275;
        Fri, 26 Aug 2022 08:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bcc1:0:b0:261:ccd8:c60 with SMTP id z1-20020a2ebcc1000000b00261ccd80c60ls708542ljp.10.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:25 -0700 (PDT)
X-Received: by 2002:a2e:be24:0:b0:261:c760:3839 with SMTP id z36-20020a2ebe24000000b00261c7603839mr2601586ljq.218.1661526565775;
        Fri, 26 Aug 2022 08:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526565; cv=none;
        d=google.com; s=arc-20160816;
        b=f3uJMaFYgu5FyrcYGZJFgNwUGW7GuK+ZUS4Y9Ugg1ZDOBs3qYS4Jnk/Ft1RCs3SWP6
         hIiCozl/2/xH02Nj5xSsvBG7gAcu3/5CP5/w6H5H6O5copyadfudH1KJ7WOXAdPVPRvp
         f2itqcSWH43Cz6/SO4O6yohrCpnYKYA+puxF8EBiCMeq5/0cUoITkY/E9+Cs4KTOr/kk
         Vi1wXBejHpWSjC45upc/7JP23n4wHr2BFXPIhd0tSsnItnsh9Msrk3OQjrZG7Yb26TDh
         BJf09mheTBoA4nQbyNgZRcS30j7JxL5XR3eJtRcSvjxvLcpgo1P/bPXP/cuHaPW9CkrG
         H73Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=78OHj/gzoCKqAY5c+j3k9RRp1IwnWy2nlunSdcq054Y=;
        b=bYv7cNoCwVdCRyEEBl+xi29vwnt4aRL+MUrY3x2lWAVlyP76sJXhjNv9IPyhqB8g4j
         MgV+1cA+15XdL/9ac3cqUHpOfufXwWcIZ+wA+rg5r32BpoFqUStjVi9FYbR/MAdNw/82
         +b6df1cmUHJPmTieV7RCn9xlLIokkl9RM1y9A7gHnBlX6mQWpxZ3bWMVULTvewQtWXV1
         k4FbZZ2y3oY5JQnW2Fm/MtFV8Sv+bWiRBi7+fyoL/BuGa/gUSO3At4p1BrW/yzP/8nMa
         g/8hKILbmgUM/xx4pYv+Lv7hNL4mZf/ykYs9zSd3yS2FXzC87J91FY2Uhjs/WDdAoQDW
         1tKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=infDBXfa;
       spf=pass (google.com: domain of 3jeiiywykcswotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3JeIIYwYKCSwOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id v11-20020a056512348b00b0048b38f379d7si77630lfr.0.2022.08.26.08.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jeiiywykcswotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qw34-20020a1709066a2200b00730ca5a94bfso721970ejc.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:25 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a50:fc17:0:b0:446:861b:ee10 with SMTP id
 i23-20020a50fc17000000b00446861bee10mr7463262edr.251.1661526565221; Fri, 26
 Aug 2022 08:09:25 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:49 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-27-glider@google.com>
Subject: [PATCH v5 26/44] kmsan: disable strscpy() optimization under KMSAN
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
 header.i=@google.com header.s=20210112 header.b=infDBXfa;       spf=pass
 (google.com: domain of 3jeiiywykcswotqlmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3JeIIYwYKCSwOTQLMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--glider.bounces.google.com;
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

Disable the efficient 8-byte reading under KMSAN to avoid false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/Iffd8336965e88fce915db2e6a9d6524422975f69
---
 lib/string.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index 6f334420f6871..3371d26a0e390 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -197,6 +197,14 @@ ssize_t strscpy(char *dest, const char *src, size_t count)
 		max = 0;
 #endif
 
+	/*
+	 * read_word_at_a_time() below may read uninitialized bytes after the
+	 * trailing zero and use them in comparisons. Disable this optimization
+	 * under KMSAN to prevent false positive reports.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		max = 0;
+
 	while (max >= sizeof(unsigned long)) {
 		unsigned long c, data;
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-27-glider%40google.com.
