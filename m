Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMGV26MAMGQEP43DZDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id A01305AD255
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:20 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id e2-20020adfc842000000b0022861d95e63sf717452wrh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380720; cv=pass;
        d=google.com; s=arc-20160816;
        b=qvsekfzyGi7egiCa/K562th5BDnJ0Z+HMmMrEJkJMGccNXlPRVi6o4vPwo/6QMvyED
         JfoAQVDnsjI5TvZ+QqHBGZX/kkpKznURxmH1SKA02SX5oe7aNbnqjSX8R/xNvhXKzRsU
         fwtjOWDzbfRW7Mjl0gI5WB3vF/ZyDIeEHOgTa7QstRsyRju/Sw9J2/knyH5y4erShyCH
         HkYW6sRCOjzC6rmtMm/513QOksIavOyd1ARoZs61tTWyILjrVCXHk9SNUInYkjU/w3nQ
         poY0mHgalxJrz9kbv5+1l617s839D9z8C4glYbgaik2B+Z+8lXc/qNu26ANO2Me1FbP7
         HgoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SWvQRUyaPuT+uC7DDtfgXkMoRQq3nVF8D7JJB5mACx0=;
        b=S73ETMCjbg8GkdpB0e0Mgv29EZ5pjMGpN3O+wpt+BavEcjk4lQPOxd5Y/VV6S5jbjD
         xScQvrxg8+IKGXE1gHps8/3nIHqZSEbzconIY6O2YaSsVWYjmzxEkR/HIoj88wJusHm4
         DNg9LAIOuAhI9ItlDB0utsyvAvvwuVbuHYAP24kRf0BA5YE62qTc+/AWAXAJNMC3O6hQ
         2RkblKGDEimuQgHgP4BfzjzFCayMldNn+GnfDM1PyCCgu2eo3ldyGJsYYhqJ/aAHeosS
         sn2q5zG9cGQzEQg44hkx4FgR9RQ/T23B6TQOLLu1Pnd6fgaRriy7g6ESePVybPqAuDAv
         RM/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SLwXQbzP;
       spf=pass (google.com: domain of 3r-ovywykcfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3r-oVYwYKCfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=SWvQRUyaPuT+uC7DDtfgXkMoRQq3nVF8D7JJB5mACx0=;
        b=msvRmfM/TnQSHXq+H5X/WwDxroeLvIXd/emxCOJ3U+iCeiq89FSfVB7BVRsK5RZUTo
         ctHmJCUR8+6PXC5niDL5SAKPC4jzyVfnBamFq5J3nYdEbZRb1uyaav878FqN6uoBvu67
         uDbr9vBiXrFPlN2qxU9P709tmO7qreg5FSC96mdO+3SbobSAN+mLRHUGCjpGeTpybind
         pGwNkB5yw4K5h+ENNvjAPLQFVJSRVllydKRg5nW3qZxjglNCfQB71mGta3N6ueA0kne+
         TnRicpA30jxGCR+vei4/UH/3zH9KVV1onXv089QerytRumed1ZBJRjzQ3kJlj3V0cEGY
         5M4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=SWvQRUyaPuT+uC7DDtfgXkMoRQq3nVF8D7JJB5mACx0=;
        b=EcGQm/YWOwJNXwA0P7K/L+F8adL8FUIR5ttX3GGb2xjJrjTz3HFDSgKu6TsLYh0bl9
         NukHnxO8FtyvIjLGwVFhcyuNmziGiTE7bwonfNWA2dupEO6ihbYvqzhevnOjt3SVjnJW
         w9ovFFjpsXPLCJlgujNg82R+Tvs375WEnsQQz33e+TWFZeIH3H38TyGxWoIDaq2KrLxi
         R7GI9S9hgBx582VLpjS7fEkPzcR7zYZSiwuSRDJXj3F6SSng86vrGV9Udi10tcZqD1ht
         q25+8vJqPleATA3YqZvZ2SzPsihK5dlNCBrLZPJRUO2ICa00M/u0m9zFLe15ViRM7tDx
         8kRg==
X-Gm-Message-State: ACgBeo0o4SLypngMu1IjVFDWcGRzh0GNR2b6uE7tgq/9gD9bICKM5gp3
	rktUYiTfVGMmTlDTpQ9mtCw=
X-Google-Smtp-Source: AA6agR5hUNkQ47Sa86S6tB1HoKKprgb5DCz1jCoq1TZwmgoXoWj0a9wrtwzHZi4qtyqLHg4Ka6NywA==
X-Received: by 2002:a05:6000:1090:b0:228:a963:3641 with SMTP id y16-20020a056000109000b00228a9633641mr1772981wrw.289.1662380720221;
        Mon, 05 Sep 2022 05:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:257:b0:228:a25b:134a with SMTP id
 m23-20020a056000025700b00228a25b134als3154934wrz.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:19 -0700 (PDT)
X-Received: by 2002:a5d:64cf:0:b0:220:6d8e:1db0 with SMTP id f15-20020a5d64cf000000b002206d8e1db0mr23270650wri.564.1662380719379;
        Mon, 05 Sep 2022 05:25:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380719; cv=none;
        d=google.com; s=arc-20160816;
        b=N4PVDH7lfFDvNc1B1TajbXzwJc0hiZhet1/VZZfwVxJY0NajsRm30Z0uxdYWSQ7gd5
         UoDPN2wy/T+w/Iz1V0YLtMPZ5kuinD6WOMr/ZfnKUjJRl18aZU0rzUt39rIxCachxToG
         9QSC5D8MaJyyc5CShrglpRwDSCSdDgTo4taR4ac0e4xAGBFmj/+vuplkEEz40l3ny2SI
         f5vLu+xdkv8mQfCmnDPymUqyRA85CCi4pchSVXFJndKPJXx9b4Id6qFga/5mpkip05hG
         lnkctmX6y8xzpkw/OjUsrkA6/swN54tuB4dQE3EAP8PxSU2gT7d1yY7EME0SWzoCNSSs
         jcoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eIK0S734s+WuMuzHGxUrnoQabUzsOPxTYvMm/ke78tI=;
        b=yHxxIkUBQID6GnfVepMhBGO4C3Y10IwSD7uGapM0GmeL9BcLNeB/0vjSYFvPpEivoM
         yLnwYMNci/8591U7QWm4VKu+TVjYgU4PDGcgEsi8XQ3u7rsAWB0wbXcgJGsgIe7q/Z9G
         3j7BHCsbNS4KoYrhssLtN2wVLFORCsQkgxrivpa/3Nr4/Y7S3MqUVh67Lz3zURO0V5aQ
         JfVUUh9iXA/W/yjUgeRGQ84e8fBjYEYkxozq23L2Skwop43aNPxmbQVnpnxVtb8K/ZF+
         DFn5QYovu7alder3Po+jUVZrC63lFPgNvprcho2CVdY8N1tfvmuW6ZUYvJ1ar3H2E0EY
         I4Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SLwXQbzP;
       spf=pass (google.com: domain of 3r-ovywykcfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3r-oVYwYKCfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1178476wmb.2.2022.09.05.05.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r-ovywykcfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t13-20020a056402524d00b0043db1fbefdeso5710767edd.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:2937:b0:44e:b578:6fdd with SMTP id
 ee55-20020a056402293700b0044eb5786fddmr722840edb.159.1662380719065; Mon, 05
 Sep 2022 05:25:19 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:16 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-9-glider@google.com>
Subject: [PATCH v6 08/44] kmsan: mark noinstr as __no_sanitize_memory
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
 header.i=@google.com header.s=20210112 header.b=SLwXQbzP;       spf=pass
 (google.com: domain of 3r-ovywykcfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3r-oVYwYKCfoinkfgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--glider.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 -- moved this patch earlier in the series per Mark Rutland's request

Link: https://linux-review.googlesource.com/id/I3c9abe860b97b49bc0c8026918b17a50448dec0d
---
 include/linux/compiler_types.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 4f2a819fd60a3..015207a6e2bf5 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -229,7 +229,8 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage
+	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
+	__no_sanitize_memory
 
 #endif /* __KERNEL__ */
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-9-glider%40google.com.
