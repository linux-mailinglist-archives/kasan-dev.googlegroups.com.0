Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYWV26MAMGQEV2K35VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D02E85AD266
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:10 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v3-20020a1cac03000000b003a7012c430dsf7396473wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380770; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1Gfkz3xh+XuWfTKqgHVYoDO8QjRiRhJ1RvOjjjwDW2FDkV4NyOhsJGZJyRGBDjzOk
         l3K71X3BzN7Yc/9t6pb8oUMD9OiVKzqiHvSx+MiJpBmn6GMi3wnWGXgIOhmIRl3ybLMO
         sarEBfSVMkwQyF/yRi7UwCLdP1wbGutH7zhibwR23E2ary74bo84wlR0zccav7MRO8aK
         0jkwYhGpFSNumXVFdY9WBSia2rbUK935NpKSHlPJ02IGHVXXo7zmQrIEggwhE8eBg50T
         agol6R2FFaWgpqd70Bqda4P1g77Ru0eRBqTBgmyDh5hXH6X/vD17NXd6p8FqCTcjDwBo
         ff7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+1bJE6bF1xUmvn8ALZvP8RaLMiX9Zc7Tz1KGYS+g7no=;
        b=zAVSjO1cB7l/RaM7j887VO0tGijAdDzsTYVDAEh4LIyPWZabYvOGTuy6kFvsb/iMee
         yYOF/e+aROcoks8lz9qBf30eJnAwAokAjOzUZBOo666fDXatZjEgTQ0S6R4GeOjIA1Ig
         i4zteSzbhMBW74njBUO9YYYxeBKVqoa0qjp4D1JJ8Tg3zqvfXOfo0ZGADgQ9lm6timHW
         G3JZh87tTvxPUcDLD/0NOFg1eGykHasIhT+Ali6DQdn6qoTWE5ZgUbNwtd9wc6G4L25I
         CL3xIspEbdtq+jNzClH5jqE+dO6ENzSWxiDSv4ULf9DKZpLYjKAtbbhbbeWUBDG2eTUo
         CLAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Rw0JSo2m;
       spf=pass (google.com: domain of 34eovywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=34eoVYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=+1bJE6bF1xUmvn8ALZvP8RaLMiX9Zc7Tz1KGYS+g7no=;
        b=qo5RfA4AIqG4ux5fACrApjz9xAmgegDMBGohBjh+wUxM2TFtNgWCfTdpI8Gm0bae7a
         iVlfbdNslXjZPwl9TBmNwn3ZSojzz78oMo+fvoyjXMwTy55YF0ewgkLvdIntRk9p1mSw
         xMSGEJpa4fXBX5yKx38ZYgJV9n5FMZ9IGXr2WXdtdAoVG3zVnJbqOeiMWwk9L0gbYcki
         wUzKzi1pdzbRkvVKKG/ed45N2GbAfDvIc/nMedgwsZmrwhtANl/Q8ZHoKX5exPoroPt4
         dxuWruGgOw7naBYJCbfww4VqKjSl2gJbwWB6EKwqDbXKHsXwy/piCIxqk+Yg7kbDrQuT
         3O6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=+1bJE6bF1xUmvn8ALZvP8RaLMiX9Zc7Tz1KGYS+g7no=;
        b=vsNPsmbVMcyjgXPr8s9ubGnnnFzyTwLhACbjFQ2i/RFYP5rN1JxO2p0JiWQZvvFcl6
         LsQ109AOCB8etEqFkrvpS7hEwT+vH67/0vn3IteKg+8gtj/gNlP/rcbFJ3IO+SD3rlgw
         6wa0JFUs9Mqr1w3dpWqC8mw6iK30wLpytqTLX8RfOG1p9qJiWDWpMVwKf9IlObH29OED
         23QnK0jmTDZi1XuS2J5qMVuuysetyn2R7egsAnxvk5mglC0nOl1PQUuM9/FOTDVvknhE
         wQD3LjwuN1wTUywqBtZ6z+gSIzQcl+xVIi/1OA3UcwiMe0zoVISm/DIw36rMzhlUKcBa
         u/RQ==
X-Gm-Message-State: ACgBeo2x/0j4qRHJUqPDSgbE1ImkuHiwoCwp/NtSl9ULscggfbfpV+Tr
	nH3Gx+ArCINs91+SfrljX3M=
X-Google-Smtp-Source: AA6agR7PEBFFCK6q4UQZJzlA5Y1TWhltlxCDYMaLxkuAGf0xdUyExBLFbRTZUxq9hH6k40UWJZWFNg==
X-Received: by 2002:a05:600c:214d:b0:3a5:ce18:bb71 with SMTP id v13-20020a05600c214d00b003a5ce18bb71mr11008148wml.1.1662380770517;
        Mon, 05 Sep 2022 05:26:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:60c7:0:b0:228:c8fc:9de8 with SMTP id x7-20020a5d60c7000000b00228c8fc9de8ls1533229wrt.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:09 -0700 (PDT)
X-Received: by 2002:adf:f2c9:0:b0:228:63f6:73c2 with SMTP id d9-20020adff2c9000000b0022863f673c2mr4097619wrp.554.1662380769637;
        Mon, 05 Sep 2022 05:26:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380769; cv=none;
        d=google.com; s=arc-20160816;
        b=gz/5HNd04j5XHBsiroONJ0q/RqnFInk9EWRfiKhKXvanD0SmXxgHOUhM3NuYLLAUt0
         5DpqhMLb336CjEJ79EpKUQz7Lc8nkQs0zcOCg5YnOklitpqHXsxHfhIXr6NCdV37D/Lx
         XGz/aOpiOnU7ipWj8wwP5A5UdBK/5+NHcU+feMOFPzf4ueGAs1q9nBiqVZn93bVSR1Ko
         yaEV8DgErWc46Xqk/6KH90nLcneB3QYuYkDpS5py27g9mX0ckKE5tNHx52wAm+dddtS3
         pSSHkkA00asP9rCMH57/eodH1+dkexe7dCgs3RodvwV11j6OWmInn9Tq/n8dB8b+88mL
         rXqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PRETZsLeKtd8er/vGZIvwJ67UbRQnpYPS7VnNd6iitc=;
        b=v2Ou4NlIW/0F0MeuYHczA5r8Q/3eFQ23DJ9dklMiHRC81etDRGIpa4R8xV2YXnEAYC
         2K57wU9hV2+6FxbG4JoqCRDxwCwze+p9zayYrVqiV3u5HacwUcbKCpi1YtF1wpgGKdwB
         oZiuYcuUds8y0qdkpUpMjs0eDbALsOUJq326XSsEwAEdxOGPm8M3IH684ZSz+59/vHxF
         wOsKMRAhGdJHsDMcQqP46Pj9VCCO4NiSjV9SeSm2RLjEh/v97sIorw0m64Q5zU0I1rjm
         uC0xV0Nt2ucJNEgtvcYGQTwMRVOXKtnwzx0qFuYn83TiXg07U4AczEJS40lZr6Yg4f65
         SARA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Rw0JSo2m;
       spf=pass (google.com: domain of 34eovywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=34eoVYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1178554wmb.2.2022.09.05.05.26.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34eovywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sd6-20020a1709076e0600b0073315809fb5so2264748ejc.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:09 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:4515:b0:443:7833:3d7b with SMTP id
 ez21-20020a056402451500b0044378333d7bmr18008265edb.151.1662380769211; Mon, 05
 Sep 2022 05:26:09 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:34 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-27-glider@google.com>
Subject: [PATCH v6 26/44] kmsan: disable strscpy() optimization under KMSAN
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
 header.i=@google.com header.s=20210112 header.b=Rw0JSo2m;       spf=pass
 (google.com: domain of 34eovywykcs4qvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=34eoVYwYKCS4QVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-27-glider%40google.com.
