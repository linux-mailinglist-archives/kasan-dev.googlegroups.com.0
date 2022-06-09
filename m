Return-Path: <kasan-dev+bncBAABBC7TRCKQMGQEDRZWNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F5105453F4
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:18:52 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id j4-20020aa7ca44000000b0042dd12a7bc5sf17465036edt.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654798732; cv=pass;
        d=google.com; s=arc-20160816;
        b=qAp4TNfGl2C+njvR4vZnetMMHCvZf/4gFuzc5lLORLTD58QFyb4Q+gsiWtOh0ZD5vp
         yzqvDFEP4gNhHxtNBREKEr5tSp8itE5/YUQ1k8iVTCnfDxHVIg8uh1fKewPN2LrBXLkt
         ykK/MLUXSLdT9/x9janQiAXu8ncXjXwMBwLA07APOXcFgv/1jg0VwJoHobaB8POPt6cL
         XYfSv/Pj1RYNLH5UBIHuJJKs3Ch8CfyZ1RMXFBnF58eqkKNSupKOLtJnZFishdjZoYKY
         PoJW7SNaSmFGttem9bRo/jwpDWe0NsWQ2FwtrISr9qKal8VmMXWg5V4m3uX/y4yZNo1U
         CIJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g5Z8wXEyQ++vAT08cBA4FmJOCrcHV7BruCMHSaZW/6U=;
        b=0O8xKwPmQaoAFVtbBtLQlvaWEYMlr6Id2YnphsObmOKOtuL5pD1+zS606i6oeuOqwH
         Hv6e2Ih0/t49uRLe+pka5uLsfTwJz671sqoeSV8o+3viYij+OojaJ71yRZY4lyavimKx
         Zd/dk6jRddxkanPCzqDLRX8uw741Q1YiatQ3UJGY6J83F+O7p7s7hbuVtrFiEn+BgyPD
         xuFVeCGbSzFXxOY4NkzstGvvdg511hSWTL2WSoFQdwZZqVeTTB2JfZ3FyPeykYPrhlhx
         hWOdMx5lmhxBkutRHhrw+vlYnAZogTV61+2tlM30spmRgciBIxY6BqAKAjIl9sgStlFC
         AETA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Xa3doeBq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Z8wXEyQ++vAT08cBA4FmJOCrcHV7BruCMHSaZW/6U=;
        b=UYsD5zAEmW7vtpy2Bgj5uUH2lWfHzYiUKD3PN5fllZoILqWrQgq9ck0lo643ijqN5k
         rNUyl9L8JYV1iD2+MKuUO+w757utGPxcbRAW+45S+uCvtz09zFN9VvfTqwP8gD+7t2ru
         0xwxn20gQCTkXfxZZsQY7+2uOX3wWKpG4GGHrwFVTUtYZKHeW15u4QyVabjWxs3kaY3k
         B+F06AEOzcy4o+xWDuRzd6DjYhFqAE7KQYeHkk+vi0yO0qHOm0h5YeuqlyS2+OjWrgQr
         q7Ex5uTjVlecwnabVvkSxwAzuGRccFjX+mx1mI/Bsx93A7jiEs4sVOFpJqwFG86e5vRe
         RC2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Z8wXEyQ++vAT08cBA4FmJOCrcHV7BruCMHSaZW/6U=;
        b=hSQDV8yS7I0YTAM+GLz7zXiKjpUID2VE0dXKZH72avfaAzd46nLxGXBWNq7HhmAdSt
         phWn/QATUqOj+tnmeEOOcAhs/Nn+g/y0jOKahC+4xgId1zrqLnI1UlnMlJEKEyLenCiC
         JPvTcX4ONLJGtiiwwmTuo/KbqX6h7h52l6JyhcfBqhVsBo4xNYSJs8VRZmHmsyX0wHi8
         3jRADv+aAy6Pxe8cakn23RpDv68QYmTVsi7ouBZOJhzh/dPxpyeqnGKtFjuSGaWvwdFM
         ScR2GfWCF1/W6jLhDLaa+hdphxJmicOvnJ9yavkLuONf78ubvk810svOrMyk2D5x/duD
         Ds/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530a/jjs9S2osWH36wOxF9x2gLENITxRqzzSFo6somfYz3djEFIB
	gs+N2VIypCLrpLPrHSGBDEQ=
X-Google-Smtp-Source: ABdhPJwnavooNvXevJSc77chXeXQLhEQ4Gr61BTW/dkaAmFD9DY66rlBar+bzILcklj/KkbH8GinSw==
X-Received: by 2002:aa7:d582:0:b0:42d:ce84:7e07 with SMTP id r2-20020aa7d582000000b0042dce847e07mr46694778edq.297.1654798732132;
        Thu, 09 Jun 2022 11:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3fc5:b0:6fe:fc5b:a579 with SMTP id
 k5-20020a1709063fc500b006fefc5ba579ls13032ejj.10.gmail; Thu, 09 Jun 2022
 11:18:51 -0700 (PDT)
X-Received: by 2002:a17:906:5344:b0:711:f8fa:f16a with SMTP id j4-20020a170906534400b00711f8faf16amr7629363ejo.638.1654798731360;
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654798731; cv=none;
        d=google.com; s=arc-20160816;
        b=B4uUR+sRjr2OtDSK7QruLekQDpo0vaH2ayjdk+XTPtp543FwznzUwBFql3h4uu3dmX
         qy1rShbiwGwFlNFZk7eEJs+H7AWhZQ/TeDlN1SdKfmrb1UyPNztIRRgGYoLWVMhjALfB
         AVo4Z3ZZUTYamWezAXYlWYUPiT7YJ3ouK/vpxyTeGNBJoPKjIGvk+1vP7ZTontcI4bPG
         J+ddsB+BzoTWUziimurD1m2Q7IeqUKPMeG1HsiEZp0JsnpeyDPOUmtkR3sPyoyDMv/Gh
         z6HUQiV8TCNa7pYZEfpM12CQ6BveW1EHpnG7WoE4TdSOzJ/JdLNCvqo6eCXKBIAyEcoj
         m+qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fO4jbpVApVQcfTPwx9gBa9O1ee1UTzsQG3M5HGLfNnA=;
        b=fsWt7EU702cHi/rm9lpogPykmYKB2+wl26lJXNt8P8kWjPmJhV6/3lS45piN05koL4
         kIw9S5c2c2SW2JMkWpb6APZu2Lbhn+ccNoAV9eKTQgbE7XHmHrNrsKkSHqr4SYP3fdDX
         hvRDcM7/OeEptuDqgN59xArIdeEJm7fAE9ROHL8ceRLhBUrpV6lk6CcH6HXQZo2h4G5k
         VY+etE+3iLXy/YHkJ8yMM3vyV9RiFf5iPagxDb7CLYx+qJiNOodyFJhq0s2XPfL1ZvGv
         cHmq0DQBW4I+h6Aj6uFOZD2qgcgu02fxSlYeSjlB+XTgMSYkajPLRY5cz7dbKbF3oUu1
         tuTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Xa3doeBq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id m7-20020aa7d347000000b0042dd1db7093si241709edr.5.2022.06.09.11.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 09 Jun 2022 11:18:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/3] mm: introduce clear_highpage_kasan_tagged
Date: Thu,  9 Jun 2022 20:18:46 +0200
Message-Id: <4471979b46b2c487787ddcd08b9dc5fedd1b6ffd.1654798516.git.andreyknvl@google.com>
In-Reply-To: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
References: <1ecaffc0a9c1404d4d7cf52efe0b2dc8a0c681d8.1654798516.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Xa3doeBq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Add a clear_highpage_kasan_tagged() helper that does clear_highpage()
on a page potentially tagged by KASAN.

This helper is used by the following patch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Renamed clear_highpage_tagged() to clear_highpage_kasan_tagged().
- Removed extra empty line in clear_highpage_kasan_tagged().
---
 include/linux/highmem.h | 10 ++++++++++
 mm/page_alloc.c         |  8 ++------
 2 files changed, 12 insertions(+), 6 deletions(-)

diff --git a/include/linux/highmem.h b/include/linux/highmem.h
index 3af34de54330..70b496bbd2d9 100644
--- a/include/linux/highmem.h
+++ b/include/linux/highmem.h
@@ -243,6 +243,16 @@ static inline void clear_highpage(struct page *page)
 	kunmap_local(kaddr);
 }
 
+static inline void clear_highpage_kasan_tagged(struct page *page)
+{
+	u8 tag;
+
+	tag = page_kasan_tag(page);
+	page_kasan_tag_reset(page);
+	clear_highpage(page);
+	page_kasan_tag_set(page, tag);
+}
+
 #ifndef __HAVE_ARCH_TAG_CLEAR_HIGHPAGE
 
 static inline void tag_clear_highpage(struct page *page)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 66ef8c310dce..76a02255f57c 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1302,12 +1302,8 @@ static void kernel_init_pages(struct page *page, int numpages)
 
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
-	for (i = 0; i < numpages; i++) {
-		u8 tag = page_kasan_tag(page + i);
-		page_kasan_tag_reset(page + i);
-		clear_highpage(page + i);
-		page_kasan_tag_set(page + i, tag);
-	}
+	for (i = 0; i < numpages; i++)
+		clear_highpage_kasan_tagged(page + i);
 	kasan_enable_current();
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4471979b46b2c487787ddcd08b9dc5fedd1b6ffd.1654798516.git.andreyknvl%40google.com.
