Return-Path: <kasan-dev+bncBDEKVJM7XAHRBP7JULUAKGQEHFZUHFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 338E049DD1
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 11:54:08 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id m2sf1506255lfj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 02:54:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560851647; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pu/SY+lypAV6nYV/0OKb3XL0h6vrs4Ixf/U05zWyGIEBH2L7y+KIBReJYY99dpp/cc
         TgxWSV6iEPEbr0tqHs3zxZcL68LJGc59ZflOhYqlSg3VCtosaYkoSBEC33TZgzNLssCz
         zAWVGVoUBhQ7/uNzp2d0E3Ea/JF8LLWe6zj39WdBg16NKU4NH9R/WwISPX+IvhL3w6Uo
         omOyq6oV5npMamuUNIe/tp6ud/+ovxJlWpInFoQ/fD4FP5J2A+v6sV78vgUA+2wLLf9T
         lnKPUHemCCSAce1n5Fgt8dHxtqmf4KUhqau9nzJcHA5MFCWzwfoURI9M9/nogjFjfplp
         +mAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fxTsa2ahNuQD9+V6SMheiKlAzHEZLsZyrKZsrIxUjv4=;
        b=rdtflcY+0KrdycpGoZw/WgjmnwLFR+WhWXjI5I2+aO5MJ38kJV7aRdPDXnlgLsF252
         X+++CfbQsy6iEugHbd/GGKILJDF0vKz09i2z7Qaft57W/ZYnDWf3RR9N9hllp2MF5VeH
         wMe9ktuXrFUAfyvwIpkJqRdrOHRc9Huj3uwH1XzPZNh2SwE4iUfRoY3I8Qoy3JHuRPo8
         T64Yhi6qo32BB/nH9X+k6drhTj/jPFS7/6pLsiHZDJ+I3RtYYY/iq9EGH8kcB1bxu7wH
         vslYddEoptkpDGrurxQxD9jZtfa1exxmBZnjk/R3fP3SpN9QMg4IRH0Q+kqMR+Tppt9u
         sRVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fxTsa2ahNuQD9+V6SMheiKlAzHEZLsZyrKZsrIxUjv4=;
        b=bO8A3vDrAkFb1UmI5JjkZnSjbsok8nIX52yucEIjl/7Z0cHYyxaEm1F7llopRbrINe
         pl6GvHx9FPEWGq6UXbVgQ+SPGhaKC3louEgMO8ypwlgfDWDXy3/qfsdO+yvjRjmEtOg4
         76lhYMsIJq8W/TvFqfsDXMQj5nw+HtDNUT99ybeurF50wFtZ8Rynmf04zRo9CVdBsEv7
         v292rAuE8GGaFlLI82dtC7GrzLydcXM65Fh8x/8IPnpuHIzh//30gmK+ykjWM5c+gBa9
         ciimD5/0XS49vkJMzhf1O+wkYVYdB/Kwt4Fn2ab53+woYXMt0vmKLlmpXR7d7jffbLkP
         wWhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fxTsa2ahNuQD9+V6SMheiKlAzHEZLsZyrKZsrIxUjv4=;
        b=c9Fsk9IejSAUYTy+zxoYh9rj3xR1ulGrRoJh8GDeyPk2m3UMeZnTFfcYoXD/3AH4W/
         MQbZ/5INJhcyvuJtiJN4Zn4l1qshlLqQ9+DQ1teSyssGywk6Vr/H4HthVLy53lNRk59Y
         jcpqOCIQ7NP+aublrXNVOB2XIdKDnQYvWIpqijTGczdS8k8SSd/zMCkRNiuZ0CeOwhL4
         nnXL+t2xl2RT5cT4U6VrkaTk1wzDrDdV7GUbBUtLJ3gZujPEF3Y/YKJuQXEwXIPynJ5n
         lCCKxbRxhVLGAT6+3YorZhdlErnVKMn8BDxW6v5j96gfu+4E+KqsEoFDZpo8UaJeOQRH
         v+SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWtJgR4eyPBR1QWchz9dOZveq6oQkaFHH1FL+HFnKnK72NBg9rs
	FkO43yo8+I82QlfKUucEbdY=
X-Google-Smtp-Source: APXvYqwRKx345ewywl51mzfeExA6SD5aTXaaDLe/K0Ykv6UjJg8JHchuFB7S20VrdvY6GcrVp3JgzA==
X-Received: by 2002:a2e:8e90:: with SMTP id z16mr25291472ljk.4.1560851647726;
        Tue, 18 Jun 2019 02:54:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8198:: with SMTP id e24ls2244609ljg.15.gmail; Tue, 18
 Jun 2019 02:54:07 -0700 (PDT)
X-Received: by 2002:a2e:8e90:: with SMTP id z16mr25291450ljk.4.1560851647283;
        Tue, 18 Jun 2019 02:54:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560851647; cv=none;
        d=google.com; s=arc-20160816;
        b=xXUSq6fS+3ptWG9a6r8XGlwZy62WbQ1fDJe16snylUmjtkn7xaqyBvMKlBEG3wbg9Z
         kElofb8g6u1YvwZ7SW6fLEnns0goEqA1vvH9wyCyWrD82ov6WFVml994CcUbAr89Qf1x
         LjT8EX1CFiazOFa/1mXEesKiw4gw0gp+sliDwhakk4ORoUhUZnq4Q5lNovrC+PKl21tT
         QRgbJ+0HBEWlxU/87JyhNz7LUU87EPGfsOgJD/B/9AIQs3CRZOHex+vRdUo9ubewsXQU
         713jxG0YP4gNXqPgiIlWlT0DJujb1p5F1R5qqIOe8hgWynvd5rLSDXzQHENgUTAL4eTX
         1rOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=SgnmHDwEv21XaHv/ypCvWtdlqKd3kLHEL/ZSPKbCoWM=;
        b=vrp44MAf1elt+dZ2e+F8PEhD6naVT14RhCPeir7ZRa02H5LnxpS+qdhKiQvjhZP4D1
         MixkbSx/rcEXg9lAUOTxvo8syMlsK7UZnDgelhRGd7MxxPkRuUMO2rEsH9bBJAlRcPhl
         ifl48OxbBFcMDqb1viIvWtsDxVjg2LwKZzI9NettOppQ42MAVIdanYpzmqZB67d/+Ftg
         UvkotWd4VJnnz9wTJq1UzeVHHjUPjmZVNL7jU57AHucMgqhwPA8b9vuFUXdz/cEkjVzu
         PVroyfvAmOBu3GkYTdd8i5VJMHD0l2J+h4J+6/eSZHUnNMTdMBBkEZQSO3Xy7BMBOzU/
         ml7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id z18si708110lfh.1.2019.06.18.02.54.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2019 02:54:07 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from threadripper.lan ([149.172.19.189]) by mrelayeu.kundenserver.de
 (mreue010 [212.227.15.129]) with ESMTPA (Nemesis) id
 1Ma1kC-1i95I60lue-00W10Y; Tue, 18 Jun 2019 11:54:02 +0200
From: Arnd Bergmann <arnd@arndb.de>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Konovalov <andreyknvl@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] [v2] page flags: prioritize kasan bits over last-cpuid
Date: Tue, 18 Jun 2019 11:53:27 +0200
Message-Id: <20190618095347.3850490-1-arnd@arndb.de>
X-Mailer: git-send-email 2.20.0
MIME-Version: 1.0
X-Provags-ID: V03:K1:bUJwQclvqm/katzhhzycV3+/zOxa7NbjGOKFIqH4EXPNW02vwyN
 lRoCJ9pDU+WbEFJZSH5TpY8rP8VBIOStIKLRBqcBtosxCv5LlrE/rA1pQcShjiptjGdXGMx
 y9Yby5nkzWG9VqIi84t+aokD+Qbu9EaMbAUpG7WpjvuQIBC7Yyl1HNU0eFDofbbcqLY2YTW
 O5MFfR4770dZqo2qlu0aQ==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:iIwUq5FcHw4=:EB3SY0U94Oo+TOTWQB9G2D
 PP+nddwoiOQnZ5tkbYk2Lh2TJIc6E+ObTe4LhKccCu1IcrQZOlkZn7KXdl6ZxelHoT4M9EZml
 IDZINoYBhyPor35Ghp0KLV9mzYSYx3vcijpLUUfWcw29jPzNpEVGfaOBKG2VYtAIqvyNA7n95
 nd/aMvU71fn6g9czQwP46IEaIpNTliHYKbqzxuMg/s7U8XTi0LVY56wnsQ0562+KqvoBroqfn
 LwUrik8VyfQ7qcg9vU9KSSKdUaaB744scxeMfp2X/LmyqDsQFb31u0xxf9MkgE9x4sseIEgdY
 tkUDn3azX/IOlZqJOenTjDAc6LyPGbJhgje5/4VyU2M/tgniMR/nivygYSXnAa5FGC3TQr9CK
 mFh7hpTVejfntAP3mziLcPtwJzxx+gF6nhf8Dqeqpv8vcApz51ybXO/JAl8Jjb5YYQA09oXIL
 M4NIcymsuiB6gGIYAGZgiQYFz4wZFfpUl9tnGaYECOUnnDo2MIMdMSPsASgkJ+7/ykwTsm4CK
 PNMcnQvhY/4r0oVL7obwyKN6+N07+L8fmRFkggm8Q6KHWFhHqjjIczLtP05jjiLJzVihadbZz
 QRxQa3jPCD2YHzmIS5qtobDTEM1ixuOl5ENcbORlp06BlPucfyOBj+m+6gGMXlvmMOo1L/LPF
 pwAZsa4fYFeY5Wjj6AYkesP8CdrFlMuQ9Jt1lgOI6adRwOldxtK/0CiT3LI8dPOJp1Be5giSt
 hNB6ySTYYupaUPbKZG3WZvwGdnRbzjmbIetlKQ==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

ARM64 randdconfig builds regularly run into a build error, especially
when NUMA_BALANCING and SPARSEMEM are enabled but not SPARSEMEM_VMEMMAP:

 #error "KASAN: not enough bits in page flags for tag"

The last-cpuid bits are already contitional on the available space,
so the result of the calculation is a bit random on whether they
were already left out or not.

Adding the kasan tag bits before last-cpuid makes it much more likely
to end up with a successful build here, and should be reliable for
randconfig at least, as long as that does not randomize NR_CPUS
or NODES_SHIFT but uses the defaults.

In order for the modified check to not trigger in the x86 vdso32 code
where all constants are wrong (building with -m32), enclose all the
definitions with an #ifdef.

Fixes: 2813b9c02962 ("kasan, mm, arm64: tag non slab memory allocated via pagealloc")
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
Submitted v1 in March and never followed up on the build regression,
which is fixed in this version.
---
 include/linux/page-flags-layout.h | 16 ++++++++++------
 1 file changed, 10 insertions(+), 6 deletions(-)

diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 1dda31825ec4..7d794a629822 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -32,6 +32,7 @@
 
 #endif /* CONFIG_SPARSEMEM */
 
+#ifndef BUILD_VDSO32_64
 /*
  * page->flags layout:
  *
@@ -76,21 +77,23 @@
 #define LAST_CPUPID_SHIFT 0
 #endif
 
-#if SECTIONS_WIDTH+ZONES_WIDTH+NODES_SHIFT+LAST_CPUPID_SHIFT <= BITS_PER_LONG - NR_PAGEFLAGS
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_TAG_WIDTH 8
+#else
+#define KASAN_TAG_WIDTH 0
+#endif
+
+#if SECTIONS_WIDTH+ZONES_WIDTH+NODES_SHIFT+LAST_CPUPID_SHIFT+KASAN_TAG_WIDTH \
+	<= BITS_PER_LONG - NR_PAGEFLAGS
 #define LAST_CPUPID_WIDTH LAST_CPUPID_SHIFT
 #else
 #define LAST_CPUPID_WIDTH 0
 #endif
 
-#ifdef CONFIG_KASAN_SW_TAGS
-#define KASAN_TAG_WIDTH 8
 #if SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH+LAST_CPUPID_WIDTH+KASAN_TAG_WIDTH \
 	> BITS_PER_LONG - NR_PAGEFLAGS
 #error "KASAN: not enough bits in page flags for tag"
 #endif
-#else
-#define KASAN_TAG_WIDTH 0
-#endif
 
 /*
  * We are going to use the flags for the page to node mapping if its in
@@ -104,4 +107,5 @@
 #define LAST_CPUPID_NOT_IN_PAGE_FLAGS
 #endif
 
+#endif
 #endif /* _LINUX_PAGE_FLAGS_LAYOUT */
-- 
2.20.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190618095347.3850490-1-arnd%40arndb.de.
For more options, visit https://groups.google.com/d/optout.
