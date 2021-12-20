Return-Path: <kasan-dev+bncBAABB4HZQOHAMGQEMJRRWNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 50B1847B587
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:17 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 28-20020ac24d5c000000b00425c507cfc0sf2347804lfp.20
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037617; cv=pass;
        d=google.com; s=arc-20160816;
        b=zF+WspOHtR/7XnQu/CwvKFUbo57e+bQvGUdR9AqD6Otgm/mokigxzz5Kzpdn0c4okq
         MeoYenIlYK2JcTUbaJQThD/VFdNAMeTxRibNMIZHlzk3FOgOzFT5FgJbahHVJT/Fi3ts
         /lp/4mBhbxtvfs7zDejgoIEJykDZOMo4YriDLPd9XFwY56jwJaaxgQThTwc0BxXURRqV
         ZaWBWFP+vNQLIik7EeBtUKRz1CPLcTqkGXuJ8KcbdlveQ5myFFbFrjx0hk/WRgQ3R+eD
         6vQRYAVCnsi8u59uu8BpdpebrHWXmLG0fkuxOq5kh3mVoLoy7kmKbat4+OVCuM/AspF3
         TtKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R5/xlOdKcwjK98qRq4EqIVykPOCbs96liy0ykQGxKLg=;
        b=Vmn+KysUM9j96aBR9X6PsXVhYMzH+y/JO8LhyqHf0h2Wir7K4Kqb0Rmt2TQ3l5R7/Q
         utS6iWMq/lAq1z6U7+2s0aGDQBSCyw/MybU3b9rwgjgAtRG/XwQJ964ZHHRyw5V69N93
         0QD8+2JZ4iQTVNgeTX46PhzOLaEA/hgBCZfdFK0PguxY6+oXh1TrCgM7qYZsFod7vtX8
         lr5N3voBp3xpZ3mGZJy95IzuQHW79IhMfRMJ81cQMKAYlP4JjQEKF/kr5iGWyMPD6FCc
         NN07VwJG8j8kb4MXpmqtjFCLSMs/TNDKC/XrVzlT+EFm6Boac0+bL6HDpKPIHNXjH8++
         OXKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F3c11oDq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5/xlOdKcwjK98qRq4EqIVykPOCbs96liy0ykQGxKLg=;
        b=nO+n1KjiHXfyr2cRI94Bl0tF5XA1VFmMKmVqNFmyraKKzdqtJs4yJmfKCp6Xm5IOHR
         CWI7Y5zWkKnurZ2ts2RrNh/MiJFct7mW0P3SljWLZp3n/arO6nhde7J/gQxCdqOaS1ow
         nO9QHxSvXIof2wa/1e9YR9tMzZJCvT72WB8MC51WBHcbT3IyJDY9xPoYxB8E2zn3Wv5L
         YSlbFVxVBPWWqpohtXGcQ0SsBjmtGZ11DAi8GYRyRFD1jMAu/6fUXWs/C2eqSVlRo2FB
         /KJ+rDAp62lOiXtv8CQ4oLF6Eccy6+KivmeNRVeYLFxAPLDfNi1xt/7mu6KopKNbow5B
         +BAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R5/xlOdKcwjK98qRq4EqIVykPOCbs96liy0ykQGxKLg=;
        b=UGf4EIe7IohAfarAH9o35zBGMwV5W0ZYThnY22mYP6l/w9AC5cHgxginANO/C+FSup
         S44Ja+DjLhG3CTGTdsffyVRB4GVIAUfbR45CA1u1O/ch0kM8IyIZSfNFemNbnglvfca+
         XNKcIzu95Bn5RUXcyGk3iWfRSU2kxAVDUUhDgZhyMxLD6pmiUJwdoMzZ5UdnrRS11QI6
         Wf3LrUQj8eBijrgiLm1II0o0DNi5tp+vE8XcY3RTusbJdGu8ngQLqnxo8Bowx4ri009g
         GVIbkS0fffHQes2mN0dIYZ9LALeYVwecqqDCTJC9XOLTq+FI2bhnfdaIMiIc5QNPpKsf
         4zzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PgX8IMufWAecc0Me4T+fbfUL0MB7X3cStbGz5tHWTfXu4Wwrg
	zVECWP0d72BIh8wYl8LQ9ZA=
X-Google-Smtp-Source: ABdhPJw6rrNswXV4/AP8JdHyfjDn8haDqQl+lpuvDPdRt79/08CbszNnvpnyyMJ6zYmrIR59gFwihw==
X-Received: by 2002:a05:651c:503:: with SMTP id o3mr57009ljp.249.1640037616904;
        Mon, 20 Dec 2021 14:00:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls800054lfh.3.gmail; Mon, 20 Dec
 2021 14:00:16 -0800 (PST)
X-Received: by 2002:a05:6512:2810:: with SMTP id cf16mr124722lfb.541.1640037616209;
        Mon, 20 Dec 2021 14:00:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037616; cv=none;
        d=google.com; s=arc-20160816;
        b=XWQI5oP7aVR+lpNCCVpuIvUGm8tqpjl/Gcn/PErYJ2cyNxBqhDybfjR96Dx3fIL5Yx
         YuEVyhSOK0PFA9jxQob61pVPRor6Gg9GV8QvM+QcdkIQyCtkWrtQlOQY+DF+s00cGKjC
         4pK4K2EtuaTTwUEAJ1V6hsv5+IyfMpbIxzrxIFntH7SmO8AzapVzOGbU4LP/ADz+e61t
         Xs/7v/LDA10pHUxh2KAApAtaoVPf4TbbFjYtBjfv++tgw08u5TqiurpdNpPQYc5vzYIq
         y0CMaCVWqG8trHdstw8I0toIN2VeruuHenduP8Ys+lHX1c6de9IAlblpKMzfwyDZ9z92
         sdrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cJ0jlRH/hquQ8J9ZVRCu3YYtyS2ZzdopP10ccd9wkaM=;
        b=PkWf+XShNsLRfhicxrefNtSPuSXfHl1s4P80zJC0zLho7KGZ7Qt5QXuBIiRGYuBiOq
         UzmjOdKPMcc9DvgX/J0j5feWEZNqbOYo4p+fOgYSk/W6MEkdjOWPhVsmXfqlfdnfmsgr
         eIbZmRFMEgMDnYIliLZ8iEgdmFxmjUjrqe94/tekIeuz54JvMdR8SPz4UZaYZkXHHNPK
         jvsQxsM1vmXdJ+XjI65ODXF1+saihbZdMHISUOLrDMuL0bFdazC0B42fRP5bWIOwuSc5
         D8N8iXP0q+j4mHdw1NqBBj1yFYpjDJI1y3pc53UL3okiLDuPaz9dEfzQqSYIlKepUq2s
         9cUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=F3c11oDq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id w21si991419ljd.2.2021.12.20.14.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 16/39] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Mon, 20 Dec 2021 22:59:31 +0100
Message-Id: <b929882627e19a4a2d02c13788bd2d343f3e5573.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=F3c11oDq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

In preparation for adding vmalloc support to SW_TAGS KASAN,
provide a KASAN_VMALLOC_INVALID definition for it.

HW_TAGS KASAN won't be using this value, as it falls back onto
page_alloc for poisoning freed vmalloc() memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 952cd6f9ca46..020f3e57a03f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,18 +71,19 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
+#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
+#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
 #define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
-#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b929882627e19a4a2d02c13788bd2d343f3e5573.1640036051.git.andreyknvl%40google.com.
