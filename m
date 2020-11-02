Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTW4QD6QKGQEQIYYXBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A15B62A2F19
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:35 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id y15sf10686305ilp.19
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333134; cv=pass;
        d=google.com; s=arc-20160816;
        b=IvRbrIi3rLyjoPphStYDSZ3jc5iFubuWmXt2fYL9i0k6JZjMfUM+Yug8XtTRsG5TmG
         AiIniLtNze5gABaXdKkQG/+u2bc9pjZpiF31wg3a8sK+AXkYJrLh0wkrccrKvaxpztIP
         xyIWaR9khWJXtII+QpMBR1ve6qLlQxysKOO51Q05LE609pYdfNnq7x6HyTBHybsyuQH1
         0TymEk0MuIQzbMCWkIZpzVvbBb1/GUxXpmhdJAHFsyfjIgWS3IUjyZzqsKuGGt+M7KCS
         peuYNfkrcnZi0mSgUcpl4ewvlhtdG4x4P2hwaulnmuqUGSGwyvWZysXmcKCY036zzH0B
         DpBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OMjIi6rDw73AWzx5lhZklKZcSljqPux/W3gopPDLE+U=;
        b=rfWANtfWOIhRUX0e8CJ/1SpHxX07gLDF2RxNPPFkNqhgpJLjp6YYtdoeO1MfdlLp6j
         wOjgWo0VuYQkONNBkohMeiKcK8/72ITJYCucfpVE8nrAr/N4/qc5VDqIYKs3qtqXHTjJ
         bBJsI2wvnFGDSOAlz/TOb4Ppvp3sKCSMtwl9JttymlJ5PW+G0TdRBELFeDvB2ZYlUHFl
         8etyvnRbSQMoAaxInYx8zumMbeJVpABi2LjNMdgItDNMahgRPtuzJXc7vgwC3HIVWsjT
         YkpS+mmJzC0sjVOGC7LnjqGhJ9jQxHhG0SWV3EC4i3CLbL2Tx/8un1diUACfInhs4WTR
         vmWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=riUcA41q;
       spf=pass (google.com: domain of 3ts6gxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3TS6gXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OMjIi6rDw73AWzx5lhZklKZcSljqPux/W3gopPDLE+U=;
        b=DtuTLmX6TaO6iGltwxhT41ePQXAfX8Lzig0jTPOUU7qWrcgEQmF1MR8tqERwRSzlQ+
         U/2DYb5CKU7wh3wmVBhJk/pqml1wmrfOK28WE7+rMA82RNdVhJLYXJK+h8LXVfyhZ7rz
         TaX5bzfu6/r6AdVQmnUKg4bdHSHcQWmNErb2XP4kOZf/S2yh3UpSg/5BVW4Z97WO1HBx
         hw0a4OXlytOjoiKDKNj/WyVqHezcyqIzijX7ZBoXZIZ4W58w+KLRrSr8zzzSWSf4Gzuc
         7ZmSjeLB6qXoZBs7JcHUqRWTYv2SAA6dHsap0ZLk0j117zS5seROj45qCK9kaUFZYwYF
         vmSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OMjIi6rDw73AWzx5lhZklKZcSljqPux/W3gopPDLE+U=;
        b=gttk8LOEWZBCiAMGGmXqTQsHa6wIvvGXKKLqWUcX3ByJpZJiJ84NW2c/PkDYHgrcir
         DsZkTwlgt4qIgwC6bLLPK3Ncso+o9HvJ1tjtl4krDOwC/oDrdSf99V0G+x9W1gTkP0iA
         IBCJWPSXw0O126ZIBBDvDTd5wg9xq6sgLSfSWskKUwde714h7Kw8eVpvq6N1Q2iQdlwZ
         OhMR9QXbMIAzFeWl9pQbYm0q8AvChmy4sXp/Ny7qvZzbFjSTdGMbKELHM1CSl5VKTq8c
         BHz9Zpn7zC5MIJ5rXDdj5WY08baHKqNhK5IA27BHhALfAmSXSghr9shS+r6EugfB1OBa
         gYBg==
X-Gm-Message-State: AOAM531WdRzxNMWGE31jU7c3NY6MO/inOqUMHLagyExu1NcUUYXx1UY/
	kC0Ocj53JZ+JsE9ReUJgo/Y=
X-Google-Smtp-Source: ABdhPJz58N1gbhs1JPPl/V4Anbx7FkwRfIb3XtrGcYqeqFkrPm6ShRnG1klCb2YO+OISl3Ur0au/qA==
X-Received: by 2002:a05:6638:41a:: with SMTP id q26mr4873711jap.27.1604333134739;
        Mon, 02 Nov 2020 08:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b7c6:: with SMTP id h189ls354311iof.4.gmail; Mon, 02 Nov
 2020 08:05:34 -0800 (PST)
X-Received: by 2002:a5e:8203:: with SMTP id l3mr7994595iom.138.1604333134380;
        Mon, 02 Nov 2020 08:05:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333134; cv=none;
        d=google.com; s=arc-20160816;
        b=AZ6hjLWRrTHvUjl8D49pLZt//+RVOLJalkSFNYZRCda6VarLdtT0HmxZ7czJRyJtN4
         EVOavvyCSFrpW7V9QHn4GUpDlmQ4+0WLTlpK0Y5A2J+z6vaMOkbglJ+Ul3XsN0Czk/6r
         CBIBEeO1EfiTtY00s7kPqytYRlNUm2TffgYgNHvXdeWQjbgVtW1WGd+FTNhPQwDZhjQp
         s68z7ymLE2dFA+SHoE8oTlj+1QpJi7SVgy1iEMuEfR25oj3ku3738/jNyOekIaMCeSgZ
         qQkRmVsJy3xCkE3CGrThqIogMaVGihQKhUajsKA26F7BR/flhx5WqKyb+Kyf1Goz3qk+
         9ANw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oA6gmttblv8OmG3VJbCFTsqSwJTzGphkOsRK2ZeD750=;
        b=tUuHF72aLuBae4EzqaMP8GOH/yj0KYjjU8i25Y/ktrCk1XsviD0ndHFuWDyNTvWqly
         eaNrPlEVfwZLImvX68bhohdQNAX0TLwovyhzjnqLiUCpCRzRuNrN6yg+GvEDyAL+x6JV
         kqaQE3g9PXRmIOO5dyk6rSR6RT/kS6IuPPeHHfHP9tpLrCumL3wBjmgqhuDoola4EIaX
         2diHc/BhkjmTWNAQqzJLwAYClXufpz5zxvI3j+lEJxQpf5UqXN/+rAYQcMVAk1nem5DR
         FmOoMt/Hz1ocCcj7mtTJo/z6weA3rQPBzSBNr50HM6/N201ZfqrwYkanx4+a16KThvpq
         fF8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=riUcA41q;
       spf=pass (google.com: domain of 3ts6gxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3TS6gXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id p5si908453ilg.3.2020.11.02.08.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ts6gxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id b10so5563723qvl.8
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ef02:: with SMTP id
 t2mr22391450qvr.7.1604333133885; Mon, 02 Nov 2020 08:05:33 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:08 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <5749501e35314228f1a6fbd385b7bf81da99ff56.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 28/41] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=riUcA41q;       spf=pass
 (google.com: domain of 3ts6gxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3TS6gXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d5733831ad7..594bad2a3a5e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5749501e35314228f1a6fbd385b7bf81da99ff56.1604333009.git.andreyknvl%40google.com.
