Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNPTVWBAMGQEHCJ32JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id C1EE9338FE7
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:54 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id s18sf14652248pfe.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559093; cv=pass;
        d=google.com; s=arc-20160816;
        b=RiQOlvNG1HJvB8GxqFoe8AxXkddYKfcKEZ9j+nlSvixdom4YiFgOgM/jxAj6Mj3Uu7
         YwUF4I7hvBZ8idF5VN4XY4F1dUPVx0eSOrLhs29LQZZ5s7qJzPXj83shgSsxuGTZ2t3B
         T5No4EcBdYn0sVH5egrL+n3iM5vnAWpeBLjLvUhwxP3h+oAyxIoqUKzg99J3iQo4p7v+
         SR5E/RxvawfF3rMuqUdLQgJQEPkQvQJigLrnowHtRekwZLrMQGdkR7ig58y8N7SfinJB
         tWXnEYCNUT26KqiOb2VW/LUD7p4xDVnR3KB45HstnXI7TkPTbYbJGaia/zdvP8fnrp4y
         QdPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Xb0GW83ePQ6a/x/Ui6aMcRjKCIkMNpsTfbzQNgS19p8=;
        b=xkfxhNM/MiRp3TlvBPeTMvjxUMhfZmoz9MMrTxeYznW4MCChw0JuGM2Q5rho90INAd
         dbbS6NMZfF6cyb0EaSuyQyU54GtuDWOk7et7OCPY7V0U6ro59d7rzeFD0WAqXMp2wYDc
         O50cP3cN0Qathjp9JiLKw5HP5CrygbNQGezIfxh/XT7l9fYcLzXuUzG7mTN4DNyCY+fJ
         Xh698ZP7cTYmLI6IkQL3tcM2UC/Zp5XriVNCLeysfWwKMKegYdh+0pC8x+y/O2fyZc4e
         1IsA1DjUS4qlMbj8iOZ02ZuRf93y8sDkG2I+DXjHEOKghWeHxYuuDV/Cm86uOWbLVx0W
         Wm0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWDK3QcU;
       spf=pass (google.com: domain of 3thllyaokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tHlLYAoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xb0GW83ePQ6a/x/Ui6aMcRjKCIkMNpsTfbzQNgS19p8=;
        b=QcsgScFCsBiqbZlEf5857j4HyLZNk1PdaCAdS2GpbKc7zQooBH0+CtOmgNECXZktVM
         B6YT4jC48ikuREjwi04DAshd2UAxWQE14DH110V3wEKWYQOnIbw5fH10clXWEJ/bszbL
         2vapmb+a1mCk6p2PTxD4NwUS2jJi0BEdQP4wvTs4nsMWg1huPqitckYNAR+7aEBzxYjK
         XkEPLn2D+vic9YrMZ1ZSYmCkXi6WYqYB2UKkZq5Hb5uOU1DZVDqqJQxiWSp9xuJNDcEE
         v2B3EW3sV1JRcbtASJEoHxrufPAf8wwTSMM5LybTHYe+RfhbO36dQEX6iXyDlQ9wBT7m
         9TRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xb0GW83ePQ6a/x/Ui6aMcRjKCIkMNpsTfbzQNgS19p8=;
        b=mjGz+s3oZjs8TKkbStBjKu96as7F5XiuH27eZM/tvdNa6GixClxAh/ggwNmo4MA74J
         caldHgm8AX9QSoGGmnzDFNIT76j8C7QT5nOWtCeEp5+ba1OXMpv68HeN3tdFXTl0grjr
         /0DowCpuqN6Bx19BppD04OrGQO3PtB8EdjgI1CpZQaNiRXtbaF12Lfojq8d0x3U/J1Kl
         spvwM+eLFCUpuuz0cmihLZBG066cPrcKEsWsSO38MkTcwG2F7UmCY4a9cHgEM5LFQkCO
         zbhnToo5HzON35rSkc5EeX5pXSQxil0N/8NpVD6fJ4sLkcI/iMKFbyiQzqVV4McxTeXv
         MYDw==
X-Gm-Message-State: AOAM530rRN4Bad+7II8LXruknNmqUnfPtYM8Hqut/yabWXk8esQ6lbWd
	u+GFR8YKd3yFxoWPICXq5ZI=
X-Google-Smtp-Source: ABdhPJz0tl+EyXLUGJ6UnxQc80ZbJ1jr9f5pXHh89NH9w8mLIku9pFVejcBem+YmCBUn7jTzEio/Aw==
X-Received: by 2002:a65:520d:: with SMTP id o13mr12057352pgp.57.1615559093566;
        Fri, 12 Mar 2021 06:24:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6256:: with SMTP id q22ls3644780pgv.2.gmail; Fri, 12 Mar
 2021 06:24:53 -0800 (PST)
X-Received: by 2002:a62:f244:0:b029:1f8:40aa:8d64 with SMTP id y4-20020a62f2440000b02901f840aa8d64mr12539392pfl.81.1615559093094;
        Fri, 12 Mar 2021 06:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559093; cv=none;
        d=google.com; s=arc-20160816;
        b=sybyQ8wc/8qnk/ROFTAdDx9XgYAnnwUtbK2ZannmHmKiEgCNLBx629OPY/8ctegk/S
         25I/nmQPfmio6fxvq3RstX7M2s7izliGi4LkCDq5znDVbI7ZReGAXCxTrff+uKc1YPRn
         JICaqfRJ+CRcgdUPTpJtgFGTKBVCOm1j22DC/wKto9a/jTonAATtE0nPwAjr6ycdwdWO
         pMDqWVQZpmWukqce3G3skLbvlwg4Ll3S57v9SJ5RIpto0Mbf9jKnTBPSXId6MTrY3R0g
         C06kh9P0JCOTjXIP6QbbJT7Ho9DHlN8DYSZyyDCEWVMHplsLeeWZvVR4M4G6a7SH82pl
         SnCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=VB+ZOM8lapdi+RHL0OEgOVW/Ip9OH5XFkGtr1r4Q8HI=;
        b=uhevVlGT+7HsaGYu8qTlB+36enNyHCCJJQPtMaMF5eZW62HaYk81HDfU+aheMxo5mb
         uwYT99M4mr8TZfKSLxTjDqzTLJY7Qc3luJ34iI074YRcERMbFbOqRtwpaB8ml975f1i1
         7MjuXY/Zv7716HfU9MfmRDUTgAP+L2ZPkDJG3vv+4UOFzvU5UrDomJoB6kCnY8Jv1T37
         ThjVHCDZ4G3Y51HKhdgeYJy5r5pzezn1s/uN1TQsJtG3CPgH1Rtz/bl3FCZedYCdIjJL
         rt3hJR7gDUv4UNPCwlzaSbTh2NW062Xm8ZuKOL8vcubfbQeGT7BLBOwSRI9Br0Msq8D3
         FiuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWDK3QcU;
       spf=pass (google.com: domain of 3thllyaokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tHlLYAoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id ft8si856852pjb.0.2021.03.12.06.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3thllyaokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id u8so17647564qvm.5
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:53 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:c8a:: with SMTP id
 r10mr12774809qvr.13.1615559092223; Fri, 12 Mar 2021 06:24:52 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:30 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <69b9b2e49d8cf789358fa24558be3fc0ce4ee32c.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 07/11] kasan: docs: update SW_TAGS implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uWDK3QcU;       spf=pass
 (google.com: domain of 3thllyaokcd09mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3tHlLYAoKCd09MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

Update the "Implementation details" section for SW_TAGS KASAN:

- Clarify the introduction sentence.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 39 +++++++++++++++----------------
 1 file changed, 19 insertions(+), 20 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 986410bf269f..5873d80cc1fd 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -235,38 +235,37 @@ quarantine (see mm/kasan/quarantine.c for implementation).
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Software tag-based KASAN requires software memory tagging support in the form
-of HWASan-like compiler instrumentation (see HWASan documentation for details).
-
-Software tag-based KASAN is currently only implemented for arm64 architecture.
+Software tag-based KASAN uses a software memory tagging approach to checking
+access validity. It is currently only implemented for the arm64 architecture.
 
 Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
-to store a pointer tag in the top byte of kernel pointers. Like generic KASAN
-it uses shadow memory to store memory tags associated with each 16-byte memory
-cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
+to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
+to store memory tags associated with each 16-byte memory cell (therefore, it
+dedicates 1/16th of the kernel memory for shadow memory).
 
-On each memory allocation software tag-based KASAN generates a random tag, tags
-the allocated memory with this tag, and embeds this tag into the returned
+On each memory allocation, software tag-based KASAN generates a random tag, tags
+the allocated memory with this tag, and embeds the same tag into the returned
 pointer.
 
 Software tag-based KASAN uses compile-time instrumentation to insert checks
-before each memory access. These checks make sure that tag of the memory that
-is being accessed is equal to tag of the pointer that is used to access this
-memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
+before each memory access. These checks make sure that the tag of the memory
+that is being accessed is equal to the tag of the pointer that is used to access
+this memory. In case of a tag mismatch, software tag-based KASAN prints a bug
+report.
 
-Software tag-based KASAN also has two instrumentation modes (outline, that
-emits callbacks to check memory accesses; and inline, that performs the shadow
+Software tag-based KASAN also has two instrumentation modes (outline, which
+emits callbacks to check memory accesses; and inline, which performs the shadow
 memory checks inline). With outline instrumentation mode, a bug report is
-simply printed from the function that performs the access check. With inline
-instrumentation a brk instruction is emitted by the compiler, and a dedicated
-brk handler is used to print bug reports.
+printed from the function that performs the access check. With inline
+instrumentation, a ``brk`` instruction is emitted by the compiler, and a
+dedicated ``brk`` handler is used to print bug reports.
 
 Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
-pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Software tag-based KASAN currently only supports tagging of
-kmem_cache_alloc/kmalloc and page_alloc memory.
+Software tag-based KASAN currently only supports tagging of slab and page_alloc
+memory.
 
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69b9b2e49d8cf789358fa24558be3fc0ce4ee32c.1615559068.git.andreyknvl%40google.com.
