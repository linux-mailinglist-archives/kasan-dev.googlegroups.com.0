Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHM3VKBAMGQEX5F72KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E178337FB2
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:33 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id u2sf10511942edj.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498653; cv=pass;
        d=google.com; s=arc-20160816;
        b=NB6E9Ve80q4YBVFZSs/2eRbp3GeAb2NMX4aTdvILZfZwVFH9V2BIAVYUmmaJiIQ+Mw
         vMy6Ey0imqTz0eoLgz6kDjpEa/da0qGIf6jZbx1f2lrda1//W+m+HsCx0LXGvn2Mo0qS
         NG2oqiuUV/GNCe6RFRqMF1lPFo7vFxgqJcVSW2A4qJ4OX6lFz4qRf09O1eirKx0LBzOw
         vpL/DXPsPf1ZutQBgDU4UqUA/djxsD1UEmoLsOIfyI8wDm9lYfxSHjon11zidkXXy9jQ
         h8MUNz7SAqX0SGTbXL6zB6jCBi2d5N4NSjq26Ia9gZbSR0gzPLEpASGLA/RTW7DRlgRA
         vmMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=eN+5jiUSeCjEKH5W9jjFynMPGJHV1o7cbgEaWmFWPV0=;
        b=bUNBxnCGR4yPh6YfG+roNvE0KqSdO6FKemdKkQfvDJz3cZQ4bEMxwt3exnINZs2cv3
         r9IrS4Y3RCY4221CXawtXbGC2Hv+tXjl3MWMB9Dk7yBAKT8j565/c2j53DzII6VYX/Fv
         TF5InfAzSpspz59jke8qkGi21J+NnWpnncgoJYfeqPhJtMbqkKoO9ttLKTJIj/xEaFqI
         FQruOS2kungkeHA1ORl50fB9i3BRR3YcilZKAf0wy44F3bOf9PlRj0jgd43yPIbLfV/j
         j/7FYrp4TyPzIUlZnI4JQkkV1CLWtVpEV5z8LL7cgW4OP304LB6RSPdb9IX+eErimvHP
         nUIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lAknWDT5;
       spf=pass (google.com: domain of 3ni1kyaokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nI1KYAoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eN+5jiUSeCjEKH5W9jjFynMPGJHV1o7cbgEaWmFWPV0=;
        b=NfsD/JrYxCV6+kHFJHey0WloK9UrCb3wCHAlHRM0hKxawp09FArZpHOtlVJoshF1Qa
         LZK148FZw/1x8nj+YUoZlpvLwDjI6WLukkw4t286B6qZKeyTfSIqjfqxzOWcbmcidn1d
         7ny4AjuFGSCCn1DOnoh6RGeKE7o5P/QzMHGgtorc79aNwYN7+3BUQf2dRgVEMMPcWmwY
         HZUf+lIaPKRTrZROMFArw5VC5ekeTn149mNpw70U5g1jkjjGjEnjqcDyvGtReepk6Irn
         e2N6LZcZkzMjBfMh6kBIqrEcgCXKu5GluR8LbYQK5r5t2hN7fWoICw3d0qI1IrxNcnn5
         3xXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eN+5jiUSeCjEKH5W9jjFynMPGJHV1o7cbgEaWmFWPV0=;
        b=oy1xkBhxTdI5i5Z3IfzhHU0O5FlLZ5m5heox995cuBzeQvhkeXLRCmrK4aelhb5xdM
         UoDPKJCzLLCQPinmd2hloHz93hdNAZcvHFAmiGz55LyY8znXs5lKO6pDaD6Apx+USCii
         jiCEenLuP9MKd7cvrB04KROXiUIhTZkR1AF7iBCSqClxWvpHQyj/DMBd8+6moz8z9f1V
         A2wiC53RGWo8QX8XldQ1RsKvYNup6MlLVKLX5yc4sA73Gr6cMyp3S5oQfMQPhp6scWrw
         v0+dJvxyNAPMUCCqLwYZmZ3uw7UJJh/PcE3dSnI9BYSzcP2Tp+wXP6mPBxpeYi92Pl/c
         0JuQ==
X-Gm-Message-State: AOAM533UAFoP1qxKKsXGkhvNn7eoUl7VowgzfXoU1EyVRExYqe5IYeIU
	wpOxhXWTZBQA++HXNECgPV4=
X-Google-Smtp-Source: ABdhPJwXAb9SjzTOJpjrQ3kwvqMbGiv0ZP+9XL5AbJAi+KMPLxxPhJhMcQNngZ9uJyFtAeBzm8Ab5Q==
X-Received: by 2002:a17:906:1352:: with SMTP id x18mr5004803ejb.545.1615498653272;
        Thu, 11 Mar 2021 13:37:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d788:: with SMTP id s8ls2137302edq.1.gmail; Thu, 11 Mar
 2021 13:37:32 -0800 (PST)
X-Received: by 2002:aa7:c815:: with SMTP id a21mr10892523edt.38.1615498652501;
        Thu, 11 Mar 2021 13:37:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498652; cv=none;
        d=google.com; s=arc-20160816;
        b=fhuP4N3bTN9ye6Id1B8tDv+NZBPp3Q5NsXGOvYnWtSI3KVUMH+lxXpubDrlrW72yxx
         cWnViP5RONhbE3QpDKmw0LRljDv8usimUeGdoUj+ZBQhN8SDlLuNb4u7zhEYpsQqMUSQ
         5AT/bmDIbu00UXB2Wu3DGNF+G7eJucc0+XwL54WpiGQtrZj16HxIWur2jySX9txshyfe
         PJvSFMclEJlMk6QgA5YqQB4Rezv2hThYqrb0otvpvNTo5V7EmMw8fKWebr/I2FdcAT/+
         5O9WE3F0+YULGEqC6OFmjyZO5SOwc4BIwAkMYG++vSkiggfPMyavYAUW36f/0qdqBZbu
         7gDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=DMCAKfggtb6XfOnfwXa7RpunfAY3u5vebHv4cftZQZg=;
        b=AXh1PEM791XTWJk1+tHoRDF/w/pgy8EY9FPq3qXY/iaW6aYuMq5g8r6BfHyFqhYMXP
         3XFHjkCZTrL1YVjD9Lg1GTkvCkSK/PLw0p1iwyOB6nGLXvz484u1WMu4clQGSwgXCVqG
         LhiNzIlARN/9czF+1Y/LfD0X7v8pbo0FhN6upy8ny25CCj3x85wwwgd1rDf4SSkl0UZ6
         M5js645BeZHuGLYA1/8T0nhxGC9JLkN7EdSN1XUbJwH6zpgM/QI8gOCSPwuHV/9G0/4i
         7UBbV07MMKJmi96lBivExVSEe0rk05KNSfbMYWLasK6fAGx3zg2SLkrgAhZm3X+Nq7SR
         QdqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lAknWDT5;
       spf=pass (google.com: domain of 3ni1kyaokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nI1KYAoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m18si78470edd.5.2021.03.11.13.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ni1kyaokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c9so1735066wme.5
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:32 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:35cd:: with SMTP id
 r13mr10155047wmq.186.1615498652153; Thu, 11 Mar 2021 13:37:32 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:15 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <ffe645426d4d9f6de97dcacebb2ff698cfa47a43.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 03/11] kasan: docs: update usage section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lAknWDT5;       spf=pass
 (google.com: domain of 3ni1kyaokceklyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nI1KYAoKCekLYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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

Update the "Usage" section in KASAN documentation:

- Add inline code snippet markers.
- Reword the part about stack traces for clarity.
- Other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 343a683d0520..f21c0cbebcb3 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,22 +41,21 @@ and riscv architectures, and tag-based KASAN modes are supported only for arm64.
 Usage
 -----
 
-To enable KASAN configure kernel with::
+To enable KASAN, configure the kernel with::
 
-	  CONFIG_KASAN = y
+	  CONFIG_KASAN=y
 
-and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
-CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
-CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
+and choose between ``CONFIG_KASAN_GENERIC`` (to enable generic KASAN),
+``CONFIG_KASAN_SW_TAGS`` (to enable software tag-based KASAN), and
+``CONFIG_KASAN_HW_TAGS`` (to enable hardware tag-based KASAN).
 
-For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
-CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
-The former produces smaller binary while the latter is 1.1 - 2 times faster.
+For software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
+``CONFIG_KASAN_INLINE``. Outline and inline are compiler instrumentation types.
+The former produces a smaller binary while the latter is 1.1-2 times faster.
 
-For better error reports that include stack traces, enable CONFIG_STACKTRACE.
-
-To augment reports with last allocation and freeing stack of the physical page,
-it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
+To include alloc and free stack traces of affected slab objects into reports,
+enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
+physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
 
 Error reports
 ~~~~~~~~~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ffe645426d4d9f6de97dcacebb2ff698cfa47a43.1615498565.git.andreyknvl%40google.com.
