Return-Path: <kasan-dev+bncBDX4HWEMTEBRBI64QD6QKGQEPPO57FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C87402A2EFF
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:52 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id r83sf5459748oia.19
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333091; cv=pass;
        d=google.com; s=arc-20160816;
        b=GbtNHFk48aiFIgu8u/MtPnwQ+YIWv8nPIq5Flp8ZmNoehYZcubByAP65kXW74c6HbD
         odzM39S8UguRR2kRLbykpnEEAha29VKJD+aF+fdBWM59pHazuZ4Rr/ryIp+14hAbo5u9
         KBmXqoABLyK8wj0Rjr3NSvhbj3Nv0Bb1DTAxPF0zPpHaj7Sg59Yg3AAxMvYiZMlejHyX
         8oeMM9BPQlvhtyRf3JMzMYeE6D5ibNnzcbDr7bwMeXqKw62BCGcFEacZrYPOBdQTq1VH
         /jwdlR6wrGrR618QyT8KYAIpc4MiAUog0FZBhF1YCPaxmzfMVM8RLOyYS6Ft+iKwkLoq
         on/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Jy51Slw9BRvKIq340JQRyafshuTM+vRhVkQir60REns=;
        b=bY1LALYfOieiTmYCZ8BlOz27FCX8vu69GGQM6LKzn/rRTVjyUMgHTdHtgl2un/IGbv
         GBZ1hV+etTccRE43bZFMRVYWJsywbJ04RmZc9S4YJbDkWR2FEM0qCNc5cEA3xlO7qWIp
         o/QxwomX9qti1d4lZxruXMuxmlHqYmCxhLBK+X1GHOCk1U7UN1TmPmxEz1Yfa8FUCZfL
         taX1uMs3NLSa9NKlH/TfkLKFK+gChW/7MTU4PrVHnSvfrUeIrwBryu1SGI4+9jcfLRiK
         2C6MggpplM93+jJzGkEHIDa3TFQe+JUNYrtwGWoNufdFS6f+3ErSFhPjGoB1hCn6td28
         3jgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k5i20QIv;
       spf=pass (google.com: domain of 3ii6gxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Ii6gXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Jy51Slw9BRvKIq340JQRyafshuTM+vRhVkQir60REns=;
        b=MX6Bu035jja0XLgLj5X64zHtntAs+cLXltwJ30G4pQxkHfw08tKck09Pz/aIVKn5Q+
         mmafXxL67+2vjTOtBdXcxMaj5PRnZhgmXrs/NCtcX6SugueJW1H6Hj8FGdGU0LTP+MyS
         NL/m/U4S/5VO0GpHevRggJaze8EdX1lXlboflVB/XGyWcNH9Ni+3tUKdfXeLa0JcAS+U
         whPeL8xO0qv8IbqxiRezZhCk789Xi+YhzV1BEB9Qv3auToEU1Y+1zzQAS2tXn0M6FsRV
         /POsBIURwWGDv8Q2I2a8J70p2j32ZJkzCSWO7YYk1GfHO8AfjWpth+SDZjUW/gFKIJj6
         2wgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jy51Slw9BRvKIq340JQRyafshuTM+vRhVkQir60REns=;
        b=YIOHi20mPLN8fY64CXiMF6lQUbO7gQBdrOIxsFxznEPcdgemFDqE64CslnM2m1AIC5
         rTedUWkEtZCIinpYy7yUM0BkKbF4vf/1fdVv2+MOZXBjB2arZAz9eiXSWb+0hKD0mrvG
         Fg88Na8kAlfu9F2si1tL7XF7soyn4qn32FvXO0dMp7ydhht8y7R811rPxWJqXu95MYQu
         uvaCkeVDeff+5K8GeQFF9+N0uATwzbVFP204SPv3uWPBwgN8ptnaRoogZZpFSMFzQW80
         m/MBTF8guu9NIcJvuRiZdyTKo9zwTfGsr7RQ//c2No6RB8nx464JgtODtpE008MP6ORa
         R0xg==
X-Gm-Message-State: AOAM531KQPV+BkOs3yeWIN5I6wx/DK5oXYssHswBq9x+HkSnmkGKxc7m
	sMAM2W61VxZi57muXOC8Bq0=
X-Google-Smtp-Source: ABdhPJw+mvb3CW5ILFIqQYJj8yUy3s4khQJsMxOi/yT6v+SURjhDbAQpEwXKI9e158xDGOz8VrOlQw==
X-Received: by 2002:a05:6830:1af4:: with SMTP id c20mr12427184otd.198.1604333091773;
        Mon, 02 Nov 2020 08:04:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4713:: with SMTP id u19ls3471895oia.0.gmail; Mon, 02 Nov
 2020 08:04:51 -0800 (PST)
X-Received: by 2002:aca:fdd4:: with SMTP id b203mr6091516oii.152.1604333091376;
        Mon, 02 Nov 2020 08:04:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333091; cv=none;
        d=google.com; s=arc-20160816;
        b=cBolymGKm0/eFNbuUXw9TaT+f0jaHcEXMz6S+kigq0whjowuqKNrssLt6uRlo5Kg9I
         d/281K5sjuXLxjmFNIB8Nx20f3kW66T/AZoQbB7aLjHjgsvPhPX4DbucEv8l9YLtLeUN
         chP5W1KlQJqedDUA87KKS18c8XMqmbg1FmqcZO3AHNHDFh0jmyOrK6Xb9DYkCx6wpvcl
         nzt5lPOciVrfJVHFFqzveTTrXsWk0ofJ9BfLGmYe4va0s3yq3wmYrxxAslsmcdq1OZ9L
         t8inIvVOE5FFMA/QsVRjrZA1VAYWmtqHfEQwDmUw8lorVoUEPRjmwcg+ZpkGeq5ivbWw
         Y2bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EAVCYXK+qwXTj64iW4lXgFSidDhKD1r7M09orz7ePT4=;
        b=vET9llbFNbG1nB9h8L9ThcX/WzeJ/tSeOT1z8ay+utuqj1g7roQPpqD97Jg4HqNha9
         5PJG2d4kNhxgvgqHacXez4tQB6dfJe0RYQDHcxKrayoVsfBv1ZrJ8FldUp1C5NRXAHql
         VKO/XgT6PukTGDamJfBEa42TVuVa9Rt600LXtnyNH/YbKB01K5/sO0s7FwEcmiQSFGXf
         BKep27s5f2OPtKaP3gqIFdKziw3IM5owj/SlkHTCxxuxLcmIOg9IuWLEoOXiQYfIeXWE
         ls774HcRaBc8lANQp5BHUy+ldNoH7iwsNTdn2N83HdDLtP8cAPnTmIGhrpkGI1D6IW2y
         XzJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k5i20QIv;
       spf=pass (google.com: domain of 3ii6gxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Ii6gXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id o22si1408092otk.2.2020.11.02.08.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ii6gxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id u28so2019083qtv.20
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:58d3:: with SMTP id
 dh19mr23053645qvb.14.1604333090834; Mon, 02 Nov 2020 08:04:50 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:50 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <0bfb63a90126521a6e0ba98b545c7ea2bb37b0e4.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 10/41] kasan: drop unnecessary GPL text from comment headers
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
 header.i=@google.com header.s=20161025 header.b=k5i20QIv;       spf=pass
 (google.com: domain of 3ii6gxwokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Ii6gXwoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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

Don't mention "GNU General Public License version 2" text explicitly,
as it's already covered by the SPDX-License-Identifier.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: If0a2690042a2aa0fca70cea601ae9aabe72fa233
---
 mm/kasan/common.c         |  5 -----
 mm/kasan/generic.c        |  5 -----
 mm/kasan/generic_report.c |  5 -----
 mm/kasan/init.c           |  5 -----
 mm/kasan/quarantine.c     | 10 ----------
 mm/kasan/report.c         |  5 -----
 mm/kasan/tags.c           |  5 -----
 mm/kasan/tags_report.c    |  5 -----
 8 files changed, 45 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..33d863f55db1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/export.h>
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 248264b9cb76..37ccfadd3263 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index a38c7a9e192a..6bb3f66992df 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..9ce8cc5b8621 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -4,11 +4,6 @@
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/memblock.h>
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..580ff5610fc1 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -6,16 +6,6 @@
  * Copyright (C) 2016 Google, Inc.
  *
  * Based on code by Dmitry Chernenkov.
- *
- * This program is free software; you can redistribute it and/or
- * modify it under the terms of the GNU General Public License
- * version 2 as published by the Free Software Foundation.
- *
- * This program is distributed in the hope that it will be useful, but
- * WITHOUT ANY WARRANTY; without even the implied warranty of
- * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
- * General Public License for more details.
- *
  */
 
 #include <linux/gfp.h>
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 00a53f1355ae..d500923abc8b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e02a36a51f42..5c8b08a25715 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -4,11 +4,6 @@
  *
  * Copyright (c) 2018 Google, Inc.
  * Author: Andrey Konovalov <andreyknvl@google.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index bee43717d6f0..5f183501b871 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -7,11 +7,6 @@
  *
  * Some code borrowed from https://github.com/xairy/kasan-prototype by
  *        Andrey Konovalov <andreyknvl@gmail.com>
- *
- * This program is free software; you can redistribute it and/or modify
- * it under the terms of the GNU General Public License version 2 as
- * published by the Free Software Foundation.
- *
  */
 
 #include <linux/bitops.h>
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0bfb63a90126521a6e0ba98b545c7ea2bb37b0e4.1604333009.git.andreyknvl%40google.com.
