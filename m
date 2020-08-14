Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDET3P4QKGQEDPLSISA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D2F5244DBA
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:40 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 136sf2173580lfa.19
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426060; cv=pass;
        d=google.com; s=arc-20160816;
        b=jcQvf/y/f0xuOvxustEKjzKCa0v14WmzumrYkSvSMW4sTAe0PC0BJptb0/1woxyTta
         vWmhU51uJlSdUQgPuwn7BAAD4Bi4Pa9vxlyVpnQYL6OHDaGqpbZJ7tK4xjrl8U5cTrY7
         1aapNlF/8YrXPighfZKQrttHTQCltAdZC84F2nk+nePpqgpOBczL5RCXpXTMGrIRSxVO
         DaV5457HHiLDPe7T8YR+j1j1Ct2RZojZszoCSYzt6K816OSmK5wakcCV7gn+y5rThaLX
         DSytCaGkOH9zkRtWoyv8+FiM6eFA9XlSDYKGdbTSqNmIE3BcDtoI1toZsrot67FqI+dX
         w3Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=y4Ytm+4UYCmW3Hsti05Z6DF4vZUaHZeRKheLPtaLx3g=;
        b=EQy3S6Tq07EyFoOOMSWiMzt4u7W9pXGxKFZ4PUh8NDb1/vD28CAgDGPpFev3njN8Hi
         INNXw/PZi8F68gVnqcB2u0KbA0aBaUDep6DSb4UsuQXP0DOkgBYYRI77Be7mRsrqgIkm
         lELS30ldkJYH4uKtnwPpGDxy6TCrMnQGPeB7FvDr3CioUiF9CjVvYY+n2YUdKwvCFjeO
         np+UdetNE9rGwb3Ge5afBI96wCQIgj82MUUgPBnRYPs/q9aV+zih1cq9UIL/sDXhaqYq
         UKOvIIMfMidlYHe9MOfMOcio/HByda4hgwf4MoTYGKw2kqk2qNLd7pIPGatDyiS3sTaM
         NMfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NlQYWVk4;
       spf=pass (google.com: domain of 3isk2xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3isk2XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y4Ytm+4UYCmW3Hsti05Z6DF4vZUaHZeRKheLPtaLx3g=;
        b=YpWiHQiMDzBk8ik+/RghWZ0Wmoafn00u9rJqZ1wjcaExOMS4nkUD0723MnoIvile/T
         YFYlKEG2fdGbTgafidFWu4N67bJGsI/fxdiSWdxF0vGbBgOgqNr/lBFtZUhIDhnv1KDC
         +73E00+ekKAIuPf0p5bX3sk0DJRO2BXkcSOftIDA7NH3+8F3xK61WpAIHVmjoX7rQu2U
         9aViuJ9F4VzKhCm5GhB8FNgWlv42nUE+GTJ2Fg5+HEzYo9cw7IMNJrUFIXldtKW/Tk51
         Y2iYHvesAPfcWbkTHHfO/hOVIzDhtoNZHx117Jik4ZLi5rq/cQKlKs6RBiA28fgCglxi
         pn2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y4Ytm+4UYCmW3Hsti05Z6DF4vZUaHZeRKheLPtaLx3g=;
        b=aq6Kkd3DrJ4GYyfabznwMXZcVrec1lzkHxCJfA2GHLeGX5dJTBBDVRe0qYu8IHie6A
         k4JCPxTgbt74NW4N2/f/5q7Vj//m2AKGCCFBhpyBghHdaWD/BdoYpAIPLR/pJAKFzdjs
         E3yqe/E/gi1fBKS+aIo62QriS2EjcBN8Xcyj8IAmLkmbCkbxJsua4XWb5NHAq5KUGVW8
         9JZgjywS37+B9Gs4lniRayNQSuFVHqba7eiaPxdNd60a/vx6Z3bdqQv+dvhBNPUgIAoK
         corqE8ZNumznZkxO7oSf7eXuZMKYTFQDfG7N/XjNXvSJdiY3+zVnNhR8spV147sWnmij
         oZXQ==
X-Gm-Message-State: AOAM530u3txuEthBNQa+SPDm7WAEqDfhjDiCnoXs98xM6L+u+2rl0e1u
	y5RcyJBMxbwA1yqknfwiUSY=
X-Google-Smtp-Source: ABdhPJxt+JT6CqKIr36XdpLTd4okJCWtasoehME0EIsRVR4wlFrcEJx461mso6z4uB7hRMHzJgezkQ==
X-Received: by 2002:a2e:9595:: with SMTP id w21mr1849000ljh.334.1597426060118;
        Fri, 14 Aug 2020 10:27:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4845:: with SMTP id 5ls246953lfy.2.gmail; Fri, 14 Aug
 2020 10:27:39 -0700 (PDT)
X-Received: by 2002:ac2:568b:: with SMTP id 11mr1718455lfr.87.1597426059511;
        Fri, 14 Aug 2020 10:27:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426059; cv=none;
        d=google.com; s=arc-20160816;
        b=NvB8yctaTvki1PVkpGZWwsVKwoWoFOadhvZ7At/VquNl7EpZl3IIKsr9p+5SETOImX
         X2j0xGnl3VaTqXxQN1EwkZoNvFD5Aj7X6XDvFtTaw1dZPlq7KL7iKQiQEjC9DDNDXGfZ
         C+FP8irRTm00qFA5zvIzLCPLThkxN3qG/HCoNXZ/9KeVIMW30ODhk4DoyXptjmBE9BTp
         boK1jJZ/7Y8u4AX9O0GBw+C7ujtsZEWcivFcxyI3GiKX+/czj/sQyUZ34hd2dRBLoiB/
         SkiJeNnJtlMpvbuTXEK/VP3oJpOjDaazwz0dbjgORx2yaAv4Xs3kiAmn4qbPIpzp862W
         7H4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=D1t27xMSdSDZAXG6XnkOmwCyZLvn/GNAn2saMjUMSxo=;
        b=Rgxp3F860QyCaX3cAvhzVTZ+DYCVH4B6LjHwAaORy7jBaFpE8sR1lamdc+4GQE4Ggy
         XxekOX9sGpyNJO/5gsKe+Fcuyi+eeTH8aVhwYIynm2O7VfHSduSjRMlLlpeFgvcRUAUw
         /qKFa4n7yN5/5wmff32kpIQFVJ2YsVZv6m8xYJUt4xCwHaSKTe5zs0xLqtbDMz9Z4dM/
         nvp5KdYIoB9tegDel50bQ3LG+oZAo/quCYU0+38GurCL9ImesP8937rM/lEjvLDKlPBm
         mAmz7hhcvXhSQvkcO25wQtKbrtAWIsOCSdzV7/pgYNEqOdbMeOS04nxXeu6e1LefogoO
         ne9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NlQYWVk4;
       spf=pass (google.com: domain of 3isk2xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3isk2XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id c27si566662ljn.3.2020.08.14.10.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3isk2xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e12so3602007wra.13
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:39 -0700 (PDT)
X-Received: by 2002:a05:600c:c3:: with SMTP id u3mr423906wmm.1.1597426058434;
 Fri, 14 Aug 2020 10:27:38 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:48 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <f6f402d4f5251f7413755724e2479e2042bf01e8.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 06/35] kasan: only build init.c for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NlQYWVk4;       spf=pass
 (google.com: domain of 3isk2xwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3isk2XwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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

The new mode won't be using shadow memory, so only build init.c that
contains shadow initialization code for software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/Makefile | 6 +++---
 mm/kasan/init.c   | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index d532c2587731..b5517de7fc87 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+obj-$(CONFIG_KASAN) := common.o report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 754b641c83c7..20f5e1ab8d95 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains some kasan initialization code.
+ * This file contains KASAN shadow initialization code.
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f6f402d4f5251f7413755724e2479e2042bf01e8.1597425745.git.andreyknvl%40google.com.
