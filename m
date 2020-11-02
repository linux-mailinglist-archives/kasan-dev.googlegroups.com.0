Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO64QD6QKGQEQU4GH4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B7482A2F09
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:16 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id 204sf5450168oid.21
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333115; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bkcsd7zIWJ8l93Ib8k8IGlkR6qRTKc9jKxE/VHTog+4cHw2AoHZUFa2jhikgzVkJjQ
         IURy7gWUDDDiEvPxvTqk8Hrkupzamiws2VMquUx+pLOsbMHdPhwLajvbavFnT6O9WFZx
         HPjb+GFf4VNhid9Hqin3ULVNuaU8oOq20Gei51dRi/wZpG4KvNrMUTM9dXjUYy/LZxLY
         o/pLjE+l9D3TMq7nN29vze5kpR+9Sx0vlmLo63T772DFwC7KvpCMQlW6eiyJI/SY2Ldu
         8YR3A+5ogL/M0179DskagVZfJHPhrB+rJq46EUvMA5MFQMVxZeAdx4d/pVAOqw9gSMx/
         Hwiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tQ4qRGu3BR4Q0UKi/QzZZcdVLcecqz2jPVYZkSxNMKk=;
        b=dbDRSzm2oDMvBu3XTht5Qnog/io+F/TPKPvxDxRFkvSXwJY8NeaQwwKVtlJu1pY/kT
         siBOb6LC/ifnfMZLYpe3fVVmHTxhkZ8fnh+LS1ryPxSvodZQDyAiEkW0FgULgX99voSH
         Co8roO2oOc+H9PDgKjl8/v4LlR/Ig6nG7gQ0QduWlKWDc33hpobDTVu37AjOijZL7YDQ
         00Yxu3n6Knbsa4bfbmPfU7zHu1PVaEU7+XbXivq0nYQNGqALV5F7xCsWepNBo0S/5sZ/
         iAMZPrqac5UoSFTH2gupWkeMxefyN5pwi0KKStFP7A1o6fYZnbc7W4+YDS8pxtGgyqxy
         A47A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H4N1zniD;
       spf=pass (google.com: domain of 3oi6gxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Oi6gXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tQ4qRGu3BR4Q0UKi/QzZZcdVLcecqz2jPVYZkSxNMKk=;
        b=nNHS52TfYikCYnik5FQRWajJZ4Qt0GNRbLzWlqxoXtnMlrfk6vMgcrLN3iDJ/kcAqD
         96ixRINlg9cla8xiS80Odrl5L7koS3AaL3zZl65HlGA1GHcrF6ZAnreN6EKotFHacD/y
         BADLbbmulJ3rOMI7l/VSPp+Z1sfwxoghaYaJkeaU/X6IjdqW0cSEPSJG0To0/jafXX04
         BlsAQqxrKNmwzG4AeMm8o2Nh4uoCaoP0+kVowBCVrdDW//AomNbDlO3UXNVrIAVuzIQb
         KL5K/jG10Z1iu1K/X+i0HCdEGWkumH99v1cZs+Mk9avZ5uYda0GL1jWoaHIMi4fBH+hy
         RbCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tQ4qRGu3BR4Q0UKi/QzZZcdVLcecqz2jPVYZkSxNMKk=;
        b=SvdstOPOhm8dinsWEGns86vvmHwjoP8CDlo8fVP9VjbRMbAsYb7DNMCFy/gixVqY5E
         hwKrp6tO41WLlV5V6p9B2lZ4TkZyXPBUeH5gYFDzJ5gBSVpWFoZa0en++mKJSdhJR2vl
         /Tb3/wOykgn0tgfjg8h7xhAyv7m7Inj99WWXtDcD0H0SbXM9o8kVi6seddbMw8thvtey
         RXU8v2ukUkVpA3uqEiNtoQdMRS/BWv32kj6ccWrn8KDpGuYReqMHFLLXi3vzogz/7Uug
         rHjPwsG7M3qk/oC5By9McuErCtw/RtqVF0ZSTNuyNad91wmi7Qfft52B/0no/b56TVRY
         kj5w==
X-Gm-Message-State: AOAM530smb7k1tizocad7HEYQHjQhMTKzOrgugP6OEXIKlIktExL10K1
	h0XWSSY7FqU/807Cr2fTpzs=
X-Google-Smtp-Source: ABdhPJymaQyjVv08ZwpnyGq6xtxed0XuiikbouF0u9pI7gZ/lXEly2thDFz8Mp09mjrFWgqSeOvFIg==
X-Received: by 2002:aca:5015:: with SMTP id e21mr1177109oib.41.1604333115378;
        Mon, 02 Nov 2020 08:05:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cf15:: with SMTP id f21ls3459761oig.8.gmail; Mon, 02 Nov
 2020 08:05:15 -0800 (PST)
X-Received: by 2002:aca:b4d7:: with SMTP id d206mr11084929oif.39.1604333114977;
        Mon, 02 Nov 2020 08:05:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333114; cv=none;
        d=google.com; s=arc-20160816;
        b=ldn/w3CW2gIJStBhNUjWIJC1MiJAoLDLy0xObJmCYVd7jQVUZJqaS2Yia1EEttXO+v
         lD2HUZjiS4euop+p/ro45NXmy7Cb8RFCJ2RHbfDdkUUR9lACXsBYCh3blKAUJvyhDrST
         bAXY6sP5DN6RBuGyJHY8JK1Cv5JWS+FlHHlU0aXTtX4zj996Q+WnfBtGian1Ay2IiHWp
         ip/zOvUdFyfFgqSafui2d8ZYb0Acmjs/uosupApZDj5mmCL56B5VFWmAJxfwSY+DjsiN
         WvlH05NAcQvJUxR+lDZ6flNczoR9e0WhTLt9Hpw6rrQ70j6IuZkcXwPVRQCax92CxedM
         lT2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m4Rd6JEchDCdHagjRChT+nQsGKSwHG57Cfn+FHFZG50=;
        b=pX/DdT09Ku+K2UG6zpta3ClPFoxf0sXXlOz76yvR3zT7fLbkjWBdk+ZOkvrzYmgxup
         o0+Iwfl0alZJ+GY5SNOT2QraLPHjk3ca+V47I6UeVbm3LHI8zhj8v/4loRrs65tKBR1W
         +XcMKMiQxToIOsTxwEuUXgEXtKKogMFLvTR6Xeyl1yYYVShqlI8oiYj/CADa9sS7di13
         ZHRsHXxWtztftDltWxkQCJUCG0uFkVlT/HeTztZ+Ri0WqqLXW1eBhu4f+xuiqB6vaz2O
         L+I7YkrSjDgV9xUpDG/zrSkpXSG0bL6h3wVbozcL9i6RrCVWQWBqoTZ/eKVwb+cuX1eW
         rVcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H4N1zniD;
       spf=pass (google.com: domain of 3oi6gxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Oi6gXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id d22si1342219ooj.1.2020.11.02.08.05.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oi6gxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id dd7so8456489qvb.6
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:14 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e70d:: with SMTP id
 d13mr21887401qvn.45.1604333114420; Mon, 02 Nov 2020 08:05:14 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:00 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <11c5c70b6c365cbf6a02e326b07e0f088544670f.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 20/41] kasan: rename report and tags files
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
 header.i=@google.com header.s=20161025 header.b=H4N1zniD;       spf=pass
 (google.com: domain of 3oi6gxwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Oi6gXwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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

Rename generic_report.c to report_generic.c and tags_report.c to
report_sw_tags.c, as their content is more relevant to report.c file.
Also rename tags.c to sw_tags.c to better reflect that this file contains
code for software tag-based mode.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: If77d21f655d52ef3e58c4c37fd6621a07f505f18
---
 mm/kasan/Makefile                               | 16 ++++++++--------
 mm/kasan/report.c                               |  2 +-
 mm/kasan/{generic_report.c => report_generic.c} |  0
 mm/kasan/{tags_report.c => report_sw_tags.c}    |  0
 mm/kasan/{tags.c => sw_tags.c}                  |  0
 5 files changed, 9 insertions(+), 9 deletions(-)
 rename mm/kasan/{generic_report.c => report_generic.c} (100%)
 rename mm/kasan/{tags_report.c => report_sw_tags.c} (100%)
 rename mm/kasan/{tags.c => sw_tags.c} (100%)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 7cc1031e1ef8..f1d68a34f3c9 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -6,13 +6,13 @@ KCOV_INSTRUMENT := n
 # Disable ftrace to avoid recursion.
 CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
-CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
@@ -23,14 +23,14 @@ CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
 CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
-CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7b8dcb799a78..fff0c7befbfe 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains common generic and tag-based KASAN error reporting code.
+ * This file contains common KASAN error reporting code.
  *
  * Copyright (c) 2014 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
diff --git a/mm/kasan/generic_report.c b/mm/kasan/report_generic.c
similarity index 100%
rename from mm/kasan/generic_report.c
rename to mm/kasan/report_generic.c
diff --git a/mm/kasan/tags_report.c b/mm/kasan/report_sw_tags.c
similarity index 100%
rename from mm/kasan/tags_report.c
rename to mm/kasan/report_sw_tags.c
diff --git a/mm/kasan/tags.c b/mm/kasan/sw_tags.c
similarity index 100%
rename from mm/kasan/tags.c
rename to mm/kasan/sw_tags.c
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/11c5c70b6c365cbf6a02e326b07e0f088544670f.1604333009.git.andreyknvl%40google.com.
