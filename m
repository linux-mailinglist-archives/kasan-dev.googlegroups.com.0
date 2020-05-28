Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYPFX73AKGQE7YWXQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id B7C1F1E688F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 19:20:34 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id f1sf726170qti.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 10:20:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590686433; cv=pass;
        d=google.com; s=arc-20160816;
        b=SpnEp2OHYdV+DNyxI/V0K5Hjl4Uzmqbj7qDnwWdiDB4s2g0QSbLHqIf+h4MZDKRGCV
         lEfp2GsUKt/jYj4ze5SwLETYM6Ub9CFIiAUM3CIgOHMkbqbauL7wfTNV0PT6rU6zU7ZK
         GzZj6DgC03BCrCs+KPPfB9feGxHR9tRa6I/aVHNIE2WKgxhizakSawy0hZgEYbaEBCM2
         jxdQRRn/hu+zNs/uPtKDY9xHd8RK/rVIK4/boADQeAkj1JpE0xNJqSXmwtOPMUG7DAgz
         V+P2iNO0GkXvD0ardCozwwKVzb7Rj/iw8azHNNpjSi6UjWhVxzwfQkUmlZ7prCjf98ep
         V5fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=djXTzcP1E8Aw4bYqqWaZEI/IfxUc7j6wi8h40+9GczM=;
        b=eE4Kzb7N0j2t1OkNkHUMr7fXd9LKwzZb50MYqPnC1OjOLIyqwYPyGa3rXWxPCTVYuZ
         WWLDJDHfj8nMuLjnN6fAmNp32CB8Gq2G2zrqJ/ReBEYIfXm4F5rgSDS3jEkFdLWdNypn
         /w6qEJnDDStxrLKFyk2/zKv0cbDXmPwHMLQvnAZ/5xqW/+hR+QDTxkiAwriWoe2t8TTo
         jcz109hvoL0H7ygALvFwPGIxSCIygh2MWzJNetG3yDOCa5YXJnfh0ZsUOqVGXj4ATyWe
         eDUlL0LCGkd/yrC0ucYv5C7CMq4OaJSCAuCb7EH0d0eIhtFVO7/1//bNec8T3nMWFUmG
         /vXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cxS6qz7n;
       spf=pass (google.com: domain of 34plpxgokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=34PLPXgoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=djXTzcP1E8Aw4bYqqWaZEI/IfxUc7j6wi8h40+9GczM=;
        b=ingdgyOjjFR+YoeMX/OUacYb4joloR4wkpqoxOxo5FGsdUhCMWIZCPfEZfjCHjg3nU
         3of9yyo6DkR7fanKQkf+caXpg217uNlt5KFxyuiy58mCIUeWc4STS7WrFY56gTF7Bdpm
         ig9wEY/AqjGoR1YlWqHusRa64HA+hNUcfzQBAb2pFUWVXKcOgxfeXpgXXbE8gN4NLbkU
         /LkYAMAfQ+NxlgQ1JiNXXF+Ds2NmLiRlncaFM0CygyFLYp2jhZoxNuDbYenmqekwfvWz
         hvffdBSXnabLC7LooQ1ckOmI5XoovmpzR6BGcs89IGjslj7BlwGGLUpaCsE+ciOe9AKI
         cOCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=djXTzcP1E8Aw4bYqqWaZEI/IfxUc7j6wi8h40+9GczM=;
        b=Z/jOtWMSkDdgt1UE4be63XeNNogQecFqcMOcpUZPPZ4S8AvjJFBoLyhp7Jib4r2JgB
         ZLyZknC0NDEr/VyeJpp+3eq8HbZB3fwDVVl92912sYcWpJ8tXpfNLyvqzAm07Zz5P8Rm
         O96KGsyvzFwtmMsGjh82DHZq73Py79gjo5TJASMmX+uR/p2JNuW4Q+s/Rt/pGzGtRRWo
         RBQC/SM5F8CQvPVD1nJDHlH9rNg7DF5NjNpwhVmYiVCyOdtGMnT/NYew1L4j0yykKoM/
         plxcTekQyQhbMA6EILv8/XrCPNtCApVBVaLE7NmTzXiVGdtb0NqiCE7I/VcdOckIwfHv
         k+KQ==
X-Gm-Message-State: AOAM531Ha8gV2PRcXkGKo48ww/FWF8MNkwZeXey6RMncfVVV1TlpYYBt
	Lr+ckNEm+/zn1pvcRB/3aGQ=
X-Google-Smtp-Source: ABdhPJyDwo6SfgDo3qxbyq1mUeWNkZSFvt9hPvYctfTaY+LcRp5787V/l1qAdT0uPeZ4aFInbKDc7g==
X-Received: by 2002:ad4:4cc9:: with SMTP id i9mr4273618qvz.126.1590686433647;
        Thu, 28 May 2020 10:20:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5608:: with SMTP id ca8ls756092qvb.6.gmail; Thu, 28 May
 2020 10:20:33 -0700 (PDT)
X-Received: by 2002:ad4:4141:: with SMTP id z1mr4109142qvp.227.1590686433229;
        Thu, 28 May 2020 10:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590686433; cv=none;
        d=google.com; s=arc-20160816;
        b=izL3HthrIcPJ8xmTi4ZvH0xQrOZ/aTY0lqFZNXSGxdTb5FE8tOSkbCnrTFRA1MTgdg
         RzkOQKh3FnXN6Ldzlb+bt9zSy9wHf0zNNh1joROJB1hOgniWFRDlEbowLSJ9nsfXm9xH
         92/9/Vb9ph2n0x0qb6aY1V7s54MJuQ1GvAUZ0J1sML2Cwp8DyrL1fageZAHHfjZWqT9b
         J6o+8hw2RRqOi7xnIfqevZtRsvwCAMFqr2N/fnJPgTpFSv3B24Yg5xA+ehTJ0hMHLD+s
         lrmiaDGjDXZ5tafQv+ujlvBtnAVh6ZBHYygppsPF1+0avjHpR42TJwX2hTqcQ40RPlmz
         YNOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=0xESSglLWrwf3x8cJUVzOxtDGHF6QQgQ1x5DUGqwYW8=;
        b=eYd32nGHyifYmu0dtQIscY9e3EoATRBYXVzzw8YffGDPZvTkysmofOyCLhie0JwMwl
         RM2YVSLrgzEHq8Av+/HBFrVfaE4tePJTP4RF0ShYY7qY1wbAAfsEZDIhgADdYgFzPoqm
         /8ZsBnErTdbd2PMTOlndJZLCNZ25bGPcF8z3kQDs+4KFfPV8Olx32GM7W/vhZNB4UksS
         NhoVRVvbf+0zL2GSyGI6XDxWtUxz1IKBTZJh8cFNqwIRnHeQibIIT0n/es43RD0u4RhZ
         ZtVwVe35XeS5DPAUvEVM0FPFbTaO/KxDjg64ai2uAZOe2iuK5l9G7hJGGaJoatZ4/JtT
         h9/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cxS6qz7n;
       spf=pass (google.com: domain of 34plpxgokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=34PLPXgoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y21si475568qka.2.2020.05.28.10.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 10:20:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34plpxgokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id o7so26597594qvm.15
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 10:20:33 -0700 (PDT)
X-Received: by 2002:a0c:c3cf:: with SMTP id p15mr4264539qvi.10.1590686432904;
 Thu, 28 May 2020 10:20:32 -0700 (PDT)
Date: Thu, 28 May 2020 19:20:29 +0200
Message-Id: <ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc0.183.gde8f92d652-goog
Subject: [PATCH] kasan: fix clang compilation warning due to stack protector
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, Qian Cai <cai@lca.pw>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cxS6qz7n;       spf=pass
 (google.com: domain of 34plpxgokcqmdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=34PLPXgoKCQMdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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

KASAN uses a single cc-option invocation to disable both conserve-stack
and stack-protector flags. The former flag is not present in Clang, which
causes cc-option to fail, and results in stack-protector being enabled.

Fix by using separate cc-option calls for each flag. Also collect all
flags in a variable to avoid calling cc-option multiple times for
different files.

Reported-by: Qian Cai <cai@lca.pw>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/Makefile | 21 +++++++++++++--------
 1 file changed, 13 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index de3121848ddf..bf6f7b1f6b18 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -15,14 +15,19 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
-CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CC_FLAGS_KASAN_CONFLICT := $(call cc-option, -fno-conserve-stack)
+CC_FLAGS_KASAN_CONFLICT += $(call cc-option, -fno-stack-protector)
+# Disable branch tracing to avoid recursion.
+CC_FLAGS_KASAN_CONFLICT += -DDISABLE_BRANCH_PROFILING
+
+CFLAGS_common.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_generic.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_init.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_report.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_tags.o := $(CC_FLAGS_KASAN_CONFLICT)
+CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_CONFLICT)
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-- 
2.27.0.rc0.183.gde8f92d652-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl%40google.com.
