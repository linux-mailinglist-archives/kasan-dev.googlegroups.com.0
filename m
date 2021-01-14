Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSF2QKAAMGQEC4O6C7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D95C2F6B16
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:41 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id h64sf2265839lfd.18
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653001; cv=pass;
        d=google.com; s=arc-20160816;
        b=reG2O8MheFZLfj01a2SEulWMuGygf4np2BfQQnS15eb0SrD01t0I8FhnfhxAVZSboM
         rNeaojOLOH2kAxf5o0rpi6CZTbWjEeg6hh0xsNzkUDq/5Lr4kNWBv2Z1BytXLCNBIruG
         mR/oatkmkRuGmPgoBc7+9DsZ8+EcIJBZMMTCnhOxx3ICVHP7TFk2WGQGC1S9itChWvZF
         IdxJ65MGpGYcjOah23CMfzWyFfAe287IL77lbejQPTQlpJ7zRvscsTIKKDhVWtl9ZfY/
         Q25UaPhC/YBlmSlG0WmKVx+SXKkH4JmdKBWsG6UifWuigUth3SSwGnlBlGHQM+Ljerm5
         f1/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d5yTHygx6+0NI1zTBOi7g/Rqu6TIolEqtV/ia5RMJ4Q=;
        b=aVnZ5A3b+7uwhLisdfBl8Am7+qo8Mx3zic107186HnK6DwHeny2ECn0ntEim4C7dCW
         4cY9ZIAhB3kV6RRixVM710Za5KU4r5xzUvNcMH/V03PIA4X2uAGU5ZRp3O02VoguxLcb
         VWuyCVY8lNuOzVIRFxlBWBAEbpeJbZadE2WxYWOONwQNpWT0TuIlFwhyisS6DfqQellO
         z1rogbjYBzDR5JZ6NaN5thSCQWqJ/c4W6oC0jUpDDWeAvESMDPmT+Aw38NS6RWBm31so
         wBJenuwErCg0tgUik2Mt8PaFMnlwzY+kqF3F5uwD2eH+xR77eelAoTE3OfDAR56LIbXQ
         x/zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HqcwClnA;
       spf=pass (google.com: domain of 3r50ayaokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3R50AYAoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d5yTHygx6+0NI1zTBOi7g/Rqu6TIolEqtV/ia5RMJ4Q=;
        b=oOdYkS+xLnhvYhx0w42bVcO5I/GkpfUt75f8uSae91ilI1yOZ1tSsHSBT0CibUyLkB
         haT5qcMbmWoMJWdXuhRoeVS7pfi+hLFJnzSIiCVrturUm54m2tmnbxsYgAxwpnidMwXs
         9sqLwXlwsz9oUkQwAeShXpUtKvudDxja2jdwmILALaHIXSPCUUwAkx2eaodnNPX7Ky8C
         fGYRWvz2j7bWNOAApe2rpdK6kUef/P7BpvrWN/QtGLHK+SMkUrdaHZXSI1qGBbpIC4bG
         36QhNdXs03w4v1WC0wGKTf0C5wIyR5mxkWtmiCpae4iv8Aj/kKxZioVM7ym0lo7TbN+k
         QpLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d5yTHygx6+0NI1zTBOi7g/Rqu6TIolEqtV/ia5RMJ4Q=;
        b=mOuuuuCUwY7q4/TxIOZT0s+/dkmjsnCynY8pH1MbNhWeh5H+uaBN37JAoYffcu4p+N
         VN9yEUnOWvocw53qvI1/taHlMtJhg+I5xrtIOoIXLnqRka0ivc8bCymMqrvmabWgMYc9
         KKY0WWGvE5GTDP5FaDajpMfpNtEFtB7fQsE0Qe+fNW5tTiwMqL5ViagCDqlFrBqXU54m
         tR4Nf3yp10rV+6aaM1ob0eu41jQTKbqQJ51PJPmdFL1xJ2pD4H0OVjT40k4NC3IXMQnr
         dSQgl+aoLu8BThZzROvEdpR2/UtjwpKAuH3AyLUNwI2+G7wPyXiwOma5UZh+ylFbA8DN
         XKpQ==
X-Gm-Message-State: AOAM533JgFT/4E1tufLpCCs5Uic4yDtfzlI9IhYwzN6/Dc5M6guky2Oo
	FebA9ZQqJiV7eVNQaGfEzuI=
X-Google-Smtp-Source: ABdhPJzb1OtY9n2UvKVUHMoNMdrPNt7+iMsuHDSi/fIcDdcRrrPoOevGP9s+V1O9z8Bf3laCuHRBcg==
X-Received: by 2002:a19:c357:: with SMTP id t84mr3821627lff.330.1610653001105;
        Thu, 14 Jan 2021 11:36:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b549:: with SMTP id a9ls1145026ljn.1.gmail; Thu, 14 Jan
 2021 11:36:39 -0800 (PST)
X-Received: by 2002:a2e:996:: with SMTP id 144mr3838750ljj.341.1610652999788;
        Thu, 14 Jan 2021 11:36:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610652999; cv=none;
        d=google.com; s=arc-20160816;
        b=a+3TN1CtQmYw8oQwHlKY6LE4zPlz5RU9CJYKspbVHrSmbfB0xh+A1oyL5hGMTKwPlA
         NlkA8RSukHlKUIcvYDRS1/S5N8FFdM8gyDBMlNaQv3jYvfjm9LzXpBqCTvEa4WhOlQ5O
         uJd4JOax0U90EXO0Mk3qu2k43zq+ja+80WCw1mJFn+BPkQcKmQj5o983rnGk/jzITLIR
         ebIZp9OQ3c4Gj5UXaLwc2NIXOLeOn8yGCFZCfbs9AnYo4GKvB/6irCxDaaXzL6Xwx5HU
         TgHRTAN+TitTTCV8W92JJtPsrtcmZrzOXWvnv9/JIiNwlRmTtAnWm1FmxuiuDU31+rtw
         xX6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d+lRqXXla6mV/kMKnUzgl/DAB69C3QZUVHCf/SWSD4s=;
        b=PYwi8xvOsshT13/9mywV453ocGD/RypOk8nglekXU0XLuA0QWUIOUwqh6LYSMhBxto
         5oG9eJ8P9TQPA855R7DG1kRM/keJL1qt0UnoA8sUEROT3zOCia+hzQ5+q5uCzMZRrQ3r
         fVAYdu/1G7/suMTapz3NfI54iAupeIMrCuBPLOIGP9LHba2tjgwgnBt5mUuynIbQaFfA
         TaV6sB5c8KOVWim5IA/RT+a1nsq2jjp+AYzv9jU18jTsMWpi9rIFTNC7YzeqcCth8WSM
         npa5QguNw9CzuxPIyMi5RdfepG9U4CBJd+m7LT1iMO1ghsCq2qU5IkSf5vRqqHsIid0D
         Ia7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HqcwClnA;
       spf=pass (google.com: domain of 3r50ayaokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3R50AYAoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r26si295289lfe.8.2021.01.14.11.36.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r50ayaokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u29so3062836wru.6
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf3a:: with SMTP id
 m26mr2355477wmg.55.1610652999318; Thu, 14 Jan 2021 11:36:39 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:18 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <2ae5e3db477b08bddfe36a5fc7fb10955cd49f95.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 02/15] kasan: clarify HW_TAGS impact on TBI
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HqcwClnA;       spf=pass
 (google.com: domain of 3r50ayaokcyoo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3R50AYAoKCYoo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Mention in the documentation that enabling CONFIG_KASAN_HW_TAGS
always results in in-kernel TBI (Top Byte Ignore) being enabled.

Also do a few minor documentation cleanups.

Link: https://linux-review.googlesource.com/id/Iba2a6697e3c6304cb53f89ec61dedc77fa29e3ae
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 16 +++++++++++-----
 1 file changed, 11 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0fc3fb1860c4..26c99852a852 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -147,15 +147,14 @@ negative values to distinguish between different kinds of inaccessible memory
 like redzones or freed memory (see mm/kasan/kasan.h).
 
 In the report above the arrows point to the shadow byte 03, which means that
-the accessed address is partially accessible.
-
-For tag-based KASAN this last report section shows the memory tags around the
-accessed address (see `Implementation details`_ section).
+the accessed address is partially accessible. For tag-based KASAN modes this
+last report section shows the memory tags around the accessed address
+(see the `Implementation details`_ section).
 
 Boot parameters
 ~~~~~~~~~~~~~~~
 
-Hardware tag-based KASAN mode (see the section about different mode below) is
+Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore it supports
 boot parameters that allow to disable KASAN competely or otherwise control
 particular KASAN features.
@@ -305,6 +304,13 @@ reserved to tag freed memory regions.
 Hardware tag-based KASAN currently only supports tagging of
 kmem_cache_alloc/kmalloc and page_alloc memory.
 
+If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
+won't be enabled. In this case all boot parameters are ignored.
+
+Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
+enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
+support MTE (but supports TBI).
+
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2ae5e3db477b08bddfe36a5fc7fb10955cd49f95.1610652890.git.andreyknvl%40google.com.
