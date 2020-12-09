Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW5MYT7AKGQEGC6XU6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 652DE2D48D8
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 19:24:27 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id r8sf948818wro.22
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 10:24:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607538267; cv=pass;
        d=google.com; s=arc-20160816;
        b=I7AmW77sDWgbQPUfMbNnHMkzu6BpTNAahP7iTq7ejJpbfSqcxH31gTiQAuE3She9Lq
         zYdpKAHFbV7T6CYBqC/ODkndLpUPBJ5hZqrxXUyn184xFfOOhXCcRY2ZNvD8QcPVecXr
         DAN+M4NkW4M7doynJnYqiMcPWYnOgFIM9eEBR3Oa9ch3H1/ZgFSl7dDUBdPJXyKKE1gz
         JBJb0xHFilMtf7mED53WM7oJFdlvZ/+hqbxbPEav03IZEGarhkxU8BbAXLXCtHtY1Omz
         OGZ6YM9nGnabRfzFZKs6hidNsvFZNRgn/JoQ5zii3Yc5NUqLju3T0chgV2uV+dkFkSb/
         WXqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6qnGd/wc+PfF1UaoVShqHuZMGo2Ql6X+B2C2QFuQLD0=;
        b=S2fjQe6gtUglXohOj8ZBMA0jCFEOzYp7d2riHrNh2JbcWduwX8Lwtuep7rAoTXvsa+
         N5E6M8IEYan48JuaR8gDwmpWEU5l4E7l7iUSWz5d6aM+bL99itycNM8dRccG0FXASa4c
         TEosCVEmuzBoapHEERHx/X8OYzuuWEMQhLl8lAt8ylMDDx10z9oyVND2anxYhAS9ePn+
         cXX7ma8Xt1+SXdA2xr/kx3Id4ZZaYT9PUHmKd2DS77Ap/IOO5MlXvAlgW6TZCsxMLgZf
         zzUJhtxZ+dGOLPdmKL8J3gpruXvTa56zcqtmMR2bgmVA7h7/Y8Yg52FcMAAxwp7tbtl5
         GIbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sJrzjf+r;
       spf=pass (google.com: domain of 3wrbrxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WRbRXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6qnGd/wc+PfF1UaoVShqHuZMGo2Ql6X+B2C2QFuQLD0=;
        b=e4qEhujjSwg7EdiWFxY2qvRNe2ILJY/jyR9gb8F9fzuizmdA1OJmEgDhNttGfQsJg2
         RJNxNJoSqjQTg59I1ur6meTDVegkjP3qL7c+tDv3dfXTm67ADxcMeGrcKUIg1H3urGI6
         gyYR5hfXiKuMkJ73O4oXWPu0wQhYqkEmsvyk9lXHMgruLF+Zk6t6yL7bgwsEHT/Mnhq5
         EPY0X104H/H6729a6+IkNfZQugXZFGPqWTjLr0278hKDdU1CksDirpJzvuDEPLaQ6167
         zHn7nMV+KnC2K6SrLYJdPGmPT9TtVZL+EneMioSB9zqZpcCuoY+8HkwV7ZXj8l+gTTxk
         vuuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6qnGd/wc+PfF1UaoVShqHuZMGo2Ql6X+B2C2QFuQLD0=;
        b=csePurLlCiUE1cmSNm6k8KsIbUo/7T09ZvhPTG+rKZTPpbvRsaUBG1djrGP67silUS
         QpSQIWGy9FtaOeHKhFcXrWba2UdS76WXGpkQ0PgWx3PLHqJRiI0tf4G5sYdrXtkDfuCa
         siR3cds6jt/f+UjxHOBucwYS6ZHnl12iU3dZTKUX4BGLZtMWFs4FNIfFou2RBn16aitl
         f4MTFJi1CAfjAkQF1wWGqT61QGEWjP45ImHVor2n5tVSNzP5dzDZMP/CQ3JUfdevz5OC
         MzDWQk+vAgP0pXFbOdvQgycLnxBD4bgJkgmXcFN4+bCcrtH4DYe1p1iag1n7M8lCljI3
         mP0w==
X-Gm-Message-State: AOAM531BN66pwrNLzNhog80JTyBH1NtGB0uSh6biE9AvGR5BOqNNUtdO
	ObQ8akZmpyG3eizcdh0kuy0=
X-Google-Smtp-Source: ABdhPJwKqlLrG1Mvv7Xf5WIS1oz2mHd7Uys/0nufi6huM99loLcXu653LfLqYWlRH36pMuiDEXl2Kw==
X-Received: by 2002:a5d:4c4d:: with SMTP id n13mr4139248wrt.356.1607538267183;
        Wed, 09 Dec 2020 10:24:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb0e:: with SMTP id s14ls263239wrn.2.gmail; Wed, 09 Dec
 2020 10:24:26 -0800 (PST)
X-Received: by 2002:adf:e5c7:: with SMTP id a7mr4155087wrn.300.1607538266354;
        Wed, 09 Dec 2020 10:24:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607538266; cv=none;
        d=google.com; s=arc-20160816;
        b=py2g3Q5GMKcEwhRZFenbTiZU+H/7MEWfGJRcmMmZ0a7TIYwguCWrpsj5kWBRTTD9CO
         +r5oT64OzdNbW+ppeeok5+Ma9UVaO/xiDH6QMEKnXEaSEum/T69Z4xw1F9XDrt0W7Vme
         92itNnEFvNQAv1Z1U+ecrxGpCoqaBY27Z8yf2KaneNRsw7C0HbEQdVk/7TxbmC+401+f
         gR1Ax8+yp89TqrGbdITm4gJziwNxXGqAb2KQ6y5c8+WvTx3GbiMbAKPUNwCE6k9MVJls
         zaR80HgftGUoBDrXXDh78v1MprP/P3KhnH22AWPWGodd47QuxjbrybifdYBfwe7/OEW7
         Xg6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=V2rDh/PTRpe6NWZnEeAWnr3LbupuxXOheZwv6czKP7I=;
        b=u5t2s3PistFU2TdCW4OL8SIsCKo4/0W3rwJfh4aJcFQyuxidrqvKbDEe6S4GmxF2EL
         BoHf3NL6JZJGW6Rufh01VfpK1VtRUCGuKdDGmO50i34sW1l7URsqgCd6yVwU1RvVA/5g
         pGYVV256ioT6nTU7MSv3MavkaKF2u9S8cgNaFh7pE0L6TmC1PeTF3N/K08hIu+oZrqbW
         yePyWaaU8/LNVBnlGIJt5rr0ZjhFcKNJxFfE+IjA36TFCDc8aE2vVugpExI1Xpt6eNwO
         D3xoPJCrNqL8qsZOvHHJc9d0WmW2kMa1jobwyaYAEBtahS4UXGp+1iCoj93Pk0AncC3D
         66TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sJrzjf+r;
       spf=pass (google.com: domain of 3wrbrxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WRbRXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i206si83313wmi.0.2020.12.09.10.24.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 10:24:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wrbrxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id y5so962609wrs.15
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 10:24:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e710:: with SMTP id
 c16mr4123641wrm.295.1607538265727; Wed, 09 Dec 2020 10:24:25 -0800 (PST)
Date: Wed,  9 Dec 2020 19:24:15 +0100
In-Reply-To: <cover.1607537948.git.andreyknvl@google.com>
Message-Id: <f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1607537948.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.576.ga3fc446d84-goog
Subject: [PATCH mm 1/2] kasan: don't use read-only static keys
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sJrzjf+r;       spf=pass
 (google.com: domain of 3wrbrxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3WRbRXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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

__ro_after_init static keys are incompatible with usage in loadable kernel
modules and cause crashes. Don't use those, use normal static keys.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This fix can be squashed into
"kasan: add and integrate kasan boot parameters".

---
 mm/kasan/hw_tags.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c91f2c06ecb5..55bd6f09c70f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -43,11 +43,11 @@ static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
 /* Whether KASAN is enabled at all. */
-DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_enabled);
+DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
 /* Whether to collect alloc/free stack traces. */
-DEFINE_STATIC_KEY_FALSE_RO(kasan_flag_stacktrace);
+DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
 /* Whether panic or disable tag checking on fault. */
 bool kasan_flag_panic __ro_after_init;
-- 
2.29.2.576.ga3fc446d84-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f2ded589eba1597f7360a972226083de9afd86e2.1607537948.git.andreyknvl%40google.com.
