Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRFGSWAAMGQEL5MZDWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D0BEA2F9BD2
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:22:14 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id f15sf8022430oig.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 01:22:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610961732; cv=pass;
        d=google.com; s=arc-20160816;
        b=NhXO/FKv5Ot8uKt0uy0jfczuKrbHPLSFmWdZVrxLpBHtYOZ7RFIuPMagGrgaK96eYP
         x/DjbbRy+DGo68PfzYdKe9DHAtzUboSsGi1EMRO+6+wXUkKIhfldIC9SLYNOUaosMiY2
         rhKed0fdf2vY77FazXqB5gSRyUHv1EKSGpNbcPV5xJ6Bg2jdtqe0SbEoayNuzzrf9LPT
         oO2z+MzP61BzrJ51GjjiBdXXiJhWC1lMqCuoK1Ur10phRBpuSdL3jxrcPuzR/l+BS3b4
         aX5sPnJ4Kxc8uKcODcq+DScqtQDOkaG4Du1szM9Anz8VYadGEZe9FjVyUieVZvA2aDIw
         tIxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1bwIOjrGaiEo0UNZwUlyvYk996V7VVQ9f/w3nHl7zU0=;
        b=uEke95u4hc0yk0V7GhIWvzXqWP3QwCImGe4IQdFhUedki8i9xNtcpmBX2kiWtG3JtI
         UQ/VxspL6G4/0FipoCbpqTG8bx/kuyRb3Sf6MmrZPffpf41mhO8rwzVkoYvfOGJzxJtR
         B9VZek2FviTaSOqRxFyIZCDGZnju8DDml7UJaFxmfIyOCOtO61yNaQlgcBcjKKFNkkJm
         xg24wYiKakOXVUZYTVBCX7CEoHKWogpmlGJVinSZa8uKUkT/g2+H+YMyAnusCS/NykXv
         nvb7eaKIJWUHCi9lM1IpkTl8MzAbV2H8uQD4w2NamzQuYuFMKD3cIuTHr10raiXyzzVl
         /gpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ePa1WRaC;
       spf=pass (google.com: domain of 3q1mfyaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Q1MFYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1bwIOjrGaiEo0UNZwUlyvYk996V7VVQ9f/w3nHl7zU0=;
        b=iv6JbcVUpNd9hteLLX5PuRaUww7ZTjoE+tOT9JQXIzG64O5WaK66Xb5dhrldjwY6J+
         yaGGCAVLSW/FrVRY+CDj7i09M9OeC5VU8i3Zhg5I4/BultSOaMc99K87p/KNykojzaOz
         GQ7BIOGDLNg46elVzy11m8rfJiijXPlddNAA/N11JyWtfOnqfY9owhQfYUKqqWOYXW/6
         QrlqEBtAU1SI5B95rS4/CCwbQHZ+gw38ivlXDbss8MuJ/mT8JKtx9nu1E0gLg34yJUgu
         t+P+vRUzUCBhzHLyLgiKwST7pWIGV7KJfNFPzZHOWDx7MnmA3QFIla5N/v5rrW/qO5H3
         zPwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1bwIOjrGaiEo0UNZwUlyvYk996V7VVQ9f/w3nHl7zU0=;
        b=L1oOiaI5WStSbtQ1VoMFzs6hzfkaOIxbthNVIxuCZu/0vgcVFeBCbGSWhR63s3dMOh
         I3taWg0nA/9Ss2gG9UtZmJ2T+vffpBsuANkWzjliSEwS/adbfxdzpMCUgMrnntZ5p38k
         q1Ge7/yx5809jo0O3gCk0xym2tFl8mTHhvieh3hAKzRAiUTT+teYaWy6MnsDRFZGIEPc
         l3CIc0/r7O6GXwsH7ldes492pCeE4eUaqf3P5i4gD7mfRITolPRLJ3YMdHoiQu2uDn8p
         aulQ4wqkh2gCykWtB5Fr4YuMx9dANwFkh71FPIIRVajZo1hENLD8u4JJxmBTIFuCfNry
         cnbw==
X-Gm-Message-State: AOAM532OHIoCZhrIB6nn8M0jdb80Ldv3pozsIe69GttxBaT03ZIKqaKO
	ADf+OYehtD4ikgNck0Z02Ow=
X-Google-Smtp-Source: ABdhPJx6zOrY+WaPYiU8NIntLv0x6AE9pxbcUCyfmek1MQOU24ygsJYH+WVvUP3WlG/umXWRI6Ccgw==
X-Received: by 2002:a9d:a78:: with SMTP id 111mr16593275otg.94.1610961732523;
        Mon, 18 Jan 2021 01:22:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9c05:: with SMTP id y5ls1103967ooj.0.gmail; Mon, 18 Jan
 2021 01:22:12 -0800 (PST)
X-Received: by 2002:a4a:e294:: with SMTP id k20mr16477097oot.82.1610961732188;
        Mon, 18 Jan 2021 01:22:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610961732; cv=none;
        d=google.com; s=arc-20160816;
        b=qKL3yThxCIH2tqSnxHuXKj+kdtXopMedN9iYWRK/8gwvtqegrN23A54NW2DbfOrSGw
         Qjra1IqGh+W7L7yNUhAv6sZtjIZ9OaIidVrTELGVnu9L7eA4E4RQyWsqfIvqxOfjZUo2
         iikJg7n22wZ2BV2kO1PrVhfyfgYUSjqmodxDnbpxAtKhM/gI1wA/CTbLj5sLmF/2rJaH
         9Ggrwxl0chqAPbo7piYtjnT9Is9UkSTE9D1k3FSCIzDbA6XOQhCL/Md2GbOOpAoIQTIf
         hjA6dNllsCkkS5hL6/2eoCR9UZ3mBaDnwL/Xd1qwogpO9mEaZlmfiPpbK9JsXB+uInoI
         zgrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=exfgNhM4N6uxD6xPVxC+GkQm5KFoVDD34vOu2HQsR3U=;
        b=rvzEdnMb1ruK7HhPqMpcEpA0oRRKzpPgwTIZZmOeiBLHbIWmlJ8WjBw4msaHMLYJkM
         CdCZXT5w0afe0033JOUDztdhqmFvrDBkt13Cg4nQKOSdAk+z8nKFYtXr/rxLYy5kxq4p
         p4hjn5Vuy5J3DpeNOV/46KtLrQfuV2Fru3wwymybpfYfAN9+LfjGpSoItIopdTb4/ZM6
         C2JunEYh6FPmrnp5+Uywg8Z3lT4+LLN8gEQNb1fbcrfEnHWXEBdHNf5BtX0lyCXA7v+W
         qIBXb6mZfp6Op+EzKIT8sJXADxTsIL9jhbGtheCsrPULn2tTraL2TRwyZVt36+b6rs+b
         3DGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ePa1WRaC;
       spf=pass (google.com: domain of 3q1mfyaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Q1MFYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id v23si2037956otn.0.2021.01.18.01.22.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 01:22:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q1mfyaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id t18so16006290qva.6
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 01:22:12 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:8e04:: with SMTP id v4mr23462144qvb.56.1610961731717;
 Mon, 18 Jan 2021 01:22:11 -0800 (PST)
Date: Mon, 18 Jan 2021 10:21:59 +0100
In-Reply-To: <20210118092159.145934-1-elver@google.com>
Message-Id: <20210118092159.145934-4-elver@google.com>
Mime-Version: 1.0
References: <20210118092159.145934-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH mm 4/4] kfence: add missing copyright header to documentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ePa1WRaC;       spf=pass
 (google.com: domain of 3q1mfyaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Q1MFYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add missing copyright header to KFENCE documentation.

Signed-off-by: Marco Elver <elver@google.com>
---
If appropriate, to be squashed into:

	kfence, Documentation: add KFENCE documentation
---
 Documentation/dev-tools/kfence.rst | 1 +
 1 file changed, 1 insertion(+)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 06a454ec7712..58a0a5fa1ddc 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -1,4 +1,5 @@
 .. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2020, Google LLC.
 
 Kernel Electric-Fence (KFENCE)
 ==============================
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118092159.145934-4-elver%40google.com.
