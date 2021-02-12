Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO7QTKAQMGQEP7PULWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A56CA31A366
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:17:47 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id bd22sf372708edb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:17:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150267; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJvVV32B4Zy6cEbTDNcs8Wvzl8mkG3ftoeGIwrniAOjmj/LgomVV5LiM9yQ3sKHdd1
         Ef+BYo7gq545AcjCxEWWIKabyPY0FQLGPmJfH307W1EpMkYKZoLu2kOFC6Y+AuX1ZDz3
         oMfOXm28TCIfTjX8D6WDQj3KB9P7IadoR7DvY69MNjKEJsE5AYPYssOe9eWrP3OGHPkV
         u4rkg631U1wKLaqq61XMFno9ymrz5ko4jN00r3zlKgbBrgF6hM2XrLUF0XCOEKnoA5Qb
         +vhtepLas3btMg9OPEoReEtcQ+mXc/B97u8nlriQlFfUJUUPGt/farJ1u53XuaETr4Nx
         DXWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Xwl8GGFqMITuv4NWViqn9Kl5F//E+dRpH7K2mx4ZvMg=;
        b=LrDj40z3dOOIKn2nh43klBRvrce3eocQ4pu607GhfiMcS2YhSG0xP+7j+4LqpIlsCT
         iP3zfUq/z1xmaCFQfaKDQpU6DA0Ujc/UZAMyM7xQJ+4yg8P4cQBReL0ptutM6dGD9yr5
         Kg269XZ+FyJYg4s58qwiKRIRp/kdEeXWQpKVeUVvgsFfycc2FNCgY6stgqGU/amsVHNI
         ns3xS2EvkSGlLAhkw7ojrIdqF3TOj2IeHDW3XEESL6r5+lmVzgyrUD+eIig4mGD8ExgS
         JJFvLwynT8hICB9XHZmMMeUlj2EK02tuU5nNgYYe3EuNyzatqYKbze7CIpAgoXszFqId
         m6dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pNk3Ah0g;
       spf=pass (google.com: domain of 3obgmyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ObgmYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Xwl8GGFqMITuv4NWViqn9Kl5F//E+dRpH7K2mx4ZvMg=;
        b=df3FGseTQeVxhCa3xkcMs32tQn+oabRhtUWU1slXWYbQF4v1bQTqslHTYkJscE9Ziv
         qilZXD/CLDz5Cbg/HhT9xtsROXsCukR39dw2E1lj+CqyveuziCYdP9l0Nozb0j1k2cQT
         /J2Mq94whaVn6ExXpx68URSfpHsoDVjpMvB8425IxVN79PQ1F3S7n350oY0a+edwTZGU
         JaJ4DRrwo7h6KruCnWXQEjRx2ZbJIK1L1yE818xakdhFdRKk3AU/PiH/XKkFUba1qnxC
         M6/r9li3Q7ERS/uskgUETZx0ogu+EZl5tyei1UphDYb2znMCZollDpY9i293kdUU3P25
         c3fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xwl8GGFqMITuv4NWViqn9Kl5F//E+dRpH7K2mx4ZvMg=;
        b=f9n2w+vkcqDKAeWaIgCHXzd4MTIkA45ClwXptBFoT8J96BPa+Cs7vw+4lyzNR+9WCg
         wpJuCqc2vWipiE9Ll1m/f4qfDi6v6X8I5PppBKSsCV/P6OdlXC+tC9VrQxfifeJLlLDm
         ZP7FhJ7MCfI8ETiZDcb7UFv2qGeEvk9QHJVd6PivQH4TnisVgdIelJO/eZbvPVhmQ0d5
         k8GrPgG5CixsStb7PPCtHJG9x1zc3GosMEtZQql3JpMrEt21ztQwVHAFZH7a8r1YNjr+
         GWP7KQxQ+Oh5uggSf/nSjn73VyJ6PSKUllMZ05ulWVvGxhTeEFYS422iRWH+/mWj/C8V
         Xz/w==
X-Gm-Message-State: AOAM533t3R4SQnQR6rU4pwaPf7yScE+n9EEzyFSTexBzWfqj353A4N8j
	AWTXw7yzAFbs2Sj07i77mog=
X-Google-Smtp-Source: ABdhPJwJO2cBwMKEIP7AuiXUAnz/O7aml7jIdsf0nG+ReLgiAjtgcVFCEcvk2F1HHFbfM0CLbfENZg==
X-Received: by 2002:a17:906:9bf8:: with SMTP id de56mr3959610ejc.425.1613150267378;
        Fri, 12 Feb 2021 09:17:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:eb55:: with SMTP id mc21ls759009ejb.7.gmail; Fri, 12
 Feb 2021 09:17:46 -0800 (PST)
X-Received: by 2002:a17:906:d189:: with SMTP id c9mr4137837ejz.36.1613150266405;
        Fri, 12 Feb 2021 09:17:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150266; cv=none;
        d=google.com; s=arc-20160816;
        b=xGO4ICiP/IyENnpzHonSkfQmCfWectSTQ3oB1HFDQk/pHRDJmz8S7KVmJifE41JScs
         YZr6kHxvokin/ZmlocMQK4McFQhN+lrnjxCQ2hC6XiRu1bnm22q2g1ELLrUkUBVTBg0q
         ehOkC/qX7lbYO/Q3TnurHyt147KrARXfTRQ4iL/rkHgRmhUfdGrOcj4qNN/PMr9WtH8o
         cSO+poK8+TIDZRDwfgpCrXXO61DheLsknq59G76GYPQgzN6yJ40BkXCZNfJGK06pyVpX
         TSxSElxusCi1H+B+6FaXgAzKv/To5zkn0oJiTUcBLRjs/rLHZjQfYp7kCglLbHSw+n44
         cecA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4l3MNJF+SXf57n+5Mg8X+4vTNWZXYNx/l+EET96XFKg=;
        b=rr8Tmur212clZFwAUEz0yLwsCGZuCm3ImXREtJ2tUxLo0bECdiTi5JiJM8lT3iHkYT
         cS1kfODda3rLhBayW8ZQmzSTMFCj5mKky3KKRAlkkC01Z05aWxt/owXYMd2wzqBs6ztc
         pgEDOcBDYLdaZ0dayLwvjQbdGp3mqFC33BR1LRODleVt9QrM/vEVexDU2CS/fDN/J2pA
         HmcFef3vTPYZY25tDYY6pvcrdRbdo2NOMd6L78OHjAybT7E0ag2agK22QvTLoZ/PIuCf
         SnhK9JIExOcoSDIQVvonjm+82YEtKztiGtfHeMLxC/hVT1LoNF0acsQ+h+mWqK3xotSP
         1q2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pNk3Ah0g;
       spf=pass (google.com: domain of 3obgmyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ObgmYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id cx3si470587edb.0.2021.02.12.09.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:17:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3obgmyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f11so356460edk.13
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 09:17:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:19dd:6137:bedc:2fae])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:38c3:: with SMTP id
 r3mr4065016ejd.193.1613150265987; Fri, 12 Feb 2021 09:17:45 -0800 (PST)
Date: Fri, 12 Feb 2021 18:17:38 +0100
In-Reply-To: <7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl@google.com>
Message-Id: <b0ec98dabbc12336c162788f5ccde97045a0d65e.1613150186.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <7f9771d97b34d396bfdc4e288ad93486bb865a06.1613150186.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH 2/3] MAINTAINERS: update Andrey Konovalov's email address
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pNk3Ah0g;       spf=pass
 (google.com: domain of 3obgmyaokcuwo1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ObgmYAoKCUwo1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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

Use my personal email address.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 MAINTAINERS | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/MAINTAINERS b/MAINTAINERS
index a58e56f91ed7..7b3d374c858d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9584,7 +9584,7 @@ F:	scripts/kconfig/
 
 KCOV
 R:	Dmitry Vyukov <dvyukov@google.com>
-R:	Andrey Konovalov <andreyknvl@google.com>
+R:	Andrey Konovalov <andreyknvl@gmail.com>
 L:	kasan-dev@googlegroups.com
 S:	Maintained
 F:	Documentation/dev-tools/kcov.rst
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0ec98dabbc12336c162788f5ccde97045a0d65e.1613150186.git.andreyknvl%40google.com.
