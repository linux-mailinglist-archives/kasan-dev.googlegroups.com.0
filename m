Return-Path: <kasan-dev+bncBAABBSGG2CEAMGQEURIB4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CE8E3E989F
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:44 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id o26-20020a05600c511ab0290252d0248251sf732006wms.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709704; cv=pass;
        d=google.com; s=arc-20160816;
        b=0eZKc+mHJo2gpJDo1awBKQ24TXrLmI/TzjMD1kPr1nZph+dkhODein1u5yIEoJuN+h
         nOMBR3BXvQPaElL8ToRcaWGwhNQ74iyx2yBVsp2F3vo45axPoVyquRNf38v1NMXH+5Fb
         gKR9BA+sg+4NFPIZ28XwKQoeuKdU90ywqRknXOg0LFrAJJmBoZp3mxJylLf+bAfuMSXZ
         T8GM6pxfG42xz2kM/xh8erv27n8ooHDAHF810uJQkflCSm/iea5GamYoscsYDksBfdjl
         XNH4pBldHGRn+6hXfF/KLLoj/TE07rkx4d3VAoA4HFLBIL96/YvnlqoI1QPtWVs5fclL
         mi3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pLyvnJRoeqbMowdr0IGLI6kN25BhaqEnklcvfwTcQlY=;
        b=cJFsi1telUrCbILBeLFXSww2Mueccr/xySdmuzTqeL8FBovs2K3QRDIG2V/eJCUEz/
         kCZhPB7Jd3VzFECYG8D6FHwvDjt6bA5Ke5tLuFlrxdNURC5zp9wwwGxcGLzKMBJae+5c
         Vbw0g9PF1qKDn+4Rer6Xtvnp0Qk9C/mNycGXX6DwT16soV/Z552qqB/2BkKKkFzHKM7j
         GRJzTghk5MBwBhif7842boO35MMM7nkgDf+DMXFKQqjn9nXzrz2t/VrhQgThkq0g6o2L
         a+P2eLy0gYoIyyIqPB5yZzOTW9V1K9e+bYeDeWeNrJou7oFgT5YL+Od9zxFb9rCnCBqH
         z0Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XO8QCcYF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pLyvnJRoeqbMowdr0IGLI6kN25BhaqEnklcvfwTcQlY=;
        b=MeDBcMzIchBOpHmhnRLMimHJRE0XpPG0SCDayz6qIzPM68UtKnsF47L8qVPo/01ABW
         Uw5oHh5jNcwbM/6lFeOZzt2Cw2y4JMzOG3Zb1rep9+CWA7fktePFl9cHzJUNOJpUTOxb
         wbfNotTe9z9YmN0hl4SChpNP7U66ml/EAQxcf3DAea3m0mjRDFBPwEvfDpVkwJuVvo20
         UGksh00Jdm4Jsh1UIWTaWgwviwryDMLF5BoswPeySdgUCPvN5pM/HgnhpNZnYIpMPUiH
         XzmfS/71VFJUN5j3EEHgO1Ks3JwaVtaMYw37oOu1lon4OGhI5IHjTVnaxo454S9+eae6
         qRqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pLyvnJRoeqbMowdr0IGLI6kN25BhaqEnklcvfwTcQlY=;
        b=aIEJ5tupjNme6Sy47EIuOgzbe5OfKlpgv8sH/+FUrtA8biUMXJ7wP183NpyrXSSHKN
         v7DGg2FLHOabqt4q9ih6EbC3sqzeFCj7SQta3h/UA0lKZfKZspK3xAuK7IbwOwQvExPj
         mz/eEd7j7ZdMFLyS0jW2DcJaUI47w3DKTRvMY3g9BOBDaHG91Pmtk6KgnTWoMlreshZ6
         nAfmQeUO51cFQCpcqZUwVP/Kt/yXR934oO80mK2TOiBhAjXaP23PFgwcrFkku5AQd7u6
         Jd1MdGpHYhNI4fbsfqJYP85UK4RpR/v+KpvNzsMaLLToEpzY/vbf2WTYSAqWLcyTr3u5
         3RDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531r0S81XC/qZwv5PhaR+MZM5x3n2xpcIAdXlZAoxFMSU6z8o+kh
	GIH5JZtq3XW499gTErAZuCc=
X-Google-Smtp-Source: ABdhPJzotbPLyc1Q8FoMUXAs5RKxhamj0GYlx+vyLwafFG2I71nwOx+5pFTTGz3Dwpb9mTE2Hn7ydw==
X-Received: by 2002:a05:600c:35d1:: with SMTP id r17mr88320wmq.175.1628709704292;
        Wed, 11 Aug 2021 12:21:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6251:: with SMTP id m17ls2018671wrv.1.gmail; Wed, 11 Aug
 2021 12:21:43 -0700 (PDT)
X-Received: by 2002:a5d:4ed2:: with SMTP id s18mr60417wrv.72.1628709703737;
        Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709703; cv=none;
        d=google.com; s=arc-20160816;
        b=nI90gEAls5XdZs2SUd8KfmESIc+WW4ks7BQ7BrX6ySzXplhj/vIz7oHl9AV+/l+OaM
         QwvsAE7LG95KiQuKhZ/AD4THaMFOFlJQ0GQqvG0SARQYtrh84PBjmV+wd5ZTfML4ZAUm
         IgaZJkNcRqVAazf3W7gSbk2L5S++pPJoZnm4tj31jRyM4ahsU54yNr2+85X8msAO3jAX
         BqJthFcyp45XdT+rXLtdUq35B1OSpoGt0ka3lV3FNTpdrEjrk0Rlo7sTg12g4gFgzwQd
         hMBoMnFTKlL8TwgrclEzquNJzKJ8fp+pWb1MHrnwdXjgKtXVAYvi8pvSzZUzANvAkDyB
         lyGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=weuZVW/Ysc7M7eQ1iHh/6bngJdzeOf6q/ORvgfr+R4s=;
        b=BdN7LxKkONyQyZvUkqRbKO0o7GHT6AUoEiudH5mFJ0izQmetA9elXAH4NMzHMJ+0mV
         V4WSSNzqTsexOPxY9b7228/ItKFetGCFkCaJVn3fUIKyoG08j5MLpTOJZqqoHNfeokiL
         t+/EoqusY5RLiE4uAWL0XrsOp6SkCusm3+YG2ZSwrLEnJImJV5MPt9UhlWiGbvIbIRnU
         2jLN0pYKhYcSSTtF8HmWVx1dRNpNrD1RJR5q5TbDlPMCR0Sk3oQXB8vtNu/invrxXB58
         /SvsCKMO/PxRXJJWwg8Qqlgl8R45yy2hmgEMwh3Eb9uRDlsm5sg72Hky/SDJYCMMBfur
         hD/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XO8QCcYF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id j129si278738wmj.2.2021.08.11.12.21.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 5/8] kasan: test: only do kmalloc_uaf_memset for generic mode
Date: Wed, 11 Aug 2021 21:21:21 +0200
Message-Id: <6e0ddf32ce140b9e8aaf127e9e40cbfff4430995.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XO8QCcYF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kmalloc_uaf_memset() writes to freed memory, which is only safe with the
GENERIC mode (as it uses quarantine). For other modes, this test corrupts
kernel memory, which might result in a crash.

Only enable kmalloc_uaf_memset() for the GENERIC mode.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 0b5698cd7d1d..efd0da5c750f 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -528,6 +528,12 @@ static void kmalloc_uaf_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 33;
 
+	/*
+	 * Only generic KASAN uses quarantine, which is required to avoid a
+	 * kernel memory corruption this test causes.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6e0ddf32ce140b9e8aaf127e9e40cbfff4430995.1628709663.git.andreyknvl%40gmail.com.
