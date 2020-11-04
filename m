Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHPORT6QKGQEPVZ33QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id CB8AF2A712F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:58 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id b7sf408339ybn.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531998; cv=pass;
        d=google.com; s=arc-20160816;
        b=mBC5HGqGHf/dZbJUkzH2YCPsVO88jXiFmyDbRb+boJ8JSrjnlTdsXrPVaKfEwS4Z29
         a4b4f9l/Wz3Dd8lFyFCMTWyEdZc6HXNVALmgPODyfm2jk2z/59/o6VnEG1ZmqErU2h7F
         3hfjhgYkle7EHGN/7fKdswInDPGBqQ46VG7Gl3fyE8XF1dMV2DWUPnbqvyBOKz7ET0+4
         XKka/4H6HbumDpf6J6A2V7vevLnwnSbFifwgu1f1rB0La0ojIr1KrL7TFWY2lPJUSFVu
         BA2+voxCTf4vIQJ5itGcsB6gcTEGtpH9w7YZsqFlEsgpfXU6ZtIorMGioUaSGnajYdKH
         93fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1v6tvFQozyv8oQ2hV8UYGcnVnBp5vpU0vAEZCSj+zAE=;
        b=03YjlRlGktjoPQ7GH1+ow7ONW3x9K5G/ltA8AvtMWC6n684nueidPqouFLo0be8n6x
         aYgCXBGt4cBiH3TxGCeyOpPuJ9sqlnoWLaZ456FywnNuwz4ldCmkkyvX4TeD+6+rs1dt
         wg9lEbJr3FYcYdTQBGXQk3Mo0hU5X+36c5Ug3FUTtwEfhLAZK9naIUGgY+a2TQVxlBg5
         YqxrVEkM/KY29SHI+Y7hai7wuKt3yxspnhFuwLQBmRfMN4jKMm9ZSLe+eni8NaeBsKzX
         LqvvWWSl6lO9VrMzqMbSVAwY1/pDV5ZVT8rN7epwtN5Q7MkvN5fRxrLtZc5sqCZlcIAK
         +WUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=br613dpy;
       spf=pass (google.com: domain of 3htejxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HTejXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1v6tvFQozyv8oQ2hV8UYGcnVnBp5vpU0vAEZCSj+zAE=;
        b=N7g/RvZL82QiAPb8/FxxPc22zYELx8Uyri6i1581yIjt2qBCcj3mE9WxfTyb3nwogA
         fqgG7yEklNvfRJ+FhE433nuDDIDvsavmopZArnbR9Zko+xaItrXFfplDDmFrmnfPW8mh
         G4Ol12NwQLjjKmbZnZP5EQcL3zdMtuom5UoCe2n7KlWdNfb9mr5r6wIhZlIAA8zgAV28
         o2rtxh/0EWXDSOpfk0dyeynRvKz3ztJB4wNa7cLg1WqnVjRwY0cwQdRuGohDgV/2bUtp
         TaJFShHcqSCiZ/Eiy169+nQH2JwOCfpONF5xbz19FloglOmu/AaHUEqiEqU73NpbJ0Iq
         w0yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1v6tvFQozyv8oQ2hV8UYGcnVnBp5vpU0vAEZCSj+zAE=;
        b=Ird/dNN0y4sMHZbA1LU/MyJfUBk+jUbH8LYbN6RfHbGp6e2iTPQdenvgFreklWDMAT
         OB9PSKzucB0MjwzHTdMck/VpU3NOSVzkzjODY2MvlQyItgms8cVuu0DPqUo7iQUnD3HU
         iDiyA/9720VEBYIidtOBqLHrD4Yfsx6zxVjbboJ5HoM/JysnB3qUASkW7UCZBuNgXqM/
         rHneNFqSdx92iZdsIC5TRvBcmc7qmStH3rXniSvi9mtfB2S1p2/41nJ6cyRdKL3Mhnaa
         09n5SEOhqv8SvOT910BXWCQSMERrz6+XxnnMFJjUiL40TYDYRNcieFEqHDfi+Y6+eGAF
         bloA==
X-Gm-Message-State: AOAM532DS/6A+q9Qmpdq0j+OU/4S99lHWv25a/60rYScotZ0ZEwxHsm/
	MoZlTkMApUFUgD7yNZjjqRY=
X-Google-Smtp-Source: ABdhPJxRvKFJupXB0WVeVjmsTYt9zb7TJTcLUCVQwidfaYwuQGmFfYTTRjTtYv/djCNZytuUVDUpLQ==
X-Received: by 2002:a25:a468:: with SMTP id f95mr214663ybi.327.1604531997920;
        Wed, 04 Nov 2020 15:19:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c387:: with SMTP id t129ls1273435ybf.7.gmail; Wed, 04
 Nov 2020 15:19:57 -0800 (PST)
X-Received: by 2002:a25:abac:: with SMTP id v41mr290495ybi.472.1604531997451;
        Wed, 04 Nov 2020 15:19:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531997; cv=none;
        d=google.com; s=arc-20160816;
        b=Pr2n98J58/OwyAO4j9H8YYAr7PTlS4ABVi5PyKEpyI9A8Jj6glWDqKwY6ykNDDHGmA
         XUBmeKWs6Q1TMCZvT+vLnpZkiydiI47iSvZuMMEn6LE2Y8DHnvY7LlRkUA9qrjXZ4snO
         7LkFs0bpt5DLNdkDaXeYGvvyjWUejDv3J0cpMS5ynTkLKiitV+gMqXX4JE25AW5sCQ8Y
         Hx36Vv4W/KcfMKYsOTvildQL2FaVXahzsTisfjO85DGWET08qoUPOZukyDKoR+Tf4JxJ
         y6L5JMd+8bdcSG3pWQSNtpQkANwienlxayg7vLq3Sl/09Y+3FGZSI2ch2tRujk7j/jIk
         AEnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oA6gmttblv8OmG3VJbCFTsqSwJTzGphkOsRK2ZeD750=;
        b=E/b3GUwhC8y3Q0fPGrm/JTmzlY5xAOSR7ptR9NOQ9Aik9AuryBWxJTSr/DI8KLOZl0
         7eUQpfp2cwvnAgjMeW0oV5Mpkg13r5g+OHlNxYS0qvTfUD8wSURzwNVktgjbdn9kQdJH
         d0Jp8F7Tvdvl8RHPvgyGviezlX+i3bqWpOjjDBjadtb1SQH2Zytl/I+eL2ZI2/6SbeLK
         pvhlatWFTOnZ1hAfwhIZazED6kzRuZ/a9krUfWCU+GpRgvuErW08/HNZ/iyA2HaYRoP7
         0FXetO1n99qGmeoYTBoMmeQPVv9Zf+usAeNyAw+u+tZioMi53qOmqWG+DNGA5XwmZtAn
         ibxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=br613dpy;
       spf=pass (google.com: domain of 3htejxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HTejXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id t12si307908ybp.2.2020.11.04.15.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3htejxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s9so11204621qvt.13
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:414d:: with SMTP id
 z13mr147192qvp.37.1604531997034; Wed, 04 Nov 2020 15:19:57 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:36 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <45dce4028d9f5e4c5705b481a8ac37bf516caa16.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 21/43] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=br613dpy;       spf=pass
 (google.com: domain of 3htejxwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3HTejXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d5733831ad7..594bad2a3a5e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/45dce4028d9f5e4c5705b481a8ac37bf516caa16.1604531793.git.andreyknvl%40google.com.
