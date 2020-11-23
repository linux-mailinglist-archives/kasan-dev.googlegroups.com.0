Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGVO6D6QKGQEPKC2BRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EAEB2C1562
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:10:05 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id z9sf3910430ljh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:10:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162204; cv=pass;
        d=google.com; s=arc-20160816;
        b=fiWLDJ5g1HIeLIIy0GWlQ2gM+QQf6yRnWQlUkoX2FOlwGop801tiDErZ3K4SS9Cs3F
         b3k4heXyZEV4YmFJB9CQPgMRRNX8vkhhmVtuUvQ1LydfPcnwqSwD49IZeZKIwZU/bgLW
         9rSZ80iJOwMJadjcMJaRvBSSHj3oWXIUQTat/Qa5SYEbjMl0fO51czj2Edsb2TboUrC0
         dl8qkjcOPpqtMoZpSiUc04Mc/o+NFrM0C5n9mafFLuW0394LcDScZJ3OLVMhQ5YYGTED
         BDyu5Ugso+zOW1puusXLjR1cGr+YHNQuWXgnXh1gnHGy7DpC27+sL/m5gQ1b8ayretBN
         WoNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VQiq8mm/9JgOWlpW7AbposcGzC6eUweIJE/oQH50neQ=;
        b=id40R2IKzdWTBwpDuF43iF9YOC2Rcbbd6Wj1Av2YJKkzdW5lAVqMSDSmJ2iHhgfY1Z
         3jS5mwcWoAdcUbDDc92rTqNSQdJn+7loEzUQplTINDNwuQLzWSbquD5txEk0EuT4l0Dc
         y6jKHItYSbOLDwiH7cYYjU7g28M44WeSqsen/V2IQv+BwBSP/D2aqcOroqPbgVWIJJ9m
         byY3WJqR9/0+c4qUmse3Zl8KlFQgGaM/MRo9/luseGrPTa+Q6hKQrhe/zghP0oM5rW5Z
         H3uzH1n6GbLEIQ61Gu8ZiXxtRV4CVjOyt1EkdFNei41Fa85+MLqQtFf+FkYg2jXvnY/x
         dwDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g6p3MpVR;
       spf=pass (google.com: domain of 3gre8xwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3GRe8XwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VQiq8mm/9JgOWlpW7AbposcGzC6eUweIJE/oQH50neQ=;
        b=pKRSwZ1eKZZFXAWCYGBjOKsWNXgM06tJnhjEK80houLKyc3QGEyViGSGuT3kEj8oJm
         /vf+LnBVUhMY24uLfgFwD5P/OGHueS3pUtIrCRiZnNcazCH+WRZHM/S3IQI1JIUyZiVe
         yLMKuXIU9He3r/XowpCh6upo5dg5RS4uTVVSw1+fcePpBqXquaR7iWkZ8aMU6yadHbYc
         uiFzdDGzb2kMYmAFmi0XaC24cUGxtoDXdYTlej9CO+XeqUStTMLtuFGCfstlJ/stXciX
         vd+uEJ6B8iUP8KXBi8HmxvKb8o4J5xNKmnu9lPLyeR2Agy09y71jB2WxRY8KpExs9l5v
         YZ3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VQiq8mm/9JgOWlpW7AbposcGzC6eUweIJE/oQH50neQ=;
        b=ra5+WAbCtIkJZSy7y3Z4ltPSXJWZTKJWWgYCmh1JXddr+HKFNWWBmCtXq+ygGT+VQ3
         HRrABKmM+jX/1ZWGS7Iod7QTTbxjOqLZWGgexlF4KgerogEESTtxOewP8ePYD4tL72WN
         Y9jaeiuLXlEaOZegJVGz1eIfuHv49YDYMFss/TwQicyEZs+C5yDEWmEmqU7aP5Srt6CD
         TS7+tSn33iqPDZ3xuLggv8SOkLjL2i61xGeE703OCYrJW8eLAYzkbVujNrc3trGI5+7G
         xyfZB1VK1dIuSJg0P28vj0pHNcZvui9r9Ov0wZhqYqVe+8jDbHAeplZRE/RgsQ39ZDbg
         7SUQ==
X-Gm-Message-State: AOAM533cBh+zNAPA7hpIXdLJXpKs//WXFY62jT+HFfTOjBPdjIkXLzps
	3SFhv1Zjmv3nWc69bI7Js0A=
X-Google-Smtp-Source: ABdhPJzkErxbQ0ocnskMaMlFmwYw1dk2ohP6wC5G/w75T10Itb5AL8urNYB0khQX76iWuGDtK8Hkqw==
X-Received: by 2002:a2e:bc07:: with SMTP id b7mr479399ljf.458.1606162203126;
        Mon, 23 Nov 2020 12:10:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls5177476lfa.1.gmail; Mon, 23 Nov
 2020 12:10:02 -0800 (PST)
X-Received: by 2002:ac2:446f:: with SMTP id y15mr296888lfl.415.1606162202265;
        Mon, 23 Nov 2020 12:10:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162202; cv=none;
        d=google.com; s=arc-20160816;
        b=ou3EZL/338qDMbhs/priudTNrTaMWoz0ZhxLlA7iZ97EhG3VJ4gItvfUKiQ2GxMXsU
         KEl8sTcbjacEZNHoudPerOATC7lkvF2H/3NUcJHKdbS8Wua/qe1Lq9AGyDjxH+1SDcyP
         t9P02waqN0Ipt2k6Bx8aKS3Qex2tcsNIArjVFx6x0I2rW1UmwnXlEPoEz7qMfKMvbL5b
         SRQOEbwW6azz3pLjYmZ/2RPmhq9JSqN2i4VCpQiM2b+MWdMl8rSBAdcKg3bRvTrVlL8V
         W8GvjI08Rv9WK+m/djCJ5AFBtIRkgk2p5UrrGWV6mGmg5zIqthGm5MyJc0PqesfpyKFN
         FPkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1oyed09tnLn/236j8JDGEir64Vx4l4zK2tXQ+JJGy2k=;
        b=YvpIwjYGPlAZEEA9BTj+r2u3YhtRS4Uj1DBfgmNvdXJNbfvKwAjTAKaGnUqa9vU4BQ
         HCfytRhvTpNQpoZKxj5xSAiLREK0mIjUjO81jYfgFAFkDCQXsjAtNKNoJTACjyfvLwai
         /7RZAwxQPcaoqo+i1Pm+MnXPleOMroEs+VJCn5a1EA5O8RtQZZ8RvyX7vYFzqI7K6CXF
         +03bL8UmbAEIT7JYI6IGCARmTYmtsikXmpCtWA8OYfjT/XlC8lIyFtdZN0kRGfLbfGAv
         hE6VNQURJZMZVVKd15A/VSih98xog4SRl1760EbGQ9/TAbV+a2eS07afEE7NvZgu4+7S
         vBTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g6p3MpVR;
       spf=pass (google.com: domain of 3gre8xwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3GRe8XwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f17si50723lfq.9.2020.11.23.12.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:10:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gre8xwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g17so159273wmg.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:10:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:d1:: with SMTP id
 u17mr606599wmm.38.1606162201852; Mon, 23 Nov 2020 12:10:01 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:04 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <a6fa50d3bb6b318e05c6389a44095be96442b8b0.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 40/42] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=g6p3MpVR;       spf=pass
 (google.com: domain of 3gre8xwokctwylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3GRe8XwoKCTwYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 434247e14814..6fefab9041d8 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -136,6 +136,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a6fa50d3bb6b318e05c6389a44095be96442b8b0.1606161801.git.andreyknvl%40google.com.
