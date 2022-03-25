Return-Path: <kasan-dev+bncBCT4XGV33UIBB3HA7CIQMGQELYY7KIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 091074E7AC8
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 22:13:17 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e10-20020adf9bca000000b002059b6ffa18sf1697698wrc.14
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Mar 2022 14:13:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648242796; cv=pass;
        d=google.com; s=arc-20160816;
        b=e2WkEmE6VMr4wqQBWnaZBXXOqBXnRd4UpgFPT8gdErnA2jaeVW6XdLUxqKzuprUH7y
         PpZxavKThml+alg9EcH6ezj+TRQkUk2mAvT2KTLsuLkLh/dRT50U+hXpI2JAvpo33R5R
         Sruq0EZFxZvGEKLnCnuqghGulIIOCZLrxAQjfNilRb7JMRo5zpeUMtVn54TVlA50Tnxk
         qR3HcMisI7vpkP3i2FMkOsOGgOTOveroTzSjjCzjLb7s+f4vTMB+rJ+ni+mBlhiYhTl2
         14U4KFDnWT1raclA99aU1fSudbAZS8mJsatAyuoNIHQHEAa5UeAjtQs1rQ96QwT0j5Ij
         xgtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4PIl4f16Kcbl5Glxpxq/7ioeN42e5jWgap9TEvNu6rE=;
        b=HpiE1cwYLw6GEb11BvRpkLqqpFFAPDW9d5rEDt6uE8lLAPu0ZOoVbuxOmOTrzcfm0K
         qiZXF9Qla/DLGcAJvf8qMf27/67EVFjixx72f+nX4yWmC7dipltLyjVB776YwVomkSma
         Yzr++s1ByGI2lebRFT/4cZgKIQB+HKWQYA2mh7q6qxBR5R7+jwnYcS0toaAAP3YHtTUi
         i2rlWaWuRieB8tXuIa+jpRUafHbbGWsIgBBvtMY19WHZio3Qi1rqP3Ys73Em9gbMjQyU
         1g75PCsuicycQOOtbOGPSF4yONSuUmSkerViTOScFOW2ImziNevvCuwxcurqIuz9y5+f
         Zmpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=N2MCE449;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4PIl4f16Kcbl5Glxpxq/7ioeN42e5jWgap9TEvNu6rE=;
        b=TSPyYpcnOZpUdseKuGIcjsckW1DwO/NdGdmb9br/YKevbfPoobeDK+Wy020cfzrUuG
         xNamBKaO1u4b9I4KO8ZEXEEPNN7XJ+uQcUDgujB/iH+IK1xcmu1TaUCcXy7DBv5Jg4bb
         wwU1mzxe57GsFCf7a3bj0p+fKrgwhEGJ3GWqMaGeC1BeykJOO+C9JOxFWyCsIJpkMLWS
         Skq6U+x21f1BUaK2Fr2RXJ4OoVe+Q5O/ofegaxBM9e1v6KvbGQimmxTWGGUX5imkpgJv
         NJrFj7FSgwbp9hp937zx4qqrWDDJEoDaPoNbtQ7NCeEoWjz8pwqBPT0tulz44pU7hwPW
         r2aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4PIl4f16Kcbl5Glxpxq/7ioeN42e5jWgap9TEvNu6rE=;
        b=5OwsJlgzlBnb9f6llT98J87QhrU2Uv7v8xnFdtiuBbtvzSA3WDr69EbBP4peg/U7Xv
         AH0I5dBYPg37EtWZZS0t9Azh5qGqcjsgkcc8gk7YYZQvBKNSweeCheTfFCnhpqk4Bxkf
         EiS0TuOne1A7CeoVg5JZGdUyAvUz1FivmhhpMzLKzP1V3WtLcmFiLzmKxMtPs6Uxfckt
         o56jG40t/+C5XPwU+ea5TYwpTEE2h3MvJoraEiWn5HbpWBiQYq6B+Fk5dM5hMFuW1SCm
         7rbZzBgh708yYdKhcBGneZTih6Sd5HOVCU5WnvCrXODyuh2v6Qb6pRuqfe2pSuwdqOGs
         Dp5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hc0bNbcaBEp5Sx23pCFL1/vgetXvnnfH6+l3sr/jwHflASUAN
	Y2katR5qrMez0ajqOh4RsTE=
X-Google-Smtp-Source: ABdhPJzYoAD8XOoUvUMP7wRsEWqdQMi0HTzhSWoffRbYvQ+Iv2R5ZzothEvaInnIkOa3qg3AgWS2xA==
X-Received: by 2002:a05:6000:1cc:b0:203:fdbf:e576 with SMTP id t12-20020a05600001cc00b00203fdbfe576mr10924857wrx.147.1648242796678;
        Fri, 25 Mar 2022 14:13:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c92:b0:389:e8c4:aef4 with SMTP id
 bg18-20020a05600c3c9200b00389e8c4aef4ls3189182wmb.2.gmail; Fri, 25 Mar 2022
 14:13:15 -0700 (PDT)
X-Received: by 2002:a7b:c14c:0:b0:381:32fb:a128 with SMTP id z12-20020a7bc14c000000b0038132fba128mr21513638wmi.116.1648242795629;
        Fri, 25 Mar 2022 14:13:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648242795; cv=none;
        d=google.com; s=arc-20160816;
        b=G35XLERlB9Rx1N4nVFLP7k7gCD4Opl6hpI34CgDI7yqk1gygEJ4dtsIh/aWSiS8625
         8N6/9fntMollQ44bOWk2/a7uWefAdfJdXNGwjQvredl9+SynRFsvRnsLcjB+jE4MYCHb
         lTDFKV0Qz5xMiP1IhPLEM5q7P3djim3ZYhJY5+8t3NEzogUN+lZ/2c7sN+ojgAZZy/vn
         CFe8qZvciJsqX5FK4UKMluwMdiU3ixu+LY19HQ38tUA2utrVgC4wKe0v3xciuINcug8I
         ORLujhafGsYYChnHFB8WZ3XkKAc+ItmNlSt5HHGWctUjA/0Aynt5fBdCeitOFub4Xub+
         AKGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wMX2Lt78TCSpizu7llo5vAThhIVue5pmZGbHjTF4TK8=;
        b=v8PYCP1IPFtd5Z+HVPwoIyA9yUwVkDmb2+v9kmcBAyu7bYGumqslNnScRbVlbNYgpG
         npcU+++oX58+59Z45Oq3y5btfb8xAJV9PSDzlCwCt9oYhTSJcQTX9/IhemQJeYVMAMY/
         7HCgKTRdzptu1ERCiHKxNa6RDK86l2+eMhF0lpaDNXsz7ex1G2na/3MLXPrNdvrwlH+u
         Trl4CaPzrC7JWBXuIlg/TeUyBiy93/KPHl+G/5i+kdJJX9YrmLH4LzMh4yM1EnRvnRJx
         UQ/nSnTIXtAogcw9igx8Mz0togshepbEb0wWcSEmRp1SEVoi9+kp49B7WDhAMM0ZjHQE
         FRFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=N2MCE449;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id p9-20020a5d59a9000000b0020401961161si417280wrr.6.2022.03.25.14.13.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Mar 2022 14:13:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 474AAB828FC;
	Fri, 25 Mar 2022 21:13:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4FF56C340ED;
	Fri, 25 Mar 2022 21:13:13 +0000 (UTC)
Date: Fri, 25 Mar 2022 14:13:12 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Vlastimil Babka
 <vbabka@suse.cz>, andrey.konovalov@linux.dev, Marco Elver
 <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne
 <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML
 <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v6 27/39] kasan, mm: only define
 ___GFP_SKIP_KASAN_POISON with HW_TAGS
Message-Id: <20220325141312.b71069800f279445749e79f5@linux-foundation.org>
In-Reply-To: <CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
References: <cover.1643047180.git.andreyknvl@google.com>
	<44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
	<63704e10-18cf-9a82-cffb-052c6046ba7d@suse.cz>
	<YjsaaQo5pqmGdBaY@linutronix.de>
	<CA+fCnZeG5DbxcnER1yWkJ50605_4E1xPtgeTEsSEc89qUg4w6g@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=N2MCE449;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 23 Mar 2022 14:36:29 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> If my suggestion sounds good, Andrew, could you directly apply the
> changes? They are needed for these 3 patches:
> 
> kasan, page_alloc: allow skipping memory init for HW_TAGS
> kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
> kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
> 
> As these depend on each other, I can't send separate patches that can
> be folded for all 3.

It's all upstream now, so please send along a fixup patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220325141312.b71069800f279445749e79f5%40linux-foundation.org.
