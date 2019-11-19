Return-Path: <kasan-dev+bncBDV2D5O34IDRBJFT2HXAKGQEOQVASOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 39A65102DF2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 22:07:50 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id c17sf16796497ioh.12
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 13:07:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574197668; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9SOrDkN6NibHP9N1ZSSMUIoRIy84byf414MDZevlwQJEleZwhfrNHnzdxKOZST+4m
         fhpAT8NtLwQij1jE3XdgAWkDK0WiRpaD4AnaeAIFSsQHXpvD4Sw8BMpT+PwwqcCKzjPV
         JSEDm1sQUEEq7mZtMVElMP3ucRQV3i4pa/d6aDaxCFVyROAuEwUqCnHc3XFYBUduexqq
         o/UhI/WVlmJ68guHUOu+KwUSuw4gRH/d6xZWR7S0/7U1OgnFTKyoVLZUM2K5QbYMsZ1h
         3M6pMK93Kh/5UpXcULQUAFQRi0Uv3ZCcxl3n+O8EFfSimMw2ez87PXBmWaNnRzuqdj72
         Vx0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=y0CqIqYliPauJyVF7MKzb5gqGfpYnsGMokj7VtpT2C4=;
        b=Yol3zVrkYII1bm7gz5wOC/Bo0PRG1yUO8LuBT0axH9lefiKacVgNri9XOHhbvOZDQ4
         +scT7l52iAioqR/4rGrfvUeLHNagZKJ9ceZvWJWpnblB76qFRyrJ1uGXjGAmTXnP103k
         qMUSWU43MSWlJt3hFXELS4IV3AbH37HcJE1MDmEcaQCVFEzD4lcF8wVyKsFJUg2mH9HR
         8LDdf8Rs552wEs37mme/L7qNqJWpoEJ/oEOt+A8W9f2VCrOqJuKCjEyJKRFCsJ77yDne
         g0uN2B34tyfN0mx/uX98wtOP+d2IvGhKdnEBTYuyK/ZwD3IjyJ2euhcIM6hqBX1x9fxR
         PhnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=eGaYs1XF;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y0CqIqYliPauJyVF7MKzb5gqGfpYnsGMokj7VtpT2C4=;
        b=R4bQHPRE47oSlUJKudeWz/sJ1QvfJL36cvoL4GuNJlOWooQUpOBrdPPlw2jqnytq6L
         5lOxO3nyQH8Q8rTq8Q5HA2OOv0FPvgXY9TjzNUeBGRDalN+QT0+/vqjEcfXYPzbBQvTX
         4RcNqEHhXJXfAvMdPCock8ZIC+5r3CDjGaO6Tx4SKJdhicuw7HrhvUq54/6nIX4CjAJu
         TkI3SIF2HjGRGaXxX6G4zaGYfjLjbZE1cX/W9w7UE6egTpL6UOTeOw/qhJns3BYzLKdg
         JhOJCoNYlxNHVw+jSdvXDRlD6/5+9LAzY6NuyRtUKwnZX0wMJniFOj8C6dYYUKNPHb0p
         fK7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y0CqIqYliPauJyVF7MKzb5gqGfpYnsGMokj7VtpT2C4=;
        b=Q3ZsUjQZ+inZPj8PGjLPPKq1LzgE1k1logl9pcN+5hZEdbZ9CaIt+JtK/XjWYbVRNc
         F0yZfJjzSkPKBPya2cutLok9nvqTsWsBRaZm/HmenJuEH6QhrGE4xLq7WHm8ZFCljkky
         YNdEK9FlZENuBosI95C8F64/+wZ5HJraSF3dbsnJA0jN/vRCaCB+6I9k47iMuw0nDDPO
         5JPE6W4/hvTMFVE/NHMGdE4850SYYBQKnwx4RgClX/DkXOFIt3ZLyvhAbHD9It6avnTN
         FO82z6vSlit2a527Qm4u7J0gbMQ/eVbAF9rcOvefpo8bnrTUnG4iac8FXkbQG3Rj0Xa3
         II0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7BXjODKahsEPkh91ieoCNZUz0/lwp0kflndvrRfWq7vlZ8WXq
	hioTRZIfcxhWMUhxsAxal48=
X-Google-Smtp-Source: APXvYqwZWC6HHKQG8qwNXxL2nmIBRgUmyc7875nln3rQqf9x6jWeH0ed514kyjLKTFo8jqZoIqa8oQ==
X-Received: by 2002:a92:5c5d:: with SMTP id q90mr25341751ilb.22.1574197668571;
        Tue, 19 Nov 2019 13:07:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b602:: with SMTP id g2ls3389120iof.2.gmail; Tue, 19 Nov
 2019 13:07:48 -0800 (PST)
X-Received: by 2002:a6b:8f0a:: with SMTP id r10mr15743283iod.139.1574197668121;
        Tue, 19 Nov 2019 13:07:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574197668; cv=none;
        d=google.com; s=arc-20160816;
        b=CsUSt+ZSVB4DmQYW4b5LeGhMcISYrIxiLDIZqlogdj86IdCZ/E/kBq4vv53cqGA8g4
         iCHOwClCLcuWf51/PHOVRStTqEORzIQsmefREO1jB3HfThdXIIY9QfZ+cKN/NvWHcLCK
         95bRFt4xref/VL0OabnhUmTJMpSVV4tuRB+ujZnM1YV4lONB+x8gSN8ozqsWc+2VEVEX
         nmJK5G5yvFVEUBmjYkADC/tDLa3EnvLXbf4p5BXxq+YiBF8aYrOnUbJLn4Lx2uFMfR9p
         jJvbPgPmV4zTRMRXARLMxgbpYX5wLe7dGuB/7vwmqWLDswtD/AiwtJRTF5Z4Xt2d9gOa
         D+XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=8LgZnqLUmOR88cQIUBGW/lJ1t/5IfAC+QU0QnjEpM/o=;
        b=tqgUvtalUdI1N3xRH1j0Vrjn6hN2p/AvG/Hkn8GUZDYxLI4zFuJEEwKG8GVSsVwrhz
         6RHexR9XyWXL7gewcRTKQv1BZCC0z+MoT2TzsX3oIaNtczgcV9BkbpQ6aIteKY8CZlVs
         s1tz9DKE/flNs2ZEP6MgHShSZL02+Bu0B9c1cHgdUp7jAaEPAwaShtQJnBPh+wPSMhZF
         x4YnuDlMzLrcd0UWSPsPqaqSoILVW7G58CA9IO7yQCm60d0U1f3ix9+WN6bWSNtKCxUR
         CxhHbD1b12xdbTFSRBkTZQ7XWgMkj6tJ+fMpvuTUEKnbQUUgMTUjIvnp3t997auPTHJs
         VCgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=eGaYs1XF;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id x18si1343790ill.2.2019.11.19.13.07.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 13:07:48 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::5a22]
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iXAiv-0004uV-7V; Tue, 19 Nov 2019 21:07:46 +0000
Subject: Re: [PATCH -next] kcsan, ubsan: Make KCSAN+UBSAN work together
To: Marco Elver <elver@google.com>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux Next Mailing List <linux-next@vger.kernel.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
 <20191119183407.GA68739@google.com> <20191119185742.GB68739@google.com>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <3b8e1707-4e46-560d-a1ea-22e336655ba6@infradead.org>
Date: Tue, 19 Nov 2019 13:07:43 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <20191119185742.GB68739@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=eGaYs1XF;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 11/19/19 10:57 AM, Marco Elver wrote:
> Context:
> http://lkml.kernel.org/r/fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org
> 
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested

Thanks.

> ---
>  kernel/kcsan/Makefile | 1 +
>  lib/Makefile          | 1 +
>  2 files changed, 2 insertions(+)
> 
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index dd15b62ec0b5..df6b7799e492 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -1,6 +1,7 @@
>  # SPDX-License-Identifier: GPL-2.0
>  KCSAN_SANITIZE := n
>  KCOV_INSTRUMENT := n
> +UBSAN_SANITIZE := n
>  
>  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
>  
> diff --git a/lib/Makefile b/lib/Makefile
> index 778ab704e3ad..9d5bda950f5f 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -279,6 +279,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
>  
>  UBSAN_SANITIZE_ubsan.o := n
>  KASAN_SANITIZE_ubsan.o := n
> +KCSAN_SANITIZE_ubsan.o := n
>  CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
>  
>  obj-$(CONFIG_SBITMAP) += sbitmap.o
> 


-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b8e1707-4e46-560d-a1ea-22e336655ba6%40infradead.org.
