Return-Path: <kasan-dev+bncBDEZDPVRZMARBAOTYCPAMGQEAOCW4CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D371867A1E8
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 19:54:59 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id b42-20020a2ebc2a000000b0028bc41df601sf3087484ljf.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 10:54:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674586498; cv=pass;
        d=google.com; s=arc-20160816;
        b=YUvlY3R4CVXKxAL5FY/8vVCpc8BcTGoWLDMUXpDuvsFFcFUSTAy1x6JyTvIWNg1AHi
         xRll2mOHgB+5l9aB75pOUOL7OA0IkR+9rYQ2XSg9GfXIxiZZUirimtRCWH3EZaFviDKe
         AdfWH+09bMqnNeqC987Im2gULgpjakYnRZvxIWzNqebfb+iSa4hTOgg+b+cWF2ZLQrTj
         d7wORsRp/mNePz7ewnxyVmeY9J4c4czBQCnUfmgePalILR3YWvRBsqtaedoY1Gpts7Rp
         ukHU/eF4+i9vRUQOaOXMnQJ7mm3m5y3vEP1uh+evo5QJqUfG91e+sTJPOgbruGaiy54v
         phEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6y3Kv83/5lVqV1+bsTKmtxIImnWQWQkPFPdu3nXFqFo=;
        b=Zon6xmoR+91tTaR8z1+rl/v1EwR4MUFFHzzp8RQ9Bs/L346idqkGG8Na2H02eieVWU
         zt5RlfK3en3T6YxBZusXisJIoAhmn6jU9+A8eNUdJPq8Z6MBtC85NKdC28TJNdaa5q8B
         N8WFMRjFHqSDMePzlT0F76xxNTTSqK49tp2NXjhxzo16tJkEnD+VAG9AiLWcC910jLf/
         Y5znjZk43ZaHTaqeYsf8RYgjbX+0pa9YgNTzfKdC//WHFrkyhJi0pqSafpw2uW5+8TcT
         XR3I31qdAd3TwwI07mNzR9xIqRFLwgRww2pN+0pGiQC+rC0Pp2Fns5CsLY3mixipOvVu
         Bp9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gmPyaiPn;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6y3Kv83/5lVqV1+bsTKmtxIImnWQWQkPFPdu3nXFqFo=;
        b=g71GGV2f2onrdCX4ekQVC0bJwCF0EKg5PiOBN6XW8ggHiTryf1ELJKildTonbQPrVy
         twau928Z0ptd2E36nphUZNLLFPg/DNVmUqTdjtzC+el0Ahl/3amL+WMCessZV0I5e/Av
         5qJGEmCHgqN+HFdZ2lL4dDeYO7x8K7sX8fGUXL1/oTvgHVxLydJC5nsuLJREmPCjyKVb
         S9gpslGQQpAQ8XZgUPEWjw23JUz4a36us8cDUh0I5zhl5j0EwW2CBoZ+f/bw3sD3wnUQ
         ora7piXBM+XDWEDhWP3VwQl7aT2ZbAaBx4rr/pLVYx6e1raGuTiVF7kinzYV6LDYzopC
         gAIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6y3Kv83/5lVqV1+bsTKmtxIImnWQWQkPFPdu3nXFqFo=;
        b=xqb0obX+4osU9u12MwqbqOQQJG1I9ypwA2YOIz5MHF4RjtCA+Hv7i5c3Ujkxb6pkPE
         8cgpPNOduCQr8LVQR6C+VzO2jQGCPgF4D70v6TbEdjfx1U8LTsNRMmwY5pWMjPEGw5r3
         4Snk7fgyeRNf14PUsiMnmGKoN8DStlqrjaMsPkgPvG/fVwqLMGQn273SJ8xTj2nEiazG
         5mDRO/D9dmEz37b0wqrlbGKiM0Oj3yuX9dHsSyHM4NrXu02/BL+i1VU/aQXhCvuSRcjx
         h2jjs9Q18RJzU3InEMm7sLqp3v4DHZCSs7Owi1Cp64PrFZPQQLrMQdSRwRnkouYiVYZ0
         dQHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqWlBLaMAq9rn1xKTLfgYFpvTjMchI6u+ET2BhGH91Zwf9Bg3Sd
	7ZYz5cqJS06wdilOhaFO5Ew=
X-Google-Smtp-Source: AMrXdXtUMM23t+3tHzP5YNvAoendI6xrW1WWbVTK4yeLvzzhQje5xdeJGFh10vScsMNL5HE3iAbdpQ==
X-Received: by 2002:a05:6512:ac4:b0:4b6:f627:e65a with SMTP id n4-20020a0565120ac400b004b6f627e65amr1851285lfu.564.1674586497987;
        Tue, 24 Jan 2023 10:54:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:368e:b0:4cf:ff9f:bbfd with SMTP id
 d14-20020a056512368e00b004cfff9fbbfdls7730294lfs.1.-pod-prod-gmail; Tue, 24
 Jan 2023 10:54:56 -0800 (PST)
X-Received: by 2002:ac2:5188:0:b0:4b6:f4bb:e53b with SMTP id u8-20020ac25188000000b004b6f4bbe53bmr6611645lfi.36.1674586496824;
        Tue, 24 Jan 2023 10:54:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674586496; cv=none;
        d=google.com; s=arc-20160816;
        b=K3ux2eeeJj/Qt8vjRNuNIsjTg12F5Dq+jsc1hlinFnw+hk+RbqGvDjHx+Km/kf8g+/
         lpoTNp2/ZEORT8FYqtBMyNvTg7bGm6Ijyv+OWpjwgOVRYdk2KzahrcAMIITgcbIWR5CJ
         wW9k/ZYE/Sz1JnrrGgVgY52w7CKyNXu4B1bGDT3elHOeDfQ9oXJ/+/ALfnGXspiWvGk9
         hxpMl08Ul12gV1Zrysf16TvWQBZw6EKP4i87cbnU45946JLR24u7/ccuqmY1jf5ZoqSz
         UuxoD0ZMaPh0l5mTwqYlHAqCVRh3HAWK/JSIjIvJzUTLoNQOX2RamIH8oLMiJwZaF+mT
         9Vnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GS3tJAOW2p690w/lXKS5wIkZfj1/Anmtrbk9hi00lI8=;
        b=TZVmZPum0uWmeEMUEsbqM56QKQ33+2ROj33ru6cGye/yLO1E2BIuNUk5Kdt8GqMKP6
         vdIeXpHsOmM6g9GHUpeT5NcEZixKnYRo59UF7Q3YRgS4qgxW2lC6rnKn525qHd3nAlK+
         M4dNlkpDzlRAXl8WaonfN/NzSS8XXHQww2EY2QYQpg1MAkd/7SC2s/YlWH8GPVJfDDG5
         XwEaD42oQH3MZ0eZzK5AZ/0oevc9mGzl/tOcnXFDXtDvXLH1xcXhIF7t9e3Ltrsiy7RL
         xa57OxNALMFL1bq1t/axiTQH7vMpb4AfhHXneKy6ZyHxVrov2XcrxZ25vglao+uhLzmD
         +ZSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gmPyaiPn;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t3-20020a056512068300b004b069b33a43si139492lfe.3.2023.01.24.10.54.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 10:54:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 64AB5B81614;
	Tue, 24 Jan 2023 18:54:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B5028C433D2;
	Tue, 24 Jan 2023 18:54:53 +0000 (UTC)
Date: Tue, 24 Jan 2023 10:54:44 -0800
From: Eric Biggers <ebiggers@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Seth Jenkins <sethjenkins@google.com>, SeongJae Park <sj@kernel.org>,
	Jann Horn <jannh@google.com>, Luis Chamberlain <mcgrof@kernel.org>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
Message-ID: <Y9ApdF5LaUl9dNFm@sol.localdomain>
References: <20221117234328.594699-2-keescook@chromium.org>
 <20230119201023.4003-1-sj@kernel.org>
 <CALxfFW76Ey=QNu--Vp59u2wukr6dzvOE25PkOHVw0b13YoCSiA@mail.gmail.com>
 <202301191627.FC1E24ED5@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202301191627.FC1E24ED5@keescook>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gmPyaiPn;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Jan 19, 2023 at 04:28:42PM -0800, Kees Cook wrote:
> On Thu, Jan 19, 2023 at 03:19:21PM -0500, Seth Jenkins wrote:
> > > Do you have a plan to backport this into upstream LTS kernels?
> > 
> > As I understand, the answer is "hopefully yes" with the big
> > presumption that all stakeholders are on board for the change. There
> > is *definitely* a plan to *submit* backports to the stable trees, but
> > ofc it will require some approvals.
> 
> I've asked for at least v6.1.x (it's a clean cherry-pick). Earlier
> kernels will need some non-trivial backporting. Is there anyone that
> would be interested in stepping up to do that?
> 
> https://lore.kernel.org/lkml/202301191532.AEEC765@keescook
> 

I've sent out a backport to 5.15:
https://lore.kernel.org/stable/20230124185110.143857-1-ebiggers@kernel.org/T/#t

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9ApdF5LaUl9dNFm%40sol.localdomain.
