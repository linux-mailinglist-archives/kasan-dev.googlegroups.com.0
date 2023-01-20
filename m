Return-Path: <kasan-dev+bncBDR5N7WPRQGRBEPMVKPAMGQEVYTI43Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2993D6758E7
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 16:41:08 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id q8-20020a056102204800b003d0a28475bfsf1629105vsr.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 07:41:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674229266; cv=pass;
        d=google.com; s=arc-20160816;
        b=D3qTsrtn9D5Kz4ptND70UTCBlL6H3QYb3PYwJ0SwbNS/d9q76zO8QMkkPKI5snNeua
         wCPSp/eFIh9naxJ2/b2wEYk5NRmqnSO1F86TeSx01jqezdvKExQAanhWav7rIsdSTmZV
         zap4HDnDo51uuXERYiPfkXxWUOpeF73BnHOLOeCEYELMkhjWyP/zFD4rjaFkK+wCdl5F
         OqFeFUmZBjoMoUWuO+a4P3/cG/qwoqTfD9fk7KwNy4dzzDcHTT7WIgQYwUJQ6zYqdSfJ
         hb2VyBPTjQfRKk9ZI8L+XrC8Gv/qhHjtvFafaNU6N+aDG2Jlp7NCDp//JiZ7pCmAb+Eh
         ADlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=kxeQHFGsmI93ZRrigrGn2VGlleEgv26JrVwtfQSmIi8=;
        b=ZeSIPgngVlB3FFD6oYCDxz0GLAlMpWyaJZaLJfe4ZGWDn6I6fv3JT1f3oUPVctFgv7
         nRvIy/te/bFxq+FXX1fuCaFZ+SjTeixhYdPNnStA5NtQUnGF0wehfwLahRNbdoekrN02
         kmk/vfwALa3FQPCRh+SPEojClfmICj+9FGW+prsO8JguNdT5A8sU13VxHXeoJ6FvWE0e
         L1FyOMQagQS61bN+k5q9DheZ/lJFu21fbDs2oCLyNUgu6ud/9nwmdjQn2GZ6EXfW3iB9
         ixVeX3Qzs07zl2/lKoriemSBQI12LYUe7wZgDlJwFGdJ3cRJ0S7rcN3vS05a7FfRoxb4
         DpzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=d0ImBQUc;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kxeQHFGsmI93ZRrigrGn2VGlleEgv26JrVwtfQSmIi8=;
        b=b1VQsOPUPTkY75M1Pe/COe3oyTFCkvnoHcS9cDwGd8JbJ6J5iQrhW29R7m+5uqDz+t
         QBnzykk66CmtE5Rjrh6f7DB/cS3ZFzBam6LfPmL/XBE+myNVl7XIQx9SIQR49XMzw6i6
         5GGMECZ+bXxE/Na9kMVIyZ98r0Gz6DqWfO3J8oxrWWl1zF84KXgmYWIjrHbzi3JGqni+
         v8a2pebEpwRdyK5eRFw5HorEHjtKXZGruQDIlNpXIPjImquk9NCn1T/qPy2CXCGmIImy
         LwbQFJdLz/R/UxevrK0NwyVeSIfs083U22LzwjAuwHN9DKBdW3X9Kn+tgDnNmX4JQaKQ
         8NOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kxeQHFGsmI93ZRrigrGn2VGlleEgv26JrVwtfQSmIi8=;
        b=lNasrsfMx4wRGuT3cHz1AK+sjBX6R26ZBBJIR459TY++9isDUiFZI3RNZa8CfBIgDw
         M4Nbw7rAU66Z/PWokMvSJn4LLyjflQol9XaXjwWZVMFDfNwWir/jw3ulmX/NRyjJutBK
         XfUUHNLDmM9oyIAp785BNgz0KgEZwI9tDINBnVmOITxEVn4wMQuuT8OLS5RDhYD2D1kN
         0hbG6ltCjcwjrZLIEKSeXUdEOJCx7i/qVgjeF4r56fzX95Qj/k9/YQGEcq2LFn5176Tu
         4bFdYHMAgy20iPTcTlnJBm3CmldzDO7kEVH8Y5mF6oBf2lh4kWSFD5o2xlolpYW1/zfL
         0EzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp4OvZDqtAxoO8IZBK2uE5C52iSRbss5AATsE1//88lif6te/qA
	HtJf1vikgoKaIhYMl6FjPxs=
X-Google-Smtp-Source: AMrXdXuNCBd9tNuSugzzb7JrTnkcO/A5qGFYlwt1emBK5UxNfurYpIDhFiZ8tBrm/6GzlrK9+0rJAg==
X-Received: by 2002:a05:6122:d1d:b0:3bd:ad7c:b3ec with SMTP id az29-20020a0561220d1d00b003bdad7cb3ecmr2080906vkb.0.1674229265827;
        Fri, 20 Jan 2023 07:41:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:20ca:0:b0:3b5:df37:23a6 with SMTP id g193-20020a1f20ca000000b003b5df3723a6ls947468vkg.7.-pod-prod-gmail;
 Fri, 20 Jan 2023 07:41:05 -0800 (PST)
X-Received: by 2002:a05:6122:1285:b0:3da:1c67:7011 with SMTP id i5-20020a056122128500b003da1c677011mr9493305vkp.3.1674229265238;
        Fri, 20 Jan 2023 07:41:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674229265; cv=none;
        d=google.com; s=arc-20160816;
        b=OnbM5yWIiOj45+m/6GfsmuafKC90nEaya6eA4AbGjzFWEDaOpzRTKUslch74gNUmn8
         jv6k+99eHPMOXWTbcqt609VnAxrI7aHEM3YBbNKhDaOXur/LV6tagwQaajvxZqbMn5hT
         xRo8heYoIe2HlOTD677fac59Ymy3wn4cOmzA/oRK3SNT0K98ckUHX6Si8LEzeCJC6NVO
         E5Au0oli5MUns5mUamJsmTd4viafkGDkPrVJhxWBVgi7mqDuAHWCThU91iapd9+6nGNS
         gUZ1OF6HNPfLA97B0Gd+bE0gjHUPQ69OQpVCJlj40VHisBBHuJYL9HfofrDUD7figBhR
         r1cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=75d/J3khF4Dbn5fzcg9rN+6VjL8Dp9ov4rvyfMDhcrA=;
        b=fzKEfw5fhnMZ2U6kjhPGsBkKEdidEnA0ypTnHtyyFRvCIMitIRZ2s9rNKuJvdWeXol
         rrDntCHqxaMKQwyWcHW6CD2hpbcmuI9S9ZiZwwWZTo1iVBgoMUQhjPMfltUlMYw6IKy5
         8Gr088GcXU12plE3fdNl14enCcR6+fHlV/j+3TXQ60i0etnEz5icdpUpbKkouOJC1cuP
         IP2dNcRWk5XKd02e3gTSvbGUnD8SANkN2j1IxFYyyPXRZFJkpzco//FjBvqvGYh9r6is
         J92Dhw2LGvvc5itAIdVuN6Nz8QxAWAtTDbgZNmd9HqgWYFLaxopospjzRu42eDHGBlQE
         lYyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=d0ImBQUc;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id x12-20020a1f310c000000b003e1e0719f2bsi391105vkx.3.2023.01.20.07.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Jan 2023 07:41:05 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id v6so2882348ilq.3
        for <kasan-dev@googlegroups.com>; Fri, 20 Jan 2023 07:41:05 -0800 (PST)
X-Received: by 2002:a92:c5d1:0:b0:30d:9eea:e51 with SMTP id s17-20020a92c5d1000000b0030d9eea0e51mr2273296ilt.1.1674229264495;
        Fri, 20 Jan 2023 07:41:04 -0800 (PST)
Received: from [127.0.0.1] ([96.43.243.2])
        by smtp.gmail.com with ESMTPSA id l14-20020a92700e000000b0030c27c9eea4sm11664570ilc.33.2023.01.20.07.41.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 07:41:04 -0800 (PST)
From: Jens Axboe <axboe@kernel.dk>
To: asml.silence@gmail.com, io-uring@vger.kernel.org, 
 Breno Leitao <leitao@debian.org>
Cc: kasan-dev@googlegroups.com, leit@fb.com, linux-kernel@vger.kernel.org
In-Reply-To: <20230118155630.2762921-1-leitao@debian.org>
References: <20230118155630.2762921-1-leitao@debian.org>
Subject: Re: [PATCH] io_uring: Enable KASAN for request cache
Message-Id: <167422926391.670047.2726157847923072257.b4-ty@kernel.dk>
Date: Fri, 20 Jan 2023 08:41:03 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.12-dev-78c63
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=d0ImBQUc;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=axboe@kernel.dk
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


On Wed, 18 Jan 2023 07:56:30 -0800, Breno Leitao wrote:
> Every io_uring request is represented by struct io_kiocb, which is
> cached locally by io_uring (not SLAB/SLUB) in the list called
> submit_state.freelist. This patch simply enabled KASAN for this free
> list.
> 
> This list is initially created by KMEM_CACHE, but later, managed by
> io_uring. This patch basically poisons the objects that are not used
> (i.e., they are the free list), and unpoisons it when the object is
> allocated/removed from the list.
> 
> [...]

Applied, thanks!

[1/1] io_uring: Enable KASAN for request cache
      commit: 9f61fe5e410444ccecb429e69536ecd981c73c08

Best regards,
-- 
Jens Axboe



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167422926391.670047.2726157847923072257.b4-ty%40kernel.dk.
