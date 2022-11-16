Return-Path: <kasan-dev+bncBDEZDPVRZMARBM4I2WNQMGQEXVE4BRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E58A62C9D0
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Nov 2022 21:12:37 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id pi2-20020a17090b1e4200b0021834843687sf2509565pjb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Nov 2022 12:12:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668629555; cv=pass;
        d=google.com; s=arc-20160816;
        b=TPzuRPqeqdQl4bsAmx/ZKb6DE5WYtXdfTh4dIYD7G0ESs/+0P5FCgdq3KLjQliTNTv
         2PG8/+qkG2NdtCuBw3lcyEkBthhQsNKj+XyOMYNT//a8of5lYq7YF8QaVlY2P2lIr5vt
         Ie7IHJKgPFYrj2UvktI+llkpen2wIINQj99lUb2nqKf5uox7GlIRIlUyHgobCpNuNFof
         HgalBXQ2N9vrA8D/Y2YotVrQ3Tf69obOcjIf1KqWeI8Iitqr5FQuYc0UF8iGMuU1p3va
         09Ht4jqOXyeCJjdGu9PItdpI//+hXYa+ozC6AkvvRyvclY0PqW9fgFN3YbKKVH12e2XD
         7zHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TXGNHD9d7HawFUrBi8J8ggdi5izjot36ZHCyilNzrl4=;
        b=M3BpL19wV5zDS/JliGRYtCAOm+q10pR+zZFuvR4YOftScxCLEGok+EKwyhKzMcFGlW
         87+uF981qK9UHgpcoFGHdWDe0qxhqYkqTlazYT3qCyJmwoKXs7RBHL9h7Qz7CIEHA5qQ
         lbuwhKn79obgH1SAtBNK+1puxy4Aiz3spr/OWSjDwuaNu+kJ5Qc0a4UgTjLSRL9RpzO1
         6ous+UfLcDq5N+lIEWYltdr8/t0+Aaylyh2hfnmbtjT30mDgwWz97Nrra57pGqzJPD1P
         hYIjaBzKUVl1vWu3lkGGVwhaL0J6N/EFYI/eJKJn2iEfdYewBajJeGtth2/Y3V/TvaXQ
         pzYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZmqoITTL;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TXGNHD9d7HawFUrBi8J8ggdi5izjot36ZHCyilNzrl4=;
        b=tN5lBinG9x/WxQcRzQBGq6eE55Q45ye1YRJFxrfezP/27IXyGaKQCVhTZbHA7alUiK
         EsLdIqJuwhEjfZBHlQ62GIMdl/wgxbHT3Zl6E8IwRF7FkE7E7WiNUdKRlOwNg+hnkSFv
         p1Tqo1EEcfaje+76bxHo9y9/TCbJLdAOEKGXQzqCIM6KA9mzm78aTaweCe090lF1/6bI
         sOCXVdwW2eqyF1IWvPQWzu3w6ftk7NC6Y60S/td0/otwJPYrg4jg1XTtinZfIzHio9zJ
         F5Ob5mNTEt0d6wjd6UxgT8iFzwd5bcT3Oypa5KYGe/zSrRiatiqrK0CDHKcWqiL/+2q4
         uIbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TXGNHD9d7HawFUrBi8J8ggdi5izjot36ZHCyilNzrl4=;
        b=RjHv3Fv4tkQw+6AFmAcgaQ31GOPctviaAzGvTnRQBtdl+T6lLPMrP4YBR1FOnWbf/K
         NdjWQJzI9iVZLgkYS0orSSAK+vaXcboQ6/US7rSViUZUA3aOJOlSNjn0XkvyfRnWjsS9
         8tWSENIuMBtuq7GTHiigT8mNX4emoOS+innP0i3nu6D4SGHZyZepHsnwjIGdhYwTdN+Z
         tKe30Vxm5qiNQSWQSeMzQ/JUT+1CnuBbbEWYLbCQz/fpCLw4qUC/uHvZDZ6j3Vq9Ji5H
         MbJXE8QVwOh2IJ3x35wdZBV99k8cn9hly2h36V2kPOUHVohYrQsqdybjI2wVeUnzg5TQ
         jQpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn99UcJDAQ6okV1W1QSwq52d64BbZSuoGnPJoLdwhCoKZHzrFQw
	BK5wwx/ewQSCDREYCQg4TVk=
X-Google-Smtp-Source: AA0mqf6hcuevbbjHstw73B1WRCfyFMFDTSUxBCo+6cBSvVW60q+2hbvZAGTyBQOYP/3jNxS32WXemg==
X-Received: by 2002:a62:ce4c:0:b0:56c:80e5:c436 with SMTP id y73-20020a62ce4c000000b0056c80e5c436mr24232482pfg.36.1668629555399;
        Wed, 16 Nov 2022 12:12:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1816:0:b0:56c:1251:19d with SMTP id 22-20020a621816000000b0056c1251019dls2433pfy.0.-pod-prod-gmail;
 Wed, 16 Nov 2022 12:12:34 -0800 (PST)
X-Received: by 2002:aa7:819a:0:b0:56b:e16d:b08 with SMTP id g26-20020aa7819a000000b0056be16d0b08mr24876649pfi.70.1668629554664;
        Wed, 16 Nov 2022 12:12:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668629554; cv=none;
        d=google.com; s=arc-20160816;
        b=WyClqyQCMMJOlDG6MKSE8l8ToSWTj6595B/gSQw9M/mTbwU+/+jw+BBmdVIRKAdkBj
         nS37t4dOAqw9N3o3ahrRvWgpVcfj8R5eXvP7TYfDknUHYZM4vAREpAAL+n2o04LgAfug
         p/38996m2rA9k+ENwqRusYKke0LU1qV0s3iZ7jjuinfuoL5mYhLIkLqn1TcenFfeAP0M
         WHk4avcgrtzi2W4AhiDJ2ofzunyrDCQbmfA8qoTyORavmFjiy9nSKVhXYYaxNB55Iuan
         YooTvanm0XoKuwum2f4bXNIhIQ5RO0ESYR6IzsMsLLjmoqoPAwdX5qTllR6e0JDyuzq/
         7M8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bEeJvOi1zvY1PJEhN3tJFTtRXV9zitnChh9ZoFPUJUI=;
        b=PNuYSNRZhE5eKqp4XL3odZsMJpzmPYf3OR5HinPalaUJxvi7uQb51fS8pCySfgxw/7
         g5LCwwoqDodCEVCF7bS1E3dKlUIBygWBP0FGPb1A4ebaBoVc1h/vOwSOxqZISWGrJBGG
         gY6AbADtClpePIM9uoCG+goFx4Ds7FmMRL5rUDrKQU5ijSlqs54ULPysE1ECnWTqEJXz
         7Niygidf+lo7IvhUl4RjaLG1s6eQzYjx0AEvKEu/LAsK9j++Raqq3/rqmapB5MAddl9Q
         Xduv2qxMfkHU0P7Sm0cqfR6TJfq27FGWBpIVJHrXUvAcOM3O44vcXhQTxmmeCLQKaISl
         vSRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZmqoITTL;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id m3-20020a170902db0300b0017829f95c9asi935925plx.3.2022.11.16.12.12.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Nov 2022 12:12:34 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 141E661F7E;
	Wed, 16 Nov 2022 20:12:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46950C433D6;
	Wed, 16 Nov 2022 20:12:33 +0000 (UTC)
Date: Wed, 16 Nov 2022 12:12:31 -0800
From: Eric Biggers <ebiggers@kernel.org>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: KMSAN broken with lockdep again?
Message-ID: <Y3VEL0P0M3uSCxdk@sol.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZmqoITTL;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi,

I'm trying v6.1-rc5 with CONFIG_KMSAN, but the kernel continuously spams
"BUG: KMSAN: uninit-value in __init_waitqueue_head".

I tracked it down to lockdep (CONFIG_PROVE_LOCKING=y).  The problem goes away if
I disable that.

I don't see any obvious use of uninitialized memory in __init_waitqueue_head().

The compiler I'm using is tip-of-tree clang (LLVM commit 4155be339ba80fef).

Is this a known issue?

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3VEL0P0M3uSCxdk%40sol.localdomain.
