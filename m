Return-Path: <kasan-dev+bncBCT4XGV33UIBBG73XCQAMGQEVUHZTSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AAE6F6B6BA2
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Mar 2023 22:01:16 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id y9-20020a056512044900b004b4b8aabd0csf2974734lfk.16
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Mar 2023 14:01:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678654876; cv=pass;
        d=google.com; s=arc-20160816;
        b=1FFR4O633KXJHbDPJKu6tVd691jczjT2nGSCac5DlfJTMBnMdC2DyCNOv6KvGrDw9j
         rXdXHf/PmphGaHjgvf2oseb4yjxegA7WU0Qh9NEVEoaTKtyS0pVlTlaWHypTFj+kLhW7
         EHqdYgU4n9ZhATuZ1IfP3lZGJnCDDG81CftX8k+0Wk7nWh8e+w1psG5XUJudFD28quJq
         RGLoPOlaAiZp/41BdLh7Vb9IW5ErIDRbhEZAxNsK5QzJGM+eGkvxuw7O6Y2xUP6VFD42
         BLSa1Mn0wjWBt9M9PzVZagnJCDwBLo4WZkukG8U8BCnlqDvLqiRWfzQ7U9GBFB/CyyNu
         IG0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KCw509eEUAnNyF5APosRR9FecBG11cqDzLElbxqqYN4=;
        b=LkTafDx8iONtxCyOI6tHH4pnYZ7fiK1kKq03XvVltdzsFjWfR20lUHUyWPI3y9nHfb
         PBHyJoxAkLLVNfEJMZISRN2UnOy6N+hd5m3hVg1RvaJlrjIzPZ2hK+FD8CSBczoJwTW5
         DuwTzc+hoYCnzWK/0TG6XM/Q/cY9ZTNu8MnnvlxvDuYbCluGLaFOJ98djHx/Hn4nlZp7
         MzClqlzkFJ4CHc8GAPuhoA2IbYQr2OLsPG426qSJXagvG4GUQc8rrIIqkQU6MJvfEd8R
         fjBzd31LAOn2XcgzkD9s+BSx4gQcmLVcAB+eJYI6GiHlJXu/GRUbQ9MTFyV1zNKWj6UT
         dXPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=I8MXmpmj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678654876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KCw509eEUAnNyF5APosRR9FecBG11cqDzLElbxqqYN4=;
        b=U/xxyPUw3mhb49QtCq1SciLDFNHNe+2kO7mpY75qgEyOIEQHx/JA3I/drnPythz8W/
         Ehc+YV7NgjFomNkJcVxguyTLY0lkwFpbcW6pGxgidMC5zsVh10e8yfj4hEQml0VQHTXz
         q8ZErOXoLyoRKaEoCIzQlAm/j35ZZjBc811xUWz8a+MYMMtVqRnDOS2REKxomk4jqutj
         Gdnh31ORaquMQdA+xmBbOQHBWE8nswFmTejlrCYGeEa6nWGmhbVoanY/DHoc7yoL1PFo
         vPxIbdxvCLeM9j/RoW0ctR+33/3HlgeUzBNmxK88Odnt/CyM9W8AT2URBswOYnWFUave
         4W8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678654876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KCw509eEUAnNyF5APosRR9FecBG11cqDzLElbxqqYN4=;
        b=TP9TS6pC8dykm++9bWszzDXMNhDjUo3ZDNCHkeaU4nQuCGCBjwKT3XDAvZsj5yuOfb
         RSUgCwk96j6TKBqtNyVR7HMLBjib7kmrn3kt9WWE0OHzIu5/CRRy5vc2ImOCHWiiw3JR
         9AW6YBbUkzz4tu8RahF86e5wJifixIuiBVzDuyH4jvB1SJJEbqaXtVK5AxJ/0I2JZbqr
         69LBU1w1TW72zBT5XcIU8eBOnsNNF1PmLVG6UbzS5A1XyE0r44EUGj31UFyrjehVARKd
         pOubnLnaKx1Swwwsioaj1fAcQT+1V4Y1GNRp70CpGOQRirIC1uVKZuBk1b0dk2MbchTa
         HVcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVHbpK1nPcIwtBLQj5qCRALTKApjyRvUHKRqxP1bRiuB7jtWof4
	DhTi6AVUd6ziDCrjUzBN5BE=
X-Google-Smtp-Source: AK7set/KkoAhndyPJUCOSe4nGqCM18/OC/sKEpJXIWJRbQdxXXjWa2ZJXXqUqDSeTSu3U6hY2r0/fQ==
X-Received: by 2002:a19:c212:0:b0:4d5:ca42:aee4 with SMTP id l18-20020a19c212000000b004d5ca42aee4mr9970822lfc.4.1678654875767;
        Sun, 12 Mar 2023 14:01:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0e:0:b0:295:a3ad:f338 with SMTP id b14-20020a2ebc0e000000b00295a3adf338ls1609428ljf.4.-pod-prod-gmail;
 Sun, 12 Mar 2023 14:01:13 -0700 (PDT)
X-Received: by 2002:a2e:b0f9:0:b0:293:2d80:dfe with SMTP id h25-20020a2eb0f9000000b002932d800dfemr12304120ljl.12.1678654873595;
        Sun, 12 Mar 2023 14:01:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678654873; cv=none;
        d=google.com; s=arc-20160816;
        b=gKrRYmRke11r+S2yyMfDWrpr6frNkPAOibM/d7qoToBzHnvUxbm7ApQEJpJ+FxeMsL
         LADcb/NkSHsYBO/ejmGJxawZDO+yAa7nR5+KYFdDxQE8W9/WklVQaEKKDkykmNTNhDbX
         1Ws9mzufwSVUzTeUG4AiA9Qmlq9KAzE8hDjFZ31vqMhpO5EaY0/FeD7MuAMrP2sHD9st
         mdc4OjM0Zaft+HfCwNmE7i3ZHbW3ObqiO3XObvolDYQg0DacmP+mqNbrB3J534kGUDIX
         WhuWOHKHMlEgjrE7CPJFWn67MfDSA0Dv+S+fhhoPr2b8vY6yygsFXkBQLzxdaxoeew0k
         xe8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=h/QbH9lMskUmwSBarjfV2uOScXdYpBwtqU0B8jX9MqE=;
        b=qDV5BBg1T6vDcVDuXBpFFMUdGfsJHaExPjd7m3pLizbef6SIdBp8Qsz4Kx7NJH2v9J
         E/ztwPsngpJ+Tn5XMHNQxDWZa0blFuYnbXabCAJ6LhjmMKbFfRXaavLrxAGVhhR4Y2RD
         2EOorlmRRI2QbplG8lj764u4zoC7MS1KQ88p1MsuCkM/Y7lP3Uks/XVmK6gNNAfRUPM8
         /Sws8pp5KM3c6vvS7OHz044Ki/3DTZdD+YRrA0WaLl91tmnadWzg65GqR/QdXozN3D3F
         bXPMsSDqWN1EqlIyZJHb2IpcJOW0gUy9zpiaxa5K4rHbTCPhYpw0Oo1vxPFIALoZNu7C
         LhOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=I8MXmpmj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id j16-20020a2ea910000000b0029596269cbasi294206ljq.3.2023.03.12.14.01.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 12 Mar 2023 14:01:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E352EB80B08;
	Sun, 12 Mar 2023 21:01:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20696C433EF;
	Sun, 12 Mar 2023 21:01:11 +0000 (UTC)
Date: Sun, 12 Mar 2023 14:01:10 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: <catalin.marinas@arm.com>, <will@kernel.org>, <glider@google.com>,
 <elver@google.com>, <dvyukov@google.com>, <robin.murphy@arm.com>,
 <mark.rutland@arm.com>, <jianyong.wu@arm.com>, <james.morse@arm.com>,
 <linux-arm-kernel@lists.infradead.org>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <quic_pkondeti@quicinc.com>,
 <quic_guptap@quicinc.com>, <quic_tingweiz@quicinc.com>
Subject: Re: [PATCH v4] mm,kfence: decouple kfence from page granularity
 mapping judgement
Message-Id: <20230312140110.4f3571b92a2556767d7667fc@linux-foundation.org>
In-Reply-To: <1678440604-796-1-git-send-email-quic_zhenhuah@quicinc.com>
References: <1678440604-796-1-git-send-email-quic_zhenhuah@quicinc.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=I8MXmpmj;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 10 Mar 2023 17:30:04 +0800 Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:

> Kfence only needs its pool to be mapped as page granularity, previous
> judgement was a bit over protected. Decouple it from judgement and do
> page granularity mapping for kfence pool only [1].
> 
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.

Why make this change?  What are the benefits?  What are the user
visible effects?

> LINK: [1] https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/

Chasing the links indicates that "page-granular mapping costed more (2M
per 1GB) memory".  Please spell all this out in this patch's changelog.

btw. this format:

Link: https://lore.kernel.org/linux-arm-kernel/1675750519-1064-1-git-send-email-quic_zhenhuah@quicinc.com/T/ [1]

is conventional.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230312140110.4f3571b92a2556767d7667fc%40linux-foundation.org.
