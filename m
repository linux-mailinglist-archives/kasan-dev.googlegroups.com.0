Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBUP7U3GQMGQEC4UQIEI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6KWvCNS/qWnNDQEAu9opvQ
	(envelope-from <kasan-dev+bncBCB5ZLWIQIBRBUP7U3GQMGQEC4UQIEI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:39:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B47FD2165F7
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 18:39:31 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-45f11f18a89sf75083907b6e.2
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 09:39:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772732370; cv=pass;
        d=google.com; s=arc-20240605;
        b=B4wPeOvm+YFXttNyAB2o7JwV/s/xiXKFFm9+t+g5bgPqyD8RIQRynUOF5bi1XAqzN0
         WyhlT9V3IUagMTVx5+gLhd8GN6exXpOaFgmPP9v516ZOL/acfmlkShGeh6yU/zUA9r1f
         +Jh5HT9xqMPKyxJpxbFCUq8NUpyzt/s1qOyh2gcNLwiez0m6ONvOxDRX+ONmgfaP6ok7
         fYno0S4AoazYUTDgDOcUB29PhV8sbFjqVpnJAEJgKtSulPyWsY9TX3UokQ8Zta8F+Yni
         F6iojNH56apSwwdTDLT0GwuvRIB7dPsOfzXXLdCu/fkdGzloBpsXJprv9iJswD5JiMYY
         7DDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:references:in-reply-to
         :subject:cc:to:from:message-id:date:mime-version:dkim-signature;
        bh=G+QbcCqCXTLcTrr5VibxDnU4XrbR/FGKHntpB9MKTaU=;
        fh=9xuV622jBYHZ6r+q3ggpgU0WN+fl2kVl/KRN9/8gg1o=;
        b=Md8RmjWQuy6ixKT1rsQ1MJNDy8DtKrfJNTLR6xABBjaRc4IBQmMZe6OvS2Ytt78fXV
         CqDoLGCK4Zj+bp38xpmIm+OBAHpi9aZLPxj/GEy05C3QWGZOCzfLFS3JGtZgbkar4MYC
         I5ER1AZRIM6I4BqI0fCO/iAqcebQV57X6zofpGpnnuFXyM33o7CCSifXzDuLRQW9o5gM
         g68AQSsFtcXaQFKDGYOt4GPfJVQhYTVBJ9arN/w3tmOSNVQQF745qv+tPuc9PnEpN2lQ
         kACn3m3ssXd/Ze/EuhZWJlb/dmNhnIejGY+abolP/j4UxTjBjhQZr2qDJa2TzQRDnG07
         po3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WM4y1elR;
       spf=pass (google.com: domain of tj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=tj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772732370; x=1773337170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:subject:cc:to:from:message-id:date:mime-version:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G+QbcCqCXTLcTrr5VibxDnU4XrbR/FGKHntpB9MKTaU=;
        b=vd1aCtX00eKv5vXXSq26UAHbTdnWkeikpKZOcBLrCILZiGWzU1VMsR1usHsshsrRjw
         vV0TUs712ersrE20VedNYYbZHHc6HXTLSsctX8RSgPujmtFQDkHXp00iwPDKphdHeXES
         M2QTEhDjaPqTKHfJpFKkUtK8jpipNRMmDY05z3JeW34i0J8aNFTmvG6YD87HyiONyPtJ
         9dz59XIkXpTdWjFHf7DBOQfhWEokw/zI7ReTrt3iReV/OizA0eyt2aU2CskskzC+ttfQ
         LhhpIWvfXt7zBvyT+CSRHN8kokLEa1FwGKtfRKFAYjmUXYotacvRRwTOEoINgLdFPnOy
         lwcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772732370; x=1773337170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:subject:cc:to:from:message-id:date:x-beenthere
         :mime-version:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G+QbcCqCXTLcTrr5VibxDnU4XrbR/FGKHntpB9MKTaU=;
        b=SKywZvT/JbC4Rh+DriODA1cI7s1hN3SYspyonWfk6L73tEXKZzy1icAjSHJ8h+GkxG
         aNq8/351lxNc/vab68B0mvX0z1CycYpnKI9WfptDliQNpgKnH7FlVvXZbK9VW5+fPdx1
         k4lI4Nrqc9DUMtlZ8NXUkktehZR+MCpGtzyN3ELeBSKwMFg+hRAfZ+k/QKc+gLi0viNn
         0XltguUKfjJ9RMcdSTmoi3gviIx1rdCGyyux+cOlC+o8fxvm1ESRsKTcYAv3JlLny+J1
         cUSeyJVVr9lnPx2j9Y9ZAMmmDF2JJQUQdEXy1K7uTdZ49u8FqPRWjwQeWYCKmSPKhnqb
         W2Ew==
X-Forwarded-Encrypted: i=2; AJvYcCWmKuqukJSBLWNal7wmZlCAounqp+kh/reSz16jGNLr1MSal2RnQ1r0hb4miTB3H+IhnjMNKg==@lfdr.de
X-Gm-Message-State: AOJu0Yy3pIG2HN+NaoKQdQVgWnVWDqsGQV04DR+T5TbjzOLT7TJf0Sec
	hsAbtnZPTNrS3naFM07WTJbF9LkI6bdgNSDWateKhQme6P6D/9rCUEhM
X-Received: by 2002:a05:6820:168e:b0:67a:1d5c:b240 with SMTP id 006d021491bc7-67b99d14c34mr322373eaf.73.1772732370255;
        Thu, 05 Mar 2026 09:39:30 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HgXTQJh8px4tIFUxpNPEWcX+s6AaVwIy/rhT6QQtCYzQ=="
Received: by 2002:a4a:e9f4:0:b0:679:89f7:f5c3 with SMTP id 006d021491bc7-67b92eeddbels473612eaf.0.-pod-prod-07-us;
 Thu, 05 Mar 2026 09:39:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbSMtnTinfizYva8ZkAI0KZLEUuI+OjijbD4GbGEV9OCPkJ5nw5mwTOSoeSgyaTX7zGFOzrWs/Y/E=@googlegroups.com
X-Received: by 2002:a05:6820:2907:b0:662:f0cb:84bf with SMTP id 006d021491bc7-67b99cbe0ddmr345585eaf.36.1772732369424;
        Thu, 05 Mar 2026 09:39:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772732369; cv=none;
        d=google.com; s=arc-20240605;
        b=FQY6uMZu8kyhEI8pUVrSRN138txYwQ4D7WeYKkwiYgjDSUALvSVzScKYBvAYe5klz0
         wPxxZuNOCVm2mZV0kzC9aRTMPqoBPTOPQ+Qt1LSRMzBWYiWL1oZbAZM0afCkD1ZzxMPe
         1lD4i+paPhrXpn2a1DdB/PiDX8Mo8RQ1w8ite0bbW26bM91gvSOH5hEB/gRQ9hu78/V3
         Ym7ch/8ffis+biaF35XdLyyK+aNQMi3tLecbPY9tC7vDbfUEnEEAUc0o8Vvjz1f1FOCo
         r3pmkZksUevf3we33jcyPQEK3E36VQqQ2/+obt6sMjO/P7D8lEDQ0W5JkiK6WST83+rU
         CzWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=KOsaiFlB66me3r4jsxsLmtJlMEWD3cIFwfFcxgp7akU=;
        fh=egcSSyY0SntmNRBlbwGwGwprA+DEmG2/RAUunGILURo=;
        b=GbczbqRornS2LaTDqTrY7QvhZDvCtYUHE+aArJUq5PeUu++uvtCOW0HaqFTmPd4nLv
         VepEyurDQJfBEXide/MKxVKfDu2zAacM6wo6bUOAA2RsoRhVnqCO7nPHNyWFSpE+X2ci
         n3wafsgrOmAQVJYHdXBj0RfK4c2dBNO/SGswQ+3a89az22ZMP71ZLveVhXh3r/FP5Sdf
         EONtmwRQIgZKrKjjjeH+76M8bLLaPiq78slbnLdYH4pjIQA2QilPI+YlThF0vXN+PTFq
         ebzYiSvK8kn7IjMDRVnD/pbDO/ng3Mdz+t0p7t4mPS3bCfgiAFWlOJl3KDwWagkcsos5
         fJkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WM4y1elR;
       spf=pass (google.com: domain of tj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=tj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4160d17879csi766657fac.4.2026.03.05.09.39.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 09:39:29 -0800 (PST)
Received-SPF: pass (google.com: domain of tj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B769D60053;
	Thu,  5 Mar 2026 17:39:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40825C116C6;
	Thu,  5 Mar 2026 17:39:28 +0000 (UTC)
Date: Thu, 05 Mar 2026 07:39:27 -1000
Message-ID: <07e882b4ecdfc98b34ffad3696d758ff@kernel.org>
From: "'Tejun Heo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Breno Leitao <leitao@debian.org>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-kernel@vger.kernel.org,
 Omar Sandoval <osandov@osandov.com>,
 Song Liu <song@kernel.org>,
 Danielle Costantino <dcostantino@meta.com>,
 kasan-dev@googlegroups.com,
 Petr Mladek <pmladek@suse.com>,
 kernel-team@meta.com
Subject: Re: [PATCH v2 0/5] workqueue: Improve stall diagnostics
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WM4y1elR;       spf=pass
 (google.com: domain of tj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=tj@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Tejun Heo <tj@kernel.org>
Reply-To: Tejun Heo <tj@kernel.org>
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
X-Rspamd-Queue-Id: B47FD2165F7
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[gmail.com,linux-foundation.org,vger.kernel.org,osandov.com,kernel.org,meta.com,googlegroups.com,suse.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_FROM(0.00)[bncBCB5ZLWIQIBRBUP7U3GQMGQEC4UQIEI];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[tj@kernel.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

Hello,

> Breno Leitao (5):
>   workqueue: Use POOL_BH instead of WQ_BH when checking pool flags
>   workqueue: Rename pool->watchdog_ts to pool->last_progress_ts
>   workqueue: Show in-flight work item duration in stall diagnostics
>   workqueue: Show all busy workers in stall diagnostics
>   workqueue: Add stall detector sample module

Applied 1-5 to wq/for-7.0-fixes.

One minor note for a future follow-up: show_cpu_pool_hog() and
show_cpu_pools_hogs() function names no longer reflect the broadened
scope after patch 4 - they now dump all busy workers, not just CPU
hogs.

Thanks.

--
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/07e882b4ecdfc98b34ffad3696d758ff%40kernel.org.
