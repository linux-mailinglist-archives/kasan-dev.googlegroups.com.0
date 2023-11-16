Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBOO26VAMGQEC7T36PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 62E3B7EDE08
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:55:18 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-357ce3f292bsf6625675ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:55:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700128517; cv=pass;
        d=google.com; s=arc-20160816;
        b=u4kCXyu+QpITfdQP4qZ6ZrBtmvVNq86v9sugMz7Q2sjoRjNd2amRsEhseUqE+f/UrQ
         5uw2pEz33A1oUVQJtdQAwCbkqjhKkXItCnTN+8eC5YEi5Y7PmNQXGw2f9V7swXYlnvUh
         INWWrx+yuXHZZBEAfAQhWSb3rBLWvFbzJqCiNReVxc7ZIx7tgwljXQ3x6IS/4IhZicc2
         cedTtirscfBW93bJ+rhtnUty5VSwXQYV91/UpIu/dzrYdJU/wuGnUrHnMGfCrPmqQK7i
         h5uJ4TEQ9MkjM3SUSS8049WxMl3inso21PLQ51VEUk3y7tT4a4CYKcx52stbSGXqx44G
         6PWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H9zkSNtU1N/9LB1KZpAnvw62nsaFs49G5JCvIcMd8T4=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=qsrpKuTz6Laz7kMlvYfFdLdV+OZ9MHb+bEFSjHcfOpiwQnMhv0QJGFcK+wcqmFtba0
         cnNEz8wiecOHiwC98S9/exxB57cFWjjS1JwlaOp5yjbRH/wQ88+JB+J1cBA9+3jFwuVC
         fsr2pH4z5CNvoHV9UN6DMfP9cu7bpfCVVRRukIuQ+h3/Nyzcamz0Q/BvJOX0K9y6NMcx
         C00ZP9p6LQMDaFGpt1CyGkUi03ZwE/C01V4JBUDjfohTM6kc8OZD+CjSgJINiT/KyHzm
         jHL1z67Ab1nrwLFUgDYVd38RjV1ownPpVOHHoCok+K9zi7p9m8XqfMZeUtUub5/qRuvq
         vo8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v2CW0Nqn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700128517; x=1700733317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H9zkSNtU1N/9LB1KZpAnvw62nsaFs49G5JCvIcMd8T4=;
        b=uLnLPfWlUg09htCAQYBU+8tvnpM2S66j9x7rkwwyM6tC5zSXOENkr0S/K50lyyaKgQ
         aJkPx0uINHAJkt8uCDSeSllbwd1OeB/8ljG3PjaIQtsxGVdcqZRM3YQD9zNu3HIK0NJY
         iQSbliNHmc/Bva3Js7Xhk3samZMpWAIXWW3Wxb4J+2Zqwq4Jnb5t9/LLevcJm91GmATw
         o8wfDq85a0S9puzjjFtn4WPsVC9H+XrJh1UNq23zMNrf0plEnffhAi+qbgQZbRMLbP4i
         Rw0KY3/Hny1IrN0tmBAalAaWwEj0W+09ijtaG0ThcZG2pxy8Id0wIWefOHCOf13f72pG
         VtJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700128517; x=1700733317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H9zkSNtU1N/9LB1KZpAnvw62nsaFs49G5JCvIcMd8T4=;
        b=gOUbjJiqudmHQcjENhhZVtTApPPnsji/nOYfw8EV9LNLANi6ANVH+b2iy0Tf4yZUHT
         HiTbIeu8bvYrowWBfl7GcQhSzhEIFdPq1t0OHnHL8oH0QN7tho1qykL2yrPjMcyPZaPD
         bNPuMETWMZUqhaub2Nu6yfv3P/82nR9BsjB3q167jTXNFiiJzhqFKFg47H5O5H15IPii
         NPgMRijeU9LmxMXXm9Jj6bVo9RYCIERJzSuTpmLryw5EQXLGbw78+0pnVJ2sOhjtoZyg
         Gxqndoa3vzJG/6TrevkFCOgsLif8uabuXohhGqswBXNUCciEGgMCF4NxTYiwayhMUqdY
         r23g==
X-Gm-Message-State: AOJu0Yx070eP4C92dwPbD3cKhNOvfsVvDi5pjWZZHOV8jWaKnkUUtTcq
	IKfP6e4r7c7jPCiYds1k4XQ=
X-Google-Smtp-Source: AGHT+IF1sYJnW5bV4NQ0I6apfN4+OvNnTB9Sztd3h0tw4bnFG/ZTfOn9A6WRWKrK0tOtiNAKss1RtQ==
X-Received: by 2002:a05:6e02:20e5:b0:35a:a2d8:e20d with SMTP id q5-20020a056e0220e500b0035aa2d8e20dmr21682556ilv.15.1700128517264;
        Thu, 16 Nov 2023 01:55:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f83:b0:348:84f9:eb8 with SMTP id
 v3-20020a056e020f8300b0034884f90eb8ls399406ilo.1.-pod-prod-02-us; Thu, 16 Nov
 2023 01:55:16 -0800 (PST)
X-Received: by 2002:a05:6602:29d6:b0:7af:fff7:c3f8 with SMTP id z22-20020a05660229d600b007affff7c3f8mr19538142ioq.15.1700128516486;
        Thu, 16 Nov 2023 01:55:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700128516; cv=none;
        d=google.com; s=arc-20160816;
        b=ZjWczuIlrrdyV1AI7Fd1jps1KsWjw8wMvEXoIpPQ/1Xj3gpWtF8Dm0xy9MvQtjTOuv
         0wlxLxZ8tbOa4EBPWsomwS+P5ozNep9jC1w6qZPIXGsCtUFSv0T0DFAogFAGnpBht+QJ
         yAyiTyZKZrgGWVjQwJQgvsLq2zDVojdL3EryDl8cP6x2O4yLma5nnurrvMItPn+PPsWm
         Pa8RtrwMd0rS/CQ7yjt84vZ4XQLl1htGr6NS8TayTfCDLrfzou7kJ4THZDlAxsQ8xoj6
         +H0dXvLmQNLbVvF1ZgaS7SNRc+pW55HQ9VZXRdumrlT+j4WF4H+icwT3sMMRjTH/4Wet
         YR9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=baj28rj0m1kOuDCTG+0KHDcj/t1NS6y3cMo9+0jrJJc=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=aXvTRW8vAnBgGRXJiZRqrCaeq41qxevfWqHittuYGTJ2QoYq4sqQ9uku4fOcn+J7We
         7MTLXQ5kcMbU4J5IRqM99j5TBCVKZmACmWWjhs/nHIGe4ABb1Rr5Q/vtg2ZHeKd4b0FK
         EDnROMk9WK2gs5ZRY3C189lVodLuVcN4zqjGFtiCNdu3fci3nYKlT+DWIRCPJZFNiRKa
         7iEkNgj4zxmK3wSyv4PWZYuaic94TjsGxI5NjF5qgyl7jCCe46wNHE5UwZQXz/J10uhJ
         5i6HKk5ap/IMerH2KfuUrznMaVfC2xodE5JdOf+SCuobZcqbVkob+4M/XPh2cr+izTJ/
         hQwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v2CW0Nqn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id cp14-20020a056638480e00b00437bda7a9c2si1615591jab.2.2023.11.16.01.55.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:55:16 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-5a87ac9d245so6597897b3.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:55:16 -0800 (PST)
X-Received: by 2002:a25:7a81:0:b0:d91:1296:947 with SMTP id
 v123-20020a257a81000000b00d9112960947mr13819109ybc.40.1700128515815; Thu, 16
 Nov 2023 01:55:15 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-15-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-15-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:54:39 +0100
Message-ID: <CAG_fn=WSq_r5ry-0uviR6CUx-6eqXo5tqCtYAL0nE3UYyA4=pg@mail.gmail.com>
Subject: Re: [PATCH 14/32] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=v2CW0Nqn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1130
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Improve the readability by replacing the custom aligning logic with
> ALIGN_DOWN(). Unlike other places where a similar sequence is used,
> there is no size parameter that needs to be adjusted, so the standard
> macro fits.

Good catch, thank you!

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWSq_r5ry-0uviR6CUx-6eqXo5tqCtYAL0nE3UYyA4%3Dpg%40mail.gm=
ail.com.
