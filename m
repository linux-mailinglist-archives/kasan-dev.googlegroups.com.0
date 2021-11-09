Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQW3VKGAMGQEW4OAQRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 03DB744B1DC
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Nov 2021 18:20:03 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id y23-20020a2e3217000000b00218c6ede162sf2470081ljy.23
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Nov 2021 09:20:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636478402; cv=pass;
        d=google.com; s=arc-20160816;
        b=GFf0Eay2Z4bNkKEBrVjYLjzPqAeQSOGqRkP5zh3J96a/e+eFi1mBgteQcuK/7S6xi7
         FKVLV3CQKE7Ob12HcWdMG77w4Hn6766arvMp5bi3oJnLhxLbXuswyQkjqzrwVxlANs5G
         9tpklP9mKwz/E5o3e8MfzBmpzhwCk2PNfC163wI54mBvfdwXkOcpbXHiVBejDpceC3TY
         PCo3hFGIYgyy1D8v8FrSphoPd3sBBB5V48W7xfhjjDZtclHWxci8iQgslpyGXerHPkQ4
         F6pHyOMmV84UZL3Zb33GEa11fiiC7yDfsjod+VJw5c42eHliU22bzsiGQHRT6XKXKjkv
         6wkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jBPn3wTENVQlB/3c6Is/UlpvTImsnyVoCxJUMepcf+0=;
        b=MeI/z9WS6iuiv7Zj2E3qymD/kslmChqI0bLSjKAbuy23yk6u2nL/67YUr6T9KXDyjN
         inzF4hxG9Mx9ZR4cL+89hKtKnXH9DTg9kKv2pO6okykKolRwajhs38lizrJ6wShO6U/G
         qKVrMXbBmzb0d1PGCZp3bJgQ/GhU/vPFKlDKIvYis0QkMLtn+uarKe1SmUxn0TtQJKRh
         +SifsClmkDDhFcDmlI4BHg1EtdLfztoUCr7Rc0CzDKg82xu0LOQqZUL1pkgIe9cCcmy5
         Z37JGCcWFcOsKuVcbqokgLLzyT9cV8Odg0o+MZNNMc/1ilcgbVe5TvPQicYuEVVQ8iBb
         8Uug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bxea1HiH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jBPn3wTENVQlB/3c6Is/UlpvTImsnyVoCxJUMepcf+0=;
        b=Vu8jEw9+I/FK7eWNIZVGtEwU/cV6RVXaKnbNnIOj87nOp/rJvsVJ2YLhV2TOkS3fsT
         aVZQyJ2AozhnH8gAn+CZiGwmhQ7GRZrbV4AcVBE6+FHLsW+2jKmvx2KjPFmRa2VxMm8V
         OWyYDi/nlq8zAHGpOYq6EXJrmwh7NHK4o9stx3AWWFjCGOrRsHm1zHfon/iIejmm8lpQ
         6hEDR7aoB1SjtvEzH87b9gCoH4geJKHiJZh6MPxyJYLKaW1C/tvFjqUMLDyk7TYDK86L
         RtJUO6u979WEw0ElkfJcohmCjTmqMPC55U6aRyF5C5azpXNsOq2RCYOTUl+tgXK0xMjc
         4DnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jBPn3wTENVQlB/3c6Is/UlpvTImsnyVoCxJUMepcf+0=;
        b=14DfqCptt8iTTZXy2qEZp0QF+jEbcTUc5I4cn2eB7D4dQgJvIH+3is6CZASjQt3IeD
         FFME+s2NJUEHSLrp4r3okiLkx1jIPbcqaVSs/nTjhqJpjSs+SFJ7BfZvW+VEpizzTMmo
         ZCq1SvjKRV/lsy0i8T13JdnD4xX9iNaimcl5aV5LyseZr6ZTomjWnDAzHMUx9JvKlsfv
         6n1/yVRf3VtWlk1uNTe5Y48D9QFNijfhgDZbqNe7c17fgBuHcTO35daul1Fl0z4uPEBl
         5E9rIEz0LGG+N3BSVaYwrTgogCoxVBPtdWIp/2fn4yh2xQSUmZFOa76hhWjWae5OJs1I
         LpjA==
X-Gm-Message-State: AOAM532tqw7ZhUAhqVM/NSDeaXKXSttmntpp+Gxdq/jcSyljxkc9JasM
	Hlc2QV2wY9xjD6ZYsPR1n6Y=
X-Google-Smtp-Source: ABdhPJyYj3LvMypnFWH3AbIuaSjpfcICA3VOh2dMqwf1KlH7zic2af9tLU4I9LYhRsFtafSZ3yCitw==
X-Received: by 2002:ac2:5444:: with SMTP id d4mr8292658lfn.678.1636478402465;
        Tue, 09 Nov 2021 09:20:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls786094lfr.0.gmail; Tue, 09
 Nov 2021 09:20:01 -0800 (PST)
X-Received: by 2002:a05:6512:10c5:: with SMTP id k5mr3915287lfg.34.1636478401380;
        Tue, 09 Nov 2021 09:20:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636478401; cv=none;
        d=google.com; s=arc-20160816;
        b=w/iq0kESd64rChP7saaQKYmyWusUkUgRE71e7MF1GyyMgf1cbHI+AupuJO+GPpGDDS
         b1IDKTGL0Mvw9mOp9uGRrNLaRyiQHpEY1mhulG6/K5UGO+u0sOwUvyiZv3MuH+oOlLe+
         gNsqiwBphHmIPlB43PUwMpi7glGye+xQrPrT2yifcNunMulVxED6+xgz8/w7YEgbl+Kk
         GH16fsz5d3GdAqZg1aV9W/E9eTeHxttHtOR7i4HFkfbAWWgiuHqoSE3p9zO3NOqsvrvr
         Scx/vX3m0IYz+rQaIHeB7kd6CbFqhbIIs478veKxGKeMZRel/mX4XOwvN2YzTOktQZsj
         uUYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OLzo0EOB1taa2CSck10pmNDW2WkMN2hcPFxNpgrSaIc=;
        b=iitOoaxt7ooZ+40L68SHiEywuwBGt4TSjHaHxXkAEYJAdk6doPuOlhU3BGglLT5puf
         Wa8Kt/vCw3m7XMLTbOxxSHFfRrEQe7rbaYN7HmcJUQENVMxKXdt2o7QELWzTyycg5Nu7
         g1pfz4jD84VQptV+c/d36NZ2tKbYUXy7i2K5w3pk3VwogihCyCBh5ytUg0do89QKkB8l
         qT4OeZCBq2dycAJufLMg4J1tVeK4w8CujNT5Vkbv8xHvc3HO7KLp07sGt46Ng7oqNQfe
         pdgrV1UWl7UXZVR1F7+FvyOOHKhBumdofrvqP2m67MS47uJazoQ0DgKFWuB7iNAWTUaB
         t/Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Bxea1HiH;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id z4si901873lfr.3.2021.11.09.09.20.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Nov 2021 09:20:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id u1so34257201wru.13
        for <kasan-dev@googlegroups.com>; Tue, 09 Nov 2021 09:20:01 -0800 (PST)
X-Received: by 2002:a05:6000:15c7:: with SMTP id y7mr11588170wry.424.1636478400645;
        Tue, 09 Nov 2021 09:20:00 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:d20d:9fab:cbe:339])
        by smtp.gmail.com with ESMTPSA id w15sm20755359wrk.77.2021.11.09.09.19.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Nov 2021 09:20:00 -0800 (PST)
Date: Tue, 9 Nov 2021 18:19:54 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: stable <stable@vger.kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Sasha Levin <sashal@kernel.org>
Cc: Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: [5.15.y] kfence: default to dynamic branch instead of static keys
 mode
Message-ID: <YYqtuk4r2F9Pal+4@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Bxea1HiH;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Dear stable maintainers,

We propose picking the following 2 patches to 5.15.y:

	07e8481d3c38 kfence: always use static branches to guard kfence_alloc()
	4f612ed3f748 kfence: default to dynamic branch instead of static keys mode

, which had not been marked for stable initially, but upon re-evaluation
conclude that it will also avoid various unexpected behaviours [1], [2]
as the use of frequently-switched static keys (at least on x86) is more
trouble than it's worth.

[1] https://lkml.kernel.org/r/CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com
[2] https://patchwork.kernel.org/project/linux-acpi/patch/2618833.mvXUDI8C0e@kreacher/

While optional, we recommend 07e8481d3c38 as well, as it avoids the
dynamic branch, now the default, if kfence is disabled at boot.

The main thing is to make the default less troublesome and be more
conservative. Those choosing to enable CONFIG_KFENCE_STATIC_KEYS can
still do so, but requires a deliberate opt-in via a config change.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYqtuk4r2F9Pal%2B4%40elver.google.com.
