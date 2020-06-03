Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJMZ333AKGQEZVDZC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 404951ECEA8
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:31 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id o1sf1573077plk.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=yWdVPidXjx0utRGdz3mm1180be7QfNJJm2g5aJcx8rmZIzu2/vv1fR52sonxhtpJja
         5hlCq2Sjm6OZl04OoxzGpWcUx6cuCy90vu9G4wfAHUkCK0fCLSVfEpe5P0eXDFheroJ7
         Ono/aIdyUYiPdXrc5HAwYRBYOJt3rYjCYGdbwJkgzfebCXlJkKBhgZ36MmPjL+umopwl
         nDDjEBvqW11TsI0UTTRByStjjri7Mwp4KbB7TJwICV6Gbz+nrAm+qyZdwe6zKkACCB3u
         b9SReJWlwRMckM6f6qMR89h4qtFXZ12eyHEpRKUa1f+4HwLq3syBe4j7+6LiKaM2sQVY
         yr0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:user-agent
         :message-id:mime-version:sender:dkim-signature;
        bh=hBqPkeFcqPKoGjVmihZ6G49I6kT9Qapd2iQydiOZvMc=;
        b=cbnCP1aU+4wW4GE9J6RrjTm+DwE7uCAOTNnBsXY0wWfI/jMpYFw4FMoN+Zs9pAF8Xo
         YHA+RcBykk+SfrGa3D+Bknwd3UKDItVxoQ/kw9beByy3e2lJweFGHYtnVOIfQOtGtK+k
         TBIZuEf3rdUk6aTVvJHSy2KC+yo4h1m7voJCzTcFDhtzc2ADYWxF26k05a/hi75bOKbR
         IcqAXhMqAwadGLG35i3KboNpShyjCFXMEJt4ZzkhqicrwDqyQ4xZLqRVyw8Cs81pSgsk
         SJF59NCd6yYZ8zvtr77yP7IAMRTYjBkvWZc5rE7/ZUo2QZd/afPhRcIkskBQ8qSiZv6C
         v7tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=CZmeYv88;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:user-agent:date:from:to:cc:subject
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hBqPkeFcqPKoGjVmihZ6G49I6kT9Qapd2iQydiOZvMc=;
        b=m07AYf9cXk1tyBZUUeXWGWUNBqSMpeWpq8guXG3YZSZYjJ0c2WFQ/Rpn/F99TaS8HJ
         QqHx3sjCotfn6OkANeuU5rTLY+XCqpiOoLwZCd9kJqsn3c+uc/ewZDKnrEGVuqkrRl29
         +o2KH6M8E5dl9zPsMfcQKuJsGxEMV9LEaGJQd7sZAchcWw/yNmQcqwyNtz3hQrwHGLxu
         db7IoE62oZDinE7vVPsP5RK+8sKhoKrXKCvCT2kBR27/IFygZ0JlmSA19y0iDxLx7nyq
         icSFcPTX1vG62A344+SPvN+zRKgJfQ/iBqY1ZSFz62Gyv3lU9LquLwFrjSDnXXYWjCd9
         v5eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:user-agent:date
         :from:to:cc:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hBqPkeFcqPKoGjVmihZ6G49I6kT9Qapd2iQydiOZvMc=;
        b=cIYzWoQ3T773fQw7cPBNdxrl7HlYdTe+btaO++DPGgCD7YBCikivujH5czENTjF7E/
         QSG5WY0YaLmvSTCkqqedXXOhA4gp+rTlZ9qyatNRQs1kb7X5C7gpYowSIVMnRpebb2vA
         3jwYRteZw8FLaPicV3UpDfVdlcxquHT25Bzjr8qUCRxVo7bByV8c+tcm/zmazKdGe3Mh
         xgR8aJneE58gMYJV4BwskyKZAuSt2swaiD9jZbE68GFl48FXUz+ws/YBAcj4qq2KfHwG
         eRo0Ysr8OUIFPdwSQwnVLoKga4cKWIxtA9JaEkuI7DoSsjW1eFtclqX1SwkV3hjsiwqk
         sRnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IAeAjNkIo/RlwYn6fgJCM5k2fkR5xe4U4PjIZFCJqF1j3MOpv
	kfhbLP6iqLN6hs88x2zHucA=
X-Google-Smtp-Source: ABdhPJzzLqsUbSY6mwFGdvxo1WmHoicb1j/48sOajUBgtJH4Ko2YhelT7aytePlA30QcDO76FFfDxg==
X-Received: by 2002:a17:90a:9904:: with SMTP id b4mr5307089pjp.207.1591184549553;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1415:: with SMTP id u21ls624315pgl.7.gmail; Wed, 03 Jun
 2020 04:42:29 -0700 (PDT)
X-Received: by 2002:a62:7c15:: with SMTP id x21mr18747097pfc.189.1591184549143;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184549; cv=none;
        d=google.com; s=arc-20160816;
        b=U1AWss24o7iMuayR/N5+7NtutJ9Zme/GIF7wSME2X5k6AYvkQyWDpT7OJ7ynfAV1Iy
         c0IQaiZX29aytQpIgpB76pdeg/rDI7bbCX+OCO2QjHSgzSODBF0l33vIvHeFhz0+N5nT
         Q5I5Gxw3ybWZzhCZ3roQv0GL58rhiN8511cY1Q57kQIvYXgXige5GtwC1D8wv9RQ5Hr9
         ZsTcAZa63nW3Gg4+AhSg0Et1dFGrWLbUChkBMqEQVU/YVkcWvP5dGhIFOGDiYzJJkG9o
         TkuiVH9Imbp70tBKBbR9KnY6PpSigjlAMi1A6X/29mt8/Ah6ldc1yRTwrwlXJ07llroG
         cOXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:user-agent:message-id:dkim-signature;
        bh=8Kdbt0b37eerZhg/nVUe4tBYOkqdJz7+Q7Dw50pmBzY=;
        b=v3i4J3lXVTd91lrd4N2yLGt1PmRmcsduPW/CiZevs9SMG0JSqlR+Is05cLTrCdBrFg
         YM7HBPTvOLybJqh94GASanNky7glR1LybjqvlpVLck2FJh9PZUwn8j6dRVDqaj5zK1b1
         OlLgMHe1ajBjfAhn0hUo828M60ZwWtLr2b8g/8YE6gtvNR+mOW6tKzrkvDNmhtVhpNTN
         JBzJu/xYjgPgqOHGMjmR3/slyhIuI2HkbY2NRrRw1tN6Xmqyt+nleaVPBYfv1TjrHVoL
         hefFeIIpa5zFerv52jtDpdqChFdI9nh4hu1B1TRRbb1IqCLQcuMSw6XdcuJa/JLYBbuw
         zYOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=CZmeYv88;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id m204si120449pfd.1.2020.06.03.04.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmr-0005jl-RV; Wed, 03 Jun 2020 11:42:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B67E530581E;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A2068209C23EC; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114014.152292216@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:14 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 0/9] x86/entry fixes
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=CZmeYv88;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

The first patch is a fix for x86/entry, I'm quicky runing out of brown paper bags again :/

The rest goes on top of these:

  https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
  https://lkml.kernel.org/r/20200602184409.22142-1-elver@google.com

patches from myself and Marco that enable *SAN builds. So far GCC-KASAN seen to
behave quite well, I've yet to try UBSAN.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114014.152292216%40infradead.org.
