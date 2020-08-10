Return-Path: <kasan-dev+bncBDAMN6NI5EERBGOXY34QKGQEUHAN7GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A377C241197
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:18:33 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id p7sf3698238edm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 13:18:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597090713; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nqg6ohefqHns6xd7mtClJt9xtXjIvtaRbnJIhQwjiQWFrkHN9ojDbV7FuBEfQmT8Ws
         ZoZX2DzyzO7FiFpeacW85IuLJsXV7gm+BQNE6DDbOglqaMhGGLgxhdvp7VL8FCHb3ckv
         SNjQsX2cW068j06v65N+DK42A+ZcYGJyMY987eCTGDKac4hfa5vyVA9+ArjKt3GVldmn
         igcSoW27F+CfZEmhLC/sKV7E2k/sL0CIwqs2InanNBfAbUn7KTQt00Ir2MnANChUvu7L
         1dqgyXcEFbLINA3auvqEcNymhDbo+QyhY2nZmyQs/o1eY5279gi4z6QYvMWBa2JwD7zv
         mKqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=w3UTuIUTaJQeflppuCoOmEO+x7MkPDsqXPJCyUR4OE8=;
        b=Yu62Ftd7VUxjGBlkbIuPXzovqtevVJXY975Cq8IHbV8a5tg2lA2zpn0iaA52m2oVxJ
         M4KW0HWA9PbIjMXA4RKWuylhDBMhwGoKQxJlNhY78/MYph/28xxVOsu1U5HqW5CZXQE6
         93WExJpJNTERxyc8CE2AMIMPWN+gpczVF3VgRscDw6b31swgmbqa5AsmFboWmDLeQ22R
         k1SRSVtghvawi1dS1XLECMFQ1PZ4igGRYMomYdvZg6Hn3ryJrhrfoWQ1P99t9dxmCVzS
         S/yyd6IVapqTZQ7ChTCpNd+NWCkYSU+5uTGLfOKCZbZ3tkJhIOpbw+n3JtN4wDui66HZ
         AL2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oqzjQJxi;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=NWICybjt;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w3UTuIUTaJQeflppuCoOmEO+x7MkPDsqXPJCyUR4OE8=;
        b=a9aS32B2beYJqtv++0wAzTvJCkTBJ3bBCSOozjxcMqZv0ZM1nkJef6sMVzi2yshrdp
         /X4BkghWmA/1CYTwfltmi1LLyD2fg9Bq06RyLBfVlnJ+cGmi8ZSjGYqFiBsJgy3uOqb0
         Z8ht7+GI8+PpNeGBbIXFJpvtNNgPbWTQh8rfBBkYrdkZtjlDqa3U9P7wM0UR9lUWNRey
         KT3tnCiKvpIbFJXrFdPn7Y9o5Vft1OJcsIX9pnEPj1X0K1cJ54npswBLgS4+qlSu8MHg
         02LrWbv0I4dJexS/trJw7zS3rNQx6osC92CAWDsfjbaTWXcYHOjj+lUR1Az4XWLOAa4a
         vXNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w3UTuIUTaJQeflppuCoOmEO+x7MkPDsqXPJCyUR4OE8=;
        b=KzrfDkJqw7RVWOZABker1vSXIpGXiPh8gNGyYNHusaQqoQcl2VPJDLbhdSdce3EFaH
         0xFZzjyUxArn4IalNgt4CfodGBZPH7csveP2vBD1cT2skNPCuUiwkqJIhNZV1N0THdtW
         HEADnYKZWVXfgPXYPgb7RS9iZ1xiaN4isrC44eHPdydnpbPVEY+FX+AkDE+LSJd/yMcR
         MwGbIWJX7WCp0y4KyOvFxhl1uNBkmKG8NhW2xN7+o9V5b+IeGpX+cM1vHsMODyAAx43+
         24XYLu85cxHWh7GzMuj+rJcLG1y3m8uN5ep0QIjGz3x5YerNLuHaHeKhOGOaF1a81w7S
         5wIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aKE2scdaay2dPip3ELA8q7dxb9Ijl0j6ejnKljfGsE36CqAy1
	NuDc6Wl2ehhgisGPcC7goDg=
X-Google-Smtp-Source: ABdhPJwlzvHnv6vLdT/QjxwF7FJd3A2EW/jEnkLPjwlwFiUQO837BhrGTq7AQuJfch1DNJyQGYGhbg==
X-Received: by 2002:a50:9b12:: with SMTP id o18mr23097207edi.367.1597090713386;
        Mon, 10 Aug 2020 13:18:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3b1b:: with SMTP id g27ls8585226ejf.0.gmail; Mon, 10
 Aug 2020 13:18:32 -0700 (PDT)
X-Received: by 2002:a17:906:2a04:: with SMTP id j4mr4581684eje.440.1597090712942;
        Mon, 10 Aug 2020 13:18:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597090712; cv=none;
        d=google.com; s=arc-20160816;
        b=fIQQuqXnB3Ll3ZQ59/jbPwGGnB1kCp6WohS/fs7rvW46p5Xg+0U+9hkRFJHykicxIY
         jUwK+I4JGFM+r1OKliNs4/LBh+Ut16o6g6+XUJoDX9HcRDEoghVQWOn06LVsjGSoa5Wn
         gwgI7VzH1/2V7NJ61x0lcI2whZ7OY8eaAmIkEKMyM8/GjUVI/kXSlmesYJgN9/lDeKVt
         TRcTLN6ZWq1l6AgbX596L9IghwiO5WTiUgsKSN/6LOSCdNJaWaaTq019AS+wFRKt02Iy
         pfFKNIZkjBKdFYlQK1tIFFVyNshkd7vXTJjOlGMsQ10BKLkhlK5LvUF6ajhEUgRVOoEl
         Wiyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=MipIWmCfz+EbbW+HlVadROmknV5HQ2RLosQPnMEF508=;
        b=fQ8yr3UZnDRxxZsZQ1P3nJ1DWM0uSQNUb9TUXMDbMuSYavZUa0kNDBueQZ83+CNvZj
         DlbZpmTJ8cpeFTe78s0bum/s8Cu+u/BXh+JbZz1DjVrWWmnQN/HrnWH4KeicoIjTdEts
         mLGL+53vbqFLT4B7LVTB0UQL7QeUdkhpP+cUSh8r9nvTmSsTeABsHqdlqN/wxinhM7Sj
         tKNXa+ZzrM2iWT+CwlpvsJvewrs8z3bhZwyE48qvgcmOi8oZV9/zlQ/deRN6OT8L168t
         a4hHvGC7eBQ6sV2apMxVxFgy/TZrSaAfHpQPLoDieHYvJQznt1tDBbwQtX6v/SHxjszo
         7VsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=oqzjQJxi;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=NWICybjt;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id t30si560099edi.3.2020.08.10.13.18.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Aug 2020 13:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Marco Elver <elver@google.com>, elver@google.com, paulmck@kernel.org
Cc: peterz@infradead.org, bp@alien8.de, mingo@kernel.org, mark.rutland@arm.com, dvyukov@google.com, glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
Subject: Re: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
In-Reply-To: <20200807090031.3506555-1-elver@google.com>
References: <20200807090031.3506555-1-elver@google.com>
Date: Mon, 10 Aug 2020 22:18:31 +0200
Message-ID: <87pn7yxnjc.fsf@nanos>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=oqzjQJxi;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=NWICybjt;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

Marco Elver <elver@google.com> writes:
> Since KCSAN instrumentation is everywhere, we need to treat the hooks
> NMI-like for interrupt tracing. In order to present an as 'normal' as
> possible context to the code called by KCSAN when reporting errors, we
> need to update the IRQ-tracing state.
>
> Tested: Several runs through kcsan-test with different configuration
> (PROVE_LOCKING on/off), as well as hours of syzbot testing with the
> original config that caught the problem (without CONFIG_PARAVIRT=y,
> which appears to cause IRQ state tracking inconsistencies even when
> KCSAN remains off, see Link).
>
> Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
> Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
> Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
> Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Patch Note: This patch applies to latest mainline. While current
> mainline suffers from the above problem, the configs required to hit the
> issue are likely not enabled too often (of course with PROVE_LOCKING on;
> we hit it on syzbot though). It'll probably be wise to queue this as
> normal on -rcu, just in case something is still off, given the
> non-trivial nature of the issue. (If it should instead go to mainline
> right now as a fix, I'd like some more test time on syzbot.)

I'd rather stick it into mainline before -rc1.

Reviewed-by: Thomas Gleixner <tglx@linutronix.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87pn7yxnjc.fsf%40nanos.
