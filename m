Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR5PX73AKGQEOX3LCFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 90A811E65F2
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 17:24:56 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id y16sf22641872pfe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 08:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590679495; cv=pass;
        d=google.com; s=arc-20160816;
        b=JdjJgoHADM+cyLc/QArTmjXQqZmSHcDTvdTaZy401NF68QljzlAtVQ4+ll2wchkZpL
         xuZUoLW3fjNxg2McdLdY41+WUmQyQTtU3kxhIC6c5LYrMmaakg2IzZVO3Y3oWDkCZ5ZM
         /bpXLFZRKxifi7V+bPt3tP746Mn3YB4xDJ40kU1C6QZpS3ow0xFwKVTvFKUkpsiTQcCN
         h1qJxnbIYiscNlmKHErr1qNxf40cE6/Dh9KS6CJ1QC3qoK0yB5kAlimsif37tVUsW32A
         HbwhYPOp/0m47ndCYoPXrSHEEP7fB7UpY7W+5NmVbG/UI2XIqv3pd1dWo4Xlwn2Im2Pf
         TsqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=23FHnaV6XFLmNLTkYCvS5T5LPJisg8iN+pSOJWQXvGc=;
        b=pCvYtfyYpCY26FCbM0pNt1SVXMEVxmgMmTfZAUSjwLivmKhzyZnPR+NC9vms45t7Du
         L7pTPM8g4jxN9JddKmb8Z3yuA+znoxDWwTDKK1biLNx5/pm6TCv9ObxVoknrX858e4M8
         4d0bLlYwrGbFODJBGonHky1si4utnFm8z7ythS7EXzo2E5jpgbkSOTwWTtmlWIwtVhHb
         McFnZmyQiibggNgZeNAeKFS3Y1FYJss/OC+IifAEbDl9RDCdz+ZjDzf63AT9e20PForL
         8VInOti9RuPCzGQ7StleOUpL86BrT0GqLoCPv33RRH2hLKdGZp6ok/BgSVgO3XDmmODA
         TvtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MJ6IPLKC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23FHnaV6XFLmNLTkYCvS5T5LPJisg8iN+pSOJWQXvGc=;
        b=dHeDJDMbUWSBBo3qIjxLQ+y1QZEke7uF+VnujYcNzrgxWeunG44KTqcqniUPrO8NJ3
         /2tTQS5HoHTfa3L85eeIg3pCdv4yWVuxzshJ7PNpxZqRWfsf+qfjFsAyQ1njA/i+UyiE
         ALhgOi0RXsFwEUbdBH3mivd20fHzw8aO34VR4FF8hx+UMXuCxW4yJZ4w2c+dmYm/T7A/
         na5pQRAygus9CuyPu8LhvlqfoXAqD6umVCa40RqdQv4pKH6c+94ef6eZCXzPEYRhdC4f
         unfRHmbSUSne6wvgwnm25Ee5AGj5N4QsM+xJlM0wNqcw26AF8a4NE0L8SBmXVl+1bpG6
         3C2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=23FHnaV6XFLmNLTkYCvS5T5LPJisg8iN+pSOJWQXvGc=;
        b=K+B4OVuxK0eZ5ynIcw5YuXWWLkPDpWchhn+R7iiuoJWKFizUh1eU7N5zO0vz/52OS9
         7+eVd0+fLwC3sU36zhNboT+kdeWUgoWAQNIPcPgIsL4952qSQcwwz8qZEj3U9VlWL8mJ
         ZPc+IoJZx6oB2HiXldp3b0lqKUmaZyzluPsOLSdyR4XPaEeIjddaIQU+rXTSKHXWFCPw
         dwYL6QoG/1p3LiUii7LitdQtLR9/Tu0HTygRYK0hL7WkhlErVlQT9ELS4iHXxCGE1ZLA
         GmzuRIFJW8gFnN1Ghkrns6UGRFi3mHbhr3wDcbbXe5M9aUIsEqR0y6X7DmOq3oJyr5rt
         7SuQ==
X-Gm-Message-State: AOAM531I+dZD9It1KkR2JMzQqEO7rAujXddYCFk9d+hw7bf94sXzRBw4
	0+xu3Bou3lERRI3cYd29Pu8=
X-Google-Smtp-Source: ABdhPJy2pta74sMLdGj2w48/TxmJjHdaOxMTm4TbtXlWUAl/kvYcdMhWnG8NX5yegwitYURzdjRZzA==
X-Received: by 2002:a17:90b:f8c:: with SMTP id ft12mr4454611pjb.127.1590679495234;
        Thu, 28 May 2020 08:24:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:12c:: with SMTP id 41ls1074405plb.2.gmail; Thu, 28
 May 2020 08:24:54 -0700 (PDT)
X-Received: by 2002:a17:90a:ba8b:: with SMTP id t11mr4614574pjr.191.1590679494822;
        Thu, 28 May 2020 08:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590679494; cv=none;
        d=google.com; s=arc-20160816;
        b=mxMUcA8iRDFhnt4wpTqRGCZ+D0w6yTT5sdLTNJhizPFJ7UBH+g5GlhSXsyJx6eWw1d
         l8sOmU0dpcyvzz3uvIhfBQ08y4YW7c4fp8H+3eTLRQDB3a/qJOCLLBdSm9eJy/xvmryP
         J0nRT4c1KrbqFzfH0I1KykFViJ972++KUtMi2GHc64mgcTIEBgKZ3E9InsV5D+Gz//zk
         n6ENexGEXw6lIjOjZv2HBXka/x5JlXWwarhi87w7NzjlYup8RL/OfX3VupXLXSlCWauu
         SZ92WkZ0qKB74OamgXVEEpebQhzZ50zSeQJ8OvpOoxHwzfgKzutgdg+sftODL3dTsgM1
         A6Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K6IkMqHyEOHSemzUNyydLbaMTsC3stHLolm7i5u2aKU=;
        b=isdvFMoli+wQ8Vcg0k1KabgEzLNk8ageRGdkaUTjRPFwJhbS5IzrwMPVj6bxuN9FIc
         zkCMl7RejwsoQtZnRsHdvMOj8BYTY9SThkfvd8Jk6zxFjxIa0Y+gJyjKEa8sGtc0cK5F
         JrIaOBnTNob1iRZ19LFHPS2S2vIg6krIFdVg7u1NCNUOIedURfnPaaUkl9zqXWt8SpPY
         u/EGo7kQf4a0LZouuEZHON75GJOKB46eKc7n0VvxImo0B8AZAoII1nMmoyDQ6chK4gxW
         2OudfxcEVKckRLeduIF60cXnm0uBpGIr42uaGFLN+fB5UUoC/nX1T/R8anVwEIRlA3Ug
         Sv4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MJ6IPLKC;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id ba3si443129plb.1.2020.05.28.08.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 08:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id j21so13604993pgb.7
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 08:24:54 -0700 (PDT)
X-Received: by 2002:a63:e454:: with SMTP id i20mr3439315pgk.440.1590679494343;
 Thu, 28 May 2020 08:24:54 -0700 (PDT)
MIME-Version: 1.0
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
 <20200528134913.GA1810@lca.pw> <CAAeHK+zELpKm7QA7PCxRtvRDTCXpjef9wOcOuRwjc-RcT2HSiA@mail.gmail.com>
 <20200528151554.GC2702@lca.pw>
In-Reply-To: <20200528151554.GC2702@lca.pw>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 May 2020 17:24:43 +0200
Message-ID: <CAAeHK+xKDJ-=GRDEoSNoaqbKcAYbEWS0a=Cg-_gijE7NXVWE_w@mail.gmail.com>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Leon Romanovsky <leonro@mellanox.com>, Leon Romanovsky <leon@kernel.org>, 
	Randy Dunlap <rdunlap@infradead.org>, Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MJ6IPLKC;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, May 28, 2020 at 5:15 PM Qian Cai <cai@lca.pw> wrote:
>
> On Thu, May 28, 2020 at 05:00:54PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > On Thu, May 28, 2020 at 3:49 PM Qian Cai <cai@lca.pw> wrote:
> > >
> > > On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > > > The kasan_report() functions belongs to report.c, as it's a common
> > > > functions that does error reporting.
> > > >
> > > > Reported-by: Leon Romanovsky <leon@kernel.org>
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Today's linux-next produced this with Clang 11.
> > >
> > > mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled
> > >
> > > kasan_report at mm/kasan/report.c:536
> >
> > Hm, the first patch in the series ("kasan: consistently disable
> > debugging features") disables stack protector for kasan files. Is that
> > patch in linux-next?
>
> Yes, it is there,
>
> +CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>
> It seems that will not work for Clang?

Ah, Clang doesn't have -fno-conserve-stack and that makes the whole
cc-option expression fail? OK, I'll send a fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxKDJ-%3DGRDEoSNoaqbKcAYbEWS0a%3DCg-_gijE7NXVWE_w%40mail.gmail.com.
