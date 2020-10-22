Return-Path: <kasan-dev+bncBCT6537ZTEKRBRHDY76AKGQEH2ALCLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C32A1296639
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 22:55:33 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id b195sf1949542pfb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 13:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603400132; cv=pass;
        d=google.com; s=arc-20160816;
        b=jvxRck5fO8/ojbfn/JfqGIbsIkFbXFEOfmsMZpqlCKB/cGjdUG4cyDYp85UpwZ/eMJ
         QsaRq/qPGA5xs/i2XAVjPTq8BL/q1ImTmN44sUOnmtVAouBuELVpLXNKunw/lnNfn09k
         dLXVzNicZkOJPPa/LnAsE6Zxuihg3soQisixIGyiNPD9C9Sh8GmwxCAJ+PX/QAvXw37M
         OqL7Cs+Z/ZnZux2s2ad6YaXMl/KtUPt4LFZhXTADdn+Ky1BcgmgyDC1R3x/AepKENs2x
         07fLt7MPW0R0SdloH/GJhjupnVF+4udtNdxxZW8BPQ3V4AQs/gxljlfrYp/4o/yytGsP
         4kbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tGFre6MywP2ZC0rbVkL9YmJms9qcf043yGpPff2L5Tc=;
        b=jpeW5zSW3N1MHH4L9D+u6qjSnZ4gYeULhOSrsATNz7fDWDeIm/RoeogNlhjMzIl4eO
         q09FLoerBUxqQjMkKkkBFjxGlTp2wk4RH5NS7GeANW90Abi3nFOO3hyfEQlC9kEUTRJ0
         bIGRAr9hPKhEL2UUa2ZIciKjppUNZjhqvsX8F1dd7uziWjLHrdgRCIYQW9qezcyjV2ES
         kTzMsEwIrutzTjlPGfL3z83FrrrQtZ61a0lq86K8uChrkE5bvpX++QHR2f8ZxlvVrYHQ
         kusRhynqGaPPjWX1oYIZgaMM1mSbEIUDEgoGRdzra92ng4EmHdBC0sfP91DMsBWpieg8
         wSfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VyEe68Xl;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tGFre6MywP2ZC0rbVkL9YmJms9qcf043yGpPff2L5Tc=;
        b=tAXC/2v/tvhAVjnEDlGHZyxUCo5Ljpk1fTiveiWk4Btfx2e30GP9Zyx9k5f333vor2
         haJnJeH1h7kHSCe2j+gTXkeZjQGdql9J4L5h2aHeapMSAZYAhU+LFrVXc2wpa3fJPBYW
         gHIezWpL9YxSMbLq5KXpJPjAMGL2Qn+M02gTTA3M19afGvl2dTwgSLl0PGi9cjUObz8q
         gIRwqIOdpsYa6WNH6/yRMPi8wccBBppACi2pMqICM2D6WOlHIolxPYPrObi34K/IDMDe
         h0NvwES641dtXPRY7pD227p5i4QXJRz9DfDptd8HcgovfjLj0uPcAnJph/d7lCtVqO8O
         uMPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tGFre6MywP2ZC0rbVkL9YmJms9qcf043yGpPff2L5Tc=;
        b=nXFuBQWUYsJmY7+87U24XhRzSWkBGgAtl+ZaazXwExpEE9ze5enJUwwCS1jNt/jV8v
         RVP2r0xav8S0LnElMpngUDLi0iaq0ao2M/UTOahsQ+CHQz6fhNr4674KlmiUQIoH/nnG
         2POQaOmiCS6a6pE/8wbl5gSVBEmMoanSjlajEfOllIsq9WL218Wdwc6Dp8etMcKdo0Ay
         IZQopo/OIsiuRMaq3Q2y+gXBXwfrYPwtVPKrzKxl83yJHmL3xAiW3NIj/tKGoxc1m1WF
         b+mbvZuwmiq8qW6EeVPSbHAPwqhMnSeYSITtx2xDK3YmRavMYAaJZcNQ53Dj/wt62GUS
         UCZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ej73S9QN7+rcPQwAPOJvfzGsktzgMS6zaQ/xMksLR8jvlUVip
	N2nkvUZU/g/cqbZbMGVJ+GY=
X-Google-Smtp-Source: ABdhPJyfXPt8FaRkCPQphzT8Sjp52L1sZANgEeKkVqaNEd4pFKU5w1eE8uU/NFFZUMjb/AVjJO/W6g==
X-Received: by 2002:a17:90a:8c8a:: with SMTP id b10mr4142249pjo.127.1603400132544;
        Thu, 22 Oct 2020 13:55:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b20f:: with SMTP id t15ls1507974plr.3.gmail; Thu, 22
 Oct 2020 13:55:32 -0700 (PDT)
X-Received: by 2002:a17:902:b696:b029:d5:cb0b:976f with SMTP id c22-20020a170902b696b02900d5cb0b976fmr4713017pls.26.1603400132014;
        Thu, 22 Oct 2020 13:55:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603400132; cv=none;
        d=google.com; s=arc-20160816;
        b=xcJWUDZ/9cxPRV3VI2TMZtUZxNzRuWYKHOXWTGbNA29yGUqrMZ4EnNpP8d9Wbk2yNB
         tOMwsoYhW5xN2+30hBL7xu/qVCsPAUHzXp1/+HjJDA+kXlamw0yZIns2xQpesuQyQake
         57lc2Th5WwVuAgAmfzi7f+Hb8/8RQW62oXeIj+iGLBgGo+IQuvsTFlj9J3NAt4PEETyG
         xk3lH2gHT69F+ycFkIAFr2XnfNUOK6JEGlw7kG7o/F6ygq72yLiv0kyfp93pXGwFsvFG
         FcFHzyH8eJlZ2rd5jk1UrAae9wS0Rcs3mZ26ylu3SWkSbgKZxjA/Ytxs3Ltap0FfOdNm
         8STA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VDqQ1zUFMtHdEQX/XnB1xFyEhicaRQXlC/XVGrEZwa8=;
        b=GZvQuGCPHCxEn/xb7ddAklnrS76OG5OqEgsS+7ZZMB9f/HZvkSh51LlbQ3/gmk8ZQj
         fc+uE7AX4mpXDSFgBoPzzTMiAEYo4FFQc09b7GT2LeQr0z7kCFq4pFlc+Kb+RoCzKxSU
         y1PMvcn8Cw6mlZ3XqwvEky3+gj19AyZEhU+b0Rs3dYUaVF5KBxnxldYb0zQcwKsGf06C
         H362Y8ntknJiqSZzOweWTsdhY3ZGiLQcQdljXGvYAE8FVMpFrqaeVHdqj7+xDXioePGV
         a27dVyibNhcWUbmTJg8oHY9yAY1sUQiB1xzOR0jR60unHnLspELmdp7l/QQSgtsDIUtk
         nD4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VyEe68Xl;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id k126si242058pgk.0.2020.10.22.13.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 13:55:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id p15so3165266ioh.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 13:55:31 -0700 (PDT)
X-Received: by 2002:a02:ec3:: with SMTP id 186mr3173967jae.92.1603400131365;
 Thu, 22 Oct 2020 13:55:31 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com> <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
In-Reply-To: <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 23 Oct 2020 02:25:19 +0530
Message-ID: <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: open list <linux-kernel@vger.kernel.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, X86 ML <x86@kernel.org>, 
	LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=VyEe68Xl;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, 21 Oct 2020 at 22:52, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> On Wed, 21 Oct 2020 at 22:35, Linus Torvalds
> <torvalds@linux-foundation.org> wrote:
> >
> > On Wed, Oct 21, 2020 at 9:58 AM Naresh Kamboju
> > <naresh.kamboju@linaro.org> wrote:
> > >
> > > LTP mm mtest05 (mmstress), mtest06_3 and mallocstress01 (mallocstress) tested on
> > > x86 KASAN enabled build. But tests are getting PASS on Non KASAN builds.
> > > This regression started happening from next-20201015 nowards
> >
> > Is it repeatable enough to be bisectable?
>
> Yes. This is easily reproducible.
> I will bisect and report here.

The bad commit points to,

commit d55564cfc222326e944893eff0c4118353e349ec
x86: Make __put_user() generate an out-of-line call

I have reverted this single patch and confirmed the reported
problem is not seen anymore.

- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg%40mail.gmail.com.
