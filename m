Return-Path: <kasan-dev+bncBCV5TUXXRUIBB35I4SHQMGQEU5BMUTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id CC8F74A5ADD
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Feb 2022 12:07:27 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id k10-20020a50cb8a000000b00403c8326f2asf8525057edi.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Feb 2022 03:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643713647; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZyK3fvJ+iu0uN6U+zQO4ixufWU5NSjfPBKUck6QfPjIgxQ3m0wXOoyMVRQE+M/W0T
         0pLfvbrPGv06AFl+dXbLpI8zC+1qRtAGyN7J7h4sLfEUd+aZDLyBVf0fw4BiBsBwTXoa
         MZG9rGsG35Zs44CErzddNCBS8ea+Qmf/KvZKeURU7Urh3terEx+FFuHei9nC9qGBfqa0
         JlGoG991K+l8R2+5j6JHZPWSmhoQLr9zKqnuPoLxZaV4lipyU28QVJ2CzhUxQkn1H+uZ
         GAY9hVoG5ho5mM7Do466m5J2k3B120x4/VzXTYZhdY+xO9kxSd25GET/9SMAOPeOZSHF
         Mu7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XM6geYnnVzeGjZDfFTYMaB6gCwV5pgedqXYV0At7fMM=;
        b=y5GKbcsQzwA/GTQaCFUPSKpaZtvQlLCkF3QUzYit1SbNyeEo0R66iPV5i/+AEXAp55
         K4giMjrLrs7P2GjzKxQ3iTcFnnduUNO0yXJrc9Bvqs38HvhcDt4CNq/p7WaUUC1QDgOl
         j6G5gGj8Bc8p4swYOGdhRR/w81bmHVgZDFhut74i3fwwmEf+vEQEAuu3YnkxptxpMLXQ
         vInE5J7Bin6Iv6zI5G6WAfJlfwgA6JQ/I/gL0DmZ+JbSr+CtlCANMsje+TIMBvWczpSF
         ciDM5KaV8gspEFMIRwlMcnhwvQiZILfXupLtzKFiKPkaEP6higa7fuSwMM1RjXu3w67c
         TLeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=bGv32kes;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XM6geYnnVzeGjZDfFTYMaB6gCwV5pgedqXYV0At7fMM=;
        b=e2mcRjDcRQbW0h3JUKjYYKjLt6mdUdFWuEub+WpdMUhxa9Qeezmu5e0c/VUxNz+f+J
         Vz2eQbzRtrPpivuBqOCqtF2absV4s0v8wYg/T1Vgyv7kSSXmBhEUj7+6fPiS/JW4yNOP
         VQ0R+Kv2/8lsx1RwqrdwSxrdzBaZRVDGdPH31IPNPjIila4KckuxBg5Maiz3t0EIo0nQ
         W27Ly7JFyISpy0uJAip9tyOgTyWFtk2qHvHoMyQglbOQTvum72E6SN8AJvg4YPTbagOf
         Ywy/ftkLYprqTh2tg5CWMSgIVhwbRMYhiGt43IJZXwz/V/vdPAr4MNuEiPMnZGzZYnhm
         HChg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XM6geYnnVzeGjZDfFTYMaB6gCwV5pgedqXYV0At7fMM=;
        b=3RzdGb+ytxBYNrfBB8oKDhXbS7rFCxWc03jVBvI+KZbOfPBF1zlFJMQZWMjd7bzi+d
         DfQIwbVgaWnKWPOHlp51N1SzXo0gMSsbqLUTxt6PmtOXyydHWuUVC/qAqgag04fi1VAL
         pHWK7H8qOOI43e0oCsaf+FHLfxZH7U7yRnFJUVmGxyqlOL8MydWRqyOWWAeCje2KZuB7
         ZSfXUVIH0Q5k1B3ETIGZC8jKeugb1pSCLIFqsM4S+xpVxI4N6dkHPBBwaim7fbPP6nGv
         lpPHM5UwlpjYAY/M0iCgkywabmnX1fpdjhmwuUWqClzFey7K/kRLnFwr8s0g5LGy51rH
         bxRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DIuldKuz0thL2LdK4iWcszoozYggMW2sg8pMv0+Ksg93d3kKH
	72A9/eHqgNHePHZ0zQ/fc4Q=
X-Google-Smtp-Source: ABdhPJw+2TqxA/NkzdHlClEDxqWjpJ+D1dSri3fPUmypWT6P32Tc3fZ1soAQTStUe96Y06A+BH36aw==
X-Received: by 2002:a17:906:af6a:: with SMTP id os10mr21133627ejb.730.1643713647408;
        Tue, 01 Feb 2022 03:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5246:: with SMTP id t6ls2518400edd.3.gmail; Tue, 01
 Feb 2022 03:07:26 -0800 (PST)
X-Received: by 2002:aa7:d6c5:: with SMTP id x5mr24252088edr.29.1643713646587;
        Tue, 01 Feb 2022 03:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643713646; cv=none;
        d=google.com; s=arc-20160816;
        b=kIKcadfOTQ47RRF+U9yzcz+oF1zq5R6DuMiyyKLzuEhjZRNcwLWmod44El7k+Mh7Hy
         ayuFdzh32azxrWj4MvAbBgtxgy1sUfeCRuWQmsUSxJ6qbIiZ6qsqK/SQD2YbqvzeQ47S
         JMppbRtKj5RyJIiJClSDrOwmaxVGWwbQ0fiH8ZLS4r0R/wceHLYkZcYBpQ7IG8TF07vh
         SEKF4G+xhSmW8AqUPgrJjE5fbvi2vjdhKQhyK6np9e5o5stNnKu0s8Qwbqdw5UfIgbyC
         EA8IRS8baYQmq83DEcO3T8t9LMv3U/z1E9ElcV1EsxGRfzjmDpMB4wHnToQ7KHeTDqcT
         sW3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uLsDcxgkLM505bQLLfPdUrEH+ZZAWYgX9Yuu49ayqz0=;
        b=P35kp3Ryu7rtEJER0MlqbuInDggkm6Q02C96pFsalQAb2hcIlCKyoJszoza4Jl1x/Z
         LOsfJ8cr3mAzCdudKJRNPEn4x71i29A7QazWiJvDmHMCe6ohpS5ITtbF7R5rDCSYBz+x
         0lZbyw+fSNmIAO+m8g0sHa5s3AflGQpPJFx6woBimHB+VDEVqguGuJLdHF4JOxenVwZ7
         ZMQ7QjkkIf2Ux3ihNTKtp25v4O84oY3kyZ1q/FEIKcjm17PfTPLCwiDtzn5ZRl7P8Ul1
         RZZK8lEQCDRPhYG73Ver8f2GODXMVxDgkt3+4+QEaOf0vG4G6eu6c0s+vGZwhpgixd+7
         fcEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=bGv32kes;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v18si866836edy.0.2022.02.01.03.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Feb 2022 03:07:26 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1nEr0L-00C2ht-Gs; Tue, 01 Feb 2022 11:07:21 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id CA91398623E; Tue,  1 Feb 2022 12:07:20 +0100 (CET)
Date: Tue, 1 Feb 2022 12:07:20 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Ingo Molnar <mingo@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/3] perf: Copy perf_event_attr::sig_data on modification
Message-ID: <20220201110720.GU20638@worktop.programming.kicks-ass.net>
References: <20220131103407.1971678-1-elver@google.com>
 <CACT4Y+Zcg9Jf9p+RHWwKNDoCpfH-SBTzPpuQBBryyeopMONmEw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Zcg9Jf9p+RHWwKNDoCpfH-SBTzPpuQBBryyeopMONmEw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=bGv32kes;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Feb 01, 2022 at 08:32:45AM +0100, Dmitry Vyukov wrote:
> On Mon, 31 Jan 2022 at 11:34, Marco Elver <elver@google.com> wrote:
> >
> > The intent has always been that perf_event_attr::sig_data should also be
> > modifiable along with PERF_EVENT_IOC_MODIFY_ATTRIBUTES, because it is
> > observable by user space if SIGTRAP on events is requested.
> >
> > Currently only PERF_TYPE_BREAKPOINT is modifiable, and explicitly copies
> > relevant breakpoint-related attributes in hw_breakpoint_copy_attr().
> > This misses copying perf_event_attr::sig_data.
> >
> > Since sig_data is not specific to PERF_TYPE_BREAKPOINT, introduce a
> > helper to copy generic event-type-independent attributes on
> > modification.
> >
> > Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> > Reported-by: Dmitry Vyukov <dvyukov@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks guys! Queued for perf/urgent

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220201110720.GU20638%40worktop.programming.kicks-ass.net.
