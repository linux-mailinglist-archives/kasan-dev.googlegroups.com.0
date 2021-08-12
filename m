Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5WU2SEAMGQE72HN75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 145A73EA625
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:04:40 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id y26-20020ac87c9a0000b0290295092a93fcsf3270396qtv.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:04:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628777078; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnHnTK76TDgGjlEf63KxokkF8T/GvwmG0syiOMgUAlor4QZj1cDhnxAwxtsFpVlzXt
         xBDpX9bZ2qr1JtuLvYAYLiXSLH9j8jrIPs58vpQNtftCR8PQAtj3XUBDVo7jE2acopp3
         UTzKvGoUGNPDhOs6vAkA6C8K7X5b7YqBb6f1EV9hXA0so7Csdk6u76pc96s6qmBeKkir
         Ubs13WsnuIWepaZZrkv68z9HjpzmpdEIziUjHCJdy9om9+e8TXpNwE4l69MGn0fumdBc
         fP8ZT3YNyqK4nlLFxELK2vHS7/wZYIQnLlKBQuizxjmUk6ozN9mOhAA0OwQ6KKA+VMYV
         ZUuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QW+1ZAcTkONf7g7A7THjJuK4mmsso3zK5BJeO1zDR/g=;
        b=EM8ljOIugQtqd01Nvq/eYZitXpXax7S+oazGbVflhVmsKy3XUHTWtti6FVXZo/Gd/z
         VUA7RTnJCJX8GUPdtNVL4E4G3+67T5UdiJTxNvQJ6hjmRW6y2G655z5yUKNyP0RQQWVK
         RMWHbKYcRnFa1H5b5K4yJ0CZ6CX9HkthN8RY3nMhXvX5fPebDDtEnvdgwFl2ULs3fKPg
         lhqZLr5gIVnu6dD3np+Od3lwtDUPQAKeGCrPpEsxQjWC//DyIBUFwLYJXO3wZWX6kDv8
         QpkjznV+dYPqUipQf/UZjM3OKL5t4p8uVewr9/DB0uyw27JKwzFhVB1iK42wWnPSDFO3
         ZzAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kDoK2sQd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW+1ZAcTkONf7g7A7THjJuK4mmsso3zK5BJeO1zDR/g=;
        b=dRK8USew9Ovrrn6oIeIk72mb2Lwoy5d6UnvIVaSy3NUNLbmy4sdS7Ld88R0rdI5gm9
         BV+LX5v29REgCFP9TAtXotGKXLWlzA7JlcWsgkTmKA/Jr6M8sRGiwHmPqr4N1Cv/jkMt
         MGQkd4ZCOp7oeGXbG6x68vch0SLHMxQhM7MitfYZ7QQeiviglDpWWsCmfeBk316XcMjG
         3KvzB9gqPrUZGuHKhQhBL3cr7b6CZqaicCLTqW9qvyqIlbachcTTY0YcDRPk/blXkmxQ
         yRevqaz0foAiACufGUUGOK+Uxg6+okqNe7mAaiC7j2XOwTvd/5pbtfYOUyH0cotmPeQL
         POgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QW+1ZAcTkONf7g7A7THjJuK4mmsso3zK5BJeO1zDR/g=;
        b=X334SfIUeNCgrAK3KLL3kuyhDNPnxgNXx0S5jsXaojfCMux1XImsGXXzH4NAob13K6
         Cso+dTf94/rm76e8zShiCfdm/b5LXrfs2fVt8iPSXtQ2LTouPVaVucHQPdU7TBmlheJl
         UigxZL9bl3YrXd/c8tF1DJODs0SE9Z6jSbdOuX2/4XyWCS0y7U5nXRFnoAR79h9AHX56
         wSymLO/0GvrT/ZfVCBqeTpoOFg9Nx4N4M7ce+FvtezJiIDAYN47PwdJZRNkk4zTmlyC8
         3xLI9E0CvYXRYzhCpcdU5PKxK0R8abMq24qA3S8J67+8i8YHsRstDTgq/L8+KFaYcUbk
         njmw==
X-Gm-Message-State: AOAM532uZTkg4KAy9ewk/Ri2ak3ZCOHVEqReJPDv5X5zrza/ekNQgAMw
	bxMvfFhBVYxal/x0A1YSGmY=
X-Google-Smtp-Source: ABdhPJw85LVDpwmIDB0QXPeVHMq8tcOCUXpqskjoSAVudMLwQo9q1ka1qOiZ+FuCQI2a9Ez2GEt9eA==
X-Received: by 2002:a37:a910:: with SMTP id s16mr4553346qke.439.1628777078646;
        Thu, 12 Aug 2021 07:04:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b204:: with SMTP id x4ls1528939qvd.5.gmail; Thu, 12 Aug
 2021 07:04:38 -0700 (PDT)
X-Received: by 2002:a0c:8e88:: with SMTP id x8mr1152897qvb.44.1628777078102;
        Thu, 12 Aug 2021 07:04:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628777078; cv=none;
        d=google.com; s=arc-20160816;
        b=gfgTsIkoG0B6U4eZUxkfMKKqWU1Y6T2/jIQaYzgkiCAPa45uyux49dl/gr3Gn9lq3x
         rqJhMsP9vJecCNkOMk3PMOkvQ1KHFpoFkSH1KjlZ6mQ5vtmk30EYWOwAffp3XHCTBfum
         k0IlahWLugFYruxp3aoftJ1K5SuAZ0CNQCJ1YTLzFGrddlrDcUUnyPcDkY2oiKUyK4QE
         XKH8msrIHA4lwjWHligr9hs4UkbWVAqAq2BBK7qNSDqAdHIePsSkAcHmMWjvcgfvKzgA
         frVnqWtKs6hLzeiUPaK56DTeC4dSaD/g4KCWrEfYO+C5b9KR/36iRyTppViImtp8M1HO
         LgQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bvOIAvHT/Lw36eIDHwbsiEEXIRoETITJHslQj5KEmLc=;
        b=U6J4Y00b/B0l0Lsx2Q4LPF16ljlixLkyvs/DbbrS0Kv3U61SmLxBlPoUAct/Z0cEgf
         tjkM7G6VpYue6gipG15n/4oOrTkO/L2bOGFdrvPFKiviFqb/JE8x5kz7VWtUmdBG8GrU
         q5Chf2nbeHKJkmuLTqpj00ZNIXauAjkyftsL916vaHn/Lb3F1PAGZGIcJeSLXqMitzq2
         Ld4HuveuaE6hi+Jn3B9nBzqyCbj7wWkAi0/TMDXCrJYXFVvWodF3wA7nd3RRkE5DmHDn
         cwzSkiHdC5cFAMhRTfjd5HIrpRNJRyGZTUnHyIPcCaR4g5MdPPhSWTLdit4udQGcmkIb
         6Hzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kDoK2sQd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 12si137740qtp.2.2021.08.12.07.04.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 07:04:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id 108-20020a9d01750000b029050e5cc11ae3so7849814otu.5
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 07:04:38 -0700 (PDT)
X-Received: by 2002:a9d:6f99:: with SMTP id h25mr3589241otq.17.1628777077440;
 Thu, 12 Aug 2021 07:04:37 -0700 (PDT)
MIME-Version: 1.0
References: <20200604145635.21565-1-elver@google.com> <20200604152537.GD3976@hirez.programming.kicks-ass.net>
In-Reply-To: <20200604152537.GD3976@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 16:04:25 +0200
Message-ID: <CANpmjNMAZiW-Er=2QDgGP+_3hg1LOvPYcbfGSPMv=aR6MVTB-g@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kcov, objtool: Make runtime functions noinstr-compatible
To: Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kDoK2sQd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

[-Cc most]
[+Cc Mark]

On Thu, 4 Jun 2020 at 17:25, Peter Zijlstra <peterz@infradead.org> wrote:
[...]
> I would feel very much better with those actually in noinstr, because
> without it, there is nothing stopping us from adding a kprobe/hw-
> breakpoint or other funny to the function.
>
> Even if they almost instra-return, having a kprobe on the function entry
> or condition check is enough to utterly wreck things.
>
> So something like:
>
> void noinstr __sanitizer_cov_trace_*(...)
> {
>         if (within_noinstr_section(ip))
>                 return;
>
>         instrumentation_begin();
>         write_comp_data(...);
>         instrumentation_end();
> }

Apologies for resurrecting this. :-)

It seems I'll need to use this approach soon for upcoming KCSAN
instrumentation for memory barriers. I'm able to use the same objtool
feature that erases __sanitizer_cov* calls on x86 to erase memory
barrier instrumentation, but arm64 will still be a problem because of
lack of objtool support.

Mark, on arm64, is the approach above that Peter proposed ~1y ago
acceptable in general to make instrumentation noinstr-safe?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAZiW-Er%3D2QDgGP%2B_3hg1LOvPYcbfGSPMv%3DaR6MVTB-g%40mail.gmail.com.
