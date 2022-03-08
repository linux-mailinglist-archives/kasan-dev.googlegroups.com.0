Return-Path: <kasan-dev+bncBDW2JDUY5AORBKGHTWIQMGQEB4JADAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 605054D1A0C
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 15:09:46 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id s14-20020a0566022bce00b00645e9bc9773sf2626537iov.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 06:09:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646748585; cv=pass;
        d=google.com; s=arc-20160816;
        b=F3OjYo0kwmZAa6xXpFrWfF9uRsg+j9Imsex2mG4wwmmathz5andnbrYEl0QkbYs396
         8J6phHdlV8nqLLqe00Nl4FQSQhcfHMB3lEQt3dP3xLH87ZQpv7A2rR4vf8QxRmG0Fqjp
         aWH6FoXtvZptdgB+VsMsdkxff9s14texRzFh+D3UjK3uaeOQUh6xFxYuPV/BM7TRu3B9
         CxvCT3gvfsBJ6OyGGy1D+v5RsBkzemEcmsB2R/mmYoqpczOY4DiLVSv/WuHQE9bjmNC7
         cxrvtSvRtbQ1NM2RpKEP0jNiPh4D2qJ3Yff9zMCZa1kvJmIbQIuv3StOVtV4gmGRa8Rg
         NORA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=HLU0ESCsmPHmmOa24bl2E8CWBrgFwbKszTKl0QLDnJw=;
        b=yyuEuYQtZs/Y4b42CLk9Q5q+tGYSWJewlHg3j9Ul25VCSUTAsk/LdV42/CAfW5s8bo
         gZJV6xkmsiAkpsTUaPYGVEZz5/mL+ynYHRsi85OqOvA/Sm1jxcjTqW5bbU78MWTXIXPl
         BDbkip5AYL1QP+MUdxhsQn3qVk6AzCDUfrfU2Y53Zj7tdg1ysGUJsoiN57REnu2Rc/qB
         IUUh4P8AjGWZc5hVy+axK57DAzTn4ouIwxZBUBJUt33HW7b5DCCuM+cVJR6Aozd0dXic
         s+9fO/p8CZekYKy3CNzY/GGRKD9Kkl6JSMyUC6dsBXU48KAOviLlsluhylFSg++d9M2a
         Z++w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eYia2Unk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HLU0ESCsmPHmmOa24bl2E8CWBrgFwbKszTKl0QLDnJw=;
        b=qMVdA4dmEtrCw1tkRMbm1OVyQZdRRUzwtfI6p+TyCaS0wCaqam70h+ny3ezM3oGkIk
         aSKy12U626vUxgXloUBisCa+kuuFgnXp95tkWUdZFKXgMKg/qMX1uYGpoqBjWHCVkmH4
         A5DbhTnDZKfnNaiUNOCPfnr2qV8Af/R70xJhaLR0b3Rz8bh5mlqGcLcjxa1qAtmxOVe+
         4rJcOJWdQBMsQdsKBpYt6CHvVTVGfgXOAGkNjOdu4XUS1z/ziOkpj/DRxOSOvsxwW5MJ
         aBstUrtv8tp+3f/UAVKAuvOSGgJhgutvYrnZnF6rl6pbbabNF+dYnbDohDcE4fmx6S6A
         +JCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HLU0ESCsmPHmmOa24bl2E8CWBrgFwbKszTKl0QLDnJw=;
        b=IylnWfy5KZXYLIIyzJR7Ec5TNj0DSayW0v+yT4pOlN7YeZ1HS73bMfEwTZhSiCQE1H
         PQAJa7U0mVGlfiiWugCNL9+bKymOiUpg1OecOyDo52SOi6ER/mbwbuvJuFauhaTVkfeN
         eu99eriU372M2/HmgfKMf9dOJc0uZpOzG9hLBUUYSLb5nmkdzbQGwQDvNJI896jHfV8/
         XbNLI49TCnFfUwr7AqITD129WvbBAgFd0Wk41ujo92WA2hrD9zXg3mwKLvqB8LoH1cTs
         3Gw6+mJIRVOQcuV2vGbmIW+JqsA7WfoUBn9FYa6HbnOOpffKpu0FefrqTek5xumjo+Na
         OC4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HLU0ESCsmPHmmOa24bl2E8CWBrgFwbKszTKl0QLDnJw=;
        b=qFB/WIH8rFtGqwscffZHWRHZ1gAore5bDq6nD1w1Yz5Ypma/OvQEFCJtRna5ZfFC01
         Chpx3eqmL+pljJWuqLZIknHj+r9Fmj3H5UEeqSKP3SwcrUoVUaMzPQh9moifqwB9LG9+
         rVRMsHcId5nQ6kvlo5c1VjtEjPLzM0LI+6qFOWVPeoGxq254UxR0l29Yk3YdJzsDHKBo
         CZdZ+rS93dWWgO+vhwl6aH65UtzZl8HplUTsklGcQtLWN7L4FQStQTYnYU/8KUxXZhSF
         mdMBfg0SvIdgpIpZlg4wZ0Hgqb20+U8HdgiUcq3Qspwbm6UQk5ZHv1QnTZ7Gw2FjwXe7
         bAJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530OXBHWrXhWKW2IL0Eb7Zy3YQakKYQh7LugVh6ooQCeTHnhbFmN
	rM0pugKy1xf9lk05gkHJTeo=
X-Google-Smtp-Source: ABdhPJylgG8AFHGZrJDI8YaeV73mC6BO5Olhz2S+1xTKdKHaiR1eGstGkI583j4M55KU7y+hcxI1BQ==
X-Received: by 2002:a05:6e02:218f:b0:2bf:f2bc:e129 with SMTP id j15-20020a056e02218f00b002bff2bce129mr16489816ila.292.1646748584828;
        Tue, 08 Mar 2022 06:09:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:328b:b0:311:84fd:8b1b with SMTP id
 f11-20020a056638328b00b0031184fd8b1bls2740291jav.10.gmail; Tue, 08 Mar 2022
 06:09:44 -0800 (PST)
X-Received: by 2002:a05:6638:34a7:b0:30f:5f87:1fb3 with SMTP id t39-20020a05663834a700b0030f5f871fb3mr15667705jal.219.1646748584542;
        Tue, 08 Mar 2022 06:09:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646748584; cv=none;
        d=google.com; s=arc-20160816;
        b=aQxYfBQM94GYEvpJTNYyY8y693ZkzSHvnNq3eJ4rlsRWSUpDAGrIj/ksqi+EpTI5Vt
         E98y1qhBLt6TtVloET6RLSFoIAKcNc3vgEyAVLFcBqODw+jbn4FxHMqKVTiJONoykBWJ
         2gPZjovcNC2HQPm68lurIRc2pGr35UMuD6qnE5sRPKWYKVltvG+2jzyekV8p80c10uLG
         9p9dC8jI6ltgf0ghXlCKz3wKr/0bRf9xWzxBICSF0QJbfDqxtYmum/QOjGf57oNPYyQC
         gw47gh0H0+fukx+S5+xAoOs7/h/gU5BupVEBwWD0gnZMXL/nlAcVMAbiIdgTpgkwsdP5
         hOWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hRpJxORzYHfHsib6XQ7pADNjcahneCQRQX9w7pOY0OQ=;
        b=TQn9P5FvZfrdJ88frihjZMwttFxRf1bETyjPMkMBbCnfkA3L9C0nsWqfUGhCO7cNeb
         IJuSjD31rf7Hea9eN8ZqG6/cQuPFtu6S27URtioo4I6TaN7Lf8ciapTmeaUfgbqr3o2l
         woj8jvSTtpM4j/r1wsL4w3rBUIr+IzDisQ1l3FG1TdgJCnp0azyYXB97hnnW6v0CEjHV
         j7HhNOcwA48IJj++m017M5lgYAUU6cW6sogbOEjBhvM/ycIoGE/JySn5tTElna6FnAJ5
         kZzZARq5VrXUD57Yi5I7WaLGNzvIGdz9NuyGXzILXOQzbxG0QMD23FMvjvNvDdUCVf1y
         OLbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=eYia2Unk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id s12-20020a056e0218cc00b002c1a7c1011fsi748580ilu.2.2022.03.08.06.09.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 06:09:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id s20so7654520iol.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 06:09:44 -0800 (PST)
X-Received: by 2002:a05:6602:490:b0:638:c8ed:1e38 with SMTP id
 y16-20020a056602049000b00638c8ed1e38mr14813042iov.202.1646748584377; Tue, 08
 Mar 2022 06:09:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1646237226.git.andreyknvl@google.com> <1c8ce43f97300300e62c941181afa2eb738965c5.1646237226.git.andreyknvl@google.com>
 <CAG_fn=UX_hF4RYdCMy-NRC+=KySFLE4wOTiCmzFPBwhieWjz4w@mail.gmail.com>
In-Reply-To: <CAG_fn=UX_hF4RYdCMy-NRC+=KySFLE4wOTiCmzFPBwhieWjz4w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 8 Mar 2022 15:09:33 +0100
Message-ID: <CA+fCnZdQtjF-wZRiX+CJLpp4BOQbJXDvAL3vE4+xaKVYrCqpqQ@mail.gmail.com>
Subject: Re: [PATCH mm 06/22] kasan: simplify async check in end_report
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=eYia2Unk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 2, 2022 at 6:38 PM Alexander Potapenko <glider@google.com> wrote:
>
>
>
> On Wed, Mar 2, 2022 at 5:37 PM <andrey.konovalov@linux.dev> wrote:
>>
>> From: Andrey Konovalov <andreyknvl@google.com>
>>
>> Currently, end_report() does not call trace_error_report_end() for bugs
>> detected in either async or asymm mode (when kasan_async_fault_possible()
>> returns true), as the address of the bad access might be unknown.
>>
>> However, for asymm mode, the address is known for faults triggered by
>> read operations.
>>
>> Instead of using kasan_async_fault_possible(), simply check that
>> the addr is not NULL when calling trace_error_report_end().
>>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>> ---
>>  mm/kasan/report.c | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index d60ee8b81e2b..2d892ec050be 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)
>>
>>  static void end_report(unsigned long *flags, unsigned long addr)
>>  {
>> -       if (!kasan_async_fault_possible())
>> +       if (addr)
>>                 trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
>
>
> What happens in the case of a NULL dereference? Don't we want to trigger the tracepoint as well?

A NULL pointer dereference is never reported through KASAN: for
software modes, it triggers a GPF when accessing shadow, and for
HW_TAGS, it takes precedence over a tag mismatch.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdQtjF-wZRiX%2BCJLpp4BOQbJXDvAL3vE4%2BxaKVYrCqpqQ%40mail.gmail.com.
