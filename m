Return-Path: <kasan-dev+bncBCMIZB7QWENRBS7GZ2FQMGQEXSEA5CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id BAAFE43821B
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 09:01:32 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id v14-20020a05620a0f0e00b0043355ed67d1sf4485631qkl.7
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 00:01:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634972491; cv=pass;
        d=google.com; s=arc-20160816;
        b=U9eaHFr9KxuyXoo2MhpkOBRqhyD4jKIhdBQNR/XI3lPIeHE0WDp7scY6+izF24YBgd
         W2xH0qgesRVQD6jhDMzvgKUdI/cL5M33hW8eByJJRpqOENMzoj+olwbyzZhXK7aLc2Li
         Xqpx7zP7xZwH0UG39GICYzb4A1V4M0Ld8h5lovqx6nCI+fBffTYEtkpMzYZqZw6G5q7O
         7tDk5DB0qcwpnWOWJJzlB/64yHmgnCHtMXOx2xndjXczJLx11jCn4PZXRnIW8OeoYkW8
         kFPjOR3kE/AKcg9qSlY4jxHZcevZOuNS0fRkehrc30I+uohYazbCUi+loJxUuJKqQH86
         vIjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dQhWDxHKDL1MQBRvh6EHBZMor3R+nUVDtdqVcwru6Xs=;
        b=Pc7YQWnXTuEenXVulYHrRCK4VhxeHwRGoOgiRivvh3QLv77g/PXuwBJQzJ2Qulhekt
         isEWwJ6ECaKL+Xdl0ZxbnCUx0JqyhAcSL2ka5dqgHR7TYgjk0NSSZx4uVoNeHVZkzIWv
         IaWfYIDUdj5y4dWiOZzzIm22MgAcM/Icfx57bumPYSTgitPtFzYIZz7y+1uvFGEgVxDq
         GkxSelhLeqVd33EhHr+ZPEC3jtrnFVUQn/1vWGnrZzjAf6Uwviq9Xqb/srfFjYoNF85+
         JmOVn/rF/wY5uoiSxgfMFOCbIP9QlDQrjcBSiC8AQnDuewYKY9atAzrZpcKQk5ZUcgKm
         UEgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OhhKJKYr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dQhWDxHKDL1MQBRvh6EHBZMor3R+nUVDtdqVcwru6Xs=;
        b=W29jVG4Nf4BKhcipV1Do6m4MPA57+xaXtONt9Ed1sjbG8PyFnBukv8icXuPKLXZbjq
         nrAYGEMF6JY3mpJqH9nfmHHD3O2Qev1kMe97jP93ql1d3eGNDDj8qdg18kYCEmIX+fUv
         TgJXRd7UJwxWIwBoCgFbqBSZQ7j7RnAY85kBIGeer6WdZgZvoyIKR5pdlQPCisFcDR4e
         lveb0gNfvTAG+da0QnIkt68JEFbY/2Sn/2e1tJMpGGrOFOlPS8dVZiN5ybvK7SFxJpzD
         l9njBsNE4O0WuZUwRPK7X1zqlhT7Ke5G+NGX66n8KRr7yBBoBaB7oRUN2w43fKsPmJrF
         XViw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dQhWDxHKDL1MQBRvh6EHBZMor3R+nUVDtdqVcwru6Xs=;
        b=O3vu0pvu2Za4N7X6iHASVNcWQSXi2XyJoFTGT5tdcSlOp/LlZKDn9b1gDBERHLGP9i
         lrEp7q8ouH33ADVT2gPfyoAC8LWytWiVBWrHeyQTt1i5R2c3xsg18tKT26WUbKhWVRba
         tVhZTEuAl6xToXzLhV6/DNrNttCFWTN4Pcnuoj0QC6ccmDBKq/JHCACjJBDgChZTRdTh
         zydM/T1JS4NLz4z+H11vw8jMnN7jcaVCtjyLaWkHYAs0vLN2onRIQ7UJt4KutO2ZyMFy
         sHY1s7/T4Yd9GB33snOQTI1iEYhRp1lCZ14x6Z38TjsYGCqm1XewF0T7t2ow59254G+Z
         0CkA==
X-Gm-Message-State: AOAM530sqK+MqlEqihIKkZPLlFlqiaZjY1uvZeECpQwhMKtCstlqbp0k
	1K6rAfA0L2/7YKwAZpNorpE=
X-Google-Smtp-Source: ABdhPJzMcUYYMOXoiYev/0y+HStVm8l89Wt1ldiAQe3gJ7GWeb1zv3n4jTho72OjduObESghfM9Thw==
X-Received: by 2002:a37:b606:: with SMTP id g6mr3638377qkf.328.1634972491684;
        Sat, 23 Oct 2021 00:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1883:: with SMTP id v3ls2315996qtc.3.gmail; Sat, 23
 Oct 2021 00:01:31 -0700 (PDT)
X-Received: by 2002:ac8:5c8e:: with SMTP id r14mr5001292qta.4.1634972491302;
        Sat, 23 Oct 2021 00:01:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634972491; cv=none;
        d=google.com; s=arc-20160816;
        b=SGg/lMjarJd982x9gBjR4ELOhY5k+n082rtnk3aQbPDSBLTA0BdWXGnCSBdb1UxWcA
         uS65+b//02u7/X9akHtdiN17qxTmoIxpjD6SnwcP8k5bdbD2LgXhJ9Hos9usxSNj0W7O
         9Pcc/anVvz/z4Ku+rTNf5Vpijve+psSaqyIlxB7nh3bTudPteGS/dkQ7rGTK8MdKyg6n
         IMvmSFhxBBmTloYjiaAmzTOG0ZSOLmkNm/rx51q/v5jSOJhS6TrbM/SG6Tomt3Xaix1q
         JFjNbFDhHF8grr+hNUMLTAxULvqhL+HzgREPnUFdgagxd7C66C6F7VqJrS31k544lwpA
         ImjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3XNK8/G5+03RpD0j7S3Gnth3OiCNUfmJqhs9h8ooGSo=;
        b=gimuDaoc9AaiiNTqxlw6BuebR0uh19HisefHLNgDlgo2fGvy2IAfdZhbM+wJxom+EL
         UKJpNCvWcXBIit5H9PzEz0nTF33oOOY6Rmzn0bQVOATmdOx98TSYzXCkX63+QR5gOE2o
         WYZnFIIrMQ9BgkVxmAhYfqQPq7XNpDMPU17U8Obh7fBF9HwpMbcueRRniECSo9GWDttB
         jEscqzbqf2WfWu/YZ8MOBynVDWYSinZ2qX3mCUjhEK2fFEiMeR4pncnnDBxcdmTnDcza
         +5HjPB+DVl2jskFk/N8ViWmo092c5mi5CZzw3f/ki5nwKCuboV1GxPQGuzz7XBVxwNlk
         Chaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OhhKJKYr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id z23si625727qko.6.2021.10.23.00.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Oct 2021 00:01:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id y207so7895029oia.11
        for <kasan-dev@googlegroups.com>; Sat, 23 Oct 2021 00:01:31 -0700 (PDT)
X-Received: by 2002:a05:6808:d50:: with SMTP id w16mr13922075oik.128.1634972490639;
 Sat, 23 Oct 2021 00:01:30 -0700 (PDT)
MIME-Version: 1.0
References: <20210927173348.265501-1-info@alexander-lochmann.de>
 <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net> <927385c7-0155-22b0-c2f3-7776b6fe374c@alexander-lochmann.de>
In-Reply-To: <927385c7-0155-22b0-c2f3-7776b6fe374c@alexander-lochmann.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 23 Oct 2021 09:01:19 +0200
Message-ID: <CACT4Y+aH5dZTSw7+59GTDQyikP6CqXCD7AAhjciaS_MQSbrV6A@mail.gmail.com>
Subject: Re: [PATCHv2] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Klychkov <andrew.a.klychkov@gmail.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>, 
	Johannes Berg <johannes@sipsolutions.net>, Ingo Molnar <mingo@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Jakub Kicinski <kuba@kernel.org>, 
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OhhKJKYr;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::229
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sat, 23 Oct 2021 at 00:03, Alexander Lochmann
<info@alexander-lochmann.de> wrote:
>
> Maybe Dmitry can shed some light on this. He actually suggested that
> optimization.
>
> - Alex
>
> On 29.09.21 10:33, Peter Zijlstra wrote:
> > On Mon, Sep 27, 2021 at 07:33:40PM +0200, Alexander Lochmann wrote:
> >> The existing trace mode stores PCs in execution order. This could lead
> >> to a buffer overflow if sufficient amonut of kernel code is executed.
> >> Thus, a user might not see all executed PCs. KCOV_MODE_UNIQUE favors
> >> completeness over execution order. While ignoring the execution order,
> >> it marks a PC as exectued by setting a bit representing that PC. Each
> >> bit in the shared buffer represents every fourth byte of the text
> >> segment.  Since a call instruction on every supported architecture is
> >> at least four bytes, it is safe to just store every fourth byte of the
> >> text segment.
> >
> > I'm still trying to wake up, but why are call instruction more important
> > than other instructions? Specifically, I'd think any branch instruction
> > matters for coverage.,
> >
> > More specifically, x86 can do a tail call with just 2 bytes.

Hi Peter, Alex,

The calls are important here because we only use PCs that are return
PCs from a callback emitted by the compiler. These PCs point to the
call of the callback.

I don't remember exactly what's the story for tail calls of the
callback for both compilers, ideally they should not use tail calls
for this call, and I think at least one of them does not use tail
calls.

But even with tail calls, the callback is emitted into every basic
block of code. So it should be (call, some other instructions, call)
and at least the first call is not a tail call.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaH5dZTSw7%2B59GTDQyikP6CqXCD7AAhjciaS_MQSbrV6A%40mail.gmail.com.
