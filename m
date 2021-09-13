Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQOS7OEQMGQE5N3IL5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E806408451
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 08:01:39 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 41-20020a17090a0fac00b00195a5a61ab8sf6509275pjz.3
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Sep 2021 23:01:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631512897; cv=pass;
        d=google.com; s=arc-20160816;
        b=03wbDdZ60NHyIfFsYXwilmewnXStg5DVQ3CzxCSQBNkrX4zrkaghDsjWEFjYnc7Wxn
         eLCkNSt80AJPhbG7WjgljSX1ZUUOB9qQWjHGtYcd4+WJqQfbnxrUK4M/t9t67zSBawOM
         iLsG1CWFMyaSUNGranz8uaISbh9OO7WUzDUz59YZfDJm1htwz/q8ej+Qn4H90sZ/XDhh
         tv5ePg1lIwH/QYw5hFbG/iBfV6N5iZAKM6aoq+qcu+nBvFWS6n3oMR2HRQY/pwbeIbSI
         jbuZD9tpoJ/kTgGCpfBB2xRBjDNTMRfb4/SeAklAbZClgWGavCD7QPMAy9QDWGv7pUjV
         SMpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4IBV2GL3xtMQMf/iEdBHfLvLr6CEUQ4eYKxM9vsyjrk=;
        b=ypvOR+oj4+XF4wDLJwIpQBYsJvmVaLVH15nR9pNk4kedJxmam3jLSoHGkfh2K4jO6p
         jyeU7CGMVb39Hp3MoNqFcZ8IG/M+lGEVCTVppsBrAAF9/+Hnn2skQeA2pqeXeh3j7JIE
         UMC+KD3DEHrEEZaKlBKKqFoO+CJGW4FHVoW+vNIaqUtIrXBnFuzILQs5EWIbkUOsGN1J
         IgCevN95ODNp5wJKcI12hO3+gNFSGeCtvmzVCr6qM6ROYY58pRswdSMDFQ4KAPVr7XQf
         6nTbPvKA0aNpuPhx2jFa9bHz5nt6kh1uLRai++sMQnqJYndQw4E1regq9I0IGaW6Ry8J
         ROpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FBZ+QyXW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4IBV2GL3xtMQMf/iEdBHfLvLr6CEUQ4eYKxM9vsyjrk=;
        b=pzl7aqXQq1RMa+TkPk1FttkswFLMefM9Tr2QIxTnWYbMDOP7mVqAl+D77HrIXnoHac
         ZPdjBzjVIPA77OiFyj8S8WhuusPimAXYB0gGrzeui007JG90ETqQoT49Ena9cFUhS2lS
         NyJ8y57RP+Vi9ZeiFwTGndq9RNtCy78bKgDNazbdLn5BQCnpcC/IJtji1ZXPnnuLDoKl
         DIr7ng3EhaIsZrqO0DfBdttqA5ICLQ4ZcDPJ1A4YXZRJrAtm63KMtdH1iPbQW0BQzcLx
         84JW8uiyO5MMdcguiVHqA4b53msMdc1mQj1+PiQCsNG8k/y5gNmG6LhFFrzxJ8exz+2p
         R4qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4IBV2GL3xtMQMf/iEdBHfLvLr6CEUQ4eYKxM9vsyjrk=;
        b=CZ+ntquplEvtOoSzCr4IYshqtmIrV0NSUNhhkMYgcQs4yzhfyV9Xzi1OzFpcRm0un/
         fDnQhnh+jCUBnBkHmEBgaxywip/EeY53y04UzzCjc0Glu8lMKjiAvzl81TvqsVhgkpp4
         p+Q8hDJ2pIgx++Vu6c7VugjyJIBphRr9BzCbRyEOsyLXMNrCUocnTcTVlYsClCbacu6F
         6Nv8OS/0pTE6R3tZYWCovD7sWLUc0qPry3pPyP7FKqZ4+KMuy8VRracUfZIjqdOtznIo
         dS3c7E13gbuLXAsW5TijNujEsXUs1q4DkHJrLWjXbtpmVptwiU5w5lS3IZeWH0KdCZYc
         EJRQ==
X-Gm-Message-State: AOAM5301JYNZBXTOUBXqwn5bXriKQafuw6aHnK/C59iHGUzV9q2uZAF1
	pB4JvlE51P000wrmH4q3aJ8=
X-Google-Smtp-Source: ABdhPJy5MlipAlPKCfb0bxugAhDAAqxGyKsP2q7xwhFwaNjr52j4MOvj5Efl7xSl77TSRaoeKsC3Sw==
X-Received: by 2002:a62:920b:0:b0:3ec:7912:82be with SMTP id o11-20020a62920b000000b003ec791282bemr9728589pfd.34.1631512897553;
        Sun, 12 Sep 2021 23:01:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed86:: with SMTP id e6ls721311plj.4.gmail; Sun, 12
 Sep 2021 23:01:37 -0700 (PDT)
X-Received: by 2002:a17:90a:c913:: with SMTP id v19mr11239677pjt.243.1631512896924;
        Sun, 12 Sep 2021 23:01:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631512896; cv=none;
        d=google.com; s=arc-20160816;
        b=KAm8nopCuh+BDtdeQ+naUdJj5YGf2W+W9oYFS1t/y7RBGh3NHfl95YGOisYdde2wI7
         CXhs78sZm4yNgThSES/WwesR79DtGoWQklaSHEebTD9YBjp37Pmp/413xMt4an3fDl/K
         2bcHhV4ntwxX0ddG0eOHWEL8oZgFhJr6dXVuiAOlhdabczFh+VGbDtmaFNRHz2I6E+6l
         nqKSO4ZAPY9Pvsec7WqaS13rJVnK7PTY/s9sT6MvmtimNW8Fo5LqbAQkcrfbT7Qingro
         ME+wFVgfDiB1a5pn1oyK4w6SBpG+lo7Ks6l2k2ruqdxR8hVCy8RPffDxQ5PGg+SMY2wH
         DX/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jdwXw6pKQ+eOL7alcxynWehyVWgh/32RHEhD8lJnqhE=;
        b=P5jvSi6RsghdV4ptGOAuNvQ3mfrysdpgJjrk5rsOUSI+BMlSV2HfYJz93uabZn9k4g
         89bubqdr4EYTjI3cZY/7niCstc5XMpyNO4kf5i5XqUSaAbdYKggTsAaByh3b/rtC2S0k
         Wv9n1P/freb4E67rxRNcS8uoDaY4UO0ePPAf77cuvX7G2YXf0xomCRVQjSJdxrIDN5GV
         HKU4tBY6Cqup94SsslYnk19y+tPxDTk/Lf8eZC3S6zW00tCoIn5AgqsKrpzSyRPlZuhV
         qDlx7JbnjTEbNLXpupq2m3bfvuhrgCkquRs9w4TOQcouzGzPFCWLmT9gzSaDTyFUGJPz
         dAJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FBZ+QyXW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id r14si544576pgv.3.2021.09.12.23.01.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 12 Sep 2021 23:01:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id c79so12644366oib.11
        for <kasan-dev@googlegroups.com>; Sun, 12 Sep 2021 23:01:36 -0700 (PDT)
X-Received: by 2002:a05:6808:21a5:: with SMTP id be37mr6405238oib.172.1631512896132;
 Sun, 12 Sep 2021 23:01:36 -0700 (PDT)
MIME-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com> <69f98dbd-e754-c34a-72cf-a62c858bcd2f@linuxfoundation.org>
 <1b1569ac-1144-4f9c-6938-b9d79c6743de@suse.cz> <20210910152819.ir5b2yijkqly3o6l@linutronix.de>
In-Reply-To: <20210910152819.ir5b2yijkqly3o6l@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Sep 2021 08:00:00 +0200
Message-ID: <CANpmjNM1eGjsvYUvtTEq4dwraBqw0S8adPn9o7SVZ6G-i-Eq-g@mail.gmail.com>
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Vlastimil Babka <vbabka@suse.cz>, Shuah Khan <skhan@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FBZ+QyXW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
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

On Fri, 10 Sept 2021 at 17:28, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
> On 2021-09-10 12:50:51 [+0200], Vlastimil Babka wrote:
> > > Thank you. Tested all the 6 patches in this series on Linux 5.14. This problem
> > > exists in 5.13 and needs to be marked for both 5.14 and 5.13 stable releases.
> >
> > I think if this problem manifests only with CONFIG_PROVE_RAW_LOCK_NESTING
> > then it shouldn't be backported to stable. CONFIG_PROVE_RAW_LOCK_NESTING is
> > an experimental/development option to earlier discover what will collide
> > with RT lock semantics, without needing the full RT tree.
> > Thus, good to fix going forward, but not necessary to stable backport.
>
>   Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> for the series. Thank you.

Thank you. I'll send v2 with Acks/Tested-by added and the comment
addition you suggested.

> As for the backport I agree here with Vlastimil.
>
> I pulled it into my RT tree for some testing and it looked good. I had
> to
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3030,7 +3030,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>         head->func = func;
>         head->next = NULL;
>         local_irq_save(flags);
> -       kasan_record_aux_stack(head);
> +       kasan_record_aux_stack_noalloc(head);
>         rdp = this_cpu_ptr(&rcu_data);
>
>         /* Add the callback to our list. */
>
> We could move kasan_record_aux_stack() before that local_irq_save() but
> then call_rcu() can be called preempt-disabled section so we would have
> the same problem.
>
> The second warning came from kasan_quarantine_remove_cache(). At the end
> per_cpu_remove_cache() -> qlist_free_all() will free memory with
> disabled interrupts (due to that smp-function call).
> Moving it to kworker would solve the problem. I don't mind keeping that
> smp_function call assuming that it is all debug-code and it increases
> overall latency anyway. But then could we maybe move all those objects
> to a single list which freed after on_each_cpu()?

The quarantine is per-CPU, and I think what you suggest would
fundamentally change its design. If you have something that works on
RT without a fundamental change would be ideal (it is all debug code
and not used on non-KASAN kernels).


> Otherwise I haven't seen any new warnings showing up with KASAN enabled.
>
> Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM1eGjsvYUvtTEq4dwraBqw0S8adPn9o7SVZ6G-i-Eq-g%40mail.gmail.com.
