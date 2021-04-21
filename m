Return-Path: <kasan-dev+bncBC7OBJGL2MHBB77376BQMGQET52MRWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E883366926
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:27:12 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id d16-20020a1709066410b0290373cd3ce7e6sf5698957ejm.14
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619000832; cv=pass;
        d=google.com; s=arc-20160816;
        b=1JzTQVwJJhqkJSBTO7WdHZueDmX88qr9mXDMuHFVBqZvKe6Bze2FDH7SYwvMf0GhWg
         U1cnEI22sPRp9bGH9gXEsKj3BA6RGJErZvUD+ChJL7NGftvUNUPE26OUizGO+Xnf8JIw
         G20Xsn8e12gZLA6wkFPqPPuMgZ4rnDNrDkifcGsJDaUqoLWzxBbcH8gENMG4DXZrDPWf
         TgjkLicmzy8Glz3jGpDa6T6r420sRMT8TaPUnxvWNVuwSSv4DuL4KjaBll0S3ZtuKY7Y
         +NxD5ShzK0pS4CutCaVmC88gFBDaZe8LunF8eIAUd3smddlRl7iBsyfsc8ALbiT4cnxn
         +NTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HSYW0Wqh/cbaYbfaJ7sGdtQfOQz76aP2/JN54dyT+9Y=;
        b=faG6pbCbPpA7a3IekfYAw4KlI2TqGYgI32WwxbbWd4U2PVz/sSW6j6v9KpTh5EWcGO
         N23lTQOzeotXpULkiw+i4UikfYE6KR8K0DLgkF3Xwnrr9li7Pw+XId9LBbjTCh5MWQRG
         TZtVwAsvAOCmgEYYP5fuWNAqXfM19FkgjQHdSRjKbPtYIaSBklwmyQ2qxzWMbannoFlm
         nEr8WKinzYpZygeMf8GBHhC0U83HuGa8fpNJkDTuEkuSBf1my7qHgNivDFWkUpsz/n1c
         i0pb2Jao1ME3rMnU4I/X4lDokElIgShviVx34PTnbsREu6ELHYl23POkStNhnEyIYffL
         pDLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JLKCps/Z";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=HSYW0Wqh/cbaYbfaJ7sGdtQfOQz76aP2/JN54dyT+9Y=;
        b=FBL1jYRR6w/7/d2uREyAhAP4jdIH/otdt2DnsifWjQyUhcQmg6JYvEUSDpjqpEV4D2
         hcQm6VxH8u1gmvqbSdSzENth5AbUC0Z0xmk9/8j2yBhFfEwSA/OgM3pKPJ0AdOslVQqd
         pmV9FEjCah0oAzVsCPJCj2p9UkZXiBtflAvVax1/AlUpSHqpZI6/4DcXzKacgGI5rmdG
         nV/wZNo3A57RXHQfjZrhoveih1hpChP/Nv3QYuDnlAw+cC/zpXGeYPJhST5lYS1fuZLi
         3Y0+DAIeDjF9NeKz74JSR7vo/ruRD8rX409sHYY/IBB9SYh74IquAvQCbRH0JXc+MYso
         OPqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HSYW0Wqh/cbaYbfaJ7sGdtQfOQz76aP2/JN54dyT+9Y=;
        b=kbKW60nt2JbAhE4Lu2V4HY/jbRnBydCei7Y6sHWuuq+mIw3+hT3ev036dVGxB7UiYg
         SUHrB3Zbwrq0DTUqmTBntOqExOeo8+bREVBDQJdkK5AIIhay1fWJ9EvBXqkAuGxmrJEw
         FFveY4fhdIFj6/kXRcaFSgZxZUo6W9nipiRvRF6ZhE+g/KbeEsYlGPyWIVR8wL9pRnIz
         5NiIdVSJJLYObCTNzYgMYKaO66xMiUKkszLYzKZdNY/itdCnyQ9psBWdquFb223KTHbn
         QEKeLn3IF6hjHZjf6Bd6vFlKPe4YvXyFdzkbBy9uRy9z8XBLz//BQzMVUzm5MQJVe8OY
         n/xA==
X-Gm-Message-State: AOAM5322AtT89kbCakkYsmoSVlmSg0CbopH+RGZS2sg3aEJzlptKkBz3
	hEsTU8vFKkgM+gG69HUzhIY=
X-Google-Smtp-Source: ABdhPJxr29wL5Jv3fja1Lz7cHpkuMMdrVCixzYd5dkWNFKlGWfK5DV9WnzEz9gIiN+waxC0ElAiT3g==
X-Received: by 2002:aa7:ca0f:: with SMTP id y15mr35869207eds.384.1619000832349;
        Wed, 21 Apr 2021 03:27:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cd:: with SMTP id h13ls422327edb.3.gmail; Wed, 21
 Apr 2021 03:27:11 -0700 (PDT)
X-Received: by 2002:a05:6402:cbb:: with SMTP id cn27mr24102650edb.222.1619000831164;
        Wed, 21 Apr 2021 03:27:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619000831; cv=none;
        d=google.com; s=arc-20160816;
        b=gwqNERNispusY3A1kaWJYRqA/WwS6K3IVaMABKZdeG0aNYLqroahHwwI+aFvTuRea8
         megmF3rHN5ILe09RsWl6wY1lNxuuAsNUMSEs4sJOFGuxEHE2NSfpBijl/EJ7xKBGmzSz
         c82PQ5rCkRm3bPTmtkQvuWya/bu/0CSSkTYTac85zWs3fKCKAKbLCmWGwWu+hVw4iLPA
         3rGoslH2CnZUU+dA2UPAJl6/FVA1pevsRYahvbGhmqNXKG1edh14+CUbh5LpAB7rTHds
         f+ePVgBVo8TlW7WkcPnYz1MpVJQzwbnoVqc/wjMHwVZqeL6jtkR7Un2mJVgLiOAL73K9
         9gWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DfB1PskyNKQQCJWiqpnf2aCTUFDtX+OVVcg4l3dtuu0=;
        b=AeM2WBlA2neFy8L4JGwetA1FIXqVEr86aJrNSCMe0xz3MiZu/CEt2pCbm1LFhRxhZI
         uPa9/uHbJMgfMm7JqWTW9NcbVuKEERqCH/zjiamii27ztMCj0s6rS4n3Q+lalcMclOfW
         ctsN+yEBdC8Zmes+FFPDmE1z8Cl4U3o7fQoLDlCJAu7u0fTXGirdBVb++XHU0nADBhT2
         gTC7NdipNNbYnhv5CORz2AKxUSPT9ukKLugmZow0hF5ZSz3iPIfgt+8k4aJGzbRxgv/m
         RahkaPFKPl8Bfe5RacWqICJsXx4NqGf1OnAu4b73uRap/XHJNEj0vetswCRJAsVVuUz5
         Fxgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JLKCps/Z";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id y16si198496edq.2.2021.04.21.03.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:27:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id k4-20020a7bc4040000b02901331d89fb83so938838wmi.5
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 03:27:11 -0700 (PDT)
X-Received: by 2002:a05:600c:4fce:: with SMTP id o14mr9054440wmq.121.1619000830626;
        Wed, 21 Apr 2021 03:27:10 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
        by smtp.gmail.com with ESMTPSA id c12sm2655220wro.6.2021.04.21.03.27.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Apr 2021 03:27:09 -0700 (PDT)
Date: Wed, 21 Apr 2021 12:27:04 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Hillf Danton <hdanton@sina.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/3] kfence: await for allocation using wait_event
Message-ID: <YH/4qKUAy76qNxXR@elver.google.com>
References: <20210419085027.761150-1-elver@google.com>
 <20210419085027.761150-2-elver@google.com>
 <20210419094044.311-1-hdanton@sina.com>
 <CANpmjNMR-DPj=0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ@mail.gmail.com>
 <20210421091120.1244-1-hdanton@sina.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210421091120.1244-1-hdanton@sina.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="JLKCps/Z";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Wed, Apr 21, 2021 at 05:11PM +0800, Hillf Danton wrote:
> On Mon, 19 Apr 2021 11:49:04 Marco Elver wrote:
> >On Mon, 19 Apr 2021 at 11:44, Marco Elver <elver@google.com> wrote:
> >> On Mon, 19 Apr 2021 at 11:41, Hillf Danton <hdanton@sina.com> wrote:
> >> > On Mon, 19 Apr 2021 10:50:25 Marco Elver wrote:
> >> > > +
> >> > > +     WRITE_ONCE(kfence_timer_waiting, true);
> >> > > +     smp_mb(); /* See comment in __kfence_alloc(). */
> >> >
> >> > This is not needed given task state change in wait_event().
> >>
> >> Yes it is. We want to avoid the unconditional irq_work in
> >> __kfence_alloc(). When the system is under load doing frequent
> >> allocations, at least in my tests this avoids the irq_work almost
> >> always. Without the irq_work you'd be correct of course.
> >
> >And in case this is about the smp_mb() here, yes it definitely is
> >required. We *must* order the write of kfence_timer_waiting *before*
> >the check of kfence_allocation_gate, which wait_event() does before
> >anything else (including changing the state).
> 
> One of the reasons why wait_event() checks the wait condition before anything
> else is no waker can help waiter before waiter gets themselves on the
> wait queue head list. Nor can waker without scheduling on the waiter
> side, even if the waiter is sitting on the list. So the mb cannot make sense
> without scheduling, let alone the mb in wait_event().

You are right of course. I just went and expanded wait_event():

	do {
		if (atomic_read(&kfence_allocation_gate))
			break;
		init_wait_entry(...);
		for (;;) {
			long __int = prepare_to_wait_event(...);
			if (atomic_read(&kfence_allocation_gate))
				break;
			...
			schedule();
		}
		finish_wait(...);
	} while (0);

I just kept looking at the first check. Before the wait entry setup and
finally the second re-check after the mb() in prepare_to_wait_event().
So removing the smp_mb() is indeed fine given the second re-check is
ordered after the write per state change mb().

And then I just saw we should just use waitqueue_active() anyway, which
documents this, too.

I'll send a v2.

Thank you!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YH/4qKUAy76qNxXR%40elver.google.com.
