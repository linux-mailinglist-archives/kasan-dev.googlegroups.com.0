Return-Path: <kasan-dev+bncBD62HEF5UYIBBJ7E5SAAMGQECRK3H5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5080630E763
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 00:30:48 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id b14sf988528ljf.22
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 15:30:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612395047; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ly/l/3YNpUKW2pvprdUBMvNk3GCZmmsyMWaxbBv1KvwKVj3yF2yQmBJSV2ePoXy/S5
         Cg9HJmKIy0hHGdFDFLZ05yAl/fumV5yNOgOojeZRqDvctRZ3YZGzZe++AksSDj4d0GO/
         Ygu6GAB8t93xqQcx+2IHHM2nNpB/m5LjuhQWFsYebpXKqTaVpULbPAFLVCIDNgNjrI7o
         UzeMD4aGhq2aozgPrKDMnCeRwJQUdqnHbLMyrNT4UBmwYGk0XmfCk2jVr8af7L9b/XGI
         eMWfruGG78qRUac5aPZRTkbBI2i/HlRdPCzctyfjqbnoSEfCoxqylrIMNTnnML4JKUM7
         sDNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E68fgS/SjfA2xEbpufHbnUgbwMJ0qRFgEctVVbvlKM0=;
        b=nzY4bwDud/o3Z9w79ku3CqKCIoWgh1TE/QwPovaMcZ9vPxKArOk8vgiKR3VnhBCyrh
         3+i/uSk3vj3+RPXr+VSvUC8eH3ON4mzTGUNRNaL+5PI0xKp5ynwkE8WYLQTQ9d6r73p8
         ZM1XslpDuK+s4S41P3LB4BWEzeLK2xoG8r3ig6OzDKJHUsGBpOwLMWZbYHhTt1jtCCcE
         e6GsDwLmEs3lQuobIAYjNA4UhdMfqjNSr3q01aYsrYSeruouAH9xmzzlLo72NPwgpVsK
         tu5RoM7UENkbBM3wJ7QAE3dCDUoCwaPQjGFqK9U2gC/NPzjAHRA4efs7Hb3NfDKnSkrg
         7z4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=B2166ME1;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E68fgS/SjfA2xEbpufHbnUgbwMJ0qRFgEctVVbvlKM0=;
        b=gVbrRs8eBItvtvLR8bhWgOB9bzn4sf5Sob6yN9aUgLrGBK5VWNo9ykTQwU8TipH4h8
         kDXi17lXM+I6qDTBn4zGPsZ0vBMyIEyRhl9OoqFx1ug2oIn7Sq/GqPCxRZ76YBCJv4lm
         jK8tECVdci0ZTU/gRelMpVtrWdKtmxaqyLA5oo/5X/J+CFOQPa5v8lps7Gd4CXN8KpNs
         vGFqDLMhqoZCk8bT3I/gD1udCdEZDT+JrMhoZs33vMtWSLDeAwLQ8FROuk5WTGexnbgS
         HWqklA7d6EXZs6trrCvM+iACoMozccVPGAg/fEp23arLLcZ1cxjbIW1KTM9K7BtxFl13
         aODQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E68fgS/SjfA2xEbpufHbnUgbwMJ0qRFgEctVVbvlKM0=;
        b=QNN9mAgsf9m8c6NM6638dabNzJbRaf4tl4M85KNZef1g66ezHcUqr3ZOv7dqEov15s
         vWp2vf6+qryp7q56B3kMN1Y4SCIpl48dQQbwQvpamBsdy3258PXTGn2A1UqnfPJnzGdf
         C6p8iRVZqMpfw5KNfKdiXYGf2YuE0cjzWsZoOy6u4zHecXU1GLSSl27L+YlfZqyA0FCd
         69JtOOYdHc/IVXZDE71ZmwgudyHfm2YEN/nXslDbvKDGAm1crMunRLX5PAQhk70Ndxd9
         hv3z5vnISzNEIqARJYlumyLNjNe58wz8h9n0S/oLs66kXzasRym0N+k4SlO94duak/n6
         oLJQ==
X-Gm-Message-State: AOAM53295ygQSLYc1YnBjF4EFO5V4WuqJdXM6W9paPFAaYbqa/dtZHUX
	NVEo1/9m6k8+YYdEPcW3/cA=
X-Google-Smtp-Source: ABdhPJwsAdC7JcNEc23iX5tOxOkBmitt85YTwQVVKE1xHB9A6RwkVGy5Rg/jJREBl9T7ksmmF62WCQ==
X-Received: by 2002:a2e:311:: with SMTP id 17mr3187484ljd.14.1612395047775;
        Wed, 03 Feb 2021 15:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls1371062lff.1.gmail; Wed, 03
 Feb 2021 15:30:46 -0800 (PST)
X-Received: by 2002:ac2:44db:: with SMTP id d27mr2925281lfm.248.1612395046806;
        Wed, 03 Feb 2021 15:30:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612395046; cv=none;
        d=google.com; s=arc-20160816;
        b=JqG7xHnNGucw1R5pi74kJ0eXvryAfLu9gn2bTeEu45oCXzu5WXrpGYx2ahWWUB0oon
         i/+e1IrOVdqoor2J2QnphQ/T8eiY2UA41CEGDtLlfbiz3Kpcg0SAT0RxV8uhawxpT5rT
         z4oVT3a2bVv2g+fZYC9IapS1p8FwMWQk15es+BjwKOSC/kmVCBxlPNGkfbfotTOk/6tJ
         HZFH1wBtjxCdq6c6EKwcrOtR0OVTxs2rBXG35y3j6gHR2WMguThtQFNCQfvD9ib+xJeS
         SCwftcsT7BHRUJnYniINkpYGzumpAnukGYdUrpBm/xJcqbrh+AcbCL/b16/L90ZN2HTC
         YUig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hocG39X+tz3ResWtWHRihYuESyyVfrOSMJOVeII1Yr4=;
        b=cTpOpqTqNGSTlqNtBTZxdSf1+VhFAgGEdSxG/jYcFnDQX33Qb+HA7cSvJ1rllt8Uom
         dgzgR/iSwW0E3+6mg14EtDNB8Y/7AEZ8npjtUagLg09PIxV7NVxxPd3rKe7s2ZVJmEKd
         1j88Pz9mgwP4vm+k2vVX2TJAkuqc4uQ5mf+OROcrijUbV/rD31Zz2JF1RsSjC+XKXdNx
         qHvebo/u7qqKvvXc1F+DDMkaiOMDxWERKgx4ak7kOMFqeLhhqHUXQ059kSsSPT70+WCS
         nfnczQ6S43upl8P5mwc86CR4SMPXIeqYBrcsR7MciCMB8C2Fk4H+saewGGVD7R4OLRRo
         qXhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=B2166ME1;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id b2si159128lfd.5.2021.02.03.15.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 15:30:46 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id h7so1746014lfc.6
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 15:30:46 -0800 (PST)
X-Received: by 2002:a05:6512:3904:: with SMTP id a4mr2912750lfu.340.1612395046510;
 Wed, 03 Feb 2021 15:30:46 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net> <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble> <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble>
In-Reply-To: <20210203232735.nw73kugja56jp4ls@treble>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Feb 2021 15:30:35 -0800
Message-ID: <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
Subject: Re: BUG: KASAN: stack-out-of-bounds in unwind_next_frame+0x1df5/0x2650
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, kernel-team <kernel-team@cloudflare.com>, 
	Ignat Korchagin <ignat@cloudflare.com>, Hailong liu <liu.hailong6@zte.com.cn>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Miroslav Benes <mbenes@suse.cz>, Julien Thierry <jthierry@redhat.com>, 
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel <linux-kernel@vger.kernel.org>, Alasdair Kergon <agk@redhat.com>, 
	Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com, 
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, 
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>, John Fastabend <john.fastabend@gmail.com>, 
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>, 
	"Joel Fernandes (Google)" <joel@joelfernandes.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Linux Kernel Network Developers <netdev@vger.kernel.org>, bpf@vger.kernel.org, 
	Alexey Kardashevskiy <aik@ozlabs.ru>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ivan@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google header.b=B2166ME1;       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
X-Original-From: Ivan Babrou <ivan@cloudflare.com>
Reply-To: Ivan Babrou <ivan@cloudflare.com>
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

On Wed, Feb 3, 2021 at 3:28 PM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Wed, Feb 03, 2021 at 02:41:53PM -0800, Ivan Babrou wrote:
> > On Wed, Feb 3, 2021 at 11:05 AM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
> > >
> > > On Wed, Feb 03, 2021 at 09:46:55AM -0800, Ivan Babrou wrote:
> > > > > Can you pretty please not line-wrap console output? It's unreadable.
> > > >
> > > > GMail doesn't make it easy, I'll send a link to a pastebin next time.
> > > > Let me know if you'd like me to regenerate the decoded stack.
> > > >
> > > > > > edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> > > > > > commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0
> > > > >
> > > > > Not sure what tree you're on, but that's not the upstream commit.
> > > >
> > > > I mentioned that it's a rebased core-static_call-2020-10-12 tag and
> > > > added a link to the upstream hash right below.
> > > >
> > > > > > Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> > > > > > Date:   Tue Aug 18 15:57:52 2020 +0200
> > > > > >
> > > > > >     tracepoint: Optimize using static_call()
> > > > > >
> > > > >
> > > > > There's a known issue with that patch, can you try:
> > > > >
> > > > >   http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org
> > > >
> > > > I've tried it on top of core-static_call-2020-10-12 tag rebased on top
> > > > of v5.9 (to make it reproducible), and the patch did not help. Do I
> > > > need to apply the whole series or something else?
> > >
> > > Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> > > It will spit out a bunch of stack data.
> >
> > Here's the three I'm building:
> >
> > * https://github.com/bobrik/linux/tree/ivan/static-call-5.9
> >
> > It contains:
> >
> > * v5.9 tag as the base
> > * static_call-2020-10-12 tag
> > * dm-crypt patches to reproduce the issue with KASAN
> > * x86/unwind: Add 'unwind_debug' cmdline option
> > * tracepoint: Fix race between tracing and removing tracepoint
> >
> > The very same issue can be reproduced on 5.10.11 with no patches,
> > but I'm going with 5.9, since it boils down to static call changes.
> >
> > Here's the decoded stack from the kernel with unwind debug enabled:
> >
> > * https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b
> >
> > See my first email for the exact commands that trigger this.
>
> Thanks.  Do you happen to have the original dmesg, before running it
> through the post-processing script?

Yes, here it is:

* https://gist.github.com/bobrik/8c13e6a02555fb21cadabb74cdd6f9ab

> I assume you're using decode_stacktrace.sh?  It could use some
> improvement, it's stripping the function offset.
>
> Also spaces are getting inserted in odd places, messing the alignment.
>
> [  137.291837][    C0] ffff88809c409858: d7c4f3ce817a1700 (0xd7c4f3ce817a1700)
> [  137.291837][    C0] ffff88809c409860: 0000000000000000 (0x0)
> [  137.291839][    C0] ffff88809c409868: 00000000ffffffff (0xffffffff)
> [ 137.291841][ C0] ffff88809c409870: ffffffffa4f01a52 unwind_next_frame (arch/x86/kernel/unwind_orc.c:380 arch/x86/kernel/unwind_orc.c:553)
> [ 137.291843][ C0] ffff88809c409878: ffffffffa4f01a52 unwind_next_frame (arch/x86/kernel/unwind_orc.c:380 arch/x86/kernel/unwind_orc.c:553)
> [  137.291844][    C0] ffff88809c409880: ffff88809c409ac8 (0xffff88809c409ac8)
> [  137.291845][    C0] ffff88809c409888: 0000000000000086 (0x86)
>
> --
> Josh
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg%40mail.gmail.com.
