Return-Path: <kasan-dev+bncBD62HEF5UYIBBPON5SAAMGQEEG4V4SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4860330E62D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 23:42:06 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id o2sf587986lft.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 14:42:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612392125; cv=pass;
        d=google.com; s=arc-20160816;
        b=HSBLkBjHQPrcmhwcrizy95QeBDPgRcTh5+tMn7TCvXhdnyrNllWNsPpC8R322YAQRX
         BLf1rTkIFlavQVVw921EZTwqeaJ66RUhXrF5YCCk4cpFbbuBzx19VXd/bRA9tDkw+hfZ
         Cmdl6mTvdsssPzxSDtv8uu/kqkCNdPvy8FkB4SDY/c1JBjJBLhChyJ2sknAtcFlznKQx
         zPdoO5amOhhAnxTGakWs8s17XX9KhsgipfoBkEn/BzwFqTaSUhkznbJ85fns+EM/8UVb
         NlZADwwtm6mupBhfjGmSeCco1ISAjdILXujBsfC+zp9SxcPWdftibBfHf6S/pZ5zc+n1
         dK0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e7YMq+gxGd80feHELDIaDSQ1JPvPx2WoPy+1xj4QxiQ=;
        b=BN6Xp5k8ASh6E8dQdQAaZ7DMbfW1P1ulzuO9deKGmiNb5av8rYrRQPj/HbaY2d8NbR
         +DlMRXAqI0kGZLVBNssj8WHzsjChy2woo8AcxeX9xeYTreKyslDBDLFCX1H6vSov7Fmx
         UoMhWhoczotze0g+318lLWsrj+zNX9LEVpJp/h9M4yDbgrV+MIA4nKJXIqTXhxOARs+n
         zE2ZoPxGjy8faykNwf9tD128Rvr4AO4TFONRjxEJWdvfHOEkmRzMZdtU2EeykI8XYLm/
         ONXMhyC2SMYgTivQW7qoJO6kIFRUKtk3YeDPrmMuIodTR0boQ5qWEPPbKPCCKTqUQKig
         xMkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=BKh7HWRt;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e7YMq+gxGd80feHELDIaDSQ1JPvPx2WoPy+1xj4QxiQ=;
        b=bR8E90Mto+XA4mM7bNW7VJOo8Jc2evP6hQayvFV5LrR2sLjf1H+ys9zRK18d+kvyEd
         qOCvs+cZWDhzPNFhy32j38vz+M7yhJ8qD89PiTHn3yWpxk3JVKkUjS+9a7CJXRvQhXhh
         XQoFOBsJw3ae5D3/URSWmN+DhG29873QiuIoXwL2ZFMrk6/GvUjgA+c382gJwO7UOpIp
         f258viHLsqsYQLoBq7NmYEHFrzgqhnGuTF8YlcUwmM32rlCtKrJCThiohe8X3GdiSwKq
         1YaLTHPU67bxboG3nza9h2a+GTSug0NCbcZui7DAqzsemeDZ452D+qDWN9+SAg84iB8d
         Wm5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e7YMq+gxGd80feHELDIaDSQ1JPvPx2WoPy+1xj4QxiQ=;
        b=oExXWDzTNzbpoWVWMHzP/oK+Hd85TGs0qX4Ikw4WLp95tPHyyHciTvwFFp4iSojXFZ
         YBNFaAe7tyDv4+Q5h1+fwwbqW5OWFz2j6gW3mGeWVRFPtKf82M30mTeD6W0iJZftF5eY
         2AIRl00GdYyHE5JUCn74ca5GPX7yPW4lsrYMY6evdp2cTlLee97PCiTfRMcdq6Wanw1x
         dOg42C4t7f0eL9gkK1gbNALKnk/faxxQ0xUc/I5zv+D76WAGYSFeSeLCtfC7Bp+EVxbz
         kaCoNPeCcwF+zIui9dG6ADoe91lttPw/hWYZdnTbfnspi5Cet6zfh3VjNRdcm2wt9Uzl
         0Zmg==
X-Gm-Message-State: AOAM533Lkgps+8jcwKnMQjGnEKFJjF2uwDh3OYr+nTnqCioZhBX3tUJx
	u9YONNXIzHOjWCCP/Pms6RM=
X-Google-Smtp-Source: ABdhPJxDjmnAPzKm8t+/UsBeA5j8v5/BUv8u4R5HibCw3yxcpTJ10w6YUd3WiGklRG4YPthHASgZDA==
X-Received: by 2002:a05:6512:110c:: with SMTP id l12mr2925544lfg.287.1612392125372;
        Wed, 03 Feb 2021 14:42:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:97c5:: with SMTP id m5ls667044ljj.10.gmail; Wed, 03 Feb
 2021 14:42:04 -0800 (PST)
X-Received: by 2002:a2e:9092:: with SMTP id l18mr2951784ljg.501.1612392124293;
        Wed, 03 Feb 2021 14:42:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612392124; cv=none;
        d=google.com; s=arc-20160816;
        b=zv/OpPvE1xvX/9Jp0RZTmfEc4BSRUamlyh0hOCG5QrcNNClcv7d5oIfuDqeaK7ZOU9
         e0pEWQd98wOtRMpnw5y/Cxmd3q2XO44hy2sWlhCvCW8G0BuzCb6K35xxT54EvdDW/hyw
         vJmYph2bbyOR4NelfLyJ38OlEquzP/+ObzXS2XuxOE+RjXtTueKaZS39Np3Z4R0RbsFB
         EKLPYJ/Q/RMddpjtM5rQTd7yqGW8QQ1dus9gI6rfLkNgvSlLL6C8jLX1H20XTkAUm5x7
         aIFcnUBUhXmEn3ogRu6c7GNPfKNSW3+wcRI1IDG0u11TFYXNNvjn2MS+nB6gaE94LypL
         Bl0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FumwaWvzHZWVNE5DDIsNdn258CZK4DlZwzfhawRHFFU=;
        b=Jx34J8JMzpjV+NrcCp1aTVk8ZVtgKqCEhdhJgL0oO9Avp/toD+DtxJCVpbrcxT7rn/
         b6W+pt/uNTmy3GF7nI9W5US/QAFAbYpN6W2iR8Z0/LBItvlpQpE8I3WhfjknRvDsZWwp
         uQL6mGn69Gc0jkWyDg40I3vYvn36FAh9T3ze6OX8tJsk/DcMmiwyhJGsgJTTZv6OIFtR
         qbtcz4q1UBk52D9qP8R3VJOJEQ+oVAES5KZOGSyofL1USSACA81jn5wB0NRcL4YNjSvv
         3IRtvFPbDqysmCG9kR2wlLYuuZMbNAskl4MV81fyNWEF5Ll49B5A9XQqbGADEdSjbY09
         TYiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=BKh7HWRt;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id g28si163389lfh.12.2021.02.03.14.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 14:42:04 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id y14so1001212ljn.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 14:42:04 -0800 (PST)
X-Received: by 2002:a2e:3a18:: with SMTP id h24mr2987085lja.170.1612392124007;
 Wed, 03 Feb 2021 14:42:04 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net> <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble>
In-Reply-To: <20210203190518.nlwghesq75enas6n@treble>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Feb 2021 14:41:53 -0800
Message-ID: <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
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
 header.i=@cloudflare.com header.s=google header.b=BKh7HWRt;       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::22c
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

On Wed, Feb 3, 2021 at 11:05 AM Josh Poimboeuf <jpoimboe@redhat.com> wrote:
>
> On Wed, Feb 03, 2021 at 09:46:55AM -0800, Ivan Babrou wrote:
> > > Can you pretty please not line-wrap console output? It's unreadable.
> >
> > GMail doesn't make it easy, I'll send a link to a pastebin next time.
> > Let me know if you'd like me to regenerate the decoded stack.
> >
> > > > edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> > > > commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0
> > >
> > > Not sure what tree you're on, but that's not the upstream commit.
> >
> > I mentioned that it's a rebased core-static_call-2020-10-12 tag and
> > added a link to the upstream hash right below.
> >
> > > > Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> > > > Date:   Tue Aug 18 15:57:52 2020 +0200
> > > >
> > > >     tracepoint: Optimize using static_call()
> > > >
> > >
> > > There's a known issue with that patch, can you try:
> > >
> > >   http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org
> >
> > I've tried it on top of core-static_call-2020-10-12 tag rebased on top
> > of v5.9 (to make it reproducible), and the patch did not help. Do I
> > need to apply the whole series or something else?
>
> Can you recreate with this patch, and add "unwind_debug" to the cmdline?
> It will spit out a bunch of stack data.

Here's the three I'm building:

* https://github.com/bobrik/linux/tree/ivan/static-call-5.9

It contains:

* v5.9 tag as the base
* static_call-2020-10-12 tag
* dm-crypt patches to reproduce the issue with KASAN
* x86/unwind: Add 'unwind_debug' cmdline option
* tracepoint: Fix race between tracing and removing tracepoint

The very same issue can be reproduced on 5.10.11 with no patches,
but I'm going with 5.9, since it boils down to static call changes.

Here's the decoded stack from the kernel with unwind debug enabled:

* https://gist.github.com/bobrik/ed052ac0ae44c880f3170299ad4af56b

See my first email for the exact commands that trigger this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi1ya41Ju9SsHMtRQaFQ%3Ds8N23D3ADn6OV6iBwWM6H8%3DZw%40mail.gmail.com.
