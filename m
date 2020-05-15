Return-Path: <kasan-dev+bncBCSJ7B6JQALRBCUF7P2QKGQEWLCYOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FDF51D55E2
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 18:25:48 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id v8sf1488966otj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 09:25:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589559947; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yhy1qJuuul8eInYo/JCWwyJEAx3LaTeC1MX8ZTKUYjLtiKgliIxI+LDQoE5lWZTR2T
         TBDLDlUjp+t9MHxpAlg/r2CnvQ9MvMvztseOX6JEfgvH6Wn4GyNfDbJTx5Uorgy1p/r1
         kqlmXuQGaKlEPxkKl6IjkcWv+fjnQdBqBGCWtGpLFvuhb5Mdk4+V02/q42Nj3dy7KS1+
         Z+ZmI29XZf/QfdKfYORqkAU5anh+STAN8WhgrP018WchzrJIzOJEgbaYL8Oe7xXmOLYx
         yYS8WItzyC7MvflSkqBNEhKlr5T/BZFcdiHzyVEMeR469j6au5fltxKKGm9IoRLQyYbQ
         paOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qMbXKY4Qm/4LT+lWX8YOMkVodkOjJrD6TWiu3iZE9qk=;
        b=xW5Lo4U7C+0u8d4RrLYM4YHLWPMSjbl4nt6vvvsmEPvKlod+OmzU6MrzqJpNK6B+0a
         kg/v3quPf+cjr1ypwIC5XJukAzg6CU6KjqUgIdNKD0hLE5uui+VZgghfjg5tqmBrfOCY
         dnjzo3WVIuqVrKEb/iwFFVXgDfN8ofa8977DkwRjIqSVB/C66ju5ia67TFaVDxQC73Oj
         7nY32X6zqWX4NOiaWjSih4jxs+lynLM857Md2Phkn5cHVBtsTpnbvqgCHkwCiZ17p0Kk
         eTLuGWxgghjFPOT3+UwSg83R+HRFDFfarekHvud2klu7auwvXq3p/1YpjY4RmDSEvXsI
         gj4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZV6vZWFg;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qMbXKY4Qm/4LT+lWX8YOMkVodkOjJrD6TWiu3iZE9qk=;
        b=Y/P/TJf1cnvHa1W0AWswlUzB3S0IzeFNdyalN9zGnQN15dktRhOhcEGfAGQdLKG24X
         PTsLDubyR+O16jOviEL1ovBNwg1c5bsT13VUqh8S7BbJd9G4BteSk/wlcSREC6ik8CdC
         V0jxebu6HH8aFxiaBzOgnuEK/c+gax4UwJ/fcuvSbQcGULjLq5gC5mL6o/0UxseUE5q4
         J3sjUWtJ1SvNdLkNIHoJAEDy9WHyarMfeC25kRfDDms0k3ESCUS6Z3xiWnIFddXV9WN+
         OY1tDauRzAo9QRbsBipqjjqNPdt8P8oW/La7bxwiT0wqHtxdk/0cnIA0URke1X/3TTpi
         VPaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qMbXKY4Qm/4LT+lWX8YOMkVodkOjJrD6TWiu3iZE9qk=;
        b=lUfcVczuZHH7FPjA2cneLp0Eu4OeGYZ/TGUi5WGowXsqlRrJgf0FfppZEH427UWs2V
         3B1Y20i5TC1mISbHFh4k4+m/X+zH+98sN6kXdYoOzoNdaSZgcdQom1zQRYE6Soc2fuz/
         lyvFagwAxvvLRL3LwslDm89ldYtFv1iuB2IySVt4ik3wnmyg8CR6UVl3uO+wHZWuwhEz
         BV2w267/yC8PAfJ+wM9huiHzmVbVeRxNUVIftXEKhM6Qz1FRC+STY9Z6kpVJG/AWNj1m
         1oT6LA7f+d4zhl1uaVQWbm15OMEuJW7oeMvmousOFkBks9StITQOeLwmpSiYntX8JAj5
         Qjvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53252d8YYKKzTKOepf+6t3dcrSu7PcZ0llwCOUZa6ScsAjoJ8vuu
	N/rMQwDDRgOc8I3R7qNz8d0=
X-Google-Smtp-Source: ABdhPJwcRpczOnWGrbMHg4W0+IbvJenDwIZe7rvXsrROeBHT2PZ0qx8x++sveKoNNVQ10E1DmA/Qgw==
X-Received: by 2002:a05:6830:92:: with SMTP id a18mr2990283oto.317.1589559946944;
        Fri, 15 May 2020 09:25:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d656:: with SMTP id n83ls629168oig.0.gmail; Fri, 15 May
 2020 09:25:46 -0700 (PDT)
X-Received: by 2002:a05:6808:19a:: with SMTP id w26mr2750601oic.32.1589559946663;
        Fri, 15 May 2020 09:25:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589559946; cv=none;
        d=google.com; s=arc-20160816;
        b=xaDMHEcCks1Um9ABORgxqO/+QcdOm318/AVSXS5MFSv8kwyQnAjw/NUAufqP5sBiNl
         cnwRKNdlwFnDY3kZj1BTE5kExrgFqCfvnR7cHWnmRUUDD2onthyljQ4EX+whEo4mY6Tl
         TbaQ8aNcC+TClhJ1Fgf+INcGA+GhfxLc0fAbFdPvbhTWigt8WXYVPRUwFdF3oLD5UEQG
         TA8O+eISn5wMVGBKVii4PvM49gaDD7lOUeVQnUq35YXUT021Ban423hx3ebsZ6psbqqj
         FO+lQpNK04nd2wwjXepEuBq5+wphzlV0Rpc2E2ZGflj7FxbGGGZyLgsufdTK0HTzS7zv
         mBXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ps5IsNy+4gcgBuZjYkSlVoRaiYUMkLWqlqvIdZeZJ0Y=;
        b=AXnlpelLW65IDC8EbZKQFThwiD0qG9h4agLrDV7O47cQzDt9e/81RlyaxrUKwGGkgF
         9zRPUEPo8FqeFZLyKfe2e57I4z/oOY+7EkWHLGHXKEvFMM9YZ/Bqt8xcQEVtsvlEtRaD
         tpTVajihp4nJuDMVNf1Dl71MeSTcPFt12bY8iJbJaeueD1M/mNORlbP+veVT5YuVaNnM
         sNJrg+LLPT9y7R1NZ5cOFJBGkDCeDhusm0vG6oRTvXvfwhuvkvBY5dsu5mQD5VjwVLiU
         0H2BGF/wITQXUReoFkt+UdrIp4zW8OznNZRsPsMEuspMRtQx5epsXGvJnzTQqGO1IiZp
         iCEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZV6vZWFg;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id w196si316566oif.4.2020.05.15.09.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 May 2020 09:25:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-492-QAI_14QDPhGuck0a4mvcpQ-1; Fri, 15 May 2020 12:25:42 -0400
X-MC-Unique: QAI_14QDPhGuck0a4mvcpQ-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 97D9D835B47;
	Fri, 15 May 2020 16:25:40 +0000 (UTC)
Received: from treble (ovpn-117-151.rdu2.redhat.com [10.10.117.151])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 9F83E5D714;
	Fri, 15 May 2020 16:25:39 +0000 (UTC)
Date: Fri, 15 May 2020 11:25:37 -0500
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: ORC unwinder with Clang
Message-ID: <20200515162537.j2nj5nq42b4zxmqz@treble>
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
 <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com>
 <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
 <20200514191754.dawwxxiv4cqytn2u@treble>
 <CANpmjNOoB36xu4iBwcOZ=RpjWEMwmqOX1tYU8+m285xXJDHRGg@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNOoB36xu4iBwcOZ=RpjWEMwmqOX1tYU8+m285xXJDHRGg@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZV6vZWFg;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Fri, May 15, 2020 at 01:50:07PM +0200, Marco Elver wrote:
> On Thu, 14 May 2020 at 21:18, Josh Poimboeuf <jpoimboe@redhat.com> wrote:
> >
> > On Thu, May 14, 2020 at 11:34:52AM -0700, Nick Desaulniers wrote:
> > > > The stack traces of the races shown should all start with a
> > > > "test_kernel_*" function, but do not. Then:
> > > >
> > > >   sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
> > > > kernel/kcsan/kcsan-test.c
> > > >
> > > > which adds the disable_tail_calls attribute to all "test_kernel_*"
> > > > functions, and the tests pass.
> > >
> > > That's a good lead to start with.  Do the tests pass with
> > > UNWINDER_FRAME_POINTER rather than UNWINDER_ORC?  Rather than
> > > blanketing the kernel with disable_tail_calls, the next steps I
> > > recommend is to narrow down which function caller and callee
> > > specifically trip up this test.  Maybe from there, we can take a look
> > > at the unwind info from objtool that ORC consumes?
> >
> > After a function does a tail call, it's no longer on the stack, so
> > there's no way for an unwinder to find it.
> 
> Right, if this is a general limitation of the unwinder, that's fair
> enough. However, if we build a kernel where we want to have the full
> stack-trace always available, would it be reasonable to assume we need
> to build with -fno-optimize-sibling-calls? I can imagine that we'll
> need this for the sanitizer builds, for compilation units that want to
> be sanitized normally.

It depends on your definition of a full stack trace.  Unwinders really
trace the *return* path, not the call path.  That's not specific to ORC,
though having frame pointers enabled might make sibling calls less
likely.

Building the entire kernel with -fno-optimize-sibling-calls seems like
overkill, I'm not sure what that would solve?  If the test code always
expects to see certain callers on the stack, it sounds like only the
test code needs the flag.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515162537.j2nj5nq42b4zxmqz%40treble.
