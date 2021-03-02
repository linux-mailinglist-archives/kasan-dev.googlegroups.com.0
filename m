Return-Path: <kasan-dev+bncBD4LX4523YGBBV4S7KAQMGQEC5KMCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id B281C32A9B4
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 19:52:09 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id u9sf5080010oon.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 10:52:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614711128; cv=pass;
        d=google.com; s=arc-20160816;
        b=ktaPpPG8YqkY9P6wTOTfGzNlnRuOlHTX5xmvWHApLQvtdqRkxuVuERkfGSDz1PdOj2
         djn9umJOga69zJ13pskM87jlRtMoLLNgvLek/agZMU7Mr9JTRJvdoXl7RzWbivrQlFMc
         GxQfahcRrC1njicgh1li19IUZjfPBgtouUbcVvgeBS+gMDebf4Ep5waZtyjFY9DO+Tsc
         8JKOh4vCSoOUo8i09AVuuXsaiDnEyI0TlEjK9b5aCrLi9OMXuDF8rVwy8B24NiMYYNdS
         65Mrbrcx4FTJ1sNlpvJ6KwWMxc2X+V8Sd86wEvwy/JfEIkOufFLkBdq9s4T8oSEOxx0t
         Yzrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VoWMopRml0yyH+cS6aTRrpcQxRca7hrzcqXw3mh3u0w=;
        b=qsdRHPMiiUUZxvvfIuRZQTLGPaFk4W8b/1aGG50rBFvz2sEEnHZGzPBJR3B2Y/vxMm
         fC1ZYfY+DFtESu8739V+bsWTVXRfCReHaJIaEvIK4BHzuUS5oQKm+v3NliNNwh1aSlU+
         jE3Q4DBB3bdNt/Omye/hsk/j7NKqDngS0mYYhwuZrKMFnQVqpKnGcdDU10jrXv3y6hvl
         ScjoftiwTDuxPlY/ynglvtmWL4O0/i4Lz0/Epewptpa+9ieiEfhUuw0EI5MP/6pgZ6XV
         TohMqd/uNPYeftBR+ow5PbUec2tr24BFoqGrDBaerBrt7vjvU9SZTkU5nhoCceEA9VBR
         yuhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VoWMopRml0yyH+cS6aTRrpcQxRca7hrzcqXw3mh3u0w=;
        b=NTi0FzCG2Q2qpawjGvdnqueTf/DCiEtF72gBbUdPVzr+ZTzk5yiYzRYsxw0a6iuZlx
         dTRpLCT71BjyQbiic9Dy7xD86bCRrXA4A5Zwww4nZzj9vt2kMvRmRbfOvnVqynCOyffe
         IuUJTuVryzZgxhKmIBrODg9ivt1wuzu67+TKcaurxRyRp39DzyrYt1KlmxSP4mPS9YY0
         7++EbGrEqAlNgSxWwotnNOAbl3VeyJHMrG8w1x+6kkDbiGJ1a1Vx89DfEc1MN8uw0422
         HaOeY5lMPar5twDOakMK+oFF27o2Q25UEB0hV+PA98eL7xKkPbKl5PhlOvvOA2EunBAs
         G3BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VoWMopRml0yyH+cS6aTRrpcQxRca7hrzcqXw3mh3u0w=;
        b=QgHtpHG/En1pawqI7iKT0XJ5QR3itjEm0hZlWdiu4p+NLXQHmnJCZHnP8I3qADb6lX
         m44tQnfXNn6a7PjSAhGZn/0GwJ61taQ8Sa3esv+IyrAdCymIFcpegZY62mZNpm+QsE6K
         2+wSp2r+zfxD6QGIIdunx86fo47jo+JnQTNuknn4aNebnLWmrL9BF1MmSIXT4qB87ccQ
         kWhFQsWIw3LgWH/iy/hIAXU1nN4yL7GQZF3e86+37XG2aPmJM2WXdAfBKRZPChcpzLwX
         c+7hkfIU1+Ea4Z3/ToiVRZtHipwMddb6lmJJ53wjZdJoDD37MRjkN1G1EijtUBrZWS0O
         4raA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xIgNwcaBTULdC2xlcZsmVK2FISUlCHKCQRZ+p37eq9jYM8lI7
	11L/YFipGqImU8IJlPu5Z8c=
X-Google-Smtp-Source: ABdhPJwaQD125xjVxElh26fyXq6cg7S00Rhi6ngp1Ncz7PHSmykMVrf7DjAE+q4lsfe631PFcSu08w==
X-Received: by 2002:a05:6830:204e:: with SMTP id f14mr18919903otp.171.1614711128346;
        Tue, 02 Mar 2021 10:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c650:: with SMTP id w77ls275507oif.1.gmail; Tue, 02 Mar
 2021 10:52:06 -0800 (PST)
X-Received: by 2002:aca:2b0f:: with SMTP id i15mr4268696oik.152.1614711126930;
        Tue, 02 Mar 2021 10:52:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614711126; cv=none;
        d=google.com; s=arc-20160816;
        b=yDeL5N8RDfS52ZzH2Kl2gFLaNXFw/dnlhAOt4w6pFIB1vBpZlnWARi0Z+iK2W+KIu8
         x9RtNrI0QZOHh0hRTYo4CR8/EICWv8U7wOaeLygAs/eh7hQ/Vas18Fh7crrmhhU1J5WC
         emU7XC+FnkbnJWmkb8hMvoO2glwIKPOpY11QeHXr6CFbk6umxEXO3XDIbMyXPtikrFzP
         fC0tgtrOwKl0FBntP9A5IfObnPUVMhCTBXJdDOt/zgc7V7ljsFBG6TgV0wNHFpKn29AQ
         S874hT4f10xf0wo2xoQvWtGoK0WEZ0p53EhgPGIvaYEIihWbIisLrfoqZu253mD4iFVF
         FGbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=99KweLpG/QfykfBAngQAguKue4NK58+7FB6Rnl7Npng=;
        b=jG3kGOX3fp93FTYubkfOFLAS0VCNOSyS+jGWZF7UkQhhKqPto5x9P4QSmAVfvWX3Ew
         /Y5IhQLFgU7ruvdTclWndnx+OssQgThNnNwSLmRTH6y6e5VASSBcPpNu5bt70lVoDtBs
         kaeGg/MRIf9BtgGm1dzmq86y3ijBPlt2QY4f+zC6KLld3rly8wf6PK5qEFECDxrg/qoz
         uKWXNzwpJRaB3AhmQpNgnU2cChzit21/6d6q/t1/uEWhqmtUZx2AM1RsdjdsKmIvxCQi
         jJASLGd6cZ3XBzWY4l0ubpKMXlXdFvmWGhfC905qEjXv4C8GtWj2RTL0tNeWIZ1Qxq2e
         zEtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id p23si1286830otf.2.2021.03.02.10.52.05
        for <kasan-dev@googlegroups.com>;
        Tue, 02 Mar 2021 10:52:06 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 122ImlkH002242;
	Tue, 2 Mar 2021 12:48:48 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 122Imko8002241;
	Tue, 2 Mar 2021 12:48:46 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Tue, 2 Mar 2021 12:48:46 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>,
        Paul Mackerras <paulus@samba.org>, linuxppc-dev@lists.ozlabs.org,
        Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
Message-ID: <20210302184846.GI29191@gate.crashing.org>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu> <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com> <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com> <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com> <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <87h7ltss18.fsf@mpe.ellerman.id.au>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87h7ltss18.fsf@mpe.ellerman.id.au>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Tue, Mar 02, 2021 at 10:40:03PM +1100, Michael Ellerman wrote:
> >> -- Change the unwinder, if it's possible for ppc32.
> >
> > I don't think it is possible.
> 
> I think this actually is the solution.
> 
> It seems the good architectures have all added support for
> arch_stack_walk(), and we have not.

I have no idea what arch_stack_walk does, but some background info:

PowerPC functions that do save the LR (== the return address), and/or
that set up a new stack frame, do not do this at the start of the
function necessarily (it is a lot faster to postpone this, even if you
always have to do it).  So, in a leaf function it isn't always known if
this has been done (in all callers further up it is always done, of
course).  If you have DWARF unwind info all is fine of course, but you
do not have that in the kernel.

> So I think it's probably on us to update to that new API. Or at least
> update our save_stack_trace() to fabricate an entry using the NIP, as it
> seems that's what callers expect.

This sounds very expensive?  If it is only a debug feature that won't
be used in production that does not matter, but it worries me.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210302184846.GI29191%40gate.crashing.org.
