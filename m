Return-Path: <kasan-dev+bncBCMIZB7QWENRBC5ZUPXQKGQERHZOCHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BDCB113F60
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:31:41 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id t3sf2062545ioj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:31:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575541900; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfbRlM/qLNSmSwVNrhLOq/y5HZX8iQ5TwX12mzAWKA3a0Q3TkWRpYUVeumJMop90+m
         O6bHPlv1aKNw3gCZR//c6d3Jr5FemVT+MyH1SYYUIsTA/u84ihBKoFAEU9YsAoVUCY3V
         EQzB9sKQAyTi5LLXeETvoNyGzUQtE5fJHn2KqDij18xGor1i5m4rTquPtEXT7RW6OcPC
         gYvx80AAunxVaBqTFk6lQLu/9GqkL3DpG7J0SCUiPsMmYswr1fsVlSAQq88sCD+pQUeo
         MXlOzexwCRXpkE/Ii3vUzlZ48aQ27HNqlvj/0BNeMPiaziscL9FvN1f7rfzrBqfvjjmS
         GCkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jAQqLCP5ofGcpW27RtcsIrdvLHNSGSzhsWe3sqdlefA=;
        b=Ip37+TfTn8byYmB9E5Sm23tNAelbllmfbjAL85/esBRqybJj+V8y6ZXjlGanTe+IYN
         +ovhiqji3XHJxMeTg+5arBpVfSy5ClkvaUyI5FV9KPZ/a42mSH97ud52DTVGLCfot5kV
         U0ZkoyWPwNwvOKoBipb+j7zOQU6k3Dr+kSlg/TINz+LsYFz06t6f0rzGkODsmsJW60Rm
         VX+AtEb+5LbVl1pV85VvZ4JnTIcDZX4ENX2ebn5y5MC8h/fT/bBzje7BACQBP1cdcdSe
         2Ebe8FaxxtwLrM3KeqBC22Pf2tg+LnxE7NsiBbPK+3eymjXp4x0LTbSZyDXaJLN194Aa
         10NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYZMat2H;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAQqLCP5ofGcpW27RtcsIrdvLHNSGSzhsWe3sqdlefA=;
        b=UZztvjx69HKHP43DTvtH7hS9jXwR7eutGycj7gj9HoVLpgiO3eWGE0y7dmjsfPMMGf
         lXPgyy1Ri6vunEpV9MKDVts0DMKyzezpWv+ob1f5p8XvqFUp7AT7FAxL45/y0AQwI1aP
         0HaF9oC8XqMfPso6mswDxyf2yPusMvNnkslE8bI8dZxSD6MmsE/6Vz0m6VyrwpuVSZbH
         cqRzbVVMV9xPHTcrPFA1hip1UnmBe2MtSEAZc3/nrJhEvgNqS72b6PzCqzj2184D3ITY
         xP/8kwD7cd/PIlKEZ/Sb3YZlg7SnVo/Q/nxTKZMeQ5sDjqMaqAscqDzJms9oDKlPoEpn
         DM/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jAQqLCP5ofGcpW27RtcsIrdvLHNSGSzhsWe3sqdlefA=;
        b=TFGTk6/jRILP8C3C7Cefhsx0kQpSulC/TM9hA0MCvrWlVR9q6ayImjVQShUWQon0dF
         s3jmGgNy7X7P9ANyXEVGlcKFD6L++u7gbZGY1iqIWLq7IJIPITFkz00QMefDhaXxzzLb
         YebYAcrGzTdT3q729KtegAvJotKl6E+YcnJIFq1BiZ6gKhDxwzrXLq3ceyonTrM6L7oA
         VZQmC3uuiO0kI+LIB1FCKUBiImTcEIqxAt17HGG+8fk46952+qVtJe2SMVF/eo1ywki0
         +5nQkRz2+TUR6usHYCi0KaqhxVXD88d7R/KmEVf0G7RawKLWxs5+QUYcTMrhI+x5MNPR
         xtLA==
X-Gm-Message-State: APjAAAVn5fqfSSFAZRtGad7kLlnTBsWP5WnZ06tzG8e+Tg6hBFumH4xK
	kR1NqoY1C8CvqCWY6QAgzPk=
X-Google-Smtp-Source: APXvYqxWPq+8xK2RS1+Gb1zI3jlRAT1X/A9U+WwoQjoCQX9JjVPHAzsTExWoI7fsILoYdSMWKxAs2A==
X-Received: by 2002:a02:3b14:: with SMTP id c20mr7659677jaa.10.1575541899972;
        Thu, 05 Dec 2019 02:31:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls453828iln.5.gmail; Thu, 05 Dec
 2019 02:31:39 -0800 (PST)
X-Received: by 2002:a05:6e02:1014:: with SMTP id n20mr7800882ilj.221.1575541899595;
        Thu, 05 Dec 2019 02:31:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575541899; cv=none;
        d=google.com; s=arc-20160816;
        b=jmSlbMTz8C01SZHTbqBLRFxiaU7Ws67SJPxdyZbBbiBRBJhk+VnAjUF+if3xZMNuFe
         /6JwawU6gghhScwTN1DiMrxuwaav8aLF82RiH1swAa2MWaOlXvu/i4t2x8T3ScKgQzwh
         qTaw5zyeoX3EMbV+WXN2/sTqjusVP6UPfXmBVWq8HVsy5vr2geqqzzyf1LpayWk3ZHMK
         sExaIA21WXYUB+AdrhzJVyJpy0aa6Ovx9oi5DKTcfnlNHWXxZIw/HJJ0lSWQJ9LdD0TH
         D79BzuFmVUbIPySrSoFYAXW1ZFwxqf00dERtmnXrR/BM/7tflqmZ+l69XtoVdY/OB8tr
         1U+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AIwfFBjY5pjo/AwQlYLo1XDjqkJbAe8kAMyvBg+3yAM=;
        b=iRgZujKuxHGwO3hGQbneyiqQ6tbHKOSVXxyCmEfMauuIjKm1zONjpmlgQPIHsarZOA
         fTk8Na2fBvZOMenGRLO1ppY1HlUYSn/1ga7ARHZF14wRQ+pNYwdRZRDmsYqDxhVb9eOE
         6D8V8jdCPAEzAa4NaXpnUD0/fxnYRxUlNtU77TMcuJcRrgViJZRiufXhX2iN+jWazpUg
         ZnG3iqgaT7t5xLQxKVAFC09kZp/DaRHwSc1R4IBYXxFQVX+I9+QBy4HhFUpmpgGl8HqP
         hezgzT31GyvaKazTuCxEZG1CdK7QkpVxNa/HqpTL/zdchz8Wdo/tSvuHDsC2kf3ULGDx
         4R1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eYZMat2H;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id v3si626707ilq.0.2019.12.05.02.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:31:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id y8so1075157qvk.6
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 02:31:39 -0800 (PST)
X-Received: by 2002:a0c:f8d1:: with SMTP id h17mr6889518qvo.80.1575541898628;
 Thu, 05 Dec 2019 02:31:38 -0800 (PST)
MIME-Version: 1.0
References: <0000000000003e640e0598e7abc3@google.com> <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com> <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
In-Reply-To: <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Dec 2019 11:31:27 +0100
Message-ID: <CACT4Y+ZHCmTu4tdfP+iCswU3r6+_NBM9M-pAZEypVSZ9DEq3TQ@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Paolo Bonzini <pbonzini@redhat.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	Daniel Vetter <daniel.vetter@ffwll.ch>, DRI <dri-devel@lists.freedesktop.org>, 
	ghalat@redhat.com, Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com, 
	"H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eYZMat2H;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Thu, Dec 5, 2019 at 11:22 AM Paolo Bonzini <pbonzini@redhat.com> wrote:
>
> On 05/12/19 11:16, Dmitry Vyukov wrote:
> > On Thu, Dec 5, 2019 at 11:13 AM Paolo Bonzini <pbonzini@redhat.com> wrote:
> >>
> >> On 04/12/19 22:41, syzbot wrote:
> >>> syzbot has bisected this bug to:
> >>>
> >>> commit 2de50e9674fc4ca3c6174b04477f69eb26b4ee31
> >>> Author: Russell Currey <ruscur@russell.cc>
> >>> Date:   Mon Feb 8 04:08:20 2016 +0000
> >>>
> >>>     powerpc/powernv: Remove support for p5ioc2
> >>>
> >>> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=127a042ae00000
> >>> start commit:   76bb8b05 Merge tag 'kbuild-v5.5' of
> >>> git://git.kernel.org/p..
> >>> git tree:       upstream
> >>> final crash:    https://syzkaller.appspot.com/x/report.txt?x=117a042ae00000
> >>> console output: https://syzkaller.appspot.com/x/log.txt?x=167a042ae00000
> >>> kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
> >>> dashboard link:
> >>> https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
> >>> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
> >>> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000
> >>>
> >>> Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
> >>> Fixes: 2de50e9674fc ("powerpc/powernv: Remove support for p5ioc2")
> >>>
> >>> For information about bisection process see:
> >>> https://goo.gl/tpsmEJ#bisection
> >>>
> >>
> >> Why is everybody being CC'd, even if the bug has nothing to do with the
> >> person's subsystem?
> >
> > The To list should be intersection of 2 groups of emails: result of
> > get_maintainers.pl on the file identified as culprit in the crash
> > message + emails extracted from the bisected to commit.
>
> Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
> backtrace and I get to share syzkaller's joy every time. :)

I don't see any mention of "kvm" in the crash report. And it's only 1
file, not all of them, in this case I would expect it to be
drivers/video/fbdev/core/fbcon.c. So it should be something different.

> This bisect result is bogus, though Tetsuo found the bug anyway.
> Perhaps you can exclude commits that only touch architectures other than
> x86?

We do this. It work sometimes. But sometimes it hits non-deterministic
kernel build bugs:
https://github.com/google/syzkaller/issues/1271#issuecomment-559093018
And in this case it hit some git bisect weirdness which I can't explain yet:
https://github.com/google/syzkaller/issues/1527

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZHCmTu4tdfP%2BiCswU3r6%2B_NBM9M-pAZEypVSZ9DEq3TQ%40mail.gmail.com.
