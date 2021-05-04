Return-Path: <kasan-dev+bncBD52JJ7JXILRBAEPYOCAMGQED6YP3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BDEAC3724C7
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 06:03:13 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id l6-20020a67d5060000b0290228235bc72dsf225189vsj.13
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 21:03:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620100992; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZsX0G0yb9rDo7f+tYj11LDw3g/+gG2w1w5mVaVR8WRVK2favrsDCDJvdITJ3N7p0U7
         5cEjmiEPjdjGuE9Q2Efsky58dP3RlHTvc3ov2YHz8n/6RRiV2xWyvdAO+YXGPBep0BO/
         gKccOo1uehCbqKRFbFynA2zZeMKriHwI+ChOSt9WCMtQYwLSn+QIaNK4afMcdJpbf71B
         4jyT5JcschiMC4zItlpuhYVbUN6Seo1aq+WK7qWX7YvAWOK/iwlIVS+g8aQs22WYcfxk
         2VjR+J4hFDVd/x4OVlWYkE+64mEJX6x7O9Bh4VjMl9s2n7S9o7YHaSdASVR384oahg30
         I3xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1IUWYzSqUxV7BsWl59ZusWFCIdm8rQfA9Qv7jXALf28=;
        b=btTXHnIlee/6aReNhIRnVvY+EUbvToMRpX923n2f3VlqxYMN8L19LqOq7UVVVjEOwW
         /WNHTn8sGpSGYKO3st/wqxG8IR2htcV+OpTeaKPnWrQ6bzmQ46nwifYND2uU/TBIFmZA
         kmhix3NDLRByXdd+3xKVsWMsultRvBAxnlt1TGrc6+lUfm3zUAL2mpjynhvVEgBp4Zyc
         D8AwQo8goPLDMCyNae3I1TD/6PV84dI41fUahhU/sNZYPOw1A69lYDzwIdGElL11GyF/
         TFiorFtZmD+gcVWso6wkmjCL82u0b/1do/dCtWwlGhbLx6m6SBrjaV+SHlFCnadKPGZ8
         80Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sjWwmwPL;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1IUWYzSqUxV7BsWl59ZusWFCIdm8rQfA9Qv7jXALf28=;
        b=f2RUZzsGqrrewX9iSxGpMT5NDtsdZNE5yX0dZt1XBmIIUNgpck0mFnyk8Ss4N8gh14
         JihXVfwuAHenEfQJCkI2cQUm+PEazBuNI7NnXMw9sj4Uwh1tVcX2sC6Y2ba1uHR7DcbO
         xzJm8OXyhcsnXQ3XkeTmdcjBPvrh+9joBC48dSzG+TFIkgYI4rDFxClnRhnES/VyjjgO
         llC7nbddymJIPYocJcwqHIfnVCCLfXdYfI1n43xl+vPcjZnF8MT7IBpRFvFledxMi9Te
         +Al6upMwBbYoAJOeGOgNEx9FFmXrhJfFI6Vxal6QVgQt4ekPYSWS7Q/keSb6EOVUOALu
         UmVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1IUWYzSqUxV7BsWl59ZusWFCIdm8rQfA9Qv7jXALf28=;
        b=jcRy6FjnoneR0XxWgHsyKmFbV+te9Bp1WikEf4vvzIYn35cv2Ofx/OMJZoSoHQTODg
         swibVTtMSeeUWsxit7090cUoezwSMUrgf09GZD8vbe1w4q8yHIQndy8e8rQDnrZoCj7X
         Gc4BB176tgHt8ZZFb0Iv4NdiTH+CmkLUl/Jr2Ejy4UWZl9kUa/rZFc5bCegfBgqV/psR
         qfHHF2qQ60bhuZp6MXAJnpIdyQJEzSPWW4bcpaFwf2mt2DoIpevstd5iTGPMGMgLnD4v
         bHUO947Rnc5cPDjzl9zbRnsng6D908qMlRwyn6F9cwT+/0vN9pxy4mAJik/RWYBnBodJ
         RtPw==
X-Gm-Message-State: AOAM532AEmy2s0//Xqx9dy2AuyRylWM0W6vGj2+P4eegv0PEx7t0UZgW
	buj8G5Hc8LEjDP1rwOWHjCI=
X-Google-Smtp-Source: ABdhPJwH/osRZV0vZtIKeQOWV9Ci+vx0vBCMl1VV5DhVwBnedcPSSF7JpeKddCAAUMoBUd7yM6mD2A==
X-Received: by 2002:a67:f988:: with SMTP id b8mr19701724vsq.14.1620100992615;
        Mon, 03 May 2021 21:03:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1ec2:: with SMTP id p2ls772474uak.2.gmail; Mon, 03 May
 2021 21:03:12 -0700 (PDT)
X-Received: by 2002:ab0:48cd:: with SMTP id y13mr18608204uac.18.1620100992117;
        Mon, 03 May 2021 21:03:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620100992; cv=none;
        d=google.com; s=arc-20160816;
        b=cp0RW5pOLHoPJxSMGy9slnYsJ68UtdujhTRMJiOG2PoRHWX5Ua3NnNJ/A2qfdaOy6p
         oypRAfE2cNHz2UeyeRfT6mwRtH3jpLSpADd3HztxJx3YojS+qEFjfvbD4xwFc2q2IQZJ
         8cXRLaLQtuYrGjWOk99Bd1+uPI7j9N7L5TiV6zLJVBECD+7o8gJNpqs3PjY+/HN+wzox
         womC7fd0Mk7RWAaDPZXJEKyOUkmEHDTusfzLku+Ls2OpM//pb5RqcxHMHXGNxx8OSFNP
         VGwazISa1PWrTdyoTzfMMsyCon6ug6yvmB+LOxN3jWkibo9gxu5xd6lAXrWlJLl6Orfa
         MIoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=56mc9V9A73cEiKQwEt/CmT2tfj/Xb7ZTWRyNvK3LPcU=;
        b=cw8GNZZKpySXcjXDf91DKKZ4c7JXT9khfzqraE9aiQVxiA39W8zhOsAazJ2dlrOm6n
         kLR/+8DZNtd5u+wHVKSZl++SJpZ9m34uG0/feq/PY5Ep7eJtE6lnc2x1kQ+m827JACi5
         o3XN7l5exA9MJwoLe24HWA6RBdhLnMtoZ2i906p0m2qEAKxg5ca5OcmXLrGHdtcXw6Ae
         YELxqsmhugt76rTrUcUMKRqBh62KDS3ksNUlPkaTr2SULagEyfSN8D2VCHoZfXxpPwKC
         KkUJqH+UBBsaRBtm25QaojwS5P7A94FfXOlXlr20e/JBqGsTSZNCtis7cI49h+Hy8obp
         /MAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sjWwmwPL;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id x190si110148vkf.1.2021.05.03.21.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 May 2021 21:03:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id e14so5290600ils.12
        for <kasan-dev@googlegroups.com>; Mon, 03 May 2021 21:03:12 -0700 (PDT)
X-Received: by 2002:a05:6e02:13d3:: with SMTP id v19mr18182359ilj.56.1620100991437;
 Mon, 03 May 2021 21:03:11 -0700 (PDT)
MIME-Version: 1.0
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org> <20210503203814.25487-1-ebiederm@xmission.com>
 <20210503203814.25487-10-ebiederm@xmission.com> <m1o8drfs1m.fsf@fess.ebiederm.org>
 <CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com> <m1lf8vb1w8.fsf@fess.ebiederm.org>
In-Reply-To: <m1lf8vb1w8.fsf@fess.ebiederm.org>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 May 2021 21:03:00 -0700
Message-ID: <CAMn1gO7+wMzHoGtp2t3=jJxRmPAGEbhnUDFLQQ0vFXZ2NP8stg@mail.gmail.com>
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are possible
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	sparclinux <sparclinux@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sjWwmwPL;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Mon, May 3, 2021 at 8:42 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Marco Elver <elver@google.com> writes:
>
> > On Mon, 3 May 2021 at 23:04, Eric W. Biederman <ebiederm@xmission.com> wrote:
> >> "Eric W. Beiderman" <ebiederm@xmission.com> writes:
> >> > From: "Eric W. Biederman" <ebiederm@xmission.com>
> >> >
> >> > The si_perf code really wants to add a u64 field.  This change enables
> >> > that by reorganizing the definition of siginfo_t, so that a 64bit
> >> > field can be added without increasing the alignment of other fields.
> >
> > If you can, it'd be good to have an explanation for this, because it's
> > not at all obvious -- some future archeologist will wonder how we ever
> > came up with this definition of siginfo...
> >
> > (I see the trick here is that before the union would have changed
> > alignment, introducing padding after the 3 ints -- but now because the
> > 3 ints are inside the union the union's padding no longer adds padding
> > for these ints.  Perhaps you can explain it better than I can. Also
> > see below.)
>
> Yes.  The big idea is adding a 64bit field into the second union
> in the _sigfault case will increase the alignment of that second
> union to 64bit.
>
> In the 64bit case the alignment is already 64bit so it is not an
> issue.
>
> In the 32bit case there are 3 ints followed by a pointer.  When the
> 64bit member is added the alignment of _segfault becomes 64bit.  That
> 64bit alignment after 3 ints changes the location of the 32bit pointer.
>
> By moving the 3 preceding ints into _segfault that does not happen.
>
>
>
> There remains one very subtle issue that I think isn't a problem
> but I would appreciate someone else double checking me.
>
>
> The old definition of siginfo_t on 32bit almost certainly had 32bit
> alignment.  With the addition of a 64bit member siginfo_t gains 64bit
> alignment.  This difference only matters if the 64bit field is accessed.
> Accessing a 64bit field with 32bit alignment will cause unaligned access
> exceptions on some (most?) architectures.
>
> For the 64bit field to be accessed the code needs to be recompiled with
> the new headers.  Which implies that when everything is recompiled
> siginfo_t will become 64bit aligned.
>
>
> So the change should be safe unless someone is casting something with
> 32bit alignment into siginfo_t.

How about if someone has a field of type siginfo_t as an element of a
struct? For example:

struct foo {
  int x;
  siginfo_t y;
};

With this change wouldn't the y field move from offset 4 to offset 8?

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7%2BwMzHoGtp2t3%3DjJxRmPAGEbhnUDFLQQ0vFXZ2NP8stg%40mail.gmail.com.
