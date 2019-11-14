Return-Path: <kasan-dev+bncBCMIZB7QWENRBC5NWXXAKGQEQCSHSLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CED9FC76C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:28:45 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id r4sf4482516ioo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 05:28:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573738124; cv=pass;
        d=google.com; s=arc-20160816;
        b=RBrB10ndkdDtNdKhV/NQ95cWu6ivfaQ3KP/HQEm06BLPgB6wKyp4PbV2OHeI6v7E4g
         BuSlLX65hEmJZZxtHGKgD/nuQmo0VWWsugnSAl7+xrHe8GZJ1LQVojYQq0WJ9p6lD0dd
         gViImaxd/U89p/qisXhXkCoYqPiFjWDzbCfUKZcLiwzFFiwJe3QfA2rE5vYF5+kVg5ax
         K5pvc59/Dx9Uu7KMgTqluVY6hWXWJPLlF0GYYU5487SbkEKzHn+r2U8qlYG0KOaqEttU
         BCQl7T11NiXhykeoeOi2RUOZbyb7ilmeWfR9tNwesK/y5vIvnRLigBni9qgiIkGW4n3y
         bDKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6fpsxWcy52oY9rMCQKDi8BmruKuTnxsOSR6FQoLMxto=;
        b=ZJyP4l2CZBn1rvg/Yh0nMTXXLgfgY6c/j1F8JdGp/yy0mwTalJPBkyCUSObwDrnrl7
         aPl+//K9cUlH4jo9JSUkYMhBrEGQ/m9v/RJQDhGzE/ZbP2S2SoG+xYH7WQmcsTBTIROH
         LY36uw0ftJ/sz7YsPX0Bn6eZsqFS/tdakWvrshV/psv1oFt29XcHbfRhsIDlVYYak1pK
         gY/CLdcv0E4BJtP8BYiF8DKRLUcsQ+z7JWw5a1aaiZ211PyHJXgKy/FzoKIhfmeBzbCR
         WhjGnT/siU+y8AJ83dkT9zaq44fEE/1IZePg3o3OwSh+no1fC8WVZZQJdoYgSDSoqB5K
         MSCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZHQKAym;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6fpsxWcy52oY9rMCQKDi8BmruKuTnxsOSR6FQoLMxto=;
        b=RSFRDoEh7rKLpY9QU8m7YGkBG00bLh2AfMTWeLxTbp/dEQ6X2TA0lIEtVnTep7md9J
         /gxG7BBu613qsDoCjfgeTmJ/IMZkAGdb7CdZ0iEMS9GyqJLxQ0BrwG1OtWTm5IGgOVrJ
         b/dP2ZRut8KZAeqXuvPy1uS4QUTKJX0IYkA+X1WBLhpo223VaIv1nI572Z20+XE9wQqV
         VpLyw5U0T5ZPVmRSy4YvXKgT9z2QRhwNfNIoEb+SriHluSjvqNpAtROrxfS3Z1SNbA6n
         YPmC9tYcpuPSCeqhMUUAHAeu6QndTxQPKnER14gV0WzrZUnlXUSmXR9wMgnkdaIcumt1
         bjsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6fpsxWcy52oY9rMCQKDi8BmruKuTnxsOSR6FQoLMxto=;
        b=n66UNYRlaI+GcXWlhvIxJ3Vwcg4gymE1us0OJFhm2GuiQ0fthYt3u5DtCr8u7Z0iIZ
         ofqJdyiFK0QcJacn/a3qG7O6wWhmW52nDyGaYcNLgUJXfgm3DgJNM1gwfIPjIBS9vFqP
         c9Nkui5yWhnoZ4kINUt8eFr7VMuhlYyrHGOOSCI59YB3YhQNwv2AZZpGb+Qto1IaThWP
         VsQjj0mptq3nsIiQB62aL0cOFoLiayiEg/KARhENjStirpEZV2/JwNaY60CbbkfyMA8E
         QaN1l1b54RGIfBtdwJHmr2QmlpIJgAcueeTtjZ9Fa8ZB8PRnIMfsWRsXyivXwEZxH6R4
         Dfnw==
X-Gm-Message-State: APjAAAUSKf5KHpi7iBjc/VpA+Xv+QXFfKWKqjB0sYclnwiDGp7JiExPl
	idYmzOxFqwfAvzCGeHKgdpo=
X-Google-Smtp-Source: APXvYqw93pKUb0HW26voU5y82vSmrs5z07LUrGG/YlHqOo8nM5OCCqEfGEdfnBG9+g7X2vWTMTMxTQ==
X-Received: by 2002:a92:2451:: with SMTP id k78mr10274098ilk.300.1573738124023;
        Thu, 14 Nov 2019 05:28:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:76b:: with SMTP id y11ls446725jad.0.gmail; Thu, 14
 Nov 2019 05:28:43 -0800 (PST)
X-Received: by 2002:a02:7347:: with SMTP id a7mr8031479jae.80.1573738123648;
        Thu, 14 Nov 2019 05:28:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573738123; cv=none;
        d=google.com; s=arc-20160816;
        b=s4HJ5dAWAp8Tdp27pSDyPwgRQmUE1+8UuVHfDu5qHn/7421vpGN+SDhZ3Jk4on1bIu
         dvSUV6uGNfIltPrgEB5dw515l5NcV64p4O2uv+oyHf9PBd4SnvlRRzMQd+eYAL5xidu9
         6/gkWMss7KAGxwZnGrtZWQcYzauz3WoscVFReS+m/kD2A2tvQmddxSH/VIPaJBk/ZGnu
         rGogQ59lBOqmZe8O6vCMVdXByhecXY6Vo0cr3usQPF+wXYvWYTWOxFIF0cWXcSL+5SkF
         lqFHY8TvQpanA7QI7shR1+kZbYqWbKKK6wpKWC8bvR6/bHEQQsEIMB+1UyhMnP9Qc0Hh
         +7WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/mZVNsrrdQrSd4f+jtZYtmpcQwpVbpvj9DqjgXeIhMg=;
        b=Ql5fDY4YzuQ1TkJbECdOkvr/u6pxa9xfU56G+5W1bcM11ngyJkNE5XN5HplS+wbggI
         L6PnabY0oRGiDXoeM0OrbdAV32MgDg4T8cYW9bawCifQzDj10g+pkhvY/0z3VOsIWuuo
         LreDWwlrzo58gkA1LKO8lMgzk+y83rGkVmO6sW5qch0jMPglyEMNkFlZUMAW5ZjrYtcn
         zBkJwDqaWvudBptf43yhzQSMrOC/8LkkVRP1k2KOgAcWmoN9kjlm5Wb9uZcrQ6MiqZdP
         R1tsO0B79KQA6TkS/VfoXCbLQVE3c6z4SGxqFyo/P0vqLB6QYKskyOSggruirhtZweqe
         rtiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PZHQKAym;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id j74si319780ilf.0.2019.11.14.05.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 05:28:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id h15so4897097qka.13
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 05:28:43 -0800 (PST)
X-Received: by 2002:a37:a94b:: with SMTP id s72mr7388312qke.256.1573738122547;
 Thu, 14 Nov 2019 05:28:42 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
 <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com> <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
In-Reply-To: <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 14:28:30 +0100
Message-ID: <CACT4Y+YnaFf+PmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Arnd Bergmann <arnd@arndb.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	Stephen Boyd <sboyd@kernel.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PZHQKAym;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Thu, Nov 14, 2019 at 2:22 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Thu, Nov 14, 2019 at 1:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > > >
> > > > On Thu, 14 Nov 2019, syzbot wrote:
> > > >
> > > > From the full console output:
>
> > >
> > > Urgently need +Jann's patch to better explain these things!
> >
> > +Arnd, this does not look right:
> >
> > commit adde74306a4b05c04dc51f31a08240faf6e97aa9
> > Author: Arnd Bergmann <arnd@arndb.de>
> > Date:   Wed Aug 15 20:04:11 2018 +0200
> >
> >     y2038: time: avoid timespec usage in settimeofday()
> > ...
> >
> > -               if (!timeval_valid(&user_tv))
> > +               if (tv->tv_usec > USEC_PER_SEC)
> >                         return -EINVAL;
>
> Thanks for the report!
>
> I was checking the wrong variable, fixed now,
> should push it out to my y2038 branch in a bit.
>
>       Arnd


This part from the original reporter was lost along the way:

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com

https://github.com/google/syzkaller/blob/master/docs/syzbot.md#rebuilt-treesamended-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYnaFf%2BPmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw%40mail.gmail.com.
