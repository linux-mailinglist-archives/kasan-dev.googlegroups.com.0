Return-Path: <kasan-dev+bncBCMIZB7QWENRBIP7XH6AKGQEAKOB6NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E3EB0293497
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 08:11:46 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id l8sf676380ots.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 23:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603174306; cv=pass;
        d=google.com; s=arc-20160816;
        b=GQxLxZ0deTsfYIbD/e3x+rl4Vl6DcAijm9lFzgwUJNgzNzC1BbZdkGNhX0sWrJfiSF
         UCU1CFu7ybXtyC/orwXfJbD+j74YLtfAv/v4y2sXh1jWUwF72Yj8kQF6wctSSXWbkvgB
         P59d4geX9c1nbKKNEp6PZPJ7KjnNNSPxzQKBU9ihSEqRqX++6GWOfsVsC4Rt1MukgQ9j
         lJmVv7KOLEbXAqXgawJG/xsdI03wUnGVwDa8FS+jm7JGfdou77Cm6BgW8HhSV+lLQKqV
         tyc7uNChis+L/lzvHoxITXZkYvX2pUw9+rS33RtrOAkbh+AlZTyL01N+IMLnISDeTCFB
         Rt+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wYx6iCpLww/1WxKwXZyLgmD9+LJgHKK14RE3VQWp0OM=;
        b=qTA6rgHfAR+zNuA8YkShD9xvqmBu+aXUb8Sj2SiwCB1Didebf7x/xR+NikkhvvYQ1I
         /8zDaVcD2kV8hBSK0uq9VkmWv9yRu6hjf0Dhm1uHHCBCRhF+teuSY9Ho3NksBSiHCem1
         qDS5LcmX/+U8itH9efXs+ZKGfcPrUDUCK1nQRnzoCxw1IylP9r1/B+LJulX0UyW7Vhsf
         JytXhrmS2n6GUi6gjdFWKrJfJQlJgjZ4n8FM2HDIiCtlKcP5MVy6ltVbGNTp0HjfMlRJ
         uqpl1xGHNykj2iKPUSKwfjPGebzyX0jq0DohRiFOy+O4qrcMYLomm1kRgdoY4YP/837V
         V5Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYn6LV5O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYx6iCpLww/1WxKwXZyLgmD9+LJgHKK14RE3VQWp0OM=;
        b=S6NA/+8HjniBgyBcARtkJROHAVNMUShlFe/c3NI9IRgfsCCa1mAyY+eo99Sj0Ucd6H
         ozkEnVTcx8LNqRfBevTSaQDSZV94I5QyFlvI8koLB1j1lfnW1RNENfUuQhcZocWmiGQ0
         0oFSC2Clct9q1ppJtgqzK0w45k5PjXxLz2pFMDrj6IjlNmFVSz6mPapcEgOBHOV1OoAr
         NEWDiKrPYU4f7hY1RrdqVAXKIt8EOJNlZVwQvoFnVqt8Oaf6BBugDmYwMqo3duxiOkPJ
         FjXcmVNHaU2qqvHfxQVSjBsXxYPk9zo4dV0FyBL4Na1FOObFXC3AakfQB4oJ5i/8GqHn
         xYVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wYx6iCpLww/1WxKwXZyLgmD9+LJgHKK14RE3VQWp0OM=;
        b=AXerloiDQKtGvwmjycj4eG0m5ZHF2mbDVHd8JzHFjVtIi6apQWBS5dBeJ+TSMrqz5H
         qqkm72/UmcDDave9w3zUydUpwpScqJjjPwfEoJOZxScO6sf0wXTD6C2YTIn/rm0jjuog
         87KGNnoEbsbujiz8NvB/qHl2Xi6RqF4+ZeqeObwvH/Et2TaivPvLgFWGsyV6OhW4FE2t
         YgcQtV+h8BNChTEDzhWtley3OpoYeXuREoUTrP56nZpjjDZ5dTWO/w4zcNxriZ+JPpk3
         jLVCiXLZ0+fiZ6GEBkGYCCHM/PQf7N4VEbYWwwQCbVazsoX/dphbu2wQdhObPVTxPV/Y
         /x3w==
X-Gm-Message-State: AOAM533hsooKys4VzEiMI1tG7cdAsK6aPWC2Zmpa8f8aq4uBWRikLrSD
	sIVIY+flS8be5oSoSusPb3w=
X-Google-Smtp-Source: ABdhPJzcoirZJ9Kq3qvJeW88gAQ1qo1mrAjbjDbvBUdRGF3LY0lBDjLCtsf8jeUS262ntBnI01w4qw==
X-Received: by 2002:a05:6830:31a8:: with SMTP id q8mr692298ots.15.1603174305722;
        Mon, 19 Oct 2020 23:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:c1:: with SMTP id t1ls201356oic.7.gmail; Mon, 19
 Oct 2020 23:11:45 -0700 (PDT)
X-Received: by 2002:aca:1114:: with SMTP id 20mr850482oir.5.1603174305413;
        Mon, 19 Oct 2020 23:11:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603174305; cv=none;
        d=google.com; s=arc-20160816;
        b=W9Lf89dWthKQdpvn4CsTIjvNInkD5osA3McwhvDzHSXFCO5HNwjJStyshJO1Z2fhQ5
         fsWTMdkst8EY6ZWPtL+dmiece3VCzJoQcxSLfXDaMh8LWfMb4WPvopzzas3h2r2YExRd
         rxHQf/Hwc1Y0wNSU7Sjl2RPHT82bynzynIDIrNp6RgZVFKfEHhVO2qCbKC/x6VhoazM1
         8jOOiioGPuSRk1mC3bGxJ8MGeszN86rf1J/+nfp4SJOVzJNZYCuiXbh/STyQmOtSZYSi
         3v6fYNy9UI43MqFYtc4u0lkD+D/tlaM8o+i5bToExsfFfExwGHkNN21dF72SvT42MAhK
         blRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=44p3wi2to3ENYlxeXsgHcd8F8hXNCHcnGVpzkuLoxi4=;
        b=Zt8DjhmEZV9uekW2pbPBbtXTc5y6UboEKGrHhSfDX8hxnvkRS0bGpR/4Ypu0FTeM19
         HEN8jTbwfdBjgftNmzCGe9VuLn/UculbrlOQvquhky7Kr0NWXpgldwkvNAjmpG0PS4RA
         s+jD90f7o6t83VdV63/zAgkgVr1B947qthvnMcMkr5Ju6tMVxS/XVYaqjiJZ3sA2rHLQ
         NLrC+g2fKYULSFqYugxdxxfyBimj//aRiU8OTYN3s7KBqcRFIWGZINoP11dNpV9jIozN
         nya4C1qj38wzBrtFeeZ2uPyx5ISYXVkeAIc4WWiwAfQ87VuukQnE3vMgLji/JQGDqI2O
         hHUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYn6LV5O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id t11si63589oij.2.2020.10.19.23.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 23:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id j62so388465qtd.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 23:11:45 -0700 (PDT)
X-Received: by 2002:a05:622a:9:: with SMTP id x9mr1114273qtw.43.1603174304665;
 Mon, 19 Oct 2020 23:11:44 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000005f0b605af42ab4e@google.com> <000000000000f098f005b20ced50@google.com>
In-Reply-To: <000000000000f098f005b20ced50@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Oct 2020 08:11:33 +0200
Message-ID: <CACT4Y+bXyW8++nEZJXjYoKon8a_3kzXArYHJ1MPomZRXRUddfA@mail.gmail.com>
Subject: Re: KASAN: unknown-crash Read in do_exit
To: syzbot <syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Christian Brauner <christian@brauner.io>, 
	Dan Carpenter <dan.carpenter@oracle.com>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	George Kennedy <george.kennedy@oracle.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Eric Sandeen <sandeen@sandeen.net>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BYn6LV5O;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Mon, Oct 19, 2020 at 11:38 PM syzbot
<syzbot+d9ae84069cff753e94bf@syzkaller.appspotmail.com> wrote:
>
> syzbot suspects this issue was fixed by commit:
>
> commit a49145acfb975d921464b84fe00279f99827d816
> Author: George Kennedy <george.kennedy@oracle.com>
> Date:   Tue Jul 7 19:26:03 2020 +0000
>
>     fbmem: add margin check to fb_check_caps()
>
> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=17ce19c8500000
> start commit:   729e3d09 Merge tag 'ceph-for-5.9-rc5' of git://github.com/..
> git tree:       upstream
> kernel config:  https://syzkaller.appspot.com/x/.config?x=c61610091f4ca8c4
> dashboard link: https://syzkaller.appspot.com/bug?extid=d9ae84069cff753e94bf
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=10642545900000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=141f2bed900000
>
> If the result looks correct, please mark the issue as fixed by replying with:
>
> #syz fix: fbmem: add margin check to fb_check_caps()
>
> For information about bisection process see: https://goo.gl/tpsmEJ#bisection

Based on the reproducer it looks reasonable:

#syz fix: fbmem: add margin check to fb_check_caps()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbXyW8%2B%2BnEZJXjYoKon8a_3kzXArYHJ1MPomZRXRUddfA%40mail.gmail.com.
