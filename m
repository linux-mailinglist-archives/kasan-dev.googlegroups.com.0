Return-Path: <kasan-dev+bncBCMIZB7QWENRB2NEXWBAMGQEHFFWZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DA55533B298
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 13:26:18 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id j7sf18171512pfa.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 05:26:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615811177; cv=pass;
        d=google.com; s=arc-20160816;
        b=YX8T3tactyqrTQ72lQEE6N1lbCrPRr92gKp0CgZ/8WZsG1pR/0/UeQxEXytxRjlLfX
         QeRf6tIjXuZrt44JFxDelU2q8u2WLHIrNkGiLKm9JrcpLVWipqyfsnLUOeqkONqtdlVn
         jwdMTj0xZPbRcWsoNFD/yv0FrB+UC0kb2HKJ24+YvThcSdV9BlJrgUXo0JDWE6ucF9+p
         f1plcmarAXTnAkHBUsYObWy1eNTvr/pIETqAXn+xXAPt+MBx1gLIoFcwa1THXK84uH/3
         3fR02o6QVJO7Nj27Syu8y2T6DuV1ceqPZmm1OHHkguz3Ka9RSzNQQVX4oZDRNpW7q/43
         CKEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tl5dFmX1R2Owriztd+GDfk6UpTQGFuKfQXEk4QJN3kA=;
        b=AXDJSs13M6oQMseydYHfWnpW0jQv402+g0lVdsaYlV+u8mil9PRASFRtKR46PR26zu
         f7b9uFf9sQSaFTjtzUkFikSMFM2NBcxWM293kdXE4rNvHOZdu/xqFGITwzXXRiXzsCXu
         Pdy/xztdl9KlBeWjo5bLKyI0DwJq1DjdzMyMTwIoEI3JAS9ULVRCAzfaBwoHQrp5G7Tb
         tqqYjggfXy4ezzJbG29PPPXz56hkdkYcGgRLyTTORU7lc+We5HqLrF9DpLXJhkL83J04
         lCFoGgUO/N75SvgJ5wFtTHdMK+Q20UQfMaaZO3mJMts+AZbgi+ymBFmgBhrhaERDX9nb
         kA4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OjqnRoV5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tl5dFmX1R2Owriztd+GDfk6UpTQGFuKfQXEk4QJN3kA=;
        b=j062RAW4GBXs4+JN3uKSbc0cVcbJTjKG4qI6ySj4f+2P93mHKRXnIb1H6BzZJz70mo
         aK0oyv37yb0qflVKcWM0ZB5VwsrYpxFhgJQEJwsjy4RpqL03qRvQTlXztfAYU35Hxfwj
         9Rpn/N4Rr4TJDds9MRm1nETTCOgpGR8TQxCg4kecbu+uEgzDgxpQLo0Hagi6aycOWZqq
         8kG0CZcWky5Cxhz2inIY59OLcNu1kQ2LmCI9tRvR1C+rVsCSktPbhNtD76t1EL9w61oy
         S4Il/U08BNNc217ahGNL9OrrznqB6GID+ncGDEQttENeD/EPmIgOLQRXvjUW8bbVb1Zq
         La8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tl5dFmX1R2Owriztd+GDfk6UpTQGFuKfQXEk4QJN3kA=;
        b=KSPcfVvU8LQum9Od6UISz/RZ/V3V8/SHoZKHJTxsAO8SzSdDA3TjUKotpohrsJRUSd
         LlRptA23GlHvqiwQhG/w8JvY3JviAJ6RA/7JaDKjoXAOIdqnjfcfy7gK74XXY8LPm0DE
         kzBP/JuXCIhuZUQt11X/6Z4CfiSQTVhOZAjMWAS//wr5+nm1neyAyS6i3ukwcU4sgd5c
         qpJBnZ3/cmQ3XVf9fpRkrKVoeefesAJ3t1p7vnzpERiX6MEVncDGvhWSf7IuG1QAdgV9
         0vSWigCBEcRD/PBV24O04C9GjZy1R811tGAQEv6caVMv7ndb0AnWne2tgUjjpIbx49k2
         JGDA==
X-Gm-Message-State: AOAM532nd7V7lsDrT4bu+xjNq0qNEZKMinx6hhDRqVgeFznJLFraiz12
	9yZ5DTquffgDF6cMGHogAO0=
X-Google-Smtp-Source: ABdhPJwTsHld9fZvP+SVBh3bHd8eD6UIlOEoQR+AeYs+yyvvzfNfI2nBzX0T/JDxpFL5tApXgvxXMw==
X-Received: by 2002:aa7:9192:0:b029:202:cf06:dba3 with SMTP id x18-20020aa791920000b0290202cf06dba3mr10076889pfa.16.1615811177624;
        Mon, 15 Mar 2021 05:26:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb0b:: with SMTP id z11ls9517963pjt.2.canary-gmail;
 Mon, 15 Mar 2021 05:26:17 -0700 (PDT)
X-Received: by 2002:a17:90a:2b4a:: with SMTP id y10mr12812989pjc.143.1615811177172;
        Mon, 15 Mar 2021 05:26:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615811177; cv=none;
        d=google.com; s=arc-20160816;
        b=UIJoe3Ma7zM9SULS+1bVWjW9dV0SWkSh6HDhr//FFJR7dPM6o70lWhmFOYziQuow5p
         nvcCFbAG6tCu06wwsr/6Bx3QbobbzUSL1PDGWTt3TBj006b7DS8+/2izsISeEg7XmxbQ
         PuLopSkOdGjW1FfyCVRY5bwZFiHURe42MBoL5JELme1ZJuZhjLLfdQaI96Rxv7Oe/haE
         WTdDGxScWcpwahf+Tq2d+OAJkHad694tv4ESIcfuRApeUy2B84MUhOyCGGybVG9yeSld
         YYkrlqStgZXrhVO1hzwLhnH4stedtIUTlE7hCsUNUtnaIr13QlqhkXFx0EsLlqITfrCP
         +h5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jsGt/dwOV8D6F+fCE9EMCron0uUReKVhhqz5+NJRPXc=;
        b=j4Kan0AVxIyezS2TF/kOi+dPune4YQprgff9M+Qn6PMU3K83eMOLcCxLy87Uj/24BF
         bipSE6a22KhI7afI3RbOYAuG0FSpmu5TjvxUO/BP8NsdJ0UokpS5NtHWxC/eQVYi37w+
         dNoXJ4EeQ9/34/Oqy7dX/C79ZcfTrcZ6OgiZwNtD9i1vhauzR5u54gy7G/0Sf0/6YNqQ
         jthomCv7vx4997L6Bq0YSjNbZqoGwSOKECsVWFNG59yg67ivnREAkAyWdxrwiqK6nUjY
         +rHEY6e9oMF/QaSlXZ42cvc0xyP4l/9y/EIzZAAJjqXk/pG4yKnw9fwT5oNDQLmNXIXh
         0tKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OjqnRoV5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id r7si1604039pjp.3.2021.03.15.05.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 05:26:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id 130so31333879qkh.11
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 05:26:17 -0700 (PDT)
X-Received: by 2002:a37:46cf:: with SMTP id t198mr24843358qka.265.1615811176122;
 Mon, 15 Mar 2021 05:26:16 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000009c21de05ba6849e7@google.com> <CACT4Y+ZjVc+_fg+Ggx8zRWSGqzf4gmZcngBXLf_R4F-GKU4a9A@mail.gmail.com>
 <20210315120943.GB22897@arm.com>
In-Reply-To: <20210315120943.GB22897@arm.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Mar 2021 13:26:04 +0100
Message-ID: <CACT4Y+Z0gir1LFtf_Xa2XHnu-ws8nk6Na9CtXFs71k+YLtw0xw@mail.gmail.com>
Subject: Re: kernel BUG in memory_bm_free
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: syzbot <syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com>, 
	Len Brown <len.brown@intel.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-pm@vger.kernel.org, "Rafael J. Wysocki" <rjw@rjwysocki.net>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Pavel Machek <pavel@ucw.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OjqnRoV5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72a
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

On Mon, Mar 15, 2021 at 1:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Mar 15, 2021 at 08:08:06AM +0100, Dmitry Vyukov wrote:
> > On Wed, Feb 3, 2021 at 6:59 AM syzbot
> > <syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com> wrote:
> > > syzbot found the following issue on:
> > >
> > > HEAD commit:    3aaf0a27 Merge tag 'clang-format-for-linux-v5.11-rc7' of g..
> > > git tree:       upstream
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=17ef6108d00000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=10152c2ea16351e7
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=5ecbe63baca437585bd4
> > > userspace arch: arm64
> > >
> > > Unfortunately, I don't have any reproducer for this issue yet.
> > >
> > > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > > Reported-by: syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com
> >
> > The BUG is:
> > BUG_ON(!virt_addr_valid(addr));
> >
> > #syz fix: arm64: Do not pass tagged addresses to __is_lm_address()
>
> Does this mean that commit 91cb2c8b072e ("arm64: Do not pass tagged
> addresses to __is_lm_address()") fixes the regression? The patch was
> merged in -5.11-rc7 I think.

I hope so.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ0gir1LFtf_Xa2XHnu-ws8nk6Na9CtXFs71k%2BYLtw0xw%40mail.gmail.com.
