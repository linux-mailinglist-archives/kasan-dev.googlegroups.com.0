Return-Path: <kasan-dev+bncBCQJP74GSUDRBCNUVOJAMGQEBGH5SFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47E6B4F13F4
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Apr 2022 13:44:11 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id cv23-20020a17090afd1700b001ca8b9ec493sf2087042pjb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Apr 2022 04:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649072650; cv=pass;
        d=google.com; s=arc-20160816;
        b=RFBi8dK9U2MvBM7KycssnIX1rEjCtBpnHY3uq5W7UPecISSmZ58OSAyJ+no6PKSK8W
         EUpF7pI/GMfIva1hh2SsGVQN1clrR7VHJxeGTLJAb4i9aF2CtEZlaZhdepFzEJS3XXBD
         b9/V5t7a3g4hGZLoZmXTDDaD4dJXDGe0BrNtPYeMO4uoD0x4zeGn6amrSba2CY1kbdz5
         4dgedDpUi45+eqZ/IIzX0pVM7JW82+I37hpvRz0Vf/IeXs29NgyoZnMp0MlI8TRM6Vc4
         d/xKT3PddNb/KRcnVBGtY5WhnHBI53a0GnEbViMFo5d2QGfmAdKRWg/WO6PzuRStqve2
         MgTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=VJ/Wjh3iODMdX0VUhG+m6QSmehpBUz/K5GZvpDYqLdY=;
        b=QAJ00ZMbRuWYKqSYyf1kl1236EaILze5wsTrktiAKEOYnS+xC2u5iyvL+FtukXak3c
         lt/UyhdAR1DcNprPDjBeWdXugO66FbSB+OmdiGBb1KyMG/ulJfYsoczxjCwGMWbwnLrq
         2uu+hDhkY2eRdfVsx8D9lfoStbbbjCeqhMgOURr1uwM8e+ZnhihDOUwtcqLyP7oXv5lV
         TiKEyLKb1xcJTLjXUaJxSzm0pq0Y8yc1SsPuFoDI/yWxH+gAMkf0pRuGVFB5wDCcGHTO
         aL2r3UvpnZu5HvId71jiHQSNqga/wKpxnkXU2GUl+GdfpMgqD8auIExlg/Cts767GPsl
         tAWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJ/Wjh3iODMdX0VUhG+m6QSmehpBUz/K5GZvpDYqLdY=;
        b=KTq0axXLso5K/jDa+q658pQYNeMC2MQgif1rcaMzS7IoHeuzJ5aLkppCttijEyZQPQ
         B9HbKK3dvbZQGtqWCA1k8so7LtlEt1XmV7zkNiYuI87c1PecJImeyvVTVUNkAWRvS8oy
         WBMw3ukovaokaH9MulGpf+XBnod5Ozn6xqUaiu5cC0CATCeHrrdNREGRiYp/h3Al6z4b
         /docHXE704+jNa7y7GWXJHtrABWCeVRXZFE7kl3SCBvqO8sR6Ykf4COMH4WuzanskwDa
         idw7Lzcn4XCKQfe7o73j/dzYJ+AuBvn8KY+UQVMBanUdzRjgm5qsPwJDfAm3O1Pkh0uS
         HZbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VJ/Wjh3iODMdX0VUhG+m6QSmehpBUz/K5GZvpDYqLdY=;
        b=QYP8DtnGI9GlVsOXP2TJ9tnys15WwQnDrF56K1/0qHSM5ms7mUn7wyIC/8fSjPG7ge
         O6FcFYWry64IModIqEzY1XvdJETIytDfyc9b6G6PmN55ZBXPBEtdW185AqKGB2pewEhm
         ycWlOEz2LCb7Y6GXeFAsUE8mBMj0Hmbsb+ZhP3vWVMbbNI7EuuxTG7Xm1GxS4jokWrQW
         1CjFhz80LxhO+IpIikfXyg1K9NHHH22ADzb95ZG2PTRHgmIWT7qApT7g3mNbghdLVyyp
         tiEmhhR16Axk8lPyaJ6N98PghnO7nkyV+CJzNfK92EPCzSL6aNokLxThs1f1GArBo27J
         qYuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jNGFbb4brhRU3ibwsD91CyVHuaZbl2XesVgkz+HnHQVg+bCFm
	4Y5v1XEexeph2S6jSTDl05g=
X-Google-Smtp-Source: ABdhPJzJLwFr4LXbOpCZHXRCZuO7Y3Dv5f6PYgx+POKOknEFLAoS8FLXO73mY4jZwb4voLnbG+CfxQ==
X-Received: by 2002:a17:902:bc86:b0:151:ec83:4a8b with SMTP id bb6-20020a170902bc8600b00151ec834a8bmr22276285plb.69.1649072649713;
        Mon, 04 Apr 2022 04:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:24d0:b0:4fb:11a0:408a with SMTP id
 d16-20020a056a0024d000b004fb11a0408als5991563pfv.7.gmail; Mon, 04 Apr 2022
 04:44:08 -0700 (PDT)
X-Received: by 2002:a65:53cc:0:b0:382:8506:f1a6 with SMTP id z12-20020a6553cc000000b003828506f1a6mr25599437pgr.44.1649072648866;
        Mon, 04 Apr 2022 04:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649072648; cv=none;
        d=google.com; s=arc-20160816;
        b=R0wB0O2N9hbmV0NZ4s/wSUYLNGqJlo4s/SlS2RFdvgRFamk5pVPZvs8HS/Mf4EPdND
         yL11ptT2R2AVwCGn3WMZ/BRZPEaV5rmN2EY5sVVs16fqN5dRxgIXIa9EsJQWrOEhLq41
         IHV3jCrJ25noy4X6riZFDeODon3CJVi/BuaT+P3wv+B+GbXaRI/OJ7RdKYe4JwRVPM/N
         4MSyXAQ9opexB9GEQpfU0rbnMBXdbEuNsFckZLeZR1ylOeF0NtP9sT34EnOAmW774ctE
         0GtjoDaPTGMqw/4VlzfS/b+qlrzLyy7NKOI/V9PKilN5q4gAP4pSnPzZhDDrp7GDycRT
         LBVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=nYvQ/9sOxTrqd5FO05k5YTA5C/LjNCLjagWPfQG2994=;
        b=f+JGFpdAL/qYyYqo06M2S+7GJWumr0gDuTnX81hXgJF+whv5mIBHFgSorhCooZ+mMp
         OxTZ+mKNOOMcKgELWxL5SzI6mkH20XH8Ab+JblrrPJAHJOxUtnoobHQRcjNaQFKNRtkc
         YYZrpwgoCYzKBQ0uE7SGZ1lEehodDWUx+oc7oNN80+2sOo9xnQoeg/t41UqZ7otguyZM
         DbLhdcHes2WkL1mDWiMcKMJj1lqgHX6bioC7MvYKorAOtt2lzSCJgeOGD7MYzpCtKhSf
         uOHwsW+zP3aE7sIVm3JYaBo+5PU9N+9FTQ92stkzW6hZj3wei7jp3OTfd64xiO+7Cs9c
         tzLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qt1-f182.google.com (mail-qt1-f182.google.com. [209.85.160.182])
        by gmr-mx.google.com with ESMTPS id z15-20020a056a001d8f00b004fdca03b476si330617pfw.6.2022.04.04.04.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Apr 2022 04:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.182 as permitted sender) client-ip=209.85.160.182;
Received: by mail-qt1-f182.google.com with SMTP id z19so7419974qtw.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Apr 2022 04:44:08 -0700 (PDT)
X-Received: by 2002:a05:622a:1386:b0:2e1:e812:f4c with SMTP id o6-20020a05622a138600b002e1e8120f4cmr16614255qtk.653.1649072647003;
        Mon, 04 Apr 2022 04:44:07 -0700 (PDT)
Received: from mail-yw1-f181.google.com (mail-yw1-f181.google.com. [209.85.128.181])
        by smtp.gmail.com with ESMTPSA id 64-20020a370343000000b0067b31f32693sm6319822qkd.109.2022.04.04.04.44.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Apr 2022 04:44:06 -0700 (PDT)
Received: by mail-yw1-f181.google.com with SMTP id 00721157ae682-2eb57fd3f56so31619257b3.8
        for <kasan-dev@googlegroups.com>; Mon, 04 Apr 2022 04:44:05 -0700 (PDT)
X-Received: by 2002:a81:618b:0:b0:2db:d952:8a39 with SMTP id
 v133-20020a81618b000000b002dbd9528a39mr22035506ywb.132.1649072645615; Mon, 04
 Apr 2022 04:44:05 -0700 (PDT)
MIME-Version: 1.0
References: <20220404111204.935357-1-elver@google.com>
In-Reply-To: <20220404111204.935357-1-elver@google.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Mon, 4 Apr 2022 13:43:54 +0200
X-Gmail-Original-Message-ID: <CAMuHMdURqaCYDt5SJg0GLKqEs92JgUhHAhVa8B4RKextRH43aQ@mail.gmail.com>
Message-ID: <CAMuHMdURqaCYDt5SJg0GLKqEs92JgUhHAhVa8B4RKextRH43aQ@mail.gmail.com>
Subject: Re: [PATCH] signal: Deliver SIGTRAP on perf event asynchronously if blocked
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, sparclinux <sparclinux@vger.kernel.org>, 
	Linux-Arch <linux-arch@vger.kernel.org>, linux-perf-users@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.182
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Mon, Apr 4, 2022 at 1:30 PM Marco Elver <elver@google.com> wrote:
> With SIGTRAP on perf events, we have encountered termination of
> processes due to user space attempting to block delivery of SIGTRAP.
> Consider this case:
>
>     <set up SIGTRAP on a perf event>
>     ...
>     sigset_t s;
>     sigemptyset(&s);
>     sigaddset(&s, SIGTRAP | <and others>);
>     sigprocmask(SIG_BLOCK, &s, ...);
>     ...
>     <perf event triggers>
>
> When the perf event triggers, while SIGTRAP is blocked, force_sig_perf()
> will force the signal, but revert back to the default handler, thus
> terminating the task.
>
> This makes sense for error conditions, but not so much for explicitly
> requested monitoring. However, the expectation is still that signals
> generated by perf events are synchronous, which will no longer be the
> case if the signal is blocked and delivered later.
>
> To give user space the ability to clearly distinguish synchronous from
> asynchronous signals, introduce siginfo_t::si_perf_flags and
> TRAP_PERF_FLAG_ASYNC (opted for flags in case more binary information is
> required in future).
>
> The resolution to the problem is then to (a) no longer force the signal
> (avoiding the terminations), but (b) tell user space via si_perf_flags
> if the signal was synchronous or not, so that such signals can be
> handled differently (e.g. let user space decide to ignore or consider
> the data imprecise).
>
> The alternative of making the kernel ignore SIGTRAP on perf events if
> the signal is blocked may work for some usecases, but likely causes
> issues in others that then have to revert back to interception of
> sigprocmask() (which we want to avoid). [ A concrete example: when using
> breakpoint perf events to track data-flow, in a region of code where
> signals are blocked, data-flow can no longer be tracked accurately.
> When a relevant asynchronous signal is received after unblocking the
> signal, the data-flow tracking logic needs to know its state is
> imprecise. ]
>
> Link: https://lore.kernel.org/all/Yjmn%2FkVblV3TdoAq@elver.google.com/
> Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
> Reported-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

>  arch/m68k/kernel/signal.c          |  1 +

Acked-by: Geert Uytterhoeven <geert@linux-m68k.org>

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdURqaCYDt5SJg0GLKqEs92JgUhHAhVa8B4RKextRH43aQ%40mail.gmail.com.
