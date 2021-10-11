Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSV4R6FQMGQEZJXUMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 03E5F428704
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:48:44 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id i14-20020a63d44e000000b002955652e9desf6453954pgj.16
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 23:48:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633934922; cv=pass;
        d=google.com; s=arc-20160816;
        b=jwXkIWgnPxsvJEoVQsQ3nKi1198Qruil8NKaBhqVWGA5IVURzts85C1Y42kJXH9PVQ
         zBxrs29J5HdES1NMpwg4vvw1SViBp2TLNv777t1ZyNIWD1p6rOGcjTZ70Ye7BciPQH4o
         cFtJu/SugnNCroh6v++QXRa2KQAg+/I9QmuAnlsI+ramUp//FvvZm+EKW2X9E5Erq+wN
         ZDZLeII7AKbMr9GfAEi2EYQfemdqDM1LTbVerHnouZdnVznKxHK9YHj5oTqJik+Kw67d
         qoW6t15PPvAR9HeOrKtpAg853ECLedd2tdJy3a224vz97fDwzOTT22Z/Si2Kqxx6tWZv
         diug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WRDiRJn8il9y7S4eljzbKnJcwpvKAhASGZ8mnI6iuXk=;
        b=x/pD2SGyu6STu3hJZUYqjMAQNFl1lM15WjrX6t0q87ENXHiTx0cU24T3UJJeWRlLs1
         01Sn4+8Vu2SrdSoHtYFXv2Nnhfo34t9dP1uJ87FBxynmI46E16wgVKFEfTgqkfnO08VI
         7XQgHvtX05ZQJMqLJOgN69snOpnUC+9Wg9rAkjoC9dKsX9/wHpGV+khCMG/Od4FJ36o0
         Gs5Gt4z5HhubDWzl2GQaJosMgoHfuCfnSVboL8XHHBtv1sQgL1wJy6MimrErdntSI7qf
         TIsarWVL1ztMTnDPIifxtFuRsbXsdg0Au7h2+R+bswMi1tF7UPbfFLZ+QCIK3/gbZnMg
         suAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=egUQGdXV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRDiRJn8il9y7S4eljzbKnJcwpvKAhASGZ8mnI6iuXk=;
        b=gXk/LnHeaAaUglMBa6EuPA6EHF5ATtLU5ZUzwUMJPFn6UfaqN7XxQ0KxI9Akn7CpDy
         7LwrwHgk16PXgmlnJV0zOBSk/argOxRdN8dzoL5ljxup1NQueuxoiXRw4Q+0qf3C+Xtg
         wRNjKZ8WN9fidn0HDmL35zRhgMTeDxXt3l10sOm4FgxytAyxgTOgqWMxuHGXepNBYXVk
         WT13X28QHO5u2J+lGU8foeuBmi1wD5antv2w0oaL+4ZHV0FrLc2s6SI1keRRgPbvqXdx
         376pyX4XxJ5NMevmQZdqCK2tOagW6fq8f4BcWLJg8rJnaE4HAKkIbeSQST/b0h/VB2Iv
         pJJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRDiRJn8il9y7S4eljzbKnJcwpvKAhASGZ8mnI6iuXk=;
        b=QqmBJHblB2RluHPRl5uMNUQfFnm7WhvzvCPJ4RiubWEj5Ob197co0efJqIEC1xN1pd
         PAwxbV7a0ubKeL6ZuXIiLRjjzhoGEJlESTR7alVByKbOVS2PQwQM8c5XWSUfXtsMpu02
         PvU75wL66O6jKeYEJi1KKxdQz75XrnjzIYWse3O6xxA5w7Pcvzyc4/isC8gVa4WZ86Or
         6rkrt636EWiH4frag3Eqs5ZQYjgzcEZaQb/s5tZEuFmn9KA0+1PxwdEpQv+pI3b1re54
         FE4TaulhTHhai9yAIRZAUxJPFjCz/Qcbz1GETSPvJhNuGdmTIba0Aq+n8OxG3kbYA0Sq
         pWig==
X-Gm-Message-State: AOAM531c39Bki+beEppyAojqPrl7c0Q/0ci/HEqxiaq5QQZTQLufHAe1
	xWk5/uQWmjibEjGOgiFJz04=
X-Google-Smtp-Source: ABdhPJwvh0O7Z/iZgjRTwFLflTpEc6nwmGfTn/53vzBgQaz/9gvnsqVIfigbfLJ4YXOV2BeUG/A45Q==
X-Received: by 2002:a17:90a:6583:: with SMTP id k3mr28938132pjj.147.1633934922664;
        Sun, 10 Oct 2021 23:48:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:858a:: with SMTP id w10ls3836032pfn.7.gmail; Sun, 10 Oct
 2021 23:48:42 -0700 (PDT)
X-Received: by 2002:aa7:914d:0:b0:44c:61e3:99b9 with SMTP id 13-20020aa7914d000000b0044c61e399b9mr24260861pfi.65.1633934922070;
        Sun, 10 Oct 2021 23:48:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633934922; cv=none;
        d=google.com; s=arc-20160816;
        b=Uy/u/COeOWpm0XsnnwBIpmBUGPhyERfsp7s453JHwjlEGw6RHlCoSbcKx1qh950/Dm
         rA2BmubM2ydZfdqOjEJUbSXpaz8L4K0RlsTF0AQ8wTnuelXoNo3l63SvFmSt/KRLABiX
         etiPytHpgqbnD9GsDPdd8rzHO6LaIfBy6r4AoReS6QF2YqKp0OqHRU4JN4Gce9P6LwpU
         eX11PwoFmMh1/R9vlqh6pqBIrQP34dcfZhk3ZhABqPPRJov1brvMZuGyNkG49P05HSVr
         sO0DmVDiCsIATcHQOFVwc8qQx8Id2e5Qz1x1B9Gcjjh+Oc/GXoehX/sadVP8dSEji/Ar
         Cr0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rg9FMIgGuiU1OB4eISCi95IByOPH0nsu1EJ0FkL+Lgk=;
        b=o8mDdNwaKMGzVnpyP5SpFjpBf8PsuvELbOgKdhATmVWeM+BHio/fs5h4j1KQnvmvaW
         b+8vTGU36B67uNIH0eeG3cZFIxBtoxMOUeNZpjnF9QvWIWnWicZ5rCEK4sinM356MMTL
         wpvvpb/X8+DIG/LcRGhGCZt4BH2OGfyhS699Xh90pqKq7h88ssvdpS3q6NY7Y7l3daIQ
         tZhXrUktypu8cIEagEkY3hMuulM1/XaWhffuMncRw7MvI7DjCeP6R+ai4omOLQ7v4iPU
         3FfAiTdmVDvVLfUTiJ4sRVmo0BsDazvJh7XT1LR6aVeQqZd+jKCmHKFK7XfGUpFukZDv
         iE/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=egUQGdXV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc35.google.com (mail-oo1-xc35.google.com. [2607:f8b0:4864:20::c35])
        by gmr-mx.google.com with ESMTPS id j12si255863pgk.2.2021.10.10.23.48.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Oct 2021 23:48:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as permitted sender) client-ip=2607:f8b0:4864:20::c35;
Received: by mail-oo1-xc35.google.com with SMTP id r1-20020a4a9641000000b002b6b55007bfso2910261ooi.3
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 23:48:42 -0700 (PDT)
X-Received: by 2002:a4a:d54c:: with SMTP id q12mr17516865oos.25.1633934921227;
 Sun, 10 Oct 2021 23:48:41 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop> <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
In-Reply-To: <YWPaZSX4WyOwilW+@arighi-desktop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 08:48:29 +0200
Message-ID: <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=egUQGdXV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c35 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 11 Oct 2021 at 08:32, Andrea Righi <andrea.righi@canonical.com> wrote:
> On Mon, Oct 11, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> > On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > > I can systematically reproduce the following soft lockup w/ the latest
> > > 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I've
> > > tested so far).
> > >
> > > I've found this issue by running systemd autopkgtest (I'm using the
> > > latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen with
> > > any recent version of systemd).
> > >
> > > I'm running this test inside a local KVM instance and apparently systemd
> > > is starting up its own KVM instances to run its tests, so the context is
> > > a nested KVM scenario (even if I don't think the nested KVM part really
> > > matters).
> > >
> > > Here's the oops:
> > >
> > > [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [udevadm:333]
> > > [   36.466565] Modules linked in: btrfs blake2b_generic zstd_compress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> > > [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
> > > [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
> > [...]
> > >
> > > If I disable CONFIG_KFENCE the soft lockup doesn't happen and systemd
> > > autotest completes just fine.
> > >
> > > We've decided to disable KFENCE in the latest Ubuntu Impish kernel
> > > (5.13) for now, because of this issue, but I'm still investigating
> > > trying to better understand the problem.
> > >
> > > Any hint / suggestion?
> >
> > Can you confirm this is not a QEMU TCG instance? There's been a known
> > issue with it: https://bugs.launchpad.net/qemu/+bug/1920934
>
> It looks like systemd is running qemu-system-x86 without any "accel"
> options, so IIUC the instance shouldn't use TCG. Is this a correct
> assumption or is there a better way to check?

AFAIK, the default is TCG if nothing else is requested. What was the
command line?

> > One thing that I've been wondering is, if we can make
> > CONFIG_KFENCE_STATIC_KEYS=n the default, because the static keys
> > approach is becoming more trouble than it's worth. It requires us to
> > re-benchmark the defaults. If you're thinking of turning KFENCE on by
> > default (i.e. CONFIG_KFENCE_SAMPLE_INTERVAL non-zero), you could make
> > this decision for Ubuntu with whatever sample interval you choose.
> > We've found that for large deployments 500ms or above is more than
> > adequate.
>
> Another thing that I forgot to mention is that with
> CONFIG_KFENCE_STATIC_KEYS=n the soft lockup doesn't seem to happen.

Thanks for confirming.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMFFFa%3D6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w%40mail.gmail.com.
