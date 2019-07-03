Return-Path: <kasan-dev+bncBCAKHU6U2ENBB7U26PUAKGQEARJXIBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A3B05E80A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 17:45:02 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 21sf680845wmj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 08:45:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562168702; cv=pass;
        d=google.com; s=arc-20160816;
        b=RzepcuPbiWNfsRx1cF5kM/NowAJoQ4SRpe2qZE0Hsr7WE8K/JUPtVQlNtZPXhxj/y4
         qMgSZ2h6TVcbLWAZacPl0tH96Uf32MKomU+/DE3H13J1un3yNoKio0h2S34luJpbyruT
         d5csdY5Dnl2G5b2iemsG+C0pv9i0nkZpSYB4nYtmAW4TZ7XdBSBBNObupnJc7LrX6s0E
         ZrFtCCcLDmdknWfNNv5AXEZ3HBjUxG6/29Ffn+oS6R2a3jhNluPeJy67adP6841S/uJ1
         BaBJ7AbIBDHa8MwAkSc0HhMEdv3JY14WNpeR2rCX9Bl8A+i7Y4MKZsqTe0e9Xie+QsZZ
         ng6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=1WBkd9VJbfy0wC1dTGqt+0v3zmKOnKgVnwz6GBDhfzo=;
        b=WKQeFE8jQH+bzhV6cYIYZHcorO4hhk7VWk2f4AISaqWb4/UfMy3VOUzBFXzCorWJbS
         GHmo32mehzL68hlsYMt+lrpjfrObsUmDXXQLeJkN2X/KVc6oaTe6mTb5CHqRBrLrTd5e
         X8plPn0JtI5iQldPe4h6jnpBSM7fQqJFkKkSfYSpfLwVlNNYZgynQkLxjgeI6pGpedzK
         0s1QPEuTDxWF4LtaWKpYstHD4XeHpv/eMdrHRWbkVrB1Wjs8BBvMi2oGmNv5fbA86tub
         Zb2kc6Eijrc/9x9QENlBrW0cLA3pitIbTEJGj7L4SHyDvKrEB2v6oaQ6/gPRja+IcrXP
         GmNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gmFKCxY1;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1WBkd9VJbfy0wC1dTGqt+0v3zmKOnKgVnwz6GBDhfzo=;
        b=rrBLK80WYNGIY1SKCRsT3XgIVrFEwmWt1CKsYpVHbrAhGbJHNcSSJ3/MgaSsz9hm0a
         ti/Gn+yCDvfv4KgaGTvGsqo8QLkWnot0MlZq23+7kg/Cfkw4W/bbOc/SKkSeozpuQhnM
         3o7et7mIWExWvqIESVDRdtULnnrid7lldrDTOIC7JXgrFywYlBdh9hRlMRZ377WmMGYL
         NYfwH8mfUa9Q96mRSo19+LmDt3atCp3cr3SR8tK8FZ2K9zFeVRSKybe2N7ZjtAvzvF9W
         LaFaEiwSm/r2RiwT6QRRq4EIH5rYvu1aTg9Lpm6rF0qX/NDZIvAZM5nJgvq7efy8gS/B
         Ct0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1WBkd9VJbfy0wC1dTGqt+0v3zmKOnKgVnwz6GBDhfzo=;
        b=Bs77VxCayXwEH2v1NPvYGsI+ZiNlkm3wwKaBMRSvQhXyLjsjajerra9Ma4gPrin0+D
         hJC49nx2o/+nhSmQbrgVRY/ktbsgCJuXxBrJpF77JkZ9Z57Prvr1k+KMrbS1WaUOEbg/
         NgQiZRLDZarzVD4uB7mXEL1fFR9cCchl5RepGBWNyNv3pgyKfAb6NWkAmdJC6yklxc6m
         Bzc+3MZWLzJ1WA90idRDBS9PSWj7gxy0pArprXfo8YUoDrJcJVJVIH2zSYFvNTx4D1gC
         4G/lB2i2S+ff5jFiDHab7UvVkL2nfg1FAYjxSHmTNOvzTZorP6CAkAJJNZZELMDEQmaf
         1maw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1WBkd9VJbfy0wC1dTGqt+0v3zmKOnKgVnwz6GBDhfzo=;
        b=k3KvCnfb7PshX2wRsrNaAhIhZ4cVtyi0sD5ndLo2fSryaV5jJi1RnrHAt0jAab6clw
         9ouVoBwKFIP8D1hOUCkdtI+s1oDGCqEVjalof4nQ5NVyniAXsX116cuSf3VnD85GABYK
         677y1OJXRb7tyl4gtoEAcprJztfygCdLSpuCJrxTpBiLqM9rpb2vZsDhq1ko2u5LDJ5U
         PYTEAIDZY2AKixsaOHipHsO2wNu6L7twopP/muhSZWHli2+nHKbf41fEWdCeerdOj2Ac
         XmkcwWlCqvH5v6RMm4M94SYeEYAmA38Ae8YoVz5I3L/qnl8HxNFKy+G1GGd0b5XkSSaa
         3gmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOQgCpHOQSfDqcr74wK7vIp64mt/6f5Qd2iu/xd28FculpjIdE
	C/Johxhhc/Z6PyiZax2vKGw=
X-Google-Smtp-Source: APXvYqyoEyn+adPt7GBXSxHSI0B/aoU+LJ1KTbbax3PjQ/RSg6VdJrdHsTnhMv3hX1zA2PbFxJzP4Q==
X-Received: by 2002:a5d:474b:: with SMTP id o11mr2339041wrs.4.1562168702048;
        Wed, 03 Jul 2019 08:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:96cf:: with SMTP id y198ls844079wmd.5.canary-gmail; Wed,
 03 Jul 2019 08:45:01 -0700 (PDT)
X-Received: by 2002:a7b:cc09:: with SMTP id f9mr8921624wmh.68.1562168701508;
        Wed, 03 Jul 2019 08:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562168701; cv=none;
        d=google.com; s=arc-20160816;
        b=aZn2CvYRgzUmNXJMD5cR7bGC6cMb5ohaJawqVcYVnJniZwt3l1PZ2lsg2PQuX1lxQG
         QQZpKxgJL12Smt5NvdSzVNdzg2LX6KCbCVpHvWtHmivy4w333chDjnE1auwX5MDivZQ0
         E39Nvp369OtMPmxa0N+hLx0wNUI3FtaiNcBwTN0o9NKdUh55iQ3TUfwlQuitv6msQEpM
         6h6UrT8XI9Gr/9+YOiG9ZtjWfy3eSlgsLceEB4OG+VLT4OfkMZRj2+dDbYkEmp1Tj0Pz
         DbK56/Jot1TEtRGASzmASPYILfhvFpVp5l2dQ2YygkpgydpScvKPEfEQNPYJD4gzoFwY
         1AgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YHEPbnshpXHKTpPy68IGOJokxNwoulf7A3Gqon9WAXo=;
        b=0MSxqceQDv+XSm45gNqwERYlS5LtASmSnCY9n3X908KftRf3QMHzfgJEouRKIsDf8h
         dypG69nScIJpszkHxj2fTIyL1anTxRTT9ezQ2wxYgdpL6sJg2CCshD9MzkAjIS1uj6t2
         bOD0uP/U85DBrMeDr2chQjJ9vlT+2z//PE/fJPmJUVuK8pd3v91Jx4Tfc/vZ5oZpre7J
         iMcXmEeEAo7Nnilnl8B4KqeJimZxZ+AMOAPl6iqwsSdbdZR+Xtp74pbMSrtwv3Ad78DG
         57o2LrFeRQeLsyrlSGd9ijRaWOkCTaM75Bk7bNvG2Wv7eOaHcSL7p3oRNivrCEZbS8yi
         jOiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gmFKCxY1;
       spf=pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id t25si145295wmj.2.2019.07.03.08.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 08:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of anatol.pomozov@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id b11so2128380lfa.5
        for <kasan-dev@googlegroups.com>; Wed, 03 Jul 2019 08:45:01 -0700 (PDT)
X-Received: by 2002:a19:7616:: with SMTP id c22mr18845054lff.115.1562168700688;
 Wed, 03 Jul 2019 08:45:00 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
 <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com> <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com>
In-Reply-To: <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com>
From: Anatol Pomozov <anatol.pomozov@gmail.com>
Date: Wed, 3 Jul 2019 08:44:49 -0700
Message-ID: <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anatol.pomozov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gmFKCxY1;       spf=pass
 (google.com: domain of anatol.pomozov@gmail.com designates
 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=anatol.pomozov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hello folks

Alright, I pushed the rebased code to
https://github.com/google/ktsan/commits/ktsan-master

Besides rebasing to Torvald's tree it also fixes a number of issues
and crashes in KTSAN code itself. It boots fine with Debian stable
guest at a beefy workstation. At my home coputer with 32GB and Arch
guest OS it works mostly fine but sometimes (like ~5% of all cases) I
see it hangs without any WARN messages. It might be related to a
memory pressure or something else, had no time to debug it.

On Tue, Jul 2, 2019 at 11:16 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jul 3, 2019 at 7:56 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> >
> > Hello
> >
> > On Tue, Jul 2, 2019 at 10:15 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Wed, Jul 3, 2019 at 7:01 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> > > >
> > > > Hi
> > > >
> > > > I am working on getting KernelThreadSanitizer into better shape.
> > > > Trying to make it more stable and to report racy accesses a bit more
> > > > accurately.
> > > >
> > > > The issue with Linux kernel is that it has a plenty of synchronization
> > > > primitives. And KTSAN needs to take care of them.
> > > >
> > > > One such interesting primitive is semaphore
> > > > (kernel/locking/semaphore.c). I am not sure what is the use-case for
> > > > semaphores and why other primitives do not work instead. I checked
> > > > some examples (e.g. console case -
> > > > console_trylock/down_console_sem/up_console_sem) and it looks like a
> > > > typical mutex to me.
> > > >
> > > > So I tried to add KTSAN interceptors to semaphore implementation and
> > > > found that down() and up() for semaphores can be called by different
> > > > threads. It confuses KTSAN that expects mutex ownership.
> > > >
> > > > So now I wonder what would be the best way for KTSAN to handle semaphores.
> > >
> > > Yes, that is the official meaning of a semaphore -- it can be "locked"
> > > and "unlocked" in different threads, it does not have a notion of
> > > ownership and critical sections, only the counter. The counter for a
> > > non-binary semaphore can also go above 1, i.e. can be "locked" several
> > > times.
> > >
> > > For such primitive I think we should just add release annotation in up
> > > and acquire in down.
> > > But how did it work before? Did we already have these annotations? Or
> > > it's a new primitive? Or it is used rarely enough that we never
> > > noticed? Or maybe it is already indirectly annotated via the
> > > implementation primitives (e.g. atomics)?
> >
> > Semaphores has never been annotated with KTSAN. I guess they are rare
> > and problems never been noticed. Currently ~30 of semaphore uses in
> > the whole Linux tree.
> >
> > And btw semaphores do not use atomics. It is a non-atomic counter
> > guared by a spinlock.
>
>
> Ah, ok, then I guess spinlocks provided the necessary synchronization
> for tsan (consider semaphores as applied code that uses spinlocks,
> such code should not need any explicit annotations). And that may be
> the right way to handle it, esp. taking into account that it's rarely
> used.

The spinlock provides a critical section for the internal counter only

https://github.com/google/ktsan/blob/ktsan-master/kernel/locking/semaphore.c#L61

If we want to add KTSAN support to semaphores then interceptors need
to be added to semaphore.c. But it requires introducing idea of
non-owned mutexes.
Also how KTSAN suppose to handle non-1 based semaphores?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
