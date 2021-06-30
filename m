Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4O6ODAMGQEW4SJSBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id C12A83B8933
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 21:34:44 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id ko19-20020a17090b1713b02901708f700618sf4045985pjb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 12:34:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625081683; cv=pass;
        d=google.com; s=arc-20160816;
        b=gSBFjW2GNq0fg3l2T+kyjGMLPJg0C1mpLAnNpeWGx5CoqEu2jnrlgSHnvnfpiQM2tZ
         MGX3WAE4nXEimnXbvi6VfQWUu4E8yoWRgEmH0InK2U27G0JM4r0yz+ZoCMUXzlhyrR++
         rqxtb+0cE3VDXXoaLvLIMepvnh/Kp3XWUabSAYj9ivaJ1ikaCnbuRF07VNNsqLhJHDd+
         XW3sOvX8m1KVQiRUhqmNPUX8+02tg/iKLQL24SjHCp4lgqY3l/K1YTrLeXHwgWMZPH+O
         j7H2kKYR+C2cW2y8v3DEm6J+I1NeKapyHy5NrSJzd+c+yekxe4yRv18vRQcEFtvPlcfI
         vnhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n67m7SJpLY9aRoA34P1XkdUHwcmC4fWexRcU15p9zgU=;
        b=DjnX3nTEGSI7zJgkksnORwc0dCMOcJzHDwONQ1tAkUrCJQJ0HOa2eh4GECFqlEZdm/
         A0ElJ8Rej7kIGq8lTl5u/F80MWArPrSg+hAgYAiCtG/LlMBdb0+J3n00MnKVyZNhraz5
         Fjc6N3Nz9BWP9ElLtHTrH8FVfdB1Q+gvOHY9HmMFiBKoT9EYf9jFI1DTozca5gt13mLW
         X4G6huliusWBY1949ReWJz6CJzgBdRZqvTHkN7DQVNwIFoWht9OLP3cGtBaydS7t+tVX
         nC9zs8tA33g5hjboKmA5+dx0JYfJbX6YPeeu0XvRjWjWedmGSLUTZERNDafK0khunP1Y
         lq3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="aRtt5v/X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n67m7SJpLY9aRoA34P1XkdUHwcmC4fWexRcU15p9zgU=;
        b=mHcnlWTmhPpps3vRN7U8G1vIb/MS1qDEPjbVRr4EMHUZRNlPuMCojhhzpBaKe6k1/h
         cOQtJiQwE+tZuWy7nDCx8WD0xvZuLZARx5qNtQRYr90rnysegj2yKibcCbwF5PHy895T
         4KXQDLWyh152bixyPvQ4WEmDQSYkrI3hLM050E+r/VSSJAkwJLIQPxfJn/wuscOTwzrm
         M2HgZjAqqAxGsBMRjXiIdmQbudqdmKjE4MJYqdXIHi/zVi6dtEm/Edsbd6j2iQ29y7bl
         R9wvvGd9h5TonWoFE+T78xqPPoGtKGMxR637ndJU/WzQXSwAIgo/Zf4Y37lXR8COWUGT
         7/Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n67m7SJpLY9aRoA34P1XkdUHwcmC4fWexRcU15p9zgU=;
        b=G79VksOqc5hfg0odN94+WcazJKqDD36+Ah5cQjAttLkt82lH71M37hVRVVKJ8Cj08i
         y8E48IpDS41mJAmQpiQXt5feLxkFYhdfsgdpCao3138VHZzs5iyYl3dlUkXIjIrrsFhc
         CWgm43orTjyw9Kg9SnNrNUaJQPueR5A5MV3oj2sQSiVpf2H9zWhLnhE1boVNdcc+tOA/
         nPgq1zMXhgIJ/7jTqNGl8sxpqDfRxz0XpMlZKn5ws6TNcUfFNhMnmXu+QBbDQQdPMe+D
         V4SeOC6/GflDYsX/xk6tGZxKd5Nx8xiFSyNWQ5lZCdxbFanBRk/e1XABvaxV/xt1EW9r
         dJQA==
X-Gm-Message-State: AOAM5332y2KWUEMcapzwG0uBEypKIMvepbobYwgQ/Vc+OfDf9Col7kKS
	afBspbVfPCu/exeUHRO2ABI=
X-Google-Smtp-Source: ABdhPJxQcEGX2RwV8yO7BVj1JiXJWH8eI1KyClyp6hGvauKjUZ6jxEqCO0T/UFxwEgSuYZGF476Xow==
X-Received: by 2002:a17:90b:3253:: with SMTP id jy19mr6097932pjb.196.1625081683386;
        Wed, 30 Jun 2021 12:34:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b418:: with SMTP id x24ls1884109plr.7.gmail; Wed, 30
 Jun 2021 12:34:42 -0700 (PDT)
X-Received: by 2002:a17:902:b711:b029:11e:6480:258a with SMTP id d17-20020a170902b711b029011e6480258amr34116216pls.41.1625081682768;
        Wed, 30 Jun 2021 12:34:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625081682; cv=none;
        d=google.com; s=arc-20160816;
        b=eqz7fLjrXuV4/QYbQtB3j7eC80y6o9Y7psRI5oJAqpsKLHpsI9A7j/i0d2pgrWED2Q
         OfoNYg/mMbciZmBE19qK+wUxGQjsM5DHdV+zSskvLbyyt6fSRQZxhXLBJL+Jf+8ekvTv
         1Of1vz2TCwqecMxDYBIPc/B+pkRnDnBN/K3PN2nutjUiJQSarukDxwtZCZ5ab3iZn7Pn
         /vgi3rBRQSZsiSTH1EM1iO3svihIGeFOunPzINnvPHLnC6AFxiVcI/sg1gQrS5Lgh+i5
         +PkMNWODBMRNspkTiLJC9PGzpbdLd9Bi1Zw7TW0G/qJ4REKgdaJwkpaJnd12REPY35tL
         ucIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z/iOfKm8Iao2lnEDiXuVXkhdoDSAmPD02L6Go09Galk=;
        b=WAxaXzPXtKvshvCbQRJO9d3iUw90WAWMIOW75xIRFvfj2WvyUqYBO8zsyFl2dv0jwk
         4Snn/3+ZHowDwCtaVQ4YURhUMSuuAa5E/JHO0sUhjhEq6IsBJkoRAZWBLN1Eb2GEnIKu
         Me0FDG8YZx4nNPfCRBFX/qr+9CAHrY92C5OAdxEggikdVodi4z61ghv2O+oESrFXdhGB
         mXwQkUI1kvj8y4MguK2fr0Xl8uWcr0BSQL4n7AeFH1njggGOCwCuT8hQM9hT+c+17SKt
         ivcPv3BZ8Tm6W01uIGcpo+t2qQe003g3PGZJpEkKC3k+8K+sZSNCyIhsdKYxa+5Yb6iw
         ROBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="aRtt5v/X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc36.google.com (mail-oo1-xc36.google.com. [2607:f8b0:4864:20::c36])
        by gmr-mx.google.com with ESMTPS id x14si2083553pfq.0.2021.06.30.12.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 12:34:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as permitted sender) client-ip=2607:f8b0:4864:20::c36;
Received: by mail-oo1-xc36.google.com with SMTP id s10-20020a4aeaca0000b029024c2acf6eecso925245ooh.9
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 12:34:42 -0700 (PDT)
X-Received: by 2002:a4a:956f:: with SMTP id n44mr9708434ooi.54.1625081681837;
 Wed, 30 Jun 2021 12:34:41 -0700 (PDT)
MIME-Version: 1.0
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
 <YNIaFnfnZPGVd1t3@codewreck.org> <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
 <CAJfuBxw-JUpnENT9zNgTq2wdHqH-77pAjNuthoZYbtiCud4T=g@mail.gmail.com>
 <CAJfuBxxsye593-vWtXz5As0vBCYEMm_R9r+JL=YMuD6fg+QGNA@mail.gmail.com> <YNJQBc4dawzwMrhn@codewreck.org>
In-Reply-To: <YNJQBc4dawzwMrhn@codewreck.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Jun 2021 21:34:30 +0200
Message-ID: <CANpmjNPyjTKd7tSPbQ6G75H3djHtWqipmVzNWguPU+mdnH3uag@mail.gmail.com>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: jim.cromie@gmail.com, kasan-dev@googlegroups.com, 
	v9fs-developer@lists.sourceforge.net, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="aRtt5v/X";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c36 as
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

On Tue, 22 Jun 2021 at 23:03, Dominique Martinet <asmadeus@codewreck.org> wrote:

> jim.cromie@gmail.com wrote on Tue, Jun 22, 2021 at 02:55:19PM -0600:
> > heres a fuller report - Im seeing some new stuff here.

There are lots of known data races. A non-exhaustive list can be seen
here: https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce

> Thanks, the one two should be the same as p9_client_cb / p9_client_rpc
> and p9_client_cb / p9_virtio_zc_request are very similar, and also the
> same to the first you had, so the patch didn't really work.
>
> I thought after sending it that it probably needs to be tag =
> READ_ONCE(req->tc.tag) instead of just assigning it... Would you mind
> trying that?
>
> > Im running in a vm, using virtme, which uses 9p to share host filesystems
> > since 1st report to you, Ive added --smp 2 to my testing, it seems to
> > have increased reporting
>
> I'm ashamed to say I've just never tried KCSAN... I can give it a try over
> the next few weeks* if that patch + READ_ONCE doesn't cut it

In case it helps, we have this LWN article series:
https://lwn.net/Articles/816850/

Paul McKenney also kindly wrote a summary of some parts of it:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt

There are some upcoming changes to KCSAN that can help filter some
data races that aren't too interesting today -- see linux-next and set
CONFIG_KCSAN_PERMISSIVE=y (the opposite of that is
CONFIG_KCSAN_STRICT=y, but not recommended at this time unless you're
writing complex concurrent code).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPyjTKd7tSPbQ6G75H3djHtWqipmVzNWguPU%2BmdnH3uag%40mail.gmail.com.
