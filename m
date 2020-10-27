Return-Path: <kasan-dev+bncBCMIZB7QWENRBIOT4H6AKGQERUBHN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FD4329C798
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 19:40:36 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id l7sf375995pgu.22
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 11:40:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603824034; cv=pass;
        d=google.com; s=arc-20160816;
        b=QDPPXOgz/6cSdf2YLx9DMsmkKSvT0vbJwQhenmV9CI1yu0Y9XoEouEMhHXXjiB0B7Y
         5OnQdD4bN0Wth6xRPFCxomT5N8AW3GDXbmPKZTwc60HrlS5DFAxkH5XjMlQHUQjpPwV6
         cX7JAkHC2UeJ7xAbgQuVqKvO7Cs4uE37sfwI/Ym8YET5Wt4SfS5S69uYF5O4seGsitvN
         Kn4OQvcqjLNt+WgIDlIo+NORuQE4XYkwyo1kvv5Qz+BdICn7a+6phVO4ka0b809oBjjv
         zFHRKDamcl1v0C1ck1LQ9cciRbV5n59B/2RgcFExs7Qd1pgBGlCq2lPuDHDtm1rzAgXM
         NolA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YODTGLSrSggrhXMAW5drNcAxnstJn3FkBO/IRZf9Nds=;
        b=N7nvfngMdTMGTm4UXJ+yd8Ms4bQqwrz3w4Mpwprio/fysuAiIevD87hbBaPlwyuXA1
         ePkeEuNTtF36Y10buHMGrKhhQlqYkw4akfvN27wEt5FcRCIP2q4++ucu242orbSkXeWp
         dBA5TUCtKsrek/pRwMx4LhXknWmkBckT3Ercj4PoouZdoerRZp85V20UeX5n0dz3asoo
         7ki/r2/DSri4wL6vDR8mLQzpQyKoepM6NhBXd/wpGCrXHoSXTQXnwTXgdlhCaY641PSj
         simiGpnmOVbb5h6pX3n1r/KAudBiD/oQUaDf6DKdUtt/n5/pkK1is/RarRehukySNZok
         2cGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QPZgQo40;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YODTGLSrSggrhXMAW5drNcAxnstJn3FkBO/IRZf9Nds=;
        b=YY/thCT26GEENOMFXWy9AkhX9L+NsiyIiC9zVzIRzMjGOL4mEg2TuELdMq3C5GMeK1
         vaw7jApvgD9xLdOLnHpVVH+6q8MhEoNbtkdFGASuEHOlCzidaIc0XkBVExaGNpStWrpe
         MgHgyJHMYYmslO0OhxsVeeMS2K0JK472gRAQGbedUG+I5qh3OeMMxDU1XHY81iZV1edQ
         nLQfMhUtqgsGNBXHczOWczNYgORSEmxcik45gFO4ImC+MV9331fAnsUWFlCqY89qa8J2
         a1h1f77ntOVakUMd4Kl9/bbGJqVX2w19gmlHrIa0FP/Aw12jB2SsjPNQ1XL7vnFpFJ7f
         YNjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YODTGLSrSggrhXMAW5drNcAxnstJn3FkBO/IRZf9Nds=;
        b=WoaVFRrOJ8FbGt2QLovxkL3z7mqBSYzMbZxpLPD8qtQgnU3+84I6TlJFBySRAxpyiz
         a2Lgp0sJCL1ymkDEPDa8cWHD6JOBCb6LbXdmBWnduxQlgsMlnAzEFu5nudstd3dameFz
         iL9L4l+NnqtyYm/e005I88q5hsmm387d2WppRxI0UJc1iNuGR+Si2A5gTF0+cwN1zvaI
         jlAQs+t4AWwet4y33fj8FBCbXqkcWBZ5xRGxrMRpPfpAT9fSMe7PmvMm0neQqSgOHVSI
         e2ixEsfe1mq/8x3KSDTjmfJ9xod9NupSGHKjgyiMOFm/T0VVbRy/xGLQIHdahxWndOgq
         d+GA==
X-Gm-Message-State: AOAM533vaQKKelwSMW7rtEoNtH825NH9mwR3v4EukGObX5pxsKngOiQj
	QhaDSXSqESGhxXvzyVyqlHE=
X-Google-Smtp-Source: ABdhPJyaTbNMHvJDOaRZIbGWah7eP9Pa5vJFSw56rH7fGD8UANWYc5FmzmPYi03BQXOIxOrKO/G+BA==
X-Received: by 2002:a17:90a:10c1:: with SMTP id b1mr1416542pje.58.1603824033888;
        Tue, 27 Oct 2020 11:40:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c70f:: with SMTP id n15ls954038pgg.3.gmail; Tue, 27 Oct
 2020 11:40:33 -0700 (PDT)
X-Received: by 2002:a63:e542:: with SMTP id z2mr3138955pgj.320.1603824033319;
        Tue, 27 Oct 2020 11:40:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603824033; cv=none;
        d=google.com; s=arc-20160816;
        b=d2mmPi5HCj044EDm4jDyHBuqk6YOvet3NmAmOpttk02H5+lKwFE0SvvSHtH3Wvm/2l
         YUHPHQpbcqwkko/3sq+xe4xrhR2oZKrYzjP7DHXnLPPOx6ZWmpqnbzHOYr9YdGOS6uST
         +/vzZzA5fk3IIAM8qc5YNkG802LRFNd47SErutRFy79VohMlOEWUHHxdgQ6EkHTUdLEJ
         MAJ8d/BZHETp2IsmyBFiI6yU/svUzDdiuO6KpPJyHGP697im2omHl8Cx7srCCiNqs8qR
         qZOA1YzKec/KRA/lh544VgGg0XpAit1lSuK/ABnVZXD+wd8kqwc7lmUKLNrRFoUi8qiF
         bWMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A71w7yxcxJWosYwjYFtKyzjRaHmNMuK6z2oSv7nSpPg=;
        b=06u4S2R2zEJ9UWuPpwjuIxlxSACa46eeZPdpQcRc/FQWXRiDuY4k/cw3L4g+nGEsGN
         n+DzuIkEAiVb3gkdXwLrgX6/3DMMwjoVj7dtdKcUA8lVar6OfK0D3B9S7j/5xUrRXc5n
         jYrdgv1KdBYeCzn8D72munXrcOl17KyQfNrjUPgCD0KG/O5pbfgIm0YOmHXAOc2VkGfM
         t90lBnZ4ikvdVIVb2aaU9kwL267JCyT4Ga3XV3hhIL7VmzSZED2wN27omQN7E3iyWQjV
         IEcrmIaEfXudcq3iVnnGjyeZxlhA8DSlzidJthjfM0d5zp/yj0g0c3rvROCpLf2wxDOV
         Ggtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QPZgQo40;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id d2si183759pfr.4.2020.10.27.11.40.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 11:40:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id z33so1766678qth.8
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 11:40:33 -0700 (PDT)
X-Received: by 2002:ac8:44b1:: with SMTP id a17mr3587453qto.43.1603824031886;
 Tue, 27 Oct 2020 11:40:31 -0700 (PDT)
MIME-Version: 1.0
References: <20201027175810.GA26121@paulmck-ThinkPad-P72>
In-Reply-To: <20201027175810.GA26121@paulmck-ThinkPad-P72>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 19:40:19 +0100
Message-ID: <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
Subject: Re: Recording allocation location for blocks of memory?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrii Nakryiko <andriin@fb.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QPZgQo40;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Tue, Oct 27, 2020 at 6:58 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Hello!
>
> I have vague memories of some facility some time some where that recorded
> who allocated a given block of memory, but am not seeing anything that
> does this at present.  The problem is rare enough and the situation
> sufficiently performance-sensitive that things like ftrace need not apply,
> and the BPF guys suggest that BPF might not be the best tool for this job.
>
> The problem I am trying to solve is that a generic function that detects
> reference count underflow that was passed to call_rcu(), and there are
> a lot of places where the underlying problem might lie, and pretty much
> no information.  One thing that could help is something that identifies
> which use case the underflow corresponds to.
>
> So, is there something out there (including old patches) that, given a
> pointer to allocated memory, gives some information about who allocated
> it?  Or should I risk further inflaming the MM guys by creating one?  ;-)

Hi Paul,

KASAN can do this. However (1) it has non-trivial overhead on its own
(but why would you want to debug something without KASAN anyway :))
(2) there is no support for doing just stack collection without the
rest of KASAN (they are integrated at the moment) (3) there is no
public interface function that does what you want, though, it should
be easy to add it. The code is around here:
https://github.com/torvalds/linux/blob/master/mm/kasan/report.c#L111-L128

Since KASAN already bears all overheads of stack collection/storing I
was thinking that lots of other debugging tools could indeed piggy
back on that and print much more informative errors message when
enabled with KASAN.

Since recently KASAN also memorizes up to 2 "other" stacks per
objects. This is currently used to memorize call_rcu stacks, since
they are frequently more useful than actual free stacks for
rcu-managed objects.
That mechanism could also memorize last refcount stacks, however I
afraid that they will evict everything else, since we have only 2
slots, and frequently there are lots of refcount operations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbB4sZjLx6tL6F5XzxGk5iG7j%3DSPbDkX_bwRXmXB%3DJxXA%40mail.gmail.com.
