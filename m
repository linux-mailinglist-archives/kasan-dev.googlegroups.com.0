Return-Path: <kasan-dev+bncBCA2BG6MWAHBB24CXX2AKGQEA7W37DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6338E1A374E
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 17:38:20 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id g88sf1340169otg.17
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 08:38:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586446699; cv=pass;
        d=google.com; s=arc-20160816;
        b=PZOPUsDua/6fBpX13gSVYgEC0lhL2cgyIEJ9CtPK5aod/8teEkr8Cp+xtsRUNjjYTu
         3EV8x8JZf90ECRnXjEqSIXR1zOQ/5fOGk4673dWoeHXgi5p3n0iLFcXxSKwpS0QibYOp
         Xkk7yUzwmjnRTKC28gvhvTVeEovKwClFbOVq1r7U+FirMIxjXGFwFHJPlcT0Dq9F7v2X
         Bhg63fCaZwetOHPE0CQQNDsUN7+gfYmSVhjh2pZXMSSqRkLGLvwMEERDXV43QJCccTWi
         RDPpeQ0TZyUc8zTD4Uhv/vdgP9pQ+vso6L24dRzXLcYF3uA185iJv3d3tk8UhXj+vBEk
         HxAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D+xbApzuIqP3jTV6q+Mo1V3EZkTctR5smy1qVEIrm4E=;
        b=PSv+xfCxg9UsfM+sVPTzWVk3DIzbv2G/8SORi07Wz7JP4b2jeZDvrW1BAbaoF+AS6g
         Tk+eq2dKKr8JHAEtfmWcwm0qncdNjXb4wCc5fb9euxG7/cZNkks9J6JjXbc84GiSYJMc
         Hsv67cw4mDPY6GSyusrFY9fWn4pdhvz88dueOp7HqHwfGoRNLJHD8xyp4KM7mnrvCb8n
         l7/oOyMe706uLbz4zDmhJrtFtUgiWIvm6yOGua1y6Uzg5ujhcAJXF2ul43h+cnA58I+p
         Dwddq5RUNUe01Lf4gBKf4EVJBQAe0Wzn4g7i7ht6FGkBHUAryw0XWVbWvgIf1Y9kx+ks
         +DHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JDzhtbxd;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D+xbApzuIqP3jTV6q+Mo1V3EZkTctR5smy1qVEIrm4E=;
        b=fJ+ncH0QZ5jwuOv34AL0lzVcczHgRrmm1iUVfO9lnjKI7FHOguse3ShM+caLqjQnjp
         CyLz4kgphloFlgW8U/LHnwj16nvfZYo/PcLg6quqrJQTAx4FMJMPI/bQcMSZG+CcWWJl
         tPGYvf0pf3IBVAE2FnGKvze/wlrjqPKrNM3cw2WwoqYOivCc5puQvQx2Ez4BdgxO+kxC
         rVtGKx4yqv6zosmzSTkhdqwlVHzAolxnTTWlAPC5AkXnFbE0zNiZ2ChPR0L2FCfy7Rw4
         XaojSCZ/SbverABCI7eFtRZxfb9HLuSjwt1aMOab3RngKa3z4pQr04xX6XqUmg9m+DLk
         73sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D+xbApzuIqP3jTV6q+Mo1V3EZkTctR5smy1qVEIrm4E=;
        b=TdHdJoHHJ8JsX04mp8ThunyyS518CmRF9U0WIlf57W4lxPWNZPHC/BnVJO20eqXrLC
         /m11dxEcZwh18Y7tJu6A088m92GWXfePCWPLeuXTdCTEfT6fXbh57RySGmgk/hbjYDJM
         0rrfBWOJ3wyPjqKdeOdsXx3cPN6ZZbUehWHfpzYKh8GwfLGrkp32iQV6C635E/Sdp5zA
         uUo6w/QDuXr/EvUITvhX2K1MFzrJCgYBBFaft/eHrU0zV0OouktS6HydxolVQy/Ag3nP
         lTVfccBSn4Q1jimM/Fvan5bGjK2jw5Djo2ut9SOD+JfYSlmlyv5dMiSYXX83/NTV7LBm
         16jQ==
X-Gm-Message-State: AGi0PuYhMM4PxP9ND4LRju93LXIWXJTqp/+2LR1cTeFYpfLVPZqIHunE
	mCZgcDvx7wQJffmbJ6U7zUI=
X-Google-Smtp-Source: APiQypK5MT+lui4PtmKL5Hqxku2ixJuYi1aB05FlsUJPy6qdKlQsoIbHWjf4yIY6KugW4GOSlo9fmQ==
X-Received: by 2002:a4a:929b:: with SMTP id i27mr372887ooh.95.1586446699252;
        Thu, 09 Apr 2020 08:38:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:ec0a:: with SMTP id k10ls3472716oih.8.gmail; Thu, 09 Apr
 2020 08:38:19 -0700 (PDT)
X-Received: by 2002:aca:1b14:: with SMTP id b20mr6840609oib.18.1586446698962;
        Thu, 09 Apr 2020 08:38:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586446698; cv=none;
        d=google.com; s=arc-20160816;
        b=H5HWNgwZJAO9+AVoS+xYvXBU7Mi1xexdjnezTVSGUvw8HjEC1NiQbtMslUC/MqknLU
         sRXgnGBZ+u5rNEVgvBIDVK8+fZlqTALUrgFh6N2/+XoAs5VdGs5Zz9OfTaYo/v2F1VvD
         4nj5b7umWIQbUAVYFxfdM9i6rxqhoC0JtGtO/xB/8F5cz6syVLLXoGUp3vbI8DzSEThJ
         UpNdCENnnfqJcFhb3fnqdTuYFPM3J9krD7oj2fezORj3P6SPgVeGejJWP2ljKS2kezMi
         xcmiAJNRT4Z3aStV0HPLdOV4uwyiSuBgdO60dzFviqxtgRJPSA7Scjp94FtTsmm5wuFb
         uB4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cmy/E0Wt6Cl0AUmjvQDfvM3W7oFf1zE15jB1yhakqWA=;
        b=Y8ZD+t0wAIF3OA8z0njOaKdDWWxMQdVVaVclVviptHqa1KYFkmgVjDSRhPAzWu8mY+
         FRSmknmp88x7ALu6M7dKuAPIEQ2A4zi+0ordMRTGLGc0dY5Lk2bUr7vPB10IC3kh9Gdu
         F2O6LB2BhQbGhH4CotV6mK8AXmbf+cBfzgGXdmnCDk1iwyHze6imTS3i5g92zlehEtxw
         slCKvP7sX3IQqc2zXLWQwWiY+nHE2RHsmF2T73ih09ucaJa9T2bbLAFq2qrR4vi3yaHV
         OKKG7CTfDVcMwup/beP3DTfWob2cGfzyQYMxBxsSEMgc8QGlLzkpIJkD7VcDE34lDEjC
         cn+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JDzhtbxd;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id a63si760060oib.4.2020.04.09.08.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:38:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id c20so4271697pfi.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 08:38:18 -0700 (PDT)
X-Received: by 2002:aa7:9a5d:: with SMTP id x29mr127766pfj.284.1586446697994;
 Thu, 09 Apr 2020 08:38:17 -0700 (PDT)
MIME-Version: 1.0
References: <CACT4Y+YbNNyvoYD7E1Rczt_OmkEuYTs6fDHoaUPFEygYYr_Oyg@mail.gmail.com>
 <CACT4Y+bDt_QJ8emH81qcSjFFC75u=cEz6Pc-PTNpoOELNfdBvQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bDt_QJ8emH81qcSjFFC75u=cEz6Pc-PTNpoOELNfdBvQ@mail.gmail.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Apr 2020 08:38:07 -0700
Message-ID: <CAFd5g475QQ73g2U1ZjBnoTVnCxmDTTcjfHR4XEhQ2eXUfa+Q4Q@mail.gmail.com>
Subject: Re: KernelCI and KUnit
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kernelci@groups.io, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JDzhtbxd;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, Apr 9, 2020 at 12:31 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Apr 9, 2020 at 9:16 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > Hi,
> >
> > I remember subj was discussed last year. What's the status?
> > Has KernelCI started running KUnit tests during builds? How are tests
> > selected? Does this use only UML?
> >
> > Thanks
>
> +kasan-dev
>
> For more context: we would like to get some testing for
> KASAN/KCSAN/KMSAN/KFENCE. KASAN tests are being converted to KUnit and
> KASAN is being ported to UML. Tests for other tools are in process.
> I am trying to understand if KernelCI is something we could rely here.

Yep, we have made a good deal of progress in this area. We had an Eng
Resident working on this since the end of last year, and she was able
to make most of the changes necessary for this to happen. Now we have
a working prototype with one or two final changes needing to be
upstreamed for upstream support; I am working on this now.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g475QQ73g2U1ZjBnoTVnCxmDTTcjfHR4XEhQ2eXUfa%2BQ4Q%40mail.gmail.com.
