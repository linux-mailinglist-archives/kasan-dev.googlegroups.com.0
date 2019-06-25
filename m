Return-Path: <kasan-dev+bncBDYNJBOFRECBBVPOZDUAKGQE37PU4RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A383D552C2
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2019 17:01:42 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id u10sf9330904plq.21
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2019 08:01:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561474901; cv=pass;
        d=google.com; s=arc-20160816;
        b=diFQczceIv/b7CofvJ1R6b+YWxRJCPyrDMhumLb13ttXUfDSlDI7nmlaDEuQg4ts01
         Zbiwt0W6LUfMjdhio/hRQsUJcB9Aojngs2liTUMmHeh8t1koeGFjfUQJRUOs5hArV+9j
         IL9FVIDs3O9co/j95VsqwH9pd4VrX2gDzEl13Nw/W0hv1fNRzytt0XLxymhxVGwKs0Ld
         XcHfmwA9nUOkdCHA4/BG3hdimkf5/DoRoylcZiZKPXqUT2RRfKYdYXloEw8Zzjm1tc3C
         SE6cs3DwfFUmGg1v1GfV1fw4AOy1Tl1JJFeXdiVGvQ5P3MbpFXp133meJ9XC3sIVfg+9
         O8GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=YccL0ay44Tktt5SyexTyaJkc0vMUv9KyXVtCHpuVZ7Y=;
        b=qT44NLbx5Cx5E3JbO5n+7x4YugX8hNOxbIph6zdM8xJZ3K0SsQnax/0MaFjStyMXcS
         nZUuUwb5KpSgQrDjPZ9FipsHWzkvwW05SKFQu5rouAgsz2BirdVBMD8XbFwZbUUQ9FUc
         Eg8eoI0Hiu5MDL0kf99VO7Fun8rry1+TFOhQGpd3tZYA3pmMhS/AslanZZIUhRRSakql
         SSgT7L/1455mHpQguZGgMCtYPC1YG4915xH3Cc4bCKVLCfEdP3jKDhGv9/csKKrtp8zX
         SZd5jARRJDZWvOGehRg7Vy6mTUrLv6U2Djfr9ONPCJHOHmMH2OIqmw8uEtV0F24UH8Xg
         oZiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=diW+vWQ1;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YccL0ay44Tktt5SyexTyaJkc0vMUv9KyXVtCHpuVZ7Y=;
        b=HEcFEgIornG7zMS4HzsVyIUZBJCSPT2c6uVW9GnelIgmKBj60nOff6kTrW2JFtE+cs
         BwuOeuVgsXDX5qrybAxzLIaaImG+MLRwcTFIubbvWQlR+A5a5SV64+6+Pk7PZS7AiM0x
         xn9I2CV6oMFXIuvohke/OpEzJklEPllKKU9+qkeEi8BHMIJIlNf7CSpCu+wzKF968Zd4
         wWYhy6AOnMsIqP+PsAaTx7iBcMchIHEK6uy5Djaz3ucNoTnG6oCu+rI/RKaLJ5/xDYqb
         XxPuuVvQ28I39V5B5jVbYvXdo/IN52IPebbJaGSm4BA8WpIUW/oaxqN2BuwemDWOFAen
         41Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YccL0ay44Tktt5SyexTyaJkc0vMUv9KyXVtCHpuVZ7Y=;
        b=Sm2qR+KsNHw9BLITT5hPinGksjr8EyEDwktljDUuJ4sXZz6T8seMyjSeI6LOdPYuIJ
         bDWLGif//Toriwkn8++4uLFBK+JJqjK6OSLmqE0BbB0oOYk7NT2yn+AzQe5A8kwBek1d
         EHU9v+1nboY216MIazKwK5RMOrLbxAT2O6YULid8OaPQNHYTAFAjdSomMGCk1PEGkvpO
         blu2vJFleTsXoq/pLT8D6Ri10U0oTZSmCfojMjnKSFd9ACj0QLzqwv7b/nVHsWhunLz3
         saV8y5zfiiHQTND9YNjGmzU7wTQrEmLvcAZJkyzXB4g4v7Sp5rPgVO+au+rM/4CYFaX7
         mTkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVdmjhsq5JbyqBGdRvJpLTEebAwUYFZyKx1Us46m3bhiBHvJ8eF
	ByaMudcnGaRLxC2Yt2spKy0=
X-Google-Smtp-Source: APXvYqyu23+nVhKQXaTXOH1YY5s9gMFZhMa93gMfIl0I8Gx1QS/07FVwdmYRtFxknEs1ERB7U3Ar8w==
X-Received: by 2002:a17:90a:8985:: with SMTP id v5mr32029390pjn.136.1561474901395;
        Tue, 25 Jun 2019 08:01:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a986:: with SMTP id bh6ls5641869plb.8.gmail; Tue, 25
 Jun 2019 08:01:41 -0700 (PDT)
X-Received: by 2002:a17:902:f082:: with SMTP id go2mr19100748plb.25.1561474901050;
        Tue, 25 Jun 2019 08:01:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561474901; cv=none;
        d=google.com; s=arc-20160816;
        b=nWW/q8yEvoSGFd7wZHvtCgizYPecjj4bED8zJDgXCAKfkjgE3pUBqG3yWBRv/NZm9x
         NTpxSaWdtCWkAQtTMsp0w/xuYs+dgX/0yditGR2CK6bsGukKdlJE6pKesFBcE+gjz1xT
         hkyEwt2ii80PKrcGxoRkaMCMIgQkGnzi8aEMkf9zNiNWh9ReQk+glERbw4wen1sorrnV
         O79N/RTPs0JlxZyGInCllpFHgpwFztszPZ9x4bEjks8JMJuRDOFWDdFoHhWgBePaOVGW
         pMKaOhJ3QeIoi+DXVpLtHChSfbYkEs9E1z+YM52XexaZnrj7sDMfIi2M3tuxoZ87o67E
         ya/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0yr5BGG5Soxpasmq18l/eZqmRu+7BCvMsxIS8QQvWds=;
        b=Aqxi7+gIqVLNoEBIp5Q67sJutJNx49kGgoLUdrfoB/kNyn5uZ1Gihm27RWFuJRyOJ9
         LmNJpYp1/DfgSHDhXvdHyrZWqOhKvLr6Iy9ZbMmRuTynBDkLqsJCEYmtF2djTnwowTzg
         hdUyo91MriCHuV7CPIWmv93dmPozHhpRps+Gm0KdvfUrIRwujFsxX7xu1RxFshvdQkXK
         dWiFszRL2Ia9pJEDJygbXvneqb90vbTaZue0r5W9vrKRxxQWPYGy5EBscOtK8tQHLGVo
         QeB+uISrYVAvVtpFqzDEr4j+t8aLKgsuUOpvrrEkDzEw0FrTWufr2aGZhVnYN2ETtyof
         H41Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=diW+vWQ1;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id f184si612757pfb.0.2019.06.25.08.01.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jun 2019 08:01:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id i10so1542944iol.13
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2019 08:01:40 -0700 (PDT)
X-Received: by 2002:a5d:9d83:: with SMTP id 3mr13470506ion.65.1561474900420;
 Tue, 25 Jun 2019 08:01:40 -0700 (PDT)
MIME-Version: 1.0
References: <20190618094731.3677294-1-arnd@arndb.de> <201906201034.9E44D8A2A8@keescook>
 <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
 <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com>
 <CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg@mail.gmail.com>
 <CAKv+Gu9p017iPva85dPMdnKW_MSOUcthqcy7KDhGEYCN7=C_SA@mail.gmail.com> <201906221324.C08C1EF@keescook>
In-Reply-To: <201906221324.C08C1EF@keescook>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Tue, 25 Jun 2019 17:01:29 +0200
Message-ID: <CAKv+Gu90nGDYFwdi69centW+yyS16u1QDVNT7C7VcRaCkCaRyA@mail.gmail.com>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with KASAN_STACK
To: Kees Cook <keescook@chromium.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Popov <alex.popov@linux.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, 
	LSM List <linux-security-module@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=diW+vWQ1;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Sat, 22 Jun 2019 at 22:26, Kees Cook <keescook@chromium.org> wrote:
>
> On Fri, Jun 21, 2019 at 03:50:02PM +0200, Ard Biesheuvel wrote:
> > On Fri, 21 Jun 2019 at 15:44, Arnd Bergmann <arnd@arndb.de> wrote:
> > > One pattern I have seen here is temporary variables from macros or
> > > inline functions whose lifetime now extends over the entire function
> > > rather than just the basic block in which they are defined, see e.g.
> > > lpfc_debug_dump_qe() being inlined multiple times into
> > > lpfc_debug_dump_all_queues(). Each instance of the local
> > > "char line_buf[LPFC_LBUF_SZ];" seems to add on to the previous
> > > one now, where the behavior without the structleak plugin is that
> > > they don't.
>
> Ewww.
>
> > Right, that seems to be due to the fact that this code
> >
> > /* split the first bb where we can put the forced initializers */
> > gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
> > bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
> > if (!single_pred_p(bb)) {
> >     split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
> >     gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
> > }
> >
> > puts all the initializers at the beginning of the function rather than
> > inside the scope of the definition.
>
> Do you see a sane way to improve this? I hadn't noticed that this
> actually moved it up to the start of the function. :(
>

Not from the top of my head, and I won't be able to spend any time on
this in the near future, unfortunately.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu90nGDYFwdi69centW%2ByyS16u1QDVNT7C7VcRaCkCaRyA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
