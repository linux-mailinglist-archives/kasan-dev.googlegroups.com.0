Return-Path: <kasan-dev+bncBCF5XGNWYQBRBXE5XLUAKGQEDRSFGRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 529904F828
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Jun 2019 22:26:06 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id e16sf6307569pga.4
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Jun 2019 13:26:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561235164; cv=pass;
        d=google.com; s=arc-20160816;
        b=dGPYJm4TmvSj9nchzwl8SmxmCQ2FF4ATCpiuLaJkjvMxeTYIFh/ejkr8d/PWvIelx9
         SwRlmZuUyqsS/47S8+zNe3FnVzszZaai6B4MHFJ6F6a7FMdEQBpkAkN2EZ5XBeBrDLCm
         5uLGFvK7KftpJvN7dpaVFA+ESh4CV3dqkKk17xXjCFoumdwdn5Mtvp1KwkHoHV/NXdiQ
         Fl+qOiROZ/DCI/rM/VFViEFVqpZX+vBtxnlPo1hTAf14S/b3b8u1IJNNWCxjG0xEr8iV
         uCOLIEvIjlMX3w+w7nZ1WHAZKB55TQEvuIUzasXlY9fv+8cazpddeBfR8sW0CtNjj1dY
         YP5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Wpj8OfXUN6FwtbTR2NgxUqoBP1N6CMlEDNaywaK0I10=;
        b=SU7nNTYGDP0KE31GSuQhe16y42m7KMT32HNbKUm3RFGi5M+iS1sHS6m4jKGmfSv2aV
         8OJIirjt8TEPLwhxA8AWX9l8AOCs7H0FOZ12kRSrYR2MRsyCQ+RKrZ5+NADjZcjC+EHT
         YWqVCYaj025T3B8YpDcLCGJ+tgM7YYmmEfJHrETauwSw4/qlVQXY3mOZyUrFslUFj2KN
         wC1ZWOaQWEhdoYZEkyPVP8k0Z7at4hvU3eMtn1YLRJwfJzbjtnizIXAL6LK4EzyM3Q7a
         Iev+UJ/BFndaJd3MYy020UDoTTaGEHflo7SjZZjRbCxBDMEXfDe+4Xt/t/iEm7MFLWoT
         moqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PJubyZXg;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wpj8OfXUN6FwtbTR2NgxUqoBP1N6CMlEDNaywaK0I10=;
        b=OkULpMtEw4RWkIBeEpjXoIkJu9Z1AX7PH1yafe1W8qxEUrbYMcrWbooecq9diUF9zb
         J8QvjiC7/v6jdBrwoFnGc1xJ+knqaz32T5y361eiHBe/ucLZ5cx2iXWG8d5WwC2Tq2+b
         t9znoqWvcPNgqmU9o8aA4ykNJ3f0EW8U2QYld8/h8kLCyi/7rWs7kkvs4UxSqJhfly0D
         4BG23Y9WGMF9R8G2uT6w1ooNaa5ZSsIBXY8VBJqDeBwTPUjJ5e1m1kH+29tc1yBAivIY
         UFh7+qbKgHE7mkCfE69AlwbSLeRnYI3okjlqpGeMinLI2rK1WVHdK3ea4bY6J+8HwQwZ
         26AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Wpj8OfXUN6FwtbTR2NgxUqoBP1N6CMlEDNaywaK0I10=;
        b=di6h5G6DickzDLlETSAEeap0R4soCcKn7B/zDpqE8W/MScro30yYsoptcXX16y6xzP
         FRnjBYYwSSd5YAIr6RtBT2IRMYEAKCaP1ME+8adf5CCwDkvsFm38Xol3NyUjzdrEJaSe
         ySNtT4lZsDDwJKoIfTkC6Dkwf2+pBzjNmDBo9Rp/XxvbJxzEPXpwXf2+8tgjq7NlVUOW
         I28pqK/pBxz5LDGuLFXttfDhcvBWeGPgS4zu6Q69f3z/9OWi0FknoKlRsZN7XLsz5tLy
         eT4htZn0rL4RBzdQUqh0LEtT6HpnC2IvHlKp3LGOoxrHt9E9Gz0v4/fhymym/ybxRTcI
         qjPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxYdK0MnYARXZ88k0JVfQqzpJ03cgGecGp0BhnxjOuyy/8/aZV
	AsIaBEV6sd9WLOkAcfE1wig=
X-Google-Smtp-Source: APXvYqy7PhcoF2CJbQ9COFman4YYRjWkIU9lPBbgAP+MESvMaXPKfFIx5557pghD/HDWNitduDr0lA==
X-Received: by 2002:a17:90a:37c8:: with SMTP id v66mr15142789pjb.33.1561235164423;
        Sat, 22 Jun 2019 13:26:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3227:: with SMTP id k36ls3706970pjb.0.gmail; Sat, 22
 Jun 2019 13:26:04 -0700 (PDT)
X-Received: by 2002:a17:90a:32c7:: with SMTP id l65mr2713651pjb.1.1561235164106;
        Sat, 22 Jun 2019 13:26:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561235164; cv=none;
        d=google.com; s=arc-20160816;
        b=MCCi/DgcNziUTTBtirjxVTyxR3RQ2qTwZ3BxF3yLlEFBYpp3vUsZKPO/wFONoFQSFf
         zqCbNi5cI3iew5DAN0aLczVSig+z+N70lBWRPZlJ4vf1RPysHZ3SEirs/HYmDBSkjBrJ
         co6Gumr8n1u7V+4RYdkc1W1Uo5SLHtOt4/CRkqtCnjEOy8Iu65qU4iyO5y7gsOdFWSEc
         fV5kUYW85JhDB2WGjulJMECEDk59s0BwU03YsBsjiuFyb+hf08HAK9OpVqbnidLURQQj
         4Pdjls9MfMuzNU9ztj2k2A28IXXaai7G3HSlzEj6BjzOyoH8QiR98epfecSjTuSrdD7o
         v3Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3LSJX+LSGEGQXGztmOIE004OfGh43169X3pcb5+bEdo=;
        b=MyTSXbcYlBlBtQBOI5ZtXxPPoOtXXUzLJpRzR2Hp0HolgZK0hm/HwxiD+DT8ZMk3ya
         6yXDMc3YMlc+V2zcxKg56fMepIwaGg2o9cE005pzec+SiTs1MeLHQ8+gCfdf8Sz/fW4t
         lXWNkYCyrigKGIi/t1OBlMyPQKgiIt1/4pJ3f85STqNqvaovakNwTMKb+LIP6UxW/Km8
         p6UJUIYeVXVO7fix65bE2NOSDDw6/0ZAcAT7PXVzSaX7c7DhAHdTwlWynhdVF7l+4UyV
         7gja+gNTDkBrhW6PrZlGdilhbsdy6I09kfTYfH+yIxNORYmQHVHx9JvPD+eMwmX+Ut4I
         2M5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=PJubyZXg;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id x12si270306pfm.2.2019.06.22.13.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Sat, 22 Jun 2019 13:26:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id c14so4672616plo.0
        for <kasan-dev@googlegroups.com>; Sat, 22 Jun 2019 13:26:04 -0700 (PDT)
X-Received: by 2002:a17:902:2ae8:: with SMTP id j95mr96325450plb.276.1561235163946;
        Sat, 22 Jun 2019 13:26:03 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o74sm10129957pfg.91.2019.06.22.13.26.02
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 22 Jun 2019 13:26:03 -0700 (PDT)
Date: Sat, 22 Jun 2019 13:26:02 -0700
From: Kees Cook <keescook@chromium.org>
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Popov <alex.popov@linux.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	LSM List <linux-security-module@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] structleak: disable BYREF_ALL in combination with
 KASAN_STACK
Message-ID: <201906221324.C08C1EF@keescook>
References: <20190618094731.3677294-1-arnd@arndb.de>
 <201906201034.9E44D8A2A8@keescook>
 <CAK8P3a2uFcaGMSHRdg4NECHJwgAyhtMuYDv3U=z2UdBSL5U0Lw@mail.gmail.com>
 <CAKv+Gu-A_OWUQ_neUAprmQOotPA=LoUGQHvFkZ2tqQAg=us1jA@mail.gmail.com>
 <CAK8P3a2d3H-pdiLX_8aA4LNLOVTSyPW_jvwZQkv0Ey3SJS87Bg@mail.gmail.com>
 <CAKv+Gu9p017iPva85dPMdnKW_MSOUcthqcy7KDhGEYCN7=C_SA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKv+Gu9p017iPva85dPMdnKW_MSOUcthqcy7KDhGEYCN7=C_SA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=PJubyZXg;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Jun 21, 2019 at 03:50:02PM +0200, Ard Biesheuvel wrote:
> On Fri, 21 Jun 2019 at 15:44, Arnd Bergmann <arnd@arndb.de> wrote:
> > One pattern I have seen here is temporary variables from macros or
> > inline functions whose lifetime now extends over the entire function
> > rather than just the basic block in which they are defined, see e.g.
> > lpfc_debug_dump_qe() being inlined multiple times into
> > lpfc_debug_dump_all_queues(). Each instance of the local
> > "char line_buf[LPFC_LBUF_SZ];" seems to add on to the previous
> > one now, where the behavior without the structleak plugin is that
> > they don't.

Ewww.

> Right, that seems to be due to the fact that this code
> 
> /* split the first bb where we can put the forced initializers */
> gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
> bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
> if (!single_pred_p(bb)) {
>     split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
>     gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
> }
> 
> puts all the initializers at the beginning of the function rather than
> inside the scope of the definition.

Do you see a sane way to improve this? I hadn't noticed that this
actually moved it up to the start of the function. :(

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/201906221324.C08C1EF%40keescook.
For more options, visit https://groups.google.com/d/optout.
