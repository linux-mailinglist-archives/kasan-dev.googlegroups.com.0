Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75F733AKGQEN7N2I3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FF2A1F3D0B
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 15:47:44 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id ge4sf2404616pjb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 06:47:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591710463; cv=pass;
        d=google.com; s=arc-20160816;
        b=sTgwVjVuzo5Pb3+xKAG55oK+XCTEm47q4gFSK57kKZXTxn2rMAIdIIFxF2Vo1+bSpI
         xOyKsGgDFU/S++IVAmC2ifDUU4vpLceSgSFscVgfo0RThaA3ggsQnGI8M77mmjReBkkE
         pJsafu7DsI6gXrKRhI4voNuhQPfEoshL3iri/DVIdfVlUwLYOWQNZi5oE/sYiWhPSJXZ
         fiT1ckiRB7IKAKEeIZFwCY3hP1ByZL510IVel+pwH8lrAbfGYyuMIwXFKUpaQZy1Kp75
         J6Ineu9F1+SozwaA/z6sXaTuR+19Nv+7mmkMZgz3kFrfIdU4fOQv1hop3/tFzqeknDSF
         5bHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PjbZVPIqFBd6C2Lpoyi2UD9xj5WTgvASh5ZjWr4btoU=;
        b=lJEirFcWIg/Zqnl+35LiohyWFiHo9+7MsyL2cHCEuK47r9EMCPXUDG4AParFooS/83
         2WdXRUdbBTmRsjGxAQRlIO2huK46R+pRL9LFVZcvM+x8E15TPO7Zd5+2T1SBcWxSQPFY
         7yRqxZbne0AJRT8ukUc9WGfNnD8JArZ0clHdg+WHvBIGSMrXoDXSOKsAG/VFshtBIZre
         e7QlLEyPstWaAmPAR52Kgzn2syRcUtanfib1WgGf6+tyPf5/rhOzaGMRC3NTNhMcmSQz
         KtcCwIqdhX48FNL24vbOL4YctVKOUd4WMNGcWyAU5l26TC4gaQDeZY7GoXUeK/ODawuV
         2oig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZfdkF4+s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjbZVPIqFBd6C2Lpoyi2UD9xj5WTgvASh5ZjWr4btoU=;
        b=jB9fPnSkyNdasG6WjtBH7kyEX1xosPzImK5mrJrbaas5NbM5HLDR5+jviajNc5t71p
         BKUPfyix94SDio6tNeBAfmc3rNBY9YjhbE/SoS1ZsFIoV04QKh8NvnP3u6MVLVipNVvP
         M743lwZMFC6/jfitJxlaPGtWVLGhE4efPW310ZhLvwPFPmL1669QKvrCnsfRcA2JNgFF
         MOrbkDSk0RT+QuuWfbyP6498580b2x6WpGrmW2Z0XZYmtNGoA6KYZdNYN1uQnBibQl9w
         lIpmH/Zixs10Iz/AXe6A+ooYnIvG60oTktNtCVhTo+TUfLnvw2ABbsBBEwDE0sQ/4B65
         or7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PjbZVPIqFBd6C2Lpoyi2UD9xj5WTgvASh5ZjWr4btoU=;
        b=ODJk6W37yxLxdPZrpmKAxW0gvAfVxC3oVSk0hSetatH2yG56WkkPblphpFxinEO06I
         xWSUHTg/makEXxw09Ux5CF7ol1yWItXdtiJaMYdmfzHXzcj7NdWfezLF+0zbK4C57s28
         ZRJdx+m+y/uYJ4Kf54krPnpZBlYnrQpVLeI5oGdyUMIH0zoNjCt9V88DwNTNybzh0mjt
         OfwKYoKZgyA3flee1ovzYlE67AiLHyotdkEk3p69eGpaCcM/X1cUrxAUioUrJyYvBgld
         471UpeVNYK8MbwpNe/x9fbZpQVl64GYOmrwHt/oaOqql9CFbn+HFAQxIf9nyv3SJM6qh
         qX6Q==
X-Gm-Message-State: AOAM532O/0RRBqasjNecrQJE5jWlhvPNUq3AnkXs2+N6hKhJ7ISYD+By
	7s0GzdRnlfhEv7hvapkJig8=
X-Google-Smtp-Source: ABdhPJwCGEKPOzTOCFduoUWj8FgqI6cwLl4hmmECzOJDi5xiRjMhNna3XxaJJmagezMin6LA938vVA==
X-Received: by 2002:a05:6a00:148c:: with SMTP id v12mr25305496pfu.171.1591710463119;
        Tue, 09 Jun 2020 06:47:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls1487042pjx.2.gmail; Tue, 09
 Jun 2020 06:47:42 -0700 (PDT)
X-Received: by 2002:a17:90a:fe0c:: with SMTP id ck12mr5132540pjb.209.1591710462615;
        Tue, 09 Jun 2020 06:47:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591710462; cv=none;
        d=google.com; s=arc-20160816;
        b=HZfZeXvGauDeEZCbn7HUk36gOG3P+le/imoiexyF4eo3M9GoKP5M3oUinKtEX1HW6a
         F0BXGrVay6sXkDmU1lv3YWLYhFnWpNNsTK3NzmUQBTDrOgxRiaz1xbcD6dWHI8r/Rg+i
         BPU2/UIKYA4yifE19yphhCK78s/4KX8bgi4cSdsUNu+Tidq7pn3Hbm+kfCAU3iL0AVaK
         zkCNvV/jT8/Hg0SxoNkiFEfKLlhTvxTJ5NfC3Ikca3csZlFFZu5ie9dsFfGdC8uxuFo+
         3T30vKOyiupg9W272EfQXGqduaqMttQp+9hCD02etKyMKAZKXHX9e8iP38jqvOuGsrQ3
         x8Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jHoTHjw1WYJgjqqOncQzL8W3wPe01tNTYUfgHT6QPws=;
        b=x+mPdXyKcjavHI+T7bY1IdH4Lq6zG3emzkqPyI8MSeHFAdHnXfdMOozWF98qP7DGpm
         DIGHSEk+stuy3jMSzbpccUyw2j4uYXAe9R2EZrmTI0FE4Zj0uTo4NmbIsewCNX3ngss8
         0q2HbW6i1whHUf4T2jG5n7VAyWqwgvVKeR77eeOKnXO80MtubLqs2G8+CNivwMecyTP4
         lJOYknrRx2i4E8bEQrL6ZNApCnEB+GSP/MykmcQGT1xVHif0WsGjY6sB1RTnWQaTprjO
         FIkRsAEcdXlijWcGP4AHISm7bdCxiInBQ+ERDHZ/f5JZPgGelwPh+UOroc6j6LnezkPP
         tr+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZfdkF4+s;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id t23si323635plr.4.2020.06.09.06.47.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 06:47:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id a137so18791325oii.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 06:47:42 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr3536892oih.70.1591710461765;
 Tue, 09 Jun 2020 06:47:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200609131539.180522-1-elver@google.com> <20200609132216.GE8462@tucnak>
In-Reply-To: <20200609132216.GE8462@tucnak>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 15:47:28 +0200
Message-ID: <CANpmjNMhKeg2KkY9K-8W_iwsvZgf3_s9rWOcU6nE=Un9_uVewQ@mail.gmail.com>
Subject: Re: [PATCH v3] tsan: Add optional support for distinguishing volatiles
To: Jakub Jelinek <jakub@redhat.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZfdkF4+s;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Tue, 9 Jun 2020 at 15:22, Jakub Jelinek <jakub@redhat.com> wrote:
>
> On Tue, Jun 09, 2020 at 03:15:39PM +0200, Marco Elver wrote:
> > gcc/
> >       * params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> >       * sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> >       builtin for volatile instrumentation of reads/writes.
> >       (BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> >       (BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> >       * tsan.c (get_memory_access_decl): Argument if access is
> >       volatile. If param tsan-distinguish-volatile is non-zero, and
> >       access if volatile, return volatile instrumentation decl.
> >       (instrument_expr): Check if access is volatile.
> >
> > gcc/testsuite/
> >       * c-c++-common/tsan/volatile.c: New test.
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
>
> Ok, thanks.

I think one of you has to commit the patch, as we don't have access to
the GCC git repository.

Thank you!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMhKeg2KkY9K-8W_iwsvZgf3_s9rWOcU6nE%3DUn9_uVewQ%40mail.gmail.com.
