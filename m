Return-Path: <kasan-dev+bncBCMIZB7QWENRBZWU2SYAMGQEJVPKABQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 281C089D859
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 13:45:45 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2d86adb107esf28622011fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Apr 2024 04:45:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712663144; cv=pass;
        d=google.com; s=arc-20160816;
        b=SoxTkq44B0hCGR9P98DFQyddHbG199iASp3Cq+2sNCQqmoZEtZUprE+YuGu1EykMdQ
         Hk0kCVBKD+d/omeDZ9KRgFzVxx1n7tbNG2NVjGoXli4BM8F51xMEr9Tww5El+P5O+zWK
         7spMYIop6MSodaPXepGtwu0DN8xTX9k+xzcElvpMffUGxCItbyJuiqUXyaJGi2wHP/Ab
         Su546QS2DI9XM93MChN7Yeiw2KrW1SE0FJukyZ7GcpZzFHgzzpuAstqlxT9SxyLxAsdk
         rdtbrfRycRaPAmCV2bfP2li/Q/Us9zfraFARp6ywR7SK20HLULC241C/z0fuFDsfOgxR
         Xj6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hjcShOfE4cXf8BK9XqWwy3t757TRjC7dQ1YBgmrgD6w=;
        fh=SHjJZgkjIiDZy2VcyJcNIf2FB1IWv8A7RU4XTdrznzI=;
        b=C56cZYMhzpFeDpdOnwaViwhYCq+ppSvy3M3jyBp2D4WE60L0Dhb0+VtB55mvJ4s/JX
         eEtdJoF3M4YKi2TC1TtxV/0v2FxLKs0ctvYLTE1SCXxjNgSRucnJ6EJYe8E0wBnadQpp
         +L7eyOM3rhVU+2rndh39eMV09i5Nx4rgkzDaXu7jJSrYYRBd0iFDKT4fzYPIARaWAypv
         kcbVZ6yfdKimihywpWl+k1MsJbbIBQzFyDfuYXDCeqvzrl8huZf7XsFMP274o3Dfb8KO
         ZSTi31SF873QIrvDJddHX9jbb76WRvuEG4cxcRs93xCkKJsftopwGu6J/hSWi0ZAhcBl
         hDLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hrhPBn6+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712663144; x=1713267944; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hjcShOfE4cXf8BK9XqWwy3t757TRjC7dQ1YBgmrgD6w=;
        b=I98CDPgC/syDclfLqY8Ft7WsXbBfBZ60z8nUN/NNY+4PoaT37hxNVGiu1JSGVxZuDT
         lV2zCloaWX8zzZt4pa/KIPnWUe6vlGNYYQK1+A5qUTARL53u59dHWOBpa1jSxUznX+Xm
         hbXSS4fikbU6Cfh7qhL1V6I0Agsff3XLF8095OFAoq51+eM5abrdUsEnleqnsgvAXFIE
         R/xQDg6hIX6HYBxiy/lThHGC1m8F/kR7vpu4BJ+1yM4ISRtzck9sulfMFGyN6QZbebd7
         Tny3Nu1YYJdzvK78tamdpIowYWDvfMQ3Az2djEo7vm3xSj975Y1P2TUbxwDqK9lpMjGw
         gNZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712663144; x=1713267944;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hjcShOfE4cXf8BK9XqWwy3t757TRjC7dQ1YBgmrgD6w=;
        b=X6A76yFx8HXPxNyXlnrYeZVH7Avk4PFgQkuO5clnPywlB0tGm2S5w7dctWfLWCG9iK
         0xkhdb2NI66oRA1l76X2of7u/QwVBxsksJGdIXETgYCDPhZ1oeOqzHnmyyv2/2bxXvXE
         wABahwB3FlAiKdgSxRLDKAu0BqYEOEjeDXz8if3Tym+U7QCIPqM9Nk9eyKeiUnw1dIg6
         VtLt258gU6k0/aJZYakF9ux0bMfIcNd+eMijUsud/MKi1O1JC8ps72AHuMfZAwzcCVQz
         PdMPwEKBakEKeQvgQdHcmh5lhkhQK1ETXWwCFyv1zl6VOWM5Ib7dlXk7l7PTv2QLufC3
         u5gg==
X-Forwarded-Encrypted: i=2; AJvYcCUzFMXi3qXC50A55pvFjCmi0J0UH8Y2G7v7W5/ZQSo5BQhc2h1/miCroMlnCTupamVcIrQYvG8b/GAsywzlAb8VvwcWcUso+w==
X-Gm-Message-State: AOJu0Yz5WY/MY/NoSZA4eKWEGslkMFGVVN3CrNqoCOvg+cg24XZGqXzu
	PdyL0b9VGLgSYiLvqbZY0naaVTXAd2Fh9oa8PowdZBL0bpzXqrdE
X-Google-Smtp-Source: AGHT+IG3bgUI16A4wAJzggi1EFE/dFrg7a2RbV2ybRSXHPXrt3C1bS52u5GTeuXNduZFdchmDhRAyw==
X-Received: by 2002:a2e:80d7:0:b0:2d7:10a1:481e with SMTP id r23-20020a2e80d7000000b002d710a1481emr7094698ljg.31.1712663143042;
        Tue, 09 Apr 2024 04:45:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1ca5:b0:416:7e7e:98bb with SMTP id
 k37-20020a05600c1ca500b004167e7e98bbls852168wms.1.-pod-prod-03-eu; Tue, 09
 Apr 2024 04:45:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUCsiO83iqvKUa2R5HIis+8PWAUWPeZkzMszYnEGDlqAiqspXm7b7AjAdxz1RQwPFrFxs4wtHNQkf6xdNV1HiL4/12EXpUxNONDGQ==
X-Received: by 2002:a5d:58f4:0:b0:343:efb7:8748 with SMTP id f20-20020a5d58f4000000b00343efb78748mr7466854wrd.66.1712663141211;
        Tue, 09 Apr 2024 04:45:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712663141; cv=none;
        d=google.com; s=arc-20160816;
        b=qUY3PKoprbKiwS6paEidg5ia0Gt1MrM64k3rpwK0dfJwn39SuzNpaU8j6RMHU04nEc
         SV4KETnrjXxK7qnRWP3xhLDY4tt+CFT2L26kGOt1GBd59l7k7gd750kJWus5MEZTYWU8
         OQRHBlOZKqqRgnzAMQFqS091qzxmUpPlyMmmMBrYyuluvCIz3aIYtVTYJ3l3pFKOmw7E
         7skbKr1A+S9dBmWgjiL2jXDEl6LSGG/w54XEmsCYAa9t4ye/odCbNWfjl7SG+a86bKkf
         p7CkjBHsd/J1gQT2AWRsKgrIGkPPdWddofGMXpLhS/f2wdAZuPZiFeNndYujLJ7EEe99
         dsdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XdtnM0pMYunPj+eUYeM0gH2TJdeUBrC57PV1HZeV+xE=;
        fh=lSLLKoftVZv4Th+o1qzZJR8ZBJdie0wtODRuQgUZ5zA=;
        b=L65BHWOMCzUvx2by46SgBkP3zy1VJYBszJb03VJKLOfOyDXDXgJ3QWgAW48JaFytj7
         r8zg7PfLuxXXW9fKRL6LofdObtKKQRJKvtsfxnHzhUdkTjEkTuIoi9QtW/cePeS41zp6
         dMV594KmtN9YKGzCy9Ork/kiGC3U6DWNPclmk2VMksAcL6sBTjV2kD3II3hW6gyTD/Qc
         iW/qhAlXbqKyw48RgOnEOEndMVTz8iUH6Oi4MwkasbXulyOeFMl8FKcIC0C9Rv3pkNt2
         JKAjAh9ilLWZEQHWutZ0brG35E/M6+3exZsneyv2H4yzZ6kRjCFGsVi7tJlWdWZ6b141
         fcqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hrhPBn6+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id f8-20020adff588000000b0033cddf15870si287744wro.6.2024.04.09.04.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Apr 2024 04:45:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-4154d38ce9dso73625e9.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Apr 2024 04:45:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgwjxvSib8K68/jZV4T3w68CbGgE8AciM9CystnXq9uBaCb0EdsUBTKObRAvW41evonlIB5vfgzB89iGA0e8YWdRK3zYDAvdtGrg==
X-Received: by 2002:a05:600c:314c:b0:416:7f8a:c6ea with SMTP id
 h12-20020a05600c314c00b004167f8ac6eamr120300wmo.1.1712663140470; Tue, 09 Apr
 2024 04:45:40 -0700 (PDT)
MIME-Version: 1.0
References: <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx> <20240409111051.GB29396@redhat.com>
In-Reply-To: <20240409111051.GB29396@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Apr 2024 13:45:24 +0200
Message-ID: <CACT4Y+ZOn3n+NL=JH-=yNWOv8RWOg_idGqQz10fD-F-FW27M+g@mail.gmail.com>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement check_timer_distribution()
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>, 
	Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hrhPBn6+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::332
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

On Tue, 9 Apr 2024 at 13:12, Oleg Nesterov <oleg@redhat.com> wrote:
>
> On 04/09, Thomas Gleixner wrote:
> >
> > The discussion started about running new tests on older kernels. As this
> > is a feature and not a bug fix that obviously fails on older kernels.
>
> OK, I see... please see below.
>
> > So something like the uncompiled below should work.
>
> Hmm... this patch doesn't apply to Linus's tree...
>
> It seems that this is because in your tree check_timer_distribution() does
>
>         if (timer_delete(id)) {
>                 ksft_perror("Can't delete timer");
>                 return 0;
>         }
>
> while in Linus's tree it returns -1 if timer_delete() fails. Nevermind.
>
> Thomas, I am almost shy to continue this discussion and waste your time ;)
> But ...
>
> > +static bool check_kernel_version(unsigned int min_major, unsigned int min_minor)
> > +{
> > +     unsigned int major, minor;
> > +     struct utsname info;
> > +
> > +     uname(&info);
> > +     if (sscanf(info.release, "%u.%u.", &major, &minor) != 2)
> > +             ksft_exit_fail();
> > +     return major > min_major || (major == min_major && minor >= min_minor);
> > +}
>
> this looks useful regardless. Perhaps it should be moved into
> tools/testing/selftests/kselftest.h as ksft_ck_kernel_version() ?
>
> > +static int check_timer_distribution(void)
> > +{
> > +     const char *errmsg;
> > +
> > +     if (!check_kernel_version(6, 3)) {
> > +             ksft_test_result_skip("check signal distribution (old kernel)\n");
> >               return 0;
>
> ...
>
> > +     ksft_test_result(!ctd_failed, "check signal distribution\n");
>
> Perhaps
>
>         if (!ctd_failed)
>                 ksft_test_result_pass("check signal distribution\n");
>         else if (check_kernel_version(6, 3))
>                 ksft_test_result_fail("check signal distribution\n");
>         else
>                 ksft_test_result_skip("check signal distribution (old kernel)\n");
>
> makes more sense?

This looks even better!

> This way it can be used on the older kernels with bcb7ee79029d backported.
>
> Oleg.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZOn3n%2BNL%3DJH-%3DyNWOv8RWOg_idGqQz10fD-F-FW27M%2Bg%40mail.gmail.com.
