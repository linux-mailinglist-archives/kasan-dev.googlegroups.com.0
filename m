Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHPKQ2IAMGQEAVYNIPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CF83A4ACCB3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:11:10 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id o8-20020a056e0214c800b002bc2f9cffffsf10116157ilk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:11:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279069; cv=pass;
        d=google.com; s=arc-20160816;
        b=VImO1mCW6cXHtJ1imqbRnLRo/xRfql8fh7VnWIHd/dR/Z/emTAW3HKIM9vzj8s75Gp
         AX8S+JJ5zhOAbypqiwPZ68XJgL8JkGgH2Ndz4v8xQpKF/3daZY4HYNYPdZCHPRyZfsqE
         9UmQIm/8faeGcql1aQKc7l28zi3lNFPFzHMfcCtqZXWNf6yVWCGh48tH3rjzAMtvv7dB
         nllBKjpyg7Hd5JkjxhXARjKqHR6LhAaZwxKd1lpL8A5Ut2YhkN8DSqJnWD63fZswdL/k
         BAoOBohsy2WwLi/wbboPJp9uHK6BIAEFZWbuAdRrmnmz+GgOfZaDsGpE+pM7gwOwhmiN
         tU8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JqDYPE7fgfQ0weKFl96pdFoUkrvsz1kBO7S0+iFpUWM=;
        b=b7dd3WvZQpjtjRF+/HIKtjwwmv2u7+s8mvJWTBbRlmS5PNucvGJiO1ahP/+71g2KBQ
         S1xqsG72Jjw+KOTq0MZ1VqRiO6C1x2gORSf1CBt2qjo2usKZMzgHG8L8nx9806BQg/9n
         J40da3WDRjRCq7itduZaWtDqUDQ5NXkeJ1zpMCX4buHx5qrclZbqbgClXLFKGe9CR+4e
         OS7evokV5/MRxRosntKRhKGW6buGr4xOJFZGm6c2AaALe3PZ5VslicTvyKwv9KencTFK
         u2ElfLC9x6MwU3tOpmdH1SKcp0DbxZjhbPwJ6bZ/GQ35P49SdvaXs8BYuo+5HPZNVTEm
         mZ/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hac8v4TT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JqDYPE7fgfQ0weKFl96pdFoUkrvsz1kBO7S0+iFpUWM=;
        b=bMUZSbTVNpNBydQQjFcTVSAhyElb7SIYDyqakfuqNvkhYTTqFci+6Xr/1IlY/HRaAj
         KfP8nkem4PIpPctE99nVS4HdwtpotkaiunnSgRkhhp6iXk0RD1RE6ZgsqQd0kxxpXkrM
         M0UMWo5LeYXozoa0+wVN5jjSQZTh/k49FDtqupPhNV36vLJo9wCRAdhIbDa4uZLjouV1
         GNoBtMCYj9uEDVPPH9ZvIB96Qi9U02cFEaL9aaGdTSMx+UTPMJ9mcDHqnGVA4dskbx7B
         qPcgrz2BJUOf/MoueuOkXFEQUZkWAzIjYf3Ef3jpKEdrDeC2H0xMWXxOC9P5VkovYuvB
         NRsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JqDYPE7fgfQ0weKFl96pdFoUkrvsz1kBO7S0+iFpUWM=;
        b=RVKr62+GzAusFO0MAGwa5c4ZN3S538u8eUy2dTBwYua4u8lnkk4Si1NCSfXUqqn+Yv
         TXkWNcEIX0cysYiYSHSy+b87EURRUdU3AYi+WgVQPsgJdCRciNKHPqPoPMIRweP8j3VB
         8v3xGNddC35aGiCJZmJRfGL4Bn58avRzr7Azw7ztHQF8CnSh6Zdi43OehcLPCvb7XIfi
         ZakupXM5oB6YTM+ZnspEUNAraBTt2ilHJmR0ieC098HwbGx08jEsxXWmvLLEKVwbgdqI
         qMf09mU0d6m+3l6rutK6MfQEHt+JyWIq2Ud65wg+CuPtFOa9Re5ZJ/QioyjDpVEKsPzC
         TZhg==
X-Gm-Message-State: AOAM532i6mgrEkmq8U6eUDq1VM/yLf9O+DbEjkUlcSfzqJcLIR4y35bx
	A41lMKdqCfgF6WOEwQvORVo=
X-Google-Smtp-Source: ABdhPJzrFEErTURGLvNeKc+PcSqxJYL1IRVmD1txZzlrjgsUUC8vyPawGwU1npiy/Uq9elleQ22pYg==
X-Received: by 2002:a02:83c1:: with SMTP id j1mr991620jah.185.1644279069396;
        Mon, 07 Feb 2022 16:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3395:: with SMTP id h21ls1801837jav.4.gmail; Mon,
 07 Feb 2022 16:11:09 -0800 (PST)
X-Received: by 2002:a05:6638:2506:: with SMTP id v6mr1025730jat.94.1644279068990;
        Mon, 07 Feb 2022 16:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279068; cv=none;
        d=google.com; s=arc-20160816;
        b=nCeO+WcjEUNB5F8xOiO/oIoyl7PkJTLdD9g28zIGS8jzxHwL4uTkWa6ftuxkEixWnT
         oX79Zg02A2Mtldrgl2H2ZwLg6nv/V1QOT07IPBUhqxx4Hl+HjplGttlLTjM6d5Uyr+YH
         CLTxl+n0X12kHStwpAz0ZjIlnoNUmUhc7Ze6SSt1crBV3UX8RSuGcydDK7gwmIebFeJI
         NryIlsUp0QGH0xp0YB6D71OyL7LLpGa/1f2XP1yFgJkcAqC6NdfYVpGRkzO1Cpv+FgYL
         7Um4EbwQBG1yAh05zbk8NekSclLhvT6cX2nHX0t140hsnfWbzsaGDB+kFhMVYLTqwFHX
         l0Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nzVf95jt9Q8X/Ra0n/mrM0IlQCfTHamEzF56FJSu1k4=;
        b=z5dSZ8NBCM6mNA9sIULKX/7SpQ05marAeDAoGWPj9hm/CoTRkV/PfvPmV/cUUkRJQh
         rVN2Z5okEGi0FpnxlJ+M8MWY8idoBTQQRImaklpk2XsGGFtM9HO9w4WaMXRkfzVCFapC
         UWiH9hhK5xQRpozK9icCLJgtCc6d4es3fqX4trFL0tTmvAgtv6lsssGDB/x9tdT3WRok
         4U9297vBE1Obo1ZPHap9Um8FlLtc8ZQ+OL9rWHW9NI09Do2b8UCP4ZKqiFwKIPDLiUEn
         LgcgI21afUQGiTmV01aP/jQVMq8RHyPBdcpEPOa3w1GfEDeoRkj5H8+Dwi0ASAaWriS4
         PC4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hac8v4TT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id i8si1216517jak.4.2022.02.07.16.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:11:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id j2so45216660ybu.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:11:08 -0800 (PST)
X-Received: by 2002:a25:610e:: with SMTP id v14mr2481774ybb.722.1644279068498;
 Mon, 07 Feb 2022 16:11:08 -0800 (PST)
MIME-Version: 1.0
References: <e10b79cf-d6d5-ffcc-bce4-edd92b7cb6b9@molgen.mpg.de>
 <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com> <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com>
In-Reply-To: <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 01:10:57 +0100
Message-ID: <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in add_device_randomness+0x20d/0x290
To: Jann Horn <jannh@google.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	pmenzel@molgen.mpg.de, "Theodore Y. Ts'o" <tytso@mit.edu>, LKML <linux-kernel@vger.kernel.org>, 
	Dominik Brodowski <linux@dominikbrodowski.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Hac8v4TT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Mon, 7 Feb 2022 at 22:49, Jann Horn <jannh@google.com> wrote:
> +KCSAN people
>
> On Mon, Feb 7, 2022 at 7:42 PM Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > Thanks for the report. I assume that this is actually an old bug. Do
> > you have a vmlinux or a random.o from this kernel you could send me to
> > double check? Without that, my best guess, which I'd say I have
> > relatively high confidence about,
>
> Maybe KCSAN should go through the same instruction-bytes-dumping thing
> as normal BUG() does? That might be helpful for cases like this...

A BUG() on x86 actually generates a ud2, and somewhere along the way
it uses pt_regs in show_opcodes(). Generating KCSAN stack traces is
very different, and there's no pt_regs because it's going through
compiler instrumentation.

In general, I wouldn't spend much time on one-sided non-symbolized
KCSAN reports, unless it's obvious what's going on. I've been thinking
of making CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n the default, because
the one-sided race reports are not very useful. We need to see what
we're racing against. With the normal reports where both threads'
stack traces are shown it's usually much easier to narrow down what's
happening even in the absence of symbolized stack traces.

My suggestion would be to try and get a normal "2-sided" data race report.

I also haven't found something similar in my pile of data race reports
sitting in syzbot moderation.

Jason - if you're interested in KCSAN data race reports in some
subsystems you maintain (I see a few in Wireguard), let me know, and
I'll release them from syzbot's moderation queue. The way we're trying
to do it with KCSAN is that we pre-moderate and ask maintainers if
they're happy to be forwarded all reports that syzbot finds (currently
some Networking and RCU, though the latter finds almost all data races
via KCSAN-enabled rcutorture).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPVJP_Y6TjsHAR9dm%3DRpjY5V-%3DO5u7iP61dBjH2ePGrRw%40mail.gmail.com.
