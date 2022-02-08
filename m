Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFHLQ2IAMGQEGZ5K5RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 435B94ACCB4
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:13:09 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id g14-20020a056e021e0e00b002a26cb56bd4sf10100553ila.14
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:13:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279188; cv=pass;
        d=google.com; s=arc-20160816;
        b=A4NR/Hfszvl8Hkz4fLjQ7o2cYZ3rHl03cURPc/lALqdHZUQnvtLh7YSg/7F7VCxDIy
         rrs1AfG0dDdnqx6o/uh47iFH4a0c9weIkkSJd6fwNOe3g6Tb8xqh3/9FxrmOXV0Hm5vL
         YMhTj1WtwPTVUjvO9snraJNwtBksDDMNvKVR7fw7TdrG3bIkrFI5XatAjEQTghLdw6Aj
         md86LDCrcmK3E7K3tqods0lckIT0vKEkbsL80wuA8aLNFJFXqADgmQUa2ecEs06aoK7Q
         5PspDt/P9FfSRs+di/SrbNP7ISOrg/wkmyfT2BYvQP+N9+XQ++olsz2EotwsutSdbqkF
         zAgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1DwRcymdbHho3jTLbGP/t0U7MeowHUf9luSi+4mm3EA=;
        b=HrN3QH2Lua7aenl7MKZoy9U5p06j+h3q0Fd3O+3eJM2f4LZV3zi6bP0t5gCg96rVQH
         U+2PqM8fLRdM2dT9D5MtLUO2FaeEsaXNzFTpTpeQwCHT+R9+Qze0PSW8MJmbu5hjaWdQ
         4iuT66+UZh5bucRGrhG4Dgo18WBAyIxxoKfw/LNydh8BK0QADJYiQr4MlB2LtBJKH5x6
         IHQo1sAQp8HtVfQMVL9J4YOQazfoBmhUNBJlecBnXt8lahEu/pds//JIuv6y7DR9L72y
         CtuiIIusXLdZVk4Z+Y5EfLmIl98wgCZcddpNj4CR7TyX+ZNJPiQfh8X0jHOvyHMhYvR0
         x8SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K80fsiJR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DwRcymdbHho3jTLbGP/t0U7MeowHUf9luSi+4mm3EA=;
        b=CM1SUW+TUW8fegtWxiu0MZXu0/y84aG+siKiM1fHEy18tzrtg6ru08naxK/h06MBuq
         kDvkjksb5o48sOJ6uNYNtsyyP8hr/4wdloBSv1mbBpm0TJkwDrUz8+p4hsmTIi14FjDO
         DIfAjoBntTg3WiPghkqnUTS06LQJkc79QhI+B4GRTXO4/Fo0wcimitjHylrdLFVC/FgX
         dwWmTh/zmjmGUBCgyvvuw7PlWArSmjuL3aNHgZDAT5/w4Eg4N4Cx26pyMkL5n6ddgLB7
         7ikGLNxqDI6JpIhKbTn5ubLYVKtSJxi0b8gMamrgh9H1Opj59vkqznr3MKcrKIlcBTbJ
         63Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DwRcymdbHho3jTLbGP/t0U7MeowHUf9luSi+4mm3EA=;
        b=GYZTLEIU/NsNQFzSgDxx8d5UQwWEkKQCKrEQSjr9ROjGlm9evBgy4veBlE+U0J+3Tj
         v/89yKdXXLc4AC0G7e2gzdB7otNvV1i9Ao/Uyvz7VGM6unZtJQngiNTbkLi4Do7g0V9D
         aAJn2J8dhxSSUhDHvHh89ZbdStlzS4lBVqlu458/HT0raEGshVi8gyn7MgtY6DzQCaxs
         AeteydMCcrqBXr8gn8XAf6GXKCe3Z7bLeVMqMdDTGfp8hsIbNy/bw+PGSFKLr/oGGa+3
         jSNYh94dZh+gNMRYCcX/bAlaLMQnAiJAoV/gz60YoRarg1Ht1qXCK7RMaPAhMgAuQgAl
         TyOQ==
X-Gm-Message-State: AOAM533bpEXCqtaNL8ndgH1j4zp9QHsB9fMWAQPi+Fv+MoHtP4aZdSby
	YmDj6izKDINI8zr6EYYt+Qk=
X-Google-Smtp-Source: ABdhPJxTsiiuZeWDfroMkbpZh8ali84CVKPa7CgYnFpnNASQNBCdXrEVOV1/U91NjWuOL4XgBzS79w==
X-Received: by 2002:a05:6e02:1586:: with SMTP id m6mr989601ilu.233.1644279188261;
        Mon, 07 Feb 2022 16:13:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b8e:: with SMTP id h14ls1816749ili.0.gmail; Mon,
 07 Feb 2022 16:13:07 -0800 (PST)
X-Received: by 2002:a92:c248:: with SMTP id k8mr83219ilo.273.1644279187841;
        Mon, 07 Feb 2022 16:13:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279187; cv=none;
        d=google.com; s=arc-20160816;
        b=Z1mZtQlKFnvbEf99wyGYNYmwWamUKmr4kcvFl+jz79HVV/yAEeSLrg6qC1H54huU5U
         6voo/LD5HSEqjEkoV9+Fzb+j0NY4+mbrenWip8av9u/HG3LxiBxHn7jJbKWadInR7CFq
         er4gmYAWhCEHYBPrd8AIkYCFREYF6HGhka5CZqnI47GME5aN5hUrs/qC4geF83MTUw8+
         /SdYBwomcgHGXANcSHiV9DpXscRg+LS+mW12SnZXRlNK+5u+Eo0n6zglXuLyToTeosa5
         nKVMvvPHdMs3opZSfFG2jbh5xH1USehvZYzMCBIrYueKkzdi4CBMDQXjh7lo4nLF5ek2
         Xckg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Hzy131isDHXr2lMw39S2jrdc5VN4ofTxUYoaMYMBfhk=;
        b=H7fmfjMDnphV5aCpZjF7AJC8OMdpHBkICZYv6HrR9sag2VPJUSP9T8AX8O8664197t
         ON5IpL28wY5kqOiH7DSl+aj9iCBPRoF9GDL2UuDJ3lr+U3NTAMN7GDfq0w2V+MAb9KHh
         AN8htNY7KNUqvts3HzFuIIswGb9GBWfX/k/WctnQ+H99o2X2PNfw3XSU84Zh2K1emcB3
         oL2u+z3oH1pvfbOpOv1V214weqUX9QpCacKB/Z/gu5vh074fpoK5trNOmxiIsV2J9/Ur
         4/zKeymzIZ1YjO4AY+3xrJeiQp1uVNHaxzkC+pd4gAdGoRzk3rRiHH1XjSgFiXSKEBpt
         3mEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K80fsiJR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id w6si508510iov.3.2022.02.07.16.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:13:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id y6so30287731ybc.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:13:07 -0800 (PST)
X-Received: by 2002:a05:6902:1548:: with SMTP id r8mr2560591ybu.374.1644279187380;
 Mon, 07 Feb 2022 16:13:07 -0800 (PST)
MIME-Version: 1.0
References: <e10b79cf-d6d5-ffcc-bce4-edd92b7cb6b9@molgen.mpg.de>
 <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com>
 <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com> <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com>
In-Reply-To: <CANpmjNPVJP_Y6TjsHAR9dm=RpjY5V-=O5u7iP61dBjH2ePGrRw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Feb 2022 01:12:56 +0100
Message-ID: <CANpmjNM=9A+wr_rF9RBy1esVjR+kAH8x3R0cWhZ8bSkL3r=5Hw@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in add_device_randomness+0x20d/0x290
To: Jann Horn <jannh@google.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	pmenzel@molgen.mpg.de, "Theodore Y. Ts'o" <tytso@mit.edu>, LKML <linux-kernel@vger.kernel.org>, 
	Dominik Brodowski <linux@dominikbrodowski.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K80fsiJR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b31 as
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

On Tue, 8 Feb 2022 at 01:10, Marco Elver <elver@google.com> wrote:
>
> On Mon, 7 Feb 2022 at 22:49, Jann Horn <jannh@google.com> wrote:
> > +KCSAN people
> >
> > On Mon, Feb 7, 2022 at 7:42 PM Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > > Thanks for the report. I assume that this is actually an old bug. Do
> > > you have a vmlinux or a random.o from this kernel you could send me to
> > > double check? Without that, my best guess, which I'd say I have
> > > relatively high confidence about,
> >
> > Maybe KCSAN should go through the same instruction-bytes-dumping thing
> > as normal BUG() does? That might be helpful for cases like this...
>
> A BUG() on x86 actually generates a ud2, and somewhere along the way
> it uses pt_regs in show_opcodes(). Generating KCSAN stack traces is
> very different, and there's no pt_regs because it's going through
> compiler instrumentation.
>
> In general, I wouldn't spend much time on one-sided non-symbolized
> KCSAN reports, unless it's obvious what's going on. I've been thinking
> of making CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n the default, because

(That should have been KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n ... copy-paste error.)

> the one-sided race reports are not very useful. We need to see what
> we're racing against. With the normal reports where both threads'
> stack traces are shown it's usually much easier to narrow down what's
> happening even in the absence of symbolized stack traces.
>
> My suggestion would be to try and get a normal "2-sided" data race report.
>
> I also haven't found something similar in my pile of data race reports
> sitting in syzbot moderation.
>
> Jason - if you're interested in KCSAN data race reports in some
> subsystems you maintain (I see a few in Wireguard), let me know, and
> I'll release them from syzbot's moderation queue. The way we're trying
> to do it with KCSAN is that we pre-moderate and ask maintainers if
> they're happy to be forwarded all reports that syzbot finds (currently
> some Networking and RCU, though the latter finds almost all data races
> via KCSAN-enabled rcutorture).
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%3D9A%2Bwr_rF9RBy1esVjR%2BkAH8x3R0cWhZ8bSkL3r%3D5Hw%40mail.gmail.com.
