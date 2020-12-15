Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75I4P7AKGQE7FG7TOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id BB06A2DAFEA
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 16:21:36 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id ob4sf8846408pjb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 07:21:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608045695; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQ+IGgCG+EPwKkNtxYcPUij3N3SjeJtYAYJ6UDMiSWmiXMqZZL2+2hDGAWrtG0dVBJ
         LKLNRiU1ft4LymDVQIqan53d40oPZzSpzeN99h5JXxM+qUB07KREG1mM2hCQs+nal9gw
         Uc+h+pTl8clufMXpea7dqz5Z+ISlSCUzoB7348YZQO+27lE/jYKzS5/rhnXq63jr9MZ5
         GH/kO6sABqp7Mc1NPToRc7qqE9Bqmhp6QJ6rSWzWdNcPkpn0dYnv50Abvm9Q6TOMEWy0
         EjyCkm7qTJXuD5oVqDJqRGaYO2F9SyZ299K0hP0ouXitMtPE+SAIz0MUDzv32a9n/8Lz
         1CLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0ndf87aI7tUdzDKVsuybcn8YFNYMoF94MDHZDIPgPN4=;
        b=BMfdUcZtd1YhXDyj/JSwXhOWuo2cinM5AV+/Fkk44uHpeD9A/sb/AaYsSWT9Uyka6g
         YZGYWa9F2vbE+TQ9FlS7onO1j9Bw/MHWMub8j7tLc+18PG3WplyjbRGXPvVFOkZGZBbJ
         voxbayuhwXf1MJbrKnYGHJzS4kQXCSAd2zaoBzc3Cg75mxFIyy0H/N7alcHbTYGSRgMt
         uyVafQW8v7e19ISJukQIhWITuqeLh/DsY6af/uC8EdXmxK7WQWCo90w4EVfWNSRk6JbO
         2zaE7ZU2/kvYa3KHwnO4vnat9u/t1HcYOkUAFghsbxnRiXk2eFQIFzVYlSUI0buxEoVN
         VJDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aXn6XXpt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0ndf87aI7tUdzDKVsuybcn8YFNYMoF94MDHZDIPgPN4=;
        b=hXaPnBqCpfSuXS56Zl1UhrFZpgLLuRpXA3jz1AzGJLn3W2npZfU1zZoSTiqn07W59H
         8H144+uhNZUFqE7H/oelPecQ771WSxicHjBIQ7ifMkRzlT0v2WClUUu/Kl0VPAUjKEEW
         YSldB3j9fH/fcELeX/4nLcdAftbioSGAJDVrNsBg671iBRC3nGUdrZ8zOq5n96QhhjRH
         Zwfk9ELdiM986Uz1J1F/Q8rYUbvj+scFcdv0DTyMr+Esfr9igjyl7iJnr2F3o5jnWoVs
         r9gu2/WFCtucKqUDZdlpMa0FJwvsx70HiglRPk+AAxt0OF0sV3eENlLWwGlxFoN49wSo
         ZR8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0ndf87aI7tUdzDKVsuybcn8YFNYMoF94MDHZDIPgPN4=;
        b=oJS1bCsO3EIbgdVWHHRvgFLwysi1Ao5PUPNja9mtse9QJOjgOLDNQHmSW3PZTK+on+
         Rjfo+1lgne7tYti6/8nZQcoO0jxYRdTQuglREteio0R2yYnIvnYeIEn7Aj6vvQv9KVxV
         xXbU0M6nLwK2nIM5pEHTAkyHSXjIGisXvqysEs9FeeSJXNB6r+epNyoldE9x8CC4f+AX
         RJatG7sDFHH1wSS51ZQsUzyjhyYizj0vmvssnQAIgroTKht+qSeVNa5zrp8C2MIl0iD+
         z99Xlgzfao5mOP91jCjusJTyG1jkyDqjPln752UEN3ZiObRO5b2vIbseps912+wGsZjP
         gRjQ==
X-Gm-Message-State: AOAM533bTSKN/e9yD2mu5+rKtFtgTWMR98R7xuoxt4dDThLtSrWtiCwb
	zIqYUO6tMfqXqZK/zXOjhME=
X-Google-Smtp-Source: ABdhPJyEY7+mDlPvE6EfJ3IQ0oki1YjO3f8+WNBiOuDNxL5GiZU/Oq695a3NrnB82JyrEg8ZYzoKzg==
X-Received: by 2002:a05:6a00:148d:b029:19d:9622:bf7 with SMTP id v13-20020a056a00148db029019d96220bf7mr2952151pfu.11.1608045695323;
        Tue, 15 Dec 2020 07:21:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3192:: with SMTP id x140ls5256722pgx.6.gmail; Tue, 15
 Dec 2020 07:21:34 -0800 (PST)
X-Received: by 2002:a05:6a00:804:b029:198:28cb:5564 with SMTP id m4-20020a056a000804b029019828cb5564mr19538627pfk.34.1608045694692;
        Tue, 15 Dec 2020 07:21:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608045694; cv=none;
        d=google.com; s=arc-20160816;
        b=HmbpbLzYdVTqVfnkNA/xycEB3/exmI166EeM7CQn6Ydgu4kjgOtAfhiJkcHqiimIwd
         xWcKSVFfGsmwfm6nw+hQt0fp+72qw6LEaAj4wMIxBjd6pP4LT/VFvw0PHu3nWBRTN14c
         T37me4h8SIuMXULHGLTMN+XtrFe7quK48PmBzcnFiXwp5qxfIehvmk7MIPSMpd9sN9e1
         psuEFl6bhSt1PwNUBvO1+sX0jnCGCfQFeiVawsZ4ZC4NSXCFdAhCXqjLHyh/Zi5vokdS
         +eb8WP7/624A+Yk0brxZsuVb1vKBy3oC6bYncaq0vGmtFq2ZByXKu1cgrqgV7WRGucXl
         CUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LvvoyCgDrQZe4qMvf+mq/teC4leCnSUcj1+6lsu+/PE=;
        b=nlZLOHCdNxarU07LP8ae/k57+suLW18krdk2AURydmGt17n3rBurhHI6hyNvG2j/SV
         fivkIg27D5VbW2zA+E5ZQccioIgX3jit64fvFBxlDzpBQzWk2SXl+CbFyXSY/NwQGrul
         kI0g427hUkZZsq3EDqqRMHV+ruvJmLHmcyXVpw0db+sb/EfSs+klBpvsHO3Ob8dKuJiy
         UmTaL4OUUO5Y6Q0odx5ybVyJ7T6vhe9QZSETRQFROyk4ECWfUv098slvcE1DXbFOiKqw
         3Yr75xaszRamzXX7vLTBHINxmM++SNLn3UqpBN1ez4Rfv9y010UYAk0VkDwsKehvxn1z
         QXfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aXn6XXpt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id ce15si674535pjb.3.2020.12.15.07.21.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 07:21:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id 9so4916387ooy.7
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 07:21:34 -0800 (PST)
X-Received: by 2002:a4a:48c3:: with SMTP id p186mr22934360ooa.54.1608045693716;
 Tue, 15 Dec 2020 07:21:33 -0800 (PST)
MIME-Version: 1.0
References: <20201215151401.GA3865940@cork>
In-Reply-To: <20201215151401.GA3865940@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Dec 2020 16:21:22 +0100
Message-ID: <CANpmjNOH0fS6Ce--sPk2MPntssdzm6a4BmW21d1b7NHbW=bgTA@mail.gmail.com>
Subject: Re: stack_trace_save skip
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aXn6XXpt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
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

On Tue, 15 Dec 2020 at 16:14, J=C3=B6rn Engel <joern@purestorage.com> wrote=
:
>
> We're getting kfence reports, which is good.

Very good! :-)

> But the reports include a
> fair amount of noise, for example:
>
>         BUG: KFENCE: out-of-bounds in kfence_report_error+0x6f/0x4a0
>
>         Out-of-bounds access at 0xffff88be95497000 (16B right of kfence-#=
46922):
>          kfence_report_error+0x6f/0x4a0
>          kfence_handle_page_fault+0xe2/0x200
>          no_context+0x90/0x2f0
>          __bad_area_nosemaphore+0x123/0x210
>          bad_area_nosemaphore+0x14/0x20
>          __do_page_fault+0x1d6/0x4b0
>          do_page_fault+0x22/0x30
>          page_fault+0x25/0x30
>          parse_wwn+0x20/0xf0
>          ...
>
> I would like to remove the first 8 lines.  But if I increase the skip
> parameter by 8, the code becomes fragile.  An unrelated change that
> inlines __do_page_fault() or __bad_area_nosemaphore() would result in us
> losing the most important part of the backtrace.

It is supposed to remove them. Do you have this patch:
https://lkml.kernel.org/r/20201105092133.2075331-1-elver@google.com

> That seems to be a hard problem in general.  An alternative
> stack_trace_save() implementation could have an "ignore-after"
> parameter.  If the stacktrace happens to come across an address inside
> page_fault(), it would remove the previous output.  Code would be less
> fragile, but renaming page_fault() to something else would still be a
> problem.
>
> Have any of you spent time on this issue?  Good ideas are welcome.

Yes, get_stack_skipnr() (in report.c) is supposed to solve this, but
it was fragile because the page fault handler name changed between
kernel versions. Hopefully the above patch that uses pt_regs solves
this for all cases (it uses stack_trace_save_regs()).

The version that is due to land in mainline will have that patch, too;
only the first version of KFENCE didn't have the patch yet.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOH0fS6Ce--sPk2MPntssdzm6a4BmW21d1b7NHbW%3DbgTA%40mail.gmai=
l.com.
