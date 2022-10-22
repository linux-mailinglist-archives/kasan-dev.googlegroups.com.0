Return-Path: <kasan-dev+bncBD6ZP2WSRIFRBB4ZZ2NAMGQETH7M5BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 875E7608509
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Oct 2022 08:24:08 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id w20-20020a05640234d400b0045d0d1afe8esf4663042edc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 23:24:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666419848; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lre65DsCYeVU3REZ+R5xx1X7S4P/QEnjSiKDwkQg8C5DEjJi8basBgCkkZMY7UdikE
         kpTnvxAD56ISelAkhIuY/6rXcv3tzLndhss7yTfdF6enAm08QHoe1S+bbJ1g2oFIQL/m
         AUzDliErHJzWPOXvcrQ30aRonGU3/fQiivv/hrNzvLYW9yyk/SUriSICEEVzJn6zPwC7
         1x8bVPpoO5awd/qcLcwsxXqmQmv4ydJJHn2KWXr0+WHrtCeLar6JEAB55wO3XAvm4QqW
         vrNxiBdAODnUro4wP6oCO0UvBVNV6WhmVoTc+EOFCg6lqzu7pUc/b61/o48nQWUHAN1f
         Isrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=FhK+bZMASi1E0zviDiZ89SruWjHdhcoTonszX8UkjRo=;
        b=Sxo6P+7FnOqz+cDhaDN3u2/qFP0Xh1MyK4/XzObHvDBaqtlvwgbi/63wDirPbcLHxr
         HwXPCkhN5uYdJhSuis7L/lVtEd0iGHcqulXpTiSblXBtTjS1bbKscPGShShjUIrNwXM7
         7Sw9U2saHVwd11tbVt+6mMb74dZw5FhdxKd4ncJfBAUNka7aT4LnXs/pdModGtFl6nMV
         050wQ5A235JRxkulxtvAyHpd2MzKLNrEs3UzkBe9EIodQnm+JqMLoLJ2/tTQFpn3sboq
         OC5loHXU0RmOS/JGe7Mde/Z5rt80pY6JlYv7He4imNrisOBBhAqzv1UczYaiE0e26Jrc
         SHNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ArxARJFV;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FhK+bZMASi1E0zviDiZ89SruWjHdhcoTonszX8UkjRo=;
        b=HYGm2Sox/zM41fi/o0wZ0Wb0/+bTMv7oTMNtMkBo5VJrri4BE3yr/Roak0EnIdFeOd
         pFY6xcsrBVKrqGAZjSYRaKwtTzHVQRd4gYT2OxHwimeb/LV8eHf9fA5MU/msPMKWrq4P
         Utvr0kbFtW30tLKxklzWt665imcgITxYrRje0RpBcg28JMDCfA963cbxjRzNg9CLdgzN
         rJ8+N9wId5psgJz1ttPf5LjkL4SMv/FFJX+rqjUeKcmWMXZhJPYsrEAYs6VRUn9CFm5h
         Qr7C7rapyOfTgE7OrLbD8CjSafheRLPV51m9fNcVhTj6u+hNDDbE2LUglaV5AefG+68u
         izJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FhK+bZMASi1E0zviDiZ89SruWjHdhcoTonszX8UkjRo=;
        b=eUWWjndEuCo4hu9QHO0oAyXP9gN2L1mpCJiomK147ihWRC5d6eAi2ljNqI4Sn2GHK7
         /BwtuDC81ajf4Rj0b4TcUHm1AfT3HgFwHwvdlqRD5+8OPn3AwXAmXQVZbdSkKJrcnsSd
         Euhx173s/9Z7om5InT6iS5+Bl35OaNeYu1eVKgmqXFwC7fuJkUByDTxrW9ckPMMTRFK/
         lOl9WWubLiYGNNwErazRvFK+IWTh/VbtUvwsmmKk+w+UDmZnCS9yIJtHbGLuLzArttym
         dhFF2oHmGOJWoIK2zKMhqUJpol/HT2ROaplzeOPfapeuoMSdZABCpxWMgOvMTW5aoA1o
         kIKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FhK+bZMASi1E0zviDiZ89SruWjHdhcoTonszX8UkjRo=;
        b=N3cxvTif+uK/oMPRK17eRQrrN+c5acmT5BGEbTdlAwSFnhAyO4a0P+YTiVtacpwyRF
         kM72zgkdIvPZGbmO7EgEMmF4vBTr3Im1UTbrtrrt4V0R00BBMaeabSRssZkf0o+KQeLa
         HIEWm1qvmPalg0mg1rLeRPYtMyHti+RTyVzN5XbvwKAZpsLxcLcbT87AhF1xuNjUeAfG
         qDiUg08VQZwoJ9G8hzHo3LyDOKFklCl4i7Xfa9V8yS5Fdw8WwfXzonPg9OmROdQG1GeX
         oTokw9pa2R8W1HnlWV2SfyvotGe/AzTP3E/v4WjPJELfp3ynT4MwR/ICcwv+U2wn+Xs/
         PcUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0sF1pYpOVRgJu2zB2BNtNDfXoDORKTtFE9ZxOsWFVJO+BeCnKU
	oMY3VDWz91FxxjwAoD974Mg=
X-Google-Smtp-Source: AMsMyM7lRCylGVWK/YVC2iH6MQoOvoH6sxl0E/rmdqTn3B63dTol7QG8tjboBgncbTzEWsYEUAwG1A==
X-Received: by 2002:a17:907:7635:b0:78d:c5e9:3e57 with SMTP id jy21-20020a170907763500b0078dc5e93e57mr19030068ejc.204.1666419847893;
        Fri, 21 Oct 2022 23:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1b47:b0:78a:6e59:3a74 with SMTP id
 p7-20020a1709061b4700b0078a6e593a74ls2412490ejg.4.-pod-prod-gmail; Fri, 21
 Oct 2022 23:24:06 -0700 (PDT)
X-Received: by 2002:a17:907:2cca:b0:78d:ec48:ac29 with SMTP id hg10-20020a1709072cca00b0078dec48ac29mr18687071ejc.114.1666419846698;
        Fri, 21 Oct 2022 23:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666419846; cv=none;
        d=google.com; s=arc-20160816;
        b=fHHQDCZK1IHO6F4HyIeh5UeuCc74d4CXNjEP8da5TL4WlxmLy7u6ilmquneKOwdFJm
         g7DlZKPUvyHb5xSB4Z52MG1W/gnjQj9UIMwsmlPDhqNtERPVri5xljqYglmn3f4yJvgt
         d/utL0oepbTHcofYysPs+hmYKjIzeLdT1gYYB4guSBB+DPjnAEBipSvddQmqAk6Lw2Yo
         VdNvQmr2Pknj+oCzu85dC6I8PAX3J4TGKkVeB2MPLZF8/TKIaBrEHbpH9Lxn8aij0qH3
         5/y0Wm0eDljx5lPMPecKfod8HEpr/XxE435tfJ6uT3XMHZXQChn1MfXNFWcDO5/HUoqr
         jJ3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=Q3DG5ojxl17Jx3b6LFi8HNNnUkTD/weGMM5iXG8GMb4=;
        b=NLG++NsmXapFl840KcFt84NqDJz/jiFYEvaFDJAqSiboQyugTxvig1WwYCSaHTp3Nd
         XbtnkQgVuPkzS7AC8KCx+BmbY/Gb4XQiyitl+8c+VnDgb3QE5ijH2M45mz6uopWFUNdc
         2367fzgihvmXetKpCpvHCprF3DhpQkeyPDbVes04zPTuuAfydqqwqPTqZJTBd/agmWNL
         ARM5w4pt8W99+AaaqZyA6yM4BxrrlKxOo4N5HAfMPDWRefoCCS/hT5lB0zH5yQv6AQYz
         h7u1Ol27nh6BUDZpE/iG0l9gzeipEpCC1WHdUPUDoLbwClIIupdIMUxyuK9Kj2xH8JS2
         YIGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ArxARJFV;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id a16-20020aa7cf10000000b004595ce68e4asi932024edy.5.2022.10.21.23.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Oct 2022 23:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id g1so8601376lfu.12
        for <kasan-dev@googlegroups.com>; Fri, 21 Oct 2022 23:24:06 -0700 (PDT)
X-Received: by 2002:a19:7414:0:b0:4a2:260e:6408 with SMTP id
 v20-20020a197414000000b004a2260e6408mr7905720lfe.366.1666419846130; Fri, 21
 Oct 2022 23:24:06 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Fri, 21 Oct 2022
 23:24:05 -0700 (PDT)
In-Reply-To: <CAG_fn=UVARRueXn4mU51TkzLTpZ=2fKNL7NAB3YH7mGP71ZhUQ@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
 <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
 <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
 <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com>
 <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com> <CAG_fn=UVARRueXn4mU51TkzLTpZ=2fKNL7NAB3YH7mGP71ZhUQ@mail.gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Sat, 22 Oct 2022 14:24:05 +0800
Message-ID: <CAOzgRdYhgu3v_e02RFHi3+vCjYc1kmLMgy61zEX8P=RZQ4bi_w@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ArxARJFV;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

I test this patch fix my problem.

2022-10-22 4:37 GMT+08:00, Alexander Potapenko <glider@google.com>:
> On Fri, Oct 21, 2022 at 8:19 AM youling 257 <youling257@gmail.com> wrote:
>
>> CONFIG_DEBUG_INFO=y
>> CONFIG_AS_HAS_NON_CONST_LEB128=y
>> # CONFIG_DEBUG_INFO_NONE is not set
>> CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
>> # CONFIG_DEBUG_INFO_DWARF4 is not set
>> # CONFIG_DEBUG_INFO_DWARF5 is not set
>> # CONFIG_DEBUG_INFO_REDUCED is not set
>> # CONFIG_DEBUG_INFO_COMPRESSED is not set
>> # CONFIG_DEBUG_INFO_SPLIT is not set
>> # CONFIG_DEBUG_INFO_BTF is not set
>> # CONFIG_GDB_SCRIPTS is not set
>>
>> perf top still no function name.
>>
>> 12.90%  [kernel]              [k] 0xffffffff833dfa64
>>
>
> I think I know what's going on. The two functions that differ with and
> without the patch were passing an incremented pointer to unsafe_put_user(),
> which is a macro, e.g.:
>
>    unsafe_put_user((compat_ulong_t)m, umask++, Efault);
>
> Because that macro didn't evaluate its second parameter, "umask++" was
> passed to a call to kmsan_copy_to_user(), which resulted in an extra
> increment of umask.
> This probably violated some expectations of the userspace app, which in
> turn led to repetitive kernel calls.
>
> Could you please check if the patch below fixes the problem for you?
>
> diff --git a/arch/x86/include/asm/uaccess.h
> b/arch/x86/include/asm/uaccess.h
> index 8bc614cfe21b9..1cc756eafa447 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -254,24 +254,25 @@ extern void __put_user_nocheck_8(void);
>  #define __put_user_size(x, ptr, size, label)                           \
>  do {                                                                   \
>         __typeof__(*(ptr)) __x = (x); /* eval x once */                 \
> -       __chk_user_ptr(ptr);                                            \
> +       __typeof__(ptr) __ptr = (ptr); /* eval ptr once */              \
> +       __chk_user_ptr(__ptr);                                          \
>         switch (size) {                                                 \
>         case 1:                                                         \
> -               __put_user_goto(__x, ptr, "b", "iq", label);            \
> +               __put_user_goto(__x, __ptr, "b", "iq", label);          \
>                 break;                                                  \
>         case 2:                                                         \
> -               __put_user_goto(__x, ptr, "w", "ir", label);            \
> +               __put_user_goto(__x, __ptr, "w", "ir", label);          \
>                 break;                                                  \
>         case 4:                                                         \
> -               __put_user_goto(__x, ptr, "l", "ir", label);            \
> +               __put_user_goto(__x, __ptr, "l", "ir", label);          \
>                 break;                                                  \
>         case 8:                                                         \
> -               __put_user_goto_u64(__x, ptr, label);                   \
> +               __put_user_goto_u64(__x, __ptr, label);                 \
>                 break;                                                  \
>         default:                                                        \
>                 __put_user_bad();                                       \
>         }                                                               \
> -       instrument_put_user(__x, ptr, size);                            \
> +       instrument_put_user(__x, __ptr, size);                          \
>  } while (0)
>
>  #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOzgRdYhgu3v_e02RFHi3%2BvCjYc1kmLMgy61zEX8P%3DRZQ4bi_w%40mail.gmail.com.
