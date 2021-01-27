Return-Path: <kasan-dev+bncBCMIZB7QWENRBFPEYSAAMGQETDJELRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AF753056E3
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 10:27:50 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id 185sf1017886qkl.6
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 01:27:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611739669; cv=pass;
        d=google.com; s=arc-20160816;
        b=zAP/C0UFneRVGDieuGlOwff4vWtwAupqMkpxNKZ5EKmwd/yHuWypfZJa4p4St2CDP+
         FwnyIUxe1widk2ctOOn1MCmlXYtuTKnJnkz5qbAeXQFacioemvBC41DalJr/uvZPuGUu
         5RkbF/yo4chNDXP+Q/YthQ04aVNb0kovypMRq5yc1iSFSHOD+NJpTvHGpZkKyafrQ+YC
         5ZU4cpAzNfV8v6gkZIhMAVN58rD5qhzohRVIjxbiIrA4DjRCvSweUl73uoc3dYx2GfpE
         65i4prFAvsvqWBlMVeZDF+86CWoU0zJUOnCBo/FG0uZtFGHAHGvuKzym45UD8c1I6Ak7
         piPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/tTBzvTm6y/vYcosns4CodiGsrvP2Y/B3B8/NhAV0As=;
        b=xwnV/Iv9k2ykwiQerAg/50McT2+5CqFgT+FG06KsKu9/V2AKcGs1XVKgHpld8OhYW0
         XzTk6YFeYvWXVmEdlNzBCXUpsf1EF7Cu2yy26tnCrYwFghVJ/5KlTsp66beVd+GWwJWm
         uOYVgrAXCJdoiwC95J8Lw1uy0pxPNip39AHV3kCWOYd3OmJFdEf9KgD5MrAt4DULwEKO
         RNznjwT0ezuSZ87R7bc3PiJ277wDVSizmtP8vWN2zL0yqnJpPJXn88QqKxLX/lz2BRbs
         vuEtVQZVGRuhnYpb4eBcauB8oJbXNkjgWfeFWDE1pcOqI1oD6gNOYrLJedLe1EjSvyT4
         3y5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jLaIH+nF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/tTBzvTm6y/vYcosns4CodiGsrvP2Y/B3B8/NhAV0As=;
        b=DWJUG1rXf4ALJ+bcr3wEeKnsmnkdfO3/O5lzfQkd6rXVuqgLKtVmJGgyddnaEWU/tL
         XOt+jElNIz04zNH1+NhDXN+0jcGZrPUBqraVZ+1wXeacwa5L8FrL0ljE/8CqBQ1aprL3
         aKeGkZ3SJo092X1ct7PhvXkqKi2SXrH26uKTzlqyc1xzSu7LTw/k7YWNhXSpMjTKubnQ
         RiM1w7l1fSN9uHBpzB26+zNMvJyImhUgjhA2psty2nORi4tl47wWhAu7Uo+nyMEeUZI5
         qvg0SdyQMCMdZ5HAtW4rpNyL/7yN+123JAYWMNTAUOxCVokJffe/dWmgbCLaoI9m1ssc
         8OrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/tTBzvTm6y/vYcosns4CodiGsrvP2Y/B3B8/NhAV0As=;
        b=IrALxGbiybMRZUC6WbC+tAIvhWEcPF89usPC1vSgdbZeiXk/qdl8p1xw89tzJa5H1W
         xeyzLsunguhdv3SBnmzjLw6Za2Ya5TZqMwZqz/LS33DCHftuyIaKxkerxDL5NqqQx3k1
         65sjTAANRVNyAK0eTUk7cWaO74kTw1uZyrYNxg/3ljE2gjeDB+EzLIhTJ4P/wdB2GWV4
         Wuz0IAH4kvFLF/PcTvh4csfUOJeOEo9BvJ3EqeraRB9X9QZzHJ1WZwF2uu9lhmZanjRQ
         wM9QzZAtguMPzobhF3O6ChKYTqW4m4GBoRJcPnhb3KgFx5IzWpFxcJ9SabD6UW1oNTt/
         1a3g==
X-Gm-Message-State: AOAM53060WJfHYkYpTQ3ScGP3BcjIfNlQEv87XiWZzZJaDrmCOmhHs5q
	2iBKND2vOF0dzQrCq8MePYc=
X-Google-Smtp-Source: ABdhPJz7v64fEzHV93hH2Z4GuXXKPoz+yC89dHtPBBgam+IZKF2Qm4ldkcV6R1EZnGIclVrEUt02lg==
X-Received: by 2002:a05:620a:cf5:: with SMTP id c21mr9957638qkj.207.1611739669087;
        Wed, 27 Jan 2021 01:27:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9163:: with SMTP id q90ls433686qvq.1.gmail; Wed, 27 Jan
 2021 01:27:48 -0800 (PST)
X-Received: by 2002:ad4:542b:: with SMTP id g11mr9620043qvt.47.1611739668775;
        Wed, 27 Jan 2021 01:27:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611739668; cv=none;
        d=google.com; s=arc-20160816;
        b=T24gJ+T9PM4+b+qhn3OZEqSGtaRBIHlseYJl+WXLQ/GBZlA2mtaEmL/GIjW4pn3Hy4
         0GF5lv7k6je21XsV6SvaHhIFI34BQcVk0NmjN6DN5xElDlLwAjJqDhHZA0x/9M5H5VzC
         hRLbruVa3Ud1J/DHzizrRp7C3Mpw3oa71QmyQql+VgZu3JB4aClSjQFB18vI2X+tiU90
         PI65rx3O5kEv2bAOv2V43oYgxtWtV/+r4rQQ9YA83Wwp5y7MJEZT8iCgYRAQE9oKxYMr
         XOPVMxEqzhYV5zEO2Z8iW/3KXLuoSK0wPx23F+OXlXeLNo07VHTJieIrBa9h2UB4xTHT
         2+Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=p985agwwTU9TdzBYzgEnersG9rglsNOCSNS7b+re3cU=;
        b=EuiBHTS5x+zDKE/z1I1yVbevtmjGPAlJUAFGrKh/FiEsWz8o+GRMo8wPpikLaX96nJ
         sgBZTBOAAqDgqWKwDq9K1yzxIuLK3ZwgJCo/Vys6Nr+itr8edfYsjgyFGxUMUWXP9gjv
         NNt6ALvxjNJIX2CGZ3j51L8IQqosrbq/36PQO7NfXnp3KQcxstLg8KMH+zMg91SoPqLz
         TdPQXbyImQ4ufC59q6JSAJYSwAwaYAjyPpm6c11R44hogEyKVEkSxeRckISiT3qlfpkC
         MHG6rbMqx8s7fXY4oFQ1zSRlhe9EZabDIDuoZDrUo9ulUeRopyD4hagoc7rcaoQGqjYj
         2b6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jLaIH+nF;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id h123si69507qkf.6.2021.01.27.01.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Jan 2021 01:27:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id e15so903053qte.9
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 01:27:48 -0800 (PST)
X-Received: by 2002:a05:622a:c9:: with SMTP id p9mr8764718qtw.337.1611739668250;
 Wed, 27 Jan 2021 01:27:48 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com> <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
In-Reply-To: <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Jan 2021 10:27:36 +0100
Message-ID: <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jLaIH+nF;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f
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

On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi, Macro
> Could you provide some instructions about how to use syz-symbolize to loc=
ate the kernel source code?
> I did not find any document about it.

Hi Jin,

If you build kernel in-tree, then you can just run:
$ syz-symbolize file-with-kernel-crash
from the kernel dir.

Otherwise add -kernel_src flag and/or -kernel_obj flag:
https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symboli=
ze.go#L24



> Thank You
> Best
> Jin Huang
>
>
> On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com> wrote:
>>
>> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com> wrote:
>>>
>>> Really thank you for your help, Dmitry.
>>> I tried and saw the KCSAN info.
>>>
>>> But now it seems weird, the KCSAN reports differently every time I run =
the kernel, and the /sys/kernel/debug/kcsan seems does not match with the K=
CSAN report. What is wrong?
>>
>>
>> /sys/kernel/debug/kcsan shows the total data races found, but that may d=
iffer from those reported to console, because there is an extra filtering s=
tep (e.g. KCSAN won't report the same data race more than once 3 sec).
>>
>>>
>>> And I also want to ask, besides gdb, how to use other ways to locate th=
e kernel source code, like decode_stacktrace.sh and syz-symbolize, talked a=
bout here https://lwn.net/Articles/816850/. Is gdb the best way?
>>
>>
>> I use syz-symbolize 99% of the time.
>>
>>>
>>> Also, does KCSAN recognizes all the synchronizations in the Linux Kerne=
l? Is there false positives or false negatives?
>>
>>
>> Data races in the Linux kernel is an ongoing story, however, there are n=
o false positives (but KCSAN can miss data races).
>>
>> Regarding the data races you're observing: there are numerous known data=
 races in the kernel that are expected when you currently run KCSAN. To und=
erstand the severity of different reports, let's define the following 3 con=
currency bug classes:
>>
>> A. Data race, where failure due to current compilers is unlikely (suppos=
edly "benign"); merely marking the accesses appropriately is sufficient. Fi=
nding a crash for these will require a miscompilation, but otherwise look "=
benign" at the C-language level.
>>
>> B. Race-condition bugs where the bug manifests as a data race, too -- si=
mply marking things doesn't fix the problem. These are the types of bugs wh=
ere a data race would point out a more severe issue.
>>
>> C. Race-condition bugs where the bug never manifests as a data race. An =
example of these might be 2 threads that acquire the necessary locks, yet s=
ome interleaving of them still results in a bug (e.g. because the logic ins=
ide the critical sections is buggy). These are harder to detect with KCSAN =
as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or ASSERT_EXCLUSIVE_WRIT=
ER() in the right place. See https://lwn.net/Articles/816854/.
>>
>> One problem currently is that the kernel has quite a lot type-(A) report=
s if we run KCSAN, which makes it harder to identify bugs of type (B) and (=
C). My wish for the future is that we can get to a place, where the kernel =
has almost no unintentional (A) issues, so that we primarily find (B) and (=
C) bugs.
>>
>> Hope this helps.
>>
>> Thanks,
>> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ%40mail.gmai=
l.com.
