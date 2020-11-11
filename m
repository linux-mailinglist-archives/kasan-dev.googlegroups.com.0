Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBGCV36QKGQEMQDBOGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E6FF2AEBDF
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 09:29:57 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id f66sf476255oib.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 00:29:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605083396; cv=pass;
        d=google.com; s=arc-20160816;
        b=I5617czwFFJqhjNibnN8zXPX1i+4FtiL7bbvep7sdT3//n6N9ZMkag3MYv7zJrs42W
         G57UmZqpR4FWKPBFzG23O+LTP/tmsvIHZUBBa9CwvaAx++sY3v+vLgY1Nkf2jQ7sPgpL
         No0LTb3FUR0q0iiG8GNjGKDAm6DK4/WFhKhBRyy2R88V+qdDGzFLy9o/7kCX6SLchaaR
         LKDge3wR/HgHqH/ZWI5uLJWuRj52DpRc8D4Xv5Df+e9+ywT7TJcmZtnmAPwYBxeLvdTX
         Sm0+MQwOKeQ2V8AvBEx7toSJOBV2QC5+ozSEVq7aYg6XLOSRwEQy0f+j4quhSQCvQW0g
         HYEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QhZfZr6UnHJuXLjwRStUO4x6Wxkn2vvQotV7qrMPjt4=;
        b=ZQzBvJ5rtJt3B0QbUD2ZEDt3zc3Iw0UeSxaJKIqD5LlH0YB70wBovYEao68wswv2on
         L/pboQNkndsbpy06HFOtZmB+PUDBjqmqkAN8wlv22A+ZKkKO95zssZlj6FjzJEEt4LV3
         JikE7Z+58ejSobpdtAD0q5W8zANjCr3m8DLIasr7ZbIQR2vrWyOobh+dh5nRKYtECoBb
         eZ6FVeb4mcIOqeXvPR7Ba5akX4qgj5NZoc9dveyFC6gqklaE+ZwBPzM3hbjD96COGlGI
         QptPa2QmIMzYkmDA3VtExLcEiyqsPbTdK74ipzvqp4oJuzPHkjt/PhWs2NnWQUgeBWia
         Wo5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fY5gjnlc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QhZfZr6UnHJuXLjwRStUO4x6Wxkn2vvQotV7qrMPjt4=;
        b=RHiFbnnkY6yF0JA7+4s8J/bWyJTsrhX0jh5/SU2htNc4vaz+8v4/tyxlklMzuEZgKd
         Zme+K3q/mxAtYhQTpPDLOfPR6lTFtZuPMs7xwy+G+JNbsRzmhJRj5iQbO99cnXDrSJ+Q
         L1oK8ZFnzBaDAphj19APpirmLy4PNrKIuk8ISD9rdo+uj7PFb+qr8MYlG/VLNqcp/dzc
         iSNUCsnHk2taVJRf2uFOP1arMjvUzQUf3YDf68R7Tc1eyGFxNrHHaoGcRt1yNbDQdA0t
         F6r9Dfrx/+FlIY/RutA0i4thWGViymtmFVeFKLJuiZoi9tXmNcpydutOf6uTwAZBF1+r
         aUmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QhZfZr6UnHJuXLjwRStUO4x6Wxkn2vvQotV7qrMPjt4=;
        b=MVSEa2pXjoovp/DdAOfbK4okX+JYfcIyOZBVYnrQUJLiXKQkjxkPbmsCtSaDEoqTGA
         JbNKMI6EuOcwzY/FEFO+WKRo1h4JtLT472+oYCp6ZscoGrm8xUnQHj/Zs2N5IQ0jtbul
         XrDniT/zqqnYhPyRijkPwRFm0Lp+AAU6AM7HjHE7FiQWSWtlFWEk0fch39Z0UzwXavpT
         9RQ0QDk9X74ztPXfMirRhS57aaISBEpS4mVTlJDwkZJw9Uo1jT6j9T0bxPKkeqio3H5B
         pOBPA1wrEdxcoKf6AFQDFlM9B8FfNa8mCiETHZkD5whj3hWBWMERru61VnuATuL5wKkX
         cRjQ==
X-Gm-Message-State: AOAM532gwrHklqAu8t4JG4FEO17wEd5VElYj552CZ+DTiJPj5MKMY6DB
	MXtofM2GtANHdHRYtAH1jNQ=
X-Google-Smtp-Source: ABdhPJy2X53z7FIOTz49IvyAacJbW6r7+/FtiYdOOj9jXxPWwMoqNtJSXBJ8eENHu17L1nZadkvvvQ==
X-Received: by 2002:a4a:c018:: with SMTP id v24mr16226815oop.2.1605083396118;
        Wed, 11 Nov 2020 00:29:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1ca0:: with SMTP id l32ls1010178ota.5.gmail; Wed, 11 Nov
 2020 00:29:55 -0800 (PST)
X-Received: by 2002:a9d:1b4a:: with SMTP id l68mr17541580otl.194.1605083395708;
        Wed, 11 Nov 2020 00:29:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605083395; cv=none;
        d=google.com; s=arc-20160816;
        b=wKlRCAqFLb3BGHi/ItrRHAu6HeUpaVzzrk0mmClmbWUr5cPCAedb8JUa/mibaOrofB
         m1FXNej8pkJN6/UdQOYiWF8+D8o75y42INDKSwvJ7dq+LCxMXjB1/Qp7+4KUr9Ow/wYe
         lpAXVnD1eT5k2wtZ0s5bhi5YSvsaYdrIfuQE5VAQRU3xZpKeEa+Rz3c6WMGblv0yXYZx
         fiGRY0ph/2nWW6yGXWsSMUb0iiP+NOjl2esEoJXw66Y1C7Lm2BU7xU+0KfHwj6IvH8cA
         ta1ZpQVcGGRbEhF6+1mgBfOhdMFQ+7qHvvP67M4GpsGco5UcJjwvq0mOy8bHjBjOcFud
         Urhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pfSE5/lXKDKWvupd66vFeefPVzfzS3PVTtaZxopqHn0=;
        b=0tyugQEmQyPMqaKPFUiUHvKAAeOH9Pq2I7HF56tXTHLK/GgOFfqgTCLRm7MaD72t+o
         5kh262hp4HITLjkRVtaONphM55vWo1vkfSCY/JEC/1qjSJdhF4tcy4z0m+JkcW0CNn/0
         i102vAnRoWc3uiUnARFfYO48EE+6YCmSA3TrlGS9xfjVRzc/CInJem1diRg6BBRCKExn
         L5+OhTsnshiL42xJ1IoDWJeSu6u1phKfG3EdiSJJDKzJ4pGlD74VsiXTxIRLLRxqLvcO
         PdBGuCjnhJu1eqjcuhFa7q4/DI0vU2Emg3+wXSHI02ofhbTCFOG5y49cEXMp6QZvNVJh
         rbdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fY5gjnlc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id v11si124347oiv.0.2020.11.11.00.29.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 00:29:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id q206so1280437oif.13
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 00:29:55 -0800 (PST)
X-Received: by 2002:a05:6808:5ca:: with SMTP id d10mr1524759oij.70.1605083395264;
 Wed, 11 Nov 2020 00:29:55 -0800 (PST)
MIME-Version: 1.0
References: <20201110135320.3309507-1-elver@google.com> <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
In-Reply-To: <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 09:29:43 +0100
Message-ID: <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without allocations
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fY5gjnlc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Wed, 11 Nov 2020 at 00:23, Anders Roxell <anders.roxell@linaro.org> wrote:
[...]
>
> I gave them a spin on next-20201105 [1] and on next-20201110 [2].
>
> I eventually got to a prompt on next-20201105.
> However, I got to this kernel panic on the next-20201110:
>
> [...]
> [ 1514.089966][    T1] Testing event system initcall: OK
> [ 1514.806232][    T1] Running tests on all trace events:
> [ 1514.857835][    T1] Testing all events:
> [ 1525.503262][    C0] hrtimer: interrupt took 10902600 ns
> [ 1623.861452][    C0] BUG: workqueue lockup - pool cpus=0 node=0
> flags=0x0 nice=0 stuck for 65s!
> [...]
> [ 7823.104349][   T28]       Tainted: G        W
> 5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> [ 7833.206491][   T28] "echo 0 >
> /proc/sys/kernel/hung_task_timeout_secs" disables this message.
> [ 7840.750700][   T28] task:kworker/0:1     state:D stack:26640 pid:
> 1872 ppid:     2 flags:0x00000428
> [ 7875.642531][   T28] Workqueue: events toggle_allocation_gate
> [ 7889.178334][   T28] Call trace:
> [ 7897.066649][   T28]  __switch_to+0x1cc/0x1e0
> [ 7905.326856][   T28]  0xffff00000f7077b0
> [ 7928.354644][   T28] INFO: lockdep is turned off.
> [ 7934.022572][   T28] Kernel panic - not syncing: hung_task: blocked tasks
> [ 7934.032039][   T28] CPU: 0 PID: 28 Comm: khungtaskd Tainted: G
>   W         5.10.0-rc3-next-20201110-00008-g8dc06700529d #3
> [ 7934.045586][   T28] Hardware name: linux,dummy-virt (DT)
> [ 7934.053677][   T28] Call trace:
> [ 7934.060276][   T28]  dump_backtrace+0x0/0x420
> [ 7934.067635][   T28]  show_stack+0x38/0xa0
> [ 7934.091277][   T28]  dump_stack+0x1d4/0x278
> [ 7934.098878][   T28]  panic+0x304/0x5d8
> [ 7934.114923][   T28]  check_hung_uninterruptible_tasks+0x5e4/0x640
> [ 7934.123823][   T28]  watchdog+0x138/0x160
> [ 7934.131561][   T28]  kthread+0x23c/0x260
> [ 7934.138590][   T28]  ret_from_fork+0x10/0x18
> [ 7934.146631][   T28] Kernel Offset: disabled
> [ 7934.153749][   T28] CPU features: 0x0240002,20002004
> [ 7934.161476][   T28] Memory Limit: none
> [ 7934.171272][   T28] ---[ end Kernel panic - not syncing: hung_task:
> blocked tasks ]---
>
> Cheers,
> Anders
> [1] https://people.linaro.org/~anders.roxell/output-next-20201105-test.log
> [2] https://people.linaro.org/~anders.roxell/output-next-20201110-test.log

Thanks for testing. The fact that it passes on next-20201105 but not
on 20201110 is strange. If you boot with KFENCE disabled (boot param
kfence.sample_interval=0), does it boot?

In your log [2] I see a number of "BUG: workqueue lockup ..." but that
doesn't make sense, at least I don't think the KFENCE work item is
causing this. It'd be interesting to bisect what changed between
20201105 and 20201110, but I have a suspicion that might take too
long. Short of that, let me see if there are any changes between the 2
that look like it might be causing this.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM8MZphvkTSo%3DKgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ%40mail.gmail.com.
