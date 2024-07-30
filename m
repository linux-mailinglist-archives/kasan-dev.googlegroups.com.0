Return-Path: <kasan-dev+bncBCAJFDXE4QGBB7NIUS2QMGQE3ZUMHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8071D9418FD
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 18:27:42 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-42808efc688sf28692015e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 09:27:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722356862; cv=pass;
        d=google.com; s=arc-20160816;
        b=013l9ImGX+QJlpLhT1VXtXc59ZpN7IPexplygfkB5+R7CJ0S9f1P+6w3HvraMixHC2
         gC+m7StgK2FcA08RAHfrxDp6qBG9k6OxxbO4iaOgm+MiLtkv1ZdNz09TJ2yqJJmnYRNe
         KIifVJblCC+3S0lHS0NL4WlJmM3hFadqyyIZ6sFkTI9GaEe+StuS2ruQ4rTO8HJ8lA//
         HXYx4z22QdSRZrcgwh8TugaUiLg4wqOStisaL8OelfShYf66Mpr6LALYp9rdh9qaTb72
         j7x4RNr66YEBZfSyfK+2kVB+yQLvAVo1E5fyiafwG9qetoB/WektS7T2mQRF0UQURhgS
         wRNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0hXmve7JEhbQsmIxLNY/mIrDjWAan8oeGb0NSuTg6r4=;
        fh=/pUmdHHUiVd/1b9fEmjPfC2xFVarO4OatKBvn8Iww1c=;
        b=KJRQP7wqZAHDm6uxqGLJBkruWe15yc5N+2WcYg0a0Q1+/QJ4uqXTb0nFAGxfIEbYRA
         PU5XnyYaQoi/4Ej5vztsdrgM9YAvGEmySZUfsjF92KNJak9Ns1mrM14+JedzVaGPlC6J
         eBhDpJ+mv0nbb9PErgLxp15vw1agaaL1FWhutPtcSg8kcTOUak7EShw78/D2Kv3AHtI1
         9ApZoipvZu6R7724JCQ5o59Ip0BIoS/J+RRvyF2487wTTbhMqDojburlm0m9ckGI7HGK
         WDXm2SNJDq40eg/DlxycRc+NfBQgdWZd2zEqNQLjtV/ank8PokrnlC2EVXEWhmOJ27ZP
         BWug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M4Eg6LW0;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722356862; x=1722961662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0hXmve7JEhbQsmIxLNY/mIrDjWAan8oeGb0NSuTg6r4=;
        b=OuL7YoLzuqaG71nJ2BVB7ouVQa5CNe5TJKvc30qI5EgMTr0pPiCCIdb1TcuHLhu56T
         H+l/vvwXZ1wzOIHt/EGN3ZrAeJ8ePBrNF+6iHhNTq3+NVc9zoUb2PUQpWRQehyaN2pUM
         RUwde5B6TbtHdq8l7UJO+rF4XhfL11aWfkKE8u72E3wI3k/93u6XH1cWMfQ3fdQ+BplW
         0y8tL+WC1y1CVJVbcwxdnhMTWn9+n9uFezAtxOtULM/JeaWTV4lf0AIz3ZLT9fvZgJWK
         bsICuLJs9CrIhUa3/jEIaNtFwHaY6PYWmMa1sKd0i7xyHLM7d0XSO9RQzwFI8d9PWFYN
         B61w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722356862; x=1722961662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0hXmve7JEhbQsmIxLNY/mIrDjWAan8oeGb0NSuTg6r4=;
        b=FZdQrwZ9DF4X5HvBfMiwZffNiVbz8wFWpRDfuTPM1TIbZ2uMtEUPN6MFzAEk09Lsia
         05nPglPgp9HezhgWFo+sWakDKEvoUwZbnIJxs7uo2WEDfmA5ebdaItiaFHlMfAB7iMOL
         59y1869QopmdToO7vQqM98MTgz8pfNAOXI9MNsG0zfAnglEGx5YIc1FgwnPCMRo5r4jz
         tQqyMLYvH4E0ShEwNDYhUVQTNRXUjwUv2StQMkAw1Apu5nkLYApvXLq5fd+GW7rAa5Ei
         woXWA8qh7jT4xgbIXhXbfh9HALP9/wmYa+n9tZHy4CzZxmDsn/b02yIqkwks78KKAJpN
         7VdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722356862; x=1722961662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0hXmve7JEhbQsmIxLNY/mIrDjWAan8oeGb0NSuTg6r4=;
        b=KoR+RaRfqI2iBBeFDtGTJAd7tCDnXawpxqFYn+cT+vwLt76vhJI8Nbm826wmnesbrw
         xPRQc8Im7cy3U4A84qMkGPTgDtLkYOUBlwJDcYa3XTTa+mtfmc5hZRnBVR3vZH7coFqL
         3ES+BGQf7ydpgqd/0MgtbxZPHsWvIydH28NskS2T+8EW19u/JPr1oJ1Qrx8I+gHswahM
         6diEzPShjOb98g1UHt/OzkOK4Kj87aL4H5qv90GZ1MxlR+GcPFThsXh2pwqYtH8TpwCn
         c4EWINkDPceuOBiSKo5tTfH18p5HHOUACE3FhKeypbqix03RKEhvJu7bd4jFcAXFIUpQ
         +YFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcsqMozd4YZnCCZwS8ZGgF3DROmB/VPspsFyQkRF89bO7ouVW6fq5gZxQBL639Mvm05Nh2bV2zspgwR1HOYrHZz4bf0v+Iig==
X-Gm-Message-State: AOJu0YwXu5hBptLOBUKUT3IGgB91vT49FkMNhInuPpGcYR/vrZgafSvj
	d9tImtBXIphxG5HITRZQ20qn42q6nKUM6YaI8EwOpB0scE/G1s/p
X-Google-Smtp-Source: AGHT+IFEjdkUh6eisIGEgBWxBp+MjWdPaJbGbyHnaHY2Ag3uvbVHsJP1zanQHE25LPpm6d4EjpphxQ==
X-Received: by 2002:a05:600c:4f51:b0:426:6b92:387d with SMTP id 5b1f17b1804b1-42811d9afc5mr78400885e9.21.1722356861478;
        Tue, 30 Jul 2024 09:27:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca3:b0:426:6eba:e1f4 with SMTP id
 5b1f17b1804b1-4280386beabls27492555e9.0.-pod-prod-02-eu; Tue, 30 Jul 2024
 09:27:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUF/CXQCl0PKb59EY90Qmot1CLisWBVmkgv5IX9j7CpuYEZOq62D89yCedVovwEEEsV0BDQwmOxQQDWESfqDT7wdlLXZKo8MeoR3Q==
X-Received: by 2002:a05:600c:4f07:b0:428:14b6:ce32 with SMTP id 5b1f17b1804b1-42814b6cf86mr87915715e9.9.1722356859681;
        Tue, 30 Jul 2024 09:27:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722356859; cv=none;
        d=google.com; s=arc-20160816;
        b=Pfun+4T/KfmRGnTRSUHL1KISg1CMavwtJPAnt1KM6wdy8kTOKGdj5udbJ3qR/TdCy2
         d0GhgtCG2DDaePB2gnchqvZH6HK2d+ijMNjdu0f6mgEjHAbFaNg1yH/axTGfbVDpB8aZ
         xUlitPmA20vDAtgsFHO0L+wc+w60U41nChiseV42QCMTDm4KyRjiQaI9sjLmfiJgOB/m
         xb4VceSkRG0wH/Kz7Eukjg+QYc8TxhK3vKWCabsJedvCMQaM4hQrz5LSpsuV06LZnct+
         we1FMJsssVItMY52zpKb+ZYkrYRDTONFaip96zuLMVKyeHdB5aSciiBH/FgJNG7oJSbK
         G1Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DQMm3j/WDX5wm2f/0bMEKkx0ZnqFo9kz+zHN+GCN6hs=;
        fh=Kr3jo5/v9R9Jg7Xv0r3M7C90MYACnruzTzJ1nB8dk74=;
        b=nJ1M8wV+WIhDxbMFO1jagaOMKvn4cyePQrCXro4aNvp1jXU8u0sPVQ0Y63qa2aVwPz
         AyCRmc5q5uqXTrtM2Izsvdu6ZpQT9cKVRs5VTOSt1Fkr7QeScOBtRrVSjkdjlIEtY34o
         AadlSVeuMNLamZR2aYx9iFxhptWEr4xTioWWfc2W7Bkg0+jtBuDg9wm38SvkhaHnv5fM
         stQWF+VFdGzZRC4Zzv0gNj2HmivK/jfHKUixBv52a3eRCWFdbnu3IoTDl25Ran5LO93d
         tCAs2iJS8tndj8YRbAmKIYYrv2lTHrw24N5Oq2IUMcsRLDE1Z7HHQ9lOKsymQfPhJsZ6
         ejJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M4Eg6LW0;
       spf=pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36771c65si239853f8f.1.2024.07.30.09.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 09:27:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of adrianhuang0701@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id 4fb4d7f45d1cf-5a2ffc346ceso6865967a12.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 09:27:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBKJ7Dovkirz1agz0qEYRF7p4APWUFPwXWt657zNI4HxNoI51I73X0BlYTb5gEoU2/mT4a6dUFiB5rIyuVg61RnPuJHvplkwNuPg==
X-Received: by 2002:a50:c30b:0:b0:58b:73f4:2ed with SMTP id
 4fb4d7f45d1cf-5b0224cf4d6mr6499683a12.35.1722356858839; Tue, 30 Jul 2024
 09:27:38 -0700 (PDT)
MIME-Version: 1.0
References: <Zqd9AsI5tWH7AukU@pc636> <20240730093630.5603-1-ahuang12@lenovo.com>
 <ZqjQp8NrTYM_ORN1@pc636>
In-Reply-To: <ZqjQp8NrTYM_ORN1@pc636>
From: Huang Adrian <adrianhuang0701@gmail.com>
Date: Wed, 31 Jul 2024 00:27:27 +0800
Message-ID: <CAHKZfL3c2Y91yP6X5+GUDCsN6QAa9L46czzJh+iQ6LhGJcAeqw@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of KASAN
 shadow virtual address into one operation
To: Uladzislau Rezki <urezki@gmail.com>
Cc: ahuang12@lenovo.com, akpm@linux-foundation.org, andreyknvl@gmail.com, 
	bhe@redhat.com, dvyukov@google.com, glider@google.com, hch@infradead.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	ryabinin.a.a@gmail.com, sunjw10@lenovo.com, vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: AdrianHuang0701@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=M4Eg6LW0;       spf=pass
 (google.com: domain of adrianhuang0701@gmail.com designates
 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=adrianhuang0701@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 30, 2024 at 7:38=E2=80=AFPM Uladzislau Rezki <urezki@gmail.com>=
 wrote:
>
> > On Mon, Jul 29, 2024 at 7:29 PM Uladzislau Rezki <urezki@gmail.com> wro=
te:
> > > It would be really good if Adrian could run the "compiling workload" =
on
> > > his big system and post the statistics here.
> > >
> > > For example:
> > >   a) v6.11-rc1 + KASAN.
> > >   b) v6.11-rc1 + KASAN + patch.
> >
> > Sure, please see the statistics below.
> >
> > Test Result (based on 6.11-rc1)
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
> >
> > 1. Profile purge_vmap_node()
> >
> >    A. Command: trace-cmd record -p function_graph -l purge_vmap_node ma=
ke -j $(nproc)
> >
> >    B. Average execution time of purge_vmap_node():
> >
> >       no patch (us)           patched (us)    saved
> >       -------------           ------------    -----
> >                147885.02                3692.51        97%
> >
> >    C. Total execution time of purge_vmap_node():
> >
> >       no patch (us)           patched (us)    saved
> >       -------------           ------------    -----
> >         194173036               5114138        97%
> >
> >    [ftrace log] Without patch: https://gist.github.com/AdrianHuang/a5be=
c861f67434e1024bbf43cea85959
> >    [ftrace log] With patch: https://gist.github.com/AdrianHuang/a200215=
955ee377288377425dbaa04e3
> >
> > 2. Use `time` utility to measure execution time
> >
> >    A. Command: make clean && time make -j $(nproc)
> >
> >    B. The following result is the average kernel execution time of five=
-time
> >       measurements. ('sys' field of `time` output):
> >
> >       no patch (seconds)      patched (seconds)       saved
> >       ------------------      ----------------        -----
> >           36932.904              31403.478             15%
> >
> >    [`time` log] Without patch: https://gist.github.com/AdrianHuang/987b=
20fd0bd2bb616b3524aa6ee43112
> >    [`time` log] With patch: https://gist.github.com/AdrianHuang/da2ea4e=
6aa0b4dcc207b4e40b202f694
> >
> I meant another statistics. As noted here https://lore.kernel.org/linux-m=
m/ZogS_04dP5LlRlXN@pc636/T/#m5d57f11d9f69aef5313f4efbe25415b3bae4c818
> i came to conclusion that below place and lock:
>
> <snip>
> static void exit_notify(struct task_struct *tsk, int group_dead)
> {
>         bool autoreap;
>         struct task_struct *p, *n;
>         LIST_HEAD(dead);
>
>         write_lock_irq(&tasklist_lock);
> ...
> <snip>
>
> keeps IRQs disabled, so it means that the purge_vmap_node() does the prog=
ress
> but it can be slow.
>
> CPU_1:
> disables IRQs
> trying to grab the tasklist_lock
>
> CPU_2:
> Sends an IPI to CPU_1
> waits until the specified callback is executed on CPU_1
>
> Since CPU_1 has disabled IRQs, serving an IPI and completion of callback
> takes time until CPU_1 enables IRQs back.
>
> Could you please post lock statistics for kernel compiling use case?
> KASAN + patch is enough, IMO. This just to double check whether a
> tasklist_lock is a problem or not.

Sorry for the misunderstanding.

Two experiments are shown as follows. I saw you think KASAN + patch is
enough. But, in case you need another one. ;-)

a) v6.11-rc1 + KASAN

The result is different from yours, so I ran two tests (make sure the
soft lockup warning was triggered).

Test #1: waittime-max =3D 5.4ms
<snip>
...
class name    con-bounces    contentions   waittime-min   waittime-max
waittime-total   waittime-avg    acq-bounces   acquisitions
holdtime-min   holdtime-max holdtime-total   holdtime-avg
...
tasklist_lock-W:        118762         120090           0.44
5443.22    24807413.37         206.57         429757         569051
       2.27        3222.00    69914505.87         122.86
tasklist_lock-R:        108262         108300           0.41
5381.34    23613372.10         218.04         489132         541541
       0.20        5543.40    10095470.68          18.64
    ---------------
    tasklist_lock          44594          [<0000000099d3ea35>]
exit_notify+0x82/0x900
    tasklist_lock          32041          [<0000000058f753d8>]
release_task+0x104/0x3f0
    tasklist_lock          99240          [<000000008524ff80>]
__do_wait+0xd8/0x710
    tasklist_lock          43435          [<00000000f6e82dcf>]
copy_process+0x2a46/0x50f0
    ---------------
    tasklist_lock          98334          [<0000000099d3ea35>]
exit_notify+0x82/0x900
    tasklist_lock          82649          [<0000000058f753d8>]
release_task+0x104/0x3f0
    tasklist_lock              2          [<00000000da5a7972>]
mm_update_next_owner+0xc0/0x430
    tasklist_lock          26708          [<00000000f6e82dcf>]
copy_process+0x2a46/0x50f0
...
<snip>

Test #2:waittime-max =3D 5.7ms
<snip>
...
class name    con-bounces    contentions   waittime-min   waittime-max
waittime-total   waittime-avg    acq-bounces   acquisitions
holdtime-min   holdtime-max holdtime-total   holdtime-avg
...
tasklist_lock-W:        121742         123167           0.43
5713.02    25252257.61         205.02         432111         569762
       2.25        3083.08    70711022.74         124.11
tasklist_lock-R:        111479         111523           0.39
5050.50    24557264.88         220.20         491404         542221
       0.20        5611.81    10007782.09          18.46
    ---------------
    tasklist_lock         102317          [<000000008524ff80>]
__do_wait+0xd8/0x710
    tasklist_lock          44606          [<00000000f6e82dcf>]
copy_process+0x2a46/0x50f0
    tasklist_lock          45584          [<0000000099d3ea35>]
exit_notify+0x82/0x900
    tasklist_lock          32969          [<0000000058f753d8>]
release_task+0x104/0x3f0
    ---------------
    tasklist_lock         100498          [<0000000099d3ea35>]
exit_notify+0x82/0x900
    tasklist_lock          27401          [<00000000f6e82dcf>]
copy_process+0x2a46/0x50f0
    tasklist_lock          85473          [<0000000058f753d8>]
release_task+0x104/0x3f0
    tasklist_lock            650          [<000000004d0b9f6b>]
tty_open_proc_set_tty+0x23/0x210
...
<snip>


b) v6.11-rc1 + KASAN + patch: waittime-max =3D 5.7ms
<snip>
...
class name    con-bounces    contentions   waittime-min   waittime-max
waittime-total   waittime-avg    acq-bounces   acquisitions
holdtime-min   holdtime-max holdtime-total   holdtime-avg
...
tasklist_lock-W:        108876         110087           0.33
5688.64    18622460.43         169.16         426740         568715
       1.94        2930.76    62560515.48         110.00
tasklist_lock-R:         99864          99909           0.43
5868.69    17849478.20         178.66         487654         541328
       0.20        5709.98     9207504.90          17.01
    ---------------
    tasklist_lock          91655          [<00000000a622e532>]
__do_wait+0xd8/0x710
    tasklist_lock          41100          [<00000000ccf53925>]
exit_notify+0x82/0x900
    tasklist_lock           8254          [<00000000093ccded>]
tty_open_proc_set_tty+0x23/0x210
    tasklist_lock          39542          [<00000000a0e6bf4d>]
copy_process+0x2a46/0x50f0
    ---------------
    tasklist_lock          90525          [<00000000ccf53925>]
exit_notify+0x82/0x900
    tasklist_lock          76934          [<00000000cb7ca00c>]
release_task+0x104/0x3f0
    tasklist_lock          23723          [<00000000a0e6bf4d>]
copy_process+0x2a46/0x50f0
    tasklist_lock          18223          [<00000000a622e532>]
__do_wait+0xd8/0x710
...
<snip>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHKZfL3c2Y91yP6X5%2BGUDCsN6QAa9L46czzJh%2BiQ6LhGJcAeqw%40mail.gm=
ail.com.
