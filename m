Return-Path: <kasan-dev+bncBCU2BBWH4IORBOMQQK5QMGQEEDLAAXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BE719F3A6E
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2024 21:06:19 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3eb8dd455edsf3468672b6e.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Dec 2024 12:06:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734379578; cv=pass;
        d=google.com; s=arc-20240605;
        b=VTlxHNkp3a+K3P1SjH8i7xrNIdEWiW47CO/sKjot+9lcWBqSlBP+8fYm2g2uvqYLqz
         pyueQTx1cWiP6qLfpi1hbiG9fa0d3i52wfpWDB4xkO/XUZarrtFiivk/FULbG2kILhlk
         VdZz0bU5rhyyU8MQcxC1FZGSjUe/noWuWcbybackMKX8739V17JUGlMCn4Rgk6LI0UW5
         95kLkGBgbnSSSLu2QkLUyp7moPrJoC1Pw6kweByDmslV2ykmy1uXzuWXiJ8qZ/5CN0su
         2AuE1z4cGuEgTPYN+wLs/7Zn6TCXzWbW6KnMrHnmW+H2WEK3E3I9FVsuTOrWGVXTIIUK
         9row==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4S3kUU2mVD9FF/O2P5umtpzgkURPgkHN9EBr+RTKfyY=;
        fh=OWf+G98AIfbw3wpEBQ3tRsqMwBjQx4Ykk2k3dAd+7B4=;
        b=B+SGvIEqQjJsbxgbtUVSMjoBHHm9kv6au5QFfsd2HI5A0tPTKoN8QOkGuECuSLco1r
         mgAOPTRTyqjMqv7MYy3R+ELz84tysi/+zbLuVPX35COKvB9Y9p3HjGE5oCwgldfLuEqu
         jdCFeeQopqm1/ohu9bSUGaQ4i/x/zPCM9u2PdJ3EB6vg5rJbePxiKfjIixqov1yjDIcP
         oAmEzpVRJeknfpafrlbwUWYPfRgfnnz0kgysU+8ww23qKOFlmgb/6+T50BdfSF4RGkQx
         5NHir4E3yxU+fOHRbNpM4Ud7aIoznr1rj/e3q3OcY2xxD427CocMj3W/LbiXCx3BIs1C
         l8bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jp0ioIaw;
       spf=pass (google.com: domain of briannorris@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=briannorris@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734379578; x=1734984378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4S3kUU2mVD9FF/O2P5umtpzgkURPgkHN9EBr+RTKfyY=;
        b=ms5g72EfYLvl+nXyw9/KixiXQeonym7EfGrrJ1pQbU21iqCDluE1bmuUqvXqcjKp3C
         AO+T0ztElVxPQ81YLreY2HGvU/Nw3dqADbvuPOXJBpQJixqJE3+zJ4QPoNCPQX4VG4lC
         i4TGlT0+at4KlQYd+K5K+Q44nmUtz2Oo5oZgSUJ4FBzYrm8J3kJleBAIHZ2BhLNpP2Sn
         vnsYYHATCfqKIalSkKdxeomI33Ei/jY0oqqV0AzsYCU4iuSikZfimlaelQh52lF7AcEQ
         awCG3O74tBhdsvUAgU9pGVCDqz5MQTLLCvxFatSH9wNiZBK6T9D/BOybMpoQhkL6vZiD
         H5AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734379578; x=1734984378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4S3kUU2mVD9FF/O2P5umtpzgkURPgkHN9EBr+RTKfyY=;
        b=PAG+akr2DdZMfy9skIWjZs/YOnUvNU69rTMV4M1e427t8YW5W4Ph4QJ1htFnPiTCUl
         gfp1xhlRPLWt5TYq8Q5K2yiMuVJUBCu7Zu1/fQ1E8TxtfjS84EZN5yzmSKhFljFevIwY
         Vp7uBuUeaInfLp3m+p3kT3JF22o1K/+6poFO+lm0bRS64dH0WsTpH7+UGDBs4OVUWxMA
         NxFBNEUUaI1t9Q5kOZFHYhg2S0bhQx7c0Hcx6k3c05MXmkQbSnBVtTJ2h4Z327n+3DP1
         CJ1yV0RyvR2o6dAijujqk3964jLLbWPlgi5as3JMt4yj88BoLo9jXt87YHsWmULxhM3+
         oxFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXro8RUr4NC5G4xZKZBAESg9+BzgIeM35IrjfDF5m0NxCMs4EaLw13C2yvmsaA+0odxGtNWeA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1qgYGvJ7IX3JBL775xvm1ew5n/kqCrU3EuTcQWltE33lpHl9y
	ZOh00oj9egABYxeIKkktclgH3s00ofAPXb6ZS3XHOO1k3lPNIJ6M
X-Google-Smtp-Source: AGHT+IEGLrzwQixXea3h8Cb4/Kwuor2r9u+3zZNbwnvOtYhXEovhu5vBk+ZPV7uATq9cD1jWPgwo7w==
X-Received: by 2002:a05:6808:2e8e:b0:3eb:6dd3:12aa with SMTP id 5614622812f47-3ebcb2f921amr64428b6e.23.1734379577843;
        Mon, 16 Dec 2024 12:06:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e758:0:b0:5f2:ca2b:a504 with SMTP id 006d021491bc7-5f32be13cdcls110477eaf.2.-pod-prod-07-us;
 Mon, 16 Dec 2024 12:06:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUh7crWYbY9I+qqdF7waEhBtCr5yhbQ+8MWYpZhJ6KRErLMc7oyw3QetkukC7XAAuLS8sEyux97Oic=@googlegroups.com
X-Received: by 2002:a05:6830:6a91:b0:718:2302:7560 with SMTP id 46e09a7af769-71e3b84c2f0mr8238773a34.7.1734379576968;
        Mon, 16 Dec 2024 12:06:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734379576; cv=none;
        d=google.com; s=arc-20240605;
        b=bSCCuo5jz/kadNg2S2jvLqP0hLHrS4C6wUxFmwW5TTlfTmR0RRfJfF8yvHqpnRBNW3
         gBMqtlqUxAu7vqpa+pyFeiBwBjIV/ZI1i9e55seUo5A1SKgoSbG2TsgKvyzR3GyeJ4e2
         LmnoarGERnMMqgCQuDibTeuymUmfcpxStUAhDR1KEW2+PkgPjuX6pn766xr+wirrDYbF
         +VxIwGZjasneIb5uBrcL8WmonimEDsQyOEGTOT053ywJBjp1juw9wsulyhfkjO8G7uj7
         Hnj92/X1RwZo5rAS8JJMgX96UtYDIQdJKFyQ2mGwd2NOQdES8TC5yFuHSwS9rcVWx5MG
         tgSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3EfsgiLuEZpT8xsRppiqSwVXpZ7RDZSu4foO30f3Bu4=;
        fh=5z9jvmyejDfoyxe37+CnF209r37wTgCgs7wo+1JDTZA=;
        b=kpHGXzd87mBemiczOS2n2hW2UHhr8Q6vcNWyAs+FvRAqaXy9v42IYJdKnPArMARAT5
         o8ouUa9NPzzdl0ngdhTpKRvl3a9+tkjaAa/gkgJKEPl23mwOgnaOck5zN7liQoemELW4
         +Xysq/hlqfLwxRlWNLcUavML0MNHJoHJA5/yRL7spczv72ZBR1CdEss/Khxm/vxDQMUq
         7OJMiKZ0c4A/z4Y3aoImKWgr/XXVza1EU5wIRyBZEBWcmP0Ov45JoIuTK80GpgLe4d+i
         /ELj8Ov7wgD8OtWxgXdfihCOP/BnwFy2dgZC06NehJIqD2tRIJkV+dLoPMFQBsZWJmEz
         XQXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jp0ioIaw;
       spf=pass (google.com: domain of briannorris@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=briannorris@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71e4844c65esi269504a34.3.2024.12.16.12.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Dec 2024 12:06:16 -0800 (PST)
Received-SPF: pass (google.com: domain of briannorris@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2ef6c56032eso2968455a91.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Dec 2024 12:06:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV74Fu0ZrtImdjRGW50fKpGSe5oFUZZtTMD9OvchCk0emLXpHcGNuJk9+kpvEHyVNHjCC+V4U4qclE=@googlegroups.com
X-Gm-Gg: ASbGncvtHuHHA2vDAI+IoWDWA/nNADG4joZ6poUP4R2G8rJAhQC4VbHlMQ97iXmRil1
	flt2V+qvwblq6eFldpeegR1VCi3dzlX8Sv0xa25ruZI4f3VdR8it4XBj+wyd18YKEXtXnh2wdOo
	uXbUt0vmWBdf1OTpPTTYI8BIwtjS8W9Zpt643nWOSBeiWYTkYFHPvgQGS8hqdiYMamca0iCdB2j
	k80g8eka8im7i5/EEzwHmW21HScBmVGXkqEn7xZNYhJWa73MxH+kNAM5HTpfo2s5QLP5Ifj6i6U
	eIM7C8ZPsTEynRQgcQ==
X-Received: by 2002:a17:90b:4e85:b0:2f1:2fa5:1924 with SMTP id 98e67ed59e1d1-2f28ffa4e4cmr17934259a91.26.1734379576253;
        Mon, 16 Dec 2024 12:06:16 -0800 (PST)
Received: from localhost ([2a00:79e0:2e14:7:953:5b91:a52c:e817])
        by smtp.gmail.com with UTF8SMTPSA id d9443c01a7336-218a1dcc463sm46738955ad.79.2024.12.16.12.06.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Dec 2024 12:06:15 -0800 (PST)
Date: Mon, 16 Dec 2024 12:06:14 -0800
From: Brian Norris <briannorris@chromium.org>
To: Benjamin Berg <benjamin@sipsolutions.net>
Cc: linux-um@lists.infradead.org, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v5] um: switch to regset API and depend on XSTATE
Message-ID: <Z2CINocd5Pqkzykw@google.com>
References: <20241023094120.4083426-1-benjamin@sipsolutions.net>
 <Z1ySXmjZm-xOqk90@google.com>
 <689539526e48a2648134bb8de463c3bf68724993.camel@sipsolutions.net>
 <c9bc87ceb666a9ab04a8c10a543ecfb6aa002aa2.camel@sipsolutions.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <c9bc87ceb666a9ab04a8c10a543ecfb6aa002aa2.camel@sipsolutions.net>
X-Original-Sender: briannorris@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jp0ioIaw;       spf=pass
 (google.com: domain of briannorris@chromium.org designates
 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=briannorris@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org;
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

(+ kasan-dev; leaving most of this thread intact)

On Sat, Dec 14, 2024 at 01:25:59PM +0100, Benjamin Berg wrote:
> Hi,
>=20
> On Sat, 2024-12-14 at 00:08 +0100, Benjamin Berg wrote:
> > outch. It is doing a memcpy of init_task. Now, struct task_struct is
> > variably sized, but init_struct is statically allocated, which could
> > explain why the memcpy is not permitted to read the larger memory (for
> > the FP register space).
> > I can reproduce it with the kunit.py script, but didn't run into it
> > with my own configuration.
> >=20
> > Now, this patch works around the problem:
> >=20
> > diff --git a/arch/um/kernel/process.c b/arch/um/kernel/process.c
> > index 30bdc0a87dc8..7748df822d30 100644
> > --- a/arch/um/kernel/process.c
> > +++ b/arch/um/kernel/process.c
> > @@ -191,7 +191,10 @@ void initial_thread_cb(void (*proc)(void *), void
> > *arg)
> > =C2=A0int arch_dup_task_struct(struct task_struct *dst,
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 struct task_struct *src)
> > =C2=A0{
> > -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memcpy(dst, src, arch_task_struct=
_size);
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (src =3D=3D &init_task)
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 memcpy(dst, src, sizeof(init_task));
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 else
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 memcpy(dst, src, arch_task_struct_size);
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return 0;
> > =C2=A0}
> > =C2=A0

FWIW, after fixing up the mangled whitespace, this works for me:

Tested-by: Brian Norris <briannorris@chromium.org>

> >=20
> > However, that cannot really be correct. I believe what should be
> > happening is that init_task is loaded into init_stack (see
> > INIT_TASK_DATA in vmlinux.lds.h). I am assuming that if this was the
> > case, then KASAN would be happy with it. However, I see the following
> > addresses
> > =C2=A0 __start_init_stack: 0x606dc000
> > =C2=A0 __end_init_stack: 0x606e0000
> > =C2=A0 init_task: 0x606e2ec0
> > and I am not sure why the linker script is not placing init_task into
> > the stack here.
> >=20
> > Also note that commit 2f681ba4b352 ("um: move thread info into task")
> > may be part of a correct fix here.
>=20
> So, I dug a bit more, and found
>=20
> commit 0eb5085c38749f2a91e5bd8cbebb1ebf3398343c
> Author: Heiko Carstens <hca@linux.ibm.com>
> Date:   Thu Nov 16 14:36:38 2023 +0100
>=20
>     arch: remove ARCH_TASK_STRUCT_ON_STACK
>=20
> This explains why init_task is not on init_stack. It also means that
> the related linker script entries that I saw can be removed.
>=20
> So, maybe the above patch is actually acceptable. We never need the FPU
> register state for init_task, so we do not really need it to be
> allocated either. The only place where it causes issues is in
> arch_dup_task_struct.
> In that case, x86 would require the same fix.
>=20
>=20
> My best guess right now is that whether the error occurs depends on the
> on the size/alignment of init_task. If we happen to have enough padding
> afterwards then we do not run into the red zone of the next
> (unexported) global variable (init_sighand for me). But, if the padding
> is too small, then KASAN detects the error and aborts.
>=20
>=20
> Does someone maybe know a KASAN/x86 expert that we could talk to?

Not exactly, but I've CC'd their development list.

Brian

> Benjamin
>=20
> > On Fri, 2024-12-13 at 12:00 -0800, Brian Norris wrote:
> > > Hi Benjamin,
> > >=20
> > > On Wed, Oct 23, 2024 at 11:41:20AM +0200, Benjamin Berg wrote:
> > > > From: Benjamin Berg <benjamin.berg@intel.com>
> > > >=20
> > > > The PTRACE_GETREGSET API has now existed since Linux 2.6.33. The
> > > > XSAVE
> > > > CPU feature should also be sufficiently common to be able to rely
> > > > on it.
> > > >=20
> > > > With this, define our internal FP state to be the hosts XSAVE
> > > > data.
> > > > Add
> > > > discovery for the hosts XSAVE size and place the FP registers at
> > > > the end
> > > > of task_struct so that we can adjust the size at runtime.
> > > >=20
> > > > Next we can implement the regset API on top and update the signal
> > > > handling as well as ptrace APIs to use them. Also switch coredump
> > > > creation to use the regset API and finally set
> > > > HAVE_ARCH_TRACEHOOK.
> > > >=20
> > > > This considerably improves the signal frames. Previously they
> > > > might
> > > > not
> > > > have contained all the registers (i386) and also did not have the
> > > > sizes and magic values set to the correct values to permit
> > > > userspace to
> > > > decode the frame.
> > > >=20
> > > > As a side effect, this will permit UML to run on hosts with newer
> > > > CPU
> > > > extensions (such as AMX) that need even more register state.
> > > >=20
> > > > Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
> > >=20
> > > This patch seems to trip up KASAN. Or at least, KUnit tests fail
> > > when
> > > I
> > > enable CONFIG_KASAN, and 'git bisect' points me here:
> > >=20
> > > $ git bisect run ./tools/testing/kunit/kunit.py run
> > > stackinit.test_user --kconfig_add CONFIG_KASAN=3Dy
> > > [...]
> > > 3f17fed2149192c7d3b76a45a6a87b4ff22cd586 is the first bad commit
> > > commit 3f17fed2149192c7d3b76a45a6a87b4ff22cd586
> > > Author: Benjamin Berg <benjamin.berg@intel.com>
> > > Date:=C2=A0=C2=A0 Wed Oct 23 11:41:20 2024 +0200
> > >=20
> > > =C2=A0=C2=A0=C2=A0 um: switch to regset API and depend on XSTATE
> > > [...]
> > >=20
> > > If I run at Linus's latest:
> > >=20
> > > =C2=A0 243f750a2df0 Merge tag 'gpio-fixes-for-v6.13-rc3' of
> > > git://git.kernel.org/pub/scm/linux/kernel/git/brgl/linux
> > >=20
> > > I get a KASAN warning and panic [1]. I tried this fix for fun, but
> > > it
> > > doesn't help:
> > > Subject: [PATCH] um: add back support for FXSAVE registers
> > > https://lore.kernel.org/linux-um/20241204074827.1582917-1-benjamin@si=
psolutions.net/
> > >=20
> > > I'm not very familiar with this area, but let me know if there's
> > > more
> > > I
> > > can help with on tracking the issue down. Hopefully, it's as easy
> > > as
> > > running these same commands for you to reproduce.
> > >=20
> > > Brian
> > >=20
> > > [1]
> > > $ ./tools/testing/kunit/kunit.py run stackinit.test_user --
> > > kconfig_add CONFIG_KASAN=3Dy --raw_output=3Dall
> > > [...]
> > > <3>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > =3D=3D
> > > <3>BUG: KASAN: global-out-of-bounds in
> > > arch_dup_task_struct+0x4b/0x70
> > > <3>Read of size 4616 at addr 0000000060b1aec0 by task swapper/0
> > > <3>
> > > <3>CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.13.0-rc2-00194-
> > > g6787126c27ef #61
> > > <3>Stack:
> > > <4> 00000000 00000000 ffffff00 60acc428
> > > <4> 60ad2ffc 9f225db0 00000001 6008b7fb
> > > <4> 60b17aa0 6003fbf5 60b1aec0 6004c654
> > > <3>Call Trace:
> > > <3> [<60038c0e>] ? show_stack.cold+0x64/0xf3
> > > <3> [<6008b7fb>] ? dump_stack_lvl+0x8b/0xa7
> > > <3> [<6003fbf5>] ? _printk+0x0/0x103
> > > <3> [<6004c654>] ? print_report+0x145/0x519
> > > <3> [<60090f2b>] ? arch_dup_task_struct+0x4b/0x70
> > > <3> [<6031f854>] ? kasan_report+0x114/0x160
> > > <3> [<60090f2b>] ? arch_dup_task_struct+0x4b/0x70
> > > <3> [<60320830>] ? kasan_check_range+0x0/0x1e0
> > > <3> [<603209a0>] ? kasan_check_range+0x170/0x1e0
> > > <3> [<6032135d>] ? __asan_memcpy+0x2d/0x80
> > > <3> [<60090f2b>] ? arch_dup_task_struct+0x4b/0x70
> > > <3> [<600b9381>] ? copy_process+0x3e1/0x7390
> > > <3> [<600af1a0>] ? block_signals+0x0/0x20
> > > <3> [<603bb46e>] ? vfs_kern_mount.part.0+0x6e/0x140
> > > <3> [<601b48d6>] ? stack_trace_save+0x86/0xa0
> > > <3> [<6063ef2c>] ? stack_depot_save_flags+0x2c/0xa80
> > > <3> [<601b4850>] ? stack_trace_save+0x0/0xa0
> > > <3> [<6031e919>] ? kasan_save_stack+0x49/0x60
> > > <3> [<603bb46e>] ? vfs_kern_mount.part.0+0x6e/0x140
> > > <3> [<6031e919>] ? kasan_save_stack+0x49/0x60
> > > <3> [<600b8fa0>] ? copy_process+0x0/0x7390
> > > <3> [<600c04b3>] ? kernel_clone+0xd3/0x8c0
> > > <3> [<600c03e0>] ? kernel_clone+0x0/0x8c0
> > > <3> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <3> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <3> [<600c107d>] ? user_mode_thread+0x9d/0xc0
> > > <3> [<600c0fe0>] ? user_mode_thread+0x0/0xc0
> > > <3> [<60926934>] ? kernel_init+0x0/0x18c
> > > <3> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <3> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <3> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <3> [<603bb69d>] ? kern_mount+0x3d/0xb0
> > > <3> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <3> [<60926831>] ? rest_init+0x2d/0x130
> > > <3> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <3> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <3> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <3> [<60002679>] ? do_one_initcall+0x0/0x450
> > > <3> [<60005c97>] ? start_kernel_proc+0x0/0x1d
> > > <3> [<60005cb0>] ? start_kernel_proc+0x19/0x1d
> > > <3> [<600904fa>] ? new_thread_handler+0xca/0x130
> > > <3>
> > > <3>The buggy address belongs to the variable:
> > > <3> 0x60b1aec0
> > > <3>
> > > <3>The buggy address belongs to the physical page:
> > > <4>page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0
> > > pfn:0xb1a
> > > <4>flags: 0x2000(reserved|zone=3D0)
> > > <4>raw: 0000000000002000 000000009f225db8 000000009f225db8
> > > 0000000000000000
> > > <4>raw: 0000000000000000 0000000000000000 00000001ffffffff
> > > <4>page dumped because: kasan: bad access detected
> > > <3>
> > > <3>Memory state around the buggy address:
> > > <3> 0000000060b1b600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > 00
> > > <3> 0000000060b1b680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > 00
> > > <3>>0000000060b1b700: 00 00 00 00 00 00 00 00 f9 f9 f9 f9 00 00 00
> > > 00
> > > <3>=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
> > > <3> 0000000060b1b780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > 00
> > > <3> 0000000060b1b800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > 00
> > > <3>=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > =3D=3D
> > > <4>Disabling lock debugging due to kernel taint
> > > <4>
> > > <6>Pid: 0, comm: swapper Tainted: G=C2=A0=C2=A0=C2=A0 B=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 6.13.0-r=
c2-
> > > 00194-g6787126c27ef
> > > <6>RIP: 0033:copy_namespaces+0x104/0x2b0
> > > <6>RSP: 0000000060b17b70=C2=A0 EFLAGS: 00010246
> > > <6>RAX: 0000000000000001 RBX: 00000000610a8000 RCX:
> > > 0000000060133d7f
> > > <6>RDX: 0000000000000001 RSI: 0000000000000004 RDI:
> > > 0000000000000000
> > > <6>RBP: 0000000000000000 R08: 0000000000000001 R09:
> > > 0000100000000000
> > > <6>R10: 0000000000000003 R11: ffffffffffffffff R12:
> > > 0000000000800300
> > > <6>R13: 000000006102a000 R14: 00000000610a84d8 R15:
> > > 0000000060b31ba0
> > > <0>Kernel panic - not syncing: Segfault with no mm
> > > <4>CPU: 0 UID: 0 PID: 0 Comm: swapper Tainted: G=C2=A0=C2=A0=C2=A0 B=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0
> > > 6.13.0-rc2-00194-g6787126c27ef #61
> > > <4>Tainted: [B]=3DBAD_PAGE
> > > <4>Stack:
> > > <4> 00000000 60321286 61070380 0c162f92
> > > <4> 00000000 60b1aec0 61070110 610a8000
> > > <4> 610a8498 600bae85 61001400 60b17ed0
> > > <4>Call Trace:
> > > <4> [<60321286>] ? __asan_memset+0x26/0x50
> > > <4> [<600bae85>] ? copy_process+0x1ee5/0x7390
> > > <4> [<600af1a0>] ? block_signals+0x0/0x20
> > > <4> [<6063ef2c>] ? stack_depot_save_flags+0x2c/0xa80
> > > <4> [<601b4850>] ? stack_trace_save+0x0/0xa0
> > > <4> [<6031e919>] ? kasan_save_stack+0x49/0x60
> > > <4> [<603bb46e>] ? vfs_kern_mount.part.0+0x6e/0x140
> > > <4> [<6031e919>] ? kasan_save_stack+0x49/0x60
> > > <4> [<600b8fa0>] ? copy_process+0x0/0x7390
> > > <4> [<600c04b3>] ? kernel_clone+0xd3/0x8c0
> > > <4> [<600c03e0>] ? kernel_clone+0x0/0x8c0
> > > <4> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <4> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <4> [<600c107d>] ? user_mode_thread+0x9d/0xc0
> > > <4> [<600c0fe0>] ? user_mode_thread+0x0/0xc0
> > > <4> [<60926934>] ? kernel_init+0x0/0x18c
> > > <4> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <4> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <4> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <4> [<603bb69d>] ? kern_mount+0x3d/0xb0
> > > <4> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <4> [<60926831>] ? rest_init+0x2d/0x130
> > > <4> [<6003875e>] ? arch_local_irq_disable+0x0/0xc
> > > <4> [<60038743>] ? arch_irqs_disabled_flags+0x0/0x9
> > > <4> [<60038700>] ? arch_local_save_flags+0x0/0x43
> > > <4> [<60002679>] ? do_one_initcall+0x0/0x450
> > > <4> [<60005c97>] ? start_kernel_proc+0x0/0x1d
> > > <4> [<60005cb0>] ? start_kernel_proc+0x19/0x1d
> > > <4> [<600904fa>] ? new_thread_handler+0xca/0x130
> > > [11:56:56] Elapsed time: 6.794s total, 0.001s configuring, 5.513s
> > > building, 1.280s running
> > >=20
> > >=20
> >=20
> >=20
> >=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
2CINocd5Pqkzykw%40google.com.
