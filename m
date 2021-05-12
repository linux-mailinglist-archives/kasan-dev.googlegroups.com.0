Return-Path: <kasan-dev+bncBCJZRXGY5YJBB2PP6CCAMGQE34HONMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B33A937D426
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 22:17:46 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id i18-20020aa787d20000b02902ceff7cf271sf1567550pfo.14
        for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 13:17:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620850665; cv=pass;
        d=google.com; s=arc-20160816;
        b=BeqOziecNS2cQ7+qyyHgVc9tkMQ2/X+QQRatpeVT2R8aAZOLwUeSaPQRQz7INO3wWK
         cWTYcamR6z4fMztZLT9JfPrfyNKOLLbKv1L/aNSYPB+Y948RuZDHAPq1DPTkV9M666lg
         /MFYoB8Q93P3WMai/o5KVCztI/PMS8nXoIdWwmG7B4Kceit8/9ecqRpqcxJ+ixcz5+9q
         +NPJtnV9dnujmyR7YfPqBc4VFIdrpWZgxp241+jgCZvey1m2T+ZnTeeUef4u3Ez4PyGz
         1jZK0+Dl0z05ZP+PxwCso3YYi4U6j1dx7NtYNaJxsOw1ECl0ENit4D6flZxWMDNKLgbH
         Otcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GKRISh/bSPYhF4YN6oHyVOXQTy4rgtf1B/pSUFP40Ik=;
        b=r5bUtpDYvQqhT4GWcjS2URZKsSSkSosuE+MTOY12NrBjIuaiE/xIpa+3BsVUyvFzEU
         Q7lattI2zhCZNlpXZXrfSzU0XPVs55hDLUsw1+eMwuVAzQ4y96apkFy6hMk+2f9ZooBn
         8nCNOjqbbZeWyt/DdnUNUBmPOLrt3dNIwPWlVb9a97WCllSxihXHJXISCr/vZZBw6gfO
         v/jrRY8iC98NtJPkqgvsrC7l/LvMR7T4PrGKK7z07AmEe9F4RJVJsSeL7OcMm9v62R5F
         EOdIyCWnyOm5L/6Mo3xUb0fU1OEw2EvXoanb7tcBgP2OjzG2xzFDVCpJxBfPOkoYlPbe
         IloQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KRbWatYw;
       spf=pass (google.com: domain of srs0=ije9=kh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iJE9=KH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKRISh/bSPYhF4YN6oHyVOXQTy4rgtf1B/pSUFP40Ik=;
        b=KJZJouSz8/NOjwpR/MhpK9a8JBI+QUUs2cnNA+h3v20HdOqUw1GN2ejk+KOxhJCYe/
         zhhNw7+yiMFl+1W08kO14qOWklULPDrAxHUbUoekHpNuykKxjma11qez21rPpFCc047e
         L+5VyfNZsh05+x8GZS2h0oGMHLwKVf7W4SEJTfeahJMFHnAfklBbd6iAA5pKxriu1mRN
         wneryegmH2qH25w3YEjqdFeZtjons/xwHyMLoEH6zZ3qnLVAaCKxcymLEGBQuF6SG/Jq
         TCD2CYzMaRwPodFcwsj5aJQSE3d11aisXNiDrV1Bxg6BK+IElEI8aeox+M+1I39GeSqw
         mS3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKRISh/bSPYhF4YN6oHyVOXQTy4rgtf1B/pSUFP40Ik=;
        b=ZsGh9QgR2h1bF5OKMaKxLFJxi/y5Ck3hJTgoWUT2V4mwaKNTZQkCMGZKKbH580kG0m
         6m85Ibzp7sto1GCQAkbbPyAiQT10y08ZjEdaXHzIlARv8kXjg13oJzN3/YmxyzmYcFog
         Wbw3QpEBHnNp4orFd8hNhKr50Esp5NvNacFEe3ZQ/Qr4GseG6cC7bfW3Jc0RcF1C3Ry5
         yHt2KFoGOqt/F5mCdoPqwjsSypZ80Y3UvzI3eiht958miqr5K+Zfm+WozyopfJBmTIR9
         hwZgWQrF/io3HYlTlBoqZ/x1lv0F5LAIOZqC21EBTEooIPzKevgIbRMchXl2R1VxOt/B
         aukQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rw7X3wLpI/eMRIvGMC10sV0YpJ8NLfEvomYXDbTvIvd3DZ8wZ
	KNffskdrZOzwjnCQXH453TY=
X-Google-Smtp-Source: ABdhPJwRr44JxUnc8dW+d5d7L6+nw/LwQ8O2rfBRRsJZhs78c/76SuXc+hMQuS23vKQMS9eQ0xBTNQ==
X-Received: by 2002:a17:90a:7896:: with SMTP id x22mr292220pjk.11.1620850665409;
        Wed, 12 May 2021 13:17:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3014:: with SMTP id hg20ls4344759pjb.3.canary-gmail;
 Wed, 12 May 2021 13:17:44 -0700 (PDT)
X-Received: by 2002:a17:90a:5511:: with SMTP id b17mr280420pji.41.1620850664807;
        Wed, 12 May 2021 13:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620850664; cv=none;
        d=google.com; s=arc-20160816;
        b=ld41xfyPYfxpB+eRWkxBJ/evis8Dl6BXBVCoe06UzNHi7MgMbOmJxZ9FXKc/0t4De2
         pAdvPxh6FjJFOvT0ul6bHD8CJqQI4jtQoHSvK3XAI8G8bidC9PROtM3GgzqrLqiquo1b
         eIgJADQZJ+dEgvyt8Fy4SW8AxXq0kBeiTu3hVKYEB8cPkdkTqqKzuCzThD/Ahx+lT8o9
         1zNtgxYplU3q+YflAr8L0izL+CmOWegVRikzLEnKJqk7J/iq9YKDRqu5LnN4CexTDcm3
         o47pvIB7iK1xo9blYGBAgHKlPu17unHIiPHwQ49oRIuYfpAQG+DQiMJ3ylF2zf8b4KjG
         4BAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=n/33gzjQQ2oiNHshnqGaSMLel5hXt0k4bAmrmlKlzzc=;
        b=dPOOTmB4s57IC6l5AAcchZLg06BqPM8z3DsZV2+TRNxRKROwfQKZpu5EbSjlfJSXyK
         f3yWIsy27Jh7WAKFH0TSv0eiN7rnDHDz7mTSP9PQ7+R+f3SLjg0aZJuY77eVzSZD4xFe
         u2DRlTefA7c+3JK68PpazKqBhwgwQf8WnYx0z61CMIORyQ8YeFOzwPhvk7Gj7hr3s8DE
         nfo31K0YinRTHCZ+1l3iGo1MrjxkQ5U4eRq+9FfD9yQ9wC/KNCzYa+c37JrkSasF0snk
         KDiz0VDVo0qOX1Y6tFc39fsD8yJ82taprGqabt6b5YCHS9ATEnUjdeWcKMP9sNpEG2nz
         d28A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KRbWatYw;
       spf=pass (google.com: domain of srs0=ije9=kh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iJE9=KH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q59si471126pjh.0.2021.05.12.13.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 May 2021 13:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ije9=kh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 65D9F60E09;
	Wed, 12 May 2021 20:17:44 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E6E7D5C0379; Wed, 12 May 2021 13:17:43 -0700 (PDT)
Date: Wed, 12 May 2021 13:17:43 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KRbWatYw;       spf=pass
 (google.com: domain of srs0=ije9=kh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iJE9=KH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
> Hi,
>=20
> I got a report from kcsan for sem_lock()/sem_unlock(), but I'm fairly
> certain that this is a false positive:
>=20
> > [=C2=A0 184.344960] BUG: KCSAN: data-race in sem_lock / sem_unlock.part=
.0
> > [=C2=A0 184.360437]
> > [=C2=A0 184.375443] write to 0xffff8881022fd6c0 of 4 bytes by task 1128=
 on
> > cpu 0:
> > [=C2=A0 184.391192]=C2=A0 sem_unlock.part.0+0xfa/0x118
> 0000000000001371 <sem_unlock.part.0>:
> static inline void sem_unlock(struct sem_array *sma, int locknum)
> =C2=A0=C2=A0=C2=A0 1464:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 eb 0f=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 jmp=C2=A0=C2=A0=C2=A0 1475
> <sem_unlock.part.0+0x104>
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 sma->use_global_lock--;
> =C2=A0=C2=A0=C2=A0 1466:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 e8 00 00 00 =
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 callq=C2=A0 146b <=
sem_unlock.part.0+0xfa>
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1467: R_=
X86_64_PLT32=C2=A0=C2=A0=C2=A0 __tsan_write4-0x4
> =C2=A0=C2=A0=C2=A0 146b:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 41 ff cc=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 dec=C2=A0=C2=A0=C2=A0 %r12d
>=20
> > [=C2=A0 184.406693]=C2=A0 do_semtimedop+0x690/0xab3
> > [=C2=A0 184.422032]=C2=A0 __x64_sys_semop+0x3e/0x43
> > [=C2=A0 184.437180]=C2=A0 do_syscall_64+0x9e/0xb5
> > [=C2=A0 184.452125]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xae
> > [=C2=A0 184.467269]
> > [=C2=A0 184.482215] read to 0xffff8881022fd6c0 of 4 bytes by task 1129 =
on cpu
> > 2:
> > [=C2=A0 184.497750]=C2=A0 sem_lock+0x59/0xe0
> 0000000000001bbc <sem_lock>:
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lock) {
> =C2=A0=C2=A0=C2=A0 1c0a:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 4c 89 ef=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 mov=C2=A0=C2=A0=C2=A0 %r13,%rdi
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 idx =3D array_index_nospec(sop=
s->sem_num, sma->sem_nsems);
> =C2=A0=C2=A0=C2=A0 1c0d:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0f b7 db=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 movzwl %bx,%ebx
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lock) {
> =C2=A0=C2=A0=C2=A0 1c10:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 e8 00 00 00 =
00=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 callq=C2=A0 1c15 <=
sem_lock+0x59>
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 1c11: R_=
X86_64_PLT32=C2=A0=C2=A0=C2=A0 __tsan_read4-0x4
>=20
> > [=C2=A0 184.513121]=C2=A0 do_semtimedop+0x4f6/0xab3
> > [=C2=A0 184.528427]=C2=A0 __x64_sys_semop+0x3e/0x43
> > [=C2=A0 184.543540]=C2=A0 do_syscall_64+0x9e/0xb5
> > [=C2=A0 184.558473]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xae
>=20
>=20
> sma->use_global_lock is evaluated in sem_lock() twice:
>=20
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial check for us=
e_global_lock. Just an optimization,
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, no memor=
y barrier.
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lock) {
> Both sides of the if-clause handle possible data races.
>=20
> Is
>=20
> =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
>=20
> the correct thing to suppress the warning?

Most likely READ_ONCE() rather than data_race(), but please see
the end of this message.

> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 /*
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 * It appears that no complex operation is aroun=
d.
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Acquire the per-semaphore lock.
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 spin_lock(&sem->lock);
> >=20
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 /* see SEM_BARRIER_1 for purpose/pairing */
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 if (!smp_load_acquire(&sma->use_global_lock)) {
> Here I would need advise: The code only checks for zero / non-zero.

The smp_load_acquire() is just fine.

> This pairs with complexmode_tryleave():
>=20
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (sma->use_global_lock =3D=
=3D 1) {
> >=20
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 /* See SEM_BARRIER_1 for purpose/pairing */
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 smp_store_release(&sma->use_global_lock, 0);
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else {
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 sma->use_global_lock--;
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>=20
> If use_global_lock is reduced from e.g. 6 to 5, it is undefined if a
> concurrent reader sees 6 or 5. But it doesn't matter, as both values are
> non-zero.
>=20
> The change to 0 is protected.

Again, most likely a READ_ONCE() for sma->use_global_lock, but again
please see the end of this message.

The key point is that adding (or avoiding) markings is not a mechanical
process.

> What is the right way to prevent false positives from kcsan?
>=20
> As 2nd question:
>=20
> net/netfilter/nf_conntrack_core.c, nf_conntrack_all_lock():
>=20
> Is a data_race() needed around "nf_conntrack_locks_all =3D true;"?

Interesting code.  The nf_conntrack_all_lock() function acquires
nf_conntrack_locks_all_lock, except that the smp_load_acquire() of
nf_conntrack_locks_all in nf_conntrack_lock() might be protected by any
of a number of locks.

In contrast, it appears that the smp_store_release()
in nf_conntrack_all_unlock() is always protected by
nf_conntrack_locks_all_lock.

Is the fact that nf_conntrack_all_lock()'s store can run concurrently
with nf_conntrack_lock() smp_load_acquire() intentional?  If not, then
KCSAN is letting you know of a bug.  Otherwise, WRITE_ONCE() might
be helpful, but I don't know this code, so that is just a guess.

Does tools/memory-model/Documentation/access-marking.txt, shown below,
help?

							Thanx, Paul

------------------------------------------------------------------------

MARKING SHARED-MEMORY ACCESSES
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D

This document provides guidelines for marking intentionally concurrent
normal accesses to shared memory, that is "normal" as in accesses that do
not use read-modify-write atomic operations.  It also describes how to
document these accesses, both with comments and with special assertions
processed by the Kernel Concurrency Sanitizer (KCSAN).  This discussion
builds on an earlier LWN article [1].


ACCESS-MARKING OPTIONS
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

The Linux kernel provides the following access-marking options:

1.	Plain C-language accesses (unmarked), for example, "a =3D b;"

2.	Data-race marking, for example, "data_race(a =3D b);"

3.	READ_ONCE(), for example, "a =3D READ_ONCE(b);"
	The various forms of atomic_read() also fit in here.

4.	WRITE_ONCE(), for example, "WRITE_ONCE(a, b);"
	The various forms of atomic_set() also fit in here.


These may be used in combination, as shown in this admittedly improbable
example:

	WRITE_ONCE(a, b + data_race(c + d) + READ_ONCE(e));

Neither plain C-language accesses nor data_race() (#1 and #2 above) place
any sort of constraint on the compiler's choice of optimizations [2].
In contrast, READ_ONCE() and WRITE_ONCE() (#3 and #4 above) restrict the
compiler's use of code-motion and common-subexpression optimizations.
Therefore, if a given access is involved in an intentional data race,
using READ_ONCE() for loads and WRITE_ONCE() for stores is usually
preferable to data_race(), which in turn is usually preferable to plain
C-language accesses.

KCSAN will complain about many types of data races involving plain
C-language accesses, but marking all accesses involved in a given data
race with one of data_race(), READ_ONCE(), or WRITE_ONCE(), will prevent
KCSAN from complaining.  Of course, lack of KCSAN complaints does not
imply correct code.  Therefore, please take a thoughtful approach
when responding to KCSAN complaints.  Churning the code base with
ill-considered additions of data_race(), READ_ONCE(), and WRITE_ONCE()
is unhelpful.

In fact, the following sections describe situations where use of
data_race() and even plain C-language accesses is preferable to
READ_ONCE() and WRITE_ONCE().


Use of the data_race() Macro
----------------------------

Here are some situations where data_race() should be used instead of
READ_ONCE() and WRITE_ONCE():

1.	Data-racy loads from shared variables whose values are used only
	for diagnostic purposes.

2.	Data-racy reads whose values are checked against marked reload.

3.	Reads whose values feed into error-tolerant heuristics.

4.	Writes setting values that feed into error-tolerant heuristics.


Data-Racy Reads for Approximate Diagnostics

Approximate diagnostics include lockdep reports, monitoring/statistics
(including /proc and /sys output), WARN*()/BUG*() checks whose return
values are ignored, and other situations where reads from shared variables
are not an integral part of the core concurrency design.

In fact, use of data_race() instead READ_ONCE() for these diagnostic
reads can enable better checking of the remaining accesses implementing
the core concurrency design.  For example, suppose that the core design
prevents any non-diagnostic reads from shared variable x from running
concurrently with updates to x.  Then using plain C-language writes
to x allows KCSAN to detect reads from x from within regions of code
that fail to exclude the updates.  In this case, it is important to use
data_race() for the diagnostic reads because otherwise KCSAN would give
false-positive warnings about these diagnostic reads.

In theory, plain C-language loads can also be used for this use case.
However, in practice this will have the disadvantage of causing KCSAN
to generate false positives because KCSAN will have no way of knowing
that the resulting data race was intentional.


Data-Racy Reads That Are Checked Against Marked Reload

The values from some reads are not implicitly trusted.  They are instead
fed into some operation that checks the full value against a later marked
load from memory, which means that the occasional arbitrarily bogus value
is not a problem.  For example, if a bogus value is fed into cmpxchg(),
all that happens is that this cmpxchg() fails, which normally results
in a retry.  Unless the race condition that resulted in the bogus value
recurs, this retry will with high probability succeed, so no harm done.

However, please keep in mind that a data_race() load feeding into
a cmpxchg_relaxed() might still be subject to load fusing on some
architectures.  Therefore, it is best to capture the return value from
the failing cmpxchg() for the next iteration of the loop, an approach
that provides the compiler much less scope for mischievous optimizations.
Capturing the return value from cmpxchg() also saves a memory reference
in many cases.

In theory, plain C-language loads can also be used for this use case.
However, in practice this will have the disadvantage of causing KCSAN
to generate false positives because KCSAN will have no way of knowing
that the resulting data race was intentional.


Reads Feeding Into Error-Tolerant Heuristics

Values from some reads feed into heuristics that can tolerate occasional
errors.  Such reads can use data_race(), thus allowing KCSAN to focus on
the other accesses to the relevant shared variables.  But please note
that data_race() loads are subject to load fusing, which can result in
consistent errors, which in turn are quite capable of breaking heuristics.
Therefore use of data_race() should be limited to cases where some other
code (such as a barrier() call) will force the occasional reload.

In theory, plain C-language loads can also be used for this use case.
However, in practice this will have the disadvantage of causing KCSAN
to generate false positives because KCSAN will have no way of knowing
that the resulting data race was intentional.


Writes Setting Values Feeding Into Error-Tolerant Heuristics

The values read into error-tolerant heuristics come from somewhere,
for example, from sysfs.  This means that some code in sysfs writes
to this same variable, and these writes can also use data_race().
After all, if the heuristic can tolerate the occasional bogus value
due to compiler-mangled reads, it can also tolerate the occasional
compiler-mangled write, at least assuming that the proper value is in
place once the write completes.

Plain C-language stores can also be used for this use case.  However,
in kernels built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn, this
will have the disadvantage of causing KCSAN to generate false positives
because KCSAN will have no way of knowing that the resulting data race
was intentional.


Use of Plain C-Language Accesses
--------------------------------

Here are some example situations where plain C-language accesses should
used instead of READ_ONCE(), WRITE_ONCE(), and data_race():

1.	Accesses protected by mutual exclusion, including strict locking
	and sequence locking.

2.	Initialization-time and cleanup-time accesses.	This covers a
	wide variety of situations, including the uniprocessor phase of
	system boot, variables to be used by not-yet-spawned kthreads,
	structures not yet published to reference-counted or RCU-protected
	data structures, and the cleanup side of any of these situations.

3.	Per-CPU variables that are not accessed from other CPUs.

4.	Private per-task variables, including on-stack variables, some
	fields in the task_struct structure, and task-private heap data.

5.	Any other loads for which there is not supposed to be a concurrent
	store to that same variable.

6.	Any other stores for which there should be neither concurrent
	loads nor concurrent stores to that same variable.

	But note that KCSAN makes two explicit exceptions to this rule
	by default, refraining from flagging plain C-language stores:

	a.	No matter what.  You can override this default by building
		with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn.

	b.	When the store writes the value already contained in
		that variable.	You can override this default by building
		with CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn.

	c.	When one of the stores is in an interrupt handler and
		the other in the interrupted code.  You can override this
		default by building with CONFIG_KCSAN_INTERRUPT_WATCHER=3Dy.

Note that it is important to use plain C-language accesses in these cases,
because doing otherwise prevents KCSAN from detecting violations of your
code's synchronization rules.


ACCESS-DOCUMENTATION OPTIONS
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

It is important to comment marked accesses so that people reading your
code, yourself included, are reminded of the synchronization design.
However, it is even more important to comment plain C-language accesses
that are intentionally involved in data races.  Such comments are
needed to remind people reading your code, again, yourself included,
of how the compiler has been prevented from optimizing those accesses
into concurrency bugs.

It is also possible to tell KCSAN about your synchronization design.
For example, ASSERT_EXCLUSIVE_ACCESS(foo) tells KCSAN that any
concurrent access to variable foo by any other CPU is an error, even
if that concurrent access is marked with READ_ONCE().  In addition,
ASSERT_EXCLUSIVE_WRITER(foo) tells KCSAN that although it is OK for there
to be concurrent reads from foo from other CPUs, it is an error for some
other CPU to be concurrently writing to foo, even if that concurrent
write is marked with data_race() or WRITE_ONCE().

Note that although KCSAN will call out data races involving either
ASSERT_EXCLUSIVE_ACCESS() or ASSERT_EXCLUSIVE_WRITER() on the one hand
and data_race() writes on the other, KCSAN will not report the location
of these data_race() writes.


EXAMPLES
=3D=3D=3D=3D=3D=3D=3D=3D

As noted earlier, the goal is to prevent the compiler from destroying
your concurrent algorithm, to help the human reader, and to inform
KCSAN of aspects of your concurrency design.  This section looks at a
few examples showing how this can be done.


Lock Protection With Lockless Diagnostic Access
-----------------------------------------------

For example, suppose a shared variable "foo" is read only while a
reader-writer spinlock is read-held, written only while that same
spinlock is write-held, except that it is also read locklessly for
diagnostic purposes.  The code might look as follows:

	int foo;
	DEFINE_RWLOCK(foo_rwlock);

	void update_foo(int newval)
	{
		write_lock(&foo_rwlock);
		foo =3D newval;
		do_something(newval);
		write_unlock(&foo_rwlock);
	}

	int read_foo(void)
	{
		int ret;

		read_lock(&foo_rwlock);
		do_something_else();
		ret =3D foo;
		read_unlock(&foo_rwlock);
		return ret;
	}

	int read_foo_diagnostic(void)
	{
		return data_race(foo);
	}

The reader-writer lock prevents the compiler from introducing concurrency
bugs into any part of the main algorithm using foo, which means that
the accesses to foo within both update_foo() and read_foo() can (and
should) be plain C-language accesses.  One benefit of making them be
plain C-language accesses is that KCSAN can detect any erroneous lockless
reads from or updates to foo.  The data_race() in read_foo_diagnostic()
tells KCSAN that data races are expected, and should be silently
ignored.  This data_race() also tells the human reading the code that
read_foo_diagnostic() might sometimes return a bogus value.

However, please note that your kernel must be built with
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn in order for KCSAN to
detect a buggy lockless write.  If you need KCSAN to detect such a
write even if that write did not change the value of foo, you also
need CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn.  If you need KCSAN to
detect such a write happening in an interrupt handler running on the
same CPU doing the legitimate lock-protected write, you also need
CONFIG_KCSAN_INTERRUPT_WATCHER=3Dy.  With some or all of these Kconfig
options set properly, KCSAN can be quite helpful, although it is not
necessarily a full replacement for hardware watchpoints.  On the other
hand, neither are hardware watchpoints a full replacement for KCSAN
because it is not always easy to tell hardware watchpoint to conditionally
trap on accesses.


Lock-Protected Writes With Lockless Reads
-----------------------------------------

For another example, suppose a shared variable "foo" is updated only
while holding a spinlock, but is read locklessly.  The code might look
as follows:

	int foo;
	DEFINE_SPINLOCK(foo_lock);

	void update_foo(int newval)
	{
		spin_lock(&foo_lock);
		WRITE_ONCE(foo, newval);
		ASSERT_EXCLUSIVE_WRITER(foo);
		do_something(newval);
		spin_unlock(&foo_wlock);
	}

	int read_foo(void)
	{
		do_something_else();
		return READ_ONCE(foo);
	}

Because foo is read locklessly, all accesses are marked.  The purpose
of the ASSERT_EXCLUSIVE_WRITER() is to allow KCSAN to check for a buggy
concurrent lockless write.


Lockless Reads and Writes
-------------------------

For another example, suppose a shared variable "foo" is both read and
updated locklessly.  The code might look as follows:

	int foo;

	int update_foo(int newval)
	{
		int ret;

		ret =3D xchg(&foo, newval);
		do_something(newval);
		return ret;
	}

	int read_foo(void)
	{
		do_something_else();
		return READ_ONCE(foo);
	}

Because foo is accessed locklessly, all accesses are marked.  It does
not make sense to use ASSERT_EXCLUSIVE_WRITER() in this case because
there really can be concurrent lockless writers.  KCSAN would
flag any concurrent plain C-language reads from foo, and given
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn, also any concurrent plain
C-language writes to foo.


Lockless Reads and Writes, But With Single-Threaded Initialization
------------------------------------------------------------------

For yet another example, suppose that foo is initialized in a
single-threaded manner, but that a number of kthreads are then created
that locklessly and concurrently access foo.  Some snippets of this code
might look as follows:

	int foo;

	void initialize_foo(int initval, int nkthreads)
	{
		int i;

		foo =3D initval;
		ASSERT_EXCLUSIVE_ACCESS(foo);
		for (i =3D 0; i < nkthreads; i++)
			kthread_run(access_foo_concurrently, ...);
	}

	/* Called from access_foo_concurrently(). */
	int update_foo(int newval)
	{
		int ret;

		ret =3D xchg(&foo, newval);
		do_something(newval);
		return ret;
	}

	/* Also called from access_foo_concurrently(). */
	int read_foo(void)
	{
		do_something_else();
		return READ_ONCE(foo);
	}

The initialize_foo() uses a plain C-language write to foo because there
are not supposed to be concurrent accesses during initialization.  The
ASSERT_EXCLUSIVE_ACCESS() allows KCSAN to flag buggy concurrent unmarked
reads, and the ASSERT_EXCLUSIVE_ACCESS() call further allows KCSAN to
flag buggy concurrent writes, even if:  (1) Those writes are marked or
(2) The kernel was built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dy.


Checking Stress-Test Race Coverage
----------------------------------

When designing stress tests it is important to ensure that race conditions
of interest really do occur.  For example, consider the following code
fragment:

	int foo;

	int update_foo(int newval)
	{
		return xchg(&foo, newval);
	}

	int xor_shift_foo(int shift, int mask)
	{
		int old, new, newold;

		newold =3D data_race(foo); /* Checked by cmpxchg(). */
		do {
			old =3D newold;
			new =3D (old << shift) ^ mask;
			newold =3D cmpxchg(&foo, old, new);
		} while (newold !=3D old);
		return old;
	}

	int read_foo(void)
	{
		return READ_ONCE(foo);
	}

If it is possible for update_foo(), xor_shift_foo(), and read_foo() to be
invoked concurrently, the stress test should force this concurrency to
actually happen.  KCSAN can evaluate the stress test when the above code
is modified to read as follows:

	int foo;

	int update_foo(int newval)
	{
		ASSERT_EXCLUSIVE_ACCESS(foo);
		return xchg(&foo, newval);
	}

	int xor_shift_foo(int shift, int mask)
	{
		int old, new, newold;

		newold =3D data_race(foo); /* Checked by cmpxchg(). */
		do {
			old =3D newold;
			new =3D (old << shift) ^ mask;
			ASSERT_EXCLUSIVE_ACCESS(foo);
			newold =3D cmpxchg(&foo, old, new);
		} while (newold !=3D old);
		return old;
	}


	int read_foo(void)
	{
		ASSERT_EXCLUSIVE_ACCESS(foo);
		return READ_ONCE(foo);
	}

If a given stress-test run does not result in KCSAN complaints from
each possible pair of ASSERT_EXCLUSIVE_ACCESS() invocations, the
stress test needs improvement.  If the stress test was to be evaluated
on a regular basis, it would be wise to place the above instances of
ASSERT_EXCLUSIVE_ACCESS() under #ifdef so that they did not result in
false positives when not evaluating the stress test.


REFERENCES
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

[1] "Concurrency bugs should fear the big bad data-race detector (part 2)"
    https://lwn.net/Articles/816854/

[2] "Who's afraid of a big bad optimizing compiler?"
    https://lwn.net/Articles/793253/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210512201743.GW975577%40paulmck-ThinkPad-P17-Gen-1.
