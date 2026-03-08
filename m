Return-Path: <kasan-dev+bncBD3JJNUUIQILJBFVZUDBUBHNOJBQ4@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GMxMMzZCrWkM0QEAu9opvQ
	(envelope-from <kasan-dev+bncBD3JJNUUIQILJBFVZUDBUBHNOJBQ4@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sun, 08 Mar 2026 10:32:38 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7171A22F34D
	for <lists+kasan-dev@lfdr.de>; Sun, 08 Mar 2026 10:32:38 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-40996e43ddasf26616861fac.3
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Mar 2026 01:32:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772962356; cv=pass;
        d=google.com; s=arc-20240605;
        b=XLwGAdu3jz7kO4q3AFcPxW+j2OwYsjh6ewvoJUU0Eae8mGTv37RZkt2VAgtix8JQ+3
         5H4ny4TyRWn5rkY7wQyAudX83O5ROyQxxoei9QwdsPw9aQkDCTDJM7wt/uzxa7KU3iKF
         pS7bUCPKyFOfKo3/WZduduJymGEgaWTxJk3GP+SGY2bdzdsf3AVbo2AAbVkXNcuBrwtB
         J24TsNUQy/NYEMQULVgXBHS6d6GSuZVy8pvFOVq2E4MHYL/10B4TuN9K40v/o56wUc4r
         Y+dQoDzc0rTLD3qFGrLHCAgsR3IDwGA0o5HQ+E58Iro455fuzJDCD/iStP737PSjqvvg
         YXMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=6ifxPFEYUyS9tIlMJJnNA6huP8C1fOkFE+nS3yBL/RQ=;
        fh=FtSEC2DDjebOETcmnJ591MLDYljuIQ/LO1l0zinX5Dc=;
        b=hLGdXHxX917vK6uaoOxCjFcCWf6q0G69wMYDIjnvb+U4Fth4qCnwxrd1bs9dFzn/eP
         7TaDfHJTVavtxnOEJXv2lj26sS3CHDQ7L9wgGn6tYpVXLI6Pm/y9uf2Lb4RvB+Y4UBzu
         L1OKDZCnzLbQi0OS/cdGjg0hmVKHO/cxZxO4jfLWUWlz0GAFmL2soNJ1LxTWPj1JpsjV
         XJO9RcaPXgL3ndS4VX9o1qC/tOo9+Pnp8PqTiNb0i7JuNjmSfmzqu+AVDGcDBTUfVeHY
         FDxlw48glugsU7NURaKSZat3tMMgBXxe7NC1EklYoeitFCIIIbTeuD07Mw6DdTHtiODa
         kuwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Q/IppdUS";
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772962356; x=1773567156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6ifxPFEYUyS9tIlMJJnNA6huP8C1fOkFE+nS3yBL/RQ=;
        b=TvQvqvUZqpMaYfAIe2DoGj0vEcgeKkNyRUfxj2ArcFp83gi8OqOk/fBaavC9T77okA
         Sz+MhQmhUJdFnIEvDw2WZJjnNlJINdzL6Nf+11FknLXhceC7wM7GIDqbEMqASxSw9ny1
         NhUqT4mbTHIGM2ulfmf8VzgOQcheXUoca33OKNSxWnRsBH3H3Szq4FohQbyYqovwEthC
         kGMsS0L2/EltCkxHN0HD7P6uqAMUh/5m4Mzkgd5xsx/pdchJdc5EihuP9uZtENHTGdjC
         AKBYL0BDiCA3owI5Bf4ID7Lf6Rmyo8GNo0Gg2RT3DitCaROYL+9oo+NJTO4sTH2RAu5I
         1A7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772962356; x=1773567156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6ifxPFEYUyS9tIlMJJnNA6huP8C1fOkFE+nS3yBL/RQ=;
        b=xLJwCN0Yy2lTiqD8ETnun79ZtaeihUsqWiUURJu3uQzsdVD2Ap1b0sovT8K657p59a
         ReX/fTPM8TWORuXL0O5cR/Bu1SLQq/AnaODA6/rk8sAB90nUTA8ytg8+Pv+YzqY4GZ9r
         RhvZMOHpyiSi+esn93I+IAcQjdaSMn7sqCqjPNfkUls9YMfoB0WELK/nRKJThQ0Hv0N/
         Wknx3+jD6cQ2Qa/m153LrH8JOQTqXsgWXq4yjCBV2g2Om0rIgm9I88uZmiyXZ4KntNGF
         UJ6PcboYsYHHF/P1YdjmGYeEqXjgtb2GRH6caVYp960HuV1wxPd3lGjE3149ueufp5it
         z8Bw==
X-Forwarded-Encrypted: i=2; AJvYcCVMRNQTqdfEDSC6jC14k+IuNNqCpYmC3E6/nqY52x8YdSwVkQRlXFJ/D4ny/tNaD9ynnFaWSQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHCIUDFFY2c3dNpIEMti5PaTb/I2g8i1b7LiBkDT1TpMqT+pw6
	v0+1eWtqUqJHRP30XSneD660pp8rWGLsT0y2smZIR+IZ25qXqXgGvD4/
X-Received: by 2002:a05:6870:7d03:b0:409:83a2:51c5 with SMTP id 586e51a60fabf-416e401b7cfmr4322248fac.22.1772962356359;
        Sun, 08 Mar 2026 01:32:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FJBGBU5k4ffn6uRsx1/VF+m7yPJDqEB24XGS12yQNeOQ=="
Received: by 2002:a05:6870:a70f:b0:409:6328:a767 with SMTP id
 586e51a60fabf-416c4ceea28ls1526026fac.1.-pod-prod-04-us; Sun, 08 Mar 2026
 01:32:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW9EXAGl69iRxmvQ44UW6pN8kY0EzIMR1k4qoCOyGlaipYQQOz6KdVa0Q3tRt6lhi2HWz1mKUQY8PY=@googlegroups.com
X-Received: by 2002:a05:6808:3089:b0:45c:7b2c:10bb with SMTP id 5614622812f47-466dcb9bc62mr4918280b6e.60.1772962354608;
        Sun, 08 Mar 2026 01:32:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772962354; cv=none;
        d=google.com; s=arc-20240605;
        b=KJ0a1G3yeq7tGXHjmYCgqkKumGze9VSk5ZfPhueB0Bx1m0iyxyLktjvVea8Jt9fgWW
         syLviWlM5RvCKy6mvPtYYNLOdGuJqVePc3e9nOidWkyOrutXNFA/H4m5LhGcr7OaT63U
         gykTdETFWut3Tlyk7Fj+6JsDK7ly96tsBty1c/f6h/Lnbvw/QnB4us2q5gm/0sQmYsPc
         iOHYvEr68yLoExGkugTqbh7Wr8plu0SLaNNmUSO3N3Q+461+fw2YkZcE6KdQtPsdf8bW
         MER4moK57Y+n0re3mW9q0tf3aQp7K0evFfRKCJ8X9jAqcRAuA/hK4zM78YlpNqYJs2TP
         NsnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=LSDmpHL9HsVki+UW2afAcHGV6WLwwyY5DUrYJnIQHsk=;
        fh=uvDBdXA+g0bN7KxmC5NJnN3ntTDVC0cSTWI1Fy+1FPM=;
        b=NGvJ7rVGkJQcgeG/aXNJA9wscyT9sj7ihulQ2AcPoaW0ld1vay3DlAI+iFZQKB3QD9
         FgLjFZ51GVZCSSkn3CFvk2uOMLEAsUhAkI2LilxTAC2Fp30sGmUjjsM8KOWvLBOZYM1e
         qZCESEqt3RvDgzHcp3fMtpYPZ1Gr6FYqcVgf69O3BMNiUY1bRCOjaeHdnxgqFoudyLv/
         mhujqwa7DFd77RwxnKkC68h0kaoR4k811xUmp+2WwRr+j0augEYaVBRh/jUwMymw0QhT
         kU6xd8cOtPqCR2RXoxtBAsv9EksMXsG/8XkliPrQRXvTiR+UjWfp+J+Bny8r6f6mShgy
         qk6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Q/IppdUS";
       spf=pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=tglx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-466dfa97770si198783b6e.5.2026.03.08.01.32.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 08 Mar 2026 01:32:34 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D59E944049;
	Sun,  8 Mar 2026 09:32:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DCC27C116C6;
	Sun,  8 Mar 2026 09:32:32 +0000 (UTC)
From: "'Thomas Gleixner' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot <syzbot+5fca9514ef36ad94d973@syzkaller.appspotmail.com>,
 jstultz@google.com, linux-kernel@vger.kernel.org, sboyd@kernel.org,
 syzkaller-bugs@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 kasan-dev@googlegroups.com
Subject: Re: [syzbot] [kernel?] KMSAN: uninit-value in timespec64_add_safe
In-Reply-To: <69aa4169.050a0220.13f275.0007.GAE@google.com>
References: <69aa4169.050a0220.13f275.0007.GAE@google.com>
Date: Sun, 08 Mar 2026 10:32:30 +0100
Message-ID: <874imq3bv5.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Q/IppdUS";       spf=pass
 (google.com: domain of tglx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=tglx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Thomas Gleixner <tglx@kernel.org>
Reply-To: Thomas Gleixner <tglx@kernel.org>
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
X-Rspamd-Queue-Id: 7171A22F34D
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4864::/56];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail-oa1-x3f.google.com:rdns,mail-oa1-x3f.google.com:helo];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBD3JJNUUIQILJBFVZUDBUBHNOJBQ4];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	HAS_REPLYTO(0.00)[tglx@kernel.org];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.996];
	TAGGED_RCPT(0.00)[kasan-dev,5fca9514ef36ad94d973];
	RCPT_COUNT_SEVEN(0.00)[8];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	SUBJECT_HAS_QUESTION(0.00)[]
X-Rspamd-Action: no action

On Thu, Mar 05 2026 at 18:52, syzbot wrote:
> udevd[5131]: starting eudev-3.2.14
> =====================================================
> BUG: KMSAN: uninit-value in set_normalized_timespec64 kernel/time/time.c:492 [inline]
> BUG: KMSAN: uninit-value in timespec64_add_safe+0x4b4/0x520 kernel/time/time.c:846
>  set_normalized_timespec64 kernel/time/time.c:492 [inline]
>  timespec64_add_safe+0x4b4/0x520 kernel/time/time.c:846
>  ep_timeout_to_timespec fs/eventpoll.c:1872 [inline]
>  __do_sys_epoll_wait fs/eventpoll.c:2471 [inline]
>  __se_sys_epoll_wait fs/eventpoll.c:2465 [inline]
>  __x64_sys_epoll_wait+0x1fa/0x3a0 fs/eventpoll.c:2465
>  x64_sys_call+0x2ece/0x3ea0 arch/x86/include/generated/asm/syscalls_64.h:233
>  do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
>  do_syscall_64+0x134/0xf80 arch/x86/entry/syscall_64.c:94
>  entry_SYSCALL_64_after_hwframe+0x77/0x7f
>
> Local variable now.i.i.i created at:
>  ep_timeout_to_timespec fs/eventpoll.c:1857 [inline]
>  __do_sys_epoll_wait fs/eventpoll.c:2471 [inline]
>  __se_sys_epoll_wait fs/eventpoll.c:2465 [inline]
>  __x64_sys_epoll_wait+0xcf/0x3a0 fs/eventpoll.c:2465
>  x64_sys_call+0x2ece/0x3ea0 arch/x86/include/generated/asm/syscalls_64.h:233

This lacks:

Local variable now.i.i.i initialized at:

        ktime_get_ts64(&now);                   <---- HERE

Right before the timespec64_add_safe() invocation
        
        *to = timespec64_add_safe(now, *to);

KMSAN confused itself....

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/874imq3bv5.ffs%40tglx.
