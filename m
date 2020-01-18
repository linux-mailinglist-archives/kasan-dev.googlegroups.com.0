Return-Path: <kasan-dev+bncBDYNJBOFRECBBAMWRTYQKGQE7FM3XNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CAF31417BD
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 14:41:22 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id f19sf6601657ljm.0
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 05:41:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579354881; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0ahi0ep8L0JtYAxucRt18YmItj8bChX6raykt7ZY4VoDXwghpjVEHejaji2UkIaMA
         sipgqKTcASDFF9EivEJhCr0E3fHxApx1+g/2V7Uc3c9ZcrBjeGnfrANToLDQV77q3eox
         qVqy4VDlBd0eVABzkYaqFzOgteVkncK7tPdlV+5T8qy3KTWxLZb7vt5DiSZQCjlTFiiK
         5F00fD4XOaPB9HJtH0OFtkDKiylrcKNH/NQlOAdkK4DyK86u1mxVEMLu1JhwnqMu6sH3
         bigAbXtsXJvk6skUzJJ3h6adKmNAiM5beemBcavI4yGRMC+b7l2PJl+pqnhEhZ3RBc3F
         vDxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=mH76KxFdue68qrg56aZpS9skA9MsbbktXIM51JnPAUk=;
        b=mrxqHfrbveNDPZVBFRgd7/hFEwjytzujhvKkpswFKtOoQiMprChy8rhi/W+7gvsU++
         EkQeMaiZlnd9XlBoIsymsrHfAn5I6gw4SUtpu3HFEsijfgMInkXzOL5OPu4My/YrT49O
         IpgH4vWxJrYcNHFw4CKYr+vXDKi8bfzkxQgKyyiOlOa7+p1ro1WrYhgyIoilZyUenmDH
         N8PBSB0a9gkhrk4lkEZnHfCZFCRcrFw0yft2IFtDnAn7WrNyYFxkSHRbt4au9d27fvz0
         GdxGikvGV65jHoCMhK3QziQUiuyUO45Jgbeyfc3Wf/hHq5PBn6Yy46nUflsJMjGm2S8N
         eVFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nFG8dNHB;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mH76KxFdue68qrg56aZpS9skA9MsbbktXIM51JnPAUk=;
        b=iQskKHUYT3OHTnQNFtRS3v0pmdnvPQ8FBgM0uG+6dQkpEg6SbutnjShdVuCpK+dyY2
         fvpw02VpN0RB+2l244fyEb+Co5H7iURDHBqPXWAu1mKuhDjdg3mSwuU3JIqw83PQcyNf
         hX02+aUikWgMcMXuN+WA38Mk/JkvDMjqPSbSXniWpCMbnnQcEpXQJO3K2LLiqCRuZEYU
         uLsA1cdtClW7F3KOiW3jDqL0Taz4RTO7QiPC8i8M9uoFQfA9j0FU1+kyPk1Z+myCdxOz
         OupfcuPD9Hb4nU8NVgFFkpQK5XwrA0E+ESehTQ397BwRTN9HrKDZVkK1ohTE8vYwCz38
         p3Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mH76KxFdue68qrg56aZpS9skA9MsbbktXIM51JnPAUk=;
        b=N1UlkbhtJFzKEUMBL1vz+qjpbhSnJdFiLhdt/JHVDKMEz38ZY/CfbsYgg+IesWMtPm
         GNn/gxfKeo45SY70AIem+I6suoyJoE/Sh2wsJ/V12oapZULu/+1jepaxrfZ1uR+DwaBV
         nWAMGLJfEoFba2CsHiURKqrYR7hikXTz5he4nlBeM5MW0osKPvVTuxyJigq4T/SAJJ18
         pckF7ryfoU2oOeOKElJLSR2PPxNiX544TQ9dpPyGDZNJqoSlQubgJX/U5Hn6Qkjl6O2n
         Zh9OmL+JTh+2dHdHeUksAm7yOk2L9Ez+eVNOzFAGXEs406Ix390diFfJWhA4wYxIGH0p
         9u5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfEiHTXKfYmrDCkj3X6A/eUL6r/6JbnkvaR2ZX40mI4JHLDzoY
	e3jMLK240JcWEhDdCIWsaMI=
X-Google-Smtp-Source: APXvYqx3fZmfDWbGiv103YresYd0QVhkFcnIWxa6l5rEXYXdPq8jZaV6UKarv4v0741nj47ljH8wqA==
X-Received: by 2002:a19:7d04:: with SMTP id y4mr7949552lfc.111.1579354881711;
        Sat, 18 Jan 2020 05:41:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:988d:: with SMTP id b13ls3865696ljj.6.gmail; Sat, 18 Jan
 2020 05:41:21 -0800 (PST)
X-Received: by 2002:a05:651c:106f:: with SMTP id y15mr8674110ljm.63.1579354881093;
        Sat, 18 Jan 2020 05:41:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579354881; cv=none;
        d=google.com; s=arc-20160816;
        b=ieq7qq3mXk9DocElX7WfdYSnsHFsITreueAhAIXXUo3IgenzvHoUi8rP8hUlEjV5Jo
         9yEJ0sshwipILsQ0oKn1BS0QWOm3+YfPqpctRcCjg2XCfcB5Yk709bGoX8/tjIyFWeOx
         e7JwXGILz2EC0quUvXc9CXw3p1p+O1Fxpso+Ab/VDerF2vAqLR5rxDvR2fI/0LMiVY/y
         TMbBdFoi5g9bL7EWL0Qf/9UfQE1Kbbsdga1hpKFm/o4ct2+P7nLyaEeAHw7eVhiUSV6u
         oZzphFR4Bf3mpmB2yVqpSDhm6caWzUNwobuhKv9HKOYrE69j85Ub1OvxisGuQNM1NjoP
         1ecg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wFe6n4FQHA1VOWCd6CGPk+kxacT5cKq8IuN+p1i7TQU=;
        b=VtVjI68xzpjVqy76DYy3fLP7hpErXkZ/d7u5Kqnsp1FVlRp6Gi7Cr9o3QEJX5pkMIL
         GyDFTvLTUScneD7ihiILPX7WZ3dRx42nirWNRsquMl7AE0soVSqpntOCGgrttaFM3FKd
         IMXtAB3YT5lJdK0TH2i/7CEemvPR4IOyob/z4B0awHXkia0oZdIwBhMgaKFb1YRuE/tt
         ihUtG8P5ShgfYW/oeXXFaXWlGvUz8kVxLEoGgzkHgZkaeB9k3r4jZ/+QnsfZLTnZfezb
         +Nes9yxgOjYpKbx3N7er97BZ2fUBG03VU6+t3nPRfPOL8C4LrbWC8LzmfIFMP7isGmWy
         lIug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=nFG8dNHB;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id e3si1546096ljg.2.2020.01.18.05.41.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 05:41:21 -0800 (PST)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id d16so25244582wre.10
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 05:41:20 -0800 (PST)
X-Received: by 2002:adf:fe86:: with SMTP id l6mr8723881wrr.252.1579354880364;
 Sat, 18 Jan 2020 05:41:20 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
 <934E6F23-96FE-4C59-9387-9ABA2959DBBB@lca.pw> <CAKv+Gu9PfAHP4_Xaj3_PHFGQCsZRk2oXGbh8oTt22y3aCJBFTg@mail.gmail.com>
 <CACT4Y+bKhgRdCM1v8wTht=pEcX6u-J_Rq6=zA5yfMuBUcj169w@mail.gmail.com>
In-Reply-To: <CACT4Y+bKhgRdCM1v8wTht=pEcX6u-J_Rq6=zA5yfMuBUcj169w@mail.gmail.com>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Sat, 18 Jan 2020 14:41:09 +0100
Message-ID: <CAKv+Gu8X1dPBk-_o66V81o_uXLReFYZhHgt7CfBGN_MhXXFTmg@mail.gmail.com>
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>, Ard Biesheuvel <ardb@kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=nFG8dNHB;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Sat, 18 Jan 2020 at 14:37, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Jan 18, 2020 at 2:35 PM Ard Biesheuvel
> <ard.biesheuvel@linaro.org> wrote:
> > > > On Jan 18, 2020, at 3:00 AM, Ard Biesheuvel <ard.biesheuvel@linaro.org> wrote:
> > > >
> > > > Can't we just use READ_ONCE_NOCHECK() instead?
> > >
> > > My understanding is that KASAN actually want to make sure there is a no dereference of user memory because it has security implications. Does that make no sense here?
> >
> > Not really. This code runs extremely early in the boot, with a
> > temporary 1:1 memory mapping installed so that the EFI firmware can
> > transition into virtually remapped mode.
> >
> > Furthermore, the same issue exists for mixed mode, so we'll need to
> > fix that as well. I'll spin a patch and credit you as the reporter.
>
> If this code runs extremely early and uses even completely different
> mapping, it may make sense to disable KASAN instrumentation of this
> file in Makefile.

The routine in question runs extremely early, but the other code in
the file may be called at any time, so this is probably not the right
choice in this case.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu8X1dPBk-_o66V81o_uXLReFYZhHgt7CfBGN_MhXXFTmg%40mail.gmail.com.
