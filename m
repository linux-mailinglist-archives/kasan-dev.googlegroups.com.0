Return-Path: <kasan-dev+bncBDN6PXNU2ECRBIXHZD6AKGQEKTM22FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8426C296851
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 03:36:35 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id h65sf15942oia.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 18:36:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603416994; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVVXtt/6WRUSOCNdsqE8Lnxh7xhjCfDlwWbhTo0p5J159Gm3uldH4WFUzg2D95Vd6S
         PB8jxkjBRmJ8xCVel6GZ8V9T46s7LZFyLdN4xm9eUXxP0cyVNjWgc/W9MWmUyNcitxOI
         p3PD6tALb7teZsHOYha1PBTb16cSXJE0ExBgl1QqkkruC6mQHsNIwMBbPdBesxYcXDSV
         dUZtiQUNU9Q4uHPowpcALGrIT1+hLKVXukvd7RYQjVXunuIJb2TSUBeo8YB3eeXAZG8O
         DcJLIOmZAc4UmGwdCCq3M/xuophftPJvcInomKqyQUEnA+sWfVd8bWVqrHIwdGT3hPAF
         ph9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ne5Z9O0MwgnamqkpEFWk+bJhFDmaaDPKI1gZxXUCw2A=;
        b=jLBdUml9cs/pzqJ8IfQKdE0o13AKD8CMzzxpgR1LF887LpTyBuQwfGb6kfXpH1bro9
         Vj/ETL0R8Roh6kFY77Fz1Hvq9hScQGXrFC9mp6ILARTuGpsPl5C1th3reJO3za0vcrF5
         t+VYuuJdRIZR0lo21g3zosZdnGMcm0CyJ4nPt6z9m77wT5fO8Q0PvmvBYesunm4+WMKg
         B8uXj4NRRj4aOIfef6iO6YAdQsBO45swT/1jbmFRFyKPLizSzGF0pyl37KZcfbAFKu2E
         2V6zSQzPBkFmlXrgxKqOWxL04VgcMPlVTfGRx06JJYzVCkogYcrVRkxORk1Z8cpPD/oq
         yFyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VYQTEVIO;
       spf=pass (google.com: domain of daniel.diaz@linaro.org designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=daniel.diaz@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ne5Z9O0MwgnamqkpEFWk+bJhFDmaaDPKI1gZxXUCw2A=;
        b=PhYZukRrq3zTjEKsxP/A3Nq5KXerH72Xz+EW6MQog+kafrkBDb+BRZ0MnSM7kP0CSy
         /azJ7WXAE56gSkA3NehFEYYTB+S82DLBDc2Tr0r82vKuMrxxEckvG+sctbxK6aUOK+BG
         FI8jjOezD+o69KJiic1rRv9tKWM3R9BjYXAMhXkvKl3MW3i05XOj13q27uD24fh/MuEP
         uSiVmrgBfZkUlV2VY8D/o2Zk9CmkZoh8MOJjzg9E2qnQmGo2bjPgwH3Yu9yxZrvzig3e
         IsVFshuf3c6nvlapmZ5RAOk8aD+qOOQEIgjLshlX+yk1dz7MnITQ4KoLSQvLPLP5u9x6
         T/5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ne5Z9O0MwgnamqkpEFWk+bJhFDmaaDPKI1gZxXUCw2A=;
        b=gCZtuhmPxTrCh0nGyezNAVAM32IVaS8qm9cx4HEa3ZymEq4CMxa8BHHUtphm1tQN2G
         zE7Gg+WJAQhK0gtKsgSTJmEghtOdpKzu52r6V7dAk1E1JGYm0+R1PtBQAql5FT3QDVdG
         YfU6Gj6CEOAUL1Q0dIJHNiCWmig/2JQnlYqZiJEJxxONuVFXvOVpBBxDe7wTOGed8k+c
         r0Jdzs5j8vekCA9DaMJ47ZFR3RN9XHE8Jvtm7CqC0T0Q7BH3qooBAVs8vLps1rN6uKfm
         bLMyg037I7+F5GAVYipknSOY9VoFs0lv75CUZZ2VGLRBGD/mhLothjN8huW3SifRBdZZ
         WDNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Kr9HREbb1IRZpO8L/3u1MSB9VUCvqCCv1SaxhyWqsz6X0GEPH
	xmnHSiJYcLtQ4FQhN3doVnw=
X-Google-Smtp-Source: ABdhPJzvX+7m9W6jcHxK3MJ34AN3cQ6X/EBy6Kf2Tz1D6j4oRCnd5fD+3wICSsiEv144n54bYP3olg==
X-Received: by 2002:a05:6808:344:: with SMTP id j4mr27474oie.105.1603416994422;
        Thu, 22 Oct 2020 18:36:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:20cb:: with SMTP id z11ls911935otq.9.gmail; Thu, 22
 Oct 2020 18:36:34 -0700 (PDT)
X-Received: by 2002:a9d:190a:: with SMTP id j10mr3967399ota.25.1603416994027;
        Thu, 22 Oct 2020 18:36:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603416994; cv=none;
        d=google.com; s=arc-20160816;
        b=rRnNpdcYZ1oNsMFfgvuEdFAz3tEKLENa5NgES9uoi9tNNMFtLe3xg7F0l17+PdtL8p
         py4gSRldEklwn+nxdnjOIUVoVcKqb/INfEa2bcEt3psNHP0l5QWPa187QDhIYRostrLa
         23kxJsc+xkSTEy5e5wTIuCa1Nee6W3m0RNkfzm5ci7c9rAk1ozzOFE8bSxu6pepFR7vj
         odUlXIOQirgY/X2xzxduuNqQdVRqdP2u2YoturIAd5zSRGYhQhLHAyfstJFhheiClDz6
         BHRMZ4/WkCT5np60KUBS4HGiZh4noJrJ6UR0i1SM7CC9N2bjdjA+5QARjPE8FfIO3aAn
         qK4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2+Di+znLFc6X0mmr/arvC7SPhODWgxA/Sv6sSuj9bqc=;
        b=jrJdgp/o1wHq53T3dZXdKw24GlAF218V1ghB3VaJby8hGDRV2flKR9uFRXhGUMCCnD
         sGxyH8r094VIFfifSCiaeJle4CBhd0+DiwAp1QUog5kvM2/uDWWx+cHZhGg7CRboP2hO
         WxeYZdJmVVod76MH+X+HNqtI3RW5m8cXFXATtOvUVdYZnP/T9gPINAnhk+4z0EKMSltk
         HdV/z3RgOZXK3vyetNGKRqKVB3Vi2uRElHbRYOHR8jae5dklIvp/eCKlVS5M0qlWqB6Y
         JgLsWaZ+nYh3huBQaMp1GSjz0zDWw2+7RgKh989htmJ/rUIiFE2sdGmJi4ae+Tagy5Wf
         42MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VYQTEVIO;
       spf=pass (google.com: domain of daniel.diaz@linaro.org designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=daniel.diaz@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-oo1-xc44.google.com (mail-oo1-xc44.google.com. [2607:f8b0:4864:20::c44])
        by gmr-mx.google.com with ESMTPS id a7si272945oie.4.2020.10.22.18.36.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 18:36:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of daniel.diaz@linaro.org designates 2607:f8b0:4864:20::c44 as permitted sender) client-ip=2607:f8b0:4864:20::c44;
Received: by mail-oo1-xc44.google.com with SMTP id c25so862488ooe.13
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 18:36:33 -0700 (PDT)
X-Received: by 2002:a05:6820:1055:: with SMTP id x21mr3955751oot.6.1603416993655;
 Thu, 22 Oct 2020 18:36:33 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com> <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
In-Reply-To: <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
From: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>
Date: Thu, 22 Oct 2020 20:36:22 -0500
Message-ID: <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: daniel.diaz@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=VYQTEVIO;       spf=pass
 (google.com: domain of daniel.diaz@linaro.org designates 2607:f8b0:4864:20::c44
 as permitted sender) smtp.mailfrom=daniel.diaz@linaro.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hello!

On Thu, 22 Oct 2020 at 19:11, Linus Torvalds
<torvalds@linux-foundation.org> wrote:
> On Thu, Oct 22, 2020 at 4:43 PM Linus Torvalds
> Would you mind sending me the problematic vmlinux file in private (or,
> likely better - a pointer to some place I can download it, it's going
> to be huge).

The kernel Naresh originally referred to is here:
  https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/

Greetings!

Daniel D=C3=ADaz
daniel.diaz@linaro.org

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAEUSe78A4fhsyF6%2BjWKVjd4isaUeuFWLiWqnhic87BF6cecN3w%40mail.gmai=
l.com.
