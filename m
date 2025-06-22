Return-Path: <kasan-dev+bncBDW2JDUY5AORBCH337BAMGQEV5ASYEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 86AEFAE2FFB
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 14:56:42 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6077af4c313sf2847781a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 05:56:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750597002; cv=pass;
        d=google.com; s=arc-20240605;
        b=JFxIu/DZ+xYmMpWTF+qa6cpLwHeVltJcm0YkNzs0ZOkBK8cSKnIyO3VOosSmFknSoa
         A8PSp11QNFY/MqsvdhgaN0QDKKluBRzcafUAUyu8HJEErAxUhyq65MGWqJqsIk+2rHAO
         +Nx1pbAuDrMW77OI0FE9b5kLhOSmL29YHOn9ogYM3aaNYN9GfL6sycoONbK/MvBRF581
         bUoRJ1Bdrr+pEB/L1Fz+AauJFU3e3bfywG4LabVGRD+7Unns9KoRklNM9l9Y/nSe4Wxo
         nvLxbpswZYEL5o29aYrHRhbCuNqaJt71DfuadkdLlpFu5MC9eScPr8je45Pdnhh74YDX
         EUFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zkiKELxAyMPpMN4CriQtIdmExilXsFtKw7YyRvlunA4=;
        fh=pqOKk6Tdgr6U/y4U3ZWAlVUlgelTZtmoiK7WF8kkqww=;
        b=IEgVnutAjmJF5lTUSghtNxTvKm5Sy8tbrOC/eD6Z+BuUpDBDKNioilqXBpO772Hlc/
         fr/LBwTDDxYLTtN40fqDLUJ0J3ominmQcWQeHLYx7EG4AkkkS23ejARDTWvpTqMlo453
         rXXk0eMTGjto2jO+kHBhjsGoilC3g1+/0O7wFGn+JwrjmMXvEamQItzLaHu6wYxtb6rC
         PwVGcO1oX7ksaCbJD48Rnb4Hn97p0j4uwVBsiBoSkcqWhf4spJuGjqoEI5DRnIOD8uWg
         2N4H0cpj/GemSw5u+tjQyAJcqNR6MwdvW0HH5DPngFwfMFq4oP4sHfTR0pqu8ODqc+Ek
         OLAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H8bqN0bx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750597002; x=1751201802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zkiKELxAyMPpMN4CriQtIdmExilXsFtKw7YyRvlunA4=;
        b=pHZIyUSCnmoVpnFKnqCy1xtAsF0rHrJ6qIp7EgkS0KwpBtrbjHY1jWYQ288VJT61c6
         rU0vory6D/wNPraTNODQ4GKubhjrhxr/ozh/lPrI5QE5mASbR8b5ykxTBN3vC2CTBT5R
         lWe0cs9MjZntvlAdPWkEmlWadrBno+ySSqQWCcCPffXpYIN0t39F89azGZDgeYNhgqUz
         VJbFSri+LkByQYi0Gg6efjJmw6qoOTLRo9Ct1QXCYZ3FNq2oSoiACVUWkN+em9nIa68X
         hzz0Y/OisjI7UXFVKp2qzpDEHfKMEfloihq+JafOkZmjn4cNaYsUd8lR2/t3rZcjFrI6
         heaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750597002; x=1751201802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zkiKELxAyMPpMN4CriQtIdmExilXsFtKw7YyRvlunA4=;
        b=KH6XCjV9r3ubF0n9mLC5YZG4VOwl3FIFR30RadCaJJBT4WMzCmJiIccVp7xdLVgV3C
         02Qwatfez5B+iaXXo6TS49Lc2Mka8PH2DDKnWP/Uz3HpTsJ90TxmiMuMOen6nFSbo24N
         /Xsz/vkzSO17am1SaS2AY585uy1SCVpKPGQTc5JddJZSYx/U32vHzunar1lIxmwL0/FA
         eOsvwKQ8GHf7oXcCfvz784/F2USAtkumwEpRwsnG/JBZvTU4M/5o9AaV8zghtIGE78L3
         WCYVcY4AH46fgKQhXQUvk5XPQ9Vs64qkPzf5aqv1m4f4fdOPXQiVJ+dTqddsxmJdVMs/
         tnbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750597002; x=1751201802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zkiKELxAyMPpMN4CriQtIdmExilXsFtKw7YyRvlunA4=;
        b=VBy+iWqctRONXC/PevCEt956U3mFJLmN59K8h24MdsaoopyPJDn8vMiDEklQsqMrJl
         WwHtv4zMjsSEfJydRDgmMopjSQEC+Ys2/DNKNkJsjuiQCS9bGxIiXkJ1n6Q9YbyyjTZ3
         qFhEm6HXjcYa1ub0fJrGpxbIW+ypNuN6useGOTPAesnArJJtR2nPhmxHTpvWH2FNKSJd
         dYXFODnWv2bTCiIj+vSAsknLMnbTBThrCxeCuawv1s/zY4ZZjsn95wN6dPFGHSBsFfOH
         42D0vGdrGFUK/z1RmuY/nhNh+lvKXLyrs10M/HXnBFEXAW9o9fPY++eXAn8lFoKWMAlD
         djIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXuZRiAbInvUgEzLnpE5qIAvJaOvbaxcSaQ2KJvBai2EuVXTsGvfSyTjzzs9a5xdlvR7a1TTA==@lfdr.de
X-Gm-Message-State: AOJu0Yz+bsAjQHS81cjM2j0Yit9knugUuxRyG/otbPUKEBDn5rLfiIp/
	B3qLQoUS5AnEiEJ5XEqkUgnedlCga01lFqJRQTmes+94tLXt6k3WXwz5
X-Google-Smtp-Source: AGHT+IFOpFpks8aCsZXVLQt9xFcSQGYPRoKgAszNtEAqDU/15iUfzfJitNUMEDxDij/JMzxzQYB72g==
X-Received: by 2002:a05:6402:3488:b0:602:a0:1f2c with SMTP id 4fb4d7f45d1cf-60a20ccbc52mr7420218a12.9.1750597001442;
        Sun, 22 Jun 2025 05:56:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2vJKx648nfPJ7ncbxpcRhSPWzlFZxcE601TUEbncoQA==
Received: by 2002:a05:6402:35c8:b0:607:2358:a304 with SMTP id
 4fb4d7f45d1cf-609e7be61cals2704655a12.1.-pod-prod-00-eu; Sun, 22 Jun 2025
 05:56:39 -0700 (PDT)
X-Received: by 2002:a05:6402:3549:b0:607:7cb2:7a5a with SMTP id 4fb4d7f45d1cf-60a20cd78a8mr6698335a12.13.1750596998748;
        Sun, 22 Jun 2025 05:56:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750596998; cv=none;
        d=google.com; s=arc-20240605;
        b=Bl+cJmskfSQI17dxuikjztqG+LMasv4j3zlA8HRM/aQSXpp4ir/kjmm64i/+EfxX8p
         PgfzS57NQAUDKzY3bH0aFXsYmm9/BKvk4P3Qhh0Ex5AVt331N8X68Iyn/2yCMmXzQwyp
         VySo+S7g/R+FBEqeZopZyDpsdu4av534dfixeRQ+2K+mzumwh+sfI8cgfsp/EygXpdxY
         G6XuX54/FUqWu8a9AsbMT6X3GXSYN4SpjPSbOcp/Pkt5QbpmaGDNRa0Pt3+HRMatSQMg
         d2qIE4p2ZDYpGLjlk2IDssmZKisjIrCi98+nfd9J4kl8B7ELhFhzAUlif409jL0XT1SY
         fogQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nt0xenzpPiBO9tpLDsqopfsT+U4fH3cPTHcA5xjDpkc=;
        fh=2lsUIz+BICPKGoruVn5PQ6eMV1TqeJjGPhknO964m/Q=;
        b=MnaGkG2/++UhHx14eNnMLqC/OGNM1G50opJb+A5O7RGBIiscjtqHA3MCYWybNmdMWU
         L4XyIi2pLEKn1m5SxNhdJ8y5NNkhPKbh87vmuqrcyks9ocTf2DWzIVPKy1/gLh5iwuJu
         NCZWDtmVecd6K7ZZZ578asCjbVBaMOvZdZ0j55XffOhgXGoy1rj62yhw+joDSzj/ISKK
         4vDiq4PC50SGAfP1+vV4NkCaucuWMadypY0vFps6UINpz//+im1vEyPFviNMBJOEtGDG
         WhcJtjf8xwMjyV3zjnKhCH/6MhrNdhWJVBC/7M3vwRZDdRY1ak14DFaVJGYfeeNwvXBt
         smVQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=H8bqN0bx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60a18cb8e0fsi143605a12.5.2025.06.22.05.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 05:56:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3a54700a463so1769752f8f.1
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 05:56:38 -0700 (PDT)
X-Gm-Gg: ASbGncsq32bVhbQMQ3Z1I9v2KwNH46/LpgQrFYYc2EegKIAnKlyQEWD5OVvmSNE/j2V
	Xc7Bu9uuBUCGhvYo8mTfjtsMKY4VzONgjJ6kV3LauZ33p2zvvVUlegWKbBhT8fOhk/+8lDCRrwP
	IjJckIUGbME8bHxQ+LSWvJfH1ExIDtuDwaxt0RAvK+aUrMVQ==
X-Received: by 2002:a05:6000:210a:b0:3a6:d95e:f39d with SMTP id
 ffacd0b85a97d-3a6d95ef735mr2384988f8f.4.1750596998043; Sun, 22 Jun 2025
 05:56:38 -0700 (PDT)
MIME-Version: 1.0
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com>
 <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
 <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
 <lhbd3k7gasx64nvkl5a6meia2rulbeeftilhxchctkmajk6qfq@jmiqs7ck6eb6> <ik6nus667nhf27quzcsmhwgappwrxwksbmzs7mkv5hqpcgdbh6@qiwsoogdn5pg>
In-Reply-To: <ik6nus667nhf27quzcsmhwgappwrxwksbmzs7mkv5hqpcgdbh6@qiwsoogdn5pg>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 Jun 2025 14:56:27 +0200
X-Gm-Features: Ac12FXziQk3-Iv3cpthB_nlL1qiNg4G5PyhaywAh7D2FtB1EtJOmdbZS3V7l7tc
Message-ID: <CA+fCnZdZwzxYuOGoZf2i52yntugEVhdABuBTX4jvZeXS-tF_Sw@mail.gmail.com>
Subject: Re: KASAN stack and inline
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=H8bqN0bx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jun 13, 2025 at 7:21=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On 2025-06-11 at 21:46:11 +0200, Maciej Wieczor-Retman wrote:
> >On 2025-06-11 at 21:28:20 +0200, Andrey Konovalov wrote:
> >>On Wed, Jun 11, 2025 at 8:22=E2=80=AFPM Maciej Wieczor-Retman
> >><maciej.wieczor-retman@intel.com> wrote:
> >>>
> >>> >
> >>> >You can try disabling the instrumentation of the function that cause=
s
> >>> >the issue via the __no_sanitize_address annotation if see if that
> >>> >helps, and then debug based on that.
> >>>
> >>> I already tried all the sanitization disabling tricks. In the end it =
turned out
> >>> that a compiler parameter is missing for x86 SW_TAGS. This one to be =
specific:
> >>>
> >>>         hwasan-experimental-use-page-aliases=3D$(stack_enable)
> >>
> >>Ah, didn't know about this parameter.
> >>
> >>Looking at the code, I actually don't understand what it supposed to co=
ntrol.
> >>
> >>It seems that if hwasan-experimental-use-page-aliases is enabled, then
> >>stack instrumentation just gets disabled? Is this what we want?
> >
> >Eh, yes, you're right, I missed that it's negated in shouldInstrumentSta=
ck().
> >Then no, we probably don't want to disable stack instrumentation by enab=
ling
> >this.
> >
> >It's a pity there is no documentation for these options. I'll try some g=
it
> >patch archeology, maybe I'll be able to extrapolate some stuff from that=
.
>
> I tried different versions of LLVM and did some modifications on them. Bu=
t
> couldn't get kasan stack to work yet. __no_sanitize_address doesn't have =
any
> effect anywhere unfortunately.
>
> Then I started investigating with gdb to find out what is actually causin=
g
> problems. Got to a #GP somewhere around x86_64_start_reservations() - it'=
s hard
> to tell where exactly the problem happens since when I debugged by puttin=
g
> asm("ud2") and watching whether kernel freezes or hits the ud2 I found th=
at it
> fails on load_idt() in idt_setup_early_handler(). But looking at the asse=
mbly I
> couldn't find any instrumentation that could be causing issues. Then by
> debugging with gdb and stepping through the code instruction by instructi=
on it
> started crashing around x86_64_start_reservations(). But it just froze on=
 the
> early_fixup_exception loop. So finally when I set breakpoints on the earl=
y
> exception handler I found a #GP happening on 0x1FFFFFF83607E00.

Just to refresh my memory: with LAM, the tag is expected to end up in
bits [62:57] of the pointer? So we should still have bit 63 set to 1
in tagged kernel pointers. If so, this address looks weird indeed.

> I tried to find out what this address was before it got banged up somewhe=
re and
> the only thing I found is that the RSP has a similar value inside
> copy_bootdata(). There it's equal to 0xFFFFFFFF83607ED8.

Based on this, 0x1FFFFFF83607E00 is likely a mangled stack address.

> My question is if you have any idea what part of hwasan compiler code rel=
ated to
> stack instrumentation could be doing this to a pointer? I looked at
> HWAddressSanitizer.cpp for a while now and did some trial and error on th=
ings
> that do bitshifts but I couldn't find anything yet.

The only thing that comes to mind is that, AFAIR, the SW_TAGS
instrumentation produces some weird effects if the stack allocation is
tagged (meaning the allocation for the whole stack, which is done via
vmalloc). And this might explain that weird address. So we might need
something like [1] for x86.

If that doesn't help, what we could do for now to unblock the patches
is to declare LAM-based KASAN to depend on !KASAN_STACK. And later
figure out what's wrong with the stack instrumentation and fix it via
a separate patch/set.

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/comm=
it/?id=3D51fb34de2a4c8fa0f221246313700bfe3b6c586d

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdZwzxYuOGoZf2i52yntugEVhdABuBTX4jvZeXS-tF_Sw%40mail.gmail.com.
