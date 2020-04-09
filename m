Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMRXP2AKGQEVM3BLGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C5141A2FB5
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 09:03:26 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id f4sf8521315qvu.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 00:03:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586415805; cv=pass;
        d=google.com; s=arc-20160816;
        b=XwAsabOHQMs6y/VInA0R/Dx0yYWW9TAGmvsMK5IBIStH9xGa039nRK2Ll40vSlZMHX
         If12FVStUFyX4FxMOH8TJEQ8renw1nhhmRAhHzfSRDRnQBsXr2K952l7e5Lel6lESqJQ
         aDy5NdGNxPG4yo4GpRRgxytufPMp8bVpw2Aei1r1XQf+IWoMAZ4expaR0O9+sTtTAvkU
         KHooHWRr03eWD1OPwSohZoiCJwPQutCi1tMKoiSOz4Sz490+KrwO5Br2UCpu4WfPmd6n
         FIqa+bZ1dLXUCJb58Ro0dtIWKawgE2NwJxMIDd+p/ASiKgXcx6lpEZe5BCBIgvVSOBYV
         qHDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xMv+Eo/2yc14r8RDiQSlJjKklQOYYF4qJ671bvwbaFs=;
        b=Vd7k33cfGRjj8FtOYYPUukbc3hdGsu6pXe1OIxMJ0Oweq1gr/1iNWN9dlTEQiXtcO7
         FYdwh2UFMEUY3UkSfYXXM3dQDUQJC5Dv5WwBz1fa5MGV4fcqQXW6i+7P+lMFvpWHipwM
         8+GHHdR24QP7tzDlRG7yfWv9AR7kLHSPMc5fEvNX/wpdnDSBXw7xdYRMFYmEiReXYKob
         IiNErtFzdh3ywkYeJv8NGCfi7zPmGrQMiGS2L00ZvUBkGF+O59YAsbsb0IpRI186zerK
         i+5NeQM9X2ZiAhOnT3em3xBEOix97pxIjCD4M7b0UIq79YiulLPCDzVxK5NJCR5BYGNl
         0N4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=smHx7nst;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xMv+Eo/2yc14r8RDiQSlJjKklQOYYF4qJ671bvwbaFs=;
        b=YA1Cc5CgBugmsv0ZaaIeqfiyEX22/4v8JWunAS5SAOQQ0IRclFZiqp7HfFhV5dOaws
         OptpIaLDEu4R93KVT4wNPuShnZE8Ly7yCWqszUYTJz0x7kmJ0Pi3jbGZqcysWyF2XCjq
         YPeTsCdhaaQTvn1ny9R4HLUVvhUnxsqyWvgoHa7DKvbInOhzJPSPXq0UJfyqrv/kc8dU
         MZ72j3oAXLF40HPgMkisvLl0kQUFAEnOWg8WahAoGgF0uBTsc9KCxL9+T8mWxJMQQXK6
         UK+lPV1uhm/FDHygsRnWe3rkauHDphbTIonYZSniHbsmrkYbRS6OW75FVzNkNbsrKA3F
         ew/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xMv+Eo/2yc14r8RDiQSlJjKklQOYYF4qJ671bvwbaFs=;
        b=LhLWN59VayGPKYwJ8bXfg/NfFrqer9hKMCZQ0vqMVr1uid2puDY1clrBwnCsRL+Yil
         NhQLDd5uxnja+45RajFqUU3EYVxGBs2RjJ2oopKYooGfvyMptkUZNKSgALHkqNWEltXb
         n49+UCTCDMGmMoW4YkNUyoMXKtKeyfG//2GYKVgp4OHwY/F1NpzLo59XcBiXbJVW2ygn
         V6JyuDnKTA7YFEPVDr6lwsWBy1BilTG4III9hfPtzHdmI7x5cEfYMttL8iFjQQ8BDmg4
         s/dodwDFwxdCbL1gAfcxiLouYtbfaMaJreYAtolcmvg6zrB1qWu//5vOg/Kl5H9/jFk2
         EF8A==
X-Gm-Message-State: AGi0PuYf0iyVUwMtYsoBdALQOCkX7AY2iHjxy4/msLf5CC7p+ay5TXLv
	sU+RmRmxsvVeJrVsFXmU1VY=
X-Google-Smtp-Source: APiQypKLUFnup4tAUETe8+dBaSfxM/lXmNQGhU2O3GbNoFS1EOp8E8izjwC7APGNHP0zHSUuF/Oh/w==
X-Received: by 2002:ac8:68c:: with SMTP id f12mr10924471qth.100.1586415805192;
        Thu, 09 Apr 2020 00:03:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:32c5:: with SMTP id z63ls3679694qtd.3.gmail; Thu, 09 Apr
 2020 00:03:24 -0700 (PDT)
X-Received: by 2002:ac8:7518:: with SMTP id u24mr11112781qtq.283.1586415804763;
        Thu, 09 Apr 2020 00:03:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586415804; cv=none;
        d=google.com; s=arc-20160816;
        b=ZqppnwfWqoTnEjG4yohoD1pwsK2llaRmzW1Go36t+9mJYK64Igc5tEEGUxjLei6Und
         nMAMl8dXd2TVhOuM1hw7uudSb0O+FBL0UEX9y9zyW+SjiFRFUzKR4pjwmoFPbgoCrQuk
         Rhk/sS6nQgOjmpOGlukHabawc9gQfNlSz5VYKXgwhX6GCcoKhIdhYYMz+WzSVll53oMv
         F2nlNt+tjgzw4fnL65T5vg9JiXrMKJ4VQhqWONEi02fLenYwGC/3FLOr6/2vxH96M+Ax
         IGQwcRxaVSa4lFVFPn2hqsQxm0vESVkYmXp40D4ISscPiEIprBRqpv+S/+traLsZYAMx
         1pHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WIKZ7+NEMSpKVc+/W0G6Y6asO6ZNbKBeIWnReIGgHns=;
        b=veGO+BKtTK3g9dEBWvvUmKLK0u6VL4BKBTG4SmtOm0kMJdzWOH8wuKyo9y1UN1mWCI
         Up4VOtOSUJxxsZu5P15Xg6fKqOm0WPJWuAnZljh2zIOgTNHqZ1RN6HhGpsf97FOb/9WY
         L41KdE/PMDsmEDWyIn5yjxxV6CvrwH0IS+fZd0ANeaEqpCui6OPIv+cBclbSUDWnkCAW
         Gk0ocqKNwZHfI9IXdWsTftdlBJIuYFGz6PhioQnytFu/ZazHnDKrvjmB1lST128ZWHB4
         iCv9HsQLFy48z2kifsNlsaMwCHP30l+lafSSbfBq0d0E6rI2Xc0f7ClM2KRA7sZWyoaL
         9/Ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=smHx7nst;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d13si661114qko.1.2020.04.09.00.03.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 00:03:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id x11so9482060otp.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 00:03:24 -0700 (PDT)
X-Received: by 2002:a05:6830:3150:: with SMTP id c16mr8155028ots.251.1586415804017;
 Thu, 09 Apr 2020 00:03:24 -0700 (PDT)
MIME-Version: 1.0
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw> <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
In-Reply-To: <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Apr 2020 09:03:12 +0200
Message-ID: <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=smHx7nst;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wrote:
> >
> > On 08/04/20 22:59, Qian Cai wrote:
> >> Running a simple thing on this AMD host would trigger a reset right aw=
ay.
> >> Unselect KCSAN kconfig makes everything work fine (the host would also
> >> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before runn=
ing qemu-kvm).
> >
> > Is this a regression or something you've just started to play with?  (I=
f
> > anything, the assembly language conversion of the AMD world switch that
> > is in linux-next could have reduced the likelihood of such a failure,
> > not increased it).
>
> I don=E2=80=99t remember I had tried this combination before, so don=E2=
=80=99t know if it is a
> regression or not.

What happens with KASAN? My guess is that, since it also happens with
"off", something that should not be instrumented is being
instrumented.

What happens if you put a 'KCSAN_SANITIZE :=3D n' into
arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
exact system, I'd ask you to narrow it down by placing 'KCSAN_SANITIZE
:=3D n' into suspect subsystems' Makefiles. Once you get it to work with
that, we can refine the solution.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA%40mail.gmail.=
com.
