Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBL57ZD6AKGQEWKYI7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AD2E2967D4
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 02:11:28 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id r8sf1413493ljp.21
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 17:11:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603411888; cv=pass;
        d=google.com; s=arc-20160816;
        b=InjzklPRON+ydjGmuxBLr5pFYRzzo/Rh6jLZJMKOeP3EvtS7ouALCBZEwv+67x+OjF
         if+cMZYMFlh3IbRaPHZ8P5fd2qB0a14tu64+gNz1dqhgxBGrzS4/N2+0gq4MuIlBFUNS
         Gu3VnAB6cEMs1AJcDAuwJiwn2SZlqnm9JKlgO4XaXRtZsTTAHc/3l3QuZwgh0N/uJ0ij
         M00NwHqvT0OWjQ6Qd2CwTssWTZ6qai4uZWxpdvCO99Gkj/KAhJFvvfsNE4hqmcjQ4MQ7
         0dyJbStKb0HaPGh1UCJvrLalAgyyFMy4cwEr39cs3sLZqUGxkeo4Av41qA4mjnqQY8wQ
         YOEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=EVKdsSyZW+CvoOIfDiX0659hGa7KJ1H44FUqJDM68UQ=;
        b=GghvSS733lrD8/yFI6IRAjOfM+8+yzzTKNZfopBGwwuzrz22YDQrArJ/I3FLUaQPiT
         43nQctFnTmFRfhvEhqatJTCtAjLyaNb+fP4tvc6HG10lbmYEOhrKeejtD1mCqH0FKAeE
         Fy45PcC/aJTZkHnSThLk2JuZgaCEgIIF6I8Q2OBmY3fmBqPPGPrDslz5tfWtUXYoBwM/
         MtQiC6/8/RW25pVGvFG0vbu6tfoOgukhHI1XDjusY1NpWpM9bYgb1EKlyrJ/vk/j5AQr
         oigHVk8utzFGN3CRVtYFNMURcx1fwYC8GUs7loUs2H9cyV3uwJwUjErrxRgV/jQoaeln
         JVug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=ddTlNlNR;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EVKdsSyZW+CvoOIfDiX0659hGa7KJ1H44FUqJDM68UQ=;
        b=slqqu2VTl6nQupnGQgLqhZbK/MZaPnOYvhFcctJ44qdIG0mDB2C2U2fw7FdMj56Ver
         pSIkF4uKAsiIWWjHrY1HYdEdsPpQ52ne1pQkUCG4RvBdMp7c7nBqn1hROBd5D4fmvUzH
         xKJsoA9pUs5WzF0tKW/Eu26zEH/tb97zE/UoAbA69RNTUR6OtjvzIGF9PznJ7Ze7Nzcy
         kesFcIKV4OURV475Asol+TCdj7s9mDbTjNirzGrPWGuCh0feQD1Ns+5t8Bk3jIRBv3u+
         Uxk4PeE0rp1r0brXJd3v5ap7f37fAEZSja2/2i6S1AsX88HWgclq7VKa1we64bph/Dls
         /uDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EVKdsSyZW+CvoOIfDiX0659hGa7KJ1H44FUqJDM68UQ=;
        b=aad+P+IKQ+wBnIJ/NTCMpTcdr6vKRNRgBUbIEdJ9XNKLCNjVA6Ww3St2ML2edrKjSB
         9F5uBc1Z/fia3GCdD6Jm/Eo/H2qz1eE/sBIgGUyK8cCjyBnKV4BmiTMJL5On2quElmvu
         cULSWGTRcfNuFO+ow+r0oKwHym6xyP66A7EsPwKnYaeQBCiy5YH2EfZvt1ZIrtsIVvha
         VRRxnXiQqf6sSClW8rMUnNnbwaYMvCNAJEtmUH17+YZxiNQJWrSZnGsyAeni/B7BVDxh
         3RSmh2ij4u2TH/blti7FLEG2Skrfw5aOEntcY4tVXRUVQyMTIM/dXN19sv0J0hQfkkO8
         8rLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HNXTKth6VKYWL+f/v/uz6nSQPDuDzlzrIi/8Coo4ASOClieJK
	++oa2IONQkQE+JUIfMfaYE8=
X-Google-Smtp-Source: ABdhPJy4k4MZDK0kX0MxsGs8o6WhrPsd5qwE3kDoOdb5rmkTf5hRdB8WGD1Xnhh1zPHm2JEjkjFUpQ==
X-Received: by 2002:a19:6d4:: with SMTP id 203mr1797383lfg.391.1603411887937;
        Thu, 22 Oct 2020 17:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e61:: with SMTP id a1ls2173618lfr.2.gmail; Thu, 22 Oct
 2020 17:11:26 -0700 (PDT)
X-Received: by 2002:a19:8114:: with SMTP id c20mr1492904lfd.77.1603411886722;
        Thu, 22 Oct 2020 17:11:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603411886; cv=none;
        d=google.com; s=arc-20160816;
        b=XaRVfHaSW4hUY2t4pozkk3yc4RgtQmz49piuawiVs3By2RzLZctctzAdOOIuDNW32e
         XS/AqUAZECxOEu6GIYvu1XsfPE5mvnmPUUlTUFi0e/r7cB/mb/63kyy+JhKQUoRXNRZV
         V3z9Rejj4lTDmWrumwCbu42xc34IT6M2eYkSiwj8icKVRcpv2JOioE6xrSr2TvEZPeli
         T6Zy6GMEWVAi5Cwg8odam7xFypEc/OJRGCyQrRKraEI2SfVKZK4sXqKvD6lCppkaCg6I
         EaKyrDxiWpy3dpT5e+SR7zq2ezUXtJCYUuH5h07qeM3alUD9AKJNlXfYQLBfEEp03R4y
         SDBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XLY21JX5I5QFlC2bkVrjYFHPFnXicdIVDS29HVXeTok=;
        b=l0NHr7E5/RrUntoJMvBEmGSXclz+mALAri/8OJj+feYDvHl9BZkmCj6jE/9WD6MXZf
         7F6+MHadNJYjZCzpK43BKSogBvisIdq1EOF6KFmohy+ujjY78YXVD2yjX5NK5lsgTcVo
         vCnThCZUCJTQD7zcxCcxmk5p6zdAtGR1GhfPi9561xSaCwy3NilwgU+XsWw6Jj7PMhNS
         UXWGKZcQVlqib0kpQhFxOVzb6LPlg8uZC31/obF0JuXtXpNawqEeBLF7I+tk+4iVNZTv
         oMBsgDWg+b+/KiN5PSmnc93hYyfoZfjOABCNaicgEiG/PAk+j2uMwT9k8fAanlXc1/tu
         Jbmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=ddTlNlNR;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id o4si143444lfn.12.2020.10.22.17.11.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 17:11:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id b1so4425799lfp.11
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 17:11:26 -0700 (PDT)
X-Received: by 2002:a05:6512:31d5:: with SMTP id j21mr1484301lfe.348.1603411886051;
        Thu, 22 Oct 2020 17:11:26 -0700 (PDT)
Received: from mail-lf1-f42.google.com (mail-lf1-f42.google.com. [209.85.167.42])
        by smtp.gmail.com with ESMTPSA id s2sm477410ljp.17.2020.10.22.17.11.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 17:11:24 -0700 (PDT)
Received: by mail-lf1-f42.google.com with SMTP id l2so4472722lfk.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 17:11:24 -0700 (PDT)
X-Received: by 2002:a19:c703:: with SMTP id x3mr1503603lff.105.1603411884054;
 Thu, 22 Oct 2020 17:11:24 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com> <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
In-Reply-To: <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 22 Oct 2020 17:11:08 -0700
X-Gmail-Original-Message-ID: <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
Message-ID: <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, X86 ML <x86@kernel.org>, 
	LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=ddTlNlNR;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Oct 22, 2020 at 4:43 PM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> Thanks. Very funky, but thanks. I've been running that commit on my
> machine for over half a year, and it still looks "trivially correct"
> to me, but let me go look at it one more time. Can't argue with a
> reliable bisect and revert..

Hmm. The fact that it only happens with KASAN makes me suspect it's
some bad interaction with the inline asm syntax change (and explains
why I've run with this for half a year without issues).

In particular, I wonder if it's that KASAN causes some reload pattern,
and the whole

     register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX);
..
     asm volatile(.. "r" (__val_pu) ..)

thing causes problems. That's an ugly pattern, but it's written that
way to get gcc to handle the 64-bit case properly (with the value in
%rax:%rdx).

It turns out that the decode of the user-mode SIGSEGV code is a
variation of system calls, ie

   0: b8 18 00 00 00        mov    $0x18,%eax
   5: 0f 05                syscall
   7: 48 3d 01 f0 ff ff    cmp    $0xfffffffffffff001,%rax
   d: 73 01                jae    0x10
   f:* c3                    retq    <-- trapping instruction

or

   0: 41 52                push   %r10
   2: 52                    push   %rdx
   3: 4d 31 d2              xor    %r10,%r10
   6: ba 02 00 00 00        mov    $0x2,%edx
   b: be 80 00 00 00        mov    $0x80,%esi
  10: 39 d0                cmp    %edx,%eax
  12: 75 07                jne    0x1b
  14: b8 ca 00 00 00        mov    $0xca,%eax
  19: 0f 05                syscall
  1b: 89 d0                mov    %edx,%eax
  1d: 87 07                xchg   %eax,(%rdi)
  1f: 85 c0                test   %eax,%eax
  21: 75 f1                jne    0x14
  23:* 5a                    pop    %rdx <-- trapping instruction
  24: 41 5a                pop    %r10
  26: c3                    retq

so in both cases it looks like 'syscall' returned with a bad stack pointer.

Which is certainly a sign of some code generation issue.

Very annoying, because it probably means that it's compiler-specific
too. And that "syscall 018" looks very odd. I think that's
sched_yield() on x86-64, which doesn't have any __put_user() cases at
all..

Would you mind sending me the problematic vmlinux file in private (or,
likely better - a pointer to some place I can download it, it's going
to be huge).

                      Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwi%3Dsf4WtmZXgGh%3DnAp4iQKftCKbdQqn56gjifxWNpnkxw%40mail.gmail.com.
