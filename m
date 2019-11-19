Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44Q2HXAKGQENCZPEUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 024AD102D0D
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:54:29 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id r29sf5851564pfq.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 11:54:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574193267; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUNt2+AnLG/ImTs6doRv+1KmZGqayC4UapeYmmcrezJNU/fq2pyI6xnf4JNDXiqOMm
         7EKZ3uq5YVEloNUovfEcOW1UtKrZeOb+ZzVwS/N+Ek/uRukX6ZaErMUnuZr7CADMT2t3
         Kn4apPKMqgUe47DiaDF7oQZOtQW5XWIG9J+muOib3TfOZBGj6Q0sjxWXuqsHKZdmywzr
         engy6GdrRespFUs9ZmE7w1UpX5Pw4RZ1SL0LjoyMJxoo25hnPUj5bEtDQ1R+L8YjHxe4
         Bk/J5E9x6TuP+CnITGTVJSsDwC9mUn2ok+y7bwWp1VnFLlbCyllJtRdrK4rUwAN1G/8B
         1WrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xOUlAnbHxLRKeiB1cQ7nTFqvfq8s3hzs4eBu9F+0Btc=;
        b=NMsIvIkf/+69UAHBuX+WWI0lY5CZHclzPS6oTsgcJ7vwEBYGLW9GBtbZs8aCEe54Bq
         hjkNdMGasH0X0UsGZmGXpHHVRz+gB/fLmRmZaW1rvY8pcyp/flMv1lZ9Vkq2VW2kBcPq
         BGvtF/Nvaq3wO9qUGnkYoYxAV/OoUMJZ8hEmK0ZweF7tpTs0AOn6bnUEi23ElueDyu1F
         Zz618chrtmaGH7SFAPNG2pYiDfCUQ4g9YjENPtrILuMAZgVn96q90TiQedGCgM72qkzC
         FeRM9IF6NeDbvyC0ApRiXZX377t4/gOC7UQ7S80G3b7qlag2si73qw0d5h+G+P7KOdQo
         sRdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oURkgRgG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xOUlAnbHxLRKeiB1cQ7nTFqvfq8s3hzs4eBu9F+0Btc=;
        b=cVKqJt0o0MaGy616HpJyvUhWWg7Hf0LETbazZvzUl7Jp5/kAF/qgYql4Lxd28JKITi
         aBI7Exl8zSI9eY3xQehhu6JZqK5DKhPLjo2bovC+Tv7E/K1+gs6Evp+po1rpkhl1S+ok
         SHZsOC1HjiM8iNheEYYlHncbC10uJrkjWQznwGaPWBrlwf4nExw/YuqmJX65up86Qkdt
         7WnXYwYftdIBesOyPCviQbJ4Z86PJfMHCOVyXfqo68eDTgZvnsKOADZJ3yl/VhlD6qiN
         4wSpdGYTibSo6SnlmhcKY+ZysU6HzMfGqVCsffxH0fUdQrZyVj6zgkHqFpfhTyZXK1hd
         O52Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xOUlAnbHxLRKeiB1cQ7nTFqvfq8s3hzs4eBu9F+0Btc=;
        b=kIpJLHOncJfiMMIBc5QucZ/SDXe2WeFHvLhdLBf6yBhJDVtvOQL48IrK6LArpZfYXB
         Y+NcP45jNMyuht8ygapZ5eJhPbGqTurK8jjKHQ2/iLcCQ4ZkIkPNjk7oyNZot90lpL7Q
         vxWPKQOj6MqvDTrrMut/8K3n5cjwsU02KjsejN3m7kNrxNzC/ofxpDqhkGbmZhnVa4k+
         i2bkEJRkJTE+uhVhfR5UaqyBQ8X98NXlcQWtoNR1sdphnF/zxRvugFPSgdwGN/QXfKVo
         DjDlVpJj50W0rWadv1zPmueYeiWv5vJDyp+3T9ci1ZmCiDHT087h8sMQY2HHbL++LH0y
         +d2A==
X-Gm-Message-State: APjAAAUbxuIdKWkteWwrjx7DjScTWe9BBqQwbCwGXgrs0ee43iP2OmFP
	A5dHB9nXJEanKGrzJdy8efg=
X-Google-Smtp-Source: APXvYqycPBAwqnRS84KAxxMTjUN62TxbOdFHBzWuZR1mCeT0/Fp07SLH1QvtkAkHM5e3hORBEujnaA==
X-Received: by 2002:a17:90a:bf8b:: with SMTP id d11mr8879505pjs.87.1574193267672;
        Tue, 19 Nov 2019 11:54:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f513:: with SMTP id w19ls2687971pgh.14.gmail; Tue, 19
 Nov 2019 11:54:27 -0800 (PST)
X-Received: by 2002:aa7:9151:: with SMTP id 17mr7912372pfi.3.1574193266987;
        Tue, 19 Nov 2019 11:54:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574193266; cv=none;
        d=google.com; s=arc-20160816;
        b=y1dzh8tnOkjLZbhoafEl3f7at5nz3zs/GZ7IvoST/XoUnPGrb+mo2vrBFbK9ra7ER4
         ujLvr4OVrXev/b23s2TzeVrkB5rETz2qEKiaKGyJE109UcmlH78Hfj7Y8Iol22W00d0V
         LNVfqXQ4ZCKlLRsW7OcKANfkw5A1KbrsJBwR9G00DUN0vTyzA7zhTGA5neD4L5My9fxl
         eTB6QdJBWLsz3UXB3619eFduv6N6tmBwqir/98et5NG/J+M4Itu5bxkYIwpMN/G1FyJ+
         APaXoJatzptENx0hGzXKLWiOXfxXuXHfgFp3BhLDRshVoqxdXANiYRwaK+xDOwzDhDQC
         foxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EhLUhFf+dWrZRS+as37pEKZIEswUZkBGb2xI++P3+j8=;
        b=EIxdIX6yxoYYcyIBoerlm6HQ2kGcOGJq9agJsDJDVshPWv/NW4V6zETuTJIoGlnWLa
         w8wwStvgiE3P0kRnWk1zZqJVFe3wRQBJ+Z3U/GQBUyCMmNDz5+KiCWwFznBsoKbu9OjH
         CA0J6jO374ioiI0K1r2uiJu5C7j+Ac12SJBfEE5JgIr842icP9jXqS8Rl9Ydwn9MRO7g
         DcZ1VAggpQavtXesle9IbDUMQ7cjlYqkxWFdh33Ohf5FmnfXPPaDyZwmNukvB5uZB9++
         O1d7BVBmnzEiT6JMJs3yKqXk/XQvaKUYh/ab93AHnjFZkdDDns5i4JJzlYa5fApHuI2H
         Lc9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oURkgRgG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id r142si979627pfr.2.2019.11.19.11.54.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:54:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id l14so19006184oti.10
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 11:54:26 -0800 (PST)
X-Received: by 2002:a05:6830:2308:: with SMTP id u8mr5018538ote.2.1574193265740;
 Tue, 19 Nov 2019 11:54:25 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <20191114180303.66955-2-elver@google.com>
 <1574191653.9585.6.camel@lca.pw>
In-Reply-To: <1574191653.9585.6.camel@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2019 20:54:14 +0100
Message-ID: <CANpmjNPiKg++=QHUjD87dqiBU1pHHfZmGLAh1gOZ+4JKAQ4SAQ@mail.gmail.com>
Subject: Re: [PATCH v4 01/10] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Qian Cai <cai@lca.pw>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oURkgRgG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Tue, 19 Nov 2019 at 20:27, Qian Cai <cai@lca.pw> wrote:
>
> On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:
>
> > +menuconfig KCSAN
> > +     bool "KCSAN: watchpoint-based dynamic data race detector"
> > +     depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE
>
> "!KASAN" makes me sorrow. What's problem of those two?

Both of them instrument memory accesses, and gcc doesn't let us
combine '-fsanitize=3D{kernel-,}address' and '-fsanitize=3Dthread'.

> cc1: error: =E2=80=98-fsanitize=3Daddress=E2=80=99 and =E2=80=98-fsanitiz=
e=3Dkernel-address=E2=80=99 are incompatible with =E2=80=98-fsanitize=3Dthr=
ead=E2=80=99

In principle, it may be possible:
- either by updating the compiler, which we want to avoid because we'd
have to convince gcc and clang to do this; I can see this being
infeasible because the compiler needs to become aware (somehow
propagate in the IR) of what is ASAN inline-instrumentation and what
is TSAN instrumentation and not emit recursive instrumentation.
- or somehow merging the instrumentation, but, IMHO this is probably a
really bad idea for various other reasons (complexity, performance,
stability, etc.).

Regardless of approach, my guess is that the complexity outweighs any
benefits this may provide in the end. Not only would a hypothetical
kernel that combines these be extremely slow, it'd also diminish the
practical value because testing and finding bugs would also be
impaired due to performance.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPiKg%2B%2B%3DQHUjD87dqiBU1pHHfZmGLAh1gOZ%2B4JKAQ4SAQ%40mai=
l.gmail.com.
