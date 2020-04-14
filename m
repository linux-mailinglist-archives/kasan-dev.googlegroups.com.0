Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPP272AKGQECK4BXEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A18A1A87F0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 19:50:11 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id m2sf776808ilb.21
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 10:50:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586886610; cv=pass;
        d=google.com; s=arc-20160816;
        b=vj/XUZhdeeFKQwJ6s+N19SRwk49yK9QslwKkTDZm0EwcM/+UqohyBpQ0dKc6sl1zmh
         cZV7AB0yzt9Wjua5RwBVsW9l/9ZfzumNkzIsS5wtruUQjnHULmdhPqdEok37qkO4v7V1
         lHv7IJGT6ywnL7xI1TfrJS4BUfgCc29WMWYdbTuk524jZ7fC0wOzmMEYIdtrV5FmeBxs
         jhkXmm0crakSpJT8oFvRO30WDY2LKv/GjiFuxegI3HnuX6uEwGPimuZ4jlHcXMjNnL5Q
         Ke3Uzw/SAQybk9yKVwtT1PjHRJjoZPY8LaBXNuNOvpNJOjE/ewotn0F4Zn4Z0YCW9j2T
         ZU/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ByvjQ6jiBJDw5SxlZrCj+YrJg5ZgQI1BhL4/xFHfWz0=;
        b=EgU+wekiVJ7aSu4/5Z8jCpyXtSwIChl+FIKlomfShtQImtRsFumCqcSMXX7H8MgTq0
         Jr5IyyHtwtK0d4v5TqKFHrwItb5GOCG96g0APSnkA2p/lYVst5xGuvWK/AFP8A2lB73W
         vdJJuARKL4BRI0xptaAYr/bst3F0EtgSXzRQs88JvgeAYQBz1I8QQwQXfKs+yp3YDgnI
         HNyK8r03ce6VybRPWFiuVuv4Dk+ZQKWAKlxFhqCKl0HeXdqKLzf0hegSu71LLDz1YE7I
         P6Bkfoj18WOwo9/T8JsBGAwNNdqsv2iuMnOep8f8JHW2Z8ZoDtwjHM3ERcv2xlcuslht
         iIvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UAMvKl7x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ByvjQ6jiBJDw5SxlZrCj+YrJg5ZgQI1BhL4/xFHfWz0=;
        b=XWJ2Uh/U/LuETWIl8lG0vOvCdNhOcG8xs7VFBkscVvm+n/7393eadWaqXPJHkcVXrP
         AeBiUeLwNDOrDL4r6Wvur7jem+iAOZq95hzHQNO8Si6dx4OgqdbuqUSxOE4Wbn/eTm+M
         jGqhtEUBUAcEBaM19vo9MUv0E9k33RWxKPkc3c6i6RvCuwBYaYA4PQkL3O5MKPq6m1WV
         wqOpibTcG5XdkWWYeA17FrquFhkRphWEVVzADdZlXZ6eWxFMkVzR7JAmQZqOEfYov9Bz
         /98frj1YeJi1CJ6dVqA3QbfpbUBBfmqBKWHHlne6cmP4uzeIJquBrvpVEk0mJnQ27mCS
         CGag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ByvjQ6jiBJDw5SxlZrCj+YrJg5ZgQI1BhL4/xFHfWz0=;
        b=pK9mrCAX9YcoBl/aPAqoBEatp48ciSRaxwIx75j5SGstD7Bwg0vVjXKHf09q2zD90P
         uqGVpTuPU2fRaSOg+1BpKjOGssyJXYad/MoU8Bmprqb+7BMAq/pwnxVgIgnk7BF6Sojx
         uz+Oz/QzmUKw0dxVuozxJ6tW6Dwk91ieZ7tGcV9ldHdYXTgpy3DHmlJvySVmYmbVVv9U
         i7l8yuGA02FxVZoKotJaS5V3bZ5JEsra1CSdirJti7Gz/ciJI3qVL7H+ziEAyJTyMFMx
         dr3wDotCNqcAmMYHmEr34FkINyB8hQ3+npZGiV90ftMuy6gwdsdAi7atkj8YVwvG4Wbl
         gd/w==
X-Gm-Message-State: AGi0PuajxM/VdYsddZuTEd9HFzMpa6l/sh6Ck2qi34flt88yG2bZLJmm
	B0LDMVnwl9q/2oKUoSwoUls=
X-Google-Smtp-Source: APiQypLm6JrRobupOojE6gE90cwXyyHqzS/c6FUQzwyfLJxJSdDj7mydxJ03PwHmvn1b7kdZ867FZQ==
X-Received: by 2002:a02:3b50:: with SMTP id i16mr6088660jaf.39.1586886609921;
        Tue, 14 Apr 2020 10:50:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8ac3:: with SMTP id e3ls1258280iot.10.gmail; Tue, 14 Apr
 2020 10:50:09 -0700 (PDT)
X-Received: by 2002:a6b:e519:: with SMTP id y25mr6168748ioc.97.1586886609564;
        Tue, 14 Apr 2020 10:50:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586886609; cv=none;
        d=google.com; s=arc-20160816;
        b=rxJRD+FO+NYcJEftWKAQKmEFAL//b5xvnm6QkdNlkI0Hr2L+bLtl/FWpnL7hbPmkPc
         x5/FnLFB5bWIe4CGAs2OoK8rzAUpzROVzF3UdrN+cWyLXW6NzrG+qgoocIqy6ijFxgk6
         djvzQuaUzm+/+Gc1x6hRA9okTSxe4Nzv0KfGBgSQ3zQ8gJEJmDMdYtZz27to+rnUOPZW
         +04/LTxYZRHcGtUUY5MdnOQIGiXJJ7ZBnlqe6OJ9SZoiYyeUwrln1bm9nolSm39rpZ6J
         I4HolCvCfoULZN+FfBCY/mIlPKcXLfjTSOIPr+ALOX/xzHxKAceam0S/FBEnK6EGMw7T
         yzfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TEcf9WnegdoS4TK74rJ3jgH/4y0s3Rie/mbgUIU1/FE=;
        b=iPWyCQ5sCvAZ82txtqr6PlGhTBU9JbwjES2BSXEcKxsQ+gJyam9xR9aLQO7Rvc3cmD
         EyEpTeT/yv667FlGO35zJf94QtOtTRiwYrttSrttNHWPeA/H+hPaq0FV9PADm9WNxLT1
         SpwamGD/QGTS+K3FCGOT/YBXPpj53Oee09rY0mUXWDKu6A7f6TrSEeisKTAvXzYBcFtW
         6TDeL7UOjn+xgCklyT15TqIVENumE9ifbbZ9yXANF0fY105Vo9E1t6OAmC2xJFCAE/a6
         2+nl3R7MQ9gcSSobnM9nLRIjjbY+LccDMH9JScDDioDOuzmzS32CAs+z6h/enb+5oF87
         KeEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UAMvKl7x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id o12si1486057iov.3.2020.04.14.10.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 10:50:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id x10so1761051oie.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 10:50:09 -0700 (PDT)
X-Received: by 2002:a54:481a:: with SMTP id j26mr16403284oij.172.1586886608876;
 Tue, 14 Apr 2020 10:50:08 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000009d5cef05a22baa95@google.com> <20200331202706.GA127606@gmail.com>
 <CACT4Y+ZSTjPmPmiL_1JEdroNZXYgaKewDBEH6RugnhsDVd+bUQ@mail.gmail.com>
 <CANpmjNPkzTSwtJhRXWE0DYi8mToDufuOztjE4h9KopZ11T+q+w@mail.gmail.com> <20200401162028.GA201933@gmail.com>
In-Reply-To: <20200401162028.GA201933@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Apr 2020 19:49:57 +0200
Message-ID: <CANpmjNOJ-LZXv29heKZ5LazF5e99BC7-fXi7G0EsSNQd_yiyPQ@mail.gmail.com>
Subject: Re: KCSAN: data-race in glue_cbc_decrypt_req_128bit / glue_cbc_decrypt_req_128bit
To: Eric Biggers <ebiggers@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, 
	syzbot <syzbot+6a6bca8169ffda8ce77b@syzkaller.appspotmail.com>, 
	Borislav Petkov <bp@alien8.de>, David Miller <davem@davemloft.net>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "H. Peter Anvin" <hpa@zytor.com>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UAMvKl7x;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Wed, 1 Apr 2020 at 18:20, Eric Biggers <ebiggers@kernel.org> wrote:
>
> On Wed, Apr 01, 2020 at 12:24:01PM +0200, Marco Elver wrote:
> > On Wed, 1 Apr 2020 at 09:04, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Tue, Mar 31, 2020 at 10:27 PM Eric Biggers <ebiggers@kernel.org> wrote:
> > > >
> > > > On Tue, Mar 31, 2020 at 12:35:13PM -0700, syzbot wrote:
> > > > > Hello,
> > > > >
> > > > > syzbot found the following crash on:
> > > > >
> > > > > HEAD commit:    b12d66a6 mm, kcsan: Instrument SLAB free with ASSERT_EXCLU..
> > > > > git tree:       https://github.com/google/ktsan.git kcsan
> > > > > console output: https://syzkaller.appspot.com/x/log.txt?x=111f0865e00000
> > > > > kernel config:  https://syzkaller.appspot.com/x/.config?x=10bc0131c4924ba9
> > > > > dashboard link: https://syzkaller.appspot.com/bug?extid=6a6bca8169ffda8ce77b
> > > > > compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> > > > >
> > > > > Unfortunately, I don't have any reproducer for this crash yet.
> > > > >
> > > > > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > > > > Reported-by: syzbot+6a6bca8169ffda8ce77b@syzkaller.appspotmail.com
> > > > >
> > > > > ==================================================================
> > > > > BUG: KCSAN: data-race in glue_cbc_decrypt_req_128bit / glue_cbc_decrypt_req_128bit
> > > > >
> > > > > write to 0xffff88809966e128 of 8 bytes by task 24119 on cpu 0:
> > > > >  u128_xor include/crypto/b128ops.h:67 [inline]
> > > > >  glue_cbc_decrypt_req_128bit+0x396/0x460 arch/x86/crypto/glue_helper.c:144
> > > > >  cbc_decrypt+0x26/0x40 arch/x86/crypto/serpent_avx2_glue.c:152
> > > > >  crypto_skcipher_decrypt+0x65/0x90 crypto/skcipher.c:652
> > > > >  _skcipher_recvmsg crypto/algif_skcipher.c:142 [inline]
> > > > >  skcipher_recvmsg+0x7fa/0x8c0 crypto/algif_skcipher.c:161
> > > > >  skcipher_recvmsg_nokey+0x5e/0x80 crypto/algif_skcipher.c:279
> > > > >  sock_recvmsg_nosec net/socket.c:886 [inline]
> > > > >  sock_recvmsg net/socket.c:904 [inline]
> > > > >  sock_recvmsg+0x92/0xb0 net/socket.c:900
> > > > >  ____sys_recvmsg+0x167/0x3a0 net/socket.c:2566
> > > > >  ___sys_recvmsg+0xb2/0x100 net/socket.c:2608
> > > > >  __sys_recvmsg+0x9d/0x160 net/socket.c:2642
> > > > >  __do_sys_recvmsg net/socket.c:2652 [inline]
> > > > >  __se_sys_recvmsg net/socket.c:2649 [inline]
> > > > >  __x64_sys_recvmsg+0x51/0x70 net/socket.c:2649
> > > > >  do_syscall_64+0xcc/0x3a0 arch/x86/entry/common.c:294
> > > > >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > > > >
> > > > > read to 0xffff88809966e128 of 8 bytes by task 24118 on cpu 1:
> > > > >  u128_xor include/crypto/b128ops.h:67 [inline]
> > > > >  glue_cbc_decrypt_req_128bit+0x37c/0x460 arch/x86/crypto/glue_helper.c:144
> > > > >  cbc_decrypt+0x26/0x40 arch/x86/crypto/serpent_avx2_glue.c:152
> > > > >  crypto_skcipher_decrypt+0x65/0x90 crypto/skcipher.c:652
> > > > >  _skcipher_recvmsg crypto/algif_skcipher.c:142 [inline]
> > > > >  skcipher_recvmsg+0x7fa/0x8c0 crypto/algif_skcipher.c:161
> > > > >  skcipher_recvmsg_nokey+0x5e/0x80 crypto/algif_skcipher.c:279
> > > > >  sock_recvmsg_nosec net/socket.c:886 [inline]
> > > > >  sock_recvmsg net/socket.c:904 [inline]
> > > > >  sock_recvmsg+0x92/0xb0 net/socket.c:900
> > > > >  ____sys_recvmsg+0x167/0x3a0 net/socket.c:2566
> > > > >  ___sys_recvmsg+0xb2/0x100 net/socket.c:2608
> > > > >  __sys_recvmsg+0x9d/0x160 net/socket.c:2642
> > > > >  __do_sys_recvmsg net/socket.c:2652 [inline]
> > > > >  __se_sys_recvmsg net/socket.c:2649 [inline]
> > > > >  __x64_sys_recvmsg+0x51/0x70 net/socket.c:2649
> > > > >  do_syscall_64+0xcc/0x3a0 arch/x86/entry/common.c:294
> > > > >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > > > >
> > > > > Reported by Kernel Concurrency Sanitizer on:
> > > > > CPU: 1 PID: 24118 Comm: syz-executor.1 Not tainted 5.6.0-rc1-syzkaller #0
> > > > > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
> > > > > ==================================================================
> > > > >
> > > >
> > > > I think this is a problem for almost all the crypto code.  Due to AF_ALG, both
> > > > the source and destination buffers can be userspace pages that were gotten with
> > > > get_user_pages().  Such pages can be concurrently modified, not just by the
> > > > kernel but also by userspace.
> > > >
> > > > I'm not sure what can be done about this.
> > >
> > > Oh, I thought it's something more serious like a shared crypto object.
> > > Thanks for debugging.
[...]
> > >
> > > Marco, I think we need to ignore all memory that comes from
> > > get_user_pages() somehow. Either not set watchpoints at all, or
> > > perhaps filter them out later if the check is not totally free.
> >
> > Makes sense. We already have similar checks, and they're in the
> > slow-path, so it shouldn't be a problem. Let me investigate.
>
> I'm wondering whether you really should move so soon to ignoring these races?
> They are still races; the crypto code is doing standard unannotated reads/writes
> of memory that can be concurrently modified.
>
[...]

Wanted to follow up on this, just to clarify: The issue here
essentially boils down to a user-space race involving an API that
isn't designed to be thread-safe with the provided arguments (pointer
to same user-space memory). The data race here merely manifests in
kernel code, but otherwise the kernel is unaffected (if it were
affected, a real fix would be needed). I.e. if we observe this data
race, KCSAN is helpfully pointing out that user space has a bug.

There are some options to deal with cases like this:

1. Do nothing, and just let KCSAN report the data race.

2. Somehow make KCSAN distinguish in-kernel data races that are due to
user space misusing the API. KCSAN can still show the race, but
clearly denote the nature of it by e.g. saying "KCSAN: user data-race
in ..." (instead of "KCSAN: data-race in ..."). This will require one
of 2 things:

    a. Distinguish the access by memory range. This doesn't seem
great, because I don't know if we can apply a general rule like "all
races involving this memory are user-space's fault". What if we have
data races in the memory range that aren't user-space's fault?

    b. Mark the accesses somehow, either by providing a region in
which all races are deemed user-space's fault. This is likely more
problematic than (a), because saying something like "all races in this
section of code are user-space's fault" may also hide real issues.

Because none of (2.a) or (2.b) seem great, at present I would opt for (1).

Anything better we can do here?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJ-LZXv29heKZ5LazF5e99BC7-fXi7G0EsSNQd_yiyPQ%40mail.gmail.com.
