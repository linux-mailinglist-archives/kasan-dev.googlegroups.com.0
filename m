Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV4OT24AMGQETWIXW4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E325997E94
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 09:50:49 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3e58ec286e2sf123279b6e.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 00:50:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728546648; cv=pass;
        d=google.com; s=arc-20240605;
        b=guyUjCFzNWW1otUanSe27xMcaGwsYikOodp5aN3a10xPRj1J0D4iNQcji1UpEAqQe8
         SZ44XHTdW3sBMeqkRWWfK/TFTJV4oIPZiVShgm/8yzIoBUTE/cZiBCTFVeu4sABiAzi+
         r+v8uqaCDeBiC7h3XVxDxOENsdllQuBEF0Nbouu3OF/dN4y+ZYPhYk6RtZc23Rxfit6/
         5Mr50wUuXsEnKq/A2FYMn630PVQSySvJ2ouhYbfd6iSCnrU1h1JJE+eVZ1G/K31/F+Rm
         KV/xCWvn0Uaw8TBJH0mANSwiH5UzDiHIenIw4XFdgPxvTckwaCouxnkGB3JgO6v2NjTt
         tUhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZYRvMeM2c/6benjgK1LXFHp21o4vPc2v7YSB8H5HPOg=;
        fh=X8ysHxCBU8iLYlZ6ei4dMMD7q1TLWBkJmckhMpEQzUw=;
        b=UGCYqKtBFgjvcBWA+kCLSP+5SScNFrTWowZzLnCtnL2tqpueTvd0FFK51gONcwNXnq
         wkEzcPXIpvhHRLgrPPYeD/gOj3KxoCCTGrxqApYGs8pFhD2v0DTcS3Dwrir19FCP04xP
         xnE46oSrhJo6o4kd0NeIkscO2wD3hGS1m0V/3l3k37YHcItqY01IzogWwIUK393/Qshv
         Y+lyJpPrT2Nw1G0YfqrN7D2/9LpVCeSAugOnVVw+kHC4nmNvS6TbocbhHoHyzhMARq2m
         zMeeGEAB7/G5q8FIIxlYPnPOVg93wjI3YdAeavHlU8CbLzfDoEX7rtR3mIUUbYuOuYl9
         WCxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u1qf4YWf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728546648; x=1729151448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZYRvMeM2c/6benjgK1LXFHp21o4vPc2v7YSB8H5HPOg=;
        b=tqvPHxqLA6yh7fj1QzaLPG+to6o2SDFPXuLa2WK4bF8SozlUGHfpCBEucr2PgyCyKu
         zm4UxUH7ffLUBmLEP5LbZP7ezPWyR3qqKWhOXO0UbWJrbDXXPHvrk5TghVpQh5A9UZGB
         IJl9Lb6JS+/wSsLK5FpubqfMzcGy5s0V2gJ8RVSb/Bychee+imZ/pGluSBJoUUexQ3LI
         XWfCLXShgjdMz6/YqXpT0o9kVtrfHpI9PpdaUIGE4YjF3KaR60bhyj8mc2ou5j9HZPw5
         cq9TStJJZGkrYGLC89lW/zgkEipghk2yg+kx1VYKmJuBmtHo8EFhaHLdJXKfSfnc+GGL
         xVBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728546648; x=1729151448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZYRvMeM2c/6benjgK1LXFHp21o4vPc2v7YSB8H5HPOg=;
        b=Hs6ZncyckJnXJxNCjXLbWKJrQDUQBdN5JXh8BMqw5OFe1vOngsPKiEqLSQWP3Qr/Zw
         FpmxQe3+u0I05ULSxqbZyiUDpzcIcIJf+6mFZ3slOvVSHIENQq0ynmxxVDxlvfEqfV+N
         nSHqWSd+7YY0VcTcGIkGlAd7roFEwkANclx50ydsghZyWFI2JTT/YCScqcGyGoD1aKnW
         keYXdUQ1yVHBYNYWLlWPEMWvjX/EnWdSIoCKaRaAkQsy78P96oLVfNrzRggzEEO66tky
         9MlpjhEQD+MNkcmA8wOc/Kspqt9BegErBw+d9z80jVtmQv6wlm12c+CuDVo7gm2VKkbp
         X1zw==
X-Forwarded-Encrypted: i=2; AJvYcCUK96RWKhxNj2pafHjAxzsb3luZBJRJ7dotGHY2UKxlRSGQl3X+LyDbPAjS38kf2bx1X3n/Dg==@lfdr.de
X-Gm-Message-State: AOJu0YwQvPypHsrech2WZclwjO+L4+3cyQ75NHlGLiNhNXQBwe8vp3wG
	3fLSjUv1RzJNgoRfh78sj4CZCQKFgowT0SfrNltTzP7egVJi0D4T
X-Google-Smtp-Source: AGHT+IHmu/mwNQr9a4djXGs0W+n4xz1q8vuDMMD3Xg3jsFiP51aVI1nKEXtCEOiXHlL/Oo1XyAuSpQ==
X-Received: by 2002:a05:6808:1404:b0:3e3:91ad:7c89 with SMTP id 5614622812f47-3e3e66d625amr3745559b6e.26.1728546647682;
        Thu, 10 Oct 2024 00:50:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:138a:b0:71e:268d:8d93 with SMTP id
 d2e1a72fcca58-71e270aef54ls585547b3a.2.-pod-prod-07-us; Thu, 10 Oct 2024
 00:50:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU64jc6kpv8+ykKH1BHQTw1cbfguKvSX9cQuuN4pPFvQlbvOXO9DNxzL65fbrXDi/IYBAJsUGgMqrY=@googlegroups.com
X-Received: by 2002:a05:6a00:230a:b0:710:5825:5ba0 with SMTP id d2e1a72fcca58-71e1db64435mr8324504b3a.3.1728546646091;
        Thu, 10 Oct 2024 00:50:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728546646; cv=none;
        d=google.com; s=arc-20240605;
        b=QwDwxRrM8IMeZfj3DvPXjjNAO2+4rlnwbuD1omRhVwgeUlO6XPMvDpeZ8hFBEDbBGY
         wvsB1mRKDVyVeGGQCEeNc+oQs6H18mx9w573fMQmvlSZBkwG41jqWbvyOWo0D2Hh55Mr
         NQU7jAaMOa+EmL0H1Qe3VRC2IEfNyYPD6Xssk+iCuw3IwccgB3cmQALnsBwFNzt5zqB4
         AQHZmIdvhezZVurNFkhUDt2GAshDdy6VnBy8VKs09b0c9WQdSQGF/uOuSmgqs1oNkftg
         GJ9wdaktnb78uzFYPvWiNtJ+rZl1t3icH9qmeh4ZdbkIGxd6mEMz0q4AaQPjVBZFsHH/
         9Phg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jvmR8o1Zd7WNMFxg04YvM6ScNptO0BgRV3DizZHFUZ8=;
        fh=6/tIwxQIj017QSQ4Pa4cpLtw2KEXS035bqFM7qpOXxI=;
        b=SZLFkXBoczZawlujg0jMYvlqtCArWLEpCuq/B/M7ffpbYeIuO9uYTfMi2eHuYNtLp1
         iT41ZyKBCtKPUdlB8H6YYTPSOFtn0FW3IoAXjzX4rNiHM8R01MEasgb0NXay8wx/k+6r
         e+xLE4phC9fXrLoDnC8uVDGpYMSmNFSZciBZgifMkzsj3jJuD7PTyl2CR6HrB9pgGKaw
         EAwrqlkf1/jcf+eMa8oyzhpm34SqwiZIY+57ME4eeIesj02Kub36/2qVeC3zO5XDW1LC
         89u0LQZAFQFVchQOGE/4b536ZYyDSuRvE0sP6c5hqy5GO7NlRsxJi/sJ/WM5dEzNM46w
         TWLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u1qf4YWf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71e2abad2casi24996b3a.4.2024.10.10.00.50.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 00:50:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-207115e3056so4460005ad.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 00:50:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGs2AQ4OxJAI3Zm6DqpSGWkNlOX1Qf329bauQWywiJQNZSMHtdGJ+NQWRwV8DjM5snz44R7AS4V64=@googlegroups.com
X-Received: by 2002:a17:903:1c7:b0:20c:5c37:e2e3 with SMTP id
 d9443c01a7336-20c6378011dmr65091635ad.42.1728546645201; Thu, 10 Oct 2024
 00:50:45 -0700 (PDT)
MIME-Version: 1.0
References: <6705c39b.050a0220.22840d.000a.GAE@google.com> <Zwd4vxcqoGi6Resh@infradead.org>
In-Reply-To: <Zwd4vxcqoGi6Resh@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Oct 2024 09:50:06 +0200
Message-ID: <CANpmjNMV+KfJqwTgV9vZ_JSwfZfdt7oBeGUmv3+fAttxXvRXhg@mail.gmail.com>
Subject: Re: [syzbot] [xfs?] KFENCE: memory corruption in xfs_idata_realloc
To: Christoph Hellwig <hch@infradead.org>
Cc: syzbot <syzbot+8a8170685a482c92e86a@syzkaller.appspotmail.com>, 
	chandan.babu@oracle.com, djwong@kernel.org, linux-kernel@vger.kernel.org, 
	linux-xfs@vger.kernel.org, syzkaller-bugs@googlegroups.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Vlastimil Babka <vbabka@suse.cz>, Feng Tang <feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=u1qf4YWf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 10 Oct 2024 at 08:48, Christoph Hellwig <hch@infradead.org> wrote:
>
> [adding the kfence maintainers]
>
> On Tue, Oct 08, 2024 at 04:43:23PM -0700, syzbot wrote:
> > dashboard link: https://syzkaller.appspot.com/bug?extid=8a8170685a482c92e86a
>
> [...]
>
> > XFS (loop2): Quotacheck: Done.
> > ==================================================================
> > BUG: KFENCE: memory corruption in krealloc_noprof+0x160/0x2e0
> >
> > Corrupted memory at 0xffff88823bedafeb [ 0x03 0x00 0xd8 0x62 0x75 0x73 0x01 0x00 0x00 0x11 0x4c 0x00 0x00 0x00 0x00 0x00 ] (in kfence-#108):
> >  krealloc_noprof+0x160/0x2e0
> >  xfs_idata_realloc+0x116/0x1b0 fs/xfs/libxfs/xfs_inode_fork.c:523
>
> I've tried to make sense of this report and failed.
>
> Documentation/dev-tools/kfence.rst explains these messages as:
>
> KFENCE also uses pattern-based redzones on the other side of an object's guard
> page, to detect out-of-bounds writes on the unprotected side of the object.
> These are reported on frees::
>
> But doesn't explain what "the other side of an object's guard page" is.

Every kfence object has a guard page right next to where it's allocated:

  [ GUARD | OBJECT + "wasted space" ]

or

  [ "wasted space" + OBJECT | GUARD ]

The GUARD is randomly on the left or right. If an OOB access straddles
into the GUARD, we get a page fault. For objects smaller than
page-size, there'll be some "wasted space" on the object page, which
is on "the other side" vs. where the guard page is. If a OOB write or
other random memory corruption doesn't hit the GUARD, but the "wasted
space" portion next to an object that would be detected as "Corrupted
memory" on free because the redzone pattern was likely stomped on.

> Either way this is in the common krealloc code, which is a bit special
> as it uses ksize to figure out what the actual underlying allocation
> size of an object is to make use of that.  Without understanding the
> actual error I wonder if that's something kfence can't cope with?

krealloc + KFENCE broke in next-20241003:
https://lore.kernel.org/all/CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com/T/#u
It's been removed from -next since then.

It's safe to ignore.

#syz dup: KFENCE: memory corruption in add_sysfs_param

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMV%2BKfJqwTgV9vZ_JSwfZfdt7oBeGUmv3%2BfAttxXvRXhg%40mail.gmail.com.
