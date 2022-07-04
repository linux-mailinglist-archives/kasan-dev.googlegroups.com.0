Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBJ7ZRSLAMGQEHNG6FLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 97F19565DE3
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 21:16:56 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id t20-20020a1c7714000000b003a032360873sf7784864wmi.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 12:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656962216; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFI0/5lr+LC6RxtSSuptYNUcjRIbFYB7inoJ9velId4pbKXVH2iHiTQzTas8hxHzB6
         F4h46TkMM4v2e11ZnbrQ9R5vG8GDJY88jiGjrXOAu4O7nJHQ/L27l2qlzsx64pgSEJ+b
         s+DlalA3rrlQl++b7rHGa5I8jDRzv0Gd5j2YH/kL8OvQ/q0Z73DN6gm7efAn7lJXMPH5
         Be9xBMQo8FFXPtoCq3Nzqx+5fghT7DkykR6rRXa4f+pCM+Gle2FtXzC1hrTYssVZLx1i
         wScGrYbrn/8Hzx5Q6If5JltwuRed/g5mxvJZcWdq/JnGxDy7k2o0cRIJjBovpZiU873w
         yfug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=PqZCGtWp+WLq1u4/LuceSZjz+D7sTf4ZHVf8vCy0i5k=;
        b=Lg9TUnm4FbinH+u5TXnfssyDtxWSzEeeFSKunGkKWA7XqAt25DboHqvarWn+yE2Ty9
         1qeDkiHtJWgSP3c22Jhj+Qu8Q4twP0MqB5sUgsoJf+ske0KUtIOxclTamMbXWcTSQg3v
         7iXIosyHv2lyUWcmNqALvhklyr9IBN7YJ4ezl7v7ha2tvaeFWbUMdW9zhLaxTDHUMjJ9
         1pEEy69JiI7YfE8AcXvX8IgLMNHYpElwYMPDttdkwvwCQ9TgTi1c+4iQZclV82bWkH7O
         6VC0AI1bBj1KUcc17GEa2NdPo/z/8t35CTi7bC4uayn5CmEXoZL5ofAbxFPGgyYttmnP
         WoEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=hM6KgRdJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PqZCGtWp+WLq1u4/LuceSZjz+D7sTf4ZHVf8vCy0i5k=;
        b=e77orOHBKGaUpZ/bnHVsXWDmlW7cg68nLTMbyrp5u6u+K75St6VZ3d9dcJY7QeJQkb
         BmodYR4Fam5lZ2Zd2wTqnvK0i+QkUYz1lvaGZu1vbq9nIeUhlIAA8G0SncPYtp7H0Vuw
         GOn9TjHUOZy7Rq1d2Ybw7+6Tnn0xZNrASQoXu3RasdKnVms5Z2ACWsfJAAgdYiVjupj8
         SljYXcFG3SQcZQwCizZol3WbkFYABsYnFl236LkWt7i2Fo/TbU4NhqtrEzy/sbNOY8pa
         B4Wm5MPo0cUZRnUG1EyAgaZlY1ZviVmyV/XT4qry9SZ4vr11dvDlXk2cb9hScZ92IxRh
         ykfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PqZCGtWp+WLq1u4/LuceSZjz+D7sTf4ZHVf8vCy0i5k=;
        b=JYmYv25+aRvXLYIYFhxFmVX8RN4yLuVjB1aguizJ2mBL6o2tNtIY1VEUK1i1gqE5re
         74ZmRiHAvKXAGby4XNL8z4NHHURoyBnR9a3L9r1km1O6Ml1tnNTYA9UPMvHyp3Pgrpx0
         0Tm8aKj26bNHc3KKRvHCucnnN9+WZYHfux5nCAN/4vAaPJIwNMfSxvHMFOVRw+1LP4Ph
         +qvuP3lCNT9erQW1C8Dxj0192jQxAioFkiN9wJvctEgxcqrHn/zWfy52K5CgR7i0Ei4m
         EOFueWCIMAqup1gsr/oZvIAKW48zQW9pJEhdQBwyVDM2HIWqKZEZPVgGALAOUqfPdzE8
         OsyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora81116ytU0z9dU300YJgqxN05uKwfC9DYQPJx5FZsxz0dJ/MAoD
	d0ysa0RZ99nUy8fRt9ZryqI=
X-Google-Smtp-Source: AGRyM1tFonlkLjV+z9ptz610hPcH2y4m5j2z0zEwbGXjA46MGWeg8kS8ahwT5iMPXdF2/i+s2Gp12A==
X-Received: by 2002:adf:fb03:0:b0:21d:70cb:d6b5 with SMTP id c3-20020adffb03000000b0021d70cbd6b5mr239348wrr.548.1656962216169;
        Mon, 04 Jul 2022 12:16:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da7:b0:3a0:3b20:d119 with SMTP id
 p39-20020a05600c1da700b003a03b20d119ls7602811wms.1.canary-gmail; Mon, 04 Jul
 2022 12:16:55 -0700 (PDT)
X-Received: by 2002:a05:600c:21ca:b0:3a0:48e6:60cb with SMTP id x10-20020a05600c21ca00b003a048e660cbmr35192982wmj.195.1656962215048;
        Mon, 04 Jul 2022 12:16:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656962215; cv=none;
        d=google.com; s=arc-20160816;
        b=lhp2M9mFA+McLHBv4THeuvOtOX7BybONd8gGHHnVqmRSFiff6q/OIDNRgOI4M5ZdD1
         sk6MBJG2IA832vqOnNTRwUQnd5mWOlQ4VvHU5LJavJdSMdyWmVG0+OLC63pxZ380fhmK
         cmTREwuXi9peW4guduteRONOKWOfbD8prrErcbXYrBTLDrDHVWipmo39qovnSSKBAejz
         mPCL+vxmdx6OEfcFJo/CoxQjvJqKJKbn+wo7DIZCAEWyjy2mMNqvbjyADsFXjnx9WlCY
         A7dk9bZL+Sqzu1q8zJZ7P6G/tWGKRnbecLmTJtisFxA7zbPQeVDqfUsz/k9WObNeLU+t
         zG1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MM4ez9sq6uBjf7T2AcL2UYNl+8nxT4N2iGuYkE53QQE=;
        b=mMi4QrWsCL/h7JzVGuY4sGRHN2gA3YpIN1afJ7+l8eiZ+J63zqBlWDqjuC+6nDh6Tb
         dCrJ4srXgbj2D7HkkbD3CGE3eqc8g/w2fnso7bwNvRgeEoY06vu/k6yjoeHoUXv67kPR
         kl+BWGc5Zy5eyzOqL8vyKKDHpZaCc9wtCYwck2K7vMoxaNaI4MIjt6I+f30R03KBw5jG
         OB5edu8xGyeR+1lOCt9Zt/RmMndP5xnjzWcm4xyZykYgArTmV3lruDuxsVtv33zckzyS
         GA4YSztH5u5LjdFL0xTbEVcXVAMeFcpmNEbhdXpQ/K3hvxjO0nEUIKAdgeQRwKSzynQT
         mPhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=hM6KgRdJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id bn26-20020a056000061a00b0021d6e648fd1si62505wrb.1.2022.07.04.12.16.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 12:16:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id v9so12041573ljk.10
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 12:16:54 -0700 (PDT)
X-Received: by 2002:a2e:8004:0:b0:25d:16e9:83ea with SMTP id j4-20020a2e8004000000b0025d16e983eamr6588829ljg.368.1656962214329;
        Mon, 04 Jul 2022 12:16:54 -0700 (PDT)
Received: from mail-lj1-f171.google.com (mail-lj1-f171.google.com. [209.85.208.171])
        by smtp.gmail.com with ESMTPSA id 9-20020ac25f09000000b004791e47c5b8sm4800311lfq.175.2022.07.04.12.16.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 12:16:53 -0700 (PDT)
Received: by mail-lj1-f171.google.com with SMTP id c15so12125780ljr.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 12:16:52 -0700 (PDT)
X-Received: by 2002:a5d:64e7:0:b0:21b:ad72:5401 with SMTP id
 g7-20020a5d64e7000000b0021bad725401mr27236387wri.442.1656962200967; Mon, 04
 Jul 2022 12:16:40 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com>
 <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com>
 <YsJWCREA5xMfmmqx@ZenIV> <CAHk-=wjxqKYHu2-m1Y1EKVpi5bvrD891710mMichfx_EjAjX4A@mail.gmail.com>
 <YsM5XHy4RZUDF8cR@ZenIV>
In-Reply-To: <YsM5XHy4RZUDF8cR@ZenIV>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 4 Jul 2022 12:16:24 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
Message-ID: <CAHk-=wjeEre7eeWSwCRy2+ZFH8js4u22+3JTm6n+pY-QHdhbYw@mail.gmail.com>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
To: Al Viro <viro@zeniv.linux.org.uk>
Cc: Alexander Potapenko <glider@google.com>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Evgenii Stepanov <eugenis@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Segher Boessenkool <segher@kernel.crashing.org>, Vitaly Buka <vitalybuka@google.com>, 
	linux-toolchains <linux-toolchains@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=hM6KgRdJ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Mon, Jul 4, 2022 at 12:03 PM Al Viro <viro@zeniv.linux.org.uk> wrote:
>
> Anyway, I've thrown a mount_lock check in there, running xfstests to
> see how it goes...

So my reaction had been that it would be good to just do something like this:

  diff --git a/fs/namei.c b/fs/namei.c
  index 1f28d3f463c3..25c4bcc91142 100644
  --- a/fs/namei.c
  +++ b/fs/namei.c
  @@ -1493,11 +1493,18 @@ static bool __follow_mount_rcu(struct n...
      if (flags & DCACHE_MOUNTED) {
          struct mount *mounted = __lookup_mnt(path->mnt, dentry);
          if (mounted) {
  +           struct dentry *old_dentry = dentry;
  +           unsigned old_seq = *seqp;
  +
              path->mnt = &mounted->mnt;
              dentry = path->dentry = mounted->mnt.mnt_root;
              nd->state |= ND_JUMPED;
              *seqp = read_seqcount_begin(&dentry->d_seq);
              *inode = dentry->d_inode;
  +
  +           if (read_seqcount_retry(&old_dentry->d_seq, old_seq))
  +               return false;
  +
              /*
               * We don't need to re-check ->d_seq after this
               * ->d_inode read - there will be an RCU delay

but the above is just whitespace-damaged random monkey-scribbling by
yours truly.

More like a "shouldn't we do something like this" than a serious
patch, in other words.

IOW, it has *NOT* had a lot of real thought behind it. Purely a
"shouldn't we always clearly check the old sequence number after we've
picked up the new one?"

                   Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjeEre7eeWSwCRy2%2BZFH8js4u22%2B3JTm6n%2BpY-QHdhbYw%40mail.gmail.com.
