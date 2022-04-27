Return-Path: <kasan-dev+bncBDEKVJM7XAHRBBO3UOJQMGQENVAMSZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6254B51122F
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 09:15:18 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id y7-20020a2e95c7000000b0024f29bcd594sf364287ljh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 00:15:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651043718; cv=pass;
        d=google.com; s=arc-20160816;
        b=jM2rGD/3UFbtSMlePJfDYOIVKI2zzpTqpxQ8hWU1VWqKw+Txg23YluH7gVPgwhUTk8
         pu8YkXAalruhJv9qJEmLVbZIWVKnGlJHmMLgCm1H47gB/str6GrV1tX9ttqWtLNx2Xez
         RkrphYc/3dMDwdou9f16XJhD/0U+iTPJoSlHJfyarrwTINHXYJbNFopREkmK0zsT8GOZ
         lNdL2biGdOpPbNXQZeJpgyC2Bw0SRcH6zYN9mHloYHESxc2D+3UDSxdfJ6VySXHhKvoV
         iZRGZWida4CE+qM5zhVo+lLEMvL6up5JRDIQzaT2PhQjaCOYrt85bFoSuUYqFVj311c3
         Bmew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=pc3UsJmNAFJiN8J20ON5Rdr5Y/USyPACAaNnHP6hEkQ=;
        b=KvPVbvU1OFRYJ6HEjkVWImSLpH8Y3V0mJtp83x/ysAVI1KpuupixnknE/uM0ponDvR
         KCjkNLWXbZou+42GGPnLZekbU6YuJFC3Niwe/E/bn9rgZ2LmZNBYyJWBKF/CkVxNyuUu
         KbXx+68J/1cQad6a0Q1+eGwJYobI78C+wD+LX9Wu/Lb1+7nLOfliW8uC9sO4Xzbg/+uF
         iphIVvTGNjrOQxxu1zegSEjE06B2waoGCYBtvCqmAwtef8fjT0NFqkbaYVFLNe0QtECP
         flSsRTXVKyg4rf/NSaMj5QmCzceODwh3aC7ix8BjJ6TIwxRnU9C70QphVll91KPMIej0
         AyqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pc3UsJmNAFJiN8J20ON5Rdr5Y/USyPACAaNnHP6hEkQ=;
        b=bnIcD7D+pwvgNgfDv92YVumBpYDcAd3vdP4UigplThcIL9fJ9k7cc1n6IfW0EfZeth
         qDK8WbJZKNQBlFEPca2iEhZyMKbxfyTiCdTWLiOgYsrc05HubfBhzn1+EZj9kzB3YCAG
         oLaHfxsTriGjhF13rPu8Bo1E/hWQ87jUlo5pD5zCqJrgJsq5mmKxv7b2QyTypog+Lge7
         famBFRubshpfI9kETbp2LVXWFSnMjjGROo4T+m6GvEawnSkgc4yy/HJEKMfWJVW34EyG
         xrknqm8VMXb7nsUdlpuPnB5ugtI1xkTjnf3WSoqR1/94UQZNDGJKG7e45oABD5kPnuhr
         bw4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pc3UsJmNAFJiN8J20ON5Rdr5Y/USyPACAaNnHP6hEkQ=;
        b=Q4/T2UIC96xnoX0g9O5g0kaa/KizqZqGaBHJKYvFj8hCllppzBuw7A5FgMahC1DbmP
         ewQW8G4sSVnAFTDHBA5ZkhmZ58GzMmP22kX2tO+VwEvWteAX/Gh4kZf3GrmqxPtjCBjr
         nUycE7qfcqP0JcaqaLnWkb1FPGKV4ffgr1kHMJKDUyPtiPF7WdD4iPpenRBh1GrCtg/N
         lwuNa75ZbUTD6/DMS+Inf0HtN8NCWsQ+ydGlo8aNOQddr1/vWiLLUve0Xzlw3U+P62Lf
         NkUR1NyXDMH39XIH6q8RcXhbe2U+x/IGn4OYKtnTnGuTYD7f6JJJLxfgdQN63CMnWiyy
         PF9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532X+pO5PGzRJ2VYB4xNDbLV9hmEnKFu7WOwymgO+u7TPEf40HIo
	o5TrxzEfy0NBZUh/6gO+65k=
X-Google-Smtp-Source: ABdhPJyC33pQPYnabDUxRjokB8rHvZBTWvoIV18kAwK67ugoMz63qq7rTqH7gTQl7aXnMZY+tMHRmg==
X-Received: by 2002:a05:651c:160b:b0:247:f955:1b18 with SMTP id f11-20020a05651c160b00b00247f9551b18mr17563210ljq.427.1651043717821;
        Wed, 27 Apr 2022 00:15:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a22:b0:24f:170c:7b29 with SMTP id
 by34-20020a05651c1a2200b0024f170c7b29ls1346412ljb.9.gmail; Wed, 27 Apr 2022
 00:15:16 -0700 (PDT)
X-Received: by 2002:a2e:94c5:0:b0:24b:7029:75eb with SMTP id r5-20020a2e94c5000000b0024b702975ebmr17553269ljh.506.1651043716690;
        Wed, 27 Apr 2022 00:15:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651043716; cv=none;
        d=google.com; s=arc-20160816;
        b=p6SKfqHZ3rJJ0l3euOuM2JwTZkz0/tK0ZMQnGo+13SoAXeHdRHKhyBVvmBU067mkP9
         6BnynnhtFCpimNiKA8eAAG/W3uu8xQkWVMNW5OoglszZ9eXPu5dQvXFeCOEJ4XnZ8JQ7
         jFE5G34cugG5/Hl31mJ7bGZMYUxGsuHdnYfl81xzThfDG77X4D7mwITzcq0eDP/wgV97
         JYn7Fb6se26oh2mwcTXNVkklnlP60pYTgly6jfRHfGh9Rspbn7wILbfuZmlG1jMxh5Bd
         Zj3lUVhxhP1dm80yVEt8H5kBpmjhqFHMzS2rbXqEV521BNqNBeUN6pzmcd8tQj8KWKB/
         4RRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=KpKF6nOoMy4xLrOqrlVol4dmxEDHjovijCGC4RRV4s0=;
        b=Kjfn8JDnD6ByrgE0dPUuQhzn+aszbAQjhrw4Xi15C6ZmjZFLiqMPXbxUuh+RDcj0KQ
         JnQz53StM+Syp0paGPTb9afa/Uk3ZnDGHfkT16Gxg/3zuXSP9eHXI/UfsWXMdzO8jNjo
         HffL7rWgrmy/pf6HJyHlGKK1ZRe98+tVdcLv+puUOOy8e4zqT0fpoSCPUAdJ46fEksMT
         MuQFsYklcfxEmaWiSQfxcb3LU+yqjdaPIFNBXxA+0gQpS0fkf2OQR5TdkNWbM0QGiHmI
         Qxj+FKk0xWvlFV1a4y8zD3xsmH323todsAY75KNSXV18L5lBZQjSebGV6ejz0USrC5+r
         S1Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.135])
        by gmr-mx.google.com with ESMTPS id i42-20020a0565123e2a00b004721a3e27cfsi33955lfv.12.2022.04.27.00.15.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 00:15:16 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.135;
Received: from mail-yb1-f177.google.com ([209.85.219.177]) by
 mrelayeu.kundenserver.de (mreue010 [213.165.67.97]) with ESMTPSA (Nemesis) id
 1M42zo-1njbtL3A80-0006LC for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022
 09:15:15 +0200
Received: by mail-yb1-f177.google.com with SMTP id s30so1735104ybi.8
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 00:15:15 -0700 (PDT)
X-Received: by 2002:a25:c604:0:b0:645:d969:97a7 with SMTP id
 k4-20020a25c604000000b00645d96997a7mr20381066ybf.134.1651043704287; Wed, 27
 Apr 2022 00:15:04 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-6-glider@google.com>
In-Reply-To: <20220426164315.625149-6-glider@google.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 27 Apr 2022 09:14:48 +0200
X-Gmail-Original-Message-ID: <CAK8P3a2eDDAAQ8RiQi0B+Jk4KvGeMk+pe78RB+bB9qwTTyhuag@mail.gmail.com>
Message-ID: <CAK8P3a2eDDAAQ8RiQi0B+Jk4KvGeMk+pe78RB+bB9qwTTyhuag@mail.gmail.com>
Subject: Re: [PATCH v3 05/46] x86: asm: instrument usercopy in get_user() and __put_user_size()
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:/JPQoggxGbOYDPP8SafQ2RplXz1Sl1E9+1D+9GDOdJIzrAmTheW
 1bLpCZfw+cEJR9FJkVyVeXJl9K4YC2Qo5GtqU4ZIUKbXvRwMdCKfUp5M5S0K37RYo1PVf5J
 Z8Rls28w5oVzPcRi/R9bhaby8JdD6aLkpwNrsfLXVS69NE3n6iSO3mU5BneGlw5aWay2P2/
 nJQDY9fYlUHv6LcM5tXyg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:9qXuIOR9lU0=:ZHVDUD373e8hd5+1GJE8lo
 2dHDA8ZwfL4dk+srccTkSsTK051IUcicZ/CiHe/oDCTqwcpnCA0SnShonzkv/ZZd8/ojmWR23
 ujnb2HMe93lROKNdIPU21mEMnS5rmM+E+v1qxda0YrlaCzTsdbTKRmRlHhgKyUAnqedXAPK/U
 Hw2ddb/80itKHL24CEKklsxClRwx/2yPReHup4fGfWUjty9Kyidm1ZH/Khr5xxR5wK5+CvSZq
 kimvvmf1KJesWFtZRi/SqdwvXmOr7PA71v2HcITZEIygE9YMS0KJ7s7UcGaU9bJCk5Bo6o6G8
 cPmVkYgLYV4CF0m0BPb7cQ/Gxo474NM6mSLKrJTuxv77/L1470Kcw8JdvsZFvvYu1o3gHivTJ
 O3USYW8qUsriGoyW1FzzQ2yhmYHAhdcBBcDzmwMXXcGQCgkuMyPLfDYqqlt37nS5dR7KmS0n+
 FQmYRsbb2MO9vjjc632qQkRerIF7yuBfsJwlcfcrJz6jcf/RCdvcd0Veb4ftLcZ19JSSlxyk6
 DH25q/inqg6crbbwvjRkWsCSLz1CF2Dts0qH5y8dhm3xfoWnAg1DD8IKXbJ3Rrbfovf1sGP/c
 5wSUPlcb6h6WYcPO3flIa7Jq4gkPyqnKe7X3mQhBj5deXvyDXJqeGevLndOVj4AZa6nVN5eMv
 8vCAYZq3IjxtOpUgSwSIT22Aj4yfKABPjxgpwB3ZTyhctVCPBs45Ir5P88KP0jHl3S1hknLX1
 BP1XcYvJsDLH2b/Deo3eu5zJABAJqRAeE3x8Jjy7wdTN8BIviRG+Co10w27wvvbJRzis6hpoY
 SkLP+IQp3xwC5byel+sw23L6lul9rSn56zAQ/qHYeSYodZlI3g=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.135 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Tue, Apr 26, 2022 at 6:42 PM Alexander Potapenko <glider@google.com> wrote:
> @@ -99,11 +100,13 @@ extern int __get_user_bad(void);
>         int __ret_gu;                                                   \
>         register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);            \
>         __chk_user_ptr(ptr);                                            \
> +       instrument_copy_from_user_before((void *)&(x), ptr, sizeof(*(ptr))); \
>         asm volatile("call __" #fn "_%P4"                               \
>                      : "=a" (__ret_gu), "=r" (__val_gu),                \
>                         ASM_CALL_CONSTRAINT                             \
>                      : "0" (ptr), "i" (sizeof(*(ptr))));                \
>         (x) = (__force __typeof__(*(ptr))) __val_gu;                    \
> +       instrument_copy_from_user_after((void *)&(x), ptr, sizeof(*(ptr)), 0); \

Isn't "ptr" the original pointer here? I think what happened with the
reported warning is that you get one output line for every instance this
is used in. There should probably be a

      __auto_type __ptr = (ptr);

at the beginning of the macro to ensure that 'ptr' is only evaluated once.

>>> arch/x86/kernel/signal.c:360:9: sparse: sparse: incorrect type in argument 1 (different address spaces) @@     expected void [noderef] __user *to @@     got unsigned long long [usertype] * @@

It would also make sense to add the missing __user annotation in this line, but
I suspect there are others like it in drivers.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2eDDAAQ8RiQi0B%2BJk4KvGeMk%2Bpe78RB%2BbB9qwTTyhuag%40mail.gmail.com.
