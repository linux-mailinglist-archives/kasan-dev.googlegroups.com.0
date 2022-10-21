Return-Path: <kasan-dev+bncBD6ZP2WSRIFRBM75ZCNAMGQEO7ETY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4747260702D
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 08:39:48 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id az11-20020a05600c600b00b003c6e3d4d5b1sf1025872wmb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 23:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666334387; cv=pass;
        d=google.com; s=arc-20160816;
        b=mluS6BIwb6azyUzumblRA5Zsqu7w89n4iV8Iy67s+75UaV9epC0zgcNU+TzVMC+aCJ
         CqTslRwTHWmxQJIw4JBcnQevS8gAwp+ukBnt8mTHFOXsrSE4nuEuZLjv3SKgO7GMUNqn
         R7wFRAnmBHKvzDzzX76XDgLnH1QkM0IA/WSfdGJq89d5KKt21EGkXzmmkJzPC0pRgR6l
         QvUABiHWiksdGHkzDkCQSJ8kz8nf2J2WuB+dC/KNr6/mN92MhENw7D1i6UzWi4U8iPvW
         J8IOgJ1Y76qsB7exUCLzj0WuMX5XKtRfHyh1IjIEHO/x0E/CnBkpaIpyVOt1k746AwMm
         WAhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=HXgnsRwLDSgOvlqp4L0lMVx2JMLjhx8PFcrgB25BcPU=;
        b=neC3srLTT+QL+41/ilkg0N3Y80Ss3Z0ppHEUxUbyj40r1xYSBdUTHFgt/9hHQYhNCH
         dr5Ompl6/mgQWIYqUHoBQj4H/8OU6+5iHyoS2tm7V+PZgaGTZytqNNrc3FyvKRuUbEMC
         /qjwG+ysrUGgSYiE9c7mjgpz/hSRUmamavMXZM/37a+t9c5ZgXhbkVK5EeEJoz2NqsBF
         DR3Ar2LJuTG2aopkD2C2sKJgIoYZOd9tVhj7f2KT41beRMc3g8lpNcY3hY4iNfupMoGx
         oXpC27Y8gSWCT5Yevis3vGwYSDVahAgr+1utFgHbffaQck2fIDem6eeoXpHSZ3r67/dx
         bv3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EeuUWgJR;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HXgnsRwLDSgOvlqp4L0lMVx2JMLjhx8PFcrgB25BcPU=;
        b=k6nhMvLFG32ZlGzQhoxVK2ie6OYhl3oqG1RfHXRNzKs+1LNRRX2n1U1ZPB100U/qLw
         gzk9sWg7KFpSaPMm2WhiGm1Sls+0hBOYgMqXoDDDTp+GloH1HfLNg0Tr/mLjOXwj9YMh
         xn65zHoaxYmIHkSlZRdgySXvKjtXok8Ca0gFK+V5e98kK+cgoenFdln8qtvi4wlcS7ZM
         FKmixPu48aOq7E/8dRhKIzO55MYvN/0O63QOIWsF4wEnLvnP7cxjjX6p7UEIDXhSGlzk
         +R/tTSfRZPYzX4KKI8MmsycQ8YSPP/ESXjaDt5BJm9qrLGDioGD51zTtvK2/pda1imX2
         m5Jw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HXgnsRwLDSgOvlqp4L0lMVx2JMLjhx8PFcrgB25BcPU=;
        b=JHMOo6gijAp6C53lKxNg/D4Vl4niMdbXivZTWrB7VltOQsIytANLAuB3tACE+aZl04
         TR611ZgNyU5qBOAZRxi7q96zw7pKnf5OK5wQ/t0xO3t3VFfCsxKxfd+Ny6nczSMohwtc
         dELHmvUuA5oPr7qRceMRuL05cAN9XH+zpkXLi7Flq/Gtl1cWc5M6Zn1XwPbDaPx37iJD
         wivdC9zWak7Wga28nom4z128h7JGqFCdxaGBk5frNnXCsmsgBxYXJRkaLWucPfwBxatb
         ib/ag5f/ub6LPRectANcl5y7z/FB90XJU7B/9IcWhN/aLjtAf1RBWHHXgRM4r99wMVPi
         DXNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HXgnsRwLDSgOvlqp4L0lMVx2JMLjhx8PFcrgB25BcPU=;
        b=SEryArqIfW+GOpaJPg+RAWvEDa0pVHi5qBQOciOppckkWPaw9qCxACywaw+tuO6dp/
         f8RTCAzdeFcI+Sg6mZxsipSpgqmXIBK/GR1Emm/HwY90LiQntP4AAg6fr8+oKuXDVA5S
         rMHHkj/BIPChGDv6XUtIscqHJ08vX8iaasLqBzPCm3HrTAA1BxdkzTFWi3UEUbZAEKZK
         M7MrRfH9S5FmK5M9kFG/lZcldvWE83z165tSxXIJSs9i0oZ2ZuCuicIkFw18jJePfD+o
         mOOcDO83pWdqGXRJ9aDWmrZ8BKniIDA8x3bneGExazFOylPIudZTH3TYfkWm/3W5YAAs
         QJWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2BJXZbT9dV0IknVnY8N/tDOwMR+Htabf9EHAKaXGoB8GUD8c4E
	1nlEzMSmCeoPQWbzTgSCN9k=
X-Google-Smtp-Source: AMsMyM7lc5b+/hCQKvqE5KdLePukvrn6uRHRWmbSGJwqhTQ10fOrXzN/flDrDw0BKHG3bARQBRZBlQ==
X-Received: by 2002:a05:600c:4449:b0:3c6:fb65:2463 with SMTP id v9-20020a05600c444900b003c6fb652463mr11876587wmn.128.1666334387526;
        Thu, 20 Oct 2022 23:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2316:b0:3c6:efd6:9cd8 with SMTP id
 22-20020a05600c231600b003c6efd69cd8ls768454wmo.0.-pod-control-gmail; Thu, 20
 Oct 2022 23:39:46 -0700 (PDT)
X-Received: by 2002:a7b:c341:0:b0:3c4:552d:2ea7 with SMTP id l1-20020a7bc341000000b003c4552d2ea7mr12101680wmj.82.1666334386590;
        Thu, 20 Oct 2022 23:39:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666334386; cv=none;
        d=google.com; s=arc-20160816;
        b=lJP+uOiDxFlfGpy1hHyiaE9aXkv4x4a+9c+Pc8STxzFTgFFpoVAZa17byQcE1S7/UM
         vz/jjfjvnCZ5O5u9Pvl4djdNBRMxHBZJYfnf9Stzf5gtd/txLOJo+Xbe94+okESH7+x4
         ca6wL624fMBzCxIRKHB0Ed3HYvY0c9WpfUsqDRuBnWrwCEGyfQKBtpAyxJRHYPFavxNN
         Co7/mxWwdf+lltxIT5YnXY7TjHYjRAw7oA9+/Q08E5RmPYLqOxSIMYeYtvAa5ju41KHR
         oBVD1aWY2qb8z5pNNGHYE1c/Ugi6aHM8rCp8yul7saUFztcSEj7rlGpTED6EK0ESY7wu
         z1GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=FFzVqav4ytL2f0CsiBF+eInTfMA8Iy0X1Q8WlCib4/Q=;
        b=xS824xtqOTMfY9EuPDE4SG/pZHDlqMg8DeSem+6KMJrIBK2j1zJdIG2/43rpQl7IV1
         ZW9xfeixNv8prK/u+C0XTpmxUFZmB2gQ0yVFQBJvMKNik+xmN2B43iRpZitE4XDH0pHg
         TxrXXxbr/VWoUA+jgdaDi4qTy0qly8gwCRS+bH6lRweDfl0itUQYsx8oggQFfHZjzUEA
         +RsWcaJmnwaTWPskrljEZkylzu09hB8GUP6EO26jHG10P+/nzqqEoxPQ7HTVOe5UKuMN
         JtIfSCf6EFjm5jyAwJMcxAOwD8nfm0AtrIm8dpSt2RF3q5U+4B391YKw3vz7XQwznCeR
         aIGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EeuUWgJR;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id b4-20020a05600003c400b0022e3df50e0bsi724217wrg.2.2022.10.20.23.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Oct 2022 23:39:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id a6so2422635ljq.5
        for <kasan-dev@googlegroups.com>; Thu, 20 Oct 2022 23:39:46 -0700 (PDT)
X-Received: by 2002:a2e:9652:0:b0:276:34ad:75c0 with SMTP id
 z18-20020a2e9652000000b0027634ad75c0mr398362ljh.59.1666334386089; Thu, 20 Oct
 2022 23:39:46 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Thu, 20 Oct 2022
 23:39:44 -0700 (PDT)
In-Reply-To: <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com> <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Fri, 21 Oct 2022 14:39:44 +0800
Message-ID: <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EeuUWgJR;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

PerfTop:    8253 irqs/sec  kernel:75.3%  exact: 100.0% lost: 0/0 drop:
0/17899 [4000Hz cycles],  (all, 8 CPUs)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    14.87%  [kernel]              [k] 0xffffffff941d1f37
     6.71%  [kernel]              [k] 0xffffffff942016cf

what is 0xffffffff941d1f37?

2022-10-21 14:16 GMT+08:00, Marco Elver <elver@google.com>:
> On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com> wrote:
>>
>> How to use perf tool?
>
> The simplest would be to try just "perf top" - and see which kernel
> functions consume most CPU cycles. I would suggest you compare both
> kernels, and see if you can spot a function which uses more cycles% in
> the problematic kernel.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOzgRdZsNWRHOUUksiOhGfC7XDc%2BQs2TNKtXQyzm2xj4to%2BY%3DQ%40mail.gmail.com.
