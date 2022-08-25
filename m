Return-Path: <kasan-dev+bncBD4LX4523YGBBSXLT6MAMGQE4ZLLXSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 256685A1C27
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 00:21:01 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id q60-20020a17090a17c200b001fbc6ba91bbsf613284pja.4
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 15:21:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661466059; cv=pass;
        d=google.com; s=arc-20160816;
        b=ES76CRzFXof9bx7rEFbED7Q74lzlQvbILtXQaeqK6L7w4OHtxoRsz+6gjDQ162pxzi
         CdUntBkE1P0VHVtm0v5VuQ616xCXGV/ecbDGgKPtNHBQmgn6mWB5rAPiG9+1pztfQkxi
         AuGHqW+vHEG30Ioorg6iuNTO2Pb7VmeDXnfuJFYUyvX6fFqL7El0k1W3WUGL1ydEhPN7
         MeShBEqgcidwlsXfcegEIDaY63hrAWJxmfiBlQHdKILM9096i8OAC5j6tI7GSwIp+ncc
         +KpAq49ZvWHsWznsUR6kZ2McFmEuc83SVThHRjTgJ/CVZ3jAyaLKA7lOHZLX9LO2Ypzg
         JUfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uOzPWN6Qgtm2mHHTrY+0brBpZe4Fgqap69XpuF8OFGc=;
        b=nSPaCURoJCD5CK6N260sRNgSaKNk1ExzlIiSfOwaYf/ptuNql1ME+ozgg7dfq/2XBu
         QFCiRedsTXAiFgqIM9lZLmsswZhTMpc5JRKTdH1FzVrOKH5XFeCPfVsfmNr3NGOfcM2x
         o8z74hD22TKwPiR9J0glo1eq6EMCx1k1DJHkCgn2LHdFR1SRSNWFAV4ocDsSO4EU7Jy+
         hpwClRLZEJ1Ko/1txyR/ol5NBJguM/Fcg0/jOxIZzX61l/Fe8yelrgDkeFZKc184WH0q
         h8ePIMLDehHLPkhTwn/9CZ90VZTHmx5mTtm1Tn5sn+E/gy3FcytNfKhABkLK9SOsZ/ux
         /lHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc;
        bh=uOzPWN6Qgtm2mHHTrY+0brBpZe4Fgqap69XpuF8OFGc=;
        b=cBmcng9BmDDFp0rS/B0R9Gs7yHpspq2QBqdbxjhosjbvOYhgloxp9hJFhKwqdKz4Fo
         vSUNeEtfugUbIke8rU9aLrxarvog6/A71LsdQ/FgyJDWWQ0xnMSKVXgLMmLNF8OhuZI1
         rBHzhT125mJQ2w4af2dmk4IMX++TXTGwwuW/iVt3hq9J8ZuNLLo2iiex5cKFoboIwlKS
         VxIfTJXL5rqPEuw6EokgG3t8aT+o4z9gbFbTTt7bk7XDQO2IwDvxQt2E1gEEQkojsf1b
         K1qxHom84b3ys4nmKBTtqZW/wcIs1nDUoUaki35j37zGhY33aLJXLrqRoqeARmBBzExF
         fRnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=uOzPWN6Qgtm2mHHTrY+0brBpZe4Fgqap69XpuF8OFGc=;
        b=ial5VY0iS2W7zxrJ83KFGKjeQe+1ioItWdVKVy4hyOsu34fHmWRV/1gTKp02WtQi9N
         TTGjXnD1NpsDWDCY6IJbgHlvbyBiLxWXqVOdQtrw6wNzWSStuXcF1Jjd1SfXzqkm+nbc
         ik5KIBYWOk2t7SDj6hv3dJRWY6fdBggR3G8D7JNWpDx7+PSqXhjdWmX59vsV7HdSnWUH
         Wl28xOWkHcCXqtnb2+xKAzivm0/ai+ZzYFHAhYUycf96IJgGF/+QPWeUvdEhXsM6ArSF
         z5h4n8Z5NNqKrL+88yU9tphzL9/QtELc9xIoEFh/cl1h2lcg5LWi2DF4Fxj/+yUdj7ar
         XyEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0l0MINVFvX3i+1J0r5SgPigsc0xhM8hjWaQWCEWp66pE7wuPPD
	S51RGM8jhnRnOFFhnxhofE8=
X-Google-Smtp-Source: AA6agR4Sapyfxhjw9zQcnYmozs2okjUEFWL5ZePPSfLPwKt41jhFBIeYCOSe8CdGPfUMF0Rt/WwKIQ==
X-Received: by 2002:a63:ef0e:0:b0:42a:70e1:ab97 with SMTP id u14-20020a63ef0e000000b0042a70e1ab97mr952136pgh.404.1661466059293;
        Thu, 25 Aug 2022 15:20:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6794:0:b0:41b:203a:51a with SMTP id e20-20020a656794000000b0041b203a051als331378pgr.5.-pod-prod-gmail;
 Thu, 25 Aug 2022 15:20:58 -0700 (PDT)
X-Received: by 2002:a63:e412:0:b0:41d:9c6a:7e with SMTP id a18-20020a63e412000000b0041d9c6a007emr923611pgi.575.1661466057923;
        Thu, 25 Aug 2022 15:20:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661466057; cv=none;
        d=google.com; s=arc-20160816;
        b=zurtsV4IRWEk4LGm17caQaV4fwnFCQ4Wko1sjnigqUvI4zdvXjUdXPjWP1Gx8prC8R
         VmVYTl+JL1ww9sOj0JeHbByE/2a0AndN4Dz5kuSIwxt5pzMlCRfpV8zUklsWLzs9eaV0
         4U3xMEcVnaCsT/R+bGnZcDoWLJON9Dk+JQnOktTFtVKIcGSdhn2NyFkHvBEmzEZAwqjJ
         BS0s/K0sulGsP0YiPx5oH36TCvkSpMvGoglUnQ0Gx9IWPBSJJ2RBUNti0Epp+l/rXSTY
         YTo+9+T42d8HyICoG46sjs80WzHUgmRAL+/JfAVpOQYZDuwQYR4ONqmys+QwIYj9adGj
         oa6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IuiJZCl8wFmtFotjT168+vSrYl8HtzSuyjK+lsHlc/c=;
        b=q4aYu1B6QcrZKOLSZuQhkvTjX8/4m6pk4B2jb7oJvCqFOa4T0eFhIxZdw8rzU0EDdK
         iKq26VALVxg6p+kBzzS3j7CbjK4b5t2YydCr2zGcrHMOe4guC85fPuHZUrE/keleMR5x
         +Z0d5gy1g+MXjMwL4QGivw8oJXXgTckPga491zHoaZriFZ0o1Qsa3ysDw5WEgCjIyV2K
         9LwMR6+VHrTYGM91C2sPtkPjAfTYmpwYPpnMgMS6EGjpTlwOY5yAQu2j0G/8xkWUmmLE
         a+KrnBw+7dM5TvLb1QY4uI4GHsQm+DyCfjViBJbGNCVSlAGn7sIMTR+breRgwDRpS6cb
         pOoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id i137-20020a636d8f000000b0042b329f2ff5si11423pgc.0.2022.08.25.15.20.57
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Aug 2022 15:20:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 27PMDYv8030657;
	Thu, 25 Aug 2022 17:13:34 -0500
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 27PMDWHO030656;
	Thu, 25 Aug 2022 17:13:32 -0500
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 25 Aug 2022 17:13:32 -0500
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
        Matthew Wilcox <willy@infradead.org>,
        Thomas Gleixner <tglx@linutronix.de>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Alexei Starovoitov <ast@kernel.org>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
        Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>,
        Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
        Mark Rutland <mark.rutland@arm.com>,
        "Michael S. Tsirkin" <mst@redhat.com>,
        Pekka Enberg <penberg@kernel.org>,
        Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Vegard Nossum <vegard.nossum@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Linux-Arch <linux-arch@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to write_begin/write_end interface
Message-ID: <20220825221332.GJ25951@gate.crashing.org>
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com> <YsNIjwTw41y0Ij0n@casper.infradead.org> <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com> <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Aug 25, 2022 at 09:33:18AM -0700, Linus Torvalds wrote:
> So you'd most certainly want to know that all incoming arguments are
> actually valid, because otherwise you can't do even some really simple
> and obvious optimziations.

The C11 change was via DR 338, see
<https://www.open-std.org/jtc1/sc22/wg14/www/docs/dr_338.htm>
for more info.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220825221332.GJ25951%40gate.crashing.org.
