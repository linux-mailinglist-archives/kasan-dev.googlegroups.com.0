Return-Path: <kasan-dev+bncBCMIZB7QWENRBTM37OKQMGQEHDNRLIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0812C563179
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 12:34:54 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf977321lfj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 03:34:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656671693; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzpsGH8BEUNHO1l65QRm8W3JUvo6nh4tmfctkqIuTW41ZDVVgkHDdouMiS69WEu94D
         mFVS1wQfSejlmOdeK5d9aoKzo1Emmxm5FjNbK25larXfVXgrr7JX+GKy2kuRAOszMxrn
         Wh6+dtJcF6mtFgO6ek5EkXjSnF3XcqA9LJZdWJqJcdv0zj2fpQCC631141hy7qrD3KoT
         Fre5saVKJXkwPZsHm++3F66jwI5FCFJSuXNOV4equxcI3X4vkbL/gZ/unI3l18TLKF/P
         hMZzXZXfxJ2q/nqjlrKy39mUi8qWhNYNni+CmrJvh0vAAXPB5Z27BtZEpSumLuF4Yaz0
         T3Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ew2wgBKUDUxUExm45BWt/XYdD+DGoqO3g78i4rp+luQ=;
        b=hzslWSD0NHHi35Ur4u6DY9i9px3efgawMElpKm9IBMFd5OVnwypKxWWIGBBnMU64qN
         muSkoljw4Dp+ZV4VENB/54lAd1xWLNzevxXr58tQITZ+tX4NHUU2DqVD8PqNBv6rr/ar
         AOLc//7aa/NCsEwywEN7TXzyJ868aKhNmd+TbR9ubcqnjaRN3Y+AlKogA0+8DB9fnbnh
         iViu+jYO0ttJJegKY1Na53tEBYWPNAjq3B6eaIcgNmETgmpz4uPQb9xkzkVcRjOsNlEu
         UobEPNNPQyKNvufhsYoXyJawEzdkCJ3TpUZFMn43oKA6qlzZ/q25U95+vH90LL4OpmK/
         dPhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hOWskhaT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ew2wgBKUDUxUExm45BWt/XYdD+DGoqO3g78i4rp+luQ=;
        b=NvP8giC4oWgJquhVCoTjEmOe4I8CBiaMGFIeWzkQEeJXIebupfHELs6HhsRU8EjMqc
         KlghbB/4cS6gP5VuYs1JaD5hhUMul0pm5HGLzh9rN3YxkWCSNOEMWo5Za9A1EDYDv1J7
         8+HmAwrKB2rWVFwuwV77xLTS/hvuZYpYWaqtQs3HkG6SmPhaL/dLm4UpUJ8coiDJL9k5
         Im6QoPCfNVXxuH1PemEPywKGqqgD4p2kTlKfSy38ZgaJpgov2YtDuQqm9Tcwt3fz+0+j
         uzJ2+Xxxh+fppwzKTeB9DcxpKCKeECZbKe/9PDc0F4MWWwpVTQjn7VQbd2BPDXha20BC
         SPMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ew2wgBKUDUxUExm45BWt/XYdD+DGoqO3g78i4rp+luQ=;
        b=wNj9BcVl3YrPGAiJdBjA2zCy2DNOotTRn1WPi2di87U3p+lLonuUoLiIWf8lh+dXNK
         JChy97xTYcD4GUEo9RFuxGihRReB3/H/6MxezYRKEbq7AynuMUy1NsZ+Pp7QyJk4h66Y
         hhaHE+OdUtz/VWSxWP+8c9JyjfcZ7NQL/KDl0hMazW9yWJmg1gl2nBol+vJI/Wlus+9Z
         0VRSZS7AXH0p0j5Q+rhFIANItckYfmyL3UYPXRetTrDs0k4a0QixKdwEt53M4dcrAlyf
         7nJ89m/6WHAK/PvMMqS082CBh2VtiUI5Nh3Uha/WyOItzdrgUE0R0FzI75jouFsjEEDq
         nXdw==
X-Gm-Message-State: AJIora/luzF2UXs+EHmeoCHEUoCY2wNfI/xzCPeS0vyTaSr9jnLLbIqS
	vSmQkJ4Dy+5d6Bkkz3p6wp8=
X-Google-Smtp-Source: AGRyM1vTAE7MTKnWFs8XYWmD4ByNcZNVCm6MHQtOwoDtBJ1vNmiKSqD8/C/4xuW93XbtHaZeOAKuEw==
X-Received: by 2002:a05:6512:224b:b0:47f:68cf:e697 with SMTP id i11-20020a056512224b00b0047f68cfe697mr9584932lfu.233.1656671693463;
        Fri, 01 Jul 2022 03:34:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls505381lfn.2.gmail;
 Fri, 01 Jul 2022 03:34:52 -0700 (PDT)
X-Received: by 2002:a05:6512:3e1b:b0:481:23e:2c17 with SMTP id i27-20020a0565123e1b00b00481023e2c17mr8545752lfv.444.1656671692318;
        Fri, 01 Jul 2022 03:34:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656671692; cv=none;
        d=google.com; s=arc-20160816;
        b=sQQv9TH3XjBCUU/aFc86DIJhbYIR/Ik4YekKccZ0KyHOO7gNelt7OOcOEL0U1WYH+X
         y1ANP4A3KatrQLdX8VsdJEp9Ry7e5PKNTUTwkPmt+4iLdxqZbC2EqT++G25KneTj0MWc
         pV9dXdW2m3DU6nXsqWSxTViJgDZAoPmffGb1rTKR5ZcEJETkFidamucwzcQL+bhWTDrL
         qowiVXwP2QGJ1QoeYHrk0WhXD3yzQ8QTful8PAOIiB3L+qDZQjS9AUiUyz1sF7Jivbgj
         AACiV9BVdLfkQH5UjZGTnSxXngwtnKSllvqIWfCihxzJzFiZ47lSE8JxA9kK894vcN7g
         2B1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r9tKEj16d5tR2G+qnALq6e2umf1wAchyZTQfWhHn/lQ=;
        b=GL1ISyXmI96lIVI9rVI3ofw+nmsmFnQFdmzOayDbSNXPiLNqOhWNp/u9L4hnzmMZ7u
         k/9EP/EL4xGS575DW968qGnVHQgHDUyeVOKq+Ni4+YwqmM9EKAwVP635lH2pYWrgJokX
         FbTX7rKPv48whhQDQLQfWJ72dXVQqU84bU/8puBcMUtXs67WX/pboTJgQw3hsWNSw3R/
         YgQv8t70MpXLYtnnrh1SiLE+5PaeAOdGjnyOHt4mq+65D4JTfUlNw17rkiE0GVOUqfuE
         dhkfq91nSPnqPvDJR5XZz+RwxweJ8ZoWy6Y2xwB0Oob1OTmcRcCYBwag+au2aU/56N9h
         RBcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hOWskhaT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id t28-20020a05651c205c00b00258ed232ee9si824339ljo.8.2022.07.01.03.34.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 03:34:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id t19so2476250lfl.5
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 03:34:52 -0700 (PDT)
X-Received: by 2002:a05:6512:10c3:b0:47f:a97e:35c with SMTP id
 k3-20020a05651210c300b0047fa97e035cmr8666355lfg.417.1656671686899; Fri, 01
 Jul 2022 03:34:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220630080834.2742777-1-davidgow@google.com> <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
 <20220630125434.GA20153@axis.com> <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
 <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com>
 <20220701091653.GA7009@axis.com> <CABVgOSnEEWEe16O4YsyuiWttffdAAbkpuXehefGEEeYvjPqVkA@mail.gmail.com>
 <20220701100441.GA8082@axis.com>
In-Reply-To: <20220701100441.GA8082@axis.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Jul 2022 12:34:35 +0200
Message-ID: <CACT4Y+ZvPDLR_e2VR8+hKZ+fnLo9_KkTTgUMqqM1kaoo0kW-fA@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: David Gow <davidgow@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Johannes Berg <johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hOWskhaT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 1 Jul 2022 at 12:04, Vincent Whitchurch
<vincent.whitchurch@axis.com> wrote:
> > <vincent.whitchurch@axis.com> wrote:
> > > On Fri, Jul 01, 2022 at 11:08:27AM +0200, David Gow wrote:
> > > > On Thu, Jun 30, 2022 at 9:29 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > > > > Stack trace collection code might trigger KASAN splats when walking
> > > > > stack frames, but this can be resolved by using unchecked accesses.
> > > > > The main reason to disable instrumentation here is for performance
> > > > > reasons, see the upcoming patch for arm64 [1] for some details.
> > > > >
> > > > > [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11
> > > >
> > > > Ah -- that does it! Using READ_ONCE_NOCHECK() in dump_trace() gets rid
> > > > of the nasty recursive KASAN failures we were getting in the tests.
> > > >
> > > > I'll send out v5 with those files instrumented again.
> > >
> > > Hmm, do we really want that?  In the patch Andrey linked to above he
> > > removed the READ_ONCE_NOCHECK() and added the KASAN_SANITIZE on the
> > > corresponding files for arm64, just like it's already the case in this
> > > patch for UML.
> >
> > Personally, I'm okay with the performance overhead so far: in my tests
> > with a collection of ~350 KUnit tests, the total difference in runtime
> > was about ~.2 seconds, and was within the margin of error caused by
> > fluctuations in the compilation time.
> >
> > As an example, without the stacktrace code instrumented:
> > [17:36:50] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
> > Skipped: 47, Errors: 0
> > [17:36:50] Elapsed time: 15.114s total, 0.003s configuring, 8.518s
> > building, 6.433s running
> >
> > versus with it instrumented:
> > [17:35:40] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
> > Skipped: 47, Errors: 0
> > [17:35:40] Elapsed time: 15.497s total, 0.003s configuring, 8.691s
> > building, 6.640s running
>
> OK, good to know.
>
> > That being said, I'm okay with disabling it again and adding a comment
> > if it's slow enough in some other usecase to cause problems (or even
> > just be annoying). That could either be done in a v6 of this patchset,
> > or a follow-up patch, depending on what people would prefer. But I'd
> > not have a problem with leaving it instrumented for now.
>
> I don't have any strong opinion either way either, so you don't have to
> change it back on my account.  Thanks.

I would consider using READ_ONCE_NOCHECK() by default. And then
switching to KASAN_SANITIZE:=n only if there is a real reason for
that. Disabling instrumentation of any part of the kernel makes things
faster, but at the same time we are losing checking coverage.
For arm it was done for a very specific reason related to performance.
While UML can be considered more test-oriented rather than
production-oriented.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZvPDLR_e2VR8%2BhKZ%2BfnLo9_KkTTgUMqqM1kaoo0kW-fA%40mail.gmail.com.
