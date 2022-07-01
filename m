Return-Path: <kasan-dev+bncBD653A6W2MGBBO4N7OKQMGQEDCOJ46Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6934D5630ED
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 12:04:44 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id g3-20020a2e9cc3000000b00253cc2b5ab5sf334981ljj.19
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 03:04:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656669884; cv=pass;
        d=google.com; s=arc-20160816;
        b=xjlCMUVoauXaPOU5zK/MSMLvv2TIgz7GSxN8LQpirfJBBwX9pX7RWCehY+O/7K+yxP
         F0LBOuxuKXeXaCKUPipZgucAV7d68qd2uAS4yOu3+gsKKrRrUo497cPYJDeDyQWSSsqa
         Jw7Zb48mH3F+DNV1A83FQhwa6bdc3NvUNImI5gRntD5kWSYjAh6N5e36ALetx20QjeEU
         zzEKwS/io8Gw3wlRMyteyT5JMBcqkPLbfSbkLUTpcHPfU7J8niP0U9IyDAwHQ6H8vvJu
         91bDh4N2+u9qyN+KLooI+kmv0FcbQrKvrDjFmKosGGZ7cf/I4WtBZWA+EA1s8KpSi6m+
         PQ9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=xq0t0eKuOgHdlT+nzyICP6pZ4kP3MqA7jeK7DrxxK9U=;
        b=rEk16nxAZA33GhMphRd6qbjESqdBvaTgR7au13wCe/6369oZRJM2/hcjZpRAG/SXkC
         4ywHIsTFvu46hVJUmxZ5752iwFAIexrxrbqfRawjJ1DHZfbcF+3JMsvZpB8r2PCbwA/9
         wlBRAoOt/SYifvrL00ZRVfEXh4pEE7bftwftTmBPLRTxZD7rrHPo/huzUwB4lgSnAHEH
         hByRebCxyY6G246slN4n+YQEldfVToA+DWU7Yt49RGTmzE9puNr1lHE18QOspNJRdBXf
         yTR36GodJg3DlAnOhSwDjsPFuVzKakxsp7zyopyLhiuVqbt3HCNdVlR0ZZhI+zR+fvGY
         49uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b="IIB/FNog";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xq0t0eKuOgHdlT+nzyICP6pZ4kP3MqA7jeK7DrxxK9U=;
        b=IgBkbMNZtItf4coc/cW1LS+k4fLluLNQ0bZBYMI9Lj1MaoAcQr5wDYrz9KVrtCYZK0
         colemI0IN1GibeADWdIsW9C6wYjS00i7o7E3S0CLO9JLiXUXj6n1idwOE8g6Kjgp9mXO
         2LkjTA9S9Xb6x+vtdT0FwAOuxGbvMXr7z5vd9Ig2JVRaGyd0pFnoQP96ejmDou5CUM5i
         ZZsyK7QYn4rM0VKxZa9jCy+Bq1wnrZOpiHEMqBb37uaHqqWuRyU7gaKqMXcMEcoABr7U
         8Ogyq/6Mjh9wjYP+T8EPgPNoor7DXW2fqDpPQp3O47ZDFVIo3pF2KTF7eaYEQaQShl9f
         9NuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xq0t0eKuOgHdlT+nzyICP6pZ4kP3MqA7jeK7DrxxK9U=;
        b=cQ3wqkfWMFueIGRYg+6RzUXM0BCjyjKkNqES5X1237xmkk5p/IXFuhiWx6ljJC0nri
         FMTziso7FX1m4vSijHqEG4xyf9mHXCDR06kc5tl4VfDJSq2Xn7a597VnjNJg7X/8c+Rl
         H+4FCE9FdnVsSMy8lgqrLj1b4fVgUSkP2WYNTodg2b1Qz/yJHdZiguwEan13Ym/SuoCZ
         AcpMcVCmoQN8w/vHITlVobqfltk/rq+ttxI5yD0GnOA6dZsojtTnGlark2m591sD6x1U
         CYjq/aB1RJjrldUHx1Knu2ZX3n1wAJC4plnoG1el5qg+A/GmC8fWatdw67574oVoh22R
         TKGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9bypeM4aRxFjb5ubHBi5sEMiYdjfv5/hEA1RCDwlRICQ38XapU
	zQm1OhCOHR3258f3DyplM84=
X-Google-Smtp-Source: AGRyM1tW04rgKACewCQSxanKTVDQja94r7VLje2CXBUlKezWTtidpLI+jO4KM3nnL/+1rFzvCu081w==
X-Received: by 2002:a05:6512:3d1a:b0:47f:79df:2ea8 with SMTP id d26-20020a0565123d1a00b0047f79df2ea8mr9569732lfv.610.1656669883693;
        Fri, 01 Jul 2022 03:04:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls454239lfb.1.gmail; Fri, 01 Jul 2022
 03:04:42 -0700 (PDT)
X-Received: by 2002:a05:6512:3c4:b0:47f:ab72:563e with SMTP id w4-20020a05651203c400b0047fab72563emr8567353lfp.506.1656669882553;
        Fri, 01 Jul 2022 03:04:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656669882; cv=none;
        d=google.com; s=arc-20160816;
        b=SkpxNQLB8xfm4pean7uiEQNIoWr32oDXaReZ+fWjNIBGko6cAzrKSxYW/4A+1Kpc0C
         aiPPeGkcvESOUuEE2cFfm2j0fPcxLEZfdCHsey2J2wrysPCONdmYNGbirw1048ZRptLr
         2ei106L4J8+VnQlNf34rxFBDrcF+Dv8OvGLMbHMyJ6l9dCvLwg4+EXCvqc30Z/oxJoMU
         G2NDx1ad0yaUD/+6mdrInRxLBluOu4UCAnnvTlDDsGFvRMWuP8zmeHEeYMTKucJsrD2k
         yzf1Zzh4zawqUry+lNcWbyp4ui4od4U5EuEaSEk0BY6Lx+8D24aYUaIK14UK1jtbvvwW
         TAbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C9yKLAcuZ5hnkYBCpoRQx1zMhVYu01vnHM+Lplb5HMc=;
        b=XRU8ECha5bKTQ5Wr0pvaSs8XT60WOb/LvXfIo3j+niSkdTv9++h2dg9qca7dbCbb52
         g/awbd9BTWIks0t2NkxJgCb6msL/aE2cdcDLx60a0SlQ6R3eVNA33BagFJq9+NfV2mZd
         bS1uP2RRNKMLIY8L37uq8kPH26WwiGebdG6i3ATek/xhEt93ay7MwC6DFDBWTz57VD4+
         kdWNuHiI4OVS74Lmn3qot3qBGJENlpWFGR7lV7E6DKqOu20sWFj4L+hKgPxKrz1bdByt
         fG7H8NF45eXFZkWMsUP4ybRUCrN+RfaG5dv5pMfphoO+KAhNZ4101vaTpBVRx8dbhipJ
         nFhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b="IIB/FNog";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp1.axis.com (smtp1.axis.com. [195.60.68.17])
        by gmr-mx.google.com with ESMTPS id h6-20020a05651c124600b0025a45f568e9si808215ljh.0.2022.07.01.03.04.42
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Jul 2022 03:04:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.17 as permitted sender) client-ip=195.60.68.17;
Date: Fri, 1 Jul 2022 12:04:41 +0200
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
To: David Gow <davidgow@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Johannes Berg <johannes@sipsolutions.net>, Patricia
 Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, Richard
 Weinberger <richard@nod.at>, "anton.ivanov@cambridgegreys.com"
	<anton.ivanov@cambridgegreys.com>, Brendan Higgins
	<brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, "linux-um@lists.infradead.org"
	<linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, Daniel
 Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
Message-ID: <20220701100441.GA8082@axis.com>
References: <20220630080834.2742777-1-davidgow@google.com>
 <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
 <20220630125434.GA20153@axis.com>
 <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
 <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com>
 <20220701091653.GA7009@axis.com>
 <CABVgOSnEEWEe16O4YsyuiWttffdAAbkpuXehefGEEeYvjPqVkA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABVgOSnEEWEe16O4YsyuiWttffdAAbkpuXehefGEEeYvjPqVkA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b="IIB/FNog";
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.17 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

On Fri, Jul 01, 2022 at 05:43:26PM +0800, David Gow wrote:
> On Fri, Jul 1, 2022 at 5:16 PM Vincent Whitchurch
> <vincent.whitchurch@axis.com> wrote:
> > On Fri, Jul 01, 2022 at 11:08:27AM +0200, David Gow wrote:
> > > On Thu, Jun 30, 2022 at 9:29 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > > > Stack trace collection code might trigger KASAN splats when walking
> > > > stack frames, but this can be resolved by using unchecked accesses.
> > > > The main reason to disable instrumentation here is for performance
> > > > reasons, see the upcoming patch for arm64 [1] for some details.
> > > >
> > > > [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11
> > >
> > > Ah -- that does it! Using READ_ONCE_NOCHECK() in dump_trace() gets rid
> > > of the nasty recursive KASAN failures we were getting in the tests.
> > >
> > > I'll send out v5 with those files instrumented again.
> >
> > Hmm, do we really want that?  In the patch Andrey linked to above he
> > removed the READ_ONCE_NOCHECK() and added the KASAN_SANITIZE on the
> > corresponding files for arm64, just like it's already the case in this
> > patch for UML.
> 
> Personally, I'm okay with the performance overhead so far: in my tests
> with a collection of ~350 KUnit tests, the total difference in runtime
> was about ~.2 seconds, and was within the margin of error caused by
> fluctuations in the compilation time.
> 
> As an example, without the stacktrace code instrumented:
> [17:36:50] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
> Skipped: 47, Errors: 0
> [17:36:50] Elapsed time: 15.114s total, 0.003s configuring, 8.518s
> building, 6.433s running
> 
> versus with it instrumented:
> [17:35:40] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
> Skipped: 47, Errors: 0
> [17:35:40] Elapsed time: 15.497s total, 0.003s configuring, 8.691s
> building, 6.640s running

OK, good to know.

> That being said, I'm okay with disabling it again and adding a comment
> if it's slow enough in some other usecase to cause problems (or even
> just be annoying). That could either be done in a v6 of this patchset,
> or a follow-up patch, depending on what people would prefer. But I'd
> not have a problem with leaving it instrumented for now.

I don't have any strong opinion either way either, so you don't have to
change it back on my account.  Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701100441.GA8082%40axis.com.
