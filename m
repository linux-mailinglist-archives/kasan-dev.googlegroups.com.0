Return-Path: <kasan-dev+bncBDZKHAFW3AGBBW7L2SJQMGQEATHOO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E542751DB1C
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 16:51:08 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 21-20020ac24d55000000b00473e75f3331sf1285552lfp.15
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 07:51:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651848668; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVEWZLM1+EwYH11EYpJp/PENBmQjmFCCHem2S15o43zIr1Q+MPqi7nUIsct/3tcxsA
         OzM8W9m9NBm4vdj/GjXAJspb9RHQTlAJGJp3EcPbvqSlUfCQ+a7QD8X2oJsBwBYakAyI
         9vioUicl2AxUsTeefIzP9vNf3nFvj8tGPbZDKJ6kk1dOy4UQ77jr10X5SoyqC6d3aax1
         eTojhxkcR758ELMbrYB1FlhYMyra8FdrY3tVZkP3TKHvkXwulEh5qeIWL6hE/CZAEykd
         IKesJf8+aFmr3NDWN4UzS+w1/+sUE9RvNp1exzfK0GQYuLsEIKgg/CetBGq8GVpJOwPO
         Z9yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=db8DuaKlvtQxNzxOgIwjmIlk/qXpZYfu/yonGcO7MMs=;
        b=CK0i9PcVK9AOJhhMG32LFQZ6OwaskN57ftROps174H+IJTxaedA7u4dqbNc6NDPzTh
         u0Kn92PkAt2IK5SvUlkh0KO7YehRTXpBXHsnzcpR/f0DR1Cz6jNtS+ejTLUF/AOEruNf
         CaBRcG44cxWUK1fYt/elnKjbqaxW1ecidtaF947tWiuXqwWRHnvz9GXV8ATX4MlzFig8
         Y3lWINl+DX7UIUQXGqjsy1X42jIKyah7vDukIV+CCsOAD+PZ6Z9mKc2rXEdyW2i36ZWH
         SfA5q/egrkI7RJ4qcJlWQzdjp/1u4MLxkrbD8ZVc9R8kAJ7CIHyok33X0Hd0t4MLMu/n
         N9vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=qC4Ctuw5;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=db8DuaKlvtQxNzxOgIwjmIlk/qXpZYfu/yonGcO7MMs=;
        b=JgGEW2w1RNG03pfNxH8UItPUCFBXVmGOb7Q366E1zdUqTzPnRY4LzuqrBnTvxUmE5G
         Gl+1ksovLSgEi2Xd5bDze2IR6l1s9mnJWJKeAAD456S8ia6nLekVCXpF9L/3LXU1ig5c
         EfPmHyB1aG1YJh5q/pz3zgGHDJT9IBy0UEp+SMtNSnzv0bitCzIe9BoM62r/6ci9gBPB
         bh3vq8fZ5EpNiTgd3vUd8pKIzyS0tpTsHjJ0ZwWMO7wbu6nfFoG5aDodxAu931uU9AXN
         fyKEulHWC4kxr09JD4oSBCPLwJWgd8/WN9C8aVbH8DrHRbCwyJmE/NsaU2bo7vEZPuS6
         JkQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=db8DuaKlvtQxNzxOgIwjmIlk/qXpZYfu/yonGcO7MMs=;
        b=Am/k4EurJNgpTEB66//9kJM8JcRgo1XGAbMZb+GksleDkasN2PkhLTTUr15T//YCYL
         VSfTjHDOj9wODgUWofSvFhF/wcYe6ftFFiyXzkYyrIBEMGduCrDOIFh0tWlUTeq1YecC
         Pd1GqsEyvDlFHk+Q/bgINPCfBwjyhOcjZk3r0ob00Wr/5mTraVHPqCuO9gt4QOTuuSgq
         M0iVidCSzqaFtMugzB80OaNom7iyvXLkBo+6zLVoWK2AgQmttLKjh90mgIn7xsBTwHZi
         zKri7sAxPr1tLu9SenTGni7ujB4Kc4it3T3XB3nCBkUg/t/0Ezy5BgDqYLqtDkh/Lxif
         FjlQ==
X-Gm-Message-State: AOAM5301b01GaGhqxjPCEdLbtJzPoN5StRZ+CwMcUhne9sMpuIJ++0yD
	oewaLiAQIMcL2dZJH2hcuSo=
X-Google-Smtp-Source: ABdhPJxTAtnWUncV9lnzlgjSbysiJYNhDI5Manbjt3qAskpg8aUhqPyALpAkTh5lpw9VApQRM5ytXA==
X-Received: by 2002:a19:4f56:0:b0:471:f883:7af0 with SMTP id a22-20020a194f56000000b00471f8837af0mr2706793lfk.284.1651848667737;
        Fri, 06 May 2022 07:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:198d:b0:24f:4fa4:38da with SMTP id
 bx13-20020a05651c198d00b0024f4fa438dals1761469ljb.4.gmail; Fri, 06 May 2022
 07:51:06 -0700 (PDT)
X-Received: by 2002:a2e:9943:0:b0:24f:fe4:4326 with SMTP id r3-20020a2e9943000000b0024f0fe44326mr2249031ljj.18.1651848666368;
        Fri, 06 May 2022 07:51:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651848666; cv=none;
        d=google.com; s=arc-20160816;
        b=RhXgZyxUqSmzRaE+pny5Aw0R1nzTK1N4SWgbbF3IZ0VFtrQhevwA4JP4mVgolf+SBr
         1Pv3+buyHP6v5f6JP0OW9elhGJGbGjdiOqb6NJuPsBh3ci+3VSXgKPlqc6UlFzc3i4GF
         1JtoT3ioV0OvV6SJil2/YSMUOIm7l83eXPjswfemJMQ6qlTTLzxb3aKQ2ybQYuHrdV8O
         CT/pDgf0BnCt7PXQAbcX6eFnMaulM1PPYyy/qkU8YfrrtA87ybLEHjHqZbQEDPKhIX8J
         0pxbfiVocygUv5m7TbsxAsU+U2fbSQpL2Z3ohP6o1gR4epFE3iUhfFk53w+E+eeNwkmU
         DzQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2EeefnG5AGR7PlyADAb1h9k2ib8JA+PQGwQZqxKTjr0=;
        b=00Ii1NGzuKmtQjdqe4S2JOV2/0fTShleMQlucnZrtodufpf2hIF58g7tbymHTEH6dV
         pE1Apmuw7b6ABoFryKaCgt/8PKmT5rstT9gwPkw0Fq5diPMM5yojPX6PcU5ISdE0Fiks
         8y46lDWqMmDdenszJVx/53zzTB7moOmNGtGB6Q5JUneCny5Mkje161HdM40bZFwqhtkO
         k09eCbXFzbTCiUlatV5j8RL5TpWPwbCTXcCNHdjsY/FlqjNlPP6JZY9I4muFWXa0+VmB
         SKBSZz1WIf7QBwOSH4834FxC9no3rangc9Ke2x4DJOk2k6dlN4DYd7OApXFJtpTnsmZn
         d/CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=qC4Ctuw5;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id s2-20020a2e81c2000000b0024eee872899si283211ljg.0.2022.05.06.07.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 May 2022 07:51:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 6FD3D1F8DA;
	Fri,  6 May 2022 14:51:05 +0000 (UTC)
Received: from suse.cz (unknown [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 1C6572C142;
	Fri,  6 May 2022 14:51:04 +0000 (UTC)
Date: Fri, 6 May 2022 16:51:03 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: John Ogness <john.ogness@linutronix.de>
Cc: Marco Elver <elver@google.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <YnU113/cOtv7k9tH@alley>
References: <20220503073844.4148944-1-elver@google.com>
 <87r15ae8d7.fsf@jogness.linutronix.de>
 <20220504094636.GA8069@pathway.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220504094636.GA8069@pathway.suse.cz>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=qC4Ctuw5;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Wed 2022-05-04 11:46:36, Petr Mladek wrote:
> On Tue 2022-05-03 21:20:44, John Ogness wrote:
> > On 2022-05-03, Marco Elver <elver@google.com> wrote:
> > > One notable difference is that by moving tracing into printk_sprint(),
> > > the 'text' will no longer include the "header" (loglevel and timestamp),
> > > but only the raw message. Arguably this is less of a problem now that
> > > the console tracepoint happens on the printk() call and isn't delayed.
> > 
> > Another slight difference is that messages composed of LOG_CONT pieces
> > will trigger the tracepoint for each individual piece and _never_ as a
> > complete line.
> > 
> > It was never guaranteed that all LOG_CONT pieces make it into the final
> > printed line anyway, but with this change it will be guaranteed that
> > they are always handled separately.
> > 
> > I am OK with this change, but like Steven, I agree the the users of that
> > tracepoint need to chime in.
> 
> My feeling is that the feature is not used much. Otherwise people
> would complain that it was asynchronous and hard to use.
> 
> I mean that the printk() messages appeared in the trace log
> asynchronously. So it required some post processing to correctly
> sort them against other tracing messages. The same result can be
> achieved by processing printk log buffer, dmesg.log, journalctl.
> 
> I guess that we will only find the answer when we push the change
> into linux-next and mainline. I am going to do so.

JFYI, the patch has been committed into printk/linux.git,
branch rework/kthreads.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnU113/cOtv7k9tH%40alley.
