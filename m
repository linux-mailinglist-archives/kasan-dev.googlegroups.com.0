Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMFR4OMAMGQEK45TU6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E420D5B0BB8
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:45:21 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id a21-20020a5d9815000000b006882e9be20asf9530039iol.17
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:45:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572720; cv=pass;
        d=google.com; s=arc-20160816;
        b=oL4SeJkq7Fn9rSLMzfi4asrhL8+Sa0GU7kqrhV8MwNEr+xUP4h8yLMfYZQ/fZtF+XG
         RB+/h+X8svPoeGKRkL1sccmhbAqHX370rK8cSbmHEN+PSjWrZFpyUcwYl9VD+rhZQiEy
         tzICeSMloQzbh2ByEXDoCe3+XO4EOF4jQuFKPh3N1h0QX9sBDUJiVGoSPstG09dNUSZm
         IIsX/JHvaLp4ts0fsXeu8UILiB6tkWeiFFNM72kWLO+DTt1k3iX62uPvwe0ULIrRWc9z
         gx6QvKJ/UD50opK1Zee2MzHPwXs16Ob8MjApVSTNlULR6fF8Qau12hTtETWpEtycsqx5
         DUZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7Dtw57PlmQEqA1n9aU1+7E6OrW8bhihfcS/wCgo6ToU=;
        b=abO/UJItdk4HTtr9Dt74bTYMP/yoXKzKKh2Z0uC0S7F1jO+ae/YauzT3mc+8P3R6wa
         ZzJTEoCHTiIDyWrWuzGi6pzQRKiIM5kxvVEjjbc8B5AIoQQoHwHZKxCCEcN7hdDyfaPX
         VzPwWnEIDcJVEmbb/oyKWjt2TVBPyqVSeDslnP2tqZ8NgJ3pyRxeslsuY82LSI6BuoYV
         5eRZjKObR2LE8oP6aTrRcM2RIKFy5AfcFuUcnWLLAb/dNtnjWjhnUF1ShchjE/ZY6bc2
         oHTnyh9gwf/6iPlhP4wTDHpipq9xF/rgGxY2Zaw0PbIabxNIQTbHevWIoA1DIzouWgFG
         ho0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gHOGoE/D";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=7Dtw57PlmQEqA1n9aU1+7E6OrW8bhihfcS/wCgo6ToU=;
        b=KpHdci8JZskroGKQon6ELn0lcHSxPfkYoD2aBZAw5X28IIrlAvbJCteOWnUFCcx4ij
         0mB21yAzKgrON25W0o3WQ5eewGAOBb+C6/V0cQ/RKNRPdXJPNsXAr+/l9xMrT7skP46a
         BQwaaFtnFBXE+kz6YfATWnOwT4ZZpOiff0RrRJBVSGcy1RECSm9aS7rKuzkLZDLwwKaL
         f/N2Ly7a5c+LFKpqr/O3M2K1Ai57+togNMlHwYe7PIezRoNXElgbCnoJJsgnVxbpHIF4
         2Yb114vLn72/SdF8oBh9HEHiFvL7aOXc7bQGZ0VKElwne25Vls7+Hq3sQg8sjkyAcm2p
         EVxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=7Dtw57PlmQEqA1n9aU1+7E6OrW8bhihfcS/wCgo6ToU=;
        b=qv70FScFADeUdOKTNLIt1kB79kVZYhdwD/QCI1Fszwadk+fxD07aQVxwWQTa5VvUE8
         2/XFpPIhe3WgXpQCkzVd7psAURQapvyBpmaNd/TVcsOiPuhJQVLgYYop7Jcbe5RfyK3+
         1Gt/qa2Z/TtBDWZo7Nf7SyjD1XP3ZZ4oIOvxeTYEw1/+c/RDTjg5+M56BCiL+ogPzWxn
         DpQuBZZCUPqZSBWj9nBNj5eI0s98l2IAG8tpccH7bEyIHKsWWaw4wHWGzS2qbZP+yGok
         yto4HcAgImWfaBLsTADm/5LVHJKlOth5OBrGEr6qXB/eZLSVwcsLGl6VzNYkJYpG9N+D
         XLYQ==
X-Gm-Message-State: ACgBeo13xdMvjfysaANxaKDktgXMzLIue7DUskEOC01FJhMvbRCwdkbn
	QHsD7z2D2JwRr61MDJ6en8s=
X-Google-Smtp-Source: AA6agR7EoaYRfNoyq1bTwXBE96yk0KL1hhdnsasXxfPRXyLCPngjMNJnizY3laeuv8nYxYVxdUqmig==
X-Received: by 2002:a05:6602:1409:b0:691:4dd7:48e0 with SMTP id t9-20020a056602140900b006914dd748e0mr2365452iov.23.1662572720734;
        Wed, 07 Sep 2022 10:45:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1187:b0:2f1:3be2:5483 with SMTP id
 y7-20020a056e02118700b002f13be25483ls2122765ili.10.-pod-prod-gmail; Wed, 07
 Sep 2022 10:45:20 -0700 (PDT)
X-Received: by 2002:a05:6e02:b4c:b0:2f1:e54d:9870 with SMTP id f12-20020a056e020b4c00b002f1e54d9870mr2405706ilu.214.1662572720133;
        Wed, 07 Sep 2022 10:45:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572720; cv=none;
        d=google.com; s=arc-20160816;
        b=QrGQ4PLQpezfBjKn5R41UD7fZ2nrji5eGaKx6ucNJTY+85RAMlYorO+NzNmSUfmV8a
         7Ba6aXPGSZLqvM5rxQBrCGGqSOksH7eR59cTFbuvKe1+9ME8E2XqvApdSv4yn5XWwSNz
         9Gu0KAbyT2sgXNKbosh3PhrDYY7H22pXXxbqYF0IzpYEzGaryCd2xHEAI9IUo0kiOXgx
         iZdsLt00KIpFOPO5f77T5GbvE2Z1RI1wqvmw51gtx4NBiX/gZKjF/rlnUrET9KfI7cjC
         d6I7fwA2911ApiI/Z4VoOUywjy99yYOom9UcYekAULFA0yItgt60/wDB1E4wAS2jz/N9
         Xz/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4UnzWTocG2iPpAqMvQabkV9NRhaTMUyHYWRKvOA4oZs=;
        b=gr6HU3sMsT/wBiUjEvJwFsrYdwhRx4gKjyk0QbC5vsuvfVQCHC+DAFvkri7cFxZlai
         o8UhGE4hO19mwzJ5SzmMu+SYkbImUqZ0dd/zU0hhmk78GqJi9P8V1jyIBFNgJcmNgGr5
         QZbcrkqy9BQfHqorp+uq6cUIK82g722hFZU76Bo/zk6KMRTHTDQ+MpeJ7RF1DS/bnX6d
         88hQW90El0uAgz4KAr7P8PZ8Nk5fm67kGSnF38ygOfwjk56rEb89N6weyDfCvdv2610O
         xI+nywpLChEA3ZgvCBIqWjmd0T4cCBJWPamevvUe4+t3PEshVvP9yN4hBukaKQKpkqVi
         ZEUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gHOGoE/D";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id y8-20020a02bb08000000b0035835f94123si66685jan.1.2022.09.07.10.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:45:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 130so22679603ybw.8
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:45:20 -0700 (PDT)
X-Received: by 2002:a25:1e86:0:b0:68d:549a:e4c2 with SMTP id
 e128-20020a251e86000000b0068d549ae4c2mr3717220ybe.93.1662572719703; Wed, 07
 Sep 2022 10:45:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com> <20220907173903.2268161-2-elver@google.com>
 <YxjXwBXpejAP6zoy@boqun-archlinux> <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
In-Reply-To: <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 19:44:43 +0200
Message-ID: <CANpmjNO6zbVpM2rr7frvE6S9c0PLHi34O5d+9_v5k7fOxNQMHg@mail.gmail.com>
Subject: Re: [PATCH 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="gHOGoE/D";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Wed, 7 Sept 2022 at 19:43, Marco Elver <elver@google.com> wrote:
>
> On Wed, 7 Sept 2022 at 19:42, Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > On Wed, Sep 07, 2022 at 07:39:03PM +0200, Marco Elver wrote:
> > > Adds KCSAN's volatile barrier instrumentation to objtool's uaccess
> >
> > Confused. Are things like "__tsan_volatile_read4" considered as
> > "barrier" for KCSAN?
>
> No, it's what's emitted for READ_ONCE() and WRITE_ONCE().

And you rightly pointed out there's a mistake in the commit message I
just saw. :-)

If there's no v2, Paul, kindly perform a s/barrier//.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO6zbVpM2rr7frvE6S9c0PLHi34O5d%2B9_v5k7fOxNQMHg%40mail.gmail.com.
