Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA7QXT5AKGQEFA3KVUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C4EBF25A569
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Sep 2020 08:13:23 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id a7sf1412758wmc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Sep 2020 23:13:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599027203; cv=pass;
        d=google.com; s=arc-20160816;
        b=T+v2sO9MLitBy1rcp4uV3tI83MdkFLLbOUNmMYBwfv6bIRoGlfCUyOhhjKRDuNy4bj
         nUvhvkIJsJT6nrHfU8sZtCgtP/0KlQfS6b+pr6NgC27qmep85QTlKxDS+1+8opxDqyQ0
         aZvUEmx2xRT3UzL8/v8fNc/Imo5HvCx8dcTZXTEMzJ21aOdWDfdnHP/D4agsXmBNjlUj
         C627OJ/hKxz/CQEZo0OYC3kqhWWXgE18pz9JuDf13o4T+8GwUYVydPnS/IIOe0Lp671p
         433i5EBJLBxYaIYksxvF+KDdV2ZTgcHzdiojuuHTRe1Xw/49Oyx8HN+cqF1XSPpcihAT
         hKNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tPV9JHkHWnCkORvtvvONQUT5V5mt3enQapAC6fGNWIc=;
        b=EeYmoo4009UURooi8J+zz5fGCIWggPVULop7j+SZktYLHnEeKWai026NqxFpSRALC6
         w/vVUl88HNwfs8N4Ns8UpkXBro2XUQ/QR99X7ahWF/ziGUxQt/qkFy0eh0hdvejJDjUd
         RtaUsoVRE2RlLom2BtiXNVFeVNLivWfuJ7ZtxTlzYNZ6mMQ1AgEM0hhXSqTXzbTkCMKB
         I+wYLpjO95r/C260O9H1Fa+RaIVQe8hX8V88c7mcSHMfl4p19b3/pkgX+d/UMWQhhjUr
         nyI1kY4u2sjFupL7F1DI7z7F+5HgN0HSdZrtK7jPUBGE40ui4+JownbNTPEAzWi+XwOu
         PkNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B9faO6hT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tPV9JHkHWnCkORvtvvONQUT5V5mt3enQapAC6fGNWIc=;
        b=Ua1ZgFGoC63eI1TwneZv/x4xXQA1B+WCT3ojbl6gcFGjiHqBlIvHTw36mLrrK+U8zS
         X3cLS8DSSxRS62rVTkjAA2Rt+ksh3GNaYTL/bOzGayWw9QVLUbKojoGgwGeBqzn53m77
         BWiPWkEJ+bbmX7iEQR0P++zkUvTw8G5kDxnus4xW9PLjIS2O5GDZLLh90PTlqfGGBnZd
         VaIoxLOT7sI973DKdUM1Exiav4pTQ3n8n8jb/+7qOKHoXCeUzYTRqiLiQtZ6eotWkagq
         VtwbZvxWQcIyuwYqK02EpZ0SaQggqWKIAXXD9KofN6gEoO4fMp5U4ubaievI6wPwrX3x
         lxYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tPV9JHkHWnCkORvtvvONQUT5V5mt3enQapAC6fGNWIc=;
        b=RWqfNjfDU6J7S3NGCsoOLm2uE1eyjfgBSmGkqRz9EOVypRHC2/UkmM7rozx8PwdU0Q
         4+TDH9SxYCT2yGD3BVZ3ui1h8XFC65lTk6AdRvUvwe69HEG2+TzuBjCX5Oo5b4NRELcJ
         Nf+LLBKqNoq8MF4CKqoWPTeL18pI/aKe1yE8OklOnLMCtk2wAVyBr8xbbWXr14JZipwg
         k+4VB12BlO3/RGqSwYeBmj17RO2C7h4273v67dxrggl4Cok9Kmlq9KzZ2Oqwq4Ho9AZn
         wbJfLyCFRbLVyvB/svjWHbXevT3yin76MU99LTV/P0bBmjC8XAu9nHMgWGA5Xjz4TFjG
         hfYg==
X-Gm-Message-State: AOAM5329xjMoVbKzE4b46cQSF4jcqOcwoO2dplY18mpBl13SdlcuxYlG
	xQthyg+ae/Ft0cB0uiS5UAk=
X-Google-Smtp-Source: ABdhPJxTTeIWQHcQoRq5MUUSgmoW4re31NKJOGZW2gSzZ8DrOU1zG5nJadk+j5Uf0ovFIPW6BshnMg==
X-Received: by 2002:a1c:678a:: with SMTP id b132mr5396394wmc.10.1599027203444;
        Tue, 01 Sep 2020 23:13:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd0a:: with SMTP id a10ls1112736wrm.2.gmail; Tue, 01 Sep
 2020 23:13:22 -0700 (PDT)
X-Received: by 2002:adf:fc92:: with SMTP id g18mr5834787wrr.201.1599027202777;
        Tue, 01 Sep 2020 23:13:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599027202; cv=none;
        d=google.com; s=arc-20160816;
        b=M/LCk5ByT9ehkydJEtYcnexgGKvaByGE/9PPZ9GUW/neJ9JCZIlVND2Z8zJq73JVnC
         YwXVNqkPZ5SH+8CmlF6xGiVvFRfWPNCOcw1CFXPeeWWhBx8GSAdSEMd22Gdd5MkJzatf
         SQhuTm+t8STwB6Ig2g8Cha3P0jYl7Ne3nUHThM8NjzqnoHChkrwUFEv9sxJIEkQWErwc
         +KIsHIMLPle926KsrCthqjj4B2fZdAS9VDmNJvYqRyyrHfrH3ZREQSOdNxSQPFWEF8So
         kGJ1BUNaXIIixBArGqqB26hU9QPz1xqZT3ThiJlLkajHebUxEDP3gYiEBTUw+NjxnX6I
         81LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iqd3bsowREDTYEVeGZ9VhDsWWfsaRpNMJIu5Ds4gx2g=;
        b=M8kkfgKtPSLcDeqbiQ5Shn/zjXcqDWbHIPqTHXc1Q8D9xdTdf2Cen9X9knWrrgKWWx
         IFIKTtRTvYDgmFoSH8h+2BS2YQKw4d1PLhkWNsZCRSTsycMhuPYWJIzWCgCv1FWhnPXu
         2FXb+IQ6qjX1IWQxQaWNBEDXuWzfntypRsu5nB4DGW8AzzAegtR/KmeDlYIQAAJnod44
         6pNpJNjdTgFKjJDArpA+KU6OM1l0+71Q/IdBDlrmKOsverR/GzRjHhnHyTeZC3u8FZ/+
         CgppbjpaM4I6tEWVoLrE6mmmUSqgUWdfK4D62fd9kbIF4DmsmBxf+g8zereVxdNKqD2u
         8iGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B9faO6hT;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id k14si128660wrx.1.2020.09.01.23.13.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Sep 2020 23:13:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id a9so3254468wmm.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Sep 2020 23:13:22 -0700 (PDT)
X-Received: by 2002:a1c:ed15:: with SMTP id l21mr4951241wmh.37.1599027202216;
        Tue, 01 Sep 2020 23:13:22 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id z9sm4988328wmg.46.2020.09.01.23.13.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Sep 2020 23:13:21 -0700 (PDT)
Date: Wed, 2 Sep 2020 08:13:15 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: paulmck@kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw, Will Deacon <will@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Daniel Axtens <dja@axtens.net>,
	Michael Ellerman <mpe@ellerman.id.au>, linux-arch@vger.kernel.org
Subject: Re: [PATCH kcsan 18/19] bitops, kcsan: Partially revert
 instrumentation for non-atomic bitops
Message-ID: <20200902061315.GA1167979@elver.google.com>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
 <20200831181805.1833-18-paulmck@kernel.org>
 <20200902033006.GB49492@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200902033006.GB49492@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B9faO6hT;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Wed, Sep 02, 2020 at 11:30AM +0800, Boqun Feng wrote:
> Hi Paul and Marco,
> 
> The whole update patchset looks good to me, just one question out of
> curiosity fo this one, please see below:
> 
> On Mon, Aug 31, 2020 at 11:18:04AM -0700, paulmck@kernel.org wrote:
> > From: Marco Elver <elver@google.com>
> > 
> > Previous to the change to distinguish read-write accesses, when
> > CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
> > the non-atomic bitops as atomic. We want to partially revert to this
> > behaviour, but with one important distinction: report racing
> > modifications, since lost bits due to non-atomicity are certainly
> > possible.
> > 
> > Given the operations here only modify a single bit, assuming
> > non-atomicity of the writer is sufficient may be reasonable for certain
> > usage (and follows the permissible nature of the "assume plain writes
> > atomic" rule). In other words:
> > 
> > 	1. We want non-atomic read-modify-write races to be reported;
> > 	   this is accomplished by kcsan_check_read(), where any
> > 	   concurrent write (atomic or not) will generate a report.
> > 
> > 	2. We do not want to report races with marked readers, but -do-
> > 	   want to report races with unmarked readers; this is
> > 	   accomplished by the instrument_write() ("assume atomic
> > 	   write" with Kconfig option set).
> > 
> 
> Is there any code in kernel using the above assumption (i.e.
> non-atomicity of the writer is sufficient)? IOW, have you observed
> anything bad (e.g. an anoying false positive) after applying the
> read_write changes but without this patch?

We were looking for an answer to:

	https://lkml.kernel.org/r/20200810124516.GM17456@casper.infradead.org

Initially we thought using atomic bitops might be required, but after a
longer offline discussion realized that simply marking the reader in
this case, but retaining the non-atomic bitop is probably all that's
needed.

The version of KCSAN that found the above was still using KCSAN from
Linux 5.8, but we realized with the changed read-write instrumentation
to bitops in this series, we'd regress and still report the race even if
the reader was marked. To avoid this with the default KCSAN config, we
determined that we need the patch here.

The bitops are indeed a bit more special, because for both the atomic
and non-atomic bitops we *can* reason about the generated code (since we
control it, although not sure about the asm-generic ones), and that
makes reasoning about accesses racing with non-atomic bitops more
feasible. At least that's our rationale for deciding that reverting
non-atomic bitops treatment to it's more relaxed version is ok.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200902061315.GA1167979%40elver.google.com.
