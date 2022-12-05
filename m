Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHVOW2OAMGQEONI6VSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E28A642346
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Dec 2022 08:00:48 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-3d2994e2d7dsf112447417b3.9
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Dec 2022 23:00:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670223647; cv=pass;
        d=google.com; s=arc-20160816;
        b=PgRzW8DIOJhgh8445JRvq6vbIjyvSdiu3G/TqubwSmtaeby5TDcnLRACL7iqG18NYi
         2um+ssaQ1JrggroET0AaOlnHauof7mGqSV7JvqMbQCAUaXzdHM8krdtmeeAVHl2WW3WJ
         Zq1PFjxhYJmjxFjDum6+L0OqoqftrnwuB0K/2iBrtEz8TPej78wsyTTabAu2dCPSiHZj
         /zDFzQv78rBlaF5nUOCkeUTASpLPCgWKlIuy1/chYGkF66jlwywM70ZikzfKE9qvxc7+
         tICTFRyPKRKWMAcBWp8+cEVNkSX0g3WgtdUAQsiiBG2fK+hP8Y/OgmUNN0jk9VCgGOrm
         HnjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DFjTPl3qpJGpckrmZDFDXzrtW/f3jsUn3msCVYi1l2k=;
        b=V4nHPemLDgK8ykrpNoRJnAAsXTckQfIkl08pDe7FBukHvdczJVZ4qVzYGGIYv9Hqoq
         XeYnzCDnf5TFEMvaKecBvBLWokwomsiWcxjZHuhqnWyN4jvqJvHGyQLEr1cDR62syPs8
         M6ZO3eWHa6GbpUtcFv/ncboJpwzkUWCeor0MmJfVRk0K82g35hJQK+coIfoo7Chzsvkw
         61HL11s+fD0+O0gqRFFb4SVS/W3cObww2FAmde9sla+wwf5TuoYc2XT/K44ImJGCPv50
         XNba3JzV582eCeNuXT18Yw778lANrjKZILzMDQcRrvnA/osff0Nq9ZPWBNXjRipohCRO
         9w6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cp2c4vLv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DFjTPl3qpJGpckrmZDFDXzrtW/f3jsUn3msCVYi1l2k=;
        b=lWYsUl/mOdU4RnpRREY3hM4ipbMYlvcmcbDUwbHRZAywl95IokZXqq5K2yg7ecg3e+
         NBX2XFIhbnN1P5XzRXXQqNrMXDpWQ4C+pqDCS/mc/EAnEX29xtVVYAGuZPec/cnVLtjv
         qFu7dm/hlE3veWULsk5ev+JYyWb4EM+iDs2jiSUiXnoE+vcQBety0OVQCMv07/CMKI+c
         nrMwSp4IstfRcBozWxJjqWlCnfKOCU4wdqS/dqvWRWQCCVvgaoXJldmAyu6VZkSlIjbi
         OhfZToG/gNlQPvoC8aC3VH1KeLcTdWEmH5R/UTa8pYE3OVRNke4MJ8Y90Hs9PSxWmQre
         tAFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DFjTPl3qpJGpckrmZDFDXzrtW/f3jsUn3msCVYi1l2k=;
        b=wlFZq50mP9Jyl3NuknsVIUpEiWqhBoN9hhLW/NxPIueAOWM3N9nt5582hyAJbA+2rD
         87MFiUiT7Ak+9QIL/wyhFwrIAg58PpZgoeEvCR7Uf9Fil+aC9kBqUQtViJUThtVX/fyW
         YNFDvMfAmK+aVbMVAVW4TNp/UAMkyXpPce7d5Ra2Q5ByTXawMV3YjmS90GeZXGyGFkzE
         lT3UyJ6w8rLko9ezTV7SbjATZp7WMzGrHd2hZm/95ZBSXrfIj5xab+V3k7gFE78U8Nw4
         dk1oNRzT6tb8TXhfJsMUCYvL3JLLYqZi2Lc1I8TvfsBHgCHNBQjlCC2I14qeSju0Uhhq
         /Y1Q==
X-Gm-Message-State: ANoB5pkquqK+UQ4zHRD7g+doUCGOVANfwnMBLUomyNZWlT/fV+bldYXB
	VGt+pXhAi95CAEjDRftHMHQ=
X-Google-Smtp-Source: AA0mqf74da6CuLwMFcutWvCdDpQwH6FlqH4HOESCS7BWf1DTQvmGvLw6Y5fb3gLtvMpc6KhcDq/2qg==
X-Received: by 2002:a25:9006:0:b0:6f9:fbcd:8fa1 with SMTP id s6-20020a259006000000b006f9fbcd8fa1mr11871743ybl.354.1670223646959;
        Sun, 04 Dec 2022 23:00:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a404:0:b0:6ca:10dd:4459 with SMTP id f4-20020a25a404000000b006ca10dd4459ls2558978ybi.2.-pod-prod-gmail;
 Sun, 04 Dec 2022 23:00:46 -0800 (PST)
X-Received: by 2002:a25:df86:0:b0:6f3:67a6:481a with SMTP id w128-20020a25df86000000b006f367a6481amr43746986ybg.592.1670223646272;
        Sun, 04 Dec 2022 23:00:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670223646; cv=none;
        d=google.com; s=arc-20160816;
        b=imaKH8ujZ5VswhADKO5evIDruPo2KijET+MK9lodiJqaS7PvEwP3oUGcfqF1n+S2D9
         JtJpEt7p1rvuZO/6fsezufCWgiBnk5Qri3q+fYEYwfLYA5knbOJKWwMPB2WDnKGzTuiA
         +TmsyHB3tN4hfrngjXv/ipp4nXgxZjjrFQJqDLwIBdit+IICBwCBYNbhec7tBD32LYSk
         THi9J/aVcpl2hSJF0UZlQMapRthRrvvUU8h5Ao7U+RPiYLfL0ZZQDxlpwfUUgM0RlgqN
         A0BXdzca3lqURGf/Emm5z3DSsWRkBPOMmXUv5/wlHirvTbmf3jj8QM453u7P1/2ovRc6
         uuyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=coRXOHRNz//WTvn8iz/sAzTb1yJBt0dUNQrHlt2mpPs=;
        b=G5DBs2x6nXOfj2zaBb103VxllaH0WiuEE5uNLT2WBB5z3TAoCfqkm7eKp6LuiYY3R2
         Ln9edaov5x7DWTjl15Qf/9Vepi3d4kUkQk8LUjnhapaLboIOHv/xluOVOuc94M8WhugD
         yxab7eoNxrFkFbIyEmimwfA/AuxVL3DcH+ny/2PqnVuB05PlUvaenzfUtEMipbiLKMvw
         t2ZwifeSMiuMUZMhAFICxvDwurMpoCpQ7kC26Qg32nCc8hO3QWxepwdu0hmCNxPnj1EN
         2x48L8uXGkTgPNaAAM5JaX2RULvIpJltg2CWKmCUPKvJ536VI5ZDRLrdNQpkDsoRaj0O
         +YSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cp2c4vLv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id r201-20020a819ad2000000b003e0d1cdbb77si534123ywg.3.2022.12.04.23.00.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 04 Dec 2022 23:00:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-3c090251d59so108644517b3.4
        for <kasan-dev@googlegroups.com>; Sun, 04 Dec 2022 23:00:46 -0800 (PST)
X-Received: by 2002:a81:1915:0:b0:3bf:9e45:1139 with SMTP id
 21-20020a811915000000b003bf9e451139mr39230763ywz.267.1670223645646; Sun, 04
 Dec 2022 23:00:45 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
 <Y4e3WC4UYtszfFBe@codewreck.org> <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
 <Y4ttC/qESg7Np9mR@codewreck.org> <CANpmjNNcY0LQYDuMS2pG2R3EJ+ed1t7BeWbLK2MNxnzPcD=wZw@mail.gmail.com>
 <Y4vW4CncDucES8m+@codewreck.org>
In-Reply-To: <Y4vW4CncDucES8m+@codewreck.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Dec 2022 08:00:00 +0100
Message-ID: <CANpmjNPXhEB6GeMT70UT1e-8zTHf3gY21E3wx-27VjChQ0x2gA@mail.gmail.com>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, rcu <rcu@vger.kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, kunit-dev@googlegroups.com, 
	lkft-triage@lists.linaro.org, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cp2c4vLv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Sun, 4 Dec 2022 at 00:08, Dominique Martinet <asmadeus@codewreck.org> wrote:
>
> Marco Elver wrote on Sat, Dec 03, 2022 at 05:46:46PM +0100:
> > > But I can't really find a problem with what KCSAN complains about --
> > > we are indeed accessing status from two threads without any locks.
> > > Instead of a lock, we're using a barrier so that:
> > >  - recv thread/cb: writes to req stuff || write to req status
> > >  - p9_client_rpc: reads req status || reads other fields from req
> > >
> > > Which has been working well enough (at least, without the barrier things
> > > blow up quite fast).
> > >
> > > So can I'll just consider this a false positive, but if someone knows
> > > how much one can read into this that'd be appreciated.
> >
> > The barriers only ensure ordering, but not atomicity of the accesses
> > themselves (for one, the compiler is well in its right to transform
> > plain accesses in ways that the concurrent algorithm wasn't designed
> > for). In this case it looks like it's just missing
> > READ_ONCE()/WRITE_ONCE().
>
> Aha! Thanks for this!
>
> I've always believed plain int types accesses are always atomic and the
> only thing to watch for would be compilers reordering instrucions, which
> would be ensured by the barrier in this case, but I guess there are some
> architectures or places where this isn't true?
>
>
> I'm a bit confused though, I can only see five places where wait_event*
> functions use READ_ONCE and I believe they more or less all would
> require such a marker -- I guess non-equality checks might be safe
> (waiting for a value to change from a known value) but if non-atomic
> updates are on the table equality and comparisons checks all would need
> to be decorated with READ_ONCE; afaiu, unlike usespace loops with
> pthread_cond_wait there is nothing protecting the condition itself.
>
> Should I just update the wrapped condition, as below?
>
> -       err = wait_event_killable(req->wq, req->status >= REQ_STATUS_RCVD);
> +       err = wait_event_killable(req->wq,
> +                                 READ_ONCE(req->status) >= REQ_STATUS_RCVD);

Yes, this looks good!

> The writes all are straightforward, there's all the error paths to
> convert to WRITE_ONCE too but that's not difficult (leaving only the
> init without such a marker); I'll send a patch when you've confirmed the
> read looks good.
> (the other reads are a bit less obvious as some are protected by a lock
> in trans_fd, which should cover all cases of possible concurrent updates
> there as far as I can see, but this mixed model is definitely hard to
> reason with... Well, that's how it was written and I won't ever have time
> to rewrite any of this. Enough ranting.)

If the lock-protected accesses indeed are non-racy, they should be
left unmarked. If some assumption here turns out to be wrong, KCSAN
would (hopefully) tell us one way or another.

Thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPXhEB6GeMT70UT1e-8zTHf3gY21E3wx-27VjChQ0x2gA%40mail.gmail.com.
