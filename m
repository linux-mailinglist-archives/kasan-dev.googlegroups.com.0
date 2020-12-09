Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHIYT7AKGQEDZETZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id C5DD22D4BDC
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 21:31:09 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id z2sf1839630pgb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 12:31:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607545868; cv=pass;
        d=google.com; s=arc-20160816;
        b=NVe454ouz4GmAuFO3WVEMQuC8vpk0egytzepUsJpMb3wOel8kWChPL5yl1VPVGBMp1
         ftO8t2mlfhQHCQK1Z0wkjxybOGjwKXHjx8vPE2wpPgdY8U+4Nu7XrFGBh01z2DyoBgSW
         ZIStMOl34FwPWx8jP1Rqf7yw4NCf5opmt+0goqnDKYeFK9TPkhWwN6rtvFZBSFRAWyWf
         4mYXH8S+29jrBKjHoRb9xmLALXP8VZRgbT84qP3JGs9WYmdLMm4/tGI4zlJWYOABP1kO
         HMy7OaApWCI+LJTL7d2YcYKXT0CK5xviCfK1BAdoWVpKHpW+zrtPYvc+mxhdyTOxfiCY
         wa/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tq5gvfd9BlTiAgph7r2zIsPXJVlST6NeCzCjD3Uo7sM=;
        b=zwSZi9pfPL+U8vK1MdBp0p4SMDct5kE3yjxWzLCrz3OFvqlzkFPZsdrE0XHD3iFVAW
         IHF9wxRNaBwqkIn4M4siw7KKaF9ufzH+exY5JO3P3AyqYQDPm7pypw0L2tUochKahs8A
         xZT22o9AdMhaoe0Etg1jdyAp6mnfH3YFhHFf94A+Z/UxpC5uPMo/2mWA1Ap/3eRw7yQg
         zyDHmawA6LaYCgK+i6VPAyOxoTIrxLC3ynJAwc9trBwt7Z16Wt5RgmigVRUf9p5CdXgn
         RS3BWmGZcjZahGO7CvfDBpanuITUGZ0LumNFz0EOBoIyjfgiGwJ0KsCRsS1XNR2E7Oj6
         mueQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YFX+o7YH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tq5gvfd9BlTiAgph7r2zIsPXJVlST6NeCzCjD3Uo7sM=;
        b=jG5xC3PcHuelvkyc9XlazKl3FylIZ6wKSbwafxTYKjkrAYQ+XQq0pe6y09/DIrKZPf
         ZCpozet55VXutlPxmbaDmIij/l6Ek/vYc5VVsfz7DehE878cxU242VA3tLQSu5ftAnTp
         I4dHYuXm6rCQvmFOlQHCmq4BoSYbudJrWeNhBctdYiy2NfM1nxIBoSvorzT4035eV6Ui
         tDzqJKRw9iS8xbUaL64AxT97YSZwJP/4q0lbqOlTVIc2hyOtyKWmYf6zjl/kTx1z4WV2
         2BlmLNt4534R2doJjLw4RG2Zw1iNLNL2a0kXMQIbrbMqZn72PiB+I7zLDNNquMIIFFcc
         ddQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tq5gvfd9BlTiAgph7r2zIsPXJVlST6NeCzCjD3Uo7sM=;
        b=OlpMjc0/Q0jtJlpO5rpcBPZQS050UK8elBW3uVmHn9x0wPNa+6Tm6OmgtAm2gZMqEH
         06UKNA68lMOf2hNAgA1IsAzMhfcs5CJglm9n5ZeTAv8zy/gWW2rGplnwilOg337uAjyr
         kNi2KwGi9sFPmTm9zyF2gcNFl4nU40ratCWqkytTQWEnC4RDfm/Mx4vx4tXwO6GFYvkd
         qWx/uIUyHdWvua/llibFVWbeuPjlOL1WB9vdIlTD2qMEVZlpF++gGTeoyDNAT+CHfFxP
         iRyy/8WRIixYdSwa9+0XI3Lvo+25UpM/LVhOjrtTPvQ6UjIqIBg9UE1c0qZBGmYYi6Xl
         RZ8w==
X-Gm-Message-State: AOAM533ezdCQE8Skb/RwmmDsbxZlX+deallY/UFVRGXXsg1n+p2s0V2M
	kGICz76IjDuLhMrS3JA6yzI=
X-Google-Smtp-Source: ABdhPJzJP4P9XcwG5HrTR52SATM5l3LPd/rT47oMNHaBjBaBUem+4Vcmeuwng9BlhucjYSK+ocSWlA==
X-Received: by 2002:a62:5f81:0:b029:19a:89cb:41d8 with SMTP id t123-20020a625f810000b029019a89cb41d8mr3683555pfb.48.1607545868455;
        Wed, 09 Dec 2020 12:31:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:989e:: with SMTP id r30ls1069499pfl.2.gmail; Wed, 09 Dec
 2020 12:31:07 -0800 (PST)
X-Received: by 2002:a62:1404:0:b029:19e:1be3:25e8 with SMTP id 4-20020a6214040000b029019e1be325e8mr3744524pfu.37.1607545867842;
        Wed, 09 Dec 2020 12:31:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607545867; cv=none;
        d=google.com; s=arc-20160816;
        b=UzgbhdNzeyzsNB8jDW9ees66++ko+bJCvgMfysFWGWijm7YS2rjKztXEQnBw/quLjT
         IRUb88+upUlfQbd6M5hThkQePYDGWmBOIa3qpVUD5F/Uq/qcsgnSwSnBke8Hc7eq2lSl
         5CGtNMKOPtvWxBquWMA8O4ux+IV2RytWyujBjx5YLgXAOpWGGwisD2nFpbpzU124EkJ2
         ykAV0N0RIJ6SXq/x1JvqHwJUQAdO+uEOScJ9Lt0lIFU644vHA4lOroYIumIXFU3GQ6mo
         3Z8v+zKYIULVWaBSL9hs75PGYH41qZ/8MSlBURf0B35ZF3JuxsqEwjTVxkozcRLstbqU
         dKEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LIlAR7aoeBb97uKu5Kqj7/OZ8UGBo/oPj5/DsVNeWHg=;
        b=xk28jDagdPHKetMGWvoR/5fLA74eNmwbniW5ftx0wRxxwswyDuYWhINtwbyLAMcSUy
         GNFy6P6qL4CxPSBo7kTalYnxNmgBqSvQBnh6jnK5qdQEidz6zNymippB6SJw/O/o1u15
         FyAFhHIi7MGnnNyoVsVIbXcv1haQBhjRYkwkVTmmaNQe996GCVaRE41yf5k5+t9nUSqm
         Isojb/9xYDIWEGTpQFNMxdqAtpLa1baKpbVhBYVzoLEOejb9tCZw1SQffCsT+l1d/kbI
         T2zD8fkVxLTwUGpBimV+eCSdwaEThd1g5gIUzeFjUAt6hXwJr4MlOzJl56bDekbos0l5
         OXwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YFX+o7YH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id t126si282588pgc.0.2020.12.09.12.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 12:31:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id s1so730552oon.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 12:31:07 -0800 (PST)
X-Received: by 2002:a4a:48c3:: with SMTP id p186mr3419182ooa.54.1607545867027;
 Wed, 09 Dec 2020 12:31:07 -0800 (PST)
MIME-Version: 1.0
References: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork> <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork> <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork> <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork> <X83nnTV62M/ZXFDR@elver.google.com> <20201209201038.GC2526461@cork>
In-Reply-To: <20201209201038.GC2526461@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 21:30:54 +0100
Message-ID: <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YFX+o7YH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
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

On Wed, 9 Dec 2020 at 21:10, J=C3=B6rn Engel <joern@purestorage.com> wrote:
>
> On Mon, Dec 07, 2020 at 09:28:13AM +0100, Marco Elver wrote:
> >
> > I ran benchmarks where count was (2^31)-1, so only the branch and
> > decrement were in the fast-path. That resulted in a 3% throughput
> > reduction of the benchmark we ran (sysbench I/O). Details here:
> > https://github.com/google/kasan/issues/72#issuecomment-655549813
>
> Took a look and this is triggering my bad-science-detector.

Hmm, you're right, the early benchmarks were only for sanity-checking... po=
orly.

The semi-final implementation was benchmarked more rigorously:
https://github.com/google/kasan/issues/72#issuecomment-656155497 from
here.

Plus internal benchmarks which do all that and more.

It still doesn't change the fact we probably couldn't get a dynamic
branch past reviewers. ;-)
I'll send the patch to add the option after the upcoming merge window.

> In the office, I regularly reject benchmarks that do only one run each
> before/after.  We often have 5% noise between successive benchmark runs
> without code changes.  The minimal quality I demand off benchmarks is 3
> interleaved runs, so ABABAB.
>
> Usually 3 runs each are enough, but sometimes I do more to get a more
> precise answer.  1 run is a waste of time - either you care enough to do
> proper benchmarks or you don't. ;)


Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q%40mail.gmail.=
com.
