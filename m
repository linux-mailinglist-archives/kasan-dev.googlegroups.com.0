Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VNRGIQMGQEQV6TTOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 551F14CDBEC
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Mar 2022 19:14:24 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id d3-20020a05683018e300b005ad2cb4db18sf6334669otf.7
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Mar 2022 10:14:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646417663; cv=pass;
        d=google.com; s=arc-20160816;
        b=UDdI/+ghMSsPYEfH08sFfQC3SXkWgDAHy0cnE0afkBmK8VAJcWqdnYCloaJ4STilVS
         JkHO2b2J5O0JJjHoBj4GhO4sB6+KmLZRUIXJS9kt+uvXDXzAUrgmwd2We9rqwmAiwwhx
         yNCz6qFpCDrWVj8aZHonuTZdHMfxvX4+bxs2rqLceqaIjIwEe3Yri+iQB0mf5/hjEj5/
         9nKJWeHdvyfbeTd5WqEO/43OfrCv7/h7kB1S8/210TwsLBaehrQ43WPgJ1wwFJZTNUBF
         Smlrq3q60U4tpwt/snS/ss+y6H9XIinIrKqYofX0dFJEJnCZZ89Cg9Pda8uilsEDmKxR
         +ykA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=17jR7x4VYa83NgdcF/82Tl2G/+ODOdO7ujb/gVp5Ymg=;
        b=pfsZI8FdtatRi8XrSPHNqeSiSrMemFS//KDDZxb7U8xAT/NT64jOJRVvQsGclIGZ1z
         klG7z2Jj+N+9C9EIq375U2pGpcT1bviEit81w6qWfOxhqd5m3gbXSTh0hHyY355U0aDU
         i76Ba4Tqdn+ijyNLNsS6/Zj2LTH8+20PSEqec+9SZx8noVU9LZAbAkGB1cpIX3Q8NLUR
         v34l6jdFI/A+bPW3HzMG7UzOIdQkO9ugHdoxAjFjACxPdofUHgvFzBC1SjZZPIRQg69c
         6bd5qwA0Yw0jcu+O9Q7saKO/iovnX5z3bBJlS5PzOM2V4xGg0mqBTuW6Ann+bnYFgj74
         bUFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iVNEGaLs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17jR7x4VYa83NgdcF/82Tl2G/+ODOdO7ujb/gVp5Ymg=;
        b=NtDZuQLHJC6R2gXJMI0ZZfGa2F0+mn2YTeg2tBI0Fb9ztO1W5qpfier/v+3ckiyBaA
         jiue9rrHMxqxkJGvbLNnN6jPYg5bdyXUfv2h9hGm/7p1MPAbF/E+tn5LxkktoasALbVH
         cdu7pyY9qMcve8NWyWbKoSewCK0QRkkGrE6ZZH0Er5tOHfS0mp2+Gys1dIFXOFj9N5iN
         XB+M0xVm56LJ3dIVQBAwJnO+PEQKG61mRJihmR/QnZRiJmfWKqk5vY5m6PEQ4/cArN0k
         ev52g5MiWs8gsgb5MtHnZGIS+NHBuvbrwd0nuDApLJS2DN8T8UDvYpFE9UAs+56uTig8
         BHSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17jR7x4VYa83NgdcF/82Tl2G/+ODOdO7ujb/gVp5Ymg=;
        b=ZQ5/anpCJfSRAf7qhiuGOEpJMOaM0O534bZiKkvXTPp6nE5tXUhmhCOYXJ6/4EmGLl
         Mh+MNixCOWKNEO8e2K7TWjzOd6xShYVUs025TLar/JOqfKc9VFmAnE0vfvxoqQSC8Rpg
         uPbhPnUivzsYXAdfMyDcdjQ3rCNBa8CXfcDAUpDydaFrAIwfu6G020jWQ2NX2e+at3ee
         TXlo6YORC+0810yWaptsAq4i1zmARHDmenlKfEJxHwZ8STQlWcMiOvhEGL/JFlWAfl8n
         q3fJZtGYL9O0zlsn18fAafBRm8V1s3+8K8Pva7pOmzNmrMrKNsRLzm9G9/TsECUiwKdb
         Ia0Q==
X-Gm-Message-State: AOAM532NRB8ZTajl95ORBHK8bV6len96ivtrj71KnP9Zs9HVsVs3+2SW
	T+1DN073NQCjJxZoeRzdUUs=
X-Google-Smtp-Source: ABdhPJwLQH7TbyujDhwV45BVo9nfvq1RYanqhS0RrvonbfovxEPX0Fl3vIH4+LWZ986rcQ3j4P11qA==
X-Received: by 2002:a05:6808:1646:b0:2d4:428c:659e with SMTP id az6-20020a056808164600b002d4428c659emr10672788oib.20.1646417662868;
        Fri, 04 Mar 2022 10:14:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2390:b0:2d4:a1bd:6b2e with SMTP id
 bp16-20020a056808239000b002d4a1bd6b2els2338845oib.10.gmail; Fri, 04 Mar 2022
 10:14:22 -0800 (PST)
X-Received: by 2002:a05:6808:f0e:b0:2d9:a01a:4bca with SMTP id m14-20020a0568080f0e00b002d9a01a4bcamr236135oiw.241.1646417662532;
        Fri, 04 Mar 2022 10:14:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646417662; cv=none;
        d=google.com; s=arc-20160816;
        b=ZNH8sK6HU8zfTRfDP5SvVn3Ku9iyEhV779qICDymjJAJPWo3eMBqM9S4V6t6HkxuUy
         lSLFvbAgqtXWPwLPh+F++jhe+NdOV6yL6zTpat9/J2/00p37J5HXts/nQsjGRD9mW8gW
         TuOH8Wq4YznCNmTYLFr41l+qZAtJup53WENkbFu5JRzBGrIkNV5dxqudpJRV9N/39WZ2
         mzBQXDfldv8NpP7cUgdC2gHODOtuksOnuEAKYFsQiAFOQwpmyBH5Fq0DbrKvUUk7rNH9
         jwaYFA8PRfdWl0eXErN3hEhbYzE7mObV4fjjM1+1oyDcY5MnPX5rBTxrtH25R0stRioV
         9lsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=roOvrpzRBBuu6X1VnPdwFDfTIg5X39LNxw0wRlde0q0=;
        b=hOEwfNXa7UfcTWGp1aW1KfQjQpDcuZccS3bUvSlbOHINMnXPDbiQfh68y3mJgNhQZQ
         H6dL837n/ZzFZlvtbvqlJCbpoeOr4fT7Ij9P4qg0ld4F0fj4z/vIKmUGPD3QIjNW+D2V
         nVjgUiKgiZ98kAz34VNrSuY0BqhsKvud+QON7QVjm5BU87n3IowtmCqwXFB2n6qRh3RE
         pu19m5SVfOUWVZXx8ijO/eGxHk+VtAikscw2DdwLCgUL3BtjIb7c76OYGuEyjEWGOyvt
         XAXoJu6Qjx849gVSPkWUpVWv3Fn8dI4xzY13QxUnldTe83D38Er0+05+7fB3qa/78aoL
         T5Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iVNEGaLs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id q3-20020a05683031a300b005b1ec04cd07si846151ots.1.2022.03.04.10.14.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Mar 2022 10:14:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-2d6d0cb5da4so100404377b3.10
        for <kasan-dev@googlegroups.com>; Fri, 04 Mar 2022 10:14:22 -0800 (PST)
X-Received: by 2002:a81:9ad7:0:b0:2db:f000:32e7 with SMTP id
 r206-20020a819ad7000000b002dbf00032e7mr17923054ywg.412.1646417661910; Fri, 04
 Mar 2022 10:14:21 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com> <20220303031505.28495-2-dtcccc@linux.alibaba.com>
In-Reply-To: <20220303031505.28495-2-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Mar 2022 19:13:45 +0100
Message-ID: <CANpmjNOOkg=OUmgwdcRus2gdPXT41Y7GkFrgzuBv+o8KHKXyEA@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] kfence: Allow re-enabling KFENCE after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iVNEGaLs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Thu, 3 Mar 2022 at 04:15, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>
> If once KFENCE is disabled by:
> echo 0 > /sys/module/kfence/parameters/sample_interval
> KFENCE could never be re-enabled until next rebooting.
>
> Allow re-enabling it by writing a positive num to sample_interval.
>
> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>

The only problem I see with this is if KFENCE was disabled because of
a KFENCE_WARN_ON(). See below.

> ---
>  mm/kfence/core.c | 16 ++++++++++++++--
>  1 file changed, 14 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 13128fa13062..19eb123c0bba 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -55,6 +55,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>  #endif
>  #define MODULE_PARAM_PREFIX "kfence."
>
> +static int kfence_enable_late(void);
>  static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
>  {
>         unsigned long num;
> @@ -65,10 +66,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>
>         if (!num) /* Using 0 to indicate KFENCE is disabled. */
>                 WRITE_ONCE(kfence_enabled, false);
> -       else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
> -               return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
>
>         *((unsigned long *)kp->arg) = num;
> +
> +       if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)

Should probably have an 'old_sample_interval = *((unsigned long
*)kp->arg)' somewhere before, and add a '&& !old_sample_interval',
because if old_sample_interval!=0 then KFENCE was disabled due to a
KFENCE_WARN_ON(). Also in this case, it should return -EINVAL. So you
want a flow like this:

old_sample_interval = ...;
...
if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
  return old_sample_interval ? -EINVAL : kfence_enable_late();
...

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOOkg%3DOUmgwdcRus2gdPXT41Y7GkFrgzuBv%2Bo8KHKXyEA%40mail.gmail.com.
