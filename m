Return-Path: <kasan-dev+bncBAABBV4K472AKGQECDAF6EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A3041AE068
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 17:03:53 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id y7sf2530525ybj.15
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 08:03:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587135832; cv=pass;
        d=google.com; s=arc-20160816;
        b=HjBGvxJiK9kT+VDTQeBdkbOyLd+VI5K72SlAMjFexnpsWSnRVJn/9QAeO+V4YWwYXc
         A1DMsM6pnnH3VDb//fR1+WZWMBpIDOYte2Z4rF6HNSghN72da+pg7MKaIKPGw0/liUn9
         x7rFM6mrTy4soLQRzga5pFZENXZW40OUEJp/zjfoIoVflCwnIKij+MYkFNVh4rG8U/g1
         6Yg3grQY8REVV1NQ4CqEK2BTwwZZTUE+qOFi/d4BaKbrYkUrSgm1uX9a9HAxZLpErQVO
         gmuAVAtzUMpARRAum0j2KXx4wthNcj9VnvOWSOiy0NfreYHeqLnqlmlTNXLbkTXCy8JH
         XUVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=B1vaJlpIxmSvLD83Kfr+Ys7UKifCrpNWgXmy/quJhL4=;
        b=Lq6erYa3XB5AipxxqOtQf2b40LGE/ZoXxaR5/hhGJMMgPkfAmq/3yu6gEfwQaHJpHp
         QJ8qlUWoMjokDUuVMZCbqTLW4IAdFlBTOVVi0ltPaOzVBDVMfuLpqwFTS9jRG7PnLHLj
         os8Z8r6RKUrFOoe1y2QOP07Of2+6aAa079B/KWq2Uyfmpjjg9Ie4brVVqDeCh8ZqTOO5
         HxpfRAyXr2bXOgQ8XkLionBbmsnyoJl8Qv91OfeXKS9DglELpfTvLd4cTQ2U1BL+wdoM
         ogl4/6P4rR3YRZ/wel+QKGIwNN4rb7YTlCdt10nggedncZvzRLwRDeTbr6oTZm2mCwxB
         oodA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="m6Kd8/+9";
       spf=pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B1vaJlpIxmSvLD83Kfr+Ys7UKifCrpNWgXmy/quJhL4=;
        b=o2vppaJ6Ie5vViEOCcbh79BuvRHLJJgink6LeS7cVfp3i8Sr7yYzr9hbtmoJD2jTHb
         gXIkNai9SL+TP6p2JE0E6rKAlRGtfOs1bWKfjicik6fk5pV1ySTWntxVophIrY3urM6q
         Tfo5/DSIG+CQCm+pJo4yMPzXX1U8a1zVSoV7hELxCBNiMTHAZR6t7pjfF40fR35RyK/j
         81B9gojlj+pVtsiC1FvgAeOQvnkgKo2Fv8LI7+PnTgwGymmsKR0rsZcvu82iqH3MxPv2
         8sYCaGGozsuf1azAWM1ppWxOntRcCKMycOFeo6mKGtX6m8MTqe5I6hjn+BMF+TbgiTgE
         V/Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B1vaJlpIxmSvLD83Kfr+Ys7UKifCrpNWgXmy/quJhL4=;
        b=WKyNZacI4AgejBcW8GwNdzB6qaurT344M+KlGkpoS0wdU6bvUeIQQd08C6JipI4wgu
         hUWZFvkhY734YmPuisCYnWndJ/E1w4hkpMXV+hRcobpc4EZjksE3Kn8kOMP8oNyHCmef
         wowJaAzwbIscSDOJ17y82olTRD7GFE363pXgl9oUIZZFRmdsPFROdCwlfKmHCQFxLbHH
         NVxcB3TMM0O9nzXLB3Dhz41YIPFCDSCwnquUmbrkugZFBKfaRxTpWMWHpry9V0GzhGEg
         MfUvIMT9KaUElARQFjQZzvPSvmSQ/KqHC3SQH3pcDLjZFSMqgodf9DPpL09rUYeXM+op
         yBZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaIYAiLlOgs+eWojGn60c9NwVHkwGYDYpU/GdBDvjbP3ptQUf/8
	dLSdERYjIXzpqy7W2q1lkww=
X-Google-Smtp-Source: APiQypKkpQ5CL/yd/czE2FJJ402nIhs+PNroCB7wv5NpGi+TmAb/dTnuyoDqZ4+LAKSbjhpyNQWH4g==
X-Received: by 2002:a25:cace:: with SMTP id a197mr6395238ybg.19.1587135832152;
        Fri, 17 Apr 2020 08:03:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aab3:: with SMTP id t48ls973284ybi.2.gmail; Fri, 17 Apr
 2020 08:03:51 -0700 (PDT)
X-Received: by 2002:a25:d0d1:: with SMTP id h200mr6480333ybg.237.1587135831665;
        Fri, 17 Apr 2020 08:03:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587135831; cv=none;
        d=google.com; s=arc-20160816;
        b=xeNVoKn900qmkHjaR1ubikG0v9GUhXdQ7F02aMnbR65UOdwPqZFo3FVfp1smGsNu4O
         EpN3N/s+4czuKVIGLewph0t+ZIOPMGyKjSf69stQCpu+XtBbcmXvxx6TuAy7ubYVMSN8
         8NeW6xwQRFu7SA/hNZc2QCFVn2TElG/5/LVBaS43WVDC0D6FXLIkAsiddjYAoy0twwZV
         UsaCPDRDGcwwnboeZQ9epe87GrnxjWXvcehkajjX5CBJz0cKBbLhpTNxxmcv/MxwB3gT
         XNLS0GBnlbL1OosZu4kvKfPa7qZHYGvRO+Gt/fp2DqgdKugccIg3HqRy7RS1Sq30Kdj1
         nzZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=g6oJlU69DS2BBhwa+Etlr1Me98h4u+i8Wl2xAAr3JfM=;
        b=mrGJC7+9+Fqi9ZEk7Bb4XBdC8/WJwFrMZgy6TSn1mn5veVp6IkBiW9YjV/oTCv5Cp7
         EtM/rDprHFGKNIj6Dv1ZwGHJVpCLXLrh7qh0tQfjGIy3E7QxJN2iA7dvmUa3P6WNeq/y
         qTWnNG3W/2Glh01/IJlZIG79HEN1We6xBZdXCN1+e00LvZE8HcVrAa2SwtDkEtE/a8RM
         6I7orJlIsOhLEev++I8wxLNMrTAA5dpTDuKe/a8db31Ih3XAdQBj/cbcM9Ij/9yVGpfy
         CusY/rtQ9aWP6Af10UUsUTZjjTYNbnxQDxbMl5KgCUsDoRisth2dijykVr7f4mH45QBh
         G3SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="m6Kd8/+9";
       spf=pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m18si1441471ybf.2.2020.04.17.08.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Apr 2020 08:03:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9E17820857;
	Fri, 17 Apr 2020 15:03:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 70D1E3523234; Fri, 17 Apr 2020 08:03:50 -0700 (PDT)
Date: Fri, 17 Apr 2020 08:03:50 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Wei Yongjun <weiyongjun1@huawei.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kernel-janitors@vger.kernel.org
Subject: Re: [PATCH -next] kcsan: Use GFP_ATOMIC under spin lock
Message-ID: <20200417150350.GI17661@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200417025837.49780-1-weiyongjun1@huawei.com>
 <CANpmjNMzwqFaaA-zQh0Nv4SUdoJUFO_yTmTjfbMFqyxBea1U+Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMzwqFaaA-zQh0Nv4SUdoJUFO_yTmTjfbMFqyxBea1U+Q@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="m6Kd8/+9";       spf=pass
 (google.com: domain of srs0=4ge1=6b=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4GE1=6B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Apr 17, 2020 at 11:23:05AM +0200, Marco Elver wrote:
> On Fri, 17 Apr 2020 at 04:56, Wei Yongjun <weiyongjun1@huawei.com> wrote:
> >
> > A spin lock is taken here so we should use GFP_ATOMIC.
> >
> > Signed-off-by: Wei Yongjun <weiyongjun1@huawei.com>
> 
> Good catch, thank you!
> 
> Reviewed-by: Marco Elver <elver@google.com>

Queued and pushed, thank you both!

							Thanx, Paul

> > ---
> >  kernel/kcsan/debugfs.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > index 1a08664a7fab..023e49c58d55 100644
> > --- a/kernel/kcsan/debugfs.c
> > +++ b/kernel/kcsan/debugfs.c
> > @@ -230,7 +230,7 @@ static ssize_t insert_report_filterlist(const char *func)
> >                 /* initial allocation */
> >                 report_filterlist.addrs =
> >                         kmalloc_array(report_filterlist.size,
> > -                                     sizeof(unsigned long), GFP_KERNEL);
> > +                                     sizeof(unsigned long), GFP_ATOMIC);
> >                 if (report_filterlist.addrs == NULL) {
> >                         ret = -ENOMEM;
> >                         goto out;
> > @@ -240,7 +240,7 @@ static ssize_t insert_report_filterlist(const char *func)
> >                 size_t new_size = report_filterlist.size * 2;
> >                 unsigned long *new_addrs =
> >                         krealloc(report_filterlist.addrs,
> > -                                new_size * sizeof(unsigned long), GFP_KERNEL);
> > +                                new_size * sizeof(unsigned long), GFP_ATOMIC);
> >
> >                 if (new_addrs == NULL) {
> >                         /* leave filterlist itself untouched */
> >
> >
> >
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200417150350.GI17661%40paulmck-ThinkPad-P72.
