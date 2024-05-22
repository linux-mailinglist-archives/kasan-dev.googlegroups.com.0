Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBXPFWWZAMGQEVUIZNAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 230E18CBA4A
	for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2024 06:21:51 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6a9333d993asf46839646d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 21:21:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716351710; cv=pass;
        d=google.com; s=arc-20160816;
        b=wF/3Hr2cbaWk1RqJj+CCXvJNKpdlGdpRt/xfrB2AaphiPAlrD8LtsoO3Wcf6bFJAQG
         AGHnIm81HMSHosa8ry8WUyPOyVtefX21vEmT2C8BQGnQt414fzm11OhmdL5Fxa2F3HS7
         0A289tl49O3nO6BXq3MnXbjA8kmK8VVOOxTdV6+THXjW53B3iisWVjrb5hDdAhyq2PJO
         kospB/1rnkqGXCuScnVTuOnCynXRgpiy//u1pdooOptEWNJhvhTXhlVEV4y+SQo8LKeL
         z30JZc59sSsrcuSF4HUdbqR80ILYUHFcc63MgGpsV47MRJSyPVayd88K+SQSushKA1oY
         dpzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pbJkmPJ4jQ9rcwYH4QRWPOZX8KvNJAJ3xG+AimDZSmQ=;
        fh=/Cyvf5/MdgCnl5CiLJblkpH4RWV8kmnJjmZElAJytbo=;
        b=xR6qGNueNFoev115h8li8dVHC4+ynC/H8ArdQdlPIjaQWXUq8vQ+2hJlU96sW42TmE
         CpXNu82qTsX5qhov+W1nhVZeCytsX4G8BVS10oWsgeY1HSPWmh5JX9X76dQGCUlAEnvQ
         3JwmBXtrduCWQEa0hZ8Ny7Q2foa6AQyD9FtL7b2gzjtlxkcds/WI5MG7UXwGkA75whG/
         WQW3nQm7p0IGgSTpk/so5R/fZSPOMG15mNQoBFH5g7u3tS4/gCIt2khx5oBIYhUJRb5c
         x6stQhWnHQYIGj7qysJ2yk/KgPVVXTRAQBoNPouz0CycqiXDJfkDWzH9QmT084lcKyf6
         YgVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=zSy+agBl;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716351710; x=1716956510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pbJkmPJ4jQ9rcwYH4QRWPOZX8KvNJAJ3xG+AimDZSmQ=;
        b=XOT+WI20oNzBHmvkJiT0UUzZU9pzSpa1VEhn6jYojXv0QCX7IvHjcJhE00jtlNeGBi
         Ak/6amDA2FjOSTh0YufI96cShzZs9ryMTNHdlRMJ/eJojGCXY3RckBXy3LEcnL2issoA
         FsxtrfMzMXrhguAEW80OsSAy3fXzqPALsC5mY1AyoOF2h2BfJyMywBMSamXZ0pXotked
         dbFHvGVR+ZblZaeJD06JBV1YTDZa9q2vKNsnF1LG2R9fzSddNyOQEjMR0xx4jZY+UoAt
         nymwLJODSqvdL227paWNQOxxLDfRQySm4b0cRn69pqQRO/5RDseaqmCDHyBI0G0WMTbM
         5cZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716351710; x=1716956510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pbJkmPJ4jQ9rcwYH4QRWPOZX8KvNJAJ3xG+AimDZSmQ=;
        b=IFWWCRGTAHul6yiES6pV8d8GLvmYe+fr9a6QyNgxBiT8210N0ZynMIYDFdF88GouCZ
         piNixpKhThwYyp6JnHMUEjggs4cTZvh4M0KG69sb/LqK/xQA7NIBho6hJf3hzdfGeIt0
         WUr/wpOFQcpYOUek4dtjCKxWTZt3MHwpEvBMM1pAdcx87i1tkI28PoKZpv2uMkxpsw/+
         Z0pl9MMo5Y5jlmt7u0VPehzeRtmQT+5oUcV5jKesM+7BE5M7xqatqKIEBhnrv0oUk5c1
         OyXj/0jMB6qz33BE6Icl6sHixXopB9GcuVxZcsSzA4y1/VGhIzrGHPwqdplcdQW9cp8c
         n5OQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKEdc/aezzz42+Xvi0Yh/o51DZ+S5KdAYMey8wqmx4TRaoYEABLlx9462BR+YH7GkC2kvDfKvIH9uxe6PGyAGgcPvMe2fOAw==
X-Gm-Message-State: AOJu0YyoOHfW8CW/0c/R2sC+lrKzWP2By05nUlB7gQ4uEaz2Stdp7HhA
	wKlBInfoIW+CNQdDsXs6VxtmjorEKavHhN8HQ7NlzG9fwQWxdu9A
X-Google-Smtp-Source: AGHT+IHmLWYFm+MC+HZRbX+49TQMPzbQBimio3mGHaN/JzUbkP480gB0im7VaNf5d68HxbM1mGfM9g==
X-Received: by 2002:a05:6214:4602:b0:6a9:9fa1:6562 with SMTP id 6a1803df08f44-6ab808fdd0bmr7875876d6.59.1716351709657;
        Tue, 21 May 2024 21:21:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:f0d:b0:6ab:7910:c571 with SMTP id
 6a1803df08f44-6ab7910c993ls17551596d6.2.-pod-prod-02-us; Tue, 21 May 2024
 21:21:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVka9bXkK8QMd7kEriGpxLAK1z0hSOGzZMldGnRYnFWfg1KKIy81EofcLrf9AF/tVYjf9wUT42kq3jFcvhKB5uM03h5YZDUmtKq3A==
X-Received: by 2002:a05:6214:5987:b0:6ab:5b6d:f267 with SMTP id 6a1803df08f44-6ab80907622mr9614716d6.62.1716351708637;
        Tue, 21 May 2024 21:21:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716351708; cv=none;
        d=google.com; s=arc-20160816;
        b=HmyF0Gm2K4Eq4B1cKTcGizwfi1CAaeiXfOvq6MXpNfGXYQAQuEIoiq3/VRNaJOTn4W
         IGZh76fqtpOwEYekMZI+P79ziTYG2zPaqWEPBl9ALyvvoyByPK2jJy7h9fJhlUlf53/Q
         IrD0zAqyMxTPDz9vu5iPKtrkKeku48Lp1tAjZ5cZld5Ukfs4SLxBukXK3BEc2HjnEyia
         Qu7UTVFdEEk591yITdk+BwOfGFopaQrIK4KmvHM+8PDjRrVlZmuztdFBu3a3rSpLeX9f
         D/0NeisMGWpN4VSM3hNm3FeAktEL34j5VJCNhf96mBumXR2h9/33HJwefM5SnjMCSwfT
         ysnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qcnd7a+AaQ3z4LM1z4EPj3xZikJZip8p7JvP4EzHHU4=;
        fh=UBgkGi+ivyAZAk+bhmERUx/jOzOdok8SfvOZxyMLOLg=;
        b=fUbqIq2BsEzmZQeTRpg/mf2Ofk0c9TtuhV8qrnhoLqptBpel0knsUck1bkuELGp7ws
         /XqBaW6oEh5UpwlSqDQid/anIuhCBxk8KLkgMi4Xg+SCE0uBP4AcznFfgZT8DTiYieod
         kSZoHIiajSaQn7Qfmkc99s7277kHtCfKd0sINjz+nQXWnfJKXB5hWYpEGSkS6oqXcM4x
         6q65MQGgP/VktkwAe3g/Orc1fyfjVZlu7Z7eGzWvMegg8kkiW0jWI8+yOf3LLJmvuFr4
         RmB/Wmfu85B/ccDy4nL8idQpLvOh2ET30dvMMjHdcv0m7cE4r2i7jfdi53Q+gj45nHvH
         vNjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=zSy+agBl;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6a15f32f35esi18493046d6.5.2024.05.21.21.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 May 2024 21:21:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id DC763CE109C;
	Wed, 22 May 2024 04:21:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6AC02C2BD11;
	Wed, 22 May 2024 04:21:44 +0000 (UTC)
Date: Wed, 22 May 2024 06:21:42 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: andrey.konovalov@linux.dev
Cc: Alan Stern <stern@rowland.harvard.edu>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Tejun Heo <tj@kernel.org>, linux-usb@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kcov, usb: disable interrupts in
 kcov_remote_start_usb_softirq
Message-ID: <2024052232-juggle-oxygen-5bd2@gregkh>
References: <20240521204324.479972-1-andrey.konovalov@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240521204324.479972-1-andrey.konovalov@linux.dev>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=zSy+agBl;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, May 21, 2024 at 10:43:24PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
> 
> After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH
> workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
> interrupts enabled.
> 
> Thus, the remote coverage collection section in usb_giveback_urb_bh()->
> __usb_hcd_giveback_urb() might be interrupted, and the interrupt handler
> might invoke __usb_hcd_giveback_urb() again.
> 
> This breaks KCOV, as it does not support nested remote coverage collection
> sections within the same context (neither in task nor in softirq).
> 
> Update kcov_remote_start/stop_usb_softirq() to disable interrupts for the
> duration of the coverage collection section to avoid nested sections in
> the softirq context (in addition to such in the task context, which are
> already handled).
> 
> Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> Closes: https://lore.kernel.org/linux-usb/0f4d1964-7397-485b-bc48-11c01e2fcbca@I-love.SAKURA.ne.jp/
> Closes: https://syzkaller.appspot.com/bug?extid=0438378d6f157baae1a2
> Suggested-by: Alan Stern <stern@rowland.harvard.edu>
> Fixes: 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH workqueue")
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> 
> ---
> 
> Changes v1->v2:
> 
> - Fix compiler error when CONFIG_KCOV=n.
> ---
>  drivers/usb/core/hcd.c | 12 ++++++-----
>  include/linux/kcov.h   | 47 ++++++++++++++++++++++++++++++++++--------
>  2 files changed, 45 insertions(+), 14 deletions(-)

Hi,

This is the friendly patch-bot of Greg Kroah-Hartman.  You have sent him
a patch that has triggered this response.  He used to manually respond
to these common problems, but in order to save his sanity (he kept
writing the same thing over and over, yet to different people), I was
created.  Hopefully you will not take offence and will fix the problem
in your patch and resubmit it so that it can be accepted into the Linux
kernel tree.

You are receiving this message because of the following common error(s)
as indicated below:

- You have marked a patch with a "Fixes:" tag for a commit that is in an
  older released kernel, yet you do not have a cc: stable line in the
  signed-off-by area at all, which means that the patch will not be
  applied to any older kernel releases.  To properly fix this, please
  follow the documented rules in the
  Documentation/process/stable-kernel-rules.rst file for how to resolve
  this.

If you wish to discuss this problem further, or you have questions about
how to resolve this issue, please feel free to respond to this email and
Greg will reply once he has dug out from the pending patches received
from other developers.

thanks,

greg k-h's patch email bot

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2024052232-juggle-oxygen-5bd2%40gregkh.
