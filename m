Return-Path: <kasan-dev+bncBDGIV3UHVAGBB7EUZ37AKGQEX7GBZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BB6B2D7891
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 16:04:29 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id v5sf3432842wrr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 07:04:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607699068; cv=pass;
        d=google.com; s=arc-20160816;
        b=LFJALuXSh5Xmv9KihdgIMVCYRmTHNNXe6IrSN6h1g0ryypwyQaOjCLnLlC5f17M5wz
         U1eI96l1oOAuwAxOrHetG+pp11rsoZW+h4rYkk45P2aIzrZ37j6f7afQi5KihIM/o6So
         7x2H8tZti7MGTQFSF6+WULjUkAuijHvkQQb68E19+RurQ+4Vzl1SDLX/mriNtawjjE+P
         f544cp3r0fQRNR8RbYQQqlR5jOF0Jrzj1Lfn+rXio4P+HHQ0ENe/ZsG1qyvAyhiHufll
         V/KDrxUtRfKbcrjH88cYfc/a/368tz6gk87RA75mFQ6YDo1KFaCqKPUF7xWOvegGQcFm
         4JDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cQa7+BTfK5O7urgFj4BxV8UqJfT2lEMjjHxGaWOJkdg=;
        b=ULLDqZjlkmiKzJmA4f74p1eMY+VLx6JcipGW8dc93CSLGCXcr/gwNFVsmQfuAC6cxV
         pQrLvRe7A5ME4lUFOVQzs8vlqN4v04Qn/4LDfOJGxYn6+Xva/7ITfn2FiAZCM33h/JIX
         HAQbxkVQlON0PYr/IuPeeo1fbK/iIsRHkFvE/qb0FLmUjHA05oxsZvYgmG05qCHYGh5O
         /W0sCaVUjJtWZ1JkErgO4q5v/VHX+xyYCSWCDN8GUTdl9mvGYVCrP7krKu6Il1UcOqy5
         424K754UCHx/W3cVBqOYMFfwZVHiUUtO9jymj4FtqgvmQxZK5iFURRY7cb2rC1wEd7u2
         o1QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=atFAzQuJ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cQa7+BTfK5O7urgFj4BxV8UqJfT2lEMjjHxGaWOJkdg=;
        b=K1FZjkyEXCHW1qrCTVJw1J3frA0nljnhXMidBR/crU+ui+K4OghJ0uarGKu+jzn9IG
         wnV60BJ4E300jbrjuLLtuUuKik+OS/pIUfMJuBb/bFybMYkJI/Nby48WdlKTc+iMu1GI
         Xx/WQjeNC4BRAq+Tyqc4Y0iwbsGBlSLkn+BA+gTMXp6KQ2t6Qin3L6CejmsnmxBmZHiz
         1FMiQCzwS5bHoM0FfhLNtZijGaBfcIzz5y7fzo2bXj/RHXIbmuV1qti6MESEqXEKjD5Y
         2qju75ahjMaicUZir45wZ8So4FOlXVDANqqefjRe0w+PkLrkkEKT/oTciDziq4wNdFi4
         Kf0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cQa7+BTfK5O7urgFj4BxV8UqJfT2lEMjjHxGaWOJkdg=;
        b=i3OCELdqttsPFaNo0/BNvPKwj/M4GGfqWerAufPWypzFfi+YvdMNQ6474tvFDbC9i4
         01TQM39Mwhr61DGmvApyWf+QiLrWvXu0M256ZbNRxOuoMrABXoiYmvMULiBI7YBA8xnY
         Hnip7ZXtvyNMVVxOpeE94AZLAOiXlHztWU6XOogC+UEXc44JpivckwVMGwAbnojippHZ
         ZDEWDmt2jgUVhDdbnCQFp+NFrjw7NiiaF8DoYDM+7kbSKp2txF3c5phU5Jlg9QXn7AYr
         PGkeK1ZoJmN/Xc7nx6UJ9ZH8NoacIpzu9PWKGFWhrYPUAxpX6ZV326EkWtgPXv1/X6x3
         VX7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530p47eEZRwtvRpK4qixhdzJWx3L0HEbs6Yu6skKTExmbUXjbggI
	wdbt4JcDeb+eAkbmzZPHjCY=
X-Google-Smtp-Source: ABdhPJxdw2d36HmHgesLWSOpF3CNUFW5Op90wPLEkJ3QmmeIRrXRp2tEnocHJAGQpAR7xIuFagWndw==
X-Received: by 2002:a7b:cf30:: with SMTP id m16mr13862677wmg.145.1607699068789;
        Fri, 11 Dec 2020 07:04:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbd5:: with SMTP id n21ls4934876wmi.3.gmail; Fri, 11 Dec
 2020 07:04:27 -0800 (PST)
X-Received: by 2002:a1c:2bc2:: with SMTP id r185mr13708293wmr.13.1607699067902;
        Fri, 11 Dec 2020 07:04:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607699067; cv=none;
        d=google.com; s=arc-20160816;
        b=QPKQz+aYhxgsMpfUuD9BxGPAcdGAF3DWYGOhbUC5QW660MlVsR7vXn6UTwbsZvHsF7
         JdqNgh8SFGJ28D13JfP8DkAdrsJSsUqkWCgwm1PFnWmkYUdsqBRBjhip8J95DQOc+FLk
         BwhYHB0LIo/1fxec9jSxupFarpiWtApab2uchqzZAx2MXXOmJVlaBsVMkRlBsD7GUFVz
         GuAqWAjD7lJU91B6Fm3l6EKKnpvEFziLn6lIOS6MYtY0QE80gL20D70CWbKP0tFpRK/m
         X8ETHqFlzdNqRKUe2xpt+/obsv866QaHHpfFUypO4BYA9q7vGNdwcYvzMzjr4b+x6kRo
         3mGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=/xiKtzJHIgYgE49zlVbEbtWb2jQqRpY7QvZxeq5+WwY=;
        b=fU+G/eNUWka3OY8zC1lYQ5zeeZyn1jtVKvxDR1s3APgBWNYBP92ye6XUYV0rWXZWSf
         hIUYj9Hq2JMQVX6hfFXyKmMy47C9eM88vCu0u2eJBDcgbo3x7LJpOvVr9BYRluJUAniE
         5iltGmvnxl7d/8f8MN5SGwPM3qEuQaqW0DMuPoqFBqG/6Pqgeu/mHkv8ageNDiEAajDt
         sM3xrszJ1nhMCEYfRtZUzOK8sio68iBU1QjZfne8uH+IseksscmT1DNlhxeCuTA4WFgZ
         ewhROEnp6gMzKJbsK/N8hNIgdLHrOCDBp9CGgSf8pgRH8Pwq0UB4eaPq/5Ugvhrr5fCe
         05mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=atFAzQuJ;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id x130si255059wmg.2.2020.12.11.07.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Dec 2020 07:04:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 11 Dec 2020 16:04:25 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201211150425.pjpydbmo7k7j6vtv@linutronix.de>
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207130753.kpxf2ydroccjzrge@linutronix.de>
 <87a6up7kpt.fsf@nanos.tec.linutronix.de>
 <20201207152533.rybefuzd57kxxv57@linutronix.de>
 <20201207160648.GF2657@paulmck-ThinkPad-P72>
 <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
 <87sg8ch0k4.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87sg8ch0k4.fsf@nanos.tec.linutronix.de>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=atFAzQuJ;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2020-12-11 15:36:27 [+0100], Thomas Gleixner wrote:
> So the change at hand does not make things worse, right?

Correct. This *ping*-*pong* was there before this patch because
->running_timer is always cleared after the callback finishes.

I was just curious why out of a sudden there are *that* many users of
the corner case. 

> Thanks,
> 
>         tglx

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201211150425.pjpydbmo7k7j6vtv%40linutronix.de.
