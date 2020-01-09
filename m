Return-Path: <kasan-dev+bncBAABB7FI3XYAKGQEJD4446Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 59FD4135E35
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 17:27:42 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 4sf3994341otd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 08:27:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578587261; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkpsxBdrwOF5cZJn7hd33qK6NNSlrUGSc5MckQvbdvMz5IsT/N0WXtAv9s/mtqYe1p
         A78KqIK/OF82TA9pGc++t6G48kGyyg/FqTHDfxcbkQtWxP2YkLkQpegG+yPFbr/lMBkX
         EDf/e5LdKd3AARePvJ+3o3IsyOzePbqCiWcsQiLgS6ZcldqdJL4wOfBWVAbtcOHTZnyH
         s4y2rJBoqkVbt79CpDjB4z2bKdX3l26RRxO3Nu+6RcmkaraZItXL14937JjavIAeQq2E
         RRwA5EBlRlT3e484ctseoCUb3qlLoQ4UXi0V1eaSIf16GQAOISQ8DclO2696Kb7JakjK
         8z7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=IbiE5MgaTbhQBBYVoO8HPqOFcKCog2FGmxSLd9dYmiw=;
        b=SZnr/Gl0+jqNaNkKstKRhrXdPLklBi78yijHZ1guHMXtlGczNOTyDDzrplUmYDk5Yi
         mwRu8TahirlKnCwB+umRw+8hIGQsSrmoSySe0Vw+4QPEtMTy/QbDxXGHyoaeYgx2O+hp
         tx3j4tZsjtiozuBaAngxSa0sYGVwcBHExJ/S2sP8RuyyBrmbRvA5R/HAA1TG46jcWlik
         oDo92a6DqgSYSjBxEqTqeK9c4F934xexGg+RPBfdCIUOMSLN8g4ZFZiVd/wurEoBCi78
         6AD6kFZymhqc6fmYzsroGbN4podfbgooRGT0+2CK4MdscQrt0GwC/wszTpcVkA00WEtV
         MPLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wW3c1Wxd;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IbiE5MgaTbhQBBYVoO8HPqOFcKCog2FGmxSLd9dYmiw=;
        b=SI72EZCFq40w/BjVsr8C2K7NS3Dw6RAyarYyRgK6hiOUmEHbL2ivNeLlpMOfYwpa30
         W+RuUVc7PgKum03fXTxJTOBfUjBrLaDiIExU7OH861N1fcCwbr3Yr4+5N5WZFu8qi2mP
         Fm3FmpC8PXmkXOC3FiHYQTsCnbnY/LAnWpZSuXFSXj7GT0pVKLSxiXnlqSbjjTSJjB47
         jv82GzACkRDC5f0Xy4Geivc7vvxoR0GdNcAkEPlzARcuCjdpCVSi/PtbNPeEoyKnXslW
         v9Ptp4cDf/Tv4fBHAcvX2yZVrKd7Xj7T4sPhgc0HGddX95H95r5t8keZctTA7HevYcH9
         P+cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IbiE5MgaTbhQBBYVoO8HPqOFcKCog2FGmxSLd9dYmiw=;
        b=ShQ5RVb9i712aJLnAAEI1TRYSuQkNhnPR0y41+4b3OyWiKd5b/+CTWXAo2YWa+91zJ
         ekwe/BckZ1RfMtk5aBs4Y/sFm7A4wroQZLMJ0IYnx8GwlDbHk+EXThuWPy/UYPhjZQYU
         6Xy7PIXUh+yq58ojKFIHVeYMYqYnmETnxZhMRmYhlslcfH+3DQMWa2mlxqigY6ZTyvq0
         QkwZYR1Cz+Gk0oxSXPvaVg32E8LJJXMNmo9nLUnPtqrYrNIA1i++879GcOqcJXRhuKDR
         25MxCX594K92hzggrM/v/TXmjRt8wlwFfHhYBsaSWdXejfepVdHrvXISpUrlfK3J+sMv
         XUWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3DVP1Jq5o/kA35bPGIc0IP4v15aZbRH2zCOoUWg96t49G+BR8
	8rtNNJikX97djbVVYI2CPWU=
X-Google-Smtp-Source: APXvYqwrPjKBfB5va23qXq+2v13bq65FmioiEvc2ZyVC4MALziml12YNgCwYZrC1z1KT+mqSay512Q==
X-Received: by 2002:aca:458:: with SMTP id 85mr3976289oie.56.1578587260814;
        Thu, 09 Jan 2020 08:27:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7999:: with SMTP id h25ls509258otm.2.gmail; Thu, 09 Jan
 2020 08:27:40 -0800 (PST)
X-Received: by 2002:a9d:74c4:: with SMTP id a4mr9436945otl.119.1578587260393;
        Thu, 09 Jan 2020 08:27:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578587260; cv=none;
        d=google.com; s=arc-20160816;
        b=ezMI8tDC2WiTBjyBZYQt5ry5MJNrAnmMJgTOdgAv0DKV833ZVdhXxwtpd7vRhEJRaE
         tkQnHwZEbzdhpEOuK/lSOKuQzjU4GDdLnFrOpSFipnP1ubYwWK4v8MP+JZ/YRibOsc0l
         58IyVwQbKmRRwGeaOJlelTeGW0kBqingf9cVmH4N++KjzK8t986BfLC0AFOIN/8LcuuE
         nStXqbr0rNYajTeOdfNm8E5ve9r7bN80qE+462nvp9IurMaY0AQk1GUTMeB/4psP515D
         Knse+fqHTlVtbLkg5/+oAJ6R9Kzivc53eLrwq6H24aE5CkqWClyVMypHSkafrq9DwFJl
         PXMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=efN42+VcJAwnWbUA21GzP2f/bqwT+4JYpsLERtrGJCE=;
        b=X2H4zzkwq5D/2RyWWqNQlZVikEm/uhG9TDrFoBH9svFTfyDu9Nswkqdrh0g8TAAaId
         OtbUixlQsPNQTgdFFIjTUgfnLCQ3cpJdGLOsE7jdiFnOB3rhQKmgD5EAhnMGUgYn7npg
         ScBbqWRPdX21pePTPieaqfMGQfV7jRcLQkIJyMGH+/IXWAblMhhSwv9dI+aVKR6My6Bo
         SGm9PrY2B0VC42EmrTK9gM47KpdTzWR4+zKYXe7qIDCxNwaaCrhGhea0+Nwzz4/Dqh/9
         gOdv+eHEoGSVC0g3G95m0VsZisu8NfphblhP5AT60RAw2pLszs00CrRmOsUklsRaR5uB
         ax9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wW3c1Wxd;
       spf=pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h11si453422otk.0.2020.01.09.08.27.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 08:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8134C2067D;
	Thu,  9 Jan 2020 16:27:39 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 3685F3520B2F; Thu,  9 Jan 2020 08:27:39 -0800 (PST)
Date: Thu, 9 Jan 2020 08:27:39 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH -rcu 0/2] kcsan: Improvements to reporting
Message-ID: <20200109162739.GS13449@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200109152322.104466-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200109152322.104466-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wW3c1Wxd;       spf=pass
 (google.com: domain of srs0=wnto=26=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=wNtO=26=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Jan 09, 2020 at 04:23:20PM +0100, Marco Elver wrote:
> Improvements to KCSAN data race reporting:
> 1. Show if access is marked (*_ONCE, atomic, etc.).
> 2. Rate limit reporting to avoid spamming console.
> 
> Marco Elver (2):
>   kcsan: Show full access type in report
>   kcsan: Rate-limit reporting per data races

Queued and pushed, thank you!  I edited the commit logs a bit, so could
you please check to make sure that I didn't mess anything up?

At some point, boot-time-allocated per-CPU arrays might be needed to
avoid contention on large systems, but one step at a time.  ;-)

							Thanx, Paul

>  kernel/kcsan/core.c   |  15 +++--
>  kernel/kcsan/kcsan.h  |   2 +-
>  kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
>  lib/Kconfig.kcsan     |  10 +++
>  4 files changed, 148 insertions(+), 32 deletions(-)
> 
> -- 
> 2.25.0.rc1.283.g88dfdc4193-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109162739.GS13449%40paulmck-ThinkPad-P72.
