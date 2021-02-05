Return-Path: <kasan-dev+bncBDAZZCVNSYPBBXPN6WAAMGQEXJQ64WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65664310E1D
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:48:30 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id f204sf3887795oob.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:48:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612543709; cv=pass;
        d=google.com; s=arc-20160816;
        b=jGA+aznNYmlbl6HONWpyhdKXiTGc21vsma+Ejt7F7MFxXMlp3BkdmRpdRcVYkusPh8
         savigwdsUlqJDjt9+UXcR1xe1vZplFdc8A+d3VFW0b/lIR1onq+6Qe9Tr4V7dujHabso
         ck25WD/X6KwGK5Sy35kAZh0hy7YEBxsqEQaXDtsCTwEsXuiv8N9+g8yi6Uv8jjiAQu2T
         dXeUwpVlHtZxHvmDt+aiC6JKQcRcbGTwbx/rFd76hXLESPG+ySG03/W2YKsR/CMZEJBN
         4LxczwbroNFWTRDfeFcNH34HeX1WlSS8J4Fgx2ZGgTLIXHYI4etkzopgHFiiHeZJjDqB
         KNEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=I0Z/oXMfz+F0F9JRo/hYcQa9pKC7+1IKLDeiztQuOZY=;
        b=EYdvVZxKjFC8tPlFEYjnSb4XaEi9XtwRCP5+yA8MZDA4EUHVGxvyKfB5mSwqGkooin
         GdowbxSJQ9OuND/8/eUBz9gRCM9lH8x5UNWqFtxpz3DJZ1iYehfUyYyLZvQBewMUFVwv
         irkZwNo1Hen9aFhiB68Mucj4oKRVZOg5PBr8IQTBjKHPP27SEJOcnZ4dcuCxY4j7AUFs
         MjmWfha6+FJ74ai0tKqvMqgELkGanPvPuheDLED5ij7wo1Fy0EoTp4yYCcj98TXq1VD+
         6UPLvkdDBPlgsw8OFbkkx0GjEuikCxdakzb0GUWOyp46o7jn7IYmC0BTpMHU4efoqKLv
         N7Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fr0XTPfv;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I0Z/oXMfz+F0F9JRo/hYcQa9pKC7+1IKLDeiztQuOZY=;
        b=BNXxpZHpIcy+fTxDrHvBEIvYGJnhqAz1/Bc+yxETcLUqVgwkwm7CZlZUcEWy+6yZTX
         Au6zUBASp6O48APTHgXz9SU4j/894OcyjJypZQ5gkZt6LSnOozsD307hVJ9kmxbRQwUG
         /ukvdmEV49ccyfuHmSoDhLYE52pZSyivTajqeAY24GTRPS4XCAIHHA6+dyzNXhVZI0yc
         KBVi6nyEXjS9wuDiUKeG3KOEHGjCbnLUk8eQbBw+mXSJn+y4t0QLC65XkZi/Bl7sIhff
         s4GCZknSUoEwxSwOpBzvNdMyaLkPRkluF5Er1uuORYYAxHlQg3IAqMMmoYD9RsCEDgk4
         B0Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I0Z/oXMfz+F0F9JRo/hYcQa9pKC7+1IKLDeiztQuOZY=;
        b=rG5lLw7fjICiR1e/ijNcslm9g7AWR69xy++WOEL6gzY6H9CgQ3rGII9bP1/7YNKpfH
         XR1bFJvMkXN5b7KscxV74OUwYt42tf/zHAM/dVU8XYkMYJt/MyPYQMDHDPgNAyAiYzoS
         TMMyZvcpdhLfPEECOqrCceJLJmRxjUdU8guHlSz/EpX1ZxmzMuh3DgUkp0y/zZrckMFd
         HB9P5my5v5+NccCZQzjeGrooPFTpECWxa1kQ38NtxsAJ1CPjnKzp7R2yKEXGWYxCb7Ey
         oRttE1vhJ+cg1Ct7BrTLsDrDgFakikuK9di7E0lO/fV1ANfoI0F+Uk0EGXebIqHEZC5N
         GBNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312ZIrqxc3ECy876c5ZTu2l5QgDv4CSc33pmSd72vMj8QU8LfMB
	lGtwv28VzWNMrYXSTJ/viKs=
X-Google-Smtp-Source: ABdhPJz0JqXjE96f4MvX1rWsxDXeNTx/PUh52ocea1yafSRzhTBOWmeBnSgMP/Jd0oJANqLUbBYpyg==
X-Received: by 2002:a05:6830:3108:: with SMTP id b8mr3906828ots.174.1612543709421;
        Fri, 05 Feb 2021 08:48:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1614:: with SMTP id g20ls2398304otr.1.gmail; Fri,
 05 Feb 2021 08:48:29 -0800 (PST)
X-Received: by 2002:a05:6830:14c6:: with SMTP id t6mr1679555otq.4.1612543709073;
        Fri, 05 Feb 2021 08:48:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612543709; cv=none;
        d=google.com; s=arc-20160816;
        b=nuJqPGk+fcy5uxHLYsV2Y/qWoVcdQ1jnUCvfN7CN3SUYkbGn4mpvzFROsriBq671r9
         B9NkEBVbjJqg4WlBOPtjGOKh8WdL5EHgw/rcKegMZyuZmVaaArcz0YBdoBmHH0Ocfk/j
         U5hzgDv3XUr0QW1R8HeWs5wyfVjXwhtPh5L8uQ0oiF1tCGIAf817YfaA8KfN6Fn6bwW6
         fFs0GrVrSji9KDvsAAZ3+F5Dh1/ngXOrfWAJtqhNWezwg+qKva8gIF9X4Y+wwMOE8lBG
         OrTw6IWSRbwAGhwDSOKYypKN+isE8q/Ayca9iKpbQPhAEwgQKT8t94PY7nSTO8QF5iaU
         TKXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fC0DlM4RbupT3R+gA4Pu0SCIwJNwV8HzqpwT0J4QU8k=;
        b=sQNEEdwZ2fPl+KKwp4IwEzEN8IfwN07DJyGqYMlkmQB5hKZNR00Z3EJ/J7GFv6+cJ6
         N7buuRmqprBzBErvMv4xdAlPA/Kp+YpbQHO2axlNsyRzIGEV+XaiN+87ZUeYso8A4fk8
         k5ye4JupFL4y7PJvjjuSysvciESUSrGg46qPEVOMBsM8+edEnXnFZZDw+XNfcp1GsB1L
         2traxcPuhWCOd6hVEWnKeYuI3pUcYWvnfIBINmd2+CO0Ao22xnoWef92b2bzPlF6zPRb
         I7E7M68BHxhMup5Soyo7HtHiUITo49KI+gSoJrVbqHNi3yCbBhrtdbu7YZfBo5q7WV0J
         d8Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fr0XTPfv;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e206si426572oib.3.2021.02.05.08.48.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 08:48:29 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DDE1764EE0;
	Fri,  5 Feb 2021 16:48:25 +0000 (UTC)
Date: Fri, 5 Feb 2021 16:48:22 +0000
From: Will Deacon <will@kernel.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>
Subject: Re: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
Message-ID: <20210205164822.GB22665@willie-the-truck>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-3-vincenzo.frascino@arm.com>
 <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
 <CAAeHK+wdPDZkUSu+q1zb=YWxVD68mXqde9c+gYB4bb=zCsvbZw@mail.gmail.com>
 <96163fa8-c093-8c2f-e085-8c2148882748@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <96163fa8-c093-8c2f-e085-8c2148882748@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fr0XTPfv;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Feb 05, 2021 at 04:00:07PM +0000, Vincenzo Frascino wrote:
> 
> 
> On 2/5/21 3:49 PM, Andrey Konovalov wrote:
> > On Mon, Feb 1, 2021 at 9:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >>
> >> On Sat, Jan 30, 2021 at 5:52 PM Vincenzo Frascino
> >> <vincenzo.frascino@arm.com> wrote:
> >>>
> >>> @@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> >>>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >>>  EXPORT_SYMBOL(kasan_flag_enabled);
> >>>
> >>> +/* Whether the asynchronous mode is enabled. */
> >>> +bool kasan_flag_async __ro_after_init;
> >>
> >> Just noticed that we need EXPORT_SYMBOL(kasan_flag_async) here.
> > 
> > Hi Vincenzo,
> > 
> > If you post a new version of this series, please include
> > EXPORT_SYMBOL(kasan_flag_async).
> >
> 
> I can do that, no problem.

EXPORT_SYMBOL_GPL, please :)

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210205164822.GB22665%40willie-the-truck.
