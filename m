Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUXFQLYQKGQEKKTFYZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id BACB213F5EC
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 20:00:35 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id a1sf2837646plm.12
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 11:00:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579201234; cv=pass;
        d=google.com; s=arc-20160816;
        b=meKOQ8prH1dOZEkcyrcB44hV2OyOU3TehAz2Rw/r/fMVuC0ATvT8ELhjDRtNzgS8vO
         7LhgD9VyrzrdWIiZ8l1603qLtLFAQizp7Yidb7P+PGw/XKNHhoAhzqjRLkN62YJKE2dP
         GgKdIRIeC61HsFJ6Tcjy9twd48Bs9N5kpAuMQ7D5v9abKPfAGYfzcX9TDAI1dAdTviP3
         SpWkvj029VLORX5Wtlnt4p7JXuFBL/nc4iFf1x4thrukmMxdj6oUshjsCEj+xYVdyuvQ
         tIwFEzGEHRUtuuMh/sL2+IrLtCxgZ42EZvhax1KjlJpA1btKsu+7CoyJfPu0kJm7drRy
         YHAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qCGAcG1ABrH74BwKLjPIZ781dzXCwFdp2WAsAjljrzU=;
        b=gq6MnvpIBOfq0GkcJ5rHCK6v6Z6riws9sc8kKaYZcktsOO6SzEVZGiF3IyhD8hBN3j
         6DGZx46tUsFnigYnb9d/Jbj87KT9mGhnp7vyziJScrYwST2RHxl8t8XmmBDBB5MHY2Dl
         BNdZ6FkVcabu4wia13L20HujtOz5sAcOmQh7DI4QpUz7dzsQ4NkpplOtyZEek5aCuWf7
         3ZZY1/CbGlxRuJZDVAgd/8bVtjJuZ+VHQlHZUTTBJNCFlxxiSiXqBZTY8kggtqRKmgoB
         DkCd939s8hrKjUxB8K0sUqetyO3entibb+vv25HbB19L0jgPBLNwDm9bgITtG/uX/xeM
         wVvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EpBa46mh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qCGAcG1ABrH74BwKLjPIZ781dzXCwFdp2WAsAjljrzU=;
        b=Fx/+BBx4OGKDxaaNSPDNqG8Thwlamgzh8K61RJvTlTB7U2qSZt4OaIkGe38/NEyLEx
         98Hgb7DsFPDShI9ZY3to5iytWU8byKleSg+i7O+fB3fc6p2jr9lgz9toG+xm7FVVRu6F
         cvWlj8f4CqBMkX+lubZOvaUR7kUG9CjSodDbMfqnFty90jRuhUM0wFk8kRlryLqtUBOg
         vXW+fVgIYOdyyneHuzUqbMOYuwSNE/11fWN5nh0Ce9UXP52Owo/FlEHwm3LcdNDOC3La
         uoWIqaqYK1kanQJaaOXZ9mI9LZsMZx9btaMZ1jz6uMMSvgGWAYkEI0STSzAepjECQguR
         DvAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qCGAcG1ABrH74BwKLjPIZ781dzXCwFdp2WAsAjljrzU=;
        b=dj3aFOVdQ9ogBvHchAEtW3fvuMcPeSmg/Ef2GFiNOEEF5tHt0zIVCegP6xrHk0pVeo
         mnLqXW4dHEF5x9lFzCcjPgihr1WpVLZzNAnZZAq9CUMEo2ftUzbsEGzXFXwi8X/w/76f
         vk/9BFZobjBx6/ovB7zRxHwRo7dyMw3D3RMtYhGvDir1wiN0EM2K5U98L37vd24c1GQJ
         kHxgblBOPglGP80wNdoH4EGJ8XxNXnZEv6oWbEJhsO3LuMMhr5Ak+SJpXWzBRlPGCtGy
         5bHEiV+B4AgfbIRA06CtcYifKDBz0C8VhhbTQu3R5sfCI+hpkmCUGEx4K/Io6TvLSiNl
         VlUw==
X-Gm-Message-State: APjAAAVa4mKTBX/HhFYEoFsq7xwQBAPibUw0nLiljBIuF1a2JQfhsEBu
	ry4H04SAmsA1ZlOkoZ2lUyI=
X-Google-Smtp-Source: APXvYqyHi7TAe6O5/wvIFa/O1x2JpZZnzPyVqNMSOKGOfbiAvgoe+p5YVIZWosEwNgncpXGN9ro3Mg==
X-Received: by 2002:a63:a4b:: with SMTP id z11mr39263772pgk.97.1579201234358;
        Thu, 16 Jan 2020 11:00:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b26:: with SMTP id 35ls1161279pjq.1.gmail; Thu, 16
 Jan 2020 11:00:33 -0800 (PST)
X-Received: by 2002:a17:902:b58c:: with SMTP id a12mr25998552pls.30.1579201233873;
        Thu, 16 Jan 2020 11:00:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579201233; cv=none;
        d=google.com; s=arc-20160816;
        b=IgDRuRG2R4rmopvcZlJSHCOOy6y2Pnh+MCZlfJ7Dw7Iu6RuMewhuWxQsWx3kSqg6pK
         DbeWryoMlQHnK75ioNU8ZroqHtlQbiTVUM6oHsFIHmlHt1GuxmbGUe85xhPVnL2CjgWz
         Ge7t74Rd5STOfD+HBz5YxjRChxF83jLsTTUoTp3nwevOba+SrtzihLMIENmOyjSR+HLa
         WlArhS72KJVZRqaNPiAczChWDN+FLKp6wwCiGph60TBXVIN/TJDh6cBQ+0yY8hp5TKgU
         DPkwQtEW7AcHBU3wgyhxmn6+CYYYi0H35fjRyO2qu+IndoeTFlQYA2ZqrKhvUMSZo9sL
         9eBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hyY7WW4dkzBjOHFiSnAhU1ifhGoPr9kB/eLuIeGz0AE=;
        b=Bk15YWKqwqWB5zf2fgNPvpvXpxNUl2zhTW4pG17W1nUzxklIq0ZJLdWm4pZySHwlAJ
         TnOpa9CVMl6rXyfj42UVqRFWutFUZrIulvw9hYpgDNASZLm5JSKUPLsxZcricYaGf4VJ
         vyPCUQiD09MvS5EWak0Lfgtxy3W/y25U0LaU7EMrTjZcSlMgS5bbSoIpOr+Ve6WlMahn
         4P5jmvnN24BRD2ebAR1uXuJnFDpHGfAJDgSBocVLzK3sdNpvIxFMq57IQn1/ZhtQIoaN
         Qd0m/lklZnUcYE8zq9Fa825AQyV74izzNckhbWzT+f5RTSvaavIzCIikSP5dP950moXv
         th2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EpBa46mh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id cx5si114617pjb.1.2020.01.16.11.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 11:00:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id i15so20379380oto.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 11:00:33 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr3307988otk.23.1579201233339;
 Thu, 16 Jan 2020 11:00:33 -0800 (PST)
MIME-Version: 1.0
References: <20200115162512.70807-1-elver@google.com> <20200116174344.GV2935@paulmck-ThinkPad-P72>
In-Reply-To: <20200116174344.GV2935@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 20:00:22 +0100
Message-ID: <CANpmjNP5=ZyrnueXnYJU-ZN7VUgwnG5w4GFVLja9oN1LfHFpjg@mail.gmail.com>
Subject: Re: [PATCH -rcu v2] kcsan: Make KCSAN compatible with lockdep
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EpBa46mh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Thu, 16 Jan 2020 at 18:43, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Jan 15, 2020 at 05:25:12PM +0100, Marco Elver wrote:
> > We must avoid any recursion into lockdep if KCSAN is enabled on
> > utilities used by lockdep. One manifestation of this is corrupting
> > lockdep's IRQ trace state (if TRACE_IRQFLAGS). Fix this by:
> >
> > 1. Using raw_local_irq{save,restore} in kcsan_setup_watchpoint().
> > 2. Disabling lockdep in kcsan_report().
> >
> > Tested with:
> >
> >   CONFIG_LOCKDEP=y
> >   CONFIG_DEBUG_LOCKDEP=y
> >   CONFIG_TRACE_IRQFLAGS=y
> >
> > Where previously, the following warning (and variants with different
> > stack traces) was consistently generated, with the fix introduced in
> > this patch, the warning cannot be reproduced.

Qian, thank you for testing!

> I added Vlad's ack and Qian's Tested-by and queued this.  Thank you all!

Thank you, Paul!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP5%3DZyrnueXnYJU-ZN7VUgwnG5w4GFVLja9oN1LfHFpjg%40mail.gmail.com.
