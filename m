Return-Path: <kasan-dev+bncBC7OBJGL2MHBB47N2SJQMGQE3L74TRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 88F9451DB3B
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 16:55:48 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id w133-20020a25c78b000000b0064847b10a22sf6382232ybe.18
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 07:55:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651848947; cv=pass;
        d=google.com; s=arc-20160816;
        b=j1Q8eWhhMmtSgL5CdiP1XjXUx2mg6uhpNu7q6fp7H1foIHkogJjZswzlfzP/+mq42F
         19ubrAh4eqRyRKoZLw0nMQliiI26Mgfni58/SV9grzRWqKCfh3Jj4v9ziaGeHt+9ech4
         6gl8u419BZz1rPBT/FSftBQF3I2YfhaZy11+KnVec1J5coj7UPkHTySB0VPW10KB5Low
         sXssed3+KSMQlmUU6bdLpTAQ4ob/bR4SUTjMUye7vRuAr3dN9RyM5QPEAoM9V2MtON4S
         0FZ5RyRO5YZVKqSuRAakyFK93zZ7Irvby+TUcpIlWnmrkrX7I7XL2N4d9FOJq7sm1Cby
         9pzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=t6/dJzWWHMZMHdySoBf2Esq+uH3QcOCHvee4mCTsgME=;
        b=cEtNv7fjbyUb6yf6c3X6waitpVfXE5OsYzOK5pg24hcDE04t6rhbga+L7XRCYBoBy0
         KdKGQscOkKNA222ND8B4EBRrVVKdFqNJKdxbt9Du0qgQ7VVuZIGbxWWtFtmgFyBVIfPH
         4vpVP09gjSJdn+QQ5ut+/XvOhjPN26fJiI2DmwpqiaLsu/w8SFDg+LbJwDYckz6rr3Wx
         tCcoMuWgpV60H884SK4+7O6x+J/+V5ZTN72YBX5Gge/lto2JoNuCmKxz4wGdLmm7LbqN
         B15zdDLmYo+i+0r4dLJizu0lkAqTaoODKG8o58LfSEGzPgLuS+r9fJrAJ4JOD2OyCAXa
         05vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gqcLFW8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t6/dJzWWHMZMHdySoBf2Esq+uH3QcOCHvee4mCTsgME=;
        b=FjFIWm5vTSOeLzkiOd1yO/XAdDYgwaulA5lyNJcekM6aqatrfY08CaRFcP21/FaHQn
         x7LKtmKS5yc4SuEBESmayeEtPhnhgHIKLAfXcvXQu3QJiawxcrOX3gohO/lRF3Nmk0XQ
         ZelHne9MAb31EJL1aharXJ5atCy5FT+tMCAteA2SeHHVfuIe/57pgCNWfCqW7ByHx0Hb
         PKgqQ27JKv4G0UP/KcViHj+b8gZAWog0foXyUCzYurSOKny5F6lu5WaQCo/2r/maxceX
         d7bex2W8gvL4/QlSO94TELUOBbDtWR6HUUQCFTErnKzpTM5VHVJ4GFn8APcDfkZzhmun
         uDQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t6/dJzWWHMZMHdySoBf2Esq+uH3QcOCHvee4mCTsgME=;
        b=o9pqlZtLPilWrSS36f2rCH5PIPLMdgAf1XgdZhi0KIvp/Y4CmVTerz+1P6iBq5ZWZk
         RzhAf1k0RLIxgo29pHt7//XLEpIY3uIyzkvl1pX8ptu8MIRNvfYDFt9rMcsi61lf+zNg
         vsDKjjPZo3zxGvsHEHoYrrZpBzRhREg+NtY7D0onD9oLv+wHCpNPShbUXK8ex+hymS/q
         6P+JT3SLZsC+OpRrYKMTgdjQEWJStlwwBRFOtrtm6fMquS6oghEV3mKNt6Mq/IFyGk33
         TLAms94JO3R+ueCpSFZj3XLMBDfg9a+50LfFbj5B2menZ2vzzDxfY8OCDziGQ/A5biIw
         sd9Q==
X-Gm-Message-State: AOAM530BAWaT1tW+3MzG9Rkp+sLfWLnBAvXgQvdWCMzQXZxnscymRM2g
	xU5PQReqJqxVAsRyjOjKF3o=
X-Google-Smtp-Source: ABdhPJzV0LO8GxcLgIYfYO35Fby3fEy5useL4QWw6KBbHJiU10tAtcInux5pOZOwZ2tgmYTcKj52IQ==
X-Received: by 2002:a81:9b06:0:b0:2f7:cebb:9f4b with SMTP id s6-20020a819b06000000b002f7cebb9f4bmr2982111ywg.59.1651848947401;
        Fri, 06 May 2022 07:55:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a16:0:b0:648:3bbf:52e4 with SMTP id q22-20020a252a16000000b006483bbf52e4ls4846623ybq.4.gmail;
 Fri, 06 May 2022 07:55:46 -0700 (PDT)
X-Received: by 2002:a25:4112:0:b0:649:7a4d:d5e5 with SMTP id o18-20020a254112000000b006497a4dd5e5mr2521840yba.280.1651848946778;
        Fri, 06 May 2022 07:55:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651848946; cv=none;
        d=google.com; s=arc-20160816;
        b=ZZ/pxd6qBaUnc+FhcDV6LQPkjPASV06jRbFF5nXE1jxaZQonbMiNRTu6uf1FOV5yLr
         8+6PQECVy6B7ND/cyiYgkP4uZDRQKZ5gHMMDkpSTzaCYRvjCB1UqxQKaHpxQJWO3qaL4
         IxYLaIePMY1OOF22z965TTQIZyPi88Apckb9qJMTluftnzuBrhLNrIHDoUDPmYo/aBxa
         lwOJIOx40cltu/c1TP4TS6MT5ghHc/Z835WwtGTGuDfKsN5I2rl//VPZHIfjh8Rogt2x
         wrUeJi5TaeKB8K09t0pGWVzjCb9tc9z1fvVktP1p0be8CA1NUbcC3efaMtyLx5f7t8rm
         j+BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1pp55vxmPCAUyGS9+i2Vpi8qxPfkHgsDwJp+6fIOUpY=;
        b=x1A4fgIG+QsQyY2jLOQ763L4HuFxJp9T00XUOUBqrJfgnbOYOsEs2O+1nKCUrBQpbo
         i/sK7SEXgA4pXq5XySypyebeyTbbhu7Rb1NPCy9lOvSoRakwtt6QUTt3KpgcL3UHGVgk
         iDK7dQmVTJnzuA2n0TuEWfcYAi/c1dhIm/Dx1yu7q9N8iJMQ+Gtm4nwhjsfqSv41rrrT
         RieunXAT+hY6JlwxszI6nm53KO3TGQtfVmJESeyNBiVAm+4uSDj2dqqKrAgnlfrp1hDy
         4pT6Vr4VNphJWxnx5OeeMBE+ozYglxsCvIi7HLP46gsq2kx3zR7npj8nvyBV8Z+6bqRU
         zajw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gqcLFW8E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id h82-20020a256c55000000b00634581eb904si579142ybc.2.2022.05.06.07.55.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 May 2022 07:55:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-2f83983782fso84242617b3.6
        for <kasan-dev@googlegroups.com>; Fri, 06 May 2022 07:55:46 -0700 (PDT)
X-Received: by 2002:a81:7d46:0:b0:2f8:f29:c9ea with SMTP id
 y67-20020a817d46000000b002f80f29c9eamr2950362ywc.362.1651848946371; Fri, 06
 May 2022 07:55:46 -0700 (PDT)
MIME-Version: 1.0
References: <20220503073844.4148944-1-elver@google.com> <87r15ae8d7.fsf@jogness.linutronix.de>
 <20220504094636.GA8069@pathway.suse.cz> <YnU113/cOtv7k9tH@alley>
In-Reply-To: <YnU113/cOtv7k9tH@alley>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 May 2022 16:55:10 +0200
Message-ID: <CANpmjNMD3ugyUFDHVqEDCFg6cAQSYpStQUo_ixGsC4DxZC15vg@mail.gmail.com>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
To: Petr Mladek <pmladek@suse.com>
Cc: John Ogness <john.ogness@linutronix.de>, 
	Sergey Senozhatsky <senozhatsky@chromium.org>, Steven Rostedt <rostedt@goodmis.org>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Thomas Gleixner <tglx@linutronix.de>, Johannes Berg <johannes.berg@intel.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gqcLFW8E;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112a as
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

On Fri, 6 May 2022 at 16:51, Petr Mladek <pmladek@suse.com> wrote:
>
> On Wed 2022-05-04 11:46:36, Petr Mladek wrote:
> > On Tue 2022-05-03 21:20:44, John Ogness wrote:
> > > On 2022-05-03, Marco Elver <elver@google.com> wrote:
> > > > One notable difference is that by moving tracing into printk_sprint(),
> > > > the 'text' will no longer include the "header" (loglevel and timestamp),
> > > > but only the raw message. Arguably this is less of a problem now that
> > > > the console tracepoint happens on the printk() call and isn't delayed.
> > >
> > > Another slight difference is that messages composed of LOG_CONT pieces
> > > will trigger the tracepoint for each individual piece and _never_ as a
> > > complete line.
> > >
> > > It was never guaranteed that all LOG_CONT pieces make it into the final
> > > printed line anyway, but with this change it will be guaranteed that
> > > they are always handled separately.
> > >
> > > I am OK with this change, but like Steven, I agree the the users of that
> > > tracepoint need to chime in.
> >
> > My feeling is that the feature is not used much. Otherwise people
> > would complain that it was asynchronous and hard to use.
> >
> > I mean that the printk() messages appeared in the trace log
> > asynchronously. So it required some post processing to correctly
> > sort them against other tracing messages. The same result can be
> > achieved by processing printk log buffer, dmesg.log, journalctl.
> >
> > I guess that we will only find the answer when we push the change
> > into linux-next and mainline. I am going to do so.
>
> JFYI, the patch has been committed into printk/linux.git,
> branch rework/kthreads.

Thank you, sounds good.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMD3ugyUFDHVqEDCFg6cAQSYpStQUo_ixGsC4DxZC15vg%40mail.gmail.com.
