Return-Path: <kasan-dev+bncBCS4VDMYRUNBBXXXWWLAMGQEXXTX4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F899571BAE
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:49:19 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id a11-20020a5d954b000000b0067bb240eb9csf116499ios.20
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:49:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657633758; cv=pass;
        d=google.com; s=arc-20160816;
        b=f+erbF3/TmI4OJv3xb46iOiuZpU7lkyMxf0b41tvex3IdyqoNA7R53rHsGQ/Td1GiU
         5RQg5Bm2SiYEKlUo08kP0ZyYwJEnRzNpbMr4yEEGcopfTqmybZb/JFNguv6uFKi2ATiB
         +zbeysy+ysLQKbO018XfeV+YnJ0GrMFLf5tYIxR253lte4zr8mUSj/PJOcW9PVGW4NUU
         jCK6TCG159WuTeJJw3mU2g38Wjt55EKoH1h/mbf64GZq3OOfQsngM53HW2sc9nYV2hea
         SjvpEmQCBBpMlqGW+pbDaAW7gz4CAKXGy5vWhiVSFkX+qRwKs9dahVTvqWbt8diELtkD
         uyQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=k3yMUU2GTdu3C8Dumb6f6mFt8By5Ttz+rTKa1Ik9v4Q=;
        b=oyY0WFJZK/8QJ4X81QmHn9c7XmbQf8FZZS6BlUjtMppcV8yJSH0X385LZL9YIQZW6J
         z8RUc8wutJIj4zdsOm9mwHw8yogZpQohq0130cnyBKUGnYn2DchkX3jArjBZQ5VwPCJQ
         AWkSf1x/uf6i+RWg89py5YJ2r+JcGnNWw9HwdPxZgZLxizfy+mr097DKFd1BnjTCHdQ+
         NBWq7XsvQK6Wulib4FNq6ZAW70QM/TLgLFxVp+GzugbGdAkueNVrdnaX9Ri/RGHk2/c9
         /DNKIxyIUA4nYJpeaVw/zzfh4fxcSSF3k09IL7uLkbRyBTHMfiyFcAkt3tWfz6j9afb2
         ry6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vMguKPxd;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k3yMUU2GTdu3C8Dumb6f6mFt8By5Ttz+rTKa1Ik9v4Q=;
        b=XbRGr2lbIIhY4KzUf5BEqqvxiEWgroHKYX2GGOiBipXMRz+rAJEfl8oHh7an1vj/gN
         qFB3ghxr/hua6P/hdRASgxvOv2yROZEh78Z2EQFwbaN05fJN5rKGvi1PUrXbHyyCWj25
         baJd5omvkEmQhG3+XcSPO1FkSywHTL6BHe8RlMGzeY7lMd646G1JAyzRIMavwwIFinr6
         QSZiE1J+/bzeL2Q2ZRdiyqrRqEwPvUMxbBMnQdJzuzBZpdN5kiBKuRJt8UMrB/zYh9BS
         3i/5nGq5KhWQzwFeOy1JMn5cXLrd0vOCUkcMBx15j8B7uSQTJzpls2yjZrjXKbtFzhC8
         1Gjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k3yMUU2GTdu3C8Dumb6f6mFt8By5Ttz+rTKa1Ik9v4Q=;
        b=JCTaRO9Bt7od+K4M7fZDKwcOMoHRMxQuL5Ll6Lm19cougtFSkI6QDDkg2qEsxFmAiP
         JSwY3FFTFg5SOTS1wve6A6BjIrdE0wKVJuokA9dGPNRAPB565RumNt3DQeAn+Jxl1ICV
         KjfMRTIamLe7FxJnwzK+LwlsL70HpI/2E/CPhOdJgEZe0K9pORq52aerKd4QM+O5FNOc
         OD7VkLwgO75OuIC69FicJHYeI6ztwgGPo09wcewZtNMnyJK2uc55mdMvfs6qlyFED8GP
         Hqgu6TNAmf+R95ZzuAFf+mFlLv6QP2hkluDIU5mL+D3BGMoWnmP98ril3zW2+tdsRbPV
         MO7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/T9u0oDzC7Cgee7bgwaNqccHaGSCQrdJgShBQ0LcePfvqC9xUX
	Pvts2j1rPlZUNn/gfIFrmqE=
X-Google-Smtp-Source: AGRyM1v5Teq2Ud2uJMoV1GsPthkOBKlxX2WQQlud+6GM2ptL+jFAv6QJ8IyGlmmg1RicP0oAmuRRwA==
X-Received: by 2002:a05:6638:4194:b0:33f:4795:5c68 with SMTP id az20-20020a056638419400b0033f47955c68mr8058960jab.193.1657633758168;
        Tue, 12 Jul 2022 06:49:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:270e:b0:33f:5ca5:88c7 with SMTP id
 m14-20020a056638270e00b0033f5ca588c7ls459271jav.11.gmail; Tue, 12 Jul 2022
 06:49:17 -0700 (PDT)
X-Received: by 2002:a05:6638:40a4:b0:33e:2862:4ecf with SMTP id m36-20020a05663840a400b0033e28624ecfmr12932908jam.107.1657633757676;
        Tue, 12 Jul 2022 06:49:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657633757; cv=none;
        d=google.com; s=arc-20160816;
        b=pWe/bMB5ihVndNKFdy2RcL1JUCM1ZrjMXsjBEu+7geHaIFXhH1qoY8lRMsBhHzGxgP
         ikxesbGYvAm4GkZbN7d04kCpUVccREDlQt9IcKN0HP1IFWNQrTfuDy1/Jh/AXiRqsH1v
         6zJZudzIGbwr0TLQvHVu6gM1Bb+LdSz3ae00xYLeI0ZL8vXCVTLRW86mQmK/+r3vhWBJ
         ZlzCZyZFLriVRM6gQZ0kQ+jVQHYqm+fghGZKfvahqRIXxQ0D8EkbiepPrkupNYjdUe2h
         CUmvbpKPSWnytfvDxWUMOn86LbRXiAdVLxVK8S0+3ooywihF1ToD7grENmxCbBRB0uyA
         /z8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XHekcAiefq4P3zCUPd45RaxcO2FJOtCT02txXdCp/4I=;
        b=BQ7OAdCsvWHh1WyFwmz7LvdeOf4Gqc88issdGZxboOMNy2cd13swns23n1Por/wsah
         VPZMvOm0eUjnCZqimwxMHC+ulITTTn6nUEuON4Vh0+GueYwWjpstHtKP2gn3HUbeJIbs
         Gdz/s2BoHX97lnLeJPXAfZ1vSlIGCYKHgRyYhwj4VXS+fF1sGBiIIOAJ0uyPVWBsMLdc
         +1DOppB7os+6jhjsYR2d9qm2LB2NjfrMb9hEeJBywK0jqoy2PxQ/UVbgLlg5IJbpIWhI
         pmIvSYc4YlfXD/Ua+F5J5ChddyRAfblt67dUNhU9+BOU1rYYX5dKeYHsD6gHdak+O1SP
         DjLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vMguKPxd;
       spf=pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id a3-20020a056638058300b00331dcc79d6fsi275566jar.0.2022.07.12.06.49.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:49:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 45DDE61787;
	Tue, 12 Jul 2022 13:49:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A82DDC3411C;
	Tue, 12 Jul 2022 13:49:16 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 3CFA45C0516; Tue, 12 Jul 2022 06:49:16 -0700 (PDT)
Date: Tue, 12 Jul 2022 06:49:16 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, John Ogness <john.ogness@linutronix.de>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>
Subject: Re: [PATCH -printk] printk, tracing: fix console tracepoint
Message-ID: <20220712134916.GT1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220503073844.4148944-1-elver@google.com>
 <20220711182918.338f000f@gandalf.local.home>
 <20220712002128.GQ1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220711205319.1aa0d875@gandalf.local.home>
 <20220712025701.GS1790663@paulmck-ThinkPad-P17-Gen-1>
 <20220712114954.GA3870114@paulmck-ThinkPad-P17-Gen-1>
 <20220712093940.45012e47@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220712093940.45012e47@gandalf.local.home>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vMguKPxd;       spf=pass
 (google.com: domain of srs0=8dsi=xr=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=8DSi=XR=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Jul 12, 2022 at 09:39:40AM -0400, Steven Rostedt wrote:
> On Tue, 12 Jul 2022 04:49:54 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > > But a quick fix that stopped the bleeding and allowed printk() to
> > > progress would be useful in the short term, regardless of whether or
> > > not in the longer term it makes sense to make srcu_read_lock_trace()
> > > and srcu_read_unlock_trace() NMI-safe.  
> > 
> > Except that doesn't rcuidle && in_nmi() imply a misplaced trace event?
> > 
> > Isn't it still the case that you are not supposed to have trace events
> > in NMI handlers before RCU is watching or after it is no longer watching,
> > just as for entry/exit code in general?  Once in the body of the handler,
> > rcuidle should be false and all should be well.
> > 
> > Or am I missing something here?
> 
> I guess the question is, can we have printk() in such a place? Because this
> tracepoint is attached to printk and where ever printk is done so is this
> tracepoint.

As I understand it, code in such a place should be labeled noinstr.
Then the call to printk() would be complained about as an illegal
noinstr-to-non-noinstr call.

But where exactly is that printk()?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220712134916.GT1790663%40paulmck-ThinkPad-P17-Gen-1.
