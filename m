Return-Path: <kasan-dev+bncBCS4VDMYRUNBB24J22LAMGQEFIXYPZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C5015786ED
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 18:06:05 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id o10-20020a0568300aca00b0060becb83666sf6630979otu.14
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 09:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658160363; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uf2hkAXzIlNKH8QqEHVqB2E+bSQV3Xz997zmvJwf6ReSLuNglQZSFtN9z0RcJarN5m
         BPRy0u4NT4i8PbsLpEN9lZkurTsKKUzwCmHcyw8SXT2tplZz2JhPOn05IHp1rsSuY+Dl
         KM9EwFdhCuAnjIesVRiRLQ4e4nfbt0Y5v5K5zVmnNxa/BMtVCAYR7BQSWMSXDQPBe39A
         FpmCyBgUjUbTrua+nqu71Oq5nJaYrqh+MfcTM/txM574kKL+UvJw1BbNKEbkDRKF5EJ1
         1EG+aMrtVRRmo5uGE8DOLuI+wOnsVeWGe5ygg/9VFBZ289jw2ujjmQ8M19GPziX2F+TZ
         X+Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=lcorQZgR62+DwQ6pI4wdYacZo6QQQGrxxB7jRee6ugg=;
        b=LVkv9u4DwdWGFKi/PH1ssP5eCvDgnxafoFM/WJafeUJudN6Z/khr4WpF6au7qBkcbO
         y4nZMBQuFjQlr1yehhX7Irrc/fwOEHlM1C0klnuXUqi5tG4GXP6gMznf/OWoZGe2zMUV
         vhhcmocxhdtUnKQgX/aAMScjtDqpHVAXPISUcrK9639kubSfcXLYiiZcOXT/9UTjF20o
         L50XdRHkWaZW2Mh/52n95OOrGsFrXpstG8eIkD37OSTnMUyLfTU9uoHyXywID423ni4q
         uxHNBI0A7OnGJtZUHVodUQjljLs9ZZ6RF98gAV1D4PpudZbqs2M8ZW4pgcF92/RuLIes
         7Rug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DbSXe40l;
       spf=pass (google.com: domain of srs0=olvk=xx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oLvK=XX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lcorQZgR62+DwQ6pI4wdYacZo6QQQGrxxB7jRee6ugg=;
        b=PWB2asjy647dEOsbFo1SIqtM+IAAmuH5hxZlC8pOmUVOz2+SgmYc/7IPcfjO4wukM4
         WIwTpMtXH6WGMgKi+sl0Zod7YSP+cd8KaO7OFLRu3yl9kF+Azv93G1qYO1FSYd4lvy66
         z550g4RF2K3fW0FYx7vAzKvvO5ijJiB0CX8QZCDxSjTGXPSB4xPUSR65/BRkAhNMxekY
         P+rQMnA8UWa24RkXQyV8TkUFy5eUa3DiB5ie88ziDq7EH3ZZAbc/AWlneGi8/+Xhkdxu
         EpU43G/F+jsWZEc/qdsJ8HUjDKhjCEmBishi5ATsbidXHsuss447oaz95wmdG9T4PsX0
         u5KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lcorQZgR62+DwQ6pI4wdYacZo6QQQGrxxB7jRee6ugg=;
        b=wjBwp7OgkXVlz+fPLgYzo0vFeixX8j4VdN7KD+pUUhgwAg1oaD7GIOIHqVaRXIw80j
         9VQ87PT2Ro1qccpkqf6yuGrjaLNRbextl3jL+Zn7hZZRsG4EpW3TLMR0ia0ZiYFzj4KI
         7+JJqr5g2/AjO2zm19Ys+21b1kXH9rUQINm9NcJME0pViN9t98OF/eePIOVaPaPVZ/jd
         HHoFPJZJVV/X61iVrCj53luodqAyK4G7DUb4O7ICMk8BwH6W1dev8KYcKa+15WdctVQQ
         4Ozzv8y138AfRBTwu2dX0+i/93T6Bh6XEz09662xv7RYMdzp+aKtgD9EM4OlbLaeB+/U
         KrLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9D8K5RTmPby3wh1fI/OC06cgA7DmHD6N7m9Py45jUe21EuAWVT
	JjHifDFjBTy2K0otJeqWYaI=
X-Google-Smtp-Source: AGRyM1srkpBgDvn10Mg07JHYZ77a6AhYuB6hdALxxmWfSxdbNP83eft0aC+cZyD89oMb5zP8HafVhg==
X-Received: by 2002:a05:6871:7a1:b0:10d:1f0a:47e8 with SMTP id o33-20020a05687107a100b0010d1f0a47e8mr8028137oap.150.1658160363466;
        Mon, 18 Jul 2022 09:06:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e506:b0:f6:14e2:9af9 with SMTP id
 y6-20020a056870e50600b000f614e29af9ls205276oag.3.-pod-prod-gmail; Mon, 18 Jul
 2022 09:06:02 -0700 (PDT)
X-Received: by 2002:a05:6870:a91d:b0:10c:55e:3f64 with SMTP id eq29-20020a056870a91d00b0010c055e3f64mr14927449oab.123.1658160362938;
        Mon, 18 Jul 2022 09:06:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658160362; cv=none;
        d=google.com; s=arc-20160816;
        b=qGjOTr0yLE+57tJ9uNVTMjXe+CSX5upfNosFRMTuQ2WuHdMgZgN7JzJkOwV8xQlrKx
         +CjL6/YpDiJnoS6Rr9a8wDPG3yZC/u5OekVtdj236PU+honzG0oNAz4rtKCuJ3lpmxB8
         aQ8o5bE6VDOadRWvfueHkszc7GsJguHCJbWqFuZ0EUZcsEWejsMVSzw35uzHKJHupguP
         2RZI4LO1x+RO8lxWS+PEDUIzzKfN+amy/5iBWlY3+o+OE8p5pFuzRQY95JSg8qFxEXTL
         2Iz2VU9nVjo/mFla3gaKq3UMcbza12JIgLIUKUfjk1Z+OqLgnFuTSYlO6qj+jjMM1+mF
         d7Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YJwMoc0T36o+/9m0Gy13PkmnhBQmUPTD6q4AjLzdR0g=;
        b=frJVtgRJuByAZ9pwFoSSVfUOsMfwZIDOFkJhikmcz0fs+T3+VKevnT1k2T7LMRKXdp
         1mVf/j1HDIrOnsPIDvf/1jHJA97YxlJagwXblif0oPx0ea8sjnFM7jAlj/PM2JUNRtKE
         nSNI7eJleBm2CSPd9jGohUw4Sxw3oByc/qSv8b3LfVkzFYAL+ZQtYvf8N4XsPE+atg7j
         +PFB6AQFVIQcJNqJ7BhrpIDTOBy3LPwMZqRWlgywtaanTKSOugg6z2A6eLKMqWWsU2N5
         lIxZgOIJjCZkelfSgg6lgk1emCMpQIQ5kLPCpFnLTtfLveoRym+v1YNXHSTDn0roo4eZ
         HWWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DbSXe40l;
       spf=pass (google.com: domain of srs0=olvk=xx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oLvK=XX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z14-20020a056870e30e00b000ddac42441esi1395434oad.0.2022.07.18.09.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Jul 2022 09:06:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=olvk=xx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A51946142F;
	Mon, 18 Jul 2022 16:06:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DE40BC341C0;
	Mon, 18 Jul 2022 16:06:01 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7724C5C0833; Mon, 18 Jul 2022 09:06:01 -0700 (PDT)
Date: Mon, 18 Jul 2022 09:06:01 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Petr Mladek <pmladek@suse.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
	Thomas Gleixner <tglx@linutronix.de>,
	Johannes Berg <johannes.berg@intel.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Linux Kernel Functional Testing <lkft@linaro.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] printk: Make console tracepoint safe in NMI() context
Message-ID: <20220718160601.GF1790663@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20220718151143.32112-1-pmladek@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220718151143.32112-1-pmladek@suse.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DbSXe40l;       spf=pass
 (google.com: domain of srs0=olvk=xx=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oLvK=XX=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 18, 2022 at 05:11:43PM +0200, Petr Mladek wrote:
> The commit 701850dc0c31bfadf75a0 ("printk, tracing: fix console
> tracepoint") moved the tracepoint from console_unlock() to
> vprintk_store(). As a result, it might be called in any
> context and triggered the following warning:
> 
>   WARNING: CPU: 1 PID: 16462 at include/trace/events/printk.h:10 printk_sprint+0x81/0xda
>   Modules linked in: ppdev parport_pc parport
>   CPU: 1 PID: 16462 Comm: event_benchmark Not tainted 5.19.0-rc5-test+ #5
>   Hardware name: MSI MS-7823/CSM-H87M-G43 (MS-7823), BIOS V1.6 02/22/2014
>   EIP: printk_sprint+0x81/0xda
>   Code: 89 d8 e8 88 fc 33 00 e9 02 00 00 00 eb 6b 64 a1 a4 b8 91 c1 e8 fd d6 ff ff 84 c0 74 5c 64 a1 14 08 92 c1 a9 00 00 f0 00 74 02 <0f> 0b 64 ff 05 14 08 92 c1 b8 e0 c4 6b c1 e8 a5 dc 00 00 89 c7 e8
>   EAX: 80110001 EBX: c20a52f8 ECX: 0000000c EDX: 6d203036
>   ESI: 3df6004c EDI: 00000000 EBP: c61fbd7c ESP: c61fbd70
>   DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00010006
>   CR0: 80050033 CR2: b7efc000 CR3: 05b80000 CR4: 001506f0
>   Call Trace:
>    vprintk_store+0x24b/0x2ff
>    vprintk+0x37/0x4d
>    _printk+0x14/0x16
>    nmi_handle+0x1ef/0x24e
>    ? find_next_bit.part.0+0x13/0x13
>    ? find_next_bit.part.0+0x13/0x13
>    ? function_trace_call+0xd8/0xd9
>    default_do_nmi+0x57/0x1af
>    ? trace_hardirqs_off_finish+0x2a/0xd9
>    ? to_kthread+0xf/0xf
>    exc_nmi+0x9b/0xf4
>    asm_exc_nmi+0xae/0x29c
> 
> It comes from:
> 
>   #define __DO_TRACE(name, args, cond, rcuidle) \
>   [...]
> 		/* srcu can't be used from NMI */	\
> 		WARN_ON_ONCE(rcuidle && in_nmi());	\
> 
> It might be possible to make srcu working in NMI. But it
> would be slower on some architectures. It is not worth
> doing it just because of this tracepoint.
> 
> It would be possible to disable this tracepoint in NMI
> or in rcuidle context. Where the rcuidle context looks
> more rare and thus more acceptable to be ignored.
> 
> Alternative solution would be to move the tracepoint
> back to console code. But the location is less reliable
> by definition. Also the synchronization against other
> tracing messages is much worse.
> 
> Let's ignore the tracepoint in rcuidle context as the least
> evil solution.
> 
> Link: https://lore.kernel.org/r/20220712151655.GU1790663@paulmck-ThinkPad-P17-Gen-1
> 
> Suggested-by: Steven Rostedt <rostedt@goodmis.org>
> Signed-off-by: Petr Mladek <pmladek@suse.com>

From an RCU viewpoint:

Acked-by: Paul E. McKenney <paulmck@kernel.org>

> ---
> Changes against v1:
> 
>   + use rcu_is_watching() instead of rcu_is_idle_cpu()
> 
> 
>  include/trace/events/printk.h | 9 ++++++++-
>  kernel/printk/printk.c        | 2 +-
>  2 files changed, 9 insertions(+), 2 deletions(-)
> 
> diff --git a/include/trace/events/printk.h b/include/trace/events/printk.h
> index 13d405b2fd8b..5485513d8838 100644
> --- a/include/trace/events/printk.h
> +++ b/include/trace/events/printk.h
> @@ -7,11 +7,18 @@
>  
>  #include <linux/tracepoint.h>
>  
> -TRACE_EVENT(console,
> +TRACE_EVENT_CONDITION(console,
>  	TP_PROTO(const char *text, size_t len),
>  
>  	TP_ARGS(text, len),
>  
> +	/*
> +	 * trace_console_rcuidle() is not working in NMI. printk()
> +	 * is used more often in NMI than in rcuidle context.
> +	 * Choose the less evil solution here.
> +	 */
> +	TP_CONDITION(rcu_is_watching()),
> +
>  	TP_STRUCT__entry(
>  		__dynamic_array(char, msg, len + 1)
>  	),
> diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
> index b49c6ff6dca0..bd76a45ecc7f 100644
> --- a/kernel/printk/printk.c
> +++ b/kernel/printk/printk.c
> @@ -2108,7 +2108,7 @@ static u16 printk_sprint(char *text, u16 size, int facility,
>  		}
>  	}
>  
> -	trace_console_rcuidle(text, text_len);
> +	trace_console(text, text_len);
>  
>  	return text_len;
>  }
> -- 
> 2.35.3
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220718160601.GF1790663%40paulmck-ThinkPad-P17-Gen-1.
