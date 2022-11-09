Return-Path: <kasan-dev+bncBD66FMGZA4IM7QFQTMDBUBGAK3MRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B0C1862360D
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 22:49:03 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id h18-20020adfa4d2000000b00236584fc8c7sf5308218wrb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 13:49:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668030543; cv=pass;
        d=google.com; s=arc-20160816;
        b=HFZEIHUuW+WE3RDK0yEn5Qgq4iBvOYNpV60OY+FGCOw/ojjuTnJt1fhol1cs6wq2px
         rdItXYgC35OhhlHgkhABMLvW0dFW8ULUJfZQ37rY15m1H0+QqKepBtmCRK9D1XBkP5Yw
         kZSLHe7NU/0s8+SV8GU+FwP5zD2KiWhIs5ng+w9V60gdgaIsxi+PY9SsOWemkdGiRB4M
         fK2a0cdQFq4G7DH3rdeJRFCOD3zAj7AnuJi4DNQQg2VkuUacXh/kH7vds4M8E4l7QPeI
         8gu8ieCuINlbhRuKsTPlVe+FpkG1giC/Kp8h3/BZagTVmVStTbjCsW8dbLJFDCF28BX8
         vQtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rp4Krhc0lEyfuFgMA7MgxVgYLn2ffOuDoTOrbP6KDeU=;
        b=bexf153bm6vrQye0pMmg2K0+nhRPrnvCJ3lVKdWNmmBCov7Vjs53Qrnhx9LwJEoj1n
         l+s6+u5ZMrL1WOFT33jSXaVKqN5K/KMFU26bAV3WDMUNBPzeMFhxgvlVD+nOSMQ/8ZxW
         F/q1Lw6IsHknZ+EsJIM2Q1uj6jA4OlPCGe9AM4qA356sLifObmrMmnHanAv5ILPMC7JA
         iTxPoBf7qKpRXB6sq3AIHYaT8smjQbvLK7rJcC6sMP3JTjrHtVjMwwKCyvhuFpxtThzh
         B30RFJB/mJ7zJXdPx++gZeAveZffW3N+/sogY2q9bQZ66BHq+Suxzy3qTtmg+jgS7s6o
         i9aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DO9FR6ZD;
       spf=pass (google.com: domain of morbo@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=morbo@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rp4Krhc0lEyfuFgMA7MgxVgYLn2ffOuDoTOrbP6KDeU=;
        b=bTbYVJD1QBDOnI5nV4kSP3sl19QvnkPBjdjg3I8ha5GF4gNZHLq/w2s3FBqOIoXo/Y
         LCetX3y2WLZM/EJpgk+QzDWiYw9gOCWkOHKf+JRoevWYEznmkIjFwRsGmNjgU83SwOnb
         e/tN+DW71c23+TLFhwOckOfr0+k3P/mFbE+gNT6/Ns7iZXqpFbi7qo8hyjIEW68RREfo
         VVa9v2uCV5InGpqTKMks+IX3cLHsjMIkvO0ddf+vN5WIxzkhPCnvWPASu1/1DAQK0Y4q
         7RXf1T4KPvT9ilUs4s4S+lIFuXwskZzb7lAchyY6yRwSjQ5KXj3R1lelhDQl+t34boa1
         HZTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rp4Krhc0lEyfuFgMA7MgxVgYLn2ffOuDoTOrbP6KDeU=;
        b=uJynVzjBP6p3ylAI2QHaltw8GqOL1cdWQ1nBuH4ipqXQ2i0TyM31+pLNKLtqtKqSUr
         eraQdtxiOiudawT+w54jT8gU+rDJC4JEoMqyo41SXqAFpm4kWujfP+PqLPvKUBhISPRE
         63KBjM3m4YdFUCXnywkBwAV/uAW3QKnnjdFldcOCvTSmGbVc/me9njwe6kJcQHtPcBSz
         BR+94Eps0ANdUv+s1Ij/rSyWt8ZBwOGJ8Tn5bcW2er9swjnMp/uFGNg83nsvHdLMisaq
         ieGaHVRbRSDcyKTchYaY/XRkJkBPeBZOOu/SwKdT8/qf+bGMrmSOvUBZR0Xgco5jOzKI
         posQ==
X-Gm-Message-State: ACrzQf0K4PFPdXqnNmOEJm22QyUHC4IzgRYdyt7e1388fpyKCDuLw5+K
	DNi/L3EDvukApzOL1lIwfzc=
X-Google-Smtp-Source: AMsMyM6TmMEJbtbvk8eBWZYGg6Z8uvMQea/ovJkcyxatkL+MkYx50jH/0Et1W5a7vb7a6pcZGdbwig==
X-Received: by 2002:a05:600c:19d1:b0:3cf:4757:fc3 with SMTP id u17-20020a05600c19d100b003cf47570fc3mr971973wmq.172.1668030543240;
        Wed, 09 Nov 2022 13:49:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d231:0:b0:228:ddd7:f40e with SMTP id k17-20020adfd231000000b00228ddd7f40els267008wrh.3.-pod-prod-gmail;
 Wed, 09 Nov 2022 13:49:02 -0800 (PST)
X-Received: by 2002:a5d:4952:0:b0:22e:4a4e:b890 with SMTP id r18-20020a5d4952000000b0022e4a4eb890mr918494wrs.554.1668030542262;
        Wed, 09 Nov 2022 13:49:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668030542; cv=none;
        d=google.com; s=arc-20160816;
        b=PBOTPq6iWnkIaNGTpu1b/4ddk20W25F56ZtuM9+LE3hhZU3qyWxMUXNUkNdLnUkank
         JOWWmTOH/zWmFyK7YE8dhc1BFJv/5IA6gF9y4iOn8EoOlvxypTIYW0eVlB1jffGdMw8M
         HBMA4WishU/vtr6ZbvBqt7W+mUnCfTpDZ82TFG5/3OfEBP1ZrnZr9+k7sUCDXk9XGhUL
         uB2tCCHhWpEMoo/BnJEi8+lcGu/E9OKpvwktzTQgjtC7WRRzEnppal33WgoGFMYrzOWW
         JrP1Lw5W6yGtNvw/1s0sQ94Jo7wSUx6yKc0PlALWqKHgtHMDmLsYOnBv/HCfuYBxdmSU
         Dn1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cnCKimjPnszuIv7P7tspkRhy5Ca1GNkxCTByBpzQ+sI=;
        b=ddTwnBY08yzuaRw7NzjuayiEroIWsM3AgnKUk9v8Tlz3gd4LWqR1duGReAc/vtHYX8
         n9y/uPGAXnnUAWpcEvkC5H0l1/KEGs35NPTGnr38/889Pj9vEFZwI4at/8ZUuPYB33KU
         2OOgf35tSWpp0NT+4uqlW1hQbndAp3I5w8FF7OKXaYZ3K+WszcHNYEUeSxXmmU8FDmJO
         yKUZ7Pajn8x/0fv+UynWnfH3eDGM+IUh4CiKPZJ6DCWLMJF+QZoMMZ3XELoPP9cJucr3
         wyuDp9nF2yoU4c8vW+T71c+5wxVidq1rrDXtTYPy38JGnT/IZbwpQtMl3H2B3nmMu7Ng
         7KzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DO9FR6ZD;
       spf=pass (google.com: domain of morbo@google.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=morbo@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id by9-20020a056000098900b00239778ccf84si504653wrb.2.2022.11.09.13.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 13:49:02 -0800 (PST)
Received-SPF: pass (google.com: domain of morbo@google.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id k2so347547ejr.2
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 13:49:02 -0800 (PST)
X-Received: by 2002:a17:906:c839:b0:78a:d0a4:176 with SMTP id
 dd25-20020a170906c83900b0078ad0a40176mr1831678ejb.720.1668030541823; Wed, 09
 Nov 2022 13:49:01 -0800 (PST)
MIME-Version: 1.0
References: <20221109194404.gonna.558-kees@kernel.org> <20221109200050.3400857-1-keescook@chromium.org>
In-Reply-To: <20221109200050.3400857-1-keescook@chromium.org>
From: "'Bill Wendling' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Nov 2022 13:48:45 -0800
Message-ID: <CAGG=3QXM3u_uz1fuW2LzvrZqqPhYL15m+LJgD39R=jkuyENmYg@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] panic: Separate sysctl logic from CONFIG_SMP
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Petr Mladek <pmladek@suse.com>, 
	Andrew Morton <akpm@linux-foundation.org>, tangmeng <tangmeng@uniontech.com>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Greg KH <gregkh@linuxfoundation.org>, 
	Linus Torvalds <torvalds@linuxfoundation.org>, Seth Jenkins <sethjenkins@google.com>, 
	Andy Lutomirski <luto@kernel.org>, "Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Luis Chamberlain <mcgrof@kernel.org>, David Gow <davidgow@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Jonathan Corbet <corbet@lwn.net>, 
	Baolin Wang <baolin.wang@linux.alibaba.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Anton Vorontsov <anton@enomsg.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-doc@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: morbo@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DO9FR6ZD;       spf=pass
 (google.com: domain of morbo@google.com designates 2a00:1450:4864:20::632 as
 permitted sender) smtp.mailfrom=morbo@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Bill Wendling <morbo@google.com>
Reply-To: Bill Wendling <morbo@google.com>
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

On Wed, Nov 9, 2022 at 12:01 PM Kees Cook <keescook@chromium.org> wrote:
>
> In preparation for adding more sysctls directly in kernel/panic.c, split
> CONFIG_SMP from the logic that adds sysctls.
>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  kernel/panic.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/panic.c b/kernel/panic.c
> index da323209f583..129936511380 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -75,8 +75,9 @@ ATOMIC_NOTIFIER_HEAD(panic_notifier_list);
>
>  EXPORT_SYMBOL(panic_notifier_list);
>
> -#if defined(CONFIG_SMP) && defined(CONFIG_SYSCTL)
> +#if CONFIG_SYSCTL

Should this be "#ifdef CONFIG_SYSCTL"?

>  static struct ctl_table kern_panic_table[] = {
> +#if defined(CONFIG_SMP)

nit: This could be "#ifdef CONFIG_SMP"

>         {
>                 .procname       = "oops_all_cpu_backtrace",
>                 .data           = &sysctl_oops_all_cpu_backtrace,
> @@ -86,6 +87,7 @@ static struct ctl_table kern_panic_table[] = {
>                 .extra1         = SYSCTL_ZERO,
>                 .extra2         = SYSCTL_ONE,
>         },
> +#endif
>         { }
>  };
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGG%3D3QXM3u_uz1fuW2LzvrZqqPhYL15m%2BLJgD39R%3DjkuyENmYg%40mail.gmail.com.
