Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7LV34QKGQE7GXNNHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 03A1C23D7A5
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 09:47:32 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id sd23sf10242953ejb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 00:47:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596700051; cv=pass;
        d=google.com; s=arc-20160816;
        b=JWPEP92O9h909KU/c6jJ6xW4bYt9KIUlCaqKowCJQZWCi9L2KMAUQNTnrZ1cLckRf+
         dYthcIq/yNMzXzuq9fHK0zU9Iyue86Z4ZXSiikU+898MdgQlhgr+q7qTJxN8opK26d+q
         unkNMQhOhSmr6MFf/6DV4+K+sH3PXhenbY8IP/UplRTz2rZKVtDwgFHUDacrPRDheIdw
         y+zs1AsEA0rKZXr653fxA2TIsh0PDW2AIBBmDwDwqq8MUtR/zZlPW3s1+LbHFm2O6G6I
         lM8DM+QvbhuB8yXhYQME0MyfsikRvKk7Jeu+hpzgiNmuCpXr/ZAW/+bKl0qXSBw3zTBq
         kkdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=j/O5XbUhawqn9bNCqxM56TUJL4mirj73xFpitw0bsRk=;
        b=qOSG1ymRW4qoBzhreN8ngqZ3wnZRezzz6tdTau1vokytLBcK7jMYBAoSoSXcFhHB1L
         9yVWokK4lTmgFq0bmYYXGq1XPZleeKOZnU3EOq2P3GSGuEatJ10x+Al7z4IZtYZhRo3H
         BlvJTiDt/sd0ndjAxstLzHpfNZTYdFrMODquMaoMXOBe/Yg8ZCAKrh5w5XCfs8gAKBAP
         MAkLIshc3k7evcGi6Zhckryr40hyrDI/pejDp4f92BZgciOoCJzWCQklB7nCvoIqaIa/
         S5TieSDEOW9RA1gNvgzdsAsMD2U+F88P3UG7LJqZ976a1o7s8aarzMLGa7S1nociSMpk
         q0Tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=huIdmLYi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=j/O5XbUhawqn9bNCqxM56TUJL4mirj73xFpitw0bsRk=;
        b=nAs0c3WNN0SPd4YYoZp4EMs/u+bv8FXpHjCpEk0/wHjx3TbNIL41dB4otz8A9UcIgu
         /r3LV4MwVz8sIsaVYzCA7RIb1eMmFh2g2BcW+kcgzJWF3j0BV0Yq/SGnr+k5KPvMaeu0
         ovE7npwWWZQjJ7DzFCkP9AdaZ2DodYC84wcrsabUXT/743aYUJdgI075hloQD313W1ep
         7jF6cXKaySdvYNd/lyz4YfMBJIyXWCyhGh2ovIYz4OaraOQ+0CTSZy0nvZDir1rIu9aQ
         N6PrB0zq2P+6vnutFxrqq1At7r0vOVBeyk3Dggs6OXDfEmyY4nb/UEinLv9GFP/plgcS
         HUDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j/O5XbUhawqn9bNCqxM56TUJL4mirj73xFpitw0bsRk=;
        b=LryczoTEDrsy6o4cIYYa66kF7FpwC/xO/mY9GeXaXaf7tihQLscNZUXpAlkZpo7fdf
         GJGbZe6jTKC3qWR6TLRC7CA5fitM+ojaSNXWPIahVu/po6Gn//7kvBVnHrtZ6agzqm7Z
         EDkuXDsDps+pnRxA4nC6VOkhK5gjp+csi8Hp3CTKVxMQfu/SN94T+eNFUlfqcplyfAfS
         Ehvr1K86cga0eGnV8IhLr83rpqkugAw28O6xpNXVj9ZxuwisYhCeUi2CFR6cy0piwFew
         crLIXVpmHbi0movRkbtRo6LU07cImIU+u5GscDjvk1KOrrJnZeB1dYPs8kWk5e7dZAbL
         ecOA==
X-Gm-Message-State: AOAM532BOOCDaqOxMtEt+2Q8u2a1zIGwoYXIO6WriUliDjO3N0TbPJMC
	673AbGHL/zTYxpM2omtT8B0=
X-Google-Smtp-Source: ABdhPJxWHDC+AOzgRsxe/ayj0mzV4MuIf16ge8T6JpwmY/Fm6IqrAEyToZXiBeTTtrA2KSQbaGwn+w==
X-Received: by 2002:a50:8fc4:: with SMTP id y62mr2787170edy.170.1596700051717;
        Thu, 06 Aug 2020 00:47:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:b01a:: with SMTP id v26ls2369903ejy.8.gmail; Thu, 06
 Aug 2020 00:47:31 -0700 (PDT)
X-Received: by 2002:a17:906:c8d2:: with SMTP id gc18mr3352266ejb.24.1596700051171;
        Thu, 06 Aug 2020 00:47:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596700051; cv=none;
        d=google.com; s=arc-20160816;
        b=slcwx0vmteZP+l4ZI6EyeBQTbFMQERToJwEfM6fmlj+JGkj1kX8R3enbENPWiNsJUa
         GPtr3C4Bz4IlQldjq614jrSTxGXF5yznVgrxIeCK/FtnNhN4rv3KWbkzn5LIB3bSbMF/
         Z+gommTJdJosEQ9AT9fa/Syled7cdeCkBaLP7utcLq7iaH620EcZaY9sXdiKYSXizdIx
         SGw8qI5AqqFA5JJrswb2Ky0U1NMIgMR3GeuIeGpXZbLXQbB/cJMbJNRi6MUtKpZ2Qea4
         JGU+bRAIQMutrJbpw6BDpvakY/cPME/1VXActVuucbomPx579fhXtDwcAgwKTv64dyD8
         ew0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HHOPpgbgSKjDTGkpjqLc9R9y62AcGcDlV5geHTzbj4k=;
        b=VZVZxapJsQg2dGw8nGiq/YDcHeTNgPLYUCm8SvfVQk3UTuaHf2lWV/YX4w9UcAi7Vf
         H8I9pWY06fRmE+5RPWieXcfCcWLKRlkLcGSbyBY84hwzw5cJj2JS775t6ea60gfFLYk1
         LOGSj0PW7YwWtD1t69vm4OB2VNfwlZKQzebGZ0aVmqQ0Q0t/7sCYDQIbmQ+DTZxvP0zo
         d/xjda/74NEYHtlUUbqr4aMu1vZgYeIHIiHG6lhgBEZjv7+zIcVi+yct4M/rtzZkCdD3
         sdH0Gzb3r4BEek3m3tPgUpaApqXs81kx/F+lun0Or6phuqCIy0/YxdXcQZV4BA0k+p7M
         /yiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=huIdmLYi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id q14si242989ejo.0.2020.08.06.00.47.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 00:47:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id y3so43020007wrl.4
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 00:47:31 -0700 (PDT)
X-Received: by 2002:adf:e7c3:: with SMTP id e3mr6237105wrn.356.1596700050497;
        Thu, 06 Aug 2020 00:47:30 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p14sm5943332wrx.90.2020.08.06.00.47.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Aug 2020 00:47:28 -0700 (PDT)
Date: Thu, 6 Aug 2020 09:47:23 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	jgross@suse.com, sdeep@vmware.com,
	virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200806074723.GA2364872@elver.google.com>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
 <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=huIdmLYi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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

On Wed, Aug 05, 2020 at 07:31PM +0200, Marco Elver wrote:
...
> Oh well, it seems that KCSAN on syzbot still crashes even with this
> "fix". It's harder to reproduce though, and I don't have a clear
> reproducer other than "fuzz the kernel" right now. I think the new IRQ
> state tracking code is still not compatible with KCSAN, even though we
> thought it would be. Most likely there are still ways to get recursion
> lockdep->KCSAN. An alternative would be to deal with the recursion
> like we did before, instead of trying to squash all of it. I'll try to
> investigate -- Peter, if you have ideas, help is appreciated.

Testing my hypothesis that raw then nested non-raw
local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
below. This is at least 1 case I can think of that we're bound to hit.

Thanks,
-- Marco

------ >8 ------

diff --git a/init/main.c b/init/main.c
index 15bd0efff3df..0873319dcff4 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1041,6 +1041,22 @@ asmlinkage __visible void __init start_kernel(void)
 	sfi_init_late();
 	kcsan_init();
 
+	/* DEBUG CODE */
+	lockdep_assert_irqs_enabled(); /* Pass. */
+	{
+		unsigned long flags1;
+		raw_local_irq_save(flags1);
+		{
+			unsigned long flags2;
+			lockdep_assert_irqs_enabled(); /* Pass - expectedly blind. */
+			local_irq_save(flags2);
+			lockdep_assert_irqs_disabled(); /* Pass. */
+			local_irq_restore(flags2);
+		}
+		raw_local_irq_restore(flags1);
+	}
+	lockdep_assert_irqs_enabled(); /* FAIL! */
+
 	/* Do the rest non-__init'ed, we're now alive */
 	arch_call_rest_init();
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200806074723.GA2364872%40elver.google.com.
