Return-Path: <kasan-dev+bncBCV5TUXXRUIBBOMOT33QKGQELNPMFTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 835BA1F9A5F
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 16:35:39 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id q24sf13323801pfs.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 07:35:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592231738; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNlwjrjiHyfw6ufOf2rP7p56nLuCbjVFHVpDPFwB+cymhtwOgXv7bIwJVJXuhYaB0D
         DtX1/GW6K8YvuAiJYMjPsxF6Y/zieq5Y+/KNM1RBpuMKvtIw00mJ2yM/RUZnQ88ciUyQ
         9uLGc4vkBaear/vi8l7Q8Q+jGHyql6xXPO+ST+ABQYgE5Jvhs84sPgaGFYSUFKaw8rdD
         jDbtcxz10bYZ4Rz826rKq9T4pg232ukuklireWdc2R/qsabN08X4fP7FLuTleu9iuMEy
         cgUfB8W/kb5eJi5pPMZVa54pWyNECCJk17FOASVo9CbOTIZ9J4ddJ1KbhYgz1I846ajz
         DSPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RigNv3Na5oQeMdazJHjoKfR7Wi5cQbNNKHgKv2OKGYs=;
        b=dwDyT3hHQVi8wfCewWRKffhLQEzi1/eEKvN0B41/d3JHmOlVaoEa+mvyPzgoV0OI5C
         H1oyecqjl39zVhbNowNs/PSdF26tvYMWCgIu/dUKgsQ2wQeiBi5R/5ZVvZD+rnFLhslp
         gDrHm9hAT9d4sfRm1ZUL0Z4VfkGG5j6HDius3khkQN0GIRMH0gDNSirDF6tbqT5r62hj
         C4pD74we7ceh8RBOaG0EKPEzGQX238YmTuE4DP7Md8gxibzWuSeDROwYYI26yZWqLU5n
         1AxyOI2/E4rLh7ObGmuK53uPSeo89IkspNhjf8oILuxM8yE5DLGPjLJHHSnYnWO8F6Fh
         xRbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=dt0mlxnY;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RigNv3Na5oQeMdazJHjoKfR7Wi5cQbNNKHgKv2OKGYs=;
        b=Zh67MAWAc+w7+N610xkstORapek4oP8KEqCeC/YHd8fpdFkcYlsQWVic0reuwcPHYs
         1clPG/uPD587q/slt2l6jYYW0CPPs97+3w5kQqCrB9WBiVBDbrA5at4wOIFwFgA5QQv3
         BLXY4SEvnqq2tXy10AWe0UiCBN13aFn1aMnzJyYsxQjSzVw9haPR1AF4EK1caLP+sU6v
         6eMRtnDXH+mJcd2ZXZ7p6da7m4/9McO/MpJ42KYq9/2xOHIaNakpUB2bg6yW805HEvZz
         QaLaa6nCpfwL9n2n4CAhvsPGHIDuJQnaOt0qbbbZL9vDqHBT2xlYCwj2AiTkxuz0mF37
         8Wqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RigNv3Na5oQeMdazJHjoKfR7Wi5cQbNNKHgKv2OKGYs=;
        b=ZL3ek9u3EbuomARL5LrxNoZtKhGpZWCmQhfT94H9P+KTERSAT3qsBR21XrYrqzenDy
         XMLx7KlVTWdXpQMat015LxyHZoKwPimdGZeLEGR6ow13WCqXc0AyoVaeqjPcEbQNiOFJ
         6oHoIcEyfmljat5DFMQYXNrEo5MXvvdrg7aQNrZ/7cs1EN3Z6lWO9GBVsIPIr1S7+349
         mIEVsgI4yXnbHEMvne3KokFMd35fgyasEmetKn2nE1Vusb9CvlyyZtecf3hxdVO5h67i
         LF0LOMWPSA5zkVEYei9h3QECdW6o4e/6bEsUmqQ4AQ5J5nT06o2SWNJplpKz+GD1WOcS
         zC9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533R/fWWx0yqru7o33WnXHXQztnei6qEKzk6fNp2Ihll72MCSpaa
	oPFDNcs2Ax1dP/jYg85BbmU=
X-Google-Smtp-Source: ABdhPJwj8EhG1zIf8hAYrj99DZL0TnE+7gQWko6PMsLX0SJp03OdDZ2vIWZ7pytnn5XX+UMpbYceNw==
X-Received: by 2002:a62:7a4a:: with SMTP id v71mr24110027pfc.35.1592231738059;
        Mon, 15 Jun 2020 07:35:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:94b5:: with SMTP id a21ls4104303pfl.5.gmail; Mon, 15 Jun
 2020 07:35:37 -0700 (PDT)
X-Received: by 2002:a63:b915:: with SMTP id z21mr12189351pge.145.1592231737450;
        Mon, 15 Jun 2020 07:35:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592231737; cv=none;
        d=google.com; s=arc-20160816;
        b=fshLhoQSI4WHniaavB54vVzMFzpUsfR5lYBzukZX2lhLxvVXGkjBf5eJlbFliaeZqY
         8esJJNlqi5g6de7WCEeB5/T5UMKm66ng9M+vNlFFhh0tXfse7WihUzC8DG0tD59xP1Y0
         ml8NBclNynnFH0ybB8ZxUBp/LccjSZXT9gi/8EBJ2P1tZoL6RM+QnDi80wYi73TvaVIw
         5pZqHuoljXA/TB+ztsn1jWkKlg/8VBCMH+xd72LgPBGsuOV3wQXX+UViAvkYXbjNrrKZ
         x0CgYvnvDGnxdzf0mzq3UVtHhhJPl7aGSOyVmGUKnr1ERbzeEKgdNvSKdiPylFmxlX6i
         wXIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CNJqcR8O2MGARUu3ztkILAgDD+9fnJBIlgO1t0ryM7s=;
        b=aXuiZmWevMgtef/hCJ90T4gTLhCEG6k+JgQB8WTQ82Xt/8TenuyCd2zBWi0cypH2Gq
         Q/ebo/9CWCQdUQmWa6FZ+D0puc95X+pV0QQN4rL3suUq7dkJZahVgxGyKfxjco3wEAMA
         WIlwuw865QGhO/pO1FK9HqhZot8INEtIaFp7sV7dwMCAzWhSux2VAG4ZPDWBT+j0R6ym
         TA0IRLkRzBXWnImvA8SQbt5T2MH0AgphpPQTh61nLY7Qt0qG4unOHqfZNELPYYZ32CqF
         nrGexb+QeVKlhrHtH95n7Bja4l9SoJ1mAip+cuhIsDjOcKa882WsEQBGBoIvr9S6MbFK
         AwFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=dt0mlxnY;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v197si995654pfc.0.2020.06.15.07.35.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 07:35:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkqCr-0006Q2-GC; Mon, 15 Jun 2020 14:35:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E119C301A32;
	Mon, 15 Jun 2020 16:35:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id C7117203B8172; Mon, 15 Jun 2020 16:35:23 +0200 (CEST)
Date: Mon, 15 Jun 2020 16:35:23 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200615143523.GE2554@hirez.programming.kicks-ass.net>
References: <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615142949.GT2531@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=dt0mlxnY;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 04:29:50PM +0200, Peter Zijlstra wrote:
> Let me go look at your KCSAN thing now...

vmlinux.o: warning: objtool: idtentry_enter_cond_rcu()+0x16: call to is_idle_task() leaves .noinstr.text section

---
diff --git a/include/linux/sched.h b/include/linux/sched.h
index b62e6aaf28f03..a7abc18a7d0ad 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1663,7 +1663,7 @@ extern struct task_struct *idle_task(int cpu);
  *
  * Return: 1 if @p is an idle task. 0 otherwise.
  */
-static inline bool is_idle_task(const struct task_struct *p)
+static __always_inline bool is_idle_task(const struct task_struct *p)
 {
 	return !!(p->flags & PF_IDLE);
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615143523.GE2554%40hirez.programming.kicks-ass.net.
