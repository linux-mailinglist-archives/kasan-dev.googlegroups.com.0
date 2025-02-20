Return-Path: <kasan-dev+bncBCKLNNXAXYFBBZ5B3W6QMGQE5OSLSJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 27465A3DF85
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 16:57:31 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30a323c6748sf5867401fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 07:57:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740067050; cv=pass;
        d=google.com; s=arc-20240605;
        b=j1HV2E0sEYt+XvPtCTWOazmF93khpM2RB8daoFlgprWcnNLB8JireS8xQQGXvEi20A
         YEsp6LYxYhEaRXIZp7Th7rW7YWv95DB9h+Y2p4H2s2XU9//+qaH5U60dZnVz3sxnWqni
         kBsBxbI/t0QlQ3N18B+zMwJyLK5bbyztMjFBRhAWY98WvKMaPzHQ+lOAJs/vz9xsqoip
         bpLI8YK8wPjkrL+HIfzfFn7LR6iPIhkZa0I7VemscRI+B1QJIpT2zKIZx+Xdw/nRiV52
         RpuEiNpKRfCJHFjASsJSLMOwYRS8hPymswRjWjIZkAggqmMS/jbNjDRf/GmAebbw1x5Q
         bj+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GDLPlhjJleDsjiYYml5GgpA36u4TjFhAM0rkaO82vRc=;
        fh=5pF9wHTPvnc3fVD9vqIYzulYEld/f0/GajQA6gzaaP0=;
        b=I+WrMJiKX5SSD6q4n+NRVX7GzPF6LQKu5CnvSviWNlDnH2ScAzDsj3e83xpgbMYSQF
         3TtBuIIO3v5uwdCAU8wqBiEDtRuua/92C43W4hDoz61KI7PXV95g4IBq1NzTslOHBddh
         FhXjLx8IyddAjD36Q1Sh9blddmDNzo8QBbzsU4dd2H4aLKhrFxzd76IqBHDhLI8p+b0n
         zTU1UWnZ7AGX5LJvlm9pYQHxkRVPgUHUDyxgBJtJEtAF4Q+wTW0KBFLM+4M7CNhthPfm
         ePiCPk1dG9uxqAQaHQ8/+Pr8ZZI4klEpQHkKHfJtN93c1QA5bygHxCyI694GC4mZzeQz
         ZMwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="W/1NciUT";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740067050; x=1740671850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GDLPlhjJleDsjiYYml5GgpA36u4TjFhAM0rkaO82vRc=;
        b=hw1WObgimPd/2Y5uVA3CwqAbpRUWPnwTUSWngfX9TxWfiH0r/DdZsukmt8Ldc5bVdH
         C0eLhcUueOJyXD9/+gMAQZahNJqLop+li57dp5XVFipmO7/r5IEj3881rwJ6ijj5zB+U
         uwlePOhS2Gau7gqS5PQBRaL5cQ7txlfxQKfj3acEn9Nl7wqXzBMRlgxhPm7BQfqtPF1d
         GNf0k0WExgUvqBSLc7kO3rTG2+8ukPp39rv2+wVrNydDYK69wyIkAyBqN1akjfRp6CLA
         ujoq7bhlBKxorCwDAuffopxiEVbppjY6DEqL2pXQpwzOV9uHeyHCqLsvnDmWHz+avXqF
         WGeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740067050; x=1740671850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GDLPlhjJleDsjiYYml5GgpA36u4TjFhAM0rkaO82vRc=;
        b=IQy/Bc8NFyUWL8IyFaZswq8ihGUYfghZx+w9HBtytPnGlw26K28wpGcIHVzLnGcRhx
         /Yma/AuPHmLxRCXpVxAdLfXwCvpNkiKaPORB42QWLw2kU6hTxB4IoQ2Qh2oy9byGBWd7
         fSa3AV2aJP8GiNj5Q+vpT7UjY/skkjQQ+yOsjqoQImq0NjbDOqvG8sOcY3y7Qf7ws5tn
         ItTUXBYs84/zuhjV8NthnYfJGWpz8gzkWneeIgledqsOkbmd3rMusQhrPhb5XjSbmod/
         jLrEAQ5GPzALhZ6DQfyj7HY3Hx3eufEB8D0Sp+Q1Gaj6620rTzIVl3YqeF1IdZReWLOR
         wi3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrSOkqEGe6JaCDLRd/yxkObGiI8acHWgO8K/tzTooQr6tvDn03dnWd3WAMcU899dDg5eMu5A==@lfdr.de
X-Gm-Message-State: AOJu0YwZ5XOnxcFI4SsPk/1Fs56N2LmIeM5IBIZ1ZTZbxcyS5+nfeqsz
	wOTEqWWKuAfHYDyXPDXOs6Q338HVePgTtZToJL3+UFU4ZS1vRfHp
X-Google-Smtp-Source: AGHT+IGrS61/CxYReGi+ldzIn9P/WoYN1xil/x6JVv61afmuNsbPR7CbbbcAf8uBvpQYxXk7xaOqYw==
X-Received: by 2002:a2e:b60e:0:b0:308:f4cc:9505 with SMTP id 38308e7fff4ca-30927a577c6mr63213001fa.2.1740067047645;
        Thu, 20 Feb 2025 07:57:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE7m2oQVnKNW7CUrWLbfHoQoDpti7Pkamkg/eSmwUAbdg==
Received: by 2002:a05:651c:2108:b0:30a:2c11:1241 with SMTP id
 38308e7fff4ca-30a4fe87bf4ls2754181fa.0.-pod-prod-04-eu; Thu, 20 Feb 2025
 07:57:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWU0gtctEJu9Jx+j7QCnkdIvDIddKMMmYp6Jdm5Aeajtrk6CSR1JItM6rM056JFT7jNoOBy94BFEGk=@googlegroups.com
X-Received: by 2002:a05:6512:ba6:b0:545:49d:547a with SMTP id 2adb3069b0e04-5452fe45df3mr8725728e87.18.1740067044783;
        Thu, 20 Feb 2025 07:57:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740067044; cv=none;
        d=google.com; s=arc-20240605;
        b=R7NYMeHos+hhWO+YifUZXRCTeedFKxeGiQKwBwVyFqQB7g28I4uuWGqgXf5i+L5wVo
         V7YgKISWPJ6gGLXgKSo9YPz4Cppdq7c+8hGvcEGYeoWihT9eqzh6zhmh/+SSiWcTaZYD
         Ys2o8Q89ZPmN+QTmniAX5ww9lJsoTXwB4fd2USMcBmr2escJtGNq8888cKM0NxkUNBN7
         zxoxklSoExTUQfn0HU0eFK08wBgM1srKHs/r9Xqpjubz5SXFjDRfKj1okuOUM0JMO+Ez
         MGMBdHSfyX3Yfv3BpfAL0o0Va2xc0FEGW4XaDmOTJ3937QTAts1OVzAtLVresIG3wNjL
         MX0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:message-id:subject:cc:to:from:dkim-signature
         :dkim-signature:date;
        bh=wH1m/nQDxdTsgKnO7n/1Ar9PnOVnrrN+8IoQkhMntlU=;
        fh=cLkS05ZpZ+QarjAoVgnGHwuRs5PudCJ0K6fy8aLIeMw=;
        b=XG1D2sqlbLVC2tYc78QP/vLB6FgNgDldEzZq9E3QU9z4HQmyNRsyERzNA4LtCD+Up0
         x1FTAzg2A2MpDYqTVUl0sig6NB9BD84rs4nj9KMSlpt7hxKYsx1VdxewC4P5IqAvK2Vt
         kBi4ze9p+ZJvn8nfzEhhtNdUAhFz11ECBLIfV8dvISLr7sRXa63iRDSQwmTz7WzZI99Q
         eDJPyD6SSPHVI6+wHqLGG6m/AqxcuDx1S9z1yukdxatxAe0+GX8v+eSFg5aPp6XzqDY/
         lzJIM4i5yTTZj8FKtAL3gE+tz83E5olkRfxx0SazlgFzeVuI2yfdkgPa4vxx5U2/kkE5
         G4rA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="W/1NciUT";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5461abf4dabsi352198e87.9.2025.02.20.07.57.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 20 Feb 2025 07:57:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Thu, 20 Feb 2025 16:57:22 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Oliver Sang <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, Petr Pavlu <petr.pavlu@suse.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Kees Cook <kees@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Subject: Re: [linux-next:master] [x86]  66fbf67705:
 kernel-selftests.kvm.hardware_disable_test.fail
Message-ID: <20250220155722.2Z2a-3z0@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <Z7bUC9QY815Cv6nb@xsang-OptiPlex-9020>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="W/1NciUT";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
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

On 2025-02-20 15:04:43 [+0800], Oliver Sang wrote:
> hi, Sebastian,
Hi Oliver,

+ UBSAN & KASAN + STACK unwind people. The commit question is
    e9d25b42bde5a ("x86: Use RCU in all users of __module_address().")
  in -next.

> just FYI. we rebuild the kernel, and run the tests more times upon this c=
ommit
> and its parent, still see the issue persistent:
>=20
=E2=80=A6
>=20
> f985e39203090cc6 66fbf677051818b9b5339fa8bfe
> ---------------- ---------------------------
>        fail:runs  %reproduction    fail:runs
>            |             |             |
>            :20         105%          20:20    kernel-selftests.kvm.hardwa=
re_disable_test.fail
>          %stddev     %change         %stddev
>              \          |                \
>     580.92           +17.4%     682.06        kernel-selftests.time.elaps=
ed_time
>     580.92           +17.4%     682.06        kernel-selftests.time.elaps=
ed_time.max
>     550.23           +13.1%     622.20        kernel-selftests.time.syste=
m_time

this is +~100 secs?

> as above, the time spent is also longer, though it's not only for
> kvm.hardware_disable_test (the time is for whole kernel-selftests.kvm)
=E2=80=A6
> it seems to us that the commit really causes some slow down and it happen=
s to
> make kvm.hardware_disable_test timeout on the older machine for our origi=
nal

I made it slower, why is that so, let me look. On my HW
#1 patched (as of 66fbf677051818b9b5339fa8bfe)
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m43.242s
| user    0m0.635s
| sys     0m18.292s

#2 use preempt_disable instead of rcu_read_lock() in unwind_orc.c (=3Drever=
t)
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m30.212s
| user    0m0.448s
| sys     0m12.939s

#3 replace preempt_disable with __rcu_read_lock() [slim without debug]
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|
| real    0m29.953s
| user    0m0.436s
| sys     0m12.789s

#4 replace preempt_disable with __rcu_read_lock() + lockdep [RCU watching
  test is missing]
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m41.497s
| user    0m0.639s
| sys     0m17.112s

#5 Using rcu_read_lock() only if orc_module_find() is invoked.
Lost the output but it was more or less at #2 level meaning it does not
lookup modules to the point that it matters.

#6 CONFIG_UBSAN -CONFIG_KASAN +revert
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|
| real    0m9.318s
| user    0m0.207s
| sys     0m3.395s

#7 -CONFIG_UBSAN -CONFIG_KASAN with RCU
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m9.249s
| user    0m0.196s
| sys     0m3.332s

#8 -CONFIG_UBSAN -CONFIG_KASAN -LOCKDEP
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
| ^[[A
|=20
| real    0m4.416s
| user    0m0.120s
| sys     0m1.426s

#9 -CONFIG_UBSAN -CONFIG_KASAN -LOCKDEP +revert
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m4.391s
| user    0m0.137s
| sys     0m1.415s


Now. Based on this:
The RCU read section increased the runtime (on my hardware) for the test
from 30 to 43 seconds which is roughly 43%.
This is due to the lockdep annotation within rcu_read_lock() and
unlock() which is not existing in preempt_disable(). After disabling
UBSAN + KASAN  the lockdep annotation has no effect. My guess that
UBSAN/ KASAN is in charge of countless backtraces while enabled. Those
backtraces seem to be limited to the core kernel.

How much do we care here? Is this something that makes UBSAN + KASAN
folks uncomfortable? Or is lockdep slowing things down anyway?

If so, we could either move the RCU section down (as in #5) so it is not
used that often or go the other direction and move it up. I got this:
| ~# time ./hardware_disable_test
| Random seed: 0x6b8b4567
|=20
| real    0m32.618s
| user    0m0.537s
| sys     0m13.942s

which is almost the pre-level with the hunk below after figuring out
that most callers are from arch_stack_walk().=20

diff --git a/arch/x86/include/asm/unwind.h b/arch/x86/include/asm/unwind.h
index 7cede4dc21f0..f20e3613942f 100644
--- a/arch/x86/include/asm/unwind.h
+++ b/arch/x86/include/asm/unwind.h
@@ -42,6 +42,7 @@ struct unwind_state {
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long *first_frame);
 bool unwind_next_frame(struct unwind_state *state);
+bool unwind_next_frame_unlocked(struct unwind_state *state);
 unsigned long unwind_get_return_address(struct unwind_state *state);
 unsigned long *unwind_get_return_address_ptr(struct unwind_state *state);
=20
diff --git a/arch/x86/kernel/stacktrace.c b/arch/x86/kernel/stacktrace.c
index ee117fcf46ed..4df346b11f1e 100644
--- a/arch/x86/kernel/stacktrace.c
+++ b/arch/x86/kernel/stacktrace.c
@@ -21,8 +21,9 @@ void arch_stack_walk(stack_trace_consume_fn consume_entry=
, void *cookie,
 	if (regs && !consume_entry(cookie, regs->ip))
 		return;
=20
+	guard(rcu)();
 	for (unwind_start(&state, task, regs, NULL); !unwind_done(&state);
-	     unwind_next_frame(&state)) {
+	     unwind_next_frame_unlocked(&state)) {
 		addr =3D unwind_get_return_address(&state);
 		if (!addr || !consume_entry(cookie, addr))
 			break;
diff --git a/arch/x86/kernel/unwind_orc.c b/arch/x86/kernel/unwind_orc.c
index 977ee75e047c..402779b3e90a 100644
--- a/arch/x86/kernel/unwind_orc.c
+++ b/arch/x86/kernel/unwind_orc.c
@@ -465,7 +465,7 @@ static bool get_reg(struct unwind_state *state, unsigne=
d int reg_off,
 	return false;
 }
=20
-bool unwind_next_frame(struct unwind_state *state)
+bool unwind_next_frame_unlocked(struct unwind_state *state)
 {
 	unsigned long ip_p, sp, tmp, orig_ip =3D state->ip, prev_sp =3D state->sp=
;
 	enum stack_type prev_type =3D state->stack_info.type;
@@ -475,9 +475,6 @@ bool unwind_next_frame(struct unwind_state *state)
 	if (unwind_done(state))
 		return false;
=20
-	/* Don't let modules unload while we're reading their ORC data. */
-	guard(rcu)();
-
 	/* End-of-stack check for user tasks: */
 	if (state->regs && user_mode(state->regs))
 		goto the_end;
@@ -678,6 +675,13 @@ bool unwind_next_frame(struct unwind_state *state)
 	state->stack_info.type =3D STACK_TYPE_UNKNOWN;
 	return false;
 }
+
+bool unwind_next_frame(struct unwind_state *state)
+{
+	/* Don't let modules unload while we're reading their ORC data. */
+	guard(rcu)();
+	return unwind_next_frame_unlocked(state);
+}
 EXPORT_SYMBOL_GPL(unwind_next_frame);
=20
 void __unwind_start(struct unwind_state *state, struct task_struct *task,

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250220155722.2Z2a-3z0%40linutronix.de.
