Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBL565XXQKGQE52MKRFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id AABA11260CF
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 12:29:51 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id p2sf1253928wma.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 03:29:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576754991; cv=pass;
        d=google.com; s=arc-20160816;
        b=zFgYIGocCXuLTwdeMc1ag769VHDkETH5BCgihXGN9XMP8D2DjRkVirZ2q4QO72/hD/
         twjzBlALXKlB1qK4oSzU23GgCRypArrOFhjHj0tGk1mkyW3PPN1Qghd/XvPiFMSwnaPJ
         23/9sOT3otGk/ce1yCojyy4QZlVW7cftJETdIkyaYKYXg0gL4Hd7mH+LPgIo0vY0lH8Z
         W8vgPDnbZsBP5i9UGPkbml2qjT6Gn4jyDAiZUMyPlqIv1n8vx5aoTroVKgSlawHRJq8q
         2i2DtVfyyAG93praZt+LOZlKg7AAqi4qckcQP4aYOH07NCzoaPXeaFwyuU20V9muSQJe
         POFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=gf2nJhedsizQkvUHMXtsd7wMj6Qn0yW+uEkHsz9rjqk=;
        b=XkK0dLyyfUr5NkQNccBCcKQcGZmG0oqEVYw4Zl/oIgBt37P+qVdrrRx7kYkS0j/jp7
         qwkhe925vNzwq5rQUOfkaHNXtr+VkM+aCOSRGstWUnIno9+mgZxjPOK+4/CP+e+U6NTB
         t34gMIAA7GdP53qP0r736JhjVjQpLiazrPEgx17zWz16FaMyzBfzwRIYqAXI3k/CdKDi
         T7Z6Df+6rb02jaQIaxjSgRVX7WhmIzqqaiG6qDXwq3pnY6VtBue9POIFryAR4cx2L8Hb
         nVpbv2f8CAQJipvNnddXcAJM/AThm1lOUR74IIpRXPZ2DJ8hbvvFMlxXX4Ma5aPjiO1g
         rYdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JSu+Ps3Q;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gf2nJhedsizQkvUHMXtsd7wMj6Qn0yW+uEkHsz9rjqk=;
        b=MxvLeakT5vYChbqcDVVjtXH2afTQg8MTi9Qr/uEmD15aDVxRCRUqDI0oqZD6DHZcSn
         blfUkCUmjh5AurBqZEtg81tZlVNVw5N5d1h7P+pnXmlsvbAajahpI3dttEcNzkAn1FD6
         O6gL/fW8ufdHqVnQD9H5U7ySoC+IaQeulI50bSAate91htliTX+tG9FGrqk9frtDLcj6
         XspOpXJLmMu0KOsq5lyAefrLOpZyLYsmP/wf6q4NVi0QRnJ8wkzgB2PJ70ptGIxaNJ5I
         DY43NuMwK+bAWkRA1Jm+WJF2MIfRe40HfcBoKPZ7uVcLYDLHuDKd9VBdBRlodbp4i9xD
         bC/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gf2nJhedsizQkvUHMXtsd7wMj6Qn0yW+uEkHsz9rjqk=;
        b=t8QoCeE2K8ye71JqqTxQS/OQce7yxeNVOhbmOgB2hBON58NBg8GLRkxKYh4ukGutNW
         Mdd15WZ5L+KZ7vyyiLVu4d7CLk1Vk9XxdjbWnrnUBemI9YI5e4FZP23NLA8Js32xk8f+
         Jyu4yi7j4f0LiYBHHFw2EEfe7BHmDD1Rq0G/zZrg2nGZ95+oitrq75t/3IbfavzcYY97
         how19Wp/Uvd1Qo8ZLbFUG9FX4LUZT1U5FE7rxof2FBltZfvrwJvI7a0EdYQW7GuPFqSl
         4uYSLrBZ0dpDJpL7cnvR0UoWwaNTKeq01v9fps2FB/ZoXRD9snUOYBhzA6jWU3wmPjT8
         c4lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWUDN2GZ2Kb/OmCg2DkBchSpBfK1vWAtJJMiZAYvew43WIi3h/y
	SeZG0nogd4CF/wP0IRGoIy8=
X-Google-Smtp-Source: APXvYqy96Msf8d6R988HgnHIfuMeS/UnddmlJ3xJeadexd/5gacgPdZT+AEhIhVbGM87opByTRvpiA==
X-Received: by 2002:a05:600c:24d1:: with SMTP id 17mr9293159wmu.136.1576754991059;
        Thu, 19 Dec 2019 03:29:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls1489807wru.7.gmail; Thu, 19 Dec
 2019 03:29:50 -0800 (PST)
X-Received: by 2002:adf:ee92:: with SMTP id b18mr9258502wro.281.1576754990476;
        Thu, 19 Dec 2019 03:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576754990; cv=none;
        d=google.com; s=arc-20160816;
        b=YDbRL0ncEXE/RcKfEcaba/PeLeuEdM1zlJKjekTzQHoXpHPkE6ifNSBDM0LyakEL2c
         LPdUyp/9sEgJrER+OPnAQbaQn6fNV7JPGT1790MO7z1ciBa//eEPdSBKg6tdwVwMRPRZ
         YJRX5204HpObGiikDPmOxD1Jb3uS4Gx92LnfGwLkOMftC7ZEmlTwesf91NiIPfOVrjWV
         mk4QJgWJO9Ssu2kXAGRndHsk7gaEXHn/2Tob00SgkcOgijeQLj4Hvli1gUu7+6Jd1f8c
         kY8pSLuVTr7lDc9bUd4xyRGUfb98GppZ2eLDQHsi+wy0jev2HbQ3XxdPbdHmcoQC5AIP
         UrRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=PYc4IVqGOwNMU6IvzgVfBVaX/x83qS0O9m9NnBeoH4M=;
        b=KJnpZJ49Gn2f/7MCBbFgDNGiAZMjVts/l6Sn/uUSqX8CO5laU4QU+HkNXnhyWKE38h
         TsOlUIr+KcFSB3Db5dyMcVSVTx/mSQ4fAIrv2b7aMTZhoqmNaU1UhqqWf5wY7dzqYmyF
         DyqZSeCe/QLoxuUcqBzmKrIxxYV58VDrYOJZbw1NZ4UCCal+uXESX7Zzmr40O25Wn5e6
         KDBQUfAOtlY08tHRjEIuipm8N86lPpL+ci8CHuZShFA2Awd8wBB7bpYX5YmvaCrMS7vW
         tTMfcwaqLnn3cxj2NsY9oSLxlsktRBNb+TOxq4MAiAL1LC0USTluXxnRXFsBMdpHUaUS
         RP1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=JSu+Ps3Q;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id y13si244804wrs.0.2019.12.19.03.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Dec 2019 03:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0B1C0094E9BF90CF4CAA29.dip0.t-ipconnect.de [IPv6:2003:ec:2f0b:1c00:94e9:bf90:cf4c:aa29])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 808131EC09F1;
	Thu, 19 Dec 2019 12:29:45 +0100 (CET)
Date: Thu, 19 Dec 2019 12:29:40 +0100
From: Borislav Petkov <bp@alien8.de>
To: Andy Lutomirski <luto@amacapital.net>,
	Linus Torvalds <torvalds@linux-foundation.org>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	X86 ML <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
Message-ID: <20191219112940.GD32039@zn.tnic>
References: <20191211170632.GD14821@zn.tnic>
 <BC48F4AD-8330-4ED6-8BE8-254C835506A5@amacapital.net>
 <20191211172945.GE14821@zn.tnic>
 <CALCETrXuJMBawUy3DTQfE4qLb822d9491er9-hd971BtBsPFNw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CALCETrXuJMBawUy3DTQfE4qLb822d9491er9-hd971BtBsPFNw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=JSu+Ps3Q;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Dec 11, 2019 at 10:17:25AM -0800, Andy Lutomirski wrote:
> On Wed, Dec 11, 2019 at 9:29 AM Borislav Petkov <bp@alien8.de> wrote:
> >
> > On Wed, Dec 11, 2019 at 09:22:30AM -0800, Andy Lutomirski wrote:
> > > Could we spare a few extra bytes to make this more readable?  I can n=
ever keep track of which number is the oops count, which is the cpu, and wh=
ich is the error code.  How about:
> > >
> > > OOPS 1: general protection blah blah blah (CPU 0)
> > >
> > > and put in the next couple lines =E2=80=9C#GP(0)=E2=80=9D.
> >
> > Well, right now it is:
> >
> > [    2.470492] general protection fault, probably for non-canonical add=
ress 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> > [    2.471615] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1+ #6
> >
> > and the CPU is on the second line, the error code is before the number =
-
> > [#1] - in that case.
> >
> > If we pull the number in front, we can do:
> >
> > [    2.470492] [#1] general protection fault, probably for non-canonica=
l address 0xdfff000000000001: 0000 PREEMPT SMP
> > [    2.471615] [#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1=
+ #6
> >
> > and this way you know that the error code is there, after the first
> > line's description.
>=20
> Hmm, I like that.
>=20
> >
> > I guess we can do:
> >
> > [    2.470492] [#1] general protection fault, probably for non-canonica=
l address 0xdfff000000000001 Error Code: 0000 PREEMPT SMP
> >
> > to make it even more explicit...
>=20
> I like this too.

Ok, let me add Linus too because I'm sure he would have an opinion here.

@Linus, the idea is to dump the die_counter in front of the oops for two
reasons:

1. It always has been absolutely important to know which the first oops
is.

2. Fuzzing and all those other tools scanning dmesg would not need to
make any adjustments anymore to their grepping regexes because oops
lines would be marked uniquely now.

Here's a first attempt, what do you guys think?

WIP diff follows too.

...
[    3.207442] Freeing unused kernel image (text/rodata gap) memory: 2040K
[    3.209464] Freeing unused kernel image (rodata/data gap) memory: 168K
[    3.221088] x86/mm: Checked W+X mappings: passed, no W+X pages found.
[    3.221885] [0] general protection fault: 0000  PREEMPT SMP
[    3.222590] [0] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc2+ #16
[    3.223388] [0] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), B=
IOS 1.11.1-1 04/01/2014
[    3.224374] [0] RIP: 0010:kernel_init+0x58/0x107
[    3.224727] [0] Code: 48 c7 c7 c8 74 ea 81 e8 4b 47 8f ff c7 05 c7 b3 95=
 00 02 00 00 00 e8 4e cd a0 ff e8 b9 2d 90 ff 48 b8 00 00 00 00 00 00 ff df=
 <ff> e0 48 8b 3d 4e 74 d5 00 48 85 ff 74 22 e8 1b f3 82 ff 85 c0 89
[    3.224727] [0] RSP: 0018:ffffc90000013f50 EFLAGS: 00010246[0]=20
[    3.224727] [0] RAX: dfff000000000000 RBX: ffffffff817d1b79 RCX: 0000000=
080aa00a9
[    3.224727] [0] RDX: 0000000080aa00aa RSI: 0000000000000001 RDI: ffff888=
07d406f00
[    3.224727] [0] RBP: 0000000000000000 R08: 0000000000000001 R09: 0000000=
000000000
[    3.224727] [0] R10: 0000000000000001 R11: ffff88807d526d80 R12: 0000000=
000000000
[    3.224727] [0] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000=
000000000
[    3.224727] [0] FS:  0000000000000000(0000) GS:ffff88807da40000(0000) kn=
lGS:0000000000000000
[    3.224727] [0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    3.224727] [0] CR2: 0000000000000000 CR3: 0000000002009000 CR4: 0000000=
0003406e0
[    3.224727] [0] Call Trace:
[    3.224727] [0] ret_from_fork+0x22/0x40
[    3.224727] [0] Modules linked in:
[    3.236790] ---[ end trace ef40186b3f9be0f1 ]---
[    3.237430] [0] RIP: 0010:kernel_init+0x58/0x107
[    3.238083] [0] Code: 48 c7 c7 c8 74 ea 81 e8 4b 47 8f ff c7 05 c7 b3 95=
 00 02 00 00 00 e8 4e cd a0 ff e8 b9 2d 90 ff 48 b8 00 00 00 00 00 00 ff df=
 <ff> e0 48 8b 3d 4e 74 d5 00 48 85 ff 74 22 e8 1b f3 82 ff 85 c0 89
[    3.240176] [0] RSP: 0018:ffffc90000013f50 EFLAGS: 00010246[0]=20
[    3.240950] [0] RAX: dfff000000000000 RBX: ffffffff817d1b79 RCX: 0000000=
080aa00a9
[    3.242486] [0] RDX: 0000000080aa00aa RSI: 0000000000000001 RDI: ffff888=
07d406f00
[    3.243389] [0] RBP: 0000000000000000 R08: 0000000000000001 R09: 0000000=
000000000
[    3.244283] [0] R10: 0000000000000001 R11: ffff88807d526d80 R12: 0000000=
000000000
[    3.245190] [0] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000=
000000000
[    3.246056] [0] FS:  0000000000000000(0000) GS:ffff88807da40000(0000) kn=
lGS:0000000000000000
[    3.246993] [0] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    3.247750] [0] CR2: 0000000000000000 CR3: 0000000002009000 CR4: 0000000=
0003406e0
[    3.248642] Kernel panic - not syncing: Attempted to kill init! exitcode=
=3D0x0000000b
[    3.249180] Kernel Offset: disabled
[    3.249180] ---[ end Kernel panic - not syncing: Attempted to kill init!=
 exitcode=3D0x0000000b ]---


---
diff --git a/arch/x86/include/asm/kdebug.h b/arch/x86/include/asm/kdebug.h
index 75f1e35e7c15..952f0d786bbf 100644
--- a/arch/x86/include/asm/kdebug.h
+++ b/arch/x86/include/asm/kdebug.h
@@ -35,7 +35,7 @@ enum show_regs_mode {
 extern void die(const char *, struct pt_regs *,long);
 extern int __must_check __die(const char *, struct pt_regs *, long);
 extern void show_stack_regs(struct pt_regs *regs);
-extern void __show_regs(struct pt_regs *regs, enum show_regs_mode);
+extern void __show_regs(struct pt_regs *regs, enum show_regs_mode, unsigne=
d int die_counter);
 extern void show_iret_regs(struct pt_regs *regs);
 extern unsigned long oops_begin(void);
 extern void oops_end(unsigned long, struct pt_regs *, int signr);
diff --git a/arch/x86/include/asm/stacktrace.h b/arch/x86/include/asm/stack=
trace.h
index 14db05086bbf..4634852f0536 100644
--- a/arch/x86/include/asm/stacktrace.h
+++ b/arch/x86/include/asm/stacktrace.h
@@ -86,9 +86,6 @@ get_stack_pointer(struct task_struct *task, struct pt_reg=
s *regs)
 	return (unsigned long *)task->thread.sp;
 }
=20
-void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
-			unsigned long *stack, char *log_lvl);
-
 /* The form of the top of the frame on the stack */
 struct stack_frame {
 	struct stack_frame *next_frame;
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index e07424e19274..0058a02d6c54 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -25,7 +25,7 @@
=20
 int panic_on_unrecovered_nmi;
 int panic_on_io_nmi;
-static int die_counter;
+static unsigned int die_counter;
=20
 static struct pt_regs exec_summary_regs;
=20
@@ -68,7 +68,8 @@ static void printk_stack_address(unsigned long address, i=
nt reliable,
 				 char *log_lvl)
 {
 	touch_nmi_watchdog();
-	printk("%s %s%pB\n", log_lvl, reliable ? "" : "? ", (void *)address);
+	printk("%s[%d] %s%pB\n", log_lvl, die_counter, reliable ? "" : "? ",
+	       (void *)address);
 }
=20
 /*
@@ -108,10 +109,10 @@ void show_opcodes(struct pt_regs *regs, const char *l=
oglvl)
=20
 	if (bad_ip || probe_kernel_read(opcodes, (u8 *)prologue,
 					OPCODE_BUFSIZE)) {
-		printk("%sCode: Bad RIP value.\n", loglvl);
+		printk("%s[%d] Code: Bad RIP value.\n", loglvl, die_counter);
 	} else {
-		printk("%sCode: %" __stringify(PROLOGUE_SIZE) "ph <%02x> %"
-		       __stringify(EPILOGUE_SIZE) "ph\n", loglvl, opcodes,
+		printk("%s[%d] Code: %" __stringify(PROLOGUE_SIZE) "ph <%02x> %"
+		       __stringify(EPILOGUE_SIZE) "ph\n", loglvl, die_counter, opcodes,
 		       opcodes[PROLOGUE_SIZE], opcodes + PROLOGUE_SIZE + 1);
 	}
 }
@@ -119,9 +120,9 @@ void show_opcodes(struct pt_regs *regs, const char *log=
lvl)
 void show_ip(struct pt_regs *regs, const char *loglvl)
 {
 #ifdef CONFIG_X86_32
-	printk("%sEIP: %pS\n", loglvl, (void *)regs->ip);
+	printk("%s[%d] EIP: %pS\n", loglvl, die_counter, (void *)regs->ip);
 #else
-	printk("%sRIP: %04x:%pS\n", loglvl, (int)regs->cs, (void *)regs->ip);
+	printk("%s[%d] RIP: %04x:%pS\n", loglvl, die_counter, (int)regs->cs, (voi=
d *)regs->ip);
 #endif
 	show_opcodes(regs, loglvl);
 }
@@ -129,8 +130,8 @@ void show_ip(struct pt_regs *regs, const char *loglvl)
 void show_iret_regs(struct pt_regs *regs)
 {
 	show_ip(regs, KERN_DEFAULT);
-	printk(KERN_DEFAULT "RSP: %04x:%016lx EFLAGS: %08lx", (int)regs->ss,
-		regs->sp, regs->flags);
+	printk(KERN_DEFAULT "[%d] RSP: %04x:%016lx EFLAGS: %08lx",
+		die_counter, (int)regs->ss, regs->sp, regs->flags);
 }
=20
 static void show_regs_if_on_stack(struct stack_info *info, struct pt_regs =
*regs,
@@ -146,7 +147,7 @@ static void show_regs_if_on_stack(struct stack_info *in=
fo, struct pt_regs *regs,
 	 * they can be printed in the right context.
 	 */
 	if (!partial && on_stack(info, regs, sizeof(*regs))) {
-		__show_regs(regs, SHOW_REGS_SHORT);
+		__show_regs(regs, SHOW_REGS_SHORT, die_counter);
=20
 	} else if (partial && on_stack(info, (void *)regs + IRET_FRAME_OFFSET,
 				       IRET_FRAME_SIZE)) {
@@ -159,8 +160,8 @@ static void show_regs_if_on_stack(struct stack_info *in=
fo, struct pt_regs *regs,
 	}
 }
=20
-void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
-			unsigned long *stack, char *log_lvl)
+static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *r=
egs,
+			       unsigned long *stack, char *log_lvl)
 {
 	struct unwind_state state;
 	struct stack_info stack_info =3D {0};
@@ -168,7 +169,7 @@ void show_trace_log_lvl(struct task_struct *task, struc=
t pt_regs *regs,
 	int graph_idx =3D 0;
 	bool partial =3D false;
=20
-	printk("%sCall Trace:\n", log_lvl);
+	printk("%s[%d] Call Trace:\n", log_lvl, die_counter);
=20
 	unwind_start(&state, task, regs, stack);
 	stack =3D stack ? : get_stack_pointer(task, regs);
@@ -207,7 +208,7 @@ void show_trace_log_lvl(struct task_struct *task, struc=
t pt_regs *regs,
=20
 		stack_name =3D stack_type_name(stack_info.type);
 		if (stack_name)
-			printk("%s <%s>\n", log_lvl, stack_name);
+			printk("%s[%d] <%s>\n", log_lvl, die_counter, stack_name);
=20
 		if (regs)
 			show_regs_if_on_stack(&stack_info, regs, partial);
@@ -275,7 +276,7 @@ void show_trace_log_lvl(struct task_struct *task, struc=
t pt_regs *regs,
 		}
=20
 		if (stack_name)
-			printk("%s </%s>\n", log_lvl, stack_name);
+			printk("%s[%d] </%s>\n", log_lvl, die_counter, stack_name);
 	}
 }
=20
@@ -344,7 +345,9 @@ void oops_end(unsigned long flags, struct pt_regs *regs=
, int signr)
 	oops_exit();
=20
 	/* Executive summary in case the oops scrolled away */
-	__show_regs(&exec_summary_regs, SHOW_REGS_ALL);
+	__show_regs(&exec_summary_regs, SHOW_REGS_ALL, die_counter);
+
+	die_counter++;
=20
 	if (!signr)
 		return;
@@ -368,6 +371,7 @@ NOKPROBE_SYMBOL(oops_end);
 int __die(const char *str, struct pt_regs *regs, long err)
 {
 	const char *pr =3D "";
+	char pfx[5] =3D { };
=20
 	/* Save the regs of the first oops for the executive summary later. */
 	if (!die_counter)
@@ -377,7 +381,7 @@ int __die(const char *str, struct pt_regs *regs, long e=
rr)
 		pr =3D IS_ENABLED(CONFIG_PREEMPT_RT) ? " PREEMPT_RT" : " PREEMPT";
=20
 	printk(KERN_DEFAULT
-	       "%s: %04lx [#%d]%s%s%s%s%s\n", str, err & 0xffff, ++die_counter,
+	       "[%d] %s: %04lx %s%s%s%s%s\n", die_counter, str, err & 0xffff,
 	       pr,
 	       IS_ENABLED(CONFIG_SMP)     ? " SMP"             : "",
 	       debug_pagealloc_enabled()  ? " DEBUG_PAGEALLOC" : "",
@@ -385,8 +389,10 @@ int __die(const char *str, struct pt_regs *regs, long =
err)
 	       IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) ?
 	       (boot_cpu_has(X86_FEATURE_PTI) ? " PTI" : " NOPTI") : "");
=20
+	snprintf(pfx, sizeof(pfx), "[%d] ", die_counter);
+
 	show_regs(regs);
-	print_modules();
+	print_modules(pfx);
=20
 	if (notify_die(DIE_OOPS, str, regs, err,
 			current->thread.trap_nr, SIGSEGV) =3D=3D NOTIFY_STOP)
@@ -412,9 +418,13 @@ void die(const char *str, struct pt_regs *regs, long e=
rr)
=20
 void show_regs(struct pt_regs *regs)
 {
-	show_regs_print_info(KERN_DEFAULT);
+	char prf[5] =3D { };
+
+	snprintf(prf, sizeof(prf), "%s[%d] ", KERN_DEFAULT, die_counter);
+
+	show_regs_print_info(prf);
=20
-	__show_regs(regs, user_mode(regs) ? SHOW_REGS_USER : SHOW_REGS_ALL);
+	__show_regs(regs, user_mode(regs) ? SHOW_REGS_USER : SHOW_REGS_ALL, die_c=
ounter);
=20
 	/*
 	 * When in-kernel, we also print out the stack at the time of the fault..
diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index 506d66830d4d..83422efb5a4a 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -64,7 +64,8 @@
 #include "process.h"
=20
 /* Prints also some state that isn't saved in the pt_regs */
-void __show_regs(struct pt_regs *regs, enum show_regs_mode mode)
+void __show_regs(struct pt_regs *regs, enum show_regs_mode mode,
+		 unsigned int die_counter)
 {
 	unsigned long cr0 =3D 0L, cr2 =3D 0L, cr3 =3D 0L, cr4 =3D 0L, fs, gs, sha=
dowgs;
 	unsigned long d0, d1, d2, d3, d6, d7;
@@ -74,20 +75,20 @@ void __show_regs(struct pt_regs *regs, enum show_regs_m=
ode mode)
 	show_iret_regs(regs);
=20
 	if (regs->orig_ax !=3D -1)
-		pr_cont(" ORIG_RAX: %016lx\n", regs->orig_ax);
+		pr_cont("[%d] ORIG_RAX: %016lx\n", die_counter, regs->orig_ax);
 	else
-		pr_cont("\n");
-
-	printk(KERN_DEFAULT "RAX: %016lx RBX: %016lx RCX: %016lx\n",
-	       regs->ax, regs->bx, regs->cx);
-	printk(KERN_DEFAULT "RDX: %016lx RSI: %016lx RDI: %016lx\n",
-	       regs->dx, regs->si, regs->di);
-	printk(KERN_DEFAULT "RBP: %016lx R08: %016lx R09: %016lx\n",
-	       regs->bp, regs->r8, regs->r9);
-	printk(KERN_DEFAULT "R10: %016lx R11: %016lx R12: %016lx\n",
-	       regs->r10, regs->r11, regs->r12);
-	printk(KERN_DEFAULT "R13: %016lx R14: %016lx R15: %016lx\n",
-	       regs->r13, regs->r14, regs->r15);
+		pr_cont("[%d] \n", die_counter);
+
+	printk(KERN_DEFAULT "[%d] RAX: %016lx RBX: %016lx RCX: %016lx\n",
+	       die_counter, regs->ax, regs->bx, regs->cx);
+	printk(KERN_DEFAULT "[%d] RDX: %016lx RSI: %016lx RDI: %016lx\n",
+	       die_counter, regs->dx, regs->si, regs->di);
+	printk(KERN_DEFAULT "[%d] RBP: %016lx R08: %016lx R09: %016lx\n",
+	       die_counter,regs->bp, regs->r8, regs->r9);
+	printk(KERN_DEFAULT "[%d] R10: %016lx R11: %016lx R12: %016lx\n",
+	       die_counter, regs->r10, regs->r11, regs->r12);
+	printk(KERN_DEFAULT "[%d] R13: %016lx R14: %016lx R15: %016lx\n",
+	       die_counter, regs->r13, regs->r14, regs->r15);
=20
 	if (mode =3D=3D SHOW_REGS_SHORT)
 		return;
@@ -95,8 +96,8 @@ void __show_regs(struct pt_regs *regs, enum show_regs_mod=
e mode)
 	if (mode =3D=3D SHOW_REGS_USER) {
 		rdmsrl(MSR_FS_BASE, fs);
 		rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);
-		printk(KERN_DEFAULT "FS:  %016lx GS:  %016lx\n",
-		       fs, shadowgs);
+		printk(KERN_DEFAULT "[%d] FS:  %016lx GS:  %016lx\n",
+		       die_counter, fs, shadowgs);
 		return;
 	}
=20
@@ -114,12 +115,12 @@ void __show_regs(struct pt_regs *regs, enum show_regs=
_mode mode)
 	cr3 =3D __read_cr3();
 	cr4 =3D __read_cr4();
=20
-	printk(KERN_DEFAULT "FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n",
-	       fs, fsindex, gs, gsindex, shadowgs);
-	printk(KERN_DEFAULT "CS:  %04lx DS: %04x ES: %04x CR0: %016lx\n", regs->c=
s, ds,
-			es, cr0);
-	printk(KERN_DEFAULT "CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3,
-			cr4);
+	printk(KERN_DEFAULT "[%d] FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\=
n",
+	       die_counter, fs, fsindex, gs, gsindex, shadowgs);
+	printk(KERN_DEFAULT "[%d] CS:  %04lx DS: %04x ES: %04x CR0: %016lx\n",
+	       die_counter, regs->cs, ds, es, cr0);
+	printk(KERN_DEFAULT "[%d] CR2: %016lx CR3: %016lx CR4: %016lx\n",
+	       die_counter, cr2, cr3, cr4);
=20
 	get_debugreg(d0, 0);
 	get_debugreg(d1, 1);
@@ -131,14 +132,14 @@ void __show_regs(struct pt_regs *regs, enum show_regs=
_mode mode)
 	/* Only print out debug registers if they are in their non-default state.=
 */
 	if (!((d0 =3D=3D 0) && (d1 =3D=3D 0) && (d2 =3D=3D 0) && (d3 =3D=3D 0) &&
 	    (d6 =3D=3D DR6_RESERVED) && (d7 =3D=3D 0x400))) {
-		printk(KERN_DEFAULT "DR0: %016lx DR1: %016lx DR2: %016lx\n",
-		       d0, d1, d2);
-		printk(KERN_DEFAULT "DR3: %016lx DR6: %016lx DR7: %016lx\n",
-		       d3, d6, d7);
+		printk(KERN_DEFAULT "[%d] DR0: %016lx DR1: %016lx DR2: %016lx\n",
+		       die_counter, d0, d1, d2);
+		printk(KERN_DEFAULT "[%d] DR3: %016lx DR6: %016lx DR7: %016lx\n",
+		       die_counter, d3, d6, d7);
 	}
=20
 	if (boot_cpu_has(X86_FEATURE_OSPKE))
-		printk(KERN_DEFAULT "PKRU: %08x\n", read_pkru());
+		printk(KERN_DEFAULT "[%d] PKRU: %08x\n", die_counter, read_pkru());
 }
=20
 void release_thread(struct task_struct *dead_task)
diff --git a/arch/x86/um/sysrq_64.c b/arch/x86/um/sysrq_64.c
index 903ad91b624f..62f0ecc2643f 100644
--- a/arch/x86/um/sysrq_64.c
+++ b/arch/x86/um/sysrq_64.c
@@ -16,7 +16,7 @@
 void show_regs(struct pt_regs *regs)
 {
 	printk("\n");
-	print_modules();
+	print_modules("");
 	printk(KERN_INFO "Pid: %d, comm: %.20s %s %s\n", task_pid_nr(current),
 		current->comm, print_tainted(), init_utsname()->release);
 	printk(KERN_INFO "RIP: %04lx:[<%016lx>]\n", PT_REGS_CS(regs) & 0xffff,
diff --git a/include/linux/module.h b/include/linux/module.h
index 0c7366c317bd..e83a467e7b9c 100644
--- a/include/linux/module.h
+++ b/include/linux/module.h
@@ -665,7 +665,7 @@ int lookup_module_symbol_attrs(unsigned long addr, unsi=
gned long *size, unsigned
 int register_module_notifier(struct notifier_block *nb);
 int unregister_module_notifier(struct notifier_block *nb);
=20
-extern void print_modules(void);
+extern void print_modules(const char *pfx);
=20
 static inline bool module_requested_async_probing(struct module *module)
 {
@@ -809,7 +809,7 @@ static inline int unregister_module_notifier(struct not=
ifier_block *nb)
=20
 #define module_put_and_exit(code) do_exit(code)
=20
-static inline void print_modules(void)
+static inline void print_modules(const char *pfx)
 {
 }
=20
diff --git a/init/main.c b/init/main.c
index f9d9701d600c..890208fa7430 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1127,6 +1127,9 @@ static int __ref kernel_init(void *unused)
=20
 	rcu_end_inkernel_boot();
=20
+	asm volatile("mov $0xdfff000000000000, %rax\n\t"
+		     "jmpq *%rax\n\t");
+
 	if (ramdisk_execute_command) {
 		ret =3D run_init_process(ramdisk_execute_command);
 		if (!ret)
diff --git a/kernel/module.c b/kernel/module.c
index ac058a5ad1d1..9d73718ce30b 100644
--- a/kernel/module.c
+++ b/kernel/module.c
@@ -4476,12 +4476,12 @@ struct module *__module_text_address(unsigned long =
addr)
 EXPORT_SYMBOL_GPL(__module_text_address);
=20
 /* Don't grab lock, we're oopsing. */
-void print_modules(void)
+void print_modules(const char *pfx)
 {
 	struct module *mod;
 	char buf[MODULE_FLAGS_BUF_SIZE];
=20
-	printk(KERN_DEFAULT "Modules linked in:");
+	printk(KERN_DEFAULT "%sModules linked in:", pfx);
 	/* Most callers should already have preempt disabled, but make sure */
 	preempt_disable();
 	list_for_each_entry_rcu(mod, &modules, list) {
diff --git a/kernel/panic.c b/kernel/panic.c
index b69ee9e76cb2..056b6448fec0 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -582,7 +582,7 @@ void __warn(const char *file, int line, void *caller, u=
nsigned taint,
 		panic("panic_on_warn set ...\n");
 	}
=20
-	print_modules();
+	print_modules("");
=20
 	if (regs)
 		show_regs(regs);
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 15508c202bf5..fda7ce233344 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3853,7 +3853,7 @@ static noinline void __schedule_bug(struct task_struc=
t *prev)
 		prev->comm, prev->pid, preempt_count());
=20
 	debug_show_held_locks(prev);
-	print_modules();
+	print_modules("");
 	if (irqs_disabled())
 		print_irqtrace_events(prev);
 	if (IS_ENABLED(CONFIG_DEBUG_PREEMPT)
diff --git a/kernel/watchdog.c b/kernel/watchdog.c
index f41334ef0971..597ce03f9f2c 100644
--- a/kernel/watchdog.c
+++ b/kernel/watchdog.c
@@ -448,7 +448,7 @@ static enum hrtimer_restart watchdog_timer_fn(struct hr=
timer *hrtimer)
 			smp_processor_id(), duration,
 			current->comm, task_pid_nr(current));
 		__this_cpu_write(softlockup_task_ptr_saved, current);
-		print_modules();
+		print_modules("");
 		print_irqtrace_events(current);
 		if (regs)
 			show_regs(regs);
diff --git a/kernel/watchdog_hld.c b/kernel/watchdog_hld.c
index 247bf0b1582c..76aa96a01b10 100644
--- a/kernel/watchdog_hld.c
+++ b/kernel/watchdog_hld.c
@@ -137,7 +137,7 @@ static void watchdog_overflow_callback(struct perf_even=
t *event,
=20
 		pr_emerg("Watchdog detected hard LOCKUP on cpu %d\n",
 			 this_cpu);
-		print_modules();
+		print_modules("");
 		print_irqtrace_events(current);
 		if (regs)
 			show_regs(regs);
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 4785a8a2040e..f71d639e0032 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -645,7 +645,7 @@ static void bad_page(struct page *page, const char *rea=
son,
 						bad_flags, &bad_flags);
 	dump_page_owner(page);
=20
-	print_modules();
+	print_modules("");
 	dump_stack();
 out:
 	/* Leave bad fields for debug, except PageBuddy could make trouble */

--=20
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191219112940.GD32039%40zn.tnic.
