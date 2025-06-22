Return-Path: <kasan-dev+bncBDW2JDUY5AORBO7337BAMGQEEEHDDRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1549CAE2FFC
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 14:57:32 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6077dea380esf2977472a12.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Jun 2025 05:57:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750597051; cv=pass;
        d=google.com; s=arc-20240605;
        b=GLgRCpN+F3kizKytMKzD7n/DE2ni+0PfD49bbuiqzBIvoYSzsA6t/SYSk+ib6jrBGn
         y9UemFKUE8bJA6dZO2srHv1nXUPHAlBVM93dXW9fwit68Fb/1Zm6ePrn8EVR8EcHEvk4
         Gahqv+/U1XSIJNs1w0t6r3ZHfOE/PKMYjziux/LXiUz+3a+wafvGEYp3PALoh/eIcWus
         to7f1duqcasv5HB5l5KHdGvxo4WXY03jrt/ovOwpeuhEBQfsCgFZ5rJtXp93ruEpykIy
         SOXc95ov4FFFA3aTh/i7R/wjtR6SH9UgvuoEcpcF4a690vsNTf32Bk/ZEgiMxq2DrQWC
         w9BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=hPE8LC34avnkgYIAJHYYWUSi7iP5l2z2iWClIMuonck=;
        fh=7T0lI8NrGzcVprlyAVhGTwdJuZLpbWMKKj27I2ahEbE=;
        b=cK3ZXxJn1tUwnRE+++Uof4bz3H2rcytJXeaqSoox2RjACr4kwtAPTsO8YTgsB6t7sE
         VSynODCfbrPo61ZSxG5+Fv4VjPpF3JnscPuJfJFK7UFeCCGZnzKC8/JoeS18b3eC0314
         RcG90w8ZQSnVSYazf2p97iW3kzXoPVpNOb2gNyMT3z7lKbz9shws5xk2NE44OnhASEBc
         g0lPYh99XEaUf9RRh+M16XmRVzLz4yqZk9cvPfhEvxc5AnWvbqhLg8W7YKw5swSJ9ks+
         QaukIL1xsE6nzHdSSWJvaU8Yf/BY9AbXxWFBUp06qi8sAN+jZvaS38IgcahrSfjU++O9
         z3RA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hvxNa0TW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750597051; x=1751201851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hPE8LC34avnkgYIAJHYYWUSi7iP5l2z2iWClIMuonck=;
        b=uC8bahOqSv/Dx6kX7IcSPGlJbKAPnsjk0I1WVBcQxNJ7leq2bg74wf4sivQRnnSfky
         2NBRmyQMsYOWMweejqt0DoQ71pokmbX4KrnSNwqKpvEVBqzmaCGg9c1hjPS2k7XNar6r
         65cFzCj0Q4kwiBJ4LrX4telxNOES46zjpWeyvuYuP7MoH8EWSyA3FjPQ2U8PlU9qKrza
         ZDsvr6Hr/09aaXq4xUxaYXODtd+tuDRkao/lT5hMdALTeXy+86ELmKMEkYG/X0Ha6wMY
         iUZ00The8verCd+ahwunCEhirUnQRrbAXtfWzNTH7Ri1+dAz6bYnxHWi+0wPlVuTTdBX
         /qpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750597051; x=1751201851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hPE8LC34avnkgYIAJHYYWUSi7iP5l2z2iWClIMuonck=;
        b=MqNhLESPOG5dmF9FQXdPmwZqUVEZQojkRQStYBjV0jb/kqNtgr9xuvIFzvETLoYSJj
         vVPrlQLwdQZRNru1dPH7jNXPTa/XzRZr2zzH1BYDN2/3gsu5ltAvFOZ+zoDxs0k8vjsu
         t1l0qXD6/yjM+7ZmtswpdOntx7++R3Ax/33F2SBta0kBIq1BWuYH20YtRrg/Sj4PDFqs
         ruuou8BNkh6Tq9aT9f19fLKTt5STXwx9JPb+SFqiwuSm4iTXT0BIS7BLUSpF/vrKjKaQ
         1JZsXu1WjHtUWuPYZwwylr4OUk2BV8pEOcsTq7O4yyHmYGGncmEE7h+OwMHQdparHxtW
         frgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750597051; x=1751201851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hPE8LC34avnkgYIAJHYYWUSi7iP5l2z2iWClIMuonck=;
        b=IRL3ZOMfk6KBuleL08bVdG4/cnhaFcfj9+oJ75h6/0CVmp6wo3uXhzUeLz/Th7ADmH
         3MycEuEDmn+jK1sz4FTHXbQYdVa7MUjtKPr5jO0VIJPYSpgqfsjLMb3dT/IKWP3p/yoq
         xqg9NPnWJfEHNqSZG05XE/xF3/ksbbTpexF/OBX4/LcDbrSIEZHbfvu1K+agvnZV8nD/
         V26Pmi5mpYg4GyKD14DkBNV3oOv94EdFacVS8cIfj15vKE2pBiyecE0IKk9ldEzElcO6
         I11cwgHk/iN7E35T3RtPpVScgfOhEoYfPowohKXN1Cz5rl1QsxNjg2UjCdtqfnfV6FKx
         aprg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbgBZb1MVDpHu/DO/KqmZA6wYuYIBuq09q67YjEXzV3S2MoRJ7rX+tc/LjjppW6b9Fgc01mw==@lfdr.de
X-Gm-Message-State: AOJu0Yzmfj+s9NYLMRHOOvM2gnxlpSZluTn/3v72xiiGCC9Ruhp+0TkP
	2J99tNl6Fy+YBjd/+nwwKTsieIEF3Le75+fhJOWPl/e9RZIXHIRmuMcO
X-Google-Smtp-Source: AGHT+IFqzX1dAYIM+uT6j2Agx+lQ3s5DfRSM8us0VUNLSMpqhmrIxtIpWJNPNgWyNmzifx/Xoo1yAw==
X-Received: by 2002:a05:6402:3590:b0:602:ddbe:480f with SMTP id 4fb4d7f45d1cf-60a1cd300d0mr7265191a12.9.1750597051491;
        Sun, 22 Jun 2025 05:57:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdFnX7E3jtf3dn2PcZvsZEpfmclYaoJUQexJuSbEY0mXg==
Received: by 2002:a05:6402:274d:b0:601:6090:416b with SMTP id
 4fb4d7f45d1cf-609e78dc3c4ls2520241a12.0.-pod-prod-03-eu; Sun, 22 Jun 2025
 05:57:29 -0700 (PDT)
X-Received: by 2002:a05:6402:27d0:b0:609:b5e0:5987 with SMTP id 4fb4d7f45d1cf-60a1d1906bbmr7358621a12.23.1750597049127;
        Sun, 22 Jun 2025 05:57:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750597049; cv=none;
        d=google.com; s=arc-20240605;
        b=L+0Ph+wrgnSm+pXMb2JtKVfWe61fC5OcyviHo1hnylutaZ78u3HHL9ajdEytOqT0rr
         dXVRUNHnEgYwqoEczzlii9yljYxsWUk7nnhD/Rb2QOw8YIaAjyHQJj3OdCTIdsBLpLdB
         vWVf73Ih5/eR+hRkqSiYRTbBRvfhM9bQ5AhUxbnLjOGBiGvsYFzDcMcVs66AfoO4iDA9
         HAfA31Q2MXuZthyT7lebZz7AtPeCsKs+tLUO+FFJQpEg1pFEIxrfavQO1D8XMemWKNSK
         5OP/tatwLqMeZq0dUcRydWl6mH+6PFtxscVfhfiRWKvLLlvBdtZdwxjGYT9rEoEmr4ff
         0URA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4+vkfv19nsFG3JWWcSn0RJuwkZKQGKRg+WJmGYnaTdw=;
        fh=a+Umj4exd23ArKfzLQFst0H/2EHw4ai1kJX3hgtEpmg=;
        b=J1WRJ+mdoPGjS0ULzrbauvtoiIBLMWCI/GRomgxYsoPB4SP7beFpMCMJaHY93vCtl/
         1NCKKKso/D0jZeAIZgYekqF0WpDubX0AyeqQCGaobPnmis1DNjOwLmJjyTSqLi7+CbW5
         6NwlOXGiaSQmLwjINBW5CuXLlOa5E6PwpfNxbg0B08Nda6DH6iwNK+4Th/V4JUtdyQf4
         NKte6reBiYJ+qloX6TWv3oUy9RzPVeiFAGXbjh/YHGom122cYvY2cu27kwCP23pEgXWk
         Ag9VZELKjD6dn3L7HIiKjWzv4XyLEUcKROTrJqxi0vxOPepL6b9kj3gixthMqWgCZrqZ
         alyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hvxNa0TW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60a17f4f23asi151229a12.0.2025.06.22.05.57.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Jun 2025 05:57:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3a50fc7ac4dso1811499f8f.0
        for <kasan-dev@googlegroups.com>; Sun, 22 Jun 2025 05:57:29 -0700 (PDT)
X-Gm-Gg: ASbGncsD2B2WUA4WSt5tpU5aNf6JJLq4J+uR1bC6/ssTATNtZLStsR5fp/6pYhYEbMI
	FUee6Hzd0zRYK864GJO6giaYB7lDIQJYOBgSu3V2D0VpHvVwPKi2w4eQfmVLI+Z9wuO/NJBXR2i
	Y+ibfOwvb8jcRptGvKA2jog30YgLTGmeyHhqk2wUh0hB1PPg==
X-Received: by 2002:adf:9cc4:0:b0:3a4:dbdf:7154 with SMTP id
 ffacd0b85a97d-3a6d1330d8fmr5584264f8f.54.1750597048529; Sun, 22 Jun 2025
 05:57:28 -0700 (PDT)
MIME-Version: 1.0
References: <aFVVEgD0236LdrL6@gmail.com>
In-Reply-To: <aFVVEgD0236LdrL6@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 Jun 2025 14:57:16 +0200
X-Gm-Features: Ac12FXwFbIPranIr5CD7aMTRcJJTKGnL_GbrxcoA-Rg5n9d4zqqzGNtm5fJhgK8
Message-ID: <CA+fCnZfzHOFjVo43UZK8H6h3j=OHjfF13oFJvT0P-SM84Oc4qQ@mail.gmail.com>
Subject: Re: arm64: BUG: KASAN: invalid-access in arch_stack_walk
To: Breno Leitao <leitao@debian.org>
Cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	catalin.marinas@arm.com, will@kernel.org, song@kernel.org, 
	mark.rutland@arm.com, usamaarif642@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hvxNa0TW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jun 20, 2025 at 2:33=E2=80=AFPM Breno Leitao <leitao@debian.org> wr=
ote:
>
> I'm encountering a KASAN warning during aarch64 boot and I am struggling
> to determine the cause. I haven't come across any reports about this on
> the mailing list so far, so I'm sharing this early in case others are
> seeing it too.
>
> This issue occurs both on Linus's upstream branch and in the 6.15 final
> release. The stack trace below is from 6.15 final. I haven't started
> bisecting yet, but that's my next step.
>
> Here are a few details about the problem:
>
> 1) it happen on my kernel boots on a aarch64 host
> 2) The lines do not match the code very well, and I am not sure why. It
>    seems it is offset by two lines. The stack is based on commit
>    0ff41df1cb26 ("Linux 6.15")
> 3) My config is at https://pastebin.com/ye46bEK9
>
>
>         [  235.831690] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>         [  235.861238] BUG: KASAN: invalid-access in arch_stack_walk (arc=
h/arm64/kernel/stacktrace.c:346 arch/arm64/kernel/stacktrace.c:387)
>         [  235.887206] Write of size 96 at addr a5ff80008ae8fb80 by task =
kworker/u288:26/3666
>         [  235.918139] Pointer tag: [a5], memory tag: [00]
>         [  235.942722] Workqueue: efi_rts_wq efi_call_rts
>         [  235.942732] Call trace:
>         [  235.942734] show_stack (arch/arm64/kernel/stacktrace.c:468) (C=
)
>         [  235.942741] dump_stack_lvl (lib/dump_stack.c:123)
>         [  235.942748] print_report (mm/kasan/report.c:409 mm/kasan/repor=
t.c:521)
>         [  235.942755] kasan_report (mm/kasan/report.c:636)
>         [  235.942759] kasan_check_range (mm/kasan/sw_tags.c:85)
>         [  235.942764] memset (mm/kasan/shadow.c:53)
>         [  235.942769] arch_stack_walk (arch/arm64/kernel/stacktrace.c:34=
6 arch/arm64/kernel/stacktrace.c:387)
>         [  235.942773] return_address (arch/arm64/kernel/return_address.c=
:44)
>         [  235.942778] trace_hardirqs_off.part.0 (kernel/trace/trace_pree=
mptirq.c:95)
>         [  235.942784] trace_hardirqs_off_finish (kernel/trace/trace_pree=
mptirq.c:98)
>         [  235.942789] enter_from_kernel_mode (arch/arm64/kernel/entry-co=
mmon.c:62)
>         [  235.942794] el1_interrupt (arch/arm64/kernel/entry-common.c:55=
9 arch/arm64/kernel/entry-common.c:575)
>         [  235.942799] el1h_64_irq_handler (arch/arm64/kernel/entry-commo=
n.c:581)
>         [  235.942804] el1h_64_irq (arch/arm64/kernel/entry.S:596)
>         [  235.942809]  0x3c52ff1ecc (P)
>         [  235.942825]  0x3c52ff0ed4
>         [  235.942829]  0x3c52f902d0
>         [  235.942833]  0x3c52f953e8
>         [  235.942837] __efi_rt_asm_wrapper (arch/arm64/kernel/efi-rt-wra=
pper.S:49)
>         [  235.942843] efi_call_rts (drivers/firmware/efi/runtime-wrapper=
s.c:269)
>         [  235.942848] process_one_work (./arch/arm64/include/asm/jump_la=
bel.h:36 ./include/trace/events/workqueue.h:110 kernel/workqueue.c:3243)
>         [  235.942854] worker_thread (kernel/workqueue.c:3313 kernel/work=
queue.c:3400)
>         [  235.942858] kthread (kernel/kthread.c:464)
>         [  235.942863] ret_from_fork (arch/arm64/kernel/entry.S:863)
>
>         [  236.436924] The buggy address belongs to the virtual mapping a=
t
>         [a5ff80008ae80000, a5ff80008aea0000) created by:
>         arm64_efi_rt_init (arch/arm64/kernel/efi.c:219)
>
>         [  236.506959] The buggy address belongs to the physical page:
>         [  236.529724] page: refcount:1 mapcount:0 mapping:00000000000000=
00 index:0x0 pfn:0x12682
>         [  236.562077] flags: 0x17fffd6c0000000(node=3D0|zone=3D2|lastcpu=
pid=3D0x1ffff|kasantag=3D0x5b)
>         [  236.593722] raw: 017fffd6c0000000 0000000000000000 dead0000000=
00122 0000000000000000
>         [  236.625365] raw: 0000000000000000 0000000000000000 00000001fff=
fffff 0000000000000000
>         [  236.657004] page dumped because: kasan: bad access detected
>
>         [  236.685828] Memory state around the buggy address:
>         [  236.705390]  ffff80008ae8f900: 00 00 00 00 00 a5 a5 a5 a5 00 0=
0 00 00 00 a5 a5
>         [  236.734899]  ffff80008ae8fa00: a5 a5 a5 00 00 00 00 00 00 a5 a=
5 a5 a5 a5 00 a5
>         [  236.764409] >ffff80008ae8fb00: 00 a5 a5 a5 00 a5 a5 a5 a5 a5 a=
5 00 a5 a5 a5 00
>         [  236.793918]                                                   =
  ^
>         [  236.818810]  ffff80008ae8fc00: a7 a5 a5 a5 a5 a5 a5 a5 a5 00 a=
5 00 a5 a5 a5 a5
>         [  236.848321]  ffff80008ae8fd00: a5 a5 a5 a5 00 a5 00 a5 a5 a5 a=
5 a5 a5 a5 a5 a5
>         [  236.877828] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

Looks like the memory allocated/mapped in arm64_efi_rt_init() is
tagged by __vmalloc_node(). And this memory then gets used as a
(irq-related? EFI-related?) stack. And having the SP register tagged
breaks SW_TAGS instrumentation AFAIR [1], which is likely what
produces this report.

Adding kasan_reset_tag() to arm64_efi_rt_init() should likely fix
this; similar to what we have in arch_alloc_vmap_stack(). Or should we
make arm64_efi_rt_init() just call arch_alloc_vmap_stack()?

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/comm=
it/?id=3D51fb34de2a4c8fa0f221246313700bfe3b6c586d

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfzHOFjVo43UZK8H6h3j%3DOHjfF13oFJvT0P-SM84Oc4qQ%40mail.gmail.com.
