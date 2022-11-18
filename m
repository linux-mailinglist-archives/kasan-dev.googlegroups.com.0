Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHEW32NQMGQEE5WB62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 64B3262F66A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 14:39:42 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id x18-20020a170902ec9200b001869f20da7esf3907822plg.10
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 05:39:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668778781; cv=pass;
        d=google.com; s=arc-20160816;
        b=qPUFNSerjmtiQHsySwZ/3LW6KY0cgu5/M0BG2Kh2NL6r/8fx2lnJIXSfcRv+L4tkTB
         8RjRj6poQGrpWhXeCCXimmdQ+jiv0RtYYT7duHjR8glY30XBlMEFtCtTOE/gh7k/X50N
         EtE+7zoj1JkgV8WuQYKv4e94mTj4KBzpyb8A6HXEWdF9bvdJTCrTDkkef+xUOMVN1pEU
         s94k93taM5a3kc/FS8vnzkTaiEj7laDGnVTQuK5BSsZvVdi18ZBB1cUzTwIZ9m6ml+CG
         NlKz/5bLWBIzJv7sfh2a6EWNOpwK2kVIReg1PWqWpCRbs5BhPfTe9nZWbobpUfUIkv+a
         WvBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TNYHsBBVHQIwl/JnuK1uy4nDpwrzI0GJkMiu1H7Mjps=;
        b=Oy1a3Ex2sOAOvxc5cTORcHvPArkvUmVJGTkK6oKAPLRjio0r+VTT0OedXIjMcYNcUp
         vg9vcpdnIWNEGt0D9QZjcRhta2Jfcl+TI2K6DTIOwOcwJb05A5p9wi/HSb5IbJbRVLEV
         b4UtUmsdJAE60zD/arbrnuYdPaC2DWkeK4zUwT1YxTJGw/doJIsr/+I8U1djYqUtVw8o
         bN0fNyaC6IuK1O1nC5lx7PL1wzQekEyu/tBGDjh/hyMxsxpMSji7btamECVYdoZUxJJU
         K4OMxpghJ+fwkn/PsGmrK/ogwUrKPxQAzz7yY9MZgmVlMbxgQNQSheiVdsl8m75mVwXL
         1dGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fetFG9vb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TNYHsBBVHQIwl/JnuK1uy4nDpwrzI0GJkMiu1H7Mjps=;
        b=LtulxUT6sS53422g3c5aJQuR8gEXjfZuUmL+H9M0gQmcOqC9r9bjGOo/aw9A43wfaZ
         FUkspq+7MDmBkHczMDLS6sbPB7CsO01D7StL2+ND7tOSf3xDxeOAt57dGAECO6NjGBjH
         xwquvVpmfwprFVzRbLqXXB7+hctXu5Sp1OEViLL6grNY5OTxZCsVLCTU0Nvdf5sgzpKl
         a46ZxeaTDmgeeXrKkuCtIAq3LGDzAwXlhQrZMq7p62m4h+Pvqqz+tfH49jnFTKzAIsWB
         PXZzX3/SYhcnlrxFbGXRsJN5X+VoujC7N/BmIWdn5ud8uewnHbfSvVHPMZJHJDH8RF8l
         h4nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TNYHsBBVHQIwl/JnuK1uy4nDpwrzI0GJkMiu1H7Mjps=;
        b=5U9eQLqUa9RoLrXcDjK1G5yf0jAkV0nI7SWLUXRq4pz+xoTavzSW748EyxTTqYLrpa
         NKKObkgsMozRtMlEtTXNgJrOgFrQ53fQuqRcpIWGQ2B3UrN+wQG9xAdKVnLTX9SmhsGE
         PrwPDRlvaYM5L401si1GVQIFwzFgBVJmYfcvy5xhBtf3Nv7I+bKglfMMmGk7ZJLUBQCf
         AJ25Ftd2LgyjvVx2l+afaCIa3eI06w6zq8mMarYhinTG+yShR/jb2DCDZ0r68auDYDRt
         JA9JjDxJ+nLZvcGg4ya4HogMk1zdc1+kFA4hcgsvFEVHGc531S+CVcJ6eii1ddqn2Bif
         bUTA==
X-Gm-Message-State: ANoB5pmgOi6D+hflrDbxkLDaAo0qdaZH95tiRymx0IrBaokhNfsIjOLg
	UT7l/i0E6bqFJ+6pGIWlb9c=
X-Google-Smtp-Source: AA0mqf4SSKHSs7TWyJoEgYQBJ29A9k668MI5x44CaMfBll9s5pVXDgkse6r3WB1gagMnjfVK1BAGyg==
X-Received: by 2002:a17:902:c946:b0:188:e49e:2657 with SMTP id i6-20020a170902c94600b00188e49e2657mr7602324pla.151.1668778780811;
        Fri, 18 Nov 2022 05:39:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8c0d:0:b0:573:1ead:4b00 with SMTP id c13-20020aa78c0d000000b005731ead4b00ls1295414pfd.10.-pod-prod-gmail;
 Fri, 18 Nov 2022 05:39:40 -0800 (PST)
X-Received: by 2002:a63:4461:0:b0:43b:f4a3:2f8d with SMTP id t33-20020a634461000000b0043bf4a32f8dmr6808875pgk.317.1668778780084;
        Fri, 18 Nov 2022 05:39:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668778780; cv=none;
        d=google.com; s=arc-20160816;
        b=tufMkUPENBpiTLfcqJoGJncEoBZveQI034Nzr89Quctrp8+CFkl9Ui+kqjKW6WnvTr
         KF9ArThMUTezXMp4U7qZVMyhyzR3Qu5ux73WPwYP/hgu1Asfrsw8tsJz7hXT0vQ+iSEV
         /hiEprnVCw4NUCtg8hAKzzHVkIL+lDpXJLaM5zge9qzZEixzw/5BT0jWHYnAp9xKKp0Q
         g7YkL8fPa7jIZsYIWIHQfEusrZJGrfzzXh3qMbTs1CWqdg18jZVeS/1EINzpnxTW2RJ4
         HCxKjU7Bkn5d5RusM1UzfzGEVxcPtSt+D1pFHi2SEeUgWJWtQX3P7FMVZJdWWOVLruUu
         +Ymg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EKwPWOIei0ORF4YEoW2azGGh2uCAPxfNzIEZVLw0jwE=;
        b=uHrEiXVKaP2tgEAtkZgBv7gx3bDTnam03VJV683IqEvUQDTWjs7NRS0BPpmRWDacnX
         f0xUfGbj0kvjZRvfRsI/sX/zF2UALyotbkWdB6Wf4Y5Kq+NggJaX8mM17voTgpV1AZ9N
         j3asfJZ4+BUdxDBGctrZjcP8y+Qa1oIbRiytUSNp503Zqo/zwBSb8jwF/lwB5GD4UrFm
         j57tgDq8b6JyGT7DxwZU8X0pGMKoPMEWoXILLG02S+TlQEJuBuyYchAVDoTr5sio2J6k
         vYKabvHiRFrWT7kjvOP4hfC9LjRMcdIzHCOwXh3D0ybWecdXf5iQQZ/phJx4viebcDwc
         t8KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fetFG9vb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id 19-20020a621813000000b005721caee4adsi211951pfy.3.2022.11.18.05.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 05:39:40 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-368edbc2c18so49342197b3.13
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 05:39:40 -0800 (PST)
X-Received: by 2002:a81:dd05:0:b0:36e:8228:a127 with SMTP id
 e5-20020a81dd05000000b0036e8228a127mr6571943ywn.299.1668778779156; Fri, 18
 Nov 2022 05:39:39 -0800 (PST)
MIME-Version: 1.0
References: <Y3VEL0P0M3uSCxdk@sol.localdomain> <CAG_fn=XwRo71wqyo-zvZxzE021tY52KKE0j_GmYUjpZeAZa7dA@mail.gmail.com>
 <Y3b9AAEKp2Vr3e6O@sol.localdomain>
In-Reply-To: <Y3b9AAEKp2Vr3e6O@sol.localdomain>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Nov 2022 14:39:02 +0100
Message-ID: <CAG_fn=Upw7AsM_wZq0ajPixbAKp-izC7LMxyN_5onfL=OBhRzA@mail.gmail.com>
Subject: Re: KMSAN broken with lockdep again?
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fetFG9vb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > As far as I can tell, removing `KMSAN_SANITIZE_lockdep.o :=3D n` does
> > not actually break anything now (although the kernel becomes quite
> > slow with both lockdep and KMSAN). Let me experiment a bit and send a
> > patch.

Hm, no, lockdep isn't particularly happy with the nested
lockdep->KMSAN->lockdep calls:

------------[ cut here ]------------
DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
WARNING: CPU: 0 PID: 0 at kernel/locking/lockdep.c:5508 check_flags+0x63/0x=
180
...
 <TASK>
 lock_acquire+0x196/0x640 kernel/locking/lockdep.c:5665
 __raw_spin_lock_irqsave ./include/linux/spinlock_api_smp.h:110
 _raw_spin_lock_irqsave+0xb3/0x110 kernel/locking/spinlock.c:162
 __stack_depot_save+0x1b1/0x4b0 lib/stackdepot.c:479
 stack_depot_save+0x13/0x20 lib/stackdepot.c:533
 __msan_poison_alloca+0x100/0x1a0 mm/kmsan/instrumentation.c:263
 native_save_fl ./include/linux/spinlock_api_smp.h:?
 arch_local_save_flags ./arch/x86/include/asm/irqflags.h:70
 arch_irqs_disabled ./arch/x86/include/asm/irqflags.h:130
 __raw_spin_unlock_irqrestore ./include/linux/spinlock_api_smp.h:151
 _raw_spin_unlock_irqrestore+0x60/0x100 kernel/locking/spinlock.c:194
 tty_register_ldisc+0xcb/0x120 drivers/tty/tty_ldisc.c:68
 n_tty_init+0x1f/0x21 drivers/tty/n_tty.c:2521
 console_init+0x1f/0x7ee kernel/printk/printk.c:3287
 start_kernel+0x577/0xaff init/main.c:1073
 x86_64_start_reservations+0x2a/0x2c arch/x86/kernel/head64.c:556
 x86_64_start_kernel+0x114/0x119 arch/x86/kernel/head64.c:537
 secondary_startup_64_no_verify+0xcf/0xdb arch/x86/kernel/head_64.S:358
 </TASK>
---[ end trace 0000000000000000 ]---

> > If this won't work out, we'll need an explicit call to
> > kmsan_unpoison_memory() somewhere in lockdep_init_map_type() to
> > suppress these reports.

I'll go for this option.

> Thanks.
>
> I tried just disabling CONFIG_PROVE_LOCKING, but now KMSAN warnings are b=
eing
> spammed from check_stack_object() in mm/usercopy.c.
>
> Commenting out the call to arch_within_stack_frames() makes it go away.

Yeah, arch_within_stack_frames() performs stack frame walking, which
confuses KMSAN.
We'll need to apply __no_kmsan_checks to it, like we did for other
stack unwinding functions.


> - Eric

T




--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUpw7AsM_wZq0ajPixbAKp-izC7LMxyN_5onfL%3DOBhRzA%40mail.gm=
ail.com.
