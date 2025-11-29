Return-Path: <kasan-dev+bncBCT4XGV33UIBBRPMVTEQMGQEORYZRJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb139.google.com (mail-yx1-xb139.google.com [IPv6:2607:f8b0:4864:20::b139])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7CEC9464A
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 19:07:02 +0100 (CET)
Received: by mail-yx1-xb139.google.com with SMTP id 956f58d0204a3-640d2ff4acdsf3656703d50.3
        for <lists+kasan-dev@lfdr.de>; Sat, 29 Nov 2025 10:07:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764439621; cv=pass;
        d=google.com; s=arc-20240605;
        b=OeNPGNAfxv+qFtMEKeL4wjBt5CN5wD913xRNUmjYkWLStNasqWNl5+9BUJEMgQ1Ihx
         y9Cm/54IellOsbWz+Dy5Ip0gycFlibLYs3d9d7DBYC4IebNhEXjYkI9ySN2fjgSdlDxG
         XjrseH4GbBoo6HrFrk5S0VplMCIMGXsDuW2P8vhj2o8edjQKs1gKQpYZLbrBdLUg5PB7
         EPgA+E6qa0ckYbJ1bCOqDWNEwhZklB1vJ5BBF4ugLm3c33+HgMd0Qs3YBwVGWI3KT1LL
         FtsJaH86UyUa5hdVF8by005a6HSlluHzmPVbUGoSXFcdwTTe1oqwgOCsuRHSBhh3W9Al
         Jhew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=HQS8lIHiC2E/NYN3utLsqLlZJj6XM3BkBEq/riRpC9w=;
        fh=IN73yIo1YhjmMSfObeg422wHVjKhf5iIBL1zgMu8Q5E=;
        b=Bxm8xkjwMjrbCpiSJ1gAhfZI7aOBlQ6rEr6Xo8y0TtpWsxU0YPbVFT025/JMqpChx+
         srbPSigbD5PDESJKaJHQbu9Crh40RfJtnp+rmmYBspOmeqOjdcQH/NstGb8Eom8DyEAB
         qcG2lN7ThFyJScZic4+FJcapHuOaD0xKLTEb2AshbVz856Ti4UoLU4TztvqHLq30f3GF
         owqjKwxjGtONptfC3BZipP+gdvX3mfA/yodX8J1XuX1SozT4qzucF3X2oqzC04MYusMe
         qYp4QNJefqHTAMBzrUParSCmryYfR0PDSSrShI2U+YO0I/3LrS+X4Qn4B42FKuM4XmBy
         aOHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=imequqQ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764439621; x=1765044421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HQS8lIHiC2E/NYN3utLsqLlZJj6XM3BkBEq/riRpC9w=;
        b=r90jIPOeKnd7LV7090qLyKIp5XP02jF+vcNUFX3o1YIIuKXGf5KwpRyjyJJMrgk8y9
         Mei2UyPUiw7rYsPvIgz4MW9jlLLcJz3nB6yAg6sXpXe5cTENN0jkm3feqW0ZPaOxZUSP
         L00T3XlujReTuP8lJns33STEw9iECdiZxqDrPmQBOCJ1ryhL13KbQrB8vfis/s+PbbtD
         MZ6t2eYbVcd51BWNSUWKZD3ZKlw3YXxfEzqV/5VivMnE4DWJCVpVuH75O7KZerdRRKRm
         wfRwf3fIXQGWGuvN5wXrPqrhNRGioBKcy3dPZTpnkJiVL53yFYYw5ijaXATcHzrZmhWh
         6/lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764439621; x=1765044421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HQS8lIHiC2E/NYN3utLsqLlZJj6XM3BkBEq/riRpC9w=;
        b=lZRuj1DYlntkpVF1vq3vsPJFaPvaWal1K0X4UQQBMpEpcpId7VG4N3oTEaELocMuWk
         AdERYGAq9qNxit2IbqI+42da1t8396pqe8kHnCoWzyJQuAu9tRWx1MkkowyAuH+XEi2H
         t+5mqa8tmdI/8BMQqOk/NbXblXoEmafej0GIfaDO/gvA19VJTjacyqnpnTQhv65p+zLW
         3LjeRd4+LgnKPVemNruLu9rco2rdQ8Z9MXjGOIifLTVn9yPQyO9K0lRp3hEpG06S2tYc
         3eSY2gBv6cY5GbovMgZUNjgKGfFjRostfU+eXLoJ2cm3tuES5SGWh2d/IxQW1DXQxlQx
         C/yw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVSi4fcHI50hBJEnUqMQOlYGOOIb+K9aBGNcaeoyL7TBWQWcMM+5eI7077qOILFaj+1Hd1Xg==@lfdr.de
X-Gm-Message-State: AOJu0YzvRZax1jXW37+SLQ9uaxhZWc6AOZSlGf+/SQ34DQeD5/uTDMNN
	xnfIamQExHCDE/f3mciq+KG1ivRBzr0s+FCVw09EJx5RunE2FNWnlYdt
X-Google-Smtp-Source: AGHT+IFZcxVTHjj7Qf8HjM3F3a2Fhk5muqo+j6m06aAbVTJaN6Vu9RUh/qS4Iw5i0vqPUHkWaD29RQ==
X-Received: by 2002:a53:e882:0:b0:63e:102f:e00e with SMTP id 956f58d0204a3-64302af16d4mr17702952d50.53.1764439621291;
        Sat, 29 Nov 2025 10:07:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aHu8cAHe1EzeoKjEGuGe6nysYgow/zP4Cz9moFtKlrHA=="
Received: by 2002:a05:690e:484:b0:640:d382:f19b with SMTP id
 956f58d0204a3-6433945d447ls2488888d50.1.-pod-prod-04-us; Sat, 29 Nov 2025
 10:07:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU442SWgwWcR7zphShTN1VJ9Jld+BGTWlldvxPFTeJiPDUEpSsIMmaeEINfHsd+4CeIpOv4LwJMAts=@googlegroups.com
X-Received: by 2002:a53:cb82:0:b0:640:d4fd:47fc with SMTP id 956f58d0204a3-64302b09b74mr17766711d50.63.1764439620334;
        Sat, 29 Nov 2025 10:07:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764439620; cv=none;
        d=google.com; s=arc-20240605;
        b=M2JwP+kIT+rY0d2B6aXaPf2XICDX8tHSiH1zesVx4YCB/sqNEdkU95FpytHg6WGNXg
         xo1iv8CeQdPQYCQebJW80rlvqKmFfzClJiebZMUJ48tLhhUKn4VX1pvAaL28KwdGndp1
         oNX/MUSknp2dcX2HoOztxRhmvM01V1nc6Ai8hKqWn2jCp0CZrtUiLJaiMP7XmH/SzuIl
         h1PXS3CHmRemztPVdUstSl7v5rMvT7NJjxFVfRS/m4wpcZe+RC5svOQ6vP2AbxirOotW
         bYJPWg89A8h0M/Y0EU9pedFOzYZn8XJAMMIz1E6GNEopCQfyQ9wXcTQnhtdZiFuAEOhT
         QuVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EIt6lFRNy0y5ogK7k6YPxw5lcXWuqpwlSXjb5ATV7rU=;
        fh=pGFgAJBsvJeWtqUikw5qji/ZCuhDRpLMu4NxYUvgRlQ=;
        b=Qm2Ep8WECHws7hj8mPU+SFMNemMLKSp35ZogyObvkvA8LnhRP9YRl27enJpqAlJKXK
         HAQK1FJ1wDJz959MqdrUDUnSj1EN5CaFfDtp1Lj7ApXzAHF/3tZZPQEuiNUcSix8Hmp7
         pS9GFtmElpvsjy3Ej+gzVggQDwHFJgRsi9Vp6dSTyMeUYlyeEl8Z947lB7IaWNJQPPAO
         SVbRX0S1YKxdXYBfNqH5OfhtN4La/xuPwEcrCDip2+P6BY7Btn49j/Lej5MC5Ns5n6hd
         bY2Bhh6TWiTtaxtxxicwT3pU4l6hMf87NrDd22jrUIsNt25spDoXYy1cf8dx72gJajGl
         gM4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=imequqQ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-78ad1033f4csi1920677b3.4.2025.11.29.10.07.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 29 Nov 2025 10:07:00 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6731D60051;
	Sat, 29 Nov 2025 18:06:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 952E3C4CEF7;
	Sat, 29 Nov 2025 18:06:58 +0000 (UTC)
Date: Sat, 29 Nov 2025 10:06:58 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: catalin.marinas@arm.com, kevin.brodsky@arm.com, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, urezki@gmail.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, bpf@vger.kernel.org,
 stable@vger.kernel.org, Jiayuan Chen <jiayuan.chen@linux.dev>
Subject: Re: [PATCH] kasan: hw_tags: fix a false positive case of vrealloc
 in alloced size
Message-Id: <20251129100658.6b25799da5ace00c3a6d0f42@linux-foundation.org>
In-Reply-To: <20251129123648.1785982-1-yeoreum.yun@arm.com>
References: <20251129123648.1785982-1-yeoreum.yun@arm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=imequqQ+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 29 Nov 2025 12:36:47 +0000 Yeoreum Yun <yeoreum.yun@arm.com> wrote:

> When a memory region is allocated with vmalloc() and later expanded with
> vrealloc() =E2=80=94 while still within the originally allocated size =E2=
=80=94
> KASAN may report a false positive because
> it does not update the tags for the newly expanded portion of the memory.
>=20
> A typical example of this pattern occurs in the BPF verifier,
> and the following is a related false positive report:
>=20
> [ 2206.486476] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [ 2206.486509] BUG: KASAN: invalid-access in __memcpy+0xc/0x30
> [ 2206.486607] Write at addr f5ff800083765270 by task test_progs/205
> [ 2206.486664] Pointer tag: [f5], memory tag: [fe]
> [ 2206.486703]
> [ 2206.486745] CPU: 4 UID: 0 PID: 205 Comm: test_progs Tainted: G        =
   OE       6.18.0-rc7+ #145 PREEMPT(full)
> [ 2206.486861] Tainted: [O]=3DOOT_MODULE, [E]=3DUNSIGNED_MODULE
> [ 2206.486897] Hardware name:  , BIOS
> [ 2206.486932] Call trace:
> [ 2206.486961]  show_stack+0x24/0x40 (C)
> [ 2206.487071]  __dump_stack+0x28/0x48
> [ 2206.487182]  dump_stack_lvl+0x7c/0xb0
> [ 2206.487293]  print_address_description+0x80/0x270
> [ 2206.487403]  print_report+0x94/0x100
> [ 2206.487505]  kasan_report+0xd8/0x150
> [ 2206.487606]  __do_kernel_fault+0x64/0x268
> [ 2206.487717]  do_bad_area+0x38/0x110
> [ 2206.487820]  do_tag_check_fault+0x38/0x60
> [ 2206.487936]  do_mem_abort+0x48/0xc8
> [ 2206.488042]  el1_abort+0x40/0x70
> [ 2206.488127]  el1h_64_sync_handler+0x50/0x118
> [ 2206.488217]  el1h_64_sync+0xa4/0xa8
> [ 2206.488303]  __memcpy+0xc/0x30 (P)
> [ 2206.488412]  do_misc_fixups+0x4f8/0x1950
> [ 2206.488528]  bpf_check+0x31c/0x840
> [ 2206.488638]  bpf_prog_load+0x58c/0x658
> [ 2206.488737]  __sys_bpf+0x364/0x488
> [ 2206.488833]  __arm64_sys_bpf+0x30/0x58
> [ 2206.488920]  invoke_syscall+0x68/0xe8
> [ 2206.489033]  el0_svc_common+0xb0/0xf8
> [ 2206.489143]  do_el0_svc+0x28/0x48
> [ 2206.489249]  el0_svc+0x40/0xe8
> [ 2206.489337]  el0t_64_sync_handler+0x84/0x140
> [ 2206.489427]  el0t_64_sync+0x1bc/0x1c0
>=20
> Here, 0xf5ff800083765000 is vmalloc()ed address for
> env->insn_aux_data with the size of 0x268.
> While this region is expanded size by 0x478 and initialise
> increased region to apply patched instructions,
> a false positive is triggered at the address 0xf5ff800083765270
> because __kasan_unpoison_vmalloc() with KASAN_VMALLOC_PROT_NORMAL flag on=
ly
> doesn't update the tag on increaed region.
>=20
> To address this, introduces KASAN_VMALLOC_EXPAND flag which
> is used to expand vmalloc()ed memory in range of real allocated size
> to update tag for increased region.

Thanks.

> Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS=E2=
=80=9D)
> Cc: <stable@vger.kernel.org>

Unfortunately this is changing the same code as "mm/kasan: fix
incorrect unpoisoning in vrealloc for KASAN",
(https://lkml.kernel.org/r/20251128111516.244497-1-jiayuan.chen@linux.dev)
which is also cc:stable.

So could you please take a look at the code in mm.git's
mm-hotfixes-unstable branch
(git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm) and base the
fix upon that?  This way everything should merge and backport nicely.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251129100658.6b25799da5ace00c3a6d0f42%40linux-foundation.org.
