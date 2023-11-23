Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBWF67KVAMGQEDP4A35A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B91A77F5574
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 01:39:53 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1efa8a172d5sf479177fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 16:39:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700699992; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCgbV6yNvcmKBhbzNEUrynbdDjviaNdlMoreERzDT4DPJPuG5o6f6zj9p0n2GpXYMF
         tUvkEIy8T6KcS3aXOsIptFuuRQtZggtPMDQLLafglYBUg8jZgCRhYphnwsVHr45A7dIK
         V7LdKlbBnyNUdEDpDHjYH5p/GqH3ifnXq3U1Vpj1f8jxo2toyPWyrLS/ApEGX7BwzqsA
         1a4Bs1RaDK85M1IIGJTkjU6/Be72kYCPFPwuUN3f6I48zbyNpUKpde+b3yqOgroVY6fC
         2MnvisyWeW93xHimftrc5NvK2jDaCRCcphgzzVBwWmFxI7f9g4FqRZ4/IvoLbsyo8yCI
         ti/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gGh0tg/hibXaPiwMPxo8k8HJM6FRjsge8dZYOd1YaRU=;
        fh=NVgvAXPfVK0ponh7RFTP0QpH116n/1QCtqjY2a2t4sI=;
        b=M5T6QT1Huen1irXg1wKmFdPPYxAYIRRlsdpf1kWNhNtY7TqzbU1reS8+ilw/hU/fHA
         SawkUtXCYiocNDJ2WoacJ+vvREy4ezA5tuEPNdHmM/1g2UAI1QV84D6+jZ5aA/ZmY7CG
         2oEZKlmGlg4PpGEkTz7txFMwf2oogoA0fml5d2X48AEgWgkAu4OTT8y4GMy9Ss8WSQrd
         msTcweVsrZvPT9ZX5ZjvKHbuALu8Tzm2RZBGRTmst1yFxtPjqRDltz75bxw9Fn1Mf1O2
         /2AT52oQIKzayLo2xJ8VZMHNG2qn25hxc/4f9mTCI8NqPGUx1XXBy4MwFAhOkOddRhm+
         exWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kGFXs1My;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700699992; x=1701304792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gGh0tg/hibXaPiwMPxo8k8HJM6FRjsge8dZYOd1YaRU=;
        b=nxHouMDraAeHtvsctO9/8nJl3frqjHZ2/kZrDfWrwJOQc/QtZkCAEWeb/UHoCKgU0f
         v5+NGGLO3GoyYFSVSScAeoQ3rB4Oo9U2KMhS4dYGMnCc18+FmMlePxv033K9asYavx8/
         dEt+KBDCiPymcuRA53ZHyf7DAce7FL343pIjJhlC6eisv5zQTwsy5/SSnT1p8EPqjqdb
         tR1sYWJfOni4cr75MSKTXLQl369giDh6ohaOKRSb+7skao9s7/oZoLXg7/BhoapJqKPd
         +XJZyeTxS01gv63G36QB4eiNgFauJX5SAW9tHB5o+j7waQRG061QSXWTtbY06gHn1ik6
         MlsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700699992; x=1701304792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gGh0tg/hibXaPiwMPxo8k8HJM6FRjsge8dZYOd1YaRU=;
        b=c+iniftXx/uydY8jq2urRolWNYhdeI4SJQCsREZAsoMz3zqgxk2pwT6mr6ckuzThTr
         z4oRCpl2+N+huns+sOppJyeUcEjN35nYl+pvYZEcQDZLgKlCygcn9XGpmMNHThMrdMSc
         SHwoxmAN5dAXLYTAyQDph/VLXstNhBIMuj0KSKr+zoJC4PnRThRo6TGtpymFwR2mXDyS
         nfuHesL5vXSQDk6hxVFbyjx12r74Mfcx7mXiD3YFXrwAhyGhHTRjVJA8+ioCk4pzCaNH
         J2Ap+LcZ5+7WIRAY7Kq2A4XMVwSFJbG70WperUOLmzRHkF65zuBLiJUu+pobGJN+rvhI
         xAMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700699992; x=1701304792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gGh0tg/hibXaPiwMPxo8k8HJM6FRjsge8dZYOd1YaRU=;
        b=QLm4syobf/B0V7nrR4SUV4Bs2tGERL+eXwhUN1y4ofNpkwiagqdh6HJii4d5Al53hx
         OA2r9Fk4pEgaywhs+JzaogESXnp4hkxnqAI6tBNfrXaqYl26rfSuWihYUeZTRRToBXYC
         UwiHHnf5OQ16uHks/jOMAFN40fpZx0xpDI7VgyRMYPMOVYj0fGYva9RhuocxgtTaarDy
         v/5z2A8rga8Tf+47zdHAEQ02ySpsE9vdclFaGO1ZkUmRi0o3U7uOdajc6shc4oc56OWq
         YQwaVWiJZdEZkFbkt8XX7Ltd2jnfU5dudHLg/e/a4E0IWkEjeh4HV5bpJP9Sn89cRO7T
         A/4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwDZoR+fhFgLVPDooTnuGBlBvsWpULW5z/lpRjZARU2Aov4nr7+
	W5NlFzpvmPJWrdnb7RQRPHM=
X-Google-Smtp-Source: AGHT+IHHbNNvJC+Os8uqGv5njTdx6eg8XaCUaV9jcJUb4tLdh/lSn9DTbOy/+pUT0sRn9v3Le7v54A==
X-Received: by 2002:a05:6870:3d86:b0:1f9:5ef5:44df with SMTP id lm6-20020a0568703d8600b001f95ef544dfmr5157638oab.14.1700699992483;
        Wed, 22 Nov 2023 16:39:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b489:b0:1f5:bb3d:98cc with SMTP id
 y9-20020a056870b48900b001f5bb3d98ccls134673oap.0.-pod-prod-04-us; Wed, 22 Nov
 2023 16:39:52 -0800 (PST)
X-Received: by 2002:a05:6870:c98f:b0:1e1:e36a:fb74 with SMTP id hi15-20020a056870c98f00b001e1e36afb74mr5331607oab.26.1700699991835;
        Wed, 22 Nov 2023 16:39:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700699991; cv=none;
        d=google.com; s=arc-20160816;
        b=xug4WFWt6g+mPGga+06uQ7TbL2N0+L43DjCvOkt263OF6PdNjrT+nm+mrELUIqmsFh
         VPwJDFzkXmXi6lyutb7SB42rNEmjmYMf37NynTHrRg5xARP8t4CdhyYpU8mgSKzl9aBN
         7yXYfmVgDGdqwUeKf1/uOx635rZ+hu6QIEUACVi10Ihw6V5QsoXzU827Tb27deyYp/Wf
         xxVRzyLQggsk+Fzi/SP+YerTNrvMOxUUm7kTYLnaJULvUe3ETBI+XZ+X1oZgJaSjTh5s
         GhwgHCAMe1BJ4i7jcGozaXCI2mKbI40aVSFwFX6NoH33vT6UNFyS1y96PIhfXV9Hm2s/
         Yyww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EwQlGsWYOqxIdXRKSpiAx1SqqlnvS6MmmN0ONz1p3kw=;
        fh=NVgvAXPfVK0ponh7RFTP0QpH116n/1QCtqjY2a2t4sI=;
        b=ozg8EAsWm7FiO0E7wpqawpXDSNhWZjoRlF1hTIOXaXN+lUuj/Oh6p5Sc+c6y1FNphD
         xE9NvyY3Wp34qAdTTQUO2qICZc4kaJ1euhqjV3h89Y5rd6Y6ACXx7yeDb/yHJ7Y1S1WB
         +HZM+4cy10kHSx3ePW3/lYhD8KIMqSecFjGzR9coznClaRioUjfnNUPfnizRL+fSUvMn
         w3aOU5+EOJl+E8LadpYaL6dBpH7zOIv+eE7bjdUmdc948HPZpJrftIwwTztZgPLgle9E
         C7fYyBQ+Yok8hlr88LwChOFnHE78tuTuHFFDsWTRaZo8CmhTmjmQTpY3zFdQQLZ1zIwL
         D/tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kGFXs1My;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id u27-20020a056870f29b00b001dcf3f50667si30884oap.0.2023.11.22.16.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 16:39:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id 71dfb90a1353d-4acb1260852so119576e0c.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 16:39:51 -0800 (PST)
X-Received: by 2002:a1f:6244:0:b0:4ac:962c:c2ea with SMTP id
 w65-20020a1f6244000000b004ac962cc2eamr4289472vkb.10.1700699991089; Wed, 22
 Nov 2023 16:39:51 -0800 (PST)
MIME-Version: 1.0
References: <20231122231202.121277-1-andrey.konovalov@linux.dev>
In-Reply-To: <20231122231202.121277-1-andrey.konovalov@linux.dev>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Thu, 23 Nov 2023 09:39:39 +0900
Message-ID: <CAB=+i9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn=dw@mail.gmail.com>
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, Feng Tang <feng.tang@intel.com>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kGFXs1My;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a32
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 23, 2023 at 8:12=E2=80=AFAM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> When both KASAN and slub_debug are enabled, when a free object is being
> prepared in setup_object, slub_debug poisons the object data before KASAN
> initializes its per-object metadata.
>
> Right now, in setup_object, KASAN only initializes the alloc metadata,
> which is always stored outside of the object. slub_debug is aware of
> this and it skips poisoning and checking that memory area.
>
> However, with the following patch in this series, KASAN also starts
> initializing its free medata in setup_object. As this metadata might be
> stored within the object, this initialization might overwrite the
> slub_debug poisoning. This leads to slub_debug reports.
>
> Thus, skip checking slub_debug poisoning of the object data area that
> overlaps with the in-object KASAN free metadata.
>
> Also make slub_debug poisoning of tail kmalloc redzones more precise when
> KASAN is enabled: slub_debug can still poison and check the tail kmalloc
> allocation area that comes after the KASAN free metadata.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Thank you for looking at this quickly!
Unfortunately the problem isn't fixed yet with the patch.

I applied this on top of linux-next and built a kernel with the same config=
,
it is still stuck at boot.

[dmesg]

[    0.000000] Linux version
6.7.0-rc2-next-20231122-00001-gfc1613c2f6f3
(hyeyoo@localhost.localdomain) (gcc (GCC) 11.33
[    0.000000] Command line: console=3DttyS0 root=3D/dev/sda1 nokaslr
[    0.000000] RIP: 0010:setup_arch (arch/x86/kernel/setup.c:443
arch/x86/kernel/setup.c:665 arch/x86/kernel/setup.c:81
[ 0.000000] Code: b6 0a 08 00 48 89 c5 48 85 c0 0f 84 58 13 00 00 48
c1 e8 03 48 83 05 4e a9 66 00 01 80 3c 18 00 0f3

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
   0:   b6 0a                   mov    $0xa,%dh
   2:   08 00                   or     %al,(%rax)
   4:   48 89 c5                mov    %rax,%rbp
   7:   48 85 c0                test   %rax,%rax
   a:   0f 84 58 13 00 00       je     0x1368
  10:   48 c1 e8 03             shr    $0x3,%rax
  14:   48 83 05 4e a9 66 00    addq   $0x1,0x66a94e(%rip)        # 0x66a96=
a
  1b:   01
  1c:   80 3c 18 00             cmpb   $0x0,(%rax,%rbx,1)
  20:   f3                      repz
[    0.000000] RSP: 0000:ffffffff86207e00 EFLAGS: 00010046 ORIG_RAX:
0000000000000009
[    0.000000] RAX: 1fffffffffe40069 RBX: dffffc0000000000 RCX: 1ffffffff12=
30a30
[    0.000000] RDX: 0000000000000000 RSI: 0107d62120059000 RDI: ffffffff891=
85180
[    0.000000] RBP: ffffffffff200348 R08: 8000000000000163 R09: 1ffffffff12=
30a28
[    0.000000] R10: ffffffff89194150 R11: 0000000000000000 R12: 00000000000=
00010
[    0.000000] R13: ffffffffff200354 R14: 0107d62120058348 R15: 0107d621200=
58348
[    0.000000] FS:  0000000000000000(0000) GS:ffffffff88f75000(0000)
knlGS:0000000000000000
[    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    0.000000] CR2: ffffffffff200348 CR3: 0000000009128000 CR4: 00000000000=
000b0
[    0.000000] Call Trace:
[    0.000000]  <TASK>
[    0.000000] ? show_regs (arch/x86/kernel/dumpstack.c:478)
[    0.000000] ? early_fixup_exception (arch/x86/mm/extable.c:364)
[    0.000000] ? do_early_exception (arch/x86/kernel/head64.c:423)
[    0.000000] ? early_idt_handler_common (arch/x86/kernel/head_64.S:555)
[    0.000000] ? setup_arch (arch/x86/kernel/setup.c:443
arch/x86/kernel/setup.c:665 arch/x86/kernel/setup.c:814)
[    0.000000] ? __pfx_setup_arch (arch/x86/kernel/setup.c:728)
[    0.000000] ? vprintk_default (kernel/printk/printk.c:2318)
[    0.000000] ? vprintk (kernel/printk/printk_safe.c:45)
[    0.000000] ? _printk (kernel/printk/printk.c:2328)
[    0.000000] ? __pfx__printk (kernel/printk/printk.c:2323)
[    0.000000] ? init_cgroup_root (kernel/cgroup/cgroup.c:2054)
[    0.000000] ? cgroup_init_early (kernel/cgroup/cgroup.c:6077
(discriminator 13))
[    0.000000] ? start_kernel (init/main.c:897 (discriminator 3))
[    0.000000] ? x86_64_start_reservations (arch/x86/kernel/head64.c:543)
[    0.000000] ? x86_64_start_kernel (arch/x86/kernel/head64.c:536)
[    0.000000] ? secondary_startup_64_no_verify (arch/x86/kernel/head_64.S:=
432)
[    0.000000]  </TASK>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9QFeQqSAhwY_BF-DZvZ9TL_rWz7nMOBhDWhXecamsn%3Ddw%40mail.=
gmail.com.
