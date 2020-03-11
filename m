Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBK4SUPZQKGQEC5OX7GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D930E18169D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 12:19:07 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id y15sf305809lji.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 04:19:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583925547; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxwMk80GopxNH+Qkf1HH5EVIT+7s+rjUgSh3MXhDVI7Ej+Gfa0DCa1fUhzdcBp28Df
         lcuC8gtSQWt5BSAcUypoveeze/43vWXmhAQmHO5iQDfae6eMId+lcrgTkFfMOPUInwgH
         mP8p8wek9rth8KfzvH3HzVaqhnX9oyAorO93Ie3S510SD6aFstZ0jV5GUURImHmn1oAV
         rnF0qQUA2kSbv4PYon02xvmyqumXUNYAVPbBh6Wz43vA/HHjUQRmzgpqXaBgpFztoBsM
         dlz8zq/Mearv4Lg5w9IwjWw4VoE1YCHOLT7TrgBElnl8tK94LkM+BVnbbsEfmPVvd2XT
         VpCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=N47eSv/uxnyW9NtJ+mTpDejGhFIBXMafU9XTFn1VQh0=;
        b=Y7bhjhlwcB1VjGWOSn11M7OdThDLOXROOn0CoIsYgaCJg7K1xLmnyDJ7J7JpBCRFQo
         IrAep9WuLDGpmazRcC8bN/hfopKKK41793HZwkeNTR5WMhBNCPqyNws+fXrIS8POVtZC
         dUayw5MoXgJp1hF/Y4Ne89jjbZ/nkv0Oqki5RkwOBdDtuLuIUxJUQX59JADjmUNqxcul
         HFA0a6rbFETpyKC5tY995PlRx8XW1uomvWfphR8QtUqFz5Yj6hR/ux/W7UkLz66xHCl9
         xnTsbeivfu4D5kqyQ1XX9bLIGJon+CJCm3iOP1VJdRyIs9uyQc0Yx+SoGmkOQoJzEi/L
         eK+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=N47eSv/uxnyW9NtJ+mTpDejGhFIBXMafU9XTFn1VQh0=;
        b=bcPjgYQQhr5nv9VgvUSE9lMi3xOwTFGJWHM14V6l+35G/FbP7WjEsb3K1qM81JQrZ9
         YBTm58DCMKF46vf7ZPX9cKzDwzdqW7JQHtzKh2gbLkUJEBjqsfLS/D1HHstQenK+pyfo
         RaGrsOcg1Rok84cwkNKtPK37zMNghkB9sYTjhQXqhu3ymJ+dq1kFKBc7IWn+WlpmzzvU
         CBDudSZ/GGbJw1A7PBz2TS2UMqfPKAvSrlPOVRdcMC6+MqOcXBaVrOlBNdML9xMSLc4F
         rHmUb/gfN98STrOjv0XSEygZeCEXHCgOO7AW5F1ZzULpXMtbLkBfUIr7xeRlMhL4AYlY
         nP4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N47eSv/uxnyW9NtJ+mTpDejGhFIBXMafU9XTFn1VQh0=;
        b=S2cPiPNRRNCndi4LCI3PUJCk9EjmzflesNnJZbgdaNLy7hfRE51k7B1+1PEZxlpTs+
         LIAbfM01IzSVODwnYMX3pApWLYCMnyry/a4oacArLcCWafr2d252NwRN9We1pjmuBEdp
         jkXMq5EZdPe2Rxz73CxrBWJFnUS9KbguDlud0ERVENBVq7gjFZTTk5sl2aISbq0QIUPs
         B1JnnNhZywKs7QaBnutHo7OjNYt6s9gB5nEXMS0LBJvjo/ZRqZaoaEWdkqR57LYzMj4S
         OddNs3pHcbJ8fC1rhc7xSW4HpVjLJwOtxw0xLpeMG0P3GmGRoLuF4OsrDl9cK7EO6U7W
         rQRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3/I9uxrYVfN4QkMb3Tw88PJ0tlEmNiA0FNB3XlC2hoZOjgb9sZ
	IuQIynLLJ1OeySRKy9+J8lY=
X-Google-Smtp-Source: ADFU+vt2xeL+Wk9D7mUMN+N9RMWaw6wBeE351MD4ZpJ0i2xBKik6Zg4YHehL2u1zghI+BazkYpj5Nw==
X-Received: by 2002:a2e:87cd:: with SMTP id v13mr1800745ljj.210.1583925547436;
        Wed, 11 Mar 2020 04:19:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4bd6:: with SMTP id y205ls132217lfa.8.gmail; Wed, 11 Mar
 2020 04:19:06 -0700 (PDT)
X-Received: by 2002:a05:6512:31d6:: with SMTP id j22mr1814869lfe.173.1583925546804;
        Wed, 11 Mar 2020 04:19:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583925546; cv=none;
        d=google.com; s=arc-20160816;
        b=dtCpen8AYyLMV7p24yd20+3N+2a3FMqGZA5AnaxyIiXG8oZKMviR1uzNTvpX8PaIXZ
         amXBLwBUrpKPEyPeVMOD3CzvFzukKTA0HqK2e/SrWhZfDqjuOZaEEn4voDLNDqL+2L+b
         9mISlfkTQk/DpSnd8gUBQXxvn8KQDG/62O2/bnl/nXaf+KCJmxRIBq+3cpCAuForxda1
         bvqjB1etLIO9Xd4xzF8jTghixYQmoFVftvY8fPUO1USTbT+2pdHuP5bC324zF2daeWTr
         BaR5ASYAlGqzfF2Q/RDJ9orysJdKKtBzM/HtRwXifd5xIM3UVcVHHgt1XpN4HCRBn9J/
         tlkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=KqYmo91Nk7DL+n1n7Aa1VsEPP1018vkpbsQOMwyvGSU=;
        b=C2XNGIN/MHkbcBTH2+01RNSIqcW3aySTDoMRLOmjRrKAu/VRU9Hdw1Anp7DJise/k1
         NwBL1Mm1lW0rQiguovblbqwtgHT1y68jNIcFA6bOJUlVPuOpQKJ/Oe9lcsOr+jnZFvrG
         Y4mfeNY41hOYtzrHICY/4Bt1mFF/DZ3mMbG6g50CLA+anuOtyePIMZtj/osUWc+6Haqt
         5c+2PoRUUW7+hHuopoBXRsq13tF6KrlwsmHVYUDVpDyclcqiUspSVjIg9aGbdeKNidih
         fk88NW/sSh5NeRxOxZPz0C4mc+B+0r3UTMk08KIBEmPJg1NeWhhhFs5C3AFJ29xJ1Ra1
         yOJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id u8si87789lfu.3.2020.03.11.04.19.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Mar 2020 04:19:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jBzO2-0019K5-FE; Wed, 11 Mar 2020 12:18:54 +0100
Message-ID: <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins
 <brendanhiggins@google.com>, David Gow <davidgow@google.com>
Cc: linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Date: Wed, 11 Mar 2020 12:18:53 +0100
In-Reply-To: <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 (sfid-20200306_010352_481400_662BF174) <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Wed, 2020-03-11 at 11:32 +0100, Johannes Berg wrote:
>=20
> I do see issues with modules though, e.g.=20
> https://p.sipsolutions.net/1a2df5f65d885937.txt
>=20
> where we seem to get some real confusion when lockdep is storing the
> stack trace??
>=20
> And https://p.sipsolutions.net/9a97e8f68d8d24b7.txt, where something
> convinces ASAN that an address is a user address (it might even be
> right?) and it disallows kernel access to it?

I can work around both of these by not freeing the original module copy
in kernel/module.c:

        /* Get rid of temporary copy. */
//      free_copy(info);

but I really have no idea why we get this in the first place?

Another interesting data point is that it never happens on the first
module.

Also, I've managed to get a report like this:

Memory state around the buggy address:
 000000007106cf00: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
 000000007106cf80: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
>000000007106d000: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
                   ^
 000000007106d080: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b
 000000007106d100: 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b


which indicates that something's _really_ off with the KASAN shadow?


Ohhh ...

$ gdb -p ...
(gdb) p/x task_size
$1 =3D 0x7fc0000000
(gdb) p/x __end_of_fixed_addresses
$2 =3D 0x0
(gdb) p/x end_iomem
$3 =3D 0x70000000
(gdb) p/x __va_space

#define TASK_SIZE (task_size)
#define FIXADDR_TOP        (TASK_SIZE - 2 * PAGE_SIZE)

#define FIXADDR_START      (FIXADDR_TOP - FIXADDR_SIZE)
#define FIXADDR_SIZE       (__end_of_fixed_addresses << PAGE_SHIFT)

#define VMALLOC_END       (FIXADDR_START-2*PAGE_SIZE)

#define MODULES_VADDR   VMALLOC_START
#define MODULES_END       VMALLOC_END
#define VMALLOC_START ((end_iomem + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1))
#define VMALLOC_OFFSET  (__va_space)
#define __va_space (8*1024*1024)


So from that, it would look like the UML vmalloc area is from
0x  70800000 all the way to
0x7fbfffc000, which obviously clashes with the KASAN_SHADOW_OFFSET being
just 0x7fff8000.


I'm guessing that basically the module loading overwrote the kasan
shadow then?

I tried changing it

 config KASAN_SHADOW_OFFSET
        hex
        depends on KASAN
-       default 0x7fff8000
+       default 0x8000000000


and also put a check in like this:

+++ b/arch/um/kernel/um_arch.c
@@ -13,6 +13,7 @@
 #include <linux/sched.h>
 #include <linux/sched/task.h>
 #include <linux/kmsg_dump.h>
+#include <linux/kasan.h>
=20
 #include <asm/pgtable.h>
 #include <asm/processor.h>
@@ -267,9 +268,11 @@ int __init linux_main(int argc, char **argv)
        /*
         * TASK_SIZE needs to be PGDIR_SIZE aligned or else exit_mmap craps
         * out
         */
        task_size =3D host_task_size & PGDIR_MASK;
=20
+       if (task_size > KASAN_SHADOW_OFFSET)
+               panic("KASAN shadow offset must be bigger than task size");


but now I just crash accessing the shadow even though it was mapped fine?


Pid: 504, comm: modprobe Tainted: G           O      5.5.0-rc6-00009-g09462=
ab4014b-dirty
RIP: =20
RSP: 000000006d68fa90  EFLAGS: 00010202
RAX: 000000800e0210cd RBX: 000000007010866f RCX: 00000000601a9777
RDX: 000000800e0210ce RSI: 0000000000000004 RDI: 000000007010866c
RBP: 000000006d68faa0 R08: 000000800e0210cd R09: 0000000060041432
R10: 000000800e0210ce R11: 0000000000000001 R12: 000000800e0210cd
R13: 0000000000000000 R14: 0000000000000001 R15: 00000000601c2e82
Kernel panic - not syncing: Kernel mode fault at addr 0x800e0210cd, ip 0x60=
1c332b
CPU: 0 PID: 504 Comm: modprobe Tainted: G           O      5.5.0-rc6-00009-=
g09462ab4014b-dirty #24
Stack:
601c2f89 70108638 6d68fab0 601c1209
6d68fad0 601a9777 6cf2b240 7317f000
6d68fb40 601a2ae9 6f15b118 00000001
Call Trace:
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
__kasan_check_write (/home/tester/vlab/linux/mm/kasan/common.c:102)=20
__free_pages (/home/tester/vlab/linux/./arch/x86/include/asm/atomic.h:125 /=
home/tester/vlab/linux/./include/asm-generic/atomic-instrumented.h:748 /hom=
e/tester/vlab/linux/./include/linux/page_ref.h:139 /home/tester/vlab/linux/=
./include/linux/mm.h:593 /home/tester/vlab/linux/mm/page_alloc.c:4823)=20
__vunmap (/home/tester/vlab/linux/mm/vmalloc.c:2303 (discriminator 2))=20
? __asan_load4 (/home/tester/vlab/linux/mm/kasan/generic.c:251)=20
? sysfs_create_bin_file (/home/tester/vlab/linux/fs/sysfs/file.c:537)=20
__vfree (/home/tester/vlab/linux/mm/vmalloc.c:2356)=20
? delete_object_full (/home/tester/vlab/linux/mm/kmemleak.c:693)=20
vfree (/home/tester/vlab/linux/mm/vmalloc.c:2386)=20
? sysfs_create_bin_file (/home/tester/vlab/linux/fs/sysfs/file.c:537)=20
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
load_module (/home/tester/vlab/linux/./include/linux/jump_label.h:254 /home=
/tester/vlab/linux/./include/linux/jump_label.h:264 /home/tester/vlab/linux=
/./include/trace/events/module.h:31 /home/tester/vlab/linux/kernel/module.c=
:3927)=20
? kernel_read_file_from_fd (/home/tester/vlab/linux/fs/exec.c:993)=20
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
__do_sys_finit_module (/home/tester/vlab/linux/kernel/module.c:4019)=20
? sys_finit_module (/home/tester/vlab/linux/kernel/module.c:3995)=20
? __asan_store8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
sys_finit_module (/home/tester/vlab/linux/kernel/module.c:3995)=20
handle_syscall (/home/tester/vlab/linux/arch/um/kernel/skas/syscall.c:44)=
=20
userspace (/home/tester/vlab/linux/arch/um/os-Linux/skas/process.c:173 /hom=
e/tester/vlab/linux/arch/um/os-Linux/skas/process.c:416)=20
? save_registers (/home/tester/vlab/linux/arch/um/os-Linux/registers.c:18)=
=20
? arch_prctl (/home/tester/vlab/linux/arch/x86/um/syscalls_64.c:65)=20
? calculate_sigpending (/home/tester/vlab/linux/kernel/signal.c:200)=20
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
? __asan_load8 (/home/tester/vlab/linux/mm/kasan/generic.c:252)=20
fork_handler (/home/tester/vlab/linux/arch/um/kernel/process.c:154)=20

johannes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/674ad16d7de34db7b562a08b971bdde179158902.camel%40sipsolutions.net=
.
