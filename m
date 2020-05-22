Return-Path: <kasan-dev+bncBCH2XPOBSAERBEPPUD3AKGQEHLQKPMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D55ED1DF0AB
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 22:35:30 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id o6sf3384747otp.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 13:35:30 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mwB0eG2LD/cXFYBR8kliEIjOXPNrc+c8121PSg4Wf3o=;
        b=cL8PzGCQkKSKrfD/+pl0t/QoftvcSD5SXq5dg3SQKQjbVaTfEiyAdfRpEka5dgAw4x
         JQgn3/HDsed+D7ButGd6cezjxuN7anq8g9khOJXTE91UhLWSaQ9ax9al02exlXtxzzWY
         cXcWI6nU4rcjggPGnpL+ziDu4BbNNqZ45LAEocMK+AKv1xisRRqpEBGci61/nEzvhh1P
         BOs2ecV/U+LR1WziXUD/2V/ZmEQ8KL1Nm0BalUj44id0lp+vWGfdCQMrFP8B4IEFvYu4
         aJmqCNq8v+W+kP049MRs8MqHUXBeN1dpufHF1qKgGjv9vxi/M0RR+s2C3sBUyprFvYAt
         Lh6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mwB0eG2LD/cXFYBR8kliEIjOXPNrc+c8121PSg4Wf3o=;
        b=mwXntdnp8VL4+loniMb29iANxmVXu1P5K1ErC9cz1Qn65KAibU4d6ULgmTrgOAsbyL
         qFKAdTOOlo2wjXmOjuWxl8JPfgkCUU2aX20xyYoTlqeJxGcMA7RuSmix4WUcXF6QNGHq
         CNz5gcU64dpMZKKGuPsrVz1BEYua6okektYkhMo7qGyTtwzWOM3IwSb4HUS60n/E1ew6
         QpEAunQvqxt7LfVpTx7Pkv8C7sD0blFAuqObWZFtty3Judjr1rmiEwERVS5uUdLX61A6
         6Ig2HK1FuAbBkGD3al16kL42UCe2fCK+YAnl3HP7C4v7nhz/vu6VkyPgHfqxIZ8Fz/eW
         m0iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mwB0eG2LD/cXFYBR8kliEIjOXPNrc+c8121PSg4Wf3o=;
        b=qbdnhIa+IkpnhF38GFDBc2cFSb6NbfMceagfCKnpxFO0tVJPip62/VE9+Z3lOtxKC3
         XLvjiqT7SPAoPBGHlDqj6vHks4IiOySH4INfHCmXo4utMFvnhC8pefvZxMYdkYDolkwN
         TAD8KeWluV39XOBvm7cRY4SGWKO/xCddSlFPUqPgVnhnkQhuYhT0UOPdC1XK4YKfWPxT
         YHgJi3mOGfDDr9UVA/wX+fm+q/d59owAmCOk71VCmk/T7/LJ3GPlROVY/rOo1duLTN9S
         PMleslDMr71aLz/cGK6Lud7Al1VYtU5/ORoIiVvQUeR5fjm60ACrAvk7qh9NkJ47ZUTi
         6ibA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ASlhlVS+gKyydO5SdAU8YfZC25XNEZX077/dCkwsULM/Z6Tnd
	U9hbfUR6fwoPE4PeU+CnjdU=
X-Google-Smtp-Source: ABdhPJy8f9U+7a9EMqO3jeHtRGrM54F6xt1E1nwv9K/1fGQRzjpqQA7kfSLjmFTPkMYvqB0xXORnGw==
X-Received: by 2002:a9d:588:: with SMTP id 8mr6844938otd.183.1590179729633;
        Fri, 22 May 2020 13:35:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:19af:: with SMTP id k44ls515312otk.4.gmail; Fri, 22 May
 2020 13:35:29 -0700 (PDT)
X-Received: by 2002:a9d:837:: with SMTP id 52mr12786149oty.282.1590179729088;
        Fri, 22 May 2020 13:35:29 -0700 (PDT)
Date: Fri, 22 May 2020 13:35:28 -0700 (PDT)
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <18768d5f-b3ee-4c46-a87f-2d3642fd923b@googlegroups.com>
Subject: Is this a bug in KASAN?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_625_331356829.1590179728577"
X-Original-Sender: mudongliangabcd@gmail.com
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

------=_Part_625_331356829.1590179728577
Content-Type: multipart/alternative; 
	boundary="----=_Part_626_1120365460.1590179728577"

------=_Part_626_1120365460.1590179728577
Content-Type: text/plain; charset="UTF-8"

Hi all, I found an issue in analyzing the bug(
https://syzkaller.appspot.com/bug?id=d75bc1468fb7ff9c2fa47437f4f1dc87ec7d8094
).

From the allocation and free trace, we could find that the related object 
is "struct inode"(inode = kmem_cache_alloc(inode_cachep, GFP_KERNEL);  and 
kmem_cache_free(inode_cachep, inode);)

Allocated by task 2222:
 save_stack+0x43/0xd0 mm/kasan/kasan.c:448
 set_track mm/kasan/kasan.c:460 [inline]
 kasan_kmalloc+0xc4/0xe0 mm/kasan/kasan.c:553
 kasan_slab_alloc+0x12/0x20 mm/kasan/kasan.c:490
 kmem_cache_alloc+0x12e/0x760 mm/slab.c:3554
 *alloc_inode*+0xb2/0x190 fs/inode.c:212
 new_inode_pseudo+0x69/0x1a0 fs/inode.c:895
 get_pipe_inode fs/pipe.c:707 [inline]
 create_pipe_files+0x90/0x940 fs/pipe.c:748
 umh_pipe_setup+0xac/0x430 kernel/umh.c:431
 call_usermodehelper_exec_async+0x3c0/0x9e0 kernel/umh.c:93
 ret_from_fork+0x3a/0x50 arch/x86/entry/entry_64.S:412

Freed by task 2222:
 save_stack+0x43/0xd0 mm/kasan/kasan.c:448
 set_track mm/kasan/kasan.c:460 [inline]
 __kasan_slab_free+0x11a/0x170 mm/kasan/kasan.c:521
 kasan_slab_free+0xe/0x10 mm/kasan/kasan.c:528
 __cache_free mm/slab.c:3498 [inline]
 kmem_cache_free+0x86/0x2d0 mm/slab.c:3756
 *free_inode_nonrcu*+0x1c/0x20 fs/inode.c:230
 destroy_inode+0x151/0x1f0 fs/inode.c:267
 evict+0x5cd/0x960 fs/inode.c:575
 iput_final fs/inode.c:1520 [inline]
 iput+0x62d/0xa80 fs/inode.c:1546
 dentry_unlink_inode+0x49a/0x620 fs/dcache.c:376
 __dentry_kill+0x444/0x790 fs/dcache.c:568
 dentry_kill+0xc9/0x5a0 fs/dcache.c:687
 dput.part.26+0x65a/0x780 fs/dcache.c:848
 dput+0x15/0x20 fs/dcache.c:830
 __fput+0x558/0x890 fs/file_table.c:227
 ____fput+0x15/0x20 fs/file_table.c:243
 task_work_run+0x1e4/0x290 kernel/task_work.c:113
 exit_task_work include/linux/task_work.h:22 [inline]
 do_exit+0x1aee/0x2730 kernel/exit.c:865
 do_group_exit+0x16f/0x430 kernel/exit.c:968
 __do_sys_exit_group kernel/exit.c:979 [inline]
 __se_sys_exit_group kernel/exit.c:977 [inline]
 __x64_sys_exit_group+0x3e/0x50 kernel/exit.c:977
 do_syscall_64+0x1b1/0x800 arch/x86/entry/common.c:287
 entry_SYSCALL_64_after_hwframe+0x49/0xbe

But the use site of this bug is in the "io_is_direct". And the 
corresponding memory reference is "return (filp->f_flags & O_DIRECT) || 
IS_DAX(filp->f_mapping->host);". I do not find any operation related with 
the inode object.

So is this a bug in the KASAN?


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/18768d5f-b3ee-4c46-a87f-2d3642fd923b%40googlegroups.com.

------=_Part_626_1120365460.1590179728577
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hi all, I found an issue in analyzing the bug(<a href=
=3D"https://syzkaller.appspot.com/bug?id=3Dd75bc1468fb7ff9c2fa47437f4f1dc87=
ec7d8094">https://syzkaller.appspot.com/bug?id=3Dd75bc1468fb7ff9c2fa47437f4=
f1dc87ec7d8094</a>).</div><div><br></div><div>From the allocation and free =
trace, we could find that the related object is &quot;struct inode&quot;(in=
ode =3D kmem_cache_alloc(inode_cachep, GFP_KERNEL);=C2=A0 and kmem_cache_fr=
ee(inode_cachep, inode);)</div><div><br></div><div><div>Allocated by task 2=
222:</div><div>=C2=A0save_stack+0x43/0xd0 mm/kasan/kasan.c:448</div><div>=
=C2=A0set_track mm/kasan/kasan.c:460 [inline]</div><div>=C2=A0kasan_kmalloc=
+0xc4/0xe0 mm/kasan/kasan.c:553</div><div>=C2=A0kasan_slab_alloc+0x12/0x20 =
mm/kasan/kasan.c:490</div><div>=C2=A0kmem_cache_alloc+0x12e/0x760 mm/slab.c=
:3554</div><div>=C2=A0<b><font color=3D"#ff0000">alloc_inode</font></b>+0xb=
2/0x190 fs/inode.c:212</div><div>=C2=A0new_inode_pseudo+0x69/0x1a0 fs/inode=
.c:895</div><div>=C2=A0get_pipe_inode fs/pipe.c:707 [inline]</div><div>=C2=
=A0create_pipe_files+0x90/0x940 fs/pipe.c:748</div><div>=C2=A0umh_pipe_setu=
p+0xac/0x430 kernel/umh.c:431</div><div>=C2=A0call_usermodehelper_exec_asyn=
c+0x3c0/0x9e0 kernel/umh.c:93</div><div>=C2=A0ret_from_fork+0x3a/0x50 arch/=
x86/entry/entry_64.S:412</div><div><br></div><div>Freed by task 2222:</div>=
<div>=C2=A0save_stack+0x43/0xd0 mm/kasan/kasan.c:448</div><div>=C2=A0set_tr=
ack mm/kasan/kasan.c:460 [inline]</div><div>=C2=A0__kasan_slab_free+0x11a/0=
x170 mm/kasan/kasan.c:521</div><div>=C2=A0kasan_slab_free+0xe/0x10 mm/kasan=
/kasan.c:528</div><div>=C2=A0__cache_free mm/slab.c:3498 [inline]</div><div=
>=C2=A0kmem_cache_free+0x86/0x2d0 mm/slab.c:3756</div><div>=C2=A0<b><font c=
olor=3D"#ff0000">free_inode_nonrcu</font></b>+0x1c/0x20 fs/inode.c:230</div=
><div>=C2=A0destroy_inode+0x151/0x1f0 fs/inode.c:267</div><div>=C2=A0evict+=
0x5cd/0x960 fs/inode.c:575</div><div>=C2=A0iput_final fs/inode.c:1520 [inli=
ne]</div><div>=C2=A0iput+0x62d/0xa80 fs/inode.c:1546</div><div>=C2=A0dentry=
_unlink_inode+0x49a/0x620 fs/dcache.c:376</div><div>=C2=A0__dentry_kill+0x4=
44/0x790 fs/dcache.c:568</div><div>=C2=A0dentry_kill+0xc9/0x5a0 fs/dcache.c=
:687</div><div>=C2=A0dput.part.26+0x65a/0x780 fs/dcache.c:848</div><div>=C2=
=A0dput+0x15/0x20 fs/dcache.c:830</div><div>=C2=A0__fput+0x558/0x890 fs/fil=
e_table.c:227</div><div>=C2=A0____fput+0x15/0x20 fs/file_table.c:243</div><=
div>=C2=A0task_work_run+0x1e4/0x290 kernel/task_work.c:113</div><div>=C2=A0=
exit_task_work include/linux/task_work.h:22 [inline]</div><div>=C2=A0do_exi=
t+0x1aee/0x2730 kernel/exit.c:865</div><div>=C2=A0do_group_exit+0x16f/0x430=
 kernel/exit.c:968</div><div>=C2=A0__do_sys_exit_group kernel/exit.c:979 [i=
nline]</div><div>=C2=A0__se_sys_exit_group kernel/exit.c:977 [inline]</div>=
<div>=C2=A0__x64_sys_exit_group+0x3e/0x50 kernel/exit.c:977</div><div>=C2=
=A0do_syscall_64+0x1b1/0x800 arch/x86/entry/common.c:287</div><div>=C2=A0en=
try_SYSCALL_64_after_hwframe+0x49/0xbe</div></div><div><br></div><div>But t=
he use site of this bug is in the &quot;io_is_direct&quot;. And the corresp=
onding memory reference is &quot;return (filp-&gt;f_flags &amp; O_DIRECT) |=
| IS_DAX(filp-&gt;f_mapping-&gt;host);&quot;. I do not find any operation r=
elated with the inode object.</div><div><br></div><div>So is this a bug in =
the KASAN?</div><div><br></div><div><br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/18768d5f-b3ee-4c46-a87f-2d3642fd923b%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/18768d5f-b3ee-4c46-a87f-2d3642fd923b%40googlegroups.com</a>.<br =
/>

------=_Part_626_1120365460.1590179728577--

------=_Part_625_331356829.1590179728577--
