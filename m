Return-Path: <kasan-dev+bncBCMKLENX6EKBB3PQ666QMGQE6B37UFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A863A44757
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 18:05:58 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5fe86c28863sf1843230eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 09:05:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740503150; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9VFpVNHitgQzLil4qBNg/np7Ydh7sD2ufuVo4Rw2L54+l5LIFHRg8GM1qbIK+U9Wt
         EGg9KpgyPavDwQxqlljiZVYnttkerf4Mzs8GsT0UrFr0jQQpviL7Cj/ucB7YF/AVT4GK
         Qzx0A+uwlaxK4uZnDEMkMydBLZRYmVybxsO7+GyiCn6XdlTYdbx73n/7oOJ2xKrrr/dS
         vY+KZUA3QnvvCBrM6DsnX7Dp0IPfghy19EHZC3cQl5ZTLzshY8nE5WcvEhIeIzkqsLz8
         BxsSngjBATrpUakL+TWEr0VHxz1J75Ed/NX6BbNUBknZXrXhUNepUegqneUopXxDiqq7
         MbNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=gRothLn1/0b0tC6pBttwZI9/2eK1Sz4U7pMTDNdaNaI=;
        fh=aQXHOdHPzvlW+nEmGQ3Wgug26eyKv3EVpB/h1NV9rKk=;
        b=hmoQxTn3jKeIftXFz4PiV867ZmgE61MOHRoxCXg0cz/cWpMEjJ2YX+YKEy7BTSQFkl
         nKAe12EmoC+/3Ph38E8xZqIqRdOuewpzzBXuIZnAp+hkUJCMa3DmKSZwDwCeTi+qKmxZ
         0Wy9c6vQDknQx52O1Cvk1H55QRrxUEA+jGbZp+UTLP5MmmGmZ7HFc/vbCqyrBDo2I0bg
         DP9fjS3Dg9VV/urd/0aOl84iEfi2Fr1ugM3rzX8ePYzIfjmNueX4o/TzactT8neLicMx
         TGxIlZmCVv6YH3UiXraFJGg818IkavtzuXoqasbTKrW14PW5Kn0G6ZUtGKlxf3xOh5GE
         yhvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpNiJ0xZ;
       spf=pass (google.com: domain of keith.busch@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=keith.busch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740503150; x=1741107950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gRothLn1/0b0tC6pBttwZI9/2eK1Sz4U7pMTDNdaNaI=;
        b=MUcz4AlqlZ1qirx/Mrsd0VYkif0kEcps9+pt2nbEArAfcffyT3jgpZQkNlarXMXvIo
         yH2KW5DwkRD3xKhVrv/lJB8pf3pHUU6Z8Fj0vyAHgK7RwIxbSuW2Aa25XPUkJPk23DdT
         8ebmZyG39dHDKyc33qGdec2pzwaZggS6oEq5qYH/UHkiBOv0u+Q+k6qcrD7MChvy6KHb
         ymswcSmsT1HMzU1LfvxS0oJY5P7PLvJCUDn6q6dE/cHoQrm8DiRSfnkOY3UvU1SVsqfO
         Pjx8DugqPqv/iV65qPTsbBTLOoHh0pRu+u8AJrgmhy5BDl5FFMj9KdNR1HfnQkcrziNd
         pj2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740503150; x=1741107950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=gRothLn1/0b0tC6pBttwZI9/2eK1Sz4U7pMTDNdaNaI=;
        b=VxyLZMWSnKi2ExdHEoxlfkkrmP99rpsGkspdOblrVvLVyn30wUTYtGJE/qoRkeOeME
         sbfJYAk3PkQnf/6guY7eC1H+JWfvD06EYB6n73V9Kj+6zKgN8cELnhqGsutcsNXOTF9I
         1M5CpUnR6yUaZLvrDwErJpmFFb4bgA60tYAPVRgEqRlNpqA2mB6Pu//87z2Xw444L+7Y
         lnUiyXb8E7+pmwND13VB98dXdvVrSPOz+CpQBgs4rtVBh7A+awr1FQ5A5khnKCVy4Opa
         4LiXkbsqMQG9QLBejon1DBGBRsmOIRGhPk1KrxdtJPcUw2pBgfb5f99DINZD7mLUbyFD
         TncA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740503150; x=1741107950;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gRothLn1/0b0tC6pBttwZI9/2eK1Sz4U7pMTDNdaNaI=;
        b=fP6G8hf5UDhz6Vc6uz+64nnvZnOBxXhLVP34rxd0glWSDmYvVBUbKkY8nlpZ7zciU1
         m526Fxj1Gax3A9Lw+vHVXSrelAXkKj+KecV+1ChB02cVZPQht1/Etm3u+cf+UjuZuTZ1
         vDD4kQEaPI/U0snHx2lwkK2xlMQm3Kcay6H2oJK3HoySSuBnd+xYGgM6gxktpbJ7+4pr
         SDrJ9fdrEF6G8bP51TzqufGSgj2Ye+CC3p1sRPmkV0N+CffP7IaQz9MuQQgypQOWyTc5
         Zue4P7jIwZycrRs9phuSrGn/9VjhWwzR9zMo//tR9My73LxQD3oP2BlHzWG8m57ciZCJ
         HafQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZ+IUoNdnKabqJv7HZ5hdOUN5IVcnFFXpO1YzFI2hl4HLEukgpUlVibrrz/iDCg2Ls65yghw==@lfdr.de
X-Gm-Message-State: AOJu0Yy5BSzFHejP5q5c/caxwVq6nzq5kJQ4grb1il39VLS6plQ/CTJr
	lAfbkpdboFQmgiDjOKF5K4cZC/mLkzw67PbVOZHunDtnbD1Mgg7g
X-Google-Smtp-Source: AGHT+IENTuJs1TGP4vfOqurj5q8Ru5v+eA6iDqrcqUpV9nuNzhu9xZzJ81jwOER9tLtXNwTcuBCuGg==
X-Received: by 2002:a05:6820:221d:b0:5fa:6805:645b with SMTP id 006d021491bc7-5fd1962a146mr11745449eaf.6.1740503149893;
        Tue, 25 Feb 2025 09:05:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHL/IZbqWLTtA7/mnoIL1H+gqJKJiNmt8XekYTMx2L1hA==
Received: by 2002:a05:6820:151a:b0:5fc:e5bf:2c27 with SMTP id
 006d021491bc7-5fd0c8b48fels365508eaf.0.-pod-prod-01-us; Tue, 25 Feb 2025
 09:05:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWrmMMANx+WexdQfSZ9RH87b3K/hGjXeKWiWQr475Jeuzf7oM8bJJhn3qALtDlkgSvNMBni39a6dKY=@googlegroups.com
X-Received: by 2002:a05:6808:2128:b0:3f4:365:7402 with SMTP id 5614622812f47-3f4247cfb57mr12769056b6e.29.1740503148769;
        Tue, 25 Feb 2025 09:05:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740503148; cv=none;
        d=google.com; s=arc-20240605;
        b=XeG7dxOJ3Tzj2kmGGmM4TVDbwaDJbaXOW9yqcG0DBPTPqghpRcDJB5n9KqQ1GrdfBR
         jZHHi2+kf5fTY0HNe9RJ50ab1UTIfEM+Na58F9kmlFVKvQrV++gfLKOSx8KJ8NfURfGW
         PGbi3fjefO86K0QBmJYyLUfZRt9oTscclvTVKP3q1QrOSCCYUwkCqcxkjsbTuyGuI9lb
         EVrzOXm4q3b3tnNvfYQMcmd0W16sEDi3perkn6UPFzojW64vR8kt2qdxLKNxczHKYrHe
         GvLB7dtNkuXPMChForTlueMPXwy3YE3GXMFhvUzdQXN4J9kZ9E3bDK1Bmhg7ITavSfgA
         NiXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VYV21KgAAK9DCaC1N/igtqqjHAXsIGmsKhB8/dHzdzw=;
        fh=HlgY5pBYcbAnyXNR34pZnD/9IspOCSoEWrprbtqh+JY=;
        b=fLnbA14Fq9Cs8VrgI+rVcSNLs482xrrlW6qgcEMo8ICG6B8YY0U9/Rv92H6bgSy4ul
         +BNQiSfmv8/1itC6oGKJ6py2JzsRfR35A4wnzx5fpL+DJOMsvNJ9hpdd/C/JxfwHNISx
         UgO9SUfnHCSDQbxsXYarS2PL9KwAcW03gDQ3d6IRyrVzxa9DFS1YewPiAvYBP4kWgctv
         WQty5HWEiNvv4C4C07k2fL7U4HRcWUJvV+Qq6ZVh4SMrFMbql06YqoIVC198x5Wh5zoU
         kjDCaoWC3l7nrEtWpUd+O3XQgrSLdvRcREPwlLecI9bsOkPqyeHbWV5/puBad8lYUaZg
         u/cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpNiJ0xZ;
       spf=pass (google.com: domain of keith.busch@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=keith.busch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5fe93f908aasi86681eaf.0.2025.02.25.09.05.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 09:05:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keith.busch@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id e9e14a558f8ab-3d2b08175f1so1466385ab.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 09:05:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWsITOysLhx88ZYYYmU440xDtKYft9QySR1efRtqudkMUZaI8/15hkscwhFfa6ha9svUT1+o6eoK+E=@googlegroups.com
X-Gm-Gg: ASbGncsKENw1dJk4g808+1LUXieX4g81SITTMj0H4WnWDIVOpzcEViMbJ7CDVjhegcn
	Zs9iNgLS1MQU7jfAQaww+aDe+h50wdPnpnspkflf3fDnzUwWoO6lpRLsoJMiynCb/DKIhwnBk7J
	qeZKVGRw==
X-Received: by 2002:a05:6e02:1646:b0:3d0:4ae2:17b6 with SMTP id
 e9e14a558f8ab-3d2cad72c9fmr48331585ab.0.1740503148188; Tue, 25 Feb 2025
 09:05:48 -0800 (PST)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz> <Z73p2lRwKagaoUnP@kbusch-mbp>
In-Reply-To: <Z73p2lRwKagaoUnP@kbusch-mbp>
From: Keith Busch <keith.busch@gmail.com>
Date: Tue, 25 Feb 2025 10:05:37 -0700
X-Gm-Features: AQ5f1Jrz3qY3MDeCKERua2dr5bSa2550jia32PBjWFTFKImY0jy7IP8cCbQl7FM
Message-ID: <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from kmem_cache_destroy()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Josh Triplett <josh@joshtriplett.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	rcu@vger.kernel.org, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org, 
	leitao@debian.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keith.busch@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bpNiJ0xZ;       spf=pass
 (google.com: domain of keith.busch@gmail.com designates 2607:f8b0:4864:20::129
 as permitted sender) smtp.mailfrom=keith.busch@gmail.com;       dmarc=pass
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

On Tue, Feb 25, 2025 at 09:03:38AM -0700, Keith Busch wrote:
> On Tue, Feb 25, 2025 at 10:57:38AM +0100, Vlastimil Babka wrote:
> > I tried to create a kunit test for it, but it doesn't trigger anything. Maybe
> > it's too simple, or racy, and thus we are not flushing any of the queues from
> > kvfree_rcu_barrier()?
>
> Thanks, your test readily triggers it for me, but only if I load
> rcutorture at the same time.

Oops, I sent the wrong kernel messages. This is the relevant part:

[  142.371052] workqueue: WQ_MEM_RECLAIM
test_kfree_rcu_destroy_wq:cache_destroy_workfn [slub_kunit] is
flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
[  142.371072] WARNING: CPU: 11 PID: 186 at kernel/workqueue.c:3715
check_flush_dependency.part.0+0xad/0x100
[  142.375748] Modules linked in: slub_kunit(E) rcutorture(E)
torture(E) kunit(E) iTCO_wdt(E) iTCO_vendor_support(E)
intel_uncore_frequency_common(E) skx_edac_common(E) nfit(E)
libnvdimm(E) kvm_intel(E) kvm(E) evdev(E) bochs(E) serio_raw(E)
drm_kms_helper(E) i2c_i801(E) e1000e(E) i2c_smbus(E) intel_agp(E)
intel_gtt(E) lpc_ich(E) agpgart(E) mfd_core(E) drm_shm]
[  142.384553] CPU: 11 UID: 0 PID: 186 Comm: kworker/u64:11 Tainted: G
           E    N 6.13.0-04839-g5e7b40f0ddce-dirty #831
[  142.386755] Tainted: [E]=UNSIGNED_MODULE, [N]=TEST
[  142.387849] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
[  142.390236] Workqueue: test_kfree_rcu_destroy_wq
cache_destroy_workfn [slub_kunit]
[  142.391863] RIP: 0010:check_flush_dependency.part.0+0xad/0x100
[  142.393183] Code: 75 dc 48 8b 55 18 49 8d 8d 78 01 00 00 4d 89 f0
48 81 c6 78 01 00 00 48 c7 c7 00 e1 9a 82 c6 05 4f 39 c5 02 01 e8 53
bd fd ff <0f> 0b 5b 5d 41 5c 41 5d 41 5e c3 80 3d 39 39 c5 02 00 75 83
41 8b
[  142.396981] RSP: 0018:ffffc900007cfc90 EFLAGS: 00010092
[  142.398124] RAX: 000000000000008f RBX: ffff88803e9b10a0 RCX: 0000000000000027
[  142.399605] RDX: ffff88803eba0d08 RSI: 0000000000000001 RDI: ffff88803eba0d00
[  142.401092] RBP: ffff888007d9a480 R08: ffffffff83b8c808 R09: 0000000000000003
[  142.402548] R10: ffffffff8348c820 R11: ffffffff83a11d58 R12: ffff888007150000
[  142.404098] R13: ffff888005961400 R14: ffffffff813221a0 R15: ffff888005961400
[  142.405561] FS:  0000000000000000(0000) GS:ffff88803eb80000(0000)
knlGS:0000000000000000
[  142.407297] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  142.408658] CR2: 00007f826bd1a000 CR3: 00000000069db002 CR4: 0000000000772ef0
[  142.410259] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  142.411871] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  142.413341] PKRU: 55555554
[  142.414038] Call Trace:
[  142.414658]  <TASK>
[  142.415249]  ? __warn+0x8d/0x180
[  142.416035]  ? check_flush_dependency.part.0+0xad/0x100
[  142.417182]  ? report_bug+0x160/0x170
[  142.418041]  ? handle_bug+0x4f/0x90
[  142.418861]  ? exc_invalid_op+0x14/0x70
[  142.419853]  ? asm_exc_invalid_op+0x16/0x20
[  142.420877]  ? kfree_rcu_shrink_scan+0x120/0x120
[  142.422029]  ? check_flush_dependency.part.0+0xad/0x100
[  142.423244]  __flush_work+0x38a/0x4a0
[  142.424157]  ? find_held_lock+0x2b/0x80
[  142.425070]  ? flush_rcu_work+0x26/0x40
[  142.425953]  ? lock_release+0xb3/0x250
[  142.426785]  ? __mutex_unlock_slowpath+0x2c/0x270
[  142.427906]  flush_rcu_work+0x30/0x40
[  142.428756]  kvfree_rcu_barrier+0xe9/0x130
[  142.429649]  kmem_cache_destroy+0x2b/0x1f0
[  142.430578]  cache_destroy_workfn+0x20/0x40 [slub_kunit]
[  142.431729]  process_one_work+0x1cd/0x560
[  142.432620]  worker_thread+0x183/0x310
[  142.433487]  ? rescuer_thread+0x330/0x330
[  142.434428]  kthread+0xd8/0x1d0
[  142.435248]  ? ret_from_fork+0x17/0x50
[  142.436165]  ? lock_release+0xb3/0x250
[  142.437106]  ? kthreads_online_cpu+0xf0/0xf0
[  142.438133]  ret_from_fork+0x2d/0x50
[  142.439045]  ? kthreads_online_cpu+0xf0/0xf0
[  142.440428]  ret_from_fork_asm+0x11/0x20
[  142.441476]  </TASK>
[  142.442152] irq event stamp: 22858
[  142.443002] hardirqs last  enabled at (22857): [<ffffffff82044ef4>]
_raw_spin_unlock_irq+0x24/0x30
[  142.445032] hardirqs last disabled at (22858): [<ffffffff82044ce3>]
_raw_spin_lock_irq+0x43/0x50
[  142.451450] softirqs last  enabled at (22714): [<ffffffff810bfdbc>]
__irq_exit_rcu+0xac/0xd0
[  142.453345] softirqs last disabled at (22709): [<ffffffff810bfdbc>]
__irq_exit_rcu+0xac/0xd0
[  142.455305] ---[ end trace 0000000000000000 ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw%40mail.gmail.com.
