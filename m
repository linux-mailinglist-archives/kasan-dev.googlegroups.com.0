Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBKM4S23QMGQEOABEJEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 482959790E0
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 15:22:51 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5c25cf44030sf1922819a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Sep 2024 06:22:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726320171; cv=pass;
        d=google.com; s=arc-20240605;
        b=AIPaqwmV6dthRgYGSJOmjbIMp5BrcMP/fKexo3sGG4tgOAuVKtsMb8Sn64PmAgcL9C
         Dct1/yLUk6UzBM19wLxJ5YVKynSkYzhuogKvlyX3rr2ISBlY6W9jFK0XSD2nMc0ieJXh
         uLx2u+zNEJUGFHnowq9qDeY1QP7XlGpFl0HS6ZemUciqY+4K0SF2BQDKsJoGSLeF0sjJ
         /I0YhgO7IuKUb8E3IYqyVd+y67OYuXtTl00JtJoRmr8pEl5hDeFkLwwTuZALlpUbu52/
         eAInvnF20JyTfM79dNd9FncdbVsLUi+/oTZ0vJjhr+sM4Fj/0YmcOiWxpKLb6RSqbwxR
         gFmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=w7AE7iJRVDrMttr8LVn2KUJofHV2pU3EKSFsG4XyUk8=;
        fh=Aa8w4L6CiN0CJ3i0A6liA6fT8rvAl9LmObI78E6X/Fs=;
        b=i8w92Lkgr42Q1XjJk0ts7fYXTrrQYH3+6cwseSrZOE3i9+JB+em+1B1n8XGElb01Bo
         AJzTAegICCs5aTkcBs5y2j8IU4y1j12vFSjt30iMYEEzsn+G1mMgUo1uDUUx6cdobGrk
         WKw6lK7RE3Kfo0fEBOeREAYqFMButQRdYrFx89CJ/hNyx+vrf0/9TAXwWc82smjpNnEP
         FQ+r5OAnUHk4PGcYNcJFl0uMtWlvCydXl4s7mdiqfUlgMalJTqWF2WaNuv71/uhzzpP6
         h+6Wq+mMo53RimCZcWzRyiWDBzDbhxz8eDecUxg8EtsmJ3VkYmMQ+sl+Wu50RI6JLo9u
         6eOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="nT2cww/r";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726320171; x=1726924971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=w7AE7iJRVDrMttr8LVn2KUJofHV2pU3EKSFsG4XyUk8=;
        b=tPuzYa15QAw2oIJCdIajqXly2+5oVxnZ/rnOxqmd+zgWnTYtiKvJcJ6P77kI90z6ps
         o72m8aqvAAvmXPoD47huly/SndkiKEieHh+xwGwDx998zz2fVjpbb/HkaF4z4CGXSnMf
         yXqN0svbSiSaVtDR32zqhBkLWsA5m9ENaxfX0ng93FReIwdlgfeixDoGgUv70jmdJ7gM
         ToWIyDs9nRUPLI/JtJJZLaqxuKUrySkmqz5IZTOln3U7dbwqoSvHMUNq3a/fhpUDe6Xi
         FlbzT+OCENIMYcm988YK0n2I3wNhXXwm1rDtYbNteHHDw4esPzm1cIihOiIrl5xv7YRm
         BpQQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726320171; x=1726924971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=w7AE7iJRVDrMttr8LVn2KUJofHV2pU3EKSFsG4XyUk8=;
        b=T2/it2gk3eh3hR0v62OxwkqczS5Ymz46BcTLbEM3WLL+2neSB+75nTaNM/FpjONPcr
         D+TH+dJi6RId/lj3i2B4apl/MnfCeMrUczCnEe5FLD4JXQOV041cA0YYSBF0FjZIWeBw
         //1iUdzfZFzuxBGTTyF8rbpVvvWOJT+iEFripafwBHGQ/5d+T2HgS+54AtjkiBuyURGr
         +Hpmzmt5pUkkwfHUOhmdMuBd1diCRDxwHFCUL2uE00G7bETpVKeMhiF2DV3xrS+mQqV6
         WVZ5sXZGis3C9nw5hkHSaFjsfMKCKdOFPNzAabPFogDFhXpJ6wAjOz+/Bh8RopTmfQYF
         z4ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726320171; x=1726924971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w7AE7iJRVDrMttr8LVn2KUJofHV2pU3EKSFsG4XyUk8=;
        b=DgrXQ6PVc5yoyCEQcXWH5Sd0w+xevEXDHhF9qSUb7Wm1d2cRSjNr6j9DCWIcPDt0Ic
         yKbnqyaZHMOXIuTC4ejwwITna/b9E1n5tLQu2V1I2LnZdMkGLJ8kSgocLcpjq0Kgp8u6
         eDtaGdsdLD0K7Uq8UqcSY6kmlAH0JE86VbvQrdxEJfWAi33Dp0Uf9FJyqtiZp0gY7ygE
         fBSn9CEIm6+o7vwJ0HFR4dfE0+kdx98RM4TPN10Ue36yPVk2oHVpvl6Wjjmw/LLZT7sO
         SljlLRYpJ3JwRTFwc+Wm/yZi+nhvTPNKxZbm+osOP4G5nquH1ii46LevMlbkpwF6CxRD
         q6XQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW7ygZWPRiqOv8bVAG+0X2xdBWsBOEOClrCGtYfjUHihStL2hTHE2ejxTz6WAPIf0TNPmM7ZA==@lfdr.de
X-Gm-Message-State: AOJu0YyXk26O1WeUihNXmYtpgUWQ0pr14V3NrMmpUTZeO0aR/D28jDSV
	FHTf6jkD5tK49HE9BZPCfY/lCw53rXgBWRszO8jaExm7m6Ucpo/v
X-Google-Smtp-Source: AGHT+IGfhz42D6A20hUIpOUOJR2zgh9YKYPk/9jMXeB/QDUHAFKdvCm6rA83L1KRwIn91kWV7Fr3pw==
X-Received: by 2002:a05:6402:40c4:b0:5c4:23ba:95c4 with SMTP id 4fb4d7f45d1cf-5c423ba9733mr4239493a12.9.1726320169718;
        Sat, 14 Sep 2024 06:22:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:e614:0:b0:5c4:20f0:95bb with SMTP id 4fb4d7f45d1cf-5c420f0977als96155a12.0.-pod-prod-09-eu;
 Sat, 14 Sep 2024 06:22:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmk2lu/9sS5JMgHL+7BQbkbm3/gKz2TxGyRWO4Zy2kIFSeJp/NesebktKd2EnK8FN1bKXqiZUmz+o=@googlegroups.com
X-Received: by 2002:a05:6402:274f:b0:5bf:2577:4346 with SMTP id 4fb4d7f45d1cf-5c413e1b2a3mr9132974a12.15.1726320167475;
        Sat, 14 Sep 2024 06:22:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726320167; cv=none;
        d=google.com; s=arc-20240605;
        b=kpFP8Svuy5Twh5EpQZ1gyfQg0QsrhzACRrZPI1x5PjPt2V5Nky0nV6+fnOeRsGBrhH
         UaYsTdJTnfhBHKUmXOHpD1VsVslB5NJrEBRVo0U23W6vZv7ObyrpQLLI9qzoIMpdyfa2
         2yjOncl2JEtWC26JHn/4d0/2J3iDGORwyJmj176MDB4qogrgP8n6D7rYomMG0kVa4Vn7
         rkhtkOt5QjwAKcMvyJxRrnq/0BEHqhjWrjnw9GinWhGHtbl227OAfdkpQGFF/oMm2Whr
         Ql7/Mcve1mAtWz2e2xQSJbWUy/fRZy57OmSzJcawPwtrQ5aGqAE16xj3FNfJmz1JQFyo
         prgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3+sUBUYlwVuWfbjGxbMazluFnfi9XsaxNKbywpciuJQ=;
        fh=1JxwU5b421WerFGhqK+n14uhKegkTjcv680vAsv3aBQ=;
        b=ckRtA21BVamKTW53SClZUEhGB/6VOxK4AO5WPF1J1wxkuwg3a6ndfzMXQ2FVF3bJE0
         E2SbR0w81WhnsZdI8oy5g5eZy22iNtGvx7HE/JeDATqkV0mZQ5sn1TwVkF8spygf/Ty4
         IHDU80yL1qbKxUSgRbktzARlkBTGncg6Cl0dY0/tgxjQraU6i4z1ozcnu3yX3a+/AZDI
         FlqgHSRtzPlHWO4v8WJRoZP9RH7/jdWbots1rHytCdZCpVnw8IjEh7xtMF0q79K/9kB8
         sG+GBy0RloTug3uX97l3sSJG5zws2V/QkPXgEzKcaBAEuHPUGm6OORKA8hJmeCDlA8CR
         p0+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="nT2cww/r";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c42bb46ea2si20896a12.1.2024.09.14.06.22.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 14 Sep 2024 06:22:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-5365cf5de24so3852792e87.1
        for <kasan-dev@googlegroups.com>; Sat, 14 Sep 2024 06:22:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbJ1kk4209f4oQV3wCUW7gqkDN1lrFvxE7StWF/liJ76Rm6BuTnjzojjCp4TizDL6e0CUe71rDGUQ=@googlegroups.com
X-Received: by 2002:a05:6512:3d17:b0:536:5364:bc7 with SMTP id
 2adb3069b0e04-53678fec5f7mr5021336e87.60.1726320166228; Sat, 14 Sep 2024
 06:22:46 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Sat, 14 Sep 2024 22:22:33 +0900
Message-ID: <CAB=+i9RHHbfSkmUuLshXGY_ifEZg9vCZi3fqr99+kmmnpDus7Q@mail.gmail.com>
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and test_leak_destroy()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	rcu@vger.kernel.org, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="nT2cww/r";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Wed, Aug 7, 2024 at 7:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wro=
te:
>
> Add a test that will create cache, allocate one object, kfree_rcu() it
> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
> in kmem_cache_destroy() works correctly, there should be no warnings in
> dmesg and the test should pass.
>
> Additionally add a test_leak_destroy() test that leaks an object on
> purpose and verifies that kmem_cache_destroy() catches it.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  lib/slub_kunit.c | 31 +++++++++++++++++++++++++++++++
>  1 file changed, 31 insertions(+)
>

Hi Vlastimil,

I think we might need to suppress the WARN() due to the active objects
in kmem_cache_destroy()
when it's called from slub_kunit. With this change, the warning below
will be printed every time
slub_kunit is loaded, which made me wonder if there's a bug (for a while).

Actually, SLUB calls pr_err() is called by __kmem_cache_shutdown() if
there are any active objects
during destruction, and the error message is suppressed by slub_kunit.
However, kmem_cache_destroy()
still calls WARN() regardless if there is any error during shutdown.

[  147.546531] Object 0x00000000c09342ca @offset=3D640
[  147.546542] ------------[ cut here ]------------
[  147.546544] kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still
has objects when called from test_leak_destroy+0x74/0x108 [slub_kunit]
[  147.546579] WARNING: CPU: 5 PID: 39703 at mm/slab_common.c:507
kmem_cache_destroy+0x174/0x188
[  147.546587] Modules linked in: slub_kunit uinput snd_seq_dummy
snd_hrtimer rfkill nf_conntrack_netbios_ns nf_conntrack_broadcast
nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet
nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct sunrpc nft_chain_nat
nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables
nfnetlink qrtr binfmt_misc vfat fat snd_hda_codec_generic
snd_hda_intel snd_intel_dspcfg snd_hda_codec uvcvideo snd_hda_core uvc
snd_hwdep videobuf2_vmalloc snd_seq videobuf2_memops snd_seq_device
videobuf2_v4l2 snd_pcm videobuf2_common snd_timer snd videodev mc
soundcore virtio_balloon acpi_tad joydev loop zram virtio_gpu
ahci_platform libahci_platform virtio_dma_buf crct10dif_ce polyval_ce
polyval_generic ghash_ce sha3_ce virtio_net sha512_ce net_failover
sha512_arm64 failover virtio_mmio ip6_tables ip_tables fuse
[  147.546646] CPU: 5 UID: 0 PID: 39703 Comm: kunit_try_catch Tainted:
G                 N 6.11.0-rc7-next-20240912 #2
[  147.546649] Tainted: [N]=3DTEST
[  147.546650] Hardware name: Parallels International GmbH. Parallels
ARM Virtual Machine/Parallels ARM Virtual Platform, BIOS 20.0.0
(55653) Thu, 05 Sep 202
[  147.546652] pstate: 61400005 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=
=3D--)
[  147.546655] pc : kmem_cache_destroy+0x174/0x188
[  147.546657] lr : kmem_cache_destroy+0x174/0x188
[  147.546659] sp : ffff80008aba3d60
[  147.546660] x29: ffff80008aba3d60 x28: 0000000000000000 x27: 00000000000=
00000
[  147.546662] x26: 0000000000000000 x25: 0000000000000000 x24: ffff800094a=
2b438
[  147.546665] x23: ffff80008089b750 x22: 0000000000000001 x21: f9cc80007c1=
782f4
[  147.546666] x20: ffff800082f9d088 x19: ffff0000c2308b00 x18: 00000000fff=
ffffd
[  147.546668] x17: 0000000046d4ed9c x16: 00000000ae1ad4db x15: ffff80008ab=
a3430
[  147.546670] x14: 0000000000000001 x13: ffff80008aba3657 x12: ffff800082f=
0f060
[  147.546679] x11: 0000000000000001 x10: 0000000000000001 x9 : ffff8000801=
652c8
[  147.546682] x8 : c0000000ffffdfff x7 : ffff800082e5ee68 x6 : 00000000000=
affa8
[  147.546684] x5 : ffff00031fc70448 x4 : 0000000000000000 x3 : ffff80029d6=
b7000
[  147.546686] x2 : 0000000000000000 x1 : 0000000000000000 x0 : ffff00011f1=
c8000
[  147.546688] Call trace:
[  147.546689]  kmem_cache_destroy+0x174/0x188
[  147.546692]  test_leak_destroy+0x74/0x108 [slub_kunit]
[  147.546693]  kunit_try_run_case+0x74/0x170
[  147.546697]  kunit_generic_run_threadfn_adapter+0x30/0x60
[  147.546699]  kthread+0xf4/0x108
[  147.546705]  ret_from_fork+0x10/0x20
[  147.546710] ---[ end trace 0000000000000000 ]---

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9RHHbfSkmUuLshXGY_ifEZg9vCZi3fqr99%2BkmmnpDus7Q%40mail.=
gmail.com.
