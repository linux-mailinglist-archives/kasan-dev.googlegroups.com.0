Return-Path: <kasan-dev+bncBDK7LR5URMGRBRUB7C6QMGQECIED34A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EDCDA44890
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 18:41:29 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-309219e7913sf23579871fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 09:41:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740505288; cv=pass;
        d=google.com; s=arc-20240605;
        b=ebOooyKRg0H6DJXQwf54ofnheaSp5YATKKyI3osiWafOFIIORTvmuBEAeVCxQ+XIBH
         MAuApISfYv4hPO0eGi3FR0YF0W00uZDh4bu+XwfCtQhddWRiCeGggGW3ZZnQsoHBeG8e
         4dzgp1QUR8eia1tn1r9UlBoaM09smpPmNSy2I9kBT4Y03Y2m2IZjBVRm/7bt+jM+kQkA
         nDajenb0jsMIp37ZEOyaUWOqgxNYUKiliGRKk8r1QFegCMwrMQtL32hXI/cBRD/Pspel
         bjkfS3AhHENbIlXfzVl6GIwL+Ro+yJxJOCWo3GKnbFVvrbfPlYzTadnBekj+tpzHeTg6
         e6ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:sender:dkim-signature:dkim-signature;
        bh=HdEKrCg3SO57IBPoNOYj42R6sZef0dgUEwRG/OCtFxM=;
        fh=sswb8SdJFK4Vfdu8I28x8spNShxhI8ATURo2A4IiSkg=;
        b=AhjT7EM5BmtZZD2e9MSfzEB8BY26N1vHDb8uZbLuWospP5VW99iY+ffLBU9Jdev5Dp
         nqNju0ZUqtzytBeYS0tMik9ifNTmCEbpDkn3h8TPemCZAZ0JUj5lKa4y8MiVIbGt/ps+
         SmL8mJH3dkKkv57flbtWZmwSqJV6mjnasOWuWPcBnt1lo9pfjV1T0g4okE0X7W6Duf2E
         j5JJKg3DnM9cAkR0MpZXBytfwAoEdmmnKgyZ7vxXNeCpcLI9Ht0G97OxNvpwYnwysXwh
         7RZ7JSflXWiFtGZTfG22jPM3IpUGW6q9TyRSX9aB/06s95wyQ6RAapZFnHYsIZMLmjVO
         TKIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kGxevjJq;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740505288; x=1741110088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HdEKrCg3SO57IBPoNOYj42R6sZef0dgUEwRG/OCtFxM=;
        b=VtJk5IZ4aiI4luOwXM98IiUcjIsvI4puhIEj1/iMYklzGLZqF/taVgiV6SqRBH+miy
         VgSZwFivLYMoQuChV86yiHfpCxk+xNlWWXI3LqhS+rWZY8OW5XPBau/V2gpTOAZRuzVf
         fpqgao0fasqfFIkC5yxy0QOq1mEPfN27Z/csyqimh5pgoQRTp0eQF4QoLbHpiRRETPjA
         n3jqQSqtiBWnqwT+nmHO8QGXjJGivf4mCxkrj0uRJ9I1WRgIJKc7T6+RsBU500ASYZHb
         kQX8E+/+AqjPU513iFP0P8aaewQ6fSTKzx1O3wFxSI8QPfVdjxX4N302ucCdb4Bnbcsm
         Cu6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740505288; x=1741110088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HdEKrCg3SO57IBPoNOYj42R6sZef0dgUEwRG/OCtFxM=;
        b=WCuGbALUAaVRXK8eaWTYVmPelyFfshUpKsTX9UJlZ6WCqZu6aUy1XP/6BT9W8JN6Yp
         g0xX1l5P0gvZmnYLv5quiMriTWrIW+0H/m5Ly4RZ9semC3ua4zkUnYYsUpWw8zX3FOwW
         DQvuJ6rzzyGzYhoUFZs8ZZDeKaE8uUcyc3bTe6WyfbPZJ2jRaGPMC8BiKWQzN/UeeBK7
         DKUdK425t8EhAp9dmwg8YCVNDBkn4x72/TVG/rr7Nb2ustI/xlm+aEndF21AU63eay6Z
         cz47NiLBNKeeDPbOMERmtNAqS3RqfqMfA+Gp+XAJKpDi5V86rYaB3K3qaJubPWPioxbi
         w+/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740505288; x=1741110088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HdEKrCg3SO57IBPoNOYj42R6sZef0dgUEwRG/OCtFxM=;
        b=h7nFQN4YNjCxdPRFdPYc2U+IbnpLZ5S6V/y1YOkSFUqYxdqkw9u3XgiIvz4lyXullD
         cnXIyiruVtEykXVFv4VUM1nAW7qXez9paLMtIOOFhLGIAZo9YuMCDivVTMfNsmZAIuHW
         zyPh26GHGIe9F/iSdmn5GcOK/WW7us2AUiOz1tqKzmW66+nBbmehpvM7F3u1NeAS0TNP
         ShffzbBEN4rRj74WXnDEtOdq3PHHaYzFjPklH4LZWT4cdAVoC62tfMJi2r+Mhb8PZj3Y
         qCnm8Nb8FvAQfk4fy4BvyInaFCCmVJj0oEnh6VT/ifjN+IGqHjcRGW1ExUuLEsQa19jd
         Oqnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV65wUaVsPWkKcpXWf2kxvtVMiyoaRj179E4cM0sByTMKFbBySSFNg6+hoPCVBnOW4NYDzRZA==@lfdr.de
X-Gm-Message-State: AOJu0YzZTHQ/JQZQwUDdBuJ9B+Lm21Jt+QAmuCfS8hgfgpsRsEMsXiva
	qvBZQTBOIr6Uy0LNN0cA5e6c6h3osUWGv7ianyRPTEivmeNBe4m1
X-Google-Smtp-Source: AGHT+IErkGIMMAfOSLLVWFPhuYVTVJmxpBsUxpa1wlJmu0cusW7VgyjbX0LVRkS4KMRj8roSGmyuAw==
X-Received: by 2002:a2e:300e:0:b0:302:5391:3faf with SMTP id 38308e7fff4ca-30a598f454amr68268101fa.17.1740505286875;
        Tue, 25 Feb 2025 09:41:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF6gs7uIOuuWez6Zox6iA+b8Q3b254ez/jgsZbIaZy+5Q==
Received: by 2002:a05:651c:2117:b0:309:298b:9dc7 with SMTP id
 38308e7fff4ca-30a521fc04als1706901fa.2.-pod-prod-01-eu; Tue, 25 Feb 2025
 09:41:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXpSFCuaOy3jTFDx7idMEwJvbJ9+kp/hwdGD0hde3iX6GkW8koxcgBfAWGmPZzpliag+UTsiIJMd8c=@googlegroups.com
X-Received: by 2002:a2e:83d0:0:b0:309:2627:8adc with SMTP id 38308e7fff4ca-30a5985d8ebmr55390551fa.8.1740505284567;
        Tue, 25 Feb 2025 09:41:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740505284; cv=none;
        d=google.com; s=arc-20240605;
        b=K3bUcs3cpJzhcXLKl+FLpjRdeJltnFGt7f4w/ZdOsk9fMgFqD7q4xlkfO+nXXI+cSV
         g8R1Ili58/kXrBpKsFJwMpy6D7ncwOtvqw/sR/btNosNg/aJpuQqhzHsXqYQk+0bB/Rm
         1eCd38EHeKIpcHReNY10lAHATXfwL02wWFXl4k+Woz7wUZVtXcPHxIqndxXKezA/8Bkz
         m1rLBGLvYlhLexBxi26bDLNWQ+4wtlOqMBZvIALIZShvi7oe9vxBzJUyxRTGTZ+5YeQR
         3pvEjELw892Vised8wReDGTo+AtiR7RmqGDDqMLTeaOOwbS6dyLru4ykdENu4o0YYGn2
         KOlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=o5I0Gh7oHoYbf3JrUTgHAlRAt4Em/lhq6oj6z2kkeWE=;
        fh=7yJKRyMnxegy39rMAVfs/omJhPN4Ll5hAeQC9JXVNS8=;
        b=RXKDDDea7htSC8YsCQSRRlXs0Cf+2ahNvGYlS79NXTwiUS3tsezonTbPvl5CB/rUYm
         OA1gO0vBuWFSkeecK+OO7i4YgisEEInB7O+6a9YAx7hB3omwQBQCn3fWRyqr4oLsXyjn
         J0I9OryQdm/OV3OWdTVQKb7AvlxNdCHNtZ7JyhCG+h744JVeNBJ4l22cq+ptKJvcAN55
         e1KU0PvNJBxcfCXgtsaGLkv0Pt0XpEggg49eAuLQq/HUReHM1I30s4fktvyVfJTUnxpO
         NuyeKpq1K2mLZc8qPcnU1w3p3keirMHsSv0CI4lk7f+qz/tTxJxEPc39OM2SbENnrkJc
         a3DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kGxevjJq;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30a81a2dd0asi1661131fa.3.2025.02.25.09.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 09:41:24 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-30a36eecb9dso60766971fa.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 09:41:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXxO9R1pcHcHs+WQ3N5JKGJ88jRFsKND771orNrVekKilYD0YL1xLD6q3zwct7n0EvdoFyhbQPmQnU=@googlegroups.com
X-Gm-Gg: ASbGncuFqZW3z7PclctHtEQ6CDoUiB+3UBcqfwJBgpQ8Vrtab7br1hdF+s4EUw33sVT
	cWO9xkzlI6bH7TuxM69k3Jk6oy+CRwFlpBpwA8XXNO3xzGeJQVJbGLn0gmqroAwGuq4/WPQnaBO
	Xx26ZBgLp3fSpQFSJkPCtCmhaE2ZBdHqfgD9Uvc9AqW2MYAdidKksnJjrzn/J3aOILzQIPecdQK
	BjVlXMMnbngmG02QNAyNCJom38IoPX3XZ69ohbgt7vFzS9agFMcm/Zp37w5CLdEBGqJOcVSqM/a
	9VrFwLcK4sNxmuQsmeTIlF0jLv7EyM9sBOvo6jj0cPZ8qpMY
X-Received: by 2002:a2e:8642:0:b0:307:e302:a34 with SMTP id 38308e7fff4ca-30a598f6edemr66652541fa.20.1740505283628;
        Tue, 25 Feb 2025 09:41:23 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30a819f5e4asm2812131fa.63.2025.02.25.09.41.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 09:41:22 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 25 Feb 2025 18:41:19 +0100
To: Keith Busch <keith.busch@gmail.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Vlastimil Babka <vbabka@suse.cz>, Uladzislau Rezki <urezki@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z74Av6tlSOqcfb-q@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kGxevjJq;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::231 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Transfer-Encoding: quoted-printable
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

On Tue, Feb 25, 2025 at 10:05:37AM -0700, Keith Busch wrote:
> On Tue, Feb 25, 2025 at 09:03:38AM -0700, Keith Busch wrote:
> > On Tue, Feb 25, 2025 at 10:57:38AM +0100, Vlastimil Babka wrote:
> > > I tried to create a kunit test for it, but it doesn't trigger anythin=
g. Maybe
> > > it's too simple, or racy, and thus we are not flushing any of the que=
ues from
> > > kvfree_rcu_barrier()?
> >
> > Thanks, your test readily triggers it for me, but only if I load
> > rcutorture at the same time.
>=20
> Oops, I sent the wrong kernel messages. This is the relevant part:
>=20
> [  142.371052] workqueue: WQ_MEM_RECLAIM
> test_kfree_rcu_destroy_wq:cache_destroy_workfn [slub_kunit] is
> flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
> [  142.371072] WARNING: CPU: 11 PID: 186 at kernel/workqueue.c:3715
> check_flush_dependency.part.0+0xad/0x100
> [  142.375748] Modules linked in: slub_kunit(E) rcutorture(E)
> torture(E) kunit(E) iTCO_wdt(E) iTCO_vendor_support(E)
> intel_uncore_frequency_common(E) skx_edac_common(E) nfit(E)
> libnvdimm(E) kvm_intel(E) kvm(E) evdev(E) bochs(E) serio_raw(E)
> drm_kms_helper(E) i2c_i801(E) e1000e(E) i2c_smbus(E) intel_agp(E)
> intel_gtt(E) lpc_ich(E) agpgart(E) mfd_core(E) drm_shm]
> [  142.384553] CPU: 11 UID: 0 PID: 186 Comm: kworker/u64:11 Tainted: G
>            E    N 6.13.0-04839-g5e7b40f0ddce-dirty #831
> [  142.386755] Tainted: [E]=3DUNSIGNED_MODULE, [N]=3DTEST
> [  142.387849] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
> [  142.390236] Workqueue: test_kfree_rcu_destroy_wq
> cache_destroy_workfn [slub_kunit]
> [  142.391863] RIP: 0010:check_flush_dependency.part.0+0xad/0x100
> [  142.393183] Code: 75 dc 48 8b 55 18 49 8d 8d 78 01 00 00 4d 89 f0
> 48 81 c6 78 01 00 00 48 c7 c7 00 e1 9a 82 c6 05 4f 39 c5 02 01 e8 53
> bd fd ff <0f> 0b 5b 5d 41 5c 41 5d 41 5e c3 80 3d 39 39 c5 02 00 75 83
> 41 8b
> [  142.396981] RSP: 0018:ffffc900007cfc90 EFLAGS: 00010092
> [  142.398124] RAX: 000000000000008f RBX: ffff88803e9b10a0 RCX: 000000000=
0000027
> [  142.399605] RDX: ffff88803eba0d08 RSI: 0000000000000001 RDI: ffff88803=
eba0d00
> [  142.401092] RBP: ffff888007d9a480 R08: ffffffff83b8c808 R09: 000000000=
0000003
> [  142.402548] R10: ffffffff8348c820 R11: ffffffff83a11d58 R12: ffff88800=
7150000
> [  142.404098] R13: ffff888005961400 R14: ffffffff813221a0 R15: ffff88800=
5961400
> [  142.405561] FS:  0000000000000000(0000) GS:ffff88803eb80000(0000)
> knlGS:0000000000000000
> [  142.407297] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [  142.408658] CR2: 00007f826bd1a000 CR3: 00000000069db002 CR4: 000000000=
0772ef0
> [  142.410259] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 000000000=
0000000
> [  142.411871] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 000000000=
0000400
> [  142.413341] PKRU: 55555554
> [  142.414038] Call Trace:
> [  142.414658]  <TASK>
> [  142.415249]  ? __warn+0x8d/0x180
> [  142.416035]  ? check_flush_dependency.part.0+0xad/0x100
> [  142.417182]  ? report_bug+0x160/0x170
> [  142.418041]  ? handle_bug+0x4f/0x90
> [  142.418861]  ? exc_invalid_op+0x14/0x70
> [  142.419853]  ? asm_exc_invalid_op+0x16/0x20
> [  142.420877]  ? kfree_rcu_shrink_scan+0x120/0x120
> [  142.422029]  ? check_flush_dependency.part.0+0xad/0x100
> [  142.423244]  __flush_work+0x38a/0x4a0
> [  142.424157]  ? find_held_lock+0x2b/0x80
> [  142.425070]  ? flush_rcu_work+0x26/0x40
> [  142.425953]  ? lock_release+0xb3/0x250
> [  142.426785]  ? __mutex_unlock_slowpath+0x2c/0x270
> [  142.427906]  flush_rcu_work+0x30/0x40
> [  142.428756]  kvfree_rcu_barrier+0xe9/0x130
> [  142.429649]  kmem_cache_destroy+0x2b/0x1f0
> [  142.430578]  cache_destroy_workfn+0x20/0x40 [slub_kunit]
> [  142.431729]  process_one_work+0x1cd/0x560
> [  142.432620]  worker_thread+0x183/0x310
> [  142.433487]  ? rescuer_thread+0x330/0x330
> [  142.434428]  kthread+0xd8/0x1d0
> [  142.435248]  ? ret_from_fork+0x17/0x50
> [  142.436165]  ? lock_release+0xb3/0x250
> [  142.437106]  ? kthreads_online_cpu+0xf0/0xf0
> [  142.438133]  ret_from_fork+0x2d/0x50
> [  142.439045]  ? kthreads_online_cpu+0xf0/0xf0
> [  142.440428]  ret_from_fork_asm+0x11/0x20
> [  142.441476]  </TASK>
> [  142.442152] irq event stamp: 22858
> [  142.443002] hardirqs last  enabled at (22857): [<ffffffff82044ef4>]
> _raw_spin_unlock_irq+0x24/0x30
> [  142.445032] hardirqs last disabled at (22858): [<ffffffff82044ce3>]
> _raw_spin_lock_irq+0x43/0x50
> [  142.451450] softirqs last  enabled at (22714): [<ffffffff810bfdbc>]
> __irq_exit_rcu+0xac/0xd0
> [  142.453345] softirqs last disabled at (22709): [<ffffffff810bfdbc>]
> __irq_exit_rcu+0xac/0xd0
> [  142.455305] ---[ end trace 0000000000000000 ]---
Thanks!

I can trigger this also:

<snip>
[   21.712856] KTAP version 1
[   21.712862] 1..1
[   21.714486]     KTAP version 1
[   21.714490]     # Subtest: slub_test
[   21.714492]     # module: slub_kunit
[   21.714495]     1..10
[   21.750359]     ok 1 test_clobber_zone
[   21.750955]     ok 2 test_next_pointer
[   21.751532]     ok 3 test_first_word
[   21.751991]     ok 4 test_clobber_50th_byte
[   21.752493]     ok 5 test_clobber_redzone_free
[   21.753004] stackdepot: allocating hash table of 1048576 entries via kvc=
alloc
[   21.756176]     ok 6 test_kmalloc_redzone_access
[   21.806549]     ok 7 test_kfree_rcu
[   22.058010] ------------[ cut here ]------------
[   22.058015] workqueue: WQ_MEM_RECLAIM test_kfree_rcu_destroy_wq:cache_de=
stroy_workfn [slub_kunit] is flushing !WQ_MEM_RECLAIM events_unbound:kfree_=
rcu_work
[   22.058039] WARNING: CPU: 19 PID: 474 at kernel/workqueue.c:3715 check_f=
lush_dependency.part.0+0xbe/0x130
[   22.058047] Modules linked in: slub_kunit(E) kunit(E) binfmt_misc(E) boc=
hs(E) drm_client_lib(E) drm_shmem_helper(E) ppdev(E) drm_kms_helper(E) snd_=
pcm(E) sg(E) snd_timer(E) evdev(E) snd(E) joydev(E) parport_pc(E) parport(E=
) soundcore(E) serio_raw(E) button(E) pcspkr(E) drm(E) fuse(E) dm_mod(E) ef=
i_pstore(E) configfs(E) loop(E) qemu_fw_cfg(E) ip_tables(E) x_tables(E) aut=
ofs4(E) ext4(E) crc16(E) mbcache(E) jbd2(E) sr_mod(E) sd_mod(E) cdrom(E) at=
a_generic(E) ata_piix(E) libata(E) scsi_mod(E) i2c_piix4(E) psmouse(E) e100=
0(E) i2c_smbus(E) scsi_common(E) floppy(E)
[   22.058091] CPU: 19 UID: 0 PID: 474 Comm: kworker/u257:0 Kdump: loaded T=
ainted: G            E    N 6.14.0-rc1+ #286
[   22.058096] Tainted: [E]=3DUNSIGNED_MODULE, [N]=3DTEST
[   22.058097] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
1.16.2-debian-1.16.2-1 04/01/2014
[   22.058099] Workqueue: test_kfree_rcu_destroy_wq cache_destroy_workfn [s=
lub_kunit]
[   22.058103] RIP: 0010:check_flush_dependency.part.0+0xbe/0x130
[   22.058106] Code: 75 d0 48 8b 55 18 49 8d 8d c0 00 00 00 4d 89 f0 48 81 =
c6 c0 00 00 00 48 c7 c7 b0 7d c8 bd c6 05 6c 78 53 01 01 e8 a2 ae fd ff <0f=
> 0b 5b 5d 41 5c 41 5d 41 5e c3 cc cc cc cc f6 c4 08 74 94 31 ed
[   22.058108] RSP: 0018:ffff95e5c123fd50 EFLAGS: 00010086
[   22.058111] RAX: 0000000000000000 RBX: ffff89a4ff22d5a0 RCX: 00000000000=
00000
[   22.058113] RDX: 0000000000000003 RSI: ffffffffbdce1697 RDI: 00000000fff=
fffff
[   22.058114] RBP: ffff89961043a780 R08: 0000000000000000 R09: 00000000000=
00003
[   22.058116] R10: ffff95e5c123fbe8 R11: ffff89a53fefefa8 R12: ffff89960cb=
6b080
[   22.058117] R13: ffff899600051400 R14: ffffffffbcf2ba80 R15: ffff8996000=
5a800
[   22.058120] FS:  0000000000000000(0000) GS:ffff89a4ff2c0000(0000) knlGS:=
0000000000000000
[   22.058122] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   22.058124] CR2: 000055bf2cbc6038 CR3: 000000010dc1e000 CR4: 00000000000=
006f0
[   22.058128] Call Trace:
[   22.058130]  <TASK>
[   22.058133]  ? __warn+0x85/0x130
[   22.058137]  ? check_flush_dependency.part.0+0xbe/0x130
[   22.058139]  ? report_bug+0x18d/0x1c0
[   22.058142]  ? prb_read_valid+0x17/0x20
[   22.058147]  ? handle_bug+0x58/0x90
[   22.058151]  ? exc_invalid_op+0x13/0x60
[   22.058154]  ? asm_exc_invalid_op+0x16/0x20
[   22.058158]  ? __pfx_kfree_rcu_work+0x10/0x10
[   22.058162]  ? check_flush_dependency.part.0+0xbe/0x130
[   22.058165]  __flush_work+0xd6/0x320
[   22.058168]  flush_rcu_work+0x39/0x50
[   22.058171]  kvfree_rcu_barrier+0xe9/0x130
[   22.058174]  kmem_cache_destroy+0x18/0x140
[   22.058177]  process_one_work+0x184/0x3a0
[   22.058180]  worker_thread+0x24d/0x360
[   22.058183]  ? __pfx_worker_thread+0x10/0x10
[   22.058185]  kthread+0xfc/0x230
[   22.058189]  ? finish_task_switch.isra.0+0x85/0x2a0
[   22.058192]  ? __pfx_kthread+0x10/0x10
[   22.058195]  ret_from_fork+0x30/0x50
[   22.058199]  ? __pfx_kthread+0x10/0x10
[   22.058202]  ret_from_fork_asm+0x1a/0x30
[   22.058206]  </TASK>
[   22.058207] ---[ end trace 0000000000000000 ]---
[   23.123507]     ok 8 test_kfree_rcu_wq_destroy
[   23.151033]     ok 9 test_leak_destroy
[   23.151612]     ok 10 test_krealloc_redzone_zeroing
[   23.151617] # slub_test: pass:10 fail:0 skip:0 total:10
[   23.151619] # Totals: pass:10 fail:0 skip:0 total:10
[   23.151620] ok 1 slub_test
urezki@pc638:~$
<snip>

but i had to adapt slightly the Vlastimil's test:

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index f11691315c2f..222f6d204b0d 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -6,6 +6,7 @@
 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/rcupdate.h>
+#include <linux/delay.h>
 #include "../mm/slab.h"

 static struct kunit_resource resource;
@@ -181,6 +182,63 @@ static void test_kfree_rcu(struct kunit *test)
        KUNIT_EXPECT_EQ(test, 0, slab_errors);
 }

+struct cache_destroy_work {
+        struct work_struct work;
+        struct kmem_cache *s;
+};
+
+static void cache_destroy_workfn(struct work_struct *w)
+{
+       struct cache_destroy_work *cdw;
+
+       cdw =3D container_of(w, struct cache_destroy_work, work);
+       kmem_cache_destroy(cdw->s);
+}
+
+#define KMEM_CACHE_DESTROY_NR 10
+
+static void test_kfree_rcu_wq_destroy(struct kunit *test)
+{
+       struct test_kfree_rcu_struct *p;
+       struct cache_destroy_work cdw;
+       struct workqueue_struct *wq;
+       struct kmem_cache *s;
+       unsigned int rnd;
+       int i;
+
+       if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
+               kunit_skip(test, "can't do kfree_rcu() when test is built-i=
n");
+
+       INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
+       wq =3D alloc_workqueue("test_kfree_rcu_destroy_wq",
+                       WQ_HIGHPRI | WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
+
+       if (!wq)
+               kunit_skip(test, "failed to alloc wq");
+
+       for (i =3D 0; i < KMEM_CACHE_DESTROY_NR; i++) {
+               s =3D test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy=
",
+                               sizeof(struct test_kfree_rcu_struct),
+                               SLAB_NO_MERGE);
+
+               if (!s)
+                       kunit_skip(test, "failed to create cache");
+
+               rnd =3D get_random_u8() % 255;
+               p =3D kmem_cache_alloc(s, GFP_KERNEL);
+               kfree_rcu(p, rcu);
+
+               cdw.s =3D s;
+
+               msleep(rnd);
+               queue_work(wq, &cdw.work);
+               flush_work(&cdw.work);
+       }
+
+       destroy_workqueue(wq);
+       KUNIT_EXPECT_EQ(test, 0, slab_errors);
+}
+
 static void test_leak_destroy(struct kunit *test)
 {
        struct kmem_cache *s =3D test_kmem_cache_create("TestSlub_leak_dest=
roy",
@@ -254,6 +312,7 @@ static struct kunit_case test_cases[] =3D {
        KUNIT_CASE(test_clobber_redzone_free),
        KUNIT_CASE(test_kmalloc_redzone_access),
        KUNIT_CASE(test_kfree_rcu),
+       KUNIT_CASE(test_kfree_rcu_wq_destroy),
        KUNIT_CASE(test_leak_destroy),
        KUNIT_CASE(test_krealloc_redzone_zeroing),
        {}

--
Uladzislau Rezki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
74Av6tlSOqcfb-q%40pc636.
