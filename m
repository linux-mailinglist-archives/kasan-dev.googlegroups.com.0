Return-Path: <kasan-dev+bncBC7M5BFO7YCRBLXUWW3QMGQEPOPM35I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA78897D631
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 15:35:44 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2d877d2ad3fsf2678629a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 06:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726839343; cv=pass;
        d=google.com; s=arc-20240605;
        b=gLKvt3Pss1gDwc/1ZMe2WAUz30b9ejbPTVmKhSBD4fo1Nej9sRSzAZk/RDLRM7Zg8d
         k5EJCAPpHarujW3Zgn/a2vjWU5yO1MgxGN+JzfRSb8AlEfL0sZU/V4iPp/3YgbmEQ+Gc
         IZ93LnTeAEOzLlrNH7h9ic6Vc4GOag3VqGtp/UhO7wiByqEJ0uMniO8XRRYrLLdp0Cwc
         Dn4a6lyOLI6L4lwFNqAEzZpH7qaqjg1W6TCMnyidlzrZBKt9H2FNGoHJW1vV4W8XdHRW
         MG/SRKsrA02clQ2xnGcN2upL/WUbZNikIL7Vk8hB6EZiCwu4yDzLL1br9uJ4MahzPmax
         Z4yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=or3qaB3dEwcbUJwnT99IXjhy3DwbNtewWv7AyDMTEPw=;
        fh=cLfLsAuEwL0XHC6m21kmRlIagqTkO7i/X5izJLValhs=;
        b=PLxQNlBQjaYZvnFjJoh/mj1yAM6zd+ZTRo4m1tSeMN5FuXlfnCbLjSCVRbx3ZhAL42
         gg0fbZIZFzLWagI36YEH0OiKCoUmRBrQF3tCkM6m5WCj0CAXPYcnnlIcr76/fQbcHwJ7
         rC0RmpvDoHHRxAoTO1HqfXq1n7i7zNWo3h0rxpqH5teegmy+T+OM+CWffn5zAFyPLyIf
         cjlujCT0c1HNOpxsasRnVFiHKto/TZefE/DuWhH3Sdz2eN+5H/VfMcWVMGLApBbLJiTj
         QOX7mTVFVjAqd2LZCT4ItpZoa4nMa+NxXQOHsw3pTxnrg+pUpAbxqUjQT/p17UMKfvIH
         vSug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nKSDf9kw;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726839343; x=1727444143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=or3qaB3dEwcbUJwnT99IXjhy3DwbNtewWv7AyDMTEPw=;
        b=ZvEXHj+NPC0V86A5s7C7utwWF+QHkrl7vwHHGQnr5fnLsTqXqbWp3nR+ArJ+gjmWgZ
         3/CNLUmAPvc9abGDR4nERih3dKIcwlht7t7UrHvM5/3YUmAU03avcdurLTmvnsT4A9m9
         6pPefsk2PWYQ3nXcci/kmgdSrUldNDdroEaC95YYQQjTSpTWQz5vUkeLy3Rq43H4E+D+
         31CKtO8+olXzV8V7dNhtqkCjsdX4P90WbMqJGuv7uJQpBrKy6k4RoaETQGhCh3LH24gm
         npZqeZrdvred0yHla6J9fmN8kjTuu2Rz+cVHLUUM3ZJuZzQMmciQttTCaZV8gQcHS4G6
         kzKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726839343; x=1727444143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=or3qaB3dEwcbUJwnT99IXjhy3DwbNtewWv7AyDMTEPw=;
        b=HZ7Q40kOyb0RzhJQbgjjLkuVyKDIY7Q4G8y+QtRGJuvfCCVjoKeUEwHCUoQufxQZyL
         GRzZespyfeXIUR/MicdebbUrxOw8eQVQOgNU10NC0Pcg0qHlm2fMG1eS1uU2uzcSC0Dp
         Q57Rwobv3hnHEs38AlZPm/FcK3/OTmcVOTDUafpCZ+7InL9qaJvKMdO3lCudYnsmMYJN
         hwrnhV/B7MNXNtvdrFN7kjvcrybunXJRqWwYqeuJxY14ByeSKze4t2LLDyIJz4q7OWnG
         BIz0ikjYU0eDcrYMYvpxILB4kSaxrC4gSB25sEvVVk4MVUxLM7ppZ2KIWK/S0xyaTkFk
         nTsQ==
X-Forwarded-Encrypted: i=2; AJvYcCXM3g/QHz4RVFPuEmlURspCaBEEzDSo96XcwG+L7S1zICl2TwYYj0pIO1aVTy64bOAp0MS3oQ==@lfdr.de
X-Gm-Message-State: AOJu0YxUVTuV44grYUHyRu5jNs0YXA6zoDA/4gSR1h7QjeGAwBEjidOF
	83eFf9MvuwLo0fahyG5+tWQTe7noUUpSV9LrntxGGwwX9xOaogQI
X-Google-Smtp-Source: AGHT+IErl1Srx1FWgvyn53vhquqjEvjVCVo2/Vc8ObAEfO8K/5R596zE3Mr5oIUK1GFGzypxA+V1Ig==
X-Received: by 2002:a17:90a:c505:b0:2d8:8cef:3d64 with SMTP id 98e67ed59e1d1-2dd80c054a1mr3360710a91.6.1726839342917;
        Fri, 20 Sep 2024 06:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d348:b0:2d8:7c42:a28d with SMTP id
 98e67ed59e1d1-2dd6d358617ls1570049a91.0.-pod-prod-08-us; Fri, 20 Sep 2024
 06:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY6g2yqz/9sYe0eRE4EtkxrYdzBGryb3AjXGSqf0h6jqO1feuJMLkFOQIwQHgwujg1GfdBADimxj0=@googlegroups.com
X-Received: by 2002:a17:90a:c297:b0:2da:6a4d:53a6 with SMTP id 98e67ed59e1d1-2dd80c4f8fdmr3869621a91.19.1726839341483;
        Fri, 20 Sep 2024 06:35:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726839341; cv=none;
        d=google.com; s=arc-20240605;
        b=fIXcDG2BA82xZK1/wlGpBiz6uDcrAfvV7/aJE1AtEuwJZYjjI5Mt9NiSPZ1KCkyzAu
         hySI2wq1hzszR7LLhq5bMCqQFTI5gccGqpadfc+oj4HPt93+THjGBeIlGE5RIwyOp1+g
         BzsJaGKwksJaID3SEpo1njuhWU0JNaBle8TYLzSYGwcg6ZOwL4UD5/RUskGQufYZqZgD
         cMd7sE9ZuCPWVPPRvQiyWq+CR9v+jrwyNTi4Dld6IMhFsHmeWpEqmhCt8tzPsjmYgwff
         /pHXpd/g568PHF0WypczoXQ7CSthhc0CuDMT0mMhgOiTOHcoIdC06lpfvi/vRZOUjQ2u
         /Suw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=4WiT20VvGZEoLul+yBbb3XAfILOiLHoijWP26iP09Gk=;
        fh=KJ4JKQD5RULYBDf6soPBVG9+nmNSZHdKI+njRnRcRE0=;
        b=in2dAnmztmkDOXtxMecUMFemGFPscZJSFuWY+G9qjDwXA29k7jevcuq34UV5gxy3Q9
         lEq/ePnJJjAz9W5uQhi/uil/jwN/K9CFpdzih2TfoBzCCcd307ohPbbuBm0ORL4NdrF0
         0z8GONY+SaTunK/nCSjh7zs0uAveyk9Z/8aCZU4G4xnkpGLS08Sn4mzdjcJIRXfdjwBp
         wsTBEBBESexGfgY0QJBdzcXgTRxE3rp1IAKYVeFfAxxsGWONTLFB1E4fEEZX9L/SKsM1
         +VLOyaP7yyixUnrDtvMO1XYgnoHYPdxPDMnDvpw5AGLASZRT2KAvU9C2csggglZUrCTh
         SM5w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nKSDf9kw;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2dd50c16dc8si716263a91.0.2024.09.20.06.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2024 06:35:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-7db0fb03df5so1436585a12.3
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2024 06:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXpFrpzEHC1yocinBux+KH/mzgNOJgxX68Kkr22ODvmUSrjN7x1XgrNRTqQWoP7HbSmeFDtqtADMLs=@googlegroups.com
X-Received: by 2002:a05:6a21:9216:b0:1cf:506a:cdcc with SMTP id adf61e73a8af0-1d30cb65dedmr4244909637.43.1726839340992;
        Fri, 20 Sep 2024 06:35:40 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2079460110fsm95281375ad.96.2024.09.20.06.35.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Sep 2024 06:35:39 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Fri, 20 Sep 2024 06:35:38 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
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
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Message-ID: <6fcb1252-7990-4f0d-8027-5e83f0fb9409@roeck-us.net>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nKSDf9kw;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::536 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

Hi,

On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
> Add a test that will create cache, allocate one object, kfree_rcu() it
> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
> in kmem_cache_destroy() works correctly, there should be no warnings in
> dmesg and the test should pass.
>=20
> Additionally add a test_leak_destroy() test that leaks an object on
> purpose and verifies that kmem_cache_destroy() catches it.
>=20
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

This test case, when run, triggers a warning traceback.

kmem_cache_destroy TestSlub_kfree_rcu: Slab cache still has objects when ca=
lled from test_leak_destroy+0x70/0x11c
WARNING: CPU: 0 PID: 715 at mm/slab_common.c:511 kmem_cache_destroy+0x1dc/0=
x1e4

That is, however, not the worst of it. It also causes boot stalls on
several platforms and architectures (various arm platforms, arm64,
loongarch, various ppc, and various x86_64). Reverting it fixes the
problem. Bisect results are attached for reference.

Guenter

---
# bad: [baeb9a7d8b60b021d907127509c44507539c15e5] Merge tag 'sched-rt-2024-=
09-17' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
# good: [2f27fce67173bbb05d5a0ee03dae5c021202c912] Merge tag 'sound-6.12-rc=
1' of git://git.kernel.org/pub/scm/linux/kernel/git/tiwai/sound
git bisect start 'HEAD' '2f27fce67173'
# good: [ae2c6d8b3b88c176dff92028941a4023f1b4cb91] Merge tag 'drm-xe-next-f=
ixes-2024-09-12' of https://gitlab.freedesktop.org/drm/xe/kernel into drm-n=
ext
git bisect good ae2c6d8b3b88c176dff92028941a4023f1b4cb91
# bad: [c8d8a35d094626808cd07ed0758e14c7e4cf61ac] Merge tag 'livepatching-f=
or-6.12' of git://git.kernel.org/pub/scm/linux/kernel/git/livepatching/live=
patching
git bisect bad c8d8a35d094626808cd07ed0758e14c7e4cf61ac
# bad: [cc52dc2fe39ff5dee9916ac2d9381ec3cbf650c0] Merge tag 'pwm/for-6.12-r=
c1' of git://git.kernel.org/pub/scm/linux/kernel/git/ukleinek/linux
git bisect bad cc52dc2fe39ff5dee9916ac2d9381ec3cbf650c0
# bad: [bdf56c7580d267a123cc71ca0f2459c797b76fde] Merge tag 'slab-for-6.12'=
 of git://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab
git bisect bad bdf56c7580d267a123cc71ca0f2459c797b76fde
# good: [355debb83bf79853cde43579f88eed16adb1da29] Merge branches 'context_=
tracking.15.08.24a', 'csd.lock.15.08.24a', 'nocb.09.09.24a', 'rcutorture.14=
.08.24a', 'rcustall.09.09.24a', 'srcu.12.08.24a', 'rcu.tasks.14.08.24a', 'r=
cu_scaling_tests.15.08.24a', 'fixes.12.08.24a' and 'misc.11.08.24a' into ne=
xt.09.09.24a
git bisect good 355debb83bf79853cde43579f88eed16adb1da29
# good: [067610ebaaec53809794807842a2fcf5f1f5b9eb] Merge tag 'rcu.release.v=
6.12' of git://git.kernel.org/pub/scm/linux/kernel/git/rcu/linux
git bisect good 067610ebaaec53809794807842a2fcf5f1f5b9eb
# good: [4b7ff9ab98af11a477d50f08382bcc4c2f899926] mm, slab: restore kernel=
doc for kmem_cache_create()
git bisect good 4b7ff9ab98af11a477d50f08382bcc4c2f899926
# bad: [a715e94dbda4ece41aac49b7b7ff8ddb55a7fe08] Merge branch 'slab/for-6.=
12/rcu_barriers' into slab/for-next
git bisect bad a715e94dbda4ece41aac49b7b7ff8ddb55a7fe08
# bad: [b3c34245756adada8a50bdaedbb3965b071c7b0a] kasan: catch invalid free=
 before SLUB reinitializes the object
git bisect bad b3c34245756adada8a50bdaedbb3965b071c7b0a
# good: [2eb14c1c2717396f2fb1e4a4c5a1ec87cdd174f6] mm, slab: reintroduce rc=
u_barrier() into kmem_cache_destroy()
git bisect good 2eb14c1c2717396f2fb1e4a4c5a1ec87cdd174f6
# good: [6c6c47b063b593785202be158e61fe5c827d6677] mm, slab: call kvfree_rc=
u_barrier() from kmem_cache_destroy()
git bisect good 6c6c47b063b593785202be158e61fe5c827d6677
# bad: [4e1c44b3db79ba910adec32e2e1b920a0e34890a] kunit, slub: add test_kfr=
ee_rcu() and test_leak_destroy()
git bisect bad 4e1c44b3db79ba910adec32e2e1b920a0e34890a
# first bad commit: [4e1c44b3db79ba910adec32e2e1b920a0e34890a] kunit, slub:=
 add test_kfree_rcu() and test_leak_destroy()

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6fcb1252-7990-4f0d-8027-5e83f0fb9409%40roeck-us.net.
