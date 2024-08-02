Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBT4EWW2QMGQEWFGRCGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D9B09946469
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 22:32:16 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ef1eb48794sf80373881fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 13:32:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722630736; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRP+Sb2p58WSGSA6uwx4EDeHTYR/6E0cdv/iSdrarTnfaTCn/NRPUX9q14cH9zXpri
         fyfso5L7q20kXnSyPYPL5Yi2zIChl/YIKf3HpFxPVBcOHpDodMjI/CaX9u7r95ZISVfL
         Th8kjXCueBkZt5AcESc8hI/T6nkduzRJxU4kWqw3usbW4byVdZt4qWomdPmwwpgfnkqC
         G+ktvOL9JniOLBQbz0iW/OlFnSlbiLgpx+T8isv4D44chFxecq0Mt8oY3AwdcLWYqfYC
         60GmFd5DB9gYeOPfNfqx12qkXzzbODUOg7AuhghLJHdUEmbgXg/CVUOmRoDFy/1ulFnB
         ElsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=MklfKZSKn6vK/rj/wTcE04B3Z8cDqvHKQkAApdttptE=;
        fh=oy0NoRLKc53L64vmr5hWZjVFBWDqyqJX7fn56sTsDZA=;
        b=xCJHbsbayOKnf1pt5JY26oL4usEHL6W8/f7XaNuWuLROhxoVg192xL4+wDo4Q3A6ri
         f6IpGCvqBM+rVhoElO6VpUKRjPf/V9gAsjUwD0fQ54CoqienD9w1xKTq6AJzWzrA2WJw
         hld7kdJSWrXk1MDqH7YqKv0mcLw1/dY/TjFVyasUtGltJaHIt58MT0KOtJKwiOek4f+D
         H621GE6Ov0lZxQVBYEpLCJZk6mP4JzGP/+KR/pEQhGIomcLQlb4bCMhI+drlaSLdUJtP
         H1A/4jKzUq2Zdpm+HfoMELLgmPkPCwU8JbE451p+IFHtxhZbmfPcA3WWWukM9f750mbE
         sSgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q28OOrKl;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722630736; x=1723235536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MklfKZSKn6vK/rj/wTcE04B3Z8cDqvHKQkAApdttptE=;
        b=fwnyXttVwPFXJO66sFrYSybiKwxwsbEwk88HlTQnfi8HA4mPHgFhYE/6rXAjRtRVaw
         tEkLl+C7c/8GV/CA7uLgbsrxTbaHBmvI9Ba8UOqdxFYRLzBC5Az7i01CJEqAkP7NA/in
         kVm5XFavsDkME1TBwdpH4SyVajoQSWUUlKceQ51bokMvtRNmZvwkyCtdSNySskSBhtf9
         ZQMYiAIsiTeqxK5ZXTCiKgMPaAe0a0ObvjgbX0wP6atQJMazri8EIJwTXKkK4/DNC/GW
         Ro5nJDg+2OxX7KC8qPY35KwQNJGS16HeRZG08Qc1JS+iy3oAhr0R8EhqiKgWCTSvYEDM
         bL0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722630736; x=1723235536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MklfKZSKn6vK/rj/wTcE04B3Z8cDqvHKQkAApdttptE=;
        b=kaUFgZxlnKucWWIg8I4Rw5/VR0gZMoP3PC25YNcttvD5Fe0c9yse6p45i45oi2enr5
         GGIAmLjWH1If84BcG/DL/SavQ30GyvJ8i5LO2jsbwW64KQrsHU96nuwKm0sP6nu1lUMi
         LtfKN7QpSVxmjunW2tDmYG/5AZtM64QP2CDo4cYjAo6HDPLjoMVBpX3MyWo5kkqFkJD6
         u4ejhuIz5TLOs0wZwt5cnBFiPCcDtdkc/0Huwl6LUT2QZjtjt74cZXVuXwWiFfXZZmbp
         2fGxX9yJpS0s1rtt+5ndrgCQATHV4Rl+zjetGGvAY/1BwG6BNmvaVkJH1qDoUXLnocLl
         nMhg==
X-Forwarded-Encrypted: i=2; AJvYcCXSE/a6zM2Pf6H1DTp4b3kTxxEj97Qxz28Mp0SB+pfy2lOAyGZbE+gIEMe5dZTC4Vg8fMRI5TVNYwZNEY2EoZ/kWxAum7DDYA==
X-Gm-Message-State: AOJu0YwutYgZXIO1uCaBuOcZlJeCkRllivt4Alg8MA1OP6WubFymuS9t
	W1t/qVvSSFyNS+ku35md5E+3FinQns42tAsedGYFZLYhDaiewhdV
X-Google-Smtp-Source: AGHT+IHTj+y+HMGjDswJbfuyKTQhdnvVXdxnSmo4ZE5armiOnk/uqQgNwGs0WoI8ZyjiKDUv396WxA==
X-Received: by 2002:a2e:b70a:0:b0:2ef:2c6a:4929 with SMTP id 38308e7fff4ca-2f15aa87463mr36239371fa.13.1722630735495;
        Fri, 02 Aug 2024 13:32:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0b:b0:426:6f58:8e6d with SMTP id
 5b1f17b1804b1-428ede20df2ls1096425e9.2.-pod-prod-03-eu; Fri, 02 Aug 2024
 13:32:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOyk5o4bTJBRX7iIjI8I+lKdY9NBcp+pHisROsaRTw5uMpwHeSLstEHRlQ6+f+AeRwXxrl0RP9QUEs7G517VTSQ2xbxJ1X3N8Veg==
X-Received: by 2002:a05:600c:1d17:b0:426:64a2:5375 with SMTP id 5b1f17b1804b1-428e6af2eaemr32934675e9.1.1722630733625;
        Fri, 02 Aug 2024 13:32:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722630733; cv=none;
        d=google.com; s=arc-20160816;
        b=sDSfDNYwNUNVtK4IuHbN8YucVLIUmSUNcdneQaaODUVcEySKgyX7JI1ckxST7mGQjm
         2AMxL410ukj5J+jr2zyGB3CY3nKZrNdIRqbBqvvCGCToDYHkvgdFSG2sbCgGFTpp+Lx9
         tka3ZWa/OAn+xSdfdZDNwfRYqfUDHbXExEjkRTciCoqnL3zUEv/tmnseAPxF+BblM7a+
         RgnX4aiUMi2jMPYE8xpor+wqbcYrkqBhw9Pdig7waFKHzdHEAROHMzq7aLTbc/Y8V8k/
         pRxzlY1lK5g9KwtbIAF14Piq7q/ZhEqrTLcEOOYcoxBFOZYNCZs7CYmshtz0FCg+uAXm
         gwow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=9tpvdJVeACeB5qkpDGLZPHMZmPZisvxXSMDixUJOlJA=;
        fh=/uM5sDEqg0jaYDY0Hx9//wEi2Mp4D084C+SP+spx/OA=;
        b=LVI59uaQ5kijvuJz4Y6xYjMnPCvNPvKsMYTDbp1/KrvdKWJKiH9OpqzLxEp391K/+Z
         mk/ZhXxKcRhS+YHoIT76rui3wZQtoss3Da0yqRt+NjHhQdr2U0K7cPejBT9GlSCdPdaw
         x9s6PX55MfxBPB4K79h7l3OkODD41uLAMJRn0HMeCvhVSTxXpHNaOYfGvqwkTI9Fu5Vu
         RQqnuhTGIX7iYK2vmv8lN3+IJi7ORmr+2QUgg7jEZBkdw008dkQ2vDClbBhFlyil5G8o
         HqiTq9xs3TRDckBkTsYaw2ukn+eegoptA2LWH0eAmjQdcVr/oJguigbcdCXjxy3QTarE
         /fRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q28OOrKl;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4282412a934si7639075e9.0.2024.08.02.13.32.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 13:32:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so59067a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 13:32:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWBPrJuN1tphC7wBkJc7okLeBKFlsXynATjDfC6abvmq4gHj9mRNFRaYeAgIowyPtdaYyqCe7nUbfc48h3bvMbXN2Lx0sWMqOrbmA==
X-Received: by 2002:a05:6402:2816:b0:58b:b1a0:4a2d with SMTP id 4fb4d7f45d1cf-5b9bebbc4ebmr17961a12.1.1722630732323;
        Fri, 02 Aug 2024 13:32:12 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:9337:bd1:a20d:682d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36bbd26fc0bsm2700267f8f.117.2024.08.02.13.32.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Aug 2024 13:32:11 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v6 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Fri, 02 Aug 2024 22:31:52 +0200
Message-Id: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIADhCrWYC/2XOTQrCMBCG4atI1kbyn9SV9xAX7TRpg9pIokGR3
 t1UEGq7/Aael3mjZKO3Ce03bxRt9smHoQy13SDo66Gz2LdlI0aYIJpxfK5TPeB7aiI8cKOprCt
 CndYKFXKL1vnnN3c8ld37dA/x9a1nNl1/IfEfygwTLKQzlSFKCGUOXQjdxe4gXNFUynyu5ULzo
 iWFijnjKCV0pcVcVwstJq0tGGmdIaBWWs40Jwstp89Ny6FpHQDIPz2O4wfi2NX6YwEAAA==
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>, 
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1722630727; l=6723;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=6m7b7k4S8KWZIyDEYtTqqzHl0D1lSK3y59XxPtdM71k=;
 b=ROnheg8tvs64V5aBE3C/N6iTsCrkOSnws3DYdQsxny3FmQBfdmH9iXSA+l0ZCG8iSfWllv24d
 WhfHmS099E8AKLS35y3E0a7JdnTW9eV4R7Oq5fL43NvVgOV2T/6Tl+v
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q28OOrKl;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::534 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

The purpose of the series is to allow KASAN to detect use-after-free
access in SLAB_TYPESAFE_BY_RCU slab caches, by essentially making them
behave as if the cache was not SLAB_TYPESAFE_BY_RCU but instead every
kfree() in the cache was a kfree_rcu().
This is gated behind a config flag that is supposed to only be enabled
in fuzzing/testing builds where the performance impact doesn't matter.

Output of the new kunit testcase I added to the KASAN test suite:
==================================================================
BUG: KASAN: slab-use-after-free in kmem_cache_rcu_uaf+0x3ae/0x4d0
Read of size 1 at addr ffff888106224000 by task kunit_try_catch/224

CPU: 7 PID: 224 Comm: kunit_try_catch Tainted: G    B            N 6.10.0-00003-g065427d4b87f #430
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
Call Trace:
 <TASK>
 dump_stack_lvl+0x53/0x70
 print_report+0xce/0x670
[...]
 kasan_report+0xa5/0xe0
[...]
 kmem_cache_rcu_uaf+0x3ae/0x4d0
[...]
 kunit_try_run_case+0x1b3/0x490
[...]
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
[...]
 ret_from_fork+0x34/0x70
[...]
 ret_from_fork_asm+0x1a/0x30
 </TASK>

Allocated by task 224:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 __kasan_slab_alloc+0x6e/0x70
 kmem_cache_alloc_noprof+0xef/0x2b0
 kmem_cache_rcu_uaf+0x10d/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

Freed by task 0:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 kasan_save_free_info+0x3b/0x60
 __kasan_slab_free+0x57/0x80
 slab_free_after_rcu_debug+0xe3/0x220
 rcu_core+0x676/0x15b0
 handle_softirqs+0x22f/0x690
 irq_exit_rcu+0x84/0xb0
 sysvec_apic_timer_interrupt+0x6a/0x80
 asm_sysvec_apic_timer_interrupt+0x1a/0x20

Last potentially related work creation:
 kasan_save_stack+0x33/0x60
 __kasan_record_aux_stack+0x8e/0xa0
 kmem_cache_free+0x10c/0x420
 kmem_cache_rcu_uaf+0x16e/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

The buggy address belongs to the object at ffff888106224000
 which belongs to the cache test_cache of size 200
The buggy address is located 0 bytes inside of
 freed 200-byte region [ffff888106224000, ffff8881062240c8)

The buggy address belongs to the physical page:
page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x106224
head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
flags: 0x200000000000040(head|node=0|zone=2)
page_type: 0xffffefff(slab)
raw: 0200000000000040 ffff88810621c140 dead000000000122 0000000000000000
raw: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000040 ffff88810621c140 dead000000000122 0000000000000000
head: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000001 ffffea0004188901 ffffffffffffffff 0000000000000000
head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888106223f00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff888106223f80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff888106224000: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                   ^
 ffff888106224080: fb fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc
 ffff888106224100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
    ok 38 kmem_cache_rcu_uaf

Signed-off-by: Jann Horn <jannh@google.com>
---
Changes in v6:
- in patch 1/2:
  - fix commit message (Andrey)
  - change comments (Andrey)
  - fix mempool handling of kfence objects (Andrey)
- in patch 2/2:
  - fix is_kfence_address argument (syzbot and Marco)
  - refactor slab_free_hook() to create "still_accessible" variable
  - change kasan_slab_free() hook argument to "still_accessible"
  - add documentation to kasan_slab_free() hook
- Link to v5: https://lore.kernel.org/r/20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com

Changes in v5:
- rebase to latest origin/master (akpm), no other changes from v4
- Link to v4: https://lore.kernel.org/r/20240729-kasan-tsbrcu-v4-0-57ec85ef80c6@google.com

Changes in v4:
- note I kept vbabka's ack for the SLUB changes in patch 1/2 since the
  SLUB part didn't change, even though I refactored a bunch of the
  KASAN parts
- in patch 1/2 (major rework):
  - fix commit message (Andrey)
  - add doc comments in header (Andrey)
  - remove "ip" argument from __kasan_slab_free()
  - rework the whole check_slab_free() thing and move code around (Andrey)
- in patch 2/2:
  - kconfig description and dependency changes (Andrey)
  - remove useless linebreak (Andrey)
  - fix comment style (Andrey)
  - fix do_slab_free() invocation (kernel test robot)
- Link to v3: https://lore.kernel.org/r/20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com

Changes in v3:
- in patch 1/2, integrate akpm's fix for !CONFIG_KASAN build failure
- in patch 2/2, as suggested by vbabka, use dynamically allocated
  rcu_head to avoid having to add slab metadata
- in patch 2/2, add a warning in the kconfig help text that objects can
  be recycled immediately under memory pressure
- Link to v2: https://lore.kernel.org/r/20240724-kasan-tsbrcu-v2-0-45f898064468@google.com

Changes in v2:
Patch 1/2 is new; it's some necessary prep work for the main patch to
work, though the KASAN integration maybe is a bit ugly.
Patch 2/2 is a rebased version of the old patch, with some changes to
how the config is wired up, with poison/unpoison logic added as
suggested by dvyukov@ back then, with cache destruction fixed using
rcu_barrier() as pointed out by dvyukov@ and the test robot, and a test
added as suggested by elver@.

---
Jann Horn (2):
      kasan: catch invalid free before SLUB reinitializes the object
      slub: Introduce CONFIG_SLUB_RCU_DEBUG

 include/linux/kasan.h | 63 ++++++++++++++++++++++++++++++++++---
 mm/Kconfig.debug      | 30 ++++++++++++++++++
 mm/kasan/common.c     | 62 ++++++++++++++++++++++---------------
 mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++
 mm/slab_common.c      | 12 +++++++
 mm/slub.c             | 86 ++++++++++++++++++++++++++++++++++++++++++++++-----
 6 files changed, 261 insertions(+), 38 deletions(-)
---
base-commit: 94ede2a3e9135764736221c080ac7c0ad993dc2d
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240802-kasan-tsbrcu-v6-0-60d86ea78416%40google.com.
