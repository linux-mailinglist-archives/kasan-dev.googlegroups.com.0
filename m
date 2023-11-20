Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQWN52VAMGQE4KRUTMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1235D7F1C77
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:44 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5079fd9754csf4765713e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505283; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAOAMu3GvecyJ6CrBTcAUP7XS9TMsbNSID5V+g9Hzz/GCU5mw4wwBG6bCwAaEBNsDT
         NtcPyKLfetMFI1gymlRaovb+FpSeEAYsP80ycJVgN2AgRvIIo8EC5c0LV5C9Kay8u5si
         GAlIKtG/9HBa3GU36i2sKt0UBcNLR/9ZEco0gABMiOcIcMGhiphisjaaOpw5aTOI/TCh
         MC5BmTmpEp+BoQRS43VWFOQcsvOAOmaG66oPrjoPWLtCv+YSHn091Z8NGdArZPJP01uU
         OnruPtZgjEcw4bh3eih+oI9s7kOrSyKAp5cqmevEb+oLmxU3pwvzYQjEkEaamlDksXI+
         dldg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=AfgCvIsYVbQiUvsogxYYjs96/q2Y850g3/utJe8KWCg=;
        fh=MRTOIXfVX3Adq+dUnG3e08jCcH1vzjt/FZ2JSU3w4gE=;
        b=HaC8nm+XsiFFkbizV047PcaZNX1j3dSdSHeAm7Gl4s8fAYiXqpUh8UXmQNoTMkwkq0
         pqgqrdV/BcpTEhNoJQfwjJTeqEflZEh8Ve8qZtptxoN+npWbb1jKd1Lkx8HLLouvzEwG
         /vhjPeP8TzYj+qWIxqRybxsiRfbUL15GJVghrJYMePDoIrEgOYz+OqwI9RXOFYvF5zIp
         6v55jzagz9HlhlYosUyPscU37gb1FyAcqIAXfbCoTldMWQuH6vHF6Iu8sXIGxVnj0TZd
         iju+yct1SI/jUU4KJ0+hbsWaxO0gFyO/0NGTwgQmnDOfk1NHhejBQu3gaw7vkPzWqmvO
         PFcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTA9iWAb;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505283; x=1701110083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AfgCvIsYVbQiUvsogxYYjs96/q2Y850g3/utJe8KWCg=;
        b=kf5NV3dGdYVwo01oD/0G+02FaWsiw6ueLuknwFyt1Hyy+pxOQhNb8BPUwW9wKxzbqM
         dY8gCOxGtgiGoZX50/xr1mNseZhSOfwikrBcGAQG3kUQ5Todm6ZfjP67Zuzgm7uPiAgt
         vYl2tZGC5i7RUyl9OK+FCs1jIxCcUBdqbdo6L6xgRO2MJu9dkuA7I4b/gyL+Q86IwcJ5
         vNIXIcZXY/eVZRakJP/jmUXXYAsa21co0UqSMej0TRxqjh1LDGSiFIMT6WHp0T5l5RBi
         2liPUtdtkBhPZd9qnaui/orl93d7vxCvfkefAa59ziCIr/7UCM7TXbdPtrXU24tjDjlL
         pkrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505283; x=1701110083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AfgCvIsYVbQiUvsogxYYjs96/q2Y850g3/utJe8KWCg=;
        b=aF18Oir20a8fAYxgkhLdYByOLIU5d/aO3eroyOFlQMLNGaJ3QcfPRGuS6fYUojMuY2
         qGeBNYzSTd3J5LlGCfBjqnVJTq/2X7vdko19V24TmOwlqW1E3rXwEILEat7pE3drqjaD
         YvtKIavQRQ+5r/jQPZf9UpQ1UH9hpJTtee94XbZ/WsfOIXx+iZ1ClqzIfvAOkI8LSaAw
         +8yNJT/i4o6UY/R9WyjThmVC9Q6FzE8EHDUZ2gNvrm7Tav7gBRKtIIbXP4ctDyTSN9RY
         TMqLs/Sc8XIwPoGQmeFOoHE3RbR9Msf0Enh+p1clOZMhWNhIBDwq5e8g/ZQ/Ypq6i4P2
         5u2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOJvMlB8bZmIM1eLiIVRSPpjdLrwCrVhpVIL8jPYWdak2gjTlL
	VHseXK2S5yqST5qUdDD7MPI=
X-Google-Smtp-Source: AGHT+IHtG2eEObGyCe12/Vh6L2QpjvYzsX3/10dOzwStE880xjtq2zF1CWY4+SkPCmahpo0vN9c8zQ==
X-Received: by 2002:ac2:44c6:0:b0:508:12f6:ff07 with SMTP id d6-20020ac244c6000000b0050812f6ff07mr5293615lfm.48.1700505282706;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2305:b0:507:cf9c:aa7e with SMTP id
 o5-20020a056512230500b00507cf9caa7els257250lfu.1.-pod-prod-07-eu; Mon, 20 Nov
 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a19:f60d:0:b0:50a:7640:6a83 with SMTP id x13-20020a19f60d000000b0050a76406a83mr5994333lfe.32.1700505280542;
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505280; cv=none;
        d=google.com; s=arc-20160816;
        b=ZlOwqc8xuadn0tWl5JgBEc5OyGjgDr0UWlrb/CoWlNEBaxwqkcVxU+keMWL7pIlgR0
         0r1B5H4M1oLGF39pqi4kAjFOMCFTxsUnHS6iwg7Iv7Fnt9ypAvkvgf+OG1PgBEbJewg4
         B2BGENRrARCERRkEk4im5LyZ/nDsPwviRn/09K1Snw8lYAw/ldjvYARkLMc8vjw0qC/q
         n4h3qPPiLFsuR+RB+JVbTkYCSmtYeMlQtt66i/COUVr/P7CMdKDOT/+qzOn97bn0gJtV
         DE1TzGHRRknjM5tBP7pJSic3vQSjRuLI3WSgF8hCX28GjIg3F4EiRw0AZSnPbnMjLgLR
         rpFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature;
        bh=TE/wmIqY+Mqmq3Uv3qpaJHn4wLurFsze1PiLFKu5tjU=;
        fh=MRTOIXfVX3Adq+dUnG3e08jCcH1vzjt/FZ2JSU3w4gE=;
        b=TxbZKq6jp8INy+9o+EV/jRzHR9GrlGoKvbME4voTPLiP8tns+Jh4WdZekVvh2Bv2Z5
         UoEMC1b22di/vC/z+9Q7bvyrLmgP+WD8Nf/P+M/sZOMnRx54h5NU4axsX5wBa9Ans3sE
         4hTBHPEAT6SPDulRfNyQ54gJHEY+A7bBoySPDZuh2PGSV9oRDviVUU+SBYNh3+Tg2loV
         bIPqVPcxQ/Bf3YBPuTrAP/av70iNo5VBRQTvpgcs7YHgD9KrfeJ9iQ1daIYVRmdNdtVN
         UgNGIVVG9BePSFLpHP5izXzPzR98W9qPeFQ81xUb2H3QuCKKDL3WxprAuXLNhAnerZUo
         AmCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NTA9iWAb;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bi28-20020a0565120e9c00b0050446001e0bsi344630lfb.3.2023.11.20.10.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7B0AB1F895;
	Mon, 20 Nov 2023 18:34:39 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 2D01313499;
	Mon, 20 Nov 2023 18:34:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id omBJCr+mW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:39 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH v2 00/21] remove the SLAB allocator
Date: Mon, 20 Nov 2023 19:34:11 +0100
Message-Id: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAKSmW2UC/03MQQ7CIBCF4as0s5YGhoaiK+9hXACdWqIthlFib
 Hp3iW7cvW/x/hWYciSGQ7NCphI5pqUCdw2EyS0XEnGoBpSolUIp+Oa8yDSnQr/tekPBGDvYYKD
 e7pnG+PomT+fqMadZPKZM7i+ktNor3clW9Z1FgSiKd/7qjvxkasMbtu0DXrt6spsAAAA=
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>, 
 Michal Hocko <mhocko@suse.com>
X-Mailer: b4 0.12.4
X-Spam-Level: *****
X-Spam-Score: 5.30
X-Spamd-Result: default: False [5.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_SPAM(5.10)[100.00%];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[25];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz,suse.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NTA9iWAb;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Changes from v1:
- Added new Patch 01 to fix up kernel docs build (thanks Marco Elver)
- Additional changes to Kconfig user visible texts in Patch 02 (thanks Kees
  Cook)
- Whitespace fixes and other fixups (thanks Kees)

The SLAB allocator has been deprecated since 6.5 and nobody has objected
so far. As we agreed at LSF/MM, we should wait with the removal until
the next LTS kernel is released. This is now determined to be 6.6, and
we just missed 6.7, so now we can aim for 6.8 and start exposing the
removal to linux-next during the 6.7 cycle. If nothing substantial pops
up, will start including this in slab-next later this week.

To keep the series reasonably sized and not pull in people from other
subsystems than mm and closely related ones, I didn't attempt to remove
every trace of unnecessary reference to dead config options in external
areas, nor in the defconfigs. Such cleanups can be sent to and handled
by respective maintainers after this is merged.

Instead I have added some patches aimed to reap some immediate benefits
of the removal, mainly by not having to split some fastpath code between
slab_common.c and slub.c anymore. But that is also not an exhaustive
effort and I expect more cleanups and optimizations will follow later.

Patch 09 updates CREDITS for the removed mm/slab.c. Please point out if
I missed someone not yet credited.

Git version: https://git.kernel.org/vbabka/l/slab-remove-slab-v2r1

---
Vlastimil Babka (21):
      mm/slab, docs: switch mm-api docs generation from slab.c to slub.c
      mm/slab: remove CONFIG_SLAB from all Kconfig and Makefile
      KASAN: remove code paths guarded by CONFIG_SLAB
      KFENCE: cleanup kfence_guarded_alloc() after CONFIG_SLAB removal
      mm/memcontrol: remove CONFIG_SLAB #ifdef guards
      cpu/hotplug: remove CPUHP_SLAB_PREPARE hooks
      mm/slab: remove CONFIG_SLAB code from slab common code
      mm/mempool/dmapool: remove CONFIG_DEBUG_SLAB ifdefs
      mm/slab: remove mm/slab.c and slab_def.h
      mm/slab: move struct kmem_cache_cpu declaration to slub.c
      mm/slab: move the rest of slub_def.h to mm/slab.h
      mm/slab: consolidate includes in the internal mm/slab.h
      mm/slab: move pre/post-alloc hooks from slab.h to slub.c
      mm/slab: move memcg related functions from slab.h to slub.c
      mm/slab: move struct kmem_cache_node from slab.h to slub.c
      mm/slab: move kfree() from slab_common.c to slub.c
      mm/slab: move kmalloc_slab() to mm/slab.h
      mm/slab: move kmalloc() functions from slab_common.c to slub.c
      mm/slub: remove slab_alloc() and __kmem_cache_alloc_lru() wrappers
      mm/slub: optimize alloc fastpath code layout
      mm/slub: optimize free fast path code layout

 CREDITS                           |   12 +-
 Documentation/core-api/mm-api.rst |    2 +-
 arch/arm64/Kconfig                |    2 +-
 arch/s390/Kconfig                 |    2 +-
 arch/x86/Kconfig                  |    2 +-
 include/linux/cpuhotplug.h        |    1 -
 include/linux/slab.h              |   22 +-
 include/linux/slab_def.h          |  124 --
 include/linux/slub_def.h          |  204 --
 kernel/cpu.c                      |    5 -
 lib/Kconfig.debug                 |    1 -
 lib/Kconfig.kasan                 |   11 +-
 lib/Kconfig.kfence                |    2 +-
 lib/Kconfig.kmsan                 |    2 +-
 mm/Kconfig                        |   68 +-
 mm/Kconfig.debug                  |   16 +-
 mm/Makefile                       |    6 +-
 mm/dmapool.c                      |    2 +-
 mm/kasan/common.c                 |   13 +-
 mm/kasan/kasan.h                  |    3 +-
 mm/kasan/quarantine.c             |    7 -
 mm/kasan/report.c                 |    1 +
 mm/kfence/core.c                  |    4 -
 mm/memcontrol.c                   |    6 +-
 mm/mempool.c                      |    6 +-
 mm/slab.c                         | 4026 -------------------------------------
 mm/slab.h                         |  551 ++---
 mm/slab_common.c                  |  231 +--
 mm/slub.c                         |  617 +++++-
 29 files changed, 815 insertions(+), 5134 deletions(-)
---
base-commit: b85ea95d086471afb4ad062012a4d73cd328fa86
change-id: 20231120-slab-remove-slab-a76ec668d8c6

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-0-9c9c70177183%40suse.cz.
