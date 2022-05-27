Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB6HPYKKAMGQEUZB4MTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A743535F5B
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 13:37:29 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id s16-20020adfeb10000000b0020cc4e5e683sf743952wrn.6
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653651449; cv=pass;
        d=google.com; s=arc-20160816;
        b=03ZopEJg+UrNMDfdNabXzYl1p8AcqgRg3FjSGcifNrMmLd/99WGv6UqstcEX+g9kyz
         B8hX+St+oc07t24hT6fx815LPsmQ4qAGfp7w3kDgiRFUnUNF3F+598S2XXPlxpfDcSSb
         mP6Cn92iqRcI5GBXd3wc+lLl0UA1dpUIowKldOSI0AL/7x0ef4qcGF2ZISi9bBfIcthx
         8fg2g7OYk5FxEbM9MkjA/pXBRJQWB7mDrDxzRVubDSx7u0ijRMt9RVJLg3BiqqU8iJxX
         FTLGbW8r6fGvziahLoxDMRK5WqyPEe9huxPUPLYE2Mtk5pNPLreQIrs/Vi662ONk61vK
         CEVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JVdoH+HtTmoH3qjrgq1hcBg/K4ODJ/Nx+6pSqTxUUFM=;
        b=NfP96jQbE79lpu1ozUV5ISQzmmrk960lYJyP5XLludTgw6ELIejcd9nsH8OdqTVbmo
         ZKwvRuJ6FCotPchS22wERVK7CpYxuZgdC46xlgmxAonvaT/mGKJKiw2ry+kA+dkRhDYu
         AMt68VzVq4NjYRsANoXdjxFGCbLWdANQl6oYoy3sipAbT7C7NkMqHgYgnFplbFlhmSpB
         detKYK6Rvq5mWMbCqoVU1sSdEsAZPMig06j15NkxsJCf9h/dL9mIE4wLipCAqPteerBX
         7Zxuc7IIw6pm6COe0QA+IId4abiYgiU9PJAGQ4vJun85r5eDDdnAut2QDOm7c2+cAwg+
         RawA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=i1vncFC7;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JVdoH+HtTmoH3qjrgq1hcBg/K4ODJ/Nx+6pSqTxUUFM=;
        b=IdmmO8VqbQPLps3euUpUm75XR6lCOv7i0LNo9qrZiXN0GrGzX6tu1/f+MrZrr/JXKm
         qhW+A5Nxq+DXZJyBi1CBCgdrASeUdJGUBHUsAlR0IcSCGch9vdyRrfrOnyXHXLQoXj21
         8Xx/COBWgqGMjKYD4Xfnzid4v7LJ4hbKBWhZndIe+nt83Zm+pKYXaDlk54Tnnjk3PUzX
         1/srj8DWi9cyTzZgqzpbCyWU0vWW+GBPdEQhdXmIf6bfGszcNdxHDxzQAwqhSaYU2nf7
         veClvBPPD0yms6KiWejmw5U3To1XxMeofSVR18TDONL6BnxhNg809/q2ni1KKQqbb/vf
         BQmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JVdoH+HtTmoH3qjrgq1hcBg/K4ODJ/Nx+6pSqTxUUFM=;
        b=XW2W1qS9QTx4kGuRtbdRo4YdGO3d/ktMNbBO0iBKkBzdmLZ1nk0a4uP0aQc6oGtWQD
         OtF6jO29PFu2yjK/fJZ142nCQ7J7s6hT3NTKD8I8VNbILLUNfhLuDsfP3I/o/9kalxj0
         hIl0tIsdmJ0Xn8LDYg3fF40qRP6uzftqL5ojg44NtDHnKMaXECK/jH+WqdmG5VmpAPFr
         wkJYfXG9eQmPr8wxwZRd2CLUkFRl/tuPkIXaj+q616vyl8l23F/2aUfphMtGW0JUTJZn
         l4+Ej4WCAEtUriWSzcxiydwEhqkKG5Glq+KC/I6759YhXfiQrEM5EHWvN2fMBgyvuhrf
         XKxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RobEaz60WgOeQ+pLk0PCmLP7tkA5qpZyKYJP+u6n2/Iw164BB
	sNzJ5mCQAkw42x5j18n1hWA=
X-Google-Smtp-Source: ABdhPJw7BA42fCYHZ/wRcVGdgCdGs2W0330shllrfZOq+zmXzTv0eZ5nKZShtbP9ukUAggIZVN1JUQ==
X-Received: by 2002:adf:d1c4:0:b0:210:18e6:7eb8 with SMTP id b4-20020adfd1c4000000b0021018e67eb8mr2101144wrd.462.1653651449029;
        Fri, 27 May 2022 04:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9c:b0:393:ef44:c49d with SMTP id
 bg28-20020a05600c3c9c00b00393ef44c49dls5834011wmb.2.canary-gmail; Fri, 27 May
 2022 04:37:27 -0700 (PDT)
X-Received: by 2002:a05:600c:1547:b0:394:882a:3b5 with SMTP id f7-20020a05600c154700b00394882a03b5mr6634782wmg.97.1653651447678;
        Fri, 27 May 2022 04:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653651447; cv=none;
        d=google.com; s=arc-20160816;
        b=koUJ0F8M0ogHWah44MA8rM4IeSlFkryxGaa3AOopBDT8jKBoE8fRYKZykP0gRv+NE1
         pTHpAEEP7ZBZITxllirmWXJ5OdctJFAxTs8spZ7nk24miEWnkUfW4cIod4NYolwbYPHM
         4wTj+S8B52lswd1uI8zFXfjDW8jAgbNuP5JFKn1aOjQcN2lXkMjEfXtzGEcxgGiaOfuk
         q99tc8raYWLdOKOcRwZyUWXjvVlI/OexvKfpY2dwqrdr8PLks4Xfec0wLSnRaovHWTCO
         WfQRLhzjUenQBVOrftdxSnNCVZEa1ZFA5uYtuTX3Lgb/H1K98ZT253lejsZE976+s6Uq
         i9Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=+hHq1dpI0VYa05+VLZiztmS29cD052lJCNPI3wyITqE=;
        b=dM++msMZa5Y4Hyf8Usu2/MAxB9F0xTHXgY5DfpzQkBYjX3XdIQoKr1QMO+nQOVoHqL
         hVqrgmQvPPjZrobUwPi6t60WuQZuTRaJ6jS1IirLzd3BUptCM4LbGeLWp+OXY/1y+W4w
         JUksjRrReGUd+zbJbZEKeriIRCW4txeS23Ttk+IUh7c4fnWnKnz4AmEkh6wI1ILvAF2I
         NtLe3VPARX4HgHIKxwKSc08FAhaUoSSIW3lyFrj7muUfGWAr7Zirji622487HYZqqZIz
         fnHlvRwyZBLRXR48kYvx8eOKcSuF4TLiX2B38WKS5wxPf5M3707Q5/kMRvpj2fQUJ4eF
         wotA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=i1vncFC7;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id l2-20020a05600c2cc200b003943e39b255si99355wmc.0.2022.05.27.04.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 04:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 511E6219B3;
	Fri, 27 May 2022 11:37:27 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 33947139C4;
	Fri, 27 May 2022 11:37:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +UYTDPe3kGKQDgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 27 May 2022 11:37:27 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [RFC PATCH 0/1] stackdepot hash table autosizing
Date: Fri, 27 May 2022 13:37:05 +0200
Message-Id: <20220527113706.24870-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=i1vncFC7;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

in response to Linus [1] I have been looking a bit into using
rhashtables in stackdepot, as stackdepot is gaining new users and the
config option-based static hash table size becomes unwieldy.

With rhashtables it would just scale fully automatically, and we could
also consider creating separate stackdepot instances (including own
rhashtable) for each user, as each will have a distinct set of stack
trackes to store, so there's no benefit of storing them together.

However, AFAIU stackdepot was initially created for KASAN, and is
sometimes called from restricted contexts, i.e. via
kasan_record_aux_stack_noalloc() where it avoids allocations, and it's
also why stackdepot uses raw_spin_lock.

rhashtable offloads allocations to a kthread, so that's fine, but uses
non-raw spinlock, so that would be a problem for some of the stackdepot
contexts. It also uses RCU read lock, while some of
kasan_record_aux_stack_noalloc() callsites are in the RCU implementation
code, so that could be also an issue (haven't investigated it in detail).

For the SLUB_DEBUG context specifically, rhashtable uses kmalloc() and
variants, so there's potential recursion issue. While it's expected
those allocations will eventually become large enough to be passed to
kmalloc_large() and avoid slab, we would have to make sure all of them
do.

So my impression is that we could convert some stackdepot users to
rhashtable, but not all. So maybe we could create a second stackdepot
API for those, but KASAN would have to use the original one anyway. As
such it makes sense to me to improve the existing API to replace the
problematic CONFIG_STACK_HASH_ORDER with something that is also not
resizable on the fly, but doesn't require build-time configuration
anymore, and picks automatically a size depending on the system memory
size. Hence I'm proposing the following patch, regardless of whether
we proceed with rhashtables for the other stackdepot users.

Vlastimil

[1] https://lore.kernel.org/all/CAHk-=wjC5nS+fnf6EzRD9yQRJApAhxx7gRB87ZV+pAWo9oVrTg@mail.gmail.com/

Vlastimil Babka (1):
  lib/stackdepot: replace CONFIG_STACK_HASH_ORDER with automatic sizing

 lib/Kconfig      |  9 ---------
 lib/stackdepot.c | 47 ++++++++++++++++++++++++++++++++++++-----------
 2 files changed, 36 insertions(+), 20 deletions(-)

-- 
2.36.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527113706.24870-1-vbabka%40suse.cz.
