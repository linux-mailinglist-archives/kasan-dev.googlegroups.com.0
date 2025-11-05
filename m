Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXVGVTEAMGQECPTDWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D6181C34AC4
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 10:05:35 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59427b2fe85sf382980e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 01:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762333535; cv=pass;
        d=google.com; s=arc-20240605;
        b=C8V+zbMuWeIxduQGiLxrcE0j8PqzHRNuY/URGSJ4Iu0SFrSiF0gLI6HI5s5hS8Jj+T
         rchqv/DwoFAb2Xj6Q5yBTeIAM6N1InYyywUSFnbLc81EPXCA6ma8aGFTenqhleFk+uUN
         MjVzL8Zs1A46W1Spyr6+eoP2OMjYImk4gBMNatvvT0uQ6E7OVAoNUututUEIVaBCOkc9
         r8pOk93tv+t0fPG1YVAY3zUcQ7VGDAxafyMA9qek0fFcyp8t7txlez19fOorV53MZhY4
         OvwWpQvU44Gvdg5hAnHp/KmshVK04qFHyFfNyC9GEb+1Lea/TDtsCReEuILUJwTEhE/x
         6JZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=Rxnj31ieS6nWzbrgDW/kWDfxXc3BOxQwofToZGyMMz0=;
        fh=giBneKeXTlNMgA1vf3XVLWXWxvs9Dw7GFGhSTRdNbVI=;
        b=gA8/V+iipBGgVJ1DGfJuNfKPkdKAnm04OVohdLlyEdkiaDkWthf1ETQBm2kSSh8C/H
         JKa/uP4h7hLDOB0OTW6Ud5yNqFxkZ66LDfsvzYYw2ybCCCkH53u0ECrovow2GotUHDYc
         3CYwVyYIGwXHza48Z52wiu/wlu7DQ4KoZ/ybb2+/VnM3IFpRB1jEkVYchdGbffMjwEXW
         N+Yf/CsdKP/4uxiKvy9WIivf044Rne9Y+JrMIrgs+RMO0vNfSxSYgNrbfL3eX6UkiPCU
         ewKmp9tLJ5n84WyWkjMiPyXXh3Cyo+7rwsvoWhBQIEx5VnUjBCV31N1qMG8pNc0iRdZi
         iunA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1uXJvNXZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1uXJvNXZ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762333535; x=1762938335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Rxnj31ieS6nWzbrgDW/kWDfxXc3BOxQwofToZGyMMz0=;
        b=NHGNpwAgybnH8ZVL5KaJarbBcAXZQmZLX+PFMQEoeqYM0SMh+JNZ6cJ+q5czNX+AaZ
         WG4aBJ9RNnxnqDC+zTVM5ket106bkPRoysewq+GjT+uVrl+zZGzWwXw6HLlwkxqqIXcH
         ddt2aeFiCPw4i3Qrtwsou8r1ZmNBpz8oGlfIDqOfzODoLEaa+1xVgCsaVcKAWS7RzRXT
         m5F0XB1XIvrbox9uDUI/BJfdUerhLB5xJfFvKeYPxjlyR6qkaCpqX5N7q5vqPMHtlHU+
         0BBaWe+02m7Mdp2Sk7Mm8a89QbVFvZ688BZ/6JI3a2qxctW5LKJCUimgVk/RbE619L7O
         r0pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762333535; x=1762938335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rxnj31ieS6nWzbrgDW/kWDfxXc3BOxQwofToZGyMMz0=;
        b=KQRKZFU9Ovd2VYsjC7ohcK50zZaSlnzgSqHtfknCrYTg0JUHJ4ysU43tka24coZoJz
         vjTqmFBFeeHyZu0fn3kBFNvlPYxw1M95cKKhd2+gQrWsIvJc0rRITWtEmQt8knzMmCUL
         QWblG1JH3PdJAyIGkZXQ1PmKaExy3PSsmtqw1UiX0GPC+i4a2JO3Da2GqV/bg8XT5XK4
         JjaEzhovcl+ppCCtxATWlncnZwGWltGmk6tlcf3gat6e9Lj89SQ96OW2qIMEM7AQPOfE
         a8ah3eVcbBAw+lt8M/xGMHlXp52t3H5iyMA3Ie2AHV0yuLAr/H4AmDbnKVXlVoSi3iNb
         KdDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUw99Al9Xsw23fJeQghZcC3+K2juG+N98xT7pjPBDpFVifrsSpplNQp2reIaKqhW6FUSWPMpQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZitowPMCISoXGKOgQxmYPn0yv4rzXHmi5C1i4rZGYwOsouBkp
	L1rSqpNxXRyR/bOOqxPyIahAipSKHZYbQ93lLky0KmgcLBzqh8ype+c8
X-Google-Smtp-Source: AGHT+IGweZFlptS55/MClwDalaa7m9B2gUwIMZzc0QQ0A63UVqs5guji3YR/Ex27zYc0HUCzWPB0yQ==
X-Received: by 2002:a05:6512:3d03:b0:594:2c42:abd4 with SMTP id 2adb3069b0e04-5943cbf0a09mr754763e87.5.1762333534718;
        Wed, 05 Nov 2025 01:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YsM6qSNrlhI6ecMqChR6jooIHyiXAQ4jOMN1L5jSYllw=="
Received: by 2002:ac2:47eb:0:b0:594:2d37:7fd2 with SMTP id 2adb3069b0e04-5943d26c580ls98351e87.0.-pod-prod-00-eu;
 Wed, 05 Nov 2025 01:05:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXSr5S7NeV4OCkfFz0TaOZkLHHoJbEc3CAiCzV92A5vaPf7c8F7Gs4bwrKY4nxoO66zXIdE0cuD7Ow=@googlegroups.com
X-Received: by 2002:a05:6512:3d14:b0:594:3271:44e6 with SMTP id 2adb3069b0e04-5943491cf46mr2038311e87.22.1762333531755;
        Wed, 05 Nov 2025 01:05:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762333531; cv=none;
        d=google.com; s=arc-20240605;
        b=OLp8LIVhLUxDDl4+fltbfqFPdMffr6x14GILAIyDmYZQPghwqp3X2dKoKQA1O5RSiH
         bGHCj0xMB0BXQtPaPQkneBHKLOxPalwCP9W8vFxN0SYlnqExZiOLx5uyTYfXKnMRC+f8
         y8d8AYpZr9h5U2UQosVngZ5WQGOa0ePN4eoVZiPqykZeSglLXKCTDAdoaTGV9p5OlY14
         0zeUTGzU9qvFGWw1MTHQ03Yq7cimI6Frpkmm90k8YMXUlyeWO7x7p1yA5z35cvpIK+go
         pHrHwOsYpb2ylia7FW5hV31gqd0Eo06rrXa//y9wFcnvqUR2FrmTCVQOIXk8IQe4DLB2
         E4JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=s7exJ7wPrvcdkgXiFEjvbZXYLs/HVJlgsx8rLBAN5tA=;
        fh=0VZDZxBGXWy41l171YBh+BdY6cJG+AzAPMWnSIJmIok=;
        b=Ez+rIlgVhqOyLtBiTYFodRRIJDSVD7li9aDXsXxsBjjfRkcjZ6tGCTfoWybw7vo77c
         hCi++ohKjl2wD/P63rAcC483VptFgzHG1aLVvlo78XHKs3YhvHtbTGrHNL4q21fm0/zr
         2YQ02ViY+WKjKYUoFqpIBleYRw+6Iw7Qf/5Y8+wlxmaNEAtwQUVN52dLpGGliCATIUcN
         0thXEevTMB8u1Jzh+BZpa18d8TreeSgPUpFYZHhI8wQWN1BpJMVmPlaYHBndFMJmeg63
         m9WAGMjYGNTpEJyySn6pJWbltLpTYOM64JSf8wPOVQZsNdN4jACjyLjgfMdpgFQ5W03H
         C8Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1uXJvNXZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1uXJvNXZ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-594344dbd11si109754e87.6.2025.11.05.01.05.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Nov 2025 01:05:31 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 93B981F451;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6EBB8132DD;
	Wed,  5 Nov 2025 09:05:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tOG2GloTC2lSBAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 05 Nov 2025 09:05:30 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 0/5] slab: preparatory cleanups before adding sheaves to
 all caches
Date: Wed, 05 Nov 2025 10:05:28 +0100
Message-Id: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAFgTC2kC/x3MTQqAIBBA4avErBM0sr+rRAvRsQbCwiEJxLsnL
 b/FexkYIyHD0mSImIjpChWqbcAeJuwoyFVDJzutlNSCDzQJWdgTTXhuFrqfvB9GJ+fZQc3uiJ7
 ef7lupXzrHx/cYgAAAA==
X-Change-ID: 20251105-sheaves-cleanups-548ff67d099d
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, bpf@vger.kernel.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>
X-Mailer: b4 0.14.3
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 93B981F451
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,suse.cz:email,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Score: -4.51
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1uXJvNXZ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=1uXJvNXZ;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

These patches are separated from the RFC [1] since that needs more work
and 6.19 would be unrelistic for the whole series at this point. This
subset should be safe to land, improve the codebase on its own and make
the followup smaller.

Patch "slab: make __slab_free() more clear" is a new one based on review
of one of the RFC patches where __slab_free() was found rather tricky.

Git branch: https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=b4/sheaves-cleanups

[1] https://patch.msgid.link/20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
Vlastimil Babka (5):
      slab: make __slab_free() more clear
      slab: move kfence_alloc() out of internal bulk alloc
      slab: handle pfmemalloc slabs properly with sheaves
      slub: remove CONFIG_SLUB_TINY specific code paths
      slab: prevent recursive kmalloc() in alloc_empty_sheaf()

 include/linux/gfp_types.h |   6 -
 mm/slab.h                 |   2 -
 mm/slub.c                 | 318 ++++++++++++++++++++++++----------------------
 3 files changed, 166 insertions(+), 160 deletions(-)
---
base-commit: 136fe0cba6aca506f116f7cbd41ce1891d17fa85
change-id: 20251105-sheaves-cleanups-548ff67d099d

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251105-sheaves-cleanups-v1-0-b8218e1ac7ef%40suse.cz.
