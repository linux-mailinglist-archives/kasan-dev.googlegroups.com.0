Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHOH4OXAMGQEVKMTKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id A53D8861B8E
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 19:27:42 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-412557adc00sf3050455e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 10:27:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708712862; cv=pass;
        d=google.com; s=arc-20160816;
        b=d+cc7XnRT4z6/LxF8gwO1Zc1B/6jsWT35i8vQIAQUCOyOIWvd+fxMJa/wzCy5c2NnS
         /ULx6kw7qKm2NlXKOv2EcesWzBT2aPTuUU4n98RKqBJjj3flgISepDHHyoPepysHmPly
         fwZDqeTgE1O854t6T7XfoWfxnsMuMxtYnKFkZZF1xTPHGpOJ2M2uLvuzPkecWCfmjyVn
         NlIYvlwd3S/9/k6JcqQOXGHvpzMlTd4ERwac1coKN9uiSLG7DuR9k9rreAkBTnmr4VXX
         ahvP6PQ+2Q16oyWJl7ndohfoXqjXjBx341BXS5nOhAUejrGrPUGN9JuzjSSOS3uE8hew
         h3Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=JlqzPEr53rPqI6uk9qJ6eDn35AuqVmBdqqr+tgFd8XY=;
        fh=zYfEGq6Txmwl4D4c8kz3WWmrZKH9X4ksXc2jg6AT1GE=;
        b=vl7iLrlEko3aNe989tSuWjdqkUe9OheUIsZvRTqel5MxhKgyXRypacZW92a+oPSe3f
         kB8lK3c7X3dx8etR234d3grP6xAxoI64XZo44eCqpOrKgDM4Wm5HzuQI5wTFrZkeJBCE
         KA2wSvgBL1HwG7Clt5f2mBqabGiTQpMIAT85XRhqR21iWzdBYpFptzZztw5EwvMTDfgp
         pNRSA/nlQ+vy8P+wDvLQWULQaatKmUkyTVLG1eBqelJxnB5juF8/GkFKpMk2wdj9g2gH
         HNhQUnUmGTFcicnuAzcE6TzcF6rfvjeXzGUOQXFv6qVUhKg13wuqreB+nkxDOyguuz/H
         fdLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=w0RTxYkq;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708712862; x=1709317662; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JlqzPEr53rPqI6uk9qJ6eDn35AuqVmBdqqr+tgFd8XY=;
        b=oebFLytWjYpfEGJ1VzcVWozVu67ZqynWB/yIgtmWf2zHTQ5XbCUZ/b2BtPEAvtdIqh
         mjV2SUOtL/PuSJFzeYZjuZxV400HgsvQKfvQE5YIISfEkqQbImiaPhXBfmuN08ZRXZkv
         7hqv8lgctZBcyF+dbE1wWUzTyDDkWXfHSdgrwZNkq2pcuJOSMvr8/Zx4hug/2ur/Fasb
         EbmrSqBdHgc2PMyIEARduEsBJKsELY1axjIwRkQfqrzWU+YTSCsPEOQuHeLU98uPZAFi
         tGoyUZt0fkWka/Z8IX2YxDQ71U8FO5y3UOx17dujg3YkfeF5cEPxkwvaZV28aam2n22d
         WRCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708712862; x=1709317662;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JlqzPEr53rPqI6uk9qJ6eDn35AuqVmBdqqr+tgFd8XY=;
        b=w3chOi++ZjW/DpjTcjQ+TnVM8VagW5x+P0Vc7AUfLeCGV15tO/HBQNcvC3rPctjYRA
         ylgck+ADN5bmR/Lm4OUsHETYqaHnyfECOg2/x939r73nyg7/Qus/HtM6uhK/nzHW8LA5
         xk3fOu/FcCjk7P4GBvY2Cc/+vFr4rt2AeXc8YVsLgi56zWbvOauVk8Xp37ZMvCbH1ChJ
         inY27c9VEdc82Tw8CmAxWNbAqODZboqi6QfLk7AKW4AqZF+F9YA+kp28WF2B+Oo749de
         EQU2GbGJM7zLsESvJcuc/Z47uxGIItXSNjGKgVDWn29AMAjnLu7FHh1gktMvPMgd6gYz
         oqHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3RlLNj9xEp/PqXHFo1zMLC1VrDDIvO2Ymz2IFwc6rPOdGn3rRUbNAoBkG+MJn7E76IuQexbmH+q4/7b5sY91Nf4lL3MoDiQ==
X-Gm-Message-State: AOJu0Yz25JKmdKdzxTW60AUOs/FG1ECg8u44psQYKQ4Nv9KUr8Zf17v+
	HYtn/Ge/z6uxfo6dl1c9648j5P5gw7uogFbWDIZE/cicNLkMJa5G
X-Google-Smtp-Source: AGHT+IEnsQkq+rtnDHXYNOeb9VO2khRBOgOS4UNWa+XQwjHGBaAnO+4BwSCEs5UyqfYRequwIAzh6Q==
X-Received: by 2002:a05:600c:a04:b0:40f:c404:e2d1 with SMTP id z4-20020a05600c0a0400b0040fc404e2d1mr375483wmp.19.1708712861606;
        Fri, 23 Feb 2024 10:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e85:b0:412:8e11:9b64 with SMTP id
 be5-20020a05600c1e8500b004128e119b64ls479949wmb.0.-pod-prod-08-eu; Fri, 23
 Feb 2024 10:27:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUf8TZk/gUlayBJo8IBQ7A+mm0oLxM0XRexvnz6MfuB6QIa0SM1Bg7/5o7ErGDbTGDSQgtG0dL4hi+2k+t1IVBC556mDk1uihSHeQ==
X-Received: by 2002:a05:600c:4592:b0:410:deab:96bf with SMTP id r18-20020a05600c459200b00410deab96bfmr474706wmo.22.1708712859715;
        Fri, 23 Feb 2024 10:27:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708712859; cv=none;
        d=google.com; s=arc-20160816;
        b=mcl5j8TVrLZN07HNKkkUsy0guj7jUYAmeRrgb5mSe4NIJJeGZtn9Aros4xwjVd8Ha9
         HDSwWvj2K1+E+YItLlGUIotU7uwBW8Rjot72AC3tjNYvF1+tyx9DHf2RNVMahd/7nRN/
         nxF7sJM40snCANFo1ESdf6nTYhMfhYrOfx7rGkRh3LS+ovjewnsopxjNNbKTRRfNz+Wu
         oSSCJSjmNyl371EO9GleP9fHTw1CgJ+kg0rhPynsMeDVlBsw7gbVFZiOW43a22DV+QFi
         3IVEWklJ3kFOWPCCCTMrBYhxQUuKbdXB1EYQw0wibl+eRzKu8selVEHb7x/JeaXHUxZT
         GSoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=jFPvU6fb5RZSwRXjaHsGExL2vu2XY+R4lmvjGVLfKDA=;
        fh=H+kigXjdCOVpCxcHPaVg6SgkIx4KR669HTfmciEICLo=;
        b=OEJkroX6iTanGEhnp+YWkGEeFif55T+ilBS47U8+sLS4immMRU1rz01V/Fn86+hOxw
         VT2dcOi8+UabgQtDoIXUJnL80P+YJE9GJ+COWYkeEDbwx53zD3jW5/BERdEkGYXNx517
         cxcUIAxHkcChEHdGnK7tQNJk2zpiTinfwV8AlIBNgo8oKF8nvTX/EAoMiHj/ZD/jrPar
         /hYGipQ4NnCEvkE67qT/vOgfJvz6QOlcV4+ISPjsjjWEplAtDm6Gr5g6nlR0nyH5TteK
         l+J4QJXLomxAjeYeUuzgE8rvTgJ7um0RxzGCFDC2cEPP1LnDkyuO0PL/cjd/QkDY9XPA
         cwvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=w0RTxYkq;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id c40-20020a05600c4a2800b004127b4d36f1si122845wmp.0.2024.02.23.10.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 10:27:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 039261FC26;
	Fri, 23 Feb 2024 18:27:39 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CBEDE133DC;
	Fri, 23 Feb 2024 18:27:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id zj5DMZrj2GUaTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 18:27:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH v2 0/3] cleanup of SLAB_ flags
Date: Fri, 23 Feb 2024 19:27:16 +0100
Message-Id: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAIXj2GUC/22Nyw6CMBBFf4XM2jFtKc+V/2FY1DpAE1JIRxqV8
 O9W4tLlOck9dwOm4IihzTYIFB272SdQpwzsaPxA6O6JQQmlhZIN8mRuaCcyfl2wn8zAaOtSa1m
 QtTVBGi6Bevc8otcu8ej4MYfX8RHl1/5ySvzLRYkCqSwqyqu80dpceGU62zd0+75/ANpg8i6yA
 AAA
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>, 
 Xiongwei Song <xiongwei.song@windriver.com>, 
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>, Steven Rostedt <rostedt@goodmis.org>
X-Mailer: b4 0.13.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1960; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=XEJyJuE3iDgp5Yng6UletIUmKt9m1Y+5GGOt7cPegGw=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl2OOPG1gBtDkksy5t20lOzP2N4CSXyxrsDwd0s
 01QGR/m+zCJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdjjjwAKCRC74LB10kWI
 mmavB/9y5AI6D6IRww4XMiiwjjYlhMmza4+TL9mAHyfVi8XpuIwqg006twc5K90zh55wDZTaOMV
 5x2bQLz3DZ8wXClbIqMwagmHpF2COF6dhzwEPi2sYkklX+d1vWOafBnlw0oA+wNbl3Wb059yLog
 TbRNeQ1TyL1AVvyvYt+Ad2EqZNpwdPhc/ejFwHhqlZrpMkRH/GXRNOT6xfTnsZg8uFc84q/kDSH
 50sbJijMHg56BIQrZ77wlMEX+EX2c8zmFm7r8Ij14CR5zBNHudZ0y+EbwZBneWYQx+/Wrzocvf8
 K1ZPa0fBU96x0wOYdNb8eg/g24hvX4ekw5rDFhHwTp+wFv6p
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-1.51 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[20];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:104:10:150:64:97:from];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -1.51
X-Rspamd-Queue-Id: 039261FC26
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=2pgIZN7M;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=w0RTxYkq;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

This started by the report that SLAB_MEM_SPREAD flag is dead (Patch 1).
Then in the alloc profiling series we realized it's too easy to reuse an
existing SLAB_ flag's value when defining a new one, by mistake.
Thus let the compiler do that for us via a new helper enum (Patch 2).
When checking if more flags are dead or could be removed, didn't spot
any, but found out the SLAB_KASAN handling of preventing cache merging
can be simplified since we now have an explicit SLAB_NO_MERGE (Patch 3).

The SLAB_MEM_SPREAD flag is now marked as unused and for removal, and
has a value of 0 so it's a no-op. Patches to remove its usage can/will
be submitted to respective subsystems independently of this series - the
flag is already dead as of v6.8-rc1 with SLAB removed. The removal of
dead cpuset_do_slab_mem_spread() code can also be submitted
independently.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
Changes in v2:
- Collect R-b, T-b (thanks!)
- Unify all disabled flags's value to a sparse-happy zero with a new macro (lkp/sparse).
- Rename __SF_BIT to __SLAB_FLAG_BIT (Roman Gushchin)
- Rewrod kasan_cache_create() comment (Andrey Konovalov)
- Link to v1: https://lore.kernel.org/r/20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz

---
Vlastimil Babka (3):
      mm, slab: deprecate SLAB_MEM_SPREAD flag
      mm, slab: use an enum to define SLAB_ cache creation flags
      mm, slab, kasan: replace kasan_never_merge() with SLAB_NO_MERGE

 include/linux/kasan.h |  6 ----
 include/linux/slab.h  | 97 ++++++++++++++++++++++++++++++++++++---------------
 mm/kasan/generic.c    | 22 ++++--------
 mm/slab.h             |  1 -
 mm/slab_common.c      |  2 +-
 mm/slub.c             |  6 ++--
 6 files changed, 79 insertions(+), 55 deletions(-)
---
base-commit: 6613476e225e090cc9aad49be7fa504e290dd33d
change-id: 20240219-slab-cleanup-flags-c864415ecc8e

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240223-slab-cleanup-flags-v2-0-02f1753e8303%40suse.cz.
