Return-Path: <kasan-dev+bncBDXYDPH3S4OBBR5U2OXAMGQEGQUX3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B2CB85C1E2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 17:58:48 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40e435a606asf35918645e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 08:58:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708448328; cv=pass;
        d=google.com; s=arc-20160816;
        b=cuf+g9TbqFjlkxqBRxEwIRc0eaVRC48tPT8HZsqnW0XN7sWCr/LpeOSg0Y80U9YMyj
         6ZsND9JSFHldUboYOedL2EIpE1t9Jy79j4dtrn5ej5Ur9nTdgFUW6IrBxhVqvBdZydzG
         is6XHUXpkNKH1I5k2dWLeQfKg0mgWsPXmUUcei7dGcxvLT1IzsZtFWh0sX16nQleu2jk
         /mLfMNT/c7WfOtPoLPzCyj8p12eSi56gGf0Tx53vaEoMtCNxjF7S6Azgp4+lHpH62NUa
         7Rq+kf3lPotdJw4AoZ4jm5GLDQSHGxsYec5GvSfnVIDetu3kfLn6raloNGt9xFIcmar9
         v37A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=PifOxcW/lbnTZi7qamzYVflXFTNFB8UKzDwfJW1vBxQ=;
        fh=eWFClYG6jyltvkx5xaYC9EhUn5SsiU2IeUjlQqnxOfM=;
        b=wK1P3Fb8eObLG5adRjGY7l4fNH7Jzddi+a/Hv3rwV6j0B94HI51SPeMtXCgeGAXqQs
         07p+PTRIjJ+HKSztU8Td78mQtcZDNMX+s9RGkADkmlzxCkAWyF7v9vBYr0iWk1l3dDV1
         IPG071I3mrq1enYZuU78xz365LRNU1S2gZeSaSMaUPfXpW+HSy05HhbATT3JNMk6zoxJ
         Ra1kKDCyj+19bRV/rtzII5mCg7mEG24KjAt0SqKD8D+++2NH+4vlFzGCk9F72YEjyAzc
         qdMkGKnhv6VW/SCqWEENpZZGVc3XXBx+oXJbC0VIVVrLfkcNP8crYlQo4IyJIcdzOzPZ
         w2NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708448328; x=1709053128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PifOxcW/lbnTZi7qamzYVflXFTNFB8UKzDwfJW1vBxQ=;
        b=dfBd+BC4vmOr3yKGJO7iGVQeeTNAR/0dCIpZtBOTI+6VOdVrJWqOlxU4p7l0n1+YDM
         2eHbsG31k2puQZ8oAbnpXSw9e3Q+bxj8/+56LoJ5HxX7T9Klnq9ow2/B0UfVrrIVzrqo
         FXwwL/C85lanGOZdwW/QQ57fOls3q12CljMbw3P3R8sSINXiwUmzL2OgAw9GO1g8/hyi
         G2PzzHk2tDqV39+xC6NGyZ5/uzRi3m40LRZFVzZDsYh7pcy/4Rvv97RsXfreSZHfkR7J
         gl6C9Rp3p6OIyGKmN0BQogmma8kCy3LWjUFtpchGQdOjbFrbD8nvntyKPAb0CiDpShWJ
         PCuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708448328; x=1709053128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PifOxcW/lbnTZi7qamzYVflXFTNFB8UKzDwfJW1vBxQ=;
        b=oQoOx5JWkp8uLMoWNlimEAkdpimyCNHBL1jxPtEJvt/WkTGhg2UQWcGYjvj81eBX2R
         XScxqyKEVlhj+Fbk+AdfBBRnv8Zhv+37IwyVw+vO7sNi5JgqcYxa7BtwxUnady5E6c8h
         LziT6iqcnej406k6B0//HJjgNgbUZ44yOb7nAtdhZetYGMjbJ7FDT02G45EpmOFNBBup
         7m7eRhz/q0Vw2HPc0M5bei4cHy32t3HoYwsTXWZPYuF/Pb4p8o4VP/PCdTvBwedU3gLc
         NCBn2iF+OwZfwq5hmCzaXYbuobd+GeSI2irbvp8VWgXroRdwNEDqkMjFB8SAcTdvoEOc
         9DIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUla5e5Ry7bKMq88QXrj1VQ3eOxOWL/COTLIPQR13l0LuR/lpsBwBG83RPvI168nouE0TqDxR47QOzUSGuLHAJiHnPNEzaw/g==
X-Gm-Message-State: AOJu0Yys8gW1n+6G3BNiW0k2mLUg5ZX/Qes0g4cAdXaYEJlPO/tH++Ga
	BWcCsiBQpeUiiiCVel/o0vKQl9+3mhJHyF1pLoiicD789ugek/KY
X-Google-Smtp-Source: AGHT+IEidTy1wdndQ6vyA5BKvSJ7vU2HzgAfpCvX4Y19llkWykU03YbF4hVy6KQOjavDJYbqw3HQ/g==
X-Received: by 2002:a05:600c:4584:b0:411:d620:26bd with SMTP id r4-20020a05600c458400b00411d62026bdmr11352348wmo.17.1708448327727;
        Tue, 20 Feb 2024 08:58:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e85:b0:412:689a:1c33 with SMTP id
 be5-20020a05600c1e8500b00412689a1c33ls908725wmb.0.-pod-prod-09-eu; Tue, 20
 Feb 2024 08:58:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzzBo9llAkWP85cOmFfNihLacIWvGakRc1LKFSgJd59Oiiiv6Qq/ax4znfUyFShSqgKqHsRu2FMumwr0sy3aSMeOLC+lJlwfGsJg==
X-Received: by 2002:a05:600c:1384:b0:410:c128:2bed with SMTP id u4-20020a05600c138400b00410c1282bedmr11947741wmf.20.1708448325601;
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708448325; cv=none;
        d=google.com; s=arc-20160816;
        b=BUkyYYYpQecIpd4aKjE4pCAV2TkSItCiBR6Ng8Tn+WBlzn+b4rt3OttznglJ90SuIv
         vMPY1Jw1vht4Jyj+LuPRiwWDUWQZ1+ydrlr3qv8acomA7HSeSQlzX5D9/BxY3MKsR+Cf
         ijjl8J4HRhbsAWPEhgnP+X9gZH7LqiZIGezBmBwRh3nuG7B1w99a1AS+Y0Sckhh+qp0f
         b75mm+eYrhWhIOg4t+0T5jqLoa35JxEWCeNlutimmZWhWNN49YMH4E2gp0IVMcpXXBfm
         PrSJC7HmQhgzWShvENmtLPVuDhyJHrKyW+a0JKlbEwAbiEZqpwuBlysNYlmcB4gPomSg
         HDnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=IbsSj4kPNKqeufwtGIRDxU3H/ANejP0NGaedjXyeBmw=;
        fh=H+kigXjdCOVpCxcHPaVg6SgkIx4KR669HTfmciEICLo=;
        b=bAohsvFy1RqoBZotjEbFYIRxGOsX352x3sLvfvkkgh0RiMogShFa4JGcj+o3kYEuKr
         dCVSLyAP/NxkL4bvNSTLmjMdKtaaH96OqsBK9Ln1ew3Pmx9/rN8lq0XmAUDRddD/Ju9p
         8eBxylmXfHkKbURs/CE0lDe4+MWh+pKHctL0NuNAjCLVI76NlqejtqEH3NTUn8oXRBwf
         o/kpf/2bQ9it19oZ5SvwXO5OeJ1+VXtjLwYrXyzoXSS6jRPib0jgfAHpuEsHbBL9Vxzg
         RAxYAeok9VDSS5PveTvv+LkcjgY5HiGIqFmIB5Ll2NQEauUXxC+znDvpODBXcPe0N+Zs
         k66g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id n12-20020a05600c500c00b004126e2da65csi140832wmr.2.2024.02.20.08.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 08:58:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1F2AE1F45F;
	Tue, 20 Feb 2024 16:58:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EC4FD139D0;
	Tue, 20 Feb 2024 16:58:44 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id w9cGOUTa1GVKXQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 20 Feb 2024 16:58:44 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 0/3] cleanup of SLAB_ flags
Date: Tue, 20 Feb 2024 17:58:24 +0100
Message-Id: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIADDa1GUC/x3MMQqAMAxA0atIZgO2VFGvIg41Rg2UKg2KIN7d4
 viG/x9QTsIKffFA4ktU9phhygJo83FllDkbbGVdZU2HGvyEFNjH88Al+FWR2sY5UzNRy5DDI/E
 i9z8dxvf9AAO1YOtkAAAA
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
X-Developer-Signature: v=1; a=openpgp-sha256; l=1607; i=vbabka@suse.cz;
 h=from:subject:message-id; bh=IL6IiPFaj8L1SHxsifDq30uFwnNpt+3POqEQFoB3w0c=;
 b=owEBbQGS/pANAwAIAbvgsHXSRYiaAcsmYgBl1No4DszrrX8bOb0HuwiWoDUq2/UBLf1izr1zC
 ofjfOXIfueJATMEAAEIAB0WIQR7u8hBFZkjSJZITfG74LB10kWImgUCZdTaOAAKCRC74LB10kWI
 mtb4B/9PLg3CcTI1ueE6xDEvkINOsywJ7L7b+M9ykvZu7hP6O09Z/ODodo42j2o18006IrzeLM9
 ag2Hea+OS2X0SZncBYIUydENSmTMdmaI3hrW9oVadH0sKZb/Qme3icKO4fA/HIomAgPOOsKtFmE
 CgkjqAg4gH4fDyXCMsE0h7MkFmzK/MWB9X3uunAR+2BQ7LQxvy7Tqx01bDiVwkYTNVyms4hkHqv
 x0Ih7n/T+W3OIM3GL9rgJ0opFSSsFyfVDrrzWPwfKjOgpAlDhiRcroCYFTW/agKdeoDMNY0CE6f
 Lq3obltIVTB/uCWeakaSxiv9BEpNMyUQlvAKxTZtsw483eXT
X-Developer-Key: i=vbabka@suse.cz; a=openpgp;
 fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Spam-Level: 
X-Spam-Score: 0.20
X-Spamd-Result: default: False [0.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[20];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nMby2dQa;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
Vlastimil Babka (3):
      mm, slab: deprecate SLAB_MEM_SPREAD flag
      mm, slab: use an enum to define SLAB_ cache creation flags
      mm, slab, kasan: replace kasan_never_merge() with SLAB_NO_MERGE

 include/linux/kasan.h |  6 ----
 include/linux/slab.h  | 86 +++++++++++++++++++++++++++++++++++++--------------
 mm/kasan/generic.c    | 16 +++-------
 mm/slab.h             |  1 -
 mm/slab_common.c      |  2 +-
 mm/slub.c             |  6 ++--
 6 files changed, 71 insertions(+), 46 deletions(-)
---
base-commit: 6613476e225e090cc9aad49be7fa504e290dd33d
change-id: 20240219-slab-cleanup-flags-c864415ecc8e

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240220-slab-cleanup-flags-v1-0-e657e373944a%40suse.cz.
