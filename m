Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXWTXCVQMGQETX5C26Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80790803E74
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Dec 2023 20:34:56 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58dc2d926e7sf6805364eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Dec 2023 11:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701718495; cv=pass;
        d=google.com; s=arc-20160816;
        b=iOWHuzOWkPT4w0C5QmV07/ZVKogGSC9lw+WfdOzsZWz3Iy9wVwwWvB2ag6A0dc8X1l
         /d5dTby+kgJgXiy13HZ0g6IpXNOFJmOf2qQ8ILTss4nO9Xa87EXvXNtnLZVyGtxynM0g
         bM3Lw/QxOzPdwPP805l8jQg7vSHxHVhGVTjE0qViJlBB3xNnHPzE0jOSdFo18IFB2Ayu
         Np9qhNIitFYsLb9+E0QaGjOfF3JSiwg64nQCkNeXDpDVhEyvvkyn/uSskJqpTCDMig9k
         7GlXhSHkcWVVGRJHtTlq7NC7JV3SozAHDR5PjT5Wba1aRdYuH9T3p6BUarmfTovNrNjE
         ZyEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=PQjvyyA1KnsHo+7qcdwiyrGbzTHxVjzPoFu3oDE+eTw=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=CfUVqsLkbFHIBgM30hBHGYu37pvke0/4nDiv1dja4nCc2FhgMfBi84xQMzQT9uW5ec
         pW5cNAY2qQ4TzUewUEGLITOc50yeyNlp1a/CJVvPU4p0X5NwwmwtqqC7W4Qz744ChntK
         8mX61Y0oUJ33LAlMrReSweAj4bC/KvbwlFInlNHM/nBwsGb/IVqw+mR6JWrpPJc2ullJ
         /Q7L155Cf26lY3EeEKoMJ4sxXkk6VL83FR94Fa98+xBvg1bjNWtOY4ZW4P1Lt2x6dGMK
         LzmPo0fgwSVvZZq0MQRG4XB92hfsTjNMEyGOx8i809UI99YRsBrUgWQb//yPcc6NMp/M
         2cyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701718495; x=1702323295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PQjvyyA1KnsHo+7qcdwiyrGbzTHxVjzPoFu3oDE+eTw=;
        b=Fsg2DS5eeX9NjNFQ8hX3wPb8Ep9Efcjpf3OOr7H/uihv70xl1hR3U8JqC2YSd3E8Zl
         ZvcZkEmZ/MrtkR+74Jp9ZQhM1/uSu3JRnK2XxR7TOLPhRixwbOIHvBq60MLKsrQieuK3
         MQQ5BUFZKlncZc4vPVTgIRkq7Rlz0s2du/fHsNsyT3VZWzbrCtHWWPiRsyCqrmjBGA2d
         kbLJ8Eh6iBN8cEDe0955ovTYpgq8rVG+pquZ+OzHOct5sVgjFZusCihj7GVTgOZW0lSr
         SOoAYulNSoDVFzzsJgFAcb6s7C8o8UJDyUUkHZql2PebcLDERSM34PtlF5s81eWevMzX
         7LWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701718495; x=1702323295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PQjvyyA1KnsHo+7qcdwiyrGbzTHxVjzPoFu3oDE+eTw=;
        b=pLP8i16pNpi6ENgHa4HsAShffpP9jME5nmjD3s0eIIe/xqXEnLM0kPIO1sBRXP9aYR
         FTr/S0tkhvU91KJ3JoO9K1KsY7pDz3rK32gxvRe5Tx8IU4iYaxIS+t53CHB+BoFQwg8X
         XqjjJQizLzBRwy33DhaFAaFF490u69+uzdkBWMsNJ6FhGRfi3+kkJ5TwTad5UTkw/2qL
         LN3dAEa4Vd9D48r19KHZR9pCKhXIbLxqa6jhOPGcAFVQcvtdMuAZ6fkmKU659mFzVuBQ
         Y0YZxKbC/23RQyCRMwjrNZph1EGgFbd8YoVFWp9BD2KqO/u55DdkQDNvR8YJzqHKywAh
         ky5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzjPZzx2vs75css/W2Z7VBBwwazZd/XBon0whL+nzUjAErXVSuk
	Ct5MNDOWG9NEs0tQetFc874=
X-Google-Smtp-Source: AGHT+IFAF3ckB9ANFmobE8rScWHKC93tNsx93MHro/AtVjOegdna7xLhk2RFsKoP7J7Ttg+8hJH+6Q==
X-Received: by 2002:a05:6820:60f:b0:58d:c4b0:15ab with SMTP id e15-20020a056820060f00b0058dc4b015abmr3774194oow.9.1701718495075;
        Mon, 04 Dec 2023 11:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ba92:0:b0:58f:7a18:580 with SMTP id d18-20020a4aba92000000b0058f7a180580ls2044805oop.0.-pod-prod-07-us;
 Mon, 04 Dec 2023 11:34:54 -0800 (PST)
X-Received: by 2002:a05:6820:1c9a:b0:58d:974b:504b with SMTP id ct26-20020a0568201c9a00b0058d974b504bmr4184346oob.7.1701718494382;
        Mon, 04 Dec 2023 11:34:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701718494; cv=none;
        d=google.com; s=arc-20160816;
        b=S3+3bcXdTUF1puXMM2Eu6iolx18oJLE9hzSHqq68a4c4SYhWPf8t6xHl5Ph2NhTrz0
         dvVwmbGHKyxIRD68+bXpus0gTshxtlMbTVleZ5qN4T0hVQ+2ZVKtxg2oqSPnxUY/Fdk1
         sn9fYGKth3Db9KcZNzlOK1UlCY6P+vKyy8C1t7YyMVbat8LDyzAsH3KNKJKHa0JSWG/T
         Jco6/z6LYVgh2SxMn/k+jJs2ZMg4L9k9FQIY9n854Lmc2mXzvYdarG6qtIYMl9HRS52E
         io063Pw4zk4tPYFd64jInDNRNXP6vkYaolgisNIf2l2vLYk5u8OZS8DMp+Y5MC7BQA6K
         xojg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from;
        bh=aZT4XXToznx+yNKftkZu4IjQ3/65or5OU6hVajERaWU=;
        fh=QGaHzSWEdTlyx4gN2Cp05xyAuU2J2OcL//unbyREezU=;
        b=WUvPhr7RaCKRSrryHTmtab22XGgS4q27SXm4UMZSkITKLfXC7ZglVlYp+GGd1tjcbS
         TgcIHPMJ1gWEqL4OLrGPKdhP5fjyF97shSzMpUpY3SyYH6J+9JBV4vwa+QD+cLgQiNkE
         Rvcm/4Yg3gKXL/TXDwOJIoJiHh/MJTYlb0xB1YGi0SIrTKXT9VsElOBh3lrT3Pxc4fWJ
         6buFRIUjboWHEz5zjHhtC3GCevABRbn+aP6mn1Z03Y3hONLa1v0mGiMmza/aHzvMNGum
         cs44Jo88xA+T9/+FVP0kgyrQknOniyqODsUEOwcjG2AVc9GDMh/voWq4/BbjOHc988mi
         DkBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id o17-20020a056820041100b0058e2b7a8d82si335869oou.0.2023.12.04.11.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 11:34:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7748F1FE6D;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 53667139AA;
	Mon,  4 Dec 2023 19:34:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id x9KfE9wpbmUPMwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 04 Dec 2023 19:34:52 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 0/4] SLUB: cleanup hook processing
Date: Mon, 04 Dec 2023 20:34:39 +0100
Message-Id: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAM8pbmUC/x3MQQqAIBBA0avErBtIyxZdJVqYjTkUGg5FEN09a
 fkW/z8glJkEhuqBTBcLp1ig6gpcsHEl5KUYdKNbpZsOZT9ndDvZeB4YUtoEvfGmU622vXJQwiO
 T5/ufjtP7fnAR5D9kAAAA
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: ********
X-Spamd-Bar: ++++++++
X-Rspamd-Server: rspamd2
X-Spamd-Result: default: False [8.39 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 ARC_NA(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 BAYES_HAM(-0.00)[38.82%];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 8.39
X-Rspamd-Queue-Id: 7748F1FE6D
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

This is a spin-off of preparatory patches from the percpu array series
[1] as they are IMHO useful on their own and simple enough to target
6.8, while the percpu array is still a RFC.

To avoid non-trivial conflict, the series is also rebased on top of the
SLAB removal branch. [2]

[1] https://lore.kernel.org/all/20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz/
[2] https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab.git/log/?h=slab/for-6.8/slab-removal

---
Vlastimil Babka (4):
      mm/slub: fix bulk alloc and free stats
      mm/slub: introduce __kmem_cache_free_bulk() without free hooks
      mm/slub: handle bulk and single object freeing separately
      mm/slub: free KFENCE objects in slab_free_hook()

 mm/slub.c | 109 +++++++++++++++++++++++++++++++++++++++++---------------------
 1 file changed, 73 insertions(+), 36 deletions(-)
---
base-commit: 4a38e93b3a7e6669c44929fed918b1494e902dd7
change-id: 20231204-slub-cleanup-hooks-f5f54132a61c

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5%40suse.cz.
