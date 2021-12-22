Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBEFSRWHAMGQE3DCLRWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 40E2E47D586
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 17:57:53 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id c5-20020a1c3505000000b00345c92c27c6sf1071370wma.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 08:57:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640192273; cv=pass;
        d=google.com; s=arc-20160816;
        b=hAyGWZ6DZ+EbkgL7QvZei7Inzhy1EyQbcibv3rJbaDM4/pddClbgS33bbCUIP1dlJP
         tLXjEyPc+/V2wpPkQGLVy5h0CkjqisvqncMhxhP3CF+GmSh0Z3EoTr8iHp2b+/Poh/m4
         oZKg+ssqW/Q0NQBHFcBXEhNnV9bx9ZW4HM2cF8mkoQLsGBEkpeRBkHUaa8RUXmpZDSgn
         l2wEw33KX/L95ujdJ9KGPGL33aI8cV5T81vzL/Y6GWVN7KklmqpzeT4u53pIYOobtJy1
         Eb6OPE5XdsGm8etrWEXZVTLjHsySIa3M9cP8HIN33DU7Za5ae4mDwgqy+LeeDQESCJ/Q
         +aCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ZseFExkSVVla6CByPHJqF68sPc0/N609qdunLMGYX5Y=;
        b=ts0a8Ci8RAH/0mxttLcrifQv90SyBerG59yqwPnUzhyK6XSXue/NV/xpc1XHDU/C3r
         EfdgHc08VDGLvUAzhR8y2givawkkiSTNiBQ+OMMVgfAaIF4p3LCH6dCx3ZDz6AjO3UnK
         nKPng37Rr0QxXhIZNJi+0iKLjUnZkO5QSh5OFC3EOyBgV2skO69e1Io/M0PspeLlNA/8
         tP/u7W/otAeS7jYu8v9PKAjSPtKiUTBRm93395cfJxkmp40NkXGRXzZmS/emDneCJ2zC
         0r1CPBIOL2dpoRJ/OMW9+7JtCMdJjI1ds/eRaGyoFX5kLd/YzQvEYkCuQC3ze4G7x5G8
         fe9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CDFZD6sc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:from:to:cc:references:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZseFExkSVVla6CByPHJqF68sPc0/N609qdunLMGYX5Y=;
        b=bLQ/OINI0+6PjQUocE16Q+kI/SAwUR8am8xsaIQBNTiJZBpHF5zoMbwk/pWYjsIGiM
         H4tQmXEzhTnJfyECMNBmTyZIPtcSu1CJScgGNI25Y95PDGYXHRKZQl0rehxsvNPsbi4b
         BVS8qJj+DlLgHaVqMEoRIPNZdSNn5ElG10oW2vy5Ylo/I/JSeDVMQOMsWXFLuXqo0X4f
         UgY2pQ/if52cvh+wcFlfM0gkB7Auv0c13zxYUaHIZvcHFMzGtjtfBpNWwwfHNKatCb5z
         ykJJCraqKemhgQVzCzjjws87fpV3nBfzJGX8oYOUqctf23LCpE6FKJtSPewes+814+aV
         bWAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:from:to:cc:references:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZseFExkSVVla6CByPHJqF68sPc0/N609qdunLMGYX5Y=;
        b=i/5TJwuAS/TTN+d4V8FzQ0cLITOE76HeM+n1mmV5vaPph6ZvtpwXh1M1hsi0muGFbD
         lks0GMjhiXqE3iWaltTthr1ACwneYtlqh/f0T5DC5h6/1ND/gvYIMmjmUeiigKRqN29X
         D3wPv/PpJwhBU0eelbhl/GprftvVhJsTM5BwM9kJrlSmjKbH7stBlOuh41dKw+OM9EFH
         b23RepUZJXMewLEVNl2WO7VNdp+SCJj6L5WbpWT+zhwnaMztkuNhdZuwzikp4amYD1X3
         0cJuQbeD+F/Scpy5XHExdgSVG8yXF8RpK9AoR9WSAasNst76SmOOd6mid3rJRAZ9/85O
         qx1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zlXE1JIPe9rTNomk9uJyPfQBdDp7xq0aHaLtToqW2tbvK8gzg
	Np/vmUCuHKHRTlYk7opO5HI=
X-Google-Smtp-Source: ABdhPJxGNai0VJf7u5g4yzjbYEt/DaYT84qWkPPojX6HgI1PiDZpzuHLBauk9AMwhbp9SWdgyLzdVw==
X-Received: by 2002:a05:600c:5024:: with SMTP id n36mr1525814wmr.154.1640192272874;
        Wed, 22 Dec 2021 08:57:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1042285wrb.2.gmail; Wed, 22 Dec
 2021 08:57:51 -0800 (PST)
X-Received: by 2002:a05:6000:1acd:: with SMTP id i13mr2583619wry.652.1640192271865;
        Wed, 22 Dec 2021 08:57:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640192271; cv=none;
        d=google.com; s=arc-20160816;
        b=K8p4L4Nn1AjrY6qB3NZl93eO5+gLC8UwBknbfjlTMau4hir+r6xze7X5bySG5R5Jht
         JUltZ12Zupw8y/Fih/sidxJhIwUaj7VpcgRG3n7Xf0kghEbQszzq524UMcTPJzd+oY7N
         Gg6ukD3ipXDj8zW1B8eNoRVfQSp2wXA+Fhq+LIY+qB906nO/Fx3XfwMoyhIG16U0Fgtv
         4LJsyiSJdgo/k7O2Zu6oiXONMmftO8hWd70RUP9TLbBdO0/iCVnCFAyunN7Hl7sDZN/q
         gJkg3hd+/H161S8fUhWsxxY5WFL6Uy7Id2yQhL2ywNuwnUsqLFGoyr4x57I3YlUiJg0c
         6JBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=QOgLrQeLTYXFsk2cNqehMzvGapHl59pV5Owm/dhArOw=;
        b=CiCQJqUNLXJhOtE7G3i291GyBGnhxaVSVUKboxgBTPXvuRp/VZC6LrpWHYkNzvWPJ9
         /AsV6KPUydrV+iM8Q/AUEuYdYvuGduSZJpYGysL6xTTbeWTMFMvanFSBmjIGnHg82FdM
         AIdFxNUHGGVH2sgytItTbV8y6aiPzmksoy2TYGaxZ0UfCqOC/ueBYW6o8JNcy+CPdNZW
         2wRM6I1L2h2BCGJs/C0CblCb/SU0VH68tx5lkgIeGnL24apeaj7bW1wAstIRmIcHtP4D
         Mz+SW/U0BQjDe+03CtocZnou2IAbwUe0+eBLs0lLKj5iDCYQ3/Rollhqpv2OOGWLbyVn
         l2RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CDFZD6sc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id p22si298498wms.1.2021.12.22.08.57.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Dec 2021 08:57:51 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6984B1F38E;
	Wed, 22 Dec 2021 16:57:51 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 403CA13D3A;
	Wed, 22 Dec 2021 16:57:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 5a3EDQ5Zw2HbJwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 22 Dec 2021 16:57:50 +0000
Message-ID: <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
Date: Wed, 22 Dec 2021 17:56:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>
Cc: linux-mm@kvack.org, Andrew Morton <akpm@linux-foundation.org>,
 patches@lists.linux.dev, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andy Lutomirski <luto@kernel.org>,
 Borislav Petkov <bp@alien8.de>, cgroups@vger.kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Woodhouse <dwmw2@infradead.org>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Julia Lawall <julia.lawall@inria.fr>,
 kasan-dev@googlegroups.com, Lu Baolu <baolu.lu@linux.intel.com>,
 Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>,
 Michal Hocko <mhocko@kernel.org>, Minchan Kim <minchan@kernel.org>,
 Nitin Gupta <ngupta@vflare.org>, Peter Zijlstra <peterz@infradead.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
 Thomas Gleixner <tglx@linutronix.de>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, Will Deacon <will@kernel.org>,
 x86@kernel.org, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <guro@fb.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
In-Reply-To: <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CDFZD6sc;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted
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

On 12/14/21 13:57, Vlastimil Babka wrote:
> On 12/1/21 19:14, Vlastimil Babka wrote:
>> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>> this cover letter.
>>
>> Series also available in git, based on 5.16-rc3:
>> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> 
> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:

Hi, I've pushed another update branch slab-struct_slab-v4r1, and also to
-next. I've shortened git commit log lines to make checkpatch happier,
so no range-diff as it would be too long. I believe it would be useless
spam to post the whole series now, shortly before xmas, so I will do it
at rc8 time, to hopefully collect remaining reviews. But if anyone wants
a mailed version, I can do that.

Changes in v4:
- rebase to 5.16-rc6 to avoid a conflict with mainline
- collect acks/reviews/tested-by from Johannes, Roman, Hyeonggon Yoo -
thanks!
- in patch "mm/slub: Convert detached_freelist to use a struct slab"
renamed free_nonslab_page() to free_large_kmalloc() and use folio there,
as suggested by Roman
- in "mm/memcg: Convert slab objcgs from struct page to struct slab"
change one caller of slab_objcgs_check() to slab_objcgs() as suggested
by Johannes, realize the other caller should be also changed, and remove
slab_objcgs_check() completely.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f3a83708-3f3c-a634-7bee-dcfcaaa7f36e%40suse.cz.
