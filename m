Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB4UPSWFQMGQEZ7GDFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AEB06429FE8
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 10:31:47 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id v2-20020ac25582000000b003fd1c161a31sf14507276lfg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 01:31:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634027506; cv=pass;
        d=google.com; s=arc-20160816;
        b=TtpHgYWMfGa8zdKI3L3sfVDacQgoY5DrKI1L/cwqrma3M1ZXR21G2qjg3IHa/7Jqvz
         GF0CF6tsukIxr+4e+4Um5P5YZzUyx/warNPvIEYKsbOfwYGQXlhdcdjWMPMFmli8Pm/x
         OsfRtqN+zf5Mc2CyUs8L+y0kolo/t8h1SzAKhrzWcQY0yeu10h5I5VIkQ37/JYnnmLvr
         mtMugPlHdHCHQFMtKoXamPzYzcVs+h3sWD+Aw21AN22Ir364IZnscCVFjjbQCuBaLUis
         lJYOzYNBfmsKstjJ3BhRnCxplGGd8skm8Fd/dx9iutq5LvjyC6Rk7uHYOzZQeGS685La
         +VDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=L4bI6v0VN/Y/P5IDkrj9vw82uO692Q7zr9g50pfdMcE=;
        b=WPgyNn/07ySt1CjdAMOn+pE/6xeYIVqnahSQ/NK9BQhGE6gzois/+SS4Y8dgL9qJFi
         N5RI0g+aAABSbAed4+kI40FotBNqnCkIFts08/a3ip2JjcgmuMxXgOF0j9IYaxO3r7or
         4ZnFE8IV78m88+hE0tn0U/kQA6ttdD4cs0B42HMnMcbj7Tdgzgqn9PXiJdAR3BdQM1he
         uF9rLFZCztlmlewHxoxJj6ez710H2b17lMIF0Gv7AWBvnk/7jEH72HQ9GjYWPE9MDh93
         AwD5CuRkMor287mCGM5zJHrVxHp0VWniM1jePF9iJCRBBNoFbXqlHxV1/8DOWG3mfQn5
         PA3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GBFKzyqP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L4bI6v0VN/Y/P5IDkrj9vw82uO692Q7zr9g50pfdMcE=;
        b=HA3rNmnl1FyrtWPHq4QfvDVldZ1B/kaZy4gO/hxsXknyXuHzGEsM1Jjt7LBfue14OQ
         nlzXdA+yG0gduUHt0U3gQgZ8tOg1zfK+HhTv3Z1QYOCgZmAmqD/BC+DnAhaZjNjljkU7
         KFCCOqlRlnTuhpYyQSq9AVgjNJ/GSIOpViCWeC4lukNx20AnyRIeF9GTowiFB44iLoPo
         37+j6p2C+T0EUIPh4vkWOpmnCEshmBSTHPC7H6zsUOXBRshAgbGS6lEOOPrECUq35GRh
         2uxudxXqgtPodZrtILCNHBx875Y8W7a6IxS296S+i3ljG7MJDOwqc5PsNTib7PwyuKvC
         ZZtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L4bI6v0VN/Y/P5IDkrj9vw82uO692Q7zr9g50pfdMcE=;
        b=6sU6qvg7RqaHYUWn4HophFQow64T1XRgd8r+xJDwVKyT6p7mlmkbHYs9p9zgj0BLWI
         BnYnVzorBkgvo7OyVpzsIjl3s/+VSU5pnALjiDdeSO8IH8uqfw5+bngMd0Fa1SD/q+1K
         FB7i8dW8GxdmbLOelzfDKoy5pHTyfJZUuscEQByOvU+v2HSb0tKe3bn4IEKp85/dUiRx
         rOGIuhAuTStUDn1sCYIB0vuCwh74UvMegxmVFFM2QIKaNRlw4OpRuk6gIEnX6am/2KGt
         IfXL2kM22DC1Eq9NjSgLhfbBqgO/CfpPCB0oYHH3R0wPs5v8v+mX7KxB6rwAXxDQ4oBr
         GIuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303/LBPrR3soadij0oRuSTXEnnuZJKdu74e5UiBtIZpEboL+WmY
	jkG5eZqMJSFOyytxrYcVzmU=
X-Google-Smtp-Source: ABdhPJxlQZOCsEI89eTWZUYieT1R7T/oerxESTS+h1TCRi+u9/BzTLoc0HE+fdTZLqbkE14wq9om3g==
X-Received: by 2002:a05:651c:1505:: with SMTP id e5mr5298574ljf.308.1634027506202;
        Tue, 12 Oct 2021 01:31:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3994:: with SMTP id j20ls1974830lfu.3.gmail; Tue,
 12 Oct 2021 01:31:45 -0700 (PDT)
X-Received: by 2002:a05:6512:2346:: with SMTP id p6mr31517592lfu.214.1634027505221;
        Tue, 12 Oct 2021 01:31:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634027505; cv=none;
        d=google.com; s=arc-20160816;
        b=oFx7kCkp1UvEHVmK8ygDVawpWwGoMMZ564CNeBi7qafLO7SwQy3eiJ1BamEZziFYIs
         EocreOm7fbtCzntsXB4V614mFdqOarxbBZWQLPMp898JH+J29rRULvmLiwd1T8TF+2hN
         cOUrAw/HiVehDWdM/YKGn3ZmGTbFW5O5x0sh5F9KMYx8klpfhDrxPzhD1ziTk4vhr6Pk
         Zqu2t/ELDN8FD+vMQEHa7zxo2asa/cJEqi0/cJy1eFo592xvOy+fKk58jFeffZAvBrqP
         CfmlDAVg1E3TRHHB4A08GKEoEd+Fr09OEdVzTBWkas/Vd6EuIVjTtKujRGOMEFkgJGsb
         mZiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=jzhciBvqQ0vTMCmMY7ans9eWDLkjdIgrfHAs17HgGQk=;
        b=Pbh7x23myYC4VZGWJWY09P6ev6so0tBND/Qkm4zYS00Jpeh/KE/q1bESF0tm70EZT6
         CQYcdoiq5pdBhnwA8PFWaGvbE0/WqgE3dI6QbGComJBNqd82Cj4fk0tkAJCNfHk6VeqU
         0mosa7wunzYlT/8puCx3juhgOiiP62qdN7BFhGafI2lUoFrGHecnr7VD7PorX4wolLWo
         w+hUICwMXFd/jaM1LIu9frqE6Xqrxc5Q05MZT+BayiTAETIQQV6npRpnRH1u3LUUixj2
         55lxlt8HsMyLRZ663KLUfeTHlzKWLAMhxdCTgRiI+vrBPBwX2i6XQcBik/NoCGGiKiCI
         wWhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GBFKzyqP;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id m18si11820ljg.7.2021.10.12.01.31.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Oct 2021 01:31:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 79F0220189;
	Tue, 12 Oct 2021 08:31:44 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E7E8613AD5;
	Tue, 12 Oct 2021 08:31:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +SDwN+9HZWFCSwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 12 Oct 2021 08:31:43 +0000
Message-ID: <f4f9c5b8-7bff-4d5d-8768-5e58ee1cc907@suse.cz>
Date: Tue, 12 Oct 2021 10:31:43 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org,
 intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com,
 Vijayanand Jitta <vjitta@codeaurora.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>, Oliver Glitta
 <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>
References: <20211007095815.3563-1-vbabka@suse.cz>
 <YV7TnygBLdHJjmRW@elver.google.com>
 <2a62971d-467f-f354-caac-2b5ecf258e3c@suse.cz>
 <CANpmjNP4U9a5HFoRt=HLHpUCNiR5v82ia++wfRCezTY1TpR9RA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNP4U9a5HFoRt=HLHpUCNiR5v82ia++wfRCezTY1TpR9RA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=GBFKzyqP;       dkim=neutral
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

On 10/11/21 19:08, Marco Elver wrote:
> On Mon, 11 Oct 2021 at 19:02, Vlastimil Babka <vbabka@suse.cz> wrote:
> [...]
>> > On the other hand, the lazy initialization mode you're introducing
>> > requires an explicit stack_depot_init() call somewhere and isn't as
>> > straightforward as before.
>> >
>> > Not sure what is best. My intuition tells me STACKDEPOT_LAZY_INIT would
>> > be safer as it's a deliberate opt-in to the lazy initialization
>> > behaviour.
>>
>> I think it should be fine with ALWAYS_INIT. There are not many stackdepot
>> users being added, and anyone developing a new one will very quickly find
>> out if they forget to call stack_depot_init()?
> 
> I think that's fine.
> 
>> > Preferences?
>> >
>> > [...]
>> >> --- a/drivers/gpu/drm/drm_mm.c
>> >> +++ b/drivers/gpu/drm/drm_mm.c
>> >> @@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
>> >>      add_hole(&mm->head_node);
>> >>
>> >>      mm->scan_active = 0;
>> >> +
>> >> +#ifdef CONFIG_DRM_DEBUG_MM
>> >> +    stack_depot_init();
>> >> +#endif
>> >
>> > DRM_DEBUG_MM implies STACKDEPOT. Not sure what is more readable to drm
>> > maintainers, but perhaps it'd be nicer to avoid the #ifdef here, and
>> > instead just keep the no-op version of stack_depot_init() in
>> > <linux/stackdepot.h>. I don't have a strong preference.
>>
>> Hm, but in case STACKDEPOT is also selected by something else (e.g.
>> CONFIG_PAGE_OWNER) which uses lazy init but isn't enabled on boot, then
>> without #ifdef CONFIG_DRM_DEBUG_MM above, this code would call a
>> stack_depot_init() (that's not a no-op) even in case it's not going to be
>> using it, so not what we want to achieve.
>> But it could be changed to use IS_ENABLED() if that's preferred by DRM folks.
> 
> You're right -- but I'll leave this to DRM folks.

Ah, the file only includes stackdepot.h in a #ifdef CONFIG_DRM_DEBUG_MM
section so I will keep the #ifdef here for a minimal change, unless
requested otherwise.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4f9c5b8-7bff-4d5d-8768-5e58ee1cc907%40suse.cz.
