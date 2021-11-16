Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBPF2Z6GAMGQEUICY6CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B32145378A
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 17:33:01 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id b23-20020a0565120b9700b00403a044bfcdsf7268123lfv.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 08:33:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637080381; cv=pass;
        d=google.com; s=arc-20160816;
        b=QsxOC5F1puT1jJanGDML2r6uVzUI8lY5GB9tFClLwzSRFJ6f3B/Ufvs0VbxfcuZ5y/
         FkDN3k/bwvWmUE/TpS0ui3o3+NzHAJDp4pC+uWdRPfuMQoTn9csTsJoLs5v35dYkMa6+
         1sL3mMB52ORYU0Nc1ZWSCWyk4iGx2qoCI3SoaHTEraa7e6Bd6SUnN6UtR7/daprF+Prq
         Eghl+t6qLRwTrbOnchQcQE91Zp2BH8QCRB6u0bUErO4XQYYTgUdIctBmVpw0DHsC1E8O
         lTd7owRU7oHa3e/vzZilVarJZ/fDaN+76fipKFkUme97H0USfWbzCqEVQZ3pzINmxUUO
         1Zeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=lCCrj/Hsl8Wi1AfDH5oQ1yg8f3Z5793DijCm6zskz0o=;
        b=QE+YhCxRtHUxQ5gbotU4InIgM5VKEwrhEqIAUEQCA178JW6Q0iFva/nApl2TgcJnHA
         8JFz2+CQsDkF3jJ+FRH+gkZu3dGAQjuXVmeVtc/83etHjluZMlZmrkyRSetiJc8XUZkd
         crNWImydjJ9cBUFW4VCeypDJ6Qo9V6E2Sl9wkQ44EaIn+M9cZbAmOJhYpeH5mheHI0n1
         ExLLzNsQaMN0qpagiL3PFLfG5IOdPFxw3LNf57Bo+N6kCr/wJDL59P4C+pJusA691yco
         /pREPYJiTqkrClvLD3fYcpUPXiWUiPOy2XDqit1t4VPyW3MGWa+VUXKD13cKwThx5y54
         rPfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MijUyi88;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JKrI4zxY;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lCCrj/Hsl8Wi1AfDH5oQ1yg8f3Z5793DijCm6zskz0o=;
        b=H2y8FBRxTAj8c4iID/GmsqwTRNJpYxa0xgP4ViHEykhWy1D/KYGktjkAo3tpYGK7l0
         0S7WL6US6r7/fRYLssIB9sr7XmgsKN8Hpst3CzFhFSElBRJpTBebpzLYtr6mDcdyd2Nh
         ez4FGhlRPAzCjl4MdTZK2bVHFbDh5m8W0JeKi0HzPqYaweO3BiVgP7glNcgnyXWYCP4k
         zRk8YXfWgkKnRPbcJNKGX3nYR3uvTvA87SMKwJdyi83vremZwWErQVnbAnMFafmo8YE9
         Fl5XAlYnMJ0Fhmvd1cY0xqYtQ94KhJhLC1WbDkpoZBO/k1GkdA4IRcNMibfSEqZdndVU
         bVEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lCCrj/Hsl8Wi1AfDH5oQ1yg8f3Z5793DijCm6zskz0o=;
        b=V+N0Er6gL1HPbY6lm8j69d638/zgrwAfG5RsR+UjACN/cOZ0Klsp/K+cFwieH2ESwq
         RpLAQ1s3i8MdzR/0ajIAXLWmlZ8+NYXqPJfH/orG0S5MW8OmqLTfrCrZREcnZp2/4roq
         NgruOWTd/6hwBKdedqpkIt9V332KALcRB7QOeiW6OXbQ/iFaJdo9RD25rXwmeE3Qaxcs
         HSCYg33U2YIdqvxpudfYLwbrHPIIFfUa7CFqYx+j32elvcI70AnpkPS21aFZij8iNqCp
         +W/LHJlgernOpBvMdnqleEGDWp27e+AhBBGQYZ5jZcoFgfcRexqUB1RWF37MLCN9gUE/
         Nx9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qehgdfueCiXDwDbDV8w6Psvc+kcB0rQ4DAqi98DZWRAXmjEhU
	VKZzxOf933UpIGBrFMA2sfc=
X-Google-Smtp-Source: ABdhPJwDwFDqHQsNHFpZuM7FWXV/a9yB369zK2S2pxE3UXt3x9kkKxYalGaBKdYADpuauqFEgmV2Sw==
X-Received: by 2002:a05:651c:1a4:: with SMTP id c4mr456961ljn.3.1637080380844;
        Tue, 16 Nov 2021 08:33:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:178b:: with SMTP id bn11ls2957679ljb.7.gmail; Tue,
 16 Nov 2021 08:32:59 -0800 (PST)
X-Received: by 2002:a2e:b8d0:: with SMTP id s16mr459971ljp.496.1637080379718;
        Tue, 16 Nov 2021 08:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637080379; cv=none;
        d=google.com; s=arc-20160816;
        b=cAoabM7G55E/7DSiIgpEbrtfK6g/qoaXvetmvd0xEU/PsBde8r+0OMaqGBgq3GYmF/
         qkU88JUik67uDq2Z76S+jlxPh8XDK39398nh6ofPos85k5mGHQQSTiHH1uEMecUfXV7o
         Wu2c7eCkkFI51p2wr6EWDQ6IFf2Ax7uVt0ZSL0DT2RhrizG3XLy60qj6UfOBkkIQgqY3
         oqWkcqIUqTo/xXL8WyTv74JP3AhJGjaJUtHRSXmFlxD0Dyf8ebs/2+o4wVNPPjykGIzq
         Atd/tBf+X1wbyFYQeHdEjw5kEdiLKdK6RQJb8HK1viYTH6qTCxeIsl4xB8RKP22rNL0u
         0JSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=IdNHsSJ0TUD00V1kkWXYSG/GlAFO0QPXtO8TfYkofSY=;
        b=KPmHO1/idD0v1/5HSd/AG5bXTcxxtBV2/QP/eg7vfNmcU0k+JTuJaMQynScA3jjq+N
         S0ZC0diK/nqhbuCtb3oJVhbwuqhFTiT2ypQ4g8mVETx+O6UQhqAeVGZfFSRTVjBkhYJC
         m5mG0QBNlrJ/UG8vkMru7L7bxI62+W9ehgWbMevDXXwg5bMv5j5+jDDpdo455Ho95s41
         02ezLmHxP6Vnes9pcedBkSO6p5pT0jWPZl4uld2brZjLXxGLgPXeIjg955Oj6PpalreV
         fPIJ4pZw7i13mJUymh424+9cNVeoSV1Ih9nEkV3fTK89b32mxf6Z2T2P04UK1G+HzJa0
         rMJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MijUyi88;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JKrI4zxY;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id o25si1211989lfo.9.2021.11.16.08.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 08:32:59 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E8EF91FD37;
	Tue, 16 Nov 2021 16:32:58 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 7CC0313C25;
	Tue, 16 Nov 2021 16:32:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id i4pYHDrdk2FtUQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 16:32:58 +0000
Message-ID: <6866ad09-f765-0e8b-4821-8dbdc6d0f24e@suse.cz>
Date: Tue, 16 Nov 2021 17:32:58 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.1
Subject: Re: [RFC PATCH 21/32] mm: Convert struct page to struct slab in
 functions used by other subsystems
Content-Language: en-US
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Matthew Wilcox <willy@infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Pekka Enberg <penberg@kernel.org>,
 Julia Lawall <julia.lawall@inria.fr>, Luis Chamberlain <mcgrof@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Vladimir Davydov <vdavydov.dev@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, cgroups@vger.kernel.org
References: <20211116001628.24216-1-vbabka@suse.cz>
 <20211116001628.24216-22-vbabka@suse.cz>
 <CA+fCnZd_39cEvP+ktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CA+fCnZd_39cEvP+ktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=MijUyi88;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=JKrI4zxY;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/16/21 15:02, Andrey Konovalov wrote:
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
>>
>>         if (page && PageSlab(page)) {
>>                 struct kmem_cache *cache = page->slab_cache;
>> -               void *object = nearest_obj(cache, page, addr);
>> +               void *object = nearest_obj(cache, page_slab(page),      addr);
> 
> The tab before addr should be a space. checkpatch should probably report this.

Good catch, thanks. Note the tab is there already before this patch, it just
happened to appear identical to a single space before.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6866ad09-f765-0e8b-4821-8dbdc6d0f24e%40suse.cz.
