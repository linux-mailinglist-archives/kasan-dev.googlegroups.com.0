Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZXZ2GXQMGQEAH25RCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C807987D17A
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 17:52:55 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-513b0d4e38esf2222281e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 09:52:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710521575; cv=pass;
        d=google.com; s=arc-20160816;
        b=WU5Hk7BYI/kwQvi6H/FeYm6GXp9POU4LSPAZontj03J6ZzGzBHB4mOVB6FH4FfAKfk
         TSmMHDphd1HEEafVGtLLcKVl5M0+pMOPvnmXGuDssbxJKL8QrSdLBUC0i0GRL7du+P5e
         aGpkjyh6/Zt7h8OuxJQ3ELCpvYCfkfifvQ9AWvVs1cxqIRae0ICkiAunmPglihYpIcIC
         /CU04V/Q9wA5lwLCet5EizjK+HXJq47ArWkI2X+hqF7dt99WYg/YP/aXCnHYln5pr5pT
         GDW+3kskOOVo53EkxiFD8ATEXsZqZn43xjGmr76lUt6wiYQPReycmwtKnjjdmaYhMBQg
         d0Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=v/LL8owdApL/XZLKD2e0O0nTWbH0aAGxrt7Xawmsw1o=;
        fh=Gv6ydQXM/JuMMLbiz5HeX3vOaLADUz0MaWYpvs8Yr9M=;
        b=JH2CyYD2mani9a798Ks+69541FMrGVNCj2+tg+DYI9vip+cRR4J8ZNqDXF+Gl4NMzv
         ssoynp0qtCCO43pR6ei8DdjMeMHYkHOBjsxPDuRVHcq/ofa3grQsoLagq6qIciyWCAwT
         ZaWtdY673kF8c07Hn6Oty46WoJk5Q01bsMJyF4t+KFzolUc0EYGT108UB1PTget5J6na
         5T4t/AIxopQnxqRsEyxO1Ql6JzgUyJsHlIamWCsxZNb3zOcLW4vW7qH33Z+cSrGXkoCL
         8F2Bq83uOaZ8c7YD0Fl8T1fTZpgQUdudP4AvjFNd6cujoG/mt3eQHeoHUlm2fzl0xDlh
         mjpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710521575; x=1711126375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=v/LL8owdApL/XZLKD2e0O0nTWbH0aAGxrt7Xawmsw1o=;
        b=TlBDHseQhfa344XmwmwviL7mQFszaC8fpx/Tc4lOu1znf3/YMiEDcj/6j8cR0hcWw1
         sz0LUfpxOMBFe0/Om8EedCbcm7WjebhUPyZ/QvejISpjIm7rpoKiXcQhqnDkEA44v6qP
         I+XwSm5kC77jgeM/Ef7nGwqO+0c/F94SUWcRL66Doxh/p6Q1xGNI/adk3at0Lj5aLJVr
         fsgAWHeKVS/BcloJ6U9KRyN7l+2dYfIRS/XCwTUE6RIt4pjkEuuhMHT5AEPkWBOszOJv
         5V5Tni+nahRN9B7+gwNukFHm9nE3BjMKcU8uvFP/k+xWALt5mEQgVxFSPofLWRaf9Ok9
         kC4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710521575; x=1711126375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v/LL8owdApL/XZLKD2e0O0nTWbH0aAGxrt7Xawmsw1o=;
        b=vUvvZ76AK/SnvN83AxbOLxJUICDhrA1ZxbMjedk1NX88Vk5drbLbz8Jwx13fHONm3E
         LWPyZcCnOJ+9R9oiSlFwKHNJotdv0SbkPDY2o2Yf4TyExZRGhxGUUh9iIfEn/eR2yjVi
         NS2QLkio/Z2NO1k9Tw60Hz2i4OzOMnB/2KWKCYyXANA1IoBMeQDIUMvl5SgveAhLumcx
         az1YUWANb3RzFdSk+NwBxslycQ13rIYnf4Mn0DMel9EvRVjG86f4qRvoazv4cbM2GWDe
         ucWHG7M/hSzsU83vb0WISPSprhpWSmWB4stqSGh/whj7qQxdkeJPCA2FdvDND8xbKm0y
         7rZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHUK6jGOdylPPUv/4Xsqjj0WTNxxCBLL6Bo3QfYAU8RBDOWk1npMQt1iNDclZRgoYmkm1uzfynhIfNtOpaKp61TkjQXvxvmg==
X-Gm-Message-State: AOJu0Yx0NK3n4b4qMqX7UD+sMNE6WhTQneFcfCK3zM62QOt4GXtk1ZyZ
	08MkIsfBwAqzC4kPX57ozqKQpB8y5zLE860CFEk06MJv5aT/3lxX
X-Google-Smtp-Source: AGHT+IHyRSXN/sjiD7zaX17PnU6C8bWuwLqnA8+qQZmioDNrdNyTG5rMxEvUJGQpBuQ57ib0lptQ5A==
X-Received: by 2002:a19:6905:0:b0:513:13a4:95e4 with SMTP id e5-20020a196905000000b0051313a495e4mr2586477lfc.36.1710521574440;
        Fri, 15 Mar 2024 09:52:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4354:0:b0:513:aefa:7790 with SMTP id m20-20020a194354000000b00513aefa7790ls1069787lfj.2.-pod-prod-06-eu;
 Fri, 15 Mar 2024 09:52:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYZVV74wQQsY3clge01STeK6l+U189sjNPmttUo9xFzZkdZx1yok3qrXPR5nFZz7PXjQ4Fy0FRrcHWp1Bv044pEOfzoCnD8eYs2w==
X-Received: by 2002:ac2:494f:0:b0:513:c963:895e with SMTP id o15-20020ac2494f000000b00513c963895emr2751671lfi.42.1710521572142;
        Fri, 15 Mar 2024 09:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710521572; cv=none;
        d=google.com; s=arc-20160816;
        b=Hc4q2ihcfbLFwfROn5X1HZj4jhjDdlWnvvGAPR6xkRutwy2rPrHoyOuaW2yjxGtdqK
         NnWLtXgNjgcuIpjs6FJMmRCEUJTTt4jg5WgDvu/x6TNQAdbfHFGOAvMAvjZIc2Ab9cXV
         RxVUYwRF19yUazW/e1OGQ4du3w6VTDN6SUL8aam5yXwI2fEzx164nPk9sSgtBnEetYEr
         1MGEER0MjNmo9gzzgH0RmFteWYiRRZpZsjcov1S0AgiOQRwwz96IM71kVO0Ys1Udi1t7
         5sBrnDT+hx5s+XWGplnHUO8aVchFqAasB1YZtgzMSxxGU6g9jzM57KnhYdx/K5NodMlv
         bT7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Y4ELQ8jx6kpMYkwxWHw4XIu0o8oKQ+ttZ5iD5/+0aoI=;
        fh=CwiIpABL37Oixn0hxgMfgXRQfSyFmVhOL2dxilYmEyg=;
        b=Djwk+OyU3mFMCvGFLp8Gf21PU74g3HOajpMrLcUnSDWeeE7hEA+FUJcWmYhNWtAQCo
         JcBpPaeN/8DNI2oWnXN/p1H7JQvVjbiD8Bivq66ONwfVgn58qbWYYK3ERx2pBbVgDy1W
         VTYWcNvyE2k5UjrXqae6QxxEQNppb0V0Q3QFUcaO6R41DhkjtYd30GM9NNauSVqfNsk6
         18tmKNKLA+qDJq30H121lGxFVVwfsueO3DzUUeUG7ffu8GuOwPvjt5v7tu/3nY1OmgbA
         kBpaqRMfiRksroy2UgIpCn7EnIOgpsIZWPeDDWU/PdrVZ8FtFosJmPiLww9xJu/YL7Qf
         FDHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id br4-20020a056512400400b00513a9d05166si225888lfb.9.2024.03.15.09.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Mar 2024 09:52:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2D2DF21D19;
	Fri, 15 Mar 2024 16:52:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 92B6B1368C;
	Fri, 15 Mar 2024 16:52:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id o1p9I+J89GVLbwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 15 Mar 2024 16:52:50 +0000
Message-ID: <e6e96b64-01b1-4e23-bb0b-45438f9a6cc4@suse.cz>
Date: Fri, 15 Mar 2024 17:52:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 23/37] mm/slab: add allocation accounting into slab
 allocation and free paths
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-24-surenb@google.com>
 <1f51ffe8-e5b9-460f-815e-50e3a81c57bf@suse.cz>
 <CAJuCfpE5mCXiGLHTm1a8PwLXrokexx9=QrrRF4fWVosTh5Q7BA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpE5mCXiGLHTm1a8PwLXrokexx9=QrrRF4fWVosTh5Q7BA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -3.00
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spamd-Result: default: False [-3.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[76];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Rspamd-Queue-Id: 2D2DF21D19
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=GIVcH5dt;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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

On 3/15/24 16:43, Suren Baghdasaryan wrote:
> On Fri, Mar 15, 2024 at 3:58=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 3/6/24 19:24, Suren Baghdasaryan wrote:
>> > Account slab allocations using codetag reference embedded into slabobj=
_ext.
>> >
>> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
>> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>> > Reviewed-by: Kees Cook <keescook@chromium.org>
>>
>> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>>
>> Nit below:
>>
>> > @@ -3833,6 +3913,7 @@ void slab_post_alloc_hook(struct kmem_cache *s, =
struct obj_cgroup *objcg,
>> >                         unsigned int orig_size)
>> >  {
>> >       unsigned int zero_size =3D s->object_size;
>> > +     struct slabobj_ext *obj_exts;
>> >       bool kasan_init =3D init;
>> >       size_t i;
>> >       gfp_t init_flags =3D flags & gfp_allowed_mask;
>> > @@ -3875,6 +3956,12 @@ void slab_post_alloc_hook(struct kmem_cache *s,=
        struct obj_cgroup *objcg,
>> >               kmemleak_alloc_recursive(p[i], s->object_size, 1,
>> >                                        s->flags, init_flags);
>> >               kmsan_slab_alloc(s, p[i], init_flags);
>> > +             obj_exts =3D prepare_slab_obj_exts_hook(s, flags, p[i]);
>> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
>> > +             /* obj_exts can be allocated for other reasons */
>> > +             if (likely(obj_exts) && mem_alloc_profiling_enabled())

Could you at least flip these two checks then so the static key one goes fi=
rst?

>> > +                     alloc_tag_add(&obj_exts->ref, current->alloc_tag=
, s->size);
>> > +#endif
>>
>> I think you could still do this a bit better:
>>
>> Check mem_alloc_profiling_enabled() once before the whole block calling
>> prepare_slab_obj_exts_hook() and alloc_tag_add()
>> Remove need_slab_obj_ext() check from prepare_slab_obj_exts_hook()
>=20
> Agree about checking mem_alloc_profiling_enabled() early and one time,
> except I would like to use need_slab_obj_ext() instead of
> mem_alloc_profiling_enabled() for that check. Currently they are
> equivalent but if there are more slab_obj_ext users in the future then
> there will be cases when we need to prepare_slab_obj_exts_hook() even
> when mem_alloc_profiling_enabled()=3D=3Dfalse. need_slab_obj_ext() will b=
e
> easy to extend for such cases.

I thought we don't generally future-proof internal implementation details
like this until it's actually needed. But at least what I suggested above
would help, thanks.

> Thanks,
> Suren.
>=20
>>
>> >       }
>> >
>> >       memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
>> > @@ -4353,6 +4440,7 @@ void slab_free(struct kmem_cache *s, struct slab=
 *slab, void *object,
>> >              unsigned long addr)
>> >  {
>> >       memcg_slab_free_hook(s, slab, &object, 1);
>> > +     alloc_tagging_slab_free_hook(s, slab, &object, 1);
>> >
>> >       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s)))=
)
>> >               do_slab_free(s, slab, object, object, 1, addr);
>> > @@ -4363,6 +4451,7 @@ void slab_free_bulk(struct kmem_cache *s, struct=
 slab *slab, void *head,
>> >                   void *tail, void **p, int cnt, unsigned long addr)
>> >  {
>> >       memcg_slab_free_hook(s, slab, p, cnt);
>> > +     alloc_tagging_slab_free_hook(s, slab, p, cnt);
>> >       /*
>> >        * With KASAN enabled slab_free_freelist_hook modifies the freel=
ist
>> >        * to remove objects, whose reuse must be delayed.
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e6e96b64-01b1-4e23-bb0b-45438f9a6cc4%40suse.cz.
