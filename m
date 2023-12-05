Return-Path: <kasan-dev+bncBDXYDPH3S4OBBG7RXOVQMGQEP2BPRBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 05B8180500B
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 11:17:01 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-35d68bb0ed2sf20341255ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 02:17:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701771420; cv=pass;
        d=google.com; s=arc-20160816;
        b=Se+gTG9Ve85fQRM+YBM8OGTqYuY9TmpBLNA/73WtbCuTCSyqUZRy91E/xqNVH3f2Mf
         clo18VCDdEjfD+EeoRNmWDSHz3nrY+WZBmYyMBxxrHx8+s/+8wBENw3tT/mMF+IyZ0AF
         3IGEVtpz0zjfbKez/p8YPtLLoBMP1wai6FIOC+yQu/xjff680XJLkA4wtYdR/mQ+4bb1
         V3L3u1nu0qZvJYJ3bQSG4mW5e/Pt1M0cQCYSHwVI9rKLfY2uB11mJoZhc7R6Znirpy7b
         i6QP6Yxwunu6yYR5DL/fsiIo4brvq9VjuThgbj09ppicJ9LcShjDEZ+/bw5JelV2cfxY
         btPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=dOHRgwGv42l6R5juFVvW9CXiZX1DGP6rtQYQcNu38uk=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=kmT9DibvZdw2y9varm3A6gJsN3kgO6qgl5oUh9q/i0NuambBCNErniwCvaue8hfFrj
         aAYPn5HYKLBYtN/b7WPH0lGCUgzMv1JDpAw7VrR3Wvf1/eIL1oSHnBQSDKzcnJtfCO5W
         deZ7d2WrrGVfh4VO/+pUxmPtA8SawQtLkZxDM5rH86A75YshEIA7sOlHhcLGN/vCDNwZ
         MjA34K2DZ8Dq3wxfZnu6yeAf3gE0fdNun2ObL6k82cMn0p1bV9CXuyNmd9+AcAX1+f1F
         KyrZNlKCahY1T2jVjWkB7I7iPFDINdd/Hh2lhrIyUnunx3P0bLvJLnvDQ8p8yUiPSa3h
         44fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701771420; x=1702376220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dOHRgwGv42l6R5juFVvW9CXiZX1DGP6rtQYQcNu38uk=;
        b=MrXabGTkrNFS8mYsFXA5gfDtrTaQteii24GyY6sMIrIvaxCf2I3hKMpqXj8D9UyhPu
         zGF1wTsvCi2rixXBijpS4qgZjGGEjXz9yZkiJn4gpHbZTJTBl1cue0mhPFTmkboz1TJD
         3QzLX0TiY0PEifBV5y8R4MDPtlu55lkg+sJsbjlyDgd6dYJyQZDc/ZHHaOH/mgzFG+a2
         tWAEeNPjOAqHqWafq2tH04ZIaDTH0uacSzqRyh3P0jJ1Z3wIYiQJaw830xLc897+Q4yj
         bT2ZD0v92FqEIhMUzAmOw3YTnbdD3oQmjLMGDk01g1fYFVtuxqMtRtWauUU0Y4aOMqDK
         CkHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701771420; x=1702376220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dOHRgwGv42l6R5juFVvW9CXiZX1DGP6rtQYQcNu38uk=;
        b=gqlfJdrpMCETmTeS5e3sOK5NzdkM7rxhmbc9AD43bZKpY2nKTx16eg8IhLwJAQSayh
         mpABuqdthMDr6J5awiwF9dgPSfcG+UqmnyS45sfzeuH8sVI99uxlUSkGNc2ZE+1Jgiq4
         vuZwcY+LZ5jeTb/jLnIn2gDLoVBMsmb445NIeA6KemlS+LkptRfOLDz6zoCOLnjhGzQS
         SrOIPvmm1ZVIGIetPAzsqQ3RsmeTdz3+JU+pKqdVj1YqQD6Gdz4ea04rBkUFFtVsmXHs
         TwkhNjHNYjRp+GerWIa4+90aoqjzbR4BIFBp3h51JhZ36Z44++vo9+7EiNNI+QCZcorT
         hQmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyohNRZjLhTTzJMHj+kS9/NvQqz+osjmmYCxk7mM2zCpk7SrUjD
	+pjSCQwu/b3FPvkflwyL3gA=
X-Google-Smtp-Source: AGHT+IGlpcE5erRknGxm6o/VSVhBf7QNncbsD/n+6bqO+sAeLh6zs0MIT/EsywnnWHm9Cq4aHVWsUQ==
X-Received: by 2002:a05:6e02:1545:b0:35d:551a:5c0b with SMTP id j5-20020a056e02154500b0035d551a5c0bmr4891764ilu.1.1701771419878;
        Tue, 05 Dec 2023 02:16:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ce:b0:35c:d0b2:2d3 with SMTP id
 i14-20020a056e0212ce00b0035cd0b202d3ls662913ilm.1.-pod-prod-09-us; Tue, 05
 Dec 2023 02:16:59 -0800 (PST)
X-Received: by 2002:a92:4b03:0:b0:35d:59a2:a320 with SMTP id m3-20020a924b03000000b0035d59a2a320mr4302103ilg.34.1701771418811;
        Tue, 05 Dec 2023 02:16:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701771418; cv=none;
        d=google.com; s=arc-20160816;
        b=Nd7VU3o8HukQE/hzIvRZHg6t+iZlhS+pBbHQ5X1M9r0aYz/ws9A6vUB1QHBxBqzxrK
         mHc0eayKc3ytSTqnSl73bNwl/DzNadWFwVidZAWfT6XyYQH61QVCgcxqFwcpgoq1zZtU
         DtjUXUg6bF4bNW0LC10sEWRYw4loLK2Jp3fRJLhnrD04gpzJ0VNyrvG60q5nTsfWSCmj
         AKmOJx/m+Q8ZTC1LFK3NYSGDa4hkxWJhpU8FAJ6VFyxJ3BnF84o93EwKe4hORMwX+rWO
         qCfwt3wlrb8CgoC/99pwEXCSkHgQyCtd1MeLOrEkfYgl+nuKhxg+4lEyhWra7ER6g0Vy
         c0mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=L8u0GTc7MD6XLgY8Qms86a3Tg/qLA5sTEiRQbdzvIt0=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=IoUuKLC0XAvRJKN2BquTAAfOpmvzifEfNn6NXVe8xuJRf4tmv70nOw2Lv4MiLil5+1
         NAjlBT///I8hE4pySZuntzzzvr+qus+P5zslrqoDFUXgbSZtGa+GL2qLiTiQZK9OHO2J
         FxxU4pNzZGK4YHPaVN2GCSndZJWZYQDdJlUnYTTNZEcHsv+/eI7eVjZN1o161VOKQwF6
         niNpjwp2kDMYdNi1Vh59LXvwaoKewbXlNi7j2EbyTFpOrTSK6FBxVF0YBL4fL4snaiee
         fGiajaEdA6TD7Cbv4hW8neEf9FcfShHqjzcFf9VClz1xsm/SU2Oh2dl3LLpIHloUtfhn
         bTeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id w10-20020a92db4a000000b0035d661cac44si132430ilq.5.2023.12.05.02.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Dec 2023 02:16:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9D0EA2207E;
	Tue,  5 Dec 2023 10:16:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6C908136CF;
	Tue,  5 Dec 2023 10:16:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 3fBhGZj4bmV8aAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 05 Dec 2023 10:16:56 +0000
Message-ID: <432494ef-b47f-16fa-41a0-f68613f94fc4@suse.cz>
Date: Tue, 5 Dec 2023 11:16:56 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
 <ZW6mjFlmm0ME18OQ@localhost.localdomain>
 <CAB=+i9R+zZo-AGuEAYDzEZV7f=YSC9fdczARQijk-WPZUr0iDA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAB=+i9R+zZo-AGuEAYDzEZV7f=YSC9fdczARQijk-WPZUr0iDA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Bar: ++++++++++++
X-Spam-Score: 12.84
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: 9D0EA2207E
X-Spam-Flag: NO
X-Spam-Level: ************
X-Spamd-Result: default: False [12.84 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 FREEMAIL_TO(0.00)[gmail.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 NEURAL_SPAM_SHORT(2.95)[0.983];
	 NEURAL_SPAM_LONG(3.50)[1.000];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com,cmpxchg.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

On 12/5/23 05:48, Hyeonggon Yoo wrote:
> On Tue, Dec 5, 2023 at 1:27=E2=80=AFPM Hyeonggon Yoo <42.hyeyoo@gmail.com=
> wrote:
>>
>> On Mon, Nov 20, 2023 at 07:34:14PM +0100, Vlastimil Babka wrote:
>> > With SLAB removed and SLUB the only remaining allocator, we can clean =
up
>> > some code that was depending on the choice.
>> >
>> > Reviewed-by: Kees Cook <keescook@chromium.org>
>> > Reviewed-by: Marco Elver <elver@google.com>
>> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> > ---
>> >  mm/kasan/common.c     | 13 ++-----------
>> >  mm/kasan/kasan.h      |  3 +--
>> >  mm/kasan/quarantine.c |  7 -------
>> >  3 files changed, 3 insertions(+), 20 deletions(-)
>> >
>> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> > index 256930da578a..5d95219e69d7 100644
>> > --- a/mm/kasan/common.c
>> > +++ b/mm/kasan/common.c
>> > @@ -153,10 +153,6 @@ void __kasan_poison_object_data(struct kmem_cache=
 *cache, void *object)
>> >   * 2. A cache might be SLAB_TYPESAFE_BY_RCU, which means objects can =
be
>> >   *    accessed after being freed. We preassign tags for objects in th=
ese
>> >   *    caches as well.
>> > - * 3. For SLAB allocator we can't preassign tags randomly since the f=
reelist
>> > - *    is stored as an array of indexes instead of a linked list. Assi=
gn tags
>> > - *    based on objects indexes, so that objects that are next to each=
 other
>> > - *    get different tags.
>> >   */
>> >  static inline u8 assign_tag(struct kmem_cache *cache,
>> >                                       const void *object, bool init)
>> > @@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *c=
ache,
>> >       if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
>> >               return init ? KASAN_TAG_KERNEL : kasan_random_tag();
>> >
>> > -     /* For caches that either have a constructor or SLAB_TYPESAFE_BY=
_RCU: */
>> > -#ifdef CONFIG_SLAB
>> > -     /* For SLAB assign tags based on the object index in the freelis=
t. */
>> > -     return (u8)obj_to_index(cache, virt_to_slab(object), (void *)obj=
ect);
>> > -#else
>> >       /*
>> > -      * For SLUB assign a random tag during slab creation, otherwise =
reuse
>> > +      * For caches that either have a constructor or SLAB_TYPESAFE_BY=
_RCU,
>> > +      * assign a random tag during slab creation, otherwise reuse
>> >        * the already assigned tag.
>> >        */
>> >       return init ? kasan_random_tag() : get_tag(object);
>> > -#endif
>> >  }
>> >
>> >  void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
>> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> > index 8b06bab5c406..eef50233640a 100644
>> > --- a/mm/kasan/kasan.h
>> > +++ b/mm/kasan/kasan.h
>> > @@ -373,8 +373,7 @@ void kasan_set_track(struct kasan_track *track, gf=
p_t flags);
>> >  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gf=
p_t flags);
>> >  void kasan_save_free_info(struct kmem_cache *cache, void *object);
>> >
>> > -#if defined(CONFIG_KASAN_GENERIC) && \
>> > -     (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>> > +#ifdef CONFIG_KASAN_GENERIC
>> >  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
>> >  void kasan_quarantine_reduce(void);
>> >  void kasan_quarantine_remove_cache(struct kmem_cache *cache);
>> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
>> > index ca4529156735..138c57b836f2 100644
>> > --- a/mm/kasan/quarantine.c
>> > +++ b/mm/kasan/quarantine.c
>> > @@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, =
struct kmem_cache *cache)
>> >  {
>> >       void *object =3D qlink_to_object(qlink, cache);
>> >       struct kasan_free_meta *meta =3D kasan_get_free_meta(cache, obje=
ct);
>> > -     unsigned long flags;
>> > -
>> > -     if (IS_ENABLED(CONFIG_SLAB))
>> > -             local_irq_save(flags);
>> >
>> >       /*
>> >        * If init_on_free is enabled and KASAN's free metadata is store=
d in
>> > @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, s=
truct kmem_cache *cache)
>> >       *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
>> >
>> >       ___cache_free(cache, object, _THIS_IP_);
>> > -
>> > -     if (IS_ENABLED(CONFIG_SLAB))
>> > -             local_irq_restore(flags);
>> >  }
>> >
>> >  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *c=
ache)
>>
>> Looks good to me,
>> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks!

> nit: Some KASAN tests depends on SLUB, but as now it's the only allocator
>       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB); in
>       mm/kasan/kasan_test.c can be removed

Hmm I see, but will rather also leave it for later cleanup at this point,
thanks!

>>
>> >
>> > --
>> > 2.42.1
>> >
>> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/432494ef-b47f-16fa-41a0-f68613f94fc4%40suse.cz.
