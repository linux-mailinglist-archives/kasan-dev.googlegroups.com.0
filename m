Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBS7DUOLQMGQEKXYKGTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DCC40587A06
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 11:43:40 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id y11-20020a05651c220b00b0025e4bd7731fsf1254310ljq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 02:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659433420; cv=pass;
        d=google.com; s=arc-20160816;
        b=wYcB2eDJ8WE9j1PW2bgSdEzyVbauZfwQcpjzFSKyu7PTDHPGpEiKSdp4jWqSDPe+9n
         /s3kLBJbim7F4yDc7SlPqWmh9guHuOoXJ1YjULgLThiqnTkxGJz10LcPGRiMZvBzqNfl
         Dg0FK/T2e0FxWOcyWWfmNEhTU9uLyaTmlaG8Gy599edF+cbDrorEtYa4zoFkSnm3morj
         fN/LduJSemq4EziFA2Vj5NTrVWOX0j1IlN8awJI+klq7cBz4QBapFzZWjAXEi0HNQhit
         4lrfuk1NxpUg8a6jcQbIKagUtKsp5EhbC4bj0aAPmVOVdtTXGlxDSfAywlHmr2lZ7eV3
         jtzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=5wJhCe0TvVB6XUf8mX1auWXMJTEN2S9ml+g5NI8nwDo=;
        b=OkO7eqXWIVigJVjMdsVG848fkJGhbE9kDXCdS5XLH6ILYpO/yGMl1mrBjKKYifVtxt
         1vyXue9XsnlgumKRFWwEGTn6xCnCiJ4xyc+NR55SeymawgSMqqIK5UMq3/IKyCBlBskJ
         ff9V5HBMVgk2nCckjVZ6ymG6OoNBa6Mlv+ByklunfnmRTZZmCxfnn3Qcr2PKXmFjWBjl
         mk5qO47HTvWBMDNxILF5iWDoIeyiO6GZ5MEtORr/0ivrJojzbiEAv8tDv8OWFzi2qQoW
         +Q9mNzu6kWhEY0N6+NWfw5xT4YN2Q+srlbMkTrsscedbkGiwnnrkYNWUDq3miNy3fRFa
         8ySw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OigbtW0P;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5wJhCe0TvVB6XUf8mX1auWXMJTEN2S9ml+g5NI8nwDo=;
        b=jINHfvU57sQJktx0R1fBRdEO6Vig5Fe0v5cNC+r15E1fkaFc6Hd6s1MuiLfcytP4N0
         WZBQJE5ZN50wZS0qT/1OIWOOZ7Vww6aW6PRdDNiKw3V4OKdFpeTv+TWcDaRRUzHXd9fB
         stWya5IXpVcZneOD+Mw7wZ/+DDU5wPSnlBguNu0YM4O80QN08/h6KAC9j2vqM3ZADJXX
         9jm3rsEqxsy9UIjjFkD94L6gpdFHeP/En1GclLz0LDkdtvx1bVvYFeHXinBYZT4ces+s
         Uui/0AD15f+nva4HHvIh5ry6xqTZJM/Ub/wvHyIL21Ly3Q+1gUlN9X43U72Kp9g3YSxk
         E/Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5wJhCe0TvVB6XUf8mX1auWXMJTEN2S9ml+g5NI8nwDo=;
        b=ektexPsBZKlpS9lsn7SRjIBIPNaIxGtDWKTqFyHmYwJnYAcR6OODXKrESXlNqlvDDr
         w2xozE+B5RW1V4qH0a+7fWuzfaJySIeiBk5rKUl2d55e7pVqGa+mGvafzRRQ82WZ9fRR
         2VJDCTYc3yAMRFGsnn5kxrmVXPqwFoQInpL3oWzptIvGYfPW0sAKkyPOka2B5yJsUlvb
         BnOeC9X5wtgNjG0cCQlnEjBVzFPOlmO+mbvJA0BK+inLz8PuzXqVoyR8UrzPeX9/4bBb
         9Wor02IdWSs0lr67gwimdlGE7s5lnvFlYsK67aoDNaqb8o6b2kyX0zbP/G57vRLFWm1e
         Bcow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9auULW7P2RfMa28yoBNy5g2fMRdH8h/HNNgjCwvigycsBIgNl4
	dRr7fr5+dNANyO2Tri7nPDU=
X-Google-Smtp-Source: AGRyM1s7tSdb/egx9ivya/8h70U/Fq6QM++1mZMvkWfkJd3r28CY84ZngDF8SLh41ycUI3steDu2jw==
X-Received: by 2002:a05:6512:12d6:b0:48a:acd8:7183 with SMTP id p22-20020a05651212d600b0048aacd87183mr7089037lfg.114.1659433420178;
        Tue, 02 Aug 2022 02:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1990:b0:25e:3fc1:cb41 with SMTP id
 bx16-20020a05651c199000b0025e3fc1cb41ls1639163ljb.5.-pod-prod-gmail; Tue, 02
 Aug 2022 02:43:38 -0700 (PDT)
X-Received: by 2002:a2e:2418:0:b0:25e:43f6:384f with SMTP id k24-20020a2e2418000000b0025e43f6384fmr5135760ljk.361.1659433418737;
        Tue, 02 Aug 2022 02:43:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659433418; cv=none;
        d=google.com; s=arc-20160816;
        b=wCSukTiJjCowmfHTbH5QTxQEq3l4I/8Wdu/cpSlPYJSeXXnd/PcSSKNb61a8NvTp54
         oZzLurk4yQHIXVqxZGMHGJd413icZGQg437oxYJAl5yI1U31qab9xV/RErzytZ1LTmR3
         uwfVIWLIcqfTY0Q1h3koOoF25+MLB0AsvZ6KnVyTIEw9HC9GrXKYc9N47URE+CIPS1Uc
         5WCodKAQLYu4Ok4JRHzgH33iScI/zbmgqA9Mz/P3/kO6gWOZDer0xRFtnWkAPpYXtQMG
         n68k5ZCgf+6NRpbLEa5v+CSHjpDporJx7LQ/UGT+dJJ7fbwDbb7WgHrAOD80TVKVqBKt
         41vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=r7YVoJLzpojTt0jcWLG9PMje7g7Fq1t+gY4EsDTwwLc=;
        b=UH1le6XroVxD0IHwpPRXCEb/zJUmg0OZOuTJHvQH0sTW1/k0P64TXjjvW7wRPjvCm+
         fm/j+3B0hClLCxjWJW3eP+mtiIoRZaJByYBoA5FQQWYNR64271QNCkcsTYV8hsu8eM+m
         VlwfWHlUZx/PnVW552Pnq8NgNbbkdckgk7yNtm6mJ82LjiiSaKaxlgvInwcLnI8Mg5+F
         bbOoC6hDcvyxEBmlARPHvI7AE7+XcJzpWzzLz4r4Rjog+2D5Dg+7R2uYxDLM49lGbVBU
         EHq4/ResQjo1SNEX9+KcHYNH5z7iyaHcypnqsD/Tpq1q3FNgz3wBeIeeSTPENYhO3ZXf
         MtwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=OigbtW0P;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id i28-20020a2ea37c000000b0025e4f4e6637si274611ljn.2.2022.08.02.02.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Aug 2022 02:43:38 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F1EE833EBB;
	Tue,  2 Aug 2022 09:43:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 9AD6B13A8E;
	Tue,  2 Aug 2022 09:43:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id O9cDJcnx6GKScAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 02 Aug 2022 09:43:37 +0000
Message-ID: <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
Date: Tue, 2 Aug 2022 11:43:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>, Feng Tang <feng.tang@intel.com>
Cc: "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>,
 LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org"
 <linux-mm@kvack.org>, "lkp@lists.01.org" <lkp@lists.01.org>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020> <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl>
 <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=OigbtW0P;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/2/22 09:06, Dmitry Vyukov wrote:
> On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
>>
>> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
>> > On 8/1/22 08:21, Feng Tang wrote:
>> [snip]
>> > > Cc kansan  mail list.
>> > >
>> > > This is really related with KASAN debug, that in free path, some
>> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
>> > > kasan to save free meta info.
>> > >
>> > > The callstack is:
>> > >
>> > >   kfree
>> > >     slab_free
>> > >       slab_free_freelist_hook
>> > >           slab_free_hook
>> > >             __kasan_slab_free
>> > >               ____kasan_slab_free
>> > >                 kasan_set_free_info
>> > >                   kasan_set_track
>> > >
>> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
>> > > tracks: alloc_track and free_track, for x86_64 test platform, most
>> > > of the slabs will reserve space for alloc_track, and reuse the
>> > > 'object' area for free_track.  The kasan free_track is 16 bytes
>> > > large, that it will occupy the whole 'kmalloc-16's object area,
>> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
>> > > error is triggered.
>> > >
>> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
>> > > conflict with kmalloc-redzone which stay in the latter part of
>> > > kmalloc area.
>> > >
>> > > So the solution I can think of is:
>> > > * skip the kmalloc-redzone for kmalloc-16 only, or
>> > > * skip kmalloc-redzone if kasan is enabled, or
>> > > * let kasan reserve the free meta (16 bytes) outside of object
>> > >   just like for alloc meta
>> >
>> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
>> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
>> > __ksize() does.
>>
>> How about the following patch:
>>
>> ---
>> diff --git a/mm/slub.c b/mm/slub.c
>> index added2653bb0..33bbac2afaef 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
>>         if (!slub_debug_orig_size(s))
>>                 return;
>>
>> +#ifdef CONFIG_KASAN
>> +       /*
>> +        * When kasan is enabled, it could save its free meta data in the
>> +        * start part of object area, so skip the kmalloc redzone check
>> +        * for small kmalloc slabs to avoid the data conflict.
>> +        */
>> +       if (s->object_size <= 32)
>> +               orig_size = s->object_size;
>> +#endif
>> +
>>         p += get_info_end(s);
>>         p += sizeof(struct track) * 2;
>>
>> I extend the size to 32 for potential's kasan meta data size increase.
>> This is tested locally, if people are OK with it, I can ask for 0Day's
>> help to verify this.

Is there maybe some KASAN macro we can use instead of hardcoding 32?

> 
> Where is set_orig_size() function defined? Don't see it upstream nor
> in linux-next.
> This looks fine but my only concern is that this should not increase
> memory consumption when slub debug tracking is not enabled, which
> should be the main operation mode when KASAN is enabled. But I can't
> figure this out w/o context.

It won't increase memory consumption even if slub_debug tracking is enabled.
It just fakes a bit the size that was passed to kmalloc() and which we newly
store (thanks to Feng's patches) for statistics and debugging purposes.

>> Thanks,
>> Feng
>>
>> >
>> > > I don't have way to test kasan's SW/HW tag configuration, which
>> > > is only enabled on arm64 now. And I don't know if there will
>> > > also be some conflict.
>> > >
>> > > Thanks,
>> > > Feng
>> > >
>> >
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YujKCxu2lJJFm73P%40feng-skl.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85ec4ea8-ae4c-3592-5491-3db6d0ad8c59%40suse.cz.
