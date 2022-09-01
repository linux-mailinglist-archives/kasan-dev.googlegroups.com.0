Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBEXDYGMAMGQEHP33KMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 15D6B5A9257
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 10:47:15 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id x7-20020a056512130700b00492c545b3cfsf4218177lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 01:47:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662022034; cv=pass;
        d=google.com; s=arc-20160816;
        b=KFfdD2/WuPeyTUEjM/85pv51APIxqsndiUTsXRdHOOj27KkVCXWJp4hWzoahyJYl7B
         SYmQUNhjQzN/UezMaa7fv/E2tBTnTXed4aKsr1w+kahVwvxY3kZJLmDqhuqEAmwdTAb7
         jqmjSVhxF4yr+GV5shjvWP1RmLOxgo9KcsPt54fsLvdsqwkcpTGeNRqD5I4r50Z3Ho4Z
         APolrnkVimLfoJbycdSrWan02hnYpH3SxQ2H9yalKiAJ4h0i/P8agXZL8pHBbBab6BVd
         jPONUWjA8Sp6ZNva7AxVdR3OLg5NW5NawUtE48cDhxBTQ0ANNqURuwsuUEYgE8s/8b2w
         ZHUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Rgzs3IskQCVxY1nbnIf7N/KMZcBSxbqEm1OkEavFOxs=;
        b=S/L0MSrtpyD4k9iGgMiClcpA023SaoFghVUXSfun7VpQCED8AdPWHY9g41AzPpz7I4
         qjuiNUjgIPTgeMUrYk3cvKjeWo/KxfhRmMs+my6y3NYqUBjE5sPS/kP7IR/Bbx5OmisN
         aMEZpnv3Rliw+HQO5yYyUfI19DLsRBouSuGIJ/vTcTyr/1TWIxzQsNXUBSG1XrIkYCw/
         huIZ90hKTFfqjUMLP0XAYpt1onbels2YMu2eKhHFzuDPwzT20el2+lzHICMdg74aNYOo
         PEq4bZpmMD5Fxhiw22wHIjHKIK1dEvcCG7n62Lvi13u16RuSsarXAe/fxhGN6oFi6eQL
         XRcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=umIEJIdq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=nuyJH10v;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=Rgzs3IskQCVxY1nbnIf7N/KMZcBSxbqEm1OkEavFOxs=;
        b=QVmbJB4eEJZlyUf2oLZadrKusXaUJ2ap3x/7OLXDveXpgPYe+DKQfsSWH2W2g/wQQB
         TYwMXD4gnez7Xi2L78G5hGO+DY3HmOHfXHeZseGMsmIIscs3yg6RC796CQRs6bKAnefE
         fn++U7RqtIiMQOMjnFwdWTTNwKQ55FgkQz87VxCDWt7r5PWFKZ9EkxJ4Yt0BSbI3w5/G
         yhnsbf2pOa/Gp8j79yBVpkXwwRQ/6S4HzRxJTnuatB4CJs0CZgyIexOSAFH7v0E5MJjX
         XVIAtaFezKw/4oEbpbY5Vr5OgSY07+2pwl/Mr0G28zPbBEHYQR6r6vLPFdX1suU9JAgS
         M9QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=Rgzs3IskQCVxY1nbnIf7N/KMZcBSxbqEm1OkEavFOxs=;
        b=FceT6O+UXX0GRH8MeCzhJ7vWThpMlOxXyKF0mnKurwj8Oh+Y04Xc9h8f8pIYNjX7gB
         Zj9we4jttK1+8LWY4zK0Y6ot4ovqXc9gcgj7FzAqBov45mCuP9leDH2bG1H3mjapM8cX
         VGYGyzANx33SPRq8OOuw4hsva6ukbVkDCQXQlt+e+RzTdWh6PHQDcBJoG/BC/0mcHTQe
         +DgdLwSWtq4WWqkjAHtmA3nVDrp6JOY/8kVf8ui6ZQ/aD3QKwBKfBqzM6U0okuYwJ1WY
         jwIcvGhxF5wNIdnvI2JgDkOATDe0ri92vLc5igpaiKeWHmbf9tN7ZYdc9ggB4+dzVMqi
         a6eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0LkmlmgbXcZZ+RUOMTp+bEFzAM1yYvWBQ9ZpcgzVK5vPif1Xrd
	28kjh/6N3lKUYVD6Wvm1kmY=
X-Google-Smtp-Source: AA6agR5NNfrBx28gbSVz4qBrw+/bk+yn/3NF2cn0Mr9edszWVwOHKrMlkg9lWPz9KHzMYhCJ3q/AQA==
X-Received: by 2002:a05:651c:1a1f:b0:261:cb1a:3dd6 with SMTP id by31-20020a05651c1a1f00b00261cb1a3dd6mr10323679ljb.457.1662022034379;
        Thu, 01 Sep 2022 01:47:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a912:0:b0:25d:4f02:5abf with SMTP id j18-20020a2ea912000000b0025d4f025abfls204288ljq.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 01:47:13 -0700 (PDT)
X-Received: by 2002:a2e:a174:0:b0:267:fad4:7f9c with SMTP id u20-20020a2ea174000000b00267fad47f9cmr2900880ljl.247.1662022033053;
        Thu, 01 Sep 2022 01:47:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662022033; cv=none;
        d=google.com; s=arc-20160816;
        b=qFLBFs2NGOUXPc768SIYM3MRDv3IwVK5bwM7O0z3OeVlzWlQJtg6KWcGNbx8rCi5MB
         Z2blva56yNWLJxXNRu0mqxcG6jeDCnJgonHlE6qwE3jM8fKBZO1PZ2gga9Jt7BQqROl/
         4IQzrZlUkuDl6bUCGxuW/dz2Qv4S5CTRLv4eH+486uagIacU1F2mm5edoEQ6WD9zPbQe
         KHfbJfI47RGVo/f69d1fzpqUJ4OVHFduadqTzM2i7sFeYbJUOjShh5ZbMJC74/ZMFyum
         n5dwLjimW1WBdjIlNCycVWq8f4n20wZq/tNp2h0sgnnxx1GZiH1q4KvBo0KqkJvgKFhz
         Qnjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=LGTcfsJkK1Xbb+ogV33V9MNZA3cpuGvzquse6jYX4Jo=;
        b=0nbFGX8mRK5ugR6stNwbjI+Rtz3Mgfy+Zd4k4QgrvOWgDunl0lw1S/0gySNn0fzx5r
         f+Bnd7H1uj0WfoQ0psTljrDp5jgiVTfwMG+uLUcu/9G66sgPwwMbLfRAZpPu1L6Dg4Fe
         DW87ogtvy63+XBqw6W0qfls3DwZJ/iuiVH89Itoe0uKJGQoZNOI7gdr0h9BmRaJR+tDs
         HnaMCpYzOnzuk3j72pioWz7bdasuG7v5ccRvPFiu/+zC6ddL7EXLAjVIMylIRhRVk9hu
         X5sx3vAcwwKPsJTDjr/VGRQyqYpozGwfmqUgZIkxgpyyI505IOCBXJErrT7zt+FeV7wI
         wUIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=umIEJIdq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=nuyJH10v;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si413088ljm.2.2022.09.01.01.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 01:47:12 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 54261223F6;
	Thu,  1 Sep 2022 08:47:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3011D13A79;
	Thu,  1 Sep 2022 08:47:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id QmOpCpBxEGP+OwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 01 Sep 2022 08:47:12 +0000
Message-ID: <111e54ab-67d7-2932-150d-3bfd46827b30@suse.cz>
Date: Thu, 1 Sep 2022 10:47:11 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.0
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
To: Feng Tang <feng.tang@intel.com>
Cc: Marco Elver <elver@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>
References: <20220831073051.3032-1-feng.tang@intel.com>
 <Yw9qeSyrdhnLOA8s@hyeyoo>
 <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
 <7edc9d38-da50-21c8-ea79-f003f386c29b@suse.cz> <YxAKXt+a/pqtUmDz@feng-clx>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <YxAKXt+a/pqtUmDz@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=umIEJIdq;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=nuyJH10v;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/1/22 03:26, Feng Tang wrote:
> On Thu, Sep 01, 2022 at 12:16:17AM +0800, Vlastimil Babka wrote:
>> On 8/31/22 16:21, Marco Elver wrote:
>> > On Wed, 31 Aug 2022 at 16:04, Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
>> > 
>> >> Maybe you can include those functions too?
>> >>
>> >> - __kmem_cache_alloc_node
>> >> - kmalloc_[node_]trace, kmalloc_large[_node]
>> > 
>> > This is only required if they are allocator "root" functions when
>> > entering allocator code (or may be tail called by a allocator "root"
>> > function). Because get_stack_skipnr() looks for one of the listed
>> > function prefixes in the whole stack trace.
>> > 
>> > The reason __kmem_cache_free() is now required is because it is tail
>> > called by kfree() which disappears from the stack trace if the
>> > compiler does tail-call-optimization.
>> 
>> I checked and I have this jmp tail call, yet all test pass here.
>> But I assume the right commit to amend is
>> 05a1c2e50809 ("mm/sl[au]b: generalize kmalloc subsystem")
>> 
>> Could you Feng maybe verify that that commit is the first that fails the
>> tests, and parent commit of that is OK? Thanks.
> 
> Yes, 05a1c2e50809 is the first commit that I saw the 4 kfence failed
> kunit cases.

Thanks, squashed your patch there and pushed new for-next.

> Thanks,
> Feng
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/111e54ab-67d7-2932-150d-3bfd46827b30%40suse.cz.
