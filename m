Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBMWGVCOQMGQEES5X2DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4632B656588
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 23:41:55 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id bd6-20020a05600c1f0600b003d96f7f2396sf5590918wmb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Dec 2022 14:41:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672094515; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ru2coVf0OIJiG5g+ZDwZ5pZgG/1Mp43AptPUT3dx6HNLiQJ/UnA5eWjJhkSsJ3Duci
         aJ5tsEzUq3bnTFmHTiM/OdsbEXMLZlusgsaOz4UcXpYCUR1zXYaS/G8mcQczjGhTryFD
         +Px7Klzov3XIm5cq+Dl5de8aStEF1lb2NCIGJEkS+hO0EE0zcSvd5vOAaxv5OAFQVN/k
         xySB+/xdKSXysyiQ/owaLW4p1I/nzqfhzIV5/UDGxpSgWcrq3IurWLqrge8P547mlNzF
         6Lcv8yLbPdlaMpc5AgfLuI8uXzN5tYYR4TQfha5ZD9+2Fni5kO+LlRfpDNQwoaB5HSio
         8KvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VZIf8Uof7OzUz6KB7Y/AJF709lxrGO7WcGTdIWIj3m4=;
        b=pd0Tcrb3BB/w91MWygzXfLhy3SMpxT/0iIvxFkQUMwXlQJZFeA6Oly5QQipX4qOjos
         3NDLUJjKzB8sPHyHCaB5Jr11su342H6N0VLlonxcoZtZRaud4j3PqRsPMD5KuF8NKnjY
         O0H5UtIAMyywU7iSpBrevOLG3NIaHLNgtDtsiuK5b3u/ucIyo4Kh383C8R8JcIcrEXWM
         5Z8XScESWP/HZbw2IsDWDuaLiaG2H0apGTwugPLzT1cZu/ciWB2cf0/9XfDlbagL1RQ2
         GnIVIFGA0Fxabklm3Ssmao+e8+swtVS9YQIJR7I6Y6yo/orzN26LEewaXpxUx/tjyj9b
         1PiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bBNQjL4n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VZIf8Uof7OzUz6KB7Y/AJF709lxrGO7WcGTdIWIj3m4=;
        b=fupl96sy2JTsxffcdP/MfeX0po9Sw/rv2kmX/acgz1zGxNctZKgVdwxCc/7zrJJQJZ
         qVxdSkrEadseMK/LweNAlWydFLGI6AC0zZ/+u6Kxl+4WMSgie//dd2OyyKQ0Wq5T5bhC
         EoLmoN5QXP7od4Bs/ITFcfXiN2oFOG4Qpkn6AQmS4fwDyN69HvzgFwBQEYEmN7oBelEo
         UoSBl3jf9JAt6LVL35bGcp4Q55G+yLZbqIvyR7kX6qYqNf6GocYsGV5pLZF00dtSCDYk
         fuAtkMpAdFZXb+SmJpfWz1pSesgVy1p2FjHoO/M/XYZkHdGaxr6NXrvGRYBVNu0Jicu4
         C91A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VZIf8Uof7OzUz6KB7Y/AJF709lxrGO7WcGTdIWIj3m4=;
        b=KzusuAcMtehbklyacR4gqJjztjWluEbJBntmuKahCiNDgVowik6Zt0CsTkRRSjVsWe
         To+eXF6GxnePpOo29bDNf3MINNTvchyJml4lgVN8rJcl5YE7r36g7m3obNz9nggAekPX
         nNMMeJUghUXYDKDhRYLSSIgsQN9Xw6UK2/cAvZqNfKr9fKIeq+GaQ4eBWK5oGxhAzKRB
         kNnSsKlxK6fl+CB/ThEPbGltZUTQ1xWkhJBoonco+tnbv9LidcwGcr9UB2Wvu7x5F2CB
         gYmE3o75O6H4EZVbhQ6Eli/4BU7xYorleqSBSOVYNNAAaclIDn+p+3if0uJG+hAa1Hcl
         LoVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpSYCoE19P3zXh4GzFMyNYHVpcHN9w2JLzhbKhdflpCdK8HXlti
	xNjN7t4o1Zlv6/VVlN74TEg=
X-Google-Smtp-Source: AMrXdXu/0wbHr0Fa9GmdmYlBZYBlj29eNHHxZrvnX+gyyRqN6CrEkRUDSXqj+6GP8Hua46TO8gUVDA==
X-Received: by 2002:a5d:59c4:0:b0:242:1783:5316 with SMTP id v4-20020a5d59c4000000b0024217835316mr741821wry.701.1672094514803;
        Mon, 26 Dec 2022 14:41:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f548:0:b0:225:6559:3374 with SMTP id j8-20020adff548000000b0022565593374ls1141641wrp.2.-pod-prod-gmail;
 Mon, 26 Dec 2022 14:41:53 -0800 (PST)
X-Received: by 2002:a5d:6e07:0:b0:242:285:6b39 with SMTP id h7-20020a5d6e07000000b0024202856b39mr12555985wrz.50.1672094513515;
        Mon, 26 Dec 2022 14:41:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672094513; cv=none;
        d=google.com; s=arc-20160816;
        b=iuY2QqUCLTh0jWYY1K6BCEg4KNLMB16aiNpJSl5b86RT0NpeSeIsAghwS2Bf9HVEY9
         wiRU5hl5aDbdau1hu52fSz29FK+Hk8H+/gD70HNCOwgtQ0NS2fqJan1ESSCjb7hbb5+o
         y52sRppbo2516BA4aPUSkPbQJkPCXjCJvAC3IBK24YczzTpkL2wU4AKU2oLFv4zBEh5q
         HSKiSSe1jbzbiig/WjdY2RYmvq5HYWLPGPnsMkajy5CEG8x2BeIdpmcJrKJrXmexqTBV
         LbhFDOnSfcKzzs1qxSuHjzDdPcdP9MuIw4AMscT15zkap3VyGxQ9NKWrIUO4prEjJdsV
         S56Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=+3lTW8ppgkCOp0GPcOsAwQlom3Z3C11B2XXX3v40pes=;
        b=tMUBfIwiom+Lu+OdPvZTQdq5sr8/DJHtjtDSwrbx4stOrnP9299kzdCH2Vqi94elpU
         kQgaWjp30qZtNE/H/ltUwH/2qnpArsYhfDlpMe7QrbqcqT/CrOXUU/bXQwku3pP9IWuT
         j5BVrik/56gO6PX/j7gtieadJ/OvkZShgGedV/4EtjaAeW4eyfpv0gnhU5N5QA+ABtE+
         eY12C6BLZ9lC98Ldl6GTC3ajGZ/2ghU9lHBwoTo+s0Q4p+0b70YCas0wXBga5yMwF/Af
         +lsiRhS5zBWy1VHNOgGtsiAlys3gyVpHs2sDbQZKLbEggoght8VqS7etbX9zoXOa9ecV
         Xwmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bBNQjL4n;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id l17-20020a056000023100b0024222ed1370si480797wrz.3.2022.12.26.14.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Dec 2022 14:41:53 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0959720DF9;
	Mon, 26 Dec 2022 22:41:53 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C8FAC13456;
	Mon, 26 Dec 2022 22:41:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id JBHwLzAjqmPJRgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 26 Dec 2022 22:41:52 +0000
Message-ID: <abeeda98-e6ed-fb88-f838-6b61d43e07e5@suse.cz>
Date: Mon, 26 Dec 2022 23:41:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.1
Subject: Re: Linux 6.2-rc1
To: Linus Torvalds <torvalds@linux-foundation.org>,
 Guenter Roeck <linux@roeck-us.net>, Jaegeuk Kim <jaegeuk@kernel.org>,
 Chao Yu <chao@kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Peter Zijlstra <peterz@infradead.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Kees Cook
 <keescook@chromium.org>, Max Filippov <jcmvbkbc@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221226195206.GA2626419@roeck-us.net>
 <CAHk-=whD1zMyt4c7g6-+tWvVweyb-6oHMT_+ZVHqe1EXwtFpCQ@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAHk-=whD1zMyt4c7g6-+tWvVweyb-6oHMT_+ZVHqe1EXwtFpCQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=bBNQjL4n;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/26/22 21:56, Linus Torvalds wrote:
> On Mon, Dec 26, 2022 at 11:52 AM Guenter Roeck <linux@roeck-us.net> wrote:
>>
>> fs/f2fs/inline.c: In function 'f2fs_move_inline_dirents':
>> include/linux/fortify-string.h:59:33: error: '__builtin_memset' pointer overflow between offset [28, 898293814] and size [-898293787, -1] [-Werror=array-bounds]
>> fs/f2fs/inline.c:430:9: note: in expansion of macro 'memset'
>>   430 |         memset(dst.bitmap + src.nr_bitmap, 0, dst.nr_bitmap - src.nr_bitmap);
>>       |         ^~~~~~
> 
> Well, that's unfortunate.
> 
>> kernel/kcsan/kcsan_test.c: In function '__report_matches':
>> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes
>>
>> Bisect for both points to commit e240e53ae0abb08 ("mm, slub: add
>> CONFIG_SLUB_TINY").  Reverting it on its own is not possible, but
>> reverting the following two patches fixes the problem.
>>
>> 149b6fa228ed mm, slob: rename CONFIG_SLOB to CONFIG_SLOB_DEPRECATED
>> e240e53ae0ab mm, slub: add CONFIG_SLUB_TINY
> 
> No, I think CONFIG_SLUB_TINY should probably have a
> 
>      depends on !COMPILE_TEST
> 
> or something like that instead.

We can do that, although if things are on track to be fixed, maybe it's
unnecessary?

> It already has a
> 
>         depends on SLUB && EXPERT
> 
> which is basically supposed to disable it for any normal builds, but
> obviously allmodconfig will enable EXPERT etc anyway.
> 
> That said, that f2fs case also sounds like this code triggers the
> compiler being unhappy, so it might be worth having some clarification
> from the f2fs people.
> 
> I'm not sure what triggers that problem just on powerpc, and only with
> that CONFIG_SLUB_TINY option. Maybe those make_dentry_ptr_inline() and

I think it's because e240e53ae0ab makes KASAN depend on !SLUB_TINY, because
KASAN does "select SLUB_DEBUG" which depends on !SLUB_TINY; but kconfig will
still honor the select even with dependencies unmet and only warn about it
(and the build would fail) so I prevented it this way. (maybe instead
SLUB_TINY depend on !KASAN would have worked better in retrospect?) So now
allmodconfig will have SLUB_TINY enabled and KASAN thus disabled.

On the other hand there are configs like KCSAN and KMSAN that depend on
!KASAN, so with KASAN disabled, now those become enabled. KCSAN becoming
enabled would be relevant for the xtensa problem. For the powerpc issue I'm
not sure as the macro expansion lines for include/linux/fortify-string.h in
Guenter's report make no sense in my 6.2-rc1 checkout for some reason. But
the header does test for KASAN and KMSAN at several points, to perhaps it's
also related to that?

> make_dentry_ptr_block() functions don't get inlined in that case, and
> that then makes gcc not see the values for those bitmap sizes?
> 
> Does changing the "inline" to "always_inline" perhaps fix the compiler
> unpahhiness too?
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/abeeda98-e6ed-fb88-f838-6b61d43e07e5%40suse.cz.
