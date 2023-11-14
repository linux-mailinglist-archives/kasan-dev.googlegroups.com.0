Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWNMZ6VAMGQE7KX343Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 16BBC7EB7A8
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:19:40 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-507d208be33sf6015260e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:19:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699993179; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrqr7h6qi07l2TiA9+VnpCfVSDRws/jb0XAg8FwseeeuQam7L9m3irjy6/Eozr1xim
         DMyRDtUKKiWYYbaRXqtWG210zobz0DQnkMo7yfusKIEcuzt+nrx1oPO2tm+he497yfta
         VmRFtPIZI8AAvNBpjBkPyQNoWmhMwNc7+Nm8vdRC6R1UWkd6ffZ49J3rbDTpV0k9AxuG
         HVmUJUxmgYRtYgk2/KOjuREgpFVsZA0+XEsW7Dq+Yw5yJRoWzrzxLmqUQooZiNwUO1i9
         qIRJuQfS9hlk3QCLieM4dYGw0W/NEFpVkz1FQfQylxshJfrb+mskIo8S3MoM+kwhmzYF
         2gdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=87oBx45qp/5khSwqJgkkRtC2uC83EN2QlzxQm/hOBQc=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=Zxe1wwmybhnJ6ClkI7yEi9iXcD3h/OoDpq5oiyfuEWrhaIU7cPc2z6TZWIPKdy5RVl
         Z3L42XOJznFPkJ6y6fBLOxX1lRZlKs2sj9uodMJrlA5/WjpxN3juhiIeMuJ1hDcLHOS6
         nDpcluEjAjyvee26UIdTnwN13CVZtrRVxbrCwo8hCl6GiufYxnt/3/jlAObIOzCtlA3b
         YSiczxgtg7Plu1nmmykb51lAx/+uDKXc4b5VlzhhW9hVuh8LiNIelnnVbaqXrfht8oxh
         +vulHsDn1tN+tNnoZIbNvBcEzcljnYjddicGlpnvoVYUrIj1qwtfLyInk8ODeyT+EASg
         oo0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="iu/6NjlV";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699993179; x=1700597979; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=87oBx45qp/5khSwqJgkkRtC2uC83EN2QlzxQm/hOBQc=;
        b=GhyjEtESEMM/L1zX9V+FeZIL083tz9sj2QYCLiOgDxbXdDrQzCs80rKT7bOfWIof/1
         hI4RFC1Den4k4UCyfk46LqSKH8fLCj4MuEiEYh7/M+eNU3dW6DJW03kPSYOLG0R/LHDe
         n/XrheZ12oWACSvMIT3oiKkJI2yPrP7JdOaAcYoctJM5oxJ2IOwr7xe/01uXS16bjTAt
         9DDs33lwHbH1UCfbmnpynjbppfEt19HaH9dFzyLfwALZP6yPUy66FQhyCqWRSUKTCeqW
         xM+QwZMGsiRG2qSTjGqmMZ7T+bKQWaXRw7htpLzlVb9kjUrGtqgyJUtGkcqrgKqTm8gX
         hhTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699993179; x=1700597979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=87oBx45qp/5khSwqJgkkRtC2uC83EN2QlzxQm/hOBQc=;
        b=TeN5jvTFlb6II4XTP/qA0pz0HE9kxvH5CxrY+muZ8V02+i/CQEjgMpTGtalFHqCf27
         agRC1XSCXpY4KeuXUM/rR4BlNgK98G9YLnyXKjlxtw57Lm14Dnc3fDvxiuv4zMEFkV5/
         SFti3iOL2i/w6Y8XydqRRRrQh4tCU042/y/6PaD6sEcMvQ+6uewcYkId9IOfgDiENGLE
         aABbK0Rt3sqG2AGxZ1LCoMCEYXJqYCm7b7EgaVppq8KQAQN2crIRkpPx8+i5HEDv/z1U
         tQbFUSqk/Xp2ShcjYEmotQrPuD+F64tVlCIpIhVkUsrE3bcXqSpVmlpB3Fqda2OFma1P
         gZlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwLyj6wXAftStJBwM9DyH4FEe5QCeAEIVBQfgSZsj3psUmoNt6u
	PLZG+Lwmt0CiIlHzhZK7l+w=
X-Google-Smtp-Source: AGHT+IHffe3KTkyjpf6EprRzsqNl+o5XF8khXZXQxGsdNjSiZt540TJ3W88yoVXrnbfC5sV9aKagfg==
X-Received: by 2002:ac2:44aa:0:b0:507:a04e:3207 with SMTP id c10-20020ac244aa000000b00507a04e3207mr6593263lfm.6.1699993178174;
        Tue, 14 Nov 2023 12:19:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e20:b0:509:908b:912f with SMTP id
 i32-20020a0565123e2000b00509908b912fls506400lfv.2.-pod-prod-05-eu; Tue, 14
 Nov 2023 12:19:36 -0800 (PST)
X-Received: by 2002:ac2:5e78:0:b0:509:47b9:63d0 with SMTP id a24-20020ac25e78000000b0050947b963d0mr5923284lfr.61.1699993176175;
        Tue, 14 Nov 2023 12:19:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699993176; cv=none;
        d=google.com; s=arc-20160816;
        b=Tq3A9DpePT/hYownrwNkvyteEJG1IqPHJRi4NbXsYYizVPJRLzGHzU9aRQ+Tsdz0AE
         2DrmUtnhbCPmQ0Ar0O6TGfJ5xYb9nuKt7Y23omUdmgURA5AbxHqNZHVwwonUeDNgVVKd
         6LMpJq1eeMmmrebrhbtmJb8bf0u+YLqwccaek/7/xqe7E7jUxVnsudeS2+bdD2YEwKMz
         v6tUS6x7BthoPDa+JfWaUGzKA29YAOoFiHe/CQg5/OSJzOOrenj9swvF2t9fg9HbWDdY
         qgO0lvAyGQdZHQZWEuOd4Wbu4jiLgrTfLHbL0LaVzLs4mIzUR4RPwhzHrHnI4rfLupfk
         AyhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=3thwfoQDfeifa7EY/gfWpuitk2l6esZhSluo1Ku2wH4=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=bmg9rwNlI555wMPbMdgvF7X0g3XFvbIFLIlNpho9T6zJmp3ffSmke+EgF+00gFJNsB
         gIMISth1R8p61KxC88H8vwNmRWAU3Y+7ejwIvl+LNaugNM68LBW+FN9gbRcFNYqZiaAq
         ugm+NX1gMIEZDsvQYCEQhorfesVx8UjjRLn/IFKE6OFwelj0Ig8fqpCD+c5yuxDT1SKy
         xVbPpSrf7BMkihTPkNfV+RJqMtU6H2RvQCVeUUUXRildnQRWNADV24VhSfryrDvfW2QT
         PCrmX7y9ki/9etUAcrXfWgDbxVbOq0izCRfSzrTWZ1Wq0KzYjw/8yR7HOjwuQcgjX5d1
         ewjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="iu/6NjlV";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id cf5-20020a056512280500b005091220c8c3si310567lfb.8.2023.11.14.12.19.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:19:36 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D3FBE204B3;
	Tue, 14 Nov 2023 20:19:34 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 86CDC13460;
	Tue, 14 Nov 2023 20:19:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id rTEeIFbWU2VBXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:19:34 +0000
Message-ID: <1bbabb8a-02c8-7247-0084-776a32558130@suse.cz>
Date: Tue, 14 Nov 2023 21:19:34 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 06/20] mm/slab: remove CONFIG_SLAB code from slab common
 code
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-28-vbabka@suse.cz> <202311132024.80A0D5D58@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132024.80A0D5D58@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.66
X-Spamd-Result: default: False [-2.66 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 MID_RHS_MATCH_FROM(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.06)[61.44%];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="iu/6NjlV";
       dkim=neutral (no key) header.i=@suse.cz;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/14/23 05:30, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:47PM +0100, Vlastimil Babka wrote:
>> In slab_common.c and slab.h headers, we can now remove all code behind
>> CONFIG_SLAB and CONFIG_DEBUG_SLAB ifdefs, and remove all CONFIG_SLUB
>> ifdefs.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  include/linux/slab.h | 13 +--------
>>  mm/slab.h            | 69 ++++----------------------------------------
>>  mm/slab_common.c     | 22 ++------------
>>  3 files changed, 8 insertions(+), 96 deletions(-)
>> 
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index 34e43cddc520..90fb1f0d843a 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -24,7 +24,6 @@
>>  
>>  /*
>>   * Flags to pass to kmem_cache_create().
>> - * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.
> 
> I think this comment was wrong, yes? i.e. the "DEBUG" flags are also
> used in SLUB?

Hm yeah we could change it to CONFIG_SLUB_DEBUG. I deleted it because I
didn't think "valid" was the right word, they are always valid (part of
SLAB_FLAGS_PERMITTED thus not returning -EINVAL on cache creation), but they
would be no-op (not part of CACHE_CREATE_MASK) without CONFIG_SLUB_DEBUG.

So we coould change it to e.g.
"The ones marked DEBUG are ignored unless CONFIG_SLUB_DEBUG is enabled" ?

> Regardless:
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1bbabb8a-02c8-7247-0084-776a32558130%40suse.cz.
