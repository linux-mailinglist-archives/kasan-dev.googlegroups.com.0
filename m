Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDNPZ6VAMGQE4TRKEXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8109B7EB7BC
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:24:47 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2c8321310b6sf37868251fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699993487; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJRsvJZyAYTmhblHAI8vmSgv9kwbLN6HIGQf6KkliH1ECsJblKbeY/UXiDGF+NHi24
         r+Df2q5+dKMiSw8TZEWibRUEkhZmEXYo96tyXKEx2ltn6pyJMJQOLH/DxKYmwIDAK2br
         mGeXQ+Hd8wNOlpjG5XDWABWAJIDHUOhqBE4q3ws3Z37JqMrUJYXT+813L2sw51UUUwmw
         T5rgT7La66lEh5GyM50HyFHcHgyhmN2DohHF/eQavimKGiAQyIBaiq+8zu5vxGSaT0UD
         79nZll4oursKD0uYP/y4JPRJWowCiOeGI5pICfMIfjpcL67KKz9zo5bnV8vuweKwjEPO
         IKxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=wY3pyxGUShnGhIQVlGhFGGVXZMA0ZV4vVJbbnDtxKe0=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=fXIZ1B2l/HBydPMAy3vreKLVPz85mcznkeZJ8v5JxcU8tEojdHaqqQHBACP8GiZyPW
         zBZS9I7RrSzDVTMNvxE9kxuKXBXtXCiikzVIeW3lRFZ331lcEKmegyq1nOnaYcy1NXgo
         VSZydXqFPKOwK/g+h9yajDgHafy14RWv7YmO59kTIxKeAmjItAu5+TcEvEtCUmQK+bR7
         aHD+SoM/Q2FitRnCzEOBSy5u1fTeB73LeW5yt8Bf+HAqMdl0x/7K9kudQyzERmkzLySi
         WCdqN2hPzpZZuPeVl27CLkvq+fNhLVgnOV1bvG4xPk2R/rK3J1BY1HzKxZwSmAkfG08+
         C0+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=i4CWqGKl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0YXskOkW;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699993487; x=1700598287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wY3pyxGUShnGhIQVlGhFGGVXZMA0ZV4vVJbbnDtxKe0=;
        b=dTMdYlFa923+P0nAalYFCktQy9nktfnCf1mcokr/wcpM3t0fVL4gYpgxFTCsrfh5+w
         yzfi7w+U/xGaxV/iDHKYZ9jtfaM/TBaWGB4Z7igBgkRuym2TOTV08JAML7tYYMpVDbmp
         vr39v+DmqtWMZTIBZJiHu0cgnHgY6leCuik2w61pin+YwmAyxbksWLUJSo5qUYoORYYh
         7cHJmg3rIb56jDyX4W0DAIY3zcCN98phSv1VtdwmGEtT7jgZEEO7w4xsjwcPyCGrCJ/h
         WvEKcMvCTAgRunm3vL2zI5e+O+LWAs2eeI1Kcike2XmX8Ki2W44Dq5HIg0m2gqbjbFvk
         r8IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699993487; x=1700598287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wY3pyxGUShnGhIQVlGhFGGVXZMA0ZV4vVJbbnDtxKe0=;
        b=lhpR+AdT0MnmO2qZJ0gRhZKy5kFtYA8doRJJoInIPEuLsi9ClLKObz9xvU4ckubL6X
         r+TMK3M/xoOmuw70swamp2qnzLioTBytz9KkDmjbSeE+xaWS/D0B3ec1Id66nWC5peCc
         +i70nJl9NBrpl0yYRFxVtapJwZFGBB+AOg0fsgjv1pCoPLs5Ch3twyUNvnG5QHu9oCOT
         AGS3zXJk5J0luyhdjP1QEgawZDgC0iQXheRNGjoGZsZ205/XiZBoHntwX9E1HFLRfnQZ
         o9oOYyQUZuqxTLsnxCUnyy+nXqO2lQt4goxOxaoT8DVS6S3ciwt05QR77QXj7uM2E3G0
         11ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx420WA7XZyHB2lW2I9wpo6CKZ31OiQ5zzqUh6kHTo2rKNYuEek
	HRkHeVc31lz5FDadgMPdIk0=
X-Google-Smtp-Source: AGHT+IGAiHC8ATHuqpk0e1bhtjqhg7pymAZ9t+Rqd9jj+BUElIW2PyhPEJ15pvKR2uGWFJNMPsD3xA==
X-Received: by 2002:a2e:b5a3:0:b0:2c5:1fae:e61f with SMTP id f3-20020a2eb5a3000000b002c51faee61fmr2417048ljn.6.1699993485736;
        Tue, 14 Nov 2023 12:24:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1f:0:b0:2bf:f477:1994 with SMTP id b31-20020a2ebc1f000000b002bff4771994ls457660ljf.1.-pod-prod-09-eu;
 Tue, 14 Nov 2023 12:24:44 -0800 (PST)
X-Received: by 2002:a2e:9309:0:b0:2c2:a337:5ea with SMTP id e9-20020a2e9309000000b002c2a33705eamr2121056ljh.27.1699993483799;
        Tue, 14 Nov 2023 12:24:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699993483; cv=none;
        d=google.com; s=arc-20160816;
        b=Eb8X+cdGhzY835a7Hs34EfvjMfyamHv3Bj4myKHV8pjmVqF7VLdtR944Yv6G2rqpMy
         sWK+TZ5l16yoIIVwlSHwUmpoXhZjZPL7XcRJrRc80lpQwmeajvbdpBvakRdxHlxVSa77
         +4kMHjz/vro+1VVovuV/UqK/jySManwOsHAML5Q/mnB+npqpMrAFEFeKbJiCfvZqdqiC
         SvG8D+GB19C2XrBO39GjRNHJQr3rxzoFrZL5r/+j88gTA0jmqMis8NK0UHOy6ZHQetxX
         HbXEcSm2n6qJqUtOcrGOJuWLRtdh0+zgqCtDjfVuNuqMDd84l7TWrMF2NG1dA69T1Z/v
         iZAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=+6UsT5QFBZcpyy/zzlztYcwvUhTuQe2Zg+uDJvHRCAE=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=pY8P0N9BWH3EzQlISRVO4RKUA9DmR+UiOHhagMYBdVbWBXPZ991xfpmN9S7M1ulQIs
         lJJGqY+irhfbR0FenBdFKPdRXruVGidAaikTbTHGz44T8255zGWe3qgc2MKzLPv7ueq5
         kB7zidtLBfc/1WnAt3Sg/uws7C0Vb3fl8N22+Mx93nALfX1SIUvqbyb9EVVPAWyYiciO
         1d+6Ad4C18zJYoDIEE/u/v26qhUl55ZvV0Iy5YZCtIY8dzlxU7qdEFf1fjlL8z4LG0XU
         Sug+VXeIYQfLUFiAqoF175eK/eqpBnCMTl9IroIz55TraE6wa6Ilbj1hAPuIs0Ln5ip6
         c8Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=i4CWqGKl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0YXskOkW;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id c7-20020a2e9d87000000b002c29b97d5f2si356254ljj.1.2023.11.14.12.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:24:43 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6DDE8228DF;
	Tue, 14 Nov 2023 20:24:42 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 18DD913460;
	Tue, 14 Nov 2023 20:24:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id KmZUBYrXU2V2XgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:24:42 +0000
Message-ID: <98380669-875b-3c85-006d-e3617b8fcaab@suse.cz>
Date: Tue, 14 Nov 2023 21:24:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 11/20] mm/slab: consolidate includes in the internal
 mm/slab.h
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
 <20231113191340.17482-33-vbabka@suse.cz> <202311132039.7CC758A@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132039.7CC758A@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.60
X-Spamd-Result: default: False [-2.60 / 50.00];
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
	 BAYES_HAM(-0.00)[10.02%];
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
 header.i=@suse.cz header.s=susede2_rsa header.b=i4CWqGKl;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0YXskOkW;
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

On 11/14/23 05:41, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:52PM +0100, Vlastimil Babka wrote:
>> The #include's are scattered at several places of the file, but it does
>> not seem this is needed to prevent any include loops (anymore?) so
>> consolidate them at the top. Also move the misplaced kmem_cache_init()
>> declaration away from the top.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slab.h | 28 ++++++++++++++--------------
>>  1 file changed, 14 insertions(+), 14 deletions(-)
>> 
>> diff --git a/mm/slab.h b/mm/slab.h
>> index 6e76216ac74e..c278f8b15251 100644
>> --- a/mm/slab.h
>> +++ b/mm/slab.h
>> @@ -1,10 +1,22 @@
>>  /* SPDX-License-Identifier: GPL-2.0 */
>>  #ifndef MM_SLAB_H
>>  #define MM_SLAB_H
>> +
>> +#include <linux/reciprocal_div.h>
>> +#include <linux/list_lru.h>
>> +#include <linux/local_lock.h>
>> +#include <linux/random.h>
>> +#include <linux/kobject.h>
>> +#include <linux/sched/mm.h>
>> +#include <linux/memcontrol.h>
>> +#include <linux/fault-inject.h>
>> +#include <linux/kmemleak.h>
>> +#include <linux/kfence.h>
>> +#include <linux/kasan.h>
> 
> I've seen kernel code style in other places ask that includes be
> organized alphabetically. Is the order here in this order for some
> particular reason?

Hm not aware of the alphabetical suggestion. I usually order by going from
more low-level and self-contained headers to the more complex ones that
transitively include more, so did that here as well but it's not a precise
process.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/98380669-875b-3c85-006d-e3617b8fcaab%40suse.cz.
