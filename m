Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTXV723QMGQE7QZ5O2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D23C99003F
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 11:52:15 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-42cb998fd32sf12973565e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 02:52:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728035535; cv=pass;
        d=google.com; s=arc-20240605;
        b=caEhinyvJ48iKFPxhJn5YSkGrQpYNmuvjJvLo0YdOZnvxrYXffFDM5GDkDZlWo+wwU
         9foAV5/kgb6OkLSG2WXB1YYz+MIGedkjsheAeCls1JkylkQp7SWTVN9D0q4gfOXcXIT5
         BBd5SCLjwWSaBhaDfWT/WJWtc9B0FO3ky7fy3KsjQoeLF4/3WR3WZTaqwZRvoDVWV2Uq
         Np2gMnUmDB06nZqdiQXrmPmdIUQbWwaqFrxmT02c1gpmvpOJpGmizSv1SKwdP1R/7EwQ
         J0ft5tSrqsg0QuOQ7i/HYEGFKnkYALc5LJI/uIWs00joa6scLQt3LWQQd2h9pXSQPkbv
         3TeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=JCfu0CTS/klRQVW8kfBM/w6jNbXsWpBpQLenSDO4ad4=;
        fh=f7sy8Y360J09OklKTF1ECn71+pTqtJfaR/gFzPNDnoI=;
        b=T7n9sLkcFZ7fp4RkhNmcnkU9HYzxungvJrW1Pqf8aYK8Sl0x5c3MGB9IUsZ66LbuP0
         ylTee67/ntqPxFYTgzT/K2heOmzsMstSFw0+VyUyZ4vKNsVKGfhgQAM6G2JF2Pll1JYc
         +ud0Kow/sYIHJ6h7Zp2jwlaSAUOfrOLbuU0271qsatMKUaMJNzscC3zqvHS0G1wApdHK
         eMBfwR0br7sm5HxW5CrGRPtj3cWartZ0BXQUTsGSk3s8AdV5ANTA+cKV4FQUfMfCe0gm
         gyjNO/lRcy2gUBbJakErM7t0Ja/7Zu49i4p1Rx+tY3Akyx5lA/CcL1qCqYuTUsqjA65V
         8Faw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728035535; x=1728640335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JCfu0CTS/klRQVW8kfBM/w6jNbXsWpBpQLenSDO4ad4=;
        b=wiKpCvNDpk6xapRjz6JbAVGb6SFSvMjlLlPOgzpLfXHmEbCRwhta/RL5FjrXUIb4OQ
         CtmZ+kJ/VeyUyHY0oWyb/YJQ+cP+zzwa2yq9X5saBT5rBcxeN1OrsXBFg6zx+R74A5M+
         Jtl+sTesflf6ZhRRw2VgaBGTa2iBJi4clGXtrCR4RfoPcQuNqaFYgXBwVo7Q+/nDMq7F
         U336U6ktCrgIsyvxU5HWz/hy8x/JBRDElj0j+cjsojL+zquvR23tII+J6eDOu1RAl0mZ
         UNocE5V4d9etIHJM2JB+MuoDDiLaxIJbDLKdMOc6EaMDcmaPwr/5PxZK358/WpN2XZwn
         uDZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728035535; x=1728640335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JCfu0CTS/klRQVW8kfBM/w6jNbXsWpBpQLenSDO4ad4=;
        b=VpWIpvBfdAWMl10zt0MG7YMlcEPvUVk3ktnp9wpqvxUX0D7TNC8d13XVAwtw2iUaXE
         K8FN/DCJxram6bdxoXORMwNElrTaV27OzQdLxt9NRh3tlc8moyv9Lr9n8a8QO9DbELXn
         2V+XUfpgvdvWxn2kufjzxnDjr7nfNn5VcBB0SSsdfODntE3TSf/IXBDkl39nO6rR17xu
         BM/dNQN2Fz+6aRFW8+BDNIo+hZhhknCgKRyuWCKBpbiWc7TopfLV6Eki7rp0OKtDtPrW
         ON5EQrRMK+WDs5RzT6jsR2bWgBrDhN7/jfcirmPI02aBSqAVqNFuDNoogsJFqKt+hYef
         aUzA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxrN46BwkRsJVh47XBhhiUrzRluQekBZbv1UZ6xMmKTlVErfFg0STnVylnrZ2CH3bGR71jNA==@lfdr.de
X-Gm-Message-State: AOJu0YzHAAAcQf9ExWtisu19YnsQVwvdURKOmvYM31cSJP54RB58OSOr
	jjQWX1nqAY6eW4xBFd4qzs4HngENagrHLsYrI1KIK5RRD3iVSEoZ
X-Google-Smtp-Source: AGHT+IFRqoVLjG0axJn3CZClxOpOWJDxrwr15z5AYV6tsy5EofV2chp7l7N3YTwnFmN9fzAMLt5hyw==
X-Received: by 2002:a05:600c:19c6:b0:42f:8515:e47d with SMTP id 5b1f17b1804b1-42f85ab68femr15582755e9.11.1728035534311;
        Fri, 04 Oct 2024 02:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c10:b0:42c:bb08:9fa6 with SMTP id
 5b1f17b1804b1-42f7deb74a9ls4463325e9.0.-pod-prod-03-eu; Fri, 04 Oct 2024
 02:52:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCULm12kE8oQAQidV5y5SbyEPFXrKlerBZ2YyDqnZvv5h+BUQPtO83aQFEx1pr2gug/rpuN7CnynFx4=@googlegroups.com
X-Received: by 2002:a7b:cb42:0:b0:42c:ba1f:5475 with SMTP id 5b1f17b1804b1-42f85af4366mr16193935e9.26.1728035532264;
        Fri, 04 Oct 2024 02:52:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728035532; cv=none;
        d=google.com; s=arc-20240605;
        b=LC7adJbEsHoPAqqfGkomOCLC47dhwz5G5WIr8Y+n+jUO8k9wbMOpgtbpudrLyPvD21
         FiHQI4SDYD8AAzIhdpiN1hZ0hPBvOnl+IdOO1mn4ZbSkltTbAqa0JRNIJvieYIdAxSYW
         dvcVqJf4tM3hQQrqm5exs6cUp8FM8gUaFBywssznQ89jcNYqUIeWiMH7Yfu+gRMwNam/
         OKnxVqzPV58xYxOJhSkWp0nSSAMTn8FLb8GzBMj0I6My76op5KvfJn+cINewPmZJbzOa
         P190ImSLoyuSUrkl9vpnDugEWDzAuv4voWcJBsTCQj97ldf7juTztBBxjUABsYIi5wkU
         QABQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=Mc45QIIZl/Qv9AcqyKNAc7BYIVWe6fly1TOftOh3r88=;
        fh=5N1HThlDAESuEoE7HRX8vb2Wkw61+stOkYicktTdUig=;
        b=YRCmNaWikfWNrVNlTWXwQWAaZvdT5TlK8hpSxbEYgGWgMzHdBC+FCg9SRaDMkSTbta
         tEY2S+bsw+FTRGMTdmVR/Sb2wLrtQFUPiIGmwZtNDHkp9Zznyz8GzZyslbJEqFxArXz8
         jLNFevdn8vONlo/k1DhlCmMgEaoElLkCaNIppPWjvQgQZEIT2TeycKd9cduDfQDPv6xM
         KTRFqdwAMUQXB9QYbQQeo4wBQCJHfrprR7XjDS85bym8nXjEaSR54idRlnhk5sFsXTNs
         8AeGYIH76qUmmVPI7aFtxBBTe47uL2RcclpT0aSF5mRv9gHp4gAZfoSVCsZaGR/VZ7EG
         WI1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f8598b8b1si671965e9.0.2024.10.04.02.52.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Oct 2024 02:52:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 68E3A21C47;
	Fri,  4 Oct 2024 09:52:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3D2F513A6E;
	Fri,  4 Oct 2024 09:52:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0mwbDsu6/2YTEgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 04 Oct 2024 09:52:11 +0000
Message-ID: <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
Date: Fri, 4 Oct 2024 11:52:10 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Marco Elver <elver@google.com>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Shuah Khan <skhan@linuxfoundation.org>,
 David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Eric Dumazet <edumazet@google.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 68E3A21C47
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[21];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org,arm.com,kvack.org,googlegroups.com,vger.kernel.org];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cagAmj1g;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/4/24 11:18, Vlastimil Babka wrote:
> On 10/4/24 08:44, Marco Elver wrote:
> 
> I think it's commit d0a38fad51cc7 doing in __do_krealloc()
> 
> -               ks = ksize(p);
> +
> +               s = virt_to_cache(p);
> +               orig_size = get_orig_size(s, (void *)p);
> +               ks = s->object_size;
> 
> so for kfence objects we don't get their actual allocation size but the
> potentially larger bucket size?
> 
> I guess we could do:
> 
> ks = kfence_ksize(p) ?: s->object_size;
> 
> ?

Hmm this probably is not the whole story, we also have:

-               memcpy(ret, kasan_reset_tag(p), ks);
+               if (orig_size)
+                       memcpy(ret, kasan_reset_tag(p), orig_size);

orig_size for kfence will be again s->object_size so the memcpy might be a
(read) buffer overflow from a kfence allocation.

I think get_orig_size() should perhaps return kfence_ksize(p) for kfence
allocations, in addition to the change above.

Or alternatively we don't change get_orig_size() (in a different commit) at
all, but __do_krealloc() will have an "if is_kfence_address()" that sets
both orig_size and ks to kfence_ksize(p) appropriately. That might be easier
to follow.

But either way means rewriting 2 commits. I think it's indeed better to drop
the series now from -next and submit a v3.

Vlastimil

>> Thanks,
>> -- Marco
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f%40suse.cz.
